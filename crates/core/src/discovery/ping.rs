// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

//! Platform ICMP echo implementations.
//!
//! - Windows: `IcmpSendEcho` (IP Helper API, unprivileged).
//! - Linux: `SOCK_DGRAM` ICMP sockets when `net.ipv4.ping_group_range`
//!   permits (typical on desktop distros), else the capability is reported
//!   unavailable — no raw sockets without the helper, ever.

use std::net::IpAddr;
use std::time::Duration;

/// Send one ICMP echo and wait up to `timeout`. Returns true on a reply.
pub fn echo(ip: &str, timeout: Duration) -> bool {
    let addr: IpAddr = match ip.parse() {
        Ok(IpAddr::V4(a)) => a.into(),
        _ => return false,
    };
    #[cfg(windows)]
    {
        win_icmp(addr, timeout)
    }
    #[cfg(target_os = "linux")]
    {
        linux_icmp_dgram(addr, timeout)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (addr, timeout);
        false
    }
}

/// Whether unprivileged ICMP echo works at all on this platform right now.
pub fn probe_capability() -> bool {
    echo("127.0.0.1", Duration::from_millis(1200))
}

#[cfg(windows)]
fn win_icmp(addr: IpAddr, timeout: Duration) -> bool {
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    let v4 = match addr {
        std::net::IpAddr::V4(a) => a.octets(),
        std::net::IpAddr::V6(_) => return false,
    };
    unsafe {
        let Ok(handle) = IcmpCreateFile() else {
            return false;
        };
        let payload = b"mipscan-probe";
        // MSDN: reply buffer must hold the struct + echoed data + 8 bytes.
        let mut reply_buf = [0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + 32];
        let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        let n = IcmpSendEcho(
            handle,
            u32::from_ne_bytes(v4),
            payload.as_ptr() as *const core::ffi::c_void,
            payload.len() as u16,
            None,
            reply_buf.as_mut_ptr() as *mut core::ffi::c_void,
            reply_buf.len() as u32,
            timeout_ms,
        );
        // read_unaligned, not read: `reply_buf` is a [u8] with alignment 1
        // and ICMP_ECHO_REPLY wants more, so a plain read is undefined
        // behaviour even when it happens to work.
        let reply = std::ptr::read_unaligned(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY);
        let _ = IcmpCloseHandle(handle);
        n > 0 && reply.Status == 0
    }
}

#[cfg(target_os = "linux")]
fn linux_icmp_dgram(addr: IpAddr, timeout: Duration) -> bool {
    let IpAddr::V4(dst) = addr else { return false };
    // SOCK_DGRAM IPPROTO_ICMP works unprivileged when
    // net.ipv4.ping_group_range includes our gid (common on desktops).
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM,
            libc::IPPROTO_ICMP as libc::c_int,
        )
    };
    if fd < 0 {
        return false;
    }
    unsafe {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let sockaddr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst).to_be(),
        },
        sin_zero: [0; 8],
    };
    // DGRAM ICMP echo header: type(8) code(0) checksum(0) id(0) seq(0);
    let packet = [8u8, 0, 0, 0, 0, 0, 0, 0];
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &sockaddr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        unsafe { libc::close(fd) };
        return false;
    }
    let mut buf = [0u8; 64];
    let mut from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let mut from = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut from as *mut _ as *mut libc::sockaddr,
            &mut from_len,
        )
    };
    unsafe { libc::close(fd) };
    // Echo reply: type 0.
    n >= 8 && buf[0] == 0
}

/// Resolve an IPv4 address to a MAC via ARP without leaving userspace APIs:
/// Windows `SendARP` (works unprivileged on most systems) or the helper.
#[cfg(windows)]
pub fn native_arp_resolve(ip: &str) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::SendARP;

    let v4: [u8; 4] = ip.parse::<std::net::Ipv4Addr>().ok()?.octets();
    unsafe {
        let mut mac_bytes = [0u8; 8];
        let mut len: u32 = 8;
        let rc = SendARP(
            u32::from_ne_bytes(v4),
            0,
            mac_bytes.as_mut_ptr() as *mut core::ffi::c_void,
            &mut len,
        );
        if rc == 0 && len as usize >= 6 {
            return crate::identity::mac_from_bytes(&mac_bytes);
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn native_arp_resolve(_ip: &str) -> Option<String> {
    // Raw AF_PACKET sockets require root; without the helper there is no
    // unprivileged native ARP on Linux.
    None
}

#[cfg(target_os = "linux")]
pub fn raw_socket_capability() -> bool {
    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as libc::c_int,
        );
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
}
