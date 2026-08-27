//! `laninv-helper` — the optional privileged helper.
//!
//! Speaks newline-delimited JSON:
//!   request  {"op":"arp","ip":"192.168.1.5"}
//!   response {"ok":true,"mac":"aa:bb:cc:dd:ee:ff"} | {"ok":false,"error":"..."}
//!   {"op":"shutdown"} closes the helper.
//!
//! Modes:
//!   --stdio  : serve on stdin/stdout (launched via sudo/pkexec on Linux)
//!   --pipe N : serve named pipe \\.\pipe\N (launched via UAC runas on Windows)
//!
//! Attack surface is deliberately tiny: the only operation is ARP resolution
//! of a dotted-quad IPv4 string. No file access, no shell, no arbitrary ops.

#[cfg(windows)]
use std::io::BufReader;
use std::io::{BufRead, Write};

#[derive(serde::Deserialize)]
struct Req {
    op: String,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(serde::Serialize)]
struct Resp<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--stdio") {
        serve_stdio();
        return;
    }
    #[cfg(windows)]
    if let Some(pipe) = args
        .iter()
        .position(|a| a == "--pipe")
        .and_then(|i| args.get(i + 1).cloned())
    {
        std::process::exit(serve_pipe(&pipe));
    }
    {
        eprintln!("laninv-helper: usage: --stdio | --pipe NAME");
        eprintln!("This binary is launched by laninv; running it by hand does nothing useful.");
        std::process::exit(2);
    }
}

fn handle(line: &str) -> String {
    let req: Req = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(_) => {
            return r#"{"ok":false,"error":"bad request"}"#.to_string();
        }
    };
    let resp = match req.op.as_str() {
        "shutdown" => {
            return serde_json::to_string(&Resp {
                ok: true,
                mac: None,
                error: None,
            })
            .unwrap_or_default();
        }
        "arp" => match req.ip.as_deref().and_then(valid_ipv4) {
            Some(ip) => match arp_resolve(ip) {
                Some(mac) => Resp {
                    ok: true,
                    mac: Some(mac),
                    error: None,
                },
                None => Resp {
                    ok: false,
                    mac: None,
                    error: Some("no reply"),
                },
            },
            None => Resp {
                ok: false,
                mac: None,
                error: Some("invalid or missing ip"),
            },
        },
        _ => Resp {
            ok: false,
            mac: None,
            error: Some("unknown op"),
        },
    };
    serde_json::to_string(&resp).unwrap_or_default()
}

fn valid_ipv4(s: &str) -> Option<&str> {
    arp::parse_ipv4(s).map(|_| s)
}

/// Pure ARP wire-format and routing-table logic.
///
/// Deliberately free of `#[cfg]`. This is where the bugs were, and code behind
/// a platform gate is code the other platform's build never checks — so
/// everything that is not an actual syscall lives here, compiled and tested
/// everywhere.
///
/// Only the Linux resolver calls most of this, so a non-Linux build sees it as
/// dead. That is the intended trade: the tests exercise it on every platform,
/// which is worth more than a tidy warning list on one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod arp {
    /// Ethernet header (14) + ARP payload (28).
    pub const FRAME_LEN: usize = 42;

    /// Parse a dotted quad into a host-order u32.
    pub fn parse_ipv4(s: &str) -> Option<u32> {
        Some(u32::from(s.trim().parse::<std::net::Ipv4Addr>().ok()?))
    }

    /// Lowercase colon-separated MAC. All-zero and broadcast are not
    /// identities and are rejected.
    pub fn format_mac(mac: [u8; 6]) -> Option<String> {
        if mac == [0u8; 6] || mac == [0xffu8; 6] {
            return None;
        }
        Some(
            mac.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }

    /// Build an Ethernet + ARP request frame (RFC 826).
    pub fn build_request(src_mac: [u8; 6], src_ip: u32, dst_ip: u32) -> [u8; FRAME_LEN] {
        let mut f = [0u8; FRAME_LEN];
        f[0..6].copy_from_slice(&[0xff; 6]); // ethernet destination: broadcast
        f[6..12].copy_from_slice(&src_mac); // ethernet source
        f[12..14].copy_from_slice(&[0x08, 0x06]); // ethertype: ARP
        f[14..16].copy_from_slice(&[0x00, 0x01]); // hardware type: ethernet
        f[16..18].copy_from_slice(&[0x08, 0x00]); // protocol type: IPv4
        f[18] = 6; // hardware address length
        f[19] = 4; // protocol address length
        f[20..22].copy_from_slice(&[0x00, 0x01]); // opcode: request
        f[22..28].copy_from_slice(&src_mac); // sender hardware address
        f[28..32].copy_from_slice(&src_ip.to_be_bytes()); // sender protocol address
                                                          // 32..38 is the target hardware address: the thing we are asking for,
                                                          // so it stays zero.
        f[38..42].copy_from_slice(&dst_ip.to_be_bytes()); // target protocol address
        f
    }

    /// Extract the sender's MAC from an ARP reply about `expected_ip`.
    pub fn parse_reply(frame: &[u8], expected_ip: u32) -> Option<[u8; 6]> {
        if frame.len() < FRAME_LEN {
            return None;
        }
        if frame[12] != 0x08 || frame[13] != 0x06 {
            return None; // not ARP
        }
        if frame[20] != 0x00 || frame[21] != 0x02 {
            return None; // not a reply
        }
        let sender_ip = u32::from_be_bytes([frame[28], frame[29], frame[30], frame[31]]);
        if sender_ip != expected_ip {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&frame[22..28]);
        Some(mac)
    }

    /// Pick the interface that routes to `dst` from the contents of
    /// `/proc/net/route`, preferring the most specific match.
    pub fn route_iface_for(proc_net_route: &str, dst: u32) -> Option<String> {
        let mut best: Option<(u32, &str)> = None;
        for line in proc_net_route.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 || cols[0].is_empty() {
                continue;
            }
            // /proc/net/route stores addresses little-endian.
            let (Ok(dest), Ok(mask)) = (
                u32::from_str_radix(cols[1], 16),
                u32::from_str_radix(cols[7], 16),
            ) else {
                continue;
            };
            let (dest, mask) = (dest.swap_bytes(), mask.swap_bytes());
            if dst & mask != dest {
                continue;
            }
            let prefix = mask.count_ones();
            if best.is_none_or(|(p, _)| prefix > p) {
                best = Some((prefix, cols[0]));
            }
        }
        best.map(|(_, iface)| iface.to_string())
    }
}

fn serve_stdio() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let reply = handle(&line);
        if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
            break;
        }
        if line.contains("\"shutdown\"") {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
fn arp_resolve(ip: &str) -> Option<String> {
    arp_linux::resolve(ip)
}

#[cfg(windows)]
fn arp_resolve(ip: &str) -> Option<String> {
    arp_windows::resolve(ip)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn arp_resolve(_ip: &str) -> Option<String> {
    None
}

// ---------------- Windows ----------------

#[cfg(windows)]
mod arp_windows {
    use windows::Win32::NetworkManagement::IpHelper::SendARP;

    pub fn resolve(ip: &str) -> Option<String> {
        let octets: [u8; 4] = ip.parse::<std::net::Ipv4Addr>().ok()?.octets();
        unsafe {
            let mut mac = [0u8; 8];
            let mut len: u32 = 8;
            let rc = SendARP(
                u32::from_ne_bytes(octets),
                0,
                mac.as_mut_ptr() as *mut core::ffi::c_void,
                &mut len,
            );
            if rc == 0 && len as usize >= 6 {
                let mut bytes = [0u8; 6];
                bytes.copy_from_slice(&mac[..6]);
                // SendARP can hand back an all-zero MAC for an unreachable
                // address; that is an artifact, not an identity.
                return super::arp::format_mac(bytes);
            }
        }
        None
    }
}

#[cfg(windows)]
fn serve_pipe(name: &str) -> i32 {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::ConnectNamedPipe;
    use windows::Win32::System::Pipes::CreateNamedPipeW;
    use windows::Win32::System::Pipes::PIPE_READMODE_BYTE;
    use windows::Win32::System::Pipes::PIPE_TYPE_BYTE;
    use windows::Win32::System::Pipes::PIPE_WAIT;

    // SDDL: owner = administrators, but grant read/write to Everyone so the
    // unelevated client can connect. The only op exposed is ARP resolution.
    let sddl: Vec<u16> = "D:P(A;;GWGR;;;WD)(A;;GA;;;BA)"
        .encode_utf16()
        .chain([0])
        .collect();
    let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    unsafe {
        let ok = windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            None,
        );
        if ok.is_err() {
            eprintln!("laninv-helper: SDDL parse failed");
            return 1;
        }
    }

    let full = format!(r"\\.\pipe\{name}");
    let wide: Vec<u16> = full.encode_utf16().chain([0]).collect();
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(&SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            }),
        )
    };
    if pipe.is_invalid() {
        eprintln!(
            "laninv-helper: CreateNamedPipeW failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
        };
        return 1;
    }

    // Block until the client connects.
    let connected = unsafe { ConnectNamedPipe(pipe, None) };
    if connected.is_err() {
        let _ = unsafe { CloseHandle(pipe) };
        return 1;
    }

    let mut reader = BufReader::new(PipeStream(pipe));
    let mut out = PipeWriter(pipe);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let reply = handle(&line);
                if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
                    break;
                }
                if line.contains("\"shutdown\"") {
                    break;
                }
            }
        }
    }
    let _ = unsafe { CloseHandle(pipe) };
    unsafe {
        windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
    };
    0
}

#[cfg(windows)]
struct PipeStream(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl std::io::Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut read = 0u32;
        let ok = unsafe { ReadFile(self.0, Some(buf), Some(&mut read), None) };
        ok.map_err(|_| std::io::Error::last_os_error())?;
        Ok(read as usize)
    }
}

#[cfg(windows)]
struct PipeWriter(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl std::io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut written = 0u32;
        let ok = unsafe { WriteFile(self.0, Some(buf), Some(&mut written), None) };
        ok.map_err(|_| std::io::Error::last_os_error())?;
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------- Linux ----------------

#[cfg(target_os = "linux")]
mod arp_linux {
    use super::arp;

    /// Resolve `ip` using a raw AF_PACKET socket: broadcast an ARP request,
    /// listen for the reply. Root-only, which is exactly why this lives in
    /// the helper.
    ///
    /// Only the syscalls live here; the wire format and routing logic are in
    /// [`super::arp`] so they are checked on every platform.
    pub fn resolve(ip: &str) -> Option<String> {
        let dst_ip = arp::parse_ipv4(ip)?;
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        let ifname = arp::route_iface_for(&routes, dst_ip)?;
        let src_ip = interface_ipv4(&ifname)?;
        let src_mac = interface_mac(&ifname)?;

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ARP as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            eprintln!("laninv-helper: AF_PACKET socket failed (needs root)");
            return None;
        }
        let result = exchange(fd, &ifname, src_mac, src_ip, dst_ip);
        unsafe { libc::close(fd) };
        result
    }

    /// Send the request and wait up to a second for the matching reply.
    fn exchange(
        fd: libc::c_int,
        ifname: &str,
        src_mac: [u8; 6],
        src_ip: u32,
        dst_ip: u32,
    ) -> Option<String> {
        let ifindex = if_index(fd, ifname)?;
        let frame = arp::build_request(src_mac, src_ip, dst_ip);
        let mut sll_addr = [0u8; 8];
        sll_addr[..6].copy_from_slice(&[0xff; 6]);
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: (libc::ETH_P_ARP as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 1,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr,
        };
        let sent = unsafe {
            libc::sendto(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return None;
        }

        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            let mut buf = [0u8; 128];
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < arp::FRAME_LEN as isize {
                continue;
            }
            if let Some(mac) = arp::parse_reply(&buf[..n as usize], dst_ip) {
                return arp::format_mac(mac);
            }
        }
        None
    }

    fn if_index(fd: libc::c_int, ifname: &str) -> Option<libc::c_int> {
        unsafe {
            let mut req: libc::ifreq = std::mem::zeroed();
            for (i, b) in ifname.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
                req.ifr_name[i] = b as libc::c_char;
            }
            if libc::ioctl(fd, libc::SIOCGIFINDEX, &mut req) < 0 {
                return None;
            }
            Some(req.ifr_ifru.ifru_ifindex)
        }
    }

    fn interface_ipv4(iface: &str) -> Option<u32> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return None;
        }
        let out = unsafe {
            let mut req: libc::ifreq = std::mem::zeroed();
            for (i, b) in iface.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
                req.ifr_name[i] = b as libc::c_char;
            }
            if libc::ioctl(fd, libc::SIOCGIFADDR, &mut req) == 0 {
                let sa: *const libc::sockaddr = &req.ifr_ifru.ifru_addr;
                if (*sa).sa_family as libc::c_int == libc::AF_INET {
                    let sin = &*(sa as *const libc::sockaddr_in);
                    Some(u32::from_be(sin.sin_addr.s_addr))
                } else {
                    None
                }
            } else {
                None
            }
        };
        unsafe { libc::close(fd) };
        out
    }

    fn interface_mac(iface: &str) -> Option<[u8; 6]> {
        let text = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
        let bytes: Vec<u8> = text
            .trim()
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        bytes.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::arp;

    const SRC_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    #[test]
    fn a_dotted_quad_parses_to_a_host_order_u32() {
        // The helper's only operation began with `ip.parse::<u32>()`, which
        // fails for every dotted quad, so ARP resolution always returned None.
        assert_eq!(arp::parse_ipv4("192.168.1.5"), Some(0xC0A8_0105));
        assert_eq!(arp::parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(arp::parse_ipv4("255.255.255.255"), Some(u32::MAX));
        assert_eq!(arp::parse_ipv4("192.168.1"), None);
        assert_eq!(arp::parse_ipv4("192.168.1.256"), None);
        assert_eq!(arp::parse_ipv4("not an ip"), None);
    }

    #[test]
    fn a_request_carries_the_target_ip_in_the_target_protocol_address() {
        // RFC 826 layout: sender HA 22..28, sender PA 28..32,
        // target HA 32..38, target PA 38..42.
        let frame = arp::build_request(SRC_MAC, 0x0A00_0001, 0xC0A8_0105);
        assert_eq!(
            &frame[38..42],
            &0xC0A8_0105u32.to_be_bytes(),
            "the address being asked about goes in the target protocol address"
        );
        assert_eq!(
            &frame[32..38],
            &[0u8; 6],
            "the target hardware address is what we are asking for; it must be zero"
        );
    }

    #[test]
    fn a_request_is_a_well_formed_ethernet_arp_frame() {
        let frame = arp::build_request(SRC_MAC, 0x0A00_0001, 0xC0A8_0105);
        assert_eq!(frame.len(), 42);
        assert_eq!(&frame[0..6], &[0xffu8; 6], "broadcast destination");
        assert_eq!(&frame[6..12], &SRC_MAC, "our MAC as ethernet source");
        assert_eq!(&frame[12..14], &[0x08, 0x06], "ethertype ARP");
        assert_eq!(&frame[14..16], &[0x00, 0x01], "hardware type ethernet");
        assert_eq!(&frame[16..18], &[0x08, 0x00], "protocol type IPv4");
        assert_eq!(frame[18], 6, "hardware address length");
        assert_eq!(frame[19], 4, "protocol address length");
        assert_eq!(&frame[20..22], &[0x00, 0x01], "opcode request");
        assert_eq!(&frame[22..28], &SRC_MAC, "sender hardware address");
        assert_eq!(&frame[28..32], &0x0A00_0001u32.to_be_bytes());
    }

    /// A minimal ARP reply frame from `sender_mac`/`sender_ip`.
    fn reply(sender_mac: [u8; 6], sender_ip: u32, opcode: u16, ethertype: [u8; 2]) -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[12..14].copy_from_slice(&ethertype);
        f[14..16].copy_from_slice(&[0x00, 0x01]);
        f[16..18].copy_from_slice(&[0x08, 0x00]);
        f[18] = 6;
        f[19] = 4;
        f[20..22].copy_from_slice(&opcode.to_be_bytes());
        f[22..28].copy_from_slice(&sender_mac);
        f[28..32].copy_from_slice(&sender_ip.to_be_bytes());
        f
    }

    #[test]
    fn a_reply_about_the_expected_address_yields_its_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let frame = reply(mac, 0xC0A8_0105, 2, [0x08, 0x06]);
        assert_eq!(arp::parse_reply(&frame, 0xC0A8_0105), Some(mac));
    }

    #[test]
    fn replies_about_anything_else_are_ignored() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(
            arp::parse_reply(&reply(mac, 0xC0A8_0106, 2, [0x08, 0x06]), 0xC0A8_0105),
            None,
            "a reply about a different address"
        );
        assert_eq!(
            arp::parse_reply(&reply(mac, 0xC0A8_0105, 1, [0x08, 0x06]), 0xC0A8_0105),
            None,
            "an ARP request, not a reply"
        );
        assert_eq!(
            arp::parse_reply(&reply(mac, 0xC0A8_0105, 2, [0x08, 0x00]), 0xC0A8_0105),
            None,
            "not an ARP frame at all"
        );
        assert_eq!(arp::parse_reply(&[0u8; 20], 0xC0A8_0105), None, "truncated");
    }

    #[test]
    fn an_all_zero_or_broadcast_mac_is_not_an_identity() {
        assert_eq!(arp::format_mac([0; 6]), None);
        assert_eq!(arp::format_mac([0xff; 6]), None);
        assert_eq!(
            arp::format_mac([0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22]).as_deref(),
            Some("aa:bb:cc:00:11:22")
        );
    }

    /// /proc/net/route stores addresses as little-endian hex.
    const PROC_NET_ROUTE: &str =
        "Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0102A8C0	0003	0	0	100	00000000	0	0	0
eth0	0002A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
wlan0	0000A8C0	00000000	0001	0	0	600	0000FFFF	0	0	0
";

    #[test]
    fn the_most_specific_route_wins() {
        // 192.168.2.5 is inside eth0's /24 and wlan0's /16; the /24 wins.
        assert_eq!(
            arp::route_iface_for(PROC_NET_ROUTE, 0xC0A8_0205).as_deref(),
            Some("eth0")
        );
        // 192.168.9.5 only matches wlan0's /16.
        assert_eq!(
            arp::route_iface_for(PROC_NET_ROUTE, 0xC0A8_0905).as_deref(),
            Some("wlan0")
        );
        // Anything else falls back to the default route's device.
        assert_eq!(
            arp::route_iface_for(PROC_NET_ROUTE, 0x0808_0808).as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn a_malformed_routing_table_yields_no_interface() {
        assert_eq!(arp::route_iface_for("", 0xC0A8_0205), None);
        assert_eq!(
            arp::route_iface_for(
                "Iface	Destination
",
                0xC0A8_0205
            ),
            None
        );
    }
}
