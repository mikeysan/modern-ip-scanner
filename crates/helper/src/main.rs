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

use std::io::{BufRead, BufReader, Write};

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
    } else if let Some(pipe) = args
        .iter()
        .position(|a| a == "--pipe")
        .map(|i| args[i + 1].clone())
    {
        let code = serve_pipe(&pipe);
        std::process::exit(code);
    } else {
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
    let mut count = 0;
    for part in s.split('.') {
        part.parse::<u8>().ok()?;
        count += 1;
    }
    (count == 4).then_some(s)
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
                let s: String = mac[..6]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                return Some(s);
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
    use std::io::ErrorKind;

    /// Resolve `ip` on the default interface using a raw AF_PACKET socket:
    /// broadcast an ARP request, listen for the reply. Root-only, which is
    /// exactly why this lives in the helper.
    pub fn resolve(ip: &str) -> Option<String> {
        let dst_ip: u32 = ip.parse().ok()?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ARP as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            eprintln!("laninv-helper: AF_PACKET socket failed");
            return None;
        }
        let result = (|| {
            let (ifname, src_ip, src_mac) = route_info_for(dst_ip)?;
            let ifindex = unsafe {
                let mut req: libc::ifreq = std::mem::zeroed();
                for (i, b) in ifname.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
                    req.ifr_name[i] = b as libc::c_char;
                }
                if libc::ioctl(fd, libc::SIOCGIFINDEX, &mut req) < 0 {
                    return None;
                }
                req.ifr_ifindex
            };

            // Ethernet + ARP request frame.
            let mut frame = [0u8; 42];
            frame[0..6].copy_from_slice(&[0xff; 6]); // dst broadcast
            frame[6..12].copy_from_slice(&src_mac);
            frame[12..14].copy_from_slice(&(libc::ETH_P_ARP as u16).to_be_bytes());
            frame[14..16].copy_from_slice(&[0x00, 0x01]); // ethernet
            frame[16..18].copy_from_slice(&[0x08, 0x00]); // IPv4
            frame[18] = 6; // hlen
            frame[19] = 4; // plen
            frame[20..22].copy_from_slice(&[0x00, 0x01]); // request
            frame[22..28].copy_from_slice(&src_mac);
            frame[28..32].copy_from_slice(&src_ip.to_be_bytes());
            frame[34..38].copy_from_slice(&dst_ip.to_be_bytes());

            let mut sockaddr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as libc::sa_family_t,
                sll_protocol: (libc::ETH_P_ARP as u16).to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 1,
                sll_pkttype: 0,
                sll_halen: 6,
                sll_addr: [0xff; 8],
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

            // Listen up to 1s for the ARP reply for our target.
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
                let n =
                    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n < 42 {
                    continue;
                }
                // Ethernet ARP reply: ethertype 0x0806, opcode 2.
                if buf[12] != 0x08 || buf[13] != 0x06 || buf[20] != 0x00 || buf[21] != 0x02 {
                    continue;
                }
                let sender_ip = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
                if sender_ip == dst_ip {
                    let mac: String = buf[22..28]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    let _ = sockaddr.sll_halen;
                    return Some(mac);
                }
            }
            None
        })();
        unsafe { libc::close(fd) };
        result
    }

    /// Find the interface that routes to `dst`: read /proc/net/route, prefer
    /// the most specific on-link match, fall back to the default route's dev.
    fn route_info_for(dst: u32) -> Option<(String, u32, [u8; 6])> {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        let mut best: Option<(u8, String)> = None;
        for (i, line) in text.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 {
                continue;
            }
            let Ok(mask_hex) = u32::from_str_radix(cols[7], 16) else {
                continue;
            };
            let Ok(dest_hex) = u32::from_str_radix(cols[1], 16) else {
                continue;
            };
            let mask = mask_hex.swap_bytes();
            let dest = dest_hex.swap_bytes();
            if dst & mask == dest && !cols[0].is_empty() {
                let prefix = mask.count_ones() as u8;
                if best.as_ref().map(|(p, _)| prefix > *p).unwrap_or(true) {
                    best = Some((prefix, cols[0].to_string()));
                }
            }
        }
        let iface = best.map(|(_, i)| i)?;
        let ip = interface_ipv4(&iface)?;
        let mac = interface_mac(&iface)?;
        Some((iface, ip, mac))
    }

    fn interface_ipv4(iface: &str) -> Option<u32> {
        let text = std::fs::read_to_string("/proc/net/fib_trie")?;
        // Simpler: ioctl SIOCGIFADDR on a UDP socket.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return parse_fib_trie(&text, iface);
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        for (i, b) in iface.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
            req.ifr_name[i] = b as libc::c_char;
        }
        let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFADDR, &mut req) };
        let out = if rc == 0 {
            let addr = unsafe { *req.ifr_ifru.ifru_addr };
            if addr.sa_family as libc::c_int == libc::AF_INET {
                let a = unsafe { &*(req.ifr_ifru.ifru_addr as *const libc::sockaddr_in) };
                Some(u32::from_be(a.sin_addr.s_addr))
            } else {
                None
            }
        } else {
            None
        };
        unsafe { libc::close(fd) };
        out.or_else(|| parse_fib_trie(&text, iface))
    }

    fn parse_fib_trie(_text: &str, _iface: &str) -> Option<u32> {
        None // fallback not implemented; ioctl path is the real one
    }

    fn interface_mac(iface: &str) -> Option<[u8; 6]> {
        let path = format!("/sys/class/net/{iface}/address");
        let mac = std::fs::read_to_string(path).ok()?;
        let bytes: Vec<u8> = mac
            .trim()
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        if bytes.len() == 6 {
            Some(bytes.try_into().unwrap())
        } else {
            None
        }
    }
}
