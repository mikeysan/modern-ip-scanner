//! `ssdp`: UPnP/SSDP M-SEARCH discovery on 239.255.255.250:1900.
//!
//! Sends M-SEARCH requests, then collects HTTPU responses. Each responding
//! device is asked for the description document it advertises in LOCATION,
//! which is where its human-readable `friendlyName` lives. SERVER provides a
//! vendor hint. Unprivileged: UDP multicast plus a plain HTTP GET.

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use super::{ScanContext, Strategy, StrategyOutcome};
use crate::model::{NameSource, Observation};

pub struct Ssdp {
    pub listen: Duration,
}

impl Default for Ssdp {
    fn default() -> Self {
        Ssdp {
            listen: Duration::from_secs(3),
        }
    }
}

impl Strategy for Ssdp {
    fn id(&self) -> &'static str {
        "ssdp"
    }

    fn wave(&self) -> u8 {
        1
    }

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => return StrategyOutcome::failed(format!("SSDP socket unavailable: {e}")),
        };
        if let Err(e) = super::pin_multicast_egress(&sock, &ctx.iface) {
            return StrategyOutcome::failed(format!(
                "could not send SSDP from {} ({e})",
                ctx.iface.name
            ));
        }
        let group: std::net::SocketAddr = "239.255.255.250:1900".parse().unwrap();
        let searches = [("ssdp:all", 2), ("upnp:rootdevice", 1)];
        for (st, mx) in &searches {
            let req = format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {mx}\r\nST: {st}\r\nUSER-AGENT: laninv/0.1\r\n\r\n"
            );
            let _ = sock.send_to(req.as_bytes(), group);
        }

        let deadline = Instant::now() + self.listen;
        sock.set_read_timeout(Some(Duration::from_millis(250))).ok();
        let mut responses: Vec<(String, HttpUResponse)> = Vec::new();
        loop {
            if Instant::now() >= deadline {
                break;
            }
            let mut buf = [0u8; 2048];
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let ip = match from.ip() {
                        std::net::IpAddr::V4(v4) => v4.to_string(),
                        std::net::IpAddr::V6(_) => continue,
                    };
                    if let Some(resp) = parse_httpu(&buf[..n]) {
                        responses.push((ip, resp));
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    continue;
                }
                Err(_) => break,
            }
        }

        // One entry per device (USN), not per response.
        let mut seen_usn: Vec<String> = Vec::new();
        let mut devices: Vec<(String, HttpUResponse)> = Vec::new();
        for (ip, resp) in responses {
            if !crate::util::ipv4_in_network_of(&ip, &ctx.iface) {
                continue;
            }
            let usn = resp.usn.clone().unwrap_or_else(|| format!("ip:{ip}"));
            if seen_usn.contains(&usn) {
                continue;
            }
            seen_usn.push(usn);
            devices.push((ip, resp));
        }

        // Ask each device for its description in parallel; this is where the
        // human-readable name comes from.
        let names: Vec<Option<String>> = thread::scope(|s| {
            let handles: Vec<_> = devices
                .iter()
                .map(|(_, resp)| {
                    let location = resp.location.clone();
                    s.spawn(move || location.as_deref().and_then(fetch_friendly_name))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or(None))
                .collect()
        });

        let observations = devices
            .into_iter()
            .zip(names)
            .map(|((ip, resp), friendly)| Observation {
                ip,
                mac: None,
                name: ssdp_name(friendly),
                vendor: resp.server.clone().or_else(|| resp.location_host()),
                source: self.id().to_string(),
                confidence: 0.75,
            })
            .collect();
        StrategyOutcome::ok(observations)
    }
}

/// How long a single device-description fetch may take.
const DESC_TIMEOUT: Duration = Duration::from_millis(1500);
/// Device descriptions are small; refuse to read more than this.
const DESC_MAX_BYTES: usize = 64 * 1024;

/// Split an SSDP `LOCATION` URL into (authority, path).
pub(crate) fn parse_location(url: &str) -> Option<(String, String)> {
    let rest = url.trim().strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let authority = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    Some((authority, path.to_string()))
}

/// Pull `<friendlyName>` out of a UPnP device description document.
pub(crate) fn extract_friendly_name(xml: &str) -> Option<String> {
    const OPEN: &str = "<friendlyName>";
    const CLOSE: &str = "</friendlyName>";
    let start = xml.find(OPEN)? + OPEN.len();
    let end = xml[start..].find(CLOSE)? + start;
    let name = xml[start..end].trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Fetch a device's description document and read its friendly name.
///
/// A plain HTTP GET of the document the device itself advertises in
/// `LOCATION` — the standard way a UPnP client learns a device's name.
/// Bounded in time and size; any failure just means no name.
fn fetch_friendly_name(location: &str) -> Option<String> {
    use std::io::{Read, Write};

    let (authority, path) = parse_location(location)?;
    // Numeric addresses only: LAN device descriptions are advertised by IP,
    // and this avoids a DNS lookup on a hostile string.
    let addr: std::net::SocketAddr = authority.parse().ok()?;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, DESC_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(DESC_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(DESC_TIMEOUT)).ok()?;
    // HTTP/1.1, not 1.0: Chromecast-family device servers (including the TVs
    // that embed it) simply never answer a 1.0 request. `Connection: close`
    // keeps read-to-EOF working without needing to parse Content-Length.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: laninv/0.1\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut body = Vec::new();
    let mut buf = [0u8; 4096];
    while body.len() < DESC_MAX_BYTES {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    extract_friendly_name(&String::from_utf8_lossy(&body))
}

/// The human name for an SSDP device, if one can be had.
///
/// The USN UUID is stable but meaningless to a person, so it is never used as
/// a name: a device without a `friendlyName` contributes vendor only and is
/// identified by its MAC instead.
pub(crate) fn ssdp_name(friendly: Option<String>) -> Option<(NameSource, String)> {
    let friendly = friendly?;
    let trimmed = friendly.trim();
    (!trimmed.is_empty()).then(|| (NameSource::Ssdp, trimmed.to_string()))
}

#[derive(Debug, Default, Clone)]
pub struct HttpUResponse {
    pub usn: Option<String>,
    pub server: Option<String>,
    pub location: Option<String>,
    pub st: Option<String>,
}

impl HttpUResponse {
    pub fn location_host(&self) -> Option<String> {
        self.location.as_ref().and_then(|loc| {
            loc.split("://")
                .nth(1)?
                .split('/')
                .next()?
                .split(':')
                .next()
                .map(|s| s.to_string())
        })
    }
}

/// Parse an HTTPU (SSDP) response: start line + headers.
pub fn parse_httpu(data: &[u8]) -> Option<HttpUResponse> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    let start = lines.next()?;
    if !start.starts_with("HTTP/1.1 200") {
        return None;
    }
    let mut out = HttpUResponse::default();
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.to_ascii_uppercase().as_str() {
            "USN" => out.usn = Some(v.into()),
            "SERVER" => out.server = Some(v.into()),
            "LOCATION" => out.location = Some(v.into()),
            "ST" | "NT" => out.st = Some(v.into()),
            _ => {}
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room Speaker</friendlyName>
    <manufacturer>Sonos, Inc.</manufacturer>
  </device>
</root>"#;

    #[test]
    fn friendly_name_is_extracted_from_a_device_description() {
        assert_eq!(
            extract_friendly_name(ROOT_DESC).as_deref(),
            Some("Living Room Speaker")
        );
    }

    #[test]
    fn friendly_name_tolerates_whitespace_and_newlines() {
        let xml = "<device><friendlyName>
   Office Printer 
</friendlyName></device>";
        assert_eq!(
            extract_friendly_name(xml).as_deref(),
            Some("Office Printer")
        );
    }

    #[test]
    fn missing_or_empty_friendly_name_yields_none() {
        assert_eq!(extract_friendly_name("<device></device>"), None);
        assert_eq!(
            extract_friendly_name("<friendlyName>   </friendlyName>"),
            None
        );
        assert_eq!(extract_friendly_name("<friendlyName>unterminated"), None);
    }

    #[test]
    fn location_splits_into_authority_and_path() {
        assert_eq!(
            parse_location("http://192.168.1.62:8200/rootDesc.xml"),
            Some(("192.168.1.62:8200".into(), "/rootDesc.xml".into()))
        );
        assert_eq!(
            parse_location("http://192.168.1.9/desc"),
            Some(("192.168.1.9:80".into(), "/desc".into())),
            "a missing port means the HTTP default"
        );
        assert_eq!(parse_location("not a url"), None);
    }

    #[test]
    fn a_uuid_is_never_used_as_a_device_name() {
        // The USN UUID is stable but unreadable; showing it in the device list
        // is worse than showing the MAC.
        assert_eq!(ssdp_name(None), None);
    }

    #[test]
    fn a_friendly_name_becomes_the_device_name() {
        assert_eq!(
            ssdp_name(Some("  Living Room Speaker  ".into())),
            Some((NameSource::Ssdp, "Living Room Speaker".into()))
        );
        assert_eq!(ssdp_name(Some("   ".into())), None);
    }

    #[test]
    fn parses_ssdp_response() {
        let resp = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: ...\r\nEXT:\r\nLOCATION: http://192.168.1.62:8200/rootDesc.xml\r\nSERVER: Linux UPnP/1.0 MiniDLNA\r\nST: upnp:rootdevice\r\nUSN: uuid:2fac2343-31f8-11b2-a56c-123456789012::upnp:rootdevice\r\n\r\n";
        let parsed = parse_httpu(resp).unwrap();
        assert_eq!(
            parsed.usn.as_deref(),
            Some("uuid:2fac2343-31f8-11b2-a56c-123456789012::upnp:rootdevice")
        );
        assert_eq!(parsed.server.as_deref(), Some("Linux UPnP/1.0 MiniDLNA"));
        assert_eq!(parsed.location_host().as_deref(), Some("192.168.1.62"));
    }

    #[test]
    fn rejects_non_200() {
        assert!(parse_httpu(b"NOTIFY * HTTP/1.1\r\nNT: blah\r\n\r\n").is_none());
    }
}
