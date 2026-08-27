//! `mdns`: multicast DNS discovery on 224.0.0.251:5353.
//!
//! Sends a DNS-SD service enumeration query plus common service-type
//! queries, then listens for a few seconds collecting A records (hostname →
//! IP) and SRV/PTR hints. Pure std UDP sockets, unprivileged.

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use super::{ScanContext, Strategy, StrategyOutcome};
use crate::model::{NameSource, Observation};

const MDNS_PORT: u16 = 5353;

pub struct Mdns {
    pub listen: Duration,
}

impl Default for Mdns {
    fn default() -> Self {
        Mdns {
            listen: Duration::from_secs(3),
        }
    }
}

impl Strategy for Mdns {
    fn id(&self) -> &'static str {
        "mdns"
    }

    fn wave(&self) -> u8 {
        1
    }

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome {
        let sock = match bind_mdns_socket() {
            Ok(s) => s,
            Err(e) => {
                return StrategyOutcome::failed(format!(
                    "could not share UDP port {MDNS_PORT} ({e}); mDNS replies are unreachable"
                ))
            }
        };
        if let Err(e) = super::pin_multicast_egress(&sock, &ctx.iface) {
            return StrategyOutcome::failed(format!(
                "could not send mDNS from {} ({e})",
                ctx.iface.name
            ));
        }
        // Join the multicast group on each interface address so we receive
        // multicast responses (mDNS replies go to 224.0.0.251, not to us).
        let group: std::net::Ipv4Addr = "224.0.0.251".parse().unwrap();
        for cidr in &ctx.iface.ipv4 {
            if let Ok(ip) = cidr.addr.parse::<std::net::Ipv4Addr>() {
                sock.join_multicast_v4(&group, &ip).ok();
            }
        }
        let group: std::net::SocketAddr = "224.0.0.251:5353".parse().unwrap();
        let queries = [
            "_services._dns-sd._udp.local",
            "_googlecast._tcp.local",
            "_ipp._tcp.local",
            "_http._tcp.local",
        ];
        for (i, q) in queries.iter().enumerate() {
            let packet = build_query(i as u16, q);
            let _ = sock.send_to(&packet, group);
        }

        let deadline = Instant::now() + self.listen;
        sock.set_read_timeout(Some(Duration::from_millis(250))).ok();
        let mut records = DnsRecords::default();
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let mut buf = [0u8; 1500];
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    match from.ip() {
                        std::net::IpAddr::V4(_) => {}
                        std::net::IpAddr::V6(_) => continue, // v1 is IPv4-only
                    }
                    match parse_dns_message(&buf[..n]) {
                        Ok(msg) => records.absorb(&msg),
                        Err(_) => continue,
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    continue;
                }
                Err(_) => break,
            }
        }

        let mut observations = Vec::new();
        for (hostname, ips) in &records.a_records {
            let Some(name) = hostname.strip_suffix(".local").or(Some(hostname.as_str())) else {
                continue;
            };
            for ip in ips {
                if !crate::util::ipv4_in_network_of(ip, &ctx.iface) {
                    continue;
                }
                let vendor = records
                    .txt_models
                    .iter()
                    .find(|(h, _)| h == hostname)
                    .map(|(_, m)| m.clone());
                observations.push(Observation {
                    ip: ip.clone(),
                    mac: None,
                    name: Some((NameSource::Mdns, name.to_string())),
                    vendor,
                    source: self.id().to_string(),
                    confidence: 0.9,
                });
            }
        }
        StrategyOutcome::ok(observations)
    }
}

/// Bind the mDNS listening socket to port 5353.
///
/// Responders answer to the group address on port 5353, so a socket bound to
/// any other port hears nothing. Desktops routinely already have a listener
/// there (Bonjour, Chrome, Edge, Docker), so the port must be *shared* rather
/// than owned: SO_REUSEADDR everywhere, plus SO_REUSEPORT on unix. There is
/// deliberately no ephemeral-port fallback — a socket that cannot receive
/// replies is a failed strategy, not a degraded one.
fn bind_mdns_socket() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    let addr: std::net::SocketAddr = (std::net::Ipv4Addr::UNSPECIFIED, MDNS_PORT).into();
    sock.bind(&addr.into())?;
    let sock: UdpSocket = sock.into();
    sock.set_multicast_loop_v4(true).ok();
    Ok(sock)
}

fn build_query(id: u16, qname: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(qname.len() + 18);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // flags: standard query
    p.extend_from_slice(&[0x00, 0x01]); // qdcount
    p.extend_from_slice(&[0x00, 0x00]); // ancount
    p.extend_from_slice(&[0x00, 0x00]); // nscount
    p.extend_from_slice(&[0x00, 0x00]); // arcount
    for label in qname.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0x00, 0x0c]); // QTYPE PTR
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    p
}

// ---- minimal DNS parser (with compression pointers) ----

#[derive(Default, Debug)]
pub struct DnsRecords {
    /// hostname (as written, e.g. `printer.local`) → IPv4 string list.
    pub a_records: Vec<(String, Vec<String>)>,
    /// SRV targets seen, for potential future use.
    pub srv_targets: Vec<String>,
    /// TXT `model=` / `device_description=` values per hostname.
    pub txt_models: Vec<(String, String)>,
}

impl DnsRecords {
    pub fn absorb(&mut self, msg: &DnsMessage) {
        for rr in &msg.answers {
            match rr.rtype {
                1 => {
                    if rr.rdata.len() == 4 {
                        let ip = format!(
                            "{}.{}.{}.{}",
                            rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3]
                        );
                        if let Some((_, ips)) =
                            self.a_records.iter_mut().find(|(h, _)| *h == rr.name)
                        {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        } else {
                            self.a_records.push((rr.name.clone(), vec![ip]));
                        }
                    }
                }
                33 => {
                    // SRV: prio(2) weight(2) port(2) target(compressed name)
                    if let Some(target) = read_name(rr.rdata_off + 6, &rr.full_message) {
                        self.srv_targets.push(target);
                    }
                }
                16 => {
                    // TXT: length-prefixed strings.
                    if let Some(model) = parse_txt_model(&rr.rdata) {
                        self.txt_models.push((rr.name.clone(), model));
                    }
                }
                _ => {}
            }
        }
    }
}

fn parse_txt_model(rdata: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&rdata[i..i + len]).into_owned();
        i += len;
        for key in ["model=", "device_description=", "am="] {
            if let Some(v) = s.strip_prefix(key) {
                let v = v.trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

pub struct DnsMessage {
    pub answers: Vec<DnsRr>,
}

pub struct DnsRr {
    pub name: String,
    pub rtype: u16,
    pub rdata: Vec<u8>,
    /// Offset of the RDATA within the full message (for compressed SRV names).
    pub rdata_off: usize,
    /// The full message, kept for compression-aware re-reads.
    pub full_message: Vec<u8>,
}

pub fn parse_dns_message(msg: &[u8]) -> Result<DnsMessage, &'static str> {
    if msg.len() < 12 {
        return Err("too short");
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let arcount = u16::from_be_bytes([msg[10], msg[11]]);
    let mut off = 12;
    // Skip questions.
    for _ in 0..qdcount {
        off = skip_name(off, msg).ok_or("bad question name")?;
        off = off.checked_add(4).ok_or("overflow")?;
    }
    // mDNS puts the useful A/SRV/TXT records in the ADDITIONAL section, so
    // parse answers plus additional records.
    let mut answers = Vec::new();
    for _ in 0..(ancount + arcount) {
        let name = read_name(off, msg).ok_or("bad name")?;
        off = skip_name(off, msg).ok_or("bad name")?;
        if off + 10 > msg.len() {
            return Err("truncated rr");
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        let rdata_off = off + 10;
        if rdata_off + rdlen > msg.len() {
            return Err("truncated rdata");
        }
        answers.push(DnsRr {
            name,
            rtype,
            rdata: msg[rdata_off..rdata_off + rdlen].to_vec(),
            rdata_off,
            full_message: msg.to_vec(),
        });
        off = rdata_off + rdlen;
    }
    Ok(DnsMessage { answers })
}

fn skip_name(mut off: usize, msg: &[u8]) -> Option<usize> {
    let mut jumps = 0;
    while off < msg.len() {
        let len = msg[off] as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            // compression pointer: 2 bytes total
            return Some(off + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        off += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

fn read_name(off: usize, msg: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = off;
    let mut followed = false;
    let mut jumps = 0;
    while pos < msg.len() {
        let len = msg[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | msg[pos + 1] as usize;
            if !followed {
                // Caller continues after the first pointer.
                followed = true;
            }
            pos = ptr;
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            continue;
        }
        if len & 0xC0 != 0 || pos + 1 + len > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[pos + 1..pos + 1 + len]).into_owned());
        pos += 1 + len;
    }
    Some(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_port_5353_even_when_another_socket_already_holds_it() {
        // Every desktop that runs Bonjour, Chrome, Edge or Docker already has
        // a listener on 5353. Losing the race for that port means losing every
        // multicast reply, so the bind must share the port, not fall back to
        // an ephemeral one.
        let squatter = bind_mdns_socket().expect("first bind should succeed");
        assert_eq!(squatter.local_addr().unwrap().port(), 5353);

        let ours = bind_mdns_socket().expect("must still bind while 5353 is held");
        assert_eq!(
            ours.local_addr().unwrap().port(),
            5353,
            "an ephemeral port cannot receive replies sent to 224.0.0.251:5353"
        );
    }

    #[test]
    fn builds_valid_query() {
        let q = build_query(7, "_services._dns-sd._udp.local");
        assert_eq!(&q[..2], &[0x00, 0x07]);
        // header 12 + name + root + type/class 4
        assert_eq!(q.len(), 12 + "_services._dns-sd._udp.local".len() + 2 + 4);
        assert_eq!(&q[12..13], &[9]); // first label length "_services"
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x0c, 0x00, 0x01]);
    }

    #[test]
    fn parses_response_with_a_record_and_compression() {
        // Header: 1 answer.
        let mut msg = vec![0x00, 0x01, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        // Name: printer.local
        for label in ["printer", "local"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        // Type A, class IN, ttl, rdlen 4, rdata 192.168.1.42
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
        msg.extend_from_slice(&[0x00, 0x04]);
        msg.extend_from_slice(&[192, 168, 1, 42]);

        let parsed = parse_dns_message(&msg).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "printer.local");
        assert_eq!(parsed.answers[0].rtype, 1);

        let mut records = DnsRecords::default();
        records.absorb(&parsed);
        assert_eq!(records.a_records[0].0, "printer.local");
        assert_eq!(records.a_records[0].1, vec!["192.168.1.42".to_string()]);
    }

    #[test]
    fn parses_txt_model() {
        // TXT rdata: one string "model=Deskjet 2600"
        let s = b"model=Deskjet 2600";
        let mut rdata = vec![s.len() as u8];
        rdata.extend_from_slice(s);
        assert_eq!(parse_txt_model(&rdata).as_deref(), Some("Deskjet 2600"));
    }
}
