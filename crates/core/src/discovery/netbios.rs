//! `netbios`: NBNS Node Status queries (UDP 137) against candidate
//! addresses. Windows and Samba hosts answer with their registered names —
//! a strong, stable identity signal for exactly the devices that don't do
//! mDNS. Pure std UDP, unprivileged.

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::{ScanContext, Strategy, StrategyOutcome};
use crate::model::{NameSource, Observation};

/// How many hosts to probe at once.
const MAX_PARALLEL: usize = 32;

pub struct Netbios {
    pub per_host_timeout: Duration,
    pub max_candidates: usize,
}

impl Default for Netbios {
    fn default() -> Self {
        Netbios {
            per_host_timeout: Duration::from_millis(900),
            max_candidates: 128,
        }
    }
}

impl Strategy for Netbios {
    fn id(&self) -> &'static str {
        "netbios"
    }

    fn wave(&self) -> u8 {
        2
    }

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome {
        if ctx.candidates.is_empty() {
            return StrategyOutcome::ok(Vec::new());
        }
        // One upfront bind so "no UDP sockets at all" is reported as a
        // problem rather than silently returning nothing.
        if let Err(e) = UdpSocket::bind("0.0.0.0:0") {
            return StrategyOutcome::failed(format!("UDP socket unavailable: {e}"));
        }
        let candidates: Vec<String> = ctx
            .candidates
            .iter()
            .filter(|ip| crate::util::ipv4_in_network_of(ip, &ctx.iface))
            .take(self.max_candidates)
            .cloned()
            .collect();
        if candidates.is_empty() {
            return StrategyOutcome::ok(Vec::new());
        }

        // Probed concurrently: most hosts do not run NBNS at all, so a
        // sequential walk spends its whole budget waiting out timeouts —
        // 128 candidates at 900 ms each is nearly two minutes.
        let timeout = self.per_host_timeout;
        let (tx, rx) = mpsc::channel::<Observation>();
        let candidates = std::sync::Arc::new(candidates);
        let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let id = self.id();
        thread::scope(|s| {
            for _ in 0..MAX_PARALLEL.min(candidates.len()) {
                let (tx, candidates, next) = (tx.clone(), candidates.clone(), next.clone());
                s.spawn(move || loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if i >= candidates.len() {
                        break;
                    }
                    let ip = &candidates[i];
                    if let Some(name) = query_node_status(ip, timeout) {
                        let _ = tx.send(Observation {
                            ip: ip.clone(),
                            mac: None,
                            name: Some((NameSource::Netbios, name)),
                            vendor: None,
                            source: id.to_string(),
                            confidence: 0.85,
                        });
                    }
                });
            }
        });
        drop(tx);
        StrategyOutcome::ok(rx.into_iter().collect())
    }
}

/// Ask one host for its NetBIOS names. Each caller gets its own socket so
/// replies cannot be confused between concurrent probes.
fn query_node_status(ip: &str, timeout: Duration) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let trnid = (ip_last_octet(ip) as u16) | 0x4200;
    let addr = format!("{ip}:137").parse::<std::net::SocketAddr>().ok()?;
    sock.send_to(&build_node_status_request(trnid), addr).ok()?;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let mut buf = [0u8; 1024];
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from.ip().to_string() != ip {
                    continue; // stray packet
                }
                if n >= 12 && buf[0] == (trnid >> 8) as u8 && buf[1] == (trnid & 0xff) as u8 {
                    return parse_node_status_names(&buf[..n]).into_iter().next();
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    None
}

fn ip_last_octet(ip: &str) -> u8 {
    crate::util::parse_ipv4(ip)
        .map(|a| (a & 0xff) as u8)
        .unwrap_or(1)
}

/// Build an NBSTAT (node status) request for the wildcard name `*`
/// (RFC 1002 §4.2.17). 50 bytes: 12-byte header, 34-byte QUESTION_NAME,
/// 4 bytes of QUESTION_TYPE/CLASS.
pub fn build_node_status_request(trnid: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&trnid.to_be_bytes());
    // A unicast node status request carries opcode 0 and no flag bits — in
    // particular not B (0x0010), which marks a broadcast query.
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                        // QUESTION_NAME is a single 32-byte label holding the first-level
                                        // encoding of "*" (padded with NULs to 16 bytes), then the root label.
    p.push(0x20);
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for b in raw {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0F));
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x21]); // QUESTION_TYPE = NBSTAT
    p.extend_from_slice(&[0x00, 0x01]); // QUESTION_CLASS = IN
    p
}

/// Advance past a NetBIOS name at `off`, handling both the length-prefixed
/// label form and DNS-style compression pointers. Returns the offset of the
/// byte after the name.
fn skip_name(data: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *data.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Two-byte pointer; we only need the length, not the target.
            return (off + 1 < data.len()).then_some(off + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        off = off.checked_add(1 + len)?;
    }
}

/// Parse the names out of an NBSTAT response. Returns the best machine name.
pub fn parse_node_status_names(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Vec::new(); // not a response
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return Vec::new();
    }
    // RFC 1002 §4.2.18 responses carry QDCOUNT = 0 and a full RR_NAME, but
    // some stacks echo the question first, so walk the sections rather than
    // assuming a fixed layout.
    let mut off = 12;
    for _ in 0..qdcount {
        let Some(next) = skip_name(data, off) else {
            return Vec::new();
        };
        off = next + 4; // QUESTION_TYPE + QUESTION_CLASS
    }
    let Some(next) = skip_name(data, off) else {
        return Vec::new();
    };
    off = next;
    // RR: type (2) class (2) ttl (4) rdlength (2)
    if off + 10 > data.len() {
        return Vec::new();
    }
    let rtype = u16::from_be_bytes([data[off], data[off + 1]]);
    let rdlen = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
    off += 10;
    if rtype != 0x0021 || rdlen < 1 || off + rdlen > data.len() {
        return Vec::new();
    }
    let rdata = &data[off..off + rdlen];
    let num_names = rdata[0] as usize;
    let mut names = Vec::new();
    for i in 0..num_names {
        let base = 1 + i * 18;
        if base + 18 > rdata.len() {
            break;
        }
        let raw = &rdata[base..base + 15];
        let suffix = rdata[base + 15];
        let entry_flags = u16::from_be_bytes([rdata[base + 16], rdata[base + 17]]);
        // The G bit marks a group name (workgroup/domain). Every host in the
        // group answers with it, so it can never be a device identity.
        if entry_flags & 0x8000 != 0 {
            continue;
        }
        let name: String = String::from_utf8_lossy(raw)
            .trim_end_matches([' ', '\0'])
            .to_string();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
            continue;
        }
        // Suffix 0x00 = workstation name; prefer it, else record others.
        names.push((suffix == 0x00, name));
    }
    // Sort workstation names first, keep original order otherwise.
    names.sort_by_key(|(primary, _)| !primary);
    names.into_iter().map(|(_, n)| n).take(2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First-level encoding of the wildcard name `*`: 32 characters, as it
    /// appears on the wire (RFC 1001 §4.1).
    const ENCODED_WILDCARD: &[u8] = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// One 18-byte NODE_NAME entry: 15-byte space-padded name, 1-byte suffix,
    /// 2-byte NAME_FLAGS (RFC 1002 §4.2.18).
    fn name_entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        assert_eq!(e.len(), 15, "test name must fit the 15-byte field");
        e.push(suffix);
        e.extend_from_slice(&flags.to_be_bytes());
        e
    }

    /// A NODE STATUS RESPONSE exactly as RFC 1002 §4.2.18 specifies it:
    /// QDCOUNT=0, ANCOUNT=1, and the answer RR carries the *full* encoded
    /// name, not a compression pointer.
    fn node_status_response(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0x4242u16.to_be_bytes()); // NAME_TRN_ID
        p.extend_from_slice(&0x8400u16.to_be_bytes()); // response + authoritative
        p.extend_from_slice(&0x0000u16.to_be_bytes()); // QDCOUNT = 0
        p.extend_from_slice(&0x0001u16.to_be_bytes()); // ANCOUNT = 1
        p.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT
        p.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT
        p.push(0x20); // RR_NAME: length byte
        p.extend_from_slice(ENCODED_WILDCARD);
        p.push(0x00); // root label
        p.extend_from_slice(&0x0021u16.to_be_bytes()); // NBSTAT
        p.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
        p.extend_from_slice(&0u32.to_be_bytes()); // TTL

        let mut rdata = vec![entries.len() as u8];
        for e in entries {
            rdata.extend_from_slice(e);
        }
        rdata.extend_from_slice(&[0u8; 46]); // STATISTICS
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(&rdata);
        p
    }

    #[test]
    fn request_is_a_50_byte_rfc1002_node_status_query() {
        let q = build_node_status_request(0x4242);
        assert_eq!(q.len(), 50, "header 12 + name 34 + type/class 4");
        assert_eq!(&q[0..2], &[0x42, 0x42], "NAME_TRN_ID");
        assert_eq!(&q[2..4], &[0x00, 0x00], "unicast node status: no flags set");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT = 1");
        assert_eq!(&q[6..12], &[0, 0, 0, 0, 0, 0], "AN/NS/AR counts = 0");
        assert_eq!(q[12], 0x20, "encoded name is a 32-byte label");
        assert_eq!(&q[13..45], ENCODED_WILDCARD);
        assert_eq!(q[45], 0x00, "root label terminates the name");
        assert_eq!(&q[46..48], &[0x00, 0x21], "QUESTION_TYPE = NBSTAT");
        assert_eq!(&q[48..50], &[0x00, 0x01], "QUESTION_CLASS = IN");
    }

    #[test]
    fn parses_workstation_name_from_a_spec_shaped_response() {
        let p = node_status_response(&[name_entry("DESKTOP-ABC123", 0x00, 0x0400)]);
        let names = parse_node_status_names(&p);
        assert_eq!(names, vec!["DESKTOP-ABC123".to_string()]);
    }

    #[test]
    fn prefers_the_unique_workstation_name_over_the_workgroup() {
        // The group entry is listed first; the workstation name must still win.
        let p = node_status_response(&[
            name_entry("WORKGROUP", 0x00, 0x8400), // G bit set = group
            name_entry("DESKTOP-ABC123", 0x00, 0x0400),
        ]);
        let names = parse_node_status_names(&p);
        assert_eq!(
            names.first().map(String::as_str),
            Some("DESKTOP-ABC123"),
            "a group name must never be used as a device identity"
        );
        assert!(
            !names.iter().any(|n| n == "WORKGROUP"),
            "group names are shared across hosts and must be discarded"
        );
    }

    #[test]
    fn tolerates_a_response_that_echoes_the_question() {
        // Some stacks echo the question section (QDCOUNT=1) before the answer.
        let mut p = node_status_response(&[name_entry("ECHOED-HOST", 0x00, 0x0400)]);
        let tail = p.split_off(12);
        p[4..6].copy_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
        let mut question = vec![0x20];
        question.extend_from_slice(ENCODED_WILDCARD);
        question.push(0x00);
        question.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
        p.extend_from_slice(&question);
        p.extend_from_slice(&tail);
        assert_eq!(
            parse_node_status_names(&p),
            vec!["ECHOED-HOST".to_string()],
            "the question section must be skipped, not assumed absent"
        );
    }

    #[test]
    fn ignores_queries() {
        let q = build_node_status_request(1);
        assert!(parse_node_status_names(&q).is_empty());
    }

    #[test]
    fn ignores_truncated_and_malformed_input() {
        assert!(parse_node_status_names(&[]).is_empty());
        assert!(parse_node_status_names(&[0u8; 11]).is_empty());
        let mut p = node_status_response(&[name_entry("TRUNCATED", 0x00, 0x0400)]);
        p.truncate(40);
        assert!(parse_node_status_names(&p).is_empty());
    }
}
