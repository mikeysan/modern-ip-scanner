//! Small shared helpers: time formatting and IPv4 arithmetic.

/// Current unix time in whole seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format a unix timestamp (seconds) as local-ish `YYYY-MM-DD HH:MM` in UTC.
/// We avoid a chrono dependency; the CLI/GUI treat this as display-only.
pub fn fmt_time(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Days-from-civil inverse (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse a dotted-quad IPv4 string into a host-order u32.
pub fn parse_ipv4(s: &str) -> Option<u32> {
    s.trim().parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

/// Format a host-order u32 as dotted quad.
pub fn format_ipv4(addr: u32) -> String {
    std::net::Ipv4Addr::from(addr).to_string()
}

/// The mask for an on-link prefix length, host order.
///
/// A prefix of 0 is special-cased because shifting a `u32` by 32 is undefined
/// behaviour in Rust and panics in debug builds.
pub fn netmask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    }
}

/// True if `ip` (dotted quad) is inside `network`/`prefix_len`.
pub fn ipv4_in_network(ip: &str, network: u32, prefix_len: u8) -> bool {
    match parse_ipv4(ip) {
        Some(a) => {
            let mask = netmask(prefix_len);
            a & mask == network & mask
        }
        None => false,
    }
}

/// Generate every address in `network`/`prefix_len` (host order), excluding
/// the network address itself. Only used by the privileged full-ARP strategy.
pub fn enumerate_network(network: u32, prefix_len: u8) -> Vec<u32> {
    let count = if prefix_len >= 31 {
        u32::from(prefix_len == 32)
    } else {
        1u32 << (32 - prefix_len as u32)
    };
    let mask = netmask(prefix_len);
    (1..count).map(|i| (network & mask) + i).collect()
}

/// True if `ip` (dotted quad) is inside any of the interface's on-link
/// networks.
pub fn ipv4_in_network_of(ip: &str, iface: &crate::model::Interface) -> bool {
    iface.ipv4.iter().any(|c| match parse_ipv4(&c.addr) {
        Some(a) => {
            let mask = netmask(c.prefix);
            parse_ipv4(ip).is_some_and(|i| i & mask == a & mask)
        }
        None => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_covers_both_ends_of_the_prefix_range() {
        // The /0 case is the whole reason this is not a one-liner: shifting a
        // u32 by 32 is undefined and panics in debug builds.
        assert_eq!(netmask(0), 0);
        assert_eq!(netmask(8), 0xFF00_0000);
        assert_eq!(netmask(24), 0xFFFF_FF00);
        assert_eq!(netmask(32), u32::MAX);
    }

    #[test]
    fn ipv4_roundtrip() {
        assert_eq!(parse_ipv4("192.168.1.10"), Some(0xC0A8_010A));
        assert_eq!(format_ipv4(0xC0A8_010A), "192.168.1.10");
        assert_eq!(parse_ipv4("192.168.1"), None);
        assert_eq!(parse_ipv4("192.168.1.256"), None);
        assert_eq!(parse_ipv4("192.168.01.10"), None);
        // Rust's integer parser accepts a leading '+', so the hand-rolled
        // octet loop used to read "+1.2.3.4" as 1.2.3.4. Ipv4Addr does not.
        assert_eq!(parse_ipv4("+1.2.3.4"), None);
    }

    #[test]
    fn membership() {
        assert!(ipv4_in_network("192.168.1.77", 0xC0A8_0100, 24));
        assert!(!ipv4_in_network("192.168.2.77", 0xC0A8_0100, 24));
    }

    #[test]
    fn enumeration_excludes_network_address() {
        let addrs = enumerate_network(0xC0A8_0100, 30);
        assert_eq!(addrs, vec![0xC0A8_0101, 0xC0A8_0102, 0xC0A8_0103]);
    }

    #[test]
    fn time_format() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00");
        assert_eq!(fmt_time(1_753_000_000), "2025-07-20 08:26");
    }
}
