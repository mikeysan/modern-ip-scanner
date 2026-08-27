//! Composite fingerprints for devices and networks.
//!
//! MAC randomisation means a MAC alone cannot identify a device across time,
//! so the device key combines a *name signal* (when one exists), the MAC OUI,
//! and the network where the device was first seen. The key is opaque
//! (truncated BLAKE3) and only meaningful inside the inventory database.

use crate::model::IfKind;

/// Normalize any MAC spelling (`AA-BB-CC-DD-EE-FF`, `aabbcc.ddeeff`, ...)
/// to lowercase colon-separated form. Returns None for non-MAC input.
pub fn normalize_mac(input: &str) -> Option<String> {
    let hex: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // All-zero (proxy ARP artifacts) and broadcast MACs are not identities.
    if hex == "000000000000" || hex == "ffffffffffff" {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// OUI portion of a normalized MAC (`aa:bb:cc`).
pub fn oui(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() == 6 {
        Some(parts[..3].join(":"))
    } else {
        None
    }
}

fn hash_key(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"laninv-v1\x00");
    for p in parts {
        hasher.update(p.as_bytes());
        hasher.update(b"\x00");
    }
    let hex = hasher.finalize().to_hex().to_string();
    hex[..16].to_string()
}

/// Composite network key: gateway MAC when known, else subnet; plus subnet and
/// interface kind. Stable across scans on the same network, distinct across
/// networks even when they reuse the same RFC1918 range.
pub fn network_key(gateway_mac: Option<&str>, subnet: &str, kind: IfKind) -> String {
    let gw = gateway_mac
        .map(|m| normalize_mac(m).unwrap_or_else(|| m.to_lowercase()))
        .unwrap_or_else(|| "no-gateway".to_string());
    hash_key(&[&gw, subnet, kind.as_str()])
}

/// Composite device key.
///
/// `primary_name`: best name signal (mDNS hostname, NetBIOS name, SSDP name).
/// `mac`: normalized MAC if known. `origin_network`: network key where the
/// device was first observed. When no name is known the key degrades to a
/// MAC-based identity — the aliasing layer upgrades it once a name appears.
pub fn device_key(primary_name: Option<&str>, mac: Option<&str>, origin_network: &str) -> String {
    let name_part = primary_name
        .map(|n| n.trim().to_lowercase())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            mac.map(|m| format!("mac:{m}"))
                .unwrap_or_else(|| "anonymous".to_string())
        });
    let norm_mac = mac.and_then(normalize_mac);
    let oui_part = norm_mac
        .as_deref()
        .and_then(oui)
        .unwrap_or_else(|| "no-oui".to_string());
    hash_key(&[&name_part, &oui_part, origin_network])
}

/// True when a device key was computed without a name signal (MAC fallback).
pub fn key_is_nameless(key_material_name: Option<&str>) -> bool {
    key_material_name.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mac_spellings() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(
            normalize_mac("aabbcc.ddeeff"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(normalize_mac("hello world"), None);
    }

    #[test]
    fn network_keys_differ_by_gateway_and_subnet() {
        let a = network_key(
            Some("aa:bb:cc:00:00:01"),
            "192.168.1.0/24",
            IfKind::Ethernet,
        );
        let b = network_key(
            Some("aa:bb:cc:00:00:02"),
            "192.168.1.0/24",
            IfKind::Ethernet,
        );
        let c = network_key(None, "192.168.1.0/24", IfKind::Ethernet);
        let d = network_key(
            Some("aa:bb:cc:00:00:01"),
            "192.168.1.0/24",
            IfKind::Wireless,
        );
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        // deterministic
        assert_eq!(
            a,
            network_key(
                Some("AA:BB:CC:00:00:01"),
                "192.168.1.0/24",
                IfKind::Ethernet
            )
        );
    }

    #[test]
    fn device_key_name_beats_mac() {
        let net = network_key(
            Some("aa:bb:cc:00:00:01"),
            "192.168.1.0/24",
            IfKind::Ethernet,
        );
        let k1 = device_key(Some("deskprinter"), Some("11:22:33:44:55:66"), &net);
        let k2 = device_key(Some("deskprinter"), Some("99:88:77:44:55:66"), &net);
        // Same name, different MAC (randomisation): OUI differs so keys differ,
        // but identity resolution (mac->name upgrade) keeps them aliased.
        assert_ne!(k1, k2);
        let k3 = device_key(Some("DESKPRINTER "), Some("11:22:33:44:55:66"), &net);
        assert_eq!(k1, k3, "name and MAC are normalized before hashing");
    }

    #[test]
    fn device_key_mac_fallback() {
        let net = "somenet";
        let k = device_key(None, Some("11:22:33:44:55:66"), net);
        let k2 = device_key(None, Some("11:22:33:44:55:66"), net);
        assert_eq!(k, k2);
        assert_ne!(k, device_key(None, Some("11:22:33:44:55:67"), net));
    }
}
