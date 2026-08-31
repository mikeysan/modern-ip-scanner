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
    if hex.len() != 12 {
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

/// The first six bytes of a hardware address as a normalized MAC string.
///
/// The platform APIs hand back a fixed-size buffer with a separate length, so
/// anything shorter than six bytes is not an address; anything longer is
/// padding. All-zero and broadcast are rejected by [`normalize_mac`].
pub fn mac_from_bytes(bytes: &[u8]) -> Option<String> {
    let six: &[u8] = bytes.get(..6)?;
    let hex: String = six.iter().map(|b| format!("{b:02x}")).collect();
    normalize_mac(&hex)
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

/// True when a MAC carries the locally-administered bit (bit 1 of the first
/// octet) — the marker every modern phone sets on a randomised address.
pub fn is_locally_administered(mac: &str) -> bool {
    let Some(normalized) = normalize_mac(mac) else {
        return false;
    };
    let Some(first) = normalized.split(':').next() else {
        return false;
    };
    u8::from_str_radix(first, 16).is_ok_and(|octet| octet & 0x02 != 0)
}

/// Whether a device can be re-identified across scans from these signals.
///
/// A name is matchable (`find_device_by_name_on_network`), and so is a MAC
/// that belongs to a real manufacturer. A randomised MAC is not: it changes
/// by design, so a device carrying one and nothing else cannot be told apart
/// from a different device the next time it appears. Neither can a device
/// that offered no MAC and no name at all.
///
/// Unstable identities are recorded like any other, but the diff engine may
/// never report them `gone` — it cannot distinguish "left the network" from
/// "came back wearing a different address".
pub fn is_stable(primary_name: Option<&str>, mac: Option<&str>) -> bool {
    if primary_name.is_some_and(|n| !n.trim().is_empty()) {
        return true;
    }
    mac.is_some_and(|m| normalize_mac(m).is_some() && !is_locally_administered(m))
}

/// True when a "name" is really a machine identifier — a UUID or a long hex
/// blob — rather than something a person chose.
///
/// Chromecast-family devices (including the TVs that embed it) publish their
/// mDNS hostname as `<uuid>.local`, which is stable and useless to read. The
/// same device usually advertises a real name over SSDP, so this lets the
/// merge prefer the readable one.
pub fn looks_like_identifier(name: &str) -> bool {
    let compact: String = name.chars().filter(|c| *c != '-' && *c != '_').collect();
    compact.len() >= 24 && compact.chars().all(|c| c.is_ascii_hexdigit())
}

fn hash_key(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    // Domain separation for the key hash. Deliberately NOT renamed with
    // the product: every device and network key derives from it, so
    // changing this string silently re-identifies every device in every
    // existing database. The "-v1" is the version to bump if the key
    // format ever genuinely changes.
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
    let norm_mac = mac.and_then(normalize_mac);
    let name_part = primary_name
        .map(|n| n.trim().to_lowercase())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            // The *normalized* MAC: hashing the raw spelling made
            // `AA-BB-...` and `aa:bb:...` two different devices.
            norm_mac
                .as_deref()
                .map(|m| format!("mac:{m}"))
                .unwrap_or_else(|| "anonymous".to_string())
        });
    let oui_part = norm_mac
        .as_deref()
        .and_then(oui)
        .unwrap_or_else(|| "no-oui".to_string());
    hash_key(&[&name_part, &oui_part, origin_network])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_become_a_normalized_mac_or_nothing() {
        assert_eq!(
            mac_from_bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        // Longer buffers are what the platform APIs hand back; take the first
        // six and ignore the padding.
        assert_eq!(
            mac_from_bytes(&[0x90, 0x48, 0x46, 0x10, 0x3B, 0x7A, 0x00, 0x00]).as_deref(),
            Some("90:48:46:10:3b:7a")
        );
        assert_eq!(mac_from_bytes(&[0xAA, 0xBB, 0xCC]), None, "too short");
        assert_eq!(
            mac_from_bytes(&[0u8; 6]),
            None,
            "all-zero is not an identity"
        );
        assert_eq!(
            mac_from_bytes(&[0xffu8; 6]),
            None,
            "broadcast is not either"
        );
    }

    #[test]
    fn a_uuid_hostname_is_an_identifier_not_a_name() {
        // What a Chromecast-embedded TV publishes over mDNS.
        assert!(looks_like_identifier(
            "705c66d2-019a-264d-4b6d-8e2f1a2b3c4d"
        ));
        assert!(looks_like_identifier("705c66d2019a264d4b6d8e2f1a2b3c4d"));
    }

    #[test]
    fn names_people_chose_are_not_identifiers() {
        for name in [
            "area boys",
            "BT HomeHub6DX",
            "chromecast-hq",
            "DESKTOP-ABC123",
            "printer",
            "deadbeefcafe", // hex, but too short to be an identifier
        ] {
            assert!(!looks_like_identifier(name), "{name} is a name");
        }
    }

    #[test]
    fn the_locally_administered_bit_marks_a_randomised_mac() {
        // Bit 1 of the first octet. 0x36 = 0011_0110 -> set.
        assert!(is_locally_administered("36:93:e6:08:48:d9"));
        assert!(is_locally_administered("02:00:00:00:00:01"));
        // 0xc0 = 1100_0000 -> clear; a real vendor OUI.
        assert!(!is_locally_administered("c0:d7:aa:b4:dc:9b"));
        assert!(!is_locally_administered("90:48:46:10:3b:7a"));
        assert!(!is_locally_administered("nonsense"));
    }

    #[test]
    fn a_name_makes_an_identity_stable_whatever_the_mac_does() {
        // The whole point of the composite key: a device that announces a
        // name can be found again even after its MAC rotates.
        assert!(is_stable(Some("living-room-tv"), Some("36:93:e6:08:48:d9")));
        assert!(is_stable(Some("printer"), None));
    }

    #[test]
    fn a_nameless_device_with_a_vendor_mac_is_stable() {
        assert!(is_stable(None, Some("90:48:46:10:3b:7a")));
    }

    #[test]
    fn a_nameless_device_with_a_randomised_mac_is_unstable() {
        assert!(!is_stable(None, Some("36:93:e6:08:48:d9")));
        assert!(!is_stable(Some("   "), Some("36:93:e6:08:48:d9")));
    }

    #[test]
    fn a_device_that_offered_no_signal_at_all_is_unstable() {
        assert!(!is_stable(None, None));
    }

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
    fn the_mac_fallback_key_does_not_depend_on_spelling() {
        let net = "somenet";
        let canonical = device_key(None, Some("aa:bb:cc:dd:ee:ff"), net);
        for spelling in ["AA-BB-CC-DD-EE-FF", "aabbcc.ddeeff", "AA:BB:CC:DD:EE:FF"] {
            assert_eq!(
                device_key(None, Some(spelling), net),
                canonical,
                "{spelling} is the same device"
            );
        }
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
