//! Merge observations across strategies and resolve device identity.
//!
//! Merging happens in two steps:
//! 1. Combine `Observation`s that share an IP or a MAC into one
//!    `ObservedDevice` (name signals ranked mDNS > NetBIOS > SSDP).
//! 2. Match each observed device against the inventory: exact MAC match
//!    first, then name-on-network (covers MAC randomisation); otherwise it
//!    is new. Devices first seen nameless get re-fingerprinted (and aliased)
//!    once a name signal appears.

use std::collections::HashMap;

use crate::model::{NameSource, Observation};
use crate::store::{DeviceRow, Store};

/// A device as observed during one scan, before identity resolution.
#[derive(Debug, Clone)]
pub struct ObservedDevice {
    /// IPs seen this scan (first is primary).
    pub ips: Vec<String>,
    pub mac: Option<String>,
    pub name: Option<String>,
    pub name_source: Option<NameSource>,
    pub vendor: Option<String>,
    pub sources: Vec<String>,
    /// Weighted confidence across strategies.
    pub confidence: f32,
}

pub fn merge_observations(observations: &[Observation]) -> Vec<ObservedDevice> {
    // Step 1: group by IP.
    struct IpAgg {
        ips: Vec<String>,
        mac: Option<String>,
        names: Vec<(NameSource, String)>,
        vendor: Option<String>,
        sources: Vec<String>,
        confidence: f32,
    }

    let mut by_ip: HashMap<String, IpAgg> = HashMap::new();
    for o in observations {
        let agg = by_ip.entry(o.ip.clone()).or_insert_with(|| IpAgg {
            ips: vec![o.ip.clone()],
            mac: None,
            names: Vec::new(),
            vendor: None,
            sources: Vec::new(),
            confidence: 0.0,
        });
        if let Some(mac) = &o.mac {
            // Higher-confidence MAC wins; first writer keeps ties.
            if agg.mac.is_none() || o.confidence > agg.confidence {
                agg.mac = Some(mac.clone());
            }
        }
        if let Some((src, name)) = &o.name {
            if !name.trim().is_empty() && !agg.names.iter().any(|(_, n)| n == name) {
                agg.names.push((*src, name.clone()));
            }
        }
        if agg.vendor.is_none() {
            agg.vendor = o.vendor.clone();
        }
        if !agg.sources.contains(&o.source) {
            agg.sources.push(o.source.clone());
        }
        agg.confidence = agg.confidence.max(o.confidence);
    }

    // Step 2: union groups sharing a MAC (same device, several IPs).
    let mut by_mac: HashMap<String, Vec<usize>> = HashMap::new();
    let groups: Vec<IpAgg> = by_ip.into_values().collect();
    for (idx, g) in groups.iter().enumerate() {
        if let Some(mac) = &g.mac {
            by_mac.entry(mac.clone()).or_default().push(idx);
        }
    }

    let mut merged: Vec<ObservedDevice> = Vec::new();
    let mut taken = vec![false; groups.len()];
    for (i, g) in groups.iter().enumerate() {
        if taken[i] {
            continue;
        }
        taken[i] = true;
        let mut mac_group = vec![i];
        if let Some(mac) = &g.mac {
            for &j in by_mac.get(mac).map(|v| v.as_slice()).unwrap_or(&[]) {
                if !taken[j] {
                    taken[j] = true;
                    mac_group.push(j);
                }
            }
        }
        let mut ips = Vec::new();
        let mut names: Vec<(NameSource, String)> = Vec::new();
        let mut vendor = None;
        let mut sources = Vec::new();
        let mut confidence: f32 = 0.0;
        let mut mac = g.mac.clone();
        for &j in &mac_group {
            let gg = &groups[j];
            ips.extend(gg.ips.iter().cloned());
            names.extend(gg.names.iter().cloned());
            if vendor.is_none() {
                vendor = gg.vendor.clone();
            }
            if mac.is_none() {
                mac = gg.mac.clone();
            }
            for s in &gg.sources {
                if !sources.contains(s) {
                    sources.push(s.clone());
                }
            }
            confidence = confidence.max(gg.confidence);
        }
        ips.sort();
        ips.dedup();
        names.sort(); // (source, name): Ssdp < Netbios < Mdns by enum order
        let name = names.last().map(|(_, n)| n.clone());
        let name_source = names.last().map(|(s, _)| *s);
        merged.push(ObservedDevice {
            ips,
            mac,
            name,
            name_source,
            vendor,
            sources,
            confidence,
        });
    }
    merged
}

/// The identity decision for one observed device.
#[derive(Debug)]
pub enum Resolution {
    /// Existing inventory device (canonical key).
    Existing(DeviceRow),
    /// Brand-new device; key computed from current signals + network.
    New(String),
}

pub fn resolve_identity(
    store: &Store,
    device: &ObservedDevice,
    network_key: &str,
) -> Result<Resolution, crate::store::StoreError> {
    // Strong signal: exact MAC match against the inventory.
    if let Some(mac) = &device.mac {
        if let Some(existing) = store.find_device_by_mac(mac)? {
            return Ok(Resolution::Existing(existing));
        }
    }
    // Name-on-network match: handles MAC randomisation (new MAC, same name).
    if let Some(name) = &device.name {
        if let Some(existing) = store.find_device_by_name_on_network(name, network_key)? {
            return Ok(Resolution::Existing(existing));
        }
    }
    Ok(Resolution::New(crate::identity::device_key(
        device.name.as_deref(),
        device.mac.as_deref(),
        network_key,
    )))
}

/// When an existing device gains a name signal it never had, recompute its
/// composite key and alias the old one so history and user names survive.
pub fn maybe_refingerprint(
    store: &Store,
    existing: &DeviceRow,
    device: &ObservedDevice,
) -> Result<String, crate::store::StoreError> {
    let has_name_now = device
        .name
        .as_deref()
        .map(|n| !n.trim().is_empty())
        .unwrap_or(false);
    let had_name = existing
        .primary_name
        .as_deref()
        .map(|n| !n.trim().is_empty())
        .unwrap_or(false);
    if has_name_now && !had_name {
        let new_key = crate::identity::device_key(
            device.name.as_deref(),
            device.mac.as_deref().or(existing.mac.as_deref()),
            &existing.origin_network,
        );
        if new_key != existing.key {
            // Ensure the new device row exists under the new key, then alias.
            store.upsert_device(
                &new_key,
                device.name.as_deref().or(existing.primary_name.as_deref()),
                device.mac.as_deref().or(existing.mac.as_deref()),
                device.vendor.as_deref().or(existing.vendor.as_deref()),
                &existing.origin_network,
            )?;
            store.add_alias(&existing.key, &new_key)?;
            return Ok(new_key);
        }
    }
    Ok(existing.key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ip: &str, mac: Option<&str>, name: Option<(&str, &str)>, src: &str) -> Observation {
        Observation {
            ip: ip.into(),
            mac: mac.map(|m| m.into()),
            name: name.map(|(s, n)| match s {
                "mdns" => (NameSource::Mdns, n.to_string()),
                "netbios" => (NameSource::Netbios, n.to_string()),
                _ => (NameSource::Ssdp, n.to_string()),
            }),
            vendor: None,
            source: src.into(),
            confidence: 0.8,
        }
    }

    #[test]
    fn merges_by_ip_and_mac() {
        let observations = vec![
            obs("10.0.0.1", Some("aa:aa:aa:aa:aa:aa"), None, "arp-cache"),
            obs("10.0.0.1", None, Some(("netbios", "tower")), "netbios"),
            obs("10.0.0.2", Some("aa:aa:aa:aa:aa:aa"), None, "arp-cache"),
            obs("10.0.0.3", Some("bb:bb:bb:bb:bb:bb"), None, "arp-cache"),
        ];
        let merged = merge_observations(&observations);
        assert_eq!(merged.len(), 2);
        let tower = merged
            .iter()
            .find(|d| d.name.as_deref() == Some("tower"))
            .expect("tower merged");
        assert_eq!(tower.mac.as_deref(), Some("aa:aa:aa:aa:aa:aa"));
        assert!(tower.ips.contains(&"10.0.0.1".to_string()));
        assert!(tower.ips.contains(&"10.0.0.2".to_string()));
    }

    #[test]
    fn name_ranking_prefers_mdns() {
        let observations = vec![
            obs(
                "10.0.0.5",
                Some("cc:cc:cc:cc:cc:cc"),
                Some(("ssdp", "Living Room")),
                "ssdp",
            ),
            obs("10.0.0.5", None, Some(("mdns", "chromecast-hq")), "mdns"),
            obs(
                "10.0.0.5",
                None,
                Some(("netbios", "ANDROID-9F2")),
                "netbios",
            ),
        ];
        let merged = merge_observations(&observations);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name.as_deref(), Some("chromecast-hq"));
        assert_eq!(merged[0].name_source, Some(NameSource::Mdns));
    }
}
