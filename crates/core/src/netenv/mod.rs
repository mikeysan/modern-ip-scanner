//! Local network environment: interfaces, gateways, neighbor (ARP) cache.
//!
//! Windows uses the IP Helper API exclusively (no pcap, no drivers).
//! Linux uses `getifaddrs` + `/proc/net/arp` + `/proc/net/route`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod win;

use crate::model::{Interface, NeighborEntry};

/// Enumerate usable network interfaces. Loopback and down interfaces are
/// included but flagged via their kind; the scanner picks the default.
pub fn interfaces() -> Vec<Interface> {
    #[cfg(windows)]
    {
        win::interfaces()
    }
    #[cfg(target_os = "linux")]
    {
        linux::interfaces()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Vec::new()
    }
}

/// Read the current neighbor/ARP cache (IPv4 entries).
pub fn neighbor_entries() -> Vec<NeighborEntry> {
    #[cfg(windows)]
    {
        win::neighbor_entries()
    }
    #[cfg(target_os = "linux")]
    {
        linux::neighbor_entries()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Vec::new()
    }
}

/// Pick the interface to scan: prefers an up, non-loopback interface with an
/// IPv4 address and a gateway. Ties broken by ethernet > wireless > other.
pub fn default_interface(ifaces: &[Interface]) -> Option<Interface> {
    let score = |i: &Interface| {
        let has_v4 = !i.ipv4.is_empty();
        let has_gw = i.gateway_v4.is_some();
        if !has_v4 || i.kind.is_loopback() {
            return -1;
        }
        let kind_score = match i.kind {
            crate::model::IfKind::Ethernet => 30,
            crate::model::IfKind::Wireless => 25,
            crate::model::IfKind::Other => 10,
            crate::model::IfKind::Virtual => 5,
            crate::model::IfKind::Loopback => 0,
        };
        kind_score + if has_gw { 10 } else { 0 }
    };
    ifaces
        .iter()
        .filter(|i| score(i) >= 0)
        .max_by_key(|i| score(i))
        .cloned()
}
