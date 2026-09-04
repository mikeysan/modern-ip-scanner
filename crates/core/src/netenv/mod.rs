// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

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

/// True when every IPv4 address on this interface is link-local (169.254/16).
/// APIPA means the adapter never got a lease: it is configured but not on a
/// network anyone else is on.
fn only_link_local(iface: &Interface) -> bool {
    !iface.ipv4.is_empty()
        && iface
            .ipv4
            .iter()
            .all(|c| crate::util::ipv4_in_network(&c.addr, 0xA9FE_0000, 16))
}

/// Pick the interface to scan.
///
/// A default gateway outranks everything else: it is the strongest evidence
/// that this is the network the user is actually on. Interfaces that are
/// down, loopback, or holding nothing but an APIPA address are not
/// candidates at all — scanning one of those means scanning the wrong
/// network, or a /16 of nothing.
pub fn default_interface(ifaces: &[Interface]) -> Option<Interface> {
    ifaces
        .iter()
        .filter(|i| usable(i))
        .max_by_key(|i| score(i))
        .cloned()
}

fn usable(iface: &Interface) -> bool {
    !iface.ipv4.is_empty() && iface.up && !iface.kind.is_loopback() && !only_link_local(iface)
}

fn score(iface: &Interface) -> i32 {
    let kind = match iface.kind {
        crate::model::IfKind::Ethernet => 30,
        crate::model::IfKind::Wireless => 25,
        crate::model::IfKind::Other => 10,
        crate::model::IfKind::Virtual => 5,
        crate::model::IfKind::Loopback => 0,
    };
    // Dominant, so a gatewayless Ethernet (a Docker or WSL bridge reports as
    // one) can never outrank the Wi-Fi the user is browsing on.
    kind + if iface.gateway_v4.is_some() { 100 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IfKind, Ipv4Cidr};

    fn iface(name: &str, addr: &str, kind: IfKind, gateway: Option<&str>, up: bool) -> Interface {
        Interface {
            name: name.into(),
            description: None,
            mac: None,
            ipv4: vec![Ipv4Cidr {
                addr: addr.into(),
                prefix: 24,
            }],
            ipv6: vec![],
            gateway_v4: gateway.map(|g| g.to_string()),
            gateway_mac: None,
            kind,
            up,
        }
    }

    #[test]
    fn a_gateway_outranks_a_better_looking_interface_without_one() {
        // The real shape of a dev machine: Wi-Fi carries the gateway while a
        // WSL or Docker bridge presents as plain Ethernet.
        let ifaces = vec![
            iface(
                "vEthernet (WSL)",
                "172.29.64.1",
                IfKind::Ethernet,
                None,
                true,
            ),
            iface(
                "Wi-Fi",
                "192.168.1.120",
                IfKind::Wireless,
                Some("192.168.1.254"),
                true,
            ),
        ];
        assert_eq!(default_interface(&ifaces).unwrap().name, "Wi-Fi");
    }

    #[test]
    fn a_disconnected_adapter_is_not_a_candidate() {
        // A NIC that is down keeps its address and can even keep a stale
        // gateway; scanning it scans nothing.
        let ifaces = vec![
            iface(
                "Ethernet 2",
                "10.0.0.5",
                IfKind::Ethernet,
                Some("10.0.0.1"),
                false,
            ),
            iface(
                "Wi-Fi",
                "192.168.1.120",
                IfKind::Wireless,
                Some("192.168.1.254"),
                true,
            ),
        ];
        assert_eq!(default_interface(&ifaces).unwrap().name, "Wi-Fi");
    }

    #[test]
    fn an_apipa_only_adapter_is_not_a_candidate() {
        // 169.254/16 means no lease. Scanning it would sweep a /16 of nothing.
        let ifaces = vec![
            iface("Bluetooth", "169.254.252.230", IfKind::Ethernet, None, true),
            iface(
                "Wi-Fi",
                "192.168.1.120",
                IfKind::Wireless,
                Some("192.168.1.254"),
                true,
            ),
        ];
        assert_eq!(default_interface(&ifaces).unwrap().name, "Wi-Fi");
    }

    #[test]
    fn loopback_is_never_scanned() {
        let ifaces = vec![iface("lo", "127.0.0.1", IfKind::Loopback, None, true)];
        assert!(default_interface(&ifaces).is_none());
    }

    #[test]
    fn ethernet_wins_over_wireless_when_both_are_really_connected() {
        let ifaces = vec![
            iface(
                "Wi-Fi",
                "192.168.1.120",
                IfKind::Wireless,
                Some("192.168.1.254"),
                true,
            ),
            iface(
                "Ethernet",
                "10.0.0.5",
                IfKind::Ethernet,
                Some("10.0.0.1"),
                true,
            ),
        ];
        assert_eq!(default_interface(&ifaces).unwrap().name, "Ethernet");
    }

    #[test]
    fn nothing_usable_yields_nothing() {
        assert!(default_interface(&[]).is_none());
        let down = vec![iface(
            "eth0",
            "10.0.0.5",
            IfKind::Ethernet,
            Some("10.0.0.1"),
            false,
        )];
        assert!(default_interface(&down).is_none());
    }
}
