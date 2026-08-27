//! Pluggable discovery strategies.
//!
//! A strategy produces `Observation`s for the interface under scan. It
//! declares the `Capability` it needs; the scanner only counts its output
//! toward scan completeness when that capability was confirmed at runtime.
//! Strategies must not loop over address ranges — the sole exception is the
//! privileged `arp-ping` full-coverage strategy.

pub mod arp_cache;
pub mod arp_ping;
pub mod mdns;
pub mod netbios;
pub mod ping;
pub mod ping_sweep;
pub mod ssdp;

use crate::model::{Capability, Interface, Observation};

/// Callback that resolves an IPv4 address to a normalized MAC.
pub type ArpResolver = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Input to a strategy run.
pub struct ScanContext {
    pub iface: Interface,
    /// Candidate IPv4 addresses learned before this strategy runs (wave 2+).
    pub candidates: Vec<String>,
    /// Confirmed capabilities for this scan.
    pub caps: Vec<Capability>,
    /// When set, resolves an IPv4 address to a MAC using the privileged
    /// helper or a native privileged API. Returns None when unavailable.
    pub arp_resolve: Option<ArpResolver>,
}

impl ScanContext {
    pub fn has_cap(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }
}

/// What a strategy did.
pub struct StrategyOutcome {
    pub observations: Vec<Observation>,
    /// Set when the strategy could not do its job (error, missing privilege,
    /// timeout). Makes the scan partial.
    pub problem: Option<String>,
}

impl StrategyOutcome {
    pub fn ok(observations: Vec<Observation>) -> StrategyOutcome {
        StrategyOutcome {
            observations,
            problem: None,
        }
    }

    pub fn failed(reason: impl Into<String>) -> StrategyOutcome {
        StrategyOutcome {
            observations: Vec::new(),
            problem: Some(reason.into()),
        }
    }
}

pub trait Strategy: Send + Sync {
    /// Stable id used in settings and the `scans.strategies` record.
    fn id(&self) -> &'static str;

    fn requires(&self) -> Capability {
        Capability::NeighborCache
    }

    /// Which wave this strategy runs in (1 = parallel starters, 2 = needs
    /// candidates from wave 1, 3 = privileged full coverage).
    fn wave(&self) -> u8;

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome;
}

/// The default strategy set, in registration order.
pub fn registry() -> Vec<Box<dyn Strategy>> {
    vec![
        Box::new(arp_cache::ArpCache),
        Box::new(mdns::Mdns::default()),
        Box::new(ssdp::Ssdp::default()),
        Box::new(ping_sweep::PingSweep),
        Box::new(netbios::Netbios::default()),
        Box::new(arp_ping::ArpPing),
    ]
}

pub fn strategy_ids() -> Vec<&'static str> {
    registry().iter().map(|s| s.id()).collect()
}

/// Pin a socket's multicast egress to the interface being scanned.
///
/// The OS picks the lowest-metric interface for multicast, which on any host
/// with a VPN, WSL, Docker or Hyper-V adapter is usually *not* the interface
/// under scan — group queries then leave via the wrong adapter and no reply
/// ever arrives. TTL 1 keeps the query on-link.
pub(crate) fn pin_multicast_egress(
    sock: &std::net::UdpSocket,
    iface: &Interface,
) -> std::io::Result<()> {
    let Some(addr) = iface
        .ipv4
        .first()
        .and_then(|c| c.addr.parse::<std::net::Ipv4Addr>().ok())
    else {
        return Ok(());
    };
    let sock = socket2::SockRef::from(sock);
    sock.set_multicast_if_v4(&addr)?;
    sock.set_multicast_ttl_v4(1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IfKind, Ipv4Cidr};

    pub(crate) fn iface_with_ipv4(addr: &str, prefix: u8) -> Interface {
        Interface {
            name: "test0".into(),
            description: None,
            mac: None,
            ipv4: vec![Ipv4Cidr {
                addr: addr.into(),
                prefix,
            }],
            ipv6: vec![],
            gateway_v4: None,
            gateway_mac: None,
            index: 1,
            kind: IfKind::Ethernet,
        }
    }

    #[test]
    fn multicast_egress_is_pinned_to_the_scanned_interface() {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        pin_multicast_egress(&sock, &iface_with_ipv4("127.0.0.1", 8)).unwrap();
        assert_eq!(
            socket2::SockRef::from(&sock).multicast_if_v4().unwrap(),
            std::net::Ipv4Addr::LOCALHOST,
            "queries must leave via the scanned interface, not the OS default"
        );
    }
}
