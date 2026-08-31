//! Pluggable discovery strategies.
//!
//! A strategy produces `Observation`s for the interface under scan. One that
//! needs a privilege checks for it itself, at the top of `run`, with
//! `ctx.has_cap` -- see `arp_ping` and `ping_sweep` -- and returns
//! `StrategyOutcome::failed` when it is missing, which is what makes the scan
//! partial.
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

/// Callback that resolves many IPv4 addresses to normalized MACs, returning
/// one slot per address in the order given.
///
/// Batch-shaped on purpose. The privileged helper is a single connection, so
/// asking it for one address at a time costs one ARP wait each, in series --
/// which made an exhaustive sweep through it take minutes. Backends without
/// that constraint fan out internally, so the caller never manages threads.
pub type ArpResolver = Box<dyn Fn(&[String]) -> Vec<Option<String>> + Send + Sync>;

/// Input to a strategy run.
pub struct ScanContext {
    pub iface: Interface,
    /// Candidate IPv4 addresses learned before this strategy runs (wave 2+).
    pub candidates: Vec<String>,
    /// Confirmed capabilities for this scan.
    pub caps: Vec<Capability>,
    /// When set, resolves addresses to MACs using the privileged helper or a
    /// native privileged API. Slots are None where nothing answered.
    pub arp_resolve_many: Option<ArpResolver>,
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

/// What a strategy's *silence* about an address means.
///
/// Only a strategy that probes every address in the prefix can turn "did not
/// answer" into evidence of absence. Everything else confirms presence and
/// says nothing at all about the devices it did not hear from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Probes the whole prefix: not seeing an address is evidence.
    Exhaustive,
    /// Only ever confirms presence; silence carries no information.
    PresenceOnly,
}

pub trait Strategy: Send + Sync {
    /// Stable id used in settings and the `scans.strategies` record.
    fn id(&self) -> &'static str;

    /// Whether this strategy's silence is evidence of absence.
    fn coverage(&self) -> Coverage {
        Coverage::PresenceOnly
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
            up: true,
        }
    }

    #[test]
    fn only_an_exhaustive_sweep_can_testify_to_absence() {
        // A scan built solely from presence-only strategies must never be
        // allowed to conclude a device is gone.
        for s in registry() {
            let expected = match s.id() {
                "arp-ping" => Coverage::Exhaustive,
                _ => Coverage::PresenceOnly,
            };
            assert_eq!(s.coverage(), expected, "strategy {}", s.id());
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
