//! `ping-sweep`: targeted liveness probes. This is *not* an address-range
//! loop — it probes what wave 1 found (neighbor cache, mDNS, SSDP), the
//! gateway, and a bounded set of conventional infrastructure addresses, plus
//! the subnet-directed broadcast as a cache primer. Pinging devices refreshes
//! their neighbor-cache entries, which the scanner re-reads afterwards to
//! harvest MACs.
//!
//! See [`plan_sweep`] for what is probed and what may be reported: the
//! broadcast address is probed but never reported as a device.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::{ScanContext, Strategy, StrategyOutcome};
use crate::model::{Capability, Interface, Observation};

pub struct PingSweep;

const TIMEOUT: Duration = Duration::from_millis(700);
const MAX_PARALLEL: usize = 32;

/// How many low addresses to probe as infrastructure heuristics. Routers,
/// switches, APs and NAS boxes conventionally sit at the bottom of the
/// prefix; this is a bounded guess, not a range loop.
const HEURISTIC_LOW_HOSTS: u32 = 10;

/// The addresses ping-sweep will probe.
pub(crate) struct SweepPlan {
    /// May yield a device observation.
    pub targets: Vec<String>,
    /// Probed only to populate the neighbor cache, which the scanner re-reads
    /// afterwards. Never reported as a device.
    pub primers: Vec<String>,
}

/// Decide what to probe: the candidates wave 1 found, the gateway, a bounded
/// set of conventional infrastructure addresses, and the subnet-directed
/// broadcast (as a primer). Our own addresses, the network address and the
/// broadcast address are never targets.
pub(crate) fn plan_sweep(candidates: &[String], iface: &Interface) -> SweepPlan {
    use std::collections::BTreeSet;

    let empty = || SweepPlan {
        targets: Vec::new(),
        primers: Vec::new(),
    };
    let Some(cidr) = iface.ipv4.first() else {
        return empty();
    };
    let Some(addr) = crate::util::parse_ipv4(&cidr.addr) else {
        return empty();
    };
    let prefix = cidr.prefix.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let network = addr & mask;
    let broadcast = network | !mask;

    let own: BTreeSet<u32> = iface
        .ipv4
        .iter()
        .filter_map(|c| crate::util::parse_ipv4(&c.addr))
        .collect();

    let mut targets: BTreeSet<u32> = BTreeSet::new();
    for c in candidates {
        if let Some(a) = crate::util::parse_ipv4(c) {
            targets.insert(a);
        }
    }
    if let Some(gw) = iface
        .gateway_v4
        .as_deref()
        .and_then(crate::util::parse_ipv4)
    {
        targets.insert(gw);
    }
    // Conventional infrastructure addresses: the bottom of the prefix and the
    // top usable address. Bounded, so this stays a heuristic and not a sweep.
    if broadcast > network {
        for i in 1..=HEURISTIC_LOW_HOSTS {
            let a = network.saturating_add(i);
            if a < broadcast {
                targets.insert(a);
            }
        }
        targets.insert(broadcast - 1);
    }
    targets.retain(|a| a & mask == network && *a != network && *a != broadcast && !own.contains(a));

    // The directed broadcast is probed but never reported: it is how silent
    // hosts get pulled into the neighbor cache, not a device of its own.
    let primers = if broadcast > network && !own.contains(&broadcast) {
        vec![crate::util::format_ipv4(broadcast)]
    } else {
        Vec::new()
    };

    SweepPlan {
        targets: targets.into_iter().map(crate::util::format_ipv4).collect(),
        primers,
    }
}

impl Strategy for PingSweep {
    fn id(&self) -> &'static str {
        "ping-sweep"
    }

    fn requires(&self) -> Capability {
        Capability::IcmpEcho
    }

    fn wave(&self) -> u8 {
        2
    }

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome {
        if !ctx.has_cap(Capability::IcmpEcho) {
            return StrategyOutcome::failed(
                "ICMP echo unavailable unprivileged on this system (helper enables it)".to_string(),
            );
        }
        let plan = plan_sweep(&ctx.candidates, &ctx.iface);
        // (address, reportable). Primers go first so that hosts they wake are
        // in the neighbor cache by the time the scanner re-reads it.
        let mut probes: Vec<(String, bool)> = plan
            .primers
            .into_iter()
            .map(|ip| (ip, false))
            .chain(plan.targets.into_iter().map(|ip| (ip, true)))
            .collect();
        if probes.is_empty() {
            return StrategyOutcome::ok(Vec::new());
        }
        probes.shrink_to_fit();

        let (tx, rx) = mpsc::channel::<(String, bool)>();
        let probes = std::sync::Arc::new(probes);
        let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        thread::scope(|s| {
            for _ in 0..MAX_PARALLEL.min(probes.len()) {
                let (tx, probes, next) = (tx.clone(), probes.clone(), next.clone());
                s.spawn(move || loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if i >= probes.len() {
                        break;
                    }
                    let (ip, reportable) = &probes[i];
                    let alive = super::ping::echo(ip, TIMEOUT);
                    if alive && *reportable {
                        let _ = tx.send((ip.clone(), true));
                    }
                });
            }
        });
        drop(tx);

        let observations = rx
            .into_iter()
            .map(|(ip, _)| Observation {
                ip,
                mac: None,
                name: None,
                vendor: None,
                source: self.id().to_string(),
                confidence: 0.85,
            })
            .collect();
        StrategyOutcome::ok(observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::tests::iface_with_ipv4;

    fn plan(candidates: &[&str], addr: &str, prefix: u8, gateway: Option<&str>) -> SweepPlan {
        let mut iface = iface_with_ipv4(addr, prefix);
        iface.gateway_v4 = gateway.map(|g| g.to_string());
        let owned: Vec<String> = candidates.iter().map(|c| c.to_string()).collect();
        plan_sweep(&owned, &iface)
    }

    #[test]
    fn broadcast_is_primed_but_never_a_target() {
        let p = plan(&[], "192.168.1.120", 24, Some("192.168.1.254"));
        assert!(
            p.primers.contains(&"192.168.1.255".to_string()),
            "the directed broadcast is what makes silent hosts populate the ARP cache"
        );
        assert!(
            !p.targets.contains(&"192.168.1.255".to_string()),
            "a reply from the broadcast address is not a device"
        );
    }

    #[test]
    fn our_own_address_is_never_probed() {
        let p = plan(&["192.168.1.120"], "192.168.1.120", 24, None);
        assert!(!p.targets.contains(&"192.168.1.120".to_string()));
        assert!(!p.primers.contains(&"192.168.1.120".to_string()));
    }

    #[test]
    fn the_network_address_is_never_probed() {
        let p = plan(&["192.168.1.0"], "192.168.1.120", 24, None);
        assert!(!p.targets.contains(&"192.168.1.0".to_string()));
    }

    #[test]
    fn the_gateway_is_always_a_target() {
        let p = plan(&[], "192.168.1.120", 24, Some("192.168.1.254"));
        assert!(p.targets.contains(&"192.168.1.254".to_string()));
    }

    #[test]
    fn candidates_from_earlier_waves_are_kept() {
        let p = plan(&["192.168.1.77"], "192.168.1.120", 24, None);
        assert!(p.targets.contains(&"192.168.1.77".to_string()));
    }

    #[test]
    fn off_link_candidates_are_dropped() {
        let p = plan(&["10.9.9.9"], "192.168.1.120", 24, None);
        assert!(!p.targets.contains(&"10.9.9.9".to_string()));
    }

    #[test]
    fn conventional_infrastructure_addresses_are_probed() {
        // Without this, a scan of a fresh network with a cold ARP cache has
        // nothing to probe but the gateway.
        let p = plan(&[], "192.168.1.120", 24, None);
        for expected in ["192.168.1.1", "192.168.1.2", "192.168.1.10"] {
            assert!(
                p.targets.contains(&expected.to_string()),
                "{expected} should be probed as an infrastructure heuristic"
            );
        }
        assert!(
            p.targets.contains(&"192.168.1.254".to_string()),
            "the last usable address is a conventional router address"
        );
    }

    #[test]
    fn heuristics_stay_inside_a_small_prefix() {
        // 10.0.0.0/30: usable hosts are .1 and .2 only.
        let p = plan(&[], "10.0.0.1", 30, None);
        assert_eq!(p.targets, vec!["10.0.0.2".to_string()]);
        assert_eq!(p.primers, vec!["10.0.0.3".to_string()]);
    }

    #[test]
    fn targets_are_deduplicated_and_deterministic() {
        let p = plan(
            &["192.168.1.1", "192.168.1.1", "192.168.1.5"],
            "192.168.1.120",
            24,
            Some("192.168.1.1"),
        );
        assert!(!p.targets.is_empty());
        let mut uniq = p.targets.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), p.targets.len(), "no duplicate probes");

        let again = plan(
            &["192.168.1.1", "192.168.1.1", "192.168.1.5"],
            "192.168.1.120",
            24,
            Some("192.168.1.1"),
        );
        assert_eq!(p.targets, again.targets, "order must be stable across runs");
    }
}
