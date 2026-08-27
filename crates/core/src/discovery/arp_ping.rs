//! `arp-ping`: exhaustive ARP resolution of every address in the interface's
//! prefix. This is the *only* strategy allowed to loop over an address range,
//! because it is the only one that yields definitive up/down answers — and it
//! requires the `ArpResolve` capability (native SendARP on Windows or the
//! privileged helper on Linux). When that capability is missing the strategy
//! reports a problem, which makes the scan partial.

use std::sync::mpsc;
use std::thread;

use super::{ScanContext, Strategy, StrategyOutcome};
use crate::model::{Capability, Observation};

pub struct ArpPing;

const MAX_ADDRESSES: usize = 4096;

impl Strategy for ArpPing {
    fn id(&self) -> &'static str {
        "arp-ping"
    }

    fn requires(&self) -> Capability {
        Capability::ArpResolve
    }

    /// The only strategy that probes every address, so the only one whose
    /// silence about an address is evidence that nothing is there.
    fn coverage(&self) -> super::Coverage {
        super::Coverage::Exhaustive
    }

    fn wave(&self) -> u8 {
        3
    }

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome {
        if !ctx.has_cap(Capability::ArpResolve) {
            return StrategyOutcome::failed(
                "ARP resolution unavailable (launch with the privileged helper)".to_string(),
            );
        }
        let Some(resolve) = ctx.arp_resolve.as_ref() else {
            return StrategyOutcome::failed("no ARP resolver wired up".to_string());
        };

        // Enumerate every address of the smallest on-link prefix (cap at
        // MAX_ADDRESSES; larger prefixes make the scan partial instead of
        // silently incomplete).
        let mut targets: Vec<u32> = Vec::new();
        let mut oversized = false;
        for cidr in &ctx.iface.ipv4 {
            let Some(addr) = crate::util::parse_ipv4(&cidr.addr) else {
                continue;
            };
            let size = if cidr.prefix >= 31 {
                1u64
            } else {
                1u64 << (32 - cidr.prefix)
            };
            if size > MAX_ADDRESSES as u64 {
                oversized = true;
                continue;
            }
            targets.extend(crate::util::enumerate_network(addr, cidr.prefix));
        }
        // Exclude the broadcast address and our own addresses: SendARP
        // answers for those are artifacts, not devices.
        let own: Vec<u32> = ctx
            .iface
            .ipv4
            .iter()
            .filter_map(|c| crate::util::parse_ipv4(&c.addr))
            .collect();
        let broadcast: Vec<u32> = ctx
            .iface
            .ipv4
            .iter()
            .filter_map(|c| {
                let a = crate::util::parse_ipv4(&c.addr)?;
                let mask = if c.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - c.prefix)
                };
                Some((a & mask) | !mask)
            })
            .collect();
        targets.retain(|t| !own.contains(t) && !broadcast.contains(t));
        targets.sort();
        targets.dedup();
        if targets.is_empty() {
            let reason = if oversized {
                format!("on-link prefix larger than /{} not swept", prefix_cap())
            } else {
                "no on-link prefix to sweep".into()
            };
            return StrategyOutcome::failed(reason);
        }

        let (tx, rx) = mpsc::channel::<(String, Option<String>)>();
        let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ips: Vec<String> = targets
            .iter()
            .map(|a| crate::util::format_ipv4(*a))
            .collect();
        let ips = std::sync::Arc::new(ips);
        thread::scope(|s| {
            for _ in 0..ctx.arp_concurrency.max(1).min(ips.len()) {
                let (tx, ips, next) = (tx.clone(), ips.clone(), next.clone());
                s.spawn(move || loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if i >= ips.len() {
                        break;
                    }
                    if let Some(mac) = resolve(&ips[i]) {
                        let _ = tx.send((ips[i].clone(), Some(mac)));
                    }
                });
            }
        });
        drop(tx);

        let mut observations = Vec::new();
        for (ip, mac) in rx {
            observations.push(Observation {
                ip,
                mac,
                name: None,
                vendor: None,
                source: self.id().to_string(),
                confidence: 0.95,
            });
        }
        if oversized {
            return StrategyOutcome {
                observations,
                problem: Some("prefix too large for exhaustive sweep".into()),
            };
        }
        StrategyOutcome::ok(observations)
    }
}

fn prefix_cap() -> u8 {
    32 - (MAX_ADDRESSES as f64).log2().ceil() as u8
}
