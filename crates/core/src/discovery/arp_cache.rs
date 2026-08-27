//! `arp-cache`: harvest the OS neighbor/ARP table. Zero packets, always
//! available, the baseline of every scan.

use super::{ScanContext, Strategy, StrategyOutcome};
use crate::model::Observation;

pub struct ArpCache;

impl Strategy for ArpCache {
    fn id(&self) -> &'static str {
        "arp-cache"
    }

    fn wave(&self) -> u8 {
        1
    }

    fn run(&self, ctx: &ScanContext) -> StrategyOutcome {
        let entries = crate::netenv::neighbor_entries();
        let mut observations = Vec::new();
        for e in entries {
            if !crate::util::ipv4_in_network_of(&e.ip, &ctx.iface) {
                continue;
            }
            observations.push(Observation {
                ip: e.ip,
                mac: Some(e.mac),
                name: None,
                vendor: None,
                source: self.id().to_string(),
                confidence: if e.reachable { 0.9 } else { 0.5 },
            });
        }
        StrategyOutcome::ok(observations)
    }
}
