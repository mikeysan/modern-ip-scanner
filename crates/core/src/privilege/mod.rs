//! Runtime privilege probing and the optional helper client.
//!
//! Nothing here ever *assumes* privilege: each capability is tested with a
//! cheap live operation against the loopback or the interface's gateway.

pub mod helper;

use crate::model::{Capability, PrivilegeState};
use crate::netenv;

/// Probe what actually works right now on this machine/interface.
pub fn probe(iface: Option<&crate::model::Interface>) -> PrivilegeState {
    let mut state = PrivilegeState::default();

    // Neighbor cache: works if we can read anything at all (entry count is
    // irrelevant; a permission failure yields an empty vec on both platforms,
    // so we additionally sanity-check the API path by reading /proc on Linux).
    #[cfg(target_os = "linux")]
    let cache_ok = std::path::Path::new("/proc/net/arp").exists();
    #[cfg(windows)]
    let cache_ok = true; // GetIpNetTable2 needs no privilege
    #[cfg(not(any(windows, target_os = "linux")))]
    let cache_ok = false;
    if cache_ok {
        state.capabilities.push(Capability::NeighborCache);
    } else {
        state.notes.push("neighbor cache unreadable".into());
    }

    if crate::discovery::ping::probe_capability() {
        state.capabilities.push(Capability::IcmpEcho);
    } else {
        state
            .notes
            .push("ICMP echo unavailable unprivileged (Linux ping_group_range?)".into());
    }

    // ARP resolution: Windows SendARP usually works unprivileged; Linux needs
    // raw sockets (root) — the helper provides it otherwise.
    #[cfg(windows)]
    {
        if let Some(iface) = iface {
            if let Some(gw) = &iface.gateway_v4 {
                if crate::discovery::ping::native_arp_resolve(gw, 1000).is_some() {
                    state.capabilities.push(Capability::ArpResolve);
                } else {
                    state.notes.push("SendARP failed for gateway".into());
                }
            } else {
                state.notes.push("no gateway to probe ARP against".into());
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if crate::discovery::ping::raw_socket_capability() {
            state.capabilities.push(Capability::ArpResolve);
        } else {
            state
                .notes
                .push("raw sockets unavailable (use the privileged helper for full ARP)".into());
        }
    }

    state
}

/// Try to locate the helper binary next to the current executable.
pub fn helper_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = if cfg!(windows) {
        "laninv-helper.exe"
    } else {
        "laninv-helper"
    };
    let p = dir.join(name);
    p.exists().then_some(p)
}

/// Convenience: read the neighbor table filtered to one interface's subnets.
pub fn neighbors_for(iface: &crate::model::Interface) -> Vec<crate::model::NeighborEntry> {
    netenv::neighbor_entries()
        .into_iter()
        .filter(|e| crate::util::ipv4_in_network_of(&e.ip, iface))
        .collect()
}
