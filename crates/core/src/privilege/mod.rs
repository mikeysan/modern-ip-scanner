// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

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
                // Permission is not capability: only a working implementation
                // counts, and on Windows that means SendARP actually answering
                // for the gateway.
                if crate::discovery::ping::native_arp_resolve(gw).is_some() {
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
        // The interface only matters to the Windows SendARP probe.
        let _ = iface;
        // Permission is not capability. There is no native ARP in the scanner
        // on Linux -- `native_arp_resolve` is a stub and the helper holds the
        // only implementation -- so `ArpResolve` is never granted here however
        // much privilege we hold; the note says which of the two reasons
        // applies. Granting it for permission alone let `arp-ping` sweep 4096
        // addresses in 73ms, resolve none of them, and report the failure as a
        // vanished gateway.
        if crate::discovery::ping::raw_socket_capability() {
            state.notes.push(
                "running with raw-socket privilege, but ARP resolution lives in the \
                 privileged helper: pass --helper for full ARP coverage (no prompt as root)"
                    .into(),
            );
        } else {
            state
                .notes
                .push("raw sockets unavailable (use the privileged helper for full ARP)".into());
        }
    }

    state
}

/// Platform file name of the helper binary.
pub fn helper_file_name() -> &'static str {
    if cfg!(windows) {
        "modern-ip-scanner-helper.exe"
    } else {
        "modern-ip-scanner-helper"
    }
}

/// Every place the helper is looked for, in order, given the directory
/// holding the current executable and an optional explicit override.
///
/// Split out from the environment so the ordering is testable: "why is my
/// helper not found?" should be answerable without guessing.
fn search_paths_from(
    exe_dir: Option<&std::path::Path>,
    override_path: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(p) = override_path {
        paths.push(p.to_path_buf());
    }
    if let Some(dir) = exe_dir {
        paths.push(dir.join(helper_file_name()));
    }
    if cfg!(not(windows)) {
        for dir in [
            "/usr/libexec/modern-ip-scanner",
            "/usr/lib/modern-ip-scanner",
            "/usr/local/bin",
        ] {
            paths.push(std::path::Path::new(dir).join(helper_file_name()));
        }
    }
    paths.dedup();
    paths
}

/// Every place the helper is looked for on this machine, in order. Exposed so
/// the UI can tell the user where to put it rather than only that it is
/// missing.
pub fn helper_search_paths() -> Vec<std::path::PathBuf> {
    let exe = std::env::current_exe().ok();
    let override_path = std::env::var_os("MIPSCAN_HELPER").map(std::path::PathBuf::from);
    search_paths_from(
        exe.as_deref().and_then(|e| e.parent()),
        override_path.as_deref(),
    )
}

/// Locate the helper binary, or None if it is not installed.
pub fn helper_path() -> Option<std::path::PathBuf> {
    helper_search_paths().into_iter().find(|p| p.exists())
}

/// Convenience: read the neighbor table filtered to one interface's subnets.
pub fn neighbors_for(iface: &crate::model::Interface) -> Vec<crate::model::NeighborEntry> {
    netenv::neighbor_entries()
        .into_iter()
        .filter(|e| crate::util::ipv4_in_network_of(&e.ip, iface))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn an_explicit_override_is_searched_first() {
        let paths = search_paths_from(
            Some(Path::new("/opt/app")),
            Some(Path::new("/tmp/my-helper")),
        );
        assert_eq!(paths.first().unwrap(), Path::new("/tmp/my-helper"));
    }

    #[test]
    fn the_directory_beside_the_executable_is_searched() {
        let paths = search_paths_from(Some(Path::new("/opt/app")), None);
        assert!(paths.contains(&Path::new("/opt/app").join(helper_file_name())));
    }

    #[test]
    fn searching_still_works_without_a_known_executable_path() {
        // current_exe() can fail; that must not leave zero candidates on
        // platforms with system locations.
        let paths = search_paths_from(None, None);
        if cfg!(not(windows)) {
            assert!(!paths.is_empty());
        }
    }
}
