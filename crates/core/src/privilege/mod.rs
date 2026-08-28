//! Runtime privilege probing and the optional helper client.
//!
//! Nothing here ever *assumes* privilege: each capability is tested with a
//! cheap live operation against the loopback or the interface's gateway.

pub mod helper;

use crate::model::{Capability, PrivilegeState};
use crate::netenv;

/// Whether ARP resolution is genuinely available to the scanner itself.
///
/// Permission is not capability. On Linux root may open a raw AF_PACKET
/// socket, but the scanner has no ARP built on one -- the helper is the
/// implementation. Granting the capability for permission alone let
/// `arp-ping` sweep 4096 addresses in 73ms, resolve none of them, and then
/// report the failure as a vanished gateway.
fn arp_capability(raw_sockets_permitted: bool, native_arp_works: bool) -> bool {
    // Only an implementation counts. Permission with nothing behind it is
    // not a capability, and claiming it is worse than admitting the gap:
    // `arp-ping` reads the capability as licence to sweep.
    let _ = raw_sockets_permitted;
    native_arp_works
}

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
                let native = crate::discovery::ping::native_arp_resolve(gw, 1000).is_some();
                if arp_capability(false, native) {
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
        let raw_ok = crate::discovery::ping::raw_socket_capability();
        // There is no native ARP in the scanner on Linux: `native_arp_resolve`
        // is a stub and the helper holds the only implementation. So the
        // answer here is always no, and the note explains which of the two
        // reasons applies.
        if arp_capability(raw_ok, false) {
            state.capabilities.push(Capability::ArpResolve);
        } else if raw_ok {
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
        "laninv-helper.exe"
    } else {
        "laninv-helper"
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
        for dir in ["/usr/libexec/laninv", "/usr/lib/laninv", "/usr/local/bin"] {
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
    let override_path = std::env::var_os("LANINV_HELPER").map(std::path::PathBuf::from);
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

    /// Being allowed to open a raw socket is not the same as having an ARP
    /// implementation. On Linux the scanner has none -- the helper does -- so
    /// root alone must not satisfy `arp-ping`'s requirement.
    #[test]
    fn permission_without_an_implementation_is_not_a_capability() {
        assert!(!arp_capability(true, false), "root alone is not enough");
        assert!(arp_capability(false, true), "a working native ARP is");
        assert!(arp_capability(true, true));
        assert!(!arp_capability(false, false));
    }

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
