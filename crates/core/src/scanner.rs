//! Scan orchestration: strategies in waves, identity resolution, diff, commit.
//!
//! The integrity rules from docs/design.md rule 6 are assembled here: the
//! privilege state is probed, every enabled strategy must have its capability
//! confirmed and finish cleanly, *and* the scan must show it actually covered
//! the network ([`absence_evidence_gap`]). Only when both hold may the diff
//! treat "not seen" as evidence of absence.

use std::collections::HashMap;

use crate::diff::{compute_diff, ObservedState, PriorState, ScanIntegrity};
use crate::discovery::{registry, ScanContext, Strategy, StrategyOutcome};
use crate::identity;
use crate::merge::{maybe_refingerprint, merge_observations, resolve_identity, Resolution};
use crate::model::{Interface, Observation, PartialReason, PrivilegeState, ScanReport};
use crate::store::{Store, StoreError};
use crate::util::now;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Restrict to specific strategy ids; None = enabled set from settings.
    pub strategies: Option<Vec<String>>,
    /// Launch the privileged helper for full ARP coverage (asks for
    /// elevation via UAC/sudo when needed).
    pub use_helper: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("no usable network interface found")]
    NoInterface,
    #[error("interface {0} has no IPv4 address")]
    NoIpv4(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Progress callback for frontends.
pub type ProgressFn<'a> = &'a mut dyn FnMut(&str);

/// Fold one strategy's result into the scan's accumulated state.
///
/// Observations are kept unconditionally. A strategy that discovered devices
/// and *then* hit a problem still knows what it saw; the problem costs the
/// scan its completeness (so `gone` is suppressed), not its evidence.
fn absorb_outcome(
    id: &str,
    outcome: StrategyOutcome,
    observations: &mut Vec<Observation>,
    problems: &mut Vec<PartialReason>,
) {
    if let Some(reason) = outcome.problem {
        problems.push(PartialReason {
            strategy: id.to_string(),
            reason,
        });
    }
    observations.extend(outcome.observations);
}

/// Decide whether this scan may treat "not seen" as "not there".
///
/// Two conditions, both necessary:
///
/// 1. At least one strategy with [`Coverage::Exhaustive`] ran cleanly.
///    Presence-only strategies never hear from devices that stay quiet, so a
///    scan built only from them proves nothing.
/// 2. The scan actually saw something it *must* be able to see. The default
///    gateway is the anchor: on a working link it always answers. If an
///    exhaustive sweep came back without even the gateway, the link failed —
///    the network did not empty.
///
/// Returns `Some(reason)` when absence cannot be proven.
fn absence_evidence_gap(
    exhaustive_ran: &[String],
    gateway: Option<&str>,
    observed_ips: &std::collections::BTreeSet<String>,
) -> Option<PartialReason> {
    if exhaustive_ran.is_empty() {
        return Some(PartialReason {
            strategy: "scan".into(),
            reason: "no strategy with full address coverage ran, so nothing can be \
                     reported gone (enable arp-ping, or the privileged helper)"
                .into(),
        });
    }
    match gateway {
        Some(gw) if !observed_ips.contains(gw) => Some(PartialReason {
            strategy: exhaustive_ran.join(", "),
            reason: format!(
                "the sweep did not see the gateway {gw}, so the link — not the \
                 network — is what changed"
            ),
        }),
        None if observed_ips.is_empty() => Some(PartialReason {
            strategy: exhaustive_ran.join(", "),
            reason: "the sweep observed nothing at all and there is no gateway to \
                     confirm the link is up"
                .into(),
        }),
        _ => None,
    }
}

/// The inventory's view of every device on this network, as it stands right
/// now. Must be taken *before* the scan writes anything, or every field is
/// compared against itself.
fn snapshot_prior(store: &Store, net_key: &str) -> Result<HashMap<String, PriorState>, StoreError> {
    let mut prior = HashMap::new();
    for p in store.presence_for_network(net_key)? {
        let device = store.get_device(&p.device_key).ok().flatten();
        let display = store
            .get_user_name(&p.device_key)
            .ok()
            .flatten()
            .map(|(n, _)| n)
            .or_else(|| device.as_ref().and_then(|d| d.primary_name.clone()))
            .or_else(|| device.as_ref().and_then(|d| d.mac.clone()))
            .unwrap_or_else(|| p.device_key.clone());
        prior.insert(
            p.device_key.clone(),
            PriorState {
                device_key: p.device_key,
                display_name: display,
                last_ip: p.last_ip,
                last_hostname: device.as_ref().and_then(|d| d.primary_name.clone()),
                last_mac: device.as_ref().and_then(|d| d.mac.clone()),
                miss_streak: p.miss_streak,
                reported_gone: p.reported_gone,
                identity_stable: crate::identity::is_stable(
                    device.as_ref().and_then(|d| d.primary_name.as_deref()),
                    device.as_ref().and_then(|d| d.mac.as_deref()),
                ),
            },
        );
    }
    Ok(prior)
}

/// Re-point a prior snapshot through any aliases the scan created.
///
/// Resolving identity can re-fingerprint a device, moving its presence row to
/// a new key. A snapshot taken beforehand still holds the old key, and would
/// otherwise make one device look simultaneously new and gone.
fn remap_prior_through_aliases(
    store: &Store,
    prior: HashMap<String, PriorState>,
) -> Result<HashMap<String, PriorState>, StoreError> {
    let mut out: HashMap<String, PriorState> = HashMap::with_capacity(prior.len());
    for (key, mut state) in prior {
        let canonical = store.resolve_alias(&key)?;
        state.device_key = canonical.clone();
        match out.get(&canonical) {
            // Two old identities merged into one: keep the one seen most
            // recently, so a merge can never manufacture a `gone`.
            Some(existing) if existing.miss_streak <= state.miss_streak => {}
            _ => {
                out.insert(canonical, state);
            }
        }
    }
    Ok(out)
}

/// Resolve each merged observation to a device identity, updating the stored
/// device rows as it goes.
fn resolve_observed(
    store: &Store,
    merged: &[crate::merge::ObservedDevice],
    net_key: &str,
) -> Result<HashMap<String, ObservedState>, StoreError> {
    let mut observed_states: HashMap<String, ObservedState> = HashMap::new();
    for d in merged {
        // Stability is judged on everything known about the device, not just
        // this scan: a name learned earlier still makes it findable.
        let (key, known_name, known_mac) = match resolve_identity(store, d, net_key)? {
            Resolution::Existing(existing) => {
                let canonical = maybe_refingerprint(store, &existing, d)?;
                let name = d.name.clone().or_else(|| existing.primary_name.clone());
                let mac = d.mac.clone().or_else(|| existing.mac.clone());
                store.update_device_fields(
                    &canonical,
                    d.name.as_deref(),
                    mac.as_deref(),
                    d.vendor.as_deref().or(existing.vendor.as_deref()),
                )?;
                (canonical, name, mac)
            }
            Resolution::New(key) => {
                store.upsert_device(
                    &key,
                    d.name.as_deref(),
                    d.mac.as_deref(),
                    d.vendor.as_deref(),
                    net_key,
                )?;
                (key, d.name.clone(), d.mac.clone())
            }
        };
        let display = store
            .get_user_name(&key)
            .ok()
            .flatten()
            .map(|(n, _)| n)
            .or_else(|| d.name.clone())
            .or_else(|| d.mac.clone())
            .unwrap_or_else(|| d.ips.first().cloned().unwrap_or_default());
        observed_states.insert(
            key.clone(),
            ObservedState {
                device_key: key,
                display_name: display,
                ip: d.ips.first().cloned().unwrap_or_default(),
                hostname: d.name.clone(),
                mac: d.mac.clone(),
                identity_stable: crate::identity::is_stable(
                    known_name.as_deref(),
                    known_mac.as_deref(),
                ),
            },
        );
    }
    Ok(observed_states)
}

/// Resolve identities and diff them against the inventory.
///
/// Order matters and is the whole point of this function: `resolve_observed`
/// writes this scan's values into the device rows, so the prior snapshot has
/// to be taken first or the diff compares every field against itself.
struct ResolvedScan {
    observed: HashMap<String, ObservedState>,
    /// Which device each observed address belongs to, so raw observations can
    /// be recorded against the right device with their own provenance.
    ip_owner: HashMap<String, String>,
    outcome: crate::diff::DiffOutcome,
}

fn resolve_and_diff(
    store: &Store,
    merged: &[crate::merge::ObservedDevice],
    net_key: &str,
    integrity: &ScanIntegrity,
    grace: u32,
) -> Result<ResolvedScan, StoreError> {
    let prior = snapshot_prior(store, net_key)?;
    let observed = resolve_observed(store, merged, net_key)?;
    let prior = remap_prior_through_aliases(store, prior)?;
    let outcome = compute_diff(prior, &observed, integrity, grace);

    let mut ip_owner = HashMap::new();
    for d in merged {
        let Some(state) = observed.values().find(|s| d.ips.contains(&s.ip)) else {
            continue;
        };
        for ip in &d.ips {
            ip_owner.insert(ip.clone(), state.device_key.clone());
        }
    }
    Ok(ResolvedScan {
        observed,
        ip_owner,
        outcome,
    })
}

pub fn run_scan(
    store: &mut Store,
    opts: &ScanOptions,
    progress: ProgressFn<'_>,
) -> Result<ScanReport, ScanError> {
    let started_at = now();

    // 1. Interface selection + privilege probe.
    let ifaces = crate::netenv::interfaces();
    let iface = crate::netenv::default_interface(&ifaces).ok_or(ScanError::NoInterface)?;
    if iface.ipv4.is_empty() {
        return Err(ScanError::NoIpv4(iface.name));
    }
    progress(&format!(
        "interface: {} ({})",
        iface.name,
        iface.kind.as_str()
    ));

    let mut priv_state = crate::privilege::probe(Some(&iface));
    let helper: std::sync::Arc<std::sync::Mutex<Option<crate::privilege::helper::HelperClient>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    if opts.use_helper && !priv_state.has(crate::model::Capability::ArpResolve) {
        progress("launching privileged helper (elevation prompt)...");
        match crate::privilege::helper::HelperClient::launch() {
            Ok(mut h) => {
                // Verify it answers before trusting it.
                let probe_ip = iface
                    .gateway_v4
                    .clone()
                    .or_else(|| iface.ipv4.first().map(|c| c.addr.clone()))
                    .unwrap_or_else(|| "127.0.0.1".into());
                match h.arp(&probe_ip) {
                    Ok(_) => {
                        priv_state.helper_connected = true;
                        priv_state
                            .capabilities
                            .push(crate::model::Capability::ArpResolve);
                        *helper.lock().unwrap() = Some(h);
                    }
                    Err(e) => priv_state
                        .notes
                        .push(format!("helper launched but failed: {e}")),
                }
            }
            Err(e) => priv_state.notes.push(format!("helper unavailable: {e}")),
        }
    }

    // 2. Make sure the gateway is in the neighbor cache so we get its MAC,
    //    then compute the network key.
    let subnet = iface
        .ipv4
        .first()
        .and_then(|c| c.network_string())
        .unwrap_or_else(|| "0.0.0.0/0".into());
    let iface = ensure_gateway_mac(iface, &priv_state);
    let net_key = identity::network_key(
        iface.gateway_mac.as_deref(),
        &format!(
            "{subnet}/{}",
            iface.ipv4.first().map(|c| c.prefix).unwrap_or(0)
        ),
        iface.kind,
    );
    store.upsert_network(&net_key, Some(&subnet), iface.gateway_mac.as_deref())?;
    progress(&format!("network: {subnet} (key {net_key})"));

    // 3. Decide the strategy set.
    let enabled: Vec<String> = opts.strategies.clone().unwrap_or_else(|| {
        serde_json::from_str(
            &store
                .get_setting("enabled_strategies")
                .unwrap_or_else(|| "[]".into()),
        )
        .unwrap_or_default()
    });
    let strategies: Vec<_> = registry()
        .into_iter()
        .filter(|s| enabled.iter().any(|e| e == s.id()))
        .collect();
    let grace = store.grace_scans();

    // 4. Run waves.
    let mut all_observations: Vec<Observation> = Vec::new();
    let mut problems: Vec<PartialReason> = Vec::new();
    let mut strategies_run: Vec<String> = Vec::new();
    let arp_of = build_arp_resolver(&iface, &priv_state, &helper);

    let run_wave = |wave: u8,
                    ctx: &ScanContext,
                    all_obs: &mut Vec<Observation>,
                    problems: &mut Vec<PartialReason>,
                    run: &mut Vec<String>| {
        let wave_strategies: Vec<&dyn Strategy> = strategies
            .iter()
            .map(|s| s.as_ref() as &dyn Strategy)
            .filter(|s| s.wave() == wave)
            .collect();
        if wave_strategies.is_empty() {
            return;
        }
        let results: Vec<(&dyn Strategy, StrategyOutcome)> = std::thread::scope(|s| {
            let handles: Vec<_> = wave_strategies
                .iter()
                .map(|st| s.spawn(move || (*st, st.run(ctx))))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("strategy panicked"))
                .collect()
        });
        for (st, outcome) in results {
            run.push(st.id().to_string());
            absorb_outcome(st.id(), outcome, all_obs, problems);
        }
    };

    let make_ctx = |candidates: Vec<String>| ScanContext {
        iface: iface.clone(),
        candidates,
        caps: priv_state.capabilities.clone(),
        arp_resolve: Some(Box::new({
            let arp_of = arp_of.clone();
            move |ip: &str| arp_of(ip)
        })),
    };

    let wave1_ctx = make_ctx(vec![]);
    run_wave(
        1,
        &wave1_ctx,
        &mut all_observations,
        &mut problems,
        &mut strategies_run,
    );

    // Candidates for wave 2: everything wave 1 saw plus the gateway.
    let mut candidates: Vec<String> = all_observations
        .iter()
        .map(|o| o.ip.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    candidates.extend(
        crate::privilege::neighbors_for(&iface)
            .into_iter()
            .map(|n| n.ip),
    );
    if let Some(gw) = &iface.gateway_v4 {
        candidates.push(gw.clone());
    }
    candidates.retain(|ip| crate::util::ipv4_in_network_of(ip, &iface));

    let wave2_ctx = make_ctx(candidates);
    run_wave(
        2,
        &wave2_ctx,
        &mut all_observations,
        &mut problems,
        &mut strategies_run,
    );

    // Wave 3 (privileged full ARP), then a final neighbor re-read so that
    // devices woken by pings contribute their MACs.
    let wave3_ctx = make_ctx(vec![]);
    run_wave(
        3,
        &wave3_ctx,
        &mut all_observations,
        &mut problems,
        &mut strategies_run,
    );
    if strategies_run
        .iter()
        .any(|s| s == "ping-sweep" || s == "arp-ping")
    {
        for e in crate::privilege::neighbors_for(&iface) {
            all_observations.push(Observation {
                ip: e.ip,
                mac: Some(e.mac),
                name: None,
                vendor: None,
                source: "neighbor-recheck".into(),
                confidence: 0.7,
            });
        }
    }
    progress(&format!(
        "observed {} raw facts from {} strategies",
        all_observations.len(),
        strategies_run.len()
    ));

    if let Some(mut h) = helper.lock().unwrap().take() {
        h.shutdown();
        priv_state.helper_connected = false;
    }

    // 5. Merge + resolve identity.
    let merged = merge_observations(&all_observations);

    // Which strategies actually earned the right to testify about absence:
    // exhaustive coverage, ran this scan, and reported no problem.
    let exhaustive_ran: Vec<String> = strategies
        .iter()
        .filter(|s| s.coverage() == crate::discovery::Coverage::Exhaustive)
        .map(|s| s.id().to_string())
        .filter(|id| strategies_run.contains(id) && !problems.iter().any(|p| &p.strategy == id))
        .collect();
    let observed_ips: std::collections::BTreeSet<String> =
        merged.iter().flat_map(|d| d.ips.iter().cloned()).collect();
    let coverage_gap =
        absence_evidence_gap(&exhaustive_ran, iface.gateway_v4.as_deref(), &observed_ips);
    if let Some(gap) = &coverage_gap {
        progress(&format!("cannot report devices gone: {}", gap.reason));
    }

    // Everything that stops this scan short, whether a strategy failed or the
    // scan simply never covered enough ground to prove absence.
    let mut partial_reasons = problems.clone();
    partial_reasons.extend(coverage_gap.clone());
    let integrity = ScanIntegrity {
        complete: problems.is_empty(),
        absence_provable: coverage_gap.is_none(),
        reasons: partial_reasons
            .iter()
            .map(|p| (p.strategy.clone(), p.reason.clone()))
            .collect(),
    };
    // 6. Resolve identity and diff. The prior snapshot is taken inside, before
    //    any device row is written -- see `resolve_and_diff`.
    let ResolvedScan {
        observed: observed_states,
        ip_owner,
        outcome,
    } = resolve_and_diff(store, &merged, &net_key, &integrity, grace)?;

    // 7. Commit scan + observations + transitions + presence atomically.
    let finished_at = now();
    let stats = serde_json::json!({
        "devices_seen": observed_states.len(),
        "raw_observations": all_observations.len(),
    });
    // "Partial" is what the user sees, and it must mean exactly "this scan
    // could not tell you what is gone" — which covers both a failed strategy
    // and a scan that proved nothing.
    let partial = !integrity.may_prove_absence();
    let tx = store.begin()?;
    let scan_id = Store::insert_scan(
        &tx,
        started_at,
        finished_at,
        &net_key,
        partial,
        &serde_json::to_string(&priv_state).unwrap(),
        &serde_json::to_string(&strategies_run).unwrap(),
        &partial_reasons,
        &stats.to_string(),
    )?;
    // One row per raw observation, keeping which strategy saw what. A single
    // merged row per device would make `laninv history` unable to say *how* a
    // device was seen, and the source/confidence columns constants.
    for o in &all_observations {
        let Some(key) = ip_owner.get(&o.ip) else {
            continue;
        };
        Store::insert_observation(
            &tx,
            scan_id,
            finished_at,
            key,
            &o.ip,
            o.mac.as_deref(),
            o.name.as_ref().map(|(_, n)| n.as_str()),
            &o.source,
            o.confidence as f64,
        )?;
    }
    for t in &outcome.transitions {
        Store::insert_transition(
            &tx,
            scan_id,
            finished_at,
            &t.device_key,
            &net_key,
            t.kind,
            &t.changes,
        )?;
    }
    for key in &outcome.streak_resets {
        let ip = observed_states.get(key).map(|s| s.ip.clone());
        Store::upsert_presence_tx(&tx, key, &net_key, ip.as_deref())?;
    }
    for (key, _streak) in &outcome.streak_updates {
        Store::bump_miss_streak_tx(&tx, key, &net_key)?;
    }
    for key in &outcome.gone_marks {
        Store::mark_reported_gone_tx(&tx, key, &net_key)?;
    }
    tx.commit()?;

    let _ = store.prune();

    Ok(ScanReport {
        scan_id,
        network_key: net_key.clone(),
        network_label: store.get_network_label(&net_key),
        started_at,
        finished_at,
        partial,
        partial_reasons,
        strategies_run,
        devices_seen: observed_states.len(),
        transitions: outcome.transitions,
        interface: Some(iface),
    })
}

type SharedHelper =
    std::sync::Arc<std::sync::Mutex<Option<crate::privilege::helper::HelperClient>>>;
type SharedResolver = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

fn build_arp_resolver(
    iface: &Interface,
    priv_state: &PrivilegeState,
    helper: &SharedHelper,
) -> SharedResolver {
    // Prefer native ARP (Windows SendARP works unprivileged); fall back to
    // the helper; finally the neighbor cache.
    let native_ok =
        priv_state.has(crate::model::Capability::ArpResolve) && !cfg!(target_os = "linux");
    let _ = iface;
    let helper = std::sync::Arc::clone(helper);
    std::sync::Arc::new(move |ip: &str| {
        if native_ok {
            if let Some(mac) = crate::discovery::ping::native_arp_resolve(ip, 1000) {
                return Some(mac);
            }
        }
        if let Some(h) = helper.lock().unwrap().as_mut() {
            if let Ok(Some(mac)) = h.arp(ip) {
                return Some(mac);
            }
        }
        // Neighbor-cache fallback (always available, no packets).
        crate::netenv::neighbor_entries()
            .iter()
            .find(|e| e.ip == ip)
            .map(|e| e.mac.clone())
    })
}

/// Ensure the gateway's MAC is known: probe the neighbor cache, and if it is
/// absent, ping the gateway once and re-read.
fn ensure_gateway_mac(mut iface: Interface, priv_state: &PrivilegeState) -> Interface {
    use crate::model::Capability;
    let Some(gw) = iface.gateway_v4.clone() else {
        return iface;
    };
    let lookup = |gw: &str| {
        crate::netenv::neighbor_entries()
            .into_iter()
            .find(|e| e.ip == gw)
            .map(|e| e.mac)
    };
    if let Some(mac) = lookup(&gw) {
        iface.gateway_mac = Some(mac);
        return iface;
    }
    if priv_state.has(Capability::IcmpEcho)
        && crate::discovery::ping::echo(&gw, std::time::Duration::from_millis(1000))
    {
        std::thread::sleep(std::time::Duration::from_millis(300));
        if let Some(mac) = lookup(&gw) {
            iface.gateway_mac = Some(mac);
        }
    }
    iface
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::StrategyOutcome;
    use crate::model::{Transition, TransitionKind};

    fn obs(ip: &str) -> Observation {
        Observation {
            ip: ip.into(),
            mac: None,
            name: None,
            vendor: None,
            source: "test".into(),
            confidence: 0.9,
        }
    }

    fn ips(list: &[&str]) -> std::collections::BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn tmp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.sqlite3")).unwrap();
        (dir, store)
    }

    fn seen(ip: &str, mac: Option<&str>, name: Option<&str>) -> crate::merge::ObservedDevice {
        crate::merge::ObservedDevice {
            ips: vec![ip.to_string()],
            mac: mac.map(|m| m.to_string()),
            name: name.map(|n| n.to_string()),
            name_source: name.map(|_| crate::model::NameSource::Mdns),
            vendor: None,
            sources: vec!["test".into()],
            confidence: 0.9,
        }
    }

    /// Run one scan's worth of resolve+diff and commit presence, the way
    /// run_scan does.
    fn scan_once(
        store: &mut Store,
        devices: &[crate::merge::ObservedDevice],
        net: &str,
    ) -> Vec<Transition> {
        let ResolvedScan {
            observed, outcome, ..
        } = resolve_and_diff(store, devices, net, &ScanIntegrity::complete(), 2).unwrap();
        for key in &outcome.streak_resets {
            let ip = observed.get(key).map(|s| s.ip.clone());
            store.upsert_presence(key, net, ip.as_deref()).unwrap();
        }
        for (key, _) in &outcome.streak_updates {
            store.bump_miss_streak(key, net).unwrap();
        }
        for key in &outcome.gone_marks {
            let tx = store.begin().unwrap();
            Store::mark_reported_gone_tx(&tx, key, net).unwrap();
            tx.commit().unwrap();
        }
        outcome.transitions
    }

    fn changed_fields(transitions: &[Transition]) -> Vec<(String, Option<String>, Option<String>)> {
        transitions
            .iter()
            .filter(|t| t.kind == TransitionKind::Changed)
            .flat_map(|t| t.changes.iter().cloned())
            .map(|c| (c.field, c.from, c.to))
            .collect()
    }

    #[test]
    fn a_randomised_mac_device_is_never_reported_gone() {
        // A phone with a private Wi-Fi address alongside a NAS with a real
        // vendor OUI. Both stop answering; only one of them can honestly be
        // called gone, because only one of them can be recognised if it
        // comes back.
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("10.0.0.0/24"), None)
            .unwrap();
        let first = scan_once(
            &mut store,
            &[
                seen("10.0.0.7", Some("36:93:e6:08:48:d9"), None),
                seen("10.0.0.8", Some("90:48:46:10:3b:7a"), None),
            ],
            "net1",
        );
        assert_eq!(first.len(), 2, "both are recorded");
        let phone = first
            .iter()
            .find(|t| t.device_display == "36:93:e6:08:48:d9")
            .unwrap();
        assert!(
            phone.unstable_identity,
            "the randomised device must be flagged so the UI can explain it"
        );

        // Two consecutive complete scans with neither present reaches grace.
        scan_once(&mut store, &[], "net1");
        let second = scan_once(&mut store, &[], "net1");
        let gone: Vec<&str> = second
            .iter()
            .filter(|t| t.kind == TransitionKind::Gone)
            .map(|t| t.device_display.as_str())
            .collect();
        assert_eq!(
            gone,
            vec!["90:48:46:10:3b:7a"],
            "only the device whose identity would survive a return"
        );
    }

    #[test]
    fn a_randomised_device_that_announces_a_name_becomes_trackable() {
        // Naming is the escape hatch: a name is matchable across rotations,
        // so the device stops being ephemeral and can be reported gone.
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("10.0.0.0/24"), None)
            .unwrap();
        let first = scan_once(
            &mut store,
            &[seen(
                "10.0.0.7",
                Some("36:93:e6:08:48:d9"),
                Some("my-phone"),
            )],
            "net1",
        );
        assert!(
            !first[0].unstable_identity,
            "a name outlives the MAC that carried it"
        );
        scan_once(&mut store, &[], "net1");
        let second = scan_once(&mut store, &[], "net1");
        assert!(second.iter().any(|t| t.kind == TransitionKind::Gone));
    }

    #[test]
    fn a_new_mac_on_a_known_device_is_reported_as_changed() {
        // The scan updates the device row before diffing, so without an
        // explicit pre-scan snapshot this compares the new MAC against itself
        // and reports nothing.
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("10.0.0.0/24"), None)
            .unwrap();

        let first = scan_once(
            &mut store,
            &[seen("10.0.0.5", Some("aa:aa:aa:aa:aa:aa"), Some("printer"))],
            "net1",
        );
        assert!(first.iter().any(|t| t.kind == TransitionKind::New));

        let second = scan_once(
            &mut store,
            &[seen("10.0.0.5", Some("bb:bb:bb:bb:bb:bb"), Some("printer"))],
            "net1",
        );
        assert_eq!(
            changed_fields(&second),
            vec![(
                "mac".to_string(),
                Some("aa:aa:aa:aa:aa:aa".to_string()),
                Some("bb:bb:bb:bb:bb:bb".to_string())
            )],
            "a device that changed its MAC must be reported as changed"
        );
    }

    #[test]
    fn a_new_hostname_on_a_known_device_is_reported_as_changed() {
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("10.0.0.0/24"), None)
            .unwrap();
        scan_once(
            &mut store,
            &[seen(
                "10.0.0.5",
                Some("aa:aa:aa:aa:aa:aa"),
                Some("old-name"),
            )],
            "net1",
        );
        let second = scan_once(
            &mut store,
            &[seen(
                "10.0.0.5",
                Some("aa:aa:aa:aa:aa:aa"),
                Some("new-name"),
            )],
            "net1",
        );
        assert_eq!(
            changed_fields(&second),
            vec![(
                "hostname".to_string(),
                Some("old-name".to_string()),
                Some("new-name".to_string())
            )]
        );
    }

    #[test]
    fn an_unchanged_device_is_reported_repeatedly_as_nothing() {
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("10.0.0.0/24"), None)
            .unwrap();
        let d = seen("10.0.0.5", Some("aa:aa:aa:aa:aa:aa"), Some("printer"));
        scan_once(&mut store, std::slice::from_ref(&d), "net1");
        for round in 0..3 {
            let t = scan_once(&mut store, std::slice::from_ref(&d), "net1");
            assert!(t.is_empty(), "round {round} produced spurious {t:?}");
        }
    }

    #[test]
    fn a_field_we_did_not_observe_is_not_a_change() {
        // mDNS answers on one scan and not the next. Silence about a name is
        // not the same as the name going away -- the same principle as the
        // integrity rule, applied per field.
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("10.0.0.0/24"), None)
            .unwrap();
        scan_once(
            &mut store,
            &[seen("10.0.0.5", Some("aa:aa:aa:aa:aa:aa"), Some("printer"))],
            "net1",
        );
        let second = scan_once(
            &mut store,
            &[seen("10.0.0.5", Some("aa:aa:aa:aa:aa:aa"), None)],
            "net1",
        );
        assert!(
            changed_fields(&second).is_empty(),
            "not hearing a name must not be reported as losing it, got {:?}",
            changed_fields(&second)
        );
    }

    #[test]
    fn absence_needs_a_strategy_that_sweeps_every_address() {
        let gap = absence_evidence_gap(&[], Some("192.168.1.254"), &ips(&["192.168.1.254"]));
        assert!(
            gap.is_some(),
            "presence-only strategies cannot prove a device is gone"
        );
    }

    #[test]
    fn absence_needs_the_gateway_to_have_answered() {
        // The classic false-gone: Wi-Fi drops mid-scan, the sweep completes
        // with zero replies, and every device looks gone.
        let gap = absence_evidence_gap(&["arp-ping".into()], Some("192.168.1.254"), &ips(&[]));
        assert!(
            gap.is_some(),
            "a sweep that could not even reach the gateway proves nothing"
        );
    }

    #[test]
    fn a_covered_scan_has_no_evidence_gap() {
        let gap = absence_evidence_gap(
            &["arp-ping".into()],
            Some("192.168.1.254"),
            &ips(&["192.168.1.254", "192.168.1.5"]),
        );
        assert!(gap.is_none());
    }

    #[test]
    fn without_a_gateway_seeing_anything_at_all_is_the_anchor() {
        // An isolated segment has no gateway; fall back to "the sweep saw
        // something", which still rules out a dead link.
        assert!(absence_evidence_gap(&["arp-ping".into()], None, &ips(&[])).is_some());
        assert!(absence_evidence_gap(&["arp-ping".into()], None, &ips(&["10.0.0.9"])).is_none());
    }

    #[test]
    fn a_failing_strategy_still_contributes_what_it_saw() {
        // arp-ping reports "prefix too large" *after* sweeping what it could;
        // throwing that away loses real devices and suppresses `new`.
        let outcome = StrategyOutcome {
            observations: vec![obs("10.0.0.5"), obs("10.0.0.6")],
            problem: Some("prefix too large for exhaustive sweep".into()),
        };
        let mut observations = Vec::new();
        let mut problems = Vec::new();
        absorb_outcome("arp-ping", outcome, &mut observations, &mut problems);

        assert_eq!(
            observations.len(),
            2,
            "evidence must survive; the problem only costs completeness"
        );
        assert_eq!(problems.len(), 1, "the scan must still be marked partial");
        assert_eq!(problems[0].strategy, "arp-ping");
    }

    #[test]
    fn a_clean_strategy_contributes_observations_and_no_problem() {
        let outcome = StrategyOutcome::ok(vec![obs("10.0.0.7")]);
        let mut observations = Vec::new();
        let mut problems = Vec::new();
        absorb_outcome("arp-cache", outcome, &mut observations, &mut problems);
        assert_eq!(observations.len(), 1);
        assert!(problems.is_empty());
    }
}
