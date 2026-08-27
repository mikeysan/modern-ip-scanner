//! Scan orchestration: strategies in waves, identity resolution, diff, commit.
//!
//! The integrity rules from docs/design.md are applied here end-to-end: the
//! privilege state is probed, every enabled strategy must have its capability
//! confirmed *and* complete successfully, and only then may the diff treat
//! absence as evidence.

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
    let mut observed_states: HashMap<String, ObservedState> = HashMap::new();
    for d in &merged {
        let resolution = resolve_identity(store, d, &net_key)?;
        let key = match resolution {
            Resolution::Existing(existing) => {
                let canonical = maybe_refingerprint(store, &existing, d)?;
                store.update_device_fields(
                    &canonical,
                    d.name.as_deref(),
                    d.mac.as_deref().or(existing.mac.as_deref()),
                    d.vendor.as_deref().or(existing.vendor.as_deref()),
                )?;
                canonical
            }
            Resolution::New(key) => {
                store.upsert_device(
                    &key,
                    d.name.as_deref(),
                    d.mac.as_deref(),
                    d.vendor.as_deref(),
                    &net_key,
                )?;
                key
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
            },
        );
    }

    // 6. Diff against the previous inventory state.
    let prior: HashMap<String, PriorState> = store
        .presence_for_network(&net_key)?
        .into_iter()
        .map(|p| {
            let device = store.get_device(&p.device_key).ok().flatten();
            let display = store
                .get_user_name(&p.device_key)
                .ok()
                .flatten()
                .map(|(n, _)| n)
                .or_else(|| device.as_ref().and_then(|d| d.primary_name.clone()))
                .or_else(|| device.as_ref().and_then(|d| d.mac.clone()))
                .unwrap_or_else(|| p.device_key.clone());
            (
                p.device_key.clone(),
                PriorState {
                    device_key: p.device_key,
                    display_name: display,
                    last_ip: p.last_ip,
                    last_hostname: device.as_ref().and_then(|d| d.primary_name.clone()),
                    last_mac: device.as_ref().and_then(|d| d.mac.clone()),
                    miss_streak: p.miss_streak,
                },
            )
        })
        .collect();

    let integrity = if problems.is_empty() {
        ScanIntegrity::complete()
    } else {
        ScanIntegrity {
            complete: false,
            reasons: problems
                .iter()
                .map(|p| (p.strategy.clone(), p.reason.clone()))
                .collect(),
        }
    };
    let outcome = compute_diff(prior, &observed_states, &integrity, grace);

    // 7. Commit scan + observations + transitions + presence atomically.
    let finished_at = now();
    let stats = serde_json::json!({
        "devices_seen": observed_states.len(),
        "raw_observations": all_observations.len(),
    });
    let partial = !integrity.complete;
    let partial_reasons = problems.clone();
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
    for (key, state) in &observed_states {
        Store::insert_observation(
            &tx,
            scan_id,
            finished_at,
            key,
            &state.ip,
            state.mac.as_deref(),
            state.hostname.as_deref(),
            "merged",
            1.0,
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
