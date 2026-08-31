//! Scan-vs-inventory diff engine.
//!
//! This is where the product's core trust property lives (docs/design.md
//! rule 6): a scan may only call a device `gone` when it could actually have
//! seen it. That needs two things — the scan finished without a strategy
//! failing (`complete`), and it demonstrably covered the network
//! (`absence_provable`). A scan missing either is *partial*: it may emit
//! `new` and `changed`, because seeing a device proves it is there, but it
//! may never emit `gone` nor advance a miss streak. `gone` further requires
//! the device to have been missed for `grace_scans` consecutive such scans.

use std::collections::HashMap;

use crate::model::{FieldChange, Transition, TransitionKind};

/// How complete a scan was; produced by the scanner from strategy results, the
/// privilege probe, and what the scan actually managed to observe.
#[derive(Debug, Clone)]
pub struct ScanIntegrity {
    /// All enabled strategies had their privilege confirmed and finished.
    pub complete: bool,
    /// The scan demonstrably covered the network, so "not seen" is real
    /// evidence of absence.
    ///
    /// Separate from `complete` because a scan can finish without a single
    /// error and still prove nothing: a strategy that only ever confirms
    /// presence (mDNS, SSDP, NetBIOS) is silent about devices that simply did
    /// not answer, and an exhaustive sweep that saw *nothing at all* means the
    /// link failed, not that the network emptied.
    pub absence_provable: bool,
    pub reasons: Vec<(String, String)>,
}

impl ScanIntegrity {
    /// A scan that finished cleanly and covered the network.
    pub fn complete() -> ScanIntegrity {
        ScanIntegrity {
            complete: true,
            absence_provable: true,
            reasons: Vec::new(),
        }
    }

    /// A scan where a strategy could not do its job.
    pub fn partial(strategy: &str, reason: &str) -> ScanIntegrity {
        ScanIntegrity {
            complete: false,
            absence_provable: true,
            reasons: vec![(strategy.to_string(), reason.to_string())],
        }
    }

    /// A scan that finished cleanly but cannot testify to absence.
    pub fn uncovered(strategy: &str, reason: &str) -> ScanIntegrity {
        ScanIntegrity {
            complete: true,
            absence_provable: false,
            reasons: vec![(strategy.to_string(), reason.to_string())],
        }
    }

    /// True when this scan may emit `gone` and advance miss streaks.
    pub fn may_prove_absence(&self) -> bool {
        self.complete && self.absence_provable
    }
}

/// The previous state of one device on the scanned network.
#[derive(Debug, Clone)]
pub struct PriorState {
    pub device_key: String,
    pub display_name: String,
    pub last_ip: Option<String>,
    pub last_hostname: Option<String>,
    pub last_mac: Option<String>,
    pub miss_streak: i64,
    /// True when a `gone` transition has already been emitted for this
    /// absence. Without it, "has it crossed the threshold?" is indistinguishable
    /// from "has it been past the threshold for a while?" whenever
    /// `grace_scans` changes underneath a device.
    pub reported_gone: bool,
    /// False when this device cannot be re-identified across scans — see
    /// [`crate::identity::is_stable`]. Absence is unprovable for those.
    pub identity_stable: bool,
}

/// The newly observed state of one device.
#[derive(Debug, Clone)]
pub struct ObservedState {
    pub device_key: String,
    pub display_name: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    /// False when this device cannot be re-identified across scans.
    pub identity_stable: bool,
}

/// Outcome of the diff, including updated miss streaks the store should apply.
pub struct DiffOutcome {
    pub transitions: Vec<Transition>,
    /// (device_key, new_streak) for devices not seen this scan. Only advanced
    /// when the scan could prove absence; empty on partial scans by design.
    pub streak_updates: Vec<(String, i64)>,
    /// Devices whose streak should reset because they were seen again.
    pub streak_resets: Vec<String>,
    /// Devices just announced `gone`, so the store can record that the
    /// announcement was made and not repeat it next scan.
    pub gone_marks: Vec<String>,
}

pub fn compute_diff(
    prior: HashMap<String, PriorState>,
    observed: &HashMap<String, ObservedState>,
    integrity: &ScanIntegrity,
    grace_scans: u32,
) -> DiffOutcome {
    let mut transitions = Vec::new();
    let mut streak_updates = Vec::new();
    let mut streak_resets = Vec::new();
    let mut gone_marks = Vec::new();

    // --- devices observed this scan ---
    for obs in observed.values() {
        match prior.get(&obs.device_key) {
            None => {
                // Either genuinely new, or back from `gone` (presence row may
                // still exist with a stale streak; caller decides via prior).
                transitions.push(Transition {
                    kind: TransitionKind::New,
                    device_key: obs.device_key.clone(),
                    device_display: obs.display_name.clone(),
                    changes: vec![],
                    unstable_identity: !obs.identity_stable,
                });
                streak_resets.push(obs.device_key.clone());
            }
            Some(p) => {
                streak_resets.push(obs.device_key.clone());
                // A field changed only when this scan actually observed a
                // value that differs from the one on record. Not hearing a
                // name is not the same as the name going away — the integrity
                // rule again, applied one field at a time.
                let mut changes = Vec::new();
                let mut note = |field: &str, from: &Option<String>, to: Option<&str>| {
                    if let Some(to) = to.filter(|t| !t.is_empty()) {
                        if from.as_deref() != Some(to) {
                            changes.push(FieldChange {
                                field: field.to_string(),
                                from: from.clone(),
                                to: Some(to.to_string()),
                            });
                        }
                    }
                };
                note("ip", &p.last_ip, Some(obs.ip.as_str()));
                note("hostname", &p.last_hostname, obs.hostname.as_deref());
                note("mac", &p.last_mac, obs.mac.as_deref());
                if !changes.is_empty() {
                    transitions.push(Transition {
                        kind: TransitionKind::Changed,
                        device_key: obs.device_key.clone(),
                        device_display: obs.display_name.clone(),
                        changes,
                        unstable_identity: !obs.identity_stable,
                    });
                }
                // Returning from an absence we actually announced. A quiet
                // spell nobody was told about is not a return.
                if p.reported_gone {
                    transitions.push(Transition {
                        kind: TransitionKind::Returned,
                        device_key: obs.device_key.clone(),
                        device_display: obs.display_name.clone(),
                        changes: vec![],
                        unstable_identity: !obs.identity_stable,
                    });
                }
            }
        }
    }

    // --- devices NOT observed this scan ---
    for (key, p) in &prior {
        if observed.contains_key(key) {
            continue;
        }
        if !integrity.may_prove_absence() {
            // Integrity rule: a scan that did not finish, or that never
            // covered the network, is *no evidence of absence*. No `gone`,
            // and the miss streak must not advance.
            continue;
        }
        if !p.identity_stable {
            // The same rule, one device at a time. This device's identity
            // changes by design, so "did not answer" cannot be told apart
            // from "answered under a different address". Suppression is per
            // device: its stable neighbours are still diffed normally.
            continue;
        }
        let new_streak = p.miss_streak + 1;
        streak_updates.push((key.clone(), new_streak));
        if new_streak >= grace_scans as i64 && !p.reported_gone {
            gone_marks.push(key.clone());
            transitions.push(Transition {
                kind: TransitionKind::Gone,
                device_key: key.clone(),
                device_display: p.display_name.clone(),
                changes: vec![],
                unstable_identity: false,
            });
        }
    }

    DiffOutcome {
        transitions,
        streak_updates,
        streak_resets,
        gone_marks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn prior(key: &str, ip: &str, mac: Option<&str>, hostname: Option<&str>) -> PriorState {
        PriorState {
            device_key: key.into(),
            display_name: format!("dev-{key}"),
            last_ip: Some(ip.into()),
            last_hostname: hostname.map(|s| s.into()),
            last_mac: mac.map(|s| s.into()),
            miss_streak: 0,
            reported_gone: false,
            identity_stable: true,
        }
    }

    fn observed(key: &str, ip: &str, mac: Option<&str>, hostname: Option<&str>) -> ObservedState {
        ObservedState {
            device_key: key.into(),
            display_name: format!("dev-{key}"),
            ip: ip.into(),
            hostname: hostname.map(|s| s.into()),
            mac: mac.map(|s| s.into()),
            identity_stable: true,
        }
    }

    fn map<V>(entries: Vec<(String, V)>) -> HashMap<String, V> {
        entries.into_iter().collect()
    }

    #[test]
    fn a_scan_that_cannot_prove_absence_never_emits_gone() {
        // Every strategy succeeded, but none of them can testify to absence:
        // mDNS hearing nothing means nothing. Observed live: `mipscan scan
        // --strategy mdns` returned zero observations and reported a complete
        // scan, which would have marked the whole inventory gone.
        let prior = map(vec![(
            "a".into(),
            prior("a", "10.0.0.1", Some("aa:aa:aa:aa:aa:aa"), Some("host-a")),
        )]);
        let observed: HashMap<String, ObservedState> = HashMap::new();
        let integrity = ScanIntegrity::uncovered("scan", "no exhaustive strategy ran");
        let out = compute_diff(prior, &observed, &integrity, 2);
        assert!(
            !out.transitions
                .iter()
                .any(|t| t.kind == TransitionKind::Gone),
            "a scan with no coverage must not report anything gone"
        );
        assert!(
            out.streak_updates.is_empty(),
            "nor may it advance a miss streak toward gone"
        );
    }

    #[test]
    fn an_uncovered_scan_still_reports_new_and_changed() {
        // Presence is still evidence: seeing a device proves it is there.
        let prior_map = map(vec![(
            "a".into(),
            prior("a", "10.0.0.1", Some("aa:aa:aa:aa:aa:aa"), Some("host-a")),
        )]);
        let observed = map(vec![
            (
                "a".into(),
                observed("a", "10.0.0.9", Some("aa:aa:aa:aa:aa:aa"), Some("host-a")),
            ),
            (
                "b".into(),
                observed("b", "10.0.0.2", Some("bb:bb:bb:bb:bb:bb"), None),
            ),
        ]);
        let integrity = ScanIntegrity::uncovered("scan", "gateway not seen");
        let out = compute_diff(prior_map, &observed, &integrity, 2);
        assert!(out
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::New));
        assert!(out
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::Changed));
    }

    #[test]
    fn coverage_and_completeness_are_independent_gates() {
        let complete = ScanIntegrity::complete();
        assert!(complete.may_prove_absence());
        assert!(!ScanIntegrity::partial("s", "r").may_prove_absence());
        assert!(!ScanIntegrity::uncovered("s", "r").may_prove_absence());
    }

    #[test]
    fn an_unstable_identity_is_never_reported_gone() {
        // A phone with a randomised MAC that stops answering may have left,
        // or may have come back wearing a different address. We cannot tell,
        // so we must not claim.
        let p = map(vec![(
            "phone".into(),
            PriorState {
                miss_streak: 1,
                identity_stable: false,
                ..prior("phone", "10.0.0.7", Some("36:93:e6:08:48:d9"), None)
            },
        )]);
        let out = compute_diff(p, &HashMap::new(), &ScanIntegrity::complete(), 2);
        assert!(
            !out.transitions
                .iter()
                .any(|t| t.kind == TransitionKind::Gone),
            "a randomised identity must never be reported gone"
        );
        assert!(
            out.streak_updates.is_empty(),
            "nor may it accrue a miss streak toward gone"
        );
    }

    #[test]
    fn a_stable_neighbour_is_unaffected_by_an_unstable_one() {
        // Suppression is per device, not per scan.
        let p = map(vec![
            (
                "phone".into(),
                PriorState {
                    miss_streak: 1,
                    identity_stable: false,
                    ..prior("phone", "10.0.0.7", Some("36:93:e6:08:48:d9"), None)
                },
            ),
            (
                "nas".into(),
                PriorState {
                    miss_streak: 1,
                    ..prior("nas", "10.0.0.8", Some("90:48:46:10:3b:7a"), None)
                },
            ),
        ]);
        let out = compute_diff(p, &HashMap::new(), &ScanIntegrity::complete(), 2);
        let gone: Vec<&str> = out
            .transitions
            .iter()
            .filter(|t| t.kind == TransitionKind::Gone)
            .map(|t| t.device_key.as_str())
            .collect();
        assert_eq!(gone, vec!["nas"]);
    }

    #[test]
    fn a_new_transition_records_whether_the_identity_will_hold() {
        let observed = map(vec![(
            "phone".into(),
            ObservedState {
                identity_stable: false,
                ..observed("phone", "10.0.0.7", Some("36:93:e6:08:48:d9"), None)
            },
        )]);
        let out = compute_diff(HashMap::new(), &observed, &ScanIntegrity::complete(), 2);
        let t = out
            .transitions
            .iter()
            .find(|t| t.kind == TransitionKind::New)
            .expect("new transition");
        assert!(
            t.unstable_identity,
            "the UI has to be able to say why this device will keep reappearing"
        );
    }

    #[test]
    fn partial_scan_never_emits_gone() {
        for reason in ["icmp unavailable", "helper refused", "strategy error"] {
            let prior = map(vec![(
                "a".into(),
                prior("a", "10.0.0.1", Some("aa:aa:aa:aa:aa:aa"), Some("host-a")),
            )]);
            let observed: HashMap<String, ObservedState> = HashMap::new();
            let integrity = ScanIntegrity::partial("ping-sweep", reason);
            let out = compute_diff(prior, &observed, &integrity, 2);
            assert!(
                !out.transitions
                    .iter()
                    .any(|t| t.kind == TransitionKind::Gone),
                "partial scan ({reason}) must not emit gone"
            );
            assert!(
                out.streak_updates.is_empty(),
                "partial scan must not advance streaks"
            );
        }
    }

    #[test]
    fn partial_scan_still_allows_new_and_changed() {
        let prior_map = map(vec![(
            "a".into(),
            prior("a", "10.0.0.1", Some("aa:aa:aa:aa:aa:aa"), Some("host-a")),
        )]);
        let observed = map(vec![
            (
                "a".into(),
                observed("a", "10.0.0.9", Some("aa:aa:aa:aa:aa:aa"), Some("host-a")),
            ),
            (
                "b".into(),
                observed("b", "10.0.0.2", Some("bb:bb:bb:bb:bb:bb"), None),
            ),
        ]);
        let out = compute_diff(prior_map, &observed, &ScanIntegrity::partial("x", "y"), 2);
        assert!(out
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::New));
        assert!(out
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::Changed));
    }

    #[test]
    fn gone_is_reported_once_per_absence_however_long_it_lasts() {
        let empty: HashMap<String, ObservedState> = HashMap::new();
        let absent = |streak: i64, reported: bool| {
            map(vec![(
                "a".into(),
                PriorState {
                    miss_streak: streak,
                    reported_gone: reported,
                    ..prior("a", "10.0.0.1", None, None)
                },
            )])
        };
        let gones = |p| {
            compute_diff(p, &empty, &ScanIntegrity::complete(), 2)
                .transitions
                .iter()
                .filter(|t| t.kind == TransitionKind::Gone)
                .count()
        };
        assert_eq!(gones(absent(1, false)), 1, "crossing grace reports once");
        for streak in [2, 3, 9] {
            assert_eq!(
                gones(absent(streak, true)),
                0,
                "streak {streak} re-reported an absence already announced"
            );
        }
    }

    #[test]
    fn a_lowered_grace_still_reports_a_device_that_is_already_absent() {
        // Grace was 4 and the device sat at 3, unreported. The user lowers it
        // to 2. Exact-equality would step from 3 to 4 and never fire.
        let empty: HashMap<String, ObservedState> = HashMap::new();
        let p = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 3,
                reported_gone: false,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        assert!(compute_diff(p, &empty, &ScanIntegrity::complete(), 2)
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::Gone));
    }

    #[test]
    fn returning_is_announced_only_if_the_absence_was() {
        let observed = map(vec![("a".into(), observed("a", "10.0.0.1", None, None))]);
        let returned = |reported: bool| {
            let p = map(vec![(
                "a".into(),
                PriorState {
                    miss_streak: 5,
                    reported_gone: reported,
                    ..prior("a", "10.0.0.1", None, None)
                },
            )]);
            compute_diff(p, &observed, &ScanIntegrity::complete(), 2)
                .transitions
                .iter()
                .any(|t| t.kind == TransitionKind::Returned)
        };
        assert!(returned(true), "a device we called gone came back");
        assert!(
            !returned(false),
            "a quiet spell nobody was told about is not a return"
        );
    }

    #[test]
    fn an_announced_absence_is_cleared_when_the_device_returns() {
        let observed = map(vec![("a".into(), observed("a", "10.0.0.1", None, None))]);
        let p = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 5,
                reported_gone: true,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let out = compute_diff(p, &observed, &ScanIntegrity::complete(), 2);
        assert!(
            out.streak_resets.contains(&"a".to_string()),
            "the next absence must be announceable again"
        );
    }

    #[test]
    fn gone_requires_grace_on_complete_scans() {
        let empty: HashMap<String, ObservedState> = HashMap::new();
        // First miss: streak 1 < grace 2 → no gone yet.
        let p0 = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 0,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let out1 = compute_diff(p0, &empty, &ScanIntegrity::complete(), 2);
        assert!(!out1
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::Gone));
        assert_eq!(out1.streak_updates[0].1, 1);
        // Second consecutive miss: streak 2 == grace → gone exactly once.
        let p1 = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 1,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let out2 = compute_diff(p1, &empty, &ScanIntegrity::complete(), 2);
        let gones: Vec<_> = out2
            .transitions
            .iter()
            .filter(|t| t.kind == TransitionKind::Gone)
            .collect();
        assert_eq!(gones.len(), 1);
        // Third miss: the absence was already announced, so it stays quiet.
        let p2 = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 2,
                reported_gone: true,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let out3 = compute_diff(p2, &empty, &ScanIntegrity::complete(), 2);
        assert!(!out3
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::Gone));
    }

    #[test]
    fn partial_miss_does_not_count_toward_grace() {
        // Miss, partial miss, complete miss: only 2 real misses → gone only
        // on the scan *after* that if complete again.
        let empty: HashMap<String, ObservedState> = HashMap::new();
        let p0 = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 0,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let after_complete = compute_diff(p0, &empty, &ScanIntegrity::complete(), 2).streak_updates;
        assert_eq!(after_complete[0].1, 1);
        // A partial scan leaves the streak untouched.
        let p1a = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 1,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let after_partial = compute_diff(p1a, &empty, &ScanIntegrity::partial("s", "r"), 2);
        assert!(after_partial.streak_updates.is_empty());
        // Next complete miss reaches grace 2.
        let p1b = map(vec![(
            "a".into(),
            PriorState {
                miss_streak: 1,
                ..prior("a", "10.0.0.1", None, None)
            },
        )]);
        let out = compute_diff(p1b, &empty, &ScanIntegrity::complete(), 2);
        assert!(out
            .transitions
            .iter()
            .any(|t| t.kind == TransitionKind::Gone));
    }

    #[test]
    fn field_changes_detected() {
        let p = map(vec![(
            "a".into(),
            prior("a", "10.0.0.1", Some("aa:aa:aa:aa:aa:aa"), Some("old-name")),
        )]);
        let observed = map(vec![(
            "a".into(),
            observed("a", "10.0.0.2", Some("aa:aa:aa:aa:aa:ab"), Some("new-name")),
        )]);
        let out = compute_diff(p, &observed, &ScanIntegrity::complete(), 2);
        let t = out
            .transitions
            .iter()
            .find(|t| t.kind == TransitionKind::Changed)
            .unwrap();
        let fields: Vec<&str> = t.changes.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"ip"));
        assert!(fields.contains(&"hostname"));
        assert!(fields.contains(&"mac"));
    }
}
