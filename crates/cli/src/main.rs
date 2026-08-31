//! `mipscan` — headless Modern IP Scanner CLI sharing the core with the GUI.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use modern_ip_scanner_core::display::{device_display, short_key};
use modern_ip_scanner_core::model::{DeviceView, NetworkView, ScanReport, TransitionKind};
use modern_ip_scanner_core::store::Store;
use modern_ip_scanner_core::util::fmt_time;

#[derive(Parser)]
#[command(
    name = "mipscan",
    version,
    about = "LAN inventory & diff scanner — remembers your networks and devices",
    long_about = "An inventory-first LAN scanner: every scan tells you what's new, what changed, \
                  and what's gone. Runs unprivileged; use --helper for full ARP coverage."
)]
struct Cli {
    /// Emit machine-readable JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a scan of the current network and record the diff.
    Scan {
        /// Only run these strategies (ids; repeatable).
        #[arg(long = "strategy", value_name = "ID")]
        strategies: Vec<String>,
        /// Launch the privileged helper for full ARP coverage.
        #[arg(long)]
        helper: bool,
    },
    /// List remembered devices (optionally scoped to a network).
    Devices {
        /// Network key (see `mipscan networks`). Omit for all networks.
        #[arg(long)]
        network: Option<String>,
    },
    /// Show what the last scan changed on a network.
    Diff {
        /// Network key; defaults to the most recently scanned network.
        #[arg(long)]
        network: Option<String>,
    },
    /// Assign a persistent user name (and optional notes) to a device.
    Name {
        /// Device id or key (see `mipscan devices`).
        device: String,
        /// The name to assign.
        name: Option<String>,
        #[arg(short = 'n', long)]
        notes: Option<String>,
        /// Remove the assigned name instead of setting one.
        #[arg(long, conflicts_with = "name")]
        clear: bool,
    },
    /// List remembered networks.
    Networks,
    /// Give a remembered network a label ("Home", "Office 3F").
    Label {
        /// Network key or its displayed prefix (see `mipscan networks`).
        network: String,
        /// The label to assign.
        label: String,
    },
    /// Read or change a setting.
    Config {
        /// Setting name; omit to list every setting.
        key: Option<String>,
        /// New value; omit to read the current one.
        value: Option<String>,
    },
    /// Show a device's observation/transition history.
    History {
        /// Device id or key.
        device: String,
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Export the inventory as CSV or JSON.
    Export {
        #[arg(long)]
        network: Option<String>,
        #[arg(long, default_value = "csv")]
        format: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut store = Store::open_default().context("opening inventory database")?;

    match &cli.command {
        Command::Scan { strategies, helper } => {
            let opts = modern_ip_scanner_core::ScanOptions {
                strategies: if strategies.is_empty() {
                    None
                } else {
                    Some(strategies.clone())
                },
                use_helper: *helper,
            };
            let mut progress = |msg: &str| eprintln!("  {msg}");
            let report = modern_ip_scanner_core::run_scan(&mut store, &opts, &mut progress)
                .context("scan failed")?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }
        }
        Command::Devices { network } => {
            let devices = store.list_devices(network.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&devices)?);
            } else {
                print_devices(&devices);
            }
        }
        Command::Diff { network } => {
            let nk = match network {
                Some(k) => k.clone(),
                None => most_recent_network(&store)?
                    .context("no scans recorded yet — run `mipscan scan` first")?,
            };
            let (scan_id, at) = store
                .last_scan_for_network(&nk)?
                .context("no scan recorded for that network")?;
            let summary = store.scan_summary(scan_id)?;
            let transitions = store.transitions_of_scan(scan_id)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "network": nk,
                        "scan_id": scan_id,
                        "finished_at": at,
                        "partial": summary.as_ref().map(|s| s.partial),
                        "partial_reasons": summary.as_ref().map(|s| s.partial_reasons.clone()),
                        "transitions": transitions,
                    })
                );
            } else {
                println!(
                    "Diff for network {nk} (scan #{scan_id} at {} UTC)",
                    fmt_time(at)
                );
                // A diff that cannot report `gone` has to say so, or "no
                // changes" reads as "nothing left" when it means "we could
                // not tell".
                if let Some(s) = &summary {
                    if s.partial {
                        println!("  ⚠ PARTIAL SCAN — \"gone\" transitions suppressed:");
                        for r in &s.partial_reasons {
                            println!("    · {}: {}", r.strategy, r.reason);
                        }
                    }
                }
                print_transitions(&transitions);
            }
        }
        Command::Name {
            device,
            name,
            notes,
            clear,
        } => {
            let dev = store
                .get_device_by_ref(device)?
                .with_context(|| format!("no device matches '{device}'"))?;
            match name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
                Some(n) => {
                    store.set_user_name(&dev.key, n, notes.as_deref())?;
                    eprintln!("named device {} → \"{n}\"", short_key(&dev.key));
                }
                // Silently clearing on a missing argument made a typo
                // indistinguishable from an instruction.
                None if *clear => {
                    store.clear_user_name(&dev.key)?;
                    eprintln!("cleared name for device {}", short_key(&dev.key));
                }
                None => anyhow::bail!(
                    "no name given; pass a name, or --clear to remove the existing one"
                ),
            }
        }
        Command::Label { network, label } => {
            let net = store
                .get_network_by_ref(network)?
                .with_context(|| format!("no network matches '{network}'"))?;
            store.set_network_label(&net.key, label.trim())?;
            eprintln!(
                "labelled network {} → \"{}\"",
                short_key(&net.key),
                label.trim()
            );
        }
        Command::Config { key, value } => match (key, value) {
            (Some(k), Some(v)) => {
                anyhow::ensure!(
                    Store::WRITABLE_SETTINGS.contains(&k.as_str()),
                    "'{k}' is not a writable setting (try: {})",
                    Store::WRITABLE_SETTINGS.join(", ")
                );
                store.set_setting(k, v)?;
                eprintln!("{k} = {v}");
            }
            (Some(k), None) => match store.get_setting(k)? {
                Some(v) => println!("{v}"),
                None => anyhow::bail!("'{k}' is not set"),
            },
            (None, _) => {
                for k in Store::WRITABLE_SETTINGS {
                    println!("{k} = {}", store.get_setting(k)?.unwrap_or_default());
                }
            }
        },
        Command::Networks => {
            let networks = store.list_networks()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&networks)?);
            } else {
                print_networks(&networks);
            }
        }
        Command::History { device, limit } => {
            let dev = store
                .get_device_by_ref(device)?
                .with_context(|| format!("no device matches '{device}'"))?;
            let events = store.device_history(&dev.key, *limit)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                let user_name = store.get_user_name(&dev.key)?.map(|(n, _)| n);
                println!(
                    "history for {} ({}) — times in UTC",
                    device_display(
                        user_name.as_deref(),
                        dev.primary_name.as_deref(),
                        dev.mac.as_deref(),
                        None,
                        &dev.key
                    ),
                    short_key(&dev.key)
                );
                for e in events {
                    println!("  {}", format_event(&e));
                }
            }
        }
        Command::Export { network, format } => match format.as_str() {
            "csv" => {
                let devices = store.list_devices(network.as_deref())?;
                print!("{}", modern_ip_scanner_core::export::devices_csv(&devices));
            }
            "json" => {
                let devices = store.list_devices(network.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&devices)?);
            }
            other => anyhow::bail!("unknown export format '{other}' (csv|json)"),
        },
    }
    Ok(())
}

fn most_recent_network(store: &Store) -> Result<Option<String>> {
    Ok(store
        .list_networks()?
        .into_iter()
        .max_by_key(|n| n.last_seen)
        .map(|n| n.key))
}

fn print_report(report: &ScanReport) {
    let label = report.network_label.clone().unwrap_or_default();
    let title = if label.is_empty() {
        report.network_key.clone()
    } else {
        format!("{} ({})", report.network_key, label)
    };
    println!("Scan #{} on {title}", report.scan_id);
    println!(
        "  finished {} UTC · {} strategies · {} devices seen",
        fmt_time(report.finished_at),
        report.strategies_run.len(),
        report.devices_seen
    );
    if report.partial {
        println!("  ⚠ PARTIAL SCAN — \"gone\" transitions suppressed:");
        for r in &report.partial_reasons {
            println!("    · {}: {}", r.strategy, r.reason);
        }
    } else {
        println!("  ✓ complete scan");
    }
    print_transitions(&report.transitions);
}

fn print_transitions(transitions: &[modern_ip_scanner_core::model::Transition]) {
    if transitions.is_empty() {
        println!("  no changes since last scan");
        return;
    }
    for t in transitions {
        let mark = match t.kind {
            TransitionKind::New => "+",
            TransitionKind::Changed => "~",
            TransitionKind::Gone => "-",
            TransitionKind::Returned => "↩",
        };
        let details = if t.changes.is_empty() {
            String::new()
        } else {
            let parts: Vec<String> = t
                .changes
                .iter()
                .map(|c| {
                    format!(
                        "{}: {} → {}",
                        c.field,
                        c.from.as_deref().unwrap_or("∅"),
                        c.to.as_deref().unwrap_or("∅")
                    )
                })
                .collect();
            format!(" ({})", parts.join(", "))
        };
        let kind = if t.unstable_identity {
            format!("{} · randomised identity", t.kind.as_str())
        } else {
            t.kind.as_str().to_string()
        };
        println!("  {mark} {} [{kind}]{}", t.device_display, details);
    }
    if transitions.iter().any(|t| t.unstable_identity) {
        println!(
            "  note: devices marked \"randomised identity\" change their MAC by design.\n\
             \x20       mipscan cannot follow them across rotations, so it never reports\n\
             \x20       them gone. Give one a name to make it trackable."
        );
    }
}

fn print_devices(devices: &[DeviceView]) {
    if devices.is_empty() {
        println!("no devices recorded — run `mipscan scan` first");
        return;
    }
    println!(
        "{:<4} {:<8} {:<20} {:<15} {:<17} {:<14} {:<16} networks",
        "id", "status", "name", "ip", "mac", "vendor", "last seen (UTC)"
    );
    for d in devices {
        // A randomised identity is worth flagging here too: it explains why
        // such a device is never reported gone.
        let status = if d.identity_stable {
            d.status.as_str().to_string()
        } else {
            format!("{}*", d.status.as_str())
        };
        println!(
            "{:<4} {:<8} {:<20} {:<15} {:<17} {:<14} {:<16} {}",
            d.id,
            status,
            truncate(&d.display_name, 20),
            d.last_ip.as_deref().unwrap_or("-"),
            d.mac.as_deref().unwrap_or("-"),
            truncate(d.vendor.as_deref().unwrap_or("-"), 14),
            fmt_time(d.last_seen),
            d.networks.len()
        );
    }
    if devices.iter().any(|d| !d.identity_stable) {
        println!("  * randomised identity: cannot be followed across MAC rotations");
    }
}

fn print_networks(networks: &[NetworkView]) {
    if networks.is_empty() {
        println!("no networks remembered yet — run `mipscan scan` first");
        return;
    }
    println!(
        "{:<18} {:<12} {:<18} {:<16} devices",
        "key", "label", "subnet", "last seen (UTC)"
    );
    for n in networks {
        println!(
            "{:<18} {:<12} {:<18} {:<16} {}",
            short_key(&n.key),
            truncate(n.label.as_deref().unwrap_or("-"), 12),
            n.subnet.as_deref().unwrap_or("-"),
            fmt_time(n.last_seen),
            n.device_count
        );
    }
}

fn format_event(e: &modern_ip_scanner_core::model::HistoryEvent) -> String {
    match e {
        modern_ip_scanner_core::model::HistoryEvent::Observation {
            at,
            ip,
            mac,
            hostname,
            source,
            ..
        } => format!(
            "{} seen {} mac={} host={} via {}",
            fmt_time(*at),
            ip,
            mac.as_deref().unwrap_or("?"),
            hostname.as_deref().unwrap_or("?"),
            source
        ),
        modern_ip_scanner_core::model::HistoryEvent::Transition {
            at, kind, changes, ..
        } => {
            let extra: Vec<String> = changes
                .iter()
                .map(|c| {
                    format!(
                        "{}: {}→{}",
                        c.field,
                        c.from.as_deref().unwrap_or("?"),
                        c.to.as_deref().unwrap_or("?")
                    )
                })
                .collect();
            format!("{} {} {}", fmt_time(*at), kind.as_str(), extra.join(", "))
        }
        modern_ip_scanner_core::model::HistoryEvent::Named { at, name } => {
            format!("{} named \"{}\"", fmt_time(*at), name)
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
