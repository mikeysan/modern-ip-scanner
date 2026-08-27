//! `laninv` — headless LAN inventory CLI sharing the core with the GUI.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use laninv_core::model::{DeviceView, NetworkView, ScanReport, TransitionKind};
use laninv_core::store::Store;
use laninv_core::util::fmt_time;

#[derive(Parser)]
#[command(
    name = "laninv",
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
        /// Network key (see `laninv networks`). Omit for all networks.
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
        /// Device id or key (see `laninv devices`).
        device: String,
        /// The name to assign; omit to clear.
        name: Option<String>,
        #[arg(short = 'n', long)]
        notes: Option<String>,
    },
    /// List remembered networks.
    Networks,
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
            let opts = laninv_core::ScanOptions {
                strategies: if strategies.is_empty() {
                    None
                } else {
                    Some(strategies.clone())
                },
                use_helper: *helper,
            };
            let mut progress = |msg: &str| eprintln!("  {msg}");
            let report =
                laninv_core::run_scan(&mut store, &opts, &mut progress).context("scan failed")?;
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
                None => most_recent_network(&store)
                    .context("no scans recorded yet — run `laninv scan` first")?,
            };
            let (scan_id, at) = store
                .last_scan_for_network(&nk)?
                .context("no scan recorded for that network")?;
            let transitions = store.transitions_of_scan(scan_id)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "network": nk,
                        "scan_id": scan_id,
                        "finished_at": at,
                        "transitions": transitions,
                    })
                );
            } else {
                println!(
                    "Diff for network {nk} (scan #{scan_id} at {})",
                    fmt_time(at)
                );
                print_transitions(&transitions);
            }
        }
        Command::Name {
            device,
            name,
            notes,
        } => {
            let dev = store
                .get_device_by_ref(device)?
                .with_context(|| format!("no device matches '{device}'"))?;
            match name {
                Some(n) if !n.trim().is_empty() => {
                    store.set_user_name(&dev.key, n.trim(), notes.as_deref())?;
                    eprintln!("named device {} → \"{}\"", short_key(&dev.key), n.trim());
                }
                _ => {
                    store.clear_user_name(&dev.key)?;
                    eprintln!("cleared name for device {}", short_key(&dev.key));
                }
            }
        }
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
                println!(
                    "history for {} ({})",
                    dev_display(&store, &dev.key),
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
                println!("key,name,ip,mac,vendor,first_seen,last_seen,networks");
                for d in &devices {
                    println!(
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                        d.key,
                        d.display_name.replace('"', "'"),
                        d.last_ip.as_deref().unwrap_or(""),
                        d.mac.as_deref().unwrap_or(""),
                        d.vendor.as_deref().unwrap_or("").replace('"', "'"),
                        fmt_time(d.first_seen),
                        fmt_time(d.last_seen),
                        d.networks.join(" ")
                    );
                }
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

fn most_recent_network(store: &Store) -> Option<String> {
    store
        .list_networks()
        .ok()?
        .into_iter()
        .max_by_key(|n| n.last_seen)
        .map(|n| n.key)
}

fn short_key(key: &str) -> &str {
    &key[..8.min(key.len())]
}

fn dev_display(store: &Store, key: &str) -> String {
    store
        .get_user_name(key)
        .ok()
        .flatten()
        .map(|(n, _)| n)
        .or_else(|| {
            store
                .get_device(key)
                .ok()
                .flatten()
                .and_then(|d| d.primary_name.or(d.mac).or(Some(d.key)))
        })
        .unwrap_or_else(|| key.into())
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
        "  finished {} · {} strategies · {} devices seen",
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

fn print_transitions(transitions: &[laninv_core::model::Transition]) {
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
             \x20       laninv cannot follow them across rotations, so it never reports\n\
             \x20       them gone. Give one a name to make it trackable."
        );
    }
}

fn print_devices(devices: &[DeviceView]) {
    if devices.is_empty() {
        println!("no devices recorded — run `laninv scan` first");
        return;
    }
    println!(
        "{:<4} {:<20} {:<15} {:<17} {:<16} {:<16} networks",
        "id", "name", "ip", "mac", "vendor", "last seen"
    );
    for d in devices {
        println!(
            "{:<4} {:<20} {:<15} {:<17} {:<16} {:<16} {}",
            d.id,
            truncate(&d.display_name, 20),
            d.last_ip.as_deref().unwrap_or("-"),
            d.mac.as_deref().unwrap_or("-"),
            truncate(d.vendor.as_deref().unwrap_or("-"), 16),
            fmt_time(d.last_seen),
            d.networks.len()
        );
    }
}

fn print_networks(networks: &[NetworkView]) {
    if networks.is_empty() {
        println!("no networks remembered yet — run `laninv scan` first");
        return;
    }
    println!(
        "{:<18} {:<12} {:<18} {:<16} devices",
        "key", "label", "subnet", "last seen"
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

fn format_event(e: &laninv_core::model::HistoryEvent) -> String {
    match e {
        laninv_core::model::HistoryEvent::Observation {
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
        laninv_core::model::HistoryEvent::Transition {
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
        laninv_core::model::HistoryEvent::Named { at, name } => {
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
