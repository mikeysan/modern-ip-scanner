// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

//! modern-ip-scanner-gui: Tauri 2 shell over modern-ip-scanner-core.
//!
//! Commands are thin wrappers; every integrity decision (partial scans,
//! suppressed `gone` transitions) lives in the core so CLI and GUI can never
//! disagree.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use modern_ip_scanner_core::model::{DeviceView, HistoryEvent, Interface, NetworkView};
use modern_ip_scanner_core::store::Store;

struct AppState {
    store: Arc<Mutex<Store>>,
    scanning: Arc<AtomicBool>,
    /// Set when the real database could not be opened and a throwaway one is
    /// standing in, so the UI can say so instead of silently losing writes.
    startup_error: Option<String>,
}

type SharedState<'a> = tauri::State<'a, AppState>;

fn store_err<E: std::fmt::Display>(e: E) -> String {
    format!("database error: {e}")
}

/// Take the store lock, recovering from poisoning.
///
/// A panic in one command used to poison the mutex and make every later
/// command panic too — one failure becoming a dead app. rusqlite rolls an
/// open transaction back as it unwinds, so the connection itself is still
/// sound and the next command can use it.
fn store_of(state: &AppState) -> std::sync::MutexGuard<'_, Store> {
    state.store.lock().unwrap_or_else(|e| e.into_inner())
}

/// Clears the scanning flag however the scan ends — return, error, or panic.
struct ScanGuard(Arc<AtomicBool>);

impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// What the UI needs before it can draw: whether writes are being kept, which
/// interface will be scanned, and whether the optional helper is installed.
///
/// Deliberately touches neither the store nor the privilege probe. It used to
/// do both -- a full device listing for a count nothing displayed, and a live
/// ICMP echo plus a live SendARP for a capability list nothing displayed -- and
/// taking the store lock here meant this call queued behind a running scan.
#[tauri::command]
fn get_state(state: SharedState<'_>) -> Result<serde_json::Value, String> {
    let interfaces = modern_ip_scanner_core::netenv::interfaces();
    let iface = modern_ip_scanner_core::netenv::default_interface(&interfaces);
    Ok(serde_json::json!({
        "startup_error": state.startup_error,
        "helper_available": modern_ip_scanner_core::privilege::helper_path().is_some(),
        "helper_search_paths": modern_ip_scanner_core::privilege::helper_search_paths()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "interface": iface.as_ref().map(|i| serde_json::json!({
            "name": i.name,
            "kind": i.kind.as_str(),
            "ips": i.ipv4.iter().map(|c| c.addr.clone()).collect::<Vec<String>>(),
        })),
    }))
}

#[tauri::command]
fn list_devices(state: SharedState, network: Option<String>) -> Result<Vec<DeviceView>, String> {
    let store = store_of(&state);
    store.list_devices(network.as_deref()).map_err(store_err)
}

#[tauri::command]
fn rename_device(
    state: SharedState,
    device: String,
    name: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    let store = store_of(&state);
    let dev = store
        .get_device_by_ref(&device)
        .map_err(store_err)?
        .ok_or_else(|| format!("no device matches '{device}'"))?;
    match name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => store
            .set_user_name(&dev.key, n, notes.as_deref())
            .map_err(store_err),
        None => store.clear_user_name(&dev.key).map_err(store_err),
    }
}

#[tauri::command]
fn list_networks(state: SharedState) -> Result<Vec<NetworkView>, String> {
    let store = store_of(&state);
    store.list_networks().map_err(store_err)
}

#[tauri::command]
fn set_network_label(state: SharedState, network: String, label: String) -> Result<(), String> {
    let store = store_of(&state);
    if !store
        .set_network_label(&network, &label)
        .map_err(store_err)?
    {
        return Err("unknown network".into());
    }
    Ok(())
}

#[tauri::command]
fn device_history(
    state: SharedState,
    device: String,
    limit: Option<i64>,
) -> Result<Vec<HistoryEvent>, String> {
    let store = store_of(&state);
    let dev = store
        .get_device_by_ref(&device)
        .map_err(store_err)?
        .ok_or_else(|| format!("no device matches '{device}'"))?;
    store
        .device_history(&dev.key, limit.unwrap_or(40))
        .map_err(store_err)
}

/// Summary of the most recent scan (for the diff banner at startup).
#[tauri::command]
fn last_diff(
    state: SharedState,
    network: Option<String>,
) -> Result<Option<serde_json::Value>, String> {
    let store = store_of(&state);
    let networks = store.list_networks().map_err(store_err)?;
    let target = match network {
        Some(n) => n,
        None => match networks.first() {
            Some(n) => n.key.clone(),
            None => return Ok(None),
        },
    };
    let Some((scan_id, _)) = store.last_scan_for_network(&target).map_err(store_err)? else {
        return Ok(None);
    };
    let Some(summary) = store.scan_summary(scan_id).map_err(store_err)? else {
        return Ok(None);
    };
    let transitions = store.transitions_of_scan(scan_id).map_err(store_err)?;
    Ok(Some(serde_json::json!({
        "scan_id": scan_id,
        "network": target,
        "finished_at": summary.finished_at,
        "partial": summary.partial,
        "partial_reasons": summary.partial_reasons,
        "strategies": summary.strategies,
        "transitions": transitions,
    })))
}

/// The GPL's "Appropriate Legal Notices" for the GUI. An interactive program
/// is meant to show the user the terms it comes under and where its source is,
/// which the About section in Settings does with this. Static values, so no
/// store access is needed.
#[tauri::command]
fn about() -> serde_json::Value {
    serde_json::json!({
        "name": "Modern IP Scanner",
        "version": env!("CARGO_PKG_VERSION"),
        "copyright": "Copyright (C) 2026 mikey-san",
        "license": "AGPL-3.0-or-later",
        "license_name": "GNU Affero General Public License v3 or later",
        "license_url": "https://www.gnu.org/licenses/agpl-3.0.html",
        "source_url": "https://github.com/mikeysan/modern-ip-scanner",
    })
}

#[tauri::command]
fn get_settings(state: SharedState) -> Result<serde_json::Value, String> {
    let store = store_of(&state);
    let get = |k: &str| -> Result<String, String> {
        Ok(store.get_setting(k).map_err(store_err)?.unwrap_or_default())
    };
    Ok(serde_json::json!({
        "grace_scans": store.grace_scans().map_err(store_err)?,
        "enabled_strategies": get("enabled_strategies")?,
        "retention_days": get("observations_retention_days")?,
    }))
}

#[tauri::command]
fn set_setting(state: SharedState, key: String, value: String) -> Result<(), String> {
    if !Store::WRITABLE_SETTINGS.contains(&key.as_str()) {
        return Err("setting not writable from the UI".into());
    }
    let store = store_of(&state);
    store.set_setting(&key, &value).map_err(store_err)
}

#[tauri::command]
fn export_csv(state: SharedState, network: Option<String>) -> Result<String, String> {
    let store = store_of(&state);
    let devices = store.list_devices(network.as_deref()).map_err(store_err)?;
    Ok(modern_ip_scanner_core::export::devices_csv(&devices))
}

/// Kick off a scan in the background; progress arrives as events.
/// The store mutex is held for the duration of the scan (typically seconds),
/// so rename/history commands queue behind it — acceptable for v1.
#[tauri::command]
fn start_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    use_helper: bool,
    strategies: Option<Vec<String>>,
) -> Result<(), String> {
    if state.scanning.swap(true, Ordering::SeqCst) {
        return Err("a scan is already running".into());
    }
    let store = Arc::clone(&state.store);
    let scanning = Arc::clone(&state.scanning);
    std::thread::spawn(move || {
        use tauri::Emitter;
        // Released on every path out of this thread, including a panic.
        // Setting the flag after the scan instead left the UI stuck on
        // "Scanning…" forever, with no way back but a restart.
        let _guard = ScanGuard(scanning);
        let opts = modern_ip_scanner_core::ScanOptions {
            strategies,
            use_helper,
        };
        let mut progress = |msg: &str| {
            let _ = app.emit("scan:progress", msg);
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = store.lock().unwrap_or_else(|e| e.into_inner());
            modern_ip_scanner_core::run_scan(&mut guard, &opts, &mut progress)
        }));
        match outcome {
            Ok(Ok(r)) => {
                let _ = app.emit("scan:done", &r);
            }
            Ok(Err(e)) => {
                let _ = app.emit("scan:error", e.to_string());
            }
            Err(_) => {
                // The frontend must hear something, or it waits forever.
                let _ = app.emit(
                    "scan:error",
                    "the scan crashed; the inventory is unchanged".to_string(),
                );
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn list_interfaces() -> Vec<Interface> {
    modern_ip_scanner_core::netenv::interfaces()
}

/// The strategy ids the core actually registers, so the Settings panel cannot
/// offer one that does not exist or hide one that does.
#[tauri::command]
fn list_strategies() -> Vec<&'static str> {
    modern_ip_scanner_core::discovery::strategy_ids()
}

/// Open the inventory, or fall back to a throwaway database so the app can
/// start and *say* what went wrong. Crashing at launch with no window told the
/// user nothing — release builds have no console to print to.
fn open_store() -> (Store, Option<String>) {
    match Store::open_default() {
        Ok(store) => (store, None),
        Err(e) => {
            let fallback = std::env::temp_dir().join("modern-ip-scanner-fallback.sqlite3");
            match Store::open(&fallback) {
                Ok(store) => (
                    store,
                    Some(format!(
                        "Could not open the inventory database ({e}). Running on a \
                         temporary one at {} — nothing you do here will be kept.",
                        fallback.display()
                    )),
                ),
                Err(e2) => {
                    eprintln!("modern-ip-scanner: cannot open any database: {e} / {e2}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn main() {
    let (store, startup_error) = open_store();
    tauri::Builder::default()
        .manage(AppState {
            store: Arc::new(Mutex::new(store)),
            scanning: Arc::new(AtomicBool::new(false)),
            startup_error,
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            list_devices,
            rename_device,
            list_networks,
            set_network_label,
            device_history,
            last_diff,
            get_settings,
            set_setting,
            export_csv,
            start_scan,
            list_interfaces,
            list_strategies,
            about,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Modern IP Scanner GUI");
}
