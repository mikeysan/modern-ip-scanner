//! laninv-gui: Tauri 2 shell over laninv-core.
//!
//! Commands are thin wrappers; every integrity decision (partial scans,
//! suppressed `gone` transitions) lives in the core so CLI and GUI can never
//! disagree.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use laninv_core::model::{DeviceView, HistoryEvent, Interface, NetworkView};
use laninv_core::store::Store;
use laninv_core::util::fmt_time;

struct AppState {
    store: Arc<Mutex<Store>>,
    scanning: Arc<AtomicBool>,
}

type SharedState<'a> = tauri::State<'a, AppState>;

fn store_err<E: std::fmt::Display>(e: E) -> String {
    format!("database error: {e}")
}

#[tauri::command]
fn get_state(state: SharedState<'_>) -> Result<serde_json::Value, String> {
    let store = state.store.lock().unwrap();
    let networks = store.list_networks().map_err(store_err)?;
    let interfaces = laninv_core::netenv::interfaces();
    let iface = laninv_core::netenv::default_interface(&interfaces);
    // Probing without an interface skips the ARP check entirely on Windows,
    // so the UI would report a capability set the scanner does not use.
    let privilege = laninv_core::privilege::probe(iface.as_ref());
    Ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "networks": networks.len(),
        "devices": store.list_devices(None).map_err(store_err)?.len(),
        "capabilities": privilege.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "helper_available": laninv_core::privilege::helper_path().is_some(),
        "helper_search_paths": laninv_core::privilege::helper_search_paths()
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
    let store = state.store.lock().unwrap();
    store.list_devices(network.as_deref()).map_err(store_err)
}

#[tauri::command]
fn rename_device(
    state: SharedState,
    device: String,
    name: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    let store = state.store.lock().unwrap();
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
    let store = state.store.lock().unwrap();
    store.list_networks().map_err(store_err)
}

#[tauri::command]
fn set_network_label(state: SharedState, network: String, label: String) -> Result<(), String> {
    let store = state.store.lock().unwrap();
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
    let store = state.store.lock().unwrap();
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
    let store = state.store.lock().unwrap();
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

#[tauri::command]
fn get_settings(state: SharedState) -> Result<serde_json::Value, String> {
    let store = state.store.lock().unwrap();
    let get = |k: &str| store.get_setting(k).unwrap_or_default();
    Ok(serde_json::json!({
        "grace_scans": store.grace_scans(),
        "enabled_strategies": get("enabled_strategies"),
        "retention_days": get("observations_retention_days"),
    }))
}

#[tauri::command]
fn set_setting(state: SharedState, key: String, value: String) -> Result<(), String> {
    const ALLOWED: [&str; 3] = [
        "grace_scans",
        "enabled_strategies",
        "observations_retention_days",
    ];
    if !ALLOWED.contains(&key.as_str()) {
        return Err("setting not writable from the UI".into());
    }
    let store = state.store.lock().unwrap();
    store.set_setting(&key, &value).map_err(store_err)
}

#[tauri::command]
fn export_csv(state: SharedState, network: Option<String>) -> Result<String, String> {
    let store = state.store.lock().unwrap();
    let devices = store.list_devices(network.as_deref()).map_err(store_err)?;
    let mut out = String::from("key,name,ip,mac,vendor,first_seen,last_seen,networks\n");
    for d in &devices {
        out.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            d.key,
            d.display_name.replace('"', "'"),
            d.last_ip.as_deref().unwrap_or(""),
            d.mac.as_deref().unwrap_or(""),
            d.vendor.as_deref().unwrap_or("").replace('"', "'"),
            fmt_time(d.first_seen),
            fmt_time(d.last_seen),
            d.networks.join(" ")
        ));
    }
    Ok(out)
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
        let opts = laninv_core::ScanOptions {
            strategies,
            use_helper,
        };
        let mut progress = |msg: &str| {
            let _ = app.emit("scan:progress", msg);
        };
        let report = laninv_core::run_scan(&mut store.lock().unwrap(), &opts, &mut progress);
        match report {
            Ok(r) => {
                let _ = app.emit("scan:done", &r);
            }
            Err(e) => {
                let _ = app.emit("scan:error", e.to_string());
            }
        }
        scanning.store(false, Ordering::SeqCst);
    });
    Ok(())
}

#[tauri::command]
fn list_interfaces() -> Vec<Interface> {
    laninv_core::netenv::interfaces()
}

fn main() {
    let store = Store::open_default().expect("opening inventory database");
    tauri::Builder::default()
        .manage(AppState {
            store: Arc::new(Mutex::new(store)),
            scanning: Arc::new(AtomicBool::new(false)),
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running laninv GUI");
}
