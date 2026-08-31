import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AppStateInfo,
  DeviceView,
  HistoryEvent,
  InterfaceInfo,
  LastDiff,
  NetworkView,
  ScanReport,
  Settings,
} from "./types";

export const api = {
  getState: () => invoke<AppStateInfo>("get_state"),
  listDevices: (network: string | null) =>
    invoke<DeviceView[]>("list_devices", { network }),
  renameDevice: (device: string, name: string | null, notes: string | null) =>
    invoke<void>("rename_device", { device, name, notes }),
  listNetworks: () => invoke<NetworkView[]>("list_networks"),
  setNetworkLabel: (network: string, label: string) =>
    invoke<void>("set_network_label", { network, label }),
  deviceHistory: (device: string, limit?: number) =>
    invoke<HistoryEvent[]>("device_history", { device, limit }),
  lastDiff: (network: string | null) =>
    invoke<LastDiff | null>("last_diff", { network }),
  getSettings: () => invoke<Settings>("get_settings"),
  setSetting: (key: string, value: string) =>
    invoke<void>("set_setting", { key, value }),
  exportCsv: (network: string | null) => invoke<string>("export_csv", { network }),
  startScan: (useHelper: boolean, strategies: string[] | null) =>
    invoke<void>("start_scan", { useHelper, strategies }),
  listInterfaces: () => invoke<InterfaceInfo[]>("list_interfaces"),
  listStrategies: () => invoke<string[]>("list_strategies"),
};

export function onScanProgress(cb: (msg: string) => void) {
  return listen<string>("scan:progress", (e) => cb(e.payload));
}

export function onScanDone(cb: (report: ScanReport) => void) {
  return listen<ScanReport>("scan:done", (e) => cb(e.payload));
}

export function onScanError(cb: (msg: string) => void) {
  return listen<string>("scan:error", (e) => cb(e.payload));
}

export function fmtTime(ts: number): string {
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}`;
}
