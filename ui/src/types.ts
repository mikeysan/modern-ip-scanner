// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

export type DeviceStatus = "new" | "changed" | "gone" | "known";

export interface DeviceView {
  id: number;
  key: string;
  user_name: string | null;
  primary_name: string | null;
  display_name: string;
  mac: string | null;
  vendor: string | null;
  first_seen: number;
  last_seen: number;
  last_ip: string | null;
  networks: string[];
  notes: string | null;
  /** Standing as of the network's most recent scan. */
  status: DeviceStatus;
  /** False when the device cannot be re-identified across scans. */
  identity_stable: boolean;
}

export interface NetworkView {
  key: string;
  label: string | null;
  subnet: string | null;
  gateway_mac: string | null;
  first_seen: number;
  last_seen: number;
  device_count: number;
}

export type TransitionKind = "new" | "changed" | "gone" | "returned";

export interface FieldChange {
  field: string;
  from: string | null;
  to: string | null;
}

export interface Transition {
  kind: TransitionKind;
  device_key: string;
  device_display: string;
  changes: FieldChange[];
  /** Device changes its MAC by design; it cannot be followed across rotations. */
  unstable_identity?: boolean;
}

export interface PartialReason {
  strategy: string;
  reason: string;
}

export interface ScanReport {
  scan_id: number;
  network_key: string;
  network_label: string | null;
  started_at: number;
  finished_at: number;
  partial: boolean;
  partial_reasons: PartialReason[];
  strategies_run: string[];
  devices_seen: number;
  transitions: Transition[];
  interface: InterfaceInfo | null;
}

export interface InterfaceInfo {
  name: string;
  description: string | null;
  mac: string | null;
  kind: string;
  ipv4: { addr: string; prefix: number }[];
  ipv6: string[];
  gateway_v4: string | null;
}

export interface AppStateInfo {
  /** Set when the inventory database could not be opened and writes are not kept. */
  startup_error: string | null;
  helper_available: boolean;
  helper_search_paths: string[];
  interface: { name: string; kind: string; ips: string[] } | null;
}

export interface LastDiff {
  scan_id: number;
  network: string;
  finished_at: number;
  partial: boolean;
  partial_reasons: PartialReason[];
  strategies: string[];
  transitions: Transition[];
}

export type HistoryEvent =
  | {
      type: "observation";
      at: number;
      network_key: string;
      ip: string;
      mac: string | null;
      hostname: string | null;
      source: string;
    }
  | { type: "transition"; at: number; network_key: string; kind: TransitionKind; changes: FieldChange[] }
  | { type: "named"; at: number; name: string };

export interface Settings {
  grace_scans: number;
  enabled_strategies: string;
  retention_days: string;
}

/** Licence and provenance shown in Settings > About. Sourced from the backend
 *  so the version cannot drift from the binary the user is actually running. */
export interface About {
  name: string;
  version: string;
  copyright: string;
  license: string;
  license_name: string;
  license_url: string;
  source_url: string;
}
