// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

import { useEffect, useState } from "react";
import { api } from "../api";
import type { About, AppStateInfo, Settings } from "../types";

/** Human wording for the ids the core registers. An id with no entry here
 *  still appears, labelled with the id itself — the list of strategies is the
 *  backend's to decide, not this file's. */
const STRATEGY_LABELS: Record<string, { label: string; note: string }> = {
  "arp-cache": { label: "ARP/neighbor cache", note: "zero packets, always on" },
  "ping-sweep": { label: "Targeted ping sweep", note: "candidates only, no range loops" },
  mdns: { label: "mDNS / Bonjour", note: "names for Apple/smart devices" },
  ssdp: { label: "SSDP / UPnP", note: "names + vendor for media/IoT" },
  netbios: { label: "NetBIOS names", note: "names for Windows/Samba" },
  "arp-ping": { label: "Full ARP (privileged)", note: "needs helper or SendARP" },
};

/** Fallback when the stored `enabled_strategies` is unreadable. */
const DEFAULT_ENABLED = Object.keys(STRATEGY_LABELS);

interface Props {
  onError: (message: string) => void;
}

export default function SettingsPanel({ onError }: Props) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [grace, setGrace] = useState(2);
  const [retention, setRetention] = useState(90);
  const [enabled, setEnabled] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [state, setState] = useState<AppStateInfo | null>(null);
  const [strategies, setStrategies] = useState<string[]>(DEFAULT_ENABLED);
  const [about, setAbout] = useState<About | null>(null);

  useEffect(() => {
    api.getState().then(setState).catch((e) => onError(String(e)));
    api.listStrategies().then(setStrategies).catch((e) => onError(String(e)));
    api.about().then(setAbout).catch((e) => onError(String(e)));
    api.getSettings().then((s) => {
      setSettings(s);
      setGrace(s.grace_scans);
      setRetention(Number(s.retention_days) || 90);
      try {
        setEnabled(JSON.parse(s.enabled_strategies || "[]"));
      } catch {
        setEnabled(DEFAULT_ENABLED);
      }
    });
    // `onError` is App's setError, which React guarantees is stable, so
    // listing it here does not re-fire this effect.
  }, [onError]);

  const save = async () => {
    try {
      await api.setSetting("grace_scans", String(grace));
      await api.setSetting("enabled_strategies", JSON.stringify(enabled));
      await api.setSetting("observations_retention_days", String(retention));
    } catch (e) {
      onError(String(e));
      return;
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  };

  if (!settings) return <div className="empty">loading…</div>;

  const toggle = (id: string) =>
    setEnabled((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    );

  return (
    <div className="settings">
      <section>
        <h3>Discovery strategies</h3>
        <ul className="strategy-list">
          {strategies.map((id) => {
            const meta = STRATEGY_LABELS[id] ?? { label: id, note: "" };
            return (
              <li key={id}>
                <label>
                  <input
                    type="checkbox"
                    checked={enabled.includes(id)}
                    onChange={() => toggle(id)}
                  />
                  <span className="strategy-name">{meta.label}</span>
                  {meta.note && <span className="muted"> — {meta.note}</span>}
                </label>
              </li>
            );
          })}
        </ul>
        <p className="muted small">
          A scan is marked <em>partial</em> unless every enabled strategy ran
          cleanly <em>and</em> the scan covered the network — that needs a
          full-coverage strategy (Full ARP) and a reply from the gateway.
          Partial scans still report new and changed devices, but never gone.
        </p>
      </section>
      <section>
        <h3>Gone grace period</h3>
        <label className="grace">
          A device is only reported <em>gone</em> after it misses
          <input
            type="number"
            min={1}
            max={10}
            value={grace}
            onChange={(e) => setGrace(Number(e.target.value) || 2)}
          />
          consecutive complete scans.
        </label>
      </section>
      <section>
        <h3>History retention</h3>
        <label className="grace">
          Keep raw observations for
          <input
            type="number"
            min={1}
            max={3650}
            value={retention}
            onChange={(e) => setRetention(Number(e.target.value) || 90)}
          />
          days. Device history and transitions are kept regardless; this only
          prunes the per-strategy sightings behind them.
        </label>
      </section>
      <section>
        <h3>Privileged helper</h3>
        {state?.helper_available ? (
          <p className="muted small">
            Installed. Tick <em>helper</em> before scanning for full ARP
            coverage; Modern IP Scanner never requires it.
          </p>
        ) : (
          <>
            <p className="muted small">
              Not installed. Full ARP coverage needs elevation on Linux, and
              without it no scan can report a device <em>gone</em>. On Windows
              native SendARP usually works and the helper is not needed.
            </p>
            <p className="muted small">
              Build it with <code>cargo build -p modern-ip-scanner-helper</code> and put
              the binary in one of:
            </p>
            <ul className="paths">
              {(state?.helper_search_paths ?? []).map((p) => (
                <li key={p}>
                  <code>{p}</code>
                </li>
              ))}
            </ul>
            <p className="muted small">
              Or point <code>MIPSCAN_HELPER</code> at it directly.
            </p>
          </>
        )}
      </section>
      <section>
        <h3>About</h3>
        {about && (
          <>
            <p className="muted small">
              {about.name} {about.version} — {about.copyright}
            </p>
            <p className="muted small">
              Licensed under the {about.license_name} (
              <code>{about.license}</code>). This is free software and comes
              with NO WARRANTY. You may study it, change it and pass it on,
              provided derived work carries the same licence — which under
              section 13 covers running a modified version as a network
              service, not only shipping a binary.
            </p>
            <p className="muted small">
              Licence text: <code>{about.license_url}</code>
            </p>
            <p className="muted small">
              Source: <code>{about.source_url}</code>
            </p>
          </>
        )}
      </section>
      <button className="scan-btn" onClick={save}>
        {saved ? "Saved ✓" : "Save settings"}
      </button>
    </div>
  );
}
