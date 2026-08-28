import { useEffect, useState } from "react";
import { api } from "../api";
import type { AppStateInfo, Settings } from "../types";

const ALL_STRATEGIES = [
  { id: "arp-cache", label: "ARP/neighbor cache", note: "zero packets, always on" },
  { id: "ping-sweep", label: "Targeted ping sweep", note: "candidates only, no range loops" },
  { id: "mdns", label: "mDNS / Bonjour", note: "names for Apple/smart devices" },
  { id: "ssdp", label: "SSDP / UPnP", note: "names + vendor for media/IoT" },
  { id: "netbios", label: "NetBIOS names", note: "names for Windows/Samba" },
  { id: "arp-ping", label: "Full ARP (privileged)", note: "needs helper or SendARP" },
];

export default function SettingsPanel() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [grace, setGrace] = useState(2);
  const [retention, setRetention] = useState(90);
  const [enabled, setEnabled] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [state, setState] = useState<AppStateInfo | null>(null);

  useEffect(() => {
    api.getState().then(setState).catch(() => undefined);
    api.getSettings().then((s) => {
      setSettings(s);
      setGrace(s.grace_scans);
      setRetention(Number(s.retention_days) || 90);
      try {
        setEnabled(JSON.parse(s.enabled_strategies || "[]"));
      } catch {
        setEnabled(ALL_STRATEGIES.map((s2) => s2.id));
      }
    });
  }, []);

  const save = async () => {
    await api.setSetting("grace_scans", String(grace));
    await api.setSetting("enabled_strategies", JSON.stringify(enabled));
    await api.setSetting("observations_retention_days", String(retention));
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
          {ALL_STRATEGIES.map((s) => (
            <li key={s.id}>
              <label>
                <input
                  type="checkbox"
                  checked={enabled.includes(s.id)}
                  onChange={() => toggle(s.id)}
                />
                <span className="strategy-name">{s.label}</span>
                <span className="muted"> — {s.note}</span>
              </label>
            </li>
          ))}
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
              Or point <code>LANINV_HELPER</code> at it directly.
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
