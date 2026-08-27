import { useEffect, useState } from "react";
import { api } from "../api";
import type { Settings } from "../types";

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
  const [enabled, setEnabled] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getSettings().then((s) => {
      setSettings(s);
      setGrace(s.grace_scans);
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
          A scan is marked <em>partial</em> unless every enabled strategy could
          run. Partial scans never report devices as gone.
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
      <button className="scan-btn" onClick={save}>
        {saved ? "Saved ✓" : "Save settings"}
      </button>
    </div>
  );
}
