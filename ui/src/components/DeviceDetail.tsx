import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import type { DeviceView, HistoryEvent } from "../types";

interface Props {
  device: DeviceView | null;
  deviceKey: string;
  onRenamed: () => void;
  onError: (message: string) => void;
  onClose: () => void;
}

export default function DeviceDetail({
  device,
  deviceKey,
  onRenamed,
  onError,
  onClose,
}: Props) {
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const [history, setHistory] = useState<HistoryEvent[]>([]);
  const [saving, setSaving] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  useEffect(() => {
    setName(device?.user_name ?? "");
    setNotes(device?.notes ?? "");
    // An empty list and a failed load are different things: "no history yet"
    // is what a brand-new device looks like.
    setHistoryError(null);
    api
      .deviceHistory(deviceKey, 40)
      .then(setHistory)
      .catch((e) => {
        setHistory([]);
        setHistoryError(String(e));
      });
  }, [device, deviceKey]);

  const save = async () => {
    setSaving(true);
    try {
      await api.renameDevice(deviceKey, name || null, notes || null);
      onRenamed();
    } catch (e) {
      onError(String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <aside className="detail">
      <div className="detail-head">
        <h2>{device?.display_name ?? deviceKey.slice(0, 12)}</h2>
        <button className="link" onClick={onClose}>
          close
        </button>
      </div>
      <dl className="kv">
        <dt>Key</dt>
        <dd className="mono">{deviceKey}</dd>
        <dt>MAC</dt>
        <dd className="mono">{device?.mac ?? "—"}</dd>
        <dt>Last IP</dt>
        <dd className="mono">{device?.last_ip ?? "—"}</dd>
        <dt>Hostname</dt>
        <dd>{device?.primary_name ?? "—"}</dd>
        <dt>Vendor</dt>
        <dd>{device?.vendor ?? "—"}</dd>
        <dt>Networks</dt>
        <dd>{device?.networks.length ?? 0}</dd>
        <dt>First seen</dt>
        <dd>{device ? fmtTime(device.first_seen) : "—"}</dd>
      </dl>
      <div className="rename">
        <label>
          Your name for this device
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Living Room Printer"
          />
        </label>
        <label>
          Notes
          <input
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="optional"
          />
        </label>
        <button onClick={save} disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
      <h3>History</h3>
      <ul className="history">
        {history.map((e, i) => (
          <li key={i} className={e.type}>
            <span className="when">{fmtTime(e.at)}</span>{" "}
            {e.type === "observation" &&
              `seen ${e.ip}${e.mac ? ` (${e.mac})` : ""}${e.hostname ? ` as ${e.hostname}` : ""} via ${e.source}`}
            {e.type === "transition" &&
              `${e.kind}${e.changes.length ? ": " + e.changes.map((c) => `${c.field} ${c.from ?? "?"}→${c.to ?? "?"}`).join(", ") : ""}`}
            {e.type === "named" && `named “${e.name}”`}
          </li>
        ))}
        {history.length === 0 &&
          (historyError ? (
            <li className="muted">history unavailable — {historyError}</li>
          ) : (
            <li className="muted">no history yet</li>
          ))}
      </ul>
    </aside>
  );
}
