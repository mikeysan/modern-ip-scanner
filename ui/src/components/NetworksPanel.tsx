import { useState } from "react";
import type { NetworkView } from "../types";
import { api, fmtTime } from "../api";

interface Props {
  networks: NetworkView[];
  current: string | null;
  onLabelChanged: () => void;
}

export default function NetworksPanel({ networks, current, onLabelChanged }: Props) {
  const [editing, setEditing] = useState<string | null>(null);
  const [label, setLabel] = useState("");

  const save = async (key: string) => {
    if (label.trim()) {
      await api.setNetworkLabel(key, label.trim()).catch(() => undefined);
    }
    setEditing(null);
    onLabelChanged();
  };

  if (networks.length === 0) {
    return (
      <div className="empty">
        <p>No networks remembered yet.</p>
        <p>Each place you scan gets its own row — home, office, the lab.</p>
      </div>
    );
  }

  return (
    <table className="devices">
      <thead>
        <tr>
          <th>Label</th>
          <th>Subnet</th>
          <th>Gateway MAC</th>
          <th>Devices</th>
          <th>First seen</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {networks.map((n) => (
          <tr key={n.key} className={n.key === current ? "selected" : ""}>
            <td>
              {editing === n.key ? (
                <span className="edit-row">
                  <input
                    autoFocus
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && save(n.key)}
                    placeholder="Home, Office…"
                  />
                  <button onClick={() => save(n.key)}>save</button>
                </span>
              ) : (
                <button
                  className="link"
                  onClick={() => {
                    setEditing(n.key);
                    setLabel(n.label ?? "");
                  }}
                >
                  {n.label ?? "unnamed — click to label"}
                </button>
              )}
            </td>
            <td className="mono">{n.subnet ?? "—"}</td>
            <td className="mono muted">{n.gateway_mac ?? "—"}</td>
            <td>{n.device_count}</td>
            <td className="muted">{fmtTime(n.first_seen)}</td>
            <td className="muted">{fmtTime(n.last_seen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
