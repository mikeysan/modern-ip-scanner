import type { DeviceView } from "../types";
import { fmtTime } from "../api";

interface Props {
  devices: DeviceView[];
  networkKey: string | null;
  selected: string | null;
  onSelect: (key: string) => void;
}

export default function DevicesTable({ devices, selected, onSelect }: Props) {
  if (devices.length === 0) {
    return (
      <div className="empty">
        <p>No devices recorded yet.</p>
        <p>Press “Scan now” — the first scan builds your inventory.</p>
      </div>
    );
  }
  return (
    <table className="devices">
      <thead>
        <tr>
          <th>Name</th>
          <th>IP</th>
          <th>MAC</th>
          <th>Vendor</th>
          <th>Hostname</th>
          <th>First seen</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr
            key={d.key}
            className={d.key === selected ? "selected" : ""}
            onClick={() => onSelect(d.key)}
          >
            <td className="name">
              {d.display_name}
              {d.user_name && d.primary_name && (
                <span className="muted"> · {d.primary_name}</span>
              )}
            </td>
            <td className="mono">{d.last_ip ?? "—"}</td>
            <td className="mono">{d.mac ?? "—"}</td>
            <td className="muted">{d.vendor ?? "—"}</td>
            <td className="muted">{d.primary_name ?? "—"}</td>
            <td className="muted">{fmtTime(d.first_seen)}</td>
            <td className="muted">{fmtTime(d.last_seen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
