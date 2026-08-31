import { useMemo, useState } from "react";
import type { DeviceStatus, DeviceView } from "../types";
import { fmtTime } from "../api";

interface Props {
  devices: DeviceView[];
  selected: string | null;
  onSelect: (key: string) => void;
}

type SortKey = "name" | "ip" | "mac" | "vendor" | "first_seen" | "last_seen";

const STATUS_TITLE: Record<DeviceStatus, string> = {
  new: "First seen in the latest scan",
  changed: "Seen in the latest scan with a field that differs from before",
  gone: "Absent long enough to have been reported gone",
  known: "Present and unchanged",
};

/** Sort IPs numerically; "10.0.0.9" belongs before "10.0.0.10". */
function ipOrder(ip: string | null): number {
  if (!ip) return -1;
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return -1;
  return (
    ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
  );
}

export default function DevicesTable({ devices, selected, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({
    key: "last_seen",
    asc: false,
  });

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = (d: DeviceView) =>
      !q ||
      [
        d.display_name,
        d.primary_name,
        d.last_ip,
        d.mac,
        d.vendor,
        d.notes,
      ].some((f) => f?.toLowerCase().includes(q));

    const value = (d: DeviceView) => {
      switch (sort.key) {
        case "name":
          return d.display_name.toLowerCase();
        case "ip":
          return ipOrder(d.last_ip);
        case "mac":
          return d.mac ?? "";
        case "vendor":
          return d.vendor ?? "";
        case "first_seen":
          return d.first_seen;
        default:
          return d.last_seen;
      }
    };

    return devices.filter(matches).sort((a, b) => {
      const [x, y] = [value(a), value(b)];
      const cmp = x < y ? -1 : x > y ? 1 : 0;
      return sort.asc ? cmp : -cmp;
    });
  }, [devices, query, sort]);

  if (devices.length === 0) {
    return (
      <div className="empty">
        <p>No devices recorded yet.</p>
        <p>Press “Scan now” — the first scan builds your inventory.</p>
      </div>
    );
  }

  const header = (key: SortKey, label: string) => (
    <th
      className={sort.key === key ? "sortable active" : "sortable"}
      onClick={() =>
        setSort((s) => ({ key, asc: s.key === key ? !s.asc : key === "name" }))
      }
      title={`Sort by ${label.toLowerCase()}`}
    >
      {label}
      {sort.key === key && (
        <span className="sort-arrow">{sort.asc ? "▲" : "▼"}</span>
      )}
    </th>
  );

  return (
    <div className="devices-pane">
      <div className="table-toolbar">
        <input
          className="filter"
          type="search"
          placeholder="Filter by name, IP, MAC, vendor…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <span className="muted small">
          {shown.length === devices.length
            ? `${devices.length} devices`
            : `${shown.length} of ${devices.length} devices`}
        </span>
      </div>
      <div className="table-scroll">
        <table className="devices">
          <thead>
            <tr>
              <th>Status</th>
              {header("name", "Name")}
              {header("ip", "IP")}
              {header("mac", "MAC")}
              {header("vendor", "Vendor")}
              <th>Hostname</th>
              {header("first_seen", "First seen")}
              {header("last_seen", "Last seen")}
            </tr>
          </thead>
          <tbody>
            {shown.map((d) => (
              <tr
                key={d.key}
                className={d.key === selected ? "selected" : ""}
                onClick={() => onSelect(d.key)}
              >
                <td>
                  <span
                    className={`chip status-${d.status}`}
                    title={STATUS_TITLE[d.status]}
                  >
                    {d.status}
                  </span>
                  {!d.identity_stable && (
                    <span
                      className="chip randomised"
                      title="This device changes its MAC by design. It cannot be followed across rotations, so it is never reported gone."
                    >
                      randomised
                    </span>
                  )}
                </td>
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
      </div>
      {shown.length === 0 && (
        <div className="empty">
          <p>No device matches “{query}”.</p>
        </div>
      )}
    </div>
  );
}
