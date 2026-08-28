import { useCallback, useEffect, useState } from "react";
import { api, onScanDone, onScanError, onScanProgress } from "./api";
import type { DeviceView, LastDiff, NetworkView, ScanReport } from "./types";
import DevicesTable from "./components/DevicesTable";
import DeviceDetail from "./components/DeviceDetail";
import DiffBanner from "./components/DiffBanner";
import NetworksPanel from "./components/NetworksPanel";
import SettingsPanel from "./components/SettingsPanel";

type Tab = "devices" | "networks" | "settings";

export default function App() {
  const [tab, setTab] = useState<Tab>("devices");
  const [devices, setDevices] = useState<DeviceView[]>([]);
  const [networks, setNetworks] = useState<NetworkView[]>([]);
  const [network, setNetwork] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [lastDiff, setLastDiff] = useState<LastDiff | null>(null);
  const [scanning, setScanning] = useState(false);
  const [progressMsg, setProgressMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [useHelper, setUseHelper] = useState(false);
  const [helperAvailable, setHelperAvailable] = useState(false);
  const [ifaceLabel, setIfaceLabel] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [devs, nets] = await Promise.all([
        api.listDevices(network),
        api.listNetworks(),
      ]);
      setDevices(devs);
      setNetworks(nets);
      const diff = await api.lastDiff(network);
      setLastDiff(diff);
    } catch (e) {
      setError(String(e));
    }
  }, [network]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    api
      .getState()
      .then((s) => {
        setHelperAvailable(s.helper_available);
        if (s.startup_error) {
          setError(s.startup_error);
        }
        if (s.interface) {
          setIfaceLabel(`${s.interface.name} (${s.interface.kind})`);
        }
      })
      .catch(() => undefined);
    const offProgress = onScanProgress((msg) => setProgressMsg(msg));
    const offDone = onScanDone((report: ScanReport) => {
      setScanning(false);
      setProgressMsg(null);
      refresh();
      // Surface the fresh scan as the diff banner.
      setLastDiff({
        scan_id: report.scan_id,
        network: report.network_key,
        finished_at: report.finished_at,
        partial: report.partial,
        partial_reasons: report.partial_reasons,
        strategies: report.strategies_run,
        transitions: report.transitions,
      });
    });
    const offError = onScanError((msg) => {
      setScanning(false);
      setProgressMsg(null);
      setError(msg);
    });
    return () => {
      offProgress.then((f) => f());
      offDone.then((f) => f());
      offError.then((f) => f());
    };
  }, [refresh]);

  const startScan = async () => {
    setError(null);
    setScanning(true);
    setProgressMsg("starting…");
    try {
      await api.startScan(useHelper, null);
    } catch (e) {
      setScanning(false);
      setProgressMsg(null);
      setError(String(e));
    }
  };

  const currentNetwork = networks.find((n) => n.key === network) ?? null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">⌗</span>
          <h1>LAN Inventory</h1>
          {ifaceLabel && <span className="iface">{ifaceLabel}</span>}
        </div>
        <nav className="tabs">
          {(["devices", "networks", "settings"] as Tab[]).map((t) => (
            <button
              key={t}
              className={tab === t ? "tab active" : "tab"}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ))}
        </nav>
        <div className="scan-controls">
          <select
            className="network-select"
            value={network ?? ""}
            onChange={(e) => {
              setNetwork(e.target.value || null);
              setSelected(null);
            }}
          >
            <option value="">All networks</option>
            {networks.map((n) => (
              <option key={n.key} value={n.key}>
                {n.label ?? n.subnet ?? n.key.slice(0, 8)}
              </option>
            ))}
          </select>
          {helperAvailable && (
            <label className="helper-toggle" title="Full ARP coverage via the privileged helper (asks for elevation)">
              <input
                type="checkbox"
                checked={useHelper}
                onChange={(e) => setUseHelper(e.target.checked)}
              />
              helper
            </label>
          )}
          <button className="scan-btn" disabled={scanning} onClick={startScan}>
            {scanning ? "Scanning…" : "Scan now"}
          </button>
        </div>
      </header>

      {(error || progressMsg) && (
        <div className="statusline">
          {error ? <span className="error">{error}</span> : <span>{progressMsg}</span>}
          {error && (
            <button className="link" onClick={() => setError(null)}>
              dismiss
            </button>
          )}
        </div>
      )}

      {tab === "devices" && lastDiff && (
        <DiffBanner diff={lastDiff} />
      )}

      <main className="main">
        {tab === "devices" && (
          <>
            <DevicesTable
              devices={devices}
              networkKey={network}
              selected={selected}
              onSelect={(d) => setSelected(d === selected ? null : d)}
            />
            {selected && (
              <DeviceDetail
                device={devices.find((d) => d.key === selected) ?? null}
                deviceKey={selected}
                onRenamed={refresh}
                onClose={() => setSelected(null)}
              />
            )}
          </>
        )}
        {tab === "networks" && (
          <NetworksPanel
            networks={networks}
            current={currentNetwork?.key ?? null}
            onLabelChanged={refresh}
          />
        )}
        {tab === "settings" && <SettingsPanel />}
      </main>

      <footer className="footer">
        {devices.length} devices · {networks.length} networks · inventory-first scanning —
        unprivileged by default
      </footer>
    </div>
  );
}
