//! Core data types shared across discovery, store, diff and frontends.

use serde::{Deserialize, Serialize};

/// A local network interface as seen by the OS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    /// OS name, e.g. `Ethernet` (Windows) / `enp3s0` (Linux).
    pub name: String,
    /// Human-friendly description if available.
    pub description: Option<String>,
    /// Interface MAC, normalized `aa:bb:cc:dd:ee:ff`.
    pub mac: Option<String>,
    /// IPv4 unicast addresses with on-link prefix length.
    pub ipv4: Vec<Ipv4Cidr>,
    /// IPv6 addresses (display only in v1).
    pub ipv6: Vec<String>,
    /// Default gateway IPv4 on this interface, if any.
    pub gateway_v4: Option<String>,
    /// Gateway MAC, resolved lazily by the scanner via the neighbor cache.
    pub gateway_mac: Option<String>,
    /// OS interface index.
    pub index: u32,
    /// Rough kind, used in the network composite key.
    pub kind: IfKind,
    /// Operationally up. A disconnected adapter keeps its configuration, so
    /// this is the only thing separating "my network" from "a NIC with a
    /// stale address".
    pub up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IfKind {
    Ethernet,
    Wireless,
    Loopback,
    Virtual,
    Other,
}

impl IfKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IfKind::Ethernet => "ethernet",
            IfKind::Wireless => "wireless",
            IfKind::Loopback => "loopback",
            IfKind::Virtual => "virtual",
            IfKind::Other => "other",
        }
    }

    pub fn is_loopback(self) -> bool {
        matches!(self, IfKind::Loopback)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    /// Dotted-quad address.
    pub addr: String,
    /// On-link prefix length (0-32).
    pub prefix: u8,
}

impl Ipv4Cidr {
    /// `192.168.1.0/24` style string of the network address.
    pub fn network_string(&self) -> Option<String> {
        let a = crate::util::parse_ipv4(&self.addr)?;
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        Some(crate::util::format_ipv4(a & mask))
    }
}

/// One neighbor-table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborEntry {
    pub ip: String,
    pub mac: String,
    pub interface_index: u32,
    /// true when the entry is reachable/reachable-ish (not failed/incomplete).
    pub reachable: bool,
}

/// Where a device-name signal came from; ordering encodes trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    Ssdp,
    Netbios,
    Mdns,
}

impl NameSource {
    pub fn as_str(self) -> &'static str {
        match self {
            NameSource::Ssdp => "ssdp",
            NameSource::Netbios => "netbios",
            NameSource::Mdns => "mdns",
        }
    }
}

/// A single fact observed by one strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub ip: String,
    pub mac: Option<String>,
    /// Best name for this observation, if the strategy learned one.
    pub name: Option<(NameSource, String)>,
    pub vendor: Option<String>,
    /// Strategy id, e.g. `arp-cache`.
    pub source: String,
    /// 0.0-1.0 how sure the strategy is the device is really there.
    pub confidence: f32,
}

/// Capabilities the privilege layer probes at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read the OS neighbor/ARP cache (always expected).
    NeighborCache,
    /// Send ICMP echoes (platform-dependent privilege).
    IcmpEcho,
    /// Resolve arbitrary IPv4 addresses via ARP (SendARP / raw socket / helper).
    ArpResolve,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::NeighborCache => "neighbor-cache",
            Capability::IcmpEcho => "icmp-echo",
            Capability::ArpResolve => "arp-resolve",
        }
    }
}

/// Result of the runtime capability probe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivilegeState {
    pub capabilities: Vec<Capability>,
    /// True when the privileged helper process is connected and answering.
    pub helper_connected: bool,
    /// Human-readable notes about degraded modes.
    pub notes: Vec<String>,
}

impl PrivilegeState {
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }
}

/// Why a scan was marked partial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialReason {
    pub strategy: String,
    pub reason: String,
}

/// A field-level change recorded in a `changed` transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    New,
    Changed,
    Gone,
    Returned,
}

impl TransitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransitionKind::New => "new",
            TransitionKind::Changed => "changed",
            TransitionKind::Gone => "gone",
            TransitionKind::Returned => "returned",
        }
    }
}

/// One inventory transition emitted by the diff engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub kind: TransitionKind,
    pub device_key: String,
    /// Display name at the time of the transition (user name preferred).
    pub device_display: String,
    /// Always serialized, even when empty: the frontends declare it as a
    /// plain array, and omitting it made `changes.length` throw on every
    /// `new`, `gone` and `returned` transition.
    #[serde(default)]
    pub changes: Vec<FieldChange>,
    /// True when this device cannot be re-identified across scans, so the
    /// transition should be read as "an address appeared", not "a device
    /// arrived". Omitted from JSON when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unstable_identity: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Summary of a finished scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: i64,
    pub network_key: String,
    pub network_label: Option<String>,
    pub started_at: i64,
    pub finished_at: i64,
    /// The integrity flag: see docs/design.md rule 6.
    pub partial: bool,
    pub partial_reasons: Vec<PartialReason>,
    pub strategies_run: Vec<String>,
    pub devices_seen: usize,
    pub transitions: Vec<Transition>,
    pub interface: Option<Interface>,
}

/// Where a device stands as of the most recent scan of a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// First seen in the latest scan.
    New,
    /// Seen in the latest scan, with a field that differs from before.
    Changed,
    /// Absent long enough to have been announced gone.
    Gone,
    /// Present and unremarkable — the state most of an inventory is in.
    Known,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceStatus::New => "new",
            DeviceStatus::Changed => "changed",
            DeviceStatus::Gone => "gone",
            DeviceStatus::Known => "known",
        }
    }
}

/// Device row as exposed to CLI/GUI (joined with user name and presence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceView {
    pub id: i64,
    pub key: String,
    /// User-assigned name, if any.
    pub user_name: Option<String>,
    /// Best machine-learned name (mDNS/NetBIOS/SSDP).
    pub primary_name: Option<String>,
    /// Display name: user name if set, else primary name, else MAC/IP.
    pub display_name: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Last-known IP on the queried network (or globally if no network given).
    pub last_ip: Option<String>,
    /// Networks this device has been seen on (keys).
    pub networks: Vec<String>,
    pub notes: Option<String>,
    /// Standing as of the network's most recent scan.
    pub status: DeviceStatus,
    /// False when this device cannot be re-identified across scans.
    pub identity_stable: bool,
}

/// Network row as exposed to CLI/GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkView {
    pub key: String,
    pub label: Option<String>,
    pub subnet: Option<String>,
    pub gateway_mac: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub device_count: i64,
}

/// History event for a single device (observation or transition).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HistoryEvent {
    Observation {
        at: i64,
        network_key: String,
        ip: String,
        mac: Option<String>,
        hostname: Option<String>,
        source: String,
    },
    Transition {
        at: i64,
        network_key: String,
        kind: TransitionKind,
        changes: Vec<FieldChange>,
    },
    Named {
        at: i64,
        name: String,
    },
}
