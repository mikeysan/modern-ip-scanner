//! SQLite-backed inventory store.
//!
//! Schema lives in [`MIGRATIONS`]; `user_version` drives forward-only
//! migration. All timestamps are unix seconds (UTC).

use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::{Path, PathBuf};

use crate::model::{
    DeviceView, FieldChange, HistoryEvent, NetworkView, PartialReason, Transition, TransitionKind,
};
use crate::util::now;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("io error opening database: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

const MIGRATIONS: &[&str] = &[
    // v1
    "CREATE TABLE networks (
        key TEXT PRIMARY KEY,
        label TEXT,
        subnet TEXT,
        gateway_mac TEXT,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    );
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        primary_name TEXT,
        mac TEXT,
        vendor TEXT,
        origin_network TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    );
    CREATE INDEX idx_devices_mac ON devices(mac);
    CREATE TABLE device_aliases (
        alias_key TEXT PRIMARY KEY,
        canonical_key TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX idx_aliases_canonical ON device_aliases(canonical_key);
    CREATE TABLE user_names (
        device_key TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        notes TEXT,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE presence (
        device_key TEXT NOT NULL,
        network_key TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        miss_streak INTEGER NOT NULL DEFAULT 0,
        last_ip TEXT,
        PRIMARY KEY (device_key, network_key)
    );
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at INTEGER NOT NULL,
        finished_at INTEGER NOT NULL,
        network_key TEXT NOT NULL,
        partial INTEGER NOT NULL,
        privilege_json TEXT NOT NULL,
        strategies_json TEXT NOT NULL,
        partial_reasons_json TEXT NOT NULL,
        stats_json TEXT NOT NULL
    );
    CREATE INDEX idx_scans_network ON scans(network_key, id);
    CREATE TABLE observations (
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        at INTEGER NOT NULL,
        device_key TEXT NOT NULL,
        ip TEXT NOT NULL,
        mac TEXT,
        hostname TEXT,
        source TEXT NOT NULL,
        confidence REAL NOT NULL
    );
    CREATE INDEX idx_obs_device ON observations(device_key, at);
    CREATE INDEX idx_obs_scan ON observations(scan_id);
    CREATE TABLE transitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        at INTEGER NOT NULL,
        device_key TEXT NOT NULL,
        network_key TEXT NOT NULL,
        kind TEXT NOT NULL,
        changes_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX idx_trans_device ON transitions(device_key, at);
    CREATE TABLE meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    INSERT INTO meta (key, value) VALUES
        ('grace_scans', '2'),
        ('observations_retention_days', '90'),
        ('enabled_strategies', '[\"arp-cache\",\"ping-sweep\",\"mdns\",\"ssdp\",\"netbios\",\"arp-ping\"]');",
    // v2: remember whether an absence was already announced, so `gone` is
    // emitted once per absence even if grace_scans changes underneath a
    // device that is already missing.
    "ALTER TABLE presence ADD COLUMN reported_gone INTEGER NOT NULL DEFAULT 0;",
];

/// What a frontend needs to describe a finished scan: whether it was partial,
/// when it ended, which strategies ran, and why it fell short.
#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub partial: bool,
    pub finished_at: i64,
    pub strategies: Vec<String>,
    pub partial_reasons: Vec<PartialReason>,
}

/// A device as stored, with resolved identity.
#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: i64,
    pub key: String,
    pub primary_name: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub origin_network: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// Presence of a device on a network (the diff engine's "previous" state).
#[derive(Debug, Clone)]
pub struct PresenceRow {
    pub device_key: String,
    pub network_key: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub miss_streak: i64,
    pub last_ip: Option<String>,
    /// A `gone` transition has already been emitted for this absence.
    pub reported_gone: bool,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let mut store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Default per-user database location (override with `LANINV_DB`).
    pub fn open_default() -> Result<Store> {
        if let Ok(p) = std::env::var("LANINV_DB") {
            return Store::open(Path::new(&p));
        }
        let base: PathBuf = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("laninv");
        Store::open(&base.join("laninv.sqlite3"))
    }

    fn migrate(&mut self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, sql) in MIGRATIONS.iter().enumerate() {
            let v = (i + 1) as i64;
            if v > version {
                self.conn.execute_batch(sql)?;
                self.conn.pragma_update(None, "user_version", v)?;
            }
        }
        Ok(())
    }

    // ----- settings -----

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn grace_scans(&self) -> u32 {
        self.get_setting("grace_scans")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2)
    }

    // ----- networks -----

    pub fn upsert_network(
        &self,
        key: &str,
        subnet: Option<&str>,
        gateway_mac: Option<&str>,
    ) -> Result<()> {
        let t = now();
        self.conn.execute(
            "INSERT INTO networks (key, subnet, gateway_mac, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(key) DO UPDATE SET last_seen = excluded.last_seen",
            params![key, subnet, gateway_mac, t],
        )?;
        Ok(())
    }

    pub fn set_network_label(&self, key: &str, label: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE networks SET label = ?2 WHERE key = ?1",
            params![key, label],
        )?;
        Ok(n == 1)
    }

    pub fn get_network_label(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT label FROM networks WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten()
    }

    pub fn list_networks(&self) -> Result<Vec<NetworkView>> {
        let mut stmt = self.conn.prepare(
            "SELECT n.key, n.label, n.subnet, n.gateway_mac, n.first_seen, n.last_seen,
                    (SELECT COUNT(*) FROM presence p WHERE p.network_key = n.key) AS device_count
             FROM networks n ORDER BY n.last_seen DESC",
        )?;
        let rows = stmt.query_map([], row_network)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ----- identity resolution -----

    /// Walk the alias table to the canonical key for `key` (depth-capped).
    pub fn resolve_alias(&self, key: &str) -> Result<String> {
        let mut current = key.to_string();
        for _ in 0..8 {
            let next: Option<String> = self
                .conn
                .query_row(
                    "SELECT canonical_key FROM device_aliases WHERE alias_key = ?1",
                    [&current],
                    |r| r.get(0),
                )
                .optional()?;
            match next {
                Some(n) if n != current => current = n,
                _ => break,
            }
        }
        Ok(current)
    }

    pub fn add_alias(&self, alias_key: &str, canonical_key: &str) -> Result<()> {
        if alias_key == canonical_key {
            return Ok(());
        }
        // Never create cycles: if canonical already aliases elsewhere, resolve.
        let canonical = self.resolve_alias(canonical_key)?;
        self.conn.execute(
            "INSERT INTO device_aliases (alias_key, canonical_key, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(alias_key) DO UPDATE SET canonical_key = excluded.canonical_key",
            params![alias_key, canonical, now()],
        )?;
        // Re-point anything that previously aliased to alias_key.
        self.conn.execute(
            "UPDATE device_aliases SET canonical_key = ?2 WHERE canonical_key = ?1",
            params![alias_key, canonical],
        )?;
        // Carry the device row itself over if the canonical key has none.
        self.conn.execute(
            "INSERT OR IGNORE INTO devices (key, primary_name, mac, vendor, origin_network, first_seen, last_seen)
             SELECT ?2, primary_name, mac, vendor, origin_network, first_seen, last_seen
             FROM devices WHERE key = ?1",
            params![alias_key, canonical],
        )?;
        // Presence/observations/history move to the canonical key.
        for table in ["presence", "observations", "transitions", "user_names"] {
            let sql = format!("UPDATE {table} SET device_key = ?2 WHERE device_key = ?1");
            self.conn.execute(&sql, params![alias_key, canonical])?;
        }
        self.conn.execute(
            "DELETE FROM devices WHERE key = ?1 AND key != ?2",
            params![alias_key, canonical],
        )?;
        Ok(())
    }

    pub fn find_device_by_mac(&self, mac: &str) -> Result<Option<DeviceRow>> {
        let canonical_targets: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT key FROM devices WHERE mac = ?1")?;
            let rows = stmt.query_map([mac], |r| r.get(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        // Prefer devices that are not superseded (i.e. are somebody's canonical).
        let mut resolved: Vec<String> = canonical_targets
            .iter()
            .map(|k| self.resolve_alias(k).unwrap_or_else(|_| k.clone()))
            .collect();
        resolved.sort();
        resolved.dedup();
        if resolved.len() == 1 {
            return self.get_device(&resolved[0]);
        }
        if resolved.len() > 1 {
            // Ambiguous (same MAC seen as two identities): prefer the one with
            // a primary name, then the most recently seen.
            let mut stmt = self.conn.prepare(
                "SELECT key FROM devices WHERE key IN (SELECT value FROM json_each(?1))
                 ORDER BY (primary_name IS NULL), last_seen DESC LIMIT 1",
            )?;
            let keys: Vec<String> = {
                let json = serde_json::to_string(&resolved).unwrap();
                let rows = stmt.query_map([json], |r| r.get(0))?;
                rows.filter_map(|r| r.ok()).collect()
            };
            if let Some(k) = keys.first() {
                return self.get_device(k);
            }
        }
        Ok(None)
    }

    pub fn find_device_by_name_on_network(
        &self,
        name: &str,
        network_key: &str,
    ) -> Result<Option<DeviceRow>> {
        let name = name.trim().to_lowercase();
        let mut stmt = self.conn.prepare(
            "SELECT d.id, d.key, d.primary_name, d.mac, d.vendor, d.origin_network, d.first_seen, d.last_seen
             FROM devices d
             JOIN presence p ON p.device_key = d.key
             WHERE lower(coalesce(d.primary_name,'')) = ?1 AND p.network_key = ?2
             ORDER BY d.last_seen DESC LIMIT 2",
        )?;
        let rows: Vec<DeviceRow> = stmt
            .query_map(params![name, network_key], row_device)?
            .filter_map(|r| r.ok())
            .collect();
        if rows.len() == 1 {
            Ok(Some(rows.into_iter().next().unwrap()))
        } else {
            Ok(None)
        }
    }

    pub fn get_device(&self, key: &str) -> Result<Option<DeviceRow>> {
        let canonical = self.resolve_alias(key)?;
        let mut stmt = self.conn.prepare(
            "SELECT id, key, primary_name, mac, vendor, origin_network, first_seen, last_seen
             FROM devices WHERE key = ?1",
        )?;
        let mut rows = stmt.query([canonical.as_str()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_device(row)?)),
            None => Ok(None),
        }
    }

    /// Look up a device by numeric id or by key (exact, then prefix).
    pub fn get_device_by_ref(&self, r: &str) -> Result<Option<DeviceRow>> {
        let by_id = |sql: &str, param: String| -> Result<Option<DeviceRow>> {
            let mut stmt = self.conn.prepare(sql)?;
            let mut rows = stmt.query([param])?;
            match rows.next()? {
                Some(row) => Ok(Some(row_device(row)?)),
                None => Ok(None),
            }
        };
        if let Ok(id) = r.parse::<i64>() {
            if let Some(row) = by_id(
                "SELECT id, key, primary_name, mac, vendor, origin_network, first_seen, last_seen
                 FROM devices WHERE id = ?1",
                id.to_string(),
            )? {
                return Ok(Some(row));
            }
        }
        if let Some(d) = self.get_device(r)? {
            return Ok(Some(d));
        }
        // key prefix
        let mut stmt = self.conn.prepare(
            "SELECT id, key, primary_name, mac, vendor, origin_network, first_seen, last_seen
             FROM devices WHERE key LIKE ?1 || '%' ORDER BY key LIMIT 2",
        )?;
        let rows: Vec<DeviceRow> = stmt
            .query_map([r], row_device)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(if rows.len() == 1 {
            rows.into_iter().next()
        } else {
            None
        })
    }

    pub fn upsert_device(
        &self,
        key: &str,
        primary_name: Option<&str>,
        mac: Option<&str>,
        vendor: Option<&str>,
        origin_network: &str,
    ) -> Result<()> {
        let t = now();
        self.conn.execute(
            "INSERT INTO devices (key, primary_name, mac, vendor, origin_network, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(key) DO UPDATE SET
                last_seen = excluded.last_seen,
                primary_name = coalesce(devices.primary_name, excluded.primary_name),
                mac = coalesce(devices.mac, excluded.mac),
                vendor = coalesce(devices.vendor, excluded.vendor)",
            params![key, primary_name, mac, vendor, origin_network, t],
        )?;
        Ok(())
    }

    pub fn update_device_fields(
        &self,
        key: &str,
        primary_name: Option<&str>,
        mac: Option<&str>,
        vendor: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET
                primary_name = coalesce(?2, primary_name),
                mac = coalesce(?3, mac),
                vendor = coalesce(?4, vendor),
                last_seen = ?5
             WHERE key = ?1",
            params![key, primary_name, mac, vendor, now()],
        )?;
        Ok(())
    }

    // ----- presence -----

    pub fn presence_for_network(&self, network_key: &str) -> Result<Vec<PresenceRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_key, network_key, first_seen, last_seen, miss_streak, last_ip,
                    reported_gone
             FROM presence WHERE network_key = ?1",
        )?;
        let rows = stmt.query_map([network_key], |r| {
            Ok(PresenceRow {
                device_key: r.get(0)?,
                network_key: r.get(1)?,
                first_seen: r.get(2)?,
                last_seen: r.get(3)?,
                miss_streak: r.get(4)?,
                last_ip: r.get(5)?,
                reported_gone: r.get::<_, i64>(6)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn upsert_presence(
        &self,
        device_key: &str,
        network_key: &str,
        last_ip: Option<&str>,
    ) -> Result<()> {
        let t = now();
        self.conn.execute(
            "INSERT INTO presence (device_key, network_key, first_seen, last_seen, miss_streak, last_ip)
             VALUES (?1, ?2, ?3, ?3, 0, ?4)
             ON CONFLICT(device_key, network_key) DO UPDATE SET
                last_seen = excluded.last_seen,
                miss_streak = 0,
                reported_gone = 0,
                last_ip = coalesce(excluded.last_ip, presence.last_ip)",
            params![device_key, network_key, t, last_ip],
        )?;
        Ok(())
    }

    pub fn bump_miss_streak(&self, device_key: &str, network_key: &str) -> Result<i64> {
        self.conn.execute(
            "UPDATE presence SET miss_streak = miss_streak + 1
             WHERE device_key = ?1 AND network_key = ?2",
            params![device_key, network_key],
        )?;
        let streak: i64 = self.conn.query_row(
            "SELECT miss_streak FROM presence WHERE device_key = ?1 AND network_key = ?2",
            params![device_key, network_key],
            |r| r.get(0),
        )?;
        Ok(streak)
    }

    /// Presence upsert inside an open transaction (atomic with the scan).
    pub fn upsert_presence_tx(
        tx: &rusqlite::Transaction<'_>,
        device_key: &str,
        network_key: &str,
        last_ip: Option<&str>,
    ) -> Result<()> {
        let t = now();
        tx.execute(
            "INSERT INTO presence (device_key, network_key, first_seen, last_seen, miss_streak, last_ip)
             VALUES (?1, ?2, ?3, ?3, 0, ?4)
             ON CONFLICT(device_key, network_key) DO UPDATE SET
                last_seen = excluded.last_seen,
                miss_streak = 0,
                reported_gone = 0,
                last_ip = coalesce(excluded.last_ip, presence.last_ip)",
            params![device_key, network_key, t, last_ip],
        )?;
        Ok(())
    }

    pub fn bump_miss_streak_tx(
        tx: &rusqlite::Transaction<'_>,
        device_key: &str,
        network_key: &str,
    ) -> Result<()> {
        tx.execute(
            "UPDATE presence SET miss_streak = miss_streak + 1
             WHERE device_key = ?1 AND network_key = ?2",
            params![device_key, network_key],
        )?;
        Ok(())
    }

    /// Record that a `gone` transition has been emitted for this absence.
    pub fn mark_reported_gone_tx(
        tx: &rusqlite::Transaction<'_>,
        device_key: &str,
        network_key: &str,
    ) -> Result<()> {
        tx.execute(
            "UPDATE presence SET reported_gone = 1
             WHERE device_key = ?1 AND network_key = ?2",
            params![device_key, network_key],
        )?;
        Ok(())
    }

    // ----- user names -----

    pub fn set_user_name(&self, device_key: &str, name: &str, notes: Option<&str>) -> Result<()> {
        let canonical = self.resolve_alias(device_key)?;
        self.conn.execute(
            "INSERT INTO user_names (device_key, name, notes, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(device_key) DO UPDATE SET name = excluded.name,
                notes = coalesce(excluded.notes, user_names.notes), updated_at = excluded.updated_at",
            params![canonical, name, notes, now()],
        )?;
        Ok(())
    }

    pub fn clear_user_name(&self, device_key: &str) -> Result<()> {
        let canonical = self.resolve_alias(device_key)?;
        self.conn.execute(
            "DELETE FROM user_names WHERE device_key = ?1",
            params![canonical],
        )?;
        Ok(())
    }

    pub fn get_user_name(&self, device_key: &str) -> Result<Option<(String, Option<String>)>> {
        let canonical = self.resolve_alias(device_key)?;
        self.conn
            .query_row(
                "SELECT name, notes FROM user_names WHERE device_key = ?1",
                params![canonical],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(StoreError::Sql)
    }

    // ----- scans / observations / transitions -----

    pub fn begin(&mut self) -> Result<rusqlite::Transaction<'_>> {
        Ok(self.conn.transaction()?)
    }

    #[allow(clippy::too_many_arguments)] // one argument per scans column
    pub fn insert_scan(
        tx: &rusqlite::Transaction<'_>,
        started_at: i64,
        finished_at: i64,
        network_key: &str,
        partial: bool,
        privilege_json: &str,
        strategies_json: &str,
        partial_reasons: &[PartialReason],
        stats_json: &str,
    ) -> Result<i64> {
        let reasons = serde_json::to_string(partial_reasons).unwrap();
        tx.execute(
            "INSERT INTO scans (started_at, finished_at, network_key, partial, privilege_json,
                                strategies_json, partial_reasons_json, stats_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                started_at,
                finished_at,
                network_key,
                partial as i64,
                privilege_json,
                strategies_json,
                reasons,
                stats_json
            ],
        )?;
        Ok(tx.last_insert_rowid())
    }

    #[allow(clippy::too_many_arguments)] // one argument per observations column
    pub fn insert_observation(
        tx: &rusqlite::Transaction<'_>,
        scan_id: i64,
        at: i64,
        device_key: &str,
        ip: &str,
        mac: Option<&str>,
        hostname: Option<&str>,
        source: &str,
        confidence: f64,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO observations (scan_id, at, device_key, ip, mac, hostname, source, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![scan_id, at, device_key, ip, mac, hostname, source, confidence],
        )?;
        Ok(())
    }

    pub fn insert_transition(
        tx: &rusqlite::Transaction<'_>,
        scan_id: i64,
        at: i64,
        device_key: &str,
        network_key: &str,
        kind: TransitionKind,
        changes: &[FieldChange],
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO transitions (scan_id, at, device_key, network_key, kind, changes_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                scan_id,
                at,
                device_key,
                network_key,
                kind.as_str(),
                serde_json::to_string(changes).unwrap()
            ],
        )?;
        Ok(())
    }

    pub fn transitions_of_scan(&self, scan_id: i64) -> Result<Vec<Transition>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.kind, t.device_key, t.changes_json,
                    coalesce(u.name, d.primary_name, d.mac, t.device_key),
                    d.primary_name, d.mac
             FROM transitions t
             LEFT JOIN devices d ON d.key = t.device_key
             LEFT JOIN user_names u ON u.device_key = t.device_key
             WHERE t.scan_id = ?1 ORDER BY t.id",
        )?;
        let rows = stmt.query_map([scan_id], |r| {
            let kind_s: String = r.get(0)?;
            let changes: Vec<FieldChange> =
                serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default();
            Ok(Transition {
                kind: match kind_s.as_str() {
                    "new" => TransitionKind::New,
                    "changed" => TransitionKind::Changed,
                    "gone" => TransitionKind::Gone,
                    _ => TransitionKind::Returned,
                },
                device_key: r.get(1)?,
                device_display: r.get(3)?,
                changes,
                // Derived rather than stored: a device that later gains a
                // name becomes identifiable, and old rows should say so.
                unstable_identity: !crate::identity::is_stable(
                    r.get::<_, Option<String>>(4)?.as_deref(),
                    r.get::<_, Option<String>>(5)?.as_deref(),
                ),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Summary of a scan for GUI/CLI "last diff" views.
    pub fn scan_summary(&self, scan_id: i64) -> Result<Option<ScanSummary>> {
        let row = self
            .conn
            .query_row(
                "SELECT partial, finished_at, strategies_json, partial_reasons_json
                 FROM scans WHERE id = ?1",
                [scan_id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? != 0,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((partial, finished_at, strategies_json, reasons_json)) => Ok(Some(ScanSummary {
                partial,
                finished_at,
                strategies: serde_json::from_str(&strategies_json).unwrap_or_default(),
                partial_reasons: serde_json::from_str(&reasons_json).unwrap_or_default(),
            })),
        }
    }

    pub fn last_scan_for_network(&self, network_key: &str) -> Result<Option<(i64, i64)>> {
        self.conn
            .query_row(
                "SELECT id, finished_at FROM scans WHERE network_key = ?1 ORDER BY id DESC LIMIT 1",
                [network_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(StoreError::Sql)
    }

    // ----- listing / history -----

    pub fn list_devices(&self, network_key: Option<&str>) -> Result<Vec<DeviceView>> {
        let sql = "SELECT d.id, d.key, d.primary_name, d.mac, d.vendor, d.first_seen, d.last_seen,
                          u.name, u.notes,
                          (SELECT group_concat(p.network_key) FROM presence p WHERE p.device_key = d.key)
                   FROM devices d LEFT JOIN user_names u ON u.device_key = d.key";
        let make_view = |r: &Row<'_>| -> rusqlite::Result<DeviceView> {
            let primary_name: Option<String> = r.get(2)?;
            let mac: Option<String> = r.get(3)?;
            let user_name: Option<String> = r.get(7)?;
            let networks_csv: Option<String> = r.get(9)?;
            let networks: Vec<String> = networks_csv
                .map(|c| c.split(',').map(|s| s.to_string()).collect())
                .unwrap_or_default();
            let display_name = user_name
                .clone()
                .or_else(|| primary_name.clone())
                .or_else(|| mac.clone())
                .unwrap_or_else(|| "?".into());
            Ok(DeviceView {
                id: r.get(0)?,
                key: r.get(1)?,
                user_name,
                primary_name,
                display_name,
                mac,
                vendor: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
                last_ip: None,
                networks,
                notes: r.get(8)?,
            })
        };
        match network_key {
            None => {
                let mut stmt = self
                    .conn
                    .prepare(&format!("{sql} ORDER BY d.last_seen DESC"))?;
                let mut views: Vec<DeviceView> = stmt
                    .query_map([], make_view)?
                    .filter_map(|r| r.ok())
                    .collect();
                for v in &mut views {
                    v.last_ip = self.latest_ip_any(&v.key);
                }
                Ok(views)
            }
            Some(nk) => {
                let mut stmt = self.conn.prepare(&format!(
                    "{sql} JOIN presence pr ON pr.device_key = d.key AND pr.network_key = ?1
                     ORDER BY d.last_seen DESC"
                ))?;
                let mut views: Vec<DeviceView> = stmt
                    .query_map([nk], make_view)?
                    .filter_map(|r| r.ok())
                    .collect();
                for v in &mut views {
                    v.last_ip = self.latest_ip_on(&v.key, nk);
                }
                Ok(views)
            }
        }
    }

    fn latest_ip_on(&self, key: &str, network_key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT last_ip FROM presence WHERE device_key = ?1 AND network_key = ?2",
                params![key, network_key],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    fn latest_ip_any(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT last_ip FROM presence WHERE device_key = ?1 ORDER BY last_seen DESC LIMIT 1",
                [key],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn device_history(&self, device_key: &str, limit: i64) -> Result<Vec<HistoryEvent>> {
        let canonical = self.resolve_alias(device_key)?;
        let mut events: Vec<(i64, HistoryEvent)> = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT o.at, s.network_key, o.ip, o.mac, o.hostname, o.source
             FROM observations o JOIN scans s ON s.id = o.scan_id
             WHERE o.device_key = ?1 ORDER BY o.at DESC, o.rowid DESC LIMIT ?2",
        )?;
        let obs = stmt.query_map(params![canonical, limit], |r| {
            Ok(HistoryEvent::Observation {
                at: r.get(0)?,
                network_key: r.get(1)?,
                ip: r.get(2)?,
                mac: r.get(3)?,
                hostname: r.get(4)?,
                source: r.get(5)?,
            })
        })?;
        for o in obs.flatten() {
            if let HistoryEvent::Observation { at, .. } = &o {
                events.push((*at, o));
            }
        }
        let mut stmt = self.conn.prepare(
            "SELECT at, network_key, kind, changes_json FROM transitions
             WHERE device_key = ?1 ORDER BY at DESC LIMIT ?2",
        )?;
        let trans = stmt.query_map(params![canonical, limit], |r| {
            let kind_s: String = r.get(2)?;
            let changes: Vec<FieldChange> =
                serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default();
            Ok(HistoryEvent::Transition {
                at: r.get(0)?,
                network_key: r.get(1)?,
                kind: match kind_s.as_str() {
                    "new" => TransitionKind::New,
                    "changed" => TransitionKind::Changed,
                    "gone" => TransitionKind::Gone,
                    _ => TransitionKind::Returned,
                },
                changes,
            })
        })?;
        for t in trans.flatten() {
            if let HistoryEvent::Transition { at, .. } = &t {
                events.push((*at, t));
            }
        }
        let mut stmt = self
            .conn
            .prepare("SELECT updated_at, name FROM user_names WHERE device_key = ?1")?;
        let named = stmt.query_map(params![canonical], |r| {
            Ok(HistoryEvent::Named {
                at: r.get(0)?,
                name: r.get(1)?,
            })
        })?;
        for n in named.flatten() {
            if let HistoryEvent::Named { at, .. } = &n {
                events.push((*at, n));
            }
        }
        events.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
        events.truncate(limit as usize);
        Ok(events.into_iter().map(|(_, e)| e).collect())
    }

    /// Delete observations older than the configured retention window.
    pub fn prune(&self) -> Result<usize> {
        let days: i64 = self
            .get_setting("observations_retention_days")
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);
        let cutoff = now() - days * 86_400;
        let n = self
            .conn
            .execute("DELETE FROM observations WHERE at < ?1", params![cutoff])?;
        Ok(n)
    }

    /// Integrity audit used by tests: no transition rows for partial scans.
    pub fn gone_transitions_for_scan(&self, scan_id: i64) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT device_key FROM transitions WHERE scan_id = ?1 AND kind = 'gone'")?;
        let rows = stmt.query_map([scan_id], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn row_device(r: &Row<'_>) -> rusqlite::Result<DeviceRow> {
    Ok(DeviceRow {
        id: r.get(0)?,
        key: r.get(1)?,
        primary_name: r.get(2)?,
        mac: r.get(3)?,
        vendor: r.get(4)?,
        origin_network: r.get(5)?,
        first_seen: r.get(6)?,
        last_seen: r.get(7)?,
    })
}

fn row_network(r: &Row<'_>) -> rusqlite::Result<NetworkView> {
    Ok(NetworkView {
        key: r.get(0)?,
        label: r.get(1)?,
        subnet: r.get(2)?,
        gateway_mac: r.get(3)?,
        first_seen: r.get(4)?,
        last_seen: r.get(5)?,
        device_count: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.sqlite3")).unwrap();
        (dir, store)
    }

    #[allow(dead_code)]
    fn unused() {}

    #[test]
    fn migrations_apply_and_version_set() {
        let (_d, store) = tmp_store();
        let v: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v as usize, MIGRATIONS.len());
    }

    #[test]
    fn alias_moves_history_and_names() {
        let (_d, mut store) = tmp_store();
        store
            .upsert_network("net1", Some("192.168.1.0/24"), None)
            .unwrap();
        store
            .upsert_device(
                "oldkey",
                Some("printer"),
                Some("aa:bb:cc:dd:ee:ff"),
                None,
                "net1",
            )
            .unwrap();
        store
            .set_user_name("oldkey", "Office Printer", None)
            .unwrap();
        store
            .upsert_presence("oldkey", "net1", Some("192.168.1.50"))
            .unwrap();
        let tx = store.begin().unwrap();
        let scan_id = Store::insert_scan(&tx, 1, 2, "net1", false, "{}", "[]", &[], "{}").unwrap();
        Store::insert_observation(
            &tx,
            scan_id,
            2,
            "oldkey",
            "192.168.1.50",
            Some("aa:bb:cc:dd:ee:ff"),
            Some("printer"),
            "arp-cache",
            1.0,
        )
        .unwrap();
        tx.commit().unwrap();

        store.add_alias("oldkey", "newkey").unwrap();
        assert_eq!(store.resolve_alias("oldkey").unwrap(), "newkey");
        let dev = store.get_device("oldkey").unwrap().unwrap();
        assert_eq!(dev.key, "newkey");
        assert_eq!(dev.primary_name.as_deref(), Some("printer"));
        let name = store.get_user_name("oldkey").unwrap().unwrap();
        assert_eq!(name.0, "Office Printer");
        let presence = store.presence_for_network("net1").unwrap();
        assert_eq!(presence.len(), 1);
        assert_eq!(presence[0].device_key, "newkey");
        let hist = store.device_history("oldkey", 10).unwrap();
        // one observation + one "named" event
        assert_eq!(hist.len(), 2);
    }

    #[test]
    fn mac_lookup_prefers_named() {
        let (_d, store) = tmp_store();
        store
            .upsert_device("k1", None, Some("aa:bb:cc:00:00:01"), None, "n")
            .unwrap();
        store
            .upsert_device("k2", Some("named"), Some("aa:bb:cc:00:00:01"), None, "n")
            .unwrap();
        store.add_alias("k2", "k1").unwrap(); // k2 superseded by k1
        let found = store
            .find_device_by_mac("aa:bb:cc:00:00:01")
            .unwrap()
            .unwrap();
        assert_eq!(found.key, "k1");
    }

    #[test]
    fn name_lookup_scoped_to_network() {
        let (_d, store) = tmp_store();
        store
            .upsert_device(
                "k1",
                Some("laptop"),
                Some("aa:bb:cc:00:00:01"),
                None,
                "netA",
            )
            .unwrap();
        store
            .upsert_presence("k1", "netA", Some("10.0.0.5"))
            .unwrap();
        assert!(store
            .find_device_by_name_on_network("LAPTOP", "netA")
            .unwrap()
            .is_some());
        assert!(store
            .find_device_by_name_on_network("laptop", "netB")
            .unwrap()
            .is_none());
    }

    #[test]
    fn grace_setting_roundtrip() {
        let (_d, store) = tmp_store();
        assert_eq!(store.grace_scans(), 2);
        store.set_setting("grace_scans", "3").unwrap();
        assert_eq!(store.grace_scans(), 3);
    }
}
