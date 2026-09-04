// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

//! Inventory export.
//!
//! Lives in the core so the CLI and the GUI cannot drift apart: they used to
//! carry separate copies of the same format string, and both mangled values
//! containing a quote.

use crate::model::DeviceView;
use crate::util::fmt_time;

/// Quote one CSV field per RFC 4180.
///
/// The previous implementation replaced `"` with `'`, silently corrupting any
/// name the user had typed a quote into. The rule is to double the quote, not
/// to change it.
fn field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// The inventory as RFC 4180 CSV, one row per device.
pub fn devices_csv(devices: &[DeviceView]) -> String {
    let mut out = String::from(
        "key,name,status,ip,mac,vendor,hostname,first_seen,last_seen,networks,notes\n",
    );
    for d in devices {
        let row = [
            field(&d.key),
            field(&d.display_name),
            field(d.status.as_str()),
            field(d.last_ip.as_deref().unwrap_or("")),
            field(d.mac.as_deref().unwrap_or("")),
            field(d.vendor.as_deref().unwrap_or("")),
            field(d.primary_name.as_deref().unwrap_or("")),
            field(&fmt_time(d.first_seen)),
            field(&fmt_time(d.last_seen)),
            field(&d.networks.join(" ")),
            field(d.notes.as_deref().unwrap_or("")),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DeviceStatus;

    fn device(name: &str, notes: Option<&str>) -> DeviceView {
        DeviceView {
            id: 1,
            key: "abcdef0123456789".into(),
            user_name: Some(name.into()),
            primary_name: None,
            display_name: name.into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            vendor: None,
            first_seen: 0,
            last_seen: 0,
            last_ip: Some("10.0.0.5".into()),
            networks: vec!["net1".into()],
            notes: notes.map(|n| n.into()),
            status: DeviceStatus::Known,
            identity_stable: true,
        }
    }

    fn body(csv: &str) -> Vec<&str> {
        csv.lines().skip(1).collect()
    }

    #[test]
    fn a_quote_is_doubled_not_replaced() {
        // Replacing it corrupted the user's own text.
        let csv = devices_csv(&[device(r#"Ben's "big" NAS"#, None)]);
        assert!(
            body(&csv)[0].contains(r#""Ben's ""big"" NAS""#),
            "got {}",
            body(&csv)[0]
        );
    }

    #[test]
    fn commas_and_newlines_survive_a_round_trip() {
        let csv = devices_csv(&[device("Study, upstairs", Some("line one\nline two"))]);
        assert!(csv.contains(r#""Study, upstairs""#));
        assert!(csv.contains("\"line one\nline two\""));
    }

    #[test]
    fn notes_and_status_are_exported() {
        let csv = devices_csv(&[device("nas", Some("in the cupboard"))]);
        let header = csv.lines().next().unwrap();
        assert!(header.contains("notes"), "header was {header}");
        assert!(header.contains("status"), "header was {header}");
        assert!(csv.contains("in the cupboard"));
    }

    #[test]
    fn an_empty_inventory_still_has_a_header() {
        let csv = devices_csv(&[]);
        assert_eq!(csv.lines().count(), 1);
        assert!(csv.starts_with("key,"));
    }
}
