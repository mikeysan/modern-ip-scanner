// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mikey-san

//! One rule for what a device is called on screen.
//!
//! Four copies of this decision used to live in the store (twice, once of
//! them in SQL), the scanner (twice) and the CLI, and they disagreed about
//! the last resort: the same nameless device read as `?` in the device table,
//! as its IP in a fresh scan report, and as its raw sixteen-character key in
//! a transition re-read from the database.

/// The device's display name, in descending order of what a person would
/// recognise: the name they gave it, the name it announced, its MAC, the
/// address it was last seen at, and finally the short form of its key.
pub fn device_display(
    user_name: Option<&str>,
    primary_name: Option<&str>,
    mac: Option<&str>,
    last_ip: Option<&str>,
    key: &str,
) -> String {
    // A named fn, not a closure: elision ties the output lifetime to the
    // input, which closure inference will not do here.
    fn pick(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }
    pick(user_name)
        .or_else(|| pick(primary_name))
        .or_else(|| pick(mac))
        .or_else(|| pick(last_ip))
        .map(str::to_string)
        .unwrap_or_else(|| short_key(key))
}

/// The eight characters of a device or network key that the CLI and GUI
/// display, and that `get_device_by_ref` / `get_network_by_ref` resolve by
/// prefix.
pub fn short_key(key: &str) -> String {
    key.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_the_user_chose_beats_everything() {
        assert_eq!(
            device_display(
                Some("Office Printer"),
                Some("HP1234"),
                Some("aa:bb:cc:dd:ee:ff"),
                Some("10.0.0.5"),
                "abcdef0123456789"
            ),
            "Office Printer"
        );
    }

    #[test]
    fn each_signal_falls_through_to_the_next() {
        let key = "abcdef0123456789";
        assert_eq!(
            device_display(None, Some("nas"), Some("aa:bb:cc:dd:ee:ff"), None, key),
            "nas"
        );
        assert_eq!(
            device_display(None, None, Some("aa:bb:cc:dd:ee:ff"), Some("10.0.0.5"), key),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            device_display(None, None, None, Some("10.0.0.5"), key),
            "10.0.0.5"
        );
    }

    #[test]
    fn a_device_with_no_signal_at_all_reads_as_its_short_key() {
        // Never "?": the short key is what `mipscan devices` prints and what
        // get_device_by_ref resolves, so it is something the user can act on.
        assert_eq!(
            device_display(None, None, None, None, "abcdef0123456789"),
            "abcdef01"
        );
    }

    #[test]
    fn blank_signals_are_not_names() {
        assert_eq!(
            device_display(
                Some("   "),
                Some(""),
                None,
                Some("10.0.0.5"),
                "abcdef0123456789"
            ),
            "10.0.0.5"
        );
    }
}
