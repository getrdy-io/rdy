//! Parsers for the text of `timedatectl` and `chronyc`.
//!
//! Both are defensive: a line that is not in the expected form is skipped, a value that is not in the
//! expected set is "unknown", and no input panics. The text is from the machine, so nothing here is
//! trusted to be short or plain.

/// What `timedatectl` said about the clock.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Timedate {
    /// Whether the kernel clock is synchronized. `None` when the text does not say.
    pub synchronized: Option<bool>,
    /// Whether network time is turned on (`NTP=yes`, `NTP service: active`). `None` when not said.
    pub ntp_enabled: Option<bool>,
    /// The time zone, when it is a plain zone name.
    pub timezone: Option<String>,
}

/// The most lines of either command that are looked at.
const MAX_LINES: usize = 200;

/// Parses `timedatectl show -p NTPSynchronized -p NTP -p Timezone` (`Key=value` lines).
///
/// `None` when no `NTPSynchronized` line is there, which is what the caller treats as "use `status`".
pub(crate) fn show(text: &str) -> Option<Timedate> {
    let mut found = Timedate::default();
    let mut saw_sync = false;
    for line in text.lines().take(MAX_LINES) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "NTPSynchronized" => {
                if let Some(yes) = yes_no(value) {
                    found.synchronized = Some(yes);
                    saw_sync = true;
                }
            }
            "NTP" => found.ntp_enabled = yes_no(value),
            "Timezone" => found.timezone = zone(value),
            _ => {}
        }
    }
    saw_sync.then_some(found)
}

/// Parses `timedatectl status`, the form of systemd 219 to current.
///
/// systemd 219 (RHEL 7) prints `NTP enabled: yes` and `NTP synchronized: yes`. Newer versions print
/// `System clock synchronized: yes` and `NTP service: active`. `None` when no synchronized line is there.
pub(crate) fn status(text: &str) -> Option<Timedate> {
    let mut found = Timedate::default();
    let mut saw_sync = false;
    for line in text.lines().take(MAX_LINES) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "ntp synchronized" | "system clock synchronized" => {
                if let Some(yes) = yes_no(value) {
                    found.synchronized = Some(yes);
                    saw_sync = true;
                }
            }
            "ntp enabled" | "network time on" => found.ntp_enabled = yes_no(value),
            "ntp service" => found.ntp_enabled = active(value),
            "time zone" => {
                // `Europe/Berlin (CET, +0100)`: the zone is the first word.
                found.timezone = value.split_whitespace().next().and_then(zone);
            }
            _ => {}
        }
    }
    saw_sync.then_some(found)
}

fn yes_no(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

fn active(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "active" => Some(true),
        "inactive" | "failed" => Some(false),
        _ => None,
    }
}

/// A time zone name that has only the characters zone names have, at most 64 of them.
fn zone(value: &str) -> Option<String> {
    let value = value.trim();
    let plain = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'));
    plain.then(|| value.to_owned())
}

/// The reference ID chronyd reports when it runs on its own local clock (`local` directive). It is
/// the bytes `7F 7F 01 01`.
const LOCAL_REFERENCE: &str = "7F7F0101";

/// What `chronyc -c tracking` said.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Tracking {
    /// The reference name or address, when there is one. Untrusted text.
    pub reference: Option<String>,
    /// The stratum.
    pub stratum: u8,
    /// How far the system clock is from NTP time, in seconds, always positive. The sign in the CSV is
    /// not used, because its direction is not stated in the CSV form.
    pub offset: f64,
    /// The leap status, one of chrony's four values: `Normal`, `Insert second`, `Delete second` or
    /// `Not synchronised`. Anything else is `unknown`.
    pub leap: String,
    /// Whether chronyd is tracking a real source: the leap status is not "not synchronised", the
    /// stratum is 1 to 15 and the reference is not chronyd's own local clock.
    pub synchronized: bool,
    /// Whether the reference is chronyd's own local clock (`local` directive).
    pub local_reference: bool,
}

/// Parses the one line of `chronyc -n -c tracking`.
///
/// The fields are: reference ID, reference name, stratum, reference time, system time, last offset, RMS
/// offset, frequency, residual frequency, skew, root delay, root dispersion, update interval, leap status.
/// `None` for a line with fewer than 14 fields or a number that does not parse.
pub(crate) fn tracking(text: &str) -> Option<Tracking> {
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    let fields: Vec<&str> = line.split(',').map(str::trim).collect();
    if fields.len() < 14 {
        return None;
    }
    let ref_id = fields[0].to_ascii_uppercase();
    let stratum: u8 = fields[2].parse().ok()?;
    let offset: f64 = fields[4].parse().ok()?;
    if !offset.is_finite() {
        return None;
    }
    let leap = leap_status(fields[13]);
    let local_reference = ref_id == LOCAL_REFERENCE;
    let not_synced = leap == "Not synchronised";
    let reference = printable(fields[1]);
    Some(Tracking {
        reference,
        stratum,
        offset: offset.abs(),
        synchronized: !not_synced && (1..=15).contains(&stratum) && !local_reference,
        local_reference,
        leap,
    })
}

/// chrony's leap status as one of its four values. The US spelling is read as the same value. Text from
/// the machine that is anything else is `unknown`, so it never reaches a report.
fn leap_status(text: &str) -> String {
    match text.to_ascii_lowercase().as_str() {
        "normal" => "Normal",
        "insert second" => "Insert second",
        "delete second" => "Delete second",
        "not synchronised" | "not synchronized" => "Not synchronised",
        _ => "unknown",
    }
    .to_owned()
}

/// Printable ASCII, 1 to 64 characters. A reference name that is not that is dropped.
fn printable(text: &str) -> Option<String> {
    let ok =
        !text.is_empty() && text.len() <= 64 && text.bytes().all(|b| (0x21..=0x7e).contains(&b));
    ok.then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_reads_the_three_properties_in_any_order() {
        let text = "Timezone=Europe/Berlin\nNTP=yes\nNTPSynchronized=yes\n";
        let t = show(text).expect("parsed");
        assert_eq!(t.synchronized, Some(true));
        assert_eq!(t.ntp_enabled, Some(true));
        assert_eq!(t.timezone.as_deref(), Some("Europe/Berlin"));
        let swapped = show("NTPSynchronized=no\nNTP=no\nTimezone=UTC\n").expect("parsed");
        assert_eq!(swapped.synchronized, Some(false));
        assert_eq!(swapped.ntp_enabled, Some(false));
    }

    #[test]
    fn show_without_the_sync_line_asks_for_the_status_fallback() {
        assert_eq!(show("Timezone=UTC\n"), None);
        assert_eq!(show(""), None);
        assert_eq!(show("NTPSynchronized=maybe\n"), None);
        assert_eq!(show("Unknown operation show\n"), None);
    }

    #[test]
    fn a_hostile_time_zone_is_dropped() {
        let t = show("NTPSynchronized=yes\nTimezone=UTC\u{1b}[2J\n").expect("parsed");
        assert_eq!(t.timezone, None);
        let long = format!("NTPSynchronized=yes\nTimezone={}\n", "a".repeat(65));
        assert_eq!(show(&long).expect("parsed").timezone, None);
    }

    #[test]
    fn status_reads_the_systemd_219_form() {
        let text = "      Local time: Mon 2026-11-02 09:00:00 UTC\n  Universal time: Mon 2026-11-02 09:00:00 UTC\n        RTC time: Mon 2026-11-02 09:00:00\n       Time zone: UTC (UTC, +0000)\n     NTP enabled: yes\nNTP synchronized: no\n RTC in local TZ: no\n      DST active: n/a\n";
        let t = status(text).expect("parsed");
        assert_eq!(t.synchronized, Some(false));
        assert_eq!(t.ntp_enabled, Some(true));
        assert_eq!(t.timezone.as_deref(), Some("UTC"));
    }

    #[test]
    fn status_reads_the_current_form() {
        let text = "               Local time: Mon 2026-11-02 09:00:00 UTC\n           Time zone: Europe/Berlin (CET, +0100)\nSystem clock synchronized: yes\n              NTP service: active\n          RTC in local TZ: no\n";
        let t = status(text).expect("parsed");
        assert_eq!(t.synchronized, Some(true));
        assert_eq!(t.ntp_enabled, Some(true));
        assert_eq!(t.timezone.as_deref(), Some("Europe/Berlin"));
        let inactive = status("System clock synchronized: no\nNTP service: inactive\n");
        assert_eq!(inactive.expect("parsed").ntp_enabled, Some(false));
    }

    #[test]
    fn status_without_a_sync_line_is_unknown() {
        assert_eq!(status("Failed to connect to bus: No such file\n"), None);
        assert_eq!(status(""), None);
    }

    const SYNCED: &str = "A9FEA97B,time.example,3,1793005190.123456789,0.000012345,0.000010000,0.000100000,1.234,0.010,0.050,0.001000,0.002000,64.0,Normal\n";

    #[test]
    fn tracking_reads_a_synchronized_line() {
        let t = tracking(SYNCED).expect("parsed");
        assert!(t.synchronized);
        assert_eq!(t.stratum, 3);
        assert_eq!(t.reference.as_deref(), Some("time.example"));
        assert!((t.offset - 0.000_012_345).abs() < 1e-12);
        assert_eq!(t.leap, "Normal");
    }

    #[test]
    fn tracking_takes_the_size_of_the_offset_not_its_sign() {
        let line = SYNCED.replace("0.000012345", "-0.500000000");
        let t = tracking(&line).expect("parsed");
        assert!((t.offset - 0.5).abs() < 1e-12);
    }

    #[test]
    fn tracking_not_synchronised_and_stratum_0_are_not_synchronized() {
        let line = "00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,1000000.000,0.000000,0.000000,0.0,Not synchronised\n";
        let t = tracking(line).expect("parsed");
        assert!(!t.synchronized);
        assert_eq!(t.reference, None);
        // The US spelling is read the same way.
        let us = line.replace("synchronised", "synchronized");
        assert!(!tracking(&us).expect("parsed").synchronized);
    }

    #[test]
    fn tracking_on_the_local_clock_is_not_real_time_sync() {
        let line = SYNCED.replace("A9FEA97B", "7f7f0101");
        let t = tracking(&line).expect("parsed");
        assert!(t.local_reference);
        assert!(!t.synchronized);
    }

    #[test]
    fn the_leap_status_is_one_of_four_values_or_unknown() {
        for (text, want) in [
            ("Normal", "Normal"),
            ("Insert second", "Insert second"),
            ("Delete second", "Delete second"),
            ("Not synchronised", "Not synchronised"),
            ("Not synchronized", "Not synchronised"),
            ("Evil\u{1b}[2J", "unknown"),
            ("", "unknown"),
        ] {
            let line = SYNCED.replace("Normal", text);
            assert_eq!(tracking(&line).expect("parsed").leap, want, "{text:?}");
        }
    }

    #[test]
    fn a_reference_name_is_printable_ascii_up_to_64_characters() {
        let long = "a".repeat(65);
        let ok = "a".repeat(64);
        for (name, want) in [
            ("time.example", Some("time.example")),
            (ok.as_str(), Some(ok.as_str())),
            (long.as_str(), None),
            ("a b", None),
            ("caf\u{e9}", None),
            ("x\u{1b}[2J", None),
            ("", None),
        ] {
            let line = SYNCED.replace("time.example", name);
            let got = tracking(&line).expect("parsed").reference;
            assert_eq!(got.as_deref(), want, "{name:?}");
        }
    }

    #[test]
    fn tracking_refuses_short_and_odd_lines() {
        assert_eq!(tracking(""), None);
        assert_eq!(tracking("506 Cannot talk to daemon\n"), None);
        assert_eq!(tracking("a,b,c\n"), None);
        let bad_stratum = SYNCED.replace(",3,", ",x,");
        assert_eq!(tracking(&bad_stratum), None);
        let nan = SYNCED.replace("0.000012345", "NaN");
        assert_eq!(tracking(&nan), None);
        let inf = SYNCED.replace("0.000012345", "inf");
        assert_eq!(tracking(&inf), None);
    }

    proptest::proptest! {
        #[test]
        fn no_text_panics(text in "\\PC{0,400}") {
            let _ = show(&text);
            let _ = status(&text);
            let _ = tracking(&text);
        }
    }
}
