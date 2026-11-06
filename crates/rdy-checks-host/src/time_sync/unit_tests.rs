//! Pure tests of the `host.time_sync` judgement: facts in, finding out. No probe, no fixture.

use rdy_engine::check::Level;
use serde_json::json;

use super::judge::{Attempt, Facts, Limits, Tool, judge};
use super::parse::{Timedate, Tracking};
use super::sntp::{Reject, Sample};

fn synced_td() -> Tool<Timedate> {
    Tool::Got(Timedate {
        synchronized: Some(true),
        ntp_enabled: Some(true),
        timezone: Some("UTC".to_owned()),
    })
}

fn unsynced_td() -> Tool<Timedate> {
    Tool::Got(Timedate {
        synchronized: Some(false),
        ntp_enabled: Some(false),
        timezone: None,
    })
}

fn chrony(synchronized: bool, offset: f64) -> Tool<Tracking> {
    Tool::Got(Tracking {
        reference: Some("ntp.acme.example".to_owned()),
        stratum: if synchronized { 2 } else { 0 },
        offset,
        leap: if synchronized {
            "Normal"
        } else {
            "Not synchronised"
        }
        .to_owned(),
        synchronized,
        local_reference: false,
    })
}

fn sample(offset: f64) -> Attempt {
    Attempt::Sample(Sample {
        offset,
        delay: 0.01,
        stratum: 2,
    })
}

fn facts(td: Tool<Timedate>, ch: Tool<Tracking>, servers: Vec<(&str, Attempt)>) -> Facts {
    Facts {
        timedatectl: td,
        chronyc: ch,
        servers: servers
            .into_iter()
            .map(|(name, attempt)| (name.to_owned(), attempt))
            .collect(),
    }
}

const DEFAULTS: fn() -> Limits = || Limits::new(None, None, false);

#[test]
fn the_defaults_are_5_seconds_to_warn_and_300_to_block() {
    for (offset, level) in [
        (0.0, Level::Pass),
        (5.0, Level::Pass),
        (5.1, Level::Warn),
        (300.0, Level::Warn),
        (300.1, Level::Fail),
        (-300.1, Level::Fail),
        (-6.0, Level::Warn),
    ] {
        let f = facts(synced_td(), Tool::Absent, vec![("ntp", sample(offset))]);
        assert_eq!(judge(&f, DEFAULTS()).level, level, "{offset}");
    }
}

#[test]
fn a_spec_max_skew_moves_the_block_level_and_caps_the_warn_level() {
    let limits = Limits::new(Some(2.0), None, false);
    let f = facts(synced_td(), Tool::Absent, vec![("ntp", sample(1.9))]);
    assert_eq!(judge(&f, limits).level, Level::Pass);
    let f = facts(synced_td(), Tool::Absent, vec![("ntp", sample(2.1))]);
    assert_eq!(judge(&f, limits).level, Level::Fail);
    let limits = Limits::new(Some(60.0), Some(30.0), false);
    let f = facts(synced_td(), Tool::Absent, vec![("ntp", sample(31.0))]);
    assert_eq!(judge(&f, limits).level, Level::Warn);
}

#[test]
fn not_synchronized_blocks_only_with_require_sync() {
    let f = facts(unsynced_td(), Tool::Absent, vec![]);
    assert_eq!(judge(&f, DEFAULTS()).level, Level::Warn);
    assert_eq!(judge(&f, Limits::new(None, None, true)).level, Level::Fail);
}

#[test]
fn disagreeing_sources_warn_even_with_require_sync() {
    let f = facts(synced_td(), chrony(false, 0.0), vec![]);
    let limits = Limits::new(None, None, true);
    let finding = judge(&f, limits);
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.observed["state"], "conflict");
}

#[test]
fn an_unknown_state_with_require_sync_warns_and_never_blocks() {
    let f = facts(Tool::Absent, Tool::Absent, vec![("ntp", sample(0.01))]);
    let finding = judge(&f, Limits::new(None, None, true));
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.partial.is_some());
    // Without require_sync a measured offset inside the limits is enough.
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding.message.contains("sync state not read"),
        "{}",
        finding.message
    );
}

#[test]
fn the_first_good_server_in_spec_order_wins() {
    let f = facts(
        synced_td(),
        Tool::Absent,
        vec![
            ("a.acme.example", Attempt::Silent),
            ("b.acme.example", sample(-20.0)),
            ("c.acme.example", sample(0.0)),
        ],
    );
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.observed["reference"], "b.acme.example");
    assert!(
        finding.message.contains("20 s ahead of `b.acme.example`"),
        "{}",
        finding.message
    );
}

#[test]
fn sntp_is_preferred_over_chrony_and_chrony_fills_in_when_sntp_has_nothing() {
    let f = facts(synced_td(), chrony(true, 0.4), vec![("ntp", sample(0.01))]);
    assert_eq!(judge(&f, DEFAULTS()).observed["offset_source"], "sntp");
    let f = facts(
        synced_td(),
        chrony(true, 0.4),
        vec![("ntp", Attempt::Silent)],
    );
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.observed["offset_source"], "chronyc");
    assert_eq!(finding.level, Level::Pass);
}

#[test]
fn a_chrony_offset_over_the_limit_blocks_without_any_server() {
    let f = facts(synced_td(), chrony(true, 450.0), vec![]);
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("away from chrony's reference `ntp.acme.example`"),
        "{}",
        finding.message
    );
}

#[test]
fn a_skew_limit_with_no_way_to_measure_warns_as_not_verified() {
    let f = facts(synced_td(), Tool::Absent, vec![]);
    let finding = judge(&f, Limits::new(Some(2.0), None, false));
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.starts_with("Offset not measured"),
        "{}",
        finding.message
    );
    assert!(finding.partial.is_some());
    // No limit and no server: a pass that says so.
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding.message.contains("Offset not measured"),
        "{}",
        finding.message
    );
    assert!(finding.partial.is_none());
}

#[test]
fn rejections_and_failures_are_notes_not_offsets() {
    let f = facts(
        synced_td(),
        Tool::Absent,
        vec![
            (
                "a.acme.example",
                Attempt::Rejected(Reject::Stratum0(Some("RATE".to_owned()))),
            ),
            (
                "b.acme.example",
                Attempt::Failed("the name did not resolve".to_owned()),
            ),
        ],
    );
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.notes.iter().any(|n| n.contains("kiss code RATE")),
        "{:?}",
        finding.notes
    );
    assert!(
        finding.notes.iter().any(|n| n.contains("did not resolve")),
        "{:?}",
        finding.notes
    );
    assert_eq!(finding.observed["offset_seconds"], json!(null));
}

#[test]
fn a_hostile_server_name_is_escaped_in_the_text() {
    let f = facts(
        synced_td(),
        Tool::Absent,
        vec![("evil\u{1b}[2J.acme.example", sample(400.0))],
    );
    let finding = judge(&f, DEFAULTS());
    assert!(!finding.message.contains('\u{1b}'));
    assert!(!finding.fix.clone().unwrap_or_default().contains('\u{1b}'));
    assert!(finding.message.contains("\\x1b"), "{}", finding.message);
}

#[test]
fn chronyd_on_its_own_local_clock_is_noted() {
    let local = Tool::Got(Tracking {
        reference: None,
        stratum: 10,
        offset: 0.0,
        leap: "Normal".to_owned(),
        synchronized: false,
        local_reference: true,
    });
    let f = facts(Tool::Absent, local, vec![]);
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.notes.iter().any(|n| n.contains("own local clock")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_tool_that_ran_without_an_answer_is_a_note() {
    let f = facts(
        Tool::Unusable("it exited with code 1".to_owned()),
        Tool::Unusable("chronyd may not be running".to_owned()),
        vec![],
    );
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.notes.len(), 2);
    assert_eq!(
        finding.observed["timedatectl"],
        "unusable: it exited with code 1"
    );
}

#[test]
fn the_offset_of_a_chronyd_without_a_source_is_not_used() {
    let f = facts(unsynced_td(), chrony(false, 0.0), vec![]);
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.message, "Clock is not synchronized.");
    assert_eq!(finding.observed["offset_seconds"], json!(null));
}

#[test]
fn the_chronyc_tail_is_only_said_when_chronyc_gave_the_offset() {
    // chronyc has no source: its offset is not used, so the note must not claim it.
    let f = facts(
        synced_td(),
        chrony(false, 0.0),
        vec![("169.254.169.123", Attempt::Refused)],
    );
    let finding = judge(&f, DEFAULTS());
    let note = finding.notes.first().expect("a note");
    assert!(!note.contains("Using the offset from chronyc"), "{note}");
    // chronyc is absent: the same.
    let f = facts(
        synced_td(),
        Tool::Absent,
        vec![("169.254.169.123", Attempt::Refused)],
    );
    assert!(!judge(&f, DEFAULTS()).notes[0].contains("Using the offset from chronyc"));
    // chronyc is synchronized and gave the offset: said.
    let f = facts(
        synced_td(),
        chrony(true, 0.001),
        vec![("169.254.169.123", Attempt::Refused)],
    );
    assert!(judge(&f, DEFAULTS()).notes[0].ends_with("Using the offset from chronyc instead."));
}

#[test]
fn the_error_bound_is_half_the_round_trip_and_a_long_one_is_called_out() {
    let slow = Attempt::Sample(Sample {
        offset: 0.2,
        delay: 3.0,
        stratum: 2,
    });
    let f = facts(synced_td(), Tool::Absent, vec![("ntp.acme.example", slow)]);
    let finding = judge(&f, DEFAULTS());
    assert_eq!(
        finding.observed["servers"][0]["error_bound_seconds"],
        json!(1.5)
    );
    let note = &finding.notes[0];
    assert!(note.contains("known to within 1.5 s"), "{note}");
    assert!(note.contains("uncertain"), "{note}");
    // A short trip is not called out.
    let f = facts(
        synced_td(),
        Tool::Absent,
        vec![("ntp.acme.example", sample(0.2))],
    );
    assert!(!judge(&f, DEFAULTS()).notes[0].contains("uncertain"));
}

#[test]
fn a_server_not_asked_is_a_note_and_not_an_offset() {
    let f = facts(
        synced_td(),
        Tool::Absent,
        vec![
            ("a.acme.example", sample(0.0)),
            (
                "b.acme.example",
                Attempt::NotAsked("an earlier server already answered"),
            ),
        ],
    );
    let finding = judge(&f, DEFAULTS());
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.observed["servers"][1]["result"], "not_measured");
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("not measured, an earlier server already answered")),
        "{:?}",
        finding.notes
    );
}

mod round_trip {
    use proptest::prelude::*;
    use rdy_spec::check::CheckParams;
    use rdy_spec::spec::CheckSpec;
    use serde_json::json;

    use crate::time_sync::TimeSync;

    fn host() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z]{2,6}){1,3}",
            (any::<u8>(), any::<u8>(), any::<u8>(), 1_u8..=254)
                .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
            proptest::array::uniform4(any::<u16>())
                .prop_map(|g| format!("[{:x}:{:x}:{:x}:{:x}::1]", g[0], g[1], g[2], g[3])),
        ]
    }

    proptest! {
        /// Every server the spec accepts becomes one target with the same host and port.
        #[test]
        fn every_accepted_server_becomes_a_target(
            host in host(),
            port in proptest::option::of(1_u16..=65535),
        ) {
            let text = match port {
                Some(p) => format!("{host}:{p}"),
                None => host.clone(),
            };
            let entry: CheckSpec =
                serde_json::from_value(json!({"id": "host.time_sync", "ntp_servers": [text]}))
                    .expect("an entry");
            // An input that does not decode is a failure, not a skipped case.
            let CheckParams::HostTimeSync(params) = entry.decode_params() else {
                return Err(TestCaseError::fail(format!("{text} did not decode")));
            };
            let Some(list) = &params.ntp_servers else {
                return Err(TestCaseError::fail(format!("{text} gave no server list")));
            };
            let check = TimeSync::from_params(&params);
            prop_assert_eq!(check.servers().len(), 1);
            for (server, target) in list.iter().zip(check.servers()) {
                prop_assert_eq!(server.target(), target);
                prop_assert_eq!(target.port(), port.unwrap_or(123));
            }
        }
    }
}
