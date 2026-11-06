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
