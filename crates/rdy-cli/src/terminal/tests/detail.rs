//! Quiet and verbose output (07 section 2.8, C.1 and C.2, M1-143), byte for byte on the plan samples.

use rdy_spec::result::{Capability, Need, Signature, SignatureState, Status};

use super::{matches_plan, pass, sample};
use crate::style::Styler;
use crate::terminal::{Detail, View, banner, event_line, render};

fn files(folder: &str, minisig: bool) -> Vec<String> {
    let stem = folder.rsplit('/').next().unwrap_or(folder).to_owned();
    let mut files = vec![
        format!("{stem}.html"),
        format!("{stem}.json"),
        "spec.yaml".to_owned(),
    ];
    if minisig {
        files.push("spec.yaml.minisig".to_owned());
    }
    files
}

/// The banner, a blank line and the text of a run, at `detail`.
fn at_detail(
    report: &rdy_spec::result::Report,
    spec_arg: &str,
    folder: &str,
    minisig: bool,
    styler: Styler,
    detail: Detail,
) -> String {
    let files = files(folder, minisig);
    let view = View {
        report,
        spec_arg,
        folder: Some(folder),
        files: &files,
        note: None,
        kubeconfig: None,
        styler,
        width: 100,
        detail,
    };
    let mut out = String::new();
    if let Some(banner) = banner(&report.signature, spec_arg, styler) {
        out.push_str(&banner);
        out.push('\n');
    }
    out.push_str(&render(&view));
    out
}

fn plain(report: &rdy_spec::result::Report, detail: Detail) -> String {
    at_detail(report, "x.yaml", "./f", false, Styler::new(false), detail)
}

/// What a verbose run prints: a line for each check that ran, in the order they finished, a blank
/// line, and the text of the run. The plan sample names the order.
fn verbose_run(report: &rdy_spec::result::Report, finished: &[&str], styler: Styler) -> String {
    let mut out = String::new();
    for key in finished {
        let check = report
            .checks
            .iter()
            .find(|check| check.key == *key)
            .unwrap_or_else(|| panic!("no check {key}"));
        out.push_str(&event_line(
            &check.key,
            &check.status,
            check.duration_ms,
            styler,
        ));
    }
    out.push('\n');
    out.push_str(&at_detail(
        report,
        "acme-quickstart.yaml",
        "./rdy-report-acme-quickstart-20270309T101502Z",
        true,
        styler,
        Detail::Verbose,
    ));
    out
}

#[test]
fn quiet_equals_c1() {
    let out = at_detail(
        &sample("not-ready"),
        "acme-platform.yaml",
        "./rdy-report-acme-platform-20270309T143005Z",
        false,
        Styler::new(false),
        Detail::Quiet,
    );
    matches_plan(
        "not-ready-quiet",
        "### C.1 The NOT READY run with `--quiet`",
        &out,
    );
    assert_eq!(out.lines().last(), Some("NOT READY"));
}

#[test]
fn verbose_equals_c2() {
    let out = verbose_run(
        &sample("ready"),
        &["host.memory", "host.cpu", "host.disk/root", "net.egress"],
        Styler::new(false),
    );
    matches_plan(
        "ready-verbose",
        "### C.2 The READY run with `--verbose`",
        &out,
    );
    assert_eq!(out.lines().last(), Some("READY"));
}

#[test]
fn quiet_keeps_the_banner_the_folder_and_the_verdict_and_drops_the_rest() {
    let out = at_detail(
        &sample("ready"),
        "x.yaml",
        "./rdy-report-x",
        true,
        Styler::new(false),
        Detail::Quiet,
    );
    assert_eq!(
        out,
        "0 blocks, 0 warnings, 4 passed, 1 not applicable\n\nReport written to ./rdy-report-x/\nREADY\n"
    );
    let mut unsigned = sample("ready");
    unsigned.signature = Signature::bare(SignatureState::Unsigned);
    let out = plain(&unsigned, Detail::Quiet);
    assert!(out.starts_with("WARNING: UNSIGNED SPEC\n"), "{out}");
    let lines: Vec<&str> = out.lines().collect();
    let n = lines.len();
    assert_eq!(lines[n - 2], "WARNING: UNSIGNED SPEC");
    assert_eq!(lines[n - 1], "READY");
}

#[test]
fn quiet_sizes_the_key_column_by_the_lines_it_shows() {
    let mut report = sample("ready-with-warnings");
    // A passed check with a long key is not shown, so it must not widen the column.
    let mut long = pass("host.a_very_long_check_id", "fine");
    long.key = "host.a_very_long_check_id/with_a_long_name".to_owned();
    report.checks.push(long);
    report.refresh_verdict();
    let quiet = plain(&report, Detail::Quiet);
    let normal = plain(&report, Detail::Normal);
    assert!(!quiet.contains("PASS"), "{quiet}");
    assert!(!quiet.contains("a_very_long"), "{quiet}");
    let message_column = |text: &str| {
        text.lines()
            .find(|line| line.trim_start().starts_with("WARN"))
            .map(|line| {
                // `  WARN     <key><pad>  <message>`: the column where the message starts.
                let key_end = 11 + line[11..].find(' ').unwrap_or(0);
                let rest = &line[key_end..];
                key_end + rest.len() - rest.trim_start().len()
            })
    };
    assert!(message_column(&quiet) < message_column(&normal));
    assert!(quiet.lines().count() < normal.lines().count());
}

#[test]
fn verbose_shows_values_the_way_the_plan_says() {
    let out = plain(&sample("ready"), Detail::Verbose);
    for line in [
        "expected  min=4",
        "observed  arch=x86_64 hypervisor=true logical_cores=8 physical_cores=4",
        "swap_total_bytes=0 total_bytes=16496934912",
        "options=list(2)",
        "endpoints=list(2)",
        "needs   network: available",
        "actions 11 recorded; the JSON report lists them",
        "took    241 ms",
    ] {
        assert!(out.contains(line), "missing {line:?} in\n{out}");
    }
}

#[test]
fn verbose_notes_a_cut_action_log_and_unmet_needs() {
    let mut report = sample("ready");
    report.actions_truncated = true;
    let mut chronyc = Capability::new(Need::Command, true);
    chronyc.name = Some("chronyc".to_owned());
    report.capabilities = vec![Capability::new(Need::Root, false), chronyc];
    let out = plain(&report, Detail::Verbose);
    assert!(
        out.contains("needs   root: not available, command chronyc: available"),
        "{out}"
    );
    assert!(
        out.contains("11 recorded, more were dropped; the JSON report lists them"),
        "{out}"
    );
}

#[test]
fn an_event_line_escapes_the_key_and_dims_only_rdys_words() {
    let off = Styler::new(false);
    assert_eq!(
        event_line("host.cpu", &Status::Pass, 2, off),
        "  .. finished host.cpu (PASS, 2 ms)\n"
    );
    assert_eq!(
        event_line("net.egress", &Status::Timeout, 12_345, off),
        "  .. finished net.egress (TIMEOUT, 12 s)\n"
    );
    let hostile = event_line("a\u{1b}[31mb\u{202e}", &Status::Error, 0, Styler::new(true));
    assert!(hostile.contains("a\\x1b[31mb\\u{202e}"), "{hostile:?}");
    // The key sits between two dim runs, unstyled, and no escape of the key survives.
    assert!(
        hostile.starts_with("\u{1b}[2m  .. finished \u{1b}[0ma\\x1b"),
        "{hostile:?}"
    );
    assert!(hostile.ends_with("\u{1b}[2m)\u{1b}[0m\n"), "{hostile:?}");
    assert_eq!(hostile.matches('\u{1b}').count(), 12, "{hostile:?}");
}

#[test]
fn verbose_values_from_a_check_are_escaped() {
    let mut report = sample("ready");
    if let Some(check) = report.checks.first_mut() {
        let mut observed = serde_json::Map::new();
        observed.insert(
            "k\u{1b}ey".to_owned(),
            serde_json::json!("v\u{1b}]0;x\u{7}"),
        );
        check.observed = Some(observed);
    }
    let out = plain(&report, Detail::Verbose);
    assert!(out.contains("k\\x1bey=v\\x1b]0;x\\x07"), "{out}");
    assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'), "{out:?}");
}

#[test]
fn the_detail_follows_the_flags() {
    assert_eq!(Detail::from_flags(false, false), Detail::Normal);
    assert_eq!(Detail::from_flags(true, false), Detail::Quiet);
    assert_eq!(Detail::from_flags(false, true), Detail::Verbose);
}
