//! The renderer on the plan samples (07 C.12 to C.14, C.17, C.18 and 2.7), byte for byte, and the rules
//! around them: escaping, colour, wrapping, the source of a fix, the cluster line and the Tip.

use std::path::{Path, PathBuf};

use rdy_engine::testing::golden::assert_golden;
use rdy_spec::result::{
    CheckResult, FixSource, Need, NeedState, Report, Severity, SkipKind, Status, TrustSource,
};

use super::*;
use crate::style::wrap_width;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../")
}

fn fixtures() -> PathBuf {
    repo().join("tests/fixtures")
}

fn sample(name: &str) -> Report {
    let file = match name {
        "ready" => "b1-ready",
        "ready-with-warnings" => "b2-ready-with-warnings",
        _ => "b3-not-ready",
    };
    let path = fixtures().join(format!("results/plan-07/{file}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not a report: {e}", path.display()))
}

/// The file names of a report folder, as the plan samples list them.
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

/// The whole stderr of a run: the banner, a blank line, and the rest.
fn full(
    report: &Report,
    spec_arg: &str,
    folder: &str,
    minisig: bool,
    styler: Styler,
    width: usize,
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
        width,
    };
    let mut out = String::new();
    if let Some(banner) = banner(&report.signature, spec_arg, styler) {
        out.push_str(&banner);
        out.push('\n');
    }
    out.push_str(&render(&view));
    out
}

fn plain(report: &Report, spec_arg: &str, folder: &str, minisig: bool) -> String {
    full(report, spec_arg, folder, minisig, Styler::new(false), 100)
}

/// The console block of a plan section, without the `$` lines.
fn plan_sample(heading: &str) -> String {
    let doc = std::fs::read_to_string(repo().join("docs/plan/07-cli-ux.md"))
        .unwrap_or_else(|e| panic!("cannot read 07: {e}"));
    let at = doc
        .find(heading)
        .unwrap_or_else(|| panic!("07 has no {heading}"));
    let rest = &doc[at..];
    let open = rest
        .find("```console\n")
        .unwrap_or_else(|| panic!("no sample"))
        + "```console\n".len();
    let close = rest[open..]
        .find("\n```")
        .unwrap_or_else(|| panic!("no end"));
    let lines: Vec<&str> = rest[open..open + close].lines().collect();
    let end = lines
        .iter()
        .position(|l| l.starts_with("$ echo"))
        .unwrap_or_else(|| panic!("no echo line"));
    let mut text = lines[1..end].join("\n");
    text.push('\n');
    text
}

/// Checks `actual` against the golden file and against the plan section it came from.
#[track_caller]
fn matches_plan(golden: &str, heading: &str, actual: &str) {
    assert_golden(fixtures().join(format!("terminal/{golden}.txt")), actual);
    assert_eq!(
        actual,
        plan_sample(heading),
        "the output differs from {heading} in 07"
    );
}

#[test]
fn ready_equals_c17() {
    let out = plain(
        &sample("ready"),
        "acme-quickstart.yaml",
        "./rdy-report-acme-quickstart-20270309T101502Z",
        true,
    );
    matches_plan("ready", "### C.17 Sample: READY (2.5)", &out);
    assert_eq!(out.lines().last(), Some("READY"));
}

#[test]
fn ready_with_warnings_equals_c18() {
    let out = plain(
        &sample("ready-with-warnings"),
        "acme-quickstart.yaml",
        "./rdy-report-acme-quickstart-20270309T094820Z",
        true,
    );
    matches_plan(
        "ready-with-warnings",
        "### C.18 Sample: READY with warnings (2.6)",
        &out,
    );
    assert_eq!(out.lines().last(), Some("READY with warnings"));
}

#[test]
fn not_ready_equals_section_2_7() {
    let out = plain(
        &sample("not-ready"),
        "acme-platform.yaml",
        "./rdy-report-acme-platform-20270309T143005Z",
        false,
    );
    matches_plan("not-ready", "### 2.7 Sample: NOT READY", &out);
    assert_eq!(out.lines().last(), Some("NOT READY"));
}

/// B.1 with the parts a sample changes: product, signature, version and checks.
fn based_on_ready(
    product: &str,
    version: &str,
    producer: &str,
    checks: Vec<CheckResult>,
) -> Report {
    let mut report = sample("ready");
    report.spec.product = product.to_owned();
    report.spec.version = Some(version.to_owned());
    report.spec.file_name = format!("{product}.yaml");
    report.producer.version = producer.to_owned();
    report.proxy = None;
    report.checks = checks;
    report.refresh_verdict();
    report
}

fn not_in_build(id: &str) -> CheckResult {
    let mut check = CheckResult::skipped(id, "host", Severity::Block, SkipKind::NotInBuild);
    check.message = "Not run. This version of rdy has no host checks yet.".to_owned();
    check.fix =
        Some("Install a newer rdy. If there is none yet, ask the vendor how to go on.".to_owned());
    check.fix_source = Some(FixSource::Rdy);
    check
}

#[test]
fn nothing_ran_equals_c12() {
    let mut report = based_on_ready(
        "acme-edge",
        ">=1.0",
        "0.1.0-alpha.2",
        vec![
            not_in_build("host.cpu"),
            not_in_build("host.memory"),
            not_in_build("host.disk"),
        ],
    );
    report.signature.signed_at = Some("2026-12-02T08:00:00Z".to_owned());
    let out = plain(
        &report,
        "acme-edge.yaml",
        "./rdy-report-acme-edge-20261207T191244Z",
        true,
    );
    matches_plan(
        "not-ready-nothing-ran",
        "### C.12 NOT READY with no block",
        &out,
    );
    assert_eq!(
        out.lines().last(),
        Some("NOT READY: 3 required checks were not run")
    );
}

#[test]
fn nothing_checked_equals_c13() {
    let not_applicable = |id: &str| {
        let mut check = CheckResult::skipped(id, "host", Severity::Block, SkipKind::NotApplicable);
        check.message = "Does not apply here. This check is for windows only.".to_owned();
        check
    };
    let mut report = based_on_ready(
        "acme-win-agent",
        ">=2.0",
        "0.1.0",
        vec![not_applicable("host.memory"), not_applicable("host.disk")],
    );
    report.signature.signed_at = Some("2027-03-02T15:40:09Z".to_owned());
    let out = plain(
        &report,
        "acme-win-agent.yaml",
        "./rdy-report-acme-win-agent-20270309T112240Z",
        true,
    );
    matches_plan("nothing-checked", "### C.13 Nothing was checked", &out);
    assert_eq!(
        out.lines().last(),
        Some("READY with warnings: nothing was checked")
    );
}

fn pass(id: &str, message: &str) -> CheckResult {
    let mut check = CheckResult::new(id, "host", Severity::Block, Status::Pass);
    check.message = message.to_owned();
    check
}

fn one_run_key_report() -> Report {
    let mut report = based_on_ready(
        "acme-edge",
        ">=1.0",
        "0.1.0",
        vec![
            pass("host.cpu", "4 vCPUs found, 2 needed"),
            pass("host.memory", "7.6 GiB found, 4 GiB needed"),
        ],
    );
    report.signature.trust_source = Some(TrustSource::Flag);
    report.signature.key_fingerprint = Some(format!("4d2a7c0e{}0a1c", "9b1f".repeat(13)));
    report
}

#[test]
fn a_one_run_key_equals_c14() {
    let out = plain(
        &one_run_key_report(),
        "acme-edge.yaml",
        "./rdy-report-acme-edge-20270309T112240Z",
        true,
    );
    matches_plan("key-not-pinned", "### C.14 A run with a one-run key", &out);
    assert_eq!(out.lines().last(), Some("READY"));
}

#[test]
fn the_banner_is_left_out_for_a_pinned_key_and_the_title_repeats_above_the_verdict() {
    let mut report = one_run_key_report();
    for source in [TrustSource::System, TrustSource::User] {
        report.signature.trust_source = Some(source);
        assert!(banner(&report.signature, "x.yaml", Styler::new(false)).is_none());
        let out = plain(&report, "x.yaml", "./f", false);
        assert!(!out.contains("WARNING"), "{out}");
    }
    report.signature.trust_source = Some(TrustSource::Flag);
    let out = plain(&report, "x.yaml", "./f", false);
    assert_eq!(out.matches("WARNING: KEY NOT PINNED").count(), 2, "{out}");
    let lines: Vec<&str> = out.lines().collect();
    let n = lines.len();
    assert_eq!(lines[n - 2], "WARNING: KEY NOT PINNED");
    assert_eq!(lines[n - 1], "READY");
}

#[test]
fn the_sig_line_names_the_trust_source() {
    let mut report = sample("ready");
    for (source, text) in [
        (TrustSource::User, "trusted by you"),
        (TrustSource::System, "trusted on this machine"),
        (TrustSource::Flag, "key given with --key, not pinned"),
        (
            TrustSource::Unknown("elsewhere".to_owned()),
            "key given with --key, not pinned",
        ),
    ] {
        report.signature.trust_source = Some(source);
        let out = plain(&report, "x.yaml", "./f", false);
        assert!(
            out.contains(&format!("key 9F3A6C21D4E87B05, {text}, signed 2027-03-02")),
            "{out}"
        );
    }
}

#[test]
fn the_verdict_is_the_last_line_for_every_sample() {
    for (name, last) in [
        ("ready", "READY"),
        ("ready-with-warnings", "READY with warnings"),
        ("not-ready", "NOT READY"),
    ] {
        let out = plain(&sample(name), "x.yaml", "./f", false);
        assert_eq!(out.lines().last(), Some(last), "{name}");
        assert!(out.ends_with('\n'));
    }
}

#[test]
fn no_report_folder_drops_the_report_block_and_keeps_the_verdict_last() {
    let report = sample("ready");
    let view = View {
        report: &report,
        spec_arg: "x.yaml",
        folder: None,
        files: &[],
        note: None,
        kubeconfig: None,
        styler: Styler::new(false),
        width: 100,
    };
    let out = render(&view);
    assert!(!out.contains("Report written"), "{out}");
    assert!(out.ends_with("\n\nREADY\n"), "{out}");
}

#[test]
fn a_windows_folder_closes_with_a_backslash_and_a_note_sits_above_the_verdict() {
    let report = sample("ready");
    let files = vec!["spec.yaml".to_owned()];
    let view = View {
        report: &report,
        spec_arg: "x.yaml",
        folder: Some(r"C:\Users\jdoe\rdy-reports\rdy-report-x"),
        files: &files,
        note: Some("note: keep the folder private."),
        kubeconfig: None,
        styler: Styler::new(false),
        width: 100,
    };
    let out = render(&view);
    assert!(
        out.contains("Report written to C:\\Users\\jdoe\\rdy-reports\\rdy-report-x\\\n  spec.yaml\nnote: keep the folder private.\nREADY\n"),
        "{out}"
    );
}

// ---- untrusted text ----------------------------------------------------------------------------

fn hostile() -> Report {
    let mut report = sample("not-ready");
    report.host.hostname = "evil\u{1b}[2Jhost\u{202e}.example".to_owned();
    report.identity.user = Some("ro\u{7}ot\u{2066}".to_owned());
    report.spec.product = "acme\u{1b}[31m".to_owned();
    report.spec.version = Some("\u{202e}1".to_owned());
    report.signature.key_id = Some("\u{1b}[1mKEY".to_owned());
    let mut proxy = rdy_spec::result::Proxy::default();
    proxy.https = Some("http://user:secret@proxy\u{1b}[0m.example:3128".to_owned());
    report.proxy = Some(proxy);
    let check = report.checks.get_mut(1).unwrap_or_else(|| panic!("check"));
    check.key = "host.mem\u{1b}ory".to_owned();
    check.message = "15\u{1b}[2J GiB\u{202e} found\nsecond line".to_owned();
    check.fix = Some("Add RAM\u{2066} now\u{9b}".to_owned());
    report
}

/// No raw escape, control or bidi character is left in `text`, other than the codes the styler added.
fn assert_safe(text: &str) {
    let mut rest = text;
    while let Some(at) = rest.find('\x1b') {
        let after = &rest[at + 1..];
        let end = after
            .find('m')
            .unwrap_or_else(|| panic!("an escape that is not a colour code: {text:?}"));
        let params = &after[..end];
        assert!(
            params.starts_with('[') && params[1..].chars().all(|c| c.is_ascii_digit() || c == ';'),
            "an escape that is not a colour code: {text:?}"
        );
        rest = &after[end + 1..];
    }
    for c in text.chars() {
        let allowed = c == '\n' || c == '\x1b';
        assert!(
            allowed || (!c.is_control() && !rdy_engine::text::is_invisible(c)),
            "{c:?} is left in {text:?}"
        );
    }
}

/// CSI, OSC 8 and OSC 0 with BEL and with ST, a C1 introducer and the isolates, then a plain tail.
const PAYLOAD: &str = "\u{1b}[31m\u{1b}]8;;http://x.example\u{7}\u{1b}]0;title\u{1b}\\\u{9b}31m\u{2066}\u{2067}\u{2068}\u{2069}z";

/// A report with the payload in every string field the renderer reads.
fn everywhere() -> Report {
    let p = |tail: &str| format!("{PAYLOAD}{tail}");
    let mut report = sample("not-ready");
    report.producer.version = p("");
    report.spec.product = p("");
    report.spec.version = Some(p(""));
    report.signature = {
        let mut sig = Signature::bare(rdy_spec::result::SignatureState::Verified);
        sig.key_id = Some(p(""));
        sig.key_fingerprint = Some(p(""));
        sig.product = Some(p(""));
        sig.signed_at = Some(p(""));
        sig.trust_source = Some(TrustSource::Flag);
        sig
    };
    report.host.hostname = p("");
    report.host.arch = p("");
    report.host.os.id = Some(p(""));
    report.host.os.version = Some(p(""));
    report.identity.user = Some(p(""));
    let mut kube = rdy_spec::result::KubeIdentity::default();
    kube.context = Some(p(""));
    kube.server = Some(p(""));
    kube.user = Some(p(""));
    kube.exec_plugin = Some(p(""));
    report.identity.kube = Some(kube);
    let mut proxy = rdy_spec::result::Proxy::default();
    proxy.https = Some(p(""));
    proxy.http = Some(format!("{}:3128", p("")));
    report.proxy = Some(proxy);
    for cap in &mut report.capabilities {
        cap.detail = Some(p(""));
    }
    for check in &mut report.checks {
        check.key = p(&check.key);
        check.message = p(&check.message);
        check.fix = Some(p(""));
    }
    report
}

#[test]
fn a_payload_in_every_field_prints_as_text_with_colour_on_and_off() {
    for enabled in [false, true] {
        let styler = Styler::new(enabled);
        let mut report = everywhere();
        // The flags line, with the network off.
        report.run.options.network = false;
        report.run.options.kube_context = Some(PAYLOAD.to_owned());
        for trust in [TrustSource::Flag, TrustSource::User] {
            report.signature.trust_source = Some(trust);
            let files = vec![PAYLOAD.to_owned(), "spec.yaml".to_owned()];
            let view = View {
                report: &report,
                spec_arg: PAYLOAD,
                folder: Some(PAYLOAD),
                files: &files,
                note: Some(PAYLOAD),
                kubeconfig: Some(PAYLOAD),
                styler,
                width: 100,
            };
            assert_safe(&render(&view));
            if let Some(text) = banner(&report.signature, PAYLOAD, styler) {
                assert_safe(&text);
            }
        }
    }
}

#[test]
fn a_payload_in_the_tip_and_the_unsigned_banner_prints_as_text() {
    let mut report = based_on_ready(
        "acme-platform",
        ">=4.2",
        "0.1.0",
        vec![needs_root(PAYLOAD), needs_root("host.lsm")],
    );
    report.signature.trust_source = Some(TrustSource::User);
    report.signature.product = Some(PAYLOAD.to_owned());
    for enabled in [false, true] {
        let styler = Styler::new(enabled);
        assert_safe(&full(&report, PAYLOAD, "./f", false, styler, 100));
        report.signature = Signature::unsigned();
        assert_safe(&banner(&report.signature, PAYLOAD, styler).unwrap_or_default());
    }
}

#[test]
fn text_from_the_report_is_escaped_with_colour_off_and_on() {
    let report = hostile();
    for enabled in [false, true] {
        let styler = Styler::new(enabled);
        let out = full(
            &report,
            "a\u{1b}[2J.yaml",
            "./f\u{7}older",
            false,
            styler,
            100,
        );
        assert_safe(&out);
        for shown in [
            "evil\\x1b[2Jhost\\u{202e}.example",
            "ro\\x07ot\\u{2066}",
            "host.mem\\x1bory",
            "15\\x1b[2J GiB\\u{202e} found \\x0a",
        ] {
            // A line break in a message is a word break; the rest is escaped.
            let shown = shown.replace(" \\x0a", "");
            assert!(
                out.contains(&shown),
                "colour {enabled}: no {shown:?} in {out}"
            );
        }
        // The proxy password is gone and the proxy text is escaped.
        assert!(!out.contains("secret"), "{out}");
        assert!(out.contains("http://proxy\\x1b[0m.example:3128"), "{out}");
    }
}

#[test]
fn untrusted_text_is_never_styled() {
    let report = hostile();
    let out = full(&report, "x.yaml", "./f", false, Styler::new(true), 100);
    // The hostname sits between no codes: the byte before and after it are plain.
    let host = "evil\\x1b[2Jhost\\u{202e}.example";
    let at = out.find(host).unwrap_or_else(|| panic!("{out}"));
    assert_eq!(&out[at - 8..at], "host    ", "{out:?}");
    assert!(out[at + host.len()..].starts_with("   "), "{out:?}");
}

#[test]
fn a_product_named_rdy_never_makes_its_fix_look_like_rdys() {
    let mut report = sample("ready-with-warnings");
    report.spec.product = "rdy".to_owned();
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.contains("fix from the spec file (not verified): Free space"),
        "{out}"
    );
    assert!(!out.contains("fix from rdy:"), "{out}");
}

#[test]
fn a_product_that_is_not_a_valid_name_never_labels_a_fix() {
    let mut report = sample("not-ready");
    report.signature = {
        let mut sig = report.signature.clone();
        sig.state = rdy_spec::result::SignatureState::Verified;
        sig.trust_source = Some(TrustSource::User);
        sig
    };
    report.spec.product = "ACME Official".to_owned();
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.contains("fix from the spec file (not verified): Add RAM"),
        "{out}"
    );
    assert!(!out.contains("fix from ACME"), "{out}");
}

// ---- the source of a fix -----------------------------------------------------------------------

#[test]
fn the_source_of_a_vendor_fix_depends_on_the_pin() {
    let report = sample("ready-with-warnings");
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.contains("fix from acme-quickstart: Free space on / or mount"),
        "{out}"
    );

    let mut flagged = report.clone();
    flagged.signature.trust_source = Some(TrustSource::Flag);
    let out = plain(&flagged, "x.yaml", "./f", false);
    assert!(
        out.contains("fix from the spec file (not verified): Free space"),
        "{out}"
    );

    let mut unsigned = report.clone();
    unsigned.signature = Signature::unsigned();
    let out = plain(&unsigned, "x.yaml", "./f", false);
    assert!(
        out.contains("fix from the spec file (not verified): Free space"),
        "{out}"
    );

    // rdy's own text is rdy's whatever the signature says.
    let rdy = sample("not-ready");
    let out = plain(&rdy, "x.yaml", "./f", false);
    assert!(out.contains("fix from rdy: Run again."), "{out}");
}

#[test]
fn a_fix_with_no_source_is_not_vouched_for_and_a_not_applicable_check_shows_no_fix() {
    let mut report = sample("ready-with-warnings");
    let disk = report.checks.get_mut(2).unwrap_or_else(|| panic!("disk"));
    disk.fix_source = None;
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.contains("fix from the spec file (not verified): Free space"),
        "{out}"
    );

    let mut report = sample("ready");
    let windows = report
        .checks
        .get_mut(3)
        .unwrap_or_else(|| panic!("windows disk"));
    windows.fix = Some("Never shown".to_owned());
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(!out.contains("Never shown"), "{out}");
}

// ---- colour -------------------------------------------------------------------------------------

#[test]
fn colour_follows_the_palette_and_strips_to_the_plain_text() {
    let report = sample("not-ready");
    let coloured = full(
        &report,
        "acme-platform.yaml",
        "./f",
        false,
        Styler::new(true),
        100,
    );
    let mut stripped = Vec::new();
    crate::style::write_styled(&mut stripped, false, &coloured).unwrap_or_else(|e| panic!("{e}"));
    let stripped = String::from_utf8(stripped).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        stripped,
        full(
            &report,
            "acme-platform.yaml",
            "./f",
            false,
            Styler::new(false),
            100
        )
    );

    for (code, word) in [
        ("1;31", "BLOCK"),
        ("31", "TIMEOUT"),
        ("33", "SKIP"),
        ("33", "WARN"),
        ("32", "PASS"),
        ("1", "(required)"),
        ("1", "fix"),
        ("1;31", "WARNING: UNSIGNED SPEC"),
        (
            "31",
            "The spec decides which files rdy reads and which hosts it contacts.",
        ),
        ("1;31", "NOT READY"),
    ] {
        assert!(
            coloured.contains(&format!("\x1b[{code}m{word}\x1b[0m")),
            "no {word} in {code}: {coloured:?}"
        );
    }
    // The product label is built at run time and still styled.
    let ok = full(
        &sample("ready-with-warnings"),
        "x.yaml",
        "./f",
        false,
        Styler::new(true),
        100,
    );
    assert!(
        ok.contains("\x1b[1mfix\x1b[0m \x1b[1mfrom\x1b[0m \x1b[1macme-quickstart:\x1b[0m"),
        "{ok:?}"
    );
    assert!(
        ok.ends_with("\x1b[1;33mREADY with warnings\x1b[0m\n"),
        "{ok:?}"
    );
    let ready = full(
        &sample("ready"),
        "x.yaml",
        "./f",
        false,
        Styler::new(true),
        100,
    );
    assert!(ready.ends_with("\x1b[1;32mREADY\x1b[0m\n"), "{ready:?}");
}

#[test]
fn a_verdict_line_with_counts_is_styled_whole() {
    let report = based_on_ready(
        "acme-edge",
        ">=1.0",
        "0.1.0",
        vec![not_in_build("host.cpu")],
    );
    let out = full(&report, "x.yaml", "./f", false, Styler::new(true), 100);
    assert!(
        out.ends_with("\x1b[1;31mNOT READY: 1 required check was not run\x1b[0m\n"),
        "{out:?}"
    );
}

// ---- wrapping ------------------------------------------------------------------------------------

#[test]
fn lines_wrap_at_the_width_with_a_hanging_indent() {
    let report = sample("not-ready");
    for width in [60, 80, 100] {
        let out = full(&report, "x.yaml", "./f", false, Styler::new(false), width);
        for line in out.lines() {
            if line.starts_with("  ") && line.len() > width {
                // Only an unbroken word may pass the width, and none of these samples holds one.
                panic!("width {width}: {line:?}");
            }
        }
        // Every continuation line sits under the message column (29 spaces for 16 character keys).
        assert!(out.contains("\n                             "), "{out}");
    }
}

#[test]
fn a_word_wider_than_the_line_is_not_cut() {
    let mut report = sample("ready");
    let path = format!("/{}", "very-long-directory/".repeat(8));
    report
        .checks
        .get_mut(0)
        .unwrap_or_else(|| panic!("cpu"))
        .message = format!("No room on {path} found");
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(out.contains(&path), "{out}");
}

#[test]
fn a_key_wider_than_the_column_keeps_its_message_on_the_same_line() {
    let mut report = sample("ready");
    let long = format!("host.disk/{}", "m".repeat(35));
    let check = report.checks.get_mut(2).unwrap_or_else(|| panic!("disk"));
    check.key = long.clone();
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.contains(&format!(
            "  PASS     {long}  60.0 GiB free on /, 20 GiB needed"
        )),
        "{out}"
    );
}

#[test]
fn a_check_with_no_message_has_no_trailing_space() {
    let mut report = sample("ready");
    report
        .checks
        .get_mut(0)
        .unwrap_or_else(|| panic!("cpu"))
        .message = String::new();
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(out.lines().all(|line| line == line.trim_end()), "{out}");
}

#[test]
fn the_width_rule_clamps_to_60_and_100() {
    let env = crate::style::StyleEnv::default();
    assert_eq!(wrap_width(Some(40), &env), 60);
    assert_eq!(wrap_width(Some(250), &env), 100);
    assert_eq!(wrap_width(None, &env), 100);
}

// ---- the cluster line ---------------------------------------------------------------------------

fn cluster_of(report: &Report, kubeconfig: Option<&str>) -> Option<String> {
    let files = vec![];
    let view = View {
        report,
        spec_arg: "x.yaml",
        folder: None,
        files: &files,
        note: None,
        kubeconfig,
        styler: Styler::new(false),
        width: 100,
    };
    render(&view)
        .lines()
        .find_map(|line| line.strip_prefix("cluster ").map(str::to_owned))
}

#[test]
fn the_cluster_line_says_what_the_report_holds() {
    // The sample has a Kubernetes check and the capability says why there is no cluster.
    assert_eq!(
        cluster_of(&sample("not-ready"), None).as_deref(),
        Some("no kubeconfig found")
    );
    // No Kubernetes check and no flag: no line.
    assert_eq!(cluster_of(&sample("ready"), None), None);

    // A cluster that was reached.
    let mut report = sample("not-ready");
    let mut kube = rdy_spec::result::KubeIdentity::default();
    kube.context = Some("prod-east".to_owned());
    kube.server = Some("https://api.k8s.acme.example:6443".to_owned());
    kube.user = Some("admin".to_owned());
    kube.exec_plugin = Some("aws".to_owned());
    kube.insecure_tls = true;
    report.identity.kube = Some(kube);
    assert_eq!(
        cluster_of(&report, None).as_deref(),
        Some(
            "prod-east, https://api.k8s.acme.example:6443, user admin, credential plugin: aws, TLS verification is OFF"
        )
    );
}

#[test]
fn no_network_says_a_kubernetes_flag_is_ignored() {
    let mut report = sample("not-ready");
    report.run.options.network = false;
    assert_eq!(
        cluster_of(&report, None).as_deref(),
        Some("ignored: --no-network is set")
    );
    report.run.options.kube_context = Some("prod".to_owned());
    assert_eq!(
        cluster_of(&report, None).as_deref(),
        Some("ignored: --no-network is set (--kube-context prod was given)")
    );
    assert_eq!(
        cluster_of(&report, Some("/k/config")).as_deref(),
        Some(
            "ignored: --no-network is set (--kube-context prod and --kubeconfig /k/config were given)"
        )
    );
    report.run.options.kube_context = None;
    assert_eq!(
        cluster_of(&report, Some("/k/config")).as_deref(),
        Some("ignored: --no-network is set (--kubeconfig /k/config was given)")
    );

    // A spec with no Kubernetes check and no flag has no line even with --no-network.
    let mut quiet = sample("ready");
    quiet.run.options.network = false;
    assert_eq!(cluster_of(&quiet, None), None);
    // A flag with no Kubernetes check still gets its line: the help promises it.
    assert_eq!(
        cluster_of(&quiet, Some("/k/config")).as_deref(),
        Some("ignored: --no-network is set (--kubeconfig /k/config was given)")
    );
}

// ---- the Tip ------------------------------------------------------------------------------------

fn needs_root(id: &str) -> CheckResult {
    let mut check = CheckResult::skipped(id, "host", Severity::Block, SkipKind::MissingNeed);
    check.message = "Not run. This check needs root.".to_owned();
    check.needs = vec![NeedState::new(Need::Root, true, false)];
    check
}

fn tip_of(report: &Report) -> String {
    let out = plain(report, "x.yaml", "./f", false);
    let at = out
        .find("Tip:")
        .unwrap_or_else(|| panic!("no Tip in {out}"));
    let tail = &out[at..];
    let end = tail.find("\n\n").unwrap_or(tail.len());
    tail[..end].to_owned()
}

#[test]
fn the_root_tip_has_the_two_forms_of_c16() {
    let mut report = based_on_ready(
        "acme-platform",
        ">=4.2",
        "0.1.0",
        vec![needs_root("host.ports"), needs_root("host.lsm")],
    );
    report.signature.trust_source = Some(TrustSource::System);
    assert_eq!(
        tip_of(&report),
        "Tip: 2 checks need root: host.ports, host.lsm. Run rdy as root to include them. rdy never asks for\n     sudo."
    );
    report.signature.trust_source = Some(TrustSource::User);
    report.signature.product = Some("acme-platform".to_owned());
    assert_eq!(
        tip_of(&report),
        "Tip: 2 checks need root: host.ports, host.lsm. Run rdy as root to include them. rdy never asks for\n     sudo. As root, rdy reads only /etc/rdy/trust.yaml. First trust the vendor key for root: sudo\n     rdy trust add acme-platform --key <file>"
    );
}

#[test]
fn one_check_that_needs_root_gives_no_tip() {
    let report = based_on_ready(
        "acme-platform",
        ">=4.2",
        "0.1.0",
        vec![needs_root("host.ports"), pass("host.cpu", "ok")],
    );
    assert!(!plain(&report, "x.yaml", "./f", false).contains("Tip:"));
}

#[test]
fn the_c16_text_is_in_the_plan() {
    let doc = std::fs::read_to_string(repo().join("docs/plan/07-cli-ux.md")).unwrap_or_default();
    for line in [
        "Tip: 2 checks need root: host.ports, host.lsm. Run rdy as root to include them. rdy never asks for",
        "     sudo. As root, rdy reads only /etc/rdy/trust.yaml. First trust the vendor key for root: sudo",
        "     rdy trust add acme-platform --key <file>",
    ] {
        assert!(doc.contains(line), "07 C.16 lost {line:?}");
    }
}

// ---- small rules ---------------------------------------------------------------------------------

#[test]
fn a_serial_adds_the_revision_and_an_unknown_status_prints_as_unknown() {
    let mut report = sample("ready");
    report.spec.serial = Some(7);
    report
        .checks
        .get_mut(0)
        .unwrap_or_else(|| panic!("cpu"))
        .status = Status::Unknown("exploded".to_owned());
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.contains("spec    acme-quickstart >=1.0, revision 7   (x.yaml)"),
        "{out}"
    );
    assert!(out.contains("  UNKNOWN  host.cpu"), "{out}");
}

#[test]
fn an_unknown_bucket_sorts_and_is_marked_with_required_not_run() {
    let mut report = sample("ready");
    let cpu = report.checks.get_mut(0).unwrap_or_else(|| panic!("cpu"));
    cpu.bucket = Bucket::Unknown("future".to_owned());
    let out = plain(&report, "x.yaml", "./f", false);
    let first = out
        .lines()
        .find(|l| l.starts_with("  "))
        .unwrap_or_default();
    assert!(
        first.contains("host.cpu") && first.ends_with("(required)"),
        "{first}"
    );
}

#[test]
fn strip_userinfo_keeps_the_host_and_the_path() {
    assert_eq!(
        strip_userinfo("http://u:p@proxy.example:3128"),
        "http://proxy.example:3128"
    );
    assert_eq!(
        strip_userinfo("http://proxy.example:3128/x@y"),
        "http://proxy.example:3128/x@y"
    );
    assert_eq!(strip_userinfo("proxy.example:3128"), "proxy.example:3128");
    assert_eq!(
        strip_userinfo("u:p@proxy.example:3128"),
        "proxy.example:3128"
    );
    assert_eq!(
        strip_userinfo("u:p@proxy.example:3128/x"),
        "proxy.example:3128/x"
    );
}

#[test]
fn the_fingerprint_is_cut_to_the_first_eight_and_last_four() {
    assert_eq!(
        fingerprint_short(&format!("4d2a7c0e{}0a1c", "9".repeat(52))),
        "4d2a7c0e...0a1c"
    );
    assert_eq!(fingerprint_short("zz\u{1b}"), "zz\\x1b");
}

#[test]
fn a_state_other_than_verified_or_unsigned_gets_a_banner_and_no_trust_words() {
    let mut report = sample("ready");
    report.signature = Signature::bare(SignatureState::Unknown("odd\u{1b}".to_owned()));
    let out = plain(&report, "x.yaml", "./f", false);
    assert!(
        out.starts_with("WARNING: SIGNATURE NOT VERIFIED\n"),
        "{out}"
    );
    assert!(out.contains("sig     NOT VERIFIED (odd\\x1b)"), "{out}");
}
