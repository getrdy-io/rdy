//! The page the template shows: plain strings and lists, worked out from a [`Report`].
//!
//! The template holds markup and no logic beyond loops and `if`. Every word a reader sees that is not
//! markup is made here, so it can be tested without parsing HTML. Nothing here reads a file, the
//! environment or the clock (01 section 6).

use askama::Template;
use rdy_spec::result::{
    Bucket, BucketGroup, CheckResult, Need, NeedState, Report, SignatureState, SkipKind, Status,
    TrustSource, Verdict, group_by_bucket,
};

use crate::summary::{summary_line, verdict_line};

/// A banner at the top of the page.
pub(super) struct Banner {
    /// The first line, in capitals.
    pub title: &'static str,
    /// The lines below it.
    pub lines: Vec<Line>,
}

/// One line of a banner: pieces of our own wording and pieces that came from the report.
pub(super) struct Line {
    pub spans: Vec<Span>,
}

/// A piece of a banner line. `untrusted` text is shown in `<bdi>`, so a file name with a bidi control in
/// it cannot reorder the warning around it.
pub(super) struct Span {
    pub text: String,
    pub untrusted: bool,
}

impl Line {
    /// A line made only of our own words.
    fn text(text: &str) -> Self {
        Self {
            spans: vec![Span::own(text)],
        }
    }
}

impl Span {
    fn own(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            untrusted: false,
        }
    }

    fn untrusted(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            untrusted: true,
        }
    }
}

/// One section of checks, from one [`BucketGroup`].
pub(super) struct Section {
    /// The element id, and the target of the link in the page index.
    pub id: &'static str,
    /// The heading.
    pub title: &'static str,
    /// The words of the link in the page index.
    pub nav_title: &'static str,
    /// The checks, in spec order.
    pub checks: Vec<CheckView>,
}

/// How a check that ran in part says so.
pub(super) struct PartialView {
    /// "Checked in part. Could not read: ..."
    pub summary: String,
    /// The check's own note, which can be empty.
    pub note: String,
}

/// One check.
pub(super) struct CheckView {
    /// The position in the report, which makes the element id.
    pub index: usize,
    /// The status as a word, `BLOCK` and so on.
    pub status_word: &'static str,
    /// The class that draws the left border.
    pub status_class: &'static str,
    pub id: String,
    pub name: Option<String>,
    pub message: String,
    /// Why a check that did not run did not run.
    pub not_run_reason: Option<String>,
    pub fix: Option<String>,
    pub builtin_fix: Option<String>,
    /// `root (not available)` and so on.
    pub requires: Vec<String>,
    pub partial: Option<PartialView>,
    pub notes: Vec<String>,
    /// How long the check took. Left out for a check that did not run, where it is always zero.
    pub took_ms: Option<u64>,
}

/// A row of the capabilities table.
pub(super) struct CapabilityView {
    pub label: String,
    pub state: &'static str,
    pub detail: String,
    pub hint: String,
}

/// A label and its value in the run and spec details.
pub(super) struct Row {
    pub label: &'static str,
    pub value: String,
}

/// Everything the template prints. `templates/report.html` is compiled against these fields.
#[derive(Template)]
#[template(path = "report.html")]
pub(super) struct View {
    pub product: String,
    /// The product for the `<title>`, which cannot hold `<bdi>`: wrapped in Unicode isolates instead.
    pub title_product: String,
    pub version: Option<String>,
    pub serial: Option<u64>,
    pub hostname: String,
    pub verdict_word: String,
    pub verdict_class: &'static str,
    pub summary_line: String,
    pub run_when: String,
    pub rdy_version: String,
    pub user: Option<String>,
    pub run_as: &'static str,
    pub banners: Vec<Banner>,
    pub sections: Vec<Section>,
    pub capabilities: Vec<CapabilityView>,
    pub details: Vec<Row>,
}

impl View {
    /// Builds the page for `report`. The verdict and the counts come from the check results through the
    /// same rule as the terminal, never from the stored `verdict`; the sections come from
    /// [`group_by_bucket`], so the HTML, the terminal and the portal share one order (01 section 5.2).
    pub(super) fn new(report: &Report) -> Self {
        let judgement = rdy_spec::result::verdict(&report.checks);
        let verdict_class = match judgement.verdict {
            Verdict::Ready => "verdict-ready",
            Verdict::ReadyWithWarnings => "verdict-warnings",
            // `Verdict` is non_exhaustive. A verdict this version does not know is the worst case.
            _ => "verdict-not-ready",
        };
        Self {
            product: report.spec.product.clone(),
            title_product: format!("\u{2068}{}\u{2069}", report.spec.product),
            version: report.spec.version.clone(),
            serial: report.spec.serial,
            hostname: report.host.hostname.clone(),
            // The terminal's words: `READY`, `READY with warnings`, `NOT READY` (ADR 0003 decision 6).
            verdict_word: verdict_line(judgement.verdict, None, 0),
            verdict_class,
            summary_line: summary_line(&report.checks),
            run_when: utc_text(&report.run.started_at),
            rdy_version: report.producer.version.clone(),
            user: report.identity.user.clone(),
            run_as: if report.identity.elevated {
                "root"
            } else {
                "not root"
            },
            banners: banners(report),
            sections: group_by_bucket(&report.checks)
                .iter()
                .map(|group| section(report, group))
                .collect(),
            capabilities: report
                .capabilities
                .iter()
                .map(|cap| CapabilityView {
                    label: need_label(&cap.need, cap.name.as_deref()),
                    state: available_word(cap.available),
                    detail: cap.detail.clone().unwrap_or_default(),
                    hint: cap.hint.clone().unwrap_or_default(),
                })
                .collect(),
            details: details(report),
        }
    }
}

/// The banners, first the signature one and then the incomplete one (01 section 4.7, 07 D.7).
fn banners(report: &Report) -> Vec<Banner> {
    let mut out = Vec::new();
    let sig = &report.signature;
    let pinned = matches!(sig.state, SignatureState::Verified)
        && matches!(
            sig.trust_source,
            Some(TrustSource::System | TrustSource::User)
        );
    if !pinned {
        if matches!(sig.state, SignatureState::Verified) {
            let mut first = vec![Span::own(
                "This spec was checked with a key given on the command line",
            )];
            if let Some(fp) = &sig.key_fingerprint {
                first.push(Span::own(" (fingerprint "));
                first.push(Span::untrusted(&short_fingerprint(fp)));
                first.push(Span::own(")"));
            }
            first.push(Span::own("."));
            out.push(Banner {
                title: "WARNING: KEY NOT PINNED",
                lines: vec![
                    Line { spans: first },
                    Line::text("rdy cannot tell whose key that is."),
                    Line::text("This report is marked KEY NOT PINNED."),
                ],
            });
        } else {
            out.push(Banner {
                title: "WARNING: UNSIGNED SPEC",
                lines: vec![
                    Line {
                        spans: vec![
                            Span::untrusted(&report.spec.file_name),
                            Span::own(
                                " has no signature. rdy cannot tell who wrote it or whether it was changed.",
                            ),
                        ],
                    },
                    Line::text("The spec decides which files rdy reads and which hosts it contacts."),
                    Line::text(
                        "Run it only if you wrote it yourself or got it from the vendor in a way you trust.",
                    ),
                    Line::text("This report is marked UNSIGNED SPEC."),
                ],
            });
        }
    }
    if !report.complete {
        out.push(Banner {
            title: "INCOMPLETE",
            lines: vec![Line::text(
                "This report is incomplete. rdy stopped before every check finished.",
            )],
        });
    }
    out
}

/// `4d2a7c0e...0a1c`: the first eight and last four characters, as the terminal banner shows it.
pub(super) fn short_fingerprint(fingerprint: &str) -> String {
    let chars: Vec<char> = fingerprint.chars().collect();
    if chars.len() <= 12 {
        return fingerprint.to_owned();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail}")
}

fn section(report: &Report, group: &BucketGroup<'_>) -> Section {
    let (id, title, nav_title) = match group.bucket {
        Bucket::Blocker => ("blocks", "Blocks", "Blocks"),
        Bucket::Warning => (
            "warnings",
            "Warnings",
            "Warnings and optional checks not run",
        ),
        Bucket::Passed => ("passed", "Passed", "Passed"),
        Bucket::NotApplicable => (
            "not-applicable",
            "Does not apply here",
            "Does not apply here",
        ),
        // `group_by_bucket` labels a bucket this version does not know as `required_not_run`.
        _ => (
            "required-not-run",
            "Required checks not run",
            "Required checks not run",
        ),
    };
    Section {
        id,
        title,
        nav_title,
        checks: group
            .checks
            .iter()
            .map(|check| check_view(report, check))
            .collect(),
    }
}

fn check_view(report: &Report, check: &CheckResult) -> CheckView {
    let (status_word, status_class) = match check.status {
        Status::Pass => ("PASS", "status-pass"),
        Status::Warn => ("WARN", "status-warn"),
        Status::Block => ("BLOCK", "status-block"),
        Status::Timeout => ("TIMEOUT", "status-timeout"),
        Status::Error => ("ERROR", "status-error"),
        Status::Skipped => ("SKIP", "status-skip"),
        // An unknown status counts as not run (01 section 3.2).
        _ => ("NOT RUN", "status-skip"),
    };
    CheckView {
        index: index_of(report, check),
        status_word,
        status_class,
        id: check.id.clone(),
        name: check.name.clone(),
        message: check.message.clone(),
        not_run_reason: not_run_reason(check),
        fix: check.fix.clone(),
        builtin_fix: check.builtin_fix.clone(),
        requires: check
            .needs
            .iter()
            .map(|need| {
                format!(
                    "{} ({})",
                    need_label(&need.need, need.name.as_deref()),
                    available_word(need.met)
                )
            })
            .collect(),
        partial: check.partial.as_ref().map(|partial| {
            let mut missing: Vec<String> = partial
                .missing
                .iter()
                .map(|need| need_label(need, None))
                .collect();
            missing.extend(partial.missing_grants.iter().cloned());
            let summary = if missing.is_empty() {
                "Checked in part. The result may be incomplete.".to_owned()
            } else {
                format!(
                    "Checked in part. Could not read: {}. The result may be incomplete.",
                    missing.join(", ")
                )
            };
            PartialView {
                summary,
                note: partial.note.clone(),
            }
        }),
        notes: check.notes.clone(),
        took_ms: (!matches!(check.status, Status::Skipped)).then_some(check.duration_ms),
    }
}

/// The position of `check` in the report. The sections borrow from `report.checks`, so the pointer
/// identifies the entry even when two checks look alike.
fn index_of(report: &Report, check: &CheckResult) -> usize {
    report
        .checks
        .iter()
        .position(|candidate| std::ptr::eq(candidate, check))
        .unwrap_or(0)
}

/// Why a check that did not run did not run, in the words of 01 section 6.
pub(super) fn not_run_reason(check: &CheckResult) -> Option<String> {
    match check.status {
        Status::Skipped => Some(skip_text(check)),
        Status::Timeout => Some(match check.timeout_after_ms {
            Some(ms) => format!("Stopped after {ms} ms."),
            None => "Run time limit reached.".to_owned(),
        }),
        _ => None,
    }
}

fn skip_text(check: &CheckResult) -> String {
    match &check.skip_kind {
        Some(SkipKind::MissingNeed) => {
            let missing: Vec<String> = check
                .needs
                .iter()
                .filter(|need: &&NeedState| !need.met)
                .map(|need| need_label(&need.need, need.name.as_deref()))
                .collect();
            if missing.is_empty() {
                "Missing something this check needs.".to_owned()
            } else {
                format!("Missing: {}", missing.join(", "))
            }
        }
        Some(SkipKind::NotInBuild | SkipKind::UnknownCheck) => {
            "Not in this version of rdy".to_owned()
        }
        Some(SkipKind::UnsupportedSpec) => "rdy cannot read this check".to_owned(),
        Some(SkipKind::NotYetOnOs) => "Not available on this OS yet".to_owned(),
        Some(SkipKind::NotApplicable) => "Does not apply here".to_owned(),
        Some(SkipKind::RunDeadline) => "Run time limit reached".to_owned(),
        Some(SkipKind::Cancelled) => "Run was interrupted".to_owned(),
        // A kind this version does not know, or none at all.
        _ => "rdy did not run this check".to_owned(),
    }
}

/// What a need is called on the page.
pub(super) fn need_label(need: &Need, name: Option<&str>) -> String {
    let with_name = |what: &str| match name {
        Some(name) => format!("{what} {name}"),
        None => what.to_owned(),
    };
    match need {
        Need::Root => "root".to_owned(),
        Need::KubeContext => "a Kubernetes context".to_owned(),
        Need::Network => "network access".to_owned(),
        Need::Command => with_name("the command"),
        Need::CloudCredentials => with_name("cloud credentials for"),
        // A need this version does not know is shown as written.
        other => with_name(other.as_str()),
    }
}

fn available_word(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "not available"
    }
}

/// `2027-03-09T14:30:05.000Z` as `2027-03-09 14:30:05 UTC`. Anything that is not that shape is shown as
/// written, so a report from another producer still reads.
pub(super) fn utc_text(timestamp: &str) -> String {
    let bytes = timestamp.as_bytes();
    let shaped = timestamp.is_ascii()
        && bytes.len() >= 20
        && timestamp.ends_with('Z')
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':';
    if shaped {
        format!("{} {} UTC", &timestamp[..10], &timestamp[11..19])
    } else {
        timestamp.to_owned()
    }
}

/// The run and spec details of 01 section 6 item 6: what ran, which spec, who signed it, which machine,
/// which identity and which proxy. A row with no value is left out.
fn details(report: &Report) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut add = |label: &'static str, value: Option<String>| {
        if let Some(value) = value {
            rows.push(Row { label, value });
        }
    };
    let run = &report.run;
    add("Run id", Some(run.id.clone()));
    add("Started", Some(utc_text(&run.started_at)));
    add("Finished", Some(utc_text(&run.finished_at)));
    add("Run time", Some(format!("{} ms", run.duration_ms)));
    add(
        "rdy",
        Some(format!(
            "{} for {}",
            report.producer.version, report.producer.target
        )),
    );
    add("Parallel checks", Some(run.options.jobs.to_string()));
    add(
        "Run time limit",
        Some(format!("{} ms", run.options.deadline_ms)),
    );
    add(
        "Network checks",
        Some(
            if run.options.network {
                "allowed"
            } else {
                "off"
            }
            .to_owned(),
        ),
    );

    let spec = &report.spec;
    add("Spec file", Some(spec.file_name.clone()));
    add("Spec SHA-256", Some(spec.sha256.clone()));
    add("Spec revision", spec.serial.map(|n| n.to_string()));
    add("Spec expires", spec.expires.clone());
    add("Spec contact", spec.contact.clone());

    let sig = &report.signature;
    add(
        "Signature",
        Some(
            match sig.state {
                SignatureState::Verified => "Verified",
                SignatureState::Unsigned => "Not signed",
                _ => "Not verified",
            }
            .to_owned(),
        ),
    );
    add("Signing key", sig.key_id.clone());
    add("Fingerprint", sig.key_fingerprint.clone());
    add(
        "Key source",
        sig.trust_source.as_ref().map(|source| {
            match source {
                TrustSource::System => "System trust file",
                TrustSource::User => "Your trust file",
                _ => "Given for this run only, not pinned",
            }
            .to_owned()
        }),
    );
    add("Your note about this key", sig.trust_note.clone());
    add("Signed on", sig.signed_at.as_deref().map(utc_text));

    let host = &report.host;
    add("Hostname", Some(host.hostname.clone()));
    add(
        "Machine ID (hashed, differs per vendor)",
        host.host_id.clone(),
    );
    add(
        "Operating system",
        Some(
            host.os
                .pretty_name
                .clone()
                .unwrap_or_else(|| host.os.family.as_str().to_owned()),
        ),
    );
    add("Kernel", host.kernel.clone());
    add("Architecture", Some(host.arch.clone()));

    let identity = &report.identity;
    add("User", identity.user.clone());
    add(
        "Running as",
        Some(
            if identity.elevated {
                "root"
            } else {
                "not root"
            }
            .to_owned(),
        ),
    );
    if let Some(kube) = &identity.kube {
        add("Kubernetes context", kube.context.clone());
        add("Kubernetes server", kube.server.clone());
        add("Kubernetes user", kube.user.clone());
        add(
            "Kubernetes user confirmed by the cluster",
            Some(if kube.user_verified { "yes" } else { "no" }.to_owned()),
        );
        add("Credential plugin", kube.exec_plugin.clone());
        add(
            "TLS certificate checks",
            Some(if kube.insecure_tls { "skipped" } else { "on" }.to_owned()),
        );
    }
    if let Some(proxy) = &report.proxy {
        add("HTTPS proxy", proxy.https.clone());
        add("HTTP proxy", proxy.http.clone());
        if !proxy.no_proxy.is_empty() {
            add("No proxy for", Some(proxy.no_proxy.join(", ")));
        }
    }
    rows
}
