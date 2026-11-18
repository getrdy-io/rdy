//! The page the template shows: plain strings and lists, worked out from a [`Report`].
//!
//! The template holds markup and no logic beyond loops and `if`. Every word a reader sees that is not
//! markup is made here, so it can be tested without parsing HTML. Nothing here reads a file, the
//! environment or the clock (01 section 6).

use askama::Template;
use rdy_spec::result::{
    Bucket, BucketGroup, CheckResult, FixSource, Need, NeedState, Report, SignatureState, SkipKind,
    Status, Summary, TrustSource, Verdict, group_by_bucket,
};

use crate::redact::RedactedReport;
use crate::report::{HtmlSafeJson, JsonError, json_bytes, read_report};
use crate::summary::{summary_line, verdict_line};

/// What the three status words mean (01 section 6 item 2, 07 D.7). 07 D.7 requires the same sentences
/// in `rdy run --help`; not yet.
pub(super) const LEGEND: &str =
    "BLOCK: fix before install. WARN: fix if you can. SKIP: rdy could not check it.";

/// How the verdict is decided, in plain words (01 section 6 item 2, 07 D.7).
pub(super) const RULE: &str = "NOT READY if anything blocks or a required check could not run. READY with warnings if only optional things are wrong. READY if every check ran and passed.";

/// The sentence after "What to do next" that is the same for every verdict (07 D.7).
pub(super) const SHARE: &str = "To share this result, send the .json file from the same folder.";

/// What to do next, by verdict (07 D.7). Fixed product text, so it is not shown in `<bdi>`.
fn next_step(
    verdict: Verdict,
    reason: Option<&rdy_spec::result::VerdictReason>,
    summary: &Summary,
) -> String {
    use rdy_spec::result::VerdictReason;
    match (verdict, reason) {
        (Verdict::Ready, _) => "Everything the spec asks for passed.".to_owned(),
        (Verdict::ReadyWithWarnings, Some(VerdictReason::NothingVerified)) => "rdy checked nothing on this machine. Every check in the spec is for another OS. Ask the vendor if that is expected.".to_owned(),
        (Verdict::ReadyWithWarnings, _) => "Nothing blocks the install. Read the warnings.".to_owned(),
        _ if summary.block > 0 => format!(
            "Fix the {} {} below, then run rdy again.",
            summary.block,
            if summary.block == 1 { "block" } else { "blocks" }
        ),
        _ => format!(
            "rdy could not check {} required {}. Follow the fix for each, then run rdy again.",
            summary.required_not_run,
            if summary.required_not_run == 1 { "item" } else { "items" }
        ),
    }
}

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

/// A piece of a line. `untrusted` text is shown in `<bdi>`, which limits how far a bidi control in it can
/// reorder the words around it. A U+2069 inside the text can still close the isolate early, so the text is
/// made with [`shown`], which writes every format character as an escape (M1-141, SEC-149-11). Our own
/// words stay outside the `<bdi>`.
#[derive(Clone)]
pub(super) struct Span {
    pub text: String,
    pub untrusted: bool,
}

/// The text of `spans` with the pieces joined, as a reader without markup would see it.
pub(super) fn plain(spans: &[Span]) -> String {
    spans.iter().map(|span| span.text.as_str()).collect()
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
            text: shown(text).as_str().to_owned(),
            untrusted: true,
        }
    }
}

mod actions;
mod facts;
mod shown;

pub(super) use shown::{Shown, shown};

use actions::ActionLog;
use facts::{Fact, facts};

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
    /// "Checked in part. Could not read: ...", with the names that came from the report marked.
    pub summary: Vec<Span>,
    /// The check's own note, which can be empty.
    pub note: Shown,
}

/// A fix and who it is from.
pub(super) struct FixView {
    /// "From acme-platform", "From the spec file (not verified)" or "From rdy". The product is untrusted.
    pub label: Vec<Span>,
    pub text: Shown,
}

/// One check.
pub(super) struct CheckView {
    /// The position in the report, which makes the element id.
    pub index: usize,
    /// The status as a word, `BLOCK` and so on.
    pub status_word: &'static str,
    /// The class that draws the left border.
    pub status_class: &'static str,
    pub id: Shown,
    pub name: Option<Shown>,
    pub message: Shown,
    /// Why a check that did not run did not run.
    pub not_run_reason: Option<Vec<Span>>,
    /// "required by acme-platform", or "required by the spec file" when the signature is not verified
    /// by a pinned key, on a required check that did not run (01 section 6, 07 D.7).
    pub required_by: Option<Vec<Span>>,
    pub fix: Option<FixView>,
    pub builtin_fix: Option<Shown>,
    /// What the check saw (`observed`), as labels and plain values.
    pub found: Vec<Fact>,
    /// What the check wanted (`expected`).
    pub needed: Vec<Fact>,
    /// Fact lines the page size cap left out of this check (07 D.4). The embedded JSON has them.
    pub facts_more: usize,
    /// `root (not available)` and so on, one list of spans per need.
    pub requires: Vec<Vec<Span>>,
    pub partial: Option<PartialView>,
    pub notes: Vec<Shown>,
    /// How long the check took. Left out for a check that did not run, where it is always zero.
    pub took_ms: Option<u64>,
}

/// A row of the capabilities table.
pub(super) struct CapabilityView {
    pub label: Shown,
    pub state: &'static str,
    pub detail: Shown,
    pub hint: Shown,
}

/// A label and its value in the run and spec details.
pub(super) struct Row {
    pub label: &'static str,
    pub value: Shown,
}

/// Everything the template prints. `templates/report.html` is compiled against these fields.
#[derive(Template)]
#[template(path = "report.html")]
pub(super) struct View {
    pub product: Shown,
    /// The product for the `<title>`, which cannot hold `<bdi>`: the escaped product between one U+2068
    /// and one U+2069 of ours. It is a `String` because those two are the only format characters the page
    /// writes raw, and `shown` would escape them. It is built from a `Shown` only.
    pub title_product: String,
    pub version: Option<Shown>,
    pub serial: Option<u64>,
    pub hostname: Shown,
    pub verdict_word: String,
    pub verdict_class: &'static str,
    pub summary_line: String,
    /// True when no check has status block: the header then says "No blocks." (07 D.7).
    pub no_blocks: bool,
    /// "What to do next" for this verdict (07 D.7).
    pub next_step: String,
    pub share: &'static str,
    /// The spec's `metadata.contact`, shown as plain text, never a link.
    pub contact: Option<String>,
    pub legend: &'static str,
    pub rule: &'static str,
    pub run_when: Shown,
    pub rdy_version: Shown,
    pub user: Option<Shown>,
    pub run_as: &'static str,
    pub banners: Vec<Banner>,
    /// Our own banner titles joined, which print in the top margin of every page, or `None` with no
    /// banner. Only fixed words: never text from the report.
    pub print_mark: Option<String>,
    /// `https://getrdy.io/?ref=report&product=<product>`: the only link out, with the product encoded.
    pub product_link: String,
    pub sections: Vec<Section>,
    pub capabilities: Vec<CapabilityView>,
    pub details: Vec<Row>,
    /// What rdy read and contacted, one table.
    pub actions: ActionLog,
    /// The JSON of the report, the same bytes as the `.json` file. The one value the template prints
    /// without escaping (M1-078).
    pub json: EmbeddedJson,
    /// The SHA-256 of `json`, in lowercase hex: the `data-sha256` attribute.
    pub json_sha256: String,
}

/// The Found and Needed lists of every check, in page order: what the size cap starts from.
pub(super) type FactLists = Vec<(Vec<Fact>, Vec<Fact>)>;

impl View {
    /// A copy of every check's Found and Needed lists.
    pub(super) fn fact_lists(&self) -> FactLists {
        self.sections
            .iter()
            .flat_map(|section| &section.checks)
            .map(|check| (check.found.clone(), check.needed.clone()))
            .collect()
    }

    /// Keeps the first `keep` fact lines of `all` (counting Found, then Needed, check by check) and
    /// counts the rest on the check as left out. This is how the page stays under its size cap when the
    /// action rows are gone and it is still over (07 D.4).
    pub(super) fn keep_fact_lines(&mut self, all: &FactLists, keep: usize) {
        let mut budget = keep;
        let checks = self
            .sections
            .iter_mut()
            .flat_map(|section| section.checks.iter_mut());
        for (check, (found, needed)) in checks.zip(all) {
            let before: usize = found.iter().chain(needed).map(|f| f.lines.len()).sum();
            check.found = take_lines(found, &mut budget);
            check.needed = take_lines(needed, &mut budget);
            let after: usize = check
                .found
                .iter()
                .chain(&check.needed)
                .map(|f| f.lines.len())
                .sum();
            check.facts_more = before - after;
        }
    }

    /// Builds the page for `report`. The verdict and the counts come from the check results through the
    /// same rule as the terminal, never from the stored `verdict`; the sections come from
    /// [`group_by_bucket`], so the HTML, the terminal and the portal share one order (01 section 5.2).
    ///
    /// # Errors
    ///
    /// The errors of [`json_bytes`]: the page carries the same JSON as the `.json` file, so a report the
    /// writer refuses cannot be rendered either.
    pub(super) fn new(redacted: &RedactedReport) -> Result<Self, JsonError> {
        let report: &Report = redacted;
        let json = json_bytes(redacted)?;
        let json_sha256 = sha256_hex(json.as_bytes());
        // The table lists what the JSON holds, not the report before the writer cut it, so "N more
        // entries are in the embedded JSON" is true even when the writer shed entries to fit its cap.
        let on_page = read_report(json.as_bytes())?;
        let json = EmbeddedJson(json);
        let judgement = rdy_spec::result::verdict(&report.checks);
        let verdict_class = match judgement.verdict {
            Verdict::Ready => "verdict-ready",
            Verdict::ReadyWithWarnings => "verdict-warnings",
            // `Verdict` is non_exhaustive. A verdict this version does not know is the worst case.
            _ => "verdict-not-ready",
        };
        let banners = banners(report);
        Ok(Self {
            product: shown(&report.spec.product),
            title_product: format!("\u{2068}{}\u{2069}", shown(&report.spec.product)),
            version: report.spec.version.as_deref().map(shown),
            serial: report.spec.serial,
            hostname: shown(&report.host.hostname),
            // The terminal's words: `READY`, `READY with warnings`, `NOT READY` (ADR 0003 decision 6).
            verdict_word: verdict_line(judgement.verdict, None, 0),
            verdict_class,
            summary_line: summary_line(&report.checks),
            no_blocks: Summary::from_checks(&report.checks).block == 0,
            next_step: next_step(
                judgement.verdict,
                judgement.reason.as_ref(),
                &Summary::from_checks(&report.checks),
            ),
            share: SHARE,
            contact: report.spec.contact.clone(),
            legend: LEGEND,
            rule: RULE,
            run_when: shown(&utc_text(&report.run.started_at)),
            rdy_version: shown(&report.producer.version),
            user: report.identity.user.as_deref().map(shown),
            run_as: if report.identity.elevated {
                "root"
            } else {
                "not root"
            },
            product_link: product_link(&report.spec.product),
            print_mark: print_mark(&banners),
            banners,
            sections: group_by_bucket(&report.checks)
                .iter()
                .map(|group| section(report, &on_page, group))
                .collect(),
            capabilities: report
                .capabilities
                .iter()
                .map(|cap| CapabilityView {
                    label: shown(&need_label(&cap.need, cap.name.as_deref())),
                    state: available_word(cap.available),
                    detail: shown(cap.detail.as_deref().unwrap_or_default()),
                    hint: shown(cap.hint.as_deref().unwrap_or_default()),
                })
                .collect(),
            details: details(report),
            actions: ActionLog::new(&on_page),
            json,
            json_sha256,
        })
    }
}

/// The first lines of `facts` that fit in `budget`, which is used up as they are taken.
fn take_lines(facts: &[Fact], budget: &mut usize) -> Vec<Fact> {
    let mut out = Vec::new();
    for fact in facts {
        let take = fact.lines.len().min(*budget);
        if take == 0 {
            break;
        }
        *budget -= take;
        out.push(Fact {
            label: fact.label.clone(),
            lines: fact.lines[..take].to_vec(),
        });
    }
    out
}

/// The embedded result, printed raw. It is the one value in the page that skips askama's escaping, and
/// the template prints it only as the text of `<script type="application/json">`. `HtmlSafeJson` has no
/// `"`-safe form, so it cannot go in an attribute; this wrapper is private to the page, so nothing else
/// can put it in one (M1-078, SEC-19-1). `scripts/check-html-escapes.sh` allows this one line. Clippy
/// cannot see a trait in an `impl` header, so the script is the guard for the marker.
pub(super) struct EmbeddedJson(HtmlSafeJson);

impl std::fmt::Display for EmbeddedJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl askama::filters::HtmlSafe for EmbeddedJson {}

/// The SHA-256 of `bytes` as 64 lowercase hex digits.
fn sha256_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.as_ref() {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// The link in the footer. It holds `ref=report` and the product, which the spec already shows, and
/// nothing else: no run id, host, version or date (ADR 0003 decision 8). The product is percent-encoded,
/// so nothing in it can add a parameter or a character the page would have to escape.
fn product_link(product: &str) -> String {
    let mut link = String::from("https://getrdy.io/?ref=report&product=");
    for byte in product.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            link.push(char::from(byte));
        } else {
            link.push_str(&format!("%{byte:02X}"));
        }
    }
    link
}

/// The words that print in the top margin of every page when the page has a banner (07 D.3). They are the
/// titles of the banners, which are fixed text of ours, so a printed page 2 still says that the spec was
/// not verified. Text from the report never goes here.
fn print_mark(banners: &[Banner]) -> Option<String> {
    (!banners.is_empty()).then(|| {
        banners
            .iter()
            .map(|banner| banner.title)
            .collect::<Vec<_>>()
            .join(" / ")
    })
}

/// The banners, first the signature one and then the incomplete one (01 section 4.7, 07 D.7).
fn banners(report: &Report) -> Vec<Banner> {
    let mut out = Vec::new();
    let sig = &report.signature;
    if !key_is_pinned(report) {
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

/// `true` when the spec's signature verified and the key is one the user or the system pinned. Only then
/// is the vendor's name on its fix text (01 section 2.6).
fn key_is_pinned(report: &Report) -> bool {
    let sig = &report.signature;
    matches!(sig.state, SignatureState::Verified)
        && matches!(
            sig.trust_source,
            Some(TrustSource::System | TrustSource::User)
        )
}

/// Who requires a check that is required and did not run. The product name is the vendor's own claim, so
/// it is named only when the signature verified and the key is pinned (01 section 2.6), like a fix.
fn required_by(report: &Report, check: &CheckResult) -> Option<Vec<Span>> {
    match check.bucket {
        Bucket::Blocker | Bucket::Warning | Bucket::Passed | Bucket::NotApplicable => None,
        // `required_not_run`, and a bucket this version does not know, which sits with it.
        _ if key_is_pinned(report) => Some(vec![
            Span::own("required by "),
            Span::untrusted(&report.spec.product),
        ]),
        _ => Some(vec![Span::own("required by the spec file")]),
    }
}

/// The fix with its label. The vendor's product name labels spec text only when the key is pinned. Every
/// other case is "the spec file (not verified)": a spec that was not verified, a `fix_source` this version
/// does not know and a fix with no `fix_source` at all (only another producer writes that). Unknown means
/// not verified (01 section 2.6), and the raw value is never shown, so a reader does not take commands
/// for the vendor's.
fn fix_view(report: &Report, check: &CheckResult) -> Option<FixView> {
    let text = shown(check.fix.as_deref()?);
    let label = match &check.fix_source {
        Some(FixSource::Rdy) => vec![Span::own("From rdy")],
        Some(FixSource::FromSpec) if key_is_pinned(report) => {
            vec![Span::own("From "), Span::untrusted(&report.spec.product)]
        }
        _ => vec![Span::own("From the spec file (not verified)")],
    };
    Some(FixView { label, text })
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

fn section(report: &Report, on_page: &Report, group: &BucketGroup<'_>) -> Section {
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
            .map(|check| check_view(report, on_page, check))
            .collect(),
    }
}

/// The check of `on_page`, the report the JSON holds, that is `check` of `report`. Found and Needed come
/// from it, never from `check`: the JSON writer cuts text, nesting and whole maps, and the page must not
/// show what the embedded JSON dropped (SEC-81).
fn on_page_check<'a>(
    on_page: &'a Report,
    index: usize,
    check: &CheckResult,
) -> Option<&'a CheckResult> {
    on_page
        .checks
        .get(index)
        .filter(|candidate| candidate.key == check.key && candidate.id == check.id)
}

fn check_view(report: &Report, on_page: &Report, check: &CheckResult) -> CheckView {
    let index = index_of(report, check);
    let in_json = on_page_check(on_page, index, check);
    // The writer keeps every check in order, so a miss is a bug. In release the lists are left out.
    debug_assert!(
        in_json.is_some(),
        "check {index} is not in the report the JSON holds"
    );
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
        index,
        status_word,
        status_class,
        id: shown(&check.id),
        name: check.name.as_deref().map(shown),
        message: shown(&check.message),
        not_run_reason: not_run_reason(check),
        required_by: required_by(report, check),
        fix: fix_view(report, check),
        builtin_fix: check.builtin_fix.as_deref().map(shown),
        found: facts(in_json.and_then(|c| c.observed.as_ref())),
        needed: facts(in_json.and_then(|c| c.expected.as_ref())),
        facts_more: 0,
        requires: check
            .needs
            .iter()
            .map(|need| {
                let mut spans = need_spans(&need.need, need.name.as_deref());
                spans.push(Span::own(&format!(" ({})", available_word(need.met))));
                spans
            })
            .collect(),
        partial: check.partial.as_ref().map(|partial| {
            let mut missing: Vec<Vec<Span>> = partial
                .missing
                .iter()
                .map(|need| need_spans(need, None))
                .collect();
            missing.extend(
                partial
                    .missing_grants
                    .iter()
                    .map(|grant| vec![Span::untrusted(grant)]),
            );
            let summary = if missing.is_empty() {
                vec![Span::own("Checked in part. The result may be incomplete.")]
            } else {
                let mut spans = vec![Span::own("Checked in part. Could not read: ")];
                spans.extend(join_spans(missing));
                spans.push(Span::own(". The result may be incomplete."));
                spans
            };
            PartialView {
                summary,
                note: shown(&partial.note),
            }
        }),
        notes: check.notes.iter().map(|note| shown(note)).collect(),
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
pub(super) fn not_run_reason(check: &CheckResult) -> Option<Vec<Span>> {
    match check.status {
        Status::Skipped => Some(skip_text(check)),
        Status::Timeout => Some(vec![Span::own(&match check.timeout_after_ms {
            Some(ms) => format!("Stopped after {ms} ms."),
            None => "Run time limit reached.".to_owned(),
        })]),
        _ => None,
    }
}

/// `lists` with ", " between them, in our own words.
fn join_spans(lists: Vec<Vec<Span>>) -> Vec<Span> {
    let mut out = Vec::new();
    for (i, list) in lists.into_iter().enumerate() {
        if i > 0 {
            out.push(Span::own(", "));
        }
        out.extend(list);
    }
    out
}

fn skip_text(check: &CheckResult) -> Vec<Span> {
    match &check.skip_kind {
        Some(SkipKind::MissingNeed) => {
            let missing: Vec<Vec<Span>> = check
                .needs
                .iter()
                .filter(|need: &&NeedState| !need.met)
                .map(|need| need_spans(&need.need, need.name.as_deref()))
                .collect();
            if missing.is_empty() {
                vec![Span::own("Missing something this check needs.")]
            } else {
                let mut spans = vec![Span::own("Missing: ")];
                spans.extend(join_spans(missing));
                spans
            }
        }
        Some(SkipKind::NotInBuild | SkipKind::UnknownCheck) => {
            vec![Span::own("Not in this version of rdy")]
        }
        Some(SkipKind::UnsupportedSpec) => vec![Span::own("rdy cannot read this check")],
        Some(SkipKind::NotYetOnOs) => vec![Span::own("Not available on this OS yet")],
        Some(SkipKind::NotApplicable) => vec![Span::own("Does not apply here")],
        Some(SkipKind::RunDeadline) => vec![Span::own("Run time limit reached")],
        Some(SkipKind::Cancelled) => vec![Span::own("Run was interrupted")],
        // A kind this version does not know, or none at all.
        _ => vec![Span::own("rdy did not run this check")],
    }
}

/// What a need is called on the page, as plain text.
pub(super) fn need_label(need: &Need, name: Option<&str>) -> String {
    plain(&need_spans(need, name))
}

/// What a need is called on the page. The name that came from the report is the untrusted piece.
pub(super) fn need_spans(need: &Need, name: Option<&str>) -> Vec<Span> {
    let with_name = |what: &str| match name {
        Some(name) => vec![Span::own(&format!("{what} ")), Span::untrusted(name)],
        None => vec![Span::own(what)],
    };
    match need {
        Need::Root => vec![Span::own("root")],
        Need::KubeContext => vec![Span::own("a Kubernetes context")],
        Need::Network => vec![Span::own("network access")],
        Need::Command => with_name("the command"),
        Need::CloudCredentials => with_name("cloud credentials for"),
        // A need this version does not know is shown as written, so it is not our word.
        other => match name {
            Some(name) => vec![
                Span::untrusted(other.as_str()),
                Span::own(" "),
                Span::untrusted(name),
            ],
            None => vec![Span::untrusted(other.as_str())],
        },
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
            rows.push(Row {
                label,
                value: shown(&value),
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/reports/not-ready-7.2.json");
        let text = std::fs::read_to_string(path).expect("the sample report is in the repo");
        serde_json::from_str(&text).expect("the sample is JSON")
    }

    /// The print rule puts `print_mark` in a CSS string. The template escapes HTML but does not escape
    /// CSS, so every banner title must be capitals, spaces and colons, and nothing else.
    #[test]
    fn every_banner_title_is_capitals_spaces_and_colons() {
        let mut titles = Vec::new();
        for (unsigned, complete) in [(true, true), (false, true), (false, false), (true, false)] {
            let mut doc = sample();
            if unsigned {
                doc["signature"] = serde_json::json!({"state": "unsigned"});
            } else {
                // Verified with a key given for one run: the not-pinned banner.
                doc["signature"]["trust_source"] = serde_json::json!("flag");
            }
            doc["complete"] = serde_json::json!(complete);
            let report: Report = serde_json::from_value(doc).expect("a report");
            titles.extend(banners(&report).iter().map(|banner| banner.title));
        }
        for expected in [
            "WARNING: UNSIGNED SPEC",
            "WARNING: KEY NOT PINNED",
            "INCOMPLETE",
        ] {
            assert!(titles.contains(&expected), "{expected} is not a title");
        }
        for title in titles {
            assert!(
                !title.is_empty()
                    && title
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c == ' ' || c == ':'),
                "{title:?} is not safe in a CSS string"
            );
        }
    }
}
