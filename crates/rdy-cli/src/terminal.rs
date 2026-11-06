//! The human output of `rdy run` (07 sections 2 and 6, M1-086).
//!
//! [`render`] turns a [`Report`] and a few facts of the run into the text on stderr, and [`banner`]
//! makes the warning that comes before any check. Both are pure: they read their arguments and return a
//! `String`, so the goldens run them on the report fixtures without a machine. The caller writes the
//! text with [`crate::style::write_styled`].
//!
//! **Layout** (07 section 2.1), one blank line between blocks: the header (`rdy <version>` and the
//! labelled lines), the check list, a `Tip:` when two or more checks need root, the summary line,
//! `Report written to <folder>/` with the files under it, the first line of the banner again, and the
//! verdict. The banner itself is printed earlier by [`banner`], before the first check, and the caller
//! puts one blank line after it.
//!
//! **The check list** is sorted with [`group_by_bucket`], which reads the stored bucket and never
//! recomputes it. Each entry is `  <STATUS> <key> <message>`, and a check with a fix has `fix from
//! <source>: <fix>` on the lines below, under the message. Lines wrap at word boundaries to `width`
//! with a hanging indent. A word wider than the line is not cut, so a path stays copyable.
//!
//! **Untrusted text.** Everything that comes from the report (host and user names, the spec's
//! product and file name, messages, fixes, keys) goes through [`untrusted`], so a control character
//! or a bidirectional control prints as `\x1b` or `\u{202e}` (threat model T4). That text is also
//! never styled. The report is already redacted; this module only escapes.
//!
//! **The source of a fix** (07 section 2.2). `rdy` for rdy's own text. For the vendor's text, the
//! product name when the signature is verified and the key is pinned (`trust_source` is `system` or
//! `user`), and `the spec file (not verified)` otherwise.
//!
//! **The cluster line** prints what the report holds: the kubeconfig identity when a cluster was
//! reached, `ignored: --no-network is set` when the flag is on and the spec has Kubernetes checks or a
//! Kubernetes flag was given, and the `kube_context` capability's detail when it is unavailable. The
//! probe that fills `identity.kube` and the capability is M1-107, so until then a run with a Kubernetes
//! check and network shows no cluster line.

use std::fmt::Write as _;

use rdy_engine::summary::summary_line;
use rdy_spec::result::{
    Bucket, CheckResult, FixSource, Need, Report, Signature, SignatureState, SkipKind, Status,
    TrustSource, Verdict, group_by_bucket, verdict,
};

use crate::style::{Built, Role, Styler, display_width, pad_end, untrusted};

#[cfg(test)]
mod tests;

/// The width of a header label. `cluster` is the longest.
const LABEL_WIDTH: usize = 7;
/// The width of the status column: `TIMEOUT` is the longest word.
const STATUS_WIDTH: usize = 7;
/// The widest key column. A longer key is printed whole and its message starts after it.
const MAX_KEY_COLUMN: usize = 40;
/// The words that name the source of a vendor fix that rdy cannot vouch for.
const UNVERIFIED_SOURCE: [&str; 5] = ["the", "spec", "file", "(not", "verified):"];

/// What [`render`] needs besides the report.
#[derive(Debug, Clone)]
pub struct View<'a> {
    /// The report of the run, already redacted.
    pub report: &'a Report,
    /// The spec path as the user typed it.
    pub spec_arg: &'a str,
    /// The report folder as it is shown, without the closing separator. `None` for `--no-report`.
    pub folder: Option<&'a str>,
    /// The file names in the folder, in the order they are listed.
    pub files: &'a [String],
    /// A line printed under the file list, such as the access rule note of macOS. Not for a verdict.
    pub note: Option<&'a str>,
    /// The `--kubeconfig` value, when one was given.
    pub kubeconfig: Option<&'a str>,
    /// The colour decision.
    pub styler: Styler,
    /// The line width, 60 to 100 ([`crate::style::wrap_width`]).
    pub width: usize,
}

/// One piece of a wrapped line: text of the machine, a word of rdy's, or run-time text of rdy's.
enum Piece {
    /// Escaped text of the machine or the spec. Never styled.
    Plain(String),
    /// A word written in rdy's source, styled with a role.
    Fixed(Role, &'static str),
    /// Run-time text built by rdy, styled with a role.
    Made(Role, Built),
}

impl Piece {
    fn width(&self) -> usize {
        match self {
            Piece::Plain(text) => display_width(text),
            Piece::Fixed(_, text) => display_width(text),
            Piece::Made(_, text) => display_width(text.as_str()),
        }
    }

    fn paint(&self, styler: Styler) -> String {
        match self {
            Piece::Plain(text) => text.clone(),
            Piece::Fixed(role, text) => styler.paint(*role, text),
            Piece::Made(role, text) => styler.paint_built(*role, text),
        }
    }
}

/// The words of `text`, split at spaces, tabs and line breaks, each escaped. A line break in a fix
/// that the vendor wrote as a block is a word break here, and any other control character is escaped.
fn words(text: &str) -> Vec<Piece> {
    text.split([' ', '\t', '\n', '\r'])
        .filter(|word| !word.is_empty())
        .map(|word| Piece::Plain(untrusted(word)))
        .collect()
}

/// Lays `pieces` out from column `start`, one space between pieces, breaking before a piece that would
/// pass `width` and continuing at column `hang`. The first line gets no indent: the caller has already
/// written what comes before `start`.
fn wrap(pieces: &[Piece], start: usize, hang: usize, width: usize, styler: Styler) -> String {
    let mut out = String::new();
    let mut column = start;
    let mut first_on_line = true;
    for piece in pieces {
        let w = piece.width();
        if !first_on_line && column + 1 + w > width {
            out.push('\n');
            out.push_str(&" ".repeat(hang));
            column = hang;
            first_on_line = true;
        }
        if !first_on_line {
            out.push(' ');
            column += 1;
        }
        out.push_str(&piece.paint(styler));
        column += w;
        first_on_line = false;
    }
    out
}

/// The banner, or `None` when the signature is verified by a pinned key (01 section 4.7).
///
/// The text is the five lines of the plan, each ending in a newline, red when colour is on. It is
/// printed on stderr before any check; the caller adds a blank line after it. The same title is
/// printed again by [`render`] above the verdict.
#[must_use]
pub fn banner(signature: &Signature, spec_arg: &str, styler: Styler) -> Option<String> {
    let title = banner_title(signature)?;
    let file = untrusted(spec_arg);
    let mut out = String::new();
    let line = |out: &mut String, text: &'static str| {
        out.push_str(&styler.paint(Role::Banner, text));
        out.push('\n');
    };
    let _ = writeln!(out, "{}", styler.paint(Role::BannerTitle, title));
    match title {
        UNSIGNED => {
            let _ = writeln!(
                out,
                "{file}{}",
                styler.paint(
                    Role::Banner,
                    " has no signature. rdy cannot tell who wrote it or whether it was changed."
                )
            );
            line(
                &mut out,
                "The spec decides which files rdy reads and which hosts it contacts.",
            );
            line(
                &mut out,
                "Run it only if you wrote it yourself or got it from the vendor in a way you trust.",
            );
            line(
                &mut out,
                "Every report from this run is marked UNSIGNED SPEC.",
            );
        }
        PINNED => {
            let print = signature
                .key_fingerprint
                .as_deref()
                .map(fingerprint_short)
                .map(|short| format!(" (fingerprint {short})"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "{}{}{}",
                styler.paint(
                    Role::Banner,
                    "This spec was checked with a key given on the command line"
                ),
                // The fingerprint is text of the report. It is escaped and not styled.
                untrusted(&print),
                styler.paint(Role::Banner, ".")
            );
            line(&mut out, "rdy cannot tell whose key that is.");
            line(
                &mut out,
                "Every report from this run is marked KEY NOT PINNED.",
            );
        }
        _ => {
            let _ = writeln!(
                out,
                "{file}{}",
                styler.paint(
                    Role::Banner,
                    " has a signature that rdy could not verify. Do not trust this run."
                )
            );
        }
    }
    Some(out)
}

const UNSIGNED: &str = "WARNING: UNSIGNED SPEC";
const PINNED: &str = "WARNING: KEY NOT PINNED";
const UNVERIFIED: &str = "WARNING: SIGNATURE NOT VERIFIED";

/// The first line of the banner for this signature, or `None` when there is no banner.
fn banner_title(signature: &Signature) -> Option<&'static str> {
    match (&signature.state, &signature.trust_source) {
        (SignatureState::Verified, Some(TrustSource::System | TrustSource::User)) => None,
        (SignatureState::Verified, _) => Some(PINNED),
        (SignatureState::Unsigned, _) => Some(UNSIGNED),
        _ => Some(UNVERIFIED),
    }
}

/// `4d2a7c0e...0a1c`: the first eight and the last four digits of a fingerprint. A value that is not a
/// hex string of at least twelve digits is shown whole, escaped.
fn fingerprint_short(fingerprint: &str) -> String {
    let hex = fingerprint.len() >= 12 && fingerprint.chars().all(|c| c.is_ascii_hexdigit());
    if hex {
        let head = fingerprint.get(..8).unwrap_or(fingerprint);
        let tail = fingerprint.get(fingerprint.len() - 4..).unwrap_or("");
        format!("{head}...{tail}")
    } else {
        untrusted(fingerprint)
    }
}

/// The text of a run, from the `rdy <version>` line to the verdict.
///
/// It does not hold the banner; [`banner`] is printed first. The last line is the verdict and nothing
/// follows it.
#[must_use]
pub fn render(view: &View<'_>) -> String {
    let report = view.report;
    let styler = view.styler;
    let mut blocks: Vec<String> = vec![header(view)];
    let list = check_list(view);
    if !list.is_empty() {
        blocks.push(list);
    }
    if let Some(tip) = root_tip(view) {
        blocks.push(tip);
    }
    blocks.push(format!("{}\n", summary_line(&report.checks)));

    // The closing group has no blank line inside it: the folder and its files, the banner title again,
    // and the verdict.
    let mut closing = String::new();
    if let Some(folder) = view.folder {
        let folder = untrusted(folder);
        let separator = if folder.contains('\\') && !folder.contains('/') {
            '\\'
        } else {
            '/'
        };
        let _ = writeln!(closing, "Report written to {folder}{separator}");
        for file in view.files {
            let _ = writeln!(closing, "  {}", untrusted(file));
        }
        if let Some(note) = view.note {
            let _ = writeln!(closing, "{}", untrusted(note));
        }
    }
    if let Some(title) = banner_title(&report.signature) {
        let _ = writeln!(closing, "{}", styler.paint(Role::BannerTitle, title));
    }
    let _ = writeln!(closing, "{}", verdict_line(report, styler));
    blocks.push(closing);
    blocks.join("\n")
}

/// The verdict line, styled by the verdict.
fn verdict_line(report: &Report, styler: Styler) -> String {
    let role = match verdict(&report.checks).verdict {
        Verdict::Ready => Role::VerdictReady,
        Verdict::ReadyWithWarnings => Role::VerdictWarnings,
        _ => Role::VerdictNotReady,
    };
    styler.paint_built(role, &Built::verdict(&report.checks))
}

/// `rdy <version>` and the labelled lines (07 section 2.1).
fn header(view: &View<'_>) -> String {
    let report = view.report;
    let mut out = String::new();
    let _ = writeln!(out, "rdy {}", untrusted(&report.producer.version));
    let mut row = |label: &str, value: &str| {
        let _ = writeln!(out, "{} {value}", pad_end(label, LABEL_WIDTH));
    };
    row("spec", &spec_value(view));
    row("sig", &sig_value(&report.signature));
    row("host", &host_value(report));
    row("user", &user_value(report));
    if let Some(proxy) = proxy_value(report) {
        row("proxy", &proxy);
    }
    if let Some(cluster) = cluster_value(view) {
        row("cluster", &cluster);
    }
    out
}

fn spec_value(view: &View<'_>) -> String {
    let spec = &view.report.spec;
    let mut out = untrusted(&spec.product);
    if let Some(version) = &spec.version {
        let _ = write!(out, " {}", untrusted(version));
    }
    if let Some(serial) = spec.serial {
        let _ = write!(out, ", revision {serial}");
    }
    let _ = write!(out, "   ({})", untrusted(view.spec_arg));
    out
}

fn sig_value(signature: &Signature) -> String {
    match (&signature.state, &signature.trust_source) {
        (SignatureState::Verified, source) => {
            let mut parts = vec!["verified".to_owned()];
            if let Some(id) = &signature.key_id {
                parts.push(format!("key {}", untrusted(id)));
            }
            parts.push(
                match source {
                    Some(TrustSource::User) => "trusted by you",
                    Some(TrustSource::System) => "trusted on this machine",
                    _ => "key given with --key, not pinned",
                }
                .to_owned(),
            );
            if let Some(signed) = &signature.signed_at {
                // The date part of the timestamp. Anything shorter is shown whole.
                let date = signed.get(..10).unwrap_or(signed);
                parts.push(format!("signed {}", untrusted(date)));
            }
            parts.join(", ")
        }
        (SignatureState::Unsigned, _) => "UNSIGNED (allowed by --allow-unsigned)".to_owned(),
        (other, _) => format!("NOT VERIFIED ({})", untrusted(other.as_str())),
    }
}

fn host_value(report: &Report) -> String {
    let host = &report.host;
    let os = host
        .os
        .id
        .clone()
        .unwrap_or_else(|| host.os.family.as_str().to_owned());
    let os = match &host.os.version {
        Some(version) => format!("{os} {version}"),
        None => os,
    };
    format!(
        "{}   {}   {}",
        untrusted(&host.hostname),
        untrusted(&os),
        untrusted(&host.arch)
    )
}

fn user_value(report: &Report) -> String {
    let identity = &report.identity;
    let name = match (&identity.user, identity.euid) {
        (Some(user), _) => untrusted(user),
        (None, Some(euid)) => format!("uid {euid}"),
        (None, None) => "unknown".to_owned(),
    };
    let root = identity.elevated || identity.euid == Some(0);
    format!("{name} ({})", if root { "root" } else { "not root" })
}

/// The proxy in effect with user info stripped, or `None`.
fn proxy_value(report: &Report) -> Option<String> {
    let proxy = report.proxy.as_ref()?;
    let mut shown: Vec<String> = Vec::new();
    for value in [&proxy.https, &proxy.http].into_iter().flatten() {
        let clean = untrusted(&strip_userinfo(value));
        if !clean.is_empty() && !shown.contains(&clean) {
            shown.push(clean);
        }
    }
    (!shown.is_empty()).then(|| shown.join(", "))
}

/// `scheme://host:port` for `scheme://user:pass@host:port/path`, and `host:port` for `user:pass@host:port`.
/// The report is redacted already; this is the second guard for the one place a password can sit.
fn strip_userinfo(url: &str) -> String {
    // A schemeless `user:pass@host:3128` has the same userinfo to strip.
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    match scheme {
        Some(scheme) => format!("{scheme}://{host}{tail}"),
        None => format!("{host}{tail}"),
    }
}

/// The cluster line value. See the module text.
fn cluster_value(view: &View<'_>) -> Option<String> {
    let report = view.report;
    if let Some(kube) = &report.identity.kube {
        let mut parts: Vec<String> = Vec::new();
        if let Some(context) = &kube.context {
            parts.push(untrusted(context));
        }
        if let Some(server) = &kube.server {
            parts.push(untrusted(server));
        }
        if let Some(user) = &kube.user {
            parts.push(format!("user {}", untrusted(user)));
        }
        if let Some(plugin) = &kube.exec_plugin {
            parts.push(format!("credential plugin: {}", untrusted(plugin)));
        }
        if kube.insecure_tls {
            parts.push("TLS verification is OFF".to_owned());
        }
        if !parts.is_empty() {
            return Some(parts.join(", "));
        }
    }
    let options = &report.run.options;
    let has_k8s = report.checks.iter().any(|check| check.family == "k8s");
    let kube_flag = options.kube_context.is_some() || view.kubeconfig.is_some();
    if !options.network && (has_k8s || kube_flag) {
        let mut line = "ignored: --no-network is set".to_owned();
        match (&options.kube_context, view.kubeconfig) {
            (Some(context), Some(file)) => {
                let _ = write!(
                    line,
                    " (--kube-context {} and --kubeconfig {} were given)",
                    untrusted(context),
                    untrusted(file)
                );
            }
            (Some(context), None) => {
                let _ = write!(line, " (--kube-context {} was given)", untrusted(context));
            }
            (None, Some(file)) => {
                let _ = write!(line, " (--kubeconfig {} was given)", untrusted(file));
            }
            (None, None) => {}
        }
        return Some(line);
    }
    report
        .capabilities
        .iter()
        .find(|cap| cap.need == Need::KubeContext && !cap.available)
        .and_then(|cap| cap.detail.as_deref())
        .map(untrusted)
}

/// The status word and its role.
fn status_word(status: &Status) -> (&'static str, Role) {
    match status {
        Status::Pass => ("PASS", Role::Pass),
        Status::Warn => ("WARN", Role::Warn),
        Status::Block => ("BLOCK", Role::Block),
        Status::Skipped => ("SKIP", Role::Warn),
        Status::Timeout => ("TIMEOUT", Role::Failure),
        Status::Error => ("ERROR", Role::Failure),
        // A status this version does not know counts as not run (01 section 3.2).
        _ => ("UNKNOWN", Role::Warn),
    }
}

/// The check list, or an empty string when there are no checks.
fn check_list(view: &View<'_>) -> String {
    let groups = group_by_bucket(&view.report.checks);
    let key_widths = groups
        .iter()
        .flat_map(|group| group.checks.iter())
        .map(|check| display_width(&untrusted(&check.key)));
    let key_column = key_widths.max().unwrap_or(0).min(MAX_KEY_COLUMN);
    let mut out = String::new();
    for group in &groups {
        for check in &group.checks {
            entry(view, check, &group.bucket, key_column, &mut out);
        }
    }
    out
}

/// One entry of the list: the status line and, when there is a fix, the fix line.
fn entry(
    view: &View<'_>,
    check: &CheckResult,
    bucket: &Bucket,
    key_column: usize,
    out: &mut String,
) {
    let styler = view.styler;
    let (word, role) = status_word(&check.status);
    let key = untrusted(&check.key);
    let message_column = 2 + STATUS_WIDTH + 2 + key_column + 2;
    let mut message = words(&check.message);
    if *bucket == Bucket::RequiredNotRun {
        message.push(Piece::Fixed(Role::Label, "(required)"));
    }
    let _ = write!(
        out,
        "  {}{}  ",
        styler.paint(role, word),
        " ".repeat(STATUS_WIDTH.saturating_sub(word.len()))
    );
    if message.is_empty() {
        out.push_str(key.trim_end());
        out.push('\n');
    } else {
        let _ = write!(out, "{}  ", pad_end(&key, key_column));
        let start = message_column.max(2 + STATUS_WIDTH + 2 + display_width(&key) + 2);
        out.push_str(&wrap(&message, start, message_column, view.width, styler));
        out.push('\n');
    }
    if let Some(fix) = fix_pieces(view, check, bucket) {
        out.push_str(&" ".repeat(message_column));
        out.push_str(&wrap(
            &fix,
            message_column,
            message_column,
            view.width,
            styler,
        ));
        out.push('\n');
    }
}

/// `fix from <source>: <fix>` as pieces, or `None` when the check has no fix to show. A check that does
/// not apply gets none (07 section 2.2).
fn fix_pieces(view: &View<'_>, check: &CheckResult, bucket: &Bucket) -> Option<Vec<Piece>> {
    let fix = check.fix.as_deref().filter(|fix| !fix.trim().is_empty())?;
    if *bucket == Bucket::NotApplicable || check.skip_kind == Some(SkipKind::NotApplicable) {
        return None;
    }
    let unverified = || {
        UNVERIFIED_SOURCE
            .iter()
            .map(|word| Piece::Fixed(Role::Label, word))
            .collect::<Vec<_>>()
    };
    let source = match check.fix_source {
        Some(FixSource::Rdy) => vec![Piece::Fixed(Role::Label, "rdy:")],
        Some(FixSource::FromSpec) if pinned(&view.report.signature) => {
            match Built::product("", &view.report.spec.product, ":") {
                Some(name) => vec![Piece::Made(Role::Label, name)],
                None => unverified(),
            }
        }
        _ => unverified(),
    };
    let mut pieces = vec![
        Piece::Fixed(Role::Label, "fix"),
        Piece::Fixed(Role::Label, "from"),
    ];
    pieces.extend(source);
    pieces.extend(words(fix));
    Some(pieces)
}

/// True when the signature is verified and the key is pinned in a trust store.
fn pinned(signature: &Signature) -> bool {
    signature.state == SignatureState::Verified
        && matches!(
            signature.trust_source,
            Some(TrustSource::System | TrustSource::User)
        )
}

/// The root Tip (07 section 2.1, C.16), or `None` when fewer than two checks were skipped for root.
fn root_tip(view: &View<'_>) -> Option<String> {
    let needing: Vec<&CheckResult> = view
        .report
        .checks
        .iter()
        .filter(|check| {
            check.skip_kind == Some(SkipKind::MissingNeed)
                && check
                    .needs
                    .iter()
                    .any(|need| need.need == Need::Root && !need.met)
        })
        .collect();
    if needing.len() < 2 {
        return None;
    }
    let mut pieces = vec![Piece::Fixed(Role::Label, "Tip:")];
    let lead = format!("{} checks need root:", needing.len());
    pieces.extend(words(&lead));
    for (at, check) in needing.iter().enumerate() {
        let tail = if at + 1 == needing.len() { "." } else { "," };
        pieces.push(Piece::Plain(format!("{}{tail}", untrusted(&check.key))));
    }
    pieces.extend(words(
        "Run rdy as root to include them. rdy never asks for sudo.",
    ));
    if view.report.signature.trust_source == Some(TrustSource::User) {
        pieces.extend(words(
            "As root, rdy reads only /etc/rdy/trust.yaml. First trust the vendor key for root: sudo rdy trust add",
        ));
        let product = view
            .report
            .signature
            .product
            .as_deref()
            .unwrap_or(&view.report.spec.product);
        pieces.push(Piece::Plain(untrusted(product)));
        pieces.extend(words("--key <file>"));
    }
    let mut out = wrap(&pieces, 0, 5, view.width, view.styler);
    out.push('\n');
    Some(out)
}
