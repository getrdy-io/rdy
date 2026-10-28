//! The structs of the JSON result (01 section 5), matching `schema/result.v1.schema.json` field for field.
//!
//! Reading follows the schema's rules: fields this version does not know are ignored, and every open
//! value (see [`super::codes`]) is accepted. A field typed as a plain value without a default must be
//! present. A field typed `Option` may also be missing, which reads as `null`. So reading is a little
//! more lenient than the schema: a few fields the schema lists as required (such as `fix`, `observed`
//! and `partial` of a check) read as `null` when missing, and the schema's size caps are not checked
//! here. Writing emits fields in schema order. A field the schema allows to be `null` is written as
//! `null` when unset. A field it does not allow to be `null` is left out when unset.
//!
//! Timestamps and the run id are kept as text. This crate has no clock and no UUID generator. The
//! producer writes UTC timestamps with milliseconds and a random v4 UUID.
//!
//! Like the spec types, every struct is `#[non_exhaustive]` with public fields and a `new(..)` that takes
//! only the required fields. Outside this crate, build a value with `new` and then set the optional
//! fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::codes::{
    ActionKind, ActionOutcome, Bucket, ErrorKind, FixSource, HostOsFamily, Need, RedactionRuleset,
    Severity, SignatureState, SkipKind, Status, TrustSource, Verdict, VerdictReason,
    Virtualization,
};
use super::verdict::{classify, verdict};
use crate::API_VERSION;
#[cfg(feature = "schema")]
use crate::schema::{
    action_fields, check_result_rules, exit_code_schema, host_rules, identity_rules, report_rules,
    signature_rules,
};

/// The `kind` of a report.
pub const REPORT_KIND: &str = "Report";

fn expect_const<'de, D: Deserializer<'de>>(d: D, expected: &str) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if value == expected {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(format!(
            "expected \"{expected}\", found \"{}\"",
            crate::error::echo_safe(&value)
        )))
    }
}

fn de_api_version<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    expect_const(d, API_VERSION)
}

fn de_report_kind<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    expect_const(d, REPORT_KIND)
}

fn de_producer_name<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    expect_const(d, "rdy")
}

/// One run of `rdy run`: who ran what, where, and what came of it.
///
/// This is the document `rdy` writes as JSON and Rdy Cloud reads. `verdict`, `verdict_reason`,
/// `exit_code` and `summary` follow from `checks` through [`verdict`] and [`Summary::from_checks`].
/// [`Report::new`] fills them in, and [`Report::refresh_verdict`] fills them in again after `checks`
/// changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(
    description = "One run of rdy run: who ran what, where, and what came of it. Ignore fields you do not know. Use verdict as written.",
    transform = report_rules
))]
#[non_exhaustive]
pub struct Report {
    /// Always `rdy/v1`.
    #[serde(deserialize_with = "de_api_version")]
    #[cfg_attr(feature = "schema", schemars(extend("const" = "rdy/v1")))]
    pub api_version: String,
    /// Always `Report`.
    #[serde(deserialize_with = "de_report_kind")]
    #[cfg_attr(feature = "schema", schemars(extend("const" = "Report")))]
    pub kind: String,
    /// The rdy build that wrote this.
    pub producer: Producer,
    /// When and how the run went.
    pub run: Run,
    /// Which spec ran.
    pub spec: SpecRef,
    /// Who signed the spec.
    pub signature: Signature,
    /// The machine, coarsely.
    pub host: Host,
    /// Who ran it.
    pub identity: Identity,
    /// Proxy settings in effect, user info stripped. `null` when none.
    #[serde(default)]
    pub proxy: Option<Proxy>,
    /// Every need rdy probed before running checks, and the result.
    pub capabilities: Vec<Capability>,
    /// The overall answer. Closed in v1: a new verdict value needs `rdy/v2`. Use it as written.
    pub verdict: Verdict,
    /// Set when the verdict is not explained by an observed block or warning. `required_check_not_run`
    /// means NOT READY with no block. `nothing_verified` means READY with warnings because no check
    /// reached pass, warn or block. Otherwise `null`. Open.
    pub verdict_reason: Option<VerdictReason>,
    /// The exit code for this verdict: 0, 1 or 2. When rdy cannot write the report it exits 70 instead
    /// and `complete` is false.
    #[cfg_attr(feature = "schema", schemars(schema_with = "exit_code_schema"))]
    pub exit_code: u8,
    /// Counts of the results.
    pub summary: Summary,
    /// One entry per spec check, in spec order. Sort by bucket for display.
    pub checks: Vec<CheckResult>,
    /// Every file read, command, lookup, connection and API request, in order. At most 5000 entries.
    #[cfg_attr(feature = "schema", schemars(length(max = 5000)))]
    pub actions: Vec<Action>,
    /// `true` when the log hit its 5000 entry cap. `exec`, `connect`, `tls`, `http`, `dns`, `lookup` and
    /// `kube` entries are never dropped.
    pub actions_truncated: bool,
    /// How many entries of each kind were dropped when the log hit its cap. Only `read`, `read_dir` and
    /// `stat` entries are ever dropped.
    pub actions_dropped: BTreeMap<String, u64>,
    /// What the redactor changed in this report.
    pub redaction: Redaction,
    /// `false` when rdy could not finish or write the report (exit 70).
    pub complete: bool,
    /// `true` when the run was cancelled (Ctrl-C).
    pub interrupted: bool,
}

impl Report {
    /// A complete, uninterrupted report for `checks`, with the verdict, reason, exit code and summary
    /// worked out from them. Capabilities and actions start empty, `proxy` is `None` and the redaction
    /// summary is empty.
    #[must_use]
    pub fn new(
        producer: Producer,
        run: Run,
        spec: SpecRef,
        signature: Signature,
        host: Host,
        identity: Identity,
        checks: Vec<CheckResult>,
    ) -> Self {
        let judgement = verdict(&checks);
        let summary = Summary::from_checks(&checks);
        Self {
            api_version: API_VERSION.to_owned(),
            kind: REPORT_KIND.to_owned(),
            producer,
            run,
            spec,
            signature,
            host,
            identity,
            proxy: None,
            capabilities: Vec::new(),
            verdict: judgement.verdict,
            verdict_reason: judgement.reason,
            exit_code: judgement.verdict.exit_code().code(),
            summary,
            checks,
            actions: Vec::new(),
            actions_truncated: false,
            actions_dropped: BTreeMap::new(),
            redaction: Redaction::new(RedactionRuleset::Report),
            complete: true,
            interrupted: false,
        }
    }

    /// Works out `verdict`, `verdict_reason`, `exit_code` and `summary` from `checks` again.
    pub fn refresh_verdict(&mut self) {
        let judgement = verdict(&self.checks);
        self.verdict = judgement.verdict;
        self.verdict_reason = judgement.reason;
        self.exit_code = judgement.verdict.exit_code().code();
        self.summary = Summary::from_checks(&self.checks);
    }
}

/// The rdy build that wrote a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Producer {
    /// Always `rdy`.
    #[serde(deserialize_with = "de_producer_name")]
    #[cfg_attr(feature = "schema", schemars(extend("const" = "rdy")))]
    pub name: String,
    /// Version of the rdy binary.
    pub version: String,
    /// Short git commit of the build.
    #[serde(default)]
    pub commit: Option<String>,
    /// Version of the rdy-spec crate that wrote this file.
    pub rdy_spec: String,
    /// Rust target triple.
    pub target: String,
}

impl Producer {
    /// A producer named `rdy` with no commit.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        rdy_spec: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            name: "rdy".to_owned(),
            version: version.into(),
            commit: None,
            rdy_spec: rdy_spec.into(),
            target: target.into(),
        }
    }
}

/// When a run happened and the options it ran with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Run {
    /// Random UUID v4.
    #[cfg_attr(feature = "schema", schemars(extend("format" = "uuid")))]
    pub id: String,
    /// UTC, with milliseconds.
    #[cfg_attr(feature = "schema", schemars(extend("format" = "date-time")))]
    pub started_at: String,
    /// UTC, with milliseconds.
    #[cfg_attr(feature = "schema", schemars(extend("format" = "date-time")))]
    pub finished_at: String,
    /// Wall time of the run.
    pub duration_ms: u64,
    /// The options that shaped the run.
    pub options: RunOptions,
}

impl Run {
    /// A run record.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        started_at: impl Into<String>,
        finished_at: impl Into<String>,
        duration_ms: u64,
        options: RunOptions,
    ) -> Self {
        Self {
            id: id.into(),
            started_at: started_at.into(),
            finished_at: finished_at.into(),
            duration_ms,
            options,
        }
    }
}

/// The options of a run that change what a reader should expect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct RunOptions {
    /// Checks that ran at once, 1 to 32.
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 32)))]
    pub jobs: u32,
    /// The run limit in milliseconds.
    #[cfg_attr(feature = "schema", schemars(range(min = 1)))]
    pub deadline_ms: u64,
    /// Whether `--allow-unsigned` was set.
    pub allow_unsigned: bool,
    /// `false` when sockets were turned off for this run.
    pub network: bool,
    /// Context given with `--kube-context`, if any.
    #[serde(default)]
    pub kube_context: Option<String>,
}

impl RunOptions {
    /// Options with signed specs, the network on and no kube context.
    #[must_use]
    pub fn new(jobs: u32, deadline_ms: u64) -> Self {
        Self {
            jobs,
            deadline_ms,
            allow_unsigned: false,
            network: true,
            kube_context: None,
        }
    }
}

/// Which spec ran: the signed metadata and the hash of the exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct SpecRef {
    /// `metadata.product`.
    pub product: String,
    /// `metadata.version`.
    #[serde(default)]
    pub version: Option<String>,
    /// SHA-256 of the exact bytes that were verified and parsed, 64 lowercase hex digits.
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^[0-9a-f]{64}$")))]
    pub sha256: String,
    /// Base name only, never the full path.
    pub file_name: String,
    /// Size of the spec file.
    pub size_bytes: u64,
    /// `metadata.serial`.
    #[serde(default)]
    pub serial: Option<u64>,
    /// `metadata.expires`.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(extend("format" = "date-time")))]
    pub expires: Option<String>,
    /// `metadata.contact`.
    #[serde(default)]
    pub contact: Option<String>,
    /// `metadata.annotations`.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

impl SpecRef {
    /// A spec reference with every optional field unset.
    #[must_use]
    pub fn new(
        product: impl Into<String>,
        sha256: impl Into<String>,
        file_name: impl Into<String>,
        size_bytes: u64,
    ) -> Self {
        Self {
            product: product.into(),
            version: None,
            sha256: sha256.into(),
            file_name: file_name.into(),
            size_bytes,
            serial: None,
            expires: None,
            contact: None,
            annotations: BTreeMap::new(),
        }
    }
}

/// Who signed the spec, as far as rdy could tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(transform = signature_rules))]
#[non_exhaustive]
pub struct Signature {
    /// `verified` is signed by a trusted key. `unsigned` is no signature, run with `--allow-unsigned`.
    /// `invalid` appears only in the `rdy verify` object, never in a report. Open: treat an unknown
    /// value as not verified.
    pub state: SignatureState,
    /// Minisign key id, 16 uppercase hex digits.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^[0-9A-F]{16}$")))]
    pub key_id: Option<String>,
    /// SHA-256 of the 32 byte ed25519 public key, 64 hex digits. The key id alone is not an identity.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^[0-9a-f]{64}$")))]
    pub key_fingerprint: Option<String>,
    /// Product from the signed trusted comment.
    #[serde(default)]
    pub product: Option<String>,
    /// From the signed trusted comment.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(extend("format" = "date-time")))]
    pub signed_at: Option<String>,
    /// The local note from the trust store entry. Never text from the spec.
    #[serde(default)]
    pub trust_note: Option<String>,
    /// Where the key came from: the system or user trust store, or `flag` for a key given with `--key`
    /// for one run. Open: treat an unknown value like `flag`.
    #[serde(default)]
    pub trust_source: Option<TrustSource>,
    /// For `invalid` only.
    #[serde(default)]
    pub reason: Option<String>,
}

impl Signature {
    /// An unsigned spec. The run needed `--allow-unsigned`.
    #[must_use]
    pub fn unsigned() -> Self {
        Self::bare(SignatureState::Unsigned)
    }

    /// A signature in `state` with every other field unset. A verified signature must also carry the
    /// key id, fingerprint, product, signing time and trust source, which the schema requires.
    #[must_use]
    pub fn bare(state: SignatureState) -> Self {
        Self {
            state,
            key_id: None,
            key_fingerprint: None,
            product: None,
            signed_at: None,
            trust_note: None,
            trust_source: None,
            reason: None,
        }
    }
}

/// The machine, coarsely. No MAC addresses, environment values, command line, working directory, home
/// paths, kubeconfig contents, raw machine id or serial numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(transform = host_rules))]
#[non_exhaustive]
pub struct Host {
    /// As the OS reports it.
    pub hostname: String,
    /// First 16 hex digits of an HMAC-SHA256 of the OS machine id with key `rdy-host-id-v1` plus the
    /// product. The same host and product give the same value. Different products give unrelated
    /// values. `null` when there is no usable machine id (macOS for now).
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^[0-9a-f]{16}$")))]
    pub host_id: Option<String>,
    /// The operating system.
    pub os: HostOs,
    /// Kernel version.
    #[serde(default)]
    pub kernel: Option<String>,
    /// CPU architecture.
    pub arch: String,
    /// Whether the host is a virtual machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Virtualization"))]
    pub virtualization: Option<Virtualization>,
    /// rdy ran inside a container or WSL.
    #[serde(default)]
    pub container: bool,
}

impl Host {
    /// A host with no machine id, no kernel and no virtualization info.
    #[must_use]
    pub fn new(hostname: impl Into<String>, os: HostOs, arch: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            host_id: None,
            os,
            kernel: None,
            arch: arch.into(),
            virtualization: None,
            container: false,
        }
    }
}

/// The operating system of the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct HostOs {
    /// Linux, macOS or Windows.
    pub family: HostOsFamily,
    /// Distribution id, such as `rhel`.
    #[serde(default)]
    pub id: Option<String>,
    /// OS version.
    #[serde(default)]
    pub version: Option<String>,
    /// Human readable name.
    #[serde(default)]
    pub pretty_name: Option<String>,
}

impl HostOs {
    /// An OS of `family` with no details.
    #[must_use]
    pub fn new(family: HostOsFamily) -> Self {
        Self {
            family,
            id: None,
            version: None,
            pretty_name: None,
        }
    }
}

/// Who ran rdy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(transform = identity_rules))]
#[non_exhaustive]
pub struct Identity {
    /// Effective uid on Unix, `null` on Windows.
    pub euid: Option<u64>,
    /// Local login name.
    pub user: Option<String>,
    /// Effective uid 0 on Unix, a high integrity token on Windows.
    pub elevated: bool,
    /// The Kubernetes identity in use. `null` when no k8s check ran.
    #[serde(default)]
    pub kube: Option<KubeIdentity>,
}

impl Identity {
    /// An identity with no Kubernetes part.
    #[must_use]
    pub fn new(euid: Option<u64>, user: Option<String>, elevated: bool) -> Self {
        Self {
            euid,
            user,
            elevated,
            kube: None,
        }
    }
}

/// The Kubernetes identity of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct KubeIdentity {
    /// The kubeconfig context in use.
    #[serde(default)]
    pub context: Option<String>,
    /// The API server URL.
    #[serde(default)]
    pub server: Option<String>,
    /// The authenticated user from `SelfSubjectReview`. When that API is missing or the call fails, the
    /// user entry named in the kubeconfig context, with `user_verified` false.
    #[serde(default)]
    pub user: Option<String>,
    /// `true` when `user` came from `SelfSubjectReview`. `false` when it is the kubeconfig user, which
    /// the API server did not verify.
    pub user_verified: bool,
    /// Base name of the kubeconfig credential plugin that ran, if any.
    #[serde(default)]
    pub exec_plugin: Option<String>,
    /// The context skips TLS verification.
    #[serde(default)]
    pub insecure_tls: bool,
}

/// Proxy settings in effect, user info stripped from URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Proxy {
    /// The HTTPS proxy URL.
    #[serde(default)]
    pub https: Option<String>,
    /// The HTTP proxy URL.
    #[serde(default)]
    pub http: Option<String>,
    /// The `no_proxy` entries.
    #[serde(default)]
    pub no_proxy: Vec<String>,
}

/// One thing rdy probed before running checks, such as root or a reachable cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Capability {
    /// What was probed.
    pub need: Need,
    /// Program name for `command`, provider for `cloud_credentials`.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether the need is met.
    pub available: bool,
    /// For example `uid 1000` or `context acme-staging`.
    #[serde(default)]
    pub detail: Option<String>,
    /// What to do when not available.
    #[serde(default)]
    pub hint: Option<String>,
}

impl Capability {
    /// A probe result with no name, detail or hint.
    #[must_use]
    pub fn new(need: Need, available: bool) -> Self {
        Self {
            need,
            name: None,
            available,
            detail: None,
            hint: None,
        }
    }
}

/// Counts of the results.
///
/// `pass + warn + block + skipped + timeout + error = total` for every result whose status is known.
/// `skipped` counts every `status: skipped` entry, not applicable included. `not_applicable`,
/// `required_not_run` and `optional_not_run` are views inside that sum. A result whose status this
/// version does not know counts in `total` and in `required_not_run` or `optional_not_run` only. The
/// summary may gain keys, so never sum every key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Summary {
    /// Number of results.
    pub total: u32,
    /// Results with status `pass`.
    pub pass: u32,
    /// Results with status `warn`.
    pub warn: u32,
    /// Results with status `block`.
    pub block: u32,
    /// Every result with status `skipped`, not applicable included.
    pub skipped: u32,
    /// Results with status `timeout`.
    pub timeout: u32,
    /// Results with status `error`.
    pub error: u32,
    /// Skipped because the spec's `os` list leaves this OS out. Never counts toward the verdict.
    pub not_applicable: u32,
    /// Severity block (or unknown) and not run.
    pub required_not_run: u32,
    /// Severity warn and not run.
    pub optional_not_run: u32,
}

impl Summary {
    /// Counts `checks`. The counts come from severity, status and skip kind, never from the stored
    /// `bucket`.
    #[must_use]
    pub fn from_checks(checks: &[CheckResult]) -> Self {
        let mut s = Self::default();
        for c in checks {
            s.total = s.total.saturating_add(1);
            let counter = match &c.status {
                Status::Pass => Some(&mut s.pass),
                Status::Warn => Some(&mut s.warn),
                Status::Block => Some(&mut s.block),
                Status::Skipped => Some(&mut s.skipped),
                Status::Timeout => Some(&mut s.timeout),
                Status::Error => Some(&mut s.error),
                Status::Unknown(_) => None,
            };
            if let Some(n) = counter {
                *n = n.saturating_add(1);
            }
            match classify(&c.severity, &c.status, c.skip_kind.as_ref()) {
                Bucket::NotApplicable => s.not_applicable = s.not_applicable.saturating_add(1),
                Bucket::RequiredNotRun => s.required_not_run = s.required_not_run.saturating_add(1),
                Bucket::Warning if !matches!(c.status, Status::Warn) => {
                    s.optional_not_run = s.optional_not_run.saturating_add(1);
                }
                _ => {}
            }
        }
        s
    }
}

/// The outcome of one check entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(transform = check_result_rules))]
#[non_exhaustive]
pub struct CheckResult {
    /// `id`, or `id/name` when the spec gave a name. Unique in the report.
    pub key: String,
    /// The check id.
    pub id: String,
    /// The spec's name for this entry, shown next to the id.
    #[serde(default)]
    pub name: Option<String>,
    /// The check family, such as `host`.
    pub family: String,
    /// From the spec. A value a consumer does not know counts as block. Open.
    pub severity: Severity,
    /// After severity is applied. An unknown status counts as not run. Open.
    pub status: Status,
    /// Display group, from the same rule as the verdict. Sort by it in this order: blocker,
    /// required_not_run, warning, passed, not_applicable. Do not recompute it. Open.
    pub bucket: Bucket,
    /// Present when `status` is `skipped`. `not_applicable` comes only from the spec's `os` list. A
    /// check that cannot work on this OS is `not_yet_on_os`. Open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "SkipKind"))]
    pub skip_kind: Option<SkipKind>,
    /// For `unsupported_spec`: the fields this rdy could not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub unsupported_fields: Option<Vec<String>>,
    /// Present when `status` is `timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "u64"))]
    pub timeout_after_ms: Option<u64>,
    /// Present when `status` is `error`. Open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "ErrorKind"))]
    pub error_kind: Option<ErrorKind>,
    /// One line, at most 1 KiB, such as `15.4 GiB found, 32 GiB needed`.
    #[cfg_attr(feature = "schema", schemars(length(max = 1024)))]
    pub message: String,
    /// What to do. `null` only for pass and not applicable.
    #[serde(default)]
    pub fix: Option<String>,
    /// Whose fix text `fix` is: `spec` is the vendor's text, `rdy` is rdy's own. `null` on pass. Open.
    #[serde(default)]
    pub fix_source: Option<FixSource>,
    /// rdy's text when the spec's fix replaced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builtin_fix: Option<String>,
    /// Measured values, at most 64 KiB. Keys are per check id, in snake_case, with the unit in the name
    /// (`_bytes`, `_ms`, `_percent`). Keys are only ever added.
    #[serde(default)]
    pub observed: Option<Map<String, Value>>,
    /// Thresholds that applied after defaults. Same rules as `observed`.
    #[serde(default)]
    pub expected: Option<Map<String, Value>>,
    /// Hard and soft needs the check declared, and whether each was met.
    pub needs: Vec<NeedState>,
    /// Set when some sources could not be read. A partial check never blocks on data it could not read.
    #[serde(default)]
    pub partial: Option<Partial>,
    /// A size cap cut `message`, `fix`, `observed` or `expected`.
    pub truncated: bool,
    /// Up to 20 notes of 1 KiB each.
    #[cfg_attr(
        feature = "schema",
        schemars(length(max = 20), inner(length(max = 1024)))
    )]
    pub notes: Vec<String>,
    /// Milliseconds after `run.started_at`.
    pub started_ms: u64,
    /// How long the check took.
    pub duration_ms: u64,
}

impl CheckResult {
    /// A result for `id` with `severity` and `status`, with the key equal to the id, the bucket worked
    /// out and everything else empty.
    ///
    /// Set `skip_kind` and any other field you need, then call [`CheckResult::refresh_bucket`].
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        family: impl Into<String>,
        severity: Severity,
        status: Status,
    ) -> Self {
        let id = id.into();
        let bucket = classify(&severity, &status, None);
        Self {
            key: id.clone(),
            id,
            name: None,
            family: family.into(),
            severity,
            status,
            bucket,
            skip_kind: None,
            unsupported_fields: None,
            timeout_after_ms: None,
            error_kind: None,
            message: String::new(),
            fix: None,
            fix_source: None,
            builtin_fix: None,
            observed: None,
            expected: None,
            needs: Vec::new(),
            partial: None,
            truncated: false,
            notes: Vec::new(),
            started_ms: 0,
            duration_ms: 0,
        }
    }

    /// A skipped result of `skip_kind`, with the bucket worked out.
    #[must_use]
    pub fn skipped(
        id: impl Into<String>,
        family: impl Into<String>,
        severity: Severity,
        skip_kind: SkipKind,
    ) -> Self {
        let mut result = Self::new(id, family, severity, Status::Skipped);
        result.skip_kind = Some(skip_kind);
        result.refresh_bucket();
        result
    }

    /// Works out `bucket` from severity, status and skip kind.
    pub fn refresh_bucket(&mut self) {
        self.bucket = classify(&self.severity, &self.status, self.skip_kind.as_ref());
    }
}

/// A need a check declared and whether it was met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct NeedState {
    /// What the check needs.
    pub need: Need,
    /// Program name for `command`, provider for `cloud_credentials`.
    #[serde(default)]
    pub name: Option<String>,
    /// `true`: the check does not run without it. `false`: it runs partial.
    pub hard: bool,
    /// Whether it was available.
    pub met: bool,
}

impl NeedState {
    /// A need with no name.
    #[must_use]
    pub fn new(need: Need, hard: bool, met: bool) -> Self {
        Self {
            need,
            name: None,
            hard,
            met,
        }
    }
}

/// Which sources a check could not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Partial {
    /// The needs that were missing.
    pub missing: Vec<Need>,
    /// What is missing, or the OS note for a `Partial` OS.
    pub note: String,
}

impl Partial {
    /// A partial result.
    #[must_use]
    pub fn new(missing: Vec<Need>, note: impl Into<String>) -> Self {
        Self {
            missing,
            note: note.into(),
        }
    }
}

/// One side effect, recorded as it happened.
///
/// The fields that depend on `kind` (`path`, `program`, `host` and so on, 01 section 5.4) stay in
/// [`Action::fields`] as JSON until the action log ticket types them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(
    description = "One side effect, recorded as it happened. Fields beyond the required ones depend on kind.",
    transform = action_fields
))]
#[non_exhaustive]
pub struct Action {
    /// Position in the log, from 1.
    #[cfg_attr(feature = "schema", schemars(range(min = 1)))]
    pub seq: u64,
    /// Check key, or `null` for run level probes.
    pub check: Option<String>,
    /// Milliseconds after `run.started_at`.
    pub at_ms: u64,
    /// How long it took.
    pub duration_ms: u64,
    /// What kind of effect.
    pub kind: ActionKind,
    /// How it ended.
    pub outcome: ActionOutcome,
    /// The fields of this `kind`, flattened into the entry.
    #[serde(flatten)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub fields: Map<String, Value>,
}

impl Action {
    /// An entry with no kind-specific fields.
    #[must_use]
    pub fn new(
        seq: u64,
        check: Option<String>,
        at_ms: u64,
        duration_ms: u64,
        kind: ActionKind,
        outcome: ActionOutcome,
    ) -> Self {
        Self {
            seq,
            check,
            at_ms,
            duration_ms,
            kind,
            outcome,
            fields: Map::new(),
        }
    }
}

/// What the redactor changed in a report. Counts only, never the matched text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Redaction {
    /// Which compiled rule set ran.
    pub ruleset: RedactionRuleset,
    /// Total replacements.
    pub total: u64,
    /// Replacements per rule name.
    pub by_rule: BTreeMap<String, u64>,
}

impl Redaction {
    /// A summary with no replacements.
    #[must_use]
    pub fn new(ruleset: RedactionRuleset) -> Self {
        Self {
            ruleset,
            total: 0,
            by_rule: BTreeMap::new(),
        }
    }
}
