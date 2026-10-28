//! The `rdy/v1` readiness spec as Rust types.
//!
//! These are the wire types of docs/plan/01-spec-format.md section 2. They derive `serde` and carry no
//! behaviour beyond the grammar of the few names that are cheap to check on the way in (product, check
//! id, check name). Size and count limits, expiry and the typed scalars (`Quantity`, `Duration`,
//! `Version`, `Target`) belong to later tickets.
//!
//! A [`Spec`] is untrusted input. Nothing here proves a vendor signed it. Only [`crate::load`] returns a
//! [`crate::LoadedSpec`], which is the value the engine runs.
//!
//! Following the rules of 01 section 3.4, every public wire struct is `#[non_exhaustive]` with public
//! fields and a `new(..)` that takes only the required fields. Outside this crate, build a value with
//! `new` and then set the optional fields.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{API_VERSION, SpecError};

/// Defines a string newtype whose constructor and `Deserialize` impl both check one grammar.
macro_rules! checked_string {
    (
        $(#[$meta:meta])*
        $name:ident, $valid:path, $error:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Checks `value` against the grammar and wraps it.
            ///
            /// # Errors
            ///
            /// Returns the matching [`SpecError`] when `value` does not fit the grammar.
            pub fn new(value: impl Into<String>) -> Result<Self, SpecError> {
                let value = value.into();
                if $valid(&value) {
                    Ok(Self(value))
                } else {
                    Err(SpecError::$error { value })
                }
            }

            /// The text, exactly as written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = SpecError;

            fn try_from(value: String) -> Result<Self, SpecError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// `^[a-z0-9][a-z0-9-]{0,62}$`
fn is_product_slug(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() <= 63
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `^[a-z0-9][a-z0-9_-]{0,62}$`
fn is_check_name(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() <= 63
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_'))
}

/// `^[a-z][a-z0-9]{0,15}\.[a-z][a-z0-9_]{0,47}$`
fn is_check_id(s: &str) -> bool {
    let Some((family, name)) = s.split_once('.') else {
        return false;
    };
    let part = |p: &str, max: usize, extra: Option<u8>| {
        let b = p.as_bytes();
        b.len() <= max
            && b.first().is_some_and(u8::is_ascii_lowercase)
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || Some(*c) == extra)
    };
    part(family, 16, None) && part(name, 48, Some(b'_'))
}

checked_string! {
    /// A product name, `^[a-z0-9][a-z0-9-]{0,62}$`.
    ///
    /// It binds a signature to a pinned key and names the report directory and files.
    ProductSlug, is_product_slug, InvalidProduct
}

checked_string! {
    /// A check id, `family.name` in lowercase, such as `host.memory`.
    ///
    /// Any well-formed id is accepted here, including ids rdy does not know. Whether rdy has the check is
    /// decided later and gives a skipped result, never a parse error.
    CheckId, is_check_id, InvalidCheckId
}

checked_string! {
    /// A short label for a check entry, `^[a-z0-9][a-z0-9_-]{0,62}$`.
    ///
    /// Needed when the same id appears twice. Reports show it as `host.disk (data)`.
    CheckName, is_check_name, InvalidCheckName
}

/// The `kind` of a spec document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Kind {
    /// A readiness spec. The only kind in `rdy/v1`.
    Readiness,
}

/// A whole `rdy/v1` readiness spec, as the YAML file describes it.
///
/// Unknown top-level keys are refused, so a newer spec fails loudly on an older rdy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Spec {
    /// Format version. Must be [`API_VERSION`] (`rdy/v1`). Kept as text so the message for a wrong
    /// version can quote what the file said.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Document kind. Only [`Kind::Readiness`] exists in v1.
    pub kind: Kind,
    /// Who the spec is for and how fresh it is.
    pub metadata: Metadata,
    /// The checks to run, in report order. A valid spec has 1 to 256 entries.
    pub checks: Vec<CheckSpec>,
    /// What `rdy bundle` collects, from M2. It parses today so specs written now keep working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BundleSpec>,
}

impl Spec {
    /// A spec for `rdy/v1` with the given metadata and checks and no bundle block.
    #[must_use]
    pub fn new(metadata: Metadata, checks: Vec<CheckSpec>) -> Self {
        Self {
            api_version: API_VERSION.to_owned(),
            kind: Kind::Readiness,
            metadata,
            checks,
            bundle: None,
        }
    }
}

/// The `metadata` block: who the spec is for, which revision it is and when it stops being valid.
///
/// Unknown keys are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Metadata {
    /// Product name. Binds the signature to a pinned key and names the report directory and files.
    pub product: ProductSlug,
    /// Product versions this spec is for, such as `>=4.2`, at most 64 characters. Shown in the report
    /// and never evaluated, because rdy cannot know the product version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Where the customer asks questions, at most 256 characters. Shown as plain text, never as a link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// Spec revision, rising on every signed release. Shown as "Spec revision 7".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u64>,
    /// The UTC time after which rdy refuses the spec, in the full form `YYYY-MM-DDTHH:MM:SSZ`. Kept as
    /// text here. The shape and the comparison with the clock are checked when the spec is validated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Up to 32 labels for vendor tooling and the portal. rdy never changes behaviour because of them
    /// and copies them into the result. Sorted by key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl Metadata {
    /// Metadata for `product` with every optional field unset.
    #[must_use]
    pub fn new(product: ProductSlug) -> Self {
        Self {
            product,
            version: None,
            contact: None,
            serial: None,
            expires: None,
            annotations: BTreeMap::new(),
        }
    }
}

/// How bad a failed check is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// Required. A failure makes the run NOT READY. This is the default.
    #[default]
    Block,
    /// Optional. A failure gives READY with warnings.
    Warn,
}

/// An operating system family a check can be limited to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OsFamily {
    /// Linux.
    Linux,
    /// macOS.
    Macos,
    /// Windows.
    Windows,
}

/// One entry of `checks`: the common fields and the raw parameters of its check id.
///
/// An entry is a flat map in the YAML file. The common fields are typed here. Everything else is kept in
/// [`CheckSpec::params`] for now. A later ticket decodes those into a typed value per id, so that an
/// unknown id or a bad parameter skips the one check and not the whole file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CheckSpec {
    /// Which check to run.
    pub id: CheckId,
    /// A short label. The entry's key is `id` or `id/name`, unique per spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<CheckName>,
    /// Whether a failure blocks or only warns. Defaults to [`Severity::Block`].
    #[serde(default)]
    pub severity: Severity,
    /// The vendor's advice, 1 to 2000 characters, shown instead of rdy's own as the headline fix. Plain
    /// text with no templating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// How long the check may run, `1s` to `60s`, written like `10s`. Kept as text here. The grammar and
    /// range are checked by the typed `Duration` of a later ticket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Run only on these operating systems. Elsewhere the check is skipped as not applicable and never
    /// counts. `None` means every system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<Vec<OsFamily>>,
    /// Every other key of the entry: the parameters of the check id, such as `min` or `endpoints`.
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

impl CheckSpec {
    /// An entry for `id` with severity `block` and no other fields.
    #[must_use]
    pub fn new(id: CheckId) -> Self {
        Self {
            id,
            name: None,
            severity: Severity::Block,
            fix: None,
            timeout: None,
            os: None,
            params: Map::new(),
        }
    }
}

/// The `bundle` block: what `rdy bundle` collects and how it redacts.
///
/// It parses in v1 and nothing acts on it before M2. `rdy run` never collects anything, whatever this
/// says. Unknown keys are refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct BundleSpec {
    /// Collectors such as `journal:7d`, `k8s:events` or `file:/etc/acme/*.yaml`. At most 64.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collect: Vec<String>,
    /// Redactor groups to add, such as `aws_keys`. At most 64. The built-in rules always run, so a spec
    /// can add redaction and can never remove it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<String>,
    /// The vendor's own redaction patterns. At most 32. A pattern can only add redaction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact_patterns: Vec<RedactPattern>,
    /// A size cap, such as `200Mi`. It lowers rdy's own cap and never raises it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<RawQuantity>,
}

impl BundleSpec {
    /// A bundle block with nothing set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A vendor redaction pattern in the `bundle` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RedactPattern {
    /// The rule name. A match is replaced with a `custom.<name>` placeholder.
    pub name: String,
    /// The pattern, in Rust `regex` syntax, at most 256 characters. Not compiled here.
    pub regex: String,
}

impl RedactPattern {
    /// A pattern called `name` that matches `regex`.
    #[must_use]
    pub fn new(name: impl Into<String>, regex: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            regex: regex.into(),
        }
    }
}

/// A byte size exactly as the file wrote it: a whole number, or text such as `200Mi`.
///
/// The typed `Quantity` of a later ticket replaces this and checks the grammar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RawQuantity {
    /// A whole number of bytes.
    Bytes(u64),
    /// Text such as `200Mi`.
    Text(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(s: &str) -> ProductSlug {
        ProductSlug::new(s).expect("valid slug")
    }

    fn full_metadata() -> Metadata {
        let mut m = Metadata::new(slug("acme-platform"));
        m.version = Some(">=4.2".into());
        m.contact = Some("support@acme.example".into());
        m.serial = Some(7);
        m.expires = Some("2027-01-31T00:00:00Z".into());
        m.annotations.insert("portal.id".into(), "spec-123".into());
        m.annotations.insert("team".into(), "se".into());
        m
    }

    #[test]
    fn metadata_round_trips_through_serde_json() {
        let m = full_metadata();
        let json = serde_json::to_string(&m).expect("serialize");
        let back: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, m);
    }

    #[test]
    fn metadata_uses_the_wire_field_names() {
        let json = serde_json::to_value(full_metadata()).expect("serialize");
        let mut keys: Vec<_> = json.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "annotations",
                "contact",
                "expires",
                "product",
                "serial",
                "version"
            ]
        );
    }

    #[test]
    fn minimal_metadata_writes_only_the_product() {
        let json = serde_json::to_string(&Metadata::new(slug("a"))).expect("serialize");
        assert_eq!(json, r#"{"product":"a"}"#);
        let back: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, Metadata::new(slug("a")));
    }

    #[test]
    fn metadata_refuses_unknown_and_missing_keys() {
        assert!(serde_json::from_str::<Metadata>(r#"{"product":"a","prodcut":"b"}"#).is_err());
        assert!(serde_json::from_str::<Metadata>(r#"{"version":"1"}"#).is_err());
    }

    #[test]
    fn metadata_refuses_a_bad_product() {
        for bad in ["Acme Platform", "", "-a", "a_b", "a.b", &"a".repeat(64)] {
            let json = serde_json::json!({ "product": bad }).to_string();
            let err = serde_json::from_str::<Metadata>(&json).expect_err(bad);
            assert!(
                err.to_string().contains("not a valid product name"),
                "{err}"
            );
        }
        assert!(ProductSlug::new("a".repeat(63)).is_ok());
        assert!(ProductSlug::new("0-9").is_ok());
    }

    #[test]
    fn check_id_grammar() {
        for ok in [
            "host.memory",
            "k8s.storageclass",
            "host.security_agents",
            "gpu.cuda",
        ] {
            assert!(CheckId::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "host",
            "Host.memory",
            "host.",
            ".memory",
            "host.memory.x",
            "1host.memory",
            "host.Memory",
            "host.mem-ory",
            "host memory",
            "host._x",
        ] {
            assert!(CheckId::new(bad).is_err(), "{bad}");
        }
        assert!(CheckId::new(format!("{}.x", "a".repeat(17))).is_err());
        assert!(CheckId::new(format!("a.{}", "x".repeat(49))).is_err());
    }

    #[test]
    fn check_name_grammar() {
        for ok in ["data", "data-windows", "a_b", "0"] {
            assert!(CheckName::new(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Data", "-x", "a b", "a.b"] {
            assert!(CheckName::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn check_entry_is_a_flat_map() {
        let json = r#"{"id":"host.memory","min":"32Gi","severity":"warn","fix":"Add RAM.",
            "timeout":"20s","name":"main","os":["linux","macos"],"swap":"forbid"}"#;
        let c: CheckSpec = serde_json::from_str(json).expect("deserialize");
        assert_eq!(c.id.as_str(), "host.memory");
        assert_eq!(c.name.as_ref().map(CheckName::as_str), Some("main"));
        assert_eq!(c.severity, Severity::Warn);
        assert_eq!(c.fix.as_deref(), Some("Add RAM."));
        assert_eq!(c.timeout.as_deref(), Some("20s"));
        assert_eq!(c.os, Some(vec![OsFamily::Linux, OsFamily::Macos]));
        let mut keys: Vec<_> = c.params.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["min", "swap"]);
        let back: CheckSpec =
            serde_json::from_str(&serde_json::to_string(&c).expect("serialize")).expect("again");
        assert_eq!(back, c);
    }

    #[test]
    fn severity_defaults_to_block_and_bad_values_fail() {
        let c: CheckSpec = serde_json::from_str(r#"{"id":"host.cpu","min":4}"#).expect("parse");
        assert_eq!(c.severity, Severity::Block);
        assert_eq!(Severity::default(), Severity::Block);
        assert!(
            serde_json::from_str::<CheckSpec>(r#"{"id":"host.cpu","severity":"blok"}"#).is_err()
        );
        assert!(serde_json::from_str::<CheckSpec>(r#"{"severity":"warn"}"#).is_err());
    }

    #[test]
    fn os_family_values() {
        let v: Vec<OsFamily> =
            serde_json::from_str(r#"["linux","macos","windows"]"#).expect("parse");
        assert_eq!(v, [OsFamily::Linux, OsFamily::Macos, OsFamily::Windows]);
        assert!(serde_json::from_str::<Vec<OsFamily>>(r#"["rhel"]"#).is_err());
    }

    #[test]
    fn bundle_block_parses_the_documented_shape() {
        let json = r#"{"collect":["journal:7d","k8s:events","file:/etc/acme/*.yaml"],
            "redact":["aws_keys","bearer_tokens","emails"],
            "redact_patterns":[{"name":"acme_license","regex":"ACME-[A-Z0-9]{20}"}],
            "max_size":"200Mi"}"#;
        let b: BundleSpec = serde_json::from_str(json).expect("parse");
        assert_eq!(b.collect.len(), 3);
        assert_eq!(b.redact, ["aws_keys", "bearer_tokens", "emails"]);
        assert_eq!(
            b.redact_patterns,
            [RedactPattern::new("acme_license", "ACME-[A-Z0-9]{20}")]
        );
        assert_eq!(b.max_size, Some(RawQuantity::Text("200Mi".into())));
        let again: BundleSpec =
            serde_json::from_str(&serde_json::to_string(&b).expect("serialize")).expect("again");
        assert_eq!(again, b);
        let n: BundleSpec = serde_json::from_str(r#"{"max_size":1048576}"#).expect("parse");
        assert_eq!(n.max_size, Some(RawQuantity::Bytes(1_048_576)));
    }

    #[test]
    fn bundle_refuses_unknown_keys() {
        assert!(serde_json::from_str::<BundleSpec>(r#"{"upload":true}"#).is_err());
        assert!(
            serde_json::from_str::<BundleSpec>(
                r#"{"redact_patterns":[{"name":"a","regex":"b","x":1}]}"#
            )
            .is_err()
        );
    }

    /// The shape of `examples/specs/acme-platform.yaml`, written as JSON because the YAML parser is a
    /// later ticket.
    #[test]
    fn a_whole_spec_round_trips() {
        let json = r#"{
            "apiVersion": "rdy/v1",
            "kind": "Readiness",
            "metadata": {"product": "acme-platform", "version": ">=4.2"},
            "checks": [
                {"id": "host.memory", "min": "32Gi", "severity": "block", "fix": "Add RAM."},
                {"id": "host.disk", "path": "/var/lib", "min": "100Gi", "severity": "warn"},
                {"id": "gpu.cuda", "min": "12.4"}
            ],
            "bundle": {"collect": ["k8s:events"]}
        }"#;
        let spec: Spec = serde_json::from_str(json).expect("parse");
        assert_eq!(spec.api_version, API_VERSION);
        assert_eq!(spec.kind, Kind::Readiness);
        assert_eq!(spec.checks.len(), 3);
        assert!(spec.bundle.is_some());
        let back: Spec =
            serde_json::from_str(&serde_json::to_string(&spec).expect("serialize")).expect("again");
        assert_eq!(back, spec);
    }

    #[test]
    fn spec_refuses_unknown_top_level_keys_and_bad_kind() {
        let base = |extra: &str| {
            format!(
                r#"{{"apiVersion":"rdy/v1","kind":"Readiness","metadata":{{"product":"a"}},
                "checks":[{{"id":"host.cpu"}}]{extra}}}"#
            )
        };
        assert!(serde_json::from_str::<Spec>(&base("")).is_ok());
        assert!(serde_json::from_str::<Spec>(&base(r#","upload":{}"#)).is_err());
        let bad_kind = base("").replace("Readiness", "Report");
        assert!(serde_json::from_str::<Spec>(&bad_kind).is_err());
    }

    #[test]
    fn constructors_set_the_v1_envelope() {
        let spec = Spec::new(Metadata::new(slug("a")), vec![]);
        assert_eq!(spec.api_version, "rdy/v1");
        assert_eq!(spec.kind, Kind::Readiness);
        assert!(spec.bundle.is_none());
    }
}
