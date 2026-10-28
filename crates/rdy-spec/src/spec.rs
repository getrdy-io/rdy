//! The `rdy/v1` readiness spec as Rust types.
//!
//! These are the wire types of docs/plan/01-spec-format.md section 2. They derive `serde` and carry no
//! behaviour beyond the grammar of the few names that are cheap to check on the way in (product, check
//! id, check name) and the typed [`crate::scalar`] values. Size and count limits and expiry belong to
//! later tickets.
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

use crate::{API_VERSION, Duration, Quantity, SpecError};

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
                    Err(SpecError::$error {
                        value: crate::error::echo_safe(&value),
                    })
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

/// The keys of the top level of a spec, for did-you-mean. A test compares the lists of this section with
/// what serde itself accepts, so they cannot drift from the structs.
pub(crate) const SPEC_KEYS: &[&str] = &["apiVersion", "kind", "metadata", "checks", "bundle"];

/// The keys of `metadata`. See [`SPEC_KEYS`].
pub(crate) const METADATA_KEYS: &[&str] = &[
    "product",
    "version",
    "contact",
    "serial",
    "expires",
    "annotations",
];

/// The keys of `bundle`. See [`SPEC_KEYS`].
pub(crate) const BUNDLE_KEYS: &[&str] = &["collect", "redact", "redact_patterns", "max_size"];

/// The keys of one item of `bundle.redact_patterns`. See [`SPEC_KEYS`].
pub(crate) const REDACT_PATTERN_KEYS: &[&str] = &["name", "regex"];

/// The largest `metadata.serial`, 2^53 - 1. Larger numbers lose precision in JSON consumers.
pub const MAX_SERIAL: u64 = 9_007_199_254_740_991;

fn deserialize_serial<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let value = Option::<u64>::deserialize(d)?;
    match value {
        Some(v) if v > MAX_SERIAL => Err(serde::de::Error::custom(SpecError::InvalidSerial {
            value: v,
        })),
        other => Ok(other),
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
    /// Spec revision, rising on every signed release, 0 to [`MAX_SERIAL`]. Shown as "Spec revision 7".
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_serial"
    )]
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

/// The longest `fix` text, in characters.
const MAX_FIX_CHARS: usize = 2000;

/// The vendor's advice for a check, 1 to 2000 characters.
///
/// Plain text. There is no templating and no markup. Control characters other than newlines are stripped
/// before it is printed, so print it through the report code and not straight to a terminal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FixText(String);

impl FixText {
    /// Checks the length and wraps the text.
    ///
    /// # Errors
    ///
    /// [`SpecError::InvalidValue`] when the text is empty or longer than 2000 characters.
    pub fn new(value: impl Into<String>) -> Result<Self, SpecError> {
        let value = value.into();
        let chars = value.chars().take(MAX_FIX_CHARS + 1).count();
        if (1..=MAX_FIX_CHARS).contains(&chars) {
            Ok(Self(value))
        } else {
            Err(SpecError::InvalidValue {
                reason: "fix must be 1 to 2000 characters".to_owned(),
            })
        }
    }

    /// The text, exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FixText {
    type Error = SpecError;

    fn try_from(value: String) -> Result<Self, SpecError> {
        Self::new(value)
    }
}

impl From<FixText> for String {
    fn from(value: FixText) -> String {
        value.0
    }
}

impl AsRef<str> for FixText {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The `timeout` of a check: a [`Duration`] from `1s` to `60s`.
///
/// `60s` and `1m` are both fine, and so is `1000ms`. `500ms`, `90s` and `1h` are not. The text as
/// written is kept and written back.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CheckTimeout(Duration);

impl CheckTimeout {
    /// The shortest timeout, in milliseconds.
    pub const MIN_MILLIS: u64 = 1_000;
    /// The longest timeout, in milliseconds.
    pub const MAX_MILLIS: u64 = 60_000;

    /// Checks the range and wraps the duration.
    ///
    /// # Errors
    ///
    /// [`SpecError::InvalidValue`] when the duration is outside `1s` to `60s`.
    pub fn new(value: Duration) -> Result<Self, SpecError> {
        if (Self::MIN_MILLIS..=Self::MAX_MILLIS).contains(&value.as_millis()) {
            Ok(Self(value))
        } else {
            Err(SpecError::InvalidValue {
                reason: "timeout must be between 1s and 60s".to_owned(),
            })
        }
    }

    /// Reads text such as `10s` and checks the range.
    ///
    /// # Errors
    ///
    /// [`SpecError::InvalidValue`] when the text is not a duration, or is outside `1s` to `60s`.
    pub fn parse(text: &str) -> Result<Self, SpecError> {
        match Duration::parse(text) {
            Ok(d) => Self::new(d),
            Err(e) => Err(SpecError::InvalidValue {
                reason: crate::error::echo_reason(&e.to_string(), 160),
            }),
        }
    }

    /// The duration.
    #[must_use]
    pub fn as_duration(&self) -> &Duration {
        &self.0
    }

    /// The text as written, such as `20s`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for CheckTimeout {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let duration = Duration::deserialize(deserializer)?;
        Self::new(duration).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for CheckTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// A common field of a check entry that is either well formed or kept as the raw value that was
/// written.
///
/// One bad common field must skip one check and not reject the whole file (01 sections 2.5 and 3.2). So
/// decoding never fails on these fields. A value that does not fit stays as [`Lenient::Invalid`], and the
/// code that plans the run turns it into an `unsupported_spec` skip. It serializes back to what was read.
///
/// The raw value is untrusted. Strip control characters before printing it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Lenient<T> {
    /// The value fits the field.
    Valid(T),
    /// The value does not fit. This is what the file said.
    Invalid(Value),
}

impl<T> Lenient<T> {
    /// The value, or `None` when it did not fit.
    #[must_use]
    pub fn valid(&self) -> Option<&T> {
        match self {
            Self::Valid(v) => Some(v),
            Self::Invalid(_) => None,
        }
    }
}

impl<T: Serialize> Serialize for Lenient<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Valid(v) => v.serialize(serializer),
            Self::Invalid(raw) => raw.serialize(serializer),
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Lenient<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Value::deserialize(deserializer)?;
        Ok(match T::deserialize(raw.clone()) {
            Ok(v) => Self::Valid(v),
            Err(_) => Self::Invalid(raw),
        })
    }
}

/// One entry of `checks`: the common fields and the raw parameters of its check id.
///
/// An entry is a flat map in the YAML file. Decoding it is the first of two steps (01 section 2.4).
/// Only a missing `id`, an `id` that is not text, or an entry that is not a map rejects the file. Every
/// other common field is a [`Lenient`] slot, so a bad `severity`, `os`, `name`, `fix` or `timeout` leaves
/// the entry in place for the planner to skip. The remaining keys wait in [`CheckSpec::params`]. The
/// second step, [`CheckSpec::decode_params`], turns them into a [`crate::check::CheckParams`] and treats a
/// [`Lenient::Invalid`] common field as `unsupported_spec`. A [`Lenient::Valid`] value is always one that
/// step two accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CheckSpec {
    /// Which check to run, as written. It should read `family.name` in lowercase. Use
    /// [`CheckSpec::check_id`] to test that. An id that does not fit, or that rdy does not know, skips
    /// this one check as unknown and never rejects the file.
    pub id: String,
    /// A short label. The entry's key is `id` or `id/name`, unique per spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Lenient<CheckName>>,
    /// Whether a failure blocks or only warns. `None` means [`Severity::Block`]. A value that does not
    /// read, such as `info` or a typo, counts as block too. See [`CheckSpec::effective_severity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Lenient<Severity>>,
    /// The vendor's advice, 1 to 2000 characters, shown instead of rdy's own as the headline fix. Plain
    /// text with no templating. See [`FixText`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<Lenient<FixText>>,
    /// How long the check may run, `1s` to `60s`, written like `10s`. A value outside that range, or one
    /// that is not a duration, stays [`Lenient::Invalid`] and the check is skipped. See [`CheckTimeout`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Lenient<CheckTimeout>>,
    /// Run only on these operating systems. Elsewhere the check is skipped as not applicable and never
    /// counts. `None` means every system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<Lenient<Vec<OsFamily>>>,
    /// Every other key of the entry: the parameters of the check id, such as `min` or `endpoints`.
    ///
    /// These values go through `serde_json::Value`, which keeps the last of two equal keys, turns a
    /// non-finite float into `null` and has no line numbers. So [`crate::parse_unverified`] checks the
    /// YAML first and rejects duplicate keys, `.nan`, `.inf` and unquoted decimals such as `12.10`,
    /// with a line and column, before this type sees them. A `Spec` built any other way has no such
    /// guarantee.
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

impl CheckSpec {
    /// An entry for `id` with every other field unset.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            severity: None,
            fix: None,
            timeout: None,
            os: None,
            params: Map::new(),
        }
    }

    /// The id as a checked [`CheckId`].
    ///
    /// # Errors
    ///
    /// [`SpecError::InvalidCheckId`] when the id is not `family.name` in lowercase. The planner reports
    /// that as an unknown check.
    pub fn check_id(&self) -> Result<CheckId, SpecError> {
        CheckId::new(self.id.as_str())
    }

    /// The severity that applies: the written one, or [`Severity::Block`] when it is absent or does not
    /// read. A check that cannot read its own severity is treated as required, so it can never make a
    /// run look better than it is.
    #[must_use]
    pub fn effective_severity(&self) -> Severity {
        match &self.severity {
            Some(Lenient::Valid(s)) => *s,
            _ => Severity::Block,
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
    pub max_size: Option<Quantity>,
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

    /// serde names the keys a struct accepts when it refuses a key: "unknown field `x`, expected one of
    /// `a`, `b`", "..., expected `a` or `b`" or "..., expected `a`".
    fn serde_keys<T: serde::de::DeserializeOwned>() -> Vec<String> {
        let probe = serde_json::json!({ "__rdy_probe__": 1 });
        let Err(error) = serde_json::from_value::<T>(probe) else {
            panic!("the struct accepted an unknown key");
        };
        let message = error.to_string();
        let Some((_, expected)) = message.split_once("`, ") else {
            panic!("unexpected serde message: {message}");
        };
        let mut keys: Vec<String> = expected
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect();
        keys.sort();
        keys
    }

    fn sorted(list: &[&str]) -> Vec<String> {
        let mut keys: Vec<String> = list.iter().map(|k| (*k).to_owned()).collect();
        keys.sort();
        keys
    }

    #[test]
    fn the_key_lists_for_did_you_mean_match_the_structs() {
        assert_eq!(sorted(SPEC_KEYS), serde_keys::<Spec>());
        assert_eq!(sorted(METADATA_KEYS), serde_keys::<Metadata>());
        assert_eq!(sorted(BUNDLE_KEYS), serde_keys::<BundleSpec>());
        assert_eq!(sorted(REDACT_PATTERN_KEYS), serde_keys::<RedactPattern>());
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

    fn entry(json: &str) -> CheckSpec {
        serde_json::from_str(json).expect("one bad field must not reject the entry")
    }

    #[test]
    fn check_entry_is_a_flat_map() {
        let json = r#"{"id":"host.memory","min":"32Gi","severity":"warn","fix":"Add RAM.",
            "timeout":"20s","name":"main","os":["linux","macos"],"swap":"forbid"}"#;
        let c = entry(json);
        assert_eq!(c.id, "host.memory");
        assert_eq!(c.check_id().expect("id").as_str(), "host.memory");
        assert_eq!(
            c.name,
            Some(Lenient::Valid(CheckName::new("main").expect("name")))
        );
        assert_eq!(c.severity, Some(Lenient::Valid(Severity::Warn)));
        assert_eq!(c.effective_severity(), Severity::Warn);
        assert_eq!(
            c.fix,
            Some(Lenient::Valid(FixText::new("Add RAM.").expect("fix")))
        );
        assert_eq!(
            c.timeout,
            Some(Lenient::Valid(CheckTimeout::parse("20s").expect("timeout")))
        );
        assert_eq!(
            c.os,
            Some(Lenient::Valid(vec![OsFamily::Linux, OsFamily::Macos]))
        );
        let mut keys: Vec<_> = c.params.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["min", "swap"]);
        let back: CheckSpec =
            serde_json::from_str(&serde_json::to_string(&c).expect("serialize")).expect("again");
        assert_eq!(back, c);
    }

    #[test]
    fn severity_defaults_to_block() {
        let c = entry(r#"{"id":"host.cpu","min":4}"#);
        assert_eq!(c.severity, None);
        assert_eq!(c.effective_severity(), Severity::Block);
        assert_eq!(Severity::default(), Severity::Block);
    }

    /// 01 sections 2.5 and 3.2: a bad value in one entry skips that check and never rejects the file.
    #[test]
    fn a_bad_common_field_is_kept_not_rejected() {
        let c = entry(r#"{"id":"host.cpu","severity":"blok"}"#);
        assert_eq!(c.severity, Some(Lenient::Invalid(Value::from("blok"))));
        assert_eq!(c.effective_severity(), Severity::Block);

        let c = entry(r#"{"id":"host.cpu","severity":"info"}"#);
        assert_eq!(c.severity, Some(Lenient::Invalid(Value::from("info"))));
        assert_eq!(c.effective_severity(), Severity::Block);

        let c = entry(r#"{"id":"host.cpu","os":["rhel"]}"#);
        assert_eq!(c.os.as_ref().and_then(Lenient::valid), None);
        assert!(matches!(c.os, Some(Lenient::Invalid(_))));

        let c = entry(r#"{"id":"host.cpu","name":"Data"}"#);
        assert_eq!(c.name, Some(Lenient::Invalid(Value::from("Data"))));

        let c = entry(r#"{"id":"host.cpu","timeout":10}"#);
        assert_eq!(c.timeout, Some(Lenient::Invalid(Value::from(10))));

        let c = entry(r#"{"id":"host.cpu","fix":["a"]}"#);
        assert!(matches!(c.fix, Some(Lenient::Invalid(_))));
    }

    #[test]
    fn timeout_is_kept_only_from_one_to_sixty_seconds() {
        for ok in ["1s", "1000ms", "60s", "1m", "10s"] {
            assert!(CheckTimeout::parse(ok).is_ok(), "{ok}");
            let c = entry(&format!(r#"{{"id":"host.cpu","timeout":"{ok}"}}"#));
            assert!(
                c.timeout.as_ref().and_then(Lenient::valid).is_some(),
                "{ok}"
            );
        }
        for bad in [
            "500ms", "999ms", "61s", "90s", "2m", "1h", "10 s", "0s", "ten", "",
        ] {
            assert!(CheckTimeout::parse(bad).is_err(), "{bad}");
            let c = entry(&format!(r#"{{"id":"host.cpu","timeout":"{bad}"}}"#));
            assert_eq!(c.timeout, Some(Lenient::Invalid(Value::from(bad))), "{bad}");
        }
        let c = entry(r#"{"id":"host.cpu","timeout":60}"#);
        assert!(matches!(c.timeout, Some(Lenient::Invalid(_))));
        // The text as written comes back out.
        let c = entry(r#"{"id":"host.cpu","timeout":"1m"}"#);
        let back = serde_json::to_value(&c).expect("value");
        assert_eq!(back["timeout"], "1m");
        let err = CheckTimeout::parse("90s").unwrap_err();
        assert_eq!(err.to_string(), "timeout must be between 1s and 60s");
    }

    #[test]
    fn fix_is_kept_only_from_one_to_two_thousand_characters() {
        assert!(FixText::new("a").is_ok());
        assert!(FixText::new("a".repeat(2000)).is_ok());
        assert!(FixText::new("\u{e9}".repeat(2000)).is_ok());
        assert!(FixText::new("").is_err());
        assert!(FixText::new("a".repeat(2001)).is_err());
        let c = entry(r#"{"id":"host.cpu","fix":""}"#);
        assert_eq!(c.fix, Some(Lenient::Invalid(Value::from(""))));
        let long = "a".repeat(2001);
        let c = entry(&format!(r#"{{"id":"host.cpu","fix":"{long}"}}"#));
        assert!(matches!(c.fix, Some(Lenient::Invalid(_))));
    }

    #[test]
    fn a_malformed_id_is_kept_and_reported_by_check_id() {
        let c = entry(r#"{"id":"memroy","min":"1Gi"}"#);
        assert_eq!(c.id, "memroy");
        assert!(matches!(
            c.check_id(),
            Err(SpecError::InvalidCheckId { .. })
        ));
    }

    #[test]
    fn a_missing_or_non_text_id_rejects_the_entry() {
        assert!(serde_json::from_str::<CheckSpec>(r#"{"severity":"warn"}"#).is_err());
        assert!(serde_json::from_str::<CheckSpec>(r#"{"id":7}"#).is_err());
        assert!(serde_json::from_str::<CheckSpec>(r#"["host.cpu"]"#).is_err());
    }

    #[test]
    fn bad_entries_do_not_reject_the_spec_and_round_trip_as_written() {
        let json = r#"{
            "apiVersion": "rdy/v1", "kind": "Readiness", "metadata": {"product": "a"},
            "checks": [
                {"id": "host.cpu", "min": 4},
                {"id": "host.memory", "severity": "blok", "min": "1Gi"},
                {"id": "host.disk", "os": ["rhel"], "path": "/", "min": "1Gi"},
                {"id": "memroy", "name": "Data", "timeout": 10}
            ]
        }"#;
        let spec: Spec = serde_json::from_str(json).expect("the file must still parse");
        assert_eq!(spec.checks.len(), 4);
        assert_eq!(spec.checks[0].effective_severity(), Severity::Block);
        let again: Spec =
            serde_json::from_str(&serde_json::to_string(&spec).expect("serialize")).expect("again");
        assert_eq!(again, spec);
        let out = serde_json::to_value(&spec).expect("value");
        assert_eq!(out["checks"][1]["severity"], "blok");
        assert_eq!(out["checks"][3]["timeout"], 10);
    }

    #[test]
    fn serial_is_capped_at_two_to_the_53_minus_one() {
        let ok = format!(r#"{{"product":"a","serial":{MAX_SERIAL}}}"#);
        assert_eq!(
            serde_json::from_str::<Metadata>(&ok).expect("max").serial,
            Some(MAX_SERIAL)
        );
        let bad = format!(r#"{{"product":"a","serial":{}}}"#, MAX_SERIAL + 1);
        let err = serde_json::from_str::<Metadata>(&bad).expect_err("too big");
        assert!(err.to_string().contains("serial"), "{err}");
        assert!(serde_json::from_str::<Metadata>(r#"{"product":"a","serial":-1}"#).is_err());
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
        assert_eq!(b.max_size, Some(Quantity::parse("200Mi").unwrap()));
        let again: BundleSpec =
            serde_json::from_str(&serde_json::to_string(&b).expect("serialize")).expect("again");
        assert_eq!(again, b);
        let n: BundleSpec = serde_json::from_str(r#"{"max_size":1048576}"#).expect("parse");
        assert_eq!(n.max_size, Some(Quantity::parse("1048576").unwrap()));
    }

    #[test]
    fn bundle_refuses_a_bad_max_size() {
        for bad in [r#""200M""#, r#""200 Mi""#, "1.5", "-1", "1000000000000000"] {
            let json = format!(r#"{{"max_size":{bad}}}"#);
            assert!(serde_json::from_str::<BundleSpec>(&json).is_err(), "{bad}");
        }
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

    /// The shape of `examples/specs/acme-platform.yaml`, written as JSON. The YAML version is tested
    /// in `tests/parse.rs`.
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
