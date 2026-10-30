//! Value types shared by the parameter structs of the check ids.
//!
//! Each type here is a `$defs` entry of the spec schema (`crates/rdy-spec/schema/spec.v1.schema.json`)
//! or a small piece of one. A value that is out of range is refused while it is read, with a message
//! that says what the range is. Messages echo refused text escaped and cut, because a spec is untrusted.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::ops::Deref;

use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer};

use crate::error::echo_safe;
use crate::scalar::Target;

/// Builds a deserialize error from a message.
fn bad<E: de::Error>(message: impl fmt::Display) -> E {
    E::custom(message)
}

/// The longest host with an optional port, in characters: a 253 character name, a colon and a 5 digit
/// port.
pub(crate) const MAX_HOST_PORT_CHARS: usize = 259;

/// Reads the text of a host that may carry a port, for a check with a default port.
///
/// Returns the text to give [`Target::parse`], with the default port added when the text has none, and
/// whether the port was written. A bare IPv6 address (`fd00::1`), a bracketed one (`[fd00::1]`) and
/// either with a port (`[fd00::1]:123`) are all read. Returns `None` for a character a host never
/// holds, so a URL, user info and a space are refused before [`Target::parse`] sees them.
pub(crate) fn host_with_default_port(text: &str, default_port: u16) -> Option<(String, bool)> {
    let fits = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']');
    if text.is_empty() || text.chars().count() > MAX_HOST_PORT_CHARS || !text.chars().all(fits) {
        return None;
    }
    Some(if text.parse::<std::net::Ipv6Addr>().is_ok() {
        (format!("[{text}]:{default_port}"), false)
    } else if text.starts_with('[') && text.ends_with(']') {
        (format!("{text}:{default_port}"), false)
    } else if text.contains(':') {
        (text.to_owned(), true)
    } else {
        (format!("{text}:{default_port}"), false)
    })
}

/// A TCP or UDP port, 1 to 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(u16);

impl Port {
    /// The port number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(deserializer)?;
        match u16::try_from(n) {
            Ok(port) if port >= 1 => Ok(Self(port)),
            _ => Err(bad(format!("a port is 1 to 65535, not {n}"))),
        }
    }
}

/// A count of CPU cores, 1 to 4096.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cores(u16);

impl Cores {
    /// The number of cores.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Cores {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(deserializer)?;
        match u16::try_from(n) {
            Ok(cores) if (1..=4096).contains(&cores) => Ok(Self(cores)),
            _ => Err(bad(format!("a core count is 1 to 4096, not {n}"))),
        }
    }
}

/// A CPU architecture name. `amd64` means `x86_64` and `arm64` means `aarch64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum Arch {
    /// 64-bit x86.
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64-bit Arm.
    #[serde(rename = "aarch64")]
    Aarch64,
    /// Another name for `x86_64`.
    #[serde(rename = "amd64")]
    Amd64,
    /// Another name for `aarch64`.
    #[serde(rename = "arm64")]
    Arm64,
}

/// An absolute path: `/...` on Unix or `C:\...` on Windows, at most 1024 characters.
///
/// The text is kept as written. The check resolves it. A path never reaches a shell. A control
/// character, which includes NUL, is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AbsPath(String);

impl AbsPath {
    /// The longest path in characters.
    pub const MAX_CHARS: usize = 1024;

    /// The path as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AbsPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut chars = text.chars();
        let absolute = match (chars.next(), chars.next(), chars.next()) {
            (Some('/'), _, _) => true,
            (Some(drive), Some(':'), Some('\\')) => drive.is_ascii_alphabetic(),
            _ => false,
        };
        if !absolute {
            return Err(bad(format!(
                "'{}' is not an absolute path: start it with / or a drive such as C:\\",
                echo_safe(&text)
            )));
        }
        if text.chars().count() > Self::MAX_CHARS {
            return Err(bad(format!(
                "a path is at most {} characters",
                Self::MAX_CHARS
            )));
        }
        if text.chars().any(char::is_control) {
            return Err(bad("a path has a control character"));
        }
        Ok(Self(text))
    }
}

/// A fraction of one hundred, 0 to 20, such as the 5 of `tolerance_percent: 5`. It may have a decimal
/// part.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TolerancePercent(f64);

// A value read from a spec is finite and in 0 to 20, so it never compares unequal to itself.
impl Eq for TolerancePercent {}

impl TolerancePercent {
    /// The tolerance when the spec does not set one.
    pub const DEFAULT: Self = Self(5.0);

    /// The percent, from 0 to 20.
    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl Default for TolerancePercent {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl<'de> Deserialize<'de> for TolerancePercent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = f64::deserialize(deserializer)?;
        if (0.0..=20.0).contains(&n) {
            Ok(Self(n))
        } else {
            Err(bad(format!("a tolerance is 0 to 20 percent, not {n}")))
        }
    }
}

/// Defines a text value of 1 to `$max` characters from a closed alphabet.
macro_rules! restricted_text {
    ($(#[$meta:meta])* $name:ident, max $max:literal, $alphabet:literal, $allowed:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The text as written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                let allowed: fn(char) -> bool = $allowed;
                if (1..=$max).contains(&text.chars().count()) && text.chars().all(allowed) {
                    Ok(Self(text))
                } else {
                    Err(bad(format!(
                        "'{}' does not fit: use 1 to {} characters from {}",
                        echo_safe(&text),
                        $max,
                        $alphabet
                    )))
                }
            }
        }
    };
}

restricted_text!(
    /// A CPU feature name such as `avx2` or `x86-64-v3`.
    CpuFlag, max 32, "a-z, 0-9, _ and -", |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
);

restricted_text!(
    /// A filesystem type name such as `nfs` or `ext4`.
    FsType, max 32, "a-z, 0-9, _ and .", |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.'
);

restricted_text!(
    /// A distribution id from `/etc/os-release`, such as `rhel` or `ubuntu`.
    DistroId, max 32, "a-z, 0-9, _, . and -", |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
);

restricted_text!(
    /// A container storage driver name such as `overlay2` or `fuse-overlayfs`.
    StorageDriver, max 32, "a-z, 0-9, _, . and -", |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
);

restricted_text!(
    /// A cgroup controller name such as `cpu`, `memory`, `io` or `pids`.
    CgroupController, max 32, "a-z, 0-9 and _", |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
);

restricted_text!(
    /// A kernel module name such as `overlay`, `br_netfilter` or `xt_TCPMSS`.
    ModuleName, max 64, "letters, 0-9, _ and -", |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
);

/// A distribution version such as `9` or `22.04`, at most 32 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsVersion(String);

impl OsVersion {
    /// The version as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OsVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.chars().count() <= 32 {
            Ok(Self(text))
        } else {
            Err(bad("a version is at most 32 characters"))
        }
    }
}

/// An item of a list of names, such as a process name: 1 to 256 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListText(String);

impl ListText {
    /// The text as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ListText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if (1..=256).contains(&text.chars().count()) {
            Ok(Self(text))
        } else {
            Err(bad("a list item is 1 to 256 characters"))
        }
    }
}

/// A regular expression as written, 1 to 256 characters.
///
/// This type checks the length only. rdy-spec has no regex engine, so a pattern that does not compile
/// is found by the lint and sign steps and, as a last stop, by the check that uses it. The text is
/// kept as written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegexText(String);

impl RegexText {
    /// The longest pattern in characters.
    pub const MAX_CHARS: usize = 256;

    /// The start of the message for a pattern of the wrong length.
    #[cfg(test)]
    pub(crate) const LENGTH_RULE: &'static str = "a pattern is 1 to";

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RegexText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if (1..=Self::MAX_CHARS).contains(&text.chars().count()) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "a pattern is 1 to {} characters",
                Self::MAX_CHARS
            )))
        }
    }
}

/// A list of `MIN` to `MAX` items. With `UNIQUE` set, a repeated item is refused. `MIN` is 0 unless set,
/// and 1 where an empty list would be a threshold that measures nothing.
///
/// It reads as a plain YAML list and derefs to a slice.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedList<T, const MAX: usize, const UNIQUE: bool = false, const MIN: usize = 0>(
    Vec<T>,
);

/// A list of names with the limits of the schema's `StringList`: at most 256 items of 1 to 256
/// characters.
pub type StringList = BoundedList<ListText, 256>;

impl<T, const MAX: usize, const UNIQUE: bool, const MIN: usize> Deref
    for BoundedList<T, MAX, UNIQUE, MIN>
{
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'a, T, const MAX: usize, const UNIQUE: bool, const MIN: usize> IntoIterator
    for &'a BoundedList<T, MAX, UNIQUE, MIN>
{
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de, T, const MAX: usize, const UNIQUE: bool, const MIN: usize> Deserialize<'de>
    for BoundedList<T, MAX, UNIQUE, MIN>
where
    T: Deserialize<'de> + Eq + Hash,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        if items.len() < MIN {
            return Err(bad(format!(
                "a list has {} items, at least {MIN} needed",
                items.len()
            )));
        }
        if items.len() > MAX {
            return Err(bad(format!(
                "a list has at most {MAX} items, this one has {}",
                items.len()
            )));
        }
        if UNIQUE {
            let mut seen = HashSet::new();
            if !items.iter().all(|item| seen.insert(item)) {
                return Err(bad("a list must not repeat an item"));
            }
        }
        Ok(Self(items))
    }
}

/// A map of `MIN` to `MAX` entries. `MIN` is 0 unless set, and 1 where an empty map would be a threshold
/// that measures nothing. The entries are kept sorted by key.
///
/// It reads as a plain YAML mapping and derefs to a `BTreeMap`. A key or a value that does not fit is
/// refused with the message of its own reader.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedMap<K, V, const MAX: usize, const MIN: usize = 0>(BTreeMap<K, V>);

impl<K, V, const MAX: usize, const MIN: usize> Deref for BoundedMap<K, V, MAX, MIN> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

impl<'a, K, V, const MAX: usize, const MIN: usize> IntoIterator for &'a BoundedMap<K, V, MAX, MIN> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de, K, V, const MAX: usize, const MIN: usize> Deserialize<'de> for BoundedMap<K, V, MAX, MIN>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = BTreeMap::<K, V>::deserialize(deserializer)?;
        if entries.len() < MIN {
            return Err(bad(format!(
                "a map has {} entries, at least {MIN} needed",
                entries.len()
            )));
        }
        if entries.len() > MAX {
            return Err(bad(format!(
                "a map has at most {MAX} entries, this one has {}",
                entries.len()
            )));
        }
        Ok(Self(entries))
    }
}

/// A `host:port` that a check or the product connects to: a name, an IPv4 address or a bracketed IPv6
/// address, and a port. A URL is refused.
///
/// It is read with the grammar of [`Target`]. Parsing does not classify an address: a check that
/// connects applies the egress policy of ADR 0009 first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPort(Target);

impl HostPort {
    /// The host and port.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HostPort {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let target = Target::parse(&text).map_err(bad)?;
        if target.is_url() {
            return Err(bad(format!(
                "'{}' is a URL: write host:port",
                echo_safe(&crate::scalar::redact_for_echo(&text))
            )));
        }
        Ok(Self(target))
    }
}

/// Reads `value` as `T` for a type that cannot use a derived reader, with an error that keeps the
/// message of the inner reader.
pub(crate) fn from_value<T: DeserializeOwned, E: de::Error>(
    value: serde_json::Value,
) -> Result<T, E> {
    serde_json::from_value(value).map_err(|e| bad(e))
}

/// The keys that the struct `P` itself accepts, read from serde's own refusal of an unknown key.
///
/// A test compares this with [`ParamSet::FIELDS`](super::ParamSet::FIELDS), so the list that names
/// unknown fields in a reason cannot drift from the struct. It needs `#[serde(deny_unknown_fields)]`
/// on `P`.
#[cfg(test)]
pub(crate) fn serde_fields_of<P: super::ParamSet>() -> std::collections::BTreeSet<String> {
    let probe = serde_json::json!({ "__rdy_probe__": 1 });
    let message = match serde_json::from_value::<P>(probe) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("the struct accepted an unknown key: add deny_unknown_fields"),
    };
    // serde says "unknown field `x`, expected one of `a`, `b`", "..., expected `a`" or
    // "..., there are no fields".
    let (_, expected) = message
        .split_once("`, ")
        .unwrap_or_else(|| panic!("unexpected serde message: {message}"));
    expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}
