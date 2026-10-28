//! Step two of check decoding: from the raw parameters of an entry to a [`CheckParams`].
//!
//! `docs/plan/01-spec-format.md` section 2.4 sets the rule. Each check id has its own closed set of
//! parameters, but serde's tagged enums fail a whole file on an unknown id or field, and that would break
//! the skip rule of ADR 0005, 0007 and 0008. So an entry is read in two steps.
//!
//! 1. The entry becomes a [`CheckSpec`]: the common fields and a raw map of every other key. Only a
//!    missing `id` rejects the file.
//! 2. [`CheckSpec::decode_params`] turns the raw map into the parameter struct of the id. It never fails.
//!    What it cannot read becomes a value that says why, so one bad check skips one check.
//!
//! | Result | Meaning | The run reports |
//! | --- | --- | --- |
//! | A typed variant such as [`CheckParams::HostMemory`] | rdy knows the id and reads every field | the check runs |
//! | [`CheckParams::Unknown`] | rdy has no check with this id | `not_in_build` or `unknown_check` |
//! | [`CheckParams::Unsupported`] | rdy knows the id and cannot read a field or a value | `unsupported_spec` |
//!
//! Telling `not_in_build` from `unknown_check` needs the list of reserved ids. That list arrives with the
//! reserved-id lint rule. Until then `Unknown` stands for both.
//!
//! Nothing is ever ignored. A field the parameter struct does not have is [`UnsupportedReason::UnknownField`],
//! because dropping a stricter threshold from a newer spec would turn a failing host into a passing one
//! (ADR 0008).
//!
//! The parameter structs of the 17 M1 ids are placeholders here. They have no fields yet, so every
//! parameter is refused as unknown until the tickets for the host, net and k8s parameters fill them in.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::SpecError;
use crate::error::{echo_reason, echo_safe};
use crate::spec::{CheckSpec, Lenient, Spec};

/// The most characters of a message from the value reader that a reason keeps.
const MAX_REASON_CHARS: usize = 160;

/// A closed set of parameters for one check id.
pub(crate) trait ParamSet: DeserializeOwned {
    /// Every key the check accepts. A key outside this list is refused by name.
    const FIELDS: &'static [&'static str];
}

/// Defines a parameter struct with no fields yet.
macro_rules! placeholder_params {
    ($($id:literal => $name:ident),* $(,)?) => {
        $(
            #[doc = concat!("Parameters of `", $id, "`.")]
            ///
            /// This struct has no fields yet. Any parameter is refused as unknown until the ticket for
            /// this check family adds them.
            #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
            #[serde(deny_unknown_fields)]
            #[non_exhaustive]
            pub struct $name {}

            impl ParamSet for $name {
                const FIELDS: &'static [&'static str] = &[];
            }
        )*
    };
}

placeholder_params! {
    "host.cpu" => HostCpu,
    "host.memory" => HostMemory,
    "host.disk" => HostDisk,
    "host.ports" => HostPorts,
    "host.lsm" => HostLsm,
    "host.security_agents" => HostSecurityAgents,
    "host.os" => HostOs,
    "net.egress" => NetEgress,
    "net.proxy" => NetProxy,
    "net.tls_intercept" => NetTlsIntercept,
    "net.dns" => NetDns,
    "k8s.access" => K8sAccess,
    "k8s.storageclass" => K8sStorageClass,
    "k8s.rbac" => K8sRbac,
    "k8s.admission" => K8sAdmission,
    "k8s.nodes" => K8sNodes,
    "k8s.version" => K8sVersion,
}

/// Defines [`CheckParams`] and the table from check id to parameter struct.
macro_rules! known_checks {
    ($($id:literal => $variant:ident($ty:ident)),* $(,)?) => {
        /// The decoded parameters of one check entry.
        ///
        /// There is one variant per check id that this rdy implements, one for an id it does not have and
        /// one for an entry it cannot read. See the [module documentation](self) for what each means for
        /// a run. The enum is `#[non_exhaustive]`: a new check id is a new variant.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum CheckParams {
            $(
                #[doc = concat!("Parameters of `", $id, "`.")]
                $variant($ty),
            )*
            /// The id is not one of the checks in this build, or is not written as `family.name`.
            ///
            /// The check is skipped. The entry's other fields are not read, because they only have a
            /// meaning for a check that exists.
            Unknown {
                /// The id as written. It is untrusted: strip control characters before printing it.
                id: String,
                /// Every key of the entry that is not a common field, as written.
                fields: Map<String, Value>,
            },
            /// The id is known and the entry cannot be read: a key the check does not have, a missing
            /// required key, a value that does not fit, or a common field that does not fit.
            ///
            /// The check is skipped. A required check that is skipped makes the run NOT READY.
            Unsupported {
                /// The id, which is a known check id.
                id: String,
                /// Every key of the entry that is not a common field, as written.
                fields: Map<String, Value>,
                /// What could not be read, first problem only.
                reason: UnsupportedReason,
            },
        }

        impl CheckParams {
            /// The check id these parameters belong to.
            ///
            /// For a variant that rdy knows this is a fixed id. For [`CheckParams::Unknown`] it is the
            /// text of the entry, which is untrusted.
            #[must_use]
            pub fn id(&self) -> &str {
                match self {
                    $(Self::$variant(_) => $id,)*
                    Self::Unknown { id, .. } | Self::Unsupported { id, .. } => id,
                }
            }
        }

        /// Reads the parameters of `id`, or `None` when no check in this build has that id.
        fn decode_known(
            id: &str,
            fields: &Map<String, Value>,
        ) -> Option<Result<CheckParams, UnsupportedReason>> {
            match id {
                $($id => Some(decode::<$ty>(fields).map(CheckParams::$variant)),)*
                _ => None,
            }
        }

        /// Every check id that this build implements.
        pub const KNOWN_IDS: &[&str] = &[$($id),*];
    };
}

known_checks! {
    "host.cpu" => HostCpu(HostCpu),
    "host.memory" => HostMemory(HostMemory),
    "host.disk" => HostDisk(HostDisk),
    "host.ports" => HostPorts(HostPorts),
    "host.lsm" => HostLsm(HostLsm),
    "host.security_agents" => HostSecurityAgents(HostSecurityAgents),
    "host.os" => HostOs(HostOs),
    "net.egress" => NetEgress(NetEgress),
    "net.proxy" => NetProxy(NetProxy),
    "net.tls_intercept" => NetTlsIntercept(NetTlsIntercept),
    "net.dns" => NetDns(NetDns),
    "k8s.access" => K8sAccess(K8sAccess),
    "k8s.storageclass" => K8sStorageClass(K8sStorageClass),
    "k8s.rbac" => K8sRbac(K8sRbac),
    "k8s.admission" => K8sAdmission(K8sAdmission),
    "k8s.nodes" => K8sNodes(K8sNodes),
    "k8s.version" => K8sVersion(K8sVersion),
}

/// Why an entry for a known check id could not be read. Only the first problem is kept.
///
/// `Display` gives a short phrase for a skip message. Every name and message in it is cut and escaped, so
/// it is safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedReason {
    /// The entry has a key the check does not have, such as `mn` for `min`.
    ///
    /// This may be a typo, or a field from a newer spec. Either way it is not ignored.
    UnknownField {
        /// The key, already cut and escaped so it is safe to print.
        field: String,
    },
    /// A key the check requires is missing.
    MissingField {
        /// The key, already cut and escaped so it is safe to print.
        field: String,
    },
    /// A value does not fit its field, such as `min: 32G`.
    BadValue {
        /// The key whose value is wrong, when it can be told, already cut and escaped.
        field: Option<String>,
        /// What the reader said, already cut and escaped so it is safe to print.
        message: String,
    },
    /// A common field of the entry does not fit: `name`, `severity`, `fix`, `timeout` or `os`.
    ///
    /// An unreadable `severity` still counts as `block` when the verdict is worked out.
    BadCommonField {
        /// The name of the common field.
        field: &'static str,
    },
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownField { field } => write!(f, "cannot read '{field}'"),
            Self::MissingField { field } => write!(f, "'{field}' is required and missing"),
            Self::BadValue {
                field: Some(field),
                message,
            } => write!(f, "the value of '{field}' does not fit: {message}"),
            Self::BadValue {
                field: None,
                message,
            } => write!(f, "a value does not fit: {message}"),
            Self::BadCommonField { field } => write!(f, "the value of '{field}' does not fit"),
        }
    }
}

/// Reads `fields` into the parameter struct `P`, naming the first problem.
fn decode<P: ParamSet>(fields: &Map<String, Value>) -> Result<P, UnsupportedReason> {
    // Naming the field needs a list, because a serde message cannot be taken apart safely when the
    // key is attacker text. The list is checked first and `deny_unknown_fields` stays as a backstop.
    // The first unknown key in sorted order is named, whatever order the map keeps its keys in.
    if let Some(field) = fields
        .keys()
        .filter(|k| !P::FIELDS.contains(&k.as_str()))
        .min()
    {
        return Err(UnsupportedReason::UnknownField {
            field: echo_safe(field),
        });
    }
    serde_json::from_value::<P>(Value::Object(fields.clone())).map_err(|e| {
        let message = e.to_string();
        if let Some(field) = missing_field_name(&message) {
            UnsupportedReason::MissingField {
                field: echo_safe(field),
            }
        } else {
            UnsupportedReason::BadValue {
                field: culprit::<P>(fields),
                message: echo_reason(&message, MAX_REASON_CHARS),
            }
        }
    })
}

/// The field named by serde's `missing field` message. The name comes from the struct, not the file.
fn missing_field_name(message: &str) -> Option<&str> {
    let rest = message.strip_prefix("missing field `")?;
    rest.split_once('`').map(|(name, _)| name)
}

/// The key whose value alone makes `P` fail. A required key that is absent is not a culprit.
fn culprit<P: ParamSet>(fields: &Map<String, Value>) -> Option<String> {
    // Sorted, so the key named does not depend on the order the map keeps.
    let mut entries: Vec<(&String, &Value)> = fields.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries.into_iter().find_map(|(key, value)| {
        let mut one = Map::new();
        one.insert(key.clone(), value.clone());
        match serde_json::from_value::<P>(Value::Object(one)) {
            Err(e) if missing_field_name(&e.to_string()).is_none() => Some(echo_safe(key)),
            _ => None,
        }
    })
}

impl CheckSpec {
    /// Step two of decoding: the typed parameters of this entry. It never fails.
    ///
    /// - An id that is not written as `family.name`, or that no check in this build has, gives
    ///   [`CheckParams::Unknown`].
    /// - A known id whose common fields do not fit (a [`Lenient::Invalid`] `name`, `severity`, `fix`,
    ///   `timeout` or `os`) gives [`CheckParams::Unsupported`] with [`UnsupportedReason::BadCommonField`].
    /// - A known id whose parameters have an unknown key, miss a required key or hold a bad value gives
    ///   [`CheckParams::Unsupported`] with the matching reason.
    /// - Anything else gives the typed variant.
    ///
    /// Use [`CheckSpec::effective_severity`] for the severity, also when this returns `Unknown` or
    /// `Unsupported`: a skipped required check still blocks the verdict.
    #[must_use]
    pub fn decode_params(&self) -> CheckParams {
        let unknown = || CheckParams::Unknown {
            id: self.id.clone(),
            fields: self.params.clone(),
        };
        let Ok(id) = self.check_id() else {
            return unknown();
        };
        let Some(decoded) = decode_known(id.as_str(), &self.params) else {
            return unknown();
        };
        let unsupported = |reason| CheckParams::Unsupported {
            id: self.id.clone(),
            fields: self.params.clone(),
            reason,
        };
        if let Some(field) = self.bad_common_field() {
            return unsupported(UnsupportedReason::BadCommonField { field });
        }
        decoded.unwrap_or_else(unsupported)
    }

    /// The first common field that was written and does not fit, in the order of the spec reference.
    fn bad_common_field(&self) -> Option<&'static str> {
        fn bad<T>(slot: Option<&Lenient<T>>) -> bool {
            matches!(slot, Some(Lenient::Invalid(_)))
        }
        if bad(self.name.as_ref()) {
            Some("name")
        } else if bad(self.severity.as_ref()) {
            Some("severity")
        } else if bad(self.fix.as_ref()) {
            Some("fix")
        } else if bad(self.timeout.as_ref()) {
            Some("timeout")
        } else if bad(self.os.as_ref()) {
            Some("os")
        } else {
            None
        }
    }
}

impl Spec {
    /// Decodes every check entry, in order. The result has one [`CheckParams`] per entry of
    /// [`Spec::checks`], so the two lists line up by index.
    ///
    /// # Errors
    ///
    /// [`SpecError::DuplicateCheck`] when two entries have the same key. The key is the `id`, or the
    /// `id` and `name` when there is a name. A [`Lenient::Invalid`] name has no key, because that entry
    /// is skipped anyway. [`crate::parse_unverified`] reports the same error with a line and column.
    pub fn decode_checks(&self) -> Result<Vec<CheckParams>, SpecError> {
        if let Some((_, error)) = find_duplicate(&self.checks) {
            return Err(error);
        }
        Ok(self.checks.iter().map(CheckSpec::decode_params).collect())
    }
}

/// The index and error of the first entry whose key an earlier entry already has.
pub(crate) fn find_duplicate(checks: &[CheckSpec]) -> Option<(usize, SpecError)> {
    let mut seen: HashSet<(&str, Option<&str>)> = HashSet::new();
    for (index, check) in checks.iter().enumerate() {
        let name = match &check.name {
            None => None,
            Some(Lenient::Valid(name)) => Some(name.as_str()),
            Some(Lenient::Invalid(_)) => continue,
        };
        if !seen.insert((check.id.as_str(), name)) {
            let error = SpecError::DuplicateCheck {
                id: echo_safe(&check.id),
                name: name.map(str::to_owned),
            };
            return Some((index, error));
        }
    }
    None
}

#[cfg(test)]
mod tests;
