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
//! `Unknown` stands for two skips. [`CheckParams::unknown_kind`] tells them apart with the list of
//! reserved ids in [`crate::reserved`]: [`UnknownKind::NotInBuild`] for a reserved id this build lacks,
//! [`UnknownKind::UnknownCheck`] for any other.
//!
//! Nothing is ever ignored. A field the parameter struct does not have is [`UnsupportedReason::UnknownField`],
//! because dropping a stricter threshold from a newer spec would turn a failing host into a passing one
//! (ADR 0008).
//!
//! The 17 M1 ids and the 14 M1-late ids have their parameter structs: the 13 host ids from [`HostCpu`]
//! to [`HostKernel`], the 7 net ids from [`NetEgress`] to [`NetBandwidth`], and the 11 k8s ids from
//! [`K8sAccess`] to [`K8sCni`]. A parameter type is additive (01 section 2.7): an id that gains one
//! stops being `not_in_build`, and a spec that already named it with keys the type does not have is
//! [`UnsupportedReason::UnknownField`] from then on.
//!
//! A check that needs a threshold and has none is [`UnsupportedReason::NoThreshold`], not a pass. A bare
//! `- id: host.memory` would otherwise measure nothing and report ready. The same goes for a bare
//! `net.egress` without `endpoints`, a `k8s.rbac` without `can` and a `host.sysctl` without `expect` or
//! `limits`.

use std::collections::HashSet;
use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::SpecError;
use crate::error::{echo_reason, echo_safe};
use crate::reserved::{UnknownKind, is_reserved_id};
use crate::spec::{CheckSpec, Lenient, Spec};
use crate::suggest::did_you_mean;

mod common;
mod host;
mod k8s;
mod net;
#[cfg(test)]
mod testkit;

pub(crate) use common::host_with_default_port;
pub use common::{
    AbsPath, Arch, BoundedList, BoundedMap, CgroupController, Cores, CpuFlag, DistroId, FsType,
    HostPort, ListText, ModuleName, OsVersion, Port, RegexText, StorageDriver, StringList,
    TolerancePercent,
};
pub use host::{
    ApparmorMode, ApparmorPolicy, Bind, CgroupDriver, CgroupVersion, Compare, ContainerRuntime,
    FipsPolicy, HostCgroups, HostContainerRuntime, HostCpu, HostDisk, HostFirewall, HostKernel,
    HostLsm, HostMemory, HostOs, HostPorts, HostSecurityAgents, HostSysctl, HostTimeSync,
    KernelVersion, MountOption, NtpServer, PortRule, SelinuxMode, SelinuxPolicy, SupportedOs,
    SwapPolicy, SysctlLimits, SysctlName, ToleranceResult, ValueRule,
};

pub use k8s::{
    AccessMode, ApiGroup, ApiRef, CpuAmount, CrdRule, CrdVersion, GatewayApi, ImpersonatedUser,
    IngressController, K8sAccess, K8sAdmission, K8sCni, K8sCrds, K8sDns, K8sIngress, K8sName,
    K8sNamespace, K8sNodes, K8sQuantity, K8sRbac, K8sResources, K8sStorageClass, K8sVersion,
    LabelKey, LabelSelector, LabelValue, LimitNeeds, NetworkPolicyMode, NonResourcePath,
    NonResourceRule, OperatorRule, OverMax, PodFeature, PodSecurityLevel, QuotaResource, RbacItem,
    RbacResource, RbacRule, RbacSubresource, RbacVerb, ReclaimPolicy, TaintEffect, Toleration,
    TolerationOperator, VolumeBinding,
};
pub use net::{
    Cidr, DnsName, DnsRule, Endpoint, HttpMethod, HttpStatus, HttpUrl, ImageRef, Mbps, Mtu,
    NetBandwidth, NetDns, NetEgress, NetMtu, NetProxy, NetRegistry, NetTlsIntercept, Overlay,
    RegistryRule, SampleBytes, Sha256Hex, TlsHost, Trust, Underlay, ViaProxy,
};

/// The most characters of a message from the value reader that a reason keeps.
const MAX_REASON_CHARS: usize = 160;

/// A closed set of parameters for one check id.
pub(crate) trait ParamSet: DeserializeOwned {
    /// Every key the check accepts. A key outside this list is refused by name.
    const FIELDS: &'static [&'static str];

    /// The keys of which an entry needs at least one, because without it the check measures nothing.
    /// Empty when the check needs no threshold. An entry with none of them is
    /// [`UnsupportedReason::NoThreshold`].
    const THRESHOLD: &'static [&'static str] = &[];

    /// Keys of [`ParamSet::THRESHOLD`] that are booleans and count only when `true`. A `false` there
    /// measures nothing, so an entry with only that key is [`UnsupportedReason::NoThreshold`].
    const TRUE_ONLY: &'static [&'static str] = &[];

    /// A key and value to show a vendor whose entry has no threshold, such as `min: 4`. Empty when the
    /// check has no one obvious example. Then the fix lists the threshold keys instead.
    const THRESHOLD_EXAMPLE: &'static str = "";

    /// Keys that are required besides the threshold. They are named in a
    /// [`UnsupportedReason::NoThreshold`] when they are missing too, so one message asks for everything.
    const ALSO_REQUIRED: &'static [&'static str] = &[];

    /// The keys whose value is a [`RegexText`]. Lint and sign compile each of them, because
    /// `RegexText` checks the length only. A test finds the regex keys of every struct by trying them,
    /// so a key left out of this list fails it.
    const REGEX_FIELDS: &'static [&'static str] = &[];
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

        /// The example threshold of `id` for a lint fix, or `""` when it has none.
        pub(crate) fn threshold_example_of(id: &str) -> &'static str {
            match id {
                $($id => <$ty as ParamSet>::THRESHOLD_EXAMPLE,)*
                _ => "",
            }
        }

        /// The keys of `id` whose value reads as a [`RegexText`], found by giving each key a text that is
        /// too long for a pattern, for the test that keeps `ParamSet::REGEX_FIELDS` complete.
        #[cfg(test)]
        pub(crate) fn probe_regex_fields(id: &str) -> Option<Vec<&'static str>> {
            fn probe<P: ParamSet>() -> Vec<&'static str> {
                let too_long = "a".repeat(RegexText::MAX_CHARS + 1);
                P::FIELDS
                    .iter()
                    .copied()
                    .filter(|field| {
                        let object = serde_json::json!({ *field: too_long });
                        serde_json::from_value::<P>(object)
                            .err()
                            .is_some_and(|e| e.to_string().contains(RegexText::LENGTH_RULE))
                    })
                    .collect()
            }
            match id {
                $($id => Some(probe::<$ty>()),)*
                _ => None,
            }
        }

        /// The keys of `id` that `rdy spec lint` compiles as patterns.
        #[cfg(test)]
        pub(crate) fn declared_regex_fields(id: &str) -> Option<&'static [&'static str]> {
            match id {
                $($id => Some(<$ty as ParamSet>::REGEX_FIELDS),)*
                _ => None,
            }
        }

        /// Every check id that this build implements.
        pub const KNOWN_IDS: &[&str] = &[$($id),*];

        /// The keys the parameter struct of `id` accepts, or `None` when no check in this build has
        /// that id. Lint offers them as did-you-mean suggestions.
        pub(crate) fn fields_of(id: &str) -> Option<&'static [&'static str]> {
            match id {
                $($id => Some(<$ty as ParamSet>::FIELDS),)*
                _ => None,
            }
        }

        /// The keys the parameter struct of `id` accepts, or `None` when no check in this build has
        /// that id. For did-you-mean advice in `rdy-engine`'s run plan, the same list lint uses.
        ///
        /// Not part of the stable API.
        #[doc(hidden)]
        #[must_use]
        pub fn known_fields(id: &str) -> Option<&'static [&'static str]> {
            fields_of(id)
        }
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
    "host.firewall" => HostFirewall(HostFirewall),
    "host.time_sync" => HostTimeSync(HostTimeSync),
    "host.sysctl" => HostSysctl(HostSysctl),
    "host.container_runtime" => HostContainerRuntime(HostContainerRuntime),
    "host.cgroups" => HostCgroups(HostCgroups),
    "host.kernel" => HostKernel(HostKernel),
    "net.egress" => NetEgress(NetEgress),
    "net.proxy" => NetProxy(NetProxy),
    "net.tls_intercept" => NetTlsIntercept(NetTlsIntercept),
    "net.dns" => NetDns(NetDns),
    "net.registry" => NetRegistry(NetRegistry),
    "net.mtu" => NetMtu(NetMtu),
    "net.bandwidth" => NetBandwidth(NetBandwidth),
    "k8s.access" => K8sAccess(K8sAccess),
    "k8s.storageclass" => K8sStorageClass(K8sStorageClass),
    "k8s.rbac" => K8sRbac(K8sRbac),
    "k8s.admission" => K8sAdmission(K8sAdmission),
    "k8s.nodes" => K8sNodes(K8sNodes),
    "k8s.version" => K8sVersion(K8sVersion),
    "k8s.namespace" => K8sNamespace(K8sNamespace),
    "k8s.dns" => K8sDns(K8sDns),
    "k8s.ingress" => K8sIngress(K8sIngress),
    "k8s.crds" => K8sCrds(K8sCrds),
    "k8s.cni" => K8sCni(K8sCni),
}

impl CheckParams {
    /// Why an [`CheckParams::Unknown`] entry is skipped, or `None` for any other variant.
    #[must_use]
    pub fn unknown_kind(&self) -> Option<UnknownKind> {
        match self {
            Self::Unknown { id, .. } if is_reserved_id(id) => Some(UnknownKind::NotInBuild),
            Self::Unknown { .. } => Some(UnknownKind::UnknownCheck),
            _ => None,
        }
    }
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
    /// A block inside a value has a key the block does not have, such as `prot` in
    /// `free: [{port: 80, prot: tcp}]` of `host.ports`.
    ///
    /// The path names the key from the top of the entry: `free[0].prot`.
    UnknownNestedField {
        /// The path of the key, already cut and escaped so it is safe to print.
        path: String,
        /// The key of that block nearest to the one written, when it is a close match (a typo).
        near: Option<String>,
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
    /// The check needs a threshold and the entry has none, such as a bare `- id: host.memory`.
    ///
    /// A check without a threshold measures nothing, so it is skipped and not passed.
    NoThreshold {
        /// The keys that would fix it. One of them is enough.
        one_of: &'static [&'static str],
        /// Other required keys that the entry also lacks, such as `path` of `host.disk`.
        and: Vec<&'static str>,
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
            Self::UnknownNestedField { path, .. } => write!(f, "cannot read '{path}'"),
            Self::MissingField { field } => write!(f, "'{field}' is required and missing"),
            Self::BadValue {
                field: Some(field),
                message,
            } => write!(f, "the value of '{field}' does not fit: {message}"),
            Self::BadValue {
                field: None,
                message,
            } => write!(f, "a value does not fit: {message}"),
            Self::NoThreshold { one_of, and } => {
                // With one key, "add 'min' and 'path'" reads fine. With several, "and 'path'" would
                // read as part of the list, so the second part is a separate clause.
                let joiner = if one_of.len() > 1 {
                    "; also add "
                } else {
                    " and "
                };
                match one_of {
                    [only] => write!(f, "has no threshold: add '{only}'")?,
                    [init @ .., last] => {
                        write!(f, "has no threshold: add at least one of ")?;
                        for key in init {
                            write!(f, "'{key}', ")?;
                        }
                        write!(f, "or '{last}'")?;
                    }
                    [] => f.write_str("has no threshold")?,
                }
                for (i, key) in and.iter().enumerate() {
                    f.write_str(if i == 0 { joiner } else { " and " })?;
                    write!(f, "'{key}'")?;
                }
                Ok(())
            }
            Self::BadCommonField { field } => write!(f, "the value of '{field}' does not fit"),
        }
    }
}

/// Reads `fields` into the parameter struct `P`, naming the first problem.
fn decode<P: ParamSet>(fields: &Map<String, Value>) -> Result<P, UnsupportedReason> {
    // A top-level unknown key is named from the list of fields, not from serde's message, so the name
    // is the key itself and not a guess at where the key ends. `deny_unknown_fields` stays as a
    // backstop. The first unknown key in sorted order is named, whatever order the map keeps its keys in.
    // An unknown key inside a nested block does come from serde's message: `nested_unknown_field`
    // splits it at the last "`, expected ", which no struct field name contains, and escapes the name.
    if let Some(field) = fields
        .keys()
        .filter(|k| !P::FIELDS.contains(&k.as_str()))
        .min()
    {
        return Err(UnsupportedReason::UnknownField {
            field: echo_safe(field),
        });
    }
    // A key with no value, such as `min:` in YAML, is a mistake and not an absent key. Reading it as
    // absent would drop a threshold silently.
    // This holds at any depth: `selinux: {allow:}` would otherwise allow every mode.
    if let Some(key) = fields.iter().find_map(|(k, v)| has_null(v).then_some(k)) {
        return Err(UnsupportedReason::BadValue {
            field: Some(echo_safe(key)),
            message: "the key has no value: write one, or remove the key".to_owned(),
        });
    }
    let counts = |key: &&str| {
        fields
            .get(*key)
            .is_some_and(|v| !(P::TRUE_ONLY.contains(key) && *v == Value::Bool(false)))
    };
    if !P::THRESHOLD.is_empty() && !P::THRESHOLD.iter().any(counts) {
        return Err(UnsupportedReason::NoThreshold {
            one_of: P::THRESHOLD,
            and: P::ALSO_REQUIRED
                .iter()
                .copied()
                .filter(|key| !fields.contains_key(*key))
                .collect(),
        });
    }
    serde_json::from_value::<P>(Value::Object(fields.clone())).map_err(|e| {
        let message = e.to_string();
        if let Some(reason) = nested_unknown_field(&message, fields) {
            reason
        } else if let Some(field) = missing_field_name::<P>(&message, fields) {
            UnsupportedReason::MissingField {
                field: echo_safe(field),
            }
        } else {
            UnsupportedReason::BadValue {
                field: culprit::<P>(fields, &message),
                message: echo_reason(&message, MAX_REASON_CHARS),
            }
        }
    })
}

/// How deep [`nested_unknown_field`] looks. A parsed spec nests 64 levels at most.
const MAX_SEARCH_DEPTH: usize = 64;

/// Turns serde's refusal of an unknown key inside a nested block into a reason with the path of the key.
///
/// serde says "unknown field `x`, expected one of `a`, `b`" (or "expected `a`", "expected `a` or `b`",
/// "there are no fields"). The names after "expected" come from the struct. The name before it comes from
/// the file, and may hold anything, so the split is at the last "`, expected ", which no struct name can
/// contain. The path is found by searching `fields` for a block that has that key, preferring one whose
/// other keys are all keys the struct expects.
fn nested_unknown_field(message: &str, fields: &Map<String, Value>) -> Option<UnsupportedReason> {
    const EXPECTED: &str = "`, expected ";
    let rest = message.strip_prefix("unknown field `")?;
    let (name, expected) = match rest.rfind(EXPECTED) {
        Some(at) => (&rest[..at], &rest[at + EXPECTED.len()..]),
        None => (rest.strip_suffix("`, there are no fields")?, ""),
    };
    let expected: Vec<&str> = expected.split('`').skip(1).step_by(2).collect();
    let mut found = Search::default();
    for (key, value) in fields {
        walk_blocks(value, key, name, &expected, &mut found, 0);
    }
    let block = found.exact.or(found.any)?;
    Some(UnsupportedReason::UnknownNestedField {
        path: echo_safe(&format!("{block}.{name}")),
        near: did_you_mean(name, &expected).map(echo_safe),
    })
}

/// Where [`walk_blocks`] has found the block with the unknown key.
#[derive(Debug, Default)]
struct Search {
    /// The path of the first block that has the key and no other key the struct does not expect.
    exact: Option<String>,
    /// The path of the first block that has the key.
    any: Option<String>,
}

/// Looks through `value`, whose path is `at`, for blocks that have the key `name`.
fn walk_blocks(
    value: &Value,
    at: &str,
    name: &str,
    expected: &[&str],
    found: &mut Search,
    depth: usize,
) {
    if depth > MAX_SEARCH_DEPTH || found.exact.is_some() {
        return;
    }
    match value {
        Value::Object(map) => {
            if map.contains_key(name) {
                found.any.get_or_insert_with(|| at.to_owned());
                if map
                    .keys()
                    .all(|k| k == name || expected.contains(&k.as_str()))
                {
                    found.exact = Some(at.to_owned());
                    return;
                }
            }
            for (key, inner) in map {
                walk_blocks(
                    inner,
                    &format!("{at}.{key}"),
                    name,
                    expected,
                    found,
                    depth + 1,
                );
            }
        }
        Value::Array(items) => {
            for (i, inner) in items.iter().enumerate() {
                walk_blocks(
                    inner,
                    &format!("{at}[{i}]"),
                    name,
                    expected,
                    found,
                    depth + 1,
                );
            }
        }
        _ => {}
    }
}

/// Whether a value is null, or holds a null in a list or an object at any depth.
fn has_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.iter().any(has_null),
        Value::Object(map) => map.values().any(has_null),
        _ => false,
    }
}

/// The field named by serde's `missing field` message. The name comes from the struct, not the file.
///
/// Only a key of `P` itself that `fields` lacks counts. A nested struct that lacks a key, such as a port
/// object without `port`, gives the same message, and that is a bad value of the outer key.
fn missing_field_name<'m, P: ParamSet>(
    message: &'m str,
    fields: &Map<String, Value>,
) -> Option<&'m str> {
    let rest = message.strip_prefix("missing field `")?;
    let (name, _) = rest.split_once('`')?;
    (P::FIELDS.contains(&name) && !fields.contains_key(name)).then_some(name)
}

/// The key whose value alone makes `P` fail. A required key that is absent is not a culprit.
///
/// A key that fails alone with the very message of the whole entry wins. Otherwise a rule that spans two
/// keys (`min_version` needs `runtime`) would blame the key that sorts first and not the bad one.
fn culprit<P: ParamSet>(fields: &Map<String, Value>, message: &str) -> Option<String> {
    // Sorted, so the key named does not depend on the order the map keeps.
    let mut entries: Vec<(&String, &Value)> = fields.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let failures: Vec<(&String, String)> = entries
        .into_iter()
        .filter_map(|(key, value)| {
            let mut one = Map::new();
            one.insert(key.clone(), value.clone());
            match serde_json::from_value::<P>(Value::Object(one.clone())) {
                Err(e) if missing_field_name::<P>(&e.to_string(), &one).is_none() => {
                    Some((key, e.to_string()))
                }
                _ => None,
            }
        })
        .collect();
    let same = failures.iter().find(|(_, own)| own == message);
    same.or_else(|| failures.first())
        .map(|(key, _)| echo_safe(key))
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
mod late_tests;
#[cfg(test)]
mod tests;
