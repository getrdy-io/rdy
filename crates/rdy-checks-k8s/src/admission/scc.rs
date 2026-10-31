//! The OpenShift `SecurityContextConstraints` list, for the names only.
//!
//! k8s-openapi has no type for it, and kube's dynamic object needs a runtime resource description that the
//! read-only client does not hand out. So this is a small resource type of its own, naming the one path the
//! guard allows for it (`GET /apis/security.openshift.io/v1/securitycontextconstraints`, a list). Only the
//! object name is kept: users, groups, volumes and every other field of an SCC are dropped while parsing.

use std::borrow::Cow;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::serde::{Deserialize, Deserializer, de};
use kube::core::ClusterResourceScope;
use serde_json::Value;

/// One SCC, as far as the check reads it: its metadata.
#[derive(Debug, Clone, Default)]
pub(super) struct Scc {
    metadata: ObjectMeta,
}

impl Scc {
    /// The name of the SCC.
    pub(super) fn name(&self) -> Option<&str> {
        self.metadata.name.as_deref()
    }
}

impl<'de> Deserialize<'de> for Scc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let metadata = match value.get("metadata") {
            Some(metadata) => {
                serde_json::from_value(metadata.clone()).map_err(de::Error::custom)?
            }
            None => ObjectMeta::default(),
        };
        Ok(Self { metadata })
    }
}

impl kube::Resource for Scc {
    type DynamicType = ();
    type Scope = ClusterResourceScope;

    fn kind(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("SecurityContextConstraints")
    }

    fn group(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("security.openshift.io")
    }

    fn version(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("v1")
    }

    fn plural(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("securitycontextconstraints")
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

/// The UID range an OpenShift namespace allocates (`openshift.io/sa.scc.uid-range`, `<first>/<size>`), when
/// the annotation has that shape: two decimal numbers of at most 10 digits, the size not zero. Anything
/// else is dropped, so a hostile annotation never reaches a sentence.
pub(super) fn uid_range(annotation: &str) -> Option<String> {
    let (first, size) = annotation.split_once('/')?;
    let number = |text: &str| {
        (1..=10).contains(&text.len())
            && text.bytes().all(|b| b.is_ascii_digit())
            && text.parse::<u64>().is_ok()
    };
    (number(first) && number(size) && size.parse::<u64>().ok()? > 0)
        .then(|| format!("{first}/{size}"))
}
