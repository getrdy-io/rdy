//! The OpenShift `ClusterVersion` object, for the one field `k8s.version` reads.
//!
//! k8s-openapi has no type for it, and kube's dynamic object needs a runtime resource description that the
//! read-only client does not hand out. So this is a small resource type of its own, read-only, naming the
//! one path the guard allows for it (`GET /apis/config.openshift.io/v1/clusterversions/version`).

use std::borrow::Cow;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::serde::{Deserialize, Deserializer, de};
use kube::core::ClusterResourceScope;
use serde_json::Value;

/// What `ClusterVersion` says about the version, with the update state.
#[derive(Debug, Clone, Default)]
pub(super) struct ClusterVersion {
    metadata: ObjectMeta,
    /// `status.desired.version`.
    desired: Option<String>,
    /// `status.history[0].version`: the newest entry. The server lists newest first.
    newest: Option<String>,
    /// `status.history[0].state`: `Completed` once the update finished, `Partial` while it runs.
    state: Option<String>,
}

impl ClusterVersion {
    /// The version to judge: `desired.version`, or the newest history entry when `desired` is missing.
    pub(super) fn version(&self) -> Option<&str> {
        self.desired.as_deref().or(self.newest.as_deref())
    }

    /// True while an update is running (`Partial`), so the cluster may not yet run `desired`.
    pub(super) fn updating(&self) -> bool {
        self.state.as_deref() == Some("Partial")
    }
}

impl<'de> Deserialize<'de> for ClusterVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let metadata = match value.get("metadata") {
            Some(metadata) => {
                serde_json::from_value(metadata.clone()).map_err(de::Error::custom)?
            }
            None => ObjectMeta::default(),
        };
        let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
        let status = value.get("status");
        let newest = status
            .and_then(|status| status.get("history"))
            .and_then(|history| history.get(0));
        Ok(Self {
            metadata,
            desired: text(
                status
                    .and_then(|status| status.get("desired"))
                    .and_then(|desired| desired.get("version")),
            ),
            newest: text(newest.and_then(|entry| entry.get("version"))),
            state: text(newest.and_then(|entry| entry.get("state"))),
        })
    }
}

impl kube::Resource for ClusterVersion {
    type DynamicType = ();
    type Scope = ClusterResourceScope;

    fn kind(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("ClusterVersion")
    }

    fn group(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("config.openshift.io")
    }

    fn version(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("v1")
    }

    fn plural(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("clusterversions")
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}
