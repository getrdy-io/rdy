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
    /// The version of the newest history entry whose state is `Completed`: what the cluster runs while an
    /// update is moving it elsewhere.
    completed: Option<String>,
}

impl ClusterVersion {
    /// The version to judge. While an update runs, `desired.version` is where the cluster is going, not
    /// what it runs, so the newest `Completed` history entry is judged. Otherwise `desired.version`, or the
    /// newest history entry when `desired` is missing.
    pub(super) fn version(&self) -> Option<&str> {
        if self.updating()
            && let Some(done) = self.completed.as_deref()
        {
            return Some(done);
        }
        self.target()
    }

    /// The version the cluster is moving to or has reached: `desired.version`, else the newest entry.
    pub(super) fn target(&self) -> Option<&str> {
        self.desired.as_deref().or(self.newest.as_deref())
    }

    /// While an update runs, the newest completed version: what the cluster runs now.
    pub(super) fn updating_from(&self) -> Option<&str> {
        self.updating()
            .then_some(self.completed.as_deref())
            .flatten()
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
            completed: status
                .and_then(|status| status.get("history"))
                .and_then(Value::as_array)
                .and_then(|history| {
                    history
                        .iter()
                        .find(|entry| entry.get("state").and_then(Value::as_str) == Some("Completed"))
                })
                .and_then(|entry| text(entry.get("version"))),
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
