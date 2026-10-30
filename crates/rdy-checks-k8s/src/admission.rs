//! `k8s.admission`: what can reject the product's pods (03 section 4, M1 half: M1-114).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - the target `Namespace` by name: the Pod Security labels (`pod-security.kubernetes.io/enforce`, `audit`,
//!   `warn` and `enforce-version`) and, on OpenShift, the `openshift.io/sa.scc.uid-range` annotation. The
//!   namespace is the spec's `namespace`, else the family's;
//! - `GET /apis`, the group list: `security.openshift.io` means OpenShift, and the groups of Kyverno
//!   (`kyverno.io`, `policies.kyverno.io`) and Gatekeeper (`templates.gatekeeper.sh`,
//!   `constraints.gatekeeper.sh`) mean the engine is installed (see [`engines`]);
//! - `GET /apis/<group>/<version>` for each engine group that is served, to name the kinds it serves
//!   (at most four requests);
//! - on OpenShift, when the spec names an `scc`: the `SecurityContextConstraints` list, one page, for the
//!   names only.
//!
//! That is at most seven requests. Nothing is created and no pod is tried: the dry-run `POST` of 03 is an
//! M2 mode behind its own ADR, and the guard refuses it.
//!
//! How the spec's bounds apply (`pod_security`, `uses`, `namespace`, `scc`):
//!
//! - The level the product needs is the most permissive of `pod_security` and the levels of the `uses`:
//!   hostPath, host networking, the host PID namespace and privileged containers need `privileged`, running
//!   as root needs `baseline`. A spec with neither key judges no level and only reports what it found.
//! - A namespace that **enforces** a stricter level blocks. A stricter **warn** or **audit** label warns.
//! - No enforce label is the cluster default, which the API does not show (it lives in the API server's
//!   admission configuration). That is a note. On RKE2 it also makes the result "not verified", because the
//!   hardened profile defaults to `restricted`.
//! - OpenShift without an `scc` in the spec warns with the SCC text. With one, it passes and says how to
//!   bind it. Pod Security labels still apply on OpenShift, but only `warn` and `audit` are synced from the
//!   SCCs, so the SCC is the real gate.
//! - A policy engine group warns with the engine's name, the groups and the kinds. A group is evidence of
//!   an install, not of an enforcing policy.
//!
//! Anything the identity may not read is not evaluated, never a block: a namespace it may not get (grant
//! `get namespaces`), a group list it may not get (grant `get /apis`).
//!
//! Not in this half (M1-160): admission webhooks, `ValidatingAdmissionPolicy`, and the policies themselves.
//! Every result says so in a note.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::{K8sAdmission, K8sName};

use crate::client::guard::RULE_PATH_SHAPE;
use crate::client::{KubeError, ReadOnlyClient};
use crate::cluster::Cluster;

mod engines;
mod fix;
mod judge;
mod level;
mod scc;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use engines::{FoundGroup, OPENSHIFT_GROUP};
use judge::{Gathered, NsFacts, Openshift};
use level::{Labels, need_of};
use scc::Scc;

/// The most SCCs one read asks for. A longer list is read as its first page.
const PAGE: u32 = 500;

/// Below this much time left, the optional reads are skipped.
const MIN_LEFT: Duration = Duration::from_millis(500);

/// The static facts about `k8s.admission` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.admission",
    family: "k8s",
    summary: "Pod Security labels, policy engines and OpenShift SCCs that can reject the product's pods",
    meta: CheckMeta {
        title: "Admission",
        remediation: "Set the Pod Security level of the install namespace to what the product needs: `kubectl label ns <namespace> pod-security.kubernetes.io/enforce=<level> --overwrite`. On OpenShift, grant the SCC the vendor documents: `oc adm policy add-scc-to-user <scc> -z <service-account> -n <namespace>`. If a policy engine is installed, ask the platform team which policies apply to the namespace.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(30)),
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `k8s.admission`, built from its spec entry.
pub struct AdmissionCheck {
    params: K8sAdmission,
    namespace: Option<K8sName>,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for AdmissionCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionCheck")
            .field("params", &self.params)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl AdmissionCheck {
    /// The check for `params`, reading `cluster`.
    ///
    /// `namespace` is the target namespace of the k8s block of the spec. The entry's own `namespace` wins
    /// over it. With neither, the Pod Security labels are not read.
    #[must_use]
    pub fn new(
        params: K8sAdmission,
        namespace: Option<K8sName>,
        cluster: Arc<dyn Cluster>,
    ) -> Self {
        Self {
            params,
            namespace,
            cluster,
        }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for AdmissionCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let gathered = self.gather(ctx).await?;
            Ok(judge::judge(
                &self.params,
                need_of(&self.params).as_ref(),
                &gathered,
            ))
        })
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

/// The answer to a read the server may refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Read<T> {
    Ok(T),
    /// 403: the identity may not read it.
    Forbidden,
    /// 404: it does not exist here.
    Missing,
    /// Any other status of the server.
    Unreadable(u16),
    /// A list longer than the page rdy reads, and the answer was not in the first page.
    Cut,
    /// The check ran out of time before it asked.
    OutOfTime,
}

impl<T> Read<T> {
    /// Why the read gave nothing, as a phrase.
    pub(crate) fn why(&self) -> String {
        match self {
            Self::Ok(_) => "it was read".to_owned(),
            Self::Forbidden => "the identity may not read it".to_owned(),
            Self::Missing => "the server does not have it".to_owned(),
            Self::Unreadable(code) => format!("the server answered {code}"),
            Self::Cut => "the list is longer than the first page".to_owned(),
            Self::OutOfTime => "rdy ran out of time".to_owned(),
        }
    }
}

/// How a failed request becomes a [`KubeError`]: `Cluster::map_error`, which knows the connection.
type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> KubeError + Sync);

/// Sorts the result of one request. A refusal for this identity, a missing object and another status of the
/// server are answers. Anything else (the network, the credentials, the guard) fails the check.
/// `shape_is_missing` reads the guard's refusal of a group or version that cannot be one as "not served".
fn read<T, U>(
    mapper: Mapper<'_>,
    result: Result<T, kube::Error>,
    shape_is_missing: bool,
    map: impl FnOnce(T) -> U,
) -> Result<Read<U>, CheckError> {
    match result {
        Ok(value) => Ok(Read::Ok(map(value))),
        Err(error) => match mapper(&error) {
            KubeError::Forbidden { .. } => Ok(Read::Forbidden),
            KubeError::Api { code: 404, .. } => Ok(Read::Missing),
            KubeError::Api { code, .. } => Ok(Read::Unreadable(code)),
            KubeError::Refused { rule, .. } if shape_is_missing && rule == RULE_PATH_SHAPE => {
                Ok(Read::Missing)
            }
            other => Err(CheckError::Failed {
                message: other.to_string(),
                hint: other.hint(),
            }),
        },
    }
}

/// True when too little of the check's time is left to ask the cluster another question.
fn out_of_time(ctx: &CheckContext) -> bool {
    ctx.remaining() < MIN_LEFT
}

/// One group of `/apis`: its name and the version discovery should be asked for (the preferred one).
type Group = (String, Option<String>);

impl AdmissionCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let namespace = self
            .params
            .namespace
            .as_ref()
            .or(self.namespace.as_ref())
            .map(|name| name.as_str().to_owned());

        // The namespace is the main read, so it goes first.
        let ns = match &namespace {
            Some(name) => Some(read_namespace(&mapper, &client, name).await?),
            None => None,
        };

        let listed: Read<Vec<Group>> = if out_of_time(ctx) {
            Read::OutOfTime
        } else {
            read(&mapper, client.api_groups().await, false, |list| {
                list.groups
                    .into_iter()
                    .map(|group| {
                        let preferred = group
                            .preferred_version
                            .map(|version| version.version)
                            .or_else(|| group.versions.first().map(|v| v.version.clone()));
                        (group.name, preferred)
                    })
                    .collect()
            })?
        };
        let (openshift, groups_read, engines) = match &listed {
            Read::Ok(groups) => {
                let openshift = if groups.iter().any(|(name, _)| name == OPENSHIFT_GROUP) {
                    Openshift::Yes
                } else {
                    Openshift::No
                };
                let engines = self.read_engines(&mapper, &client, ctx, groups).await?;
                (openshift, Read::Ok(()), engines)
            }
            Read::Forbidden => (Openshift::Unknown, Read::Forbidden, Vec::new()),
            Read::Missing => (Openshift::Unknown, Read::Missing, Vec::new()),
            Read::Unreadable(code) => (Openshift::Unknown, Read::Unreadable(*code), Vec::new()),
            Read::Cut => (Openshift::Unknown, Read::Cut, Vec::new()),
            Read::OutOfTime => (Openshift::Unknown, Read::OutOfTime, Vec::new()),
        };

        // The SCC list is read only to say whether the SCC the spec names is on the cluster.
        let scc = match (&self.params.scc, openshift) {
            (Some(name), Openshift::Yes) if !out_of_time(ctx) => {
                Some(read_scc(&mapper, &client, name.as_str()).await?)
            }
            _ => None,
        };

        Ok(Gathered {
            namespace,
            ns,
            groups: groups_read,
            openshift,
            engines,
            scc,
            rke2: self.cluster.server_version().git_version.contains("+rke2"),
        })
    }

    /// The kinds each served engine group offers. A group version that cannot be read still counts as
    /// found: `/apis` already showed it.
    async fn read_engines(
        &self,
        mapper: Mapper<'_>,
        client: &ReadOnlyClient,
        ctx: &CheckContext,
        groups: &[Group],
    ) -> Result<Vec<engines::Found>, CheckError> {
        let mut read_groups: Vec<(&'static str, FoundGroup)> = Vec::new();
        for (engine, group) in engines::served(groups) {
            let version = groups
                .iter()
                .find(|(name, _)| name == group)
                .and_then(|(_, version)| version.clone());
            let kinds = match &version {
                Some(version) if !out_of_time(ctx) => read(
                    mapper,
                    client.group_resources(group, version).await,
                    true,
                    |list| {
                        list.resources
                            .into_iter()
                            .filter(|resource| !resource.name.contains('/'))
                            .map(|resource| resource.kind)
                            .collect::<Vec<String>>()
                    },
                )?,
                _ => Read::OutOfTime,
            };
            let (kinds, more) = match kinds {
                Read::Ok(kinds) => engines::cut_kinds(kinds),
                _ => (Vec::new(), 0),
            };
            read_groups.push((
                engine,
                FoundGroup {
                    group,
                    version,
                    kinds,
                    more,
                },
            ));
        }
        Ok(engines::found(read_groups))
    }
}

/// `GET` of the namespace: its Pod Security labels and, on OpenShift, its UID range.
async fn read_namespace(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    name: &str,
) -> Result<Read<NsFacts>, CheckError> {
    read(
        mapper,
        client.all::<Namespace>().get(name).await,
        false,
        |namespace| {
            let labels = namespace.metadata.labels.unwrap_or_default();
            let uid_range = namespace
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get("openshift.io/sa.scc.uid-range"))
                .and_then(|range| scc::uid_range(range));
            NsFacts {
                labels: Labels::from_map(&labels),
                uid_range,
            }
        },
    )
}

/// The SCC list, first page: is `name` on it?
async fn read_scc(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    name: &str,
) -> Result<Read<bool>, CheckError> {
    let listed = read(
        mapper,
        client
            .all::<Scc>()
            .list(&ListParams::default().limit(PAGE))
            .await,
        false,
        |list| {
            let found = list.items.iter().any(|scc| scc.name() == Some(name));
            let more = list
                .metadata
                .continue_
                .as_deref()
                .is_some_and(|token| !token.is_empty());
            (found, more)
        },
    )?;
    Ok(match listed {
        Read::Ok((true, _)) => Read::Ok(true),
        Read::Ok((false, true)) => Read::Cut,
        Read::Ok((false, false)) => Read::Ok(false),
        Read::Forbidden => Read::Forbidden,
        Read::Missing => Read::Missing,
        Read::Unreadable(code) => Read::Unreadable(code),
        Read::Cut => Read::Cut,
        Read::OutOfTime => Read::OutOfTime,
    })
}
