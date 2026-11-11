//! `k8s.admission`: what can reject the product's pods (03 section 4: M1-114 and M1-160).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - the target `Namespace` by name: the Pod Security labels (`pod-security.kubernetes.io/enforce`, `audit`,
//!   `warn` and `enforce-version`), every other label (for the selectors below) and, on OpenShift, the
//!   `openshift.io/sa.scc.uid-range` annotation. The namespace is the spec's `namespace`, else the family's;
//! - `GET /apis`, the group list: `security.openshift.io` means OpenShift, and the groups of Kyverno
//!   (`kyverno.io`, `policies.kyverno.io`) and Gatekeeper (`templates.gatekeeper.sh`,
//!   `constraints.gatekeeper.sh`) mean the engine is installed (see [`engines`]);
//! - `GET /apis/<group>/<version>` for each engine group that is served, to name the kinds it serves
//!   (at most four requests), and `GET /apis/kyverno.io/v1` when that group lists `v1`, `v1` is not the
//!   preferred version and the preferred version did not show `ClusterPolicy` or `Policy` (one more
//!   request): the server prefers `v2`, which holds `PolicyException` and never the legacy kinds. When the
//!   preferred version of a group may not be read, `v1` is not asked either: the answer would be the same
//!   refusal, and the legacy kinds are left unknown;
//! - on OpenShift, when the spec names an `scc`: the `SecurityContextConstraints` list, one page, for the
//!   names only;
//! - (M1-160) the validating and the mutating webhook configurations, one page each; for each `Fail`
//!   webhook that applies, its Service and `EndpointSlice` list, at most eight Services; the
//!   `ValidatingAdmissionPolicy` list and, when it holds a policy, the binding list; and the engines' own
//!   policies: Kyverno `ClusterPolicy`, `ValidatingPolicy` and `ImageValidatingPolicy`, and one list per
//!   Gatekeeper constraint kind (at most eight policy lists in all, ADR 0042).
//!
//! That is at most 36 requests, all `GET`. Nothing is created and no pod is tried: the dry-run `POST` of 03
//! is an M2 mode behind its own ADR, and the guard refuses it.
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
//!   an install, not of an enforcing policy; the policy lists name the ones that reject.
//! - A `Fail` webhook that applies to a pod create and has no ready endpoint blocks. What may exempt a pod
//!   (`matchConditions`, an `objectSelector`) or what rdy cannot check (a URL backend) is "not evaluated".
//!   A `ValidatingAdmissionPolicy` binding that denies and applies warns, by name.
//!
//! Anything the identity may not read is not evaluated, never a block: a namespace it may not get (grant
//! `get namespaces`), a group list it may not get (grant `get /apis`), a webhook, policy or endpoint list it
//! may not make (the grant names the list).

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
    ValidatingWebhookConfiguration,
};
use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::ListParams;
use kube::core::{ApiResource, GroupVersionKind};
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
mod matching;
mod policies;
mod scc;
mod vap;
mod webhooks;

#[cfg(test)]
mod late_unit_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use engines::{Found, FoundGroup, Group, OPENSHIFT_GROUP};
use judge::{Gathered, NsFacts, Openshift};
use level::{Labels, need_of};
use matching::NsLabels;
use policies::{ApiKind, EnginePolicies, PolicyList, PolicyRead};
use scc::Scc;
use vap::Policies;
use webhooks::{BackendState, ReadGrant, ServiceRead, Webhooks};

/// The most SCCs one read asks for. A longer list is read as its first page.
const PAGE: u32 = 500;

/// The most requests one run makes: the namespace, `/apis`, up to four group versions and the legacy
/// Kyverno one, the SCC list (8 in all, M1-114); both webhook lists and both admission policy lists; a
/// Service list and a slice list for each of [`webhooks::MAX_SERVICES`] Services; and the policy lists.
#[cfg(test)]
const MAX_REQUESTS: usize = 8 + 2 + 2 + 2 * webhooks::MAX_SERVICES + policies::MAX_LISTS;
#[cfg(test)]
const _: () = assert!(MAX_REQUESTS == 36);

/// The most names a sentence lists from one list.
const LISTED: usize = 8;

/// Below this much time left, the optional reads are skipped.
const MIN_LEFT: Duration = Duration::from_millis(500);

/// The static facts about `k8s.admission` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.admission",
    family: "k8s",
    summary: "Pod Security labels, policy engines, OpenShift SCCs, admission webhooks and admission policies that can reject the product's pods",
    meta: CheckMeta {
        title: "Admission",
        remediation: "Set the Pod Security level of the install namespace to what the product needs: `kubectl label ns <namespace> pod-security.kubernetes.io/enforce=<level> --overwrite`. On OpenShift, grant the SCC the vendor documents: `oc adm policy add-scc-to-user <scc> -z <service-account> -n <namespace>`. If a policy engine or a webhook is installed, ask the platform team which policies apply to the namespace, and whether every webhook that fails closed has a running backend.",
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

/// One page of a list, and whether the server said there was more.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Listed<T> {
    pub(crate) items: Vec<T>,
    /// True when the list has a next page that was not read.
    pub(crate) cut: bool,
}

impl<T> Default for Listed<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            cut: false,
        }
    }
}

/// A list cut to what a sentence names, and the tail that says how many were left out.
pub(crate) fn cut_list(mut names: Vec<String>) -> (Vec<String>, String) {
    let more = names.len().saturating_sub(LISTED);
    names.truncate(LISTED);
    let tail = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    (names, tail)
}

impl<T> Read<T> {
    /// The same answer with the value changed.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Read<U> {
        match self {
            Self::Ok(value) => Read::Ok(f(value)),
            Self::Forbidden => Read::Forbidden,
            Self::Missing => Read::Missing,
            Self::Unreadable(code) => Read::Unreadable(code),
            Self::Cut => Read::Cut,
            Self::OutOfTime => Read::OutOfTime,
        }
    }

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
                        let versions: Vec<String> =
                            group.versions.iter().map(|v| v.version.clone()).collect();
                        let preferred = group
                            .preferred_version
                            .map(|version| version.version)
                            .or_else(|| versions.first().cloned());
                        Group {
                            name: group.name,
                            preferred,
                            versions,
                        }
                    })
                    .collect()
            })?
        };
        let (openshift, groups_read, engines) = match &listed {
            Read::Ok(groups) => {
                let openshift = if groups.iter().any(|group| group.name == OPENSHIFT_GROUP) {
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

        // Webhooks, admission policies and the engines' policies (M1-160). The selectors of all three match
        // on the labels of the namespace.
        let labels: NsLabels = match &ns {
            Some(Read::Ok(facts)) => Some(facts.all_labels.clone()),
            _ => None,
        };
        let webhooks = self.read_webhooks(&mapper, &client, ctx, &labels).await?;
        let policies = read_admission_policies(&mapper, &client, ctx).await?;
        let engine_policies = read_engine_policies(
            &mapper,
            &client,
            ctx,
            &engines,
            &labels,
            namespace.as_deref(),
        )
        .await?;

        Ok(Gathered {
            namespace,
            ns,
            groups: groups_read,
            openshift,
            engines,
            scc,
            rke2: self.cluster.server_version().git_version.contains("+rke2"),
            webhooks,
            policies,
            engine_policies,
        })
    }

    /// Both webhook configuration lists, then the Service and endpoints of each `Fail` webhook that applies.
    async fn read_webhooks(
        &self,
        mapper: Mapper<'_>,
        client: &ReadOnlyClient,
        ctx: &CheckContext,
        labels: &NsLabels,
    ) -> Result<Webhooks, CheckError> {
        let validating = list_page(
            mapper,
            ctx,
            client.all::<ValidatingWebhookConfiguration>(),
            ListParams::default(),
        )
        .await?
        .map(|listed| Listed {
            cut: listed.cut,
            items: webhooks::from_validating(listed.items),
        });
        let mutating = list_page(
            mapper,
            ctx,
            client.all::<MutatingWebhookConfiguration>(),
            ListParams::default(),
        )
        .await?
        .map(|listed| Listed {
            cut: listed.cut,
            items: webhooks::from_mutating(listed.items),
        });
        let mut wanted: Vec<(String, String)> = Vec::new();
        for read in [&validating, &mutating] {
            if let Read::Ok(listed) = read {
                for hook in &listed.items {
                    if let Some((namespace, name)) = hook.service_to_read(labels) {
                        let key = (namespace.to_owned(), name.to_owned());
                        if !wanted.contains(&key) {
                            wanted.push(key);
                        }
                    }
                }
            }
        }
        let mut services = Vec::new();
        for (index, (namespace, name)) in wanted.into_iter().enumerate() {
            let state = if index >= webhooks::MAX_SERVICES || out_of_time(ctx) {
                BackendState::NotAsked
            } else if !(webhooks::safe_name(&namespace) && webhooks::safe_name(&name)) {
                BackendState::BadName
            } else {
                read_backend(mapper, client, ctx, &namespace, &name).await?
            };
            services.push(ServiceRead {
                namespace,
                name,
                state,
            });
        }
        Ok(Webhooks {
            validating,
            mutating,
            services,
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
            let entry = groups.iter().find(|entry| entry.name == group);
            let version = entry.and_then(|entry| entry.preferred.clone());
            let kinds = match &version {
                Some(version) if !out_of_time(ctx) => {
                    read_kinds(mapper, client, group, version).await?
                }
                _ => Read::OutOfTime,
            };
            let preferred_forbidden = matches!(kinds, Read::Forbidden);
            let mut lists: Vec<PolicyList> = Vec::new();
            let (mut kinds, mut legacy_policies) = match kinds {
                Read::Ok(resources) => {
                    if let Some(version) = &version {
                        lists.extend(policies::plan(group, version, &resources));
                    }
                    let kinds: Vec<String> = resources.into_iter().map(|r| r.kind).collect();
                    let legacy = engines::has_legacy_policies(&kinds);
                    (kinds, Some(legacy))
                }
                _ => (Vec::new(), None),
            };
            // The preferred version of `kyverno.io` is `v2` on every Kyverno from 1.12 to 1.19, and the
            // legacy kinds live in `v1`. Without them in the preferred version, ask `v1` as well, and list
            // its kinds with the others. If that read fails, the state is unknown, not "no". A preferred
            // version the identity may not read says the same of `v1`, so it is not asked.
            if legacy_policies != Some(true)
                && !preferred_forbidden
                && let Some(other) = entry.and_then(engines::legacy_version)
            {
                let more_kinds = if out_of_time(ctx) {
                    Read::OutOfTime
                } else {
                    read_kinds(mapper, client, group, other).await?
                };
                match more_kinds {
                    Read::Ok(extra) => {
                        lists.extend(policies::plan(group, other, &extra));
                        let extra: Vec<String> = extra.into_iter().map(|r| r.kind).collect();
                        if engines::has_legacy_policies(&extra) {
                            legacy_policies = Some(true);
                        }
                        kinds.extend(extra);
                    }
                    _ => legacy_policies = None,
                }
            }
            let (kinds, more) = engines::cut_kinds(kinds);
            read_groups.push((
                engine,
                FoundGroup {
                    group,
                    version,
                    kinds,
                    more,
                    legacy_policies,
                    lists,
                },
            ));
        }
        Ok(engines::found(read_groups))
    }
}

/// `GET /apis/<group>/<version>`: the resources it serves, subresources left out.
async fn read_kinds(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    group: &str,
    version: &str,
) -> Result<Read<Vec<ApiKind>>, CheckError> {
    read(
        mapper,
        client.group_resources(group, version).await,
        true,
        |list| {
            list.resources
                .into_iter()
                .filter(|resource| !resource.name.contains('/'))
                .map(|resource| ApiKind {
                    plural: resource.name,
                    kind: resource.kind,
                    namespaced: resource.namespaced,
                })
                .collect::<Vec<ApiKind>>()
        },
    )
}

/// One page of a list. Asked for only when there is time left.
async fn list_page<K>(
    mapper: Mapper<'_>,
    ctx: &CheckContext,
    api: kube::Api<K>,
    params: ListParams,
) -> Result<Read<Listed<K>>, CheckError>
where
    K: kube::Resource + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    if out_of_time(ctx) {
        return Ok(Read::OutOfTime);
    }
    read(mapper, api.list(&params.limit(PAGE)).await, false, |list| {
        Listed {
            cut: list
                .metadata
                .continue_
                .as_deref()
                .is_some_and(|token| !token.is_empty()),
            items: list.items,
        }
    })
}

/// The `Service` a webhook names, and the ready endpoints behind it.
async fn read_backend(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ctx: &CheckContext,
    namespace: &str,
    name: &str,
) -> Result<BackendState, CheckError> {
    let unread = |read: &Read<()>, grant: ReadGrant| BackendState::Unread {
        why: read.why(),
        grant: matches!(read, Read::Forbidden).then_some(grant),
    };
    let services = read(
        mapper,
        client
            .namespaced::<Service>(namespace)
            .list(
                &ListParams::default()
                    .fields(&format!("metadata.name={name}"))
                    .limit(2),
            )
            .await,
        false,
        |list| list.items,
    )?;
    match services {
        Read::Ok(items) => match items.first() {
            None => return Ok(BackendState::ServiceMissing),
            Some(service)
                if service.spec.as_ref().and_then(|spec| spec.type_.as_deref())
                    == Some("ExternalName") =>
            {
                return Ok(BackendState::External);
            }
            Some(_) => {}
        },
        other => return Ok(unread(&other.map(|_| ()), ReadGrant::Services)),
    }
    if out_of_time(ctx) {
        return Ok(BackendState::NotAsked);
    }
    let slices = read(
        mapper,
        client
            .namespaced::<EndpointSlice>(namespace)
            .list(
                &ListParams::default()
                    .labels(&format!("kubernetes.io/service-name={name}"))
                    .limit(PAGE),
            )
            .await,
        false,
        |list| {
            let more = list
                .metadata
                .continue_
                .as_deref()
                .is_some_and(|token| !token.is_empty());
            let (mut ready, mut total) = (0_usize, 0_usize);
            for slice in &list.items {
                for endpoint in slice.endpoints.iter().flatten() {
                    total += 1;
                    // `ready` unset means ready (the API says consumers must read it that way).
                    let is_ready = endpoint
                        .conditions
                        .as_ref()
                        .and_then(|conditions| conditions.ready)
                        .unwrap_or(true);
                    ready += usize::from(is_ready);
                }
            }
            (ready, total, more)
        },
    )?;
    Ok(match slices {
        Read::Ok((ready, _, _)) if ready > 0 => BackendState::Ready(ready),
        Read::Ok((_, _, true)) => unread(&Read::Cut, ReadGrant::EndpointSlices),
        Read::Ok((_, total, false)) => BackendState::NoReady { total },
        other => unread(&other.map(|_| ()), ReadGrant::EndpointSlices),
    })
}

/// The `ValidatingAdmissionPolicy` list and, when it holds a policy, the binding list.
async fn read_admission_policies(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ctx: &CheckContext,
) -> Result<Policies, CheckError> {
    let policies = list_page(
        mapper,
        ctx,
        client.all::<ValidatingAdmissionPolicy>(),
        ListParams::default(),
    )
    .await?
    .map(|listed| Listed {
        cut: listed.cut,
        items: listed.items.into_iter().map(vap::policy_of).collect(),
    });
    let bindings = match &policies {
        Read::Ok(listed) if !listed.items.is_empty() => Some(
            list_page(
                mapper,
                ctx,
                client.all::<ValidatingAdmissionPolicyBinding>(),
                ListParams::default(),
            )
            .await?
            .map(|listed| Listed {
                cut: listed.cut,
                items: listed.items.into_iter().map(vap::binding_of).collect(),
            }),
        ),
        _ => None,
    };
    Ok(Policies { policies, bindings })
}

/// The policy objects of the engines that discovery found: the lists the engine groups called for, at most
/// [`policies::MAX_LISTS`].
async fn read_engine_policies(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ctx: &CheckContext,
    engines: &[Found],
    labels: &NsLabels,
    namespace: Option<&str>,
) -> Result<EnginePolicies, CheckError> {
    let planned: Vec<&PolicyList> = engines
        .iter()
        .flat_map(|engine| &engine.groups)
        .flat_map(|group| &group.lists)
        .collect();
    // The caps: constraint kinds first (the planner sorts real kinds first), then all lists. What is left
    // out is counted, so the result says what it did not evaluate.
    let mut skipped = 0;
    let mut constraint_kinds = 0;
    let mut chosen: Vec<&PolicyList> = Vec::new();
    for list in planned {
        if list.group == "constraints.gatekeeper.sh" {
            if constraint_kinds >= policies::MAX_CONSTRAINT_KINDS {
                skipped += 1;
                continue;
            }
            constraint_kinds += 1;
        }
        if chosen.len() >= policies::MAX_LISTS {
            skipped += 1;
            continue;
        }
        chosen.push(list);
    }
    let mut found = EnginePolicies {
        reads: Vec::new(),
        skipped,
    };
    for list in chosen {
        let resource = ApiResource::from_gvk_with_plural(
            &GroupVersionKind::gvk(list.group, &list.version, &list.kind),
            &list.plural,
        );
        let result = list_page(
            mapper,
            ctx,
            client.all_dynamic(&resource),
            ListParams::default(),
        )
        .await?
        .map(|listed| Listed {
            cut: listed.cut,
            items: listed
                .items
                .iter()
                .map(|object| {
                    policies::fact(
                        list,
                        object.metadata.name.as_deref().unwrap_or("<unnamed>"),
                        &object.data,
                        labels,
                        namespace,
                    )
                })
                .collect(),
        });
        found.reads.push(PolicyRead {
            list: list.clone(),
            result,
        });
    }
    Ok(found)
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
                label_sync_off: labels
                    .get("security.openshift.io/scc.podSecurityLabelSync")
                    .is_some_and(|value| value == "false"),
                labels: Labels::from_map(&labels),
                all_labels: labels,
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
