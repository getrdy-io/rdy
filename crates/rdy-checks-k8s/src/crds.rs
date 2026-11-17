//! `k8s.crds`: the custom resource definitions the product needs are installed and serve the needed
//! versions, and its operators run at an acceptable version (03 section 4, M1-late: M1-164).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - `GET /apis`: the API groups and their versions (discovery, open to every signed-in user);
//! - `GET /apis/<group>/<version>` for the versions a definition must serve: the resources of that version.
//!   A definition is installed at a version when the document lists its plural name. Each distinct group
//!   and version is read once, and at most 32 documents in a run;
//! - `GET` of each operator `Deployment` by name in the namespace of the spec (`apps/v1`): its replicas, ready
//!   count, image tags and `app.kubernetes.io/version` label, and nothing else (`objects`).
//!
//! The `CustomResourceDefinition` objects are not read. API discovery lists a definition only once it is
//! established, so the list answers the question the check asks (is it installed and served at this
//! version?) without a grant that reads every schema in the cluster. A definition that is still being
//! installed, or whose names conflict, shows as missing, and a note says so. This is the one place the
//! check differs from the "when allowed" read of the CRD object in 03, and it is on purpose: the check
//! needs no new grant for definitions.
//!
//! How the rules of 03 apply:
//!
//! - A definition that is not installed, or does not serve a version the spec names, blocks. The definitions
//!   of one missing group are one block, with one install line.
//! - An operator Deployment that is missing, scaled to zero or has fewer replicas ready than it wants warns.
//! - An operator whose version, read from the image tag of its container (else the version label), is below
//!   `min_version` blocks. A pre-release sorts below its release.
//! - Anything the identity may not read, or the check ran out of time for, is not evaluated, never a block:
//!   a Deployment it may not get (grant `get deployments.apps/<name> in <namespace>`), the discovery documents
//!   (grant `get /apis`), a version that no tag or label gives.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::{CrdRule, K8sCrds, OperatorRule};

use crate::client::{KubeError, ReadOnlyClient};
use crate::cluster::Cluster;

mod fix;
mod judge;
mod objects;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{CrdRead, Gathered, GroupState, OperatorRead};
use objects::{Fetched, OperatorDeployment, Unread};

/// Below this much time left, the remaining reads are skipped.
const MIN_LEFT: Duration = Duration::from_millis(500);

/// The most discovery documents one run reads.
const MAX_DOCS: usize = 32;

/// The static facts about `k8s.crds` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.crds",
    family: "k8s",
    summary: "Required CRDs are installed and served at the needed versions, and their operators run",
    meta: CheckMeta {
        title: "CRDs and operators",
        remediation: "Install the product's prerequisites from your registry or mirror with `helm install <release> <chart> -n <namespace> --create-namespace`, using the chart reference the vendor gave you. If an operator is not ready, run `kubectl describe deployment <name> -n <namespace>` and `kubectl get pods -n <namespace>`. If a CRD is installed at an older version, apply the CRDs of the newer chart with `kubectl apply --server-side -f <crds.yaml>`, then upgrade the release with `helm upgrade <release> <chart> -n <namespace>`.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(20)),
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

/// `k8s.crds`, built from its spec entry.
pub struct CrdsCheck {
    params: K8sCrds,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for CrdsCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrdsCheck")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl CrdsCheck {
    /// The check for `params`, reading `cluster`.
    #[must_use]
    pub fn new(params: K8sCrds, cluster: Arc<dyn Cluster>) -> Self {
        Self { params, cluster }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for CrdsCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let gathered = self.gather(ctx).await?;
            Ok(judge::judge(&self.params, &gathered))
        })
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

/// How a failed request becomes a [`KubeError`]: `Cluster::map_error`, which knows the connection.
type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> KubeError + Sync);

/// Sorts the result of one request. A refusal for this identity, a missing object and another status of the
/// server are answers. The guard refusing the path is one too, and says nothing about the cluster. Anything
/// else (the network, the credentials) fails the check.
fn read<T, U>(
    mapper: Mapper<'_>,
    result: Result<T, kube::Error>,
    map: impl FnOnce(T) -> U,
) -> Result<Fetched<U>, CheckError> {
    match result {
        Ok(value) => Ok(Fetched::Got(map(value))),
        Err(error) => match mapper(&error) {
            KubeError::Forbidden { .. } => Ok(Fetched::Unread(Unread::Forbidden)),
            KubeError::Api { code: 404, .. } => Ok(Fetched::Missing),
            // The guard refused the path. Whatever the rule, rdy did not ask, so nothing is known: partial,
            // never a block.
            KubeError::Refused { .. } => Ok(Fetched::Unread(Unread::Refused)),
            KubeError::Api { code, .. } => Ok(Fetched::Unread(Unread::Status(code))),
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

/// Splits a definition name into its plural and its group, at the first dot.
fn split_name(name: &str) -> Option<(String, String)> {
    name.split_once('.')
        .filter(|(plural, group)| !plural.is_empty() && !group.is_empty())
        .map(|(plural, group)| (plural.to_owned(), group.to_owned()))
}

/// The discovery documents read so far in this run, and how many requests that took.
struct Docs<'a> {
    client: &'a ReadOnlyClient,
    mapper: Mapper<'a>,
    cache: BTreeMap<(String, String), Result<BTreeSet<String>, Unread>>,
    asked: usize,
}

impl Docs<'_> {
    /// The plural names of `group` at `version`. A 404 is an empty set: the server serves nothing there.
    async fn plurals(
        &mut self,
        ctx: &CheckContext,
        group: &str,
        version: &str,
    ) -> Result<Result<BTreeSet<String>, Unread>, CheckError> {
        let key = (group.to_owned(), version.to_owned());
        if let Some(known) = self.cache.get(&key) {
            return Ok(known.clone());
        }
        let got = if out_of_time(ctx) {
            Err(Unread::Time)
        } else if self.asked >= MAX_DOCS {
            Err(Unread::Budget)
        } else {
            self.asked += 1;
            match read(
                self.mapper,
                self.client.group_resources(group, version).await,
                |list| {
                    list.resources
                        .into_iter()
                        // `certificates/status` is a subresource, not a plural name.
                        .filter(|resource| !resource.name.contains('/'))
                        .map(|resource| resource.name)
                        .collect::<BTreeSet<String>>()
                },
            )? {
                Fetched::Got(set) => Ok(set),
                Fetched::Missing => Ok(BTreeSet::new()),
                Fetched::Unread(why) => Err(why),
            }
        };
        self.cache.insert(key, got.clone());
        Ok(got)
    }
}

impl CrdsCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let rules: Vec<&CrdRule> = self
            .params
            .crds
            .iter()
            .flat_map(|list| list.iter())
            .collect();
        let mut crds = Vec::new();
        if !rules.is_empty() {
            let groups = self.read_groups(ctx, &client, &mapper, &rules).await?;
            let mut docs = Docs {
                client: &client,
                mapper: &mapper,
                cache: BTreeMap::new(),
                asked: 0,
            };
            for rule in rules {
                crds.push(read_crd(ctx, &mut docs, &groups, rule).await?);
            }
        }
        let mut operators = Vec::new();
        for rule in self.params.operators.iter().flat_map(|list| list.iter()) {
            operators.push(read_operator(ctx, &client, &mapper, rule).await?);
        }
        Ok(Gathered { crds, operators })
    }

    /// `GET /apis`, cut down to the groups the spec names: each with its versions in the server's order.
    async fn read_groups(
        &self,
        ctx: &CheckContext,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
        rules: &[&CrdRule],
    ) -> Result<Result<BTreeMap<String, Vec<String>>, Unread>, CheckError> {
        let wanted: BTreeSet<String> = rules
            .iter()
            .filter_map(|rule| split_name(rule.name.as_str()).map(|(_, group)| group))
            .collect();
        if wanted.is_empty() {
            // No name has a group, so there is nothing to look up.
            return Ok(Ok(BTreeMap::new()));
        }
        if out_of_time(ctx) {
            return Ok(Err(Unread::Time));
        }
        Ok(
            match read(mapper, client.api_groups().await, |list| {
                list.groups
                    .into_iter()
                    .filter(|group| wanted.contains(&group.name))
                    .map(|group| {
                        // Only text in the shape of an API version is ever put in a path.
                        let versions = group
                            .versions
                            .into_iter()
                            .map(|version| version.version)
                            .filter(|version| judge::is_version(version))
                            .collect();
                        (group.name, versions)
                    })
                    .collect::<BTreeMap<String, Vec<String>>>()
            })? {
                Fetched::Got(map) => Ok(map),
                // The group list is a discovery path every cluster serves. A 404 is a server that does
                // not, so nothing can be said.
                Fetched::Missing => Err(Unread::Status(404)),
                Fetched::Unread(why) => Err(why),
            },
        )
    }
}

/// Reads what one definition needs: the group, and the document of each version it must serve.
async fn read_crd(
    ctx: &CheckContext,
    docs: &mut Docs<'_>,
    groups: &Result<BTreeMap<String, Vec<String>>, Unread>,
    rule: &CrdRule,
) -> Result<CrdRead, CheckError> {
    let name = rule.name.as_str().to_owned();
    let wanted: Vec<String> = rule
        .versions
        .iter()
        .flat_map(|list| list.iter())
        .map(|version| version.as_str().to_owned())
        .collect();
    let mut read = CrdRead {
        name,
        split: split_name(rule.name.as_str()),
        wanted,
        group: GroupState::Absent,
        listed: Vec::new(),
    };
    let Some((plural, group)) = read.split.clone() else {
        return Ok(read);
    };
    let versions = match groups {
        Err(why) => {
            read.group = GroupState::Unread(*why);
            return Ok(read);
        }
        Ok(map) => match map.get(&group) {
            None => return Ok(read),
            Some(versions) => versions.clone(),
        },
    };
    read.group = GroupState::Served(versions.clone());

    // The versions the spec names and the group serves. With none named, the group's versions in the
    // server's order (preferred first), until one lists the definition.
    if read.wanted.is_empty() {
        for version in &versions {
            let found = list_version(ctx, docs, &mut read, &group, &plural, version).await?;
            if found {
                break;
            }
        }
        return Ok(read);
    }
    let wanted = read.wanted.clone();
    let mut lacking = false;
    for version in &wanted {
        if versions.contains(version) {
            lacking |= !list_version(ctx, docs, &mut read, &group, &plural, version).await?;
        } else {
            lacking = true;
        }
    }
    // A wanted version is missing: read the others too, so the message can say what is served.
    if lacking {
        for version in versions.iter().filter(|v| !wanted.contains(v)) {
            list_version(ctx, docs, &mut read, &group, &plural, version).await?;
        }
    }
    Ok(read)
}

/// Reads the document of one version and records whether it lists the plural. True when it does.
async fn list_version(
    ctx: &CheckContext,
    docs: &mut Docs<'_>,
    read: &mut CrdRead,
    group: &str,
    plural: &str,
    version: &str,
) -> Result<bool, CheckError> {
    let got = docs
        .plurals(ctx, group, version)
        .await?
        .map(|set| set.contains(plural));
    let found = matches!(got, Ok(true));
    read.listed.push((version.to_owned(), got));
    Ok(found)
}

/// `GET` of one operator Deployment.
async fn read_operator(
    ctx: &CheckContext,
    client: &ReadOnlyClient,
    mapper: Mapper<'_>,
    rule: &OperatorRule,
) -> Result<OperatorRead, CheckError> {
    let state = if out_of_time(ctx) {
        Fetched::Unread(Unread::Time)
    } else {
        read(
            mapper,
            client
                .namespaced::<OperatorDeployment>(rule.namespace.as_str())
                .get(rule.deployment.as_str())
                .await,
            |deployment| deployment,
        )?
    };
    Ok(OperatorRead {
        namespace: rule.namespace.as_str().to_owned(),
        deployment: rule.deployment.as_str().to_owned(),
        min: rule.min_version.clone(),
        state,
    })
}
