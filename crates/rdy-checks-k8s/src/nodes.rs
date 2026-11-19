//! `k8s.nodes`: ready nodes, their allocatable size, pods per node, conditions and zones (03 section 4).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - the `Node` list, by the paging helper (`list_all`: pages of 500, at most 5000 nodes, one restart on
//!   `410 Gone`). Only labels, taints, conditions, `status.allocatable`, `status.capacity` and `nodeInfo`
//!   are kept;
//! - only when the one thing wrong is a count of nodes that is too small: whether a node autoscaler
//!   exists. The node labels and names are looked at first (they cost nothing), then `GET /apis` for the
//!   groups `karpenter.sh`, `karpenter.k8s.aws` and `autoscaling.openshift.io`, then the `Deployment`
//!   list of `kube-system`, where a name or an `app.kubernetes.io/name` label that equals or ends
//!   with `cluster-autoscaler` counts (the Helm chart names vary), if a replica is ready. The list is filtered here and not by a
//!   selector, so no selector has to cover every spelling. A group in `/apis` says the autoscaler is
//!   installed, not that it can add the nodes the product needs: the warning says "not verified".
//!
//! Not read, and why:
//!
//! - the `cluster-autoscaler-status` ConfigMap that GKE Standard and AKS keep in `kube-system`.
//!   The guard allows no `ConfigMap` read, and adding one needs the Appendix B table, the example role and
//!   a security review. GKE node auto-provisioning is seen by its `nap-` node pools instead.
//!
//! Nothing is created. The rules are in [`judge`]. How this build differs from 03:
//!
//! - **Free capacity** (`free`, from pod requests, M1-159) reads the Pod list only when the spec holds
//!   `free` and a node counts: `status.phase!=Succeeded,status.phase!=Failed`, kept to node name, phase and
//!   requests. A forbidden, cut or unreadable list is "not evaluated" (partial), never a pass. See [`free`].
//! - **A forbidden or failing Node list** is a partial with the grant `list nodes`, never a block.
//! - **`per_node` without `min_ready`** means every counted node, as the spec reference says. With
//!   `min_ready`, that many counted nodes.
//! - **GKE Autopilot** is recognised by the `gk3-` prefix of node names only: Google documents the prefix
//!   and no node label.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Node;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::K8sNodes;

use crate::client::list::list_all;
use crate::client::{KubeError, ReadOnlyClient};
use crate::cluster::Cluster;
use facts::command_arg;

mod facts;
mod fix;
mod free;
mod judge;
mod pod;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use facts::NodeFacts;
use free::{FreeRead, PHASE_SELECTOR, PodsRead};
use judge::{Assessment, Scaler};
use pod::PodRequests;

/// Below this much time left, the optional reads are skipped.
const MIN_LEFT: Duration = Duration::from_millis(500);

/// The API groups that say a node autoscaler is installed, and what to call it.
const SCALER_GROUPS: [(&str, &str); 3] = [
    ("karpenter.sh", "Karpenter"),
    ("karpenter.k8s.aws", "Karpenter"),
    (
        "autoscaling.openshift.io",
        "the OpenShift machine autoscaler",
    ),
];

/// The static facts about `k8s.nodes` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.nodes",
    family: "k8s",
    summary: "Ready nodes, allocatable size, pods per node, conditions, zones",
    meta: CheckMeta {
        title: "Nodes",
        remediation: "Add nodes the product can use. Only Ready, uncordoned Linux nodes without an untolerated `NoSchedule` or `NoExecute` taint count. EKS: `eksctl create nodegroup --cluster <cluster> --nodes 3 --node-type m6i.2xlarge`. Write the spec's sizes as allocatable, which is less than the machine size: `kubectl describe node <node>` shows both.",
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

/// `k8s.nodes`, built from its spec entry.
pub struct NodesCheck {
    params: K8sNodes,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for NodesCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodesCheck")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl NodesCheck {
    /// The check for `params`, reading `cluster`.
    #[must_use]
    pub fn new(params: K8sNodes, cluster: Arc<dyn Cluster>) -> Self {
        Self { params, cluster }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for NodesCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.execute(ctx))
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

/// The answer to a read the server may refuse.
#[derive(Debug)]
enum Read<T> {
    Ok(T),
    /// 403: the identity may not read it.
    Forbidden,
    /// 404: it does not exist here.
    Missing,
    /// Any other status of the server.
    Unreadable(u16),
}

impl<T> Read<T> {
    /// Why the read gave nothing, as a phrase.
    fn why(&self) -> String {
        match self {
            Self::Ok(_) => "it was read".to_owned(),
            Self::Forbidden => "the identity may not list nodes".to_owned(),
            Self::Missing => "the server does not have it".to_owned(),
            Self::Unreadable(code) => format!("the server answered {code}"),
        }
    }
}

/// How a failed request becomes a [`KubeError`]: `Cluster::map_error`, which knows the connection.
type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> KubeError + Sync);

/// Sorts the result of one request. A refusal for this identity, a missing object and another status of the
/// server are answers. Anything else (the network, the credentials, the guard) fails the check.
fn sort<T, U>(
    mapper: Mapper<'_>,
    result: Result<T, kube::Error>,
    map: impl FnOnce(T) -> U,
) -> Result<Read<U>, CheckError> {
    match result {
        Ok(value) => Ok(Read::Ok(map(value))),
        Err(error) => match mapper(&error) {
            KubeError::Forbidden { .. } => Ok(Read::Forbidden),
            KubeError::Api { code: 404, .. } => Ok(Read::Missing),
            KubeError::Api { code, .. } => Ok(Read::Unreadable(code)),
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

impl NodesCheck {
    async fn execute(&self, ctx: &CheckContext) -> CheckOutcome {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let listed = sort(
            &mapper,
            list_all(&client.all::<Node>(), &ListParams::default()).await,
            |listed| {
                let nodes: Vec<NodeFacts> = listed.items.iter().map(NodeFacts::from_node).collect();
                (nodes, listed.partial)
            },
        )?;
        let (nodes, cut) = match listed {
            Read::Ok(read) => read,
            other => {
                let forbidden = matches!(other, Read::Forbidden);
                return Ok(judge::unreadable(&self.params, &other.why(), forbidden));
            }
        };
        let found = Assessment::new(&self.params, &nodes);
        let scaler = if found.only_a_count_is_short() {
            Some(self.find_scaler(&client, &mapper, ctx, &nodes).await?)
        } else {
            None
        };
        let pods = match &self.params.free {
            None => FreeRead::NotAsked,
            Some(_) if found.counted.is_empty() => FreeRead::NoNodes,
            Some(_) => {
                self.read_pods(&client, &mapper, ctx, &found.counted)
                    .await?
            }
        };
        Ok(judge::finish(
            &self.params,
            &found,
            scaler.as_ref(),
            cut,
            &pods,
        ))
    }

    /// Reads the pods that hold requests on the counted nodes: one cluster-wide list, and when that list
    /// was cut, one list per counted node (at most [`free::MAX_NODE_LISTS`]).
    async fn read_pods(
        &self,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
        ctx: &CheckContext,
        counted: &[&NodeFacts],
    ) -> Result<FreeRead, CheckError> {
        let not_evaluated =
            |why: String, grants: Vec<String>| Ok(FreeRead::NotEvaluated { why, grants });
        if out_of_time(ctx) {
            return not_evaluated("the check ran out of time".to_owned(), Vec::new());
        }
        let params = ListParams::default().fields(PHASE_SELECTOR);
        let all = sort(
            mapper,
            list_all(&client.all::<PodRequests>(), &params).await,
            |l| l,
        )?;
        let listed = match all {
            Read::Ok(listed) => listed,
            Read::Forbidden => {
                return not_evaluated(
                    "the identity may not list pods".to_owned(),
                    vec!["list pods".to_owned()],
                );
            }
            other => return not_evaluated(other.why_discovery(), Vec::new()),
        };
        let mut read = PodsRead::default();
        if !listed.partial {
            read.add(&listed.items);
            return Ok(FreeRead::Read(read));
        }
        // The cluster-wide list was cut. A node's own list is short, so each counted node is asked for.
        if counted.len() > free::MAX_NODE_LISTS {
            return not_evaluated(
                format!(
                    "the cluster has too many pods to list at once, and {} counted nodes are more than the {} that are listed one by one",
                    counted.len(),
                    free::MAX_NODE_LISTS
                ),
                Vec::new(),
            );
        }
        read.by_node_lists();
        for node in counted {
            let name = command_arg(&node.name, "");
            if name.is_empty() {
                return not_evaluated(
                    "a counted node has a name that cannot go into a field selector".to_owned(),
                    Vec::new(),
                );
            }
            if out_of_time(ctx) {
                return not_evaluated("the check ran out of time".to_owned(), Vec::new());
            }
            let params =
                ListParams::default().fields(&format!("spec.nodeName={name},{PHASE_SELECTOR}"));
            match sort(
                mapper,
                list_all(&client.all::<PodRequests>(), &params).await,
                |l| l,
            )? {
                Read::Ok(one) if !one.partial => read.add(&one.items),
                Read::Ok(_) => {
                    return not_evaluated(
                        "a node has too many pods to list".to_owned(),
                        Vec::new(),
                    );
                }
                Read::Forbidden => {
                    return not_evaluated(
                        "the identity may not list pods".to_owned(),
                        vec!["list pods".to_owned()],
                    );
                }
                other => return not_evaluated(other.why_discovery(), Vec::new()),
            }
        }
        Ok(FreeRead::Read(read))
    }

    /// Looks for a node autoscaler, cheapest evidence first. The first one found ends the search.
    async fn find_scaler(
        &self,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
        ctx: &CheckContext,
        nodes: &[NodeFacts],
    ) -> Result<Scaler, CheckError> {
        if let Some(hint) = nodes.iter().find_map(NodeFacts::scaler_hint) {
            return Ok(Scaler::Found(hint.to_owned()));
        }
        let mut unknown: Vec<String> = Vec::new();

        if out_of_time(ctx) {
            unknown.push("the check ran out of time".to_owned());
            return Ok(Scaler::Unknown(unknown.join("; ")));
        }
        match sort(mapper, client.api_groups().await, |list| {
            list.groups.into_iter().find_map(|group| {
                SCALER_GROUPS
                    .iter()
                    .find(|(name, _)| *name == group.name)
                    .map(|(_, what)| *what)
            })
        })? {
            Read::Ok(Some(what)) => return Ok(Scaler::Found(what.to_owned())),
            Read::Ok(None) => {}
            other => unknown.push(format!("the group list: {}", other.why_discovery())),
        }

        if out_of_time(ctx) {
            unknown.push("the check ran out of time".to_owned());
            return Ok(Scaler::Unknown(unknown.join("; ")));
        }
        let deployments = client.namespaced::<Deployment>("kube-system");
        match sort(
            mapper,
            list_all(&deployments, &ListParams::default()).await,
            |listed| {
                listed
                    .items
                    .iter()
                    .filter(|deployment| is_autoscaler(deployment))
                    .count()
            },
        )? {
            Read::Ok(n) if n > 0 => return Ok(Scaler::Found("cluster-autoscaler".to_owned())),
            Read::Ok(_) | Read::Missing => {}
            Read::Forbidden => {
                unknown.push("the identity may not list deployments in kube-system".to_owned())
            }
            Read::Unreadable(code) => {
                unknown.push(format!("the deployment list: the server answered {code}"));
            }
        }
        Ok(if unknown.is_empty() {
            Scaler::NotFound
        } else {
            Scaler::Unknown(unknown.join("; "))
        })
    }
}

impl<T> Read<T> {
    /// Like [`Read::why`], for a read that is not the node list.
    fn why_discovery(&self) -> String {
        match self {
            Self::Forbidden => "the identity may not read it".to_owned(),
            other => other.why(),
        }
    }
}

/// True for a running Deployment of the Kubernetes cluster autoscaler: its name or its
/// `app.kubernetes.io/name` label equals or ends with `cluster-autoscaler` (the Helm names are
/// `aws-cluster-autoscaler` and the like), and at least one replica is ready.
fn is_autoscaler(deployment: &Deployment) -> bool {
    let is_it = |text: &str| text.ends_with("cluster-autoscaler");
    let named = deployment.metadata.name.as_deref().is_some_and(is_it);
    let labeled = deployment
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("app.kubernetes.io/name"))
        .is_some_and(|value| is_it(value));
    let ready = deployment
        .status
        .as_ref()
        .and_then(|status| status.ready_replicas)
        .unwrap_or(0)
        > 0;
    (named || labeled) && ready
}
