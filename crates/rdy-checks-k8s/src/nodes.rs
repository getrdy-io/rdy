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
//!   list of `kube-system`, where a name or an `app.kubernetes.io/name` label that contains
//!   `cluster-autoscaler` counts (the Helm chart names vary). The list is filtered here and not by a
//!   selector, so no selector has to cover every spelling. A group in `/apis` says the autoscaler is
//!   installed, not that it can add the nodes the product needs: the warning says "not verified".
//!
//! Not read: the `cluster-autoscaler-status` ConfigMap that GKE Standard and AKS keep in `kube-system`.
//!   The guard allows no `ConfigMap` read, and adding one needs the Appendix B table, the example role and
//!   a security review. GKE node auto-provisioning is seen by its `nap-` node pools instead.
//!
//! Nothing is created. The rules are in [`judge`]. How this build differs from 03:
//!
//! - **Free capacity** (`free`, from pod requests) is M1-159. A spec that holds `free` gets a partial that
//!   says it was not evaluated, so it is never a pass.
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

mod facts;
mod fix;
mod judge;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use facts::NodeFacts;
use judge::{Assessment, Scaler};

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
        Ok(judge::finish(&self.params, &found, scaler.as_ref(), cut))
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

/// True for a Deployment of the Kubernetes cluster autoscaler: its name or its `app.kubernetes.io/name`
/// label contains `cluster-autoscaler`.
fn is_autoscaler(deployment: &Deployment) -> bool {
    let named = deployment
        .metadata
        .name
        .as_deref()
        .is_some_and(|name| name.contains("cluster-autoscaler"));
    let labeled = deployment
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("app.kubernetes.io/name"))
        .is_some_and(|value| value.contains("cluster-autoscaler"));
    named || labeled
}
