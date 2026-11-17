//! `k8s.cni`: which network plugin runs, whether it enforces `NetworkPolicy`, whether the install
//! namespace has a default-deny egress policy, and the pod and service ranges (03 section 4, M1-late:
//! M1-165).
//!
//! What it reads, all read-only and all through the guard, cheapest first:
//!
//! 1. the node list (first page of 500): the `NetworkUnavailable` condition reason (`FlannelIsUp`,
//!    `CalicoIsUp`, `CiliumIsUp`), `spec.podCIDRs` and the kubelet version (k3s). Cut down while parsing:
//!    no annotation, label or taint is held;
//! 2. `GET /apis`: the API groups the cluster serves (`crd.projectcalico.org`, `cilium.io`, `crd.antrea.io`,
//!    `k8s.ovn.org`, `kubeovn.io`, and Multus `k8s.cni.cncf.io`). Groups, never CustomResourceDefinition
//!    objects;
//! 3. on OpenShift (`config.openshift.io` served), `Network` `cluster`: the network type and both ranges;
//! 4. the service range, when OpenShift did not give it: `ServiceCIDR` (`v1`, then `v1beta1`), else the
//!    `ClusterConfiguration` key of the `kubeadm-config` ConfigMap;
//! 5. only when steps 1 to 3 did not name a plugin, or the one they named needs a setting from its
//!    DaemonSet (the AWS VPC CNI): the node agent DaemonSets of `data/cni.toml`, one `GET` each by
//!    namespace and name, in the order of the table, stopping at the first that exists. A refusal in a
//!    namespace skips the rest of that namespace. At most 16 requests;
//! 6. the `NetworkPolicy` list of the install namespace, first page of 500.
//!
//! A cluster-wide DaemonSet list is never asked for. A DaemonSet holds environment values, so each one is
//! read by name through an optional Role of its namespace (`examples/rbac/rdy-readonly-cni.yaml`), and only
//! `ENABLE_NETWORK_POLICY` of the VPC CNI is kept from it (see `objects`).
//!
//! How the rules of 03 apply is in `judge`. Anything the identity may not read is not evaluated, never a
//! block: the result is partial and `missing_grants` names what to ask for.
//!
//! Not read: Calico `GlobalNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `AdminNetworkPolicy`, the pod
//! restart evidence of crash-looping plugin pods (M2), IPPools and Cilium cluster pools. A "no default-deny"
//! pass says "namespace policies only".

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::{K8sCni, K8sName};

use crate::client::ReadOnlyClient;
use crate::cluster::Cluster;
use crate::namespace::{Read, has_more, out_of_time, read};

mod cidr;
mod fix;
mod judge;
mod objects;
mod table;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{
    Gathered, OPENSHIFT_CONFIG, Page, Probe, ServiceCidrs, ServiceSource, Unread, cheap_signals,
    first_family, settled,
};
use objects::{
    CniDaemonSet, CniNode, CniPolicy, Kubeadm, OcpNetwork, ServiceCidrV1, ServiceCidrV1Beta1,
};
use table::Table;

/// The shipped network plugin table text (`data/cni.toml`, 03 Appendix B). `table` parses it.
const EMBEDDED: &str = include_str!("../data/cni.toml");

/// The most objects one list asks for. A longer list is read as its first page and the rest is "not read".
const PAGE: u32 = 500;

/// The most `ServiceCIDR` objects read. A cluster has one or two.
const SERVICE_CIDR_PAGE: u32 = 20;

/// The static facts about `k8s.cni` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.cni",
    family: "k8s",
    summary: "Network plugin, NetworkPolicy enforcement, default-deny egress in the install namespace, pod and service ranges",
    meta: CheckMeta {
        title: "Network plugin",
        remediation: "Run the product on a cluster whose network plugin enforces NetworkPolicy when the spec asks for it (Calico, Cilium or Antrea). If the namespace has a default-deny egress policy, add a policy that allows the destinations the product needs (`kubectl get networkpolicy -n <namespace>`). If a pod or service range overlaps one the spec says to avoid, the cluster must be rebuilt with other ranges.",
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

/// `k8s.cni`, built from its spec entry.
pub struct CniCheck {
    params: K8sCni,
    namespace: Option<K8sName>,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for CniCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CniCheck")
            .field("params", &self.params)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl CniCheck {
    /// The check for `params`, reading `cluster`.
    ///
    /// `namespace` is the install namespace of the k8s block of the spec. The `k8s.cni` entry has no
    /// namespace of its own. Without one, no `NetworkPolicy` is read.
    #[must_use]
    pub fn new(params: K8sCni, namespace: Option<K8sName>, cluster: Arc<dyn Cluster>) -> Self {
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

impl Check for CniCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let table = Table::shipped().map_err(|error| CheckError::Failed {
                message: error.to_string(),
                hint: "Use a build of rdy that ships a valid network plugin table.".to_owned(),
            })?;
            let gathered = self.gather(ctx, table).await?;
            Ok(judge::judge(table, &self.params, &gathered))
        })
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> crate::client::KubeError + Sync);

impl CniCheck {
    async fn gather(&self, ctx: &CheckContext, table: &Table) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);

        let nodes = read(
            &mapper,
            client
                .all::<CniNode>()
                .list(&ListParams::default().limit(PAGE))
                .await,
            |list| Page {
                cut: has_more(&list.metadata),
                items: list.items.into_iter().map(CniNode::facts).collect(),
            },
        )?;
        let groups: Read<Vec<String>> = if out_of_time(ctx) {
            Read::OutOfTime
        } else {
            read(&mapper, client.api_groups().await, |list| {
                list.groups.into_iter().map(|group| group.name).collect()
            })?
        };
        let openshift =
            matches!(&groups, Read::Ok(names) if names.iter().any(|n| n == OPENSHIFT_CONFIG));
        let ocp = if openshift && !out_of_time(ctx) {
            Some(read(
                &mapper,
                client.all::<OcpNetwork>().get("cluster").await,
                OcpNetwork::facts,
            )?)
        } else {
            None
        };
        let service = self.service_cidrs(ctx, &client, &mapper, &ocp).await?;

        // The plugin: the DaemonSets are asked only when the cheap signals did not settle it.
        let node_items: &[_] = match &nodes {
            Read::Ok(page) => &page.items,
            _ => &[],
        };
        let group_names: &[String] = match &groups {
            Read::Ok(names) => names,
            _ => &[],
        };
        let network_type = match &ocp {
            Some(Read::Ok(facts)) => facts.network_type.as_deref(),
            _ => None,
        };
        let signals = cheap_signals(table, node_items, group_names, network_type);
        let (probes, probes_cut) = if settled(table, &signals) {
            (None, false)
        } else {
            let (probes, cut) = read_daemonsets(
                ctx,
                &client,
                &mapper,
                table,
                first_family(table, &signals).or_else(|| family_hint(node_items)),
            )
            .await?;
            (Some(probes), cut)
        };

        let namespace = self.namespace.as_ref().map(|name| name.as_str().to_owned());
        let policies = match &namespace {
            Some(name) if !out_of_time(ctx) => Some(read(
                &mapper,
                client
                    .namespaced::<CniPolicy>(name)
                    .list(&ListParams::default().limit(PAGE))
                    .await,
                |list| Page {
                    cut: has_more(&list.metadata),
                    items: list.items.into_iter().map(CniPolicy::facts).collect(),
                },
            )?),
            Some(_) => Some(Read::OutOfTime),
            None => None,
        };
        Ok(Gathered {
            namespace,
            nodes,
            groups,
            ocp,
            service,
            probes,
            probes_cut,
            policies,
        })
    }

    /// The service range: the OpenShift `Network` when it was read, else a `ServiceCIDR` object (`v1`,
    /// then `v1beta1`), else the `kubeadm-config` ConfigMap.
    async fn service_cidrs(
        &self,
        ctx: &CheckContext,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
        ocp: &Option<Read<objects::OcpFacts>>,
    ) -> Result<ServiceCidrs, CheckError> {
        let mut out = ServiceCidrs::default();
        if let Some(Read::Ok(facts)) = ocp
            && !facts.service_cidrs.is_empty()
        {
            out.found = Some((ServiceSource::OpenShiftNetwork, facts.service_cidrs.clone()));
            return Ok(out);
        }
        let params = ListParams::default().limit(SERVICE_CIDR_PAGE);
        // GA in 1.33 at v1, beta (v1beta1) before. A 404 means the version is not served.
        let v1: Read<Vec<String>> = if out_of_time(ctx) {
            Read::OutOfTime
        } else {
            read(
                mapper,
                client.all::<ServiceCidrV1>().list(&params).await,
                |list| {
                    list.items
                        .into_iter()
                        .flat_map(ServiceCidrV1::cidrs)
                        .collect()
                },
            )?
        };
        let served = match v1 {
            Read::Missing if !out_of_time(ctx) => read(
                mapper,
                client.all::<ServiceCidrV1Beta1>().list(&params).await,
                |list| {
                    list.items
                        .into_iter()
                        .flat_map(ServiceCidrV1Beta1::cidrs)
                        .collect::<Vec<String>>()
                },
            )?,
            other => other,
        };
        match served {
            Read::Ok(ranges) if !ranges.is_empty() => {
                out.found = Some((ServiceSource::ServiceCidr, ranges));
                return Ok(out);
            }
            Read::Forbidden => out.unread.push(Unread {
                what: "ServiceCIDR",
                why: "the identity may not list them".to_owned(),
                grant: Some(&judge::LIST_SERVICECIDRS),
            }),
            Read::Ok(_) | Read::Missing => {}
            other => out.unread.push(Unread {
                what: "ServiceCIDR",
                why: other.why(),
                grant: None,
            }),
        }
        if out_of_time(ctx) {
            out.unread.push(Unread {
                what: "kubeadm-config",
                why: Read::<()>::OutOfTime.why(),
                grant: None,
            });
            return Ok(out);
        }
        let kubeadm = read(
            mapper,
            client
                .namespaced::<Kubeadm>("kube-system")
                .get("kubeadm-config")
                .await,
            // The document is parsed here, so the whole ClusterConfiguration never leaves `read`.
            |map| {
                map.cluster_configuration()
                    .map(|text| service_subnet(&text))
            },
        )?;
        match kubeadm {
            Read::Ok(Some(ranges)) => {
                if ranges.is_empty() {
                    out.unread.push(Unread {
                        what: "kubeadm-config",
                        why: "it names no serviceSubnet".to_owned(),
                        grant: None,
                    });
                } else {
                    out.found = Some((ServiceSource::KubeadmConfig, ranges));
                }
            }
            Read::Ok(None) | Read::Missing => {}
            Read::Forbidden => out.unread.push(Unread {
                what: "kubeadm-config",
                why: "the identity may not read it".to_owned(),
                grant: Some(&judge::GET_KUBEADM),
            }),
            other => out.unread.push(Unread {
                what: "kubeadm-config",
                why: other.why(),
                grant: None,
            }),
        }
        Ok(out)
    }
}

/// The family of the plugin a managed distribution runs by default, from the kubelet version its nodes
/// report (`v1.30.4-eks-a737599`, `v1.30.4-gke.1348000`, `v1.30.4+rke2r1`). Only the order of the
/// DaemonSet reads uses it, so a wrong guess costs requests and never changes the answer.
fn family_hint(nodes: &[objects::NodeFacts]) -> Option<&'static str> {
    nodes.iter().find_map(|node| {
        let version = node.kubelet_version.as_deref()?;
        if version.contains("-eks-") {
            Some("aws-vpc-cni")
        } else if version.contains("-gke.") {
            Some("cilium")
        } else if version.contains("+rke2") {
            Some("canal")
        } else {
            None
        }
    })
}

/// The `networking.serviceSubnet` of a `ClusterConfiguration` document, split on commas (a dual-stack
/// cluster writes two). Read as text, defensively: one line `serviceSubnet: <value>` under `networking:`.
/// The values are not trusted here; the judge reads each as a range or notes it.
fn service_subnet(document: &str) -> Vec<String> {
    let mut in_networking = false;
    for line in document.lines().take(2000) {
        let trimmed = line.trim_end();
        let indent = trimmed.len() - trimmed.trim_start().len();
        let body = trimmed.trim_start();
        if indent == 0 && !body.is_empty() && !body.starts_with('#') {
            in_networking = body == "networking:";
            continue;
        }
        if in_networking && let Some(value) = body.strip_prefix("serviceSubnet:") {
            return value
                .trim()
                .trim_matches(['"', '\''])
                .split(',')
                .map(|part| part.trim().to_owned())
                .filter(|part| !part.is_empty())
                .take(4)
                .collect();
        }
    }
    Vec::new()
}

/// Reads the DaemonSets of the table by name, stopping at the first that exists. Entries of `family` go
/// first. A refusal in a namespace skips the rest of that namespace.
async fn read_daemonsets(
    ctx: &CheckContext,
    client: &ReadOnlyClient,
    mapper: Mapper<'_>,
    table: &Table,
    family: Option<&str>,
) -> Result<(Vec<Probe>, bool), CheckError> {
    let mut order: Vec<(&str, &str, &table::Entry)> = table.daemonsets().collect();
    // A stable sort: the entries of the named family first, the rest in file order.
    order.sort_by_key(|(_, _, entry)| Some(entry.family.as_str()) != family);
    let mut probes: Vec<Probe> = Vec::new();
    // Namespaces to skip: one the server refused, or one that does not exist (a Role cannot be applied in
    // a namespace that is missing, so a refusal there is no grant anyone can give). `checked` holds the
    // namespaces asked about, so each is asked once. kube-system always exists.
    let mut refused: Vec<&str> = Vec::new();
    let mut checked: Vec<&str> = vec!["kube-system"];
    for (namespace, name, entry) in order {
        if refused.contains(&namespace) {
            continue;
        }
        if out_of_time(ctx) {
            return Ok((probes, true));
        }
        if !checked.contains(&namespace) {
            checked.push(namespace);
            let exists = read(
                mapper,
                client.all::<Namespace>().get(namespace).await,
                |_| (),
            )?;
            if matches!(exists, Read::Missing) {
                refused.push(namespace);
                continue;
            }
            if out_of_time(ctx) {
                return Ok((probes, true));
            }
        }
        let result = read(
            mapper,
            client.namespaced::<CniDaemonSet>(namespace).get(name).await,
            CniDaemonSet::facts,
        )?;
        let found = matches!(result, Read::Ok(_));
        if matches!(result, Read::Forbidden) {
            refused.push(namespace);
        }
        probes.push(Probe {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            entry: entry.id.clone(),
            read: result,
        });
        if found {
            break;
        }
    }
    Ok((probes, false))
}
