//! `k8s.dns`: the cluster DNS is running, has a ClusterIP, and shows no sign of a forward loop (03 section 4,
//! M1-late: M1-162).
//!
//! What it reads, all read-only and all through the guard, in at most seven requests:
//!
//! - in `kube-system`: the Deployments and DaemonSets that carry the label `k8s-app=kube-dns` (or, for
//!   DaemonSets, `node-local-dns`), and the pods with `k8s-app=kube-dns`: the guard allows a pod list only
//!   cluster wide, so that is one label-filtered list of the cluster, and the pods of other namespaces are
//!   dropped. The label is the selector, not the
//!   name `coredns`: RKE2 names its Deployment `rke2-coredns-rke2-coredns`, and GKE runs kube-dns, not
//!   CoreDNS, under the same label;
//! - when `kube-system` holds no cluster DNS workload, the same in `openshift-dns` (the `dns-default`
//!   DaemonSet of the OpenShift DNS operator, found by the operator's own label);
//! - the Service by name: `kube-dns` in `kube-system`, or `dns-default` in `openshift-dns`;
//! - the ConfigMap `coredns` in `kube-system`, only when the workload there is CoreDNS: its `Corefile` key
//!   and nothing else. Distributions that name the ConfigMap otherwise are not read (a note says so).
//!
//! Objects are read into cut-down types (`objects`), so the spec of a pod, env values and every ConfigMap key
//! but `Corefile` are dropped while parsing (02 Appendix B rule 6).
//!
//! The rules (03):
//!
//! - A cluster DNS workload with fewer ready pods than wanted (or none wanted) blocks. No workload and no
//!   Service blocks. A Service with no ClusterIP (headless) or one that is missing blocks.
//! - The loop cannot be read from the API: the guard refuses `pods/log`. The loop verdict is restart
//!   evidence plus the Corefile: a pod in `CrashLoopBackOff` whose last run ended in the last hour, and a
//!   root-zone `forward . /etc/resolv.conf`. Lifetime restart counts alone are never evidence. A last run
//!   that was `OOMKilled` is not loop evidence.
//! - `cluster_domain` (default `cluster.local`) must be a zone of the Corefile's `kubernetes` plugin.
//!   Where there is no Corefile to read (kube-dns, OpenShift, a differently named ConfigMap) it is not
//!   checked, and a note says so.
//! - Anything the identity may not read is not evaluated, never a block: the result is partial with the
//!   grant to ask for.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::jiff::Timestamp;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::K8sDns;

use crate::client::ReadOnlyClient;
use crate::cluster::Cluster;
use crate::namespace::{Read, has_more, out_of_time, read};

mod corefile;
mod fix;
mod judge;
mod objects;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{Gathered, Place, ServiceFacts};
use objects::{
    DnsConfigMap, DnsDaemonSet, DnsDeployment, DnsPod, Workload, corefile_of, daemon_set_of,
    deployment_of, pod_of,
};

/// The most objects one list asks for. A longer list is read as its first page and the rest is "not read".
const PAGE: u32 = 500;

/// The namespace of the cluster DNS in most distributions, and of the `coredns` ConfigMap this check reads.
pub(crate) const KUBE_SYSTEM: &str = "kube-system";
/// The namespace of the OpenShift DNS operator's workload.
pub(crate) const OPENSHIFT_DNS: &str = "openshift-dns";
/// The ConfigMap with the Corefile.
pub(crate) const COREFILE_MAP: &str = "coredns";

/// Label selectors. A distribution that labels its DNS another way is found by its Service only.
const KUBE_DNS_LABEL: &str = "k8s-app=kube-dns";
const DEPLOYMENT_LABEL: &str = "k8s-app=kube-dns";
const DAEMON_SET_LABEL: &str = "k8s-app in (kube-dns,node-local-dns)";
/// The OpenShift DNS operator labels what it owns with its `DNS` resource name, `default`.
const OPENSHIFT_LABEL: &str = "dns.operator.openshift.io/owning-dns=default";
const OPENSHIFT_POD_LABEL: &str = "dns.operator.openshift.io/daemonset-dns=default";
/// Pods that finished are no evidence of a crash loop and are not asked for.
const LIVE_PODS: &str = "status.phase!=Succeeded,status.phase!=Failed";

/// The static facts about `k8s.dns` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.dns",
    family: "k8s",
    summary: "Cluster DNS runs, has a ClusterIP, serves the cluster domain and shows no forward loop",
    meta: CheckMeta {
        title: "Cluster DNS",
        remediation: "Find out why the cluster DNS pods are not ready with `kubectl -n kube-system get pods -l k8s-app=kube-dns` and `kubectl -n kube-system describe pods -l k8s-app=kube-dns`. If CoreDNS crash-loops and forwards to `/etc/resolv.conf`, change the forward in the coredns ConfigMap (`kubectl -n kube-system edit configmap coredns`) to the node's real upstream resolvers.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(15)),
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

/// `k8s.dns`, built from its spec entry.
pub struct DnsCheck {
    params: K8sDns,
    cluster: Arc<dyn Cluster>,
    now: Option<Timestamp>,
}

impl std::fmt::Debug for DnsCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsCheck")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl DnsCheck {
    /// The check for `params`, reading `cluster`.
    #[must_use]
    pub fn new(params: K8sDns, cluster: Arc<dyn Cluster>) -> Self {
        Self {
            params,
            cluster,
            now: None,
        }
    }

    /// Fixes the time that "in the last hour" is counted from. Tests use it; a run uses the clock.
    #[cfg(test)]
    fn at(mut self, now: Timestamp) -> Self {
        self.now = Some(now);
        self
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for DnsCheck {
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

type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> crate::client::KubeError + Sync);

impl DnsCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let now = self.now.unwrap_or_else(Timestamp::now).as_second();

        let mut places = vec![read_place(&mapper, &client, ctx, Which::KubeSystem, now).await?];
        // Only a cluster that has no DNS workload under the label in kube-system is looked at again, in
        // the OpenShift namespace. A kube-system that could not be read is not a reason to ask another
        // namespace, unless the cluster facts already say OpenShift.
        let first = places.first().is_some_and(Place::has_cluster_workload);
        let first_readable = places.first().is_some_and(Place::readable);
        if !first && (first_readable || self.cluster.is_openshift()) && !out_of_time(ctx) {
            places.push(read_place(&mapper, &client, ctx, Which::OpenShift, now).await?);
        }
        let chosen = places
            .iter()
            .rposition(Place::has_cluster_workload)
            .unwrap_or(0);
        let namespace = places
            .get(chosen)
            .map_or(KUBE_SYSTEM, |place| place.namespace);

        let service = if out_of_time(ctx) {
            Read::OutOfTime
        } else {
            read_service(&mapper, &client, namespace).await?
        };

        // The Corefile is the CoreDNS Corefile of kube-system. kube-dns has none, and OpenShift's is owned by
        // its operator and kept in another ConfigMap, which this check does not read.
        let coredns_in_kube_system = places.get(chosen).is_some_and(|place| {
            place.namespace == KUBE_SYSTEM
                && place
                    .cluster_workloads()
                    .any(|workload| !workload.is_kube_dns())
        });
        let corefile = if !coredns_in_kube_system {
            None
        } else if out_of_time(ctx) {
            Some(Read::OutOfTime)
        } else {
            Some(read_corefile(&mapper, &client).await?)
        };
        Ok(Gathered {
            places,
            chosen,
            service,
            corefile,
        })
    }
}

/// Where the cluster DNS is looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    KubeSystem,
    OpenShift,
}

/// The deployments, daemon sets and pods of one namespace.
async fn read_place(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ctx: &CheckContext,
    which: Which,
    now: i64,
) -> Result<Place, CheckError> {
    let (namespace, deployment_label, daemon_label, pod_label) = match which {
        Which::KubeSystem => (
            KUBE_SYSTEM,
            Some(DEPLOYMENT_LABEL),
            DAEMON_SET_LABEL,
            KUBE_DNS_LABEL,
        ),
        // The OpenShift DNS operator runs a DaemonSet and no Deployment.
        Which::OpenShift => (OPENSHIFT_DNS, None, OPENSHIFT_LABEL, OPENSHIFT_POD_LABEL),
    };
    let deployments = match deployment_label {
        None => Read::Ok(objects_page(Vec::new(), false)),
        Some(_) if out_of_time(ctx) => Read::OutOfTime,
        Some(label) => read(
            mapper,
            client
                .namespaced::<DnsDeployment>(namespace)
                .list(&ListParams::default().labels(label).limit(PAGE))
                .await,
            |list| {
                let cut = has_more(&list.metadata);
                objects_page(list.items.into_iter().map(deployment_of).collect(), cut)
            },
        )?,
    };
    let daemon_sets = if out_of_time(ctx) {
        Read::OutOfTime
    } else {
        read(
            mapper,
            client
                .namespaced::<DnsDaemonSet>(namespace)
                .list(&ListParams::default().labels(daemon_label).limit(PAGE))
                .await,
            |list| {
                let cut = has_more(&list.metadata);
                objects_page(list.items.into_iter().map(daemon_set_of).collect(), cut)
            },
        )?
    };
    // Pods are read for a workload to explain. With no cluster DNS workload found there is nothing to explain,
    // so the pod list is not asked. The one exception is kube-system when a list there was refused: the
    // workload may exist, and its pods may still be readable.
    let found_workload = [&deployments, &daemon_sets].into_iter().any(|read| {
        matches!(read, Read::Ok(list) if list.items.iter().any(|w| w.role == objects::Role::Cluster))
    });
    let both_read = matches!((&deployments, &daemon_sets), (Read::Ok(_), Read::Ok(_)));
    let nothing_to_explain = !found_workload && !(which == Which::KubeSystem && !both_read);
    let pods = if nothing_to_explain {
        Read::Ok(judge::Pods {
            pods: Vec::new(),
            cut: false,
        })
    } else if out_of_time(ctx) {
        Read::OutOfTime
    } else {
        read(
            mapper,
            client
                .all::<DnsPod>()
                .list(
                    &ListParams::default()
                        .labels(pod_label)
                        .fields(LIVE_PODS)
                        .limit(PAGE),
                )
                .await,
            |list| {
                let cut = has_more(&list.metadata);
                // The list is cluster wide (the guard allows a pod list only so), so keep this namespace's.
                let pods = list
                    .items
                    .into_iter()
                    .filter(|pod| pod.is_in(namespace))
                    .map(|pod| pod_of(pod, now))
                    .collect();
                judge::Pods { pods, cut }
            },
        )?
    };
    Ok(Place {
        namespace,
        deployments,
        daemon_sets,
        pods,
    })
}

fn objects_page(items: Vec<Workload>, cut: bool) -> judge::Workloads {
    judge::Workloads { items, cut }
}

/// The DNS Service by name: `kube-dns` in `kube-system`, `dns-default` in `openshift-dns`.
async fn read_service(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    namespace: &str,
) -> Result<Read<ServiceFacts>, CheckError> {
    let name = if namespace == OPENSHIFT_DNS {
        "dns-default"
    } else {
        "kube-dns"
    };
    read(
        mapper,
        client.namespaced::<Service>(namespace).get(name).await,
        |service| {
            let spec = service.spec.unwrap_or_default();
            let ip = spec.cluster_ip.unwrap_or_default();
            ServiceFacts {
                name: name.to_owned(),
                namespace: namespace.to_owned(),
                headless: ip == "None",
                cluster_ip: (!ip.is_empty() && ip != "None").then_some(ip),
                dns_port: spec
                    .ports
                    .unwrap_or_default()
                    .iter()
                    .any(|port| port.port == 53),
            }
        },
    )
}

/// The `Corefile` of the `coredns` ConfigMap of `kube-system`. A ConfigMap with no such key is `Ok(None)`.
async fn read_corefile(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
) -> Result<Read<Option<corefile::Corefile>>, CheckError> {
    read(
        mapper,
        client
            .namespaced::<DnsConfigMap>(KUBE_SYSTEM)
            .get(COREFILE_MAP)
            .await,
        |map| corefile_of(map).map(|text| corefile::parse(&text)),
    )
}
