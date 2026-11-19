//! `k8s.ingress`: an ingress path exists. `IngressClass` by controller, the Gateway API, the OpenShift
//! `Route` API and LoadBalancer Services that stay pending (03 section 4, M1-late: M1-163).
//!
//! What it reads, all read-only and all through the guard, in at most five GETs:
//!
//! - the `IngressClass` list (`networking.k8s.io/v1`, first page of 500): each class's name, its
//!   `spec.controller` and the default-class annotation. Classes are matched on the controller, not the
//!   name, which people rename;
//! - `GET /apis`, the group list (open to every signed-in caller): is `gateway.networking.k8s.io` served and
//!   at which versions, is `route.openshift.io` served (OpenShift), is `metallb.io` served (a hint);
//! - only when the Gateway API is served at `v1`: `GET /apis/gateway.networking.k8s.io/v1` (which kinds) and
//!   the `GatewayClass` list (first page of 500): name, `spec.controllerName` and the `Accepted` condition;
//! - only when the spec says `loadbalancer: true` and a namespace is known: the `Service` list of that
//!   namespace (first page of 500), keeping the `LoadBalancer` ones: name, age and whether an address is
//!   assigned. A cluster-wide list is never asked (usually forbidden).
//!
//! Nothing is created and no canary Service is made, so the check says "load balancer not verified" on
//! every result. Objects are read into cut-down types (`objects`), so a Service spec, its addresses and
//! every annotation but the default-class marker are dropped while parsing (02 Appendix B rule 6).
//!
//! The levels are 03's (see `judge`): a required controller or API that is missing blocks, except on GKE
//! and OpenShift where a missing class or Gateway API is "not verified"; no default class, no accepted
//! `GatewayClass` and a pending load balancer older than 10 minutes warn; the retired community
//! `k8s.io/ingress-nginx` controller warns with the retirement text. Anything the identity may not read is
//! not evaluated, never a block: the result is partial with the grant to ask for.
//!
//! Not read: the Gateway API CRD annotations (`bundle-version`, `channel`), which need a `get
//! customresourcedefinitions` grant that no other M1 check holds; `Ingress`, `Gateway` and `HTTPRoute`
//! objects; and the `providerID` hint for the cloud load balancer. A note says what each leaves open.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::jiff::Timestamp;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::{K8sIngress, K8sName};

use crate::client::ReadOnlyClient;
use crate::cluster::Cluster;
use crate::namespace::{Read, has_more, out_of_time, read};

mod fix;
mod judge;
mod objects;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{GATEWAY_GROUP, Gathered, Groups, METALLB_GROUP, Page, Platform, ROUTE_GROUP};
use objects::{
    GatewayClassObject, IngressClassObject, ServiceObject, balancer_of, class_of, gateway_class_of,
};

/// The most objects one list asks for. A longer list is read as its first page and the rest is "not read".
const PAGE: u32 = 500;

/// The static facts about `k8s.ingress` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.ingress",
    family: "k8s",
    summary: "Ingress classes by controller, the Gateway API, the OpenShift Route API and pending load balancers",
    meta: CheckMeta {
        title: "Ingress",
        remediation: "Install an ingress controller your platform team supports, or tell the vendor which ingress classes exist (`kubectl get ingressclass`). For the Gateway API, install its CRDs and a controller. A LoadBalancer Service that stays pending needs a load balancer implementation: MetalLB on bare metal, the cloud controller manager in a cloud.",
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

/// `k8s.ingress`, built from its spec entry.
pub struct IngressCheck {
    params: K8sIngress,
    namespace: Option<K8sName>,
    cluster: Arc<dyn Cluster>,
    now: Option<Timestamp>,
}

impl std::fmt::Debug for IngressCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressCheck")
            .field("params", &self.params)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl IngressCheck {
    /// The check for `params`, reading `cluster`.
    ///
    /// `namespace` is the target namespace of the k8s block of the spec, where the LoadBalancer Services
    /// are looked for. With none, `loadbalancer: true` cannot be judged and the result says so.
    #[must_use]
    pub fn new(params: K8sIngress, namespace: Option<K8sName>, cluster: Arc<dyn Cluster>) -> Self {
        Self {
            params,
            namespace,
            cluster,
            now: None,
        }
    }

    /// Fixes the time that a Service's age is counted from. Tests use it; a run uses the clock.
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

impl Check for IngressCheck {
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

impl IngressCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let now = self.now.unwrap_or_else(Timestamp::now).as_second();

        let classes = read_classes(&mapper, &client).await?;
        let groups = if out_of_time(ctx) {
            Read::OutOfTime
        } else {
            read_groups(&mapper, &client).await?
        };

        // The Gateway API is asked about only when `GET /apis` says it is served at v1.
        let gateway_v1 = matches!(&groups, Read::Ok(g) if g.gateway.as_ref().is_some_and(|v| v.iter().any(|x| x == "v1")));
        let (gateway_kinds, gateway_classes) = if gateway_v1 {
            let kinds = if out_of_time(ctx) {
                Read::OutOfTime
            } else {
                read_kinds(&mapper, &client).await?
            };
            let classes = if out_of_time(ctx) {
                Read::OutOfTime
            } else {
                read_gateway_classes(&mapper, &client).await?
            };
            (Some(kinds), Some(classes))
        } else {
            (None, None)
        };

        let namespace = self.namespace.as_ref().map(|name| name.as_str().to_owned());
        let services = match (&namespace, self.params.loadbalancer) {
            (Some(namespace), true) => Some(if out_of_time(ctx) {
                Read::OutOfTime
            } else {
                read_services(&mapper, &client, namespace, now).await?
            }),
            _ => None,
        };

        let route = matches!(&groups, Read::Ok(g) if g.route);
        let platform = Platform {
            gke: self.cluster.server_version().git_version.contains("-gke."),
            openshift: self.cluster.is_openshift() || route,
        };
        Ok(Gathered {
            namespace,
            platform,
            classes,
            groups,
            gateway_kinds,
            gateway_classes,
            services,
        })
    }
}

/// The `IngressClass` list, first page. A server that does not serve the API (404) has no classes.
async fn read_classes(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
) -> Result<Read<Page<objects::Class>>, CheckError> {
    let answer = read(
        mapper,
        client
            .all::<IngressClassObject>()
            .list(&ListParams::default().limit(PAGE))
            .await,
        |list| {
            let cut = has_more(&list.metadata);
            let mut items: Vec<_> = list.items.into_iter().map(class_of).collect();
            items.sort_by(|a, b| a.name.cmp(&b.name));
            Page { items, cut }
        },
    )?;
    Ok(match answer {
        Read::Missing => Read::Ok(Page::empty()),
        other => other,
    })
}

/// `GET /apis`: the groups this check looks for.
async fn read_groups(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
) -> Result<Read<Groups>, CheckError> {
    read(mapper, client.api_groups().await, |list| {
        let mut groups = Groups::default();
        for group in &list.groups {
            match group.name.as_str() {
                GATEWAY_GROUP => {
                    groups.gateway = Some(
                        group
                            .versions
                            .iter()
                            .map(|version| version.version.clone())
                            .collect(),
                    );
                }
                ROUTE_GROUP => groups.route = true,
                METALLB_GROUP => groups.metallb = true,
                _ => {}
            }
        }
        groups
    })
}

/// The resources the Gateway API serves at `v1`, by plural name. Subresources are dropped.
async fn read_kinds(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
) -> Result<Read<Vec<String>>, CheckError> {
    read(
        mapper,
        client.group_resources(GATEWAY_GROUP, "v1").await,
        |list| {
            list.resources
                .into_iter()
                .filter(|resource| !resource.name.contains('/'))
                .map(|resource| resource.name)
                .collect()
        },
    )
}

/// The `GatewayClass` list, first page.
async fn read_gateway_classes(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
) -> Result<Read<Page<objects::GatewayClass>>, CheckError> {
    read(
        mapper,
        client
            .all::<GatewayClassObject>()
            .list(&ListParams::default().limit(PAGE))
            .await,
        |list| {
            let cut = has_more(&list.metadata);
            let mut items: Vec<_> = list.items.into_iter().map(gateway_class_of).collect();
            items.sort_by(|a, b| a.name.cmp(&b.name));
            Page { items, cut }
        },
    )
}

/// The Services of the namespace, first page, keeping the `LoadBalancer` ones.
async fn read_services(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    namespace: &str,
    now: i64,
) -> Result<Read<Page<objects::Balancer>>, CheckError> {
    read(
        mapper,
        client
            .namespaced::<ServiceObject>(namespace)
            .list(&ListParams::default().limit(PAGE))
            .await,
        |list| {
            let cut = has_more(&list.metadata);
            let mut items: Vec<_> = list
                .items
                .into_iter()
                .filter_map(|service| balancer_of(service, now))
                .collect();
            items.sort_by(|a, b| a.name.cmp(&b.name));
            Page { items, cut }
        },
    )
}
