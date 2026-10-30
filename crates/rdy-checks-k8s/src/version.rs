//! `k8s.version`: the server version, the distribution and the APIs the product needs (03 section 4).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - the run's `GET /version` (`gitVersion`, parsed; `major` and `minor` only as a fallback, because some
//!   distributions put a `+` in the minor);
//! - `GET /apis`, the group list: the OpenShift group `config.openshift.io`, and which group versions exist;
//! - on OpenShift, `GET` of the `ClusterVersion` named `version`, because the vendor's minimum is an
//!   OpenShift version while the API server says Kubernetes;
//! - the first page (500) of the node list: `spec.providerID`, a few labels and `kubeletVersion`, for the
//!   distribution (AKS has no version suffix) and for the kubelet skew;
//! - `GET /apis/<group>/<version>` (or `/api/v1`) for each API the spec lists.
//!
//! Only the version and the APIs are required to answer. A node list or a `ClusterVersion` the identity may
//! not read leaves a note, and a spec `openshift_min` or `apis` that cannot be judged makes the result
//! partial. Nothing the identity is not allowed to read ever blocks.
//!
//! How the spec's bounds apply:
//!
//! - `min` blocks below it. `max` warns above it, or blocks with `over_max: block`. Both compare over the
//!   parts they share, so `max: "1.31"` accepts every 1.31 patch.
//! - On an OpenShift cluster with `openshift_min` set, the OpenShift version is judged against it and `min`
//!   is not applied: `min` is a Kubernetes version, and OpenShift 4.14 reports Kubernetes 1.27. `max` still
//!   applies to the Kubernetes version. Off OpenShift, `openshift_min` does not apply.
//! - Every API in `apis` must be served, or the result blocks.
//! - A kubelet more than three minors behind the API server, or newer than it, warns.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Node;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Need, OsSupport, Partial, Support,
};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::{ApiRef, K8sVersion, OverMax};
use serde_json::{Map, Value, json};

use crate::client::from_kube_error;
use crate::client::guard::RULE_PATH_SHAPE;
use crate::client::{KubeError, ReadOnlyClient};
use crate::cluster::Cluster;

mod apis;
mod fix;
mod openshift;
mod server;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use openshift::ClusterVersion;
use server::{Distro, NodeFacts, Reported, compare, detect, dotted, parse_openshift};

/// The nodes `k8s.version` reads. A cluster with more has its kubelet skew judged on the first page.
const NODE_PAGE: u32 = 500;

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// How many nodes or APIs a sentence lists before it counts the rest.
const LISTED: usize = 3;

/// What the check says about the server in an error from the API.
const SERVER: &str = "the API server";

/// The static facts about `k8s.version` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.version",
    family: "k8s",
    summary: "Server version, distribution, API availability",
    meta: CheckMeta {
        title: "Kubernetes version",
        remediation: "Upgrade the cluster to a version in the range the vendor lists, one minor at a time. EKS: `aws eks update-cluster-version`. GKE: `gcloud container clusters upgrade`. AKS: `az aks upgrade`. OpenShift: `oc adm upgrade`. For an API that is not served, ask the vendor for a build that matches this Kubernetes version, or install the add-on that provides it. Keep every kubelet within three minors behind the API server.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(10)),
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

/// `k8s.version`, built from its spec entry.
pub struct VersionCheck {
    params: K8sVersion,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for VersionCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionCheck")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl VersionCheck {
    /// The check for `params`, reading `cluster`.
    #[must_use]
    pub fn new(params: K8sVersion, cluster: Arc<dyn Cluster>) -> Self {
        Self { params, cluster }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for VersionCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let gathered = self.gather(ctx).await?;
            Ok(judge(&self.params, &gathered))
        })
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

/// The answer to a read the server may refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn ok(&self) -> Option<&T> {
        match self {
            Self::Ok(value) => Some(value),
            _ => None,
        }
    }

    /// Why the read gave nothing, as a phrase.
    fn why(&self) -> String {
        match self {
            Self::Ok(_) => "it was read".to_owned(),
            Self::Forbidden => "the identity may not read it".to_owned(),
            Self::Missing => "the server does not have it".to_owned(),
            Self::Unreadable(code) => format!("the server answered {code}"),
        }
    }
}

/// Sorts the error of one request. A refusal by the server for this identity or a missing object is an
/// answer. Anything else (the network, the credentials, the guard) fails the check.
fn read<T, U>(
    result: Result<T, kube::Error>,
    map: impl FnOnce(T) -> U,
) -> Result<Read<U>, CheckError> {
    match result {
        Ok(value) => Ok(Read::Ok(map(value))),
        Err(error) => match from_kube_error(&error, SERVER, None, false, false) {
            KubeError::Forbidden { .. } => Ok(Read::Forbidden),
            KubeError::Api { code: 404, .. } => Ok(Read::Missing),
            KubeError::Api { code, .. } => Ok(Read::Unreadable(code)),
            // A group or version that cannot be one: it is not served.
            KubeError::Refused { rule, .. } if rule == RULE_PATH_SHAPE => Ok(Read::Missing),
            other => Err(CheckError::Failed {
                message: other.to_string(),
                hint: other.hint(),
            }),
        },
    }
}

/// One API of the spec, and whether the server serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Served {
    Yes,
    No,
    /// Discovery could not say. The text is a fixed phrase.
    Unknown(String),
}

/// What was read, before any judgement.
#[derive(Debug)]
struct Gathered {
    /// The `gitVersion` the server reported.
    reported: String,
    server: Option<Reported>,
    /// The groups and their versions from `/apis`.
    groups: Read<Vec<(String, Vec<String>)>>,
    /// The `ClusterVersion`, read only where the OpenShift group exists.
    cluster_version: Option<Read<ClusterVersion>>,
    /// The first page of nodes, and whether there were more.
    nodes: Read<(Vec<NodeFacts>, bool)>,
    /// The spec's APIs, in order.
    apis: Vec<(ApiRef, Served)>,
}

impl Gathered {
    fn openshift_group(&self) -> bool {
        self.groups
            .ok()
            .is_some_and(|groups| groups.iter().any(|(name, _)| name == "config.openshift.io"))
    }
}

impl VersionCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let reported = self.cluster.server_version();
        let server = Reported::parse(&reported.git_version)
            .or_else(|| Reported::from_major_minor(&reported.major, &reported.minor));
        if server.is_none() {
            // Nothing can be compared with the spec, so nothing more is asked of the cluster.
            return Ok(Gathered {
                reported: reported.git_version.clone(),
                server,
                groups: Read::Missing,
                cluster_version: None,
                nodes: Read::Missing,
                apis: Vec::new(),
            });
        }

        let groups = read(client.api_groups().await, |list| {
            list.groups
                .into_iter()
                .map(|group| {
                    let versions = group.versions.into_iter().map(|v| v.version).collect();
                    (group.name, versions)
                })
                .collect::<Vec<(String, Vec<String>)>>()
        })?;
        let openshift = groups
            .ok()
            .is_some_and(|groups| groups.iter().any(|(name, _)| name == "config.openshift.io"));
        let cluster_version = if openshift {
            Some(read(
                client.all::<ClusterVersion>().get("version").await,
                |version| version,
            )?)
        } else {
            None
        };
        let nodes = read(
            client
                .all::<Node>()
                .list(&ListParams::default().limit(NODE_PAGE))
                .await,
            |list| {
                let more = list
                    .metadata
                    .continue_
                    .as_deref()
                    .is_some_and(|token| !token.is_empty());
                (list.items.iter().map(NodeFacts::from_node).collect(), more)
            },
        )?;
        let apis = match &self.params.apis {
            Some(wanted) => served(&client, ctx, &groups, wanted).await?,
            None => Vec::new(),
        };
        Ok(Gathered {
            reported: reported.git_version.clone(),
            server,
            groups,
            cluster_version,
            nodes,
            apis,
        })
    }
}

/// Asks discovery about each API, once per group version.
async fn served(
    client: &ReadOnlyClient,
    ctx: &CheckContext,
    groups: &Read<Vec<(String, Vec<String>)>>,
    wanted: &[ApiRef],
) -> Result<Vec<(ApiRef, Served)>, CheckError> {
    let mut kinds: BTreeMap<(Option<String>, String), Read<Vec<String>>> = BTreeMap::new();
    let mut out = Vec::with_capacity(wanted.len());
    for api in wanted {
        let key = (api.group().map(str::to_owned), api.version().to_owned());
        if !kinds.contains_key(&key) && out_of_time(ctx.remaining()) {
            // Better a partial answer now than a timeout with none.
            out.push((
                api.clone(),
                Served::Unknown("rdy ran out of time".to_owned()),
            ));
            continue;
        }
        if !kinds.contains_key(&key) {
            let listed = match &key.0 {
                None => read(client.core_resources(&key.1).await, resource_kinds)?,
                // `/apis` already says the group version does not exist: no request needed.
                Some(group) if absent(groups, group, &key.1) => Read::Missing,
                Some(group) => read(client.group_resources(group, &key.1).await, resource_kinds)?,
            };
            kinds.insert(key.clone(), listed);
        }
        let state = match kinds.get(&key) {
            Some(Read::Ok(list)) if list.iter().any(|kind| kind == api.kind()) => Served::Yes,
            Some(Read::Ok(_) | Read::Missing) | None => Served::No,
            Some(other) => Served::Unknown(other.why()),
        };
        out.push((api.clone(), state));
    }
    Ok(out)
}

/// True when too little of the check's time is left to ask the cluster another question.
fn out_of_time(remaining: Duration) -> bool {
    remaining < Duration::from_millis(500)
}

/// The top-level kinds of a discovery document. A name with a `/` is a subresource.
fn resource_kinds(
    list: k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList,
) -> Vec<String> {
    list.resources
        .into_iter()
        .filter(|resource| !resource.name.contains('/'))
        .map(|resource| resource.kind)
        .collect()
}

/// True when `/apis` was read and does not list `group` at `version`.
fn absent(groups: &Read<Vec<(String, Vec<String>)>>, group: &str, version: &str) -> bool {
    groups.ok().is_some_and(|groups| {
        !groups
            .iter()
            .any(|(name, versions)| name == group && versions.iter().any(|v| v == version))
    })
}

// ---- judging --------------------------------------------------------------------------------------------------

/// One thing that is not as the spec wants.
struct Problem {
    level: Level,
    text: String,
    fix: String,
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Pass => 0,
        Level::Warn => 1,
        Level::Fail => 2,
    }
}

/// Text from the server or the cluster, safe for a terminal and cut short.
fn shown(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(SHOWN).collect();
    let mut out = escape_untrusted(&head);
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// `a, b, c` and `and N more` for a long list.
fn listed(items: &[String]) -> String {
    let head = items
        .iter()
        .take(LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match items.len().checked_sub(LISTED) {
        Some(rest) if rest > 0 => format!("{head}, and {rest} more"),
        _ => head,
    }
}

/// Turns what was read into a finding. A pure function: the fixture tests and the unit tests both call it.
fn judge(params: &K8sVersion, facts: &Gathered) -> Finding {
    let Some(server) = &facts.server else {
        return unreadable(params, facts);
    };
    let distro = detect(
        server,
        facts.openshift_group(),
        facts
            .nodes
            .ok()
            .map_or(&[][..], |(nodes, _)| nodes.as_slice()),
    );
    let mut problems: Vec<Problem> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    let mut grants: Vec<String> = Vec::new();

    // OpenShift: the OpenShift version against `openshift_min`, and `min` is left to non-OpenShift clusters.
    let on_openshift = distro == Distro::OpenShift;
    let openshift_version = facts
        .cluster_version
        .as_ref()
        .and_then(Read::ok)
        .and_then(|version| version.version())
        .map(str::to_owned);
    let judged_on_openshift = on_openshift && params.openshift_min.is_some();
    if judged_on_openshift && params.min.is_some() {
        notes.push(
            "min is a Kubernetes version and is not applied here: this cluster is OpenShift, judged on openshift_min."
                .to_owned(),
        );
    }
    if let (true, Some(need)) = (on_openshift, &params.openshift_min) {
        match (&facts.cluster_version, &openshift_version) {
            (Some(Read::Ok(version)), Some(have)) => {
                match parse_openshift(have) {
                    Some(parts) if compare(&parts, need.components()) == Ordering::Less => {
                        problems.push(Problem {
                            level: Level::Fail,
                            text: format!(
                                "OpenShift {} is older than the {} minimum (Kubernetes {})",
                                shown(have),
                                need.as_str(),
                                shown(&facts.reported)
                            ),
                            fix: fix::below_openshift_min(&shown(have), need.components()),
                        });
                    }
                    Some(_) => {}
                    None => unverified.push(format!(
                        "OpenShift reports the version `{}`, which rdy cannot read",
                        shown(have)
                    )),
                }
                if version.updating() {
                    notes.push(
                        "An OpenShift update is running. The version is the one it is moving to."
                            .to_owned(),
                    );
                }
            }
            (Some(other), _) => {
                unverified.push(format!(
                    "openshift_min was not checked: the ClusterVersion could not be read ({})",
                    match other {
                        Read::Ok(_) => "it names no version".to_owned(),
                        other => other.why(),
                    }
                ));
                if matches!(other, Read::Forbidden) {
                    grants.push("get clusterversions.config.openshift.io/version".to_owned());
                }
            }
            (None, _) => {}
        }
    } else if let Some(min) = &params.min
        && compare(server.parts(), min.components()) == Ordering::Less
    {
        problems.push(Problem {
            level: Level::Fail,
            text: format!(
                "Server {} is older than the {} minimum",
                shown(&facts.reported),
                min.as_str()
            ),
            fix: fix::below_min(distro, server, min.components()),
        });
    }

    if let Some(max) = &params.max
        && compare(server.parts(), max.components()) == Ordering::Greater
    {
        let level = match params.over_max {
            OverMax::Block => Level::Fail,
            _ => Level::Warn,
        };
        problems.push(Problem {
            level,
            text: format!(
                "Server {} is newer than {}, the newest this product is tested on",
                shown(&facts.reported),
                max.as_str()
            ),
            fix: fix::above_max(server, max.components()),
        });
    }

    // Kubelet skew: evidence from the node list, never a reason to be partial.
    match &facts.nodes {
        Read::Ok((nodes, more)) => {
            if let Some(problem) = skew(server, nodes) {
                problems.push(problem);
            }
            if *more {
                notes.push(format!(
                    "Kubelet skew was judged on the first {NODE_PAGE} nodes only."
                ));
            }
        }
        other => notes.push(format!(
            "Kubelet skew was not checked: the node list could not be read ({}). Grant `list` on `nodes` to check it.",
            other.why()
        )),
    }

    // APIs.
    let missing: Vec<&ApiRef> = facts
        .apis
        .iter()
        .filter(|(_, state)| *state == Served::No)
        .map(|(api, _)| api)
        .collect();
    if !missing.is_empty() {
        let names: Vec<String> = missing.iter().map(|api| apis::show(api)).collect();
        let text = if let [only] = names.as_slice() {
            format!("{only} is not served")
        } else {
            format!(
                "{} required APIs are not served: {}",
                names.len(),
                listed(&names)
            )
        };
        let fix = missing
            .iter()
            .take(LISTED)
            .map(|api| apis::why_missing(api, Some(server.minor())))
            .collect::<Vec<_>>()
            .join(" ");
        problems.push(Problem {
            level: Level::Fail,
            text,
            fix,
        });
    }
    for (api, state) in &facts.apis {
        if let Served::Unknown(why) = state {
            unverified.push(format!("{} was not checked: {why}", apis::show(api)));
        }
    }
    if !matches!(facts.groups, Read::Ok(_)) && !facts.apis.is_empty() {
        notes.push(format!(
            "The group list could not be read ({}), so every API was asked for one by one.",
            facts.groups.why()
        ));
    }

    problems.sort_by_key(|problem| std::cmp::Reverse(rank(problem.level)));
    let level = problems.first().map_or(Level::Pass, |p| p.level);
    let observed = observed(facts, server, distro, openshift_version.as_deref());
    let expected = expected(params);

    let mut finding = match problems.first() {
        Some(first) => {
            let more = problems.len() - 1;
            let message = if more == 0 {
                first.text.clone()
            } else {
                format!("{} (and {more} more, see the notes)", first.text)
            };
            let mut finding = Finding::new(level, message);
            for problem in problems.iter().skip(1) {
                finding = finding.with_note(problem.text.clone());
            }
            finding.with_fix(
                problems
                    .iter()
                    .map(|problem| problem.fix.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        }
        None => pass_message(
            params,
            facts,
            judged_on_openshift,
            openshift_version.as_deref(),
        ),
    };
    for note in notes {
        finding = finding.with_note(note);
    }
    if !unverified.is_empty() {
        finding = finding.with_partial(
            Partial::new(Vec::new(), unverified.join("; ")).with_missing_grants(grants),
        );
    }
    finding.with_observed(observed).with_expected(expected)
}

/// The finding when nothing is wrong.
fn pass_message(
    params: &K8sVersion,
    facts: &Gathered,
    judged_on_openshift: bool,
    openshift_version: Option<&str>,
) -> Finding {
    let on_openshift = facts.openshift_group();
    // The spec holds only `openshift_min` and this is not OpenShift: nothing applies.
    if params.openshift_min.is_some()
        && !on_openshift
        && params.min.is_none()
        && params.max.is_none()
        && params.apis.is_none()
    {
        return Finding::pass_by_absence(format!(
            "Server {} is not OpenShift, so openshift_min does not apply",
            shown(&facts.reported)
        ));
    }
    let head = match (judged_on_openshift, openshift_version) {
        (true, Some(version)) => format!(
            "OpenShift {} (Kubernetes {})",
            shown(version),
            shown(&facts.reported)
        ),
        _ => format!("Server {}", shown(&facts.reported)),
    };
    // On OpenShift the bound is the OpenShift one, and only where its version was read.
    let min = if judged_on_openshift {
        openshift_version.and(params.openshift_min.as_ref())
    } else {
        params.min.as_ref()
    };
    let range = match (min, &params.max) {
        (Some(min), Some(max)) => Some(format!("{} to {} needed", min.as_str(), max.as_str())),
        (Some(min), None) => Some(format!("{} or newer needed", min.as_str())),
        (None, Some(max)) => Some(format!("{} or older needed", max.as_str())),
        (None, None) => None,
    };
    let mut message = head;
    if let Some(range) = range {
        message.push_str(", ");
        message.push_str(&range);
    }
    match facts.apis.len() {
        0 => {}
        1 => message.push_str(", 1 API served"),
        n => message.push_str(&format!(", {n} APIs served")),
    }
    Finding::pass(message)
}

/// Kubelets more than three minors behind the API server, or newer than it.
fn skew(server: &Reported, nodes: &[NodeFacts]) -> Option<Problem> {
    let mut behind: Vec<String> = Vec::new();
    let mut ahead: Vec<String> = Vec::new();
    for node in nodes.iter().filter(|node| !node.virtual_kubelet) {
        let Some(kubelet) = &node.kubelet else {
            continue;
        };
        if kubelet.major() != server.major() {
            continue;
        }
        let label = format!("{} ({})", shown(&node.name), kubelet.dotted());
        match server.minor().cmp(&kubelet.minor()) {
            Ordering::Less => ahead.push(label),
            Ordering::Greater if server.minor() - kubelet.minor() > 3 => behind.push(label),
            _ => {}
        }
    }
    let mut texts = Vec::new();
    if !behind.is_empty() {
        texts.push(format!(
            "{} {} more than three minors behind the API server: {}",
            behind.len(),
            if behind.len() == 1 {
                "kubelet is"
            } else {
                "kubelets are"
            },
            listed(&behind)
        ));
    }
    if !ahead.is_empty() {
        texts.push(format!(
            "{} {} newer than the API server: {}",
            ahead.len(),
            if ahead.len() == 1 {
                "kubelet is"
            } else {
                "kubelets are"
            },
            listed(&ahead)
        ));
    }
    (!texts.is_empty()).then(|| Problem {
        level: Level::Warn,
        text: texts.join("; "),
        fix: fix::skew().to_owned(),
    })
}

/// The result when the server's version text cannot be read as a Kubernetes version.
fn unreadable(params: &K8sVersion, facts: &Gathered) -> Finding {
    Finding::warn(format!(
        "The server reported the version `{}`, which rdy cannot read as a Kubernetes version",
        shown(&facts.reported)
    ))
    .with_partial(Partial::new(
        Vec::new(),
        "the server version could not be compared with the spec",
    ))
    .with_observed(json!({"git_version": shown(&facts.reported)}))
    .with_expected(expected(params))
    .with_fix("Run `kubectl version` and check that it shows a version such as v1.29.4. Tell the vendor which distribution this is.")
}

fn observed(
    facts: &Gathered,
    server: &Reported,
    distro: Distro,
    openshift_version: Option<&str>,
) -> Value {
    let mut map = Map::new();
    map.insert("git_version".into(), json!(shown(&facts.reported)));
    map.insert("kubernetes".into(), json!(server.dotted()));
    map.insert("distribution".into(), json!(distro.wire()));
    if let Some((nodes, _)) = facts.nodes.ok() {
        if let Some(cloud) = server::cloud(nodes) {
            map.insert("cloud".into(), json!(cloud));
        }
        let minors: BTreeSet<String> = nodes
            .iter()
            .filter(|node| !node.virtual_kubelet)
            .filter_map(|node| node.kubelet.as_ref())
            .map(|kubelet| dotted(&[kubelet.major(), kubelet.minor()]))
            .collect();
        map.insert("nodes_read".into(), json!(nodes.len()));
        map.insert("kubelet_minors".into(), json!(minors));
    }
    if let Some(version) = openshift_version {
        map.insert("openshift_version".into(), json!(shown(version)));
    }
    if !facts.apis.is_empty() {
        let apis: Vec<Value> = facts
            .apis
            .iter()
            .map(|(api, state)| {
                let served = match state {
                    Served::Yes => Value::Bool(true),
                    Served::No => Value::Bool(false),
                    Served::Unknown(_) => Value::Null,
                };
                json!({"api": apis::show(api), "served": served})
            })
            .collect();
        map.insert("apis".into(), Value::Array(apis));
    }
    Value::Object(map)
}

/// The effective thresholds: what the spec set, and `over_max` only where `max` is set.
fn expected(params: &K8sVersion) -> Value {
    let mut map = Map::new();
    if let Some(min) = &params.min {
        map.insert("min".into(), json!(min.as_str()));
    }
    if let Some(max) = &params.max {
        map.insert("max".into(), json!(max.as_str()));
        let over = match params.over_max {
            OverMax::Block => "block",
            _ => "warn",
        };
        map.insert("over_max".into(), json!(over));
    }
    if let Some(min) = &params.openshift_min {
        map.insert("openshift_min".into(), json!(min.as_str()));
    }
    if let Some(wanted) = &params.apis {
        let apis: Vec<String> = wanted.iter().map(apis::show).collect();
        map.insert("apis".into(), json!(apis));
    }
    Value::Object(map)
}
