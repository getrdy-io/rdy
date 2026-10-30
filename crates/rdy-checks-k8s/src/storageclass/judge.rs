//! The judgement of `k8s.storageclass`: pure functions from what was read to a [`Finding`].
//!
//! Nothing here touches the cluster. The check reads in stages (classes, then driver evidence for the class
//! it picked, then the waiting claims) and calls the matching function after each stage; the functions add
//! to one [`Verdict`]. [`Verdict::finish`] turns it into the finding.
//!
//! How the rules of 03 map to levels:
//!
//! - A requirement that is not met on data that was read is `Fail`, and the spec's severity says whether
//!   that blocks or warns.
//! - A softer problem (the node plugin may be down, expansion is off, a reclaim policy differs) is `Warn`.
//! - Data that could not be read is never a `Fail` and never a `Pass`. It is a `Warn` that says what was not
//!   verified, with the grant that would complete it in `partial.missing_grants`. The one exception is
//!   a positive answer from the weaker source: a `CSIDriver` object found while `CSINode` is unreadable is
//!   a `Pass` with a partial, which the engine turns into "not verified".

use rdy_engine::check::{Finding, Level, Partial};
use rdy_spec::check::{AccessMode, K8sStorageClass, ReclaimPolicy, VolumeBinding};
use serde_json::{Map, Value, json};

use super::facts::{Binding, Class, Page, Read, Reclaim, Registered, Waiting, command_arg, token};
use super::fix;
use crate::provisioners::{Kind, Normalised, Topology};

/// Server versions below this one fail a persistent volume claim when two classes are the default.
const ONE_DEFAULT_BEFORE: (u64, u64) = (1, 26);

/// The classes shown by name in a sentence before the rest are counted.
const LISTED: usize = 5;

/// The longest `observed` list: names of waiting claims.
const OBSERVED_LIST: usize = 20;

/// The classes that were read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Classes {
    /// The list, or its first page.
    Listed(Page<Class>),
    /// The list was refused and the spec names a class, so the class was fetched by name.
    ByName(super::facts::Read<Class>),
    /// The list could not be read and the spec names no class.
    NoList(super::facts::Read<()>),
}

/// How the class under judgement was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum How {
    /// The spec names it.
    Named,
    /// It is the cluster's default.
    Default,
}

/// The class the rest of the check judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Chosen {
    pub(super) class: Class,
    pub(super) how: How,
}

impl Chosen {
    /// `Default class gp3` or `Class gp3`.
    fn label(&self) -> String {
        let name = token(&self.class.name);
        match self.how {
            How::Named => format!("Class {name}"),
            How::Default => format!("Default class {name}"),
        }
    }
}

/// Why a source gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unread {
    /// 403.
    Forbidden,
    /// The list was longer than the page that was read.
    Capped,
    /// Another status.
    Status(u16),
    /// The check had too little time left to ask.
    Time,
}

impl Unread {
    /// How the sentence says the list stands: `the CSINode list {state}`.
    fn state(self) -> &'static str {
        match self {
            Self::Forbidden => "may not be listed by this identity",
            Self::Capped => "is longer than the page rdy read",
            Self::Status(_) => "could not be read",
            Self::Time => "was not read, the check ran out of time",
        }
    }
}

/// A permission the identity lacked, in the words of `kubectl auth can-i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Grant {
    verb: &'static str,
    resource: &'static str,
    /// The API group, empty for the core group.
    group: &'static str,
    /// The namespace the verb is needed in, for a namespaced list.
    namespace: Option<String>,
}

impl Grant {
    pub(super) fn cluster(verb: &'static str, resource: &'static str, group: &'static str) -> Self {
        Self {
            verb,
            resource,
            group,
            namespace: None,
        }
    }

    pub(super) fn namespaced(verb: &'static str, resource: &'static str, namespace: &str) -> Self {
        Self {
            verb,
            resource,
            group: "",
            namespace: Some(namespace.to_owned()),
        }
    }

    /// The wire text: `list csinodes (storage.k8s.io)`, `list events in acme-system`.
    pub(super) fn text(&self) -> String {
        let mut text = format!("{} {}", self.verb, self.resource);
        if !self.group.is_empty() {
            text.push_str(&format!(" ({})", self.group));
        }
        if let Some(namespace) = &self.namespace {
            text.push_str(&format!(" in {}", token(namespace)));
        }
        text
    }

    /// The command that checks it.
    pub(super) fn can_i(&self) -> String {
        let group = if self.group.is_empty() {
            String::new()
        } else {
            format!(".{}", self.group)
        };
        let namespace = self.namespace.as_ref().map_or_else(String::new, |ns| {
            format!(" -n {}", command_arg(ns, "<namespace>"))
        });
        format!(
            "`kubectl auth can-i {} {}{group}{namespace}`",
            self.verb, self.resource
        )
    }
}

/// What the `CSINode` list says about a driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Nodes {
    /// At least one node lists the driver.
    Found(Registered),
    /// The whole list was read and no node lists it.
    NotFound(Registered),
    /// The list was not read, or not read to the end without a hit.
    Unknown(Unread),
}

/// What the `CSIDriver` list says about a driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Object {
    /// A `CSIDriver` object has the name.
    Found,
    /// The whole list was read and has no such object.
    NotFound,
    /// The list was not read to the end.
    Unknown(Unread),
}

/// The driver evidence for the chosen class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) nodes: Nodes,
    /// Not read when a node already lists the driver.
    pub(super) object: Option<Object>,
}

/// What the check says in its sentence about the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DriverNote {
    None,
    Registered(Registered),
    Declared,
    NotVerified,
}

/// What `observed` says about the driver evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceSource {
    Csinode,
    Csidriver,
    None,
    Unread,
    NotNeeded,
}

impl EvidenceSource {
    fn word(self) -> &'static str {
        match self {
            Self::Csinode => "csinode",
            Self::Csidriver => "csidriver",
            Self::None => "none",
            Self::Unread => "unread",
            Self::NotNeeded => "not_needed",
        }
    }
}

/// How an access mode stands against the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Support {
    Yes,
    No(String),
    Unverified(String),
}

/// The words of an access mode.
pub(super) fn mode_name(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::ReadWriteOnce => "ReadWriteOnce",
        AccessMode::ReadOnlyMany => "ReadOnlyMany",
        AccessMode::ReadWriteMany => "ReadWriteMany",
        AccessMode::ReadWriteOncePod => "ReadWriteOncePod",
        _ => "an unknown access mode",
    }
}

fn list_names(names: &[String]) -> String {
    let shown: Vec<String> = names.iter().take(LISTED).map(|n| token(n)).collect();
    let rest = names.len().saturating_sub(LISTED);
    if rest == 0 {
        shown.join(", ")
    } else {
        format!("{} and {rest} more", shown.join(", "))
    }
}

/// A problem found, with the fix for it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Issue {
    level: Level,
    message: String,
    fix: Option<String>,
}

/// Everything the stages found, until [`Verdict::finish`].
#[derive(Debug, Default)]
pub(super) struct Verdict {
    issues: Vec<Issue>,
    notes: Vec<String>,
    unread: Vec<String>,
    grants: Vec<Grant>,
    /// A pass that rests on weaker evidence than the check wanted: the engine shows it as "not verified".
    partial_pass: bool,
    observed: Map<String, Value>,
    // The parts of the pass sentence.
    chosen: Option<Chosen>,
    provisioner: Option<String>,
    modes_ok: Vec<&'static str>,
    driver: Option<DriverNote>,
}

impl Verdict {
    pub(super) fn new() -> Self {
        Self {
            driver: Some(DriverNote::None),
            ..Self::default()
        }
    }

    fn fail(&mut self, message: String, fix: Option<String>) {
        self.issues.push(Issue {
            level: Level::Fail,
            message,
            fix,
        });
    }

    fn warn(&mut self, message: String, fix: Option<String>) {
        self.issues.push(Issue {
            level: Level::Warn,
            message,
            fix,
        });
    }

    /// Records data that could not be read: what it was, and the grant that would complete it (none for a
    /// status that is not a refusal).
    pub(super) fn unread(&mut self, what: &str, grant: Option<Grant>) {
        if !self.unread.iter().any(|w| w == what) {
            self.unread.push(what.to_owned());
        }
        if let Some(grant) = grant
            && !self.grants.contains(&grant)
        {
            self.grants.push(grant);
        }
    }

    fn observe(&mut self, key: &str, value: Value) {
        self.observed.insert(key.to_owned(), value);
    }

    /// Adds a note that is not a problem.
    pub(super) fn note(&mut self, text: String) {
        self.notes.push(text);
    }

    /// Records that the target namespace is not there, so no claim in it was read. Whether the namespace
    /// must exist is the business of `k8s.namespace`, so this is a note and not a problem.
    pub(super) fn namespace_missing(&mut self, namespace: &str) {
        self.notes.push(format!(
            "The namespace {} does not exist, so no claim in it was read",
            token(namespace)
        ));
        self.observe("pending_claims", json!("namespace does not exist"));
    }

    /// Records the events of the waiting claims that the identity may not list.
    pub(super) fn events_forbidden(&mut self, namespace: &str) {
        self.unread(
            "the claim events",
            Some(Grant::namespaced("list", "events", namespace)),
        );
    }

    /// Records a claim list that could not be read (the claims are evidence, not a requirement).
    pub(super) fn claims_unread(&mut self, namespace: &str, reason: &Unread) {
        let grant = matches!(reason, Unread::Forbidden)
            .then(|| Grant::namespaced("list", "persistentvolumeclaims", namespace));
        self.unread(
            &format!("the waiting claims in {}", token(namespace)),
            grant,
        );
        self.observe("pending_claims", json!("not read"));
    }
}

// ---- stage 1: which class ----------------------------------------------------------------------------------

/// Picks the class to judge.
///
/// `server` is the Kubernetes version as (major, minor), when it could be read.
pub(super) fn select(
    verdict: &mut Verdict,
    params: &K8sStorageClass,
    classes: &Classes,
    server: Option<(u64, u64)>,
) -> Option<Chosen> {
    if let Some((major, minor)) = server {
        verdict.observe("server_minor", json!(format!("{major}.{minor}")));
    }
    let wanted = params.class.as_ref().map(|name| name.as_str());
    match (classes, wanted) {
        (Classes::NoList(why), _) => {
            list_unreadable(verdict, why);
            None
        }
        (Classes::ByName(read), Some(name)) => by_name(verdict, read, name),
        // `ByName` follows a refused list and needs a class name in the spec, so this pair is never built.
        // If it were, say "not verified" with the grant for the list, and never pass.
        (Classes::ByName(_), None) => {
            list_unreadable(verdict, &Read::Forbidden);
            None
        }
        (Classes::Listed(page), Some(name)) => listed_named(verdict, page, name),
        (Classes::Listed(page), None) => listed_default(verdict, page, server),
    }
}

fn list_unreadable(verdict: &mut Verdict, why: &super::facts::Read<()>) {
    use super::facts::Read;
    verdict.observe("classes_complete", json!(false));
    match why {
        Read::Forbidden => {
            verdict.unread(
                "the storage class list",
                Some(Grant::cluster("list", "storageclasses", "storage.k8s.io")),
            );
            verdict.warn(
                "Not verified: the identity may not list storage classes".to_owned(),
                None,
            );
        }
        Read::Unreadable(code) => {
            verdict.unread("the storage class list", None);
            verdict.warn(
                format!("Not verified: the server answered {code} to the storage class list"),
                Some(
                    "Run `kubectl get storageclass` with the same kubeconfig to see the error."
                        .to_owned(),
                ),
            );
        }
        Read::Missing | Read::Ok(()) => {
            verdict.unread("the storage class list", None);
            verdict.warn(
                "Not verified: the server has no storage class API".to_owned(),
                Some(
                    "Run `kubectl get storageclass` with the same kubeconfig to see the error."
                        .to_owned(),
                ),
            );
        }
    }
}

fn by_name(verdict: &mut Verdict, read: &super::facts::Read<Class>, name: &str) -> Option<Chosen> {
    use super::facts::Read;
    verdict.observe("classes_complete", json!(false));
    match read {
        Read::Ok(class) => Some(Chosen {
            class: class.clone(),
            how: How::Named,
        }),
        Read::Missing => {
            missing_class(verdict, name, &[], false);
            None
        }
        Read::Forbidden => {
            verdict.unread(
                &format!("storage class {}", token(name)),
                Some(Grant::cluster("get", "storageclasses", "storage.k8s.io")),
            );
            verdict.warn(
                format!(
                    "Not verified: the identity may not read the storage class {}",
                    token(name)
                ),
                None,
            );
            None
        }
        Read::Unreadable(code) => {
            verdict.unread(&format!("storage class {}", token(name)), None);
            verdict.warn(
                format!(
                    "Not verified: the server answered {code} for the storage class {}",
                    token(name)
                ),
                None,
            );
            None
        }
    }
}

fn missing_class(verdict: &mut Verdict, name: &str, have: &[String], more: bool) {
    let shown = token(name);
    let existing = if have.is_empty() {
        "The cluster has no storage class.".to_owned()
    } else {
        format!(
            "It has: {}{}.",
            list_names(have),
            if more { " (first page)" } else { "" }
        )
    };
    verdict.fail(
        format!("Storage class {shown} does not exist. {existing}"),
        Some(fix::create_class(&shown)),
    );
}

fn listed_named(verdict: &mut Verdict, page: &Page<Class>, name: &str) -> Option<Chosen> {
    verdict.observe("classes_read", json!(page.items.len()));
    verdict.observe("classes_complete", json!(!page.more));
    if let Some(class) = page.items.iter().find(|class| class.name == name) {
        return Some(Chosen {
            class: class.clone(),
            how: How::Named,
        });
    }
    if page.more {
        // The class may be on a page that was not read.
        verdict.unread("the storage classes after the first page", None);
        verdict.warn(
            format!(
                "Not verified: the cluster has more than {} storage classes and {} is not in the first page",
                page.items.len(),
                token(name)
            ),
            None,
        );
    } else {
        let have: Vec<String> = page.items.iter().map(|c| c.name.clone()).collect();
        missing_class(verdict, name, &have, false);
    }
    None
}

fn listed_default(
    verdict: &mut Verdict,
    page: &Page<Class>,
    server: Option<(u64, u64)>,
) -> Option<Chosen> {
    verdict.observe("classes_read", json!(page.items.len()));
    verdict.observe("classes_complete", json!(!page.more));
    let mut defaults: Vec<&Class> = page.items.iter().filter(|class| class.default).collect();
    // Newest first, then by name: the class the API server uses when there are several.
    defaults.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.name.cmp(&b.name)));
    let names: Vec<Value> = defaults.iter().map(|c| json!(token(&c.name))).collect();
    verdict.observe("default_classes", Value::Array(names));
    match defaults.as_slice() {
        [] if page.more => {
            verdict.unread("the storage classes after the first page", None);
            verdict.warn(
                format!(
                    "Not verified: no default class in the first {} storage classes, and there are more",
                    page.items.len()
                ),
                None,
            );
            None
        }
        [] => {
            let have: Vec<String> = page.items.iter().map(|c| c.name.clone()).collect();
            let (message, fix_text) = match suggest(&have) {
                Some(name) => (
                    format!(
                        "No default storage class. The cluster has: {}",
                        list_names(&have)
                    ),
                    fix::mark_default(&name),
                ),
                None => (
                    "No default storage class. The cluster has no storage class".to_owned(),
                    fix::no_classes(),
                ),
            };
            verdict.fail(message, Some(fix_text));
            None
        }
        [only] => {
            if page.more {
                // A second default may sit on a page that was not read.
                verdict.unread("the storage classes after the first page", None);
            }
            Some(Chosen {
                class: (*only).clone(),
                how: How::Default,
            })
        }
        [first, rest @ ..] => {
            let all: Vec<String> = defaults.iter().map(|c| c.name.clone()).collect();
            let others: Vec<String> = rest.iter().map(|c| c.name.clone()).collect();
            let list = list_names(&all);
            let fix_text = fix::unmark_defaults(&others);
            match server {
                Some(version) if version < ONE_DEFAULT_BEFORE => verdict.fail(
                    format!(
                        "{} storage classes are marked as the default ({list}). Kubernetes {}.{} rejects a claim with no class when there are several",
                        defaults.len(),
                        version.0,
                        version.1,
                    ),
                    Some(fix_text),
                ),
                Some(_) => verdict.warn(
                    format!(
                        "{} storage classes are marked as the default ({list}). The newest, {}, is used",
                        defaults.len(),
                        token(&first.name)
                    ),
                    Some(fix_text),
                ),
                None => verdict.warn(
                    format!(
                        "{} storage classes are marked as the default ({list}). A server older than 1.26 rejects a claim with no class when there are several, and rdy could not read the server version",
                        defaults.len()
                    ),
                    Some(fix_text),
                ),
            }
            Some(Chosen {
                class: (*first).clone(),
                how: How::Default,
            })
        }
    }
}

/// The class to suggest as the default: a managed-service class by name, else the first class by name.
fn suggest(names: &[String]) -> Option<String> {
    const KNOWN: [&str; 4] = ["standard-rwo", "managed-csi", "gp3-csi", "gp3"];
    for known in KNOWN {
        if names.iter().any(|name| name == known) {
            return Some(known.to_owned());
        }
    }
    names.iter().min().cloned()
}

// ---- stage 2: the driver ---------------------------------------------------------------------------------

/// Whether the chosen class needs `CSINode` and `CSIDriver` evidence: it does for a CSI driver.
pub(super) fn needs_evidence(kind: &Kind<'_>) -> bool {
    matches!(kind, Kind::Csi(_) | Kind::MigratedCsi)
}

/// What the driver evidence means for the chosen class.
pub(super) fn judge_driver(
    verdict: &mut Verdict,
    chosen: &Chosen,
    normalised: &Normalised<'_>,
    kind: &Kind<'_>,
    evidence: Option<&Evidence>,
) {
    let class = token(&chosen.class.name);
    let driver = token(normalised.name);
    verdict.chosen = Some(chosen.clone());
    verdict.provisioner = Some(if normalised.migrated {
        format!("{} via {driver}", token(&chosen.class.provisioner))
    } else {
        token(&chosen.class.provisioner)
    });
    verdict.observe("class", json!(token(&chosen.class.name)));
    verdict.observe(
        "selected",
        json!(match chosen.how {
            How::Named => "named",
            How::Default => "default",
        }),
    );
    verdict.observe("provisioner", json!(token(&chosen.class.provisioner)));
    if normalised.migrated {
        verdict.observe("serving_driver", json!(driver));
    }
    verdict.observe(
        "driver_kind",
        json!(match kind {
            Kind::NoProvisioner => "static",
            Kind::Csi(_) => "csi",
            Kind::MigratedCsi => "csi_by_migration",
            Kind::NotCsi(_) => "not_csi",
            Kind::Unknown => "unknown",
        }),
    );
    let source = match (kind, evidence) {
        (Kind::NoProvisioner, _) => {
            verdict.driver = Some(DriverNote::NotVerified);
            verdict.note(
                "kubernetes.io/no-provisioner creates no volumes. An admin must create them by hand"
                    .to_owned(),
            );
            EvidenceSource::NotNeeded
        }
        (Kind::NotCsi(_) | Kind::Unknown, _) => {
            verdict.driver = Some(DriverNote::NotVerified);
            EvidenceSource::NotNeeded
        }
        (Kind::Csi(_) | Kind::MigratedCsi, Some(evidence)) => {
            csi_evidence(verdict, &class, &driver, evidence)
        }
        // The caller reads the evidence for a CSI driver; without it nothing is claimed.
        (Kind::Csi(_) | Kind::MigratedCsi, None) => {
            verdict.driver = Some(DriverNote::NotVerified);
            EvidenceSource::Unread
        }
    };
    verdict.observe("driver_evidence", json!(source.word()));
}

fn csi_evidence(
    verdict: &mut Verdict,
    class: &str,
    driver: &str,
    evidence: &Evidence,
) -> EvidenceSource {
    if let Nodes::Found(registered) | Nodes::NotFound(registered) = evidence.nodes {
        verdict.observe("csinodes_read", json!(registered.read));
        verdict.observe("csinodes_with_driver", json!(registered.with_driver));
    }
    match (evidence.nodes, evidence.object) {
        (Nodes::Found(registered), _) => {
            verdict.driver = Some(DriverNote::Registered(registered));
            EvidenceSource::Csinode
        }
        (Nodes::NotFound(_), Some(Object::Found)) => {
            verdict.driver = Some(DriverNote::Declared);
            verdict.warn(
                format!(
                    "The driver {driver} has a CSIDriver object, but no node has registered it, so PVCs on {class} may stay Pending"
                ),
                Some(fix::node_plugin(driver)),
            );
            EvidenceSource::Csidriver
        }
        (Nodes::NotFound(_), Some(Object::NotFound)) => {
            verdict.driver = Some(DriverNote::None);
            verdict.fail(
                format!("No {driver} CSI driver is registered, so PVCs on {class} stay Pending"),
                Some(fix::install_driver(driver, class)),
            );
            EvidenceSource::None
        }
        (Nodes::NotFound(_), unread) => {
            // The weaker list could not settle between "declared" and "absent".
            let why = match unread {
                Some(Object::Unknown(why)) => why,
                _ => Unread::Time,
            };
            unread_object(verdict, why);
            verdict.driver = Some(DriverNote::NotVerified);
            verdict.warn(
                format!(
                    "Not verified: no node has registered {driver}, and the CSIDriver list {}",
                    why.state()
                ),
                None,
            );
            EvidenceSource::Unread
        }
        (Nodes::Unknown(why), object) => {
            unread_nodes(verdict, why);
            match object {
                Some(Object::Found) => {
                    verdict.driver = Some(DriverNote::Declared);
                    verdict.partial_pass = true;
                    verdict.note(format!(
                        "The driver {driver} has a CSIDriver object. Whether a node has registered it was not read"
                    ));
                    EvidenceSource::Csidriver
                }
                Some(Object::Unknown(object_why)) => {
                    unread_object(verdict, object_why);
                    verdict.driver = Some(DriverNote::NotVerified);
                    verdict.warn(
                        format!(
                            "Not verified: the CSINode list {} and the CSIDriver list {}, so rdy cannot tell if {driver} is installed",
                            why.state(),
                            object_why.state()
                        ),
                        None,
                    );
                    EvidenceSource::Unread
                }
                Some(Object::NotFound) | None => {
                    verdict.driver = Some(DriverNote::NotVerified);
                    verdict.warn(
                        format!(
                            "Not verified: {driver} has no CSIDriver object, and the CSINode list {}, so rdy cannot tell if a node registered it",
                            why.state()
                        ),
                        None,
                    );
                    EvidenceSource::Unread
                }
            }
        }
    }
}

fn unread_nodes(verdict: &mut Verdict, why: Unread) {
    match why {
        Unread::Forbidden => verdict.unread(
            "the CSINode list",
            Some(Grant::cluster("list", "csinodes", "storage.k8s.io")),
        ),
        Unread::Capped => verdict.unread("the CSINode objects after the first page", None),
        Unread::Status(_) | Unread::Time => verdict.unread("the CSINode list", None),
    }
}

fn unread_object(verdict: &mut Verdict, why: Unread) {
    match why {
        Unread::Forbidden => verdict.unread(
            "the CSIDriver list",
            Some(Grant::cluster("list", "csidrivers", "storage.k8s.io")),
        ),
        Unread::Capped => verdict.unread("the CSIDriver objects after the first page", None),
        Unread::Status(_) | Unread::Time => verdict.unread("the CSIDriver list", None),
    }
}

// ---- stage 3: access modes and class settings -----------------------------------------------------------------

/// How an access mode stands against what the table says about the provisioner.
pub(super) fn mode_support(kind: &Kind<'_>, provisioner: &str, mode: AccessMode) -> Support {
    let name = token(provisioner);
    match kind {
        Kind::NoProvisioner => Support::Unverified(
            "the volumes of a class with no provisioner are made by hand, so rdy cannot tell their modes"
                .to_owned(),
        ),
        Kind::Unknown => Support::Unverified(format!("rdy has no access mode data for {name}")),
        Kind::MigratedCsi => Support::Unverified(format!(
            "rdy has no access mode data for the driver that serves {name}"
        )),
        Kind::Csi(driver) | Kind::NotCsi(driver) => {
            if driver.modes().contains(&mode) {
                return Support::Yes;
            }
            if driver.conditional_modes().contains(&mode) {
                let condition = driver.condition().unwrap_or("some volumes");
                return Support::Unverified(format!(
                    "{name} serves {} only for {condition}, and a class cannot say which it makes",
                    mode_name(mode)
                ));
            }
            let serves = |m: &AccessMode| driver.modes().contains(m);
            if driver.is_unverified_csi() {
                return Support::Unverified(format!(
                    "rdy cannot confirm {name} as a CSI driver, so it cannot tell whether it serves {}",
                    mode_name(mode)
                ));
            }
            match mode {
                AccessMode::ReadWriteOncePod if !driver.is_csi() => Support::No(format!(
                    "{name} is not a CSI driver, and Kubernetes serves ReadWriteOncePod for CSI volumes only"
                )),
                AccessMode::ReadWriteOncePod | AccessMode::ReadOnlyMany
                    if driver.is_csi() && serves(&AccessMode::ReadWriteOnce) =>
                {
                    Support::Unverified(format!(
                        "{name} serves ReadWriteOnce, and {} depends on the driver version",
                        mode_name(mode)
                    ))
                }
                _ => {
                    let list: Vec<&str> = driver.modes().iter().map(|m| mode_name(*m)).collect();
                    Support::No(format!("{name} serves {}", list.join(", ")))
                }
            }
        }
    }
}

/// Judges the access modes the spec needs.
pub(super) fn judge_modes(
    verdict: &mut Verdict,
    params: &K8sStorageClass,
    kind: &Kind<'_>,
    provisioner: &str,
) {
    let Some(wanted) = params.access_modes.as_ref() else {
        return;
    };
    let class = verdict
        .chosen
        .as_ref()
        .map(|chosen| token(&chosen.class.name))
        .unwrap_or_default();
    let mut observed = Map::new();
    for &mode in wanted {
        let support = mode_support(kind, provisioner, mode);
        let word = match &support {
            Support::Yes => "served",
            Support::No(_) => "not served",
            Support::Unverified(_) => "not verified",
        };
        observed.insert(mode_name(mode).to_owned(), json!(word));
        match support {
            Support::Yes => verdict.modes_ok.push(mode_name(mode)),
            Support::No(why) => verdict.fail(
                format!("Class {class} cannot serve {}: {why}", mode_name(mode)),
                Some(fix::other_driver(mode)),
            ),
            Support::Unverified(why) => verdict.warn(
                format!("Not verified: {} on class {class}: {why}", mode_name(mode)),
                None,
            ),
        }
    }
    verdict.observe("access_modes", Value::Object(observed));
}

/// Judges binding, expansion and reclaim policy against the spec, and the topology risk.
pub(super) fn judge_settings(
    verdict: &mut Verdict,
    params: &K8sStorageClass,
    class: &Class,
    kind: &Kind<'_>,
) {
    let name = token(&class.name);
    let raw = class.name.as_str();
    verdict.observe("binding_mode", json!(class.binding.word()));
    verdict.observe("allow_volume_expansion", json!(class.expansion));
    verdict.observe("reclaim_policy", json!(class.reclaim.word()));

    let want = match params.binding {
        VolumeBinding::WaitForFirstConsumer => Some(Binding::WaitForFirstConsumer),
        VolumeBinding::Immediate => Some(Binding::Immediate),
        _ => None,
    };
    match want {
        Some(want) if want != class.binding => verdict.fail(
            format!(
                "Class {name} binds with {}, and {} is needed",
                class.binding.word(),
                want.word()
            ),
            Some(fix::rebind(raw, want.word())),
        ),
        // The spec says nothing about binding: warn about the one pairing that goes wrong.
        None if class.binding == Binding::Immediate => {
            let place = match kind {
                Kind::Csi(driver) | Kind::NotCsi(driver) => match driver.topology() {
                    Topology::Zone => Some("one zone"),
                    Topology::Node => Some("one node"),
                    Topology::None => None,
                },
                _ => None,
            };
            if let Some(place) = place {
                verdict.warn(
                    format!(
                        "Class {name} binds with Immediate, and its volumes live in {place}. If the nodes span more than one zone, a pod can land where its volume cannot attach"
                    ),
                    Some(fix::rebind(raw, "WaitForFirstConsumer")),
                );
            }
        }
        _ => {}
    }

    if params.expansion == Some(true) && !class.expansion {
        verdict.warn(
            format!("Class {name} does not allow volume expansion"),
            Some(fix::allow_expansion(raw)),
        );
    }

    let want = params.reclaim_policy.map(|policy| match policy {
        ReclaimPolicy::Retain => Reclaim::Retain,
        _ => Reclaim::Delete,
    });
    if let Some(want) = want
        && want != class.reclaim
    {
        let extra = if class.reclaim == Reclaim::Delete {
            ". Deleting a claim deletes its data"
        } else {
            ""
        };
        verdict.warn(
            format!(
                "Class {name} reclaims with {}, and {} is wanted{extra}",
                class.reclaim.word(),
                want.word()
            ),
            Some(fix::reclaim(raw, want.word())),
        );
    }
}

// ---- stage 4: claims that wait ---------------------------------------------------------------------------------

/// Records the claims that wait on the class, and warns about the ones whose provisioning failed.
pub(super) fn judge_waiting(verdict: &mut Verdict, namespace: &str, waiting: &[Waiting]) {
    let shown: Vec<Value> = waiting
        .iter()
        .take(OBSERVED_LIST)
        .map(|claim| {
            json!({
                "claim": token(&claim.name),
                "minutes": claim.minutes,
                "provisioning_failed": claim.failed,
            })
        })
        .collect();
    verdict.observe("pending_claims", Value::Array(shown));
    let failed: Vec<&Waiting> = waiting.iter().filter(|claim| claim.failed).collect();
    let Some(first) = failed.first() else {
        return;
    };
    let names: Vec<String> = failed.iter().map(|claim| claim.name.clone()).collect();
    let class = verdict
        .chosen
        .as_ref()
        .map(|chosen| token(&chosen.class.name))
        .unwrap_or_default();
    verdict.warn(
        format!(
            "{} claim{} in {} on class {class} {} been Pending for 5 minutes or more with a ProvisioningFailed event: {}",
            failed.len(),
            if failed.len() == 1 { "" } else { "s" },
            token(namespace),
            if failed.len() == 1 { "has" } else { "have" },
            list_names(&names),
        ),
        Some(fix::failing_claims(namespace, &first.name)),
    );
}

// ---- the finding -------------------------------------------------------------------------------------------------

impl Verdict {
    /// Adds the spec's thresholds to the result.
    pub(super) fn expected(params: &K8sStorageClass) -> Value {
        let mut expected = Map::new();
        if let Some(class) = &params.class {
            expected.insert("class".to_owned(), json!(class.as_str()));
        }
        if let Some(modes) = &params.access_modes {
            let words: Vec<&str> = modes.iter().map(|m| mode_name(*m)).collect();
            expected.insert("access_modes".to_owned(), json!(words));
        }
        match params.binding {
            VolumeBinding::WaitForFirstConsumer => {
                expected.insert("binding".to_owned(), json!("WaitForFirstConsumer"));
            }
            VolumeBinding::Immediate => {
                expected.insert("binding".to_owned(), json!("Immediate"));
            }
            _ => {}
        }
        if let Some(expansion) = params.expansion {
            expected.insert("expansion".to_owned(), json!(expansion));
        }
        if let Some(policy) = params.reclaim_policy {
            let word = match policy {
                ReclaimPolicy::Retain => "Retain",
                _ => "Delete",
            };
            expected.insert("reclaim_policy".to_owned(), json!(word));
        }
        Value::Object(expected)
    }

    /// The finding: the worst problem first, the rest as notes, every fix in order.
    pub(super) fn finish(self, params: &K8sStorageClass) -> Finding {
        let level = if self.issues.iter().any(|i| i.level == Level::Fail) {
            Level::Fail
        } else if self.issues.is_empty() {
            Level::Pass
        } else {
            Level::Warn
        };
        let message = if self.issues.is_empty() {
            self.pass_message()
        } else {
            self.issues
                .iter()
                .find(|issue| issue.level == level)
                .map_or_else(String::new, |issue| issue.message.clone())
        };
        let mut finding = Finding::new(level, message.clone())
            .with_observed(Value::Object(self.observed.clone()))
            .with_expected(Self::expected(params));

        let mut fixes: Vec<&str> = Vec::new();
        for issue in self
            .issues
            .iter()
            .filter(|issue| issue.level == Level::Fail)
        {
            if let Some(text) = &issue.fix
                && !fixes.contains(&text.as_str())
            {
                fixes.push(text);
            }
        }
        for issue in self
            .issues
            .iter()
            .filter(|issue| issue.level == Level::Warn)
        {
            if let Some(text) = &issue.fix
                && !fixes.contains(&text.as_str())
            {
                fixes.push(text);
            }
        }
        let grant_fix = fix::grants(
            &self.grants.iter().map(Grant::can_i).collect::<Vec<_>>(),
            &self.grants.iter().map(Grant::text).collect::<Vec<_>>(),
        );
        if !self.grants.is_empty() {
            fixes.push(&grant_fix);
        } else if !self.unread.is_empty() && fixes.is_empty() {
            fixes.push(fix::by_hand());
        }
        if !fixes.is_empty() {
            finding = finding.with_fix(fixes.join(" "));
        }
        for issue in &self.issues {
            if issue.message != message {
                finding = finding.with_note(issue.message.clone());
            }
        }
        for note in &self.notes {
            finding = finding.with_note(note.clone());
        }
        if !self.unread.is_empty() || self.partial_pass {
            let what = if self.unread.is_empty() {
                "node registration of the driver was not read".to_owned()
            } else {
                format!("could not read {}", self.unread.join(", "))
            };
            let grants = self.grants.iter().map(Grant::text).collect();
            finding =
                finding.with_partial(Partial::new(Vec::new(), what).with_missing_grants(grants));
        }
        finding
    }

    /// `Default class gp3 (ebs.csi.aws.com) supports ReadWriteOnce, driver registered on 3 nodes`.
    fn pass_message(&self) -> String {
        let Some(chosen) = &self.chosen else {
            return "The storage class passes".to_owned();
        };
        let mut text = chosen.label();
        if let Some(provisioner) = &self.provisioner {
            text.push_str(&format!(" ({provisioner})"));
        }
        if !self.modes_ok.is_empty() {
            text.push_str(&format!(" supports {}", self.modes_ok.join(", ")));
        }
        let driver = match &self.driver {
            Some(DriverNote::Registered(registered)) => {
                let nodes = if registered.with_driver == 1 {
                    "1 node".to_owned()
                } else {
                    format!("{} nodes", registered.with_driver)
                };
                format!("driver registered on {nodes}")
            }
            Some(DriverNote::Declared) => {
                "driver declared, node registration not verified".to_owned()
            }
            Some(DriverNote::NotVerified) if self.modes_ok.is_empty() => {
                "not CSI or unknown, driver not verified".to_owned()
            }
            Some(DriverNote::NotVerified) => "driver not verified".to_owned(),
            Some(DriverNote::None) | None => String::new(),
        };
        if !driver.is_empty() {
            text.push_str(if self.modes_ok.is_empty() { ": " } else { ", " });
            text.push_str(&driver);
        }
        text
    }
}
