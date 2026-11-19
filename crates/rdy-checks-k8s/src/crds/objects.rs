//! What the check keeps of an operator `Deployment`, and how it reads a version.
//!
//! A Deployment holds the environment, the arguments and the annotations of its containers, and those
//! carry credentials and `last-applied-configuration` copies of the whole object. The type here is read
//! through private wire structs that name only the fields the check uses, so serde skips the rest while it
//! parses and no other byte is ever held. The metadata is a private `{name, namespace, labels}` struct,
//! and the `ObjectMeta` that `kube::Resource` needs is built from it with the version label only.

use std::borrow::Cow;
use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::core::NamespaceResourceScope;
use rdy_spec::Version;
use serde::{Deserialize, Deserializer};

/// The label that most charts set to the version of the application.
pub(super) const VERSION_LABEL: &str = "app.kubernetes.io/version";

/// The most containers kept from one Deployment.
const MAX_CONTAINERS: usize = 16;

/// The longest image reference or label value looked at, in bytes. A longer one is not read as a version.
const MAX_TEXT: usize = 256;

/// Why something could not be read, as the check reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unread {
    /// 403: the identity may not read it.
    Forbidden,
    /// Another status of the server.
    Status(u16),
    /// The guard refuses a path through a name that is `secrets`.
    Refused,
    /// The check ran out of time before it asked.
    Time,
    /// The check read as many discovery documents as it reads in one run.
    Budget,
}

impl Unread {
    /// Why the read gave nothing, as a phrase.
    pub(super) fn why(self) -> String {
        match self {
            Self::Forbidden => "the identity may not read it".to_owned(),
            Self::Status(code) => format!("the server answered {code}"),
            Self::Refused => "rdy never reads a path through a name that is secrets".to_owned(),
            Self::Time => "rdy ran out of time".to_owned(),
            Self::Budget => "rdy reads a bounded number of discovery documents".to_owned(),
        }
    }
}

/// The answer to one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Fetched<T> {
    Got(T),
    /// 404: the server does not have it.
    Missing,
    Unread(Unread),
}

/// One container of the Deployment: its name and image, nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Container {
    pub(super) name: String,
    pub(super) image: String,
}

/// An operator `Deployment`, as far as the check reads it.
#[derive(Debug, Clone)]
pub(super) struct OperatorDeployment {
    /// The name, the namespace and the version label. Nothing else of the metadata.
    metadata: ObjectMeta,
    /// `spec.replicas`, which the API server defaults to 1.
    pub(super) desired: i64,
    /// `status.readyReplicas`.
    pub(super) ready: i64,
    pub(super) containers: Vec<Container>,
}

#[derive(Deserialize)]
struct Wire {
    metadata: Option<WireMeta>,
    spec: Option<WireSpec>,
    status: Option<WireStatus>,
}

/// The three metadata fields the check reads. `annotations` is not among them.
#[derive(Deserialize)]
struct WireMeta {
    name: Option<String>,
    namespace: Option<String>,
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct WireSpec {
    replicas: Option<i64>,
    template: Option<WireTemplate>,
}

#[derive(Deserialize)]
struct WireTemplate {
    spec: Option<WirePod>,
}

#[derive(Deserialize)]
struct WirePod {
    containers: Option<Vec<WireContainer>>,
}

#[derive(Deserialize)]
struct WireContainer {
    name: Option<String>,
    image: Option<String>,
}

#[derive(Deserialize)]
struct WireStatus {
    #[serde(rename = "readyReplicas")]
    ready_replicas: Option<i64>,
}

impl<'de> Deserialize<'de> for OperatorDeployment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let meta = wire.metadata;
        let labels = meta
            .as_ref()
            .and_then(|meta| meta.labels.as_ref())
            .and_then(|labels| labels.get(VERSION_LABEL))
            .map(|value| BTreeMap::from([(VERSION_LABEL.to_owned(), value.clone())]));
        let metadata = ObjectMeta {
            name: meta.as_ref().and_then(|meta| meta.name.clone()),
            namespace: meta.as_ref().and_then(|meta| meta.namespace.clone()),
            labels,
            ..ObjectMeta::default()
        };
        let (desired, containers) = match wire.spec {
            Some(spec) => (
                spec.replicas.unwrap_or(1),
                spec.template
                    .and_then(|template| template.spec)
                    .and_then(|pod| pod.containers)
                    .unwrap_or_default()
                    .into_iter()
                    .take(MAX_CONTAINERS)
                    .map(|container| Container {
                        name: container.name.unwrap_or_default(),
                        image: container.image.unwrap_or_default(),
                    })
                    .collect(),
            ),
            None => (1, Vec::new()),
        };
        Ok(Self {
            metadata,
            desired,
            ready: wire
                .status
                .and_then(|status| status.ready_replicas)
                .unwrap_or(0),
            containers,
        })
    }
}

impl OperatorDeployment {
    /// The value of the `app.kubernetes.io/version` label.
    pub(super) fn label(&self) -> Option<&str> {
        self.metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(VERSION_LABEL))
            .map(String::as_str)
    }
}

impl kube::Resource for OperatorDeployment {
    type DynamicType = ();
    type Scope = NamespaceResourceScope;

    fn kind(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("Deployment")
    }

    fn group(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("apps")
    }

    fn version(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("v1")
    }

    fn plural(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("deployments")
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

// ---- versions -------------------------------------------------------------------------------------------------

/// A version read from an image tag or a label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Tag {
    pub(super) version: Version,
    /// True for a pre-release (`1.15.0-rc1`), which sorts below the release of the same number.
    pub(super) pre: bool,
}

impl Tag {
    /// The version as numbers, built from the parsed parts and never from the server's text.
    pub(super) fn text(&self) -> String {
        let parts: Vec<String> = self
            .version
            .components()
            .iter()
            .map(u32::to_string)
            .collect();
        let numbers = parts.join(".");
        if self.pre {
            format!("{numbers} (a pre-release)")
        } else {
            numbers
        }
    }
}

/// Reads `1.14.5`, `v1.14.5`, `1.14.5-ubi8` or `v1.15.0-rc.1`: two to four numbers, then nothing, or a
/// suffix that starts with `-`, `+` or `_`. A bare number (`3`, `20240101`) is not read as a version, since
/// a date or a build number would pass any minimum.
pub(super) fn parse_tag(text: &str) -> Option<Tag> {
    if text.len() > MAX_TEXT {
        return None;
    }
    let body = text.strip_prefix('v').unwrap_or(text);
    let end = body
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(body.len());
    let (numbers, rest) = body.split_at(end);
    if !(rest.is_empty() || rest.starts_with(['-', '+', '_'])) {
        return None;
    }
    if numbers.split('.').count() < 2 {
        return None;
    }
    let version = Version::parse(numbers).ok()?;
    Some(Tag {
        version,
        pre: is_pre_release(rest),
    })
}

/// True when the suffix of a tag marks a pre-release. Build metadata after a `+` is ignored, the rest is cut
/// at `-`, `.`, `_` and `+` into tokens, and a token counts only when it is a whole word (`rc`, `alpha`,
/// `beta`, `pre`, `dev`, `snapshot`, `nightly`) with an optional number after it. So `-rc.1` and `-beta2` are
/// pre-releases, and `-source`, `-express`, `-devicemapper`, `-arch64` and `-prebuilt` are not.
fn is_pre_release(suffix: &str) -> bool {
    let before_build = suffix.split('+').next().unwrap_or(suffix);
    before_build.split(['-', '.', '_']).any(|token| {
        let word = token.to_ascii_lowercase();
        let word = word.trim_end_matches(|c: char| c.is_ascii_digit());
        matches!(
            word,
            "alpha" | "beta" | "rc" | "pre" | "dev" | "snapshot" | "nightly"
        )
    })
}

/// The tag of an image reference: the part after the last `:` of the last path part. A digest is not a tag.
pub(super) fn image_tag(image: &str) -> Option<&str> {
    let reference = image.split('@').next().unwrap_or(image);
    let last = reference.rsplit('/').next().unwrap_or(reference);
    last.rsplit_once(':').map(|(_, tag)| tag)
}

/// What the Deployment says its version is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Versions {
    /// From the image tag of the operator container: what runs.
    pub(super) image: Option<Tag>,
    /// From the `app.kubernetes.io/version` label.
    pub(super) label: Option<Tag>,
    /// The Deployment has several containers, none is named like it, and their tags differ.
    pub(super) ambiguous: bool,
}

impl Versions {
    /// The version to judge: the image tag, else the label.
    pub(super) fn best(&self) -> Option<&Tag> {
        self.image.as_ref().or(self.label.as_ref())
    }
}

/// Reads the versions of `deployment`, called `name`.
///
/// The operator container is the one named `name`, else the only one whose name starts with `name`
/// (cert-manager's container is `cert-manager-controller`), else the only container. With several and none
/// of those, the tags of all of them are read, and they count only when they all agree: a sidecar such as
/// a proxy has a version of its own.
pub(super) fn versions_of(deployment: &OperatorDeployment, name: &str) -> Versions {
    let containers = &deployment.containers;
    let tag_of = |container: &Container| image_tag(&container.image).and_then(parse_tag);
    let named: Vec<&Container> = containers.iter().filter(|c| c.name == name).collect();
    let prefixed: Vec<&Container> = containers
        .iter()
        .filter(|c| !c.name.is_empty() && c.name.starts_with(name))
        .collect();
    let (image, ambiguous) = if let [one] = named.as_slice() {
        (tag_of(one), false)
    } else if let [one] = prefixed.as_slice() {
        (tag_of(one), false)
    } else if let [one] = containers.as_slice() {
        (tag_of(one), false)
    } else {
        let mut tags: Vec<Tag> = containers.iter().filter_map(tag_of).collect();
        tags.dedup();
        match tags.as_slice() {
            [] => (None, false),
            [one] => (Some(one.clone()), false),
            _ => (None, true),
        }
    };
    Versions {
        image,
        label: deployment.label().and_then(parse_tag),
        ambiguous,
    }
}
