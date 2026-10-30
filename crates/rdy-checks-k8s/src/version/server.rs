//! Reading what a server says about itself: the `gitVersion`, the distribution and the node facts.
//!
//! Pure functions of text, so every distribution is a table row in a unit test. Nothing here sends a
//! request.

use std::cmp::Ordering;

use k8s_openapi::api::core::v1::Node;

/// The longest version text rdy reads. A real `gitVersion` is under 40 characters.
const MAX_VERSION_TEXT: usize = 128;

/// The longest part of a version, in digits. Keeps a hostile server from sending a huge number.
const MAX_DIGITS: usize = 6;

/// A version as a server reports it: two or three numbers, then the vendor suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reported {
    parts: Vec<u32>,
    suffix: String,
}

impl Reported {
    /// Reads `v1.29.4-eks-abc123`, `v1.29.4+k3s1` or `v1.29.4`. `None` when the text is not that shape.
    ///
    /// The `major` and `minor` fields of `/version` are not used first: some distributions put a `+` in
    /// the minor (`29+`). [`Reported::from_major_minor`] is the fallback.
    pub(super) fn parse(git_version: &str) -> Option<Self> {
        if git_version.len() > MAX_VERSION_TEXT {
            return None;
        }
        let body = git_version.strip_prefix('v').unwrap_or(git_version);
        let end = body
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(body.len());
        let (numbers, suffix) = body.split_at(end);
        if !(suffix.is_empty() || suffix.starts_with(['-', '+'])) {
            return None;
        }
        let parts = numbers
            .split('.')
            .map(number)
            .collect::<Option<Vec<u32>>>()?;
        (2..=3).contains(&parts.len()).then(|| Self {
            parts,
            suffix: suffix.to_owned(),
        })
    }

    /// Reads the `major` and `minor` fields (`1` and `29+`). The patch is unknown.
    pub(super) fn from_major_minor(major: &str, minor: &str) -> Option<Self> {
        let minor = minor.trim_end_matches('+');
        Some(Self {
            parts: vec![number(major)?, number(minor)?],
            suffix: String::new(),
        })
    }

    pub(super) fn parts(&self) -> &[u32] {
        &self.parts
    }

    pub(super) fn major(&self) -> u32 {
        self.parts.first().copied().unwrap_or(0)
    }

    pub(super) fn minor(&self) -> u32 {
        self.parts.get(1).copied().unwrap_or(0)
    }

    /// The vendor suffix, for example `-eks-abc123` or `+k3s1`. Empty for a plain version.
    pub(super) fn suffix(&self) -> &str {
        &self.suffix
    }

    /// `1.29.4`, or `1.29` when the patch is unknown.
    pub(super) fn dotted(&self) -> String {
        dotted(&self.parts)
    }
}

fn number(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > MAX_DIGITS || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `[1, 29, 4]` as `1.29.4`.
pub(super) fn dotted(parts: &[u32]) -> String {
    parts
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// Compares two versions over the parts both have, so `1.28` equals `1.28.7` and a bound written as
/// `1.31` accepts every 1.31 patch. A bound with a patch (`1.28.3`) is compared on the patch when the
/// server reported one.
pub(super) fn compare(have: &[u32], bound: &[u32]) -> Ordering {
    have.iter()
        .zip(bound)
        .map(|(h, b)| h.cmp(b))
        .find(|order| order.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// The distributions rdy names. Anything else is `Vanilla`, the upstream shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Distro {
    Eks,
    Gke,
    Aks,
    OpenShift,
    K3s,
    Rke2,
    Kind,
    Vanilla,
}

impl Distro {
    /// The value in the result's `observed.distribution`.
    pub(super) fn wire(self) -> &'static str {
        match self {
            Self::Eks => "eks",
            Self::Gke => "gke",
            Self::Aks => "aks",
            Self::OpenShift => "openshift",
            Self::K3s => "k3s",
            Self::Rke2 => "rke2",
            Self::Kind => "kind",
            Self::Vanilla => "vanilla",
        }
    }
}

/// What rdy keeps of one node. Nothing else of the node is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NodeFacts {
    pub(super) name: String,
    /// The scheme of `spec.providerID` (`aws`, `gce`, `azure`, `kind`), when it is one rdy knows.
    pub(super) cloud: Option<&'static str>,
    pub(super) kubelet: Option<Reported>,
    pub(super) aks_label: bool,
    pub(super) eks_label: bool,
    pub(super) gke_label: bool,
    /// A virtual kubelet (Azure container instances, Fargate-style nodes of other projects). Its
    /// version is the connector's, not a kubelet's, so it is left out of the skew.
    pub(super) virtual_kubelet: bool,
}

/// The `spec.providerID` schemes rdy knows. The text of an unknown scheme is never kept.
const CLOUDS: &[(&str, &str)] = &[
    ("aws://", "aws"),
    ("gce://", "gcp"),
    ("azure://", "azure"),
    ("kind://", "kind"),
];

impl NodeFacts {
    pub(super) fn from_node(node: &Node) -> Self {
        let labels = node.metadata.labels.as_ref();
        let has = |key: &str| labels.is_some_and(|labels| labels.contains_key(key));
        let label = |key: &str| {
            labels
                .and_then(|labels| labels.get(key))
                .map(String::as_str)
        };
        let provider = node
            .spec
            .as_ref()
            .and_then(|spec| spec.provider_id.as_deref())
            .unwrap_or_default();
        let kubelet = node
            .status
            .as_ref()
            .and_then(|status| status.node_info.as_ref())
            .map(|info| info.kubelet_version.as_str());
        Self {
            name: node.metadata.name.clone().unwrap_or_default(),
            cloud: CLOUDS
                .iter()
                .find(|(prefix, _)| provider.starts_with(prefix))
                .map(|(_, cloud)| *cloud),
            virtual_kubelet: label("type") == Some("virtual-kubelet")
                || kubelet.is_some_and(|text| text.contains("-vk-")),
            kubelet: kubelet.and_then(Reported::parse),
            aks_label: has("kubernetes.azure.com/cluster"),
            eks_label: has("eks.amazonaws.com/nodegroup"),
            gke_label: has("cloud.google.com/gke-nodepool"),
        }
    }
}

/// Which distribution this is.
///
/// Strongest evidence first: the OpenShift API group, then the suffix of `gitVersion` (`-eks-` needs a hex
/// hash after it, `-gke.` needs a Google Cloud node), then the labels that only one managed service sets,
/// then the `kind` provider scheme. AKS has no suffix, so its label is
/// the only evidence. A plain version with an `aws://` provider is a self-managed cluster on AWS, not EKS.
pub(super) fn detect(server: &Reported, openshift_group: bool, nodes: &[NodeFacts]) -> Distro {
    let suffix = server.suffix();
    let any = |test: fn(&NodeFacts) -> bool| nodes.iter().any(test);
    // `-gke.` is also the suffix of other Google distributions (GKE on bare metal or VMware). With a node
    // list, it counts only when a node says Google Cloud. With none (the list was not readable), the suffix
    // is all there is.
    let gke_suffix = suffix.starts_with("-gke.")
        && (nodes.is_empty() || any(|node| node.cloud == Some("gcp") || node.gke_label));
    if openshift_group {
        Distro::OpenShift
    } else if is_eks_suffix(suffix) {
        Distro::Eks
    } else if gke_suffix {
        Distro::Gke
    } else if suffix.starts_with("+k3s") {
        Distro::K3s
    } else if suffix.starts_with("+rke2") {
        Distro::Rke2
    } else if any(|node| node.aks_label) {
        Distro::Aks
    } else if any(|node| node.eks_label) {
        Distro::Eks
    } else if any(|node| node.gke_label) {
        Distro::Gke
    } else if any(|node| node.cloud == Some("kind")) {
        Distro::Kind
    } else {
        Distro::Vanilla
    }
}

/// True for `-eks-` and a build hash (`-eks-c417bb3`). The distribution for machines you run yourself
/// writes `-eks-1-29-5`, which is not Amazon EKS and gets no `aws eks` command.
fn is_eks_suffix(suffix: &str) -> bool {
    suffix.strip_prefix("-eks-").is_some_and(|hash| {
        (6..=40).contains(&hash.len()) && hash.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// The cloud the nodes say they run on, if they agree on one rdy knows.
pub(super) fn cloud(nodes: &[NodeFacts]) -> Option<&'static str> {
    let first = nodes.iter().find_map(|node| node.cloud)?;
    nodes
        .iter()
        .all(|node| node.cloud.is_none_or(|cloud| cloud == first))
        .then_some(first)
}

/// An OpenShift version such as `4.14.9` or `4.15.0-rc.1`: two to four numbers, then anything.
pub(super) fn parse_openshift(text: &str) -> Option<Vec<u32>> {
    if text.len() > MAX_VERSION_TEXT {
        return None;
    }
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (numbers, rest) = text.split_at(end);
    if !(rest.is_empty() || rest.starts_with(['-', '+'])) {
        return None;
    }
    let parts = numbers
        .split('.')
        .map(number)
        .collect::<Option<Vec<u32>>>()?;
    (2..=4).contains(&parts.len()).then_some(parts)
}
