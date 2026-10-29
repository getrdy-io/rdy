//! The rules of the read-only guard: one pure function from a request to allow or refuse.
//!
//! Deny by default (02 Appendix B, ADR 0010 decision 2). A request is allowed only when it matches a
//! shape on this page: a discovery GET, a GET of one entry of [`ALLOWED`], or a POST to one of the three
//! self review resources. Everything else is refused with a fixed rule sentence, and the request never
//! leaves the process.
//!
//! What M1-103 builds here is the deny-by-default frame: the method rule, the POST rules (target, query
//! string, exact body), the secrets rule, the path pre-filter, the query keys, `Upgrade` and
//! `Impersonate-*`, and the resource table. M1-104 replaces the segment matching with the full
//! request-info parser (so `/api/v1/namespaces/secrets` becomes allowed again), adds the citation test
//! against the checks' `CheckInfo`, and relaxes `Impersonate-*` on the two access review POSTs.

use http::header::{CONNECTION, UPGRADE};
use http::{HeaderMap, Method, Uri};

/// The rule of a method other than GET and POST.
pub const RULE_METHOD: &str = "only GET and the three self review POSTs are allowed";
/// The rule of a POST to anything but a self review resource.
pub const RULE_POST_TARGET: &str = "POST is allowed only to the three self review resources";
/// The rule of a review POST that has a query string.
pub const RULE_POST_QUERY: &str = "a review POST takes no query string";
/// The rule of a `SelfSubjectReview` whose body is not the fixed body.
pub const RULE_REVIEW_BODY: &str = "SelfSubjectReview takes exactly the fixed body";
/// The rule of an access review POST whose body is missing, streamed or too big.
pub const RULE_BODY: &str = "a review POST takes one buffered JSON body under 64 KiB";
/// The rule of a GET that carries a body.
pub const RULE_GET_BODY: &str = "a GET carries no body";
/// The rule of any path that names `secrets`.
pub const RULE_SECRETS: &str = "Secrets are never read";
/// The rule of a path that is malformed or not in the plain form kube builds.
pub const RULE_PATH_SHAPE: &str = "the path is not in the plain form rdy builds";
/// The rule of a GET of anything not in [`ALLOWED`] or the discovery paths.
pub const RULE_NOT_ALLOWED: &str = "this resource is not on the list rdy reads";
/// The rule of a query key or value that is not allowed.
pub const RULE_QUERY: &str = "this query string is not allowed";
/// The rule of a connection upgrade.
pub const RULE_UPGRADE: &str = "connection upgrades are not allowed";
/// The rule of an `Impersonate-*` header.
pub const RULE_IMPERSONATE: &str = "Impersonate headers are not allowed";

/// The exact body of a `SelfSubjectReview` POST, compared byte for byte (ADR 0010 decision 2).
///
/// A typed `SelfSubjectReview` from `k8s-openapi` serializes with a `metadata` member, so it does not
/// match: send these bytes. The caller is M1-109.
pub const SELF_SUBJECT_REVIEW_BODY: &[u8] =
    br#"{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}"#;

/// The largest body of an access review POST. A real one is a few hundred bytes.
const MAX_REVIEW_BODY: usize = 64 * 1024;
/// The longest path rdy accepts.
const MAX_PATH: usize = 512;
/// The longest query string rdy accepts.
const MAX_QUERY: usize = 8 * 1024;
/// The longest name in a path.
const MAX_SEGMENT: usize = 253;

/// Which names or namespaces an entry of [`ALLOWED`] admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Only {
    /// Any valid name.
    Any,
    /// This one name.
    Name(&'static str),
}

impl Only {
    fn admits(self, name: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Name(only) => only == name,
        }
    }
}

/// One GET shape of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// A list of the resource in the whole cluster: `/<prefix>/<resource>`.
    List,
    /// A list in one namespace: `/<prefix>/namespaces/<ns>/<resource>`.
    ListInNamespace(Only),
    /// One object of a cluster-scoped resource by name, or a `Namespace` by name:
    /// `/<prefix>/<resource>/<name>`.
    Get(Only),
}

/// One resource the M1 checks read (02 Appendix B, section 4). There is no `secrets` entry, and a test
/// keeps it that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowed {
    /// The API group. Empty for the core group.
    pub group: &'static str,
    /// The API version.
    pub version: &'static str,
    /// The plural resource name.
    pub resource: &'static str,
    /// The GET shapes allowed for it.
    pub access: &'static [Access],
    /// The ids of the checks that read it. M1-104 asserts each is cited by a `CheckInfo`.
    pub checks: &'static [&'static str],
    /// What the checks read from it.
    pub reads: &'static str,
}

/// Every resource a GET may name, in the order of 02 Appendix B. Discovery paths are separate.
pub const ALLOWED: &[Allowed] = &[
    Allowed {
        group: "",
        version: "v1",
        resource: "namespaces",
        access: &[Access::Get(Only::Any)],
        checks: &["k8s.admission", "k8s.storageclass", "k8s.rbac"],
        reads: "Pod Security labels; whether the target namespace exists",
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "nodes",
        access: &[Access::List],
        checks: &["k8s.nodes", "k8s.version"],
        reads: "allocatable, conditions, taints, labels; providerID and kubeletVersion",
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "pods",
        access: &[Access::List],
        checks: &["k8s.nodes"],
        reads: "requests, nodeName and phase only, with a status.phase field selector",
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "persistentvolumeclaims",
        access: &[Access::ListInNamespace(Only::Any)],
        checks: &["k8s.storageclass"],
        reads: "Pending claims older than 5 minutes in the target namespace",
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "events",
        access: &[Access::ListInNamespace(Only::Any)],
        checks: &["k8s.storageclass"],
        reads: "ProvisioningFailed and WaitForFirstConsumer reasons for claims",
    },
    Allowed {
        group: "storage.k8s.io",
        version: "v1",
        resource: "storageclasses",
        access: &[Access::List, Access::Get(Only::Any)],
        checks: &["k8s.storageclass"],
        reads: "classes, the default marker, the provisioner",
    },
    Allowed {
        group: "storage.k8s.io",
        version: "v1",
        resource: "csinodes",
        access: &[Access::List],
        checks: &["k8s.storageclass"],
        reads: "spec.drivers[].name",
    },
    Allowed {
        group: "storage.k8s.io",
        version: "v1",
        resource: "csidrivers",
        access: &[Access::List],
        checks: &["k8s.storageclass"],
        reads: "driver objects",
    },
    Allowed {
        group: "apps",
        version: "v1",
        resource: "deployments",
        access: &[Access::ListInNamespace(Only::Name("kube-system"))],
        checks: &["k8s.nodes"],
        reads: "the cluster-autoscaler deployment by name",
    },
    Allowed {
        group: "security.openshift.io",
        version: "v1",
        resource: "securitycontextconstraints",
        access: &[Access::List],
        checks: &["k8s.admission"],
        reads: "the OpenShift SCCs",
    },
    Allowed {
        group: "config.openshift.io",
        version: "v1",
        resource: "clusterversions",
        access: &[Access::Get(Only::Name("version"))],
        checks: &["k8s.version"],
        reads: "the OpenShift version",
    },
];

/// What the guard can see of a request body.
#[derive(Debug, Clone, Copy)]
pub(crate) enum BodyView<'a> {
    /// No bytes.
    Empty,
    /// All the bytes, read from a body that can be replayed.
    Bytes(&'a [u8]),
    /// A body that is streamed or cannot be read without consuming it.
    Opaque,
}

/// Decides one request. `Ok` means the request may go on; `Err` is the rule that refuses it.
///
/// The order is fixed so the rule in the log is the first one broken: method, headers, path shape,
/// secrets, then the rules of the method.
pub(crate) fn judge(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: BodyView<'_>,
) -> Result<(), &'static str> {
    let is_get = method == Method::GET;
    if !is_get && method != Method::POST {
        return Err(RULE_METHOD);
    }
    check_headers(headers)?;
    let segments = path_segments(uri)?;
    if segments.contains(&"secrets") {
        return Err(RULE_SECRETS);
    }
    if is_get {
        if !matches!(body, BodyView::Empty) {
            return Err(RULE_GET_BODY);
        }
        check_query(uri.query())?;
        check_get(&segments)
    } else {
        check_post(&segments, uri.query(), body)
    }
}

/// The path of `uri` for the action log: no query string, escaped, cut to 200 characters.
pub(crate) fn log_path(uri: &Uri) -> String {
    super::super::text::escape_capped(uri.path(), 200)
}

fn check_headers(headers: &HeaderMap) -> Result<(), &'static str> {
    if headers.contains_key(UPGRADE) {
        return Err(RULE_UPGRADE);
    }
    for value in headers.get_all(CONNECTION) {
        let Ok(text) = value.to_str() else {
            return Err(RULE_UPGRADE);
        };
        if text
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        {
            return Err(RULE_UPGRADE);
        }
    }
    // Header names are lower case in `http`. This covers `Impersonate-User`, `-Group`, `-Uid` and
    // `-Extra-*`. Headers that the kubeconfig sets are added below the guard and are not seen here.
    if headers
        .keys()
        .any(|name| name.as_str().starts_with("impersonate-"))
    {
        return Err(RULE_IMPERSONATE);
    }
    Ok(())
}

/// Splits the path of a request kube built. kube sends a path with no scheme or host at this layer.
/// Anything that is not plain ASCII path text is refused, which covers `%`, `..`, `//`, `;`, a trailing
/// `/` and an empty segment.
fn path_segments(uri: &Uri) -> Result<Vec<&str>, &'static str> {
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(RULE_PATH_SHAPE);
    }
    let path = uri.path();
    let Some(inner) = path.strip_prefix('/') else {
        return Err(RULE_PATH_SHAPE);
    };
    if path.len() > MAX_PATH || path.ends_with('/') || path.contains("//") || path.contains("..") {
        return Err(RULE_PATH_SHAPE);
    }
    let segments: Vec<&str> = inner.split('/').collect();
    for segment in &segments {
        let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_');
        if segment.is_empty()
            || *segment == "."
            || segment.len() > MAX_SEGMENT
            || !segment.bytes().all(plain)
        {
            return Err(RULE_PATH_SHAPE);
        }
    }
    Ok(segments)
}

/// Allows the keys `limit`, `continue`, `labelSelector` and `fieldSelector`, with plain values. M1-104
/// decodes the selector values once and validates them.
fn check_query(query: Option<&str>) -> Result<(), &'static str> {
    // kube writes a bare `?` when there are no parameters, and a `&` before the first one (`?&limit=5`).
    let Some(query) = query
        .map(|query| query.strip_prefix('&').unwrap_or(query))
        .filter(|query| !query.is_empty())
    else {
        return Ok(());
    };
    if query.len() > MAX_QUERY {
        return Err(RULE_QUERY);
    }
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "limit" => {
                if value.is_empty() || value.len() > 6 || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(RULE_QUERY);
                }
            }
            "continue" | "labelSelector" | "fieldSelector" => check_query_value(value)?,
            _ => return Err(RULE_QUERY),
        }
    }
    Ok(())
}

/// A query value is printable ASCII, and a `%` starts two hex digits.
fn check_query_value(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if !byte.is_ascii_graphic() || byte == b'#' {
            return Err(RULE_QUERY);
        }
        if byte == b'%' {
            let escape = bytes.get(index + 1..index + 3);
            if !escape.is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
                return Err(RULE_QUERY);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn check_get(segments: &[&str]) -> Result<(), &'static str> {
    if is_discovery(segments) {
        return Ok(());
    }
    let (group, version, rest) = match segments {
        ["api", "v1", rest @ ..] => ("", "v1", rest),
        ["apis", group, version, rest @ ..] if is_group(group) && is_version(version) => {
            (*group, *version, rest)
        }
        _ => return Err(RULE_NOT_ALLOWED),
    };
    let (namespace, resource, name) = match rest {
        [resource] => (None, *resource, None),
        ["namespaces", name] => (None, "namespaces", Some(*name)),
        [resource, name] => (None, *resource, Some(*name)),
        ["namespaces", namespace, resource] => (Some(*namespace), *resource, None),
        _ => return Err(RULE_NOT_ALLOWED),
    };
    let Some(entry) = ALLOWED
        .iter()
        .find(|e| e.group == group && e.version == version && e.resource == resource)
    else {
        return Err(RULE_NOT_ALLOWED);
    };
    let allowed = entry
        .access
        .iter()
        .any(|access| match (access, namespace, name) {
            (Access::List, None, None) => true,
            (Access::ListInNamespace(only), Some(namespace), None) => only.admits(namespace),
            (Access::Get(only), None, Some(name)) => only.admits(name),
            _ => false,
        });
    if allowed {
        Ok(())
    } else {
        Err(RULE_NOT_ALLOWED)
    }
}

/// `/version`, `/api`, `/apis`, `/api/v1`, `/apis/<group>` and `/apis/<group>/<version>`.
fn is_discovery(segments: &[&str]) -> bool {
    match segments {
        ["version"] | ["api"] | ["apis"] | ["api", "v1"] => true,
        ["apis", group] => is_group(group),
        ["apis", group, version] => is_group(group) && is_version(version),
        _ => false,
    }
}

/// A DNS-1123 subdomain: labels of lower case letters, digits and `-`, each starting and ending with a
/// letter or digit, at most 63 characters, at most 253 in all.
fn is_group(group: &str) -> bool {
    group.len() <= 253
        && group.split('.').all(|label| {
            let bytes = label.as_bytes();
            let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first().is_some_and(edge)
                && bytes.last().is_some_and(edge)
                && bytes.iter().all(|b| edge(b) || *b == b'-')
        })
}

/// `^v[0-9]+((alpha|beta)[0-9]+)?$`.
fn is_version(version: &str) -> bool {
    let Some(rest) = version.strip_prefix('v') else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    let tail = rest.get(digits..).unwrap_or("x");
    if tail.is_empty() {
        return true;
    }
    let Some(number) = tail
        .strip_prefix("alpha")
        .or_else(|| tail.strip_prefix("beta"))
    else {
        return false;
    };
    !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
}

fn check_post(
    segments: &[&str],
    query: Option<&str>,
    body: BodyView<'_>,
) -> Result<(), &'static str> {
    let identity = match segments {
        [
            "apis",
            "authorization.k8s.io",
            "v1",
            "selfsubjectaccessreviews" | "selfsubjectrulesreviews",
        ] => false,
        ["apis", "authentication.k8s.io", "v1", "selfsubjectreviews"] => true,
        _ => return Err(RULE_POST_TARGET),
    };
    // kube writes a bare `?` for no parameters. A real query string, `dryRun` included, is refused.
    if query.is_some_and(|query| !query.is_empty()) {
        return Err(RULE_POST_QUERY);
    }
    match (identity, body) {
        (true, BodyView::Bytes(bytes)) if bytes == SELF_SUBJECT_REVIEW_BODY => Ok(()),
        (true, _) => Err(RULE_REVIEW_BODY),
        (false, BodyView::Bytes(bytes)) if bytes.len() <= MAX_REVIEW_BODY => Ok(()),
        (false, _) => Err(RULE_BODY),
    }
}
