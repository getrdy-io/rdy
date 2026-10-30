//! The rules of the read-only guard: one pure function from a request to allow or refuse.
//!
//! Deny by default (02 Appendix B, ADR 0010 decision 2). A request is allowed only when it matches a
//! shape on this page: a discovery GET, a GET of one entry of [`ALLOWED`], or a POST to one of the three
//! self review resources. Everything else is refused with a fixed rule sentence, and the request never
//! leaves the process.
//!
//! The frame is deny by default: the method rule, the POST rules (target, query string, exact body), the
//! secrets rule, the path pre-filter, the query keys, `Upgrade`, `Impersonate-*` and the resource table.
//! A GET path that passes the pre-filter is parsed the way the API server's request-info parser reads it
//! ([`request_info`]): group, version, namespace, resource, name and subresource. The table then judges
//! those parts, so a path the server reads one way is never judged another way. A subresource
//! (`finalize`, `status`, `exec`, `log`, `proxy`, `scale`) is refused as [`RULE_SUBRESOURCE`], and the
//! legacy `watch` and `proxy` path verbs are refused as [`RULE_NOT_ALLOWED`].
//!
//! `secrets` is refused in any path segment. The one exception is `GET /api/v1/namespaces/secrets`, a
//! namespace that is called `secrets`. A namespace with that name cannot have its claims or events
//! listed, because `/api/v1/namespaces/secrets/persistentvolumeclaims` is refused: rdy keeps the rule one
//! sentence long rather than teach it which segment is a name.
//!
//! `Impersonate-User` is allowed only on the two access review POSTs, only when the guard was built with
//! the spec's `as:` value ([`ImpersonateAs`]), and only with that exact value. Every other `Impersonate-*`
//! header, and the header on any other request, is refused as [`RULE_IMPERSONATE`].
//!
//! For check authors: a list takes `limit`, `continue`, `labelSelector` and `fieldSelector` and nothing
//! else. `resourceVersion` (so `ListParams::match_any()` too), `timeoutSeconds`, `watch` and the rest are
//! refused as [`RULE_QUERY`]. A list of `pods` or `events` must also carry the field selector its
//! [`ALLOWED`] entry names, or it is refused as [`RULE_SELECTOR`]. A request carries only the headers
//! `accept`, `content-type` and `content-length`; any other is refused as [`RULE_HEADER`].

use std::fmt;

use http::header::{ACCEPT, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, UPGRADE};
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
/// The rule of a GET of a subresource: `finalize`, `status`, `exec`, `log`, `proxy`, `scale` and the rest.
pub const RULE_SUBRESOURCE: &str = "subresources are not allowed";
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
/// The rule of a request header that is not on the short list (`accept`, `content-type`,
/// `content-length`). It covers a check-set `Authorization`, `X-Remote-User`, `X-HTTP-Method-Override`
/// and `Host`.
pub const RULE_HEADER: &str = "this request header is not allowed";
/// The rule of a list that lacks the field selector its [`ALLOWED`] entry requires.
pub const RULE_SELECTOR: &str = "this list needs the field selector rdy uses for it";

/// The exact body of a `SelfSubjectReview` POST, compared byte for byte (ADR 0010 decision 2).
///
/// A typed `SelfSubjectReview` from `k8s-openapi` serializes with a `metadata` member, so it does not
/// match: send these bytes. `ReadOnlyClient::self_subject_review` is the raw send route (M1-105).
pub const SELF_SUBJECT_REVIEW_BODY: &[u8] =
    br#"{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}"#;

/// The path of the `SelfSubjectReview` POST.
pub(crate) const SELF_SUBJECT_REVIEW_PATH: &str =
    "/apis/authentication.k8s.io/v1/selfsubjectreviews";

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

/// The field selector a list of a resource must carry. The value is decoded once and split on `,`. A
/// selector with a backslash is refused, so a term cannot hide an escaped comma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSelector {
    /// No requirement.
    NotRequired,
    /// Some term on this key, with `=`, `==` or `!=` (`status.phase!=Succeeded`).
    Key(&'static str),
    /// This exact term, with `=` or `==` (`involvedObject.kind=PersistentVolumeClaim`).
    Equals(&'static str, &'static str),
}

impl FieldSelector {
    /// True when `decoded` (the value of the `fieldSelector` key) meets the requirement.
    fn met_by(self, decoded: Option<&str>) -> bool {
        let mut terms = decoded
            .into_iter()
            .flat_map(|text| text.split(','))
            .filter_map(split_term);
        match self {
            Self::NotRequired => true,
            Self::Key(key) => terms.any(|(k, _, _)| k == key),
            Self::Equals(key, value) => {
                terms.any(|(k, op, v)| k == key && matches!(op, "=" | "==") && v == value)
            }
        }
    }
}

/// Splits `key op value` at the first operator: `!=`, `==` or `=`.
fn split_term(term: &str) -> Option<(&str, &str, &str)> {
    let at = term.find(['=', '!'])?;
    let (key, rest) = term.split_at(at);
    let op_len = if rest.starts_with("!=") || rest.starts_with("==") {
        2
    } else if rest.starts_with('=') {
        1
    } else {
        return None;
    };
    let (op, value) = rest.split_at(op_len);
    Some((key, op, value))
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
    /// The ids of the checks that read it. A test asserts each is cited by a `CheckInfo`.
    pub checks: &'static [&'static str],
    /// What the checks read from it.
    pub reads: &'static str,
    /// The field selector a list must carry. A get by name needs none.
    pub field_selector: FieldSelector,
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
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "nodes",
        access: &[Access::List],
        checks: &["k8s.nodes", "k8s.version"],
        reads: "allocatable, conditions, taints, labels; providerID and kubeletVersion",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "pods",
        access: &[Access::List],
        checks: &["k8s.nodes"],
        reads: "requests, nodeName and phase only, with a status.phase field selector",
        field_selector: FieldSelector::Key("status.phase"),
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "persistentvolumeclaims",
        access: &[Access::ListInNamespace(Only::Any)],
        checks: &["k8s.storageclass"],
        reads: "Pending claims older than 5 minutes in the target namespace",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "",
        version: "v1",
        resource: "events",
        access: &[Access::ListInNamespace(Only::Any)],
        checks: &["k8s.storageclass"],
        reads: "ProvisioningFailed and WaitForFirstConsumer reasons for claims",
        field_selector: FieldSelector::Equals("involvedObject.kind", "PersistentVolumeClaim"),
    },
    Allowed {
        group: "storage.k8s.io",
        version: "v1",
        resource: "storageclasses",
        access: &[Access::List, Access::Get(Only::Any)],
        checks: &["k8s.storageclass"],
        reads: "classes, the default marker, the provisioner",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "storage.k8s.io",
        version: "v1",
        resource: "csinodes",
        access: &[Access::List],
        checks: &["k8s.storageclass"],
        reads: "spec.drivers[].name",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "storage.k8s.io",
        version: "v1",
        resource: "csidrivers",
        access: &[Access::List],
        checks: &["k8s.storageclass"],
        reads: "driver objects",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "apps",
        version: "v1",
        resource: "deployments",
        access: &[Access::ListInNamespace(Only::Name("kube-system"))],
        checks: &["k8s.nodes"],
        reads: "the cluster-autoscaler deployment by name",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "security.openshift.io",
        version: "v1",
        resource: "securitycontextconstraints",
        access: &[Access::List],
        checks: &["k8s.admission"],
        reads: "the OpenShift SCCs",
        field_selector: FieldSelector::NotRequired,
    },
    Allowed {
        group: "config.openshift.io",
        version: "v1",
        resource: "clusterversions",
        access: &[Access::Get(Only::Name("version"))],
        checks: &["k8s.version"],
        reads: "the OpenShift version",
        field_selector: FieldSelector::NotRequired,
    },
];

/// The longest `as:` value, in bytes.
const MAX_AS: usize = 253;
/// The prefix of a service account user name.
const SERVICE_ACCOUNT_PREFIX: &str = "system:serviceaccount:";
/// The two review resources an `Impersonate-User` header may ride on (02 Appendix B rule 8). Not
/// `selfsubjectreviews`: that call shows who rdy really is.
const ACCESS_REVIEW_PATHS: [&str; 2] = [
    "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
    "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
];

/// Why a spec `as:` value cannot be sent as `Impersonate-User`.
///
/// The text holds no part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImpersonateError {
    /// The value is empty.
    #[error(
        "the `as` value is empty. Fix: give a user name such as system:serviceaccount:app:installer"
    )]
    Empty,
    /// The value is longer than 253 bytes.
    #[error("the `as` value is longer than 253 bytes. Fix: use a shorter user name")]
    TooLong,
    /// The value has a byte outside printable ASCII, or a space at either end.
    #[error(
        "the `as` value has a character that is not printable ASCII, or a space at its start or end. Fix: use only letters, digits and punctuation in the user name"
    )]
    BadCharacter,
    /// A `system:serviceaccount:` value that is not `system:serviceaccount:<namespace>:<name>`.
    #[error(
        "the `as` value starts with system:serviceaccount: but is not system:serviceaccount:<namespace>:<name>. Fix: name the namespace and the service account, both in DNS-1123 form"
    )]
    BadServiceAccount,
}

/// The user the two access review POSTs may impersonate: the spec's `as:` value, checked once.
///
/// A value is 1 to 253 bytes, uses only the bytes 0x20 to 0x7E (printable ASCII, so no control character,
/// no non-ASCII letter and no Unicode format character such as a right-to-left override, which could
/// spoof the user shown in a report and which an HTTP header value cannot carry anyway), and has no space
/// at either end. A value that starts with `system:serviceaccount:` must be exactly
/// `system:serviceaccount:<namespace>:<name>`, a DNS-1123 label and a DNS-1123 subdomain.
#[derive(Clone, PartialEq, Eq)]
pub struct ImpersonateAs(String);

impl ImpersonateAs {
    /// Checks `value` and keeps it.
    ///
    /// # Errors
    ///
    /// [`ImpersonateError`] naming the rule that the value breaks.
    pub fn new(value: &str) -> Result<Self, ImpersonateError> {
        if value.is_empty() {
            return Err(ImpersonateError::Empty);
        }
        if value.len() > MAX_AS {
            return Err(ImpersonateError::TooLong);
        }
        if !value.bytes().all(|b| (0x20..=0x7E).contains(&b))
            || value.starts_with(' ')
            || value.ends_with(' ')
        {
            return Err(ImpersonateError::BadCharacter);
        }
        if let Some(rest) = value.strip_prefix(SERVICE_ACCOUNT_PREFIX) {
            let valid = rest
                .split_once(':')
                .is_some_and(|(namespace, name)| is_label(namespace) && is_group(name));
            if !valid {
                return Err(ImpersonateError::BadServiceAccount);
            }
        }
        Ok(Self(value.to_owned()))
    }

    /// The checked value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ImpersonateAs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImpersonateAs").finish_non_exhaustive()
    }
}

/// The value an `Impersonate-User` header may carry on this request, or `None` when none may.
pub(crate) fn impersonation_allowed<'a>(
    method: &Method,
    uri: &Uri,
    configured: Option<&'a ImpersonateAs>,
) -> Option<&'a str> {
    let user = configured?;
    (method == Method::POST && ACCESS_REVIEW_PATHS.contains(&uri.path())).then(|| user.as_str())
}

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
/// secrets, then the rules of the method. `configured` is the guard's `as:` user, if it has one.
pub(crate) fn judge(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: BodyView<'_>,
    configured: Option<&ImpersonateAs>,
) -> Result<(), &'static str> {
    let is_get = method == Method::GET;
    if !is_get && method != Method::POST {
        return Err(RULE_METHOD);
    }
    bad_header(headers, impersonation_allowed(method, uri, configured))
        .map_or(Ok(()), |(rule, _)| Err(rule))?;
    let segments = path_segments(uri)?;
    if segments.contains(&"secrets") && !(is_get && segments == NAMESPACE_NAMED_SECRETS) {
        return Err(RULE_SECRETS);
    }
    if is_get {
        if !matches!(body, BodyView::Empty) {
            return Err(RULE_GET_BODY);
        }
        let field_selector = check_query(uri.query())?;
        check_get(&segments, field_selector.as_deref())
    } else {
        check_post(&segments, uri.query(), body)
    }
}

/// What a request path is, for the audit of a fixture run (`client::mock`).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// A path with no [`ALLOWED`] entry by design: `/version`, discovery and the three review POSTs.
    Exempt,
    /// A resource path, and the entry that names its group, version and resource.
    Entry(&'static Allowed),
    /// Anything else: not a plain path, not a resource path, or a resource with no entry.
    Unknown,
}

/// Classifies a path as written in the action log (no query string). Only the path is judged, so this
/// says which entry a request belongs to, not whether the guard would allow it ([`judge`] does that).
#[cfg(test)]
pub(crate) fn target_of(path: &str) -> Target {
    const REVIEWS: [&str; 3] = [
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        SELF_SUBJECT_REVIEW_PATH,
    ];
    if REVIEWS.contains(&path) {
        return Target::Exempt;
    }
    let Ok(uri) = path.parse::<Uri>() else {
        return Target::Unknown;
    };
    let Ok(segments) = path_segments(&uri) else {
        return Target::Unknown;
    };
    if is_discovery(&segments) {
        return Target::Exempt;
    }
    let Ok(info) = request_info(&segments) else {
        return Target::Unknown;
    };
    ALLOWED
        .iter()
        .find(|e| e.group == info.group && e.version == info.version && e.resource == info.resource)
        .map_or(Target::Unknown, Target::Entry)
}

/// The one path with `secrets` in it that is allowed: a GET of the namespace called `secrets`.
const NAMESPACE_NAMED_SECRETS: [&str; 4] = ["api", "v1", "namespaces", "secrets"];

/// The path of `uri` for the action log: no query string, escaped, cut to 200 characters.
pub(crate) fn log_path(uri: &Uri) -> String {
    super::super::text::escape_capped(uri.path(), 200)
}

/// The rule and the name of the first request header the guard refuses, if any. Only the name is ever
/// logged, never the value (02 Appendix B, rule 8).
///
/// The guard sits above kube's own layers (the exec plugin and the token are added below it), so it
/// sees the headers the caller set. kube's request builders set `accept` and `content-type`
/// (`kube-core` 4.2.0, `request.rs`) and nothing else; hyper adds `content-length`, `host` and
/// `user-agent` later. Anything else here was set by check code, so it is refused: an `Authorization`
/// from a client-certificate kubeconfig, `X-Remote-User` and `X-Remote-Group` (front-proxy
/// authentication), `X-HTTP-Method-Override`, `Host`, and every `Impersonate-*` except one.
///
/// The exception: `allowed_user` is the value an `Impersonate-User` header may carry on this request
/// (see [`impersonation_allowed`]). The header passes when it appears once with exactly that value.
/// `Impersonate-Group`, `-Uid` and `-Extra-*` never pass: a service account user has its groups from
/// the server.
pub(crate) fn bad_header<'h>(
    headers: &'h HeaderMap,
    allowed_user: Option<&str>,
) -> Option<(&'static str, &'h str)> {
    if headers.contains_key(UPGRADE) {
        return Some((RULE_UPGRADE, UPGRADE.as_str()));
    }
    for value in headers.get_all(CONNECTION) {
        let upgrade = value.to_str().map_or(true, |text| {
            text.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
        if upgrade {
            return Some((RULE_UPGRADE, CONNECTION.as_str()));
        }
    }
    // Header names are lower case in `http`. This covers `Impersonate-User`, `-Group`, `-Uid` and
    // `-Extra-*`. Headers that the kubeconfig sets are added below the guard and are not seen here.
    for name in headers.keys() {
        if !name.as_str().starts_with("impersonate-") {
            continue;
        }
        let mut values = headers.get_all(name).iter();
        let exact = allowed_user.is_some_and(|user| {
            name.as_str() == "impersonate-user"
                && values
                    .next()
                    .is_some_and(|v| v.as_bytes() == user.as_bytes())
                && values.next().is_none()
        });
        if !exact {
            return Some((RULE_IMPERSONATE, name.as_str()));
        }
    }
    // Any `impersonate-user` still here passed the exact-value test above.
    headers
        .keys()
        .find(|name| {
            ![ACCEPT, CONTENT_TYPE, CONTENT_LENGTH].contains(name)
                && name.as_str() != "impersonate-user"
        })
        .map(|name| (RULE_HEADER, name.as_str()))
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

/// Allows the keys `limit`, `continue`, `labelSelector` and `fieldSelector`, once each, with plain
/// values. Every value is decoded once, as the server does, and the decoded text is checked: a `continue`
/// token, a label selector and a field selector each have a short character set, so a `%26`, `%00`, `%25`
/// or `%5C` cannot carry anything the raw text hid. Returns the decoded `fieldSelector` for the selector
/// rule of the resource.
fn check_query(query: Option<&str>) -> Result<Option<String>, &'static str> {
    // kube writes a bare `?` when there are no parameters, and a `&` before the first one (`?&limit=5`).
    let Some(query) = query
        .map(|query| query.strip_prefix('&').unwrap_or(query))
        .filter(|query| !query.is_empty())
    else {
        return Ok(None);
    };
    if query.len() > MAX_QUERY {
        return Err(RULE_QUERY);
    }
    // Go's `URL.Query()` drops every pair that holds a raw `;`. The server would then see no selector
    // while this guard saw one. `%3B` is fine: it is decoded once, after the split.
    if query.contains(';') {
        return Err(RULE_QUERY);
    }
    let mut field_selector = None;
    // A key twice is ambiguous: the server reads the first, a proxy may read the last.
    let mut seen: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if seen.contains(&key) {
            return Err(RULE_QUERY);
        }
        seen.push(key);
        match key {
            "limit" => {
                if value.is_empty() || value.len() > 6 || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(RULE_QUERY);
                }
            }
            "continue" => {
                check_query_value(value)?;
                check_continue(&decode_query_value(value)?)?;
            }
            "labelSelector" => {
                check_query_value(value)?;
                check_label_selector(&decode_query_value(value)?)?;
            }
            "fieldSelector" => {
                check_query_value(value)?;
                let decoded = decode_query_value(value)?;
                check_field_selector(&decoded)?;
                field_selector = Some(decoded);
            }
            _ => return Err(RULE_QUERY),
        }
    }
    Ok(field_selector)
}

/// The longest decoded `continue` token, label selector or field selector.
const MAX_DECODED: usize = 4096;

/// A `continue` token is base64 (the standard or the URL alphabet, with or without `=`).
fn check_continue(token: &str) -> Result<(), &'static str> {
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'/' | b'=');
    if token.len() > MAX_DECODED || !token.bytes().all(plain) {
        return Err(RULE_QUERY);
    }
    Ok(())
}

/// A label selector is names, values, `,`, `=`, `!`, `<`, `>`, `(`, `)`, `in` and `notin`, so: letters,
/// digits, space and `. _ - / , = ! < > ( )`.
fn check_label_selector(selector: &str) -> Result<(), &'static str> {
    let plain = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b' ' | b'.' | b'_' | b'-' | b'/' | b',' | b'=' | b'!' | b'<' | b'>' | b'(' | b')'
            )
    };
    if selector.len() > MAX_DECODED || !selector.bytes().all(plain) {
        return Err(RULE_QUERY);
    }
    Ok(())
}

/// A field selector is terms `key=value`, `key==value` or `key!=value` joined by `,`. The characters are
/// letters, digits and `. _ - / : , = !`, and every term has a key and an operator. An empty selector
/// has no terms.
fn check_field_selector(selector: &str) -> Result<(), &'static str> {
    let plain = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'_' | b'-' | b'/' | b':' | b',' | b'=' | b'!')
    };
    if selector.len() > MAX_DECODED || !selector.bytes().all(plain) {
        return Err(RULE_QUERY);
    }
    if selector.is_empty() {
        return Ok(());
    }
    let terms_ok = selector
        .split(',')
        .all(|term| split_term(term).is_some_and(|(key, _, _)| !key.is_empty()));
    if terms_ok { Ok(()) } else { Err(RULE_QUERY) }
}

/// Decodes a query value once, as the API server does: `%XX` is a byte and `+` is a space. A backslash
/// or bytes that are not UTF-8 are refused.
pub(crate) fn decode_query_value(value: &str) -> Result<String, &'static str> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'%' => {
                let hex = value.get(index + 1..index + 3).ok_or(RULE_QUERY)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| RULE_QUERY)?);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }
    let text = String::from_utf8(out).map_err(|_| RULE_QUERY)?;
    if text.contains('\\') {
        return Err(RULE_QUERY);
    }
    Ok(text)
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

/// A request path as the API server's request-info parser reads it (`k8s.io/apiserver`,
/// `RequestInfoFactory.NewRequestInfo`).
///
/// `namespace` is set only for a namespaced resource: `/api/v1/namespaces/x/pods` has namespace `x` and
/// resource `pods`, while `/api/v1/namespaces/x` has resource `namespaces` and name `x`, and
/// `/api/v1/namespaces/x/finalize` has resource `namespaces`, name `x` and subresource `finalize`.
///
/// This differs from the server's `NewRequestInfo` in two places, on purpose. For `/api/v1/namespaces/x`
/// the server also sets the namespace to `x`; this parser leaves it `None`, so the `Get(Only::Any)`
/// entry of `namespaces` matches by name and a namespaced list does not. And the server keeps one
/// subresource part; this parser joins the whole tail (`proxy/a/b`) into `subresource`. Neither changes
/// a verdict, because every subresource is refused. Do not "fix" either to match the server.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RequestInfo<'a> {
    pub(super) group: &'a str,
    pub(super) version: &'a str,
    pub(super) namespace: Option<&'a str>,
    pub(super) resource: &'a str,
    pub(super) name: Option<&'a str>,
    /// What follows the name, joined by `/`. `None` for no subresource.
    pub(super) subresource: Option<String>,
}

/// Parses the segments of a resource path. `Err` is the rule for a path that is not a resource path or
/// that uses a legacy path verb.
pub(super) fn request_info<'a>(segments: &[&'a str]) -> Result<RequestInfo<'a>, &'static str> {
    let (group, version, mut parts) = match segments {
        ["api", version, rest @ ..] => ("", *version, rest),
        ["apis", group, version, rest @ ..] => (*group, *version, rest),
        _ => return Err(RULE_NOT_ALLOWED),
    };
    // `/api/v1/watch/nodes` and `/api/v1/proxy/nodes/x` are the legacy forms of a watch and a proxy.
    if parts.len() > 1 && matches!(parts.first(), Some(&"watch" | &"proxy")) {
        return Err(RULE_NOT_ALLOWED);
    }
    // `/namespaces/<ns>/<resource>/...` is a namespaced resource, unless the part after the name is a
    // subresource of the namespace itself.
    let mut namespace = None;
    if let ["namespaces", name, third, ..] = parts
        && !matches!(*third, "status" | "finalize")
    {
        namespace = Some(*name);
        parts = parts.get(2..).unwrap_or_default();
    }
    let Some(resource) = parts.first() else {
        return Err(RULE_NOT_ALLOWED);
    };
    let subresource = parts
        .get(2..)
        .filter(|rest| !rest.is_empty())
        .map(|rest| rest.join("/"));
    Ok(RequestInfo {
        group,
        version,
        namespace,
        resource,
        name: parts.get(1).copied(),
        subresource,
    })
}

fn check_get(segments: &[&str], field_selector: Option<&str>) -> Result<(), &'static str> {
    if is_discovery(segments) {
        return Ok(());
    }
    let info = request_info(segments)?;
    if info.subresource.is_some() {
        return Err(RULE_SUBRESOURCE);
    }
    let Some(entry) = ALLOWED.iter().find(|e| {
        e.group == info.group && e.version == info.version && e.resource == info.resource
    }) else {
        return Err(RULE_NOT_ALLOWED);
    };
    let allowed = entry
        .access
        .iter()
        .any(|access| match (access, info.namespace, info.name) {
            (Access::List, None, None) => true,
            (Access::ListInNamespace(only), Some(namespace), None) => only.admits(namespace),
            (Access::Get(only), None, Some(name)) => only.admits(name),
            _ => false,
        });
    if !allowed {
        return Err(RULE_NOT_ALLOWED);
    }
    // A list (no name) must carry the field selector its entry names. A get by name needs none.
    if info.name.is_none() && !entry.field_selector.met_by(field_selector) {
        return Err(RULE_SELECTOR);
    }
    Ok(())
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
pub(super) fn is_group(group: &str) -> bool {
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

/// A DNS-1123 label: lower case letters, digits and `-`, starting and ending with a letter or digit, at
/// most 63 characters.
fn is_label(label: &str) -> bool {
    !label.contains('.') && label.len() <= 63 && is_group(label)
}

/// `^v[0-9]+((alpha|beta)[0-9]+)?$`.
pub(super) fn is_version(version: &str) -> bool {
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
