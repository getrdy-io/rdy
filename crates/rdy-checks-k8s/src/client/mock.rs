//! The kube mock harness (M1-105): a tower service that replays the `api/` files of a fixture, and the
//! audit that proves INV-14 over a fixture run.
//!
//! Test code only. A check's fixture test builds a [`Harness`] over a fixture, gets a [`ReadOnlyClient`]
//! for its probe, runs the real check code, and the harness audits the run when it is dropped. The client
//! is built by `ReadOnlyClient::over`, the same constructor production uses, so the guard sits in front
//! of the mock exactly as it sits in front of the real server.
//!
//! # What the mock answers
//!
//! - A request is found by its method, its path and its **decoded query pairs**, sorted. A fixture may
//!   write `fieldSelector=status.phase!=Failed,status.phase!=Succeeded&limit=500` in plain text and in any
//!   order, and kube's own `%21%3D` form still matches. That is how selectors work: a list with another
//!   selector is another request, and the fixture holds one file per full query (03, "Fixtures for all of
//!   them").
//! - Paged lists have one file per `continue` token, as in 08. [`Mock::expire_once`] makes a token answer
//!   `410 Gone` the first time it is presented, as a server that compacted its history does; a file that
//!   records a 410 answers it every time.
//! - Discovery (`/version`, `/api`, `/apis`, `/apis/<group>/<version>`) is the legacy document. A request
//!   whose `Accept` selects the aggregated document is answered `406`, because no such document is
//!   recorded.
//! - `SelfSubjectAccessReview` is answered from the table in `api/reviews.json`:
//!   `{"access": [{"spec": {...}, "status": {...}}]}`. A row matches when its `spec` equals the posted
//!   `spec`, ignoring empty strings and nulls, and the row's `status` is the answer. Any other POST (the
//!   `SelfSubjectReview`) is a plain recorded request.
//! - Anything the fixture does not hold fails: a `501` that names the request, and a line in
//!   [`Mock::unrecorded`]. A fixture never falls through to a default (02).
//!
//! # The audit
//!
//! The guard refuses an unlisted request before it reaches the mock, so a fixture run proves INV-14 only
//! if the harness also looks at what the mock *recorded* ([`audit`]):
//!
//! 1. every recorded request passes the guard's own rules (`judge`) and names a path that is an
//!    [`ALLOWED`](super::guard::ALLOWED) entry or is discovery, `/version` or a review;
//! 2. every action-log entry that was sent, if its path names an `ALLOWED` entry, is logged under a check
//!    id that the entry cites in `checks` (a `None` check id cites nothing);
//! 3. each recorded request pairs with one sent log entry of the same method and path (a multiset), so no
//!    request reached the mock without the guard, and no sent entry is left without a request;
//! 4. the fixture answered every request.
//!
//! The harness runs the audit when it is dropped, so no fixture test can forget it. A test that expects a
//! failing audit calls [`Harness::audit`] itself, and a failing audit turns the drop audit off.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, Method, Request, Response, Uri};
use http_body::Body as _;
use kube::api::ListParams;
use kube::client::Body;
use rdy_engine::check::{Need, Os};
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Fixture, Replay, TestRun, fixtures_dir};
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::{Value, json};
use tower_service::Service;

use super::guard::{BodyView, Target, decode_query_value, judge, log_path, target_of};
use super::text::escape_capped;
use super::{ConnectionFacts, KubeError, ReadOnlyClient, ServerVersion, from_kube_error};

#[cfg(test)]
mod tests;

/// The path of the access review the mock answers from its table.
const ACCESS_REVIEW_PATH: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";

/// Why a mock could not be built from a fixture.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum MockError {
    /// A recorded query is not valid query text.
    #[error("the query `{0}` of a recorded request is not valid query text")]
    BadQuery(String),
    /// Two files record the same request once their queries are decoded and sorted.
    #[error(
        "two recorded requests are the same once their query pairs are decoded and sorted: {0}"
    )]
    Duplicate(String),
    /// `api/reviews.json` is not in the shape the mock reads.
    #[error("api/reviews.json: {0}")]
    BadReviews(String),
    /// The fixture did not load.
    #[error("the fixture did not load: {0}")]
    Fixture(String),
}

/// One recorded answer.
#[derive(Debug, Clone)]
struct Record {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
}

/// One row of the review table.
#[derive(Debug, Clone)]
struct ReviewRow {
    /// The `spec` with empty strings and nulls removed.
    spec: Value,
    status: Value,
}

/// A request that reached the mock.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Seen {
    /// `METHOD path?query`, as the request was sent.
    pub(crate) fn line(&self) -> String {
        format!(
            "{} {}",
            self.method,
            self.uri
                .path_and_query()
                .map_or("", http::uri::PathAndQuery::as_str)
        )
    }
}

#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    unrecorded: Vec<String>,
    /// Decoded `continue` tokens that answer 410 the next time they are presented.
    expire_once: BTreeSet<String>,
}

struct Inner {
    /// `(METHOD, path, canonical query)` to the answer.
    records: BTreeMap<(String, String, String), Record>,
    reviews: Vec<ReviewRow>,
    state: Mutex<State>,
}

/// The mock API server: a `tower::Service` over the `api/` files of a fixture. Clones share state.
#[derive(Clone)]
pub(crate) struct Mock {
    inner: Arc<Inner>,
}

impl fmt::Debug for Mock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mock").finish_non_exhaustive()
    }
}

/// The decoded query pairs of `query`, sorted and joined: the key a request is found by. kube writes a
/// leading `&` (`?&limit=5`), and a fixture may leave the query out.
fn canonical_query(query: &str) -> Result<String, MockError> {
    let bad = || MockError::BadQuery(query.to_owned());
    let mut pairs = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_query_value(key).map_err(|_| bad())?;
        let value = decode_query_value(value).map_err(|_| bad())?;
        pairs.push(format!("{key}={value}"));
    }
    pairs.sort();
    Ok(pairs.join("&"))
}

/// A `Status` body, as the API server writes a failure.
fn status_body(code: u16, reason: &str, message: &str) -> Value {
    json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code,
    })
}

/// `spec` without nulls and empty strings, so `{"verb": "get", "name": ""}` equals `{"verb": "get"}`.
fn without_empty(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, member)| !member.is_null() && member.as_str() != Some(""))
                .map(|(key, member)| (key.clone(), without_empty(member)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn parse_reviews(table: &Value) -> Result<Vec<ReviewRow>, MockError> {
    let bad = |reason: &str| MockError::BadReviews(reason.to_owned());
    let object = table
        .as_object()
        .ok_or_else(|| bad("must be an object with an `access` list"))?;
    if let Some(key) = object.keys().find(|key| key.as_str() != "access") {
        return Err(MockError::BadReviews(format!("unknown key `{key}`")));
    }
    let rows = object
        .get("access")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("`access` must be a list"))?;
    let mut parsed: Vec<ReviewRow> = Vec::new();
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| bad("a row must be an object with `spec` and `status`"))?;
        if let Some(key) = row
            .keys()
            .find(|key| !matches!(key.as_str(), "spec" | "status"))
        {
            return Err(MockError::BadReviews(format!("unknown row key `{key}`")));
        }
        let spec = row
            .get("spec")
            .filter(|spec| spec.is_object())
            .ok_or_else(|| bad("a row needs a `spec` object"))?;
        let status = row
            .get("status")
            .filter(|status| status.get("allowed").is_some_and(Value::is_boolean))
            .ok_or_else(|| bad("a row needs a `status` object with a boolean `allowed`"))?;
        let spec = without_empty(spec);
        if parsed.iter().any(|earlier| earlier.spec == spec) {
            return Err(MockError::BadReviews(format!(
                "two rows have the spec {spec}"
            )));
        }
        parsed.push(ReviewRow {
            spec,
            status: status.clone(),
        });
    }
    Ok(parsed)
}

impl Mock {
    /// Builds the mock from the `api/` records of `replay`.
    ///
    /// # Errors
    ///
    /// [`MockError`] for a query that cannot be decoded, two records that are one request once their
    /// queries are decoded and sorted, or a malformed review table.
    pub(crate) fn new(replay: &Replay) -> Result<Self, MockError> {
        let mut records = BTreeMap::new();
        for (method, path, query, record) in replay.api_records() {
            let key = (method.to_owned(), path.to_owned(), canonical_query(query)?);
            let body = if record.body.is_null() {
                Vec::new()
            } else {
                serde_json::to_vec(&record.body).expect("a JSON value serializes")
            };
            let answer = Record {
                status: record.status,
                body,
                delay: record.delay,
            };
            if records.insert(key, answer).is_some() {
                return Err(MockError::Duplicate(format!("{method} {path} {query}")));
            }
        }
        let reviews = replay.reviews().map(parse_reviews).transpose()?;
        Ok(Self {
            inner: Arc::new(Inner {
                records,
                reviews: reviews.unwrap_or_default(),
                state: Mutex::new(State::default()),
            }),
        })
    }

    /// The next presentation of the `continue` token `token` (decoded) answers `410 Gone`, once.
    pub(crate) fn expire_once(&self, token: &str) {
        self.state().expire_once.insert(token.to_owned());
    }

    /// Every request that reached the mock, in arrival order.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.state().seen.clone()
    }

    /// `METHOD path?query` of every request the fixture had no answer for.
    pub(crate) fn unrecorded(&self) -> Vec<String> {
        self.state().unrecorded.clone()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().expect("mock state")
    }

    /// Answers one request.
    async fn answer(&self, request: Request<Body>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let bytes = read_all(body).await;
        let seen = Seen {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            headers: parts.headers.clone(),
            body: bytes,
        };
        let line = seen.line();
        self.state().seen.push(seen.clone());

        let path = parts.uri.path().to_owned();
        let query = match canonical_query(parts.uri.query().unwrap_or("")) {
            Ok(query) => query,
            Err(_) => return self.not_recorded(&line),
        };

        // The aggregated discovery document is selected by `Accept` and is not recorded.
        let aggregated =
            parts.headers.get_all(ACCEPT).iter().any(|value| {
                String::from_utf8_lossy(value.as_bytes()).contains("apidiscovery.k8s.io")
            });
        if parts.method == Method::GET && aggregated && matches!(path.as_str(), "/api" | "/apis") {
            return respond(
                406,
                &status_body(
                    406,
                    "NotAcceptable",
                    "the mock records the legacy discovery document only",
                ),
            );
        }

        // A continue token that expires: the first presentation answers 410, the next finds the record.
        let token = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("continue="))
            .map(str::to_owned);
        if let Some(token) = token
            && self.state().expire_once.remove(&token)
        {
            return respond(
                410,
                &status_body(
                    410,
                    "Expired",
                    "The provided continue parameter is too old to display a consistent list result. You can start a new list without the continue parameter.",
                ),
            );
        }

        if parts.method == Method::POST && path == ACCESS_REVIEW_PATH {
            return self.access_review(&seen.body, &line);
        }

        let key = (parts.method.as_str().to_owned(), path, query);
        let Some(record) = self.inner.records.get(&key) else {
            return self.not_recorded(&line);
        };
        if !record.delay.is_zero() {
            tokio::time::sleep(record.delay).await;
        }
        respond_bytes(record.status, record.body.clone())
    }

    fn access_review(&self, body: &[u8], line: &str) -> Response<Body> {
        let Ok(posted) = serde_json::from_slice::<Value>(body) else {
            return respond(400, &status_body(400, "BadRequest", "the body is not JSON"));
        };
        let spec = posted.get("spec").map(without_empty).unwrap_or(Value::Null);
        let Some(row) = self.inner.reviews.iter().find(|row| row.spec == spec) else {
            return self.not_recorded(line);
        };
        respond(
            201,
            &json!({
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SelfSubjectAccessReview",
                "metadata": { "creationTimestamp": null },
                "spec": posted.get("spec").cloned().unwrap_or(Value::Null),
                "status": row.status,
            }),
        )
    }

    fn not_recorded(&self, line: &str) -> Response<Body> {
        self.state().unrecorded.push(line.to_owned());
        respond(
            501,
            &status_body(
                501,
                "NotImplemented",
                "the fixture holds no answer for this request",
            ),
        )
    }
}

fn respond(status: u16, body: &Value) -> Response<Body> {
    respond_bytes(status, serde_json::to_vec(body).expect("JSON serializes"))
}

fn respond_bytes(status: u16, body: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("a response")
}

/// Reads a request body to the end.
async fn read_all(body: Body) -> Vec<u8> {
    let mut body = pin!(body);
    let mut bytes = Vec::new();
    while let Some(frame) = poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        if let Ok(data) = frame.expect("a readable body").into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    bytes
}

impl Service<Request<Body>> for Mock {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mock = self.clone();
        Box::pin(async move { Ok(mock.answer(request).await) })
    }
}

// ---- the audit ----------------------------------------------------------------------------------------------

/// Checks a fixture run against `ALLOWED` (INV-14). Returns one sentence per violation; empty is clean.
///
/// `seen` is what reached the mock, `log` is the run's action log and `unrecorded` is what the fixture
/// had no answer for. See the module docs for the four rules.
pub(crate) fn audit(seen: &[Seen], log: &[Action], unrecorded: &[String]) -> Vec<String> {
    let mut violations = Vec::new();

    for request in seen {
        let body = if request.body.is_empty() {
            BodyView::Empty
        } else {
            BodyView::Bytes(&request.body)
        };
        let line = request.line();
        // The `else if` below (a request `judge` passes whose target is `Unknown`) is not reachable
        // today: a GET that `judge` passes is discovery, `/version` or an `ALLOWED` entry, and a review
        // POST is exempt. No test makes it happen. It stays so the audit fails closed if `judge` and
        // `target_of` ever drift apart.
        if let Err(rule) = judge(&request.method, &request.uri, &request.headers, body, None) {
            violations.push(format!(
                "INV-14: the mock recorded `{line}`, which the guard refuses ({rule})"
            ));
        } else if target_of(request.uri.path()) == Target::Unknown {
            violations.push(format!(
                "INV-14: the mock recorded `{line}`, which no entry of ALLOWED names"
            ));
        }
    }

    // Pair each recorded request with one sent log entry of the same method and path, as a multiset.
    // A count alone would let an unguarded request hide behind a guarded entry that never reached the
    // mock (a timeout before the send). What is left on either side is a violation, and the citation is
    // proven for every pair.
    let mut sent: Vec<(String, String, Option<&str>)> = log
        .iter()
        .filter(|entry| entry.kind == ActionKind::Kube && entry.outcome != ActionOutcome::Denied)
        .map(|entry| {
            let field = |name: &str| {
                entry
                    .fields
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            (field("method"), field("path"), entry.check.as_deref())
        })
        .collect();
    for request in seen {
        let method = escape_capped(request.method.as_str(), 16);
        let path = log_path(&request.uri);
        let Some(index) = sent.iter().position(|(m, p, _)| *m == method && *p == path) else {
            violations.push(format!(
                "INV-14: the mock recorded `{}` but the log holds no sent entry for it; a request reached the mock without the guard",
                request.line()
            ));
            continue;
        };
        let (_, path, check) = sent.swap_remove(index);
        match target_of(&path) {
            Target::Exempt => {}
            // Not reachable today, for the reason given at the first loop. It keeps the match total and
            // fails closed.
            Target::Unknown => violations.push(format!(
                "INV-14: the log holds a sent request for `{path}`, which no entry of ALLOWED names"
            )),
            Target::Entry(allowed) => {
                if !check.is_some_and(|id| allowed.checks.contains(&id)) {
                    violations.push(format!(
                        "INV-14: `{path}` was read under {}, but its ALLOWED entry ({}) cites only {:?}",
                        check.map_or("no check id".to_owned(), |id| format!("`{id}`")),
                        allowed.resource,
                        allowed.checks,
                    ));
                }
            }
        }
    }
    for (method, path, _) in sent {
        violations.push(format!(
            "INV-14: the log holds a sent entry `{method} {path}` that the mock never recorded; the request did not reach the mock, or the log and the mock disagree"
        ));
    }

    violations.extend(unrecorded.iter().map(|line| {
        format!("the fixture has no answer for `{line}`; record it under api/ or fix the check")
    }));
    violations
}

// ---- the harness --------------------------------------------------------------------------------------------

/// A fixture run: the mock, the run it logs into, and the audit that closes it.
pub(crate) struct Harness {
    run: TestRun,
    mock: Mock,
    audited: AtomicBool,
    via_proxy: Option<String>,
}

impl fmt::Debug for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Harness").finish_non_exhaustive()
    }
}

impl Harness {
    /// Loads the fixture `name` under `tests/fixtures` (for example `checks/_kube/cluster`).
    ///
    /// # Errors
    ///
    /// [`MockError`] when the fixture does not load or its `api/` files do not make a mock.
    pub(crate) fn load(name: &str) -> Result<Self, MockError> {
        let fixture = Fixture::load(&fixtures_dir(), name)
            .map_err(|error| MockError::Fixture(error.to_string()))?;
        Self::new(TestRun::for_fixture(&fixture), fixture.replay())
    }

    /// A harness over `replay`, logging into `run`.
    ///
    /// # Errors
    ///
    /// [`MockError`] when the `api/` records of `replay` do not make a mock.
    pub(crate) fn new(run: TestRun, replay: &Replay) -> Result<Self, MockError> {
        Ok(Self {
            run,
            mock: Mock::new(replay)?,
            audited: AtomicBool::new(false),
            via_proxy: None,
        })
    }

    /// Makes the clients record `via_proxy: origin` on every `kube` entry, as a connection through a
    /// proxy does.
    #[must_use]
    pub(crate) fn via_proxy(mut self, origin: &str) -> Self {
        self.via_proxy = Some(origin.to_owned());
        self
    }

    /// The run the clients log into.
    pub(crate) fn run(&self) -> &TestRun {
        &self.run
    }

    /// The mock, for its recorded requests.
    pub(crate) fn mock(&self) -> &Mock {
        &self.mock
    }

    /// A read-only client for the check that owns `probe` (`CheckContext::probe`): the guard in front of
    /// the mock, as `Connected::read_only` builds it in front of the real server. Needs a tokio runtime.
    pub(crate) fn client(&self, probe: &Probe) -> ReadOnlyClient {
        ReadOnlyClient::over(self.mock.clone(), probe, self.via_proxy.as_deref())
    }

    /// Like [`Harness::client`], for a check called `check` that has the `KubeContext` need.
    pub(crate) fn client_for(&self, check: &str) -> ReadOnlyClient {
        let context = self.run.context(check, Os::Linux, [Need::KubeContext]);
        self.client(context.probe())
    }

    /// A client from the run-level probe, which logs `check: null`, as `Loaded::connect` does.
    pub(crate) fn run_client(&self) -> ReadOnlyClient {
        self.client(&self.run.run_probe(Os::Linux))
    }

    /// The run's connection attempt over the mock, as `Loaded::connect` makes it: `GET /version` through
    /// the guard from the run-level probe (`check: null`), timed, with an error mapped as production maps
    /// it. `facts` says whether a proxy or a CA was in play, for the hints.
    pub(crate) async fn attempt(
        &self,
        facts: &ConnectionFacts,
    ) -> Result<(ServerVersion, Duration), KubeError> {
        let plugin = facts.line().plugin();
        let started = std::time::Instant::now();
        let info = self.run_client().version().await.map_err(|error| {
            from_kube_error(
                &error,
                facts.line().server(),
                plugin,
                facts.proxy().is_proxied(),
                facts.ca_set(),
            )
        })?;
        Ok((ServerVersion::from_info(info), started.elapsed()))
    }

    /// Audits the run so far ([`audit`]). A failing audit turns off the audit at drop, so the test does not
    /// panic twice; a clean one leaves it on, so requests made later are still audited.
    ///
    /// # Errors
    ///
    /// One sentence per violation.
    pub(crate) fn audit(&self) -> Result<(), Vec<String>> {
        let violations = audit(
            &self.mock.seen(),
            &self.run.action_log().actions,
            &self.mock.unrecorded(),
        );
        if violations.is_empty() {
            Ok(())
        } else {
            self.audited.store(true, Ordering::SeqCst);
            Err(violations)
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if self.audited.load(Ordering::SeqCst) || std::thread::panicking() {
            return;
        }
        if let Err(violations) = self.audit() {
            panic!(
                "the fixture run broke INV-14 or left a request unanswered:\n{}",
                violations.join("\n")
            );
        }
    }
}

// ---- paging -------------------------------------------------------------------------------------------------

/// A list read to the end.
#[derive(Debug)]
pub(crate) struct Listed<K> {
    /// Every object, in page order.
    pub(crate) items: Vec<K>,
    /// How many times the walk started over after a `410 Gone`: 0 or 1.
    pub(crate) restarts: u32,
}

/// Reads a whole list by following `continue` tokens. A `410 Gone` on an expired token starts the walk
/// over once from the first page (03: "restarts once, then marks the check partial"); a second `410` is
/// returned as the error. `params` carries the limit and the selectors.
///
/// This is the paging contract of 03, written for the harness. The 5000 object cap and the "partial"
/// mark belong to the production paging helper that M1-107 builds.
///
/// # Errors
///
/// The `kube::Error` of the request that failed.
pub(crate) async fn list_all<K>(
    api: &kube::Api<K>,
    params: &ListParams,
) -> Result<Listed<K>, kube::Error>
where
    K: Clone + k8s_openapi::serde::de::DeserializeOwned + fmt::Debug,
{
    let mut restarts = 0;
    loop {
        let mut items = Vec::new();
        let mut token: Option<String> = None;
        let walked: Result<(), kube::Error> = loop {
            let mut page = params.clone();
            if let Some(token) = &token {
                page = page.continue_token(token);
            }
            match api.list(&page).await {
                Ok(list) => {
                    items.extend(list.items);
                    match list.metadata.continue_.filter(|next| !next.is_empty()) {
                        Some(next) => token = Some(next),
                        None => break Ok(()),
                    }
                }
                Err(error) => break Err(error),
            }
        };
        match walked {
            Ok(()) => return Ok(Listed { items, restarts }),
            Err(kube::Error::Api(status)) if status.code == 410 && restarts == 0 => restarts += 1,
            Err(error) => return Err(error),
        }
    }
}
