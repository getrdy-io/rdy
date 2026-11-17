//! The `k8s` family: the checks of this crate and the lazy `kube_context` probe (M1-107, 02 "Privilege and
//! needs", ADR 0031, ADR 0037).
//!
//! **Lazy.** Nothing is read until the engine calls [`Family::probe`], and it calls it only when the plan
//! holds a runnable `k8s.*` check. A spec with no k8s check loads no kubeconfig and sends no request. With
//! `--no-network` no client is built.
//!
//! **One attempt per run.** The probe runs the steps in this order, and the order is the contract:
//!
//! 1. `load` reads the kubeconfig (or the pod's config) on the blocking pool. It opens no socket and runs no
//!    plugin.
//! 2. Every file it read is recorded as a `read` entry, and the credential plugin as one `exec` entry
//!    (`delegated`: kube starts it, rdy does not see its output).
//! 3. Every secret of the config (the credentials of every user entry, the proxy password) is registered as
//!    a known secret. One the set refuses ends the run with exit 70, before anything is printed.
//! 4. The cluster line is printed, then the client is built (which may run the plugin) and `GET /version`
//!    is sent. The engine ends the probe after [`FAMILY_PROBE_LIMIT`]; a plugin that waits for a login is
//!    then abandoned, and its process cannot keep rdy from exiting (the runtime shuts down without waiting,
//!    ADR 0031 decision 7).
//!
//! The answer is kept in one holder ([`Holder`]). The checks read it: `k8s.access` as a [`Dial`] (it says why
//! an attempt failed), the others as a [`Cluster`] (the need gate skips them when the attempt failed). A
//! check built here holds the same `Arc` as the family, so the checks can be built at plan time, before
//! the attempt, and read the answer after it.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use rdy_engine::check::{BoxFuture, CheckInfo, Need};
use rdy_engine::family::{
    BuildError, Built, FAMILY_PROBE_LIMIT, Family, FamilyFatal, FamilyProbe, HostSet,
};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{Capability, CheckResult, KubeIdentity};
use rdy_spec::spec::{CheckSpec, Spec};

use crate::access::{AccessCheck, Dial, DialOutcome, Dialed};
use crate::client::{
    ConnectionFacts, Env, ImpersonateAs, ImpersonationError, KubeError, KubeOptions,
    ReadOnlyClient, ServerVersion, from_kube_error, load,
};
use crate::cluster::Cluster;
use crate::registry;
use crate::version::VersionCheck;

#[cfg(test)]
mod tests;

/// The ids of this crate that the family does not build yet. The planner skips each as `not_in_build`.
/// Their checks exist, and the tickets that give them a spec entry (the target namespace of the k8s block of
/// the spec for three of them) add the arm to [`K8sFamily::build`] and take the id off this list.
static NOT_BUILT: [&str; 4] = [
    "k8s.admission",
    "k8s.namespace",
    "k8s.rbac",
    "k8s.storageclass",
];

/// What a check that has no cluster to read sees: no version.
static NO_VERSION: ServerVersion = ServerVersion {
    git_version: String::new(),
    major: String::new(),
    minor: String::new(),
    platform: String::new(),
};

/// What `k8s.access` reads before the probe has run: no attempt was made.
static NOT_ATTEMPTED: DialOutcome = DialOutcome::NoNetwork;

/// The `k8s` family.
#[derive(Debug)]
pub struct K8sFamily {
    holder: Arc<Holder>,
}

impl K8sFamily {
    /// A family that reads the process environment (`KUBECONFIG`, the proxy variables, `PATH`) when the
    /// probe runs.
    #[must_use]
    pub fn new() -> Self {
        Self {
            holder: Arc::new(Holder::new(None)),
        }
    }

    /// A family that reads `env` and not the process. Tests use it, so they never change the process.
    #[must_use]
    pub fn with_env(env: Env) -> Self {
        Self {
            holder: Arc::new(Holder::new(Some(env))),
        }
    }
}

impl Default for K8sFamily {
    fn default() -> Self {
        Self::new()
    }
}

/// The answer of the run's attempt, shared by the family and every check it built.
pub(crate) struct Holder {
    /// `None` reads the process when the probe runs.
    env: Option<Env>,
    /// What the attempt came to. Set once, by the probe or by the timeout.
    dialed: OnceLock<Dialed>,
    /// The facts of the config, set as soon as it loaded, so a timeout can still report them.
    facts: Mutex<Option<ConnectionFacts>>,
}

impl std::fmt::Debug for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Holder")
            .field("dialed", &self.dialed.get())
            .finish_non_exhaustive()
    }
}

impl Holder {
    fn new(env: Option<Env>) -> Self {
        Self {
            env,
            dialed: OnceLock::new(),
            facts: Mutex::new(None),
        }
    }

    fn settle(&self, dialed: Dialed) {
        // The first answer stands. A probe that ended at the timeout and one that finished a moment later
        // cannot both be the answer.
        let _ = self.dialed.set(dialed);
    }

    fn remember(&self, facts: ConnectionFacts) {
        *self.facts.lock().unwrap_or_else(PoisonError::into_inner) = Some(facts);
    }

    fn remembered(&self) -> Option<ConnectionFacts> {
        self.facts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The probe: one attempt to reach the cluster, in the order of the module text.
    async fn attempt(&self, ctx: FamilyProbe<'_>) -> Result<Vec<Capability>, FamilyFatal> {
        if !ctx.network {
            self.settle(Dialed::no_network());
            return Ok(vec![unavailable(
                "--no-network".to_owned(),
                "run rdy again without --no-network to check the cluster".to_owned(),
            )]);
        }
        let mut options = KubeOptions::new(FAMILY_PROBE_LIMIT);
        if let Some(path) = ctx.kubeconfig {
            options = options.kubeconfig(path);
        }
        if let Some(name) = ctx.kube_context {
            options = options.context(name);
        }
        let env = self.env.clone().unwrap_or_else(Env::from_process);
        let loaded = match load(&options, &env).await {
            Ok(loaded) => loaded,
            Err(error) => return Ok(self.failed(None, error)),
        };
        let facts = loaded.facts();
        self.remember(facts.clone());

        // The files the client reads and the plugin it runs are in the action log (SEC-22, 02).
        for path in loaded.files() {
            let _ = ctx.probe.record_run_read(path);
        }
        if let Some(plugin) = loaded.plugin_exec() {
            let _ = ctx.probe.record_run_exec(plugin.command(), plugin.args());
        }
        // Every secret before the line: a value the set refuses ends the run (exit 70). A value under the
        // set's minimum is not a secret it can hide without hiding common words, and is not asked.
        for secret in loaded.known_secrets() {
            if secret.len() >= rdy_engine::redact::KNOWN_SECRET_MIN_LEN
                && !ctx.hub.add_known_secret(&secret)
            {
                return Err(FamilyFatal::new(
                    "rdy cannot promise to keep a credential of the kubeconfig or of the proxy out of its output",
                    "use credentials of 6 bytes to 64 KiB, or a kubeconfig that holds fewer secrets, then run rdy again",
                ));
            }
        }

        let announce = ctx.announce;
        match loaded
            .connect(&ctx.probe, |line| announce(&line.to_string()))
            .await
        {
            Ok(connected) => {
                let mut cap = Capability::new(Need::KubeContext.wire(), true);
                cap.detail = Some(format!("{}", connected.line()));
                self.settle(Dialed::reached(connected));
                Ok(vec![cap])
            }
            Err(error) => Ok(self.failed(Some(facts), error)),
        }
    }

    /// The attempt failed: the capability says why, and `k8s.access` gets the error.
    fn failed(&self, facts: Option<ConnectionFacts>, error: KubeError) -> Vec<Capability> {
        let cap = unavailable(error.to_string(), error.hint());
        self.settle(Dialed::failed(facts, error));
        vec![cap]
    }
}

/// The `kube_context` capability of an attempt that did not reach the cluster.
fn unavailable(detail: String, hint: String) -> Capability {
    let mut cap = Capability::new(Need::KubeContext.wire(), false);
    cap.detail = Some(detail);
    cap.hint = Some(hint);
    cap
}

impl Dial for Holder {
    fn facts(&self) -> Option<&ConnectionFacts> {
        self.dialed.get().and_then(Dial::facts)
    }

    fn outcome(&self) -> &DialOutcome {
        self.dialed.get().map_or(&NOT_ATTEMPTED, Dial::outcome)
    }

    fn read_only(&self, probe: &rdy_engine::probe::Probe) -> Option<ReadOnlyClient> {
        self.dialed.get().and_then(|dialed| dialed.read_only(probe))
    }
}

impl Cluster for Holder {
    fn server_version(&self) -> &ServerVersion {
        self.dialed
            .get()
            .and_then(Dialed::connected)
            .map_or(&NO_VERSION, |connected| connected.server_version())
    }

    fn read_only(&self, probe: &rdy_engine::probe::Probe) -> ReadOnlyClient {
        match self.dialed.get().and_then(Dialed::connected) {
            Some(connected) => connected.read_only(probe),
            None => ReadOnlyClient::unconnected(probe),
        }
    }

    fn read_only_as(
        &self,
        probe: &rdy_engine::probe::Probe,
        user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        match self.dialed.get().and_then(Dialed::connected) {
            Some(connected) => connected.read_only_as(probe, user),
            // No connection: the user cannot be used. A check that needs the cluster never runs here.
            None => Err(ImpersonationError::Conflict),
        }
    }

    /// Sorts an error with what the connection knows: the server, the credential plugin, whether a proxy
    /// is in the path and the CA setting, so the hint can name them.
    fn map_error(&self, error: &kube::Error) -> KubeError {
        match Dial::facts(self) {
            Some(facts) => from_kube_error(
                error,
                facts.line().server(),
                facts.line().plugin(),
                facts.proxy().is_proxied(),
                facts.ca_set(),
            ),
            None => from_kube_error(error, "the API server", None, false, false),
        }
    }
}

impl Family for K8sFamily {
    fn name(&self) -> &'static str {
        "k8s"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        registry::infos()
    }

    fn not_built(&self) -> &'static [&'static str] {
        &NOT_BUILT
    }

    fn probe<'a>(
        &'a self,
        ctx: FamilyProbe<'a>,
    ) -> BoxFuture<'a, Result<Vec<Capability>, FamilyFatal>> {
        Box::pin(self.holder.attempt(ctx))
    }

    fn probe_timed_out(&self) {
        // The future was dropped: the plugin, if any, is abandoned. What the config said is known.
        self.holder
            .settle(Dialed::timed_out(self.holder.remembered()));
    }

    fn kube_identity(&self, results: &[CheckResult]) -> Option<KubeIdentity> {
        let facts = Dial::facts(&*self.holder)?;
        let line = facts.line();
        let verified = results
            .iter()
            .find(|result| result.id == "k8s.access")
            .and_then(|result| result.observed.as_ref())
            .and_then(|observed| observed.get("identity"))
            .filter(|identity| identity["verified"] == true)
            .and_then(|identity| identity["username"].as_str())
            .map(str::to_owned);
        let mut kube = KubeIdentity::default();
        kube.context = Some(line.context().to_owned());
        kube.server = Some(line.server().to_owned());
        kube.user_verified = verified.is_some();
        kube.user = verified.or_else(|| line.user().map(str::to_owned));
        kube.exec_plugin = line
            .plugin()
            .filter(|name| is_plugin_name(name))
            .map(str::to_owned);
        kube.insecure_tls = line.tls_verification_off();
        Some(kube)
    }

    fn build(
        &self,
        _entry: &CheckSpec,
        params: CheckParams,
        _spec: &Spec,
    ) -> Result<Built, BuildError> {
        let holder = Arc::clone(&self.holder);
        match params {
            CheckParams::K8sVersion(params) => Ok(Built::new(Box::new(VersionCheck::new(
                params,
                holder as Arc<dyn Cluster>,
            )))),
            CheckParams::K8sAccess(params) => AccessCheck::new(&params, holder as Arc<dyn Dial>)
                .map(|check| Built::new(Box::new(check)).with_hosts(HostSet::empty()))
                .map_err(|_| {
                    BuildError::Unsupported(
                        "the `expect` pattern is not a valid pattern".to_owned(),
                    )
                }),
            _ => Err(BuildError::Unsupported(
                "not a k8s check this rdy can build".to_owned(),
            )),
        }
    }
}

/// The schema's rule for `identity.kube.exec_plugin`: one to 255 letters, digits, `.`, `_`, `+` or `-`.
fn is_plugin_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}
