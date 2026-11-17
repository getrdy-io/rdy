//! The family probe hook of the engine (M1-107): when it is called, what it is given, what it can end.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rdy_spec::check::CheckParams;
use rdy_spec::result::{Capability, CheckResult, KubeIdentity, Need as WireNeed, SkipKind, Status};
use rdy_spec::spec::{CheckSpec, Spec};

use super::tests::{
    Counting, CountingFamily, KUBE_CHECK, KUBE_CHECKS, NET_CHECKS, find, loaded, privilege,
};
use super::*;
use crate::check::{BoxFuture, CheckInfo, Need, Os};
use crate::family::{BuildError, Built, FAMILY_PROBE_LIMIT, Family, FamilyFatal, FamilyProbe};
use crate::probe::ProbeHub;
use crate::redact::{Redactor, TagKey};
use crate::testing::Replay;

/// How the stand-in `k8s` family's probe ends.
#[derive(Clone, Copy)]
enum Probing {
    /// `kube_context` is available.
    Met,
    /// The probe never ends, as a credential plugin that waits for a login.
    Never,
    /// The probe refuses to go on.
    Fatal,
}

/// A `k8s` family whose probe is scripted, and which counts what the engine asks of it.
struct ProbingFamily {
    how: Probing,
    probed: Arc<AtomicUsize>,
    timed_out: Arc<AtomicUsize>,
    given: Arc<Mutex<Vec<String>>>,
}

impl ProbingFamily {
    fn new(how: Probing) -> Self {
        Self {
            how,
            probed: Arc::default(),
            timed_out: Arc::default(),
            given: Arc::default(),
        }
    }
}

impl Family for ProbingFamily {
    fn name(&self) -> &'static str {
        "k8s"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &KUBE_CHECKS
    }

    fn probe<'a>(
        &'a self,
        ctx: FamilyProbe<'a>,
    ) -> BoxFuture<'a, Result<Vec<Capability>, FamilyFatal>> {
        Box::pin(async move {
            self.probed.fetch_add(1, Ordering::SeqCst);
            (ctx.announce)("acme-prod, https://k8s.acme.example:6443");
            self.given.lock().expect("lock").push(format!(
                "{:?} {:?} {}",
                ctx.kubeconfig.map(|path| path.to_string_lossy().into_owned()),
                ctx.kube_context,
                ctx.checks.len()
            ));
            match self.how {
                Probing::Met => Ok(vec![Capability::new(Need::KubeContext.wire(), true)]),
                Probing::Never => std::future::pending().await,
                Probing::Fatal => Err(FamilyFatal::new("stop", "fix it")),
            }
        })
    }

    fn probe_timed_out(&self) {
        self.timed_out.fetch_add(1, Ordering::SeqCst);
    }

    fn kube_identity(&self, _: &[CheckResult]) -> Option<KubeIdentity> {
        let mut kube = KubeIdentity::default();
        kube.context = Some("acme-prod".to_owned());
        Some(kube)
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Counting(&KUBE_CHECK))))
    }
}

const KUBE_SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: k8s.version\n    min: \"1.28\"\n";
const NET_ONLY_SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: net.egress\n    endpoints: [\"registry.acme.example:443\"]\n";

async fn run_probing(
    family: ProbingFamily,
    text: &str,
    configure: impl FnOnce(&mut RunOptions),
) -> Executed {
    let mut registry = Registry::new();
    registry
        .register(CountingFamily("net", &NET_CHECKS))
        .expect("registers");
    registry.register(family).expect("registers");
    let hub = ProbeHub::new(
        Arc::new(Replay::new()),
        Redactor::new(TagKey::fixed([7; 32])),
    );
    let engine = Engine::new(registry, hub);
    let spec = loaded(text);
    let plan = engine.plan(&spec, Os::Linux, "0.1.0");
    let mut options = RunOptions::new();
    configure(&mut options);
    engine
        .execute(&spec, plan, &privilege(false), &options)
        .await
}

#[tokio::test(start_paused = true)]
async fn a_spec_with_no_check_of_a_family_never_calls_its_probe() {
    let family = ProbingFamily::new(Probing::Met);
    let probed = Arc::clone(&family.probed);
    let done = run_probing(family, NET_ONLY_SPEC, |_| {}).await;
    assert_eq!(probed.load(Ordering::SeqCst), 0);
    assert!(done.kube.is_none());
    assert!(done.fatal.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_family_probe_runs_once_gets_the_flags_and_can_announce_and_its_capability_opens_the_gate()
 {
    let family = ProbingFamily::new(Probing::Met);
    let (probed, given) = (Arc::clone(&family.probed), Arc::clone(&family.given));
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let done = run_probing(family, KUBE_SPEC, |options| {
        options.kubeconfig = Some("/work/kubeconfig".into());
        options.kube_context = Some("acme-prod".to_owned());
        options.announce = Some(Announce::new(move |line| {
            sink.lock().expect("lock").push(line.to_owned());
        }));
    })
    .await;
    assert_eq!(probed.load(Ordering::SeqCst), 1);
    assert_eq!(
        *given.lock().expect("lock"),
        [r#"Some("/work/kubeconfig") Some("acme-prod") 1"#]
    );
    assert_eq!(
        *lines.lock().expect("lock"),
        ["acme-prod, https://k8s.acme.example:6443"]
    );
    assert_eq!(find(&done, "k8s.version").status, Status::Pass);
    assert!(
        done.capabilities
            .iter()
            .any(|cap| cap.need == WireNeed::KubeContext && cap.available)
    );
    assert_eq!(
        done.kube.and_then(|kube| kube.context).as_deref(),
        Some("acme-prod")
    );
}

#[tokio::test(start_paused = true)]
async fn a_probe_that_does_not_end_is_cut_at_the_limit_and_the_check_is_skipped() {
    let family = ProbingFamily::new(Probing::Never);
    let timed_out = Arc::clone(&family.timed_out);
    let started = tokio::time::Instant::now();
    let done = run_probing(family, KUBE_SPEC, |_| {}).await;
    // Virtual time: the limit passed, and the run went on.
    assert!(started.elapsed() >= FAMILY_PROBE_LIMIT);
    assert!(started.elapsed() < FAMILY_PROBE_LIMIT + Duration::from_secs(1));
    assert_eq!(timed_out.load(Ordering::SeqCst), 1);
    let result = find(&done, "k8s.version");
    assert_eq!(result.status, Status::Skipped);
    assert_eq!(result.skip_kind, Some(SkipKind::MissingNeed));
    let cap = done
        .capabilities
        .iter()
        .find(|cap| cap.need == WireNeed::KubeContext)
        .expect("the kube_context capability");
    assert!(!cap.available);
    assert!(
        cap.hint
            .as_deref()
            .is_some_and(|hint| hint.contains("login"))
    );
}

#[tokio::test(start_paused = true)]
async fn a_fatal_probe_runs_no_check_and_the_entries_are_not_finished() {
    let family = ProbingFamily::new(Probing::Fatal);
    let done = run_probing(family, KUBE_SPEC, |_| {}).await;
    let fatal = done.fatal.clone().expect("the run ended");
    assert_eq!(
        (fatal.message.as_str(), fatal.hint.as_str()),
        ("stop", "fix it")
    );
    assert_eq!(find(&done, "k8s.version").status, Status::Error);
    assert!(done.kube.is_none());
}
