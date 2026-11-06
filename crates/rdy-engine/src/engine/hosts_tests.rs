//! A real run gives each check's probe the hosts its own entry lists (M1-095, INV-11).
//!
//! Two `net.egress` entries list one host each. Each check tries both. The host of its own entry
//! connects, the other host is denied by rule, and the action log shows both. A run with `network:
//! false` skips the entries as `missing_need` and makes no socket call.

use std::sync::{Arc, Mutex};

use rdy_spec::Target;
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome, SkipKind, Status};
use rdy_spec::sig::{Policy, TrustStore};
use rdy_spec::spec::{CheckSpec, Spec};

use super::*;
use crate::check::{
    BoxFuture, Check, CheckContext, CheckMeta, CheckOutcome, OsSupport, PeerClass, Support,
};
use crate::family::{BuildError, Built, Family, HostSet};
use crate::privilege::{Elevation, ProcessIds};
use crate::probe::ProbeError;
use crate::probe::net::{RULE_TCP_HOST, Route};
use crate::redact::{Redactor, TagKey};
use crate::testing::{Replay, TcpScript};

static DIALER: CheckInfo = CheckInfo {
    id: "net.egress",
    family: "net",
    summary: "A fake check that dials the hosts it is told to.",
    meta: CheckMeta {
        title: "Dialer",
        remediation: "Nothing to fix. A test double.",
    },
    needs: &[Need::Network],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[PeerClass::SpecHosts],
};

/// What each dialer saw: `(own host -> tried host, what happened)`.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

struct Dialer {
    own: String,
    seen: Seen,
}

impl Check for Dialer {
    fn info(&self) -> &'static CheckInfo {
        &DIALER
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            for text in ["a.acme.test:443", "b.acme.test:443"] {
                let target = Target::parse(text).expect("a target");
                let saw = match ctx.probe().tcp(&target, Route::Direct).await {
                    Ok(report) if report.connected => "connected".to_owned(),
                    Ok(_) => "not connected".to_owned(),
                    Err(ProbeError::Denied { rule, .. }) => rule.to_owned(),
                    Err(other) => format!("error: {other}"),
                };
                let key = format!("{} -> {}", self.own, target.host());
                self.seen.lock().expect("lock").push((key, saw));
            }
            Ok(Finding::pass("dialed"))
        })
    }
}

struct Net {
    seen: Seen,
}

impl Family for Net {
    fn name(&self) -> &'static str {
        "net"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        static ALL: [&CheckInfo; 1] = [&DIALER];
        &ALL
    }

    fn build(&self, _: &CheckSpec, params: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        let CheckParams::NetEgress(egress) = params else {
            return Err(BuildError::Unsupported("not net.egress".to_owned()));
        };
        let own: Vec<Target> = egress.endpoints.iter().map(|e| e.target.clone()).collect();
        let name = own
            .first()
            .map(|t| t.host().to_string())
            .unwrap_or_default();
        let check = Dialer {
            own: name,
            seen: Arc::clone(&self.seen),
        };
        Ok(Built::new(Box::new(check)).with_hosts(HostSet::new(own)))
    }
}

const SPEC: &str = "\
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme
checks:
  - id: net.egress
    endpoints: [\"a.acme.test:443\"]
  - id: net.egress
    name: other
    endpoints: [\"b.acme.test:443\"]
";

fn loaded() -> LoadedSpec {
    rdy_spec::load(
        SPEC.as_bytes(),
        None,
        &TrustStore::new(),
        Policy::AllowUnsigned,
    )
    .expect("the spec loads")
}

fn privilege() -> Privilege {
    Privilege {
        ids: Some(ProcessIds::new([1000; 4], [1000; 4])),
        cap_eff: 0,
        cap_prm: 0,
        cap_amb: 0,
        at_secure: false,
        elevation: Elevation::NotElevated,
    }
}

fn engine(replay: Replay, seen: &Seen) -> (Engine, ProbeHub) {
    let mut registry = Registry::new();
    registry
        .register(Net {
            seen: Arc::clone(seen),
        })
        .expect("registers");
    let hub = ProbeHub::new(Arc::new(replay), Redactor::new(TagKey::fixed([7; 32])));
    (Engine::new(registry, hub.clone()), hub)
}

#[tokio::test(start_paused = true)]
async fn a_real_run_gives_each_entry_its_own_hosts_and_denies_the_others() {
    let web = TcpScript::Serve("web".to_owned());
    let replay = Replay::new()
        .host("a.acme.test", ["192.0.2.1".parse().expect("ip")])
        .host("b.acme.test", ["192.0.2.2".parse().expect("ip")])
        .tcp("192.0.2.1:443".parse().expect("addr"), web.clone())
        .tcp("192.0.2.2:443".parse().expect("addr"), web)
        .serve_duplex("web", |_server| async {});
    let seen: Seen = Arc::default();
    let (engine, hub) = engine(replay, &seen);
    let spec = loaded();
    let plan = engine.plan(&spec, Os::Linux, "0.1.0");
    let done = engine
        .execute(&spec, plan, &privilege(), &RunOptions::default())
        .await;
    assert!(
        done.results.iter().all(|r| r.status == Status::Pass),
        "{:?}",
        done.results
    );

    let mut seen = seen.lock().expect("lock").clone();
    seen.sort();
    let want = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    assert_eq!(
        seen,
        vec![
            want("a.acme.test -> a.acme.test", "connected"),
            want("a.acme.test -> b.acme.test", RULE_TCP_HOST),
            want("b.acme.test -> a.acme.test", RULE_TCP_HOST),
            want("b.acme.test -> b.acme.test", "connected"),
        ]
    );
    let log = hub.action_log();
    let connects: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Connect)
        .collect();
    assert_eq!(connects.len(), 4);
    let denied = connects
        .iter()
        .filter(|a| a.outcome == ActionOutcome::Denied)
        .count();
    assert_eq!(denied, 2, "the other entry's host is denied and logged");
}

#[tokio::test(start_paused = true)]
async fn a_run_without_network_skips_the_check_as_a_missing_need() {
    let seen: Seen = Arc::default();
    let (engine, hub) = engine(Replay::new(), &seen);
    let spec = loaded();
    let plan = engine.plan(&spec, Os::Linux, "0.1.0");
    let options = RunOptions {
        network: false,
        ..RunOptions::default()
    };
    let done = engine.execute(&spec, plan, &privilege(), &options).await;
    assert_eq!(done.results.len(), 2);
    for result in &done.results {
        assert_eq!(result.status, Status::Skipped, "{result:?}");
        assert_eq!(result.skip_kind, Some(SkipKind::MissingNeed));
    }
    assert!(seen.lock().expect("lock").is_empty(), "the check never ran");
    let log = hub.action_log();
    assert!(
        log.actions.iter().all(|a| a.kind != ActionKind::Connect),
        "no connect entry"
    );
}
