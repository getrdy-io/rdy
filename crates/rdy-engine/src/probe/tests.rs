//! Tests for the probe facade: the read denylist, the action log and the per-check handle.
//!
//! The fixture run at the bottom is the exit test of M1-040.

use std::path::Path;
use std::sync::Arc;

use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::{Value, json};

use super::replay::Replay;
use super::sealed::Sealed;
use super::*;
use crate::check::{BoxFuture, CheckContext, CheckError, Os};
use crate::redact::TagKey;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([3; 32]))
}

fn hub(replay: Replay) -> ProbeHub {
    ProbeHub::new(Arc::new(replay), redactor())
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

#[test]
fn probe_errors_are_clone_eq_like_check_errors() {
    fn needs<T: Clone + PartialEq + Eq>() {}
    needs::<ProbeError>();
    needs::<CheckError>();
    let error = CheckError::from(ProbeError::NotFound);
    assert_eq!(error, error.clone());
    assert_eq!(error.skip_kind(), None);
}

// ---- the read denylist -------------------------------------------------------------------------

#[cfg(unix)]
mod denylist {
    use super::*;
    use crate::probe::policy::{
        RULE_DEVICE, RULE_DOT_DOT, RULE_KUBECONFIG, RULE_PRIVATE_KEY, RULE_PROC, RULE_RELATIVE,
        RULE_SSH, RULE_SYSTEM_SECRET, check_names,
    };

    fn verdict(path: &str) -> Result<(), &'static str> {
        check_names(Path::new(path), false)
    }

    #[test]
    fn the_listed_files_are_refused_with_their_rule() {
        let cases = [
            ("/etc/shadow", RULE_SYSTEM_SECRET),
            ("/etc/shadow-", RULE_SYSTEM_SECRET),
            ("/etc/gshadow", RULE_SYSTEM_SECRET),
            ("/etc/sudoers", RULE_SYSTEM_SECRET),
            ("/etc/sudoers.d/90-cloud-init", RULE_SYSTEM_SECRET),
            ("/home/ada/.ssh/id_ed25519", RULE_SSH),
            ("/home/ada/.ssh", RULE_SSH),
            ("/root/.kube/config", RULE_KUBECONFIG),
            ("/home/ada/.kube/cache/discovery/x.json", RULE_KUBECONFIG),
            ("/proc/1/environ", RULE_PROC),
            ("/proc/self/environ", RULE_PROC),
            ("/proc/1/cmdline", RULE_PROC),
            ("/proc/1/mem", RULE_PROC),
            ("/proc/1/fd", RULE_PROC),
            ("/proc/1/fd/3", RULE_PROC),
            ("/proc/1/root/etc/passwd", RULE_PROC),
            ("/proc/1/map_files/7f00-7f01", RULE_PROC),
            ("/proc/1/task/1/environ", RULE_PROC),
            ("/proc/kcore", RULE_PROC),
            ("/dev/mem", RULE_DEVICE),
            ("/dev/null", RULE_DEVICE),
            ("/dev", RULE_DEVICE),
            ("/etc/ssl/private/site.pem", RULE_PRIVATE_KEY),
            ("/etc/pki/tls/private/site.pem", RULE_PRIVATE_KEY),
            ("/srv/app/server.key", RULE_PRIVATE_KEY),
            ("/srv/app/SERVER.KEY", RULE_PRIVATE_KEY),
            ("/srv/app/store.p12", RULE_PRIVATE_KEY),
            ("/srv/app/id_rsa", RULE_PRIVATE_KEY),
            ("/etc/ssh/ssh_host_ed25519_key", RULE_PRIVATE_KEY),
        ];
        for (path, rule) in cases {
            assert_eq!(verdict(path), Err(rule), "{path}");
        }
    }

    #[test]
    fn spelling_tricks_do_not_get_past_the_list() {
        for path in [
            "/etc//shadow",
            "/etc/./shadow",
            "/etc/shadow/",
            "//etc/shadow",
            "/proc//1/./environ",
        ] {
            assert!(verdict(path).is_err(), "{path} was allowed");
        }
        assert_eq!(verdict("/tmp/../etc/shadow"), Err(RULE_DOT_DOT));
        assert_eq!(verdict("/proc/1/../1/status"), Err(RULE_DOT_DOT));
        assert_eq!(verdict("etc/passwd"), Err(RULE_RELATIVE));
        assert_eq!(verdict(""), Err(RULE_RELATIVE));
    }

    #[test]
    fn what_checks_need_is_not_refused() {
        for path in [
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/1/status",
            "/proc/self/mountinfo",
            "/proc/sys/kernel/osrelease",
            "/sys/fs/cgroup/cpu.max",
            "/etc/os-release",
            "/etc/passwd",
            "/etc/sudo.conf",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/openssl.cnf",
            "/etc/ssh/ssh_host_ed25519_key.pub",
            "/home/ada/id_rsa.pub",
            "/usr/share/ca-certificates/site.crt",
        ] {
            assert_eq!(verdict(path), Ok(()), "{path}");
        }
    }

    #[test]
    fn macos_ignores_case_and_the_private_prefix() {
        let mac = |path: &str| check_names(Path::new(path), true);
        assert_eq!(mac("/ETC/Shadow"), Err(RULE_SYSTEM_SECRET));
        assert_eq!(mac("/private/etc/sudoers"), Err(RULE_SYSTEM_SECRET));
        assert_eq!(mac("/Users/ada/.SSH/id_rsa"), Err(RULE_SSH));
        // On a case-sensitive file system these are other files.
        assert_eq!(verdict("/ETC/Shadow"), Ok(()));
        assert_eq!(verdict("/private/etc/sudoers"), Ok(()));
    }

    #[tokio::test]
    async fn a_denied_read_never_reaches_the_backend_and_is_logged() {
        // The fixture holds the file, so a read that got through would succeed.
        let replay = Replay::new()
            .file("/proc/1/environ", "AWS_SECRET_ACCESS_KEY=xyz")
            .file("/etc/shadow", "root:$6$salt$hash::");
        let hub = hub(replay);
        let probe = hub.check_probe("host.cpu");

        let error = probe
            .read(Path::new("/proc/1/environ"))
            .await
            .expect_err("refused");
        assert_eq!(
            error,
            ProbeError::Denied {
                rule: policy::RULE_PROC,
                what: "/proc/1/environ".to_owned()
            }
        );
        assert!(probe.read_dir(Path::new("/proc/1/fd")).await.is_err());
        assert!(probe.stat(Path::new("/etc/shadow")).await.is_err());

        let log = hub.action_log();
        let kinds: Vec<_> = log.actions.iter().map(|a| a.kind.to_string()).collect();
        assert_eq!(kinds, ["read", "read_dir", "stat"]);
        for action in &log.actions {
            assert_eq!(action.outcome, ActionOutcome::Denied);
            assert_eq!(action.check.as_deref(), Some("host.cpu"));
            assert!(field(action, "rule").and_then(Value::as_str).is_some());
        }
        let first = &log.actions[0];
        assert_eq!(field(first, "path"), Some(&json!("/proc/1/environ")));
        assert!(field(first, "bytes").is_none(), "no bytes were read");
    }

    #[tokio::test]
    async fn reads_show_home_paths_with_a_tilde() {
        let hub = hub(Replay::new().file("/home/tester/notes.txt", "hi")).with_home("/home/tester");
        let probe = hub.check_probe("host.cpu");
        probe
            .read(Path::new("/home/tester/notes.txt"))
            .await
            .expect("read");
        let log = hub.action_log();
        assert_eq!(field(&log.actions[0], "path"), Some(&json!("~/notes.txt")));
    }

    #[tokio::test]
    async fn read_dir_stat_and_missing_files_are_recorded() {
        let replay = Replay::new().file("/proc/cpuinfo", "processor : 0\n").dir(
            "/sys/class/net",
            vec![DirEntry::new("eth0", true), DirEntry::new("lo", true)],
        );
        let hub = hub(replay);
        let probe = hub.check_probe("host.cpu");

        assert_eq!(
            probe
                .read(Path::new("/proc/cpuinfo"))
                .await
                .expect("read")
                .bytes,
            b"processor : 0\n"
        );
        assert_eq!(
            probe
                .read_dir(Path::new("/sys/class/net"))
                .await
                .expect("dir")
                .len(),
            2
        );
        assert!(
            probe
                .stat(Path::new("/proc/cpuinfo"))
                .await
                .expect("stat")
                .is_some_and(|m| m.is_file && m.len == 14)
        );
        assert_eq!(probe.stat(Path::new("/nope")).await, Ok(None));
        assert_eq!(
            probe.read(Path::new("/nope")).await,
            Err(ProbeError::NotFound)
        );

        let log = hub.action_log();
        let seen: Vec<_> = log
            .actions
            .iter()
            .map(|a| (a.kind.to_string(), a.outcome.to_string()))
            .collect();
        assert_eq!(
            seen,
            [
                ("read", "ok"),
                ("read_dir", "ok"),
                ("stat", "ok"),
                ("stat", "ok"),
                ("read", "failed")
            ]
            .map(|(k, o)| (k.to_owned(), o.to_owned()))
        );
        assert_eq!(field(&log.actions[0], "bytes"), Some(&json!(14)));
        assert_eq!(field(&log.actions[0], "truncated"), Some(&json!(false)));
        assert_eq!(field(&log.actions[1], "entries"), Some(&json!(2)));
        assert!(field(&log.actions[4], "error").is_some());
        let seqs: Vec<u64> = log.actions.iter().map(|a| a.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
    }
}

#[cfg(windows)]
#[tokio::test]
async fn windows_refuses_every_file_read() {
    let hub = hub(Replay::new().file("C:\\x", "y"));
    let probe = hub.check_probe("host.cpu");
    let error = probe.read(Path::new("C:\\x")).await.expect_err("refused");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: policy::RULE_WINDOWS,
            ..
        }
    ));
}

// ---- exec --------------------------------------------------------------------------------------

#[tokio::test]
async fn a_command_is_logged_with_its_path_argv_and_exit() {
    let hub = hub(Replay::new().command("ip", &["-j", "addr"], 0, "[]"));
    let probe = hub.check_probe("net.mtu");
    let output = probe
        .exec(Cmd::new("ip").args(["-j", "addr"]))
        .await
        .expect("ran");
    assert_eq!(output.exit, Some(0));
    assert_eq!(output.stdout, b"[]");

    let missing = probe.exec(Cmd::new("ss").args(["-lnt"])).await;
    assert_eq!(missing, Err(ProbeError::NotFound));

    let log = hub.action_log();
    let ok = &log.actions[0];
    assert_eq!(ok.kind, ActionKind::Exec);
    assert_eq!(ok.outcome, ActionOutcome::Ok);
    assert_eq!(field(ok, "program"), Some(&json!("/usr/bin/ip")));
    assert_eq!(field(ok, "argv"), Some(&json!(["-j", "addr"])));
    assert_eq!(field(ok, "exit"), Some(&json!(0)));
    assert_eq!(field(ok, "stdout_bytes"), Some(&json!(2)));
    let failed = &log.actions[1];
    assert_eq!(failed.outcome, ActionOutcome::Failed);
    assert_eq!(field(failed, "program"), Some(&json!("ss")));
}

// ---- the handle's life -------------------------------------------------------------------------

#[tokio::test]
async fn a_closed_probe_refuses_everything() {
    let probe = Probe::closed();
    let error = probe.exec(Cmd::new("ip")).await.expect_err("refused");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: RULE_NO_PROBE,
            ..
        }
    ));
    // A bare context, as the existing tests build, has this probe.
    let ctx = CheckContext::new("fake.plain", Os::Linux, []);
    assert!(ctx.probe().stat(Path::new("/proc")).await.is_err());
}

#[tokio::test]
async fn a_call_after_the_check_ended_is_denied_and_logged() {
    let hub = hub(Replay::new().file("/proc/cpuinfo", "x"));
    let probe = hub.check_probe("host.cpu");
    let straggler = probe.clone();
    probe
        .read(Path::new("/proc/cpuinfo"))
        .await
        .expect("before the end");
    probe.end();

    let error = straggler
        .read(Path::new("/proc/cpuinfo"))
        .await
        .expect_err("after the end");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: RULE_CHECK_FINISHED,
            ..
        }
    ));
    assert!(probe.exec(Cmd::new("ip")).await.is_err());
    assert!(probe.begin(ActionKind::Connect, Map::new(), "h").is_err());

    let log = hub.action_log();
    assert_eq!(log.actions.len(), 4);
    let late = &log.actions[1];
    assert_eq!(late.outcome, ActionOutcome::Denied);
    assert_eq!(late.check.as_deref(), Some("host.cpu"));
    assert_eq!(field(late, "rule"), Some(&json!(RULE_CHECK_FINISHED)));
    assert_eq!(field(late, "path"), Some(&json!("/proc/cpuinfo")));
}

/// A backend whose calls never finish, to stand in for a check that the scheduler aborts.
struct Hanging;

impl Sealed for Hanging {}

impl Backend for Hanging {
    fn open_read<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, io::Result<FileBytes>> {
        Box::pin(std::future::pending())
    }
    fn read_dir<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        Box::pin(std::future::pending())
    }
    fn stat<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
        Box::pin(std::future::pending())
    }
    fn spawn<'a>(&'a self, _: &'a Cmd) -> BoxFuture<'a, Result<Executed, ProbeError>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn a_call_dropped_before_it_finished_is_logged_as_a_timeout() {
    let hub = ProbeHub::new(Arc::new(Hanging), redactor());
    let probe = hub.check_probe("net.dns");
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        probe.exec(Cmd::new("dig").args(["example.com"])),
    )
    .await;
    assert!(outcome.is_err(), "the call hangs");

    let log = hub.action_log();
    assert_eq!(log.actions.len(), 1);
    assert_eq!(log.actions[0].outcome, ActionOutcome::Timeout);
    assert_eq!(field(&log.actions[0], "program"), Some(&json!("dig")));
}

// ---- retention ---------------------------------------------------------------------------------

/// Writes one entry of `kind` with `outcome` straight into the log, as a facade method would.
fn put(probe: &Probe, kind: ActionKind, outcome: ActionOutcome) {
    let (_, entry) = probe
        .begin(kind, Map::new(), "fixture")
        .expect("probe is live");
    entry.finish(outcome);
}

fn is_droppable_kind(kind: &str) -> bool {
    matches!(kind, "read" | "read_dir" | "stat")
}

#[test]
fn truncation_drops_only_ok_read_read_dir_and_stat() {
    let hub = hub(Replay::new()).with_max_entries(20);
    let probe = hub.check_probe("fixture.flood");
    let keep = [
        (ActionKind::Exec, ActionOutcome::Ok),
        (ActionKind::Connect, ActionOutcome::Ok),
        (ActionKind::Connect, ActionOutcome::Failed),
        (ActionKind::Tls, ActionOutcome::Ok),
        (ActionKind::Http, ActionOutcome::Timeout),
        (ActionKind::Kube, ActionOutcome::Ok),
        (ActionKind::Lookup, ActionOutcome::Ok),
        (ActionKind::Native, ActionOutcome::Ok),
        (ActionKind::Read, ActionOutcome::Denied),
        (ActionKind::Read, ActionOutcome::Failed),
        (ActionKind::Stat, ActionOutcome::Failed),
        (ActionKind::ReadDir, ActionOutcome::Timeout),
    ];
    // A flood of droppable entries first, then the entries that must survive, then more flood.
    for _ in 0..20 {
        put(&probe, ActionKind::Read, ActionOutcome::Ok);
        put(&probe, ActionKind::ReadDir, ActionOutcome::Ok);
        put(&probe, ActionKind::Stat, ActionOutcome::Ok);
    }
    for (kind, outcome) in keep.clone() {
        put(&probe, kind, outcome);
    }
    for _ in 0..20 {
        put(&probe, ActionKind::Read, ActionOutcome::Ok);
    }

    let log = hub.action_log();
    let kept: Vec<(ActionKind, ActionOutcome)> = log
        .actions
        .iter()
        .filter(|a| !(is_droppable_kind(a.kind.as_str()) && a.outcome == ActionOutcome::Ok))
        .map(|a| (a.kind.clone(), a.outcome.clone()))
        .collect();
    // Every entry that may not be dropped is still there, in order.
    assert_eq!(kept, keep.to_vec());

    assert!(log.truncated);
    assert!(!log.dropped.is_empty());
    for kind in log.dropped.keys() {
        assert!(is_droppable_kind(kind), "dropped a {kind} entry");
    }
    assert_eq!(log.actions.len(), 20, "the log holds exactly its cap");
    // Every dropped entry is a gap in seq: 92 entries were made, 20 are left.
    let total_dropped: u64 = log.dropped.values().sum();
    assert_eq!(total_dropped + 20, 60 + 12 + 20);
    let seqs: Vec<u64> = log.actions.iter().map(|a| a.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn a_full_log_with_nothing_droppable_keeps_its_bound_and_counts_the_loss() {
    let hub = hub(Replay::new()).with_max_entries(2);
    let probe = hub.check_probe("fixture.flood");
    for _ in 0..3 {
        put(&probe, ActionKind::Connect, ActionOutcome::Ok);
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 2);
    assert!(log.truncated);
    assert_eq!(log.dropped.get("connect"), Some(&1));
}

// ---- the fixture run, through the scheduler -------------------------------------------------------

#[cfg(feature = "runtime")]
mod scheduled {
    use std::sync::Mutex;

    use rdy_spec::result::Report;

    use super::*;
    use crate::check::{Check, CheckContext, CheckInfo, CheckOutcome, Finding};
    use crate::check::{Need, Os, OsSupport, Support};
    use crate::sched::{End, Planned, Scheduler};

    static WALKER: CheckInfo = CheckInfo {
        id: "fixture.walker",
        family: "fixture",
        summary: "Reads, runs, connects and calls the cluster, then leaks its probe.",
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OsSupport {
            linux: Support::Full,
            macos: Support::Full,
            windows: Support::Full,
        },
        reads: &[],
        env: &[],
        commands: &[],
        peers: &[],
    };

    /// A check that does every kind of side effect and keeps a clone of its probe.
    struct Walker {
        leaked: Arc<Mutex<Option<Probe>>>,
    }

    impl Check for Walker {
        fn info(&self) -> &'static CheckInfo {
            &WALKER
        }

        fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
            Box::pin(async move {
                let probe = ctx.probe();
                *self.leaked.lock().expect("lock") = Some(probe.clone());

                probe.read(Path::new("/proc/cpuinfo")).await?;
                let refused = probe.read(Path::new("/proc/1/environ")).await;
                assert!(matches!(refused, Err(ProbeError::Denied { .. })));
                probe
                    .exec(Cmd::new("ip").args(["--password=hunter2hunter2", "addr"]))
                    .await?;

                // The network and kube tickets open their entries through the same door.
                let (_, mut connect) =
                    probe.begin(ActionKind::Connect, Map::new(), "registry.acme.example")?;
                connect.set("host", "registry.acme.example");
                connect.set("port", 443);
                connect.set("addr", Value::Null);
                connect.set("via_proxy", Value::Null);
                connect.finish(ActionOutcome::Ok);
                let (_, mut kube) = probe.begin(ActionKind::Kube, Map::new(), "/version")?;
                kube.set("method", "GET");
                kube.set("path", "/version");
                kube.set("status", 200);
                kube.finish(ActionOutcome::Ok);

                Ok(Finding::pass("walked"))
            })
        }
    }

    /// The first `json` block of the `### 7.2` example in 01, the report of a run.
    fn sample_report() -> Report {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let doc = std::fs::read_to_string(root.join("docs/plan/01-spec-format.md"))
            .expect("01 is in the repo")
            .replace("\r\n", "\n");
        let start = doc.find("\n### 7.2 ").expect("section 7.2");
        let section = &doc[start + 1..];
        let open = section.find("```json\n").expect("json block") + "```json\n".len();
        let body = &section[open..];
        let close = body.find("\n```").expect("end of block");
        serde_json::from_str(&body[..close]).expect("the sample is a report")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_fixture_run_lists_every_side_effect_in_the_json_report() {
        let leaked = Arc::new(Mutex::new(None));
        let replay = Replay::new()
            .file("/proc/cpuinfo", "processor : 0\n")
            // The fixture has the file. Only the denylist stands between the check and it.
            .file("/proc/1/environ", "TOKEN=abc")
            .command("ip", &["--password=hunter2hunter2", "addr"], 0, "[]");
        let hub = hub(replay).with_home("/home/tester");

        // Run-level work: the engine reads the kubeconfig itself and logs it with `check: null`.
        let run = hub.run_probe();
        let (_, mut kubeconfig) = run
            .begin(ActionKind::Read, Map::new(), "~/.kube/config")
            .expect("run probe");
        kubeconfig.set("path", "~/.kube/config");
        kubeconfig.set("bytes", 5412);
        kubeconfig.set("truncated", false);
        kubeconfig.finish(ActionOutcome::Ok);

        let scheduler = Scheduler::new(2, Os::Linux, [Need::Network]).with_probes(hub.clone());
        let walker = Walker {
            leaked: Arc::clone(&leaked),
        };
        let ran = scheduler
            .run(vec![Planned::new(Arc::new(walker), "host.cpu")])
            .await;
        assert!(
            matches!(&ran[0].end, End::Done(outcome) if outcome.is_ok()),
            "{:?}",
            ran[0].end
        );

        // The check is over. A call from a clone of its probe is denied and logged.
        let straggler = leaked.lock().expect("lock").take().expect("leaked probe");
        let late = straggler.read(Path::new("/proc/cpuinfo")).await;
        assert!(matches!(
            late,
            Err(ProbeError::Denied {
                rule: RULE_CHECK_FINISHED,
                ..
            })
        ));

        // The report is the 7.2 sample with the fixture run's log put in.
        let mut report = sample_report();
        assert_eq!(report.redaction.total, 0);
        hub.action_log().apply(&mut report);
        let json = serde_json::to_value(&report).expect("report");
        let text = serde_json::to_string(&json).expect("text");

        let actions = json["actions"].as_array().expect("actions");
        let seen: Vec<(Option<&str>, &str, &str)> = actions
            .iter()
            .map(|a| {
                (
                    a["check"].as_str(),
                    a["kind"].as_str().expect("kind"),
                    a["outcome"].as_str().expect("outcome"),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (None, "read", "ok"),
                (Some("host.cpu"), "read", "ok"),
                (Some("host.cpu"), "read", "denied"),
                (Some("host.cpu"), "exec", "ok"),
                (Some("host.cpu"), "connect", "ok"),
                (Some("host.cpu"), "kube", "ok"),
                (Some("host.cpu"), "read", "denied"),
            ]
        );
        // seq runs from 1 and the entries sit in seq order.
        let seqs: Vec<u64> = actions.iter().filter_map(|a| a["seq"].as_u64()).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5, 6, 7]);

        // A command: the resolved path and argv, with the secret already gone.
        assert_eq!(actions[3]["program"], "/usr/bin/ip");
        let argv = actions[3]["argv"].as_array().expect("argv");
        assert!(
            argv[0]
                .as_str()
                .is_some_and(|a| a.starts_with("--password=[REDACTED:secret_by_key:"))
        );
        assert!(!text.contains("hunter2"), "a secret reached the report");
        // A file, and the refused read of /proc/1/environ with its rule.
        assert_eq!(actions[1]["path"], "/proc/cpuinfo");
        assert_eq!(actions[2]["path"], "/proc/1/environ");
        assert_eq!(actions[2]["rule"], policy::RULE_PROC);
        assert!(actions[2].get("bytes").is_none());
        // An endpoint and a kube request.
        assert_eq!(actions[4]["host"], "registry.acme.example");
        assert_eq!(actions[4]["port"], 443);
        assert_eq!(actions[5]["path"], "/version");
        // The late call names the check and the rule.
        assert_eq!(actions[6]["rule"], RULE_CHECK_FINISHED);

        // Identity is the report's own, and the redaction count includes what the log redacted.
        assert!(json["identity"]["euid"].is_number());
        assert_eq!(json["redaction"]["total"], 1);
        assert_eq!(json["redaction"]["by_rule"]["secret_by_key"], 1);
        assert_eq!(json["actions_truncated"], false);

        // It is still a report.
        let again: Report = serde_json::from_value(json).expect("round trip");
        assert_eq!(again.actions.len(), 7);
        assert_eq!(hub.action_log().actions.len(), 7);
    }

    #[tokio::test(start_paused = true)]
    async fn the_scheduler_ends_the_probe_when_the_check_times_out() {
        /// Hands its probe out, then waits forever.
        struct Sleeper {
            leaked: Arc<Mutex<Option<Probe>>>,
        }
        impl Check for Sleeper {
            fn info(&self) -> &'static CheckInfo {
                &WALKER
            }
            fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
                Box::pin(async move {
                    *self.leaked.lock().expect("lock") = Some(ctx.probe().clone());
                    std::future::pending::<CheckOutcome>().await
                })
            }
        }
        let leaked = Arc::new(Mutex::new(None));
        let hub = hub(Replay::new().file("/proc/cpuinfo", "x"));
        let scheduler = Scheduler::new(1, Os::Linux, []).with_probes(hub.clone());
        let planned = Planned::new(
            Arc::new(Sleeper {
                leaked: Arc::clone(&leaked),
            }),
            "fixture.walker",
        )
        .with_timeout(Duration::from_secs(1));
        let ran = scheduler.run(vec![planned]).await;
        assert!(matches!(ran[0].end, End::TimedOut { .. }));

        let probe = leaked.lock().expect("lock").take().expect("leaked");
        let error = probe
            .stat(Path::new("/proc/cpuinfo"))
            .await
            .expect_err("ended");
        assert!(matches!(
            error,
            ProbeError::Denied {
                rule: RULE_CHECK_FINISHED,
                ..
            }
        ));
    }
}

#[test]
fn the_log_survives_a_poisoned_lock() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("fixture.walker");
    hub.log.poison();
    put(&probe, ActionKind::Exec, ActionOutcome::Ok);
    assert_eq!(hub.action_log().actions.len(), 1);
}
