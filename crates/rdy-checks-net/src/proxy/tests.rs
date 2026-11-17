//! Tests of `net.proxy` against the synthetic machines under `tests/fixtures/checks/net.proxy/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`reads`, `env`, `peers`) and the action log are the ones a run has. The run reads
//! the proxy from the machine's environment as `rdy run` does (`TestRun::with_proxy_from_env`). The proxy
//! URL of most cases carries a planted password, and every case checks that no planted secret reaches the
//! finding, the serialised result or the action log.

use std::sync::Arc;

use rdy_engine::check::{CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

/// The planted secrets of the fixtures. None may reach any output.
const CANARIES: &[&str] = &[
    "longer-canary-pw",
    "bG9uZ2VyLWNhbmFyeS1wdw",
    "svc:longer",
    "daemon-canary-pw",
    "AUTHS-CANARY-PW",
    "YWNtZTpBVVRIUy1DQU5BUlktUFc",
    "PAC-USERINFO-CANARY",
    "PAC-QUERY-CANARY",
    "SOCKS-CANARY-PW",
];

fn plain() -> Value {
    json!({"id": "net.proxy"})
}

fn required() -> Value {
    json!({
        "id": "net.proxy",
        "required_no_proxy": [".svc", ".cluster.local", "10.0.0.0/8", "172.16.0.0/12"]
    })
}

/// Every case with the spec entry its golden is made from.
fn cases() -> Vec<(&'static str, Value)> {
    vec![
        ("no-proxy", plain()),
        ("shell-proxy-no-docker-dropin", plain()),
        ("docker-dropin-ok", plain()),
        ("daemon-json-proxy", plain()),
        ("no-proxy-covered", required()),
        ("no-proxy-gap", required()),
        ("pac-auto-proxy", plain()),
        ("proxy-refused", plain()),
        ("proxy-blackhole", plain()),
        ("env-conflict", plain()),
        ("socks-all-proxy", plain()),
        ("environment-file", plain()),
        ("dropin-reset", plain()),
        ("no-network", plain()),
        ("macos-env-only", plain()),
        ("unreadable-dropins", plain()),
    ]
}

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/net.proxy/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("net.proxy").expect("it answers");
    fixture
}

fn check(entry: &Value) -> ProxyCheck {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::NetProxy(params) => ProxyCheck::from_params(&params),
        other => panic!("not net.proxy: {other:?}"),
    }
}

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
}

impl Run {
    fn outcome(&self) -> &CheckOutcome {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done
    }

    fn finding(&self) -> &Finding {
        match self.outcome() {
            Ok(finding) => finding,
            Err(error) => panic!("no finding: {error}"),
        }
    }

    /// Every string the run could show: the finding, the rendered result and the action log.
    fn everything(&self) -> String {
        format!(
            "{} {}",
            serde_json::to_string(&render(&self.end)).expect("serialises"),
            serde_json::to_string(&self.log.actions).expect("serialises")
        )
    }

    fn kinds(&self) -> Vec<ActionKind> {
        self.log.actions.iter().map(|a| a.kind.clone()).collect()
    }

    fn assert_no_secret(&self) {
        let text = self.everything();
        for canary in CANARIES {
            assert!(!text.contains(canary), "the run holds {canary}: {text}");
        }
    }
}

/// Runs `check` on the machine of `case` through the scheduler, on a paused clock. The proxy is read from
/// the machine's environment, and the `proxy` server accepts the one connection a reach test makes.
fn run(case: &str, check: ProxyCheck) -> Run {
    let fixture = load(case);
    let (os, needs) = (fixture.os(), fixture.available_needs());
    let offline = !needs.contains(&Need::Network);
    let replay = fixture
        .into_replay()
        .serve_duplex("proxy", |_server| async {});
    let mut test_run = TestRun::new(replay);
    if offline {
        test_run = test_run.offline();
    }
    let test_run = test_run.with_proxy_from_env();
    let scheduler = test_run.scheduler(1, os, needs);
    let planned = Planned::new(Arc::new(check), "net.proxy");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let mut ran = runtime.block_on(scheduler.run(vec![planned]));
    let log = test_run.action_log();
    let end = ran.remove(0).end;
    if let End::Done(done) = &end
        && done.is_ok()
    {
        assert_within_manifest("net.proxy", &INFO, &log);
    }
    Run { end, log }
}

fn run_case(case: &str) -> Run {
    let entry = cases()
        .into_iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("{case} is not in cases()"))
        .1;
    run(case, check(&entry))
}

fn level_word(level: Level) -> &'static str {
    match level {
        Level::Pass => "pass",
        Level::Warn => "warn",
        Level::Fail => "fail",
    }
}

/// The result as the goldens hold it.
fn render(end: &End) -> Value {
    match end {
        End::TimedOut { after } => json!({ "timed_out_ms": after.as_millis() }),
        End::Done(done) => match done.as_ref() {
            Ok(finding) => json!({
                "level": level_word(finding.level),
                "message": finding.message,
                "observed": finding.observed,
                "expected": finding.expected,
                "fix": finding.fix,
                "notes": finding.notes,
                "partial": finding.partial.as_ref().map(|p| json!({
                    "missing": p.missing.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>(),
                    "note": p.note,
                })),
            }),
            Err(CheckError::Unsupported(why)) => json!({ "unsupported": why }),
            Err(error) => json!({ "error": error.to_string() }),
        },
        other => panic!("unexpected end: {other:?}"),
    }
}

/// The value with every object's keys in order, so the goldens do not depend on `preserve_order`.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

#[test]
fn every_case_matches_its_golden() {
    for (case, entry) in cases() {
        let result = run(case, check(&entry));
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/net.proxy/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn no_planted_secret_reaches_any_case() {
    for (case, entry) in cases() {
        let ran = run(case, check(&entry));
        ran.assert_no_secret();
    }
}

fn level_of(case: &str) -> Level {
    run_case(case).finding().level
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    assert_eq!(level_of("no-proxy"), Level::Pass);
    // A shell proxy with Docker installed and no drop-in warns.
    assert_eq!(level_of("shell-proxy-no-docker-dropin"), Level::Warn);
    assert_eq!(level_of("docker-dropin-ok"), Level::Pass);
    assert_eq!(level_of("daemon-json-proxy"), Level::Pass);
    assert_eq!(level_of("no-proxy-covered"), Level::Pass);
    // A required NO_PROXY entry is missing, and the spec listed it.
    assert_eq!(level_of("no-proxy-gap"), Level::Fail);
    assert_eq!(level_of("pac-auto-proxy"), Level::Warn);
    assert_eq!(level_of("proxy-refused"), Level::Fail);
    assert_eq!(level_of("proxy-blackhole"), Level::Fail);
    assert_eq!(level_of("env-conflict"), Level::Warn);
    assert_eq!(level_of("socks-all-proxy"), Level::Warn);
    assert_eq!(level_of("dropin-reset"), Level::Warn);
    assert_eq!(level_of("no-network"), Level::Pass);
    assert_eq!(level_of("macos-env-only"), Level::Pass);
    // A drop-in directory that cannot be read is not a missing proxy: no warning, and the result is partial.
    assert_eq!(level_of("unreadable-dropins"), Level::Pass);
}

#[test]
fn a_shell_proxy_with_no_docker_dropin_warns_and_prints_the_dropin_text() {
    let ran = run_case("shell-proxy-no-docker-dropin");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .to_lowercase()
            .contains("docker is installed")
            && finding.message.contains("does not see the proxy"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("`/etc/systemd/system/docker.service.d/http-proxy.conf`"),
        "{fix}"
    );
    assert!(fix.contains("`[Service]`"), "{fix}");
    // The proxy without its userinfo, and a NO_PROXY the shell already has.
    assert!(
        fix.contains(
            "Environment=\"HTTP_PROXY=http://proxy.acme.test:3128\" \"HTTPS_PROXY=http://proxy.acme.test:3128\" \"NO_PROXY=localhost,.svc\""
        ),
        "{fix}"
    );
    assert!(
        fix.contains("`systemctl daemon-reload && systemctl restart docker`"),
        "{fix}"
    );
    // The URL had a user name and password, which the fix never prints.
    assert!(fix.contains("rdy does not print them"), "{fix}");
    ran.assert_no_secret();
    rdy_engine::fixtext::check(fix).unwrap_or_else(|e| panic!("fix text: {e}"));
}

#[test]
fn daemons_need_proxy_turns_the_warning_into_a_block() {
    let entry = json!({"id": "net.proxy", "daemons_need_proxy": true});
    let ran = run("shell-proxy-no-docker-dropin", check(&entry));
    assert_eq!(ran.finding().level, Level::Fail);
    // With a drop-in it passes whatever the spec says.
    let ran = run("docker-dropin-ok", check(&entry));
    assert_eq!(ran.finding().level, Level::Pass);
    // And a host with no proxy at all has nothing to compare.
    let ran = run("no-proxy", check(&entry));
    assert_eq!(ran.finding().level, Level::Pass);
}

#[test]
fn no_proxy_coverage_is_reported_for_every_required_entry() {
    let ran = run_case("no-proxy-gap");
    let finding = ran.finding();
    let required: Vec<&Value> = finding.observed["no_proxy_coverage"]
        .as_array()
        .expect("a list")
        .iter()
        .filter(|r| r["scope"] == "shell")
        .collect();
    assert_eq!(required.len(), 4);
    let covered: Vec<(&str, bool)> = required
        .iter()
        .map(|r| {
            (
                r["entry"].as_str().expect("entry"),
                r["covered"].as_bool().expect("covered"),
            )
        })
        .collect();
    // `10.1.0.0/16` is narrower than the required `10.0.0.0/8`, so it does not cover it.
    assert_eq!(
        covered,
        [
            (".svc", false),
            (".cluster.local", false),
            ("10.0.0.0/8", false),
            ("172.16.0.0/12", false)
        ]
    );
    assert!(
        finding.message.contains(
            "NO_PROXY does not cover `.svc`, `.cluster.local`, `10.0.0.0/8`, `172.16.0.0/12`"
        ),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("Add `.svc`"), "{fix}");

    let ran = run_case("no-proxy-covered");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    let required = finding.observed["no_proxy_coverage"]
        .as_array()
        .expect("a list");
    // Four for the shell and four for the one daemon that has a proxy.
    assert_eq!(required.len(), 8);
    assert!(
        required.iter().all(|r| r["covered"] == true),
        "{required:?}"
    );
    assert_eq!(required[0]["scope"], "shell");
    assert_eq!(required[0]["by"], ".svc");
    assert_eq!(required[4]["scope"], "docker");
}

#[test]
fn a_pac_case_warns_and_fetches_nothing() {
    let ran = run_case("pac-auto-proxy");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("PAC or WPAD") && finding.message.contains("does not fetch"),
        "{}",
        finding.message
    );
    // The address is shown as scheme, host and path only: no userinfo and no query.
    assert!(
        finding.message.contains("http://wpad.acme.test/proxy.pac"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("Set HTTPS_PROXY") && fix.contains("via_proxy"),
        "{fix}"
    );
    // No lookup, no connection, no HTTP request: the check has no route to fetch anything.
    let kinds = ran.kinds();
    for kind in [
        ActionKind::Connect,
        ActionKind::Lookup,
        ActionKind::Http,
        ActionKind::Tls,
    ] {
        assert!(!kinds.contains(&kind), "{kind:?} in {kinds:?}");
    }
    ran.assert_no_secret();
}

#[test]
fn the_docker_client_config_is_never_opened() {
    // The planted `auths` secret sits in `~/.docker/config.json`, where the facade refuses a read. The check
    // does not ask: no read, stat or listing names it, and its secret is in no output.
    for case in ["shell-proxy-no-docker-dropin", "docker-dropin-ok"] {
        let ran = run_case(case);
        for action in &ran.log.actions {
            let shown = serde_json::to_string(action).expect("serialises");
            assert!(!shown.contains(".docker"), "{case}: {shown}");
        }
        ran.assert_no_secret();
    }
}

#[test]
fn an_unreachable_proxy_blocks_with_the_cause() {
    let refused = run_case("proxy-refused");
    let finding = refused.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("not reachable (connection refused)"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["reach"]["class"], "refused");
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("Nothing listens at the proxy http://proxy.acme.test:3128")),
        "{:?}",
        finding.fix
    );
    let silent = run_case("proxy-blackhole");
    let finding = silent.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(finding.observed["reach"]["class"], "blackhole");
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("ask the network team to allow tcp/3128")),
        "{:?}",
        finding.fix
    );
    // One TCP connection to the proxy and nothing else on the network: no CONNECT, no TLS, no HTTP.
    for ran in [&refused, &silent] {
        let net: Vec<&ActionKind> = ran
            .log
            .actions
            .iter()
            .map(|a| &a.kind)
            .filter(|k| {
                matches!(
                    k,
                    ActionKind::Connect | ActionKind::Lookup | ActionKind::Tls | ActionKind::Http
                )
            })
            .collect();
        assert!(
            net.iter()
                .all(|k| matches!(k, ActionKind::Connect | ActionKind::Lookup)),
            "{net:?}"
        );
        let connects: Vec<_> = ran
            .log
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::Connect)
            .collect();
        assert_eq!(connects.len(), 1);
        assert_eq!(connects[0].fields["host"], "proxy.acme.test");
        assert_eq!(connects[0].fields["port"], 3128);
        assert!(connects[0].fields["via_proxy"].is_null());
        ran.assert_no_secret();
    }
}

#[test]
fn a_reachable_proxy_is_one_connection_that_sends_nothing() {
    let ran = run_case("docker-dropin-ok");
    let finding = ran.finding();
    assert_eq!(finding.observed["reach"]["state"], "connected");
    assert_eq!(
        finding.observed["reach"]["proxy"],
        "http://proxy.acme.test:3128"
    );
    let connects: Vec<_> = ran
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Connect)
        .collect();
    assert_eq!(connects.len(), 1, "{:?}", ran.log.actions);
    assert_eq!(connects[0].outcome, ActionOutcome::Ok);
}

#[test]
fn two_spellings_that_differ_are_reported_by_name_and_never_by_value() {
    let ran = run_case("env-conflict");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("HTTPS_PROXY and https_proxy are both set and differ"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .message
            .contains("NO_PROXY and no_proxy are both set and differ"),
        "{}",
        finding.message
    );
    ran.assert_no_secret();
}

#[test]
fn a_socks_address_is_unsupported_and_not_probed() {
    let ran = run_case("socks-all-proxy");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("ALL_PROXY uses socks5://"),
        "{}",
        finding.message
    );
    assert!(!ran.kinds().contains(&ActionKind::Connect));
    ran.assert_no_secret();
}

#[test]
fn a_later_dropin_with_an_empty_environment_line_clears_the_proxy() {
    let ran = run_case("dropin-reset");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .to_lowercase()
            .contains("docker is installed"),
        "{}",
        finding.message
    );
    let docker = &finding.observed["daemons"][0];
    assert_eq!(docker["unit"], "docker");
    assert!(docker.get("proxy").is_none(), "{docker}");
}

#[test]
fn an_environment_file_is_named_and_not_read() {
    let ran = run_case("environment-file");
    let finding = ran.finding();
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("`/etc/sysconfig/containerd`") && n.contains("does not read it")),
        "{:?}",
        finding.notes
    );
    // The kubelet unit is under /usr/lib, and its drop-in sets no proxy: containerd and the kubelet both
    // lack one, so both are named.
    assert!(
        finding
            .message
            .to_lowercase()
            .contains("containerd is installed"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .message
            .to_lowercase()
            .contains("kubelet is installed"),
        "{}",
        finding.message
    );
    // The sysconfig file is not on the manifest, so a read of it would have been refused and logged.
    assert!(
        !serde_json::to_string(&ran.log.actions)
            .expect("serialises")
            .contains("sysconfig/containerd\","),
        "the environment file was opened"
    );
}

#[test]
fn a_run_with_no_network_does_not_contact_the_proxy_and_is_partial() {
    let ran = run_case("no-network");
    let finding = ran.finding();
    assert!(!ran.kinds().contains(&ActionKind::Connect));
    assert!(!ran.kinds().contains(&ActionKind::Lookup));
    let partial = finding.partial.as_ref().expect("partial");
    assert_eq!(partial.missing, [Need::Network]);
    assert!(partial.note.contains("--no-network"), "{}", partial.note);
    assert_eq!(finding.observed["reach"]["state"], "not_tried");
}

#[test]
fn an_unreadable_dropin_directory_is_partial_and_not_absent() {
    let ran = run_case("unreadable-dropins");
    let finding = ran.finding();
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial
            .note
            .contains("docker.service.d could not be listed"),
        "{}",
        partial.note
    );
}

#[test]
fn macos_reads_the_environment_and_no_linux_path() {
    let ran = run_case("macos-env-only");
    let finding = ran.finding();
    assert_eq!(finding.observed["os"], "macos");
    assert_eq!(finding.observed["daemons"], json!([]));
    let kinds = ran.kinds();
    for kind in [ActionKind::Read, ActionKind::Stat, ActionKind::ReadDir] {
        assert!(!kinds.contains(&kind), "{kind:?}: {kinds:?}");
    }
    // The engine marks every result of a `Partial` OS, so the check does not.
    assert!(INFO.os.on(Os::Macos).partial_note().is_some());
}

#[test]
fn a_proxy_in_daemon_json_counts_as_seen_by_docker() {
    let ran = run_case("daemon-json-proxy");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    let docker = &finding.observed["daemons"][0];
    assert_eq!(docker["proxy"], "http://proxy.acme.test:3128");
    assert_eq!(docker["sources"], "/etc/docker/daemon.json");
    ran.assert_no_secret();
}

/// How many levels of list or object `value` holds.
fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn keys(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(items) => items.iter().for_each(|v| keys(v, out)),
        Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.clone());
                keys(inner, out);
            }
        }
        _ => {}
    }
}

#[test]
fn the_evidence_fits_the_report_bounds_and_no_key_reads_as_a_secret_name() {
    // The report writer cuts a list or object nested more than two levels below `observed`'s keys, and the
    // redactor replaces the value of a key such as `credentials` or `bypass`. Neither may touch the evidence.
    for (case, entry) in cases() {
        let ran = run(case, check(&entry));
        let Ok(finding) = ran.outcome() else { continue };
        let observed = finding.observed.as_object().expect("an object");
        for (key, value) in observed {
            assert!(depth(value) <= 2, "{case}: {key} is {} deep", depth(value));
        }
        let mut names = Vec::new();
        keys(&finding.observed, &mut names);
        for name in names {
            assert!(
                !rdy_engine::redact::is_secret_name(&name),
                "{case}: the key {name} reads as a secret name"
            );
        }
    }
}

#[test]
fn the_check_declares_only_the_proxy_peer_and_no_command() {
    assert_eq!(INFO.peers, [rdy_engine::check::PeerClass::Proxy]);
    assert!(INFO.commands.is_empty());
    assert!(INFO.needs.is_empty());
    assert!(
        !INFO.reaches_network(),
        "no spec host, so no fetch is possible"
    );
    rdy_engine::fixtext::check(INFO.meta.remediation)
        .unwrap_or_else(|e| panic!("remediation: {e}"));
}

// ---- parsers ----------------------------------------------------------------------------------------

mod parsers {
    use super::super::parse::*;
    use rdy_engine::probe::ProxyUrlError;

    #[test]
    fn a_proxy_value_is_classified_without_its_userinfo() {
        assert_eq!(
            classify("http://svc:pw-pw-pw-pw@proxy.acme.test:3128"),
            Setting::Proxy {
                origin: "http://proxy.acme.test:3128".to_owned(),
                credentials: true
            }
        );
        assert_eq!(
            classify(" proxy.acme.test:3128 "),
            Setting::Proxy {
                origin: "http://proxy.acme.test:3128".to_owned(),
                credentials: false
            }
        );
        assert_eq!(
            classify("socks5://user:pw@h.test:1080"),
            Setting::Unsupported("socks5".to_owned())
        );
        assert_eq!(
            classify("HTTPS://p.acme.test:443"),
            Setting::Unsupported("https".to_owned())
        );
        assert_eq!(
            classify("p@ss://x"),
            Setting::Bad(ProxyUrlError::Scheme),
            "a scheme with an at sign is not named"
        );
        assert!(matches!(classify("http://"), Setting::Bad(_)));
        assert!(matches!(classify(""), Setting::Bad(_)));
    }

    #[test]
    fn a_pac_address_is_recognised_and_shown_without_userinfo_or_query() {
        for (value, shown) in [
            (
                "http://wpad.acme.test/proxy.pac",
                "http://wpad.acme.test/proxy.pac",
            ),
            (
                "http://u:p@wpad.acme.test:8080/wpad.dat?x=1#f",
                "http://wpad.acme.test:8080/wpad.dat",
            ),
            (
                "pac+https://cfg.acme.test/any",
                "pac+https://cfg.acme.test/any",
            ),
            ("HTTP://WPAD.ACME.TEST/A.PAC", "HTTP://WPAD.ACME.TEST/A.PAC"),
        ] {
            assert_eq!(classify(value), Setting::Pac(shown.to_owned()), "{value}");
        }
        assert_eq!(pac_url("http://proxy.acme.test:3128"), None);
        assert_eq!(pac_url("proxy.acme.test:3128"), None);
        // A password with a slash has no safe reading, so nothing of it is shown.
        assert_eq!(
            pac_url("http://u:p/w@h.test/a.pac"),
            Some("(an address rdy cannot show)".to_owned())
        );
    }

    #[test]
    fn a_dropin_gives_its_proxy_lines_in_order() {
        let text = "# comment\n[Unit]\nEnvironment=\"HTTP_PROXY=ignored\"\n[Service]\nEnvironment=\"HTTP_PROXY=http://p.test:1\" 'https_proxy=http://p.test:2' NO_PROXY=a,b OTHER=x\nEnvironment=FOO=bar\nEnvironmentFile=-/etc/sysconfig/x\n";
        assert_eq!(
            parse_dropin(text),
            [
                Assign::Var(Kind::Http, "http://p.test:1".to_owned()),
                Assign::Var(Kind::Https, "http://p.test:2".to_owned()),
                Assign::Var(Kind::No, "a,b".to_owned()),
                Assign::File("/etc/sysconfig/x".to_owned()),
            ]
        );
    }

    #[test]
    fn an_empty_environment_line_resets_and_a_value_with_spaces_stays_whole() {
        assert_eq!(parse_dropin("[Service]\nEnvironment=\n"), [Assign::Reset]);
        assert_eq!(
            parse_dropin("[Service]\nEnvironment=\"NO_PROXY=a, b\"\n"),
            [Assign::Var(Kind::No, "a, b".to_owned())]
        );
        // A blank value is not an assignment.
        assert!(parse_dropin("[Service]\nEnvironment=\"HTTP_PROXY=\"\n").is_empty());
    }

    #[test]
    fn a_dropin_is_read_to_a_bounded_number_of_lines() {
        let mut text = "[Service]\n".to_owned();
        text.push_str(&"# filler\n".repeat(600));
        text.push_str("Environment=HTTP_PROXY=http://late.test:1\n");
        assert!(parse_dropin(&text).is_empty());
    }

    #[test]
    fn daemon_json_gives_only_the_proxies() {
        let text = r#"{"auths":{"r.test":{"auth":"AUTHS-CANARY"}},"proxies":{"http-proxy":"http://p.test:1","https-proxy":" ","no-proxy":"a"},"log-driver":"x"}"#;
        assert_eq!(
            daemon_json_proxies(text),
            Ok(vec![
                Assign::Var(Kind::Http, "http://p.test:1".to_owned()),
                Assign::Var(Kind::No, "a".to_owned()),
            ])
        );
        assert_eq!(daemon_json_proxies(""), Ok(Vec::new()));
        assert_eq!(daemon_json_proxies("{"), Err("it is not valid JSON"));
        assert_eq!(daemon_json_proxies("[1]"), Err("it is not a JSON object"));
        assert_eq!(daemon_json_proxies("{\"proxies\":3}"), Ok(Vec::new()));
    }

    proptest::proptest! {
        #[test]
        fn the_parsers_never_panic(text in proptest::prelude::any::<String>()) {
            let _ = classify(&text);
            let _ = pac_url(&text);
            let _ = parse_dropin(&text);
            let _ = daemon_json_proxies(&text);
        }

        #[test]
        fn a_classified_proxy_never_holds_its_password(
            user in "[a-z]{3,8}",
            password in "[A-Za-z0-9]{6,20}",
            host in "[a-z]{3,10}",
        ) {
            let value = format!("http://{user}:{password}@{host}.acme.test:3128");
            let shown = format!("{:?}", classify(&value));
            proptest::prop_assert!(!shown.contains(&password), "{shown}");
            let pac = format!("http://{user}:{password}@{host}.acme.test/p.pac?t={password}");
            let shown = format!("{:?}", classify(&pac));
            proptest::prop_assert!(!shown.contains(&password), "{shown}");
        }
    }
}
