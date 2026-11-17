//! `--no-network` in the facade (M1-059, SEC-01): every lookup, TCP, UDP and network command is
//! refused with `RULE_NO_NETWORK` before anything is opened, whatever the check declared.

use rdy_spec::Target;
use rdy_spec::result::{ActionKind, ActionOutcome};

use super::http::{HttpMethod, HttpProbe};
use super::tests::{entries, hub_over, probe_with, target};
use super::{Probe, Route};
use crate::check::{CheckInfo, CheckMeta, CommandSpec, Os, OsSupport, PeerClass, Support};
use crate::exec::table;
use crate::probe::replay::Replay;
use crate::probe::{ProbeError, ProbeHub, RULE_NO_NETWORK};

const META: CheckMeta = CheckMeta {
    title: "Fixture check",
    remediation: "Nothing to fix. This check is a test double.",
};

/// A check that declares every network door and the two network commands.
static EVERYTHING: CheckInfo = CheckInfo {
    id: "net.egress",
    family: "net",
    summary: "A fixture check.",
    meta: META,
    needs: &[],
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
    commands: &[
        CommandSpec {
            program: "getent",
            extra_dirs: &[],
            max_stdout: 4096,
            env: &[],
        },
        CommandSpec {
            program: "chronyc",
            extra_dirs: &[],
            max_stdout: 4096,
            env: &[],
        },
    ],
    peers: &[
        PeerClass::SpecHosts,
        PeerClass::NtpServers,
        PeerClass::Proxy,
    ],
};

const HOST: &str = "registry.acme.example:443";
const NTP: &str = "ntp.acme.example:123";

fn setup(allowed: bool) -> (ProbeHub, Probe) {
    let hub = hub_over(Replay::new());
    hub.set_network(allowed);
    let probe = probe_with(&hub, &EVERYTHING, "net.egress", &[HOST, NTP]);
    (hub, probe)
}

fn refused(error: &ProbeError) -> bool {
    error.is_no_network()
}

#[tokio::test]
async fn tcp_is_refused_and_logged_as_denied() {
    let (hub, probe) = setup(false);
    let error = probe
        .tcp(&target(HOST), Route::Direct)
        .await
        .expect_err("refused");
    assert!(refused(&error), "{error:?}");
    let log = entries(&hub);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].outcome, ActionOutcome::Denied);
    nothing_connected(&hub);
}

/// No entry is a connection: a `connect` entry, if any, is a refused call.
fn nothing_connected(hub: &ProbeHub) {
    let log = entries(hub);
    assert!(
        log.iter()
            .all(|a| a.kind != ActionKind::Connect || a.outcome == ActionOutcome::Denied),
        "{log:?}"
    );
}

#[tokio::test]
async fn a_direct_http_call_is_refused_and_nothing_connects() {
    for url in [
        "http://registry.acme.example:443/",
        "https://registry.acme.example:443/",
    ] {
        let (hub, probe) = setup(false);
        let target = Target::parse(url).expect("a valid url");
        let error = probe
            .http(HttpProbe::new(target, HttpMethod::Get))
            .await
            .expect_err("refused");
        assert!(refused(&error), "{url}: {error:?}");
        nothing_connected(&hub);
        assert!(
            entries(&hub)
                .iter()
                .all(|a| a.outcome == ActionOutcome::Denied),
            "{url}: {:?}",
            entries(&hub)
        );
    }
}

#[tokio::test]
async fn a_tls_chain_call_is_refused_and_nothing_connects() {
    for route in [Route::Direct, Route::ViaProxy] {
        let (hub, probe) = setup(false);
        let error = probe
            .tls_chain(&target(HOST), route)
            .await
            .expect_err("refused");
        assert!(refused(&error), "{error:?}");
        nothing_connected(&hub);
    }
}

#[tokio::test]
async fn a_proxied_tcp_call_is_refused_too() {
    let (_, probe) = setup(false);
    let error = probe
        .tcp(&target(HOST), Route::ViaProxy)
        .await
        .expect_err("refused");
    assert!(refused(&error), "{error:?}");
}

#[tokio::test]
async fn a_lookup_is_refused() {
    let (_, probe) = setup(false);
    let error = probe
        .lookup("registry.acme.example")
        .await
        .expect_err("refused");
    assert!(refused(&error), "{error:?}");
}

#[tokio::test]
async fn a_udp_exchange_is_refused() {
    let (_, probe) = setup(false);
    let error = probe
        .udp_exchange(&target(NTP), &[0; 48], 48)
        .await
        .expect_err("refused");
    assert!(refused(&error), "{error:?}");
}

#[tokio::test]
async fn getent_and_chronyc_are_refused_and_never_spawned() {
    let (_, probe) = setup(false);
    let getent = table::entry("getent")
        .expect("in the table")
        .cmd_for(Os::Linux, "ahosts", &["registry.acme.example"])
        .expect("a valid name");
    let error = probe.exec(getent).await.expect_err("refused");
    assert!(refused(&error), "{error:?}");
    let chronyc = table::entry("chronyc")
        .expect("in the table")
        .cmd_for(Os::Linux, "tracking", &[])
        .expect("a valid form");
    let error = probe.exec(chronyc).await.expect_err("refused");
    assert!(refused(&error), "{error:?}");
}

#[tokio::test]
async fn with_the_network_allowed_none_of_them_is_refused_by_this_rule() {
    let (_, probe) = setup(true);
    let error = probe
        .tcp(&target(HOST), Route::Direct)
        .await
        .expect_err("a replay with no script");
    assert!(!refused(&error), "{error:?}");
    let error = probe
        .lookup("registry.acme.example")
        .await
        .expect_err("a replay with no script");
    assert!(!refused(&error), "{error:?}");
    let error = probe
        .udp_exchange(&target(NTP), &[0; 48], 48)
        .await
        .expect_err("a replay with no script");
    assert!(!refused(&error), "{error:?}");
}

#[test]
fn the_rule_text_names_the_flag() {
    assert!(RULE_NO_NETWORK.contains("--no-network"));
}
