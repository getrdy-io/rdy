//! `net.egress` through the proxy (M1-097).
//!
//! The proxy and the servers are in-process loopback servers (`rdy_engine::testing::loopback`); the
//! machine's names point at them, so nothing leaves the host. The proxy URL carries a planted password,
//! and every test that proxies checks that it is in no finding, result or log entry.

use rdy_engine::testing::loopback::{ConnectProxy, ProxyMode};

use super::*;

/// The planted proxy password, and the base64 of `svc:` and the password, as `Proxy-Authorization`
/// would carry it.
const PASSWORD: &str = "longer-canary-pw";
const PAIR: &str = "c3ZjOmxvbmdlci1jYW5hcnktcHc=";

const PROXY_URL: &str = "http://svc:longer-canary-pw@proxy.acme.test:3128";
const PROXY_ORIGIN: &str = "http://proxy.acme.test:3128";

/// A machine whose `proxy.acme.test:3128` is the loopback `proxy`. Names are not looked up through a
/// proxy, so no other host is scripted; the OS store trusts `ca` when one is given.
fn through(proxy: &ConnectProxy, ca: Option<&TestCa>) -> Replay {
    let replay = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp(
            "192.0.2.50:3128".parse().expect("addr"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_tcp("proxy", proxy.addr());
    match ca {
        Some(ca) => replay.native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(vec![der(ca)].into()),
        ),
        None => replay,
    }
}

fn kinds(ran: &Ran) -> Vec<rdy_spec::result::ActionKind> {
    ran.run
        .action_log()
        .actions
        .iter()
        .filter(|a| a.check.as_deref() == Some("net.egress"))
        .map(|a| a.kind.clone())
        .collect()
}

fn assert_secrets_absent(ran: &Ran) {
    ran.assert_no_secret(PASSWORD);
    ran.assert_no_secret(PAIR);
    ran.assert_no_secret("svc:");
}

// ---- CONNECT ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_https_url_is_tunnelled_with_connect_and_verified_end_to_end() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "api.acme.test", Validity::Always).await;
    let at = format!("api.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, Some(&ca)),
        json!([url("api.acme.test", &server, "/health")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(
        ran.finding().level,
        Level::Pass,
        "{}",
        ran.finding().message
    );
    let e = ran.endpoint(0);
    assert_eq!(e["route"], "proxy");
    assert_eq!(e["proxy"], PROXY_ORIGIN);
    assert!(
        e["proxy_attempts"].is_array() && e.get("attempts").is_none(),
        "{e}"
    );
    assert_eq!(e["tls_stage"]["roots"], "system");
    assert_eq!(e["http_stage"]["status"], 200);
    // The name resolved at the proxy: this machine looked up nothing for the endpoint.
    let log = kinds(&ran);
    assert!(
        !log.contains(&rdy_spec::result::ActionKind::Lookup),
        "{log:?}"
    );
    // Two tunnels, one for the handshake stage and one for the request, each with the credential, and the
    // origin saw one request with none.
    let connects = proxy.requests();
    assert_eq!(connects.len(), 2, "{connects:?}");
    for connect in &connects {
        assert_eq!(connect.target, at);
        assert_eq!(
            connect.proxy_authorization.as_deref(),
            Some(format!("Basic {PAIR}").as_str())
        );
    }
    let seen = server.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].header("proxy-authorization"), None);
    assert!(
        ran.finding().notes.iter().any(|n| n.contains(PROXY_ORIGIN)),
        "{:?}",
        ran.finding().notes
    );
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_host_port_endpoint_is_tunnelled_and_passes() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("db.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!([at]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(ran.endpoint(0)["route"], "proxy");
    assert_eq!(proxy.requests().len(), 1);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_403_to_connect_is_proxy_403_with_the_allow_list_text() {
    let proxy = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!(["registry.acme.test:8443"]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with("The proxy refused CONNECT to registry.acme.test:8443."),
        "{fix}"
    );
    assert!(fix.contains("add it to the allow list"), "{fix}");
    // A port other than 443 gets the Squid hint, because a default proxy allows tunnels only to 443.
    assert!(fix.contains("only to port 443"), "{fix}");
    assert_eq!(ran.result().status, Status::Block);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_407_to_connect_names_what_the_proxy_wants() {
    for (mode, url, word, want) in [
        (
            ProxyMode::Basic407,
            PROXY_URL,
            "rejected",
            "rejected the user name or password",
        ),
        (
            ProxyMode::Basic407,
            "http://proxy.acme.test:3128",
            "needed",
            "wants a user name and password",
        ),
        (
            ProxyMode::Negotiate407,
            PROXY_URL,
            "negotiate",
            "wants integrated sign-in",
        ),
    ] {
        let proxy = ConnectProxy::start(mode).await.expect("proxy");
        let ran = run_via(
            through(&proxy, None),
            json!(["registry.acme.test:443"]),
            json!({}),
            NET,
            Some(url),
        )
        .await;
        assert_eq!(ran.endpoint(0)["class"], "proxy_407", "{word}");
        let fix = ran.finding().fix.as_deref().expect("a fix");
        assert!(fix.contains(want), "{word}: {fix}");
        assert_eq!(ran.result().status, Status::Block);
        assert_secrets_absent(&ran);
    }
}

#[tokio::test]
async fn another_status_to_connect_is_proxy_refused_with_its_status() {
    // The proxy has no route for the name, so it answers 502.
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!(["gone.acme.test:443"]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_refused");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("answered 502"), "{fix}");
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_proxy_that_cannot_be_reached_is_proxy_unreachable_and_not_a_fault_of_the_endpoint() {
    let replay = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp("192.0.2.50:3128".parse().expect("addr"), TcpScript::Refused);
    for endpoint in ["registry.acme.test:8443", "https://api.acme.test/"] {
        let ran = run_via(
            replay.clone(),
            json!([endpoint]),
            json!({}),
            NET,
            Some(PROXY_URL),
        )
        .await;
        assert_eq!(ran.endpoint(0)["class"], "proxy_unreachable", "{endpoint}");
        let fix = ran.finding().fix.as_deref().expect("a fix");
        assert!(fix.contains("`HTTPS_PROXY` or `HTTP_PROXY`"), "{fix}");
        assert_secrets_absent(&ran);
    }
}

// ---- the absolute form -----------------------------------------------------------------------------

#[tokio::test]
async fn an_http_url_uses_the_absolute_form_and_never_connect() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let target = format!("http://{at}/repo/index?token=q-canary");
    let ran = run_via(
        through(&proxy, None),
        json!([target]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(
        ran.finding().level,
        Level::Pass,
        "{}",
        ran.finding().message
    );
    assert!(
        proxy.requests().is_empty(),
        "no CONNECT: {:?}",
        proxy.requests()
    );
    let plain = proxy.plain_requests();
    assert_eq!(plain.len(), 1);
    assert_eq!(
        plain[0].target,
        format!("http://{at}/repo/index?token=q-canary")
    );
    assert_eq!(
        plain[0].proxy_authorization.as_deref(),
        Some(format!("Basic {PAIR}").as_str())
    );
    assert_eq!(server.requests()[0].target, "/repo/index?token=q-canary");
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 200);
    assert_secrets_absent(&ran);
    ran.assert_no_secret("q-canary");
}

#[tokio::test]
async fn a_403_to_the_absolute_form_is_proxy_403_unless_the_spec_lists_it() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Forbidden, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!([format!("http://{at}/")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("answered 403 to the request"), "{fix}");
    assert!(fix.contains("expect_status"), "{fix}");
    assert_eq!(ran.result().status, Status::Block);

    // The vendor says 403 is a normal answer of the server: it passes.
    let ran = run_via(
        through(&proxy, None),
        json!([{"target": format!("http://{at}/"), "expect_status": [403]}]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_407_to_the_absolute_form_is_proxy_407() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Basic407, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!([format!("http://{at}/")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_407");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("rejected the user name or password"), "{fix}");
    assert_eq!(server.accepted(), 0, "the origin was never reached");
    assert_secrets_absent(&ran);
}

// ---- redirects -------------------------------------------------------------------------------------

#[tokio::test]
async fn a_302_records_the_location_host_is_not_followed_and_says_to_add_it() {
    let location = "https://cdn.acme.example/next?token=hunter2-canary#frag";
    let server =
        HttpServer::start(HttpOptions::plain().reply(Reply::Redirect(location.to_owned())))
            .await
            .expect("server");
    let replay = Replay::new()
        .host("www.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server.addr());
    let target = format!("http://www.acme.test:{}/", server.addr().port());
    let ran = run_on(replay.clone(), json!([target]), json!({}), NET).await;
    let http = &ran.endpoint(0)["http_stage"];
    assert_eq!(http["status"], 302);
    assert_eq!(http["location_host"], "cdn.acme.example");
    assert_eq!(server.requests().len(), 1, "the redirect was not followed");
    assert!(
        ran.finding().notes.iter().any(|n| n.contains(
            "redirects to cdn.acme.example, which rdy did not follow. Add cdn.acme.example:443 to the endpoints to test it."
        )),
        "{:?}",
        ran.finding().notes
    );
    // Only the host is kept: the path, the query and the fragment are not in the result.
    ran.assert_no_secret("hunter2-canary");
    ran.assert_no_secret("/next");

    // A host the check lists already needs no advice.
    let both = json!([
        format!("http://www.acme.test:{}/", server.addr().port()),
        "cdn.acme.example:8443"
    ]);
    let replay = replay
        .host("cdn.acme.example", ["127.0.0.1".parse().expect("ip")])
        .tcp(
            "127.0.0.1:8443".parse().expect("addr"),
            TcpScript::Serve("web".to_owned()),
        );
    let ran = run_on(replay, both, json!({}), NET).await;
    assert!(
        !ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("Add cdn.acme.example")),
        "{:?}",
        ran.finding().notes
    );
}

// ---- the route of each endpoint --------------------------------------------------------------------

#[tokio::test]
async fn the_route_follows_via_proxy_and_whether_the_run_has_a_proxy() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("db.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let direct_machine = || {
        through(&proxy, None)
            .host("db.acme.test", ["127.0.0.1".parse().expect("ip")])
            .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
            .serve_tcp("web", server.addr())
    };

    // `auto` with a proxy goes through it.
    let ran = run_via(
        direct_machine(),
        json!([at]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["route"], "proxy");
    assert_eq!(proxy.requests().len(), 1);

    // `direct` never touches it.
    let ran = run_via(
        direct_machine(),
        json!([at]),
        json!({"via_proxy": "direct"}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert!(ran.endpoint(0).get("route").is_none());
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(proxy.requests().len(), 1, "no second CONNECT");

    // `auto` with no proxy is direct; `proxy_only` with none is not tried.
    let ran = run_on(direct_machine(), json!([at]), json!({}), NET).await;
    assert!(ran.endpoint(0).get("route").is_none());
    let ran = run_on(
        direct_machine(),
        json!([at]),
        json!({"via_proxy": "proxy_only"}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["result"], "not_tried");
    assert!(
        ran.endpoint(0)["why"]
            .as_str()
            .is_some_and(|why| why.contains("HTTPS_PROXY or HTTP_PROXY")),
        "{}",
        ran.endpoint(0)
    );

    // An endpoint of its own beats the entry.
    let ran = run_via(
        direct_machine(),
        json!([{"target": at, "via_proxy": "direct"}]),
        json!({"via_proxy": "proxy_only"}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert!(ran.endpoint(0).get("route").is_none());
}
