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

#[tokio::test(start_paused = true)]
async fn a_proxy_that_cannot_be_reached_is_proxy_unreachable_and_not_a_fault_of_the_endpoint() {
    let refused = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp("192.0.2.50:3128".parse().expect("addr"), TcpScript::Refused);
    let silent = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp(
            "192.0.2.50:3128".parse().expect("addr"),
            TcpScript::Blackhole,
        );
    // The proxy's own name does not resolve: the answer is empty.
    let no_name = Replay::new().host("proxy.acme.test", Vec::<std::net::IpAddr>::new());
    for (what, replay) in [
        ("refused", refused),
        ("silent", silent),
        ("no name", no_name),
    ] {
        for endpoint in [
            "registry.acme.test:8443",
            "https://api.acme.test/",
            "http://mirror.acme.test/",
        ] {
            let ran = run_via(
                replay.clone(),
                json!([endpoint]),
                json!({}),
                NET,
                Some(PROXY_URL),
            )
            .await;
            assert_eq!(
                ran.endpoint(0)["class"],
                "proxy_unreachable",
                "{what}: {endpoint}"
            );
            let fix = ran.finding().fix.as_deref().expect("a fix");
            assert!(fix.contains("`HTTPS_PROXY` or `HTTP_PROXY`"), "{fix}");
            assert_secrets_absent(&ran);
        }
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

// ---- review round ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_403_inside_an_https_tunnel_is_the_servers_and_only_warns() {
    let ca = TestCa::root("Acme Test Root");
    let options =
        HttpOptions::tls(&ca.issue(&["api.acme.test"], Validity::Always)).reply(Reply::Status(403));
    let server = HttpServer::start(options).await.expect("server");
    let at = format!("api.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, Some(&ca)),
        json!([url("api.acme.test", &server, "/")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    // The tunnel was open and verified, so the 403 came from the server: the direct rule applies.
    assert_eq!(
        ran.finding().level,
        Level::Warn,
        "{}",
        ran.finding().message
    );
    assert_eq!(ran.endpoint(0)["result"], "reached");
    assert_ne!(ran.endpoint(0)["class"], "proxy_403");
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 403);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_direct_http_endpoint_sends_no_proxy_credential_when_a_proxy_is_set() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let replay = through(&proxy, None)
        .host("mirror.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server.addr());
    let ran = run_via(
        replay,
        json!([{"target": format!("http://{at}/"), "via_proxy": "direct"}]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    let seen = server.requests();
    assert!(!seen.is_empty());
    assert!(
        seen.iter()
            .all(|r| r.header("proxy-authorization").is_none())
    );
    assert_eq!(proxy.accepted(), 0);
    assert_secrets_absent(&ran);
}

// ---- NO_PROXY (M1-098) -------------------------------------------------------------------------------

/// The machine of the NO_PROXY tests: the proxy of `through`, the `HTTPS_PROXY` and `NO_PROXY` of the
/// environment, and the name `direct.acme.test` that points straight at `direct`.
fn with_no_proxy(
    proxy: &ConnectProxy,
    direct: &HttpServer,
    no_proxy: &str,
    extra: &[(&str, &str)],
) -> Replay {
    let mut replay = through(proxy, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .env("NO_PROXY", no_proxy)
        .host("direct.acme.test", ["192.0.2.60".parse().expect("ip")])
        .tcp(
            format!("192.0.2.60:{}", direct.addr().port())
                .parse()
                .expect("addr"),
            TcpScript::Serve("direct".to_owned()),
        )
        .serve_tcp("direct", direct.addr());
    for (name, value) in extra {
        replay = replay.env(name, value);
    }
    replay
}

#[tokio::test]
async fn a_no_proxy_host_connects_direct_while_the_other_hosts_use_the_proxy() {
    let direct = HttpServer::start(HttpOptions::plain())
        .await
        .expect("direct server");
    let via = HttpServer::start(HttpOptions::plain())
        .await
        .expect("proxied server");
    let via_at = format!("via.acme.test:{}", via.addr().port());
    let direct_at = format!("direct.acme.test:{}", direct.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&via_at, via.addr())])
        .await
        .expect("proxy");
    let replay = with_no_proxy(&proxy, &direct, "internal.example, direct.acme.test", &[]);
    let ran = run_from_env(replay, json!([direct_at, via_at]), json!({}), NET).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    // The NO_PROXY host: direct. It was looked up here, connected on its own address, and the report says
    // which entry sent it direct.
    let d = ran.endpoint(0);
    assert_eq!(d["endpoint"], direct_at.as_str());
    assert_eq!(d["route"], "direct");
    assert_eq!(
        d["exempted_by"],
        "NO_PROXY entry \"direct.acme.test\" covers the host"
    );
    assert!(d["lookup"].is_object() && d["attempts"].is_array(), "{d}");
    assert_eq!(d["attempts"][0]["outcome"], "connected");
    assert!(d.get("proxy").is_none(), "{d}");
    // The other host: through the proxy, with a CONNECT and no local lookup.
    let v = ran.endpoint(1);
    assert_eq!(v["route"], "proxy");
    assert_eq!(v["proxy"], PROXY_ORIGIN);
    assert!(v.get("exempted_by").is_none(), "{v}");
    // The proxy saw one CONNECT, for the other host only.
    let connects = proxy.requests();
    assert_eq!(connects.len(), 1, "{connects:?}");
    assert_eq!(connects[0].target, via_at);
    // The log: the NO_PROXY host was looked up here and the proxied one was not.
    let lookups: Vec<String> = ran
        .run
        .action_log()
        .actions
        .iter()
        .filter(|a| a.kind == rdy_spec::result::ActionKind::Lookup)
        .map(|a| a.fields["host"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(lookups, ["direct.acme.test"]);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains(&direct_at) && n.contains("went direct, not through the proxy")),
        "{:?}",
        finding.notes
    );
    // The list is shown only as the one entry that matched, never whole.
    ran.assert_no_secret("internal.example");
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_star_a_cidr_and_loopback_send_hosts_direct_and_a_narrow_entry_does_not() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let port = server.addr().port();
    for (list, host, direct) in [
        ("*", "direct.acme.test", true),
        ("192.0.2.0/24", "192.0.2.60", true),
        ("192.0.2.0/24", "direct.acme.test", false),
        ("other.acme.test", "direct.acme.test", false),
        (".acme.test", "direct.acme.test", true),
        ("", "127.0.0.1", true),
    ] {
        let at = format!("{host}:{port}");
        let replay = with_no_proxy(&proxy, &server, list, &[])
            .host("127.0.0.1", ["127.0.0.1".parse().expect("ip")])
            .tcp(
                format!("127.0.0.1:{port}").parse().expect("addr"),
                TcpScript::Serve("direct".to_owned()),
            )
            .tcp(
                format!("192.0.2.60:{port}").parse().expect("addr"),
                TcpScript::Serve("direct".to_owned()),
            );
        let ran = run_from_env(replay, json!([at]), json!({}), NET).await;
        let route = ran.endpoint(0)["route"].as_str().map(str::to_owned);
        if direct {
            assert_eq!(route.as_deref(), Some("direct"), "{list:?} {host}");
        } else {
            assert_eq!(route.as_deref(), Some("proxy"), "{list:?} {host}");
        }
    }
}

#[tokio::test]
async fn proxy_only_and_direct_ignore_no_proxy_as_the_spec_asks() {
    let direct = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("direct.acme.test:{}", direct.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, direct.addr())])
        .await
        .expect("proxy");
    // `proxy_only` takes the proxy although NO_PROXY lists the host.
    let replay = with_no_proxy(&proxy, &direct, "direct.acme.test", &[]);
    let ran = run_from_env(replay, json!([at]), json!({"via_proxy": "proxy_only"}), NET).await;
    assert_eq!(ran.endpoint(0)["route"], "proxy");
    assert_eq!(proxy.requests().len(), 1);
    // `direct` never takes it, and says nothing about NO_PROXY.
    let replay = with_no_proxy(&proxy, &direct, "", &[]);
    let ran = run_from_env(replay, json!([at]), json!({"via_proxy": "direct"}), NET).await;
    assert!(
        ran.endpoint(0).get("route").is_none(),
        "{}",
        ran.endpoint(0)
    );
    assert!(ran.endpoint(0).get("exempted_by").is_none());
    assert_eq!(proxy.requests().len(), 1, "no new CONNECT");
}

#[tokio::test]
async fn no_proxy_in_either_case_is_read_and_a_blank_one_is_not() {
    let direct = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("direct.acme.test:{}", direct.addr().port());
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let lower = through(&proxy, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .env("no_proxy", "direct.acme.test")
        .host("direct.acme.test", ["192.0.2.60".parse().expect("ip")])
        .tcp(
            format!("192.0.2.60:{}", direct.addr().port())
                .parse()
                .expect("addr"),
            TcpScript::Serve("direct".to_owned()),
        )
        .serve_tcp("direct", direct.addr());
    let ran = run_from_env(lower, json!([at]), json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["route"], "direct");
    // A blank NO_PROXY exempts nothing: the endpoint takes the proxy.
    let blank = through(&proxy, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .env("NO_PROXY", "   ");
    let ran = run_from_env(blank, json!([at]), json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["route"], "proxy");
    assert!(
        !ran.finding().notes.iter().any(|n| n.contains("NO_PROXY")),
        "{:?}",
        ran.finding().notes
    );
}

#[tokio::test]
async fn two_spellings_of_the_proxy_that_differ_are_noted_by_name_only() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("db.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let replay = through(&proxy, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .env("https_proxy", "http://other-canary.acme.test:8080");
    let ran = run_from_env(replay, json!([at]), json!({}), NET).await;
    let note = ran
        .finding()
        .notes
        .iter()
        .find(|n| n.starts_with("HTTPS_PROXY and https_proxy are both set and differ"))
        .unwrap_or_else(|| panic!("no conflict note: {:?}", ran.finding().notes));
    assert!(note.contains("rdy used HTTPS_PROXY"), "{note}");
    // The other value is never shown: only the proxy the run used is named, as an origin.
    ran.assert_no_secret("other-canary");
    assert_secrets_absent(&ran);
    // The same value in both spellings is no conflict.
    let same = through(&proxy, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .env("https_proxy", PROXY_URL);
    let ran = run_from_env(same, json!([at]), json!({}), NET).await;
    assert!(
        !ran.finding().notes.iter().any(|n| n.contains("both set")),
        "{:?}",
        ran.finding().notes
    );
}

#[tokio::test]
async fn direct_works_and_proxy_fails_is_said_for_an_auto_endpoint_and_for_no_other() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("direct.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let machine = || with_no_proxy(&proxy, &server, "internal.example", &[]);
    let ran = run_from_env(machine(), json!([at]), json!({}), NET).await;
    let finding = ran.finding();
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    assert_eq!(ran.endpoint(0)["direct_works"], true);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("direct works, proxy fails") && n.contains(PROXY_ORIGIN)),
        "{:?}",
        finding.notes
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("add direct.acme.test to NO_PROXY so the product connects direct"),
        "{fix}"
    );
    assert_secrets_absent(&ran);
    // `proxy_only` fails the same way and the direct path is not tried: the spec asked for the proxy.
    let ran = run_from_env(
        machine(),
        json!([at]),
        json!({"via_proxy": "proxy_only"}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    assert!(ran.endpoint(0).get("direct_works").is_none());
    // Where the direct connect fails too, nothing is said.
    let broken = through(&proxy, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .host("direct.acme.test", ["192.0.2.60".parse().expect("ip")])
        .tcp(
            format!("192.0.2.60:{}", server.addr().port())
                .parse()
                .expect("addr"),
            TcpScript::Refused,
        );
    let ran = run_from_env(broken, json!([at]), json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    assert_eq!(ran.endpoint(0)["direct_tried"], true);
    assert_eq!(ran.endpoint(0)["direct_works"], false);
}

#[tokio::test]
async fn a_proxy_read_from_http_proxy_is_named_for_an_https_endpoint_and_in_the_fixes() {
    // A tunnelled TLS endpoint (port 443): the note names the variable. The proxy refuses, which is
    // enough: the endpoint went through the proxy.
    let forbidden = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let ran = run_from_env(
        through(&forbidden, None).env("http_proxy", PROXY_URL),
        json!(["registry.acme.test:443"]),
        json!({}),
        NET,
    )
    .await;
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.starts_with("An https endpoint went through a proxy read from http_proxy")),
        "{:?}",
        ran.finding().notes
    );
    // HTTPS_PROXY as the source: no such note.
    let ran = run_from_env(
        through(&forbidden, None).env("HTTPS_PROXY", PROXY_URL),
        json!(["registry.acme.test:443"]),
        json!({}),
        NET,
    )
    .await;
    assert!(!ran.finding().notes.iter().any(|n| n.contains("read from")));

    // The 407 fix names the variable the proxy came from.
    for (var, want) in [
        ("HTTP_PROXY", "`HTTP_PROXY`"),
        ("https_proxy", "`https_proxy`"),
    ] {
        let denied = ConnectProxy::start(ProxyMode::Basic407)
            .await
            .expect("proxy");
        let ran = run_from_env(
            through(&denied, None).env(var, PROXY_URL),
            json!(["registry.acme.test:443"]),
            json!({}),
            NET,
        )
        .await;
        let fix = ran.finding().fix.as_deref().expect("a fix");
        assert!(fix.contains(want), "{var}: {fix}");
        assert_secrets_absent(&ran);
    }
}

#[tokio::test]
async fn a_redirect_to_a_plain_http_host_suggests_port_80() {
    let server = HttpServer::start(
        HttpOptions::plain().reply(Reply::Redirect("http://old.acme.example/x".to_owned())),
    )
    .await
    .expect("server");
    let replay = Replay::new()
        .host("www.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server.addr());
    let target = format!("http://www.acme.test:{}/", server.addr().port());
    let ran = run_on(replay, json!([target]), json!({}), NET).await;
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("Add old.acme.example:80 to the endpoints")),
        "{:?}",
        ran.finding().notes
    );
}

#[test]
fn the_new_evidence_keys_do_not_read_as_secret_names() {
    // The redactor replaces the value of a key such as `bypass` or `credentials` (it did for the first
    // name chosen for the NO_PROXY reason), so the keys of M1-098 are checked against the same rule.
    for key in ["exempted_by", "direct_works", "route", "proxy"] {
        assert!(!rdy_engine::redact::is_secret_name(key), "{key}");
    }
}

#[tokio::test]
async fn a_star_in_no_proxy_never_sends_a_forbidden_address_anywhere() {
    // INV-12: whatever the route, a metadata address is refused before any connection, literal or resolved,
    // and so is the direct retry after a proxy failure.
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let replay = || {
        through(&proxy, None)
            .env("HTTPS_PROXY", PROXY_URL)
            .env("NO_PROXY", "*")
            .host("meta.acme.test", ["169.254.169.254".parse().expect("ip")])
    };
    for at in ["169.254.169.254:80", "meta.acme.test:80"] {
        let ran = run_from_env(replay(), json!([at]), json!({}), NET).await;
        assert_eq!(ran.endpoint(0)["route"], "direct", "{at}");
        assert_eq!(ran.endpoint(0)["class"], "refused_by_policy", "{at}");
    }
    assert!(proxy.requests().is_empty(), "no CONNECT was sent");
    // The retry: no NO_PROXY, the proxy refuses, and the name resolves to the metadata address.
    let forbidden = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let machine = through(&forbidden, None)
        .env("HTTPS_PROXY", PROXY_URL)
        .host("meta.acme.test", ["169.254.169.254".parse().expect("ip")]);
    let ran = run_from_env(machine, json!(["meta.acme.test:80"]), json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    assert_eq!(ran.endpoint(0)["direct_tried"], true);
    assert_eq!(ran.endpoint(0)["direct_works"], false);
}
