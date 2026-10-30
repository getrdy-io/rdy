//! Tests of proxy resolution: the order of the rules, the `NO_PROXY` forms, the schemes rdy refuses, and
//! that a proxy password never reaches a text.

use super::*;

fn server(url: &str) -> Uri {
    Uri::from_str(url).expect("a URL")
}

fn env_with(proxy: &str) -> Env {
    Env::empty().with_https_proxy(proxy)
}

const API: &str = "https://k8s.acme.example:6443";

fn resolve_api(kubeconfig: Option<&str>, env: &Env) -> Result<Resolved, KubeError> {
    resolve(kubeconfig, env, &server(API))
}

// ---- the order of the rules ---------------------------------------------------------------------------------

#[test]
fn no_proxy_anywhere_is_a_direct_request() {
    let resolved = resolve_api(None, &Env::empty()).expect("resolve");
    assert!(resolved.uri.is_none());
    assert_eq!(resolved.used, ProxyUse::none());
    assert_eq!(resolved.used.describe(), None);
    assert!(!resolved.used.is_proxied());
}

#[test]
fn the_kubeconfig_proxy_url_is_used_and_reported() {
    let resolved = resolve_api(Some("http://proxy.acme.example:3128"), &Env::empty()).expect("ok");
    assert_eq!(
        resolved.uri.expect("a proxy").to_string(),
        "http://proxy.acme.example:3128/"
    );
    assert_eq!(resolved.used.rule(), &ProxyRule::KubeconfigProxyUrl);
    assert_eq!(
        resolved.used.proxy(),
        Some("http://proxy.acme.example:3128")
    );
    assert_eq!(
        resolved.used.describe().as_deref(),
        Some("through the proxy http://proxy.acme.example:3128 (proxy-url in the kubeconfig)")
    );
}

#[test]
fn the_kubeconfig_proxy_url_wins_over_the_environment_and_over_no_proxy() {
    let env = env_with("http://env.acme.example:3128").with_no_proxy("*");
    let resolved = resolve_api(Some("http://cfg.acme.example:3128"), &env).expect("ok");
    assert_eq!(resolved.used.rule(), &ProxyRule::KubeconfigProxyUrl);
    assert_eq!(resolved.used.proxy(), Some("http://cfg.acme.example:3128"));
}

#[test]
fn an_empty_kubeconfig_proxy_url_counts_as_unset() {
    let env = env_with("http://env.acme.example:3128");
    let resolved = resolve_api(Some(""), &env).expect("ok");
    assert_eq!(resolved.used.rule(), &ProxyRule::Environment("HTTPS_PROXY"));
}

#[test]
fn https_proxy_applies_to_an_https_server() {
    let resolved = resolve_api(None, &env_with("http://proxy.acme.example:3128")).expect("ok");
    assert_eq!(resolved.used.rule(), &ProxyRule::Environment("HTTPS_PROXY"));
    assert_eq!(
        resolved.used.describe().as_deref(),
        Some("through the proxy http://proxy.acme.example:3128 (HTTPS_PROXY)")
    );
}

#[test]
fn the_lower_case_variable_is_named_as_read() {
    let mut env = env_with("http://proxy.acme.example:3128");
    env.https_proxy_name = "https_proxy";
    let resolved = resolve_api(None, &env).expect("ok");
    assert_eq!(resolved.used.rule(), &ProxyRule::Environment("https_proxy"));
}

#[test]
fn a_proxy_without_a_scheme_is_read_as_http_like_go_does() {
    let resolved = resolve_api(None, &env_with("proxy.acme.example:3128")).expect("ok");
    assert_eq!(
        resolved.used.proxy(),
        Some("http://proxy.acme.example:3128")
    );
}

#[test]
fn an_http_server_never_uses_the_https_proxy_variable() {
    let resolved = resolve(
        None,
        &env_with("http://proxy.acme.example:3128"),
        &server("http://k8s.acme.example:8080"),
    )
    .expect("ok");
    assert_eq!(resolved.used.rule(), &ProxyRule::None);
    assert!(resolved.uri.is_none());
}

#[test]
fn an_empty_variable_is_unset() {
    let resolved = resolve_api(None, &env_with("")).expect("ok");
    assert_eq!(resolved.used.rule(), &ProxyRule::None);
}

// ---- NO_PROXY -----------------------------------------------------------------------------------------------

#[test]
fn no_proxy_makes_the_request_direct_and_the_report_says_which_entry() {
    let env = env_with("http://proxy.acme.example:3128").with_no_proxy("10.0.0.0/8, .Acme.Example");
    let resolved = resolve_api(None, &env).expect("ok");
    assert!(resolved.uri.is_none());
    let text = resolved.used.describe().expect("a description");
    assert_eq!(
        text,
        "directly, although HTTPS_PROXY is set (NO_PROXY entry \".acme.example\" covers the API host)"
    );
    assert!(!resolved.used.is_proxied());
}

#[test]
fn a_proxy_that_no_proxy_exempts_is_never_parsed() {
    let env = env_with("::garbage::").with_no_proxy(".acme.example");
    let resolved = resolve_api(None, &env).expect("a stale value must not fail a direct run");
    assert!(resolved.uri.is_none());
}

#[test]
fn loopback_and_localhost_never_use_the_proxy() {
    for url in [
        "https://localhost:6443",
        "https://127.0.0.1:6443",
        "https://127.8.9.10:6443",
        "https://[::1]:6443",
    ] {
        let resolved = resolve(
            None,
            &env_with("http://proxy.acme.example:3128"),
            &server(url),
        )
        .expect("ok");
        assert!(resolved.uri.is_none(), "{url}");
        assert_eq!(
            resolved.used.describe().as_deref(),
            Some("directly, although HTTPS_PROXY is set (loopback addresses never use a proxy)"),
            "{url}"
        );
    }
}

#[test]
fn the_no_proxy_forms_follow_the_go_rules() {
    let m = |list: &str, host: &str, port: u16| no_proxy_entry(list, host, port).is_some();
    // A name matches itself and its subdomains.
    assert!(m("acme.example", "acme.example", 443));
    assert!(m("acme.example", "k8s.acme.example", 443));
    assert!(m("ACME.example", "k8s.acme.example", 443));
    assert!(!m("acme.example", "notacme.example", 443));
    assert!(!m("acme.example", "acme.example.evil.test", 443));
    // A leading dot matches subdomains only.
    assert!(m(".acme.example", "k8s.acme.example", 443));
    assert!(!m(".acme.example", "acme.example", 443));
    // A wildcard prefix is the same as a leading dot.
    assert!(m("*.acme.example", "k8s.acme.example", 443));
    assert!(!m("*.acme.example", "acme.example", 443));
    // A port limits the entry.
    assert!(m("acme.example:6443", "k8s.acme.example", 6443));
    assert!(!m("acme.example:6443", "k8s.acme.example", 443));
    // `*` matches all, the empty list and empty items match nothing.
    assert!(m("*", "anything.test", 1));
    assert!(m("a.test, *", "anything.test", 1));
    assert!(!m("", "acme.example", 443));
    assert!(!m(" , ,", "acme.example", 443));
    // Addresses.
    assert!(m("10.1.2.3", "10.1.2.3", 443));
    assert!(!m("10.1.2.3", "10.1.2.4", 443));
    assert!(m("10.0.0.0/8", "10.200.1.1", 443));
    assert!(!m("10.0.0.0/8", "11.0.0.1", 443));
    assert!(m("192.168.1.0/24", "192.168.1.77", 443));
    assert!(!m("192.168.1.0/24", "192.168.2.77", 443));
    assert!(m("fd00::/8", "fd12:3456::1", 443));
    assert!(!m("fd00::/8", "fe80::1", 443));
    assert!(m("[fd00::5]:6443", "fd00::5", 6443));
    assert!(!m("[fd00::5]:6443", "fd00::5", 443));
    assert!(m("fd00::5", "fd00::5", 443));
    // A CIDR never matches a name, a family mismatch never matches, and a prefix too long is no match.
    assert!(!m("10.0.0.0/8", "k8s.acme.example", 443));
    assert!(!m("10.0.0.0/8", "fd00::1", 443));
    assert!(!m("10.0.0.0/33", "10.0.0.1", 443));
    assert!(!m("10.0.0.0/zz", "10.0.0.1", 443));
    // /0 covers the family.
    assert!(m("0.0.0.0/0", "8.8.8.8", 443));
}

#[test]
fn the_matching_entry_is_returned_lower_cased() {
    assert_eq!(
        no_proxy_entry("x.test,  .ACME.example ", "k8s.acme.example", 443).as_deref(),
        Some(".acme.example")
    );
}

// ---- what rdy refuses ---------------------------------------------------------------------------------------

#[test]
fn only_an_http_proxy_is_used() {
    for (raw, shown) in [
        (
            "https://proxy.acme.example:3128",
            "https://proxy.acme.example:3128",
        ),
        (
            "socks5://proxy.acme.example:1080",
            "socks5://proxy.acme.example:1080",
        ),
        (
            "socks5h://proxy.acme.example:1080",
            "socks5h://proxy.acme.example:1080",
        ),
        ("ftp://proxy.acme.example", "ftp://proxy.acme.example"),
        (
            "http://proxy.acme.example:3128/path",
            "http://proxy.acme.example:3128",
        ),
        (
            "http://proxy.acme.example:3128/?x=1",
            "http://proxy.acme.example:3128",
        ),
        ("::not a url::", "(not a valid URL)"),
        ("http://", "http://"),
    ] {
        let error = resolve_api(Some(raw), &Env::empty()).expect_err(raw);
        assert!(
            matches!(&error, KubeError::ProxyUnsupported { proxy, origin }
                if proxy == shown && *origin == "the proxy-url in the kubeconfig"),
            "{raw}: {error:?}"
        );
        assert!(error.hint().contains("http:// proxy"), "{raw}");
    }
}

#[test]
fn the_environment_variable_is_named_when_it_is_the_one_that_fails() {
    let error =
        resolve_api(None, &env_with("socks5://proxy.acme.example:1080")).expect_err("socks");
    assert!(
        matches!(&error, KubeError::ProxyUnsupported { origin, .. } if *origin == "HTTPS_PROXY"),
        "{error:?}"
    );
    assert!(
        error.to_string().starts_with("HTTPS_PROXY names the proxy"),
        "{error}"
    );
    let hint = error.hint();
    assert!(
        hint.contains("NO_PROXY") && !hint.contains("Do not edit"),
        "{hint}"
    );
}

// ---- credentials in the proxy URL ---------------------------------------------------------------------------

#[test]
fn proxy_credentials_become_known_secrets_and_never_show() {
    let resolved = resolve_api(
        Some("http://svc-rdy:PROXY-CANARY-77@proxy.acme.example:3128"),
        &Env::empty(),
    )
    .expect("ok");
    assert_eq!(
        resolved.secrets,
        ["svc-rdy:PROXY-CANARY-77", "PROXY-CANARY-77"]
    );
    let shown = format!(
        "{:?} {:?} {}",
        resolved.used,
        resolved.used.describe(),
        resolved.used.proxy().unwrap_or_default()
    );
    assert!(!shown.contains("PROXY-CANARY"), "{shown}");
    assert!(!shown.contains("svc-rdy"), "{shown}");
    assert!(shown.contains("proxy.acme.example:3128"), "{shown}");
    // kube builds the Basic header from the authority, so the URI keeps the user info.
    assert!(
        resolved
            .uri
            .expect("a proxy")
            .to_string()
            .contains("PROXY-CANARY-77@")
    );
}

#[test]
fn percent_escapes_in_the_user_info_are_decoded_for_the_header_and_every_form_is_a_secret() {
    // The facade decodes the user info, as Go does. kube builds the Basic header from the URL as it
    // stands, so the decoded text goes into the URL it gets.
    let resolved = resolve_api(
        Some("http://svc:p%3AWORD%2B9@proxy.acme.example:3128"),
        &Env::empty(),
    )
    .expect("ok");
    let uri = resolved.uri.expect("a proxy");
    let authority = uri.authority().expect("an authority").as_str().to_owned();
    assert_eq!(authority, "svc:p:WORD+9@proxy.acme.example:3128");
    assert_eq!(uri.host(), Some("proxy.acme.example"));
    assert_eq!(uri.port_u16(), Some(3128));
    for form in [
        "svc:p%3AWORD%2B9",
        "svc:p:WORD+9",
        "p%3AWORD%2B9",
        "p:WORD+9",
    ] {
        assert!(
            resolved.secrets.iter().any(|secret| secret == form),
            "{form}: {:?}",
            resolved.secrets
        );
    }
    assert_eq!(
        resolved.used.proxy(),
        Some("http://proxy.acme.example:3128")
    );
}

#[test]
fn a_user_info_the_facade_refuses_is_refused_here_too() {
    // The same parse as the other checks: a bad escape, text that is not UTF-8 and an empty user name.
    for raw in [
        "http://svc:p%zz@proxy.acme.example:3128",
        "http://svc:p%4@proxy.acme.example:3128",
        "http://svc:%ff@proxy.acme.example:3128",
        "http://:pw@proxy.acme.example:3128",
    ] {
        let error = resolve_api(Some(raw), &Env::empty()).expect_err(raw);
        assert!(
            matches!(error, KubeError::ProxyUnsupported { .. }),
            "{raw}: {error:?}"
        );
        assert!(!format!("{error}").contains("zz"), "{error}");
    }
}

#[test]
fn a_user_info_rdy_cannot_send_exactly_is_refused_and_never_shown() {
    // An @ once decoded (kube cuts the header at the first @), and a decoded / ? or # that would end the
    // authority early and could name another host, or a line break.
    for raw in [
        "http://svc:p%40ss-CANARY@proxy.acme.example:3128",
        "http://svc:1%2Fx-CANARY@proxy.acme.example:3128",
        "http://svc:x%3Fy-CANARY@proxy.acme.example:3128",
        "http://svc:x%23y-CANARY@proxy.acme.example:3128",
        "http://svc:x%0D%0Ay-CANARY@proxy.acme.example:3128",
        "http://svc:x%20y-CANARY@proxy.acme.example:3128",
    ] {
        let error = resolve_api(Some(raw), &Env::empty()).expect_err(raw);
        assert!(
            matches!(&error, KubeError::ProxyUserInfo { proxy, .. } if proxy == "http://proxy.acme.example:3128"),
            "{raw}: {error:?}"
        );
        let shown = format!("{error} {error:?} {}", error.hint());
        assert!(
            !shown.contains("CANARY") && !shown.contains("svc"),
            "{shown}"
        );
    }
}

#[test]
fn a_proxy_without_user_info_has_no_secrets() {
    let resolved = resolve_api(Some("http://proxy.acme.example:3128"), &Env::empty()).expect("ok");
    assert!(resolved.secrets.is_empty());
    let resolved = resolve_api(
        Some("http://onlyuser@proxy.acme.example:3128"),
        &Env::empty(),
    )
    .expect("ok");
    assert_eq!(resolved.secrets, ["onlyuser"]);
}

#[test]
fn the_env_debug_hides_the_proxy_value() {
    let env = env_with("http://u:ENV-CANARY-9@proxy.acme.example:3128");
    assert!(!format!("{env:?}").contains("ENV-CANARY"));
}
