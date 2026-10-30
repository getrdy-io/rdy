//! Tests of the connection facts a load builds: the kinds of credential and their end dates, and the
//! proxy route. No socket is opened.

use rcgen::{CertificateParams, KeyPair, date_time_ymd};

use super::testkit::{facts, kubeconfig};
use super::*;

/// 2026-10-30 00:00:00 UTC.
const NOW: i64 = 1_793_318_400;
const DAY: i64 = 86_400;
/// A JWT whose `exp` is `NOW + 3 days`, and one whose `exp` is `NOW - 100 s`. The payloads are base64url
/// of `{"exp":N}`, written out so the test does not use the decoder it checks.
const JWT_IN_3_DAYS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTM1Nzc2MDB9.c2ln";
const JWT_EXPIRED: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTMzMTgzMDB9.c2ln";

fn env() -> Env {
    Env::empty().with_now(NOW)
}

fn api() -> &'static str {
    "https://k8s.acme.example:6443"
}

fn with_user(user_yaml: &str, extra: &str, env: &Env) -> ConnectionFacts {
    facts(&kubeconfig("ctx", api(), extra, user_yaml), &[], env)
}

fn cert_and_key(not_after: (i32, u8, u8)) -> (String, String) {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["admin.acme.example".to_owned()]).expect("params");
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
    let cert = params.self_signed(&key).expect("cert");
    (cert.pem(), key.serialize_pem())
}

// ---- credentials --------------------------------------------------------------------------------------------

#[test]
fn a_jwt_token_has_its_time_left() {
    let facts = with_user(&format!("\n    token: {JWT_IN_3_DAYS}\n"), "", &env());
    assert_eq!(
        facts.credentials(),
        [Credential::Token {
            expires_in: Some(3 * DAY)
        }]
    );
    let facts = with_user(&format!("\n    token: {JWT_EXPIRED}\n"), "", &env());
    assert_eq!(
        facts.credentials(),
        [Credential::Token {
            expires_in: Some(-100)
        }]
    );
}

#[test]
fn an_opaque_token_has_no_known_end() {
    let facts = with_user("\n    token: opaque-token-value\n", "", &env());
    assert_eq!(
        facts.credentials(),
        [Credential::Token { expires_in: None }]
    );
}

#[test]
fn a_token_file_is_read_for_its_exp() {
    let yaml = kubeconfig("ctx", api(), "", "\n    tokenFile: token.txt\n");
    let loaded = facts(&yaml, &[("token.txt", JWT_IN_3_DAYS)], &env());
    assert_eq!(
        loaded.credentials(),
        [Credential::Token {
            expires_in: Some(3 * DAY)
        }]
    );
}

#[test]
fn a_client_certificate_has_its_not_after() {
    let (cert, key) = cert_and_key((2026, 11, 4));
    let yaml = kubeconfig(
        "ctx",
        api(),
        "",
        "\n    client-certificate: client.crt\n    client-key: client.key\n",
    );
    let loaded = facts(
        &yaml,
        &[("client.crt", &cert), ("client.key", &key)],
        &env(),
    );
    // 2026-11-04 00:00 UTC is 5 days after NOW.
    assert_eq!(
        loaded.credentials(),
        [Credential::ClientCertificate {
            expires_in: Some(5 * DAY)
        }]
    );
}

/// Standard base64 with padding, by hand: the test must not use the decoder it checks.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                let index = usize::try_from((n >> (18 - 6 * i)) & 63).expect("six bits");
                out.push(char::from(ALPHABET[index]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn inline_certificate_data_is_read_like_a_file() {
    let (cert, key) = cert_and_key((2026, 11, 4));
    let user = format!(
        "\n    client-certificate-data: {}\n    client-key-data: {}\n",
        base64(cert.as_bytes()),
        base64(key.as_bytes())
    );
    let loaded = with_user(&user, "", &env());
    assert_eq!(
        loaded.credentials(),
        [Credential::ClientCertificate {
            expires_in: Some(5 * DAY)
        }]
    );
}

#[test]
fn a_certificate_with_no_key_is_not_a_credential() {
    // kube builds an identity only from a certificate and a key together.
    let (cert, _) = cert_and_key((2026, 11, 4));
    let user = format!(
        "\n    client-certificate-data: {}\n",
        base64(cert.as_bytes())
    );
    assert!(with_user(&user, "", &env()).credentials().is_empty());
}

#[test]
fn an_expired_client_certificate_is_negative() {
    let (cert, key) = cert_and_key((2026, 10, 1));
    let yaml = kubeconfig(
        "ctx",
        api(),
        "",
        "\n    client-certificate: client.crt\n    client-key: client.key\n",
    );
    let loaded = facts(
        &yaml,
        &[("client.crt", &cert), ("client.key", &key)],
        &env(),
    );
    assert_eq!(
        loaded.credentials(),
        [Credential::ClientCertificate {
            expires_in: Some(-29 * DAY)
        }]
    );
}

#[test]
fn a_plugin_is_a_credential_with_no_expiry_and_a_password_is_a_password() {
    let exec = "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /usr/local/bin/aws\n      args: [\"eks\", \"get-token\", \"--cluster-name\", \"acme-prod\"]\n";
    let loaded = with_user(exec, "", &env());
    assert_eq!(
        loaded.credentials(),
        [Credential::Plugin {
            binary: "aws".to_owned()
        }]
    );
    assert_eq!(loaded.credentials()[0].expires_in(), None);
    let loaded = with_user(
        "\n    username: ops\n    password: pw-value-1\n",
        "",
        &env(),
    );
    assert_eq!(loaded.credentials(), [Credential::Password]);
}

#[test]
fn a_user_with_nothing_has_no_credentials() {
    let loaded = facts(&kubeconfig("ctx", api(), "", " {}\n"), &[], &env());
    assert!(loaded.credentials().is_empty());
}

#[test]
fn the_pod_has_a_service_account_credential() {
    // The in-cluster path needs the service account files, which only a pod has. `credentials_of` is the
    // kubeconfig half; the in-cluster half is a constant, checked here against the type.
    assert_eq!(Credential::ServiceAccount.expires_in(), None);
}

// ---- the proxy route ----------------------------------------------------------------------------------------

#[test]
fn a_kubeconfig_proxy_url_goes_on_the_config_and_into_the_facts() {
    let yaml = kubeconfig(
        "ctx",
        api(),
        "    proxy-url: http://svc:PROXY-CANARY-1@proxy.acme.example:3128\n",
        "\n    token: t-1\n",
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    fs::write(&path, yaml).expect("write");
    let loaded = load_sync(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        &env(),
    )
    .expect("load");

    assert_eq!(loaded.proxy().rule(), &ProxyRule::KubeconfigProxyUrl);
    assert!(loaded.proxy().is_proxied());
    assert_eq!(
        loaded
            .config
            .proxy_url
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("http://svc:PROXY-CANARY-1@proxy.acme.example:3128/")
    );
    // The password is a known secret, and no text shows it.
    assert!(
        loaded
            .known_secrets()
            .contains(&"PROXY-CANARY-1".to_owned())
    );
    let shown = format!("{loaded:?} {:?} {}", loaded.facts(), loaded.line());
    assert!(!shown.contains("PROXY-CANARY"), "{shown}");
}

#[test]
fn the_environment_proxy_applies_to_an_https_server_and_is_reported() {
    let env = env().with_https_proxy("http://proxy.acme.example:3128");
    let yaml = kubeconfig("ctx", api(), "", "\n    token: t-1\n");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    fs::write(&path, yaml).expect("write");
    let loaded = load_sync(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        &env,
    )
    .expect("load");
    assert_eq!(
        loaded.proxy().rule(),
        &ProxyRule::Environment("HTTPS_PROXY")
    );
    assert_eq!(
        loaded
            .config
            .proxy_url
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("http://proxy.acme.example:3128/")
    );
}

#[test]
fn no_proxy_keeps_the_config_direct() {
    let env = env()
        .with_https_proxy("http://proxy.acme.example:3128")
        .with_no_proxy(".acme.example");
    let yaml = kubeconfig("ctx", api(), "", "\n    token: t-1\n");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    fs::write(&path, yaml).expect("write");
    let loaded = load_sync(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        &env,
    )
    .expect("load");
    assert!(loaded.config.proxy_url.is_none());
    assert!(!loaded.proxy().is_proxied());
    assert!(matches!(loaded.proxy().rule(), ProxyRule::Bypassed { .. }));
}

#[test]
fn the_proxy_is_not_on_the_cluster_line() {
    // The line is what the user sees before the first request; the route is in the report (ADR 0037).
    let env = env().with_https_proxy("http://proxy.acme.example:3128");
    let loaded = with_user("\n    token: t-1\n", "", &env);
    assert!(!loaded.line().to_string().contains("proxy"));
}

// ---- the cluster info a plugin is given ---------------------------------------------------------------------

const INFO_USER: &str = "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /usr/local/bin/get-token\n      provideClusterInfo: true\n";

fn plugin_cluster_proxy(loaded: &Loaded) -> Option<Option<String>> {
    loaded
        .config
        .auth_info
        .exec
        .as_ref()
        .and_then(|exec| exec.cluster.as_ref())
        .map(|cluster| cluster.proxy_url.clone())
}

fn load_text(yaml: &str, env: &Env) -> Result<Loaded, KubeError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    fs::write(&path, yaml).expect("write");
    load_sync(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        env,
    )
}

#[test]
fn the_plugin_cluster_info_carries_the_real_proxy_url_never_the_placeholder() {
    // `kubectl` passes the cluster's own `proxy-url` to a plugin that asks for the cluster
    // (`provideClusterInfo`). kube builds that copy after the placeholder was written to the cluster.
    let with = kubeconfig(
        "ctx",
        api(),
        "    proxy-url: http://proxy.acme.example:3128\n",
        INFO_USER,
    );
    let loaded = load_text(&with, &env()).expect("load");
    assert_eq!(
        plugin_cluster_proxy(&loaded),
        Some(Some("http://proxy.acme.example:3128".to_owned()))
    );
    // No `proxy-url`: the plugin gets none, whatever the environment says.
    let without = kubeconfig("ctx", api(), "", INFO_USER);
    let env = env().with_https_proxy("http://env-proxy.acme.example:3128");
    let loaded = load_text(&without, &env).expect("load");
    assert_eq!(plugin_cluster_proxy(&loaded), Some(None));
    for yaml in [&with, &without] {
        let loaded = load_text(yaml, &env).expect("load");
        assert!(
            !format!("{:?}", plugin_cluster_proxy(&loaded)).contains(".invalid"),
            "the placeholder must not reach the plugin"
        );
    }
}

#[test]
fn a_proxy_url_for_an_http_server_fails_the_load_with_its_own_error() {
    let yaml = kubeconfig(
        "ctx",
        "http://k8s.acme.example:8080",
        "    proxy-url: http://svc:PLAIN-CANARY-6@proxy.acme.example:3128\n",
        "\n    token: t-1\n",
    );
    let error = load_text(&yaml, &env()).expect_err("a plain server behind a proxy");
    assert!(
        matches!(&error, KubeError::ProxyPlainServer { proxy, .. } if proxy == "http://proxy.acme.example:3128"),
        "{error:?}"
    );
    let shown = format!("{error} | {error:?} | {}", error.hint());
    assert!(!shown.contains("PLAIN-CANARY"), "{shown}");
}
