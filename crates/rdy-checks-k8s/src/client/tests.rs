//! Tests of `load`: sources, contexts, the cluster line, refusals and the limits. No socket is opened.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;

const TIMEOUT: Duration = Duration::from_secs(10);

/// A kubeconfig with one context named `ctx` that uses `server` and the user YAML `user`.
fn kubeconfig_yaml(current: Option<&str>, server: &str, extra_cluster: &str, user: &str) -> String {
    let current = current.map_or_else(String::new, |name| format!("current-context: {name}\n"));
    format!(
        "apiVersion: v1\nkind: Config\n{current}clusters:\n- name: cl\n  cluster:\n    server: {server}\n{extra_cluster}contexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n{user}"
    )
}

fn token_user(token: &str) -> String {
    format!("    token: {token}\n")
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).expect("write fixture");
    path
}

fn options() -> KubeOptions {
    KubeOptions::new(TIMEOUT)
}

fn load_one(text: &str) -> Result<Loaded, KubeError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), "config", text);
    load(&options().kubeconfig(path), &Env::empty())
}

fn simple(current: Option<&str>) -> String {
    kubeconfig_yaml(
        current,
        "https://prod.example:6443",
        "",
        &token_user("tok-1"),
    )
}

#[test]
fn the_flag_file_wins_over_kubeconfig_and_the_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let flag = write(
        dir.path(),
        "flag",
        &kubeconfig_yaml(Some("ctx"), "https://flag.example", "", &token_user("a")),
    );
    let env_file = write(
        dir.path(),
        "env",
        &kubeconfig_yaml(Some("ctx"), "https://env.example", "", &token_user("b")),
    );
    let home = dir.path().join("home");
    fs::create_dir_all(home.join(".kube")).expect("mkdir");
    write(
        &home.join(".kube"),
        "config",
        &kubeconfig_yaml(Some("ctx"), "https://default.example", "", &token_user("c")),
    );
    let env = Env::empty()
        .with_kubeconfig_var(env_file.as_os_str())
        .with_home(&home);

    let loaded = load(&options().kubeconfig(&flag), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://flag.example");
    assert_eq!(loaded.source(), &Source::Flag(flag.clone()));
    assert_eq!(loaded.source().label(), "--kubeconfig");
    assert_eq!(loaded.files(), [flag]);

    let loaded = load(&options(), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://env.example");
    assert_eq!(loaded.source().label(), "KUBECONFIG");

    let env = Env::empty().with_home(&home);
    let loaded = load(&options(), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://default.example");
    assert_eq!(loaded.source().label(), "~/.kube/config");
}

#[test]
fn a_missing_flag_file_is_an_error_and_does_not_fall_through() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    fs::create_dir_all(home.join(".kube")).expect("mkdir");
    write(&home.join(".kube"), "config", &simple(Some("ctx")));
    let env = Env::empty().with_home(&home);

    let error = load(&options().kubeconfig(dir.path().join("nope")), &env).expect_err("missing");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if *reason == "no such file"),
        "{error:?}"
    );
    assert!(!error.hint().is_empty());
}

#[test]
fn kubeconfig_lists_merge_with_the_first_file_winning_and_skip_missing_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = write(
        dir.path(),
        "one",
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: https://first.example\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\n",
    );
    let second = write(
        dir.path(),
        "two",
        &kubeconfig_yaml(
            Some("other"),
            "https://second.example",
            "",
            &token_user("t"),
        ),
    );
    let missing = dir.path().join("missing");
    let list = std::env::join_paths([&missing, &first, &second]).expect("join");
    let env = Env::empty().with_kubeconfig_var(list);

    let loaded = load(&options(), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://first.example");
    assert_eq!(loaded.line().context(), "ctx");
    assert_eq!(loaded.files(), [first, second]);
}

#[test]
fn nothing_found_is_no_kubeconfig_with_the_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = Env::empty().with_home(dir.path());
    let error = load(&options(), &env).expect_err("none");
    assert!(matches!(error, KubeError::NoKubeconfig), "{error:?}");
    assert_eq!(error.detail(), "no kubeconfig found");
    assert_eq!(error.hint(), "Pass --kubeconfig <file> or set KUBECONFIG.");

    // No home, no variable, no in-cluster fallback.
    let error = load(&options(), &Env::empty()).expect_err("none");
    assert!(matches!(error, KubeError::NoKubeconfig), "{error:?}");
}

#[test]
fn an_empty_kubeconfig_variable_counts_as_unset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = Env::empty()
        .with_kubeconfig_var(OsString::new())
        .with_home(dir.path());
    let error = load(&options(), &env).expect_err("none");
    assert!(matches!(error, KubeError::NoKubeconfig), "{error:?}");
}

#[test]
fn a_context_flag_in_a_pod_is_refused_not_ignored() {
    let error =
        load(&options().context("prod"), &Env::empty().with_in_cluster()).expect_err("refused");
    assert!(
        matches!(error, KubeError::ContextNotFound { .. }),
        "{error:?}"
    );
    assert!(
        error.hint().contains("Leave out --kube-context"),
        "{}",
        error.hint()
    );
}

#[test]
fn the_context_flag_picks_the_context_and_an_unknown_one_lists_the_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let text = "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: https://one.example\n- name: cl2\n  cluster:\n    server: https://two.example\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\n- name: second\n  context:\n    cluster: cl2\n    user: usr\nusers:\n- name: usr\n  user:\n    token: t\n";
    let path = write(dir.path(), "config", text);

    let loaded = load(&options().kubeconfig(&path), &Env::empty()).expect("load");
    assert_eq!(loaded.line().context(), "ctx");
    assert_eq!(loaded.line().server(), "https://one.example");

    let loaded = load(
        &options().kubeconfig(&path).context("second"),
        &Env::empty(),
    )
    .expect("load");
    assert_eq!(loaded.line().context(), "second");
    assert_eq!(loaded.line().server(), "https://two.example");

    let error =
        load(&options().kubeconfig(&path).context("nope"), &Env::empty()).expect_err("unknown");
    assert!(
        matches!(&error, KubeError::ContextNotFound { name, .. } if name == "nope"),
        "{error:?}"
    );
    assert!(error.hint().contains("ctx, second"), "{}", error.hint());
}

#[test]
fn no_current_context_lists_the_names() {
    let error = load_one(&simple(None)).expect_err("no current context");
    assert!(
        matches!(&error, KubeError::NoCurrentContext { available } if available == &["ctx"]),
        "{error:?}"
    );
    assert!(error.hint().contains("--kube-context"), "{}", error.hint());
}

#[test]
fn the_server_loses_user_info_query_and_fragment_but_keeps_a_path_prefix() {
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://admin:hunter2@rancher.example:8443/k8s/clusters/c-m-1/?x=1",
        "",
        &token_user("t"),
    );
    let loaded = load_one(&text).expect("load");
    assert_eq!(
        loaded.line().server(),
        "https://rancher.example:8443/k8s/clusters/c-m-1"
    );
    let shown = format!("{} {:?} {:?}", loaded.line(), loaded.line(), loaded);
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(!shown.contains("admin:"), "{shown}");
}

#[test]
fn the_line_shows_context_server_and_user() {
    let loaded = load_one(&simple(Some("ctx"))).expect("load");
    assert_eq!(loaded.line().user(), Some("usr"));
    assert_eq!(
        loaded.line().to_string(),
        "ctx, https://prod.example:6443, user usr"
    );
    assert!(!loaded.line().tls_verification_off());
}

#[test]
fn insecure_skip_tls_verify_shows_on_the_line() {
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "    insecure-skip-tls-verify: true\n",
        &token_user("t"),
    );
    let loaded = load_one(&text).expect("load");
    assert!(loaded.line().tls_verification_off());
    assert!(
        loaded
            .line()
            .to_string()
            .ends_with(", TLS verification is OFF"),
        "{}",
        loaded.line()
    );
}

#[test]
fn an_exec_plugin_is_named_by_its_file_name_and_never_its_arguments() {
    let user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /opt/bin/get-token\n      args: [\"--secret-arg=ARGCANARY\"]\n      env:\n      - name: TOKEN_SEED\n        value: ENVCANARY\n      interactiveMode: Never\n";
    let text = kubeconfig_yaml(Some("ctx"), "https://prod.example:6443", "", user);
    let loaded = load_one(&text).expect("load");
    assert_eq!(loaded.line().plugin(), Some("get-token"));
    assert_eq!(
        loaded.line().to_string(),
        "ctx, https://prod.example:6443, user usr, credential plugin: get-token"
    );
    let shown = format!("{} {:?} {:?}", loaded.line(), loaded.line(), loaded);
    assert!(!shown.contains("ARGCANARY"), "{shown}");
    assert!(!shown.contains("ENVCANARY"), "{shown}");
}

#[test]
fn control_characters_in_names_cannot_reach_the_terminal() {
    let text = "apiVersion: v1\nkind: Config\ncurrent-context: \"evil\\e[2J\"\nclusters:\n- name: cl\n  cluster:\n    server: https://prod.example\ncontexts:\n- name: \"evil\\e[2J\"\n  context:\n    cluster: cl\n    user: \"u\\u202esr\"\nusers:\n- name: \"u\\u202esr\"\n  user:\n    token: t\n";
    let loaded = load_one(text).expect("load");
    let shown = loaded.line().to_string();
    assert!(!shown.contains('\u{1b}'), "{shown:?}");
    assert!(!shown.contains('\u{202e}'), "{shown:?}");
    assert!(shown.contains("evil\\u{001b}[2J"), "{shown}");
}

#[test]
fn a_cluster_proxy_url_is_refused_with_a_hint() {
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "    proxy-url: http://user:PROXYCANARY@proxy.example:3128\n",
        &token_user("t"),
    );
    let error = load_one(&text).expect_err("proxy");
    assert!(matches!(error, KubeError::ProxyUnsupported), "{error:?}");
    let shown = format!("{error} {error:?} {}", error.hint());
    assert!(!shown.contains("PROXYCANARY"), "{shown}");
}

#[test]
fn a_legacy_auth_provider_is_refused() {
    let user =
        "    auth-provider:\n      name: gcp\n      config:\n        cmd-path: /tmp/CMDCANARY\n";
    let text = kubeconfig_yaml(Some("ctx"), "https://prod.example:6443", "", user);
    let error = load_one(&text).expect_err("auth provider");
    assert!(
        matches!(&error, KubeError::AuthProviderUnsupported { name } if name == "gcp"),
        "{error:?}"
    );
    let shown = format!("{error} {error:?} {}", error.hint());
    assert!(!shown.contains("CMDCANARY"), "{shown}");
}

#[test]
fn a_context_with_a_missing_cluster_is_incomplete() {
    let text = "apiVersion: v1\nkind: Config\ncurrent-context: ctx\ncontexts:\n- name: ctx\n  context:\n    cluster: ghost\n    user: usr\n";
    let error = load_one(text).expect_err("no cluster");
    assert!(
        matches!(error, KubeError::IncompleteKubeconfig { .. }),
        "{error:?}"
    );
}

#[test]
fn a_cluster_without_a_server_is_incomplete() {
    let text = "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster: {}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\n";
    let error = load_one(text).expect_err("no server");
    assert!(
        matches!(&error, KubeError::IncompleteKubeconfig { what } if what.contains("no server URL")),
        "{error:?}"
    );
}

#[test]
fn a_parse_error_never_quotes_the_file() {
    let error =
        load_one("apiVersion: v1\ntoken: PARSECANARY\n  bad: [unclosed\n").expect_err("invalid");
    assert!(
        matches!(error, KubeError::KubeconfigInvalid { .. }),
        "{error:?}"
    );
    let shown = format!("{error} {error:?} {}", error.hint());
    assert!(!shown.contains("PARSECANARY"), "{shown}");
}

#[test]
fn a_directory_is_not_read_as_a_kubeconfig() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = load(&options().kubeconfig(dir.path()), &Env::empty()).expect_err("directory");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if reason.contains("not a regular file")),
        "{error:?}"
    );
}

#[test]
fn a_huge_file_is_refused_before_it_is_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big");
    let file = fs::File::create(&path).expect("create");
    file.set_len(MAX_KUBECONFIG_BYTES + 1).expect("set_len");
    drop(file);
    let error = load(&options().kubeconfig(&path), &Env::empty()).expect_err("big");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if reason.contains("8 MiB")),
        "{error:?}"
    );
}

#[test]
fn the_limits_come_from_the_check_timeout_and_are_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), "config", &simple(Some("ctx")));

    let loaded = load(
        &KubeOptions::new(Duration::from_secs(7)).kubeconfig(&path),
        &Env::empty(),
    )
    .expect("load");
    assert_eq!(loaded.config.connect_timeout, Some(Duration::from_secs(7)));
    assert_eq!(loaded.config.read_timeout, Some(Duration::from_secs(7)));
    assert_eq!(loaded.config.write_timeout, Some(Duration::from_secs(7)));
    assert!(!loaded.config.default_retry);
    assert!(loaded.config.proxy_url.is_none());

    let loaded = load(
        &KubeOptions::new(Duration::from_secs(600)).kubeconfig(&path),
        &Env::empty(),
    )
    .expect("load");
    assert_eq!(loaded.config.connect_timeout, Some(MAX_TIMEOUT));
    assert_eq!(loaded.config.read_timeout, Some(MAX_TIMEOUT));
}

#[test]
fn debug_output_never_shows_credentials() {
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "",
        &token_user("TOKENCANARY"),
    );
    let loaded = load_one(&text).expect("load");
    let shown = format!("{loaded:?} {:?}", loaded.line());
    assert!(!shown.contains("TOKENCANARY"), "{shown}");
}
