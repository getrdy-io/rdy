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
    load_sync(&options().kubeconfig(path), &Env::empty())
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

    let loaded = load_sync(&options().kubeconfig(&flag), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://flag.example");
    assert_eq!(loaded.source(), &Source::Flag(flag.clone()));
    assert_eq!(loaded.source().label(), "--kubeconfig");
    assert_eq!(loaded.files(), [flag]);

    let loaded = load_sync(&options(), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://env.example");
    assert_eq!(loaded.source().label(), "KUBECONFIG");

    let env = Env::empty().with_home(&home);
    let loaded = load_sync(&options(), &env).expect("load");
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

    let error =
        load_sync(&options().kubeconfig(dir.path().join("nope")), &env).expect_err("missing");
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

    let loaded = load_sync(&options(), &env).expect("load");
    assert_eq!(loaded.line().server(), "https://first.example");
    assert_eq!(loaded.line().context(), "ctx");
    assert_eq!(loaded.files(), [first, second]);
}

#[test]
fn nothing_found_is_no_kubeconfig_with_the_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = Env::empty().with_home(dir.path());
    let error = load_sync(&options(), &env).expect_err("none");
    assert!(matches!(error, KubeError::NoKubeconfig), "{error:?}");
    assert_eq!(error.detail(), "no kubeconfig found");
    // The exact text: the distro paths are for Linux only (07 section 11).
    let plain = "Pass --kubeconfig <file> or set KUBECONFIG.";
    if cfg!(target_os = "linux") {
        assert_eq!(
            error.hint(),
            format!(
                "{plain} k3s keeps one at /etc/rancher/k3s/k3s.yaml, RKE2 at /etc/rancher/rke2/rke2.yaml and kubeadm at /etc/kubernetes/admin.conf. They are root-only: copy one to ~/.kube/config and chmod 600 it."
            )
        );
    } else {
        assert_eq!(error.hint(), plain);
    }

    // No home, no variable, no in-cluster fallback.
    let error = load_sync(&options(), &Env::empty()).expect_err("none");
    assert!(matches!(error, KubeError::NoKubeconfig), "{error:?}");
}

#[test]
fn an_empty_kubeconfig_variable_counts_as_unset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = Env::empty()
        .with_kubeconfig_var(OsString::new())
        .with_home(dir.path());
    let error = load_sync(&options(), &env).expect_err("none");
    assert!(matches!(error, KubeError::NoKubeconfig), "{error:?}");
}

#[test]
fn a_context_flag_in_a_pod_is_refused_not_ignored() {
    let error = load_sync(&options().context("prod"), &Env::empty().with_in_cluster())
        .expect_err("refused");
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

    let loaded = load_sync(&options().kubeconfig(&path), &Env::empty()).expect("load");
    assert_eq!(loaded.line().context(), "ctx");
    assert_eq!(loaded.line().server(), "https://one.example");

    let loaded = load_sync(
        &options().kubeconfig(&path).context("second"),
        &Env::empty(),
    )
    .expect("load");
    assert_eq!(loaded.line().context(), "second");
    assert_eq!(loaded.line().server(), "https://two.example");

    let error = load_sync(&options().kubeconfig(&path).context("nope"), &Env::empty())
        .expect_err("unknown");
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
    assert!(shown.contains("evil\\x1b[2J"), "{shown}");
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
    assert!(
        matches!(&error, KubeError::ProxyUnsupported { proxy } if proxy == "http://proxy.example:3128"),
        "{error:?}"
    );
    let shown = format!("{error} {error:?} {}", error.hint());
    assert!(!shown.contains("PROXYCANARY"), "{shown}");
    assert!(!shown.contains("user:"), "{shown}");
    assert!(shown.contains("proxy.example:3128"), "{shown}");
    assert!(
        error.hint().contains("Do not edit your working kubeconfig")
            && error.hint().contains("--kubeconfig"),
        "{}",
        error.hint()
    );
}

#[test]
fn a_proxy_url_is_shown_as_scheme_host_and_port_only() {
    for (raw, want) in [
        ("http://u:p@h.example:3128/x?y=1#z", "http://h.example:3128"),
        ("socks5://h.example:1080", "socks5://h.example:1080"),
        ("http://a@b@h.example", "http://h.example"),
        ("not a url", "(not a valid URL)"),
    ] {
        assert_eq!(proxy_display(raw), want, "{raw}");
    }
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
    let error = load_sync(&options().kubeconfig(dir.path()), &Env::empty()).expect_err("directory");
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
    let error = load_sync(&options().kubeconfig(&path), &Env::empty()).expect_err("big");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if reason.contains("8 MiB")),
        "{error:?}"
    );
}

#[test]
fn the_limits_come_from_the_check_timeout_and_are_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), "config", &simple(Some("ctx")));

    let loaded = load_sync(
        &KubeOptions::new(Duration::from_secs(7)).kubeconfig(&path),
        &Env::empty(),
    )
    .expect("load");
    assert_eq!(loaded.config.connect_timeout, Some(Duration::from_secs(7)));
    assert_eq!(loaded.config.read_timeout, Some(Duration::from_secs(7)));
    assert_eq!(loaded.config.write_timeout, Some(Duration::from_secs(7)));
    assert!(!loaded.config.default_retry);
    assert!(loaded.config.proxy_url.is_none());

    let loaded = load_sync(
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

// ---- the plugin: terminal use and environment ------------------------------------------------------------

/// A user entry with an exec plugin. `mode` is the `interactiveMode` line, when there is one.
fn exec_user(mode: Option<&str>) -> String {
    let mode = mode.map_or_else(String::new, |mode| {
        format!("      interactiveMode: {mode}\n")
    });
    format!(
        "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /opt/bin/get-token\n      args: [\"--flag\", \"value\\u001b\"]\n{mode}"
    )
}

fn load_exec(mode: Option<&str>, env: &Env) -> Loaded {
    let dir = tempfile::tempdir().expect("tempdir");
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "",
        &exec_user(mode),
    );
    let path = write(dir.path(), "config", &text);
    load_sync(&options().kubeconfig(path), env).expect("load")
}

fn mode_of(loaded: &Loaded) -> Option<ExecInteractiveMode> {
    loaded
        .config
        .auth_info
        .exec
        .as_ref()
        .expect("exec")
        .interactive_mode
        .clone()
}

#[test]
fn a_plugin_is_never_interactive_without_both_terminals() {
    let terminal = Env::empty().with_terminal();
    let mut only_stdin = Env::empty();
    only_stdin.stdin_is_terminal = true;
    let mut only_stderr = Env::empty();
    only_stderr.stderr_is_terminal = true;

    for mode in [None, Some("IfAvailable"), Some("Always"), Some("Never")] {
        for env in [&Env::empty(), &only_stdin, &only_stderr] {
            let loaded = load_exec(mode, env);
            assert!(
                matches!(mode_of(&loaded), Some(ExecInteractiveMode::Never)),
                "{mode:?} stayed interactive without a terminal"
            );
        }
    }
    // With both terminals the kubeconfig's own choice stands, as in client-go.
    assert!(mode_of(&load_exec(None, &terminal)).is_none());
    assert!(matches!(
        mode_of(&load_exec(Some("IfAvailable"), &terminal)),
        Some(ExecInteractiveMode::IfAvailable)
    ));
    assert!(matches!(
        mode_of(&load_exec(Some("Always"), &terminal)),
        Some(ExecInteractiveMode::Always)
    ));
    assert!(matches!(
        mode_of(&load_exec(Some("Never"), &terminal)),
        Some(ExecInteractiveMode::Never)
    ));
}

#[test]
fn a_plugin_does_not_inherit_the_rdy_secrets() {
    let env = Env::empty()
        .with_rdy_var("RDY_EXTERNAL_ID_PROD")
        .with_rdy_var("RDY_TOKEN");
    let loaded = load_exec(Some("Never"), &env);
    let dropped = loaded
        .config
        .auth_info
        .exec
        .as_ref()
        .and_then(|exec| exec.drop_env.clone())
        .expect("drop_env");
    for name in ["RDY_TOKEN", "RDY_KEY_PASSWORD", "RDY_EXTERNAL_ID_PROD"] {
        assert_eq!(
            dropped.iter().filter(|dropped| *dropped == name).count(),
            1,
            "{name} in {dropped:?}"
        );
    }
    // The plugins of the cloud providers need their own credentials.
    assert!(!dropped.iter().any(|name| name.starts_with("AWS_")));
}

#[test]
fn the_plugin_command_and_args_are_there_for_the_action_log() {
    let loaded = load_exec(None, &Env::empty());
    let exec = loaded.plugin_exec().expect("plugin");
    assert_eq!(exec.command(), "/opt/bin/get-token");
    assert_eq!(exec.args(), ["--flag", "value\\x1b"]);
    let shown = format!("{exec:?} {loaded:?}");
    assert!(!shown.contains("--flag"), "{shown}");
    assert!(shown.contains("[2 hidden]"), "{shown}");
    let plain = load_one(&simple(Some("ctx"))).expect("load");
    assert!(plain.plugin_exec().is_none());
}

// ---- files and secrets ------------------------------------------------------------------------------------

fn ca_fixture(dir: &Path) -> PathBuf {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-ca.pem");
    let pem = fs::read_to_string(fixture).expect("fixture");
    write(dir, "ca.pem", &pem)
}

#[test]
fn files_lists_every_file_kube_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    ca_fixture(dir.path());
    write(dir.path(), "client.crt", "cert");
    write(dir.path(), "client.key", "KEYCANARY\n");
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "    certificate-authority: ca.pem\n",
        "    client-certificate: client.crt\n    client-key: client.key\n",
    );
    let path = write(dir.path(), "config", &text);

    let loaded = load_sync(&options().kubeconfig(&path), &Env::empty()).expect("load");

    assert_eq!(
        loaded.files(),
        [
            path,
            dir.path().join("ca.pem"),
            dir.path().join("client.crt"),
            dir.path().join("client.key"),
        ]
    );
    assert_eq!(loaded.known_secrets(), ["KEYCANARY"]);
}

#[test]
fn a_token_file_is_listed_and_its_value_is_a_known_secret_but_an_inline_token_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "token", "FILE-TOKEN\n");
    let file_user = "    tokenFile: token\n";
    let path = write(
        dir.path(),
        "config",
        &kubeconfig_yaml(Some("ctx"), "https://prod.example:6443", "", file_user),
    );
    let loaded = load_sync(&options().kubeconfig(&path), &Env::empty()).expect("load");
    assert_eq!(loaded.files(), [path.clone(), dir.path().join("token")]);
    assert_eq!(loaded.known_secrets(), ["FILE-TOKEN"]);

    let both = "    token: INLINE-TOKEN\n    tokenFile: token\n";
    let path = write(
        dir.path(),
        "config2",
        &kubeconfig_yaml(Some("ctx"), "https://prod.example:6443", "", both),
    );
    let loaded = load_sync(&options().kubeconfig(&path), &Env::empty()).expect("load");
    assert_eq!(loaded.files(), [path]);
    assert_eq!(loaded.known_secrets(), ["INLINE-TOKEN"]);
}

/// Standard base64, for the one test that needs `certificate-authority-data`.
fn base64_of(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(TABLE[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn inline_data_wins_over_a_path_and_the_path_is_not_listed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pem = fs::read_to_string(ca_fixture(dir.path())).expect("ca");
    let extra = format!(
        "    certificate-authority-data: {}\n    certificate-authority: gone.pem\n",
        base64_of(pem.as_bytes())
    );
    let path = write(
        dir.path(),
        "config",
        &kubeconfig_yaml(
            Some("ctx"),
            "https://prod.example:6443",
            &extra,
            &token_user("t"),
        ),
    );
    let loaded = load_sync(&options().kubeconfig(&path), &Env::empty()).expect("load");
    assert_eq!(loaded.files(), [path]);
}

#[test]
fn a_file_kube_would_read_must_be_a_regular_small_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A directory as the CA.
    fs::create_dir(dir.path().join("ca.d")).expect("mkdir");
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "    certificate-authority: ca.d\n",
        &token_user("t"),
    );
    let error = load_sync(
        &options().kubeconfig(write(dir.path(), "c1", &text)),
        &Env::empty(),
    )
    .expect_err("directory");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if reason.contains("not a regular file")),
        "{error:?}"
    );

    // A token file over the cap.
    let big = fs::File::create(dir.path().join("big")).expect("create");
    big.set_len(MAX_FILE_BYTES + 1).expect("set_len");
    drop(big);
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "",
        "    tokenFile: big\n",
    );
    let error = load_sync(
        &options().kubeconfig(write(dir.path(), "c2", &text)),
        &Env::empty(),
    )
    .expect_err("big");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if reason.contains("1 MiB")),
        "{error:?}"
    );

    // A client key that is not there.
    let text = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "",
        "    client-certificate-data: eA==\n    client-key: missing.key\n",
    );
    let error = load_sync(
        &options().kubeconfig(write(dir.path(), "c3", &text)),
        &Env::empty(),
    )
    .expect_err("missing");
    assert!(
        matches!(&error, KubeError::KubeconfigUnreadable { reason, .. } if *reason == "no such file"),
        "{error:?}"
    );
}

// ---- hints ----------------------------------------------------------------------------------------------

#[test]
fn the_no_kubeconfig_hint_names_the_distro_files_and_so_does_permission_denied() {
    let hint = KubeError::NoKubeconfig.hint();
    let denied = KubeError::KubeconfigUnreadable {
        path: "x".to_owned(),
        reason: "permission denied",
    };
    if !cfg!(target_os = "linux") {
        assert!(!hint.contains("k3s") && !denied.hint().contains("k3s"));
        return;
    }
    for part in [
        "/etc/rancher/k3s/k3s.yaml",
        "/etc/rancher/rke2/rke2.yaml",
        "/etc/kubernetes/admin.conf",
        "root-only",
        "chmod 600",
    ] {
        assert!(hint.contains(part), "{part} missing from {hint}");
    }
    assert!(denied.hint().contains("/etc/rancher/k3s/k3s.yaml"));
    let other = KubeError::KubeconfigUnreadable {
        path: "x".to_owned(),
        reason: "no such file",
    };
    assert!(!other.hint().contains("k3s"));
}

#[test]
fn each_auth_provider_gets_its_own_hint_and_oidc_makes_no_false_claim() {
    let hint = |name: &str| {
        KubeError::AuthProviderUnsupported {
            name: name.to_owned(),
        }
        .hint()
    };
    assert!(hint("gcp").contains("gke-gcloud-auth-plugin"));
    assert!(hint("azure").contains("kubelogin convert-kubeconfig -l azurecli"));
    let oidc = hint("oidc");
    assert!(
        oidc.contains("does not run the oidc auth-provider yet"),
        "{oidc}"
    );
    assert!(!oidc.contains("kubectl"), "{oidc}");
    assert!(!oidc.contains("1.26"), "{oidc}");
    assert!(hint("other").contains("exec credential plugin"));
}

#[test]
fn the_proxy_environment_note_shows_only_when_it_applies() {
    let note = "HTTPS_PROXY is set; rdy does not use it for the cluster yet.";
    for proxy_env_set in [false, true] {
        let timeout = KubeError::Timeout {
            server: "https://a".to_owned(),
            proxy_env_set,
        };
        let unreachable = KubeError::Unreachable {
            server: "https://a".to_owned(),
            cause: "the connection failed",
            proxy_env_set,
            ca_set: true,
        };
        assert_eq!(timeout.hint().contains(note), proxy_env_set);
        assert_eq!(unreachable.hint().contains(note), proxy_env_set);
        assert!(timeout.hint().contains("VPN"));
    }
}

#[test]
fn the_403_hint_does_not_blame_the_identity() {
    let hint = KubeError::Forbidden {
        server: "https://a".to_owned(),
    }
    .hint();
    assert!(hint.contains("system:public-info-viewer"), "{hint}");
    assert!(!hint.contains("read-only role"), "{hint}");
}

// ---- other rules -----------------------------------------------------------------------------------------

#[test]
fn the_namespace_of_a_context_is_not_used_or_shown() {
    let text = "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: https://prod.example\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\n    namespace: other-ns\nusers:\n- name: usr\n  user:\n    token: t\n";
    let loaded = load_one(text).expect("load");
    let shown = format!("{} {:?} {:?}", loaded.line(), loaded.line(), loaded);
    assert!(!shown.contains("other-ns"), "{shown}");
    // kube's config does not hold it either.
    assert!(loaded.config.default_namespace.is_empty());
}

#[test]
fn the_in_cluster_config_needs_the_service_account_files() {
    if Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists() {
        return; // The tests are running inside a pod.
    }
    let error = load_sync(&options(), &Env::empty().with_in_cluster()).expect_err("no files");
    assert!(
        matches!(&error, KubeError::InClusterUnusable { what } if what.contains("token")),
        "{error:?}"
    );
    assert!(error.hint().contains("automountServiceAccountToken"));
    // The error is not "no kubeconfig": that hint would be wrong inside a pod.
    assert!(!matches!(error, KubeError::NoKubeconfig));
}

#[tokio::test]
async fn the_async_load_gives_the_same_answer_as_the_sync_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), "config", &simple(Some("ctx")));
    let loaded = load(&options().kubeconfig(&path), &Env::empty())
        .await
        .expect("load");
    assert_eq!(loaded.line().server(), "https://prod.example:6443");
    assert_eq!(loaded.files(), [path]);
}

#[test]
fn an_unknown_issuer_hint_depends_on_whether_the_kubeconfig_has_a_ca() {
    let unknown = |ca_set| {
        KubeError::Unreachable {
            server: "https://a".to_owned(),
            cause: "the server certificate is signed by an authority that is not trusted (UnknownIssuer)",
            proxy_env_set: false,
            ca_set,
        }
        .hint()
    };
    let without = unknown(false);
    assert!(
        without.contains("names no certificate authority"),
        "{without}"
    );
    assert!(without.contains("not this machine's store"), "{without}");
    assert!(without.contains("--kubeconfig"), "{without}");
    assert!(!without.contains("VPN"), "{without}");
    let with = unknown(true);
    assert!(with.contains("does not match this server"), "{with}");
    assert!(with.contains("net.tls_intercept"), "{with}");
    // Another cause keeps the network hint.
    let other = KubeError::Unreachable {
        server: "https://a".to_owned(),
        cause: "the connection was refused",
        proxy_env_set: false,
        ca_set: false,
    };
    assert!(other.hint().contains("VPN"));
}

#[test]
fn the_ca_state_comes_from_the_kubeconfig() {
    let dir = tempfile::tempdir().expect("tempdir");
    ca_fixture(dir.path());
    let with_ca = kubeconfig_yaml(
        Some("ctx"),
        "https://prod.example:6443",
        "    certificate-authority: ca.pem\n",
        &token_user("t"),
    );
    let path = write(dir.path(), "config", &with_ca);
    let loaded = load_sync(&options().kubeconfig(path), &Env::empty()).expect("load");
    assert!(loaded.ca_set);
    assert!(!load_one(&simple(Some("ctx"))).expect("load").ca_set);
}

#[test]
fn rustls_wording_maps_to_the_fixed_phrases() {
    use super::error::cause_words;
    // The Display text of rustls 0.23.
    let name = cause_words(
        "invalid peer certificate: certificate not valid for name \"127.0.0.1\"",
        None,
    );
    assert!(name.contains("NotValidForName"), "{name}");
    let early = cause_words("invalid peer certificate: certificate not valid yet", None);
    assert!(early.contains("NotValidYet"), "{early}");
    let old = cause_words("invalid peer certificate: expired", None);
    assert!(old.contains("Expired"), "{old}");
}

#[test]
fn a_secret_looking_exec_env_value_is_a_known_secret() {
    let user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /opt/bin/get-token\n      env:\n      - name: API_TOKEN\n        value: ENVSECRET-12345\n      - name: AWS_PROFILE\n        value: prod-profile\n";
    let text = kubeconfig_yaml(Some("ctx"), "https://prod.example:6443", "", user);
    let loaded = load_one(&text).expect("load");
    assert_eq!(loaded.known_secrets(), ["ENVSECRET-12345"]);
}

#[test]
fn rdy_variable_names_are_matched_by_case_where_the_os_does() {
    for insensitive in [false, true] {
        assert!(is_rdy_var("RDY_TOKEN", insensitive));
        assert!(!is_rdy_var("RDX_TOKEN", insensitive));
        assert!(!is_rdy_var("RDY", insensitive));
        // A multi-byte character across byte 4 must not panic.
        assert!(!is_rdy_var("abc\u{e9}", insensitive));
        assert!(!is_rdy_var("\u{e9}\u{e9}\u{e9}", insensitive));
    }
    assert!(!is_rdy_var("rdy_token", false));
    assert!(is_rdy_var("rdy_token", true));
    assert!(is_rdy_var("Rdy_Token", true));
}
