//! Test support for code outside `client` that needs real `ConnectionFacts`: a synthetic kubeconfig is
//! written to a temporary directory and loaded by the real `load_sync`, so a check's fixture test sees the
//! same facts a run would build. A check module may not touch files (INV-07), so the file work is here.

use std::fs;

use super::{ConnectionFacts, Env, KubeError, KubeOptions, from_kube_error, load_sync};

/// A kubeconfig with one context named `ctx`, a cluster at `server` with the extra cluster lines, and a
/// user entry given as indented YAML lines (`user_yaml` starts after `user:`).
pub(crate) fn kubeconfig(
    context: &str,
    server: &str,
    cluster_extra: &str,
    user_yaml: &str,
) -> String {
    format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: {context}\nclusters:\n- name: cl\n  cluster:\n    server: {server}\n{cluster_extra}contexts:\n- name: {context}\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:{user_yaml}"
    )
}

/// A CA certificate for kubeconfigs that need one. A check module may not embed a file, so it is read here.
pub(crate) fn test_ca_pem() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-ca.pem");
    fs::read_to_string(path).expect("the test CA fixture")
}

/// The `KubeError` that production builds when the network chain says `text` (for example
/// `invalid peer certificate: UnknownIssuer`), mapped by the real `from_kube_error`.
pub(crate) fn network_error(text: &str, facts: &ConnectionFacts) -> KubeError {
    network_error_kind(std::io::ErrorKind::Other, text, facts)
}

/// Like [`network_error`], for an I/O error of this kind (for example `ConnectionRefused`).
pub(crate) fn network_error_kind(
    kind: std::io::ErrorKind,
    text: &str,
    facts: &ConnectionFacts,
) -> KubeError {
    let error = kube::Error::Service(Box::new(std::io::Error::new(kind, text.to_owned())));
    from_kube_error(
        &error,
        facts.line().server(),
        facts.line().plugin(),
        facts.proxy().is_proxied(),
        facts.ca_set(),
    )
}

/// The `KubeError` for a connect that timed out, mapped by the real `from_kube_error`.
pub(crate) fn timeout_error(facts: &ConnectionFacts) -> KubeError {
    let error = kube::Error::Service(Box::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "connect timed out",
    )));
    from_kube_error(
        &error,
        facts.line().server(),
        facts.line().plugin(),
        facts.proxy().is_proxied(),
        facts.ca_set(),
    )
}

/// The facts of `yaml` loaded with `env`. Files the kubeconfig names must be in `files`
/// (`(name, text)` pairs written next to it, so a relative `certificate-authority: ca.pem` resolves).
///
/// # Panics
///
/// When the kubeconfig does not load. Tests that expect a load error call `load_sync` themselves.
pub(crate) fn facts(yaml: &str, files: &[(&str, &str)], env: &Env) -> ConnectionFacts {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, text) in files {
        fs::write(dir.path().join(name), text).expect("write a named file");
    }
    let path = dir.path().join("kubeconfig");
    fs::write(&path, yaml).expect("write the kubeconfig");
    let options = KubeOptions::new(std::time::Duration::from_secs(10)).kubeconfig(path);
    load_sync(&options, env)
        .expect("the synthetic kubeconfig loads")
        .facts()
}
