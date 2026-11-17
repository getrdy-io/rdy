//! `rdy run` reads the proxy from the environment (M1-097).
//!
//! `HTTPS_PROXY` and `HTTP_PROXY`, either case, go into the probe hub after it is built and before the
//! privilege snapshot, which is the first probe read and the point after which the proxy can no longer
//! be set (`ProxyError::TooLate`). A proxied run that ends with exit 0 shows the order is right. A
//! password the known-secret set refuses is exit 70, and a URL that does not parse is exit 64 with a fix.
//!
//! The proxy is an in-process scripted server on the replay backend: no socket is opened.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use rdy_cli::RunHooks;
use rdy_engine::testing::{Replay, TcpScript};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

/// The planted proxy password, and the base64 of `svc:` and the password.
const PASSWORD: &str = "longer-canary-pw";
const PAIR: &str = "c3ZjOmxvbmdlci1jYW5hcnktcHc=";
const PROXY_URL: &str = "http://svc:longer-canary-pw@proxy.acme.test:3128";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("not UTF-8: {e}"))
}

fn call(machine: Replay, args: &[&str]) -> Ran {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut hooks = RunHooks::default();
    hooks.stderr_terminal = Some(false);
    hooks.stderr_columns = Some(100);
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = runtime
        .block_on(rdy_cli::run(
            argv,
            Arc::new(machine),
            hooks,
            &mut out,
            &mut err,
        ))
        .code();
    Ran {
        code,
        stdout: text(out),
        stderr: text(common::without_fd_warning(&err)),
    }
}

/// An ordinary user's machine with `name` set to `value` in the environment, and a proxy at
/// `proxy.acme.test:3128` that opens every tunnel and records each request head it reads.
fn machine(name: &str, value: &str, heads: &Arc<Mutex<Vec<String>>>) -> Replay {
    let heads = Arc::clone(heads);
    common::unprivileged()
        .env(name, value)
        .host(
            "proxy.acme.test",
            ["192.0.2.50"
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))],
        )
        .tcp(
            "192.0.2.50:3128"
                .parse()
                .unwrap_or_else(|e| panic!("addr: {e}")),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_duplex("proxy", move |mut stream| {
            let heads = Arc::clone(&heads);
            async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 512];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&chunk[..n]),
                    }
                }
                heads
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(String::from_utf8_lossy(&seen).into_owned());
                let _ = stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                // Hold the tunnel open until the client closes it.
                let _ = stream.read(&mut chunk).await;
            }
        })
}

/// A spec with one `host:port` endpoint, which a proxy tunnels with `CONNECT`.
fn spec(dir: &Path) -> PathBuf {
    let spec = dir.join("egress.yaml");
    std::fs::write(
        &spec,
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: net.egress\n    endpoints: [\"web.acme.test:8080\"]\n",
    )
    .unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    spec
}

fn args<'a>(spec: &'a str, out: &'a str) -> Vec<&'a str> {
    vec!["run", spec, "--allow-unsigned", "--json", "--out-dir", out]
}

/// Every file under `dir`, as text.
fn files_text(dir: &Path) -> String {
    let mut all = String::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return all;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            all.push_str(&files_text(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            all.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    all
}

fn assert_secret_free(ran: &Ran, out: &Path) {
    let report = files_text(out);
    for (what, haystack) in [
        ("stdout", &ran.stdout),
        ("stderr", &ran.stderr),
        ("the report files", &report),
    ] {
        for secret in [PASSWORD, PAIR, "svc:"] {
            assert!(!haystack.contains(secret), "{secret} is in {what}");
        }
    }
}

#[test]
fn a_proxied_run_reads_each_variable_sets_the_proxy_in_time_and_hides_the_password() {
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
        let spec = spec(dir.path());
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the out dir: {e}"));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let ran = call(
            machine(name, PROXY_URL, &heads),
            &args(&spec.to_string_lossy(), &out.to_string_lossy()),
        );
        // Exit 0 and a report: the proxy was set before the privilege snapshot, so it did not hit
        // `TooLate` (which would be exit 70 before the spec is read).
        assert_eq!(ran.code, 0, "{name}: {}", ran.stderr);
        assert!(!ran.stderr.contains("after the run had started"), "{name}");
        let doc: Value = serde_json::from_str(&ran.stdout)
            .unwrap_or_else(|e| panic!("{name}: stdout is not JSON ({e}): {}", ran.stdout));
        let check = &doc["checks"][0];
        assert_eq!(check["status"], "pass", "{name}: {check}");
        let endpoint = &check["observed"]["endpoints"][0];
        assert_eq!(endpoint["route"], "proxy", "{name}: {endpoint}");
        assert_eq!(endpoint["proxy"], "http://proxy.acme.test:3128", "{name}");
        // The proxy got a CONNECT with the credential, and the credential is nowhere in the output.
        let heads = heads.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(heads.len(), 1, "{name}: {heads:?}");
        assert!(
            heads[0].starts_with("CONNECT web.acme.test:8080 HTTP/1.1"),
            "{name}"
        );
        assert!(
            heads[0].contains(&format!("Proxy-Authorization: Basic {PAIR}")),
            "{name}"
        );
        assert_secret_free(&ran, &out);
    }
}

#[test]
fn a_run_with_no_proxy_variable_goes_direct_and_sets_no_proxy() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path());
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the out dir: {e}"));
    let heads = Arc::new(Mutex::new(Vec::new()));
    // A blank value is not a proxy. The endpoint has no script, so the direct connect has no answer and
    // the check ends in its own way; the point is that no proxy was used.
    let ran = call(
        machine("HTTPS_PROXY", "   ", &heads),
        &args(&spec.to_string_lossy(), &out.to_string_lossy()),
    );
    assert!(
        ran.code == 0 || ran.code == 2 || ran.code == 70,
        "{}",
        ran.stderr
    );
    assert!(
        heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty(),
        "the proxy was used"
    );
}

#[test]
fn a_proxy_password_the_set_refuses_is_exit_70_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path());
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the out dir: {e}"));
    let heads = Arc::new(Mutex::new(Vec::new()));
    // Five bytes: the set cannot match it without redacting common words.
    let ran = call(
        machine(
            "HTTPS_PROXY",
            "http://svc:pw5ab@proxy.acme.test:3128",
            &heads,
        ),
        &args(&spec.to_string_lossy(), &out.to_string_lossy()),
    );
    assert_eq!(ran.code, 70, "{}", ran.stderr);
    let doc: Value = serde_json::from_str(&ran.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", ran.stdout));
    assert_eq!(doc["error"]["code"], "internal", "{doc}");
    let message = doc["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("HTTPS_PROXY"), "{message}");
    let fix = doc["error"]["fix"].as_str().unwrap_or_default();
    assert!(fix.contains("6 bytes"), "{fix}");
    for haystack in [&ran.stdout, &ran.stderr] {
        assert!(!haystack.contains("pw5ab"), "the password was printed");
    }
    assert!(files_text(&out).is_empty(), "nothing was written");
    assert!(
        heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty(),
        "no connection was made"
    );
}

#[test]
fn a_proxy_url_that_does_not_parse_is_exit_64_with_a_fix_and_never_echoes_the_value() {
    for (name, value, fix_word) in [
        (
            "HTTPS_PROXY",
            "socks5://svc:Canary-pw-1@proxy.acme.test:1080",
            "http://",
        ),
        (
            "http_proxy",
            "http://svc:Canary-pw-1@proxy.acme.test:99999",
            "host:port",
        ),
        (
            "HTTP_PROXY",
            "https://svc:Canary-pw-1@proxy.acme.test:3128",
            "http://",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
        let spec = spec(dir.path());
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the out dir: {e}"));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let ran = call(
            machine(name, value, &heads),
            &args(&spec.to_string_lossy(), &out.to_string_lossy()),
        );
        assert_eq!(ran.code, 64, "{name}: {}", ran.stderr);
        let doc: Value = serde_json::from_str(&ran.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", ran.stdout));
        assert_eq!(doc["error"]["code"], "usage", "{name}: {doc}");
        let message = doc["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with(&format!("{name} is not a usable proxy URL")),
            "{message}"
        );
        let fix = doc["error"]["fix"].as_str().unwrap_or_default();
        assert!(fix.contains(fix_word), "{name}: {fix}");
        assert!(fix.contains(&format!("unset {name}")), "{fix}");
        for haystack in [&ran.stdout, &ran.stderr] {
            assert!(
                !haystack.contains("Canary"),
                "{name}: the password was printed"
            );
            assert!(!haystack.contains("svc"), "{name}: the user was printed");
        }
        assert!(files_text(&out).is_empty(), "nothing was written");
    }
}

#[test]
fn rdy_commands_other_than_run_do_not_read_the_proxy() {
    // `rdy version` with a bad proxy variable is not affected: only `rdy run` reads it.
    let heads = Arc::new(Mutex::new(Vec::new()));
    let ran = call(
        machine("HTTPS_PROXY", "socks5://nope", &heads),
        &["version"],
    );
    assert_eq!(ran.code, 0, "{}", ran.stderr);
}
