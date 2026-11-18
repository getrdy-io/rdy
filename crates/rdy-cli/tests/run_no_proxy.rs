//! `rdy run` passes `NO_PROXY` to the probe hub (M1-098).
//!
//! The run reads `NO_PROXY` (else `no_proxy`) with the proxy, before the privilege snapshot, so a host
//! the list covers connects direct while every other host goes through the proxy, which is the route
//! ADR 0014 gives the facade. The machine is a replay: no socket is opened. The proxy URL carries a
//! planted password, and `net.proxy` runs in the same spec to show the check sees the same list.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use rdy_cli::RunHooks;
use rdy_engine::testing::{Replay, TcpScript};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

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

fn address(text: &str) -> std::net::SocketAddr {
    text.parse().unwrap_or_else(|e| panic!("addr {text}: {e}"))
}

fn ip(text: &str) -> std::net::IpAddr {
    text.parse().unwrap_or_else(|e| panic!("ip {text}: {e}"))
}

/// A machine with a proxy in `HTTPS_PROXY` and `NO_PROXY` set to `no_proxy`. `web.acme.test` answers
/// directly on `192.0.2.1:8080`. The proxy records the head of every request it gets and tunnels none.
fn machine(no_proxy_name: &str, no_proxy: &str, heads: &Arc<Mutex<Vec<String>>>) -> Replay {
    let heads = Arc::clone(heads);
    common::unprivileged()
        .env("HTTPS_PROXY", PROXY_URL)
        .env(no_proxy_name, no_proxy)
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .host("web.acme.test", [ip("192.0.2.1")])
        .tcp(
            address("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .tcp(
            address("192.0.2.1:8080"),
            TcpScript::Serve("direct".to_owned()),
        )
        .serve_duplex("direct", |_stream| async {})
        .serve_duplex("proxy", move |mut stream| {
            let heads = Arc::clone(&heads);
            async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 512];
                // A reach test connects and closes without a byte: record only a request that came.
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
                let _ = stream.read(&mut chunk).await;
            }
        })
}

fn spec(dir: &Path) -> PathBuf {
    let spec = dir.join("no-proxy.yaml");
    std::fs::write(
        &spec,
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: net.egress\n    endpoints: [\"web.acme.test:8080\", \"api.acme.test:8081\"]\n  - id: net.proxy\n    required_no_proxy: [\".svc\", \"web.acme.test\"]\n",
    )
    .unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    spec
}

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

fn check<'a>(doc: &'a Value, id: &str) -> &'a Value {
    doc["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|c| c["id"] == id))
        .unwrap_or_else(|| panic!("no result for {id}: {}", doc["checks"]))
}

#[test]
fn a_no_proxy_host_connects_direct_and_the_other_host_uses_the_proxy() {
    for name in ["NO_PROXY", "no_proxy"] {
        // Windows names are not case sensitive, so a machine there has no `no_proxy` apart from
        // `NO_PROXY`, and `net.proxy` reads the upper-case spelling only. The replay's environment is a
        // plain map, so it could hold the lower-case name alone, which no Windows machine can.
        if cfg!(windows) && name == "no_proxy" {
            continue;
        }
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
        let spec = spec(dir.path());
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the out dir: {e}"));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let ran = call(
            machine(name, "internal-canary.example, web.acme.test", &heads),
            &[
                "run",
                &spec.to_string_lossy(),
                "--allow-unsigned",
                "--json",
                "--out-dir",
                &out.to_string_lossy(),
            ],
        );
        // The spec's required `.svc` is not in NO_PROXY, so `net.proxy` warns: exit 1.
        assert_eq!(ran.code, 1, "{name}: {}", ran.stderr);
        let doc: Value = serde_json::from_str(&ran.stdout)
            .unwrap_or_else(|e| panic!("{name}: stdout is not JSON ({e}): {}", ran.stdout));
        let egress = check(&doc, "net.egress");
        let endpoints = &egress["observed"]["endpoints"];
        // The NO_PROXY host: direct, by a connection of its own.
        assert_eq!(endpoints[0]["endpoint"], "web.acme.test:8080", "{name}");
        assert_eq!(endpoints[0]["route"], "direct", "{name}: {}", endpoints[0]);
        assert_eq!(endpoints[0]["result"], "reached", "{name}");
        // Its own connection was timed; the report says which entry sent it direct.
        assert!(
            endpoints[0]["connect_ms"].is_number(),
            "{name}: {}",
            endpoints[0]
        );
        assert_eq!(
            endpoints[0]["exempted_by"], "NO_PROXY entry \"web.acme.test\" covers the host",
            "{name}"
        );
        // The other host: through the proxy.
        assert_eq!(endpoints[1]["endpoint"], "api.acme.test:8081", "{name}");
        assert_eq!(endpoints[1]["route"], "proxy", "{name}: {}", endpoints[1]);
        // The proxy was asked for the other host only. The reach test of `net.proxy` is a bare connection.
        let heads = heads.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(heads.len(), 1, "{name}: {heads:?}");
        assert!(
            heads[0].starts_with("CONNECT api.acme.test:8081 HTTP/1.1"),
            "{name}: {}",
            heads[0]
        );
        // `net.proxy` saw the same list: `web.acme.test` is covered, `.svc` is not.
        let proxy = check(&doc, "net.proxy");
        let required = &proxy["observed"]["no_proxy_coverage"];
        assert_eq!(required[0]["entry"], ".svc", "{name}");
        assert_eq!(required[0]["covered"], false, "{name}");
        assert_eq!(required[1]["entry"], "web.acme.test", "{name}");
        assert_eq!(required[1]["covered"], true, "{name}");
        assert_eq!(proxy["observed"]["no_proxy"]["var"], name);
        assert_eq!(
            proxy["observed"]["reach"]["state"], "connected",
            "{name}: {proxy}"
        );
        // The run-level entry names the variables and never a value; neither the password nor the list
        // reaches any file.
        let report = files_text(&out);
        for (what, haystack) in [
            ("stdout", &ran.stdout),
            ("stderr", &ran.stderr),
            ("the report files", &report),
        ] {
            for secret in [PASSWORD, PAIR, "svc:", "internal-canary"] {
                assert!(!haystack.contains(secret), "{name}: {secret} is in {what}");
            }
        }
    }
}
