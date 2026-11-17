//! The shipped `rdy` against real sockets, signed specs and the live runner (M1-127).
//!
//! The exit test of the ticket: the test binds a loopback listener on port 0, signs net-only specs at
//! test time with a key made at test time, and runs the built binary on every leg. An open port gives
//! 0. A `severity: warn` check on a closed port gives 1. A `severity: block` check on a closed port gives
//! 2. An unsigned spec gives 64. A spec with one byte flipped after signing gives 64, even with
//! `--allow-unsigned`.
//!
//! How it stays safe and fast:
//! - The key is `--unencrypted` (no 1 GiB key derivation) and is trusted with `--key`, so the real user
//!   and system trust stores are never read or written. `HOME` and the other profile variables point at a
//!   temp folder anyway.
//! - The only destination is `127.0.0.1`. The proxy variables are removed.
//! - The closed port is a port this test bound and then released. Nothing listens on it, and the
//!   kernel answers a connect with a refusal on all three OSes.
//! - No cargo runs here: the binary is the one cargo built for this test target.
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

mod common;

/// A live run on the slowest leg (a Windows refusal, a cold macOS runner) finishes well inside this.
const RUN_LIMIT: Duration = Duration::from_secs(90);

/// Runs `rdy` in `dir` with a scrubbed environment and no terminal, and fails the test on a hang.
fn rdy(dir: &Path, args: &[&str]) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).expect("home dir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.args(args)
        .current_dir(dir)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("APPDATA", &home)
        .env("LOCALAPPDATA", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env("XDG_DATA_HOME", &home)
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("RDY_KEY_PASSWORD")
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("the rdy binary starts");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = rx
        .recv_timeout(RUN_LIMIT)
        .unwrap_or_else(|_| panic!("rdy {args:?} did not finish in {RUN_LIMIT:?}"))
        .expect("rdy finishes");
    common::quiet(out)
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A spec with one `net.egress` check on a loopback port: TCP connect only, no proxy.
fn spec_text(port: u16, severity: &str) -> String {
    format!(
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-smoke\nchecks:\n  - id: net.egress\n    endpoints: [\"127.0.0.1:{port}\"]\n    via_proxy: direct\n    severity: {severity}\n    fix: Open the port on the loopback test machine.\n"
    )
}

/// Makes a key pair in `dir` once, signs `name`.yaml, and returns the path of the public key.
fn sign(dir: &Path, name: &str, body: &str) -> PathBuf {
    if !dir.join("smoke.pub").exists() {
        let out = rdy(dir, &["spec", "keygen", "smoke", "--unencrypted"]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
    }
    let spec = format!("{name}.yaml");
    std::fs::write(dir.join(&spec), body).expect("write spec");
    let out = rdy(dir, &["spec", "sign", &spec, "--secret-key", "smoke.key"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    dir.join("smoke.pub")
}

/// A port nothing listens on: bound, noted and released. A connect to it is refused.
fn closed_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Runs a spec with `--key` and no report files. `extra` is added to the arguments.
fn run_with_key(dir: &Path, name: &str, key: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "run",
        name,
        "--key",
        key.to_str().expect("utf-8 path"),
        "--no-report",
    ];
    args.extend_from_slice(extra);
    rdy(dir, &args)
}

#[test]
fn live_exit_codes_0_1_2_and_64() {
    let d = tempfile::tempdir().expect("tempdir");
    let dir = d.path();

    // The listener stays up for the whole test. It never needs to accept: the kernel completes the
    // handshake from the backlog, and a connect that completes is all the check measures.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
    let open = listener.local_addr().expect("local addr").port();
    let closed = closed_port();
    assert_ne!(open, closed);

    let key = sign(dir, "open", &spec_text(open, "block"));
    sign(dir, "warn", &spec_text(closed, "warn"));
    sign(dir, "block", &spec_text(closed, "block"));

    // An open port: READY.
    let out = run_with_key(dir, "open.yaml", &key, &["--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("net.egress"), "{json}");

    // A closed port with severity warn: READY with warnings.
    let out = run_with_key(dir, "warn.yaml", &key, &[]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));

    // A closed port with severity block: NOT READY.
    let out = run_with_key(dir, "block.yaml", &key, &[]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));

    // An unsigned spec is refused.
    std::fs::write(dir.join("unsigned.yaml"), spec_text(open, "block")).expect("write");
    let out = run_with_key(dir, "unsigned.yaml", &key, &[]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));

    // One byte flipped after signing is refused, and --allow-unsigned does not change that.
    let mut bytes = std::fs::read(dir.join("open.yaml")).expect("read");
    let at = bytes
        .windows(4)
        .position(|w| w == b"Open")
        .expect("the fix text");
    bytes[at] ^= 0x20; // 'O' becomes 'o': still valid YAML, different bytes
    std::fs::write(dir.join("open.yaml"), bytes).expect("write");
    let out = run_with_key(dir, "open.yaml", &key, &[]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    let out = run_with_key(dir, "open.yaml", &key, &["--allow-unsigned"]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    let out = rdy(
        dir,
        &["run", "open.yaml", "--allow-unsigned", "--no-report"],
    );
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    drop(listener);
}
