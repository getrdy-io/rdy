//! The shipped `rdy` against real sockets, signed specs and the live runner (M1-127).
//!
//! The exit test of the ticket: the test binds a loopback listener on port 0, signs net-only specs at
//! test time with a key made at test time, and runs the built binary on every leg. An open port gives
//! 0. A `severity: warn` check on a closed port gives 1. A `severity: block` check on a closed port gives
//! 2. An unsigned spec gives 64. A spec with one byte flipped after signing gives 64, even with
//! `--allow-unsigned`.
//!
//! How it stays safe and fast:
//! - The key is `--unencrypted` (no 1 GiB key derivation) and is trusted with `--key`, and `--key` runs
//!   read no trust store. `HOME`, `ProgramData` and the other profile variables point at a temp folder
//!   anyway, so no run can reach a real store.
//! - The only destination is `127.0.0.1`. The proxy variables are removed.
//! - The closed port is held by a socket that is bound but never listens, for the whole test. Nothing else
//!   can take it, and the kernel refuses a connect to it on all three OSes.
//! - No cargo runs here: the binary is the one cargo built for this test target.
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod common;

/// One call. A live run on the slowest leg (a Windows refusal, a cold macOS runner) takes a few seconds.
const RUN_LIMIT: Duration = Duration::from_secs(30);

/// Reads a pipe to its end on its own thread, so a full pipe never stalls the child.
fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

/// Runs `rdy` in `dir` with a scrubbed environment and no terminal. A hung run is killed and fails the test.
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
        .env("ProgramData", &home)
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
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("the rdy binary starts");
    let out_reader = drain(child.stdout.take().expect("stdout pipe"));
    let err_reader = drain(child.stderr.take().expect("stderr pipe"));
    let deadline = Instant::now() + RUN_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for rdy") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rdy {args:?} did not finish in {RUN_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    common::quiet(Output {
        status,
        stdout: out_reader.join().expect("stdout reader"),
        stderr: err_reader.join().expect("stderr reader"),
    })
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The JSON document on stdout.
fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {}", stderr(out)))
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

/// A port nothing listens on: a socket bound to it and never put into listening. The caller keeps it
/// alive, so no other process can take the port, and a connect to it is refused.
fn closed_port() -> (socket2::Socket, u16) {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("socket");
    let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    socket.bind(&addr.into()).expect("bind a loopback port");
    let port = socket
        .local_addr()
        .expect("local addr")
        .as_socket()
        .expect("an ip address")
        .port();
    (socket, port)
}

/// Runs a spec with `--key`, `--json` and no report files. `extra` is added to the arguments.
fn run_with_key(dir: &Path, name: &str, key: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "run",
        name,
        "--key",
        key.to_str().expect("utf-8 path"),
        "--no-report",
        "--json",
    ];
    args.extend_from_slice(extra);
    rdy(dir, &args)
}

/// Asserts the first check is `net.egress` with this status and a refused first endpoint. Windows may
/// retry a refused loopback connect until the attempt times out, so `blackhole` is accepted there only.
fn assert_refused(doc: &serde_json::Value, status: &str) {
    let check = &doc["checks"][0];
    assert_eq!(check["id"], "net.egress", "{doc}");
    assert_eq!(check["status"], status, "{doc}");
    let class = check["observed"]["endpoints"][0]["class"]
        .as_str()
        .unwrap_or_default();
    assert!(
        class == "refused" || (cfg!(windows) && class == "blackhole"),
        "class {class}: {doc}"
    );
}

#[test]
fn live_exit_codes_0_1_2_and_64() {
    let d = tempfile::tempdir().expect("tempdir");
    let dir = d.path();

    // The listener stays up for the whole test. It never needs to accept: the kernel completes the
    // handshake from the backlog, and a connect that completes is all the check measures.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
    let open = listener.local_addr().expect("local addr").port();
    let (closed_socket, closed) = closed_port();
    assert_ne!(open, closed);

    let key = sign(dir, "open", &spec_text(open, "block"));
    sign(dir, "warn", &spec_text(closed, "warn"));
    sign(dir, "block", &spec_text(closed, "block"));

    // An open port: READY.
    let out = run_with_key(dir, "open.yaml", &key, &[]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let doc = json(&out);
    assert_eq!(doc["checks"][0]["id"], "net.egress", "{doc}");
    assert_eq!(doc["checks"][0]["status"], "pass", "{doc}");

    // A closed port with severity warn: READY with warnings.
    let out = run_with_key(dir, "warn.yaml", &key, &[]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_refused(&json(&out), "warn");

    // A closed port with severity block: NOT READY.
    let out = run_with_key(dir, "block.yaml", &key, &[]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert_refused(&json(&out), "block");

    // An unsigned spec is refused.
    std::fs::write(dir.join("unsigned.yaml"), spec_text(open, "block")).expect("write");
    let out = run_with_key(dir, "unsigned.yaml", &key, &[]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert_eq!(json(&out)["error"]["code"], "spec_unsigned");

    // One byte flipped after signing is refused, and --allow-unsigned does not change that.
    let mut bytes = std::fs::read(dir.join("open.yaml")).expect("read");
    let at = bytes
        .windows(4)
        .position(|w| w == b"Open")
        .expect("the fix text");
    bytes[at] ^= 0x20; // 'O' becomes 'o': still valid YAML, different bytes
    std::fs::write(dir.join("open.yaml"), bytes).expect("write");
    for extra in [&[][..], &["--allow-unsigned"][..]] {
        let out = run_with_key(dir, "open.yaml", &key, extra);
        assert_eq!(code(&out), 64, "{extra:?}: {}", stderr(&out));
        assert_eq!(
            json(&out)["error"]["code"],
            "spec_signature_invalid",
            "{extra:?}"
        );
    }
    drop(closed_socket);
    drop(listener);
}
