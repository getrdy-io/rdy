//! The in-process entry point `rdy_cli::run` (M1-074, ADR 0011 decision 4 as amended).
//!
//! A test hands `run` a replay backend, `RunHooks` and capture buffers, and reads back the exit code,
//! stdout and stderr. The privilege gate (M1-042, INV-10) runs through the same backend, so each test
//! below also shows the gate is in front of every command that reads a spec or the trust store.

use std::sync::Arc;

use rdy_cli::RunHooks;
use rdy_engine::testing::Replay;
use rdy_spec::result::ExitCode;
use serde_json::Value;

mod common;

struct Ran {
    code: ExitCode,
    stdout: String,
    stderr: String,
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("not UTF-8: {e}"))
}

/// Calls `run` the way the exit test says: the Replay backend, `RunHooks` and capture buffers.
fn call(machine: Replay, args: &[&str]) -> Ran {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = runtime.block_on(rdy_cli::run(
        argv,
        Arc::new(machine),
        RunHooks::default(),
        &mut out,
        &mut err,
    ));
    Ran {
        code,
        stdout: text(out),
        stderr: text(err),
    }
}

#[test]
fn run_gives_the_exit_code_stdout_and_stderr() {
    let ran = call(common::unprivileged(), &["version"]);
    assert_eq!(ran.code, ExitCode::Ready);
    assert!(ran.stdout.starts_with("rdy "), "{}", ran.stdout);
    assert!(ran.stderr.is_empty(), "{}", ran.stderr);

    // A command that passes the gate and fails on its own: a spec that is not there.
    let ran = call(
        common::unprivileged(),
        &["spec", "lint", "/no/such/dir/spec.yaml"],
    );
    assert_eq!(ran.code, ExitCode::Usage);
    assert!(ran.stdout.is_empty(), "{}", ran.stdout);
    assert!(
        ran.stderr.starts_with("error: cannot read "),
        "{}",
        ran.stderr
    );
}

#[test]
fn a_command_that_reads_a_spec_runs_after_a_clean_snapshot() {
    let spec = format!(
        "{}/../../examples/specs/acme-platform.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let ran = call(common::unprivileged(), &["spec", "lint", &spec]);
    assert!(
        matches!(ran.code, ExitCode::Ready | ExitCode::Warnings),
        "{:?} {}",
        ran.code,
        ran.stderr
    );
    assert!(
        format!("{}{}", ran.stdout, ran.stderr).contains("0 errors"),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
}

#[test]
fn help_version_and_usage_errors_read_nothing_so_they_need_no_snapshot() {
    // An empty machine records no privilege source. A command that needed the snapshot would exit 70.
    for (args, want) in [
        (&["--help"][..], ExitCode::Ready),
        (&["help", "run"], ExitCode::Ready),
        (&["version"], ExitCode::Ready),
        (&["-V"], ExitCode::Ready),
        (&["--bogus"], ExitCode::Usage),
        (&["run"], ExitCode::Usage),
    ] {
        let ran = call(Replay::new(), args);
        assert_eq!(ran.code, want, "rdy {args:?}: {}", ran.stderr);
    }
}

/// A machine that shows rdy started with more privilege than the user who ran it.
#[cfg(not(windows))]
fn privileged() -> Replay {
    let user = [1000; 4];
    if cfg!(target_os = "macos") {
        // The effective id is root while the real id is the user: a setuid exec.
        Replay::for_os(rdy_engine::check::Os::Macos).ids([1000, 0, 0, 0], user)
    } else {
        Replay::new()
            .file("/proc/self/status", common::proc_status(user, user, 0, 0))
            .file("/proc/self/auxv", common::proc_auxv(1))
    }
}

/// Every command of the tree that reads a spec, a key or the trust store, or writes one.
#[cfg(not(windows))]
const GATED: &[&[&str]] = &[
    &["run", "/no/such/dir/spec.yaml"],
    &["verify", "/no/such/dir/spec.yaml"],
    &["spec", "lint", "/no/such/dir/spec.yaml"],
    &[
        "spec",
        "sign",
        "/no/such/dir/spec.yaml",
        "--secret-key",
        "/no/such/key",
    ],
    &["spec", "keygen", "no-such-product", "--unencrypted"],
    &["trust", "add", "acme", "--key", "/no/such/key.pub"],
    &["trust", "list"],
    &["trust", "remove", "acme"],
];

#[cfg(not(windows))]
#[test]
fn a_privileged_snapshot_exits_70_before_any_command_runs() {
    for args in GATED {
        let ran = call(privileged(), args);
        assert_eq!(ran.code, ExitCode::Internal, "rdy {args:?}: {}", ran.stderr);
        assert!(ran.stdout.is_empty(), "rdy {args:?}: {}", ran.stdout);
        assert!(
            ran.stderr
                .starts_with("error: rdy will not run with more privilege"),
            "rdy {args:?}: {}",
            ran.stderr
        );
        // The command did not run: no "cannot read" and no not-implemented text.
        assert!(!ran.stderr.contains("cannot read"), "rdy {args:?}");
        assert!(!ran.stderr.contains("not yet implemented"), "rdy {args:?}");
    }
}

#[cfg(not(windows))]
#[test]
fn a_snapshot_that_cannot_be_taken_is_also_exit_70() {
    for args in GATED {
        let ran = call(Replay::for_os(rdy_engine::check::current_os()), args);
        assert_eq!(ran.code, ExitCode::Internal, "rdy {args:?}: {}", ran.stderr);
        assert!(
            ran.stderr.starts_with("error: rdy could not read "),
            "rdy {args:?}: {}",
            ran.stderr
        );
    }
}

#[cfg(not(windows))]
#[test]
fn with_json_the_refusal_is_the_error_object_on_stdout() {
    let ran = call(
        privileged(),
        &["spec", "lint", "/no/such/dir/spec.yaml", "--json"],
    );
    assert_eq!(ran.code, ExitCode::Internal);
    let json: Value = serde_json::from_str(&ran.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", ran.stdout));
    assert_eq!(json["kind"], "Error");
    assert_eq!(json["error"]["code"], "internal");
}

/// Makes a FIFO with the system `mkfifo`. `rustix` has no `mknodat` on Apple targets, and `mkfifo` is
/// on every Unix CI image.
#[cfg(unix)]
fn mkfifo(path: &std::path::Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("mkfifo: {e}"));
    assert!(status.success(), "mkfifo failed: {status}");
}

/// Runs `rdy spec sign <fifo> --secret-key <fifo>` on its own thread and gives the exit code if the
/// call returns within `limit`. `spec sign` opens its spec path, so on a FIFO with no writer it blocks
/// for ever. A call that never returns leaves its thread blocked in `open`; the test process ends it.
#[cfg(unix)]
fn sign_a_fifo(machine: Replay, fifo: &str, limit: std::time::Duration) -> Option<ExitCode> {
    let (tx, rx) = std::sync::mpsc::channel();
    let path = fifo.to_owned();
    std::thread::spawn(move || {
        let ran = call(machine, &["spec", "sign", &path, "--secret-key", &path]);
        let _ = tx.send(ran.code);
    });
    rx.recv_timeout(limit).ok()
}

/// A spec path that is a FIFO with no writer: opening it blocks for ever. The gate must refuse first,
/// so `run` returns. The control shows the FIFO does block: with no privilege the same call does not
/// return. Without it, a command that refused a FIFO before opening it would pass this test for the wrong
/// reason (`spec lint` does that).
#[cfg(unix)]
#[test]
fn a_refused_run_never_opens_the_spec_path() {
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let fifo = dir.path().join("spec.yaml");
    mkfifo(&fifo);
    let path = fifo.to_string_lossy().into_owned();

    let blocked = sign_a_fifo(common::unprivileged(), &path, Duration::from_secs(2));
    assert_eq!(
        blocked, None,
        "the control returned, so `spec sign` does not block on a FIFO and this test proves nothing"
    );

    let code = sign_a_fifo(privileged(), &path, Duration::from_secs(10))
        .unwrap_or_else(|| panic!("run did not return: the spec path was opened"));
    assert_eq!(code, ExitCode::Internal);
}
