//! The real, unsteered `rdy` binary and the watchdog (M1-176, PC-51).
//!
//! The shipped binary has no hook (ADR 0011 decision 4): its deadline is five minutes and its families
//! are the real ones, so no check of it can be made to hang. What can be made to hang is its stdout.
//! This test runs `rdy run --json` on a spec whose report is bigger than a pipe, with stdout a pipe
//! that nobody reads, and expects exit 70 after the real deadline plus the 10 s grace: about 5 min 10 s.
//! The spin clause of the M1-176 exit test cannot use the shipped binary, and is proved in
//! `run_watchdog.rs` with a test binary that calls `rdy_cli::run` (see PC-51 in the plan corrections).
//!
//! It takes over five minutes of real time, so it is `#[ignore]`d. There is no nightly test job to run it
//! in. Run it by hand before a release, and after any change to the watchdog or the end of `rdy run`:
//!
//! ```text
//! cargo test -p rdy --test run_watchdog_binary -- --ignored --nocapture
//! ```

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod common;

/// The run deadline of the shipped binary (`rdy_engine::sched::DEFAULT_DEADLINE`).
const DEADLINE: Duration = Duration::from_secs(300);
const GRACE: Duration = Duration::from_secs(10);
/// 02: the worst case from the deadline.
const EXIT_BOUND: Duration = Duration::from_secs(22);
const HARD_LIMIT: Duration = Duration::from_secs(420);

/// A spec of 200 entries. Each result is a few hundred bytes of JSON, so the report is far past the
/// 64 KiB of a pipe whatever the host family does with them.
fn big_spec() -> String {
    let mut spec =
        String::from("apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n");
    for n in 0..200 {
        spec.push_str(&format!(
            "  - id: host.cpu\n    name: c{n:03}\n    min: 1\n"
        ));
    }
    spec
}

#[test]
#[ignore = "takes over five minutes: the shipped binary's real run deadline plus the grace"]
fn the_shipped_binary_ends_a_json_run_into_an_unread_pipe_with_exit_70_and_a_partial_report() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("spec.yaml");
    std::fs::write(&spec, big_spec()).unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the out dir: {e}"));

    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .arg("run")
        .arg(&spec)
        .args(["--allow-unsigned", "--json", "--out-dir"])
        .arg(&out)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        // Piped and never read until the process is gone: its stdout fills up and blocks.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"));
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|e| panic!("cannot wait: {e}"))
        {
            break status;
        }
        if started.elapsed() > HARD_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rdy was still running after {HARD_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let took = started.elapsed();

    assert_eq!(status.code(), Some(70), "{status:?}");
    assert!(took >= DEADLINE + GRACE, "it ended too early, at {took:?}");
    assert!(
        took < DEADLINE + EXIT_BOUND,
        "it ended too late, at {took:?}"
    );

    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr)
            .unwrap_or_else(|e| panic!("cannot read stderr: {e}"));
    }
    let stderr = String::from_utf8_lossy(&common::without_fd_warning(&stderr)).into_owned();
    assert!(
        stderr.contains("error: the run did not finish, so rdy stopped itself."),
        "stderr: {stderr}"
    );

    // A folder with a `complete: false` report in it.
    let report = std::fs::read_dir(&out)
        .unwrap_or_else(|e| panic!("cannot read the out dir: {e}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find_map(|folder| {
            let name = folder.file_name()?.to_string_lossy().into_owned();
            let json = folder.join(format!("{name}.json"));
            json.is_file().then_some(json)
        })
        .unwrap_or_else(|| panic!("no report in the out dir"));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report).unwrap_or_else(|e| panic!("cannot read it: {e}")),
    )
    .unwrap_or_else(|e| panic!("the report is not JSON: {e}"));
    assert_eq!(doc["kind"], "Report");
    assert_eq!(doc["complete"], false);
    assert_eq!(doc["checks"].as_array().map(Vec::len), Some(200));
}
