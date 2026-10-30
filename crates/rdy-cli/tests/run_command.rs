//! `rdy run` end to end (M1-057): load, needs, families, engine, report and exit code.
//!
//! Two kinds of test. The in-process ones call `rdy_cli::run` with a replay machine and pinned hooks. The
//! binary ones run the built `rdy` on the real machine, which is the demo command of the ticket.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use jsonschema::Validator;
use rdy_cli::RunHooks;
use rdy_engine::testing::Replay;
use serde_json::Value;

mod common;

const ACME: &str = "../../examples/specs/acme-platform.yaml";

fn acme() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(ACME)
}

fn validator() -> Validator {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let schema: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

fn assert_valid(doc: &Value) {
    let errors: Vec<String> = validator()
        .iter_errors(doc)
        .take(10)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the report fails the schema: {errors:#?}"
    );
}

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("not UTF-8: {e}"))
}

/// Runs `rdy_cli::run` on `machine` with `hooks`.
fn call(machine: Replay, hooks: RunHooks, args: &[&str]) -> Ran {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
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
        stderr: text(err),
    }
}

/// Hooks that pin the clock and the run id.
fn pinned() -> RunHooks {
    let mut hooks = RunHooks::default();
    // 2027-03-09T10:15:02.123Z
    hooks.clock = Some(UNIX_EPOCH + Duration::from_millis(1_804_587_302_123));
    hooks.run_id = Some("00000000-0000-4000-8000-000000000001".to_owned());
    hooks
}

fn report_dirs(parent: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(parent)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", parent.display()))
        .map(|entry| entry.unwrap_or_else(|e| panic!("cannot list: {e}")).path())
        .collect();
    found.sort();
    found
}

fn parse(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout}"))
}

#[test]
fn a_run_writes_a_private_report_folder_and_prints_the_same_report_on_stdout() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = acme();
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &spec.to_string_lossy(),
            "--allow-unsigned",
            "--json",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    let doc = parse(&ran.stdout);
    assert_valid(&doc);
    assert_eq!(doc["kind"], "Report");
    assert_eq!(doc["complete"], true);
    // The exit code is the verdict's. Every example check is required or not run, so it is not 0.
    assert_eq!(u64::from(ran.code), doc["exit_code"].as_u64().unwrap_or(99));
    assert!(matches!(ran.code, 1 | 2), "{}", ran.code);

    // One result per spec entry, in spec order, and the ones no family builds are skipped.
    let keys: Vec<&str> = doc["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("no checks"))
        .iter()
        .map(|c| c["key"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        keys,
        [
            "host.cpu",
            "host.memory",
            "host.disk",
            "net.egress",
            "k8s.version",
            "k8s.storageclass",
            "gpu.cuda",
            "aws.iam"
        ]
    );
    for check in &doc["checks"].as_array().cloned().unwrap_or_default()[3..] {
        assert_eq!(check["status"], "skipped", "{check}");
        assert_eq!(check["skip_kind"], "not_in_build", "{check}");
    }

    // The folder: one, named for the product and the pinned clock, private, holding the report and the
    // verified spec bytes.
    let dirs = report_dirs(out.path());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let dir = &dirs[0];
    assert_eq!(
        dir.file_name().map(|n| n.to_string_lossy().into_owned()),
        Some("rdy-report-acme-platform-20270309T101502Z".to_owned())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir)
            .unwrap_or_else(|e| panic!("no metadata: {e}"))
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    }
    let file = std::fs::read_to_string(dir.join("rdy-report-acme-platform-20270309T101502Z.json"))
        .unwrap_or_else(|e| panic!("no report file: {e}"));
    assert_eq!(file, ran.stdout, "stdout and the .json file differ");
    assert_eq!(
        std::fs::read(dir.join("spec.yaml")).unwrap_or_default(),
        std::fs::read(&spec).unwrap_or_default()
    );

    // The pinned facts, and the unsigned spec says so.
    assert_eq!(doc["run"]["id"], "00000000-0000-4000-8000-000000000001");
    assert_eq!(doc["run"]["started_at"], "2027-03-09T10:15:02.123Z");
    assert_eq!(doc["signature"]["state"], "unsigned");
    assert_eq!(doc["run"]["options"]["allow_unsigned"], true);
    assert_eq!(doc["spec"]["file_name"], "acme-platform.yaml");

    // The short result on stderr ends with the verdict.
    let last = ran.stderr.lines().last().unwrap_or_default();
    assert!(
        last.starts_with("NOT READY") || last.starts_with("READY"),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.contains("Report written to "), "{}", ran.stderr);
}

#[test]
fn the_report_records_the_identity_of_the_privilege_snapshot() {
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &acme().to_string_lossy(),
            "--allow-unsigned",
            "--json",
            "--no-report",
        ],
    );
    let doc = parse(&ran.stdout);
    assert_valid(&doc);
    // `unprivileged()` records uid 1000 on Unix. Windows records no ids and no elevation.
    if cfg!(windows) {
        assert_eq!(doc["identity"]["euid"], Value::Null);
    } else {
        assert_eq!(doc["identity"]["euid"], 1000);
    }
    assert_eq!(doc["identity"]["elevated"], false);
    // The snapshot's reads are in the same action log as the checks' (one hub for the whole run).
    let actions = doc["actions"].as_array().cloned().unwrap_or_default();
    assert!(
        actions.iter().any(|a| a["check"].is_null()),
        "no run-level entry in the action log"
    );
}

#[test]
fn no_report_writes_nothing_and_still_prints_the_report() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &acme().to_string_lossy(),
            "--allow-unsigned",
            "--json",
            "--no-report",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    assert_valid(&parse(&ran.stdout));
    assert!(report_dirs(out.path()).is_empty());
    assert!(!ran.stderr.contains("Report written"), "{}", ran.stderr);
}

#[test]
fn an_unsigned_spec_without_the_flag_is_refused_before_any_folder_is_made() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &acme().to_string_lossy(),
            "--json",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    let doc = parse(&ran.stdout);
    assert_eq!(doc["kind"], "Error");
    assert_eq!(doc["error"]["code"], "spec_unsigned");
    assert!(report_dirs(out.path()).is_empty());
}

#[test]
fn a_spec_that_is_not_there_is_exit_64_and_makes_no_folder() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            "/no/such/dir/spec.yaml",
            "--allow-unsigned",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    assert!(
        ran.stderr.starts_with("error: cannot read "),
        "{}",
        ran.stderr
    );
    assert!(report_dirs(out.path()).is_empty());
}

#[test]
fn an_out_dir_that_is_missing_is_exit_70_with_report_write_and_runs_no_check() {
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &acme().to_string_lossy(),
            "--allow-unsigned",
            "--json",
            "--out-dir",
            "/no/such/dir",
        ],
    );
    assert_eq!(ran.code, 70, "{}", ran.stderr);
    let doc = parse(&ran.stdout);
    assert_eq!(doc["error"]["code"], "report_write");
}

#[test]
fn a_one_run_key_is_not_silently_ignored() {
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &acme().to_string_lossy(),
            "--allow-unsigned",
            "--key",
            "RWQ-not-a-key",
            "--no-report",
        ],
    );
    assert_eq!(ran.code, 70, "{}", ran.stderr);
    assert!(
        ran.stderr.contains("is not yet implemented"),
        "{}",
        ran.stderr
    );
}

#[test]
fn the_deadline_hook_sets_the_recorded_deadline() {
    let mut hooks = pinned();
    hooks.deadline = Some(Duration::from_secs(30));
    let ran = call(
        common::unprivileged(),
        hooks,
        &[
            "run",
            &acme().to_string_lossy(),
            "--allow-unsigned",
            "--json",
            "--no-report",
        ],
    );
    let doc = parse(&ran.stdout);
    assert_eq!(doc["run"]["options"]["deadline_ms"], 30_000);
}

// --- the built binary, on the real machine ---

fn rdy(args: &[&str]) -> Output {
    common::quiet(
        Command::new(env!("CARGO_BIN_EXE_rdy"))
            .args(args)
            .env_remove("RDY_PROGRESS")
            .env_remove("RUST_LOG")
            .output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
    )
}

/// The demo command of the ticket: the example spec, unsigned, with the report as JSON on stdout.
#[test]
fn the_binary_runs_the_example_spec_and_exits_by_the_verdict() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let output = rdy(&[
        "run",
        &acme().to_string_lossy(),
        "--allow-unsigned",
        "--json",
        "--out-dir",
        &out.path().to_string_lossy(),
    ]);
    let stdout = text(output.stdout.clone());
    let doc = parse(&stdout);
    assert_valid(&doc);
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        i64::from(code),
        doc["exit_code"].as_i64().unwrap_or(99),
        "{doc}"
    );
    assert!(matches!(code, 1 | 2), "{code}");
    assert_eq!(doc["checks"].as_array().map(Vec::len), Some(8));

    // Nothing but the document is on stdout, and it is the file.
    assert!(stdout.ends_with("}\n"));
    let dirs = report_dirs(out.path());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let json = std::fs::read_dir(&dirs[0])
        .unwrap_or_else(|e| panic!("cannot read the report folder: {e}"))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap_or_else(|| panic!("no .json file in {:?}", dirs[0]));
    assert_eq!(std::fs::read_to_string(json).unwrap_or_default(), stdout);
}

#[test]
fn the_binary_exits_64_for_an_unsigned_spec_without_the_flag() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let output = rdy(&[
        "run",
        &acme().to_string_lossy(),
        "--out-dir",
        &out.path().to_string_lossy(),
    ]);
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert!(report_dirs(out.path()).is_empty());
}

/// A signed spec with a pinned key runs with no flag, and the report records who signed it. The user
/// store is used, so the test skips for root (a root run reads only the system store, which a test must
/// not write) and on Windows (no user store).
#[cfg(unix)]
#[test]
fn the_binary_runs_a_signed_spec_whose_key_the_user_pinned() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped: a root run reads only /etc/rdy/trust.yaml");
        return;
    }
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed");
    let home = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let with_home = |args: &[&str]| -> Output {
        common::quiet(
            Command::new(env!("CARGO_BIN_EXE_rdy"))
                .args(args)
                .env("HOME", home.path())
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("RDY_PROGRESS")
                .env_remove("RUST_LOG")
                .output()
                .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
        )
    };
    let pinned = with_home(&[
        "trust",
        "add",
        "acme-platform",
        "--key",
        &fixtures.join("acme-platform.pub").to_string_lossy(),
        "--yes",
    ]);
    assert_eq!(pinned.status.code(), Some(0), "{pinned:?}");

    let spec = fixtures.join("acme-platform.yaml");
    let ran = with_home(&["run", &spec.to_string_lossy(), "--json", "--no-report"]);
    let doc = parse(&text(ran.stdout.clone()));
    assert_valid(&doc);
    assert_eq!(doc["signature"]["state"], "verified", "{doc}");
    assert_eq!(doc["signature"]["trust_source"], "user");
    assert_eq!(doc["run"]["options"]["allow_unsigned"], false);

    // The signature is checked even when the flag is given, and a spec that was edited after it was
    // signed is refused, with or without the flag.
    let edited = home.path().join("acme-platform.yaml");
    let mut bytes = std::fs::read(&spec).unwrap_or_default();
    bytes.extend(b"# edited\n");
    std::fs::write(&edited, bytes).unwrap_or_else(|e| panic!("cannot write: {e}"));
    std::fs::copy(
        fixtures.join("acme-platform.yaml.minisig"),
        home.path().join("acme-platform.yaml.minisig"),
    )
    .unwrap_or_else(|e| panic!("cannot copy: {e}"));
    for extra in [&[][..], &["--allow-unsigned"]] {
        let mut args = vec!["run", "--json", "--no-report"];
        args.extend(extra);
        let path = edited.to_string_lossy().into_owned();
        args.push(&path);
        let refused = with_home(&args);
        assert_eq!(refused.status.code(), Some(64), "{refused:?}");
        let doc = parse(&text(refused.stdout.clone()));
        assert_eq!(doc["error"]["code"], "spec_signature_invalid", "{doc}");
    }
}
