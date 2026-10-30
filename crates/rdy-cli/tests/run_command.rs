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
fn an_out_dir_that_is_missing_is_exit_70_with_report_write() {
    // That no check runs is proved in src/run_cmd/tests.rs, with a check that counts its runs.
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

// --- the unsigned warning (product rule 3) ---

const UNSIGNED_WARNING: &str =
    "warning: this spec is not signed. rdy cannot tell who wrote it or if it was changed.";

fn warning_lines(stderr: &str) -> usize {
    stderr
        .lines()
        .filter(|line| *line == UNSIGNED_WARNING)
        .count()
}

#[test]
fn the_binary_warns_once_on_stderr_when_it_runs_an_unsigned_spec() {
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let output = rdy(&[
        "run",
        &acme().to_string_lossy(),
        "--allow-unsigned",
        "--json",
        "--out-dir",
        &out.path().to_string_lossy(),
    ]);
    let stderr = text(output.stderr.clone());
    assert_eq!(warning_lines(&stderr), 1, "{stderr}");
    // It comes first, above everything else the run prints, and nothing of it is on stdout.
    assert_eq!(stderr.lines().next(), Some(UNSIGNED_WARNING), "{stderr}");
    assert!(!text(output.stdout.clone()).contains("not signed"));
    // The warning names no flag.
    assert!(!UNSIGNED_WARNING.contains("--"));
}

#[test]
fn the_warning_does_not_wait_for_the_report_folder() {
    // A folder that cannot be made is exit 70, after the warning.
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &acme().to_string_lossy(),
            "--allow-unsigned",
            "--out-dir",
            "/no/such/dir",
        ],
    );
    assert_eq!(ran.code, 70, "{}", ran.stderr);
    assert_eq!(ran.stderr.lines().next(), Some(UNSIGNED_WARNING));
}

#[test]
fn a_refused_spec_prints_no_warning() {
    let output = rdy(&["run", &acme().to_string_lossy(), "--no-report"]);
    assert_eq!(output.status.code(), Some(64));
    assert_eq!(warning_lines(&text(output.stderr.clone())), 0);
}

#[cfg(unix)]
#[test]
fn a_signed_spec_prints_no_unsigned_warning() {
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
    // With and without the flag: a verified spec is never "not signed".
    for extra in [&[][..], &["--allow-unsigned"]] {
        let mut args = vec!["run", "--no-report"];
        args.extend(extra);
        let path = spec.to_string_lossy().into_owned();
        args.push(&path);
        let ran = with_home(&args);
        let stderr = text(ran.stderr.clone());
        assert!(matches!(ran.status.code(), Some(0..=2)), "{stderr}");
        assert_eq!(warning_lines(&stderr), 0, "{stderr}");
    }
}

// --- a sidecar that cannot be used ---

/// A temp folder with a copy of the example spec in it, and the path of the copy.
fn spec_copy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("acme-platform.yaml");
    std::fs::copy(acme(), &spec).unwrap_or_else(|e| panic!("cannot copy the spec: {e}"));
    (dir, spec)
}

fn run_with_sidecar(spec: &Path, out: &Path, extra: &[&str]) -> Ran {
    let out = out.to_string_lossy().into_owned();
    let spec = spec.to_string_lossy().into_owned();
    let mut args = vec!["run", "--allow-unsigned", "--json", "--out-dir", &out];
    args.extend(extra);
    args.push(&spec);
    call(common::unprivileged(), pinned(), &args)
}

fn assert_refused_with_no_folder(ran: &Ran, out: &Path) {
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    let doc = parse(&ran.stdout);
    assert_eq!(doc["kind"], "Error", "{doc}");
    assert_ne!(doc["error"]["code"], "spec_unsigned");
    assert!(report_dirs(out).is_empty(), "a folder was made");
    // Never run as unsigned: no warning, no report.
    assert_eq!(warning_lines(&ran.stderr), 0, "{}", ran.stderr);
}

#[test]
fn a_sidecar_that_is_a_folder_is_exit_64_and_makes_no_folder() {
    let (dir, spec) = spec_copy();
    std::fs::create_dir(dir.path().join("acme-platform.yaml.minisig"))
        .unwrap_or_else(|e| panic!("cannot make the folder: {e}"));
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = run_with_sidecar(&spec, out.path(), &[]);
    assert_refused_with_no_folder(&ran, out.path());
    assert_eq!(parse(&ran.stdout)["error"]["code"], "spec_unreadable");
}

#[test]
fn a_sidecar_of_garbage_is_exit_64_and_is_not_read_as_unsigned() {
    let (dir, spec) = spec_copy();
    std::fs::write(
        dir.path().join("acme-platform.yaml.minisig"),
        b"this is not a signature\n",
    )
    .unwrap_or_else(|e| panic!("cannot write: {e}"));
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = run_with_sidecar(&spec, out.path(), &[]);
    assert_refused_with_no_folder(&ran, out.path());
    assert_eq!(
        parse(&ran.stdout)["error"]["code"],
        "spec_signature_invalid"
    );
}

#[test]
fn a_named_sidecar_that_is_missing_is_exit_64_even_with_the_flag() {
    let (dir, spec) = spec_copy();
    let missing = dir.path().join("nothing.minisig");
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = run_with_sidecar(&spec, out.path(), &["--sig", &missing.to_string_lossy()]);
    assert_refused_with_no_folder(&ran, out.path());
}

#[cfg(unix)]
#[test]
fn a_sidecar_that_cannot_be_read_is_exit_64_and_makes_no_folder() {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped: root reads a mode 000 file");
        return;
    }
    let (dir, spec) = spec_copy();
    let sidecar = dir.path().join("acme-platform.yaml.minisig");
    std::fs::write(&sidecar, b"x").unwrap_or_else(|e| panic!("cannot write: {e}"));
    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o000))
        .unwrap_or_else(|e| panic!("cannot chmod: {e}"));
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = run_with_sidecar(&spec, out.path(), &[]);
    assert_refused_with_no_folder(&ran, out.path());
    assert_eq!(parse(&ran.stdout)["error"]["code"], "spec_unreadable");
}

// --- the words of a skipped entry carry the did-you-mean hint ---

/// The `message` and `fix` of the entry `key` in the report of a run of `yaml`.
fn skip_words(yaml: &str, key: &str) -> (String, String) {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("typos.yaml");
    std::fs::write(&spec, yaml).unwrap_or_else(|e| panic!("cannot write: {e}"));
    let ran = call(
        common::unprivileged(),
        pinned(),
        &[
            "run",
            &spec.to_string_lossy(),
            "--allow-unsigned",
            "--json",
            "--no-report",
        ],
    );
    let doc = parse(&ran.stdout);
    let check = doc["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|c| c["key"] == key))
        .unwrap_or_else(|| panic!("no result {key} in {doc} ({})", ran.stderr));
    (
        check["message"].as_str().unwrap_or_default().to_owned(),
        check["fix"].as_str().unwrap_or_default().to_owned(),
    )
}

const TYPOS: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.memroy\n    min: 1Gi\n  - id: hots.cpu\n    min: 1\n  - id: upload.now\n  - id: host.cpu\n    mn: 1\n";

/// The words of the run for `key` are the words of `SkipWhy` (01 section 5.2), hint included.
fn assert_words(key: &str, why: &rdy_cli::error::SkipWhy) -> String {
    let (message, fix) = skip_words(TYPOS, key);
    let want = why.text();
    assert_eq!(message, want.message);
    assert_eq!(Some(&fix), want.fix.as_ref());
    fix
}

#[test]
fn an_unknown_id_and_an_unknown_field_carry_the_did_you_mean_hint_of_skip_why() {
    use rdy_cli::error::SkipWhy;
    let version = env!("CARGO_PKG_VERSION").to_owned();
    let s = |text: &str| text.to_owned();

    let fix = assert_words(
        "host.memroy",
        &SkipWhy::UnknownCheck {
            id: s("host.memroy"),
            rdy_version: version.clone(),
            family_reserved: true,
            did_you_mean: Some(s("host.memory")),
        },
    );
    assert!(fix.contains("(did you mean 'host.memory'?)"), "{fix}");

    assert_words(
        "hots.cpu",
        &SkipWhy::UnknownCheck {
            id: s("hots.cpu"),
            rdy_version: version.clone(),
            family_reserved: false,
            did_you_mean: Some(s("host.cpu")),
        },
    );

    // Nothing near: no parenthesis.
    let fix = assert_words(
        "upload.now",
        &SkipWhy::UnknownCheck {
            id: s("upload.now"),
            rdy_version: version.clone(),
            family_reserved: false,
            did_you_mean: None,
        },
    );
    assert!(!fix.contains("did you mean"), "{fix}");

    let fix = assert_words(
        "host.cpu",
        &SkipWhy::UnsupportedField {
            check: s("host.cpu"),
            field: s("mn"),
            rdy_version: version,
            did_you_mean: Some(s("min")),
        },
    );
    assert!(fix.contains("(did you mean 'min'?)"), "{fix}");
}
