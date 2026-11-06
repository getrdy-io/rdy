//! The human output of `rdy run` end to end (M1-086): colour choice, the cluster line, the verdict as the
//! last line, and a secret cut by a buffer cap that never reaches stderr (the stderr half of M1-061).
//!
//! The byte-for-byte comparison with the plan samples is in `src/terminal/tests.rs`, on the report
//! fixtures. These tests run `rdy_cli::run` in process on a replay machine.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rdy_cli::RunHooks;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_engine::probe::MAX_READ;
use rdy_engine::testing::Replay;
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

mod common;

const LOG: &str = "/var/log/synthetic.log";
const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

static READER: CheckInfo = CheckInfo {
    id: "host.cpu",
    family: "host",
    summary: "Reads a log and says what it saw.",
    meta: CheckMeta {
        title: "Reader",
        remediation: "Nothing to fix. A test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: FULL,
    reads: &[LOG],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// Reads the log through the facade and puts the end of its text in the message.
struct Reader;

impl Check for Reader {
    fn info(&self) -> &'static CheckInfo {
        &READER
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let file = ctx.probe().read(Path::new(LOG)).await.map_err(|e| {
                rdy_engine::check::CheckError::Failed {
                    message: e.to_string(),
                    hint: String::new(),
                }
            })?;
            let shown = ctx.probe().file_text(&file).map_err(|e| {
                rdy_engine::check::CheckError::Failed {
                    message: e.to_string(),
                    hint: String::new(),
                }
            })?;
            let tail = &shown[shown.ceil_char_boundary(shown.len().saturating_sub(1500))..];
            Ok(Finding::pass(format!("the log ends with {tail}")))
        })
    }
}

static READER_LIST: [&CheckInfo; 1] = [&READER];

struct ReaderFamily;

impl Family for ReaderFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &READER_LIST
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Reader)))
    }
}

fn reader_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(ReaderFamily)?;
    Ok(registry)
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn hooks(terminal: bool) -> RunHooks {
    let mut hooks = RunHooks::default();
    hooks.clock = Some(UNIX_EPOCH + Duration::from_millis(1_804_587_302_123));
    hooks.run_id = Some("00000000-0000-4000-8000-000000000001".to_owned());
    hooks.families = Some(reader_registry);
    hooks.stderr_terminal = Some(terminal);
    hooks.stderr_columns = Some(100);
    // Not the developer's NO_COLOR or CLICOLOR_FORCE.
    hooks.style_env = Some(rdy_cli::style::StyleEnv::default());
    hooks
}

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
        stdout: String::from_utf8(out).unwrap_or_else(|e| panic!("stdout: {e}")),
        stderr: String::from_utf8(err).unwrap_or_else(|e| panic!("stderr: {e}")),
    }
}

fn spec_file() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let path = dir.path().join("acme.yaml");
    std::fs::write(&path, SPEC).unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    (dir, path.to_string_lossy().into_owned())
}

fn run_reader(machine: Replay, extra: &[&str], terminal: bool) -> Ran {
    let (_dir, spec) = spec_file();
    run_reader_on(&spec, machine, extra, terminal)
}

fn run_reader_on(spec: &str, machine: Replay, extra: &[&str], terminal: bool) -> Ran {
    let mut args = vec!["run", spec, "--allow-unsigned", "--no-report"];
    args.extend(extra);
    call(machine, hooks(terminal), &args)
}

fn quiet_machine() -> Replay {
    common::unprivileged().file(LOG, b"all quiet\n".to_vec())
}

// ---- colour -------------------------------------------------------------------------------------

#[test]
fn color_never_and_a_pipe_give_plain_text_and_color_always_gives_codes() {
    let (_dir, spec) = spec_file();
    let never = run_reader_on(&spec, quiet_machine(), &["--color", "never"], true);
    assert!(!never.stderr.contains('\x1b'), "{}", never.stderr);

    let auto_pipe = run_reader_on(&spec, quiet_machine(), &["--color", "auto"], false);
    assert!(!auto_pipe.stderr.contains('\x1b'), "{}", auto_pipe.stderr);

    let auto_terminal = run_reader_on(&spec, quiet_machine(), &["--color", "auto"], true);
    assert!(
        auto_terminal.stderr.contains("\x1b[1;32mREADY\x1b[0m"),
        "{:?}",
        auto_terminal.stderr
    );

    let always = run_reader_on(&spec, quiet_machine(), &["--color", "always"], false);
    assert!(
        always.stderr.contains("\x1b[1;32mREADY\x1b[0m"),
        "{:?}",
        always.stderr
    );
    assert!(
        always.stderr.contains("\x1b[32mPASS\x1b[0m"),
        "{:?}",
        always.stderr
    );

    // The text is the same once the codes are gone, and the verdict is the last line.
    let mut stripped = Vec::new();
    rdy_cli::style::write_styled(&mut stripped, false, &always.stderr)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(String::from_utf8_lossy(&stripped), never.stderr);
    assert_eq!(never.stderr.lines().last(), Some("READY"));
}

#[test]
fn stdout_is_never_coloured_and_json_stays_the_report() {
    let (_dir, spec) = spec_file();
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let ran = call(
        quiet_machine(),
        hooks(true),
        &[
            "run",
            &spec,
            "--allow-unsigned",
            "--json",
            "--color",
            "always",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(!ran.stdout.contains('\x1b'));
    // The folder holds the same bytes as stdout.
    let folders: Vec<PathBuf> = std::fs::read_dir(out.path())
        .unwrap_or_else(|e| panic!("{e}"))
        .map(|e| e.unwrap_or_else(|e| panic!("{e}")).path())
        .collect();
    assert_eq!(folders.len(), 1);
    let json = std::fs::read_dir(&folders[0])
        .unwrap_or_else(|e| panic!("{e}"))
        .map(|e| e.unwrap_or_else(|e| panic!("{e}")).path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap_or_else(|| panic!("no json file"));
    assert_eq!(
        std::fs::read_to_string(json).unwrap_or_default(),
        ran.stdout
    );
    // The report block lists the files that were written, and the verdict is last.
    assert!(ran.stderr.contains("Report written to "), "{}", ran.stderr);
    assert!(ran.stderr.contains("\n  spec.yaml\n"), "{}", ran.stderr);
    assert!(ran.stderr.contains(".json\n"), "{}", ran.stderr);
    let mut plain = Vec::new();
    rdy_cli::style::write_styled(&mut plain, false, &ran.stderr).unwrap_or_else(|e| panic!("{e}"));
    // This spec is unsigned, so the banner title is the line above the verdict.
    let plain = String::from_utf8_lossy(&plain).into_owned();
    let lines: Vec<&str> = plain.lines().collect();
    assert_eq!(lines[lines.len() - 2], "WARNING: UNSIGNED SPEC", "{plain}");
    assert_eq!(lines[lines.len() - 1], "READY", "{plain}");
}

// ---- the cluster line ---------------------------------------------------------------------------

#[test]
fn no_network_with_a_kube_flag_says_the_flag_is_ignored() {
    let acme =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-platform.yaml");
    let spec = acme.to_string_lossy().into_owned();
    let mut hooks = RunHooks::default();
    hooks.stderr_terminal = Some(false);
    hooks.stderr_columns = Some(100);
    let ran = call(
        common::unprivileged(),
        hooks,
        &[
            "run",
            &spec,
            "--allow-unsigned",
            "--no-report",
            "--no-network",
            "--kube-context",
            "prod",
        ],
    );
    assert!(
        ran.stderr
            .contains("\ncluster ignored: --no-network is set (--kube-context prod was given)\n"),
        "{}",
        ran.stderr
    );
}

// ---- a secret cut by a buffer cap ----------------------------------------------------------------

/// A secret and the 8-byte windows of it that must not survive.
struct Canary {
    name: &'static str,
    text: String,
    needles: Vec<String>,
}

fn windows(secret: &str) -> Vec<String> {
    secret
        .as_bytes()
        .windows(8)
        .filter_map(|w| std::str::from_utf8(w).ok().map(str::to_owned))
        .collect()
}

fn canaries() -> Vec<Canary> {
    let body: Vec<String> = (0..5)
        .map(|i| {
            let line: String = (0..64)
                .map(|j| {
                    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    char::from(table[(i * 17 + j * 7 + j / 3) % 64])
                })
                .collect();
            format!("{line}Zk{i}")
        })
        .collect();
    let pem = Canary {
        name: "pem key",
        text: format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            body.join("\n")
        ),
        needles: body.iter().flat_map(|line| windows(line)).collect(),
    };
    let id = "AKIAZ3Q7XK2MCANARY4B";
    let aws = Canary {
        name: "aws key id",
        text: format!("id: {id}"),
        needles: windows(id),
    };
    let userinfo = "svcuser:Pw7canaryZq9";
    let url = Canary {
        name: "url with userinfo",
        text: format!("proxy: https://{userinfo}@proxy.example.test:3128/"),
        needles: windows(userinfo),
    };
    vec![pem, aws, url]
}

/// Lines of 63 `x` and a newline, `n` bytes in all.
fn filler(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| if i % 64 == 63 { b'\n' } else { b'x' })
        .collect()
}

/// A file whose first `MAX_READ` bytes end in `canary`, starting `k` bytes before the cap, and 100 more
/// bytes the cap cuts off.
fn cut_file(k: usize, canary: &str) -> Vec<u8> {
    let mut data = filler(MAX_READ - k);
    data.extend_from_slice(canary.as_bytes());
    if canary.len() < k {
        data.extend(std::iter::repeat_n(b'p', k - canary.len()));
    }
    data.extend(std::iter::repeat_n(b'q', 100));
    data
}

#[test]
fn a_secret_cut_at_the_read_cap_never_reaches_stderr_or_stdout() {
    for canary in canaries() {
        for k in [1, 2, 9, 20, 33, 64, 200] {
            let machine = common::unprivileged().file(LOG, cut_file(k, &canary.text));
            for color in ["never", "always"] {
                let (_dir, spec) = spec_file();
                let ran = call(
                    machine.clone(),
                    hooks(false),
                    &[
                        "run",
                        &spec,
                        "--allow-unsigned",
                        "--no-report",
                        "--json",
                        "--color",
                        color,
                    ],
                );
                assert_eq!(ran.code, 0, "{} at {k}: {}", canary.name, ran.stderr);
                for needle in &canary.needles {
                    assert!(
                        !ran.stderr.contains(needle.as_str())
                            && !ran.stdout.contains(needle.as_str()),
                        "{} survived at {k} ({color}): needle {needle}\n{}",
                        canary.name,
                        ran.stderr
                    );
                }
                // The check did run and its message is there, so the test saw the line it guards.
                assert!(ran.stderr.contains("the log ends with"), "{}", ran.stderr);
            }
        }
    }
}

#[test]
fn a_secret_in_a_whole_line_near_the_cap_never_reaches_stderr() {
    for canary in canaries() {
        // The canary is whole and ends a few lines before the cap.
        let mut data = filler(MAX_READ - 300);
        data.extend_from_slice(canary.text.as_bytes());
        data.push(b'\n');
        data.extend(filler(300 + 100));
        let machine = common::unprivileged().file(LOG, data);
        let ran = run_reader(machine, &["--color", "never"], false);
        for needle in &canary.needles {
            assert!(
                !ran.stderr.contains(needle.as_str()),
                "{} survived: {needle}\n{}",
                canary.name,
                ran.stderr
            );
        }
    }
}
