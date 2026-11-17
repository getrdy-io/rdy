//! `rdy run`, end to end (M1-057, 07 sections 1 and 4.1, 02 "Privilege and needs").
//!
//! The order is the security property. [`crate::run`] has already taken the privilege snapshot and
//! passed the gate (INV-10), so nothing here runs for a binary with extra privilege. Then:
//!
//! 1. Read the spec file and, when there is one, its `.minisig` sidecar. Verify, then parse
//!    ([`rdy_spec::load`], INV-01). A spec that fails stops here with exit 64 and no folder.
//! 2. When the spec is not signed by a pinned key, print its banner on stderr (`terminal::banner`, product rule 3). Then make the
//!    report folder, right after verification and before any check (ADR 0016). `--no-report` makes none.
//!    The run id is made before the folder, so a failure to make it leaves no folder. A failure after the
//!    folder exists removes it again when it is still empty.
//! 3. Plan, probe the needs, run the checks, map and redact each result ([`Engine::execute`]). The
//!    watchdog (M1-176) was started by the entry point before the runtime. It is armed with the folder
//!    and the run board right after the folder is made, before the host and needs probes, so a check
//!    that never yields, or a stdout nobody reads, ends in exit 70 with a `complete: false` report in
//!    the folder (07 section 5.2).
//! 4. Build the report from the results and the facts of the run (producer, run, spec, signature,
//!    host, identity from the privilege snapshot), redact the whole of it and write it.
//! 5. Print, then write the files: with `--json` the document goes to stdout first, then the state
//!    moves to `Writing`, the files are written and `finish` stores the exit code. The human result
//!    goes to stderr last ([`crate::terminal`], M1-086): the header, the checks sorted by bucket with
//!    their fixes, the summary, the report folder and the verdict. Stdout comes first because it is the
//!    one write that can block for good: while it does, the watchdog still owns the report.
//!
//! **Exit codes.** A verdict gives 0, 1 or 2. A spec problem gives 64. A folder that cannot be made, a
//! report that cannot be written and a bug give 70. When the files cannot be written after the
//! verdict exists, the exit code is 70 and the summary and the error go to stderr. Without `--json`
//! nothing is on stdout. With `--json` stdout already holds the whole document, printed before the
//! files (see 5 above), so a second one would not be one document (PC-50 in 13).
//!
//! **Not here.** The proxy (M1-097), the hosts of a check's spec entry (M1-095), Ctrl-C (M1-058),
//! `--jobs` (M1-059), the kube flags (M1-107) and `--key` (M1-126). `--quiet` and `--verbose` (M1-143)
//! and the live progress line (M1-142) change the output later; this is the plain run.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use rdy_engine::check::{Os, current_os};
use rdy_engine::engine::{Engine, RunOptions as EngineOptions};
use rdy_engine::family::Registry;
use rdy_engine::output::{OutputDir, ReportError, report_time};
use rdy_engine::privilege::Privilege;
use rdy_engine::probe::{NativeCall, NativeValue, Probe, ProbeHub};
use rdy_engine::redact::{RedactedReport, Redactor, RuleCounts};
use rdy_engine::report::{JsonError, write_json};
use rdy_engine::sched::cap_jobs;
use rdy_engine::watchdog::{ReportSink, Timing};
use rdy_spec::result::{
    CheckResult, Host, HostOs, HostOsFamily, Producer, Report, Run, RunOptions, Signature, SpecRef,
};
use rdy_spec::sig::{MAX_SIGNATURE_BYTES, Policy, TrustStore};
use rdy_spec::{LoadedSpec, VerifiedSpecBytes, load};

use crate::cli::{COMMIT, ColorChoice, RunArgs, TARGET};
use crate::error::{CliError, InternalKind, IoReason, ReportStep, emit, shell_word};
use crate::hooks::RunHooks;
use crate::output::{open_report_dir, report_error};
use crate::rig::Rig;
use crate::signing::files::{FileError, read_public};
use crate::style::{StyleEnv, Styler, stderr_columns, use_color, wrap_width, write_styled};
use crate::terminal::{View, banner, render};
use crate::trust::{self, Layout, Vars};
use crate::{lint, redaction};

/// How the human output looks: decided once, from `--color`, the environment and the stream.
#[derive(Debug, Clone, Copy)]
struct Look {
    /// Whether stderr gets colour codes.
    color: bool,
    /// The wrap width, 60 to 100.
    width: usize,
}

impl Look {
    fn new(choice: ColorChoice, hooks: &RunHooks) -> Self {
        let env = hooks
            .style_env
            .clone()
            .unwrap_or_else(StyleEnv::from_process);
        let terminal = hooks
            .stderr_terminal
            .unwrap_or_else(|| std::io::IsTerminal::is_terminal(&std::io::stderr()));
        let columns = hooks.stderr_columns.or_else(stderr_columns);
        Self {
            color: use_color(choice, &env, terminal),
            width: wrap_width(columns, &env),
        }
    }

    fn styler(self) -> Styler {
        Styler::new(self.color)
    }
}

/// Writes `text` to stderr as the run's look says. A closed stderr is not an error of the run.
fn say(stderr: &mut dyn Write, look: Look, text: &str) {
    let _ = write_styled(stderr, look.color, text);
}

/// What `rdy run` needs from the entry point: everything built before the spec is read.
pub(crate) struct RunContext {
    /// The run's hub. Its redactor is the process redactor, so the log, the errors and the report
    /// share one known-secret set.
    pub(crate) hub: ProbeHub,
    /// The process redactor.
    pub(crate) redactor: Redactor,
    /// The clean privilege snapshot.
    pub(crate) privilege: Privilege,
    /// The test hooks (default in the binary).
    pub(crate) hooks: RunHooks,
    /// The families of this build.
    pub(crate) registry: Registry,
    /// The `--color` choice.
    pub(crate) color: ColorChoice,
    /// The watchdog and the write state, started before the runtime (M1-176).
    pub(crate) rig: Rig,
}

/// Runs the command and returns the exit code.
pub(crate) async fn run(
    args: &RunArgs,
    cx: RunContext,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match execute(args, cx, json, stdout, stderr).await {
        Ok(code) => code,
        Err(error) => emit(&error, json, stdout, stderr),
    }
}

async fn execute(
    args: &RunArgs,
    cx: RunContext,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, CliError> {
    // A user-supplied value in the log: the redactor has to cover it (threat model I2).
    tracing::debug!(spec = %args.spec.display(), "run requested");
    let RunContext {
        hub,
        redactor,
        privilege,
        hooks,
        registry,
        color,
        rig,
    } = cx;
    let look = Look::new(color, &hooks);
    // The watchdog was started before the runtime, from the first thing `main` did. The scheduler counts
    // from the same origin (M1-176, 02 "Watchdog").
    let origin = rig.origin;
    // The rig's deadline, so the watchdog and the scheduler cannot count different ones.
    let deadline = rig.deadline;
    let state = Arc::clone(&rig.state);
    let clock = || hooks.clock.unwrap_or_else(SystemTime::now);

    if args.key.is_some() {
        // The one-run key and its banner are M1-126. Ignoring the flag would run a spec the user did
        // not mean to trust, so it stops.
        return Err(CliError::Internal(InternalKind::NotImplemented {
            command: "run with a one-run key",
        }));
    }
    let name = args.spec.to_string_lossy().into_owned();
    let loaded = load_spec(args, &name, &privilege)?;

    // The banner comes before any check (01 section 4.7). The path is shown as typed, redacted first.
    let out = Out::new(args, look, &name);
    if let Some(text) = banner(
        &Signature::from(loaded.signature()),
        &out.spec,
        look.styler(),
    ) {
        say(stderr, look, &format!("{text}\n"));
    }

    // Before the folder: a failure here must not leave one behind.
    let run_id = match &hooks.run_id {
        Some(id) => id.clone(),
        None => uuid_v4()?,
    };
    let started_at = clock();
    let product = loaded.spec().metadata.product.as_str().to_owned();
    let dir = open_report_dir(args, &product, started_at)?.map(Arc::new);

    let mut options = EngineOptions::new();
    options.network = !args.no_network;
    options.deadline = deadline;
    options.spec_arg = shell_word(&name);
    options.origin = Some(origin);

    let mut run_options = RunOptions::new(
        u32::try_from(cap_jobs(options.jobs)).unwrap_or(1),
        u64::try_from(options.deadline.as_millis()).unwrap_or(u64::MAX),
    );
    run_options.allow_unsigned = args.allow_unsigned;
    run_options.network = options.network;
    // Recorded only. The flag does nothing until M1-107 builds the Kubernetes family.
    run_options.kube_context.clone_from(&args.kube_context);

    let engine = Engine::new(registry, hub);
    let plan = engine.plan(&loaded, current_os(), env!("CARGO_PKG_VERSION"));

    // Arm the watchdog right after the folder exists and before anything that can hang (the host
    // probes, the needs probe, the checks), so a hang anywhere from here on leaves a `complete: false`
    // report in the folder (07 sections 4.1 and 5.2). `--no-report` has no folder, so a hang there ends
    // in exit 70 with no report. The watchdog gets the folder through a weak handle, so a folder
    // removed after a failure is not held open.
    let board = dir.as_ref().map(|dir| {
        // The report as it stands when the watchdog fires: the run is over, as far as it can tell, and
        // the checks are whatever the board has by then. The host is a stand-in until it is read.
        let grace = Timing::DEFAULT.grace;
        let fires_at = started_at
            .checked_add(deadline + grace)
            .unwrap_or(started_at);
        let base = assemble(
            &loaded,
            args,
            &privilege,
            stand_in_host(),
            make_run(
                run_id.clone(),
                started_at,
                fires_at,
                deadline + grace,
                run_options.clone(),
            ),
            Vec::new(),
        );
        let board = engine.board(&loaded, &plan, base, deadline, &options.spec_arg);
        let sink: Arc<dyn ReportSink> = Arc::new(FolderSink {
            dir: Arc::downgrade(dir),
            spec: loaded.verified_bytes().clone(),
        });
        rig.watchdog.arm(Arc::clone(&board), sink);
        board
    });

    let host = host_facts(&engine.hub().run_probe()).await;
    if let Some(board) = &board {
        board.set_host(host.clone());
    }
    options.board = board;
    let executed = engine.execute(&loaded, plan, &privilege, &options).await;

    let finished_at = clock();
    let run = make_run(
        run_id,
        started_at,
        finished_at,
        origin.elapsed(),
        run_options,
    );
    let mut report = assemble(&loaded, args, &privilege, host, run, executed.results);
    report.capabilities = executed.capabilities;
    executed.log.apply(&mut report);
    let counts = executed.counts;

    let redacted = match redactor.redact_report_counted(report.clone(), counts.clone()) {
        Ok(redacted) => redacted,
        Err(_) => {
            discard_if_empty(dir);
            return Err(CliError::bug());
        }
    };

    // The order is the watchdog's contract (M1-043, M1-176). Stdout first: it is the one write that can
    // block for good, on a pipe nobody reads, and while it blocks the state is still `Running`, so the
    // watchdog can write the partial report and end the run. Then the claim, then the files, then
    // `finish`. After `finish` the watchdog is only a backstop with the stored exit code.
    let printed = if json {
        print_json(&redacted, stdout).map_err(writer_error)
    } else {
        Ok(())
    };
    state.claim_or_park();
    let files = match &dir {
        Some(dir) => write_files(dir, &loaded, &redacted),
        None => Ok(Vec::new()),
    };
    if let Err(error) = printed {
        // The report exists and stdout cannot take it. The files were still written; the error is what
        // the user sees, on stderr only: it must not go to the stdout that just failed (`json` false).
        if files.is_err() {
            discard_if_empty(dir);
        }
        state.finish(crate::EXIT_INTERNAL);
        return Ok(emit(&error, false, stdout, stderr));
    }
    match files {
        Ok(files) => {
            state.finish(redacted.exit_code);
            out.print(
                &redacted,
                dir.as_deref().map(OutputDir::path),
                &files,
                stderr,
            );
            Ok(redacted.exit_code)
        }
        Err(error) => {
            // A folder with nothing in it is not a report. One with a file in it stays, for the user.
            discard_if_empty(dir);
            state.finish(crate::EXIT_INTERNAL);
            // With `--json` the document is on stdout already, so only the summary, a plain note and the
            // error follow, on stderr.
            Ok(fail_after_verdict(
                &error, report, counts, &redactor, &out, false, json, stdout, stderr,
            ))
        }
    }
}

/// What the watchdog writes into the report folder when it has to: the spec copy and the partial
/// report. The folder is held weakly, so it is not kept open after the run has dropped it.
struct FolderSink {
    dir: Weak<OutputDir>,
    spec: VerifiedSpecBytes,
}

impl ReportSink for FolderSink {
    fn write(&self, report: &RedactedReport) -> Result<(), ReportError> {
        // The run dropped the folder, which it does only after it removed an empty one or finished with
        // it. The watchdog has nothing to write into then, and the run is already ending.
        let Some(dir) = self.dir.upgrade() else {
            return Ok(());
        };
        dir.write_spec(&self.spec)?;
        dir.write_json(report)?;
        Ok(())
    }
}

/// A host to put in the report before the machine has been read: the arch of this build and a name
/// that says so. [`rdy_engine::watchdog::Board::set_host`] replaces it once the facts are in.
fn stand_in_host() -> Host {
    Host::new(
        "unknown",
        HostOs::new(host_os_family()),
        std::env::consts::ARCH,
    )
}

fn host_os_family() -> HostOsFamily {
    match current_os() {
        Os::Macos => HostOsFamily::Macos,
        Os::Windows => HostOsFamily::Windows,
        _ => HostOsFamily::Linux,
    }
}

/// The `run` block of the report.
fn make_run(
    id: String,
    started_at: SystemTime,
    finished_at: SystemTime,
    took: Duration,
    options: RunOptions,
) -> Run {
    Run::new(
        id,
        report_time(started_at),
        report_time(finished_at),
        u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
        options,
    )
}

/// The report from the facts of the run and its `results`.
fn assemble(
    loaded: &LoadedSpec,
    args: &RunArgs,
    privilege: &Privilege,
    host: Host,
    run: Run,
    results: Vec<CheckResult>,
) -> Report {
    Report::new(
        producer(),
        run,
        spec_ref(loaded, &args.spec),
        Signature::from(loaded.signature()),
        host,
        privilege.identity(),
        results,
    )
}

/// Removes the report folder when nothing was written into it. A folder that holds a file stays, and so
/// does one that cannot be removed: this is a best-effort tidy, and the run's own error is what counts.
/// The handle is dropped first, because Windows cannot remove a folder that is still open.
fn discard_if_empty(dir: Option<Arc<OutputDir>>) {
    if let Some(dir) = dir {
        let path = dir.path().to_owned();
        drop(dir);
        // `remove_dir` only removes an empty folder, and does not follow a link.
        let _ = std::fs::remove_dir(path);
    }
}

/// Printed on stderr when the JSON report is already on stdout and the files could not be written.
/// stdout may say `complete: true`; this line says what the exit code means (PC-50, 07 section 4.1).
pub(crate) const FILES_NOT_WRITTEN_NOTE: &str =
    "error: report files not written. The JSON on stdout is complete but the exit code is 70.";

/// The files could not be written, but the verdict exists. The result still prints (07 section 4.1): the
/// Report with `complete: false` on stdout with `--json`, the summary on stderr, then the error. The
/// exit code is 70. If the report cannot be printed either (it is over the cap, or stdout is closed),
/// stdout gets the error object instead.
///
/// `on_stdout` is true when the document is already on stdout (printed before the files, PC-50): a
/// plain note then goes to stderr between the summary and the error.
#[allow(clippy::too_many_arguments)]
fn fail_after_verdict(
    error: &CliError,
    mut report: Report,
    counts: RuleCounts,
    redactor: &Redactor,
    out: &Out,
    json: bool,
    on_stdout: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    report.complete = false;
    let incomplete = redactor.redact_report_counted(report, counts).ok();
    let printed = json
        && incomplete
            .as_ref()
            .is_some_and(|report| print_json(report, stdout).is_ok());
    if let Some(report) = &incomplete {
        // No folder line: the files are the thing that failed.
        out.print(report, None, &[], stderr);
    }
    if on_stdout {
        let _ = writeln!(stderr, "{FILES_NOT_WRITTEN_NOTE}");
    }
    emit(error, json && !printed, stdout, stderr)
}

/// Reads the spec and its signature sidecar, then verifies and parses them ([`rdy_spec::load`]).
///
/// Without a sidecar the policy decides: `--allow-unsigned` loads the spec as unsigned, and no flag is
/// `spec_unsigned` (exit 64). With a sidecar the trust stores are read and the signature has to verify,
/// whatever the flag says. A sidecar that cannot be read is an error and never "no signature".
fn load_spec(args: &RunArgs, name: &str, privilege: &Privilege) -> Result<LoadedSpec, CliError> {
    let bytes = lint::read_spec(&args.spec, name)?;
    let sidecar = read_sidecar(args)?;
    let trust = match &sidecar {
        Some(_) => {
            let layout =
                Layout::from_env(&Vars::from_process(), privilege.euid().unwrap_or(u32::MAX));
            trust::load(&layout)?
        }
        None => TrustStore::new(),
    };
    let policy = if args.allow_unsigned {
        Policy::AllowUnsigned
    } else {
        Policy::RequireSigned
    };
    load(&bytes, sidecar.as_deref(), &trust, policy).map_err(|error| CliError::spec(name, error))
}

/// The signature sidecar: `--sig`, else `<SPEC>.minisig`. A missing default file means no signature. A
/// missing `--sig` file, and any other failure to read either, is an error.
fn read_sidecar(args: &RunArgs) -> Result<Option<Vec<u8>>, CliError> {
    let (path, explicit) = match &args.sig {
        Some(path) => (path.clone(), true),
        None => {
            let mut name = args.spec.as_os_str().to_owned();
            name.push(".minisig");
            (PathBuf::from(name), false)
        }
    };
    // One byte past the limit is enough for the loader to say "too large".
    match read_public(&path, MAX_SIGNATURE_BYTES + 1) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(FileError::Unreadable {
            reason: IoReason::NoSuchFile,
        }) if !explicit => Ok(None),
        Err(error) => {
            let reason = match error {
                FileError::Unreadable { reason } => reason,
                FileError::NotRegular => IoReason::NotAFile,
                _ => IoReason::Other,
            };
            Err(CliError::SpecUnreadable {
                path: path.to_string_lossy().into_owned(),
                reason,
            })
        }
    }
}

/// Writes the spec copy and the JSON report into the folder and returns the names of the files, in the
/// order the terminal lists them.
fn write_files(
    dir: &OutputDir,
    loaded: &LoadedSpec,
    report: &RedactedReport,
) -> Result<Vec<String>, CliError> {
    let failed = |error| report_error(ReportStep::WriteFiles, dir.path(), error);
    let mut written = dir.write_spec(loaded.verified_bytes()).map_err(failed)?;
    written.push(dir.write_json(report).map_err(failed)?);
    let mut names: Vec<String> = written
        .iter()
        .filter_map(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

/// Writes the report as JSON to stdout and flushes it, so a closed or full pipe shows up here and not
/// at exit. A flush that fails is the same error as a write that fails.
fn print_json(report: &RedactedReport, stdout: &mut dyn Write) -> Result<(), JsonError> {
    write_json(report, stdout)?;
    stdout.flush()?;
    Ok(())
}

/// The error for a failed write of the JSON document to stdout.
fn writer_error(error: JsonError) -> CliError {
    CliError::report_writer(&error).unwrap_or_else(CliError::bug)
}

/// What the human output needs from the command line, decided once.
struct Out {
    /// Colour and width.
    look: Look,
    /// The spec path as typed, redacted.
    spec: String,
    /// The `--kubeconfig` value, redacted.
    kubeconfig: Option<String>,
    /// `--out-dir` was given (it decides the Windows note).
    out_dir_given: bool,
}

impl Out {
    fn new(args: &RunArgs, look: Look, name: &str) -> Self {
        // The spec, the kubeconfig and the folder are typed by the user. They are redacted here and
        // escaped by the renderer.
        Self {
            look,
            spec: redaction::redact_text(name),
            kubeconfig: args
                .kubeconfig
                .as_ref()
                .map(|path| redaction::redact_text(&path.display().to_string())),
            out_dir_given: args.out_dir.is_some(),
        }
    }

    /// The human result on stderr: header, checks, summary, report folder and verdict (07 section 2).
    /// The verdict is the last line. `folder` is `None` for `--no-report` and after a failed write.
    fn print(
        &self,
        report: &RedactedReport,
        folder: Option<&std::path::Path>,
        files: &[String],
        stderr: &mut dyn Write,
    ) {
        let folder = folder.map(|path| redaction::redact_text(&path.display().to_string()));
        let note = folder
            .as_ref()
            .and_then(|_| residual_note(current_os(), self.out_dir_given));
        let view = View {
            report,
            spec_arg: &self.spec,
            folder: folder.as_deref(),
            files,
            note,
            kubeconfig: self.kubeconfig.as_deref(),
            styler: self.look.styler(),
            width: self.look.width,
        };
        say(stderr, self.look, &render(&view));
    }
}

/// The access-rule residual of ADR 0016 decision 7, for the OS that has one. The `Report` has no `notes`
/// field in `rdy/v1`, so it is a line on stderr.
///
/// Windows keeps the access list of the folder it is in, which matters most for an `--out-dir` at a drive
/// root. macOS applies an inheritable access rule of the parent folder before the mode bits, whichever
/// parent it is.
fn residual_note(os: Os, out_dir_given: bool) -> Option<&'static str> {
    match os {
        Os::Windows if out_dir_given => Some(
            "note: on Windows rdy cannot set who may read the report folder. It keeps the access of the folder it is in. For the most privacy, leave out --out-dir and use the default folder.",
        ),
        Os::Macos => Some(
            "note: on macOS an access rule that the parent folder passes down can let others read the report, whatever the file mode says. Keep the report in a folder only you can read.",
        ),
        _ => None,
    }
}

/// The rdy build that writes the report.
fn producer() -> Producer {
    let known = |text: &str| (!text.is_empty()).then(|| text.to_owned());
    let mut producer = Producer::new(env!("CARGO_PKG_VERSION"), rdy_spec::VERSION, TARGET);
    producer.commit = known(COMMIT);
    producer
}

/// Which spec ran: the signed metadata and the hash of the exact bytes (threat model R1).
fn spec_ref(loaded: &LoadedSpec, path: &std::path::Path) -> SpecRef {
    let meta = &loaded.spec().metadata;
    let file_name = path.file_name().map_or_else(
        || "spec.yaml".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let mut spec = SpecRef::new(
        meta.product.as_str(),
        loaded.sha256(),
        file_name,
        u64::try_from(loaded.verified_bytes().yaml().len()).unwrap_or(u64::MAX),
    );
    spec.version.clone_from(&meta.version);
    spec.serial = meta.serial;
    spec.expires.clone_from(&meta.expires);
    spec.contact.clone_from(&meta.contact);
    spec.annotations.clone_from(&meta.annotations);
    spec
}

/// The machine, coarsely: the host name, the kernel release and the architecture. `host_id` stays
/// `null` until M2-002, and the OS release fields stay unset until the host report reads them.
async fn host_facts(probe: &Probe) -> Host {
    let hostname = match probe.native(NativeCall::Hostname).await {
        Ok(NativeValue::Hostname(name)) if !name.trim().is_empty() => name,
        _ => "unknown".to_owned(),
    };
    let uname = match probe.native(NativeCall::Uname).await {
        Ok(NativeValue::Uname(info)) => Some(info),
        _ => None,
    };
    let family = host_os_family();
    let arch = uname
        .as_ref()
        .map_or_else(|| std::env::consts::ARCH.to_owned(), |u| u.machine.clone());
    let mut host = Host::new(hostname, HostOs::new(family), arch);
    host.kernel = uname.map(|u| u.release);
    host
}

/// A random UUID v4, as text.
fn uuid_v4() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CliError::Internal(InternalKind::NoRandomness))?;
    if let Some(b) = bytes.get_mut(6) {
        *b = (*b & 0x0f) | 0x40;
    }
    if let Some(b) = bytes.get_mut(8) {
        *b = (*b & 0x3f) | 0x80;
    }
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let (a, rest) = hex.split_at(4);
    let (b, rest) = rest.split_at(2);
    let (c, rest) = rest.split_at(2);
    let (d, e) = rest.split_at(2);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        a.concat(),
        b.concat(),
        c.concat(),
        d.concat(),
        e.concat()
    ))
}

#[cfg(test)]
mod tests;
