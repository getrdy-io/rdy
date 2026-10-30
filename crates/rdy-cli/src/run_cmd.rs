//! `rdy run`, end to end (M1-057, 07 sections 1 and 4.1, 02 "Privilege and needs").
//!
//! The order is the security property. [`crate::run`] has already taken the privilege snapshot and
//! passed the gate (INV-10), so nothing here runs for a binary with extra privilege. Then:
//!
//! 1. Read the spec file and, when there is one, its `.minisig` sidecar. Verify, then parse
//!    ([`rdy_spec::load`], INV-01). A spec that fails stops here with exit 64 and no folder.
//! 2. Make the report folder, right after verification and before any check (ADR 0016). `--no-report`
//!    makes none.
//! 3. Plan, probe the needs, run the checks, map and redact each result ([`Engine::execute`]).
//! 4. Build the report from the results and the facts of the run (producer, run, spec, signature,
//!    host, identity from the privilege snapshot), redact the whole of it and write it.
//! 5. Write the files, then print: with `--json` the same bytes as the `.json` file on stdout, and a
//!    short result on stderr. The full terminal layout is M1-086.
//!
//! **Exit codes.** A verdict gives 0, 1 or 2. A spec problem gives 64. A folder that cannot be made, a
//! report that cannot be written and a bug give 70. When the files cannot be written after the
//! verdict exists, the result still prints (stdout gets the Report with `complete: false`, 07 section
//! 4.1) and the exit code is 70. If even that cannot be written, stdout gets the error object.
//!
//! **Not here.** The proxy (M1-097), the hosts of a check's spec entry (M1-095), Ctrl-C (M1-058),
//! `--jobs` (M1-059), the kube flags (M1-107), `--key` and the unsigned banner (M1-126) and the terminal
//! renderer (M1-086).

use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use rdy_engine::check::{Os, current_os};
use rdy_engine::engine::{Engine, RunOptions as EngineOptions};
use rdy_engine::family::Registry;
use rdy_engine::output::{OutputDir, report_time};
use rdy_engine::privilege::Privilege;
use rdy_engine::probe::{NativeCall, NativeValue, Probe, ProbeHub};
use rdy_engine::redact::{RedactedReport, Redactor, RuleCounts};
use rdy_engine::report::{JsonError, write_json};
use rdy_engine::sched::{DEFAULT_DEADLINE, cap_jobs};
use rdy_engine::summary::{last_line, summary_line};
use rdy_spec::result::{
    Host, HostOs, HostOsFamily, Producer, Report, Run, RunOptions, Signature, SpecRef,
};
use rdy_spec::sig::{MAX_SIGNATURE_BYTES, Policy, TrustStore};
use rdy_spec::{LoadedSpec, load};

use crate::cli::{COMMIT, RunArgs, TARGET};
use crate::error::{
    CliError, InternalKind, IoReason, ReportStep, emit, escape_untrusted, shell_word,
};
use crate::hooks::RunHooks;
use crate::output::{open_report_dir, report_error};
use crate::signing::files::{FileError, read_public};
use crate::trust::{self, Layout, Vars};
use crate::{lint, redaction};

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
    let origin = Instant::now();
    let RunContext {
        hub,
        redactor,
        privilege,
        hooks,
        registry,
    } = cx;
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

    let started_at = clock();
    let product = loaded.spec().metadata.product.as_str().to_owned();
    let dir = open_report_dir(args, &product, started_at)?;

    let mut options = EngineOptions::new();
    options.network = !args.no_network;
    options.deadline = hooks.deadline.unwrap_or(DEFAULT_DEADLINE);
    options.spec_arg = shell_word(&name);
    options.origin = Some(origin);

    let run_id = match &hooks.run_id {
        Some(id) => id.clone(),
        None => uuid_v4()?,
    };
    let host = host_facts(&hub.run_probe()).await;
    let engine = Engine::new(registry, hub);
    let plan = engine.plan(&loaded, current_os(), env!("CARGO_PKG_VERSION"));
    let executed = engine.execute(&loaded, plan, &privilege, &options).await;

    let finished_at = clock();
    let mut run_options = RunOptions::new(
        u32::try_from(cap_jobs(options.jobs)).unwrap_or(1),
        u64::try_from(options.deadline.as_millis()).unwrap_or(u64::MAX),
    );
    run_options.allow_unsigned = args.allow_unsigned;
    run_options.network = options.network;
    run_options.kube_context.clone_from(&args.kube_context);
    let run = Run::new(
        run_id,
        report_time(started_at),
        report_time(finished_at),
        u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        run_options,
    );
    let mut report = Report::new(
        producer(),
        run,
        spec_ref(&loaded, &args.spec),
        Signature::from(loaded.signature()),
        host,
        privilege.identity(),
        executed.results,
    );
    report.capabilities = executed.capabilities;
    executed.log.apply(&mut report);
    let counts = executed.counts;

    let redacted = redactor
        .redact_report_counted(report.clone(), counts.clone())
        .map_err(|_| CliError::bug())?;

    // Files first, so the "Report written to" line is true when it prints.
    let files = match &dir {
        Some(dir) => write_files(dir, &loaded, &redacted).map(|()| Some(dir)),
        None => Ok(None),
    };
    match files {
        Ok(written) => {
            if json {
                write_json(&redacted, stdout).map_err(writer_error)?;
            }
            print_result(&redacted, written, args, stderr);
            Ok(redacted.exit_code)
        }
        Err(error) => Ok(fail_after_verdict(
            &error, report, counts, &redactor, json, stdout, stderr,
        )),
    }
}

/// The files could not be written, but the verdict exists. The result still prints (07 section 4.1): the
/// Report with `complete: false` on stdout with `--json`, the summary on stderr, then the error. The
/// exit code is 70. If the report cannot be printed either (it is over the cap, or stdout is closed),
/// stdout gets the error object instead.
fn fail_after_verdict(
    error: &CliError,
    mut report: Report,
    counts: RuleCounts,
    redactor: &Redactor,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    report.complete = false;
    let incomplete = redactor.redact_report_counted(report, counts).ok();
    let printed = json
        && incomplete
            .as_ref()
            .is_some_and(|report| write_json(report, stdout).is_ok());
    if let Some(report) = &incomplete {
        print_summary(report, stderr);
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

/// Writes the spec copy and the JSON report into the folder.
fn write_files(
    dir: &OutputDir,
    loaded: &LoadedSpec,
    report: &RedactedReport,
) -> Result<(), CliError> {
    let failed = |error| report_error(ReportStep::WriteFiles, dir.path(), error);
    dir.write_spec(loaded.verified_bytes()).map_err(failed)?;
    dir.write_json(report).map_err(failed)?;
    Ok(())
}

/// The error for a failed write of the JSON document to stdout.
fn writer_error(error: JsonError) -> CliError {
    CliError::report_writer(&error).unwrap_or_else(CliError::bug)
}

/// The summary, where the report went, and the verdict, on stderr. The full layout is M1-086.
fn print_result(
    report: &RedactedReport,
    written: Option<&OutputDir>,
    args: &RunArgs,
    stderr: &mut dyn Write,
) {
    print_summary(report, stderr);
    if let Some(dir) = written {
        let folder = dir.path().display().to_string();
        let line =
            redaction::redact_text_then(&format!("Report written to {folder}/"), escape_untrusted);
        let _ = writeln!(stderr, "{line}");
        if cfg!(windows) && args.out_dir.is_some() {
            let _ = writeln!(
                stderr,
                "note: on Windows rdy cannot set who may read the report folder. It keeps the access of the folder it is in. For the most privacy, leave out --out-dir and use the default folder."
            );
        }
    }
    let _ = writeln!(stderr, "{}", last_line(&report.checks));
}

fn print_summary(report: &RedactedReport, stderr: &mut dyn Write) {
    let _ = writeln!(stderr, "{}", summary_line(&report.checks));
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
    let family = match current_os() {
        Os::Macos => HostOsFamily::Macos,
        Os::Windows => HostOsFamily::Windows,
        _ => HostOsFamily::Linux,
    };
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
