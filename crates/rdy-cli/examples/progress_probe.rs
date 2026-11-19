//! Test helper for `tests/run_progress_pty.rs`. It is not a rdy command and is not shipped.
//!
//! It runs `rdy_cli::run` in process on the real stdout and stderr, on a replay machine, with one check
//! that waits `RDY_PROBE_NAP_MS` milliseconds (900 by default) and then passes. Every other hook is the
//! default, so the live progress line sees the real terminal check, the real environment and the real
//! stderr. The arguments after the program name are the arguments of `rdy`.
#![allow(clippy::expect_used)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rdy_cli::RunHooks;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};
use rdy_engine::check::{Os, current_os};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_engine::testing::Replay;
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

static NAP: CheckInfo = CheckInfo {
    id: "host.cpu",
    family: "host",
    summary: "Waits a while and passes.",
    meta: CheckMeta {
        title: "Nap",
        remediation: "Nothing to fix. A test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: FULL,
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

struct Nap;

impl Check for Nap {
    fn info(&self) -> &'static CheckInfo {
        &NAP
    }

    fn run<'a>(&'a self, _: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async {
            let ms = std::env::var("RDY_PROBE_NAP_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(900);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(Finding::pass("rested".to_owned()))
        })
    }
}

static NAP_LIST: [&CheckInfo; 1] = [&NAP];

struct NapFamily;

impl Family for NapFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &NAP_LIST
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Nap)))
    }
}

fn registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(NapFamily)?;
    Ok(registry)
}

/// A clean privilege snapshot (user 1000, no capability, no `AT_SECURE`) for the OS of the test.
fn machine() -> Replay {
    let user = [1000_u32; 4];
    let status = format!(
        "Name:\trdy\nUid:\t{0}\t{0}\t{0}\t{0}\nGid:\t{0}\t{0}\t{0}\t{0}\nCapEff:\t{1:016x}\nCapPrm:\t{1:016x}\nCapAmb:\t{1:016x}\n",
        user[0], 0_u64
    );
    let mut auxv = Vec::new();
    for (key, value) in [(3_usize, 0x5555_0000_usize), (23, 0), (0, 0)] {
        auxv.extend(key.to_ne_bytes());
        auxv.extend(value.to_ne_bytes());
    }
    match current_os() {
        Os::Macos => Replay::for_os(Os::Macos).ids(user, user),
        _ => Replay::new()
            .file("/proc/self/status", status)
            .file("/proc/self/auxv", auxv),
    }
}

fn main() -> ExitCode {
    let mut hooks = RunHooks::default();
    hooks.families = Some(registry);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let code = runtime
        .block_on(rdy_cli::run(
            std::env::args_os(),
            Arc::new(machine()),
            hooks,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        ))
        .code();
    ExitCode::from(code)
}
