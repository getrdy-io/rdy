//! Helpers for testing checks (feature `testing`, never in the release binary).
//!
//! A check crate builds a [`TestRun`] over a [`Replay`] fixture, asks it for a
//! [`CheckContext`] and runs the check against it. The probe in that
//! context applies the real policy and writes the real action log, so a test sees what a run would
//! refuse and record.
//!
//! ```
//! # use rdy_engine::check::{Need, Os};
//! # use rdy_engine::testing::{Replay, TestRun};
//! let run = TestRun::new(Replay::new().file("/proc/meminfo", "MemTotal: 1 kB\n"));
//! let ctx = run.context("host.memory", Os::Linux, [Need::Root]);
//! assert_eq!(ctx.key(), "host.memory");
//! assert!(run.action_log().actions.is_empty());
//! ```

use std::path::PathBuf;
use std::sync::Arc;

pub use crate::probe::replay::{
    ApiRecord, Caps, DnsAnswer, Expect, Fixture, FixtureError, Manifest, NetScript, Origin, Replay,
    RunPins, TcpScript,
};

#[cfg(feature = "loopback")]
pub mod loopback;

use crate::check::{CheckContext, CheckInfo, Need, Os};
use crate::family::HostSet;
use crate::probe::{ActionLogOutput, Probe, ProbeHub};
use crate::redact::{Redactor, TagKey};

/// The shared fixtures directory, `tests/fixtures` at the repo root (08 section 1). It resolves from
/// this crate's manifest directory, so it works from any crate of the workspace and not from a
/// crates.io tarball, which does not ship the fixtures.
#[must_use]
pub fn fixtures_dir() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// One fixture run: a replay backend, a probe hub and the action log they write.
#[derive(Debug, Clone)]
pub struct TestRun {
    hub: ProbeHub,
}

impl TestRun {
    /// A run over `replay`. Redaction tags are the same on every run.
    #[must_use]
    pub fn new(replay: Replay) -> Self {
        let redactor = Redactor::new(TagKey::fixed([7; 32]));
        Self {
            hub: ProbeHub::new(Arc::new(replay), redactor),
        }
    }

    /// A run over the machine of a loaded fixture (08 section 2).
    #[must_use]
    pub fn for_fixture(fixture: &Fixture) -> Self {
        Self::new(fixture.replay().clone())
    }

    /// Shows paths under `home` as `~/...` in the log.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.hub = self.hub.with_home(home);
        self
    }

    /// A context for the check with result `key`, on `os`, where the `available` needs are met. Its
    /// probe is bound to `key` and never ends, so a test can call it after the check returns. The
    /// probe has no manifest, so a command skips the declaration step and still has to be in the command
    /// table for `os`. A check's own test must use [`TestRun::context_for`], which applies what the
    /// check declared in its `CheckInfo`, as a real run does. This one is for tests of the probe and
    /// the harness (M1-044 may lint its use in check crates).
    #[must_use]
    pub fn context(
        &self,
        key: &str,
        os: Os,
        available: impl IntoIterator<Item = Need>,
    ) -> CheckContext {
        CheckContext::new(key, os, available).with_probe(self.hub.check_probe(key, os, None))
    }

    /// Like [`TestRun::context`], for a check with the manifest `info`. A command must be one that
    /// `info.commands` declares, and its directories, environment names and stdout cap come from
    /// there, as in a real run.
    #[must_use]
    pub fn context_for(
        &self,
        info: &'static CheckInfo,
        key: &str,
        os: Os,
        available: impl IntoIterator<Item = Need>,
    ) -> CheckContext {
        CheckContext::new(key, os, available).with_probe(self.hub.check_probe(key, os, Some(info)))
    }

    /// Like [`TestRun::context_for`], for a check whose spec entry names `hosts`. The probe may send
    /// a datagram only to these (`Probe::udp_exchange`), as a real run does with `Built::hosts`. With
    /// [`TestRun::context_for`] there are no hosts and every datagram is refused.
    #[must_use]
    pub fn context_for_hosts(
        &self,
        info: &'static CheckInfo,
        key: &str,
        os: Os,
        available: impl IntoIterator<Item = Need>,
        hosts: HostSet,
    ) -> CheckContext {
        let probe = self.hub.check_probe(key, os, Some(info));
        probe.permit_hosts(hosts);
        CheckContext::new(key, os, available).with_probe(probe)
    }

    /// The run-level probe (`check: null` in the log) for `os`, as the privilege snapshot and the
    /// capability probes use it.
    #[must_use]
    pub fn run_probe(&self, os: Os) -> Probe {
        self.hub.run_probe_for(os)
    }

    /// Adds a secret to the run's known-secret set, as the facade does for a kubeconfig token (ADR 0015
    /// decision 3). Returns `false` if the value was refused (see `Redactor::add_known_secret`).
    pub fn add_known_secret(&self, secret: &str) -> bool {
        self.hub.add_known_secret(secret)
    }

    /// A scheduler whose checks get a probe from this run, so a test sees the check's timeout, its
    /// manifest and the action log as a real run does. A test that needs a hung call to end in
    /// `End::TimedOut` runs the check through it (`Scheduler::run`), on a runtime with a paused clock.
    #[cfg(feature = "runtime")]
    #[must_use]
    pub fn scheduler(
        &self,
        jobs: usize,
        os: Os,
        available: impl IntoIterator<Item = Need>,
    ) -> crate::sched::Scheduler {
        crate::sched::Scheduler::new(jobs, os, available).with_probes(self.hub.clone())
    }

    /// The action log so far.
    #[must_use]
    pub fn action_log(&self) -> ActionLogOutput {
        self.hub.action_log()
    }
}

/// Whether `actual` is the golden text `expected`, where a placeholder stands for a value that changes
/// from run to run (08 Appendix C):
///
/// - `<sha256>` is 64 lower case hex digits, for the digest of a generated certificate;
/// - `<serial>` is a run of 2 to 64 hex digits, for a generated serial number. It takes the longest
///   run, so a literal that follows it must not begin with a hex digit.
///
/// Everything else must match byte for byte. A golden file with placeholders therefore compares equal
/// across runs whose generated values differ, and still fails when anything else changes.
///
/// ```
/// # use rdy_engine::testing::matches_placeholders;
/// let digest = "ab".repeat(32);
/// assert!(matches_placeholders(
///     r#"{"root_sha256":"<sha256>"}"#,
///     &format!(r#"{{"root_sha256":"{digest}"}}"#),
/// ));
/// assert!(!matches_placeholders("<sha256>", "not a digest"));
/// ```
#[must_use]
pub fn matches_placeholders(expected: &str, actual: &str) -> bool {
    const SHA256: &str = "<sha256>";
    const SERIAL: &str = "<serial>";
    let mut want = expected;
    let mut have = actual;
    loop {
        let sha = want.find(SHA256).map(|at| (at, SHA256));
        let serial = want.find(SERIAL).map(|at| (at, SERIAL));
        let next = match (sha, serial) {
            (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
            (a, b) => a.or(b),
        };
        let Some((at, token)) = next else {
            return want == have;
        };
        let (literal, rest) = want.split_at(at);
        let Some(after) = have.strip_prefix(literal) else {
            return false;
        };
        let run = after.bytes().take_while(u8::is_ascii_hexdigit).count();
        let lower = after.bytes().take(run).all(|b| !b.is_ascii_uppercase());
        let fits = if token == SHA256 {
            run == 64 && lower
        } else {
            (2..=64).contains(&run)
        };
        if !fits {
            return false;
        }
        want = rest.get(token.len()..).unwrap_or_default();
        have = after.get(run..).unwrap_or_default();
    }
}
