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

pub use crate::probe::replay::Replay;

use crate::check::{CheckContext, CheckInfo, Need, Os};
use crate::family::HostSet;
use crate::probe::{ActionLogOutput, Probe, ProbeHub};
use crate::redact::{Redactor, TagKey};

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

    /// The action log so far.
    #[must_use]
    pub fn action_log(&self) -> ActionLogOutput {
        self.hub.action_log()
    }
}
