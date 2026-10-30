//! `FakeCheck`: a check that does one scripted thing, for scheduler and report tests (02 "Time and
//! hangs", 08 section 5).
//!
//! It needs the runtime (it sleeps on the tokio clock and blocks on the blocking pool), so it is built
//! only with feature `runtime`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::json;

use crate::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};

/// The info of a fake check with no needs, no reads and no default timeout. Its id is `fake.plain`.
pub static FAKE_INFO: CheckInfo = CheckInfo {
    id: "fake.plain",
    family: "fake",
    summary: "A fake check with no needs.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// What a [`FakeCheck`] does when it runs.
///
/// Every variant but [`Fake::Outcome`] and [`Fake::Panic`] ends with the same pass as
/// [`FakeCheck::passed`], so a test can tell that the check ran to the end.
#[non_exhaustive]
pub enum Fake {
    /// Returns this outcome at once. It covers every status: a [`Finding`] of each level, and each
    /// [`CheckError`](crate::check::CheckError).
    ///
    /// Boxed: a finding carries two JSON values, which are large when `serde_json` keeps key order
    /// (ADR 0019).
    Outcome(Box<CheckOutcome>),
    /// Waits this long on the tokio clock, then passes. Under paused time the wait costs nothing.
    Sleep(Duration),
    /// Waits on the tokio clock for ever. The scheduler's timeout is what ends it.
    Forever,
    /// Panics with this text.
    Panic(String),
    /// Waits on a blocking-pool thread that the test releases ([`FakeCheck::block`]). The thread
    /// outlives an abort of the check, as a real stuck read does.
    Block(Mutex<Option<Receiver<()>>>),
    /// Holds its worker thread, never yielding, until the test releases it ([`FakeCheck::spin`]).
    ///
    /// It needs a multi-thread runtime (`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`).
    /// On the current-thread runtime that `#[tokio::test]` builds by default, the spin would hold the
    /// only thread, the scheduler's timer could never fire and the test would hang. Running it there
    /// panics with that advice instead.
    Spin(Arc<AtomicBool>),
}

impl std::fmt::Debug for Fake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The panic text is not printed: it stands for text a check might hold in hand.
        f.write_str(match self {
            Self::Outcome(_) => "Fake::Outcome(..)",
            Self::Sleep(_) => "Fake::Sleep(..)",
            Self::Forever => "Fake::Forever",
            Self::Panic(_) => "Fake::Panic(..)",
            Self::Block(_) => "Fake::Block(..)",
            Self::Spin(_) => "Fake::Spin(..)",
        })
    }
}

/// Lets a [`Fake::Block`] or [`Fake::Spin`] go. Dropping it lets it go too, so a test that fails an
/// assert before it releases does not leave a thread behind for ever.
///
/// Bind it to a name that lives as long as the test: `let (check, release) = FakeCheck::block();`.
/// `let (check, _) = ...` drops it at once and frees the fake before it runs, which defeats the test.
#[derive(Debug)]
#[must_use = "dropping a Release frees the fake at once; bind it to a name and keep it until the test is done"]
pub struct Release(Hold);

#[derive(Debug)]
enum Hold {
    Flag(Arc<AtomicBool>),
    Channel(Sender<()>),
}

impl Release {
    /// Lets the check go now.
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        match &self.0 {
            Hold::Flag(flag) => flag.store(true, Ordering::SeqCst),
            // A send that finds no receiver is fine, and dropping the sender releases the receiver
            // anyway.
            Hold::Channel(sender) => drop(sender.send(())),
        }
    }
}

/// A check that does what its [`Fake`] says.
#[derive(Debug)]
pub struct FakeCheck {
    info: &'static CheckInfo,
    fake: Fake,
}

impl FakeCheck {
    /// A fake with the info [`FAKE_INFO`].
    #[must_use]
    pub fn new(fake: Fake) -> Self {
        Self::with_info(&FAKE_INFO, fake)
    }

    /// A fake with its own info, for a test of needs, timeouts or the manifest.
    #[must_use]
    pub fn with_info(info: &'static CheckInfo, fake: Fake) -> Self {
        Self { info, fake }
    }

    /// A fake that returns `outcome` at once.
    #[must_use]
    pub fn outcome(outcome: CheckOutcome) -> Self {
        Self::new(Fake::Outcome(Box::new(outcome)))
    }

    /// A fake that passes at once.
    #[must_use]
    pub fn pass() -> Self {
        Self::sleep(Duration::ZERO)
    }

    /// A fake that passes after `wait` on the tokio clock.
    #[must_use]
    pub fn sleep(wait: Duration) -> Self {
        Self::new(Fake::Sleep(wait))
    }

    /// A fake that never returns.
    #[must_use]
    pub fn forever() -> Self {
        Self::new(Fake::Forever)
    }

    /// A fake that panics with `text`.
    #[must_use]
    pub fn panic(text: impl Into<String>) -> Self {
        Self::new(Fake::Panic(text.into()))
    }

    /// A fake that waits on a blocking-pool thread until the returned [`Release`] is used or dropped.
    ///
    /// Bind the [`Release`] to a name (not `_`), or the fake is freed before it runs. The fake can run
    /// once: its receiver goes to the blocking thread, and a second run panics.
    pub fn block() -> (Self, Release) {
        let (sender, receiver) = mpsc::channel();
        let fake = Self::new(Fake::Block(Mutex::new(Some(receiver))));
        (fake, Release(Hold::Channel(sender)))
    }

    /// A fake that spins on its worker until the returned [`Release`] is used or dropped.
    ///
    /// Bind the [`Release`] to a name (not `_`), or the fake is freed before it runs. It needs a
    /// multi-thread runtime, as [`Fake::Spin`] says.
    pub fn spin() -> (Self, Release) {
        let flag = Arc::new(AtomicBool::new(false));
        let fake = Self::new(Fake::Spin(Arc::clone(&flag)));
        (fake, Release(Hold::Flag(flag)))
    }

    /// The pass a fake ends with: the message is `<key> ran` and `observed` is `{"ok": true}`.
    pub fn passed(key: &str) -> CheckOutcome {
        Ok(Finding::pass(format!("{key} ran")).with_observed(json!({ "ok": true })))
    }
}

impl Check for FakeCheck {
    fn info(&self) -> &'static CheckInfo {
        self.info
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            match &self.fake {
                Fake::Outcome(outcome) => return (**outcome).clone(),
                Fake::Sleep(wait) if wait.is_zero() => {}
                Fake::Sleep(wait) => tokio::time::sleep(*wait).await,
                Fake::Forever => std::future::pending::<()>().await,
                Fake::Panic(text) => panic!("{text}"),
                Fake::Block(slot) => {
                    let receiver = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
                    let Some(receiver) = receiver else {
                        panic!(
                            "this FakeCheck::block() fake has already run once and cannot block \
                             again. Fix: make a new one with FakeCheck::block() for each run."
                        );
                    };
                    // Ends when the test sends, or drops its `Release`. If the task is aborted
                    // first, the thread stays here until then, which is what the test is for.
                    drop(tokio::task::spawn_blocking(move || receiver.recv()).await);
                }
                Fake::Spin(flag) => {
                    assert!(
                        tokio::runtime::Handle::current().runtime_flavor()
                            != tokio::runtime::RuntimeFlavor::CurrentThread,
                        "FakeCheck::spin() needs a multi-thread runtime, or the timeout can never \
                         fire. Fix: use #[tokio::test(flavor = \"multi_thread\", worker_threads = 2)]."
                    );
                    while !flag.load(Ordering::SeqCst) {
                        std::hint::spin_loop();
                    }
                }
            }
            Self::passed(ctx.key())
        })
    }
}
