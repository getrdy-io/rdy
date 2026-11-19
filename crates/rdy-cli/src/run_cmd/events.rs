//! The event lines of `rdy run --verbose` (07 section 2.8 and C.2, M1-143).
//!
//! The engine tells a `ProgressHook` when each scheduled check ends, from the scheduler's tasks. The hook
//! cannot write to stderr itself: the run holds stderr as a plain `&mut dyn Write`. So the hook puts a
//! finished line in an [`EventQueue`] and wakes the run, and [`Narrated::execute`] writes the lines while
//! it waits for the engine. A line is written as soon as its check ends, on a pipe too, so the lines are
//! there before the report text. The lines are text on stderr only. Nothing goes to stdout.
//!
//! **A full stderr pipe.** The write is blocking and happens on the run's current-thread runtime. If the
//! reader of stderr stops reading and the pipe fills, the runtime stalls with it, and the watchdog (a
//! thread of its own) ends the run with exit 70 and a partial report (07 section 5.2). That is the
//! same end as a stalled `--json` pipe, and it is why the lines are small and written one at a time.

use std::future::poll_fn;
use std::io::Write;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Waker;

use rdy_engine::engine::{Engine, Executed, Progress, ProgressHook, RunOptions as EngineOptions};
use rdy_engine::plan::RunPlan;
use rdy_engine::privilege::Privilege;
use rdy_spec::LoadedSpec;

use super::{Look, say};
use crate::style::Styler;
use crate::terminal::event_line;

#[derive(Default)]
struct State {
    lines: Vec<String>,
    waker: Option<Waker>,
}

/// Finished lines on their way from the scheduler's tasks to stderr.
#[derive(Clone, Default)]
pub(super) struct EventQueue(Arc<Mutex<State>>);

impl EventQueue {
    /// The hook to give the engine. The engine redacts the key, and [`event_line`] escapes it.
    pub(super) fn hook(&self, styler: Styler) -> ProgressHook {
        let queue = self.clone();
        ProgressHook::new(move |event| {
            // Events are added over time. This one prints the ones it knows.
            let Progress::Finished(done) = event else {
                return;
            };
            let line = event_line(done.key, done.status, done.duration_ms, styler);
            let waker = {
                let mut state = queue.0.lock().unwrap_or_else(PoisonError::into_inner);
                state.lines.push(line);
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        })
    }

    /// Takes the lines so far and, with a waker, asks to be woken for the next one. Both happen under one
    /// lock, so a line pushed in between cannot be missed.
    fn take(&self, waker: Option<&Waker>) -> Vec<String> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(waker) = waker {
            state.waker = Some(waker.clone());
        }
        std::mem::take(&mut state.lines)
    }
}

/// The engine as `rdy run` calls it. Without `--verbose` it is the engine. With it, [`Narrated::execute`]
/// also writes the queue's lines to stderr while the checks run.
pub(super) struct Narrated {
    engine: Engine,
    events: Option<(EventQueue, Look)>,
}

impl Narrated {
    /// With `verbose`, puts the finish hook in `options`.
    pub(super) fn new(
        engine: Engine,
        verbose: bool,
        look: Look,
        options: &mut EngineOptions,
    ) -> Self {
        let events = verbose.then(|| {
            let queue = EventQueue::default();
            options.on_progress = Some(queue.hook(look.styler()));
            (queue, look)
        });
        Self { engine, events }
    }

    /// [`Engine::execute`]. `after_poll` runs after every poll of the engine, with `stderr`: the run uses
    /// it for the lines a family announces (ADR 0031) and to clear the live line. With `--verbose`, the
    /// event lines are written before each poll. When any was written, one blank line follows, so the
    /// lines are a block of their own above the report text.
    pub(super) async fn execute(
        &mut self,
        spec: &LoadedSpec,
        plan: RunPlan,
        privilege: &Privilege,
        options: &EngineOptions,
        stderr: &mut dyn Write,
        after_poll: &mut dyn FnMut(&mut dyn Write),
    ) -> Executed {
        let work = self.engine.execute(spec, plan, privilege, options);
        let mut work = pin!(work);
        let events = self.events.as_ref().map(|(queue, look)| (queue, *look));
        let mut written = false;
        let output = poll_fn(|cx| {
            if let Some((queue, look)) = events {
                for line in queue.take(Some(cx.waker())) {
                    say(&mut *stderr, look, &line);
                    written = true;
                }
            }
            let polled = work.as_mut().poll(cx);
            after_poll(&mut *stderr);
            polled
        })
        .await;
        if let Some((queue, look)) = events {
            for line in queue.take(None) {
                say(&mut *stderr, look, &line);
                written = true;
            }
            if written {
                say(&mut *stderr, look, "\n");
            }
        }
        output
    }
}
