//! The event lines of `rdy run --verbose` (07 section 2.8 and C.2, M1-143).
//!
//! The engine tells a [`FinishHook`] when each scheduled check ends, from the scheduler's tasks. The hook
//! cannot write to stderr itself: the run holds stderr as a plain `&mut dyn Write`. So the hook puts a
//! finished line in an [`EventQueue`] and wakes the run, and [`drive`] writes the lines while it waits
//! for the engine. A line is written as soon as its check ends, on a pipe too, so a run that hangs still
//! shows what finished. The lines are text on stderr only. Nothing goes to stdout.

use std::future::poll_fn;
use std::io::Write;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Waker;

use rdy_engine::engine::{Engine, Executed, FinishHook, RunOptions as EngineOptions};
use rdy_engine::plan::RunPlan;
use rdy_engine::privilege::Privilege;
use rdy_spec::LoadedSpec;

use super::{Look, say};
use crate::redaction;
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
    /// The hook to give the engine. The key is redacted, then escaped by [`event_line`].
    pub(super) fn hook(&self, styler: Styler) -> FinishHook {
        let queue = self.clone();
        FinishHook::new(move |done| {
            let line = event_line(
                &redaction::redact_text(done.key),
                done.status,
                done.duration_ms,
                styler,
            );
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
pub(super) struct Narrated<'a> {
    engine: Engine,
    events: Option<(EventQueue, Look, &'a mut dyn Write)>,
}

impl<'a> Narrated<'a> {
    /// With `verbose`, puts the finish hook in `options` and keeps `stderr` for the lines.
    pub(super) fn new(
        engine: Engine,
        verbose: bool,
        look: Look,
        options: &mut EngineOptions,
        stderr: &'a mut dyn Write,
    ) -> Self {
        let events = verbose.then(|| {
            let queue = EventQueue::default();
            options.on_finish = Some(queue.hook(look.styler()));
            (queue, look, stderr)
        });
        Self { engine, events }
    }

    /// [`Engine::execute`]. When any line was written, one blank line follows, so the lines are a block of
    /// their own above the report text.
    pub(super) async fn execute(
        &mut self,
        spec: &LoadedSpec,
        plan: RunPlan,
        privilege: &Privilege,
        options: &EngineOptions,
    ) -> Executed {
        let work = self.engine.execute(spec, plan, privilege, options);
        let Some((queue, look, stderr)) = self.events.as_mut() else {
            return work.await;
        };
        let (queue, look) = (&*queue, *look);
        let mut work = pin!(work);
        let mut written = false;
        let output = poll_fn(|cx| {
            for line in queue.take(Some(cx.waker())) {
                say(&mut **stderr, look, &line);
                written = true;
            }
            work.as_mut().poll(cx)
        })
        .await;
        for line in queue.take(None) {
            say(&mut **stderr, look, &line);
            written = true;
        }
        if written {
            say(&mut **stderr, look, "\n");
        }
        output
    }
}
