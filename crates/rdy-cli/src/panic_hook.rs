//! The panic hook (ADR 0015 decision 6, 04 section 3.4, 07 section 5).
//!
//! The default hook prints `thread 'x' panicked at file:line:` and the raw message to stderr. The
//! message can hold anything the code had in hand, so rdy replaces the hook before it does anything
//! else. [`install`] never lets the default text reach stderr, and the new hook **prints nothing**.
//!
//! - A panic inside a check is caught by the scheduler and becomes an `ERROR` result. Its text goes
//!   through `PanicText::redacted`. Nothing else is printed (07, row 10 of the check outcomes).
//! - A panic outside a check unwinds to [`crate::entry::guarded`], which prints the two standard lines
//!   (or the `ErrorOutput` with `--json`) and exits 70.
//! - A panic in another thread or task that nobody joins is silent.
//!
//! The hook does not redact. A panic inside a panic hook aborts the process, so a redactor bug in the
//! hook could not be contained. The hook keeps only the source location of the panic, which is a
//! compile-time constant and holds no input. The payload is read, redacted and escaped where the panic
//! is caught.

use std::any::Any;
use std::cell::RefCell;
use std::panic;

thread_local! {
    static LOCATION: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Replaces the panic hook. The previous hook, normally the default one, is dropped.
pub fn install() {
    panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        // Never panic in a hook. A thread that is shutting down may have no slot, which is fine.
        let _ = LOCATION.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                *slot = at;
            }
        });
    }));
}

/// The location of the last panic on this thread, once. The latest panic wins, including one that was
/// caught and handled earlier.
#[must_use]
pub fn take_location() -> Option<String> {
    LOCATION
        .try_with(|slot| slot.try_borrow_mut().ok().and_then(|mut s| s.take()))
        .ok()
        .flatten()
}

/// The raw text of a panic payload. Redact it, then escape it, before it goes anywhere.
#[must_use]
pub fn payload_text(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a non-text payload")
        .to_owned()
}
