//! The panic hook (ADR 0015 decision 6, 04 section 3.4).
//!
//! The default hook prints `thread 'x' panicked at file:line:` and the raw message to stderr. The
//! message can hold anything the code had in hand, so rdy replaces the hook before it does anything
//! else. [`install`] never lets the default text reach stderr.
//!
//! The hook prints the same two lines as every other internal error: `error:` with the redacted
//! message, and `fix:` with the bug hint. A panic inside a check is also caught by the scheduler and
//! reported as an `ERROR` result (its text goes through `PanicText::redacted`). The hook runs first, in
//! both cases.

use std::io::Write;
use std::panic::{self, PanicHookInfo};

use rdy_engine::redact::Redactor;

use crate::error::{BUG_HINT, escape_untrusted};

/// A function that opens the stream the hook writes to. `main` passes stderr.
pub type OpenSink = Box<dyn Fn() -> Box<dyn Write> + Send + Sync>;

/// Replaces the panic hook. The previous hook, normally the default one, is dropped.
pub fn install(redactor: Redactor, sink: OpenSink) {
    panic::set_hook(Box::new(move |info| {
        let text = report(info, &redactor);
        let mut out = sink();
        // A closed stderr has nowhere to report to, and the exit code still says 70.
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }));
}

/// The two lines the hook prints, each ending in a newline.
fn report(info: &PanicHookInfo<'_>, redactor: &Redactor) -> String {
    let payload = info.payload();
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a non-text payload");
    // Escape first: this is the text that reaches the terminal. Then redact it.
    // The message and the location are redacted apart. A bare secret value runs to the end of its line,
    // so a location behind the message would be lost with it.
    let message = redactor.redact_str(&escape_untrusted(message));
    let at = info
        .location()
        .map(|l| {
            let place = escape_untrusted(&format!("{}:{}:{}", l.file(), l.line(), l.column()));
            format!(" (at {})", &**redactor.redact_str(&place))
        })
        .unwrap_or_default();
    format!(
        "error: rdy hit an internal error: {}{at}\nfix: {BUG_HINT}\n",
        &**message
    )
}
