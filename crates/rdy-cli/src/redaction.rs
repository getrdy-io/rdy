//! The process-wide redactor (ADR 0015, 04 section 3.4).
//!
//! `main` builds one [`Redactor`] first, before the spec is read ([`init`]). The log writer, the panic
//! hook and the CLI error text all use it, so equal secrets get equal tags everywhere in one run.
//!
//! The key is made once. If the OS cannot supply random bytes, [`init`] fails and rdy exits 70.
//! A caller that asks for the redactor before `init` (an in-process test) gets the same lazy key.
//! If no key can be made, or the redactor itself panics, [`redact_text`] replaces the whole text. It
//! never returns the raw text.
//!
//! Carry note for M1-061: the run-scoped known-secret set must be shared through an `Arc`, so that the
//! log writer, the CLI error text and the report all see the same secrets. Today the process redactor is
//! the key and the built-in rules only.

use std::panic::{self, AssertUnwindSafe};
use std::sync::OnceLock;

use rdy_engine::redact::{RedactError, Redactor, TagKey};

static REDACTOR: OnceLock<Option<Redactor>> = OnceLock::new();

/// What replaces a whole text when no redactor can be built.
pub const DROPPED: &str = "[REDACTED:redactor_error:00000000]";

fn get() -> Option<&'static Redactor> {
    REDACTOR
        .get_or_init(|| TagKey::generate().ok().map(Redactor::new))
        .as_ref()
}

/// Makes the process redactor, once, and returns it.
///
/// # Errors
///
/// [`RedactError::NoRandomness`] when the OS cannot supply random bytes. The caller exits 70.
pub fn init() -> Result<&'static Redactor, RedactError> {
    get().ok_or(RedactError::NoRandomness)
}

/// `text` with secrets removed, or a fixed placeholder if no redactor can be built or it panics.
#[must_use]
pub fn redact_text(text: &str) -> String {
    redact_text_then(text, str::to_owned)
}

/// Like [`redact_text`], then `finish` runs on the redacted text. Use it to escape for the terminal.
///
/// The order matters. The key-name rule reads raw tabs and spaces, so the redactor must see the raw
/// text. Escaping first turns a tab into `\x09` and hides `password<TAB>= x` from the rule. `finish`
/// runs inside the same panic guard, so a panic in either step gives [`DROPPED`], never the raw text.
#[must_use]
pub fn redact_text_then(text: &str, finish: impl FnOnce(&str) -> String) -> String {
    match get() {
        Some(redactor) => {
            try_redact_then(redactor, text, finish).unwrap_or_else(|| DROPPED.to_owned())
        }
        None => DROPPED.to_owned(),
    }
}

/// `text` redacted by `redactor`. A panic inside the redactor gives [`DROPPED`], never the raw text.
///
/// The panic is caught here, not in a panic hook: a panic inside a hook aborts the process.
#[must_use]
pub fn redact_guarded(redactor: &Redactor, text: &str) -> String {
    try_redact(redactor, text).unwrap_or_else(|| DROPPED.to_owned())
}

/// `text` redacted by `redactor`, or `None` if the redactor panicked.
#[must_use]
pub fn try_redact(redactor: &Redactor, text: &str) -> Option<String> {
    try_redact_then(redactor, text, str::to_owned)
}

/// `text` redacted by `redactor`, then passed through `finish`, or `None` if either step panicked.
#[must_use]
pub fn try_redact_then(
    redactor: &Redactor,
    text: &str,
    finish: impl FnOnce(&str) -> String,
) -> Option<String> {
    panic::catch_unwind(AssertUnwindSafe(|| {
        let redacted = redactor.redact_str(text);
        finish(&redacted)
    }))
    .ok()
}
