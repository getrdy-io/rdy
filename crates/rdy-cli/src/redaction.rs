//! The process-wide redactor (ADR 0015, 04 section 3.4).
//!
//! `main` builds one [`Redactor`] first, before the spec is read ([`init`]). The log writer, the panic
//! hook and the CLI error text all use it, so equal secrets get equal tags everywhere in one run.
//!
//! The key is made once. If the OS cannot supply random bytes, [`init`] fails and rdy exits 70.
//! A caller that asks for the redactor before `init` (an in-process test) gets the same lazy key.
//! If no key can be made, [`redact_text`] replaces the whole text. It never returns the raw text.

use std::sync::OnceLock;

use rdy_engine::redact::{RedactError, Redactor, TagKey};

static REDACTOR: OnceLock<Option<Redactor>> = OnceLock::new();

/// What replaces a whole text when no redactor can be built.
const DROPPED: &str = "[REDACTED:redactor_error:00000000]";

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

/// `text` with secrets removed, or a fixed placeholder if no redactor can be built.
#[must_use]
pub fn redact_text(text: &str) -> String {
    match get() {
        Some(redactor) => (**redactor.redact_str(text)).to_owned(),
        None => DROPPED.to_owned(),
    }
}
