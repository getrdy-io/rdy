//! The redacting log writer (ADR 0015 decision 5, 04 section 3.4, threat model I2).
//!
//! `tracing` events pass through [`RedactingMakeWriter`] before they reach stderr. Each formatted event
//! is held whole, redacted once and written once, so a secret cannot be split across two writes.
//!
//! - **No colour.** The formatter runs with ANSI off. Colour codes between a field name and `=` would
//!   hide `password=hunter2` from the key-name rule.
//! - **Caps.** With `RUST_LOG` unset (or empty, or not a valid filter), the level is `warn` and hyper,
//!   h2, rustls, tower and kube are capped at `warn` by name ([`DEFAULT_FILTER`]). With a valid
//!   `RUST_LOG` the operator's filter wins, and every line is still redacted.
//! - **No time stamp.** Lines are the level, the target and the message, which keeps them stable for
//!   golden files.
//!
//! A PEM block split over several events is a known gap in M1 (04 section 3.4).

use std::io::{self, Write};

use rdy_engine::redact::Redactor;
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The filter used when `RUST_LOG` is unset: `warn` everywhere, and the noisy dependencies named.
pub const DEFAULT_FILTER: &str = "warn,hyper=warn,h2=warn,rustls=warn,tower=warn,kube=warn";

/// The filter for a `RUST_LOG` value. Unset, empty and invalid values give [`DEFAULT_FILTER`].
#[must_use]
pub fn filter(rust_log: Option<&str>) -> EnvFilter {
    rust_log
        .filter(|v| !v.trim().is_empty())
        .and_then(|v| EnvFilter::try_new(v).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_FILTER))
}

/// A `tracing` subscriber that writes redacted lines to the writers `make` builds.
pub fn subscriber<M>(
    make: M,
    redactor: Redactor,
    rust_log: Option<&str>,
) -> impl Subscriber + Send + Sync
where
    M: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(filter(rust_log))
        .with_ansi(false)
        .without_time()
        .with_writer(RedactingMakeWriter::new(make, redactor))
        .finish()
}

/// Installs the global subscriber on stderr. Call it first in `main`, with the process redactor.
///
/// A subscriber that is already installed stays. Nothing else can fail.
pub fn init_stderr(redactor: Redactor) {
    let rust_log = std::env::var("RUST_LOG").ok();
    let sub = subscriber(io::stderr, redactor, rust_log.as_deref());
    let _ = tracing::subscriber::set_global_default(sub);
}

/// Builds [`RedactingWriter`]s around the writers of `inner`.
#[derive(Debug, Clone)]
pub struct RedactingMakeWriter<M> {
    inner: M,
    redactor: Redactor,
}

impl<M> RedactingMakeWriter<M> {
    /// Wraps `inner` so that every event is redacted before it is written.
    #[must_use]
    pub fn new(inner: M, redactor: Redactor) -> Self {
        Self { inner, redactor }
    }
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer(), self.redactor.clone())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer_for(meta), self.redactor.clone())
    }
}

/// Holds one event, then writes it redacted when it is dropped.
///
/// `tracing` makes a writer per event and drops it after the event is written, so the drop is the end
/// of the event. `flush` does nothing on purpose: a flush in the middle of an event would let a secret
/// be cut in two.
#[derive(Debug)]
pub struct RedactingWriter<W: Write> {
    inner: W,
    redactor: Redactor,
    held: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    fn new(inner: W, redactor: Redactor) -> Self {
        Self {
            inner,
            redactor,
            held: Vec::new(),
        }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.held.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        if self.held.is_empty() {
            return;
        }
        // Bytes that are not UTF-8 become U+FFFD first, so the redactor always sees text.
        let text = String::from_utf8_lossy(&self.held);
        let redacted = self.redactor.redact_str(&text);
        // A closed stderr has nowhere to report to.
        let _ = self.inner.write_all(redacted.as_bytes());
        let _ = self.inner.flush();
    }
}
