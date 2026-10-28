//! The panic hook (M1-056, ADR 0015 decision 6).
//!
//! The hook is process-wide, so this file holds one test. It installs the hook over a capture buffer
//! and panics three ways. The default Rust text (`thread '...' panicked at`) must never appear, and the
//! raw message must not either.

use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use rdy_cli::{panic_hook, redaction};

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn text(sink: &Sink) -> String {
    let bytes = sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("hook output is not UTF-8: {e}"))
}

/// Panics with `f` and returns what the hook printed.
fn printed(sink: &Sink, f: impl FnOnce()) -> String {
    let before = text(sink).len();
    let caught = panic::catch_unwind(AssertUnwindSafe(f));
    assert!(caught.is_err(), "the closure did not panic");
    text(sink)[before..].to_owned()
}

#[test]
fn the_hook_prints_redacted_text_and_never_the_default_panic_text() {
    let redactor = redaction::init()
        .unwrap_or_else(|e| panic!("the test host has a random source: {e}"))
        .clone();
    let sink = Sink::default();
    let writer = sink.clone();
    panic_hook::install(redactor, Box::new(move || Box::new(writer.clone())));

    let mut outputs = Vec::new();
    // A &'static str payload.
    outputs.push(printed(&sink, || {
        panic!("bad config password=canary-panic-str-1 end")
    }));
    // A String payload.
    let owned = String::from("token: canary-panic-string-2");
    outputs.push(printed(&sink, move || panic!("{owned}")));
    // A payload that is not text.
    outputs.push(printed(&sink, || panic::panic_any(42_u8)));
    // A control character in the message is escaped.
    outputs.push(printed(&sink, || panic!("clear \u{1b}[2J screen")));

    // Put the default hook back, so that a failed assertion below is visible.
    drop(panic::take_hook());

    for out in &outputs {
        assert!(!out.contains("thread '"), "default hook text: {out}");
        assert!(!out.contains("panicked at"), "default hook text: {out}");
        assert!(!out.contains("RUST_BACKTRACE"), "default hook text: {out}");
        assert!(!out.contains("canary-panic"), "raw secret: {out}");
        assert!(!out.contains('\u{1b}'), "raw control character: {out:?}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "want error and fix lines: {out}");
        assert!(
            lines[0].starts_with("error: rdy hit an internal error: "),
            "{out}"
        );
        assert!(lines[1].starts_with("fix: this is a bug in rdy"), "{out}");
    }
    assert!(
        outputs[0].contains("password=[REDACTED:secret_by_key:"),
        "{}",
        outputs[0]
    );
    assert!(
        outputs[1].contains("token: [REDACTED:secret_by_key:"),
        "{}",
        outputs[1]
    );
    assert!(outputs[2].contains("a non-text payload"), "{}", outputs[2]);
    assert!(outputs[3].contains("\\x1b"), "{}", outputs[3]);
    // The location is the test file, which holds no secret.
    assert!(outputs[0].contains("panic_hook.rs:"), "{}", outputs[0]);
}
