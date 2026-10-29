//! The redacting log writer (M1-056, ADR 0015 decision 5, threat model I2, INV-15).
//!
//! The tests install the real subscriber of `rdy_cli::logging` over a capture buffer and emit events
//! that carry synthetic canaries. At `RUST_LOG=trace` no canary may reach the buffer. The golden file
//! holds the exact output, with every tag replaced by `~` because the key is random per run.

use std::io::Write;
use std::sync::{Arc, Mutex};

use rdy_cli::logging::{self, DEFAULT_FILTER, RedactingMakeWriter};
use rdy_cli::redaction;
use rdy_engine::redact::PANIC_TRIGGER;
use tracing_subscriber::fmt::MakeWriter;

/// A capture buffer that hands out writers onto the same bytes.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        String::from_utf8(bytes).unwrap_or_else(|e| panic!("log output is not UTF-8: {e}"))
    }
}

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

impl MakeWriter<'_> for Sink {
    type Writer = Sink;

    fn make_writer(&self) -> Sink {
        self.clone()
    }
}

fn redactor() -> rdy_engine::redact::Redactor {
    redaction::init()
        .unwrap_or_else(|e| panic!("the test host has a random source: {e}"))
        .clone()
}

/// Runs `emit` under the real subscriber and returns what reached the sink.
fn captured(rust_log: Option<&str>, emit: impl FnOnce()) -> String {
    let sink = Sink::default();
    let subscriber = logging::subscriber(sink.clone(), redactor(), rust_log);
    tracing::subscriber::with_default(subscriber, emit);
    sink.text()
}

/// Replaces each 8-digit tag with `~`, so output from two runs compares equal.
fn normalize_tags(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("[REDACTED:") {
        let (before, tail) = rest.split_at(at);
        out.push_str(before);
        match tail.find(']') {
            Some(end) => {
                let placeholder = &tail[..end];
                match placeholder.rfind(':') {
                    Some(colon) => out.push_str(&placeholder[..=colon]),
                    None => out.push_str(placeholder),
                }
                out.push_str("~]");
                rest = &tail[end + 1..];
            }
            None => {
                out.push_str(tail);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

const CANARIES: [&str; 5] = [
    "canary-field-pw-1",
    "canary-env-token-2",
    "canary-kube-token-3",
    "canary-output-hdr-4",
    "canary-dep-hdr-5",
];

/// One event of each kind the ticket names: a tracing field, an env pair, a kubeconfig, command output
/// and a dependency header.
fn emit_canaries() {
    tracing::info!(password = "canary-field-pw-1", "login attempt");
    tracing::debug!("env seen: HOME=/home/synthetic API_TOKEN=canary-env-token-2");
    tracing::trace!(
        "kubeconfig:\n  users:\n  - name: synthetic\n    user:\n      token: canary-kube-token-3\n"
    );
    tracing::trace!(
        output = "Authorization: Bearer canary-output-hdr-4\nok",
        "command output"
    );
    // A capped dependency still logs at warn, so its line goes through the redactor too.
    tracing::warn!(
        target: "hyper::proto::h1::io",
        "write headers: authorization: Bearer canary-dep-hdr-5"
    );
}

#[test]
fn trace_level_output_matches_the_golden_file_and_holds_no_canary() {
    let out = captured(Some("trace"), emit_canaries);
    for canary in CANARIES {
        assert!(!out.contains(canary), "{canary} leaked:\n{out}");
    }
    assert_eq!(out.matches("[REDACTED:secret_by_key:").count(), 5, "{out}");
    let got = normalize_tags(&out);
    let want = include_str!("snapshots/log-trace-redacted.txt");
    assert_eq!(got, want, "golden mismatch. Got:\n{got}");
}

#[test]
fn a_tag_is_the_same_for_the_same_secret_in_one_run() {
    let out = captured(Some("trace"), || {
        tracing::info!(password = "canary-same-1", "first");
        tracing::info!(password = "canary-same-1", "second");
    });
    let tags: Vec<&str> = out
        .match_indices("secret_by_key:")
        .map(|(at, m)| &out[at + m.len()..at + m.len() + 8])
        .collect();
    assert_eq!(tags.len(), 2, "{out}");
    assert_eq!(tags[0], tags[1]);
}

#[test]
fn an_event_is_redacted_whole_not_line_by_line() {
    // A multi-line value runs over several lines of one event. The block rule needs all of them.
    let out = captured(Some("trace"), || {
        tracing::trace!("secret: |\n  canary-block-1\n  canary-block-2\nnext: ok");
    });
    assert!(!out.contains("canary-block"), "{out}");
    assert!(out.contains("next: ok"), "{out}");
}

#[test]
fn unset_empty_and_invalid_rust_log_log_nothing() {
    assert_eq!(DEFAULT_FILTER, "off");
    for rust_log in [None, Some(""), Some("  "), Some("=[bad")] {
        let out = captured(rust_log, || {
            tracing::error!("error line");
            tracing::warn!("rdy warn line");
            tracing::info!("info line");
            tracing::debug!(target: "hyper::client", "hyper debug line");
            tracing::warn!(target: "hyper::client", "hyper warn line");
        });
        assert!(out.is_empty(), "{rust_log:?}: {out}");
    }
}

#[test]
fn a_plain_level_in_rust_log_turns_logging_on() {
    let out = captured(Some("warn"), || {
        tracing::warn!("rdy warn line");
        tracing::info!("info line");
    });
    assert!(out.contains("rdy warn line"), "{out}");
    assert!(!out.contains("info line"), "{out}");
}

#[test]
fn a_set_rust_log_still_caps_the_noisy_dependencies_at_warn() {
    for rust_log in [
        "trace",
        "debug",
        "hyper=trace,h2=trace,kube=trace",
        "rdy_cli=trace,trace",
    ] {
        let out = captured(Some(rust_log), || {
            tracing::trace!(target: "hyper::proto::h1::io", "hyper trace canary-cap-1");
            tracing::debug!(target: "h2::codec", "h2 debug canary-cap-2");
            tracing::info!(target: "rustls::client", "rustls info canary-cap-3");
            tracing::debug!(target: "tower::buffer", "tower debug canary-cap-4");
            tracing::debug!(target: "kube_client::client", "kube debug canary-cap-5");
            tracing::debug!(target: "hyper_util::client", "hyper_util debug canary-cap-6");
            tracing::warn!(target: "h2::codec", "h2 warn line");
            tracing::error!(target: "kube::client", "kube error line");
            tracing::debug!(target: "hypermedia", "other crate trace line");
        });
        assert!(!out.contains("canary-cap"), "{rust_log}: {out}");
        assert!(out.contains("h2 warn line"), "{rust_log}: {out}");
        assert!(out.contains("kube error line"), "{rust_log}: {out}");
        assert!(out.contains("other crate trace line"), "{rust_log}: {out}");
    }
}

#[test]
fn a_set_rust_log_names_the_targets_and_is_still_redacted() {
    let out = captured(Some("trace"), || {
        tracing::trace!(target: "my_crate::codec", "frame token=canary-lift-1");
    });
    assert!(out.contains("my_crate::codec"), "{out}");
    assert!(!out.contains("canary-lift-1"), "{out}");
}

#[test]
fn output_has_no_ansi_codes_and_no_time_stamp() {
    let out = captured(Some("trace"), || tracing::info!(password = "x", "line"));
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.starts_with(" INFO "), "{out:?}");
}

#[test]
fn a_secret_split_over_two_writes_is_still_redacted() {
    let sink = Sink::default();
    let make = RedactingMakeWriter::new(sink.clone(), redactor());
    {
        let mut w = make.make_writer();
        w.write_all(b"pass").unwrap_or_else(|e| panic!("{e}"));
        w.flush().unwrap_or_else(|e| panic!("{e}"));
        w.write_all(b"word=canary-split-1\n")
            .unwrap_or_else(|e| panic!("{e}"));
        // Nothing is written until the event ends.
        assert!(sink.text().is_empty());
    }
    let out = sink.text();
    assert!(!out.contains("canary-split-1"), "{out}");
    assert!(
        out.starts_with("password=[REDACTED:secret_by_key:"),
        "{out}"
    );
}

#[test]
fn bytes_that_are_not_utf8_do_not_panic_and_do_not_leak() {
    let sink = Sink::default();
    let make = RedactingMakeWriter::new(sink.clone(), redactor());
    {
        let mut w = make.make_writer();
        w.write_all(b"token=canary-bytes-1\xff\xfe tail\n")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let out = sink.text();
    assert!(!out.contains("canary-bytes-1"), "{out}");
    // The replacement character is not a plain value character, so the rest of the line goes too.
    // That is the fail-closed choice of the key-name rule.
    assert!(out.starts_with("token=[REDACTED:secret_by_key:"), "{out}");
}

#[test]
fn a_span_field_is_redacted_when_an_event_is_logged_inside_the_span() {
    let out = captured(Some("trace"), || {
        let span = tracing::info_span!("s", token = "canary-span-1");
        let _guard = span.enter();
        tracing::info!("event inside the span");
    });
    // The bare value runs to the end of the line on purpose (it fails closed), so the message after the
    // span is swallowed with it. M1-060 tunes that. The event is live if its line is there at all.
    assert!(
        out.starts_with(" INFO s{token=[REDACTED:secret_by_key:"),
        "{out}"
    );
    assert!(!out.contains("canary-span-1"), "{out}");
    assert!(out.contains("[REDACTED:secret_by_key:"), "{out}");
}

#[test]
fn control_and_invisible_characters_in_a_field_are_escaped_and_line_ends_stay() {
    // A message is written with Display, so the characters reach the writer raw.
    let out = captured(Some("trace"), || {
        tracing::info!("a\rb\u{202e}c\u{1b}[2Jd\nsecond line");
    });
    assert!(!out.contains('\r'), "{out:?}");
    assert!(!out.contains('\u{202e}'), "{out:?}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.contains("a\\x0db\\u{202e}c\\x1b[2Jd"), "{out:?}");
    assert!(out.contains("d\nsecond line"), "{out:?}");
}

#[test]
fn a_crlf_line_end_is_escaped_not_passed_on() {
    let sink = Sink::default();
    let make = RedactingMakeWriter::new(sink.clone(), redactor());
    {
        let mut w = make.make_writer();
        w.write_all(b"first\r\nsecond\n")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    assert_eq!(sink.text(), "first\\x0d\nsecond\n");
}

#[test]
fn a_panicking_redactor_drops_the_event_and_never_writes_the_raw_text() {
    let out = captured(Some("trace"), || {
        tracing::info!("before");
        tracing::info!("{PANIC_TRIGGER} password=canary-panic-rule-1");
        tracing::info!("after");
    });
    assert!(!out.contains("canary-panic-rule-1"), "{out}");
    assert!(!out.contains(PANIC_TRIGGER), "{out}");
    assert!(
        out.contains("[REDACTED:redactor_error:00000000]\n"),
        "{out}"
    );
    assert!(out.contains("before") && out.contains("after"), "{out}");
}

#[test]
fn a_panicking_redactor_while_another_panic_unwinds_does_not_abort() {
    struct LogOnDrop;
    impl Drop for LogOnDrop {
        fn drop(&mut self) {
            tracing::info!("{PANIC_TRIGGER} token=canary-unwind-1");
        }
    }
    let out = captured(Some("trace"), || {
        let caught = std::panic::catch_unwind(|| {
            let _guard = LogOnDrop;
            panic!("first panic");
        });
        assert!(caught.is_err());
    });
    assert!(!out.contains("canary-unwind-1"), "{out}");
    assert!(out.contains("[REDACTED:redactor_error:00000000]"), "{out}");
}

#[test]
fn redact_text_drops_the_whole_text_when_the_redactor_panics() {
    let got = redaction::redact_text(&format!("x {PANIC_TRIGGER} password=canary-text-1"));
    assert_eq!(got, "[REDACTED:redactor_error:00000000]");
}

/// A proxy URL with userinfo needs the URL rule of M1-060. Until then only the key-name rule exists, so
/// the password of `http://user:pass@host` is not found. M1-060 removes the `ignore` (13 correction).
#[test]
#[ignore = "M1-060"]
fn a_proxy_url_with_userinfo_never_reaches_the_log() {
    let out = captured(Some("trace"), || {
        tracing::debug!(proxy = %"http://synthetic:canary-proxy-url-1@proxy.example:3128", "using proxy");
    });
    assert!(!out.contains("canary-proxy-url-1"), "{out}");
}
