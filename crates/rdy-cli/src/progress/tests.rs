//! The gate, the glyph choice and the timing of the live line, on a paused clock.

use std::ffi::OsString;

use super::*;

fn env(vars: &[(&str, &str)]) -> ProgressEnv {
    ProgressEnv::from_lookup(|name| {
        vars.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(value))
    })
}

#[test]
fn the_gate_needs_a_terminal_and_every_off_switch_closes_it() {
    use ProgressChoice::{Auto, Never};
    let plain = env(&[("TERM", "xterm-256color")]);
    // (name, choice, quiet, env, terminal, draws?)
    let rows: [(&str, ProgressChoice, bool, ProgressEnv, bool, bool); 9] = [
        ("terminal", Auto, false, plain.clone(), true, true),
        ("no TERM at all", Auto, false, env(&[]), true, true),
        ("pipe", Auto, false, plain.clone(), false, false),
        ("--quiet", Auto, true, plain.clone(), true, false),
        ("--progress never", Never, false, plain.clone(), true, false),
        (
            "TERM=dumb",
            Auto,
            false,
            env(&[("TERM", "dumb")]),
            true,
            false,
        ),
        (
            "RUST_LOG",
            Auto,
            false,
            env(&[("RUST_LOG", "rdy=debug")]),
            true,
            false,
        ),
        (
            "empty RUST_LOG",
            Auto,
            false,
            env(&[("RUST_LOG", "")]),
            true,
            true,
        ),
        ("pipe and quiet", Auto, true, plain, false, false),
    ];
    for (name, choice, quiet, env, terminal, want) in rows {
        assert_eq!(
            live_line_allowed(choice, quiet, &env, terminal),
            want,
            "{name}"
        );
    }
}

/// A case of the Unicode table: name, variables, Windows rule, Unicode?
type UnicodeRow = (
    &'static str,
    &'static [(&'static str, &'static str)],
    bool,
    bool,
);

#[test]
fn unicode_follows_d1() {
    let rows: [UnicodeRow; 13] = [
        ("LANG utf-8", &[("LANG", "en_US.UTF-8")], false, true),
        ("LANG utf8", &[("LANG", "C.utf8")], false, true),
        (
            "LC_ALL wins over LANG",
            &[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")],
            false,
            false,
        ),
        (
            "empty LC_ALL is skipped",
            &[("LC_ALL", ""), ("LANG", "en_US.UTF-8")],
            false,
            true,
        ),
        (
            "LC_CTYPE wins over LANG",
            &[("LC_CTYPE", "POSIX"), ("LANG", "en_US.UTF-8")],
            false,
            false,
        ),
        ("no locale", &[], false, false),
        (
            "TERM=dumb",
            &[("LANG", "en_US.UTF-8"), ("TERM", "dumb")],
            false,
            false,
        ),
        (
            "TERM=linux",
            &[("LANG", "en_US.UTF-8"), ("TERM", "linux")],
            false,
            false,
        ),
        ("Windows Terminal", &[("WT_SESSION", "abc")], true, true),
        ("VS Code", &[("TERM_PROGRAM", "vscode")], true, true),
        ("other program", &[("TERM_PROGRAM", "other")], true, false),
        (
            "Windows ignores the locale",
            &[("LANG", "en_US.UTF-8")],
            true,
            false,
        ),
        (
            "Unix ignores WT_SESSION",
            &[("WT_SESSION", "abc")],
            false,
            false,
        ),
    ];
    for (name, vars, windows, want) in rows {
        assert_eq!(unicode_allowed(&env(vars), windows), want, "{name}");
    }
}

#[test]
fn the_message_shows_elapsed_time_after_two_seconds() {
    assert_eq!(message(8, Duration::from_millis(1999)), "Running 8 checks");
    assert_eq!(message(8, Duration::from_secs(4)), "Running 8 checks, 4 s");
    assert_eq!(message(1, Duration::ZERO), "Running 1 check");
}

#[test]
fn the_frames_are_ten_braille_or_four_ascii() {
    assert_eq!(BRAILLE.len(), 10);
    assert_eq!(ASCII, ["-", "\\", "|", "/"]);
    assert!(
        BRAILLE
            .iter()
            .all(|f| f.chars().count() == 1 && !f.is_ascii())
    );
    assert_eq!(frames(&env(&[])), &ASCII);
}

#[tokio::test(start_paused = true)]
async fn a_run_under_250_ms_draws_nothing() {
    let capture = ProgressCapture::default();
    let mut line = Progress::start(3, &ASCII, Target::Capture(capture.clone()));
    sleep(Duration::from_millis(249)).await;
    line.clear();
    assert_eq!(capture.text(), "");
    // The line is gone for good: time passing draws nothing.
    sleep(Duration::from_secs(1)).await;
    assert_eq!(capture.text(), "");
}

#[tokio::test(start_paused = true)]
async fn a_slow_run_draws_one_line_and_clears_it() {
    let capture = ProgressCapture::default();
    let mut line = Progress::start(3, &ASCII, Target::Capture(capture.clone()));
    sleep(Duration::from_millis(600)).await;
    let drawn = capture.text();
    assert!(drawn.contains("Running 3 checks"), "{drawn:?}");
    assert!(!drawn.contains(", "), "no elapsed time yet: {drawn:?}");
    assert!(!drawn.contains('\x1b'), "{drawn:?}");
    line.clear();
    let after = capture.text();
    assert!(capture.cleared(), "the last frame is cleared: {after:?}");
    // No frame ends in a newline, so the cursor never leaves the line and nothing is left on screen.
    assert!(!after.contains('\n'), "{after:?}");
    sleep(Duration::from_secs(1)).await;
    assert_eq!(capture.text(), after, "nothing is drawn after the clear");
}

#[tokio::test(start_paused = true)]
async fn elapsed_time_shows_after_two_seconds() {
    let capture = ProgressCapture::default();
    let mut line = Progress::start(2, &BRAILLE, Target::Capture(capture.clone()));
    sleep(Duration::from_millis(4_050)).await;
    line.clear();
    let drawn = capture.text();
    assert!(drawn.contains("Running 2 checks, 3 s"), "{drawn:?}");
    assert!(BRAILLE.iter().any(|f| drawn.contains(f)), "{drawn:?}");
}

#[tokio::test(start_paused = true)]
async fn dropping_the_line_clears_it() {
    let capture = ProgressCapture::default();
    {
        let _line = Progress::start(2, &ASCII, Target::Capture(capture.clone()));
        sleep(Duration::from_millis(500)).await;
    }
    assert!(capture.cleared(), "{:?}", capture.text());
}

#[tokio::test(start_paused = true)]
async fn the_off_line_draws_nothing() {
    let mut line = Progress::off();
    sleep(Duration::from_secs(1)).await;
    line.clear();
}
