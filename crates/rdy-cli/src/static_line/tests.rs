use super::*;

fn on() -> Gate {
    Gate {
        terminal: true,
        term_dumb: false,
        rust_log: false,
        detail: Detail::Normal,
        progress: ProgressChoice::Auto,
    }
}

fn shown(gate: Gate) -> Vec<u8> {
    let mut err = Vec::new();
    let mut line = StaticLine::show(gate, 8, &mut err);
    line.clear(&mut err);
    err
}

#[test]
fn a_terminal_gets_the_line_and_then_a_clear_of_the_same_width() {
    let err = shown(on());
    let text = "Running 8 checks...";
    assert_eq!(
        err,
        format!("{text}\r{}\r", " ".repeat(text.len())).into_bytes()
    );
}

#[test]
fn one_check_is_singular() {
    assert_eq!(text(1), "Running 1 check...");
}

#[test]
fn every_reason_to_stay_quiet_prints_nothing() {
    let gates = [
        Gate {
            terminal: false,
            ..on()
        },
        Gate {
            term_dumb: true,
            ..on()
        },
        Gate {
            detail: Detail::Quiet,
            ..on()
        },
        Gate {
            detail: Detail::Verbose,
            ..on()
        },
        Gate {
            progress: ProgressChoice::Never,
            ..on()
        },
        Gate {
            rust_log: true,
            ..on()
        },
    ];
    for gate in gates {
        assert!(shown(gate).is_empty(), "{gate:?}");
    }
}

#[test]
fn the_flags_make_the_detail() {
    assert_eq!(Detail::from_flags(false, false), Detail::Normal);
    assert_eq!(Detail::from_flags(true, false), Detail::Quiet);
    assert_eq!(Detail::from_flags(false, true), Detail::Verbose);
}

#[test]
fn the_clear_uses_no_escape_sequence_and_runs_once() {
    let mut err = Vec::new();
    let mut line = StaticLine::show(on(), 3, &mut err);
    line.clear(&mut err);
    let after_first = err.len();
    line.clear(&mut err);
    assert_eq!(err.len(), after_first);
    assert!(!err.contains(&0x1b));
}

#[test]
fn a_cleared_line_has_nothing_left_for_the_drop_to_write() {
    let mut err = Vec::new();
    let mut line = StaticLine::show(on(), 3, &mut err);
    line.clear(&mut err);
    assert!(line.shown.is_none());
}

#[test]
fn a_line_that_is_still_shown_is_what_the_drop_clears() {
    let mut err = Vec::new();
    let line = StaticLine::show(on(), 3, &mut err);
    assert_eq!(line.shown, Some("Running 3 checks...".len()));
}

#[test]
fn a_failed_write_leaves_nothing_to_clear() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut line = StaticLine::show(on(), 2, &mut Closed);
    assert!(line.shown.is_none());
    line.clear(&mut Closed);
}
