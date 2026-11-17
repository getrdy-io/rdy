use super::*;

fn on() -> Gate {
    Gate {
        terminal: true,
        ..Gate::default()
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
        Gate::default(),
        Gate {
            term_dumb: true,
            ..on()
        },
        Gate {
            quiet: true,
            ..on()
        },
        Gate {
            verbose: true,
            ..on()
        },
        Gate {
            progress_never: true,
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
