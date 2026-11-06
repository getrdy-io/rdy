use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use rdy_engine::output::OutputDir;
use rdy_engine::watchdog::{Effects, WriteState};

use super::Interrupt;

/// Records what the signal path does to the outside world.
#[derive(Default)]
struct Recorder {
    kills: AtomicUsize,
    exit: AtomicI32,
}

impl Effects for Recorder {
    fn kill_groups(&self) {
        self.kills.fetch_add(1, Ordering::SeqCst);
    }

    fn notice(&self) {}

    fn exit(&self, code: i32) {
        self.exit.store(code, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct Written {
    err: RefCell<Vec<u8>>,
    out: RefCell<Vec<u8>>,
}

impl Written {
    fn put(&self) -> impl Fn(&[u8], &[u8]) + '_ {
        |err, out| {
            self.err.borrow_mut().extend_from_slice(err);
            self.out.borrow_mut().extend_from_slice(out);
        }
    }

    fn err(&self) -> String {
        String::from_utf8_lossy(&self.err.borrow()).into_owned()
    }

    fn out(&self) -> String {
        String::from_utf8_lossy(&self.out.borrow()).into_owned()
    }
}

fn folder(parent: &std::path::Path) -> Arc<OutputDir> {
    Arc::new(
        OutputDir::create_new(parent, "acme", "20270101T000000Z")
            .unwrap_or_else(|e| panic!("no folder: {e:?}")),
    )
}

fn no_terminal() -> bool {
    false
}

fn terminal() -> bool {
    true
}

#[test]
fn a_signal_during_a_run_kills_removes_the_empty_folder_and_exits_70() {
    let parent = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let dir = folder(parent.path());
    let interrupt = Interrupt::default();
    interrupt.set_run();
    interrupt.set_folder(Arc::downgrade(&dir));
    let fx = Recorder::default();
    let written = Written::default();
    let state = WriteState::new();

    assert!(interrupt.handle(&state, false, false, &fx, &no_terminal, &written.put()));

    assert_eq!(fx.kills.load(Ordering::SeqCst), 1);
    assert_eq!(fx.exit.load(Ordering::SeqCst), 70);
    assert_eq!(interrupt.exit.load(Ordering::SeqCst), super::SIGNAL);
    assert_eq!(
        written.err(),
        "error: interrupted. No report was written.\nfix: run rdy again and let it finish\n"
    );
    assert_eq!(written.out(), "");
    // The run still holds its handle, as in the binary. On Unix the folder is gone anyway. On Windows
    // an open folder cannot be removed, so it may stay (M1-058 deferral).
    #[cfg(unix)]
    {
        assert!(!dir.path().exists(), "the empty folder is still there");
        assert_eq!(
            std::fs::read_dir(parent.path()).map(Iterator::count).ok(),
            Some(0)
        );
    }
    #[cfg(not(unix))]
    let _ = (&dir, &parent);
}

#[test]
fn a_folder_that_holds_a_file_stays() {
    let parent = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let dir = folder(parent.path());
    std::fs::write(dir.path().join("spec.yaml"), b"x").unwrap_or_else(|e| panic!("{e}"));
    let interrupt = Interrupt::default();
    interrupt.set_run();
    interrupt.set_folder(Arc::downgrade(&dir));
    let fx = Recorder::default();
    let written = Written::default();

    assert!(interrupt.handle(
        &WriteState::new(),
        false,
        false,
        &fx,
        &no_terminal,
        &written.put()
    ));

    assert!(dir.path().join("spec.yaml").is_file());
    assert_eq!(fx.exit.load(Ordering::SeqCst), 70);
}

#[test]
fn with_json_stdout_gets_an_error_output_with_code_interrupted() {
    let interrupt = Interrupt::default();
    interrupt.set_run();
    let fx = Recorder::default();
    let written = Written::default();

    assert!(interrupt.handle(
        &WriteState::new(),
        true,
        false,
        &fx,
        &no_terminal,
        &written.put()
    ));

    let doc: serde_json::Value =
        serde_json::from_str(&written.out()).unwrap_or_else(|e| panic!("{e}: {}", written.out()));
    assert_eq!(doc["kind"], "Error");
    assert_eq!(doc["error"]["code"], "interrupted");
    assert_eq!(
        doc["error"]["message"],
        "interrupted. No report was written."
    );
    assert!(written.err().starts_with("error: interrupted."));
    assert_eq!(fx.exit.load(Ordering::SeqCst), 70);
}

#[test]
fn a_signal_while_the_report_is_being_written_is_ignored() {
    let parent = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let dir = folder(parent.path());
    let interrupt = Interrupt::default();
    interrupt.set_run();
    interrupt.set_folder(Arc::downgrade(&dir));
    let state = WriteState::new();
    // The end of the run (or the watchdog) holds the claim.
    assert!(state.claim());
    let fx = Recorder::default();
    let written = Written::default();

    assert!(!interrupt.handle(&state, false, false, &fx, &no_terminal, &written.put()));

    assert_eq!(fx.kills.load(Ordering::SeqCst), 0);
    assert_eq!(fx.exit.load(Ordering::SeqCst), 0);
    assert!(
        interrupt.exit.load(Ordering::SeqCst) == super::FREE,
        "the main thread must not wait for an exit that never comes"
    );
    assert!(dir.path().is_dir());
    assert_eq!(written.err(), "");
}

#[test]
fn a_second_signal_is_ignored_and_does_not_clear_the_flag() {
    let interrupt = Interrupt::default();
    let state = WriteState::new();
    let fx = Recorder::default();
    let written = Written::default();
    assert!(interrupt.handle(&state, false, false, &fx, &no_terminal, &written.put()));
    assert!(!interrupt.handle(&state, false, false, &fx, &no_terminal, &written.put()));
    assert_eq!(
        interrupt.exit.load(Ordering::SeqCst),
        super::SIGNAL,
        "the exit is still coming"
    );
    assert_eq!(fx.kills.load(Ordering::SeqCst), 1);
}

#[test]
fn outside_a_run_the_prompt_text_is_used_and_a_restored_terminal_starts_a_new_line() {
    let interrupt = Interrupt::default();
    let fx = Recorder::default();
    let written = Written::default();

    assert!(interrupt.handle(
        &WriteState::new(),
        false,
        false,
        &fx,
        &terminal,
        &written.put()
    ));

    assert_eq!(
        written.err(),
        "\nerror: interrupted\nfix: run the command again\n"
    );
    assert_eq!(fx.exit.load(Ordering::SeqCst), 70);
}

#[test]
fn at_a_terminal_the_text_starts_on_a_new_line_after_the_echoed_ctrl_c() {
    let interrupt = Interrupt::default();
    interrupt.set_run();
    let written = Written::default();
    assert!(interrupt.handle(
        &WriteState::new(),
        false,
        true,
        &Recorder::default(),
        &no_terminal,
        &written.put()
    ));
    assert!(
        written
            .err()
            .starts_with("\nerror: interrupted. No report was written.\n")
    );
}

#[test]
fn a_second_signal_after_a_lost_claim_kills_and_exits_70_and_leaves_the_folder() {
    let parent = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let dir = folder(parent.path());
    let interrupt = Interrupt::default();
    interrupt.set_run();
    interrupt.set_folder(Arc::downgrade(&dir));
    let state = WriteState::new();
    // A hung report write holds the claim.
    assert!(state.claim());
    let fx = Recorder::default();
    let written = Written::default();

    // The first is ignored.
    assert!(!interrupt.handle(&state, false, false, &fx, &no_terminal, &written.put()));
    assert_eq!(fx.exit.load(Ordering::SeqCst), 0);
    // The second ends it at once.
    assert!(interrupt.handle(&state, false, false, &fx, &no_terminal, &written.put()));
    assert_eq!(fx.kills.load(Ordering::SeqCst), 1);
    assert_eq!(fx.exit.load(Ordering::SeqCst), 70);
    assert!(dir.path().is_dir(), "the folder is not touched");
    assert!(written.err().starts_with("error: interrupted."));
}

#[test]
fn once_the_json_document_has_started_the_error_goes_to_stderr_only() {
    let interrupt = Interrupt::default();
    interrupt.set_run();
    interrupt.set_stdout_used();
    let written = Written::default();

    assert!(interrupt.handle(
        &WriteState::new(),
        true,
        false,
        &Recorder::default(),
        &no_terminal,
        &written.put()
    ));

    assert_eq!(written.out(), "", "stdout must hold one document");
    assert!(written.err().starts_with("error: interrupted."));
}

#[test]
fn a_signal_after_the_main_thread_took_the_exit_is_ignored() {
    let interrupt = Interrupt::default();
    assert!(interrupt.claim_exit());
    let fx = Recorder::default();
    let written = Written::default();

    assert!(!interrupt.handle(
        &WriteState::new(),
        false,
        false,
        &fx,
        &no_terminal,
        &written.put()
    ));

    assert_eq!(fx.kills.load(Ordering::SeqCst), 0);
    assert_eq!(fx.exit.load(Ordering::SeqCst), 0);
    assert_eq!(
        written.err(),
        "",
        "nothing is printed, so no code can contradict it"
    );
}

#[test]
fn the_main_thread_waits_while_a_signal_owns_the_exit_and_takes_it_when_it_is_given_back() {
    let interrupt = Arc::new(Interrupt::default());
    // A signal owns the exit and then gives it back (the report is being written).
    interrupt.exit.store(super::SIGNAL, Ordering::SeqCst);
    let for_thread = Arc::clone(&interrupt);
    let giver = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        for_thread.exit.store(super::FREE, Ordering::SeqCst);
    });
    assert!(interrupt.claim_exit());
    giver.join().unwrap_or_else(|_| panic!("giver panicked"));
}
