//! `rdy trust add`, `list` and `remove` through the built binary (M1-131).
//!
//! The exit test of the ticket: `trust add` without a terminal and without `--yes` exits 64 with a fix
//! line. With `--yes` it pins, and `trust list` shows the key id and the fingerprint in groups of four.
//! A key given with `--key` on another command leaves the store unchanged. On a terminal the output
//! matches 07 C.10 (the golden is shared with the unit tests).
//!
//! Every test sets `HOME` to a temporary folder and removes `XDG_CONFIG_HOME`, so a run reads and writes
//! only that folder. The tests for a normal user return early when the tests themselves run as root,
//! because a root run uses `/etc/rdy` and never reads `HOME` (INV-04). The `root_*` tests do the
//! opposite: they return early unless `RDY_REQUIRE_ROOT` is set, and then run the real binary as root
//! against the real `/etc/rdy`, which they leave as they found it. A run that finds a system store
//! already there fails and touches nothing. They share that one path, so they never run together: a
//! lock in this file for threads, and the nextest test group `etc-rdy` for processes.
//!
//! Windows has its own file, `trust_commands_windows.rs`: there `add` and `remove` are not supported.
#![cfg(unix)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod common;

use rdy_spec::sig::PublicKey;

const GOLDEN_ADD_TTY: &str = include_str!("../src/trust_cmds/golden/c10-add-tty.txt");
const GOLDEN_NO_TERMINAL: &str = include_str!("../src/trust_cmds/golden/c10-add-no-terminal.txt");
const GOLDEN_SECRET_FILE: &str = include_str!("../src/trust_cmds/golden/c10-add-secret-file.txt");
const GOLDEN_SECRET_TEXT: &str = include_str!("../src/trust_cmds/golden/c10-add-secret-text.txt");
const GOLDEN_TWO_KEYS: &str = include_str!("../src/trust_cmds/golden/c10-remove-two-keys.txt");

const DOC_ID: &str = "9F3A6C21D4E87B05";
const DOC_ID_2: &str = "51B0C4D7E2A93F68";
const DOC_FP_1: &str = "4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d";
const DOC_FP_2: &str = "1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c";

/// A file from `tests/fixtures`, read at run time (the folder is outside the crate).
fn fixture(path: &str) -> String {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// Two synthetic public keys. The first one's comment says "The secret key was discarded", which a
/// careless check for the words "secret key" would mistake for a secret key file.
fn pub_a() -> String {
    fixture("signed/acme-platform.pub")
}

fn pub_b() -> String {
    fixture("minisign-c/acme-platform.pub")
}

/// A secret key file made by stock minisign. It is encrypted, and it signs nothing real.
fn secret_key_text() -> String {
    fixture("minisign-c/acme-platform.key")
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// True when this test must not run: it is for a normal user and the tests run as root.
fn skip_as_root() -> bool {
    if is_root() {
        eprintln!("skipped: a root run uses /etc/rdy, so this test is for a normal user");
        return true;
    }
    false
}

/// A temporary home and the `rdy` command that uses it.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn store(&self) -> PathBuf {
        self.home().join(".config/rdy/trust.yaml")
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, text).expect("write");
        path.to_str().expect("utf8").to_owned()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
        cmd.args(args)
            .current_dir(self.dir.path())
            .env("HOME", self.home())
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RDY_PROGRESS")
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        common::quiet(self.command(args).output().expect("rdy runs"))
    }
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn key_of(pub_text: &str) -> PublicKey {
    PublicKey::from_key_file_text(pub_text).expect("public key")
}

fn groups(key: &PublicKey) -> (String, String) {
    let fp = key.fingerprint();
    let group = |range: std::ops::Range<usize>| -> String {
        fp[range]
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("hex"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    (group(0..32), group(32..64))
}

/// The golden text, with no space at the end of a line.
fn golden(text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    while lines.last() == Some(&"") {
        lines.pop();
    }
    lines.join("\n") + "\n"
}

/// Output with this run's values replaced by the ones 07 C.10 shows.
fn as_document(text: &str, home: &Home, keys: &[&PublicKey]) -> String {
    let root = home.dir.path().display().to_string();
    let mut text = text
        .replace('\r', "")
        .replace(
            &home.store().display().to_string(),
            "/home/jdoe/.config/rdy/trust.yaml",
        )
        .replace(&format!("{root}/"), "");
    for (key, doc_id) in keys.iter().zip([DOC_ID, DOC_ID_2]) {
        let (first, second) = groups(key);
        text = text
            .replace(&key.key_id().to_string(), doc_id)
            .replace(&first, DOC_FP_1)
            .replace(&second, DOC_FP_2);
    }
    golden(&text)
}

// ---------------------------------------------------------------------------------------------
// The exit test
// ---------------------------------------------------------------------------------------------

#[test]
fn add_without_a_terminal_and_without_yes_exits_64_with_a_fix_and_saves_nothing() {
    if skip_as_root() {
        return;
    }
    let home = Home::new();
    let key = home.file("acme-platform.pub", &pub_a());
    let out = home.run(&["trust", "add", "acme-platform", "--key", &key]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert_eq!(golden(&stderr(&out)), golden(GOLDEN_NO_TERMINAL));
    assert!(out.stdout.is_empty());
    assert!(!home.home().exists(), "a refused add made a folder");

    // `--yes` is argv only (INV-05): the environment cannot stand in for it.
    for name in ["RDY_YES", "YES", "RDY_ASSUME_YES"] {
        let out = common::quiet(
            home.command(&["trust", "add", "acme-platform", "--key", &key])
                .env(name, "1")
                .output()
                .expect("rdy runs"),
        );
        assert_eq!(code(&out), 64, "{name}: {}", stderr(&out));
    }
    assert!(!home.home().exists());
}

#[test]
fn add_with_yes_pins_and_list_shows_the_key_id_and_the_fingerprint_in_groups_of_four() {
    if skip_as_root() {
        return;
    }
    let home = Home::new();
    let key = home.file("acme-platform.pub", &pub_a());
    let out = home.run(&["trust", "add", "acme-platform", "--key", &key, "--yes"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "add prints on stderr");
    assert!(stderr(&out).contains("Trusted key "), "{}", stderr(&out));

    let public = key_of(&pub_a());
    let (first, second) = groups(&public);
    let list = home.run(&["trust", "list"]);
    assert_eq!(code(&list), 0, "{}", stderr(&list));
    assert!(list.stderr.is_empty(), "list prints on stdout only");
    let shown = stdout(&list);
    assert!(shown.starts_with("acme-platform\n"), "{shown}");
    assert!(
        shown.contains(&format!("  key id       {}\n", public.key_id())),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("  fingerprint  {first}\n")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("               {second}\n")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("  file         {}\n", home.store().display())),
        "{shown}"
    );

    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode(&home.store()), 0o600);
        assert_eq!(mode(home.store().parent().expect("dir")), 0o700);
    }
}

#[test]
fn other_commands_with_key_leave_the_store_unchanged() {
    // `--key` trusts a key for one run and saves nothing (01 section 4.3). `run` and `verify` are not
    // built yet (M1-126), so today they exit 70 before they look at the key. The spec and signature are
    // the real ones that key `b` signed, so when M1-126 makes the commands real, the run goes through the
    // key path. The exit code is pinned to 70 on purpose: this test turns red when M1-126 lands, and
    // M1-126 must change it to assert the real run result and an unchanged store (12-progress carry
    // note). Until then it checks that the store and its folder are what they were.
    if skip_as_root() {
        return;
    }
    let home = Home::new();
    let a = home.file("a.pub", &pub_a());
    let b = home.file("b.pub", &pub_b());
    let out = home.run(&["trust", "add", "acme-platform", "--key", &a, "--yes"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let folder = home.store().parent().expect("dir").to_owned();
    let listing = |dir: &Path| {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        names.sort();
        names
    };
    let before = (
        std::fs::read(home.store()).expect("store"),
        listing(&folder),
    );
    let spec = home.file(
        "acme-platform.yaml",
        &fixture("minisign-c/acme-platform.yaml"),
    );
    home.file(
        "acme-platform.yaml.minisig",
        &fixture("minisign-c/acme-platform.yaml.minisig"),
    );
    for args in [
        vec!["run", &spec, "--key", &b],
        vec!["run", &spec, "--key", &b, "--allow-unsigned"],
        vec!["verify", &spec, "--key", &b],
    ] {
        let out = home.run(&args);
        assert_eq!(
            code(&out),
            70,
            "run and verify are stubs until M1-126, which must change this assertion: {args:?}: {}",
            stderr(&out)
        );
        let after = (
            std::fs::read(home.store()).expect("store"),
            listing(&folder),
        );
        assert_eq!(after, before, "{args:?}");
    }
    let list = home.run(&["trust", "list"]);
    assert!(!stdout(&list).contains(&key_of(&pub_b()).key_id().to_string()));
}

// ---------------------------------------------------------------------------------------------
// Refusals and the other two commands
// ---------------------------------------------------------------------------------------------

#[test]
fn a_secret_key_is_refused_with_the_c10_fix_and_nothing_is_written() {
    if skip_as_root() {
        return;
    }
    let home = Home::new();
    let secret = home.file("acme-signing.key", &secret_key_text());
    let out = home.run(&["trust", "add", "acme-platform", "--key", &secret, "--yes"]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert_eq!(
        as_document(&stderr(&out), &home, &[]),
        golden(GOLDEN_SECRET_FILE)
    );
    assert!(out.stdout.is_empty());

    // As text on the command line: the key line is not echoed, and the shell history is named.
    let whole = secret_key_text();
    let line = whole.lines().nth(1).expect("key line");
    // A paste with a stray space or line end is still key text, and is never taken for a file name.
    let (leading, trailing, carriage) =
        (format!(" {line}"), format!("{line} "), format!("{line}\r"));
    for text in [whole.as_str(), line, &leading, &trailing, &carriage] {
        let out = home.run(&["trust", "add", "acme-platform", "--key", text, "--yes"]);
        assert_eq!(code(&out), 64, "{}", stderr(&out));
        assert_eq!(golden(&stderr(&out)), golden(GOLDEN_SECRET_TEXT));
        assert!(!stderr(&out).contains(line));
    }
    assert!(!home.home().exists(), "a refused add made a folder");
}

#[test]
fn remove_takes_a_key_out_and_two_keys_need_a_key_id() {
    if skip_as_root() {
        return;
    }
    let home = Home::new();
    let (a, b) = (home.file("a.pub", &pub_a()), home.file("b.pub", &pub_b()));
    for file in [&a, &b] {
        let out = home.run(&["trust", "add", "acme-platform", "--key", file, "--yes"]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
    }
    let (key_a, key_b) = (key_of(&pub_a()), key_of(&pub_b()));

    let out = home.run(&["trust", "remove", "acme-platform"]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert_eq!(
        as_document(&stderr(&out), &home, &[&key_a, &key_b]),
        golden(GOLDEN_TWO_KEYS)
    );

    let id = key_a.key_id().to_string();
    let out = home.run(&["trust", "remove", "acme-platform", "--key-id", &id]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        format!("Removed key {id} for acme-platform.\n")
    );
    let list = stdout(&home.run(&["trust", "list"]));
    assert!(!list.contains(&id), "{list}");
    assert!(list.contains(&key_b.key_id().to_string()), "{list}");

    let out = home.run(&["trust", "remove", "acme-platform"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = home.run(&["trust", "remove", "acme-platform"]);
    assert_eq!(code(&out), 64);
    assert!(
        stderr(&out).contains("has no trusted key"),
        "{}",
        stderr(&out)
    );
    let list = home.run(&["trust", "list"]);
    assert_eq!(code(&list), 0);
    assert_eq!(
        stdout(&list),
        "No keys are trusted yet.\nTo trust a vendor key: rdy trust add <product> --key <file>\n"
    );
}

#[test]
fn list_with_no_store_exits_0_and_a_store_others_can_write_exits_64() {
    if skip_as_root() {
        return;
    }
    let home = Home::new();
    let list = home.run(&["trust", "list"]);
    assert_eq!(code(&list), 0, "{}", stderr(&list));
    assert!(stdout(&list).starts_with("No keys are trusted yet."));

    let key = home.file("a.pub", &pub_a());
    let out = home.run(&["trust", "add", "acme-platform", "--key", &key, "--yes"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.store(), std::fs::Permissions::from_mode(0o666))
            .expect("chmod");
    }
    let list = home.run(&["trust", "list"]);
    assert_eq!(code(&list), 64);
    assert!(list.stdout.is_empty(), "a refused store prints no keys");
    assert!(
        stderr(&list).contains("is writable by other users"),
        "{}",
        stderr(&list)
    );
    assert!(
        stderr(&list).contains("fix: chmod 600"),
        "{}",
        stderr(&list)
    );
    let out = home.run(&["trust", "add", "acme-platform", "--key", &key, "--yes"]);
    assert_eq!(code(&out), 64, "an unsafe store is not added to");
}

// ---------------------------------------------------------------------------------------------
// On a terminal (07 C.10)
// ---------------------------------------------------------------------------------------------

mod pty {
    use super::*;
    use rexpect::process::WaitStatus;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    const TIMEOUT_MS: u64 = 20_000;

    /// One test at a time inside this test binary, so `cargo test` (threads in one process) is safe.
    /// rexpect forks, and a fork in a busy multi-threaded process is not safe. nextest runs every test in
    /// its own process, so there the lock does nothing and is not needed.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `rdy trust add` on a terminal that echoes what is typed, answers the question with `typed`
    /// and returns everything the person saw and the exit code.
    fn ask(home: &Home, key: &str, typed: &str, extra: &[&str]) -> (String, i32) {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("stty echo && exec \"$0\" \"$@\"")
            .arg(env!("CARGO_BIN_EXE_rdy"))
            .args(["trust", "add", "acme-platform", "--key", key])
            .args(extra)
            .current_dir(home.dir.path())
            .env("HOME", home.home())
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RDY_PROGRESS")
            .env_remove("NO_COLOR");
        let mut session =
            rexpect::session::spawn_command(cmd, Some(TIMEOUT_MS)).expect("spawn on a pty");
        let before = session.exp_string("[y/N] ").expect("the question");
        session.send_line(typed).expect("send");
        let rest = session.exp_eof().expect("eof");
        let code = match session.process().wait().expect("wait") {
            WaitStatus::Exited(_, code) => code,
            other => panic!("rdy did not exit normally: {other:?}"),
        };
        // The terminal shows stderr. Drop the inherited-descriptor warning a CI runner causes (M1-168).
        let screen = format!("{before}[y/N] {rest}");
        let screen: String = screen
            .split_inclusive('\n')
            .filter(|line| !line.starts_with(common::FD_WARNING_PREFIX))
            .collect();
        (screen, code)
    }

    #[test]
    fn yes_at_the_question_saves_and_the_screen_matches_c10() {
        if skip_as_root() {
            return;
        }
        let _guard = lock();
        let home = Home::new();
        let key = home.file("acme-platform.pub", &pub_a());
        let (screen, code) = ask(&home, &key, "y", &[]);
        assert_eq!(code, 0, "{screen}");
        assert_eq!(
            as_document(&screen, &home, &[&key_of(&pub_a())]),
            golden(GOLDEN_ADD_TTY)
        );
        assert!(home.store().is_file());
        let list = home.run(&["trust", "list"]);
        assert!(stdout(&list).contains(&key_of(&pub_a()).key_id().to_string()));
    }

    #[test]
    fn any_other_answer_exits_64_and_changes_nothing() {
        if skip_as_root() {
            return;
        }
        let _guard = lock();
        for typed in ["n", "", "maybe"] {
            let home = Home::new();
            let key = home.file("acme-platform.pub", &pub_a());
            let (screen, code) = ask(&home, &key, typed, &["--note", "a note"]);
            assert_eq!(code, 64, "{typed:?}: {screen}");
            assert!(
                screen
                    .replace('\r', "")
                    .ends_with("Not trusted. Nothing was changed.\n"),
                "{typed:?}: {screen}"
            );
            assert!(!screen.contains("Your note appears"), "{screen}");
            assert!(!home.home().exists(), "{typed:?} made a folder");
        }
    }

    #[test]
    fn a_note_is_stored_and_the_screen_says_where_it_goes() {
        if skip_as_root() {
            return;
        }
        let _guard = lock();
        let home = Home::new();
        let key = home.file("acme-platform.pub", &pub_a());
        let (screen, code) = ask(&home, &key, "yes", &["--note", "Acme security page"]);
        assert_eq!(code, 0, "{screen}");
        assert!(
            screen
                .replace('\r', "")
                .ends_with("Your note appears in every report you send.\n"),
            "{screen}"
        );
        let list = stdout(&home.run(&["trust", "list"]));
        assert!(
            list.contains("  note         Acme security page\n"),
            "{list}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// As root (the `root` CI job)
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod root {
    use super::*;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// Both tests below read or write the one real `/etc/rdy/trust.yaml`, and one asserts it is absent
    /// while the other makes it. Under `cargo test` they are threads of one process and this lock
    /// serializes them. Under nextest each test is its own process, so the test group `etc-rdy` in
    /// `.config/nextest.toml` (max-threads = 1) does it. Keep the two in step: a new test that touches
    /// `/etc/rdy` goes in the group's filter and takes this lock.
    static ETC_RDY: Mutex<()> = Mutex::new(());

    fn lock_etc_rdy() -> MutexGuard<'static, ()> {
        ETC_RDY.lock().unwrap_or_else(PoisonError::into_inner)
    }

    const SYSTEM_DIR: &str = "/etc/rdy";
    const SYSTEM_STORE: &str = "/etc/rdy/trust.yaml";

    /// True when this test should run: as root, and only when `RDY_REQUIRE_ROOT` is set. A plain run as
    /// root (a sandbox) must not write the real `/etc/rdy`.
    fn wanted() -> bool {
        if std::env::var_os("RDY_REQUIRE_ROOT").is_none() {
            eprintln!("skipped: needs uid 0 and RDY_REQUIRE_ROOT=1 (the root job sets both)");
            return false;
        }
        assert!(is_root(), "RDY_REQUIRE_ROOT is set but the euid is not 0");
        true
    }

    /// Puts `/etc/rdy` back as it was: removes the store, and the folder if the test made it.
    struct Restore {
        made_dir: bool,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(SYSTEM_STORE);
            if self.made_dir {
                let _ = std::fs::remove_dir(SYSTEM_DIR);
            }
        }
    }

    #[test]
    fn root_add_list_and_remove_use_only_the_system_store() {
        if !wanted() {
            return;
        }
        let _etc = lock_etc_rdy();
        assert!(
            !Path::new(SYSTEM_STORE).exists(),
            "{SYSTEM_STORE} already exists. This test will not touch it."
        );
        let _restore = Restore {
            made_dir: !Path::new(SYSTEM_DIR).exists(),
        };
        let home = Home::new();
        let key = home.file("acme-platform.pub", &pub_a());
        // sudo resets HOME and XDG_CONFIG_HOME, but a root run must not depend on that. Both point at a
        // folder that must stay empty.
        let out = common::quiet(
            home.command(&["trust", "add", "acme-platform", "--key", &key, "--yes"])
                .env("XDG_CONFIG_HOME", home.dir.path().join("xdg"))
                .env("SUDO_USER", "nobody")
                .output()
                .expect("rdy runs"),
        );
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!("Saved to {SYSTEM_STORE}\n")),
            "{}",
            stderr(&out)
        );
        assert!(!home.home().exists(), "a root run made a path under HOME");
        assert!(!home.dir.path().join("xdg").exists());

        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::metadata(SYSTEM_STORE).expect("stat");
        assert_eq!(meta.uid(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);

        let list = home.run(&["trust", "list"]);
        assert_eq!(code(&list), 0, "{}", stderr(&list));
        let shown = stdout(&list);
        assert!(
            shown.contains(&format!("  file         {SYSTEM_STORE}\n")),
            "{shown}"
        );
        assert!(
            shown.contains(&key_of(&pub_a()).key_id().to_string()),
            "{shown}"
        );

        let out = home.run(&["trust", "remove", "acme-platform"]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        assert!(stdout(&home.run(&["trust", "list"])).starts_with("No keys are trusted yet."));
        assert!(!home.home().exists());
    }

    #[test]
    fn root_ignores_a_user_store_that_the_environment_points_at() {
        if !wanted() {
            return;
        }
        let _etc = lock_etc_rdy();
        assert!(
            !Path::new(SYSTEM_STORE).exists(),
            "{SYSTEM_STORE} already exists. This test will not touch it."
        );
        let home = Home::new();
        // A valid user store with a key in it, in the place a normal user's rdy would read.
        std::fs::create_dir_all(home.store().parent().expect("dir")).expect("dir");
        let planted = format!(
            "apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n  - product: acme-platform\n    key: {}\n    added_at: 2026-11-30T16:20:00Z\n",
            pub_b().lines().nth(1).expect("key line")
        );
        std::fs::write(home.store(), planted).expect("store");
        let list = home.run(&["trust", "list"]);
        assert_eq!(code(&list), 0, "{}", stderr(&list));
        assert!(
            stdout(&list).starts_with("No keys are trusted yet."),
            "a root run read the user store: {}",
            stdout(&list)
        );
        assert!(
            !Path::new(SYSTEM_STORE).exists(),
            "list made the system store"
        );
    }
}
