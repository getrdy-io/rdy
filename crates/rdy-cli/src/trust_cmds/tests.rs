//! Tests for `trust add`, `list` and `remove` without a terminal or the process environment.
//!
//! The terminal is a transcript: the question, the typed answer and everything the command prints go
//! into one string, the way they read on a screen. Keys are synthetic and made in each test. The
//! goldens in `golden/` are the text of 07 C.9 and C.10. A test replaces the values that change from run
//! to run (the key id, the fingerprint, the temporary folder, the hash) with the values the document
//! shows, so the golden is the document and the check is on the layout and the words.
//!
//! Layouts are built with [`Layout::from_env`] and a chosen effective uid, so every test runs the same
//! way as a normal user and as root, and none of them touches a real home or `/etc/rdy`.
// The helpers below are not `#[test]` functions, so clippy.toml does not cover them.
#![allow(clippy::expect_used)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use ct_codecs::{Base64, Decoder, Encoder};

use super::*;
use crate::cli::{KeygenArgs, SignArgs};
use crate::error::ErrorCode;
use crate::password::{KeyPassword, PasswordError};
use crate::prompt::Secret;
use crate::signing::key::{KdfCost, SecretKey};
use crate::spec_cmds::{keygen, sign};
use crate::trust::Vars;

const CHEAP: KdfCost = KdfCost::new(32_768, 1 << 20);
const SIGNED_AT: &str = "2027-03-02T15:40:09Z";
const ADDED: &str = "2026-11-30T16:20:00Z";
const NOTE: &str = "Acme security page, fingerprint read back by phone";
const GOOD_SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n    fix: Use a bigger node.\n";

// The values 07 C.9 and C.10 show.
const DOC_ID: &str = "9F3A6C21D4E87B05";
const DOC_ID_2: &str = "51B0C4D7E2A93F68";
const DOC_FP_1: &str = "4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d";
const DOC_FP_2: &str = "1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c";
const DOC_FP: &str = "4d2a7c0e9b1f3a5c6e8d0b2f4a6c8e0d1b3f5a7c9e2d4b6f8a0c2e4d6b8f0a1c";
const DOC_SHA: &str = "231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f";

// ---------------------------------------------------------------------------------------------
// The transcript terminal
// ---------------------------------------------------------------------------------------------

type Screen = Rc<RefCell<String>>;

/// What a person sees: prompts, the typed answer (a terminal echoes it) and the program's own output.
struct Transcript {
    interactive: bool,
    lines: VecDeque<&'static str>,
    hidden: VecDeque<&'static str>,
    screen: Screen,
    /// Runs when the person starts to type an answer: something else changes while the question is open.
    while_asking: Option<Box<dyn FnOnce()>>,
}

impl Transcript {
    fn new(
        interactive: bool,
        lines: &[&'static str],
        hidden: &[&'static str],
    ) -> (Prompter<Self>, Out) {
        let screen = Screen::default();
        let term = Self {
            interactive,
            lines: lines.iter().copied().collect(),
            hidden: hidden.iter().copied().collect(),
            screen: Rc::clone(&screen),
            while_asking: None,
        };
        (Prompter::new(term), Out(screen))
    }

    /// A terminal where `change` happens while the question is open, and then the person types `y`.
    fn answering_after(change: impl FnOnce() + 'static) -> (Prompter<Self>, Out) {
        let screen = Screen::default();
        let term = Self {
            interactive: true,
            lines: VecDeque::from(["y"]),
            hidden: VecDeque::new(),
            screen: Rc::clone(&screen),
            while_asking: Some(Box::new(change)),
        };
        (Prompter::new(term), Out(screen))
    }

    /// A terminal where the person types `answer` at the next question.
    fn answering(answer: &'static str) -> (Prompter<Self>, Out) {
        Self::new(true, &[answer], &[])
    }

    /// No terminal at all.
    fn none() -> (Prompter<Self>, Out) {
        Self::new(false, &[], &[])
    }
}

impl Terminal for Transcript {
    fn is_interactive(&self) -> bool {
        self.interactive
    }

    fn write_prompt(&mut self, text: &str) -> io::Result<()> {
        self.screen.borrow_mut().push_str(text);
        Ok(())
    }

    fn read_line(&mut self) -> io::Result<Option<String>> {
        if let Some(change) = self.while_asking.take() {
            change();
        }
        Ok(self.lines.pop_front().map(|line| {
            self.screen.borrow_mut().push_str(&format!("{line}\n"));
            line.to_owned()
        }))
    }

    fn read_hidden(&mut self) -> Result<Secret, PromptError> {
        let text = self.hidden.pop_front().unwrap_or_default();
        // The typed text is not shown. The terminal ends the line itself.
        self.screen.borrow_mut().push('\n');
        Ok(Secret::new(text.to_owned()))
    }
}

/// The output stream of the command, on the same screen as the prompts.
struct Out(Screen);

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Out {
    fn text(&self) -> String {
        self.0.borrow().clone()
    }
}

// ---------------------------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------------------------

fn real_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A temporary folder with a pretend home and a pretend `/etc`.
struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("etc")).expect("etc");
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn vars(&self) -> Vars {
        Vars {
            home: Some(self.path("home").into_os_string()),
            xdg_config_home: None,
            program_data: None,
        }
    }

    /// A normal user, with the system store in the pretend `/etc`. A test run as root passes 1000, and
    /// the files root makes are accepted as the store rules accept them (owned by root).
    fn user(&self) -> Layout {
        let euid = if real_euid() == 0 { 1000 } else { real_euid() };
        Layout::from_env(&self.vars(), euid)
            .with_system_file(self.path("etc/rdy/trust.yaml"), real_euid())
    }

    /// Root, with the system store in the pretend `/etc`. `HOME` is set, to show it is not used.
    fn system(&self) -> Layout {
        Layout::from_env(&self.vars(), 0)
            .with_system_file(self.path("etc/rdy/trust.yaml"), real_euid())
    }

    fn user_store(&self) -> PathBuf {
        self.path("home/.config/rdy/trust.yaml")
    }

    fn system_store(&self) -> PathBuf {
        self.path("etc/rdy/trust.yaml")
    }

    /// Writes a store file that the rules accept: the user's (0600, in a 0700 folder) or the system's.
    fn put_store(&self, path: &Path, entries: &[(&str, &SecretKey, Option<&str>)]) {
        let dir = path.parent().expect("parent");
        std::fs::create_dir_all(dir).expect("dir");
        set_mode(dir, 0o755);
        let mut text = "apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n".to_owned();
        for (product, key, note) in entries {
            text.push_str(&format!(
                "  - product: {product}\n    key: {}\n    added_at: {ADDED}\n",
                key.public_key_base64()
            ));
            if let Some(note) = note {
                text.push_str(&format!("    note: \"{note}\"\n"));
            }
        }
        std::fs::write(path, text).expect("store");
        set_mode(path, 0o644);
    }

    /// Writes `<name>` with the public key file of `key` and returns the name as typed.
    fn pub_file(&self, name: &str, key: &SecretKey) -> String {
        let path = self.path(name);
        std::fs::write(&path, key.public_key_file()).expect("pub file");
        path.to_str().expect("utf8").to_owned()
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

fn new_key() -> SecretKey {
    SecretKey::generate().expect("key")
}

fn public(key: &SecretKey) -> PublicKey {
    PublicKey::from_base64(&key.public_key_base64()).expect("public key")
}

fn add_args(product: &str, key: &str, yes: bool, note: Option<&str>) -> TrustAddArgs {
    TrustAddArgs {
        product: product.to_owned(),
        key: key.to_owned(),
        yes,
        note: note.map(str::to_owned),
    }
}

fn remove_args(product: &str, key_id: Option<&str>) -> TrustRemoveArgs {
    TrustRemoveArgs {
        product: product.to_owned(),
        key_id: key_id.map(str::to_owned),
    }
}

/// The two lines on stderr and the exit code for an error.
fn rendered(err: &CliError) -> (u8, String) {
    let rendered = err.render();
    (rendered.exit_code(), rendered.text())
}

fn run_list(layout: &Layout) -> Result<String, CliError> {
    let mut out = Vec::new();
    list(layout, &mut out)?;
    Ok(String::from_utf8(out).expect("utf8"))
}

// ---------------------------------------------------------------------------------------------
// Goldens
// ---------------------------------------------------------------------------------------------

/// Text with the values that change from run to run replaced by the ones the document shows, and with
/// no spaces at the end of a line (the document is stored without them).
fn normalized(text: &str, env: &Env, keys: &[&SecretKey]) -> String {
    let root = env.root().display().to_string();
    let mut text = text
        .replace(
            &env.user_store().display().to_string(),
            "/home/jdoe/.config/rdy/trust.yaml",
        )
        .replace(
            &env.system_store().display().to_string(),
            "/etc/rdy/trust.yaml",
        )
        .replace(&format!("{root}/"), "");
    for (key, doc_id) in keys.iter().zip([DOC_ID, DOC_ID_2]) {
        let key = public(key);
        let (first, second) = fingerprint_lines(&key.fingerprint());
        text = text
            .replace(&key.key_id().to_string(), doc_id)
            .replace(&first, DOC_FP_1)
            .replace(&second, DOC_FP_2)
            .replace(&key.fingerprint(), DOC_FP);
    }
    tidy(&text)
}

/// No spaces at the end of a line, and one line ending at the end.
fn tidy(text: &str) -> String {
    let mut out: Vec<&str> = text.lines().map(str::trim_end).collect();
    while out.last() == Some(&"") {
        out.pop();
    }
    out.join("\n") + "\n"
}

macro_rules! golden {
    ($name:literal) => {
        tidy(include_str!(concat!("golden/", $name)))
    };
}

/// Every golden file is a run of lines that 07 appendix C.9 or C.10 shows, so the goldens cannot drift
/// from the document that is the source of truth for the wording.
#[test]
fn every_golden_is_text_that_07_shows() {
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/plan/07-cli-ux.md");
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", doc_path.display()))
        .replace("\r\n", "\n");
    let doc_lines: Vec<&str> = doc.lines().map(str::trim_end).collect();
    let prose = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust_cmds/golden");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("golden dir") {
        let path = entry.expect("entry").path();
        let text = std::fs::read_to_string(&path).expect("golden");
        let golden = tidy(&text);
        let lines: Vec<&str> = golden.lines().collect();
        // Most goldens are a run of lines of a console block. A few are shown inline in the prose, which
        // wraps, so each of their lines only has to be somewhere in the text with line ends as spaces.
        let shown = doc_lines.windows(lines.len()).any(|window| window == lines)
            || lines.iter().all(|line| prose.contains(line));
        assert!(shown, "{} is not text that 07 shows", path.display());
        seen += 1;
    }
    assert_eq!(seen, 10, "a golden was added or removed: update this count");
}

// ---------------------------------------------------------------------------------------------
// add: the answer, the question and the refusals
// ---------------------------------------------------------------------------------------------

#[test]
fn add_on_a_terminal_matches_c10_and_saves_after_yes() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let (mut prompter, mut out) = Transcript::answering("y");
    let outcome = add(
        &add_args("acme-platform", &file, false, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("adds");
    assert_eq!(outcome, AddOutcome::Saved);
    assert_eq!(
        normalized(&out.text(), &env, &[&key]),
        golden!("c10-add-tty.txt")
    );

    // The file holds the key, the product and the time, in a private store.
    let saved = std::fs::read_to_string(env.user_store()).expect("store");
    assert!(saved.contains("product: acme-platform"), "{saved}");
    assert!(
        saved.contains(&format!("key: {}", key.public_key_base64())),
        "{saved}"
    );
    assert!(saved.contains(&format!("added_at: {ADDED}")), "{saved}");
    assert_eq!(mode_of(&env.user_store()), 0o600);
    assert_eq!(mode_of(env.user_store().parent().expect("dir")), 0o700);
}

#[test]
fn add_with_a_note_says_where_the_note_goes_and_stores_it() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let (mut prompter, mut out) = Transcript::answering("yes");
    add(
        &add_args("acme-platform", &file, false, Some(NOTE)),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("adds");
    let shown = out.text();
    assert!(
        shown.ends_with("Your note appears in every report you send.\n"),
        "{shown}"
    );
    let saved = std::fs::read_to_string(env.user_store()).expect("store");
    assert!(saved.contains(&format!("note: \"{NOTE}\"")), "{saved}");
}

#[test]
fn any_answer_but_y_or_yes_changes_nothing() {
    for answer in ["n", "", "no", "maybe", "yep", "y es"] {
        let env = Env::new();
        let key = new_key();
        let file = env.pub_file("acme-platform.pub", &key);
        let (mut prompter, mut out) = Transcript::answering(answer);
        let outcome = add(
            &add_args("acme-platform", &file, false, Some("a note")),
            &env.user(),
            ADDED,
            &mut prompter,
            &mut out,
        )
        .expect("a no is not an error");
        assert_eq!(outcome, AddOutcome::Declined, "{answer:?}");
        let shown = out.text();
        assert!(
            shown.ends_with("Not trusted. Nothing was changed.\n"),
            "{shown}"
        );
        assert!(!shown.contains("Saved to"), "{shown}");
        assert!(!shown.contains("note appears"), "{shown}");
        assert!(!env.path("home").exists(), "{answer:?} made a folder");
    }
}

#[test]
fn end_of_input_at_the_question_is_a_no() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let (mut prompter, mut out) = Transcript::new(true, &[], &[]);
    let outcome = add(
        &add_args("acme-platform", &file, false, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("no");
    assert_eq!(outcome, AddOutcome::Declined);
    assert!(!env.path("home").exists());
}

#[test]
fn no_terminal_and_no_yes_refuses_before_it_prints_the_key() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let (mut prompter, mut out) = Transcript::none();
    let err = add(
        &add_args("acme-platform", &file, false, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect_err("refused");
    let (code, text) = rendered(&err);
    assert_eq!(code, 64);
    assert_eq!(tidy(&text), golden!("c10-add-no-terminal.txt"));
    assert_eq!(out.text(), "", "nothing is printed before the refusal");
    assert!(!env.path("home").exists());
}

#[test]
fn yes_pins_without_a_terminal_and_the_summary_has_no_compare_paragraph() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let (mut prompter, mut out) = Transcript::none();
    let outcome = add(
        &add_args("acme-platform", &file, true, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("adds");
    assert_eq!(outcome, AddOutcome::Saved);
    let shown = normalized(&out.text(), &env, &[&key]);
    assert!(
        shown.starts_with("product      acme-platform\nkey id       9F3A6C21D4E87B05\n"),
        "{shown}"
    );
    assert!(!shown.contains("Compare this fingerprint"), "{shown}");
    assert!(!shown.contains("[y/N]"), "{shown}");
    assert!(
        shown.contains("Trusted key 9F3A6C21D4E87B05 for acme-platform.\n"),
        "{shown}"
    );

    // `trust list` now shows the key id and the fingerprint in groups of four.
    let listed = run_list(&env.user()).expect("lists");
    let public = public(&key);
    let (first, second) = fingerprint_lines(&public.fingerprint());
    assert!(
        listed.contains(&format!("  key id       {}\n", public.key_id())),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("  fingerprint  {first}\n")),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("               {second}\n")),
        "{listed}"
    );
    assert!(
        first
            .split(' ')
            .chain(second.split(' '))
            .all(|group| group.len() == 4)
    );
}

#[test]
fn add_takes_the_key_text_as_well_as_a_file_and_never_prints_it() {
    let env = Env::new();
    let key = new_key();
    let (mut prompter, mut out) = Transcript::none();
    add(
        &add_args("acme-platform", &key.public_key_file(), true, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("adds");
    let shown = out.text();
    assert!(
        shown.contains("file         (key text from the command line)\n"),
        "{shown}"
    );
    assert!(!shown.contains(&key.public_key_base64()), "{shown}");
}

#[test]
fn a_secret_key_file_is_refused_with_the_c10_words_and_nothing_is_written() {
    let env = Env::new();
    let key = new_key();
    let secret = env.path("acme-signing.key");
    std::fs::write(
        &secret,
        key.key_file(None, CHEAP).expect("key file").as_bytes(),
    )
    .expect("write");
    let (mut prompter, mut out) = Transcript::answering("y");
    let err = add(
        &add_args("acme-platform", secret.to_str().expect("utf8"), true, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect_err("secret key");
    let (code, text) = rendered(&err);
    assert_eq!(code, 64);
    assert_eq!(
        normalized(&text, &env, &[]),
        golden!("c10-add-secret-file.txt")
    );
    assert_eq!(out.text(), "");
    assert!(!env.path("home").exists());
}

#[test]
fn secret_key_text_is_refused_with_the_shell_history_sentence_and_is_not_echoed() {
    let env = Env::new();
    let key = new_key();
    let secret = key.key_file(None, CHEAP).expect("key file").to_string();
    let line = secret.lines().nth(1).expect("line").to_owned();
    for text in [
        secret.clone(),
        line.clone(),
        "untrusted comment: rdy secret key ...".to_owned(),
        // A paste often carries a space or a line end. It must not turn into a file name that is echoed.
        format!(" {line}"),
        format!("{line} "),
        format!("{line}\r"),
    ] {
        let (mut prompter, mut out) = Transcript::answering("y");
        let err = add(
            &add_args("acme-platform", &text, true, None),
            &env.user(),
            ADDED,
            &mut prompter,
            &mut out,
        )
        .expect_err("secret key");
        let (code, shown) = rendered(&err);
        assert_eq!(code, 64);
        assert_eq!(tidy(&shown), golden!("c10-add-secret-text.txt"));
        assert!(!shown.contains(&line), "{shown}");
        assert_eq!(out.text(), "");
    }
    assert!(!env.path("home").exists());
}

#[test]
fn a_key_that_is_not_usable_or_not_there_is_a_usage_error_with_a_fix() {
    let env = Env::new();
    let missing = env.path("nope.pub");
    for (arg, needle) in [
        (missing.to_str().expect("utf8").to_owned(), "no such file"),
        (
            env.root().to_str().expect("utf8").to_owned(),
            "is not a regular file",
        ),
        (
            "untrusted comment: x\nnot a key at all\n".to_owned(),
            "not usable",
        ),
    ] {
        let (mut prompter, mut out) = Transcript::answering("y");
        let err = add(
            &add_args("acme-platform", &arg, true, None),
            &env.user(),
            ADDED,
            &mut prompter,
            &mut out,
        )
        .expect_err("refused");
        let (code, shown) = rendered(&err);
        assert_eq!(code, 64, "{shown}");
        assert!(shown.contains(needle), "{shown}");
        assert!(shown.contains("\nfix: "), "{shown}");
        assert!(!shown.contains("not a key at all"), "{shown}");
    }
}

#[test]
fn a_bad_product_or_note_is_refused_before_anyone_is_asked() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let cases = [
        add_args("Acme Platform", &file, false, None),
        add_args("", &file, false, None),
        add_args("acme-platform", &file, false, Some("two\nlines")),
        add_args("acme-platform", &file, false, Some(&"x".repeat(513))),
    ];
    for args in &cases {
        let (mut prompter, mut out) = Transcript::answering("y");
        let err = add(args, &env.user(), ADDED, &mut prompter, &mut out).expect_err("refused");
        let (code, shown) = rendered(&err);
        assert_eq!(code, 64, "{shown}");
        assert_eq!(out.text(), "", "nothing was asked or shown");
    }
    assert!(!env.path("home").exists());
}

#[test]
fn the_same_key_twice_and_a_different_key_with_the_same_id_are_refused_and_change_nothing() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let go = |file: &str| {
        let (mut prompter, mut out) = Transcript::none();
        add(
            &add_args("acme-platform", file, true, None),
            &env.user(),
            ADDED,
            &mut prompter,
            &mut out,
        )
    };
    go(&file).expect("first add");
    let before = std::fs::read(env.user_store()).expect("store");

    let (code, shown) = rendered(&go(&file).expect_err("same key"));
    assert_eq!(code, 64);
    assert!(
        shown.contains("is already trusted for acme-platform"),
        "{shown}"
    );

    // Another key that carries the first key's id. Anyone can make one.
    let (other, forged) = (new_key(), env.path("forged.pub"));
    let mut raw = Base64::decode_to_vec(other.public_key_base64(), None).expect("b64");
    let mine = Base64::decode_to_vec(key.public_key_base64(), None).expect("b64");
    raw[2..10].copy_from_slice(&mine[2..10]);
    let text = Base64::encode_to_string(&raw).expect("b64");
    std::fs::write(&forged, format!("untrusted comment: forged\n{text}\n")).expect("write");
    let (code, shown) = rendered(&go(forged.to_str().expect("utf8")).expect_err("same id"));
    assert_eq!(code, 64);
    assert!(
        shown.contains("already has a different key with the id"),
        "{shown}"
    );
    assert!(
        shown.contains("rdy trust remove acme-platform --key-id"),
        "{shown}"
    );

    assert_eq!(std::fs::read(env.user_store()).expect("store"), before);
}

#[test]
fn the_same_key_may_be_trusted_for_two_products_and_two_keys_for_one() {
    let env = Env::new();
    let (a, b) = (new_key(), new_key());
    let (file_a, file_b) = (env.pub_file("a.pub", &a), env.pub_file("b.pub", &b));
    for (product, file) in [
        ("acme-platform", &file_a),
        ("acme-edge", &file_a),
        ("acme-platform", &file_b),
    ] {
        let (mut prompter, mut out) = Transcript::none();
        add(
            &add_args(product, file, true, None),
            &env.user(),
            ADDED,
            &mut prompter,
            &mut out,
        )
        .expect("adds");
    }
    let listed = run_list(&env.user()).expect("lists");
    assert_eq!(listed.matches("  key id ").count(), 3, "{listed}");
}

#[test]
fn an_unsafe_store_stops_add_before_the_question() {
    let env = Env::new();
    let (old, new) = (new_key(), new_key());
    env.put_store(&env.user_store(), &[("acme-platform", &old, None)]);
    set_mode(env.user_store().parent().expect("dir"), 0o700);
    set_mode(&env.user_store(), 0o666);
    let file = env.pub_file("new.pub", &new);
    let (mut prompter, mut out) = Transcript::answering("y");
    let err = add(
        &add_args("acme-platform", &file, false, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect_err("unsafe store");
    assert_eq!(err.code(), ErrorCode::TrustStoreInsecure);
    assert_eq!(out.text(), "");
    assert_eq!(
        mode_of(&env.user_store()),
        0o666,
        "the store was not rewritten"
    );
}

#[test]
fn an_invalid_store_stops_add_and_is_not_replaced() {
    let env = Env::new();
    let key = new_key();
    let dir = env.path("home/.config/rdy");
    std::fs::create_dir_all(&dir).expect("dir");
    set_mode(&dir, 0o700);
    std::fs::write(
        env.user_store(),
        "apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n  - nope: 1\n",
    )
    .expect("store");
    set_mode(&env.user_store(), 0o600);
    let before = std::fs::read(env.user_store()).expect("store");
    let file = env.pub_file("k.pub", &key);
    let (mut prompter, mut out) = Transcript::none();
    let err = add(
        &add_args("acme-platform", &file, true, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect_err("invalid store");
    assert_eq!(err.code(), ErrorCode::Usage);
    assert_eq!(std::fs::read(env.user_store()).expect("store"), before);
}

#[test]
fn a_user_with_no_home_gets_a_fix_and_nothing_is_asked() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("k.pub", &key);
    let layout = Layout::from_env(&Vars::default(), 1000);
    let (mut prompter, mut out) = Transcript::answering("y");
    let err = add(
        &add_args("acme-platform", &file, false, None),
        &layout,
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect_err("no store");
    let (code, shown) = rendered(&err);
    assert_eq!(code, 64);
    assert!(shown.contains("fix: set HOME"), "{shown}");
    assert_eq!(out.text(), "");
}

// ---------------------------------------------------------------------------------------------
// Root writes the system store and never looks under a home
// ---------------------------------------------------------------------------------------------

#[test]
fn system_scope_add_writes_the_system_store_and_makes_nothing_under_home() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme-platform.pub", &key);
    let (mut prompter, mut out) = Transcript::answering("y");
    add(
        &add_args("acme-platform", &file, false, None),
        &env.system(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("adds");
    let shown = normalized(&out.text(), &env, &[&key]);
    assert!(shown.ends_with("Saved to /etc/rdy/trust.yaml\n"), "{shown}");
    assert!(env.system_store().is_file());
    assert_eq!(mode_of(&env.system_store()), 0o644);
    assert_eq!(mode_of(env.system_store().parent().expect("dir")), 0o755);
    assert!(
        !env.path("home").exists(),
        "a root run made a path under the home"
    );
}

#[test]
fn system_scope_list_and_remove_see_only_the_system_store() {
    let env = Env::new();
    let (user_key, system_key) = (new_key(), new_key());
    env.put_store(&env.user_store(), &[("acme-user", &user_key, None)]);
    env.put_store(&env.system_store(), &[("acme-platform", &system_key, None)]);
    let listed = run_list(&env.system()).expect("lists");
    assert!(listed.starts_with("acme-platform\n"), "{listed}");
    assert!(!listed.contains("acme-user"), "{listed}");

    let mut out = Vec::new();
    let err = remove(&remove_args("acme-user", None), &env.system(), &mut out)
        .expect_err("not in system");
    assert_eq!(err.code(), ErrorCode::Usage);
    // The user's store was not read for the hint either.
    assert!(!err.hint().contains("home"), "{}", err.hint());
    remove(&remove_args("acme-platform", None), &env.system(), &mut out).expect("removes");
    assert!(
        run_list(&env.system())
            .expect("lists")
            .starts_with("No keys are trusted yet.")
    );
    assert!(
        std::fs::read_to_string(env.user_store())
            .expect("user store")
            .contains("acme-user")
    );
}

// ---------------------------------------------------------------------------------------------
// A key given for one run is never saved
// ---------------------------------------------------------------------------------------------

#[test]
fn a_one_run_key_leaves_the_store_unchanged() {
    // `run --key` and `verify --key` pin with `TrustSource::Flag` in memory and never call `save`
    // (01 section 4.3). Saving a store that holds such a pin writes no trace of it, so even a call that
    // did save could not keep a one-run key.
    let env = Env::new();
    let (kept, one_run) = (new_key(), new_key());
    env.put_store(&env.user_store(), &[("acme-platform", &kept, Some(NOTE))]);
    set_mode(&env.user_store(), 0o600);
    set_mode(env.user_store().parent().expect("dir"), 0o700);
    let before = std::fs::read(env.user_store()).expect("store");

    let layout = env.user();
    let mut store = trust::load_scope(&layout, Scope::User).expect("loads");
    let original = store.to_yaml();
    assert_eq!(String::from_utf8_lossy(&before), original);
    store.pin(
        ProductSlug::new("acme-platform").expect("slug"),
        public(&one_run),
        TrustSource::Flag,
    );
    trust::save(&layout, &store).expect("saves");
    let after = std::fs::read_to_string(env.user_store()).expect("store");
    assert!(!after.contains(&one_run.public_key_base64()), "{after}");
    assert_eq!(after, original);
}

// ---------------------------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------------------------

#[test]
fn list_matches_c10_with_the_fingerprint_in_groups_of_four() {
    let env = Env::new();
    let key = new_key();
    env.put_store(&env.system_store(), &[("acme-platform", &key, Some(NOTE))]);
    let listed = run_list(&env.user()).expect("lists");
    assert_eq!(normalized(&listed, &env, &[&key]), golden!("c10-list.txt"));
    // The fingerprint is what `PublicKey::fingerprint` says, in two lines of eight groups.
    let fp = public(&key).fingerprint();
    let grouped: String = listed
        .lines()
        .filter(|l| l.starts_with("  fingerprint  ") || l.starts_with("               "))
        .flat_map(|l| l.split_whitespace().filter(|w| w.len() == 4))
        .collect();
    assert_eq!(grouped, fp);
}

#[test]
fn list_with_no_keys_says_how_to_add_one() {
    let env = Env::new();
    assert_eq!(
        tidy(&run_list(&env.user()).expect("lists")),
        golden!("c10-list-empty.txt")
    );
    assert_eq!(
        tidy(&run_list(&env.system()).expect("lists")),
        golden!("c10-list-empty.txt")
    );
}

#[test]
fn list_shows_the_user_store_then_the_system_store_with_the_file_of_each() {
    let env = Env::new();
    let (user_key, system_key) = (new_key(), new_key());
    env.put_store(&env.user_store(), &[("acme-user", &user_key, None)]);
    env.put_store(
        &env.system_store(),
        &[("acme-system", &system_key, Some("from root"))],
    );
    let listed = run_list(&env.user()).expect("lists");
    let user_at = listed.find("acme-user\n").expect("user entry");
    let system_at = listed.find("acme-system\n").expect("system entry");
    assert!(user_at < system_at, "{listed}");
    assert!(
        listed.contains(&format!("  file         {}\n", env.user_store().display())),
        "{listed}"
    );
    assert!(
        listed.contains(&format!(
            "  file         {}\n",
            env.system_store().display()
        )),
        "{listed}"
    );
    // A key with no note has no note line. Blocks are separated by one blank line.
    assert_eq!(listed.matches("  note         ").count(), 1, "{listed}");
    assert_eq!(listed.matches("\n\n").count(), 1, "{listed}");
}

#[test]
fn list_escapes_a_note_and_stops_at_an_unsafe_store_without_printing_keys() {
    let env = Env::new();
    let (a, b) = (new_key(), new_key());
    env.put_store(
        &env.system_store(),
        &[("acme-platform", &a, Some("a\\u202eb"))],
    );
    let listed = run_list(&env.user()).expect("lists");
    assert!(listed.contains("a\\u{202e}b"), "{listed}");
    assert!(!listed.contains('\u{202e}'));

    env.put_store(&env.user_store(), &[("acme-edge", &b, None)]);
    set_mode(&env.user_store(), 0o666);
    let err = run_list(&env.user()).expect_err("unsafe");
    assert_eq!(err.code(), ErrorCode::TrustStoreInsecure);
    assert_eq!(rendered(&err).0, 64);
}

#[test]
fn the_empty_listing_does_not_offer_trust_add_where_keys_cannot_be_saved() {
    let text = empty_listing(false);
    assert!(text.starts_with("No keys are trusted yet.\n"));
    assert!(!text.contains("rdy trust add"), "{text}");
    assert!(text.contains("https://docs.getrdy.io/unsigned"), "{text}");
    assert!(
        !text.contains("--key") && !text.contains("--allow-unsigned"),
        "{text}"
    );
}

// ---------------------------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------------------------

#[test]
fn remove_matches_c10_and_leaves_an_empty_store() {
    let env = Env::new();
    let key = new_key();
    env.put_store(&env.user_store(), &[("acme-platform", &key, None)]);
    set_mode(&env.user_store(), 0o600);
    set_mode(env.user_store().parent().expect("dir"), 0o700);
    let mut out = Vec::new();
    remove(&remove_args("acme-platform", None), &env.user(), &mut out).expect("removes");
    assert_eq!(
        normalized(&String::from_utf8(out).expect("utf8"), &env, &[&key]),
        golden!("c10-remove.txt")
    );
    let text = std::fs::read_to_string(env.user_store()).expect("store");
    assert!(text.ends_with("keys: []\n"), "{text}");
    assert_eq!(mode_of(&env.user_store()), 0o600);
}

#[test]
fn remove_with_two_keys_needs_a_key_id_and_names_both() {
    let env = Env::new();
    let (a, b) = (new_key(), new_key());
    env.put_store(
        &env.user_store(),
        &[("acme-platform", &a, None), ("acme-platform", &b, None)],
    );
    set_mode(&env.user_store(), 0o600);
    set_mode(env.user_store().parent().expect("dir"), 0o700);
    let before = std::fs::read(env.user_store()).expect("store");
    let mut out = Vec::new();
    let err =
        remove(&remove_args("acme-platform", None), &env.user(), &mut out).expect_err("ambiguous");
    let (code, shown) = rendered(&err);
    assert_eq!(code, 64);
    assert_eq!(
        normalized(&shown, &env, &[&a, &b]),
        golden!("c10-remove-two-keys.txt")
    );
    assert_eq!(std::fs::read(env.user_store()).expect("store"), before);

    // The id is the one `trust list` shows. Lower case works too.
    let id = public(&b).key_id().to_string().to_lowercase();
    remove(
        &remove_args("acme-platform", Some(&id)),
        &env.user(),
        &mut out,
    )
    .expect("removes b");
    let left = run_list(&env.user()).expect("lists");
    assert!(left.contains(&public(&a).key_id().to_string()), "{left}");
    assert!(!left.contains(&public(&b).key_id().to_string()), "{left}");
}

#[test]
fn remove_names_the_problem_when_there_is_no_such_key() {
    let env = Env::new();
    let (a, other) = (new_key(), new_key());
    env.put_store(&env.user_store(), &[("acme-platform", &a, None)]);
    set_mode(&env.user_store(), 0o600);
    set_mode(env.user_store().parent().expect("dir"), 0o700);
    let before = std::fs::read(env.user_store()).expect("store");
    let mut out = Vec::new();

    let (code, shown) = rendered(
        &remove(&remove_args("acme-edge", None), &env.user(), &mut out).expect_err("no product"),
    );
    assert_eq!(code, 64);
    assert!(shown.contains("acme-edge has no trusted key in"), "{shown}");
    assert!(shown.contains("fix: run rdy trust list"), "{shown}");

    let wrong = public(&other).key_id().to_string();
    let (code, shown) = rendered(
        &remove(
            &remove_args("acme-platform", Some(&wrong)),
            &env.user(),
            &mut out,
        )
        .expect_err("no id"),
    );
    assert_eq!(code, 64);
    assert!(
        shown.contains(&format!("has no trusted key with the id {wrong}")),
        "{shown}"
    );
    assert!(
        shown.contains(&public(&a).key_id().to_string()),
        "the fix lists the real ids: {shown}"
    );

    // Text that is not a key id is not repeated.
    let (_, shown) = rendered(
        &remove(
            &remove_args("acme-platform", Some("hunter2-secret")),
            &env.user(),
            &mut out,
        )
        .expect_err("no id"),
    );
    assert!(!shown.contains("hunter2"), "{shown}");
    assert_eq!(std::fs::read(env.user_store()).expect("store"), before);
}

#[test]
fn a_user_who_tries_to_remove_a_system_key_is_told_to_use_sudo() {
    let env = Env::new();
    let key = new_key();
    env.put_store(&env.system_store(), &[("acme-platform", &key, None)]);
    let mut out = Vec::new();
    let err =
        remove(&remove_args("acme-platform", None), &env.user(), &mut out).expect_err("not theirs");
    let hint = err.hint();
    assert!(
        hint.contains("sudo rdy trust remove acme-platform"),
        "{hint}"
    );
    assert!(hint.contains("system store"), "{hint}");
    assert!(
        run_list(&env.user())
            .expect("lists")
            .contains("acme-platform")
    );
}

#[test]
fn a_key_removed_while_the_question_is_open_does_not_come_back() {
    let env = Env::new();
    let (old, new) = (new_key(), new_key());
    env.put_store(&env.user_store(), &[("acme-platform", &old, None)]);
    set_mode(&env.user_store(), 0o600);
    set_mode(env.user_store().parent().expect("dir"), 0o700);
    let file = env.pub_file("new.pub", &new);
    // The old key is found to be compromised and removed from another shell while the question is open.
    let store = env.user_store();
    let (mut prompter, mut out) = Transcript::answering_after(move || {
        std::fs::write(&store, "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n")
            .expect("rewrite");
    });
    add(
        &add_args("acme-platform", &file, false, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("adds");
    let text = std::fs::read_to_string(env.user_store()).expect("store");
    assert!(text.contains(&new.public_key_base64()), "{text}");
    assert!(!text.contains(&old.public_key_base64()), "{text}");
}

#[test]
fn a_key_added_while_the_question_is_open_is_found_as_a_duplicate_after_the_yes() {
    let env = Env::new();
    let key = new_key();
    let file = env.pub_file("acme.pub", &key);
    let store = env.user_store();
    let entry = format!(
        "apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n  - product: acme-platform\n    key: {}\n    added_at: {ADDED}\n",
        key.public_key_base64()
    );
    let (mut prompter, mut out) = Transcript::answering_after({
        let store = store.clone();
        move || {
            std::fs::create_dir_all(store.parent().expect("dir")).expect("dir");
            std::fs::write(&store, entry).expect("write");
            set_mode(&store, 0o600);
            set_mode(store.parent().expect("dir"), 0o700);
        }
    });
    let err = add(
        &add_args("acme-platform", &file, false, None),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect_err("now a duplicate");
    assert_eq!(err.exit_code().code(), 64);
    assert!(err.to_string().contains("already trusted"), "{err}");
    let text = std::fs::read_to_string(&store).expect("store");
    assert_eq!(text.matches(&key.public_key_base64()).count(), 1, "{text}");
}

#[test]
fn a_user_who_tries_to_remove_a_system_key_by_id_is_told_the_id_in_the_sudo_line() {
    let env = Env::new();
    let key = new_key();
    env.put_store(&env.system_store(), &[("acme-platform", &key, None)]);
    let id = public(&key).key_id().to_string();
    let mut out = Vec::new();
    let err = remove(
        &remove_args("acme-platform", Some(&id.to_ascii_lowercase())),
        &env.user(),
        &mut out,
    )
    .expect_err("not theirs");
    assert!(
        err.hint().contains(&format!(
            "sudo rdy trust remove acme-platform --key-id {id}"
        )),
        "{}",
        err.hint()
    );
    // An id the system store does not have gets no sudo advice.
    let err = remove(
        &remove_args("acme-platform", Some("0000000000000000")),
        &env.user(),
        &mut out,
    )
    .expect_err("no such id anywhere");
    assert!(!err.hint().contains("sudo"), "{}", err.hint());
}

#[test]
fn remove_refuses_an_unsafe_store_and_a_bad_product() {
    let env = Env::new();
    let key = new_key();
    env.put_store(&env.user_store(), &[("acme-platform", &key, None)]);
    set_mode(&env.user_store(), 0o666);
    let mut out = Vec::new();
    let err =
        remove(&remove_args("acme-platform", None), &env.user(), &mut out).expect_err("unsafe");
    assert_eq!(err.code(), ErrorCode::TrustStoreInsecure);
    assert_eq!(
        rendered(
            &remove(&remove_args("Not A Slug", None), &env.user(), &mut out).expect_err("slug")
        )
        .0,
        64
    );
}

// ---------------------------------------------------------------------------------------------
// C.9 and the chain from keygen to sign to trust add
// ---------------------------------------------------------------------------------------------

fn no_password(_: &mut dyn Write) -> Result<Option<KeyPassword>, PasswordError> {
    Ok(None)
}

#[test]
fn keygen_and_sign_match_c9_and_the_fingerprint_is_the_one_trust_add_shows() {
    let env = Env::new();
    let name = env.path("acme-signing");

    // keygen, with the password typed twice.
    let (mut prompter, mut out) = Transcript::new(true, &[], &["correct horse", "correct horse"]);
    keygen(
        &KeygenArgs {
            name: name.to_str().expect("utf8").to_owned(),
            unencrypted: false,
            password_file: None,
        },
        &mut no_password,
        &mut prompter,
        CHEAP,
        &mut out,
    )
    .expect("keygen");
    let pub_text = std::fs::read_to_string(env.path("acme-signing.pub")).expect("pub");
    let made = PublicKey::from_key_file_text(&pub_text).expect("public key");
    let (first, second) = fingerprint_lines(&made.fingerprint());
    let generated = out.text();
    assert!(
        generated.contains(&format!("fingerprint  {first}\n")),
        "{generated}"
    );
    assert!(
        generated.contains(&format!("             {second}\n")),
        "{generated}"
    );
    let doc_keygen = |text: &str| {
        tidy(
            &text
                .replace(&format!("{}/", env.root().display()), "")
                .replace(&made.key_id().to_string(), DOC_ID)
                .replace(&first, DOC_FP_1)
                .replace(&second, DOC_FP_2),
        )
    };
    assert_eq!(doc_keygen(&generated), golden!("c9-keygen.txt"));

    // sign, with the password typed at the prompt.
    let spec = env.path("acme-platform.yaml");
    std::fs::write(&spec, GOOD_SPEC).expect("spec");
    let (mut prompter, mut out) = Transcript::new(true, &[], &["correct horse"]);
    sign(
        &SignArgs {
            spec: spec.clone(),
            secret_key: env.path("acme-signing.key"),
            sig: None,
            force: false,
            password_file: None,
        },
        SIGNED_AT,
        &mut no_password,
        &mut prompter,
        &mut out,
    )
    .expect("sign");
    let signed = out.text();
    let sha = rdy_spec::load(
        GOOD_SPEC.as_bytes(),
        None,
        &TrustStore::new(),
        rdy_spec::sig::Policy::AllowUnsigned,
    )
    .expect("loads unsigned")
    .sha256()
    .to_owned();
    let doc_sign = tidy(
        &signed
            .replace(&format!("{}/", env.root().display()), "")
            .replace(&sha, DOC_SHA)
            .replace(&made.key_id().to_string(), DOC_ID)
            .replace(&made.fingerprint(), DOC_FP)
            .replace(&first, DOC_FP_1)
            .replace(&second, DOC_FP_2),
    );
    assert_eq!(doc_sign, golden!("c9-sign.txt"));

    // The line sign tells the vendor to send works as written: trust add, on a terminal, with the file
    // keygen made. The key id and the fingerprint it shows are the ones keygen and sign printed.
    let (mut prompter, mut out) = Transcript::answering("y");
    add(
        &add_args(
            "acme-platform",
            env.path("acme-signing.pub").to_str().expect("utf8"),
            false,
            None,
        ),
        &env.user(),
        ADDED,
        &mut prompter,
        &mut out,
    )
    .expect("trust add");
    let shown = out.text();
    assert!(
        shown.contains(&format!("key id       {}\n", made.key_id())),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("fingerprint  {first}\n")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("             {second}\n")),
        "{shown}"
    );
}
