//! Tests for `spec keygen` and `spec sign` without a terminal or the process environment.
//!
//! The prompt is a scripted terminal, the password source is a closure, the clock is a string and the
//! key derivation is cheap. Keys, specs and passwords are synthetic.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use std::rc::Rc;

use ct_codecs::{Base64, Decoder, Encoder};

use super::*;
use crate::prompt::{PromptError, Secret};

/// A password that must never show up in any output.
const PASSWORD: &str = "CANARY-correct horse battery staple";
const SIGNED_AT: &str = "2027-03-02T15:40:09Z";
const CHEAP: KdfCost = KdfCost::new(32_768, 1 << 20);

const GOOD_SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n    fix: Use a bigger node.\n";

/// What the scripted terminal was asked to show.
type Log = Rc<RefCell<Vec<String>>>;

/// A terminal that needs no TTY. Hidden reads come from a queue.
struct Scripted {
    interactive: bool,
    hidden: VecDeque<&'static str>,
    prompts: Log,
}

impl Scripted {
    fn typing(passwords: &[&'static str]) -> (Prompter<Self>, Log) {
        Self::build(true, passwords)
    }

    fn no_terminal() -> (Prompter<Self>, Log) {
        Self::build(false, &[])
    }

    fn build(interactive: bool, passwords: &[&'static str]) -> (Prompter<Self>, Log) {
        let prompts = Log::default();
        let term = Self {
            interactive,
            hidden: passwords.iter().copied().collect(),
            prompts: Rc::clone(&prompts),
        };
        (Prompter::new(term), prompts)
    }
}

impl Terminal for Scripted {
    fn is_interactive(&self) -> bool {
        self.interactive
    }

    fn write_prompt(&mut self, text: &str) -> io::Result<()> {
        self.prompts.borrow_mut().push(text.to_owned());
        Ok(())
    }

    fn read_line(&mut self) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn read_hidden(&mut self) -> Result<Secret, PromptError> {
        let text = self.hidden.pop_front().unwrap_or("");
        Ok(Secret::new(text.to_owned()))
    }
}

/// The prompts shown so far.
fn shown_prompts(log: &Log) -> Vec<String> {
    log.borrow().clone()
}

fn no_password(_: &mut dyn Write) -> Result<Option<KeyPassword>, PasswordError> {
    Ok(None)
}

fn from_file_or_env(_: &mut dyn Write) -> Result<Option<KeyPassword>, PasswordError> {
    Ok(Some(KeyPassword::new(PASSWORD.to_owned())))
}

fn must_not_be_called(_: &mut dyn Write) -> Result<Option<KeyPassword>, PasswordError> {
    panic!("the password source must not be called");
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"))
}

fn keygen_args(dir: &Path, name: &str, unencrypted: bool) -> KeygenArgs {
    KeygenArgs {
        name: dir.join(name).display().to_string(),
        unencrypted,
        password_file: None,
    }
}

fn sign_args(spec: &Path, key: &Path) -> SignArgs {
    SignArgs {
        spec: spec.to_path_buf(),
        secret_key: key.to_path_buf(),
        sig: None,
        force: false,
        password_file: None,
    }
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

/// Runs keygen with a password from the source. Returns the result and the output.
fn make_key(dir: &Path, name: &str, password: Option<&str>) -> (Result<(), CliError>, String) {
    let args = keygen_args(dir, name, password.is_none());
    let mut out = Vec::new();
    let (mut prompter, _log) = Scripted::no_terminal();
    let result = if password.is_some() {
        keygen(&args, &mut from_file_or_env, &mut prompter, CHEAP, &mut out)
    } else {
        keygen(
            &args,
            &mut must_not_be_called,
            &mut prompter,
            CHEAP,
            &mut out,
        )
    };
    (result, text(&out))
}

fn write_spec(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("acme-platform.yaml");
    std::fs::write(&path, body).unwrap_or_else(|e| panic!("write spec: {e}"));
    path
}

fn run_sign(
    args: &SignArgs,
    source: PasswordSource<'_>,
    prompter: &mut Prompter<Scripted>,
) -> (Result<(), CliError>, String) {
    let mut out = Vec::new();
    let result = sign(args, SIGNED_AT, source, prompter, &mut out);
    (result, text(&out))
}

fn rendered(result: Result<(), CliError>) -> (u8, String) {
    match result {
        Ok(()) => panic!("expected an error"),
        Err(err) => {
            let r = err.render();
            (r.exit_code(), r.text())
        }
    }
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat: {e}"))
        .permissions()
        .mode()
        & 0o7777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod: {e}"));
}

// ---- keygen --------------------------------------------------------------------------------

#[test]
fn keygen_with_typed_passwords_writes_an_encrypted_key_and_a_public_key() {
    let d = dir();
    let args = keygen_args(d.path(), "acme-signing", false);
    let (mut prompter, log) = Scripted::typing(&[PASSWORD, PASSWORD]);
    let mut out = Vec::new();
    keygen(&args, &mut no_password, &mut prompter, CHEAP, &mut out).expect("keygen");

    // Two prompts, in the words of 07 C.9.
    assert_eq!(
        shown_prompts(&log),
        [
            "Password for the new secret key (input hidden): ",
            "Repeat the password: "
        ]
    );
    let key_path = d.path().join("acme-signing.key");
    let pub_path = d.path().join("acme-signing.pub");
    let key_text = std::fs::read_to_string(&key_path).expect("key file");
    let stored = StoredKey::parse(&key_text).expect("parse");
    assert!(stored.is_encrypted());
    let key = stored
        .unlock(Some(PASSWORD))
        .expect("opens with the password");
    assert_eq!(
        std::fs::read_to_string(&pub_path).expect("pub file"),
        key.public_key_file()
    );

    let shown = text(&out);
    assert!(
        shown.contains("(secret, readable only by you)") || !cfg!(unix),
        "{shown}"
    );
    assert!(
        shown.contains("Publish the fingerprint on your docs page"),
        "{shown}"
    );
    assert!(shown.contains("Back up "), "{shown}");
    assert!(
        shown.contains("Next: rdy spec sign <spec> --secret-key "),
        "{shown}"
    );
    assert!(!shown.contains("CANARY"), "{shown}");
    assert!(
        !shown.contains("warning"),
        "an encrypted key has no warning: {shown}"
    );
}

#[test]
fn keygen_prints_the_key_id_and_the_fingerprint_in_groups_of_four() {
    let d = dir();
    let (result, shown) = make_key(d.path(), "k", Some(PASSWORD));
    result.expect("keygen");
    let pub_text = std::fs::read_to_string(d.path().join("k.pub")).expect("pub");
    let public = PublicKey::from_base64(pub_text.lines().nth(1).expect("line")).expect("key");
    let (first, second) = fingerprint_lines(&public.fingerprint());
    assert!(
        shown.contains(&format!("key id       {}\n", public.key_id())),
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
    assert_eq!(first.split(' ').count(), 8);
    assert!(
        first
            .split(' ')
            .chain(second.split(' '))
            .all(|g| g.len() == 4)
    );
    assert_eq!(
        format!("{first} {second}").replace(' ', ""),
        public.fingerprint()
    );
}

#[cfg(unix)]
#[test]
fn keygen_makes_the_secret_key_0600_and_the_public_key_0644() {
    let d = dir();
    let (result, _) = make_key(d.path(), "k", Some(PASSWORD));
    result.expect("keygen");
    assert_eq!(mode_of(&d.path().join("k.key")), 0o600);
    // Exactly 0644 whatever the umask: the file is set after it is created (M1-168 runs rdy with 077).
    assert_eq!(mode_of(&d.path().join("k.pub")), 0o644);
}

#[cfg(unix)]
#[test]
fn the_private_file_helper_creates_with_no_group_or_other_bits() {
    // The mode is passed to open(2), so there is no moment when the file is wider than 0600. A umask can
    // only remove bits, so this holds under any umask. This pins the creation helper itself.
    let d = dir();
    let path = d.path().join("secret");
    let _file = files::create_new_private(&path).expect("create");
    assert_eq!(mode_of(&path) & 0o077, 0);
}

#[test]
fn keygen_unencrypted_asks_for_nothing_and_warns() {
    let d = dir();
    let (result, shown) = make_key(d.path(), "ci", None);
    result.expect("keygen");
    let key_text = std::fs::read_to_string(d.path().join("ci.key")).expect("key");
    let stored = StoredKey::parse(&key_text).expect("parse");
    assert!(!stored.is_encrypted());
    assert!(stored.unlock(None).is_ok());
    assert!(shown.contains("is not protected by a password"), "{shown}");
}

#[test]
fn keygen_with_a_password_from_the_file_or_variable_never_prompts() {
    let d = dir();
    let args = keygen_args(d.path(), "ci", false);
    // No terminal at all: a prompt would be an error.
    let (mut prompter, log) = Scripted::no_terminal();
    keygen(
        &args,
        &mut from_file_or_env,
        &mut prompter,
        CHEAP,
        &mut Vec::new(),
    )
    .expect("keygen");
    assert!(shown_prompts(&log).is_empty());
    let key_text = std::fs::read_to_string(d.path().join("ci.key")).expect("key");
    assert!(
        StoredKey::parse(&key_text)
            .expect("parse")
            .unlock(Some(PASSWORD))
            .is_ok()
    );
}

#[test]
fn keygen_refuses_passwords_that_differ_or_are_empty_and_writes_nothing() {
    for typed in [&["one", "two"][..], &["", ""], &["one", ""]] {
        let d = dir();
        let args = keygen_args(d.path(), "k", false);
        let (mut prompter, _log) = Scripted::typing(typed);
        let result = keygen(
            &args,
            &mut no_password,
            &mut prompter,
            CHEAP,
            &mut Vec::new(),
        );
        let (code, shown) = rendered(result);
        assert_eq!(code, 64, "{typed:?}");
        assert!(shown.contains("\nfix: "), "{shown}");
        assert!(!d.path().join("k.key").exists() && !d.path().join("k.pub").exists());
        assert!(!shown.contains("one") && !shown.contains("two"), "{shown}");
    }
}

#[test]
fn keygen_with_no_terminal_and_no_password_says_how_to_give_one() {
    let d = dir();
    let args = keygen_args(d.path(), "k", false);
    let result = keygen(
        &args,
        &mut no_password,
        &mut Scripted::no_terminal().0,
        CHEAP,
        &mut Vec::new(),
    );
    let (code, shown) = rendered(result);
    assert_eq!(code, 64);
    assert!(
        shown.contains("--password-file") && shown.contains("RDY_KEY_PASSWORD"),
        "{shown}"
    );
    assert!(shown.contains("--unencrypted"), "{shown}");
    assert!(!d.path().join("k.key").exists());
}

#[test]
fn keygen_never_overwrites_either_file() {
    for existing in ["k.key", "k.pub"] {
        let d = dir();
        let theirs = d.path().join(existing);
        std::fs::write(&theirs, "precious").expect("write");
        let (result, _) = make_key(d.path(), "k", Some(PASSWORD));
        let (code, shown) = rendered(result);
        assert_eq!(code, 64, "{existing}");
        assert!(shown.contains("already exists"), "{shown}");
        assert!(shown.contains("never overwrites"), "{shown}");
        assert_eq!(std::fs::read_to_string(&theirs).expect("read"), "precious");
        let other = if existing == "k.key" {
            "k.pub"
        } else {
            "k.key"
        };
        assert!(
            !d.path().join(other).exists(),
            "no half pair is left behind"
        );
    }
}

#[test]
fn keygen_does_not_ask_for_a_password_when_a_file_exists() {
    let d = dir();
    std::fs::write(d.path().join("k.key"), "x").expect("write");
    let args = keygen_args(d.path(), "k", false);
    let (mut prompter, log) = Scripted::typing(&["a", "a"]);
    let result = keygen(
        &args,
        &mut no_password,
        &mut prompter,
        CHEAP,
        &mut Vec::new(),
    );
    assert!(result.is_err());
    assert!(shown_prompts(&log).is_empty(), "refused before any prompt");
}

#[cfg(unix)]
#[test]
fn keygen_does_not_write_through_a_symlink() {
    let d = dir();
    let target = d.path().join("target");
    std::fs::write(&target, "precious").expect("write");
    // A link to a file that exists, and a dangling link.
    for (link_name, link_to) in [
        ("k.key", target.clone()),
        ("k.pub", d.path().join("nowhere")),
    ] {
        std::os::unix::fs::symlink(&link_to, d.path().join(link_name)).expect("symlink");
        let (result, _) = make_key(d.path(), "k", Some(PASSWORD));
        assert_eq!(rendered(result).0, 64, "{link_name}");
        std::fs::remove_file(d.path().join(link_name)).expect("rm");
    }
    assert_eq!(std::fs::read_to_string(&target).expect("read"), "precious");
    assert!(!d.path().join("nowhere").exists());
}

#[test]
fn keygen_in_a_missing_folder_is_a_usage_error_with_a_fix_and_makes_no_file() {
    let d = dir();
    let args = KeygenArgs {
        name: d
            .path()
            .join("no-such-folder")
            .join("k")
            .display()
            .to_string(),
        unencrypted: true,
        password_file: None,
    };
    let result = keygen(
        &args,
        &mut must_not_be_called,
        &mut Scripted::no_terminal().0,
        CHEAP,
        &mut Vec::new(),
    );
    let (code, shown) = rendered(result);
    assert_eq!(code, 64, "{shown}");
    assert!(shown.contains("cannot create"), "{shown}");
    assert!(shown.contains("\nfix: make the folder"), "{shown}");
    assert!(!d.path().join("no-such-folder").exists());
}

#[test]
fn keygen_refuses_an_empty_name_or_one_that_ends_in_a_slash() {
    for name in ["", "keys/", "keys\\"] {
        let args = KeygenArgs {
            name: name.to_owned(),
            unencrypted: true,
            password_file: None,
        };
        let result = keygen(
            &args,
            &mut must_not_be_called,
            &mut Scripted::no_terminal().0,
            CHEAP,
            &mut Vec::new(),
        );
        assert_eq!(rendered(result).0, 64, "{name:?}");
    }
}

// ---- sign ----------------------------------------------------------------------------------

/// A spec and an encrypted key in `dir`, and the arguments to sign the spec.
fn setup(d: &Path, spec: &str) -> SignArgs {
    let (result, _) = make_key(d, "acme-signing", Some(PASSWORD));
    result.expect("keygen");
    sign_args(&write_spec(d, spec), &d.join("acme-signing.key"))
}

/// The signature file next to `args.spec`, loaded back the way a customer's rdy loads it.
fn verify_written(args: &SignArgs, sig_path: &Path) -> rdy_spec::LoadedSpec {
    let bytes = std::fs::read(&args.spec).expect("spec");
    let sidecar = std::fs::read(sig_path).expect("sidecar");
    let pub_path = args.secret_key.with_extension("pub");
    let pub_text = std::fs::read_to_string(pub_path).expect("pub");
    let public = PublicKey::from_base64(pub_text.lines().nth(1).expect("line")).expect("key");
    let mut trust = TrustStore::new();
    let product = rdy_spec::spec::ProductSlug::new("acme-platform").expect("slug");
    trust.pin(product, public, TrustSource::User);
    load(&bytes, Some(&sidecar), &trust, Policy::RequireSigned).expect("verifies")
}

#[test]
fn sign_writes_a_signature_that_verifies_and_prints_the_vendors_lines() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let (result, shown) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
    result.expect("sign");

    let sig_path = d.path().join("acme-platform.yaml.minisig");
    let loaded = verify_written(&args, &sig_path);
    // The signature is public: 0644 whatever the umask (M1-168 runs rdy with 077).
    #[cfg(unix)]
    assert_eq!(mode_of(&sig_path), 0o644);
    assert_eq!(
        std::fs::read_to_string(&sig_path)
            .expect("sidecar")
            .lines()
            .nth(2),
        Some("trusted comment: rdy-spec-v1 product=acme-platform signed_at=2027-03-02T15:40:09Z")
    );
    assert!(
        shown.contains("signed on    2027-03-02T15:40:09Z"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("sha256       {}", loaded.sha256())),
        "{shown}"
    );
    assert!(
        shown.contains("Checked the new signature: it verifies."),
        "{shown}"
    );
    assert!(
        shown.contains("  rdy trust add acme-platform --key "),
        "{shown}"
    );
    assert!(shown.contains("acme-signing.pub"), "{shown}");
    assert!(
        shown.contains("compare it with your docs page before they say yes"),
        "{shown}"
    );
    assert!(!shown.contains("CANARY"), "{shown}");
    let SignatureState::Verified { fingerprint, .. } = loaded.signature() else {
        panic!("not verified");
    };
    assert!(
        shown.contains(&format!("The fingerprint is {fingerprint}.")),
        "{shown}"
    );
    // The spec itself is untouched.
    assert_eq!(
        std::fs::read_to_string(&args.spec).expect("spec"),
        GOOD_SPEC
    );
}

#[test]
fn sign_asks_for_the_password_at_the_prompt_when_there_is_no_other_source() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let (mut prompter, log) = Scripted::typing(&[PASSWORD]);
    let (result, shown) = run_sign(&args, &mut no_password, &mut prompter);
    result.expect("sign");
    let asked = shown_prompts(&log);
    assert_eq!(asked.len(), 1);
    assert!(asked[0].starts_with("Password for "), "{asked:?}");
    assert!(asked[0].contains("acme-signing.key") && asked[0].ends_with("(input hidden): "));
    assert!(!shown.contains("CANARY"));
}

#[test]
fn sign_with_a_password_from_the_file_or_variable_does_not_prompt() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    // No terminal: a prompt would be an error.
    let (mut prompter, log) = Scripted::no_terminal();
    run_sign(&args, &mut from_file_or_env, &mut prompter)
        .0
        .expect("sign");
    assert!(shown_prompts(&log).is_empty());
}

#[test]
fn sign_with_an_unencrypted_key_never_asks_for_a_password() {
    let d = dir();
    make_key(d.path(), "ci", None).0.expect("keygen");
    let spec = write_spec(d.path(), GOOD_SPEC);
    let args = sign_args(&spec, &d.path().join("ci.key"));
    let (result, shown) = run_sign(
        &args,
        &mut must_not_be_called,
        &mut Scripted::no_terminal().0,
    );
    result.expect("sign");
    assert!(d.path().join("acme-platform.yaml.minisig").exists());
    // One warning line, and it names the key.
    let warnings: Vec<&str> = shown
        .lines()
        .filter(|l| l.starts_with("warning:") && l.contains("is not protected by a password"))
        .collect();
    assert_eq!(warnings.len(), 1, "{shown}");
    assert!(warnings[0].contains("ci.key"), "{shown}");
}

#[test]
fn sign_with_an_encrypted_key_does_not_warn_about_a_missing_password() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let (result, shown) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
    result.expect("sign");
    assert!(!shown.contains("is not protected"), "{shown}");
}

#[test]
fn a_missing_random_source_has_its_own_message_not_the_bug_text() {
    let (code, shown) = rendered(Err(key_error_without_file(KeyError::Random)));
    assert_eq!(code, 70);
    assert!(shown.contains("could not give random bytes"), "{shown}");
    assert!(!shown.contains("internal error"), "{shown}");
}

#[test]
fn sign_with_no_password_source_and_no_terminal_refuses_with_a_fix() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let (result, _) = run_sign(&args, &mut no_password, &mut Scripted::no_terminal().0);
    let (code, shown) = rendered(result);
    assert_eq!(code, 64);
    assert!(
        shown.contains("--password-file") && shown.contains("RDY_KEY_PASSWORD"),
        "{shown}"
    );
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn a_wrong_password_signs_nothing_and_does_not_echo_it() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let mut wrong = |_: &mut dyn Write| Ok(Some(KeyPassword::new("CANARY-wrong".to_owned())));
    let (result, _) = run_sign(&args, &mut wrong, &mut Scripted::no_terminal().0);
    let (code, shown) = rendered(result);
    assert_eq!(code, 64);
    assert!(
        shown.contains("password") && shown.contains("wrong"),
        "{shown}"
    );
    assert!(!shown.contains("CANARY"), "{shown}");
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn sign_refuses_a_spec_with_lint_errors_and_asks_for_nothing() {
    // The three typos of the ticket: `mn`, `32G` and `host.memroy`.
    let typos = [
        ("mn: 32Gi", "  - id: host.memory\n    mn: 32Gi\n"),
        ("min: 32G", "  - id: host.memory\n    min: 32G\n"),
        ("host.memroy", "  - id: host.memroy\n    min: 32Gi\n"),
        ("no threshold", "  - id: host.memory\n"),
    ];
    for (what, check) in typos {
        let d = dir();
        let spec = format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n{check}"
        );
        // The key does not even exist: lint comes first, so nothing about the key is read.
        let spec_path = write_spec(d.path(), &spec);
        let args = sign_args(&spec_path, &d.path().join("missing.key"));
        let (mut prompter, log) = Scripted::typing(&[PASSWORD]);
        let (result, shown) = run_sign(&args, &mut must_not_be_called, &mut prompter);
        let (code, err) = rendered(result);
        assert_eq!(code, 64, "{what}");
        assert!(shown.contains(": error: "), "{what}: {shown}");
        assert!(shown.contains("\n  fix: "), "{what}: {shown}");
        assert!(
            err.contains("not signed: ") && err.contains("1 error"),
            "{what}: {err}"
        );
        assert!(
            err.contains("fix: correct the errors above and run rdy spec sign again"),
            "{err}"
        );
        assert!(shown_prompts(&log).is_empty(), "{what}");
        assert!(
            !d.path().join("acme-platform.yaml.minisig").exists(),
            "{what}"
        );
    }
}

#[test]
fn sign_counts_every_error_and_prints_every_finding() {
    let d = dir();
    let spec = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.memory\n    mn: 32Gi\n  - id: host.memroy\n    min: 1Gi\n  - id: gpu.cuda\n    min: \"12.4\"\n";
    let spec_path = write_spec(d.path(), spec);
    let args = sign_args(&spec_path, &d.path().join("missing.key"));
    let (result, shown) = run_sign(
        &args,
        &mut must_not_be_called,
        &mut Scripted::no_terminal().0,
    );
    let (_, err) = rendered(result);
    assert!(err.contains("has 2 errors"), "{err}");
    assert_eq!(shown.matches(": error: ").count(), 2, "{shown}");
    assert_eq!(shown.matches(": warning: ").count(), 1, "{shown}");
}

#[test]
fn sign_prints_warnings_and_goes_on() {
    let d = dir();
    let spec = format!("{GOOD_SPEC}  - id: gpu.cuda\n    min: \"12.4\"\n    fix: Install CUDA.\n");
    let args = setup(d.path(), &spec);
    let (result, shown) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
    result.expect("a warning does not stop signing");
    assert!(shown.contains(": warning: "), "{shown}");
    assert!(shown.contains("gpu.cuda"), "{shown}");
    assert!(d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn sign_refuses_a_spec_that_does_not_parse() {
    let d = dir();
    let spec_path = write_spec(d.path(), "apiVersion: rdy/v1\nkind: [unclosed\n");
    let args = sign_args(&spec_path, &d.path().join("missing.key"));
    let (result, _) = run_sign(
        &args,
        &mut must_not_be_called,
        &mut Scripted::no_terminal().0,
    );
    let (code, err) = rendered(result);
    assert_eq!(code, 64);
    assert!(err.starts_with("error: "), "{err}");
    assert!(err.contains("\nfix: "), "{err}");
}

#[test]
fn sign_reports_a_missing_or_wrong_kind_of_spec_file() {
    let d = dir();
    let key = d.path().join("missing.key");
    for path in [d.path().join("nope.yaml"), d.path().to_path_buf()] {
        let args = sign_args(&path, &key);
        let (result, _) = run_sign(
            &args,
            &mut must_not_be_called,
            &mut Scripted::no_terminal().0,
        );
        let (code, err) = rendered(result);
        assert_eq!(code, 64);
        assert!(err.contains("cannot read"), "{err}");
    }
}

#[test]
fn sign_signs_the_exact_bytes_with_crlf_and_a_bom() {
    for (what, bytes) in [
        ("crlf", GOOD_SPEC.replace('\n', "\r\n").into_bytes()),
        ("trailing space", format!("{GOOD_SPEC}  \n").into_bytes()),
        ("no final newline", GOOD_SPEC.trim_end().as_bytes().to_vec()),
    ] {
        let d = dir();
        let args = setup(d.path(), "placeholder");
        std::fs::write(&args.spec, &bytes).expect("write");
        let (result, _) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
        result.unwrap_or_else(|e| panic!("{what}: {e}"));
        verify_written(&args, &d.path().join("acme-platform.yaml.minisig"));
        assert_eq!(std::fs::read(&args.spec).expect("spec"), bytes, "{what}");
    }
}

#[test]
fn sign_refuses_to_replace_a_signature_without_force_and_replaces_it_with_force() {
    let d = dir();
    let mut args = setup(d.path(), GOOD_SPEC);
    let sig_path = d.path().join("acme-platform.yaml.minisig");
    std::fs::write(&sig_path, "old").expect("write");

    let (mut prompter, log) = Scripted::typing(&[PASSWORD]);
    let (result, _) = run_sign(&args, &mut no_password, &mut prompter);
    let (code, err) = rendered(result);
    assert_eq!(code, 64);
    assert!(
        err.contains("already exists") && err.contains("--force"),
        "{err}"
    );
    assert!(shown_prompts(&log).is_empty(), "refused before the prompt");
    assert_eq!(std::fs::read_to_string(&sig_path).expect("read"), "old");

    args.force = true;
    let (result, _) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
    result.expect("sign with force");
    verify_written(&args, &sig_path);
    #[cfg(unix)]
    assert_eq!(mode_of(&sig_path), 0o644, "the replaced file too");
    let leftovers: Vec<_> = std::fs::read_dir(d.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "no temporary file is left behind");
}

#[test]
fn sign_writes_to_the_file_named_by_sig() {
    let d = dir();
    let mut args = setup(d.path(), GOOD_SPEC);
    let out = d.path().join("elsewhere.minisig");
    args.sig = Some(out.clone());
    run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0)
        .0
        .expect("sign");
    verify_written(&args, &out);
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn sign_never_replaces_the_spec_or_the_key_with_its_signature() {
    let d = dir();
    let mut args = setup(d.path(), GOOD_SPEC);
    args.force = true;
    for target in [args.spec.clone(), args.secret_key.clone()] {
        let before = std::fs::read(&target).expect("read");
        args.sig = Some(target.clone());
        let (result, _) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
        assert_eq!(rendered(result).0, 64);
        assert_eq!(std::fs::read(&target).expect("read"), before);
    }
}

#[cfg(unix)]
#[test]
fn sign_with_force_replaces_a_symlink_and_does_not_write_through_it() {
    let d = dir();
    let mut args = setup(d.path(), GOOD_SPEC);
    args.force = true;
    let target = d.path().join("target");
    std::fs::write(&target, "precious").expect("write");
    let sig_path = d.path().join("acme-platform.yaml.minisig");
    std::os::unix::fs::symlink(&target, &sig_path).expect("symlink");
    run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0)
        .0
        .expect("sign");
    assert_eq!(std::fs::read_to_string(&target).expect("read"), "precious");
    assert!(
        !std::fs::symlink_metadata(&sig_path)
            .expect("stat")
            .file_type()
            .is_symlink()
    );
    verify_written(&args, &sig_path);
}

#[cfg(unix)]
#[test]
fn sign_without_force_does_not_write_through_a_symlink() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let sig_path = d.path().join("acme-platform.yaml.minisig");
    std::os::unix::fs::symlink(d.path().join("nowhere"), &sig_path).expect("symlink");
    let (result, _) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
    assert_eq!(rendered(result).0, 64);
    assert!(!d.path().join("nowhere").exists());
}

#[cfg(unix)]
#[test]
fn sign_refuses_a_key_that_group_or_others_can_read_or_write() {
    for mode in [0o640, 0o604, 0o644, 0o660, 0o606, 0o666, 0o710] {
        let d = dir();
        let args = setup(d.path(), GOOD_SPEC);
        set_mode(&args.secret_key, mode);
        let (mut prompter, log) = Scripted::typing(&[PASSWORD]);
        let (result, _) = run_sign(&args, &mut must_not_be_called, &mut prompter);
        let (code, err) = rendered(result);
        assert_eq!(code, 64, "{mode:o}");
        assert!(
            err.contains("can be read or written by other users"),
            "{mode:o}: {err}"
        );
        assert!(err.contains("chmod 600 "), "{mode:o}: {err}");
        assert!(
            shown_prompts(&log).is_empty(),
            "{mode:o}: refused before the prompt"
        );
        assert!(
            !d.path().join("acme-platform.yaml.minisig").exists(),
            "{mode:o}"
        );
    }
}

#[cfg(unix)]
#[test]
fn sign_accepts_a_key_that_is_0400_or_0600() {
    for mode in [0o400, 0o600] {
        let d = dir();
        let args = setup(d.path(), GOOD_SPEC);
        set_mode(&args.secret_key, mode);
        run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0)
            .0
            .unwrap_or_else(|e| panic!("{mode:o}: {e}"));
    }
}

#[cfg(unix)]
#[test]
fn sign_refuses_a_key_that_is_a_symlink_or_not_a_file() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let link = d.path().join("link.key");
    std::os::unix::fs::symlink(&args.secret_key, &link).expect("symlink");
    for key in [link, d.path().to_path_buf()] {
        let mut args = args.clone_with_key(&key);
        args.force = false;
        let (result, _) = run_sign(
            &args,
            &mut must_not_be_called,
            &mut Scripted::no_terminal().0,
        );
        let (code, err) = rendered(result);
        assert_eq!(code, 64);
        assert!(err.contains("\nfix: "), "{err}");
    }
}

impl SignArgs {
    fn clone_with_key(&self, key: &Path) -> Self {
        Self {
            spec: self.spec.clone(),
            secret_key: key.to_path_buf(),
            sig: self.sig.clone(),
            force: self.force,
            password_file: self.password_file.clone(),
        }
    }
}

#[test]
fn sign_refuses_a_file_that_is_not_a_secret_key_and_names_keygen() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let not_a_key = d.path().join("notes.key");
    std::fs::write(&not_a_key, "hello\nworld\n").expect("write");
    #[cfg(unix)]
    set_mode(&not_a_key, 0o600);
    let args = args.clone_with_key(&not_a_key);
    let (result, _) = run_sign(
        &args,
        &mut must_not_be_called,
        &mut Scripted::no_terminal().0,
    );
    let (code, err) = rendered(result);
    assert_eq!(code, 64);
    assert!(err.contains("rdy spec keygen"), "{err}");
    assert!(
        !err.contains("world"),
        "file contents are not echoed: {err}"
    );
}

#[test]
fn sign_refuses_a_key_file_that_asks_for_too_much_memory() {
    let d = dir();
    let args = setup(d.path(), GOOD_SPEC);
    let text = std::fs::read_to_string(&args.secret_key).expect("key");
    let line = text.lines().nth(1).expect("line");
    let mut raw = Base64::decode_to_vec(line, None).expect("base64");
    // The memlimit field of the record.
    raw[46..54].copy_from_slice(&u64::MAX.to_le_bytes());
    let bad = format!(
        "untrusted comment: x\n{}\n",
        Base64::encode_to_string(&raw).expect("encode")
    );
    std::fs::write(&args.secret_key, bad).expect("write");
    #[cfg(unix)]
    set_mode(&args.secret_key, 0o600);
    let (result, _) = run_sign(&args, &mut from_file_or_env, &mut Scripted::no_terminal().0);
    let (code, err) = rendered(result);
    assert_eq!(code, 64);
    assert!(err.contains("more memory or time"), "{err}");
}

#[test]
fn control_characters_in_a_path_cannot_act_on_the_terminal() {
    let d = dir();
    let spec = write_spec(d.path(), GOOD_SPEC);
    let args = sign_args(&spec, &d.path().join("missing\u{1b}[2J.key"));
    let (result, shown) = run_sign(
        &args,
        &mut must_not_be_called,
        &mut Scripted::no_terminal().0,
    );
    let (_, err) = rendered(result);
    assert!(
        !err.contains('\u{1b}') && !shown.contains('\u{1b}'),
        "{err:?}"
    );
    assert!(err.contains("\\x1b"), "{err:?}");
}

// ---- helpers -------------------------------------------------------------------------------

#[test]
fn the_suggested_public_key_name_follows_the_key_name() {
    assert_eq!(
        suggested_pub_path(Path::new("acme-signing.key")),
        "acme-signing.pub"
    );
    assert_eq!(suggested_pub_path(Path::new("keys/a.key")), "keys/a.pub");
    assert_eq!(suggested_pub_path(Path::new("secret")), "secret.pub");
}

#[test]
fn a_fingerprint_is_cut_into_two_lines_of_eight_groups() {
    let fingerprint = "4d2a7c0e9b1f3a5c6e8d0b2f4a6c8e0d1b3f5a7c9e2d4b6f8a0c2e4d6b8f0a1c";
    let (first, second) = fingerprint_lines(fingerprint);
    assert_eq!(first, "4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d");
    assert_eq!(second, "1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c");
}
