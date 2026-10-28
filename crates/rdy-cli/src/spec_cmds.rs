//! `rdy spec keygen` and `rdy spec sign` (M1-125, 01 section 4.5, 07 C.9).
//!
//! The commands are split in two so tests can drive them without a terminal or the process
//! environment:
//!
//! - [`run_keygen`] and [`run_sign`] read the key password from `--password-file` or
//!   `RDY_KEY_PASSWORD` ([`crate::password::read_key_password`]) and print errors the rdy way.
//! - [`keygen`] and [`sign`] do the work. They take the password source, a [`Prompter`], the clock
//!   value and the key derivation cost as arguments.
//!
//! All human output goes to stderr. These commands print nothing on stdout, with or without
//! `--json`; with `--json` a failure also puts an `ErrorOutput` on stdout.
//!
//! What a refusal looks like (07 section 5): exit 64 for anything the user can fix (a spec with
//! lint errors, a key readable by others, a signature file that exists, a wrong password), exit 70
//! when rdy cannot write its result.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rdy_spec::lint::CheckLint;
use rdy_spec::sig::{Policy, PublicKey, SignatureState, TrustSource, TrustStore};
use rdy_spec::{MAX_SPEC_BYTES, load, parse_unverified};

use crate::cli::{KeygenArgs, SignArgs};
use crate::error::{CliError, InternalKind, IoReason, emit, escape_untrusted, shell_word};
use crate::password::{KeyPassword, PasswordError, read_key_password};
use crate::prompt::{Prompter, Terminal};
use crate::signing::files::{self, FileError};
use crate::signing::key::{KdfCost, KeyError, MAX_KEY_FILE_BYTES, SecretKey, StoredKey};
use crate::signing::{sidecar, time};

/// Where a command gets a key password that was not typed: the file and the variable. Called at
/// most once, and only when a password is needed.
pub type PasswordSource<'a> =
    &'a mut dyn FnMut(&mut dyn Write) -> Result<Option<KeyPassword>, PasswordError>;

/// Runs `rdy spec keygen` on the real terminal and environment.
pub fn run_keygen(
    args: &KeygenArgs,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let file = args.password_file.clone();
    let mut source = move |err: &mut dyn Write| read_key_password(file.as_deref(), err);
    let mut prompter = Prompter::stdio();
    let result = keygen(args, &mut source, &mut prompter, KdfCost::STANDARD, stderr);
    finish(result, json, stdout, stderr)
}

/// Runs `rdy spec sign` on the real terminal, environment and clock.
pub fn run_sign(args: &SignArgs, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let file = args.password_file.clone();
    let mut source = move |err: &mut dyn Write| read_key_password(file.as_deref(), err);
    let mut prompter = Prompter::stdio();
    let result = time::timestamp(SystemTime::now())
        .map_err(|e| CliError::usage(e.to_string(), "set the clock, then run again"))
        .and_then(|signed_at| sign(args, &signed_at, &mut source, &mut prompter, &mut *stderr));
    finish(result, json, stdout, stderr)
}

/// Prints the error if there is one, and gives the exit code.
fn finish(
    result: Result<(), CliError>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match result {
        Ok(()) => crate::EXIT_OK,
        Err(err) => emit(&err, json, stdout, stderr),
    }
}

// ---------------------------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------------------------

/// Makes a key pair: `<name>.key` (secret) and `<name>.pub` (public).
///
/// Nothing is overwritten. The password comes from `password` (file or variable), else from two
/// prompts. With `--unencrypted` there is no password and `password` is never called.
///
/// # Errors
///
/// A [`CliError`]: exit 64 when a file exists, the name is unusable, or the password is missing,
/// empty or typed differently twice; exit 70 when a file cannot be written.
pub fn keygen<T: Terminal>(
    args: &KeygenArgs,
    password: PasswordSource<'_>,
    prompter: &mut Prompter<T>,
    cost: KdfCost,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let (key_path, pub_path) = key_paths(&args.name)?;
    // Refuse before asking for a password or doing the slow key derivation.
    for path in [&key_path, &pub_path] {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(already_exists(path));
        }
    }

    let password = if args.unencrypted {
        None
    } else {
        Some(new_password(password, prompter, out)?)
    };

    let key = SecretKey::generate().map_err(key_error_without_file)?;
    let key_text = key
        .key_file(password.as_ref().map(KeyPassword::expose), cost)
        .map_err(key_error_without_file)?;
    drop(password);
    let pub_text = key.public_key_file();

    let mut key_file = create(&key_path)?;
    let mut pub_file = match create_public(&pub_path) {
        Ok(file) => file,
        Err(err) => {
            drop(key_file);
            let _ = std::fs::remove_file(&key_path);
            return Err(err);
        }
    };
    let written = files::write_and_sync(&mut key_file, key_text.as_bytes())
        .map_err(|e| write_error(&key_path, &e))
        .and_then(|()| {
            files::write_and_sync(&mut pub_file, pub_text.as_bytes())
                .map_err(|e| write_error(&pub_path, &e))
        });
    drop((key_file, pub_file));
    if let Err(err) = written {
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&pub_path);
        return Err(err);
    }

    let public = PublicKey::from_base64(&key.public_key_base64()).map_err(|_| CliError::bug())?;
    report_keygen(out, &key_path, &pub_path, &public, args.unencrypted);
    Ok(())
}

/// `<name>.key` and `<name>.pub`.
fn key_paths(name: &str) -> Result<(PathBuf, PathBuf), CliError> {
    if name.is_empty() || name.ends_with(['/', '\\']) {
        return Err(CliError::usage(
            "the key name is empty or ends with a slash",
            "give a name like acme-signing",
        ));
    }
    Ok((
        PathBuf::from(format!("{name}.key")),
        PathBuf::from(format!("{name}.pub")),
    ))
}

fn already_exists(path: &Path) -> CliError {
    CliError::usage(
        format!("{} already exists", display(path)),
        "rdy never overwrites a key. Pick another name, or move the old key first.",
    )
}

/// The password for a new key: from the file or variable, else typed twice.
fn new_password<T: Terminal>(
    source: PasswordSource<'_>,
    prompter: &mut Prompter<T>,
    notices: &mut dyn Write,
) -> Result<KeyPassword, CliError> {
    if let Some(password) = source(notices)? {
        return Ok(password);
    }
    let fix = "use --password-file, set RDY_KEY_PASSWORD, or pass --unencrypted for CI";
    let first = prompter.password("Password for the new secret key (input hidden): ", fix)?;
    if first.is_empty() {
        return Err(CliError::usage(
            "the password is empty",
            "type a password, or pass --unencrypted for CI",
        ));
    }
    let second = prompter.password("Repeat the password: ", fix)?;
    if first.expose() != second.expose() {
        return Err(CliError::usage(
            "the passwords did not match",
            "run the command again and type the same password twice",
        ));
    }
    Ok(KeyPassword::new(first.expose().to_owned()))
}

fn create(path: &Path) -> Result<File, CliError> {
    files::create_new_private(path).map_err(|e| create_error(path, &e))
}

fn create_public(path: &Path) -> Result<File, CliError> {
    files::create_new_public(path).map_err(|e| create_error(path, &e))
}

fn create_error(path: &Path, err: &io::Error) -> CliError {
    if err.kind() == io::ErrorKind::AlreadyExists {
        already_exists(path)
    } else {
        write_error(path, err)
    }
}

fn write_error(path: &Path, err: &io::Error) -> CliError {
    CliError::Internal(InternalKind::FileWrite {
        path: path.display().to_string(),
        reason: IoReason::from_io(err),
    })
}

fn report_keygen(
    out: &mut dyn Write,
    key_path: &Path,
    pub_path: &Path,
    public: &PublicKey,
    unencrypted: bool,
) {
    let secret = if cfg!(unix) {
        "secret, readable only by you"
    } else {
        "secret"
    };
    if unencrypted {
        let _ = writeln!(
            out,
            "warning: {} is not protected by a password. Anyone who can read it can sign specs as you.",
            display(key_path)
        );
    }
    let _ = writeln!(
        out,
        "Wrote {} ({secret}) and {} (public).",
        display(key_path),
        display(pub_path)
    );
    if !cfg!(unix) {
        let _ = writeln!(
            out,
            "note: Windows gives a new file the access list of its folder. Keep the key in a folder only you can read."
        );
    }
    let _ = writeln!(out);
    let _ = write!(
        out,
        "{}",
        key_table(public, "key id       ", "fingerprint  ")
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Publish the fingerprint on your docs page so customers can check it."
    );
    let _ = writeln!(
        out,
        "Back up {}. Anyone who has it can sign specs as you.",
        display(key_path)
    );
    let _ = writeln!(
        out,
        "Next: rdy spec sign <spec> --secret-key {}",
        shell_word(&key_path.display().to_string())
    );
}

/// The key id and the fingerprint in groups of four, as in 07 C.9. The fingerprint takes two lines of
/// eight groups. `id_label` and `fp_label` are the same width, so the second line lines up.
fn key_table(public: &PublicKey, id_label: &str, fp_label: &str) -> String {
    let (first, second) = fingerprint_lines(&public.fingerprint());
    let pad = " ".repeat(fp_label.len());
    format!(
        "{id_label}{}\n{fp_label}{first}\n{pad}{second}\n",
        public.key_id()
    )
}

/// The 64 hex digits of a fingerprint as two lines of eight groups of four.
#[must_use]
pub fn fingerprint_lines(fingerprint: &str) -> (String, String) {
    let groups: Vec<&str> = fingerprint
        .as_bytes()
        .chunks(4)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect();
    let (a, b) = groups.split_at(groups.len().min(8));
    (a.join(" "), b.join(" "))
}

// ---------------------------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------------------------

/// Lints a spec, signs its exact bytes, checks the signature and writes `<spec>.minisig`.
///
/// `signed_at` is the stamp for the signed comment (`YYYY-MM-DDTHH:MM:SSZ`). The spec is read once.
/// The signature is checked with `rdy_spec::load` before anything is written, and the bytes that
/// were checked are the bytes that are written.
///
/// # Errors
///
/// A [`CliError`]: exit 64 for a spec that cannot be parsed or has lint errors, a key that others
/// can read, a wrong password, or a signature file that exists; exit 70 for a write failure or a
/// signature that does not check (a bug).
pub fn sign<T: Terminal>(
    args: &SignArgs,
    signed_at: &str,
    password: PasswordSource<'_>,
    prompter: &mut Prompter<T>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let spec_name = args.spec.display().to_string();
    let bytes = read_spec(&args.spec)?;

    // 1. Lint the buffer. Errors refuse. Warnings are printed and signing goes on.
    let spec =
        parse_unverified(&bytes).map_err(|source| CliError::spec(spec_name.clone(), source))?;
    let findings = spec.lint_checks();
    let errors = print_findings(out, &spec_name, &findings);
    if errors > 0 {
        let plural = if errors == 1 { "" } else { "s" };
        return Err(CliError::usage(
            format!(
                "not signed: {} has {errors} error{plural}",
                escape_untrusted(&spec_name)
            ),
            "correct the errors above and run rdy spec sign again",
        ));
    }

    // 2. The place for the signature. Refuse an existing file before asking for a password.
    let sig_path = args
        .sig
        .clone()
        .unwrap_or_else(|| default_sig_path(&args.spec));
    if same_file(&sig_path, &args.spec) || same_file(&sig_path, &args.secret_key) {
        return Err(CliError::usage(
            "the signature file would replace the spec or the key",
            "choose another file with --sig",
        ));
    }
    if !args.force && std::fs::symlink_metadata(&sig_path).is_ok() {
        return Err(CliError::usage(
            format!("{} already exists", display(&sig_path)),
            "use --force to replace it, or --sig to write the signature somewhere else",
        ));
    }

    // 3. The key. It must be private, and it is opened once.
    let key_name = display(&args.secret_key);
    let key = open_key(args, &key_name, password, prompter, out)?;

    // 4. Sign, then check the signature the way a customer's rdy will.
    let product = spec.metadata.product.clone();
    let text = sidecar::sign(&key, &product, signed_at, &bytes);
    let public = PublicKey::from_base64(&key.public_key_base64()).map_err(|_| CliError::bug())?;
    let mut trust = TrustStore::new();
    trust.pin(product.clone(), public.clone(), TrustSource::User);
    let loaded = load(&bytes, Some(text.as_bytes()), &trust, Policy::RequireSigned)
        .map_err(|_| CliError::bug())?;
    let verified = matches!(
        loaded.signature(),
        SignatureState::Verified { key_id, fingerprint, signed_at: at, .. }
            if *key_id == key.key_id() && *fingerprint == public.fingerprint() && at == signed_at
    );
    if !verified {
        return Err(CliError::bug());
    }

    // 5. Write it. Nothing is written before this point.
    write_sig(&sig_path, text.as_bytes(), args.force)?;

    report_sign(
        out,
        &Signed {
            spec_name: &spec_name,
            sig_path: &sig_path,
            key_path: &args.secret_key,
            sha256: loaded.sha256(),
            signed_at,
            product: product.as_ref(),
        },
        &public,
    );
    Ok(())
}

/// Reads the spec once, at most one byte over the cap, from a regular file.
fn read_spec(path: &Path) -> Result<Vec<u8>, CliError> {
    let name = path.display().to_string();
    let mut file = File::open(path).map_err(|e| CliError::spec_unreadable(name.clone(), &e))?;
    let meta = file
        .metadata()
        .map_err(|e| CliError::spec_unreadable(name.clone(), &e))?;
    if !meta.is_file() {
        let not_a_file = io::Error::from(io::ErrorKind::IsADirectory);
        return Err(CliError::spec_unreadable(name, &not_a_file));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_SPEC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CliError::spec_unreadable(name, &e))?;
    Ok(bytes)
}

/// Prints each finding as two lines and returns how many are errors.
///
/// Positions (line and column) come with `rdy spec lint` (M1-031). Until then a finding names its
/// check by id in the message.
fn print_findings(out: &mut dyn Write, file: &str, findings: &[CheckLint]) -> usize {
    let file = escape_untrusted(file);
    for finding in findings {
        let level = if finding.blocks_signing() {
            "error"
        } else {
            "warning"
        };
        let _ = writeln!(
            out,
            "{file}: {level}: {}\n  fix: {}",
            escape_untrusted(&finding.message),
            escape_untrusted(&finding.fix)
        );
    }
    findings.iter().filter(|f| f.blocks_signing()).count()
}

/// Reads the key file, refuses one that others can read, and opens it with the password.
fn open_key<T: Terminal>(
    args: &SignArgs,
    key_name: &str,
    password: PasswordSource<'_>,
    prompter: &mut Prompter<T>,
    notices: &mut dyn Write,
) -> Result<SecretKey, CliError> {
    let raw = files::read_private(&args.secret_key, MAX_KEY_FILE_BYTES)
        .map_err(|e| file_error(&args.secret_key, &e))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| key_error(key_name, KeyError::Malformed("it is not text")))?;
    let stored = StoredKey::parse(text).map_err(|e| key_error(key_name, e))?;
    let typed = if stored.is_encrypted() {
        match password(notices)? {
            Some(password) => Some(password),
            None => {
                let fix = "use --password-file, or set RDY_KEY_PASSWORD";
                let secret = prompter.password(
                    &format!(
                        "Password for {} (input hidden): ",
                        escape_untrusted(key_name)
                    ),
                    fix,
                )?;
                Some(KeyPassword::new(secret.expose().to_owned()))
            }
        }
    } else {
        None
    };
    stored
        .unlock(typed.as_ref().map(KeyPassword::expose))
        .map_err(|e| key_error(key_name, e))
}

fn file_error(path: &Path, err: &FileError) -> CliError {
    let name = display(path);
    let fix = match err {
        FileError::TooOpen => format!(
            "make it private with: chmod 600 {}",
            shell_word(&path.display().to_string())
        ),
        FileError::NotOwned => "use a key that you own".to_owned(),
        FileError::Symlink | FileError::NotRegular => {
            "give the key file itself, not a link or a folder".to_owned()
        }
        FileError::TooLarge => "give a secret key made with 'rdy spec keygen'".to_owned(),
        _ => "check the file name and that you can read it".to_owned(),
    };
    CliError::usage(format!("{name}: {err}"), fix)
}

fn key_error(key_name: &str, err: KeyError) -> CliError {
    let name = escape_untrusted(key_name);
    let new_key = "make a key with: rdy spec keygen <name>";
    match err {
        KeyError::WrongPassword => CliError::usage(
            format!("the password for {name} is wrong"),
            "type the password again, or check the file you gave to --password-file",
        ),
        KeyError::NeedsPassword => CliError::usage(
            format!("{name} needs a password"),
            "use --password-file, or set RDY_KEY_PASSWORD",
        ),
        KeyError::Damaged => CliError::usage(
            format!("{name} is damaged"),
            "restore the key from your backup",
        ),
        KeyError::Random => CliError::bug(),
        other => CliError::usage(format!("cannot use {name}: {other}"), new_key),
    }
}

fn key_error_without_file(err: KeyError) -> CliError {
    match err {
        KeyError::Random => CliError::bug(),
        other => CliError::usage(
            format!("cannot make the key: {other}"),
            "run the command again",
        ),
    }
}

/// `<spec>.minisig`.
fn default_sig_path(spec: &Path) -> PathBuf {
    let mut name = OsString::from(spec.as_os_str());
    name.push(".minisig");
    PathBuf::from(name)
}

/// True when two paths are the same file, by name or by where they resolve to.
fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

/// Writes the signature file. Without `force` it must not exist. With `force` it is replaced
/// whole: written to a new file next to it, then renamed over it, so a symlink at the path is
/// replaced and never written through.
fn write_sig(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    if !force {
        let mut file = files::create_new_public(path).map_err(|e| create_error(path, &e))?;
        let written = files::write_and_sync(&mut file, bytes);
        drop(file);
        return written.map_err(|e| {
            let _ = std::fs::remove_file(path);
            write_error(path, &e)
        });
    }
    let mut suffix = [0u8; 6];
    getrandom::fill(&mut suffix).map_err(|_| CliError::bug())?;
    let mut tmp_name = OsString::from(path.as_os_str());
    tmp_name.push(format!(".tmp{}", hex(&suffix)));
    let tmp = PathBuf::from(tmp_name);
    let mut file = files::create_new_public(&tmp).map_err(|e| write_error(path, &e))?;
    let written = files::write_and_sync(&mut file, bytes);
    drop(file);
    let result = written.and_then(|()| std::fs::rename(&tmp, path));
    if let Err(err) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(write_error(path, &err));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// What `rdy spec sign` tells the vendor when it is done.
struct Signed<'a> {
    spec_name: &'a str,
    sig_path: &'a Path,
    key_path: &'a Path,
    sha256: &'a str,
    signed_at: &'a str,
    product: &'a str,
}

fn report_sign(out: &mut dyn Write, done: &Signed<'_>, public: &PublicKey) {
    let Signed {
        spec_name,
        sig_path,
        key_path,
        sha256,
        signed_at,
        product,
    } = *done;
    let (first, second) = fingerprint_lines(&public.fingerprint());
    let _ = writeln!(out, "Signed {}", escape_untrusted(spec_name));
    let _ = writeln!(out, "  signature    {}", display(sig_path));
    let _ = writeln!(out, "  sha256       {sha256}");
    let _ = writeln!(out, "  signing key  {}", public.key_id());
    let _ = writeln!(out, "  fingerprint  {first}");
    let _ = writeln!(out, "               {second}");
    let _ = writeln!(out, "  signed on    {signed_at}");
    let _ = writeln!(out, "Checked the new signature: it verifies.");
    let _ = writeln!(out);
    let pub_name = shell_word(&suggested_pub_path(key_path));
    let _ = writeln!(
        out,
        "Send your customer the spec, the .minisig file, {pub_name}, and this line:"
    );
    let _ = writeln!(out, "  rdy trust add {product} --key {pub_name}");
    let _ = writeln!(out, "The fingerprint is {}.", public.fingerprint());
    let _ = writeln!(
        out,
        "Tell them to compare it with your docs page before they say yes."
    );
}

/// The public key file that `rdy spec keygen` made next to `key`: `acme-signing.key` to
/// `acme-signing.pub`.
fn suggested_pub_path(key: &Path) -> String {
    let text = key.display().to_string();
    let stem = text.strip_suffix(".key").unwrap_or(&text);
    format!("{stem}.pub")
}

/// A path as the user gave it, safe to print.
fn display(path: &Path) -> String {
    escape_untrusted(&path.display().to_string())
}

#[cfg(test)]
mod tests;
