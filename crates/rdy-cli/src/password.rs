//! Key passwords for `rdy spec sign` and `rdy spec keygen` (M1-112).
//!
//! A password never goes on the command line. `/proc/<pid>/cmdline` is world-readable on Linux and
//! shell history keeps what you type (07 section 10). This module does two things:
//!
//! 1. It refuses `--password` on argv with exit 64, without echoing what followed it
//!    ([`argv_has_password_flag`] and [`refuse_argv_password`]).
//! 2. It reads a key password from `--password-file <file>` (`-` is standard input) or from the
//!    `RDY_KEY_PASSWORD` variable ([`read_key_password`]). The result is `None` when neither is
//!    given, and the caller then asks at the prompt (M1-123).
//!
//! The flag beats the variable when both are set. A password file must be a regular file, not a
//! symlink, and (on Unix) not readable by group or others. Windows has no mode bits, so only the
//! symlink and file-type rules apply there; ACL checks are not done. One trailing line ending is
//! removed. Any other newline is an error. The password may be at most [`MAX_PASSWORD_BYTES`]
//! bytes.
//!
//! The password is held in a [`KeyPassword`], which wipes its memory on drop and prints as
//! `KeyPassword(..)`. The process environment itself is not wiped, and a pipe or a file the user
//! made is theirs to protect.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::EXIT_USAGE;

/// The variable that holds the key password in CI. Never put the password on argv.
pub const ENV_NAME: &str = "RDY_KEY_PASSWORD";

/// The longest password rdy reads, in bytes, not counting the line ending.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The most bytes read from a file or from standard input: the password and a `\r\n`.
const MAX_INPUT_BYTES: usize = MAX_PASSWORD_BYTES + 2;

/// The error line and fix line for `--password` on argv (07 section 6, C.6 style).
const ARGV_ERROR: &str = "passwords on the command line show up in shell history and in ps";
const ARGV_FIX: &str = "use --password-file, the RDY_KEY_PASSWORD variable, or the prompt";

/// A key password. It is wiped from memory when it is dropped.
///
/// There is no `Clone`, no `Display` and no `PartialEq`. `Debug` hides the text.
pub struct KeyPassword(Zeroizing<String>);

impl KeyPassword {
    /// Wrap a password that is already in memory, such as one typed at the prompt.
    #[must_use]
    pub fn new(password: String) -> Self {
        Self(Zeroizing::new(password))
    }

    /// The password text. Do not log it, print it or put it in an error.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyPassword(..)")
    }
}

/// Where a password came from. Used in error messages. It never holds the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The `RDY_KEY_PASSWORD` variable.
    Env,
    /// A file named by `--password-file`.
    File(PathBuf),
    /// Standard input, from `--password-file -`.
    Stdin,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => f.write_str(ENV_NAME),
            // Debug quoting escapes control and bidirectional characters in the typed path.
            Self::File(path) => write!(f, "the password file {path:?}"),
            Self::Stdin => f.write_str("standard input"),
        }
    }
}

/// Why a key password could not be read. Every case is exit 64 and has a fix hint.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// The source exists but holds no password.
    #[error("{0} is empty")]
    Empty(Origin),
    /// The source is longer than [`MAX_PASSWORD_BYTES`].
    #[error("{0} is longer than the {MAX_PASSWORD_BYTES} bytes a key password may have")]
    TooLarge(Origin),
    /// The source has a newline in the middle of the password.
    #[error("{0} has more than one line")]
    MultipleLines(Origin),
    /// The source is not valid UTF-8.
    #[error("{0} is not valid UTF-8 text")]
    NotUtf8(Origin),
    /// The source could not be opened or read. The OS error is kept for `source()`, not shown.
    #[error("cannot read {origin}")]
    Unreadable {
        /// What was being read.
        origin: Origin,
        /// The OS error. It never holds the password.
        #[source]
        source: std::io::Error,
    },
    /// The password file is a symlink.
    #[error("{0:?} is a symlink")]
    Symlink(PathBuf),
    /// The password file is not a regular file.
    #[error("{0:?} is not a regular file")]
    NotRegular(PathBuf),
    /// The path was replaced between the check and the open.
    #[error("{0:?} changed while rdy was opening it")]
    Changed(PathBuf),
    /// Group or others can read the password file (Unix).
    #[error("{0:?} can be read by other users")]
    TooOpen(PathBuf),
}

impl PasswordError {
    /// The one thing to do about it, for the `fix:` line.
    #[must_use]
    pub fn fix(&self) -> String {
        match self {
            Self::Empty(Origin::Env) => {
                format!("set {ENV_NAME} to the key password, or unset it to use the prompt")
            }
            Self::Empty(_) => "put the key password on the first line, or use the prompt".into(),
            Self::TooLarge(_) => format!("use a password of {MAX_PASSWORD_BYTES} bytes or fewer"),
            Self::MultipleLines(_) => "put only the key password in it, on one line".into(),
            Self::NotUtf8(_) => "use a password made of UTF-8 text".into(),
            Self::Unreadable {
                origin: Origin::Stdin,
                ..
            } => "pipe the password into rdy, or use the prompt".into(),
            Self::Unreadable { .. } => {
                "check the file name and that you can read it, or use the prompt".into()
            }
            Self::Symlink(path) => format!("give the real file, not a link to it: {path:?}"),
            Self::NotRegular(_) => "use a plain file, or '-' for standard input".into(),
            Self::Changed(_) => {
                "run the command again, and do not change the file meanwhile".into()
            }
            Self::TooOpen(path) => format!("make it private with: chmod 600 {path:?}"),
        }
    }
}

/// Print `error:` and `fix:` for a password error and return the exit code (64).
///
/// A write failure on `stderr` is ignored: the exit code still says what happened.
pub fn report_error(err: &PasswordError, stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(stderr, "error: {err}\nfix: {}", err.fix());
    EXIT_USAGE
}

/// True when `--password` or `--password=...` is on the command line before any `--`.
///
/// The check is on raw bytes, so a value that is not UTF-8 cannot hide the flag. The first item of
/// `args` is the program name and is skipped.
#[must_use]
pub fn argv_has_password_flag(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .map(OsString::as_os_str)
        .take_while(|a| *a != OsStr::new("--"))
        .any(is_password_flag)
}

fn is_password_flag(arg: &OsStr) -> bool {
    arg.as_encoded_bytes()
        .strip_prefix(b"--password")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"="))
}

/// Refuse `--password` on argv. Prints the two lines and returns 64.
///
/// What follows the flag is never read into the message. It is fixed text.
pub fn refuse_argv_password(stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(stderr, "error: {ARGV_ERROR}\nfix: {ARGV_FIX}");
    EXIT_USAGE
}

/// Read the key password from the file or the variable, or `None` when neither is given.
///
/// `file` is the value of `--password-file`; `-` means standard input. The file wins over the
/// variable. Standard input is read only when `file` is `-`.
///
/// # Errors
///
/// A [`PasswordError`] when the source is empty, too large, has more than one line, is not UTF-8,
/// cannot be read, or (a file) is a symlink, is not a regular file or is open to other users.
pub fn read_key_password(file: Option<&Path>) -> Result<Option<KeyPassword>, PasswordError> {
    let env = std::env::var_os(ENV_NAME);
    read_key_password_from(file, env, &mut std::io::stdin().lock())
}

/// The testable core of [`read_key_password`]: the variable's value and standard input are passed
/// in.
///
/// # Errors
///
/// The same as [`read_key_password`].
pub fn read_key_password_from(
    file: Option<&Path>,
    env: Option<OsString>,
    stdin: &mut dyn Read,
) -> Result<Option<KeyPassword>, PasswordError> {
    if let Some(path) = file {
        let (origin, raw) = if path == Path::new("-") {
            let raw = read_capped(stdin).map_err(|e| e.into_error(Origin::Stdin))?;
            (Origin::Stdin, raw)
        } else {
            let raw = read_file(path)?;
            (Origin::File(path.to_path_buf()), raw)
        };
        return finish(raw, &origin).map(Some);
    }
    match env {
        Some(value) => {
            let raw = Zeroizing::new(value.into_encoded_bytes());
            if raw.len() > MAX_PASSWORD_BYTES {
                return Err(PasswordError::TooLarge(Origin::Env));
            }
            finish(raw, &Origin::Env).map(Some)
        }
        None => Ok(None),
    }
}

/// How a capped read failed, before the origin is known.
enum ReadFailure {
    TooLarge,
    Io(std::io::Error),
}

impl ReadFailure {
    fn into_error(self, origin: Origin) -> PasswordError {
        match self {
            Self::TooLarge => PasswordError::TooLarge(origin),
            Self::Io(source) => PasswordError::Unreadable { origin, source },
        }
    }
}

/// Read at most [`MAX_INPUT_BYTES`]. The buffer is sized up front so that it never reallocates,
/// which would leave an unwiped copy of the password behind.
fn read_capped(reader: &mut dyn Read) -> Result<Zeroizing<Vec<u8>>, ReadFailure> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_INPUT_BYTES + 1));
    let mut limited = reader.take(MAX_INPUT_BYTES as u64 + 1);
    limited.read_to_end(&mut buf).map_err(ReadFailure::Io)?;
    if buf.len() > MAX_INPUT_BYTES {
        return Err(ReadFailure::TooLarge);
    }
    Ok(buf)
}

/// Open a password file after the symlink, file type and mode checks, and read it.
fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    let origin = || Origin::File(path.to_path_buf());
    let unreadable = |source| PasswordError::Unreadable {
        origin: origin(),
        source,
    };

    let before = std::fs::symlink_metadata(path).map_err(unreadable)?;
    if before.file_type().is_symlink() {
        return Err(PasswordError::Symlink(path.to_path_buf()));
    }
    // A named pipe would block the open, so the type is checked before opening.
    if !before.is_file() {
        return Err(PasswordError::NotRegular(path.to_path_buf()));
    }
    let mut file = File::open(path).map_err(unreadable)?;
    let opened = file.metadata().map_err(unreadable)?;
    if !opened.is_file() {
        return Err(PasswordError::NotRegular(path.to_path_buf()));
    }
    check_private(path, &before, &opened)?;
    read_capped(&mut file).map_err(|e| e.into_error(origin()))
}

/// Unix: the opened file is the one that was checked, and group and others have no access.
#[cfg(unix)]
fn check_private(
    path: &Path,
    before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<(), PasswordError> {
    use std::os::unix::fs::MetadataExt;

    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(PasswordError::Changed(path.to_path_buf()));
    }
    if opened.mode() & 0o077 != 0 {
        return Err(PasswordError::TooOpen(path.to_path_buf()));
    }
    Ok(())
}

/// Other platforms have no mode bits. The symlink and file-type rules above still apply.
#[cfg(not(unix))]
fn check_private(
    _path: &Path,
    _before: &std::fs::Metadata,
    _opened: &std::fs::Metadata,
) -> Result<(), PasswordError> {
    Ok(())
}

/// Remove one trailing line ending, then check the text and wrap it.
fn finish(mut raw: Zeroizing<Vec<u8>>, origin: &Origin) -> Result<KeyPassword, PasswordError> {
    if raw.ends_with(b"\n") {
        raw.pop();
        if raw.ends_with(b"\r") {
            raw.pop();
        }
    }
    if raw.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLarge(origin.clone()));
    }
    if raw.is_empty() {
        return Err(PasswordError::Empty(origin.clone()));
    }
    if raw.contains(&b'\n') || raw.contains(&b'\r') {
        return Err(PasswordError::MultipleLines(origin.clone()));
    }
    // `from_utf8` takes the Vec without copying. On failure the bytes come back in the error and
    // are wiped when `Zeroizing` drops them.
    match String::from_utf8(std::mem::take(&mut *raw)) {
        Ok(text) => Ok(KeyPassword::new(text)),
        Err(err) => {
            drop(Zeroizing::new(err.into_bytes()));
            Err(PasswordError::NotUtf8(origin.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const SECRET: &str = "CANARY-correct horse battery staple";

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn from_stdin(input: &[u8]) -> Result<Option<KeyPassword>, PasswordError> {
        read_key_password_from(Some(Path::new("-")), None, &mut Cursor::new(input.to_vec()))
    }

    fn from_env(value: &str) -> Result<Option<KeyPassword>, PasswordError> {
        read_key_password_from(None, Some(value.into()), &mut std::io::empty())
    }

    fn text(result: Result<Option<KeyPassword>, PasswordError>) -> String {
        match result {
            Ok(Some(p)) => p.expose().to_string(),
            other => panic!("want a password, got {other:?}"),
        }
    }

    fn err(result: Result<Option<KeyPassword>, PasswordError>) -> PasswordError {
        match result {
            Err(e) => e,
            other => panic!("want an error, got {other:?}"),
        }
    }

    #[test]
    fn the_flag_is_found_in_every_form_and_only_before_double_dash() {
        for args in [
            &["rdy", "spec", "sign", "--password", "x"][..],
            &["rdy", "spec", "sign", "--password=x"],
            &["rdy", "spec", "sign", "--password="],
            &["rdy", "spec", "sign", "--password"],
        ] {
            assert!(argv_has_password_flag(&os(args)), "{args:?}");
        }
        for args in [
            &["rdy", "spec", "sign", "--password-file", "f"][..],
            &["rdy", "spec", "sign", "--passwords"],
            &["rdy", "spec", "sign", "--", "--password"],
        ] {
            assert!(!argv_has_password_flag(&os(args)), "{args:?}");
        }
        // The program name is not an argument.
        assert!(!argv_has_password_flag(&os(&["--password"])));
    }

    #[cfg(unix)]
    #[test]
    fn a_value_that_is_not_utf8_cannot_hide_the_flag() {
        use std::os::unix::ffi::OsStringExt;

        let mut arg = b"--password=".to_vec();
        arg.extend_from_slice(&[0xff, 0xfe]);
        let args = vec![OsString::from("rdy"), OsString::from_vec(arg)];
        assert!(argv_has_password_flag(&args));
    }

    #[test]
    fn the_refusal_text_is_fixed_and_exits_64() {
        let mut out = Vec::new();
        assert_eq!(refuse_argv_password(&mut out), 64);
        let out = String::from_utf8(out).unwrap_or_default();
        assert_eq!(
            out,
            "error: passwords on the command line show up in shell history and in ps\n\
             fix: use --password-file, the RDY_KEY_PASSWORD variable, or the prompt\n"
        );
    }

    #[test]
    fn nothing_is_read_when_no_source_is_given() {
        assert!(matches!(
            read_key_password_from(None, None, &mut std::io::empty()),
            Ok(None)
        ));
    }

    #[test]
    fn the_variable_is_read_as_is() {
        assert_eq!(text(from_env(SECRET)), SECRET);
        // Spaces are part of a password. Only a line ending is removed.
        assert_eq!(text(from_env("  pad  ")), "  pad  ");
        assert_eq!(text(from_env("with newline\n")), "with newline");
    }

    #[test]
    fn an_empty_variable_is_an_error_not_a_prompt() {
        let e = err(from_env(""));
        assert!(matches!(e, PasswordError::Empty(Origin::Env)));
        assert!(e.fix().contains(ENV_NAME));
    }

    #[test]
    fn a_long_variable_is_refused() {
        let e = err(from_env(&"x".repeat(MAX_PASSWORD_BYTES + 1)));
        assert!(matches!(e, PasswordError::TooLarge(Origin::Env)));
        assert_eq!(
            text(from_env(&"x".repeat(MAX_PASSWORD_BYTES))).len(),
            MAX_PASSWORD_BYTES
        );
    }

    #[test]
    fn standard_input_drops_one_line_ending_only() {
        assert_eq!(text(from_stdin(b"pw\n")), "pw");
        assert_eq!(text(from_stdin(b"pw\r\n")), "pw");
        assert_eq!(text(from_stdin(b"pw")), "pw");
        assert_eq!(text(from_stdin(b"pw \n")), "pw ");
        assert!(matches!(
            err(from_stdin(b"pw\n\n")),
            PasswordError::MultipleLines(Origin::Stdin)
        ));
        assert!(matches!(
            err(from_stdin(b"a\nb\n")),
            PasswordError::MultipleLines(_)
        ));
        assert!(matches!(
            err(from_stdin(b"a\rb")),
            PasswordError::MultipleLines(_)
        ));
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(
            err(from_stdin(b"")),
            PasswordError::Empty(Origin::Stdin)
        ));
        assert!(matches!(err(from_stdin(b"\n")), PasswordError::Empty(_)));
        assert!(matches!(err(from_stdin(b"\r\n")), PasswordError::Empty(_)));
    }

    #[test]
    fn input_that_is_not_utf8_is_refused_without_showing_it() {
        let e = err(from_stdin(b"pw\xff\xfe\n"));
        assert!(matches!(e, PasswordError::NotUtf8(Origin::Stdin)));
        assert!(!e.to_string().contains("pw"));
    }

    #[test]
    fn the_size_cap_is_exact_for_both_line_endings() {
        let max = "x".repeat(MAX_PASSWORD_BYTES);
        assert_eq!(text(from_stdin(max.as_bytes())).len(), MAX_PASSWORD_BYTES);
        assert_eq!(
            text(from_stdin(format!("{max}\n").as_bytes())).len(),
            MAX_PASSWORD_BYTES
        );
        assert_eq!(
            text(from_stdin(format!("{max}\r\n").as_bytes())).len(),
            MAX_PASSWORD_BYTES
        );
        let over = format!("{max}x");
        assert!(matches!(
            err(from_stdin(over.as_bytes())),
            PasswordError::TooLarge(_)
        ));
        assert!(matches!(
            err(from_stdin(format!("{over}\r\n").as_bytes())),
            PasswordError::TooLarge(_)
        ));
    }

    #[test]
    fn a_huge_stream_is_cut_off_at_the_cap() {
        /// Yields bytes forever. The test ends only if the reader stops asking.
        struct Endless;
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf.fill(b'x');
                Ok(buf.len())
            }
        }
        let e = err(read_key_password_from(
            Some(Path::new("-")),
            None,
            &mut Endless,
        ));
        assert!(matches!(e, PasswordError::TooLarge(Origin::Stdin)));
    }

    #[test]
    fn a_failing_stdin_is_unreadable() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        let e = err(read_key_password_from(
            Some(Path::new("-")),
            None,
            &mut Broken,
        ));
        assert!(matches!(
            e,
            PasswordError::Unreadable {
                origin: Origin::Stdin,
                ..
            }
        ));
    }

    #[test]
    fn the_file_beats_the_variable() {
        let got = read_key_password_from(
            Some(Path::new("-")),
            Some("from-env".into()),
            &mut Cursor::new(b"from-stdin\n".to_vec()),
        );
        assert_eq!(text(got), "from-stdin");
    }

    #[test]
    fn the_variable_is_used_when_there_is_no_file_and_stdin_is_not_touched() {
        struct Panics;
        impl Read for Panics {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("standard input must not be read");
            }
        }
        let got = read_key_password_from(None, Some("from-env".into()), &mut Panics);
        assert_eq!(text(got), "from-env");
    }

    #[test]
    fn debug_never_shows_the_password() {
        let p = KeyPassword::new(SECRET.to_string());
        assert_eq!(format!("{p:?}"), "KeyPassword(..)");
        assert_eq!(p.expose(), SECRET);
    }

    #[test]
    fn every_error_has_a_fix_and_none_shows_the_password() {
        let path = PathBuf::from("pw.txt");
        let all = [
            PasswordError::Empty(Origin::Env),
            PasswordError::Empty(Origin::Stdin),
            PasswordError::Empty(Origin::File(path.clone())),
            PasswordError::TooLarge(Origin::Env),
            PasswordError::MultipleLines(Origin::Stdin),
            PasswordError::NotUtf8(Origin::File(path.clone())),
            PasswordError::Unreadable {
                origin: Origin::Stdin,
                source: std::io::Error::other(SECRET),
            },
            PasswordError::Unreadable {
                origin: Origin::File(path.clone()),
                source: std::io::Error::other(SECRET),
            },
            PasswordError::Symlink(path.clone()),
            PasswordError::NotRegular(path.clone()),
            PasswordError::Changed(path.clone()),
            PasswordError::TooOpen(path),
        ];
        for e in &all {
            assert!(!e.fix().is_empty(), "{e}");
            let mut out = Vec::new();
            assert_eq!(report_error(e, &mut out), 64);
            let out = String::from_utf8(out).unwrap_or_default();
            assert!(out.starts_with("error: "), "{out:?}");
            assert!(out.contains("\nfix: "), "{out:?}");
            assert_eq!(out.lines().count(), 2, "{out:?}");
            assert!(!out.contains("CANARY"), "{out:?}");
            assert!(!out.contains("os error"), "{out:?}");
        }
    }

    #[test]
    fn a_typed_path_is_escaped_in_messages() {
        let e = PasswordError::Symlink(PathBuf::from("a\u{202e}b\nc"));
        let shown = format!("{e} {}", e.fix());
        assert!(
            !shown.contains('\u{202e}') && !shown.contains('\n'),
            "{shown:?}"
        );
        assert!(shown.contains("\\u{202e}"), "{shown:?}");
    }

    #[cfg(unix)]
    mod files {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};

        use super::*;

        fn write(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap_or_else(|e| panic!("write: {e}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .unwrap_or_else(|e| panic!("chmod: {e}"));
            path
        }

        fn dir() -> tempfile::TempDir {
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"))
        }

        fn read(path: &Path) -> Result<Option<KeyPassword>, PasswordError> {
            read_key_password_from(Some(path), None, &mut std::io::empty())
        }

        #[test]
        fn a_private_file_is_read_and_its_newline_dropped() {
            let d = dir();
            for mode in [0o600, 0o400] {
                let p = write(d.path(), "pw", format!("{SECRET}\n").as_bytes(), mode);
                assert_eq!(text(read(&p)), SECRET, "mode {mode:o}");
            }
        }

        #[test]
        fn a_file_open_to_group_or_others_is_refused_with_chmod() {
            let d = dir();
            for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o601] {
                let p = write(d.path(), "pw", SECRET.as_bytes(), mode);
                let e = err(read(&p));
                assert!(matches!(e, PasswordError::TooOpen(_)), "mode {mode:o}: {e}");
                assert!(e.fix().contains("chmod 600"), "{}", e.fix());
                assert!(!e.to_string().contains("CANARY"));
            }
        }

        #[test]
        fn a_symlink_is_refused_even_to_a_private_file() {
            let d = dir();
            let real = write(d.path(), "real", SECRET.as_bytes(), 0o600);
            let link = d.path().join("link");
            symlink(&real, &link).unwrap_or_else(|e| panic!("symlink: {e}"));
            assert!(matches!(err(read(&link)), PasswordError::Symlink(_)));
        }

        #[test]
        fn a_dangling_symlink_is_refused_as_a_symlink() {
            let d = dir();
            let link = d.path().join("link");
            symlink(d.path().join("nowhere"), &link).unwrap_or_else(|e| panic!("symlink: {e}"));
            assert!(matches!(err(read(&link)), PasswordError::Symlink(_)));
        }

        #[test]
        fn a_directory_is_not_a_password_file() {
            let d = dir();
            assert!(matches!(err(read(d.path())), PasswordError::NotRegular(_)));
        }

        #[test]
        fn a_missing_file_is_unreadable_with_a_fix() {
            let d = dir();
            let e = err(read(&d.path().join("missing")));
            assert!(matches!(
                e,
                PasswordError::Unreadable {
                    origin: Origin::File(_),
                    ..
                }
            ));
            assert!(!e.fix().is_empty());
            assert!(!e.to_string().contains("os error"));
        }

        #[test]
        fn a_file_with_no_read_permission_is_unreadable() {
            let d = dir();
            let p = write(d.path(), "pw", SECRET.as_bytes(), 0o000);
            // Root ignores mode bits. Only assert the refusal when the open really fails.
            if File::open(&p).is_ok() {
                return;
            }
            let e = err(read(&p));
            assert!(matches!(e, PasswordError::Unreadable { .. }), "{e}");
            assert!(!e.fix().is_empty());
        }

        #[test]
        fn a_file_over_the_cap_is_refused() {
            let d = dir();
            let big = vec![b'x'; MAX_PASSWORD_BYTES * 64];
            let p = write(d.path(), "big", &big, 0o600);
            assert!(matches!(
                err(read(&p)),
                PasswordError::TooLarge(Origin::File(_))
            ));
            let at_cap = write(
                d.path(),
                "cap",
                "x".repeat(MAX_PASSWORD_BYTES).as_bytes(),
                0o600,
            );
            assert_eq!(text(read(&at_cap)).len(), MAX_PASSWORD_BYTES);
            let over = write(
                d.path(),
                "over",
                "x".repeat(MAX_PASSWORD_BYTES + 1).as_bytes(),
                0o600,
            );
            assert!(matches!(err(read(&over)), PasswordError::TooLarge(_)));
        }

        #[test]
        fn empty_and_multi_line_files_are_refused() {
            let d = dir();
            let empty = write(d.path(), "empty", b"", 0o600);
            assert!(matches!(
                err(read(&empty)),
                PasswordError::Empty(Origin::File(_))
            ));
            let two = write(d.path(), "two", b"a\nb\n", 0o600);
            assert!(matches!(err(read(&two)), PasswordError::MultipleLines(_)));
        }

        #[test]
        fn a_file_named_dash_in_another_folder_is_a_file_not_stdin() {
            let d = dir();
            let p = write(d.path(), "-", b"from-file\n", 0o600);
            assert_eq!(text(read(&p)), "from-file");
        }
    }
}
