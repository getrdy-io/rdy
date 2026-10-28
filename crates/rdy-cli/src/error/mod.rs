//! Errors at the edge of the CLI (ADR 0008, 07 sections 4.1 and 9).
//!
//! Every library error ends up as a [`CliError`]. A `CliError` has four things, and none is optional:
//!
//! - a stable [`ErrorCode`] from the closed list of ADR 0008 decision 7,
//! - a message that names the thing,
//! - a fix hint, one action in the imperative,
//! - an exit code: 64 when the input must change, 70 when rdy cannot deliver its result.
//!
//! [`emit`] prints it: two lines on stderr (`error:` and `fix:`), and with `--json` one
//! [`ErrorOutput`] on stdout. Both come from the same [`Rendered`] value, so they never differ.
//!
//! Every string is escaped by [`escape_untrusted`] when it is rendered. A spec is untrusted, and its
//! text reaches the terminal in messages, so control characters and bidirectional controls are shown as
//! `\x1b` and `\u{202e}` and never act on the terminal. The library crates already escape what they
//! echo. This is the second layer, at the point of printing.
//!
//! The run exit codes 0, 1 and 2 come from the verdict ([`rdy_spec::result::Verdict::exit_code`]) and
//! are not errors. [`ErrorCode::exit_code`] gives 64 or 70 as an [`rdy_spec::result::ExitCode`].
//!
//! `anyhow` appears once, in [`CliError::from_anyhow`]: command code may return `anyhow::Result` with
//! `.context(..)`, and the binary edge downcasts to pick the code (ADR 0008 decision 5).

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};

use rdy_spec::result::{ExitCode, Verdict};
use rdy_spec::sig::SignatureError;
use rdy_spec::{ScalarError, SpecError};
use serde::Serialize;

use crate::password::PasswordError;
use crate::prompt::{Cancel, PromptError};

mod skip;
mod text;

pub use skip::{SkipText, SkipWhy, timeout_text};
pub use text::{did_you_mean, echo, escape_untrusted, shell_word};

/// The fix line for a bug in rdy (ADR 0008 decision 5, 07 section 9 rule 6).
pub const BUG_HINT: &str = "this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues and include the output of rdy version.";

/// A stable error code. The list is closed for `rdy/v1` and part of the JSON promise (ADR 0007, 0008).
///
/// A new code is an additive change and needs a line in ADR 0008. Scripts may branch on [`as_str`].
///
/// [`as_str`]: ErrorCode::as_str
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A bad flag, value or argument. Exit 64.
    Usage,
    /// The spec file is missing, is not a regular file or cannot be read. Exit 64.
    SpecUnreadable,
    /// The spec is not valid YAML or breaks a limit. Exit 64.
    SpecParse,
    /// The spec is valid YAML but not a valid spec. Exit 64.
    SpecInvalid,
    /// The spec has no signature. Exit 64.
    SpecUnsigned,
    /// The signature does not verify. Exit 64.
    SpecSignatureInvalid,
    /// The signing key is not pinned. Exit 64.
    SpecKeyUnknown,
    /// The spec's `expires` has passed. Exit 64.
    SpecExpired,
    /// The trust store can be changed by other users. Exit 64.
    TrustStoreInsecure,
    /// The report folder or the report files could not be written. Exit 70.
    ReportWrite,
    /// The run was interrupted. Exit 70.
    Interrupted,
    /// A bug or a runtime failure. Exit 70.
    Internal,
}

impl ErrorCode {
    /// Every code, in the order of ADR 0008 decision 7.
    pub const ALL: [ErrorCode; 12] = [
        Self::Usage,
        Self::SpecUnreadable,
        Self::SpecParse,
        Self::SpecInvalid,
        Self::SpecUnsigned,
        Self::SpecSignatureInvalid,
        Self::SpecKeyUnknown,
        Self::SpecExpired,
        Self::TrustStoreInsecure,
        Self::ReportWrite,
        Self::Interrupted,
        Self::Internal,
    ];

    /// The wire text, such as `spec_parse`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::SpecUnreadable => "spec_unreadable",
            Self::SpecParse => "spec_parse",
            Self::SpecInvalid => "spec_invalid",
            Self::SpecUnsigned => "spec_unsigned",
            Self::SpecSignatureInvalid => "spec_signature_invalid",
            Self::SpecKeyUnknown => "spec_key_unknown",
            Self::SpecExpired => "spec_expired",
            Self::TrustStoreInsecure => "trust_store_insecure",
            Self::ReportWrite => "report_write",
            Self::Interrupted => "interrupted",
            Self::Internal => "internal",
        }
    }

    /// The process exit code: 64 when the input must change, 70 when rdy cannot deliver its result
    /// (07 section 5).
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::Usage
            | Self::SpecUnreadable
            | Self::SpecParse
            | Self::SpecInvalid
            | Self::SpecUnsigned
            | Self::SpecSignatureInvalid
            | Self::SpecKeyUnknown
            | Self::SpecExpired
            | Self::TrustStoreInsecure => ExitCode::Usage,
            Self::ReportWrite | Self::Interrupted | Self::Internal => ExitCode::Internal,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What went wrong with a file, in plain words. Never an OS error number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoReason {
    /// The file or folder does not exist.
    NoSuchFile,
    /// The OS refused access.
    PermissionDenied,
    /// The path is a folder or a device, not a regular file.
    NotAFile,
    /// The disk is full.
    DiskFull,
    /// Anything else.
    Other,
}

impl IoReason {
    /// The plain-words reason for an I/O error.
    #[must_use]
    pub fn from_io(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NoSuchFile,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::IsADirectory | io::ErrorKind::NotADirectory => Self::NotAFile,
            io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => Self::DiskFull,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for IoReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoSuchFile => "no such file",
            Self::PermissionDenied => "permission denied",
            Self::NotAFile => "not a regular file",
            Self::DiskFull => "the disk is full",
            Self::Other => "an unexpected error",
        })
    }
}

/// What rdy was writing when [`CliError::ReportWrite`] happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportStep {
    /// Making the report folder, before the first check (ADR 0016).
    CreateFolder,
    /// Writing the report files at the end of the run, or for `rdy report` and `rdy bundle`.
    WriteFiles,
}

/// A failure inside rdy that is not the user's input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalKind {
    /// A bug. Nothing more is said, because the cause may hold text that must not be printed.
    Bug,
    /// stdout could not be written.
    OutputClosed,
    /// The command exists in the tree but a later ticket builds it.
    NotImplemented {
        /// The command as typed in the tree, such as `spec lint`. Always a name from the command tree.
        command: &'static str,
    },
}

/// Every failure that ends a command with exit 64 or 70 and no verdict.
///
/// Where the honest fix is "this is a bug", the hint says so ([`BUG_HINT`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// A bad flag, value or argument.
    #[error("{message}")]
    Usage {
        /// What is wrong, without anything the user typed after the flag name.
        message: String,
        /// What to do.
        fix: String,
    },
    /// The spec file cannot be read.
    #[error("cannot read {path}: {reason}")]
    SpecUnreadable {
        /// The spec path as typed.
        path: String,
        /// Why, in plain words.
        reason: IoReason,
    },
    /// A spec error from `rdy-spec`.
    #[error("{source}")]
    Spec {
        /// The spec path as typed, when known.
        file: Option<String>,
        /// The error.
        source: SpecError,
    },
    /// A scalar error from `rdy-spec`, such as a bad size or duration.
    #[error("{source}")]
    Scalar {
        /// The spec path as typed, when known.
        file: Option<String>,
        /// The error.
        source: ScalarError,
    },
    /// A key password could not be read.
    #[error("{0}")]
    Password(#[from] PasswordError),
    /// A prompt could not be shown or answered.
    #[error("{0}")]
    Prompt(#[from] PromptError),
    /// The report folder or the report files could not be written.
    #[error("{}", report_write_message(*step, path, *reason))]
    ReportWrite {
        /// What rdy was doing.
        step: ReportStep,
        /// The folder or file as rdy names it.
        path: String,
        /// Why, in plain words.
        reason: IoReason,
    },
    /// Ctrl-C in M1 (07 section 5.1).
    #[error("interrupted. No report was written.")]
    Interrupted,
    /// A bug or a runtime failure.
    #[error("{}", internal_message(.0))]
    Internal(InternalKind),
}

fn report_write_message(step: ReportStep, path: &str, reason: IoReason) -> String {
    match step {
        ReportStep::CreateFolder => {
            format!("cannot create the report folder {path} ({reason})")
        }
        ReportStep::WriteFiles => format!("cannot write the report files to {path} ({reason})"),
    }
}

fn internal_message(kind: &InternalKind) -> String {
    match kind {
        InternalKind::Bug => "rdy hit an internal error".to_owned(),
        InternalKind::OutputClosed => "rdy could not write its output".to_owned(),
        InternalKind::NotImplemented { command } => {
            format!("rdy {command} is not yet implemented in this build")
        }
    }
}

impl CliError {
    /// A usage error with fixed text.
    #[must_use]
    pub fn usage(message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::Usage {
            message: message.into(),
            fix: fix.into(),
        }
    }

    /// The spec file at `path` could not be read.
    #[must_use]
    pub fn spec_unreadable(path: impl Into<String>, err: &io::Error) -> Self {
        Self::SpecUnreadable {
            path: path.into(),
            reason: IoReason::from_io(err),
        }
    }

    /// A spec error found in the file at `file`.
    #[must_use]
    pub fn spec(file: impl Into<String>, source: SpecError) -> Self {
        Self::Spec {
            file: Some(file.into()),
            source,
        }
    }

    /// A bug, with the standard hint.
    #[must_use]
    pub fn bug() -> Self {
        Self::Internal(InternalKind::Bug)
    }

    /// Picks the error out of an `anyhow::Error` (ADR 0008 decision 5).
    ///
    /// Looks through `.context(..)` layers for a [`CliError`], a [`PasswordError`], a [`PromptError`], a
    /// [`SpecError`] or a [`ScalarError`]. Anything else is a bug. The text of an unknown error is dropped
    /// on purpose: it may hold a path, a URL or a secret, and the M1 redactor has only the key-name rule
    /// until M1-060 adds URL userinfo, headers and token shapes. Every string that [`CliError::render`]
    /// prints does go through the redactor (M1-056), so showing the redacted chain later is a change in
    /// this one function.
    #[must_use]
    pub fn from_anyhow(err: anyhow::Error) -> Self {
        let err = match err.downcast::<Self>() {
            Ok(found) => return found,
            Err(err) => err,
        };
        let err = match err.downcast::<PasswordError>() {
            Ok(found) => return Self::Password(found),
            Err(err) => err,
        };
        let err = match err.downcast::<PromptError>() {
            Ok(found) => return Self::Prompt(found),
            Err(err) => err,
        };
        let err = match err.downcast::<SpecError>() {
            Ok(source) => return Self::Spec { file: None, source },
            Err(err) => err,
        };
        match err.downcast::<ScalarError>() {
            Ok(source) => Self::Scalar { file: None, source },
            Err(_) => Self::bug(),
        }
    }

    /// The stable code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Usage { .. } | Self::Password(_) => ErrorCode::Usage,
            Self::SpecUnreadable { .. } => ErrorCode::SpecUnreadable,
            Self::Spec { source, .. } => spec_error_code(source),
            Self::Scalar { .. } => ErrorCode::SpecInvalid,
            Self::Prompt(err) => prompt_code(err),
            Self::ReportWrite { .. } => ErrorCode::ReportWrite,
            Self::Interrupted => ErrorCode::Interrupted,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }

    /// The process exit code: 64 or 70.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        self.code().exit_code()
    }

    /// The fix hint. Never empty. It is not escaped: use [`CliError::render`] for output.
    #[must_use]
    pub fn hint(&self) -> String {
        match self {
            Self::Usage { fix, .. } => fix.clone(),
            Self::SpecUnreadable { reason, .. } => match reason {
                IoReason::NoSuchFile => "check the file name and the folder you are in",
                IoReason::PermissionDenied => {
                    "check who owns the file and that you are allowed to read it"
                }
                IoReason::NotAFile => "give the path of a spec file, not a folder or a device",
                IoReason::DiskFull | IoReason::Other => {
                    "check that the disk the file is on is still connected, then run again"
                }
            }
            .to_owned(),
            Self::Spec { source, .. } => source.fix(),
            Self::Scalar { source, .. } => source.hint().to_owned(),
            Self::Password(err) => err.fix(),
            Self::Prompt(err) => err.fix().to_owned(),
            Self::ReportWrite { step, .. } => match step {
                ReportStep::CreateFolder => {
                    "use --out-dir <a folder you can write to>, or --no-report to skip the files"
                }
                ReportStep::WriteFiles => {
                    "make room or use --out-dir <a folder you can write to>, then run again"
                }
            }
            .to_owned(),
            Self::Interrupted => "run rdy again and let it finish".to_owned(),
            Self::Internal(InternalKind::Bug) => BUG_HINT.to_owned(),
            Self::Internal(InternalKind::OutputClosed) => {
                "check that the output is not closed or full".to_owned()
            }
            Self::Internal(InternalKind::NotImplemented { .. }) => {
                "use a later release of rdy, listed at https://github.com/getrdy-io/rdy/releases"
                    .to_owned()
            }
        }
    }

    /// Everything a printer needs, with every string escaped.
    #[must_use]
    pub fn render(&self) -> Rendered {
        match self {
            Self::Password(err) => return render_password(err),
            Self::Prompt(err) => return render_prompt(err),
            _ => {}
        }
        let (file, location) = match self {
            Self::Spec { file, source } => (file.as_deref(), source.location()),
            Self::Scalar { file, .. } => (file.as_deref(), None),
            _ => (None, None),
        };
        Rendered {
            code: self.code(),
            message: clean(&self.to_string()),
            fix: clean(&self.hint()),
            file: file.map(clean),
            line: location.map(|at| at.line),
            column: location.map(|at| at.column),
        }
    }
}

/// The text as it is printed: control characters escaped, then secrets removed (ADR 0015 decision 6).
///
/// Redaction runs on the escaped text, which is what reaches the terminal and the JSON document.
fn clean(text: &str) -> String {
    crate::redaction::redact_text(&escape_untrusted(text))
}

/// The code of a prompt error: Ctrl-C is `interrupted`, a terminal failure is `internal`, and the rest
/// (no terminal, end of input, a password that is too long) need the input to change.
fn prompt_code(err: &PromptError) -> ErrorCode {
    match err {
        PromptError::Cancelled(Cancel::Interrupted) => ErrorCode::Interrupted,
        PromptError::Io(_) => ErrorCode::Internal,
        _ => ErrorCode::Usage,
    }
}

/// The rendered form of a password error, for code that holds a reference.
pub(crate) fn render_password(err: &PasswordError) -> Rendered {
    Rendered::plain(ErrorCode::Usage, &err.to_string(), &err.fix())
}

/// The rendered form of a prompt error, for code that holds a reference.
pub(crate) fn render_prompt(err: &PromptError) -> Rendered {
    Rendered::plain(prompt_code(err), &err.to_string(), err.fix())
}

/// The code of a spec error. Parse problems in the YAML itself are `spec_parse`. A well-formed
/// document that is not a valid spec is `spec_invalid`. A spec error that no code fits is `spec_invalid`
/// too: the input has to change.
fn spec_error_code(err: &SpecError) -> ErrorCode {
    match err.kind() {
        SpecError::TooLarge { .. }
        | SpecError::NotUtf8
        | SpecError::Syntax { .. }
        | SpecError::TooDeep { .. }
        | SpecError::MultipleDocuments
        | SpecError::Directive
        | SpecError::Tag { .. }
        | SpecError::Anchor
        | SpecError::Alias
        | SpecError::MergeKey
        | SpecError::DuplicateKey { .. }
        | SpecError::NonFiniteNumber { .. }
        | SpecError::UnquotedDecimal { .. } => ErrorCode::SpecParse,
        SpecError::Signature(error) => signature_error_code(error),
        _ => ErrorCode::SpecInvalid,
    }
}

/// The code of a signature error (01 section 4.8). All of them exit 64, and none can be waved through.
///
/// - `Missing` is `spec_unsigned`.
/// - `UnknownKey` is `spec_key_unknown`.
/// - A signature file that is too large, malformed, legacy or has a bad comment, a file or comment that
///   does not match, and a product mismatch are `spec_signature_invalid`.
/// - A public key that is not usable or is weak is `spec_signature_invalid` too: the key cannot vouch for
///   anything, and the fix is to get the key again.
/// - A variant this build does not know is `spec_signature_invalid`. It fails closed and never becomes
///   `spec_invalid`.
///
/// `spec_expired` has no source yet: `rdy-spec` does not check `metadata.expires`.
fn signature_error_code(err: &SignatureError) -> ErrorCode {
    match err {
        SignatureError::Missing => ErrorCode::SpecUnsigned,
        SignatureError::UnknownKey { .. } => ErrorCode::SpecKeyUnknown,
        _ => ErrorCode::SpecSignatureInvalid,
    }
}

/// An error ready to print. Every string is escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The stable code.
    pub code: ErrorCode,
    /// The first line, without `error:` and without the position.
    pub message: String,
    /// The second line, without `fix:`.
    pub fix: String,
    /// The spec file as typed, when the error is about a spec.
    pub file: Option<String>,
    /// The line in the file, from 1.
    pub line: Option<u32>,
    /// The column in the file, from 1.
    pub column: Option<u32>,
}

impl Rendered {
    /// An error with no file and no position. The strings are escaped.
    fn plain(code: ErrorCode, message: &str, fix: &str) -> Self {
        Self {
            code,
            message: clean(message),
            fix: clean(fix),
            file: None,
            line: None,
            column: None,
        }
    }

    /// The process exit code as a number.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.code.exit_code().code()
    }

    /// The two lines for stderr, each ending in a newline. The terminal puts `file:line:column:` in
    /// front of the message. The JSON message does not repeat it (07 section 4.1).
    #[must_use]
    pub fn text(&self) -> String {
        let place = match (&self.file, self.line, self.column) {
            (Some(file), Some(line), Some(column)) => format!("{file}:{line}:{column}: "),
            (Some(file), _, _) => format!("{file}: "),
            _ => String::new(),
        };
        format!("error: {place}{}\nfix: {}\n", self.message, self.fix)
    }

    /// The object for stdout with `--json`.
    #[must_use]
    pub fn output(&self) -> ErrorOutput {
        ErrorOutput {
            api_version: rdy_spec::API_VERSION,
            kind: "Error",
            error: ErrorBody {
                code: self.code.as_str(),
                message: self.message.clone(),
                fix: self.fix.clone(),
                file: self.file.clone(),
                line: self.line,
                column: self.column,
            },
            verdict: None,
            complete: false,
        }
    }

    /// The JSON document and a final newline. `<`, `>` and `&` are written as the escapes
    /// `\u003c`, `\u003e` and `\u0026`, like every document rdy prints (01 section 5.5).
    #[must_use]
    pub fn json(&self) -> String {
        // The object holds strings and numbers only, so serializing cannot fail. If it ever did, an
        // empty object would still be valid JSON for a reader that checks the exit code first.
        let text = serde_json::to_string_pretty(&self.output()).unwrap_or_else(|_| "{}".to_owned());
        let mut out = text
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026");
        out.push('\n');
        out
    }
}

/// What rdy prints on stdout with `--json` when it exits 64 or 70 without a verdict
/// (`$defs/ErrorOutput` in the result schema).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorOutput {
    /// Always `rdy/v1`.
    pub api_version: &'static str,
    /// Always `Error`.
    pub kind: &'static str,
    /// What went wrong.
    pub error: ErrorBody,
    /// Always `null`: an error has no verdict.
    pub verdict: Option<Verdict>,
    /// Always `false`.
    pub complete: bool,
}

/// The `error` object of an [`ErrorOutput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// The stable code, such as `spec_parse`.
    pub code: &'static str,
    /// The first line of the terminal message, without the position.
    pub message: String,
    /// The fix line.
    pub fix: String,
    /// The spec file, when the error is about a spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The line, from 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The column, from 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Prints `err` and returns the exit code.
///
/// stderr always gets the `error:` and `fix:` lines. With `json`, stdout gets the [`ErrorOutput`] too
/// (ADR 0008 decision 7). A stream that cannot be written is ignored: the exit code still says what
/// happened, and there is nowhere left to report it.
pub fn emit(err: &CliError, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let rendered = err.render();
    if json {
        let _ = stdout.write_all(rendered.json().as_bytes());
    }
    let _ = stderr.write_all(rendered.text().as_bytes());
    rendered.exit_code()
}

/// True when `--json` is on the command line before any `--`.
///
/// This is read from the raw arguments, so that a failure to parse the command line can still answer in
/// JSON. The check is on the exact flag, so a near miss such as `--jsno` is a usage error in text.
#[must_use]
pub fn wants_json(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--json")
}

#[cfg(test)]
mod tests;
