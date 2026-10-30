//! The JSON writer (ADR 0003 decision 4, 01 section 5.5, 02 "Renderers").
//!
//! [`json_bytes`] turns a [`RedactedReport`] into the bytes of the report. They are the same bytes
//! everywhere: the `.json` file, `--json` on stdout and the copy embedded in the HTML report, so the
//! three hash alike. What the writer promises:
//!
//! - **Layout.** UTF-8, no BOM, LF, two-space indent, fields in the order the types declare them (the
//!   order of the schema), a trailing newline. The keys of every free-form map (`observed`, `expected`
//!   and the fields of an action) are sorted, so the bytes do not depend on how a map was filled or on
//!   which crate turned on `serde_json`'s `preserve_order`. The same report gives the same bytes.
//! - **HTML safe.** After serializing, `<`, `>` and `&` become `<`, `>` and `&`, and
//!   U+2028 and U+2029 become ` ` and ` `. Those characters only occur inside JSON strings,
//!   so the result is still the same JSON and cannot close a `<script>` element. The result is an
//!   [`HtmlSafeJson`], which only this writer can build.
//! - **The schema's caps.** The redactor has cut every text already (4 KiB, a message 1 KiB). The writer
//!   cuts what the redactor leaves: a list past its `maxItems`, a map past its keys, a value in
//!   `observed`, `expected` or an action nested deeper than three levels (the deeper list or object
//!   becomes the text `[truncated]`), and a text in those maps longer than 4 KiB. A cut in a check sets
//!   its `truncated` flag. A cut of a list or a map elsewhere (capabilities, annotations) sets nothing,
//!   because those are not results. So a large real cluster still gives a report that validates.
//! - **The 2 MiB cap.** The whole document is at most [`MAX_REPORT_BYTES`], measured on the final bytes
//!   after the escapes. Past that, entries of the action log go in the order the log itself keeps
//!   (01 section 5.4): the newest `ok` `read`, `read_dir` and `stat`, then `failed` ones, then
//!   other entries, and `denied` entries last. `actions_truncated` and `actions_dropped` say what went.
//!   Past 5000 entries the same order applies. Results are never cut. If the report is still too big
//!   with no action entries, [`JsonError::TooLarge`] says so and nothing is written.
//! - **A reader's cap.** [`read_report`] refuses a document over the cap before it parses it (threat
//!   model D2). A schema cannot cap bytes, so this check is the real size control.

use std::io::{self, Write};

use rdy_spec::result::Report;
use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};

use crate::redact::RedactedReport;

mod bound;
mod shed;
#[cfg(test)]
mod tests;

/// The most bytes a report document may hold: 2 MiB, measured after the JSON escapes. Every reader checks
/// it before it parses (01 section 5, threat model D2).
pub const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;

/// Why a report could not be written or read.
///
/// None of the messages quote report text, because it can hold a hostname or a path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonError {
    /// The report has more results than the format holds. A spec has at most 256 checks (01 section
    /// 2.1), so this is a bug.
    #[error(
        "the report has {found} check results, and the format holds at most {max}. \
         Fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues"
    )]
    TooManyChecks {
        /// How many results the report has.
        found: usize,
        /// The most the format holds.
        max: usize,
    },
    /// The report is over the cap even with every action entry shed.
    #[error(
        "the report is {bytes} bytes with no action log, over the limit of {max} bytes, so it was not written. \
         Fix: run again with fewer checks in the spec, or tell the vendor which checks give so much output"
    )]
    TooLarge {
        /// The size of the smallest form the writer could make.
        bytes: usize,
        /// The cap, [`MAX_REPORT_BYTES`].
        max: usize,
    },
    /// The document to read is over the cap. It was not parsed.
    #[error(
        "the report is {bytes} bytes, over the limit of {max} bytes, so it was not read. \
         Fix: a report from rdy is never this big; check where the file came from"
    )]
    InputTooLarge {
        /// The size of the document.
        bytes: usize,
        /// The cap, [`MAX_REPORT_BYTES`].
        max: usize,
    },
    /// The document to read is not a valid report. The text of the parser is dropped on purpose: it can
    /// quote a value.
    #[error(
        "the report is not valid JSON for a report (line {line}, column {column}). \
         Fix: use the .json file that rdy wrote, unchanged"
    )]
    Parse {
        /// The line of the first problem.
        line: usize,
        /// The column of the first problem.
        column: usize,
    },
    /// The report could not be turned into JSON.
    #[error(
        "the report could not be written as JSON. \
         Fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues"
    )]
    Serialize,
    /// The writer's output refused the bytes.
    #[error("cannot write the report: {0}. Fix: check that the output is open and has room")]
    Io(#[from] io::Error),
}

/// The bytes of a report as JSON, with no `<`, `>` or `&` in them.
///
/// Only the writer builds one: there is no `From<String>`, no `Default` and no `Deserialize`. A template
/// can put it inside a `<script type="application/json">` element without escaping it, because it
/// cannot close the element, and because it is the same bytes as the `.json` file, a hash of one is a
/// hash of the other. The text ends with one newline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlSafeJson(String);

impl HtmlSafeJson {
    /// The JSON text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The JSON bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `false`: a report is never empty. It exists because `len` does.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for HtmlSafeJson {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<str> for HtmlSafeJson {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for HtmlSafeJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The bytes of `report` as JSON, cut to the schema's caps and to [`MAX_REPORT_BYTES`]. See the
/// [module](self) for the rules.
///
/// # Errors
///
/// [`JsonError::TooManyChecks`] for more than 256 results, [`JsonError::TooLarge`] when no cut of the
/// action log brings the report under the cap, and [`JsonError::Serialize`] if serde fails (a bug).
pub fn json_bytes(report: &RedactedReport) -> Result<HtmlSafeJson, JsonError> {
    let mut cut = (**report).clone();
    bound::bound_report(&mut cut)?;
    shed::fit(cut)
}

/// Writes the report as JSON to `out`: the bytes of [`json_bytes`], nothing before or after.
///
/// Use it for `--json` on stdout. The caller flushes. A failed write is [`JsonError::Io`].
///
/// # Errors
///
/// The same as [`json_bytes`], and [`JsonError::Io`] when `out` refuses the bytes.
pub fn write_json(report: &RedactedReport, out: &mut dyn Write) -> Result<(), JsonError> {
    let json = json_bytes(report)?;
    out.write_all(json.as_bytes())?;
    Ok(())
}

/// Reads a report from `bytes`, after checking the size.
///
/// A document over [`MAX_REPORT_BYTES`] is refused before any of it is parsed (threat model D2). The
/// result is not redacted: a reader that shows or forwards a report it did not write runs the redactor
/// on it first (`rdy report`, M2).
///
/// # Errors
///
/// [`JsonError::InputTooLarge`] over the cap, [`JsonError::Parse`] if it is not a report.
pub fn read_report(bytes: &[u8]) -> Result<Report, JsonError> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(JsonError::InputTooLarge {
            bytes: bytes.len(),
            max: MAX_REPORT_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|e| JsonError::Parse {
        line: e.line(),
        column: e.column(),
    })
}

/// Serializes in the layout of 01 section 5.5 and escapes it for HTML.
fn render(report: &Report) -> Result<HtmlSafeJson, JsonError> {
    let mut buf = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut buf, PrettyFormatter::with_indent(b"  "));
    report
        .serialize(&mut serializer)
        .map_err(|_| JsonError::Serialize)?;
    buf.push(b'\n');
    let text = String::from_utf8(buf).map_err(|_| JsonError::Serialize)?;
    Ok(HtmlSafeJson(escape_html(&text)))
}

/// Replaces `<`, `>`, `&`, U+2028 and U+2029 with JSON escapes. In JSON text they can only be inside a
/// string, where the escape means the same character.
fn escape_html(json: &str) -> String {
    let mut out = String::with_capacity(json.len() + json.len() / 32);
    for ch in json.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}
