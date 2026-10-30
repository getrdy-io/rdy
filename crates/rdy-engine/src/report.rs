//! What rdy writes about a run (ADR 0003, 01 sections 5.5 and 6).
//!
//! - [`json`]: the JSON writer. [`write_json`] and [`json_bytes`] take a [`crate::redact::RedactedReport`]
//!   and nothing else, and give the one byte string that the `.json` file, `--json` on stdout and the
//!   copy embedded in the HTML report all share ([`HtmlSafeJson`]). [`read_report`] is the matching
//!   reader: it refuses a document over [`MAX_REPORT_BYTES`] before it parses a byte.
//!
//! The HTML renderer arrives with M1-077.

pub mod json;

pub use json::{HtmlSafeJson, JsonError, MAX_REPORT_BYTES, json_bytes, read_report, write_json};
