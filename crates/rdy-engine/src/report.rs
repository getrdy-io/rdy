//! What rdy writes about a run (ADR 0003, 01 sections 5.5 and 6).
//!
//! - [`json`]: the JSON writer. [`write_json`] and [`json_bytes`] take a [`crate::redact::RedactedReport`]
//!   and nothing else, and give the one byte string that the `.json` file, `--json` on stdout and the
//!   copy embedded in the HTML report all share ([`HtmlSafeJson`]). [`read_report_from`] is the matching
//!   reader: it refuses a document over [`MAX_REPORT_BYTES`] before it parses a byte.
//!
//! - `html` (feature `html`, on by default): [`render_html`] turns a [`crate::redact::RedactedReport`] into
//!   one self-contained HTML page (M1-077). It needs no runtime, so `rdy-cloud` and `rdy report` can use
//!   it with `default-features = false, features = ["html"]`.

#[cfg(feature = "html")]
pub mod html;
pub mod json;

#[cfg(feature = "html")]
pub use html::{HtmlError, render_html};
pub use json::{
    HtmlSafeJson, JsonError, MAX_REPORT_BYTES, json_bytes, read_report, read_report_from,
    write_json,
};
