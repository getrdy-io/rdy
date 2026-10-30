//! The HTML report (ADR 0003, 01 section 6, 07 section 8).
//!
//! [`render_html`] turns a [`RedactedReport`] into one self-contained page: inline CSS, no script that
//! runs (the embedded result is a data block), no font or image to load, a Content-Security-Policy
//! `<meta>`, `lang="en"` and a `color-scheme` that follows the reader's setting. It reads the report and
//! nothing else: no file, no environment, no clock. The same report gives the same bytes.
//!
//! What is on the page, in DOM order:
//!
//! 1. The banners: UNSIGNED SPEC or KEY NOT PINNED when the signature is not verified by a pinned key
//!    (01 section 4.7), and INCOMPLETE when the run did not finish.
//! 2. The header: the verdict in the terminal's words, what the spec is for, the summary line, when
//!    and by whom it ran, and the line about hostnames.
//! 3. The page index.
//! 4. One section per group of [`rdy_spec::result::group_by_bucket`], in that order: Blocks, Required
//!    checks not run, Warnings, Passed, Does not apply here. A group with no checks has no section.
//! 5. What rdy could use on this machine, and the run and spec details (the signature, the machine, the
//!    identity with any kubeconfig credential plugin, the proxy).
//! 6. The result, embedded: `<script type="application/json" id="rdy-result" data-sha256="...">` holds
//!    exactly the bytes of the `.json` file ([`super::json_bytes`]), and `data-sha256` is their SHA-256
//!    in lowercase hex. It is a data block. The browser never runs it, and the CSP has no `script-src`.
//!
//! The verdict and the counts are worked out from the check results with the same rule as the terminal
//! ([`crate::summary`]). The stored `verdict` is not trusted.
//!
//! **Untrusted text.** The templates live in `crates/rdy-engine/templates/` and askama checks them when
//! the crate compiles. Every value is HTML-escaped by askama, which is on for `.html` templates. The one
//! value printed unescaped is [`super::HtmlSafeJson`], the embedded result: the JSON writer has turned
//! every `<`, `>` and `&` in it into a `\uXXXX` escape, so it cannot close the element. That type is the
//! only one with askama's safe marker. `scripts/check-html-escapes.sh` fails CI on any other way to
//! switch escaping off (the `safe` filter, `escape = "none"`, a second marker, the askama features that
//! add `json` and `urlencode` filters), M1-078.
//!
//! Left to later tickets: the print override and legend (M1-079), the fix source label and the action
//! log table (M1-080), Found and Needed and the footer link (M1-081).

use crate::redact::RedactedReport;
use crate::report::JsonError;

#[cfg(test)]
mod tests;
mod view;

use askama::Template as _;
use view::View;

/// Why a report could not be rendered as HTML.
///
/// The message quotes no report text, because it can hold a hostname or a path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HtmlError {
    /// The template engine failed. The templates are checked at compile time, so this is a bug.
    #[error(
        "the report could not be rendered as HTML. \
         Fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues"
    )]
    Render,
    /// The report could not be turned into the JSON that the page carries (M1-078). It is the error of
    /// the JSON writer, so the same report fails the same way in both files.
    #[error(transparent)]
    Json(#[from] JsonError),
}

/// Renders `report` as one HTML page. See the [module](self) for what is on it.
///
/// It takes a [`RedactedReport`] and nothing else, so text that has not been through the redactor cannot
/// reach the page.
///
/// # Errors
///
/// [`HtmlError::Render`] if the template engine fails, which is a bug. [`HtmlError::Json`] if the JSON
/// writer refuses the report (more than 256 results, or too large with nothing left to cut).
pub fn render_html(report: &RedactedReport) -> Result<String, HtmlError> {
    View::new(report)?.render().map_err(|_| HtmlError::Render)
}
