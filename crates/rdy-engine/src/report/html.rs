//! The HTML report (ADR 0003, 01 section 6, 07 section 8).
//!
//! [`render_html`] turns a [`RedactedReport`] into one self-contained page: inline CSS, no script, no
//! font or image to load, a Content-Security-Policy `<meta>`, `lang="en"` and a `color-scheme` that
//! follows the reader's setting. It reads the report and nothing else: no file, no environment, no
//! clock. The same report gives the same bytes.
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
//!
//! The verdict and the counts are worked out from the check results with the same rule as the terminal
//! ([`crate::summary`]). The stored `verdict` is not trusted.
//!
//! **Untrusted text.** The templates live in `crates/rdy-engine/templates/` and askama checks them when
//! the crate compiles. Every value is HTML-escaped by askama, which is on for `.html` templates. No
//! template uses the `safe` filter (a CI grep enforces that, M1-078). The one value that may ever be
//! printed unescaped is [`super::HtmlSafeJson`], and this renderer does not print it yet.
//!
//! Left to later tickets: the embedded JSON and its hash (M1-078), the print override and legend
//! (M1-079), the fix source label and the action log table (M1-080), Found and Needed and the footer
//! link (M1-081).

use crate::redact::RedactedReport;

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
}

/// Renders `report` as one HTML page. See the [module](self) for what is on it.
///
/// It takes a [`RedactedReport`] and nothing else, so text that has not been through the redactor cannot
/// reach the page.
///
/// # Errors
///
/// [`HtmlError::Render`] if the template engine fails, which is a bug.
pub fn render_html(report: &RedactedReport) -> Result<String, HtmlError> {
    View::new(report).render().map_err(|_| HtmlError::Render)
}
