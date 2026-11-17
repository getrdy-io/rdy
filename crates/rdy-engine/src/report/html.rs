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
//! 2. The header: the verdict in the terminal's words, what the spec is for, the summary line, "No
//!    blocks." when no check blocks, when and by whom it ran, the legend of the status words, the
//!    rule for the verdict in plain words, and the line about hostnames.
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
//! **Print.** `@media print` is black on white whatever the screen theme: it sets `color-scheme: light`
//! and replaces every variable of the dark palette, with no backgrounds. No raw JSON key is visible
//! text in the template (a test scans it).
//!
//! **Fix label and action log (M1-080).** A fix says who wrote it ("From acme-platform" only for a verified
//! signature with a pinned key). The last section is the action log as one table, built from the report
//! the JSON holds, so its "N more entries are in the embedded JSON" line is true. The whole page is at most
//! 5 MiB: past that, rows of the table are cut and the checks and the JSON never are.
//!
//! Left to later tickets: Found and Needed, the footer link and the fixed banner in print (M1-081).

use crate::redact::RedactedReport;
use crate::report::JsonError;

#[cfg(test)]
mod tests;
mod view;

use askama::Template as _;
use view::View;

/// The most bytes a page may hold: 5 MiB (07 D.4). The JSON inside it is at most 2 MiB, so the cap only
/// ever cuts rows of the action table.
const MAX_PAGE_BYTES: usize = 5 * 1024 * 1024;

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
    fit_page(&mut View::new(report)?, MAX_PAGE_BYTES)
}

/// Renders `view`. Over `max` bytes, the action table is cut to the most rows that fit and the page is
/// rendered again. The checks and the embedded JSON are never cut (07 D.4).
fn fit_page(view: &mut View, max: usize) -> Result<String, HtmlError> {
    let page = view.render().map_err(|_| HtmlError::Render)?;
    if page.len() <= max {
        return Ok(page);
    }
    let all = view.actions.rows.clone();
    let (mut fits, mut over) = (0, all.len());
    // `fits` rows are known to fit once the loop settles; `over` rows are known not to (or all of them).
    while fits < over {
        let middle = fits + (over - fits).div_ceil(2);
        view.actions.keep_first(&all, middle);
        let size = view.render().map_err(|_| HtmlError::Render)?.len();
        if size <= max {
            fits = middle;
        } else {
            over = middle - 1;
        }
    }
    view.actions.keep_first(&all, fits);
    let page = view.render().map_err(|_| HtmlError::Render)?;
    // With no rows left the page is the checks plus the embedded JSON. The JSON is at most 2 MiB and the
    // checks are at most 256 results with the same bounded text, so this holds for the real cap. A smaller
    // `max` (the tests) can be below that floor.
    debug_assert!(
        max < MAX_PAGE_BYTES || page.len() <= max,
        "a page with no action rows is over the cap"
    );
    Ok(page)
}
