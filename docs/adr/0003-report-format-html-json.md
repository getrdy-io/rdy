# ADR 0003: Reports are one JSON file plus one self-contained HTML file, rendered with askama

- Status: Accepted
- Date: 2026-10-27

## Context

The report is the demo (plan, M1 build order step 3). Air-gapped customers carry it out on a USB stick
and email it to the SE. Customer security reviewers read the renderer's source (CLAUDE.md rule 7). The
JSON result is the contract `rdy-cloud` ingests (ADR 0007). The HTML shows strings from two untrusted
sources: vendor text in the spec (`fix`) and values observed on the customer box (hostnames, Kubernetes
object names, proxy banners). Any of these could carry markup.

## Decision

1. `rdy run` writes `rdy-report-<product>-<UTC timestamp>.json` and `.html` side by side. JSON is
   primary; HTML is rendered from the same `Report` value, never from separate data.
2. The HTML file is fully self-contained: inline CSS, no JavaScript in M1, no web fonts, no images except
   an inline SVG logo, no external URLs that load on open. A strict CSP meta tag
   (`default-src 'none'; style-src 'unsafe-inline'; img-src data:`) enforces it.
3. The full result JSON is embedded in `<script type="application/json" id="rdy-result">`, with `<`, `>`
   and `&` escaped as `<`, `>`, `&`. Uploading the HTML alone gives the portal everything.
4. Templating with `askama`: templates are plain `.html` files in `crates/rdy-engine/templates/`, checked
   at compile time, HTML auto-escaping on by default. `|safe` is banned in templates (CI grep).
5. Dark mode with `prefers-color-scheme`, a print stylesheet (`@media print`: no backgrounds, every
   section expanded, page breaks between families). Colour is never the only signal: every status has a
   text label (PASS, WARN, BLOCK, SKIPPED, TIMEOUT, ERROR).
6. The footer links to getrdy.io with the product name in the query string (plan, conversion flow 4).
   It is a plain link: nothing is fetched unless the reader clicks it.
7. Output is deterministic for a given `Report`, so golden-file tests are exact.

## Consequences

- Opens anywhere, offline, in any browser, and prints for a change board.
- No client-side filtering or sorting in M1. If it is added later, it is a hashed inline script and the
  CSP is updated in the same PR.
- Custom-branded reports (M4) are data (name, logo as data URI, accent colour) fed into the same
  template, not vendor-supplied templates.
- HTML size grows with check count; at a few hundred checks it stays well under 1 MB.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| `maud` (HTML in Rust macros) | Safe and fast, but a security reviewer or designer has to read Rust macros to see the markup. |
| `minijinja` (runtime templates) | Errors surface at runtime; a missing variable can break a report on a customer box. Would make vendor-supplied templates easy, which we do not want. |
| `tera` or `handlebars` | Runtime templates with the same drawback and more dependencies. |
| HTML plus separate CSS and JS assets | Files get separated on the way out of an air-gapped site. |
| PDF output | Needs a layout engine in the binary. Print-to-PDF from the HTML covers it. |

## Tickets implied

- [M1] askama HTML report with inline CSS, dark mode and print | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: the golden HTML renders with no network requests in a headless browser test and passes an HTML validator.
- [M1] Embed result JSON in the HTML report safely | owner: rust-engineer | est: 2h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a fixture with `</script><img onerror>` in a hostname round-trips through the embedded JSON unchanged and renders as text.
- [M1] Golden tests for JSON and HTML reports | owner: qa-engineer | est: 2h | depends on: Embed result JSON in the HTML report safely | exit test: insta snapshots for ready, warning and blocked fixtures pass on all four CI targets.
