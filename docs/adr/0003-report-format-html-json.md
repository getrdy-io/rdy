# ADR 0003: Reports are one JSON file plus one self-contained HTML file, rendered with askama

- Status: Accepted (revised 2026-10-28 after security-reviewer and cli-ux review; decisions 1, 2 and 6 amended 2026-10-28 in M1-009 to match ADR 0016 and 01)
- Date: 2026-10-27

## Context

The report is the demo (plan, M1 build order step 3). Air-gapped customers carry it out on a USB stick.
Customer security reviewers read the renderer's source (CLAUDE.md rule 7). The JSON result is the
contract `rdy-cloud` ingests (ADR 0007). The HTML shows untrusted strings from two sources: vendor text
in the spec (`fix`) and values observed on the box (hostnames, object names, proxy banners). `rdy` often
runs as root, and the output name would otherwise come from vendor-controlled `metadata.product`.

## Decision

1. **Names and place.** `metadata.product` must match `^[a-z0-9][a-z0-9-]{0,62}$` (`rdy_spec::validate`,
   and the same rule on the signed trusted comment). Timestamps use basic ISO 8601 with no colons,
   `20261027T143005Z`. Right after spec verification and before the first check, `rdy run` creates a
   new directory `rdy-report-<product>-<ts>/` under `--out-dir` (default `.` on Unix,
   `%USERPROFILE%\rdy-reports` on Windows) with `create_dir`, mode 0700. If the name exists it retries
   with `-2` to `-9`, then exits 70 before any check runs (ADR 0016). It writes
   `rdy-report-<product>-<ts>.json` and `.html` inside it with `create_new`, mode 0600, through a
   directory handle that does not follow symlinks (`cap-std`), temp file then rename. The report code
   re-checks the slug defensively. `--no-report` writes nothing.
2. **Terminal and stdout.** A `Report written to <dir>` line prints above the verdict, so the verdict
   stays last. `--json` writes the same bytes to stdout as the JSON file. If the directory cannot be
   created, rdy prints `error:` and `fix: use --out-dir <writable dir>` and exits 70 before any check
   runs (ADR 0016). If the files cannot be written at the end, the full terminal result still prints,
   then `error:` and `fix:`, and the exit code is 70.
3. **Self-contained HTML.** Inline CSS, no JavaScript in M1, no web fonts, no images except an inline SVG
   logo, nothing loads on open. CSP meta: `default-src 'none'; style-src 'unsafe-inline'; img-src data:;
   base-uri 'none'; form-action 'none'`. `<html lang="en">`, a `color-scheme` meta, headings in order.
4. **Embedded JSON.** The full result is embedded in `<script type="application/json" id="rdy-result">`.
   After serializing, every `<` becomes the six characters `\u003c`, every `>` becomes `\u003e`,
   and every `&` becomes `\u0026` (JSON unicode escapes: backslash, `u`, four hex digits). Those characters only occur inside JSON strings, so the result is still valid
   JSON and cannot close the script element. The JSON file, not the HTML, is the supported upload; the
   portal treats JSON pulled from an HTML file as untrusted input.
5. **askama** templates in `crates/rdy-engine/templates/`, checked at compile time, HTML auto-escaping on.
   `|safe` is banned in templates (CI grep).
6. **Order and words.** Top of the page: the unsigned-spec or unpinned-key banner when it applies
   (first, as in the terminal, 01 sections 4.7 and 6), then the verdict in the terminal's words (`READY`,
   `READY with warnings`, `NOT READY`), the counts, and the line
   "This file lists hostnames and addresses from this machine. Read it before you send it." Then blocks,
   then required checks not run, then warnings, then passes. Status labels, same as the terminal:
   `PASS`, `WARN`, `BLOCK`, `SKIP`, `TIMEOUT`, `ERROR`. Colour is never the only signal.
7. **Dark mode and print.** `prefers-color-scheme`; `@media print` expands every section and keeps the
   order.
8. The footer links to getrdy.io with the product name in the query string, `rel="noopener noreferrer"`.
   Nothing is fetched unless the reader clicks. The docs security page lists the parameters it carries.
9. Output is deterministic for a given `Report`, so golden tests are exact.

## Consequences

- Opens offline in any browser and prints for a change board. Root runs cannot be steered into writing
  outside a fresh directory.
- No client-side filtering in M1. A later inline script must be hashed in the CSP in the same PR.
- Custom-branded reports (M4) are data fed into the same template, never vendor templates.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| `maud` (HTML in Rust macros) | Safe and fast, but reviewers must read Rust macros to see the markup. |
| `minijinja`, `tera`, `handlebars` (runtime templates) | Errors surface at runtime on a customer box; invite vendor-supplied templates. |
| Files written straight into the cwd | A pre-planted symlink in a shared dir makes root overwrite any file. |
| Separate CSS and JS assets | Files get separated on the way out of an air-gapped site. |
| PDF output | Needs a layout engine; print-to-PDF covers it. |

## Tickets implied

- [M1] askama HTML report with inline CSS, dark mode and print | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: the golden HTML shows the verdict and blocks first, makes no network requests in a headless browser test, and passes an HTML validator with lang and color-scheme set.
- [M1] Embed result JSON in the HTML report safely | owner: rust-engineer | est: 2.5h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a hostname of `</script><img onerror>` round-trips through the embedded JSON unchanged, renders as text, and the CSP and link attributes match this ADR.
- [M1] Golden tests for JSON and HTML reports | owner: qa-engineer | est: 2h | depends on: Embed result JSON in the HTML report safely | exit test: insta snapshots for ready, warning and not-ready fixtures pass on all four CI targets.
- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a product of `../x` fails validation, a pre-planted symlink is not followed, an existing dir is refused, modes are 0700 and 0600, and `--out-dir` and `--no-report` behave as written.
