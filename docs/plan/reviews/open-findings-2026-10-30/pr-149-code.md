# PR #149 (M1-077) cold review, head 2f63431

**Verdict: changes required.**

## Findings

1. **High.** `crates/rdy-engine/src/report.rs:8`. The intra-doc link [`render_html`] does not resolve when `html` is off. CI lint job on 2f63431 is red: "cargo doc rdy-engine without default features" fails with `unresolved link to render_html`. The loopback doc step would fail the same way. Fix: write it as plain `` `html::render_html` `` with no brackets, or wrap the bullet in `#[cfg_attr(feature = "html", doc = ...)]`. Also add `cargo doc/clippy -p rdy-engine --no-default-features --features html`. That is the advertised rdy-cloud build, and CI never compiles it.
2. **High.** `crates/rdy-engine/tests/html_report.rs:7-9, 84-142`. The exit test says "passes an HTML validator". `well_formed` only checks the doctype, lang and color-scheme strings, tag balance and unique ids. It does not check content models, attribute validity or parse errors. So the exit test is not proven. "Needs Java" is not a blocker: GitHub ubuntu runners ship a JDK. Fix: on the linux-x64 leg, run the Nu validator (vnu.jar, sha256-pinned) over `tests/fixtures/reports/golden/*.html` with `--Werror`. Or get a recorded plan correction that redefines the exit test. Keep `well_formed` as the five-leg smoke.
3. **Medium (merge gate).** `docs/plan/05-threat-model.md:329-355`. askama is "pending security review". 07 D.5 and the 05 policy need security-reviewer approval before merge. The record is also wrong: askama 0.16.1 `src/ascii_str.rs` has four `transmute` sites (lines 35, 42, 92, 102), not two (05:340, 05:344, 12-progress). Fix the count and get the approval.
4. **Low.** `crates/rdy-engine/templates/report.css:1-25`. The tokens do not match 07 D.2: text, panel, muted, warn, pass, the dark page colours and the banner fill. Use the D.2 values now so M3-007 does not churn the goldens.
5. **Low.** `crates/rdy-engine/src/report/html/view.rs:182,174,188`. The banners differ from 01 4.7: "has no verified signature" instead of "has no signature". Use the 4.7 sentence. "This report is marked" is a fair HTML adaptation. Note it in 12-progress.
6. **Low.** 01 section 6 item 2 and 07 D.7 have a "rule in plain words" sentence and a "No blocks" verdict-box note. Neither is built, and 12-progress names no owner. Name M1-079 or M1-140 as the owner.
7. **Nit.** `docs/plan/12-progress.md:169`. The claim that "NOT READY: 2 required checks were not run" shows in the summary line is wrong. The summary line says "2 required checks not run". Reword.
8. **Nit.** The determinism test renders twice in one process, which proves little. The goldens are the real proof. That is fine as is.

## Questions asked

- **Verdict computed or stored.** Computing from the checks is right. ADR 0003 decision 6 and M1-054 `summary` both say never trust the stored verdict. Sections from the stored `bucket` are also right (01 5.2: "Do not recompute it"). The h1 plain word matches ADR 0003 decision 6.
- **HtmlError instead of ReportError.** Acceptable. It follows the JsonError precedent, `ReportError` is runtime-gated, and 02 is updated. The error has a fix hint and quotes no report text.
- **`html` default feature.** The feature was already approved in 02:75. The release binary gets askama's small runtime crate, and the release tree check is unaffected.
- **`log_phrase` warning.** Not a CI issue and not from this PR. `probe/proxy.rs` is unchanged from main. The `--all-targets` clippy steps turn on the self dev-dependency (default plus testing plus loopback). So no CI job sees the `--lib` warning. One consequence: the "without default features" clippy steps do not really test that build. File a follow-up ticket.
- **Scope.** Clean. M1-078 to M1-081, M1-140 and M1-141 items are deferred and listed. Adding `<bdi>` early is harmless.
- **Determinism and goldens.** The renderer reads no env, clock or `CARGO_PKG_VERSION`. Templates are LF via .gitattributes and goldens are `-text`. Both goldens go through `assert_golden`, and xtask covers html.

## Exit test status

- Proven: verdict and blocks first, the five-section `group_by_bucket` golden, and the credential plugin `aws` in the run details.
- Not proven: "passes an HTML validator" (finding 2).
