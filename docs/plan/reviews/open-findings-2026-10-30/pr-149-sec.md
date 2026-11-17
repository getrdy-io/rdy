# PR #149 (M1-077) security review, head 2f63431

Verdict: changes required (one CI break). askama is approved. Escaping, CSP and the RedactedReport gate are sound.

## askama 0.16.1: APPROVED
crates.io owners of askama and askama_derive: GuillaumeGomez, djc, Kijewski, team askama-rs:maintainer. askama_parser: djc, Kijewski, team. askama_macros: GuillaumeGomez alone. 0.16.1 is latest, published 2026-09-04, not yanked. No RustSec advisory for any askama crate or rustc-hash. `build = false` in all four. MIT OR Apache-2.0. MSRV 1.88. Runtime unsafe: four transmutes in `ascii_str.rs` (lines 35, 42, 92, 102), not two. All sound: `AsciiStr`/`AsciiChar` are `repr(transparent)`, `AsciiChar::new` panics on non-ASCII, the field is private, no `DerefMut`. The escaper (`html.rs`) maps `" & ' < >` to `&#NN;`. Derive-crate unsafe runs only in rustc.

## Findings
- SEC-149-1 high, crates/rdy-engine/src/report.rs:8. CI `lint` fails at "cargo doc rdy-engine without default features": [`render_html`] is an intra-doc link to an item cfg'd out without `html`. Fix: plain backticks, as lib.rs does.
- SEC-149-2 medium, docs/plan/05-threat-model.md:329-348. Record is "pending" and wrong (two transmutes). Fix: replace "Pending security review..." with "Approved by security-reviewer, PR #149 (SEC-149-2)"; maintainers as above, askama_macros single owner; "four `transmute` calls in `ascii_str.rs`, read and sound". Enforce "check crates may depend on none": add `{ crate = "askama", wrappers = ["rdy-engine"] }` to deny.toml bans.
- SEC-149-3 medium, exit test. "Passes an HTML validator" is not proven; `well_formed` is a homemade tag balancer. Fix: run vnu.jar (pinned SHA-256) on both goldens on linux-x64 (Java ships on ubuntu runners), or record a plan correction.
- SEC-149-4 low, templates/report.html:8, 18, 26, 50, 62, 104. Untrusted text outside `<bdi>`: `spec.file_name` inside the UNSIGNED SPEC banner sentence, need names and `missing_grants` in `why`/`partial.summary`, `run_when`, `rdy_version`, the title. An RLO in the file name reorders the rest of the security warning. Fix: give Banner a separate untrusted field rendered in `<bdi>`; wrap the others. Correct the 12-progress claim "on every untrusted string".
- SEC-149-5 low, crates/rdy-engine/tests/html_report.rs:395-396. Positive controls cover host and msg only. Add `secret=`, `run it with password=`, `token=` asserts for note, fix, part. Vacuous until M1-080/M1-081: env-token-2, kube-token-3, kube-text-3b, output-hdr-4, argv-5 (observed), action-argv-6 (actions). Carry: those tickets assert the planted fields render.
- SEC-149-6 low, carry to M1-078. Grep only for `|safe` is too narrow for askama 0.16. Also ban `escape = "none"`, `|e(`/`|escape(` with "none", `filters::Safe`, `MaybeSafe`, `impl HtmlSafe`, `{% filter safe`, and askama features `serde_json`/`urlencode`.
- SEC-149-7 low, backlog. M1-141 is not core, so 0.1.0 ships fix text (copied and run as root) with live bidi controls. Promote it, and cover the title and Cf/zero-width characters.
- nit, Cargo.lock: unrelated serde-saphyr base64 0.22.1 to 0.23.1 (xtask `serialize` only). Revert or explain.

CSP matches ADR 0003. Nothing loads. The only attribute values are static or numeric. No `|safe`. Compile-fail test is valid.
