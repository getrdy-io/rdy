## What and why

<!-- One change per PR. Name the ticket (for example M1-003). Say what changed and why. -->

## Checklist

- [ ] Tests pass: `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo fmt --all --check` is clean
- [ ] `cargo deny check` is clean
- [ ] Docs are updated in this PR
- [ ] I added `changelog.d/<ticket>.md` (one or two user-facing bullet lines). I did not edit `CHANGELOG.md`.
- [ ] Every commit is signed off (`git commit -s`, the DCO) and has an imperative one-line summary
- [ ] If an AI tool wrote most of this change, the description says so, and I read and understand it

## Sensitive areas

Does this touch privileges, network, redaction, signing or the install script? If yes, say how.
If it does, a `security-reviewer` review is needed.

## Golden changes

<!-- Only if a golden file changed: one sentence per changed file saying why. Delete this section if none did. -->

## Compat matrix

<!-- Needed if you changed crates/rdy-checks-*/src/**, tests/fixtures/** or CheckInfo::os: update the compatibility page.
Otherwise write: Compat matrix: unchanged because <reason> -->

Compat matrix: unchanged because

## Check ticket checklist

Only for a PR that adds or changes a check (docs/plan/08-testing.md, Appendix E). Delete the rest otherwise.

- [ ] CheckInfo complete: id, family, needs, os table, default timeout, manifest of reads, commands, env and peers. The registry test passes (ids unique, id matches its row in 03).
- [ ] Evaluation is a pure function over plain fact structs. Unit tests hit each threshold boundary: exactly at min, one below, inside the nominal band, severity warn capping a block.
- [ ] Parsers of external text have a "never panics on arbitrary bytes" property (shared helper).
- [ ] `tests/fixtures/checks/<id>/` has the minimum cases: pass, each non-pass level, no-privilege (partial) if a root-optional need exists, Timeout if the source can hang, garbage input (empty, truncated, odd locale) giving Error or partial and never a panic. Each case has a reviewed `expect.json`.
- [ ] `assert_within_manifest` passes for every case.
- [ ] Fix text: every placeholder is filled in `expect.json`, and the spec fix override case exists.
- [ ] If the check records env, URLs or command output: a canary case shows it absent from JSON and HTML.
- [ ] Every OS in `CheckInfo::os` is right; the plan unit test for Windows and macOS passes.
- [ ] The check is used by at least one env spec; env goldens are updated and explained in "Golden changes".
- [ ] Fixture lint passes.
- [ ] Compatibility page changed, or "Compat matrix: unchanged because ..." is above.
- [ ] Green on all five legs; no new `#[ignore]` outside the allowed form.
- [ ] Ran once on a real machine if one is at hand; command and redacted evidence are in this PR.
- [ ] `code-reviewer` read the golden diff first. `security-reviewer` has it if the check execs, opens sockets or reads sensitive paths.
