# PR #156 (M1-063) cold code review, head 0893d77

Verdict: changes required (small). CI test and lint legs still running; nothing built locally.

## Findings

1. High. crates/rdy-engine/tests/redaction_corpus.rs:49-72 (CLAIMS). The form gate checks a hand-written table, not 04 Appendix B, and the table leaves out M1 forms that B claims in 04 section 4's own form list (env, YAML, JSON, INI, flag, header). No case covers: `SecretAccessKey` in JSON (session-json.in has no SecretAccessKey line, though real STS output always has one), `aws_session_token` as INI or env, and `x-amz-security-token` as a header. The B Matches column also claims these with no case and no line in the "not claimed" list: `X-Auth-Token`, bare `Bearer <token>`, `-H 'Authorization: ...'`, systemd `Environment=`, and the kubeconfig keys `password`, `id-token`, `client-secret` and `access-token`. The form gate only covers what someone typed into CLAIMS. Fix: add these forms to CLAIMS and cover them with one-line additions to existing cases (a SecretAccessKey line in aws/session-json, an aws_session_token line in aws/credentials-ini, password and id-token lines in kubeconfig/token) plus small header and systemd cases. M1-060 unit tests show the engine handles them. Anything left out goes in the "not claimed" lists.
2. Low. tests/fixtures/redaction/synthetic.toml and redaction_corpus.rs:195. "At least 2 parts" accepts `["", "whole-token"]`. Nothing stops a raw `.in` or `secrets` entry from holding a whole PEM block, JWT or AWS key. Grep is clean today (only `AKIAIOSFODNN7EXAMPLE`). Fix: refuse empty pieces, and fail the load when the raw (unexpanded) `.in` or `.toml` text has a PEM private-key marker, a JWT, `rdy_st_` or any AWS key id other than the documented one.
3. Low. docs/plan/12-progress.md:140. "PR #TBD". Fix: `[#156](https://github.com/getrdy-io/rdy/pull/156)`.
4. Low (plan text, not this PR). 08-testing.md line 731 on main: "[M1] SEC-26 ... 60 synthetic cases across the M1 categories". This contradicts the current plan. 04 "Plan corrections found" (60 in M1 becomes 28) and 11 line 51 (the 32 M2 cases are SEC-44, M2-061) both supersede it; 60 includes M2-only categories. Not the full SEC-26 target; M1-063 scope unchanged. Fix: log a correction and edit 08 to 28 cases (keep the UPDATE_GOLDENS clause).
5. Nit. redaction_corpus.rs:472. "a negative case lists no `rules`..." reads as a statement of fact. Fix: "must not list".
6. Nit. changelog.d/M1-063.md says "gates every build". It gates `cargo test`.

## Verified OK
- Self-tests fail on a survivor, a vacuous secret, a rule that did not fire, a changed negative, and a missing rule, form, exclusion or FLOOR.
- `built_in_rule_names` is test or `testing` only and maps `BUILT_IN`, the only table `redact_str` runs, so it cannot drift.
- The Appendix B reader fails loudly on a renamed heading, a changed table shape or a set mismatch.
- All 28 Appendix D cases are present. `/tests/fixtures/** -text` keeps LF and ESC bytes on Windows.

## Exit test
Mostly proven: the corpus, the parts, the negatives, survivor detection and the coverage gate mechanics. "Fails on a syntax form with no positive case" is only partly proven until finding 1 is fixed. Five-leg green is pending CI.
