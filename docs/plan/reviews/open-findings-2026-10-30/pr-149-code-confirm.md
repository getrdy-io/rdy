# PR #149 (M1-077) confirm review, head 499fe4d

**Verdict: approve with fixes.** Merge only once CI on 499fe4d is green, in particular the linux-x64 step "The HTML goldens pass the Nu HTML Checker" and the two new lint steps. CI was still queued when I reviewed. I could not run vnu myself because running the downloaded jar was blocked, so the --Werror result (the inline CSS included) is not proven yet.

## Prior high and medium findings: all fixed
- Code 1 / SEC-149-1: report.rs:8 now uses plain backticks. ci.yml:74-79 adds clippy and doc for `--no-default-features --features html`.
- Code 2 / SEC-149-3: scripts/validate-html.sh runs on linux-x64 (ci.yml:395-399). I checked the pin. The tarball sha256 is 3925f073...b7ab and matches. Its sha512 equals the registry `dist.integrity`. A provenance attestation is listed. `package/build/dist/vnu.jar` exists. shellcheck covers the script (ci.yml:220).
- Code 3 / SEC-149-2: 05 says approved, with owners and four transmutes. The deny.toml ban matches the existing entries' format and `deny_entries()` parsing.
- wall_intact.rs:458-465 pins four commands. They match ci.yml:55,63,66,75 exactly, and 02:612 says "four".
- Also confirmed: the Cargo.lock revert, the D.2 colours, the 4.7 wording, the SEC-149-5 asserts (`<bdi>token=` is unique to the partial note), and backlog correction-31 (on branch origin/correction-31, not merged yet).

## Findings
1. **Low.** The branch does not include origin/main (M1-060 ed56f63, M1-093 de5dcd6), but fix brief 149-fix1 required merging it. `git merge-tree` shows no conflicts, and CI tests the `pull_request` merge ref, so the risk is small. Fix: merge main with Signed-off-by. Land correction-31 before or with #149, because 12-progress:169 cites it.
2. **Low.** scripts/validate-html.sh:52-53: curl has no timeout, so a stall uses up the 25 min job budget. Also, if `sha256sum` is missing (macOS), the script reports a misleading "hash mismatch". Fix: add `--connect-timeout 20 --max-time 300`, and run `command -v sha256sum` first with a fix hint (or fall back to `shasum -a 256`).
3. **Low.** view.rs:333-339, 371-385 and template lines 50, 59: `why` and `partial.summary` sit whole inside one `<bdi>`. An RLO in a `missing_grants` entry or a need name can still reorder our own trailing words ("The result may be incomplete.") inside that isolate. The same holds for "(available)" in `Requires:`. So the 12-progress:169 claim "every untrusted string is in `<bdi>`" goes too far. Fix: build these as `Vec<Span>` like the banner lines, or reword the claim and rely on M1-141 (core under correction-31).
4. **Nit.** view.rs:154: a U+2069 inside the product closes the title isolate early. M1-141 now covers the title, so this is carried. 12-progress:169 says the product sits "after the verdict word", but the title (and 07:2653) puts it before. Fix that sentence.
5. **Nit.** html_report.rs:7 names a "CI job `html-validator`". It is a step in the `test` job, linux-x64 leg. Fix the wording.
6. **Nit.** 05-threat-model.md askama record: it says "two places" and then lists four transmutes plus one `from_utf8_unchecked`. Say "two files".
7. **Nit.** deny.toml bans only `askama`. `askama_derive`, `askama_macros` and `askama_parser` are kept off check crates only by ci/check-crate-deps.toml. That is acceptable. Optionally add bans for them too.

## Exit test
These are proven by goldens and tests: verdict and blocks first, the five sections, and the credential plugin row. "Passes an HTML validator" will be proven when the vnu step passes on linux-x64. The wiring and the pin are correct, but the result is still pending.
