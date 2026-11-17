# PR #149 M1-077 fix round 2. Branch m1/077-html-report, head 499fe4d.
Reviews: findings/149-code-confirm.md (code N) and findings/149-sec-confirm.md (SEC-149-N). Both approve with fixes; all lows/nits below are cheap, do them all.
First `git merge origin/main` (code 1). Every commit, merges included, carries `Signed-off-by: Rdy <dev@getrdy.io>`.
1. SEC-149-9 + code 5: move the validator into its own `html-validator` job in ci.yml (checkout + Java only, no rust-cache, `permissions: contents: read`, pinned actions as the rest of ci.yml), make ci-ok need it, and keep the html_report.rs:7 comment true. If the lint wall or zizmor pins the job list, update the pin in the same commit and say so.
2. Code 2 + SEC-149-13: validate-html.sh: curl `--connect-timeout 20 --max-time 300`; fall back to `shasum -a 256` when `sha256sum` is missing, refuse an empty digest with a fix hint; INT and TERM traps `exit 1`.
3. SEC-149-8: the bump procedure in the script header runs `cosign verify-blob-attestation` with identity `https://github.com/validator/validator/.github/workflows/build.yml@refs/heads/main` and issuer `https://token.actions.githubusercontent.com`; note commit 973e40b16d1c653cf52523b126ef92aec8bf9e0e and Rekor index 3228121956 by the pin; record vnu-jar (CI only, never shipped) in 05 under dependency approvals.
4. SEC-149-10 + code 4: `<title>rdy report: {{ verdict_word }}, {{ title_product }}</title>`; update html_report.rs asserts and goldens; fix the 12-progress sentence so it matches.
5. Code 3: build the not-run reason and the partial summary as `Vec<Span>` like the banner lines, so only untrusted pieces sit in `<bdi>` and our own trailing words stay outside; add a test with an RLO in a missing_grants entry and a need name.
6. SEC-149-12 / code 7: add deny.toml bans for askama_macros (wrappers ["askama"]), askama_derive (wrappers ["askama_macros"]), askama_parser (wrappers ["askama_derive"]), kube pattern; cargo deny check must stay clean.
7. SEC-149-11: view.rs:29 comment says `<bdi>` limits reordering and M1-141 escapes the controls (coordinator adds the M1-141 test string via a backlog correction).
8. SEC-149-14 / code 6: 05 says "in two files".
Run the full gate incl. scripts/validate-html.sh on both goldens, shellcheck, lint-wall tests.
