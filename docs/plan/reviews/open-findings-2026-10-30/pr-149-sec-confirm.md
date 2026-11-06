# PR #149 (M1-077) security confirm review, head 499fe4d

Verdict: approve with fixes. SEC-149-1 to SEC-149-5 are fixed. Nothing new is high. CI on 499fe4d was still queued when I looked, so merge waits for green.

## Earlier findings
- SEC-149-1 fixed. report.rs:8 now uses plain backticks. CI adds clippy and doc for `--no-default-features --features html`, and wall_intact.rs plus 02 pin four clippy commands.
- SEC-149-2 fixed. 05 says "Approved by security-reviewer", lists the owners (askama_macros has one), states four transmutes at 35/42/92/102, and deny.toml:106 bans askama. See SEC-149-12 for the gap.
- SEC-149-3 fixed. scripts/validate-html.sh plus ci.yml:392-399. I ran the pinned jar with `--Werror` over both branch goldens and it exited 0. Three negative controls (a div inside a span, a bad CSS property, an unknown attribute) each exited 1. The jar is Java 11 bytecode, and the runner's Java 17 runs it.
- SEC-149-4 fixed as specified. The file name and fingerprint use Span::untrusted, and why, partial.summary, run_when and rdy_version are in `<bdi>`. The unwrapped fields left (summary_line, run_as, state, labels) are static or computed. See SEC-149-10 and SEC-149-11.
- SEC-149-5 fixed. html_report.rs:399-401.
- SEC-149-6 and SEC-149-7 are carried in correction-31. The Cargo.lock nit is fixed: the base64 change was reverted, and only askama and rustc-hash were added.

## The vnu-jar pin: acceptable, and the founder does not need a hand step
I checked it myself. The tarball sha256 is 3925f073...b7ab, which matches the script. Its sha1 and sha512 match `dist` in the registry. npm trusted publishing (OIDC) published it. I verified the SLSA v1 provenance bundle with cosign v3.1.4 against the Sigstore public root:
- identity: `https://github.com/validator/validator/.github/workflows/build.yml@refs/heads/main`
- issuer: token.actions.githubusercontent.com
- trigger: push
- workflow sha: 973e40b16d1c653cf52523b126ef92aec8bf9e0e
- Rekor log index: 3228121956 (2026-10-12)
The jar's manifest says `Implementation-Version: 26.10.12 (973e40b)`.

That signed chain is stronger than the GitHub release asset, which is an unsigned zip from the same project. Its hash is not even comparable to the tgz, and there is no promise that two builds of the inner jar are byte-identical. I could not reach the GitHub release either (the proxy returns 403). The tool runs only in CI and never ships in the binary.

## New findings
- SEC-149-8 low, scripts/validate-html.sh:14-18. The bump procedure compares the digest with an attestation that nobody verifies. The registry serves both, so the check is circular. Fix: make the procedure run `cosign verify-blob-attestation --bundle <slsa bundle> --type https://slsa.dev/provenance/v1 --certificate-identity https://github.com/validator/validator/.github/workflows/build.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com vnu-jar-<v>.tgz`. Put the commit and the Rekor index in a comment next to the pin. Record vnu-jar 26.10.12 (CI only) in 05 T4 or in "Dependency approvals".
- SEC-149-9 low, ci.yml:392-399. Third-party code runs inside the test job, and on main that job saves the rust-cache. The pin keeps this residual. Fix: move the step to its own `html-validator` job with checkout and Java only, no rust-cache, and `contents: read`. That also makes html_report.rs:7 true, because it names a job `html-validator` that does not exist.
- SEC-149-10 low, templates/report.html:8 and 12-progress. The product comes before the verdict in the title. 12-progress says it comes "after the verdict word". If the product contains U+2069, it closes our FSI early, and a U+202E after that reverses ", NOT READY". Fix: `<title>rdy report: {{ verdict_word }}, {{ title_product }}</title>`, then update html_report.rs:203,226 and the goldens.
- SEC-149-11 low, carry to M1-141 through correction-31. A U+2069 inside the text can break out of `<bdi>` too: CSS Writing Modes 3 section 2.4.2 says "bidi control codes in the source text are still honored". Fix: change view.rs:29 "cannot reorder" to "limits reordering; M1-141 escapes the controls". M1-141's tests must include `"x\u{2069}\u{202e}"`.
- SEC-149-12 low, deny.toml:106. Only askama is banned, but 05 says "none of them". Fix: follow the kube pattern and add `askama_macros` wrappers ["askama"], `askama_derive` wrappers ["askama_macros"], and `askama_parser` wrappers ["askama_derive"].
- SEC-149-13 nit, validate-html.sh:53. macOS has no `sha256sum`. `got` comes back empty and the error wrongly says "the download changed". Fix: fall back to `shasum -a 256` and refuse an empty digest. The INT and TERM traps should also `exit 1`.
- SEC-149-14 nit, 05:341. "in two places: four transmute calls... and one from_utf8_unchecked" is inconsistent. Say "in two files".

## Confirm 2, head 8912d5b (fix round 2)

Verdict: approve. SEC-149-8 to SEC-149-14 are fixed, and I found nothing new. CI on 8912d5b was queued when I checked. Merge on green ci-ok.

- SEC-149-8 fixed. The header of scripts/validate-html.sh now says nothing in the registry is trusted by itself. It gives the `cosign verify-blob-attestation` command with the pinned identity and issuer; I ran exactly that form on 26.10.12 earlier and it printed Verified OK. It records commit 973e40b and Rekor index 3228121956 next to the pin. 05 has a vnu-jar entry: CI only, never shipped, no deny.toml or lockfile entry, and every bump runs cosign.
- SEC-149-9 fixed. ci.yml has its own `html-validator` job. It has checkout (SHA-pinned v7.0.1, `persist-credentials: false`) and a run step, with no rust-cache, no cargo, `contents: read` and `timeout-minutes: 10`. The step is gone from `test`. ci-ok `needs` it and requires every result to be success. 06's job table lists it, and html_report.rs:7 now matches.
- SEC-149-10 fixed. The title is now `rdy report: NOT READY, ⁨acme-platform⁩`, with the verdict first. The goldens and html_report.rs:203,226 are updated, and 12-progress now matches.
- SEC-149-11 fixed in this PR. The view.rs Span doc now says `<bdi>` limits reordering, a U+2069 can close it, and M1-141 escapes the controls. Carry: correction-31 is not written on the branch or on main yet. When the coordinator files it, M1-141's tests must include `"x\u{2069}\u{202e}"` in a banner span, a `<bdi>` field and the title.
- SEC-149-12 fixed. deny.toml bans askama_macros (wrappers askama), askama_derive (wrappers askama_macros) and askama_parser (wrappers askama_derive), and 05 says so.
- SEC-149-13 fixed. There is a shasum fallback, an empty digest is refused with a fix hint, `trap 'exit 1' HUP INT TERM` is separate from the EXIT cleanup, and curl has `--connect-timeout 20 --max-time 300`. shellcheck is clean. I ran the script end to end under dash from a scratch tree: it exited 0 with "ok: 2 file(s) pass", and a missing file gave 64.
- SEC-149-14 fixed. 05 now says "in two files".
- Spans. Only text from the report is untrusted: file name, fingerprint, need names, `missing_grants`, and an unknown need kind (also marked untrusted, which is right). Our own words (Missing:, Checked in part..., Requires:, (not available), the commas) stay outside `<bdi>`. The unit and integration tests prove the split with U+202E inputs. The capabilities cell still wraps the whole label in one `<bdi>`, which is harmless because the cell holds only that label.
- Validator on the new goldens. I fetched the tarball again (sha256 matches the pin) and ran `--Werror` over both round-2 goldens. Exit 0.
