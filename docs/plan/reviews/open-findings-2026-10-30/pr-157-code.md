# PR #157 cold review (code-reviewer), head 39f45ca

Verdict: approve with fixes (no critical or high).

What I checked myself, on a scratch export of the branch:
- `dist plan --output-format=json` (dist 0.33.0): all five archives list NOTICE (kind `unknown`) next to LICENSE, README.md, CHANGELOG.md and the binary.
- `scripts/gen-release-workflow.sh --check`: passes. The `include` key does not change release.yml.
- `scripts/test-check-release-artifacts.sh`: 20 of 20 pass, including "an archive without NOTICE fails". `fresh` builds a full passing set first, so the case fails only on the missing NOTICE.
- `cargo package --list` for rdy, rdy-spec, rdy-engine and the three check crates: each lists LICENSE and NOTICE.
- No em dashes, no competitor names and no old name in the new text. CI: deny, dco, release-workflow and zizmor pass. The test legs and lint were still running.

## Findings

1. Medium. TRADEMARKS.md:37-39 contradicts SECURITY.md:37. SECURITY.md accepts security reports at security@getrdy.io. TRADEMARKS.md says "Please do not send security reports there." That can turn a reporter away. Fix: replace the last two sentences with "It is the same inbox as security reports, so the subject line matters."

2. Medium. crates/rdy-cli/tests/license.rs:1-2 says the copies exist "so `cargo package` includes them". The test only checks that the file exists and matches the root file. A crate whose `include` leaves out NOTICE still passes. Fix: in the same loop, skip `publish = false` manifests, find the `include = [` line and assert it has `"LICENSE"` and `"NOTICE"`. A string check is enough. rdy-cli has no `toml` dev-dependency.

3. Low. TRADEMARKS.md:26 "A fork must use a different name" also covers the GitHub forks contributors use for PRs. Those are all named `rdy`. Fix: "A fork that you publish or distribute as its own project must use a different name."

4. Low. TRADEMARKS.md:12-13 counts only the GitHub release archives as official. Crates on crates.io and distro packagers who build an unmodified tag from source are not covered. Fix: name the crates.io crates as official too. Add "Package an unmodified tagged release under the name rdy, with only the changes your package system needs to build it. Say where it came from."

5. Low. NOTICE:7 (and all six crate copies) says "See TRADEMARKS.md". Crates and release archives do not ship that file. Fix: use https://github.com/getrdy-io/rdy/blob/main/TRADEMARKS.md.

6. Low. NOTICE:6-7 and TRADEMARKS.md:3-4 state section 6 without its exception. Section 6 allows use of the name to describe where the Work came from and to reproduce NOTICE. Nothing conflicts with the license, but the text overstates it. Fix: "...does not grant permission to use them, except to say where the code came from (section 6)."

7. Nit. TRADEMARKS.md:19 uses "Rdy-Cloud" as an example of a confusing name, but the project's own portal is "Rdy Cloud". Fix: use "RdyCheck".

8. Nit. scripts/test-check-release-artifacts.sh:216 expects "FAIL ... holds its files". Fix: match "missing: NOTICE" to tie the failure to its cause.

9. Nit. docs/plan/10-devrel-and-launch.md:565 lists the repo hygiene files. Fix: add NOTICE and TRADEMARKS.md.

## Notes (no change needed in this PR)
- There is no backlog ticket, so there is no 12-progress line. The `legal-notice` fragment slug follows ADR 0017.
- The owner of the copyright and the marks: superseded. The founder chose Apostolic Path LLC (2026-10-30), and the PR now says so.
- I could not delete my scratch export (permission denied): scratchpad/r157src and scratchpad/r157tgt.

## Confirm (fix round 4e0b9fc)

Read `git diff 39f45ca 4e0b9fc` in a scratch clone. All nine findings are fixed. I found nothing new.

1. Fixed. TRADEMARKS.md:43 now reads "It is the same inbox as security reports, so the subject line matters." It no longer contradicts SECURITY.md.
2. Fixed. license.rs adds `every_published_crate_includes_license_and_notice`. It skips `publish = false` and needs `"LICENSE"` and `"NOTICE"` on the `include` line, for at least 6 crates. A manifest with no `include`, or with `include` over several lines, fails loudly. That is safe. rustfmt 1.9 `--check --edition 2024` passes on the file.
3. Fixed. The rename rule now covers only a fork "that you publish or distribute as its own project". A fork used for a PR can keep the name.
4. Fixed. The crates.io crates count as official. There is a new bullet for packaging an unmodified tag with build-only changes.
5. Fixed. NOTICE now links the full TRADEMARKS.md URL. All seven crate copies match the root file byte for byte.
6. Fixed. NOTICE and TRADEMARKS.md:4-5 now state the section 6 exception.
7. Fixed. The example is now "RdyCheck".
8. Fixed. The self-test now matches "missing: NOTICE". Ran the full script on a full checkout: exit 0, and "an archive without NOTICE fails" passes.
9. Fixed. 10-devrel line 565 lists NOTICE and TRADEMARKS.md.

New text: no em or en dashes, no competitor names, short sentences. The commit has a Signed-off-by line. CI on 4e0b9fc had only just queued when I checked.

Verdict: approve.

Scratch: the clone c157 is deleted. r157src and r157tgt (listed under Notes above) are also gone now.
