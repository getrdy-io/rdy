# Review of 06-release-and-distribution.md by code-reviewer

Reviewer: code-reviewer (did not write the document). Date: 2026-10-27. Reviewed: the version at commit
`ad72266` (Worker route for `getrdy.io/install`, stub `curl` in tests). Cross-checked against CLAUDE.md,
KICKOFF.md, rdy-plan.md, `05-threat-model.md` and ADRs 0006, 0007, 0009 and 0011.

## What holds up

- Coverage of KICKOFF item 7 is complete. CI matrix, dist config, cosign, SBOM, install.sh, Homebrew,
  winget, apt and yum, self-update and version policy each have a section.
- Runner labels are right: `ubuntu-24.04-arm` is free for public repos, `macos-15` is arm64,
  `macos-15-intel` is the last Intel image, `macos-13` is retired. Private-repo math is right
  (2,000 minutes, Windows 2x, macOS 10x).
- dist facts are right: renamed from cargo-dist, `dist-workspace.toml`, `[dist.github-custom-runners]`,
  `./`-prefixed custom jobs, `post-announce-jobs`, `HOMEBREW_TAP_TOKEN`.
- The `cosign verify-blob` shape is right, including the point that a reusable workflow's certificate
  identity is the called file (`sign-release.yml`), not `release.yml`.
- install.sh design is mostly sound: `main` on the last line, fail-closed signature, no `sudo`, no
  profile edits, Rosetta detection, atomic `mv`, stdout empty, one error shape.
- No em dashes. The old working name does not appear. No competitor names.

## Findings

### Must fix

1. **Tickets implied, lines 434 to 450: M1 release work is about twice the budget.** 17 M1 tickets,
   46 hours (16 for release-engineer, 45 hours). All of M1 is 60 to 90 founder hours. Worse,
   `05-threat-model.md` lists SEC-01, 02, 03, 05, 06, 07, 08, 09, 10, 11 (about 26 hours) for the same
   work, and ADR 0006 and ADR 0007 add "Prove static musl binaries" and "cargo-semver-checks"
   (4 hours). If the backlog takes all three at face value, release work is about 75 hours of M1.
   Fix: cut to the eight tickets below (24 hours), and write the SEC id each one closes into its title
   so the backlog counts it once.

   | Keep in M1 | Merges | Est |
   | --- | --- | --- |
   | CI lint and deny: fmt, clippy, doc, cargo-deny | SEC-01 | 2h |
   | CI test matrix on five native runners with ci-ok gate and static-link check | ci-ok ticket, ADR 0006 static musl ticket | 4h |
   | Rulesets on main and v* tags, Dependabot, SHA-pinned actions | repo settings ticket, pinning half of SEC-03 | 1h |
   | dist init: five targets, cargo-auditable and SBOM flags, tested in a sandbox repo | auditable and SBOM ticket, minus reproducibility | 3h |
   | sign-release with cosign keyless and a self-verify step | SEC-06, SEC-07 | 4h |
   | First signed alpha, scripts/verify-release.sh and a one-page RELEASING.md | runbook ticket | 2h |
   | install.sh core: detection, root refusal, sha256, install dir, with its shell tests | SEC-08, half of SEC-10 | 4h |
   | install.sh signature check with pinned cosign, with tamper tests | SEC-09, rest of SEC-10 | 4h |

   Move to M2: crate name reservation (ADR 0007 says the first publish is M2), audit.yml and zizmor
   (the `deny` job already checks advisories on every PR), the MSRV job (MSRV only matters to
   `rdy-cloud`, which starts in M2), `dist-check` (dist's own `plan` job fails on a stale `release.yml`
   when `pr-run-mode = "plan"`), `release-smoke`, reproducibility flags, the post-release verify job,
   the Worker at `getrdy.io/install`, cargo-semver-checks, and the `rdy self-update` stub (cli-ux can
   leave the subcommand out until then). M1 design partners install from the release URL, pinned to
   the alpha the SE tested:
   `curl --proto '=https' --tlsv1.2 -sSfL https://github.com/getrdy-io/rdy/releases/download/v0.1.0-alpha.N/install.sh | sh`.

2. **install.sh and signing contract conflicts with `05-threat-model.md`.** The two documents
   disagree on almost every interface:

   | Item | 06 | 05 |
   | --- | --- | --- |
   | No cosign on the host | download a pinned cosign (line 286) | stop and print the manual path (05 line 200) |
   | Signature opt-out | `RDY_VERIFY=checksum` (line 272) | `RDY_INSECURE_SKIP_SIGNATURE=1` |
   | Root opt-in | `RDY_ALLOW_ROOT=1` | `--allow-root` (INV-18, SEC-08) |
   | Signing identity | `sign-release.yml` | `release.yml` |
   | What is signed | every asset | `SHA256SUMS` only |
   | Checksum file name | `sha256.sum` | `SHA256SUMS` |
   | Immutable releases | fallback rules them out (line 144) | required in M1 (T3) |
   | Release job approval | none | GitHub environment with a manual approval click (E2) |

   Fix: 06 owns the contract. Add one table like the one above with the chosen values and have 05 refer
   to it. Suggested picks: `RDY_ALLOW_ROOT=1` (KICKOFF asks for it, and `curl | sh` cannot pass a flag
   without `sh -s --`); the pinned cosign download; the opt-out named `RDY_INSECURE_SKIP_SIGNATURE=1`
   (the name says what it costs); identity `sign-release.yml`; dist's real checksum file name; a
   `release` environment with required approval on the signing job. Also record under Plan
   corrections that 05's identity regexp (05 line 210) ends in `[0-9]+$` and so rejects every
   `-alpha.N` tag, which is every M1 release.

3. **Air-gapped alternative, lines 301 and 302, and the M2 ticket on line 452: the offline trust root
   is circular.** `sigstore-trusted-root.json` is "a release asset we publish". An attacker who can
   replace release assets replaces the archive, its bundle and the trusted root together. The bundle
   is then signed by the attacker's CA and passes `--trusted-root`. Fix: never take the trusted root
   from our own release. On the connected machine, use the root cosign fetched through Sigstore's TUF
   (cached under `~/.sigstore/root/`, or wherever `TUF_ROOT` points) and carry that file across. If we
   ever publish a copy, its sha256 must be pinned somewhere the release cannot change.

4. **Version and support policy, lines 345 and 348, and the crates.io row on line 320: contradicts
   accepted ADR 0007.** 06 says one shared version in `[workspace.package]` and `cargo release`. ADR
   0007 says independent per-crate versions with `release-plz`, and that every crate is published so
   `cargo install rdy` works. 06 publishes only `rdy-spec` and `rdy-engine`. Fix: follow ADR 0007.
   The binary tag `v*` follows the `rdy` package version only. Drop `cargo release` from the runbook.
   Drop the "Reserve crate names" ticket, which also duplicates SEC-11 and ADR 0007's placeholders.
   The ticket's "the other six names" is also wrong: CLAUDE.md has nine crates, so five others.

### Should fix

5. **sign-release.yml step 1, line 136: permissions will not be granted.** A called workflow cannot
   get more than its caller. dist gives custom publish jobs `{ id-token = "write", packages = "write" }`
   by default, with no `contents: write`, so `gh release upload` fails. Fix: add
   `[dist.github-custom-job-permissions]` with `sign-release = { contents = "write", id-token = "write" }`
   to the config block (overriding drops the defaults, so list both) and say so in the ticket.

6. **Static-link check, lines 21, 22, 229 and the test-matrix exit test on line 437.** Since Rust 1.59
   the musl targets build static-pie by default. `file` prints "static-pie linked", not "statically
   linked", and `ldd` on static-pie varies by glibc version. The exit test as written fails on a
   correct binary. Fix: fail if `readelf -lW rdy` shows an `INTERP` header or `readelf -d rdy` shows a
   `NEEDED` entry, then run the binary in a `scratch` container (ADR 0006). If `ring` needs a C
   compiler, set `CC_<target>` only. Never set the linker to `musl-gcc`: its wrappers do not handle
   static-pie.

7. **SBOM section, lines 217 and 265: dist's SBOM is per package, not per target.** dist's
   `cargo-cyclonedx = true` makes one SBOM per package. cargo-cyclonedx also defaults to XML and to
   the host target. The fallback, "one explicit `cargo cyclonedx` step in `sign-release`", contradicts
   "No checkout of repo code" on line 136. Fix: in M1, ship the one SBOM dist makes, signed, and fix
   the asset table. If per-target SBOMs are wanted later, generate them in `sign-release` from each
   shipped binary with `auditable2cdx` (from the cargo-auditable project). That needs no checkout and
   describes the bytes we ship.

8. **Lines 31 and 369: `RUSTFLAGS` drops the Windows static CRT setting.** Cargo uses the first rustflags
   source it finds: `RUSTFLAGS` in the environment wins over `.cargo/config.toml`, and nothing is merged.
   Setting `RUSTFLAGS` for `--remap-path-prefix` silently drops `+crt-static`. dist already sets static
   CRT itself (`msvc-crt-static` defaults to true). Fix: remove `crt-static` from `.cargo/config.toml`,
   rely on dist, keep all extra flags in one place, and add a release check that `rdy.exe` does not
   import `VCRUNTIME140.dll` (`objdump -p` or `dumpbin /dependents`).

9. **Line 283 and the Worker on line 308: version resolution leans on the GitHub API.** The Worker now
   runs the same resolution from Cloudflare's shared egress IPs. Without a token that is 60 requests an
   hour per IP, so busy hours will fail. install.sh also sends any `GITHUB_TOKEN` it finds in the
   environment, which may be a CI token with write scope. With write scope, `releases?per_page=1` can
   return a draft. Fix: the Worker resolves the newest release that has `install.sh.sigstore.json`,
   caches it for five minutes, and writes that version into the script it serves
   (`RDY_DEFAULT_VERSION=...`). install.sh then makes no API call and never reads `GITHUB_TOKEN`. This
   also undercuts the reason given against option (c) on line 423.

10. **Line 286: pin the exact identity in install.sh.** The script knows the version it asked for, so
    it can pass `--certificate-identity ...sign-release.yml@refs/tags/v$VERSION`. The regexp accepts any
    tagged release, so a hostile mirror or proxy can serve an older signed release with a known bug.
    Keep the regexp for humans who verify by hand.

11. **Line 286: a missing signature is not an attack.** In the publish window (fallback ordering on
    line 144) a customer gets "do not run this file, report it to security@getrdy.io". Fix: two
    messages. A missing bundle says "this release is still publishing, retry in ten minutes". A bad
    bundle keeps the security wording.

12. **Line 308: the Worker token does not belong in GitHub.** The Worker is "deployed once", yet its
    token lives in a GitHub Environment. Fix: deploy it from the founder's machine with
    `wrangler login`. Keep no Cloudflare secret in Actions until CI deploys it, which is not planned.

13. **dist init exit test, line 440.** Pushing `v0.1.0-alpha.1` "on a test branch" in the real repo
    makes a permanent public unsigned prerelease (the tag ruleset forbids delete) and burns alpha.1.
    The First alpha and install.sh core tickets also claim alpha.1. Fix: test in a throwaway repo
    (`getrdy-io/release-sandbox`, as SEC-06 already says), and make alpha.1 the first signed release.

14. **ci-ok, line 47.** It `needs:` "all of the above", which includes `release-smoke`. That job is
    skipped on PRs, and a job is also skipped when one of its needs fails. Fix: list only the gating
    jobs in `needs:` and fail on any result other than `success`.

15. **Dangling references and stale text.** "The spike ticket" (line 32), "tickets 3 and 7" (line 390)
    and "Release runbook" do not match any ticket title. `release-smoke` and the six-weekly toolchain
    bump have no ticket. Line 231 still asks rust-architect about ring versus aws-lc-rs. ADR 0009 has
    decided that, and `deny.toml` bans `aws-lc-sys`. Fix: name real tickets, cite ADR 0009, and add a
    Plan correction that ADR 0011's `rdy-<target>.tar.xz` should say `.tar.gz` (line 185).

16. **Length: 7,700 words reads in about 30 minutes, not 15.** The body is about 5,500 words and the
    tail (corrections, ADRs, tickets) about 2,200. Fix, aiming for a 3,000-word body:
    - Move to an appendix: the `ci.yml` skeleton, the caching notes and time table, the full dist
      config block, the archive table, the reproducibility deviations table.
    - Cut to one line each: dist ownership history (line 164; the uv fork is trivia), the musl section
      (point to ADR 0006 and 0009), cost (one sentence plus "Total new spend in M1: $0"), and the
      macOS and Windows signing paragraph.
    - Move the M3 self-update design (lines 333 to 338) into the self-update spike ADR.
    - Shrink the M3 to M5 package-manager rows to one sentence each.
    - Trim Plan corrections that repeat 05 (the specs-not-cosign item).
    - The eight-ticket M1 list in finding 1 saves another 400 words.

17. **Exit tests that cannot be observed inside the ticket.** "Three consecutive warm runs under ten
    minutes" (line 438) is trivially true in week 1, when there is almost no code. "Dependabot opens
    its first PR" (line 434) waits on a weekly schedule. The audit ticket's issue-on-failure
    (line 439) runs only on cron, per the table on line 152, but the exit test uses
    `workflow_dispatch`. The reproducible-hash check sits in an M1 ticket (line 441) while the text
    calls reproducibility M2. Fix: "the Dependabot job runs green in Insights", "issue opens on
    dispatch too", and move the hash check to the M2 repro ticket.

### Nits

18. Line 238: "PRs in October 2026 make bundle-only verification mandatory" is unsourced. Drop it.
19. Line 162: `dist-workspace.toml` became the default in 0.23, but `[workspace.metadata.dist]` is still
    read. Say "new default", not "moved".
20. Line 326: the `brew upgrade rdy` hint is dead code in M1, since there is no tap until M3.
21. Line 359: check the aarch64 kernel floor against Rust's platform-support page. It lists a newer
    kernel than 3.7 for aarch64 Linux.
22. Line 317: `RdyLabs.Rdy` assumes the entity name. Rdy Labs LLC is still pending (CLAUDE.md), so
    confirm before the first submission.
23. Lines 144, 163, 164, 206, 317, 322: first-person "I am not sure" and "I could not". State the
    fact, then the ticket that settles it.
24. Line 283: `RDY_VERSION=alpha` overloads a version variable. Use an explicit
    `RDY_CHANNEL=prerelease`, or drop it once finding 9 lands.
25. Line 286: set `TUF_ROOT` to the temp directory so cosign leaves no `~/.sigstore` behind. That
    matches the "touches nothing outside the install dir" spirit.
26. Line 295: with stub `curl` and stub cosign, CI never runs real verification before a release.
    Make sure the M2 post-release job runs on one host without cosign, so the pinned-download path
    runs for real. Note the download size (cosign v3 is about 30 MB compressed) in the ADR on line 423.

## Verdict

Request changes. Four must-fix items: the M1 hour budget, the contract conflicts with 05, the circular
offline trust root, and the conflict with ADR 0007. The technical core is sound. Findings 5 to 8 are
small edits that save debugging time in the first release week.
