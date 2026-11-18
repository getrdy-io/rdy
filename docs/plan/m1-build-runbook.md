# M1 build runbook

This file lets a new coordinator session resume the M1 build where the last one paused. Read it after
`CLAUDE.md`, `docs/plan/00-overview.md`, `docs/plan/11-backlog.md` and `docs/plan/12-progress.md`.
`12-progress.md` is the record of what merged. This file is the record of how the work runs and what was in
flight at the pause.

## The founder's rules for the build

These are the founder's instructions for M1, kept here so they survive a session reset.

- Read CLAUDE.md, 00-overview.md, 11-backlog.md and the design doc each ticket points to before that ticket.
- Use the subagents in `.claude/agents/` as the backlog assigns them. The coordinator never does a
  subagent's job. Run independent tickets in parallel.
- One branch and one PR per ticket, ticket id in the title. Before opening each PR run `cargo build`,
  `cargo test`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check` and
  `cargo deny check`.
- Cold review from code-reviewer on every PR. Add security-reviewer when the ticket touches privileges,
  network, redaction, signing or install.sh. Fix every high or critical finding.
- Squash-merge green PRs only. Never merge a red PR.
- Keep `12-progress.md` current: one line per ticket (id, PR link, merged at, deferrals and why), updated in
  the PR that completes the ticket.
- A ticket that is wrong or impossible as written gets the smallest correction in `11-backlog.md`, in its own
  PR, noted in `12-progress.md`. Do not improvise.
- When a decision cannot be made safely, take the most conservative option, write an ADR, keep going.
  Never wait for the founder. The founder is not answering questions during the build.
- Never commit secrets. Fixtures are synthetic. The product's old working name must not appear anywhere.
  No competitor company or product names anywhere.
- If a tool call is blocked and no allowed route exists, note it in `12-progress.md` and move on.

Done means: every M1 ticket merged and CI green on main; `cargo install --path crates/rdy-cli` builds;
`rdy run examples/specs/acme-platform.yaml` gives the expected report against the fixtures; `rdy verify`
rejects a tampered spec; `12-progress.md` summarizes what shipped and what moved to M2 and why. The final
reply to the founder gives that summary, the install command a design partner runs, and the three decisions
the founder should look at.

## How one ticket runs

1. Pick tickets whose dependencies are merged (the `depends on` column in `11-backlog.md`, and the
   dependency table at its end). Take them in id order, as "How to work the backlog" says, and run the
   ones that do not depend on each other in parallel, as the founder's rules allow.
2. Launch the backlog owner as a background agent with `isolation: worktree` and the implementer brief
   below, adding the ticket id, branch name and any carried notes for that ticket.
3. When it reports, open the PR from its branch. Title `M1-NNN: <summary>`. Body: what changed, exit test
   and proof, check output, deferrals. Run `fill.sh` on its worktree first so the progress line carries the PR
   number and date.
4. Launch code-reviewer (and security-reviewer where the rules say so) read-only on the PR diff.
5. Send high and critical findings back to the same implementer (SendMessage to its agent id if it is still
   reachable, or a fresh agent of the same role with the findings). Mediums: fix when cheap, else carry them
   as a note to the ticket that owns them (list below). Re-review after the fix round.
6. Wait for `ci-ok` on the head (`wait-ci.sh <sha>` in the background). Then post one review-record comment
   on the PR (who reviewed, verdict, what was fixed, what was carried) and squash-merge with this message
   ending:

   ```text
   Signed-off-by: Rdy <dev@getrdy.io>
   Co-Authored-By: Claude <model name> <noreply@anthropic.com>
   Claude-Session: <the coordinator session URL>
   ```

7. When main moves under an open PR: merge main into the branch, resolve `Cargo.toml` by taking the union of
   both sides, run `git checkout origin/main -- Cargo.lock` and let `cargo build` refresh it, run every
   check (plus `cargo run -p xtask -- docs --check` and `docs-lint`), push. A PR whose `mergeable_state` is
   `dirty` gets no CI run at all, so a missing CI run usually means a conflict.

### Environment facts

- Toolchain 1.99.1 from `rust-toolchain.toml`, MSRV 1.97, sccache wraps rustc. The machine has 4 CPUs, so
  run at most three or four implementers at once.
- Resolve action SHAs with `git ls-remote --tags https://github.com/<owner>/<repo>`. The proxy serves
  anonymous reads of public repos. `api.github.com` answers for this repo only.
- `curl https://api.github.com/repos/getrdy-io/rdy/...` works for check runs and PR state.
- The proxy rejects remote branch deletes. Leave merged branches for the founder.
- Reviewer agents cannot commit. Record their verdict in the review-record comment, never commit on their
  behalf.
- Agents refuse to edit `CLAUDE.md`. In M1-009 the coordinator applied the architect's exact text, and the
  founder is asked to look at that. Do not do it again: if a ticket needs a CLAUDE.md change, the architect
  writes the exact text, it goes into `12-progress.md` as a founder hand step, and the build keeps going.

## Implementer brief

Every implementing agent gets this text, plus the ticket id and branch name.

```markdown
# M1 build brief for every implementing subagent

You implement exactly one M1 ticket from docs/plan/11-backlog.md. The coordinator gives you its id.

Read first, completely: CLAUDE.md, your role file in .claude/agents/, the ticket's row in
docs/plan/11-backlog.md (title, depends on, exit test), the design doc sections the ticket names or implies
(docs/plan/00 to 10 and docs/adr/), and docs/plan/00-overview.md for crate boundaries. The planning docs are
approved. Build what they say. Do not widen the ticket.

## Where you work
- You are in your own git worktree. Run `git fetch -q origin main && git checkout -q -B <branch> origin/main`
  where <branch> is `m1/<NNN>-<short-slug>` (e.g. m1/003-workspace-skeleton).
- Never touch the coordinator's checkout (/home/user/rdy) and never push to main.
- Commit as `Rdy <dev@getrdy.io>` (the repo's git config; never override it), in imperative mood, with a
  one-line summary that starts with the ticket id, e.g. `M1-003: create workspace skeleton`. End every
  commit message, merges included, with these three lines:
  Signed-off-by: Rdy <dev@getrdy.io>
  Co-Authored-By: Claude <your model name> <noreply@anthropic.com>
  Claude-Session: <the coordinator session URL>
- Push with `git push -q -u origin <branch>`. Do not open the PR; the coordinator does.

## Every ticket must
- Pass, from the worktree root: `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, `cargo deny check`,
  `cargo run -q -p xtask -- docs --check` and `cargo run -q -p xtask -- docs-lint`.
  Paste the last lines of each into your reply. A red check means you are not done.
- Add a changelog fragment `changelog.d/M1-NNN.md` (one or two lines, user-facing wording) unless the
  ticket is docs-only plan bookkeeping.
- Update your ticket's line in docs/plan/12-progress.md to: `- M1-NNN | PR #TBD | | <deferrals and why, or none>`.
  Change only your own line. The coordinator fills in the PR number and date.
- Update docs touched by the change in the same branch.
- Keep tests deterministic and fixtures synthetic. Never commit secrets, real hostnames of real companies,
  or real specs.
- No em dashes anywhere, short sentences, the product's old working name never appears, no competitor
  company or product names anywhere (describe by category). `#![forbid(unsafe_code)]` in every crate.

## If the ticket is wrong or impossible as written
Do not improvise. Stop, push nothing that pretends to satisfy it, and reply with: what is wrong, the smallest
correction to the ticket row, and what you could safely build now. The coordinator files the correction.
If you must choose between options and cannot decide safely, take the most conservative one and write a
short ADR in docs/adr/ (next free number, same format as the others, add it to docs/adr/README.md).

## Tools you lack
You cannot open PRs, read CI, or change GitHub settings. If the ticket needs a GitHub setting, an account you
do not have, or a human, build every repo-side part (scripts, checklists, docs), and list the remaining
manual steps in your reply and in your 12-progress.md line as a deferral.

## Reply format (under 250 words)
Branch and head commit SHA, files changed, the exit test and how you proved it, the check command results,
deferrals, and anything the reviewer should look at hard.
```

## Coordinator scripts

Save these in the session scratchpad. They are not part of the product.

`fill.sh <worktree> <ticket-id> <pr-number>` writes the PR link and date into the ticket's progress line,
commits and pushes:

```sh
#!/bin/sh
# usage: fill.sh <worktree> <ticket-id> <pr-number>
set -e
cd "$1"
d=$(date -u +%F)
python3 -I - "$2" "$3" "$d" <<'PY'
import sys
t,n,d=sys.argv[1:4]
p='docs/plan/12-progress.md'; L=open(p).read().split('\n')
for i,l in enumerate(L):
    if l.startswith(f'- {t} |'):
        parts=[x.strip() for x in l[2:].split('|')]
        rest=' | '.join(parts[3:]) if len(parts)>3 else 'none'
        L[i]=f'- {t} | [#{n}](https://github.com/getrdy-io/rdy/pull/{n}) | {d} | {rest}'
        break
else: sys.exit('line not found')
open(p,'w').write('\n'.join(L))
PY
git add docs/plan/12-progress.md
git commit -q -m "$2: record PR #$3 in progress tracker

Signed-off-by: Rdy <dev@getrdy.io>
Co-Authored-By: Claude <model name> <noreply@anthropic.com>
Claude-Session: <the coordinator session URL>"
git push -q
grep "^- $2 |" docs/plan/12-progress.md
git rev-parse --short HEAD
```

`wait-ci.sh <sha>` polls the `ci-ok` gate for a commit and prints `ci-ok <conclusion> <sha>`. Run it in the
background:

```sh
#!/bin/sh
sha=$1; n=0
while [ $n -lt 120 ]; do
  out=$(curl -s --max-time 15 "https://api.github.com/repos/getrdy-io/rdy/commits/$sha/check-runs?check_name=ci-ok" || true)
  c=$(printf '%s' "$out" | python3 -I -c 'import sys,json
try:
  d=json.load(sys.stdin); r=[x for x in d.get("check_runs",[]) if x["status"]=="completed"]
  print(r[0]["conclusion"] if r else "")
except Exception: print("")')
  if [ -n "$c" ]; then echo "ci-ok $c $sha"; exit 0; fi
  n=$((n+1)); sleep 20
done
echo "ci-ok timeout $sha"
```

## State at the pause (2026-11-06)

The fifth coordinator session paused here at the founder's request. Read this section and
`reviews/open-findings-2026-11-06/pending-fixes.md`, then check every open PR's head and CI before acting.
Every agent was stopped at the pause. The briefs, fix lists and coordinator scripts for the resume are in
`reviews/open-findings-2026-11-06/`. They carry `<the coordinator session URL>` and `<scratchpad>`
placeholders, which the next session fills in.

**Identity.** The 2026-10-31 rule is unchanged. Every commit is authored and committed as
`Rdy <dev@getrdy.io>`. Every commit message, merges too, ends with `Signed-off-by: Rdy <dev@getrdy.io>`, a
`Co-Authored-By` line and the coordinator's `Claude-Session` URL. Set it first in a new container:
`git config user.name Rdy && git config user.email dev@getrdy.io`. `get_me` returned `getrdy-io` all session.
Squash merges are authored `getrdy-io <dev@getrdy.io>`. Never rewrite pushed history. A subagent writes its
own model name in `Co-Authored-By`; the brief now says so.

**Ownership.** Apostolic Path LLC owns the code, the copyright and the marks (NOTICE and TRADEMARKS.md on
main). No document may name a person as owner, and no document may mention the founder's employer.

**Merged in this session** (main at 3c49a5a), in merge order:
- #31 correction-35, #18 M1-174, #33 correction-36, #20 M1-149, #19 M1-078, #36 correction-37.
- #37 fixes main after #36. #36 changed 03 Appendix A rows that a test pins.
- #21 M1-079, #38 correction-38, #32 M1-161, #40 correction-39, #34 M1-176, #22 M1-080.
- #44 M1-124, #43 correction-40, #46 correction-41, #23 M1-150, #25 M1-072, #42 M1-086.

**Progress.** 119 of 178 M1 tickets are merged on main: 111 of 148 core and 8 of 30 non-core. #24 adds
M1-177 and M1-178, which makes 180, and correction-45 adds M1-181. Totals after correction-34 and
correction-57: M1 184 tickets, 408.5 h, 342 h core; M2 145 tickets, 492.75 h; all milestones 429 tickets,
1414.75 h, 1348.25 h core.
Recompute with `python3 -I totals.py < docs/plan/11-backlog.md`.

**Corrections filed in this session:**
- 35: M1-148 drops adjtimex. `NativeCall::Adjtimex` moves to M2-004.
- 36: M1-175 builds k8s.namespace. New M2-116 (`limit_needs`) and M2-117 (OpenShift namespace reads).
- 37: `chronyc -n -c tracking`, with no `-t`. time_sync gets a step budget. The INV-11 local IPC exception
  and a forged-SNTP T5 row.
- 38: new M1-179 (env harness bounded hang), M2-118 (the watchdog report keeps the action log) and M2-119
  (parallel SNTP). M1-130 takes three carries.
- 39: `--no-network` is an allow-list: only AF_UNIX sockets from rdy or its children. firewall-cmd's local
  IPC is named. chronyc does not run offline. The facade refuses network calls.
- 40: the unsigned banner may name `--allow-unsigned`. M1-126's rule covers only hint, fix and error lines.
- 41: new core M1-180 (`report.host.os` from os-release) and M2-120 (`ProductSlug` refuses `rdy`).
- 42: the print banners stay in the flow with the title in the top margin of every page; the HTML size cap
  cuts action rows, then Found and Needed lines. M1-175 builds k8s.dns. New M2-121 to M2-125.
- 43: records and approves the 03 changes of #64 (k8s.crds reads discovery) and #65 (k8s.ingress). M1-175
  builds k8s.crds and k8s.ingress. Two k8s verdicts go to the founder. New M2-126 and M2-127.
- 44: records #68's decisions (M1-143). The run header prints at the end, so `--verbose` event lines come
  before it. `--verbose` turns the live line off (M1-142's exit test), in the second of #60 and #68 to merge.
  A full stderr pipe under `--verbose` ends in the watchdog (07 5.2). New M2-128 moves the header earlier.
- 45: new core M1-181: `rdy run` writes the HTML report next to the JSON, and M1-138 depends on it. M1-100
  takes #71's deferrals (pins, the generated-chain rig, the Timeout case) and grows to 3.5 h. M1-101 moves
  to week 21.
- 47: records and approves the 03 changes of #78 (k8s.cni reads DaemonSets by name only, unknown is partial,
  default-deny is 03's). M1-175 builds k8s.cni. New M2-129: plugin pod restarts, ready below desired and a
  live check of the unverified `cni.toml` entries.
- 48: the env harness skips Linux envs on macOS and Windows (M1-086), so M1-117, M1-138, the done test and
  08 say the Linux legs; PC-53 for the plan. New M2-130: a `RunHooks` OS override. M1-107 adds k8s.version
  and the `api/` tree to `all-pass` and regenerates its goldens (4 h; M1-117's if it is not merged first).
- 50: `--key` needs a signature; the unknown-key line shows the key id, not a fingerprint (01, 07 C.5). The
  `--allow-unsigned` page is M1-181's. 05 Surface 2 lists the `--key` file swap for M1-132. M1-098 builds
  the `auto` "direct works, proxy fails" sentence. M1-107 never uses an `HTTP_PROXY` proxy for https and
  takes the slow `/version` case of `timeouts`. The black hole gives Block. M2-037 takes the cancellation tests (4 h).
- 51: new core M1-182: host.container_runtime stores a proxy as `ProxyUrl::origin`, so a password in a URL
  with no scheme never reaches the report, plus a `url_userinfo` form for it; M1-138 depends on it. 05 INV-11
  names the proxy lookup, `proxy_reach` and the direct retry. M1-107 checks `proxy_source` itself. 03 net.proxy
  reads `daemon.json`.
- 52: no new M1 ticket. M1-100 pins match the leaf only, and its net.tls_intercept `PENDING` row moves to
  M1-179 as `Timeout`. 05 T3 gains the JSON control rule. New M2-131 to M2-136: JSON escapes, the fix
  `<bdi>` override, `FixText` controls, the Java and Node stores, the verified path, the real anchor.
- 53: new core M1-183: every spec read goes through `signing::files::read_public`, so a FIFO or
  `/dev/zero` exits 64 within 1 s, and `spec sign` refuses an expired spec before any prompt; M1-138
  depends on it. The future `signed_at` warning moves to M2-032. M1-134 says to compare the full
  fingerprint. New M2-137: the container runtime proxy password joins the known-secret set.
- 54: no new M1 ticket. M1-107 registers the plugin token before the first request leaves. The second of
  #80 and M1-107 to merge adds k8s.version and `api/` to `all-pass`. 07 D.7's `nothing_verified` sentence
  covers optional checks not run. New M2-138 to M2-141: the `delegated` outcome, `O_PATH` spec reads, the
  Windows `spec sign` pipe opens, the kind `rdy run` step and paging variant.
- 55: new core M1-184: a test that the recording handshake refuses a server without the leaf's key, the
  unknown-CA zero-bytes case, and the "no revocation check" note on net.tls_intercept and net.egress
  results; M1-138 depends on it. 03 names the real OS roots source and says to pin the leaf or set
  `forbid_interception` until M2-135. M1-073 moves back to week 14. The real-run proof of a spec `as:`
  and the OpenShift grant text moves from M1-113 to M1-175.
- 56: no new M1 ticket. `rdy run` has no family namespace in M1: 03 says what each k8s check does without
  one, and 07 says `rdy run` has no `--namespace`. ADR 0049 (Proposed) picks a spec `k8s:` block with
  `namespace` for M2 and no run flag. M1-162 to M1-165 register their check in the family if M1-175
  merges first. New M2-142 (the `k8s:` block) and M2-143 (the `cluster-autoscaler-status` ConfigMap).
- 57: no new M1 ticket. M1-159 adds back the k8s.nodes `pods` `ALLOWED` entry, its role rule, the
  `live_cluster.rs` read and 03's "wants list on nodes and pods", which M1-115 removes as unused, with a
  fixture that reads the pair, and depends on M1-115. M1-116's Kubernetes page lists each check's API
  reads from `ALLOWED`. M1-162 to M1-165 fold their duplicate `ALLOWED` entries and `Access::GetIn` so
  M1-115's one-entry guard test passes, and copy its pair test (+0.5 h each). New M2-144 (k8s.version
  `v1beta1` rows by kind) and M2-145 (AKS and vSphere or Longhorn storage class fixtures).

**Open PRs at the pause.** The order and what each still needs are in `pending-fixes.md`:
- #26, #27, #28 and #24 come first, from the 2026-10-31 list.
- Then #35, #39, #45, #47, #41, #48, #49 and #30.
- #1 and #2 (Dependabot) are for the founder.

**Not finished.** M1-162 and M1-087 pushed nothing. Rerun them from the brief.

**Numbers.**
- The next PR is #51 (#50 is this pause-state PR).
- The next free ADR is 0051 (0050 is the macOS CI gate, `ci/macos-arm64-gate`). ADR 0042 (the Gatekeeper constraints list wildcard) is in #48, accepted by
  security. ADR 0043 is in #62 (M1-162), ADR 0044 in #65 (M1-163), ADR 0045 in #64 (M1-164) and ADR 0046
  in #78 (M1-165). ADR 0047 is in #85 (M1-133, merged). ADR 0048 is M1-136's docs-test ADR. ADR 0049 is
  correction-56's (Proposed).
- The next ticket ids are M1-185 and M2-146, and the next correction is 58 (49 is in #85).
- The next plan-correction row is PC-54. PC-50 to PC-52 are on main, from M1-176, and PC-53 from correction-48.

**Process lessons from this session.**
- A docs PR that touches a doc a test reads waits for `ci-ok`. Main went red once: #36 merged without CI,
  and #37 fixed it. Tests read these parts:
  - 03: its `###` headings and Appendix A.
  - 05: the Native calls table.
  - 07: B.1 to B.3, C.11, the trust goldens, and the console blocks C.12 to C.18 and 2.7.
  - 01: the json and yaml blocks under `###` headings.
  Grep `crates/`, `tests/` and `xtask/` for the file name before calling a PR docs-only.
- After any code merge, run the full `cargo test --workspace`. A compile error in one test crate stops every
  other result. The lint wall's include prefixes are now `&[&str]` lists, and old branches still use a plain
  string.
- Host family merges conflict in `family.rs`, `family/tests.rs`, `lib.rs` and the fixtures README. Take
  main's files and apply the branch's own changes, rather than resolving hunk by hunk.
- `mergemain.sh` now works on a detached HEAD. The old version moved the branch out from under an agent's
  worktree.
- The kind workflow is outside `ci-ok`. It must still be green for a k8s PR that changes the role or the
  guard, because `live_cluster.rs` pins the `GRANTED` list and a derived action count.
- When main moves under a running CI, cancel the stale run and merge main again.
- When a docs correction merges, hold it until the code PR whose CI is running has merged. Then main does not
  move under that CI.
- A security review on test-only PRs found a vacuous leak test (#41). Keep adding security review when a
  ticket tests redaction.

**Environment facts from this session.**
- The pinned toolchain 1.99.1 was installed and worked. `cargo-deny` and `cargo-nextest` are not installed,
  and the CI deny job covers deny.
- The macOS x64 leg is the slowest at about 25 minutes. Three PRs at once is the most CI keeps up with.
- The GitHub job log API sometimes cuts nextest failure output. A haiku agent with `get_job_logs` and
  `tail_lines` finds the failing test names.

## Notes carried to later tickets

Review findings that belong to a later ticket. Give each note to that ticket's implementer and reviewer.

- M1-024 and M1-025: a bare `- id: host.memory` with no threshold must decode to `unsupported_spec` with
  reason `no_threshold` (01 section 2.5). Add a per-struct test so the FIELDS lists cannot drift.
- M1-026: stop recording parse entries after 257.
- M1-033: `pass_by_absence` shows its note twice (as the message and in notes); add `#[non_exhaustive]`
  to `PeerClass`; add a `compile_error!` for Unix targets other than linux and macos (PR #32 review).
- M1-040: `CheckError` derives Clone, PartialEq and Eq, so `ProbeError` and `NetFailure` must too, or drop
  the derives before the M2 publish. Give check crates a test constructor for `CheckContext` (PR #32 review).
- M1-044: use `allow-invalid = true` for disallowed paths that do not resolve in every crate. Add
  `std::io::stdout`, `std::io::stderr`, the print macros, and the clippy lints `print_stdout`, `print_stderr`
  and `dbg_macro`.
- M1-058: SIGINT and SIGTERM during a password prompt must restore the terminal. Test it.
- M1-063: the redaction corpus is 28 cases, per 04.
- M1-125: wire `spec sign` and `spec keygen` to `rdy_cli::password::read_key_password`. The exit test covers
  `RDY_KEY_PASSWORD` and `--password-file -` with no prompt.
- M1-126: print `SpecError::fix()` (it fills in the product). Mention the signature error codes in the
  changelog (PR #31 nit). Add the CRLF note to every signature error. Read the `.minisig` file once; an unreadable or
  non-regular file passes `Some`, never `None`. Show the KEY NOT PINNED banner from `TrustSource::Flag`.
- M1-031: did-you-mean for unknown keys including nested key paths; regex compile; line numbers and
  `LintReport`; `assert!(!ids.is_empty())` in the reserved drift test; mention `no_threshold` in the M1-023
  changelog; rename `gpu.device_plugin` in acme-inference-gpu.yaml; distance 2 or less.
- M1-039: CLOEXEC on inherited fds (or an ADR), the umask, the shell and sudo refusal, PATH and env policy.
- M1-043: the narrow window where the watchdog can kill after a reap, and a check that the
  SIGCHLD-ignored test really ignores SIGCHLD on macOS.
- M1-044: also prove the clippy disallowed-methods list, including the M1-030 bans. Add
  `cargo clippy -p rdy-engine --no-default-features --all-targets -- -D warnings` to CI. Delete the stale
  `strsim` row in 07 (around line 2591). Add a test that pins near-miss echoes (`--allow-unsigne`).
- M1-050: add an allow entry for `tests/fixtures/canary/netstat-crlf.txt` in the `\r` lint.
- M1-056 and M1-062: the CLI panic hook never prints default panic text. `End::Panicked` text is raw.
  `CliError::from_anyhow` text goes through the redactor.
- M1-057: End to CheckResult glue (TimedOut becomes timeout, Panicked becomes error with a fixed message,
  Cancelled becomes a cancelled skip). Reconcile plan skip text with `rdy_cli::error::SkipWhy`. Test that
  the CLI fills in `<spec>`.
- M1-060: commented-out blocks, including commented PEM lines; crafted escapes of the bracket and quote
  counts; tuning of over-redaction (all-quoted .env files, stray apostrophes, sibling `- ` items);
  `--password hunter2` as separate words.
- M1-073: what an os `arch: []` means. M1-145: what `allow: []` and `supported: []` mean.
- M1-110: owns the `partial.missing_grants` wire field (13-plan-corrections open item). Its row needs the
  rdy-spec work and the hours.
- M1-126: also exit 64 on an expired spec, and the file-prefix wording.
- The HostFamily registering ticket must drop the stubs, or first add an engine `NotInBuild` skip.
- M1-137: the README leads with the pinned GitHub release URL in M1, not getrdy.io/install.
- CF-03: the upload transport is an open M2 item.

- From this session:
  - M1-010: done in #66 (the PR #47 security lows).
  - M1-015: the fake `rdy` drops a canary file, and the bad-hash and bad-signature cases assert it is
    absent; `fetch` takes the missing-bundle message (06 "this release looks incomplete"); the stop message
    prints a reachable URL for `scripts/verify-release.sh` at the tag, then 06's manual path.
  - M1-044: `exec::run`, `ExecSpec`, `exec::policy::run` (and anything but `exec::table::run`) on the
    check-crate deny list; `ExecSpec` may need `disallowed-types`.
  - M1-060: accept `\\+t` as a blank in `ASSIGNMENT` (a tab inside a Debug-printed field); the proxy URL
    canary (PC-43); `--password hunter2` as separate words.
  - M1-061: known secrets shared through `Arc` so the log writer and CLI errors see them.
  - M1-066: programs that take code or a command line never enter the allow-list (done in #70).
  - M1-102: the run probe denies `.kube`, so the engine's own kubeconfig read needs a settled path.
  - M1-121, M1-122, M1-128: `sudo` resets HOME and XDG_CONFIG_HOME; root tests set them on the child.
  - M1-126: `--key` runs never read the trust stores; the INV-04 strace check runs the real `rdy verify`
    (correction-10).
  - M3: `CAPPED_TARGETS` needs `reqwest`, `aws_smithy_*` and `aws_config` when cloud checks land.

- From the 2026-10-30 session:
  - M1-072: process name from `comm`, never `cmdline`; walk only the needed pids and stop at the first
    match (correction-33); the #153 code nits N1 to N3.
  - M1-086 and the README: once M1-057 merges, the README's status and build-from-source sections change
    (`rdy run` works on main). Link NOTICE and TRADEMARKS.md once #157 merges. Add host.firewall and
    k8s.access to "Works on main today".
  - M1-115: two OpenShift label-sync checks (correction-33).
  - M1-141: test string `"x\u{2069}\u{202e}"` in a banner line, a `<bdi>` field and the title.
  - M1-110 or the next k8s change: SEC-147-9 comment wording.

- From the 2026-11-06 session:
  - M1-137 or release-engineer: the `install.sh` header comment (lines 6 and 7) and RELEASING.md:123 run
    `curl -sSf` without `-L` on a GitHub release URL. GitHub answers with a redirect, so curl downloads 0
    bytes and `| sh` installs nothing. Use `--proto '=https' --proto-redir '=https' --tlsv1.2 -sSfL`.
  - M1-126 or qa: `tests/fixtures/signed/acme-platform.yaml:11` and `tests/fixtures/minisign-c/acme-platform.yaml:11`
    say the quickstart "can reach READY today". That is stale. Re-sign the fixtures if they change.
  - M1-095 and M1-107: rerun the `root_*` `--no-network` strace test once net and k8s are registered. The
    M1-107 kube client builds sockets outside the facade, so it must honour `--no-network` itself.
  - M1-107: with network on and a context available, the k8s check is not `missing_need` (a control for the
    M1-059 skip).
  - qa (PC-52): the M1-043 macOS SIGCHLD carry stays open. The ECHILD probe failed on macos-x64, so it is gated
    to Linux.
  - M1-179: deletes the host.time_sync PENDING row in the env harness that #35 adds.
  - Follow-ups that correction-42 gave ids:
    - M2-121, net.mtu: a per-interface note on a hostile link, instead of ending the check.
    - M2-122: a per-response byte cap in the k8s client, 16 MiB, with a cut list reported as partial
      (#48 F3).
    - M2-123: `NetFailure::NotConnected` carries the connect attempts, so net.egress needs no second tcp
      call (#45).
  - Follow-ups that correction-43 gave ids:
    - M2-126: the guard pins the Service list and the operator Deployment GET to the spec's namespaces
      (#65 security review).
    - M2-127: CI builds the pty probe examples once before nextest (#66 review).
  - Follow-ups that correction-44 gave ids:
    - M2-128: the run header prints before progress starts, so 07's M1-142 rule holds (#68 reviews).
  - Follow-ups that correction-47 gave ids:
    - M2-129: k8s.cni reports crash-looping and not-ready plugin pods, and k8s-expert checks the
      `cni.toml` entries still marked `verified = false` against a live cluster (#78 reviews).
  - Follow-ups that correction-48 gave ids:
    - M2-130: a `RunHooks` OS override, so the env harness runs every env on every leg (#80 review).
  - Follow-ups that correction-52 gave ids:
    - M2-131: the JSON writer writes Cc, Cf and zero-width characters as `\u` escapes (#89 security F3).
    - M2-132: `unicode-bidi: isolate-override` on the fix `<bdi>` (#89 security F5).
    - M2-133: `FixText` refuses control characters at parse (#89 security F1).
    - M2-134: net.tls_intercept reports the Java `cacerts` and `NODE_EXTRA_CA_CERTS` stores (#91).
    - M2-135: the recording verifier keeps the verified path, so a pin matches any certificate on it
      (#91 SEC-100-1).
    - M2-136: the real trust anchor through `TrustStore` root subjects (#91 review).
  - #91 (M1-100) and #70 (M1-179): add "backlog corrected 2026-11-17 (correction-52)" to their progress
    lines. The second to merge deletes the net.tls_intercept `PENDING` row.
  - Follow-ups that correction-53 gave ids:
    - M1-183: every spec read through `read_public`, and `spec sign` refuses an expired spec (#96 MF-01).
      A 0.1.0 gate.
    - M2-137: host.container_runtime adds `ProxyUrl::secrets()` to the known-secret set (#92 security F8).
  - M2-032 (correction-53): the `signed_at` more than 24 h in the future warning (#96 SF-01).
  - M1-134 (correction-53): the sign and verify page and #85's unsigned page say to compare the full
    fingerprint from `rdy verify --key`, never the short form in the banner (#96 SF-02).
  - M2-107 (correction-53, +0.25 h): `check_note` also refuses the code points `is_invisible` flags in
    trust-store notes (#96 N-01).
  - Follow-ups that correction-54 gave ids:
    - M2-138: the action-log outcome `delegated` for the kube credential plugin, replacing M1-107's
      `form: delegated` field (02, M1-107 reviews).
    - M2-139: Linux spec reads open with `O_PATH`, then `fstat`, then reopen `/proc/self/fd/N` (#98
      security).
    - M2-140: `rdy spec sign` opens `--sig` and `--secret-key`, and `rdy spec keygen` checks its key paths,
      at identification level on Windows, not through `canonicalize` and `symlink_metadata` (#98 security).
    - M2-141: the kind job runs `rdy run` on a k8s.version spec, and a three-node variant pages the node
      list with `continue` tokens (M1-107 reviews).
  - M1-107 (correction-54): its row says the plugin token is registered before the first request leaves.
    Its PR adds "backlog corrected 2026-11-17 (correction-54)" to its progress line.
  - #100 (M1-140): use the new 07 D.7 `nothing_verified` sentence (correction-54) in `view.rs`,
    `html_print.rs` and the golden.
  - Follow-ups that correction-55 gave ids:
    - M1-184: the handshake signature test on TLS 1.2 and 1.3, the unknown-CA zero-bytes case, and
      `REVOCATION_NOTE` once per net.tls_intercept and net.egress result (M1-101 review SF-01, SF-02). A
      0.1.0 gate. Build it after #74 (M1-096) and #91 (M1-100) merge.
  - M1-101's PR (correction-55): SF-01's owner is M1-184, not M1-096, and SF-02 is an M1-138 dependency.
    In the review, its progress line and 05 "TLS", write "from M1-184" for "from M1-096", and drop the
    facade zero-bytes test from SF-02's fix (it exists:
    `the_live_backend_handshakes_on_loopback_and_reads_the_real_store`, `probe/net/tls/tests.rs` ~764).
  - #91 (M1-100) and correction-55 both edit 03's net.tls_intercept Thresholds line. The second to merge
    keeps #91's pin text and appends correction-55's "Until M2-135" sentence.
  - M1-113 and M1-175 (correction-55): M1-113 implements `Cluster::read_only_as` and
    `Cluster::is_openshift` with tests through the family holder; M1-175 proves in a run on the kube mock
    that a spec `as:` reaches k8s.rbac and an OpenShift mock shows the grant text (M1-113 code review).
  - M1-116 (correction-55): the network page says to pin the leaf or set `forbid_interception` to block
    until M2-135 (M1-101 review AR-01).
  - Follow-ups that correction-56 gave ids:
    - M2-142: the spec `k8s:` block with `namespace`, handed to `K8sFamily::with_namespace` by `rdy run`;
      no `rdy run --namespace` (ADR 0049, M1-175 review). cli-ux and security-reviewer review ADR 0049
      in it.
    - M2-143: k8s.nodes reads `kube-system/cluster-autoscaler-status` by name for GKE Standard and AKS,
      with the 03 grant text, a new ADR and a security review (M1-113 k8s review). Build it after #62
      (M1-162), which brings the `Access::GetIn` guard shape.
  - #62, #65, #64, #78 (M1-162 to M1-165) and M1-175 (correction-56): the second of M1-175 and each of
    them to merge registers that check in the family: the `build_check` arm, the registry info and the
    family test counts. Each PR keeps the correction-56 clause in its progress line.
  - M1-175's PR (correction-56): in its progress line, "a correction will file it" becomes
    "correction-56 filed it (M2-142)", and "a correction adds the clause to those rows" becomes
    "correction-56 added the clause to those rows".
  - #65 (M1-163, correction-56): its no-namespace fix says "the `k8s` block of the spec", which M1 does
    not have. If #65 takes another fix round, word it like k8s.cni's (no key named); otherwise M2-142
    rewrites it.
  - docs/adr/README.md (correction-56): the rows of ADR 0043 to 0048 go above the 0049 row as their PRs
    merge.
  - Follow-ups that correction-57 gave ids:
    - M2-144: k8s.version's `networking.k8s.io`, `storage.k8s.io` and `admissionregistration.k8s.io`
      `v1beta1` removed-API rows become per-kind rows for the kinds removed in 1.22 (M1-115 review SF-03).
    - M2-145: k8s.storageclass fixtures for AKS `managed-csi` (registered and not) and a vSphere or
      Longhorn class (M1-115 review SF-04).
  - M1-159 (correction-57): add back what M1-115 removes: the `pods` `ALLOWED` entry with the
    `status.phase` selector (or, if M1-162 merged first, only k8s.nodes in that entry), its guard tests
    and call table lines, the `rules.rs` module doc line on `pods` and `events` selectors,
    `_kube/cluster/api/pods-active.json`, `pods` in the `rdy-readonly.yaml` list rule and its header text,
    the `live_cluster.rs` pods read, 02 Appendix B's `pods` row and rule 1 sentence, and 03's "wants list
    on nodes and pods". Read the M1-115 diff (`e6183499`, `f68ec65a`) for the exact lines. A
    k8s.nodes fixture with a Pod list must hit the pair in
    `every_allowed_entry_that_cites_this_check_is_read_by_a_fixture_run`.
  - M1-115's PR (correction-57): SF-01's "M1-159 adds the entry, the grant, a fixture and the pair test
    back" is now in M1-159's row. SF-03 and SF-04 are M2-144 and M2-145; SF-05 and SF-06 stay with M2-126
    and M2-125. The SF-02 fold is in the rows of M1-162 to M1-165 (+0.5 h each).
  - #62, #64, #65 and #78 (M1-162 to M1-165, correction-57), if M1-115 merged first: fold the duplicate
    `services`, `configmaps` and `apps/v1` `daemonsets` entries into one entry each, add `Access::GetIn`
    only in the first of #62 and #78 to merge, and copy M1-115's pair test into the module, so
    `allowed_has_one_entry_per_group_version_and_resource` passes. `pods`: M1-115 removes the entry #62
    extends, so the first of #62 and M1-159 to merge adds the `pods` entry, the role rule and the
    `live_cluster.rs` read citing only its own check, and the second adds its id. #62 drops k8s.nodes from
    the entry unless M1-159 merged first. Each PR adds "backlog corrected 2026-11-17 (correction-57)" to
    its progress line.
  - M1-116's PR (correction-57): add "backlog corrected 2026-11-17 (correction-57)" to its progress line
    for the Kubernetes page API reads line.
  - After #84, M1-097's PR and M1-119's PR merge, change "correction-49" in their progress lines to
    "correction-50".
  - M1-107 and #80 (M1-117) (correction-48, correction-54): the second of the two to merge adds
    k8s.version and the `api/` tree to `all-pass`, sets `kube = true` and regenerates its three goldens.
    #80 adds "backlog corrected 2026-11-17 (correction-54)" to M1-117's progress line.
  - M1-115 (correction-47): 13 of the 15 `cni.toml` entries from #78 are `verified = false` (all but Flannel
    and the AWS VPC CNI): their names come from memory of the projects' manifests. Read each entry's
    `source` page. Where the page shows the names, set `verified = true` and `checked_on`. Leave the rest
    for M2-129.
  - Whichever of #60 (M1-142) and #68 (M1-143) merges second passes `quiet or verbose` to
    `live_line_allowed` and updates the run_cmd.rs docs sentence on `--quiet` and `--verbose`.

## For the founder

Hand steps an agent cannot do (also in the Founder hand steps list in `11-backlog.md`):

- Create the labels in `.github/labels.yml`.
- Add the branch rulesets and make `ci-ok` a required check.
- Turn on immutable releases, then cut a fresh tag. Releases stay pre-releases until M1-139 is sent.
- Domain hardening from M1-008: hardware-key MFA, registrar lock, DNSSEC, CAA, HSTS. Rerun
  `scripts/check-domain.sh` after.
- Delete the throwaway branches `tmp/m1-005-clippy`, `tmp/m1-005-openssl`, `tmp/m1-005-unsigned` and
  `tmp/m1-005-signed`, and any merged `m1/*` branches. The agent proxy refuses branch deletes.

- Done by ADR 0050 (2026-11-18): the gate runs the arm64 tests on `macos-15`, and `macos-intel.yml` runs the
  Intel tests on main and nightly. CLAUDE.md's "Five CI legs" wording is updated.
- Run the release-sandbox proof in 06 "Sandbox proof" before M1-010 (correction-07).
- Add a ruleset that restricts tag creation (M1-007).
- Delete `tmp/m1-006-macos-probe` as well.
- Scratchpad reviewer build folders could not be removed. The `rm` was denied by permissions and was not
  worked around. They disappear with the session.

Decisions to look at:

- `CLAUDE.md` was edited by the coordinator in M1-009 (edits C-1 to C-9, the architect's text), under the
  build instruction, because agents refuse to edit it.
- ADR 0018 replaces the planned minisign verification crate with an in-tree envelope parser on
  `ed25519-dalek` `verify_strict` and `blake2`.
- M1 started before the M0 go or no-go gate (decision 2 in `13-plan-corrections.md`).

- Correction-05: four native test legs plus an arm64 compile leg gate PRs until arm64 runners exist.
- M1-022 boxes `End::Done(Box<CheckOutcome>)` and turns on serde_json preserve_order behind a `schema`
  feature (ADR 0019).
- M1-048's redactor fails closed and over-redacts on purpose. M1-060 tunes it with corpus evidence.

Process events worth knowing:

- During M1-008 an agent tried to rewrite a URL to get past a guard. The guard denied it and the agent did
  not retry.
- The security-reviewer could not commit its sign-off file in M1-009. The verdict is recorded as a PR comment.


From the 2026-10-29 session:

- Decision: `getrdy-io` is a personal account, not an organization, so org-wide 2FA cannot be enforced.
  Convert it or move the repo to a new org (docs/security/github-settings.md section 1). Either choice
  changes the login or the signing identity.
- Add `--proto =https` to the curl calls in `scripts/check-org-settings.sh` by hand; the agent sandbox
  refused to write it.
- Dependabot PRs #63 and #64 bump crypto crates by a major version; review by hand per ADR 0018.
- Ratify ADR 0024 (release proofs are founder steps) and ADR 0027 (Windows trust stores refused in M1).
- Delete the branch `tmp/m1-011-unpinned` (proof PR #61, closed).
From the 2026-10-30 session:

- Claude's GitHub connection now returns the `getrdy-io` account, and squash merges are authored
  `getrdy-io <dev@getrdy.io>`. Nothing more to do unless that changes.
- Decide the kind gate (ADR 0039): keep the kind job out of `ci-ok`, or require it.
- Run the trademark search and filing in Apostolic Path LLC's name.

From the 2026-10-31 session:

- To have GitHub show commits as Verified, add a signing key for `dev@getrdy.io` to the `getrdy-io`
  account and configure commit signing in the build environment. Commits are not signed today, and
  "Unverified" only means that. The DCO check reads the `Signed-off-by` line.
- Install `cargo-deny` in the build environment, or accept that only CI runs it.
- Review Dependabot PRs #1 (syn 3) and #2 (scrypt 0.12). Both CI runs were red at the pause.

From the 2026-11-06 session:

- File two issues labelled `flake` (08:435). One is for the fixtext test "`ip` must not be a fix command".
  The other is for `probe::tests::link_reads_fold_and_drop_like_file_reads`. The labels do not exist yet, so
  this is a hand step.
- Decisions to look at:
  - ADR 0042: the guard and the example role list every resource of `constraints.gatekeeper.sh/v1beta1`,
    list only. Security accepted it with a written residual.
  - Correction-35: adjtimex is moved to M2-004.
  - Correction-39: `--no-network` allows only AF_UNIX sockets, and chronyc does not run offline.
- Main went red once (#36, a docs PR merged without CI), and #37 fixed it within the hour. The runbook now
  says which docs need `ci-ok`.

From the 2026-11-17 session:

- Decisions to look at (correction-43, decision 8 in `13-plan-corrections.md`):
  - k8s.dns blocks when CoreDNS ready replicas are below desired. k8s-expert suggests a block only at 0 ready,
    a warn for some ready, and a block for a headless DNS Service.
  - k8s.ingress gives a note, not a warn, for two default classes.
