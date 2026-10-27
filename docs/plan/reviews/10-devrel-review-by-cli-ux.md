# Review of 10-devrel-and-launch.md, example specs and CONTRIBUTING.md, by cli-ux

Reviewer: cli-ux. Date: 2026-10-27. Reviewed cold. Files not edited.

Scope read: `docs/plan/10-devrel-and-launch.md`, `examples/specs/*.yaml` (4 files), `CONTRIBUTING.md`. Cross-checked against CLAUDE.md, `rdy-plan.md`, `docs/plan/06-release-and-distribution.md`, and ADRs 0002, 0008 and 0011. `docs/plan/07-cli-ux.md` does not exist yet, so output rules below are the house rules from my role file plus CLAUDE.md.

Mechanical checks, all clean: no em dashes or en dashes in any reviewed file. I found no sign of the old working name (I cannot grep for a name I must not know, so this was a read-through). The Show HN title is 63 characters, as stated (limit is 80).

## Ranked findings

### Must fix

**M1. The READY transcript contradicts accepted ADR 0008.**
Location: section 1 draft copy, second `console` block; "Decisions needing an ADR", skipped-check bullet.
Problem: the rerun shows `6 passed, 2 skipped`, then `READY`, exit 0. ADR 0008 (Accepted) says any `Skipped` lowers the verdict to at most `Warnings`, so that run is exit 1. The author treats option (a) as live. It is already ruled out. Under the rule I recommend below, the run would be exit 2, because `gpu.cuda` and `aws.iam` are `severity: block`.
Fix: the README demo must not use a spec that holds checks no M1 binary can run. Add a fifth file, `examples/specs/acme-quickstart.yaml`: host.cpu, host.memory, host.disk, net.egress only (no k8s, so a laptop with no kubeconfig can reach green). Use it in the README, the HN sample, the quickstart and the golden test. Keep `acme-platform.yaml` as the plan-shaped canonical file and show it only in a "what happens with checks that cannot run" snippet (see M2). Delete "Decisions needing an ADR: how skipped checks affect the verdict" from this doc and point to rust-architect's decision in 02-engine-design.

**M2. The quickstart cannot reach green on the example it tells people to use.**
Location: Quickstart steps 3 to 5.
Problem: `acme-platform.yaml` has two block checks that never run in M1 (`gpu.cuda`, `aws.iam`), plus `k8s.version` (block), which is skipped on any machine with no kubeconfig. Step 5 "Make it green" says to edit memory and egress. The user still gets NOT READY. The step teaches nothing and looks broken.
Fix: switch the quickstart to `acme-quickstart.yaml` (M1 above). In step 3, say plainly what a reader will see: `net.egress` fails on DNS (`registry.acme.example does not resolve`), not "refused by proxy". The first transcript's proxy 403 only happens in the lab.

**M3. Wrong counts in the first transcript and the HN sample.**
Location: first `console` block; Show HN body.
Problem: the block has 3 PASS, 2 BLOCK, 1 WARN, 2 SKIP. The summary says `4 passed`. The golden-file ticket asks for a byte-for-byte match, so this will fail the first time. The HN sample prints `4 passed` over a trimmed list, which reads as an error.
Fix: summary is `2 blocks, 1 warning, 3 passed, 2 skipped`. In the HN body, either show the full list or add one line before it: "Output trimmed."

**M4. The HN sample would exit 64, not show a verdict.**
Location: Show HN body, `$ rdy run acme-platform.yaml`.
Problem: the file is unsigned. Per ADR 0002 an unsigned spec exits 64 without `--allow-unsigned`. The post also says "the vendor signs it", then shows an unsigned run with no `--allow-unsigned`.
Fix: add `--allow-unsigned` to the sample, or show a signed run. Prefer both in the README: first the refusal (see S1), then the allowed run.

**M5. The copy-paste cosign command is unsafe.**
Location: Quickstart, manual verify block.
Problem: `--certificate-identity-regexp 'https://github.com/getrdy-io/rdy/'` is unanchored and matches any workflow in the repo, and any string containing that URL. Doc 06 says this exactly: never use a loose regexp, and the identity is `sign-release.yml@refs/tags/<tag>`. A security reviewer on HN will spot this in a minute. The block also skips `sha256sum -c`.
Fix: copy the exact-identity form and the anchored regexp from 06 verbatim, and add the `sha256sum -c` line. The tag in examples is `v0.1.0-alpha.N`, not `v0.1.0` (06: every release is a prerelease through M1, and GitHub "latest" skips prereleases). Update the raw spec URL and the archive URLs too.

**M6. Invented first-person stories are drafted as fact.**
Location: Show HN body ("At three companies I have written the same bash script"); PreSales Collective post ("Last year a POC of mine lost nine days ... the third time that quarter").
Problem: these are specifics the founder has not given us. "Three companies" is the plan's persona line for the champion, not a biography. The doc's own rule 3 says every claim has a test. A made-up anecdote posted under the founder's name is the thing HN and the Collective punish hardest.
Fix: replace each with a bracketed placeholder, `[FOUNDER: one true story, with the real number of days]`, and add a launch-gate checkbox: "Every personal claim was written by the founder from memory."

**M7. CONTRIBUTING lists a command that cannot pass.**
Location: `CONTRIBUTING.md`, "Build and test"; ticket "Review CONTRIBUTING.md on a fresh clone".
Problem: "All of these must pass" includes `cargo run -p rdy -- run examples/specs/acme-platform.yaml --allow-unsigned`. That exits 1 or 2 on any dev machine by design. The ticket's exit test ("every command runs green") fails.
Fix: move that line to a separate "Try it" block with the note "exits 2 on most machines, that is expected". Or run `acme-quickstart.yaml` with `--json` and say the exit code is not the point.

**M8. Skipped-check behaviour in the example specs and ticket text is not honest about the verdict.**
Location: `acme-platform.yaml` header comment; `acme-inference-gpu.yaml` header comment; section 2 "Behaviour the examples depend on".
Problem: the comments say gpu checks are "skipped, and runs the rest" and "never as passed", which is true, but they do not say the run ends NOT READY while those checks are required. A reader will expect a green run.
Fix: add to both headers: "Required checks that cannot run make the verdict NOT READY. This file will not reach READY until the family ships." Same sentence in section 2.

### Should fix

**S1. Show the signing refusal. It is the first thing a new user sees.**
Location: Quickstart step 2 and 3; section 1 transcript header.
Problem: the text says "rdy will refuse it" but never shows how. ADR 0002: exit 64, a fix hint, and a loud banner on stderr when allowed. The transcript header is one quiet line. CLAUDE.md says "say so loudly".
Fix: add a 6-line block to the README:
```console
$ rdy run acme-quickstart.yaml
error: acme-quickstart.yaml has no signature.
fix:   Ask the vendor for the .minisig file and public key, then run
       rdy run acme-quickstart.yaml --key <key>. To run it anyway: --allow-unsigned.
$ echo $?
64
```
And on the allowed run, print one banner line above the header: `WARNING: this spec is UNSIGNED. rdy cannot tell who wrote it.` (stderr, bold red on a terminal, plain text under `NO_COLOR`). Also show one signed run, with `--key`, since signing is an M1 feature and the README never uses it. Command names are provisional per ADR 0002, so mark it `[M1, sync with 07]`.

**S2. stdout, stderr, `--json` and `NO_COLOR` are missing from the README, the HN post and the FAQ.**
Location: sections 1, 3 and 5.
Problem: CLAUDE.md: human output on stderr, JSON on stdout with `--json`. A CI gate is half of the HN pitch ("so CI can gate on it") but nothing shows the one-liner. No mention of `NO_COLOR` or pipes anywhere in the doc.
Fix: add to "How it works": "Reading output goes to stderr. With `--json`, stdout carries only the JSON result. `NO_COLOR` or a pipe turns off colour. The words PASS, WARN, BLOCK and SKIP carry the meaning, so nothing depends on colour." Add a 3-line CI snippet:
```sh
rdy run spec.yaml --json > result.json
test $? -eq 0   # 0 ready, 1 warnings, 2 blockers
```
Add the exit-64 and exit-70 behaviour: they print `error:` and `fix:` lines and no verdict line.

**S3. "READY with warnings" is used in "How it works" but defined nowhere else, and the last-line rule is not stated.**
Fix: state the three last lines once, in the README exit-code paragraph:
`READY` (0), `READY with warnings` (1), `NOT READY` (2). Skipped checks of severity `warn` give exit 1. See the verdict rule below for skipped blockers.

**S4. Quickstart claims about install.sh are wrong against doc 06.**
Location: Quickstart step 1; objections table ("`curl | sh`").
Problem: "does nothing else" is false. 06: it refuses to run as root unless `RDY_ALLOW_ROOT=1`, may download a pinned cosign, runs `rdy version` once as a smoke test, and prints PATH instructions. "Windows zip `[M3]`" is wrong: 06 puts the Windows zip in M1 and `install.ps1` in M3.
Fix: "puts one binary in `~/.local/bin` after checking its SHA-256 and its Sigstore signature. It refuses to run as root. It never edits your shell profile." Tag only `install.ps1` as M3.

**S5. `rdy self-update` is cited as network traffic, but in M1 it downloads nothing.**
Location: trust table "No telemetry" row; objections table "What about telemetry?".
Problem: 06 defers self-update: it prints the install command and nothing else.
Fix: drop `self-update` from both. Say "The only network traffic is what a check exists to make."

**S6. "The only code that sends anything" points at a file that does not exist in M1, and net checks send packets.**
Location: trust table row 1; HN body.
Problem: upload is M2. `crates/rdy-cli/src/upload.rs` does not exist at the alpha. Net checks do connect out, so "Read ..., the only code that sends anything" is false. `unshare -rn` also needs unprivileged user namespaces, which Ubuntu 24.04 blocks by default, and `net.egress` will BLOCK in the empty namespace.
Fix: split the claim. M1: "Checks connect only to the endpoints in the spec. Run a host-only spec with `unshare -rn` (or `unshare -n` as root) and see no traffic." M2+: add the upload.rs pointer when it exists. Add "needs user namespaces" to the note.

**S7. The proxy URL in output can leak credentials.**
Location: first transcript, `net.egress` line (`http://proxy.acme.example:3128`).
Problem: `HTTPS_PROXY=http://user:pass@proxy:3128` is common. The terminal and the HTML report print the proxy. The bug template says "rdy redacts bundles, not the terminal."
Fix: print proxy URLs with userinfo stripped (`http://proxy.acme.example:3128`), in terminal, HTML and JSON. Add a golden test (qa-engineer) and a line to the README sample's note. I will put the rule in 07.

**S8. Port check shows a PID and process name that need root.**
Location: series day 1, `host.ports 8443 in use by pid 1214 (nginx)`.
Problem: a non-root user cannot map a socket to another user's process. Least privilege means the real output is `8443 in use (process unknown without root)`.
Fix: show the unprivileged form in the post, and mention in the CTA that `sudo rdy run` adds the process name. (It never asks for sudo; the user may choose to.)

**S9. Series day 2 shows check ids that no example spec contains.**
Location: series day 2 (`net.tls`, `net.dns`).
Problem: the post says "reproducible", but no file in `examples/specs/` has `net.tls` or `net.dns`. Only `net.egress` appears. Readers cannot run it.
Fix: add `net.dns` and `net.tls` to `acme-platform.yaml` is out (it must stay plan-shaped), so add them to `acme-k8s-only.yaml`'s net section or a new `acme-proxy.yaml`. Alternatively give day 2 a spec snippet in the post. Also: day 3's `kind` demo will also show a `net.egress` BLOCK (charts.acme.example does not exist), so the post must say "output trimmed" or the reader sees NOT READY and wonders.

**S10. Example specs: `fix` is present on some block checks and missing on others, and the README says each check has one.**
Location: `acme-platform.yaml` (k8s.version, gpu.cuda, aws.iam), `acme-airgap-host.yaml` (host.cpu), `acme-inference-gpu.yaml` (gpu.cuda, k8s.node_resources), `acme-k8s-only.yaml` (net.egress).
Problem: examples teach by imitation. House rule: every failure has a fix.
Fix: add a `fix` to every block and warn check in all four files. State in docs that an omitted `fix` falls back to the check's built-in text. Also state that the spec `fix` is shown after the check's own cause line (a DNS failure and a proxy 403 need different advice; one static spec string cannot do both).

**S11. `acme-k8s-only.yaml` has a misleading `net.egress`.**
Location: `acme-k8s-only.yaml`, last check; header comment ("No host checks, because the nodes are not where rdy runs").
Problem: the header says nodes are out of reach, then `net.egress` tests from the laptop. That says nothing about whether pods can pull from `registry.acme.example`.
Fix: delete that check, or add a comment: "This tests from the machine running rdy, not from inside the cluster." Prefer deleting it for M1.

**S12. Field naming in the example specs is not uniform.**
Location: `acme-inference-gpu.yaml` `gpu.vram per_gpu: 40Gi`; `acme-airgap-host.yaml` `host.cgroups version: 2`; `acme-k8s-only.yaml` `k8s.rbac can_i: ["create clusterroles", ...]`.
Problem: every numeric check elsewhere uses `min`. `version` already means the product version at spec level. `can_i` strings drop the API group (`clusterroles.rbac.authorization.k8s.io`), which a SelfSubjectAccessReview needs to be exact.
Fix: `gpu.vram: min: 40Gi` with `per: gpu` if needed; `host.cgroups: require: v2`; `k8s.rbac` entries as `verb resource.group` like `kubectl auth can-i`. Provisional until 01-spec-format lands, so list these three as known open points in section 2.

**S13. Series day 5 uses a flag that conflicts with the command surface.**
Location: day 5 bundle sample: `uploaded nothing. Use --upload to send it`.
Problem: my role file and CLAUDE.md make upload its own verb: `rdy upload`. Upload also asks for explicit approval.
Fix: `not uploaded. To send it: rdy upload ./rdy-bundle.tar.zst (read the manifest first)`. I will define the bundle and upload samples in 07.

**S14. r/kubernetes copy is stale and the subreddit rule check is only applied to r/devops.**
Location: r/kubernetes post ("a pod security policy rejects the workload"); r/devops, r/rust, r/kubernetes sections.
Problem: PodSecurityPolicy was removed in Kubernetes 1.25. Use "Pod Security Admission or an admission policy". Separately, several of these subreddits restrict self-promotion to a weekly thread or require a disclosure and a ratio of other activity, and r/rust has been tightening its rules on AI-assisted projects. I cannot verify current wording; the doc should not assume.
Fix: apply "read the current rules the week before; if promotion is limited to a thread, post there" to all three. Add a gate: "founder accounts have history on each sub".

**S15. HN mechanics: waitlist email and account history.**
Location: launch day table, "send the waitlist email"; Show HN rules.
Problem: an email that links straight to the HN thread, or asks for votes, looks like a voting ring and can get the post penalised or flagged. Also the doc does not say whose HN account posts it. A throwaway or brand-new account looks bad.
Fix: the waitlist email links to the repo, never to the HN item, and does not mention HN. Post from the founder's own account, which should already have comments. Also "Do not post anywhere else today" conflicts with the series day-2 post at 10:00 on the same row; reword to "no other community posts today". Optional: if the post sinks, email `hn@ycombinator.com` and ask about the second-chance pool, rather than reposting.

**S16. Tickets: sizes, dependencies and missing items.**
Location: "Tickets implied".
Problems:
- "README first draft with verified commands" (4h) hides a docs-test harness that runs README commands against the build, with install, cosign and a kube API. That is not 4h. Its dependency list names only host checks and the HTML report, but the README shows net, k8s, signing and install.sh.
- "Golden report for acme-platform fixture" (3h, qa-engineer) needs a fake proxy, a fake kube API and byte-stable output. It depends on host, net and k8s checks and on the verdict decision. Not 3h. Its exit test points at the old `acme-platform` transcript.
- "CI job: lint every example spec" has no dependency on `rdy spec lint` existing.
- "Write example specs (4 files)" is already done in this pass; the ticket should be "Review and lint example specs" with the new fifth file.
- "CODE_OF_CONDUCT and SECURITY.md" is devrel-owned but SECURITY.md is security-reviewer's; depend on their ticket by name.
- "lobste.rs invite and account history" at 1h is not 1h; it is weeks of small comments.
- DCO has no enforcement ticket (an app or CI check).
- Missing: sync transcripts with 07-cli-ux samples; asciinema cast; repo hygiene (topics, social preview, Discussions); `--dry-run` (see S17).
Fix: split the README ticket into (a) docs-test harness, 3h; (b) README draft, 3h. Split the golden ticket into (a) fixture proxy and fake kube API, 4h; (b) golden transcripts, 2h. Add the missing tickets at 1 to 2h each. Every M1 ticket then stays at one to four hours with an exit test.

**S17. The `--dry-run` gap proposal: accept it, with a small M1 slice.**
Location: "Plan corrections found", last bullet.
Problem: none. The idea is right and cheap, since each check already declares its needs. It answers "what will this do on my box" better than prose.
Fix: name it `rdy run --dry-run` (the convention in gh and cargo). It prints, per check: id, needs, and what it reads or connects to, then exits 0 without running. Sample:
```console
$ rdy run acme-quickstart.yaml --allow-unsigned --dry-run
Would run 4 checks. Nothing was run.
  host.cpu     reads /proc/cpuinfo                       needs: none
  host.memory  reads /proc/meminfo                       needs: none
  host.disk    reads filesystem stats for /var/lib       needs: none
  net.egress   connects to 2 endpoints through the proxy needs: network
```
M1 stretch (2h), M2 at the latest. cli-ux owns it; I will add it to 07.

**S18. "The CLI does not need it and never will."**
Location: README Status section.
Problem: a promise about the future that the founder cannot test, and a gift to the first critic. Offline first is a design rule, not a prophecy.
Fix: "The CLI does not need it. Every command works offline."

### Nits

- N1. Section 1 draft: "This run was recorded on a lab VM." Add "with a test proxy". The 403 from `proxy.acme.example` cannot come from a real network.
- N2. "Fix these first:" lists a WARN too. Rename to "Fixes:" and tag each line `BLOCK` or `WARN`, blocks first.
- N3. Show HN title and body use "Rdy"; README and commands use `rdy`. Pick one for prose. Plan says product Rdy, command `rdy`; keep that split and say so in a style note.
- N4. Windows `[M3]` tag, the `ldd rdy` line ("not a dynamic executable" is glibc ldd wording; Alpine differs) are flagged by the author already. Keep the "test before shipping" note.
- N5. "Honest" appears five times (section headings, objections). Cut most. The tone is already honest; the word reads as a tell.
- N6. `acme-airgap-host.yaml`: "ask us for a port override" is fine as vendor voice but invents a feature. Say "ask the vendor for a different port".
- N7. CONTRIBUTING: add one line on where a new check goes (which crate, which file), and a pointer to the golden-file command. Add "Windows and macOS CI run on every PR" so contributors expect it. "Reviews are blunt" sits oddly next to "Be kind"; try "Reviews are direct."
- N8. Reports are written to `./rdy-report.*` and overwrite silently. Note `--out-dir` in the README, and the exit-70 case when the dir is not writable.
- N9. Series day 4 and day 5 are fine for launch (end of M3), but note day 5 needs M2 bundle and day 4 needs AWS credentials: say "read-only role" once in the demo line, as the CTA already does.
- N10. The "Used for the pre-launch walk" claims table is good. Add rows for "report has no external requests" (the README says so) and "proxy credentials never printed" (S7).

## Verified and fine

- Exit codes 0/1/2/64/70 are stated correctly in the README.
- Commands used (`run`, `verify`, `version`, `spec lint`, `bundle`) are verbs from my surface. No `--token`, no portal command anywhere in M1 copy. Good.
- Plan corrections section is accurate and matches ADR 0011 on `-p rdy`.
- `.example` hostnames throughout. No real customers.
- Check ids in the examples match the plan's five ids and CLAUDE.md families. Provisional ids are flagged.
- r/devops "lead with the question" framing, the incumbent-tool paragraph, and the objections table are plain and not hype.
- HN mechanics stated correctly: URL or text not both (so the text goes in the first comment), no upvote asks, weekday morning ET, stay on the thread. Lobsters: invite needed, "I am the author" box, `show` tag, history first. All correct as far as I know.
- Tone: short sentences, no corporate language beyond "funnel" and "lead generation" in internal notes.

## My answer: a skipped `severity: block` check

Rust-architect makes the final call in 02-engine-design. This is my recommendation.

**Rule.** A required check that did not run is an unverified blocker. It can never produce READY. Keep three buckets in the result model:

| Case | Verdict | Exit |
| --- | --- | --- |
| Any `Block` observed | NOT READY | 2 |
| No `Block` observed, but a `severity: block` check was Skipped, Timeout or Error | NOT READY | 2 |
| Only `Warn`, or a skipped / timed-out / errored `severity: warn` check | READY with warnings | 1 |
| Everything ran and passed | READY | 0 |

This tightens ADR 0008 for exactly one case. Today it would give exit 1 for a skipped block. Exit 1 reads as "warnings only", and a CI gate written as `[ $? -le 1 ]` would then pass an environment nobody checked. For a tool whose whole job is "install day should be boring", a false green is the worst failure, and a false red costs one rerun. Exit 2 is the safe side.

**Do not blur it with a real blocker in the output.** The customer must not hunt for a problem that was never found. So the text separates "failed" from "not run":

- The status word stays `SKIP`, with a visible marker that it is required, and a reason with a fix.
- The summary line counts them apart: `0 blocks, 1 warning, 3 passed, 1 required check not run`.
- The last line starts with `NOT READY` and gives the reason.
- The JSON gets `"verdict": "not_ready"`, `"reason": "required_check_not_run"`, and per check `"status": "skipped"`, `"severity": "block"`, `"skip_kind": "missing_need" | "not_in_build" | "unsupported_os"`. The portal can then show "could not check" apart from "failed", as ADR 0008 wants.

**Sample for a missing privilege:**

```console
  PASS   host.cpu        8 cores (need 8)
  SKIP   host.ports      not run, needs root to read all listeners (required)
  PASS   host.memory     32.0 GiB found, 32 GiB needed

0 blocks, 0 warnings, 2 passed, 1 required check not run

Fixes:
  1. host.ports  Not run. Rerun as root to check the listening ports:
                 sudo rdy run acme-quickstart.yaml --key <key>

NOT READY: 1 required check was not run
```

**Sample for a check this build does not have:**

```console
  SKIP   gpu.cuda        not run, no gpu checks in this build (required)
  ...
  1. gpu.cuda  Not run. This rdy build has no GPU checks. Install a newer
               rdy, or ask the vendor to mark this check as warn.

NOT READY: 1 required check was not run
```

**Detail the engine must get right:**

1. Three skip kinds, because the fix differs. `missing_need`: user can supply privilege. `not_in_build`: user can upgrade, or the vendor can relax the spec. `unsupported_os`: the check does not apply here (for example `host.selinux` on macOS). For `unsupported_os`, I recommend the check returns a pass-with-note ("not applicable on macOS"), not a skip. Otherwise a cross-platform spec can never be READY on one of its own platforms. rust-architect should decide this explicitly; it changes what `Skipped` means in ADR 0008.
2. `severity: warn` + skipped gives exit 1, as in ADR 0008. No change there.
3. Timeout and Error on a `severity: block` check follow the same rule as Skipped. They are already not passes.
4. No `--strict` or `--lenient` flag in M1. One rule is easier to document, test and trust. A `--allow-skipped` escape hatch can come later if a design partner needs it, and it must stamp the report so the portal shows it.
5. The suggestion to "ask the vendor to mark this check as warn" is real: it hands the decision to the spec author, who owns the requirements, not to the tool or the customer.

Consequence for this doc: the README demo needs `acme-quickstart.yaml` (M1), and `acme-platform.yaml` ends NOT READY until M3 and M4 ship. That is correct and worth saying out loud in the docs.

## Verdict

**Request changes.** Eight must-fix items (M1 to M8). The biggest are the ADR 0008 contradiction in the README demo, the unsafe cosign regexp, and the invented founder stories. All are quick edits. After that I expect approve with nits.
