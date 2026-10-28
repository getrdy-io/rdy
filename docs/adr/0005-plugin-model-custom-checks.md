# ADR 0005: No plugins in M1; a sandboxed `custom.exec` check in M4; no dynamic loading or WASM in v1

- Status: Accepted (revised 2026-10-28 after security-reviewer and cli-ux review); amended 2026-10-28
  (`custom.exec` moves from M3 to M4, see Amendment)
- Date: 2026-10-27

## Context

Every vendor has one or two checks no built-in family covers ("is our license daemon on port 7070",
"does `acmectl preflight` print OK"). The plan lists "Custom: a shell or script check with a declared
expected output, sandboxed" among the launch families. A check that executes commands turns a signed
spec into code execution, often as root, on a customer box. M1 scope (KICKOFF) does not include it.

## Decision

1. **M1: no plugin mechanism.** Only the built-in families: host, net, k8s. Community check families
   arrive as PRs adding a crate to this workspace and are compiled in.
2. **The `Check` trait** is public Rust API (families live in separate crates) but documented as "no
   stability promise" until 1.0 (ADR 0007).
3. **M4: `custom.exec`.** Constraints, detailed in 02-engine-design.md and the threat model first:
   - `argv` list only. No `shell: true`. A vendor who needs a shell writes `["/bin/sh", "-c", "..."]`,
     and the report and the consent list show it as written.
   - Declared expectations: exit code, stdout regex or JSON pointer equals, max duration.
   - When euid is 0, the command runs as an unprivileged user unless the check declares
     `needs: [root]`, and then the consent prompt says "as root".
   - Same subprocess policy as ADR 0004: fixed PATH, cleared environment, fresh temp working directory,
     64 KiB output caps, process-group kill on timeout.
   - **Consent is bound to the exact command list.** The list is the same output as `rdy run --dry-run`.
     Interactive: print it, ask `Run these 2 commands? [y/N]`. Non-interactive: `--allow-exec=<sha256 of
     the exec plan>` only; a bare `--allow-exec` is refused. Without consent the exec checks are
     `Skipped`, and a `severity: block` one makes the run NOT READY (ADR 0008), with
     `fix: read the list above, then rerun with --allow-exec=<hash>`.
   - An unsigned spec that contains `custom.exec` exits 64: `error: this spec runs commands and is not
     signed. rdy will not run them.` `--allow-unsigned` never implies consent.
   - Linux hardening where available: `no_new_privs`, Landlock read-only outside the temp dir. Absent on
     macOS and Windows; the docs say so.
4. **Non-goals for v1:** dynamic loading (`.so`, `.dll`, `dlopen`), WASM plugins, embedded scripting
   (Lua, Rhai, JavaScript), downloading checks at runtime, a public plugin ABI.

## Consequences

- M1 cannot express vendor-specific checks. Design partners get them as built-in checks if they
  generalize, or wait for M4.
- Everything compiled in keeps one static binary (ADR 0006) and one reviewable source tree.
- A pasted share-link command cannot carry a blanket yes: the hash changes when the commands do.
- The Embed SDK (M5) is where WASM may come back, as a build target of the engine, not a plugin host.

## Amendment (2026-10-28): M4, not M3

The code-reviewer review of `docs/plan/11-backlog.md` moved `custom.exec` to M4, and this ADR follows.
M3 already carries the AWS family, the public launch and about 270 hours. A check that turns a signed
spec into code execution, often as root, should not ship in the same milestone as the launch. Its
consent list reuses the `rdy run --dry-run` plan (M2), which gets a milestone of use first. The launch
claim "specs cannot run commands" stays true on launch day. No design partner has asked for it. The
constraints in decision 3 are unchanged.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| `custom.exec` in M1 | Not in M1 scope; needs its own threat model and review. |
| `custom.exec` in M3 | Lands in the launch milestone, which already carries AWS checks and the launch; see Amendment. |
| Blanket `--allow-exec` | Copies into a share-link command and approves whatever the spec says next week. |
| `shell: true` | Brings back the shell and its quoting bugs; `sh -c` in argv is explicit and visible. |
| Dynamic libraries | Impossible from a static musl binary, unsafe FFI, ABI churn. |
| WASM plugins (wasmtime) | Large runtime in a binary that sells on small attack surface. No customer has asked. |
| Embedded Rhai or Lua | A new language for vendors and a second sandbox to secure. |

## Tickets implied

- [M1] Unknown check ids report Skipped with a "needs a newer rdy" reason | owner: rust-engineer | est: 2h | depends on: Check trait, Need and Context in rdy-engine | exit test: the plan's example spec, which contains gpu.cuda and aws.iam, runs on M1 and reports both as SKIP with the reason and fix line, not as a parse error.
- [M4] Threat model and design note for custom.exec | owner: security-reviewer | est: 4h | depends on: none | exit test: section added to 05-threat-model.md and reviewed by rust-architect.
- [M4] Spec-origin exec policy, hash-bound consent and temp workdir for custom.exec | owner: rust-engineer | est: 4h | depends on: Threat model and design note for custom.exec | exit test: a bare --allow-exec is refused, the right hash runs commands as an unprivileged user under euid 0 in a fresh temp dir with 64 KiB caps, and a wrong hash runs nothing.
- [M4] Implement custom.exec with argv, expectations, caps and hash-bound consent | owner: check-author | est: 16h | depends on: Spec-origin exec policy, hash-bound consent and temp workdir for custom.exec | exit test: pass, fail, timeout, refused-without-consent, wrong-hash and unsigned-spec fixtures produce the documented statuses and exit codes on Linux, macOS and Windows.
