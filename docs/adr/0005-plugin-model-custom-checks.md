# ADR 0005: No plugins in M1; a sandboxed `custom.exec` check later; no dynamic loading or WASM in v1

- Status: Accepted
- Date: 2026-10-27

## Context

Every vendor has one or two checks no built-in family covers ("is our license daemon on port 7070",
"does `acmectl preflight` print OK"). The plan lists "Custom: a shell or script check with a declared
expected output, sandboxed" among the launch families. But a check that executes commands turns a signed
spec into remote code execution as root on a customer box. M1 scope (KICKOFF) does not include it.

## Decision

1. **M1: no plugin mechanism.** Only the built-in families: host, net, k8s. Community check families
   arrive as PRs adding a crate to this workspace and are compiled in.
2. **The `Check` trait is internal to the workspace in M1.** It is public Rust API (families live in
   separate crates) but documented as "no stability promise" until 1.0 (ADR 0007).
3. **M3: `custom.exec`.** Design constraints, to be detailed in 02-engine-design.md before building:
   - `argv` list, no shell. `shell: true` is an explicit opt-in that the report flags.
   - Declared expectations: exit code, stdout regex or JSON pointer equals, max duration.
   - Runs as the invoking user. Never escalates. A `needs: [root]` declaration only makes it skip when
     not root.
   - Cleared environment plus an allowlist, working directory in a fresh temp dir, stdout and stderr
     capped at 64 KiB, killed on timeout (ADR 0004).
   - Opt-in per run: the CLI lists every command a spec would execute and refuses to run them without
     `--allow-exec` or an interactive yes. Signed specs only; `--allow-unsigned` never implies `--allow-exec`.
   - Linux hardening where available: `no_new_privs`, Landlock read-only filesystem outside the temp dir.
     Absent on macOS and Windows, and the docs say so.
4. **Non-goals for v1:** dynamic loading (`.so`, `.dll`, `dlopen`), WASM plugins, embedded scripting
   (Lua, Rhai, JavaScript), downloading checks at runtime, a public plugin ABI.

## Consequences

- M1 cannot express vendor-specific checks. Design partners whose blockers need one get them as built-in
  checks if they generalize, or wait for M3.
- Keeping everything compiled in keeps one static binary (ADR 0006) and one reviewable source tree.
- The Embed SDK (M5) is the place to revisit WASM, as a build target of the engine, not a plugin host.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| `custom.exec` in M1 | Not in M1 scope, and it needs its own threat model and security review. |
| Dynamic libraries | Impossible from a static musl binary (no `dlopen`), unsafe FFI, ABI churn. |
| WASM plugins (wasmtime) | Adds a large runtime to a binary that sells on small attack surface. Capability design is real work. No customer has asked. |
| Embedded Rhai or Lua | A new language for vendors to learn and a second sandbox to secure. Vendors already have shell and their own CLIs. |
| Shell string checks | Quoting bugs and injection through spec values. argv lists avoid both. |

## Tickets implied

- [M1] Unknown check ids report Skipped with a "needs a newer rdy" reason | owner: rust-engineer | est: 2h | depends on: Define public spec types in rdy-spec | exit test: the plan's example spec, which contains gpu.cuda and aws.iam, runs on M1 and reports both as Skipped, not as a parse error.
- [M3] Threat model and design note for custom.exec | owner: security-reviewer | est: 4h | depends on: none | exit test: section added to 05-threat-model.md and reviewed by rust-architect.
- [M3] Implement custom.exec with argv, expectations, caps and --allow-exec | owner: check-author | est: 12h | depends on: Threat model and design note for custom.exec | exit test: fixtures for pass, fail, timeout and refused-without-flag all produce the expected statuses on Linux, macOS and Windows.
