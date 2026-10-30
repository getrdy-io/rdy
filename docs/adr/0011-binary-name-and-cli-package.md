# ADR 0011: The package is `rdy`, it lives in `crates/rdy-cli`, the binary is `rdy`

- Status: Accepted (revised 2026-10-28 after security-reviewer and cli-ux review; decision 4 amended 2026-10-28 for the in-process test entry point, 08 decision A)
- Date: 2026-10-27

## Context

CLAUDE.md lists the crates as `rdy`, `rdy-spec`, ... and the binary crate directory as `crates/rdy-cli`.
Its Commands section runs `cargo run -p rdy-cli`, which only works if the package is named `rdy-cli`.
The plan reserves `rdy` on crates.io. Package name, directory and binary name must agree, because
`cargo install <name>`, `cargo run -p <name>`, release artefact names and Homebrew key off them.

## Decision

1. `crates/rdy-cli/Cargo.toml` declares `name = "rdy"` with `[[bin]] name = "rdy"`.
2. The directory stays `crates/rdy-cli` so the binary crate is obvious in the tree.
3. Commands become `cargo run -p rdy -- run examples/specs/acme-platform.yaml --json`.
4. `rdy` has one library target, `rdy_cli`, for tests and the docs CLI reference, with one entry point:
   `#[doc(hidden)] pub fn run(args, backend, hooks: RunHooks, stdout, stderr) -> ExitCode`. `main.rs`
   calls it with `rdy_engine::live_backend()` and `RunHooks::default()`, nothing else. Conditions, each
   checked in CI:
   - Test hooks (clock, run id, deadline, watchdog action, privilege ids) are fields of `RunHooks`.
     They are never argv flags or env vars, so the shipped binary cannot be steered into them.
   - `crates/rdy-cli/src` outside `#[cfg(test)]` never names `Replay` or `testing` (CI grep). The
     release build is `-p rdy` without `--all-targets`, and `cargo tree -p rdy -e normal,features
     --target <t>` lacks `rdy-engine/testing` on every leg. A marker string compiled only into the Replay
     module is absent from each dist binary before signing.
   - Process-global effects stay in `main`: the redacting log layer, the panic hook, the ring provider
     and `process::exit`. In process, the watchdog fires a hook instead of exiting. So the SEC-25
     `RUST_LOG=trace` canary test and the watchdog exit-70 test run against the real binary
     (`assert_cmd`).
   - `Backend` is sealed (ADR 0014), so `run` cannot take a third-party backend.
   - **As built (M1-074).** `run` is `async` and takes `Arc<dyn Backend>`, because the privilege snapshot
     (INV-10) reads through the backend and a test then runs it under a runtime it owns (paused time
     works). It returns `rdy_spec::result::ExitCode`. It calls the privilege gate before every command
     except help and version. `RunHooks` is a `#[non_exhaustive]` struct with no field yet: each field
     (clock, run id, deadline, watchdog action) is added by the ticket that reads it. The privilege ids
     need no hook, because a replay backend that records `/proc/self/status` supplies them. `main.rs`
     stays a one-line wrapper around `entry::main_code`, which builds the live backend and the runtime,
     because the umask and the descriptor list come before anything else opens a file. That is the one
     call of `live_backend` in the CLI (INV-07, allowed in `tests/lint-wall`). The CI conditions above
     are checked as: the `cargo tree` steps of `ci.yml` (feature tree), `crates/rdy-cli/tests/
     entry_point_wall.rs` (no `Replay` or `testing` outside `cfg(test)`, one `live_backend` call site,
     no `testing` on the normal engine dependency). The marker-string check on release archives belongs
     to the release workflow and is not built yet (see 12-progress, M1-074).
5. A no-code `rdy-cli` 0.0.1 placeholder is published whose description says "install `rdy`", so
   someone who reads the directory name and runs `cargo install rdy-cli` cannot get a squatter's code.
6. `rdy version` and `rdy --version` both work and print `rdy 0.1.0-alpha.3 (abc1234 2026-12-01)` on
   stdout; `rdy version --json` gives the same fields for bug reports.

## Consequences

- `cargo install rdy` installs the real CLI. Release artefacts are `rdy-<target>.tar.gz` (Windows
  `.zip`), as 06-release-and-distribution.md sets.
- CLAUDE.md's Commands section changes to `-p rdy` (plan correction).
- Directory and package names differ in exactly one crate. Contributors learn it once.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Package `rdy-cli`, binary `rdy`, `rdy` as a placeholder | `cargo install rdy` would install the placeholder. Two names for one thing. |
| Rename the directory to `crates/rdy` | Contradicts the CLAUDE.md layout; `rdy/crates/rdy` reads as a nested repo. |
| Leave `rdy-cli` unreserved | A squatter could publish code under the name people will guess. |

## Tickets implied

- [M1] In-process CLI entry point rdy_cli::run taking a Backend | owner: rust-engineer | est: 2.5h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: a test calls `run` with the Replay backend, RunHooks and capture buffers and gets the exit code, stdout and stderr; the CI grep, feature-tree and marker-string checks of decision 4 pass on every leg.

- [M1] Package rdy in crates/rdy-cli with binary name rdy | owner: rust-engineer | est: 1h | depends on: Create workspace skeleton | exit test: `cargo run -p rdy -- version` and `-- --version` print the documented line and `cargo package -p rdy --list` contains no stray files.
- [M1] Update CLAUDE.md commands to cargo run -p rdy | owner: docs-writer | est: 1h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: every command in the CLAUDE.md Commands block runs green on a fresh clone.
