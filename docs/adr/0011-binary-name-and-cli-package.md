# ADR 0011: The package is `rdy`, it lives in `crates/rdy-cli`, the binary is `rdy`

- Status: Accepted (revised 2026-10-28 after security-reviewer and cli-ux review)
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
4. `rdy` publishes no library API: `src/main.rs` plus private modules.
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

- [M1] Package rdy in crates/rdy-cli with binary name rdy | owner: rust-engineer | est: 1h | depends on: Create workspace skeleton | exit test: `cargo run -p rdy -- version` and `-- --version` print the documented line and `cargo package -p rdy --list` contains no stray files.
- [M1] Update CLAUDE.md commands to cargo run -p rdy | owner: docs-writer | est: 1h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: every command in the CLAUDE.md Commands block runs green on a fresh clone.
