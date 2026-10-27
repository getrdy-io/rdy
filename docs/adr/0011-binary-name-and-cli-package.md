# ADR 0011: The package is `rdy`, it lives in `crates/rdy-cli`, the binary is `rdy`

- Status: Accepted
- Date: 2026-10-27

## Context

CLAUDE.md lists the crates as `rdy`, `rdy-spec`, ... and the binary crate directory as `crates/rdy-cli`.
Its Commands section runs `cargo run -p rdy-cli`, which only works if the package is named `rdy-cli`.
The plan reserves `rdy` on crates.io. Package name, directory and binary name have to agree, because
`cargo install <name>`, `cargo run -p <name>`, cargo-dist artefact names and Homebrew all key off them.

## Decision

1. `crates/rdy-cli/Cargo.toml` declares `name = "rdy"` with `[[bin]] name = "rdy"`, `path = "src/main.rs"`.
2. The directory stays `crates/rdy-cli` so it is obvious in the tree which crate is the binary.
3. Commands become `cargo run -p rdy -- run examples/specs/acme-platform.yaml --json`.
4. `rdy` publishes no library API: `src/main.rs` plus private modules. Shared logic belongs in a library
   crate.
5. No `rdy-cli` package is published. If someone squats it, nothing breaks.

## Consequences

- `cargo install rdy` installs the real CLI. cargo-dist artefacts are `rdy-<target>.tar.xz`.
- CLAUDE.md's Commands section must change to `-p rdy` (recorded as a plan correction).
- Directory and package names differ in exactly one crate. Contributors learn it once.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Package `rdy-cli`, binary `rdy`, `rdy` as a placeholder | `cargo install rdy` would install the placeholder. Two names for one thing. |
| Rename the directory to `crates/rdy` | Contradicts CLAUDE.md layout, and `rdy/crates/rdy` reads as a nested repo. |

## Tickets implied

- [M1] Package rdy in crates/rdy-cli with binary name rdy | owner: rust-engineer | est: 1h | depends on: Create workspace skeleton | exit test: `cargo run -p rdy -- version` prints the version and `cargo package -p rdy --list` contains no stray files.
- [M1] Update CLAUDE.md commands to cargo run -p rdy | owner: docs-writer | est: 1h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: every command in the CLAUDE.md Commands block runs green on a fresh clone.
