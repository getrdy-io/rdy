# ADR 0048: Docs-test markers, the run folder, and README transcript goldens

- Status: Proposed (M1-136). Stacked on PR #85 (M1-133).
- Date: 2026-11-17

## Context

09 says a fenced block marked `tested` runs in docs-test, with an exit set such as `exit=0|1|2`. M1-136 adds the
runner and its exit test: a CI job runs every tested block live, asserts the exit set and a shape regex, never
host numbers, and diffs every README transcript against a golden file. 09 does not say where the shape goes,
what a block that cannot run is called, how a block stays off the network, or what a transcript golden holds.
ADR 0047 already defined `install-only` and `pending=<ticket>`.

## Decision

1. **Every shell block carries one marker.** A fenced `sh`, `bash`, `console`, `powershell` or `pwsh` block in
   `README.md` or `docs/src/content/docs/` has exactly one of:
   `tested exit=<n>|<n> shape=<regex>`, `install-only`, `pending=<ticket>`, `skip=<reason>`.
   `exit=` defaults to `0`. `shape=` is required on `tested`. The regex has no spaces (write `\s`) and is matched with
   line-edge `^` and `$` against stdout then stderr. A block with no marker fails the test, so a new command
   cannot reach a page untested and unexplained. `skip=` takes a reason from a closed list: `placeholder`,
   `builds` (a build from source), `network`, `needs-release-files`, `windows-only` and `page-test` (a dedicated page test runs this block's commands as written). Another word fails the
   test, so the set only grows by a reviewed change. `pending=` takes a ticket id (`M<n>-<nnn>`) that has a `todo`
   row in `docs/plan/12-progress.md`, so a ticket that merged cannot keep a block pending. `install-only` blocks
   run as a user with no rights on a clean host, so a block that needs root (`--allow-root`) or a folder of
   release files stays `skip=`. The words go in 09 rule 7 too.
2. **The runner is an integration test of the `rdy` package** (`crates/rdy-cli/tests/docs_test.rs`). It runs on
   every leg of the existing `test` job, which is in `ci-ok`, against the binary that job built. No new workflow,
   no new `uses:`, no extra permission. A named step prints its count and its skips on each leg. 09's
   `cargo xtask docs-test` in `docs-gen` stays an M2 option for the Starlight build.
3. **Run folder.** Each block gets a fresh folder with `examples/` and a flat copy of every example spec (the pages
   say "save the spec in the folder you are in"), an empty `HOME`, and a cleared environment: no proxy variable,
   no `RUST_LOG`, `NO_COLOR=1`. The block runs as `sh -c`; the exit code is the last command's, so a block with
   several commands checks only the last exit. A block that must check two exits is two blocks. On a timeout the
   runner kills the whole process group, not only `sh`. A `console` block
   runs its first `$ ` line. Each block has a 60 s timeout.
4. **No network.** `rdy` is a wrapper script in a temporary folder at the front of `PATH`. It adds `--no-network` to `rdy run` unless
   the block has it. The pages show the command without the flag, as a reader types it. A block that needs the
   network, such as the install commands, is `skip=network` or `install-only`, and is never tested here. A test
   proves the wrapper: the example's `net.egress` is SKIP, not BLOCK. The networked path is not proven here:
   "live" means the real binary on the real host, with the network off. M2-100 plans a docs-test that runs with
   no network at all.
5. **README transcripts.** `transcript=<path>` on a README `console` block names a golden under
   `tests/fixtures/readme/`. The block body must equal the file. Every README `console` block needs one, and a
   golden no block uses fails the test. A transcript is hand-trimmed from a real run and has host numbers, so it is
   not compared with live output. The live run of its first command is asserted by the block's exit set and shape.
   The golden's own `$ echo $?` value must be in the block's exit set, and its verdict line (the last line before
   `$ echo $?`) must match the shape, so the hand-written text cannot drift from what the block declares.
   `transcript=` on a docs page is refused.
   M1-137 replaces the transcript when it writes the README.
6. **Windows.** The runner needs a POSIX shell. The `windows-2022` image has Git's `sh`, but its path and quote
   translation is not verified for these blocks, so the blocks are skipped on Windows with the reason printed.
   The marker, golden and self tests run on the legs that run tests. `first_run_page.rs` still runs the first run page's
   commands directly on Windows.

## Consequences

- A page edit that changes an exit code or a shape fails the `test` job on every Unix leg.
- Authors write the shape with `\s`. The match is multi-line, so `^$` matches any empty line. A shape of `\A\z`
  means "prints nothing".
- The wrapper is found through `PATH`, so `env rdy` and `xargs rdy` work. An absolute path to `rdy` does not
  reach it. Such a block is `skip=`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| A new `docs-test` workflow | Another job to pin, another cache, and not in `ci-ok` unless added. The `test` job already builds the binary on every leg. |
| `xtask docs-test` now | Needs the binary built and found by xtask. 09 plans it for M2 with docs-gen. |
| Put the shape in a comment under the block | Moves the contract away from the fence. The info string is read by the same line that runs the block. |
| Compare transcripts with live output | A transcript has host numbers. That is the thing the rule forbids. |

## Amendment 2026-11-18 (M1-135)

Rule 5 said a transcript is hand-trimmed from a real run and every golden must be used by a block. M1-135
replaces that. The four goldens in `tests/fixtures/readme/` are made in process from the Replay envs by
`crates/rdy-cli/tests/env_harness/readme.rs`, and `UPDATE_GOLDENS=1` rewrites them. A README block still
must equal its golden, and the golden's exit code and verdict line must still agree with the block's marker.
A golden that no README block uses is allowed only if the generator lists it, in
`crates/rdy-cli/tests/common/readme_goldens.rs`. That file is the one list: the generator test and
`docs_test` both read it, and a test fails if the folder and the list differ. The first command of a block
still runs live, with the exit set and shape as before. The spec is shown under the name a reader types, and
the version line is `rdy <version>`.
