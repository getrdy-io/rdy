# ADR 0036: host.security_agents matches the kernel's cut process name, and a check crate may embed its own shipped data

- Status: Proposed, needs security-review (it adds an entry to the lint wall and one dependency to a check crate)
- Date: 2026-10-30

## Context

M1-146 builds `host.security_agents`. 03 section 2 says the Linux source is `/proc/*/comm` plus the basename
of `/proc/*/cmdline` argv[0], because the kernel cuts `comm` to 15 bytes. Two other rules disagree with that
text.

1. The read policy (02, "The probe facade") refuses `/proc/<pid>/cmdline`, `environ`, `exe`, `fd` and the rest.
   Only `status`, `stat`, `statm`, `comm`, `cgroup`, `mountinfo`, `mounts`, `limits` and `net` pass. Command
   lines carry tokens and passwords, and INV-07 keeps them out of every check. `/proc/<pid>/stat` and `status`
   hold the same cut name as `comm`.
2. 03 Appendix B says `agents.toml` is embedded at build time. The lint wall (02, "Lint wall") lets a check
   crate use `include_str!` only inside a `#[cfg(test)]` module, and `rdy-checks-host` may not depend on
   `toml` (`ci/check-crate-deps.toml`).

## Decision

1. **The check does not read `cmdline`.** It reads `/proc/<pid>/comm` and compares it with the catalog by
   whole name. A catalog name longer than 15 bytes also matches a `comm` of exactly 15 bytes that equals its
   first 15 bytes (`elastic-endpoin` matches `elastic-endpoint`). A shorter `comm` must match whole. The read
   policy and the 03 rule against showing a command line are unchanged.
2. **The cost is a rare false match.** Another program whose name starts with the same 15 bytes would match.
   The message says "a process with this name is running", the evidence shows the name as the kernel shows it,
   and the fix text claims nothing about the product. Hiding the cmdline matters more than this.
3. **A check crate may embed its own shipped data with `include_str!` in non-test code, by exact entry.**
   `INCLUDE_SHIPPED_DATA_ALLOWED` in `tests/lint-wall/tests/allow_grep.rs` lists `(file, literal, reason)`.
   The file holds one include call, the literal is `../data/<name>.toml`, the file sits directly in the
   crate's `src/`, and the target exists in the crate's own `data/`. `crates/*/data/` is already `eol=lf` in
   `.gitattributes` and `data/**` is added to the crate's `include`. The first entry is
   `crates/rdy-checks-host/src/agents.rs` with `../data/agents.toml`.
4. **`rdy-checks-host` may depend on `toml`.** It parses text that `include_str!` already put in the binary.
   It opens no file. `serde` was already on the list. The rdy-plan crate table already names `toml` for this
   crate.
5. **The catalog is public API.** `rdy_checks_host::agents` exposes `Catalog`, `Agent` and `catalog()`, so
   `rdy spec lint` can list the known agent ids (the spec reference says it does) and the release workflow can
   call `Catalog::stale` for the 180-day rule in 03 Appendix B.

## Alternatives considered

- **Allow `cmdline` for this check.** Rejected. It would open a secret-bearing source for every check that
  declares `/proc`, and the policy is an allowlist by directory, not by check.
- **Match on `comm` only, whole name.** Rejected. It misses every product whose name is over 15 bytes, which
  is three of the ten seed entries.
- **Keep the catalog as a Rust table.** Rejected. 03 and the review want a data file the founder can read and
  approve, and the 08 matrix names `agents.toml`.
- **Generate a Rust table from the TOML with xtask.** Rejected for M1. It adds a generator and a drift check
  to save one parser dependency in a crate that must stay small and boring.
- **Read the file at run time.** Rejected. A check crate reads the machine only through its Probe, and a
  catalog that a customer can edit would let them hide a product from the report.

## Consequences

- 03's source line for `host.security_agents` changes: no argv[0], and the cut-name rule instead.
- Windows and macOS (M2-007, M2-009) get full process names from `sysinfo`, so the cut rule only applies to
  Linux there. The same catalog serves all three; `process_names` is one list.
- A future check that ships data adds one entry to the new list and needs security-review.
- `toml` is now in the release binary. It was already in the lock file through the engine's `testing` feature.

## Tickets implied

- Release workflow step that calls `Catalog::stale(today, 180)` and fails on a stale entry (release-engineer).
- `rdy spec lint` lists `agents::catalog()` ids and warns on an unknown id in `forbid` or `allow` (cli-ux, M1-late).
