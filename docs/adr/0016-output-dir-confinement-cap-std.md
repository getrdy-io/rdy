# ADR 0016: Output is confined to one new directory, opened early through a cap-std handle

- Status: Proposed (2026-10-28, applies the security-reviewer review of 02; security-reviewer re-review pending)
- Date: 2026-10-28

## Context

ADR 0003 decision 1 and threat model INV-09: reports go into one new directory, 0700 and 0600 on Unix,
no symlink following, temp file then rename. `rdy` often runs as root in a shared working directory.
The 02 review (SF-03) found that creating the directory at the end costs a whole run before failing,
that opening it by name after `create_dir` leaves a swap window, and that the spec copy could come from
bytes nobody verified.

## Decision

1. Right after spec verification and before the first check, `OutputDir::create_new(parent, name)`
   creates `rdy-report-<product>-<ts>/` under `--out-dir` (default `.`) with `create_dir` (fails if it
   exists), opens it with a no-follow directory open, and checks with `fstat` that it is a directory
   owned by the effective user with mode 0700. Otherwise exit 70 before any check runs. The handle is
   held for the whole run.
2. The product slug is re-checked against `^[a-z0-9][a-z0-9-]{0,62}$` before the name is built.
3. Files are created inside the handle with `create_new`, mode 0600 and `fchmod` (umask independent),
   as `.name.tmp`, written, fsynced, renamed inside the same handle, then the directory is fsynced.
4. Writers take only `&RedactedReport` (ADR 0015) and `&VerifiedSpecBytes` (the in-memory buffers that
   `rdy_spec::load` verified), so unredacted text and unverified spec bytes cannot be written.
5. `cap-std` (`cap_std::fs::Dir`) on all four targets. On Windows the directory inherits the parent's
   ACL in M1; the docs say so and SEC-58 tightens it in M2.
6. `--no-report` creates nothing. The M1 watchdog (02) writes through the same held handle.

## Consequences

- A bad output location fails in the first second, not after a five-minute run.
- A killed run leaves at most `.tmp` files inside the new directory, never a file under a final name.
- One more dependency, `cap-std` (with `rustix`, already used for ids and statvfs).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Hand-rolled `openat` with `O_NOFOLLOW` via `rustix`, plus a Windows path | Two code paths to get right; cap-std already covers all four OSes. |
| Create the directory at the end | A full run before an exit 70, and the parent can change in between. |
| Write into the working directory without a new directory | Pre-planted symlinks and name collisions in shared directories. |

## Tickets implied

- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: product `../x` fails validation, a pre-planted symlink is not followed, an existing directory is refused before the first check, modes are 0700 and 0600, the spec copy matches the verified bytes, and a killed run leaves no file under a final name.
