# ADR 0016: Output is confined to one new directory, opened early through a cap-std handle

- Status: Accepted (2026-10-28, after the security-reviewer review of ADRs 0013 to 0016)
- Date: 2026-10-28

## Context

ADR 0003 decision 1 and threat model INV-09 and I3: reports go into one new directory, 0700 and 0600 on
Unix, no symlink following, temp file then rename; on Windows the default directory is under the user
profile. `rdy` often runs as root or elevated in a shared working directory; an elevated Windows prompt
starts in `C:\Windows\System32`. Reviews found that creating the directory at the end costs a whole run
before failing, that the spec copy could come from unverified bytes, that the owner and mode check has
no Windows meaning, and that the watchdog could race the normal write.

## Decision

1. **Where.** Unix: under `--out-dir`, default `.`. Windows: under `--out-dir`, default
   `%USERPROFILE%\rdy-reports` (created if missing; owner, SYSTEM and Administrators by default). `.` is
   used on Windows only when given explicitly. cli-ux confirms the folder name.
2. **When.** Right after spec verification and before the first check. `OutputDir::create_new` creates
   `rdy-report-<product>-<ts>/` with `create_dir`. If the name exists it retries with `-2` to `-9`, then
   exits 70. The product slug is re-checked against `^[a-z0-9][a-z0-9-]{0,62}$`.
3. **Post-open checks**, or exit 70 before any check runs. The handle is held for the whole run.
   - Unix: open no-follow, then `fstat`. It must be a directory owned by the effective user. Check
     `mode & 0o777` and `fchmod` to 0700, which also clears a setgid bit inherited from the parent. The
     hint names NFS `root_squash` when the owner check fails.
   - Windows: the opened handle is a directory, `FILE_ATTRIBUTE_REPARSE_POINT` is clear, and its final
     path equals the expected path. Junctions and symlinks with the target name are both refused.
4. **Writes.**
   - Files are created inside the handle with `create_new`, mode 0600 and `fchmod` (umask
     independent), as `.name.tmp`, written, fsynced, and renamed inside the same handle.
   - The directory is fsynced on Unix; on Windows that step is a no-op, never an exit 70.
   - On Windows the final rename is retried up to 5 times at 100 ms, because security software
     briefly holds new files.
   - The verified spec is copied under fixed names, `spec.yaml` and `spec.yaml.minisig`, never the
     operator's file name.
5. **Types.** Writers take only `&RedactedReport` (ADR 0015) and `&VerifiedSpecBytes` (the buffers
   `rdy_spec::load` verified).
6. **One writer.** An `AtomicU8` write state (`Running`, `Writing`, `Done`) decides between the CLI and
   the watchdog: whoever moves it from `Running` to `Writing` writes. The loser never writes. A watchdog
   that loses waits at most 5 s for `Done`, then exits 70.
7. **Residuals, named in the report's notes until SEC-58:** Windows files inherit the directory ACL;
   macOS honours inheritable ACEs on the parent before mode bits.
8. `cap-std` and `cap-primitives` pinned to 3.4.1 or later (RUSTSEC-2024-0445). Dependency approval is
   recorded in the PR under the 05 dependency policy. `--no-report` creates nothing.

## Consequences

- A bad output location fails in the first second, not after a five-minute run.
- A killed run leaves at most `.tmp` files inside the new directory, never a file under a final name.
- Windows users find reports in one place by default, with an owner-only profile ACL.
- One more dependency, `cap-std` (with `rustix`, already used for ids and statvfs).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Hand-rolled `openat` with `O_NOFOLLOW` via `rustix`, plus a Windows path | Two code paths to get right; cap-std already covers all four OSes. |
| Create the directory at the end | A full run before an exit 70, and the parent can change in between. |
| Windows default `.` with a warning | An elevated prompt writes into `System32` with a readable ACL (05 I3). |
| Windows default `%LOCALAPPDATA%\rdy\reports` | Same ACL, but users cannot find it to carry the report out. |

## Tickets implied

- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: product `../x` fails validation, a pre-planted symlink is not followed, a taken name moves to `-2`, modes are 0700 and 0600 under a setgid parent, the spec copy matches the verified bytes under fixed names, and a killed run leaves no file under a final name.
- [M1] Windows output directory default and reparse-point checks | owner: rust-engineer | est: 1h | depends on: SEC-19 Confine writes to a new output dir with safe names | exit test: on the Windows CI leg the default lands under %USERPROFILE%\rdy-reports, and a pre-planted junction and a symlink with the target name are both refused before the first check.
