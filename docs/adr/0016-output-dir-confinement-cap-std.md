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
     path equals the expected path. A pre-planted junction or symlink with the target name is never
     followed or written through (the name moves to `-2`, as on Unix); one swapped in after `mkdir`
     stops the run before the first check (M1-037).
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

## Build notes (M1-036)

Four details the build settled. None changes a decision above.

- **Version.** The pin is `cap-std` and `cap-primitives` 4.0.3, the newest release when this was built.
  It is above the 3.4.1 floor of decision 8.
- **The open step is `openat`.** `cap-std` opens a directory with `O_PATH` on Linux, and `fchmod` and
  `fsync` fail on such a descriptor (`EBADF`). So on Unix the new directory is opened with
  `openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW)` on the held parent, through `rustix`. The name is one
  path component that `OutputDir` built, so it cannot leave the parent. Every file operation inside
  still goes through `cap-std`. Windows uses `cap_primitives::fs::open_dir_nofollow`.
- **No replace.** The final name is given with a hard link from the temp file, which fails if the name
  exists. It falls back only when the link fails with `EPERM`, `EOPNOTSUPP`, `EMLINK` or `ENOSYS`, the
  codes of a file system without hard links. Any other error is reported. The fallback is
  `renameat2(RENAME_NOREPLACE)` on Linux and macOS, and a check plus a rename where that flag is
  missing. Windows tries the hard link first and falls back on any error but "exists".
- **File names.** The files in a `-2` folder are named after the folder (`rdy-report-<product>-<ts>-2.json`).

## Build notes (M1-037)

What the Windows build does. Decision 3 is amended above to say what happens to a link with the
target name. Nothing else here changes a decision.

- **Default folder.** `default_report_parent()` opens `%USERPROFILE%\rdy-reports` and makes it if it is
  missing (the profile folder must exist). The profile is held open, and the default folder is opened
  as a name below that handle without following a link, so a link swapped in for it after the make is
  refused. Its handle gets the same attribute and final path checks as the run folder, so a symlink,
  a junction, any other reparse point or a file in the way is `NotPlainFolder`. The run folder is then
  made through that held parent (`OutputDir::create_new_in`). The open is relative to the handle. On
  Windows `cap-std` turns the handle back into a path to make a folder, so a race between the make and
  the open is possible, and it fails closed: the open and the checks refuse a swapped link. The
  profile is opened by its resolved local path, and resolved again after the open, because std has no
  safe way to read the final path of a handle without FFI. A different answer is refused.
- **No network default.** `USERPROFILE` must be an absolute path on a local drive, and so must its
  resolved form, so a share (`\\server\share`, or a mapped drive that points at one) is
  `NoDefaultFolder`. A default run never sends a report over SMB. `--out-dir` is the operator's
  choice and is not checked this way. It is opened following links, and only the new run folder in it
  is checked.
- **Post-open checks (decision 3).** The handle's attributes must have the folder bit set and
  `FILE_ATTRIBUTE_REPARSE_POINT` clear. That catches every reparse tag, such as cloud-sync
  placeholders, and not only symlinks and junctions. Then `canonicalize(path)` must equal
  `canonicalize(parent)` plus the folder name. That second step reads the final path by name, with no
  FFI, so it is a second check beside the handle. A failure of any step is an error, so the check
  fails closed.
- **Error mapping.** When the no-follow open fails and the name is no longer a plain folder (a link, a
  junction or a file), the error is `NotPlainFolder`, which gives exit 70 and `report_write` with a
  fix hint. The same holds on Unix for a symlink swapped in after the `mkdir`.
- **A link with the target name.** As on Unix, a junction or symlink that already has the folder
  name makes `mkdir` report the name as taken, and the report goes to `-2`. The link is not followed,
  opened or removed.
- **ACLs stay a residual.** Reading or setting an ACL needs the Win32 security API, which needs
  `unsafe`. rdy keeps `forbid(unsafe_code)`, so M1 sets no ACL on Windows and gives no ACL
  guarantee. The folder keeps the ACL it inherits. For the default folder that is the profile ACL
  (owner, SYSTEM and Administrators by default). For `--out-dir` elsewhere it is whatever that folder
  passes on. The worst case is `--out-dir C:\`: a new folder at a drive root inherits an ACL that
  lets `Authenticated Users` modify it, so other local users can read the report. M1-057 adds a note
  to the Windows report that says this and tells the user to keep the default folder. The note stays
  until SEC-58 (M2-085) and the `rdy-winacl` crate (M2-105). **As built (M1-057):** the Report has no
  top-level `notes` field in `rdy/v1`, so the note is a `note:` line on stderr, printed on Windows when
  `--out-dir` was given. The default folder prints none. The macOS residual (an inheritable access rule on the parent applies before the mode bits) is a `note:` line on stderr after every written report on macOS. Refusing every Windows run for lack of an
  ACL check was considered and not taken: it would remove Windows reports from M1, and the reparse
  and final path checks close the redirect attack that this ticket is about.
- **Other targets.** A target with neither Unix modes nor these checks refuses every folder.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Hand-rolled `openat` with `O_NOFOLLOW` via `rustix`, plus a Windows path | Two code paths to get right; cap-std already covers all four OSes. |
| Create the directory at the end | A full run before an exit 70, and the parent can change in between. |
| Windows default `.` with a warning | An elevated prompt writes into `System32` with a readable ACL (05 I3). |
| Windows default `%LOCALAPPDATA%\rdy\reports` | Same ACL, but users cannot find it to carry the report out. |

## Tickets implied

- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: product `../x` fails validation, a pre-planted symlink is not followed, a taken name moves to `-2`, modes are 0700 and 0600 under a setgid parent, the spec copy matches the verified bytes under fixed names, and a killed run leaves no file under a final name.
- [M1] Windows output directory default and reparse-point checks | owner: rust-engineer | est: 1h | depends on: SEC-19 Confine writes to a new output dir with safe names | exit test: on the Windows CI leg the default lands under %USERPROFILE%\rdy-reports, and a pre-planted junction or symlink with the target name is never followed or written through (the name moves to `-2`), and one swapped in after mkdir stops the run before the first check.
