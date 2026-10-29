# ADR 0027: Windows trust stores stay refused in M1

- Status: Accepted (2026-10-29, M1-122). Settles what ADR 0021 decision 5 called temporary.
- Date: 2026-10-29

## Context

01 section 4.3 asks for ACL rules on Windows: the store and `%ProgramData%\rdy` must belong to
`Administrators` or `SYSTEM`, no other principal may hold write, delete or `WRITE_DAC`, and neither may be a
reparse point. `BUILTIN\Users` may create folders under `C:\ProgramData`, so a store that a non-admin
pre-created must fail. M1-122 was to build this.

Reading a DACL takes Win32 calls (`GetSecurityInfo`, `GetAce`, `EqualSid`). From Rust that is `windows-sys`
and `unsafe`, and `#![forbid(unsafe_code)]` holds in `rdy-cli`. The safe wrappers on crates.io are
`windows-permissions` (last release 2021), `windows-acl` (2021) and, for elevation, `is_elevated` (2019).
All sit on `winapi`, and none is maintained. Telling an elevated run from a normal one needs a token query,
which has the same two options.

## Decision

1. **A Windows trust store that exists is refused** with `trust_store_insecure` (exit 64) and the reason
   "cannot check who can change it". This is ADR 0021 decision 5, now the M1 design and not a stop-gap.
   A missing file is an empty store. Saving is not supported.
2. **Windows has no user store.** The layout has `%ProgramData%\rdy\trust.yaml` and no user path, and
   `%APPDATA%` is not read. An elevated run is therefore never able to read a user path, and rdy does not
   need to detect elevation.
3. **No FFI and no unmaintained crate goes into the trust path in M1.** Neither `unsafe` nor `winapi`
   wrappers touch the code that decides what to trust.
4. **The fix line does not name `run --key`.** 07 section 1, rule 8 and 01 section 4.7 forbid hints that suggest it. The line says
   the file is not read on Windows yet and to move it away. The Windows page of the docs says that a
   Windows run is verified with the vendor key given for that run.
5. **The follow-up is M2-105**, "rdy-winacl FFI crate: admin-only ProgramData store and elevation
   detection": a small crate with `windows-sys`, one documented `unsafe` block per call, and a safe
   interface (`store_is_admin_only(path)`, `is_elevated()`). It follows CLAUDE.md's rule for FFI crates and
   needs a security review. The coordinator files the backlog row in a correction PR.
6. **Tests.** On Windows CI, a store made by the current user, a store in a folder where `Users` has a
   write ACE (granted with `icacls`), and a store under a pretend `%ProgramData%` each exit 64 with
   `trust_store_insecure`. The Windows layout has no user path even when `HOME`, `XDG_CONFIG_HOME` and
   `APPDATA` point at stores.

## Consequences

- On Windows, a spec cannot be verified against a pinned key in M1. A run uses the vendor key for that run
  only. This is the cost, and it is paid by the one platform whose ACL model we cannot read safely yet.
- Any account that can create `C:\ProgramData\rdy\trust.yaml` can make every Windows run that reads the
  system store exit 64. It blocks verification and never makes a planted store trusted (threat model S2).
- `rdy trust add` on Windows exits 64 with "not supported". The Windows fix line of 01 section 4.8 changes
  with this ADR.
- macOS extended ACLs stay a residual risk for the same reason: reading them needs FFI (ADR 0021,
  threat model 05 Surface 2).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| A tiny FFI crate with `windows-sys` in M1 | Right answer, but new unsafe code in the trust path needs its own review and is more than this ticket. It is M2-105. |
| Safe crates (`windows-permissions`, `is_elevated`) | Unmaintained for years, on `winapi`, in the one place that decides trust. |
| Shell out to `icacls` and parse the text | Output is localised and has no stable format. A wrong parse trusts a bad store. |
| Read the store without ACL checks | A store a non-admin planted would be trusted by an elevated run (threat model S2). |

## Tickets implied

- [M2] M2-105 rdy-winacl FFI crate: admin-only ProgramData store and elevation detection | owner: rust-engineer | est: 8h | depends on: M1-122, security-reviewer sign-off | exit test: on Windows CI a ProgramData\rdy directory created by a non-admin user, or with a Users write ACE, exits 64 with trust_store_insecure, and an Administrators-owned store with a protected DACL is read.
