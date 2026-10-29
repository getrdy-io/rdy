# ADR 0027: Windows trust stores stay refused in M1

- Status: Accepted, security-reviewed and architect-reviewed (PR #68). Settles what ADR 0021 decision 5 called temporary.
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
   `%APPDATA%` is not read. An elevated and a normal run read the same single store, so M1 needs no
   elevation detection for the trust path. `whoami` feeds only the `root` need and `identity.elevated`.
3. **No FFI and no unmaintained crate goes into the trust path in M1.**
4. **A `--key` run never reads a store.** `rdy verify --key` and `rdy run --key` do not call
   `trust::load`, so a store that is refused (or planted) cannot stop them. This is what keeps Windows
   usable in M1: any member of `Users` can create `C:\ProgramData\rdy\trust.yaml`, and if a `--key` run
   read the stores, every Windows run would exit 64. 01 section 4.4 says so. M1-126 owns the exit test
   (PR #69): on `windows-x64` with a store present, `rdy verify --key` exits 0, and `rdy verify` without
   `--key` exits 64 with `trust_store_insecure`.
5. **The fix lines point at an administrator and the docs.** The `trust_store_insecure` fix on Windows is
   `ask an administrator to remove <path>`, then a link to https://docs.getrdy.io/unsigned. The
   `spec_key_unknown` fix on Windows points at the same page, because `rdy trust add` is not supported
   there. No line names `run --key` or `--allow-unsigned` (07 section 1 rule 8, 01 section 4.7). The page
   itself is written by M1-133 (docs-writer).
6. **The follow-up is M2-105**, "rdy-winacl FFI crate: admin-only ProgramData store and elevation
   detection for the trust path" (8 h, depends on M1-122, filed in PR #69). It is a small crate with
   `windows-sys`, one documented `unsafe` block per call and a safe interface (`store_is_admin_only(path)`,
   `is_elevated()`), and it needs a security review. It takes the ProgramData folder from
   `FOLDERID_ProgramData` (`SHGetKnownFolderPath`), not from the environment, which the caller sets.
   M2-105 also adds `rdy-winacl` to the crate list in CLAUDE.md (a founder edit), an ADR 0007 note, and the
   documented `forbid(unsafe_code)` exception for that crate.
7. **Tests.** On Windows CI, a store made by the current user, a store in a folder where `Users` has a
   write ACE (granted with `icacls`), and a store under a pretend `%ProgramData%` each exit 64 with
   `trust_store_insecure`. The Windows layout has no user path, even with a real `%APPDATA%` or when `HOME`
   and `XDG_CONFIG_HOME` point at stores. The `strace` test of the root rule runs the library call, not the
   binary. The check on the real binary is part of the M1-126 exit test (PR #69).

## Consequences

- On Windows, a spec cannot be verified against a pinned key in M1. A run uses the vendor key for that run
  only (decision 4). This is the cost, and it is paid by the one platform whose ACL model we cannot read
  safely yet.
- Any account that can create `C:\ProgramData\rdy\trust.yaml` can make every Windows run that reads the
  system store exit 64. It blocks verification and never makes a planted store trusted (threat model S2).
- `rdy trust add` on Windows exits 64 with "not supported" (07 section 1). The Windows fix line of 01
  section 4.8 changes with this ADR.
- macOS extended ACLs stay a residual risk for the same reason: reading them needs FFI (ADR 0021,
  threat model 05 Surface 2).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| A tiny FFI crate with `windows-sys` in M1 | Right answer, but new unsafe code in the trust path needs its own review and is more than this ticket. It is M2-105. |
| Safe crates (`windows-permissions`, `is_elevated`) | Unmaintained for years, on `winapi`, in the one place that decides trust. |
| Shell out to `icacls` and parse the text | Output is localised and has no stable format. A wrong parse trusts a bad store. |
| Elevation detection with `whoami.exe /groups /fo csv` for trust | Not needed in M1 (decision 2). It would be parsed tool output deciding trust, and the integrity SID is not the fact "this DACL is admin-only". M2-105 decides. |
| SDDL text from `icacls /save` or `(Get-Acl).Sddl`, parsed in Rust | Tool output parsed for a trust decision, with inheritance flags and aliases to get right. A parse slip trusts a bad store. M2-105 can compare real SIDs. |
| The `exacl` crate for macOS ACLs | A new dependency in the trust path needs its own review, and it does not cover Windows DACLs. Routed to M2-105. |
| Read the store without ACL checks | A store a non-admin planted would be trusted by an elevated run (threat model S2). |

## Tickets implied

- [M2] M2-105 rdy-winacl FFI crate: admin-only ProgramData store and elevation detection for the trust path | owner: rust-engineer | est: 8h | depends on: M1-122 | exit test: on Windows CI a ProgramData\rdy directory created by a non-admin user, or with a Users write ACE, exits 64 with trust_store_insecure, and an Administrators-owned store with a protected DACL is read.
