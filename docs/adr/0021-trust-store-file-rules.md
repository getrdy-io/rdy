# ADR 0021: Trust store file rules where the design is silent are the strict ones

- Status: Accepted (2026-10-28, M1-121). Fills gaps in ADR 0002 decision 4 and 01 section 4.3. Decision 5 and the last consequence are settled by ADR 0027: Windows stays refused in M1.
- Date: 2026-10-28

## Context

ADR 0002 decision 4 and 01 section 4.3 give the refusal rules for the system store on Unix. They say less
about the user store, about Windows before the ACL ticket (M1-122), and about which error code a store that
is unreadable or not valid gets. M1-121 has to pick. Each choice below is the one that refuses more.

## Decision

1. **The user store is refused if it is a symlink**, like the system store. The design names only the mode
   for the user file. A symlink can point at a file that another account controls, and the open handle
   check is what makes the owner and mode checks mean anything. Cost: a dotfile manager that links the file
   must copy it instead.
2. **The user store must be owned by the current user or by root.** A file that another user owns can be
   changed by that user even when it is not group or world writable.
   **The folder of the user store (`~/.config/rdy`) gets the same checks as the folder of the system
   store.** It is opened with `O_NOFOLLOW` and must not be a symlink, must be owned by the current user or
   by root, and must not be group or world writable. A user store in a folder that others can write could
   be swapped for another file, whatever the mode of the file says. The folders above it are not checked,
   so a dotfile manager may link `~/.config`. The same holds for `/etc` and `/` above `/etc/rdy`.
3. **The system store is checked through its folder.** The folder is opened with `O_NOFOLLOW`, checked
   (owner root, not group or world writable), and the file is opened inside it with `openat`. Nothing is
   decided from a path after the open.
4. **A trust file is read whole or not at all.** One bad entry (a weak key, a duplicate key id for a
   product, an unknown key, a control character in a note) makes the file an error. `apiVersion`,
   `kind`, `keys` and each entry's `added_at` are required. A note is at most 512 characters. A relative or
   empty `HOME` or `XDG_CONFIG_HOME` gives no user store.
5. **Windows and other non-Unix systems refuse what they cannot check.** Until M2-105 (ADR 0027) adds the
   ACL rules, any trust file that exists there is refused with `trust_store_insecure`, a missing file is an
   empty store, and saving is reported as not supported. `--key` runs read no store and are not affected.
   The fix line for this refusal tells the user to ask an administrator to remove the file (ADR 0027). It
   differs from the one in 01 section 4.8 (run `rdy trust add` from an elevated prompt), because that
   command cannot work until M2-105.
6. **Error codes.** A store that can be changed by the wrong people, that rdy cannot check, that is not
   a regular file (a folder, a pipe or a device), or whose folder is not a folder, is
   `trust_store_insecure`. A store that cannot be read, is not valid, or cannot be written is `usage`
   (exit 64, the input has to change). No new code is added to ADR 0008's closed list. If the reviewers want
   a separate code for an invalid store, that is an additive change under ADR 0007.
7. **One-run keys are never saved.** A pin made with `TrustStore::pin` has no `added_at`, and
   `to_yaml` writes only pins that have one.

## Consequences

- A user who links their store, or whose store or its folder is owned by another account, may see a
  refusal that 01 section 4.3 does not list. The fix line says what to do. A root-owned user store is
  accepted, and root writes only the system store.
- On Windows, until M2-105 (ADR 0027), any account that can create `C:\ProgramData\rdy\trust.yaml` can make every
  run that reads the system store exit 64. This blocks verification and does not make a planted store
  trusted. M2-105 replaces it with the ACL checks (ADR 0027).
- Extended ACLs on macOS are not in the mode bits, so a file with a write ACL for another account passes
  the mode check. This is a residual risk (threat model 05, Surface 2). M1-122 decided not to read them:
  it needs FFI, and `#![forbid(unsafe_code)]` holds in `rdy-cli`. The system store folder `/etc/rdy` is
  made by root, which limits who can plant an ACL there.
- ADR 0027 keeps decision 5 for M1 and removes the Windows user store. The ACL checks of 01 section 4.3 wait for M2-105.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Follow a symlink for the user store | Weakens the one check that the handle checks depend on, for a convenience the design does not ask for. |
| Check only the mode of the user file, as written | A file owned by another account passes and that account can change it. |
| Read a Windows store without ACL checks | A store that a non-admin user pre-created would be trusted by an elevated run (threat model S2). |
| A new `trust_store_invalid` code | Wider than the ticket. Possible later as an additive change. |
