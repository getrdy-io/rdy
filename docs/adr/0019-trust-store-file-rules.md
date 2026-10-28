# ADR 0019: Trust store file rules where the design is silent are the strict ones

- Status: Accepted (2026-10-28, M1-121). Fills gaps in ADR 0002 decision 4 and 01 section 4.3.
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
3. **The system store is checked through its folder.** The folder is opened with `O_NOFOLLOW`, checked
   (owner root, not group or world writable), and the file is opened inside it with `openat`. Nothing is
   decided from a path after the open.
4. **A trust file is read whole or not at all.** One bad entry (a weak key, a duplicate key id for a
   product, an unknown key, a control character in a note) makes the file an error. `apiVersion`,
   `kind`, `keys` and each entry's `added_at` are required. A note is at most 512 characters. A relative or
   empty `HOME` or `XDG_CONFIG_HOME` gives no user store.
5. **Windows and other non-Unix systems refuse what they cannot check.** Until M1-122 adds the ACL rules,
   any trust file that exists there is refused with `trust_store_insecure`, a missing file is an empty
   store, and saving is reported as not supported. `--key` runs read no store and are not affected.
6. **Error codes.** A store that can be changed by the wrong people, or that rdy cannot check, is
   `trust_store_insecure`. A store that cannot be read, is not valid, or cannot be written is `usage`
   (exit 64, the input has to change). No new code is added to ADR 0008's closed list. If the reviewers want
   a separate code for an invalid store, that is an additive change under ADR 0007.
7. **One-run keys are never saved.** A pin made with `TrustStore::pin` has no `added_at`, and
   `to_yaml` writes only pins that have one.

## Consequences

- A user who links their store, or who runs `sudo -E` and leaves a root-owned file in their home, may see a
  refusal that 01 section 4.3 does not list. The fix line says what to do.
- M1-122 replaces decision 5 for Windows with the ACL checks of 01 section 4.3.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Follow a symlink for the user store | Weakens the one check that the handle checks depend on, for a convenience the design does not ask for. |
| Check only the mode of the user file, as written | A file owned by another account passes and that account can change it. |
| Read a Windows store without ACL checks | A store that a non-admin user pre-created would be trusted by an elevated run (threat model S2). |
| A new `trust_store_invalid` code | Wider than the ticket. Possible later as an additive change. |
