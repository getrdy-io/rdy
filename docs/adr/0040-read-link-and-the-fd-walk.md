# ADR 0040: The facade reads links with `read_link`, judges the link where it sits, and opens `/proc/<pid>/fd` to a declared walk that returns sockets only

- Status: Accepted, security-reviewed (PR #153)
- Date: 2026-10-30

## Context

`host.ports` (M1-072) needs two facts that only a link read gives. It reports the network namespace
(`/proc/self/ns/net`, which reads as `net:[4026531840]`) so a container view can be named. And it finds
which process holds a port by matching the socket inode in `/proc/net/tcp` to a link in
`/proc/<pid>/fd` (`socket:[8841]`). The read policy refused both: `ns` and `fd` are not on the
`/proc/<pid>/` allowlist, and the facade had no call that reads a link without opening its target (PR #88
review, correction 14).

An fd link is also the most sensitive link on the machine. Each one leads to whatever the process holds
open: a file, a pipe, a key. A path such as `/home/ada/.ssh/id_ed25519` in a result would be a leak on its
own. And opening an fd path follows the link to its target.

Two choices were open: how a check declares the walk, and what a link read may return.

## Decision

1. **`Probe::read_link` is a facade call with its own action-log kind, `read_link`.** It returns the raw
   target as `FileBytes` (text goes into a finding only through `Probe::file_text`, as for a file). The
   entry holds `path`, the link itself, and never the target. No new field: only a new `kind` value, which
   is additive because `ActionKind` is open (result schema revision, `crates/rdy-spec/schema/README.md`).
   The kind folds, drops and coalesces like `read`, `read_dir` and `stat`.
2. **A link is judged where it sits.** The path as written and its real path (the real parent plus the
   link's own name, the link not followed) must be off the denylist and under one of the check's `reads`.
   Where the link points is not judged, because nothing is opened. Linux holds the parent through an
   `O_PATH` descriptor and calls `readlinkat` on it, so the judged directory and the read directory are one
   inode. Linux also checks that the real path of the parent leads to that inode here (a `lstat` of the
   name), and that a procfs is seen as `/proc`: a directory that came from another mount namespace, or a
   procfs mounted under another name, is refused, because the rules match on the name `proc` (security
   review SEC-153-1). macOS resolves the parent with `realpath` and opens it without following links.
   Another Unix answers `Unsupported`: it has no way to hold the parent.
3. **The fd walk is declared by one `reads` entry, `rdy_engine::check::FD_WALK` (`/proc/<pid>/fd`).** A
   typed `CheckInfo` field would force every check and every test double in the workspace and in the open
   PRs to change. The text is not a real path (`<pid>` is no process id), so as a prefix it matches nothing
   and grants nothing; the guard looks for it by name. `host.ports` is the only check that declares it.
4. **What the declaration opens.** `read_dir` of `/proc/<pid>/fd` and `read_link` of `/proc/<pid>/fd/<n>`,
   for a number or `self`, with `proc` at the root. Nothing else: `read`, `stat` and `Statvfs` of any fd
   path stay refused, so the file behind a link is out of reach. `thread-self`, `task/<tid>/fd` and a
   `proc` that is not the first component stay refused.
5. **Only sockets come back.** After the read, a link whose real path is `/proc/<pid>/fd/<n>` must lead to
   `socket:[digits]`. Any other target (a path, a pipe, an anonymous inode) is refused with a fixed rule,
   and neither the error nor the log holds it. The target is read into memory first and then dropped, so
   "refused" means not kept, not never read. The rule is applied on the real path, so a link to an fd
   directory cannot hide it. The check treats a refused fd as "not a socket" and goes on.
6. **`/proc/self/ns/net` is open to `read_link` for rdy's own process only,** when the check's `reads` cover
   it. Another process's namespace and every other namespace stay refused. "Own" is the process id of
   rdy, and the live backend reads `/proc/self` once when it is built: if that is not the same number
   (the procfs of another pid namespace), the own-process grants for `ns/net` and `auxv` stay closed.
   Where there is no `/proc` the call is `NotFound`. A Windows check reads no links, as it reads no files in M1: the policy refuses it
   with the Windows rule.
7. **Replay serves the manifest `symlinks` map** through the same policy. The fixture form needs no new key:
   `root.manifest.json` already lists links, and a link whose target is not a path is a socket or pipe
   name. A `read_link` on a fixture applies the real-path judgment and the socket-only rule as the live
   backend does. The case is `tests/fixtures/checks/_policy/fd-walk`.

## Consequences

- `host.ports` declares `FD_WALK` and the namespace link in `reads`, and reads `/proc/<pid>/comm` and
  `/proc/<pid>/cgroup` as before. The process name comes from `comm`, not `cmdline`, which the
  allowlist refuses (ADR 0036; the catalog says so).
- A walk over many processes makes many `denied` link entries (every file and pipe fd). They fold per
  directory like any denied file call, so one process costs one directory key. M1-072 stops at the
  first match. A walk over hundreds of processes would still fill the quota of a check, so the log folds
  the refusals of non-socket fd links (`RULE_FD_TARGET`, now public in `rdy_engine::probe`) under one key
  per check (21 entries), not one per directory.
- The declaration is skipped as a prefix, so it never covers a read of the literal text
  `/proc/<pid>/fd/x` (SEC-153-3). The fixture run's manifest audit counts an fd link or listing as
  declared only under `FD_WALK`, with the path shape tied to the call (three names for a listing, four for
  a link), and `cargo xtask checks` flags any check other than `host.ports` that lists it.
- Windows has no file reads in M1, so `/proc/self/ns/net` is `Denied` there (the Windows file rule), not
  `NotFound`. It is `NotFound` on macOS, which has no `/proc`.
- The result schema gained a `kind` value and the reference page changed. Readers that keep unknown kinds
  are unaffected.
- A future M2 collector that wants the fd directory of another process for a bundle needs its own decision.
