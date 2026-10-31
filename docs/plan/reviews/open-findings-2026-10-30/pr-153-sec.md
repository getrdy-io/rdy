# PR #153 (M1-169) security review, head 89f9bb0

Verdict: approve with fixes. Fix SEC-153-1 and SEC-153-3 before merge. ADR 0040 then becomes "security-reviewed (PR #153)".

Sound against a spec and against hostile files in rdy's own mount namespace. These all fail closed: thread-self,
task/<tid>/fd, a non-root proc, a symlink to /proc/<pid>/fd (admit_link judges the real path),
read/stat/Statvfs of fd paths, other pids' ns links, and a target that is not socket:[1-20 digits]. A refused
target is not in the error, the log or the JSON.

## SEC-153-1 (medium): the real-path rule and the socket-only rule can be bypassed through another mount namespace
files.rs:224-243. real_parent is d_path of the anchor, so another mount namespace's paths come back
unchecked. Checked on this host: a link through /proc/<pid>/root to an rbind of /proc reads back as
"/mnt/p/1/fd". It has no `proc` component, so the allowlist and admit_link never fire, and pid 1's fd
targets come back raw. An unprivileged user can do this where unprivileged user namespaces are allowed. A root
procfs bind under another name does the same. host.ports cannot be steered this way, so medium. ADR 0040 decision 5 is false as written.
Fix: after the readlink, (a) `statat(CWD, real_parent, SYMLINK_NOFOLLOW)` and compare (dev, ino) with
`fstat(anchor)`, else RULE_CHANGED; (b) if `fstatfs(anchor).f_type == PROC_SUPER_MAGIC`, require the first
component to be `proc`, else RULE_PROC. Add a unit test for each.

## SEC-153-2 (medium, pre-existing, own ticket; must fix before M2 custom.file)
`locate` (files.rs:499-516) has the same flaw, and it reaches content (`<rendered>/1/environ`). Same fix.
Add it as a residual in 05 I5 now.

## SEC-153-3 (low): FD_WALK still works as a prefix
policy.rs:369-373 and fixture_run.rs:228. `is_pid("<pid>")` is false, so `read("/proc/<pid>/fd/x")` is
admitted. Fix: skip FD_WALK in both prefix loops. Test that `content(WALK)` refuses that path with RULE_OUTSIDE_READS.

## SEC-153-4 (low, pre-existing pattern): "own" is std::process::id()
policy.rs:309-313 and 657-663. Under a foreign pid namespace's /proc (nsenter -m), another process's ns/net
and auxv pass as rdy's own. Fix: read /proc/self once when Live is built, and refuse ns/net and auxv when it differs from process::id().

## SEC-153-5 (nit): non-Linux, non-Apple Unix
files.rs:250-283. O_NOFOLLOW covers only the last component, and nothing re-checks. Not a release target.
Fix: compare (dev, ino) with a stat taken before the open, or return Unsupported there.

## SEC-153-6 (nit): docs
- ADR 0040 decision 5: say that the target is read into memory and dropped. "denied" means not kept.
- 03 still says cmdline first (ADR 0036): change it to comm.
- 12-progress "PR #TBD": change it to #153.

Exit test: proven for rdy's own procfs: the live walk over its own fds, a link to the fd directory, and replay.
Windows gives Denied, not NotFound (noted, accepted). Fully proven once SEC-153-1 lands.

## Confirm (fix round 1, 90f918b; main-merge content ignored)

Verdict: approve. Security sign-off given. ADR 0040 "Accepted, security-reviewed (PR #153)" stands.

- SEC-153-1: fixed for procfs. files.rs:265-272 `confirm_real_parent`. A procfs not seen at `/proc` is refused (RULE_PROC). A parent name that leads nowhere or to another inode is refused (RULE_CHANGED). Unit tests cover both. The fd socket-only rule and the /proc allowlist now hold across mount namespaces. One gap remains in the inode check: SEC-153-7 below.
- SEC-153-2: the residual is in 05 I5 and owned by its own ticket. That ticket must use the stronger check from SEC-153-7.
- SEC-153-3: fixed. FD_WALK is skipped in policy.rs `decide` and in fixture_run `undeclared_file`. Test `the_fd_walk_text_is_no_prefix` covers it.
- SEC-153-4: fixed. `proc_self_is_own` runs once. `guard_for` is applied to every Live file and native call. auxv and ns/net close when `/proc/self` is not rdy's pid or cannot be read. Tested.
- SEC-153-5: fixed. Other Unix returns Unsupported, and `read_link_by_path` is compiled for Linux and Apple only.
- SEC-153-6: fixed. ADR decision 5 says the target is read and then dropped. 03 uses comm. 12-progress links #153.

## SEC-153-7 (low, new; non-blocking, fold into the SEC-153-2 ticket)
files.rs:269. `statat(..., SYMLINK_NOFOLLOW)` does not follow the last name, but it does follow
symlinks in the middle of the path. Shown on this host as root with `unshare -m`:
- Another namespace mounts tmpfs at T and binds `H/.ssh` at `T/a`. The parent's real path reads back as `T/a/b`, with no `.ssh` in it.
- In rdy's namespace, `T/a` is a symlink to `H/.ssh`. So `lstat(T/a/b)` gives the anchor's inode, and the check passes.
- The judged path is `T/a/b/<name>`, so the `.ssh` deny rule never runs.
Procfs is still covered by the `/proc` name check. For read_link, only a link target leaks, so this is low. For `locate` it would leak file content.
Fix: open real_parent with `O_PATH`, read `/proc/self/fd/<n>` back and require it to equal real_parent
byte for byte, and require the same (dev, ino) as the anchor. `openat2` with `RESOLVE_NO_SYMLINKS` is an
alternative where the kernel has it. Test without namespaces: give the check a parent name that runs
through a symlink to the anchor's directory, and expect RULE_CHANGED. Until then, add one sentence on
this to the 05 I5 residual.
