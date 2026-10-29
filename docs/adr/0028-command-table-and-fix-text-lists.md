# ADR 0028: The command table is typed data in `rdy-engine`, and fix text is audited against two reviewed lists

- Status: Accepted
- Date: 2026-10-29

## Context

03 Appendix A lists every external command a check may run, with a path, a timeout and the exit codes
that matter. 03 also says that every command and sysctl name in fix text is checked against an
allow-list file in CI. M1-039 built the command policy (search path, refusals, environment), which says
what can never run. Nothing yet said what may run, and nothing read fix text.

Two facts shape the design. The policy resolves a program by name from `/usr/sbin:/usr/bin:/sbin:/bin`
and starts it from its real path, because the same tool is in `/usr/bin` or `/bin` depending on the
distribution. And the check crates that need the list (host, net, gpu) must not depend on each other.

## Decision

1. The table is a `static` of typed entries in `rdy_engine::exec::table`. An entry holds the program
   name, the absolute path 03 gives, the operating systems, the check ids, declared extra directories
   (GPU tools only) and a list of forms. A form is one argv shape (`Lit`, `Param`, or a literal prefix
   joined to a `Param`) with its own timeout, stdout cap and exit-code meanings. There is one entry per
   program; the Windows and Linux `nvidia-smi` are two entries.
2. The path is the documented location, not a second resolution rule. The policy still resolves by
   name. A test keeps the path in a search directory or a declared directory under the program's own
   name. Pinning the runtime to the exact path would block healthy hosts whose tool lives in `/bin`.
3. Spec-derived values pass a validator before they reach argv. A host name is `A-Za-z0-9._-` up to 253
   bytes, a zone is `A-Za-z0-9_-` up to 64 bytes starting with a letter or digit, and neither may start
   with `-`. Validators never echo the value.
4. `table::validate` checks any `Cmd` against the table: entry, OS, form, time limit, stdout cap,
   declared directories and declared environment names (none are allowed; 03 gives every command the
   base environment only). `table::run` validates, then calls `policy::run`. `policy::run` itself does
   not require an entry, so policy tests can run `true`. The probe (M1-040) must call `table::run`.
5. Programs that run another program or take code in their arguments never get an entry, and the
   policy refuses them by name as well: `time`, `setarch`, `linux32`, `linux64`, `chpst`,
   `start-stop-daemon`, `run-parts`, `awk` and its relatives, `node`, `expect`, `osascript`, and any
   name starting with `python`, `perl`, `ruby`, `lua`, `php`, `tclsh` or `nodejs`. A table test walks
   every entry against `is_refused_name`.
6. Fix text is audited by `rdy_engine::fixtext` against `commands.txt`, `sysctls.txt` and
   `literals.txt`. Only backtick spans are read. The rules are in the module docs. A span of one unknown
   word is a term, not a command; a bare typo with no arguments can pass, a typo with arguments cannot.
   `literals.txt` lists whole spans that are quoted messages or config lines. The fix-command list is
   not the table: it is what a customer is told to run.
7. `crates/rdy-engine/tests/command_table.rs` parses 03 Appendix A and holds it equal to the table
   (program, arguments, OS letters, timeout, path), and runs the audit over every fix bullet of 03.
   Drift in either direction fails the build. It lives in `tests/` because the catalog is in the
   workspace and not in the published crate.

## Consequences

- The Windows rows are typed now, and the policy still runs only `whoami.exe` there until M2-006.
- `containerd` is listed at `/usr/bin/containerd` as in 03. Tarball installs put it in
  `/usr/local/bin`, which is not searched. M1-150 decides whether to declare that directory.
- The audit is a heuristic and says so. Its failure mode is a false positive that a reviewer clears by
  editing a list, never a silent pass for a multi-word typo.
- Rejected: matching only the exact absolute path at run time (breaks merged-`/usr` and `/bin`
  layouts); a regex per parameter (a hand-written validator is shorter to review); one allow-list for
  both the table and fix text (`rdy` never runs `lvextend`, and a customer is never told to run
  `getent`).
