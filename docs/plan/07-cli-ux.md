# 07 CLI UX: commands, output, JSON, exit codes, accessibility and the HTML report

Owner: cli-ux. Date: 2026-10-28. Status: revision 2, after the cold review by code-reviewer
(`docs/plan/reviews/07-cli-ux-review-by-code-reviewer.md`). Draft for review by rust-architect,
rust-engineer, security-reviewer and devrel. Sources: CLAUDE.md, ADRs 0002, 0003, 0008, 0011, 0013, 0016,
00-overview.md, 01-spec-format.md (draft 2), 02-engine-design.md (revision 3), 04-bundle-and-redaction.md,
`result.v1.schema.json` (working tree of 2026-10-28), and the reviews in `docs/plan/reviews/`. Where this file
and 10-devrel-and-launch.md differ, this file wins; the lines 10 must change are under "Plan corrections found".

Every message a user sees comes from here. The samples are golden files: the renderer tickets must reproduce
them byte for byte. They use `.example` names and synthetic keys. Terminal samples are stderr unless marked.
Long material is in the appendices: A help text, B the three JSON reports, C other samples, D HTML tokens,
tests, Unicode, Windows and new crates, E the M2 and M3 outlines.

Founder decision of 2026-10-28: M1 is extended, not cut. Every M1 ticket stays. Each carries `core: yes` or
`core: no`; the `yes` tickets are the six-week minimum if the founder wants to trim (see "Tickets implied").

## Decisions in one screen

1. **Streams.** Talk goes to stderr: progress, results, prompts, errors. Data goes to stdout: `--json`,
   `rdy version`, `rdy trust list`.
2. **Order of a run.** Checks are listed by `bucket` (01 section 5.2), each problem with its fix on the line
   below. Then the summary line, the report folder and the verdict.
3. **Last line.** `READY`, `READY with warnings`, `NOT READY`, `NOT READY: N required checks were not run` or
   `READY with warnings: nothing was checked`. Nothing prints after it, except an exit-70 error.
4. **Ctrl-C.** Settled. M1: stops the run, no report, exit 70. From M2: the first writes a partial report;
   the second exits 70 at once. The hard stop is 70, not 130.
5. **Names.** `--no-network`, `--out-dir`, `--dry-run` (not `--plan`), `--kube-context`.
6. **clap's own errors exit 64, not 2.** In rdy, 2 means NOT READY.
7. **No colour-only meaning, no Unicode except the spinner.** Every status is a word. Static text is ASCII.
8. **No hint, fix or suggestion names `--allow-unsigned` or `run --key`** (01 section 4.7), including the
   did-you-mean for a mistyped flag. Secrets never go on argv.
9. **The watchdog never touches stdout.** If a run hangs, `--json` stdout may be empty. The partial Report is
   in the report folder (5.2).
10. **The HTML report** puts the banner, the verdict and the blocks first, reads in DOM order, prints with
    every section open, follows the system colour scheme, and links to getrdy.io with the product name only.

## 1. Commands and flags

Commands are verbs. `trust` is the one noun group, and `completion` (M3) the one other noun, kept because
every shell tool uses it.

| Command | M | What it does | stdout |
| --- | --- | --- | --- |
| `rdy run <spec>` | M1 | Verify the spec, run the checks, write the reports, print the verdict | `--json`: Report |
| `rdy verify <spec>` | M1 | Check the signature only. Never prompts | `--json`: Verification |
| `rdy spec lint <spec>` | M1 | Check the spec file, with line and column | `--json`: LintReport |
| `rdy spec sign <spec>` | M1 | Lint, then write `<spec>.minisig` | none |
| `rdy spec keygen <name>` | M1 | Make a signing key pair | none |
| `rdy trust add <product>` | M1 | Pin a vendor key for one product. Asks, or `--yes` | none |
| `rdy trust list` / `remove <product>` | M1 | Show or remove pinned keys | list (M2: `--json`) |
| `rdy version` | M1 | Version, commit, date | the line, or JSON |
| `rdy bundle <spec>` | M2 | Build a redacted diagnostics bundle | `--json`: summary |
| `rdy upload <file>` | M2 | Send a report or bundle after showing what leaves | `--json`: receipt |
| `rdy report <result.json>` | M2 | Re-render the HTML from a result file | none |
| `rdy redact [file]` | M2 | Print a file through the redactor | the text |
| `rdy spec init <name>` | M3 | Start a spec from a template | none |
| `rdy self-update` | M3 | Verify and install a newer rdy. Asks first | none |
| `rdy completion <shell>` | M3 | Print a completion script | the script |

`rdy verify` stays top level because the plan names it; `rdy spec --help` ends with "See also: rdy verify".
`rdy`, `rdy spec` and `rdy trust` with no subcommand print help on stdout and exit 0. A missing required
argument is a usage error: exit 64.
On Windows `rdy trust add` exits 64 and is not supported in M1 (ADR 0027).

**Global flags** (every command, before or after the subcommand): `--color <auto|always|never>`,
`--progress <auto|never>` (env `RDY_PROGRESS`), `-q/--quiet` (conflicts with `-v`), `-v/--verbose`, `-h`
(compact help), `--help` (full help with examples), `-V/--version` (top level only). All M1.

**`rdy run <spec>` flags**

| Flag | M | Meaning |
| --- | --- | --- |
| `--allow-unsigned` | M1 | Run a spec with no signature. Argv only. A bad signature is still refused |
| `--key <key>` | M1 | Trust this public key (file or text) for this run only. Argv only. Prints the KEY NOT PINNED banner |
| `--sig <file>` | M1 | Signature file. Default `<spec>.minisig` |
| `--json` | M1 | Write the Report to stdout |
| `--out-dir <dir>` | M1 | Parent folder for the report folder. Default `.` on Unix, `%USERPROFILE%\rdy-reports` on Windows |
| `--no-report` | M1 | Write no files |
| `--kubeconfig <file>`, `--kube-context <name>` | M1 | Kubernetes access. Help warns that a kubeconfig from someone else can run programs |
| `--no-network` | M1 | Open no sockets. Network and Kubernetes checks are skipped as `missing_need`. With a kube flag, the `cluster` header line says the flag is ignored; it is not a usage error |
| `--jobs <n>` | M1 | Checks at once. Default 8. Above 32 is capped with a note. 0 is a usage error |
| `--timeout <time>` | M2 | See below |
| `--dry-run` | M2 | Print what each check would read, contact and need. Runs nothing. One ticket with SEC-40 |
| `--token-file <file>`, `--server <url>`, `--upload`, `--yes` | M2 | Share-link token, portal origin, offer the upload after the run, answer yes to it |
| `--allow-exec <hash>` | M4 | Allow the exact `custom.exec` commands that hash to this value |

**`--timeout` (M2, with a guard).** The spec's `timeout` wins over a check's default (01 section 2.3), so the
customer must not raise a limit the vendor wrote. `--timeout` may lower any limit and raise only limits the spec
did not set. It uses the 01 Duration grammar (`20s`; a bare `20` is a usage error). The header prints `limits
20 s per check (set by --timeout)`, the HTML details show it, and `run.options.timeout_ms` records it. Nothing
in M1 needs it.

**Flag rules.** Long flags are lowercase words with hyphens; short flags only `-h -V -q -v`. Flags that grant
trust or consent (`--allow-unsigned`, `--key`, `--allow-exec`, `--yes`) are read from argv only (INV-05).
`--json` never changes a verdict or exit code. `--password` (M1) is not a clap flag. A scan of the raw command
line, before clap parses anything, refuses it on `spec sign` and `spec keygen` with exit 64 and the reason
(section 10). `--token` and `--secret` (M2) get the same treatment on the commands that read them.

**Usage errors.** clap exits 2 on its own errors. rdy parses with `try_parse_from` and maps by kind:
`DisplayHelp`, `DisplayVersion` and `DisplayHelpOnMissingArgumentOrSubcommand` (bare `rdy`, `rdy spec`,
`rdy trust`) print on stdout and exit 0; every other kind prints the two-line form and exits 64.
`clap::Parser::parse`, `clap::Command::get_matches` and `clap::Error::exit` are clippy `disallowed-methods`, so
no call can exit 2. When parsing fails, rdy cannot read `--json`, so it scans raw argv for a literal `--json`
before any `--`. Three more rules:

- **No echo.** A usage error prints the flag name, never the text after `=` or the next argument, unless the
  flag is known and not secret (`--jobs abc` may print `abc`). A typo such as `--tokne=rdy_st_...` or
  `--pasword hunter2` leaks nothing. A typed flag name can be a secret too (`--hunter2`, `--<api key>`), so rdy
  prints an unknown name only when it is a typo of a flag rdy has (the same distance rule as below, over every
  flag of every command, hidden ones included, plus `token`, `secret`, `yes` and `password`). Any other
  unknown name gets `unknown option or argument`.
- **rdy suggests, clap does not.** clap's suggester is off (it uses Jaro similarity). rdy offers a did-you-mean
  at most two edits away (a swap of two neighbouring letters counts as one, and the limit is one third of the
  typed length, at least one) over the visible flags of that command. rdy does its own count, so there is no
  `strsim` dependency.
- **Never `--key` or `--allow-unsigned`.** The suggester never proposes either, a hidden flag, or a flag of
  another command. For those near-misses the fix is `see 'rdy run --help'`. So `--yes` (an M2 flag) typed on
  `run` in M1 cannot teach `--key` (C.6).

## 2. What a run prints

### 2.1 Layout

Blocks in this order, one blank line between them: (1) the banner, if any; (2) the header: `rdy <version>` and
labelled lines; (3) the check list; (4) a `Tip:` when two or more checks were skipped for lack of root; (5) the
summary line; (6) in M2, `Interrupted. This report is partial.`; (7) `Report written to <folder>/` with the
files indented under it (not with `--no-report`); (8) the banner's first line again; (9) the verdict line.

| Header label | Content |
| --- | --- |
| `spec` | `<product> <version>   (<file as typed>)`, with `, revision N` when the spec has a `serial` |
| `sig` | `verified, key <id>, <trust>, signed <date>` with `<trust>` one of `trusted by you`, `trusted on this machine`, `key given with --key, not pinned`; or `UNSIGNED (allowed by --allow-unsigned)` |
| `host`, `user`, `proxy` | `<hostname>   <os> <version>   <arch>`; `<login> (root)` or `(not root)`; the proxy in effect with user info stripped, left out when none |
| `cluster` | `<context>, <server>, user <kubeconfig user>`, plus `, credential plugin: <name>` and `, TLS verification is OFF` when they apply. The user is the entry name in the kubeconfig. The identity the API server sees comes later (ADR 0031). Printed before the first request, so the user sees which cluster rdy is about to touch. `no kubeconfig found` when none, with the hint `Pass --kubeconfig <file> or set KUBECONFIG.` (on Linux it adds where k3s, RKE2 and kubeadm keep a root-only kubeconfig: copy it to `~/.kube/config` and `chmod 600` it; the JSON sample in appendix C shows the short form). `ignored: --no-network is set` with `--no-network`, plus `(--kube-context <name> was given)` when a kube flag was passed. Left out when the spec has no Kubernetes checks |
| `limits` (M2) | `20 s per check (set by --timeout)`. Left out without `--timeout` |

**The root Tip.** Shown when two or more checks were skipped with `missing_need: root`: `Tip: 2 checks need root:
host.ports, host.lsm. Run rdy as root to include them. rdy never asks for sudo.` As root, rdy reads only
`/etc/rdy/trust.yaml` (ADR 0002 decision 4). So when `trust_source` is `user`, the Tip adds `As root, rdy reads
only /etc/rdy/trust.yaml. First trust the vendor key for root: sudo rdy trust add acme-platform --key <file>`;
without it, following the Tip lands in `spec_key_unknown`. Both forms are goldens (C.16).

### 2.2 The check list

Sorted by `bucket` (`blocker`, `required_not_run`, `warning`, `passed`, `not_applicable`), spec order inside
a bucket. Read the bucket from the result; never recompute it. One entry per check:

```text
<2 spaces><STATUS padded to 7><2 spaces><key padded to the longest key><2 spaces><message>
<spaces up to the message column>fix from <source>: <fix>          (only when the check has a fix)
```

- `STATUS` is `PASS`, `WARN`, `BLOCK`, `SKIP`, `TIMEOUT` or `ERROR`. `key` is the `id`, or `id/name`.
- `message` is the JSON `message`, word for word. A check in the `required_not_run` bucket gets ` (required)`
  after it. A `not_applicable` skip gets no marker and no fix: it does not count.
- `<source>` is `rdy` for `fix_source: rdy`. For `fix_source: spec` it is the product name only when the
  signature is verified and the key is pinned (`trust_source` is `system` or `user`); otherwise it is `the
  spec file (not verified)`, because an unsigned or one-run-key spec can carry any text under any name (01
  section 2.6). The terminal shows the vendor's fix only; the HTML adds rdy's text below it.
- Lines wrap at word boundaries with a hanging indent under the message. Width is the terminal width, or
  `COLUMNS`, or 100, clamped to 60 to 100. `error:` and `fix:` lines in errors never wrap.

### 2.3 Banner for a one-run key

The unsigned banner is 01 section 4.7 and appears in 2.7. A `--key` run prints the KEY NOT PINNED banner of 01
section 4.7 in the same places (before any check, red, first line again above the verdict; C.14). Neither hint
nor error ever names the flags. M2 adds `Run it anyway? [y/N]` after either banner on a TTY.

### 2.4 Summary line and last line

Three parts always print: `N block(s)`, `N warning(s)`, `N passed`. Then, only when above zero and in this
order: `N required check(s) not run`, `N optional check(s) not run`, `N not applicable`. A timeout or error
inside a not-run count adds a suffix: `4 required checks not run (1 timed out)`, `(1 failed)`, or
`(1 timed out, 1 failed)`. Parts are joined with `, `. Singular for one. This is 01 section 5.3.

| `verdict` | `verdict_reason` | Last line | Exit |
| --- | --- | --- | --- |
| `ready` | null | `READY` | 0 |
| `ready_with_warnings` | null | `READY with warnings` | 1 |
| `ready_with_warnings` | `nothing_verified` | `READY with warnings: nothing was checked` (C.13) | 1 |
| `not_ready` | null (a block was seen) | `NOT READY` | 2 |
| `not_ready` | `required_check_not_run` | `NOT READY: 1 required check was not run` or `NOT READY: 3 required checks were not run` (C.12) | 2 |

With a block and unrun required checks together the last line is plain `NOT READY` and the summary line
carries the count. 02 proposed the headline `NOT READY: 1 blocker, 2 required checks not run`; it is rejected
and the last line is this table (Plan corrections).

### 2.5 Sample: READY

A signed spec, normal user, Linux. Exit 0. The sample is C.17.

### 2.6 Sample: READY with warnings

The same spec with a smaller disk: the optional disk check sorts first with its fix, labelled with the product
because the key is pinned. Exit 1. The sample is C.18.

### 2.7 Sample: NOT READY

An unsigned spec with `--allow-unsigned`, no kubeconfig, and a name server that hangs. It shows a block, a
warning, a timed-out required check, required checks that could not run (no cluster, not in this version)
and an optional one. Exit 2. It takes about ten seconds, which is what the progress line is for.

```console
$ rdy run acme-platform.yaml --allow-unsigned
WARNING: UNSIGNED SPEC
acme-platform.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy 0.1.0
spec    acme-platform >=4.2   (acme-platform.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    acme-node-01.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128
cluster no kubeconfig found

  BLOCK    host.memory       15.4 GiB found, 32 GiB needed
                             fix from the spec file (not verified): Add RAM or choose a larger node
                             class.
  TIMEOUT  net.egress        Timed out after 10 s. (required)
                             fix from rdy: Run again. If it times out again, tell the vendor which
                             check it was.
  SKIP     k8s.version       Not run. No Kubernetes cluster was reachable. (required)
                             fix from rdy: Set a kubeconfig, or pass --kube-context <name>, then run
                             again.
  SKIP     gpu.cuda          Not run. This version of rdy has no gpu checks yet. (required)
                             fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                             how to go on.
  SKIP     aws.iam           Not run. This version of rdy has no aws checks yet. (required)
                             fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                             how to go on.
  WARN     host.disk         60.0 GiB free on / for /var/lib, 100 GiB needed
                             fix from the spec file (not verified): Mount a larger volume at
                             /var/lib before install.
  SKIP     k8s.storageclass  Not run. No Kubernetes cluster was reachable.
                             fix from rdy: Set a kubeconfig, or pass --kube-context <name>, then run
                             again.
  PASS     host.cpu          8 vCPUs found, 8 needed

1 block, 1 warning, 1 passed, 4 required checks not run (1 timed out), 1 optional check not run

Report written to ./rdy-report-acme-platform-20270309T143005Z/
  rdy-report-acme-platform-20270309T143005Z.html
  rdy-report-acme-platform-20270309T143005Z.json
  spec.yaml
WARNING: UNSIGNED SPEC
NOT READY
$ echo $?
2
```

Notice: the banner comes first and again above the verdict; fixes read "from the spec file (not verified)"
because without a pinned key the product name proves nothing; `TIMEOUT` counts as a required check not run
and carries rdy's fix; `k8s.storageclass` is `SKIP` with no marker, because its severity is `warn`, so it is
an optional check not run and sorts with the warnings; the passing check is last. The same `acme-platform.yaml`
is signed in C.4. That is a different machine.

### 2.8 Quiet, verbose and dry run

`--quiet` drops the header, PASS and not-applicable lines, the file list and the progress. It keeps the
banner, every problem with its fix, the summary, the folder line and the verdict (C.1). `--verbose` adds
under each entry `expected`, `observed` (scalars as `key=value`, lists as `key=list(N)`, objects as
`key=map(N)`) and `took` lines, a `needs` block under the header, one plain line as each check finishes (on a
pipe too), and an `actions` count (C.2). `--dry-run` (M2) verifies the spec, prints what each check would
read, contact and need, and ends with `Dry run: nothing was run.` It reads only rdy's own process state and
the trust store, opens no socket and creates no folder (C.3).

## 3. Progress display

Progress uses `indicatif`. A run can take ten seconds or more (a check timeout is 10 s by default), and a
silent terminal looks hung. It is never needed to read a result. The core build prints one static line,
`Running 8 checks...`, on a TTY only, and clears it before the check list. The live line below is the full
build.

The live line draws only when stderr is a TTY, `TERM` is not `dumb`, and none of `--quiet`, `--progress never`,
`RDY_PROGRESS=never` and `RUST_LOG` is set. `--verbose` adds plain event lines on any stream.

It draws one line, redrawn at most 10 times a second, no bar, nothing else on screen:

```text
⠋ Probing: kubernetes context acme-staging
⠙ Running checks 3 of 8, 4 s: net.egress, k8s.version
```

The text after the colon lists the checks running now, cut to the width with `...`. Elapsed time shows after
2 seconds. The first frame waits 250 ms, so fast runs never flash. The line is cleared (`finish_and_clear`)
before the check list prints and leaves no trace in scrollback. The spinner is Braille when Unicode is allowed
(Appendix D.1) and `- \ | /` otherwise. The rules for the code are in the ticket.

## 4. `--json` and the stable-output promise

### 4.1 What goes where

With `--json`, stdout holds one JSON document and a final newline: UTF-8, no BOM, LF. The bytes equal the
`.json` file in the report folder (ADR 0003), including the `\u003c`, `\u003e`, `\u0026` escapes (01 section
5.5), and are the same with `--no-report`. Anything else on stdout is a bug, except on the watchdog path.

| Outcome | stdout with `--json` |
| --- | --- |
| `run` exits 0, 1 or 2 | The Report (`kind: Report`) |
| exit 64 | An ErrorOutput (`kind: Error`, `verdict: null`, `complete: false`), with `file`, `line`, `column` where known |
| exit 70, a verdict exists, the files could not be written at the end (full disk) | The Report with `complete: false`. The error text is on stderr. There is no `.json` file |
| exit 70, the watchdog fired | Nothing, or a cut-off document. Do not parse it. The Report with `complete: false` is in the report folder, if the folder exists and `--no-report` was not given (5.2) |
| exit 70, no verdict (`internal`, `interrupted`, `report_write` before any check, or from `report` or `bundle`) | An ErrorOutput |
| `verify` accepts the spec / `spec lint` / `version` | Verification / LintReport (`kind: Lint`, exit 0, 1 or 2) / version object (4.3) |

`--json` is read from the raw arguments (ADR 0008 decision 7), so a command line that does not parse, or a command that has no `--json` flag of its own, still answers an error in JSON when `--json` is on the line before any `--`. Help and version still print on stdout and exit 0.

The error text is on stderr in every case as `error:` and `fix:` lines, and equals the JSON `message` and
`fix`. For a spec error with a position, the terminal prefixes the message with `file:line:column:` built
from the three JSON fields; the JSON `message` does not repeat them. The error codes are 01 section 4.8 and
ADR 0008 decision 7. This file adds `spec_unreadable` (exit 64: the spec file is missing, not a regular file or
unreadable) and `interrupted` (exit 70). Samples of each object are in B and C.11.

**Start-up warning (M1-168).** If the parent left file descriptors above 2 open, `rdy` prints one line on
stderr before the redacted log layer starts, with `--json` too, and never on stdout: `warning: rdy inherited open file
descriptor 7, and the commands it runs inherit them. To start without, close them in the shell: rdy ... 7>&-`.
It names at most 8 numbers and counts the rest. It goes through the same redaction and escaping as every
other stderr line. Windows prints nothing. The code is `crates/rdy-cli/src/startup.rs`.

### 4.2 The promise

1. **Within `rdy/v1` the JSON only grows.** No field is removed, renamed, retyped or given a new meaning. New
   optional fields and new values in enums the schema marks "Open" appear in minor releases. `verdict` and
   `exit_code` are closed.
2. **Scripts may rely on** (01 section 5): `verdict`, `verdict_reason`, `exit_code`, `complete`,
   `interrupted`, `summary.*`, `checks[].key`, `.id`, `.severity`, `.status`, `.bucket`, `.skip_kind`,
   `.duration_ms`, and `error.code`. They must not parse `message`, `fix`, `notes` or `observed` as text.
   `exit_code` is the verdict's code (the schema pins it to 0, 1 or 2). It can differ from the process exit
   when `complete` is false: the process exits 70. **Exit 70 with empty or short stdout means: look in the
   report folder.**
3. **Consumers** ignore unknown fields, accept unknown values in open enums, never recompute the verdict, and
   never rely on key order or whitespace.
4. **Summary arithmetic:** `pass + warn + block + skipped + timeout + error = total`. `not_applicable`,
   `required_not_run` and `optional_not_run` are views inside that sum.
5. **Removing or changing anything needs `rdy/v2`,** an ADR, and 12 months of v1 support (ADR 0007).
6. **Not promised:** the words of human output, help, `--verbose`, `rdy trust list`, the progress line.
   Promised for scripts: the exit codes, the first words of the last line (`READY`, `READY with warnings` or
   `NOT READY`, then optionally `: <reason>`), and the `error:` and `fix:` prefixes.
7. **How we keep it:** every golden result from every release parses in CI forever
   (`tests/fixtures/results/`, 01 section 3.4); B.1 to B.3 are fixtures; the schema drift check runs on every
   PR.

The three Reports in Appendix B are the same runs as C.17, C.18 and 2.7 and validate against the schema. `checks`
stays in spec order; sorting by `bucket` is the reader's job. B.1 is the clean case (a not-applicable skip,
`trust_source: user`). B.2 is a JSON Patch against B.1 (a `warn` with `builtin_fix`). B.3 is unsigned and
carries a timeout, two `missing_need` skips and two `not_in_build` skips. A NOT READY run with no block has
`verdict_reason: "required_check_not_run"`; C.12 is its terminal form.

### 4.3 `rdy version`

```console
$ rdy version
rdy 0.1.0 (4c1e9a2 2027-03-07)
```

`rdy --version` prints the same line. Alpha builds read `rdy 0.1.0-alpha.3 (abc1234 2026-12-01)` (ADR 0011).
`rdy version --json` prints `name`, `version`, `commit`, `date`, `target`, `rdy_spec`, `api_version`
(C.11), and only grows. The result schema has a `Version` definition for it (M1-022).

## 5. Exit codes

| Code | Name | Who returns it | Meaning |
| --- | --- | --- | --- |
| 0 | ready | `run`; every other command on success | Everything the spec asks for passed, or the command did its job |
| 1 | warnings | `run`; `spec lint` | `run`: READY with warnings. `lint`: warnings and no errors |
| 2 | blockers | `run`; `spec lint` | `run`: NOT READY. `lint`: the spec has errors |
| 64 | usage | any command | The input must change: you can fix it |
| 70 | internal | any command | rdy could not deliver its result: the input may be fine |

A gate that accepts 0 and 1 never passes an unchecked environment, because a required check that did not run
is exit 2 (ADR 0008, 0013). `spec sign` and `verify` use only 0, 64 and 70: a spec that lint would reject
makes `sign` print the findings and exit 64. Which cause gives which code:

| Cause | Exit |
| --- | --- |
| A bad flag or value, a missing argument, conflicting flags, a hidden refused flag | 64 |
| A spec that is missing, unreadable, unparsable, invalid, too large or expired | 64 |
| No signature; a signature that does not verify (even with `--allow-unsigned`); a key that is not pinned; an unreadable sidecar; an unsafe trust file | 64 |
| `trust add` without a TTY and without `--yes`, or answered no; `spec sign` on a spec with errors or a key readable by others; M2: a bad token, an upload answered no | 64 |
| The report folder cannot be created, or its name and the next eight (`-2` to `-9`) are taken. Checked right after the spec is verified, before any check (ADR 0016) | 70 |
| Files cannot be written at the end, such as a full disk. The result prints first | 70 |
| A refused privileged launch; a runtime failure; a panic outside a check (inside a check it is an `ERROR` result); M2: an upload that could not reach the server | 70 |
| The watchdog: the run hung 10 s past its 5 minute deadline (5.2). Ctrl-C in M1, and the second Ctrl-C from M2 (5.1) | 70 |

Not exit codes: a missing kubeconfig, a closed port, no root, a check that times out. They are results, and
the verdict rule decides the code.

### 5.1 Ctrl-C

| Event | M1 | From M2 |
| --- | --- | --- |
| First Ctrl-C (or SIGTERM, or Ctrl-Break on Windows) | Abort, kill child process groups, remove the report folder if nothing was written to it, print the two lines below. Exit 70 | Print `Interrupted. Finishing the report. Press Ctrl-C again to quit now.` Stop starting checks, abort running ones, mark them `skipped` with `skip_kind: cancelled`, set `interrupted: true`, write the report and print the normal result with `Interrupted. This report is partial.`. Exit by verdict, usually 2 |
| Second Ctrl-C | Exit 70 at once | Exit 70 at once, no report |

```console
$ rdy run acme-platform.yaml
^C
error: interrupted. No report was written.
fix: run rdy again and let it finish
$ echo $?
70
```

From M2 the second Ctrl-C prints `error: stopped before the report was written. Nothing was saved.` and
`fix: run rdy again, and press Ctrl-C only once to get a partial report`. Why 70 and not 130, the shell
convention: the code set is fixed at five values, a sixth is a new contract for every script, Windows has no
128+n convention, and 70 already means "rdy could not deliver its result". With `--json`, stdout gets an
ErrorOutput with code `interrupted`. The cost: an interactive `for` loop in bash keeps going after Ctrl-C,
because rdy exits normally and does not die by signal. rdy does not re-raise SIGINT, since that gives 130. The
docs exit-codes page says "a loop should stop on 70".

### 5.2 When the watchdog fires

A hung run is rare, and its output is the one case where `--json` stdout is not a document. The watchdog
(02, ADR 0016 decision 6) writes the partial Report with `complete: false` only through the output directory
rdy already holds, so the folder has a `.html` marked INCOMPLETE and a `.json`. It never takes the stdout or
stderr lock, because a hung run may hold them. It writes one fixed two-line buffer to stderr in a single
non-blocking `write`, and exits 70. What the user sees:

```console
$ rdy run acme-platform.yaml --json > result.json
error: the run did not finish, so rdy stopped itself. A partial report may be in the newest rdy-report folder.
fix: run it again and tell the vendor which check was running.
$ echo $?
70
$ wc -c < result.json
0
```

Stdout can be empty, as here, or cut short. It is never promised to be a document. With `--no-report`, or
before the folder exists, there is no partial report at all. A script that sees exit 70 and an empty file
reads the newest `rdy-report-*` folder, or just runs again.

## 6. Colour, symbols and Windows

**Choosing colour.** First match wins, per stream. stdout is data and is never coloured.

| Order | Rule | Result |
| --- | --- | --- |
| 1 | `--color always` or `never` | as asked |
| 2 | `NO_COLOR` set to any non-empty value | never |
| 3 | `CLICOLOR_FORCE` set to anything but `0` | always |
| 4 | `CLICOLOR=0`, or `TERM=dumb` | never |
| 5 | the stream is a terminal | always, else never |

There is no `RDY_NO_COLOR`: `NO_COLOR` is the standard. `NO_COLOR` beats `CLICOLOR_FORCE`, because the safe
error is too little colour. Use `anstream` for stripping and Windows handling.

**Palette.** ANSI 16 only: no 256-colour or truecolour, no backgrounds, no blink, no OSC 8 links, so it works
on light and dark themes. `PASS` green, `WARN` and `SKIP` yellow, `BLOCK` red bold, `TIMEOUT` and `ERROR` red,
banners and `error:` red, verdict lines bold in their colour (D.1 has the full table). Colour never carries
meaning alone, and nothing the user must read is dim. Yellow is weak on some light themes; the word still says
WARN, and `--color never` is the fix. Untrusted strings are escaped first and never styled.

**Symbols.** rdy's own static text is ASCII: check list, headers, banners, errors, prompts, summaries. That
keeps logs, pipes, goldens and old consoles safe. Unicode is used for one thing, the spinner, when the locale
allows. Text from the machine or the spec may hold any UTF-8; rdy escapes control characters (section 9) and
pads by display width (`unicode-width`). The locale rules and the Windows details are in Appendix D.1.

## 7. Accessibility

Terminal: (1) one linear order, top to bottom, with the verdict last, so `tail -n 1` gives it (except on exit
70, where an `error:` line follows); (2) every status is a word at the same position on every line; (3) no
layout carries meaning: no tables, box drawing, emoji or right-aligned columns, and a label and its value
share a line; (4) the only redraw is the progress line, and `--progress never`, `RDY_PROGRESS=never`,
`TERM=dumb` and `--quiet` remove it so a screen reader does not read spinner frames; (5) contrast follows the
user's theme and nothing important is dim; (6) `error:` and `fix:` start at column 0; (7) prompts are plain
questions ending in `[y/N]`, passwords are read with echo off, and a prompt never appears while progress is
live; (8) short sentences, plain words, English only in M1, with all user text in one module.

HTML: the list is in D.4.

## 8. The HTML report design brief

The contract is 01 section 6 and ADR 0003. rust-engineer builds the page from the `Report` value alone, with
askama, and the output is deterministic. The readers are a customer engineer who needs the verdict in two
seconds, a change board with a printout, an SE who got the file by email, a screen-reader user, and a security
reviewer who wants one file with no network and no script. The design in six rules:

1. **Same order as the terminal.** The banner (UNSIGNED SPEC, KEY NOT PINNED or INCOMPLETE) comes first, as
   01 section 4.7 says ("at the top"); 01 section 6 lists it second, and that list moves (Plan corrections).
   Then the verdict word, the summary line and what to do next. Then the checks by `bucket`: Blocks, Required
   checks not run, Warnings, Passed, Does not apply here. Empty sections are left out.
2. **Words, not colours.** Each check shows a status word, and the border style survives grayscale printing.
3. **No engine words.** Labels follow 01 section 6 (`Found`, `Needed`, `From acme-platform` only when the
   signature is verified and the key pinned, else `From the spec file (not verified)`). A CI grep over the
   template finds no raw JSON key.
4. **Untrusted text stays text.** Every string from the machine or the spec is HTML-escaped and wrapped in
   `<bdi>`, and bidirectional controls show as `\u{202e}`, as in the terminal.
5. **Prints and darkens.** Print is black on white with every section open; dark mode follows
   `prefers-color-scheme`. There is no toggle and no script.
6. **One link out.** The footer link carries the product name and nothing else (D.4).

The page layout, the wording of the header and the look are in D.7. Tokens, print rules and tests are in D.2 to
D.4.

## 9. Error message style guide

An error is two lines at column 0: what happened, then what to do.

```text
error: <what happened, naming the thing>
fix: <one thing to do>
```

Rules:

1. **Name the thing:** the file as typed, the key id, the flag, the check id, the value.
2. **The fix is one action,** in the imperative, with the command to type when there is one. Every exit-64
   and exit-70 path, and every `Skipped`, `Timeout` and `Error` result, has one; a unit test over every
   error variant asserts a non-empty hint (ADR 0008).
3. **Plain words.** No `os error 13`, Rust type names or bare HTTP codes. Say spec, check, folder, key,
   signature file; not manifest, probe, directory. No blame, no "you must", no "please" (one exception: the
   bug line), no exclamation marks. Say what did and did not happen when it matters: "Nothing was sent."
4. **Punctuation.** One sentence: no final period. Two or more: each ends with a period. Lowercase first word
   after the prefix unless it is a name.
5. **JSON matches.** `message` and `fix` in an ErrorOutput are the two lines without prefixes; a position
   goes in `file`, `line`, `column`. Spec errors and not-run checks use the words of 01 sections 2.5 and 5.2.
6. **A bug says so:** `fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues
   and include the output of rdy version.`
7. **Never weaken security in a fix.** No error, fix, hint or did-you-mean ever names `--allow-unsigned` or
   `rdy run --key` (01 section 4.7, threat model T2); both are documented in `--help` and on
   docs.getrdy.io. A hint may name `rdy trust add ... --key`, the pinning command. The flag suggester of
   section 1 skips both flags, so a mistyped `--keey` or `--yes` gets `see 'rdy run --help'`. Exit tests:
   `--keey`, `--yes`, `--allow-unsgned` and `--kye` never put either flag name in stderr or `ErrorOutput.fix`.
8. **No secrets.** Tokens, passwords, key bytes, proxy user info and environment values never appear; every
   string goes through the redactor first (ADR 0008 decision 9). A usage error never echoes the text after
   `=` or the next argument of an unknown flag (section 1). When a secret key's text was passed on argv, the
   refusal adds "It is now in your shell history. Make a new key pair." (C.10).
9. **Untrusted text is escaped:** control characters as `\xNN`, bidirectional controls as `\u{202e}`; never
   styled. The HTML does the same inside `<bdi>`.

Ten before-and-after rows are in C.15.

## 10. Environment variables and secrets

The variables rdy reads are in the table in D.6 (colour and locale, progress, logging, proxy and certificates,
kubeconfig, home folders, key password, and in M2 the share-link token). It reads no others for behaviour. A
test runs the binary with an empty environment and then with each listed variable alone, and checks that the
output changes only as the table says. There is no `RDY_NO_COLOR` or `RDY_COLOR`, and no variable that turns on
`--allow-unsigned`, `--key`, `--allow-exec` or `--yes`.

**Secrets never go on argv.** `/proc/<pid>/cmdline` is world-readable on Linux and shell history keeps what
you type. Signing key password: the prompt, `--password-file`, or `RDY_KEY_PASSWORD`; `--password <value>`
exits 64 with "passwords on the command line show up in shell history and in ps". Share-link token (M2):
`RDY_TOKEN`, `--token-file <file>` (`-` for stdin), or a hidden prompt; `--token <value>` exits 64 the same
way. The signing key is a path, never bytes. Proxy credentials come from `HTTPS_PROXY`; there is no `--proxy`
flag. Public keys may be on argv. Token and password files must not be symlinks or readable by group or
others (Unix). rdy never prints its own argv or environment, and the action log records variable names only.

**Reading a key password (M1-112).** `--password-file <file>` beats `RDY_KEY_PASSWORD`, and either beats the
prompt. `-` is standard input, read from an unbuffered duplicate of the descriptor so no copy stays in the
standard library's buffer. rdy removes one trailing line ending and nothing else, so spaces are part of the
password. It refuses an empty value, a second line, text that is not UTF-8 and more than 1024 bytes. A password
file is opened once, without following a symlink, and every check runs on the open handle: it must be a regular
file. On Unix it must also be owned by the effective user and not readable or writable by group or others, and
the fix is `chmod 600 <file>`. Windows opens the file without following a reparse point and checks the file
type only; it does not check ACLs. The password is held in memory that is wiped on drop. `--password` is
refused before clap parses anything, on `spec sign` and `spec keygen` only, so the refusal beats a
missing-argument error and the value is never read. The code is `crates/rdy-cli/src/password.rs`.

**Secret key files (M1-125).** `spec keygen` writes `<name>.key` and `<name>.pub` with `create_new`, so it
never replaces a file and never follows a link, and the secret key has mode 0600 from the first byte. The public key and the signature are set to mode 0644 after they are created, whatever the umask. It
looks for both names before it asks for a password. The password comes from `--password-file`,
`RDY_KEY_PASSWORD` or two prompts that must match, and an empty one is refused. With `--unencrypted` it asks
for nothing and prints a warning, and `--password-file` is refused together with it. If `RDY_KEY_PASSWORD` is
also set, it prints `note: RDY_KEY_PASSWORD is set and was not used (--unencrypted)`. `spec sign` lints the
spec first and asks for nothing if lint fails. It opens the key once without following a symlink and checks
the open handle (regular file, yours, no group or other access, at most 1 KiB), then asks for the password
only if the key is encrypted, and prints `warning: <key> is not protected by a password` when it is not. A key
file may ask for no more than scrypt N = 2^20 and 1 GiB, with p = 1 (ADR 0022).
Windows checks the file type only and a new file gets its folder's access list, and the success message
says so. The code is `crates/rdy-cli/src/spec_cmds.rs` and `crates/rdy-cli/src/signing/`.

**`RDY_KEY_PASSWORD` is the weakest source.** The same user's processes and root can read it from
`/proc/<pid>/environ`, and every child process inherits it. In CI, store it as a masked secret and prefer a
`--password-file -` pipe when the CI system allows it. When the password comes from the variable and stderr is
a terminal, rdy prints one line: `note: the key password comes from RDY_KEY_PASSWORD, which child processes
inherit and root can read`. It prints nothing when stderr is not a terminal.

## Appendix A: help text for rdy and every M1 command

This is what the M1 build prints. The wording, the order of sections and the examples are fixed here. clap
sets the column alignment, and the snapshot (the plain-file helper of 08) is taken from the first build
whose text matches this. `-h` prints the compact form (the first sentence of each option, no examples).
`--help` prints the full form shown here. Later milestones add their commands and flags to these pages.

M1-029 built these pages. Three layout facts of the clap build change no wording. In `--help`, clap puts each
option's text on the line below the flag. The global options come after the command's own options, and for
`run` before its grouped sections (`Signature`, `Output`, `Scope`). `rdy spec` and `rdy trust` have no `help`
subcommand, only `-h` and `--help`. The snapshots are in `crates/rdy-cli/tests/snapshots/`.

Lines are 80 columns or fewer. `--timeout` (M2) and `--dry-run` (M2) are not in the M1 pages.

**Flags by command** (moved here from section 1). `verify`: `--sig`, `--key`, `--json`, no `--allow-unsigned`.
`spec lint`: `--json`; exit 0 clean, 1 warnings, 2 errors, 64 usage (01 section 2.5). `spec sign`:
`--secret-key <file>` (required; 01 shows it in brackets, but guessing a key location is worse), `--sig <out>`,
`--force`, `--password-file <file>`. `spec keygen <name>`: writes `<name>.key` and `<name>.pub`;
`--unencrypted` (CI only), `--password-file`; never overwrites, so no `--force`. `trust add`: `--key <key>`
(required), `--yes`, `--note <text>`; refuses a secret key. `trust remove`: `--key-id <id>` when a product has
two keys. `spec init` (M3): `--template`, `--force`. `bundle` (M2): the flags of 04 section 7 with `--plan`
renamed `--dry-run`. `upload` (M2): `--token-file`, `--server`, `--yes`, `--json`. `self-update` (M3):
`--check`, `--yes`. `version`: `--json`.

### A.0 Global options

Every command takes these, before or after the subcommand. They are printed once here. A.3 to A.12 leave them
out to save space; the real output and the snapshots put them under `Options:` after the command's own
options. `-V, --version` is on `rdy` only.

```text
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print less
  -v, --verbose          Print more
  -h, --help             Print help (see a summary with '-h')
```

### A.1 `rdy -h`

```text
Check an environment against a vendor's requirements before install day

Usage: rdy [OPTIONS] <COMMAND>

Commands:
  run      Run the checks in a spec and write the reports
  verify   Check a spec's signature without running any checks
  spec     Lint, sign and make keys for spec files
  trust    Choose which vendor keys rdy trusts
  version  Print the version
  help     Print help for a command

Options:
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print less
  -v, --verbose          Print more
  -h, --help             Print help (see more with '--help')
  -V, --version          Print the version
```

### A.2 `rdy --help`

```text
Check an environment against a vendor's requirements before install day.

rdy runs a signed spec of checks on this machine. It prints what is ready,
what is not, and how to fix it. It writes an HTML report and a JSON report.
It works offline. It never asks for sudo. Nothing leaves this machine unless
you send it.

Usage: rdy [OPTIONS] <COMMAND>

Commands:
  run      Run the checks in a spec and write the reports
  verify   Check a spec's signature without running any checks
  spec     Lint, sign and make keys for spec files
  trust    Choose which vendor keys rdy trusts
  version  Print the version
  help     Print help for a command

Options:
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print less
  -v, --verbose          Print more
  -h, --help             Print help (see a summary with '-h')
  -V, --version          Print the version

Examples:
  Run a spec your vendor signed:
    rdy run acme-platform.yaml

  Use rdy as a gate in CI and keep the result:
    rdy run acme-platform.yaml --json > result.json

  Check a signature without running anything:
    rdy verify acme-platform.yaml

  Trust a vendor's key, once, after you check its fingerprint:
    rdy trust add acme-platform --key acme-platform.pub

Exit codes:
  0   READY
  1   READY with warnings
  2   NOT READY
  64  Usage error, or a spec that must change
  70  Internal error, the report could not be written, or the run was stopped

Environment:
  NO_COLOR     Turn colors off (any non-empty value)
  HTTPS_PROXY  Proxy for network checks (also HTTP_PROXY, NO_PROXY)
  KUBECONFIG   Kubeconfig for Kubernetes checks
  RUST_LOG     Log level for diagnostics, for example RUST_LOG=rdy=debug

Learn more: https://docs.getrdy.io
Report a bug: https://github.com/getrdy-io/rdy/issues
```

### A.3 `rdy run --help`

```text
Run the checks in a spec and write the reports

rdy checks this machine against the spec, prints the result, and writes an
HTML report and a JSON report into a new folder. It runs what it can and says
what it could not run. It never asks for sudo and never changes anything.

The spec must be signed by a key you trust (see 'rdy trust add'). rdy refuses
a spec with a signature that does not match, and a spec signed by a key you
have not trusted. To run a spec that has no signature at all, such as an
example file, see --allow-unsigned.

Usage: rdy run [OPTIONS] <SPEC>

Arguments:
  <SPEC>  The spec file, for example acme-platform.yaml. Its signature is
          read from <SPEC>.minisig unless you pass --sig.

Signature:
      --sig <FILE>      Read the signature from this file
      --key <KEY>       Trust this public key for this run only. A key file or
                        the key text. Nothing is saved, and the run prints a
                        KEY NOT PINNED warning. Use 'rdy trust add' to keep a
                        key.
      --allow-unsigned  Run a spec that has no signature. rdy prints an
                        UNSIGNED SPEC warning and marks every report. A
                        signature that does not match is still refused.

Output:
      --json           Print the JSON report on stdout. The text report still
                       goes to stderr.
      --out-dir <DIR>  Folder to create the report folder in
                       [default: . ; on Windows %USERPROFILE%\rdy-reports]
      --no-report      Write no report files

Scope:
      --kubeconfig <FILE>    Kubeconfig to use. Use only one you trust: a
                             kubeconfig can run programs.
      --kube-context <NAME>  Kubernetes context to use
      --no-network           Open no network connections. Network and
                             Kubernetes checks are skipped. A Kubernetes flag
                             is ignored, and the header says so.
      --jobs <N>             Checks to run at once [default: 8, max: 32]

Verdict:
  NOT READY if anything blocks or a required check could not run.
  READY with warnings if only optional things are wrong.
  READY if every check ran and passed.

Examples:
  Run a spec your vendor signed:
    rdy run acme-platform.yaml

  Run an example spec that has no signature (you wrote it, or you trust it):
    rdy run acme-quickstart.yaml --allow-unsigned

  Use the exit code in a script and keep the JSON result:
    rdy run acme-platform.yaml --json > result.json
    echo $?

  Check a cluster with a kubeconfig and context you choose:
    rdy run acme-platform.yaml --kubeconfig ~/.kube/acme --kube-context staging

  Run with no network, for a host-only spec on an air-gapped machine:
    rdy run acme-edge.yaml --no-network

Files:
  rdy creates a new folder, rdy-report-<product>-<time>/, with mode 0700. It
  holds the HTML report, the JSON report, and a copy of the spec and its
  signature. rdy never overwrites a folder.

Exit codes:
  0   READY
  1   READY with warnings
  2   NOT READY
  64  Usage error, or a spec that must change
  70  Internal error, the report could not be written, or the run was stopped
```

### A.4 `rdy verify --help`

```text
Check a spec's signature without running any checks

Reads the spec and its signature and checks the signature against the keys
you trust. Prints who signed it and when. Exit 0 means 'rdy run' would accept
this file with the same --sig and --key. It never asks a question.

Usage: rdy verify [OPTIONS] <SPEC>

Arguments:
  <SPEC>  The spec file, for example acme-platform.yaml

Options:
      --sig <FILE>  Read the signature from this file
                    [default: <SPEC>.minisig]
      --key <KEY>   Check against this public key only, for this command.
                    Prints a KEY NOT PINNED warning.
      --json        Print a JSON result on stdout

Examples:
  Check a spec your vendor sent:
    rdy verify acme-platform.yaml

  Check it in a script:
    rdy verify acme-platform.yaml --json

Exit codes:
  0   Verified
  64  Not verified: no signature, a signature that does not match, or a key
      you have not trusted
  70  Internal error
```

### A.5 `rdy spec --help`

```text
Lint, sign and make keys for spec files

Usage: rdy spec [OPTIONS] <COMMAND>

Commands:
  lint    Check a spec file for mistakes
  sign    Sign a spec with your secret key
  keygen  Make a signing key pair

See also: 'rdy verify <SPEC>' checks a signature.
```

### A.6 `rdy spec lint --help`

```text
Check a spec file for mistakes

Reads the spec and reports every problem with its line and column. Run it
before you sign. It never runs a check and never needs a signature.

Usage: rdy spec lint [OPTIONS] <SPEC>

Arguments:
  <SPEC>  The spec file, for example acme-platform.yaml

Options:
      --json             Print a JSON result on stdout

Examples:
  Check a spec:
    rdy spec lint acme-platform.yaml

  Use it in CI:
    rdy spec lint acme-platform.yaml --json

Exit codes:
  0   No problems
  1   Warnings only
  2   The spec has errors
  64  Usage error, or the file cannot be read
  70  Internal error
```

### A.7 `rdy spec sign --help`

```text
Sign a spec with your secret key

Runs 'rdy spec lint' first and refuses to sign a spec with errors. Then it
signs the exact bytes of the file and writes <SPEC>.minisig next to it. It
checks its own signature and prints the key fingerprint and the line to send
your customers. Stock minisign can verify the signature.

Usage: rdy spec sign [OPTIONS] --secret-key <FILE> <SPEC>

Arguments:
  <SPEC>  The spec file, for example acme-platform.yaml

Options:
      --secret-key <FILE>     Your secret key, made with 'rdy spec keygen'
      --sig <FILE>            Where to write the signature
                              [default: <SPEC>.minisig]
      --force                 Replace the signature file if it exists
      --password-file <FILE>  Read the key password from a file, or '-' for
                              standard input. The prompt is the default.

Environment:
  RDY_KEY_PASSWORD  The key password, for CI. Never put it on the command line.
                    Other processes of your user and root can read it, and
                    child processes inherit it. Use a masked secret in CI.

Examples:
  Sign a spec:
    rdy spec sign acme-platform.yaml --secret-key acme-signing.key

Exit codes:
  0   Signed and verified
  64  Refused: the spec has errors, the key is readable by others, the
      signature file exists, or the password is wrong
  70  Internal error
```

### A.8 `rdy spec keygen --help`

```text
Make a signing key pair

Writes <NAME>.key (secret) and <NAME>.pub (public). The secret key is
password protected and readable only by you. rdy never overwrites a key. Use
a key only for specs. Back it up: anyone who has it can sign specs as you.

Usage: rdy spec keygen [OPTIONS] <NAME>

Arguments:
  <NAME>  Name for the key files, for example acme-signing

Options:
      --unencrypted           Do not protect the secret key with a password.
                              For CI only.
      --password-file <FILE>  Read the new password from a file, or '-' for
                              standard input. The prompt is the default.

Environment:
  RDY_KEY_PASSWORD  The new key password, for CI. Never put it on the command
                    line. Other processes of your user and root can read it,
                    and child processes inherit it. Use a masked secret in CI.

Examples:
  Make a key pair:
    rdy spec keygen acme-signing

Exit codes:
  0   Key pair written
  64  A key file already exists, or the passwords did not match
  70  Internal error
```

### A.9 `rdy trust --help`

```text
Choose which vendor keys rdy trusts

rdy runs a spec only if a key you trust for that product signed it. Trust is
per product: a key trusted for acme-platform means nothing for another
product. Ask the vendor for the key by another route than the spec, and check
its fingerprint before you say yes.

Usage: rdy trust [OPTIONS] <COMMAND>

Commands:
  add     Trust a vendor key for one product
  list    Show the keys you trust
  remove  Stop trusting a key

Where keys are kept:
  As a normal user: ~/.config/rdy/trust.yaml, then /etc/rdy/trust.yaml.
  As root: only /etc/rdy/trust.yaml. Run 'sudo rdy trust add' to trust a
  key for root runs.
```

### A.10 `rdy trust add --help`

```text
Trust a vendor key for one product

Shows the key id and the fingerprint (SHA-256 of the public key) and asks
you to compare the fingerprint with the one the vendor published. Answer y
only if they match. rdy saves the key only after you say yes.

Usage: rdy trust add [OPTIONS] --key <KEY> <PRODUCT>

Arguments:
  <PRODUCT>  The product the key may sign for, for example acme-platform

Options:
      --key <KEY>    The vendor's public key: a .pub file, or the key text
      --yes          Do not ask. For scripts. Only use it after you have
                     checked the fingerprint.
      --note <TEXT>  A note for yourself. It appears in every report you send.

Examples:
  Trust a key for yourself:
    rdy trust add acme-platform --key acme-platform.pub

  Trust a key for runs as root:
    sudo rdy trust add acme-platform --key acme-platform.pub

Exit codes:
  0   Key saved
  64  Not saved: you answered no, there is no terminal and no --yes, the file
      is a secret key, or the product already has a key with this key id
  70  Internal error
```

### A.11 `rdy trust list --help` and `rdy trust remove --help`

```text
Show the keys you trust

Prints every trusted key with its product, key id, fingerprint, the date you
added it, and your note. As a normal user it lists your file and the system
file. As root it lists only the system file.

Usage: rdy trust list [OPTIONS]

Exit codes:
  0   Done, even when no key is trusted yet
  64  The trust file is unsafe: other users can write to it
  70  Internal error
```

```text
Stop trusting a key

Removes the key for a product from the trust file you can write: yours as a
normal user, the system file as root. Specs signed by it are refused after
this. If the product has two keys, say which one with --key-id.

Usage: rdy trust remove [OPTIONS] <PRODUCT>

Arguments:
  <PRODUCT>  The product to stop trusting, for example acme-platform

Options:
      --key-id <ID>  Remove only the key with this id, as 'rdy trust list'
                     shows it

Examples:
  Stop trusting a vendor:
    rdy trust remove acme-platform

Exit codes:
  0   Key removed
  64  Not removed: no such key, or the product has two keys and no --key-id
  70  Internal error
```

### A.12 `rdy version --help`

```text
Print the version

Prints the version, the commit and the build date. Put this in a bug report.

Usage: rdy version [OPTIONS]

Options:
      --json             Print the fields as JSON on stdout

Example output:
  rdy 0.1.0 (4c1e9a2 2027-03-07)
```

## Appendix B: the three JSON reports

stdout of `rdy run ... --json`, and the `.json` file in the report folder (the same bytes). Small objects are
folded onto one line here so the page is readable; the writer's layout is 01 section 5.5, and the golden
files are whatever the writer emits. Each validates against `result.v1.schema.json` (re-checked on 2026-10-28 with `python3 -I` and jsonschema 4.26.0, Draft 2020-12, with the format checker; B.2 after applying its patch). `checks` is in spec
order. The action logs are short because the specs have few checks.

### B.1 READY (C.17)

```json
{
  "api_version": "rdy/v1",
  "kind": "Report",
  "producer": {
    "name": "rdy",
    "version": "0.1.0",
    "commit": "4c1e9a2",
    "rdy_spec": "0.1.0",
    "target": "x86_64-unknown-linux-musl"
  },
  "run": {
    "id": "0c7e5a39-8d24-4f1b-b6e2-9a4f3d7c1e08",
    "started_at": "2027-03-09T10:15:02.000Z",
    "finished_at": "2027-03-09T10:15:02.241Z",
    "duration_ms": 241,
    "options": {"jobs": 8, "deadline_ms": 300000, "allow_unsigned": false, "network": true, "kube_context": null}
  },
  "spec": {
    "product": "acme-quickstart",
    "version": ">=1.0",
    "sha256": "d59c4ca63be4c639085ede021a7e66c196792bdfd68c81981469687358667886",
    "file_name": "acme-quickstart.yaml",
    "size_bytes": 1418,
    "serial": null,
    "expires": null,
    "contact": null,
    "annotations": {}
  },
  "signature": {
    "state": "verified",
    "key_id": "9F3A6C21D4E87B05",
    "key_fingerprint": "4d2a7c0e9b1f3a5c6e8d0b2f4a6c8e0d1b3f5a7c9e2d4b6f8a0c2e4d6b8f0a1c",
    "product": "acme-quickstart",
    "signed_at": "2027-03-02T15:40:09Z",
    "trust_note": "Acme security page, fingerprint read back by phone",
    "trust_source": "user",
    "reason": null
  },
  "host": {
    "hostname": "acme-vm-03.corp.example",
    "host_id": "5f1c0a9e3b7d2c41",
    "os": {
      "family": "linux",
      "id": "rhel",
      "version": "9.4",
      "pretty_name": "Red Hat Enterprise Linux 9.4 (Plow)"
    },
    "kernel": "5.14.0-427.13.1.el9_4.x86_64",
    "arch": "x86_64",
    "virtualization": "vm",
    "container": false
  },
  "identity": {"euid": 1000, "user": "jdoe", "elevated": false, "kube": null},
  "proxy": {
    "https": "http://proxy.corp.example:3128",
    "http": "http://proxy.corp.example:3128",
    "no_proxy": [".corp.example", "10.0.0.0/8"]
  },
  "capabilities": [{"need": "network", "name": null, "available": true, "detail": null, "hint": null}],
  "verdict": "ready",
  "verdict_reason": null,
  "exit_code": 0,
  "summary": {
    "total": 5,
    "pass": 4,
    "warn": 0,
    "block": 0,
    "skipped": 1,
    "timeout": 0,
    "error": 0,
    "not_applicable": 1,
    "required_not_run": 0,
    "optional_not_run": 0
  },
  "checks": [
    {
      "key": "host.cpu",
      "id": "host.cpu",
      "name": null,
      "family": "host",
      "severity": "block",
      "status": "pass",
      "bucket": "passed",
      "message": "8 vCPUs found, 4 needed",
      "fix": null,
      "fix_source": null,
      "observed": {"logical_cores": 8, "physical_cores": 4, "arch": "x86_64", "hypervisor": true},
      "expected": {"min": 4},
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 2
    },
    {
      "key": "host.memory",
      "id": "host.memory",
      "name": null,
      "family": "host",
      "severity": "block",
      "status": "pass",
      "bucket": "passed",
      "message": "15.4 GiB found, 8 GiB needed",
      "fix": null,
      "fix_source": null,
      "observed": {
        "total_bytes": 16496934912,
        "available_bytes": 12884901888,
        "swap_total_bytes": 0,
        "cgroup_limit_bytes": null
      },
      "expected": {"min_bytes": 8589934592, "tolerance_bytes": 429496730},
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 1
    },
    {
      "key": "host.disk/root",
      "id": "host.disk",
      "name": "root",
      "family": "host",
      "severity": "warn",
      "status": "pass",
      "bucket": "passed",
      "message": "60.0 GiB free on /, 20 GiB needed",
      "fix": null,
      "fix_source": null,
      "observed": {
        "path": "/",
        "mount": "/",
        "fstype": "xfs",
        "free_bytes": 64424509440,
        "free_inodes": 31205120,
        "options": ["rw", "relatime"]
      },
      "expected": {"min_free_bytes": 21474836480, "recommended_free_bytes": 25769803776},
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 42,
      "duration_ms": 3
    },
    {
      "key": "host.disk/system",
      "id": "host.disk",
      "name": "system",
      "family": "host",
      "severity": "warn",
      "status": "skipped",
      "bucket": "not_applicable",
      "skip_kind": "not_applicable",
      "message": "Does not apply here. This check is for windows only.",
      "fix": null,
      "fix_source": null,
      "observed": null,
      "expected": null,
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0
    },
    {
      "key": "net.egress",
      "id": "net.egress",
      "name": null,
      "family": "net",
      "severity": "block",
      "status": "pass",
      "bucket": "passed",
      "message": "2 of 2 endpoints reachable through the proxy",
      "fix": null,
      "fix_source": null,
      "observed": {
        "via": "proxy",
        "proxy": "http://proxy.corp.example:3128",
        "endpoints": [
          {"target": "registry.acme.example:443", "outcome": "ok", "connect_ms": 38, "tls_ms": 61},
          {"target": "license.acme.example:443", "outcome": "ok", "connect_ms": 36, "tls_ms": 60}
        ]
      },
      "expected": {"via_proxy": "auto", "reachable": ["registry.acme.example:443", "license.acme.example:443"]},
      "needs": [{"need": "network", "name": null, "hard": true, "met": true}],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 42,
      "duration_ms": 190
    }
  ],
  "actions": [
    {
      "seq": 1,
      "check": "host.cpu",
      "at_ms": 41,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/proc/cpuinfo",
      "bytes": 8320,
      "truncated": false
    },
    {
      "seq": 2,
      "check": "host.cpu",
      "at_ms": 41,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/sys/fs/cgroup/cpu.max",
      "bytes": 13,
      "truncated": false
    },
    {
      "seq": 3,
      "check": "host.memory",
      "at_ms": 41,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/proc/meminfo",
      "bytes": 1482,
      "truncated": false
    },
    {
      "seq": 4,
      "check": "host.memory",
      "at_ms": 42,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/sys/fs/cgroup/memory.max",
      "bytes": 4,
      "truncated": false
    },
    {
      "seq": 5,
      "check": "host.disk/root",
      "at_ms": 42,
      "duration_ms": 1,
      "kind": "read",
      "outcome": "ok",
      "path": "/proc/self/mountinfo",
      "bytes": 2870,
      "truncated": false
    },
    {
      "seq": 6,
      "check": "net.egress",
      "at_ms": 42,
      "duration_ms": 2,
      "kind": "lookup",
      "outcome": "ok",
      "host": "proxy.corp.example",
      "answers": 1
    },
    {
      "seq": 7,
      "check": "host.disk/root",
      "at_ms": 43,
      "duration_ms": 0,
      "kind": "native",
      "outcome": "ok",
      "api": "statvfs",
      "path": "/"
    },
    {
      "seq": 8,
      "check": "net.egress",
      "at_ms": 45,
      "duration_ms": 36,
      "kind": "connect",
      "outcome": "ok",
      "host": "registry.acme.example",
      "port": 443,
      "addr": null,
      "via_proxy": "http://proxy.corp.example:3128"
    },
    {
      "seq": 9,
      "check": "net.egress",
      "at_ms": 82,
      "duration_ms": 61,
      "kind": "tls",
      "outcome": "ok",
      "host": "registry.acme.example",
      "sni": "registry.acme.example"
    },
    {
      "seq": 10,
      "check": "net.egress",
      "at_ms": 144,
      "duration_ms": 36,
      "kind": "connect",
      "outcome": "ok",
      "host": "license.acme.example",
      "port": 443,
      "addr": null,
      "via_proxy": "http://proxy.corp.example:3128"
    },
    {
      "seq": 11,
      "check": "net.egress",
      "at_ms": 181,
      "duration_ms": 60,
      "kind": "tls",
      "outcome": "ok",
      "host": "license.acme.example",
      "sni": "license.acme.example"
    }
  ],
  "actions_truncated": false,
  "actions_dropped": {},
  "redaction": {"ruleset": "report", "total": 0, "by_rule": {}},
  "complete": true,
  "interrupted": false
}
```

### B.2 READY with warnings (C.18)

B.2 is B.1 with fifteen changes: the run id and times, the disk entry (`status: warn`, `bucket: warning`, a
spec `fix`, a `builtin_fix`, less free space), the summary, the verdict and the exit code. Here they are as a
JSON Patch (RFC 6902) against B.1. The golden file is the full document the writer emits, and the patch
applied to B.1 gives it exactly.

```json
[
  {"op": "replace", "path": "/run/id", "value": "3b9d1f70-52c6-4a8e-8c13-7e0a5d2b9f41"},
  {"op": "replace", "path": "/run/started_at", "value": "2027-03-09T09:48:20.000Z"},
  {"op": "replace", "path": "/run/finished_at", "value": "2027-03-09T09:48:20.243Z"},
  {"op": "replace", "path": "/run/duration_ms", "value": 243},
  {"op": "replace", "path": "/verdict", "value": "ready_with_warnings"},
  {"op": "replace", "path": "/exit_code", "value": 1},
  {"op": "replace", "path": "/summary/pass", "value": 3},
  {"op": "replace", "path": "/summary/warn", "value": 1},
  {"op": "replace", "path": "/checks/2/status", "value": "warn"},
  {"op": "replace", "path": "/checks/2/bucket", "value": "warning"},
  {"op": "replace", "path": "/checks/2/message", "value": "12.0 GiB free on /, 20 GiB needed"},
  {"op": "replace", "path": "/checks/2/fix", "value": "Free space on / or mount a larger volume."},
  {"op": "replace", "path": "/checks/2/fix_source", "value": "spec"},
  {"op": "add", "path": "/checks/2/builtin_fix", "value": "/ has 12.0 GiB free, 20 GiB needed. Run df -h /. Grow the volume or point the install at a larger disk."},
  {"op": "replace", "path": "/checks/2/observed/free_bytes", "value": 12884901888}
]
```

### B.3 NOT READY (2.7)

```json
{
  "api_version": "rdy/v1",
  "kind": "Report",
  "producer": {
    "name": "rdy",
    "version": "0.1.0",
    "commit": "4c1e9a2",
    "rdy_spec": "0.1.0",
    "target": "x86_64-unknown-linux-musl"
  },
  "run": {
    "id": "6f8d2c4e-1b3a-4e5f-9a7b-2c1d0e9f8a6b",
    "started_at": "2027-03-09T14:30:05.000Z",
    "finished_at": "2027-03-09T14:30:15.231Z",
    "duration_ms": 10231,
    "options": {"jobs": 8, "deadline_ms": 300000, "allow_unsigned": true, "network": true, "kube_context": null}
  },
  "spec": {
    "product": "acme-platform",
    "version": ">=4.2",
    "sha256": "231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f",
    "file_name": "acme-platform.yaml",
    "size_bytes": 1988,
    "serial": null,
    "expires": null,
    "contact": null,
    "annotations": {}
  },
  "signature": {
    "state": "unsigned",
    "key_id": null,
    "key_fingerprint": null,
    "product": null,
    "signed_at": null,
    "trust_note": null,
    "trust_source": null,
    "reason": null
  },
  "host": {
    "hostname": "acme-node-01.corp.example",
    "host_id": "a03e7d91c4b2f580",
    "os": {
      "family": "linux",
      "id": "rhel",
      "version": "9.4",
      "pretty_name": "Red Hat Enterprise Linux 9.4 (Plow)"
    },
    "kernel": "5.14.0-427.13.1.el9_4.x86_64",
    "arch": "x86_64",
    "virtualization": "vm",
    "container": false
  },
  "identity": {"euid": 1000, "user": "jdoe", "elevated": false, "kube": null},
  "proxy": {
    "https": "http://proxy.corp.example:3128",
    "http": "http://proxy.corp.example:3128",
    "no_proxy": [".corp.example", "10.0.0.0/8"]
  },
  "capabilities": [
    {
      "need": "kube_context",
      "name": null,
      "available": false,
      "detail": "no kubeconfig found",
      "hint": "Pass --kubeconfig <file> or set KUBECONFIG."
    },
    {"need": "network", "name": null, "available": true, "detail": null, "hint": null}
  ],
  "verdict": "not_ready",
  "verdict_reason": null,
  "exit_code": 2,
  "summary": {
    "total": 8,
    "pass": 1,
    "warn": 1,
    "block": 1,
    "skipped": 4,
    "timeout": 1,
    "error": 0,
    "not_applicable": 0,
    "required_not_run": 4,
    "optional_not_run": 1
  },
  "checks": [
    {
      "key": "host.cpu",
      "id": "host.cpu",
      "name": null,
      "family": "host",
      "severity": "block",
      "status": "pass",
      "bucket": "passed",
      "message": "8 vCPUs found, 8 needed",
      "fix": null,
      "fix_source": null,
      "observed": {"logical_cores": 8, "physical_cores": 4, "arch": "x86_64", "hypervisor": true},
      "expected": {"min": 8},
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 2
    },
    {
      "key": "host.memory",
      "id": "host.memory",
      "name": null,
      "family": "host",
      "severity": "block",
      "status": "block",
      "bucket": "blocker",
      "message": "15.4 GiB found, 32 GiB needed",
      "fix": "Add RAM or choose a larger node class.",
      "fix_source": "spec",
      "builtin_fix": "15.4 GiB RAM, 32 GiB needed. Add RAM or pick a larger node class. A nominal 32 GiB machine shows about 31 GiB, so ask for a size class, not an exact number.",
      "observed": {
        "total_bytes": 16496934912,
        "available_bytes": 12884901888,
        "swap_total_bytes": 0,
        "cgroup_limit_bytes": null
      },
      "expected": {"min_bytes": 34359738368, "tolerance_bytes": 1717986918},
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 1
    },
    {
      "key": "host.disk",
      "id": "host.disk",
      "name": null,
      "family": "host",
      "severity": "warn",
      "status": "warn",
      "bucket": "warning",
      "message": "60.0 GiB free on / for /var/lib, 100 GiB needed",
      "fix": "Mount a larger volume at /var/lib before install.",
      "fix_source": "spec",
      "builtin_fix": "/var/lib is on / with 60.0 GiB free, 100 GiB needed. Run df -h /var/lib. Grow the volume or point the install at a larger disk.",
      "observed": {
        "path": "/var/lib",
        "mount": "/",
        "fstype": "xfs",
        "free_bytes": 64424509440,
        "free_inodes": 31205120,
        "options": ["rw", "relatime"]
      },
      "expected": {"min_free_bytes": 107374182400, "recommended_free_bytes": 128849018880},
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 42,
      "duration_ms": 3
    },
    {
      "key": "net.egress",
      "id": "net.egress",
      "name": null,
      "family": "net",
      "severity": "block",
      "status": "timeout",
      "bucket": "required_not_run",
      "timeout_after_ms": 10000,
      "message": "Timed out after 10 s.",
      "fix": "Run again. If it times out again, tell the vendor which check it was.",
      "fix_source": "rdy",
      "observed": null,
      "expected": {"via_proxy": "auto", "reachable": ["registry.acme.example:443", "license.acme.example:443"]},
      "needs": [{"need": "network", "name": null, "hard": true, "met": true}],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 42,
      "duration_ms": 10000
    },
    {
      "key": "k8s.version",
      "id": "k8s.version",
      "name": null,
      "family": "k8s",
      "severity": "block",
      "status": "skipped",
      "bucket": "required_not_run",
      "skip_kind": "missing_need",
      "message": "Not run. No Kubernetes cluster was reachable.",
      "fix": "Set a kubeconfig, or pass --kube-context <name>, then run again.",
      "fix_source": "rdy",
      "observed": null,
      "expected": null,
      "needs": [{"need": "kube_context", "name": null, "hard": true, "met": false}],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0
    },
    {
      "key": "k8s.storageclass",
      "id": "k8s.storageclass",
      "name": null,
      "family": "k8s",
      "severity": "warn",
      "status": "skipped",
      "bucket": "warning",
      "skip_kind": "missing_need",
      "message": "Not run. No Kubernetes cluster was reachable.",
      "fix": "Set a kubeconfig, or pass --kube-context <name>, then run again.",
      "fix_source": "rdy",
      "observed": null,
      "expected": null,
      "needs": [{"need": "kube_context", "name": null, "hard": true, "met": false}],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0
    },
    {
      "key": "gpu.cuda",
      "id": "gpu.cuda",
      "name": null,
      "family": "gpu",
      "severity": "block",
      "status": "skipped",
      "bucket": "required_not_run",
      "skip_kind": "not_in_build",
      "message": "Not run. This version of rdy has no gpu checks yet.",
      "fix": "Install a newer rdy. If there is none yet, ask the vendor how to go on.",
      "fix_source": "rdy",
      "observed": null,
      "expected": null,
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0
    },
    {
      "key": "aws.iam",
      "id": "aws.iam",
      "name": null,
      "family": "aws",
      "severity": "block",
      "status": "skipped",
      "bucket": "required_not_run",
      "skip_kind": "not_in_build",
      "message": "Not run. This version of rdy has no aws checks yet.",
      "fix": "Install a newer rdy. If there is none yet, ask the vendor how to go on.",
      "fix_source": "rdy",
      "observed": null,
      "expected": null,
      "needs": [],
      "partial": null,
      "truncated": false,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0
    }
  ],
  "actions": [
    {
      "seq": 1,
      "check": null,
      "at_ms": 2,
      "duration_ms": 0,
      "kind": "env",
      "outcome": "ok",
      "name": "KUBECONFIG"
    },
    {
      "seq": 2,
      "check": null,
      "at_ms": 3,
      "duration_ms": 0,
      "kind": "stat",
      "outcome": "failed",
      "path": "~/.kube/config",
      "error": "not found"
    },
    {
      "seq": 3,
      "check": "host.cpu",
      "at_ms": 41,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/proc/cpuinfo",
      "bytes": 8320,
      "truncated": false
    },
    {
      "seq": 4,
      "check": "host.cpu",
      "at_ms": 41,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/sys/fs/cgroup/cpu.max",
      "bytes": 13,
      "truncated": false
    },
    {
      "seq": 5,
      "check": "host.memory",
      "at_ms": 41,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/proc/meminfo",
      "bytes": 1482,
      "truncated": false
    },
    {
      "seq": 6,
      "check": "host.memory",
      "at_ms": 42,
      "duration_ms": 0,
      "kind": "read",
      "outcome": "ok",
      "path": "/sys/fs/cgroup/memory.max",
      "bytes": 4,
      "truncated": false
    },
    {
      "seq": 7,
      "check": "host.disk",
      "at_ms": 42,
      "duration_ms": 1,
      "kind": "read",
      "outcome": "ok",
      "path": "/proc/self/mountinfo",
      "bytes": 2870,
      "truncated": false
    },
    {
      "seq": 8,
      "check": "host.disk",
      "at_ms": 43,
      "duration_ms": 0,
      "kind": "native",
      "outcome": "ok",
      "api": "statvfs",
      "path": "/var/lib"
    },
    {
      "seq": 9,
      "check": "net.egress",
      "at_ms": 42,
      "duration_ms": 10000,
      "kind": "lookup",
      "outcome": "timeout",
      "host": "proxy.corp.example",
      "answers": 0
    }
  ],
  "actions_truncated": false,
  "actions_dropped": {},
  "redaction": {"ruleset": "report", "total": 0, "by_rule": {}},
  "complete": true,
  "interrupted": false
}
```

## Appendix C: samples for the other commands

All stderr unless marked. Exit codes follow each block. Names and paths are synthetic.

### C.1 The NOT READY run with `--quiet`

The run of 2.7 with `--quiet`: no header, no PASS line, no file list. Exit 2.

```console
$ rdy run acme-platform.yaml --allow-unsigned --quiet
WARNING: UNSIGNED SPEC
acme-platform.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

  BLOCK    host.memory       15.4 GiB found, 32 GiB needed
                             fix from the spec file (not verified): Add RAM or choose a larger node
                             class.
  TIMEOUT  net.egress        Timed out after 10 s. (required)
                             fix from rdy: Run again. If it times out again, tell the vendor which
                             check it was.
  SKIP     k8s.version       Not run. No Kubernetes cluster was reachable. (required)
                             fix from rdy: Set a kubeconfig, or pass --kube-context <name>, then run
                             again.
  SKIP     gpu.cuda          Not run. This version of rdy has no gpu checks yet. (required)
                             fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                             how to go on.
  SKIP     aws.iam           Not run. This version of rdy has no aws checks yet. (required)
                             fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                             how to go on.
  WARN     host.disk         60.0 GiB free on / for /var/lib, 100 GiB needed
                             fix from the spec file (not verified): Mount a larger volume at
                             /var/lib before install.
  SKIP     k8s.storageclass  Not run. No Kubernetes cluster was reachable.
                             fix from rdy: Set a kubeconfig, or pass --kube-context <name>, then run
                             again.

1 block, 1 warning, 1 passed, 4 required checks not run (1 timed out), 1 optional check not run

Report written to ./rdy-report-acme-platform-20270309T143005Z/
WARNING: UNSIGNED SPEC
NOT READY
```

### C.2 The READY run with `--verbose`

Exit 0. The `.. finished` lines are printed as checks finish, so on a pipe they appear before the list.

```console
$ rdy run acme-quickstart.yaml --verbose
rdy 0.1.0
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     verified, key 9F3A6C21D4E87B05, trusted by you, signed 2027-03-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128
needs   network: available

  .. finished host.memory (PASS, 1 ms)
  .. finished host.cpu (PASS, 2 ms)
  .. finished host.disk/root (PASS, 3 ms)
  .. finished net.egress (PASS, 190 ms)

  PASS     host.cpu          8 vCPUs found, 4 needed
                             expected  min=4
                             observed  logical_cores=8 physical_cores=4 arch=x86_64 hypervisor=true
                             took      2 ms
  PASS     host.memory       15.4 GiB found, 8 GiB needed
                             expected  min_bytes=8589934592 tolerance_bytes=429496730
                             observed  total_bytes=16496934912 available_bytes=12884901888
                                       swap_total_bytes=0 cgroup_limit_bytes=null
                             took      1 ms
  PASS     host.disk/root    60.0 GiB free on /, 20 GiB needed
                             expected  min_free_bytes=21474836480 recommended_free_bytes=25769803776
                             observed  path=/ mount=/ fstype=xfs free_bytes=64424509440
                                       free_inodes=31205120 options=list(2)
                             took      3 ms
  PASS     net.egress        2 of 2 endpoints reachable through the proxy
                             expected  via_proxy=auto reachable=list(2)
                             observed  via=proxy proxy=http://proxy.corp.example:3128
                                       endpoints=list(2)
                             took      190 ms
  SKIP     host.disk/system  Does not apply here. This check is for windows only.
                             took      0 ms

actions  11 recorded; the JSON report lists them
took     241 ms

0 blocks, 0 warnings, 4 passed, 1 not applicable

Report written to ./rdy-report-acme-quickstart-20270309T101502Z/
  rdy-report-acme-quickstart-20270309T101502Z.html
  rdy-report-acme-quickstart-20270309T101502Z.json
  spec.yaml
  spec.yaml.minisig
READY
```

### C.3 Dry run (M2)

Exit 0. It reads only rdy's own process state and the trust store, opens no socket and creates no folder. The
list is the one the M3 `--allow-exec` consent shows (ADR 0005). It is built with SEC-40.

```console
$ rdy run acme-quickstart.yaml --dry-run
Would run 4 checks. Nothing was run, read or sent.
  host.cpu          reads /proc/cpuinfo, /sys/fs/cgroup/cpu.max             needs: nothing
  host.memory       reads /proc/meminfo, /sys/fs/cgroup/memory.max           needs: nothing
  host.disk/root    reads /proc/self/mountinfo, filesystem stats for /       needs: nothing
  net.egress        connects to 2 endpoints in the spec, through the proxy   needs: network
  host.disk/system  does not apply on linux

Dry run: nothing was run.
```

### C.4 `rdy verify`

Exit 0. The fingerprint is in groups of four so it can be read aloud. `--json` prints the Verification in
C.11.

```console
$ rdy verify acme-platform.yaml
spec         acme-platform.yaml
product      acme-platform
sha256       231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f
signed on    2026-11-30T16:02:11Z
signing key  9F3A6C21D4E87B05
fingerprint  4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d
             1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c
trust        trusted on this machine (/etc/rdy/trust.yaml)
note         Acme security page, fingerprint read back by phone
revision     none
expires      never

VERIFIED
```

With `--key acme-platform.pub` instead of a pinned key, the KEY NOT PINNED banner prints first, the `trust`
line reads `key given with --key, not pinned`, and the last line is `VERIFIED, KEY NOT PINNED`. Exit 0, because
`rdy run` would accept the file with the same `--sig` and `--key`, and the same banner.

### C.5 Refusals (exit 64)

No verdict, no report. Two lines each. The strings are 01 section 4.8. No line names `--allow-unsigned` or
`run --key`; the `rdy trust add ... --key` line is the pinning command and is allowed.

```console
$ rdy run acme-quickstart.yaml
error: no signature found at acme-quickstart.yaml.minisig
fix: ask the vendor for acme-quickstart.yaml.minisig and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned

$ rdy run acme-platform.yaml
error: acme-platform.yaml is signed with key 9F3A6C21D4E87B05 (fingerprint 4d2a...0a1c), which you have not trusted for acme-platform
fix: get the vendor's public key from their docs, compare its fingerprint with what the vendor tells you, then run: rdy trust add acme-platform --key <file>

$ rdy run acme-platform.yaml --allow-unsigned
error: the signature on acme-platform.yaml does not match the file. It may have been changed after signing.
fix: get a fresh copy and its .minisig from the vendor. Do not run this file.

$ rdy run acme-platform.yaml
error: acme-platform.yaml expired on 2027-01-31. This machine's clock says 2027-02-03.
fix: ask the vendor for a current spec. If this machine's clock is wrong, set it and run again.
```

As root, the unknown-key refusal ends with the hint of 01 section 4.3: `as root, rdy reads only
/etc/rdy/trust.yaml. If you pinned this key as a normal user, pin it for root too: sudo rdy trust add
acme-platform --key <file>`. The other signature causes replace the first line: `the signature on
acme-platform.yaml is not in the form rdy accepts.` and `acme-platform.yaml is signed for product
'acme-edge', but the spec says 'acme-platform'.` A file with Windows line endings adds `The file has Windows
line endings. If it went through Git or email, ask for the original.`

### C.6 Usage errors (exit 64)

```console
$ rdy run
error: missing the spec file
fix: run 'rdy run <SPEC>', for example 'rdy run acme-platform.yaml'. See 'rdy run --help'.

$ rdy run acme-platform.yaml --out-dri reports
error: unknown flag --out-dri
fix: did you mean --out-dir? See 'rdy run --help'.

$ rdy run acme-platform.yaml --keey acme-platform.pub
error: unknown flag --keey
fix: see 'rdy run --help'

$ rdy run acme-platform.yaml --yes
error: unknown flag --yes
fix: see 'rdy run --help'

$ rdy run acme-platform.yaml --tokne=rdy_st_example
error: unknown flag --tokne
fix: see 'rdy run --help'

$ rdy run acme-platform.yaml --jobs 0
error: --jobs must be 1 or more
fix: use a number from 1 to 32, for example --jobs 8

$ rdy run acme-platfrom.yaml
error: cannot read acme-platfrom.yaml: no such file
fix: check the file name and the folder you are in

$ rdy run acme-platform.yaml
error: acme-platform.yaml:14:11: min is read as the number 1.3, but versions must be text
fix: write it with quotes: min: "1.30"
```

The suggester never offers `--key` or `--allow-unsigned`, so the second block (`--keey`) and the third (`--yes`,
an M2 flag typed on `run` in M1) get the plain fix. The fourth block shows that the text after `=` is never
echoed. With `--json`, the same fix goes in `ErrorOutput.fix` (C.11). M2 adds the refusal of a secret on argv:

```console
$ rdy run acme-platform.yaml --token rdy_st_example
error: tokens on the command line show up in shell history and in ps
fix: use --token-file, the RDY_TOKEN variable, or the prompt
```

### C.7 The report folder cannot be created (exit 70)

Checked right after the spec is verified (ADR 0016), so no check runs. With `--json`, stdout holds an
ErrorOutput with code `report_write`.

```console
$ rdy run acme-quickstart.yaml --out-dir /usr/share
error: cannot create the report folder /usr/share/rdy-report-acme-quickstart-20270309T101502Z (permission denied)
fix: use --out-dir <a folder you can write to>, or --no-report to skip the files
```

The reason in the brackets is plain words, never an OS error number. Four reasons beyond the OS ones
(permission denied, no such folder, disk full) are specific to the report folder. Each has its own text
and fix. Exact-text tests in `crates/rdy-cli/src/error/tests.rs` hold them.

| Reason | Message | Fix |
| --- | --- | --- |
| The new folder is owned by another user | `error: cannot create the report folder <path> (the folder is owned by another user)` | `use --out-dir <a folder on a local disk>, or --no-report to skip the files. On NFS with root_squash, root cannot own new folders` |
| The new folder cannot be made private | `error: cannot create the report folder <path> (the folder cannot be made private)` | `use --out-dir <a folder on a disk that keeps Unix permissions>, or --no-report to skip the files` |
| The folder name and the next eight are taken | `error: cannot create the report folder in <parent> (all the folder names are taken)` | `wait a second and run again, or use --out-dir <another folder>` |
| A report file with the final name exists (a bug, rdy never replaces it) | `error: cannot write the report files to <path> (the file already exists)` | The standard bug hint |

### C.8 `rdy spec lint`

Exit 1 (two warnings, no errors). `--json` prints the LintReport in C.11.

```console
$ rdy spec lint acme-platform.yaml
acme-platform.yaml:45:9: warning: gpu.cuda: this version of rdy has no gpu checks yet
  fix: customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want.
acme-platform.yaml:50:9: warning: aws.iam: this version of rdy has no aws checks yet
  fix: customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want.

acme-platform.yaml: 0 errors, 2 warnings
```

Exit 2 (errors):

```console
$ rdy spec lint acme-typo.yaml
acme-typo.yaml:24:5: error: unknown field 'mn' in host.memory
  fix: check the spelling (did you mean 'min'?)
acme-typo.yaml:30:5: error: host.cpu has no threshold, so it can only pass
  fix: add 'min: 4'.

acme-typo.yaml: 2 errors, 0 warnings
```

### C.9 `rdy spec keygen` and `rdy spec sign`

Exit 0 for both. Prompts are on stderr and read from the keyboard with echo off.

```console
$ rdy spec keygen acme-signing
Password for the new secret key (input hidden):
Repeat the password:
Wrote acme-signing.key (secret, readable only by you) and acme-signing.pub (public).

key id       9F3A6C21D4E87B05
fingerprint  4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d
             1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c

Publish the fingerprint on your docs page so customers can check it.
Back up acme-signing.key. Anyone who has it can sign specs as you.
Next: rdy spec sign <spec> --secret-key acme-signing.key
```

```console
$ rdy spec sign acme-platform.yaml --secret-key acme-signing.key
acme-platform.yaml:45:9: warning: gpu.cuda: this version of rdy has no gpu checks yet
  fix: customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want.
acme-platform.yaml:50:9: warning: aws.iam: this version of rdy has no aws checks yet
  fix: customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want.
Password for acme-signing.key (input hidden):
Signed acme-platform.yaml
  signature    acme-platform.yaml.minisig
  sha256       231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f
  signing key  9F3A6C21D4E87B05
  fingerprint  4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d
               1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c
  signed on    2027-03-02T15:40:09Z
Checked the new signature: it verifies.

Send your customer the spec, the .minisig file, acme-signing.pub, and this line:
  rdy trust add acme-platform --key acme-signing.pub
The fingerprint is 4d2a7c0e9b1f3a5c6e8d0b2f4a6c8e0d1b3f5a7c9e2d4b6f8a0c2e4d6b8f0a1c.
Tell them to compare it with your docs page before they say yes.
```

`sign` on a spec with lint errors prints the findings as in C.8, then `error: not signed: acme-typo.yaml has
2 errors` and `fix: correct the errors above and run rdy spec sign again`. Exit 64.

### C.10 `rdy trust`

`trust add` on a TTY, as a normal user. Exit 0.

```console
$ rdy trust add acme-platform --key acme-platform.pub
product      acme-platform
key id       9F3A6C21D4E87B05
fingerprint  4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d
             1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c
file         acme-platform.pub

Compare this fingerprint with the one the vendor published on their site or
told you by phone. If it differs, answer n.

Trust this key for acme-platform? [y/N] y
Trusted key 9F3A6C21D4E87B05 for acme-platform.
Saved to /home/jdoe/.config/rdy/trust.yaml
```

Any answer but `y` or `yes` prints `Not trusted. Nothing was changed.` and exits 64. With `--note`, it adds
"Your note appears in every report you send." Without a TTY and without `--yes`, and with a secret key by
mistake (both exit 64):

```console
$ rdy trust add acme-platform --key acme-platform.pub < /dev/null
error: cannot ask for confirmation because there is no terminal
fix: check the key's fingerprint with the vendor, then run again with --yes

$ rdy trust add acme-platform --key acme-signing.key
error: acme-signing.key is a secret key, not a public key
fix: give trust add the .pub file. Never share the .key file.
```

When the text of the secret key was typed on the command line instead of a file name, the refusal adds a
sentence. The text is not echoed.

```console
$ rdy trust add acme-platform --key 'untrusted comment: rdy secret key ...'
error: that is a secret key, not a public key
fix: give trust add the .pub file. Never share the .key file. It is now in your shell history. Make a new key pair.
```

`trust list` (stdout). Each key is a block, so it reads the same on a screen reader and in a log:

```console
$ rdy trust list
acme-platform
  key id       9F3A6C21D4E87B05
  fingerprint  4d2a 7c0e 9b1f 3a5c 6e8d 0b2f 4a6c 8e0d
               1b3f 5a7c 9e2d 4b6f 8a0c 2e4d 6b8f 0a1c
  added        2026-11-30
  note         Acme security page, fingerprint read back by phone
  file         /etc/rdy/trust.yaml
```

With no keys it prints `No keys are trusted yet.` and `To trust a vendor key: rdy trust add <product> --key
<file>`, exit 0. `trust remove acme-platform` prints `Removed key 9F3A6C21D4E87B05 for acme-platform.` With
two keys and no `--key-id`:

```console
$ rdy trust remove acme-platform
error: acme-platform has 2 trusted keys
fix: say which one to remove with --key-id: 9F3A6C21D4E87B05, 51B0C4D7E2A93F68
```

Build details: ADR 0033.

### C.11 JSON objects other than the Report

stdout. Each validates against its definition in `result.v1.schema.json`. Exit 64 for a spec that is
unsigned, and for a parse error with its position:

```json
{
  "api_version": "rdy/v1",
  "kind": "Error",
  "error": {
    "code": "spec_unsigned",
    "message": "no signature found at acme-platform.yaml.minisig",
    "fix": "ask the vendor for acme-platform.yaml.minisig and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned"
  },
  "verdict": null,
  "complete": false
}
```

```json
{
  "api_version": "rdy/v1",
  "kind": "Error",
  "error": {
    "code": "spec_parse",
    "message": "min is read as the number 1.3, but versions must be text",
    "fix": "write it with quotes: min: \"1.30\"",
    "file": "acme-platform.yaml",
    "line": 14,
    "column": 11
  },
  "verdict": null,
  "complete": false
}
```

Exit 64, a mistyped flag (code `usage`). The fix names neither `--key` nor `--allow-unsigned`:

```json
{
  "api_version": "rdy/v1",
  "kind": "Error",
  "error": {
    "code": "usage",
    "message": "unknown flag --keey",
    "fix": "see 'rdy run --help'"
  },
  "verdict": null,
  "complete": false
}
```

Exit 70, Ctrl-C in M1 (code `interrupted`; the M2 text is in 5.1):

```json
{
  "api_version": "rdy/v1",
  "kind": "Error",
  "error": {
    "code": "interrupted",
    "message": "interrupted. No report was written.",
    "fix": "run rdy again and let it finish"
  },
  "verdict": null,
  "complete": false
}
```

`rdy spec lint acme-platform.yaml --json` (a LintReport, exit 1):

```json
{
  "api_version": "rdy/v1",
  "kind": "Lint",
  "file": "acme-platform.yaml",
  "findings": [
    {
      "level": "warning",
      "code": "not_in_build",
      "line": 45,
      "column": 9,
      "key": "gpu.cuda",
      "message": "gpu.cuda: this version of rdy has no gpu checks yet",
      "fix": "customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want."
    },
    {
      "level": "warning",
      "code": "not_in_build",
      "line": 50,
      "column": 9,
      "key": "aws.iam",
      "message": "aws.iam: this version of rdy has no aws checks yet",
      "fix": "customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want."
    }
  ],
  "errors": 0,
  "warnings": 2
}
```

`rdy verify acme-platform.yaml --json` (a Verification, exit 0):

```json
{
  "api_version": "rdy/v1",
  "kind": "Verification",
  "producer": {
    "name": "rdy",
    "version": "0.1.0",
    "commit": "4c1e9a2",
    "rdy_spec": "0.1.0",
    "target": "x86_64-unknown-linux-musl"
  },
  "spec": {
    "product": "acme-platform",
    "version": ">=4.2",
    "sha256": "231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f",
    "file_name": "acme-platform.yaml",
    "size_bytes": 1988,
    "serial": null,
    "expires": null,
    "contact": null,
    "annotations": {}
  },
  "signature": {
    "state": "verified",
    "key_id": "9F3A6C21D4E87B05",
    "key_fingerprint": "4d2a7c0e9b1f3a5c6e8d0b2f4a6c8e0d1b3f5a7c9e2d4b6f8a0c2e4d6b8f0a1c",
    "product": "acme-platform",
    "signed_at": "2026-11-30T16:02:11Z",
    "trust_note": "Acme security page, fingerprint read back by phone",
    "trust_source": "system",
    "reason": null
  }
}
```

`rdy version --json`:

```json
{
  "name": "rdy",
  "version": "0.1.0",
  "commit": "4c1e9a2",
  "date": "2027-03-07",
  "target": "x86_64-unknown-linux-musl",
  "rdy_spec": "0.1.0",
  "api_version": "rdy/v1"
}
```
### C.12 NOT READY with no block (the week 2 alpha)

Every check is `not_in_build`, so nothing blocked and nothing ran. This is the first golden anyone sees
(ADR 0008, Consequences). The last line carries the count. Exit 2.

```console
$ rdy run acme-edge.yaml
rdy 0.1.0-alpha.2
spec    acme-edge >=1.0   (acme-edge.yaml)
sig     verified, key 9F3A6C21D4E87B05, trusted by you, signed 2026-12-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)

  SKIP     host.cpu     Not run. This version of rdy has no host checks yet. (required)
                        fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                        how to go on.
  SKIP     host.memory  Not run. This version of rdy has no host checks yet. (required)
                        fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                        how to go on.
  SKIP     host.disk    Not run. This version of rdy has no host checks yet. (required)
                        fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                        how to go on.

0 blocks, 0 warnings, 0 passed, 3 required checks not run

Report written to ./rdy-report-acme-edge-20261207T191244Z/
  rdy-report-acme-edge-20261207T191244Z.html
  rdy-report-acme-edge-20261207T191244Z.json
  spec.yaml
  spec.yaml.minisig
NOT READY: 3 required checks were not run
$ echo $?
2
```

### C.13 Nothing was checked

Both checks are for Windows, so on Linux neither counts and nothing was measured (ADR 0013 decision 5). Exit 1,
so a strict gate (`-eq 0`) still stops. The HTML says "rdy checked nothing on this machine" (D.7).

```console
$ rdy run acme-win-agent.yaml
rdy 0.1.0
spec    acme-win-agent >=2.0   (acme-win-agent.yaml)
sig     verified, key 9F3A6C21D4E87B05, trusted by you, signed 2027-03-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)

  SKIP     host.memory  Does not apply here. This check is for windows only.
  SKIP     host.disk    Does not apply here. This check is for windows only.

0 blocks, 0 warnings, 0 passed, 2 not applicable

Report written to ./rdy-report-acme-win-agent-20270309T112240Z/
  rdy-report-acme-win-agent-20270309T112240Z.html
  rdy-report-acme-win-agent-20270309T112240Z.json
  spec.yaml
  spec.yaml.minisig
READY with warnings: nothing was checked
$ echo $?
1
```

### C.14 A run with a one-run key

The key was given on the command line and is not saved (`rdy trust list` is unchanged). The banner prints first
and its first line again above the verdict. The verdict itself does not change. Exit 0.

```console
$ rdy run acme-edge.yaml --key acme-edge.pub
WARNING: KEY NOT PINNED
This spec was checked with a key given on the command line (fingerprint 4d2a7c0e...0a1c).
rdy cannot tell whose key that is.
Every report from this run is marked KEY NOT PINNED.

rdy 0.1.0
spec    acme-edge >=1.0   (acme-edge.yaml)
sig     verified, key 9F3A6C21D4E87B05, key given with --key, not pinned, signed 2027-03-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)

  PASS     host.cpu     4 vCPUs found, 2 needed
  PASS     host.memory  7.6 GiB found, 4 GiB needed

0 blocks, 0 warnings, 2 passed

Report written to ./rdy-report-acme-edge-20270309T112240Z/
  rdy-report-acme-edge-20270309T112240Z.html
  rdy-report-acme-edge-20270309T112240Z.json
  spec.yaml
  spec.yaml.minisig
WARNING: KEY NOT PINNED
READY
$ echo $?
0
```

### C.15 Ten before and after

| # | Before | After |
| --- | --- | --- |
| 1 | `Error: No such file or directory (os error 2)` (signature file missing) | `error: no signature found at acme-platform.yaml.minisig`<br>`fix: ask the vendor for acme-platform.yaml.minisig and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned` |
| 2 | `Error: signature verification failed: InvalidSignature` | `error: the signature on acme-platform.yaml does not match the file. It may have been changed after signing.`<br>`fix: get a fresh copy and its .minisig from the vendor. Do not run this file.` |
| 3 | clap: `error: unexpected argument '--keey' found`, a tip that suggests a flag, a usage block, exit 2 | `error: unknown flag --keey`<br>`fix: see 'rdy run --help'`. Exit 64, and no suggestion of `--key` |
| 4 | `Error: Os { code: 2, kind: NotFound, message: "No such file or directory" }` | `error: cannot read acme-platfrom.yaml: no such file`<br>`fix: check the file name and the folder you are in` |
| 5 | `invalid type: floating point '1.3', expected a string at line 14 column 11` | `error: acme-platform.yaml:14:11: min is read as the number 1.3, but versions must be text`<br>`fix: write it with quotes: min: "1.30"` |
| 6 | `Error: Permission denied (os error 13)`, shown after the whole run | Before any check: `error: cannot create the report folder ./rdy-report-acme-quickstart-20270309T101502Z (permission denied)`<br>`fix: use --out-dir <a folder you can write to>, or --no-report to skip the files`. Exit 70 |
| 7 | `Error: not a terminal`, or a prompt that hangs in CI | `error: cannot ask for confirmation because there is no terminal`<br>`fix: check the key's fingerprint with the vendor, then run again with --yes` |
| 8 | `Error: invalid public key` (the user passed a secret key) | `error: acme-signing.key is a secret key, not a public key`<br>`fix: give trust add the .pub file. Never share the .key file.` |
| 9 | `error trying to connect: tcp connect error: Connection refused (os error 111)` (a check result) | Message `Cannot reach https://api.k8s.acme.example:6443: connection refused`<br>Fix `Check the server address in your kubeconfig and that you are on the right network or VPN, then run rdy again` |
| 10 | `thread 'tokio-runtime-worker' panicked at crates/rdy-checks-host/src/memory.rs:41` | A `host.memory` result with status `ERROR`, message `internal error in host.memory`, and the bug fix line of rule 6. The rest of the run continues |


### C.16 The root Tip

Two forms, both excerpts of the line under the check list. The first is for a key pinned system-wide or a run
with no pinned key. The second is for a key pinned as a normal user (`trust_source: user`).

```text
Tip: 2 checks need root: host.ports, host.lsm. Run rdy as root to include them. rdy never asks for
     sudo.
```

```text
Tip: 2 checks need root: host.ports, host.lsm. Run rdy as root to include them. rdy never asks for
     sudo. As root, rdy reads only /etc/rdy/trust.yaml. First trust the vendor key for root: sudo
     rdy trust add acme-platform --key <file>
```

### C.17 Sample: READY (2.5)

A signed spec, normal user, Linux. The Windows disk entry does not apply and never counts. Exit 0.

```console
$ rdy run acme-quickstart.yaml
rdy 0.1.0
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     verified, key 9F3A6C21D4E87B05, trusted by you, signed 2027-03-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128

  PASS     host.cpu          8 vCPUs found, 4 needed
  PASS     host.memory       15.4 GiB found, 8 GiB needed
  PASS     host.disk/root    60.0 GiB free on /, 20 GiB needed
  PASS     net.egress        2 of 2 endpoints reachable through the proxy
  SKIP     host.disk/system  Does not apply here. This check is for windows only.

0 blocks, 0 warnings, 4 passed, 1 not applicable

Report written to ./rdy-report-acme-quickstart-20270309T101502Z/
  rdy-report-acme-quickstart-20270309T101502Z.html
  rdy-report-acme-quickstart-20270309T101502Z.json
  spec.yaml
  spec.yaml.minisig
READY
$ echo $?
0
```

### C.18 Sample: READY with warnings (2.6)

Same spec, a smaller disk. Exit 1. Only the optional disk check failed, so it sorts first with its fix,
labelled with the product because the key is pinned.

```console
$ rdy run acme-quickstart.yaml
rdy 0.1.0
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     verified, key 9F3A6C21D4E87B05, trusted by you, signed 2027-03-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128

  WARN     host.disk/root    12.0 GiB free on /, 20 GiB needed
                             fix from acme-quickstart: Free space on / or mount a larger volume.
  PASS     host.cpu          8 vCPUs found, 4 needed
  PASS     host.memory       15.4 GiB found, 8 GiB needed
  PASS     net.egress        2 of 2 endpoints reachable through the proxy
  SKIP     host.disk/system  Does not apply here. This check is for windows only.

0 blocks, 1 warning, 3 passed, 1 not applicable

Report written to ./rdy-report-acme-quickstart-20270309T094820Z/
  rdy-report-acme-quickstart-20270309T094820Z.html
  rdy-report-acme-quickstart-20270309T094820Z.json
  spec.yaml
  spec.yaml.minisig
READY with warnings
$ echo $?
1
```

## Appendix D: HTML details, colour, Unicode, Windows, environment and new crates

### D.1 Palette, Unicode and Windows

| Element | Style |
| --- | --- |
| `PASS` | green |
| `WARN`, `SKIP` | yellow |
| `BLOCK` | red, bold |
| `TIMEOUT`, `ERROR` | red |
| `(required)`, `Tip:`, `fix from ...:` | bold |
| Banners; `error:` | red, first line bold; red, bold |
| `READY`; `READY with warnings`; `NOT READY` | green bold; yellow bold; red bold |
| Elapsed time, verbose event lines | dim |


The only Unicode rdy prints is the spinner (`⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏`, ASCII `- \ | /`). Cut text uses `...`, never
`…`. Unicode is allowed when:

- on Unix, the first of `LC_ALL`, `LC_CTYPE`, `LANG` that is set and non-empty names `UTF-8` or `utf8`, and
  `TERM` is not `dumb` or `linux`;
- on Windows, `WT_SESSION` is set, or `TERM_PROGRAM` is `vscode`.

Otherwise it is ASCII. rdy does not ask the console for its code page, because that needs FFI and the crates
forbid unsafe code.

`anstream` enables colour where the Windows console supports it, converts SGR for legacy consoles where it can,
and strips it when output is not a console. Windows Terminal, the VS Code terminal and current conhost get full
behaviour; legacy conhost gets ASCII. Lines end in `\n`; stdout JSON is bytes, UTF-8, no BOM, so it matches the
file. Windows PowerShell 5.1 re-encodes redirected native output as UTF-16, so the docs tell users to read the
`.json` file in the report folder or use PowerShell 7. Paths print as typed, except the default report folder,
which is absolute (ADR 0016):

```text
Report written to C:\Users\jdoe\rdy-reports\rdy-report-acme-quickstart-20270309T101502Z\
```

Ctrl-C and Ctrl-Break work as in 5.1, through `tokio::signal::windows`.

### D.2 Colour tokens and contrast

CSS custom properties switched by `prefers-color-scheme`. WCAG ratios against the page and the panel
background; every pair is at or above 4.5:1.

| Token | Light | on page / panel | Dark | on page / panel |
| --- | --- | --- | --- | --- |
| page, panel | `#ffffff`, `#f6f8fa` | | `#0d1117`, `#161b22` | |
| text | `#1f2328` | 15.8 / 14.8 | `#e6edf3` | 16.0 / 14.6 |
| muted | `#59636e` | 6.1 / 5.7 | `#9da7b3` | 7.8 / 7.1 |
| block | `#b3261e` | 6.5 / 6.1 | `#ff8b84` | 8.4 / 7.6 |
| warn | `#8a4b00` | 6.8 / 6.4 | `#e3b341` | 9.7 / 8.9 |
| pass | `#1a7f37` | 5.1 / 4.8 | `#56d364` | 9.8 / 9.0 |
| link | `#0b5cad` | 6.7 / 6.3 | `#79b8ff` | 9.1 / 8.3 |
| banner text on fill | `#8a1c14` on `#fff1f0` | 8.5 | `#ffb4ae` on `#3b1214` | 9.7 |

A CI script reads the variables from the rendered CSS and fails under 4.5, in light, dark, and print with a
dark preference.

### D.3 Dark mode and print

`<meta name="color-scheme" content="light dark">` so the first paint is right; no toggle, because a toggle
needs JavaScript. `@media print` sets `color-scheme: light`, black text on white, no panel fills, whatever
the screen theme, so a dark-mode browser cannot print light text on white; the border styles stay; every
section is expanded (no `<details>` anywhere); `break-inside: avoid` on each check. Page breaks come only
before Passed, the capabilities section and the action log, so the verdict, blocks and required checks not
run share page one (01 section 6). The banner is `position: fixed` in the page margin so it prints on every
page, and the body gets a print `padding-top` equal to the banner height so the banner never covers the first
lines. The footer link prints its URL as text.

### D.4 Accessibility, size, embedded JSON, link and tests

`<html lang="en">`; one `h1`, then `h2`, then `h3`, never skipping a level; landmarks `header`, `nav
aria-label="Sections"`, `main`, `footer`; the status word is text inside the `h3`; tables only for the action
log and capabilities, with `<caption>` and `th scope`; `dl` for label and value; link text says where it
goes; a visible `:focus-visible` outline; no CSS `order`; 200% zoom and 320 px without sideways scroll; no
motion. The "Jump to" links are in-page `href="#<id>"` links.

The embedded `<script type="application/json" id="rdy-result" data-sha256="<hex>">` holds the exact bytes of
the `.json` file with the `\u003c`, `\u003e`, `\u0026` escapes (ADR 0003). Typical size under 300 KiB; hard
cap 5 MiB: past it the action table is cut to the rows that fit and ends with "N more entries are in the
embedded JSON"; checks are never cut.

The footer holds two links, both visible as text: `https://getrdy.io/?ref=report&product=<product>`, with
`rel="noopener noreferrer"` so no referrer is sent, and the source repository. The only parameters on the first
are `ref=report` and the product name, which the spec already shows. No run id, hostname, version, date or
customer data; no pixel, beacon, redirect or outside font or style. Nothing loads unless the reader clicks.
Clicks are counted by Plausible on getrdy.io, never by rdy. The footer says "This link carries the product
name and nothing else", and the docs security page lists the two parameters (ADR 0003 decision 8).

Tests:

- Golden HTML for B.1 to B.3.
- A Rust structure test: heading order, `lang`, `th scope`, unique ids, a status word in every `h3`, no raw
  engine word, every `href="#id"` has a target in the document, and no other `href` or `src` except `data:`,
  the footer link and the repo link. It also feeds a hostname with U+202E and a `fix` with U+2066 and asserts
  they sit inside `<bdi>` as `\u{202e}` and `\u{2066}`.
- The contrast script (D.2).
- In the headless-browser job of ADR 0003: `scrollWidth <= 320` at a 320 px viewport, and print media with
  dark preferred renders black on white.
- A release checklist item before 0.1.0: print each golden to PDF from a headless browser and look at it on
  paper.

### D.5 New crates

Each needs security-reviewer approval under the 05 dependency policy (purpose, maintainers, `unsafe`,
`build.rs`, license). The PR for each records the last three. Licenses below are the expected ones and are
checked by `cargo deny`.

| Crate | Purpose | Notes |
| --- | --- | --- |
| `indicatif` | The live progress line (section 3) | Pulls `console`. Both MIT. Drawn only through `ProgressDrawTarget::stderr_with_hz(10)` or `hidden()` |
| `anstream` | Colour stripping and Windows console handling (section 6) | MIT or Apache-2.0. Replaces `atty`, which is banned; TTY checks use `std::io::IsTerminal` |
| `unicode-width` | Pad columns by display width (section 6) | MIT or Apache-2.0 |
| `strsim` | The flag suggester (section 1) | MIT. Levenshtein distance over the visible flags |

### D.6 Environment variables

| Variable | Used by | Meaning | M |
| --- | --- | --- | --- |
| `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`, `TERM` | all | Colour and Unicode rules of section 6. `TERM=dumb` also turns off progress | M1 |
| `COLUMNS`, `LC_ALL`, `LC_CTYPE`, `LANG` | all | Wrap width (60 to 100) when stderr is not a terminal; UTF-8 locale allows the spinner | M1 |
| `WT_SESSION`, `TERM_PROGRAM` | all (Windows) | `WT_SESSION` set, or `TERM_PROGRAM=vscode`, allows the spinner (D.1) | M1 |
| `RDY_PROGRESS` | all | `never` equals `--progress never` | M1 |
| `RUST_LOG` | all | `tracing` filter, such as `RUST_LOG=rdy=debug`. Unset means no log output. Logs go to stderr through the redactor, never include secrets, and turn off the live progress line | M1 |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (and lower case) | `run` | Proxy settings for network checks. Printed without user info | M1 |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | `run` | Extra trust roots, where the platform loader reads them (Linux) | M1 |
| `KUBECONFIG` | `run` | Kubeconfig path list. `--kubeconfig` wins | M1 |
| `HOME`, `XDG_CONFIG_HOME` | `trust`, `run`, `verify` | The user trust file (Unix only; Windows has no user store and never reads `APPDATA`, ADR 0027). Never read when euid is 0 (ADR 0002). The kube client also reads `HOME` for `~/.kube/config` | M1 |
| `USERPROFILE` | `run` (Windows) | Default report folder `%USERPROFILE%\rdy-reports` (ADR 0016) | M1 |
| `RDY_KEY_PASSWORD` | `spec sign`, `spec keygen` | Signing key password for CI. The prompt and `--password-file` are the other ways | M1 |
| `RDY_TOKEN` | `run`, `bundle`, `upload` | Share-link token, `rdy_st_...` | M2 |

### D.7 HTML page order, wording and look

#### Page order

DOM order is visual order, and it is the terminal's `bucket` order. Empty sections are left out; the verdict
box says what is missing ("No blocks"). The banner comes before the header, as in the terminal and as 01
section 4.7 says ("at the top"). 01 section 6 lists it second; that list moves (Plan corrections).

```text
<title>rdy report: acme-platform, NOT READY</title>                       (01 section 6)

[ banner: UNSIGNED SPEC or KEY NOT PINNED, by the 4.7 rule; INCOMPLETE when complete is false ]
header
  h1   NOT READY                       the terminal's words; a hidden "Verdict:" comes before it
       For acme-platform >=4.2, revision 7, on acme-node-01.corp.example     (", revision N" only with a serial)
       1 block, 1 warning, 1 passed, 4 required checks not run (1 timed out), 1 optional check not run
       Run 2027-03-09 14:30:05 UTC with rdy 0.1.0 by jdoe (not root)
       What to do next / the legend / the rule in plain words (Header wording, below)
       This file lists hostnames and addresses from this machine. Read it before you send it.
nav    Jump to: Blocks (1) | Required checks not run (4) | Warnings and optional checks not run (2) | Passed (1) | Details
main
  h2   Blocks | Required checks not run | Warnings | Passed | Does not apply here     (by bucket)
  h2   What rdy could use on this machine      capabilities, available or not, with the hint
  h2   Run and spec details                    the 01 section 6 list, with the Signing key, Fingerprint, Your note
                                               about this key, Signed on and Spec revision labels
  h2   What rdy read and contacted             table, first 1000 rows, then "N more entries are in the embedded JSON"
footer  Made with Rdy. Use Rdy for your product: https://getrdy.io/?ref=report&product=acme-platform
        rdy 0.1.0 | source: https://github.com/getrdy-io/rdy
script  <script type="application/json" id="rdy-result" data-sha256="...">   (not rendered)
```

Each check is an `article` with an `h3` that holds the status word and `id (name)`, the message, the fix with
its label (`From acme-platform` only when verified and pinned, else `From the spec file (not verified)`;
`From rdy`; `More from rdy` below a vendor fix when `builtin_fix` is present), `Found` and `Needed` lists,
`Requires: kube_context (not available)`, `required by acme-platform` on a required check that did not run
(`required by the spec file` when the signature is not verified and pinned, as 01 section 6 says), and the
duration. `Found` and `Needed` render `observed` and `expected` with no per-check code (01 section 6): keys
humanised, `_bytes` as sizes, `_ms` as milliseconds, `_percent` with `%`, nested lists one per line. No raw
JSON key or engine word is visible text (a CI grep over the template). `TIMEOUT` and `ERROR` with `severity:
block` sit under "Required checks not run" next to the skips. Every string that came from the machine or the
spec is wrapped in `<bdi>`, and bidirectional controls show as `\u{202e}`, as in the terminal.

#### Header wording

The INCOMPLETE banner reads: "This report is incomplete. rdy stopped before every check finished." The
checks that did not finish are `TIMEOUT` or `SKIP`, as in the terminal.

"What to do next" by verdict: `ready` "Everything the spec asks for passed."; `ready_with_warnings` "Nothing
blocks the install. Read the warnings."; `ready_with_warnings` with `nothing_verified` "rdy checked nothing on
this machine. Every check in the spec is for another OS. Ask the vendor if that is expected."; `not_ready`
with blocks "Fix the N blocks below, then run rdy again."; `not_ready` with only unrun checks "rdy could not
check N required items. Follow the fix for each, then run rdy again." Then for all: "To share this result,
send the .json file from the same folder." and, if `metadata.contact` exists, "Questions: <contact>" as plain
text, never a link. Legend: "BLOCK: fix before install. WARN: fix if you can. SKIP: rdy could not check it."
Rule: "NOT READY if anything blocks or a required check could not run. READY with warnings if only optional
things are wrong. READY if every check ran and passed." The same three sentences are in `rdy run --help`.

#### Look

System fonts (`system-ui`, `ui-monospace`), sizes in `rem`, line height 1.5, content at most 60rem, no icons,
no images but the inline SVG logo, no animation. Status is a word plus a left-border style, so it survives
grayscale printing: BLOCK thick solid, TIMEOUT and ERROR thick double, SKIP thick dashed, WARN medium dashed,
PASS thin solid.

## Appendix E: M2 and M3 outlines

### E.1 Shell completion and man pages (M3)

`rdy completion <bash|zsh|fish|powershell|elvish>` prints a script on stdout from the same `clap` tree as the
help (`clap_complete`), with install lines in the help, such as `rdy completion bash >
~/.local/share/bash-completion/completions/rdy`. It reads no file and makes no call. Man pages come from the
same tree (`clap_mangen`) through `cargo xtask man`: one page for `rdy` and one per command; the Examples and
Exit codes sections of `--help` become the same sections. Release archives hold `completions/` and `man/`;
Homebrew, deb and rpm install them. `install.sh` installs the binary only, no root and nothing outside
`~/.local/bin`. The help text is snapshot-tested in M1, so neither can drift from it.

### E.2 M2 and M3 in brief

**Share-link run (M2).** `RDY_TOKEN=... rdy run acme-platform`. A bare name with no path separator and no
file of that name is a product. rdy says it is about to contact the portal, fetches the signed spec, shows
the key id and fingerprint, and asks before it trusts the key (see Decisions). `--no-network` makes this an
error with a fix. After the result, with a share link, the upload offer (the prompt in 04 section 6) prints
above the verdict, so the verdict is still last. Without a TTY or `--yes`, rdy prints `Not uploaded. To send
it: rdy upload <path>` and exits by verdict.

**Bundle, upload, report, redact (M2).** The output in 04 (sections 6 and 7 and Appendix C) follows these
rules with `--plan` renamed `--dry-run`. A bundle has no verdict; its last line is `not uploaded. To send it:
rdy upload <path>  (read manifest.json first)`. `report` writes a new folder like `run`. `redact` copies a
file or stdin to stdout through the redactor and prints a count on stderr. Exit codes: 0 done, 64 bad input or
consent refused, 70 could not deliver.

**`rdy spec init` and `rdy self-update` (M3).** `init` writes `<name>.yaml` with `metadata.product` set,
refuses to overwrite without `--force`, and ends by printing `rdy spec lint <name>.yaml`. `self-update`
prints current and latest versions, verifies the release as `install.sh` does, asks `Install 0.2.0 over
<path>? [y/N]`, and replaces the binary only after every check passes; `--check` stops after printing. A
failed check keeps the old binary and says how to reinstall by hand. Exit 0 done or current, 64 declined, 70
could not verify or write.

## Plan corrections found

- docs/plan/10-devrel-and-launch.md, section 1 README draft: the transcripts differ from C.17, C.18, 2.7 and C.5
  here. Use C.5 for the refusal (no error or fix line names `--allow-unsigned` or `run --key`, 01 section
  4.7); the five-line banner of 01 section 4.7 and its first line again above the verdict; the header
  `rdy`, `spec`, `sig`, `host`, `user`, `proxy` (no cpu or memory line); checks sorted by bucket with a
  `fix from ...:` line under each problem and no `Fixes:` block; `, 1 not applicable` in the summary; a report
  folder of four files (three when unsigned), never overwritten, so quickstart step 4 ("overwrite the last
  run") is wrong; `NOT READY: 2 required checks were not run` only when no block was seen. Regenerate the Show
  HN sample and the series posts from the goldens. The line-by-line list belongs in a review of 10. The
  earlier revision of this file (commit e3e3f96) has it in full.
- docs/plan/10-devrel-and-launch.md, trust table row "Checks connect only to the endpoints in the spec":
  `--dry-run` is M2, not "M1 stretch". Delete 10's ticket "rdy run --dry-run (stretch)"; it is merged into
  SEC-40 (below).
- docs/plan/10-devrel-and-launch.md, tickets "Review and lint example specs" and "CI job: lint every example
  spec": `rdy spec lint examples/specs/acme-platform.yaml` exits 1 by design (two warnings, 01 section 2.5).
  Fix: CI treats 0 and 1 as pass and 2 and 64 as fail.
- docs/plan/01-spec-format.md section 5.4, 02-engine-design.md (Decisions, SEC-40), 04-bundle-and-redaction.md
  (section 7, tickets) and 05-threat-model.md (R1, SEC-40): `--plan`. Fix: `--dry-run` everywhere, as in ADR
  0005, 00-overview.md and 10. SEC-40 is renamed "`rdy run --dry-run` preview" and absorbs the dry-run
  output work (C.3). Its claim is "reads only rdy's own process state and the trust store": the privilege
  snapshot reads `/proc/self/status` and `auxv`, and verification reads the trust store, so "reads no host
  file" cannot be tested. The consent list that ADR 0005 binds `--allow-exec` to must be this same list.
- docs/plan/02-engine-design.md, Verdict "Headline": `NOT READY: 1 blocker, 2 required checks not run` is
  rejected. The last line is 01 section 5.3 (`NOT READY`, or `NOT READY: N required checks were not run` when
  nothing blocked), and the summary line carries the counts. This answers 02's ticket "cli-ux review of verdict
  wording, interrupt behaviour and output naming".
- docs/plan/02-engine-design.md, Ctrl-C bullet: confirmed. M1: Ctrl-C aborts, prints `error: interrupted. No
  report was written.` and exits 70. rdy also removes the report folder if nothing was written to it
  (`remove_dir`, which only removes an empty folder; add to the SEC-19 ticket). From M2: first Ctrl-C partial
  report, second exits 70. `--no-network` and `--out-dir` are confirmed.
- docs/plan/02-engine-design.md, Scheduling, Watchdog "Locks", and its watchdog ticket: the watchdog writes
  "one fixed stderr line". Fix: one fixed two-line buffer (`error:` and `fix:`) in a single non-blocking
  `write`, so the `fix:` prefix holds. Add to the exit test: under `--json` with a blocked stdout pipe, stdout
  is empty or cut short, the exit is 70, and the partial Report is in the folder. 5.2 is the output.
- docs/plan/03-check-catalog.md (k8s intro, about line 261), docs/plan/04-bundle-and-redaction.md section 7 and
  docs/plan/05-threat-model.md (the open `--context` proposal, about lines 344 and 345): `--context` and
  `--namespace`. Fix: `--kube-context` (ADR 0010, 00-overview). `--namespace` belongs to `rdy bundle` in M2
  only. Close 05's proposal.
- docs/plan/01-spec-format.md section 4.8 and the result schema: add `spec_unreadable` (exit 64) and
  `interrupted` (exit 70) to the `ErrorOutput` code description, and add a `Version` definition for `rdy
  version --json` (4.3). All three land before 0.1.0, so they are revision 0 and need no rdy-spec bump. Also,
  ADR 0008 decision 7 lists `report_write` as an error-object code, while 01 section 5.3 and 02 print the
  Report with `complete: false` when a verdict exists. Fix: `report_write` is an ErrorOutput only when no
  verdict exists (before any check, `rdy report`, `rdy bundle`); with a verdict, stdout is the Report.
- docs/plan/01-spec-format.md section 2.3 and 02-engine-design.md Scheduling: record the `--timeout` guard
  (section 1 here): it may lower any limit and raise only limits the spec did not set. M2 adds
  `run.options.timeout_ms` to the schema. docs/plan/00-overview.md (the `rdy` crate paragraph, about line 315)
  lists `--timeout` among the M1 flags: move it to M2.
- docs/plan/01-spec-format.md section 6, content order: item 2 (the banner) moves above item 1 (the header),
  because 4.7 says "at the top", the terminal prints it first and the printed page repeats it first.
- docs/plan/01-spec-format.md section 5.2, the root fix `Rerun as root: sudo rdy run ...`: a user whose key
  is pinned in the user store lands in `spec_key_unknown` as root (ADR 0002 decision 4). Fix: when
  `trust_source` is `user`, add `First trust the vendor key for root: sudo rdy trust add <product> --key
  <file>`. 2.1 has the wording.
- docs/plan/01-spec-format.md section 6, header and labels: 01 shows "Spec revision N" in the header and `required
  by acme-platform` on a required skip when verified. 07 now follows 01 on both (D.7). No change to 01.
- docs/plan/02-engine-design.md, Output and reports: "vendor fix text is labelled 'From <product>'". 01 section
  2.6 labels it with the product only when the signature is verified and the key pinned, else "From the spec
  file (not verified)" (the terminal does the same, 2.2). Fix: 02 follows 01. 02 also says the spec copies are
  `spec.yaml` and `spec.yaml.minisig`; the `Report written to` block lists those names.
- docs/adr/0003, decision 2: "a `Report written to <dir>` line". 01 section 5.5 says the line names all four
  files. Fix: the folder line plus the files indented under it (2.1). The ADR has no `<title>` rule; 01
  section 6 sets `rdy report: <product>, <VERDICT>`, which this file follows.
- docs/plan/00-overview.md, `rdy` crate paragraph: the `run` flag list lacks `--no-network` and `--progress`;
  commands lack `redact` (M2) and `completion` (M3); `spec lint --json` is M1 (LintReport is in the schema).
- docs/plan/01-spec-format.md sections 4.7 and 4.8: the fix line links `https://docs.getrdy.io/unsigned`. The
  planned page in 09-docs-site.md is `/specs/signing/`. Fix: serve `/unsigned` as a redirect or page by 0.1.0
  (ticket below).
- CLAUDE.md, Engineering standards: exit codes are listed but clap's own default for a usage error is 2, which
  this project reserves for NOT READY. Fix: add "clap usage errors are mapped to 64, and `Parser::parse`,
  `Command::get_matches` and `Error::exit` are banned by clippy `disallowed-methods`" and the test.
- docs/plan/01-spec-format.md section 5.3 ticket "Summary line grammar and nothing-verified last line": its
  samples are the ones in 2.4. Fix: the exit test also covers the `(1 timed out)` and `(1 failed)` suffixes.

## Decisions needing an ADR

- **Exit code for a hard stop by Ctrl-C: 70. Settled** (code-reviewer, 2026-10-28). Reasons: the code set is
  fixed at five values; 130 is a sixth that every gate script must learn; Windows has no 128+n convention; 70
  already means "rdy could not deliver its result"; `error.code: interrupted` tells it from a crash. Needs a
  one-line amendment to ADR 0008 decision 4 (add Ctrl-C to the exit-70 list). Cost, stated on the docs
  exit-codes page: a bash loop keeps going after Ctrl-C, so "a loop should stop on 70". rdy does not re-raise
  SIGINT.
- **A declined `trust add` exits 64.** Chosen because a script chained with `&&` must stop when the key was
  not trusted. Alternative: exit 0 ("the user chose"), which lets a chain continue as if the key were pinned.
  Needs one line in ADR 0002 decision 5, the same rule as "no TTY and no `--yes`".
- **`--timeout` (M2) may lower any limit and raise only limits the spec did not set.** Not an architecture
  choice, so not an ADR: a one-line decision in 01 section 2.3 and 02 Scheduling, with security-reviewer
  sign-off. Alternatives: replace every limit (rejected: a vendor who sets `timeout: 5s` to match its own
  installer would get a READY from a path that needs 30 s, and the customer would hold a knob over the vendor's
  settings), or no flag.
- **Pinning from the M2 share-link flow.** ADR 0002 decision 6 pins a served key on an explicit yes inside `rdy
  run`, which conflicts with its own alternatives row ("pinning from run" lost). Security-relevant. Conservative
  choice: `run` writes no trust state. It shows the fingerprint, offers "trust this key for this run only" with
  the KEY NOT PINNED banner, and prints the `rdy trust add` line to pin it. Alternative: a `[y/p/N]` prompt
  that pins. Needs an ADR 0002 amendment before M2, not M1.
- **`run --upload` in M2.** CLAUDE.md rule 2 says upload is an explicit flag or a prompt. Chosen: a flag that
  asks the same consent question as `rdy upload`, plus the verb. Alternative: the verb only. One line in 04
  section 7.

## Tickets implied

Founder decision of 2026-10-28: M1 is extended, not cut, so every ticket below
stays. `core: yes` marks the six-week minimum; `core: no` marks what a trim drops first, in this order:
Unicode spinner choice, live progress line (with `--progress`), quiet and verbose, headless layout checks,
next-step sentences, `bdi` rendering, help text for spec, trust and version. A trimmed build also drops
`--progress`, `-q` and `-v` from the help snapshots. Never cut: the exit-code suite, the clap-to-64 mapping,
the banners, the verdict as last line. Tickets that overlap work other slices already count say "extends"
and carry only the extra hours, so 11-backlog can dedupe by title.

M1 total 44.5 hours in 26 tickets, on top of the other slices. Core total 33.5 hours (`core: yes`); `core: no` is 11 hours. The reviewer's core list came to 31.5 hours; this one adds 1 hour for the flag suggester inside the usage-error ticket and 1 hour for the `/unsigned` page, which the reviewer left in the docs-writer slice. `--dry-run` left M1 for M2 (it duplicated SEC-40), and `--timeout` left M1 for M2.

- [M1] clap command tree in rdy-cli exposed as library rdy_cli | owner: rust-engineer | est: 3h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: snapshots of `-h` and `--help` for `rdy`, `rdy run` and `rdy verify` match Appendix A (global options of A.0 included, `--timeout` and `--dry-run` absent), the other commands print the compact form, and bare `rdy`, `rdy spec` and `rdy trust` print help on stdout and exit 0. | core: yes
- [M1] Full help text for spec, trust and version commands | owner: rust-engineer | est: 1h | depends on: clap command tree in rdy-cli exposed as library rdy_cli | exit test: snapshots of `--help` for every command in A.5 to A.12 match Appendix A in wording, section order and examples. | core: no
- [M1] Extends "Error types with fix hints and exit code mapping at the CLI edge": usage errors, the flag suggester and no echo | owner: rust-engineer | est: 4h | depends on: clap command tree in rdy-cli exposed as library rdy_cli | exit test: every parse goes through `try_parse_from` and `clap::Parser::parse`, `clap::Command::get_matches` and `clap::Error::exit` are clippy `disallowed-methods`; `DisplayHelp`, `DisplayVersion` and `DisplayHelpOnMissingArgumentOrSubcommand` print on stdout and exit 0 and every other kind prints the two-line form and exits 64; `--json` is read from raw argv before any `--` and gives an ErrorOutput with code `usage`; golden stderr for an unknown flag with a did-you-mean (`--out-dri`), a missing argument, a bad value, `-q` with `-v` and `--password`; canaries in `--tokne=` and `--pasword` are absent from stderr and from the ErrorOutput; `--keey`, `--yes`, `--allow-unsgned` and `--kye` never put `--key` or `--allow-unsigned` in stderr or in `ErrorOutput.fix`. | core: yes
- [M1] Terminal styling layer: colour choice, width, escaping and ASCII text | owner: rust-engineer | est: 1.5h | depends on: clap command tree in rdy-cli exposed as library rdy_cli | exit test: table tests cover the colour rules of section 6, `TERM=dumb` and `COLUMNS` clamping, and a hostname holding an ANSI escape and a bidi override prints as `\x1b` and `\u{202e}`. | core: yes
- [M1] Unicode choice for the spinner: locale, `WT_SESSION` and `TERM_PROGRAM` | owner: rust-engineer | est: 1.5h | depends on: Terminal styling layer: colour choice, width, escaping and ASCII text | exit test: table tests cover D.1 (UTF-8 locale and `TERM` on Unix, `WT_SESSION` and `TERM_PROGRAM=vscode` on Windows, ASCII otherwise); no FFI is used. | core: no
- [M1] Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | owner: cli-ux | est: 4h | depends on: Add `bucket` to CheckResult and sort by it in terminal and HTML; Terminal styling layer: colour choice, width, escaping and ASCII text | exit test: golden stderr for B.1, B.2 and B.3 equals C.17, C.18 and 2.7 byte for byte at width 100 with `--color never`, the goldens C.12, C.13 and C.14 match, and the last line is the verdict. | core: yes
- [M1] Extends "SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading": fix source labels, wrapping, banner placement and the root Tip | owner: cli-ux | est: 1.5h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict; SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | exit test: an unsigned run and a `--key` run label spec fixes "the spec file (not verified)", a pinned run labels the product, a 130-character message wraps at 100 with a hanging indent, both banners print before the first check and again above the verdict, and both Tip forms of 2.1 match (the user-pinned form adds the `sudo rdy trust add` sentence). | core: yes
- [M1] Static "Running N checks..." line on a TTY | owner: rust-engineer | est: 0.5h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | exit test: a pty capture shows the line before the first check and no trace of it in the final screen, and a pipe, `--quiet` and `TERM=dumb` print nothing. | core: yes
- [M1] Progress line with indicatif, TTY only | owner: rust-engineer | est: 3h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict; Unicode choice for the spinner: locale, `WT_SESSION` and `TERM_PROGRAM` | exit test: a pty capture shows one spinner line that is cleared before the check list, a 250 ms run draws nothing (paused-time test), a pipe, `--quiet`, `--progress never`, `RDY_PROGRESS=never`, `TERM=dumb` and `RUST_LOG` each produce zero progress bytes; rules for the code: the banner and header print once before progress starts, one writer owns stderr so result text and `tracing` output go through it while a line is live, prompts never appear while it is live, Ctrl-C and any error clear the line first so `error:` starts at column 0, the bar is built with `ProgressDrawTarget::stderr_with_hz(10)` or `hidden()` because indicatif's own TTY check ignores `TERM`, `--quiet` and `RUST_LOG`, and nothing is drawn on stdout. | core: no
- [M1] Quiet and verbose output modes | owner: cli-ux | est: 2.5h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | exit test: golden stderr for C.1 (`--quiet`) and C.2 (`--verbose`), and `--verbose` prints one event line per finished check on a pipe. | core: no
- [M1] Ctrl-C in M1: abort, remove the empty report folder, exit 70 | owner: rust-engineer | est: 2h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation; SEC-19 Confine writes to a new output dir with safe names | exit test: a pty test sends SIGINT once and gets the two-line error of 5.1, exit 70, no report folder (removed with `remove_dir`, so a folder that holds a file stays) and no child process left, SIGTERM does the same, and `--json` prints an ErrorOutput with code `interrupted`. | core: yes
- [M1] Exit-code golden suite for 0, 1, 2, 64 and 70 | owner: rust-engineer | est: 2h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict; Extends "Error types with fix hints and exit code mapping at the CLI edge": usage errors, the flag suggester and no echo | exit test: assert_cmd runs one fixture per row of 5 (ready, warnings, not ready by a block, not ready by a required check not run, unsigned, bad flag, missing file, unwritable `--out-dir`) and compares exit code and stderr golden, and with `--json` validates stdout against the schema. | core: yes
- [M1] `--json` stdout hygiene on every exit path | owner: rust-engineer | est: 1.5h | depends on: Exit-code golden suite for 0, 1, 2, 64 and 70 | exit test: for each exit path except the watchdog, stdout is exactly one JSON document, equals the `.json` file where one exists, carries no ANSI under `--color always`, and `--no-report --json` still prints the Report; on the watchdog path, with a blocked stdout pipe, stdout is empty or cut short, stderr is the two lines of 5.2, the exit is 70 and the folder holds a Report with `complete: false`. | core: yes
- [M1] Extends "Package rdy in crates/rdy-cli with binary name rdy": `rdy version --json` | owner: rust-engineer | est: 1h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: golden stdout for both forms equals 4.3 and C.11, `rdy --version` prints the first form, and the object validates against the new `Version` definition. | core: yes
- [M1] Prompt helper: y/N, no-terminal refusal and hidden input | owner: rust-engineer | est: 2h | depends on: clap command tree in rdy-cli exposed as library rdy_cli | exit test: pty tests cover `y`, `yes`, `n`, empty and EOF, a missing TTY exits 64 with the fix line of C.10, and a password is read with echo off. | core: yes
- [M1] Extends "rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner" and "rdy spec lint with errors, warnings and did-you-mean": adds the output goldens | owner: cli-ux | est: 1h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner; rdy spec lint with errors, warnings and did-you-mean | exit test: golden output for C.4 and C.8, the Verification and LintReport JSON validate against the schema, and `verify --key` prints the KEY NOT PINNED banner and ends `VERIFIED, KEY NOT PINNED`. | core: yes
- [M1] Extends "rdy spec keygen and rdy spec sign" and "rdy trust add, list and remove": adds the output goldens | owner: cli-ux | est: 1h | depends on: rdy spec keygen and rdy spec sign; rdy trust add, list and remove; Prompt helper: y/N, no-terminal refusal and hidden input | exit test: golden output for C.9 and C.10, the fingerprint prints in groups of four and matches `signature.key_fingerprint`, and a secret key given to `trust add` is refused with the fix of C.10 (and the shell-history sentence when the key text was on argv). | core: yes
- [M1] Refuse --password on argv and read key passwords from env or file | owner: rust-engineer | est: 1h | depends on: clap command tree in rdy-cli exposed as library rdy_cli | exit test: `--password` exits 64 with the reason of 10, and `RDY_KEY_PASSWORD` and `--password-file -` sign a spec in CI without a prompt. | core: yes
- [M1] `--no-network` and `--jobs` flags | owner: rust-engineer | est: 1.5h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: `--no-network` skips network and Kubernetes checks as `missing_need` with `run.options.network` false, `strace -f -e trace=socket` shows zero `socket(2)` calls and the action log has no `connect` entries, `--no-network --kube-context x` prints the `cluster` line of 2.1 and exits by verdict, `--jobs 500` prints a cap note, and `--jobs 0` exits 64. | core: yes
- [M1] Extends "askama HTML report with inline CSS, dark mode and print": colour tokens and the contrast script | owner: cli-ux | est: 1.5h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a script reads the CSS variables and fails any text or border pair under 4.5:1 in light, dark, dark-preferred print and light print (D.2), and the golden HTML for B.1 to B.3 matches. | core: yes
- [M1] Extends "HTML print override, labels and legend": Found and Needed rendering and the footer link | owner: cli-ux | est: 2h | depends on: HTML print override, labels and legend; Extends "askama HTML report with inline CSS, dark mode and print": colour tokens and the contrast script | exit test: `_bytes`, `_ms` and `_percent` values print as sizes, milliseconds and percents, the footer link has only `ref=report` and the product with `rel="noopener noreferrer"`, and print has a top padding equal to the banner height. | core: yes
- [M1] HTML next-step sentences and the nothing-verified wording | owner: cli-ux | est: 1h | depends on: Extends "HTML print override, labels and legend": Found and Needed rendering and the footer link | exit test: golden HTML carries the sentences of D.7 by verdict, including the `nothing_verified` sentence for C.13. | core: no
- [M1] HTML structure test: headings, landmarks, tables and links | owner: cli-ux | est: 1.5h | depends on: Extends "HTML print override, labels and legend": Found and Needed rendering and the footer link | exit test: a Rust test over the three goldens asserts heading levels never skip, `lang` is set, every `h3` has a status word, tables have `th scope`, ids are unique, every `href="#id"` has a target in the document, and no other `href` or `src` is anything but `data:`, the footer link or the repo link. | core: yes
- [M1] HTML untrusted strings in bdi with bidi controls shown as escapes | owner: cli-ux | est: 1h | depends on: HTML structure test: headings, landmarks, tables and links | exit test: a hostname holding U+202E and a vendor `fix` holding U+2066 render inside `<bdi>` as `\u{202e}` and `\u{2066}`, and the structure test asserts it. | core: no
- [M1] Headless layout checks: 320 px and print with dark preferred | owner: qa-engineer | est: 1h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: in the headless-browser job of ADR 0003, `scrollWidth <= 320` at a 320 px viewport for the three goldens, and print media with dark preferred renders black on white; the manual PDF look stays a release checklist item. | core: no
- [M1] Serve https://docs.getrdy.io/unsigned | owner: docs-writer | est: 1h | depends on: none | exit test: the URL in 01 section 4.8 returns the page on what `--allow-unsigned` and `--key` do and when not to use them, and the docs link check passes. | core: yes
- [M2] Graceful first Ctrl-C with a partial report and the second-Ctrl-C message | owner: rust-engineer | est: 3h | depends on: Family limits and graceful Ctrl-C with a partial report | exit test: a pty test gets exit 2 with `interrupted` true after one SIGINT and exit 70 with the message of 5.1 after two.
- [M2] Extends "SEC-40 `rdy run --plan` preview": rename to `--dry-run` and add the C.3 output | owner: cli-ux | est: 2h | depends on: SEC-40 `rdy run --plan` preview | exit test: golden output for C.3, no report folder is created, no socket is opened (`strace -f -e trace=socket`), the only host reads are rdy's own process state and the trust store, and `--dry-run --json` exits 64 until the plan has a schema.
- [M2] `rdy run --timeout` with the lower-always, raise-defaults-only guard | owner: rust-engineer | est: 2h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: `--timeout 3s` ends a 10 s default at 3 s, a spec `timeout: 5s` is not raised by `--timeout 20s` but is lowered by `--timeout 2s`, a bare `20` exits 64, `run.options.timeout_ms` records it, and the header prints `limits  20 s per check (set by --timeout)`.
- [M2] Hidden --token and --secret refusals | owner: rust-engineer | est: 1h | depends on: Opt-in upload client and share-link spec fetch | exit test: `--token` and `--secret` exit 64 with the reason of C.6 and echo nothing after the flag name.
- [M2] Share-link run output: fetch notice, key fingerprint question, upload offer above the verdict | owner: cli-ux | est: 4h | depends on: Opt-in upload client and share-link spec fetch | exit test: golden transcripts for a TTY yes, a TTY no and no TTY, each ending in the verdict, and `--no-network` fails with a fix.
- [M2] Output for bundle, upload, report and redact | owner: cli-ux | est: 4h | depends on: rdy bundle command and plan and built-in collector set and redact | exit test: golden output for the 04 section 6 and Appendix C samples with `--dry-run` in place of `--plan`, and each command's exit codes match section 5.
- [M2] JSON for trust list and the dry-run plan | owner: rust-engineer | est: 4h | depends on: Extends "SEC-40 `rdy run --plan` preview": rename to `--dry-run` and add the C.3 output | exit test: both outputs validate against new schema definitions and the stable-output promise of 4.2 lists them.
- [M3] rdy completion and man pages from the clap tree | owner: rust-engineer | est: 4h | depends on: clap command tree in rdy-cli exposed as library rdy_cli | exit test: `rdy completion <shell>` output sources cleanly in bash, zsh, fish and PowerShell CI jobs, `cargo xtask man` writes one page per command, and the release archive holds `completions/` and `man/`.
- [M3] rdy spec init and rdy self-update output | owner: cli-ux | est: 4h | depends on: Signed self-update | exit test: golden output for init (refuses overwrite without `--force`) and for update, decline, check-only and a refused tampered release, each with the exit codes of E.2.
