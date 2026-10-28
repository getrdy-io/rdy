# 07 CLI UX: commands, output, JSON, exit codes, accessibility and the HTML report

Owner: cli-ux. Date: 2026-10-28. Status: draft for review by rust-architect, rust-engineer, security-reviewer
and devrel. Sources: CLAUDE.md, ADRs 0002, 0003, 0008, 0011, 0013, 0016, 00-overview.md, 01-spec-format.md
(draft 2), 02-engine-design.md (revision 3), 04-bundle-and-redaction.md, `result.v1.schema.json` (working
tree of 2026-10-28), and the reviews in `docs/plan/reviews/`. Where this file and 10-devrel-and-launch.md
differ, this file wins; the lines 10 must change are under "Plan corrections found".

Every message a user sees comes from here. The samples are golden files: the renderer tickets must
reproduce them byte for byte. They use `.example` names and synthetic keys. Terminal samples are stderr
unless marked. Long material is in the appendices: A help text, B the three JSON reports, C other samples.

## Decisions in one screen

1. **Streams.** Talk goes to stderr: progress, results, prompts, errors. Data goes to stdout: `--json`,
   `rdy version`, `rdy trust list`. With `--json` the human output still goes to stderr.
2. **Order of a run.** Checks are listed by `bucket` (blocks, required checks not run, warnings, passed, not
   applicable; 01 section 5.2). Each problem carries its fix on the line below it. Then the summary line, the
   report folder and the verdict.
3. **Last line.** `READY`, `READY with warnings`, `NOT READY`, `NOT READY: N required checks were not run` or
   `READY with warnings: nothing was checked`. Nothing prints after it, except an exit-70 error.
4. **Ctrl-C.** M1: stops the run, no report, exit 70. From M2: the first writes a partial report and exits by
   verdict; the second exits 70 at once. The hard stop is 70.
5. **Names.** `--no-network`, `--out-dir` (not `--out`), `--dry-run` (not `--plan`), `--kube-context`.
6. **clap's own errors exit 64, not 2.** clap's default is 2, which here means NOT READY.
7. **Progress is TTY only.** Nothing live on a pipe or in CI. `--verbose` adds plain event lines anywhere.
8. **rdy's own static text is ASCII.** Unicode only for the progress spinner, when the locale allows.
9. **No colour-only meaning.** Every status is a word. ANSI 16 colours, no backgrounds.
10. **No hint names `--allow-unsigned` or `run --key`** (01 section 4.7). Secrets never go on argv. Consent
    flags have no environment twin.
11. **The HTML report** puts the verdict and blocks first, reads in DOM order, prints with every section
    open, follows the system colour scheme, and links to getrdy.io with the product name and nothing else.

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

**Global flags** (every command, before or after the subcommand): `--color <auto|always|never>` (M1),
`--progress <auto|never>` (M1, env `RDY_PROGRESS`), `-q/--quiet` (M1, conflicts with `-v`), `-v/--verbose`
(M1), `-h` (compact help), `--help` (full help with examples), `-V/--version` (top level only).

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
| `--no-network` | M1 | Open no sockets. Network and Kubernetes checks are skipped as `missing_need` |
| `--timeout <time>` | M1 | Limit for every check, 1s to 60s. Replaces check and spec limits. A bare number is seconds |
| `--jobs <n>` | M1 | Checks at once. Default 8. Above 32 is capped with a note. 0 is a usage error |
| `--dry-run` | M1 stretch | Print what each check would read, contact and need. Runs nothing. `--json` with it is a usage error until M2 |
| `--token-file <file>`, `--server <url>`, `--upload`, `--yes` | M2 | Share-link token, portal origin, offer the upload after the run, answer yes to it |
| `--allow-exec <hash>` | M3 | Allow the exact `custom.exec` commands that hash to this value |

**Other commands.** `verify`: `--sig`, `--key`, `--json`, no `--allow-unsigned`. `spec lint`: `--json`; exit 0
clean, 1 warnings, 2 errors, 64 usage (01 section 2.5). `spec sign`: `--secret-key <file>` (required; 01 shows
it in brackets, but guessing a key location is worse), `--sig <out>`, `--force`, `--password-file <file>`.
`spec keygen <name>`: writes `<name>.key` and `<name>.pub`; `--unencrypted` (CI only), `--password-file`;
never overwrites, so no `--force`. `trust add`: `--key <key>` (required), `--yes`, `--note <text>`; refuses a
secret key. `trust remove`: `--key-id <id>` when a product has two keys. `spec init` (M3): `--template`,
`--force`. `bundle` (M2): the flags of 04 section 7 with `--plan` renamed `--dry-run`. `upload` (M2):
`--token-file`, `--server`, `--yes`, `--json`. `self-update` (M3): `--check`, `--yes`. `version`: `--json`.

**Flag rules.** Long flags are lowercase words with hyphens; short flags only `-h -V -q -v`. Flags that grant
trust or consent (`--allow-unsigned`, `--key`, `--allow-exec`, `--yes`) are read from argv only (INV-05).
Hidden `--token`, `--password` and `--secret` exist only to exit 64 with the reason. `--json` never changes a
verdict or exit code. Unknown flags get a did-you-mean at edit distance two or less.

## 2. What a run prints

### 2.1 Layout

Blocks in this order, one blank line between them: (1) the banner, if any; (2) the header: `rdy <version>` and
labelled lines; (3) the check list; (4) a `Tip:` line when two or more checks were skipped for lack of
root (`Tip: 2 checks need root: host.ports, host.lsm. Run rdy as root to include them. rdy never asks for
sudo.`); (5) the summary line; (6) in M2, `Interrupted. This report is partial.`; (7) `Report written to
<folder>/` with the files indented under it (not with `--no-report`); (8) the banner's first line again;
(9) the verdict line.

| Header label | Content |
| --- | --- |
| `spec` | `<product> <version>   (<file as typed>)`, with `, revision N` when the spec has a `serial` |
| `sig` | `verified, key <id>, <trust>, signed <date>` with `<trust>` one of `trusted by you`, `trusted on this machine`, `key given with --key, not pinned`; or `UNSIGNED (allowed by --allow-unsigned)` |
| `host`, `user`, `proxy` | `<hostname>   <os> <version>   <arch>`; `<login> (root)` or `(not root)`; the proxy in effect with user info stripped, left out when none |
| `cluster` | `<context>, <server>`, plus `, credential plugin: <name>` and `, TLS verification is OFF` when they apply. Printed before the first request, so the user sees which cluster rdy is about to touch. `no kubeconfig found` when none. Left out when the spec has no Kubernetes checks |

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

The unsigned banner is 01 section 4.7 and appears in the third sample. A `--key` run prints this one in the
same places (before any check, red, first line again above the verdict). Neither hint nor error ever names
the flags. M2 adds `Run it anyway? [y/N]` after either banner on a TTY.

```text
WARNING: KEY NOT PINNED
This spec was checked with a key given on the command line (fingerprint 4d2a7c0e...0a1c).
rdy cannot tell whose key that is.
Every report from this run is marked KEY NOT PINNED.
```

### 2.4 Summary line and last line

Three parts always print: `N block(s)`, `N warning(s)`, `N passed`. Then, only when above zero and in this
order: `N required check(s) not run`, `N optional check(s) not run`, `N not applicable`. A timeout or error
inside a not-run count adds a suffix: `4 required checks not run (1 timed out)`, `(1 failed)`, or
`(1 timed out, 1 failed)`. Parts are joined with `, `. Singular for one. This is 01 section 5.3.

| `verdict` | `verdict_reason` | Last line | Exit |
| --- | --- | --- | --- |
| `ready` | null | `READY` | 0 |
| `ready_with_warnings` | null | `READY with warnings` | 1 |
| `ready_with_warnings` | `nothing_verified` | `READY with warnings: nothing was checked` | 1 |
| `not_ready` | null (a block was seen) | `NOT READY` | 2 |
| `not_ready` | `required_check_not_run` | `NOT READY: 1 required check was not run` or `NOT READY: 3 required checks were not run` | 2 |

With a block and unrun required checks together the last line is plain `NOT READY` and the summary line
carries the count.

### 2.5 Sample: READY

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

### 2.6 Sample: READY with warnings

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
an optional check not run and sorts with the warnings; the passing check is last.

### 2.8 Quiet, verbose and dry run

`--quiet` drops the header, PASS and not-applicable lines, the file list and the progress. It keeps the
banner, every problem with its fix, the summary, the folder line and the verdict (C.1). `--verbose` adds
under each entry `expected`, `observed` (scalars as `key=value`, lists as `key=list(N)`, objects as
`key=map(N)`) and `took` lines, a `needs` block under the header, one plain line as each check finishes (on a
pipe too), and an `actions` count (C.2). `--dry-run` (M1 stretch) verifies the spec,
prints what each check would read, contact and need, and ends with `Dry run: nothing was run.` It reads no
host file, opens no socket and creates no folder (C.3).

## 3. Progress display

Progress uses `indicatif`. A run can take ten seconds or more (a check timeout is 10 s by default), and a
silent terminal looks hung. It is never needed to read a result.

| Condition | Live line | Plain event lines |
| --- | --- | --- |
| stderr is a TTY, `TERM` not `dumb`, no `--quiet`, `--progress auto`, `RUST_LOG` unset | yes | no |
| stderr not a TTY (pipe, file, CI), `--quiet`, `--progress never` or `RDY_PROGRESS=never`, `TERM=dumb`, `RUST_LOG` set, `--dry-run` | no | no |
| `--verbose` | as above | yes, on any stream |

What it draws: one line, redrawn at most 10 times a second, no bar, nothing else on screen.

```text
⠋ Probing: kubernetes context acme-staging
⠙ Running checks 3 of 8, 4 s: net.egress, k8s.version
```

The text after the colon lists the checks running now, cut to the width with `...`. Elapsed time shows after
2 seconds. The first frame waits 250 ms, so fast runs never flash. The line is cleared (`finish_and_clear`)
before the check list prints and leaves no trace in scrollback. The spinner is Braille when Unicode is
allowed (section 6) and `- \ | /` otherwise.

Rules for the code: the banner and header print once, before progress starts. One writer owns stderr, so
result text and `tracing` output go through it while a line is live. Prompts never appear while progress is
live. On Ctrl-C and on any error the line is cleared first, so `error:` starts at column 0. Build the bar
with `ProgressDrawTarget::stderr_with_hz(10)` or `hidden()`; indicatif's own TTY check is not enough because
`TERM`, `--quiet` and `RUST_LOG` are ours. Nothing is ever drawn on stdout.

## 4. `--json` and the stable-output promise

### 4.1 What goes where

With `--json`, stdout holds one JSON document and a final newline: UTF-8, no BOM, LF. The bytes equal the
`.json` file in the report folder (ADR 0003), including the `\u003c`, `\u003e`, `\u0026` escapes (01 section
5.5), and are the same with `--no-report`. Anything else on stdout is a bug.

| Outcome | stdout with `--json` |
| --- | --- |
| `run` exits 0, 1 or 2 | The Report (`kind: Report`) |
| exit 64 | An ErrorOutput (`kind: Error`, `verdict: null`, `complete: false`), with `file`, `line`, `column` where known |
| `run` exits 70 and a verdict exists (files not written, watchdog fired) | The Report with `complete: false`. The error text is on stderr only |
| exit 70 with no verdict (`internal`, `interrupted`, `report_write` from `report` or `bundle`) | An ErrorOutput |
| `verify` accepts the spec / `spec lint` / `version` | Verification / LintReport (`kind: Lint`, exit 0, 1 or 2) / version object (4.4) |

The error text is on stderr in every case as `error:` and `fix:` lines, and equals the JSON `message` and
`fix`. For a spec error with a position, the terminal prefixes the message with `file:line:column:` built
from the three JSON fields; the JSON `message` does not repeat them. Samples of each object are in B and
C.11.

| Error `code` (stable, open) | Exit | When |
| --- | --- | --- |
| `usage` | 64 | A bad flag, missing argument or bad value |
| `spec_unreadable` | 64 | The spec file is missing, not a regular file, or unreadable. New |
| `spec_parse`, `spec_invalid` | 64 | YAML or structure problems, with position |
| `spec_unsigned`, `spec_signature_invalid`, `spec_key_unknown` | 64 | 01 section 4.8 |
| `spec_expired`, `trust_store_insecure` | 64 | 01 section 4.8 |
| `report_write`, `interrupted`, `internal` | 70 | No verdict exists and the files could not be written; Ctrl-C (new); a bug in rdy |

### 4.2 The promise

1. **Within `rdy/v1` the JSON only grows.** No field is removed, renamed, retyped or given a new meaning. New
   optional fields and new values in enums the schema marks "Open" appear in minor releases. `verdict` and
   `exit_code` are closed.
2. **Scripts may rely on** (01 section 5): `verdict`, `verdict_reason`, `exit_code`, `complete`,
   `interrupted`, `summary.*`, `checks[].key`, `.id`, `.severity`, `.status`, `.bucket`, `.skip_kind`,
   `.duration_ms`, and `error.code`. They must not parse `message`, `fix`, `notes` or `observed` as text.
3. **Consumers** ignore unknown fields, accept unknown values in open enums, never recompute the verdict,
   and never rely on key order or whitespace. The writer is deterministic (schema order, two spaces), which
   keeps diffs readable; that is a courtesy, not a promise.
4. **Summary arithmetic:** `pass + warn + block + skipped + timeout + error = total`. `not_applicable`,
   `required_not_run` and `optional_not_run` are views inside that sum. The summary may gain keys.
5. **Removing or changing anything needs `rdy/v2`,** an ADR, and 12 months of v1 support (ADR 0007).
6. **Not promised:** the words of human output, help, `--verbose`, the layout of `rdy trust list`, the
   progress line. Promised for scripts: the exit codes, the verdict forms of the last line (first words are
   exactly `READY`, `READY with warnings` or `NOT READY`, then optionally `: <reason>`), and the `error:` and
   `fix:` prefixes.
7. **How we keep it:** every golden result from every release parses in CI forever
   (`tests/fixtures/results/`, 01 section 3.4); B.1 to B.3 are fixtures; the schema drift check runs on every
   PR.

The three Reports in Appendix B are the same runs as 2.5 to 2.7 and validate against the schema. `checks`
stays in spec order; sorting by `bucket` is the reader's job. B.1 is the clean case (a not-applicable skip,
`trust_source: user`). B.2 adds a `warn` with `builtin_fix`. B.3 is unsigned and carries a timeout, two
`missing_need` skips and two `not_in_build` skips. A NOT READY run with no block has `verdict_reason:
"required_check_not_run"`; that is B.3 without the block, covered by a unit test.

### 4.3 `rdy version`

```console
$ rdy version
rdy 0.1.0 (4c1e9a2 2027-03-07)
```

`rdy --version` prints the same line. Alpha builds read `rdy 0.1.0-alpha.3 (abc1234 2026-12-01)` (ADR 0011).
`rdy version --json` prints `name`, `version`, `commit`, `date`, `target`, `rdy_spec`, `api_version`
(C.11), and only grows. 01 should add a `Version` definition to the result schema.

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
makes `sign` print the findings and exit 64.

**64, the input must change:** a bad flag or value, a missing argument, conflicting flags, a hidden refused
flag; a spec that is missing, unreadable, unparsable, invalid, too large or expired; no signature, a
signature that does not verify (always, even with `--allow-unsigned`), a key that is not pinned, a sidecar
that cannot be read; an unsafe trust file; `trust add` without a TTY and without `--yes`, or answered no;
`spec sign` on a spec with errors or with a key readable by others; M2: a missing or malformed token, an
upload answered no.

**70, rdy could not deliver:** the report folder cannot be created, or its name and the next eight (`-2` to `-9`) are
taken (checked right after the spec is verified, before any check, ADR 0016; files that cannot be written at the end, such as a full
disk, print the result first); a refused privileged launch; a runtime failure or a panic outside a check (a
panic inside a check is an `ERROR` result); the watchdog (the run hung 10 s past its 5 minute deadline: rdy
writes a report with `complete: false`, marked INCOMPLETE in the HTML, and prints one fixed line, because the
watchdog takes no output lock: `error: the run did not finish, so rdy stopped itself. fix: run it again and
tell the vendor which check was running.`);
Ctrl-C in M1 and the second Ctrl-C from M2; M2: an upload that could not reach the server.

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
convention: the code set is fixed at five values, and a sixth is a new contract for every script. 70 already
means "rdy could not deliver its result". With `--json`, stdout gets an ErrorOutput with code `interrupted`.

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

**Palette.** ANSI 16 only: no 256-colour or truecolour, no backgrounds, no blink, no OSC 8 links. The user's
theme picks the shades, so it works on light and dark terminals.

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

Colour never carries meaning alone. Nothing the user must read is dim. Yellow is weak on some light themes;
the word still says WARN, and `--color never` is the fix. Untrusted strings are escaped first and never
styled.

**Symbols.** rdy's own static text is ASCII: check list, headers, banners, errors, prompts, summaries. That
keeps logs, pipes, goldens and old consoles safe. Unicode is used for one thing, the spinner.

| Use | Unicode | ASCII |
| --- | --- | --- |
| Spinner | `⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏` | `- \ \| /` |
| Cut text | `…` | `...` |

Unicode is allowed when: on Unix, the first of `LC_ALL`, `LC_CTYPE`, `LANG` that is set and non-empty names
`UTF-8` or `utf8`, and `TERM` is not `dumb` or `linux`; on Windows, `WT_SESSION` is set, or `TERM_PROGRAM` is
`vscode`, or the console code page is 65001. Text from the machine or the spec may hold any UTF-8; rdy
escapes control characters (section 9) and pads by display width (`unicode-width`).

**Windows.** `anstream` enables colour where the console supports it, converts SGR for legacy consoles where
it can, and strips it when output is not a console. Windows Terminal, the VS Code terminal and current conhost
get full behaviour; legacy conhost gets ASCII. Lines end in `\n`; stdout JSON is bytes, UTF-8, no BOM, so it
matches the file. Windows PowerShell 5.1 re-encodes redirected native output as UTF-16, so the docs tell
users to read the `.json` file in the report folder or use PowerShell 7. Paths print as typed
(`.\rdy-report-...`). Ctrl-C and Ctrl-Break work as in 5.1, through `tokio::signal::windows`.

## 7. Accessibility

Terminal: (1) one linear order, top to bottom, with the verdict last, so `tail -n 1` always gives it; (2)
every status is a word at the same position on every line; (3) no layout carries meaning: no tables, box
drawing, emoji or right-aligned columns, and a label and its value share a line; (4) the only redraw is the
progress line, and `--progress never`, `RDY_PROGRESS=never`, `TERM=dumb` and `--quiet` remove it so a screen
reader does not read spinner frames; (5) contrast follows the user's theme and nothing important is dim; (6)
`error:` and `fix:` start at column 0; (7) prompts are plain questions ending in `[y/N]`, passwords are read
with echo off, and a prompt never appears while progress is live; (8) short sentences, plain words, English
only in M1, with all user text in one module so a catalog can be added later.

HTML: the list is in 8.6.

## 8. The HTML report design brief

The contract is 01 section 6 and ADR 0003. This is the design that fills it in. rust-engineer builds it from
the `Report` value alone, with askama, and the output is deterministic. Readers: a customer engineer who
needs the verdict in two seconds, a change board with a printout, an SE who got the file by email, a
screen-reader user, and a security reviewer who wants one file with no network and no script.

### 8.1 Page order

DOM order is visual order, and it is the terminal's `bucket` order. Empty sections are left out; the verdict
box says what is missing ("No blocks").

```text
<title>rdy report: acme-platform, NOT READY</title>                       (01 section 6)

[ banner: UNSIGNED SPEC or KEY NOT PINNED, by the 4.7 rule; INCOMPLETE when complete is false ]
header
  h1   NOT READY                       the terminal's words; a hidden "Verdict:" comes before it
       For acme-platform >=4.2 on acme-node-01.corp.example
       1 block, 1 warning, 1 passed, 4 required checks not run (1 timed out), 1 optional check not run
       Run 2027-03-09 14:30:05 UTC with rdy 0.1.0 by jdoe (not root)
       What to do next / the legend / the rule in plain words (8.2)
       This file lists hostnames and addresses from this machine. Read it before you send it.
nav    Jump to: Blocks (1) | Required checks not run (4) | Warnings (2) | Passed (1) | Details
main
  h2   Blocks | Required checks not run | Warnings | Passed | Does not apply here     (by bucket)
  h2   What rdy could use on this machine      capabilities, available or not, with the hint
  h2   Run and spec details                    rdy and target, run id, options, spec file, SHA-256, signature,
                                               Signing key, Fingerprint, Your note about this key, Signed on,
                                               Spec revision, expiry, contact, identity, credential plugin,
                                               TLS verification, proxy
  h2   What rdy read and contacted             table, first 1000 rows, then "N more entries are in the embedded JSON"
footer  Made with Rdy. Use Rdy for your product: https://getrdy.io/?ref=report&product=acme-platform
        rdy 0.1.0 | source: https://github.com/getrdy-io/rdy
script  <script type="application/json" id="rdy-result" data-sha256="...">   (not rendered)
```

Each check is an `article` with an `h3` that holds the status word and `id (name)`, the message, the fix with
its label (`From acme-platform` only when verified and pinned, else `From the spec file (not verified)`;
`From rdy`; `More from rdy` below a vendor fix when `builtin_fix` is present), `Found` and `Needed` lists,
`Requires: kube_context (not available)`, `required by the spec file` on a required check that did not run,
and the duration. `Found` and `Needed` render `observed` and `expected` with no per-check code (01 section
6): keys humanised, `_bytes` as sizes, `_ms` as milliseconds, `_percent` with `%`, nested lists one per
line. No raw JSON key or engine word is visible text (a CI grep over the template). `TIMEOUT` and `ERROR`
with `severity: block` sit under "Required checks not run" next to the skips.

### 8.2 Header wording

The INCOMPLETE banner reads: "This report is incomplete. rdy stopped before every check finished." The
checks that did not finish are `TIMEOUT` or `SKIP`, as in the terminal.

"What to do next" by verdict: `ready` "Everything the spec asks for passed."; `ready_with_warnings` "Nothing
blocks the install. Read the warnings."; `not_ready` with blocks "Fix the N blocks below, then run rdy
again."; `not_ready` with only unrun checks "rdy could not check N required items. Follow the fix for each,
then run rdy again." Then for all: "To share this result, send the .json file from the same folder." and, if
`metadata.contact` exists, "Questions: <contact>" as plain text, never a link. Legend: "BLOCK: fix before
install. WARN: fix if you can. SKIP: rdy could not check it." Rule: "NOT READY if anything blocks or a
required check could not run. READY with warnings if only optional things are wrong. READY if every check
ran and passed." The same three sentences are in `rdy run --help`.

### 8.3 Look

System fonts (`system-ui`, `ui-monospace`), sizes in `rem`, line height 1.5, content at most 60rem, no icons,
no images but the inline SVG logo, no animation. Status is a word plus a left-border style, so it survives
grayscale printing: BLOCK thick solid, TIMEOUT and ERROR thick double, SKIP thick dashed, WARN medium dashed,
PASS thin solid.

### 8.4 Colour tokens and contrast

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

### 8.5 Dark mode and print

`<meta name="color-scheme" content="light dark">` so the first paint is right; no toggle, because a toggle
needs JavaScript. `@media print` sets `color-scheme: light`, black text on white, no panel fills, whatever
the screen theme, so a dark-mode browser cannot print light text on white; the border styles stay; every
section is expanded (no `<details>` anywhere); `break-inside: avoid` on each check. Page breaks come only
before Passed, the capabilities section and the action log, so the verdict, blocks and required checks not
run share page one (01 section 6). The banner is `position: fixed` in the page margin so it prints on every
page, and the footer link prints its URL as text.

### 8.6 Accessibility, size, embedded JSON, link

`<html lang="en">`; one `h1`, then `h2`, then `h3`, never skipping a level; landmarks `header`, `nav
aria-label="Sections"`, `main`, `footer`; the status word is text inside the `h3`; tables only for the action
log and capabilities, with `<caption>` and `th scope`; `dl` for label and value; link text says where it
goes; a visible `:focus-visible` outline; no CSS `order`; 200% zoom and 320 px without sideways scroll; no
motion.

The embedded `<script type="application/json" id="rdy-result" data-sha256="<hex>">` holds the exact bytes of
the `.json` file with the `\u003c`, `\u003e`, `\u0026` escapes (ADR 0003). Typical size under 300 KiB; hard
cap 5 MiB: past it the action table is cut to the rows that fit and ends with "N more entries are in the
embedded JSON"; checks are never cut.

The footer holds one link, visible as text: `https://getrdy.io/?ref=report&product=<product>`, with
`rel="noopener noreferrer"` so no referrer is sent. The only parameters are `ref=report` and the product
name, which the spec already shows. No run id, hostname, version, date or customer data; no pixel, beacon,
redirect or outside font or style. Nothing loads unless the reader clicks. Clicks are counted by Plausible
on getrdy.io, never by rdy. The footer says "This link carries the product name and nothing else", and the
docs security page lists the two parameters (ADR 0003 decision 8).

Tests: golden HTML for B.1 to B.3; a Rust structure test (heading order, `lang`, `th scope`, unique ids, a
status word in every `h3`, no raw engine word, no `href` or `src` except `data:`, the footer link and the
repo link); the contrast script; and a manual step before 0.1.0: print each golden to PDF from a headless
browser and view it at 320 px wide, in dark mode and on paper.

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
3. **Plain words.** No `os error 13`, Rust type names, bare HTTP codes ("the proxy refused it (403)"),
   "invalid" or "failed" alone. Say spec, check, folder, key, signature file; not manifest, probe, directory.
4. **Say what did and did not happen** when it matters: "Nothing was sent." "Nothing was saved."
5. **No blame,** no "you must", no "please" (one exception: the bug line), no exclamation marks.
6. **Punctuation.** One sentence: no final period. Two or more: each ends with a period. Lowercase first word
   after the prefix unless it is a name.
7. **Never weaken security in a fix.** No error, fix or hint names `--allow-unsigned` or `rdy run --key`
   (01 section 4.7, threat model T2); both are documented in `--help` and on docs.getrdy.io. A hint may name
   `rdy trust add ... --key`, the pinning command. A did-you-mean for a flag the user mistyped is not a hint:
   the user already chose it.
8. **No secrets.** Tokens, passwords, key bytes, proxy user info and environment values never appear; every
   string goes through the redactor first (ADR 0008 decision 9).
9. **Untrusted text is escaped:** control characters as `\xNN`, bidirectional controls as `\u{202e}`; never
   styled.
10. **A bug says so:** `fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues
    and include the output of rdy version.`
11. **JSON matches.** `message` and `fix` in an ErrorOutput are the two lines without prefixes; a position
    goes in `file`, `line`, `column`.
12. **Spec errors and not-run checks use the words of 01 sections 2.5 and 5.2,** not repeated here.

Ten before and after:

| # | Before | After |
| --- | --- | --- |
| 1 | `Error: No such file or directory (os error 2)` (signature file missing) | `error: no signature found at acme-platform.yaml.minisig`<br>`fix: ask the vendor for acme-platform.yaml.minisig and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned` |
| 2 | `Error: signature verification failed: InvalidSignature` | `error: the signature on acme-platform.yaml does not match the file. It may have been changed after signing.`<br>`fix: get a fresh copy and its .minisig from the vendor. Do not run this file.` |
| 3 | clap: `error: unexpected argument '--keey' found`, a tip, a usage block, exit 2 | `error: unknown flag --keey`<br>`fix: did you mean --key? See 'rdy run --help'.` Exit 64 |
| 4 | `Error: Os { code: 2, kind: NotFound, message: "No such file or directory" }` | `error: cannot read acme-platfrom.yaml: no such file`<br>`fix: check the file name and the folder you are in` |
| 5 | `invalid type: floating point '1.3', expected a string at line 14 column 11` | `error: acme-platform.yaml:14:11: min is read as the number 1.3, but versions must be text`<br>`fix: write it with quotes: min: "1.30"` |
| 6 | `Error: Permission denied (os error 13)`, shown after the whole run | Before any check: `error: cannot create the report folder ./rdy-report-acme-quickstart-20270309T101502Z (permission denied)`<br>`fix: use --out-dir <a folder you can write to>, or --no-report to skip the files`. Exit 70 |
| 7 | `Error: not a terminal`, or a prompt that hangs in CI | `error: cannot ask for confirmation because there is no terminal`<br>`fix: check the key's fingerprint with the vendor, then run again with --yes` |
| 8 | `Error: invalid public key` (the user passed a secret key) | `error: acme-signing.key is a secret key, not a public key`<br>`fix: give trust add the .pub file. Never share the .key file.` |
| 9 | `error trying to connect: tcp connect error: Connection refused (os error 111)` (a check result) | Message `Cannot reach https://api.k8s.acme.example:6443: connection refused`<br>Fix `Check the server address in your kubeconfig and that you are on the right network or VPN, then run rdy again` |
| 10 | `thread 'tokio-runtime-worker' panicked at crates/rdy-checks-host/src/memory.rs:41` | A `host.memory` result with status `ERROR`, message `internal error in host.memory`, and the bug fix line of rule 10. The rest of the run continues |

## 10. Environment variables and secrets

| Variable | Used by | Meaning | M |
| --- | --- | --- | --- |
| `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`, `TERM` | all | Colour and Unicode rules of section 6. `TERM=dumb` also turns off progress | M1 |
| `COLUMNS`, `LC_ALL`, `LC_CTYPE`, `LANG` | all | Wrap width (60 to 100) when stderr is not a terminal; UTF-8 locale allows the spinner | M1 |
| `RDY_PROGRESS` | all | `never` equals `--progress never` | M1 |
| `RUST_LOG` | all | `tracing` filter, such as `RUST_LOG=rdy=debug`. Unset means no log output. Logs go to stderr through the redactor, never include secrets, and turn off the live progress line | M1 |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (and lower case) | `run` | Proxy settings for network checks. Printed without user info | M1 |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | `run` | Extra trust roots, where the platform loader reads them (Linux) | M1 |
| `KUBECONFIG` | `run` | Kubeconfig path list. `--kubeconfig` wins | M1 |
| `HOME`, `XDG_CONFIG_HOME`, `APPDATA` | `trust`, `run`, `verify` | The user trust file. Never read when euid is 0 (ADR 0002) | M1 |
| `RDY_KEY_PASSWORD` | `spec sign`, `spec keygen` | Signing key password for CI. The prompt and `--password-file` are the other ways | M1 |
| `RDY_TOKEN` | `run`, `bundle`, `upload` | Share-link token, `rdy_st_...` | M2 |

rdy reads no other variable for behaviour. There is no `RDY_NO_COLOR` or `RDY_COLOR`, and no variable that
turns on `--allow-unsigned`, `--key`, `--allow-exec` or `--yes`.

**Secrets never go on argv.** `/proc/<pid>/cmdline` is world-readable on Linux and shell history keeps what
you type. Share-link token (M2): `RDY_TOKEN`, `--token-file <file>` (`-` for stdin), or a hidden prompt;
`--token <value>` exits 64 with "tokens on the command line show up in shell history and in ps". Signing key
password: the prompt, `--password-file`, or `RDY_KEY_PASSWORD`; `--password <value>` exits 64 the same way.
The signing key is a path, never bytes. Proxy credentials come from `HTTPS_PROXY`; there is no `--proxy`
flag. Public keys may be on argv. Token and password files must not be symlinks or readable by group or
others (Unix). rdy never prints its own argv or environment, and the action log records variable names only.

## 11. Shell completion and man pages (M3)

`rdy completion <bash|zsh|fish|powershell|elvish>` prints a script on stdout from the same `clap` tree as the
help (`clap_complete`), with install lines in the help, such as `rdy completion bash >
~/.local/share/bash-completion/completions/rdy`. It reads no file and makes no call. Man pages come from the
same tree (`clap_mangen`) through `cargo xtask man`: one page for `rdy` and one per command; the Examples and
Exit codes sections of `--help` become the same sections. Release archives hold `completions/` and `man/`;
Homebrew, deb and rpm install them. `install.sh` installs the binary only, no root and nothing outside
`~/.local/bin`. The help text is snapshot-tested in M1, so neither can drift from it.

## 12. M2 and M3 in brief

**Share-link run (M2).** `RDY_TOKEN=... rdy run acme-platform`. A bare name with no path separator and no
file of that name is a product. rdy says it is about to contact the portal, fetches the signed spec, shows
the key id and fingerprint, and asks before it trusts the key (see Decisions). `--no-network` makes this an
error with a fix. After the result, with a share link, the upload offer (the prompt in 04 section 6.2) prints
above the verdict, so the verdict is still last. Without a TTY or `--yes`, rdy prints `Not uploaded. To send
it: rdy upload <path>` and exits by verdict.

**Bundle, upload, report, redact (M2).** The output in 04 (Appendix F, section 6.2) follows these rules with
`--plan` renamed `--dry-run`. A bundle has no verdict; its last line is `not uploaded. To send it: rdy upload
<path>  (read manifest.json first)`. `report` writes a new folder like `run`. `redact` copies a file or stdin
to stdout through the redactor and prints a count on stderr. Exit codes: 0 done, 64 bad input or consent
refused, 70 could not deliver.

**`rdy spec init` and `rdy self-update` (M3).** `init` writes `<name>.yaml` with `metadata.product` set,
refuses to overwrite without `--force`, and ends by printing `rdy spec lint <name>.yaml`. `self-update`
prints current and latest versions, verifies the release as `install.sh` does, asks `Install 0.2.0 over
<path>? [y/N]`, and replaces the binary only after every check passes; `--check` stops after printing. A
failed check keeps the old binary and says how to reinstall by hand. Exit 0 done or current, 64 declined, 70
could not verify or write.

## Appendix A: help text for rdy and every M1 command

This is what the M1 build prints. The wording, the order of sections and the examples are fixed here. clap
sets the column alignment, and the snapshot (the plain-file helper of 08) is taken from the first build
whose text matches this. `-h` prints the compact form (the first sentence of each option, no examples).
`--help` prints the full form shown here. Later milestones add their commands and flags to these pages.
Lines are 80 columns or fewer.

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
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
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
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
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
  70  Internal error, or the report could not be written

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
                             Kubernetes checks are skipped.
      --timeout <TIME>       Time limit for every check, such as 20s. Replaces
                             the limits in the spec. 1s to 60s.
      --jobs <N>             Checks to run at once [default: 8, max: 32]
      --dry-run              Show what each check would read and connect to.
                             Runs nothing.

Options:
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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
  70  Internal error, or the report could not be written
```

### A.4 `rdy verify --help`

```text
Check a spec's signature without running any checks

Reads the spec and its signature and checks the signature against the keys
you trust. Prints who signed it and when. Exit 0 means 'rdy run' would accept
this file with no override. It never asks a question.

Usage: rdy verify [OPTIONS] <SPEC>

Arguments:
  <SPEC>  The spec file, for example acme-platform.yaml

Options:
      --sig <FILE>  Read the signature from this file
                    [default: <SPEC>.minisig]
      --key <KEY>   Check against this public key only, for this command.
                    Prints a KEY NOT PINNED warning.
      --json        Print a JSON result on stdout
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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

Options:
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

Environment:
  RDY_KEY_PASSWORD  The key password, for CI. Never put it on the command line.

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
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

Environment:
  RDY_KEY_PASSWORD  The new key password, for CI. Never put it on the command
                    line.

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

Options:
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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

Options:
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

Exit codes:
  0   Done, even when no key is trusted yet
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
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

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
      --color <WHEN>     Colors: auto, always, never [default: auto]
      --progress <WHEN>  Live progress: auto, never [default: auto]
  -q, --quiet            Print only problems and the verdict
  -v, --verbose          Print details for every check
  -h, --help             Print help (see a summary with '-h')

Example output:
  rdy 0.1.0 (4c1e9a2 2027-03-07)
```

## Appendix B: the three JSON reports

stdout of `rdy run ... --json`, and the `.json` file in the report folder (the same bytes). Small objects are
folded onto one line here so the page is readable; the writer's layout is 01 section 5.5, and the golden
files are whatever the writer emits. Each validates against `result.v1.schema.json`. `checks` is in spec
order. The action logs are short because the specs have few checks.

### B.1 READY (2.5)

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

### B.2 READY with warnings (2.6)

The differences from B.1 are the disk entry (`status: warn`, `bucket: warning`, a spec `fix`, a
`builtin_fix`), the summary, the verdict and the exit code. The full file:

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
    "id": "3b9d1f70-52c6-4a8e-8c13-7e0a5d2b9f41",
    "started_at": "2027-03-09T09:48:20.000Z",
    "finished_at": "2027-03-09T09:48:20.243Z",
    "duration_ms": 243,
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
  "verdict": "ready_with_warnings",
  "verdict_reason": null,
  "exit_code": 1,
  "summary": {
    "total": 5,
    "pass": 3,
    "warn": 1,
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
      "status": "warn",
      "bucket": "warning",
      "message": "12.0 GiB free on /, 20 GiB needed",
      "fix": "Free space on / or mount a larger volume.",
      "fix_source": "spec",
      "builtin_fix": "/ has 12.0 GiB free, 20 GiB needed. Run df -h /. Grow the volume or point the install at a larger disk.",
      "observed": {
        "path": "/",
        "mount": "/",
        "fstype": "xfs",
        "free_bytes": 12884901888,
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

### C.3 Dry run (M1 stretch)

Exit 0. Nothing is read from the host, no socket is opened, no folder is created. The list is the one the M3
`--allow-exec` consent shows.

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
`rdy run` would accept the file, with the same banner.

### C.5 Refusals (exit 64)

No verdict, no report. Two lines each. The strings are 01 section 4.8 and no line names `--allow-unsigned`
or `--key`.

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

$ rdy run acme-platform.yaml --keey acme-platform.pub
error: unknown flag --keey
fix: did you mean --key? See 'rdy run --help'.

$ rdy run acme-platform.yaml --jobs 0
error: --jobs must be 1 or more
fix: use a number from 1 to 32, for example --jobs 8

$ rdy run acme-platfrom.yaml
error: cannot read acme-platfrom.yaml: no such file
fix: check the file name and the folder you are in

$ rdy run acme-platform.yaml --token rdy_st_example
error: tokens on the command line show up in shell history and in ps
fix: use --token-file, the RDY_TOKEN variable, or the prompt

$ rdy run acme-platform.yaml
error: acme-platform.yaml:14:11: min is read as the number 1.3, but versions must be text
fix: write it with quotes: min: "1.30"
```

### C.7 The report folder cannot be created (exit 70)

Checked right after the spec is verified (ADR 0016), so no check runs. With `--json`, stdout holds an
ErrorOutput with code `report_write`.

```console
$ rdy run acme-quickstart.yaml --out-dir /usr/share
error: cannot create the report folder /usr/share/rdy-report-acme-quickstart-20270309T101502Z (permission denied)
fix: use --out-dir <a folder you can write to>, or --no-report to skip the files
```

### C.8 `rdy spec lint`

Exit 1 (two warnings, no errors). `--json` prints the LintReport in C.11.

```console
$ rdy spec lint acme-platform.yaml
acme-platform.yaml:45:9: warning: gpu.cuda: this version of rdy has no gpu checks yet
  fix: keep it for later. Until the check ships, set severity: warn, or customers will see NOT READY.
acme-platform.yaml:50:9: warning: aws.iam: this version of rdy has no aws checks yet
  fix: keep it for later. Until the check ships, set severity: warn, or customers will see NOT READY.

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
  fix: keep it for later. Until the check ships, set severity: warn, or customers will see NOT READY.
acme-platform.yaml:50:9: warning: aws.iam: this version of rdy has no aws checks yet
  fix: keep it for later. Until the check ships, set severity: warn, or customers will see NOT READY.
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

Exit 70, Ctrl-C from M2 (code `interrupted`):

```json
{
  "api_version": "rdy/v1",
  "kind": "Error",
  "error": {
    "code": "interrupted",
    "message": "stopped before the report was written. Nothing was saved.",
    "fix": "run rdy again, and press Ctrl-C only once to get a partial report"
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
      "fix": "keep it for later. Until the check ships, set severity: warn, or customers will see NOT READY."
    },
    {
      "level": "warning",
      "code": "not_in_build",
      "line": 50,
      "column": 9,
      "key": "aws.iam",
      "message": "aws.iam: this version of rdy has no aws checks yet",
      "fix": "keep it for later. Until the check ships, set severity: warn, or customers will see NOT READY."
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
## Plan corrections found

- docs/plan/10-devrel-and-launch.md, section 1 README draft, "What it looks like" and the skipped-required
  snippet: the transcripts differ from 2.5 to 2.7 and C.5 here. Lines to change:
  - The refusal block (`error: acme-quickstart.yaml has no signature.` and the `fix:` that names `--key` and
    `--allow-unsigned`): use C.5. No error or fix line may name either flag (01 section 4.7). The README
    prose around the block names `--allow-unsigned` and links `docs.getrdy.io/unsigned`.
  - The banner `WARNING: this spec is UNSIGNED. rdy cannot tell who wrote it.`: use the five-line banner of
    01 section 4.7 (shown in 2.7), and its first line again above the verdict.
  - The header (`rdy 0.1.0`, `spec`, `target ... 4 cpu 4.0 GiB`): use `rdy`, `spec`, `sig`, `host`, `user`,
    `proxy`. There is no cpu or memory in the header; the checks say it.
  - The check list: checks are sorted by bucket (blocks first), `host.disk` is now `host.disk/root` plus a
    `host.disk/system` SKIP ("Does not apply here. This check is for windows only."), and every problem has a
    `fix from ...:` line under it. The `Fixes:` block is gone.
  - Summary lines: `2 blocks, 1 warning, 1 passed` gets `, 1 not applicable`; the ready transcript's `4
    passed` becomes `0 blocks, 0 warnings, 4 passed, 1 not applicable`.
  - `Report written to ./rdy-report.html and ./rdy-report.json`: the report is a new folder with four files
    (three when the spec is unsigned), never overwritten. Quickstart step 4 ("overwrite the last run") is
    wrong, and "if it is not writable, rdy exits 70" happens before any check runs.
  - The skipped-required snippet: messages read `Not run. This version of rdy has no gpu checks yet.
    (required)`; the numbered `Fixes:` list becomes `fix from rdy:` lines; `NOT READY: 2 required checks were
    not run` is the last line only when no block was seen.
  - The Show HN sample and series posts must be regenerated from the golden files, not trimmed by hand.
  - "How it works": the words that carry meaning are PASS, WARN, BLOCK, SKIP, TIMEOUT and ERROR. The exit-64
    and exit-70 sentence should say exit 70 can print a result before the error.
- docs/plan/10-devrel-and-launch.md, tickets "Review and lint example specs" and "CI job: lint every example
  spec": `rdy spec lint examples/specs/acme-platform.yaml` exits 1 by design (two warnings, 01 section 2.5).
  Fix: CI treats 0 and 1 as pass and 2 and 64 as fail.
- docs/plan/01-spec-format.md section 5.4, 02-engine-design.md (Decisions, SEC-40), 04-bundle-and-redaction.md
  (section 7, Appendix F, tickets) and 05-threat-model.md (R1, SEC-40): `--plan`. Fix: `--dry-run` everywhere,
  as in ADR 0005, 00-overview.md and 10. One name for "show what this would do" on `run` and `bundle`.
- docs/plan/02-engine-design.md, Ctrl-C bullet and the cli-ux review ticket: confirmed. M1: Ctrl-C aborts,
  prints `error: interrupted. No report was written.` and exits 70; rdy also removes the report folder if
  nothing was written to it (add to the SEC-19 ticket). From M2: first Ctrl-C partial report, second exits 70.
  `--no-network` and `--out-dir` are confirmed. 02 already uses `--out-dir`.
- docs/plan/03-check-catalog.md (k8s intro, about line 261) and 04-bundle-and-redaction.md section 7: flags
  `--context` and `--namespace`. Fix: `--kube-context` (ADR 0010, 00-overview). `--namespace` belongs to
  `rdy bundle` in M2 only.
- docs/plan/01-spec-format.md section 4.8 and result schema `ErrorOutput`: two new codes, `spec_unreadable`
  (spec file missing, not a regular file, unreadable; exit 64) and `interrupted` (exit 70), both additive
  under ADR 0007. Also ADR 0008 decision 7 lists `report_write` as an error-object code, while 01 section 5.3
  and 02 print the Report with `complete: false` when a verdict exists. Fix: `report_write` is an
  ErrorOutput only when no verdict exists (`rdy report`, `rdy bundle`); with a verdict, stdout is the Report.
- docs/plan/01-spec-format.md and result schema `Run.options`: add optional `timeout_ms` (null unless
  `--timeout` is given), so a report shows that a customer changed the vendor's limits. Add a `Version`
  definition for `rdy version --json` (4.3).
- docs/plan/02-engine-design.md, Output and reports: "vendor fix text is labelled 'From <product>'". 01 section
  2.6 labels it with the product only when the signature is verified and the key pinned, else "From the spec
  file (not verified)" (the terminal does the same, 2.2). Fix: 02 follows 01. 02 also says the spec copies are
  `spec.yaml` and `spec.yaml.minisig`; the `Report written to` block lists those names.
- docs/adr/0003, decision 2: "a `Report written to <dir>` line". 01 section 5.5 says the line names all four
  files. Fix: the folder line plus the files indented under it (2.1). The ADR has no `<title>` rule; 01
  section 6 sets `rdy report: <product>, <VERDICT>`, which this file follows.
- docs/plan/00-overview.md, `rdy` crate paragraph: the `run` flag list lacks `--no-network` and `--progress`;
  commands lack `redact` (M2) and `completion` (M3); `spec lint --json` is M1 (LintReport is in the schema).
  `--timeout` replaces check and spec limits for the run (section 1 of this file).
- docs/plan/01-spec-format.md section 4.7 and 4.8: the fix line links `https://docs.getrdy.io/unsigned`. The
  planned page in 09-docs-site.md is `/specs/signing/`. Fix: serve `/unsigned` as a redirect or page by 0.1.0
  (ticket below).
- CLAUDE.md, Engineering standards: exit codes are listed but clap's own default for a usage error is 2,
  which this project reserves for NOT READY. Fix: add "clap usage errors are mapped to 64" and the test.
- docs/plan/01-spec-format.md section 5.3 ticket "Summary line grammar and nothing-verified last line": its
  samples are the ones in 2.4. Fix: the exit test also covers the `(1 timed out)` and `(1 failed)` suffixes.

## Decisions needing an ADR

- **Exit code for a hard stop by Ctrl-C.** Chosen: 70 ("rdy could not deliver its result"). Alternatives:
  130, the shell convention, which adds a sixth code to a set CLAUDE.md fixes at five. Amends the ADR 0008
  list of what exit 70 covers.
- **A declined `trust add` exits 64.** Chosen because a script chained with `&&` must stop when the key was
  not trusted. Alternative: exit 0 ("the user chose"), which lets a chain continue as if the key were
  pinned.
- **`--timeout` lets the customer replace the vendor's check limits (1 s to 60 s),** recorded in
  `run.options.timeout_ms`. Alternatives: lower only (a customer on a slow link cannot help), or no flag
  (00-overview lists it, so it stays). A longer limit can only turn a TIMEOUT into a real answer, never a
  false READY.
- **Pinning from the M2 share-link flow.** ADR 0002 decision 6 pins a served key on an explicit yes inside
  `rdy run`; the settled rule is that `run` writes no trust state. Conservative choice: `run` shows the
  fingerprint, offers "trust this key for this run only" with the KEY NOT PINNED banner, and prints the `rdy
  trust add` line to pin it. Alternative: a `[y/p/N]` prompt that pins.
- **`run --upload` in M2.** CLAUDE.md rule 2 says upload is an explicit flag or a prompt. Chosen: a flag that
  asks the same consent question as `rdy upload`, plus the verb. Alternative: the verb only, so `run` never
  contacts the portal after a run.

## Tickets implied

M1 total 51 hours, on top of the other slices. Cut order if M1 slips: `--dry-run`, the verbose event
lines, the `--progress` flag (keep auto), the HTML next-step sentences. Never cut: the exit-code suite, the
clap-to-64 mapping, the banners, the verdict as last line.

- [M1] Clap command tree, global flags and help text from 07 Appendix A | owner: rust-engineer | est: 4h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: snapshots of `-h`, `--help` and `help <command>` for every M1 command match Appendix A in wording, section order and examples, and bare `rdy` prints help on stdout and exits 0.
- [M1] Map clap usage errors to the error and fix form with exit 64 | owner: rust-engineer | est: 3h | depends on: Clap command tree, global flags and help text from 07 Appendix A | exit test: golden stderr for an unknown flag with did-you-mean, a missing argument, a bad value, `-q` with `-v`, and hidden `--token` and `--password` each exit 64 with `error:` and `fix:` lines, `--json` prints an ErrorOutput with code `usage`, and `--help` and `--version` exit 0.
- [M1] Terminal styling layer: colour choice, Unicode choice, width and escaping | owner: rust-engineer | est: 3h | depends on: Clap command tree, global flags and help text from 07 Appendix A | exit test: table tests cover the colour rules of section 6, `TERM=dumb`, the locale and Windows Unicode rules, and `COLUMNS` clamping, and a hostname holding an ANSI escape and a bidi override prints as `\x1b` and `\u{202e}`.
- [M1] Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | owner: cli-ux | est: 4h | depends on: Add `bucket` to CheckResult and sort by it in terminal and HTML; Terminal styling layer: colour choice, Unicode choice, width and escaping | exit test: golden stderr for B.1, B.2 and B.3 equals 2.5, 2.6 and 2.7 byte for byte at width 100 with `--color never`, and the last line is the verdict.
- [M1] Fix source labels, wrapping and banner placement in the run renderer | owner: cli-ux | est: 2h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict; SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | exit test: an unsigned run and a `--key` run label spec fixes "the spec file (not verified)", a pinned run labels the product, a 130-character message wraps at 100 with a hanging indent, and both banners print before the first check and again above the verdict.
- [M1] Progress line with indicatif, TTY only | owner: rust-engineer | est: 3h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | exit test: a pty capture shows one spinner line that is cleared before the check list, a 250 ms run draws nothing (paused-time test), and a pipe, `--quiet`, `--progress never`, `TERM=dumb` and `RUST_LOG` each produce zero progress bytes.
- [M1] Quiet and verbose output modes | owner: cli-ux | est: 2.5h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | exit test: golden stderr for C.1 (`--quiet`) and C.2 (`--verbose`), and `--verbose` prints one event line per finished check on a pipe.
- [M1] Ctrl-C in M1: abort, remove the empty report folder, exit 70 | owner: rust-engineer | est: 2h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation; SEC-19 Confine writes to a new output dir with safe names | exit test: a pty test sends SIGINT once and gets the two-line error of 5.1, exit 70, no report folder and no child process left, SIGTERM does the same, and `--json` prints an ErrorOutput with code `interrupted`.
- [M1] Exit-code golden suite for 0, 1, 2, 64 and 70 | owner: rust-engineer | est: 3h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict; Map clap usage errors to the error and fix form with exit 64 | exit test: assert_cmd runs one fixture per row of 5.1 and 5.2 (ready, warnings, not ready by a block, not ready by a required check not run, unsigned, bad flag, missing file, unwritable `--out-dir`) and compares exit code and stderr golden, and with `--json` validates stdout against the schema.
- [M1] `--json` stdout hygiene on every exit path | owner: rust-engineer | est: 2h | depends on: Exit-code golden suite for 0, 1, 2, 64 and 70 | exit test: for each exit path stdout is exactly one JSON document, equals the `.json` file where one exists, carries no ANSI under `--color always`, and `--no-report --json` still prints the Report.
- [M1] rdy version and rdy version --json | owner: rust-engineer | est: 1.5h | depends on: Clap command tree, global flags and help text from 07 Appendix A | exit test: golden stdout for both forms equals 4.3 and C.11 and `rdy --version` prints the first form.
- [M1] Prompt helper: y/N, no-terminal refusal and hidden input | owner: rust-engineer | est: 2.5h | depends on: Clap command tree, global flags and help text from 07 Appendix A | exit test: pty tests cover `y`, `yes`, `n`, empty and EOF, a missing TTY exits 64 with the fix line of C.10, and a password is read with echo off.
- [M1] Output for verify and spec lint, human and JSON | owner: cli-ux | est: 2h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner; rdy spec lint with errors, warnings and did-you-mean | exit test: golden output for C.4 and C.8, the Verification and LintReport JSON validate against the schema, lint exits 0, 1 and 2 on the clean, warning and error fixtures, and `verify --key` prints the KEY NOT PINNED banner and ends `VERIFIED, KEY NOT PINNED`.
- [M1] Output for spec keygen, spec sign and trust add, list and remove | owner: cli-ux | est: 2h | depends on: rdy spec keygen and rdy spec sign; rdy trust add, list and remove; Prompt helper: y/N, no-terminal refusal and hidden input | exit test: golden output for C.9 and C.10, the fingerprint prints in groups of four and matches `signature.key_fingerprint`, and a secret key given to `trust add` is refused with the fix of C.10.
- [M1] Refuse secrets on argv and read key passwords from env or file | owner: rust-engineer | est: 1h | depends on: Clap command tree, global flags and help text from 07 Appendix A | exit test: `--token`, `--password` and `--secret` exit 64 with the reason of C.6, and `RDY_KEY_PASSWORD` and `--password-file -` sign a spec in CI without a prompt.
- [M1] `--no-network`, `--timeout` and `--jobs` flags | owner: rust-engineer | est: 2.5h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: `--no-network` skips network and Kubernetes checks as `missing_need` with `run.options.network` false and no socket opened (`unshare -n` test), `--timeout 3s` ends a 10 s fixture at 3 s with `timeout_ms` 3000, `--jobs 500` prints a cap note, and `--jobs 0` exits 64.
- [M1] HTML report stylesheet: tokens, dark mode and print | owner: cli-ux | est: 3h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a script reads the CSS variables and fails any text or border pair under 4.5:1 in light, dark, dark-preferred print and light print, and the golden HTML for B.1 to B.3 matches.
- [M1] HTML report: next-step sentences, Found and Needed rendering and footer link | owner: cli-ux | est: 3h | depends on: HTML print override, labels and legend; HTML report stylesheet: tokens, dark mode and print | exit test: golden HTML carries the sentences of 8.2 by verdict, `_bytes`, `_ms` and `_percent` values print as sizes, milliseconds and percents, and the footer link has only `ref=report` and the product with `rel="noopener noreferrer"`.
- [M1] HTML structure test: headings, landmarks, tables and links | owner: cli-ux | est: 1.5h | depends on: HTML report: next-step sentences, Found and Needed rendering and footer link | exit test: a Rust test over the three goldens asserts heading levels never skip, `lang` is set, every `h3` has a status word, tables have `th scope`, ids are unique, and no `href` or `src` is anything but `data:`, the footer link or the repo link.
- [M1] rdy run --dry-run (stretch) | owner: cli-ux | est: 2h | depends on: Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | exit test: golden output for C.3, no report folder is created, no host file is read and no socket is opened (strace and `unshare -n` test), and `--dry-run --json` exits 64.
- [M1] Serve https://docs.getrdy.io/unsigned | owner: docs-writer | est: 1.5h | depends on: none | exit test: the URL in 01 section 4.8 returns the page on what `--allow-unsigned` and `--key` do and when not to use them, and the docs link check passes.
- [M2] Graceful first Ctrl-C with a partial report and the second-Ctrl-C message | owner: rust-engineer | est: 3h | depends on: Family limits and graceful Ctrl-C with a partial report | exit test: a pty test gets exit 2 with `interrupted` true after one SIGINT and exit 70 with the message of 5.1 after two.
- [M2] Share-link run output: fetch notice, key fingerprint question, upload offer above the verdict | owner: cli-ux | est: 4h | depends on: Opt-in upload client and share-link spec fetch | exit test: golden transcripts for a TTY yes, a TTY no and no TTY, each ending in the verdict, and `--no-network` fails with a fix.
- [M2] Output for bundle, upload, report and redact | owner: cli-ux | est: 4h | depends on: rdy bundle command, plan output and summary | exit test: golden output for the 04 Appendix F and section 6.2 samples with `--dry-run` in place of `--plan`, and each command's exit codes match section 5.
- [M2] JSON for trust list and the dry-run plan | owner: rust-engineer | est: 4h | depends on: rdy run --dry-run (stretch) | exit test: both outputs validate against new schema definitions and the stable-output promise of 4.4 lists them.
- [M3] rdy completion and man pages from the clap tree | owner: rust-engineer | est: 4h | depends on: Clap command tree, global flags and help text from 07 Appendix A | exit test: `rdy completion <shell>` output sources cleanly in bash, zsh, fish and PowerShell CI jobs, `cargo xtask man` writes one page per command, and the release archive holds `completions/` and `man/`.
- [M3] rdy spec init and rdy self-update output | owner: cli-ux | est: 4h | depends on: Signed self-update | exit test: golden output for init (refuses overwrite without `--force`) and for update, decline, check-only and a refused tampered release, each with the exit codes of 12.
