# Review of 07-cli-ux.md by code-reviewer

Reviewer: code-reviewer (cold review, did not write 07). Date: 2026-10-28. Reviewed: docs/plan/07-cli-ux.md
as of 2026-10-28, against CLAUDE.md, KICKOFF item 8, 01-spec-format.md, 02-engine-design.md revision 3,
03, 04, 05, ADRs 0002, 0003, 0008, 0011, 0013, 0016, `crates/rdy-spec/schema/result.v1.schema.json` and
`.claude/agents/cli-ux.md`.

## Verdict

**Request changes.** 3 must fix, 17 should fix, 20 nits.

The doc is strong. It covers KICKOFF item 8 in full: every M1 command and flag, help text, ready, warning
and blocked samples, JSON samples, exit codes, colour, no colour and accessibility. The verdict rule, the
summary-line grammar, the last-line forms, both banners and the skip wording match 01, ADR 0008 and ADR
0013 exactly. All three must-fix items are contract contradictions. Each is a few lines to fix.

## What I checked, and how

- **JSON samples: validated by machine.** I ran `python3 -I` with jsonschema 4.26.0 (Draft 2020-12, with
  FormatChecker) on every fenced `json` block. B.1, B.2 and B.3 pass as `Report`. The three ErrorOutputs
  pass, and so do the LintReport and the Verification. `rdy version --json` has no schema definition, so
  I could not validate it (07 already asks for one). A second script recomputed the bucket, summary,
  verdict, `verdict_reason` and fix rules of 01 5.2 and 5.3 for B.1 to B.3. All match. `interrupted` and
  `spec_unreadable` pass only because `OpenCode` is open. The schema's code list does not name them yet.
- **Samples against 01, ADR 0008 and ADR 0013.** I checked the required timeout, the `missing_need` and
  `not_in_build` skips, the optional skip in the warnings bucket, `(1 timed out)`, the plain `NOT READY`
  after a block, both banners (byte for byte with 01 4.7) and the banner's first line above the verdict.
  I also checked fix labels "from the spec file (not verified)" and 01 5.2's skip messages and fixes.
  All correct.
- **Example specs.** The SHA-256 and size of `examples/specs/acme-quickstart.yaml` and `acme-platform.yaml`
  match B.1 and B.3. The lint positions 45:9 and 50:9 match the file.
- **Widths.** Every help line in Appendix A is 80 columns or fewer. Every check-list line in 2.5 to 2.7 and
  C.1 is 100 or fewer, with the fix indent at column 29 as the layout rule says. Error lines exceed 100
  by design (rule: they never wrap).
- **Contrast.** I recomputed every WCAG ratio in 8.4. All of them match the table.
- **Hours.** The M1 tickets sum to 51 h, as stated.
- **House rules.** No em dashes and no competitor names in 07.

## Must fix

1. **Must fix. 4.1 (line 343), 5 (lines 424 to 427), ticket "`--json` stdout hygiene on every exit
   path".** *Problem:* 07 says that when the watchdog fires, stdout under `--json` holds the Report with
   `complete: false`. 02 (Scheduling, MF-02) and ADR 0016 decision 6 forbid that. The watchdog never takes
   the stdout lock. It writes only through the held output directory, and the "blocked stdout pipe" test
   requires exit 70 anyway. So the promise cannot be kept, and the hygiene ticket's exit test ("stdout is
   exactly one JSON document on each exit path") would fail on that path. *Fix:* in 4.1, split the row.
   For "files not written at the end", stdout gets the Report with `complete: false`. For "watchdog
   fired", stdout may be empty or cut short. The JSON with `complete: false` is in the report folder, and
   with `--no-report`, or before the folder exists, there is none. Exclude the watchdog path from the
   hygiene ticket's "exactly one document" assertion and add "empty stdout plus exit 70 means look in the
   folder" to the 4.2 promise.

2. **Must fix. 1 Flag rules (line 95), 9 rule 7 (lines 662 to 665), C.6 (lines 2470 to 2472), 9 table
   row 3, ticket "Map clap usage errors...".** *Problem:* the rule "a did-you-mean is not a hint"
   contradicts 01 4.7. That rule says no hint, fix line or error message ever names `--allow-unsigned` or
   `--key`, and security wins (01 4.8 note). It also fails in practice. At edit distance 2, `--yes` (an M2
   flag that users will try on `run` in M1) suggests `--key`, so a user who never chose `--key` is taught
   it. The suggestion also lands in `ErrorOutput.fix`. *Fix:* the suggester never proposes
   `--allow-unsigned` or `--key`. For those, print `error: unknown flag --keey` and `fix: see 'rdy run
   --help'`. Implement the suggester yourself with `strsim` Levenshtein over the visible flags, because
   clap's built-in suggestion uses Jaro similarity, not edit distance. Add an exit test: `--keey`,
   `--yes`, `--allow-unsgned` and `--kye` never put either flag name in stderr or `ErrorOutput.fix`.
   Reword C.5's "no line names `--allow-unsigned` or `--key`" to "`run --key`": the `trust add ... --key`
   line in that block is allowed, and as written the sentence is false.

3. **Must fix. 1 (line 77), A.3, "Decisions needing an ADR" item 3, ticket "`--no-network`, `--timeout`
   and `--jobs` flags".** *Problem:* the line "Replaces check and spec limits" contradicts 01 2.3 and
   02 Scheduling, where the spec value wins over the check default. It also hands the customer a knob over
   the vendor's settings. A vendor who sets `timeout: 5s` to match its installer's own limit gets a
   READY from a path that needs 30 s. The claim "never a false READY" holds only if no vendor ever uses
   `timeout` that way. The ticket's exit test needs `run.options.timeout_ms`, which is not in the schema,
   and no ticket adds it. *Fix (recommended):* drop `--timeout` from M1, because nothing in M1 needs it.
   In M2, add it with a guard. It may lower any limit. It may raise only limits the spec did not set
   (check defaults), never a `timeout` the vendor wrote. `run.options.timeout_ms` goes into the schema
   (revision 0 if it lands before 0.1.0). The header prints `limits  20 s per check (set by --timeout)`
   and the HTML details show it, so the SE reading the report sees it. Parse it with the 01 Duration
   grammar, so a bare `20` is a usage error, matching the spec. Record the decision in 01 2.3 and in 02
   Scheduling.

## Should fix

1. **Should fix. 9 rule 8, C.6, ticket "Map clap usage errors...".** *Problem:* no rule stops a usage
   error from echoing a secret value. A typo such as `--tokne=rdy_st_...` or `--pasword hunter2` reaches
   clap's UnknownArgument path, whose default text includes the token as typed. The hidden-flag trick
   only covers the exact names. *Fix:* add a rule. Usage errors print the flag name only, never the part
   after `=` or the next argv item, unless the flag is known and non-secret. Add exit tests with canaries
   in `--tokne=` and `--pasword` that are absent from stderr and from the ErrorOutput.

2. **Should fix. 1 (line 58), tickets "Clap command tree..." and "Map clap usage errors...".** *Problem:*
   the exit-64 override is real, but it has two traps. (a) Bare `rdy`, `rdy spec` and `rdy trust` with
   `arg_required_else_help` raise `ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand`, which clap
   prints to stderr with exit 2. A blanket "error means 64" mapping turns that into 64, which contradicts
   07's "help on stdout, exit 0". (b) Any `Parser::parse()`, `get_matches()` or `Error::exit()` call
   anywhere still exits 2. *Fix:* use `try_parse_from`. Map `DisplayHelp` and `DisplayVersion` to stdout
   and exit 0, and `DisplayHelpOnMissingArgumentOrSubcommand` to help on stdout and exit 0. Map every
   other kind to the two-line form and exit 64. Add `clap::Parser::parse`, `clap::Command::get_matches`
   and `clap::Error::exit` to clippy `disallowed-methods`. Say how `--json` is detected when parsing
   fails: scan raw argv for a literal `--json` before `--`.

3. **Should fix. 2.1 Tip line (lines 103 and 104).** *Problem:* "Run rdy as root to include them",
   together with 01's `Rerun as root: sudo rdy run ...`, sends a user whose key is pinned in the user
   store straight into `spec_key_unknown`. As root, rdy reads only `/etc/rdy/trust.yaml` (ADR 0002
   decision 4). *Fix:* when `trust_source` is `user`, the Tip adds `First trust the vendor key for root:
   sudo rdy trust add <product> --key <file>`. Add a golden test for it. Raise the same line against 01
   5.2's root fix.

4. **Should fix. C.8, C.9, C.11 lint fix text.** *Problem:* the fix "set severity: warn, or customers will
   see NOT READY" tells vendors to downgrade a required check they cannot yet run. A `-le 1` gate then
   passes an environment where CUDA or IAM was never checked. That is the exact case 5's "a gate that
   accepts 0 and 1 never passes an unchecked environment" rules out. *Fix:* use neutral text, for example
   `fix: customers will see this check as not run, and NOT READY while it is required. Keep it if that
   is what you want.`

5. **Should fix. 1 (line 79), 2.8, C.3, ticket "rdy run --dry-run (stretch)".** *Problem:* three issues.
   (a) "Reads no host file" is false: the privilege snapshot reads `/proc/self/status` and `auxv` (02),
   and verification reads the trust store, so the strace exit test cannot pass. (b) It duplicates M2
   SEC-40 (6 h, "matches the action log of a real run") and 10's identical stretch ticket. (c) It creates
   a second output format before ADR 0005 binds `--allow-exec` consent to that exact list. *Fix:* move it
   to M2 and merge it into SEC-40 under the name `--dry-run`. Delete 10's duplicate ticket. Reword the
   claim to "reads only rdy's own process state and the trust store".

6. **Should fix. 8.1 nav (line 543) against the 8.6 structure test and ticket "HTML structure test".**
   *Problem:* the test forbids every `href` except `data:`, the footer link and the repo link, so the
   in-page "Jump to" links fail it. *Fix:* allow `href="#<id>"` where the id exists in the document, and
   assert each target exists.

7. **Should fix. 8.1 (line 535).** *Problem:* 07 puts the banner above the header. 01 section 6 puts it
   second, after the header, while 01 4.7 says "at the top". 07 picks the 4.7 reading but does not record
   that it deviates from the contract. *Fix:* keep the banner first, because it matches the terminal, and
   add a plan correction: 01 section 6 item 2 moves above item 1.

8. **Should fix. Plan corrections (lines 2794 to 2797).** *Problem:* 02 line 175 proposes the headline
   `NOT READY: 1 blocker, 2 required checks not run`, and 02's cli-ux ticket asks 07 to confirm it. 07
   uses plain `NOT READY` plus the summary line (correct per 01 5.3) but never answers 02. *Fix:* add a
   bullet. 02 Verdict "Headline" is rejected, and the last line is 01 5.3's table.

9. **Should fix. 10 (lines 693 to 707).** *Problem:* the claim "rdy reads no other variable for
   behaviour" is false. Section 6 reads `WT_SESSION` and `TERM_PROGRAM`, the Windows default output folder
   uses `USERPROFILE` (line 73), and the kube client reads `HOME` for `~/.kube/config`. *Fix:* add them to
   the table, and add a test that runs with an empty environment plus each listed variable.

10. **Should fix. 2, 4.2 (lines 386 and 387).** *Problem:* there is no terminal sample for the
    no-block `NOT READY: 3 required checks were not run`. That is the week 2 alpha's real output (ADR
    0008 Consequences), so it is the first golden anyone sees. There is also no sample for `READY with
    warnings: nothing was checked`, and none for a run with `--key` (KEY NOT PINNED in a run, not
    `verify`). *Fix:* add three short samples to Appendix C. Each is about 10 lines, and each becomes a
    golden in the renderer ticket.

11. **Should fix. 8 (HTML), 9 rule 9.** *Problem:* the terminal escapes bidi controls, but the HTML
    only HTML-escapes, and 01 6 strips control characters. U+202A to U+202E and U+2066 to U+2069 are
    format characters, not control characters, so a hostname or vendor `fix` can reorder visible text
    in the report. *Fix:* the HTML renders untrusted strings inside `<bdi>` and shows bidi controls as
    `\u{202e}`, the same as the terminal. Add the bidi case to the structure test.

12. **Should fix. 5 (lines 426 and 427).** *Problem:* the watchdog's message puts `error:` and `fix:` on
    one line. That breaks section 9 ("two lines at column 0") and the 4.2 promise that scripts can rely
    on the `fix:` prefix. *Fix:* use one constant buffer with two lines, written in a single non-blocking
    `write`.

13. **Should fix. 7 and 8.6 (lines 621, 638 and 639).** *Problem:* "200% zoom and 320 px without
    sideways scroll" and print layout are checked only by a manual step, so the accessibility claims are
    not testable. *Fix:* ADR 0003's ticket already runs a headless browser. In that job, assert
    `scrollWidth <= 320` at a 320 px viewport, and render print media with dark preferred. Keep the
    manual PDF look as a release checklist item.

14. **Should fix. 8.2 (lines 571 to 574).** *Problem:* for `nothing_verified`, the HTML says "Nothing
    blocks the install. Read the warnings." when there may be no warnings, only checks that do not apply.
    *Fix:* add a sentence for that case: "rdy checked nothing on this machine. Every check in the spec is
    for another OS. Ask the vendor if that is expected."

15. **Should fix. A.4, C.4.** *Problem:* the help says "Exit 0 means 'rdy run' would accept this file
    with no override", but `verify --key` exits 0 only because of an override. *Fix:* reword it as "with
    the same --sig and --key".

16. **Should fix. Tickets implied.** *Problem:* many tickets overlap work that other docs already count,
    so the 51 h is partly double-counted and 11-backlog cannot dedupe by title:
    - "Map clap usage errors" overlaps 00's "Error types with fix hints and exit code mapping at the CLI
      edge".
    - "Fix source labels..." overlaps SEC-59.
    - "HTML report stylesheet" overlaps "askama HTML report with inline CSS, dark mode and print" and
      01's "HTML print override, labels and legend".
    - "Output for verify and spec lint" overlaps 01's lint and verify tickets.
    - "Output for spec keygen, spec sign and trust" overlaps ADR 0002's tickets.
    - "rdy version" overlaps ADR 0011's "Package rdy..." ticket.
    - The dry-run ticket overlaps 10's ticket.
    - The 08 dependency title "clap command tree in rdy-cli exposed as library rdy_cli" differs from
      07's title.

    *Fix:* turn each into "extends <title>: adds <output goldens>" with the extra hours only, and align
    the titles.

17. **Should fix. M1 hours and doc length.** See the two sections below. Cut M1 to about 31 h, and bring
    the body to about 4,000 words.

## Nits

1. **7 item 1 (line 509).** "tail -n 1 always gives it" is false on exit 70. Add "except on exit 70".
2. **8.1 nav.** "Warnings (2)" sits next to the summary's "1 warning", because the bucket counts
   optional checks that did not run. Label it "Warnings and optional checks not run (2)".
3. **8.6 (line 629).** "The footer holds one link" conflicts with the repo link in 8.1 and in the test.
   Say "two links".
4. **12 and Plan corrections.** "04 Appendix F" and "04 section 6.2" do not hold the bundle output or
   `--plan` (Appendix F is streaming, and 04 has no 6.2). 04 section 7 has no `--context`. 05 lines 344
   and 345 (proposal `--context`) are not closed. Fix the references and add 05 to the `--kube-context`
   bullet.
5. **A.11.** `trust list` can exit 64 (`trust_store_insecure`, section 5). Add it.
6. **6 Windows (line 504).** "Paths print as typed (`.\rdy-report-...`)" does not fit the Windows default,
   which is `%USERPROFILE%\rdy-reports`. Show the absolute path in a Windows line.
7. **6 (lines 496 and 497).** The console code page check needs `GetConsoleOutputCP` through FFI, and the
   crate forbids unsafe code. Drop it: ASCII unless `WT_SESSION` or `TERM_PROGRAM=vscode` is set.
8. **6 Symbols.** The Unicode "…" row contradicts "Unicode for one thing" and section 3's `...`. Delete
   the row.
9. **A.1 to A.12.** The global `-q` and `-v` help ("problems and the verdict", "every check") is wrong
   on `version`, `trust` and `keygen`. Use neutral text: "Print less" and "Print more".
10. **A.2, A.3.** The exit 70 line reads "Internal error, or the report could not be written". Add "or
    the run was stopped".
11. **4.2 item 2.** Say that `exit_code` is the verdict's code (the schema pins it to 0, 1 or 2) and can
    differ from the process exit when `complete` is false.
12. **Ticket "`--no-network`...".** `unshare -n` proves no reachability, not "no socket opened". Assert
    zero `socket(2)` calls with `strace -f -e trace=socket`, plus no `connect` entries in the action log.
13. **1.** `--no-network` with `--kube-context` or `--kubeconfig`: say what happens. A note line is
    better than exit 64.
14. **8.1 against 01 section 6.** 01 shows "Spec revision N" in the header, and 07 shows it only in the
    details. 01 labels a required skip "required by acme-platform" when verified, and 07 always says "the
    spec file". Pick one and record it as a plan correction.
15. **8.5.** A `position: fixed` banner in print overlaps content unless the body reserves the space.
    Add print `padding-top` equal to the banner height.
16. **C.10.** When a secret key's text was passed on argv to `trust add --key`, the refusal should add
    "It is now in your shell history. Make a new key pair."
17. **New crates.** indicatif (pulls console), anstream, unicode-width and strsim need a line each under
    the 05 dependency policy and `cargo deny`. List them in 07.
18. **Schema additions.** `spec_unreadable`, `interrupted`, `timeout_ms` (if kept) and `Version` should
    land in the schema and in the ErrorOutput code description before 0.1.0, so they are revision 0 with
    no rdy-spec bump. Say so.
19. **2.7 against C.4.** The same bytes (`231d161a...`) are unsigned in one sample and signed in the
    other. Add one clause saying they are different machines.
20. **7 item 8.** Drop "so a catalog can be added later". The goldens already guard the text, and no
    abstraction is needed.

## Decisions the reviewer was asked to make

**Ctrl-C exit: 70, not 130.** I agree with the author.
- CLAUDE.md and the brief fix the code set at five values. 130 is a sixth code that every gate script
  must learn.
- Windows has no 128+n convention.
- 70 already means "rdy could not deliver its result" (ADR 0008 decision 4).
- With `--json`, `error.code: interrupted` tells it apart from a crash.

The cost is that an interactive `for` loop in bash keeps going after Ctrl-C, because rdy exits normally
instead of dying by signal. State that on the docs exit-codes page ("a loop should stop on 70"). Do not
re-raise SIGINT, because that yields 130. 07 is consistent with 02 for M1: abort, kill child groups,
exit 70. Removing the empty folder is a small, safe addition to SEC-19, because `remove_dir` only removes
an empty directory.

**`--timeout`:** see must fix 3. Cut it from M1. In M2 it may lower any limit and raise only defaults,
and every report records it.

**`--no-network`, `--out-dir`, `--dry-run` and `--kube-context`** are consistent with 02, ADR 0016 and
ADR 0010, apart from must fix 1, should fix 5 and nit 4.

**HTML brief against ADR 0003 and 01 section 6:**
- Single file: yes.
- Embedded JSON with `data-sha256`: yes.
- Blockers first: yes.
- Print light: yes.
- Dark mode by `prefers-color-scheme`: yes.
- 5 MiB cap with the action table cut first: yes.
- Footer link with only `ref=report` and the product, plus `noopener noreferrer`: yes. Counting clicks
  on getrdy.io's own analytics is within ADR 0003 decision 8, because the report itself loads nothing.
- Gaps: should fix 6, 7, 11 and 13.

**Open ADR items listed by the author:**

| Item | Needs | Why |
| --- | --- | --- |
| Ctrl-C exit 70 | One-line amendment to ADR 0008 decision 4 | Adds a case to an existing list |
| Declined `trust add` exits 64 | One line in ADR 0002 decision 5 | Same rule as "no TTY and no `--yes`" |
| `--timeout` replaces limits | One-line decision in 01 2.3 and 02, with security sign-off, after the guard above | Not an architecture choice |
| Share-link pinning (M2) | ADR 0002 amendment | Decision 6 ("pinned on an explicit yes") conflicts with its own alternatives row ("pinning from run" lost). Security-relevant. Due before M2, not M1 |
| `run --upload` (M2) | One-line decision in 04 section 7 | CLAUDE.md rule 2 already allows an explicit flag. It must use the same consent prompt as `rdy upload` |

## M1 cut: 51 h to about 31 h

Keep in M1, in hours:
- clap tree and full help for `rdy`, `run` and `verify`, compact help elsewhere: 3
- clap errors mapped to 64, merged with 00's error-mapping ticket: 3
- styling (colour rules, width, escaping, ASCII only): 1.5
- run renderer: 4
- labels and banners, folded into SEC-59: 1.5
- a static `Running 8 checks...` line on a TTY instead of a live line: 0.5
- Ctrl-C: 2
- exit-code suite including `--json` stdout hygiene: 3.5
- `version --json`, folded into ADR 0011's ticket: 1
- prompt helper: 2
- verify and lint goldens: 1
- keygen, sign and trust goldens: 1
- `--password` refusal, `RDY_KEY_PASSWORD` and `--password-file`: 1
- `--no-network` and `--jobs`: 1.5
- contrast script and tokens: 1.5
- Found and Needed rendering and the footer: 2
- HTML structure test: 1.5

Total about 31.5 h. The `/unsigned` page (1 h) stays in the docs-writer slice.

Move to M2:
- the live progress line, `--progress` and `RDY_PROGRESS` (3 h)
- `--quiet` and `--verbose` (2.5 h; `RUST_LOG` covers debugging)
- `--timeout` with the guard
- `--dry-run`, merged into SEC-40
- Unicode spinner detection
- the HTML next-step sentences (keep 01's legend and rule in M1)
- hidden `--token` and `--secret`, together with the token work

The "never cut" list stays as written.

## Doc length

The body before Appendix A is about 8,000 words, and the file is about 18,400 words. The brief targets
a 15-minute read. Move the following to appendices or pointers:
- the ten before-and-after rows of section 9, to Appendix C
- the 4.1 error code table, which repeats 01 4.8 (replace it with a pointer)
- the Unicode and Windows detail of section 6, and 8.4 to 8.6 tokens and tests, to a new Appendix D
- sections 11 and 12 (M2 and M3), to Appendix E
- section 3's "Rules for the code", into its ticket
- section 5's 64 and 70 prose, into a two-column table

In Appendix A, print the global options once instead of eleven times (about 120 lines). B.2 should be a
diff against B.1 (about 330 lines), since the goldens are generated anyway. The README line-by-line
corrections for 10 belong in a review of 10, with a one-line pointer left here. Target: a body of about
4,000 words.
