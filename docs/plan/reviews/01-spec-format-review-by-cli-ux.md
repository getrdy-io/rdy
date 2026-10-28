# Review of 01-spec-format.md and the rdy/v1 schema files, by cli-ux

Reviewer: cli-ux. Date: 2026-10-28. Reviewed cold. No reviewed file was edited.

Read: `docs/plan/01-spec-format.md` (all), `crates/rdy-spec/schema/spec.v1.schema.json`,
`result.v1.schema.json`, `schema/README.md`, `examples/specs/*.yaml`, ADRs 0001, 0002, 0003, 0007, 0008,
0011, and my own `adr-and-00-review-by-cli-ux.md` (the command names and the pinning flow stay as settled:
`rdy trust add` pins, `rdy run --key` is one run, no `--trust-key`).

Mechanical checks:

- Em dashes and en dashes in the doc and both schema files: none.
- Competitor names: none found (grepped the category terms). The old working name: not seen on a read.
- I validated the five example specs against `spec.v1.schema.json` with a 2020-12 validator, and both
  result samples in section 7 against `result.v1.schema.json`. Results are in "Example specs" below.
- `docs/plan/07-cli-ux.md` does not exist yet. This doc defers several outputs to it (summary line,
  sign flags). The wording in this review is what I will put in 07, so the doc can adopt it now.

## Verdict

**Request changes.** Six must-fix items, all short edits to text and schema. The structure is right: the
tagged union with a skip fallback, the verdict rule, the signature flow, the `fix` override and the HTML
contract are all sound and match my earlier review. What is missing is the words the user reads when
something is wrong, a way for every reader of the JSON to sort blockers first, and a few labels in the
HTML that are engine vocabulary. After the six land, approve with the should-fix list as follow-up tickets.

Answers to the questions asked, one line each:

| Question | Answer |
| --- | --- |
| Easy to write by hand? | Mostly. Field names are plain (`min`, `fix`, `severity: block|warn`). Six names or behaviours trip a vendor (S1 to S5, S7). |
| Bad-spec errors each have a fix? | Signature, unpinned key and expiry do. Unknown key, unknown id and wrong value do not. M1. |
| `--allow-unsigned` banner? | Clear and calm. Keep it. Two small edits (N1). |
| Verdict rule understood at a glance? | The rule and the exit codes yes. The summary line does not cover optional or not-applicable checks, and "nothing verified" has no words. M6. |
| Result JSON complete for terminal and HTML? | Nearly. Durations, fix text, needs met and measured values are there. No ordering key. M3. |
| `--json` stable? | The rules are right (additive only, open enums). The doc never tells a script author what to rely on. S6, S7. |
| HTML consistent with ADR 0003? | Yes on order, CSP, escaping, dark mode. Print in dark mode is a bug waiting (M4). Three extras need an ADR edit (S9). |
| Examples match the schema? | Two fail, as the author says. Exact edits below. |

## Ranked findings

### Must fix

**M1. 2.5, 2.6, 5.2: most bad-spec messages have no fix, and the skip fixes talk to the wrong person.**
Problem. Section 4.8 gives a first line and a `fix:` for signature, key, expiry and trust-store errors.
Spec errors get less:

- Unknown top-level key (2.5): "field `x` is not part of rdy/v1 as rdy 0.1.0 knows it. It may need a newer
  rdy." No line or column, no did-you-mean, no `fix:` line. "rdy/v1 as rdy 0.1.0 knows it" is jargon.
- Unknown check id and unknown field (5.2): the fix text is written for the vendor ("It is a typo, or it
  needs a newer rdy"). On a run, the reader is the customer. They cannot fix a vendor typo. The line must
  say who acts.
- Wrong value type: 2.6 says `32G` is "rejected with use 32Gi" and ADR 0001 says an unquoted `1.30` is
  "rejected". 2.5 says the same inputs make the check `skipped` with `unsupported_spec`. These disagree.
  And the skip text names only unknown fields, not bad values.
- Missing `id`, duplicate entry keys, bad product slug, malformed `expires`: "exit 64, line and column"
  and nothing else.
- "This rdy build has no gpu checks" (7.2 sample): "build" is jargon for a customer.

Fix. Settle the contradiction: a bad value in a known check **skips that check at run time** (so a newer
spec on an older rdy fails closed, as 2.5 says) and is an **error in `spec lint` and `spec sign`** (M2).
The skip carries the parser's reason. Then add this table to 2.5 and 4.8 as the specified wording. All
`error:` lines carry `file:line:col:` where known. `fix:` is always present.

Exit 64 (spec_invalid, spec_parse), same text in `lint` with `error:` or `warning:`:

| Case | First line | Fix line |
| --- | --- | --- |
| Unknown top-level key | `error: acme-platform.yaml:3:1: unknown key 'metdata'` | `fix: check the spelling (did you mean 'metadata'?). If it is right, this spec needs a newer rdy than 0.1.0. Install the latest and run again.` |
| Unknown key in `metadata` or `bundle` | `error: acme-platform.yaml:6:3: unknown key 'prodcut' in metadata` | same fix line |
| `apiVersion` is `rdy/v2` | `error: acme-platform.yaml:1:13: this spec is for rdy/v2. rdy 0.1.0 reads rdy/v1 only.` | `fix: install the latest rdy.` |
| `apiVersion` missing or wrong group | `error: acme-platform.yaml:1:1: apiVersion must be rdy/v1` | `fix: add 'apiVersion: rdy/v1' as the first line.` |
| Entry has no `id` | `error: acme-platform.yaml:18:5: check 3 has no id` | `fix: add an id such as 'id: host.memory'.` |
| Same id twice | `error: acme-platform.yaml:31:5: two checks are named host.disk` | `fix: give each one a name, for example 'name: data'. The name is only a label.` |
| Bad product name | `error: acme-platform.yaml:15:12: 'Acme Platform' is not a valid product name` | `fix: use lowercase letters, digits and hyphens, such as 'acme-platform'.` |
| Bad `expires` | `error: acme-platform.yaml:16:12: expires must be a full UTC time` | `fix: write it like 'expires: 2027-01-31T00:00:00Z'.` |
| Too many checks or endpoints | `error: acme-platform.yaml: 257 checks. The limit is 256.` | `fix: split the spec in two, or remove checks.` |

A bad value, a typo in a known check, an unknown id. Lint and sign show `warning:` / `error:` (see M2). A
run shows the check as `SKIP`. Specified `message` (one line) and `fix` per skip kind:

| `skip_kind` | `message` | `fix` (written for the customer) |
| --- | --- | --- |
| `not_in_build` | `Not run. This version of rdy has no gpu checks yet.` | `Install a newer rdy. If there is none yet, ask the vendor how to go on.` |
| `unknown_check` | `Not run. rdy 0.1.0 does not know the check 'host.memroy'.` | `Tell the vendor. The spec may have a typo (did you mean 'host.memory'?), or it may need a newer rdy than 0.1.0.` |
| `unsupported_spec`, unknown field | `Not run. rdy 0.1.0 cannot read 'mn' in host.memory.` | `Tell the vendor. The spec may have a typo (did you mean 'min'?), or it may need a newer rdy than 0.1.0.` |
| `unsupported_spec`, bad value | `Not run. 'min: 32G' in host.memory is not a size.` | `Tell the vendor to write 32Gi, not 32G. Sizes use Ki, Mi, Gi or Ti.` |
| `missing_need` (root) | `Not run. This check needs root.` | `Rerun as root: sudo rdy run acme-platform.yaml` |
| `missing_need` (cluster) | `Not run. No Kubernetes cluster was reachable.` | `Set a kubeconfig, or pass --kube-context <name>, then run again.` |
| `not_yet_on_os` | `Not run. This check does not work on macOS yet.` | `Run rdy on the machine you will install on.` |
| `not_applicable` | `Does not apply here. This check is for linux only.` | none |
| timeout (status) | `Timed out after 10 s.` | `Run again. If it times out again, tell the vendor which check it was.` |

Drop "mark this check as warn" from `not_in_build`. A customer does not know what `warn` means and the
text invites them to ask for a weaker requirement. The `did you mean` part appears only when the edit
distance is small; otherwise the sentence ends after "a typo".

Add one sample of each non-pass outcome to section 7 (a new 7.4 with the check JSON for a missing-need
skip, a timeout, an unknown check and a not-applicable). Today both samples show only pass, block, warn
and `not_in_build`, which are the easy cases.

**M2. 2.5 open question: `spec sign` must refuse typos in known checks.**
Problem. As written, `spec sign` signs a spec that contains `mn: 32Gi`, `min: 32G` or `severity: blok`
(lint only warns). Every customer then sees a required check skipped and the run ends NOT READY, from a
file with a valid signature, and nobody on the customer side can fix it. The author asks whether sign
should refuse. It should.
Fix. Answer in 2.5: `spec sign` and `spec lint` (as errors, exit 2) treat as
**errors**: `unsupported_spec` (unknown field or bad value in a known id) and `unknown_check` in a family
this rdy builds. They treat as **warnings**: `not_in_build` (a check from a family a later rdy will add),
the deprecated `needs` alias (S1), thresholdless checks (S5). One more change makes this work: ship a list
of **reserved ids** in `rdy-spec` (every id in the catalog, built or not), so `host.kernel`,
`host.cgroups` and `host.time_sync` are `not_in_build`, not `unknown_check`. Today they would show "does
not know host.kernel, did you mean...", which is wrong for an id the vendor spelled correctly. `lint`
exits 0 with no findings, 1 with warnings only, 2 with errors, and 64 for usage, the same as `run`. Say
so in 4.5 step 1.

**M3. 5.2, schema `CheckResult`: no ordering key, so every reader re-derives "blockers first".**
Problem. `checks` is in spec order. The terminal, the HTML and the portal each need blocks, then required
checks not run, then warnings, then passes, then not applicable (ADR 0003 decision 6). The rule needs
`severity`, `status` and `skip_kind`, with unknown severity meaning block and unknown status meaning not
run. Three implementations will drift. Customers also want it in `jq`: "show me what to fix first".
Fix. Add a required field to each check result, computed by the same function as the verdict:
`"bucket": "blocker" | "required_not_run" | "warning" | "passed" | "not_applicable"` (open enum). Warn
checks that did not run sit in `warning`, as 6.4 says. The renderers sort by bucket order, then spec order.
Add `bucket` to `CheckResult.required` and to both samples in 7.2 and 7.3. The summary counts then equal
the bucket counts, and a test asserts it. Document in 5.2: "Sort by `bucket` in the order above. Do not
recompute it."

**M4. 6 (print and dark mode): print in a dark browser will be unreadable.**
Problem. 6 says print has "no backgrounds" and also that `prefers-color-scheme` drives dark mode with
`color-scheme: light dark`. Some browsers carry the dark text colour into print. Light text on a white
page is blank. A change board prints this file. The banner "repeated on every page" is also not a thing
CSS does without `position: fixed` in print.
Fix. Add to 6: "`@media print` sets `color-scheme: light`, black text on white, whatever the screen theme.
The unsigned banner is a `position: fixed` block in print so it repeats on each page. Page breaks come only
before Passed, Capabilities and the action log, so the verdict, the blocks and the required checks not run
share page one." Add to the HTML exit test: render with dark preferred and print media, assert text colour
and background contrast at least 4.5 to 1. Dropping the page break before every section also keeps a
small report to two pages.

**M5. 6 (content list): labels are engine vocabulary.**
Problem. Section 6 names what the page shows with the engine's words: "needs", "capabilities", "partial
note", "action log", "key id", "trust note", "serial", "annotations". A customer reading the page has
never heard these. Same for the skip kinds if they are printed raw.
Fix. Add a label table to 6, and ban raw JSON keys as visible text (CI grep on the template):

| Engine word | Visible label |
| --- | --- |
| needs, with `met` | `Requires: root (not available)` or `Requires: root (available)` |
| capabilities | `What rdy could use on this machine` |
| partial | `Checked in part. Could not read: <list>. The result may be incomplete.` |
| action log | `What rdy read and contacted` |
| observed, expected | `Found`, `Needed` |
| fix_source spec / rdy | `From acme-platform` / `From rdy` (already in 6) |
| key id, trust note | `Signing key`, `Your note about this key` |
| signed_at, serial | `Signed on`, `Spec revision` |
| host_id | `Machine ID (hashed, differs per vendor)` |
| `severity: block` on SKIP | `required by acme-platform` |
| skip kinds | `Not in this version of rdy`, `rdy cannot read this check`, `Missing: root`, `Not available on this OS yet`, `Does not apply here`, `Run time limit reached`, `Run was interrupted` |
| section headings | `Blocks`, `Required checks not run`, `Warnings`, `Passed`, `Does not apply here` |

Also add a one-line legend under the verdict: "BLOCK: fix before install. WARN: fix if you can. SKIP: rdy
could not check it." and the verdict rule in plain words: "NOT READY if anything blocks or a required check
could not run. READY with warnings if only optional things are wrong. READY if every check ran and passed."
The same three sentences go in `rdy run --help`.

**M6. 5.3, 5.2 (summary): the summary line leaves out three buckets, and "nothing verified" has no words.**
Problem. The line `2 blocks, 1 warning, 3 passed, 2 required checks not run` has no place for an optional
check that did not run (`optional_not_run`) or a not-applicable one. `READY with warnings` with nothing
under it would puzzle the reader. Case 3 of the verdict rule (`nothing_verified`) says READY with warnings
but defines no last line. A spec where every check is `os: [windows]`, run on Linux, would end there.
Fix. Specify the grammar in 5.3, for 07 to copy:

- Always: `<n> block(s), <n> warning(s), <n> passed`. Then, only if above zero, in this order:
  `<n> required check(s) not run`, `<n> optional check(s) not run`, `<n> not applicable`. Singular for
  one: `1 block`, `1 required check not run`.
- Last line: `NOT READY` (any block). `NOT READY: 1 required check was not run` or `NOT READY: 2 required
  checks were not run` (none observed). `READY with warnings`. `READY with warnings: nothing was checked`
  (`nothing_verified`). `READY`.

Samples:

```text
0 blocks, 0 warnings, 5 passed, 1 optional check not run, 2 not applicable
READY with warnings
```

```text
0 blocks, 0 warnings, 0 passed, 3 not applicable
READY with warnings: nothing was checked
```

Timeouts and errors count as "not run" (5.3 amendment 1). Say so on the line they sit in:
`2 required checks not run (1 timed out)`. Keep it as an optional suffix, only when a timeout or error is
in the bucket.

### Should fix

**S1. 2.7, `needs` alias on `k8s.storageclass`: drop it.**
Problem. The canonical example teaches a deprecated name, and `rdy spec lint` on it warns about the alias,
which contradicts the lint exit test ("two not_in_build warnings"). No release exists, so there is nobody
to keep compatible. The doc's own reason (the plan's example must keep parsing) is a plan-doc problem, not
a user problem.
Fix. Remove `needs` from `K8sStorageClassParams` and from 2.7. Edit `acme-platform.yaml` line 41 to
`access_modes: ["ReadWriteOnce"]`, and `acme-k8s-only.yaml` line 24 likewise. The SHA-256 (7.1, both
samples) and the sidecar sample change. Fix the plan example in `rdy-plan.md` as a plan correction. If you
keep the alias, the lint test must list three warnings.

**S2. 2.7, `k8s.version`: `max_severity` collides with `severity`, and the default surprises.**
Problem. A vendor writes `max: "1.31"` and `severity: block` (this is exactly `acme-k8s-only.yaml`) and
expects 1.32 to block. It warns, because `max_severity` defaults to `warn`. The name reads as "the
highest severity", so it looks like a second `severity`.
Fix. Rename to `over_max: warn | block` (default `warn`), and have lint print a hint when `max` is set and
`over_max` is not: `note: servers above 1.31 give a warning. Set over_max: block to make them block.`

**S3. 2.7, plain-word parameter names.**
Problem. `band` and `band_result` on `host.memory` are internal words ("a band of percent below min").
`swap: off | any` is the one enum value that YAML 1.1 tools (yq, PyYAML, Ansible, some editors) turn into
`false`; I confirmed a 1.1 loader rejects it against the schema. Everywhere else the spec says `forbid`
(`fips: forbid | require | any`, `forbid_options`).
Fix. `tolerance_percent` (number, 0 to 20) and `tolerance_result` (`pass` | `warn`) replace `band` and
`band_result`; the check explains it in its message ("15.7 GiB found, 16 GiB needed, inside the 5%
tolerance"). `swap: forbid | any`. Both are free to change now.

**S4. 2.3 `timeout`: a vendor can only lower it, and the schema does not enforce the range.**
Problem. The effective value is `min(spec, check default, 60 s, time left)`. A vendor with a slow proxy sets
`timeout: 30s` on `net.egress`, the check default is 10 s, and the check still stops at 10 s with no
message. The schema accepts `timeout: 90s` (I tested it), though 2.3 says 1 s to 60 s and 02 expects 01 to
reject above 60 s.
Fix. Either make the spec value win up to 60 s (`min(spec or default, 60 s, time left)`), which is what a
vendor expects, or keep the cap and make lint say `warning: timeout 30s is higher than host.disk allows
(10s). rdy will use 10s.` I recommend the first. State where the 1 s to 60 s range is enforced: the schema
cannot express it with the shared `Duration` pattern, so say "enforced by `spec lint` and at load, exit
64, `error: timeout must be between 1s and 60s`".

**S5. 2.7 / schema: a check with no threshold validates and can only pass.**
Problem. `- id: host.memory` and `- id: host.cpu` with no `min` pass the schema (I tested both). A vendor
who forgets `min` gets a green check and a false READY on that line.
Fix. `spec lint` warns, and `spec sign` refuses (M2): `error: acme-platform.yaml:22:5: host.memory has no
threshold, so it can only pass` / `fix: add 'min: 16Gi'.` Do this for every id whose catalog entry has
no default threshold. Mark `min` required in the schema where the check has none.

**S6. 2.6 fix override: the vendor's text replaces useful detail from rdy.**
Problem. In 7.2, the vendor's fix for `host.memory` is "Add RAM or choose a larger node class." rdy's own
text says "A nominal 32 GiB machine shows about 31 GiB, so ask for a size class, not an exact number." That
is the line that saves the support call. Verbatim replacement drops it. The result keeps `builtin_fix`, so
the data is there.
Fix. Terminal: the vendor's fix only (short). HTML: the vendor's fix first, labelled "From acme-platform",
then rdy's text below it labelled "More from rdy" when `builtin_fix` is present. No `<details>`, so print
shows both. State this in 6.

**S7. 4.8 and 2.2: wording gaps in loading errors.**
- `spec_expired`: air-gapped hosts often have a wrong clock, and there is no override. Fix line becomes
  `fix: ask the vendor for a current spec. If this machine's clock is wrong (it says 2027-02-03), set it
  and run again.` The first line already shows the date; add today's date to it.
- `spec_unsigned` fix: `fix: ask the vendor for the .minisig file. If you wrote this spec yourself, run it
  with --allow-unsigned.` (It matches the banner's own words, and puts the vendor first.)
- `spec_key_unknown` fix: `fix: get the vendor's public key from their docs, compare its fingerprint with
  what the vendor tells you, then run: rdy trust add acme-platform --key <file>` (not just "check its
  fingerprint": against what?).
- `spec_signature_invalid` covers six causes with one code. Specify the first line for each, so the
  message is never "something is wrong with the signature". Bad comment or legacy algorithm: `error: the
  signature on X is not in the form rdy accepts.` Product mismatch: `error: X is signed for product
  'acme-edge', but the spec says 'acme-platform'.` Fix for all: `get a fresh copy and its .minisig from the
  vendor. Do not run this file.` When the file has CRLF: add `The file has Windows line endings. If it went
  through Git or email, ask for the original.`
- `trust.yaml` unknown key (4.3): add the fix `fix: remove that line, or run rdy trust list to see what
  rdy wrote.`

**S8. 5 (JSON): add a "for scripts" paragraph and fix the summary arithmetic.**
Problem. 3.2 says what may change. Nothing says what a script may rely on. Also `summary.skipped` excludes
`not_applicable`, so `jq '[.checks[]|select(.status=="skipped")]|length'` does not equal `summary.skipped`.
`required_not_run` overlaps `skipped`, `timeout` and `error`, but nothing says so.
Fix. Add to 5: "Stable for scripts: `verdict`, `verdict_reason`, `exit_code`, `complete`, `summary.*`,
`checks[].key`, `.id`, `.severity`, `.status`, `.bucket`, `.skip_kind`, `.duration_ms`, and `error.code`.
Do not parse `message`, `fix`, `notes` or `observed` values as text: the words can change in any release.
`observed` and `expected` keys per check id are additive, documented per check." And fix the arithmetic:
`skipped` counts every `status: skipped` entry, so `pass + warn + block + skipped + timeout + error =
total`. `not_applicable`, `required_not_run` and `optional_not_run` are views inside that sum, not extra
terms. A test asserts both identities. Say so in the schema `description` for `Summary`.

**S9. 5.5, 6 vs ADR 0003: three additions the ADR does not know about.**
Problem. 01 goes beyond ADR 0003, and the ADR is the thing reviewers read.
- The report directory also holds "a copy of the verified spec and its `.minisig`" (5.5). ADR 0003
  decision 1 lists two files. Good idea (an audit trail), but the `Report written to` line and `rdy upload`
  must say what is in the folder.
- `data-sha256` on the embedded script (6) is not in decision 4.
- The 5 MiB HTML cap and the 2 MiB JSON cap exist only here. The JSON side says what is cut first. The HTML
  side does not.
Fix. Add all three to ADR 0003 in its next revision. For the HTML cap, specify: past the cap, the action
table is cut to the rows that fit and ends with "N more entries are in the embedded JSON" (6 already does
this at 1000 rows); the checks and blocks are never cut. Add a `<title>` of `rdy report: acme-platform,
NOT READY` so the tab, the history and the printed header read right.

**S10. Schemas: descriptions leak internal references into editor tooltips and the docs page.**
Problem. Descriptions become the hover text vendors see in their editor and the generated reference page
(09-docs-site). `spec.v1.schema.json` has "ADR 0009" (line 790), "ADR 0010" and "the catalog" (1059),
"ADR 0007" (1166), "04-bundle-and-redaction.md" (1180), "the shipped catalog" (667), "the plan's first
example" (932), "M2" (1166), and the root description ("Hand-written contract", "revision 0", the doc
path). The result schema has three more. Also `os` says "reported as excluded", while the doc and the
result say `not_applicable`.
Fix. Strip ADR numbers, doc names, milestone names and "the plan" from every `description`. Replacements:
line 790 "At most 64 endpoints in the whole spec."; 1059 "Dry-run checks are not supported yet."; 1166
"Used by rdy bundle. Unknown keys are an error."; 1180 "Adds groups. rdy always applies its built-in
minimum as well."; 667 "Agent ids that block. Run rdy spec lint to see the known ids." `os`: "Run only
on these operating systems. On others the check is reported as not applicable and does not count." The
CI drift check can grep descriptions for `ADR `, `plan` and `M[1-5]`.

**S11. Schema `CheckResult`: `fix` is not required where the doc says it is.**
Problem. 5.2 says `fix` is null only for `pass` and `not_applicable`. The schema's `allOf` requires a
string for `warn`, `block`, `timeout`, `error` but not for `skipped`. A skipped required check with no fix
passes validation, which breaks the house rule.
Fix. Add a branch: `status: skipped` and `skip_kind` not `not_applicable` then `fix` is a non-empty
string.

**S12. 5.2 `observed` and `expected`: say how the HTML turns them into "Found" and "Needed".**
Problem. The HTML shows "observed against expected", but the key names differ per check (`total_bytes`
against `min_bytes`; `logical_cores` against `min`). A generic renderer will print two JSON blobs.
Fix. State the rule in 6 so a template can do it without per-check code: render both objects as two
key-value tables; humanise keys (`total_bytes` becomes "total", with the value as a size); `_bytes` values
print as sizes, `_ms` as milliseconds, `_percent` with `%`; nested lists print one per line. The unit
suffix convention already in 5.2 makes this possible. The one-line `message` stays the headline.

**S13. `--json` output of the other commands is undefined; `ErrorOutput` has no position.**
Problem. `rdy spec lint --json` is what a vendor's CI runs before `spec sign`. No shape is defined for
it. `ErrorOutput.error` has `code`, `message`, `fix` only, so a `spec_parse` failure loses its line and
column in JSON, though 2.5 promises them.
Fix. Add two optional fields to `ErrorOutput.error`: `file`, `line`, `column`. Add a `LintReport` object
to the result schema `$defs`: `{api_version, kind: "Lint", file, findings: [{level: "error" | "warning",
code, line, column, key, message, fix}], errors: n, warnings: n}`. Codes are the open snake_case kind:
`unknown_key`, `unknown_check`, `unsupported_field`, `bad_value`, `not_in_build`, `no_threshold`. Both are
additive, so they can land in revision 0.

**S14. Duplicate ids across `os` filters need a name, and `name` is not shown.**
Problem. A cross-platform spec wants two `host.disk` entries, one `os: [linux]`, one `os: [windows]`. 2.3
rejects the duplicate key unless both have a `name`. A vendor will hit that error on the first
cross-platform spec. And `name` reads as a display title, but 5.2 only uses it in the `key`.
Fix. Keep the rule; the error text in M1 tells them what to do. Show `name` in the report as the heading:
`host.disk (data)`. Put a cross-platform example with two named entries in 2.3.

**S15. Example specs: field changes (details in the next section).**
Two files fail the schema today. Three files use ids the doc renames, and one passes only because an
unknown id is allowed. Apply the edits below; the CI validation ticket then passes.

**S16. First run is `error: no signature found`.**
Problem. `CLAUDE.md` Commands runs `rdy run examples/specs/acme-platform.yaml --json`. The README quickstart
uses `acme-quickstart.yaml`. Neither has a `.minisig` file, so the first command a new user types exits 64
with `spec_unsigned`. The `acme-quickstart.yaml` header does not mention it.
Fix. Either ship `examples/specs/*.yaml.minisig` signed by a published demo key (`examples/keys/acme-demo.pub`,
synthetic) with `rdy trust add acme-quickstart --key examples/keys/acme-demo.pub` in the quickstart, or put
`--allow-unsigned` in every README and CLAUDE.md command and say in the header: "This file is unsigned.
Run it with --allow-unsigned; rdy prints a warning." I prefer the first: the quickstart then shows the real
flow. Record it as a plan correction for CLAUDE.md.

### Nits

- **N1. 4.7 banner.** Keep the text. Two small edits. Line 3: "got it straight from the vendor" fits an
  e-mailed file, which is the risky case; write "or got it from the vendor in a way you trust." Add one
  plain line of what is at stake: "The spec decides which files rdy reads and which hosts it contacts." It
  is true and short, and it is not scary: no exclamation, no "danger". Use the path as typed in the first
  line, not the base name, so the user sees which file. Nothing else changes; the `WARNING: UNSIGNED SPEC`
  repeat above the verdict is right, and so is putting the banner on stderr.
- **N2. 7.2 and 7.3 `run`.** `started_at` has whole seconds and `finished_at` has milliseconds. Use
  milliseconds for both, or whole seconds for both and rely on `duration_ms`.
- **N3. 6 header.** `metadata.version` is shown as "spec `version`". A reader takes it for the spec's own
  version (`serial` is that). Print "For acme-platform >=4.2" and "Spec revision 7".
- **N4. Vocabulary.** The status is `BLOCK`, the summary says "blocks", 6 says "Blockers". Use "Blocks" in
  headings (M5) so one word runs through the page. `severity: block` is also "required" in the summary;
  add one sentence to the spec reference: "`severity: block` means required. `severity: warn` means
  optional."
- **N5. Schema `Target`.** The port part is `[0-9]{1,5}`, so `registry:99999` passes. Lint catches it;
  say so, or tighten the pattern.
- **N6. Quickstart on Windows.** `host.disk path: /` is not a Windows path (2.6 says absolute is `C:\...`).
  Add a second named entry with `os: [windows]` and `path: 'C:\'`, or note it is macOS and Linux only.
- **N7. `expires`.** An unquoted `expires: 2027-01-31` is a date, not a time. The M1 message above covers
  it; add a lint hint that quoting does not help and the full form is needed.
- **N8. 2.5 `os` field and `host.os` check.** A vendor may write `os: [rhel]` on a check. The schema error
  is "not one of linux, macos, windows". Add to the lint message: `os selects the operating system family.
  To match a distribution, use the host.os check.`

## Verdict rule and summary wording: at a glance

The rule in 5.3 is right and I confirm the exit codes. A customer engineer can hold three sentences:

1. Any block, or any required check that did not run: NOT READY, exit 2.
2. Only warnings, or only optional checks that did not run: READY with warnings, exit 1.
3. Everything ran and passed: READY, exit 0.

"Required check not run" is understood once the page says "required by acme-platform" next to the SKIP
(M5). The four skip kinds in the question are internal names (`not_in_build`, `unknown_check`,
`unsupported_spec`, `not_applicable`). The customer should never see those strings. They see the messages
in M1 and the labels in M5. Only `--json` shows the kinds, which is right for scripts.

## Does the result JSON carry what the outputs need?

| Needed by terminal or HTML | Where | State |
| --- | --- | --- |
| Duration per check, and for the run | `checks[].duration_ms`, `started_ms`, `run.duration_ms` | Present |
| Measured against threshold | `message` (headline), `observed`, `expected` | Present; HTML rule missing (S12) |
| Fix text and who wrote it | `fix`, `fix_source`, `builtin_fix` | Present; `fix` not required for skips in schema (S11) |
| Needs, met or not | `needs[].met`, `hard`, `partial`, `capabilities[]` | Present |
| Timeout, error detail | `timeout_after_ms`, `error_kind`, `message`, `fix` | Present |
| Unsigned banner | `signature.state`, `run.options.allow_unsigned` | Present |
| Questions contact | `spec.contact` | Present |
| Order, blockers first | none | **Missing** (M3) |
| Required or optional for a SKIP | `severity` | Present (derive is easy: not `warn`) |
| Summary counts | `summary` | Present; arithmetic unstated (S8); line grammar missing (M6) |
| Position of a spec error in `--json` | `ErrorOutput.error` | **Missing** (S13) |

## `--json` stability

The rules are right: additive changes only inside `rdy/v1`, open enums marked "Open", consumers told not to
recompute `verdict`, golden results from every release parsed forever, `deny_unknown_fields` never on
results, error codes stable. Three gaps: the script contract (S8), the lint object (S13), and the `Summary` description, which should say
the object grows by adding keys, so a script must not sum every key.

## HTML report against ADR 0003

| ADR 0003 point | 01 section 6 | Match |
| --- | --- | --- |
| One file, inline CSS, no JS, CSP as written | Same CSP string | Yes |
| Embedded JSON with `<`, `>`, `&` escapes | Same, adds `data-sha256` | Yes, ADR needs the attribute (S9) |
| Order: verdict, counts, banner, privacy line, blocks, required not run, warnings, passes | Same, adds not applicable last | Yes |
| Words: PASS WARN BLOCK SKIP TIMEOUT ERROR | Same | Yes |
| Dark mode, print | Adds page breaks, repeated banner | Print is unsafe in dark mode (M4) |
| Size cap | 5 MiB HTML, 2 MiB JSON, only in 01 | Add to ADR (S9) |
| Two files in the report folder | Also the spec copy and `.minisig` | ADR needs updating (S9) |
| `lang`, `color-scheme`, headings in order | Same | Yes |
| Footer link with `rel="noopener noreferrer"` | Same | Yes |

## Example specs: exact field changes

Validated with a draft 2020-12 validator against `spec.v1.schema.json`.

| File | Today | Edits |
| --- | --- | --- |
| `acme-airgap-host.yaml` | **Fails.** Line 46: `via_proxy: never` is not one of `auto`, `direct`, `proxy_only`. | Line 46: `via_proxy: direct`. Also (no schema error today, because unknown ids are allowed): line 29 `require: v2` to `version: v2`; lines 40 to 41 `host.selinux` with `allow: [...]` becomes `id: host.lsm` and `selinux: { allow: [permissive, disabled] }` (written as a nested block). Add to the header: "host.kernel, host.cgroups and host.time_sync are not built yet, so a run reports them as not run and the verdict is NOT READY until they ship." Validated after these edits: passes. |
| `acme-k8s-only.yaml` | **Fails.** Line 28: `can_i` is not a field; `k8s.rbac` requires `can`. | Line 28: `can_i:` to `can:`. Lines 17 to 22: `id: k8s.node_resources` to `id: k8s.nodes`, `nodes: 3` to `min_ready: 3`, `cpu_per_node: 4` and `memory_per_node: 16Gi` to `per_node: { cpu: 4, memory: 16Gi }`. Line 24: `needs:` to `access_modes:` (S1). Optional: line 15 comment on `over_max` (S2). Validated after these edits: passes. |
| `acme-inference-gpu.yaml` | Passes. `k8s.node_resources` is an unknown id, so a run reports it `unknown_check` with a did-you-mean. | Lines 30 to 32: `id: k8s.nodes`, `min_ready: 2`, `per_node: { memory: 128Gi }`. Leave `gpu.*` until the gpu family is specified. Validated: passes. |
| `acme-platform.yaml` | Passes. Uses the deprecated alias `needs`. | Line 41: `needs:` to `access_modes:` (S1). New SHA-256 and size; update 7.1, the `spec.sha256` and `size_bytes` in 7.2 and 7.3, and the sidecar sample. Validated: passes. |
| `acme-quickstart.yaml` | Passes. | Header comment: it is unsigned (S16). Windows path (N6). |

## Plan corrections found

- `CLAUDE.md`, Commands: `rdy run examples/specs/acme-platform.yaml --json` exits 64 (`spec_unsigned`).
  Fix: add `--allow-unsigned`, or ship signed examples (S16). Also `-p rdy-cli` should be `-p rdy` (ADR 0011).
- `docs/plan/01-spec-format.md` 5.2: `not_in_build` message says "rdy build". Fix: "this version of rdy" (M1).
- `docs/adr/0003`, decisions 1 and 4: add the spec copy, the `.minisig` copy, `data-sha256` and the size caps
  (S9).
- `docs/adr/0008`, decision 2: the example skip reason reads "(needs a newer rdy, or a typo)". Fix: use the
  M1 wording, which names who acts.
- `docs/plan/rdy-plan.md`, example spec: `needs: ["ReadWriteOnce"]` becomes `access_modes` if S1 is taken.
- `docs/plan/02-engine-design.md`: "rdy-spec validation rejects a spec timeout above 60 s (01 to confirm)".
  01 does not confirm it anywhere an implementer will find; S4 does.

## Tickets implied

- [M1] Write the spec error and skip message table into 01-spec-format and rdy-spec hints | owner: rust-architect | est: 2h | depends on: none | exit test: every row of the M1 tables is in the doc and a unit test asserts each `SpecError` and each skip kind has a message and a non-empty fix.
- [M1] Reserved check ids and sign-refuses-on-typos rule | owner: rust-engineer | est: 2h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: `host.kernel` lints as not_in_build, `mn: 32Gi` and `min: 32G` make `spec sign` exit 2 with a fix, and a `gpu.cuda` entry only warns.
- [M1] Add `bucket` to CheckResult and sort by it in terminal and HTML | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture with every outcome sorts blocker, required_not_run, warning, passed, not_applicable and the bucket counts equal the summary.
- [M1] HTML print override, labels and legend | owner: rust-engineer | est: 2h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a headless render with dark preferred and print media has text contrast at least 4.5 to 1, and a template grep finds no raw JSON key as visible text.
- [M1] Summary line grammar and nothing-verified last line | owner: rust-engineer | est: 1.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: golden strings for the six samples in M6 and the singular and plural forms pass.
- [M1] Rename k8s.version max_severity, host.memory band and swap off | owner: rust-architect | est: 1h | depends on: none | exit test: schema, 2.7 and the catalog use over_max, tolerance_percent and swap forbid.
- [M1] Drop the needs alias and strip internal references from schema descriptions | owner: rust-architect | est: 1.5h | depends on: none | exit test: no description contains ADR, plan or a milestone name, and the five example specs validate.
- [M1] Apply the example spec edits in this review and re-sign the sample | owner: rust-architect | est: 1.5h | depends on: Drop the needs alias and strip internal references from schema descriptions | exit test: every file in examples/specs validates and the 7.1 SHA-256 matches the file.
- [M1] LintReport and ErrorOutput position fields in the result schema | owner: rust-architect | est: 1.5h | depends on: none | exit test: `rdy spec lint --json` output validates against the schema and a spec_parse error carries line and column.
- [M1] Script contract paragraph and summary identities | owner: rust-architect | est: 1h | depends on: none | exit test: 01 section 5 lists the stable fields and a unit test asserts the two summary sums.
- [M2] Signed demo key and signed example specs for the quickstart | owner: devrel | est: 2h | depends on: rdy spec keygen and rdy spec sign | exit test: the README quickstart runs on a clean machine with `rdy trust add` and no flags beyond the file name.
