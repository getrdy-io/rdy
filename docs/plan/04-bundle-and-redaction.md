# 04 Bundle and redaction

Owners: rust-engineer (drafted all of it) and security-reviewer (joint owner; confirms sections 3, 4 and 6).
Status: draft 1, 2026-10-28, waiting for security-reviewer. Date: 2026-10-28.

This note designs the redactor, the collectors, the bundle archive and manifest, and the opt-in upload.
It builds on ADRs 0002, 0003, 0004, 0007, 0008, 0009, 0010 and 0012, on 02-engine-design.md (probe facade,
action log, output confinement) and on 05-threat-model.md (Surface 4, INV-15, INV-20, Appendix F). Field
names follow `crates/rdy-spec/schema/*.json`. 01-spec-format.md is not written yet; where 01 differs, 01
wins and this note follows. Everything on the server side (storage, viewer, analyzers) belongs to
`rdy-cloud` and is out of scope. Where I propose a server behaviour, it is a request to `rdy-cloud`.

## Decisions in one screen

1. One redactor engine, `rdy_engine::redact` (02, ADR 0015). M1 ships the whole-string API and the report
   rule set. M2 adds streaming and the rest. It is one compiled rule set, not a chain of trait objects.
   Rules find spans, overlaps resolve by priority, replaced text is never re-scanned.
2. Rules are compiled into the binary. A spec can add redaction and can never remove a built-in rule. A
   customer can add more on the command line.
3. A placeholder is `[REDACTED:aws_access_key_id:3fa9c01b]`. The tag is a keyed hash with a random key made at
   process start and never stored. Same secret, same tag, inside one run only.
4. The archive writer only accepts bytes that came out of the `Redactor`. No temp file ever holds raw bytes.
5. A bundle never records a hash of raw content. It records raw byte counts and the hash of what it stored.
6. Collectors go through the probe facade with a declared manifest. Bundle scope needs streaming reads and
   larger caps than checks get (a correction to 02).
7. Caps never fail a bundle. A capped entry is cut with a marker and listed in the manifest. Defaults: 256 MiB
   raw, 100 MiB archive. The archive is `tar` plus `zstd` level 3 with a manifest last.
8. Upload is `rdy upload <file>`. The token comes from a prompt, `RDY_TOKEN` or `--token-file`, never argv.
   Two requests to one fixed origin: create, then one `PUT`. The client shows what it will send and asks.
9. Unknown collector kinds are skipped with a manifest entry. Unknown redactor groups exit 64. Missing data is
   acceptable. Missing redaction is not.

## 1. Scope and milestones

CLAUDE.md rule 2 says redaction runs before anything is written to disk. The M1 report already writes
hostnames, proxy settings and command output to disk (HTML and JSON). So a small redactor is an M1 safety
gate, not a bundle feature. The bundle pipeline is M2, with the portal MVP (plan, milestone table).

| Item | M1 | M2 | Later |
| --- | --- | --- | --- |
| Redactor API | `redact_str` (whole string), counts, keyed tags | `redact_bytes`, streaming `RedactStream`, residual scan | none |
| Rules | url userinfo, auth headers and cookies, AWS keys, PEM private keys, kubeconfig credentials, `rdy_st_` tokens, secrets by key name (env, YAML, JSON, INI) | emails, JWTs, SaaS token prefixes, GCP and Azure credentials, Kubernetes Secret manifests, generic high-entropy tokens, IPv4, IPv6 and MAC (opt-in), custom patterns | more prefixes as reports arrive |
| Where it runs | every string in the `Report` including the action log, error output, `--json` stdout, the `tracing` layer and panic messages | every byte of every bundle entry, the result JSON it embeds, and the manifest | `rdy report` re-render input |
| Tests | 60 or more corpus cases, property tests, CI gate | 300 cases, chunk-boundary cases, fuzzing, second-opinion scanner, throughput floor | none |
| Collectors, archive, manifest | none | all of section 2 and 5 on Linux and Kubernetes; basic macOS and Windows | `k8s:logs`, OS log collectors on macOS and Windows |
| `rdy bundle` | none | yes | none |
| `rdy upload`, receipt | none | yes, single `PUT` | resumable upload if partners need it |
| Result schema | `redaction` summary field | manifest schema in `rdy-spec` | none |

M1 does not contain collectors, an archive, a manifest, streaming, binary handling, emails, JWTs, entropy
rules, IP rules, custom patterns or any upload code. 05 says the same ("M1 has no upload code").

## 2. Collectors

A collector turns one entry of the spec's `bundle.collect` list into zero or more files in the archive.

**Contract.**

- Id syntax is `kind:argument`, matching the schema pattern `^[a-z][a-z0-9_]{0,15}:.{1,1024}$`. Examples:
  `journal:7d`, `k8s:events`, `file:/etc/acme/*.yaml`. The argument is validated by the collector. A bad
  argument exits 64 with a line and column, and `spec lint` reports it first.
- An unknown kind is skipped, with a manifest entry `skipped` and reason `unknown_collector` ("needs a newer
  rdy"). Collecting less is safe. This differs from checks on purpose: a skipped check can look like a pass.
- Every collector declares a static `CollectorInfo`: kind, OS support, commands, read prefixes, Kubernetes
  kinds, privilege need, default caps and which end it keeps when it truncates (head or tail).
- Collectors cannot write. They push raw chunks into an `EntryWriter`. The writer feeds the redactor and
  buffers the redacted entry. Nothing else can reach the archive (section 3, "Where the guarantee lives").
- Collectors run one at a time in priority order: `rdy:*`, `file:`, `host:*`, `container:*`, `k8s:*`,
  `host:kernel_log`, `journal`. That keeps memory bounded. Each has a time cap. On expiry the data gathered so
  far is kept and the entry is `partial`.
- The customer can only subtract. `--skip <id>` drops a collector. `--max-size` lowers the caps. The spec
  can only add collectors. Hard ceilings live in the binary.

| Id | What it collects | Needs | Milestone |
| --- | --- | --- | --- |
| `rdy:result` | the run's JSON result, the verified spec and its `.minisig`, the bundle action log. Always included, never listed in `collect:` | none | M2 |
| `file:<glob>` | files matching an absolute glob, each capped | read access | M2 |
| `journal:<duration>` | systemd journal, newest lines first kept, chronological output | root or `systemd-journal` group | M2 |
| `host:processes` | process list: pid, ppid, uid, state, age, rss, executable name. Never arguments or environment | none | M2 |
| `host:network` | interfaces, addresses, routes, listening sockets, resolver and hosts config, proxy variable names | root for socket owners | M2 |
| `host:disk` | mounts, filesystem types, free space, mount options | none | M2 |
| `host:kernel_log` | kernel ring buffer | root when `dmesg_restrict=1` | M2 |
| `container:runtime` | runtime version and info, containers and images list, daemon config files | docker group or root | M2 |
| `k8s:events` | events in the install namespaces, JSON Lines | RBAC `list events` | M2 |
| `k8s:describe:<ns>` | structured objects for the install namespace (not `kubectl describe` text) | RBAC `list` on the named kinds | M2 |
| `k8s:logs:<ns>` | pod logs, tail only | needs an ADR 0010 amendment | M3 |

Appendix A has the per-OS source, privilege, degrade, caps and time cap for each row.

**Install namespace.** The union of `namespace` params in the spec's k8s checks and `--namespace`. If it is
empty, `k8s:describe` is skipped with the fix "add `--namespace <ns>`". There is no cluster-wide describe.

**How collectors use the facade.** Every file read, command and Kubernetes request goes through `Probe`
(02). The policies stay: argv only, fixed PATH, scrubbed environment, the read deny list checked on the path
and on its canonical target, the Kubernetes guard. Bundle scope adds three things, each a change to 02:

1. Streaming `read_stream` and `exec_stream` with a cap declared in `CollectorInfo`. Today the facade caps
   files and command output at 1 MiB. A 32 MiB journal needs more.
2. A bundle `CollectorInfo` manifest checked like `CheckInfo`. The facade refuses a collector that reads or
   runs something it did not declare.
3. More deny-list entries (Plan corrections). The list applies even when a spec glob names the file.

`file:` globs are expanded with `Probe::read_dir` (so listing is logged and capped) and matched with
`globset`. At most 8 levels deep, 10,000 entries visited, 200 files per glob. Symlinks are resolved, and a
target outside the glob's literal prefix is refused unless it passes the deny list and the prefix check
(SEC-43). `rdy bundle --plan` prints the resolved file list, commands and caps before anything is read.

**Kubernetes objects carry secrets.** Pod specs hold literal `env[].value` strings and the
`last-applied-configuration` annotation holds a whole manifest. The k8s collector strips both before the text
redactor sees anything: `env[].value` becomes `[REDACTED:env_value:<tag>]` (names and `valueFrom` stay),
`kubectl.kubernetes.io/last-applied-configuration` and `managedFields` are dropped. Secrets are never listed
(guard). ConfigMaps are listed as metadata only.

**Degrade.** A collector that lacks a privilege collects what it can and says so. The manifest entry has
`status: partial` or `skipped`, a reason code and a one-line hint ("run as root to read other users'
sockets"). rdy never asks for sudo (rule 1).

## 3. Redactor design

> security-reviewer to confirm

### 3.1 Model

```rust
// rdy_engine::redact (feature `redact`, independent of `runtime` so rdy-cloud can reuse it)
pub struct Redactor { /* Arc<CompiledRules>, TagKey, per-rule AtomicU64 counts */ }
impl Redactor {
    pub fn new(set: RuleSet, extra: &Extra, key: TagKey) -> Result<Self, RedactError>; // only custom regex can fail
    pub fn redact_str<'a>(&self, s: &'a str) -> Cow<'a, str>;        // M1
    pub fn redact_bytes<'a>(&self, b: &'a [u8]) -> Cow<'a, [u8]>;    // M2
    pub fn stream(&self) -> RedactStream;                            // M2: push(chunk, out), finish(out)
    pub fn summary(&self) -> RedactionSummary;                       // rule name -> count. Never values.
}
pub enum RuleSet { Report, Bundle }                                   // Bundle is a superset of Report
```

One `Redactor` serves a whole process. Its key and counts are shared by the report and the bundle in one run.

**Spans, not rewrites.** For each record, every active rule reports `(start, end, rule, priority)` spans.
The merger sorts them, keeps the highest priority (then the longest) where they overlap, and writes the
output once. A later rule never sees an earlier placeholder. This also makes redaction idempotent by
construction: a placeholder matches no rule, and the key-name rule skips values that start with `[REDACTED:`.

**Order (priority, first wins).**

1. Multi-line blocks: PEM private keys, Kubernetes Secret `data:` blocks.
2. Known token shapes: AWS key ids, `rdy_st_`, JWTs, SaaS prefixes.
3. Auth headers and cookies.
4. URL userinfo.
5. Secrets by key name, kubeconfig credentials.
6. Custom patterns from the spec and the command line.
7. Emails.
8. Opt-in IPv4, IPv6, MAC.
9. Generic high-entropy tokens, on whatever is still uncovered.

Specific rules go first because they give a typed placeholder and keep the entropy rule quiet. The entropy
rule is last because it is the weakest signal and the one most likely to hit something support needs.

**Groups and names.** A spec names groups (`aws_keys`, `bearer_tokens`, `emails`, and the others in
Appendix B). Placeholders and the manifest use rule names. The built-in minimum set runs whatever the spec
says: every group except `ipv4`, `ipv6` and `mac`. A spec that lists an always-on group is accepted and the
entry changes nothing. A spec that lists an optional group turns it on. An unknown group exits 64
("needs a newer rdy"). A rule that is missing is a privacy failure, so this one fails closed.

**Structure is kept.** A replaced span excludes quotes and delimiters. `password="hunter2"` becomes
`password="[REDACTED:secret_by_key:1a2b3c4d]"`. JSON and YAML stay parseable by the vendor's tools. A PEM
block becomes one placeholder line.

**What the rules do not decode.** Rules tolerate the usual escapes around the secret: `\"`, `\u0040` for
`@`, `%40` in userinfo, and literal `\n` in JSON-escaped PEM. rdy does not decode base64, double encoding or
compressed values. An encoded secret that is not caught by key name or by entropy stays. The docs say so and
the customer can add `--redact-pattern`.

### 3.2 Placeholder and the stable tag

`[REDACTED:<rule>:<tag>]`. Rule names are `[a-z0-9_.]` (`custom.<name>` for custom patterns). The tag is the
first 4 bytes of `HMAC-SHA256(key, secret_bytes)` as 8 lowercase hex digits.

- `key` is 32 random bytes from the OS RNG, made once at process start, held in memory, never written, never
  logged (its `Debug` is masked). It is not in the manifest or the receipt.
- Why keyed: an unkeyed hash of a short password is a lookup table. With a random key the tag only says
  "these two values are equal", and only inside this run. Two bundles from the same host differ.
- The hash input is the captured secret bytes only, not the rule name. The same password in a URL and in an
  env var gets the same tag, which is what support wants to see.
- 32 bits means a collision at roughly 9,000 distinct secrets has a 1% chance. A collision only merges two
  labels. It never reveals a value.
- Tests use `TagKey::fixed(..)` under feature `testing`. The corpus normalizes tags to `~` (section 4).

### 3.3 Streaming and whole strings

| Input | Mode | Why |
| --- | --- | --- |
| Report strings, errors, log lines (M1) | whole string | small, at most 64 KiB each after caps |
| Bundle entries (M2) | line-oriented stream, entry buffered | a journal is far bigger than one string, and `tar` needs the entry size before the data |

- The stream reads 64 KiB chunks, splits at `\n` and redacts complete records. A record longer than 1 MiB is
  force-split, and the last 16 KiB of each piece is carried into the next. Every rule has a declared maximum
  match length of at most 16 KiB, checked when the rule set is built. So a secret cut by a chunk boundary or
  a forced split still sits whole in the carry window.
- PEM blocks use a small state machine. After `-----BEGIN ... PRIVATE KEY-----` the stream keeps redacting
  while lines look like key material (header lines, 64-column base64) and stops at the END line or at the first
  line that does not look like key material. A truncated key is redacted to the point it stops. It fails
  closed without eating the rest of the log.
- Custom patterns never match across lines. The docs say so.
- Entry buffers hold the redacted bytes only. Peak memory is the largest entry (at most 32 MiB) plus one chunk
  plus the zstd encoder. Target: under 128 MiB RSS for a full default bundle, tested in M2.

### 3.4 Binary and odd encodings (M2)

- Sniff the first 8 KiB. A NUL byte, a high share of control bytes, or the magic number of gzip, zstd, xz,
  bzip2, zip or tar means binary. Binary files are **skipped, not collected**: entry `skipped`, reason
  `binary` or `compressed`. rdy cannot prove a binary is redacted, so it does not ship one. The summary
  counts them.
- A UTF-16 BOM, or NULs at every second byte, is transcoded to UTF-8 with `char::decode_utf16` first. The
  manifest records `transcoded_from`.
- Text that is not valid UTF-8 is redacted as bytes (`regex::bytes`). A stray byte never disables a rule.

### 3.5 Limits and performance budget

| Limit | Value |
| --- | --- |
| Record length before forced split | 1 MiB (carry 16 KiB) |
| Maximum match length of any rule | 16 KiB (checked at build) |
| Custom patterns | at most 32, each at most 256 chars (schema), compile size limit 256 KiB each |
| Cold compile, M1 report set | 20 ms or less on a CI runner |
| Throughput, bundle set, typical log text | 50 MiB/s or more per core. CI fails under 25 MiB/s on the reference corpus (M2) |
| Report redaction, 1 MiB report | 50 ms or less |
| Full 256 MiB bundle with residual scan | under 15 s |

The regex set is compiled once into a `LazyLock<Arc<CompiledRules>>` per `RuleSet`. In M2, an `aho-corasick`
automaton of trigger literals (`AKIA`, `://`, `eyJ`, `-----BEGIN`, key stems such as `pass`, `secret`,
`token`, ASCII case-insensitive) gates which regexes run on a record. M1 uses `regex` alone: strings are
small and the gate is an optimization to add after a measurement, not before. The `regex` crate is linear
time, so a hostile custom pattern cannot cause catastrophic backtracking.

Crates: `regex` 1 (`regex::bytes` in M2), `aho-corasick` 1 (M2), `hmac`, `sha2`, `getrandom`. All are new
direct dependencies and need security-reviewer approval under 05's dependency policy. `sha2` is also used
for manifest hashes.

### 3.6 Where the guarantee lives

- `Redacted<Vec<u8>>` can only be built inside `rdy_engine::redact`. `BundleWriter::add` and the report
  writers accept nothing else. Skipping redaction is a compile error, not a review comment.
- Raw bytes exist only in memory owned by the collector task and the redactor. No temp file, no raw value in
  the action log (it records sizes), in `tracing` (no `Debug` of buffers) or in an error (errors name a rule
  and an offset, never the text).
- If anything fails inside an entry (panic, redactor error), the entry is dropped and the manifest records
  `dropped` with reason `redactor_error`. rdy never falls back to raw bytes.
- **Residual scan (M2).** The stored bytes are scanned again with the same rule set. Hits are redacted again
  and counted in `residual_hits`, and the CLI prints "this is a bug in rdy" with the rule name. It costs a
  second pass and catches span-merge and boundary bugs before they ship.
- Entry names are redacted too, in a filename-safe form (`REDACTED-<rule>-<tag>`).
- **What ships in the binary.** Rules, thresholds and the placeholder format. No rule files, no dictionaries,
  no downloaded updates (rule changes arrive with a signed release). Each rule has a version. Changing what a
  rule matches bumps it and needs security-reviewer approval. The manifest lists the set id
  (`rdy-redact/1`) and every rule version applied. Release assets are the archive, SBOM and checksums (06,
  Appendix C), so there is nothing else to keep in step. `rdy-bundle` adds `regex`, `tar`, `zstd` and a C
  compiler to the musl build, so the M2 binary size budget ticket (06) must measure it.

### 3.7 Open questions for security-reviewer

- Is emails always-on right for bundles, given that support loses real addresses? The stable tag still shows
  that two lines name the same person.
- Thresholds for the entropy rule (24 or more characters, 4.0 bits or more per character, three of four
  character classes, pure hex of length 32, 40 or 64 and UUIDs excluded). They are starting values to be
  tuned against the corpus.
- Should `rdy upload` run a residual scan over a result JSON the customer may have edited?
- Do you want `prctl(PR_SET_DUMPABLE, 0)` during redaction, so a crash dump cannot hold raw text? It is a safe
  call through `rustix`, but Linux only.

## 4. Redaction test strategy

> security-reviewer to confirm

### 4.1 The golden corpus

All values are synthetic. Layout follows 05, Appendix F:

```text
tests/fixtures/redaction/
  FLOOR                      # integer: minimum case count for the milestone (60 in M1, 300 in M2)
  known-gaps.toml            # cases marked known_gap, each with a ticket id
  synthetic.toml             # secret values stored in parts, for push-protection safety
  <category>/<case>.in       # input
  <category>/<case>.expected # exact output with tags normalized to ~
  <category>/<case>.toml     # metadata
```

```toml
# aws/env-secret-key.toml
polarity = "positive"                       # positive | negative | known_gap
rules = ["aws_secret_access_key"]           # rules that must fire (positive only)
since = "m1"                                # m1 | m2
rulesets = ["report", "bundle"]             # run against each set
secrets = ["${SYN:aws_example_secret}"]     # strings that must not appear in the output
```

- `${SYN:name}` in `.in` and `secrets` is expanded by the harness from `synthetic.toml`, where values are
  stored as parts (`["xoxb-", "123456789012-", "..."]`). A scanner that blocks pushes never sees a whole token
  in the repo. The vendor-documented example `AKIAIOSFODNN7EXAMPLE` is used as is.
- The harness redacts `.in` with a fixed test key, replaces every tag with `~`, and compares with `.expected`
  byte for byte.
- `secrets` is the independent oracle. A human blesses `.expected`. The oracle catches a wrongly blessed
  file: no listed secret may appear in the output, whatever `.expected` says.
- Tag behaviour has its own cases: a `[[tag_equal]]` table lists pairs of inputs whose tags must match, and
  `[[tag_differ]]` pairs that must not.
- Every missed-secret report adds a case before the fix (05).

**M1: 71 cases.** Appendix D has the table. Positives cover 05's M1 categories; negatives and hostile cases
cover the "must not redact" list. M2 grows this to 300 (SEC-44) with emails, JWTs, SaaS prefixes, GCP and
Azure credentials, IPs, entropy positives and negatives, Kubernetes Secret manifests, binary and UTF-16 cases,
custom patterns and tag cases. Chunk-boundary cases are generated: each positive is run through the stream
with every split offset and must give the same bytes as the whole-string call.

**Negatives (must not change).** Things a support engineer needs: git SHAs, image digests, UUIDs, versions,
data URIs, long Kubernetes names, public certificates, `secretName:` and `${VAR}` references, and prose that
mentions "password". Appendix D lists them. A negative that changes is a counted false positive (not gated
in M1, gated by a budget in M2).

**Known gaps.** Cases such as a fullwidth-letter key name or a base64-wrapped short password are written down
with the expected (unredacted) output and `polarity = "known_gap"`. The case exists so the gap is visible
and tracked.

### 4.2 Property tests (proptest)

| Property | Statement |
| --- | --- |
| No survivors | For each rule, a generator builds secrets from the rule's grammar plus random context (quotes, escapes, prefixes, suffixes). After redaction the secret is absent. |
| No residual matches | Scanning the output with the same rule set finds nothing. This is the literal form of "no input bytes that match a redactor survive", and it runs inside every corpus and property test too. |
| Idempotence | `redact(redact(x)) == redact(x)`. |
| Stable tags | Equal secrets give equal tags in one `Redactor`. Different keys give different tags. |
| Total | Arbitrary bytes, including invalid UTF-8 and 1 MiB lines, never panic and finish within a time bound. |
| Quiet on plain text | Text built from short ordinary words and numbers is returned unchanged. |
| Chunk invariance (M2) | For any set of split points, stream output equals whole-input output. |

The generators come from the rules themselves, so they cannot find a pattern the rules do not know. That is
why the corpus (written from real-world forms) and the second-opinion scanner exist.

M2 adds a cargo-fuzz target on `RedactStream` (SEC-45) and a CI step that runs a pinned, independent secret
scanner over every redacted bundle fixture and expects zero findings (a short allowlist file for known false
positives, each with a reason).

### 4.3 The CI gate

A required `redaction` job in `ci.yml`, part of `ci-ok`, on all five legs. It fails on:

1. Any survivor, any rule that did not fire, any `.expected` mismatch.
2. A case count below `FLOOR`.
3. A `known_gap` case that now passes ("promote it"), or a gap case missing from `known-gaps.toml`.
4. Property test failures (256 cases per PR, 100,000 nightly).
5. M2 only: more than 2% of negatives changed, throughput under the floor, memory over the ceiling, any
   second-opinion finding. In M1 false positives are printed, not gated.

CODEOWNERS (SEC-04) puts `redact/`, the rule tables and `tests/fixtures/redaction/` under security-reviewer.

## 5. Bundle manifest, archive and caps

### 5.1 Layout

One top directory, so extracting never spills into the current directory. Regular files only: no symlinks, no
hard links, no devices. Headers are deterministic (uid and gid 0, mode 0644, mtime is the bundle time).

```text
rdy-bundle-<product>-<ts>/
  README.txt                       what this is, that it was redacted before writing, how to verify
  rdy/spec.yaml, rdy/spec.yaml.minisig, rdy/result.json, rdy/actions.json
  host/processes.txt  host/network/*.txt  host/disk.txt  host/kernel.log
  container/*.txt
  k8s/<ns>/<kind>.jsonl   k8s/<ns>/events.jsonl
  journal/journal-7d.log
  files/etc/acme/server.yaml      source path with the root stripped (Windows: files/C/ProgramData/...)
  manifest.json                   last: it needs every hash
```

Names are sanitized: no `..`, no absolute paths, control characters become `_`, components at most 255
bytes, collisions get `-2`, `-3`. `<ts>` is the basic ISO 8601 form from ADR 0003.

### 5.2 Where it is written

`rdy bundle` follows ADR 0003: it creates a new directory `rdy-bundle-<product>-<ts>/` under `--out-dir`
through `cap-std` (mode 0700, `create_new`, no symlink following, temp file then rename). Inside:
`rdy-bundle-<product>-<ts>.tar.zst` (0600) and `rdy-bundle-<product>-<ts>.tar.zst.sha256`. The manifest
cannot hold the archive's own hash, so the sidecar and the upload receipt hold it. An interrupted run removes
the `.tmp` file and writes nothing.

### 5.3 Compression

`zstd` level 3, window log 23 (8 MiB, so any decoder can read it), content checksum on, one frame, no
dictionary, one thread. Extension `.tar.zst`. A 256 MiB log-heavy bundle compresses in a few seconds and
usually lands near 10 to 30 MiB.

### 5.4 Manifest

`manifest.json` is a wire type in `rdy_spec::bundle` with a generated schema (Plan corrections, ADR 0012).
Appendix C has a full sample. It holds:

- **Provenance:** bundle id (UUID v4), `created_at`, producer (rdy version, commit, target), the result's
  `run.id` when a result is included, the spec reference (`product`, `version`, `serial`, `sha256`, file name,
  signature state, key id, `signed_at`), and `host_id` and OS family (the same derivation as the result).
- **Redactor:** set id and every rule version applied, groups switched on by the spec, by the customer's
  flags, and always.
- **Entries**, one per file in the archive and one per collector outcome that produced no file: `path`,
  `collector` (the exact `collect:` string), `status`, `reason`, `source` (redacted path), `bytes_in` (raw
  bytes read, a count), `bytes_out`, `sha256` (of the stored redacted bytes), `redactions` by rule,
  `residual_hits`, `truncated`, `truncation` (`head` or `tail`), `transcoded_from`, `collected_at`.
- **Totals and caps:** file count, bytes, redactions by rule, caps in force, caps hit, `degraded` list with
  hints.

**No hash of raw content. Ever.** The brief says "sha256 before and after redaction (before-hash of redacted
content only, never of the raw)". I read that as: no hash of raw bytes exists anywhere. Reasons: a hash of a
file with a known template and one unknown secret is a guessing oracle; a hash of a secret is derived from
it; and nothing needs it, since integrity of what was sent is proved by the hash of the stored bytes. So an
entry has `bytes_in` (a count) and `sha256` of the stored redacted bytes (before compression), and the
sidecar has the sha256 of the compressed archive (after compression). If the intent was different, change it
here before building.

### 5.5 Size caps

Defaults, all lowered (never raised) by `--max-size` and the spec's proposed `bundle.max_size`:

| Scope | Cap | Keeps | Time cap |
| --- | --- | --- | --- |
| `journal` | 32 MiB | tail | 120 s |
| `host:kernel_log` | 8 MiB | tail | 30 s |
| `host:processes` | 2 MiB | head | 15 s |
| `host:network` | 2 MiB total | head | 30 s |
| `host:disk` | 1 MiB | head | 30 s |
| `container:runtime` | 8 MiB total | head | 60 s |
| `k8s:events` | 8 MiB per namespace | whole objects | 60 s |
| `k8s:describe` | 8 MiB per kind, 32 MiB total | whole objects | 120 s |
| `file:` | 4 MiB per file (tail for `*.log`, `*.out`, `*.err`, `messages`, `syslog`), 32 MiB and 200 files per glob | head or tail | 60 s per glob |
| `rdy:result` | 16 MiB | head | 15 s |
| Bundle, raw, after redaction | 256 MiB | by priority | 10 min |
| Bundle, archive | 100 MiB (soft stop at 90 MiB written) | by priority | none |

**When a cap is hit, the bundle still succeeds.**

- The entry is cut and a marker line is added, for example
  `[rdy: truncated, kept the last 33554432 bytes (journal cap)]` at the top of a tail-kept entry, or
  `[rdy: truncated, kept the first 4194304 of at least 9812345 bytes (per-file cap)]` at the end of a head-kept
  one. The manifest sets `truncated: true`. Kubernetes files are JSON Lines, so the cut falls between
  objects.
- If the raw total would pass 256 MiB, the current entry is truncated to the remaining budget minus a 256 KiB
  reserve for each collector still to run. Collectors after the budget is gone get `skipped: total_cap`.
  Nobody is starved.
- The archive soft stop works the same way. The final CLI summary lists every cap hit.
- `rdy upload` refuses an archive over 100 MiB and prints `fix: run rdy bundle --max-size 128MiB`, or send it
  another way. The bundle is not lost.

## 6. The opt-in upload flow

> security-reviewer to confirm

Endpoints, headers and responses below are a proposal for `rdy-cloud` to accept (SEC-42 owns the token
format). The client rules are what the CLI will enforce whatever the server does.

### 6.1 Invariant

Nothing leaves the machine unless the user typed `rdy upload` (or `--upload` on `run` or `bundle`) and then
either answered `y` at the prompt or passed `--yes`. `rdy run` and `rdy bundle` open no socket for
uploading. `rdy bundle` contacts only the Kubernetes API through the guard (and only if a `k8s:` collector is
listed). Tested under `unshare -n` and `strace` (SEC-22 extended). This is INV-20, plus the additions in
"Plan corrections".

### 6.2 Step by step

**Step 0. Pre-flight, no network.**

1. The file must be a regular file, not a symlink, owned by the caller. At most 100 MiB for a bundle and 16 MiB
   for a result.
2. It must be one of two things. A result: `.json` that validates against `result.v1.schema.json`. HTML is
   refused ("upload the .json file"). A bundle: `.tar.zst` whose frame decodes, whose `manifest.json` parses
   and whose entry hashes match the manifest. Nothing else uploads, so `rdy upload /etc/shadow` fails here.
3. Compute `sha256` and the size of the exact bytes to send.

**Step 1. Token.** Precedence: `--token-file`, then `RDY_TOKEN`, then a hidden prompt on a TTY.

- `--token-file <path>` (or `-` for stdin) is the one for scripts. On Unix the file must not be a symlink or
  readable by group or others. It is read up to 256 bytes and trimmed.
- `RDY_TOKEN` is for CI. It stays out of the process list but is readable by the same user and root through
  `/proc/<pid>/environ`. rdy cannot clear it in a `forbid(unsafe_code)` build (`remove_var` is unsafe in
  edition 2024), so it relies on the facade's cleared child environment: no child ever sees it.
- The prompt is the default for a person: `Share-link token (input hidden):`, read with no echo.
- There is no `--token <value>`. A hidden flag of that name exists only to exit 64 with: "tokens on the
  command line show up in shell history and in `ps` for other users. Use `--token-file`, `RDY_TOKEN` or the
  prompt." On Linux `/proc/<pid>/cmdline` is world-readable by default. `environ` is not.
- With no TTY and no token: exit 64, `fix: set RDY_TOKEN or use --token-file`.
- The token is checked locally against `^rdy_st_[A-Za-z0-9]{20,64}$` before any request. A mistyped value, or
  a password pasted into the prompt by accident, never leaves the box.
- The token goes only into the `Authorization` header of requests to the consented origin. It is never in a
  URL, a log line, the receipt or an error. The `rdy_st_` rule redacts it everywhere else.

**Step 2. Consent.** On a TTY the client prints this and waits. Default is no.

```text
About to upload to https://app.getrdy.io (Rdy Cloud):

  file      rdy-bundle-acme-platform-20261104T101500Z.tar.zst
  size      12.4 MiB (38 files, 61 MiB unpacked)
  sha256    9f2c...e41a
  redacted  3 aws_keys, 2 bearer_tokens, 14 emails (by rdy, before writing)
  spec      acme-platform, signed, key 7A3F9C21B04D55E1
  token     rdy_st_...Q7XA

rdy sends this file, its name, size and SHA-256, and the rdy version. Nothing else.
To read what is inside first:  tar --zstd -xOf <file> '*/manifest.json'
Upload this file? [y/N]
```

For a result JSON the `redacted` line shows the result's `redaction` summary. A server other than the default
(set with `--server`, `https` only, no userinfo; `http` only for `localhost` in tests) adds a line in bold:
`server    https://staging.example.test (NOT the default Rdy Cloud server)`. The same line goes into the receipt.
With no TTY, `--yes` is required. Without it: exit 64, `fix: add --yes to confirm the upload, or run this in
a terminal`. A non-TTY run never prompts. A command pasted from a vendor email must not carry `--yes`; the
docs say so.

**Step 3. Create the upload.** `POST /api/v1/uploads` with the token in `Authorization`, a JSON body of
`kind` (`bundle` or `result`), `file_name`, `size`, `sha256` and `rdy_version`, and an `Idempotency-Key` made
once per run. The server answers `201` with `upload_id`, `max_bytes` and `expires_at`. Only these three
fields are read, and `upload_id` must match `^upl_[A-Za-z0-9]{16,64}$`. If `size` exceeds `max_bytes`, the
client stops and prints the size fix. This request carries metadata only. A failure here means no file bytes
left the machine, and the CLI says so. Appendix E has the exact bytes.

**Step 4. Send the bytes.** One `PUT /api/v1/uploads/<upload_id>/content`. The client builds the URL from the
id. It does not take a URL from the server. Headers: `Authorization`, `Content-Type` (`application/zstd` or
`application/json`), `Content-Length`, `Content-Digest: sha-256=:<base64>:`, `User-Agent`. The body is the
exact bytes of the file, streamed, with no extra compression and no chunked encoding. The server answers
`200` with `receipt_id`, `upload_id`, `received_bytes` and `sha256`. The client checks the last two against
its own values. A mismatch is an error, even on a `200`.

**Step 5. Receipt and output.** The client writes `upload-receipt.json` next to the file (`create_new`, 0600):
receipt version, time, server origin, file name, kind, size, sha256, upload id, receipt id, the server's
echoed size and hash, rdy version. No token, no argv. If the directory is not writable, it prints the receipt
instead.

```text
uploaded    rdy-bundle-acme-platform-20261104T101500Z.tar.zst (12.4 MiB)
sha256      9f2c...e41a  (the server reports the same)
receipt     rcp_9Qx4...  saved to ./upload-receipt.json
```

Server text is never printed raw. Errors map error codes to fixed local messages (`token_expired`,
`token_revoked`, `too_large`, `rate_limited`, `bad_digest`, `unsupported`). Anything unknown prints the HTTP
status and "unexpected answer from the server". Response bodies over 64 KiB are discarded.

### 6.3 Transport rules

- Client: the M2 upload client from ADR 0009 (reqwest, rustls with `ring`, platform verifier), no redirects
  (so the token cannot follow one to another host), the address policy on the server address, no cookies.
  `User-Agent` carries the rdy version and target only. No telemetry.
- Timeouts: connect 15 s (TLS included), 60 s without body progress, 60 s for the response, 30 min in all.
- Retries: connect errors, timeouts, `408`, `429`, `502`, `503`, `504`. At most 4 attempts, waits of 2 s, 8 s
  and 30 s with 20% jitter, `Retry-After` honoured up to 60 s. A retry repeats the whole `PUT` to the same
  `upload_id`, so the server must accept a repeat of the same digest and return the same receipt. Other `4xx`
  do not retry. The prompt is never asked twice.
- Proxy: `HTTPS_PROXY` and `NO_PROXY` as in ADR 0009, with the `ProxyUrl` mask. On `407` the CLI says the proxy
  wants credentials and shows the variable form without the password. NTLM and Negotiate are not supported;
  the hint points to the manual route. A TLS failure behind an interception proxy prints `SSL_CERT_FILE`
  advice and points at the `net.tls_intercept` result.

### 6.4 Offline

If step 3 cannot connect (DNS, refused, TLS, timeout), the CLI prints this and exits 70:

```text
error: could not reach app.getrdy.io. Nothing was sent.
fix: check the network or proxy, then run the same command again.
Your file is safe here: ./rdy-bundle-acme-platform-20261104T101500Z/rdy-bundle-....tar.zst
  sha256 9f2c...e41a
To send it without this tool: open the share link in a browser and drop the file on the page,
or send it to the contact in the spec: <metadata.contact, as plain text>
```

The contact is spec text and passes the control-character filter. If the failure comes after bytes were
sent, the CLI says the server may hold a partial copy that it should discard. `rdy bundle` and `rdy run`
never fail because upload is unavailable.

### 6.5 Open questions for security-reviewer and rdy-cloud

- A single `PUT` restarts from zero on a bad link: about 7 minutes per try at 100 MiB and 2 Mbit/s. Resumable
  upload is an M3 decision, once a design partner hits it.
- Will `rdy-cloud` accept `Content-Digest`, an idempotent repeat of a `PUT`, and a web drop page on the share
  link? The offline text depends on the last one.
- Spec fetch with `--token` is a different request, owned by SEC-42 and the portal.

## 7. The `rdy bundle` command surface

cli-ux owns the final names. This is the proposal.

```text
rdy bundle <spec> [--result <report.json>] [--out-dir <dir>] [--namespace <ns>] [--context <name>]
                  [--kubeconfig <path>] [--skip <collector-id>]... [--redact <group>,...]
                  [--redact-pattern <regex>]... [--max-size <size>] [--plan] [--list-collectors]
                  [--list-redactors] [--allow-unsigned] [--json] [--upload [--yes]]
rdy upload <file> [--token-file <path|->] [--server <https-url>] [--yes] [--json]
rdy redact [<file>|-]            # prints the redacted text. Lets a customer try the redactor. M2.
```

- `<spec>` is verified like `run` (ADR 0002). Without a `bundle:` block it exits 64:
  `fix: ask the vendor for a spec with a bundle: section`. The spec decides what is collected.
- `--result` embeds a result JSON. It is validated against the schema and redacted again, because rdy did not
  just produce it. `rdy run --bundle` (cli-ux to decide) would pass the in-memory report instead.
- `--redact` adds groups. `--redact-pattern` adds a regex. Neither can remove anything.
- `--plan` prints collectors, commands, resolved files and caps. It reads nothing and makes no request.
- Exit codes: 0 bundle written, even if collectors degraded. 64 usage, spec or signature problem, unknown
  redactor group. 70 cannot write the output. A bundle has no readiness verdict. `rdy upload` exits 0 on
  success, 64 on bad input or a refused consent, 70 when it cannot deliver.
- `--json` prints the manifest summary on stdout (not the archive).

Appendix F has a sample run.

Docs-site pages (09) list collectors and redactors from `--list-collectors` and `--list-redactors`, so the
page cannot drift from the code.

## Appendix A: collectors per OS

Defaults are in section 5.5. "Facade" is the call used. All commands are `&'static str` programs resolved
from the fixed search path (ADR 0004, INV-08). M2 builds Linux and Kubernetes. macOS and Windows columns mark
what is planned. A `-` means no data source yet (reason `not_yet_on_os`).

| Id | Linux | macOS | Windows | Privilege and degrade |
| --- | --- | --- | --- | --- |
| `file:<glob>` | `read_dir`, `read_stream` | same | same, `C:\` paths | permission denied gives an entry `partial` with the hint. Deny list always applies |
| `journal:<d>` | `exec journalctl --no-pager -o short-iso --since -<d> -n 200000` | `-` (M3: `log show --last <d>`) | `-` (M3: `wevtutil qe`) | non-root sees only the user journal: `partial`, hint "run as root or join systemd-journal". No journald: `skipped no_journald`. Duration 1h to 30d |
| `host:processes` | `read_dir /proc`, `read /proc/<pid>/stat` and `status` | `exec ps -axo pid,ppid,uid,state,etime,rss,comm` | `exec tasklist /fo csv` | none. `cmdline` and `environ` are never read. `/proc/*/environ` is on the deny list |
| `host:network` | `exec ip -details addr`, `ip route`, `ss -tuln`, `read /etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`; proxy variable names via `Probe::env` | `exec ifconfig -a`, `netstat -rn`, `scutil --dns`, `scutil --proxy` | `exec ipconfig /all`, `route print`, `netsh winhttp show proxy` | `ss -p` owners need root: without it the process column is empty and the entry says so. A missing tool is one `skipped` sub-entry, the rest continue |
| `host:disk` | `native` (sysinfo disks) and `read /proc/mounts` | `native` | `native` | none. `statvfs` runs on `spawn_blocking` under the time cap, so a hung NFS mount ends as `partial` |
| `host:kernel_log` | `exec dmesg --time-format iso`; fallback `exec journalctl -k -b --no-pager` | `-` | `-` (system events are in `eventlog`, M3) | `dmesg_restrict=1` and not root: fallback, then `partial` |
| `container:runtime` | `exec docker version`, `docker info`, `docker ps -a`, `docker images`; `crictl info`, `crictl ps -a`; `podman info`; read `/etc/docker/daemon.json`, `/etc/containerd/config.toml` | `exec docker version`, `docker info` | same | needs docker group or root. Each runtime is probed separately. Not installed gives `skipped not_present`. Auth blocks in daemon configs are caught by the key-name rule |
| `k8s:events` | kube `list events` per install namespace, `limit=500`, at most 5,000 objects | same | same | RBAC `forbidden`: `skipped` with the verb and resource. No kube context: `skipped no_kube_context` |
| `k8s:describe:<ns>` | kube `get` or `list` of pods, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs, services, endpointslices, ingresses, networkpolicies, persistentvolumeclaims, resourcequotas, limitranges, plus configmap metadata | same | same | each kind is independent. `env[].value`, `last-applied-configuration` and `managedFields` are removed before redaction. Secrets are never requested |
| `rdy:result` | in memory plus the verified spec bytes | same | same | none |

The Kubernetes rows need the guard allowlist extended (Plan corrections). `pods/log` stays refused until
`k8s:logs` has its own ADR.

## Appendix B: redaction rules

Rule names appear in placeholders and the manifest. Group is the name a spec uses. Versions start at 1.
Patterns are sketches. The code is the source of truth and the corpus is its test.

| Rule | Group | M | Matches | Replaced span |
| --- | --- | --- | --- | --- |
| `url_userinfo` | `url_credentials` | 1 | `scheme://user:pass@host`, `scheme://token@host`, percent-encoded userinfo | the userinfo only |
| `auth_header` | `bearer_tokens` | 1 | `Authorization:` and `Proxy-Authorization:` values (Bearer, Basic, Token, any scheme), `-H 'Authorization: ...'`, bare `Bearer <token>` | the credential |
| `api_key_header` | `bearer_tokens` | 1 | `X-Api-Key`, `X-Auth-Token`, `Cookie` and `Set-Cookie` values | each value |
| `aws_access_key_id` | `aws_keys` | 1 | `(AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}` | the id |
| `aws_secret_access_key` | `aws_keys` | 1 | by key name (`aws_secret_access_key`, `SecretAccessKey`) and a 40-char base64 value within 80 chars of a key id | the value |
| `aws_session_token` | `aws_keys` | 1 | by key name (`aws_session_token`, `SessionToken`, `x-amz-security-token`) | the value |
| `pem_private_key` | `private_keys` | 1 | `-----BEGIN [A-Z0-9 ]*PRIVATE KEY...-----` to END, plain or with literal `\n`; unterminated blocks | the whole block |
| `kubeconfig_credential` | `kubeconfig` | 1 | keys `token`, `client-key-data`, `password`, `access-token`, `refresh-token`, `id-token`, `client-secret` in YAML or JSON. `certificate-authority-data` and `client-certificate-data` are public and stay | the value |
| `rdy_share_token` | `rdy_tokens` | 1 | `rdy_st_[A-Za-z0-9]{20,64}` | the token |
| `secret_by_key` | `secrets_by_key` | 1 | a key containing `pass`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential`, `auth`, `bearer`, `dsn` followed by `=` or `:`, in env, YAML, JSON, INI, flags (`--password=x`), systemd `Environment=`, connection strings (`Password=...;`, `AccountKey=...`) | the value, without quotes |
| `jwt` | `jwt` | 2 | `eyJ...` three base64url parts | the token |
| `github_token`, `gitlab_token`, `slack_token`, `stripe_key`, `google_api_key`, `npm_token`, `pypi_token`, `docker_pat` | `saas_tokens` | 2 | documented prefixes (`gh[pousr]_`, `github_pat_`, `glpat-`, `xox[baprs]-`, `[sr]k_live_`, `AIza`, `npm_`, `pypi-`, `dckr_pat_`) | the token |
| `gcp_service_account_key`, `azure_credential` | `cloud_credentials` | 2 | `"private_key"` in service-account JSON, `client_secret`, SAS `sig=`, `AccountKey=` | the value |
| `k8s_secret_data` | `k8s_secrets` | 2 | `data:` and `stringData:` values inside a `kind: Secret` document | each value |
| `email` | `emails` | 2 | `local@domain.tld`, also `\u0040` and `%40` forms | the address |
| `ipv4` | `ipv4` (opt-in) | 2 | dotted quads that parse as addresses. `127.0.0.0/8`, `0.0.0.0`, `255.255.255.255` stay | the address |
| `ipv6` | `ipv6` (opt-in) | 2 | candidates that parse with `Ipv6Addr`. `::1` and `::` stay | the address |
| `mac` | `mac` (opt-in) | 2 | six hex pairs | the address |
| `entropy_token` | `entropy` | 2 | see 3.7: 24 or more chars, 4.0 bits per char or more, three character classes. Not pure hex of length 32, 40 or 64, UUIDs, `sha256:` digests, data URIs | the token |
| `custom.<name>` | spec or `--redact-pattern` | 2 | Rust regex, per record, never across lines | the whole match, or group `secret` if named |

Key-name exclusions (corpus-tuned): values that are empty, `null`, `true`, `false`, `none`, `required`; shell
or template references (`${X}`, `$(...)`, `{{ ... }}`); `valueFrom` and `secretKeyRef` blocks; keys ending in
`name`, `ref`, `file`, `path`, `namespace`; paths under `/run/secrets/`.

## Appendix C: manifest sample

```json
{
  "api_version": "rdy/v1",
  "kind": "BundleManifest",
  "bundle": { "id": "6c1f3c0e-2d54-4c52-9d4e-0a8f1e7c9b11", "created_at": "2026-11-04T10:15:00Z" },
  "producer": { "name": "rdy", "version": "0.2.0", "commit": "abc1234", "target": "x86_64-unknown-linux-musl" },
  "run_id": "b2d7f4a0-8e0c-4a61-8f3e-5c9a1d2e7f10",
  "spec": {
    "file_name": "acme-platform.yaml", "sha256": "<64 hex>", "product": "acme-platform", "version": ">=4.2",
    "serial": 7, "signature": { "state": "verified", "key_id": "7A3F9C21B04D55E1", "signed_at": "2026-10-30T09:00:00Z" }
  },
  "host": { "host_id": "0123456789abcdef", "os_family": "linux", "arch": "x86_64" },
  "redactor": {
    "set": "rdy-redact/1",
    "rules": [ { "name": "aws_access_key_id", "version": 1 }, { "name": "email", "version": 1 } ],
    "groups_always": ["aws_keys", "bearer_tokens", "private_keys", "emails"],
    "groups_from_spec": ["aws_keys", "bearer_tokens", "emails"],
    "groups_from_flags": ["ipv4"]
  },
  "entries": [
    {
      "path": "files/etc/acme/server.yaml", "collector": "file:/etc/acme/*.yaml", "status": "ok",
      "source": "/etc/acme/server.yaml", "bytes_in": 2210, "bytes_out": 2144, "sha256": "<64 hex of the stored bytes>",
      "redactions": { "secret_by_key": 2, "email": 1 }, "residual_hits": 0,
      "truncated": false, "collected_at": "2026-11-04T10:15:02Z"
    },
    {
      "path": "journal/journal-7d.log", "collector": "journal:7d", "status": "partial", "reason": "cap",
      "bytes_in": 91234567, "bytes_out": 33554432, "sha256": "<64 hex>",
      "redactions": { "aws_access_key_id": 3, "auth_header": 2, "email": 13 }, "residual_hits": 0,
      "truncated": true, "truncation": "tail", "collected_at": "2026-11-04T10:15:09Z"
    },
    { "path": null, "collector": "k8s:describe", "status": "skipped", "reason": "no_install_namespace",
      "hint": "add --namespace <ns>" }
  ],
  "totals": { "files": 38, "bytes_out": 64012345, "redactions": { "email": 14, "aws_access_key_id": 3 } },
  "caps": { "raw_bytes": 268435456, "archive_bytes": 104857600, "hit": ["journal:7d"] },
  "degraded": [ { "collector": "journal:7d", "reason": "cap", "hint": "kept the last 32 MiB" } ],
  "timing": { "started_at": "2026-11-04T10:15:00Z", "finished_at": "2026-11-04T10:15:41Z" }
}
```

Never in the manifest: a raw value, a raw hash, the tag key, a token, environment values, argv, user names.

## Appendix D: M1 corpus plan (71 cases)

| Category (directory) | Core positive | Hostile, negative or gap | Notes |
| --- | --- | --- | --- |
| `url` | 8 | 0 | http, https with port, proxy URL, Postgres DSN, Redis, AMQP, percent-encoded password, token-only userinfo |
| `auth` | 8 | 0 | Bearer, lowercase bearer, Basic, `Token`, Proxy-Authorization, `X-Api-Key`, Cookie, quoted curl header |
| `aws` | 8 | 0 | AKIA id, ASIA id, env secret, JSON `SecretAccessKey`, INI credentials file, session token, id and secret on one log line, vendor example key |
| `pem` | 6 | 0 | RSA, EC, OpenSSH, PKCS8, encrypted, JSON-escaped `\n`, unterminated |
| `kubeconfig` | 6 | 0 | `token`, `client-key-data`, `refresh-token`, `id-token`, exec-plugin env, auth-provider config |
| `rdy_token` | 3 | 0 | plain text, JSON, Authorization header |
| `key_name` | 12 | 0 | env, `export`, YAML, JSON, INI, `--password=`, quoted with spaces, systemd `Environment=`, compose list, camelCase key, URL query `access_token=`, connection string |
| `hostile` | 0 | 10 | 8 secrets in hostile forms that must be redacted: JSON-escaped quote, percent-encoded, ANSI-wrapped, YAML block scalar, multi-line, tabs, CRLF, very long line, plus 2 `known_gap` (unredacted on purpose): fullwidth-letter key name, base64-wrapped short password |
| `negative` | 0 | 10 (must not change) | git SHA, `sha256:` digest, UUID, semver, data URI, long pod name, image reference with digest, `BEGIN CERTIFICATE`, `secretName`, prose containing "password" |
| Total | 51 | 20 | 71 files, above the floor of 60 |

Negatives, in full: git SHAs (40 hex), `sha256:` image digests, UUIDs, semver and calendar versions
(`4.2.1-rc.1`), `data:image/png;base64,` URIs, long Kubernetes names (`acme-platform-worker-7f9c6d8b5-x2k4m`), file
paths, `BEGIN CERTIFICATE` blocks (public), `secretName: acme-tls`, `secretKeyRef` blocks, `${DB_PASSWORD}`
references, empty values, and prose such as "password policy requires 12 characters".

Cut order if M1 time runs out (the ADR review table agrees): keep 30 positives for `0.1.0` and add the rest by
`0.1.1`, keep the property tests for `0.1.1`, keep the kubeconfig rule as key names inside `secret_by_key`.

## Appendix E: upload wire sample

```text
POST /api/v1/uploads HTTP/1.1
Host: app.getrdy.io
Authorization: Bearer rdy_st_<token>
Content-Type: application/json
Accept: application/json
User-Agent: rdy/0.2.0 (x86_64-unknown-linux-musl)
Idempotency-Key: <uuid v4>

{"kind":"bundle","file_name":"rdy-bundle-acme-platform-20261104T101500Z.tar.zst",
 "size":13002752,"sha256":"9f2c...e41a","rdy_version":"0.2.0"}

HTTP/1.1 201 Created
{"upload_id":"upl_7Hk2...","max_bytes":104857600,"expires_at":"2026-11-04T11:15:00Z"}

PUT /api/v1/uploads/upl_7Hk2.../content HTTP/1.1
Host: app.getrdy.io
Authorization: Bearer rdy_st_<token>
Content-Type: application/zstd
Content-Length: 13002752
Content-Digest: sha-256=:<base64 of the digest>:
User-Agent: rdy/0.2.0 (x86_64-unknown-linux-musl)

<exact bytes of the file>

HTTP/1.1 200 OK
{"receipt_id":"rcp_...","upload_id":"upl_7Hk2...","received_bytes":13002752,"sha256":"9f2c...e41a"}
```

Nothing else is sent: no cookies, no host details beyond what is in the file, no telemetry. The result-JSON
upload is the same with `"kind":"result"` and `Content-Type: application/json`.

## Appendix F: sample `rdy bundle` output

```text
$ rdy bundle acme-platform.yaml --result rdy-report-acme-platform-20261104T100900Z/rdy-report-acme-platform-20261104T100900Z.json
Collecting 7 collectors. No network. Nothing is uploaded.
  ok       rdy:result           3 files    41 KiB
  ok       file:/etc/acme/*.yaml  4 files  18 KiB
  ok       host:processes       1 file     38 KiB
  partial  journal:7d           1 file     32 MiB  kept the last 32 MiB (cap)
  skipped  k8s:describe         no install namespace. fix: add --namespace <ns>
redacted    3 aws_keys, 2 bearer_tokens, 14 emails, 1 private_keys
skipped     2 binary files
wrote       ./rdy-bundle-acme-platform-20261104T101500Z/rdy-bundle-acme-platform-20261104T101500Z.tar.zst (12.4 MiB, 38 files)
not uploaded. To send it: rdy upload <path>  (read manifest.json first)
```

## Plan corrections found

- docs/plan/00-overview.md, `rdy-bundle` sketch: a `Redactor` trait with `redact(&self, &str) -> Cow<str>`,
  one object per redactor. That cannot do span merging, stable tags or streaming. Fix: one `Redactor` struct
  built from a compiled rule set (section 3). Keep a trait only for `Collector`.
- docs/plan/00-overview.md, `build(spec, ctx, out: &Path)`: it takes a plain path. Fix: take the `cap-std`
  `OutputDir` from 02 and return the manifest. The writer accepts only `Redacted` bytes.
- CLAUDE.md, repo layout: `rdy-bundle/ collectors, redactors, tar+zstd, manifest`. Redactors live in
  `rdy-engine::redact` (02, ADR 0015). Fix: `rdy-bundle/ collectors, tar+zstd, manifest (reuses rdy-engine::redact)`.
- docs/plan/00-overview.md lines 46 and 397, rdy-plan.md "How a POC flows": `rdy run acme-platform --token abc123`
  puts a bearer token in argv. 05 Surface 4 forbids it and `/proc/<pid>/cmdline` is world-readable on Linux.
  Fix: the vendor one-liner uses `RDY_TOKEN` (or `--token-file`, or the prompt), and a hidden `--token` exits 64
  with the reason.
- docs/plan/05-threat-model.md, Surface 4 point 2: "Upload reads only files listed in the output dir manifest".
  No such manifest exists in M1 (ADR 0003, 02). Fix: upload accepts only a schema-valid result JSON or a bundle
  whose manifest and hashes verify (section 6.2). Point 5 ("a receipt id and a URL") becomes "an upload id, a
  receipt id, a byte count and a hash"; the client builds URLs itself.
- docs/plan/05-threat-model.md invariants vs docs/plan/02-engine-design.md: 02 cites an earlier numbering
  (INV-14 for redaction, INV-08 for output confinement, INV-06 for file reads and the action log, INV-10 for
  network peers). 05's table now has INV-15, INV-09, INV-07 and INV-11, and no invariant for the action log.
  Fix: renumber 02's references to 05's table, and add INV-21 to INV-26 from the list below to 05.
  - INV-21: every byte in a bundle passed the redactor (the writer accepts only `Redacted`), and no temp file
    holds raw bytes. Test: canaries in every collector fixture are absent from the archive and from every
    other file the run created.
  - INV-22: the manifest holds no raw value, no raw hash and no tag key. Test: canary grep.
  - INV-23: `rdy bundle` opens only the guarded kube client's connection. Test: contact-set under `unshare -n`.
  - INV-24: no collected path is on the deny list, and a spec cannot remove a built-in rule. Test: fixtures.
  - INV-25: the bytes sent hash to the value shown at consent. Test: fake server.
  - INV-26: the token is never in argv, logs, the receipt or errors. Test: canary at `RUST_LOG=trace`.
- docs/plan/05-threat-model.md, Appendix F: replacements are `[REDACTED:aws_access_key_id]`. Fix: add the
  keyed tag, `[REDACTED:<rule>:<tag>]`, and say the corpus normalizes it.
- docs/plan/02-engine-design.md, probe facade: reads and command output are capped at 1 MiB. A journal
  collector needs more. Fix: streaming `read_stream` and `exec_stream` with a cap declared in `CollectorInfo`,
  amending ADR 0014. The ticket "rdy-bundle collectors read through the probe facade" (4h) becomes 6h.
- docs/plan/02-engine-design.md, deny list: it lacks files that matter once root collects by glob. Add
  `*/.docker/config.json`, `*/.config/containers/auth.json`, `*/.aws/credentials`, `*/.netrc`,
  `*/.git-credentials`, `*/.npmrc`, `*/.pgpass`, `/etc/ssh/ssh_host_*_key`, `/etc/kubernetes/pki/*`,
  `/var/lib/kubelet/pki/*` and `/etc/kubernetes/*.conf` (admin.conf holds `client-key-data`). SEC-43 owns it.
- docs/adr/0010-kubernetes-client-kube-rs.md and the guard table in 02: allowed kinds are the check set only,
  and `pods/log` is refused. Bundle needs list on the kinds in Appendix A and `events`. Fix: an ADR 0010
  amendment that names the kinds. `pods/log` stays refused until the `k8s:logs` ADR.
- docs/adr/0012-wire-types-in-rdy-spec-schema-generated.md: the manifest is a wire format `rdy-cloud` reads.
  Fix: put it in `rdy_spec::bundle` with `bundle-manifest.v1.schema.json`, so `rdy-cloud` does not depend on
  `tar` or `zstd`.
- crates/rdy-spec/schema/result.v1.schema.json: no `redaction` field, although ADR 0012 decision 3 lists
  `redactions`. Fix: add `redaction { ruleset, total, by_rule }` (M1 ticket below).
- crates/rdy-spec/schema/spec.v1.schema.json, `Bundle`: it has no custom pattern list and no size cap, and its
  `redact` text can read as "the vendor chooses". Fix: add optional `redact_patterns: [{name, regex}]` (at most
  32) and `max_size`, both additive under ADR 0007, and reword `redact` to "adds groups; the built-in minimum
  always runs".
- docs/plan/10-devrel-and-launch.md, day 5 sample: `wrote ./rdy-bundle.tar.zst` and `redacted ... aws_keys`.
  Fix: the file sits in a new directory (ADR 0003 style) and the summary prints groups as in section 7.
- docs/plan/05-threat-model.md, SEC-25 (4h) and SEC-26 (3h): they cover the redactor, the corpus, the log layer
  and the property tests in 7 hours. The tickets below total 38.5 hours. M1 is already over budget (02). The
  cut order is in Appendix D.

## Decisions needing an ADR

- **ADR 0015 content (rust-architect writes it in M1).** Inputs from here: the module has its own feature
  `redact` so `rdy-cloud` can reuse it; the span-merge model; keyed placeholder tags; rules compiled in with no
  rule files; a spec cannot remove built-in rules; no hash of raw content anywhere; a `Redacted` type gates
  every writer. Conservative choice taken: all of these.
- **Manifest wire types in `rdy-spec`** (extends ADR 0012) rather than in `rdy-bundle`. Alternative: keep them
  in `rdy-bundle` and let `rdy-cloud` depend on it. Conservative choice: `rdy-spec`.
- **Compression crate.** `zstd` (C libzstd, mature, good ratio) or `ruzstd` (pure Rust, fewer features, weaker
  ratio). Conservative choice taken: `zstd` for correctness, flagged for security-reviewer because it adds C to
  a root binary and to the musl build.
- **Upload transport.** Single `PUT` to one origin, idempotent. Alternatives: presigned object-store URL (a second
  destination to allow and show), resumable upload (tus or ranges). Conservative choice: single `PUT`, same
  origin, no server-supplied URLs.
- **Kubernetes guard amendment for bundles** (ADR 0010). Alternative: allow `pods/log` now. Conservative choice:
  object lists and events only; no `pods/log`, no Secrets.
- **Where k8s collectors live.** In `rdy-bundle` behind a `k8s` feature, using the guarded client from
  `rdy-checks-k8s`. Alternatives: inside `rdy-checks-k8s` (makes it depend on `rdy-bundle`), or a new crate.
  Conservative choice: `rdy-bundle`, no new crate.

## Tickets implied

Reused tickets keep their exact titles so 11-backlog.md can dedupe. Scope notes sit in the exit test.

- [M1] Write ADR 0015 minimal redactor lives in rdy-engine | owner: rust-architect | est: 1h | depends on: none | exit test: the ADR records the `redact` feature, span merge, keyed placeholder tags, no rule files, no raw hashes and the `Redacted` writer gate, and carries a security-reviewer sign-off.
- [M1] Redactor core: rule table, span merge and keyed placeholder tags | owner: rust-engineer | est: 4h | depends on: Write ADR 0015 minimal redactor lives in rdy-engine, Define result model and verdict mapping in rdy-spec | exit test: unit tests show overlapping rules resolve by priority then length, equal secrets share a tag inside one Redactor and differ in another, redact(redact(x)) equals redact(x), and the key's Debug output is masked.
- [M1] Redaction rules for URL userinfo, auth headers, cookies and rdy share tokens | owner: rust-engineer | est: 3h | depends on: Redactor core: rule table, span merge and keyed placeholder tags | exit test: userinfo, Basic, Bearer, Proxy-Authorization, X-Api-Key, Cookie and rdy_st_ canaries are gone while scheme, host and header names stay.
- [M1] Redaction rules for AWS keys and secrets by key name in env, YAML, JSON and INI | owner: rust-engineer | est: 4h | depends on: Redactor core: rule table, span merge and keyed placeholder tags | exit test: AWS id, secret and session canaries, PASSWORD=, "client_secret": and --password=x are replaced with quotes and delimiters kept, while secretName: acme-tls, ${DB_PASSWORD} and empty values are untouched.
- [M1] Redaction rules for PEM private keys and kubeconfig credentials | owner: rust-engineer | est: 3h | depends on: Redactor core: rule table, span merge and keyed placeholder tags | exit test: RSA, EC, OpenSSH, PKCS8 and encrypted keys in plain, JSON-escaped and unterminated forms and client-key-data, token and refresh-token values are replaced, and a BEGIN CERTIFICATE block is not.
- [M1] Apply the redactor to every Report string before return | owner: rust-engineer | est: 2h | depends on: Redactor core: rule table, span merge and keyed placeholder tags, Map outcomes to CheckResult with fix source, partial and size caps | exit test: canaries in an observed value, a fix text, an env-derived message and an action-log argv are redacted in JSON and HTML, and the report carries per-rule counts.
- [M1] Redacting tracing layer, panic hook and error strings | owner: rust-engineer | est: 3h | depends on: Redactor core: rule table, span merge and keyed placeholder tags | exit test: at RUST_LOG=trace canaries in env, a proxy URL and command output never reach stderr, and a panic message and an anyhow chain pass through the redactor.
- [M1] Add the redaction summary to the result schema | owner: rust-architect | est: 1h | depends on: Generate JSON schemas with schemars and check drift in CI | exit test: result.v1.schema.json has redaction with ruleset, total and by_rule, the drift check passes and 01-spec-format.md uses the same names.
- [M1] Redaction corpus harness with synthetic value expansion | owner: qa-engineer | est: 3h | depends on: Redactor core: rule table, span merge and keyed placeholder tags | exit test: the harness loads tests/fixtures/redaction, expands ${SYN:name} from parts, normalizes tags and fails on a survivor, a missing rule, an expected-file mismatch and an unlisted known gap.
- [M1] Redaction corpus: 51 positive cases | owner: qa-engineer | est: 3h | depends on: Redaction corpus harness with synthetic value expansion, Redaction rules for AWS keys and secrets by key name in env, YAML, JSON and INI | exit test: the url, auth, aws, pem, kubeconfig, rdy_token and key_name cases pass with zero survivors.
- [M1] Redaction corpus: 20 negative, hostile and known-gap cases | owner: qa-engineer | est: 3h | depends on: Redaction corpus harness with synthetic value expansion | exit test: git SHAs, UUIDs, versions, data URIs, pod names, certificates and prose stay unchanged, hostile forms are redacted or listed as known gaps, and false positives are printed.
- [M1] Property tests for the redactor | owner: qa-engineer | est: 3h | depends on: Redactor core: rule table, span merge and keyed placeholder tags, Redaction rules for PEM private keys and kubeconfig credentials | exit test: 10k cases per property show no generated secret survives, no residual matches, idempotence, no panic on arbitrary bytes and unchanged plain text.
- [M1] CI redaction gate with case-count floor and known-gaps ledger | owner: release-engineer | est: 2h | depends on: Redaction corpus harness with synthetic value expansion | exit test: the redaction job is part of ci-ok on all five legs and fails below the floor of 60 and when a known gap starts to pass.
- [M1] Document what rdy redacts and the placeholder format on the security page | owner: docs-writer | est: 1.5h | depends on: SEC-31 Docs security page and verify-first install, Redaction rules for AWS keys and secrets by key name in env, YAML, JSON and INI | exit test: the page lists the M1 rules, what stays (hostnames, addresses, encoded values) and the tag format, and the docs link check passes.
- [M1] Security review of the M1 redactor and corpus | owner: security-reviewer | est: 2h | depends on: Redaction corpus: 51 positive cases, Redaction corpus: 20 negative, hostile and known-gap cases | exit test: a review file in docs/plan/reviews/ is filed, and every miss it finds is a corpus case before its fix.
- [M2] Streaming redactor with line framing, overlap window and PEM state | owner: rust-engineer | est: 8h | depends on: Apply the redactor to every Report string before return | exit test: stream output equals whole-input output for every split offset of every positive case.
- [M2] Bundle rules: emails, JWTs, SaaS tokens, GCP and Azure credentials | owner: rust-engineer | est: 6h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: the new corpus categories pass with zero survivors and the negatives are unchanged.
- [M2] Bundle rules: entropy tokens, Kubernetes Secret manifests, IPv4, IPv6 and MAC | owner: rust-engineer | est: 6h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: opt-in groups stay off unless asked, loopback and unspecified addresses stay, and false positives on the negative corpus are under 2%.
- [M2] Spec and CLI additions: bundle.redact_patterns, bundle.max_size and --redact-pattern | owner: rust-architect | est: 3h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a custom pattern redacts with a custom.<name> tag, 33 patterns or a regex over 256 chars exits 64, and an unknown group exits 64.
- [M2] Binary, compressed and UTF-16 handling in the redaction pipeline | owner: rust-engineer | est: 4h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a gzip file and a NUL-heavy file are skipped with a reason, a UTF-16 log is redacted as UTF-8, and invalid UTF-8 around a secret does not stop the rule.
- [M2] Residual scan and per-entry fail-closed handling | owner: rust-engineer | est: 3h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a rule injected with a deliberate gap shows residual_hits above zero and the stored entry still contains no secret, and a panicking redactor drops the entry instead of writing raw bytes.
- [M2] Redaction throughput and memory floor in CI | owner: qa-engineer | est: 3h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: CI fails under 25 MiB/s on the reference corpus and above 128 MiB RSS for a full default bundle.
- [M2] SEC-44 Full redaction corpus with chunk-boundary cases | owner: qa-engineer | est: 10h | depends on: Bundle rules: emails, JWTs, SaaS tokens, GCP and Azure credentials | exit test: 300 cases including every chunk offset pass with zero misses.
- [M2] SEC-45 Fuzz targets for spec parser and redactor | owner: qa-engineer | est: 6h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a weekly 30-minute fuzz run per target finds no crash.
- [M2] Second-opinion secret scan over redacted fixtures in CI | owner: qa-engineer | est: 3h | depends on: SEC-44 Full redaction corpus with chunk-boundary cases | exit test: a pinned independent scanner finds nothing in the redacted bundle fixtures apart from allowlisted false positives, each with a reason.
- [M2] Bundle manifest wire types and schema in rdy-spec | owner: rust-engineer | est: 5h | depends on: Generate JSON schemas with schemars and check drift in CI | exit test: bundle-manifest.v1.schema.json is generated, the Appendix C sample validates, and a test shows no field can hold a raw hash.
- [M2] Collector trait, registry, caps and truncation helpers in rdy-bundle | owner: rust-engineer | est: 8h | depends on: Streaming redactor with line framing, overlap window and PEM state, Bundle manifest wire types and schema in rdy-spec | exit test: a fake collector over its cap is cut with the marker, later collectors keep their reserve, an unknown kind is skipped with a manifest entry and the archive writer has no path that accepts unredacted bytes.
- [M2] Bundle scope in the probe facade: streaming reads, exec caps and deny-list additions | owner: rust-engineer | est: 6h | depends on: File and env read policy in the facade | exit test: a 32 MiB file streams under a declared cap, an undeclared command or path is Denied and logged, and every path added in Plan corrections is refused even when a glob names it.
- [M2] SEC-43 Bundle collector path policy | owner: security-reviewer | est: 6h | depends on: Bundle scope in the probe facade: streaming reads, exec caps and deny-list additions | exit test: denylisted paths and symlink escapes are refused and the resolved file list is shown before collection.
- [M2] Collector file glob | owner: rust-engineer | est: 6h | depends on: SEC-43 Bundle collector path policy, Collector trait, registry, caps and truncation helpers in rdy-bundle | exit test: a glob finds 200 files at most, tail-keeps a .log file, refuses a symlink to /etc/shadow and lists permission-denied files as partial.
- [M2] Collectors for host processes, network, disk and kernel log on Linux | owner: rust-engineer | est: 10h | depends on: Collector trait, registry, caps and truncation helpers in rdy-bundle | exit test: recorded-output fixtures produce the files in Appendix A, cmdline and environ are never read, and a missing ip or ss gives one skipped sub-entry.
- [M2] Collectors for journal and container runtime on Linux | owner: rust-engineer | est: 6h | depends on: Collector trait, registry, caps and truncation helpers in rdy-bundle | exit test: a 90 MiB journal fixture is tail-cut at 32 MiB with the marker, a non-root fixture is partial with the hint, and a docker info fixture with a proxy password is redacted.
- [M2] Kubernetes guard allowlist amendment for bundles and Kubernetes collectors | owner: rust-engineer | est: 10h | depends on: Collector trait, registry, caps and truncation helpers in rdy-bundle, SEC-23 Enforce Kubernetes request allowlist | exit test: the mock API server sees only list and get on the Appendix A kinds, a pod fixture with env values and last-applied-configuration comes out with both stripped, Secrets and pods/log are refused, and k8s-expert signs off.
- [M2] macOS and Windows variants of the host collectors | owner: rust-engineer | est: 8h | depends on: Collectors for host processes, network, disk and kernel log on Linux | exit test: recorded macOS and Windows outputs produce the Appendix A files, and unsupported ids report not_yet_on_os.
- [M2] Archive writer: layout, deterministic tar headers, name sanitizing and archive cap | owner: rust-engineer | est: 6h | depends on: Collector trait, registry, caps and truncation helpers in rdy-bundle | exit test: the archive has one top directory and regular files only, names with .. or control characters are sanitized, two runs with a fixed key and clock give identical bytes, and the 90 MiB soft stop skips later entries.
- [M2] rdy bundle command, plan output and summary | owner: rust-engineer | est: 6h | depends on: Archive writer: layout, deterministic tar headers, name sanitizing and archive cap, Collector file glob | exit test: the sample in section 7 is produced from fixtures, --plan reads nothing and opens no socket, and a spec without bundle exits 64.
- [M2] rdy redact command | owner: rust-engineer | est: 1.5h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: piping a corpus input through the command prints the corpus expected output with live tags.
- [M2] No-socket and no-stray-file tests for rdy bundle | owner: qa-engineer | est: 3h | depends on: rdy bundle command, plan output and summary | exit test: under unshare -n with strace a bundle run opens no socket apart from the kube fixture, and canary secrets appear in no file in the output dir or a sandboxed temp dir.
- [M2] SEC-42 Share-link token format and scope | owner: security-reviewer | est: 6h | depends on: none | exit test: the token spec is agreed with rdy-cloud, including the rdy_st_ prefix, the length range in section 6.2 and the corpus cases.
- [M2] Token input: prompt, RDY_TOKEN, --token-file and the refused --token | owner: rust-engineer | est: 3h | depends on: SEC-42 Share-link token format and scope | exit test: precedence is file, then env, then prompt, a group-readable token file is refused, --token exits 64 with the reason, and a malformed token never causes a request.
- [M2] SEC-41 Upload client with consent, receipt and exact bytes | owner: rust-engineer | est: 12h | depends on: Token input: prompt, RDY_TOKEN, --token-file and the refused --token, rdy bundle command, plan output and summary | exit test: fake-server tests prove steps 0 to 5 of section 6.2, no upload without a yes or --yes, the sent bytes hash to the consent value, retries repeat the same upload id, and the receipt holds no token.
- [M2] Fake upload server and offline behaviour tests | owner: qa-engineer | est: 5h | depends on: SEC-41 Upload client with consent, receipt and exact bytes | exit test: tests cover 401, 413, 429 with Retry-After, 503 then success, a wrong echoed hash, a redirect, a dead proxy and no network, with the section 6.4 text.
- [M2] Security review of the bundle pipeline and upload client | owner: security-reviewer | est: 4h | depends on: Fake upload server and offline behaviour tests, Second-opinion secret scan over redacted fixtures in CI | exit test: a review file is filed and every blocker is fixed before the first design partner receives an M2 build.
- [M2] Bundle and upload docs, and README output | owner: docs-writer | est: 3h | depends on: rdy bundle command, plan output and summary | exit test: the Bundles page lists collectors and groups exactly as --list-collectors and --list-redactors print them.
- [M3] Pod logs collector k8s:logs with its own ADR | owner: k8s-expert | est: 6h | depends on: Kubernetes guard allowlist amendment for bundles and Kubernetes collectors | exit test: tail-limited logs per container are collected through the guard with an amended allowlist, and the redaction corpus has log-line cases.
- [M3] OS log collectors for macOS and Windows | owner: rust-engineer | est: 8h | depends on: macOS and Windows variants of the host collectors | exit test: recorded unified-log and event-log fixtures are collected, capped and redacted.
- [M3] Resumable upload | owner: rust-engineer | est: 8h | depends on: SEC-41 Upload client with consent, receipt and exact bytes | exit test: an upload cut at 60% resumes with the remaining bytes only, if a design partner has hit the single PUT limit first.
