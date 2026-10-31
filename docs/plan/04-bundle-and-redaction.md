# 04 Bundle and redaction

Owners: rust-engineer (drafted it) and security-reviewer (joint owner; wrote the contract in sections 3, 4
and 6). Status: draft 3, 2026-10-28, after the code-reviewer review.

This note designs the redactor, the collectors, the bundle archive and manifest, and the opt-in upload. It
builds on ADRs 0002, 0003, 0007 to 0010, 0012, 0014, 0015 and 0016, 01-spec-format.md, 02-engine-design.md and
05-threat-model.md. Field names follow `crates/rdy-spec/schema/*.json`. Where 01 differs, 01 wins and Plan
corrections lists what 01 must change. A server behaviour here is a request to `rdy-cloud`.

## Decisions in one screen

1. One redactor, `rdy_engine::redact` (ADR 0015). M1: whole-string API, eleven rules. M2: streaming and the
   rest. Rules find spans in the original text, overlaps merge into their union, output is written once.
2. Rules are compiled in. A spec can add redaction, never remove it. The one subtraction is the customer's
   own `--keep-emails`. Every writer takes only a `Redacted<T>`, which only the redactor can build.
3. Placeholder `[REDACTED:aws_access_key_id:3fa9c01b]`: a keyed hash tag, random key per process, never stored.
4. Nothing hashes raw content. The manifest holds the sha256 of stored bytes and a raw size rounded up to 4 KiB.
5. Collectors go through the probe facade. Caps never fail a bundle: 256 MiB raw, 100 MiB archive, enforced.
6. Upload is `rdy upload <file>`. Token from a prompt, `RDY_TOKEN` or `--token-file`, never argv. Two requests
   to one fixed origin. The client shows what it sends and asks.
7. Unknown collector kind: skipped. Unknown redactor group: exit 64. Missing data is acceptable; missing
   redaction is not.

## 1. Scope and milestones

CLAUDE.md rule 2 says redaction runs before anything is written to disk. The M1 report already writes
hostnames, proxy settings and command output, so a small redactor is an M1 safety gate (05 INV-15), not a
bundle feature. The bundle pipeline is M2, with the portal MVP.

- **M1:** `redact_str` and `redact_report`, keyed tags, the `Redacted` gate, eleven rules (Appendix B), applied
  to every string in the `Report`, `--json`, the `tracing` writer, panic hook and CLI errors. 28 golden cases
  in `cargo test`.
- **M2:** streaming, `redact_bytes`, residual scan, `with_extra`; emails, SaaS prefixes, cloud credentials,
  Secret manifests, entropy, IPs and MAC (opt-in), custom patterns; every byte of every bundle entry; sections
  2, 5 and 6 on Linux and Kubernetes (basic macOS and Windows); 60 cases, properties, fuzzing, a second-opinion
  scan.
- **Later:** `k8s:logs`, OS log collectors, resumable upload, `rdy report` input.

**The M1 minimum redactor** is the whole-string API, the keyed tag, span union and the `Redacted` gate, with
eleven rules (Appendix B) covering every M1 category in 05 Appendix F: token shapes, header names, URL
userinfo, PEM blocks, and a key-name matcher over `=`, `:`, JSON members, INI lines and `--flag=`. `jwt` is in
M1 because a bare service-account token in a Kubernetes error string is M1 evidence and nothing else catches
it (01 asked; the answer is yes). `redact_report` runs once on the finished `Report`, before the JSON, HTML,
`--json` stdout and terminal summary exist; the 02 field caps run after it. The same `redact_str` wraps the
`tracing` writer, the panic hook and CLI errors. Cost: 14.5 hours. There is no cut below this line.

## 2. Collectors

A collector turns one entry of `bundle.collect` into zero or more archive files.

- **Ids** are `kind:argument` (schema pattern `^[a-z][a-z0-9_]{0,15}:.{1,1024}$`): `journal:<duration>`,
  `file:<absolute glob>`, `k8s:events`, `k8s:describe`, `k8s:logs` (M3), `host:processes`, `host:network`,
  `host:disk`, `host:kernel_log`, `container:runtime`. A bad argument exits 64 (lint reports it first;
  journal durations run 1h to 30d). `rdy:*` in a spec exits 64; `rdy:result` is always included.
- **Unknown kind: skipped**, with a manifest entry (`unknown_collector`). Collecting less is safe; a skipped
  check can look like a pass, which is why checks differ.
- **Each collector declares** a static `CollectorInfo` (OS support, commands, read prefixes, Kubernetes kinds,
  privilege, caps, which end it keeps). The facade refuses anything else. Collectors cannot write: they push
  raw chunks into an `EntryWriter` that feeds the redactor and buffers the redacted entry.
- **Order.** One at a time: `rdy:*`, `file:`, `host:*`, `container:*`, `k8s:*`, `host:kernel_log`, `journal`.
  The customer only subtracts (`--skip <id>`, `--max-size`); the spec only adds collectors.
- **Install namespace.** The union of `namespace` params in the spec's k8s checks and `--namespace`. Empty:
  the two `k8s:` collectors are skipped with "add `--namespace <ns>`". No cluster-wide describe.
- **Built-in set.** A spec not verified with a pinned key (01 2.8) gets `rdy:result`, `host:processes`,
  `host:network` and `host:disk`, and the summary says so. Its `redact_patterns` still apply.
- **Facade.** Every read, command and Kubernetes request goes through `Probe` (02): argv only, fixed search
  path, scrubbed environment, deny list on the path and canonical target, the Kubernetes guard. Bundle scope
  adds streaming `read_stream` and `exec_stream` with a cap from `CollectorInfo` (checks get 1 MiB), the
  `CollectorInfo` check, and more deny-list entries. `file:` globs expand through `Probe::read_dir` (8
  levels, 10,000 entries, 200 files per glob). A symlink is refused if its target is outside the glob's
  literal prefix or on the deny list (SEC-43). `--plan` lists directories, reads no file content, makes no
  request. `source` and archive paths use 01's home-path rule (`/home/alice/x` becomes `~/x`).
- **Kubernetes objects carry secrets.** The collector drops `env[].value` (becomes
  `[REDACTED:env_value:<tag>]`), `last-applied-configuration` and `managedFields` before the redactor runs.
  Secrets are never listed; ConfigMaps are metadata only.
- **Degrade.** A missing privilege gives what can be read, `partial` or `skipped`, a reason code and a hint.
  rdy never asks for sudo.

Appendix A has the per-OS source, privilege and degrade for each id.

## 3. Redactor design

### 3.1 The contract

These hold in every milestone. ADR 0015 records them and CI tests each one.

1. **Compiled in, add only.** Rules, thresholds and the placeholder format ship in the binary. A spec can
   switch on optional groups and add `redact_patterns`; it cannot remove or weaken a rule. An unknown group
   exits 64. The only subtraction is the customer's `--keep-emails` (3.4).
2. **Spans, merged by union.** Every rule runs on the original text and reports `(start, end, rule,
   priority)`. Overlapping or touching spans merge into one covering their union, named after the highest
   priority rule in it. Output is written once, so no rule sees a placeholder and no partly overlapped span
   leaves bytes behind.
3. **No raw digests.** Nothing hashes raw content, except `host_id` in 01 (machine id plus a product salt). A
   hash of a known template with one secret is a guessing oracle. The manifest holds `sha256` of the stored
   bytes and `raw_size_kib`, the raw size rounded up to a multiple of 4 KiB, because an exact raw size minus
   the stored size gives away a secret's length. Exact counts stay in memory.
4. **Fail closed.** An error or panic inside redaction drops the string or entry and records why. No raw
   fallback. If the OS RNG cannot make a key, rdy exits 70.
5. **Binary is skipped**, never shipped (Appendix F).

### 3.2 Model

```rust
// rdy_engine::redact (outside the `runtime` feature, so rdy-cloud can reuse it)
pub struct Redacted<T>(T);   // built only in this module: no pub constructor, From, Default or Deserialize
impl<T> std::ops::Deref for Redacted<T> { type Target = T; /* no DerefMut */ }
impl Redactor {
    pub fn new(key: TagKey) -> Self;                                    // built-ins only; built first in `main`
    pub fn with_extra(&self, e: &Extra) -> Result<Redactor, RedactError>; // M2: after the spec is verified; same key
    pub fn redact_str(&self, s: &str) -> Redacted<String>;              // M1
    pub fn redact_report(&self, r: Report) -> Result<RedactedReport, RedactError>;  // M1: RedactedReport = Redacted<Report>
    pub fn redact_report_counted(&self, r: Report, earlier: RuleCounts) -> Result<RedactedReport, RedactError>; // M1: keeps the counts of results redacted earlier
    pub fn redact_check(&self, c: CheckResult, counts: &mut RuleCounts) -> Result<Redacted<CheckResult>, RedactError>; // M1: as each result completes
    pub fn redact_action(&self, a: Action, counts: &mut RuleCounts) -> Result<Redacted<Action>, RedactError>;         // M1: as each entry is written
    pub fn redact_buffer(&self, b: &[u8], cut: Cut) -> Redacted<String>; // M1: a facade buffer with its cut flags (M1-061)
    pub fn add_known_secret(&self, s: &str) -> bool;                    // M1: run-scoped set, shared by clones (M1-061)
    pub fn redact_bytes(&self, b: &[u8]) -> Redacted<Vec<u8>>;         // M2
    pub fn stream(&self) -> RedactStream;                               // M2
}
#[non_exhaustive] pub enum RuleSet { Report, Bundle }                   // Bundle is a superset of Report
#[non_exhaustive] pub enum RedactError { /* ... */ }
```

- **Counts are per call.** A `Redactor` shares only its key between the report, the logs and bundle entries.
  `redact_report` keeps its own tally and writes `redaction { ruleset, total, by_rule }` after the walk; a
  bundle entry counts for itself. Log lines count nowhere in the report, so `by_rule` is the same with
  `RUST_LOG` unset and at `trace`. `redaction.total` and `by_rule` count every replacement the walk made,
  including in text that a later cap dropped (a list past 200 items, notes past 20, keys dropped to fit
  64 KiB), so they are never lower than what was hidden. The final pass of `redact_report_counted` finds
  nothing new in results redacted earlier. A trailing ` [truncated]` is set aside while a string is redacted
  and put back after. A cut never ends inside a placeholder or a reference the key rule leaves alone
  (`${NAME}`, a `/run/secrets/` path, `null`), right behind a placeholder, or between a key and the quote
  that opens either; it backs up to where the token starts (tokens up to 512 bytes), and a quoted single placeholder (`password="[REDACTED:..]"`) is exempt
  like a bare one, so `password=" [truncated]` is never produced and a second pass changes nothing.
- **`redact_report` is schema-aware.** It serializes the report to a `serde_json::Value` and walks it. Typed
  fields keep their names and non-string values; only string leaves go through `redact_str`. The whole-member
  rule (replace the value of a member whose key matches a secret stem, and the `value` of a `{name, value}`
  pair whose `name` matches) runs only inside free-form subtrees: `checks[*].observed`, `checks[*].expected`,
  env pairs and action `argv` (a flag such as `--password` takes the next argument whole). It never touches a
  schema-defined field, so `summary.pass`, `by_rule` keys and check keys such as `passed` survive. Numbers under a secret key are
  replaced too (`db_password: 12345678`), unless the key's last word is a unit or a count (`ms`, `seconds`,
  `ttl`, `count`, `size`, `len`) and the number sits directly under the key, so `token_ttl_ms: 3600`
  survives. A list or object under the key is replaced whole, so `private_key_bytes: [48, 130]` does not
  stay (`bytes` is not a unit word for the same reason). Booleans and `null` stay, and so do the forms the
  key rule leaves alone (`${NAME}`, a `/run/secrets/` path, `null`, a placeholder). Every list in a
  free-form subtree is read as a command line, numbers and objects included, so
  `["--password", "hunter2", 5432]` loses its second item. `{key, value}` and `Name`/`Value` pairs match
  like `{name, value}`. The walk deserializes
  back into `Report` and applies the 02 caps, which never cut inside a placeholder or a reference. A cut string ends with
  ` [truncated]` and sets the result's `truncated` flag. On any error no report is written and rdy exits 70.
  The watchdog snapshot uses the same function. `redact_check` and `redact_action` run the same walk on one
  entry as it completes. The final pass finds nothing new in them, so the caller keeps one `RuleCounts` across
  the run and gives it to `redact_report_counted`.
- **Structure is kept.** A span excludes quotes and delimiters: `password="hunter2"` becomes
  `password="[REDACTED:secret_by_key:1a2b3c4d]"`. The key-name rule skips a value only when it is exactly one
  well-formed placeholder, so `password=[REDACTED:x:00000000]hunter2` is still redacted.
- **Groups.** Specs name groups; placeholders and the manifest use rule names (Appendix B). Priority, highest
  first: PEM and Secret blocks, token shapes, headers, URL userinfo, key names, custom patterns, emails, IPs,
  entropy. Every group except `ipv4`, `ipv6` and `mac` is always on.
- **Not decoded.** Rules tolerate `\"`, `\u0040`, `%40` and literal `\n` in JSON-escaped PEM, not base64 or
  double encoding; the docs say so and point to `--redact-pattern`. The placeholder grammar is part of
  `rdy/v1` (01 section 5): a rule version bump is a CHANGELOG entry, a grammar change is breaking.

### 3.3 Placeholder and the stable tag

`[REDACTED:<rule>:<tag>]`, rule names `[a-z0-9_.]` (`custom.<name>` for custom patterns). The tag is the first
4 bytes of `HMAC-SHA256(key, secret_bytes)` as 8 lowercase hex digits. The key is 32 bytes from
`ring::rand::SystemRandom`, made once per process, held in memory only, never written, logged, or put in a
manifest, receipt or error. Unkeyed, a hash of a short password would be a lookup table; keyed, the tag only
says "these two values are equal", inside this process, and two bundles from one host differ. The input is the
secret bytes only, so one password in a URL and in an env var gets one tag. 32 bits gives a 1% collision
chance at about 9,000 distinct secrets; a collision merges two labels and reveals nothing. `TagKey::fixed(..)`
exists only under feature `testing`, which CI keeps out of the release binary (M1-048 also refuses a release
build with the feature on, with a `compile_error!` in `rdy_engine::redact`).

**Equality oracle.** Two placeholders with the same tag mean two equal secrets (or a 1 in 4 billion collision).
Whoever reads a report learns that equality and nothing else: the key never leaves the process, so a guessed
value cannot be tested against a tag. A 4-byte tag is a deliberate trade against a longer one that would make
the equality easier to see in a diff.

### 3.4 Where the guarantee lives, and review decisions

- **Typed writers.** `report::write_json`, `render_html`, `OutputDir::write_atomic` and (M2)
  `BundleWriter::add` take `&Redacted<_>` only. The verified spec copy goes through
  `write_spec_copy(&VerifiedSpecBytes)`, because signed bytes must stay exact. Terminal summary and `--json`
  come from the same `Redacted<Report>`.
- **Logs.** A redacting writer under the `tracing` fmt layer redacts each formatted event whole before stderr.
  The inner fmt layer uses `.with_ansi(false)`, because colour codes between a field name and `=` would hide
  `password=hunter2` from the key-name rule. With `RUST_LOG` unset nothing is logged (07 D.6); with it set,
  hyper, h2, rustls, tower and kube stay capped at warn whatever the filter says. A PEM block split over several events is a known gap in M1. Panic and CLI error text is
  redacted too.
- **Raw bytes** live only in memory owned by the collector task and the redactor: no temp file, and no raw
  value in the action log, `tracing` or an error.
- **M2.** A failed entry is dropped (`redactor_error`). A residual scan re-checks stored bytes and prints "this
  is a bug in rdy" on a hit. Entry names are redacted in a filename-safe form. On Linux, `rdy bundle` and
  `rdy upload` call `rustix::process::set_dumpable_behavior(NotDumpable)`.
- **Versions.** Each rule has a version; changing what it matches bumps it and needs security-reviewer
  approval. The manifest lists the set id (`rdy-redact/1`) and every rule version.
- **Emails in bundles: on by default, customer opt-out.** Only the customer can turn it off, with
  `--keep-emails` on `rdy bundle`: argv only, no spec field, env var or config. The manifest lists it in
  `groups_off_by_flags`; the summary and consent screen print `not redacted  emails (--keep-emails)`. The M1
  Report set has no email rule: the report shows the Kubernetes user on purpose (SEC-24).
- **Entropy thresholds** start at 24 or more characters, 4.0 bits per character, three of four classes, never
  pure hex of length 32, 40 or 64, UUIDs, `sha256:` digests or data URIs. They are constants tuned in M2.
- **Limits and crates.** Maximum match length of any rule 16 KiB, except the key-name rule: its value runs to
  the end of the line (or the end of a YAML block), and a cap would leave the tail of a long secret in the
  output, so M1-048 has no cap there; custom patterns at most 32 of 256 chars; M2
  speed 50 MiB/s per core (CI fails under 25). Rules compile once into a `LazyLock<Arc<CompiledRules>>`. M1
  uses `regex` alone (linear time). HMAC-SHA256, SHA-256 and the RNG come from `ring` (ADR 0009); `aho-corasick`
  is added in M2 only after a measurement. `rdy-bundle` adds a C compiler to the musl build, so 06's size
  budget ticket must measure it.

## 4. Redaction test strategy

All values are synthetic. Layout follows 05 Appendix F:

```text
tests/fixtures/redaction/
  FLOOR  known-gaps.toml (M2)  synthetic.toml     # FLOOR: minimum case count, 28 in M1 and 60 in M2
  <category>/<case>.in  <case>.expected  <case>.toml
```

A case's `.toml` holds `polarity` (`positive`, `negative` or `known_gap`), the `rules` that must fire, `since`
(`m1` or `m2`), the `rulesets` to run it against, and `secrets`, the strings that must not appear in the output.

- `${SYN:name}` in `.in` and `secrets` expands from `synthetic.toml`, stored as parts, so push protection never
  sees a whole token. The vendor-documented `AKIAIOSFODNN7EXAMPLE` is used as is.
- The harness redacts `.in` with a fixed key, replaces each tag with its ordinal in the file (`~1`, `~2`),
  and compares with `.expected` byte for byte (negatives: `.expected` equals `.in`). `.expected` is blessed by hand; `UPDATE_GOLDENS=1` never
  touches this directory (08). It also checks on its own that no `secrets` string survives (the oracle that
  catches a wrongly blessed file), that `redact(output) == output`, and that the rules find no span outside
  placeholders.
- **The gate is coverage, not count.** The harness reads Appendix B and fails unless every rule marked for the
  milestone has a positive case for each syntax form it claims (env, YAML, JSON, INI, `--flag=`, header), and
  every key-name exclusion has a negative. `FLOOR` is a second guard. Every miss report adds a case first (05).
  Volume comes from M2 property and chunk-offset cases: 300 hand-blessed goldens would cost 15 to 25 founder
  hours and buy repetition, not coverage.

M1 has 28 cases: 23 positive and 5 negative (Appendix D lists them). M2 adds 32 for the bundle rules and more
hostile forms, for 60 with 11 negatives and 2 known gaps.

**M1 gate.** A `cargo test` in `rdy-engine`, so it runs in the existing job on all five legs and in `ci-ok`. It
fails on a survivor, a rule that did not fire, an `.expected` mismatch, an idempotence or residual failure, a
rule or form with no positive case, or fewer cases than `FLOOR`.

**M2 gate.** A separate `redaction` job adds property tests (08: no generated secret survives, idempotence,
stable tags, no panic on arbitrary bytes, stream equals whole-input output at any split; 256 cases per PR,
100,000 nightly), the known-gaps ledger (a gap that starts to pass fails with "promote it"), a cargo-fuzz
target (SEC-45), a pinned independent secret scanner over redacted fixtures, the throughput and memory floor,
and a 2% false-positive budget on the reference log corpus. Generators come from the rules, so they cannot find
a form the rules do not know: that is why the corpus exists. CODEOWNERS (SEC-04) puts `redact/`, the rule
tables and `tests/fixtures/redaction/` under security-reviewer.

## 5. Bundle manifest, archive and caps

### 5.1 Manifest

`manifest.json` is a wire type in `rdy_spec::bundle` with a generated schema; Appendix C has the layout,
compression settings and a sample. It holds provenance (bundle id, producer, the result's `run.id`, the spec
reference and signature state, `host_id`), the redactor (set id, rule versions, groups always on, from the spec,
from flags, switched off by flags), one entry per file or collector outcome (`path`, `collector`, `status`,
`reason`, `source`, `raw_size_kib`, `bytes_out`, `sha256` of the stored bytes, `redactions` by rule,
`residual_hits`, `truncated`, `truncation` of `head`, `tail` or `time`), totals, caps hit and a `degraded`
list. Never in it: a raw value, a raw hash, the tag key, a token, environment values, argv. The archive's own
sha256 is in a sidecar `.sha256` and in the upload receipt.

### 5.2 Size caps

`--max-size` and the spec's `bundle.max_size` lower both the raw and the archive cap to `min(value, default)`.
Nothing raises them.

| Scope | Cap | Keeps | Time cap |
| --- | --- | --- | --- |
| `journal` | 32 MiB | tail | 120 s |
| `host:kernel_log` | 8 MiB | tail | 30 s |
| `host:processes` / `network` / `disk` | 2 / 2 / 1 MiB | head | 15 / 30 / 30 s |
| `container:runtime` | 8 MiB | head | 60 s |
| `k8s:events` / `k8s:describe` | 8 MiB per namespace / 8 MiB per kind, 32 MiB total | whole objects | 60 / 120 s |
| `file:` | 4 MiB per file (tail for `*.log`, `*.out`, `*.err`, `messages`, `syslog`), 32 MiB and 200 files per glob | head or tail | 60 s per glob |
| `rdy:result` | 16 MiB; a `--result` over it is refused, never cut | none | 15 s |
| Bundle raw / archive | 256 MiB after redaction / 100 MiB and 13,000 entries | by priority | 10 min in all |

**A cap never fails the bundle.** A cut entry gets a marker line and `truncated: true`; sizes use the same
4 KiB rounding, for example `[rdy: truncated, kept the last 32768 KiB (journal cap)]` or `[rdy: stopped after
120 s (journal time cap), output is incomplete]`. Kubernetes files are JSON Lines, so the cut falls between objects. When the raw total would pass
256 MiB, the current entry is cut to the remaining budget minus a 256 KiB reserve for each collector still to
run, and collectors after it get `skipped: total_cap`; when the 10 minutes run out, `skipped: total_time`.

**Archive cap.** Before each entry the writer requires compressed bytes so far, plus the entry's
`ZSTD_compressBound`, plus a 6 MiB manifest reserve, to stay at or under 100 MiB. Otherwise it cuts the entry
with a marker to fit, or skips it with `archive_cap`. Incompressible data therefore never gives an archive
over 100 MiB; an archive over the cap was not made by this rdy, and `rdy upload` says so.

## 6. The opt-in upload flow

Endpoints and responses are a proposal to `rdy-cloud` (SEC-42 owns the token format). The client rules hold
whatever the server does.

**Invariant.** Nothing leaves unless the user typed `rdy upload` (or `--upload` on `run` or `bundle`) and then
answered yes or passed `--yes`. Before the answer there is no connection to, and no DNS query for, the upload
origin; after a no, never. `rdy bundle` talks only to the Kubernetes API, through the guard. Tested under
`unshare -n` and `strace`. This is INV-20 plus INV-25 to INV-27.

**Step 0. Pre-flight, no network, one streaming pass over one handle.**

1. Open once (`O_NOFOLLOW`; Windows: refuse reparse points) and `fstat` the handle: a regular file owned by
   the euid (Windows owner check: documented residual), at most 100 MiB for a bundle, 16 MiB for a result.
2. In that pass compute the sha256 and decode. A result is `.json` that parses into
   `rdy_spec::result::Report` (HTML is refused). A bundle is `.tar.zst` decoded with `window_log_max(23)`, one
   top directory, regular files only, whose `manifest.json` parses and whose entry hashes match. Decoding
   stops at 257 MiB of output or 13,000 entries and exits 64.
3. Scan each entry (Report set over a result, Bundle set over bundle entries). A hit exits 64 with rule names
   and paths, never text. A bundle built with `--keep-emails` carries `groups_off_by_flags: ["emails"]`; the
   scan honours exactly that value and any other exits 64. A spec's `redact_patterns` cannot be re-checked,
   because `rdy upload` has no verified spec.
4. The size and sha256 from this pass are the consent values.

**Step 1. Token.** Precedence: `--token-file`, `RDY_TOKEN`, hidden prompt. The consent screen names the source.

- `--token-file <path>`: `O_NOFOLLOW`, `fstat` must say regular file (a FIFO or `/dev/tty` exits 64), owned
  by the euid, no group or other bits, else exit 64 with the `chmod 600` fix. Read through `take(257)`; over
  256 bytes exits 64. One trailing `\n` or `\r\n` is trimmed. `-` reads stdin and needs `--yes`.
- `RDY_TOKEN` is for CI: not in `ps`, but readable by the same user and root via `/proc/<pid>/environ`, and a
  kube exec plugin in `bundle --upload` inherits it (documented residuals). The prompt
  `Share-link token (input hidden):` appears only when stdin and stderr are terminals.
- There is no `--token <value>`. A hidden flag of that name exits 64 with: "tokens on the command line show up
  in shell history and in `ps` for other users. Use `--token-file`, `RDY_TOKEN` or the prompt." (On Linux
  `/proc/<pid>/cmdline` is world-readable by default; `environ` is not.) No TTY and no token: exit 64.
- The token must match `^rdy_st_[A-Za-z0-9]{20,64}$` before any request, so a mistyped value or a password
  pasted by accident never leaves the box. A `ShareToken` shows only `rdy_st_...` and the last 4 characters in
  `Debug` and `Display`, and goes only into `Authorization: Bearer` (`set_sensitive`).

**Step 2. Consent.** Always printed to stderr. Default is no.

```text
About to upload to https://app.getrdy.io (Rdy Cloud):

  file      rdy-bundle-acme-platform-20261104T101500Z.tar.zst
  size      12.4 MiB (38 files, 61 MiB unpacked)
  sha256    9f2c4b0e7d1a3c5e8f60b2d4a6c8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9e41a
  redacted  3 aws_keys, 2 bearer_tokens, 14 emails (by rdy, before writing)
  spec      acme-platform, signed, key 7A3F9C21B04D55E1
  token     rdy_st_...Q7XA (from RDY_TOKEN)

rdy sends this file, its name, size and SHA-256, and the rdy version and platform.
Nothing else. The server also sees your IP address, as with any connection.
To read what is inside first:  tar --zstd -xOf <file> '*/manifest.json'
Upload this file? [y/N]
```

Only `y` or `yes` is yes; empty input, EOF, Ctrl-C and anything else is no (exit 64, `Nothing was sent.`). No
TTY: `--yes` is required (exit 64 with a fix line); a non-TTY run never prompts. On a TTY, `--yes` skips the
question and the screen still prints. `--yes`, `--upload` and `--server` come from argv only; a command
pasted from a vendor email should not carry `--yes`. `--server` takes an `https` origin only, no userinfo,
path or query. A non-default server adds a bold `server ... (NOT the default Rdy Cloud server)` line, also in
the receipt, and **`--yes` does not skip the question on a TTY** for it. A `--keep-emails` bundle adds `not
redacted  emails (--keep-emails)`. The screen and summary count by group; the manifest by rule.

**Step 3. Create.** `POST /api/v1/uploads` with the token, a JSON body (`kind`, `file_name`, `size`, `sha256`,
`rdy_version`) and an `Idempotency-Key` (UUID, once per invocation, reused on retry). On `201` the client reads
`upload_id` (`^upl_[A-Za-z0-9]{16,64}$`) and `max_bytes` and ignores every other field; the cap is the smaller
of `max_bytes` and the local 100 MiB. This request carries metadata only: a failure here means no file bytes
left the machine, and the CLI says so.

**Step 4. Send.** One `PUT /api/v1/uploads/<upload_id>/content`; the client builds the URL from the validated
id and never takes one from the server. Headers include `Content-Digest: sha-256=:<base64>:` (RFC 9530). The
body streams from the step 0 handle, uncompressed, and is hashed again on the way; the last chunk is held back
until hash and count equal the consent values, otherwise the request aborts and rdy exits 70 ("the file changed
during upload"). The `200` reply carries `receipt_id` (`^rcp_[A-Za-z0-9]{16,64}$`), `upload_id`,
`received_bytes` and `sha256`; the last three must equal the client's values, even on a `200`. Appendix E has
the bytes of both requests.

**Step 5. Receipt.** `upload-receipt-<local ts>.json` through a `cap-std` handle on the file's directory
(`create_new`, 0600): version, time, server origin, file name, kind, size, sha256, upload id, receipt id, the
server's echo, rdy version. No token, no argv. It is the only write `rdy upload` makes. If the directory is
not writable it goes to stdout; with `--json` the receipt is the JSON output. Server text is never printed
raw: error codes map to fixed local messages (`token_expired`, `token_revoked`, `too_large`, `rate_limited`,
`bad_digest`), anything else prints the status. At most 64 KiB of a response is read, then the connection
closes.

**Transport.** The M2 upload client from ADR 0009 (reqwest, rustls with `ring`, platform verifier): no
redirects, address policy on the server address, no cookies, no telemetry. Connect 15 s including DNS and TLS,
60 s without body progress, 30 min in all. Retries on connect errors, timeouts, `408`, `429`, `502`, `503`,
`504`: at most 4 attempts, waits of 2, 8 and 30 s with 20% jitter, `Retry-After` up to 60 s, the whole `PUT`
repeated to the same `upload_id`. `409` and other `4xx` do not retry; the prompt is never asked twice. Proxy:
`HTTPS_PROXY` and `NO_PROXY` per ADR 0009 with the `ProxyUrl` mask. An intercepting proxy whose CA the OS
trusts sees the token and the file (the customer's own middlebox; the security page says so). On `407` the
CLI shows the variable form without the password.

**Offline.** If step 3 cannot connect, the CLI prints `error: could not reach app.getrdy.io. Nothing was
sent.`, a `fix:` line, the file path and sha256, and how to send it by hand (the share-link page, or the
spec's contact, printed only if the embedded spec and `.minisig` verify against the local trust store). Exit
70. `rdy run` and `rdy bundle` never fail because upload is unavailable.

**Tests (SEC-41 and the fake-server ticket).** No socket or DNS query before the answer or after a no. A
canary token never appears in argv, stderr at `RUST_LOG=trace`, the receipt or any file. Bytes sent hash to the
consent value; a file changed after consent aborts with 70. A `302` is not followed. `--server http://...`, a
token on argv, a group-readable token file, a residual hit, a zstd bomb, a 20,000-entry tar (each within 5 s)
and a non-TTY run without `--yes` exit 64 before any request. `401`, `409`, `413`, `429`, `503` then success,
a wrong echoed hash, a dead proxy and no network each give a fixed message. On macOS and Windows the loopback
TLS server is trusted through a test-only extra root under feature `testing`, because the platform verifier
ignores `SSL_CERT_FILE`.

## 7. Command surface

cli-ux owns names and output samples (07). Proposal: `rdy bundle <spec>` with `--result`, `--out-dir`,
`--namespace`, `--skip <id>`, `--redact <group>`, `--redact-pattern <regex>`, `--max-size`, `--plan`,
`--list-collectors`, `--list-redactors`, `--keep-emails`, `--allow-unsigned`, `--json` and `--upload`;
`rdy upload <file>` with `--token-file`, `--server`, `--yes` and `--json`; `--upload [--yes]` on `rdy run` as
the same code path; and, in M2, `rdy redact [<file>|-]` so a customer can try the redactor. `rdy bundle`
verifies the spec like `run` (ADR 0002), exits 64 with no `bundle:` block, and creates
`rdy-bundle-<product>-<ts>/`. `--result` embeds a result JSON, validated and redacted again. Exit codes: 0
bundle written (even with degraded collectors), 64 usage or spec problem, 70 cannot write. `rdy upload`: 0
success, 64 bad input or refused consent, 70 cannot deliver.

## Appendix A: collectors per OS

Programs are `&'static str`, resolved from the fixed search path (ADR 0014, 02). M2 builds Linux and
Kubernetes. `-` means no data source yet (`not_yet_on_os`).

| Id | Linux | macOS | Windows | Privilege and degrade |
| --- | --- | --- | --- | --- |
| `rdy:result` | memory: result, verified spec and `.minisig`, bundle action log | same | same | none |
| `file:<glob>` | `read_dir`, `read_stream` | same | same, `C:\` paths | permission denied: `partial` with hint. Deny list always applies |
| `journal:<d>` | `journalctl --no-pager -o short-iso --since -<d> -n 200000` | `-` (M3) | `-` (M3) | non-root sees the user journal: `partial`. No journald: `skipped no_journald` |
| `host:processes` | `/proc/<pid>/stat` and `status`. Never arguments or environment | `ps -axo pid,ppid,uid,state,etime,rss,comm` | `tasklist /fo csv` | none |
| `host:network` | `ip -details addr`, `ip route`, `ss -tulnp`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, proxy variable names | `ifconfig -a`, `netstat -rn`, `scutil --dns`, `scutil --proxy` | `ipconfig /all`, `route print`, `netsh winhttp show proxy` | `ss -p` owners need root; without it the column is empty and the entry says so. A missing tool is one `skipped` sub-entry |
| `host:disk` | `native` (sysinfo), `/proc/mounts` | `native` | `native` | none. A hung NFS mount ends as `partial` |
| `host:kernel_log` | `dmesg --time-format iso`; fallback `journalctl -k -b` | `-` | `-` | `dmesg_restrict=1` and not root: fallback, then `partial` |
| `container:runtime` | `docker version`, `info`, `ps -a`, `images`; `crictl info`, `ps -a`; `podman info`; `/etc/docker/daemon.json`, `/etc/containerd/config.toml` | `-` (ADR 0014 amendment) | `-` (same) | docker group or root. Each runtime is probed alone. Auth blocks are caught by the key-name rule |
| `k8s:events` | kube `list events` per install namespace, `limit=500`, at most 5,000 | same | same | RBAC `forbidden`: `skipped` with verb and resource. No context: `skipped no_kube_context` |
| `k8s:describe` | `get` or `list` of pods, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs, services, endpointslices, ingresses, networkpolicies, persistentvolumeclaims, resourcequotas, limitranges, configmap metadata | same | same | each kind is independent. Secrets are never requested |

`k8s:logs` (M3) needs the guard to allow `pods/log`, refused until its own ADR.

## Appendix B: redaction rules

Rule names appear in placeholders and the manifest; a group is the name a spec uses. Versions start at 1.
Patterns are sketches; the code is the source of truth and the corpus is its test.

| Rule | Group | M | Matches | Span |
| --- | --- | --- | --- | --- |
| `url_userinfo` | `url_credentials` | 1 | `scheme://user:pass@host`, `scheme://token@host`, percent-encoded | the userinfo |
| `auth_header` | `bearer_tokens` | 1 | `Authorization:` and `Proxy-Authorization:` values (any scheme), `-H 'Authorization: ...'`, bare `Bearer <token>` | the credential |
| `api_key_header` | `bearer_tokens` | 1 | `X-Api-Key`, `X-Auth-Token` values. M2 adds `Cookie` and `Set-Cookie` | each value |
| `aws_access_key_id` | `aws_keys` | 1 | `(AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}` | the id |
| `aws_secret_access_key` | `aws_keys` | 1 | key names `aws_secret_access_key`, `SecretAccessKey`. M2: a 40-char base64 value near a key id | the value |
| `aws_session_token` | `aws_keys` | 1 | key names `aws_session_token`, `SessionToken`, `x-amz-security-token` | the value |
| `pem_private_key` | `private_keys` | 1 | `-----BEGIN [A-Z0-9 ]*PRIVATE KEY...-----` through the matching END, header and blank lines included, plain or literal `\n`. No END: to the end of the input (whole string) or entry (stream) | the block |
| `kubeconfig_credential` | `kubeconfig` | 1 | keys `token`, `client-key-data`, `password`, `access-token`, `refresh-token`, `id-token`, `client-secret`. Public certificates stay | the value |
| `rdy_share_token` | `rdy_tokens` | 1 | `rdy_st_[A-Za-z0-9]{20,}` up to 16 KiB | the token |
| `jwt` | `jwt` | 1 | `eyJ...` three base64url parts | the token |
| `secret_by_key` | `secrets_by_key` | 1 | a key containing `pass`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential`, `auth`, `bearer` or `dsn` followed by `=` or `:`, in env, YAML, JSON, INI, `--flag=x`, systemd `Environment=`, connection strings | the value, no quotes |
| `github_token`, `gitlab_token`, `slack_token`, `stripe_key`, `google_api_key`, `npm_token`, `pypi_token`, `docker_pat` | `saas_tokens` | 2 | documented prefixes (`gh[pousr]_`, `github_pat_`, `glpat-`, `xox[baprs]-`, `[sr]k_live_`, `AIza`, `npm_`, `pypi-`, `dckr_pat_`) | the token |
| `gcp_service_account_key`, `azure_credential` | `cloud_credentials` | 2 | service-account `"private_key"`, `client_secret`, SAS `sig=`, `AccountKey=` | the value |
| `k8s_secret_data` | `k8s_secrets` | 2 | `data:` and `stringData:` values in a `kind: Secret` document | each value |
| `email` | `emails` | 2 | `local@domain.tld`, also `\u0040` and `%40`. Always on in the Bundle set; only `--keep-emails` turns it off | the address |
| `ipv4`, `ipv6`, `mac` | opt-in | 2 | addresses that parse. Loopback, unspecified and broadcast stay | the address |
| `entropy_token` | `entropy` | 2 | thresholds in 3.4 | the token |
| `custom.<name>` | spec or `--redact-pattern` | 2 | Rust regex, per record, never across lines | the match, or group `secret` |

Key-name exclusions (each has a negative): empty, `null`, `true`, `false`, `none`, `required`; `${X}`,
`$(...)`, `{{ ... }}`; `valueFrom` and `secretKeyRef` blocks; keys ending in `name`, `ref`, `file`, `path`,
`namespace`; paths under `/run/secrets/`. Stems match only in free-form text or free-form subtrees, never
schema-defined field names (3.2).

**How the M1 rules are built (M1-060).** The table is the contract and the code is the detail. These are
the choices the table leaves open.

- **Priority**, highest first: `pem_private_key` 90; `aws_access_key_id`, `rdy_share_token`, `jwt` 80;
  `auth_header`, `api_key_header` 70; `url_userinfo` 65; `aws_secret_access_key`, `aws_session_token`,
  `kubeconfig_credential` 62; `secret_by_key` 60. The merged span takes the highest name, so
  `Authorization: Bearer x` reads `[REDACTED:auth_header:..]` although the key rule also took it.
- **`url_userinfo`** reads the text after `://` up to the first `/`, `?`, `#`, quote, angle bracket, white
  space, control character or backslash. The userinfo ends at the last `@` in it, or at a JSON `@`.
  A raw `/`, `?` or `#` in a password ends the authority with no `@` in it. If what came before is
  `user:x` (`x` not all digits, so not a port) and an `@` follows before white space, a quote or a
  backslash, the userinfo runs to the last such `@` (`postgres://app:K7x/9+Qa@db/app`). A space in a
  password is not read; write it as a percent escape. `http:\/\/` (JSON slashes) is read too.
- **`auth_header`** keeps the scheme and replaces the credential after it (`Authorization: Basic
  <credential>`; one word is all credential). A quoted value runs to its closing quote, a header inside
  a quoted word (`-H 'Authorization: ...'`) to that quote, anything else to the end of the line or a
  backslash. A bare `Bearer <token>` needs 8 or more token characters and is not one of a few prose words.
- **`pem_private_key`** takes every label that holds `PRIVATE KEY`, from the BEGIN line through the END
  line of the same label, comment markers and `\n` escapes inside. No END, or another label's END: to the
  end of the text. Certificates and public keys stay.
- **`kubeconfig_credential`** names `client-key-data`, `client-secret`, `access-token`, `refresh-token`
  and `id-token` wherever they appear (`client-key` is a file path and stays), and `token` and `password` only in a text that looks
  like a kubeconfig (`users:`, `clusters:`, `current-context`, `kind: Config` and the like). Elsewhere
  those two are `secret_by_key`. `client-key-data` also has the `keydata` stem.
- **The key rule** also reads `--password hunter2` (a flag that names a secret takes the next word; a
  quoted word runs to its plain closing quote; another long flag, `$VAR` and a reference are left alone),
  colour codes (`\x1b[0m`) around a key, its separator and its value, a tab written as backslash and `t`
  before the separator, and commented-out blocks (`# token: |` takes the `#` lines below it). A list
  marker (`- name: x`) counts as a key only as a sibling (its dash is left of the key's content column), so
  `tokens:` with an empty value takes the list below it. A line that is one quoted assignment (`NAME="x"`)
  counts as a key, so a secret ends at its next sibling in an all-quoted `.env` file. A plain value with
  spaces that opens no bracket and holds no quote, backtick or backslash takes only the deeper lines below
  it. For `Authorization` keys the scheme word stays, as in the header rule, so `Authorization: Bearer T`,
  `--token T` and a bare `Bearer T` give `T` one tag. A `<word>` after a flag is a placeholder in a usage
  text or a fix, and stays.
- **Words**: `method`, `mode`, `type`, `kind`, `scheme`, `provider`, `stdin` and `env` join the name
  suffixes (`auth_method` is not a secret), `length`, `secs` and `sec` join the unit words, and
  `authenticate` is not a stem hit.
- **Evidence URLs**: `rdy_engine::redact::evidence_url` returns `scheme://host:port/path` with no userinfo,
  query or fragment, and `None` for text that is not a URL or has an `@` after its authority (a raw `/` in a
  password, a digest, a scoped package path, a query value). A check stores that and never the URL it was
  given (03, "Redaction in evidence").

## Appendix C: layout, compression and manifest sample

One top directory, so extracting never spills into the current directory; regular files only; deterministic
headers (uid and gid 0, mode 0644, mtime the bundle time); names with no `..` or control characters.
`rdy bundle` creates `rdy-bundle-<product>-<ts>/` under `--out-dir` through `cap-std` (0700, `create_new`, temp
then rename) holding `rdy-bundle-<product>-<ts>.tar.zst` (0600) and its `.sha256`; an interrupted run writes
nothing. `zstd` level 3, window log 23 (any decoder can read it), content checksum on, one frame, one thread.

```text
rdy-bundle-<product>-<ts>/
  README.txt   rdy/spec.yaml  rdy/spec.yaml.minisig  rdy/result.json  rdy/actions.json
  host/processes.txt  host/network/*.txt  host/disk.txt  host/kernel.log   container/*.txt
  k8s/<ns>/<kind>.jsonl  k8s/<ns>/events.jsonl   journal/journal-7d.log
  files/etc/acme/server.yaml        source path with the root stripped (Windows: files/C/...)
  manifest.json                     last: it needs every hash
```

```json
{
  "api_version": "rdy/v1", "kind": "BundleManifest",
  "bundle": { "id": "6c1f3c0e-2d54-4c52-9d4e-0a8f1e7c9b11", "created_at": "2026-11-04T10:15:00Z" },
  "producer": { "name": "rdy", "version": "0.2.0", "commit": "abc1234", "target": "x86_64-unknown-linux-musl" },
  "run_id": "b2d7f4a0-8e0c-4a61-8f3e-5c9a1d2e7f10",
  "spec": { "product": "acme-platform", "sha256": "<64 hex>", "serial": 7,
            "signature": { "state": "verified", "key_id": "7A3F9C21B04D55E1", "signed_at": "2026-10-30T09:00:00Z" } },
  "host": { "host_id": "0123456789abcdef", "os_family": "linux", "arch": "x86_64" },
  "redactor": { "set": "rdy-redact/1", "rules": [ { "name": "aws_access_key_id", "version": 1 } ],
                "groups_always": ["aws_keys", "emails"], "groups_from_spec": ["aws_keys"],
                "groups_from_flags": ["ipv4"], "groups_off_by_flags": [] },
  "entries": [
    { "path": "journal/journal-7d.log", "collector": "journal:7d", "status": "partial", "reason": "cap",
      "raw_size_kib": 89100, "bytes_out": 33554432, "sha256": "<64 hex of the stored bytes>",
      "truncated": true, "truncation": "tail", "redactions": { "aws_access_key_id": 3, "email": 13 },
      "residual_hits": 0, "collected_at": "2026-11-04T10:15:09Z" },
    { "path": null, "collector": "k8s:describe", "status": "skipped", "reason": "no_install_namespace",
      "hint": "add --namespace <ns>" }
  ],
  "totals": { "files": 38, "bytes_out": 64012345, "redactions": { "email": 14, "aws_access_key_id": 3 } },
  "caps": { "raw_bytes": 268435456, "archive_bytes": 104857600, "hit": ["journal:7d"] },
  "timing": { "started_at": "2026-11-04T10:15:00Z", "finished_at": "2026-11-04T10:15:41Z" }
}
```

## Appendix D: corpus cases

M1 has 28 cases, M2 adds 32. Counts are M1 / M2 added.

- `url` 3 / 1: proxy URL `http://svc:pa55@proxy.acme.test:3128`, Postgres DSN, percent-encoded password; M2 token-only userinfo.
- `auth` 4 / 1: Bearer, Basic, Proxy-Authorization, `X-Api-Key`; M2 Cookie in a quoted curl trace.
- `aws` 4 / 1: example key id in a log line, `AWS_SECRET_ACCESS_KEY=` env, JSON `SessionToken` with an `ASIA` id, INI credentials file; M2 secret by proximity.
- `pem` 2 / 3: RSA plain, PKCS8 with JSON-escaped `\n`; M2 OpenSSH, unterminated, `Proc-Type: 4,ENCRYPTED`.
- `kubeconfig` 2 / 1: `token:`, `client-key-data:`; M2 exec-plugin env with `refresh-token`.
- `rdy_token` 1 / 1: plain text; M2 inside an `Authorization` header (span union).
- `key_name` 5 / 1: `DB_PASSWORD=`, YAML `password:`, fake placeholder prefix, `--password=x`, JSON `"client_secret":`; M2 connection string.
- `jwt` 1 / 1: bare service-account token in a Kubernetes error string; M2 inside a cookie.
- `hostile` 1 / 1: ANSI-wrapped `password=hunter2`; M2 CRLF and YAML block scalar.
- `email` 0 / 2, `saas` and `cloud` 0 / 2, `k8s_secret` 0 / 2, `entropy` 0 / 2, `network` 0 / 2 (group on and off), `custom` 0 / 1, `binary` 0 / 2 (gzip skipped, UTF-16).
- `negative` 5 / 4. M1: a 40-hex git SHA, a UUID, a `BEGIN CERTIFICATE` block, `${DB_PASSWORD}` next to `secretName: acme-tls`, and `passed: 12` with `author: alice` (stem false positives). M2: a `sha256:` image reference, semver versions (`4.2.1-rc.1`), a `data:image/png;base64,` URI, a long Kubernetes name, prose such as "password policy requires 12 characters".
- `known_gap` 0 / 2: a key name in fullwidth letters, and a base64-wrapped short password, each with its unredacted output and a ticket.

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

Nothing else is sent: no cookies, no host details beyond the file, no telemetry. A result upload is the same
with `"kind":"result"` and `Content-Type: application/json`.

## Appendix F: streaming, binary and encodings (M2)

- Bundle entries are a line-oriented stream into a buffered entry (`tar` needs the size first): 64 KiB chunks,
  split at `\n`. A record over 1 MiB is force-split with a 16 KiB carry, and every rule's maximum match length
  is at most 16 KiB, so a secret cut by a boundary sits whole in the carry window. PEM state carries across
  chunks (Appendix B), so stream output equals whole-input output. Target: under 128 MiB RSS.
- The first 8 KiB is sniffed. A NUL byte, many control bytes, or a gzip, zstd, xz, bzip2, zip or tar magic
  number means binary: entry `skipped`, reason `binary` or `compressed`. rdy cannot prove a binary is
  redacted, so it does not ship one.
- UTF-16 (BOM, or NULs at every second byte) is transcoded to UTF-8 first (`transcoded_from`). Invalid UTF-8
  is redacted as bytes (`regex::bytes`), so a stray byte never disables a rule.

## Plan corrections found

- 00-overview.md `rdy-bundle` sketch: a `Redactor` trait per redactor cannot do span union, tags or streaming,
  and `build(.., out: &Path)` takes a plain path. Fix: one `Redactor` struct, a trait only for `Collector`, the
  `cap-std` `OutputDir`. CLAUDE.md layout lists redactors under `rdy-bundle/`; fix: "collectors, tar+zstd,
  manifest (reuses rdy-engine::redact)".
- 00-overview.md lines 46 and 397, rdy-plan.md "How a POC flows": `--token abc123` puts a bearer token in argv,
  world-readable in `/proc/<pid>/cmdline`. Fix: `RDY_TOKEN`, `--token-file` or the prompt; hidden `--token` exits 64.
- 01 2.8 and its ticket "Bundle block strict validation in rdy bundle": only three kinds listed, others "bad
  values", unknown kinds refused. Fix: list `host:*`, `container:runtime`, `k8s:describe` (no argument); skip an
  unknown kind, exit 64 on an unknown group; lint checks journal durations (1h to 30d). SEC-66 ignores
  `redact_patterns` for unpinned specs; fix: apply them (they only add) and let only `collect` fall back.
- `spec.v1.schema.json` `Bundle.collect` allows only `k8s:events` for `k8s:`. Fix: `^k8s:[a-z_]{1,32}$`.
- 01 section 5: add the placeholder grammar `[REDACTED:<rule>:<tag>]`. Answer to 01's question: `jwt` moves into M1.
- 02 Appendix A and ADRs 0015 and 0016 name `RedactedReport` and `write_report`. Fix: generic `Redacted<Report>`
  and `write_atomic(&Redacted<_>)` plus `write_spec_copy(&VerifiedSpecBytes)`, or keep the old names as aliases.
  ADR 0015 decision 1 stays: outside the `runtime` feature, no feature of its own.
- 02 watchdog (line 170) writes "already redacted" results; fix: it calls `redact_report` on its snapshot.
- 02 probe facade caps reads and output at 1 MiB. Fix: streaming `read_stream` and `exec_stream` with a cap from
  `CollectorInfo` (ADR 0014 amendment), and `/usr/local/bin` as an extra Linux exec directory, used as root only
  if directory and binary are root-owned and not group or world writable.
- 02 deny list: add `*/.docker/config.json`, `*/.config/containers/auth.json`, `*/.aws/credentials`,
  `*/.netrc`, `*/.git-credentials`, `*/.npmrc`, `*/.pgpass`, `/etc/ssh/ssh_host_*_key`,
  `/etc/kubernetes/pki/*`, `/var/lib/kubelet/pki/*`, `/etc/kubernetes/*.conf`. On the canonical target: macOS
  `/private/etc/...`, `/private/var/...`, `*/Library/Keychains/*`; Windows `C:\Windows\System32\config\*`,
  `*\.ssh\*`, `*\.aws\credentials`, `*\.docker\config.json`.
- ADR 0010 and the 02 guard table: bundle needs list on the Appendix A kinds and `events`; `pods/log` stays
  refused until `k8s:logs` has an ADR. ADR 0012: the manifest is a wire format `rdy-cloud` reads, so it lives
  in `rdy_spec::bundle` with `bundle-manifest.v1.schema.json`.
- 05 Surface 4: point 2 ("files listed in the output dir manifest") has no manifest to read in M1; point 5
  ("a receipt id and a URL") is wrong. Fix: upload accepts a typed `Report` or a bundle whose manifest and
  hashes verify; the client reads an upload id, receipt id, byte count and hash and builds URLs itself.
- 05 invariants: add INV-21 to INV-27. 21: every byte in a bundle passed the redactor, no temp file holds raw
  bytes. 22: the manifest holds no raw value, raw hash or tag key. 23: `rdy bundle` opens only the guarded kube
  connection. 24: no collected path is on the deny list and a spec cannot remove a built-in rule. 25: bytes
  sent hash to the consent value. 26: the token is never in argv, logs, the receipt or errors. 27: no socket or
  DNS query for the upload origin before the consent answer or after a no. Amend INV-09 to allow `rdy-bundle-*`
  and `upload-receipt-*.json` (`create_new`, 0600) and INV-11 to add "the upload origin, only in `rdy upload`
  after consent".
- 05 Appendix F, SEC-25, SEC-26, SEC-44 and 08 section 4: replacements are `[REDACTED:<rule>:<tag>]`; 60 cases
  in M1 and 300 in M2 become 28 and 60, gated on rule coverage; "false positives not gated" becomes "golden
  negatives match exactly from M1; the 2% budget is for the M2 log corpus"; SEC-25 (4h) and SEC-26 (3h) become
  the six tickets below, 14.5 hours.

## Decisions needing an ADR

- **Amend ADR 0015 (M1):** span union; HMAC, SHA-256 and RNG from `ring`; keyed tags; `Redacted<T>` with no
  public constructor, `From`, `Default`, `Deserialize` or `DerefMut`; the schema-aware walk with per-call
  counts; rules compiled in; no raw hashes. Conservative: all.
- **Manifest types in `rdy-spec`** (extends ADR 0012), not `rdy-bundle`.
- **Compression crate:** `zstd` (C, mature) or `ruzstd` (pure Rust, weaker ratio). Taken: `zstd`, if `cargo
  deny` passes and the size budget holds.
- **Upload transport:** single idempotent `PUT` to one origin; not a presigned URL or resumable upload.
- **Guard amendment for bundles** (ADR 0010): lists and events only; no `pods/log`, no Secrets. **Extra exec
  directory** and the macOS and Windows `container:runtime` gap (ADR 0014 amendment).
- **k8s collectors live in `rdy-bundle`** behind a `k8s` feature, using the guarded client from
  `rdy-checks-k8s`. Alternatives: inside `rdy-checks-k8s`, or a new crate.
- **Email opt-out:** cli-ux owns the name. The rule is fixed: customer only, argv only, `rdy bundle` only,
  shown at consent and in the manifest. Alternative: no opt-out.
- **Open with rdy-cloud:** `Content-Digest`; an idempotent repeat of a `PUT` with `409` on a different digest;
  `Idempotency-Key` semantics on the `POST`; a web drop page on the share link; resumable upload as an M3 call.

## Tickets implied

Reused titles are exact so 11-backlog.md can dedupe. Titles carry no commas; dependencies are separated by `;`.
M1 redactor: six tickets, 14.5 hours, plus a 0.5-hour clause on SEC-31 (15 hours in all).

- [M1] Amend ADR 0015 with span union and keyed tags and Redacted<T> and ring | owner: rust-architect | est: 1h | depends on: none | exit test: ADR 0015 is Accepted with the bullet above and a security-reviewer sign-off.
- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 2.5h | depends on: Amend ADR 0015 with span union and keyed tags and Redacted<T> and ring; Define result model and verdict mapping in rdy-spec | exit test: overlapping spans give one placeholder, equal secrets share a tag per Redactor, `password=[REDACTED:x:00000000]hunter2` is redacted, and `Redacted` has no public constructor or Deserialize.
- [M1] M1 redaction rules for URLs and auth headers and AWS keys and PEM keys and JWTs and rdy tokens and key names | owner: rust-engineer | est: 3.5h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: the 23 positive corpus inputs come out typed with quotes kept, and `secretName: acme-tls`, `${DB_PASSWORD}`, `passed: 12` and a certificate are unchanged.
- [M1] Redact then cap every Report string and return RedactedReport | owner: rust-engineer | est: 2.5h | depends on: SEC-25 Minimal redactor for evidence, errors and logs; Map outcomes to CheckResult with fix source, partial and needs | exit test: a PEM key across a 64 KiB cap is fully redacted, 01's sample reports 7.2 to 7.4 round-trip byte-identical apart from planted canaries, `by_rule` is the same with RUST_LOG unset and at trace, the watchdog report is redacted, and an error exits 70 with no report.
- [M1] Redacting tracing writer and panic hook and CLI error text | owner: rust-engineer | est: 2h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: canaries in env, kubeconfig, command output and a tracing field never reach stderr at RUST_LOG=trace (the proxy URL canary moves to M1-060, PC-43).
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 3h | depends on: M1 redaction rules for URLs and auth headers and AWS keys and PEM keys and JWTs and rdy tokens and key names | exit test: the 28 cases run in `cargo test` on five legs and the harness fails on a survivor or a rule or syntax form with no positive case.
- Fold, +0.5h on "SEC-31 Docs security page and verify-first install": list the M1 rules, what stays (hostnames, addresses, encoded values, the verified spec copy) and the placeholder format.

M2 and later (coarser; split to four hours or less when M2 is planned):

- [M2] Redactor property tests and the schema-walk canary test | owner: qa-engineer | est: 3h | depends on: SEC-26 M1 redaction corpus | exit test: idempotence and planted-secret properties hold.
- [M2] CI redaction gate with known-gaps ledger | owner: release-engineer | est: 2h | depends on: SEC-26 M1 redaction corpus | exit test: a separate job in ci-ok fails below FLOOR 60 and on a gap that starts to pass.
- [M2] Streaming redactor with line framing and PEM state | owner: rust-engineer | est: 7h | depends on: SEC-26 M1 redaction corpus | exit test: stream equals whole-input output at every split offset.
- [M2] Binary and compressed and UTF-16 handling in the redaction pipeline | owner: rust-engineer | est: 4h | depends on: Streaming redactor with line framing and PEM state | exit test: gzip is skipped with a reason and UTF-16 is redacted.
- [M2] Bundle rules for emails and SaaS tokens and cloud credentials | owner: rust-engineer | est: 6h | depends on: Streaming redactor with line framing and PEM state | exit test: new cases pass and `--keep-emails` sets `groups_off_by_flags`.
- [M2] Bundle rules for entropy and IPv4 and IPv6 and MAC | owner: rust-engineer | est: 6h | depends on: Streaming redactor with line framing and PEM state | exit test: opt-in groups stay off unless asked and false positives are under 2%.
- [M2] Spec and CLI additions for redact_patterns and max_size and redact-pattern | owner: rust-engineer | est: 2h | depends on: Streaming redactor with line framing and PEM state | exit test: 33 patterns or an unknown group exit 64.
- [M2] Residual scan and per-entry fail-closed handling and non-dumpable process | owner: rust-engineer | est: 4h | depends on: Streaming redactor with line framing and PEM state | exit test: a planted rule gap shows `residual_hits` and Linux shows `Dumpable: 0`.
- [M2] SEC-44 Full redaction corpus with chunk-boundary cases | owner: qa-engineer | est: 7h | depends on: Bundle rules for emails and SaaS tokens and cloud credentials | exit test: the 60 cases pass at every split offset, CI fails under 25 MiB/s or over 128 MiB RSS, and a pinned second-opinion scanner finds only allowlisted false positives.
- [M2] Bundle manifest wire types and schema in rdy-spec | owner: rust-engineer | est: 4h | depends on: Generate JSON schemas with schemars and check drift in CI | exit test: the Appendix C sample validates and no field holds a raw hash.
- [M2] Collector trait and registry and caps and truncation markers | owner: rust-engineer | est: 8h | depends on: Bundle manifest wire types and schema in rdy-spec | exit test: unknown kinds are skipped and every cut carries the 5.2 marker.
- [M2] Bundle scope in the probe facade with streaming reads and deny-list additions | owner: rust-engineer | est: 7h | depends on: File and env read policy in the facade | exit test: a 32 MiB file streams under its cap and every deny-list path is refused.
- [M2] SEC-43 Bundle collector path policy | owner: security-reviewer | est: 4h | depends on: Bundle scope in the probe facade with streaming reads and deny-list additions | exit test: symlink escapes are refused and `--plan` shows the resolved list.
- [M2] Collectors for file glob and Linux host and journal and container runtime | owner: rust-engineer | est: 20h | depends on: SEC-43 Bundle collector path policy | exit test: fixtures produce the Appendix A files and cmdline and environ are never read.
- [M2] Kubernetes guard amendment and collectors for events and describe | owner: rust-engineer | est: 10h | depends on: Read-only guard layer and test for rdy-checks-k8s | exit test: the mock API server sees only list and get on the Appendix A kinds and env values are stripped.
- [M2] macOS and Windows host collectors | owner: rust-engineer | est: 8h | depends on: Collectors for file glob and Linux host and journal and container runtime | exit test: recorded outputs produce the files.
- [M2] Archive writer with layout and deterministic headers and archive cap | owner: rust-engineer | est: 6h | depends on: Collector trait and registry and caps and truncation markers | exit test: a fixed key and clock and bundle id give identical bytes, and incompressible fixtures never give an archive over 100 MiB.
- [M2] rdy bundle command and plan and built-in collector set and redact | owner: rust-engineer | est: 8h | depends on: Archive writer with layout and deterministic headers and archive cap | exit test: a fixture run writes the bundle and `--plan` reads no file and opens no socket.
- [M2] No-socket and no-stray-file tests for rdy bundle | owner: qa-engineer | est: 3h | depends on: rdy bundle command and plan and built-in collector set and redact | exit test: only the kube fixture is contacted and canaries appear in no file.
- [M2] SEC-42 Share-link token format and scope | owner: security-reviewer | est: 4h | depends on: none | exit test: the token spec is agreed with rdy-cloud.
- [M2] Upload pre-flight with single-pass scan and hash and bounded decode | owner: rust-engineer | est: 4h | depends on: Residual scan and per-entry fail-closed handling and non-dumpable process | exit test: a zstd bomb and a 20,000-entry tar exit 64 within 5 s.
- [M2] Upload token input and consent screen | owner: rust-engineer | est: 4h | depends on: SEC-42 Share-link token format and scope; Upload pre-flight with single-pass scan and hash and bounded decode | exit test: FIFO and group-readable token files and `--token` exit 64.
- [M2] SEC-41 Upload client with consent and receipt and exact bytes | owner: rust-engineer | est: 4h | depends on: Upload token input and consent screen | exit test: fake-server tests prove steps 3 to 5 and retries reuse the upload id.
- [M2] Fake upload server and offline behaviour tests | owner: qa-engineer | est: 4h | depends on: SEC-41 Upload client with consent and receipt and exact bytes | exit test: every test in section 6 passes on five legs.
- [M2] Security review of the bundle pipeline and upload client | owner: security-reviewer | est: 4h | depends on: Fake upload server and offline behaviour tests; SEC-44 Full redaction corpus with chunk-boundary cases | exit test: blockers fixed before a design partner gets an M2 build.
- [M2] Bundle and upload docs and README output | owner: docs-writer | est: 3h | depends on: rdy bundle command and plan and built-in collector set and redact | exit test: the Bundles page matches `--list-collectors`.
- [M3] Pod logs collector k8s logs with its own ADR | owner: k8s-expert | est: 6h | depends on: Kubernetes guard amendment and collectors for events and describe | exit test: tail-limited logs are collected through an amended guard.
- [M3] OS log collectors for macOS and Windows | owner: rust-engineer | est: 8h | depends on: macOS and Windows host collectors | exit test: recorded unified-log and event-log fixtures are collected and redacted.
- [M3] Resumable upload | owner: rust-engineer | est: 8h | depends on: SEC-41 Upload client with consent and receipt and exact bytes | exit test: a cut upload resumes with the remaining bytes only.
