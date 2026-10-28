# 04 Bundle and redaction

Owners: rust-engineer (drafted it) and security-reviewer (joint owner; wrote sections 3, 4 and 6 of draft 2).
Status: draft 2, 2026-10-28. Sections 3, 4 and 6 are confirmed by security-reviewer. Date: 2026-10-28.

This note designs the redactor, the collectors, the bundle archive and manifest, and the opt-in upload.
It builds on ADRs 0002, 0003, 0004, 0007, 0008, 0009, 0010 and 0012, on 02-engine-design.md (probe facade,
action log, output confinement) and on 05-threat-model.md (Surface 4, INV-15, INV-20, Appendix F). Field
names follow `crates/rdy-spec/schema/*.json` and 01-spec-format.md (revision 0). Where 01 differs, 01
wins and this note follows. Everything on the server side (storage, viewer, analyzers) belongs to
`rdy-cloud` and is out of scope. Where I propose a server behaviour, it is a request to `rdy-cloud`.

## Decisions in one screen

1. One redactor engine, `rdy_engine::redact` (02, ADR 0015). M1 ships the whole-string minimum (section 1).
   M2 adds streaming and the rest. It is one compiled rule set, not a chain of trait objects. Rules find
   spans in the original text, overlapping spans merge into their union, and the output is written once.
2. Rules are compiled into the binary. A spec can add redaction and can never remove a built-in rule. A
   customer can add more on the command line. The one subtraction is the customer's own `--keep-emails` on
   `rdy bundle`, argv only, shown at consent and in the manifest.
3. A placeholder is `[REDACTED:aws_access_key_id:3fa9c01b]`. The tag is a keyed hash with a random key made at
   process start and never stored. Same secret, same tag, inside one run only.
4. Every writer (report, log, archive) accepts only a `Redacted` value, which only the redactor can build.
   No temp file ever holds raw bytes.
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
| Redactor API | `redact_str` and `redact_report` (whole string), counts, keyed tags, the `Redacted` gate | `redact_bytes`, streaming `RedactStream`, residual scan | none |
| Rules | the ten M1 rules below | emails, JWTs, SaaS token prefixes, GCP and Azure credentials, Kubernetes Secret manifests, generic high-entropy tokens, AWS secrets by proximity, IPv4, IPv6 and MAC (opt-in), custom patterns | more prefixes as reports arrive |
| Where it runs | every string in the `Report` including the action log, error output, `--json` stdout, the `tracing` layer and panic messages | every byte of every bundle entry, the result JSON it embeds, and the manifest | `rdy report` re-render input |
| Tests | 20 golden cases in `cargo test` (section 4) | 60 cases, property tests, chunk offsets, fuzzing, second-opinion scanner, throughput floor, own CI job | grows with every miss report |
| Collectors, archive, manifest | none | all of section 2 and 5 on Linux and Kubernetes; basic macOS and Windows | `k8s:logs`, OS log collectors on macOS and Windows |
| `rdy bundle` | none | yes | none |
| `rdy upload`, receipt | none | yes, single `PUT` | resumable upload if partners need it |
| Result schema | `redaction { ruleset, total, by_rule }` (01, already in the schema) | manifest schema in `rdy-spec` | none |

**The M1 minimum redactor.** `rdy_engine::redact` with the whole-string API only, the keyed tag, span union
and the `Redacted` writer gate (section 3). It has ten rule names built from five matchers: token shapes
(`aws_access_key_id`, `rdy_share_token`), header names (`auth_header`, `api_key_header`), URL userinfo
(`url_userinfo`), PEM blocks (`pem_private_key`, to the END line or, if there is none, to the end of the
string), and one key-name matcher with four stem lists (`secret_by_key`, `kubeconfig_credential`,
`aws_secret_access_key`, `aws_session_token`) over `=`, `:`, JSON members and `--flag=` forms. That covers
every M1 category in 05 Appendix F. `redact_report` runs once on the finished `Report`, over every string
leaf and object key including the action log, before the JSON file, the HTML, `--json` stdout and the
terminal summary exist. The 02 field caps run after it. The same `redact_str` wraps the `tracing` writer,
the panic hook and CLI error text. Tests are a golden corpus of 20 synthetic cases (16 positive, 4
negative) in the normal `cargo test` job, growing to 60 in M2. Cost: 12.5 hours (Tickets implied). There
is no cut below this line: it is 05 INV-15.

M1 does not contain collectors, an archive, a manifest or any upload code. 05 says the same ("M1 has no
upload code").

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

Confirmed by security-reviewer on 2026-10-28. Changes from draft 1 are in Plan corrections.

### 3.1 The contract

These hold in every milestone. ADR 0015 records them and CI tests each one.

1. **Compiled in, add only.** Rules, thresholds and the placeholder format ship in the binary: no rule
   files, no dictionaries, no downloads. A spec can switch on optional groups and add `redact_patterns`. It
   cannot remove or weaken a built-in rule. An unknown group exits 64, because a missing rule is a leak.
   The customer can add groups and patterns on argv. The only subtraction is the customer's
   `--keep-emails` (3.6).
2. **Spans, merged by union.** Every rule runs on the original text and reports `(start, end, rule,
   priority)`. Spans that overlap or touch merge into one span covering their union, named after the
   highest priority rule in it. The output is written once, so no rule sees a placeholder and no partly
   overlapped span leaves bytes behind.
3. **Keyed tag, no stored key** (3.3).
4. **Typed writers.** Only a `Redacted<T>` reaches a writer (3.5).
5. **Binary is skipped**, never shipped, because rdy cannot prove it is redacted (3.4).
6. **No raw digests.** Nothing hashes raw content. The keyed tag is the only value derived from a secret.
   The manifest holds the sha256 of the stored, redacted bytes.
7. **Fail closed.** An error or panic inside redaction drops the string or entry and records why. There is
   no raw fallback. If the OS RNG cannot make a key, rdy exits 70.

### 3.2 Model

```rust
// rdy_engine::redact (feature `redact`, independent of `runtime` so rdy-cloud can reuse it)
pub struct Redactor { /* Arc<CompiledRules>, TagKey, per-rule AtomicU64 counts */ }
pub struct Redacted<T>(T);   // built only in this module: no pub constructor, From, Default or Deserialize
impl<T> std::ops::Deref for Redacted<T> { type Target = T; /* no DerefMut */ }
impl Redactor {
    pub fn new(set: RuleSet, extra: &Extra, key: TagKey) -> Result<Self, RedactError>; // only custom regex can fail
    pub fn redact_str(&self, s: &str) -> Redacted<String>;             // M1
    pub fn redact_report(&self, r: Report) -> Redacted<Report>;       // M1
    pub fn redact_bytes(&self, b: &[u8]) -> Redacted<Vec<u8>>;        // M2
    pub fn stream(&self) -> RedactStream;                              // M2: push(chunk, out), finish(out)
    pub fn summary(&self) -> Redaction;                                // 01: ruleset, total, by_rule. Never values
}
impl TagKey { pub fn random() -> Result<Self, RedactError>; }         // ring SystemRandom; Debug prints TagKey(..)
pub enum RuleSet { Report, Bundle }                                    // Bundle is a superset of Report
```

- One `Redactor` per process, built in `main` before the spec is read. The report, the logs and (M2) the
  bundle share its key and counts.
- `redact_report` turns the `Report` into a `serde_json::Value` and redacts every string leaf and object
  key. A member whose key matches a secret key stem, and the `value` of a `{name, value}` pair whose `name`
  matches, is replaced whole. It then deserializes and applies the 02 field caps, which never cut inside a
  placeholder. A field added to the result later is covered with no code change.
- **Priority**, highest first: PEM and Kubernetes Secret blocks; token shapes (AWS key ids, `rdy_st_`,
  JWTs, SaaS prefixes); auth headers and cookies; URL userinfo; key names and kubeconfig credentials;
  custom patterns; emails; opt-in IPv4, IPv6 and MAC; generic entropy. Priority only names a merged span.
  It never shrinks what is replaced.
- **Groups.** Specs name groups (Appendix B); placeholders and the manifest use rule names. Every group
  except `ipv4`, `ipv6` and `mac` is always on. Listing an always-on group changes nothing; listing an
  optional one turns it on.
- **Structure is kept.** A span excludes quotes and delimiters: `password="hunter2"` becomes
  `password="[REDACTED:secret_by_key:1a2b3c4d]"`, so JSON and YAML stay parseable. A PEM block becomes one
  placeholder line. The key-name rule skips a value only when it is exactly one well-formed placeholder
  (`^\[REDACTED:[a-z0-9_.]+:[0-9a-f]{8}\]$`), so `password=[REDACTED:x:00000000]hunter2` is still redacted.
- **Not decoded.** Rules tolerate `\"`, `@`, `%40` in userinfo and literal `\n` in JSON-escaped PEM.
  rdy does not decode base64, double encoding or compressed values. An encoded secret not caught by key
  name or entropy stays. The docs say so and point to `--redact-pattern`.

### 3.3 Placeholder and the stable tag

`[REDACTED:<rule>:<tag>]`. Rule names are `[a-z0-9_.]` (`custom.<name>` for custom patterns). The tag is the
first 4 bytes of `HMAC-SHA256(key, secret_bytes)` as 8 lowercase hex digits.

- `key` is 32 bytes from `ring::rand::SystemRandom`, made once per process, held in memory only. It is
  never written or logged, and never in the manifest, the receipt or an error.
- Keyed because an unkeyed hash of a short password is a lookup table. With a random key the tag only says
  "these two values are equal", inside this process. Two bundles from the same host differ.
- The input is the secret bytes only, not the rule name, so one password in a URL and in an env var gets
  one tag.
- 32 bits gives a 1% collision chance at about 9,000 distinct secrets. A collision merges two labels. It
  never reveals a value.
- `TagKey::fixed(..)` exists only under feature `testing`, which CI keeps out of the release binary (02).
  The corpus normalizes tags to `~`.

### 3.4 Streaming, binary and encodings (M2)

M1 redacts each report string, error and log line whole, before the field caps (02 review MF-05); each is
bounded by the facade's 1 MiB output cap. M2 bundle entries are a line-oriented stream into a buffered
entry, because a journal is far bigger than one string and `tar` needs the size first.

- 64 KiB chunks, split at `\n`, complete records redacted. A record over 1 MiB is force-split with a 16
  KiB carry. Every rule declares a maximum match length of at most 16 KiB, checked at build, so a secret
  cut by a boundary sits whole in the carry window.
- PEM uses a small state machine: after `-----BEGIN ... PRIVATE KEY-----` it redacts while lines look like
  key material and stops at END or the first line that does not. Custom patterns never cross lines.
- Entry buffers hold redacted bytes only. Target: under 128 MiB RSS for a full default bundle.
- The first 8 KiB is sniffed. A NUL byte, a high share of control bytes, or a gzip, zstd, xz, bzip2, zip or
  tar magic number means binary: entry `skipped`, reason `binary` or `compressed`, counted in the summary.
- UTF-16 (BOM, or NULs at every second byte) is transcoded first and the manifest records
  `transcoded_from`. Invalid UTF-8 is redacted as bytes (`regex::bytes`), so a stray byte never disables a
  rule.

### 3.5 Where the guarantee lives

- **Writers.** `report::write_json`, `report::render_html`, `OutputDir::write_atomic` and (M2)
  `BundleWriter::add` take `&Redacted<_>` only. The verified spec copy goes through
  `OutputDir::write_spec_copy(&VerifiedSpecBytes)` because signed bytes must stay exact (02 review SF-03).
  The terminal summary and `--json` stdout come from the same `Redacted<Report>`. Skipping redaction is a
  compile error.
- **Logs.** A redacting writer under the `tracing` fmt layer redacts each formatted event whole before
  stderr. It is installed first in `main`. With `RUST_LOG` unset, hyper, h2, rustls, tower and kube are
  capped at warn (05 I2). The panic hook and CLI error chains print only redacted text (ADR 0008 points 8
  and 9).
- **Raw bytes** live only in memory owned by the collector task and the redactor: no temp file, no raw
  value in the action log (sizes only), in `tracing` or in an error (rule and offset, never text).
- **M2.** A failed entry is dropped with reason `redactor_error`. A residual scan re-checks stored bytes
  with the same rules, counts `residual_hits` and prints "this is a bug in rdy". Entry names are redacted
  in a filename-safe form (`REDACTED-<rule>-<tag>`). During `rdy bundle` and `rdy upload` on Linux, rdy
  calls `rustix::process::set_dumpable_behavior(NotDumpable)`, so a core dump or same-user `ptrace` cannot
  read raw text or the token. macOS and Windows have no safe equivalent (documented residual).
- **Versions.** Each rule has a version. Changing what it matches bumps it and needs security-reviewer
  approval. The manifest lists the set id (`rdy-redact/1`) and every rule version. Rules change only with a
  signed release.

### 3.6 Answers to draft 1's open questions

- **Hash of redacted bytes only: confirmed.** `bytes_in` is a count. `sha256` covers the stored redacted
  bytes; the sidecar covers the archive. A hash of a known template with one secret is a guessing oracle.
- **Emails in bundles: on by default, customer opt-out.** The Bundle set always redacts emails. Only the
  customer can turn that off, with `--keep-emails` on `rdy bundle`: argv only, no spec field, env var or
  config (cli-ux owns the name). The manifest lists it in `groups_off_by_flags`, and the summary and the
  consent screen print `not redacted  emails (--keep-emails)`. The M1 Report set has no email rule: the
  report shows the Kubernetes user on purpose (SEC-24) and ADR 0003's banner says to read it first.
- **Entropy thresholds: tunable, with a ticket.** Start at 24 or more characters, 4.0 bits or more per
  character, three of four classes, never pure hex of length 32, 40 or 64, UUIDs, `sha256:` digests or data
  URIs. They are constants in the rule table, set by the M2 ticket "Tune entropy rule thresholds against
  the corpus". Each change bumps the rule version.
- **Residual scan on upload: yes.** Pre-flight scans with the current rules and refuses on a hit (6.2). It
  cannot fix the file, because it sends exact bytes.
- **`PR_SET_DUMPABLE`: yes**, M2, Linux (3.5).

### 3.7 Limits and dependencies

| Limit | Value |
| --- | --- |
| Maximum match length of any rule | 16 KiB (checked at build) |
| Custom patterns | at most 32, each at most 256 chars (schema), compile size limit 256 KiB each |
| Cold compile, M1 report set | 20 ms or less on a CI runner (measured, not gated, in M1) |
| Throughput, bundle set (M2) | 50 MiB/s or more per core. CI fails under 25 MiB/s on the reference corpus |
| Full 256 MiB bundle with residual scan (M2) | under 15 s |

Rules compile once into a `LazyLock<Arc<CompiledRules>>` per `RuleSet`. M1 uses `regex` alone. M2 may add
an `aho-corasick` trigger-literal gate after a measurement. `regex` is linear time, so a hostile custom
pattern cannot backtrack.

Dependencies (05 policy). Approved: `regex` 1 (M1) and `aho-corasick` 1 (M2), rust-lang maintained, MIT or
Apache-2.0. HMAC-SHA256, SHA-256 and the RNG come from `ring`, already shipped by ADR 0009, so `hmac`,
`sha2` and `getrandom` are not added. `tar` and `zstd` are reviewed with their M2 ticket. `rdy-bundle`
adds a C compiler to the musl build, so 06's M2 size budget ticket must measure it.

## 4. Redaction test strategy

Confirmed by security-reviewer on 2026-10-28.

### 4.1 The golden corpus

All values are synthetic. Layout follows 05, Appendix F:

```text
tests/fixtures/redaction/
  FLOOR                      # minimum case count: 20 in M1, 60 in M2. It only goes up
  known-gaps.toml            # (M2) known_gap cases, each with a ticket id
  synthetic.toml             # secret values stored in parts, for push-protection safety
  <category>/<case>.in       # input
  <category>/<case>.expected # exact output with tags normalized to ~
  <category>/<case>.toml     # metadata
```

```toml
# aws/env-secret-key.toml
polarity = "positive"                       # positive | negative | known_gap (M2)
rules = ["aws_secret_access_key"]           # rules that must fire (positive only)
since = "m1"                                # m1 | m2
rulesets = ["report", "bundle"]             # run against each set
secrets = ["${SYN:aws_example_secret}"]     # strings that must not appear in the output
```

- `${SYN:name}` is expanded from `synthetic.toml`, where values are stored as parts, so push protection
  never sees a whole token. The vendor-documented `AKIAIOSFODNN7EXAMPLE` is used as is.
- The harness redacts `.in` with a fixed test key, replaces every tag with `~`, and compares with
  `.expected` byte for byte. Negatives have `.expected` equal to `.in`.
- On every case the harness also checks three things on its own: no string in `secrets` appears in the
  output (the oracle, which catches a wrongly blessed `.expected`), `redact(output) == output`
  (idempotence), and the same rule set finds no span in the output outside placeholders (residual).
- `.expected` files are written and blessed by hand. `UPDATE_GOLDENS=1` never touches this directory (08).
- Every missed-secret report adds a case before the fix (05).

### 4.2 Sixty cases by category

M1 has 20 cases: 16 positive across every M1 category in 05 Appendix F, and 4 negative. M2 adds 40 for the
bundle rules and the hostile forms. The 60 include 11 negatives (they must come out unchanged) and 2 known
gaps. Generated chunk-offset variants and property cases (M2) come on top and are not counted.

| Category | M1 | M2 adds | Total | Cases (M1 first) |
| --- | --- | --- | --- | --- |
| `url` | 3 | 1 | 4 | proxy URL `http://svc:pa55@proxy.acme.test:3128`, Postgres DSN, percent-encoded password; M2: token-only userinfo |
| `auth` | 3 | 1 | 4 | Bearer, Basic, Proxy-Authorization; M2: Cookie and `X-Api-Key` in a quoted curl trace |
| `aws` | 2 | 2 | 4 | vendor example key id in a log line, `AWS_SECRET_ACCESS_KEY=` env; M2: `ASIA` id with JSON `SessionToken`, INI credentials file |
| `pem` | 2 | 2 | 4 | RSA plain, PKCS8 with JSON-escaped `\n`; M2: OpenSSH, unterminated |
| `kubeconfig` | 2 | 1 | 3 | `token:`, `client-key-data:`; M2: exec-plugin env with `refresh-token` |
| `rdy_token` | 1 | 1 | 2 | plain text; M2: inside an `Authorization` header (checks the span union) |
| `key_name` | 3 | 3 | 6 | `DB_PASSWORD=`, YAML `password:`, fake placeholder prefix `password=[REDACTED:x:00000000]hunter2`; M2: `--password=x`, JSON `"client_secret":`, connection string `Password=...;` |
| `hostile` | 0 | 3 | 3 | ANSI-wrapped, CRLF, YAML block scalar |
| `email` | 0 | 3 | 3 | plain, `@`, `%40`; one case run with `--keep-emails` expects the address kept |
| `jwt` | 0 | 2 | 2 | bare, inside a cookie |
| `saas` | 0 | 2 | 2 | GitHub and Slack prefixes, built from parts |
| `cloud` | 0 | 2 | 2 | GCP service-account JSON `private_key`, Azure connection string with `AccountKey` and SAS `sig` |
| `k8s_secret` | 0 | 2 | 2 | `data:` and `stringData:` in a `kind: Secret` document |
| `entropy` | 0 | 2 | 2 | one positive and one negative near the thresholds |
| `network` | 0 | 2 | 2 | IPv4 with the group on; the same input with it off, unchanged (negative) |
| `custom` | 0 | 2 | 2 | named group `secret`, whole match |
| `binary` | 0 | 2 | 2 | gzip file skipped with its reason, UTF-16 log redacted as UTF-8 |
| `negative` | 4 | 5 | 9 | M1: git SHA, UUID, `BEGIN CERTIFICATE` block, `${DB_PASSWORD}` with `secretName: acme-tls`; M2: Appendix D |
| `known_gap` | 0 | 2 | 2 | fullwidth-letter key name, base64-wrapped short password: unredacted on purpose, each with a ticket |
| Total | 20 | 40 | 60 | |

### 4.3 Property tests, fuzzing and a second opinion (M2)

08's ticket "Redactor property tests and the schema-walk canary test" covers: no generated secret
survives, no residual match, idempotence, stable tags, no panic or hang on arbitrary bytes, and stream
output equal to whole-input output at any split points. Generators come from the rules, so they cannot
find a form the rules do not know: that is why the corpus exists, plus a cargo-fuzz target on
`RedactStream` (SEC-45) and a pinned, independent secret scanner over every redacted bundle fixture
(zero findings apart from an allowlist with a reason per entry).

### 4.4 The CI gate

- **M1.** The harness is a `cargo test` in `rdy-engine`, so it runs in the existing test job on all five
  legs and is part of `ci-ok`. It fails on a survivor, a rule that did not fire, an `.expected` mismatch
  (negatives included), an idempotence or residual failure, or fewer cases than `FLOOR`.
- **M2.** A separate required `redaction` job adds: property tests (256 cases per PR, 100,000 nightly), the
  known-gaps ledger (a gap that starts to pass fails with "promote it", a gap missing from the ledger
  fails), the second-opinion scanner, the throughput and memory floor, and a false-positive budget of 2%
  on the reference log corpus used for throughput.

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
  flags, and always, and groups the customer switched off (`--keep-emails`, section 3.6).
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
sidecar has the sha256 of the compressed archive (after compression). security-reviewer confirms this
reading (3.6).

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

Confirmed by security-reviewer on 2026-10-28. Endpoints, headers and responses are a proposal to
`rdy-cloud` (SEC-42 owns the token format). The client rules hold whatever the server does.

### 6.1 Invariant

Nothing leaves unless the user typed `rdy upload` (or `--upload` on `run` or `bundle`) and then answered
yes or passed `--yes`. Before the answer no socket opens and no DNS query goes out; after a no, nothing
ever does. `rdy bundle` talks only to the Kubernetes API through the guard, for `k8s:` collectors. Tested
under `unshare -n` and `strace` (SEC-22 extended). This is 05 INV-20 plus INV-25 to INV-27.

### 6.2 Step by step

**Step 0. Pre-flight. No network.**

1. Open the file once (`O_NOFOLLOW` on Unix) and `fstat` the handle: a regular file, owned by the caller's
   euid, at most 100 MiB for a bundle and 16 MiB for a result. Every later read uses this handle, never the
   path again.
2. Decide the kind. A result is `.json` that parses into `rdy_spec::result::Report` (typed parsing, ADR
   0012 decision 7). HTML is refused (`fix: upload the .json file`). A bundle is `.tar.zst` whose frame
   decodes, with one top directory and regular files only, whose `manifest.json` parses and whose entry
   hashes match. Anything else exits 64, so `rdy upload /etc/shadow` stops here.
3. Residual scan: the Report rule set over a result, the Bundle rule set over every bundle entry. Any hit
   exits 64 with rule names and entry paths, never the text: `fix: create the file again with this rdy
   version`. A file rdy just wrote never hits. An edited or older file can.
4. Compute the size and sha256 of the exact bytes.

**Step 1. Token.** Precedence: `--token-file`, then `RDY_TOKEN`, then a hidden prompt. The consent screen
names the source.

- `--token-file <path>`, for scripts. Unix: opened with `O_NOFOLLOW`, owned by the euid, no group or other
  bits, else exit 64 with the `chmod 600` fix. Read through `take(257)`; over 256 bytes exits 64. `-`
  reads stdin, so `--yes` is required. Windows ACLs are not checked (documented residual).
- `RDY_TOKEN`, for CI. Not in the process list, but readable by the same user and root through
  `/proc/<pid>/environ`. rdy cannot clear it without `unsafe` (`remove_var`, edition 2024). The upload
  path starts no child; elsewhere the facade clears child environments.
- The prompt, for a person: `Share-link token (input hidden):`, no echo, only when stdin and stderr are
  both terminals.
- There is no `--token <value>`. A hidden flag of that name exists only to exit 64 with: "tokens on the
  command line show up in shell history and in `ps` for other users. Use `--token-file`, `RDY_TOKEN` or the
  prompt." On Linux `/proc/<pid>/cmdline` is world-readable by default. `environ` is not.
- With no TTY and no token: exit 64, `fix: set RDY_TOKEN or use --token-file`.
- The token is checked locally against `^rdy_st_[A-Za-z0-9]{20,64}$` before any request. A mistyped value,
  or a password pasted into the prompt by accident, never leaves the box.
- It is held in a `ShareToken` whose `Debug` and `Display` show only `rdy_st_...` and the last 4
  characters, and sent only as `Authorization: Bearer` (`HeaderValue::set_sensitive(true)`) to the
  consented origin. Never in a URL, a log line, the receipt or an error.

**Step 2. Consent.** The screen always prints to stderr, whether or not a question follows. Default is no.

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

- Only `y` or `yes`, in any case, is yes. Empty input, EOF, Ctrl-C and anything else is no: exit 64 and
  `Nothing was sent.`
- With no TTY, `--yes` is required. Without it: exit 64, `fix: add --yes to confirm the upload, or run this
  in a terminal`. A non-TTY run never prompts. On a TTY, `--yes` skips the question and the screen still
  prints.
- `--yes`, `--upload` and `--server` come from argv only, never env or config (as `--allow-unsigned`,
  INV-05). Docs say a command pasted from a vendor email should not carry `--yes`.
- `--server` takes an `https` origin only: no userinfo, path, query or fragment, and no plain `http`, not
  even for localhost (tests use 08's loopback TLS server). A non-default server adds a bold line,
  `server    https://staging.example.test (NOT the default Rdy Cloud server)`, also in the receipt.
- If the bundle was built with `--keep-emails`, the screen adds `not redacted  emails (--keep-emails)`.
  For a result JSON, the `redacted` line uses its `redaction.by_rule` counts.

**Step 3. Create the upload.** `POST /api/v1/uploads` with the token in `Authorization`, a JSON body of
`kind` (`bundle` or `result`), `file_name`, `size`, `sha256` and `rdy_version`, and an `Idempotency-Key` (a
UUID made once per invocation, reused on retry). The server answers `201`. The client reads `upload_id`,
which must match `^upl_[A-Za-z0-9]{16,64}$`, and `max_bytes`. It ignores every other field. The effective
cap is the smaller of `max_bytes` and the local 100 MiB: the server can lower it, never raise it. Over the
cap, the client stops with the size fix. This request carries metadata only. A failure here means no file
bytes left the machine, and the CLI says so. Appendix E has the exact bytes.

**Step 4. Send the bytes.** One `PUT /api/v1/uploads/<upload_id>/content`. The client builds the URL from
the validated id and never takes a URL from the server. Headers: `Authorization`, `Content-Type`
(`application/zstd` or `application/json`), `Content-Length`, `Content-Digest: sha-256=:<base64>:` (RFC
9530), `User-Agent`. The body is streamed from the step 0 handle, with no extra compression and no chunked
encoding, and hashed again on the way. The last chunk is held back until hash and count equal the consent
values; otherwise the request is aborted and rdy exits 70 ("the file changed during upload"). The server
answers `200` with `receipt_id` (`^rcp_[A-Za-z0-9]{16,64}$`), `upload_id`, `received_bytes` and `sha256`.
The last three must equal the client's values, or it is an error even on a `200` (exit 70).

**Step 5. Receipt and output.** The client writes `upload-receipt-<ts>.json` (local timestamp, never a
server value in a file name) through a `cap-std` handle on the file's directory, `create_new`, mode 0600. It
holds the receipt version, time, server origin, file name, kind, size, sha256, upload id, receipt id, the
server's echoed size and hash, and the rdy version. No token, no argv. This is the only write `rdy upload`
makes. If the directory is not writable, the receipt prints to stdout instead.

```text
uploaded    rdy-bundle-acme-platform-20261104T101500Z.tar.zst (12.4 MiB)
sha256      9f2c...e41a  (the server reports the same)
receipt     rcp_9Qx4...  saved to ./upload-receipt-20261104T102010Z.json
```

Server text is never printed raw. Errors map error codes to fixed local messages (`token_expired`,
`token_revoked`, `too_large`, `rate_limited`, `bad_digest`, `unsupported`). Anything unknown prints the HTTP
status and "unexpected answer from the server". Response bodies over 64 KiB are discarded.

### 6.3 Transport rules

- Client: the M2 upload client from ADR 0009 (reqwest, rustls with `ring`, platform verifier), no
  redirects (so the token cannot follow one to another host), the address policy on the server address, no
  cookies. `User-Agent` carries the rdy version and target only. No telemetry.
- Timeouts: connect 15 s (TLS included), 60 s without body progress, 60 s for the response, 30 min in all.
- Retries: connect errors, timeouts, `408`, `429`, `502`, `503`, `504`. At most 4 attempts, waits of 2 s,
  8 s and 30 s with 20% jitter, `Retry-After` honoured up to 60 s. A retry repeats the whole `PUT` to the
  same `upload_id`, so the server must accept a repeat of the same digest and return the same receipt. A
  `409` (another digest for the same id) and other `4xx` do not retry. The prompt is never asked twice.
- Proxy: `HTTPS_PROXY` and `NO_PROXY` as in ADR 0009, with the `ProxyUrl` mask. A plain proxy sees only
  `CONNECT app.getrdy.io:443`. An intercepting proxy whose CA the OS trusts sees the token and the file:
  that is the customer's own middlebox, and the docs security page says so. On `407` the CLI says the
  proxy wants credentials and shows the variable form without the password. NTLM and Negotiate are not
  supported; the hint points to the manual route. A TLS failure behind an interception proxy prints
  `SSL_CERT_FILE` advice and points at the `net.tls_intercept` result.

### 6.4 Offline

There is no pre-check connection. If step 3 cannot connect (DNS, refused, TLS, timeout), the CLI prints
this and exits 70:

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

### 6.5 Tests the client must pass (SEC-41 and the fake-server ticket)

No socket or DNS query before the answer, and none after a no (strace). A canary token never appears in
argv, stderr at `RUST_LOG=trace`, the receipt or any file. The fake server's bytes hash to the consent
value, and a file changed after consent aborts with 70. A `302` is not followed. `--server http://...`, a
token on argv, a group-readable token file, a residual-scan hit and a non-TTY run without `--yes` exit 64
before any request. `401`, `409`, `413`, `429` with `Retry-After`, `503` then success, a wrong echoed hash,
a dead proxy and no network each give their fixed message.

### 6.6 Open with rdy-cloud

- A single `PUT` restarts from zero on a bad link: about 7 minutes per try at 100 MiB and 2 Mbit/s.
  Resumable upload is an M3 decision, once a design partner hits it.
- Will `rdy-cloud` accept `Content-Digest`, an idempotent repeat of a `PUT`, and a web drop page on the
  share link? The offline text depends on the last one.
- Spec fetch with a share token is a different request, owned by SEC-42 and the portal.

## 7. The `rdy bundle` command surface

cli-ux owns the final names. This is the proposal.

```text
rdy bundle <spec> [--result <report.json>] [--out-dir <dir>] [--namespace <ns>] [--context <name>]
                  [--kubeconfig <path>] [--skip <collector-id>]... [--redact <group>,...]
                  [--redact-pattern <regex>]... [--max-size <size>] [--plan] [--list-collectors]
                  [--list-redactors] [--keep-emails] [--allow-unsigned] [--json] [--upload [--yes]]
rdy upload <file> [--token-file <path|->] [--server <https-url>] [--yes] [--json]
rdy redact [<file>|-]            # prints the redacted text. Lets a customer try the redactor. M2.
```

- `<spec>` is verified like `run` (ADR 0002). Without a `bundle:` block it exits 64:
  `fix: ask the vendor for a spec with a bundle: section`. The spec decides what is collected.
- `--result` embeds a result JSON. It is validated against the schema and redacted again, because rdy did not
  just produce it. `rdy run --bundle` (cli-ux to decide) would pass the in-memory report instead.
- `--redact` adds groups. `--redact-pattern` adds a regex. Neither can remove anything. `--keep-emails`
  is the only subtraction (3.6).
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
| `aws_secret_access_key` | `aws_keys` | 1 | by key name (`aws_secret_access_key`, `SecretAccessKey`). M2 adds a 40-char base64 value within 80 chars of a key id | the value |
| `aws_session_token` | `aws_keys` | 1 | by key name (`aws_session_token`, `SessionToken`, `x-amz-security-token`) | the value |
| `pem_private_key` | `private_keys` | 1 | `-----BEGIN [A-Z0-9 ]*PRIVATE KEY...-----` to END, plain or with literal `\n`; unterminated blocks | the whole block |
| `kubeconfig_credential` | `kubeconfig` | 1 | keys `token`, `client-key-data`, `password`, `access-token`, `refresh-token`, `id-token`, `client-secret` in YAML or JSON. `certificate-authority-data` and `client-certificate-data` are public and stay | the value |
| `rdy_share_token` | `rdy_tokens` | 1 | `rdy_st_[A-Za-z0-9]{20,64}` | the token |
| `secret_by_key` | `secrets_by_key` | 1 | a value that is exactly one placeholder is skipped. A key containing `pass`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential`, `auth`, `bearer`, `dsn` followed by `=` or `:`, in env, YAML, JSON, INI, flags (`--password=x`), systemd `Environment=`, connection strings (`Password=...;`, `AccountKey=...`) | the value, without quotes |
| `jwt` | `jwt` | 2 | `eyJ...` three base64url parts | the token |
| `github_token`, `gitlab_token`, `slack_token`, `stripe_key`, `google_api_key`, `npm_token`, `pypi_token`, `docker_pat` | `saas_tokens` | 2 | documented prefixes (`gh[pousr]_`, `github_pat_`, `glpat-`, `xox[baprs]-`, `[sr]k_live_`, `AIza`, `npm_`, `pypi-`, `dckr_pat_`) | the token |
| `gcp_service_account_key`, `azure_credential` | `cloud_credentials` | 2 | `"private_key"` in service-account JSON, `client_secret`, SAS `sig=`, `AccountKey=` | the value |
| `k8s_secret_data` | `k8s_secrets` | 2 | `data:` and `stringData:` values inside a `kind: Secret` document | each value |
| `email` | `emails` | 2 | `local@domain.tld`, also `\u0040` and `%40` forms. Always on in the Bundle set; only the customer's `--keep-emails` turns it off | the address |
| `ipv4` | `ipv4` (opt-in) | 2 | dotted quads that parse as addresses. `127.0.0.0/8`, `0.0.0.0`, `255.255.255.255` stay | the address |
| `ipv6` | `ipv6` (opt-in) | 2 | candidates that parse with `Ipv6Addr`. `::1` and `::` stay | the address |
| `mac` | `mac` (opt-in) | 2 | six hex pairs | the address |
| `entropy_token` | `entropy` | 2 | see 3.6: 24 or more chars, 4.0 bits per char or more, three character classes. Not pure hex of length 32, 40 or 64, UUIDs, `sha256:` digests, data URIs | the token |
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
    "groups_from_flags": ["ipv4"],
    "groups_off_by_flags": []
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

## Appendix D: negatives and known gaps in full

Negatives that must come out unchanged. M1: a 40-hex git SHA, a UUID, a `BEGIN CERTIFICATE` block (public),
and `${DB_PASSWORD}` next to `secretName: acme-tls`. M2: a `sha256:` image reference with digest, semver
and calendar versions (`4.2.1-rc.1`), a `data:image/png;base64,` URI, a long Kubernetes name
(`acme-platform-worker-7f9c6d8b5-x2k4m`), and prose such as "password policy requires 12 characters". The
`network` and `entropy` categories each add one negative. The key-name exclusions in Appendix B (empty
values, `secretKeyRef` blocks, file paths) are unit tests in the rules ticket, not corpus cases.

Known gaps (M2): a key name written with fullwidth letters, and a base64-wrapped short password. Each is
written down with its unredacted expected output and `polarity = "known_gap"`, so the gap stays visible.

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
  No such manifest exists in M1 (ADR 0003, 02). Fix: upload accepts only a result JSON that parses as a typed `Report`
  or a bundle whose manifest and hashes verify (section 6.2). Point 5 ("a receipt id and a URL") becomes "an upload id, a
  receipt id, a byte count and a hash"; the client builds URLs itself. Accepted by security-reviewer; 05
  revision 3 applies it.
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
  - INV-27: `rdy upload` opens no socket and sends no DNS query before the consent answer, and none after a
    no. Test: strace on the fake-server suite.
  - security-reviewer accepts INV-21 to INV-27 for 05 revision 3.
- docs/plan/05-threat-model.md, Appendix F, and docs/plan/08-testing.md, section 4: replacements are
  `[REDACTED:aws_access_key_id]`. Fix: add the keyed tag, `[REDACTED:<rule>:<tag>]`, and say the corpus
  normalizes it.
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
- docs/plan/10-devrel-and-launch.md, day 5 sample: `wrote ./rdy-bundle.tar.zst` and `redacted ... aws_keys`.
  Fix: the file sits in a new directory (ADR 0003 style) and the summary prints groups as in section 7.
- 05 Appendix F, SEC-26 and SEC-44, and 08 SEC-26: 60 corpus cases in M1, 300 in M2. Fix: 20 and 60 (4.2),
  then growth by miss reports; generated cases carry the volume. 05 revision 3 applies it.
- 05 Appendix F: "false positives counted, not gated, in M1". Fix: golden negatives match exactly from M1,
  because a hand-picked negative that changes is a regression; the 2% budget is for the M2 log corpus.
- 05 SEC-25 (4h), SEC-26 (3h) and 02 SEC-25 (4h): replaced by the six M1 tickets below, 12h plus a 0.5h
  clause on SEC-31. Draft 1 had 38.5h, far over the M1 budget.
- This note, 3.1 draft 1, "keeps the highest priority (then the longest)": a partly overlapped span leaked
  its uncovered bytes (INV-15). Fix: union of overlapping and touching spans.
- This note, 3.1 draft 1: the key-name rule skipped values starting with `[REDACTED:`, so
  `password=[REDACTED:x:00000000]hunter2` leaked. Fix: skip only an exact placeholder.
- This note, 3.5 draft 1: new crates `hmac`, `sha2`, `getrandom`. Fix: use `ring` (ADR 0009), which has all
  three (05 dependency policy).
- This note, 3.3 draft 1: report strings capped before redaction. Conflicts with 02 review MF-05. Fix:
  redact the whole string, then cap.
- 02, report renderers: `OutputDir::write_atomic(name, &[u8])` takes any bytes. Fix: `&Redacted<_>` only,
  plus `write_spec_copy(&VerifiedSpecBytes)` (02 review SF-03).
- This note, 6.2 draft 1: runtime validation against `result.v1.schema.json`. Conflicts with ADR 0012
  decision 7. Fix: typed parse.
- This note, 6.2 draft 1: `http` for localhost. Conflicts with CLAUDE.md rule 5 for a token path. Fix:
  `https` only.
- This note, 6.2 draft 1: `upload-receipt.json` with `create_new` fails on a second upload. Fix:
  `upload-receipt-<local ts>.json`.
- This note, 5.4, Appendix C and section 7: no place for the email opt-out (3.6). Fix: `--keep-emails` and
  `groups_off_by_flags`.
- This note, M1 ticket "Add the redaction summary to the result schema": 01 revision 0 already has
  `redaction { ruleset, total, by_rule }`. Fix: dropped. Likewise 01 has the spec half of the M2 ticket
  "Spec and CLI additions", which drops to 2h.
- This note, intro: "01-spec-format.md is not written yet". 01 revision 0 now exists. Fix: field names
  follow it.

## Decisions needing an ADR

- **ADR 0015 content (rust-architect writes it in M1).** Inputs from here: the module has its own feature
  `redact` so `rdy-cloud` can reuse it; the span-merge model; keyed placeholder tags; rules compiled in with no
  rule files; a spec cannot remove built-in rules; no hash of raw content anywhere; a `Redacted` type gates
  every writer. security-reviewer adds: overlapping spans merge into their union; HMAC, SHA-256 and the RNG
  come from `ring`; `Redacted` has no public constructor and no `Deserialize`. Conservative choice taken:
  all of these.
- **Manifest wire types in `rdy-spec`** (extends ADR 0012) rather than in `rdy-bundle`. Alternative: keep them
  in `rdy-bundle` and let `rdy-cloud` depend on it. Conservative choice: `rdy-spec`.
- **Compression crate.** `zstd` (C libzstd, mature, good ratio) or `ruzstd` (pure Rust, fewer features, weaker
  ratio). Conservative choice taken: `zstd` for correctness, flagged for security-reviewer because it adds C to
  a root binary and to the musl build. security-reviewer: acceptable for M2 if `cargo deny` passes, libzstd
  stays on the daily audit and the size budget holds. Revisit `ruzstd` once its encoder reaches level 3.
- **Upload transport.** Single `PUT` to one origin, idempotent. Alternatives: presigned object-store URL (a second
  destination to allow and show), resumable upload (tus or ranges). Conservative choice: single `PUT`, same
  origin, no server-supplied URLs.
- **Kubernetes guard amendment for bundles** (ADR 0010). Alternative: allow `pods/log` now. Conservative choice:
  object lists and events only; no `pods/log`, no Secrets.
- **Where k8s collectors live.** In `rdy-bundle` behind a `k8s` feature, using the guarded client from
  `rdy-checks-k8s`. Alternatives: inside `rdy-checks-k8s` (makes it depend on `rdy-bundle`), or a new crate.
  Conservative choice: `rdy-bundle`, no new crate.
- **Email opt-out flag.** cli-ux owns the name (`--keep-emails` proposed). The rule is fixed: customer only,
  argv only, `rdy bundle` only, shown at consent and in the manifest. Alternative: no opt-out at all.

## Tickets implied

Reused tickets keep their exact titles so 11-backlog.md can dedupe. Scope notes sit in the exit test.

M1 redactor: six tickets, 12 hours, plus a 0.5-hour clause on SEC-31 (12.5 hours in all). Everything else
from draft 1's M1 list moved to M2 below.

- [M1] Write ADR 0015 minimal redactor lives in rdy-engine | owner: rust-architect | est: 1h | depends on: none | exit test: the ADR is Accepted with the `redact` feature, the whole-string M1 API, span union, keyed tags from ring, compiled-in rules a spec cannot remove, no raw hashes and the `Redacted` writer gate, and carries a security-reviewer sign-off.
- [M1] SEC-25 Build minimal redactor for reports and evidence | owner: rust-engineer | est: 2.5h | depends on: Write ADR 0015 minimal redactor lives in rdy-engine, Define result model and verdict mapping in rdy-spec | exit test: unit tests show overlapping and touching spans become one placeholder named after the higher priority rule, equal secrets share a tag in one Redactor and differ across two, an exact placeholder is left alone while `password=[REDACTED:x:00000000]hunter2` is redacted, `Redacted` has no public constructor or Deserialize, and the TagKey Debug output is masked.
- [M1] M1 redaction rules for URLs, auth headers, AWS key ids, PEM keys, rdy tokens and key names | owner: rust-engineer | est: 3h | depends on: SEC-25 Build minimal redactor for reports and evidence | exit test: the 16 positive corpus inputs come out with typed placeholders and their quotes and delimiters kept, and `secretName: acme-tls`, `${DB_PASSWORD}`, an empty value and a BEGIN CERTIFICATE block are unchanged.
- [M1] Apply the redactor to every Report string before return | owner: rust-engineer | est: 2h | depends on: SEC-25 Build minimal redactor for reports and evidence, Map outcomes to CheckResult with fix source, partial and size caps | exit test: canary secrets placed in an observed value, a fix text, an env-derived message and an argv in the action log are redacted in both JSON and HTML, the field caps run after redaction, `redaction.by_rule` matches the canaries, and the report writers and `OutputDir` accept only `Redacted` values.
- [M1] Redacting tracing writer, panic hook and CLI error text | owner: rust-engineer | est: 1.5h | depends on: SEC-25 Build minimal redactor for reports and evidence | exit test: canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`, and a panic message and an anyhow chain carrying a canary print redacted.
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 2h | depends on: M1 redaction rules for URLs, auth headers, AWS key ids, PEM keys, rdy tokens and key names | exit test: a `cargo test` harness in the existing CI job runs the 20 synthetic M1 cases of section 4.2 on all five legs and fails on a survivor, a rule that did not fire, an `.expected` mismatch, a non-idempotent output, a residual match or fewer cases than `FLOOR`, and `UPDATE_GOLDENS=1` leaves the directory untouched.
- Fold, +0.5h on "SEC-31 Docs security page and verify-first install": the page lists the M1 rules, what stays (hostnames, addresses, encoded values) and the placeholder format.

Moved from draft 1's M1 list to M2: property tests (08 already has them in M2), the separate CI gate and
known-gaps ledger, the security-page redaction details beyond the fold, the security review ticket
(CODEOWNERS review of each redactor PR covers it), and the schema ticket (done in 01).

- [M2] Redactor property tests and the schema-walk canary test | owner: qa-engineer | est: 3h | depends on: Apply the redactor to every Report string before return | exit test: idempotence and the planted-secret properties hold, and a new string field added to the result schema is covered with no test change.
- [M2] CI redaction gate with case-count floor and known-gaps ledger | owner: release-engineer | est: 2h | depends on: SEC-26 M1 redaction corpus | exit test: a separate redaction job is part of ci-ok on all five legs and fails below the floor of 60, when a known gap starts to pass, and over the 2% false-positive budget on the reference log corpus.
- [M2] Tune entropy rule thresholds against the corpus | owner: security-reviewer | est: 2h | depends on: Bundle rules: entropy tokens, Kubernetes Secret manifests, IPv4, IPv6 and MAC | exit test: the chosen thresholds are recorded in the rule table with their false-positive rate on the reference corpus, and the entropy rule version is bumped.
- [M2] Non-dumpable process during rdy bundle and rdy upload on Linux | owner: rust-engineer | est: 1h | depends on: rdy bundle command, plan output and summary | exit test: `/proc/self/status` shows `Dumpable: 0` during a bundle run and an upload in CI, with no `unsafe` added.
- [M2] Streaming redactor with line framing, overlap window and PEM state | owner: rust-engineer | est: 8h | depends on: Apply the redactor to every Report string before return | exit test: stream output equals whole-input output for every split offset of every positive case.
- [M2] Bundle rules: emails, JWTs, SaaS tokens, GCP and Azure credentials | owner: rust-engineer | est: 6h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: the new corpus categories pass with zero survivors, the negatives are unchanged, and `--keep-emails` keeps addresses and is listed in `groups_off_by_flags`.
- [M2] Bundle rules: entropy tokens, Kubernetes Secret manifests, IPv4, IPv6 and MAC | owner: rust-engineer | est: 6h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: opt-in groups stay off unless asked, loopback and unspecified addresses stay, the corpus negatives are unchanged, and false positives on the reference log corpus are under 2%.
- [M2] Spec and CLI additions: bundle.redact_patterns, bundle.max_size and --redact-pattern | owner: rust-architect | est: 2h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a custom pattern redacts with a custom.<name> tag, 33 patterns or a regex over 256 chars exits 64, and an unknown group exits 64.
- [M2] Binary, compressed and UTF-16 handling in the redaction pipeline | owner: rust-engineer | est: 4h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a gzip file and a NUL-heavy file are skipped with a reason, a UTF-16 log is redacted as UTF-8, and invalid UTF-8 around a secret does not stop the rule.
- [M2] Residual scan and per-entry fail-closed handling | owner: rust-engineer | est: 3h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: a rule injected with a deliberate gap shows residual_hits above zero and the stored entry still contains no secret, and a panicking redactor drops the entry instead of writing raw bytes.
- [M2] Redaction throughput and memory floor in CI | owner: qa-engineer | est: 3h | depends on: Streaming redactor with line framing, overlap window and PEM state | exit test: CI fails under 25 MiB/s on the reference corpus and above 128 MiB RSS for a full default bundle.
- [M2] SEC-44 Full redaction corpus with chunk-boundary cases | owner: qa-engineer | est: 6h | depends on: Bundle rules: emails, JWTs, SaaS tokens, GCP and Azure credentials | exit test: the 60 cases of section 4.2, each positive also split at every offset, pass with zero misses and `FLOOR` is 60.
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
- [M2] SEC-41 Upload client with consent, receipt and exact bytes | owner: rust-engineer | est: 12h | depends on: Token input: prompt, RDY_TOKEN, --token-file and the refused --token, rdy bundle command, plan output and summary | exit test: fake-server tests prove steps 0 to 5 of section 6.2 and every test in 6.5, including no socket before the answer, the residual-scan refusal, the changed-file abort, retries to the same upload id and a receipt with no token.
- [M2] Fake upload server and offline behaviour tests | owner: qa-engineer | est: 5h | depends on: SEC-41 Upload client with consent, receipt and exact bytes | exit test: tests cover 401, 413, 429 with Retry-After, 503 then success, a wrong echoed hash, a redirect, a dead proxy and no network, with the section 6.4 text.
- [M2] Security review of the bundle pipeline and upload client | owner: security-reviewer | est: 4h | depends on: Fake upload server and offline behaviour tests, Second-opinion secret scan over redacted fixtures in CI | exit test: a review file is filed and every blocker is fixed before the first design partner receives an M2 build.
- [M2] Bundle and upload docs, and README output | owner: docs-writer | est: 3h | depends on: rdy bundle command, plan output and summary | exit test: the Bundles page lists collectors and groups exactly as --list-collectors and --list-redactors print them.
- [M3] Pod logs collector k8s:logs with its own ADR | owner: k8s-expert | est: 6h | depends on: Kubernetes guard allowlist amendment for bundles and Kubernetes collectors | exit test: tail-limited logs per container are collected through the guard with an amended allowlist, and the redaction corpus has log-line cases.
- [M3] OS log collectors for macOS and Windows | owner: rust-engineer | est: 8h | depends on: macOS and Windows variants of the host collectors | exit test: recorded unified-log and event-log fixtures are collected, capped and redacted.
- [M3] Resumable upload | owner: rust-engineer | est: 8h | depends on: SEC-41 Upload client with consent, receipt and exact bytes | exit test: an upload cut at 60% resumes with the remaining bytes only, if a design partner has hit the single PUT limit first.
