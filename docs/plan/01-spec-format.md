# 01 Spec format, result format, signing and the report contract

Owner: rust-architect. Status: draft, for review by security-reviewer and cli-ux. Date: 2026-10-28.

This is the `rdy/v1` contract. `rdy-cloud` consumes it from crates.io through `rdy-spec` (ADR 0012), so
every change follows section 3. The schema files are `crates/rdy-spec/schema/spec.v1.schema.json` and
`crates/rdy-spec/schema/result.v1.schema.json` (JSON Schema 2020-12, hand-written until the schemars
generator exists; see the README next to them). Where this text and a schema file disagree, the schema
file wins and this text gets a fix.

**ADRs this doc relies on:** 0001 (YAML, parser limits, version scalars), 0002 (minisign, trusted comment,
trust store, `--allow-unsigned`), 0003 (report files, self-contained HTML, embedded JSON), 0004
(timeouts), 0005 (no exec in M1), 0007 (versioning, unknown keys), 0008 (statuses, verdict, error codes),
0009 (egress policy, endpoint cap), 0010 (read-only kube guard), 0012 (wire types in `rdy-spec`,
provenance fields). It also builds on 02-engine-design.md for the needs model, skip reasons, the action
log and the not-applicable refinement of the verdict rule.

## 1. Three version numbers

| Thing | Example | Who bumps it | Rule |
| --- | --- | --- | --- |
| Wire format | `apiVersion: rdy/v1` in specs, `"api_version": "rdy/v1"` in results | rust-architect, by ADR | Changes only for a breaking change (3.3). |
| `rdy-spec`, `rdy-engine` crates | `0.1.0` | release-plz, per crate | Semver (ADR 0007). A release that changes the wire format adds a line to `schema/README.md` and a "Wire format" CHANGELOG entry. |
| `rdy` binary | `0.1.0` | release tag | Recorded in every result. |

A result records all three: `api_version`, `producer.rdy_spec`, `producer.version`.

## 2. The rdy/v1 spec

One YAML 1.2 document per file, at most 1 MiB, with the limits of ADR 0001: depth 64, no duplicate
keys, no merge keys, no anchors or aliases, one document.

### 2.1 Top level

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `apiVersion` | string | yes | Exactly `rdy/v1`. |
| `kind` | string | yes | Exactly `Readiness`. |
| `metadata` | object | yes | 2.2. |
| `checks` | list | yes | 1 to 256 entries, in report order. 2.3. |
| `bundle` | object | no | Diagnostics bundle request, used from M2. 2.8. |

### 2.2 metadata

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `product` | `^[a-z0-9][a-z0-9-]{0,62}$` | yes | Product slug (ADR 0003). Binds the signature to a pinned key and names the report directory and files. |
| `version` | string, max 64 | no | Product versions this spec covers, as a semver requirement (`">=4.2"`). Shown in the report, not evaluated: rdy cannot know the product version. |
| `contact` | string, max 256 | no | Where the customer asks questions. Shown as plain text, never as a link. |
| `serial` | integer, 0 or more | no | Spec revision, rising on every signed release. Recorded in the result. M2 warns when a lower serial follows a higher one for the same product (threat model T4). |
| `expires` | RFC 3339 UTC | no | After this, `rdy run` and `rdy verify` refuse the spec: exit 64, `spec_expired`. No override flag; the vendor sends a fresh spec. |
| `annotations` | map of string to string | no | Up to 32 entries. Labels for vendor tooling and the portal (for example a portal spec id). rdy ignores them and copies them into the result. The one place for extension data. |

### 2.3 Check entries

Each entry is a flat map: common fields and the parameters of its check id side by side, as in the
plan's example.

```yaml
- id: host.memory                                  # common
  min: 32Gi                                        # parameter of host.memory
  severity: block                                  # common
  fix: "Add RAM or choose a larger node class."    # common
```

| Common field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | `family.name`, lowercase | required | Families reserved in v1: `host`, `net`, `k8s`, `aws`, `gcp`, `azure`, `gpu`, `store`, `custom`. |
| `name` | `^[a-z0-9][a-z0-9_-]{0,62}$` | none | Makes the entry key unique when an id repeats (two `host.disk` paths). The key is `id` or `id/name`; keys are unique per spec. |
| `severity` | `block` or `warn` | `block` | The most a failing check can count for (2.6). |
| `fix` | string, 1 to 2000 chars | none | Replaces the built-in remediation text (2.6). |
| `timeout` | duration, 1s to 60s | the check's default, else 10s | Engine timeout. The effective value is `min(spec, check default, 60s, time left)` (02). |
| `os` | list of `linux`, `macos`, `windows` | all | Run only there. Elsewhere the check is `skipped` with `skip_kind: not_applicable`, which never counts toward the verdict (02). |

Not adopted from the catalog's assumed list: `optional` (`severity: warn` already says "not required")
and `severity: info` (a check that can never count is a measurement; it can come later as an additive
enum value).

### 2.4 Per-check parameters: a tagged union, decoded in two steps

Each id has its own parameters (`min`, `endpoints`, `via_proxy`, `access_modes`, `simulate`). The choice:

| Option | For | Against |
| --- | --- | --- |
| Tagged union on `id`, one closed parameter set per id | Typed values, one definition per check, a precise schema for editor completion and errors. | serde's internally tagged enum fails the whole file on an unknown id or field, which breaks the skip rule of ADR 0005 and ADR 0007. |
| Open map plus per-check validation | Tolerant. | Typos pass unless every check re-implements validation; the schema says nothing useful. |

**Decision: the contract is a tagged union on `id`; the code decodes it in two steps.**

1. The entry decodes into the common fields plus a raw map of the other keys.
2. The raw map decodes into the parameter struct for that id, unknown fields denied. Success gives
   `CheckParams::HostMemory(..)` and so on. An unknown id gives `CheckParams::Unknown { id, fields }`.
   A field or value the struct rejects gives `CheckParams::Unsupported { id, fields, reason }`.

In the schema file this is `allOf` with one `if id == X then XParams` branch per known id, closed by
`unevaluatedProperties: false`, plus one branch that lets unknown ids carry anything. So a typo in a
known check is an editor error, and a check id from a later family is not.

Version fields take quoted strings or bare integers. The raw map in step 1 holds values the parser has
already resolved, so an unquoted `1.30` is the float 1.3 by then; per ADR 0001 decision 4 it is rejected
with "quote it: min: \"1.30\"", never read as 1.3.

Parameter types are added to `rdy-spec` in the PR that builds the check (ADR 0012). Revision 0 of the
schema has the 17 ids of the catalog's M1 tier. M1-late ids report `unknown_check` until they are built.

### 2.5 Unknown fields and unknown check ids

Principle (ADR 0007 decision 6): **rdy never ignores something it does not understand if ignoring it
could change the verdict or what leaves the machine.**

| Where | `rdy run`, `rdy verify` | `rdy spec lint`, `rdy spec sign` |
| --- | --- | --- |
| Unknown key at the top level, in `metadata` or in `bundle` | Exit 64, `spec_invalid`: "field `x` is not part of rdy/v1 as rdy 0.1.0 knows it. It may need a newer rdy." | Error |
| Unknown id, family not built into this rdy (`gpu.cuda` on M1) | That check is `skipped`, `skip_kind: not_in_build`. The run goes on. | Warning |
| Unknown id, family built in (`host.memroy`) | `skipped`, `skip_kind: unknown_check`, with a did-you-mean. | Warning with did-you-mean |
| Unknown field or unreadable value in a known check (`mn: 32Gi`, `min: 32G`, `severity: critical`) | `skipped`, `skip_kind: unsupported_spec`, `unsupported_fields` names them. An unreadable `severity` counts as `block`. | Warning with did-you-mean (ADR 0008 decision 2) |
| YAML syntax, limits, missing or malformed `id`, duplicate keys or entry keys, wrong `apiVersion` or `kind`, more than 256 checks or 64 endpoints, expired spec | Exit 64, line and column where the parser has them | Error |

Splitting ADR 0005's "needs a newer rdy" into three skip kinds gives three different fix lines (2.5,
5.2). `spec sign` refuses on errors and prints warnings. Open question for cli-ux and security-reviewer:
should `spec sign` refuse unknown fields in a known check too? The signer is the vendor with a current
rdy, so such a field is nearly always a typo.

### 2.6 Scalars, severity and the fix override

| Type | Grammar | Notes |
| --- | --- | --- |
| Quantity (bytes) | integer, or integer plus `Ki`, `Mi`, `Gi`, `Ti`, `Pi` | `32G` and `32GB` rejected with "use 32Gi". Lint warns on a bare integer under 1 MiB ("32 bytes, did you mean 32Gi?"). |
| Duration | integer plus `ms`, `s`, `m`, `h` or `d` | `10s`, `7d`. No compound forms. |
| Version | quoted dotted string, or bare integer | Compared per numeric component, not as semver. |
| Path | absolute (`/...`, `C:\...`), max 1024 | Normalized. Never reaches a shell; there is none. |
| Regex | Rust `regex` syntax, max 256 chars | Linear time, size-limited when compiled. |
| Target | `host:port`, `[v6]:port`, or `http(s)://` URL | At most 64 per spec (ADR 0009). Link-local and metadata addresses parse, and the egress policy refuses them at run time: the check reports `block` with the reason (ADR 0009). |

**Severity.** A check computes a level from its thresholds: pass, warn or fail. `severity` caps it:
`block` (default) maps fail to `block`; `warn` maps fail to `warn`. The result carries the capped
`status` and the spec's `severity`.

**The fix override.** `fix` is plain text from the vendor. It replaces the built-in remediation on `warn`
and `block`, verbatim (02): no templating, so a spec cannot inject values; braces are literal; the HTML
escapes it; newlines are kept; other control characters are stripped before printing. The result keeps
rdy's text as `builtin_fix` and sets `fix_source: spec`; the HTML labels it "From acme-platform" so a
reader knows the vendor wrote it. When a check did not run, the vendor's fix is not shown, because it
would tell the customer to fix something nobody measured; rdy's own fix for the non-run is shown, with
`fix_source: rdy`.

### 2.7 Parameters of the M1 check ids

Two conventions: the main threshold is `min` (or `max`), as in the plan's example and
`examples/specs/acme-platform.yaml`, and a warn threshold is `recommended`. Types, ranges and defaults
are in the schema file; what each threshold means is in 03-check-catalog.md.

| Id | Parameters (required in bold) |
| --- | --- |
| `host.cpu` | `min` cores, `recommended`, `arch` (`x86_64`, `aarch64`, or `amd64`, `arm64`), `flags` |
| `host.memory` | `min`, `min_available`, `swap` (`off`, `any`), `band` (percent), `band_result` (`pass`, `warn`) |
| `host.disk` | **`path`**, `min`, `recommended`, `min_inodes`, `forbid_options` (`noexec`, `nosuid`, `nodev`, `ro`), `forbid_fstypes`. One path per entry; repeat the id with a `name` for more. |
| `host.ports` | `free` (a port or `{port, bind}` with `bind` `public` or `loopback`), `udp_free`, `allow_owner` |
| `host.lsm` | `selinux: {allow, denials_max, denials_window, watch}`, `apparmor: {allow, require_profiles}` |
| `host.security_agents` | `forbid`, `allow` |
| `host.os` | `supported: [{id, versions}]`, `arch`, `fips` (`forbid`, `require`, `any`), `windows_min_build` |
| `net.egress` | **`endpoints`** (a target, or `{target, optional, expect_status, method, via_proxy, tls}`), `via_proxy` (`auto`, `direct`, `proxy_only`; default `auto`), `trust` (`system`, `bundled`), `max_latency` |
| `net.proxy` | `required_no_proxy`, `daemons_need_proxy` |
| `net.tls_intercept` | `hosts` (default: every `net.egress` host in the spec), `expected_issuer`, `pin_sha256`, `forbid_interception` |
| `net.dns` | **`names`** (a name or `{name, expect_in, expect_public}`), `max_latency` |
| `k8s.access` | `context_pattern`, `server_pattern`, `max_latency` |
| `k8s.storageclass` | `class`, `access_modes` (deprecated alias `needs`), `binding`, `expansion`, `reclaim_policy` |
| `k8s.rbac` | **`can`** (1 to 100; `"create namespaces"` or `{verb, group, resource, subresource, namespace, name}`), `namespace` |
| `k8s.admission` | `pod_security` (`privileged`, `baseline`, `restricted`), `uses` (`hostPath`, `hostNetwork`, `hostPID`, `privileged`, `runAsRoot`), `namespace`, `scc` |
| `k8s.nodes` | `min_ready`, `min_zones`, `per_node: {cpu, memory, ephemeral, pods}`, `free: {...}`, `arch`, `selector`, `tolerations` |
| `k8s.version` | `min`, `max`, `max_severity` (default `warn`), `openshift_min`, `apis` |

`k8s.storageclass` accepts `needs` as a deprecated alias of `access_modes` (lint warns; never both),
because the plan's example uses it and must keep parsing. The canonical name is `access_modes`, because
"needs" is the engine's word for privileges in every result, and `custom.exec` will take `needs: [root]`
(ADR 0005). `k8s.admission` has no `dry_run` or `probe_pod` in revision 0: the read-only guard of ADR
0010 and threat model INV-13 reject the dry-run POST in M1. They arrive as an additive revision with the
ADR 0010 amendment.

### 2.8 The bundle block

Used by `rdy bundle` from M2. It must parse in v1 so specs written today keep working.

```yaml
bundle:
  collect: ["journal:7d", "k8s:events", "file:/etc/acme/*.yaml"]   # kind:argument, max 64
  redact: ["aws_keys", "bearer_tokens", "emails"]                  # redactor groups to add, max 64
  redact_patterns: [{name: acme_license, regex: "ACME-[A-Z0-9]{20}"}]   # optional, max 32
  max_size: 200Mi                                                  # optional, lowers the built-in cap
```

Revision 0 fixes the shape: `collect` items match `kind:argument`; `redact` names groups that are
added, and the built-in minimum always runs, so a spec can add redaction and never remove it;
`redact_patterns` and `max_size` are in revision 0 already, at 04-bundle-and-redaction.md's request, so
specs that use them parse on an M1 binary. Known collector kinds: `journal:<duration>`, `k8s:events`,
`file:<absolute glob>`. Known groups: `aws_keys`, `bearer_tokens`, `emails`. 04 owns their meaning, the
path policy, the always-on rules and the bundle manifest format.
Unknown keys in `bundle` exit 64 (ADR 0007). In M1, `rdy run` validates the shape and otherwise ignores
the block. `rdy bundle` (M2) refuses to build when a collector kind or redactor name is unknown: a
missing redactor is a leak.

## 3. Versioning and compatibility

### 3.1 apiVersion handling

- `rdy/v1`: read.
- `rdy/v2` or later: exit 64, `spec_invalid`, "this spec needs a newer rdy that reads rdy/v2", fix
  "install the latest rdy".
- Missing, misspelled or another group (`rdy/v1beta1`, `acme/v1`): exit 64, `spec_invalid`.
- There is no `rdy/v1.1`. Additive revisions do not touch `apiVersion`; the rules in 2.5 make an older
  reader fail loudly or skip a check, never pass by accident.

Results use the same rule: `rdy report` and `rdy-cloud` read `api_version: rdy/v1` from any producer.

### 3.2 Additive changes inside v1

Allowed without a new `apiVersion` (ADR 0007 decision 5), each with a revision line in
`schema/README.md` and regenerated schema files:

- A new check id, or new parameters for an existing id.
- A new optional field anywhere in the spec or result.
- A new value in an open result enum: `status`, `skip_kind`, `error_kind`, `need`, action `kind` and
  `outcome`, `signature.state`, `verdict_reason`, `fix_source`. The schema marks them "Open".
- A new error `code`.
- A new spec enum value (`severity: info`, say). An older rdy skips that check as `unsupported_spec`.
- New keys inside a check's `observed` or `expected`.

| Reader | Newer spec | Newer result |
| --- | --- | --- |
| Older `rdy` | Unknown top-level, `metadata` or `bundle` key: exit 64 with an upgrade hint. Unknown id or check field: that check skips and counts as not run. | n/a |
| Older `rdy-cloud`, `rdy report` | Same rules when validating portal-authored specs. | Ignores unknown fields. An unknown status counts as not run, an unknown severity as block. Uses `verdict` as written, never recomputes it. |

### 3.3 When rdy/v2 is required

Removing or renaming a field or check id (id renames keep the old id as an alias until v2, per the
catalog); narrowing a type so a once-valid value fails; changing a default or a unit or what a value
means; a new required field; a new verdict, a new value in a closed enum (`verdict`, `exit_code`, spec
`kind`) or a change to the verdict rule; changing the signed bytes or the trusted comment format. A v2
needs an ADR. An `rdy` that reads v2 keeps reading v1 specs for at least 12 months (ADR 0007).

### 3.4 Crate version to schema version

| `rdy-spec` | Milestone | Reads specs | Writes results | Reads results | Schema files |
| --- | --- | --- | --- | --- | --- |
| 0.1.x | M1 | rdy/v1 | rdy/v1 | rdy/v1 | `*.v1.schema.json`, revision 0 |
| 0.2 to 0.x | M2, M3 | rdy/v1 | rdy/v1 | every rdy/v1 | same files; a revision line per wire change |
| 1.x | from M3 launch | rdy/v1 | rdy/v1 | every rdy/v1 | 1.0 freezes the current revision as the long-term v1 base |
| 2.x, only if v2 | later | rdy/v1 and rdy/v2 | rdy/v2 | every v1 and v2 | adds `*.v2.schema.json`; v1 files stay |

Rust rules that keep "additive" true for `cargo-semver-checks` too: every public wire struct is
`#[non_exhaustive]` with public fields and a `new(..)` taking only required fields, so `rdy-engine`
builds values through constructors and a new optional field is a compatible change. Every public wire
enum is `#[non_exhaustive]`; open result enums have a `#[serde(other)] Unknown` variant. Result types
never use `deny_unknown_fields`. Golden results from every released version live in
`tests/fixtures/results/` and parse in CI forever (ADR 0007).

## 4. Signing

### 4.1 Format and the bytes signed

ADR 0002: a detached minisign signature in `<spec file>.minisig`, or the file named by `--sig`.

- Algorithm: minisign prehashed (`ED`: ed25519 over BLAKE2b-512 of the file). Legacy `Ed` is rejected
  (`allow_legacy = false`). One algorithm, no choice for an attacker.
- Signed bytes: the spec file exactly as read. No YAML canonicalization, no BOM stripping, no line
  ending conversion. A file that went through CRLF conversion fails; the hint says so when the file
  contains CRLF, and the vendor docs say to ship specs with `*.yaml -text` in `.gitattributes`.
- The global signature covers the signature plus the trusted comment, so the comment is signed.
- Size caps: sidecar 4 KiB, `trust.yaml` 256 KiB (threat model INV-02).

### 4.2 The trusted comment

```text
rdy-spec-v1 product=<metadata.product> signed_at=<RFC 3339 UTC, whole seconds>
```

Exactly this form; anything else is refused (ADR 0002 decision 1). The `rdy-spec-v1` prefix is the
domain separation: a signature the same key made for something else carries a different comment. The
untrusted comment line is never read.

### 4.3 The trust store

| Running as | Reads | `rdy trust add` writes |
| --- | --- | --- |
| euid 0, or elevated on Windows | only `/etc/rdy/trust.yaml` (`%ProgramData%\rdy\trust.yaml`), whatever `HOME` or `XDG_CONFIG_HOME` say | the system file |
| a normal user | `$XDG_CONFIG_HOME/rdy/trust.yaml` (default `~/.config/rdy/trust.yaml`; `%APPDATA%\rdy\trust.yaml`), then the system file (threat model Surface 2, requirement 3) | the user file |

The system file is refused, with the reason, when it is a symlink, not owned by root, group or world
writable, or in a directory writable by anyone but root (ADR 0002 decision 4). A user file writable by
group or others is refused too. Both exit 64 with `trust_store_insecure`. When root finds no key but the
invoking user's file has one, the hint says: "as root, rdy reads only /etc/rdy/trust.yaml. Run: sudo rdy
trust add acme-platform --key <file>".

```yaml
apiVersion: rdy/v1
kind: TrustStore
keys:
  - product: acme-platform
    key: RWQFbHsh1NTnBwUEXAMPLEONLYnotarealpublickeyAAAAAAAAAAAAA
    added_at: 2026-11-30T16:20:00Z
    note: "Acme security page, fingerprint read back by phone"
```

Unknown keys in this file are an error; it is rdy's own file. The key id is derived from `key`, never
stored. A key is trusted only for the products listed with it. Pinning happens only in `rdy trust add`,
which shows the key id and fingerprint and asks (`--yes` to skip). `rdy run --key <file>` trusts a key
for one run and writes nothing; the result says `trust_source: flag`.

### 4.4 Verification order

The parser only sees bytes a trusted key signed, unless the user chose `--allow-unsigned` (ADR 0002
decision 3):

1. Read the spec (1 MiB cap) and the sidecar (4 KiB cap).
2. Parse the sidecar; reject legacy `Ed` and any trusted comment not in the 4.2 form.
3. Look up keys pinned for the comment's `product` with the signature's key id (`--key` first).
4. Verify the raw bytes, then the global signature over the comment.
5. Only now parse the YAML (ADR 0001) and validate (2.5).
6. Check `metadata.product` equals the comment's `product`.
7. Check `expires`.

### 4.5 rdy spec sign and keygen

`rdy spec keygen` writes the secret key with `create_new`, mode 0600, password-encrypted unless
`--unencrypted` (for vendor CI, ADR 0002 decision 8), plus the public key file.

`rdy spec sign <spec> [--secret-key <file>] [--sig <out>] [--force]` (flags final in 07-cli-ux.md):

1. Runs `rdy spec lint`. Any error refuses to sign; warnings are printed.
2. Refuses a secret key readable by group or others. Asks for its password if encrypted.
3. Signs the exact file bytes with the 4.2 trusted comment, `signed_at` = now.
4. Writes `<spec>.minisig` with exclusive create; `--force` replaces it.
5. Verifies its own output, then prints the key id, the spec SHA-256 and the line the vendor sends to
   customers: `rdy trust add acme-platform --key acme-platform.pub`.

Stock minisign interoperates: `minisign -V` verifies an rdy signature, and a spec signed with
`minisign -S -t "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z"` verifies in rdy.

### 4.6 rdy verify

`rdy verify <spec> [--sig <file>] [--key <file>] [--json]` runs 4.4 and no checks. It never prompts and
does not take `--allow-unsigned`. Exit 0 means "`rdy run` would accept this file with no override".
Otherwise exit 64 with a code from 4.8. It prints product, key id, trust note and source, `signed_at`,
serial, expiry and SHA-256. With `--json`: a `Verification` object, or an `ErrorOutput` on failure
(both in the result schema `$defs`).

### 4.7 --allow-unsigned

It allows exactly one thing: a spec with **no** signature. Any signature that is present but does not
verify against a key pinned for the product, or given with `--key`, exits 64 even with the flag (ADR
0002 decision 7). That includes a valid signature by an unpinned key: the fix is `rdy trust add` or a
one-run `--key`, and no hint ever suggests the flag. An unsigned spec containing `custom.exec` exits 64
from M3 (ADR 0005). Expired specs are refused regardless.

The flag is read from argv only (threat model INV-05). Exact text, on stderr, red when colour is on,
before any check runs:

```text
WARNING: UNSIGNED SPEC
acme-platform.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
Run it only if you wrote it yourself or got it straight from the vendor.
Every report from this run is marked UNSIGNED SPEC.
```

`WARNING: UNSIGNED SPEC` is printed again directly above the verdict line. The result has
`signature.state: unsigned` and `run.options.allow_unsigned: true`; the HTML shows the banner (section
6). M2 adds a TTY confirmation after the banner, `Run it anyway? [y/N]`, default no (threat model T2);
the text above does not change.

### 4.8 Error codes for spec loading

All exit 64. With `--json`, each is an `ErrorOutput` on stdout (ADR 0008 decision 7).

| Code | When | First line | Fix line |
| --- | --- | --- | --- |
| `spec_unsigned` | no sidecar, no flag | `error: no signature found at acme-platform.yaml.minisig` | `fix: ask the vendor for the .minisig file, or run with --allow-unsigned` |
| `spec_key_unknown` | no key pinned for this product with this key id | `error: acme-platform.yaml is signed with key 9F3A6C21D4E87B05, which you have not trusted for acme-platform` | `fix: get the vendor's public key from their docs, check its fingerprint, then run rdy trust add acme-platform --key <file>` |
| `spec_signature_invalid` | bytes or comment do not verify, legacy `Ed`, malformed sidecar or comment, or product mismatch; the first line names which | `error: the signature on acme-platform.yaml does not match the file. It may have been changed after signing.` | `fix: get a fresh copy and its .minisig from the vendor. Do not run this file.` |
| `spec_expired` | `metadata.expires` has passed | `error: acme-platform.yaml expired on 2027-01-31` | `fix: ask the vendor for a current spec` |
| `spec_parse`, `spec_invalid` | 2.5 | the parser message with line and column | the `SpecError` hint |
| `trust_store_insecure` | 4.3 | `error: /etc/rdy/trust.yaml is writable by other users` | `fix: chmod 644 /etc/rdy/trust.yaml` |

`spec_expired` and `trust_store_insecure` are new codes, added to ADR 0008's list under ADR 0007's
additive rule.

## 5. The JSON result

Top level (`$defs/Report`). ADR 0012 decision 3 fixes the provenance fields; this doc names the rest.

| Field | Meaning |
| --- | --- |
| `api_version`, `kind` | `rdy/v1`, `Report` |
| `producer` | `name` (`rdy`), `version`, `commit`, `rdy_spec` (crate version), `target` (triple) |
| `run` | `id` (UUID v4), `started_at`, `finished_at`, `duration_ms`, `options` (`jobs`, `deadline_ms`, `allow_unsigned`, `network`, `kube_context`) |
| `spec` | `product`, `version`, `sha256` of the verified bytes, `file_name` (base name only), `size_bytes`, `serial`, `expires`, `contact`, `annotations` |
| `signature` | `state` (`verified`, `unsigned`), `key_id`, `product` and `signed_at` from the signed comment, `trust_note`, `trust_source` (`system`, `user`, `flag`) |
| `host` | 5.1 |
| `identity` | `euid`, `user`, `elevated`, `kube` (`context`, `server`, `user`) |
| `proxy` | proxy URLs in effect, user info stripped, and `no_proxy`; null when none |
| `capabilities` | each probed need: `need`, `name`, `available`, `detail`, `hint` (02) |
| `verdict`, `verdict_reason`, `exit_code` | 5.3 |
| `summary` | `total`, `pass`, `warn`, `block`, `skipped`, `timeout`, `error`, `not_applicable`, `required_not_run`, `optional_not_run` |
| `checks` | one result per spec entry, in spec order (5.2) |
| `actions`, `actions_truncated` | the action log (5.4) |
| `redaction` | `ruleset` (`report`), `total`, `by_rule`: counts only, never matched text (04) |
| `complete`, `interrupted` | `complete: false` when rdy could not finish or write the report (exit 70); `interrupted: true` after Ctrl-C |

`signature.trust_note` is the local note from the trust store, never text from the spec, so the report
never shows a vendor name the spec chose for itself (threat model Surface 2, S1). `invalid` exists in the
Rust `SignatureState` for `rdy verify` but never appears in a written report.

### 5.1 Host identity

Included: `hostname` (after redaction), `host_id`, `os` (`family`, `id`, `version`, `pretty_name`),
`kernel`, `arch`, `virtualization` (`none`, `vm`, `unknown`), `container` (rdy ran in a container or
WSL). `identity` adds `euid`, the local login name and the kube identity (ADR 0012), so the reader knows
who ran it and against which cluster.

`host_id` is the first 16 hex digits of SHA-256 over `rdy-host-id-v1`, NUL, the product, NUL and the OS
machine id (`/etc/machine-id`, macOS `kern.uuid`, Windows `MachineGuid`). The portal uses it to match a
rerun to the same box. Salting by product means two vendors cannot link one host. `null` when the OS
has no machine id.

Deliberately excluded, outside a check's own `observed` data: IP and MAC addresses, environment values
(except the proxy settings, user info stripped), the command line (it can hold tokens), the working
directory, home paths (action log paths under the home directory are written with `~`), kubeconfig
contents and credentials, the raw machine id, hardware serial numbers. Checks may record what they
measure, and the redactor runs over every string before write (threat model I1). The hostname stays
because SEs must tell boxes apart; an option to replace it is an M2 ticket.

### 5.2 Check results

Each entry: `key`, `id`, `name`, `family`, `severity`, `status`, `message` (one line, 1 KiB cap), `fix`
(4 KiB cap), `fix_source` (`spec`, `rdy`), `builtin_fix`, `observed`, `expected` (64 KiB cap each),
`needs`, `partial`, `truncated`, `notes`, `started_ms` (offset from `run.started_at`), `duration_ms`.
Status-specific: `skip_kind` and `unsupported_fields` for `skipped`, `timeout_after_ms` for `timeout`,
`error_kind` (`check_failed`, `panic`) for `error`. `fix` is null only for `pass` and `not_applicable`;
every other outcome carries one (ADR 0008 decision 5).

`observed` holds measured values, `expected` the thresholds after defaults. Keys are snake_case per
check id with units in the name (`total_bytes`, `connect_ms`), documented per check on the docs site,
additive only. `needs` lists each declared need as `{need, name, hard, met}`: `hard: true` means the
check does not run without it, `false` means it runs `partial`. `partial` is `null` or
`{missing: [needs], note}`; a partial check never blocks on data it could not read (02, needs rule 4).
Known needs: `root`, `kube_context`, `network`, `command` (with `name`), `cloud_credentials` (with the
provider as `name`, M3).

One vocabulary everywhere (ADR 0008 decision 1):

| JSON `status` | Terminal and HTML |
| --- | --- |
| `pass` | `PASS` |
| `warn` | `WARN` |
| `block` | `BLOCK` |
| `skipped` | `SKIP` |
| `timeout` | `TIMEOUT` |
| `error` | `ERROR` |

| JSON `verdict` | Display | Exit |
| --- | --- | --- |
| `ready` | `READY` | 0 |
| `ready_with_warnings` | `READY with warnings` | 1 |
| `not_ready` | `NOT READY` | 2 |

Skip kinds. 02's `NeedsNewerRdy` is split three ways here because the fix differs:

| `skip_kind` | When | Counts as not run | rdy's fix text |
| --- | --- | --- | --- |
| `missing_need` | a hard need is not met: not root, no reachable cluster | yes | from the need: "Rerun as root to check the listening ports." |
| `not_in_build` | the id's family is reserved but not built into this rdy | yes | "Install a newer rdy, or ask the vendor to mark this check as warn." |
| `unknown_check` | the family is built in, the id is not known | yes | "rdy 0.1.0 does not know host.memroy. Did you mean host.memory? Otherwise install a newer rdy." |
| `unsupported_spec` | known id, a field or value this rdy cannot read | yes | "Field mn is not known for host.memory. It is a typo, or it needs a newer rdy." |
| `not_yet_on_os` | the check has no data source on this OS yet | yes | "This check has no data source on macOS yet. Run rdy on the target host." |
| `not_applicable` | the concept does not exist here (SELinux on Windows), or the spec's `os` list leaves this OS out | **no** | none |
| `run_deadline` | the 5 minute run deadline passed before it started | yes | "The run hit its 5 minute limit. Rerun, or ask the vendor to shorten slow checks." |
| `cancelled` | the run was interrupted | yes | "The run was interrupted. Run it again." |

This answers cli-ux's open point on unsupported OSes (10-devrel review, detail 1) the way 02 does: a
check whose concept does not exist on an OS is `not_applicable`, not a pass with a note, because rdy
measured nothing. A check that merely lacks a data source yet is `not_yet_on_os` and counts.

### 5.3 The verdict rule

```text
not_run(c)  = c.status in {skipped, timeout, error, <unknown>} and c.skip_kind != not_applicable
required(c) = c.severity != warn          # unreadable or unknown severity counts as block

not_ready            if any c.status == block, or any c is required and not_run
ready_with_warnings  else if any c.status == warn, or any c is not required and not_run,
                     or no check reached pass, warn or block (nothing was verified)
ready                otherwise
```

**Confirmed: a `severity: block` check that did not run makes the verdict NOT READY, exit 2, and is
counted apart as "required check not run"**, as cli-ux proposed and ADR 0008 decision 3 now says. The
reasons: a false READY is the worst failure this tool can have and a false NOT READY costs one rerun;
exit 1 means "warnings only" and a `[ $? -le 1 ]` gate would pass an unchecked environment; and only
the vendor, who wrote `severity: block`, may relax the requirement. Amendments, each already in 02 or
needed by this doc:

1. Timeout and Error count as not run (02, cli-ux detail 3). Otherwise a firewall that drops packets
   until the engine timeout would score better than one that refuses them.
2. `not_applicable` never counts (02). That is how a cross-platform spec reaches READY on each platform.
3. A run that verified nothing is at least READY with warnings (02), `verdict_reason: nothing_verified`.
4. An unreadable or unknown `severity` counts as block, and an unknown status counts as not run (this
   doc), so neither a typo nor a newer producer can turn into a READY.

02 lists a ticket to record these refinements in ADR 0013; this doc does not take that number.

`verdict_reason` is `required_check_not_run` when the verdict is `not_ready` with no observed block,
`nothing_verified` as above, otherwise null. The summary line counts the buckets apart (format in
07-cli-ux.md): `2 blocks, 1 warning, 3 passed, 2 required checks not run`. `exit_code` is the verdict's
code. If rdy cannot write the report it exits 70; the JSON it still prints has `complete: false`.

### 5.4 The action log

Threat model R1 and INV-06: every side effect goes through the probe facade, which appends one entry
(02). JSON shape: the common fields `seq`, `check` (key, or null for run-level probes), `at_ms`,
`duration_ms`, `kind`, `outcome` (`ok`, `denied` with `rule` when rdy's policy refused, `failed` with
`error` when the OS or peer refused, `timeout`), then the fields of that kind, flattened:

| `kind` | Fields |
| --- | --- |
| `exec` | `program`, `argv`, `exit`, `stdout_bytes`, `truncated` |
| `read`, `read_dir`, `stat` | `path`, and `bytes`, `truncated` or `entries` |
| `env` | `name` (never the value) |
| `lookup`, `dns` | `host`, `answers`; or `server`, `name`, `rtype` |
| `connect`, `tls` | `host`, `port`, `addr`, `via_proxy`; or `host`, `sni` |
| `http`, `kube` | `method`, `url` (no query string) or `path`, `status` |
| `native` | `api`, `path` |
| `coalesced` | `of` (the kind), `under`, `count` (reads past 200 per check, per directory) |

Every string passes the redactor. Bodies are never recorded. The log is capped at 5000 entries
(`actions_truncated`). `rdy run --plan` (M2) prints the same shape before running.

### 5.5 Writer rules

- UTF-8, no BOM, LF, two-space indent, fields in schema order, trailing newline. Deterministic for a
  given `Report`, so golden files are exact.
- `<`, `>` and `&` are written as the JSON escapes `\u003c`, `\u003e`, `\u0026` (ADR 0003 decision 4),
  in the `.json` file too. So the file, `--json` on stdout and the copy embedded in the HTML are the same
  bytes, and the portal can compare an HTML upload with a JSON upload by hash.
- Size: target under 1 MiB, hard cap 2 MiB. Over the cap the action log is truncated first, then lists
  inside `observed` are cut to 200 items with `truncated: true`.
- Location (ADR 0003): a new directory `rdy-report-<product>-<YYYYMMDDTHHMMSSZ>/` holding
  `rdy-report-<product>-<ts>.json`, `.html`, and a copy of the verified spec and its `.minisig` (02).

## 6. The HTML report contract

The report is the demo, and security reviewers read its renderer (CLAUDE.md rule 7). ADR 0003 sets the
technology; this is what the file must contain and guarantee.

**Data.** Rendered only from the `Report` value that produced the JSON, plus the static template. The
renderer reads no files, environment or clock. `rdy report <result.json>` (M2) re-renders a result file
to the same bytes, after running the redactor on input it did not produce (02).

**One self-contained file.** Inline CSS, no JavaScript in M1, system fonts, one inline SVG logo, nothing
that loads on open. CSP meta `default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri
'none'; form-action 'none'` (ADR 0003). No `<details>` elements: a closed one does not print, and print
must show everything.

**Embedded JSON.** `<script type="application/json" id="rdy-result" data-sha256="<hex>">` holds the
exact bytes of the `.json` file. The portal imports an HTML file by extracting this element, treats it
as untrusted input, validates it against `result.v1.schema.json`, labels it customer-reported, and can
compare `data-sha256` with a JSON upload. The JSON file stays the supported upload; HTML import is the
convenience for air-gapped sites that send one file.

**Content, in this order** (ADR 0003 decision 6, 02 renderers):

1. Header: product, spec `version`, the verdict word, the summary counts line, run time in UTC,
   hostname.
2. The `UNSIGNED SPEC` banner when `signature.state` is not `verified`.
3. "This file lists hostnames and addresses from this machine. Read it before you send it."
4. Blockers. 5. Required checks not run, each with the missing need and its hint. 6. Warnings,
   including warn checks not run. 7. Passed. 8. Not applicable.
   Each check shows its status word, key, message, fix with its source ("From acme-platform" or "From
   rdy"), observed against expected, needs and whether they were met, partial note, and duration.
9. Capabilities: each probed need, available or not, and the hint.
10. Run and spec details: rdy version and target, run id, options, spec file name, SHA-256, signature
    state, key id, trust note, `signed_at`, serial, expiry, contact; identity and proxy.
11. Action log as a plain table, first 1000 rows, then "N more entries are in the embedded JSON".
12. Footer: a plain link to `https://getrdy.io/?ref=report&product=<product>` with
    `rel="noopener noreferrer"`, the rdy version and the source repository. Nothing loads unless clicked.

**Text safety.** Every string from the spec or host is HTML-escaped by askama, control characters
stripped. No string from data becomes a link; `contact` and URLs show as text.

**Size.** Hard cap 5 MiB; typical under 300 KiB.

**Print and dark mode.** `@media print`: no backgrounds, everything visible, a page break before each
section, and the unsigned banner repeated on every page. `prefers-color-scheme` for dark mode, with
`<meta name="color-scheme" content="light dark">` so it applies before first paint.

**Accessibility.** `<html lang="en">`, headings in order, every status as a word (colour is never the
only signal), WCAG AA contrast in both themes, table headers with `scope`.

## 7. Examples

### 7.1 Spec, signature and trust entry

The spec is `examples/specs/acme-platform.yaml` exactly as of 2026-10-28 (SHA-256
`a56b97c8c43d7de6a0f9cd1b5cd21a7e6d38a76ed7c602f85a0950c6ad97e07c`, 1981 bytes). `gpu.cuda` and `aws.iam` are not in an M1 build, so this spec cannot reach
READY until the cloud family (M3) and the gpu family (M4) ship. Its header says so.

```yaml
# Synthetic example. "Acme Platform" is a made-up product. Every hostname
# ends in .example (RFC 2606), so nothing here points at a real service.
#
# This is the canonical example spec. The docs, the README and the CI
# integration tests all use it. Checks marked (later) parse today but
# only run once their check family ships. Until then rdy reports them as
# skipped, never as passed.
#
# Required checks that cannot run make the verdict NOT READY. This file will
# not reach READY until the cloud family (M3) and the gpu family (M4) ship.
# For a spec that can reach READY today, see acme-quickstart.yaml.
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme-platform
  version: ">=4.2"
checks:
  - id: host.cpu
    min: 8
    severity: block
    fix: "Use a node with at least 8 vCPUs."
  - id: host.memory
    min: 32Gi
    severity: block
    fix: "Add RAM or choose a larger node class."
  - id: host.disk
    path: /var/lib
    min: 100Gi
    severity: warn
    fix: "Mount a larger volume at /var/lib before install."
  - id: net.egress
    endpoints: ["registry.acme.example:443", "license.acme.example:443"]
    via_proxy: auto
    severity: block
    fix: "Ask your network team to allow these endpoints through the proxy."
  - id: k8s.version
    min: "1.28"
    severity: block
    fix: "Upgrade the cluster to Kubernetes 1.28 or newer."
  - id: k8s.storageclass
    needs: ["ReadWriteOnce"]
    severity: warn
    fix: "Mark a storage class that supports ReadWriteOnce as the default."
  # (later) gpu family, M4
  - id: gpu.cuda
    min: "12.4"
    severity: block
    fix: "Install CUDA 12.4 or newer on every GPU node."
  # (later) cloud family, M3
  - id: aws.iam
    simulate: ["eks:DescribeCluster", "ec2:CreateSecurityGroup"]
    severity: block
    fix: "Add the missing actions to the install role. The report lists them."
bundle:
  collect: ["journal:7d", "k8s:events", "file:/etc/acme/*.yaml"]
  redact: ["aws_keys", "bearer_tokens", "emails"]
```

Its sidecar `acme-platform.yaml.minisig`, with fake base64:

```text
untrusted comment: rdy spec signature for acme-platform, key 9F3A6C21D4E87B05
RUQFbHsh1NTnBwUEXAMPLEONLYnotarealsignatureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
trusted comment: rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z
EXAMPLEONLYnotarealglobalsignatureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
```

The customer pinned the key with `sudo rdy trust add acme-platform --key acme-platform.pub`, which wrote
the entry in 4.3 to `/etc/rdy/trust.yaml`. The NOT READY run is not root, so it read the user file, then
the system file, and found the key there. The READY run is root and read only the system file. Both say
`trust_source: system`.

### 7.2 NOT READY run (rdy 0.1.0, M1)

A RHEL 9 VM with 16 GB of RAM behind a proxy that does not allow the license host, run as a normal user
with a kubeconfig. Two blocks, one warning, two required checks not run, exit 2. Summary line:
`2 blocks, 1 warning, 3 passed, 2 required checks not run`. `verdict_reason` is null because blocks
were observed.

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
    "started_at": "2026-12-01T14:30:05Z",
    "finished_at": "2026-12-01T14:30:05.318Z",
    "duration_ms": 318,
    "options": {
      "jobs": 8,
      "deadline_ms": 300000,
      "allow_unsigned": false,
      "network": true,
      "kube_context": null
    }
  },
  "spec": {
    "product": "acme-platform",
    "version": ">=4.2",
    "sha256": "a56b97c8c43d7de6a0f9cd1b5cd21a7e6d38a76ed7c602f85a0950c6ad97e07c",
    "file_name": "acme-platform.yaml",
    "size_bytes": 1981,
    "serial": null,
    "expires": null,
    "contact": null,
    "annotations": {}
  },
  "signature": {
    "state": "verified",
    "key_id": "9F3A6C21D4E87B05",
    "product": "acme-platform",
    "signed_at": "2026-11-30T16:02:11Z",
    "trust_note": "Acme security page, fingerprint read back by phone",
    "trust_source": "system",
    "reason": null
  },
  "host": {
    "hostname": "acme-node-01.corp.example",
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
  "identity": {
    "euid": 1000,
    "user": "jdoe",
    "elevated": false,
    "kube": {
      "context": "acme-staging",
      "server": "https://api.k8s.acme.example:6443",
      "user": "acme-installer"
    }
  },
  "proxy": {
    "https": "http://proxy.corp.example:3128",
    "http": "http://proxy.corp.example:3128",
    "no_proxy": [".corp.example", "10.0.0.0/8"]
  },
  "capabilities": [
    {"need": "kube_context", "name": null, "available": true, "detail": "context acme-staging at https://api.k8s.acme.example:6443 as acme-installer", "hint": null},
    {"need": "network", "name": null, "available": true, "detail": null, "hint": null}
  ],
  "verdict": "not_ready",
  "verdict_reason": null,
  "exit_code": 2,
  "summary": {
    "total": 8,
    "pass": 3,
    "warn": 1,
    "block": 2,
    "skipped": 2,
    "timeout": 0,
    "error": 0,
    "not_applicable": 0,
    "required_not_run": 2,
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
      "message": "8 vCPUs found, 8 needed",
      "fix": null,
      "fix_source": null,
      "observed": {"logical_cores": 8, "physical_cores": 4, "arch": "x86_64", "hypervisor": true},
      "expected": {"min": 8},
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 2,
      "truncated": false
    },
    {
      "key": "host.memory",
      "id": "host.memory",
      "name": null,
      "family": "host",
      "severity": "block",
      "status": "block",
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
      "expected": {"min_bytes": 34359738368, "band_bytes": 1717986918},
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 1,
      "truncated": false
    },
    {
      "key": "host.disk",
      "id": "host.disk",
      "name": null,
      "family": "host",
      "severity": "warn",
      "status": "warn",
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
      "notes": [],
      "started_ms": 42,
      "duration_ms": 3,
      "truncated": false
    },
    {
      "key": "net.egress",
      "id": "net.egress",
      "name": null,
      "family": "net",
      "severity": "block",
      "status": "block",
      "message": "1 of 2 endpoints unreachable: license.acme.example:443 (proxy refused CONNECT, 403)",
      "fix": "Ask your network team to allow these endpoints through the proxy.",
      "fix_source": "spec",
      "builtin_fix": "The proxy refused CONNECT to license.acme.example:443. Ask the proxy team to add it to the allow list.",
      "observed": {
        "via": "proxy",
        "proxy": "http://proxy.corp.example:3128",
        "endpoints": [
          {"target": "registry.acme.example:443", "outcome": "ok", "connect_ms": 38, "tls_ms": 61},
          {"target": "license.acme.example:443", "outcome": "proxy_403", "connect_ms": 37, "tls_ms": null}
        ]
      },
      "expected": {
        "via_proxy": "auto",
        "reachable": ["registry.acme.example:443", "license.acme.example:443"]
      },
      "needs": [{"need": "network", "name": null, "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 42,
      "duration_ms": 212,
      "truncated": false
    },
    {
      "key": "k8s.version",
      "id": "k8s.version",
      "name": null,
      "family": "k8s",
      "severity": "block",
      "status": "pass",
      "message": "Server v1.29.4, 1.28 or newer needed",
      "fix": null,
      "fix_source": null,
      "observed": {"git_version": "v1.29.4", "distribution": "vanilla"},
      "expected": {"min": "1.28"},
      "needs": [{"need": "kube_context", "name": null, "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 43,
      "duration_ms": 48,
      "truncated": false
    },
    {
      "key": "k8s.storageclass",
      "id": "k8s.storageclass",
      "name": null,
      "family": "k8s",
      "severity": "warn",
      "status": "pass",
      "message": "Default class gp3 (ebs.csi.aws.com) supports ReadWriteOnce",
      "fix": null,
      "fix_source": null,
      "observed": {
        "default_class": "gp3",
        "provisioner": "ebs.csi.aws.com",
        "csi_driver_present": true,
        "access_modes": ["ReadWriteOnce"],
        "binding": "WaitForFirstConsumer"
      },
      "expected": {"access_modes": ["ReadWriteOnce"]},
      "needs": [{"need": "kube_context", "name": null, "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 43,
      "duration_ms": 95,
      "truncated": false
    },
    {
      "key": "gpu.cuda",
      "id": "gpu.cuda",
      "name": null,
      "family": "gpu",
      "severity": "block",
      "status": "skipped",
      "skip_kind": "not_in_build",
      "message": "Not run. This rdy build has no gpu checks.",
      "fix": "Install a newer rdy, or ask the vendor to mark this check as warn.",
      "fix_source": "rdy",
      "observed": null,
      "expected": null,
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0,
      "truncated": false
    },
    {
      "key": "aws.iam",
      "id": "aws.iam",
      "name": null,
      "family": "aws",
      "severity": "block",
      "status": "skipped",
      "skip_kind": "not_in_build",
      "message": "Not run. This rdy build has no aws checks.",
      "fix": "Install a newer rdy, or ask the vendor to mark this check as warn.",
      "fix_source": "rdy",
      "observed": null,
      "expected": null,
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 41,
      "duration_ms": 0,
      "truncated": false
    }
  ],
  "actions": [
    {"seq": 1, "check": null, "at_ms": 2, "duration_ms": 1, "kind": "read", "outcome": "ok", "path": "~/.kube/config", "bytes": 5412, "truncated": false},
    {"seq": 2, "check": null, "at_ms": 3, "duration_ms": 31, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/version", "status": 200},
    {"seq": 3, "check": null, "at_ms": 35, "duration_ms": 5, "kind": "kube", "outcome": "ok", "method": "POST", "path": "/apis/authentication.k8s.io/v1/selfsubjectreviews", "status": 201},
    {"seq": 4, "check": "host.cpu", "at_ms": 41, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/cpuinfo", "bytes": 8320, "truncated": false},
    {"seq": 5, "check": "host.cpu", "at_ms": 41, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/cpu.max", "bytes": 13, "truncated": false},
    {"seq": 6, "check": "host.memory", "at_ms": 41, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/meminfo", "bytes": 1482, "truncated": false},
    {"seq": 7, "check": "host.memory", "at_ms": 42, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/memory.max", "bytes": 4, "truncated": false},
    {"seq": 8, "check": "host.disk", "at_ms": 42, "duration_ms": 1, "kind": "read", "outcome": "ok", "path": "/proc/self/mountinfo", "bytes": 2870, "truncated": false},
    {"seq": 9, "check": "net.egress", "at_ms": 42, "duration_ms": 2, "kind": "lookup", "outcome": "ok", "host": "proxy.corp.example", "answers": 1},
    {"seq": 10, "check": "host.disk", "at_ms": 43, "duration_ms": 0, "kind": "native", "outcome": "ok", "api": "statvfs", "path": "/var/lib"},
    {"seq": 11, "check": "k8s.version", "at_ms": 43, "duration_ms": 48, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/version", "status": 200},
    {"seq": 12, "check": "k8s.storageclass", "at_ms": 44, "duration_ms": 52, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/storageclasses", "status": 200},
    {"seq": 13, "check": "net.egress", "at_ms": 45, "duration_ms": 36, "kind": "connect", "outcome": "ok", "host": "registry.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128"},
    {"seq": 14, "check": "net.egress", "at_ms": 82, "duration_ms": 61, "kind": "tls", "outcome": "ok", "host": "registry.acme.example", "sni": "registry.acme.example"},
    {"seq": 15, "check": "k8s.storageclass", "at_ms": 96, "duration_ms": 43, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/csidrivers", "status": 200},
    {"seq": 16, "check": "net.egress", "at_ms": 144, "duration_ms": 37, "kind": "connect", "outcome": "failed", "host": "license.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128", "error": "proxy answered 403 to CONNECT"}
  ],
  "actions_truncated": false,
  "redaction": {"ruleset": "report", "total": 0, "by_rule": {}},
  "complete": true,
  "interrupted": false
}
```

### 7.3 READY run (same spec, rdy 0.4.0, after M4)

The same signed spec on a GPU node with 64 GB of RAM, the proxy fixed, AWS credentials from the instance
role, run as root. Every family is built and every check passes, exit 0. `producer.version` 0.4.0 with
`rdy_spec` 0.3.0 shows the crates moving independently while the wire format stays `rdy/v1`.

```json
{
  "api_version": "rdy/v1",
  "kind": "Report",
  "producer": {
    "name": "rdy",
    "version": "0.4.0",
    "commit": "b72d0f1",
    "rdy_spec": "0.3.0",
    "target": "x86_64-unknown-linux-musl"
  },
  "run": {
    "id": "0c7e5a39-8d24-4f1b-b6e2-9a4f3d7c1e08",
    "started_at": "2027-04-12T09:15:40Z",
    "finished_at": "2027-04-12T09:15:41.034Z",
    "duration_ms": 1034,
    "options": {
      "jobs": 8,
      "deadline_ms": 300000,
      "allow_unsigned": false,
      "network": true,
      "kube_context": null
    }
  },
  "spec": {
    "product": "acme-platform",
    "version": ">=4.2",
    "sha256": "a56b97c8c43d7de6a0f9cd1b5cd21a7e6d38a76ed7c602f85a0950c6ad97e07c",
    "file_name": "acme-platform.yaml",
    "size_bytes": 1981,
    "serial": null,
    "expires": null,
    "contact": null,
    "annotations": {}
  },
  "signature": {
    "state": "verified",
    "key_id": "9F3A6C21D4E87B05",
    "product": "acme-platform",
    "signed_at": "2026-11-30T16:02:11Z",
    "trust_note": "Acme security page, fingerprint read back by phone",
    "trust_source": "system",
    "reason": null
  },
  "host": {
    "hostname": "acme-gpu-01.corp.example",
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
  "identity": {
    "euid": 0,
    "user": "root",
    "elevated": true,
    "kube": {
      "context": "acme-staging",
      "server": "https://api.k8s.acme.example:6443",
      "user": "acme-installer"
    }
  },
  "proxy": {
    "https": "http://proxy.corp.example:3128",
    "http": "http://proxy.corp.example:3128",
    "no_proxy": [".corp.example", "10.0.0.0/8"]
  },
  "capabilities": [
    {"need": "root", "name": null, "available": true, "detail": "uid 0", "hint": null},
    {"need": "kube_context", "name": null, "available": true, "detail": "context acme-staging at https://api.k8s.acme.example:6443 as acme-installer", "hint": null},
    {"need": "network", "name": null, "available": true, "detail": null, "hint": null},
    {"need": "command", "name": "nvidia-smi", "available": true, "detail": "/usr/bin/nvidia-smi", "hint": null},
    {"need": "cloud_credentials", "name": "aws", "available": true, "detail": "arn:aws:sts::111122223333:assumed-role/acme-installer/i-0abc", "hint": null}
  ],
  "verdict": "ready",
  "verdict_reason": null,
  "exit_code": 0,
  "summary": {
    "total": 8,
    "pass": 8,
    "warn": 0,
    "block": 0,
    "skipped": 0,
    "timeout": 0,
    "error": 0,
    "not_applicable": 0,
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
      "message": "16 vCPUs found, 8 needed",
      "fix": null,
      "fix_source": null,
      "observed": {"logical_cores": 16, "physical_cores": 8, "arch": "x86_64", "hypervisor": true},
      "expected": {"min": 8},
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 52,
      "duration_ms": 2,
      "truncated": false
    },
    {
      "key": "host.memory",
      "id": "host.memory",
      "name": null,
      "family": "host",
      "severity": "block",
      "status": "pass",
      "message": "62.8 GiB found, 32 GiB needed",
      "fix": null,
      "fix_source": null,
      "observed": {
        "total_bytes": 67430977536,
        "available_bytes": 60129542144,
        "swap_total_bytes": 0,
        "cgroup_limit_bytes": null
      },
      "expected": {"min_bytes": 34359738368, "band_bytes": 1717986918},
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 52,
      "duration_ms": 1,
      "truncated": false
    },
    {
      "key": "host.disk",
      "id": "host.disk",
      "name": null,
      "family": "host",
      "severity": "warn",
      "status": "pass",
      "message": "180.0 GiB free for /var/lib (its own mount), 100 GiB needed",
      "fix": null,
      "fix_source": null,
      "observed": {
        "path": "/var/lib",
        "mount": "/var/lib",
        "fstype": "xfs",
        "free_bytes": 193273528320,
        "free_inodes": 94371840,
        "options": ["rw", "relatime"]
      },
      "expected": {"min_free_bytes": 107374182400, "recommended_free_bytes": 128849018880},
      "needs": [],
      "partial": null,
      "notes": [],
      "started_ms": 53,
      "duration_ms": 2,
      "truncated": false
    },
    {
      "key": "net.egress",
      "id": "net.egress",
      "name": null,
      "family": "net",
      "severity": "block",
      "status": "pass",
      "message": "2 of 2 endpoints reachable through the proxy",
      "fix": null,
      "fix_source": null,
      "observed": {
        "via": "proxy",
        "proxy": "http://proxy.corp.example:3128",
        "endpoints": [
          {"target": "registry.acme.example:443", "outcome": "ok", "connect_ms": 35, "tls_ms": 58},
          {"target": "license.acme.example:443", "outcome": "ok", "connect_ms": 36, "tls_ms": 60}
        ]
      },
      "expected": {
        "via_proxy": "auto",
        "reachable": ["registry.acme.example:443", "license.acme.example:443"]
      },
      "needs": [{"need": "network", "name": null, "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 53,
      "duration_ms": 190,
      "truncated": false
    },
    {
      "key": "k8s.version",
      "id": "k8s.version",
      "name": null,
      "family": "k8s",
      "severity": "block",
      "status": "pass",
      "message": "Server v1.29.4, 1.28 or newer needed",
      "fix": null,
      "fix_source": null,
      "observed": {"git_version": "v1.29.4", "distribution": "vanilla"},
      "expected": {"min": "1.28"},
      "needs": [{"need": "kube_context", "name": null, "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 54,
      "duration_ms": 44,
      "truncated": false
    },
    {
      "key": "k8s.storageclass",
      "id": "k8s.storageclass",
      "name": null,
      "family": "k8s",
      "severity": "warn",
      "status": "pass",
      "message": "Default class gp3 (ebs.csi.aws.com) supports ReadWriteOnce",
      "fix": null,
      "fix_source": null,
      "observed": {
        "default_class": "gp3",
        "provisioner": "ebs.csi.aws.com",
        "csi_driver_present": true,
        "access_modes": ["ReadWriteOnce"],
        "binding": "WaitForFirstConsumer"
      },
      "expected": {"access_modes": ["ReadWriteOnce"]},
      "needs": [{"need": "kube_context", "name": null, "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 54,
      "duration_ms": 88,
      "truncated": false
    },
    {
      "key": "gpu.cuda",
      "id": "gpu.cuda",
      "name": null,
      "family": "gpu",
      "severity": "block",
      "status": "pass",
      "message": "CUDA 12.6 (driver 560.35.03), 12.4 or newer needed",
      "fix": null,
      "fix_source": null,
      "observed": {"cuda_version": "12.6", "driver_version": "560.35.03", "source": "driver", "gpus": 4},
      "expected": {"min": "12.4"},
      "needs": [{"need": "command", "name": "nvidia-smi", "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 52,
      "duration_ms": 640,
      "truncated": false
    },
    {
      "key": "aws.iam",
      "id": "aws.iam",
      "name": null,
      "family": "aws",
      "severity": "block",
      "status": "pass",
      "message": "2 of 2 actions allowed for the caller",
      "fix": null,
      "fix_source": null,
      "observed": {
        "principal": "arn:aws:iam::111122223333:role/acme-installer",
        "decisions": [
          {"action": "eks:DescribeCluster", "decision": "allowed"},
          {"action": "ec2:CreateSecurityGroup", "decision": "allowed"}
        ]
      },
      "expected": {"simulate": ["eks:DescribeCluster", "ec2:CreateSecurityGroup"]},
      "needs": [{"need": "cloud_credentials", "name": "aws", "hard": true, "met": true}],
      "partial": null,
      "notes": [],
      "started_ms": 52,
      "duration_ms": 930,
      "truncated": false
    }
  ],
  "actions": [
    {"seq": 1, "check": null, "at_ms": 2, "duration_ms": 1, "kind": "read", "outcome": "ok", "path": "~/.kube/config", "bytes": 5412, "truncated": false},
    {"seq": 2, "check": null, "at_ms": 3, "duration_ms": 30, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/version", "status": 200},
    {"seq": 3, "check": null, "at_ms": 34, "duration_ms": 5, "kind": "kube", "outcome": "ok", "method": "POST", "path": "/apis/authentication.k8s.io/v1/selfsubjectreviews", "status": 201},
    {"seq": 4, "check": null, "at_ms": 36, "duration_ms": 120, "kind": "http", "outcome": "ok", "method": "POST", "url": "https://sts.us-east-1.amazonaws.com/", "status": 200},
    {"seq": 5, "check": "host.cpu", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/cpuinfo", "bytes": 16640, "truncated": false},
    {"seq": 6, "check": "host.cpu", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/cpu.max", "bytes": 13, "truncated": false},
    {"seq": 7, "check": "host.memory", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/meminfo", "bytes": 1482, "truncated": false},
    {"seq": 8, "check": "host.memory", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/memory.max", "bytes": 4, "truncated": false},
    {
      "seq": 9,
      "check": "gpu.cuda",
      "at_ms": 52,
      "duration_ms": 610,
      "kind": "exec",
      "outcome": "ok",
      "program": "/usr/bin/nvidia-smi",
      "argv": ["--query-gpu=driver_version,name,memory.total", "--format=csv,noheader"],
      "exit": 0,
      "stdout_bytes": 212,
      "truncated": false
    },
    {"seq": 10, "check": "aws.iam", "at_ms": 52, "duration_ms": 810, "kind": "http", "outcome": "ok", "method": "POST", "url": "https://iam.amazonaws.com/", "status": 200},
    {"seq": 11, "check": "host.disk", "at_ms": 53, "duration_ms": 1, "kind": "read", "outcome": "ok", "path": "/proc/self/mountinfo", "bytes": 3110, "truncated": false},
    {"seq": 12, "check": "net.egress", "at_ms": 53, "duration_ms": 2, "kind": "lookup", "outcome": "ok", "host": "proxy.corp.example", "answers": 1},
    {"seq": 13, "check": "host.disk", "at_ms": 54, "duration_ms": 0, "kind": "native", "outcome": "ok", "api": "statvfs", "path": "/var/lib"},
    {"seq": 14, "check": "k8s.version", "at_ms": 54, "duration_ms": 44, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/version", "status": 200},
    {"seq": 15, "check": "k8s.storageclass", "at_ms": 54, "duration_ms": 48, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/storageclasses", "status": 200},
    {"seq": 16, "check": "net.egress", "at_ms": 55, "duration_ms": 35, "kind": "connect", "outcome": "ok", "host": "registry.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128"},
    {"seq": 17, "check": "net.egress", "at_ms": 90, "duration_ms": 58, "kind": "tls", "outcome": "ok", "host": "registry.acme.example", "sni": "registry.acme.example"},
    {"seq": 18, "check": "k8s.storageclass", "at_ms": 102, "duration_ms": 40, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/csidrivers", "status": 200},
    {"seq": 19, "check": "net.egress", "at_ms": 148, "duration_ms": 36, "kind": "connect", "outcome": "ok", "host": "license.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128"},
    {"seq": 20, "check": "net.egress", "at_ms": 186, "duration_ms": 60, "kind": "tls", "outcome": "ok", "host": "license.acme.example", "sni": "license.acme.example"}
  ],
  "actions_truncated": false,
  "redaction": {"ruleset": "report", "total": 0, "by_rule": {}},
  "complete": true,
  "interrupted": false
}
```

All three blocks validate against the schema files with a draft 2020-12 validator (checked 2026-10-28).

## Plan corrections found

- docs/adr/0012, decision 5: names the files `rdy-v1-spec.schema.json` and `rdy-v1-result.schema.json`.
  The kickoff task and this doc use `spec.v1.schema.json` and `result.v1.schema.json`, and 09-docs-site.md
  takes its names from this doc. Fix: change ADR 0012 to these names.
- docs/adr/0012, decision 3: lists `redactions: u32`. 04-bundle-and-redaction.md asks for counts per
  rule. Fix: `redaction { ruleset, total, by_rule }`, as in the result schema now.
- docs/plan/04-bundle-and-redaction.md, M2 ticket "Spec and CLI additions: bundle.redact_patterns,
  bundle.max_size and --redact-pattern": the spec half is done in revision 0 (2.8). Fix: the ticket keeps
  the CLI flag and the redactor work only.
- docs/adr/0010, decision 2: the guard allows POST only to `selfsubjectaccessreviews` and
  `selfsubjectrulesreviews`, while decision 4 reads the user from `SelfSubjectReview`. Fix: add
  `selfsubjectreviews` to the allowlist, as threat model "Kubernetes read-only rule" already does.
- docs/adr/0008, decision 3: the table says any skipped block-severity check gives NOT READY, without
  02's `not_applicable` exception, the nothing-verified rule, or the unknown severity and status rules.
  Fix: the ADR 0013 ticket in 02 records all four (this doc 5.3).
- docs/adr/0008, decision 7: the code list lacks `spec_expired` and `trust_store_insecure`. Fix: add
  them (this doc 4.8).
- docs/plan/02-engine-design.md, Report renderers: "action log (collapsed per check)" in `<details>`.
  ADR 0003 decision 7 requires print to show every section, and closed `<details>` do not print. Fix:
  plain table at the end, first 1000 rows (this doc 6), and the ticket "HTML report grouping with
  blockers first and a collapsed action log" drops "collapsed".
- docs/plan/02-engine-design.md, Result model: `SkipReason::NeedsNewerRdy`. Fix: three kinds,
  `not_in_build`, `unknown_check`, `unsupported_spec` (this doc 5.2), and `NotYetOnOs` serializes as
  `not_yet_on_os`. `Summary::not_run` is named `optional_not_run`.
- docs/plan/02-engine-design.md, Report renderers: "escaped as `<`, `>` and `&`" lost its escapes the same
  way ADR 0003 once did. Fix: `\u003c`, `\u003e`, `\u0026`.
- docs/plan/05-threat-model.md, INV-06: unknown check ids and fields "cap the verdict at Warnings". Under
  ADR 0008 a block-severity one gives NOT READY. Fix: "count as required checks not run".
- docs/plan/05-threat-model.md, Surface 2 trust boundaries: lists `--trust-key`, which ADR 0002 removed.
  Fix: `trust.yaml`, `--key`, `rdy trust`.
- docs/plan/03-check-catalog.md, Thresholds: `host.cpu` `min_cores` and `recommended_cores` are `min` and
  `recommended`; `host.disk` `paths: [{path, min_free, ...}]` is one `path` per entry with `min`,
  `recommended`, `min_inodes`, `forbid_options`, `forbid_fstypes`; `k8s.admission`
  `needs_pod_security` is `pod_security`, and `dry_run`, `probe_pod` wait for ADR 0010; `k8s.nodes` drops
  the `nodes:` wrapper; `net.dns` `max_ms` is `max_latency`; the `net.egress` object uses `target`, not
  `url`. Reason: `examples/specs/acme-platform.yaml`, the canonical spec, already uses `host.cpu min` and
  `host.disk path`, and the rest follow the same conventions. Fix: align the catalog with 2.7.
- examples/specs/acme-airgap-host.yaml: `host.selinux` is `host.lsm` with `selinux: {allow: [...]}`;
  `host.cgroups` `require: v2` is `version: v2`; `via_proxy: never` is `direct`. `host.kernel`,
  `host.cgroups`, `host.time_sync` are M1-late and report `unknown_check` until built. Fix: rename and add
  the "cannot reach READY until" note. Today the file fails the schema on `via_proxy`.
- examples/specs/acme-k8s-only.yaml: `k8s.node_resources` is `k8s.nodes` (`min_ready`, `per_node`);
  `k8s.rbac` `can_i` is `can`. Fix: rename. Today the file fails the schema on `can_i`.
- examples/specs/acme-inference-gpu.yaml: `k8s.node_resources` as above; `gpu.vram` `per`/`min` and
  `gpu.device_plugin` differ from the catalog. Fix: align when the gpu family is specified for M4.
- docs/plan/00-overview.md, rdy-spec API sketch: `Report { run_id, rdy_version, started_at, .. }`, a
  single `verdict_reason` enum with one value, `Status::Skipped { reason: String }`, `CheckParams` without
  `Unsupported`, `Metadata` without `serial`, `expires`, `contact`, `annotations`. Fix: sketch the
  `producer` and `run` objects, `SkipKind`, `CheckParams::Unsupported` and the metadata fields of this doc.
- CLAUDE.md, Engineering standards: "machine output to stdout as JSON when `--json`". Fix: add that
  failures with `--json` print an `ErrorOutput` object (ADR 0008 decision 7).

## Tickets implied

Titles reused from ADRs, 00-overview and 02 are kept exactly so 11-backlog.md can dedupe; the exit tests
below add this doc's cases.

- [M1] Define public spec types in rdy-spec | owner: rust-engineer | est: 3h | depends on: Create workspace skeleton | exit test: the plan's example spec and every file in examples/specs decode into Spec with typed common fields, and the metadata fields of 2.2 round-trip through serde_json.
- [M1] Two-step check decoding with Unknown and Unsupported variants | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: `gpu.cuda` decodes to Unknown, `host.memory` with `mn` to Unsupported naming `mn`, and a missing id or duplicate entry key is a SpecError with line and column.
- [M1] Scalar types Quantity, Duration, Version and Target with strict grammars | owner: rust-engineer | est: 2h | depends on: Define public spec types in rdy-spec | exit test: unit tests reject `32G`, unquoted `1.30` and `10 s`, and accept `32Gi`, `"1.30"`, `14`, `7d` and `[::1]:443`.
- [M1] Typed parameters for M1 host check ids | owner: rust-engineer | est: 3h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: every host id in 2.7 decodes from a fixture covering each field, and each field has a rejecting case.
- [M1] Typed parameters for M1 net and k8s check ids | owner: rust-engineer | est: 4h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: acme-platform.yaml decodes with `needs` mapped to access_modes, both together are Unsupported, and every net and k8s id in 2.7 has an accepting and a rejecting fixture.
- [M1] Semantic validation and structural limits for specs | owner: rust-engineer | est: 2h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: fixtures for 257 checks, 65 endpoints, a duplicate key, a bad product slug, an unknown `metadata` key and an unknown `bundle` key each exit 64 with spec_invalid.
- [M1] Spec expiry and serial in metadata | owner: rust-engineer | est: 1h | depends on: Semantic validation and structural limits for specs | exit test: an expired fixture exits 64 with spec_expired before any check runs, and a valid one's serial appears in the result.
- [M1] rdy spec lint with errors, warnings and did-you-mean | owner: rust-engineer | est: 3h | depends on: Semantic validation and structural limits for specs | exit test: lint passes acme-platform.yaml with two not_in_build warnings and reports `mn: 32Gi` with "did you mean min" and its line number.
- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: the two example results in 01-spec-format.md deserialize and serialize back byte for byte, and unit tests cover every line of the 5.3 rule including not_applicable, nothing verified, unknown severity and unknown status.
- [M1] Host identity and host_id derivation | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture machine id gives the documented host_id, another product gives a different one, and a fixture run's JSON has no IP, MAC, home path or environment value outside observed.
- [M1] HTML-safe deterministic JSON writer with size caps | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a hostname with `</script>` is written as `\u003c/script\u003e`, the .json file, --json stdout and the HTML-embedded copy hash the same, and a 10000-action fixture stays under 2 MiB with actions_truncated true.
- [M1] Validate hand-written schemas against examples in CI | owner: rust-engineer | est: 2h | depends on: Create workspace skeleton | exit test: CI validates every file in examples/specs and every golden result with a 2020-12 validator and fails on the known-bad spec fixtures listed in 2.5.
- [M1] Generate JSON schemas with schemars and check drift in CI | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: the generated files accept and reject the same fixtures as the hand-written ones, replace them, and a doc-comment change without regenerating fails CI.
- [M1] Forward-compatibility fixtures for results | owner: rust-engineer | est: 1h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a result with an extra top-level field, status "quarantined" and skip_kind "frozen" deserializes, maps both to Unknown and keeps its recorded verdict.
- [M1] Verify minisign signatures in rdy-spec against a trust store with product binding | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: a tampered byte, a changed trusted comment, a legacy Ed signature, a comment without the rdy-spec-v1 prefix, a product mismatch and an unpinned key each fail before the YAML is parsed, and Wycheproof vectors pass.
- [M1] Trust store load and save in user and system locations | owner: rust-engineer | est: 3h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: as root only /etc/rdy/trust.yaml is read, as a user the user file then the system file, and symlinked, non-root-owned or group-writable files exit 64 with trust_store_insecure.
- [M1] rdy spec keygen and rdy spec sign | owner: rust-engineer | est: 4h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: an rdy signature verifies with stock minisign and a stock minisign signature with the 4.2 comment verifies in rdy; sign refuses a spec with a lint error and a key readable by others.
- [M1] rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | owner: rust-engineer | est: 3.5h | depends on: rdy spec keygen and rdy spec sign | exit test: every code in the 4.8 table comes from a fixture, the banner matches 4.7 byte for byte, and --allow-unsigned still exits 64 for an unpinned key and for an invalid signature.
- [M1] Align example specs and check catalog with 01-spec-format names | owner: rust-architect | est: 2h | depends on: none | exit test: every file in examples/specs validates against spec.v1.schema.json and 03-check-catalog.md uses the parameter names of 2.7.
- [M1] Collect security-reviewer and cli-ux reviews of 01-spec-format | owner: rust-architect | est: 2h | depends on: none | exit test: review files exist under docs/plan/reviews/ and every must-fix item is resolved in this doc or the schema files.
- [M1] Apply 01-spec-format corrections to ADRs 0008, 0010, 0012 and 00-overview | owner: rust-architect | est: 1h | depends on: Collect security-reviewer and cli-ux reviews of 01-spec-format | exit test: every Plan corrections bullet above is applied or answered in the review file.
- [M2] Bundle block strict validation in rdy bundle | owner: rust-engineer | est: 3h | depends on: rdy-bundle: collectors, redactors, tar plus zstd, manifest | exit test: an unknown redactor or collector kind refuses to build a bundle with a fix line.
- [M2] Warn on spec serial rollback | owner: rust-engineer | est: 3h | depends on: Spec expiry and serial in metadata | exit test: running serial 6 after serial 7 for the same product warns and records it in the result.
- [M2] Option to replace the hostname in reports | owner: rust-engineer | est: 2h | depends on: Host identity and host_id derivation | exit test: with the option set no report file contains the real hostname and host_id is unchanged.
- [M2] TTY confirmation for unsigned specs | owner: rust-engineer | est: 1h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: on a pty, answering no exits 64 with spec_unsigned; without a TTY the flag alone runs.
- [M2] Portal import of HTML reports via the embedded JSON | owner: rust-engineer | est: 4h | depends on: First crates.io release of rdy-spec and rdy-engine for rdy-cloud | exit test: rdy-cloud imports a golden HTML report, rejects one whose embedded JSON fails the schema, and labels it customer-reported.
- [M2] k8s.admission dry-run parameters after the ADR 0010 amendment | owner: rust-engineer | est: 2h | depends on: none | exit test: `dry_run` and `probe_pod` decode, appear in the schema revision table, and are refused at run time if the guard does not allow the call.
- [M3] Freeze rdy/v1 for the 1.0 release of rdy-spec | owner: rust-architect | est: 3h | depends on: none | exit test: schema files, golden results and this doc agree, and schema/README.md lists every revision since 0.1.
