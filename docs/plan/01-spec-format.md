# 01 Spec format, result format, signing and the report contract

Owner: rust-architect. Status: draft 2, revised after the security-reviewer and cli-ux reviews in
`docs/plan/reviews/01-spec-format-review-by-*.md`. Date: 2026-10-28.

This is the `rdy/v1` contract. `rdy-cloud` consumes it from crates.io through `rdy-spec` (ADR 0012), so
every change follows section 3. The schema files are `crates/rdy-spec/schema/spec.v1.schema.json` and
`crates/rdy-spec/schema/result.v1.schema.json` (JSON Schema 2020-12, generated from the `rdy-spec` types
by `cargo xtask schema` since M1-022; see the README next to them and ADR 0019). Where this text and a
schema file disagree, the schema file wins and this text gets a fix. Wording a user sees follows cli-ux; security rules follow
security-reviewer.

**ADRs this doc relies on:** 0001 (YAML, parser limits, version scalars), 0002 (minisign, trusted comment,
trust store, `--allow-unsigned`), 0003 (report files, self-contained HTML, embedded JSON), 0004
(timeouts), 0005 (no exec in M1), 0007 (versioning, unknown keys), 0008 (statuses, verdict, error codes),
0009 (egress policy, endpoint cap), 0010 (read-only kube guard), 0012 (wire types in `rdy-spec`,
provenance fields). It also builds on 02-engine-design.md (needs, skip reasons, action log, the
not-applicable refinement of the verdict), 04-bundle-and-redaction.md (redaction) and 05-threat-model.md.

## 1. Three version numbers

| Thing | Example | Who bumps it | Rule |
| --- | --- | --- | --- |
| Wire format | `apiVersion: rdy/v1` in specs, `"api_version": "rdy/v1"` in results | rust-architect, by ADR | Changes only for a breaking change (3.3). |
| `rdy-spec`, `rdy-engine` crates | `0.1.0` | release-plz, per crate | Semver (ADR 0007). A release that changes the wire format adds a line to `schema/README.md` and a "Wire format" CHANGELOG entry. |
| `rdy` binary | `0.1.0` | release tag | Recorded in every result. |

A result records all three: `api_version`, `producer.rdy_spec`, `producer.version`.

## 2. The rdy/v1 spec

One YAML 1.2 document per file, at most 1 MiB, with the limits of ADR 0001: depth 64, no duplicate
keys, no merge keys, no anchors or aliases, one document. Also exit 64 with line and column: any explicit
tag (`!!binary`, `!custom`), any `%YAML` or `%TAG` directive, and any non-finite float (`.inf`, `.nan`)
anywhere in the file, because a NaN threshold compares false both ways and could pass by accident. An
unquoted decimal (`12.10`, `1e3`), a whole number with a leading zero (`0755`) and a whole number outside
`i64` and `u64` are also errors with a line, a column and the hint to quote them. Once `apiVersion` names
`rdy/v2` or later, any such error further down is reported as the upgrade message instead. It
applies to every plain scalar, not only to version fields, because the parameters are read before their
types are known (ADR 0001, implementation notes). `rdy_spec::parse_unverified` enforces all of this.

The limits that need no clock live in the `limits` module of `rdy-spec` and run at the end of `parse_unverified`: 1 to 256 checks;
at most 64 distinct hosts across every `net.egress` endpoint, `net.tls_intercept` host and `net.dns` name in the
whole spec (threat model INV-11), counted once per host whatever the port; at most 256 distinct host and port
pairs across every `net.egress` endpoint and `net.tls_intercept` host, so 256 checks of 64 endpoints cannot turn a
spec into a port scan; the lengths of `metadata`; and the
sizes and collector grammar of `bundle` (2.8). `expires` is shape-checked there and compared with the clock by
`rdy_spec::load`, as the last step of 4.4.

### 2.1 Top level

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `apiVersion` | string | yes | Exactly `rdy/v1`. |
| `kind` | string | yes | Exactly `Readiness`. |
| `metadata` | object | yes | 2.2. |
| `checks` | list | yes | 1 to 256 entries, in report order. 2.3. |
| `bundle` | object | no | What `rdy bundle` collects, from M2. 2.8. |

### 2.2 metadata

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `product` | `^[a-z0-9][a-z0-9-]{0,62}$` | yes | Product name (ADR 0003). Binds the signature to a pinned key and names the report directory and files. |
| `version` | string, max 64 | no | Product versions this spec is for (`">=4.2"`). The report shows "For acme-platform >=4.2". Not evaluated: rdy cannot know the product version. |
| `contact` | string, max 256 | no | Where the customer asks questions. Shown as plain text, never as a link. |
| `serial` | integer, 0 or more | no | Spec revision, rising on every signed release. Shown as "Spec revision 7". M2 warns when a lower serial follows a higher one for the same product (threat model T4). |
| `expires` | `YYYY-MM-DDTHH:MM:SSZ` | no | After this, `rdy run` and `rdy verify` refuse the spec: exit 64, `spec_expired`. No override flag. An unquoted date (`2027-01-31`) is an error; lint says the full form is needed and quoting alone does not help. |
| `annotations` | map of string to string | no | Up to 32 entries, for vendor tooling and the portal (a portal spec id, say). rdy never changes behaviour because of an annotation and copies them into the result. `rdy-cloud` treats annotations in a result as customer-reported and never routes or authorizes on them. |

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
| `name` | `^[a-z0-9][a-z0-9_-]{0,62}$` | none | A short label. Needed when an id repeats. The key is `id` or `id/name`, unique per spec, and reports show `host.disk (data)`. |
| `severity` | `block` or `warn` | `block` | `block` means required, `warn` means optional (2.6). |
| `fix` | string, 1 to 2000 chars | none | Replaces rdy's advice as the headline fix (2.6). |
| `timeout` | duration, 1s to 60s | the check's own default, else 10s | How long the check may run. The spec value wins over the check's default; the effective value is `min(spec or default, 60s, time left in the run)`. Outside 1s to 60s: lint and sign error `timeout must be between 1s and 60s`, and at run time that check is not run (`unsupported_spec`). |
| `os` | list of `linux`, `macos`, `windows` | all | Run only there. Elsewhere the check is `skipped`, `not_applicable`, and never counts. An empty list `os: []` is `unsupported_spec`, because it would hide the check on every OS. `os: [rhel]` is an error with the lint note "os selects the operating system family. To match a distribution, use the host.os check." |

A cross-platform spec names the two entries:

```yaml
- id: host.disk
  name: data
  os: [linux, macos]
  path: /var/lib/acme
  min: 100Gi
- id: host.disk
  name: data-windows
  os: [windows]
  path: 'D:\acme'
  min: 100Gi
```

Not adopted from the catalog's assumed list: `optional` (`severity: warn` already says it) and
`severity: info` (it can come later as an additive enum value).

### 2.4 Per-check parameters: a tagged union, decoded in two steps

Each id has its own parameters (`min`, `endpoints`, `via_proxy`, `access_modes`, `simulate`). The choice:

| Option | For | Against |
| --- | --- | --- |
| Tagged union on `id`, one closed parameter set per id | Typed values, one definition per check, a precise schema for editor completion and errors. | serde's internally tagged enum fails the whole file on an unknown id or field, which breaks the skip rule of ADR 0005 and ADR 0007. |
| Open map plus per-check validation | Tolerant. | Typos pass unless every check re-implements validation; the schema says nothing useful. |

**Decision: the contract is a tagged union on `id`; the code decodes it in two steps.**

1. The entry decodes into the common fields plus a raw map of the other keys.
2. The raw map decodes into the parameter struct for that id, unknown fields denied. Success gives
   `CheckParams::HostMemory(..)` and so on. An id rdy does not implement gives
   `CheckParams::Unknown { id, fields }`. A field or value the struct rejects gives
   `CheckParams::Unsupported { id, fields, reason }`.

In the schema file this is `allOf` with one `if id == X then XParams` branch per known id, closed by
`unevaluatedProperties: false`, plus one branch that lets unknown ids carry anything.

Version fields take quoted strings or bare integers. By step 1 an unquoted `1.30` is already the float
1.3, so per ADR 0001 decision 4 it is rejected with "quote it: min: \"1.30\"".

Parameter types are added to `rdy-spec` in the PR that builds the check (ADR 0012). Revision 0 of the
schema has the 17 ids of the catalog's M1 tier.

**Reserved ids.** `rdy-spec` ships the list of every id named in 03-check-catalog.md, built or not:
the host, net, k8s, aws, gpu, store and custom ids of sections 2 to 8, the `gcp.*` and `azure.*` ids of
section 5, and the reserved ids of section 9 (`aws.imds`, `gpu.rocm`, `gpu.vgpu_license`,
`host.hostname`, `host.virtualization`, `k8s.egress_probe`, `k8s.images`, `k8s.metrics`, `k8s.snapshots`,
`net.pmtu`, `store.kafka`). Adding an id to the list is additive. A reserved id this rdy does not
implement is `not_in_build`, so `host.kernel` on M1 says "not in this version", not "did you mean".

### 2.5 Unknown fields, unknown ids and bad values

Principle (ADR 0007 decision 6): **rdy never ignores something it does not understand if ignoring it
could change the verdict or what leaves the machine.** At run time, anything wrong inside one check
entry skips that check, so a newer spec on an older rdy fails closed. Anything wrong outside a check entry
exits 64. Lint and sign are stricter, because the person running them is the vendor:

| Case | `rdy run`, `rdy verify` | `rdy spec lint` | `rdy spec sign` |
| --- | --- | --- | --- |
| Unknown key at the top level, in `metadata` or in `bundle` | exit 64 | error | refuses |
| Structure: syntax, limits, tags, missing `id`, duplicate keys, wrong `apiVersion` or `kind`, no checks, over 256 checks, over 64 distinct hosts or over 256 host and port pairs, bad product, bad `expires`, expired | exit 64 | error | refuses |
| Reserved id not implemented here (`gpu.cuda`, `host.kernel` on M1) | skipped, `not_in_build` | warning | signs, with the warning |
| Id not reserved (`host.memroy`, `upload.now`) | skipped, `unknown_check` | error | refuses |
| Unknown field or bad value in a known check (`mn: 32Gi`, `min: 32G`, `severity: blok`, `timeout: 90s`) | skipped, `unsupported_spec`; an unreadable `severity` counts as `block` | error | refuses |
| A check with no threshold (`- id: host.memory` alone) | skipped, `unsupported_spec` (the parameter is required) | error, `no_threshold` | refuses |
| A `redact_patterns` regex that does not compile or matches the empty string | exit 64 | error | refuses |

A key with no value (`min:` and nothing after it) is a bad value, not an absent key, so it cannot drop a
threshold by accident. Where this table says "no threshold", the required key or keys are the bold ones
and the "one of" groups in section 2.7. `host.lsm`, `host.security_agents` and `host.os` have no required
key and read when bare.

`spec lint` exits 0 with no findings, 1 with warnings only, 2 with errors, 64 for usage, like `run`.
With `--json` it prints a `LintReport` (result schema `$defs`). This answers the open question of draft 1
(both reviews: sign refuses typos in known checks). It amends ADR 0008 decision 2, which made unknown
fields lint warnings.

Every error line carries `file:line:col:` where known, and every one has a `fix:` line. Spec content
errors (exit 64, codes `spec_parse` and `spec_invalid`; the same text in lint as `error:`):

| Case | First line | Fix line |
| --- | --- | --- |
| Unknown top-level key | `error: acme-platform.yaml:3:1: unknown key 'metdata'` | `fix: check the spelling (did you mean 'metadata'?). If it is right, this spec needs a newer rdy than 0.1.0. Install the latest and run again.` |
| Unknown key in `metadata` or `bundle` | `error: acme-platform.yaml:6:3: unknown key 'prodcut' in metadata` | same fix line |
| `apiVersion` is `rdy/v2` | `error: acme-platform.yaml:1:13: this spec is for rdy/v2. rdy 0.1.0 reads rdy/v1 only.` | `fix: install the latest rdy.` |
| `apiVersion` missing or wrong | `error: acme-platform.yaml:1:1: apiVersion must be rdy/v1` | `fix: add 'apiVersion: rdy/v1' as the first line.` |
| Entry has no `id` | `error: acme-platform.yaml:18:5: check 3 has no id` | `fix: add an id such as 'id: host.memory'.` |
| Same id twice | `error: acme-platform.yaml:31:5: two checks are named host.disk` | `fix: give each one a name, for example 'name: data'. The name is only a label.` |
| Bad product name | `error: acme-platform.yaml:15:12: 'Acme Platform' is not a valid product name` | `fix: use lowercase letters, digits and hyphens, such as 'acme-platform'.` |
| Bad `expires` | `error: acme-platform.yaml:16:12: expires must be a full UTC time` | `fix: write it like 'expires: 2027-01-31T00:00:00Z'.` |
| Too many checks | `error: acme-platform.yaml: 257 checks. The limit is 256.` | `fix: split the spec in two, or remove checks.` |
| Too many hosts | `error: acme-platform.yaml: 65 endpoints. The limit is 64.` | `fix: remove hosts, or split the spec in two. A host counts once, however many checks name it.` |
| Too many host and port pairs | `error: acme-platform.yaml: 257 host and port pairs. The limit is 256.` | `fix: remove endpoints, or split the spec in two. A host and port counts once, however many checks name it.` |
| `expires` has passed | `error: acme-platform.yaml expired on 2027-01-31. This machine's clock says 2027-02-03.` | `fix: ask the vendor for a current spec. If this machine's clock is wrong, set it and run again.` |
| Tag, directive or `.nan` | `error: acme-platform.yaml:22:10: '.nan' is not allowed in a spec` | `fix: write a plain number, string or list.` |

The `did you mean` part appears only when the edit distance is small; otherwise the sentence ends after
"a typo". The run-time skip messages are in 5.2.

### 2.6 Scalars, severity and the fix override

| Type | Grammar | Notes |
| --- | --- | --- |
| Quantity (bytes) | integer, or integer plus `Ki`, `Mi`, `Gi`, `Ti`, `Pi` | `32G` and `32GB` are bad values: "write 32Gi, not 32G". Lint warns on a bare integer under 1 MiB ("32 bytes, did you mean 32Gi?"). At most 15 digits and 2^53 - 1 bytes. Units are case sensitive. |
| Duration | integer plus `ms`, `s`, `m`, `h` or `d` | `10s`, `7d`. No compound forms. The number is 1 to 999999999, so `0s` is a bad value. |
| Version | quoted dotted string, or bare integer | Compared per numeric component, not as semver. One to four parts of up to 9 digits; a leading `v` is allowed. The text is kept as written. An unquoted `1.30` is a bad value (ADR 0001 decision 4). |
| Path | absolute (`/...`, `C:\...`), max 1024 | Kept as written; the check resolves it. No control characters. Never reaches a shell; there is none. |
| Regex | Rust `regex` syntax, max 256 chars | Linear time, size-limited when compiled. Lint and sign compile every pattern. |
| Target | `host:port` (port 1 to 65535), `[v6]:port`, or `http(s)://` URL | At most 64 per spec (ADR 0009). Specs never carry credentials: user info in a URL is a bad value, and fragments are not allowed. Query strings never enter the action log. A host name has no trailing dot (write `example.com`, not `example.com.`) and cannot end in a number. An IPv4 address is four plain decimal parts: `2852039166`, `0xa9.0xfe.0xa9.0xfe`, `0251.0376.0251.0376` and `127.1` are bad values, because resolvers read them as other addresses than they look like. IPv6 forms of an IPv4 address (`::ffff:a9fe:a9fe`) are bad values: write the IPv4 form. Parsing does not classify addresses: `localhost`, `0.0.0.0`, `[::]`, NAT64 and unique local literals, wildcard DNS names, link-local and metadata addresses all parse; the egress policy refuses them at run time and the check reports `block` with the reason (ADR 0009). |

**Severity.** `severity: block` means required and `severity: warn` means optional. A check computes a
level from its thresholds: pass, warn or fail. `block` (default) maps fail to `block`; `warn` maps fail
to `warn`. The result carries the capped `status` and the spec's `severity`.

**The fix override.** `fix` is plain text from the vendor: no templating (braces are literal), no markup
(the HTML escapes it), newlines kept, other control characters stripped before printing. On `warn` and
`block` it replaces rdy's advice as the headline: the terminal shows the vendor's fix only; the HTML shows
it first and rdy's own text below it as "More from rdy" when `builtin_fix` is present. The vendor text is
labelled with the product ("From acme-platform") only when `signature.state` is `verified` and
`trust_source` is `system` or `user`, because only then is the product bound to a pinned key. Otherwise
the label, in the terminal and the HTML, is "From the spec file (not verified)" (threat model Surface 2,
S1). When a check did not run the vendor's fix is not shown, because it would tell the customer to fix
something nobody measured; rdy's own fix for the non-run is shown, with `fix_source: rdy`. The same holds for a pass that the partial rule turns into `warn` (02, Verdict): nothing was measured as
failing, so rdy's own text is shown, with `fix_source: rdy`, and the vendor's `fix` is hidden.

### 2.7 Parameters of the M1 check ids

Two conventions: the main threshold is `min` (or `max`), as in `examples/specs/acme-platform.yaml`, and a
warn threshold is `recommended`. Types, ranges and defaults are in the schema file; what each threshold
means is in 03-check-catalog.md. Bold parameters are required; "one of" means at least one is required.

| Id | Parameters |
| --- | --- |
| `host.cpu` | one of `min` (cores), `arch` (`x86_64`, `aarch64`, or `amd64`, `arm64`), `flags`; also `recommended` |
| `host.memory` | **`min`**, `min_available`, `swap` (`forbid`, `any`), `tolerance_percent` (0 to 20, default 5, at least 256 MiB. The band is never wider than half of `min`, so a tiny value always blocks), `tolerance_result` (`pass`, `warn`) |
| `host.disk` | **`path`**, **`min`**, `recommended`, `min_inodes`, `forbid_options` (`noexec`, `nosuid`, `nodev`, `ro`), `forbid_fstypes`. One path per entry; repeat the id with a `name` for more. |
| `host.ports` | one of `free` (a port or `{port, bind}`, `bind` `public` or `loopback`), `udp_free`; also `allow_owner` |
| `host.lsm` | `selinux: {allow, denials_max, denials_window, watch}`, `apparmor: {allow, require_profiles}` |
| `host.security_agents` | `forbid`, `allow` |
| `host.os` | `supported: [{id, versions}]`, `arch`, `fips` (`forbid`, `require`, `any`), `windows_min_build` |
| `net.egress` | **`endpoints`** (a target, or `{target, optional, expect_status, method, via_proxy, tls}`), `via_proxy` (`auto`, `direct`, `proxy_only`; default `auto`), `trust` (`system`, `bundled`), `max_latency` |
| `net.proxy` | `required_no_proxy`, `daemons_need_proxy` |
| `net.tls_intercept` | `hosts` (default: every `net.egress` host in the spec, so an empty `tls_intercept` tests each of them and adds at most 64 connections), `expected_issuer`, `pin_sha256`, `forbid_interception` |
| `net.dns` | **`names`** (a name or `{name, expect_in, expect_public}`), `max_latency` |
| `k8s.access` | `context_pattern`, `server_pattern`, `max_latency` |
| `k8s.storageclass` | `class`, `access_modes`, `binding`, `expansion`, `reclaim_policy` |
| `k8s.rbac` | **`can`** (1 to 100; `"create namespaces"` or `{verb, group, resource, subresource, namespace, name}`), `namespace` |
| `k8s.admission` | `pod_security` (`privileged`, `baseline`, `restricted`), `uses` (`hostPath`, `hostNetwork`, `hostPID`, `privileged`, `runAsRoot`), `namespace`, `scc` |
| `k8s.nodes` | one of `min_ready`, `per_node: {cpu, memory, ephemeral, pods}`, `free: {...}`; also `min_zones`, `arch`, `selector`, `tolerations` |
| `k8s.version` | one of `min`, `max`, `openshift_min`, `apis`; also `over_max` (`warn` or `block`, default `warn`) |

Changes from draft 1, from the cli-ux review: the deprecated `needs` alias on `k8s.storageclass` is gone
(nothing has shipped, and the canonical example now says `access_modes`); `k8s.version` `max_severity` is
`over_max`, and lint prints `note: servers above 1.31 give a warning. Set over_max: block to make them
block.` when `max` is set without it; `host.memory` `band` and `band_result` are `tolerance_percent` and
`tolerance_result`, and the message says "15.7 GiB found, 16 GiB needed, inside the 5% tolerance";
`swap: off` is `swap: forbid`, because YAML 1.1 tools turn `off` into `false`. `k8s.admission` has no
`dry_run` or `probe_pod`: the read-only guard of ADR 0010 and threat model INV-14 reject that call in M1.
They arrive as an additive revision with the ADR 0010 amendment.

### 2.8 The bundle block

Used by `rdy bundle` from M2. It must parse in v1 so specs written today keep working.

```yaml
bundle:
  collect: ["journal:7d", "k8s:events", "file:/etc/acme/*.yaml"]          # max 64
  redact: ["aws_keys", "bearer_tokens", "emails"]                         # groups to add, max 64
  redact_patterns: [{name: acme_license, regex: "ACME-[A-Z0-9]{20}"}]     # optional, max 32
  max_size: 200Mi                                                         # optional
```

- `collect` items are `journal:<duration>`, `k8s:events` or `file:<absolute path or glob>` (no `..`
  segments, no backslash until the Windows path form lands in M2, no control characters). Other kinds are bad values until 04-bundle-and-redaction.md adds them.
- `redact` names groups to add. The built-in rules always run: a spec can add redaction and can never
  remove it.
- `redact_patterns` adds vendor patterns. **A pattern can only add redaction. Overlapping spans merge:
  the replaced region is the union of every overlapping span, and priority picks only the placeholder's
  rule name. A custom pattern can never leave a byte unredacted that the built-in rules alone would
  redact.** A pattern that matches the empty string, or does not compile, is an error. 04 section 3.1
  applies the same rule.
- `max_size` lowers rdy's own cap, never raises it.
- `rdy run` never collects anything, whatever the block says. `rdy bundle` uses the spec's `collect` and
  `redact_patterns` only when the spec is `verified` with a pinned key (`trust_source` `system` or
  `user`), the same rule ADR 0005 applies to `custom.exec`. Otherwise it uses the built-in collector set
  and says so. `rdy bundle` refuses a spec with no `bundle:` block (04).

## 3. Versioning and compatibility

### 3.1 apiVersion handling

- `rdy/v1`: read.
- `rdy/v2` or later: exit 64, `spec_invalid`, wording in 2.5.
- Missing, misspelled or another group: exit 64, `spec_invalid`.
- There is no `rdy/v1.1`. Additive revisions do not touch `apiVersion`; 2.5 makes an older reader fail
  loudly or skip a check, never pass by accident.

Results use the same rule: `rdy report` and `rdy-cloud` read `api_version: rdy/v1` from any producer.

### 3.2 Additive changes inside v1

Allowed without a new `apiVersion` (ADR 0007 decision 5), each with a revision line in
`schema/README.md` and regenerated schema files:

- A new check id or reserved id, or new parameters for an existing id.
- A new optional field anywhere in the spec or result.
- A new value in an open result enum: `status`, `bucket`, `skip_kind`, `error_kind`, `need`, action
  `kind` and `outcome`, `signature.state`, `trust_source`, `verdict_reason`, `fix_source`. The schema marks
  them "Open".
- A new error `code` or lint finding `code`.
- A new spec enum value (`severity: info`, say). An older rdy skips that check as `unsupported_spec`.
- New keys inside a check's `observed` or `expected`, or a new `summary` key.

| Reader | Newer spec | Newer result |
| --- | --- | --- |
| Older `rdy` | Unknown top-level, `metadata` or `bundle` key: exit 64 with an upgrade hint. Unknown id or check field: that check skips and counts as not run. | n/a |
| Older `rdy-cloud`, `rdy report` | Same rules when validating portal-authored specs. | Ignores unknown fields. An unknown status counts as not run, an unknown severity as block, an unknown `bucket` sorts with `required_not_run`, an unknown `signature.state` or `trust_source` counts as not verified and shows the banner. Displays `verdict` as written. The portal may also recompute from known statuses and flag a mismatch as "inconsistent report"; it never replaces the recorded verdict. |

### 3.3 When rdy/v2 is required

Removing or renaming a field or check id (id renames keep the old id as an alias until v2, per the
catalog); narrowing a type so a once-valid value fails; changing a default, a unit or what a value means;
a new required field; a new verdict, a new value in a closed enum (`verdict`, `exit_code`, spec `kind`) or
a change to the verdict rule; changing the signed bytes or the trusted comment format. In v2 the comment
prefix must match (`rdy-spec-v2` for `rdy/v2`), so a v1 signature can never vouch for a v2 body. A v2
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
  ending conversion. A file that went through CRLF conversion fails, and the error says so (4.8). Vendor
  docs say to ship specs with `*.yaml -text` in `.gitattributes`.
- The global signature covers the signature plus the trusted comment, so the comment is signed.
- Size caps: sidecar 4 KiB, `trust.yaml` 256 KiB (threat model INV-02).

### 4.2 The trusted comment

```text
^rdy-spec-v1 product=[a-z0-9][a-z0-9-]{0,62} signed_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$
```

Exactly this form, no trailing whitespace or CR; anything else is refused (ADR 0002 decision 1). The
`rdy-spec-v1` prefix is the domain separation: a signature the same key made for something else carries a
different comment. A `signed_at` more than 24 hours in the future gives a warning, not a refusal. The
untrusted comment line is never read.

### 4.3 The trust store

**Identity of a key.** A minisign key id is 8 random bytes chosen at keygen, so anyone can mint a key with
the vendor's key id. The identity is the **fingerprint: SHA-256 over the 32-byte ed25519 public key**, 64
hex digits. `rdy trust add`, `rdy verify`, `rdy spec sign` and both reports show it. Lookup uses the key
id only to preselect and then compares the full public key. `trust add` refuses a second key with the same
id for the same product, and refuses malformed and small-order keys, as does `--key` (threat model Surface
2, requirement 2).

**Where it lives.**

| Running as | Reads | `rdy trust add` writes |
| --- | --- | --- |
| euid 0 on Unix | only `/etc/rdy/trust.yaml`, whatever `HOME`, `SUDO_USER` or `XDG_CONFIG_HOME` say | `/etc/rdy/trust.yaml` |
| elevated on Windows | only `%ProgramData%\rdy\trust.yaml` | that file |
| a normal user | `$XDG_CONFIG_HOME/rdy/trust.yaml` (default `~/.config/rdy/trust.yaml`; Windows `%APPDATA%\rdy\trust.yaml`), then the system file (threat model Surface 2, requirement 3) | the user file |

**A root run never stats, opens or parses any path under a user's home**, not even to word a hint
(threat model INV-04). Whenever a root run finds no matching key it prints the same hint: `as root, rdy
reads only /etc/rdy/trust.yaml. If you pinned this key as a normal user, pin it for root too: sudo rdy
trust add acme-platform --key <file>`.

**Refusal rules** (exit 64, `trust_store_insecure`, with the reason):

- Unix system file: a symlink, not owned by root, group or world writable, or in a directory writable by
  anyone but root (ADR 0002 decision 4). User file: group or world writable, and, by ADR 0021, a symlink or a
  file that another user owns, or a user folder (`~/.config/rdy`) that is a symlink, is owned by another
  user, or is group or world writable. Until the Windows rules below are built (M1-122), a Windows trust file that
  exists is refused as unverifiable (ADR 0021).
- Windows, elevated runs: refused unless the file and `%ProgramData%\rdy` are owned by `Administrators`
  or `SYSTEM`, their DACLs grant write, delete or `WRITE_DAC` to no other principal (CREATOR OWNER
  included), and neither is a reparse point. By default `BUILTIN\Users` may create folders under
  `C:\ProgramData`, so a store a non-admin user pre-created must fail. `rdy trust add`, run elevated,
  creates the directory with a protected DACL: Administrators and SYSTEM full control, Users read.

```yaml
apiVersion: rdy/v1
kind: TrustStore
keys:
  - product: acme-platform
    key: RWQFbHsh1NTnBwUEXAMPLEONLYnotarealpublickeyAAAAAAAAAAAAA
    added_at: 2026-11-30T16:20:00Z
    note: "Acme security page, fingerprint read back by phone"
```

Unknown keys in this file are an error with `fix: remove that line, or run rdy trust list to see what
rdy wrote.` The key id and fingerprint are derived from `key`, never stored. A key is trusted only for the
products listed with it. Pinning happens only in `rdy trust add`, which shows the key id and fingerprint,
asks the user to compare the fingerprint with the one the vendor published, and asks `Trust this key for
acme-platform? [y/N]` (`--yes` to skip). `--note` is optional; `trust add` says "Your note appears in
every report you send."

**One-run keys.** `rdy run --key <file>` trusts a key for one run and writes nothing (`trust_source:
flag`). `--key` is read from argv only, like `--allow-unsigned` (threat model INV-05), and no hint ever
suggests it. Because an attacker can mail a key as easily as a spec, a `--key` run shows the KEY NOT
PINNED banner (4.7).

### 4.4 Verification order

The parser only sees bytes a trusted key signed, unless the user chose `--allow-unsigned` (ADR 0002
decision 3). **The spec and the sidecar are each read once, into memory. Verify, parse, hash and the copy
into the output directory all use that buffer; rdy never reopens the path.** `rdy spec sign` likewise
lints and signs one buffer.

1. Read the spec (1 MiB cap) and the sidecar (4 KiB cap).
2. Parse the sidecar; reject legacy `Ed` and any trusted comment not in the 4.2 form.
3. Look up keys pinned for the comment's `product`: `--key` first, then the stores; preselect by key id,
   match the full public key.
4. Verify the raw bytes, then the global signature over the comment.
5. Only now parse the YAML (ADR 0001) and validate (2.5).
6. Check `metadata.product` equals the comment's `product`.
7. Check `expires`.

### 4.5 rdy spec sign and keygen

`rdy spec keygen` writes the secret key with `create_new`, mode 0600, password-encrypted unless
`--unencrypted` (for vendor CI, ADR 0002 decision 8), plus the public key file, and prints the
fingerprint for the vendor to publish on its docs page. The encryption is scrypt at the cost stock
minisign uses, N = 2^20 and 1 GiB, which is also the most a key file may ask for (ADR 0022).

`rdy spec sign <spec> [--secret-key <file>] [--sig <out>] [--force]` (flags final in 07-cli-ux.md):

1. Runs `rdy spec lint` on the buffer. Any error refuses to sign (2.5); warnings are printed.
2. Refuses a secret key readable by group or others. Asks for its password if encrypted.
3. Signs the exact bytes with the 4.2 trusted comment, `signed_at` = now.
4. Checks the signature with `rdy_spec::load`, the code a customer's rdy runs, with the key pinned for the
   product. This happens before anything is written. A failure is an internal error (exit 70).
5. Writes `<spec>.minisig` with exclusive create; `--force` writes a new file beside it and renames it over
   the old one, so a symlink at the path is replaced and never written through. Then it prints the key id,
   the fingerprint, the spec SHA-256 and the lines the vendor sends to customers: `rdy trust add acme-platform --key acme-platform.pub` and "the fingerprint
   is <hex>; compare it before you say yes".

Stock minisign interoperates: `minisign -V` verifies an rdy signature, and a spec signed with
`minisign -S -t "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z"` verifies in rdy.

### 4.6 rdy verify

`rdy verify <spec> [--sig <file>] [--key <file>] [--json]` runs 4.4 and no checks. It never prompts and
does not take `--allow-unsigned`. Exit 0 means "`rdy run` would accept this file with no override".
Otherwise exit 64 with a code from 4.8. It prints product, key id, fingerprint, trust note and source,
`signed_at`, serial, expiry and SHA-256, and the KEY NOT PINNED banner when `--key` was used. With
`--json`: a `Verification` object, or an `ErrorOutput` on failure (result schema `$defs`).

### 4.7 --allow-unsigned, --key and the two banners

`--allow-unsigned` allows exactly one thing: a spec with **no** signature. "No signature" means no `--sig`
was given and opening `<spec>.minisig` returned not-found. Permission denied, a directory, a dangling
symlink, an empty file, or a `--sig` path that does not exist all exit 64 (`spec_signature_invalid`, or
`usage` for `--sig`), even with the flag. Any signature that is present but does not verify against a key
pinned for the product, or given with `--key`, exits 64 even with the flag (ADR 0002 decision 7),
including a valid signature by an unpinned key. An unsigned spec containing `custom.exec` exits 64 from M4
(ADR 0005). Expired specs are refused regardless. **No hint, fix line or error message ever names
`--allow-unsigned` or `--key`** (threat model T2); the flags are documented on
`https://docs.getrdy.io/unsigned`.

**Banner rule:** show a banner unless `signature.state` is `verified` and `trust_source` is `system` or
`user`. Both banners print on stderr before any check runs, red when colour is on, and again, first line
only, directly above the verdict line. The HTML shows them at the top and on every printed page.

Unsigned (`signature.state: unsigned`, `run.options.allow_unsigned: true`):

```text
WARNING: UNSIGNED SPEC
./specs/acme-platform.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.
```

One-run key (`signature.state: verified`, `trust_source: flag`):

```text
WARNING: KEY NOT PINNED
This spec was checked with a key given on the command line (fingerprint 4d2a7c0e...0a1c).
rdy cannot tell whose key that is.
Every report from this run is marked KEY NOT PINNED.
```

The path is shown as typed. M2 adds a TTY confirmation after either banner, `Run it anyway? [y/N]`,
default no (threat model T2); the text above does not change.

### 4.8 Error codes for spec loading

All exit 64. With `--json`, each is an `ErrorOutput` on stdout with `file`, `line` and `column` where
known (ADR 0008 decision 7). Spec content errors are in 2.5.

| Code | When | First line | Fix line |
| --- | --- | --- | --- |
| `spec_unreadable` | the spec file is missing, not a regular file, or unreadable | `error: cannot read acme-platfrom.yaml: no such file` | `fix: check the file name and the folder you are in` (07 C.6) |
| `spec_unsigned` | no sidecar, no flag | `error: no signature found at acme-platform.yaml.minisig` | `fix: ask the vendor for acme-platform.yaml.minisig and put it next to the spec.` and `If you wrote this spec yourself, see https://docs.getrdy.io/unsigned` |
| `spec_key_unknown` | no pinned key matches | `error: acme-platform.yaml is signed with key 9F3A6C21D4E87B05 (fingerprint 4d2a...0a1c), which you have not trusted for acme-platform` | `fix: get the vendor's public key from their docs, compare its fingerprint with what the vendor tells you, then run: rdy trust add acme-platform --key <file>` |
| `spec_signature_invalid`, tampered | bytes or comment do not verify | `error: the signature on acme-platform.yaml does not match the file. It may have been changed after signing.` | `fix: get a fresh copy and its .minisig from the vendor. Do not run this file.` |
| `spec_signature_invalid`, form | legacy `Ed`, malformed sidecar or comment, unreadable sidecar | `error: the signature on acme-platform.yaml is not in the form rdy accepts.` | same fix |
| `spec_signature_invalid`, product | comment or metadata product differs | `error: acme-platform.yaml is signed for product 'acme-edge', but the spec says 'acme-platform'.` | same fix |
| any of the above, file has CRLF | | adds `The file has Windows line endings. If it went through Git or email, ask for the original.` | |
| `spec_expired` | `metadata.expires` has passed | `error: acme-platform.yaml expired on 2027-01-31. This machine's clock says 2027-02-03.` | `fix: ask the vendor for a current spec. If this machine's clock is wrong, set it and run again.` |
| `trust_store_insecure` | 4.3 | `error: /etc/rdy/trust.yaml is writable by other users` | `fix: chmod 644 /etc/rdy/trust.yaml` (Windows: `fix: run rdy trust add from an elevated prompt to recreate the store`) |

`spec_unreadable`, `spec_expired` and `trust_store_insecure` are new codes, added to ADR 0008's list
under ADR 0007's additive rule. One more ErrorOutput code is not about spec loading: `interrupted`
(exit 70, Ctrl-C in M1, 07 section 5.1). cli-ux proposed naming `--allow-unsigned` in the `spec_unsigned` fix line; security's
MF-01 forbids it, and security rules win.

## 5. The JSON result

Top level (`$defs/Report`). ADR 0012 decision 3 fixes the provenance fields; this doc names the rest.

| Field | Meaning |
| --- | --- |
| `api_version`, `kind` | `rdy/v1`, `Report` |
| `producer` | `name` (`rdy`), `version`, `commit`, `rdy_spec` (crate version), `target` (triple) |
| `run` | `id` (UUID v4), `started_at`, `finished_at` (UTC, milliseconds), `duration_ms`, `options` (`jobs`, `deadline_ms`, `allow_unsigned`, `network`, `kube_context`) |
| `spec` | `product`, `version`, `sha256` of the verified bytes, `file_name` (base name only), `size_bytes`, `serial`, `expires`, `contact`, `annotations` |
| `signature` | `state` (`verified`, `unsigned`), `key_id`, `key_fingerprint`, `product` and `signed_at` from the signed comment, `trust_note`, `trust_source` (`system`, `user`, `flag`) |
| `host` | 5.1 |
| `identity` | `euid`, `user`, `elevated`, `kube` (`context`, `server`, `user`, `user_verified`, `exec_plugin`, `insecure_tls`). `kube.user` is the authenticated user from `SelfSubjectReview` (ADR 0010 decision 2), with `user_verified: true`. When that API is missing (1.27 and older) or the call fails, it is the user entry named in the kubeconfig context with `user_verified: false`, shown as "not verified by the API server". `user_verified` is required whenever `kube` is an object. |
| `proxy` | proxy URLs in effect, user info stripped, and `no_proxy`; null when none |
| `capabilities` | each probed need: `need`, `name`, `available`, `detail`, `hint` (02) |
| `verdict`, `verdict_reason`, `exit_code` | 5.3 |
| `summary` | `total`, `pass`, `warn`, `block`, `skipped`, `timeout`, `error`, `not_applicable`, `required_not_run`, `optional_not_run` |
| `checks` | one result per spec entry, in spec order (5.2) |
| `actions`, `actions_truncated`, `actions_dropped` | the action log (5.4) |
| `redaction` | `ruleset` (`report`), `total`, `by_rule`: counts only, never matched text (04) |
| `complete`, `interrupted` | `complete: false` when rdy could not finish or write the report (exit 70); `interrupted: true` after Ctrl-C |

`signature.trust_note` is the local note from the trust store, never text from the spec (threat model
Surface 2, S1). `invalid` exists in the Rust `SignatureState` for `rdy verify` but never appears in a
written report. The schema checks two consistency rules: `unsigned` implies `allow_unsigned: true`, and
`ready` implies no blocks, warnings or checks not run.

**For scripts.** Stable: `verdict`, `verdict_reason`, `exit_code`, `complete`, `interrupted`,
`summary.*`, `checks[].key`, `.id`, `.severity`, `.status`, `.bucket`, `.skip_kind`, `.duration_ms`, and
`error.code`. Do not parse `message`, `fix`, `notes` or `observed` values as text: the words can change in
any release. `observed` and `expected` keys per check id are only ever added, and documented per check.
Summary arithmetic: `pass + warn + block + skipped + timeout + error = total`, where `skipped` counts every
`status: skipped` entry, not applicable included. `not_applicable`, `required_not_run` and
`optional_not_run` are views inside that sum, and the summary may gain keys, so never sum every key. A
test asserts both identities, and that bucket counts match the summary.

**Size caps in the schema.** `message` 1 KiB; `fix` and `builtin_fix` 4 KiB; `notes` 20 items of 1 KiB;
`actions` 5000 items; every other string 4 KiB; `observed` and `expected` 64 KiB each (prose, checked by
the writer). A string cut by a cap ends with ` [truncated]`, and the check's `truncated` flag is set. The whole document is at most 2 MiB, which the portal checks before it parses.

### 5.1 Host identity

Included: `hostname` (as the OS reports it; an M2 option replaces it), `host_id`, `os` (`family`, `id`,
`version`, `pretty_name`), `kernel`, `arch`, `virtualization` (`none`, `vm`, `unknown`), `container`
(rdy ran in a container or WSL). `identity` adds `euid`, the local login name and the kube identity (ADR
0012), so the reader knows who ran it and against which cluster, with any kubeconfig credential plugin
that ran and whether TLS verification was off.

`host_id` is the first 16 hex digits of HMAC-SHA256 over the OS machine id, keyed with
`rdy-host-id-v1` followed by the product (`/etc/machine-id` on Linux, `MachineGuid` on Windows). The
portal uses it to match a rerun to the same box; keying by product means two vendors cannot link one
host. On macOS it is `null` in M1: `kern.uuid` is the kernel build UUID, shared by every Mac on the same
build, and `IOPlatformUUID` needs an `ioreg` exec or IOKit FFI, which waits for a decision (Decisions
needing an ADR).

IP addresses appear only in check `observed` data, in the `connect.addr` field and in the `dns.server`
field of the action log. Never included: MAC addresses, environment values (except the proxy settings,
user info stripped), the command line, the working directory, home paths (action log paths under a home
directory start with `~`), kubeconfig contents and credentials, the raw machine id, hardware serial
numbers. The redactor runs over every string before write (threat model I1); its M1 coverage of each
field is in the security review's sensitive-field table.

### 5.2 Check results

Each entry: `key`, `id`, `name`, `family`, `severity`, `status`, `bucket`, `message` (one line), `fix`,
`fix_source` (`spec`, `rdy`; null on pass), `builtin_fix`, `observed`, `expected`, `needs`, `partial`,
`truncated`, `notes`, `started_ms` (offset from `run.started_at`), `duration_ms`. Status-specific:
`skip_kind` and `unsupported_fields` for `skipped`, `timeout_after_ms` for `timeout`, `error_kind`
(`check_failed`, `panic`) for `error`. `fix` is a non-empty string for every outcome except `pass` and
`not_applicable` (ADR 0008 decision 5); the schema enforces it.

**`bucket`** is the display group, computed by the same function as the verdict:

| `bucket` | Contains |
| --- | --- |
| `blocker` | `status: block` |
| `required_not_run` | `severity: block` (or unknown) and skipped (not `not_applicable`), timeout or error |
| `warning` | `status: warn`, and `severity: warn` checks that did not run |
| `passed` | `status: pass` |
| `not_applicable` | `skip_kind: not_applicable` |

Sort by `bucket` in the order above, then spec order. Do not recompute it. Terminal, HTML and portal all
use it.

`observed` holds measured values, `expected` the thresholds after defaults. Keys are snake_case per check
id with the unit in the name (`total_bytes`, `connect_ms`, `tolerance_percent`). `needs` lists each
declared need as `{need, name, hard, met}`. `partial` is `null` or `{missing: [needs], note}`; a partial
check never blocks on data it could not read (02, needs rule 4). Known needs: `root`, `kube_context`,
`network`, `command` (with `name`), `cloud_credentials` (provider as `name`, M3).

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

**Skip kinds and their words.** 02's `NeedsNewerRdy` is split three ways because the fix differs. The
`message` and `fix` are written for the customer, who reads the run; the kind names appear only in JSON.

| `skip_kind` | `message` | `fix` | Counts |
| --- | --- | --- | --- |
| `not_in_build` | `Not run. This version of rdy has no gpu checks yet.` (or "does not have the check host.kernel yet") | `Install a newer rdy. If there is none yet, ask the vendor how to go on.` | yes |
| `unknown_check` | `Not run. rdy 0.1.0 does not know the check 'host.memroy'.` (unreserved family: "No version of rdy has checks named upload.") | `Tell the vendor. The spec may have a typo (did you mean 'host.memory'?), or it may need a newer rdy than 0.1.0.` | yes |
| `unsupported_spec`, field | `Not run. rdy 0.1.0 cannot read 'mn' in host.memory.` | `Tell the vendor. The spec may have a typo (did you mean 'min'?), or it may need a newer rdy than 0.1.0.` | yes |
| `unsupported_spec`, value | `Not run. 'min: 32G' in host.memory is not a size.` | `Tell the vendor to write 32Gi, not 32G. Sizes use Ki, Mi, Gi or Ti.` | yes |
| `missing_need`, root | `Not run. This check needs root.` | `Rerun as root: sudo rdy run acme-platform.yaml` | yes |
| `missing_need`, cluster | `Not run. No Kubernetes cluster was reachable.` | `Set a kubeconfig, or pass --kube-context <name>, then run again.` | yes |
| `not_yet_on_os` | `Not run. This check does not work on macOS yet.` | `Run rdy on the machine you will install on.` | yes |
| `not_applicable` | `Does not apply here. This check is for linux only.` Only the spec's `os` list produces it. | none | **no** |
| `run_deadline` | `Not run. The run reached its 5 minute limit first.` | `Run again. If it happens again, tell the vendor.` | yes |
| `cancelled` | `Not run. The run was interrupted.` | `Run it again.` | yes |
| (status `timeout`) | `Timed out after 10 s.` | `Run again. If it times out again, tell the vendor which check it was.` | yes |

**Only the spec's `os` list produces `not_applicable`** (02, after its security review). A check whose
concept does not exist on this OS (SELinux on Windows) is `not_yet_on_os` and counts as not run, so a
vendor can never hide a required check by accident; a cross-platform spec says `os: [linux]` on it.
Section 7.4 has a JSON sample of each harder case.

### 5.3 The verdict rule and the summary line

```text
not_run(c)  = (c.status == skipped and c.skip_kind != not_applicable)
              or c.status in {timeout, error, <unknown>}
required(c) = c.severity != warn          # unreadable or unknown severity counts as block

not_ready            if any c.status == block, or any c is required and not_run
ready_with_warnings  else if any c.status == warn, or any c is not required and not_run,
                     or no check reached pass, warn or block (nothing_verified)
ready                otherwise
```

**Confirmed: a `severity: block` check that did not run makes the verdict NOT READY, exit 2, and is
counted apart as "required check not run"**, as cli-ux proposed and ADR 0008 decision 3 now says. A false
READY is the worst failure this tool can have and a false NOT READY costs one rerun; exit 1 means
"warnings only" and a `[ $? -le 1 ]` gate would pass an unchecked environment; and only the vendor may
relax a requirement. Refinements: timeout and error count as not run (02); `not_applicable`, which only
the spec's `os` list produces, never counts (02); a run that verified nothing is at least READY with warnings (02); an unknown severity counts as
block and an unknown status as not run (this doc). 02 lists a ticket to record these in ADR 0013.

`verdict_reason` is `required_check_not_run` when the verdict is `not_ready` with no observed block,
`nothing_verified` as above, otherwise null. `exit_code` is the verdict's code; if rdy cannot write the
report it exits 70 and the JSON it still prints has `complete: false`.

**Summary line grammar** (cli-ux, for 07 to copy). Always `<n> block(s), <n> warning(s), <n> passed`.
Then, only when above zero and in this order: `<n> required check(s) not run`, `<n> optional check(s) not
run`, `<n> not applicable`. Singular for one. When a timeout or error is inside a not-run count, add
`(1 timed out)` or `(1 failed)` after it.

| Case | Last line |
| --- | --- |
| any block | `NOT READY` |
| no block, required checks not run | `NOT READY: 1 required check was not run` / `NOT READY: 2 required checks were not run` |
| warnings or optional checks not run | `READY with warnings` |
| `nothing_verified` | `READY with warnings: nothing was checked` |
| all passed | `READY` |

```text
2 blocks, 1 warning, 3 passed, 2 required checks not run
NOT READY
```

```text
0 blocks, 0 warnings, 5 passed, 1 optional check not run, 2 not applicable
READY with warnings
```

```text
0 blocks, 0 warnings, 0 passed, 3 not applicable
READY with warnings: nothing was checked
```

### 5.4 The action log

Threat model R1 and INV-07: every side effect goes through the probe facade, which appends one entry
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

Every string passes the redactor. Bodies are never recorded. **Retention:** `exec`, `connect`, `tls`,
`http`, `dns`, `lookup` and `kube` entries are never dropped; they are bounded already by the 256 host and
port pairs a spec may name (2.1) and the fixed command set. When the log reaches 5000 entries, or the document its size cap, `read`,
`read_dir` and `stat` entries are dropped first, `actions_truncated` is true, and `actions_dropped` gives
a count per kind. `rdy run --plan` (M2) prints the same shape before running.

### 5.5 Writer rules

- UTF-8, no BOM, LF, two-space indent, fields in schema order, trailing newline. Deterministic for a
  given `Report`, so golden files are exact.
- `<`, `>` and `&` are written as the JSON escapes `\u003c`, `\u003e`, `\u0026` (ADR 0003 decision 4), in
  the `.json` file too. The file, `--json` on stdout and the copy embedded in the HTML are the same bytes.
- The writer returns an `HtmlSafeJson` newtype, built only by the writer, which guarantees there is no
  `<`, `>` or `&`. It is the only value templates render unescaped; a CI grep keeps `|safe` out of every
  template. Without it askama would escape `"` and break both the JSON and the hash.
- Size: target under 1 MiB, hard cap 2 MiB, with the action log retention rule of 5.4 and lists inside
  `observed` cut to 200 items with `truncated: true`.
- Location (ADR 0003): a new directory `rdy-report-<product>-<YYYYMMDDTHHMMSSZ>/` holding
  `rdy-report-<product>-<ts>.json`, `.html`, and a copy of the verified spec and its `.minisig` from the
  same buffers (02). The `Report written to` line names all four files.

## 6. The HTML report contract

The report is the demo, and security reviewers read its renderer (CLAUDE.md rule 7). ADR 0003 sets the
technology; this is what the file must contain and guarantee.

**Data.** Rendered only from the `Report` value that produced the JSON, plus the static template. The
renderer reads no files, environment or clock. `rdy report <result.json>` (M2) runs the redactor on input
it did not produce, then renders; for input written by rdy the output is the same bytes.

**One self-contained file.** Inline CSS, no JavaScript in M1, system fonts, one inline SVG logo, nothing
that loads on open. CSP meta `default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri
'none'; form-action 'none'` (ADR 0003). No `<details>` elements: a closed one does not print. `<title>`
is `rdy report: acme-platform, NOT READY`, so the tab, history and printed header read right.

**Embedded JSON.** `<script type="application/json" id="rdy-result" data-sha256="<hex>">` holds the
`HtmlSafeJson` bytes, which equal the `.json` file. The portal imports an HTML file by extracting this
element, treats it as untrusted input, validates it against `result.v1.schema.json`, labels it
customer-reported, and can compare `data-sha256` with a JSON upload. The JSON file stays the supported
upload.

**Content, in this order** (ADR 0003 decision 6, 02 renderers, cli-ux labels):

1. The UNSIGNED SPEC or KEY NOT PINNED banner, by the 4.7 rule. It comes first, as in the terminal.
2. Header: "For acme-platform >=4.2", "Spec revision 7" when `serial` is set, the verdict word, the summary
   line (5.3), run time in UTC, hostname. Below it the legend: "BLOCK: fix before install. WARN: fix if you
   can. SKIP: rdy could not check it." and the rule in plain words: "NOT READY if anything blocks or a
   required check could not run. READY with warnings if only optional things are wrong. READY if every
   check ran and passed." The same three sentences are in `rdy run --help`.
3. "This file lists hostnames and addresses from this machine. Read it before you send it."
4. Sections by `bucket`: **Blocks**, **Required checks not run**, **Warnings**, **Passed**, **Does not
   apply here**. Each check shows its status word, `id (name)`, message, fix with its label (2.6) and "More
   from rdy" below a vendor fix, Found against Needed, what it requires and whether that was available,
   any partial note, and duration.
5. What rdy could use on this machine (capabilities), with hints.
6. Run and spec details: rdy version and target, run id, options, spec file name, SHA-256, signature state,
   signing key and fingerprint, your note about this key, signed on, spec revision, expiry, contact;
   identity (including any kubeconfig credential plugin and skipped TLS verification) and proxy.
7. What rdy read and contacted (the action log), a plain table, first 1000 rows, then "N more entries are
   in the embedded JSON".
8. Footer: a plain link to `https://getrdy.io/?ref=report&product=<product>` with
   `rel="noopener noreferrer"`, the rdy version and the source repository. Nothing loads unless clicked.

**Labels.** No raw JSON key or engine word is visible text (CI grep on the template):

| Engine word | Visible label |
| --- | --- |
| needs, with `met` | `Requires: root (not available)` or `Requires: root (available)` |
| capabilities | `What rdy could use on this machine` |
| partial | `Checked in part. Could not read: <list>. The result may be incomplete.` |
| action log | `What rdy read and contacted` |
| observed, expected | `Found`, `Needed` |
| `fix_source` | `From acme-platform` (verified and pinned only) or `From the spec file (not verified)`; `From rdy`; `More from rdy` for `builtin_fix` |
| key id, fingerprint, trust note | `Signing key`, `Fingerprint`, `Your note about this key` |
| `signed_at`, `serial` | `Signed on`, `Spec revision` |
| `host_id` | `Machine ID (hashed, differs per vendor)` |
| `severity: block` on a SKIP | `required by acme-platform` (or `required by the spec file` when not verified) |
| skip kinds | `Not in this version of rdy`, `rdy cannot read this check`, `Missing: root`, `Not available on this OS yet`, `Does not apply here`, `Run time limit reached`, `Run was interrupted` |

**Found and Needed.** Both objects render as two key-value tables with no per-check code: keys are
humanised (`total_bytes` becomes "total"), `_bytes` values print as sizes, `_ms` as milliseconds,
`_percent` with `%`, nested lists one per line. The one-line `message` stays the headline.

**Text safety.** Every string from the spec or host is HTML-escaped by askama, control characters
stripped. No string from data becomes a link; `contact` and URLs show as text.

**Size.** Hard cap 5 MiB, typical under 300 KiB. Past the cap the action table is cut to the rows that
fit and ends with the "N more entries" line; checks are never cut.

**Print and dark mode.** `prefers-color-scheme` drives dark mode on screen, with `<meta
name="color-scheme" content="light dark">` so it applies before first paint. `@media print` sets
`color-scheme: light`, black text on white, no backgrounds, whatever the screen theme. The banner is a
`position: fixed` block in print so it repeats on every page. Page breaks come only before Passed, the
capabilities section and the action log, so the verdict, the blocks and the required checks not run share
page one. Exit test: rendered with dark preferred and print media, text contrast is at least 4.5 to 1.

**Accessibility.** `<html lang="en">`, headings in order, every status as a word (colour is never the
only signal), WCAG AA contrast in both themes, table headers with `scope`.

## 7. Examples

### 7.1 Spec, signature and trust entry

The spec is `examples/specs/acme-platform.yaml` exactly as of 2026-10-28 (SHA-256
`231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f`, 1988 bytes). `gpu.cuda` and `aws.iam` are reserved ids not in an M1 build, so this spec
cannot reach READY until the cloud family (M3) and the gpu family (M4) ship. Its header says so.

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
    access_modes: ["ReadWriteOnce"]
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
`trust_source: system`, so neither shows a banner.

### 7.2 NOT READY run (rdy 0.1.0, M1)

A RHEL 9 VM with 16 GB of RAM behind a proxy that does not allow the license host, run as a normal user
with a kubeconfig. `identity.kube.user` comes from `SelfSubjectReview` (`user_verified: true`). Two
blocks, one warning, two required checks not run, exit 2. The terminal ends with
`2 blocks, 1 warning, 3 passed, 2 required checks not run` and `NOT READY`. `verdict_reason` is null
because blocks were observed.

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
    "started_at": "2026-12-01T14:30:05.000Z",
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
      "user": "acme-installer",
      "user_verified": true,
      "exec_plugin": null,
      "insecure_tls": false
    }
  },
  "proxy": {
    "https": "http://proxy.corp.example:3128",
    "http": "http://proxy.corp.example:3128",
    "no_proxy": [".corp.example", "10.0.0.0/8"]
  },
  "capabilities": [
    {"need": "kube_context", "name": null, "available": true, "detail": "context acme-staging at https://api.k8s.acme.example:6443, kubeconfig user acme-installer", "hint": null},
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
      "bucket": "passed",
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
      "bucket": "blocker",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "required_not_run",
      "skip_kind": "not_in_build",
      "message": "Not run. This version of rdy has no gpu checks yet.",
      "fix": "Install a newer rdy. If there is none yet, ask the vendor how to go on.",
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
      "bucket": "required_not_run",
      "skip_kind": "not_in_build",
      "message": "Not run. This version of rdy has no aws checks yet.",
      "fix": "Install a newer rdy. If there is none yet, ask the vendor how to go on.",
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
    {"seq": 3, "check": "host.cpu", "at_ms": 41, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/cpuinfo", "bytes": 8320, "truncated": false},
    {"seq": 4, "check": "host.cpu", "at_ms": 41, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/cpu.max", "bytes": 13, "truncated": false},
    {"seq": 5, "check": "host.memory", "at_ms": 41, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/meminfo", "bytes": 1482, "truncated": false},
    {"seq": 6, "check": "host.memory", "at_ms": 42, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/memory.max", "bytes": 4, "truncated": false},
    {"seq": 7, "check": "host.disk", "at_ms": 42, "duration_ms": 1, "kind": "read", "outcome": "ok", "path": "/proc/self/mountinfo", "bytes": 2870, "truncated": false},
    {"seq": 8, "check": "net.egress", "at_ms": 42, "duration_ms": 2, "kind": "lookup", "outcome": "ok", "host": "proxy.corp.example", "answers": 1},
    {"seq": 9, "check": "host.disk", "at_ms": 43, "duration_ms": 0, "kind": "native", "outcome": "ok", "api": "statvfs", "path": "/var/lib"},
    {"seq": 10, "check": "k8s.version", "at_ms": 43, "duration_ms": 48, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/version", "status": 200},
    {"seq": 11, "check": "k8s.storageclass", "at_ms": 44, "duration_ms": 52, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/storageclasses", "status": 200},
    {"seq": 12, "check": "net.egress", "at_ms": 45, "duration_ms": 36, "kind": "connect", "outcome": "ok", "host": "registry.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128"},
    {"seq": 13, "check": "net.egress", "at_ms": 82, "duration_ms": 61, "kind": "tls", "outcome": "ok", "host": "registry.acme.example", "sni": "registry.acme.example"},
    {"seq": 14, "check": "k8s.storageclass", "at_ms": 96, "duration_ms": 43, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/csidrivers", "status": 200},
    {"seq": 15, "check": "net.egress", "at_ms": 144, "duration_ms": 37, "kind": "connect", "outcome": "failed", "host": "license.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128", "error": "proxy answered 403 to CONNECT"}
  ],
  "actions_truncated": false,
  "actions_dropped": {},
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
    "started_at": "2027-04-12T09:15:40.000Z",
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
      "user": "acme-installer",
      "user_verified": true,
      "exec_plugin": null,
      "insecure_tls": false
    }
  },
  "proxy": {
    "https": "http://proxy.corp.example:3128",
    "http": "http://proxy.corp.example:3128",
    "no_proxy": [".corp.example", "10.0.0.0/8"]
  },
  "capabilities": [
    {"need": "root", "name": null, "available": true, "detail": "uid 0", "hint": null},
    {"need": "kube_context", "name": null, "available": true, "detail": "context acme-staging at https://api.k8s.acme.example:6443, kubeconfig user acme-installer", "hint": null},
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
      "bucket": "passed",
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
    {"seq": 3, "check": null, "at_ms": 36, "duration_ms": 120, "kind": "http", "outcome": "ok", "method": "POST", "url": "https://sts.us-east-1.amazonaws.com/", "status": 200},
    {"seq": 4, "check": "host.cpu", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/cpuinfo", "bytes": 16640, "truncated": false},
    {"seq": 5, "check": "host.cpu", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/cpu.max", "bytes": 13, "truncated": false},
    {"seq": 6, "check": "host.memory", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/proc/meminfo", "bytes": 1482, "truncated": false},
    {"seq": 7, "check": "host.memory", "at_ms": 52, "duration_ms": 0, "kind": "read", "outcome": "ok", "path": "/sys/fs/cgroup/memory.max", "bytes": 4, "truncated": false},
    {
      "seq": 8,
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
    {"seq": 9, "check": "aws.iam", "at_ms": 52, "duration_ms": 810, "kind": "http", "outcome": "ok", "method": "POST", "url": "https://iam.amazonaws.com/", "status": 200},
    {"seq": 10, "check": "host.disk", "at_ms": 53, "duration_ms": 1, "kind": "read", "outcome": "ok", "path": "/proc/self/mountinfo", "bytes": 3110, "truncated": false},
    {"seq": 11, "check": "net.egress", "at_ms": 53, "duration_ms": 2, "kind": "lookup", "outcome": "ok", "host": "proxy.corp.example", "answers": 1},
    {"seq": 12, "check": "host.disk", "at_ms": 54, "duration_ms": 0, "kind": "native", "outcome": "ok", "api": "statvfs", "path": "/var/lib"},
    {"seq": 13, "check": "k8s.version", "at_ms": 54, "duration_ms": 44, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/version", "status": 200},
    {"seq": 14, "check": "k8s.storageclass", "at_ms": 54, "duration_ms": 48, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/storageclasses", "status": 200},
    {"seq": 15, "check": "net.egress", "at_ms": 55, "duration_ms": 35, "kind": "connect", "outcome": "ok", "host": "registry.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128"},
    {"seq": 16, "check": "net.egress", "at_ms": 90, "duration_ms": 58, "kind": "tls", "outcome": "ok", "host": "registry.acme.example", "sni": "registry.acme.example"},
    {"seq": 17, "check": "k8s.storageclass", "at_ms": 102, "duration_ms": 40, "kind": "kube", "outcome": "ok", "method": "GET", "path": "/apis/storage.k8s.io/v1/csidrivers", "status": 200},
    {"seq": 18, "check": "net.egress", "at_ms": 148, "duration_ms": 36, "kind": "connect", "outcome": "ok", "host": "license.acme.example", "port": 443, "addr": null, "via_proxy": "http://proxy.corp.example:3128"},
    {"seq": 19, "check": "net.egress", "at_ms": 186, "duration_ms": 60, "kind": "tls", "outcome": "ok", "host": "license.acme.example", "sni": "license.acme.example"}
  ],
  "actions_truncated": false,
  "actions_dropped": {},
  "redaction": {"ruleset": "report", "total": 0, "by_rule": {}},
  "complete": true,
  "interrupted": false
}
```

### 7.4 Check results for the harder cases

One entry each for a missing need, a timeout, an unknown id, a bad value and a not-applicable check,
from other runs. Each validates against `$defs/CheckResult`.

```json
[
  {
    "key": "host.ports",
    "id": "host.ports",
    "name": null,
    "family": "host",
    "severity": "block",
    "status": "skipped",
    "bucket": "required_not_run",
    "skip_kind": "missing_need",
    "message": "Not run. This check needs root.",
    "fix": "Rerun as root: sudo rdy run acme-platform.yaml",
    "fix_source": "rdy",
    "observed": null,
    "expected": null,
    "needs": [{"need": "root", "name": null, "hard": true, "met": false}],
    "partial": null,
    "truncated": false,
    "notes": [],
    "started_ms": 40,
    "duration_ms": 0
  },
  {
    "key": "net.dns",
    "id": "net.dns",
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
    "expected": null,
    "needs": [{"need": "network", "name": null, "hard": true, "met": true}],
    "partial": null,
    "truncated": false,
    "notes": [],
    "started_ms": 40,
    "duration_ms": 10000
  },
  {
    "key": "host.memroy",
    "id": "host.memroy",
    "name": null,
    "family": "host",
    "severity": "block",
    "status": "skipped",
    "bucket": "required_not_run",
    "skip_kind": "unknown_check",
    "message": "Not run. rdy 0.1.0 does not know the check 'host.memroy'.",
    "fix": "Tell the vendor. The spec may have a typo (did you mean 'host.memory'?), or it may need a newer rdy than 0.1.0.",
    "fix_source": "rdy",
    "observed": null,
    "expected": null,
    "needs": [],
    "partial": null,
    "truncated": false,
    "notes": [],
    "started_ms": 40,
    "duration_ms": 0
  },
  {
    "key": "host.memory",
    "id": "host.memory",
    "name": null,
    "family": "host",
    "severity": "block",
    "status": "skipped",
    "bucket": "required_not_run",
    "skip_kind": "unsupported_spec",
    "unsupported_fields": ["min"],
    "message": "Not run. 'min: 32G' in host.memory is not a size.",
    "fix": "Tell the vendor to write 32Gi, not 32G. Sizes use Ki, Mi, Gi or Ti.",
    "fix_source": "rdy",
    "observed": null,
    "expected": null,
    "needs": [],
    "partial": null,
    "truncated": false,
    "notes": [],
    "started_ms": 40,
    "duration_ms": 0
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
    "started_ms": 40,
    "duration_ms": 0
  }
]
```

All blocks above validate against the schema files with a draft 2020-12 validator (checked
2026-10-28), and so does every file in `examples/specs/`.

## Plan corrections found

- docs/adr/0012, decision 5: names the files `rdy-v1-spec.schema.json` and `rdy-v1-result.schema.json`.
  The kickoff task and this doc use `spec.v1.schema.json` and `result.v1.schema.json`, and 09-docs-site.md
  takes its names from this doc. Fix: change ADR 0012 to these names.
- docs/adr/0012, decision 3: lists `redactions: u32`. Fix: `redaction { ruleset, total, by_rule }`
  (04), and add `signature.key_fingerprint` (security SF-02).
- docs/adr/0010, decision 2: the guard allows POST only to `selfsubjectaccessreviews` and
  `selfsubjectrulesreviews`, while decision 4 reads the user from `SelfSubjectReview`. Fix: add
  `selfsubjectreviews`, as threat model "Kubernetes read-only rule" already does. Until then this doc's
  examples take `identity.kube.user` from the kubeconfig and make no such call (02 agrees).
- docs/adr/0008, decision 2: unknown fields are lint warnings, and the sample reason reads "(needs a newer
  rdy, or a typo)". Fix: lint and sign treat `unsupported_spec` and `unknown_check` as errors (both reviews),
  and the skip wording is the customer-facing text of 5.2.
- docs/adr/0008, decision 3: no `not_applicable` exception, nothing-verified rule, or unknown severity and
  status rules. Fix: the ADR 0013 ticket in 02 records all four. Decision 7: add `spec_expired`,
  `trust_store_insecure`, and the `file`, `line`, `column` fields of `ErrorOutput`.
- docs/adr/0003, decisions 1 and 4: add the spec and `.minisig` copies in the report directory,
  `data-sha256`, `<title>`, the 2 MiB and 5 MiB caps and the `HtmlSafeJson` exception (cli-ux S9,
  security SF-08).
- docs/adr/0002, decisions 4 and 5: add the fingerprint identity, the Windows ACL rules, "root never
  touches a user path", and the KEY NOT PINNED banner for `--key` (security MF-02, MF-03, MF-05, SF-02).
- docs/plan/02-engine-design.md, Scheduling: per-check timeout `min(spec timeout, CheckInfo::default_timeout,
  60 s, time left)`. Fix: `min(spec or default, 60 s, time left)`, so a vendor can raise a slow check's
  limit (cli-ux S4). Also: action log "collapsed per check" becomes a plain table (no `<details>`), the
  renderers sort by `bucket`, `Summary::not_run` is `optional_not_run`, `summary.skipped` includes not
  applicable, and `NeedsNewerRdy` splits into `not_in_build`, `unknown_check`, `unsupported_spec`.
- docs/plan/02-engine-design.md, Report renderers: "escaped as `<`, `>` and `&`" lost its escapes. Fix:
  `\u003c`, `\u003e`, `\u0026`.
- docs/plan/04-bundle-and-redaction.md, section 3.1: overlapping spans keep the highest priority. Fix: the
  span-union rule of 2.8 (security MF-04). Its M2 ticket "Spec and CLI additions: bundle.redact_patterns,
  bundle.max_size and --redact-pattern" keeps only the CLI and redactor work; the spec fields are in
  revision 0.
- docs/plan/05-threat-model.md, INV-06: unknown ids and fields "cap the verdict at Warnings". Fix: "count
  as required checks not run" (security accepted). Surface 2: drop `--trust-key` (security accepted).
- docs/plan/03-check-catalog.md, Thresholds: `host.cpu` `min_cores`, `recommended_cores` are `min`,
  `recommended`; `host.disk` `paths: [...]` is one `path` per entry with `min`, `recommended`, `min_inodes`,
  `forbid_options`, `forbid_fstypes`; `host.memory` `band` is `tolerance_percent` and `swap: off` is
  `forbid`; `k8s.version` `max_severity` is `over_max`; `k8s.admission` `needs_pod_security` is
  `pod_security`, and `dry_run`, `probe_pod` wait for ADR 0010; `k8s.nodes` drops the `nodes:` wrapper;
  `net.dns` `max_ms` is `max_latency`; the `net.egress` object uses `target`, not `url`. Fix: align the
  catalog with 2.7.
- docs/plan/rdy-plan.md, example spec: `needs: ["ReadWriteOnce"]` is `access_modes` now that the alias is
  gone (cli-ux S1).
- CLAUDE.md, Commands: `rdy run examples/specs/acme-platform.yaml --json` exits 64 (`spec_unsigned`) since
  no example ships a `.minisig`. Fix: add `--allow-unsigned` there now, and ship signed examples with a
  synthetic demo key in M2 (cli-ux S16). Rule 3 still says the flag runs tampered specs; ADR 0002 decision
  7 is right.
- Disagreements kept, with reasons. cli-ux S4 asks that a timeout out of range exit 64 at load; cli-ux M1
  and security N-08 say a bad value inside a check skips it. I kept the skip at run time (a newer spec on
  an older rdy must fail closed per check, not stop the run) and made it an error in lint and sign. cli-ux
  S7 asks the `spec_unsigned` fix to name `--allow-unsigned`; security MF-01 forbids that, and security
  wins.

## Decisions needing an ADR

- `rdy trust add --fingerprint <sha256>` (ADR 0002 amendment), so a swapped key fails without a human
  comparing hex. Conservative choice until decided: `spec keygen` and `spec sign` print the fingerprint,
  and `trust add` asks the user to compare it.
- macOS `host_id` source: an `ioreg` exec, IOKit FFI (unsafe, INV-18), or `null`. Conservative choice:
  `null` in M1.
- Moving the `jwt` redaction rule from M2 into M1 (04 owns it): a bare service account token in a kube
  error string is caught by no M1 rule. Conservative choice: add it to the M1 rule ticket, about 1h.

## Tickets implied

Titles reused from ADRs, 00-overview, 02 and the two reviews are kept exactly so 11-backlog.md can dedupe.

- [M1] Define public spec types in rdy-spec | owner: rust-engineer | est: 3h | depends on: Create workspace skeleton | exit test: every file in examples/specs decodes into Spec with typed common fields, and the metadata fields of 2.2 round-trip through serde_json.
- [M1] Two-step check decoding with Unknown and Unsupported variants | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: `gpu.cuda` decodes to Unknown, `host.memory` with `mn` to Unsupported naming `mn`, and a missing id or duplicate entry key is a SpecError with line and column.
- [M1] Reserved check ids and sign-refuses-on-typos rule | owner: rust-engineer | est: 2h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: `host.kernel` lints as not_in_build, `mn: 32Gi`, `min: 32G` and `host.memroy` make `spec sign` refuse with a fix, and a `gpu.cuda` entry only warns.
- [M1] Scalar types Quantity, Duration, Version and Target with strict grammars | owner: rust-engineer | est: 2h | depends on: Define public spec types in rdy-spec | exit test: unit tests reject `32G`, unquoted `1.30`, `10 s`, `host:99999` and `https://u:p@host/`, and accept `32Gi`, `"1.30"`, `14`, `7d` and `[::1]:443`.
- [M1] SEC-62 Parser rejects tags, directives and non-finite floats | owner: rust-engineer | est: 1h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: `!!binary`, `!custom`, `%YAML 1.1`, `.inf` and `.nan` fixtures each exit 64 with line and column.
- [M1] Typed parameters for M1 host check ids | owner: rust-engineer | est: 3h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: every host id in 2.7 decodes from a fixture covering each field, each field has a rejecting case, and a missing required threshold is Unsupported.
- [M1] Typed parameters for M1 net and k8s check ids | owner: rust-engineer | est: 4h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: acme-platform.yaml and acme-k8s-only.yaml decode, `needs` on k8s.storageclass is Unsupported, and every net and k8s id in 2.7 has an accepting and a rejecting fixture.
- [M1] Semantic validation and structural limits for specs | owner: rust-engineer | est: 2h | depends on: Two-step check decoding with Unknown and Unsupported variants | exit test: fixtures for 257 checks, 65 endpoints, a duplicate key, a bad product, an unknown metadata key, an unknown bundle key and a relative `file:` collector each exit 64 with the 2.5 wording.
- [M1] Spec expiry and serial in metadata | owner: rust-engineer | est: 1h | depends on: Semantic validation and structural limits for specs | exit test: an expired fixture exits 64 with spec_expired, both dates in the first line, before any check runs.
- [M1] Write the spec error and skip message table into 01-spec-format and rdy-spec hints | owner: rust-architect | est: 2h | depends on: none | exit test: done in this revision; a unit test asserts every SpecError and skip kind has the 2.5 or 5.2 message and a non-empty fix.
- [M1] rdy spec lint with errors, warnings and did-you-mean | owner: rust-engineer | est: 3h | depends on: Reserved check ids and sign-refuses-on-typos rule | exit test: lint exits 1 on acme-platform.yaml with two not_in_build warnings, 2 on `mn: 32Gi` with "did you mean min" and its line, and `--json` output validates as LintReport.
- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: the 7.2, 7.3 and 7.4 samples round-trip byte for byte, and unit tests cover every line of 5.3 including not_applicable, nothing_verified, unknown severity and unknown status.
- [M1] Add `bucket` to CheckResult and sort by it in terminal and HTML | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture with every outcome sorts blocker, required_not_run, warning, passed, not_applicable and the bucket counts equal the summary.
- [M1] Summary line grammar and nothing-verified last line | owner: rust-engineer | est: 1.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: golden strings for the three samples in 5.3, each last line in its table, and singular and plural forms pass.
- [M1] Host identity and host_id derivation | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture machine id gives the documented HMAC host_id, another product gives a different one, macOS gives null, and a fixture run's JSON has no MAC, home path or environment value.
- [M1] SEC-63 Result schema caps, identity.kube exec plugin and action log retention | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a 5 MiB message fails the result schema, an exec plugin shows in JSON and HTML, and a 300-check flood keeps every connect and kube entry with actions_dropped counts.
- [M1] HTML-safe deterministic JSON writer with size caps | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a hostname with `</script>` is written as `\u003c/script\u003e`, and the .json file, --json stdout and the HTML copy hash the same.
- [M1] SEC-64 HtmlSafeJson as the only unescaped template value | owner: rust-engineer | est: 1h | depends on: HTML-safe deterministic JSON writer with size caps | exit test: CI fails on any `|safe` in templates, and the golden HTML's data-sha256 equals the SHA-256 of the golden .json.
- [M1] HTML print override, labels and legend | owner: rust-engineer | est: 2h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a headless render with dark preferred and print media has text contrast at least 4.5 to 1, and a template grep finds no raw JSON key as visible text.
- [M1] Validate hand-written schemas against examples in CI | owner: rust-engineer | est: 2h | depends on: Create workspace skeleton | exit test: CI validates every file in examples/specs, the 7.x samples and every golden result with a 2020-12 validator, and the hostile fixtures of both reviews give the documented accept or reject.
- [M1] Generate JSON schemas with schemars and check drift in CI | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: the generated files accept and reject the same fixtures as the hand-written ones, replace them, and a schema description containing "ADR" or a milestone name fails CI.
- [M1] Forward-compatibility fixtures for results | owner: rust-engineer | est: 1h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a result with an extra top-level field, status "quarantined" and bucket "frozen" deserializes, maps both to Unknown and keeps its recorded verdict.
- [M1] Verify minisign signatures in rdy-spec against a trust store with product binding | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: a tampered byte, a changed comment, a legacy Ed signature, a missing prefix, a product mismatch and an unpinned key each fail before the YAML is parsed, and Wycheproof vectors pass.
- [M1] SEC-61 Single-buffer spec load and key fingerprints | owner: rust-engineer | est: 2h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: a file swapped after the first read does not change the parsed, hashed or copied bytes, a forged key with the vendor's key id fails, and the result carries signature.key_fingerprint.
- [M1] Trust store load and save in user and system locations | owner: rust-engineer | est: 3h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: as root only /etc/rdy/trust.yaml is read, as a user the user file then the system file, and symlinked, non-root-owned or group-writable files exit 64 with trust_store_insecure.
- [M1] SEC-60 Root trust lookup touches no user path, Windows store ACL rules | owner: rust-engineer | est: 3h | depends on: Trust store load and save in user and system locations | exit test: a root run under strace opens no path under SUDO_USER's home, and on Windows CI a ProgramData\rdy directory created by a non-admin user, or with a Users write ACE, exits 64 with trust_store_insecure.
- [M1] rdy spec keygen and rdy spec sign | owner: rust-engineer | est: 4h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: an rdy signature verifies with stock minisign and the reverse with the 4.2 comment; sign refuses a lint error and a key readable by others, and prints the fingerprint.
- [M1] rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | owner: rust-engineer | est: 3.5h | depends on: rdy spec keygen and rdy spec sign | exit test: every code in 4.8 comes from a fixture, `--allow-unsigned` still exits 64 for an unpinned key, an invalid signature and a permission-denied sidecar, and no ErrorOutput.fix or stderr line contains `--allow-unsigned`.
- [M1] SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | owner: rust-engineer | est: 1.5h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: both 4.7 banners match byte for byte, a `--key` run prints KEY NOT PINNED on stderr and every HTML page, and the fix label reads "From the spec file (not verified)" for unsigned and flag-key runs.
- [M1] Apply the example spec edits in this review and re-sign the sample | owner: rust-architect | est: 1.5h | depends on: none | exit test: done in this revision; every file in examples/specs validates and the 7.1 SHA-256 matches the file.
- [M1] Align the check catalog with 01-spec-format names | owner: rust-architect | est: 1h | depends on: none | exit test: 03-check-catalog.md uses the parameter names of 2.7.
- [M1] Apply 01-spec-format corrections to ADRs 0002, 0003, 0008, 0010, 0012 and 00-overview | owner: rust-architect | est: 2h | depends on: none | exit test: every Plan corrections bullet above is applied or answered in a review file.
- [M2] Bundle block strict validation in rdy bundle | owner: rust-engineer | est: 3h | depends on: rdy-bundle: collectors, redactors, tar plus zstd, manifest | exit test: an unknown redactor or collector kind refuses to build a bundle with a fix line.
- [M2] SEC-65 Redaction span union with hostile custom patterns | owner: rust-engineer | est: 3h | depends on: SEC-44 Full redaction corpus with chunk-boundary cases | exit test: every built-in positive in the corpus, run with custom patterns `@`, `.`, the first secret byte and the key name, has zero survivors.
- [M2] SEC-66 rdy bundle ignores spec collectors unless the spec is verified with a pinned key | owner: rust-engineer | est: 1h | depends on: SEC-43 Bundle collector path policy | exit test: an unsigned or --key spec with `collect: ["file:/etc/acme/*"]` builds a bundle from the built-in set only and says so.
- [M2] Warn on spec serial rollback | owner: rust-engineer | est: 3h | depends on: Spec expiry and serial in metadata | exit test: running serial 6 after serial 7 for the same product warns and records it in the result.
- [M2] Option to replace the hostname in reports | owner: rust-engineer | est: 2h | depends on: Host identity and host_id derivation | exit test: with the option set no report file contains the real hostname and host_id is unchanged.
- [M2] TTY confirmation for unsigned specs | owner: rust-engineer | est: 1h | depends on: SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | exit test: on a pty, answering no exits 64 for both banners; without a TTY the flag alone runs.
- [M2] Signed demo key and signed example specs for the quickstart | owner: devrel | est: 2h | depends on: rdy spec keygen and rdy spec sign | exit test: the README quickstart runs on a clean machine with `rdy trust add` and no flags beyond the file name.
- [M2] Portal import of HTML reports via the embedded JSON | owner: rust-engineer | est: 4h | depends on: First crates.io release of rdy-spec and rdy-engine for rdy-cloud | exit test: rdy-cloud imports a golden HTML report, rejects one whose embedded JSON fails the schema, and labels it customer-reported.
- [M2] k8s.admission dry-run parameters after the ADR 0010 amendment | owner: rust-engineer | est: 2h | depends on: none | exit test: `dry_run` and `probe_pod` decode, appear in the schema revision table, and are refused at run time if the guard does not allow the call.
- [M3] Freeze rdy/v1 for the 1.0 release of rdy-spec | owner: rust-architect | est: 3h | depends on: none | exit test: schema files, golden results and this doc agree, and schema/README.md lists every revision since 0.1.
