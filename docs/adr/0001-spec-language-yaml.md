# ADR 0001: Spec language is YAML, parsed with serde-saphyr

- Status: Accepted (revised 2026-10-28 after security-reviewer review)
- Date: 2026-10-27

## Context

Vendors write a readiness spec once and send it to many customers. The audience is sales engineers and
DevOps people who already write Kubernetes manifests and Helm values. The plan's example spec is YAML
with `apiVersion: rdy/v1` and `kind: Readiness`. The parser runs as root on customer machines. Since
ADR 0002 verifies the signature before parsing, partner runs parse only verified bytes, but `spec lint`,
`--allow-unsigned` and portal authoring still parse untrusted input. So the parser must not panic, must
bound memory and time, and must carry as little unsafe code as we can manage.

The plan names `serde_yaml`. Its author deprecated and archived it in March 2024 (last release
`0.9.34+deprecated`). The best-known successor, `serde_yml`, is archived and covered by RUSTSEC-2025-0068
(unsound `libyml`). `serde_yaml_ng` and `serde_norway` are maintained forks, but both still sit on
`unsafe-libyaml`, a machine translation of C libyaml with a large unsafe surface.

## Decision

1. The spec format is YAML 1.2, one document per file, extension `.yaml` or `.yml`. JSON is valid YAML
   1.2 and parses on the same path. We document YAML.
2. The parser is `serde-saphyr` (pure Rust, fuzzed, designed to be panic-free, configurable budgets). It
   is used only inside `rdy-spec` (ADR 0012), never named in a public signature.
3. Limits, enforced before and during parsing: file size 1 MiB, nesting depth 64, one document only,
   duplicate keys rejected, merge keys (`<<`) rejected, **anchors and aliases rejected** (alias limit
   zero, so any anchor or alias is an error with line and column). A spec never needs them. The budget
   stays on as a second limit.
4. YAML 1.2 core schema only: `no`, `on`, `yes` are strings. Version-like fields are typed as strings and
   must keep their text: `cuda: 12.10` reaches the field as `"12.10"`, never as the float `12.1`. A plain
   scalar that the parser has already resolved to a float is rejected for those fields, with a hint to
   quote it.
5. Signatures cover the raw file bytes (ADR 0002), so no YAML canonicalization is ever needed.
6. "No unsafe" is a claim from the crate's docs, not something we have checked. Before the parser ticket
   merges, `cargo geiger` (or a grep of the sources) runs over `serde-saphyr` and its parser crate, and
   the result is written into this ADR. Done in M1-017: see "Geiger result" below.

## Implementation notes (M1-017, 2026-10-28)

`rdy_spec::parse_unverified(bytes) -> Result<Spec, SpecError>` is the only call site of `serde-saphyr`
(2.0.0, `default-features = false, features = ["deserialize"]`). `rdy_spec::load` keeps failing closed until
M1-120 verifies the signature first. `parse_unverified` never returns a `LoadedSpec`.

The reader makes two passes over text that is already in memory:

1. A **guard** reads the YAML event stream (and the token stream for directives) with `granit-parser`, the
   parser crate `serde-saphyr` re-exports. It refuses, with line and column and in file order:
   size over 1 MiB (checked first, before any parsing), invalid UTF-8, `%` directives, every explicit tag
   (`!!binary`, `!custom`, `!!str`), anchors, aliases (including an alias to an unknown anchor), merge keys,
   a second document, a duplicate key at any depth (including inside a check's parameters), nesting past
   64 levels, non-finite numbers (`.nan`, `.inf`, `-.inf`, and a decimal that overflows `f64`, such as
   `1e999`) and any unquoted decimal.
2. A **typed read** by `serde-saphyr` into `Spec`, with the same limits set again as a second line of
   defence (budget: depth 64, one document, zero anchors and aliases; errors on duplicate keys, merge keys,
   unknown tags and non-finite numbers).

The guard exists because the parameters of a check are read into `serde_json::Value`, which keeps the last of
two equal keys and turns a non-finite number into `null`, and because `serde-saphyr` accepts some tags
(`!!binary`) that a spec must not contain. Unit tests call the typed read alone to prove the second line
holds on its own.

Rules that go beyond the list above, all from decision 4 and `docs/plan/01-spec-format.md` section 2:

- **Decimals.** Decision 4 says a plain scalar that resolved to a float is refused for version fields. The
  parameters are a raw map at this point and carry no field types, so the rule applies to every plain scalar
  in the file: `min: 12.10`, `1e3`, `.5` and `5.` are refused, `"12.10"` is text, `12`, `0x1F` and `12.10.1`
  are not decimals. A future numeric parameter that is a real decimal needs a rule here first. The same
  rule refuses a whole number that would not keep its text: a leading zero (`0755`, which YAML 1.1 reads as
  octal) or a value outside `i64` and `u64` (the reader would turn it into a float and lose digits). The
  message says "versions must be text" only under a version key (`min`, `max`, `openshift_min`, `version`,
  `versions`), and "Quote it to keep it as typed" under any other key.
- **Later versions.** Once the top-level `apiVersion` says `rdy/v2` or later, any refusal that sits below it
  in the file (an unquoted decimal, a tag, a duplicate key, a syntax error) is reported as
  `UnsupportedApiVersion` with "install the latest rdy", because a file for a later rdy may use anything. A
  refusal above the `apiVersion` line is reported as it is.
- **Value count.** The crate's own caps on nodes and events are raised to the size limit (1,048,576 nodes,
  4,194,304 events), so any valid file of 1 MiB parses. A value takes at least one byte, so the size limit
  is the real bound. The worst case is a 1 MiB list of one-digit numbers, about 500,000 values.
- **Use.** `parse_unverified` is for `spec lint` and `verify` diagnostics. A run, including `--allow-unsigned`,
  goes through `load()` with an unsigned policy (M1-120).
- **Booleans.** `strict_booleans` is on, so `yes`, `no`, `on` and `off` are strings (decision 4). `true` and
  `false` are booleans.
- **Root.** The root must be a map. A list, a scalar or an empty `---` document is an error at its place.
- **`apiVersion`.** The guard reads the top-level `apiVersion` first. `rdy/v2` and later give
  `UnsupportedApiVersion` (install the latest rdy) and the rest of the file is not read. Anything else,
  including a missing key, gives `BadApiVersion`.
- **Errors.** Every refusal is a `SpecError::Located` with a line and column (1-based, columns count
  characters). Any text from the file that an error echoes goes through `echo_safe`: cut to 64 characters and
  escaped. Reasons from the YAML crate are cut to 160 and escaped.

## Geiger result (2026-10-28)

`cargo geiger` 0.14.0 over `rdy-spec` with `serde-saphyr` 2.0.0 and `granit-parser` 2.0.0, plus a grep of both
crates' sources:

| Crate | Unsafe in the crate | Declares `#![forbid(unsafe_code)]` |
| --- | --- | --- |
| `serde-saphyr` 2.0.0 | 0 functions, 0 expressions | yes (`lib.rs` and `[lints]`) |
| `granit-parser` 2.0.0 | 0 functions, 0 expressions | yes (`lib.rs` and `[lints]`) |

The claim in the docs holds for the two crates that parse. The unsafe code is in small leaf crates that most
Rust programs already carry. New in the tree with the `deserialize` feature (the others were there already or
are build-time): `smallvec` 1.16.4 (1 function, 611 expressions), `arraydeque` 0.5.1 (2 functions, 343
expressions), `encoding_rs` 0.8.42 (713 expressions), `simdutf8` 0.1.5 (347 expressions), `core_detect` 1.0.0,
`scopeguard` 1.2.0 and `anstyle` 1.0.14 (small counts), with `annotate-snippets`, `encoding_rs_io`,
`num-traits` and `unicode-width` clean. `encoding_rs`, `encoding_rs_io`, `simdutf8` and `annotate-snippets`
come with the `deserialize` feature for reader input and snippet rendering that rdy does not use, and the
feature cannot be split. This is a larger dependency tail than the ADR expected. If it matters later, the
documented fallback (`serde_yaml_ng`, one day to swap) applies, and `cargo deny` bans the archived crates either way.

`rdy-spec` itself still has `#![forbid(unsafe_code)]`.

**Accepted risk.** The `deserialize` feature pulls in `encoding_rs`, `encoding_rs_io`, `simdutf8` and
`annotate-snippets` although rdy reads only UTF-8 text already in memory. We accept that larger tail for
now, because the feature cannot be split. `serde-saphyr` is pinned as `~2.0` in the workspace, so a minor
release cannot change parser behaviour without a reviewed `Cargo.toml` edit. The parser tests are the check
on each bump.

## Consequences

- Vendors copy and paste from the docs. Editors validate through the generated JSON schema (ADR 0012).
- We depend on a younger, mostly single-maintainer crate. Mitigation: one call site, proptest and fuzz
  over the parser, and `serde_yaml_ng` as the documented fallback (about one day to swap).
- `cargo deny` bans `serde_yaml`, `serde_yml` and `libyml`.
- YAML errors carry line and column, wrapped in `SpecError`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| JSON only | No comments, noisy to hand-write. Still accepted as a YAML subset. |
| TOML | Arrays of tables (`[[checks]]`) read badly for 20 checks with nested params. Unfamiliar to the Kubernetes audience. |
| KCL or CUE | Real languages with evaluation; evaluating spec code on a customer box is attack surface. Vendors can generate YAML from either. |
| `serde_yaml_ng` or `serde_norway` | Maintained, drop-in, but built on `unsafe-libyaml`. Kept as the fallback. |
| `serde_yml` | Archived, RUSTSEC-2025-0068. |
| `noyalib` | Pre-1.0 (0.0.x), very new. Revisit in a year. |
| Cap aliases instead of rejecting them | A cap limits the damage of a billion-laughs file; rejecting removes it. Specs gain nothing from aliases. |

## Tickets implied

- [M1] Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a 2 MiB file, an anchor or alias, a duplicate key and `cuda: 12.10` unquoted each give the documented SpecError with line and column, never a panic, and the geiger result is recorded in ADR 0001.
- [M1] Property and fuzz tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: proptest over 10k random inputs in CI finds no panic.
