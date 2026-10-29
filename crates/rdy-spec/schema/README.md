# rdy/v1 JSON schemas

| File | Describes |
| --- | --- |
| `spec.v1.schema.json` | The readiness spec a vendor writes (`apiVersion: rdy/v1`, `kind: Readiness`). |
| `result.v1.schema.json` | The JSON report `rdy run` writes and Rdy Cloud ingests (`kind: Report`), plus the objects printed with `--json`: `Verification`, `ErrorOutput`, `LintReport` and `Version` (`rdy version --json`). |

Both are JSON Schema draft 2020-12. The design and the compatibility rules are in
`docs/plan/01-spec-format.md`.

## Where these files come from

Do not edit them. They are generated from the Rust types in `rdy-spec` with `schemars` (ADR 0012, ADR 0019):

```console
cargo xtask schema            # write both files
cargo xtask schema --check    # fail when a file differs from what the types generate
```

A doc comment on a type or a field is the description in the schema. A change to a type or a doc comment
shows up as a diff of these files, and CI fails until the files are regenerated. `cargo xtask schema` also
fails when a description names an ADR, a milestone, a plan document or a section of one, because the text
reaches customers.

Three parts of the contract have no Rust type yet. They are JSON fragments in
`crates/rdy-spec/src/schema/` that the generator merges in as they are: the parameters of the 17 check ids,
the kind-specific fields of an action, and the `Verification`, `ErrorOutput` and `LintReport` objects. Edit
the fragment, then regenerate. Each goes away when its type derives the schema.

Editors can use the spec schema today, for example with yaml-language-server:

```yaml
# yaml-language-server: $schema=https://getrdy.io/schema/rdy/v1/spec.v1.schema.json
```

rdy itself never fetches a schema at run time.

## Revisions

The wire format stays `rdy/v1` while changes are additive. Each `rdy-spec` release that changes either
file adds a line here.

| v1 revision | rdy-spec | Change |
| --- | --- | --- |
| 0 | 0.1.0 | First contract: spec envelope, 17 M1 check ids with required thresholds, bundle shape with `redact_patterns` and `max_size`; result report with `bucket`, key fingerprint, action log retention, redaction summary, size caps; `Verification`, `ErrorOutput` and `LintReport` objects. |
| 0 | 0.1.0 | The files are generated from the types. Same documents accepted and refused, with these differences: `spec.serial` in a result has `minimum` 0, the `file:` rule of `bundle.collect` writes the NUL byte as `\x00` so every validator can compile it, and enum values and the `Kind` constant are definitions of their own. Added the `Version` definition for `rdy version --json`. |
