# ADR 0019: Schemas are derived from the types where they are typed, and from fragments where they are not yet

- Status: Accepted (2026-10-28, M1-022). Builds on ADR 0012 decision 5.
- Date: 2026-10-28

## Context

ADR 0012 says the Rust types are the source of truth and `schemars` derives the two schema files. M1-022
makes that true and removes the hand-written files. Three things were not ready when it landed.

1. **The check parameters have no types yet.** The 17 parameter structs are empty placeholders until the host
   and the net and k8s parameter tickets fill them. The hand-written spec schema already holds a strict
   definition for each id. Deriving from empty structs would make the spec schema accept any parameter.
2. **The action log, the `rdy verify` object, the lint report and the error object have no types in
   `rdy-spec`.** The action log keeps its kind-specific fields as a JSON map. The other three are printed by
   commands that are not built, or typed in `rdy-cli`.
3. **Property order.** The docs site and the JSON writer both want `properties` in the order of the struct
   fields. `serde_json` sorts object keys unless its `preserve_order` feature is on, and `schemars` derives
   `properties` through that map.

## Decision

1. **Derive what is typed.** The envelope, metadata, bundle, scalars, check common fields, the whole
   report and its parts, and `Version` (the `rdy version --json` object) derive `JsonSchema`. Rules that a
   derive cannot say (a verdict fixes the exit code, a verified signature needs its key fields, each check id
   has its own parameters) are `schemars` transforms in `crates/rdy-spec/src/schema/rules.rs`, named on the
   type they belong to.
2. **Merge fragments for the rest.** `check_params.json`, `action_fields.json` and `command_output.json` in
   `crates/rdy-spec/src/schema/` hold the parts that have no type. They are merged into the output as they are,
   pass the same description lint, and a test keeps the id list of `check_params.json` equal to
   `rdy_spec::check::KNOWN_IDS`. Each owning ticket deletes its fragment when its type derives.
3. **A pass over the finished schema** makes descriptions plain text, drops Rust integer widths from
   `format`, removes `null` alternatives in the spec schema, and gives every result text with no other limit
   `maxLength` 4096. The last step makes the size cap of SEC-63 hold for fields added later.
4. **`serde_json/preserve_order` is on for the whole workspace**, through `schemars`. Code that relied on a
   sorted map must sort. `check.rs` now names the first unknown key in sorted order, and the result
   schema test compares sorted copies.
5. **Lint in `cargo xtask schema`.** A description that names an ADR, a milestone or ticket, a plan document
   or a plan section, a rustdoc link or a Rust path fails the command, written or checked.

## Consequences

- A type or doc comment change shows up as a diff of two JSON files, and CI fails until it is regenerated.
- The generated schema accepts and refuses the same documents as the hand-written one on every case tried
  (a differential run of about 630,000 mutated documents before the files were replaced). The one difference is
  `spec.serial` in a result, which now has `minimum` 0 as `metadata.serial` has.
- `rdy-spec` has a new dependency, `schemars`, and with it `serde_json` keeps insertion order. A map built
  in a fixed order now writes in that order.
- Until the fragments go, the host parameter definitions are edited in `check_params.json`, not in the
  generated file.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Generate from the empty parameter structs | The spec schema would stop checking parameters until two tickets land. |
| Keep the hand-written files and test them against the types | Two sources, which is what ADR 0012 set out to end. |
| Sorted `properties`, no `preserve_order` | The writer order and the docs tables would be alphabetical, not the order of 07 and the samples. |
| `preserve_order` only in the tool | Cargo unifies features, so the library would change with the tool present and not without it. |
