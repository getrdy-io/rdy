# ADR 0026: CheckMeta holds a check's title and remediation and lives in its static CheckInfo

- Status: Proposed (M1-089). Accept once cli-ux has reviewed the remediation wording and the
  `xtask checks` output in the PR.
- Date: 2026-10-29

## Context

09 section 6 asks for a `CheckMeta` value per check in the registry, with ten fields: id, family, title,
what it measures, privilege needed, supported operating systems, what it reads on each OS, thresholds,
remediation text and sort order. The docs pages (M1-116), the privilege table (M2-096) and the catalog sync
(M2-094) read it. The report prints the same remediation.

Most of those fields already exist. 02 gives every check one `static CheckInfo` with the id, family,
summary, needs, wants, OS support and reads, and the planner and the facade already depend on it. The
thresholds are the typed spec parameters in `rdy-spec`. A second struct with all ten fields would be a
second source for seven of them.

`rdy-engine` is a public crate that `rdy-cloud` will consume from crates.io (ADR 0007). `CheckInfo` has
public fields and is built with a struct literal, so a new field is a breaking change for any crate that
builds one. Today only the check families and tests do, and `rdy-engine` is not published yet.

The CLI has no registry yet. `rdy run` gets one in M1-057. The M1-067 rule says `HostFamily` must not be
registered in the CLI while its checks are stubs.

## Decision

1. `rdy_engine::check::CheckMeta { title, remediation }` is a plain `Copy` struct of two
   `&'static str`. It is the `meta` field of `CheckInfo`, so each check has it exactly once and the
   compiler refuses a check without it.
2. Every other field of 09 section 6 has one home: id, family, `summary` (what it measures), needs and
   wants (the privilege), `os` and `reads` stay in `CheckInfo`. Thresholds stay in the typed spec
   parameters. The sort order is the order of `Family::checks`. `Registry::families()` returns the
   families in registration order, so a reader walks families, then checks, in catalog order.
3. A title is a short heading. A remediation is the general fix in plain sentences, on one line, with no
   measured value and no placeholder to fill. A finding's own `fix` stays the specific advice, and a spec
   `fix` still replaces rdy's text (ADR 0008, `rdy_engine::outcome`). Nothing on the wire changes.
4. `cargo xtask checks` prints a header and one tab-separated row per registered check (id, family,
   title, remediation) to stdout. It exits 1 and names the check when a title or remediation is blank or
   holds a control character. `cargo xtask docs-lint` runs the same validation, as 09 section 10 asks.
   A unit test runs it over the registry of this build, so `cargo test` fails too.
5. Until M1-057, the family list lives in `xtask` (`checks::registry`). M1-057 moves it into `rdy_cli`
   and points `xtask` at that function, so the docs and the binary read one registry. This ADR does not
   register `HostFamily` in the CLI.

## Consequences

- The docs, the report and the listing read the same string. A check cannot ship without a title and a
  remediation.
- Every `CheckInfo` literal grows by one field. The seven host stubs carry text taken from the Fix lines of
  03 section 2, with the values removed. Each real check may sharpen its text.
- `xtask` depends on `rdy-engine` and `rdy-checks-host`. Each new family crate is added to
  `checks::registry` until M1-057 moves the list.
- `xtask checks` lists the host stubs. The docs renderer must not publish an id that
  `HostFamily::stub_ids()` still holds (09 section 6, release scope).
- The changelog fragment records the new `CheckInfo` field. No version bump: `rdy-engine` is unpublished.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| A separate `CheckMeta` with all ten fields of 09 | Two sources for id, family, OS support, needs and reads, which then drift. |
| `title` and `remediation` as flat `CheckInfo` fields | Works, but mixes docs text into the side-effect manifest that security review reads, and 09 and the backlog name `CheckMeta`. |
| `Family::meta(id)` returning the text | A lookup can miss an id. A field cannot. |
| Refuse a blank remediation in `Registry::register` | The shipped binary would refuse to start over a docs fault. A test catches it before release instead. |
| A `sort_order` number | A second order to keep in step with the family's own list. |
| `rdy_cli::registry()` now | It would register `HostFamily` in the CLI while its checks are stubs (M1-067 rule) and add the engine to the binary before `rdy run` uses it. |

## Tickets implied

- [M1] Report shows the registry remediation when a check gives no fix | owner: rust-engineer | est: 1h | depends on: CheckMeta in the check registry, read by xtask | exit test: a warn result whose finding has no fix and whose spec entry has no fix shows the check's `meta.remediation` with `fix_source: rdy`, not the "no advice" text.
- Correction to M1-057 (wire `rdy run`): add "the family list moves from `xtask` into `rdy_cli`, and `cargo xtask checks` reads that registry" to its exit test.
- Correction to M1-116 (family renderer): add "no id in `HostFamily::stub_ids()` gets a section" to its exit test.
