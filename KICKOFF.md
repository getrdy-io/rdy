# Kickoff prompt for `rdy` (paste into Claude Code at the repo root)

You are planning and then building the open-source `rdy` CLI described in CLAUDE.md and docs/plan/rdy-plan.md.
Read both completely before doing anything else. Then produce a complete, execution-ready plan for both
phases, and only after the plan is reviewed, start building milestone M1.

## What I want from the planning pass

Work in `docs/plan/`. Use the subagents in `.claude/agents/` for every slice; do not do their jobs yourself.
Run independent subagents in parallel. Every document below is written by the owning subagent and reviewed
by at least one other subagent who did not write it. Report back only when every file exists.

1. `docs/plan/00-overview.md` (rust-architect): phases, milestones M1 to M5 with exit tests taken from the
   plan, what is public vs private, the one-paragraph description of each crate and its public API surface.
2. `docs/plan/01-spec-format.md` (rust-architect, reviewed by security-reviewer and cli-ux): the `rdy/v1`
   spec schema in full, versioning and compatibility rules, signing format, the JSON result schema that
   `rdy-cloud` will consume, and the HTML report contract. Include the JSON schema files under
   `crates/rdy-spec/schema/`.
3. `docs/plan/02-engine-design.md` (rust-architect, reviewed by security-reviewer): the Check trait,
   privilege negotiation, scheduling and timeouts, result model, how checks declare needs and degrade,
   how the engine runs on each OS, and the plugin story for custom checks.
4. `docs/plan/03-check-catalog.md` (check-author with k8s-expert, cloud-iam-expert, gpu-expert): every
   check at launch, grouped by family, each with: id, what it measures, exact data source and command or
   API used per OS, privilege needed, pass/warn/block thresholds, remediation text, and the fixture needed
   to test it. Order them by how often they catch real install failures.
5. `docs/plan/04-bundle-and-redaction.md` (security-reviewer and rust-engineer): collectors, redactor
   design, redaction test strategy, bundle manifest, size caps, the opt-in upload flow byte by byte.
6. `docs/plan/05-threat-model.md` (security-reviewer): STRIDE over the CLI running as root inside a
   customer environment, the spec supply chain, the install script, and the upload path. Mitigations
   mapped to tickets.
7. `docs/plan/06-release-and-distribution.md` (release-engineer): CI matrix, dist config
   (`dist-workspace.toml`), cosign signing, SBOM, install.sh behaviour, Homebrew tap, winget, apt and yum
   later, self-update, version policy.
8. `docs/plan/07-cli-ux.md` (cli-ux): every command and flag, help text, output samples for ready, warning
   and blocked runs, JSON output samples, exit codes, color and no-color behaviour, accessibility.
9. `docs/plan/08-testing.md` (qa-engineer): fixture strategy for environments you cannot have in CI
   (air-gapped, GPU nodes, Windows hosts), golden tests, property tests, the compatibility matrix.
10. `docs/plan/09-docs-site.md` (docs-writer): docs.getrdy.io information architecture, the pages, how
    the schema generates the reference, versioning of docs with releases.
11. `docs/plan/10-devrel-and-launch.md` (devrel): README, examples, the public launch checklist for
    Show HN and the PreSales Collective, the "one check family a day" content series.
12. `docs/plan/11-backlog.md` (rust-architect, everyone contributes): the full ticket list for M1 through
    M5 as a table: id, milestone, title, owner subagent, estimate in hours, depends on, exit test. Tickets
    are one to four hours each. M1 must be fully ticketed; later milestones can be coarser.
13. `docs/adr/0001-*.md` onward: one ADR per decision that could be argued (spec language YAML vs
    others, signature scheme, report format, async runtime, plugin model, musl vs glibc).

Constraints the plan must respect: one part-time founder, a usable binary every week. M1 runs at its real
size from `docs/plan/11-backlog.md`: the founder started it on 2026-10-28, tickets marked `core: yes` are
the minimum and `core: no` is the trim list. M1 contains only workspace plus CI, spec parser and result
model, host checks plus HTML report, network checks, Kubernetes checks, and spec signing and release
signing, plus the minimum docs, security and release work those need; anything else is M2 or later. Flag every place where the plan doc
is wrong or out of date and propose the fix instead of silently following it.

## After the plan

Ask me to review `docs/plan/11-backlog.md`. When I approve, start M1 ticket by ticket. For each ticket:
the owning subagent implements, `code-reviewer` reviews cold, `security-reviewer` reviews if the ticket
touches privileges, network, redaction, signing or the install script, `qa-engineer` adds or updates
fixtures and golden tests, `docs-writer` updates docs in the same PR. One PR per ticket, small, green.
