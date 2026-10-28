# Contributing to rdy

Thanks for looking. rdy is a small tool with a narrow job: tell a customer,
before install day, whether their environment is ready for a vendor's software.
Good contributions keep it small, safe and boring.

## Before you start

- **Bugs and ideas:** open an issue first for anything bigger than a typo. Use the
  templates. A bug report with the `rdy version` output and the JSON report is
  worth ten paragraphs.
- **New checks:** open a "check request" issue. We need the id, what it measures,
  where the data comes from on each OS, what privilege it needs, the
  pass/warn/block thresholds, and the fix text. `docs/plan/03-check-catalog.md`
  shows the format. The id is `family.name`, in a family `docs/plan/01-spec-format.md`
  reserves (`host`, `net`, `k8s`, `aws`, `gcp`, `azure`, `gpu`, `store`, `custom`).
- **Security problems:** do not open a public issue. Follow `SECURITY.md`.

## Rules every check must follow

1. It declares what it needs (root, kube context, cloud credentials). It never
   asks for `sudo` itself.
2. It has a timeout and reports `Timeout` as a result. It never hangs.
3. Nothing leaves the machine. No network calls except the ones the check exists
   to make.
4. It ships with a fixture and a golden-file test. Fixtures are synthetic: no
   real hostnames, keys, tokens or customer data. Use `.example` domains and
   acme-style names.
5. No OpenSSL. rustls only. No `unsafe` unless the crate documents each block.
6. Every user-facing error says how to fix it. An error is two lines at column 0:
   `error: <what happened>` and `fix: <one thing to do>`. Plain words, no Rust type
   names, no `os error 13`.
7. A check that cannot run says why and what to do, and does not fail the run. If
   the spec marks that check `severity: block`, the run is NOT READY (exit 2). It is
   never a quiet pass.
8. No error, fix or hint ever names `--allow-unsigned` or `rdy run --key`. They are
   documented in `--help` and at docs.getrdy.io, not suggested. A hint may name
   `rdy trust add ... --key`, which pins a key. Secrets never go on argv.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
cargo doc --workspace --no-deps
```

`cargo doc` treats rustdoc warnings as errors (`.cargo/config.toml`). All of these must pass before a PR is reviewed. CI also runs on five native
runners for every PR (Linux x86_64 and aarch64 on musl, macOS arm64 and x86_64,
Windows x86_64), so expect your change to be tested on all five. The Rust version
is pinned in `rust-toolchain.toml`.

Repo tasks run through `cargo xtask`, from `crates/xtask`. Run these when you change docs or generated files:

```sh
cargo xtask docs
cargo xtask docs --check
cargo xtask schema --check
cargo xtask docs-lint
```

`cargo xtask docs` writes the generated pages under `docs/`. Never edit those pages by hand. Change the generator, then run the command again. `docs-lint` reads only the files that git tracks. Run `git add` on a new file before you lint it. `dist` and `publish` are off in this build.

To try your change by hand:

```sh
cargo run -p rdy -- run examples/specs/acme-quickstart.yaml --allow-unsigned --out-dir /tmp
```

The example spec has no signature, so rdy prints a red `UNSIGNED SPEC` banner
before the checks and again above the verdict. That is expected. The exit code is
not the point here. It is 2 on most machines, because the example's endpoints do
not exist. Exit codes are 0 ready, 1 ready with warnings, 2 not ready, 64 usage
error and 70 internal error. Each run writes a new `rdy-report-...` folder, so
use `--out-dir` or `--no-report` to keep your checkout clean.

## Where things go

- A new check goes in the `rdy-checks-<family>` crate for its family, one module
  per check, with its fixture and golden test.
- Golden files live under `tests/fixtures/`. The testing docs say how to
  regenerate them. Read the diff before you commit it.
- Anything a user reads (output, errors, help) follows `docs/plan/07-cli-ux.md`.
  Its samples are golden files, so a wording change changes a golden file, and
  the diff shows it. Human output goes to stderr. Only `--json` data goes to
  stdout.

## Pull requests

- One change per PR. Small is good. Imperative commit summary, one line.
- Add tests. Update docs in the same PR.
- Add a changelog fragment. Create `changelog.d/<ticket>.md` (for example `changelog.d/M1-003.md`) with
  one or two bullet lines in plain, user-facing words. Do not edit `CHANGELOG.md` itself, so parallel PRs
  never conflict. The release ticket collects the fragments into `CHANGELOG.md`. The PR template has the box.
- Sign off your commits (`git commit -s`). This is the
  [Developer Certificate of Origin](https://developercertificate.org/): you wrote
  it, or you have the right to submit it, under Apache-2.0. CI fails a PR with a commit that has no
  `Signed-off-by:` line. To fix the last commit run `git commit --amend -s`. For a whole branch run
  `git rebase --signoff origin/main`, then force-push. The check accepts any well-formed
  `Signed-off-by: Name <email>` line. It does not compare the name or email with the commit author.
- If an AI tool wrote most of the change, say so in the PR description. That is
  fine. You are still responsible for reading it and understanding it.
- Reviews are direct and about the code. Expect questions about privileges,
  failure modes and what happens on Windows.

## Spec and result formats

`rdy-spec` and `rdy-engine` define the spec and the result format. Changes to
either need a design note in `docs/plan/` or an ADR in `docs/adr/` first. Other
programs read these formats, so we do not break them casually. Within `rdy/v1`
the JSON only grows: no field is removed, renamed, retyped or given a new meaning.
New optional fields are fine. Anything else needs `rdy/v2` and an ADR.

## Conduct

Be kind and be direct. See `CODE_OF_CONDUCT.md`.

## License

By contributing you agree that your work is licensed under Apache-2.0.
