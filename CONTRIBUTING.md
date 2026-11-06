# Contributing to rdy

Thanks for looking. rdy is a small tool with a narrow job: tell a customer,
before install day, whether their environment is ready for a vendor's software.
Good contributions keep it small, safe and boring.

## Before you start

- **Bugs and ideas:** open an issue first for anything bigger than a typo. A bug
  report with the `rdy version` output and the JSON report is worth ten paragraphs.
  Issue forms are not set up yet, so write the title and the steps yourself.
- **New checks:** open an issue titled "check request: `family.name`". We need the id, what it measures,
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

## Set up

You need git and [rustup](https://rustup.rs). Nothing else is needed to build.

```sh
git clone https://github.com/getrdy-io/rdy.git
cd rdy
cargo build --workspace
```

`rust-toolchain.toml` pins the exact stable Rust (1.99.1 today, with clippy and rustfmt).
rustup installs it the first time you run cargo in the folder. The minimum Rust version
for people who depend on our crates (`rust-version` in `Cargo.toml`) is older: stable minus
two minors. Develop on the pinned one. Do not pass `+stable` or `+nightly`.

Your commits need a name and an email, because the DCO line carries them (see Pull requests):

```sh
git config user.name "Your Name"
git config user.email "you@example.com"
```

`cargo deny` is a separate install: `cargo install cargo-deny --version 0.20.2 --locked`. CI pins that version
in `.github/workflows/ci.yml`.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
cargo doc --workspace --no-deps
cargo xtask docs --check
cargo xtask schema --check
cargo xtask docs-lint
```

`cargo doc` treats rustdoc warnings as errors (`.cargo/config.toml`). All of these must pass before a PR is reviewed.
The first build takes a few minutes. Some tests make a key with a 1 GiB password hash, so
give the test run memory. CI also runs on native
runners for every PR (Linux x86_64 and aarch64 on musl, macOS x86_64, Windows x86_64),
and it compiles the macOS arm64 target without running its tests. The full macOS arm64
tests run nightly and on `main` in a separate workflow, until the org has arm64 runners.
The Rust version is pinned in `rust-toolchain.toml`.

CI runs the tests with `cargo nextest` (profile `ci` in `.config/nextest.toml`, no retries) and runs
doc tests on Linux x86_64 only. A test that fails once in three runs is a bug. Fix the test. To run
the suite the way CI does, install `cargo-nextest` and run `cargo nextest run --workspace --profile ci`
and `cargo test --doc --workspace`. A test named `root_*` needs uid 0. Nextest skips it unless you pass
`--profile root`, and CI runs it in the `root` job under `sudo`. On Linux, CI also builds the musl binary and checks it with
`scripts/check-static.sh target/<triple>/debug/rdy`. To do that yourself, add the target first
(`rustup target add x86_64-unknown-linux-musl`) and build with `--target`. On Debian or Ubuntu, `apt install musl-tools` and set `CC_x86_64_unknown_linux_musl=musl-gcc`, as CI does.

Property tests use `proptest`. Each test sets its own case count (10,000 for "never panics" and
limits, 256 for the rest), so do not set `PROPTEST_CASES`. Pull requests use a fixed seed, so a
test never fails on an unrelated change. To try other draws, set `PROPTEST_RNG_SEED=<number>`. A
failure is saved in `crates/rdy-spec/proptest-regressions/`. Commit that file with the fix, and add
a plain test with the smallest input next to the fix.

Repo tasks run through `cargo xtask`, from any folder in the checkout (an alias in `.cargo/config.toml`). Run these when you change docs or generated files:

```sh
cargo xtask docs
cargo xtask docs --check
cargo xtask schema --check
cargo xtask docs-lint
cargo xtask checks
```

`cargo xtask docs` writes the generated reference pages under `docs/src/content/docs/reference/`.
Never edit those pages by hand. Change the generator, then run the command again. `docs-lint` reads only the files that git tracks. Run `git add` on a new file before you lint it. `dist` and `publish` are off in this build.

`cargo xtask checks` lists every registered check with its id, family, title and remediation, one tab-separated row each. It fails when a title or remediation is empty. A new check fills in the `meta` field of its `CheckInfo` (ADR 0026). `docs-lint` runs the same test.

To try your change by hand:

```sh
mkdir -p /tmp/rdy-try
cargo run -p rdy -- run examples/specs/acme-quickstart.yaml --allow-unsigned --out-dir /tmp/rdy-try
```

The folder for `--out-dir` must exist. The example spec has no signature, so rdy
prints `warning: this spec is not signed` on stderr before the checks, and the JSON
report records it. The full red UNSIGNED SPEC banner on the terminal comes with M1-126.
That is expected. The exit code is not the point here. It is 2 today: `net.egress`
is not built yet, so the run ends with `NOT READY: 1 required check was not run`.
Once it is built, the made-up endpoints in the example make it a blocker, and the
exit stays 2. Exit codes are 0 ready, 1 ready with warnings, 2 not ready, 64 usage
error and 70 internal error. Each run writes a new `rdy-report-...` folder, so
use `--out-dir` or `--no-report` to keep your checkout clean.

## Where things go

- A new check goes in the `rdy-checks-<family>` crate for its family, one module
  per check, with its fixture and golden test.
- Docs: hand-written intros are in `docs/intro/`. The published site is
  `docs/src/content/docs/`. `docs/plan/` and `docs/adr/` are design notes and are
  never published. The README is the front page.
- Golden files live under `tests/fixtures/`. The testing docs say how to
  regenerate them. Read the diff before you commit it.
- Anything a user reads (output, errors, help) follows `docs/plan/07-cli-ux.md`.
  Its samples are golden files, so a wording change changes a golden file, and
  the diff shows it. Human output goes to stderr. Only `--json` data goes to
  stdout.

## Pull requests

- One change per PR. Small is good. Imperative commit summary, one line.
- Add tests. Update docs in the same PR.
- Add a changelog fragment when a user can see the change (ADR 0017, `docs/adr/0017-changelog-fragments.md`).
  Create `changelog.d/<ticket>.md` (for example `changelog.d/M1-003.md`) with one or two bullet lines in
  plain, user-facing words. With no ticket, use a short slug, such as `changelog.d/fix-disk-units.md`. A
  PR that only changes `docs/plan/`, `docs/adr/` or the backlog needs none. Do not edit `CHANGELOG.md` itself, so parallel PRs never conflict.
  The release step collects the fragments into `CHANGELOG.md`. The PR template has the box.
- Sign off your commits (`git commit -s`). This is the
  [Developer Certificate of Origin](https://developercertificate.org/): you wrote
  it, or you have the right to submit it, under Apache-2.0. CI fails a PR with a commit that has no
  `Signed-off-by:` line. To fix the last commit run `git commit --amend -s`. For a whole branch run
  `git rebase --signoff origin/main`, then force-push. The check accepts any well-formed
  `Signed-off-by: Name <email>` line. It does not compare the name or email with the commit author.
  To run the same check yourself: `scripts/check-dco.sh origin/main HEAD`.
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

Be kind and be direct. Assume good faith and argue about the code, not the person.
A formal `CODE_OF_CONDUCT.md` is planned and will be linked here.

## License

By contributing you agree that your work is licensed under Apache-2.0, and you certify that with the
DCO sign-off on every commit (see Pull requests above). `NOTICE` says who owns the code and
the marks (Apostolic Path LLC). The name and the logo are covered by `TRADEMARKS.md`, not by
the license.
