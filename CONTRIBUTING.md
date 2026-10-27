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
  shows the format.
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
6. Every user-facing error says how to fix it.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
```

All of these must pass before a PR is reviewed. CI also runs on Linux (x86_64
and aarch64), macOS and Windows for every PR, so expect your change to be
tested on all four. The Rust version is pinned in `rust-toolchain.toml`.

To try your change by hand:

```sh
cargo run -p rdy -- run examples/specs/acme-quickstart.yaml --allow-unsigned
```

The exit code is not the point here. It is 2 on most machines, because the
example's endpoints do not exist. That is expected.

## Where things go

- A new check goes in the `rdy-checks-<family>` crate for its family, one module
  per check, with its fixture and golden test.
- Golden files live under `tests/fixtures/`. The testing docs say how to
  regenerate them. Read the diff before you commit it.

## Pull requests

- One change per PR. Small is good. Imperative commit summary, one line.
- Add tests. Update docs in the same PR. Add a `CHANGELOG.md` entry.
- Sign off your commits (`git commit -s`). This is the
  [Developer Certificate of Origin](https://developercertificate.org/): you wrote
  it, or you have the right to submit it, under Apache-2.0.
- If an AI tool wrote most of the change, say so in the PR description. That is
  fine. You are still responsible for reading it and understanding it.
- Reviews are direct and about the code. Expect questions about privileges,
  failure modes and what happens on Windows.

## Spec and result formats

`rdy-spec` and `rdy-engine` define the spec and the result format. Changes to
either need a design note in `docs/plan/` or an ADR in `docs/adr/` first. Other
programs read these formats, so we do not break them casually.

## Conduct

Be kind and be direct. See `CODE_OF_CONDUCT.md`.

## License

By contributing you agree that your work is licensed under Apache-2.0.
