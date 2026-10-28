# Signed spec fixture

Synthetic. Nothing here is a real key, a real spec or a real customer.

- `acme-platform.yaml` is a frozen copy of `examples/specs/acme-platform.yaml`.
- `acme-platform.yaml.minisig` is a minisign signature over those exact bytes. Its signed comment is
  `rdy-spec-v1 product=acme-platform signed_at=2026-10-28T12:00:00Z`.
- `acme-platform.pub` is the matching public key.

The secret key was made in memory by the `regenerate` test and thrown away. No secret key is stored
anywhere in the repo. To make a new fixture, change the spec if you must, then run:

```text
cargo test -p rdy-spec --test signed_fixture -- --ignored regenerate
```

It makes a new key pair, signs the spec file as it is, and overwrites the `.minisig` and `.pub` files.

These files are signed over exact bytes. `.gitattributes` marks them `-text` so Git never converts their
line endings, not even on Windows with `core.autocrlf true`. A test fails if a CR appears in them.
