# C minisign fixture

Synthetic. Nothing here protects anything or belongs to anyone.

These files were made once by the C `minisign` tool, version 0.11 (Ubuntu package `minisign` 0.11-1). They
prove that `rdy spec sign` opens a key that stock tooling made, and that rdy reads a signature that stock
tooling made (ADR 0022 decision 6).

- `acme-platform.key` is an encrypted secret key. scrypt N = 2^20, 1 GiB, which is the stock cost. The
  password is `rdy-test-password-not-a-secret`. It is published on purpose. The key signs nothing real.
- `acme-platform.pub` is its public key. The key id is `62DF9736939C03E8`.
- `acme-platform.yaml` is a copy of `tests/fixtures/signed/acme-platform.yaml`.
- `acme-platform.yaml.minisig` is the signature over those exact bytes. Its trusted comment is
  `rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z` (01 section 4.2).

They were made with:

```text
printf 'rdy-test-password-not-a-secret\nrdy-test-password-not-a-secret\n' \
  | minisign -G -p acme-platform.pub -s acme-platform.key
printf 'rdy-test-password-not-a-secret\n' | minisign -S -s acme-platform.key \
  -m acme-platform.yaml -x acme-platform.yaml.minisig \
  -c 'rdy spec signature for acme-platform, key 62DF9736939C03E8' \
  -t 'rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z'
```

Git does not keep file modes, so the test copies the key to a temporary folder and sets mode 0600 there,
because rdy refuses a key that others can read. The files are signed or keyed over exact bytes, and
`.gitattributes` marks everything under `tests/fixtures/` as `-text`.

Never edit these files. A new case gets new files. The test is `crates/rdy-cli/tests/minisign_c_interop.rs`.
