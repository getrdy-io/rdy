---
title: Unsigned specs
description: What --allow-unsigned and --key do, when not to use them, and how to check a spec with your vendor's key on Windows.
---

After you read this page, you can decide whether `--allow-unsigned` or `--key` fits a run. You can also check a spec with your vendor's key on Windows.

rdy runs a spec only when a key you trust signed it. Two flags change that rule. Use either one only when you know who wrote the spec.

This page describes `--key` and `rdy verify` as they ship in 0.1.0. Older builds print `not yet implemented`. Upgrade first.

## What the flags do

`--allow-unsigned` runs a spec that has no signature at all. The spec has no `.minisig` file next to it, and you pass no `--sig`.

- rdy prints `WARNING: UNSIGNED SPEC` before any check runs.
- rdy marks every report from the run `UNSIGNED SPEC`.

```sh
rdy run acme-quickstart.yaml --allow-unsigned
```

`--key` checks the spec against one public key, for one run only.

- rdy saves nothing. The key is not trusted after the run.
- rdy prints `WARNING: KEY NOT PINNED` and marks every report `KEY NOT PINNED`.

```sh pending=M1-126
rdy run --key acme-platform.pub acme-platform.yaml
```

## What the flags never do

Neither flag accepts a signature that does not match. rdy exits 64 when:

- the spec has a signature, and the signature does not verify;
- the signature is by a key that rdy does not trust, and you gave no `--key`;
- the spec is expired.

A flag only changes the case where there is no signature, or where you give the key yourself.

## When not to use them

Do not use `--allow-unsigned` for a spec that your vendor sends to production. Ask the vendor for the signed spec and its `.minisig` file. Put the `.minisig` file next to the spec.

Use `--allow-unsigned` for:

- a spec you wrote yourself, to test it;
- the example specs in the rdy repository.

Use `--key` when your vendor gives you a key but you do not want to trust it on this machine. Check the fingerprint first. Get it from the vendor by another route than the spec.

Exit codes are the same as for any run. See [Exit codes](/run/exit-codes/).

## Windows

On Windows, rdy does not trust a store in this release. rdy refuses a trust store file that it finds in `%ProgramData%\rdy`, and it exits 64 with `trust_store_insecure`. It also cannot save a key there. `rdy trust add` exits 64 on Windows.

A run with `--key` never reads a trust store. So you can check a spec with your vendor's key on Windows in these steps.

1. Get the vendor's public key file. Get the fingerprint the vendor publishes, by another route than the spec.
2. Put the spec, its `.minisig` file and the key file in one folder. Open a terminal in that folder.
3. Check the signature.

```sh pending=M1-126
rdy verify --key acme-platform.pub acme-platform.yaml
```

Exit 0 means the signature is good for that key. rdy prints the fingerprint of the key. Compare it with the fingerprint the vendor published. If they differ, do not run the spec.

To run the spec with the same key, use `--key` on the run:

```sh pending=M1-126
rdy run --key acme-platform.pub acme-platform.yaml
```

Every run with `--key` prints `WARNING: KEY NOT PINNED`. That warning is expected on Windows in this release.

A plain `rdy verify` or `rdy run` without `--key` reads the trust store. If the store file is there, that run exits 64. Ask an administrator to remove the file, then run again.
