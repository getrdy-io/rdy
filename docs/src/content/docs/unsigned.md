---
title: Unsigned specs
description: What --allow-unsigned and --key do, the risk they carry, when not to use them, and how to check a spec with your vendor's key on Windows.
---

After you read this page, you can decide whether `--allow-unsigned` or `--key` fits a run. You can also check a spec with your vendor's key on Windows.

The spec decides which files rdy reads and which hosts it contacts. A spec that you cannot trust can make rdy read files and contact hosts you did not expect. A signature tells you who wrote the spec. rdy runs a spec only when a key you trust signed it. Two flags change that rule. Use either one only when you know who wrote the spec.

The examples on this page assume `rdy` is on your `PATH`. See [Install](install.md).

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
- rdy does not ask you to confirm the key. A `--key` run has no fingerprint prompt.

Anyone who can send you a spec can send you a key as easily. So a `--key` run proves only that the spec matches the key you gave. It does not prove the key is your vendor's.

## Trust a key the normal way

On Linux and macOS, `rdy trust add` is the normal path. It shows the key's fingerprint and asks you to compare it with the one the vendor published. It saves the key only after you say yes. Then every run of that product checks against the saved key.

```sh pending=M1-126
rdy trust add acme-platform --key acme-platform.pub
```

Use `--key` on a run when you do not want to save the key. Before you run the spec, check the key with `rdy verify`. Compare the fingerprint it prints with the vendor's fingerprint. Get the vendor's fingerprint by another route than the spec.

```sh pending=M1-126
rdy verify --key acme-platform.pub acme-platform.yaml
rdy run --key acme-platform.pub acme-platform.yaml
```

Only run the spec when the fingerprints match.

Compare the full fingerprint that `rdy verify --key` prints. Do not compare the short fingerprint in the `KEY NOT PINNED` banner. Someone can grind a key until its short form matches the one you expect.

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

Exit codes are the same as for any run. See [Exit codes](run/exit-codes.md).

## Windows

On Windows, rdy does not trust a store in this release. rdy refuses a trust store file it finds in `%ProgramData%\rdy`, and it exits 64 with `trust_store_insecure`. It also cannot save a key there. `rdy trust add` exits 64 on Windows.

A signed spec on Windows needs `--key`. Without it rdy exits 64: `spec_key_unknown`, or `trust_store_insecure` when a store file exists.

Check a spec with your vendor's key on Windows in these steps.

1. Get the vendor's public key file. Get the fingerprint the vendor publishes, by another route than the spec.
2. Put the spec, its `.minisig` file and the key file in one folder. Open a terminal in that folder.
3. Check the signature. Compare the full fingerprint that rdy prints with the vendor's. Not the short one in the banner.

```powershell pending=M1-126
rdy verify --key acme-platform.pub acme-platform.yaml
```

Exit 0 means the signature is good for that key. If the fingerprints differ, do not run the spec.

4. Run the spec with the same key:

```powershell pending=M1-126
rdy run --key acme-platform.pub acme-platform.yaml
```

Every run with `--key` prints `WARNING: KEY NOT PINNED`. That warning is expected on Windows in this release.

Do not delete or rename the `.minisig` file to use `--allow-unsigned`. That removes the only check.

A plain `rdy verify` or `rdy run` without `--key` reads the trust store. If the store file is there, that run exits 64. Ask an administrator to remove the file. Until then, run again with `--key`.
