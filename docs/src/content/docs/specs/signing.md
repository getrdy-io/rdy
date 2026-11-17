---
title: Sign and verify
description: Make a signing key, sign a spec, check a signature with rdy verify, and trust a vendor key with rdy trust add.
---

After you read this page, you can make a signing key, sign a spec, check a signature, and trust a vendor's key. You can also compare fingerprints the right way.

rdy runs a spec only when a key you trust signed it. The vendor signs the spec. The customer checks the signature and pins the vendor's key. Read the [unsigned specs](../unsigned.md) page if you want to run a spec that has no signature.

The commands on this page assume `rdy` is on your `PATH`. See [Install](../install.md).

## Make a signing key

Vendors make a key once. Run this in the folder where you want the key files:

```sh
rdy spec keygen acme-signing
```

rdy writes two files:

- `acme-signing.key` is the secret key. Only your user can read it.
- `acme-signing.pub` is the public key. Send it to customers.

On Windows, keep the key in a folder only you can read. The key file inherits that folder's access list.

rdy asks for a password for the secret key. For CI, set `RDY_KEY_PASSWORD` to the password. Do not put the password on the command line.

rdy prints the fingerprint of the public key. Publish that fingerprint on your docs page. Customers compare it with the one they see.

Keep a backup of `acme-signing.key`. Anyone who has it can sign specs as you. Do not commit it to the repository that holds your specs.

## Sign a spec

```sh
rdy spec sign acme-platform.yaml --secret-key acme-signing.key
```

Before it signs, rdy lints the spec. A spec with errors is not signed. Warnings print, and the signing goes on.

rdy writes `acme-platform.yaml.minisig` next to the spec. It checks the new signature before it finishes. If a signature file already exists, rdy exits 64. Use `--force` to replace it.

Send the customer three things:

- the spec, `acme-platform.yaml`;
- the signature, `acme-platform.yaml.minisig`;
- the public key, `acme-signing.pub`, and the fingerprint from your docs page.

Do not change the spec after you sign it. A change, even a space or a line ending, breaks the signature. If your repository converts line endings, add `*.yaml -text` to `.gitattributes`.

## Check a signature

Use `--key` to check a spec against a key you have. This run does not save the key:

```sh
rdy verify --key acme-signing.pub acme-platform.yaml
```

Exit 0 means the signature matches the key and the spec. rdy prints `WARNING: KEY NOT PINNED`, because the key is not saved. The spec is valid for that key only.

Compare the full fingerprint that `rdy verify --key` prints with the fingerprint the vendor published. Do not compare the short fingerprint in the `KEY NOT PINNED` banner. Someone can grind a key until its short form matches the one you expect.

Without `--key`, rdy checks the signature against the keys you trust. A new vendor key is not trusted yet, so this command exits 64:

```sh
rdy verify acme-platform.yaml
```

Trust the key first. See the next section.

If the spec changed after signing, `rdy verify` exits 64 with `does not match the file`. Do not run that spec. Ask the vendor for a fresh copy and its `.minisig` file.

## Trust a vendor key

Trust a key once, after you check its fingerprint:

```sh
rdy trust add acme-platform --key acme-signing.pub
```

rdy shows the key id and the full fingerprint. Compare the fingerprint with the one the vendor published. Answer `y` only when they match. rdy saves the key only after you answer `y`.

In a script, add `--yes` after you have checked the fingerprint. Without a terminal and without `--yes`, `rdy trust add` exits 64.

After you trust the key, check the spec again. The `KEY NOT PINNED` banner does not appear:

```sh
rdy verify acme-platform.yaml
```

A normal user's key is saved in `$XDG_CONFIG_HOME/rdy/trust.yaml` when that variable is set, and in `~/.config/rdy/trust.yaml` when it is not. A root run reads only `/etc/rdy/trust.yaml`, so run `sudo rdy trust add` to trust a key for root runs.

On Windows, this release does not save trusted keys. Use `--key` instead. See [Unsigned specs](../unsigned.md#windows).

## Read the exit codes

| Command | Exit 0 | Exit 64 |
| --- | --- | --- |
| `rdy spec sign` | The spec is signed and the new signature verifies. | The spec has errors, the key is readable by others, the signature file exists, or the password is wrong. |
| `rdy verify` | `rdy run` would accept the spec with no override, with the same `--key`. | The signature does not match, or no trusted key signed the spec. |
| `rdy trust add` | The key is saved. | You did not confirm, there is no terminal and no `--yes`, the file is a secret key, or the product already has a key with this key id. |

For the full list, see [Exit codes](../run/exit-codes.md).
