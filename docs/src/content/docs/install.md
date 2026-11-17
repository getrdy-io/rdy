---
title: Install
description: Install rdy on Linux or macOS with the release install script, confirm it runs, and install by hand on a host with no network.
---

After you read this page, you can install `rdy` from a release, confirm that it runs, and know what to do when the install script stops.

## Before you start

You need:

- Linux or macOS, on x86_64 or arm64.
- `curl` and `sh`.
- cosign 3.1.3 or newer on your `PATH`. Follow the [cosign installation guide](https://docs.sigstore.dev/cosign/system_config/installation/). The install script checks the release signature with cosign, and it stops without it.
- A user account. Do not run the install as root. If you must, read the root note below.

rdy installs one file, `rdy`. It has no daemon and it needs no runtime.

## Choose a release

Each release has an `install.sh` file. Its address looks like this, where `<tag>` is the release tag, for example `v0.1.0`:

`https://github.com/getrdy-io/rdy/releases/download/<tag>/install.sh`

Find the tag on the [releases page](https://github.com/getrdy-io/rdy/releases). Set the address in `RDY_INSTALL_URL`. The next block reads that variable.

## Install

```sh install-only
curl --proto '=https' --tlsv1.2 -sSf "$RDY_INSTALL_URL" | sh
```

The script checks the signature of the release's checksum list with cosign. Then it checks the hash of the archive. It installs nothing until both checks pass. It installs `rdy` to `$HOME/.local/bin`.

If the install stops, it prints the reason and the fix. It exits 1 and leaves no file behind.

## Confirm the install

```sh install-only
"$HOME/.local/bin/rdy" version
```

The output names the version you installed. If `rdy` is not on your `PATH`, run it by its full path, as this block does.

## Root

The script refuses to run as root. To install as root, add `--allow-root` after `sh -s --`:

`curl --proto '=https' --tlsv1.2 -sSf "$RDY_INSTALL_URL" | sh -s -- --allow-root`

A root install goes to `/usr/local/bin`. The script never runs `sudo`. It never edits a shell profile.

## Install by hand

Use this route when the host has no network, or when you do not want to run a script.

1. On a connected machine, get the release files: `SHA256SUMS`, `SHA256SUMS.sigstore.json` and the archive for your platform.
2. On the same machine, run `scripts/verify-release.sh <tag>` from a checkout of the repository. Read the script first. The release steps in `RELEASING.md` show the full form. The script checks the signature of `SHA256SUMS` and the hash of each file.
3. Copy the files to the host. On the host, check the archive against its line in `SHA256SUMS`.
4. Unpack the archive. Move the `rdy` file to a folder on your `PATH`.

A failed check means the file changed. Do not use it. Get the release again.

## Platforms

| Platform | Install script | Archive on the release page |
| --- | --- | --- |
| Linux x86_64 (musl, static) | Yes | Yes |
| Linux arm64 (musl, static) | Yes | Yes |
| macOS arm64 | Yes | Yes |
| macOS x86_64 | Yes | Yes |
| Windows x86_64 | No. Ships in M3 as an install script | Zip |

On Windows, rdy refuses a trust store file that it finds. Read [Unsigned specs](/unsigned/) before you run a spec there.

## Remove rdy

Delete the file: `rm "$HOME/.local/bin/rdy"`. A root install is at `/usr/local/bin/rdy`.
