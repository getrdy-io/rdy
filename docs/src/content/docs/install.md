---
title: Install
description: Install rdy on Linux or macOS with the release install script, confirm it runs, and install by hand on a host with no network. Windows has a zip.
---

After you read this page, you can install `rdy` from a release, confirm that it runs, and know what to do when the install script stops.

## Before you start

You need:

- Linux or macOS, on x86_64 or arm64, or Windows x86_64 (see [Windows](#windows)).
- `curl` and `sh`.
- cosign 3.1.3 or newer on your `PATH`. Follow the [cosign installation guide](https://docs.sigstore.dev/cosign/system_config/installation/). The install script checks the release signature with cosign, and it stops without it.
- A user account. Do not run the install as root. If you must, read the root note below.

rdy installs one file, `rdy`. It has no daemon and it needs no runtime.

## Choose a release

Each release has an `install.sh` file. Its address has this form, where `<tag>` is the release tag, for example `v0.1.0`:

```sh
RDY_INSTALL_URL=https://github.com/getrdy-io/rdy/releases/download/<tag>/install.sh
```

Find the tag on the [releases page](https://github.com/getrdy-io/rdy/releases). Use only an address under `github.com/getrdy-io/rdy/releases`. If someone sends you another address, do not run it.

## Install

```sh install-only
curl --proto '=https' --tlsv1.2 -sSf "${RDY_INSTALL_URL:?set RDY_INSTALL_URL to the install.sh address of a release}" | sh
```

The script checks the signature of the release's checksum list with cosign. Then it checks the hash of the archive. It installs nothing until both checks pass. It installs `rdy` to `$HOME/.local/bin`.

If the install stops, it prints the reason and the fix. It exits 1 and leaves no file behind.

## Confirm the install

```sh install-only
"$HOME/.local/bin/rdy" version
```

The output names the version you installed.

## Put rdy on your PATH

The script does not edit your shell profile. If `rdy` is not found, add the folder to your `PATH`:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Put that line in your shell profile to keep it. The other pages assume `rdy` is on your `PATH`.

## Root

The script refuses to run as root. To install as root, add `--allow-root` after `sh -s --`:

```sh
curl --proto '=https' --tlsv1.2 -sSf "$RDY_INSTALL_URL" | sh -s -- --allow-root
```

A root install goes to `/usr/local/bin`. The script never runs `sudo`. It never edits a shell profile.

## Install by hand

Use this route when the host has no network, or when you do not want to run a script.

1. On a connected machine, make one empty folder. Download every file of the release into it. That is `SHA256SUMS`, `SHA256SUMS.sigstore.json` and every archive. Do not use the files from another folder.
2. Check the folder against the signature. Use a checkout of `main` that you have read. Run `scripts/verify-release.sh --dir <folder> <tag>`. The script needs every file that `SHA256SUMS` lists. The [release steps in RELEASING.md](https://github.com/getrdy-io/rdy/blob/main/RELEASING.md#every-release) describe the script and its output.
3. Copy the folder to the host. On the host, check each file against `SHA256SUMS`. Run one of these from the folder:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

   On macOS, run `shasum -a 256 -c --ignore-missing SHA256SUMS`.

4. Unpack the archive for your platform. Move the `rdy` file to a folder on your `PATH`.

A failed check means a file changed. Do not use it. Get the release again.

## Windows

The Windows install script ships in M3. In M1, install by hand from the zip. Use PowerShell.

1. On a connected machine, download the zip, `SHA256SUMS` and `SHA256SUMS.sigstore.json` into one empty folder.
2. Check the folder with `scripts/verify-release.sh --dir <folder> <tag>`, as in step 2 above. That script runs under bash, so use Git Bash or WSL on that machine.
3. Copy the folder to the Windows host. Compare the hash of the zip with its line in `SHA256SUMS`:

   ```powershell
   Get-FileHash -Algorithm SHA256 .\rdy-x86_64-pc-windows-msvc.zip
   ```

   The hash must match the line for the zip in `SHA256SUMS`. If it does not, do not use the zip.
4. Unzip the file. Move `rdy.exe` to a folder on your `PATH`.

On Windows, rdy refuses a trust store file that it finds. Read [Unsigned specs](unsigned.md) before you run a spec there.

## Platforms

| Platform | Install script | Archive on the release page |
| --- | --- | --- |
| Linux x86_64 (musl, static) | Yes | Yes |
| Linux arm64 (musl, static) | Yes | Yes |
| macOS arm64 | Yes | Yes |
| macOS x86_64 | Yes | Yes |
| Windows x86_64 | No. Ships in M3 | Zip, by hand (see above) |

## Next step

<!-- M3: the Starlight site links to these pages with root-relative paths. Convert the links to /x/ then. -->

Run a signed spec. Your vendor sends the spec and a `.minisig` file. Keep both in one folder, then run:

```sh
"$HOME/.local/bin/rdy" run <spec>
```

Read the last line of the output. The [exit codes](run/exit-codes.md) page says what each exit code means.

## Remove rdy

Delete the file: `rm "$HOME/.local/bin/rdy"`. A root install is at `/usr/local/bin/rdy`.
