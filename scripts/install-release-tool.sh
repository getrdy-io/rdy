#!/bin/sh
# install-release-tool.sh: install a pinned release tool for CI after checking its sha256 (ADR 0020).
#
# Usage: scripts/install-release-tool.sh <tool> [<table>]
#   <tool>   dist, cargo-cyclonedx or cosign
#   <table>  the pin file. Default: .github/release-tools.txt next to this script's repo root.
# It picks the file for this OS and CPU from the table, downloads it over HTTPS, checks the hash and
# only then unpacks it and copies the program to $HOME/.cargo/bin. A hash that does not match
# installs nothing. The release workflow and the release-workflow CI job use it in place of
# `curl | sh`.
# Exit: 0 installed, 1 failed, 64 usage error.

set -eu

LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: scripts/install-release-tool.sh <tool> [<table>]" >&2
    exit 64
fi
tool=$1
table=${2:-$here/../.github/release-tools.txt}

case $tool in
    dist) program=dist ;;
    cargo-cyclonedx) program=cargo-cyclonedx ;;
    cosign) program=cosign ;;
    *)
        echo "error: unknown tool '$tool'" >&2
        echo "fix: use dist, cargo-cyclonedx or cosign, or add the tool to $table" >&2
        exit 64
        ;;
esac
if [ ! -f "$table" ]; then
    echo "error: $table does not exist" >&2
    echo "fix: run the script from a full checkout" >&2
    exit 64
fi

os=$(uname -s)
cpu=$(uname -m)
case "$os/$cpu" in
    Linux/x86_64) triple=x86_64-unknown-linux-musl ;;
    Linux/aarch64 | Linux/arm64) triple=aarch64-unknown-linux-musl ;;
    Darwin/x86_64) triple=x86_64-apple-darwin ;;
    Darwin/arm64 | Darwin/aarch64) triple=aarch64-apple-darwin ;;
    MINGW* | MSYS* | CYGWIN*) triple=x86_64-pc-windows-msvc ;;
    *)
        echo "error: no pinned $tool for $os on $cpu" >&2
        echo "fix: add a line to $table with the file and its sha256" >&2
        exit 1
        ;;
esac
case $triple in
    *windows*) program=$program.exe ;;
    *) ;;
esac

# The text that marks this platform in a file name. cosign publishes bare programs named
# cosign-<os>-<cpu>, so it does not use the target triple.
key=$triple
if [ "$tool" = cosign ]; then
    case $triple in
        x86_64-unknown-linux-musl) key=linux-amd64 ;;
        aarch64-unknown-linux-musl) key=linux-arm64 ;;
        x86_64-apple-darwin) key=darwin-amd64 ;;
        aarch64-apple-darwin) key=darwin-arm64 ;;
        *)
            echo "error: no pinned cosign for $os on $cpu" >&2
            echo "fix: install cosign by hand from its release page and check the hash" >&2
            exit 1
            ;;
    esac
fi

# The line for this tool and platform: <tool> <version> <file> <sha256> <url>.
line=$(awk -v t="$tool" -v s="$key" '$1 == t && index($3, s) > 0 { print; exit }' "$table")
if [ -z "$line" ]; then
    echo "error: $table has no $tool for $key" >&2
    echo "fix: add a line with the file name, its sha256 and its URL" >&2
    exit 1
fi
version=$(printf '%s\n' "$line" | awk '{ print $2 }')
file=$(printf '%s\n' "$line" | awk '{ print $3 }')
want=$(printf '%s\n' "$line" | awk '{ print $4 }')
url=$(printf '%s\n' "$line" | awk '{ print $5 }')
case $want in
    *[!0-9a-f]*)
        echo "error: the hash for $file is not lower-case hex" >&2
        echo "fix: correct the line in $table" >&2
        exit 1
        ;;
    *) ;;
esac
if [ "${#want}" -ne 64 ]; then
    echo "error: the hash for $file is not 64 characters" >&2
    echo "fix: correct the line in $table" >&2
    exit 1
fi
case $url in
    https://*) ;;
    *)
        echo "error: the URL for $file is not https" >&2
        echo "fix: correct the line in $table" >&2
        exit 1
        ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

echo "downloading $tool $version ($file)"
if ! curl --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 300 --retry 3 -fsSL -o "$work/$file" "$url"; then
    echo "error: could not download $url" >&2
    echo "fix: check the network, then re-run. Nothing was installed." >&2
    exit 1
fi

if command -v sha256sum > /dev/null 2>&1; then
    got=$(sha256sum "$work/$file" | awk '{ print $1 }')
else
    got=$(shasum -a 256 "$work/$file" | awk '{ print $1 }')
fi
if [ "$got" != "$want" ]; then
    echo "error: $file has sha256 $got, the pin is $want" >&2
    echo "fix: do not run this file. If the project re-issued the release, check it by hand, then update $table. Nothing was installed." >&2
    exit 1
fi
echo "sha256 ok: $file"

mkdir "$work/x"
case $file in
    cosign-*-*)
        # A bare program, not an archive. The hash above is the only check on it.
        cp "$work/$file" "$work/x/$program"
        ;;
    *.tar.xz) tar -xJf "$work/$file" -C "$work/x" ;;
    *.zip)
        if command -v unzip > /dev/null 2>&1; then
            unzip -q "$work/$file" -d "$work/x"
        else
            powershell.exe -NoProfile -Command "Expand-Archive -LiteralPath '$(cygpath -w "$work/$file")' -DestinationPath '$(cygpath -w "$work/x")'"
        fi
        ;;
    *)
        echo "error: unknown file type: $file" >&2
        echo "fix: use .tar.xz, .zip or a bare cosign program in $table" >&2
        exit 1
        ;;
esac

found=$(find "$work/x" -type f -name "$program" | head -n 1)
if [ -z "$found" ]; then
    echo "error: $file holds no $program" >&2
    echo "fix: check the archive layout and $table" >&2
    exit 1
fi
dest=${HOME}/.cargo/bin
mkdir -p "$dest"
cp "$found" "$dest/$program"
chmod 755 "$dest/$program"
echo "installed $dest/$program ($tool $version)"
