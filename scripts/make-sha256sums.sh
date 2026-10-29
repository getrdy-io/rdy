#!/bin/sh
# make-sha256sums.sh: print the SHA256SUMS text for a release folder (M1-010).
#
# Usage: scripts/make-sha256sums.sh <dir>
# One line per file in <dir>: "<sha256>  <name>" (two spaces, the format `sha256sum -c` and
# `shasum -a 256 -c` read), in byte order of the names. SHA256SUMS and SHA256SUMS.sigstore.json are
# left out, so the list is the same before and after signing. Folders, symlinks and names that
# are not plain file names stop the script. sign-release.sh writes the output to SHA256SUMS, and
# check-release-artifacts.sh --files-only --signed compares it with the file in the folder to
# be published.
# Exit: 0 ok, 1 an unsafe entry, 64 usage error or a missing tool.

set -eu

LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
    echo "usage: scripts/make-sha256sums.sh <dir>" >&2
    exit 64
fi
dir=${1%/}
if [ ! -d "$dir" ]; then
    echo "error: $dir is not a directory" >&2
    echo "fix: pass the folder with the release assets" >&2
    exit 64
fi
if command -v sha256sum > /dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{ print $1 }'; }
elif command -v shasum > /dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }
else
    echo "error: neither sha256sum nor shasum is installed" >&2
    echo "fix: install coreutils (sha256sum) or perl (shasum)" >&2
    exit 64
fi

cd "$dir"
# The shell expands each pattern in byte order under LC_ALL=C. * skips names that start with a dot,
# so the first two patterns find them, and they stop the script.
for f in .[!.]* ..?* *; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    case $f in
        SHA256SUMS | SHA256SUMS.sigstore.json) continue ;;
        *[!A-Za-z0-9._-]* | -* | .*)
            echo "error: '$f' is not a plain release file name" >&2
            echo "fix: remove it and find out what wrote it" >&2
            exit 1
            ;;
        *) ;;
    esac
    if [ -L "$f" ] || [ ! -f "$f" ]; then
        echo "error: '$f' is not a regular file" >&2
        echo "fix: remove it and find out what wrote it" >&2
        exit 1
    fi
    printf '%s  %s\n' "$(sha256_of "$f")" "$f"
done
