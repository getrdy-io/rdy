#!/bin/sh
# verify-release.sh: check a published release of getrdy-io/rdy from nothing but the tag (M1-012).
#
# Usage: scripts/verify-release.sh [--dir <folder>] <tag>
#   <tag>   the release tag, for example v0.1.0-alpha.1
#   --dir   do not download. Check the assets that are already in <folder> (a release you carried
#           across, or one fetched with `gh release download`). The folder is only read.
#
# What it does, in order. Any failure stops it with exit 1 and a fix line, and nothing from the
# release is run or installed:
#   1. Download SHA256SUMS and SHA256SUMS.sigstore.json with curl (https only, TLS 1.2 or newer,
#      from github.com/getrdy-io/rdy, no other host).
#   2. Check the signature with cosign 3 or newer, with the full identity contract from 06 and
#      SECURITY.md. All five parts are required. Without the last three, a workflow in another
#      repository that calls our reusable workflow would pass:
#        --certificate-oidc-issuer https://token.actions.githubusercontent.com
#        --certificate-identity https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/<tag>
#        --certificate-github-workflow-repository getrdy-io/rdy
#        --certificate-github-workflow-ref refs/tags/<tag>
#        --certificate-github-workflow-trigger push
#      The repository is fixed in this script. No flag or variable changes it, and none changes the
#      download host.
#   3. Only after the signature passes, read SHA256SUMS. Every line must be "<sha256>  <name>" with a
#      plain file name. The five release archives must be listed.
#   4. Download every listed file and compare its sha256 with its line. Nothing is extracted.
# It prints the sha256 of SHA256SUMS and the Rekor log index of the signature. The founder publishes
# both out of band for each release (06, trust roots).
#
# Needs: cosign 3 or newer (`sh scripts/install-release-tool.sh cosign` installs the pinned one), curl
# (not with --dir), awk, grep, mktemp, and sha256sum or shasum. jq is optional (the Rekor index).
# Environment: TUF_ROOT is honored. By default cosign's trust root cache goes to a temporary folder,
# so nothing is left in ~/.sigstore.
# Exit: 0 verified, 1 a check or a download failed, 64 usage error or a missing tool.

set -u

LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)

# The contract. Keep equal to docs/plan/06-release-and-distribution.md and scripts/sign-release.sh.
repo=getrdy-io/rdy
issuer=https://token.actions.githubusercontent.com
base="https://github.com/$repo/releases/download"
# The five release targets (ADR 0006, decision 1). Keep this list equal to dist-workspace.toml.
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc"

usage() {
    echo "usage: scripts/verify-release.sh [--dir <folder>] <tag>" >&2
    echo "example: scripts/verify-release.sh v0.1.0-alpha.1" >&2
    exit 64
}

die() {
    printf 'error: %s\n' "$1" >&2
    printf 'fix: %s\n' "$2" >&2
    exit 1
}

dir_arg=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --dir)
            [ "$#" -ge 2 ] || usage
            dir_arg=$2
            shift 2
            ;;
        -h | --help)
            echo "usage: scripts/verify-release.sh [--dir <folder>] <tag>"
            exit 0
            ;;
        -*) usage ;;
        *) break ;;
    esac
done
[ "$#" -eq 1 ] || usage
tag=$1

if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    echo "error: '$tag' is not a release tag" >&2
    echo "fix: tags look like v0.1.0-alpha.1, with the v" >&2
    exit 64
fi
if [ -n "$dir_arg" ] && [ ! -d "$dir_arg" ]; then
    echo "error: $dir_arg is not a directory" >&2
    echo "fix: pass the folder that holds the downloaded release assets" >&2
    exit 64
fi

for tool in cosign awk grep mktemp; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "error: $tool is not installed" >&2
        if [ "$tool" = cosign ]; then
            echo "fix: run 'sh scripts/install-release-tool.sh cosign' (it installs the pinned version to \$HOME/.cargo/bin), then put that folder on PATH. This script does not skip the signature check." >&2
        else
            echo "fix: install $tool from your package manager" >&2
        fi
        exit 64
    fi
done
if [ -z "$dir_arg" ] && ! command -v curl > /dev/null 2>&1; then
    echo "error: curl is not installed" >&2
    echo "fix: install curl, or download the release by hand and run this script with --dir <folder>" >&2
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

# cosign 3 or newer. A different version from the pin is allowed, with a note.
cosign_version=$(cosign version 2> /dev/null | awk '/GitVersion:/ { print $2; exit }')
cosign_major=${cosign_version#v}
cosign_major=${cosign_major%%.*}
case $cosign_major in
    '' | *[!0-9]*)
        echo "error: cannot read the cosign version (got '$cosign_version')" >&2
        echo "fix: run 'sh scripts/install-release-tool.sh cosign' and use that cosign" >&2
        exit 64
        ;;
    *) ;;
esac
if [ "$cosign_major" -lt 3 ]; then
    echo "error: cosign $cosign_version is too old" >&2
    echo "fix: run 'sh scripts/install-release-tool.sh cosign' to install the pinned cosign 3" >&2
    exit 64
fi
pin_table=$here/../.github/release-tools.txt
if [ -f "$pin_table" ]; then
    pinned=$(awk '$1 == "cosign" { print $2; exit }' "$pin_table")
    if [ -n "$pinned" ] && [ "v$pinned" != "$cosign_version" ]; then
        echo "NOTE: cosign is $cosign_version, the pinned version is v$pinned (sh scripts/install-release-tool.sh cosign)"
    fi
fi

identity="https://github.com/$repo/.github/workflows/sign-release.yml@refs/tags/$tag"
wf_ref="refs/tags/$tag"
wf_trigger=push

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
TUF_ROOT=${TUF_ROOT:-$work/tuf}
export TUF_ROOT

if [ -n "$dir_arg" ]; then
    rel=${dir_arg%/}
else
    rel=$work/release
    mkdir "$rel"
fi

# fetch <name>: download one asset of the tag into $rel. On failure it leaves the HTTP status (or
# 000) in $fetch_code, and returns 1.
fetch_code=000
fetch() {
    fetch_code=000
    if fetch_code=$(curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 600 --retry 3 -fsSL \
        -o "$rel/$1" -w '%{http_code}' "$base/$tag/$1" 2> "$work/curl.err"); then
        return 0
    fi
    rm -f "$rel/$1"
    return 1
}

# fetch_or_die <name> <what a 404 means>
fetch_or_die() {
    if fetch "$1"; then
        return 0
    fi
    if [ "$fetch_code" = 404 ]; then
        die "$1 does not exist for $tag" "$2"
    fi
    sed 's/^/  curl: /' "$work/curl.err" >&2
    die "could not download $base/$tag/$1 (HTTP status $fetch_code)" "check the network and the tag. Behind a proxy, set HTTPS_PROXY, and SSL_CERT_FILE or CURL_CA_BUNDLE for a private CA. Nothing was verified."
}

# 1. The signed list and its bundle.
if [ -n "$dir_arg" ]; then
    echo "checking the files in $rel (no download)"
    for f in SHA256SUMS SHA256SUMS.sigstore.json; do
        if [ -L "$rel/$f" ] || [ ! -f "$rel/$f" ]; then
            if [ "$f" = SHA256SUMS ]; then
                die "$rel/$f is missing" "download SHA256SUMS and SHA256SUMS.sigstore.json from the release page of $tag, into one folder"
            fi
            die "$rel/$f is missing, so this release looks incomplete" "download it from the release page of $tag. If the release has no such file, it was not signed: do not use it."
        fi
    done
else
    echo "downloading the signed list for $tag from github.com/$repo"
    fetch_or_die SHA256SUMS "the tag has no published release. A tag with no release is normal while the signing approval is pending, and after a release that failed. Check the tag name, or wait."
    fetch_or_die SHA256SUMS.sigstore.json "this release looks incomplete: it has SHA256SUMS but no signature. Do not use it. Tell security@getrdy.io."
fi

# 2. The signature, with the full identity contract. Exact strings, no regular expression.
if ! (cd "$rel" && cosign verify-blob \
    --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer" \
    --certificate-github-workflow-repository "$repo" \
    --certificate-github-workflow-ref "$wf_ref" \
    --certificate-github-workflow-trigger "$wf_trigger" \
    SHA256SUMS); then
    die "the signature on SHA256SUMS does not verify as $identity" "do not run or install anything from this release, and tell security@getrdy.io. If the cosign lines above show a network or trust root error instead, fix that and run again."
fi
echo "PASS signature: SHA256SUMS is signed by $identity"
echo "     issuer $issuer, repository $repo, ref $wf_ref, trigger $wf_trigger"

# 3. Read the signed list. Only now is it trusted. Names must be plain, so a line cannot point
# outside the folder.
listed=""
count=0
while IFS= read -r line || [ -n "$line" ]; do
    hash=${line%%  *}
    name=${line#*  }
    if [ "${#hash}" -ne 64 ] || [ "$line" != "$hash  $name" ]; then
        die "SHA256SUMS has a line that is not '<sha256>  <name>': $line" "do not use this release. Tell security@getrdy.io."
    fi
    case $hash in
        *[!0-9a-f]*) die "SHA256SUMS has a hash that is not lower-case hex for $name" "do not use this release. Tell security@getrdy.io." ;;
        *) ;;
    esac
    case $name in
        '' | -* | .* | *[!A-Za-z0-9._-]*) die "SHA256SUMS lists '$name', which is not a plain file name" "do not use this release. Tell security@getrdy.io." ;;
        SHA256SUMS | SHA256SUMS.sigstore.json) die "SHA256SUMS lists $name, which it must not" "do not use this release. Tell security@getrdy.io." ;;
        *) ;;
    esac
    case " $listed " in
        *" $name "*) die "SHA256SUMS lists $name twice" "do not use this release. Tell security@getrdy.io." ;;
        *) ;;
    esac
    listed="$listed $name"
    count=$((count + 1))
done < "$rel/SHA256SUMS"
if [ "$count" -eq 0 ]; then
    die "SHA256SUMS is empty" "do not use this release. Tell security@getrdy.io."
fi
for t in $targets; do
    case $t in
        *-windows-*) a=rdy-$t.zip ;;
        *) a=rdy-$t.tar.gz ;;
    esac
    case " $listed " in
        *" $a "*) ;;
        *) die "SHA256SUMS does not list $a" "this release is missing a build for $t. Do not use it. Tell security@getrdy.io." ;;
    esac
done

# 4. Every listed file, against its line. In download mode the file comes from the release now.
while IFS= read -r line || [ -n "$line" ]; do
    hash=${line%%  *}
    name=${line#*  }
    if [ -z "$dir_arg" ]; then
        fetch_or_die "$name" "SHA256SUMS lists $name but the release has no such file. This release looks incomplete. Do not use it."
    elif [ -L "$rel/$name" ] || [ ! -f "$rel/$name" ]; then
        die "$rel/$name is missing" "SHA256SUMS lists it. Download it from the release page of $tag into $rel."
    fi
    got=$(sha256_of "$rel/$name")
    if [ "$got" != "$hash" ]; then
        die "$name has sha256 $got, SHA256SUMS says $hash" "do not run this file. Download it again. If it still differs, tell security@getrdy.io."
    fi
    echo "PASS sha256 $name"
done < "$rel/SHA256SUMS"
if [ -n "$dir_arg" ]; then
    for f in "$rel"/*; do
        [ -e "$f" ] || continue
        name=${f##*/}
        case $name in
            SHA256SUMS | SHA256SUMS.sigstore.json) continue ;;
            *) ;;
        esac
        case " $listed " in
            *" $name "*) ;;
            *) echo "NOTE: $name is in the folder but not in SHA256SUMS, so it is not verified" ;;
        esac
    done
fi

digest=$(sha256_of "$rel/SHA256SUMS")
rekor=unknown
if command -v jq > /dev/null 2>&1; then
    rekor=$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // "unknown"' "$rel/SHA256SUMS.sigstore.json" 2> /dev/null || echo unknown)
fi
echo "verified $tag: $count files match the signed SHA256SUMS"
echo "  sha256 of SHA256SUMS: $digest"
echo "  rekor log index:      $rekor"
