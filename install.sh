#!/bin/sh
# install.sh: install the rdy binary for this machine. POSIX sh. Needs no root.
#
# Usage:
#   sh install.sh [--allow-root] [--help]
#   curl --proto '=https' --tlsv1.2 -sSf <url of this file> | sh
#   curl --proto '=https' --tlsv1.2 -sSf <url of this file> | sh -s -- --allow-root
#
# In M1 the url is the pinned release asset:
#   https://github.com/getrdy-io/rdy/releases/download/v<VERSION>/install.sh
#
# The contract is docs/plan/06-release-and-distribution.md ("Install and signing contract") and
# docs/adr/0025-install-sh-core.md. In short:
# - Installs one file, <dir>/rdy. The dir is $HOME/.local/bin, or RDY_INSTALL_DIR. Root needs
#   --allow-root and gets /usr/local/bin. It never runs sudo, never edits a shell profile and never
#   sets a setuid bit.
# - Downloads over https only, from the one release URL below. No variable changes the host.
# - Allowed variables: RDY_VERSION, RDY_INSTALL_DIR, RDY_INSECURE_SKIP_SIGNATURE. HOME, TMPDIR and
#   the proxy variables are read by the tools themselves.
# - Order: download, check the signature of SHA256SUMS (seam: verify_signature, M1-015), check the
#   sha256 of the archive against SHA256SUMS, extract, run `rdy version`, install atomically.
# - Everything is written to stderr. Stdout stays empty (except for --help).
# - Exit: 0 installed, 1 failed, 64 bad usage.
#
# Truncation guard (SEC-08): this file holds only assignments and function definitions until the last
# line. The last line calls main with an end marker as its final argument. A copy cut at any byte is a
# syntax error, a command that does not exist, or a call without the marker, and main refuses to run
# without it. Keep the call on the last line and change nothing after it.

set -eu
LC_ALL=C
export LC_ALL
umask 022

# sign-release (M1-010) replaces the placeholder text between the quotes with this release's tag,
# for example v0.1.0-alpha.2. Nothing else in this file changes. A copy that was not stamped has no
# default version, so it needs RDY_VERSION.
RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'

RELEASE_BASE='https://github.com/getrdy-io/rdy/releases/download'
END_MARK='__rdy_end_of_script__'
NL='
'

# Globals. cleanup() runs from a trap, so they are set before anything can fail.
WORK=''
NEW_FILE=''
ALLOW_ROOT=0
UID_NOW=''
VERSION=''
TARGET=''
ARCHIVE=''
DIR=''
DL=''
HASHER=''
BIN=''
NEW_VERSION=''
OLD_VERSION=''

say() {
    printf '%s\n' "$1" >&2
}

# die <what happened> <likely cause> <what to do>
die() {
    printf 'error: %s\n  cause: %s\n  fix: %s\n' "$1" "$2" "$3" >&2
    exit 1
}

cleanup() {
    if [ -n "$NEW_FILE" ]; then
        rm -f "$NEW_FILE"
    fi
    if [ -n "$WORK" ]; then
        rm -rf "$WORK"
    fi
}

usage() {
    cat << 'EOF'
Install the rdy binary.

Usage: install.sh [--allow-root] [--help]

  --allow-root   Allow a run as root. The binary goes to /usr/local/bin.
  --help         Show this text.

Installs to $HOME/.local/bin, or to RDY_INSTALL_DIR if you set it.
RDY_VERSION picks a release. RDY_INSECURE_SKIP_SIGNATURE=1 skips the
signature check only. It does not skip the sha256 check.
When you pipe the script into sh, pass flags after "-s --":
  curl --proto '=https' --tlsv1.2 -sSf <url> | sh -s -- --allow-root
EOF
}

# The last argument must be the end marker. A cut copy of this file cannot have it.
require_end_marker() {
    last=''
    for arg in "$@"; do
        last=$arg
    done
    if [ "$last" != "$END_MARK" ]; then
        die "this script was cut off before its last line. Nothing was installed." \
            "the download stopped early, or the file was changed." \
            "run the download again. Do not run a partial file."
    fi
}

parse_args() {
    for arg in "$@"; do
        case $arg in
            "$END_MARK") ;;
            --allow-root) ALLOW_ROOT=1 ;;
            --help | -h)
                usage
                exit 0
                ;;
            *)
                say "error: unknown option: $arg"
                say "  fix: use --allow-root or --help. With a pipe: curl ... | sh -s -- --allow-root"
                exit 64
                ;;
        esac
    done
}

refuse_root() {
    UID_NOW=$(id -u 2> /dev/null) || UID_NOW=''
    case $UID_NOW in
        '' | *[!0-9]*)
            die "could not tell which user is running this script." \
                "the id command is missing or printed something unexpected." \
                "install coreutils (or busybox) and run the script again."
            ;;
    esac
    if [ "$UID_NOW" = 0 ] && [ "$ALLOW_ROOT" != 1 ]; then
        die "install.sh will not run as root unless you ask for it." \
            "the user id is 0 (a root shell, or sudo)." \
            "run it as a normal user, or pass --allow-root to install in /usr/local/bin (curl ... | sh -s -- --allow-root)."
    fi
}

resolve_version() {
    v=${RDY_VERSION:-}
    if [ -z "$v" ]; then
        case $RDY_STAMPED_VERSION in
            '' | @@*)
                die "this copy of install.sh has no version." \
                    "it was not taken from a release, so no version is stamped into it." \
                    "set RDY_VERSION, for example RDY_VERSION=0.1.0-alpha.2, or use the install.sh from a release."
                ;;
        esac
        v=$RDY_STAMPED_VERSION
    fi
    v=${v#v}
    # Only these characters reach the download URL, so a value cannot add a path or a host.
    case $v in
        '' | *[!0-9A-Za-z.-]* | *..*)
            die "the version is not valid: $v" \
                "a version has digits, letters, dots and dashes only, such as 0.1.0-alpha.2." \
                "fix RDY_VERSION, or unset it to use the version stamped into this script."
            ;;
        [0-9]*.[0-9]*.[0-9]*) ;;
        *)
            die "the version is not valid: $v" \
                "a version looks like 0.1.0 or 0.1.0-alpha.2." \
                "fix RDY_VERSION, or unset it to use the version stamped into this script."
            ;;
    esac
    VERSION=$v
}

detect_target() {
    os=$(uname -s 2> /dev/null) || os=unknown
    arch=$(uname -m 2> /dev/null) || arch=unknown
    case $arch in
        x86_64 | amd64) cpu=x86_64 ;;
        aarch64 | arm64) cpu=aarch64 ;;
        *)
            die "this CPU is not supported: $arch" \
                "rdy is built for x86_64 and aarch64 only." \
                "run it on a supported machine, or ask your vendor for another route."
            ;;
    esac
    case $os in
        Linux)
            # Linux always gets the static musl build, so there is no libc to detect.
            TARGET="$cpu-unknown-linux-musl"
            ;;
        Darwin)
            # A shell started under Rosetta reports x86_64 on an Apple silicon Mac.
            if [ "$cpu" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2> /dev/null || true)" = 1 ]; then
                cpu=aarch64
            fi
            TARGET="$cpu-apple-darwin"
            ;;
        *)
            die "this operating system is not supported: $os" \
                "install.sh handles Linux and macOS. A Windows installer comes later." \
                "on Windows, download the .zip from the release page and check its sha256 by hand."
            ;;
    esac
    ARCHIVE="rdy-$TARGET.tar.gz"
}

resolve_install_dir() {
    if [ -n "${RDY_INSTALL_DIR:-}" ]; then
        DIR=$RDY_INSTALL_DIR
    elif [ "$UID_NOW" = 0 ]; then
        DIR=/usr/local/bin
    elif [ -n "${HOME:-}" ]; then
        DIR=$HOME/.local/bin
    else
        die "there is no place to install to." \
            "HOME is not set." \
            "set RDY_INSTALL_DIR to a folder you own, for example RDY_INSTALL_DIR=/opt/tools/bin."
    fi
    case $DIR in
        /*) ;;
        *)
            die "the install folder is not an absolute path: $DIR" \
                "RDY_INSTALL_DIR or HOME holds a relative path." \
                "use a path that starts with /."
            ;;
    esac
    DIR=${DIR%/}
    if [ -z "$DIR" ]; then
        die "refusing to install into /." \
            "the install folder is the root folder." \
            "set RDY_INSTALL_DIR to a folder such as /usr/local/bin."
    fi
}

pick_hash_tool() {
    if command -v sha256sum > /dev/null 2>&1; then
        HASHER=sha256sum
    elif command -v shasum > /dev/null 2>&1; then
        HASHER=shasum
    elif command -v openssl > /dev/null 2>&1; then
        HASHER=openssl
    else
        die "no tool to compute a sha256 was found." \
            "none of sha256sum, shasum or openssl is on PATH." \
            "install coreutils (sha256sum), perl (shasum) or openssl, then run the script again."
    fi
}

# Prefer curl. wget counts only if it can refuse plain http (GNU wget); busybox wget cannot.
pick_downloader() {
    if command -v curl > /dev/null 2>&1; then
        DL=curl
    elif command -v wget > /dev/null 2>&1 && wget --help 2>&1 | grep -q -e '--https-only'; then
        DL=wget
        # wget reads the lower case name only.
        if [ -z "${https_proxy:-}" ] && [ -n "${HTTPS_PROXY:-}" ]; then
            https_proxy=$HTTPS_PROXY
            export https_proxy
        fi
    else
        die "no download tool was found." \
            "neither curl nor a wget with --https-only is on PATH." \
            "install curl, then run the script again."
    fi
}

# fetch <name>: download one release asset into the work folder. Both tools honor HTTPS_PROXY.
fetch() {
    url="$RELEASE_BASE/v$VERSION/$1"
    rc=0
    case $DL in
        curl)
            curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
                --connect-timeout 20 --retry 2 -o "$WORK/$1" "$url" < /dev/null || rc=$?
            ;;
        wget)
            wget --https-only --secure-protocol=TLSv1_2 -q -O "$WORK/$1" "$url" < /dev/null || rc=$?
            ;;
    esac
    if [ "$rc" = 0 ]; then
        return 0
    fi
    case $DL:$rc in
        curl:35 | curl:51 | curl:58 | curl:59 | curl:60 | curl:77 | curl:83 | curl:90 | curl:91 | wget:5)
            die "could not make a secure connection to download $1." \
                "a proxy that re-signs TLS, or a CA bundle that does not trust it (exit $rc)." \
                "point SSL_CERT_FILE or CURL_CA_BUNDLE at your CA bundle, or download the files by hand and check them (see the docs)."
            ;;
        curl:22 | wget:8)
            die "the release has no file named $1 for version $VERSION." \
                "the version does not exist, the release is not finished, or this platform has no build." \
                "check RDY_VERSION and the release page. Nothing was installed."
            ;;
        *)
            die "could not download $1 (exit $rc)." \
                "the network is down, a firewall blocks github.com, or the proxy is not set." \
                "check the connection. Behind a proxy, set HTTPS_PROXY. Nothing was installed."
            ;;
    esac
}

# SEAM FOR M1-015. Called after SHA256SUMS is downloaded and before anything is trusted.
# Contract: return 0 only when the signature of the file $1 (SHA256SUMS) was verified for release
# $2 with cosign and the exact signer identity from docs/plan/06. In every other case it exits 1 with
# the documented message. M1-015 downloads SHA256SUMS.sigstore.json in main, replaces the body of
# this function with the cosign check, and keeps RDY_INSECURE_SKIP_SIGNATURE=1 as the only override.
# Until then this copy cannot check a signature, so it behaves as if cosign were missing: it stops,
# unless the override is set. The override never skips the sha256 check.
verify_signature() {
    if [ "${RDY_INSECURE_SKIP_SIGNATURE:-}" = 1 ]; then
        say "WARNING: RDY_INSECURE_SKIP_SIGNATURE=1 is set. The signature of SHA256SUMS is NOT checked."
        say "  Only the sha256 of the archive is checked, against a list from the same place."
        say "  That does not prove who built the file. Use this only on a host you control."
        return 0
    fi
    die "this copy of install.sh cannot check the release signature yet." \
        "the cosign check is not built into this version of the script." \
        "use an install.sh from a later release, or set RDY_INSECURE_SKIP_SIGNATURE=1 to check the sha256 only."
}

sha256_of() {
    case $HASHER in
        sha256sum) sha256sum "$1" | awk '{ print $1 }' ;;
        shasum) shasum -a 256 "$1" | awk '{ print $1 }' ;;
        openssl) openssl dgst -sha256 "$1" | awk '{ print $NF }' ;;
    esac
}

is_sha256() {
    case $1 in
        *[!0-9a-f]*) return 1 ;;
    esac
    [ "${#1}" -eq 64 ]
}

# The archive's hash must equal the one SHA256SUMS line whose file name is exactly the archive name.
# No such line, or two, or a hash that is not 64 lowercase hex digits, stops the install.
verify_archive_hash() {
    sums="$WORK/SHA256SUMS"
    wanted=$(awk -v f="$ARCHIVE" '
        { n = $2; if (substr(n, 1, 1) == "*") n = substr(n, 2) }
        NF == 2 && n == f { print $1 }
    ' "$sums")
    if [ -z "$wanted" ]; then
        die "SHA256SUMS has no line for $ARCHIVE." \
            "the release looks incomplete, or it has no build for this platform." \
            "do not use this download. Check the release page, or tell your vendor."
    fi
    case $wanted in
        *"$NL"*)
            die "SHA256SUMS has more than one line for $ARCHIVE." \
                "the list is malformed or was changed." \
                "do not use this download. Tell your vendor."
            ;;
    esac
    if ! is_sha256 "$wanted"; then
        die "SHA256SUMS holds a malformed hash for $ARCHIVE." \
            "the list is malformed or was changed." \
            "do not use this download. Tell your vendor."
    fi
    actual=$(sha256_of "$WORK/$ARCHIVE") || actual=''
    if ! is_sha256 "$actual"; then
        die "could not compute the sha256 of $ARCHIVE." \
            "$HASHER failed or printed something unexpected." \
            "check the disk and the tool, then run the script again."
    fi
    if [ "$actual" != "$wanted" ]; then
        die "the sha256 of $ARCHIVE does not match SHA256SUMS." \
            "the download is damaged, or the file was replaced on the way." \
            "do not run this file. Nothing was installed. Download again, and tell your vendor if it repeats."
    fi
    say "sha256 ok: $ARCHIVE"
}

extract_binary() {
    mkdir "$WORK/x"
    if ! tar -xzf "$WORK/$ARCHIVE" -C "$WORK/x" "rdy-$TARGET/rdy" < /dev/null 2> /dev/null; then
        die "could not unpack rdy from $ARCHIVE." \
            "the archive is damaged or does not hold rdy-$TARGET/rdy." \
            "download again. If it repeats, tell your vendor."
    fi
    BIN="$WORK/x/rdy-$TARGET/rdy"
    if [ ! -f "$BIN" ] || [ -L "$BIN" ]; then
        die "the archive does not hold a plain file for rdy." \
            "the archive is damaged or was changed." \
            "do not use it. Tell your vendor."
    fi
    # Nothing was executable until now, and the hash had already passed.
    chmod 0755 "$BIN"
}

# Run the new binary once from the work folder, before it goes anywhere. It must name the version
# that was asked for.
check_binary() {
    out=$("$BIN" version < /dev/null 2> /dev/null) || out=''
    out=${out%%"$NL"*}
    case $out in
        "rdy $VERSION" | "rdy $VERSION "*) NEW_VERSION=$out ;;
        '')
            die "the new rdy did not run." \
                "TMPDIR is mounted noexec, or the file does not fit this machine." \
                "set TMPDIR to a folder you can run programs from, for example TMPDIR=\$HOME/tmp, and try again."
            ;;
        *)
            die "the new rdy reports a different version: $out" \
                "the archive does not match release $VERSION." \
                "do not use it. Nothing was installed. Tell your vendor."
            ;;
    esac
}

install_binary() {
    dest="$DIR/rdy"
    if [ -d "$dest" ]; then
        die "$dest is a folder." \
            "something else lives where the rdy binary goes." \
            "move it away, or set RDY_INSTALL_DIR to another folder."
    fi
    if ! mkdir -p "$DIR" 2> /dev/null; then
        die "could not create $DIR." \
            "you may not have write access, or a file is in the way." \
            "set RDY_INSTALL_DIR to a folder you own. This script never uses sudo."
    fi
    # The new file is made next to the old one, so the final mv is an atomic replace.
    if ! NEW_FILE=$(mktemp "$DIR/.rdy.new.XXXXXX" 2> /dev/null); then
        NEW_FILE=''
        die "could not write into $DIR." \
            "you may not have write access to it." \
            "set RDY_INSTALL_DIR to a folder you own. This script never uses sudo."
    fi
    OLD_VERSION=''
    if [ -f "$dest" ] && [ -x "$dest" ]; then
        OLD_VERSION=$("$dest" version < /dev/null 2> /dev/null) || OLD_VERSION=''
        OLD_VERSION=${OLD_VERSION%%"$NL"*}
    fi
    if ! cp "$BIN" "$NEW_FILE" || ! chmod 0755 "$NEW_FILE" || ! mv -f "$NEW_FILE" "$dest"; then
        die "could not write $dest." \
            "the disk is full or $DIR is read-only." \
            "free space or pick another folder with RDY_INSTALL_DIR. The old file, if any, is unchanged."
    fi
    NEW_FILE=''
}

finish() {
    if [ -n "$OLD_VERSION" ]; then
        say "Replaced $OLD_VERSION with $NEW_VERSION"
    fi
    say "Installed $NEW_VERSION at $DIR/rdy"
    case ":${PATH:-}:" in
        *":$DIR:"*) ;;
        *)
            say "note: $DIR is not on your PATH."
            say "  To run rdy by name, add it to your shell profile yourself:"
            say "    export PATH=\"$DIR:\$PATH\""
            ;;
    esac
    say "Next: \"$DIR/rdy\" run <spec>"
}

main() {
    require_end_marker "$@"
    parse_args "$@"
    refuse_root
    resolve_version
    detect_target
    resolve_install_dir
    pick_hash_tool
    pick_downloader

    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    say "Installing rdy $VERSION ($TARGET) to $DIR"
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/rdy-install.XXXXXX") || die \
        "could not make a temporary folder." \
        "TMPDIR (or /tmp) is missing or not writable." \
        "set TMPDIR to a folder you can write to."
    fetch "$ARCHIVE"
    fetch SHA256SUMS
    verify_signature "$WORK/SHA256SUMS" "$VERSION"
    verify_archive_hash
    extract_binary
    check_binary
    install_binary
    finish
}

main "$@" "$END_MARK"
