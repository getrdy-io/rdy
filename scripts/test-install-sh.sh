#!/bin/sh
# test-install-sh.sh: shell tests for install.sh (M1-014, SEC-08, INV-19). Exit 0 when all pass.
#
# Usage: sh scripts/test-install-sh.sh [dash] [busybox]
# With no argument it runs install.sh under every shell it finds: dash and busybox sh.
# A missing shell is a SKIP on a developer machine and a failure in CI ($CI set), so a runner image
# change cannot turn the tests into a silent pass.
#
# Nothing touches the network or the real machine. Each case runs in a clean environment (env -i) with
# a PATH folder made of symlinks to the few tools install.sh needs, plus stubs for curl, wget, id,
# uname and sysctl. A stub curl maps the release URL to a synthetic release folder. In the busybox run
# the tools are busybox applets too, so the script is tried against busybox tar, awk, mktemp and the
# rest, as on Alpine.
#
# Needs on the host: tar, gzip, sha256sum or shasum, head, wc, sed, grep, awk, mktemp.

set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
script="$root/install.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0
casefail=0

VER=0.1.0-alpha.2
A64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
LINUX=x86_64-unknown-linux-musl

for tool in tar gzip head wc sed grep awk mktemp; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "FAIL the test host has no $tool"
        exit 1
    fi
done
if command -v sha256sum > /dev/null 2>&1; then
    host_hash() { sha256sum "$1" | awk '{ print $1 }'; }
else
    host_hash() { shasum -a 256 "$1" | awk '{ print $1 }'; }
fi

# ---------------------------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------------------------
mkdir "$tmp/stubs"

cat > "$tmp/stubs/curl" << 'EOF'
#!/bin/sh
# Stub curl. It logs its arguments, eats stdin like a greedy child would, and serves files from
# $STUB_REL for URLs under the release base. A missing file is an HTTP error (exit 22).
printf 'curl %s\n' "$*" >> "$STUB_LOG"
cat > /dev/null
if [ -n "${STUB_CURL_RC:-}" ]; then exit "$STUB_CURL_RC"; fi
out=''
url=''
while [ "$#" -gt 0 ]; do
    case $1 in
        -o) out=$2; shift 2 ;;
        --proto | --proto-redir | --connect-timeout | --retry) shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
base="https://github.com/getrdy-io/rdy/releases/download/v$STUB_VERSION/"
case $url in
    "$base"*) name=${url#"$base"} ;;
    *) echo "stub curl: unexpected url $url" >&2; exit 7 ;;
esac
[ -f "$STUB_REL/$name" ] || exit 22
cp "$STUB_REL/$name" "$out"
EOF

# A wget that supports --https-only (GNU wget) and one that does not (busybox wget).
cat > "$tmp/stubs/wget" << 'EOF'
#!/bin/sh
if [ "${1:-}" = "--help" ]; then
    echo "GNU Wget stub"
    echo "      --https-only    follow only secure HTTPS links"
    exit 0
fi
printf 'wget %s\n' "$*" >> "$STUB_LOG"
out=''
url=''
while [ "$#" -gt 0 ]; do
    case $1 in
        -O) out=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
base="https://github.com/getrdy-io/rdy/releases/download/v$STUB_VERSION/"
case $url in
    "$base"*) name=${url#"$base"} ;;
    *) echo "stub wget: unexpected url $url" >&2; exit 7 ;;
esac
[ -f "$STUB_REL/$name" ] || exit 8
cp "$STUB_REL/$name" "$out"
EOF
cat > "$tmp/stubs/wget-old" << 'EOF'
#!/bin/sh
if [ "${1:-}" = "--help" ]; then
    echo "BusyBox wget stub"
    exit 0
fi
printf 'wget-old %s\n' "$*" >> "$STUB_LOG"
exit 1
EOF
cat > "$tmp/stubs/id" << 'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then echo "${STUB_UID:-1000}"; exit 0; fi
exit 1
EOF
cat > "$tmp/stubs/uname" << 'EOF'
#!/bin/sh
case ${1:-} in
    -s) echo "${STUB_OS:-Linux}" ;;
    -m) echo "${STUB_ARCH:-x86_64}" ;;
    *) exit 1 ;;
esac
EOF
cat > "$tmp/stubs/sysctl" << 'EOF'
#!/bin/sh
if [ -n "${STUB_TRANSLATED:-}" ]; then echo "$STUB_TRANSLATED"; exit 0; fi
echo "sysctl: unknown oid 'sysctl.proc_translated'" >&2
exit 1
EOF
chmod +x "$tmp/stubs/"*

# ---------------------------------------------------------------------------------------------
# PATH folders
# ---------------------------------------------------------------------------------------------
base_tools="cat chmod cp grep gzip mkdir mktemp mv rm tar awk"

# build_path <dir> <mode: real|busybox> <hash: sha256sum|shasum|openssl|none> <dl: curl|wget|wget-old|none>
build_path() {
    d=$1
    mkdir -p "$d"
    for t in $base_tools; do
        if [ "$2" = busybox ]; then
            ln -s "$BUSYBOX" "$d/$t"
        else
            ln -s "$(command -v "$t")" "$d/$t"
        fi
    done
    case $3 in
        sha256sum)
            if [ "$2" = busybox ]; then ln -s "$BUSYBOX" "$d/sha256sum"; else ln -s "$(command -v sha256sum)" "$d/sha256sum"; fi
            ;;
        shasum | openssl) ln -s "$(command -v "$3")" "$d/$3" ;;
    esac
    case $4 in
        curl | wget | wget-old) ln -s "$tmp/stubs/$4" "$d/${4%-old}" ;;
    esac
    ln -s "$tmp/stubs/id" "$d/id"
    ln -s "$tmp/stubs/uname" "$d/uname"
    ln -s "$tmp/stubs/sysctl" "$d/sysctl"
}

# ---------------------------------------------------------------------------------------------
# Case helpers
# ---------------------------------------------------------------------------------------------
ncase=0

# begin <name>: a fresh home, temp folder and release folder, and the default environment.
begin() {
    ncase=$((ncase + 1))
    CASE="$SHELL_LABEL: $1"
    casefail=0
    cdir="$tmp/c/$SHELL_LABEL-$ncase"
    mkdir -p "$cdir/home" "$cdir/tmp" "$cdir/rel"
    HOME_D="$cdir/home"
    TMP_D="$cdir/tmp"
    REL="$cdir/rel"
    LOG="$cdir/stub.log"
    OUT="$cdir/out"
    ERR="$cdir/err"
    : > "$LOG"
    BIN_D="$HOME_D/.local/bin"
    E="STUB_UID=1000 STUB_OS=Linux STUB_ARCH=x86_64 RDY_VERSION=$VER"
    HASH=sha256sum
    DL=curl
    PATH_SUFFIX=''
    STDIN=''
    TRIPLE=$LINUX
}

addenv() { E="$E $1"; }
skipsig() { addenv RDY_INSECURE_SKIP_SIGNATURE=1; }

# mkrel <ver> <triple> <what the fake rdy prints, or FAIL>: a valid synthetic release in $REL.
mkrel() {
    pkg="$cdir/pkg-$2"
    mkdir -p "$pkg/rdy-$2"
    if [ "$3" = FAIL ]; then
        printf '#!/bin/sh\nexit 3\n' > "$pkg/rdy-$2/rdy"
    else
        printf '#!/bin/sh\necho "rdy %s"\n' "$3" > "$pkg/rdy-$2/rdy"
    fi
    # Mode 0644 on purpose: install.sh must be the one that makes the file executable.
    chmod 644 "$pkg/rdy-$2/rdy"
    echo "synthetic licence" > "$pkg/rdy-$2/LICENSE"
    tar -czf "$REL/rdy-$2.tar.gz" -C "$pkg" "rdy-$2"
    printf 'synthetic installer\n' > "$cdir/decoy"
    # A decoy line for a different archive. It must never be the one that is picked.
    other=aarch64-unknown-linux-musl
    [ "$2" != "$other" ] || other=$LINUX
    h=$(host_hash "$REL/rdy-$2.tar.gz")
    d=$(host_hash "$cdir/decoy")
    {
        printf '%s  rdy-%s.tar.gz\n' "$d" "$other"
        printf '%s  %s\n' "$h" "rdy-$2.tar.gz"
        printf '%s  install.sh\n' "$d"
        printf '%s  rdy.cdx.xml\n' "$d"
    } > "$REL/SHA256SUMS"
}

# defrel: the release for the default case.
defrel() { mkrel "$VER" "$TRIPLE" "$VER"; }

# Run $SHELL_CMD with the given arguments in a clean environment. Sets CODE.
# shellcheck disable=SC2086 # $E and $SHELL_CMD are lists of words on purpose
sh_run() {
    pd="$tmp/path/$SHELL_LABEL-$HASH-$DL"
    if [ ! -d "$pd" ]; then build_path "$pd" "$SHELL_MODE" "$HASH" "$DL"; fi
    env -i PATH="$pd$PATH_SUFFIX" HOME="$HOME_D" TMPDIR="$TMP_D" STUB_LOG="$LOG" STUB_REL="$REL" \
        STUB_VERSION="$VER" $E $SHELL_CMD "$@" > "$OUT" 2> "$ERR" < "${STDIN:-/dev/null}"
    CODE=$?
}

# run [args]: run install.sh as a file.
run() { sh_run "$script" "$@"; }

casebad() {
    casefail=1
    printf '  - %s\n' "$1"
}
want_code() { [ "$CODE" = "$1" ] || casebad "exit code $CODE, want $1"; }
want_err() { grep -F -q -e "$1" "$ERR" || casebad "stderr lacks: $1"; }
want_no_err() { if grep -F -q -e "$1" "$ERR"; then casebad "stderr has: $1"; fi; }
want_out_empty() { [ ! -s "$OUT" ] || casebad "stdout is not empty"; }
want_log() { grep -F -q -e "$1" "$LOG" || casebad "stub log lacks: $1"; }
want_no_net() { [ ! -s "$LOG" ] || casebad "the script made a download call"; }
want_tmp_clean() { [ -z "$(ls -A "$TMP_D")" ] || casebad "temp folder not cleaned: $(ls -A "$TMP_D")"; }
want_nothing_installed() {
    [ -z "$(ls -A "$BIN_D" 2> /dev/null)" ] || casebad "files were installed: $(ls -A "$BIN_D")"
}
want_installed() {
    d=${1:-$BIN_D}
    if [ ! -f "$d/rdy" ] || [ ! -x "$d/rdy" ]; then
        casebad "no executable rdy in $d"
        return
    fi
    [ ! -L "$d/rdy" ] || casebad "rdy is a symlink"
    ls_out=$(ls -A "$d")
    [ "$ls_out" = rdy ] || casebad "extra files in $d: $ls_out"
    [ -n "$(find "$d/rdy" -perm 755 -print)" ] || casebad "the mode of rdy is not 0755"
}
endcase() {
    if [ "$casefail" = 0 ]; then
        printf 'PASS %s\n' "$CASE"
    else
        printf 'FAIL %s\n' "$CASE"
        fail=1
        sed 's/^/    stderr| /' "$ERR" | head -n 12
    fi
}

# ---------------------------------------------------------------------------------------------
# The suite, run once per shell
# ---------------------------------------------------------------------------------------------
suite() {
    # --- happy path -------------------------------------------------------------------------
    begin "installs to \$HOME/.local/bin, stdout empty, temp folder cleaned"
    defrel
    skipsig
    run
    want_code 0
    want_installed
    want_out_empty
    want_tmp_clean
    want_err "Installed rdy $VER at $BIN_D/rdy"
    want_err "$BIN_D is not on your PATH"
    want_err 'Next: '
    want_err 'WARNING: RDY_INSECURE_SKIP_SIGNATURE=1'
    want_err 'sha256 ok'
    out=$("$BIN_D/rdy" version)
    [ "$out" = "rdy $VER" ] || casebad "installed binary prints: $out"
    want_log "--proto =https --proto-redir =https --tlsv1.2 -fsSL"
    want_log "/v$VER/rdy-$LINUX.tar.gz"
    want_log "/v$VER/SHA256SUMS"
    endcase

    begin "no PATH hint when the folder is on PATH"
    defrel
    skipsig
    PATH_SUFFIX=":$BIN_D"
    run
    want_code 0
    want_no_err 'is not on your PATH'
    endcase

    begin "piped into sh -s (the curl | sh route)"
    defrel
    skipsig
    STDIN="$script"
    sh_run -s --
    want_code 0
    want_installed
    want_out_empty
    endcase

    begin "piped into sh -s -- --allow-root as a non-root user"
    defrel
    skipsig
    STDIN="$script"
    sh_run -s -- --allow-root
    want_code 0
    want_installed
    endcase

    begin "replaces an old binary and says both versions"
    defrel
    skipsig
    mkdir -p "$BIN_D"
    printf '#!/bin/sh\necho "rdy 0.0.9"\n' > "$BIN_D/rdy"
    chmod 755 "$BIN_D/rdy"
    run
    want_code 0
    want_installed
    want_err "Replaced rdy 0.0.9 with rdy $VER"
    endcase

    begin "RDY_INSTALL_DIR is used"
    defrel
    skipsig
    addenv "RDY_INSTALL_DIR=$cdir/custom/"
    run
    want_code 0
    want_installed "$cdir/custom"
    want_nothing_installed
    endcase

    # --- root --------------------------------------------------------------------------------
    begin "uid 0 without --allow-root exits 1 with the fix, makes no call, installs nothing"
    defrel
    skipsig
    addenv STUB_UID=0
    run
    want_code 1
    want_err 'will not run as root'
    want_err 'fix:'
    want_err '--allow-root'
    want_no_net
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "uid 0 without --allow-root: RDY_INSTALL_DIR does not lift the refusal"
    defrel
    skipsig
    addenv STUB_UID=0
    addenv "RDY_INSTALL_DIR=$cdir/custom"
    run
    want_code 1
    want_no_net
    [ ! -e "$cdir/custom" ] || casebad "the install folder was created"
    endcase

    begin "uid 0 with --allow-root installs to RDY_INSTALL_DIR"
    defrel
    skipsig
    addenv STUB_UID=0
    addenv "RDY_INSTALL_DIR=$cdir/custom"
    run --allow-root
    want_code 0
    want_installed "$cdir/custom"
    endcase

    begin "uid 0 with --allow-root defaults to /usr/local/bin"
    # The stub curl fails, so the script stops before it writes anything.
    addenv STUB_UID=0
    addenv STUB_CURL_RC=22
    run --allow-root
    want_code 1
    want_err 'to /usr/local/bin'
    want_nothing_installed
    endcase

    begin "uid 0 detection failure stops"
    defrel
    addenv STUB_UID=notanumber
    run
    want_code 1
    want_err 'could not tell which user'
    want_no_net
    endcase

    # --- usage -------------------------------------------------------------------------------
    begin "unknown option exits 64"
    defrel
    run --bogus
    want_code 64
    want_err 'unknown option: --bogus'
    want_err 'fix:'
    want_no_net
    want_nothing_installed
    endcase

    begin "--help prints usage on stdout, exits 0, installs nothing"
    defrel
    run --help
    want_code 0
    grep -q 'Usage: install.sh' "$OUT" || casebad "usage is not on stdout"
    want_no_net
    want_nothing_installed
    endcase

    # --- platform ----------------------------------------------------------------------------
    for spec in \
        "Linux aarch64 aarch64-unknown-linux-musl" \
        "Linux arm64 aarch64-unknown-linux-musl" \
        "Linux amd64 x86_64-unknown-linux-musl" \
        "Darwin arm64 aarch64-apple-darwin" \
        "Darwin x86_64 x86_64-apple-darwin"; do
        # shellcheck disable=SC2086 # three words on purpose
        set -- $spec
        begin "picks $3 for $1 $2"
        TRIPLE=$3
        defrel
        skipsig
        addenv "STUB_OS=$1"
        addenv "STUB_ARCH=$2"
        run
        want_code 0
        want_installed
        want_log "/rdy-$3.tar.gz"
        endcase
    done

    begin "macOS under Rosetta gets the arm64 build"
    TRIPLE=aarch64-apple-darwin
    defrel
    skipsig
    addenv STUB_OS=Darwin
    addenv STUB_ARCH=x86_64
    addenv STUB_TRANSLATED=1
    run
    want_code 0
    want_log "/rdy-aarch64-apple-darwin.tar.gz"
    endcase

    begin "an unknown OS stops"
    defrel
    addenv STUB_OS=FreeBSD
    run
    want_code 1
    want_err 'operating system is not supported: FreeBSD'
    want_err 'fix:'
    want_no_net
    endcase

    begin "an unknown CPU stops"
    defrel
    addenv STUB_ARCH=riscv64
    run
    want_code 1
    want_err 'CPU is not supported: riscv64'
    want_no_net
    endcase

    # --- version -----------------------------------------------------------------------------
    begin "an unstamped copy with no RDY_VERSION stops"
    defrel
    skipsig
    E="STUB_UID=1000 RDY_INSECURE_SKIP_SIGNATURE=1"
    run
    want_code 1
    want_err 'has no version'
    want_err 'RDY_VERSION'
    want_no_net
    endcase

    begin "the stamp placeholder appears exactly once"
    n=$(grep -c '@@RDY_STAMPED_VERSION@@' "$script")
    [ "$n" = 1 ] || casebad "the placeholder appears $n times"
    endcase

    begin "a stamped copy installs its own version"
    defrel
    skipsig
    E="STUB_UID=1000 RDY_INSECURE_SKIP_SIGNATURE=1"
    sed "s/@@RDY_STAMPED_VERSION@@/v$VER/" "$script" > "$cdir/stamped.sh"
    sh_run "$cdir/stamped.sh"
    want_code 0
    want_installed
    want_log "/v$VER/rdy-$LINUX.tar.gz"
    endcase

    begin "RDY_VERSION beats the stamp"
    defrel
    skipsig
    addenv RDY_VERSION=0.2.0
    sed "s/@@RDY_STAMPED_VERSION@@/v$VER/" "$script" > "$cdir/stamped.sh"
    sh_run "$cdir/stamped.sh"
    want_code 1
    want_log '/v0.2.0/'
    want_nothing_installed
    endcase

    begin "RDY_VERSION with a leading v works"
    defrel
    skipsig
    addenv RDY_VERSION=v$VER
    # The last assignment in the environment list wins.
    run
    want_code 0
    want_installed
    endcase

    for bad in '0.1.0/../../x' 'latest' '1.2' '1.2.3 4' '..1.2.3' '1..2.3' 'a1.2.3' '1.2.3?x=1' '1.2.3#x'; do
        begin "rejects RDY_VERSION=$bad"
        defrel
        skipsig
        sh_run_bad_version "$bad"
        want_code 1
        want_err 'version is not valid'
        want_no_net
        want_nothing_installed
        endcase
    done

    # --- downloads ---------------------------------------------------------------------------
    begin "a missing archive stops with a clear message"
    skipsig
    run
    want_code 1
    want_err 'no file named'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "a missing SHA256SUMS stops"
    defrel
    skipsig
    rm -f "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'no file named SHA256SUMS'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "a TLS failure points at the CA bundle"
    defrel
    skipsig
    addenv STUB_CURL_RC=60
    run
    want_code 1
    want_err 'SSL_CERT_FILE'
    want_err 'CURL_CA_BUNDLE'
    want_nothing_installed
    endcase

    begin "a network failure names the proxy variable"
    defrel
    skipsig
    addenv STUB_CURL_RC=6
    run
    want_code 1
    want_err 'HTTPS_PROXY'
    want_nothing_installed
    endcase

    begin "wget with --https-only is used when curl is missing"
    defrel
    skipsig
    DL=wget
    run
    want_code 0
    want_installed
    want_log 'wget --https-only --secure-protocol=TLSv1_2 -q -O'
    endcase

    begin "a wget without --https-only does not count"
    defrel
    skipsig
    DL=wget-old
    run
    want_code 1
    want_err 'no download tool'
    want_no_net
    endcase

    begin "no downloader stops"
    defrel
    skipsig
    DL=none
    run
    want_code 1
    want_err 'no download tool'
    want_nothing_installed
    endcase

    # --- signature seam (M1-015 replaces verify_signature) -----------------------------------
    begin "without the override this copy stops before it trusts anything"
    defrel
    run
    want_code 1
    want_err 'cannot check the release signature yet'
    want_err 'RDY_INSECURE_SKIP_SIGNATURE=1'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "the override must be exactly 1"
    defrel
    addenv RDY_INSECURE_SKIP_SIGNATURE=yes
    run
    want_code 1
    want_nothing_installed
    endcase

    # --- sha256 ------------------------------------------------------------------------------
    begin "a wrong hash in SHA256SUMS stops, installs nothing, cleans up"
    defrel
    skipsig
    sed "s/^[0-9a-f]\{64\}  rdy-$LINUX/$A64  rdy-$LINUX/" "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'does not match SHA256SUMS'
    want_err 'do not run this file'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "a tampered archive stops"
    defrel
    skipsig
    printf 'x' >> "$REL/rdy-$LINUX.tar.gz"
    run
    want_code 1
    want_err 'does not match SHA256SUMS'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "no line for the archive stops"
    defrel
    skipsig
    grep -v "  rdy-$LINUX.tar.gz\$" "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    run
    want_code 1
    want_err "no line for rdy-$LINUX.tar.gz"
    want_nothing_installed
    endcase

    begin "a line for a longer or shorter name does not count"
    defrel
    skipsig
    h=$(host_hash "$REL/rdy-$LINUX.tar.gz")
    {
        printf '%s  xrdy-%s.tar.gz\n' "$h" "$LINUX"
        printf '%s  rdy-%s.tar.gz.sha256\n' "$h" "$LINUX"
        printf '%s  rdy-%s.tar\n' "$h" "$LINUX"
        printf '%s  dir/rdy-%s.tar.gz\n' "$h" "$LINUX"
    } > "$REL/SHA256SUMS"
    run
    want_code 1
    want_err "no line for rdy-$LINUX.tar.gz"
    want_nothing_installed
    endcase

    begin "two lines for the archive stop"
    defrel
    skipsig
    grep "  rdy-$LINUX.tar.gz\$" "$REL/SHA256SUMS" > "$REL/dup"
    cat "$REL/dup" >> "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'more than one line'
    want_nothing_installed
    endcase

    begin "a short or upper case hash stops"
    defrel
    skipsig
    printf 'abc123  rdy-%s.tar.gz\n' "$LINUX" > "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'malformed hash'
    want_nothing_installed
    h=$(host_hash "$REL/rdy-$LINUX.tar.gz" | tr 'a-f' 'A-F')
    printf '%s  rdy-%s.tar.gz\n' "$h" "$LINUX" > "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'malformed hash'
    want_nothing_installed
    endcase

    begin "CRLF line ends in SHA256SUMS fail closed"
    defrel
    skipsig
    sed 's/$/\r/' "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    run
    want_code 1
    want_nothing_installed
    endcase

    begin "the binary-mode marker (hash *name) is accepted"
    defrel
    skipsig
    sed "s/  rdy-$LINUX.tar.gz\$/ *rdy-$LINUX.tar.gz/" "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    run
    want_code 0
    want_installed
    endcase

    for tool in shasum openssl; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            echo "SKIP $SHELL_LABEL: hash with $tool ($tool is not on this host)"
            if [ -n "${CI:-}" ]; then
                echo "FAIL $tool is missing in CI"
                fail=1
            fi
            continue
        fi
        begin "hashes with $tool when it is the only tool"
        defrel
        skipsig
        HASH=$tool
        run
        want_code 0
        want_installed
        endcase
    done

    begin "no hash tool stops before any download"
    defrel
    skipsig
    HASH=none
    run
    want_code 1
    want_err 'no tool to compute a sha256'
    want_no_net
    want_nothing_installed
    endcase

    # --- the archive and the binary ----------------------------------------------------------
    begin "a binary that reports another version is not installed"
    mkrel "$VER" "$LINUX" 0.1.0-alpha.1
    skipsig
    run
    want_code 1
    want_err 'reports a different version'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "a binary that does not run is not installed"
    mkrel "$VER" "$LINUX" FAIL
    skipsig
    run
    want_code 1
    want_err 'did not run'
    want_err 'TMPDIR'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "an archive without rdy in it stops"
    defrel
    skipsig
    mkdir -p "$cdir/other/rdy-$LINUX"
    echo hi > "$cdir/other/rdy-$LINUX/README.md"
    tar -czf "$REL/rdy-$LINUX.tar.gz" -C "$cdir/other" "rdy-$LINUX"
    h=$(host_hash "$REL/rdy-$LINUX.tar.gz")
    printf '%s  rdy-%s.tar.gz\n' "$h" "$LINUX" > "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'could not unpack'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "an archive whose rdy is a symlink stops"
    defrel
    skipsig
    mkdir -p "$cdir/link/rdy-$LINUX"
    ln -s /bin/sh "$cdir/link/rdy-$LINUX/rdy"
    tar -czf "$REL/rdy-$LINUX.tar.gz" -C "$cdir/link" "rdy-$LINUX"
    h=$(host_hash "$REL/rdy-$LINUX.tar.gz")
    printf '%s  rdy-%s.tar.gz\n' "$h" "$LINUX" > "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'does not hold a plain file'
    want_nothing_installed
    endcase

    # --- the install folder ------------------------------------------------------------------
    begin "a relative RDY_INSTALL_DIR stops"
    defrel
    skipsig
    addenv RDY_INSTALL_DIR=bin
    run
    want_code 1
    want_err 'not an absolute path'
    want_no_net
    endcase

    begin "HOME unset and no RDY_INSTALL_DIR stops"
    defrel
    skipsig
    HOME_D=''
    run
    want_code 1
    want_err 'HOME is not set'
    want_no_net
    endcase

    begin "an install folder that cannot be made stops"
    defrel
    skipsig
    : > "$cdir/afile"
    addenv "RDY_INSTALL_DIR=$cdir/afile/sub"
    run
    want_code 1
    want_err 'could not create'
    want_err 'never uses sudo'
    want_tmp_clean
    endcase

    begin "a folder where the binary goes stops and keeps it"
    defrel
    skipsig
    mkdir -p "$BIN_D/rdy"
    run
    want_code 1
    want_err 'is a folder'
    [ -d "$BIN_D/rdy" ] || casebad "the folder was removed"
    endcase

    # --- truncation (SEC-08) -----------------------------------------------------------------
    trunc_suite
}

# Used by the version loop: RDY_VERSION holds spaces or glob characters, so it cannot go through $E.
sh_run_bad_version() {
    pd="$tmp/path/$SHELL_LABEL-$HASH-$DL"
    if [ ! -d "$pd" ]; then build_path "$pd" "$SHELL_MODE" "$HASH" "$DL"; fi
    # shellcheck disable=SC2086 # $SHELL_CMD is a list of words on purpose
    env -i PATH="$pd" HOME="$HOME_D" TMPDIR="$TMP_D" STUB_LOG="$LOG" STUB_REL="$REL" STUB_VERSION="$VER" \
        STUB_UID=1000 STUB_OS=Linux STUB_ARCH=x86_64 RDY_INSECURE_SKIP_SIGNATURE=1 RDY_VERSION="$1" \
        $SHELL_CMD "$script" > "$OUT" 2> "$ERR" < /dev/null
    CODE=$?
}

# dirty: true when a run left a trace: the install folder exists, a download call was logged, or the
# temp folder holds a file. Shell builtins only, so the cut loops stay fast.
dirty() {
    [ -e "$HOME_D/.local" ] && return 0
    [ -s "$LOG" ] && return 0
    for f in "$TMP_D"/* "$TMP_D"/.[!.]*; do
        [ -e "$f" ] && return 0
    done
    return 1
}

# A copy of install.sh cut at any byte installs nothing, makes no call and leaves no file. The
# environment is the happy path, so a cut copy that ran to the end would install.
trunc_suite() {
    total=$(wc -c < "$script")

    begin "control: the whole file without its last newline still installs"
    defrel
    skipsig
    head -c "$((total - 1))" "$script" > "$cdir/cut.sh"
    sh_run "$cdir/cut.sh"
    want_code 0
    want_installed
    endcase

    begin "cut before the call to main: nothing runs"
    defrel
    skipsig
    sed '$d' "$script" > "$cdir/cut.sh"
    sh_run "$cdir/cut.sh"
    want_nothing_installed
    want_no_net
    want_tmp_clean
    endcase

    begin "a call to main without the end marker refuses"
    defrel
    skipsig
    { sed '$d' "$script"; echo 'main "$@"'; } > "$cdir/cut.sh"
    sh_run "$cdir/cut.sh"
    want_code 1
    want_err 'cut off'
    want_nothing_installed
    want_no_net
    endcase

    begin "cut at every byte: nothing is installed, no call, no leftovers"
    defrel
    skipsig
    cutbad=0
    # Every byte of the last 500 (the final function and the call), every 13th byte before that.
    n=0
    while [ "$n" -lt $((total - 1)) ]; do
        head -c "$n" "$script" > "$cdir/cut.sh"
        sh_run "$cdir/cut.sh"
        if dirty; then
            casebad "a copy cut at byte $n installed, called out, or left files"
            cutbad=$((cutbad + 1))
            [ "$cutbad" -lt 5 ] || break
        fi
        if [ "$n" -lt $((total - 500)) ]; then n=$((n + 13)); else n=$((n + 1)); fi
    done
    endcase

    begin "cut at every line end: nothing is installed"
    defrel
    skipsig
    lines=$(wc -l < "$script")
    i=1
    while [ "$i" -lt "$lines" ]; do
        head -n "$i" "$script" > "$cdir/cut.sh"
        sh_run "$cdir/cut.sh"
        if dirty; then
            casebad "a copy cut after line $i installed, called out, or left files"
            break
        fi
        i=$((i + 1))
    done
    endcase

    begin "a cut copy piped into sh installs nothing"
    defrel
    skipsig
    n=0
    while [ "$n" -lt $((total - 1)) ]; do
        head -c "$n" "$script" > "$cdir/cut.sh"
        STDIN="$cdir/cut.sh"
        sh_run -s --
        if dirty; then
            casebad "a copy cut at byte $n and piped in installed or called out"
            break
        fi
        n=$((n + 211))
    done
    endcase
}

# ---------------------------------------------------------------------------------------------
# Pick the shells and run
# ---------------------------------------------------------------------------------------------
want=${*:-dash busybox}
for name in $want; do
    case $name in
        dash)
            if ! DASH=$(command -v dash); then
                echo "SKIP dash is not installed (apt-get install dash)"
                [ -z "${CI:-}" ] || {
                    echo "FAIL dash is missing in CI"
                    fail=1
                }
                continue
            fi
            SHELL_LABEL=dash
            SHELL_CMD=$DASH
            SHELL_MODE=real
            ;;
        busybox)
            if ! BUSYBOX=$(command -v busybox); then
                echo "SKIP busybox is not installed (apt-get install busybox-static)"
                [ -z "${CI:-}" ] || {
                    echo "FAIL busybox is missing in CI"
                    fail=1
                }
                continue
            fi
            SHELL_LABEL=busybox
            SHELL_CMD="$BUSYBOX sh"
            SHELL_MODE=busybox
            ;;
        *)
            echo "usage: sh scripts/test-install-sh.sh [dash] [busybox]" >&2
            exit 64
            ;;
    esac
    suite
done

if [ "$fail" -eq 0 ]; then
    echo "install.sh tests passed"
fi
exit "$fail"
