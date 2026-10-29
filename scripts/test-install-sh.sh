#!/bin/sh
# test-install-sh.sh: shell tests for install.sh (M1-014, SEC-08, INV-19). Exit 0 when all pass.
#
# Usage: sh scripts/test-install-sh.sh [dash] [busybox] [sh]
# With no argument it runs install.sh under dash and busybox sh. `sh` runs it under /bin/sh with the
# host tools (CI uses it on macOS, where /bin/sh is bash in POSIX mode and the tools are BSD).
# A missing shell is a SKIP on a developer machine and a failure in CI ($CI set), so a runner image
# change cannot turn the tests into a silent pass.
#
# Nothing touches the network or the real machine. Each case runs in a clean environment (env -i) with
# a PATH folder made of symlinks to the few tools install.sh needs, plus stubs for curl, wget, id,
# uname, sysctl and mktemp. A stub curl maps the release URL to a synthetic release folder. In the
# busybox run the tools are busybox applets too, so the script is tried against busybox tar, awk,
# mktemp and the rest, as on Alpine.
#
# The busybox run needs a busybox that looks up applets on PATH. Alpine's does. The Debian and Ubuntu
# busybox-static prefers its own built-in id, uname and sha256sum, so the stubs never run. Before the
# suite, each shell must prove that a stub id and uname win (check_stubs). If not, the run fails with a
# message and does not pretend to test. CI runs the busybox leg in a pinned Alpine container.
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
# The hash tool the cases use unless they pick one. macOS has shasum and no sha256sum.
if command -v sha256sum > /dev/null 2>&1; then
    DEFHASH=sha256sum
    host_hash() { sha256sum "$1" | awk '{ print $1 }'; }
else
    DEFHASH=shasum
    host_hash() { shasum -a 256 "$1" | awk '{ print $1 }'; }
fi
CR=$(printf '\r')

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
max=''
while [ "$#" -gt 0 ]; do
    case $1 in
        -o) out=$2; shift 2 ;;
        --max-filesize) max=$2; shift 2 ;;
        --proto | --proto-redir | --connect-timeout | --retry | --speed-limit | --speed-time) shift 2 ;;
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
# Like curl, a file over --max-filesize is refused with exit 63.
if [ -n "$max" ] && [ "$(wc -c < "$STUB_REL/$name")" -gt "$max" ]; then exit 63; fi
cp "$STUB_REL/$name" "$out"
EOF

# A wget that supports --https-only and --no-config (GNU wget), one with only --https-only, and one
# with neither (busybox wget).
cat > "$tmp/stubs/wget" << 'EOF'
#!/bin/sh
if [ "${1:-}" = "--help" ]; then
    echo "GNU Wget stub"
    echo "      --https-only    follow only secure HTTPS links in recursive mode"
    echo "      --no-config     do not read any config file"
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
cat > "$tmp/stubs/wget-noconfig" << 'EOF'
#!/bin/sh
if [ "${1:-}" = "--help" ]; then
    echo "GNU Wget stub, old"
    echo "      --https-only    follow only secure HTTPS links in recursive mode"
    exit 0
fi
printf 'wget-noconfig %s\n' "$*" >> "$STUB_LOG"
exit 1
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
# mktemp passes through to the real one, except for a file in /usr/local/bin. That one is logged and
# refused, so a test can see where install.sh meant to write without touching the real folder.
cat > "$tmp/stubs/mktemp" << 'EOF'
#!/bin/sh
case ${1:-} in
    /usr/local/bin/*)
        printf 'mktemp %s\n' "$1" >> "$STUB_LOG.mktemp"
        exit 1
        ;;
esac
exec $STUB_REAL_MKTEMP "$@"
EOF
cat > "$tmp/stubs/sysctl" << 'EOF'
#!/bin/sh
if [ -n "${STUB_TRANSLATED:-}" ]; then echo "$STUB_TRANSLATED"; exit 0; fi
echo "sysctl: unknown oid 'sysctl.proc_translated'" >&2
exit 1
EOF
# A fake cosign (M1-015), the same idea as the one in scripts/test-verify-release.sh. The bundle that
# mksig writes holds the sha256 of the blob, the signer identity and the caller claims (what Fulcio puts
# in the certificate of a reusable workflow: the identity names the called file, the claims name the
# caller). `verify-blob` fails unless the blob, the identity and the issuer match, and each
# --certificate-github-workflow-* flag that it gets matches the claim. A flag that is not passed is not
# checked, as in cosign, so a test can show that the wrong caller passes when install.sh leaves a flag
# out. It logs every call to $STUB_LOG.cosign. It uses the host tools (FAKE_HOST_PATH), because the PATH
# folder of install.sh holds only the few tools install.sh itself may use.
# FAKE_COSIGN_VERSION sets the GitVersion (NONE prints no version line). FAKE_COSIGN_FAIL=network makes
# verify-blob fail the way a blocked Sigstore does.
cat > "$tmp/stubs/cosign" << 'EOF'
#!/bin/sh
PATH=$FAKE_HOST_PATH
printf '%s\n' "$*" >> "$STUB_LOG.cosign"
cmd=$1
shift
if [ "$cmd" = version ]; then
    v=${FAKE_COSIGN_VERSION:-v3.1.4}
    if [ "$v" = NONE ]; then
        echo "cosign: a fake"
    else
        printf 'cosign: a fake\n\nGitVersion:    %s\nPlatform:      linux/amd64\n' "$v"
    fi
    exit 0
fi
[ "$cmd" = verify-blob ] || { echo "fake cosign: unexpected command $cmd" >&2; exit 2; }
printf 'TUF_ROOT=%s\n' "${TUF_ROOT:-}" >> "$STUB_LOG.cosign"
bundle=''
identity=''
issuer=''
wf_repo=''
wf_ref=''
wf_trigger=''
blob=''
while [ "$#" -gt 0 ]; do
    case $1 in
        --bundle) bundle=$2; shift ;;
        --certificate-identity) identity=$2; shift ;;
        --certificate-oidc-issuer) issuer=$2; shift ;;
        --certificate-github-workflow-repository) wf_repo=$2; shift ;;
        --certificate-github-workflow-ref) wf_ref=$2; shift ;;
        --certificate-github-workflow-trigger) wf_trigger=$2; shift ;;
        -*) echo "fake cosign: unexpected flag $1" >&2; exit 2 ;;
        *) blob=$1 ;;
    esac
    shift
done
if [ "${FAKE_COSIGN_FAIL:-}" = network ]; then
    echo "fake cosign: error updating to TUF remote mirror: no route to host" >&2
    exit 1
fi
if command -v sha256sum > /dev/null 2>&1; then
    digest=$(sha256sum "$blob" | awk '{ print $1 }')
else
    digest=$(shasum -a 256 "$blob" | awk '{ print $1 }')
fi
field() { sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" "$bundle"; }
[ "$(field digest)" = "$digest" ] || { echo "fake cosign: invalid signature when validating ASN.1 encoded signature" >&2; exit 1; }
[ "$(field identity)" = "$identity" ] || { echo "fake cosign: none of the expected identities matched" >&2; exit 1; }
[ "$issuer" = "https://token.actions.githubusercontent.com" ] || { echo "fake cosign: issuer mismatch" >&2; exit 1; }
[ -z "$wf_repo" ] || [ "$(field repo)" = "$wf_repo" ] || { echo "fake cosign: expected GitHub workflow repository value does not match" >&2; exit 1; }
[ -z "$wf_ref" ] || [ "$(field ref)" = "$wf_ref" ] || { echo "fake cosign: expected GitHub workflow ref value does not match" >&2; exit 1; }
[ -z "$wf_trigger" ] || [ "$(field trigger)" = "$wf_trigger" ] || { echo "fake cosign: expected GitHub workflow trigger value does not match" >&2; exit 1; }
echo "Verified OK" >&2
EOF
chmod +x "$tmp/stubs/"*

HOST_PATH=$PATH

# ---------------------------------------------------------------------------------------------
# PATH folders
# ---------------------------------------------------------------------------------------------
base_tools="cat chmod cp grep gzip mkdir mv rm tar awk wc"

# build_path <dir> <mode: real|busybox> <hash: sha256sum|shasum|openssl|none> <dl: curl|wget|wget-noconfig|wget-old|none> <cosign: fake|none>
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
        curl | wget | wget-noconfig | wget-old) ln -s "$tmp/stubs/$4" "$d/${4%%-*}" ;;
    esac
    if [ "$5" = fake ]; then ln -s "$tmp/stubs/cosign" "$d/cosign"; fi
    ln -s "$tmp/stubs/mktemp" "$d/mktemp"
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
    # The fake rdy touches STUB_CANARY when it runs. install.sh runs the new binary only after the
    # signature and the hash have passed, so a refused install must leave no canary.
    CANARY="$cdir/canary"
    E="STUB_UID=1000 STUB_OS=Linux STUB_ARCH=x86_64 RDY_VERSION=$VER STUB_CANARY=$CANARY"
    HASH=$DEFHASH
    DL=curl
    COS=fake
    PATH_SUFFIX=''
    STDIN=''
    TRIPLE=$LINUX
    # What the fake cosign finds in the bundle that mksig writes: a good signature from our workflow.
    B_ID="$SIGNER_PREFIX@refs/tags/v$VER"
    B_REPO=getrdy-io/rdy
    B_REF="refs/tags/v$VER"
    B_TRIGGER=push
    B_MEDIA=application/vnd.dev.sigstore.bundle.v0.3+json
    B_EXTRA=''
}

addenv() { E="$E $1"; }
skipsig() { addenv RDY_INSECURE_SKIP_SIGNATURE=1; }

SIGNER_PREFIX=https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml

# mksig: write $REL/SHA256SUMS.sigstore.json for the SHA256SUMS that is there now, from the B_* values.
mksig() {
    sd=$(host_hash "$REL/SHA256SUMS")
    media=''
    if [ -n "$B_MEDIA" ]; then media="\"mediaType\":\"$B_MEDIA\","; fi
    printf '{%s"digest":"%s","identity":"%s","repo":"%s","ref":"%s","trigger":"%s"%s}\n' \
        "$media" "$sd" "$B_ID" "$B_REPO" "$B_REF" "$B_TRIGGER" "$B_EXTRA" > "$REL/SHA256SUMS.sigstore.json"
}

# mkrel <ver> <triple> <what the fake rdy prints, or FAIL>: a valid synthetic release in $REL.
mkrel() {
    pkg="$cdir/pkg-$2"
    mkdir -p "$pkg/rdy-$2"
    if [ "$3" = FAIL ]; then
        printf '#!/bin/sh\nexit 3\n' > "$pkg/rdy-$2/rdy"
    else
        # shellcheck disable=SC2016 # the fake rdy expands STUB_CANARY, not this script
        printf '#!/bin/sh\n[ -z "${STUB_CANARY:-}" ] || : > "$STUB_CANARY"\necho "rdy %s"\n' "$3" > "$pkg/rdy-$2/rdy"
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
    mksig
}

# defrel: the release for the default case.
defrel() { mkrel "$VER" "$TRIPLE" "$VER"; }

# The clean environment for one run. $pd is the PATH folder.
# shellcheck disable=SC2086 # $E and $SHELL_CMD are lists of words on purpose
in_env() {
    env -i PATH="$pd$PATH_SUFFIX" HOME="$HOME_D" TMPDIR="$TMP_D" STUB_LOG="$LOG" STUB_REL="$REL" \
        STUB_VERSION="$VER" STUB_REAL_MKTEMP="$REAL_MKTEMP" FAKE_HOST_PATH="$HOST_PATH" $E $SHELL_CMD "$@"
}

# Run $SHELL_CMD with the given arguments in a clean environment. Sets CODE. When $STDIN names a file,
# it is fed through a real pipe (cat file | sh -s), as in `curl ... | sh`. Otherwise stdin is /dev/null.
sh_run() {
    pd="$tmp/path/$SHELL_LABEL-$HASH-$DL-$COS"
    if [ ! -d "$pd" ]; then build_path "$pd" "$SHELL_MODE" "$HASH" "$DL" "$COS"; fi
    if [ -n "$STDIN" ]; then
        # shellcheck disable=SC2002 # a real pipe on purpose, not a redirect
        cat "$STDIN" 2> /dev/null | in_env "$@" > "$OUT" 2> "$ERR"
    else
        in_env "$@" > "$OUT" 2> "$ERR" < /dev/null
    fi
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
want_canary() { [ -e "$CANARY" ] || casebad "the new rdy never ran (no canary)"; }
want_no_canary() { [ ! -e "$CANARY" ] || casebad "the new rdy ran (canary exists)"; }
# The fake cosign logs one line per call. verify-blob lines start with the word.
want_no_verify() {
    if grep -q '^verify-blob' "$LOG.cosign" 2> /dev/null; then casebad "cosign verify-blob was called"; fi
}
want_no_cosign_call() { [ ! -e "$LOG.cosign" ] || casebad "cosign was called"; }
# The exact verify-blob call from the contract in 06: absolute paths in the work folder, the exact
# identity and issuer, and the three caller claims.
want_verify_line() {
    line=$(grep '^verify-blob' "$LOG.cosign" 2> /dev/null) || line=''
    wantmid="--certificate-identity $SIGNER_PREFIX@refs/tags/v$VER --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-github-workflow-repository getrdy-io/rdy --certificate-github-workflow-ref refs/tags/v$VER --certificate-github-workflow-trigger push"
    case $line in
        "verify-blob --bundle $TMP_D/rdy-install."*"/SHA256SUMS.sigstore.json $wantmid $TMP_D/rdy-install."*"/SHA256SUMS") ;;
        *) casebad "cosign verify-blob call is not the contract: $line" ;;
    esac
    # cosign gets its own trust root cache inside the work folder, not ~/.sigstore.
    tuf=$(grep '^TUF_ROOT=' "$LOG.cosign" 2> /dev/null) || tuf=''
    case $tuf in
        "TUF_ROOT=$TMP_D/rdy-install."*"/tuf") ;;
        *) casebad "cosign TUF_ROOT is not private to the work folder: $tuf" ;;
    esac
    [ ! -e "$HOME_D/.sigstore" ] || casebad "something wrote ~/.sigstore"
}
# A refused signature: exit 1, the attack wording, a contact, nothing installed, nothing run, no hash
# step, everything cleaned up.
want_sig_refused() {
    want_code 1
    want_err 'does not verify as'
    want_err 'do not run this file'
    want_err 'security@getrdy.io'
    want_err 'fix:'
    want_no_err 'sha256 ok'
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    want_out_empty
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
    want_log "curl -q --proto =https --proto-redir =https --tlsv1.2 -fsSL --connect-timeout 20 --speed-limit 1024 --speed-time 60"
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
    # The stub mktemp refuses a file in /usr/local/bin and logs the name, so the real folder is not
    # touched. The script gets as far as the point where it would write there.
    defrel
    skipsig
    addenv STUB_UID=0
    run --allow-root
    want_code 1
    want_err 'could not write into /usr/local/bin'
    grep -F -q 'mktemp /usr/local/bin/.rdy.new.' "$LOG.mktemp" 2> /dev/null ||
        casebad "install.sh did not try to write into /usr/local/bin"
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

    begin "-h is not an option (06 lists --allow-root and --help only)"
    defrel
    run -h
    want_code 64
    want_err 'unknown option: -h'
    want_out_empty
    want_no_net
    want_nothing_installed
    endcase

    begin "an unknown option echoes its name, not its value"
    defrel
    run --token=hunter2
    want_code 64
    want_err 'unknown option: --token'
    want_no_err 'hunter2'
    want_no_net
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

    begin "a missing SHA256SUMS says the release looks incomplete"
    defrel
    skipsig
    rm -f "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'this release looks incomplete'
    want_err 'SHA256SUMS'
    want_err 'fix:'
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

    begin "GNU wget is used when curl is missing, with no config file and timeouts"
    defrel
    skipsig
    DL=wget
    run
    want_code 0
    want_installed
    want_log 'wget --no-config --https-only --secure-protocol=TLSv1_2 --timeout=30 --read-timeout=60 --tries=3 -q -O'
    endcase

    begin "a wget without --no-config does not count"
    defrel
    skipsig
    DL=wget-noconfig
    run
    want_code 1
    want_err 'no download tool'
    want_no_net
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

    # --- signature (M1-015, SEC-09, SEC-10) --------------------------------------------------
    sig_suite

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

    begin "CRLF line ends in SHA256SUMS stop the install"
    defrel
    skipsig
    sed "s/\$/$CR/" "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'carriage return'
    want_err 'fix:'
    want_nothing_installed
    want_tmp_clean
    endcase

    begin "a carriage return on any one line stops the install, even a decoy line"
    defrel
    skipsig
    printf '%s  elsewhere.txt%s\n' "$A64" "$CR" >> "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'carriage return'
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

# wrong_caller <label> <flag> <B_ variable> <value>: the identity is ours, but the run that called the
# reusable workflow was not. The second case shows that the first has teeth: a copy of install.sh that
# leaves the flag out installs, so only the flag stops it.
wrong_caller() {
    begin "wrong caller $1: refused, nothing runs"
    defrel
    eval "$3=\$4"
    mksig
    run
    want_sig_refused
    want_err "expected GitHub workflow $2 value does not match"
    endcase

    begin "wrong caller $1: without the --certificate-github-workflow-$2 flag the fake accepts it"
    defrel
    eval "$3=\$4"
    mksig
    grep -v -e "--certificate-github-workflow-$2" "$script" > "$cdir/noflag.sh"
    sh_run "$cdir/noflag.sh"
    want_code 0
    want_canary
    endcase
}

# bad_bundle <label> <mediaType> <extra json members> <text the error must have>
bad_bundle() {
    begin "bundle with $1 is refused before cosign runs"
    defrel
    B_MEDIA=$2
    B_EXTRA=$3
    mksig
    run
    want_code 1
    want_err "$4"
    want_err 'do not run this file'
    want_err 'security@getrdy.io'
    want_no_verify
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    endcase
}

# The signature suite. The fake cosign stands in for Sigstore. The real cosign is not used here: that
# needs the network and a published signed release (the alpha.1 install is a founder hand step,
# RELEASING.md).
sig_suite() {
    V3=application/vnd.dev.sigstore.bundle.v0.3+json

    begin "a good signature installs, and cosign gets the exact contract"
    defrel
    run
    want_code 0
    want_installed
    want_canary
    want_out_empty
    want_tmp_clean
    want_err "signature ok: SHA256SUMS is signed by $SIGNER_PREFIX@refs/tags/v$VER"
    want_err 'sha256 ok'
    want_no_err 'WARNING'
    want_log "/v$VER/SHA256SUMS.sigstore.json"
    want_verify_line
    # The signature check comes first, the hash check second.
    awk '/signature ok/ { s = NR } /sha256 ok/ { h = NR } END { exit !(s && h && s < h) }' "$ERR" ||
        casebad "the signature check did not come before the hash check"
    endcase

    begin "a good signature installs with GNU wget"
    defrel
    DL=wget
    run
    want_code 0
    want_installed
    want_canary
    want_log "wget --no-config --https-only"
    want_log "/v$VER/SHA256SUMS.sigstore.json"
    endcase

    begin "a good signature installs through the curl | sh route"
    defrel
    STDIN="$script"
    sh_run -s --
    want_code 0
    want_installed
    want_canary
    want_out_empty
    endcase

    # --- bad hash ----------------------------------------------------------------------------
    begin "bad hash: the archive differs from the signed list"
    defrel
    printf 'x' >> "$REL/rdy-$LINUX.tar.gz"
    run
    want_code 1
    want_err 'signature ok'
    want_err 'does not match SHA256SUMS'
    want_err 'do not run this file'
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    endcase

    begin "bad hash: a wrong hash in a list that is signed"
    defrel
    sed "s/^[0-9a-f]\{64\}  rdy-$LINUX/$A64  rdy-$LINUX/" "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    mksig
    run
    want_code 1
    want_err 'does not match SHA256SUMS'
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    endcase

    # --- bad signature -----------------------------------------------------------------------
    begin "bad signature: SHA256SUMS changed by one byte after signing"
    defrel
    printf 'x' >> "$REL/SHA256SUMS"
    run
    want_sig_refused
    want_err 'invalid signature'
    want_verify_line
    endcase

    begin "bad signature: archive and list both replaced, the old bundle kept"
    defrel
    printf 'x' >> "$REL/rdy-$LINUX.tar.gz"
    h=$(host_hash "$REL/rdy-$LINUX.tar.gz")
    sed "s/^[0-9a-f]\{64\}  rdy-$LINUX/$h  rdy-$LINUX/" "$REL/SHA256SUMS" > "$REL/new"
    mv "$REL/new" "$REL/SHA256SUMS"
    run
    want_sig_refused
    endcase

    begin "bad signature: a bundle for another file"
    defrel
    printf 'other file\n' > "$cdir/other-list"
    sd=$(host_hash "$cdir/other-list")
    printf '{"mediaType":"%s","digest":"%s","identity":"%s","repo":"getrdy-io/rdy","ref":"refs/tags/v%s","trigger":"push"}\n' \
        "$B_MEDIA" "$sd" "$B_ID" "$VER" > "$REL/SHA256SUMS.sigstore.json"
    run
    want_sig_refused
    endcase

    begin "bad signature: cosign cannot reach Sigstore, so it fails closed and shows its lines"
    defrel
    addenv FAKE_COSIGN_FAIL=network
    run
    want_sig_refused
    want_err 'no route to host'
    want_err 'network error'
    endcase

    # --- wrong identity ----------------------------------------------------------------------
    begin "wrong identity: another workflow file in our repository"
    defrel
    B_ID="https://github.com/getrdy-io/rdy/.github/workflows/release.yml@refs/tags/v$VER"
    mksig
    run
    want_sig_refused
    want_err 'none of the expected identities matched'
    endcase

    begin "wrong identity: the signature of another release (replay)"
    defrel
    B_ID="$SIGNER_PREFIX@refs/tags/v0.1.0-alpha.1"
    mksig
    run
    want_sig_refused
    want_err 'none of the expected identities matched'
    endcase

    begin "wrong identity: our workflow in another repository"
    defrel
    B_ID="https://github.com/evil-org/rdy/.github/workflows/sign-release.yml@refs/tags/v$VER"
    mksig
    run
    want_sig_refused
    want_err 'none of the expected identities matched'
    endcase

    begin "wrong identity: our workflow from a branch"
    defrel
    B_ID="$SIGNER_PREFIX@refs/heads/main"
    mksig
    run
    want_sig_refused
    want_err 'none of the expected identities matched'
    endcase

    # --- wrong caller (the reusable workflow hole) -------------------------------------------
    wrong_caller "repository" repository B_REPO evil-org/rdy
    wrong_caller "ref (a branch)" ref B_REF refs/heads/main
    wrong_caller "ref (another tag)" ref B_REF refs/tags/v0.1.0-alpha.1
    wrong_caller "trigger" trigger B_TRIGGER workflow_dispatch

    # --- missing bundle ----------------------------------------------------------------------
    begin "missing bundle: the release looks incomplete, in the plain wording"
    defrel
    rm -f "$REL/SHA256SUMS.sigstore.json"
    run
    want_code 1
    want_err 'this release looks incomplete'
    want_err 'SHA256SUMS.sigstore.json'
    want_err 'fix:'
    want_no_err 'do not run this file'
    want_no_verify
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    endcase

    # --- missing cosign ----------------------------------------------------------------------
    begin "missing cosign: stops before any download and gives the manual route"
    defrel
    COS=none
    run
    want_code 1
    want_err 'cosign is not installed'
    want_err "https://github.com/getrdy-io/rdy/blob/v$VER/scripts/verify-release.sh"
    want_err 'fix:'
    # ADR 0025: the stop message does not name the override. The docs do.
    want_no_err 'RDY_INSECURE_SKIP_SIGNATURE'
    want_no_net
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    endcase

    begin "missing cosign with the override: installs on the hash, with the loud warning"
    defrel
    COS=none
    skipsig
    run
    want_code 0
    want_installed
    want_canary
    want_err 'WARNING: RDY_INSECURE_SKIP_SIGNATURE=1'
    want_err 'sha256 ok'
    want_no_err 'signature ok'
    ! grep -q 'sigstore.json' "$LOG" || casebad "the bundle was downloaded although the signature is skipped"
    endcase

    begin "missing cosign with the override: the sha256 check still runs"
    defrel
    COS=none
    skipsig
    printf 'x' >> "$REL/rdy-$LINUX.tar.gz"
    run
    want_code 1
    want_err 'does not match SHA256SUMS'
    want_nothing_installed
    want_no_canary
    endcase

    for val in yes true 0 2 ''; do
        begin "the override must be exactly 1 (RDY_INSECURE_SKIP_SIGNATURE='$val')"
        defrel
        COS=none
        addenv "RDY_INSECURE_SKIP_SIGNATURE=$val"
        run
        want_code 1
        want_err 'cosign is not installed'
        want_nothing_installed
        want_no_canary
        endcase
    done

    begin "the override with a cosign present never calls cosign and never fetches the bundle"
    defrel
    skipsig
    run
    want_code 0
    want_installed
    want_no_cosign_call
    ! grep -q 'sigstore.json' "$LOG" || casebad "the bundle was downloaded although the signature is skipped"
    endcase

    begin "the override installs a release that has no bundle, on the hash only"
    defrel
    skipsig
    rm -f "$REL/SHA256SUMS.sigstore.json"
    run
    want_code 0
    want_installed
    endcase

    # --- cosign version floor ----------------------------------------------------------------
    for v in v3.1.3 v3.1.4 v3.1.10 v3.2.0 v3.10.0 v4.0.0; do
        begin "cosign $v is accepted"
        defrel
        addenv "FAKE_COSIGN_VERSION=$v"
        run
        want_code 0
        want_installed
        want_canary
        endcase
    done
    for v in v3.1.2 v3.1.0 v3.0.9 v3.0.0 v2.9.9 v1.13.6 v0.9.9; do
        begin "cosign $v is too old"
        defrel
        addenv "FAKE_COSIGN_VERSION=$v"
        run
        want_code 1
        want_err "cosign $v is too old"
        want_err '3.1.3 or newer'
        want_err 'fix:'
        want_no_net
        want_nothing_installed
        want_no_canary
        want_no_verify
        endcase
    done
    for v in NONE v3.1 garbage 3.1.3.1 v3.1.4-rc1 v3..1 v3.1.x v99999999999999999999.1.1; do
        begin "cosign version '$v' cannot be read, so it is refused"
        defrel
        addenv "FAKE_COSIGN_VERSION=$v"
        run
        want_code 1
        want_err 'could not read the version of cosign'
        want_no_net
        want_nothing_installed
        want_no_canary
        want_no_verify
        endcase
    done
    begin "with the override an old cosign is never asked"
    defrel
    skipsig
    addenv FAKE_COSIGN_VERSION=v2.0.0
    run
    want_code 0
    want_no_cosign_call
    endcase

    # --- trust-root variables ----------------------------------------------------------------
    for v in SIGSTORE_ROOT_FILE SIGSTORE_REKOR_PUBLIC_KEY SIGSTORE_CT_LOG_PUBLIC_KEY_FILE \
        SIGSTORE_TSA_CERTIFICATE_FILE TUF_MIRROR TUF_ROOT_JSON TUF_ROOT; do
        begin "refuses $v when it is set"
        defrel
        addenv "$v=/tmp/x"
        run
        want_code 1
        want_err "$v is set"
        want_err "unset $v"
        want_err 'fix:'
        want_no_net
        want_nothing_installed
        want_no_canary
        want_no_cosign_call
        want_tmp_clean
        endcase

        begin "refuses $v even when it is empty"
        defrel
        addenv "$v="
        run
        want_code 1
        want_err "$v is set"
        want_no_net
        want_nothing_installed
        want_no_cosign_call
        endcase
    done
    begin "with the override a trust variable is not read, because cosign is not used"
    defrel
    skipsig
    addenv TUF_ROOT=/tmp/x
    run
    want_code 0
    want_installed
    want_no_cosign_call
    endcase

    # --- bundle format -----------------------------------------------------------------------
    bad_bundle "an old mediaType" 'application/vnd.dev.sigstore.bundle+json;version=0.2' '' 'v0.3 format'
    bad_bundle "no mediaType" '' '' 'v0.3 format'
    bad_bundle "a legacy base64Signature key" "$V3" ',"base64Signature":"ZmFrZQ=="' 'v0.3 format'
    bad_bundle "a legacy rekorBundle key" "$V3" ',"rekorBundle":{}' 'v0.3 format'
    # base64 + backslash + u0053 + ignature spells base64Signature once the escape is decoded.
    BS=$(printf '\134')
    bad_bundle "a JSON \\u escape" "$V3" ",\"base64${BS}u0053ignature\":\"x\"" 'JSON \u escape'

    begin "a bundle over 1 MiB is refused"
    defrel
    head -c 1100000 /dev/zero | tr '\0' ' ' >> "$REL/SHA256SUMS.sigstore.json"
    run
    want_code 1
    want_err 'too large'
    want_no_verify
    want_nothing_installed
    want_no_canary
    want_tmp_clean
    endcase

    begin "a SHA256SUMS over 1 MiB is refused"
    defrel
    head -c 1100000 /dev/zero | tr '\0' ' ' >> "$REL/SHA256SUMS"
    mksig
    run
    want_code 1
    want_err 'too large'
    want_no_verify
    want_nothing_installed
    want_no_canary
    endcase

    begin "a SHA256SUMS over 1 MiB is refused on the override path too, with curl and with wget"
    defrel
    skipsig
    head -c 1100000 /dev/zero | tr '\0' ' ' >> "$REL/SHA256SUMS"
    run
    want_code 1
    want_err 'too large'
    want_nothing_installed
    want_no_canary
    want_log '--max-filesize 1048576'
    DL=wget
    run
    want_code 1
    want_err 'too large'
    want_nothing_installed
    want_no_canary
    endcase

    # --- the contract is the same everywhere -------------------------------------------------
    begin "install.sh refuses the same trust variables as scripts/verify-release.sh"
    mine=$(sed -n "s/^TRUST_VARS='\(.*\)'\$/\1/p" "$script" | tr ' ' '\n' | sort)
    theirs=$(awk '/^for var in/ { p = 1 } p { print } /; do$/ { p = 0 }' "$root/scripts/verify-release.sh" | grep -o '[A-Z][A-Z_]*' | sort)
    if [ -z "$mine" ] || [ "$mine" != "$theirs" ]; then
        casebad "install.sh has [$mine], verify-release.sh has [$theirs]"
    fi
    endcase

    begin "the signer repository and the download base agree"
    sr=$(sed -n "s/^SIGNER_REPO='\(.*\)'\$/\1/p" "$script")
    rb=$(sed -n "s/^RELEASE_BASE='\(.*\)'\$/\1/p" "$script")
    if [ "$sr" != getrdy-io/rdy ] || [ "$rb" != "https://github.com/$sr/releases/download" ]; then
        casebad "SIGNER_REPO='$sr' RELEASE_BASE='$rb'"
    fi
    endcase
}

# Used by the version loop: RDY_VERSION holds spaces or glob characters, so it cannot go through $E.
sh_run_bad_version() {
    pd="$tmp/path/$SHELL_LABEL-$HASH-$DL-$COS"
    if [ ! -d "$pd" ]; then build_path "$pd" "$SHELL_MODE" "$HASH" "$DL" "$COS"; fi
    # shellcheck disable=SC2086 # $SHELL_CMD is a list of words on purpose
    env -i PATH="$pd" HOME="$HOME_D" TMPDIR="$TMP_D" STUB_LOG="$LOG" STUB_REL="$REL" STUB_VERSION="$VER" \
        STUB_REAL_MKTEMP="$REAL_MKTEMP" STUB_UID=1000 STUB_OS=Linux STUB_ARCH=x86_64 RDY_INSECURE_SKIP_SIGNATURE=1 RDY_VERSION="$1" \
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
# check_stubs: in a clean environment, `id -u` and `uname -s` must come from the stubs. A busybox
# that runs its own applets first (Debian, Ubuntu) fails this, and every case after it would test the
# host, not the script. Returns 1 and says why.
check_stubs() {
    pd="$tmp/path/$SHELL_LABEL-$DEFHASH-curl-fake"
    if [ ! -d "$pd" ]; then build_path "$pd" "$SHELL_MODE" "$DEFHASH" curl fake; fi
    # shellcheck disable=SC2086 # $SHELL_CMD is a list of words on purpose
    got=$(env -i PATH="$pd" STUB_UID=4242 STUB_OS=StubOS $SHELL_CMD -c 'id -u; uname -s' 2>&1 < /dev/null) || got=''
    want_stub="4242
StubOS"
    if [ "$got" != "$want_stub" ]; then
        echo "FAIL $SHELL_LABEL: stubs bypassed (id -u and uname -s printed: $(echo "$got" | tr '\n' ' '))"
        echo "  The shell ran its own id or uname instead of the stubs on PATH, so the tests would not test"
        echo "  install.sh. Use a busybox that looks up applets on PATH, such as Alpine's (CI runs it in a"
        echo "  pinned Alpine container). Debian and Ubuntu busybox-static does not."
        return 1
    fi
    return 0
}

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
        sh)
            SHELL_LABEL="sh"
            SHELL_CMD=/bin/sh
            SHELL_MODE=real
            ;;
        busybox)
            if ! BUSYBOX=$(command -v busybox); then
                echo "SKIP busybox is not installed (apk add busybox on Alpine)"
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
            echo "usage: sh scripts/test-install-sh.sh [dash] [busybox] [sh]" >&2
            exit 64
            ;;
    esac
    case $SHELL_MODE in
        busybox) REAL_MKTEMP="$BUSYBOX mktemp" ;;
        *) REAL_MKTEMP=$(command -v mktemp) ;;
    esac
    if ! check_stubs; then
        fail=1
        continue
    fi
    suite
done

if [ "$fail" -eq 0 ]; then
    echo "install.sh tests passed"
fi
exit "$fail"
