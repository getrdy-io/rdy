#!/bin/sh
# test-sign-release.sh: tests for scripts/make-sha256sums.sh and scripts/sign-release.sh. Exit 0 when
# all pass.
#
# A fake `cosign` on PATH stands in for Sigstore, so no test needs the network or an OIDC token.
# The fake behaves like the parts of cosign that matter here. `sign-blob` writes a bundle that holds
# the sha256 of the blob and the identity in $FAKE_SIGNER. `verify-blob` fails unless the blob's sha256,
# the identity and the issuer all match. Every call is logged, so the tests read the exact arguments.
# What the fake cannot show is that Fulcio puts the identity we expect into the certificate. The
# release-sandbox run (06, "Sandbox proof") shows that, and scripts/test-cosign-roundtrip.sh runs the
# real verify-blob against a real keyless signature.

set -u

here=$(cd "$(dirname "$0")" && pwd)
sign="$here/sign-release.sh"
sums="$here/make-sha256sums.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

for tool in sha256sum jq awk cmp find sed; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        if [ -n "${CI:-}" ]; then
            echo "FAIL $tool is missing in CI"
            exit 1
        fi
        echo "SKIP all: $tool is missing here"
        exit 0
    fi
done

repo=getrdy-io/rdy
tag=v0.1.0-alpha.1
want_identity="https://github.com/$repo/.github/workflows/sign-release.yml@refs/tags/$tag"
want_issuer=https://token.actions.githubusercontent.com

# ---- the fake cosign ---------------------------------------------------------------------------
mkdir "$tmp/bin"
cat > "$tmp/bin/cosign" << 'EOF'
#!/bin/sh
# Fake cosign. Logs its arguments to $FAKE_LOG, one call per line.
printf '%s\n' "$*" >> "$FAKE_LOG"
cmd=$1
shift
bundle=""
identity=""
issuer=""
blob=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --bundle) bundle=$2; shift ;;
        --certificate-identity) identity=$2; shift ;;
        --certificate-oidc-issuer) issuer=$2; shift ;;
        --yes) ;;
        -*) echo "fake cosign: unexpected flag $1" >&2; exit 2 ;;
        *) blob=$1 ;;
    esac
    shift
done
digest=$(sha256sum "$blob" | awk '{ print $1 }')
case $cmd in
    sign-blob)
        [ -z "${FAKE_SIGN_FAIL:-}" ] || { echo "fake cosign: no OIDC token" >&2; exit 1; }
        printf '{"digest":"%s","identity":"%s","verificationMaterial":{"tlogEntries":[{"logIndex":"4242"}]}}\n' \
            "$digest" "$FAKE_SIGNER" > "$bundle"
        echo "ZmFrZQ=="
        ;;
    verify-blob)
        [ "$(jq -r .digest "$bundle")" = "$digest" ] || { echo "fake cosign: invalid signature when validating ASN.1 encoded signature" >&2; exit 1; }
        [ "$(jq -r .identity "$bundle")" = "$identity" ] || { echo "fake cosign: none of the expected identities matched" >&2; exit 1; }
        [ "$issuer" = "https://token.actions.githubusercontent.com" ] || { echo "fake cosign: issuer mismatch" >&2; exit 1; }
        echo "Verified OK" >&2
        ;;
    *) echo "fake cosign: unexpected command $cmd" >&2; exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/cosign"
FAKE_LOG="$tmp/cosign.log"
export FAKE_LOG
FAKE_SIGNER=$want_identity
export FAKE_SIGNER

# ---- fixtures ----------------------------------------------------------------------------------
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc"

# release <name>: a folder shaped like the artifacts that the sign job downloads.
release() {
    d="$tmp/$1"
    rm -rf "$d"
    mkdir -p "$d"
    : > "$d/sha256.sum"
    for t in $targets; do
        case $t in
            *-windows-*) a=rdy-$t.zip ;;
            *) a=rdy-$t.tar.gz ;;
        esac
        echo "synthetic archive for $t" > "$d/$a"
        h=$(sha256sum "$d/$a" | awk '{ print $1 }')
        echo "$h *$a" > "$d/$a.sha256"
        echo "$h *$a" >> "$d/sha256.sum"
        echo '{}' > "$d/$t-dist-manifest.json"
    done
    echo "synthetic source" > "$d/source.tar.gz"
    echo "$(sha256sum "$d/source.tar.gz" | awk '{ print $1 }') *source.tar.gz" >> "$d/sha256.sum"
    echo '<bom xmlns="http://cyclonedx.org/schema/bom/1.3"></bom>' > "$d/rdy.cdx.xml"
    echo '{}' > "$d/dist-manifest.json"
    echo '{}' > "$d/plan-dist-manifest.json"
    echo '{}' > "$d/global-dist-manifest.json"
}

# source <name> <install.sh text or "-" for none>: a fake checkout of the tag.
source_tree() {
    mkdir -p "$tmp/$1"
    if [ "$2" != "-" ]; then
        printf '%s\n' "$2" > "$tmp/$1/install.sh"
    fi
}
source_tree src-none -
source_tree src-ok '#!/bin/sh
RDY_DEFAULT_VERSION="@RDY_VERSION@"
echo hello'
source_tree src-two '#!/bin/sh
RDY_DEFAULT_VERSION="@RDY_VERSION@"
# also @RDY_VERSION@ here'
source_tree src-zero '#!/bin/sh
echo hello'

# run <name> <expected exit> <expected text> <args...>: runs sign-release.sh with the fake cosign.
run() {
    name=$1
    want=$2
    text=$3
    shift 3
    : > "$FAKE_LOG"
    out=$(PATH="$tmp/bin:$PATH" "$sign" "$@" 2>&1)
    code=$?
    if [ "$code" -ne "$want" ]; then
        bad "$name (exit $code, want $want)"
        printf '%s\n' "$out"
    elif ! printf '%s\n' "$out" | grep -q -- "$text"; then
        bad "$name (output lacks '$text')"
        printf '%s\n' "$out"
    else
        ok "$name"
    fi
}

# ---- make-sha256sums.sh ------------------------------------------------------------------------
mkdir "$tmp/m1"
echo b > "$tmp/m1/b.txt"
echo a > "$tmp/m1/a.txt"
echo old > "$tmp/m1/SHA256SUMS"
echo old > "$tmp/m1/SHA256SUMS.sigstore.json"
"$sums" "$tmp/m1" > "$tmp/m1.out"
if [ "$(awk '{ print $2 }' "$tmp/m1.out" | tr '\n' ' ')" = "a.txt b.txt " ]; then
    ok "make-sha256sums lists the files in byte order and leaves out SHA256SUMS and the bundle"
else
    bad "make-sha256sums lists the files in byte order and leaves out SHA256SUMS and the bundle"
fi
if (cd "$tmp/m1" && sha256sum -c "$tmp/m1.out" > /dev/null 2>&1); then
    ok "sha256sum -c accepts the output"
else
    bad "sha256sum -c accepts the output"
fi
if grep -q '^[0-9a-f]\{64\}  a.txt$' "$tmp/m1.out"; then
    ok "the format is the hash, two spaces and the name"
else
    bad "the format is the hash, two spaces and the name"
fi
mkdir "$tmp/m2"
echo a > "$tmp/m2/a.txt"
ln -s a.txt "$tmp/m2/link"
if "$sums" "$tmp/m2" > /dev/null 2>&1; then bad "make-sha256sums refuses a symlink"; else ok "make-sha256sums refuses a symlink"; fi
mkdir "$tmp/m3"
mkdir "$tmp/m3/sub"
if "$sums" "$tmp/m3" > /dev/null 2>&1; then bad "make-sha256sums refuses a folder"; else ok "make-sha256sums refuses a folder"; fi
mkdir "$tmp/m4"
echo a > "$tmp/m4/.hidden"
if "$sums" "$tmp/m4" > /dev/null 2>&1; then bad "make-sha256sums refuses a hidden file"; else ok "make-sha256sums refuses a hidden file"; fi
mkdir "$tmp/m5"
echo a > "$tmp/m5/has space"
if "$sums" "$tmp/m5" > /dev/null 2>&1; then bad "make-sha256sums refuses a name with a space"; else ok "make-sha256sums refuses a name with a space"; fi
if "$sums" > /dev/null 2>&1; then bad "make-sha256sums without an argument fails"; else ok "make-sha256sums without an argument fails"; fi

# ---- sign-release.sh: the good path ------------------------------------------------------------
release good
run "a good release is signed and verified" 0 "signed and verified SHA256SUMS" "$tmp/good" "$tag" "$repo" "$tmp/src-ok"
if [ -f "$tmp/good/SHA256SUMS" ] && [ -f "$tmp/good/SHA256SUMS.sigstore.json" ]; then
    ok "SHA256SUMS and its bundle are in the folder"
else
    bad "SHA256SUMS and its bundle are in the folder"
fi
# The signed list covers every published file, including the stamped install.sh, and not dist's
# per-job manifests, which announce deletes.
names=$(awk '{ print $2 }' "$tmp/good/SHA256SUMS" | tr '\n' ' ')
case $names in
    *install.sh*) ok "SHA256SUMS lists install.sh" ;;
    *) bad "SHA256SUMS lists install.sh" ;;
esac
case $names in
    *-dist-manifest.json*) bad "SHA256SUMS leaves out dist's per-job manifests" ;;
    *) ok "SHA256SUMS leaves out dist's per-job manifests" ;;
esac
case $names in
    *"dist-manifest.json"*) ok "SHA256SUMS lists dist-manifest.json" ;;
    *) bad "SHA256SUMS lists dist-manifest.json" ;;
esac
if [ ! -e "$tmp/good/plan-dist-manifest.json" ] && [ -e "$tmp/good/dist-manifest.json" ]; then
    ok "the per-job manifests are removed and dist-manifest.json stays"
else
    bad "the per-job manifests are removed and dist-manifest.json stays"
fi
if grep -q 'RDY_DEFAULT_VERSION="v0.1.0-alpha.1"' "$tmp/good/install.sh" && ! grep -q '@RDY_VERSION@' "$tmp/good/install.sh"; then
    ok "install.sh carries this tag as its default version"
else
    bad "install.sh carries this tag as its default version"
fi
if (cd "$tmp/good" && sha256sum -c SHA256SUMS > /dev/null 2>&1); then
    ok "sha256sum -c SHA256SUMS passes on the signed folder"
else
    bad "sha256sum -c SHA256SUMS passes on the signed folder"
fi
# The folder passes the check that announce runs before it publishes.
if "$here/check-release-artifacts.sh" --files-only --signed "$tmp/good" > /dev/null 2>&1; then
    ok "the signed folder passes check-release-artifacts.sh --files-only --signed"
else
    bad "the signed folder passes check-release-artifacts.sh --files-only --signed"
fi

# The exact arguments of the two cosign calls.
sign_line=$(grep '^sign-blob' "$FAKE_LOG")
verify_line=$(grep '^verify-blob' "$FAKE_LOG")
if [ "$sign_line" = "sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS" ]; then
    ok "cosign sign-blob gets --yes, the bundle path and SHA256SUMS"
else
    bad "cosign sign-blob gets --yes, the bundle path and SHA256SUMS (got: $sign_line)"
fi
if [ "$verify_line" = "verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity $want_identity --certificate-oidc-issuer $want_issuer SHA256SUMS" ]; then
    ok "cosign verify-blob gets the exact identity and issuer, no regular expression"
else
    bad "cosign verify-blob gets the exact identity and issuer, no regular expression (got: $verify_line)"
fi
case $verify_line in
    *regexp*) bad "no -regexp flag is used" ;;
    *) ok "no -regexp flag is used" ;;
esac
if [ "$(wc -l < "$FAKE_LOG" | tr -d ' ')" = "2" ]; then
    ok "cosign is called twice: sign, then verify"
else
    bad "cosign is called twice: sign, then verify"
fi

# The exit test, in the fake's terms: the bundle verifies, and fails after one byte changes.
if PATH="$tmp/bin:$PATH" cosign verify-blob --bundle "$tmp/good/SHA256SUMS.sigstore.json" --certificate-identity "$want_identity" --certificate-oidc-issuer "$want_issuer" "$tmp/good/SHA256SUMS" > /dev/null 2>&1; then
    ok "verify-blob passes on the signed SHA256SUMS"
else
    bad "verify-blob passes on the signed SHA256SUMS"
fi
printf 'x' >> "$tmp/good/SHA256SUMS"
if PATH="$tmp/bin:$PATH" cosign verify-blob --bundle "$tmp/good/SHA256SUMS.sigstore.json" --certificate-identity "$want_identity" --certificate-oidc-issuer "$want_issuer" "$tmp/good/SHA256SUMS" > /dev/null 2>&1; then
    bad "verify-blob fails after one byte of SHA256SUMS changes"
else
    ok "verify-blob fails after one byte of SHA256SUMS changes"
fi

# ---- sign-release.sh: self-verify catches a wrong identity -------------------------------------
release wrongid
FAKE_SIGNER="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"
export FAKE_SIGNER
run "a signature from another workflow file fails the self-verify" 1 "do not publish" "$tmp/wrongid" "$tag" "$repo" "$tmp/src-ok"
if [ -e "$tmp/wrongid/SHA256SUMS" ] || [ -e "$tmp/wrongid/SHA256SUMS.sigstore.json" ]; then
    bad "a failed self-verify leaves no signature files"
else
    ok "a failed self-verify leaves no signature files"
fi
FAKE_SIGNER="https://github.com/$repo/.github/workflows/sign-release.yml@refs/tags/v0.1.0-alpha.2"
export FAKE_SIGNER
release wrongtag
run "a signature for another tag fails the self-verify" 1 "does not verify as" "$tmp/wrongtag" "$tag" "$repo" "$tmp/src-ok"
FAKE_SIGNER=$want_identity
export FAKE_SIGNER

release signfail
FAKE_SIGN_FAIL=1
export FAKE_SIGN_FAIL
run "a cosign signing failure stops the script and says what to check" 1 "id-token: write" "$tmp/signfail" "$tag" "$repo" "$tmp/src-ok"
unset FAKE_SIGN_FAIL
if [ -e "$tmp/signfail/SHA256SUMS" ]; then bad "a failed signing leaves no SHA256SUMS"; else ok "a failed signing leaves no SHA256SUMS"; fi

# ---- sign-release.sh: checks before the signature ----------------------------------------------
release badhash
printf 'x' >> "$tmp/badhash/rdy-x86_64-apple-darwin.tar.gz"
run "an archive that does not match sha256.sum is not signed" 1 "does not match sha256.sum" "$tmp/badhash" "$tag" "$repo" "$tmp/src-ok"
if [ -s "$FAKE_LOG" ]; then bad "cosign is not called after a hash mismatch"; else ok "cosign is not called after a hash mismatch"; fi

release nosum
rm "$tmp/nosum/sha256.sum"
run "a missing sha256.sum is not signed" 1 "sha256.sum is missing" "$tmp/nosum" "$tag" "$repo" "$tmp/src-ok"

release extra
echo surprise > "$tmp/extra/notes.txt"
run "an unexpected file is not signed" 1 "must not be signed" "$tmp/extra" "$tag" "$repo" "$tmp/src-ok"
if [ -s "$FAKE_LOG" ]; then bad "cosign is not called after an unexpected file"; else ok "cosign is not called after an unexpected file"; fi

release unlisted
echo "synthetic source two" > "$tmp/unlisted/source.tar.gz"
run "a source archive that changed after hashing is not signed" 1 "does not match sha256.sum" "$tmp/unlisted" "$tag" "$repo" "$tmp/src-ok"

release preexisting
echo old > "$tmp/preexisting/SHA256SUMS"
run "an existing SHA256SUMS is refused" 1 "already exists" "$tmp/preexisting" "$tag" "$repo" "$tmp/src-ok"

# ---- sign-release.sh: install.sh ---------------------------------------------------------------
release noinstall
run "a tag without install.sh is signed with a note" 0 "NOTE:" "$tmp/noinstall" "$tag" "$repo" "$tmp/src-none"
if awk '{ print $2 }' "$tmp/noinstall/SHA256SUMS" | grep -qx install.sh; then
    bad "SHA256SUMS lists no install.sh when the tag has none"
else
    ok "SHA256SUMS lists no install.sh when the tag has none"
fi
release twostamps
run "an install.sh with two stamp lines is refused" 1 "on 2 lines" "$tmp/twostamps" "$tag" "$repo" "$tmp/src-two"
release nostamp
run "an install.sh with no stamp line is refused" 1 "on 0 lines" "$tmp/nostamp" "$tag" "$repo" "$tmp/src-zero"

# ---- sign-release.sh: usage --------------------------------------------------------------------
release usage
run "a tag that is not a release tag is a usage error" 64 "is not a release tag" "$tmp/usage" "v1.0" "$repo" "$tmp/src-ok"
run "a branch name is not a release tag" 64 "is not a release tag" "$tmp/usage" "main" "$repo" "$tmp/src-ok"
run "a tag with shell text is not a release tag" 64 "is not a release tag" "$tmp/usage" 'v1.0.0;id' "$repo" "$tmp/src-ok"
run "a repository without a slash is a usage error" 64 "is not owner/repo" "$tmp/usage" "$tag" "rdy" "$tmp/src-ok"
run "a missing folder is a usage error" 64 "is not a directory" "$tmp/does-not-exist" "$tag" "$repo" "$tmp/src-ok"
run "too few arguments is a usage error" 64 "usage:" "$tmp/usage" "$tag"

# No cosign on PATH: a tool-missing error (64), not a silent unsigned release.
mkdir "$tmp/nocosign-bin"
for t in sh sed awk jq cmp find grep cat rm mktemp sha256sum wc tr dirname head cp; do
    p=$(command -v "$t") && ln -s "$p" "$tmp/nocosign-bin/$t"
done
release nocosign
out=$(PATH="$tmp/nocosign-bin" "$sign" "$tmp/nocosign" "$tag" "$repo" "$tmp/src-ok" 2>&1)
code=$?
if [ "$code" -eq 64 ] && printf '%s\n' "$out" | grep -q "cosign is not installed"; then
    ok "no cosign on PATH is exit 64 with the fix"
else
    bad "no cosign on PATH is exit 64 with the fix (exit $code)"
    printf '%s\n' "$out"
fi

exit "$fail"
