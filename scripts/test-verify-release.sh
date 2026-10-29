#!/bin/sh
# test-verify-release.sh: offline tests for scripts/verify-release.sh. Exit 0 when all pass.
#
# A fake `cosign` and a stub `curl` on PATH stand in for Sigstore and GitHub, so no test needs the
# network or an OIDC token. The fake cosign behaves like the parts of cosign that matter here.
# `sign-blob` writes a bundle that holds the sha256 of the blob, the identity in $FAKE_SIGNER and the
# caller claims in $FAKE_REPO, $FAKE_REF and $FAKE_TRIGGER (what Fulcio puts in the certificate of a
# reusable workflow: the identity names the called file, the claims name the caller). `verify-blob`
# fails unless the blob, the identity and the issuer match, and each --certificate-github-workflow-*
# flag that it gets matches the claim. A flag that is not passed is not checked, as in cosign, so a
# test shows that the fake would accept the wrong caller when the flags are left off. The stub curl
# serves files from a folder and refuses any URL outside the one release path. Every call is logged.
# What the fakes cannot show is that Fulcio issues the claims. scripts/test-cosign-roundtrip.sh runs
# the real verify-blob against a real keyless signature, and the release proof in 06 runs it on a
# real release.

set -u

here=$(cd "$(dirname "$0")" && pwd)
verify="$here/verify-release.sh"
sums="$here/make-sha256sums.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

for tool in sha256sum jq awk cmp sed dd; do
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
want_claims="--certificate-github-workflow-repository $repo --certificate-github-workflow-ref refs/tags/$tag --certificate-github-workflow-trigger push"
pinned=$(awk '$1 == "cosign" { print $2; exit }' "$here/../.github/release-tools.txt")
if [ -z "$pinned" ]; then
    echo "FAIL .github/release-tools.txt has no cosign line"
    exit 1
fi

# ---- the fakes ---------------------------------------------------------------------------------
mkdir "$tmp/bin"
cat > "$tmp/bin/cosign" << 'EOF'
#!/bin/sh
# Fake cosign. Logs its arguments to $FAKE_LOG, one call per line.
printf '%s\n' "$*" >> "$FAKE_LOG"
cmd=$1
shift
if [ "$cmd" = version ]; then
    printf 'cosign: a fake\n\nGitVersion:    %s\nPlatform:      linux/amd64\n' "$FAKE_VERSION"
    exit 0
fi
bundle=""
identity=""
issuer=""
wf_repo=""
wf_ref=""
wf_trigger=""
blob=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --bundle) bundle=$2; shift ;;
        --certificate-identity) identity=$2; shift ;;
        --certificate-oidc-issuer) issuer=$2; shift ;;
        --certificate-github-workflow-repository) wf_repo=$2; shift ;;
        --certificate-github-workflow-ref) wf_ref=$2; shift ;;
        --certificate-github-workflow-trigger) wf_trigger=$2; shift ;;
        --yes) ;;
        -*) echo "fake cosign: unexpected flag $1" >&2; exit 2 ;;
        *) blob=$1 ;;
    esac
    shift
done
digest=$(sha256sum "$blob" | awk '{ print $1 }')
case $cmd in
    sign-blob)
        printf '{"digest":"%s","identity":"%s","repo":"%s","ref":"%s","trigger":"%s","verificationMaterial":{"tlogEntries":[{"logIndex":"4242"}]}}\n' \
            "$digest" "$FAKE_SIGNER" "$FAKE_REPO" "$FAKE_REF" "$FAKE_TRIGGER" > "$bundle"
        ;;
    verify-blob)
        [ "$(jq -r .digest "$bundle")" = "$digest" ] || { echo "fake cosign: invalid signature when validating ASN.1 encoded signature" >&2; exit 1; }
        [ "$(jq -r .identity "$bundle")" = "$identity" ] || { echo "fake cosign: none of the expected identities matched" >&2; exit 1; }
        [ "$issuer" = "https://token.actions.githubusercontent.com" ] || { echo "fake cosign: issuer mismatch" >&2; exit 1; }
        [ -z "$wf_repo" ] || [ "$(jq -r .repo "$bundle")" = "$wf_repo" ] || { echo "fake cosign: expected GitHub workflow repository value does not match" >&2; exit 1; }
        [ -z "$wf_ref" ] || [ "$(jq -r .ref "$bundle")" = "$wf_ref" ] || { echo "fake cosign: expected GitHub workflow ref value does not match" >&2; exit 1; }
        [ -z "$wf_trigger" ] || [ "$(jq -r .trigger "$bundle")" = "$wf_trigger" ] || { echo "fake cosign: expected GitHub workflow trigger value does not match" >&2; exit 1; }
        echo "Verified OK" >&2
        ;;
    *) echo "fake cosign: unexpected command $cmd" >&2; exit 2 ;;
esac
EOF
cat > "$tmp/bin/curl" << 'EOF'
#!/bin/sh
# Stub curl. Logs its arguments to $CURL_LOG. Serves $FAKE_SERVE/<name> for URLs under the release
# path of $FAKE_TAG. A missing file is HTTP 404 and $FAKE_503 names a file that answers 503. Like
# curl -f, a failure prints the status through -w and exits 22. Any other URL is refused.
printf '%s\n' "$*" >> "$CURL_LOG"
out=""
url=""
while [ "$#" -gt 0 ]; do
    case $1 in
        -o) out=$2; shift ;;
        -w) shift ;;
        --proto | --proto-redir | --connect-timeout | --max-time | --retry) shift ;;
        -*) ;;
        *) url=$1 ;;
    esac
    shift
done
prefix="https://github.com/getrdy-io/rdy/releases/download/$FAKE_TAG/"
case $url in
    "$prefix"*) ;;
    *) echo "stub curl: refused $url" >&2; printf '000'; exit 6 ;;
esac
name=${url#"$prefix"}
if [ "$name" = "${FAKE_503:-}" ]; then
    echo "stub curl: The requested URL returned error: 503" >&2
    printf '503'
    exit 22
fi
if [ ! -f "$FAKE_SERVE/$name" ]; then
    echo "stub curl: The requested URL returned error: 404" >&2
    printf '404'
    exit 22
fi
cp "$FAKE_SERVE/$name" "$out"
printf '200'
EOF
chmod +x "$tmp/bin/cosign" "$tmp/bin/curl"
FAKE_LOG="$tmp/cosign.log"
CURL_LOG="$tmp/curl.log"
FAKE_TAG=$tag
FAKE_VERSION=v$pinned
FAKE_SIGNER=$want_identity
FAKE_REPO=$repo
FAKE_REF=refs/tags/$tag
FAKE_TRIGGER=push
export FAKE_LOG CURL_LOG FAKE_TAG FAKE_VERSION FAKE_SIGNER FAKE_REPO FAKE_REF FAKE_TRIGGER

# ---- fixtures ----------------------------------------------------------------------------------
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc"

# files <name>: the assets of a release in $tmp/<name>, without SHA256SUMS.
files() {
    d=$tmp/$1
    mkdir "$d"
    for t in $targets; do
        case $t in
            *-windows-*) a=rdy-$t.zip ;;
            *) a=rdy-$t.tar.gz ;;
        esac
        echo "synthetic archive for $t" > "$d/$a"
    done
    echo "synthetic source" > "$d/source.tar.gz"
    echo '<bom xmlns="http://cyclonedx.org/schema/bom/1.3"></bom>' > "$d/rdy.cdx.xml"
    echo '#!/bin/sh' > "$d/install.sh"
    echo '{}' > "$d/dist-manifest.json"
}
# sign <name>: sign the SHA256SUMS in $tmp/<name> with the fake cosign, using the current FAKE_*.
sign() {
    (cd "$tmp/$1" && PATH="$tmp/bin:$PATH" cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS > /dev/null)
}
# release <name>: a good signed release folder.
release() {
    files "$1"
    "$sums" "$tmp/$1" > "$tmp/$1.sums"
    mv "$tmp/$1.sums" "$tmp/$1/SHA256SUMS"
    sign "$1"
}

# run <name> <expected exit> <expected text> <args...>: runs verify-release.sh with the fakes.
run() {
    name=$1
    want=$2
    text=$3
    shift 3
    : > "$FAKE_LOG"
    : > "$CURL_LOG"
    out=$(PATH="$tmp/bin:$PATH" "$verify" "$@" 2>&1)
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
# last_out: the output of the last run.
last_out() { printf '%s\n' "$out"; }

# ---- the good path, from a folder --------------------------------------------------------------
release good
run "a good release verifies from a folder" 0 "verified $tag: 9 files match the signed SHA256SUMS" --dir "$tmp/good" "$tag"
if last_out | grep -q 'rekor log index:      4242' && last_out | grep -q "sha256 of SHA256SUMS: $(sha256sum "$tmp/good/SHA256SUMS" | awk '{ print $1 }')"; then
    ok "it prints the sha256 of SHA256SUMS and the Rekor log index"
else
    bad "it prints the sha256 of SHA256SUMS and the Rekor log index"
fi
for t in $targets; do
    case $t in
        *-windows-*) a=rdy-$t.zip ;;
        *) a=rdy-$t.tar.gz ;;
    esac
    if last_out | grep -q "^PASS sha256 $a\$"; then
        ok "the sha256 of $a is checked"
    else
        bad "the sha256 of $a is checked"
    fi
done
verify_line=$(grep '^verify-blob' "$FAKE_LOG")
if [ "$verify_line" = "verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity $want_identity --certificate-oidc-issuer $want_issuer $want_claims SHA256SUMS" ]; then
    ok "cosign verify-blob gets the exact identity, issuer, repository, ref and trigger"
else
    bad "cosign verify-blob gets the exact identity, issuer, repository, ref and trigger (got: $verify_line)"
fi
case $verify_line in
    *regexp*) bad "no -regexp flag is used" ;;
    *) ok "no -regexp flag is used" ;;
esac
if [ "$(grep -c '^verify-blob' "$FAKE_LOG")" = 1 ] && ! grep -q '^sign-blob' "$FAKE_LOG"; then
    ok "cosign verifies once and never signs"
else
    bad "cosign verifies once and never signs"
fi
if [ -s "$CURL_LOG" ]; then bad "--dir downloads nothing"; else ok "--dir downloads nothing"; fi
if last_out | grep -q '^NOTE'; then bad "the pinned cosign version gives no note"; else ok "the pinned cosign version gives no note"; fi

# ---- the good path, downloaded -----------------------------------------------------------------
FAKE_SERVE=$tmp/good
export FAKE_SERVE
run "a good release verifies from a download" 0 "verified $tag: 9 files match the signed SHA256SUMS" "$tag"
first=$(sed -n 1p "$CURL_LOG")
second=$(sed -n 2p "$CURL_LOG")
case $first in
    *"https://github.com/getrdy-io/rdy/releases/download/$tag/SHA256SUMS") ok "the signed list is downloaded first" ;;
    *) bad "the signed list is downloaded first (got: $first)" ;;
esac
case $second in
    *"https://github.com/getrdy-io/rdy/releases/download/$tag/SHA256SUMS.sigstore.json") ok "its bundle is downloaded second, before any archive" ;;
    *) bad "its bundle is downloaded second, before any archive (got: $second)" ;;
esac
if [ "$(wc -l < "$CURL_LOG" | tr -d ' ')" = 11 ]; then
    ok "eleven downloads: the list, the bundle and the nine listed files"
else
    bad "eleven downloads: the list, the bundle and the nine listed files"
fi
if grep -v -- "--proto =https --proto-redir =https --tlsv1.2 " "$CURL_LOG" | grep -q .; then
    bad "every download is https only with TLS 1.2 or newer"
else
    ok "every download is https only with TLS 1.2 or newer"
fi
if grep -v 'https://github.com/getrdy-io/rdy/releases/download/' "$CURL_LOG" | grep -q .; then
    bad "every download is from the release path of getrdy-io/rdy"
else
    ok "every download is from the release path of getrdy-io/rdy"
fi
if grep -q -- '^-q ' "$CURL_LOG"; then ok "curl ignores the user's config file"; else bad "curl ignores the user's config file"; fi

# ---- the fake accepts a wrong caller when the flags are left off (so the tests below mean something)
FAKE_REPO=evil-org/rdy
export FAKE_REPO
release wrongrepo
FAKE_REPO=$repo
export FAKE_REPO
if (cd "$tmp/wrongrepo" && PATH="$tmp/bin:$PATH" cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$want_identity" --certificate-oidc-issuer "$want_issuer" SHA256SUMS > /dev/null 2>&1); then
    ok "the fake accepts another repository's signature when no claim flags are passed"
else
    bad "the fake accepts another repository's signature when no claim flags are passed"
fi

# ---- the reusable-workflow hole: the identity is ours, the caller is not -----------------------
FAKE_REPO=evil-org/rdy
export FAKE_REPO
release wrongcaller
FAKE_REPO=$repo
export FAKE_REPO
FAKE_SERVE=$tmp/wrongcaller
export FAKE_SERVE
run "a signature from another repository's run fails (download)" 1 "expected GitHub workflow repository value does not match" "$tag"
if last_out | grep -q "does not verify as $want_identity"; then ok "the failure names the identity it wanted"; else bad "the failure names the identity it wanted"; fi
if [ "$(wc -l < "$CURL_LOG" | tr -d ' ')" = 2 ]; then
    ok "nothing but the list and the bundle is downloaded after a failed signature"
else
    bad "nothing but the list and the bundle is downloaded after a failed signature"
fi
run "a signature from another repository's run fails (folder)" 1 "expected GitHub workflow repository value does not match" --dir "$tmp/wrongcaller" "$tag"
if last_out | grep -q '^verified'; then bad "a wrong caller repository never prints verified"; else ok "a wrong caller repository never prints verified"; fi

FAKE_REF=refs/heads/main
export FAKE_REF
release wrongref
FAKE_REF=refs/tags/$tag
export FAKE_REF
run "a signature from a branch run fails" 1 "expected GitHub workflow ref value does not match" --dir "$tmp/wrongref" "$tag"
FAKE_REF=refs/tags/v0.1.0-alpha.2
export FAKE_REF
release wrongtagref
FAKE_REF=refs/tags/$tag
export FAKE_REF
run "a signature from a run on another tag fails" 1 "expected GitHub workflow ref value does not match" --dir "$tmp/wrongtagref" "$tag"

FAKE_TRIGGER=workflow_dispatch
export FAKE_TRIGGER
release wrongtrigger
FAKE_TRIGGER=push
export FAKE_TRIGGER
run "a signature from a manual run fails" 1 "expected GitHub workflow trigger value does not match" --dir "$tmp/wrongtrigger" "$tag"

# ---- the identity and the signature itself -----------------------------------------------------
FAKE_SIGNER="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"
export FAKE_SIGNER
release wrongfile
FAKE_SIGNER=$want_identity
export FAKE_SIGNER
run "a signature from another workflow file fails" 1 "none of the expected identities matched" --dir "$tmp/wrongfile" "$tag"

FAKE_SIGNER="https://github.com/$repo/.github/workflows/sign-release.yml@refs/tags/v0.1.0-alpha.2"
export FAKE_SIGNER
release wrongidtag
FAKE_SIGNER=$want_identity
export FAKE_SIGNER
run "a signature for another tag fails" 1 "none of the expected identities matched" --dir "$tmp/wrongidtag" "$tag"
run "a release is not accepted as another tag" 1 "none of the expected identities matched" --dir "$tmp/good" v0.1.0-alpha.2

release tampered
printf 'X' | dd of="$tmp/tampered/SHA256SUMS" bs=1 count=1 conv=notrunc 2> /dev/null
run "one changed byte of SHA256SUMS fails" 1 "invalid signature" --dir "$tmp/tampered" "$tag"

# ---- the archives ------------------------------------------------------------------------------
release badarchive
printf 'x' >> "$tmp/badarchive/rdy-aarch64-apple-darwin.tar.gz"
run "an archive changed after signing fails (folder)" 1 "rdy-aarch64-apple-darwin.tar.gz has sha256" --dir "$tmp/badarchive" "$tag"
FAKE_SERVE=$tmp/badarchive
export FAKE_SERVE
run "an archive changed after signing fails (download)" 1 "rdy-aarch64-apple-darwin.tar.gz has sha256" "$tag"
if last_out | grep -q '^verified'; then bad "a bad archive never prints verified"; else ok "a bad archive never prints verified"; fi

files nowin
rm "$tmp/nowin/rdy-x86_64-pc-windows-msvc.zip"
"$sums" "$tmp/nowin" > "$tmp/nowin/SHA256SUMS"
sign nowin
run "a signed list without the Windows archive fails" 1 "does not list rdy-x86_64-pc-windows-msvc.zip" --dir "$tmp/nowin" "$tag"

release missingfile
rm "$tmp/missingfile/rdy-x86_64-apple-darwin.tar.gz"
run "a listed archive that is not in the folder fails" 1 "rdy-x86_64-apple-darwin.tar.gz is missing" --dir "$tmp/missingfile" "$tag"
FAKE_SERVE=$tmp/missingfile
export FAKE_SERVE
# The download needs the same SHA256SUMS, so serve it from a copy that keeps the list.
mkdir "$tmp/serve-missing"
cp "$tmp/missingfile/"* "$tmp/serve-missing/"
FAKE_SERVE=$tmp/serve-missing
export FAKE_SERVE
run "a listed archive that the release lacks fails (download)" 1 "does not exist for $tag" "$tag"

FAKE_SERVE=$tmp/good
export FAKE_SERVE
FAKE_503=rdy-aarch64-apple-darwin.tar.gz
export FAKE_503
run "a server error on an archive says to check the network" 1 "HTTP status 503" "$tag"
unset FAKE_503
if last_out | grep -q 'HTTPS_PROXY'; then ok "a download failure mentions the proxy variables"; else bad "a download failure mentions the proxy variables"; fi

# ---- a signed list with an unsafe or odd line --------------------------------------------------
for case_name in traversal dup upper short empty crlf listsig; do
    files "$case_name"
    "$sums" "$tmp/$case_name" > "$tmp/$case_name/SHA256SUMS"
done
h=$(sha256sum "$tmp/traversal/source.tar.gz" | awk '{ print $1 }')
printf '%s  ../source.tar.gz\n' "$h" >> "$tmp/traversal/SHA256SUMS"
printf '%s  source.tar.gz\n' "$h" >> "$tmp/dup/SHA256SUMS"
sed 's/^\(..\)/\U\1/' "$tmp/upper/SHA256SUMS" > "$tmp/upper/S" && mv "$tmp/upper/S" "$tmp/upper/SHA256SUMS"
printf 'abc  source.tar.gz\n' >> "$tmp/short/SHA256SUMS"
: > "$tmp/empty/SHA256SUMS"
sed 's/$/\r/' "$tmp/crlf/SHA256SUMS" > "$tmp/crlf/S" && mv "$tmp/crlf/S" "$tmp/crlf/SHA256SUMS"
printf '%s  SHA256SUMS.sigstore.json\n' "$h" >> "$tmp/listsig/SHA256SUMS"
for case_name in traversal dup upper short empty crlf listsig; do
    sign "$case_name"
done
run "a name with a path in it is refused" 1 "not a plain file name" --dir "$tmp/traversal" "$tag"
run "a name listed twice is refused" 1 "twice" --dir "$tmp/dup" "$tag"
run "a hash in capital letters is refused" 1 "not lower-case hex" --dir "$tmp/upper" "$tag"
run "a line with a short hash is refused" 1 "not '<sha256>  <name>'" --dir "$tmp/short" "$tag"
run "an empty list is refused" 1 "SHA256SUMS is empty" --dir "$tmp/empty" "$tag"
run "a carriage return in the list is refused" 1 "not a plain file name" --dir "$tmp/crlf" "$tag"
run "a list that names its own bundle is refused" 1 "which it must not" --dir "$tmp/listsig" "$tag"

# ---- an unlisted file in the folder is called out ----------------------------------------------
release extra
echo hi > "$tmp/extra/notes.txt"
run "a file that SHA256SUMS does not list is called out" 0 "NOTE: notes.txt is in the folder but not in SHA256SUMS" --dir "$tmp/extra" "$tag"

# ---- missing pieces ----------------------------------------------------------------------------
mkdir "$tmp/serve-nobundle"
cp "$tmp/good/"* "$tmp/serve-nobundle/"
rm "$tmp/serve-nobundle/SHA256SUMS.sigstore.json"
FAKE_SERVE=$tmp/serve-nobundle
export FAKE_SERVE
run "a release with no bundle looks incomplete (download)" 1 "this release looks incomplete" "$tag"
mkdir "$tmp/serve-empty"
FAKE_SERVE=$tmp/serve-empty
export FAKE_SERVE
run "a tag with no release says so (download)" 1 "the tag has no published release" "$tag"
mkdir "$tmp/nobundle"
cp "$tmp/good/SHA256SUMS" "$tmp/nobundle/"
run "a folder with no bundle looks incomplete" 1 "looks incomplete" --dir "$tmp/nobundle" "$tag"
mkdir "$tmp/nosums"
run "a folder with no SHA256SUMS says what to download" 1 "SHA256SUMS is missing" --dir "$tmp/nosums" "$tag"

# ---- cosign: missing, too old, different from the pin ------------------------------------------
# A PATH with the tools the script needs and no cosign.
mkdir "$tmp/nocosign"
for tool in sh awk grep mktemp rm sed cat sha256sum curl jq dirname; do
    p=$(command -v "$tool" 2> /dev/null) && ln -s "$p" "$tmp/nocosign/$tool"
done
out=$(PATH="$tmp/nocosign" "$verify" --dir "$tmp/good" "$tag" 2>&1)
code=$?
if [ "$code" -eq 64 ] && printf '%s\n' "$out" | grep -q 'install-release-tool.sh cosign'; then
    ok "a missing cosign stops with exit 64 and the install line"
else
    bad "a missing cosign stops with exit 64 and the install line (exit $code)"
    printf '%s\n' "$out"
fi
FAKE_VERSION=v2.4.1
export FAKE_VERSION
run "cosign 2 is refused" 64 "is too old" --dir "$tmp/good" "$tag"
FAKE_VERSION=v99.0.0
export FAKE_VERSION
run "a cosign that differs from the pin gets a note and still verifies" 0 "NOTE: cosign is v99.0.0, the pinned version is v$pinned" --dir "$tmp/good" "$tag"
FAKE_VERSION=garbage
export FAKE_VERSION
run "an unreadable cosign version is refused" 64 "cannot read the cosign version" --dir "$tmp/good" "$tag"
FAKE_VERSION=v$pinned
export FAKE_VERSION

# ---- usage -------------------------------------------------------------------------------------
run "no arguments is a usage error" 64 "usage:"
run "a tag without the v is a usage error" 64 "is not a release tag" 0.1.0-alpha.1
run "a tag that is a path is a usage error" 64 "is not a release tag" "../v0.1.0"
run "an unknown flag is a usage error" 64 "usage:" --repo evil-org/rdy "$tag"
run "a missing folder is a usage error" 64 "is not a directory" --dir "$tmp/nope" "$tag"
run "--help exits 0" 0 "usage:" --help

if [ "$fail" -eq 0 ]; then
    echo "all verify-release tests passed"
fi
exit "$fail"
