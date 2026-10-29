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
# serves files from a folder and refuses any URL outside the one release path. It honors -f (an HTTP
# error is a failure only with -f), -w '%{http_code}' (the status is printed only when asked) and
# --max-filesize, so dropping one of those flags from the script changes the result. Every call is
# logged. Set SHELL_UNDER_TEST (for example "busybox sh") to run verify-release.sh under that shell.
# What the fakes cannot show is that Fulcio issues the claims. scripts/test-cosign-roundtrip.sh runs
# the real verify-blob against a real keyless signature, and the release proof in 06 runs it on a
# real release.

set -u

here=$(cd "$(dirname "$0")" && pwd)
verify="$here/verify-release.sh"
sums="$here/make-sha256sums.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
        media=""
        [ -z "$FAKE_MEDIATYPE" ] || media="\"mediaType\":\"$FAKE_MEDIATYPE\","
        printf '{%s"digest":"%s","identity":"%s","repo":"%s","ref":"%s","trigger":"%s","verificationMaterial":{"tlogEntries":[{"logIndex":"4242"}]}}\n' \
            "$media" "$digest" "$FAKE_SIGNER" "$FAKE_REPO" "$FAKE_REF" "$FAKE_TRIGGER" > "$bundle"
        ;;
    verify-blob)
        [ "$(jq -r .digest "$bundle")" = "$digest" ] || { echo "fake cosign: invalid signature when validating ASN.1 encoded signature" >&2; exit 1; }
        [ "$(jq -r .identity "$bundle")" = "$identity" ] || { echo "fake cosign: none of the expected identities matched" >&2; exit 1; }
        [ "$issuer" = "https://token.actions.githubusercontent.com" ] || { echo "fake cosign: issuer mismatch" >&2; exit 1; }
        [ -z "$wf_repo" ] || [ "$(jq -r .repo "$bundle")" = "$wf_repo" ] || { echo "fake cosign: expected GitHub workflow repository value does not match" >&2; exit 1; }
        [ -z "$wf_ref" ] || [ "$(jq -r .ref "$bundle")" = "$wf_ref" ] || { echo "fake cosign: expected GitHub workflow ref value does not match" >&2; exit 1; }
        [ -z "$wf_trigger" ] || [ "$(jq -r .trigger "$bundle")" = "$wf_trigger" ] || { echo "fake cosign: expected GitHub workflow trigger value does not match" >&2; exit 1; }
        # FAKE_MUTATE names a file to change after the check, as an attacker with write access to the
        # folder would. A script that reads that file again, not its checked copy, sees the change.
        [ -z "${FAKE_MUTATE:-}" ] || printf 'changed after the check\n' >> "$FAKE_MUTATE"
        echo "Verified OK" >&2
        ;;
    *) echo "fake cosign: unexpected command $cmd" >&2; exit 2 ;;
esac
EOF
cat > "$tmp/bin/curl" << 'EOF'
#!/bin/sh
# Stub curl. Logs its arguments to $CURL_LOG. Serves $FAKE_SERVE/<name> for URLs under the release
# path of $FAKE_TAG. A missing file is HTTP 404 and $FAKE_503 names a file that answers 503. Like
# curl, an HTTP error is a failure (exit 22) only with -f, and without -f the error page is saved and
# the exit is 0. The status goes to stdout only with -w '%{http_code}'. A file over --max-filesize
# fails with exit 63. Any other URL is refused.
printf '%s\n' "$*" >> "$CURL_LOG"
out=""
url=""
fflag=0
wfmt=""
max=""
while [ "$#" -gt 0 ]; do
    case $1 in
        -o) out=$2; shift ;;
        -w) wfmt=$2; shift ;;
        --max-filesize) max=$2; shift ;;
        --proto | --proto-redir | --connect-timeout | --max-time | --retry) shift ;;
        --*) ;;
        -*f*) fflag=1 ;;
        -*) ;;
        *) url=$1 ;;
    esac
    shift
done
status() {
    case $wfmt in
        *'%{http_code}'*) printf '%s' "$1" ;;
        *) ;;
    esac
}
prefix="https://github.com/getrdy-io/rdy/releases/download/$FAKE_TAG/"
case $url in
    "$prefix"*) ;;
    *) echo "stub curl: refused $url" >&2; status 000; exit 6 ;;
esac
name=${url#"$prefix"}
if [ "$name" = "${FAKE_503:-}" ]; then
    : > "$out"
    status 503
    [ "$fflag" = 1 ] || exit 0
    echo "stub curl: The requested URL returned error: 503" >&2
    exit 22
fi
if [ ! -f "$FAKE_SERVE/$name" ]; then
    : > "$out"
    status 404
    [ "$fflag" = 1 ] || exit 0
    echo "stub curl: The requested URL returned error: 404" >&2
    exit 22
fi
if [ -n "$max" ]; then
    size=$(wc -c < "$FAKE_SERVE/$name")
    if [ "$((size + 0))" -gt "$max" ]; then
        echo "stub curl: Maximum file size exceeded" >&2
        status 200
        exit 63
    fi
fi
cp "$FAKE_SERVE/$name" "$out"
status 200
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
FAKE_MEDIATYPE=application/vnd.dev.sigstore.bundle.v0.3+json
export FAKE_LOG CURL_LOG FAKE_TAG FAKE_VERSION FAKE_SIGNER FAKE_REPO FAKE_REF FAKE_TRIGGER FAKE_MEDIATYPE

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
    # shellcheck disable=SC2086 # SHELL_UNDER_TEST is a command and its arguments, split on purpose.
    out=$(cd "${run_cwd:-.}" && PATH="$tmp/bin:$PATH" ${SHELL_UNDER_TEST:-} "$verify" "$@" 2>&1)
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
# no_verify: cosign verify-blob was never called in the last run.
no_verify() { ! grep -q '^verify-blob' "$FAKE_LOG"; }
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
# The two paths must be absolute and must be copies in a private folder, not the user's folder. The
# words between them are the contract. (No argument has a space in it, so word splitting is safe.)
# shellcheck disable=SC2086
set -- $verify_line
bundle_path=$3
blob_path=""
middle=""
i=0
for w in "$@"; do
    i=$((i + 1))
    blob_path=$w
    if [ "$i" -ge 4 ] && [ "$i" -lt "$#" ]; then
        middle="$middle $w"
    fi
done
middle=${middle# }
case $bundle_path:$blob_path in
    "$tmp/good/"*) bad "cosign verifies copies, not the files in the user's folder (got: $verify_line)" ;;
    /*/SHA256SUMS.sigstore.json:/*/SHA256SUMS) ok "cosign verifies absolute paths to copies, not the files in the user's folder" ;;
    *) bad "cosign verifies absolute paths to copies, not the files in the user's folder (got: $verify_line)" ;;
esac
if [ "$1 $2" = "verify-blob --bundle" ] && [ "$middle" = "--certificate-identity $want_identity --certificate-oidc-issuer $want_issuer $want_claims" ]; then
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
if grep -v -- '^-q ' "$CURL_LOG" | grep -q .; then bad "every curl call ignores the user's config file (-q first)"; else ok "every curl call ignores the user's config file (-q first)"; fi
if grep -v -- ' -fsSL ' "$CURL_LOG" | grep -q .; then bad "every curl call fails on an HTTP error and follows redirects (-fsSL)"; else ok "every curl call fails on an HTTP error and follows redirects (-fsSL)"; fi
if grep -v -- "-w %{http_code} " "$CURL_LOG" | grep -q .; then bad "every curl call asks for the HTTP status (-w)"; else ok "every curl call asks for the HTTP status (-w)"; fi
if grep -v -- '--max-filesize [0-9]' "$CURL_LOG" | grep -q .; then bad "every curl call has a size cap (--max-filesize)"; else ok "every curl call has a size cap (--max-filesize)"; fi
if sed -n '1,2p' "$CURL_LOG" | grep -v -- '--max-filesize 1048576 ' | grep -q .; then bad "the list and the bundle are capped at 1 MiB"; else ok "the list and the bundle are capped at 1 MiB"; fi

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
awk '{ print toupper(substr($0, 1, 2)) substr($0, 3) }' "$tmp/upper/SHA256SUMS" > "$tmp/upper/S" && mv "$tmp/upper/S" "$tmp/upper/SHA256SUMS"
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
for tool in sh awk grep mktemp rm sed cat cp wc sha256sum curl jq dirname; do
    p=$(command -v "$tool" 2> /dev/null) || continue
    # busybox sh prints a bare applet name for a built-in. Only an absolute path can be linked.
    case $p in
        /*) ln -s "$p" "$tmp/nocosign/$tool" ;;
        *) ;;
    esac
done
# shellcheck disable=SC2086
out=$(PATH="$tmp/nocosign" ${SHELL_UNDER_TEST:-} "$verify" --dir "$tmp/good" "$tag" 2>&1)
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

# cosign 3.0.0 to 3.1.2 have GHSA-fx35-mq7g-6g98, so the floor is 3.1.3. Each refusal stops before
# cosign verifies anything.
for v in v3.1.2 v3.0.3 v3.0.0 v2.4.1; do
    FAKE_VERSION=$v
    export FAKE_VERSION
    run "cosign $v is refused" 64 "cosign $v is too old: it must be 3.1.3 or newer" --dir "$tmp/good" "$tag"
    if no_verify; then ok "cosign $v is refused before it verifies anything"; else bad "cosign $v is refused before it verifies anything"; fi
done
for v in v3.1.3 v3.1.10 v3.2.0 v4.0.0; do
    FAKE_VERSION=$v
    export FAKE_VERSION
    run "cosign $v is accepted" 0 "verified $tag" --dir "$tmp/good" "$tag"
done
for v in v3.1 v3.1.3-rc.1 v3.1.3.1 v3..3 3.x.4; do
    FAKE_VERSION=$v
    export FAKE_VERSION
    run "the cosign version $v is unreadable and refused" 64 "cannot read the cosign version" --dir "$tmp/good" "$tag"
done
FAKE_VERSION=v$pinned
export FAKE_VERSION

# ---- the bundle must be the v0.3 format --------------------------------------------------------
# The fake would accept all of these, so only the script's own check can refuse them.
FAKE_MEDIATYPE="application/vnd.dev.sigstore.bundle+json;version=0.1"
export FAKE_MEDIATYPE
release media01
FAKE_MEDIATYPE=""
export FAKE_MEDIATYPE
release medianone
FAKE_MEDIATYPE=application/vnd.dev.sigstore.bundle.v0.3+json
export FAKE_MEDIATYPE
release medialegacy
jq '. + {base64Signature: "AAAA"}' "$tmp/medialegacy/SHA256SUMS.sigstore.json" > "$tmp/medialegacy/S" && mv "$tmp/medialegacy/S" "$tmp/medialegacy/SHA256SUMS.sigstore.json"
for m in media01 medianone medialegacy; do
    run "a bundle of the wrong or no media type ($m) is refused" 1 "not a Sigstore bundle of the v0.3 format" --dir "$tmp/$m" "$tag"
    if no_verify; then ok "a bundle of the wrong or no media type ($m) is refused before cosign runs"; else bad "a bundle of the wrong or no media type ($m) is refused before cosign runs"; fi
done
FAKE_SERVE=$tmp/media01
export FAKE_SERVE
run "a bundle of the wrong media type is refused (download)" 1 "not a Sigstore bundle of the v0.3 format" "$tag"

# ---- cosign must not take a trust root or a log key from the environment -----------------------
for var in SIGSTORE_ROOT_FILE SIGSTORE_REKOR_PUBLIC_KEY SIGSTORE_CT_LOG_PUBLIC_KEY_FILE; do
    eval "$var=$tmp/good/SHA256SUMS; export $var"
    run "$var set is refused" 64 "$var is set" --dir "$tmp/good" "$tag"
    eval "unset $var"
    if no_verify; then ok "$var set is refused before cosign runs"; else bad "$var set is refused before cosign runs"; fi
done
run "with those variables unset the same release verifies" 0 "verified $tag" --dir "$tmp/good" "$tag"

# ---- the tag ------------------------------------------------------------------------------------
nl='
'
run "a tag with a newline and a path on the second line is refused" 64 "newline" --dir "$tmp/good" "v0.1.0${nl}../../x"
run "a tag with a newline after a good first line is refused" 64 "newline" --dir "$tmp/good" "$tag$nl"
run "a tag with a space is refused" 64 "is not a release tag" --dir "$tmp/good" "$tag x"

# ---- the folder is read once: the checked copy is what is parsed -------------------------------
# After cosign verifies, the fake appends a line to SHA256SUMS in the user's folder. A script that
# parsed that file again would stop on the line. This one parses the copy it checked.
release toctou
FAKE_MUTATE=$tmp/toctou/SHA256SUMS
export FAKE_MUTATE
run "SHA256SUMS changed in the folder after the check does not matter (the copy is read)" 0 "verified $tag: 9 files match" --dir "$tmp/toctou" "$tag"
unset FAKE_MUTATE
if grep -q 'changed after the check' "$tmp/toctou/SHA256SUMS"; then ok "the fake really changed the file in the folder"; else bad "the fake really changed the file in the folder"; fi

# ---- a relative folder with CDPATH set ---------------------------------------------------------
# cd through CDPATH would take the script to the decoy folder, which holds a changed SHA256SUMS.
mkdir "$tmp/decoy"
cp -R "$tmp/tampered" "$tmp/decoy/good"
CDPATH=$tmp/decoy
export CDPATH
run_cwd=$tmp
run "a relative --dir with CDPATH set reads the folder named, not the decoy" 0 "verified $tag: 9 files match" --dir good "$tag"
run_cwd=""
unset CDPATH
if last_out | grep -q "$tmp/decoy"; then bad "the decoy folder is never entered"; else ok "the decoy folder is never entered"; fi

# ---- symbolic links are refused -----------------------------------------------------------------
release symsums
mv "$tmp/symsums/SHA256SUMS" "$tmp/symsums/real-sums"
ln -s real-sums "$tmp/symsums/SHA256SUMS"
run "a SHA256SUMS that is a symbolic link is refused" 1 "SHA256SUMS is a symbolic link" --dir "$tmp/symsums" "$tag"
if no_verify; then ok "a SHA256SUMS link is refused before cosign runs"; else bad "a SHA256SUMS link is refused before cosign runs"; fi
release symbundle
mv "$tmp/symbundle/SHA256SUMS.sigstore.json" "$tmp/symbundle/real-bundle"
ln -s real-bundle "$tmp/symbundle/SHA256SUMS.sigstore.json"
run "a bundle that is a symbolic link is refused" 1 "SHA256SUMS.sigstore.json is a symbolic link" --dir "$tmp/symbundle" "$tag"
release symasset
mv "$tmp/symasset/rdy-aarch64-apple-darwin.tar.gz" "$tmp/symasset/real-archive"
ln -s real-archive "$tmp/symasset/rdy-aarch64-apple-darwin.tar.gz"
run "an archive that is a symbolic link is refused" 1 "rdy-aarch64-apple-darwin.tar.gz is a symbolic link" --dir "$tmp/symasset" "$tag"

# ---- size caps ----------------------------------------------------------------------------------
release big
dd if=/dev/zero bs=1048576 count=2 2> /dev/null >> "$tmp/big/SHA256SUMS"
run "a SHA256SUMS over 1 MiB in the folder is refused" 1 "which is too large for this file" --dir "$tmp/big" "$tag"
if no_verify; then ok "a SHA256SUMS over 1 MiB is refused before cosign runs"; else bad "a SHA256SUMS over 1 MiB is refused before cosign runs"; fi
FAKE_SERVE=$tmp/big
export FAKE_SERVE
run "a SHA256SUMS over 1 MiB is refused (download)" 1 "Maximum file size exceeded" "$tag"

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
