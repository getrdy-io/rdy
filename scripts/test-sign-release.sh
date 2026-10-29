#!/bin/sh
# test-sign-release.sh: tests for scripts/make-sha256sums.sh and scripts/sign-release.sh. Exit 0 when
# all pass.
#
# A fake `cosign` on PATH stands in for Sigstore, so no test needs the network or an OIDC token.
# The fake behaves like the parts of cosign that matter here. `sign-blob` writes a bundle that holds
# the sha256 of the blob, the identity in $FAKE_SIGNER and the caller claims in $FAKE_REPO, $FAKE_REF
# and $FAKE_TRIGGER (what Fulcio puts in the certificate of a reusable workflow: the identity names the
# called file, the claims name the caller). `verify-blob` fails unless the blob's sha256, the identity
# and the issuer all match, and each --certificate-github-workflow-* flag that it gets matches the claim. Every call is logged, so the tests read the exact arguments.
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
# The caller's claims. The identity alone names the called workflow file, so any repository that
# calls a public reusable workflow would match it.
want_claims="--certificate-github-workflow-repository $repo --certificate-github-workflow-ref refs/tags/$tag --certificate-github-workflow-trigger push"

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
        [ -z "${FAKE_SIGN_FAIL:-}" ] || { echo "fake cosign: no OIDC token" >&2; exit 1; }
        media=""
        [ -z "$FAKE_MEDIATYPE" ] || media="\"mediaType\":\"$FAKE_MEDIATYPE\","
        printf '{%s"digest":"%s","identity":"%s","repo":"%s","ref":"%s","trigger":"%s"%s,"verificationMaterial":{"tlogEntries":[{"logIndex":"4242"}]}}\n' \
            "$media" "$digest" "$FAKE_SIGNER" "$FAKE_REPO" "$FAKE_REF" "$FAKE_TRIGGER" "${FAKE_EXTRA:-}" > "$bundle"
        # FAKE_TOUCH: a file in the folder changes while the signature is made.
        [ -z "${FAKE_TOUCH:-}" ] || echo changed >> rdy-x86_64-apple-darwin.tar.gz
        echo "ZmFrZQ=="
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
chmod +x "$tmp/bin/cosign"
FAKE_LOG="$tmp/cosign.log"
export FAKE_LOG
FAKE_SIGNER=$want_identity
FAKE_REPO=$repo
FAKE_REF=refs/tags/$tag
FAKE_TRIGGER=push
FAKE_MEDIATYPE=application/vnd.dev.sigstore.bundle.v0.3+json
export FAKE_SIGNER FAKE_REPO FAKE_REF FAKE_TRIGGER FAKE_MEDIATYPE

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
# The placeholder line is the one in M1-014's install.sh.
source_tree src-ok "#!/bin/sh
RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'
case \$RDY_STAMPED_VERSION in '' | @@*) echo unstamped ;; esac
echo hello"
source_tree src-two "#!/bin/sh
RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'
RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'
echo hello"
source_tree src-indented "#!/bin/sh
 RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'
echo hello"
source_tree src-oldname '#!/bin/sh
RDY_DEFAULT_VERSION="@RDY_VERSION@"
echo hello'
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
GITHUB_STEP_SUMMARY="$tmp/summary.md"
export GITHUB_STEP_SUMMARY
run "a good release is signed and verified" 0 "rekor log: 4242" "$tmp/good" "$tag" "$repo" "$tmp/src-ok"
unset GITHUB_STEP_SUMMARY
# shellcheck disable=SC2016  # the backticks are literal Markdown
if grep -q 'Rekor log index: `4242`' "$tmp/summary.md" && grep -q "Claims: repository \`$repo\`, ref \`refs/tags/$tag\`, trigger \`push\`" "$tmp/summary.md"; then
    ok "the step summary holds the Rekor log index and the claims"
else
    bad "the step summary holds the Rekor log index and the claims"
fi
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
stamped_lines=$(grep -c -x "RDY_STAMPED_VERSION='v0.1.0-alpha.1'" "$tmp/good/install.sh")
if [ "$stamped_lines" = 1 ] && ! grep -q '^RDY_STAMPED_VERSION=.@@' "$tmp/good/install.sh"; then
    ok "install.sh carries this tag, with the v, on exactly one RDY_STAMPED_VERSION line"
else
    bad "install.sh carries this tag, with the v, on exactly one RDY_STAMPED_VERSION line"
fi
if [ "$(sed -n 2p "$tmp/good/install.sh")" = "RDY_STAMPED_VERSION='v0.1.0-alpha.1'" ] && [ "$(sed -n 3p "$tmp/good/install.sh")" = "case \$RDY_STAMPED_VERSION in '' | @@*) echo unstamped ;; esac" ]; then
    ok "only the placeholder line changes in install.sh"
else
    bad "only the placeholder line changes in install.sh"
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
if [ "$verify_line" = "verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity $want_identity --certificate-oidc-issuer $want_issuer $want_claims SHA256SUMS" ]; then
    ok "cosign verify-blob gets the exact identity, issuer, repository, ref and trigger, no regular expression"
else
    bad "cosign verify-blob gets the exact identity, issuer, repository, ref and trigger, no regular expression (got: $verify_line)"
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

# verify_good: the verify-blob form from 06 against the signed folder, with the fake cosign.
verify_good() {
    # shellcheck disable=SC2086  # want_claims is a list of flags, one word each
    PATH="$tmp/bin:$PATH" cosign verify-blob --bundle "$tmp/good/SHA256SUMS.sigstore.json" \
        --certificate-identity "$want_identity" --certificate-oidc-issuer "$want_issuer" \
        $want_claims "$tmp/good/SHA256SUMS" > /dev/null 2>&1
}
# The exit test, in the fake's terms: the bundle verifies, and fails after one byte changes.
if verify_good; then
    ok "verify-blob passes on the signed SHA256SUMS"
else
    bad "verify-blob passes on the signed SHA256SUMS"
fi
printf 'x' >> "$tmp/good/SHA256SUMS"
if verify_good; then
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

# The reusable-workflow hole: the identity is right (it names our file) but the run that called it
# belongs to another repository, another ref or another trigger.
release wrongrepo
FAKE_REPO=evil-org/rdy
export FAKE_REPO
run "a signature made by another repository's run fails the self-verify" 1 "does not verify as" "$tmp/wrongrepo" "$tag" "$repo" "$tmp/src-ok"
if [ -e "$tmp/wrongrepo/SHA256SUMS" ] || [ -e "$tmp/wrongrepo/SHA256SUMS.sigstore.json" ]; then
    bad "a wrong caller repository leaves no signature files"
else
    ok "a wrong caller repository leaves no signature files"
fi
FAKE_REPO=$repo
export FAKE_REPO
release wrongref
FAKE_REF=refs/heads/main
export FAKE_REF
run "a signature made from a branch run fails the self-verify" 1 "does not verify as" "$tmp/wrongref" "$tag" "$repo" "$tmp/src-ok"
FAKE_REF=refs/tags/$tag
export FAKE_REF
release wrongtrigger
FAKE_TRIGGER=workflow_dispatch
export FAKE_TRIGGER
run "a signature made by a manual run fails the self-verify" 1 "does not verify as" "$tmp/wrongtrigger" "$tag" "$repo" "$tmp/src-ok"
FAKE_TRIGGER=push
export FAKE_TRIGGER

# The bundle format guard (M1-015). install.sh and verify-release.sh refuse a bundle that is not v0.3,
# that has a legacy key, or that has a JSON escape. A release that fails here is never published.
# Each spec is name:mediaType:extra JSON members. The escape spec has a backslash, u0053, in a key.
bs='\'
for spec in "legacy:application/vnd.dev.sigstore.bundle+json;version=0.1:" \
    "none::" \
    'legacykey:application/vnd.dev.sigstore.bundle.v0.3+json:,"base64Signature":"ZmFrZQ=="' \
    "escape:application/vnd.dev.sigstore.bundle.v0.3+json:,\"base64${bs}u0053ignature\":\"x\""; do
    bname=${spec%%:*}
    rest=${spec#*:}
    FAKE_MEDIATYPE=${rest%%:*}
    FAKE_EXTRA=${rest#*:}
    export FAKE_MEDIATYPE FAKE_EXTRA
    release "bundle-$bname"
    run "a bundle with $bname format fails the self-verify guard" 1 "not a plain Sigstore bundle" "$tmp/bundle-$bname" "$tag" "$repo" "$tmp/src-ok"
    if [ -e "$tmp/bundle-$bname/SHA256SUMS" ] || [ -e "$tmp/bundle-$bname/SHA256SUMS.sigstore.json" ]; then
        bad "a $bname bundle leaves no signature files"
    else
        ok "a $bname bundle leaves no signature files"
    fi
done
FAKE_MEDIATYPE=application/vnd.dev.sigstore.bundle.v0.3+json
FAKE_EXTRA=""
export FAKE_MEDIATYPE FAKE_EXTRA

# The files change while cosign signs.
release touched
FAKE_TOUCH=1
export FAKE_TOUCH
run "files that change while signing are not published" 1 "changed while signing" "$tmp/touched" "$tag" "$repo" "$tmp/src-ok"
unset FAKE_TOUCH
if [ -e "$tmp/touched/SHA256SUMS" ] || [ -e "$tmp/touched/SHA256SUMS.sigstore.json" ]; then
    bad "files that changed while signing leave no signature files"
else
    ok "files that changed while signing leave no signature files"
fi

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
release indented
run "an install.sh whose stamp line is indented is refused" 1 "on 0 lines" "$tmp/indented" "$tag" "$repo" "$tmp/src-indented"
release oldname
run "an install.sh with the old @RDY_VERSION@ text is refused" 1 "on 0 lines" "$tmp/oldname" "$tag" "$repo" "$tmp/src-oldname"
if [ -e "$tmp/oldname/install.sh" ]; then bad "a refused install.sh is not copied in"; else ok "a refused install.sh is not copied in"; fi
if [ -s "$FAKE_LOG" ]; then bad "cosign is not called after a refused install.sh"; else ok "cosign is not called after a refused install.sh"; fi

# The repo's real install.sh, not a stand-in: it must survive the stamp. The stamp must leave a script
# that parses, keeps its end marker on the last line (M1-014's truncation guard), and holds exactly
# one stamped line. Only that one line may differ from the source.
real=$here/../install.sh
mkdir "$tmp/src-real"
cp "$real" "$tmp/src-real/install.sh"
release realinstall
run "the real install.sh is stamped" 0 "stamped install.sh" "$tmp/realinstall" "$tag" "$repo" "$tmp/src-real"
if sh -n "$tmp/realinstall/install.sh" 2> /dev/null; then
    ok "the stamped real install.sh passes sh -n"
else
    bad "the stamped real install.sh passes sh -n"
fi
if [ "$(tail -n 1 "$real")" = "$(tail -n 1 "$tmp/realinstall/install.sh")" ] && tail -n 1 "$tmp/realinstall/install.sh" | grep -q 'END_MARK'; then
    ok "the stamped real install.sh keeps its end marker on the last line"
else
    bad "the stamped real install.sh keeps its end marker on the last line"
fi
if [ "$(grep -c -x "RDY_STAMPED_VERSION='$tag'" "$tmp/realinstall/install.sh")" = 1 ] && ! grep -q '@@RDY_STAMPED_VERSION@@' "$tmp/realinstall/install.sh"; then
    ok "the stamped real install.sh has exactly one stamped line and no placeholder"
else
    bad "the stamped real install.sh has exactly one stamped line and no placeholder"
fi
if [ "$(diff "$real" "$tmp/realinstall/install.sh" | grep -c '^[<>]')" = 2 ]; then
    ok "only the stamp line differs from the real install.sh"
else
    bad "only the stamp line differs from the real install.sh"
fi

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
