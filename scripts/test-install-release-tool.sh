#!/bin/sh
# test-install-release-tool.sh: tests for scripts/install-release-tool.sh. Exit 0 when all pass.
#
# A stub `curl` on PATH copies a local file, so no test uses the network. HOME points at a scratch
# folder, so nothing outside it changes. Linux only: it builds a .tar.xz.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/install-release-tool.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

missing=""
for tool in tar xz sha256sum; do
    command -v "$tool" > /dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    if [ -n "${CI:-}" ]; then
        echo "FAIL tools missing in CI:$missing"
        exit 1
    fi
    echo "SKIP all: missing$missing"
    exit 0
fi

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) triple=x86_64-unknown-linux-musl ;;
    Linux/aarch64 | Linux/arm64) triple=aarch64-unknown-linux-musl ;;
    *)
        echo "SKIP all: this test runs on Linux"
        exit 0
        ;;
esac

# A fake release file: <name>/dist inside a .tar.xz.
mkdir -p "$tmp/pkg/cargo-dist-$triple"
printf '#!/bin/sh\necho fake dist\n' > "$tmp/pkg/cargo-dist-$triple/dist"
tar -cJf "$tmp/cargo-dist-$triple.tar.xz" -C "$tmp/pkg" "cargo-dist-$triple"
good_hash=$(sha256sum "$tmp/cargo-dist-$triple.tar.xz" | awk '{ print $1 }')
bad_hash=$(printf '%s' "$good_hash" | tr '0-9a-f' '1-9a-f0')

# Stub curl: copy $STUB_FILE to the -o target. Exit $STUB_CURL_CODE when it is set.
mkdir "$tmp/stubs"
cat > "$tmp/stubs/curl" << 'EOF'
#!/bin/sh
if [ -n "${STUB_CURL_CODE:-}" ]; then exit "$STUB_CURL_CODE"; fi
out=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then out=$2; shift; fi
    shift
done
cp "$STUB_FILE" "$out"
EOF
chmod +x "$tmp/stubs/curl"
STUB_FILE="$tmp/cargo-dist-$triple.tar.xz"
export STUB_FILE

# table <hash> <url>: write a pin table with one dist line for this platform.
table() {
    printf '# test table\ndist 9.9.9 cargo-dist-%s.tar.xz %s %s\n' "$triple" "$1" "$2" > "$tmp/table.txt"
}

# run <name> <expected exit> <expected text> <args...>: runs with a fresh HOME.
run() {
    name=$1
    want=$2
    text=$3
    shift 3
    rm -rf "${tmp:?}/home"
    mkdir "$tmp/home"
    out=$(HOME="$tmp/home" PATH="$tmp/stubs:$PATH" "$script" "$@" 2>&1)
    code=$?
    if [ "$code" -ne "$want" ]; then
        bad "$name (exit $code, want $want)"
        printf '%s\n' "$out"
    elif ! printf '%s\n' "$out" | grep -q "$text"; then
        bad "$name (output lacks '$text')"
        printf '%s\n' "$out"
    else
        ok "$name"
    fi
}

url=https://example.invalid/cargo-dist-$triple.tar.xz

table "$good_hash" "$url"
run "a file with the pinned hash installs" 0 "installed" dist "$tmp/table.txt"
if [ -x "$tmp/home/.cargo/bin/dist" ] && [ "$("$tmp/home/.cargo/bin/dist")" = "fake dist" ]; then
    ok "the installed program is executable and is the one in the archive"
else
    bad "the installed program is executable and is the one in the archive"
fi

table "$bad_hash" "$url"
run "a different hash fails and says so" 1 "has sha256" dist "$tmp/table.txt"
if [ -e "$tmp/home/.cargo/bin/dist" ]; then
    bad "a failed check installs nothing"
else
    ok "a failed check installs nothing"
fi

table "$good_hash" "http://example.invalid/cargo-dist-$triple.tar.xz"
run "a plain http URL is refused" 1 "not https" dist "$tmp/table.txt"

table "abc" "$url"
run "a short hash is refused" 1 "not 64 characters" dist "$tmp/table.txt"

table "$good_hash" "$url"
STUB_CURL_CODE=22
export STUB_CURL_CODE
run "a failed download installs nothing and says so" 1 "could not download" dist "$tmp/table.txt"
unset STUB_CURL_CODE

# cosign is a bare program named cosign-<os>-<cpu>.
case $triple in
    x86_64-unknown-linux-musl) cosign_key=linux-amd64 ;;
    *) cosign_key=linux-arm64 ;;
esac
printf '#!/bin/sh\necho fake cosign\n' > "$tmp/cosign-$cosign_key"
cosign_hash=$(sha256sum "$tmp/cosign-$cosign_key" | awk '{ print $1 }')
printf 'cosign 9.9.9 cosign-%s %s https://example.invalid/cosign-%s\n' "$cosign_key" "$cosign_hash" "$cosign_key" > "$tmp/table.txt"
STUB_FILE="$tmp/cosign-$cosign_key"
export STUB_FILE
run "a bare cosign program with the pinned hash installs" 0 "installed" cosign "$tmp/table.txt"
if [ -x "$tmp/home/.cargo/bin/cosign" ] && [ "$("$tmp/home/.cargo/bin/cosign")" = "fake cosign" ]; then
    ok "the installed cosign is executable and is the downloaded file"
else
    bad "the installed cosign is executable and is the downloaded file"
fi
printf 'cosign 9.9.9 cosign-%s %s https://example.invalid/cosign-%s\n' "$cosign_key" "$bad_hash" "$cosign_key" > "$tmp/table.txt"
run "a cosign file with another hash fails and installs nothing" 1 "has sha256" cosign "$tmp/table.txt"
if [ -e "$tmp/home/.cargo/bin/cosign" ]; then bad "a failed cosign check installs nothing"; else ok "a failed cosign check installs nothing"; fi
STUB_FILE="$tmp/cargo-dist-$triple.tar.xz"
export STUB_FILE

printf '# empty\n' > "$tmp/table.txt"
run "a tool with no line for this platform fails" 1 "has no dist for" dist "$tmp/table.txt"

run "an unknown tool is a usage error" 64 "unknown tool" mystery "$tmp/table.txt"
run "no argument is a usage error" 64 "usage:"

# The committed table must hold a line for every tool and the platforms CI uses.
real="$here/../.github/release-tools.txt"
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin x86_64-pc-windows-msvc; do
    if awk -v s="$t" '$1 == "dist" && index($3, s) > 0 { f = 1 } END { exit !f }' "$real"; then
        ok "the committed table pins dist for $t"
    else
        bad "the committed table pins dist for $t"
    fi
done
for k in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
    if awk -v s="$k" '$1 == "cosign" && index($3, s) > 0 && length($4) == 64 { f = 1 } END { exit !f }' "$real"; then
        ok "the committed table pins cosign for $k"
    else
        bad "the committed table pins cosign for $k"
    fi
done
if awk '$1 == "cargo-cyclonedx" { f = 1 } END { exit !f }' "$real"; then
    ok "the committed table pins cargo-cyclonedx"
else
    bad "the committed table pins cargo-cyclonedx"
fi

exit "$fail"
