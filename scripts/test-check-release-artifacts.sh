#!/bin/sh
# test-check-release-artifacts.sh: tests for scripts/check-release-artifacts.sh. Exit 0 when all pass.
#
# The script is run on a synthetic release folder. The Linux binary is a real static-pie built with
# musl-gcc (the CI Linux legs install musl-tools). The other binaries are stubs with the right
# headers. `objdump` and `cargo` are stubs on PATH, so the tests need no network and no Windows
# build. The real thing runs on the real artifacts in the release workflow.
# Linux only: it needs readelf, tar, unzip and musl-gcc.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/check-release-artifacts.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

# A missing tool skips the tests on a developer machine. In CI ($CI is set) it is a failure, so a
# runner image change cannot turn the tests into a silent pass.
for tool in musl-gcc readelf objdump unzip zip jq python3 tar; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        if [ -n "${CI:-}" ]; then
            echo "FAIL $tool is missing in CI"
            exit 1
        fi
        echo "SKIP all: $tool is missing here (the Linux CI legs have it)"
        exit 0
    fi
done

printf 'int main(void) { return 0; }\n' > "$tmp/hello.c"
if ! musl-gcc -static-pie -Wl,-z,relro,-z,now -o "$tmp/good" "$tmp/hello.c" 2> /dev/null; then
    if [ -n "${CI:-}" ]; then
        echo "FAIL musl-gcc cannot build a static-pie in CI"
        exit 1
    fi
    echo "SKIP all: musl-gcc cannot build a static-pie here"
    exit 0
fi

# Stubs. objdump prints $STUB_DLLS as an import table. cargo prints the file $STUB_AUDIT_FILE and
# exits with $STUB_CODE.
mkdir "$tmp/stubs"
cat > "$tmp/stubs/objdump" << 'EOF'
#!/bin/sh
for dll in $STUB_DLLS; do
    echo "	DLL Name: $dll"
done
EOF
cat > "$tmp/stubs/cargo" << 'EOF'
#!/bin/sh
# `cargo tree` prints $STUB_TREE. Anything else is `cargo audit`.
if [ "$1" = "tree" ]; then
    printf '%s\n' "${STUB_TREE:-rdy v0.1.0}"
    exit "${STUB_TREE_CODE:-0}"
fi
cat "$STUB_AUDIT_FILE"
exit "${STUB_CODE:-0}"
EOF
chmod +x "$tmp/stubs/objdump" "$tmp/stubs/cargo"
STUB_AUDIT_FILE="$tmp/audit.json"
export STUB_AUDIT_FILE
# set_audit <exit code> <json>: what the stub cargo does next.
set_audit() {
    STUB_CODE=$1
    export STUB_CODE
    printf '%s\n' "$2" > "$STUB_AUDIT_FILE"
}
good_audit='{"lockfile":{"dependency-count":63},"vulnerabilities":{"found":false,"count":0,"list":[]}}'

# set_machine <file> <octal byte>: set the low byte of e_machine (offset 18). 076 = x86-64, 267 = AArch64.
set_machine() {
    printf '%b' "\\0$2" | dd of="$1" bs=1 seek=18 count=1 conv=notrunc 2> /dev/null
}

# make_archive <dir> <triple> <binary file>: put the binary in a dist-shaped archive.
make_archive() {
    d=$1
    t=$2
    src=$3
    name=rdy
    case $t in *-windows-*) name=rdy.exe ;; esac
    stage="$tmp/stage-$t"
    rm -rf "$stage"
    mkdir -p "$stage/rdy-$t"
    cp "$src" "$stage/rdy-$t/$name"
    for f in LICENSE README.md CHANGELOG.md; do echo "synthetic $f" > "$stage/rdy-$t/$f"; done
    case $t in
        *-windows-*) (cd "$stage" && zip -q -r "$d/rdy-$t.zip" "rdy-$t") ;;
        *) tar -czf "$d/rdy-$t.tar.gz" -C "$stage" "rdy-$t" ;;
    esac
}

# hash_all <dir>: write the .sha256 files and sha256.sum for every archive in the folder.
hash_all() {
    : > "$1/sha256.sum"
    for a in "$1"/rdy-*.tar.gz "$1"/rdy-*.zip; do
        [ -f "$a" ] || continue
        h=$(sha256sum "$a" | awk '{ print $1 }')
        echo "$h *$(basename "$a")" > "$a.sha256"
        echo "$h *$(basename "$a")" >> "$1/sha256.sum"
    done
}

# Stub binaries: a good x86-64 ELF, a good AArch64 ELF, Mach-O headers and a PE header.
cp "$tmp/good" "$tmp/elf-x64"
set_machine "$tmp/elf-x64" 076
cp "$tmp/good" "$tmp/elf-arm64"
set_machine "$tmp/elf-arm64" 267
{ printf '\317\372\355\376\007\000\000\001'; head -c 64 /dev/zero; } > "$tmp/macho-x64"
{ printf '\317\372\355\376\014\000\000\001'; head -c 64 /dev/zero; } > "$tmp/macho-arm64"
# A PE header: MZ, e_lfanew = 64 at byte 60, then "PE\0\0" and the machine 0x8664 (x86-64).
{ printf 'MZ'; head -c 58 /dev/zero; printf '\100\000\000\000'; printf 'PE\000\000\144\206'; head -c 64 /dev/zero; } > "$tmp/pe"
# The same with machine 0x014c (i386), and a bare MZ with no PE header.
{ printf 'MZ'; head -c 58 /dev/zero; printf '\100\000\000\000'; printf 'PE\000\000\114\001'; head -c 64 /dev/zero; } > "$tmp/pe-i386-bin"
{ printf 'MZ'; head -c 64 /dev/zero; } > "$tmp/mz-only"

cat > "$tmp/sbom.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.3" version="1">
  <components><component type="library"><name>serde</name></component></components>
</bom>
EOF

# fresh <name>: a complete, passing release folder at $tmp/<name>.
fresh() {
    d="$tmp/$1"
    rm -rf "$d"
    mkdir -p "$d"
    make_archive "$d" x86_64-unknown-linux-musl "$tmp/elf-x64"
    make_archive "$d" aarch64-unknown-linux-musl "$tmp/elf-arm64"
    make_archive "$d" x86_64-apple-darwin "$tmp/macho-x64"
    make_archive "$d" aarch64-apple-darwin "$tmp/macho-arm64"
    make_archive "$d" x86_64-pc-windows-msvc "$tmp/pe"
    cp "$tmp/sbom.xml" "$d/rdy.cdx.xml"
    hash_all "$d"
}

# check <name> <expected exit> <expected text in output> <dir> [env assignments are set by the caller]
# The stubs come first on PATH. STUB_DLLS, STUB_AUDIT and STUB_CODE are read from the caller's shell.
check() {
    name=$1
    want=$2
    text=$3
    shift 3
    out=$(PATH="$tmp/stubs:$PATH" "$script" "$@" 2>&1)
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

STUB_DLLS="KERNEL32.dll ntdll.dll"
export STUB_DLLS
set_audit 0 "$good_audit"

fresh good
check "a complete release folder passes" 0 "release artifacts ok" "$tmp/good"

# 1. Archives and checksums.
fresh missing
rm "$tmp/missing/rdy-aarch64-apple-darwin.tar.gz"
check "a missing archive fails and is named" 1 "FAIL rdy-aarch64-apple-darwin.tar.gz exists" "$tmp/missing"

fresh nosum
rm "$tmp/nosum/rdy-x86_64-pc-windows-msvc.zip.sha256"
check "a missing .sha256 file fails" 1 "FAIL rdy-x86_64-pc-windows-msvc.zip has a .sha256 file" "$tmp/nosum"

fresh tampered
printf 'x' >> "$tmp/tampered/rdy-x86_64-apple-darwin.tar.gz"
check "an archive changed after hashing fails" 1 "FAIL rdy-x86_64-apple-darwin.tar.gz matches" "$tmp/tampered"

fresh badsum
sed 's/^[0-9a-f]/0/' "$tmp/badsum/sha256.sum" > "$tmp/badsum/sha256.sum.new"
mv "$tmp/badsum/sha256.sum.new" "$tmp/badsum/sha256.sum"
check "a sha256.sum that disagrees fails" 1 "FAIL rdy-.* matches sha256.sum" "$tmp/badsum"

# 2. Contents.
fresh traversal
if tar -czf "$tmp/traversal/rdy-x86_64-apple-darwin.tar.gz" --transform 's,^,../,' -C "$tmp" macho-x64 2> /dev/null; then
    hash_all "$tmp/traversal"
    check "an archive with a .. path fails" 1 "FAIL rdy-x86_64-apple-darwin.tar.gz holds only safe paths" "$tmp/traversal"
else
    echo "SKIP traversal fixture: this tar has no --transform"
fi

fresh nolicense
mkdir "$tmp/nolicense-stage"
mkdir "$tmp/nolicense-stage/rdy-x86_64-apple-darwin"
cp "$tmp/macho-x64" "$tmp/nolicense-stage/rdy-x86_64-apple-darwin/rdy"
tar -czf "$tmp/nolicense/rdy-x86_64-apple-darwin.tar.gz" -C "$tmp/nolicense-stage" rdy-x86_64-apple-darwin
hash_all "$tmp/nolicense"
check "an archive without LICENSE fails" 1 "FAIL rdy-x86_64-apple-darwin.tar.gz holds its files" "$tmp/nolicense"

# 3. Format and CPU.
fresh wrongcpu
make_archive "$tmp/wrongcpu" aarch64-apple-darwin "$tmp/macho-x64"
hash_all "$tmp/wrongcpu"
check "an x86-64 Mach-O in the arm64 archive fails" 1 "FAIL aarch64-apple-darwin binary is an arm64 Mach-O" "$tmp/wrongcpu"

fresh wrongelf
make_archive "$tmp/wrongelf" aarch64-unknown-linux-musl "$tmp/elf-x64"
hash_all "$tmp/wrongelf"
check "an x86-64 ELF in the aarch64 archive fails" 1 "FAIL aarch64-unknown-linux-musl binary is an AArch64 ELF" "$tmp/wrongelf"

fresh pe32
make_archive "$tmp/pe32" x86_64-pc-windows-msvc "$tmp/pe-i386-bin"
hash_all "$tmp/pe32"
check "a 32-bit PE in the x86-64 Windows archive fails" 1 "FAIL x86_64-pc-windows-msvc binary is an x86-64 PE file" "$tmp/pe32"
fresh mzonly
make_archive "$tmp/mzonly" x86_64-pc-windows-msvc "$tmp/mz-only"
hash_all "$tmp/mzonly"
check "a file with only an MZ header fails" 1 "FAIL x86_64-pc-windows-msvc binary is an x86-64 PE file" "$tmp/mzonly"

# 4. Static-pie.
if musl-gcc -static -no-pie -o "$tmp/nopie-bin" "$tmp/hello.c" 2> /dev/null; then
    set_machine "$tmp/nopie-bin" 267
    fresh nopie
    make_archive "$tmp/nopie" aarch64-unknown-linux-musl "$tmp/nopie-bin"
    hash_all "$tmp/nopie"
    check "a non-PIE aarch64 binary fails check-static" 1 "FAIL aarch64-unknown-linux-musl binary is a hardened static-pie" "$tmp/nopie"
    check "check-static's own failure lines are shown" 1 "| FAIL position independent" "$tmp/nopie"
else
    echo "SKIP non-PIE fixture: musl-gcc -static -no-pie did not build"
fi

# 5. VCRUNTIME.
STUB_DLLS="KERNEL32.dll VCRUNTIME140.dll"
export STUB_DLLS
check "a VCRUNTIME140 import fails" 1 "FAIL rdy.exe imports no VCRUNTIME DLL" "$tmp/good"
STUB_DLLS="KERNEL32.dll vcruntime140_1.dll"
export STUB_DLLS
check "a lower-case vcruntime140_1 import fails" 1 "FAIL rdy.exe imports no VCRUNTIME DLL" "$tmp/good"
STUB_DLLS=""
export STUB_DLLS
check "an empty import table proves nothing and fails" 1 "FAIL rdy.exe imports no VCRUNTIME DLL" "$tmp/good"
STUB_DLLS="KERNEL32.dll ntdll.dll"
export STUB_DLLS

# 6. cargo audit bin.
set_audit 0 '{"lockfile":{"dependency-count":0},"vulnerabilities":{"found":false,"count":0,"list":[]}}'
check "a binary with no dependency data fails" 1 "FAIL cargo audit bin lists dependencies" "$tmp/good"
set_audit 1 '{"lockfile":{"dependency-count":63},"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-0000-0000"},"package":{"name":"example","version":"1.0.0"}}]}}'
check "a known vulnerability fails" 1 "RUSTSEC-0000-0000 example 1.0.0" "$tmp/good"
set_audit 2 ""
check "an audit run that prints nothing fails" 1 "FAIL cargo audit bin lists dependencies" "$tmp/good"
set_audit 0 "$good_audit"
check "--skip-audit warns loudly and passes the rest" 0 "WARN cargo audit bin SKIPPED" --skip-audit "$tmp/good"

# 7. SBOM.
fresh nosbom
rm "$tmp/nosbom/rdy.cdx.xml"
check "a missing SBOM fails" 1 "FAIL an SBOM exists" "$tmp/nosbom"
fresh badsbom
echo '<bom' > "$tmp/badsbom/rdy.cdx.xml"
check "a broken SBOM fails" 1 "FAIL rdy.cdx.xml is CycloneDX XML" "$tmp/badsbom"
fresh emptysbom
echo '<bom xmlns="http://cyclonedx.org/schema/bom/1.3"></bom>' > "$tmp/emptysbom/rdy.cdx.xml"
check "an SBOM without components fails" 1 "FAIL rdy.cdx.xml is CycloneDX XML" "$tmp/emptysbom"
fresh jsonsbom
rm "$tmp/jsonsbom/rdy.cdx.xml"
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"serde"}]}' > "$tmp/jsonsbom/rdy.cdx.json"
check "a CycloneDX JSON SBOM passes" 0 "rdy.cdx.json is CycloneDX JSON" "$tmp/jsonsbom"

# 0. Only the expected files.
fresh extra
echo surprise > "$tmp/extra/install-me.sh"
check "an unexpected file fails and is named" 1 "FAIL install-me.sh is an expected release file" "$tmp/extra"
fresh extradir
mkdir "$tmp/extradir/sub"
check "a folder fails" 1 "FAIL sub is a regular file" "$tmp/extradir"
fresh nested
mkdir "$tmp/nested/sub"
echo nested > "$tmp/nested/sub/sha256.sum"
check "a file in a folder fails even with an allowed name" 1 "FAIL sub/sha256.sum is an expected release file" "$tmp/nested"
fresh link
ln -s /etc/passwd "$tmp/link/sha256.sum.link"
check "a symlink fails" 1 "FAIL sha256.sum.link is not a symlink" "$tmp/link"
fresh linkallowed
rm "$tmp/linkallowed/sha256.sum"
ln -s /etc/passwd "$tmp/linkallowed/sha256.sum"
check "a symlink with an allowed name fails" 1 "FAIL sha256.sum is not a symlink" "$tmp/linkallowed"
fresh manifests
for m in dist-manifest.json plan-dist-manifest.json global-dist-manifest.json x86_64-unknown-linux-musl-dist-manifest.json source.tar.gz source.tar.gz.sha256; do
    echo '{}' > "$tmp/manifests/$m"
done
check "dist's own manifests and the source tarball are allowed" 0 "release artifacts ok" "$tmp/manifests"
check "--files-only passes a clean folder without any tool" 0 "release files ok" --files-only "$tmp/good"
check "--files-only fails on an unexpected file" 1 "FAIL install-me.sh" --files-only "$tmp/extra"
check "--files-only does not look at the contents" 0 "release files ok" --files-only "$tmp/badsbom"

# 8. Features. The stub `cargo tree` prints what it is told.
STUB_TREE='rdy v0.1.0 / serde_json feature preserve_order'
export STUB_TREE
check "preserve_order in the rdy build fails" 1 "FAIL no preserve_order in the x86_64-unknown-linux-musl build" "$tmp/good"
unset STUB_TREE
STUB_TREE_CODE=101
export STUB_TREE_CODE
check "a failing cargo tree fails" 1 "FAIL cargo tree runs for" "$tmp/good"
unset STUB_TREE_CODE
check "a clean feature tree passes" 0 "PASS no preserve_order in the aarch64-apple-darwin build" "$tmp/good"

# Usage.
check "no argument is a usage error" 64 "usage:"
check "a missing folder is a usage error" 64 "is not a directory" "$tmp/does-not-exist"

exit "$fail"
