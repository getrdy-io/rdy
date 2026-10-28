#!/bin/sh
# check-release-artifacts.sh: prove the files dist built are the files we mean to ship (M1-007).
#
# Usage: scripts/check-release-artifacts.sh [--skip-audit | --files-only] <dir>
# <dir> holds the release assets in one flat folder: what dist writes to target/distrib, or what
# `gh release download` fetches. The release workflow runs this on the built artifacts in a publish
# job before the GitHub Release is created (.github/workflows/check-release-artifacts.yml). Its
# `announce` job runs it again with --files-only on the folder it publishes.
#
# Checks:
#   0. The folder holds only files from the expected list (below), as regular files. Any other
#      name, folder or symlink fails, so nothing unexpected is published. --files-only runs just this.
#      The expected files, with <t> a target triple from the list in this script: rdy-<t>.tar.gz
#      (rdy-<t>.zip on Windows) and its .sha256, source.tar.gz and its .sha256, sha256.sum,
#      rdy.cdx.xml (or rdy.cdx.json), dist-manifest.json, and dist's per-job manifests (plan-,
#      global- and <t>-dist-manifest.json), which the announce job deletes before it publishes.
#   1. All five archives exist, each with its .sha256 file, and the hashes match. If dist's
#      sha256.sum exists, it must agree too.
#   2. Each archive holds only safe paths and rdy-<triple>/{rdy|rdy.exe,LICENSE,README.md,CHANGELOG.md}.
#   3. Each binary has the format and CPU its file name says (ELF, Mach-O or PE).
#   4. Both Linux binaries pass scripts/check-static.sh (ADR 0006, decision 2). A linker override
#      such as cargo-zigbuild would bypass scripts/musl-pie-linker.sh. This catches it.
#   5. rdy.exe is an x86-64 PE file and imports no VCRUNTIME DLL (the C runtime is linked in).
#   6. `cargo audit bin` finds the embedded dependency list in every binary and no vulnerability.
#   7. The SBOM is well-formed CycloneDX with components.
#   8. `cargo tree -p rdy -e features` for each target shows no `preserve_order`. That feature of
#      serde_json belongs to the schema tooling (rdy-spec's optional `schema` feature, used only by
#      xtask). It would reach the binary if dist built the whole workspace, so a build with
#      `precise-builds = false` fails here. `cargo tree -p rdy` cannot see a workspace build, so
#      this step also requires the line `precise-builds = true` in dist-workspace.toml.
#      Run from a full checkout: it reads Cargo.lock.
# Exit: 0 all checks pass, 1 at least one fails, 64 usage error or a missing tool.
#
# Needs: tar, unzip, readelf, objdump, od, awk, jq, python3, cargo with cargo-audit, and sha256sum or
# shasum. Pass --skip-audit only for offline runs of the script tests. It prints a loud warning.

set -u

LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)

skip_audit=0
files_only=0
if [ "$#" -eq 2 ]; then
    case $1 in
        --skip-audit) skip_audit=1 ;;
        --files-only) files_only=1 ;;
        *)
            echo "usage: scripts/check-release-artifacts.sh [--skip-audit | --files-only] <dir>" >&2
            exit 64
            ;;
    esac
    shift
fi
if [ "$#" -ne 1 ]; then
    echo "usage: scripts/check-release-artifacts.sh [--skip-audit | --files-only] <dir>" >&2
    exit 64
fi
dir=${1%/}
if [ ! -d "$dir" ]; then
    echo "error: $dir is not a directory" >&2
    echo "fix: pass the folder with the release assets, for example target/distrib" >&2
    exit 64
fi

need() {
    if ! command -v "$1" > /dev/null 2>&1; then
        echo "error: $1 is not installed" >&2
        echo "fix: $2" >&2
        exit 64
    fi
}
need awk "install awk"
need find "install findutils"
if [ "$files_only" -eq 0 ]; then
    need tar "install tar"
    need unzip "install unzip (on Debian or Ubuntu, 'apt-get install unzip')"
    need readelf "install binutils (on Debian or Ubuntu, 'apt-get install binutils')"
    need objdump "install binutils (on Debian or Ubuntu, 'apt-get install binutils')"
    need od "install coreutils"
    need jq "install jq (on Debian or Ubuntu, 'apt-get install jq')"
    need python3 "install python3"
    need cargo "install the Rust toolchain from rust-toolchain.toml"
    if command -v sha256sum > /dev/null 2>&1; then
        sha256_of() { sha256sum "$1" | awk '{ print $1 }'; }
    elif command -v shasum > /dev/null 2>&1; then
        sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }
    else
        echo "error: neither sha256sum nor shasum is installed" >&2
        echo "fix: install coreutils (sha256sum) or perl (shasum)" >&2
        exit 64
    fi
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

bad=0
fail() {
    bad=$((bad + 1))
    printf 'FAIL %s\n' "$1"
    printf '  fix: %s\n' "$2"
}
pass() { printf 'PASS %s\n' "$1"; }

# The five release targets (ADR 0006, decision 1). Keep this list equal to dist-workspace.toml.
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc"

archive_of() {
    case $1 in
        *-windows-*) echo "rdy-$1.zip" ;;
        *) echo "rdy-$1.tar.gz" ;;
    esac
}

# ---- 0. Only the expected files ------------------------------------------------------------
{
    for t in $targets; do
        a=$(archive_of "$t")
        printf '%s\n' "$a" "$a.sha256" "$t-dist-manifest.json"
    done
    printf '%s\n' source.tar.gz source.tar.gz.sha256 sha256.sum rdy.cdx.xml rdy.cdx.json \
        dist-manifest.json plan-dist-manifest.json global-dist-manifest.json
} > "$work/allowed.txt"
find "$dir" -mindepth 1 > "$work/found.txt"
unexpected=0
while IFS= read -r f; do
    rel=${f#"$dir"/}
    if [ -L "$f" ]; then
        fail "$rel is not a symlink" "a symlink could publish a file from outside this folder. Remove it and find out what made it."
        unexpected=1
    elif [ ! -f "$f" ]; then
        fail "$rel is a regular file" "folders and special files are not release assets. Remove it and find out what made it."
        unexpected=1
    elif ! grep -Fxq -- "$rel" "$work/allowed.txt"; then
        fail "$rel is an expected release file" "it is not on the list in scripts/check-release-artifacts.sh. If it should ship, add it there with a ticket. If not, find out what wrote it."
        unexpected=1
    fi
done < "$work/found.txt"
if [ "$unexpected" -eq 0 ]; then
    pass "the folder holds only expected release files"
fi
if [ "$files_only" -eq 1 ]; then
    if [ "$bad" -gt 0 ]; then
        printf 'error: %s holds files that must not be published (%s check(s) failed)\n' "$dir" "$bad" >&2
        exit 1
    fi
    echo "release files ok: $dir"
    exit 0
fi

# first_hash <file>: the first field of the first line, which is the sha256 in dist's files.
first_hash() { awk 'NR == 1 { print $1; exit }' "$1"; }

# ---- 1. Archives and checksums -------------------------------------------------------------
for t in $targets; do
    a=$(archive_of "$t")
    if [ ! -f "$dir/$a" ]; then
        fail "$a exists" "the build for $t produced no archive. Look at its job in the release run."
        continue
    fi
    if [ ! -f "$dir/$a.sha256" ]; then
        fail "$a has a .sha256 file" "dist writes one per archive. Check 'checksum = \"sha256\"' in dist-workspace.toml."
        continue
    fi
    want=$(first_hash "$dir/$a.sha256")
    got=$(sha256_of "$dir/$a")
    if [ "$want" != "$got" ]; then
        fail "$a matches $a.sha256" "the archive changed after dist hashed it. Do not ship it. Rebuild from the tag."
        continue
    fi
    if [ -f "$dir/sha256.sum" ]; then
        # dist's combined file: "<hash> *<name>" lines.
        line=$(awk -v n="$a" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$dir/sha256.sum")
        if [ "$line" != "$got" ]; then
            fail "$a matches sha256.sum" "sha256.sum has a different hash or no line for this archive. Rebuild from the tag."
            continue
        fi
    fi
    pass "$a and its checksum"
done

# ---- 2 and 3. Contents, format, CPU --------------------------------------------------------
# bin_of <triple>: the extracted binary path, or nothing when the archive was not usable.
bin_of() {
    case $1 in
        *-windows-*) echo "$work/$1/rdy-$1/rdy.exe" ;;
        *) echo "$work/$1/rdy-$1/rdy" ;;
    esac
}

# elf_machine <path>: readelf's Machine text.
elf_machine() { readelf -hW "$1" 2> /dev/null | awk -F: '/^[[:space:]]*Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }'; }

# magic <path> <bytes>: lower-case hex of the first bytes.
magic() { od -An -tx1 -N"$2" "$1" | tr -d ' \n'; }

check_format() {
    t=$1
    b=$(bin_of "$t")
    case $t in
        x86_64-unknown-linux-musl)
            if [ "$(magic "$b" 4)" = "7f454c46" ] && [ "$(elf_machine "$b")" = "Advanced Micro Devices X86-64" ]; then
                pass "$t binary is an x86-64 ELF"
            else
                fail "$t binary is an x86-64 ELF" "the archive holds another kind of file. Check the matrix in the release run."
            fi
            ;;
        aarch64-unknown-linux-musl)
            if [ "$(magic "$b" 4)" = "7f454c46" ] && [ "$(elf_machine "$b")" = "AArch64" ]; then
                pass "$t binary is an AArch64 ELF"
            else
                fail "$t binary is an AArch64 ELF" "the archive holds another kind of file. Check the matrix in the release run."
            fi
            ;;
        x86_64-apple-darwin)
            # 64-bit little-endian Mach-O (cffaedfe), CPU_TYPE_X86_64 (07000001).
            if [ "$(magic "$b" 8)" = "cffaedfe07000001" ]; then
                pass "$t binary is an x86-64 Mach-O"
            else
                fail "$t binary is an x86-64 Mach-O" "the archive holds another kind of file. Check the matrix in the release run."
            fi
            ;;
        aarch64-apple-darwin)
            # This target is cross-compiled on an Intel runner and never run there (ADR 0006,
            # decision 8). The CPU in the header is the proof that it is arm64: CPU_TYPE_ARM64.
            if [ "$(magic "$b" 8)" = "cffaedfe0c000001" ]; then
                pass "$t binary is an arm64 Mach-O"
            else
                fail "$t binary is an arm64 Mach-O" "the cross build made another CPU. Check 'dist_args' for this target in the release run."
            fi
            ;;
        x86_64-pc-windows-msvc)
            # MZ header, then at the offset in e_lfanew (byte 60) "PE\0\0" and machine 0x8664.
            off=$(od -An -tu4 -j60 -N4 "$b" 2> /dev/null | tr -d ' \n')
            case $off in
                '' | *[!0-9]*) off="" ;;
                *) ;;
            esac
            if [ "$(magic "$b" 2)" = "4d5a" ] && [ -n "$off" ] &&
                [ "$(od -An -tx1 -j"$off" -N6 "$b" 2> /dev/null | tr -d ' \n')" = "504500006486" ]; then
                pass "$t binary is an x86-64 PE file"
            else
                fail "$t binary is an x86-64 PE file" "the archive holds another kind of file or another CPU. Check the matrix in the release run."
            fi
            ;;
        *) fail "$t is a known target" "add it to scripts/check-release-artifacts.sh" ;;
    esac
}

usable=""
for t in $targets; do
    a=$(archive_of "$t")
    [ -f "$dir/$a" ] || continue
    mkdir -p "$work/$t"
    case $a in
        *.zip) listing=$(unzip -Z1 "$dir/$a" 2> /dev/null) ;;
        *) listing=$(tar -tzf "$dir/$a" 2> /dev/null) ;;
    esac
    if [ -z "$listing" ]; then
        fail "$a can be read" "the archive is empty or damaged. Rebuild from the tag."
        continue
    fi
    # Absolute paths and '..' parts would write outside the folder on extraction.
    if printf '%s\n' "$listing" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
        fail "$a holds only safe paths" "the archive has an absolute path or a '..' part. Do not extract or ship it."
        continue
    fi
    binname=rdy
    case $t in *-windows-*) binname=rdy.exe ;; esac
    missing=""
    for f in "$binname" LICENSE README.md CHANGELOG.md; do
        if ! printf '%s\n' "$listing" | grep -Fxq "rdy-$t/$f"; then
            missing="$missing $f"
        fi
    done
    if [ -n "$missing" ]; then
        fail "$a holds its files" "missing:$missing. Check the archive contents in 06 Appendix C."
        continue
    fi
    case $a in
        *.zip) unzip -q -o "$dir/$a" -d "$work/$t" ;;
        *) tar -xzf "$dir/$a" -C "$work/$t" ;;
    esac
    if [ ! -f "$(bin_of "$t")" ]; then
        fail "$a holds its files" "the binary is not a regular file."
        continue
    fi
    pass "$a holds only safe paths and its files"
    check_format "$t"
    usable="$usable $t"
done

# ---- 4. Static-pie on both Linux binaries --------------------------------------------------
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    case $usable in
        *" $t"*)
            if out=$("$here/check-static.sh" "$(bin_of "$t")" 2>&1); then
                pass "$t binary is a hardened static-pie"
            else
                printf '%s\n' "$out" | sed 's/^/  | /'
                fail "$t binary is a hardened static-pie" "see the lines above. If the linker was overridden (cargo-zigbuild, CARGO_TARGET_*_LINKER), scripts/musl-pie-linker.sh did not run. ADR 0006, decision 2."
            fi
            ;;
        *) fail "$t binary is a hardened static-pie" "there is no usable binary to check." ;;
    esac
done

# ---- 5. No VCRUNTIME import on Windows -----------------------------------------------------
t=x86_64-pc-windows-msvc
case $usable in
    *" $t"*)
        exe=$(bin_of "$t")
        dlls=$(objdump -p "$exe" 2> /dev/null | sed -n 's/^[[:space:]]*DLL Name:[[:space:]]*//p')
        if [ -z "$dlls" ]; then
            fail "rdy.exe imports no VCRUNTIME DLL" "objdump found no import table in $exe, so nothing was proven. Check that it is a PE file."
        elif printf '%s\n' "$dlls" | grep -Eqi '^vcruntime'; then
            fail "rdy.exe imports no VCRUNTIME DLL" "the C runtime is not linked in. Check msvc-crt-static in dist-workspace.toml and do not set RUSTFLAGS in the workflow: it drops +crt-static."
        else
            pass "rdy.exe imports no VCRUNTIME DLL ($(printf '%s\n' "$dlls" | tr 'A-Z\n' 'a-z ' | sed 's/ $//'))"
        fi
        ;;
    *) fail "rdy.exe imports no VCRUNTIME DLL" "there is no usable rdy.exe to check." ;;
esac

# ---- 6. cargo audit bin --------------------------------------------------------------------
if [ "$skip_audit" -eq 1 ]; then
    echo "WARN cargo audit bin SKIPPED (--skip-audit). Never use this flag on a real release."
else
    first=1
    for t in $targets; do
        case $usable in
            *" $t"*) ;;
            *)
                fail "cargo audit bin lists dependencies of the $t binary" "there is no usable binary to audit."
                continue
                ;;
        esac
        b=$(bin_of "$t")
        # The first run updates the advisory database. The others reuse it.
        if [ "$first" -eq 1 ]; then
            out=$(cargo audit --json bin "$b" 2> "$work/audit.err")
        else
            out=$(cargo audit --json --no-fetch bin "$b" 2> "$work/audit.err")
        fi
        code=$?
        first=0
        count=$(printf '%s\n' "$out" | jq -r '.lockfile."dependency-count" // 0' 2> /dev/null || echo 0)
        found=$(printf '%s\n' "$out" | jq -r '.vulnerabilities.found // false' 2> /dev/null || echo false)
        if [ -z "$count" ] || [ "$count" = "0" ]; then
            fail "cargo audit bin lists dependencies of the $t binary" "no dependency data in the binary (exit $code). Check 'cargo-auditable = true' in dist-workspace.toml and that the build used it. $(head -c 300 "$work/audit.err")"
        elif [ "$found" = "true" ]; then
            printf '%s\n' "$out" | jq -r '.vulnerabilities.list[] | "  | \(.advisory.id) \(.package.name) \(.package.version)"' 2> /dev/null
            fail "cargo audit bin finds no vulnerability in the $t binary" "update the crate named above, or write an ignore with a ticket and an expiry in deny.toml. Do not ship a known vulnerability."
        elif [ "$code" -ne 0 ]; then
            fail "cargo audit bin runs on the $t binary" "cargo audit exited $code. $(head -c 300 "$work/audit.err")"
        else
            pass "cargo audit bin lists $count dependencies in the $t binary"
        fi
    done
fi

# ---- 7. SBOM -------------------------------------------------------------------------------
# dist runs `cargo cyclonedx`, which writes XML. A JSON file is accepted too.
sbom_seen=0
for f in "$dir"/*.cdx.json; do
    [ -f "$f" ] || continue
    sbom_seen=1
    if jq -e '.bomFormat == "CycloneDX" and ((.components // []) | length) > 0' "$f" > /dev/null 2>&1 ||
        jq -e '.bomFormat == "CycloneDX" and ((.metadata.component.components // []) | length) > 0' "$f" > /dev/null 2>&1; then
        pass "$(basename "$f") is CycloneDX JSON with components"
    else
        fail "$(basename "$f") is CycloneDX JSON with components" "the SBOM is not valid CycloneDX or lists no components. Check the cargo-cyclonedx step."
    fi
done
for f in "$dir"/*.cdx.xml; do
    [ -f "$f" ] || continue
    sbom_seen=1
    # -I: isolated mode. The file name is data, never code.
    if python3 -I -c '
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
ns = root.tag.partition("}")[0].lstrip("{")
ok = root.tag.endswith("}bom") and ns.startswith("http://cyclonedx.org/schema/bom/")
n = sum(1 for e in root.iter() if e.tag.endswith("}component"))
sys.exit(0 if ok and n > 0 else 1)
' "$f" 2> /dev/null; then
        pass "$(basename "$f") is CycloneDX XML with components"
    else
        fail "$(basename "$f") is CycloneDX XML with components" "the SBOM is not well-formed CycloneDX or lists no components. Check the cargo-cyclonedx step."
    fi
done
if [ "$sbom_seen" -eq 0 ]; then
    fail "an SBOM exists" "dist should write rdy.cdx.xml. Check 'cargo-cyclonedx = true' in dist-workspace.toml and the cargo-cyclonedx step of build-global-artifacts."
fi

# ---- 8. No schema-tooling feature in the release build -------------------------------------
# `cargo tree --package rdy` resolves features for rdy alone, so it passes even when dist builds the
# whole workspace. The setting that prevents that is precise-builds, so require it too.
dist_config=${RDY_DIST_CONFIG:-$here/../dist-workspace.toml}
if grep -Eq '^precise-builds = true$' "$dist_config" 2> /dev/null; then
    pass "dist builds one package at a time (precise-builds = true)"
else
    fail "dist builds one package at a time (precise-builds = true)" "$dist_config must have the line 'precise-builds = true'. Without it dist builds the whole workspace and feature unification can put xtask's features (preserve_order) into rdy."
fi
# The features that `cargo build --package rdy` would turn on, for each release target. cargo-dist
# builds one package at a time (precise-builds), so this must match what was shipped.
for t in $targets; do
    if tree=$(cd "$here/.." && cargo tree --locked --package rdy --edges features --target "$t" 2> "$work/tree.err"); then
        if printf '%s\n' "$tree" | grep -q 'preserve_order'; then
            fail "no preserve_order in the $t build" "the schema feature of rdy-spec leaked into the rdy build. Keep 'precise-builds = true' in dist-workspace.toml and make sure only xtask enables the feature."
        else
            pass "no preserve_order in the $t build"
        fi
    else
        fail "cargo tree runs for $t" "cargo tree failed: $(head -c 300 "$work/tree.err"). Run this script from a full checkout with the pinned toolchain."
    fi
done

if [ "$bad" -gt 0 ]; then
    printf 'error: the release artifacts in %s are not ready to ship (%s check(s) failed)\n' "$dir" "$bad" >&2
    exit 1
fi
echo "release artifacts ok: $dir"
