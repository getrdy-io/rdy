#!/bin/sh
# check-static.sh: prove a Linux binary is static-pie and hardened (ADR 0006, decision 2).
#
# Usage: scripts/check-static.sh <path-to-rdy>
# Checks, with readelf only:
#   1. No INTERP program header (no dynamic loader is needed).
#   2. No NEEDED entry in the dynamic section (no shared library is needed).
#   3. ELF type DYN, so the binary is position independent and gets ASLR.
#   4. A GNU_RELRO segment and immediate binding (BIND_NOW or the NOW flag): full RELRO.
#   5. A GNU_STACK segment that is not executable.
# Exit:  0 all checks pass, 1 at least one fails, 64 usage error or no readelf.
#
# Since Rust 1.59 the musl targets build static-pie, so `file` and `ldd` output varies. This
# script does not read them. Run it on both Linux binaries (x86_64 and aarch64).

set -u

if [ "$#" -ne 1 ]; then
    echo "usage: scripts/check-static.sh <path-to-binary>" >&2
    exit 64
fi
bin=$1

if [ ! -f "$bin" ]; then
    echo "error: $bin is not a file" >&2
    echo "fix: build it first, for example 'cargo build --locked --target x86_64-unknown-linux-musl -p rdy'" >&2
    exit 64
fi
if ! command -v readelf > /dev/null 2>&1; then
    echo "error: readelf is not installed" >&2
    echo "fix: install binutils (on Debian or Ubuntu, 'apt-get install binutils')" >&2
    exit 64
fi

if ! header=$(readelf -hW "$bin" 2>&1); then
    echo "error: readelf could not read $bin: $header" >&2
    echo "fix: pass a Linux ELF binary" >&2
    exit 64
fi
programs=$(readelf -lW "$bin" 2>&1)
dynamic=$(readelf -dW "$bin" 2>&1)

bad=0
fail() {
    bad=$((bad + 1))
    printf 'FAIL %s\n' "$1"
    printf '  fix: %s\n' "$2"
}
pass() { printf 'PASS %s\n' "$1"; }

if printf '%s\n' "$programs" | grep -Eq '^[[:space:]]*INTERP[[:space:]]'; then
    fail "no INTERP header" "the binary asks for a dynamic loader. Build a musl target with static linking (ADR 0006) and do not set the linker to musl-gcc."
else
    pass "no INTERP header"
fi

if printf '%s\n' "$dynamic" | grep -q '(NEEDED)'; then
    libs=$(printf '%s\n' "$dynamic" | grep '(NEEDED)' | sed 's/.*\[\(.*\)\]/\1/' | tr '\n' ' ')
    fail "no NEEDED entry" "the binary needs shared libraries: $libs. Remove the dependency that links them."
else
    pass "no NEEDED entry"
fi

if printf '%s\n' "$header" | grep -Eq '^[[:space:]]*Type:[[:space:]]+DYN'; then
    pass "position independent (static-pie)"
else
    fail "position independent (static-pie)" "the binary is not PIE, so it has no ASLR. Check that the musl target is not built with -C relocation-model=static."
fi

if printf '%s\n' "$programs" | grep -Eq '^[[:space:]]*GNU_RELRO[[:space:]]' &&
    printf '%s\n' "$dynamic" | grep -Eq '\(BIND_NOW\)|\(FLAGS(_1)?\).*NOW'; then
    pass "full RELRO"
else
    fail "full RELRO" "the binary lacks GNU_RELRO or immediate binding. Check linker flags for -z relro -z now."
fi

# The flags of GNU_STACK sit between MemSiz and Align. "RW" is fine. Any E means executable.
stack=$(printf '%s\n' "$programs" | awk '$1 == "GNU_STACK" { for (i = 7; i < NF; i++) printf "%s", $i; print "" }')
case $stack in
    "") fail "non-executable stack" "there is no GNU_STACK header, so the kernel may default to an executable stack." ;;
    *E*) fail "non-executable stack" "GNU_STACK is marked executable ($stack). Check for assembly objects missing a .note.GNU-stack section." ;;
    *) pass "non-executable stack" ;;
esac

if [ "$bad" -gt 0 ]; then
    printf 'error: %s is not a hardened static-pie binary (%s check(s) failed)\n' "$bin" "$bad" >&2
    exit 1
fi
echo "static-pie ok: $bin"
