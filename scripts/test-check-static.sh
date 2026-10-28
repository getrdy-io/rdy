#!/bin/sh
# test-check-static.sh: tests for scripts/check-static.sh. Exit 0 when all pass.
#
# The pass case is the real musl binary, which CI checks right after building it. These tests
# cover the failure paths: a dynamic binary must fail, and bad input must exit 64.
# Linux only: it needs an ELF dynamic binary and readelf.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/check-static.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

# check <name> <expected exit> <expected text in output> <args...>
check() {
    name=$1
    want=$2
    text=$3
    shift 3
    out=$("$script" "$@" 2>&1)
    code=$?
    if [ "$code" -ne "$want" ]; then
        bad "$name (exit $code, want $want)"
        echo "$out"
    elif ! printf '%s\n' "$out" | grep -q "$text"; then
        bad "$name (output lacks '$text')"
        echo "$out"
    else
        ok "$name"
    fi
}

# A dynamic binary: the shell that runs this script is one on Debian and Ubuntu.
dynamic=$(command -v sh)
if readelf -lW "$dynamic" 2> /dev/null | grep -q INTERP; then
    check "dynamic binary fails the INTERP check" 1 "FAIL no INTERP header" "$dynamic"
    check "dynamic binary names the missing fix" 1 "fix:" "$dynamic"
else
    echo "SKIP dynamic binary checks: $dynamic is not dynamically linked here"
fi

printf '#!/bin/sh\n' > "$tmp/not-elf"
check "a script is a usage error" 64 "could not read" "$tmp/not-elf"
check "a missing file is a usage error" 64 "is not a file" "$tmp/missing"
check "no argument is a usage error" 64 "usage:"
check "two arguments are a usage error" 64 "usage:" a b

exit "$fail"
