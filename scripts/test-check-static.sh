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

# Fixtures built with musl-gcc, one per hardening failure. musl-gcc is installed on the Linux CI
# legs with musl-tools. Without it, or if a good static-pie does not build, these are skipped.
printf 'int main(void) { return 0; }\n' > "$tmp/hello.c"
if command -v musl-gcc > /dev/null 2>&1 &&
    musl-gcc -static-pie -Wl,-z,relro,-z,now -o "$tmp/good" "$tmp/hello.c" 2> /dev/null; then
    check "a hardened static-pie passes" 0 "static-pie ok" "$tmp/good"
    if musl-gcc -static -no-pie -o "$tmp/nopie" "$tmp/hello.c" 2> /dev/null; then
        check "a non-PIE static binary fails the PIE check" 1 "FAIL position independent" "$tmp/nopie"
    else
        echo "SKIP non-PIE fixture: musl-gcc -static -no-pie did not build"
    fi
    if musl-gcc -static-pie -Wl,-z,relro,-z,now -Wl,-z,execstack -o "$tmp/execstack" "$tmp/hello.c" 2> /dev/null; then
        check "an executable stack fails the stack check" 1 "FAIL non-executable stack" "$tmp/execstack"
    else
        echo "SKIP execstack fixture: musl-gcc -z execstack did not build"
    fi
    if musl-gcc -static-pie -Wl,-z,norelro -o "$tmp/norelro" "$tmp/hello.c" 2> /dev/null; then
        check "a binary without RELRO fails the RELRO check" 1 "FAIL full RELRO" "$tmp/norelro"
    else
        echo "SKIP norelro fixture: musl-gcc -z norelro did not build"
    fi
    # A shared library is type DYN but not a PIE executable. DYN alone must not pass.
    if musl-gcc -shared -fPIC -Wl,-z,relro,-z,now -o "$tmp/lib.so" "$tmp/hello.c" 2> /dev/null; then
        check "a shared library fails the PIE check" 1 "FAIL position independent" "$tmp/lib.so"
    else
        echo "SKIP shared library fixture: musl-gcc -shared did not build"
    fi
    # A data word in .text with an absolute relocation forces a text relocation at load time.
    printf 'int g;\n__asm__(".text\\n.quad g\\n");\nint main(void) { return g; }\n' > "$tmp/textrel.c"
    if musl-gcc -static-pie -Wl,-z,relro,-z,now -Wl,-z,notext -o "$tmp/textrel" "$tmp/textrel.c" 2> /dev/null &&
        readelf -dW "$tmp/textrel" | grep -q TEXTREL; then
        check "a text relocation fails the TEXTREL check" 1 "FAIL no text relocations" "$tmp/textrel"
    else
        echo "SKIP TEXTREL fixture: this architecture did not produce a text relocation"
    fi
else
    echo "SKIP musl-gcc fixtures: musl-gcc is missing or cannot build a static-pie"
fi

printf '#!/bin/sh\n' > "$tmp/not-elf"
check "a script is a usage error" 64 "could not read" "$tmp/not-elf"
check "a missing file is a usage error" 64 "is not a file" "$tmp/missing"
check "no argument is a usage error" 64 "usage:"
check "two arguments are a usage error" 64 "usage:" a b

exit "$fail"
