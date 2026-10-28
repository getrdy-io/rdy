#!/bin/sh
# test-musl-pie-linker.sh: tests for scripts/musl-pie-linker.sh with a stub linker. Exit 0 when all pass.
#
# The stub prints one argument per line, so the tests read exactly what the real linker would get.
# The end-to-end proof is the real aarch64 binary, which CI checks with scripts/check-static.sh.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/musl-pie-linker.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

cat > "$tmp/stub-linker" << 'EOF'
#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done
EOF
chmod +x "$tmp/stub-linker"

sc="$tmp/lib/self-contained"
mkdir -p "$sc"
for f in crt1.o rcrt1.o crti.o crtbegin.o crtbeginS.o crtend.o crtendS.o crtn.o; do
    : > "$sc/$f"
done

# has <name> <output> <line>: the output has the exact line.
has() {
    if printf '%s\n' "$2" | grep -qxF -- "$3"; then ok "$1"; else
        bad "$1 (missing: $3)"
        printf '%s\n' "$2"
    fi
}
# lacks <name> <output> <line>: the output does not have the exact line.
lacks() {
    if printf '%s\n' "$2" | grep -qxF -- "$3"; then
        bad "$1 (unexpected: $3)"
        printf '%s\n' "$2"
    else ok "$1"; fi
}

out=$(RDY_REAL_LINKER="$tmp/stub-linker" "$script" -m64 "$sc/crt1.o" "$sc/crti.o" "$sc/crtbegin.o" \
    -Wl,-Bstatic -lfoo "$sc/crtend.o" "$sc/crtn.o" -nostartfiles -static -no-pie -Wl,-z,relro,-z,now -o out)
has "crt1.o becomes rcrt1.o" "$out" "$sc/rcrt1.o"
lacks "crt1.o is gone" "$out" "$sc/crt1.o"
has "crtbegin.o becomes crtbeginS.o" "$out" "$sc/crtbeginS.o"
lacks "crtbegin.o is gone" "$out" "$sc/crtbegin.o"
has "crtend.o becomes crtendS.o" "$out" "$sc/crtendS.o"
lacks "crtend.o is gone" "$out" "$sc/crtend.o"
has "crti.o is kept" "$out" "$sc/crti.o"
has "-static-pie is added" "$out" "-static-pie"
lacks "-static is dropped" "$out" "-static"
lacks "-no-pie is dropped" "$out" "-no-pie"
has "other arguments are kept" "$out" "-Wl,-z,relro,-z,now"
has "arguments with the value after them are kept" "$out" "out"

# A missing S variant keeps the original object.
rm "$sc/crtbeginS.o"
out=$(RDY_REAL_LINKER="$tmp/stub-linker" "$script" "$sc/crt1.o" "$sc/crtbegin.o" -static -no-pie)
has "crtbegin.o stays when crtbeginS.o is missing" "$out" "$sc/crtbegin.o"

# A link line without crt1.o is passed through unchanged.
out=$(RDY_REAL_LINKER="$tmp/stub-linker" "$script" -static -no-pie -o lib.so)
has "a link without crt1.o keeps -static" "$out" "-static"
lacks "a link without crt1.o gets no -static-pie" "$out" "-static-pie"

# A response file cannot be rewritten: the wrapper stops with a fix line.
if err=$(RDY_REAL_LINKER="$tmp/stub-linker" "$script" "@$tmp/args" 2>&1); then
    bad "a response file is refused"
else
    if printf '%s\n' "$err" | grep -q "^fix:"; then ok "a response file is refused"; else bad "a response file is refused without a fix line"; fi
fi

exit "$fail"
