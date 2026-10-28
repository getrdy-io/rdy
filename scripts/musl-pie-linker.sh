#!/bin/sh
# musl-pie-linker.sh: link aarch64-unknown-linux-musl binaries as static-pie (ADR 0006, decision 2).
#
# Why this exists. rustc marks x86_64-unknown-linux-musl as able to build static-pie, so it links
# with -static-pie and musl's rcrt1.o. It does not mark aarch64-unknown-linux-musl, so there it links
# with -static -no-pie and musl's crt1.o: no ASLR, and no dynamic section for full RELRO. Rust 1.99.1
# has no stable switch for this. This wrapper rewrites the link line rustc built:
#   - crt1.o becomes rcrt1.o from the same directory (rcrt1.o relocates the binary at start);
#   - -static and -no-pie are dropped and -static-pie is added.
# rustc already passes -Wl,-z,relro,-z,now and compiles position-independent code.
#
# It is the linker for aarch64-unknown-linux-musl only (.cargo/config.toml). The real linker is
# `cc`, or $RDY_REAL_LINKER for a cross build. It is not musl-gcc: that wrapper does not handle
# static-pie. Delete this file when rustc can link aarch64 musl as static-pie itself. Until then
# scripts/check-static.sh fails CI if a binary comes out non-PIE.

set -eu

linker=${RDY_REAL_LINKER:-cc}

# A link line without rustc's self-contained crt1.o is not an executable link. Pass it through.
has_crt=0
for arg in "$@"; do
    case $arg in
        @*)
            echo "error: musl-pie-linker.sh cannot rewrite a linker response file ($arg)" >&2
            echo "fix: shorten the link line, or drop the aarch64-unknown-linux-musl linker in .cargo/config.toml and amend ADR 0006" >&2
            exit 1
            ;;
        */self-contained/crt1.o) has_crt=1 ;;
        *) ;;
    esac
done
if [ "$has_crt" -eq 0 ]; then
    exec "$linker" "$@"
fi

# Rebuild the argument list: one pass, each argument kept, changed or dropped.
n=$#
i=0
while [ "$i" -lt "$n" ]; do
    arg=$1
    shift
    i=$((i + 1))
    case $arg in
        */self-contained/crt1.o) set -- "$@" "${arg%crt1.o}rcrt1.o" ;;
        -static | -no-pie) ;;
        *) set -- "$@" "$arg" ;;
    esac
done
exec "$linker" "$@" -static-pie
