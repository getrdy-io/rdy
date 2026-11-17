#!/bin/sh
# test-install-blocks.sh: tests for scripts/install-blocks.sh (M1-133, ADR 0047). No network.
#
# gh and curl are stubs on PATH. The stub curl writes a small fake install.sh that puts a fake rdy in
# $HOME/.local/bin, so the real install page runs end to end. The stubs record the URL they were asked for.
# Exit 0 when every case passes, 1 when one fails.

set -eu
LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
runner="$root/scripts/install-blocks.sh"
page="$root/docs/src/content/docs/install.md"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stubs="$work/stubs"
mkdir -p "$stubs" "$work/home"

fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }

# gh stub: GH_STUB picks the answer. none: no release. tag: one release. fail: the API call fails.
cat > "$stubs/gh" <<'EOF'
#!/bin/sh
case ${GH_STUB:-none} in
    none) exit 0 ;;
    tag) echo 'v9.9.9' ;;
    fail) echo 'HTTP 500' >&2; exit 1 ;;
esac
EOF

# curl stub: records its arguments. It prints a fake install.sh that puts a fake rdy in $HOME.
cat > "$stubs/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$STUB_LOG"
cat <<'SCRIPT'
mkdir -p "$HOME/.local/bin"
printf '#!/bin/sh\necho "rdy 9.9.9-stub"\n' > "$HOME/.local/bin/rdy"
chmod 755 "$HOME/.local/bin/rdy"
echo "stub install.sh ran"
SCRIPT
EOF
chmod 755 "$stubs/gh" "$stubs/curl"

export STUB_LOG="$work/curl.log"
export HOME="$work/home"
export PATH="$stubs:$PATH"

# 1. No release: resolve prints nothing and says it skipped. Exit 0.
out=$(GH_STUB=none sh "$runner" --resolve-tag 2> "$work/err1") && rc=0 || rc=$?
if [ "$rc" = 0 ] && [ -z "$out" ] && grep -q '^SKIPPED: .* no published release yet' "$work/err1"; then
    pass "no release skips with a message"
else
    fail "no release skips with a message (rc=$rc out=$out)"
fi

# 2. One release: resolve prints its tag.
out=$(GH_STUB=tag sh "$runner" --resolve-tag 2> /dev/null) && rc=0 || rc=$?
if [ "$rc" = 0 ] && [ "$out" = 'tag=v9.9.9' ]; then
    pass "resolve prints the newest tag"
else
    fail "resolve prints the newest tag (rc=$rc out=$out)"
fi

# 3. A failed API call is a failure, not a skip.
rc=0
GH_STUB=fail sh "$runner" --resolve-tag > /dev/null 2> "$work/err3" || rc=$?
if [ "$rc" = 1 ] && grep -q 'cannot list the releases' "$work/err3"; then
    pass "a failed release lookup exits 1"
else
    fail "a failed release lookup exits 1 (rc=$rc)"
fi

# 4. Run with no release: skip, exit 0, nothing fetched.
rm -f "$STUB_LOG"
rc=0
GH_STUB=none sh "$runner" > /dev/null 2> "$work/err4" || rc=$?
if [ "$rc" = 0 ] && [ ! -e "$STUB_LOG" ] && grep -q SKIPPED "$work/err4"; then
    pass "run with no release skips and fetches nothing"
else
    fail "run with no release skips and fetches nothing (rc=$rc)"
fi

# 5. The real install page, against a tag: the install-only blocks run, the URL is built here, and the
# fake rdy answers `rdy version`.
rm -f "$STUB_LOG"
rc=0
sh "$runner" --tag v9.9.9 --page "$page" > "$work/out5" 2> "$work/err5" || rc=$?
want_url='https://github.com/getrdy-io/rdy/releases/download/v9.9.9/install.sh'
if [ "$rc" = 0 ] && grep -qx "rdy 9.9.9-stub" "$work/out5" && grep -q "PASS for v9.9.9" "$work/err5" \
    && grep -q -- "$want_url" "$STUB_LOG"; then
    pass "the real install page runs its install-only blocks against the tag"
else
    fail "the real install page runs its install-only blocks against the tag (rc=$rc)"
fi

# 6. A page whose only fence is not install-only is refused. Nothing runs.
cat > "$work/no-blocks.md" <<'EOF'
# Page

```sh
exit 9
```
EOF
rc=0
sh "$runner" --tag v9.9.9 --page "$work/no-blocks.md" > /dev/null 2> "$work/err6" || rc=$?
if [ "$rc" = 1 ] && grep -q 'has no install-only block' "$work/err6"; then
    pass "a page with no install-only block fails"
else
    fail "a page with no install-only block fails (rc=$rc)"
fi

# 7. The fence that is not install-only is never run: the install-only block passes and the run passes.
cat > "$work/mixed.md" <<'EOF'
```sh install-only
true
```

```sh
exit 9
```
EOF
rc=0
sh "$runner" --tag v9.9.9 --page "$work/mixed.md" > /dev/null 2> "$work/err7" || rc=$?
if [ "$rc" = 0 ] && grep -q 'PASS for v9.9.9' "$work/err7"; then
    pass "a fence that is not install-only is never run"
else
    fail "a fence that is not install-only is never run (rc=$rc)"
fi

# 7b. A failing install-only block fails the run.
cat > "$work/failing.md" <<'EOF'
```sh install-only
false
```
EOF
rc=0
sh "$runner" --tag v9.9.9 --page "$work/failing.md" > /dev/null 2> "$work/err7b" || rc=$?
if [ "$rc" = 1 ] && grep -q 'FAIL for v9.9.9' "$work/err7b"; then
    pass "a failing install-only block fails the run"
else
    fail "a failing install-only block fails the run (rc=$rc)"
fi

# 8. A tag that could change the URL is refused before anything runs.
rc=0
sh "$runner" --tag 'v1.0.0/../x' > /dev/null 2> "$work/err8" || rc=$?
if [ "$rc" = 1 ] && grep -q 'is not a release tag' "$work/err8"; then
    pass "a tag with path characters is refused"
else
    fail "a tag with path characters is refused (rc=$rc)"
fi

# 8b. A tag with a newline or another control character is refused, even when its first line looks right.
# The newline case matters: grep reads one line at a time, so only the explicit check catches it.
for bad_tag in "$(printf 'v9.9.9\nv1.0.0')" "$(printf 'v9.9.9\t')" "$(printf 'v9.9.9\033')"; do
    rc=0
    sh "$runner" --tag "$bad_tag" > /dev/null 2> "$work/err8b" || rc=$?
    if [ "$rc" = 1 ] && grep -q 'is not a release tag' "$work/err8b"; then
        pass "a tag with a control character is refused"
    else
        fail "a tag with a control character is refused (rc=$rc)"
    fi
done

# 9. Usage errors exit 64.
rc=0
sh "$runner" --bogus > /dev/null 2>&1 || rc=$?
if [ "$rc" = 64 ]; then
    pass "a bad flag exits 64"
else
    fail "a bad flag exits 64 (rc=$rc)"
fi

if [ "$fails" -ne 0 ]; then
    echo "install-blocks tests: $fails failed"
    exit 1
fi
echo "install-blocks tests: all passed"
