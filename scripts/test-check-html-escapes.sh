#!/bin/sh
# test-check-html-escapes.sh: tests for scripts/check-html-escapes.sh (M1-078). Exit 0 when all pass.
#
# Each case builds a small stand-in repository in a temporary folder, runs the checker on it and looks at
# the exit code and the output. The last case runs it on the real repository.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/check-html-escapes.sh"
real_root=$(dirname "$here")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
  printf 'FAIL %s\n' "$1"
  fail=1
}

ALLOWED='impl askama::filters::HtmlSafe for HtmlSafeJson {}'

# fresh: a clean stand-in repository in $tmp/repo with the one allowed marker.
fresh() {
  rm -rf "$tmp/repo"
  mkdir -p "$tmp/repo/crates/rdy-engine/src/report" "$tmp/repo/crates/rdy-engine/templates" "$tmp/repo/xtask/src"
  cat >"$tmp/repo/Cargo.toml" <<'EOF'
[workspace.dependencies]
askama = { version = "=0.16.1", default-features = false }
EOF
  cat >"$tmp/repo/crates/rdy-engine/Cargo.toml" <<'EOF'
[dependencies]
askama = { workspace = true, features = ["derive", "std"], optional = true }
EOF
  printf '%s\n' "$ALLOWED" >"$tmp/repo/crates/rdy-engine/src/report/json.rs"
  printf '%s\n' '#[derive(Template)]' '#[template(path = "report.html")]' 'struct View;' \
    >"$tmp/repo/crates/rdy-engine/src/report/view.rs"
  printf '%s\n' '<p>{{ name }}</p>' '<script type="application/json">{{ json }}</script>' \
    >"$tmp/repo/crates/rdy-engine/templates/report.html"
}

# expect NAME WANT_EXIT WANT_TEXT: run the checker on $tmp/repo.
expect() {
  name=$1
  want=$2
  text=$3
  out=$(sh "$script" "$tmp/repo" 2>&1)
  code=$?
  if [ "$code" -ne "$want" ]; then
    bad "$name (exit $code, want $want)"
    printf '%s\n' "$out"
  elif ! printf '%s\n' "$out" | grep -Fq -- "$text"; then
    bad "$name (output lacks '$text')"
    printf '%s\n' "$out"
  else
    ok "$name"
  fi
}

fresh
expect "a clean repository passes, with the one allowed marker" 0 "ok: no askama escape bypass"

# Templates.
for filter in '{{ name|safe }}' '{{ name | safe }}' '{{ name|unsafe }}' '{{ name|e("none") }}' \
  '{{ name|escape("none") }}' '{{ name | e ("none") }}' '{% filter safe %}x{% endfilter %}' \
  '{%- filter escape("none") -%}x{% endfilter %}' '{# #}{{ name|safe }}'; do
  fresh
  printf '%s\n' "$filter" >>"$tmp/repo/crates/rdy-engine/templates/report.html"
  expect "template: $filter" 1 "FAIL"
done
fresh
printf '%s\n' '{{ name|safely }} {{ name|escape_all }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: other filters that start with the same letters pass" 0 "ok:"
fresh
printf '%s\n' 'escape = "none"' >"$tmp/repo/crates/rdy-engine/templates/other.html"
expect "template: escape = none" 1 "an escape setting"
fresh
printf '%s\n' '{{ name|safe }}' >"$tmp/repo/crates/rdy-engine/templates/report.css"
expect "template: any file in templates/ is judged, not only .html" 1 "report.css"

# Rust.
for code in 'use askama::filters::Safe;' 'use askama::filters::{Escaper, Safe};' 'use askama::filters::Unsafe;' \
  'use askama::filters::MaybeSafe;' 'fn f() -> MaybeSafe<String> { todo!() }' 'impl HtmlSafe for Other {}' \
  'impl askama::filters::HtmlSafe for Other {}' 'impl askama::filters::HtmlSafe for HtmlSafeJson {} // twice' \
  'use askama::filters::HtmlSafeOutput;' '#[template(path = "a.html", escape = "none")]' \
  'let _ = askama::filters::Safe("x");'; do
  fresh
  printf '%s\n' "$code" >>"$tmp/repo/xtask/src/main.rs"
  expect "rust: $code" 1 "FAIL"
done
fresh
printf '%s\n' "$ALLOWED" >>"$tmp/repo/xtask/src/main.rs"
expect "rust: the allowed marker in any other file fails" 1 "xtask/src/main.rs"
fresh
printf '%s\n' "$ALLOWED" >>"$tmp/repo/crates/rdy-engine/src/report/json.rs"
expect "rust: the allowed marker twice in its own file fails" 1 "report/json.rs"
fresh
printf '%s\n' '// the safe filter, MaybeSafe and impl HtmlSafe are banned' '/// filters::Safe too' \
  'struct HtmlSafeJsonLike; // HtmlSafeJson' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: a comment that names a bypass passes" 0 "ok:"
fresh
printf '%s\n' '#[template(' '    path = "report.html",' '    ext = "txt"' ')]' 'struct A;' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: a template attribute with ext fails, over several lines" 1 "must be path"
fresh
printf '%s\n' '#[template(source = "{{ x }}", ext = "html")]' 'struct A;' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: an inline template fails" 1 "must be path"
fresh
printf '%s\n' '#[template(path = "report.txt")]' 'struct A;' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: a template that is not .html fails" 1 "must be path"

# Cargo.toml.
for feature in '"serde_json"' '"urlencode"' '"full"' '"default"' '"config"'; do
  fresh
  printf 'askama = { workspace = true, features = ["derive", %s] }\n' "$feature" >"$tmp/repo/xtask/Cargo.toml"
  expect "toml: askama feature $feature" 1 "askama feature"
done
fresh
printf '%s\n' 'askama = { workspace = true, features = [' '  "derive",' '  "urlencode",' '] }' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: a feature on a later line" 1 "askama feature"
fresh
printf '%s\n' '[dependencies.askama]' 'version = "0.16"' 'features = ["serde_json"]' '[dev-dependencies]' 'serde_json = "1"' \
  >"$tmp/repo/xtask/Cargo.toml"
expect "toml: askama as a table" 1 "askama feature"
fresh
printf '%s\n' '[dependencies]' 'serde_json = { workspace = true, features = ["std"] }' '# askama = ["urlencode"]' \
  'other = { features = ["urlencode"] }' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: the same feature names on other crates and in comments pass" 0 "ok:"
fresh
printf '%s\n' '' >"$tmp/repo/crates/rdy-engine/askama.toml"
expect "files: askama.toml fails" 1 "askama.toml"

# Usage.
out=$(sh "$script" "$tmp/does-not-exist" 2>&1)
code=$?
if [ "$code" -eq 64 ] && printf '%s\n' "$out" | grep -q "usage:"; then ok "usage: a missing root exits 64"; else bad "usage: a missing root (exit $code)"; fi
out=$(sh "$script" a b 2>&1)
code=$?
if [ "$code" -eq 64 ]; then ok "usage: two arguments exit 64"; else bad "usage: two arguments (exit $code)"; fi

# The real repository.
out=$(sh "$script" "$real_root" 2>&1)
code=$?
if [ "$code" -eq 0 ]; then ok "the real repository passes"; else
  bad "the real repository (exit $code)"
  printf '%s\n' "$out"
fi
# And the real marker is there, so the allowed line is exercised and not just absent.
if grep -Fxq -- "$ALLOWED" "$real_root/crates/rdy-engine/src/report/json.rs"; then
  ok "the real marker is the allowed line"
else
  bad "crates/rdy-engine/src/report/json.rs lacks the allowed marker line"
fi

exit "$fail"
