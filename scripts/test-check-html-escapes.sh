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

JSON_LINE='<script type="application/json" id="rdy-result" data-sha256="{{ json_sha256 }}">{{ json }}</script>'
ALLOWED='impl askama::filters::HtmlSafe for EmbeddedJson {}'
VIEW=crates/rdy-engine/src/report/html/view.rs

# fresh: a clean stand-in repository in $tmp/repo with the one allowed marker.
fresh() {
  rm -rf "$tmp/repo"
  mkdir -p "$tmp/repo/crates/rdy-engine/src/report/html" "$tmp/repo/crates/rdy-engine/templates" "$tmp/repo/xtask/src"
  cat >"$tmp/repo/Cargo.toml" <<'EOF'
[workspace.dependencies]
askama = { version = "=0.16.1", default-features = false }
EOF
  cat >"$tmp/repo/crates/rdy-engine/Cargo.toml" <<'EOF'
[dependencies]
askama = { workspace = true, features = ["derive", "std"], optional = true }
EOF
  printf '%s\n' '//! The page.' 'use askama::Template;' '/// A comment about filters::Safe and Unsafe.' "$ALLOWED" \
    '#[derive(Template)]' '#[template(path = "report.html")]' 'struct View;' \
    >"$tmp/repo/$VIEW"
  printf '%s\n' 'pub struct HtmlSafeJson(String);' >"$tmp/repo/crates/rdy-engine/src/report/json.rs"
  printf '%s\n' '<p>{{ name }}</p>' "$JSON_LINE" \
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
# A bypass split over lines, a path call and the json and urlencode filters.
fresh
printf '%s\n' '{{ name |' '   safe }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: |safe split over two lines" 1 "the safe filter"
fresh
printf '%s\n' '{{ name' '  | escape(' '"none") }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: |escape split over lines" 1 "escaper name"
fresh
printf '%s\n' '{{ askama::filters::Safe(name) }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a path call to askama::filters::Safe" 1 "a path inside a template"
fresh
printf '%s\n' '{% let x = crate::other(name) %}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: any path inside a tag" 1 "a path inside a template"
for filter in json json_pretty tojson urlencode urlencode_strict; do
  fresh
  printf '%s\n' "{{ name|$filter }}" >>"$tmp/repo/crates/rdy-engine/templates/report.html"
  expect "template: |$filter" 1 "json or urlencode filter"
done
fresh
printf '%s\n' '{{ "}" ~ askama::filters::Safe(name) }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a path call after a } in a string" 1 "a path inside a template"
fresh
printf '%s\n' '{% if "%" == x %}{{ crate::y }}{% endif %}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a path call after a % in a string" 1 "a path inside a template"
fresh
printf '%s\n' '<a href="{{ json }}">x</a>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: the embedded result in an attribute" 1 "exactly once"
fresh
printf '%s\n' "$JSON_LINE" >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: the embedded result twice, on the right line" 1 "exactly once"
fresh
printf '%s\n' '<p>{{ json|lower }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: the embedded result with a filter, on another line" 1 "exactly once"
fresh
printf '%s\n' '<script type="application/json">{{ json }}</script>' >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: the embedded result on a looser script line" 1 "exactly once"
fresh
printf '%s\n' '<p>{{ name }}</p>' >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: no embedded result at all" 1 "exactly once"
fresh
printf '%s\n' '<a href="{{json}}">x</a>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: {{json}} with no space, in an attribute" 1 "exactly once"
fresh
printf '%s\n' '<p>{{json|lower}}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: {{json|lower}} with no space" 1 "exactly once"
fresh
printf '%s\n' '<p>{{-json-}}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: {{-json-}} with trim marks" 1 "exactly once"
fresh
printf '%s\n' '{% let a = json %}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: json in a block tag" 1 "exactly once"
fresh
printf '%s\n' '<p>{{json_sha256}} {{ x.json_len }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: names that only start with json pass" 0 "ok:"
fresh
printf '%s\n' '{{ "}}" ~ askama::filters::Safe(name) }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: KNOWN LIMIT, a }} inside a string hides a path call (a known limit)" 0 "ok:"
fresh
printf '%s\n' '{{ json_sha256 }} {{ json.len() }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: json.len() counts as a second use" 1 "exactly once"
fresh
printf '%s\n' '<p>{{ json ~ json }}</p>' >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: {{ json ~ json }} counts 2 in one tag" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '{% let a = json %}{{ json }}' >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: {% let a = json %}{{ json }} counts 2, one per tag" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '<p>{{ json ~ json }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: the allowed line plus {{ json ~ json }} counts 3" 1 "found 3 use(s) of the word json"
fresh
printf '%s\n' '<p>{{ jsonjson }} {{ a_json }} {{ json_a ~ json }}</p>' >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: json inside a longer word does not count, a bare json does" 1 "found 1 use(s) of the word json"
fresh
printf '%s\n' '{% let (s, a) = ("%}", json) %}<p title="{{ a }}">' >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a %} inside a string does not end the tag, json after it counts 1" 1 "found 1 use(s) of the word json"
fresh
printf '%s\n' '<p>{{ "}}" ~ json }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a }} inside a string does not end the tag, so the allowed line plus this counts 2" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' "<p>{{ 'a}}' ~ json }}</p>" >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a }} inside single quotes does not end the tag either" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '<p>{{ "a\"}}" ~ json }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: an escaped quote does not end the string" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '<p>{{ "json" }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: the word json inside a string still counts, by design" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' "{# {{ ' #}{% let a = json %}{# ' }} #}<p title=\"{{ a }}\">" >"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a quote in a comment does not hide a json after it, counts 1" 1 "found 1 use(s) of the word json"
fresh
printf '%s\n' "{% raw %}{{ '{% endraw %}{% let a = json %}{% raw %}' }}{% endraw %}{{ a }}" >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a raw block that hides a json fails" 1 "raw block"
fresh
printf '%s\n' '{# {{ " #}<p title={{ json }}>{# " #}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a double quote in a comment does not hide a json, the allowed line plus this counts 2" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' "{{ stringify!('a) }}{% let a = json %}{{ stringify!('b) }}<p title=\"{{ a }}\">" >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: stringify! with lifetimes does not hide a json" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '{{ stringify!(r#"x"y"#) }}{% let a = json %}{{ stringify!(r#"x"y"#) }}<p title="{{ a }}">' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: stringify! with a raw string does not hide a json" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '{{ stringify!(/* " */) }}{% let a = json %}{{ stringify!(/* " */) }}<p title="{{ a }}">' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: stringify! with a block comment does not hide a json" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '{{ stringify!(r"\") }}{% let a = json %}{{ stringify!(r"\") }}<p title="{{ a }}">' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: stringify! with a raw string ending in a backslash does not hide a json" 1 "found 2 use(s) of the word json"
T="$tmp/repo/crates/rdy-engine/templates/report.html"
fresh
printf '%s\n' '{% macro m(a) %}{{ a }}{% endmacro %}' >>"$T"
expect "template: a macro tag fails" 1 "macro, import, extends and call"
fresh
printf '%s\n' '{% import "x.html" as x %}' >>"$T"
expect "template: an import tag fails" 1 "macro, import, extends and call"
fresh
printf '%s\n' '{%- extends "base.html" %}' >>"$T"
expect "template: an extends tag fails" 1 "macro, import, extends and call"
fresh
printf '%s\n' '{% call m() %}' >>"$T"
expect "template: a call tag fails" 1 "macro, import, extends and call"
fresh
printf '%s\n' '{% include "other.html" %}' >>"$T"
expect "template: an include of another file fails" 1 "an include other than"
fresh
printf '%s\n' '{%- include "report.css" %}' '{% include "report.css" %}' >>"$T"
expect "template: the stylesheet include passes" 0 "ok:"
fresh
printf '%s\n' '{% include "report.css" ~ x %}' >>"$T"
expect "template: the stylesheet include with an extra expression fails" 1 "an include other than"
fresh
printf '%s\n' '<p>x</p>' "    $JSON_LINE" >"$T"
expect "template: the allowed line indented passes" 0 "ok:"
fresh
printf '%s\n' "<p>x</p>" "x$JSON_LINE" >"$T"
expect "template: text before the allowed line on its line fails" 1 "exactly once"
fresh
printf '%s\n' "<p>x</p>" "$JSON_LINE x" >"$T"
expect "template: text after the allowed line on its line fails" 1 "exactly once"
fresh
printf '%s\n' '<a title="' '' "$JSON_LINE" >"$T"
expect "template: the allowed line right after an open tag fails" 1 "open tag"
fresh
printf '%s\n' '<a title="x">y</a>' '' "$JSON_LINE" >"$T"
expect "template: the allowed line after closed tags passes" 0 "ok:"
V="$tmp/repo/$VIEW"
fresh
printf '%s\n' 'fn f(a: EmbeddedJson) {}' >>"$V"
expect "rust: EmbeddedJson on another line of view.rs fails" 1 "EmbeddedJson may be named only"
fresh
printf '%s\n' 'struct EmbeddedJson;' >"$tmp/repo/crates/rdy-engine/src/report/html/other.rs"
expect "rust: EmbeddedJson in another file of report/html fails" 1 "EmbeddedJson may be named only"
fresh
printf '%s\n' 'struct EmbeddedJsonX;' 'fn embedded_json() {}' >"$tmp/repo/crates/rdy-engine/src/report/html/other.rs"
expect "rust: names that only start with EmbeddedJson pass" 0 "ok:"
fresh
printf '%s\n' 'pub json: EmbeddedJson,' 'let json = EmbeddedJson(json);' 'pub(super) struct EmbeddedJson(HtmlSafeJson);' 'impl std::fmt::Display for EmbeddedJson {' >>"$V"
expect "rust: the known EmbeddedJson lines of view.rs pass" 0 "ok:"
fresh
printf '%s\n' '{% raw %}{{ "{% endraw %}<p title={{ json }}>{% raw %}" }}{% endraw %}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a raw block with a quote that hides a json fails" 1 "raw block"
fresh
printf '%s\n' '{%- raw -%}x{%- endraw -%}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a raw block with trim marks fails" 1 "raw block"
fresh
printf '%s\n' '<p>{{ rawness }} {{ x.raw_y }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: names that only start with raw pass" 0 "ok:"
fresh
printf '%s\n' '{# a {# b #}{{ json }} #}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a comment inside a comment counts every json" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '{# never ends {{ json }}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a comment that never ends counts every json" 1 "found 2 use(s) of the word json"
fresh
printf '%s\n' '<p>{# a comment #}{{ name }}</p>' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: a plain comment passes" 0 "ok:"
fresh
printf '%s\n' 'a::b in plain text, and {# askama::filters::Safe in a comment #}' >>"$tmp/repo/crates/rdy-engine/templates/report.html"
expect "template: :: outside a tag and inside a comment passes" 0 "ok:"
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
  'impl askama::filters::HtmlSafe for Other {}' 'impl askama::filters::HtmlSafe for HtmlSafeJson {}' \
  'use askama::filters::HtmlSafeOutput;' '#[template(path = "a.html", escape = "none")]' \
  'let _ = askama::filters::Safe("x");' \
  'use askama::filters::*;' 'use askama::filters as f;' 'use askama::{filters, Template};' \
  'struct S { v: Safe<String> }' 'let _ = askama::filters::safe("x", y);' 'let _ = askama::filters::escape("x", y);' \
  'let _ = askama::filters::e("x", y);' 'enum Mode { Unsafe }' 'impl HtmlSafe for HtmlSafeJson {}'; do
  fresh
  printf '%s\n' 'use askama::Template;' "$code" >>"$tmp/repo/xtask/src/main.rs"
  expect "rust: $code" 1 "FAIL"
done
fresh
printf '%s\n' 'use askama::filters::{' '    Escaper,' '    Safe,' '};' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: a multi-line use of Safe" 1 "FAIL"
fresh
printf '%s\n' 'fn f() { let _ = "Safe"; }' >>"$tmp/repo/xtask/src/other.rs"
expect "rust: the word Safe in a file that does not name askama passes" 0 "ok:"
fresh
printf '%s\n' '#[cfg_attr(' '    feature = "html",' '    template(path = "report.txt")' ')]' 'struct A;' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: a template attribute inside cfg_attr over several lines" 1 "must be path"
fresh
printf '%s\n' "$ALLOWED" >>"$tmp/repo/xtask/src/main.rs"
expect "rust: the allowed marker in any other file fails" 1 "xtask/src/main.rs"
fresh
printf '%s\n' "$ALLOWED" >>"$tmp/repo/$VIEW"
expect "rust: the allowed marker twice in its own file fails" 1 "html/view.rs"
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
printf '%s\n' '[features]' 'html = ["askama/urlencode"]' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: askama/urlencode in a feature list" 1 "askama feature"
fresh
printf '%s\n' '[features]' 'html = ["askama?/serde_json"]' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: askama?/serde_json in a feature list" 1 "askama feature"
fresh
printf '%s\n' '[features]' '# html = ["askama/urlencode"]' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: the same in a comment passes" 0 "ok:"
fresh
printf '%s\n' 'askama = { version = "0.16" }' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: no default-features = false" 1 "must say default-features = false"
fresh
printf '%s\n' 'askama = { version = "0.16", default-features = true }' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: default-features = true" 1 "must not turn on"
fresh
printf '%s\n' '[dependencies.askama]' 'version = "0.16"' >"$tmp/repo/xtask/Cargo.toml"
expect "toml: askama as a table with default features" 1 "must say default-features = false"
fresh
printf '%s\n' '#[template(path = "a.html", config = "x.toml")]' 'struct A;' >>"$tmp/repo/xtask/src/main.rs"
expect "rust: a template attribute with config" 1 "must be path"
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
if grep -Fxq -- "$ALLOWED" "$real_root/$VIEW"; then
  ok "the real marker is the allowed line"
else
  bad "$VIEW lacks the allowed marker line"
fi

exit "$fail"
