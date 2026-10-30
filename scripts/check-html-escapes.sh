#!/bin/sh
# check-html-escapes.sh: fail on any way to switch off askama's HTML escaping (M1-078, ADR 0003 decision 5,
# SEC-64, PR #149 security review).
#
# The HTML report prints untrusted text from the machine and from the vendor's spec. askama escapes every
# value in an `.html` template. The one value that is printed raw is `HtmlSafeJson`, the embedded result,
# whose text has no `<`, `>` or `&` in it. This script keeps it the only one. It looks for:
#
#   templates   a `|safe` or `|unsafe` filter, `|e(...)` or `|escape(...)` (which takes an escaper name,
#               and `"none"` turns escaping off), `{% filter safe %}` and the like, `escape =`, `autoescape`
#   Rust        `filters::Safe`, `MaybeSafe`, `HtmlSafeOutput`, `HtmlSafe` (an `impl` of the marker trait),
#               `escape = "..."`, and a `#[template(...)]` that does not name an `.html` file with `path`
#               (`ext = "txt"` and `source = "..."` pick another escaper)
#   Cargo.toml  the askama features `serde_json`, `urlencode`, `full`, `default` and `config`: they add
#               filters that return output marked safe, or let a config file add escapers
#   files       any file named `askama.toml`
#
# One line is allowed: `impl askama::filters::HtmlSafe for HtmlSafeJson {}` in
# crates/rdy-engine/src/report/json.rs. A second marker on any other type fails, and so does that line in
# any other file.
#
# Usage: scripts/check-html-escapes.sh [repo-root]
# Exit:  0 no bypass, 1 at least one bypass, 64 usage error.
# Tests: scripts/test-check-html-escapes.sh. Needs only sh, find, grep and awk.

set -u

LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)
root=${1:-$(dirname "$here")}
if [ "$#" -gt 1 ] || [ ! -d "$root" ]; then
  echo "usage: scripts/check-html-escapes.sh [repo-root]" >&2
  exit 64
fi

ALLOWED_FILE=crates/rdy-engine/src/report/json.rs
ALLOWED_LINE='impl askama::filters::HtmlSafe for HtmlSafeJson {}'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# Where the code lives. Build output, git data and vendored trees are not ours to judge.
dirs=""
for d in crates xtask; do
  [ -d "$root/$d" ] && dirs="$dirs $root/$d"
done
if [ -z "$dirs" ]; then
  echo "no crates/ or xtask/ directory under $root" >&2
  exit 64
fi

list() {
  # shellcheck disable=SC2086
  find $dirs \( -name target -o -name .git -o -name node_modules \) -prune -o -type f "$@" -print
}

list -name '*.rs' >"$tmp/rs"
list -path '*/templates/*' >"$tmp/templates"
list -name Cargo.toml >"$tmp/tomls"
[ -f "$root/Cargo.toml" ] && echo "$root/Cargo.toml" >>"$tmp/tomls"
list -name askama.toml >"$tmp/configs"

found=0
hit() {
  # hit FILE LINE TEXT WHY
  found=$((found + 1))
  printf 'FAIL %s:%s: %s\n     %s\n' "${1#"$root"/}" "$2" "$3" "$4"
}

# scan LIST_FILE WHY PATTERN [skip-comments]: every line of every listed file that matches PATTERN.
scan() {
  list_file=$1
  why=$2
  pattern=$3
  skip=${4:-}
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    grep -En -e "$pattern" "$file" 2>/dev/null | while IFS= read -r match; do
      line=${match%%:*}
      text=${match#*:}
      if [ "$skip" = comments ]; then
        # A comment can name a pattern without using it.
        trimmed=$(printf '%s' "$text" | sed 's/^[[:space:]]*//')
        case $trimmed in
        //*) continue ;;
        esac
      fi
      printf '%s\t%s\t%s\t%s\n' "$file" "$line" "$why" "$text"
    done
  done <"$list_file"
}

# Templates.
word='([^A-Za-z0-9_]|$)'
{
  scan "$tmp/templates" "the safe filter prints a value without escaping it" "[|][[:space:]]*(safe|unsafe)$word"
  scan "$tmp/templates" "the e and escape filters take an escaper name, and \"none\" turns escaping off" "[|][[:space:]]*(e|escape)[[:space:]]*\\("
  scan "$tmp/templates" "a filter block with safe or escape turns escaping off" "[{]%[-+~]?[[:space:]]*filter[[:space:]]+(safe|unsafe|e|escape)$word"
  scan "$tmp/templates" "an escape setting in a template" "escape[[:space:]]*="
  scan "$tmp/templates" "autoescape switches escaping" "autoescape"
} >"$tmp/hits"

# Rust sources.
{
  scan "$tmp/rs" "a safe marker or safe filter output type switches escaping off" "(^|[^A-Za-z0-9_])(MaybeSafe|HtmlSafeOutput|HtmlSafe)$word" comments
  scan "$tmp/rs" "askama's Safe and Unsafe wrappers switch escaping off" "filters::([^;]*[^A-Za-z0-9_])?(Safe|Unsafe)$word" comments
  scan "$tmp/rs" "an escaper named in a template attribute" "escape[[:space:]]*=[[:space:]]*\"" comments
} >>"$tmp/hits"

# A `#[template(...)]` must name a file that ends in `.html`, and must not pick another escaper or give
# the template inline.
while IFS= read -r file; do
  [ -n "$file" ] || continue
  awk -v file="$file" '
    function flush() {
      ok = (attr ~ /path[ \t]*=[ \t]*"[^"]*\.html"/)
      bad = (attr ~ /(^|[^A-Za-z0-9_])(ext|source|in_doc)[ \t]*=/)
      if (!ok || bad) {
        gsub(/[ \t]+/, " ", attr)
        printf "%s\t%d\t%s\t%s\n", file, start, "a template attribute must be path = \"....html\" with no ext, source or in_doc", attr
      }
      collecting = 0
    }
    {
      line = $0
      if (!collecting && line ~ /^[ \t]*#\[template\(/) {
        collecting = 1; attr = ""; start = NR
      }
      if (collecting) {
        attr = attr line
        if (line ~ /\)\]/) flush()
      }
    }
  ' "$file" >>"$tmp/hits"
done <"$tmp/rs"

# Cargo.toml: the askama dependency, written inline, as dotted keys or as a table.
while IFS= read -r file; do
  [ -n "$file" ] || continue
  awk -v file="$file" '
    function opens(s,   t) { t = s; return gsub(/[\[{]/, "", t) }
    function closes(s,  t) { t = s; return gsub(/[\]}]/, "", t) }
    function flush() {
      if (buf ~ /"(serde_json|urlencode|full|default|config)"/) {
        gsub(/[ \t]+/, " ", buf)
        printf "%s\t%d\t%s\t%s\n", file, start, "this askama feature adds a filter that marks output safe, or reads a config file", buf
      }
      mode = 0
    }
    {
      line = $0
      sub(/[ \t]*#.*$/, "", line)
      if (mode == 0 && line ~ /^[ \t]*askama[A-Za-z0-9_-]*[ \t]*(=|\.)/) {
        mode = 1; buf = line; start = NR; depth = opens(line) - closes(line)
        if (depth <= 0) flush()
        next
      }
      if (mode == 0 && line ~ /^[ \t]*\[.*askama/) {
        mode = 2; buf = line; start = NR
        next
      }
      if (mode == 1) {
        buf = buf " " line; depth += opens(line) - closes(line)
        if (depth <= 0) flush()
        next
      }
      if (mode == 2) {
        if (line ~ /^[ \t]*\[/) { flush(); if (line ~ /askama/) { mode = 2; buf = line; start = NR } ; next }
        buf = buf " " line
      }
    }
    END { if (mode == 1 || mode == 2) flush() }
  ' "$file" >>"$tmp/hits"
done <"$tmp/tomls"

# A file named askama.toml.
while IFS= read -r file; do
  [ -n "$file" ] || continue
  printf '%s\t%s\t%s\t%s\n' "$file" 1 "an askama config file can add escapers (the config feature is off)" "(file)" >>"$tmp/hits"
done <"$tmp/configs"

# Report every hit but the first copy of the one allowed line. A line that two patterns match counts once.
awk -F '\t' '!seen[$1 FS $2]++' "$tmp/hits" >"$tmp/unique"
allowed_seen=0
while IFS="	" read -r file line why text; do
  [ -n "$file" ] || continue
  rel=${file#"$root"/}
  trimmed=$(printf '%s' "$text" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  if [ "$rel" = "$ALLOWED_FILE" ] && [ "$trimmed" = "$ALLOWED_LINE" ]; then
    allowed_seen=$((allowed_seen + 1))
    [ "$allowed_seen" -eq 1 ] && continue
    why="the allowed marker may appear once"
  fi
  hit "$file" "$line" "$trimmed" "$why"
done <"$tmp/unique"

if [ "$found" -gt 0 ]; then
  echo "FAIL $found askama escape bypass(es)"
  echo "fix: remove them. Untrusted text must go through askama's escaping. Only HtmlSafeJson (the embedded result) may be printed raw, and its marker is the one allowed line in $ALLOWED_FILE"
  exit 1
fi
echo "ok: no askama escape bypass"
exit 0
