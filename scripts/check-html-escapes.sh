#!/bin/sh
# check-html-escapes.sh: fail on any way to switch off askama's HTML escaping (M1-078, ADR 0003 decision 5,
# SEC-64, PR #149 and PR #19 security reviews).
#
# The HTML report prints untrusted text from the machine and from the vendor's spec. askama escapes every
# value in an `.html` template. The one value that is printed raw is the embedded result, wrapped in
# `EmbeddedJson` (crates/rdy-engine/src/report/html/view.rs), whose text has no `<`, `>` or `&` in it and is
# printed only as the text of a `<script type="application/json">` element. This script keeps it the only
# one. The compiler is the first layer (the root clippy.toml bans the Safe types and the safe, escape and e
# functions). This script is the second layer, because clippy does not see the trait of an `impl` header. It
# looks for:
#
#   templates   (each file is read with its newlines joined, so a filter name split over two lines is seen)
#               a `|safe` or `|unsafe` filter, `|e(...)` or `|escape(...)` (which takes an escaper name, and
#               `"none"` turns escaping off), `|json`, `|json_pretty`, `|urlencode`, `|urlencode_strict`,
#               `{% filter safe %}` and the like, `escape =`, `autoescape`, and any `::` inside `{{ }}` or
#               `{% %}` (a path call such as `askama::filters::Safe(x)` works in a template)
#   Rust        `MaybeSafe`, `HtmlSafeOutput`, `HtmlSafe` anywhere; in a file that names askama also the
#               words `filters`, `Safe` and `Unsafe` (comments are skipped); `escape = "..."`; and a
#               `#[template(...)]` (also inside `cfg_attr`) that does not name an `.html` file with `path`,
#               or that has `ext`, `source`, `in_doc`, `config` or `escape` (they pick another escaper)
#   Cargo.toml  the askama features `serde_json`, `urlencode`, `full`, `default` and `config` (also written
#               as `askama/feature` or `askama?/feature`); an askama dependency that is neither
#               `workspace = true` nor `default-features = false`, or has `default-features = true`
#   files       any file named `askama.toml`
#
# One line is allowed, once: `impl askama::filters::HtmlSafe for EmbeddedJson {}` in
# crates/rdy-engine/src/report/html/view.rs. A second marker, or that line in another file, fails.
#
# Usage: scripts/check-html-escapes.sh [repo-root]
# Exit:  0 no bypass, 1 at least one bypass, 64 usage error.
# Tests: scripts/test-check-html-escapes.sh. Needs only sh, find, grep, awk, sed and tr.

set -u

LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)
root=${1:-$(dirname "$here")}
if [ "$#" -gt 1 ] || [ ! -d "$root" ]; then
  echo "usage: scripts/check-html-escapes.sh [repo-root]" >&2
  exit 64
fi

ALLOWED_FILE=crates/rdy-engine/src/report/html/view.rs
ALLOWED_LINE='impl askama::filters::HtmlSafe for EmbeddedJson {}'

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
# The lint wall names askama's Safe items on purpose, in a manifest of its own.
[ -f "$root/tests/lint-wall/Cargo.toml" ] && echo "$root/tests/lint-wall/Cargo.toml" >>"$tmp/tomls"
list -name askama.toml >"$tmp/configs"

found=0
hit() {
  # hit FILE LINE TEXT WHY
  found=$((found + 1))
  printf 'FAIL %s:%s: %s\n     %s\n' "${1#"$root"/}" "$2" "$3" "$4"
}

word='([^A-Za-z0-9_]|$)'

# scan LIST_FILE WHY PATTERN [skip-comments]: every line of every listed file that matches PATTERN.
# askama-only (4th argument "askama") limits the scan to files that name askama.
scan() {
  list_file=$1
  why=$2
  pattern=$3
  mode=${4:-}
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    if [ "$mode" = askama ] && ! grep -q askama "$file"; then
      continue
    fi
    grep -En -e "$pattern" "$file" 2>/dev/null | while IFS= read -r match; do
      line=${match%%:*}
      text=${match#*:}
      if [ -n "$mode" ]; then
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

# tscan WHY PATTERN: the same for templates, each read as one line, so a filter split over two lines is
# seen. The text shown is the part that matched.
tscan() {
  why=$1
  pattern=$2
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    tr '\n\r\t' '   ' <"$file" | grep -Eo -e "$pattern" 2>/dev/null | while IFS= read -r part; do
      printf '%s\t%s\t%s\t%s\n' "$file" "0" "$why" "$part"
    done
  done <"$tmp/templates"
}

# Templates.
{
  tscan "the safe filter prints a value without escaping it" "[|][[:space:]]*(safe|unsafe)$word"
  tscan "the e and escape filters take an escaper name, and \"none\" turns escaping off" "[|][[:space:]]*(e|escape)[[:space:]]*\\("
  tscan "a json or urlencode filter returns output marked safe" "[|][[:space:]]*(json|json_pretty|urlencode|urlencode_strict)$word"
  tscan "a filter block with safe or escape turns escaping off" "[{]%[-+~]?[[:space:]]*filter[[:space:]]+(safe|unsafe|e|escape)$word"
  tscan "an escape setting in a template" "escape[[:space:]]*="
  tscan "autoescape switches escaping" "autoescape"
  tscan "a path inside a template can name askama::filters::Safe" "[{][{%][^}]*::"
} >"$tmp/hits"

# Rust sources.
{
  scan "$tmp/rs" "a safe marker or safe filter output type switches escaping off" "(^|[^A-Za-z0-9_])(MaybeSafe|HtmlSafeOutput|HtmlSafe)$word" comments
  scan "$tmp/rs" "askama's filters module, Safe and Unsafe are not used outside the one marker line" "(^|[^A-Za-z0-9_])(filters|Safe|Unsafe)$word" askama
  scan "$tmp/rs" "an escaper named in a template attribute" "escape[[:space:]]*=[[:space:]]*\"" comments
} >>"$tmp/hits"

# A `#[template(...)]` (also inside `cfg_attr`, over any number of lines) must name a file that ends in
# `.html`, and must not pick another escaper, give the template inline or read a config.
while IFS= read -r file; do
  [ -n "$file" ] || continue
  awk -v file="$file" '
    BEGIN { RS = "\001" }
    {
      rest = $0; line = 1
      while (match(rest, /#\[[^\]]*\]/)) {
        before = substr(rest, 1, RSTART - 1)
        attr = substr(rest, RSTART, RLENGTH)
        line += gsub(/\n/, "\n", before)
        rest = substr(rest, RSTART + RLENGTH)
        if (attr ~ /template[ \t\n]*\(/) {
          ok = (attr ~ /path[ \t\n]*=[ \t\n]*"[^"]*\.html"/)
          bad = (attr ~ /(^|[^A-Za-z0-9_])(ext|source|in_doc|config|escape)[ \t\n]*=/)
          if (!ok || bad) {
            shown = attr
            gsub(/[ \t\n]+/, " ", shown)
            printf "%s\t%d\t%s\t%s\n", file, line, "a template attribute must be path = \"....html\" with no ext, source, in_doc, config or escape", shown
          }
        }
        line += gsub(/\n/, "\n", attr)
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
      gsub(/[ \t]+/, " ", buf)
      if (buf ~ /"(serde_json|urlencode|full|default|config)"/) {
        printf "%s\t%d\t%s\t%s\n", file, start, "this askama feature adds a filter that marks output safe, or reads a config file", buf
      }
      if (buf ~ /default-features ?= ?true/) {
        printf "%s\t%d\t%s\t%s\n", file, start, "an askama dependency must not turn on its default features", buf
      } else if (buf !~ /default-features ?= ?false/ && buf !~ /workspace ?= ?true/) {
        printf "%s\t%d\t%s\t%s\n", file, start, "an askama dependency must say default-features = false (or workspace = true)", buf
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
  # A feature of askama switched on from another crate's feature list.
  grep -En 'askama[?]?/(serde_json|urlencode|full|default|config)' "$file" 2>/dev/null | while IFS= read -r match; do
    text=${match#*:}
    trimmed=$(printf '%s' "$text" | sed 's/^[[:space:]]*//')
    case $trimmed in
    \#*) continue ;;
    esac
    printf '%s\t%s\t%s\t%s\n' "$file" "${match%%:*}" "this askama feature adds a filter that marks output safe, or reads a config file" "$text" >>"$tmp/hits"
  done
done <"$tmp/tomls"

# A file named askama.toml.
while IFS= read -r file; do
  [ -n "$file" ] || continue
  printf '%s\t%s\t%s\t%s\n' "$file" 1 "an askama config file can add escapers (the config feature is off)" "(file)" >>"$tmp/hits"
done <"$tmp/configs"

# Report every hit but the first copy of the one allowed line. A line that two patterns match counts once.
# (Template hits have line 0, so each matched fragment is its own line there.)
awk -F '\t' '$2 == 0 || !seen[$1 FS $2]++' "$tmp/hits" >"$tmp/unique"
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
  echo "fix: remove them. Untrusted text must go through askama's escaping. Only the embedded result may be printed raw, and its marker is the one allowed line in $ALLOWED_FILE"
  exit 1
fi
echo "ok: no askama escape bypass"
exit 0
