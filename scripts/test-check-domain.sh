#!/bin/sh
# test-check-domain.sh: offline stub tests for scripts/check-domain.sh.
# A fake curl on PATH returns canned DoH and RDAP answers. Needs jq. Exit 0 when all pass.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/check-domain.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir "$tmp/bin"
cat >"$tmp/bin/curl" <<'EOF'
#!/bin/sh
# Fake curl. The URL is the last argument.
for a; do url=$a; done
[ "${STUB_FAIL:-}" = all ] && exit 6
case "$url" in
*type=257*) printf '%s' "${STUB_CAA:-}" ;;
*type=43*) printf '%s' '{"Status":0,"Answer":null}' ;;
*type=SOA*) printf '%s' '{"Status":0,"AD":false}' ;;
*rdap.test*) printf '%s' "${STUB_RDAP:-}" ;;
*) exit 7 ;;
esac
EOF
chmod +x "$tmp/bin/curl"

failures=0

# expect NAME GREP_PATTERN: the captured output must match the pattern.
expect() {
  if printf '%s\n' "$out" | grep -Eq "$2"; then
    echo "ok      $1"
  else
    echo "NOT OK  $1 (wanted: $2)"
    printf '%s\n' "$out" | sed 's/^/        | /'
    failures=$((failures + 1))
  fi
}

run() {
  out=$(PATH="$tmp/bin:$PATH" RDY_DNS_TOOL=doh RDY_RDAP_URL=https://rdap.test/ "$script" example.com 2>&1)
}

caa_json() {
  printf '{"Status":0,"Answer":[%s]}' "$1"
}

# 1. issuewild only must fail.
STUB_CAA=$(caa_json '{"type":257,"data":"0 issuewild \"letsencrypt.org\""}') run
expect "issuewild-only CAA fails" 'FAIL +CAA: no plain issue tag'

# 2. a plain issue record on an allowed CA passes.
STUB_CAA=$(caa_json '{"type":257,"data":"0 issue \"letsencrypt.org\""},{"type":257,"data":"0 issuewild \"pki.goog; cansignhttpexchanges=yes\""}') run
expect "issue plus issuewild CAA passes" 'PASS +CAA: issuers: letsencrypt.org pki.goog'

# 3. an issue record for a CA off the list fails.
STUB_CAA=$(caa_json '{"type":257,"data":"0 issue \"evil-ca.example\""}') run
expect "unlisted CA fails" 'FAIL +CAA: CAs not on the allowed list: evil-ca.example'

# 4. a failed lookup is reported as a failed lookup.
STUB_FAIL=all run
expect "CAA lookup failure is reported" 'FAIL +CAA: lookup failed'
expect "DS lookup failure is reported" 'FAIL +DNSSEC: lookup failed'

# 5. a missing record is still reported as missing.
STUB_CAA='{"Status":0,"Answer":null}' run
expect "empty CAA answer is no records" 'FAIL +CAA: no CAA records'
expect "empty DS answer is no DS" 'FAIL +DNSSEC: no DS record'

# 6. server transfer lock alone counts. A client lock counts. Neither fails.
STUB_RDAP='{"status":["server transfer prohibited"]}' run
expect "serverTransferProhibited passes" 'PASS +registrar lock: serverTransferProhibited'
STUB_RDAP='{"status":["client transfer prohibited","active"]}' run
expect "clientTransferProhibited passes" 'PASS +registrar lock: clientTransferProhibited'
STUB_RDAP='{"status":["active"]}' run
expect "no lock fails" 'FAIL +registrar lock: neither'

# 7. non-numeric HSTS minimum is a usage error.
out=$(RDY_HSTS_MIN=abc "$script" example.com 2>&1)
rc=$?
expect "bad RDY_HSTS_MIN is rejected" 'must be a whole number'
if [ "$rc" -eq 64 ]; then echo "ok      bad RDY_HSTS_MIN exits 64"; else
  echo "NOT OK  bad RDY_HSTS_MIN exit code $rc"
  failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all tests passed"
