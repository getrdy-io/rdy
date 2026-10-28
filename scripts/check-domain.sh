#!/bin/sh
# check-domain.sh: one-time and repeatable check of the domain hardening for getrdy.io (SEC-05).
#
# Checks, with a PASS or FAIL line and a fix line for each failure:
#   1. registrar lock   clientTransferProhibited in RDAP or whois status
#   2. DNSSEC           DS record at the parent and the AD flag from a validating resolver
#   3. CAA              at least one issue record, and only allowed CAs
#   4. HSTS             Strict-Transport-Security on https://<domain>
# Hardware-key MFA cannot be read from outside. It is printed as MANUAL.
#
# Usage: scripts/check-domain.sh [domain]
# Exit:  0 all automated checks passed, 1 at least one failed, 64 usage error.
#
# Tools: uses dig (and delv if present) for DNS. If dig is missing it falls back to a
# DNS-over-HTTPS JSON API through curl and jq. Registrar lock uses RDAP (curl and jq)
# when the TLD publishes RDAP, and whois otherwise. Every result names the tool behind it.
#
# Environment:
#   RDY_DNS_TOOL     dig or doh. Default: dig if installed, else doh.
#   RDY_RESOLVER     validating resolver for dig and delv. Default 1.1.1.1.
#   RDY_DOH_URL      DoH JSON endpoint. Default https://dns.google/resolve.
#   RDY_CAA_ALLOWED  space-separated CAA issuer domains. Default: the CAs Cloudflare uses.
#   RDY_RDAP_URL     RDAP base URL (ending in a slash). Overrides the IANA bootstrap lookup.
#   RDY_HSTS_MIN     minimum HSTS max-age in seconds. Default 15552000 (180 days).

set -u

DOMAIN="${1:-getrdy.io}"
RESOLVER="${RDY_RESOLVER:-1.1.1.1}"
DOH_URL="${RDY_DOH_URL:-https://dns.google/resolve}"
CAA_ALLOWED="${RDY_CAA_ALLOWED:-letsencrypt.org pki.goog ssl.com sectigo.com}"
HSTS_MIN="${RDY_HSTS_MIN:-15552000}"
case "$HSTS_MIN" in
'' | *[!0-9]*)
  echo "RDY_HSTS_MIN must be a whole number of seconds" >&2
  exit 64
  ;;
esac
CURL_OPTS="--silent --show-error --max-time 20"

case "$DOMAIN" in
-h | --help)
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
  ;;
-* | '' | *[!A-Za-z0-9.-]*)
  echo "usage: scripts/check-domain.sh [domain]" >&2
  exit 64
  ;;
esac
case "$DOMAIN" in
*.*) ;;
*)
  echo "usage: scripts/check-domain.sh [domain]  (needs a name like example.com)" >&2
  exit 64
  ;;
esac

TLD="${DOMAIN##*.}"
FAILS=0
PASSES=0

have() { command -v "$1" >/dev/null 2>&1; }

# with_timeout CMD ARGS...: run with a 20 second limit when timeout exists.
with_timeout() {
  if have timeout; then
    timeout 20 "$@"
  else
    "$@"
  fi
}

pass() {
  PASSES=$((PASSES + 1))
  printf 'PASS    %s: %s\n' "$1" "$2"
}

fail() {
  FAILS=$((FAILS + 1))
  printf 'FAIL    %s: %s\n' "$1" "$2"
  printf '        fix: %s\n' "$3"
}

if [ -n "${RDY_DNS_TOOL:-}" ]; then
  DNS_TOOL="$RDY_DNS_TOOL"
elif have dig; then
  DNS_TOOL=dig
else
  DNS_TOOL=doh
fi
case "$DNS_TOOL" in
dig)
  have dig || {
    echo "RDY_DNS_TOOL=dig but dig is not installed" >&2
    exit 64
  }
  ;;
doh)
  if ! have curl || ! have jq; then
    echo "DNS-over-HTTPS mode needs curl and jq" >&2
    exit 64
  fi
  ;;
*)
  echo "RDY_DNS_TOOL must be dig or doh" >&2
  exit 64
  ;;
esac

# dns_data TYPE NUMBER: print the record data, one record per line. Empty when none.
# Returns 2 when the lookup itself failed (network, timeout, bad JSON), 0 otherwise.
dns_data() {
  if [ "$DNS_TOOL" = dig ]; then
    dd_out=$(dig +short +time=5 +tries=2 "@$RESOLVER" "$DOMAIN" "$1" 2>/dev/null) || return 2
  else
    # shellcheck disable=SC2086
    dd_body=$(curl $CURL_OPTS -H 'accept: application/dns-json' \
      "$DOH_URL?name=$DOMAIN&type=$2&do=1" 2>/dev/null) || return 2
    dd_out=$(printf '%s' "$dd_body" |
      jq -r --argjson t "$2" '.Answer[]? | select(.type == $t) | .data' 2>/dev/null) || return 2
  fi
  if [ -n "$dd_out" ]; then printf '%s\n' "$dd_out"; fi
  return 0
}

# dns_ad: print yes or no for the AD flag on an apex SOA answer. Prints nothing on failure.
dns_ad() {
  if [ "$DNS_TOOL" = dig ]; then
    if dig +dnssec +noall +comments +time=5 +tries=2 "@$RESOLVER" "$DOMAIN" SOA 2>/dev/null |
      grep -E '^;; flags:' | grep -qE ' ad[ ;]'; then
      echo yes
    elif dig +noall +comments +time=5 +tries=2 "@$RESOLVER" "$DOMAIN" SOA 2>/dev/null |
      grep -qE '^;; flags:'; then
      echo no
    fi
  else
    # shellcheck disable=SC2086
    curl $CURL_OPTS -H 'accept: application/dns-json' \
      "$DOH_URL?name=$DOMAIN&type=SOA&do=1" |
      jq -r 'if .AD == true then "yes" elif .AD == false then "no" else empty end'
  fi
}

dns_tool_label() {
  if [ "$DNS_TOOL" = dig ]; then
    echo "dig @$RESOLVER"
  else
    echo "DoH $DOH_URL, curl+jq"
  fi
}

# ---- 1. registrar lock -------------------------------------------------------------
check_lock() {
  item="registrar lock"
  fixmsg="Registrar dashboard: turn on the transfer lock for $DOMAIN (see docs/security/domain-hardening.md)."
  statuses=""
  via=""
  base="${RDY_RDAP_URL:-}"

  if [ -z "$base" ] && have curl && have jq; then
    # shellcheck disable=SC2086
    base=$(curl $CURL_OPTS https://data.iana.org/rdap/dns.json 2>/dev/null |
      jq -r --arg t "$TLD" '[.services[] | select(.[0] | index($t))][0][1][0] // empty' 2>/dev/null)
  fi

  if [ -n "$base" ] && have curl && have jq; then
    # shellcheck disable=SC2086
    out=$(curl $CURL_OPTS -H 'accept: application/rdap+json' "${base}domain/$DOMAIN" 2>/dev/null) || out=""
    statuses=$(printf '%s' "$out" | jq -r '.status[]?' 2>/dev/null)
    via="RDAP ${base}domain/$DOMAIN via curl+jq"
  fi

  if [ -z "$statuses" ] && have whois; then
    out=$(with_timeout whois "$DOMAIN" 2>/dev/null) || out=""
    statuses=$(printf '%s\n' "$out" | grep -iE '^[[:space:]]*(domain )?status:' | sed 's/^[^:]*:[[:space:]]*//')
    via="whois $DOMAIN"
  fi

  if [ -z "$via" ]; then
    fail "$item" "cannot check. $TLD has no RDAP in the IANA bootstrap and whois is not installed." \
      "Install whois and rerun, or read the status in the registrar dashboard. Set RDY_RDAP_URL if the registry publishes RDAP."
    return
  fi
  if [ -z "$statuses" ]; then
    fail "$item" "no status codes returned by $via. The domain may not be registered, or the query was blocked." \
      "Run the same query by hand and check the domain is registered. $fixmsg"
    return
  fi

  norm=$(printf '%s\n' "$statuses" | tr '[:upper:]' '[:lower:]' | tr -d ' _-')
  if printf '%s\n' "$norm" | grep -q 'clienttransferprohibited'; then
    pass "$item" "clientTransferProhibited is set (via $via)"
  elif printf '%s\n' "$norm" | grep -q 'servertransferprohibited'; then
    pass "$item" "serverTransferProhibited is set, a registry lock (via $via)"
  else
    shown=$(printf '%s\n' "$statuses" | sed 's/ http.*//' | tr '\n' ',' | sed 's/,$//')
    fail "$item" "neither clientTransferProhibited nor serverTransferProhibited is set. Status: $shown (via $via)" "$fixmsg"
  fi
}

# ---- 2. DNSSEC ---------------------------------------------------------------------
check_dnssec() {
  item="DNSSEC"
  label=$(dns_tool_label)
  fixmsg="Cloudflare: DNS > Settings > DNSSEC > Enable DNSSEC, then add the DS record at the registrar."

  ds=$(dns_data DS 43)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$item" "lookup failed for the DS record (via $label)" "Check the network and the resolver, then rerun."
    return
  fi
  if [ -z "$ds" ]; then
    fail "$item" "no DS record at the parent zone, so the zone is not signed in the chain (via $label)" "$fixmsg"
    return
  fi

  ad=$(dns_ad) || ad=""
  if [ "$DNS_TOOL" = dig ] && have delv; then
    if with_timeout delv "@$RESOLVER" "$DOMAIN" SOA 2>&1 | grep -q 'fully validated'; then
      pass "$item" "DS present and delv reports fully validated (via dig and delv @$RESOLVER)"
    else
      fail "$item" "DS present but delv did not report fully validated (via delv @$RESOLVER)" \
        "The DS at the registrar probably does not match the key in Cloudflare. Copy it again from Cloudflare."
    fi
    return
  fi
  case "$ad" in
  yes) pass "$item" "DS present and the resolver sets the AD flag (via $label)" ;;
  no) fail "$item" "DS present but the resolver did not set the AD flag (via $label)" \
    "The DS at the registrar probably does not match the key in Cloudflare. Copy it again from Cloudflare." ;;
  *) fail "$item" "could not read the AD flag (via $label)" "Rerun with network access to a validating resolver." ;;
  esac
}

# ---- 3. CAA ------------------------------------------------------------------------
check_caa() {
  item="CAA"
  label=$(dns_tool_label)
  fixmsg="Cloudflare: DNS > Records > Add record > CAA, once per allowed CA. Cloudflare adds the other CAs it needs."

  caa=$(dns_data CAA 257)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$item" "lookup failed for CAA records (via $label)" "Check the network and the resolver, then rerun."
    return
  fi
  if [ -z "$caa" ]; then
    fail "$item" "no CAA records on $DOMAIN (via $label)" "$fixmsg"
    return
  fi
  if printf '%s\n' "$caa" | grep -q '^\\#'; then
    fail "$item" "the resolver returned CAA in raw form, which this script cannot read (via $label)" \
      "Use a newer dig, or set RDY_DNS_TOOL=doh."
    return
  fi

  caa=$(printf '%s\n' "$caa" | tr '[:upper:]' '[:lower:]')
  plain=$(printf '%s\n' "$caa" | grep -cE '^[0-9]+[[:space:]]+issue[[:space:]]')
  if [ "$plain" -eq 0 ]; then
    fail "$item" "no plain issue tag. issuewild alone does not limit non-wildcard issuance, so any CA may still issue (via $label)" \
      "Add an issue record for each CA we use, as well as any issuewild records. $fixmsg"
    return
  fi
  issuers=$(printf '%s\n' "$caa" |
    sed -n 's/^[0-9][0-9]*[[:space:]][[:space:]]*issue\(wild\)\{0,1\}[[:space:]][[:space:]]*"\{0,1\}\([^";]*\).*/\2/p' |
    grep -v '^$' | sort -u)

  bad=""
  for ca in $issuers; do
    ok=no
    for allowed in $CAA_ALLOWED; do
      if [ "$ca" = "$allowed" ]; then ok=yes; fi
    done
    if [ "$ok" = no ]; then bad="$bad $ca"; fi
  done
  if [ -n "$bad" ]; then
    fail "$item" "CAs not on the allowed list:$bad. Allowed: $CAA_ALLOWED (via $label)" \
      "Delete the CAA records for CAs we do not use, or add the CA to RDY_CAA_ALLOWED and to the doc if it is really used."
    return
  fi
  pass "$item" "issuers: $(printf '%s\n' "$issuers" | tr '\n' ' ' | sed 's/ $//') (via $label)"
}

# ---- 4. HSTS -----------------------------------------------------------------------
check_hsts() {
  item="HSTS"
  fixmsg="Cloudflare: SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS) > Enable. Set max-age 6 months or more, include subdomains."
  if ! have curl; then
    fail "$item" "curl is not installed" "Install curl and rerun."
    return
  fi
  # shellcheck disable=SC2086
  if ! hdr=$(curl $CURL_OPTS --head "https://$DOMAIN" 2>&1); then
    fail "$item" "could not fetch https://$DOMAIN (via curl): $(printf '%s' "$hdr" | grep -i "^curl:" | tail -n 1)" \
      "Publish the site first (Pages custom domain), then rerun. $fixmsg"
    return
  fi
  line=$(printf '%s\n' "$hdr" | tr -d '\r' | grep -i '^strict-transport-security:' | tail -n 1)
  if [ -z "$line" ]; then
    fail "$item" "no Strict-Transport-Security header on https://$DOMAIN (via curl --head)" "$fixmsg"
    return
  fi
  lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
  age=$(printf '%s' "$lower" | sed -n 's/.*max-age=\([0-9][0-9]*\).*/\1/p')
  if [ -z "$age" ] || [ "$age" -lt "$HSTS_MIN" ]; then
    fail "$item" "max-age is ${age:-missing}, need at least $HSTS_MIN (via curl --head): $line" "$fixmsg"
    return
  fi
  if ! printf '%s' "$lower" | grep -q 'includesubdomains'; then
    fail "$item" "includeSubDomains is missing (via curl --head): $line" "$fixmsg"
    return
  fi
  pass "$item" "$line (via curl --head)"
}

echo "Domain hardening check for $DOMAIN on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "DNS tool: $DNS_TOOL"
check_lock
check_dnssec
check_caa
check_hsts

echo "MANUAL  registrar MFA: hardware key or passkey is the only second factor. Cannot be read from outside."
echo "MANUAL  Cloudflare MFA: hardware key or passkey is the only second factor. Cannot be read from outside."
echo "        how: docs/security/domain-hardening.md, sections on MFA. Record the date in the PR."

echo "Summary: $PASSES passed, $FAILS failed, 2 manual."
if [ "$FAILS" -gt 0 ]; then
  exit 1
fi
exit 0
