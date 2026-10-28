# Domain and account hardening for getrdy.io

Ticket: M1-008 (SEC-05). Threat: T1 in `docs/plan/05-threat-model.md`. Someone who takes over the
registrar or Cloudflare can serve a bad `install.sh` at `getrdy.io/install`. The signature checks in
`install.sh` limit the damage, but we do not want to lean on them. This page is the founder's checklist
for the account-side work, plus the record of the check.

Do this before M2-019 puts a Worker on `getrdy.io/install`. M2-019 depends on this ticket.

## How the check works

`scripts/check-domain.sh` checks four items from the outside. It prints PASS or FAIL per item, a fix line
for each FAIL, and exits 1 if any item fails.

```sh
scripts/check-domain.sh            # checks getrdy.io
scripts/check-domain.sh example.com
```

| Item | Passes when | Tools |
| --- | --- | --- |
| Registrar lock | `clientTransferProhibited` or `serverTransferProhibited` is in the RDAP or whois status | RDAP (curl, jq) if the TLD publishes it, else `whois` |
| DNSSEC | A DS record exists at the parent and a validating resolver sets the AD flag | `dig` (and `delv` if present), else DNS-over-HTTPS JSON via curl and jq |
| CAA | At least one plain `issue` record (`issuewild` alone is not enough), and every issuer is on the allowed list | `dig`, else DNS-over-HTTPS |
| HSTS | `Strict-Transport-Security` on `https://getrdy.io` with max-age of 180 days or more and `includeSubDomains` | `curl --head` |

Offline stub tests for the parsers are in `scripts/test-check-domain.sh`.

Hardware-key MFA cannot be read from outside. The script prints it as MANUAL. You confirm it by hand
(see below) and write the date in the PR.

Every result line names the tool that produced it. Settings are environment variables, listed at the top of
the script: `RDY_DNS_TOOL`, `RDY_RESOLVER`, `RDY_DOH_URL`, `RDY_CAA_ALLOWED`, `RDY_RDAP_URL`, `RDY_HSTS_MIN`.

Note on `.io`: the IANA RDAP bootstrap has no entry for `.io`, and `rdap.nic.io` does not resolve. So for
`getrdy.io` the lock check needs the `whois` command. Install it on your own machine (`apt install whois`
or `brew install whois`).

## Checklist for the founder

Do the items in this order. Tick each box and put the date in the PR.

### 1. Hardware-key MFA on the registrar

- [ ] Buy two hardware security keys (one primary, one backup kept offline in a different place). A
  platform passkey is acceptable as an extra, not as the only factor.
- [ ] Where to click: registrar account settings, security or sign-in section, two-factor authentication,
  add security key. Register both keys.
- [ ] Remove every weaker factor: SMS, email codes, authenticator-app codes. If the registrar forces one
  to stay, say so in the PR and treat it as a risk to close.
- [ ] Use a unique long password from a password manager. Use a dedicated mailbox for the account that is
  itself protected by a hardware key.
- [ ] Turn on registrar notifications for login, contact change and transfer events.
- [ ] How to verify: sign out, sign in on a fresh browser profile. The registrar must ask for the key and
  nothing else. Screenshot the security page with the two keys listed and attach it to the PR with account
  identifiers blurred. Do not commit the screenshot.

### 2. Hardware-key MFA on Cloudflare

- [ ] Where to click: Cloudflare dashboard, profile menu (top right), My Profile, Authentication,
  Two-Factor Authentication, add a security key. Register both keys.
- [ ] Remove the authenticator-app and email-code methods once both keys work.
- [ ] Do not create a Global API Key. Use scoped API tokens only, with an expiry. Revoke old tokens.
- [ ] Keep the account member list to one person. Dashboard, Manage Account, Members.
- [ ] How to verify: sign in on a fresh browser profile. Cloudflare must ask for the key. Screenshot as
  above. Also look at My Profile, API Tokens, and confirm no Global API Key was ever used.

### 3. Recovery codes stored offline

- [ ] For each of the two accounts, generate recovery codes (registrar and Cloudflare both offer this next
  to the MFA settings).
- [ ] Print them or write them by hand. Store them in a sealed envelope in a safe place, apart from the
  backup key. Do not store them in the password manager, in cloud notes or in the repo.
- [ ] Test one recovery path on the account that allows it, then regenerate the codes.
- [ ] How to verify: you can name where the envelope is. Nothing else is needed in the PR. Do not write
  the location in the PR.

### 4. Registrar lock

- [ ] Where to click: registrar domain page for `getrdy.io`, look for "Transfer lock", "Registrar lock" or
  "Domain lock". Turn it on. This sets the EPP status `clientTransferProhibited`.
- [ ] Also turn on update and delete locks if the registrar offers them.
- [ ] Turn off auto-transfer and turn on auto-renew. Set the renewal payment to a card that does not
  expire soon.
- [ ] Optional: ask whether the registry offers a registry lock (`serverTransferProhibited`). It is a
  stronger lock that needs an out-of-band call to change. Not required for M1.
- [ ] How to verify: `whois getrdy.io | grep -i status` shows `clientTransferProhibited`, and
  `scripts/check-domain.sh` shows PASS for registrar lock.

### 5. DNSSEC

- [ ] Where to click, step one: Cloudflare dashboard, `getrdy.io`, DNS, Settings, DNSSEC, Enable DNSSEC.
  Keep the dialog open or click "DS record" afterwards to see the values (key tag, algorithm 13, digest
  type 2, digest).
- [ ] Step two: at the registrar, domain page, DNSSEC section, add a DS record with those values. If the
  registrar does not list algorithm 13, pick "ECDSA Curve P-256 with SHA-256".
- [ ] Wait for the parent zone to publish it. This can take minutes to hours.
- [ ] How to verify: `dig +dnssec getrdy.io SOA @1.1.1.1` shows the `ad` flag, `dig DS getrdy.io` returns
  a record, and `scripts/check-domain.sh` shows PASS for DNSSEC. If `delv getrdy.io SOA` is installed it
  should say "fully validated".
- [ ] If validation breaks (SERVFAIL on a validating resolver), the DS at the registrar does not match the
  Cloudflare key. Copy the values again. If you must back out, remove the DS at the registrar first, then
  disable DNSSEC in Cloudflare.

### 6. CAA records

Only allow the CAs that actually issue for the site. Cloudflare Universal SSL issues from Let's Encrypt,
Google Trust Services and SSL.com. Cloudflare also adds its own CAA records automatically once the zone has
any CAA record (these do not show in the dashboard, but `dig CAA` shows them). The script allows
`letsencrypt.org pki.goog ssl.com sectigo.com` by default, which matches what Cloudflare adds. Check the
Cloudflare certificate authorities page again when you do this, and change `RDY_CAA_ALLOWED` and this list
together if it moved.

- [ ] Where to click: Cloudflare dashboard, `getrdy.io`, DNS, Records, Add record, type CAA. Add one record
  per CA: tag "Only allow specific hostnames" (`issue`) for each of `letsencrypt.org`, `pki.goog` and
  `ssl.com`. Add `issuewild` records for the same CAs if you will use a wildcard certificate.
- [ ] Add an `iodef` record with `mailto:security@getrdy.io` so a CA can tell us about a refused request.
- [ ] Do not add a CA we do not use. If a new CA appears later, change this list in the same PR.
- [ ] How to verify: `dig CAA getrdy.io +short` lists only allowed CAs, and `scripts/check-domain.sh`
  shows PASS for CAA.

### 7. HSTS

HSTS needs the site to serve HTTPS first. Do this after the Pages custom domain works.

- [ ] Where to click: Cloudflare dashboard, `getrdy.io`, SSL/TLS, Edge Certificates, HTTP Strict Transport
  Security (HSTS), Enable HSTS.
- [ ] Settings: max-age 6 months (15552000) or more, include subdomains on, no-sniff on. Leave preload off
  for now. Preload is hard to undo, so turn it on only once every subdomain is HTTPS-only.
- [ ] Set SSL/TLS encryption mode to Full (strict) and turn on Always Use HTTPS in the same section.
- [ ] How to verify: `curl -sI https://getrdy.io | grep -i strict-transport` shows `max-age` and
  `includeSubDomains`, and `scripts/check-domain.sh` shows PASS for HSTS.

## Exit test for M1-008

The PR shows one run of `scripts/check-domain.sh` with all four items at PASS, plus a line from the
founder stating the date hardware-key MFA was confirmed on the registrar and on Cloudflare. Until the
founder does the account-side steps, the run below shows what is still open.

## Check run 2026-10-28

Run from the build machine of the M1-008 branch, by `scripts/check-domain.sh` with no arguments. This
machine has no `dig`, `delv`, `whois` or `shellcheck`, and no system-wide installs were made. So the script
used its fallbacks: DNS-over-HTTPS JSON from `https://dns.google/resolve` through curl and jq for DNSSEC and
CAA, and `curl --head` for HSTS. Registrar lock found no tool: `.io` has no RDAP and `whois` is missing.
HTTPS from this machine goes through a proxy, which matters only for the HSTS line.

```text
Domain hardening check for getrdy.io on 2026-10-28T11:26:23Z
DNS tool: doh
FAIL    registrar lock: cannot check. io has no RDAP in the IANA bootstrap and whois is not installed.
        fix: Install whois and rerun, or read the status in the registrar dashboard. Set RDY_RDAP_URL if the registry publishes RDAP.
FAIL    DNSSEC: no DS record at the parent zone, so the zone is not signed in the chain (via DoH https://dns.google/resolve, curl+jq)
        fix: Cloudflare: DNS > Settings > DNSSEC > Enable DNSSEC, then add the DS record at the registrar.
FAIL    CAA: no CAA records on getrdy.io (via DoH https://dns.google/resolve, curl+jq)
        fix: Cloudflare: DNS > Records > Add record > CAA, once per allowed CA. Cloudflare adds the other CAs it needs.
FAIL    HSTS: could not fetch https://getrdy.io (via curl): curl: (56) CONNECT tunnel failed, response 502
        fix: Publish the site first (Pages custom domain), then rerun. Cloudflare: SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS) > Enable. Set max-age 6 months or more, include subdomains.
MANUAL  registrar MFA: hardware key or passkey is the only second factor. Cannot be read from outside.
MANUAL  Cloudflare MFA: hardware key or passkey is the only second factor. Cannot be read from outside.
        how: docs/security/domain-hardening.md, sections on MFA. Record the date in the PR.
Summary: 0 passed, 4 failed, 2 manual.
```

What the same session saw by hand with DNS-over-HTTPS (Google JSON API through curl):

- NS for `getrdy.io` is `mario.ns.cloudflare.com` and `love.ns.cloudflare.com`. The zone is delegated to
  Cloudflare.
- The parent zone `io` answers the DS query with a signed denial (NSEC3). There is no DS, so DNSSEC is off.
- There is no CAA record, and no A or AAAA record yet. The site is not live, so HSTS cannot be read.
  The HSTS failure is that, not a fault of the proxy.
- The script's pass paths were exercised against a large, well-known domain (not committed output). They
  returned PASS for lock, DNSSEC and HSTS, and CAA passed with a widened allow list. This shows the parsers
  work. It says nothing about `getrdy.io`.

Result: 0 of 4 pass, as expected before the founder does the account-side steps. Items 1 to 7 above are
still open. The script was syntax-checked with `sh -n` and run under dash (`/bin/sh` here). `shellcheck`
is not installed on this machine, so it has not been run. Run `shellcheck scripts/check-domain.sh` before
merge if you have it.
