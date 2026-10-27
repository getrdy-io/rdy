# Security policy

`rdy` runs inside other people's environments, often with elevated privileges. We take reports seriously
and we answer them.

## Supported versions

Until 1.0, only the latest minor release gets security fixes. Upgrade to get a fix.

| Version | Supported |
|---|---|
| Latest 0.x minor | Yes |
| Older 0.x | No |

## What is in scope

- The `rdy` binary and the public crates in this repo (`rdy-spec`, `rdy-engine`, `rdy-bundle`, `rdy-checks-*`).
- The install script served at https://getrdy.io/install.
- Release artifacts and the release pipeline (signatures, checksums, SBOM, GitHub Actions workflows).

The portal at app.getrdy.io joins scope when it launches.

## How to report

Please do not open a public issue.

- Preferred: GitHub private vulnerability reporting. Go to the Security tab of `getrdy-io/rdy` and
  choose "Report a vulnerability".
- Or email security@getrdy.io. PGP key: to be published.

Include the version (`rdy version`), the OS, what you did, what happened, and a proof of concept if you
have one. Use synthetic data only. Do not send real secrets or customer data.

## What happens next

Rdy is maintained by one person part time. These are the timelines we can keep.

1. We acknowledge your report within 3 business days.
2. We confirm the issue and assign a severity within 7 days.
3. We fix it in a private advisory. Targets: critical 14 days, high 30 days, others 90 days.
4. We publish the fix, a GitHub security advisory and a CVE. Affected crates also get a RustSec entry.
5. We credit you in the advisory unless you ask us not to.

We disclose at fix release or 90 days after your report, whichever comes first. We can agree on more time
if a fix needs it.

## Safe harbor

We will not take legal action against good-faith research that follows this policy, avoids privacy
harm and service disruption, and gives us a reasonable time to fix before disclosure. There is no bug
bounty yet.

## Verifying releases

Every release is signed with Sigstore cosign (keyless, bound to our release workflow) and ships SHA-256
checksums and an SBOM. Specs are signed by the vendor that wrote them with ed25519; `rdy` refuses unsigned
or tampered specs unless `--allow-unsigned` is set. Verification steps are on docs.getrdy.io.
