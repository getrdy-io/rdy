# Security policy

`rdy` runs inside other people's environments, often with elevated privileges. We take reports seriously
and we answer them. The threat model is in `docs/plan/05-threat-model.md`.

## Supported versions

Until 1.0, only the latest minor release gets security fixes, including its alpha and beta builds.
Upgrade to get a fix.

| Version | Supported |
|---|---|
| Latest 0.x minor | Yes |
| Older 0.x | No |

## In scope

- The `rdy` binary and the public crates in this repo (`rdy-spec`, `rdy-engine`, `rdy-bundle`, `rdy-checks-*`).
- `install.sh`, release artifacts and the release pipeline (signatures, checksums, SBOM, GitHub Actions).

The portal at app.getrdy.io joins scope when it launches.

## Out of scope

- Issues that need root or the operator's own configuration to exploit, such as a kubeconfig exec
  plugin doing what the kubeconfig says.
- What a vendor puts in its own spec, beyond what `rdy` lets a spec do.
- Social engineering, physical access, and volumetric denial of service.
- Bugs in dependencies with no exploit path through `rdy`. Please report those upstream.

## How to report

Please do not open a public issue.

- Preferred: GitHub private vulnerability reporting. On `getrdy-io/rdy`, open the Security tab and choose
  "Report a vulnerability". This channel is already encrypted.
- Or email security@getrdy.io. PGP key: to be published.

Include the version (`rdy version`), the OS, what you did, what happened, and a proof of concept if you
have one. Use synthetic data only. Do not send real secrets or customer data.

## What happens next

Rdy is maintained by one person part time. These are the timelines we can keep.

1. We acknowledge your report within 3 business days.
2. We confirm the issue and assign a severity within 7 days.
3. We fix it in a private advisory. Targets: critical 14 days, high 30 days, others 90 days.
4. We publish the fix and a GitHub security advisory, with a CVE where the issue qualifies. Affected
   crates also get a RustSec entry.
5. We credit you in the advisory unless you ask us not to.

We disclose at fix release or 90 days after your report, whichever comes first. We can agree on more time
if a fix needs it.

## Safe harbor

We will not take legal action against good-faith research that follows this policy, avoids privacy
harm and service disruption, and gives us a reasonable time to fix before disclosure. There is no bug
bounty yet.

## Verifying releases

Every release ships `SHA256SUMS`, signed with Sigstore cosign keyless by the `sign-release.yml` workflow
of `getrdy-io/rdy`, plus SBOMs. `scripts/verify-release.sh <tag>` runs the exact checks. By hand:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/v0.1.0-alpha.3" \
  --certificate-github-workflow-repository getrdy-io/rdy \
  --certificate-github-workflow-ref refs/tags/v0.1.0-alpha.3 \
  --certificate-github-workflow-trigger push \
  SHA256SUMS
```

The three `--certificate-github-workflow-*` lines matter. The identity names our workflow file, and any
repository can call that file. These lines say that the run that signed was ours, on this tag.

Replace the tag with the release you downloaded (twice). Then check your archive's line in `SHA256SUMS` with
`sha256sum` (Linux) or `shasum -a 256` (macOS).

Specs are signed by the vendor that wrote them, in minisign format. `rdy` refuses unsigned or tampered
specs unless `--allow-unsigned` is set.
