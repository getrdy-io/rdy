# Review of 03-check-catalog.md, section 5 (cloud family), by cloud-iam-expert

Reviewed: section 5 (`aws.*`, reserved GCP and Azure), the cloud parts of sections 1 and 7, Appendix B, the ADR list and the ticket list. Read against `CLAUDE.md`, ADR 0008, ADR 0009, `00-overview.md` (engine API sketch) and `05-threat-model.md` (INV-06, INV-07, SEC-17, SEC-21, SEC-48).

Scope: these checks ship in M3 and later. I judged correctness, and what the M1 engine must keep open. I did not judge M1 scope.

Date of review: 2026-10-28.

## Verdict

Not ready to build as written. The AWS API choices are mostly right and the simulator facts are sound. Seven items must be fixed first: two on `assume:`, two on how the SDK reaches the network (crypto provider and shell-out, then proxy and audit log), one false-blocker risk in `aws.region`, one verdict bug in `aws.identity`, and the M1 engine shape. Fix the engine items before M1 freezes the `rdy-engine` contract crate. The rest can be fixed during M3.

Counts: 7 must fix, 12 should fix, 8 nit.

## What I verified (so the author need not redo it)

| Item | Result | Source |
| --- | --- | --- |
| `SimulatePrincipalPolicy` `PolicySourceArn` takes user, group or role only | Correct. `CallerArn` also refuses assumed-role and federated-user ARNs. | IAM API reference |
| Simulator evaluates SCPs and permissions boundaries | Correct. The reference says it evaluates identity policies, SCPs "including their condition keys and resource scoping", and your inputs. It also says results "can differ from your live AWS environment". RCPs are not supported. Resource-policy simulation is not supported for roles. Session policies are not evaluated. | IAM API reference |
| `MaxItems` 1 to 1000, default 100 | Correct. | same |
| `ActionNames` per call | No documented count limit. Each name is 3 to 128 characters. "Batches of 50" is a house choice, not an AWS limit. Say so. | same |
| Quotas `L-1216C47A`, `L-DB2E81BA`, `L-417A185B` | Correct (Standard A/C/D/H/I/M/R/T/Z, G and VT, P). Counted in vCPUs. | EC2 quota docs, search |
| Quotas `L-0263D0A3`, `L-F678F1CE`, `L-FE5A380F`, `L-A4707A72` | Correct (EC2-VPC Elastic IPs, VPCs per Region, NAT gateways per AZ, Internet gateways per Region). Internet gateways are tied to VPCs per Region. | VPC and EC2 quota docs, search |
| Quota `L-1194D53C` | Correct (EKS Clusters). | EKS quota docs, search |
| `GetServiceQuota` returns `UsageMetric` | Yes: `MetricNamespace`, `MetricName`, `MetricDimensions`, `MetricStatisticRecommendation`. | Service Quotas API reference |
| EC2 DryRun codes | `DryRunOperation` (412) means allowed, `UnauthorizedOperation` (403) means denied. Correct. | known behaviour |
| SSM global-infrastructure paths | The documented forms differ from the catalog's. See M5. | Systems Manager user guide |
| AWS SDK vs the ring-only rule | Verified with `cargo tree` in a scratch project. See M3. Dependency graph only, not a musl build. | spike |

All eight quota codes are confirmed by documentation lookups. A live `ListServiceQuotas` run is still needed at implementation time, as the catalog says. I could not call AWS from here. The `service_code` for each quota is missing from the catalog (see S1).

## Must fix

### M1. `assume:` can ship a secret to another account
- Where: section 5 intro, spec field `assume: {role_arn, external_id_env, session_name}`.
- Problem: the spec is vendor-authored and `external_id_env` names any environment variable. A signed spec can say `external_id_env: AWS_SECRET_ACCESS_KEY` (or any token the customer exported). `rdy` then sends that value as `ExternalId` to STS. AWS records AssumeRole request parameters in CloudTrail of the target account, so treat the external id as logged. This is a leak path from a hostile or compromised signed spec.
- Problem 2: the consent rule exists only under "Decisions needing an ADR" (`--allow-assume-role` or confirm interactively). Section 5, where an implementer reads, says "`rdy` calls `sts:AssumeRole`" with no gate. Non-interactive runs (the `curl | sh && rdy run --token` flow) have no defined behaviour.
- Fix:
  1. `external_id_env` must match `^RDY_[A-Z0-9_]{1,60}$`. Anything else is a lint error and a runtime refusal. Never print or store the value. ExternalId is 2 to 1224 characters; validate that.
  2. Move the consent rule into section 5. Without `--allow-assume-role`, `assume` is `skipped: "needs --allow-assume-role"`. Interactive terminals get a prompt that shows: full role ARN, target account id, session name, the env var name (not the value), and the sentence "this call is recorded in CloudTrail in account X". Non-interactive runs never assume.
  3. Show the base identity and the assumed identity side by side in the report (two `GetCallerIdentity` results).
  4. Session name: `rdy-<8 hex of run id>`, not a fixed `rdy-readiness`. The report prints the same string so the customer can find the run in CloudTrail. Allowed characters are `[\w+=,.@-]`, max 64.
  5. Optional defence in depth: pass an inline session `Policy` (reader actions only) on `AssumeRole`. Do not use it with `probe: dry_run`, because the session policy would deny the dry-run call itself.

### M2. `assume:` cannot prove what the catalog says it proves
- Where: section 5 intro: "the customer created the cross-account role for the vendor, and the check proves the role works before install day".
- Problem: a BYOC role made for a vendor normally trusts the vendor's AWS account, with an ExternalId condition. The customer's operator, running `rdy` with their own credentials, is not that principal. `sts:AssumeRole` returns `AccessDenied`. The check would fail on a correct setup, or push customers to add themselves to the trust policy, which weakens it.
- What `rdy` can verify read-only, with no assume:
  - `iam:GetRole` on the role: read `AssumeRolePolicyDocument`. Check that the trusted principal account equals the vendor account in the spec, that an `sts:ExternalId` condition exists (report "present", never the value), that no `Principal: "*"` appears without a condition. Report `MaxSessionDuration` and `PermissionsBoundary`.
  - `iam:SimulatePrincipalPolicy` with `PolicySourceArn` set to that role. The catalog already has `principal:` for this. It needs `iam:GetRole` and `iam:SimulatePrincipalPolicy` on the role, both in the reader policy.
- Fix: make "inspect and simulate the vendor role" the primary BYOC path. Add `trust: {vendor_account, external_id_required: true}` to `aws.iam` (or a small `aws.trust` check using the same APIs). Keep `assume` for the case where the operator is trusted (an installer role in the customer's own account). Rewrite the section 5 sentence so it does not promise that `rdy` proves the vendor's own assume will work.

### M3. The default AWS SDK breaks ADR 0009 and also spawns a shell
- Where: section 5 intro ("Rust SDK ... on rustls"), Appendix A, ADR 0009 "M3 risk".
- Verified: with default features, `aws-config` 1.13 plus `aws-sdk-*` pulls `aws-lc-sys` 0.46 (through `aws-smithy-http-client` `rustls-aws-lc`) and an old rustls 0.21 stack. `cargo deny` would fail on the first build. With the settings below, the graph has `ring` 0.17 and one `rustls` 0.23, and no `aws-lc-*`, `openssl-sys` or `native-tls`.
- Do not lift the `aws-lc-sys` ban. Pin the feature set:

```toml
aws-config  = { version = "1", default-features = false, features = ["rt-tokio", "sso", "behavior-version-latest"] }
aws-sdk-iam = { version = "1", default-features = false, features = ["rt-tokio"] }   # same line for every aws-sdk-* crate
aws-smithy-http-client = { version = "1", default-features = false, features = ["rustls-ring", "default-client"] }
```

  Build the client with `tls_provider(Provider::Rustls(CryptoMode::Ring))`, pass it to every SDK client config as `http_client`, and never rely on `default-https-client`. `CryptoMode::Custom` needs the `aws_sdk_unstable` cfg flag, so use `Ring`.
- Not yet tested: a musl build, and the full workspace graph with `reqwest`, `kube`, `tokio-postgres-rustls` and `redis`. `rustls` turns on `aws_lc_rs` in its own default features, so any crate that takes rustls with defaults brings aws-lc back. Keep the `cargo deny` ban as the gate and add `cargo tree -i aws-lc-sys` (must fail with "did not match") to CI. The M2 spike ticket stays, with scope "full graph and musl build".
- Shell-out: the default feature `credentials-process` makes `aws-config` run `sh -c <command>` (Unix) or `cmd.exe /C` (Windows) for any profile with `credential_process`. I read the source. That breaks INV-07 (no shell is ever spawned) and the catalog's "never shell out", and it is not in Appendix A. Many enterprise users rely on it (SSO wrappers, vault tools).
  - Conservative fix: disable the feature (as in the snippet). A profile with `credential_process` returns `skipped` with the hint "run `aws configure export-credentials --profile {p} --format env` and export the result". If you later allow it, do it by ADR, behind a flag, listed in Appendix A, with an action-log entry.

### M4. AWS traffic bypasses the probe facade, the proxy rules and the shared roots
- Where: section 5 intro, ADR 0009 decision 2, INV-06, SEC-17, SEC-21.
- Problem 1: the SDK's HTTP client does its own networking. INV-06 says every side effect goes through the facade and into the action log. As designed, AWS calls would be missing from that log, which is the audit story ("explains exactly which API it called").
- Problem 2: verified in `aws-smithy-http-client` 1.5.2 source: with no `proxy_config` set, the proxy is disabled. The SDK does not read `HTTPS_PROXY` by default. Behind a corporate proxy, `net.egress` passes (it uses the shared builder) while every `aws.*` check times out. That is the confusing split ADR 0009 was written to avoid.
- Problem 3: the SDK default trust store is its own. A TLS-intercepting proxy needs the same roots choice as `net.*` (OS store plus any extra PEM).
- Problem 4: SEC-21 refuses link-local and metadata targets for net checks. The SDK credential chain legitimately talks to `169.254.169.254` (IMDS) and the container credentials address. The policy must exempt the SDK's own credential providers by name, or EC2 instance-role runs fail.
- Fix: write one adapter in `rdy-checks-cloud`, `FacadeHttpClient`, that implements the SDK `HttpClient` trait and sends each request through the engine's HTTP primitive. That primitive applies `ProxyConfig`, the trust store from `net::client`, a host allow-list (`*.amazonaws.com` plus the spec's `endpoint`), and writes an action-log entry. It also gives fixtures one replay point (replace the primitive, not the SDK). If the adapter slips, the minimum is `ProxyConfig::from_env()` and the same `TrustStore` set on the SDK connector, plus an SDK interceptor that logs each operation. SEC-48 (read-only allow-list) is then enforceable in the same place: an interceptor that rejects any operation name not on the list.

### M5. `aws.region` can block a correct customer because of the SSM lookup
- Where: `aws.region`, Source and Thresholds ("Service missing: block").
- Findings on the path the author flagged as unconfirmed:
  - The Systems Manager guide documents `/aws/service/global-infrastructure/services/<svc>/regions` (list with `GetParametersByPath`; each value is a region name) and `/aws/service/global-infrastructure/regions/<region>/services/<svc>/endpoint` (one `GetParameter`; value is the endpoint host). The catalog's `/regions/<region>/services/<service>` without `/endpoint` is not in the guide. Use a documented path.
  - The guide says queries under `/aws/service/global-infrastructure` are supported only in 17 regions: us-east-1, us-east-2, us-west-1, us-west-2, ap-east-1, ap-south-1, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ca-central-1, eu-central-1, eu-west-1, eu-west-2, eu-west-3, eu-north-1, sa-east-1. For any other region, query one of those. A customer in eu-south-2 or ap-southeast-4 would get not-found and be blocked wrongly.
  - A customer whose SCP denies `aws:RequestedRegion` outside their own regions gets `AccessDenied` from the fallback region. That must not be read as "service missing".
  - SSM service codes (`eks`, `ssm`, `bedrock`) are short names that a spec author may not guess.
- Fix:
  1. Call a supported region (the spec region if listed, else the nearest listed; configurable `ssm_region`).
  2. `ParameterNotFound` in a supported region is `warn`: "AWS public data lists no `{svc}` in `{r}`; confirm in the console".
  3. `AccessDenied`, throttling or an unsupported-region answer is `unknown`, never `block`.
  4. Add `ssm:GetParametersByPath` to the reader policy.
  5. Keep `block` only for facts from the EC2 APIs (opt-in status, offerings).
  6. Say in the fix text that this is AWS's published list and may lag a new service or region.

### M6. `aws.identity` expiry warning means many runs can never be `Ready`
- Where: `aws.identity` Thresholds ("Credentials expiring within 15 minutes: warn"), together with `assume` "900s session".
- Problem 1: an assumed session lasts 900 seconds, so the check always warns after `assume`. Every `assume` run exits 1.
- Problem 2: credentials from IMDS, container credentials and web identity (IRSA) rotate on their own, and IMDS routinely serves credentials with under 15 minutes left. Same false warning on many EC2 and EKS runs.
- Under ADR 0008 a `Warn` makes the verdict `Warnings` (exit 1). This is a verdict bug, not noise.
- Fix: warn only when the credentials are static-with-expiry (env or profile session tokens, SSO) and the time left is below the run budget plus margin, for example `max(120s, 2 x run deadline)`. Do not warn for refreshing sources or for the check's own `assume` session. Report the credential source (env, profile name, SSO, IMDS, container, web identity). The SDK does not expose the source cleanly, so infer it from the environment variables and the selected profile. Keep `Credentials::expiry()` as the expiry value.

### M7. The M1 engine sketch cannot express what the cloud family needs
- Where: `00-overview.md` engine API (`Need`, `Context`, `Finding`), ADR 0008, catalog section 1 "Degrade rule", section 5 "No credentials" and `require: true`.
- Gaps, in order of cost to fix later:
  1. `Context` is a plain struct with public fields (`os`, `available`, `host_root`, `exec`). `rdy-engine` is a published contract crate. Adding an HTTP primitive, a cloud handle or a consent set later breaks every constructor. Make `Context` `#[non_exhaustive]` with a builder, and add a typed extension slot (a type-keyed map) so `rdy-checks-cloud` can store one lazily built `AwsSession` per run (credentials, region, partition, caller identity). That removes the "identity runs first" ordering dependency.
  2. No HTTP injection point. Only `Exec` is injectable. ADR 0009 `net::client` returns a concrete `reqwest::Client`. See M4. Define in M1 an `Http` trait next to `Exec` (send an `http::Request`, get a response, log it) even if only `net` uses it first.
  3. `Need` has `Root`, `KubeContext`, `Network`, `Command`. It needs `Credentials(Provider)` and `Consent(&'static str)` (for `--allow-assume-role`, later `--allow-custom`), both under the existing `#[non_exhaustive]`. Skipped reasons must be able to carry the missing need.
  4. No `partial`. ADR 0008 has `Pass`, `Warn`, `Block`, `Skipped`, `Timeout`, `Error`. The catalog degrade rule says "mark `partial`, name the missing privilege", and `aws.iam` needs `unknown` per action. Add to `Finding` (or the result) `partial: Option<Partial { missing: Vec<String> }>`, where `missing` holds IAM actions, plus `evidence: Vec<ApiCall>`. This is a schema change in `rdy-spec::result`, so it must land before that crate's first release.
  5. `require: true` turns `skipped` into `block`; ADR 0008 says skipped can only lower the verdict to `Warnings`. Record the exception in the engine design: the engine applies it from the spec field, not the check.
  6. Account ids and role ARNs appear in evidence. They are not secrets but they identify the customer. Add an evidence class (`identifier`) that the redactor and the upload prompt can treat separately, and say in the upload consent text that account ids are included.

## Should fix

### S1. `aws.quota`: usage metric, service codes, pending requests
- Problem: CloudWatch dimensions are hardcoded (`Service`, `Type`, `Resource`, `Class`) and given only for EC2 vCPUs. For other quotas the author must guess, and a wrong guess returns empty data, which reads as "used = 0" and a false pass.
- Fix:
  - Take namespace, metric name, dimensions and statistic from `GetServiceQuota.Quota.UsageMetric` (it is in the response). Use the recommended statistic (Maximum) over the last 15 minutes, period 60.
  - When `UsageMetric` is absent, or CloudWatch is denied, count with the service API: `ec2:DescribeAddresses` (Elastic IPs), `ec2:DescribeVpcs`, `ec2:DescribeNatGateways` per AZ, `ec2:DescribeInternetGateways`, `eks:ListClusters`. Add those actions to the reader policy.
  - Add `service_code` to every row of `aws_quotas.toml`: `ec2` for `L-1216C47A`, `L-DB2E81BA`, `L-417A185B`, `L-0263D0A3`; `vpc` for `L-F678F1CE`, `L-FE5A380F`, `L-A4707A72`; `eks` for `L-1194D53C`. Confirm with `ListServices` in the live check.
  - Say whether a request is already pending: `servicequotas:ListRequestedServiceQuotaChangeHistoryByQuota`. The fix text then says "a request is pending since {date}".
  - Compute the vCPU `need` from `instance_types` and `count` using `DescribeInstanceTypes` (`VCpuInfo.DefaultVCpus`). On-demand quotas count vCPUs, not instances.
  - `NoSuchResourceException` from `GetServiceQuota` means no applied value; fall back to `GetAWSDefaultServiceQuota` (as the catalog says) and mark the evidence "default, not applied".
  - Add Spot quota codes as optional rows for products that use Spot.

### S2. `aws.vpc`: capacity math and reachability gaps
- Capacity: `min_free_ips` per subnet is a number the spec author must guess. Add `nodes` (per AZ or total), `pods_per_node`, `cni_mode: secondary_ip|prefix` and derive the need. With the VPC CNI default (`WARM_ENI_TARGET=1`) a node holds its pods plus one spare ENI of addresses. State the formula in the docs and let the spec override it. `AvailableIpAddressCount` already excludes the 5 reserved addresses, so do not subtract them again.
- Prefix delegation needs free contiguous /28 blocks. A subnet can show enough free IPs and still fail from fragmentation. Warn on that ("free count is not proof of free /28 blocks; use a subnet CIDR reservation"). The fix text offers prefix delegation, so it must say this.
- EKS control plane ENIs need free addresses in the cluster subnets (to my knowledge the EKS docs say at least 6, 16 recommended; confirm when building). Add a floor for subnets passed to cluster creation.
- The `/24 for pod networking: warn` rule is arbitrary. Replace it with the computed need.
- Route check: a subnet without an explicit association uses the VPC main route table (`DescribeRouteTables` returns it with `Associations[].Main = true`). Without this rule the check reports "no route" for many default-association subnets. Also treat `State = blackhole` as broken, accept `::/0` for IPv6 and egress-only gateways (`eigw-`), and treat routes to `tgw-`, `vgw-`, `pcx-` or a firewall endpoint as "other path, cannot verify" (warn, not block) when the spec says `internet: nat`.
- NAT: the NAT gateway state must be `available`, and it must sit in a subnet whose route table has an `igw-` default route. Check both.
- Endpoints ("PrivateLink and endpoint reachability"): the catalog checks existence, state and `PrivateDnsEnabled`. That is not reachability. Add: interface endpoint subnets cover the workload AZs; the endpoint security group allows 443 from the node CIDR (`ec2:DescribeSecurityGroups`); gateway endpoints (S3) are associated with the subnets' route tables (`PrivateDnsEnabled` does not apply to them); private DNS needs both `enableDnsSupport` and `enableDnsHostnames`; a custom endpoint policy is reported as "present, not evaluated". When `rdy` runs inside the VPC, add an optional probe through the `net` code: resolve the endpoint host (for example `ecr.api`), expect a private address inside the VPC CIDR, then connect to 443.
- Fix text: `associate-vpc-cidr-block` with `100.64.0.0/16` also needs VPC CNI custom networking (`ENIConfig` per AZ) before pods use it. Say that.
- `DescribeVpcAttribute` takes one attribute per call. Count two calls per VPC in the budget.
- IPv6-only and dual-stack clusters are not covered. State it.

### S3. `aws.region`: names vs ids, paging, capacity wording
- AZ names (`us-east-1a`) map to different physical zones per account. Use `ZoneId` (`use1-az1`) in output, fixtures and any comparison with the vendor's list.
- `DescribeAvailabilityZones` returns Local Zones and Wavelength Zones only with `AllAvailabilityZones`. Filter `zone-type = availability-zone` and `state = available`.
- `DescribeInstanceTypeOfferings` pages with `NextToken`. Put paging in the fixture and the call budget.
- "Offered" is not "capacity available". `InsufficientInstanceCapacity` can still happen, especially for GPU types. Say so in Measures and in the fix text, and suggest an On-Demand Capacity Reservation for GPU types.
- Call `DescribeRegions` from a region that is already enabled (the spec region if enabled, else the profile default). A not-enabled region's EC2 endpoint is not usable.
- If a region is enabled but an SCP denies `aws:RequestedRegion`, `aws.iam` with `context: {aws:RequestedRegion: <r>}` catches it. Cross-link in the fix text.
- The fix command `aws account enable-region` needs `account:EnableRegion`. Name the action.
- Partitions: `aws-cn` and `aws-us-gov` use different ARN prefixes and endpoint suffixes, and the SSM path may not exist there. Derive the partition from the caller ARN. If unsupported, return `skipped` with "partition not supported yet".

### S4. `aws.iam`: simulator semantics to state, and a few traps
- Label results "simulated". The reference says results "can differ from your live environment". Evidence should say: evaluated identity policies, permissions boundary and SCPs; not evaluated: session policies, resource policies (not for roles), RCPs, VPC endpoint policies. Put this in the report line so a customer can audit the claim.
- `ec2:RunInstances` and similar: with the default resource `*`, results can mislead. The API has `ResourceHandlingOption` (`EC2-VPC-EBS-Subnet` and others) that needs instance, image, security group, network interface, subnet and volume ARNs. Support `resources` per action in the spec and set the option for `ec2:RunInstances`.
- Context: when a result has `MissingContextValues`, optionally call `iam:GetContextKeysForPrincipalPolicy` so the warn text lists the keys the policy really uses. Add the action to the reader policy as optional.
- Principal resolution gaps beyond SSO:
  - `arn:aws:sts::acct:federated-user/name` and root cannot be simulated. Return `unknown` with a reason, not an error.
  - IAM Identity Center role paths are `/aws-reserved/sso.amazonaws.com/` and, outside us-east-1, include a region segment (`/aws-reserved/sso.amazonaws.com/eu-west-1/`). Never build the path by hand; use `Role.Arn` from `iam:GetRole`. Add the regional-path case to the fixture.
  - `iam:GetRole` is often denied to SSO users. Then try `arn:aws:iam::{acct}:role/{NAME}` once (works for roles with no path), else use the dry-run path or return `unknown`.
  - Instance-profile and IRSA sessions resolve as `assumed-role` and work the same way.
- Treat `AllowedByOrganizations = false` as an SCP block even when `EvalDecision` is `implicitDeny`. Keep the catalog rule that denial plus missing context is a warn.
- SCP fix text: members cannot read SCPs. Say what the admin must do ("allow `{action}` for account `{a}` in the SCPs that apply").
- Policy fix text: `"Resource":"*"` is a poor default for actions that take resources. Print a resource-scoped example when the spec gave `resources`.
- Budget: 20 calls is fine for 1000 actions at 50 per call, but 30s can fail in slow regions with SDK retries. Set an explicit per-call timeout and `RetryConfig::standard()` with 3 attempts, and report which batches finished.

### S5. EC2 dry-run fallback: noise, scope and parameters
- `UnauthorizedOperation` calls are the classic alarm in CIS-style CloudWatch alerting on unauthorized API calls and can reach a SOC. `SimulatePrincipalPolicy` denials are not logged that way. Default `probe: auto` should try simulate first, and the report must say when it falls back: "this run made N DryRun calls; AWS logs them as errors in CloudTrail". Consider making the fallback opt-in (`probe: dry_run`) and list it under "Decisions needing an ADR".
- A dry run tests only the calling principal. It cannot honour `principal:` for another role. Reject that combination at lint time.
- Placeholder parameters are not neutral. EC2 can return validation errors (`InvalidAMIID.NotFound`, `InvalidParameterValue`) instead of the authorization result, and resource-level conditions depend on real subnet, AMI and tag values. Treat any error other than `DryRunOperation` and `UnauthorizedOperation` as `unknown`, never as pass.
- Some EC2 actions have no `DryRun` parameter. Ship an explicit table (action to operation and minimal parameters) as `ec2_dryrun.toml` in Appendix B, with `source` and `checked_on`. Today only `aws_quotas.toml` is listed.
- The plan's example (`eks:DescribeCluster`) has no dry-run path. Say "non-EC2 actions are `unknown` when simulate is denied", and offer an optional real read call for `Describe*` and `List*` actions (`probe: call`), since such a call is already read-only.

### S6. Credential sources: what the common fields do not say
- Env, profile, SSO, container, instance role and web identity are named. Missing:
  - Precedence trap: static `AWS_ACCESS_KEY_ID` in the environment beats `AWS_PROFILE`. The "no credentials" fix suggests exporting `AWS_PROFILE`, which does nothing if stale keys are exported. Report which source won and warn when both are set.
  - Expired SSO session: the SDK returns a provider error, not "not found". Map it to "SSO session expired, run `aws sso login --profile {p}`" and keep the generic text for the truly-empty case.
  - Resolution time: on a laptop with no credentials, the IMDS probe retries. Bound the whole chain (suggest 5s) and add a spec field or flag `imds: false`. Keep the chain inside the 10s of `aws.identity`.
  - Region: if neither the spec nor the config gives one, return `skipped: "no region"` with a fix, not an SDK error string.
  - SDK `tracing` output can contain profile names and `sso_start_url`, which identify the customer. Keep SDK log targets off unless `RUST_LOG` asks.
  - MFA-gated or `SourceIdentity`-requiring trust policies are not supported by `assume`. Say so, or add `mfa_serial` and `source_identity` fields.

### S7. "Explains exactly which API it called" is not met by the current text
- Section 5 says the `AssumeRole` call shows up in CloudTrail. Every call shows up: AWS logs read-only management calls too. A customer's security team will see tens to hundreds of events from the principal. Say that up front for all calls.
- Fix:
  - Evidence for every `aws.*` result lists each call: service, operation, region, selected non-secret parameters (batch size, counts, never `ExternalId` or credentials), HTTP status, error code, and the AWS request id (`x-amzn-requestid`). The request id lets the customer find that exact event in CloudTrail. Put it in the action log (SEC-17).
  - Set the SDK app name to `rdy/<version>` so the user agent identifies the tool in CloudTrail. Print a filter hint in the report: user agent contains `rdy/` and the run's time range.
  - Each check's "Source" line becomes its single list of allowed operations, and SEC-48 tests against it.
  - Wording: "never write" should read "makes no change to any resource". `AssumeRole` creates a session and an event. `SimulatePrincipalPolicy` and DryRun change nothing but are logged. Auditors will read this closely.

### S8. Fixtures are not enough as listed
- The layout in section 1 (`api/` recorded JSON or XML) does not say how multi-call sequences are matched. The SDK static replay client matches an ordered list of request and response pairs. Define the file shape: `api/001-iam-GetRole.json` with `{operation, expect_request: {body_subset}, status, headers_subset, body}`, ordered per case.
- Missing cases:
  - Pagination: `IsTruncated` and `Marker` for simulate; `NextToken` for offerings and subnets; a second page of `ListServiceQuotas`.
  - `AccessDenied` on each non-simulate call (the degrade rule: partial with the action named). The catalog lists it only for simulate.
  - Throttling (`Throttling`, `TooManyRequestsException`) with a retry that succeeds, and one that exhausts the budget.
  - Expired SSO token; IMDS timeout; static env keys overriding a profile; a profile with `credential_process` (expect `skipped`).
  - `AssumeRole` denied (trust mismatch) and allowed with ExternalId; the trust-policy cases from M2.
  - Subnet with no explicit route association (main table), blackhole route, NAT gateway `pending`.
  - Opt-in region not enabled; `ParameterNotFound` in a supported region; SSM unsupported region; SCP region deny.
  - `aws-cn` partition ARN (expect `skipped`).
- Time: tests need a controlled clock (SDK `TimeSource`) and a fake sleep, or retries make tests slow and flaky.
- Secrets: recorded requests carry `Authorization` and `X-Amz-Security-Token`. The recorder must drop them. Add a golden test that scans all `api/` files for `AKIA` and `ASIA` patterns that are not the `EXAMPLE` values.
- The static replay client now lives in `aws-smithy-http-client` (`test-util` feature), not in `aws-smithy-runtime`. If the facade adapter (M4) is built, fixtures replay at the facade and this concern shrinks.

### S9. Reader policy: gaps and one note
- Add, as the fixes above need: `iam:GetContextKeysForPrincipalPolicy` (optional), `ssm:GetParametersByPath` (same ARN pattern), `servicequotas:ListRequestedServiceQuotaChangeHistoryByQuota`, `ec2:DescribeAddresses`, `ec2:DescribeSecurityGroups`, `eks:ListClusters`. Keep `sts:AssumeRole` out of the reader policy: it is a grant on the operator, scoped to the role in the spec.
- `cloudwatch:GetMetricData` has no resource-level support, so its `Resource` is `*`. Say it in the published policy to stop a reviewer asking.
- The `ssm:GetParameter` ARN `arn:aws:ssm:*::parameter/aws/service/global-infrastructure/*` is correct (public parameters have an empty account field). In `aws-cn` and `aws-us-gov` the partition prefix differs.
- Publish the policy as JSON in the docs, with a CloudFormation or Terraform snippet that creates a role named `rdy-reader` trusting the operator's own principal. This is what makes "least privilege" credible to the customer's cloud team.
- Each check's Needs line should list exact action names. Some say `ec2:Describe*`; a wildcard hides the audit list.

### S10. Cost of the AWS SDK in the binary and in CI
- `aws-sdk-ec2` 1.271 is 87 MB of source in the registry. The catalog needs ec2, iam, sts, servicequotas, cloudwatch, eks, ssm, sso, ssooidc, and later s3. That compiles slowly with high RAM, on five CI targets, and grows the binary by tens of MB.
- Fix: put `rdy-checks-cloud` and `store.s3` behind a cargo feature `cloud` that is on in release builds. Measure in the M2 spike: clean build time per target, stripped size, peak RAM on a 7 GB CI runner. If `aws-sdk-ec2` is too heavy, the alternative is `aws-sigv4` signing plus a hand-written client for the ten EC2 query operations used (XML through `quick-xml`). Decide on numbers.
- The "AWS common" ticket at 5h is too low. It holds the credential chain, `assume`, the replay harness, the ring client, proxy and roots, the facade adapter, source detection and degrade rules. Estimate 10 to 12h, or split the adapter into its own ticket (done below).

### S11. `gcp.*` and `azure.*` reserved ids: facts and shape
- Spec shape: the common fields (`region`, `profile`, `account`, `assume`) are AWS-shaped, but the table promises "the spec shape stays stable". Reserve now: GCP `project`, `region`, `impersonate_service_account`; Azure `tenant`, `subscription`, `location`, `resource_group`. Make `assume` provider-neutral or document that each provider has its own. Use one list key across providers for "things to check" (`simulate` in AWS; reserve `permissions` for GCP and `actions` for Azure as aliases).
- `gcp.iam`: `projects.testIamPermissions` tests the caller only. For another principal (a vendor service account) the options are impersonation (`generateAccessToken`, needs `iam.serviceAccounts.getAccessToken`) or the Policy Troubleshooter API. State which. The claim "up to 100 permissions per call": I could not find it in Google's documentation (the only 100 I found is a page size on `QueryTestablePermissions`). Mark it unverified; batching in groups of 100 is harmless. Organization policy constraints and VPC Service Controls are not covered; say so.
- `gcp.quota`: `compute.regions.get` quotas (metric, limit, usage) is right for Compute. For other services, the Cloud Quotas API (`quotaInfos`, read-only, `dimensionsInfo.quotaValue`) is the supported route; do not make the older Service Usage `consumerQuotaMetrics` the only source. Cloud Quotas shows no usage, so usage comes from Cloud Monitoring (`monitoring.timeSeries.list`) or the service API.
- `gcp.apis`: `services:batchGet` is right. I believe it takes up to 20 service names per call; confirm when building.
- `azure.rbac`: the `Permissions - List` operations in api-version 2022-04-01 are for a resource group (`/subscriptions/{id}/resourcegroups/{rg}/providers/Microsoft.Authorization/permissions`) and for a resource. I found no subscription-scope operation, but the catalog writes `{scope}`. Restrict the check to a resource group or resource, or use role assignments plus role definitions for subscription scope (needs `Microsoft.Authorization/roleAssignments/read`). The API returns the caller's `actions`, `notActions`, `dataActions`, `notDataActions`; apply wildcard matching and `notActions` subtraction per entry, then union the entries.
- `azure.quota` and `azure.providers`: the calls are right. Missing are region and SKU availability: `Microsoft.Compute/skus` with `restrictions` (for example `NotAvailableForSubscription`), and for GCP zone and machine type availability (`zones.list`, `machineTypes.aggregatedList`). Reserve `gcp.region` and `azure.region`.
- Azure Policy (deny effects) and GCP organization policy are the equivalent of SCPs. Say they are not covered at launch.
- Credentials for M5: do not shell out to `az` or `gcloud` (INV-07). Use env service principals and workload identity, managed identity (IMDS), and GCP ADC files. Azure CLI token caches can be encrypted on macOS and Windows, so "use my `az login`" may not work without the CLI. Record that in an ADR before M5. Check that any official GCP or Azure Rust crate builds ring-only; if not, use plain REST with the shared client (the catalog already leans this way).
- Tickets: the M5 GCP and Azure tickets depend on "AWS common: credential chain". They cannot reuse it. Depend on a provider-neutral cloud session ticket instead (below).

### S12. Ordering and sharing between cloud checks
- "`aws.identity` runs first in practice (the others use its result)" is a hidden dependency the engine does not model. Use the lazy `AwsSession` from M7.1. Each check also writes the caller identity it used into its own evidence, so one result file is self-contained.
- The ticket `aws.eks` depends on `aws.vpc`, but `aws.eks` reads cluster subnets from `DescribeCluster`. Remove the dependency or explain it. If both need `DescribeSubnets`, cache the call in the session.

## Nit

- N1. `aws.quota` fix text: also give the console path (Service Quotas, AWS services, EC2) for customers without the CLI, and warn that GPU families may need manual review.
- N2. `aws.identity`: "Root user: warn" is right. Add "do not run `rdy` as root; create a reader role" and link the reader policy.
- N3. `aws.identity` fix text: "`aws sts get-caller-identity` shows the same answer" holds only in the same shell with the same profile and environment. Say "run it in the same shell".
- N4. Common field `account`: 12 digits, a string. A leading zero is legal; YAML may parse it as a number. Add a check to `rdy spec lint`.
- N5. Section 5 intro lists "container and instance credentials, web identity". After M3, add "process credentials are off" so docs and code agree.
- N6. `aws.region` fix: the console path wording ("Account settings, AWS Regions") may be out of date. Check against the console when the docs are written.
- N7. Appendix B: add `ec2_dryrun.toml` (S5), with `source`, `checked_on` and one unit test per row.
- N8. `aws.imds` is reserved "after `aws.eks`" and needs `ec2:DescribeInstances`, not in the reader policy. Note it when built. The hop limit is also visible in launch templates (`ec2:DescribeLaunchTemplateVersions`), so consider folding it into `aws.eks` instead of a seventh check.

## What the M1 engine must keep open (for rust-architect)

1. `Context` and `Finding` as `#[non_exhaustive]` with builders; a typed extension slot on `Context`.
2. An `Http` trait on the probe facade (`http::Request` in, `http::Response` out) with proxy, roots, allow-list and action log built in. Adapters for reqwest (net) and the AWS SDK (cloud) sit on top.
3. `Need::Credentials(Provider)` and `Need::Consent(&'static str)`; skipped reasons that carry the missing need.
4. `partial { missing: Vec<String> }` and `evidence: Vec<ApiCall>` (with request ids) in the result schema.
5. A rule for `require: true` (skipped becomes block), applied by the engine.
6. An `identifier` evidence class (account ids, ARNs) for redaction and upload consent.
7. An SEC-21 exemption for the SDK credential providers (IMDS, container credentials).
8. The deny list stays: `aws-lc-sys`, `openssl-sys`, `native-tls`. Add `cargo tree -i aws-lc-sys` to CI.

## Plan corrections found

- `docs/plan/03-check-catalog.md`, section 5 intro, "`rdy` calls `sts:AssumeRole`": the consent rule recorded under "Decisions needing an ADR" is missing from the check text. Fix: M1.
- `docs/plan/03-check-catalog.md`, section 5 intro, "The `AssumeRole` call shows up in CloudTrail": every API call shows up. Fix: S7.
- `docs/plan/03-check-catalog.md`, `aws.region` Source: the SSM path is not in the AWS guide, and queries work from only 17 listed regions. Fix: M5.
- `docs/adr/0009-http-client-and-tls.md`, Consequences "M3 risk": resolved on paper. The AWS SDK can run on ring with the feature set in M3 above. Amend the ADR to record the feature set, the shared `ProxyConfig` and trust store for AWS clients, and that `credentials-process` is off. The M2 spike ticket changes scope to "full workspace graph, musl build, size and time numbers".
- `docs/plan/00-overview.md`, engine API sketch: no HTTP injection, no cloud need, no partial result, public-field `Context`. Fix: M7.
- `docs/adr/0008-errors-and-result-model.md`: no `partial` and no evidence; `require: true` conflicts with "skipped lowers to Warnings". Fix: M7.4 and M7.5.
- `docs/plan/05-threat-model.md`, SEC-21 and SEC-17: SEC-21 must exempt the SDK credential providers, and the SEC-17 action log must include SDK calls through the `Http` trait. Fix: M4.
- `docs/plan/03-check-catalog.md`, tickets: "AWS common" at 5h is low (S10); GCP and Azure tickets depend on the AWS credential chain (S11).

## Decisions needing an ADR

- Allow `credential_process` profiles or not. Conservative: not allowed (feature off, `skipped` with an export hint). Alternative: allowed behind a flag, listed in Appendix A.
- Dry-run fallback in `aws.iam`: opt-in (`probe: dry_run`) or automatic with a notice. Conservative: opt-in, because dry-run denials are logged as errors.
- Vendor-role checking: read-only trust inspection plus simulation as the primary path, `assume` only when the operator is trusted. Alternative: `assume` as the primary path (fails on standard BYOC trust).
- AWS SDK crates versus a thin SigV4 client for EC2, decided on build time, size and RAM numbers from the M2 spike.

## Tickets implied

- [M1] Add `Http` trait, `Need::Credentials`, `Need::Consent` and a non-exhaustive `Context` with extension slot to the engine design | owner: rust-architect | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: a stub cloud family in a test crate gets an HTTP client, a consent flag and a typed session from `Context` without changing `rdy-engine`.
- [M1] Add `partial` and `evidence` (API call list with request id) to the result schema | owner: rust-architect | est: 2h | depends on: Define public spec types in rdy-spec | exit test: a golden result with a partial finding and two API calls round-trips through JSON and the schema.
- [M2] Verify the AWS SDK runs on rustls with ring: full graph, musl, size and time | owner: cloud-iam-expert | est: 4h | depends on: none | exit test: `cargo tree -i aws-lc-sys` fails to match on the full workspace (reqwest, kube, SDK crates), both musl targets build, and clean build time, stripped size and peak RAM are written into ADR 0009.
- [M3] AWS HTTP adapter over the facade (`FacadeHttpClient`) sharing proxy and roots with `net` | owner: rust-engineer | est: 5h | depends on: Shared HTTP client builder with rustls ring, dual roots and proxy env | exit test: with a local CONNECT proxy, an SDK call succeeds only through the proxy and appears in the action log with its request id.
- [M3] AWS common, resized: credential chain without `credential_process`, source detection, session cache, `assume` with consent and the `RDY_` external-id rule, replay harness | owner: check-author | est: 10h | depends on: AWS HTTP adapter over the facade | exit test: a no-credentials run skips every `aws.*`; a spec naming `AWS_SECRET_ACCESS_KEY` as external id is refused; the assume fixture runs only with `--allow-assume-role`.
- [M3] aws.iam trust-policy inspection for vendor roles (`GetRole` plus `trust:` block) | owner: check-author | est: 3h | depends on: aws.iam (simulate, role ARN resolution, EC2 dry-run fallback) | exit test: fixtures for a correct vendor trust policy, a missing ExternalId condition and a wildcard principal classify as pass, block and block.
- [M3] aws.region: documented SSM paths, supported-region routing, unknown-not-block | owner: check-author | est: 2h | depends on: aws.region | exit test: fixtures for a supported region, an unsupported region and an SCP region deny give pass, pass and unknown.
- [M3] aws.quota: usage from `UsageMetric`, API-count fallback, pending request detection, `service_code` per row | owner: check-author | est: 3h | depends on: aws.quota with `aws_quotas.toml` | exit test: a quota without `UsageMetric` still reports usage from a Describe count; a pending request changes the fix text.
- [M3] Publish the reader policy as JSON plus a CloudFormation snippet, tested against the action list | owner: docs-writer | est: 2h | depends on: aws.eks | exit test: a test compares every operation the cloud checks can call (the SEC-48 list) with the policy actions and fails on any difference.
- [M5] Provider-neutral cloud session before GCP and Azure checks | owner: cloud-iam-expert | est: 4h | depends on: AWS common, resized: credential chain without `credential_process`, source detection, session cache, `assume` with consent and the `RDY_` external-id rule, replay harness | exit test: GCP and Azure stubs use the same `Http`, action log and degrade rules with no AWS types.
