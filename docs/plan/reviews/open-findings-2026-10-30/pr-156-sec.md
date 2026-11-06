# PR #156 (M1-063) security review, 0893d77

Verdict: changes required (small). Goldens are exact and write-protected. 24/24 pass in a scratch copy. No fixture holds a whole real-looking secret (only the approved `AKIAIOSFODNN7EXAMPLE`; the JWT, PEM and AWS example secret are split).

SEC-156-1 high. `redaction_corpus.rs:49-72` `CLAIMS` is a hand subset of 04 Appendix B. 04 section 4 says every M1 form Appendix B claims is gated. The engine handles these today, but no case pins them, so a regression passes 0.1.0: STS `SecretAccessKey` (session-json lacks it), `aws_session_token` INI, `x-amz-security-token`, `X-Auth-Token`, `-H 'Authorization: ...'`, bare `Bearer`, systemd `Environment=` (M1-098), kubeconfig `password`/`client-secret`/`id-token`/`refresh-token`/`access-token`, PEM with no END (05 I1), `ABIA`/`ACCA`. Fix: add these forms to `CLAIMS` and add one positive case for each, about 10 cases. All of them pass now.

SEC-156-2 medium. `:449-459` matches whole secrets only, so a surviving prefix or suffix passes this oracle. Only the hand-blessed golden catches it, but the README calls this oracle the check that "catches a wrongly blessed file". Fix: (a) a fragment oracle: no window of min(len,6) characters of a secret may survive once placeholders are stripped; (b) rename the `synthetic.toml:14,30` canaries. My window probe hit only these, via the context words `Bearer`, `client` and `secret`. (c) Optional `spans`: each tag must equal HMAC-SHA256(`[9;32]`, span)[..4], proving exact spans.

SEC-156-3 high (fails safe). `negative/key-value-from` proves nothing. `redact/` has no valueFrom or secretKeyRef exclusion. The case passes only because no stem key there has an inline value. `DB_PASSWORD:\n  valueFrom:\n    secretKeyRef: ...` comes out as one placeholder. Fix: remove `value_from` from `EXCLUSIONS` (`:85`) and list it as not claimed, with a redactor ticket. Also add a mutation guard: swap a canary into each excluded value, or drop the key suffix, and the key rule must fire.

SEC-156-4 medium. The not-claimed lists (README, harness `:29-32`) leave out M1-060 deferrals. One is a leak: `- name: DB_PASSWORD\n  value: hunter9` and `{"name":"DB_PASSWORD","value":"x"}` come out unchanged from `redact_str`. Also missing: `-pPASS`, `app:1234/x@db`, SSH2 keys, crafted BEGIN. Not in any stem: `MYSQL_PWD=`, `pwd=`. Fix: copy M1-060's deferred list and add the `PWD` ticket.

SEC-156-5 low. `normalized` (`:150-153`) maps every tag to `~`, so tag equality is never pinned (04 3.3). Fix: per-file ordinals (`~1`, `~2`), plus one case with the same password in a URL and an env var.

SEC-156-6 low. The stem negatives only cover `passed` and `author`. `max_tokens: 4096`, `secretary: bob` and `compass: north` get redacted. Fix: M2-061 negatives.

SEC-156-7 nit. 12-progress says `PR #TBD`, so set it to #156. The changelog says "every build", so make it "every CI test run".

Exit test: partly proven. Survivor, rule-fired, FLOOR and the gate self-tests hold. "Fails on a syntax form with no positive case" holds only for `CLAIMS` (1). One exclusion is vacuous (3).
