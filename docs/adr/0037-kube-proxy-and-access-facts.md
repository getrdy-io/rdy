# ADR 0037: The kube client uses an `http://` proxy the way kubectl does, and k8s.access reads the attempt, not a connected cluster

- Status: Accepted, security-reviewed (PR #130). It touches the network path and credentials.
- Date: 2026-10-30

## Context

ADR 0031 decision 6 refused a cluster `proxy-url` and kept kube away from `HTTPS_PROXY`, and said "proxy
support is M1-109, with its own feature decision". `kubectl` honours both, so `kubectl` can work while `rdy`
times out. 03 `k8s.access` says the check resolves the proxy as `net.proxy` does and reports which rule applied.

Reading kube 4.2.0 (the pinned version) for that decision:

- The `http-proxy` feature is `hyper-util/client-proxy`. It adds no crate to the lock that is not there
  already (`base64`, `ipnet`, `percent-encoding`). The `socks5` feature is the same dependency.
- An `https://` proxy is checked with the cluster's TLS settings (its CA), not with the proxy's own
  certificate. A corporate proxy would fail with an unknown issuer that has nothing to do with the cluster.
- The `Proxy-Authorization` header is built from the user info of the proxy URL as it stands, cut at the
  first `@`. It is not percent-decoded, and an `@` in the text ends the user info early.
- Only the scheme `socks5` exists. `socks5h`, which `kubectl` also takes, is refused by kube.

## Decision

1. **Feature.** `kube` gets `http-proxy`. `socks5` stays off.
2. **Only `http://`, judged by the facade's parser.** The proxy is a `CONNECT` tunnel. The text goes
   through `rdy_engine::probe::ProxyUrl::parse` (M1-091), so what is a usable proxy is decided once for
   every check: `https://`, `socks5://`, `socks5h://`, any other scheme, a path or query, a bad host or port
   and a bad user name are refused as `KubeError::ProxyUnsupported`. The error names where the value came
   from (the kubeconfig `proxy-url` or the variable) and shows the proxy as scheme, host and port. The hint
   says which of the two to change. `https://` and `socks5://` are follow-ups if a design partner needs
   them.
3. **Order, as `kubectl`.** (a) The chosen cluster's `proxy-url`. It applies whatever `NO_PROXY` says.
   (b) `HTTPS_PROXY`, else `https_proxy`, for an `https` API server, unless `NO_PROXY` (else `no_proxy`)
   covers the API host or the host is `localhost` or a loopback address. `HTTP_PROXY` is not read, and an
   `http` API server never uses an environment proxy (Go would read `HTTP_PROXY` for it; rdy does not
   support that case). (c) No proxy. Either value is trimmed once. A value without a scheme is read as
   `http://`, from either origin, and the scheme is read in any case (`HTTP://`), as Go does. A cluster
   `proxy-url` for an API server that is not `https` is refused (`KubeError::ProxyPlainServer`): kube
   tunnels to port 443 when the server URL names none, and the token would cross the proxy in clear text.
4. **`NO_PROXY` is Go's `httpproxy` rule.** A name matches itself and its subdomains, a leading dot or `*.`
   matches subdomains only, `host:port` limits an entry to a port, an IP matches itself, a CIDR matches
   addresses, `*` matches all, entries are case-insensitive and empty entries are skipped. A proxy variable
   that `NO_PROXY` exempts is not parsed, so a stale value cannot fail a run that does not use it.
5. **kube still never reads the environment.** The placeholder of ADR 0031 decision 6 stays. After the
   build, `client::proxy::resolve` writes the chosen proxy to the config. The function is pure, and its
   tests pin each rule.
6. **User info is decoded as the facade decodes it, and every form is a known secret.** The facade
   percent-decodes the user name and password, as Go does. kube does not, so the decoded text goes into the
   URL kube gets, and its header carries the same password the facade would send. kube cuts the user info
   at the first `@`, so a decoded `@` is refused (`KubeError::ProxyUserInfo`) rather than sent wrong, and so
   is a decoded `/`, `?`, `#` or a character a URL cannot hold, because the authority would end early and
   could name another host (the URL must read back exactly as built). The secrets are the facade's own
   list, `ProxyUrl::secrets` (public since this PR): the password as written and decoded, the base64 of
   `user:password` that kube sends as `Proxy-Authorization`, and for a user with no password the user name
   and the base64 of `user:` when it is at least `KNOWN_SECRET_MIN_LEN` long. The whole user info, as
   written and as decoded, is added under the same length rule. They join `Loaded::known_secrets()` (the
   caller registers them before anything is printed, ADR 0015 decision 3). A secret the set refuses is
   fatal, as for every other known secret: the run exits 70 (M1-107). The user info is never in an error,
   a log line, `Debug` output or a report: `Env` and `Resolved` hide it in `Debug`, the route is shown as
   `scheme://host:port`, and for a URL that was refused (nothing is registered yet) the display drops
   everything up to the last `@` before it cuts at `/`, `?` or `#`, so a raw `/`, `?` or `#` in the
   password cannot show.
7. **The route is reported.** `ConnectionFacts` (kinds of credential, the proxy route, the CA state, the
   source and the cluster line) is taken from `Loaded` before `connect`, so a failed connection can still
   say which rule applied. A network error carries `proxied`, and the hint then says to check that the
   proxy allows `CONNECT` to the API host and port. Two causes get their own phrase: the proxy answered 407,
   and the proxy refused the tunnel. Every `kube` entry of the action log records `via_proxy`, the proxy
   origin with no user info, or `null` for a direct request, so the proxy hop is in the log (INV-07), and
   every k8s check that talks to the API server declares `PeerClass::Proxy`. A credential plugin that
   asks for the cluster (`provideClusterInfo`) is given the cluster's own `proxy-url`, as `kubectl` does,
   never the placeholder of decision 5.
8. **Credential end dates are read at load, with no request.** A static token that is a JWT: its `exp`
   claim, nothing else. A client certificate: `notAfter`, read by a small bounded DER walk in `client`,
   because a check crate may not depend on an X.509 crate (`ci/check-crate-deps.toml`). An exec plugin and
   the pod's service account have no expiry to warn about. Times are counted from `Env::now_unix`, so tests
   pin them.
9. **`k8s.access` reads the attempt (`Dial`), not a connected cluster.** Every other k8s check needs
   `kube_context` and is skipped when the attempt failed. `k8s.access` says why it failed, so its input is
   the facts, how the attempt ended (reached, failed, timed out, no network) and, when it reached, a
   read-only client. The family probe (M1-107) makes the attempt once per run, whenever the plan holds any
   k8s check (a spec with only `k8s.access` included), and wraps it in `Dialed`. The check is built with
   a `Dial` that is filled before it runs and is read only after that attempt. `Dialed::connected()`
   gives the same connection to the other checks, so one holder serves both.
   `Connected` gained `version_latency()`, the time of `GET /version` with the plugin's time left out (the
   plugin runs when the client is built).

## Consequences

- `ProxyUnsupported` lost its "does not use a proxy yet" wording, and `proxy_env_set` became `proxied` on
  `Timeout` and `Unreachable`. `Env` lost `proxy_env_set` and gained `https_proxy`, `no_proxy` and
  `now_unix`. A malformed `HTTPS_PROXY` that applies now fails the load with an error that names the
  variable (it was ignored before).
- Proven on the real client stack: a `CONNECT` tunnel carries a TLS session for `proxy-url` and for
  `HTTPS_PROXY`, the Basic header carries the user info, a 403, 407 and 502 from the proxy and a dead
  proxy map to their own causes. `tests/tls.rs`.
- A proxy password that contains `@` once decoded cannot be sent through kube and is refused with its own
  hint. The facade (`net.*` checks) can send it. It is a known limit of kube 4.2.0.
- With `insecure-skip-tls-verify: true` and a proxy in the path, the proxy can read the bearer token,
  because rdy cannot tell the proxy from the API server behind it (SEC-130-7). The `k8s.access` warning
  says so, and the fix is to give the cluster its CA.
- A credential whose end date has passed does not block when the server answered anything but 401: the
  server accepting it means this machine's clock is wrong, which is a warning.
- DNS for the API host happens at the proxy, as with `kubectl`. `net.proxy` (M1-098) and `net.egress`
  (M1-097) build their own CONNECT through the probe facade; the two share the rule text, not code.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Leave `HTTPS_PROXY` ignored, only honour `proxy-url` | `kubectl` works and `rdy` times out, the failure 03 names. |
| Let kube read the environment | It fails the whole load on a malformed value, and it ignores `NO_PROXY`. |
| Enable `socks5` and `https://` proxies now | The first has no test here and the second is verified against the wrong CA (see Context). |
| An X.509 crate for `notAfter` | Only `rdy-checks-net` may depend on one (`ci/check-crate-deps.toml`). One field does not need it. |
| `k8s.access` takes the connected `Cluster` handle | It exists only on success, so the check could not report a failure. |
