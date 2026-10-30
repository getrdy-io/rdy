# ADR 0031: The kube client layer reads the kubeconfig itself, announces first, and keeps plugin output out of every error

- Status: Accepted, security-reviewed (PR #76). Revised 2026-10-29 after the security-reviewer, k8s-expert and code-reviewer reviews of PR #76; the security-reviewer signed it off on re-review, because it touches credentials, plugins and the network.
- Date: 2026-10-29

## Context

ADR 0010 chooses kube-rs behind a read-only guard and names the exec plugin exception. M1-102 builds the
client layer under it. Reading kube 4.2.0 (the pinned version) showed things the ADR text does not say:

- `Config::infer` and `Client::try_default` call `apply_debug_overrides`, which honours
  `KUBE_RS_DEBUG_OVERRIDE_URL` and `KUBE_RS_DEBUG_IMPERSONATE_USER`. They can swap the server or the
  identity.
- kube's `AuthExecRun` error formats the plugin's whole stdout and stderr with `{:?}`, and a YAML parse
  error can quote the kubeconfig line that holds a token.
- The `gcp` auth-provider runs a `cmd-path` command that the report would not name.
- `Config::try_from(Kubeconfig)` reads `HTTPS_PROXY` on its own, whatever the features, and fails on a
  value that is not a URI.
- A plugin whose `interactiveMode` is unset or `IfAvailable` is run as interactive even with no terminal:
  kube inherits stdin and stderr and sets `interactive: true`. client-go only prompts when a terminal is
  there.
- With no CA in the kubeconfig, kube defers to `rustls-platform-verifier`, which on macOS and Windows can
  fetch AIA and OCSP data on its own. ADR 0014 decision 3 bans that.
- kube reads the CA, client certificate, client key and token files with no check of the file type or size.

The probe facade denies reads under `.kube` (02, file deny list; PR #58 review F7), so the engine's own
kubeconfig read needed a settled path.

## Decision

1. **Features.** `kube` with `client`, `rustls-tls`, `ring` and `webpki-roots` (ADR 0010 listed the first
   two; without a provider feature rustls has none, and `cargo deny` bans `aws-lc-rs`; the last is decision
   9). `k8s-openapi` `=0.28.0` with `v1_36`, because kube 4.2.0 depends on 0.28. Both pinned in the
   workspace with `=`; they move together.
2. **The kubeconfig is read by the client module, not through a Probe.** `rdy_checks_k8s::client::load`
   reads `--kubeconfig`, else `KUBECONFIG` (files that do not exist are skipped, first file wins), else
   `~/.kube/config`, else the in-cluster config. A path the operator chose, never one from a spec or the
   working directory. `load` is async and runs its file work on the blocking pool, so the scheduler's timer
   around the probe (M1-107) can bound it. The probe's `.kube` deny stays for checks.
   - **Every file read is checked and listed.** The kubeconfig must be a regular file of at most 8 MiB. The
     CA, client certificate, client key and token file that the chosen cluster and user name (only the ones
     kube reads: inline data wins over a path, an inline token wins over a token file) must be regular files
     of at most 1 MiB. For the in-cluster config the service account token, `ca.crt` and namespace file get
     the same check. A FIFO would block and `/dev/zero` would fill memory. `Loaded::files()` lists all of
     them, in read order, so the probe hook (M1-107) logs one `read` entry each, with no check id (SEC-22).
     A check and the later read are two steps, so a file swapped in between is not caught. The operator
     owns these files. Two residuals: kube re-reads a token file about once a minute (`TokenFile::token`,
     a synchronous read on a worker; this covers the kubeconfig `tokenFile` too, `auth/mod.rs` line 339 of
     kube-client 4.2.0, not only the pod's) and the pod's `ca.crt` about once a minute (`ReloadingVerifier`),
     and neither re-read has rdy's type or size check. The pod's files sit in its own projected volume; a kubeconfig `tokenFile` is a path the operator chose.
3. **No `infer`, no `try_default`.** The client module builds a `Config` from the `Kubeconfig` it read
   and never calls `apply_debug_overrides`.
4. **Announce, then send.** `Loaded::connect(announce)` calls `announce` with the cluster line before it
   starts a plugin or opens a socket. The line is context, server (no user info) and the kubeconfig user
   name, plus the plugin file name and "TLS verification is OFF" when they apply. The authenticated
   identity comes later, from `SelfSubjectReview` (M1-103, M1-109). 07 gets `user <name>` in the line.
5. **Errors hold no kube text.** Each kube error maps to a `KubeError` variant with fixed words, a status
   code, an exit code or an `io::ErrorKind`. Plugin output, plugin arguments and parse text never enter an
   error, a log line or `Debug`. The cause of a network failure (`Unreachable`) is one of a fixed set of
   phrases chosen from the error kind and from words in the chain. Nothing is copied from the chain. Tests
   feed canaries through stdout, stderr and a failing refresh, with every tracing level on and no cap, and
   the capture also takes the records of the `log` crate (rustls logs through it). Texts that come from a
   kubeconfig or a server pass through the one shared escaper, `rdy_engine::text::escape_untrusted`, the
   same function the command line uses.
6. **Refusals and the proxy.** A cluster with `proxy-url` is refused, and the error and hint name the proxy
   as scheme, host and port, never user info, path or query. The hint says not to edit a working
   kubeconfig: run from a host that reaches the API directly, or pass a copy without `proxy-url` with
   `--kubeconfig`. A user entry with `auth-provider` is refused with a hint for its provider: `gcp` points
   at `gke-gcloud-auth-plugin`, `azure` at `kubelogin convert-kubeconfig -l azurecli`, `oidc` says rdy does not run it
   yet and to use an exec plugin for the identity provider, and any other says the same in general words.
   The `oidc` hint makes no claim about kubectl, which still ships that provider. **`HTTPS_PROXY` is never
   read by kube.** kube parses it inside `Config::try_from` and a malformed value fails the load, so a fixed
   valid placeholder takes the `proxy_url` slot of the chosen cluster before the build, and the slot is
   cleared after it. The cluster is contacted directly. When the variable is set, a timeout or unreachable
   error adds "HTTPS_PROXY is set; rdy does not use it for the cluster yet", because kubectl would use it.
   Proxy support is M1-109, with its own feature decision. **Amended by ADR 0037**: a proxy-url is no longer refused, and rdy picks the proxy itself the way kubectl does; kube still never reads the variable. Proved in a child process that is started with
   a malformed value.
7. **Limits.** The connect, read and write timeouts are the check timeout, at most 60 s. Retries are off.
   The build runs on the blocking pool, so a plugin never holds a worker. A plugin that waits for a login
   is bounded by the scheduler's timer (M1-107), and **its process is not killed**: kube starts it with
   `Command::output` on a blocking thread, and rdy cannot reach that child. This is a documented residual
   (03 `k8s.access` says the same; M1-107 proves that rdy still exits promptly with a plugin waiting). A
   token refresh later in the run runs the plugin on `spawn_blocking` inside kube 4.2.0 (`auth/mod.rs`,
   `to_header`), so a stuck refresh costs one blocking thread and one request, never a worker (02).
8. **Plugin streams: only with a terminal.** The kubeconfig's `interactiveMode` stands only when stdin and
   stderr are both terminals (`Env::stdin_is_terminal` and `stderr_is_terminal`, set from the process).
   Then device-code and SSO logins work, and the plugin's stderr goes to the user's terminal, which is a
   residual outside the redactor (the user asked for that login). Without both terminals the mode becomes
   `Never` for an unset value, `IfAvailable` and `Always` alike: stdin is not inherited and stderr is
   captured by kube and dropped, so plugin text cannot reach rdy's stderr past the redactor (INV-15) and no
   login waits for nobody (`rdy --json` in CI, over ssh with no tty, or in a pipe). Proved in a child
   process whose kubeconfig sets no `interactiveMode`.
9. **System roots are the bundled web roots, always.** The `webpki-roots` feature makes kube use the
   bundled Mozilla roots whenever the kubeconfig has no CA, so `rustls-platform-verifier` is never
   reached and no AIA or OCSP fetch happens outside the INV-11 peer set (ADR 0014 decision 3). The
   crate is still in the dependency tree (kube builds it behind `rustls-tls`) and is unreachable. A
   kubeconfig CA, or `ca.crt` in a pod, replaces the roots as before. **This differs from kubectl**,
   which uses the operating system's roots when the kubeconfig has no CA, so a cluster whose API
   certificate chains to a root that only this machine's store has (a corporate root) works in kubectl
   and fails in rdy with an unknown issuer. The error says so: with no CA set, the hint names the
   bundled-roots rule and says to pass a copy of the kubeconfig with `certificate-authority` set. This is a
   deviation from ADR 0014 decision 3 (system roots plus the CA), which equals its `trust: bundled` mode
   for the kube client. Follow-up (filed by the coordinator as a correction or carry): after M1-092, fill
   `root_cert` from the facade's `SystemRoots` when the kubeconfig has no CA, so the kube client uses the
   same store as the rest of rdy. Proved in a child process: a CA that `SSL_CERT_FILE` names is not
   trusted (it discriminates on Linux only).
10. **The plugin's environment.** `RDY_TOKEN`, `RDY_KEY_PASSWORD` and every `RDY_*` variable set in the
    process (an ExternalId variable, for example; matched without regard to case on Windows) are removed from the plugin's environment through
    kube's `drop_env`. Cloud credential variables are not removed: `aws eks get-token` and its kind need
    them, and the operator chose to run that plugin. Proved with a plugin that dumps its environment.
11. **Hand-offs to the probe hook (M1-107).** `Loaded::known_secrets()` returns the inline token, password
    and client key data, the contents of a token file or client key file, and the values of plugin `env` entries whose name the redactor's key-name rule calls secret, or contains `KEY` (at least 8 characters), for the run-scoped known-secret
    set (02, ADR 0015 decision 3). A token that a plugin hands out exists only after `connect` and is not
    in it (the redactor's token rules cover its shape). `Loaded::plugin_exec()` returns the plugin command
    (an absolute path when the kubeconfig gave a path) and escaped arguments, for the `exec` action-log
    entry (02, "The action log"). The arguments can hold a secret and must pass through the redactor.
    A bare command name is not resolved against `PATH` here: M1-107 does that for the entry.
12. **The namespace is not read.** The `namespace` of a context and the service account namespace file are
    not used. A check that needs a namespace takes it from its spec parameter.
13. **In a pod.** Missing or oversized service account files, or an unusable `KUBERNETES_SERVICE_HOST`,
    give `InClusterUnusable` with a hint about the service account mount, not `NoKubeconfig`.
    `Env::from_process` allows the in-cluster config only when `KUBERNETES_SERVICE_HOST` is set.

## Consequences

- M1-103 built the guard (`client/guard.rs`). The unguarded client stays private inside `Connected`.
  `connect(probe, announce)` sends `GET /version` through the guard with the run probe, and
  `Connected::read_only(check_probe)` wraps the raw client in `guarded_service` for one check and returns
  a `ReadOnlyClient`, the only client a check gets. The guard sits outside kube's own layers, so it sees a
  path with no host and no `Authorization` header, and `Impersonate-*` headers from the kubeconfig (added
  below it) are not its to judge.
- `cargo deny` allows `kube` only as a dependency of `rdy-checks-k8s`, and `kube-client` and `kube-core`
  only through kube (`deny.toml`, wrappers).
- The kube lint-wall entries are in `crates/rdy-checks-k8s/clippy.toml`, together with the root entries (a
  crate's file replaces the root file). A bad kube path warns, so `-D warnings` keeps them valid. The use
  file that exercises all 18 entries, the trait routes and both re-export paths is
  `crates/rdy-checks-k8s/lint-wall/kube-use.rs.txt`. It is not compiled by default. M1-107 carries the
  permanent proof from it (backlog correction-11).
- `oidc` auth-provider support is a follow-up if a design partner needs it.
- Which proofs discriminate where: the system-roots test needs Linux (`SSL_CERT_FILE`); the `HTTPS_PROXY`
  child test cannot tell `HTTPS_PROXY` from `https_proxy` on Windows (names are one variable there); the
  plugin canary and environment tests use shell scripts and run on Unix only. The distribution kubeconfig
  paths in hints appear on Linux only (07).
- Carried to M1-107 (correction-12): `.cmd` plugin tests for Windows, and resolving a bare plugin command
  name against `PATH` for the `exec` action-log entry.
- Credential plugin tests that use shell scripts run on Unix only. Windows gets `.cmd` plugin tests in
  M1-107 or M1-108.
- A kube bump needs a manual re-read of 02 Appendix A, of the error mapping in `client/error.rs`, and of
  the three kube behaviours this ADR works around (decisions 6, 8 and 9).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Read the kubeconfig through `Probe` and allow `.kube` | Opens `~/.kube/*` to every check's reads. |
| `Config::infer` | Honours debug variables that can swap the server. |
| Show kube's error text | Plugin output and file text can reach terminals and reports. |
| Always force `interactiveMode: Never` | Breaks SSO device-code logins that 03 supports at a terminal. |
| Keep kube's default `interactiveMode` | Plugin stderr reaches rdy's stderr past the redactor, and a login waits for nobody without a terminal. |
| `rustls-platform-verifier` for the system roots | AIA and OCSP fetches outside the peer set on macOS and Windows (ADR 0014 decision 3). |
| Clear `HTTPS_PROXY` in the process | Needs `unsafe` or a race with other threads. The placeholder needs neither. |
| Drop every credential variable from the plugin | Breaks `aws eks get-token` and its kind for users who log in through the environment. |
