# ADR 0031: The kube client layer reads the kubeconfig itself, announces first, and keeps plugin output out of every error

- Status: Proposed (M1-102). security-reviewer to confirm: it touches credentials, plugins and the network.
- Date: 2026-10-29

## Context

ADR 0010 chooses kube-rs behind a read-only guard and names the exec plugin exception. M1-102 builds the
client layer under it. Reading kube 4.2.0 (the pinned version) showed four things the ADR text does not say:

- `Config::infer` and `Client::try_default` call `apply_debug_overrides`, which honours
  `KUBE_RS_DEBUG_OVERRIDE_URL` and `KUBE_RS_DEBUG_IMPERSONATE_USER`. They can swap the server or the
  identity.
- kube's `AuthExecRun` error formats the plugin's whole stdout and stderr with `{:?}`, and a YAML parse
  error can quote the kubeconfig line that holds a token.
- The `gcp` auth-provider runs a `cmd-path` command that the report would not name.
- `Config` reads `HTTPS_PROXY` on its own. With no proxy feature, a set variable fails the build with a
  hidden cause.

The probe facade denies reads under `.kube` (02, file deny list; PR #58 review F7), so the engine's own
kubeconfig read needed a settled path.

## Decision

1. **Features.** `kube` with `client`, `rustls-tls` and `ring` (ADR 0010 listed the first two; without a
   provider feature rustls has none, and `cargo deny` bans `aws-lc-rs`). `k8s-openapi` 0.28 with `v1_36`,
   because kube 4.2.0 depends on 0.28. Both pinned in the workspace (kube with `=`); they move together.
2. **The kubeconfig is read by the client module, not through a Probe.** `rdy_checks_k8s::client::load`
   reads `--kubeconfig`, else `KUBECONFIG` (files that do not exist are skipped, first file wins), else
   `~/.kube/config`, else the in-cluster config. A path the operator chose, never one from a spec or the
   working directory. The file must be a regular file of at most 8 MiB (a FIFO would block). The probe's
   `.kube` deny stays for checks. `Loaded::files()` returns the paths so the probe hook (M1-107) logs one
   `read` entry each, with no check id.
3. **No `infer`, no `try_default`.** The client module builds a `Config` from the `Kubeconfig` it read
   and never calls `apply_debug_overrides`.
4. **Announce, then send.** `Loaded::connect(announce)` calls `announce` with the cluster line before it
   starts a plugin or opens a socket. The line is context, server (no user info) and the kubeconfig user
   name, plus the plugin file name and "TLS verification is OFF" when they apply. The authenticated
   identity comes later, from `SelfSubjectReview` (M1-103, M1-109). 07 gets `user <name>` in the line.
5. **Errors hold no kube text.** Each kube error maps to a `KubeError` variant with fixed words, a status
   code, an exit code or an `io::ErrorKind`. Plugin output, plugin arguments and parse text never enter an
   error, a log line or `Debug`. Tests feed canaries through stdout, stderr and a failing refresh, with
   every tracing level on and no cap.
6. **Refusals.** A user entry with `auth-provider` and a cluster with `proxy-url` are refused with a hint.
   `HTTPS_PROXY` is ignored for the cluster. Proxy support is M1-109, with its own feature decision.
7. **Limits.** The connect, read and write timeouts are the check timeout, at most 60 s. Retries are off.
   The build runs on the blocking pool, so a plugin never holds a worker. A plugin that waits for a login
   is bounded by the scheduler's timer (M1-107), and its process is not killed (02 residual).
8. **Plugin streams.** kube gives a plugin rdy's stdin and stderr unless the kubeconfig sets
   `interactiveMode: Never`, so device-code logins work. That stderr goes to the terminal, not through our
   logs. Documented residual.

## Consequences

- M1-103 puts the guard in `build_client` and `connect` returns the guarded type. Until then the unguarded
  client is private and only `GET /version` is sent.
- The kube lint-wall entries are in `crates/rdy-checks-k8s/clippy.toml`. A bad path warns, so `-D warnings`
  keeps them valid. M1-044 adds `tests/lint-wall` and the std entries.
- A kube bump needs a manual re-read of 02 Appendix A and of the error mapping in `client/error.rs`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Read the kubeconfig through `Probe` and allow `.kube` | Opens `~/.kube/*` to every check's reads. |
| `Config::infer` | Honours debug variables that can swap the server. |
| Show kube's error text | Plugin output and file text can reach terminals and reports. |
| Force `interactiveMode: Never` | Breaks SSO device-code logins that 03 supports. |
