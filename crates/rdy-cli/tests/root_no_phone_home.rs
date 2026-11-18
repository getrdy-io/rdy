//! No phone home: every network destination of a real `rdy run` is local (M1-128, SEC-22, INV-11).
//!
//! The test runs the built `rdy` as root inside `unshare -n` (a new network namespace with no route
//! out) under `strace -f -e trace=connect,sendto,sendmsg`, then reads the log. Every call that names a
//! destination must name one of these, and nothing else:
//!
//! - an exact loopback address and port pair: the fixture endpoints and NTP servers of the spec below,
//!   and UDP `127.0.0.1:323` and `[::1]:323` for `chronyc`. A loopback address on any other port is
//!   refused, so a lookup through a stub resolver such as `127.0.0.53:53` is a phone home;
//! - a unix socket a check declares (INV-28): the container runtime sockets of `host.container_runtime`;
//! - one of the local IPC sockets of INV-11's third exception: `/run/chrony/chronyd.sock` and
//!   `/var/run/chrony/chronyd.sock`, and the D-Bus system bus at `/run/dbus/system_bus_socket` and
//!   `/var/run/dbus/system_bus_socket`.
//!
//! The test traces `connect`, `sendto`, `sendmsg` and `sendmmsg`, and flags any `io_uring_setup`, because
//! a ring can send without any of those calls. `sendto`, `sendmsg` and `sendmmsg` on a connected socket name no destination (`NULL`), so there is nothing to
//! judge there. Any other socket family (`AF_NETLINK`, `AF_PACKET`) is flagged, as is a connect call
//! whose address the parser cannot read.
//!
//! Controls keep an empty or wrong log from passing. The classifier has unit tests with literal lines,
//! one per allowed destination and one per refusal. A child that connects to a documentation address
//! (`192.0.2.1`) must be flagged, and its connect must fail with `ENETUNREACH`, which shows the
//! namespace has no route out. The `rdy` run itself must reach the loopback fixture endpoint, so the
//! log is not empty for the wrong reason.
//!
//! The spec uses IP literals, so no resolver is asked: a runner's resolver address is not ours to
//! allow. Plain `cargo test` runs the `root_*` tests and they return early without root. Where `strace`
//! or `unshare -n` is unusable they skip, unless `RDY_REQUIRE_ROOT` (the `root` CI job sets it) or
//! `RDY_REQUIRE_STRACE` is set, which turns a skip into a failure.
//!
//! macOS and Windows get the equivalent in M2-084.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// The control child: connects a UDP socket to a documentation address.
const PROBE: &str = "strace_probe_connect_non_local";
const PROBE_VAR: &str = "RDY_PROBE_CONNECT_NON_LOCAL";

/// The fixture spec: every check this build registers (13 `host` and 3 `net`; `k8s` is not registered
/// yet), with loopback endpoints and NTP servers. IP literals only, so no resolver is asked.
const SPEC: &str = r#"apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme-probe
  version: ">=1"
checks:
  - {id: host.cpu, min: 1, severity: warn, fix: "Add cores."}
  - {id: host.memory, min: 1Gi, severity: warn, fix: "Add RAM."}
  - {id: host.disk, path: /tmp, min: 1Gi, severity: warn, fix: "Add disk."}
  - {id: host.kernel, min: "4.0", severity: warn, fix: "Upgrade the kernel."}
  - {id: host.cgroups, version: v2, severity: warn, fix: "Boot with cgroup v2."}
  - {id: host.ports, free: [18080], severity: warn, fix: "Free the port."}
  - {id: host.lsm, selinux: {allow: [permissive, disabled]}, severity: warn, fix: "Set permissive."}
  - {id: host.firewall, severity: warn, fix: "Open the ports."}
  - {id: host.container_runtime, severity: warn, fix: "Install a runtime."}
  - {id: host.time_sync, max_skew: 5s, ntp_servers: ["127.0.0.1:12123", "[::1]:12123"], severity: warn, fix: "Sync the clock."}
  - {id: host.os, fips: forbid, severity: warn, fix: "Disable FIPS mode."}
  - {id: host.sysctl, expect: {vm.max_map_count: ">=262144"}, severity: warn, fix: "Raise the limit."}
  - {id: host.security_agents, forbid: [acme-agent], severity: warn, fix: "Remove the agent."}
  - {id: net.tls_intercept, hosts: ["127.0.0.1:18445"], severity: warn, fix: "Trust the proxy CA."}
  - {id: net.mtu, min_mtu: 1400, severity: warn, fix: "Raise the MTU."}
  - {id: net.egress, endpoints: ["127.0.0.1:18443", "[::1]:18444"], via_proxy: direct, severity: warn, fix: "Open the endpoint."}
"#;

/// The unix sockets a check declares (INV-28): `host.container_runtime`.
const DECLARED_UNIX: [&str; 4] = [
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
    "/var/run/crio/crio.sock",
];

/// The local IPC sockets of INV-11's third exception, `chronyc` and the D-Bus system bus.
const IPC_UNIX: [&str; 4] = [
    "/run/chrony/chronyd.sock",
    "/var/run/chrony/chronyd.sock",
    "/run/dbus/system_bus_socket",
    "/var/run/dbus/system_bus_socket",
];

/// The loopback (address, port) pairs the fixture spec and the `chronyc` exception allow: the
/// `net.egress` endpoints, the `host.time_sync` NTP servers, the `net.tls_intercept` host and 323.
const LOOPBACK_V4: [u16; 4] = [18443, 12123, 18445, 323];
const LOOPBACK_V6: [u16; 3] = [18444, 12123, 323];

/// The number after `marker`, up to the next `)`.
fn port(text: &str, marker: &str) -> Option<u16> {
    text.split(marker).nth(1)?.split(')').next()?.parse().ok()
}

/// Why a call is not allowed, or `None` when it is.
fn verdict(line: &str) -> Option<String> {
    let body = line.split_once(' ').map_or(line, |(_, rest)| rest).trim();
    if body.starts_with("io_uring_setup(") {
        return Some(format!("an io_uring ring, which can send unseen: {line}"));
    }
    let is_call = ["connect(", "sendto(", "sendmsg(", "sendmmsg("]
        .iter()
        .any(|name| body.starts_with(name));
    // Signals, exits and the second half of an interrupted call carry no destination.
    if !is_call || body.contains("resumed>") {
        return None;
    }
    let mut addrs = body.split("{sa_family=").skip(1).peekable();
    if addrs.peek().is_none() {
        // A connected socket: `sendto(7, "\1", 1, MSG_NOSIGNAL, NULL, 0)`. A connect must name one.
        return body
            .starts_with("connect(")
            .then(|| format!("a connect with no readable address: {line}"));
    }
    // Every address on the line must be allowed (a `sendmmsg` carries several).
    addrs
        .any(|addr| !allowed(addr))
        .then(|| format!("a destination that is not local IPC or a fixture pair: {line}"))
}

/// True when the socket address that starts at `addr` (the text after `{sa_family=`) is allowed.
fn allowed(addr: &str) -> bool {
    let family = addr.split([',', '}']).next().unwrap_or_default();
    match family {
        "AF_INET" => {
            quoted(addr, "inet_addr(\"").is_some_and(|ip| ip == "127.0.0.1")
                && port(addr, "sin_port=htons(").is_some_and(|p| LOOPBACK_V4.contains(&p))
        }
        "AF_INET6" => {
            quoted(addr, "inet_pton(AF_INET6, \"").is_some_and(|ip| ip == "::1")
                && port(addr, "sin6_port=htons(").is_some_and(|p| LOOPBACK_V6.contains(&p))
        }
        "AF_UNIX" => quoted(addr, "sun_path=")
            .is_some_and(|path| DECLARED_UNIX.contains(&path) || IPC_UNIX.contains(&path)),
        _ => false,
    }
}

/// The text of the quoted string that follows `marker` in `text`.
fn quoted<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let rest = text.split(marker).nth(1)?;
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    rest.split('"').next()
}

/// Every refused call in the log.
fn refused(log: &str) -> Vec<String> {
    log.lines().filter_map(verdict).collect()
}

#[test]
fn classifier_allows_loopback_declared_sockets_and_the_ipc_exception() {
    let allowed = [
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(18443), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ENETUNREACH (Network is unreachable)"#,
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(323), sin_addr=inet_addr("127.0.0.1")}, 16) = 0"#,
        r#"10 connect(15, {sa_family=AF_INET6, sin6_port=htons(18444), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        r#"10 connect(15, {sa_family=AF_INET6, sin6_port=htons(323), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        r#"10 sendto(5, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(12123), sin_addr=inet_addr("127.0.0.1")}, 16) = 1"#,
        r"10 sendmmsg(3, [{msg_hdr={msg_name=NULL, msg_namelen=0}, msg_len=1}], 1, 0) = 1",
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/run/chrony/chronyd.sock"}, 110) = 0"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/chrony/chronyd.sock"}, 110) = 0"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = 0"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/dbus/system_bus_socket"}, 110) = 0"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT"#,
        r#"10 sendto(7, "\1", 1, MSG_NOSIGNAL, NULL, 0) = 1"#,
        r#"10 sendmsg(3, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="x", iov_len=1}], msg_iovlen=1}, 0) = 1"#,
        r"10 <... connect resumed>) = -1 EINPROGRESS (Operation now in progress)",
        r"10 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---",
        r"10 +++ exited with 0 +++",
    ];
    for line in allowed {
        assert_eq!(verdict(line), None, "{line}");
    }
}

#[test]
fn classifier_refuses_everything_else() {
    let refused_lines = [
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0"#,
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0"#,
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(18444), sin_addr=inet_addr("127.0.0.1")}, 16) = 0"#,
        r#"10 connect(15, {sa_family=AF_INET6, sin6_port=htons(18443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        r#"10 sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(18443), sin_addr=inet_addr("127.0.0.1")}, msg_namelen=16}, msg_len=1}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("198.51.100.7")}, msg_namelen=16}, msg_len=1}], 2, 0) = 2"#,
        r"10 io_uring_setup(8, {flags=0}) = 5",
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.1")}, 16) = 0"#,
        r#"10 connect(15, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0"#,
        r#"10 sendto(5, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(123), sin_addr=inet_addr("203.0.113.9")}, 16) = 1"#,
        r#"10 connect(15, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        r#"10 sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("198.51.100.7")}, msg_namelen=16}, 0) = 1"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/tmp/other.sock"}, 110) = 0"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path="/run/chrony/other.sock"}, 110) = 0"#,
        r#"10 connect(3, {sa_family=AF_UNIX, sun_path=@"abstract"}, 110) = 0"#,
        r"10 connect(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0",
        r"10 connect(3, {sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL)}, 20) = 0",
        r"10 connect(3, NULL, 0) = -1 EINVAL",
    ];
    for line in refused_lines {
        assert!(verdict(line).is_some(), "{line}");
    }
}

/// The child side of the control. It is `#[ignore]`, so no normal run executes it.
#[test]
#[ignore = "run by the control test under strace"]
fn strace_probe_connect_non_local() {
    if std::env::var_os(PROBE_VAR).is_none() {
        return;
    }
    let socket = std::net::UdpSocket::bind("0.0.0.0:0");
    drop(socket.and_then(|s| s.connect("192.0.2.1:9")));
}

/// The child side of the DNS control. It is `#[ignore]`, so no normal run executes it.
#[test]
#[ignore = "run by the control test under strace"]
fn strace_probe_resolve_name() {
    if std::env::var_os(PROBE_VAR).is_none() {
        return;
    }
    drop(std::net::ToSocketAddrs::to_socket_addrs(
        &"phone-home.acme.example:80",
    ));
}

fn require() -> bool {
    std::env::var_os("RDY_REQUIRE_ROOT").is_some()
        || std::env::var_os("RDY_REQUIRE_STRACE").is_some()
}

/// True when this test can run. A missing `strace`, `unshare -n` or root skips it, except where the
/// `root` job demands it.
fn usable() -> bool {
    let reason = if !rustix::process::geteuid().is_root() {
        Some("needs uid 0 (the root job sets RDY_REQUIRE_ROOT=1)")
    } else if Command::new("strace").arg("-V").output().is_err() {
        Some("strace is not installed (the root job installs it)")
    } else if !Command::new("unshare")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|status| status.success())
    {
        Some("`unshare -n` does not work here")
    } else {
        None
    };
    let Some(reason) = reason else { return true };
    assert!(
        !require(),
        "RDY_REQUIRE_ROOT or RDY_REQUIRE_STRACE is set but: {reason}"
    );
    eprintln!("skipped: {reason} (RDY_REQUIRE_STRACE=1 turns this skip into a failure)");
    false
}

struct Traced {
    log: String,
    code: Option<i32>,
    stdout: String,
}

/// Runs `argv` in a new network namespace under `strace -f` and returns the log.
fn traced(argv: &[&OsStr], envs: &[(&str, &OsStr)], log: &Path) -> Traced {
    let mut command = Command::new("unshare");
    command
        .args([
            "-n",
            "--",
            "strace",
            "-f",
            "-qq",
            "-e",
            "trace=connect,sendto,sendmsg,sendmmsg,io_uring_setup",
            "-o",
        ])
        .arg(log)
        .arg("--")
        .args(argv)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy");
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .expect("unshare could not be started; the root job installs strace and util-linux");
    let text = std::fs::read_to_string(log).unwrap_or_default();
    assert!(
        !text.is_empty(),
        "strace wrote no log (ptrace blocked?): {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Traced {
        log: text,
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    }
}

#[test]
fn root_control_a_non_local_connect_is_seen_and_flagged() {
    if !usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("a temp dir");
    let me = std::env::current_exe().expect("the test binary");
    let argv = [
        me.as_os_str(),
        OsStr::new("--ignored"),
        OsStr::new("--exact"),
        OsStr::new(PROBE),
        OsStr::new("--nocapture"),
    ];
    let seen = traced(
        &argv,
        &[(PROBE_VAR, OsStr::new("1"))],
        &dir.path().join("control.log"),
    );
    let flagged = refused(&seen.log);
    assert_eq!(
        flagged.len(),
        1,
        "the control connect is not flagged once:\n{}",
        seen.log
    );
    assert!(flagged[0].contains("192.0.2.1"), "{flagged:?}");
    // No route out: the connect fails, so nothing really left even if the classifier were blind.
    assert!(
        flagged[0].contains("ENETUNREACH"),
        "the namespace has a route out:\n{}",
        seen.log
    );
}

#[test]
fn root_run_contacts_only_loopback_and_local_ipc() {
    if !usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("a temp dir");
    let spec = dir.path().join("acme-probe.yaml");
    std::fs::write(&spec, SPEC).expect("write the spec");
    let rdy = Path::new(env!("CARGO_BIN_EXE_rdy"));
    let argv = [
        rdy.as_os_str(),
        OsStr::new("run"),
        spec.as_os_str(),
        OsStr::new("--allow-unsigned"),
        OsStr::new("--json"),
        OsStr::new("--no-report"),
    ];
    // sudo resets HOME, so the test sets it.
    let done = traced(
        &argv,
        &[("HOME", dir.path().as_os_str())],
        &dir.path().join("rdy.log"),
    );

    // The run really ran: a Report with the checks, exit 0 or 1.
    assert!(
        matches!(done.code, Some(0 | 1)),
        "exit {:?}:\n{}",
        done.code,
        done.stdout
    );
    let report: Value = serde_json::from_str(&done.stdout)
        .unwrap_or_else(|e| panic!("stdout is not the Report ({e}):\n{}", done.stdout));
    assert_eq!(report["run"]["options"]["network"], true, "{report}");
    assert_eq!(
        report["checks"].as_array().map(Vec::len),
        Some(16),
        "not every fixture check ran:\n{}",
        done.stdout
    );

    // The log is not empty for the wrong reason: rdy reached for the loopback fixture endpoint.
    assert!(
        done.log
            .contains(r#"sin_port=htons(18443), sin_addr=inet_addr("127.0.0.1")"#),
        "the run never tried the loopback endpoint:\n{}",
        done.log
    );

    let bad = refused(&done.log);
    assert!(
        bad.is_empty(),
        "rdy contacted a non-local destination:\n{}",
        bad.join("\n")
    );
}

/// The DNS control: a name lookup shows as a connect to the resolver. Whatever address the resolver
/// has (a stub on `127.0.0.53` included), the destination is not a fixture pair, so it is flagged.
#[test]
fn root_control_a_name_lookup_is_seen_and_flagged() {
    if !usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("a temp dir");
    let me = std::env::current_exe().expect("the test binary");
    let name = "strace_probe_resolve_name";
    let argv = [
        me.as_os_str(),
        OsStr::new("--ignored"),
        OsStr::new("--exact"),
        OsStr::new(name),
        OsStr::new("--nocapture"),
    ];
    let seen = traced(
        &argv,
        &[(PROBE_VAR, OsStr::new("1"))],
        &dir.path().join("dns.log"),
    );
    let flagged = refused(&seen.log);
    assert!(
        flagged.iter().any(|line| line.contains("htons(53)")),
        "the lookup did not show as a refused connect to port 53:\n{}",
        seen.log
    );
}
