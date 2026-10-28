# Review of 03-check-catalog.md (host and net families) by rust-engineer

Scope: section 1 (conventions), section 2 (`host.*`), section 3 (`net.*`), Appendix A (shell-outs), Appendix B (data files), and the host and net tickets. I read it as the person who will type it. I did not touch the catalog. K8s, cloud and GPU sections are out of scope.

Read against: CLAUDE.md, the milestones in `rdy-plan.md`, ADR 0004 (tokio), ADR 0006 (static musl), ADR 0009 (HTTP and TLS). `02-engine-design.md` does not exist yet, so every "facade" point below is a request to that doc as much as to this one.

## Verdict

**Revise before build. 13 must-fix items.** The structure is good: six bullets per check, a degrade rule, bounds, a shared fixture layout, honest tiers. Most data sources are right. The failures are concentrated in four places:

1. Three concrete bugs in `host.ports` (a bind fallback, a wrong UDP state, a wrong sysctl name in the fix text).
2. cgroup paths in `host.memory` and `host.cpu` that read nothing on a normal host.
3. Two places where the catalog contradicts an accepted ADR (`net.dns` vs ADR 0006, `net.egress` and PAC vs ADR 0009).
4. A fixture format and facade that cannot survive a Windows checkout, and shell-outs that are not pinned.

The hours for net are about 40 percent low. Details are in "Hours" at the end.

Ranking: must fix = would cause a wrong result, a broken build or CI, or a contradiction with an accepted decision. should fix = will cost rework or false results in the field. nit = polish.

---

## Must fix

### 1. `host.ports`: the bind fallback binds
Problem: the Source line falls back to `bind()` then close if `/proc/net` is unreadable. That binds the port, even if briefly. It can race the real service, it needs root below 1024 (so it returns `unknown` for exactly the ports we care about), and it can fail on TIME_WAIT without `SO_REUSEADDR`. It also breaks your own rule "read-only". `/proc/net/tcp` is world-readable on every kernel we target (hidepid affects `/proc/<pid>`, not `/proc/net`), so the fallback is nearly dead code.
Fix: delete the bind fallback. If `/proc/net/*` cannot be read, report `partial` with `unknown`. Optionally add a weak loopback `connect()` probe (refused means nothing listens on loopback, success means in use), labelled "weak evidence". `tokio::net::TcpStream::connect` is allowed by ADR 0004; do not use `std::net`.

### 2. `host.ports`: UDP has no state `0A`
Problem: the text says "`/proc/net/tcp`, `tcp6`, `udp`, `udp6` (state `0A`)". `0A` is TCP LISTEN. Bound UDP sockets show state `07` (`TCP_CLOSE`) with `rem_address 00000000:0000`. As written, UDP conflicts are never found.
Fix: TCP: state `0A` only. UDP: every row with a non-zero local port counts as bound. Add fixtures for `udp` and `udp6`. Also state in the fixture list: addresses are little-endian hex per 32-bit word (`0100007F` is 127.0.0.1, tcp6 has four words), and a `[::]` listener covers IPv4 unless `v6only` (read `/proc/sys/net/ipv6/bindv6only` is not enough; treat `[::]` as covering both and say so).

### 3. `host.ports`: wrong sysctl name in the fix text
Problem: the fix says `net.ipv4.ip_reserved_ports={port}`. The real name is `net.ipv4.ip_local_reserved_ports`. A customer who pastes this gets `unknown key`.
Fix: use `net.ipv4.ip_local_reserved_ports`. Give the full persisted form: `echo 'net.ipv4.ip_local_reserved_ports = {port}' | sudo tee /etc/sysctl.d/90-acme-ports.conf && sudo sysctl --system`. Add a unit test that every sysctl name inside fix text exists in a small allowlist file, so this class of typo fails CI.

### 4. `host.memory` and `host.cpu`: cgroup file paths are wrong on a host
Problem: the Source reads `/sys/fs/cgroup/memory.max` and `/sys/fs/cgroup/cpu.max`. On cgroup v2 the root cgroup has neither file. They exist only when `rdy` runs inside a container with a private cgroup namespace, where `/sys/fs/cgroup` is the container's own cgroup. On a normal host, `rdy` runs in something like `/user.slice/user-1000.slice/session-3.scope`, and the limit is the minimum of `memory.max` along that path and all its parents. v1 is the same problem with `/sys/fs/cgroup/memory/<path>/memory.limit_in_bytes`. `host.cpu` also has no v1 source (`cpu.cfs_quota_us`, `cpu.cfs_period_us`, directory may be `cpu,cpuacct`).
Fix: one shared `cgroup` helper (new ticket, 2h, used by `host.memory`, `host.cpu`, `host.cgroups`):
- read `/proc/self/cgroup` (`0::/path` for v2, `N:memory:/path` for v1),
- join it to the mount point from `/proc/self/mountinfo`,
- walk up to the mount root and take the minimum finite value,
- treat v2 `max` and any v1 value at or above `MemTotal` (v1 "unlimited" is `9223372036854771712`) as unlimited,
- also read `memory.swap.max` (v2) for the swap limit.
`std::thread::available_parallelism` already does this walk for CPU, so use it for "usable cores" and use the helper only to explain why (quota 200000/100000). Alternative: `sysinfo::System::cgroup_limits()` exists on Linux, but it reads the real filesystem and cannot be fed a fixture. Hand-parse.

### 5. `net.egress`: reqwest cannot give the failure classes the catalog promises
Problem: ADR 0009 says `net.egress` uses reqwest through the shared client builder. This catalog needs per-stage results (DNS, TCP connect, TLS handshake, HTTP), nine failure classes (`blackhole`, `refused`, `reset_after_hello`, `proxy_407`, `proxy_403`, ...), the redirect host list, and an injectable connector. reqwest returns one opaque error and no stage timings. You can sometimes recover `refused` and `UnknownIssuer` by walking `source()`, but not `blackhole` vs slow, not `reset_after_hello`, and not CONNECT status codes. The doc also says HTTP proxies use "CONNECT we write ourselves" (ADR 0009 item 3 says that for `tls_intercept` only). The two documents describe two different egress stacks.
Fix: amend ADR 0009 (rust-architect): `net.egress` and `net.tls_intercept` share one staged connector: `tokio::net::TcpStream` with `tokio::time::timeout`, our own CONNECT (about 40 lines, parse the status line with `httparse`, cap the header at 16 KiB), `tokio-rustls` for TLS, `hyper::client::conn::http1` for the request (hyper is already in the graph through kube). reqwest stays for the upload client in M2. Consequence: the M1 ticket "Shared HTTP client builder with rustls ring, dual roots and proxy env" (ADR 0009, 3h) has no M1 consumer and moves to M2. That pays back about 3h of the extra net hours.

### 6. `net.dns`: contradicts accepted ADR 0006
Problem: ADR 0006 item 4 decides `net.dns` resolves with `hickory-resolver` from `/etc/resolv.conf` and `/etc/hosts` and only warns about `nsswitch.conf`. The catalog makes `getent ahostsv4` the primary Linux path and lists that as an open ADR item. The catalog's reason is sound (ADR 0006 itself says we must report what glibc-linked software sees), but an accepted ADR is not changed by a side note.
Fix: rust-architect amends ADR 0006: on Linux, `net.dns` uses `/usr/bin/getent ahosts <name>` as the system answer when the binary exists, and hickory for per-nameserver queries and as the fallback (scratch containers, Alpine). Details the ticket needs:
- use `ahosts`, not `ahostsv4`, so AAAA-only names are seen; dedupe the three rows per address (STREAM, DGRAM, RAW);
- exit code 2 means not found, anything else is a tool error;
- validate the name against `^[A-Za-z0-9._-]+$` and reject a leading `-`, then pass `--` before it (argv has no shell, but getopt still parses `-x`);
- the 5s timeout kills getent; the resolver default (5s times 2 attempts times N servers) can exceed it, so report `timeout` with the resolv.conf `options timeout/attempts` values in the evidence;
- in the hickory dependency use `default-features = false` with only `tokio` and `system-config`. The default DoT and DoH features pull rustls with `aws-lc-rs` and trip the `aws-lc-sys` ban in ADR 0009 item 5. Add "cargo deny check passes" to the ticket exit test.

### 7. `net.proxy`: fetching PAC files contradicts ADR 0009 and the scope
Problem: the catalog fetches the PAC URL (256 KiB cap) and lists `PROXY host:port` strings scraped from it. ADR 0009 item 2 says PAC and WPAD are not supported in v1 and the check says so in its hint. Scraping strings from arbitrary JavaScript is guesswork, and the fetch is an extra outbound request from a check that is meant to be passive.
Fix: detect PAC (macOS `ProxyAutoConfigURLString`, Windows `AutoConfigURL`, WPAD auto-detect flag), record the URL with query and userinfo stripped, return `warn` "rdy cannot evaluate PAC, set `HTTPS_PROXY` explicitly or use `via_proxy` in the spec". No fetch, no scraping. Delete the PAC fixture.

### 8. `net.tls_intercept`: verifier design and a false-accusation path
Problem 1 (design): the catalog describes a probe verifier that "accepts any chain". That is more dangerous than needed and also does two handshakes' worth of work. Problem 2 (false positive): rustls validates against the current time. If the box clock is wrong, or the server cert truly expired, the chain "validates nowhere" and the check reports class (c) "interception CA not installed". Clock skew is also something `host.time_sync` and `net.egress` report, so the report would accuse the network team of interception when the clock is the cause.
Fix:
- Implement a recording `ServerCertVerifier` through `ClientConfig::builder_with_provider(ring).dangerous().with_custom_certificate_verifier(..)`. Inside `verify_server_cert` it runs two real `WebPkiServerVerifier`s (one built from `webpki-roots`, one from `rustls-native-certs`), records `end_entity`, `intermediates` and each verdict (Ok or the `rustls::Error` / `CertificateError` variant), then returns Ok so the handshake completes. Delegate `verify_tls12_signature`, `verify_tls13_signature` and `supported_verify_schemes` to the provider. One handshake gives all three classes. Then send `close_notify` and write zero application bytes (the existing unit test stays).
- Map `CertificateError::Expired`, `NotValidYet` and `ExpiredContext` to a separate class `clock_or_expiry`, never to interception. Make `UnixTime` injectable so a test pins this.
- Use `builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))` in `rdy-checks-net` instead of relying on the process-wide default from ADR 0009 item 1. Unit tests run without `rdy-cli`'s startup and would panic on `ClientConfig::builder()` otherwise.
- Class (b) false positive: the Windows and macOS stores carry roots that Mozilla does not. A vendor endpoint signed by such a CA looks like "private CA trusted locally". Word class (b) as "chain is trusted by this machine only, issuer `{issuer}`" and keep it at `warn`. Do not say "inspection proxy" as a fact.
- Fact check for the catalog's own plan-correction: `reqwest` does have `tls_info(true)`, but it exposes only the leaf certificate and only after a successful verification, which is exactly the case where interception is invisible. So the raw `tokio-rustls` handshake is the right tool. Say that in the correction.
- Load `rustls-native-certs` once, in `spawn_blocking`, and cache it. On macOS it can take hundreds of milliseconds. Its result type carries per-cert errors; surface the count in evidence.
- The "which OS store file holds the root" evidence exists only on Linux. Say "System keychain" or "Windows Root store" elsewhere.

### 9. Fixture layout and the fake facade are under-specified and will break on Windows CI
Problem:
- `host.ports` fixtures use `/proc/<pid>/fd` symlink trees with targets like `socket:[1234]`. Git symlinks do not survive a default Windows checkout, and `:` `[` `]` are illegal in Windows file names.
- `host.lsm` needs an audit log with mode 0600 to simulate non-root. File modes are not stored by git.
- "Read through the engine's file handle" is the only facade named. The catalog also needs: `statvfs` (a `statvfs.json` is mentioned), `uname`, `adjtimex`, `getrlimit`, `available_parallelism`, environment variables, `read_dir`, `read_link`, `stat`, a `sysinfo` snapshot, registry reads, unix socket connect, UDP send, and TCP connect. Without a list, the first check author invents it and the second one rewrites it.
Fix, in the "Fixture loader" ticket and in `02-engine-design.md`:
- Virtual paths are POSIX strings (`&str`), not `std::path::Path`, for the Linux sources, so the same fixtures run on all four CI targets.
- The fixture tree may contain a `root.manifest.json` that adds what the file system cannot: `symlinks: {"proc/1234/fd/7": "socket:[8841]"}`, `unreadable: ["var/log/audit/audit.log"]`, `dirs` for empty directories. The loader materialises these in memory only.
- Enumerate the facade in Conventions: `fs` (read, read_dir, read_link, stat), `sys` (statvfs, uname, adjtimex, rlimit, parallelism, `SysSnapshot` struct from sysinfo), `env`, `cmd`, `net` (connect, udp, resolve), `registry` (cfg windows). Each returns plain structs, never sysinfo or rustix types, so a test can build them by hand.
- Add `clippy::disallowed_methods` for `std::fs::*`, `std::env::var*` and `tokio::fs::*` in the check crates (ADR 0004 already does this for `std::process::Command`). Otherwise a check that reads the real `/proc` passes on the author's laptop and fails on CI.
- Command fixtures: key the file name by a hash of argv plus a readable slug. Raw argv in a file name breaks on Windows.
- Golden files with generated values (rcgen serials, SHA-256 of generated roots) need a placeholder rule (`"<sha256>"`) in the compare helper.

### 10. Appendix A is not pinned and one entry cannot run on Windows
Problem: the policy says "fixed argv, fixed PATH" but the table has bare names (`getent`, `xfs_info`, `timedatectl`, `chronyc`, `firewall-cmd`, `systemextensionsctl`, `netsh`, `powershell.exe`), no PATH value, and `<fixed string>` for PowerShell. On Windows the scrubbed env keeps `SystemRoot` only, so `powershell.exe` does not resolve (System32 is searched, `System32\WindowsPowerShell\v1.0` is not). Several commands that the sources use are missing from the table. This is the file security-reviewer signs against.
Fix: rewrite Appendix A with absolute paths, exact flags, expected exit codes, output cap and timeout per row. Define `PATH=/usr/sbin:/usr/bin:/sbin:/bin` (and `LC_ALL=C`, nothing else) for Linux. On Windows, derive paths from `%SystemRoot%`, do not hard-code `C:`. Proposed rows:

| Command | Check | Notes |
| --- | --- | --- |
| `/usr/bin/getent ahosts <name>` | `net.dns` | name validated, `--` before it, 5s |
| `/usr/bin/timedatectl show -p NTPSynchronized -p NTP -p Timezone` | `host.time_sync` | `show` needs systemd 239+; RHEL 7 has 219, so fall back to `timedatectl status` and parse `NTP synchronized:` |
| `/usr/bin/chronyc -n -c tracking` | `host.time_sync` | `-c` is CSV, stable to parse. Add `-t 3` |
| `/usr/bin/firewall-cmd --state`, `/usr/bin/firewall-cmd --list-all` | `host.firewall` | exit 252 means not running |
| `/usr/sbin/scutil --proxy`, `/usr/sbin/scutil --dns` | `net.proxy`, `net.dns` (macOS) | output is a text dump, not a plist |
| `/usr/sbin/netstat -anv -p tcp`, `-p udp` | `host.ports` (macOS) | ports after the last dot (`*.6443`) |
| `/usr/bin/systemextensionsctl list` | `host.security_agents` (macOS) | |
| `/usr/sbin/sysctl -n sysctl.proc_translated hw.optional.arm64` | `host.cpu` (macOS) | missing key on Intel exits 1: treat as 0 |
| `%SystemRoot%\System32\NETSTAT.EXE -ano` | `host.ports` (Windows) | |
| `%SystemRoot%\System32\netsh.exe int ipv4 show excludedportrange protocol=tcp` | `host.ports` (Windows) | rows match `^\s*\d+\s+\d+\s*\*?\s*$`, headers are localized |
| (new) `/usr/bin/containerd --version`, `/usr/bin/crio --version` | `host.container_runtime` | the check promises a version for these and has no source (see item 26) |
Remove from the table (see items 16, 18, 20): `xfs_info`, `/sbin/mount`, the `ifconfig` and PowerShell rows, and the macOS `sysctl` use for `host.sysctl`.
All commands: `stdin(Stdio::null())`, stderr captured and capped, 1 MiB stdout cap then kill. Any argument that comes from the spec (sysctl names, hostnames, paths) passes an allowlist regex first.

### 11. Redaction ships after its first users, and URLs can carry credentials
Problem: `net.proxy` and `net.egress` are M1. The ticket "Evidence redaction helpers (proxy userinfo, env allow-list)" is M1-late and depends on `net.proxy`. So the alpha's first design partner run can write proxy userinfo to a report. Second, the spec's `url` fields (`net.egress`, `net.bandwidth`, `net.registry`) may carry credentials in the query string (presigned URLs, tokens). The convention only strips proxy userinfo.
Fix: make the redaction helper an M1 plumbing ticket before `net.proxy` and `net.egress`, and have those tickets depend on it. Rule: every URL stored in evidence is `scheme://host:port/path` only. No userinfo, no query, no fragment. `~/.docker/config.json` is deserialized into a struct that has only `proxies`; the `auths` key (base64 credentials) must never reach memory as a raw string that is logged or stored. Add the "planted secret" golden test to the `net.proxy` and `net.egress` tickets, not a later ticket.

### 12. `host.security_agents`: scope, wording and no list
Problem: the brief for this check is process names only, described neutrally. The catalog matches against four sources (process names, directories, unit names, kernel modules), adds Windows WMI and Defender exclusions, and puts a free-text `{risk}` note in the fix text. "Risk" text next to a vendor's product name is where a libel complaint or a vendor email comes from. The seed list is not in the document, so I cannot review that it is sane.
Fix:
- M1-late: process names only (`/proc/*/comm` plus basename of `/proc/*/cmdline` argv[0], because `comm` is truncated to 15 bytes; `sysinfo` on macOS and Windows). Directories, units, modules and `systemextensionsctl` go to M2.
- Catalog fields: `id`, `display_name`, `category` (`edr`, `av`, `dlp`, `backup`), `process_names`, `source`, `checked_on`, `exclusion_docs_url` (the vendor's own public page). Drop `risk` and drop free-text notes.
- Fixed neutral message: "Detected `{display_name}` ({category}). Software in this category often inspects file opens and process launches. If the install is slow or fails, ask the security team to review exclusions for `{paths}`, then rerun." No claim that the product breaks anything.
- Detection says "a process with this name is running", not "this product is installed". Evidence shows the process name, not the user or command line.
- Put the seed list (10 to 15 entries, with source URL) in the catalog doc or as a ticket deliverable, and have the founder approve it. Product names of tools Rdy checks may be named under the repo rules, but keep them in `agents.toml`, not in prose docs.
- Cut Windows WMI (`wmi` crate) and Defender exclusions from M1. Reasons: the exclusions registry key is admin-only, `SecurityCenter2` is empty on Server SKUs, and WMI needs COM initialised per thread, which fights tokio's reused blocking threads. If it comes back in M2, run it on a dedicated `std::thread`.

### 13. Capacity, duplicate tickets and the cut order
Problem: three things.
- The catalog's own warning is right: 58h of M1 checks does not fit 18 to 48h. But the host and net estimates are low (see "Hours"), so the real gap is larger.
- Tickets overlap with the ADR tickets: "Command runner" (3h) vs ADR 0004 "Blocking helper and subprocess kill on timeout" (3h); "Loopback network test support" (3h) vs ADR 0009 "Shared HTTP client builder" exit test (local CONNECT proxy and test CA); "Shared HTTP client builder" has no M1 consumer once item 5 is accepted.
- The cut order "k8s.nodes, k8s.rbac, net.tls_intercept, host.os" cuts the plan's headline net check (plan, build order step 4: "Proxy and TLS interception are where most real POCs fail") and cuts the cheapest, most used host check. `host.os` is 2h and every spec has a `supported` list.
Fix:
- Merge the command runner with the ADR 0004 ticket. Net new work is the scrubbed env, the caps and the replay (2h).
- Share the loopback TLS server and CONNECT proxy between the net tests and drop the duplicate in the ADR 0009 ticket.
- Cut order for host and net (first cut first): `host.cpu` flags and cgroup quota detail (keep core count and arch); `host.ports` owner lookup (keep conflict detection, see item 17); `net.proxy` sources beyond the process environment and systemd drop-ins for docker, containerd and kubelet; the second (OS) store classification in `net.tls_intercept` (keep "issuer and chain depth reported on `tls_unknown_issuer`" inside `net.egress`, which already holds the chain). Never cut `host.os`, `host.disk`, `host.memory`, `net.egress`.
- Say in the catalog that macOS and Windows get the sysinfo-only subset in M1 (see item 14), so four-OS CI runs real code.

---

## Should fix

### 14. Windows and macOS: "skipped everywhere" is too pessimistic, and `skipped` can read as ready
`sysinfo` (with `default-features = false`, features `system`, `disk`, `network`) gives total and available memory, swap, logical and physical cores, CPU brand and arch, disk total and free, OS name, version and kernel on all three OSes. That is about 30 minutes per check once a `SysSnapshot` facade exists. Proposal: M1 = Linux full, plus the sysinfo-only subset of `host.memory`, `host.cpu` (cores and arch), `host.disk` (free space), `host.os` (name and version) on macOS and Windows. Everything that needs a shell-out, plist, registry or WMI is M1-late or M2. Also: a required check that is `skipped` for "no data source" must not count as pass. Default it to `warn` ("not run on this OS") unless the spec marks it `optional`, so a Windows run never exits 0 with five checks silently skipped. Engine design owns the exit-code rule; the catalog should state the default.

### 15. Safe crates map (answer to the `windows-sys` question)
The author is right that direct `windows-sys` calls need `unsafe`. These crates expose safe APIs (they contain the unsafe internally, which `forbid(unsafe_code)` in our crates does not cover):

| Need | Crate | Notes |
| --- | --- | --- |
| Memory, CPU, disks, processes, networks (including MTU), OS version, all OSes | `sysinfo` | Disable default features (the default `multithread` pulls rayon). Do not call `System::new_all()`; refresh only what you need, it is slow. |
| Unix syscalls: statvfs (with mount flags), uname, getrlimit | `rustix` | Pure Rust syscalls on Linux, good for static musl. Use `rustix` only; the plan's `nix` is redundant. Confirm `statvfs` flags and macOS support at the pinned version. |
| Windows registry | `winreg` (or Microsoft's `windows-registry`) | Safe API. Registry reads are fast and need no COM. |
| WMI | `wmi` | Safe API, COM per thread, M2 at the earliest. |
| Listening sockets with PIDs on all three OSes | `listeners` or `netstat2` | Evaluate for macOS and Windows `host.ports`. Would replace both `netstat` parsers and their localization hazards. Keep our own `/proc/net` parser on Linux for UDP, fixtures and no-root behaviour. |
| Plist (macOS `SystemVersion.plist`, ALF) | `plist` | Needed and not in the catalog. |
| TOML (`containerd` config, `agents.toml`) | `toml` | |
| CPU flags | `std::is_x86_feature_detected!` and `std::arch::is_aarch64_feature_detected!` | Safe, all OSes, no `raw-cpuid`. Needs a fixed table of flag names (macros need literals). On Linux, `/proc/cpuinfo` stays for arbitrary names and fixtures. |
| Named pipe (Docker on Windows) | `tokio::net::windows::named_pipe` | Safe, cfg(windows). |

Where "not applicable" is the right M1 answer: `host.lsm`, `host.cgroups`, `host.kernel` (already), `host.sysctl` on macOS too (no server product tunes macOS sysctls), `host.container_runtime` on macOS and Windows (Docker Desktop is a developer box, not a target), `host.security_agents` on Windows, `host.firewall` on macOS and Windows, `host.time_sync` sync-state on macOS and Windows (the SNTP offset is OS independent and can stay).

### 16. `host.disk`: details that will bite
- `/proc/self/mountinfo` escapes spaces and tabs as octal (`\040`). Decode them. Use the mount point (field 5), not the root (field 4). Match on whole path components (`/var` must not match `/variable`) and after resolving symlinks (`/opt` may point into `/usr`). Do the nearest-existing-parent walk and the `canonicalize` inside the `spawn_blocking` closure, because `stat` on a hung NFS mount blocks as well, not only `statvfs`.
- Inodes: skip the check when `f_files == 0` (btrfs and some others report none), not "where the filesystem has fixed inodes". `f_favail` on Linux is just `f_ffree`.
- `f_bavail` excludes root-reserved blocks. Correct for a non-root product, mention in evidence when `rdy` runs as root.
- `noexec`, `nosuid`, `ro` are already in `statvfs.f_flag` on Linux and macOS. That removes the macOS `/sbin/mount` shell-out and gives `noexec` per path without mountinfo. Keep mountinfo for fstype names.
- Windows network drives: `sysinfo` does not expose `GetDriveType`. M1 rule: a path starting with `\\` is a network share; everything else is not detected. Say so.
- Drop `xfs_info`. It is `/usr/sbin/xfs_info`, may need device access, and `ftype=0` is a RHEL 7-era problem. Docker's `/info` already reports `Supports d_type`. Move that to `host.container_runtime` and delete the row.

### 17. `host.ports` more
- `allow_owner` is matched against `/proc/<pid>/comm`, which is cut to 15 bytes. A spec value `acme-controller-manager` never matches. Compare against the basename of `/proc/<pid>/cmdline` argv[0] first, then `comm` as a prefix match on 15 bytes.
- Scan `/proc/*/fd` lazily: first find the conflicting inodes from `/proc/net`, then walk fds only until each inode is found. A box with thousands of processes would otherwise burn the 5s timeout.
- `/proc/net` is per network namespace. Inside a container without `--net=host`, `rdy` sees the container's ports only. Put the netns inode (`readlink /proc/self/ns/net`) in the evidence and warn "container view" when `host.os` says container.
- `systemctl stop {unit}` needs the unit: derive it from `/proc/<pid>/cgroup` (`.../foo.service`), or omit that sentence.
- macOS `netstat -anv` prints addresses as `127.0.0.1.6443` and `*.6443` (port after the last dot). Windows UDP rows have no state column. Both must be in the fixtures.

### 18. `net.mtu`: sources and numbers
- Use `sysinfo::Networks` for macOS and Windows (`NetworkData::mtu()` exists in recent sysinfo; confirm it at the version we pin). That deletes `ifconfig -a` and the PowerShell call, which is slow to start (0.3 to 1.5s cold) and may be blocked by constrained-language policy. If PowerShell stays, use the absolute path and print the exact string in Appendix A; `ConvertTo-Json` returns an object, not an array, when there is one result, so parse both shapes.
- Overlay overhead numbers: published tables use IPIP 20, VXLAN 50 (IPv4 underlay) or 70 (IPv6), WireGuard 60 (IPv4) or 80 (IPv6), Geneve 50 plus options (OVN-Kubernetes reserves 100). The catalog has 50, 58, 80, 20. Use the published values per underlay family and cite the source in the code.
- `warn` for MTU above 1500 fires on every EC2 instance (9001 is the default). Make it informational unless the spec sets `overlay` or an expected MTU.

### 19. `host.time_sync`
- It reads the `Date` skew from `net.egress`. That is a cross-check data channel the engine does not have, the header has 1s granularity, and it couples two checks. Drop it. Report "offset not measured" when no `ntp_servers` are given.
- `adjtimex` through `rustix`: confirm the function exists in the pinned version. If not, `nix::sys::timex::adjtimex` is the safe alternative. Docker's default seccomp profile gates `adjtimex` behind `CAP_SYS_TIME`, so `EPERM` inside a container must map to `partial`, not `error`.
- SNTP details for the ticket: random transmit timestamp and check that the reply echoes it, reject mode not 4, stratum 0 (kiss-of-death) and stratum 16, compute offset as `((T2-T1)+(T3-T4))/2`, use `tokio::net::UdpSocket` (no `spawn_blocking`).
- Remediation is right. `timedatectl show` needs systemd 239 (see item 10).

### 20. `host.sysctl`
- Define precedence in the doc: files in `/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`, `/lib/sysctl.d`; a file name in a higher-priority directory masks the same name below; the union is applied in lexical order of base name; `/etc/sysctl.conf` is applied last. "Later file wins" alone is ambiguous. Handle `#` and `;` comments, `-key` (ignore errors), spaces around `=`.
- Interface names with dots (`net.ipv4.conf.eth0.100.rp_filter`) break "dots to slashes". Accept `/` as a separator in the spec name.
- `RLIMIT_NOFILE` of `rdy` itself is the login shell's limit, not the product service's. Label it "shell limit" in evidence and report the systemd default (`DefaultLimitNOFILE`) as the service-relevant one. Mention `LimitNOFILE=` in the fix.
- Drop the macOS source (item 15).

### 21. `host.os` matching rules
`ID_LIKE` matching with the child's `VERSION_ID` is unsound. Amazon Linux 2 has `ID_LIKE="centos rhel fedora"` and `VERSION_ID=2`; Linux Mint has `ID_LIKE="ubuntu debian"` and `VERSION_ID=21`. Both compare against the wrong numbering. Fix: match `ID` exactly with its own versions; allow `ID_LIKE` only for an explicit list of rebuilds whose `VERSION_ID` tracks the parent (`rocky`, `almalinux`, `ol`, `centos`) or when the spec author lists the derived id. Version rule: `["8","9"]` means major match; `["22.04"]` means exact; define it. Add `/run/.containerenv` (Podman) and `KUBERNETES_SERVICE_HOST` to container detection. Use `/usr/lib/os-release` as the fallback file.

### 22. `net.proxy` details
- NO_PROXY semantics differ by tool (leading dot, `*`, CIDR, ports, IPv6 literals). Pick one and document it. Check whether `hyper_util::client::proxy::matcher` (feature `client-proxy`) is available at our pinned version; it is the logic reqwest uses and gives "would this URL be proxied" in one call. If not, write the matcher once and test it with a table.
- curl ignores uppercase `HTTP_PROXY` (httpoxy); reqwest honours it. Flag that in the "case disagrees" evidence.
- Detect `socks5://`, `socks5h://` and `https://` proxy schemes and report "not supported by rdy in M1" rather than failing the TCP probe.
- Percent-decode userinfo before building `Proxy-Authorization: Basic`. Never log the header.
- Debian and RHEL daemons also read `EnvironmentFile=` (`/etc/sysconfig/docker`, `/etc/sysconfig/kubelet`, RKE2 and K3s `*.env` files). Add as sources only after the first three.
- Windows service context: the HKCU IE proxy does not apply to a service running as SYSTEM; WinHTTP machine settings do. Say so in the evidence; the `WinHttpSettings` blob is binary, so ship as `partial` first.
- Fix text should set both `HTTP_PROXY` and `HTTPS_PROXY` in the Docker drop-in.

### 23. `net.egress` details
- `http://` endpoints through a proxy: send the absolute-form request, not CONNECT. Squid's default denies CONNECT to every port except 443, so a CONNECT to port 80 gives a false `proxy_403`. For `host:port` and `https://` endpoints use CONNECT, and a 403 there is the real finding.
- Dual stack: try each resolved address (cap 4), IPv6 first with the usual 250ms stagger, per-attempt timeout 3s so the total stays under 10s. Report which family failed. A dead AAAA record is a top cause of "hangs".
- `host:port` with no scheme: say whether TLS is attempted. Proposal: TLS only when the port is 443 or the spec sets `tls: true`; otherwise TCP connect only.
- A listener that never calls `accept` does not produce a blackhole: the kernel completes the handshake until the backlog fills. So the test support cannot make a blackhole on loopback. Produce `blackhole` through the scripted connector only (outcome `timeout`) and say that in the ticket. `reset_after_hello` needs a raw server that reads the ClientHello and closes with linger 0; the tokio method for that is deprecated in recent versions, use `socket2`.
- `reset_after_hello` also occurs when a legacy server speaks only TLS 1.0 and 1.1. Name that in the hint and print an `openssl s_client -connect {host}:{port} -servername {host}` command.
- Use `Accept-Encoding: identity` and no compression feature, so evidence and byte counts are honest.
- ALPN: offer `http/1.1` only and report what was negotiated.

### 24. `net.registry`
`HEAD /v2/<repo>/manifests/<tag>` returns the manifest digest, not the blob digest, so "HEAD on the first blob" needs a manifest GET, a multi-arch index decision, and the right `Accept` headers (OCI and Docker v2 types). On Docker Hub a manifest GET counts against the anonymous pull limit and HEAD does not. Fix: use HEAD for existence on `docker.io`; for other registries GET the manifest, then HEAD the config blob (it is served by the same blob host as the layers). Put the multi-arch handling in the ticket text; 3h is tight, say 4h.

### 25. `net.bandwidth`
- Send `Range: bytes=0-{bytes-1}` and `Accept-Encoding: identity`, stream and discard, never buffer. If the response is shorter than 1 MiB, report "sample too small", not a rate. Measure after the first 10 percent to avoid slow-start bias, and say "single stream, lower bound".
- Evidence URL rule from item 11 applies (presigned URLs).
- The "within 20 percent" loopback test will flake on shared macOS and Windows runners. Put the rate maths behind an injected clock and unit test it with fixed `(bytes, instant)` samples. Keep one loose loopback smoke test (within a factor of 2).

### 26. `host.container_runtime`
- The Source gives a version only for Docker and Podman (both speak the Docker HTTP API). containerd (gRPC) and CRI-O have none, yet the Thresholds use `min_version`. Add `containerd --version` and `crio --version` to Appendix A, or drop `min_version` for those two.
- containerd 2.x uses config `version = 3` and the plugin id `io.containerd.cri.v1.runtime`; the fix text uses the 1.x id `io.containerd.grpc.v1.cri`. Detect `version` in `config.toml` and print the matching table path.
- `SystemdCgroup` vs the kubelet's `cgroupDriver` needs `/var/lib/kubelet/config.yaml`, which is not in the Source line.
- Talk to the Docker socket with hyper over `tokio::net::UnixStream` (already in the graph), not a hand-rolled HTTP/1.0 parser and not `bollard`. Windows named pipe via tokio.
- Rootless Docker uses `$XDG_RUNTIME_DIR/docker.sock`. Read that env var.

### 27. `host.firewall`
- firewalld `ports:` lists explicit ports only. A port opened through a service (`kubelet`, `https`) needs the service definition: read `/usr/lib/firewalld/services/<name>.xml` (readable, no extra command) rather than calling `firewall-cmd` again.
- Pick the zone of the default-route interface (`--get-active-zones` plus the interface list), not the default zone.
- Rich rules, ipsets and direct rules cannot be judged from `--list-all`. If any exist, return `unknown`/`warn`, not "verified closed: block". A false block here costs a customer a day.
- ALF: `socketfilterfw --getglobalstate` is the supported interface; the plist is the fallback. Windows: Group Policy keys under `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall` override the service keys; read them first.
- `/etc/ufw/user.rules` is mode 640 root. As non-root report "active, rules not inspected".

### 28. `host.cgroups` remediation
`grub2-mkconfig -o /boot/grub2/grub.cfg` is wrong for RHEL 8 UEFI and awkward everywhere. Use `grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"` for the RHEL family and `update-grub` after editing `/etc/default/grub` on Debian and Ubuntu, chosen from `host.os`. Distinguish three states in the result: v1, hybrid (`/sys/fs/cgroup/unified` present) and v2. Prefer the `statfs` magic of `/sys/fs/cgroup` (cgroup2 `0x63677270`) over file presence.

### 29. `host.cpu`
- `machdep.cpu.features` on Intel Macs does not list AVX2; that is in `machdep.cpu.leaf7_features`. Moot once flags come from `is_x86_feature_detected!`.
- `sysctl.proc_translated` is missing on Intel Macs and exits 1. Treat as not translated. Add `hw.optional.arm64` to know the real hardware when the binary itself is the x86_64 build.
- aarch64 VM detection has no `hypervisor` flag. Add `/sys/class/dmi/id/product_name` and `/sys/hypervisor/type` as best-effort sources.
- Add x86-64 level aliases (`x86-64-v2`, `x86-64-v3`) computed from flags. RHEL 10 and several vendors need v3; spec authors will ask for it.

### 30. Sysinfo and other crates behind the facade, and dev dependencies
- Put every `sysinfo` call behind the `SysSnapshot` facade (item 9) so tests build the struct by hand.
- `rcgen` (0.14 default) and `hickory-server` dev dependencies may pull `aws-lc-rs`. `cargo deny` checks dev dependencies too. Pin `rcgen` with `default-features = false, features = ["ring", "pem"]` and verify `hickory-server`.
- `x509-parser`: avoid the `verify` feature; we verify with rustls.

### 31. Windows "partial" and "skipped" semantics for admin-only data
The text says without admin the Defender exclusion test is `skipped`. Use `partial` (data not readable) vs `skipped` (not applicable), as the degrade rule defines. Keep the two words distinct in the catalog.

---

## Nit

32. `host.memory` band: 5 percent is thin for small sizes. A "4 GB" VM often shows 3.7 GiB (about 7 percent below). Use `max(5%, 256 MiB)` or note the limit.
33. `host.memory`: `MemAvailable` is missing before kernel 3.14 (RHEL 6). If absent use `MemFree + Buffers + Cached` and say "estimated".
34. `host.lsm`: the audit window uses timestamps from `msg=audit(epoch.ms:id)`. State that the last 1 MiB may not cover 24h and say "window truncated" in evidence. On systems without auditd the AVCs are in the journal (not read in M1; say so).
35. `host.lsm`: inside containers `/sys/fs/selinux` is often masked. "File absent means disabled" should read "not visible" when `host.os` says container.
36. `host.kernel`: parse `5.14.0-362.el9.x86_64` with a tolerant parser (`semver` is too strict; keep the dotted compare from the helpers ticket). `modules.dep` lists module paths with `.ko.xz`/`.ko.zst`; match on the base name with `-` and `_` equal.
37. `net.tls_intercept` fix text: add SUSE (`/usr/share/pki/trust/anchors/` plus `update-ca-certificates`), Alpine, and `keytool -importcert -cacerts` for Java. Remind that a Debian file must end in `.crt`.
38. `net.tls_intercept`: when the OS trust store is empty (scratch or Alpine without `ca-certificates`), say "no OS trust store found" instead of classing everything as (c).
39. Hostnames and IPs of customer proxies and nameservers will appear in reports. That is by design, but say it in the privacy section so the redactor owners know it is a conscious choice.
40. The host family header should say what the net header says: checks describe the machine running `rdy`, which may be a bastion, not the target node.
41. `host.ports`: spec shape for "needs a public bind" is not defined (`bind: public|loopback`). Add it to the spec list.
42. `host.sysctl` fix writes with `sudo tee` and `sysctl --system`. Fine. Mention `sysctl -p` is not equivalent for `/etc/sysctl.d`.
43. Use `%SystemRoot%` rather than `C:\Windows` in the Appendix (item 10).
44. Appendix B dates: "CI warns when `checked_on` is older than 180 days" is good. Make the check fail the release workflow, not the PR workflow, or every PR turns red on day 181.
45. Cross-doc: this catalog assumes `02-engine-design.md`, which does not exist yet. The facade list in item 9 and the `skipped` default in item 14 should be copied there when it is written.

---

## Per-check scorecard (Linux source correct? other OS honest? shell-outs pinned? fixtures testable?)

| Check | Linux source | macOS and Windows | Shell-outs | Fixtures | Main item |
| --- | --- | --- | --- | --- | --- |
| `host.disk` | Good | Honest, drop `/sbin/mount` | `xfs_info` not pinned, drop | Good, add escapes | 16 |
| `host.memory` | cgroup path wrong | sysinfo is right | none | Good | 4 |
| `host.ports` | UDP and sysctl bugs, bind | netstat OK, prefer `listeners` | `netsh` bare | Symlink fixtures break | 1, 2, 3, 9, 17 |
| `host.lsm` | Good | N/A is right | none | Mode 0600 not representable | 9, 34 |
| `host.security_agents` | Over-scoped | Cut WMI | `systemextensionsctl` bare | No seed list | 12 |
| `host.firewall` | Zone and service gaps | OK, GPO caveat | bare names | OK | 27 |
| `host.time_sync` | Good, check `adjtimex` crate | SNTP portable | `chronyc` needs `-c` | Good | 19 |
| `host.cpu` | cgroup path wrong | Use std macros | macOS sysctl wrong key | Good | 4, 29 |
| `host.sysctl` | Precedence unstated | Drop macOS | bare path | Good | 20 |
| `host.container_runtime` | Version gap, containerd v3 | N/A in M1 | missing rows | Good | 26 |
| `host.cgroups` | Hybrid state, grub text | N/A right | none | Good | 28 |
| `host.os` | `ID_LIKE` unsound | Fine | none | Good | 21 |
| `host.kernel` | Good | N/A right | none | Good | 36 |
| `net.egress` | Needs staged connector | Same | none | Blackhole not on loopback | 5, 23 |
| `net.proxy` | PAC fetch, NO_PROXY | `scutil` OK | `scutil` pinned | Good | 7, 22 |
| `net.tls_intercept` | Verifier design, clock | Store wording | none | Placeholders needed | 8 |
| `net.dns` | ADR conflict | `getaddrinfo` right | `getent` unpinned | Good | 6 |
| `net.registry` | HEAD vs GET | Same | none | Good | 24 |
| `net.mtu` | Good | Use sysinfo | PowerShell unpinned | Good | 18 |
| `net.bandwidth` | Needs Range and guard | Same | none | Flaky tolerance | 25 |

## Hours (host and net only, plumbing that they need)

| Ticket | Catalog | My estimate | Why |
| --- | --- | --- | --- |
| Command runner | 3 | 2 | Merge with the ADR 0004 blocking helper ticket |
| Fixture loader and golden compare | 3 | 5 | Manifest for symlinks, perms, dirs; facade traits; placeholders; Windows-safe names |
| Units and threshold helpers | 2 | 2 | |
| cgroup path helper (new) | 0 | 2 | Item 4 |
| Redaction helper (moved into M1) | 2 (late) | 2 | Item 11 |
| Loopback test support | 3 | 4 | Four modes of proxy, reset with linger, three OS runners |
| `host.disk` | 4 | 4 | |
| `host.memory` | 3 | 3 | With the helper |
| `host.cpu` | 3 | 3 | Flags through std macros |
| `host.ports` | 3 | 4 | UDP, IPv6, lazy fd scan, comm truncation |
| `host.os` | 2 | 2 | |
| `net.egress` core | 4 | 6 | Staged connector, dual stack, nine classes, redirects |
| `net.egress` via proxy | 3 | 4 | Own CONNECT, absolute-form for http, 407 handling |
| `net.proxy` | 3 | 3 | Only if scope is env plus drop-ins, no PAC fetch |
| `net.tls_intercept` | 4 | 5 | Recording verifier with two stores, clock class, x509 evidence |
| Total | 40 | 51 | +11h. Net M1 goes from 14h to about 24h including moved redaction and loopback. |

If item 5 is accepted, the ADR 0009 "Shared HTTP client builder" ticket (3h) moves to M2, so the net change against the combined plan is about +8h. M1-late host and net tickets look right except `net.registry` (3h to 4h), `host.security_agents` (4h to 3h after the scope cut), `host.firewall` (3h to 4h with the zone and service logic). The macOS and Windows catch-up tickets (3h, 3h, 2h, 3h, 3h) are plausible only if the sysinfo-only subset is done in M1 (item 14); otherwise each is closer to 4h.

## What I am unsure about (verify in a spike before the tickets start)

- Whether `rustix` at the pinned version exposes `adjtimex` / `clock_adjtime`, and whether `statvfs` flags work on macOS. Fallback is `nix`.
- Whether `sysinfo::NetworkData::mtu()` exists in the version we pin.
- Whether `hyper_util::client::proxy::matcher` is public at the version reqwest 0.13 uses.
- `listeners` and `netstat2` maintenance status and musl behaviour. I recommend evaluating, not adopting, until a spike confirms.
- `hickory-resolver` and `hickory-server` default features and their rustls provider, for the `aws-lc-sys` ban.
- Whether `xfs_info` works for a non-root user. Moot if dropped.

## Plan corrections found

- `docs/adr/0006-static-musl-linux.md`, decision 4: `net.dns` is hickory plus an nsswitch warning. The catalog wants `getent` first. Proposed fix: amend the ADR as described in item 6 (rust-architect).
- `docs/adr/0009-http-client-and-tls.md`, decisions 1 and 2: reqwest and a shared builder for "every network check". `net.egress` needs the staged connector. Proposed fix: amend as in item 5 and move the builder ticket to M2.
- `docs/plan/03-check-catalog.md`, `net.proxy`: PAC fetch contradicts ADR 0009 item 2. Proposed fix: item 7.
- `docs/plan/rdy-plan.md`, crate table, `rdy-checks-host` row ("sysinfo, nix, windows-sys"): replace with "sysinfo, rustix, winreg, plist" (item 15).
