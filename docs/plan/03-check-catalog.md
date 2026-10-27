# Rdy check catalog

Every check at launch, grouped by family. Written by check-author. Domain review: k8s-expert (section 4), cloud-iam-expert (section 5), gpu-expert (section 6 and `k8s.device_plugins`). Companion docs: `02-engine-design.md` owns the Check trait, so this file only says what each check needs from it in one line.

How to read this: section 1 holds the rules that apply to every check. Sections 2 to 8 are the families, each ordered by how often that check catches a real install failure (my field judgement, to be re-ranked with portal failure data after M2). Each check has the same six bullets. Appendices list every shell-out and every data file the checks ship.

## 1. Conventions

**Ids.** `<family>.<name>`, lowercase, snake_case name, stable forever (a rename keeps the old id as an alias for one major spec version). Families: `host`, `net`, `k8s`, `gpu`, `store`, `custom`. Cloud checks use the provider as the prefix, not `cloud.`: `aws.iam`, `gcp.iam`, `azure.rbac`. This matches the plan's example spec (`aws.iam`). In this catalog and in the crate (`rdy-checks-cloud`) they are the "cloud" family.

**Tiers.**

| Tier | Meaning |
| --- | --- |
| M1 | In the six-week alpha. Needed for the "one design partner catches a real blocker" exit test. |
| M1-late | Inside the M1 families, but first to slip to the start of M2 if hours run out. See "Capacity" below. |
| M2 to M5 | Not in the alpha. Cloud M3, store M3, GPU M4, `custom.script` M4 (behind an ADR). |

**Capacity warning.** Plan hours for M1 are 60 to 90 (six weeks at 10 to 15 hours). About 42 of those go to workspace, spec, engine, report, signing and release, leaving 18 to 48 hours for checks. The `M1` tier below is about 58 hours including test plumbing, so it already overruns the window. `M1-late` is about 73 more. Windows and macOS data sources are all `M1-late`: every check compiles and runs on all four CI targets from day one, but on an OS without a data source yet it returns `skipped` with reason "no data source for this OS yet". The founder has to choose between a longer M1 and a smaller one. See "Plan corrections found" for the cut order.

**Result words used here.** `pass`, `warn`, `block`, `skipped` (needs not met or not applicable), `timeout`. The engine owns the real names. A check first computes a raw level from its thresholds. The spec `severity` then caps it: `severity: warn` turns a raw block into warn, `info` turns everything into info. Default is `block`.

**Common spec fields** (assumed, `01-spec-format.md` owns the final list): `id`, `severity`, `fix` (replaces the built-in remediation text), `timeout`, `os` (limit the check to some OSes), `optional`. Everything else is per check, listed under Thresholds.

**Units.** Bytes use binary suffixes as in the plan (`32Gi`). Network rates are megabits per second (`Mbit/s`). Durations are `5s`, `7d`.

**Nominal band.** Humans write nominal sizes. A "32 GB" VM shows about 31.3 GiB in `MemTotal`. A "24 GB" L4 or A10G shows about 22.5 GiB of VRAM with ECC on. So size checks have a band below `min`: memory 5% (counts as pass, with a note), VRAM 8% (counts as warn). Spec field `band` overrides it, `band: 0` turns it off.

**Degrade rule.** If a source is unreadable (permission denied, tool missing, API forbidden), the check returns what it could read, marks the result `partial`, and names the privilege that would complete it. A partial check may pass or warn. It never blocks on data it could not read.

**Bounds, for every check.** Read-only. Default timeout 5s for local reads, 15s for network probes, 30s for Kubernetes list calls, 60s hard cap per check. Files read are capped at 1 MiB (log tails: last 1 MiB). Command output capped at 1 MiB. Evidence lists cap at 200 items with a "truncated" flag. Filesystem calls that can hang (NFS `statvfs`) run in `spawn_blocking` under the timeout and report `timeout` rather than waiting.

**Command policy.** Prefer reading a file or calling an API. When a command is unavoidable it runs by fixed argv (no shell), with a scrubbed environment (`LC_ALL=C`, fixed `PATH`; on Windows `SystemRoot` only), output cap, wall timeout and kill on timeout. Appendix A lists them all.

**Redaction in evidence.** Checks record the names of environment variables, not values, except an allow-list (proxy URLs with the userinfo stripped, `NO_PROXY`). Kubeconfig tokens, DSNs, cloud keys and request bodies never enter a result. The redactor in `rdy-bundle` is the second line, not the first.

**Fixtures.** Layout is `tests/fixtures/<check-id>/<case>/` with `root/` (fake file tree, read through the engine's file handle, so `/proc/meminfo` maps to `root/proc/meminfo`), `commands/` (recorded stdout, stderr and exit code per argv), `api/` (recorded JSON or XML responses), and `expect.json` (the golden result). Everything is synthetic: acme names, `*.example` hosts, fake tokens such as `REDACTED-TEST-TOKEN`. Recorded output from real machines is rewritten before it is committed. Each fixture list below is the minimum case set.

**Needs from the engine, one line per check.** Written as `needs: <privilege>, timeout <n>s`. Handles every check may use: file reader, command runner, TCP/TLS/HTTP client, kube client, cloud SDK config. All are injectable so fixtures can replace them.

## 2. Host family (`rdy-checks-host`)

Linux is the first-class target. macOS and Windows sources are listed where they exist and marked M1-late. "Not applicable" means the concept does not exist there.

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `host.disk` | M1 | none | Free space, inodes, mount flags per path |
| 2 | `host.memory` | M1 | none | RAM, swap, cgroup limit |
| 3 | `host.ports` | M1 | root optional | Required ports free |
| 4 | `host.lsm` | M1-late | root optional | SELinux and AppArmor state, recent denials |
| 5 | `host.security_agents` | M1-late | root optional | AV and EDR agents that hook file or process activity |
| 6 | `host.firewall` | M1-late | root optional | Host firewall active, inbound ports allowed |
| 7 | `host.time_sync` | M1-late | none | Clock sync state and skew |
| 8 | `host.cpu` | M1 | none | Cores, arch, CPU flags, virtualization |
| 9 | `host.sysctl` | M1-late | none | Kernel parameters and limits |
| 10 | `host.container_runtime` | M1-late | root optional | Docker, containerd, Podman, CRI-O |
| 11 | `host.cgroups` | M1-late | none | cgroup version and controllers |
| 12 | `host.os` | M1 | none | Distro, version, arch, FIPS |
| 13 | `host.kernel` | M1-late | none | Kernel version and modules |

### host.disk (M1)
- **Measures:** free bytes and free inodes on the filesystem holding each required path (nearest existing parent if the path does not exist yet), filesystem type, mount flags (`noexec`, `nosuid`, `ro`), network filesystems.
- **Source:** L: `statvfs(2)` via `rustix` (`f_bavail * f_frsize`, `f_favail`); `/proc/self/mountinfo` for mount point, fstype and options (longest-prefix match). For overlay2 on XFS, `xfs_info <mount>` to read `ftype` (optional). M: `sysinfo::Disks` for space; `mount` flags from `getfsstat`-style output via `/sbin/mount`; inodes not applicable on APFS. W: `sysinfo::Disks` (`GetDiskFreeSpaceExW`), drive type from `GetDriveType`; inodes and `noexec` not applicable on NTFS.
- **Needs:** none, timeout 5s per path. Degrade: unreadable `xfs_info` gives `ftype: unknown`.
- **Thresholds:** spec `paths: [{path, min_free, recommended_free, min_free_inodes, noexec: forbid, fstype_not: [nfs, cifs, fuse]}]`. Block if free < `min_free`. Warn if free < `recommended_free` (default: `min_free` plus 20%, because installs use more than estimated). Block on a forbidden mount flag or fstype. Inodes default `min_free_inodes: 100000`, only where the filesystem has fixed inodes.
- **Fix:** "`{path}` is on `{mount}` with `{have}` free, `{min}` needed. Run `df -h {path}`. Grow the volume (`lvextend -r -L +{n}G {lv}`) or point the install at a larger disk. For `noexec`: remount without it (`mount -o remount,exec {mount}`) and remove `noexec` from `/etc/fstab`, or move the install path."
- **Fixture:** `mountinfo` files (root xfs, separate `/var` ext4, `/tmp` tmpfs `noexec`, NFS home), a `statvfs.json` table keyed by path, cases: plenty, tight, full inodes, missing parent, `noexec` temp dir, hung NFS (mock returns after the timeout).

### host.memory (M1)
- **Measures:** total RAM, available RAM, swap total and used, and the cgroup memory limit when `rdy` runs inside a container or slice (so the report says "limited by cgroup, host has more").
- **Source:** L: `/proc/meminfo` (`MemTotal`, `MemAvailable`, `SwapTotal`, `SwapFree`); cgroup v2 `/sys/fs/cgroup/memory.max`, v1 `/sys/fs/cgroup/memory/memory.limit_in_bytes`. M: `sysinfo` (`hw.memsize`, vm statistics, `vm.swapusage`). W: `sysinfo` (`GlobalMemoryStatusEx`, page file).
- **Needs:** none, timeout 2s.
- **Thresholds:** spec `min` (total), `min_available`, `swap: off|any` (default `any`), `band`. Total below `min` minus band: block. Inside the band: pass with a note. Available below `min_available` (default 50% of `min`): warn "the box is busy". `swap: off` with swap on: block (kubelet refuses to start with swap unless configured).
- **Fix:** "`{have}` RAM, `{min}` needed. Add RAM or pick a larger node class. A nominal 32 GiB machine shows about 31 GiB, so ask for a size class, not an exact number." Swap: "Run `swapoff -a` and comment out swap lines in `/etc/fstab`."
- **Fixture:** `meminfo` variants (32 GiB VM showing 31.3 GiB, 16 GiB, swap on, low available), cgroup v1 and v2 limit files.

### host.ports (M1)
- **Measures:** which required TCP and UDP ports are already bound, by which process; overlap of required fixed ports with the ephemeral range; ports reserved by the OS.
- **Source:** L: `/proc/net/tcp`, `tcp6`, `udp`, `udp6` (state `0A`), socket inode to process through `/proc/<pid>/fd/*` and `/proc/<pid>/comm`; `/proc/sys/net/ipv4/ip_local_port_range`. Fallback if `/proc/net` is unreadable: try `bind()` on the port and close it (`EADDRINUSE` means used, `EACCES` means unknown). M: `/usr/sbin/netstat -anv -p tcp` (and `udp`), parse listening rows including the PID column. W: `C:\Windows\System32\NETSTAT.EXE -ano` (listening rows found by foreign address `0.0.0.0:0`, because the state word is localized), `netsh int ipv4 show excludedportrange protocol=tcp` for Hyper-V, WSL and Docker reserved ranges. PID to name through `sysinfo`.
- **Needs:** root optional, timeout 5s. Without root the owner of a port held by another user is `unknown`, the port is still reported as in use.
- **Thresholds:** spec `free: [80, 443, 6443, 10250]`, `udp_free: [...]`, `allow_owner: [acme-agent]` (a previous install of the product itself is not a conflict). In use by another process: block. Required port inside the ephemeral range or a Windows excluded range: warn. Bound only to loopback while the product needs a public bind: warn.
- **Fix:** "Port `{p}` is held by `{proc}` (pid `{pid}`). Stop it (`systemctl stop {unit}`) or change the product port in `{setting}`. See owners with `ss -ltnp 'sport = :{p}'`." Ephemeral overlap: "Set `net.ipv4.ip_local_port_range` below `{port}` or add `net.ipv4.ip_reserved_ports={port}`."
- **Fixture:** `/proc/net/tcp` snapshots with matching `/proc/<pid>/fd` symlink trees (`socket:[1234]`), a non-root view where fds are unreadable, `netstat` outputs for macOS and Windows, an excluded-range listing.

### host.lsm (M1-late)
- **Measures:** SELinux mode (runtime and configured), AppArmor enabled and loaded profiles, and recent denials that name watched contexts or programs.
- **Source:** L: SELinux `/sys/fs/selinux/enforce` (`1` enforcing, `0` permissive, file absent means disabled), `/etc/selinux/config` (`SELINUX=`), denials from the tail of `/var/log/audit/audit.log` (`type=AVC ... denied`, last 1 MiB). AppArmor `/sys/module/apparmor/parameters/enabled` (`Y`), profiles from `/sys/kernel/security/apparmor/profiles`. M, W: not applicable.
- **Needs:** root optional, timeout 3s. Without root: modes are still readable, the audit log and profile list are not, so denials are `not inspected`.
- **Thresholds:** spec `selinux: {allow: [enforcing, permissive, disabled], denials_max: 0, denials_window: 24h, watch: [container_t, acme_t]}` and `apparmor: {allow: [...], require_profiles: [...]}`. A mode outside `allow`: block. Denials above `denials_max` in the window: warn (block if the context is in `watch`). Default `allow` is all modes, so with no spec the check is informational.
- **Fix:** "SELinux is enforcing and denied `{n}` actions for `{ctx}`. Read them with `ausearch -m avc -ts recent`. Install the vendor policy module, or label the volume (`chcon -Rt container_file_t {path}` or the `:Z` mount option). Last resort: `setenforce 0` now and `SELINUX=permissive` in `/etc/selinux/config`."
- **Fixture:** `sys/fs/selinux/enforce` and `etc/selinux/config` variants, synthetic `audit.log` excerpts (AVC denied for `container_t`), AppArmor `enabled` and `profiles` files, a root-less run where the audit log is mode 0600.

### host.security_agents (M1-late)
- **Measures:** security software known to hook file, process or network activity in a way that breaks installs or containers: EDR, AV, DLP, backup agents.
- **Source:** matches a shipped catalog (`agents.toml`, Appendix B) against four sources. L: process names from `/proc/*/comm` and `/proc/*/exe` link; directories (`/opt/<agent>`); unit names under `/etc/systemd/system` and `/usr/lib/systemd/system`; loaded modules in `/proc/modules`. M: process names through `sysinfo`; app and support directories (`/Applications/*.app`, `/Library/<agent>`); `systemextensionsctl list` (no argument, parsed defensively). W: process names; service keys under `HKLM\SYSTEM\CurrentControlSet\Services` read with `winreg`; `root\SecurityCenter2` `AntiVirusProduct` through the `wmi` crate (client SKUs only, empty on Server); Defender exclusions from `MSFT_MpPreference` (admin only).
- **Needs:** root optional, timeout 5s. Without root: other users' processes and some directories are invisible, so absence is reported as "not detected (limited view)". Windows Defender exclusion lists need admin; without it the exclusion test is `skipped`.
- **Thresholds:** spec `forbid: [agent ids]`, `allow: [agent ids]`, `require_exclusions: [paths]` (Windows Defender only in M1). Any detected agent not in `allow`: warn. Agent in `forbid`: block. A required path not excluded in Defender: block.
- **Fix:** "Detected `{agent}`. Ask the security team to exclude `{paths}` and the container runtime processes (`{procs}`) from real-time scanning, then rerun. Catalog note: `{risk}`." Windows Defender: "`Add-MpPreference -ExclusionPath '{path}'` in an elevated PowerShell."
- **Fixture:** synthetic process lists, fake `/opt/<agent>` trees, `/proc/modules` lines, registry exports as JSON, a `SecurityCenter2` result, a Defender preference dump. The catalog itself has a unit test per entry.

### host.firewall (M1-late)
- **Measures:** which host firewall manager is active, its default policy, and whether the spec's inbound ports are allowed.
- **Source:** L: firewalld active if `/run/firewalld` exists, then `firewall-cmd --state` and `firewall-cmd --list-all` (works for read as a normal user on most distros); ufw from `/etc/ufw/ufw.conf` (`ENABLED=yes`) and `/etc/ufw/user.rules`; raw `nft list ruleset` and `iptables -S` are root only and are M2. M: `/Library/Preferences/com.apple.alf.plist` (`globalstate`: 0 off, 1 on, 2 block all). W: registry `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{Standard,Domain,Public}Profile\EnableFirewall`. Inbound rule parsing on Windows is M2.
- **Needs:** root optional, timeout 5s. Without root: "firewall active, rules not inspected".
- **Thresholds:** spec `open_inbound: [6443, 10250]`. Verified closed: block. Active but not verifiable: warn. Inactive: pass.
- **Fix:** "firewalld blocks `{port}/tcp`. Run `firewall-cmd --permanent --add-port={port}/tcp && firewall-cmd --reload`" or "`ufw allow {port}/tcp`". Windows: "`New-NetFirewallRule -DisplayName acme -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow`."
- **Fixture:** firewalld `--list-all` recorded output (public zone with and without the port), `ufw.conf` and `user.rules`, registry JSON, a root-less run.

### host.time_sync (M1-late)
- **Measures:** whether the clock is synchronized, by what, and the offset against a reference.
- **Source:** L: `adjtimex(2)` with `modes = 0` through `rustix` (read only, no privilege): `STA_UNSYNC` and estimated error. Then `timedatectl show -p NTPSynchronized -p NTP -p Timezone`, `chronyc -n tracking` (field "System time" and "Leap status"). Offset against a reference: an in-process SNTP client (48-byte UDP packet) to the servers in spec `ntp_servers`. No default servers, because offline-first means no surprise outbound traffic; if none are given, the check uses the `Date` header skew that `net.egress` already measured, else reports "offset not measured". M: SNTP client, `systemsetup` needs admin so it is not used. W: SNTP client plus registry `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type` and service state.
- **Needs:** none, timeout 5s (SNTP 3s per server).
- **Thresholds:** spec `max_skew` (default: warn above 5s, block above 300s, because AWS signing, Kerberos and TLS validity all fail near 5 minutes), `require_sync: true|false`. Not synchronized and `require_sync`: block.
- **Fix:** "Clock is `{off}` away from `{ref}` and not synchronized. Run `timedatectl set-ntp true`, or install chrony (`dnf install chrony && systemctl enable --now chronyd`, then `chronyc makestep`). On VMs also enable host time sync (VMware Tools, Hyper-V integration services)."
- **Fixture:** `adjtimex` result JSON, `timedatectl` and `chronyc tracking` recorded output, a hex-encoded SNTP response with a known offset, loopback SNTP responder.

### host.cpu (M1)
- **Measures:** logical and physical cores (respecting cgroup CPU quota and affinity), architecture, model, feature flags, whether it is a VM, and whether `rdy` itself runs under Rosetta.
- **Source:** L: `std::thread::available_parallelism` (honours quota), `/sys/devices/system/cpu/online`, `/sys/devices/system/cpu/cpu*/topology/{core_id,physical_package_id}`, `/proc/cpuinfo` (`flags` on x86, `Features` on arm, `hypervisor` flag), `/sys/fs/cgroup/cpu.max`. M: `sysinfo` counts, `sysctl -n machdep.cpu.features` and `sysctl -n sysctl.proc_translated` (1 means Rosetta). W: `sysinfo` counts; flags through `raw-cpuid` on x86.
- **Needs:** none, timeout 2s.
- **Thresholds:** spec `min_cores`, `recommended_cores`, `arch: [x86_64, aarch64]`, `flags: [avx2, bmi2]`. Below `min_cores`, wrong arch or a missing flag: block. Below `recommended_cores`: warn. Running translated: warn.
- **Fix:** "`{n}` vCPU, `{min}` needed. Resize the instance. Missing `avx2`: set the VM CPU model to host passthrough (libvirt `<cpu mode='host-passthrough'/>`), turn off VMware EVC masking, or on Hyper-V run `Set-VMProcessor -VMName {vm} -CompatibilityForMigrationEnabled $false`."
- **Fixture:** `/proc/cpuinfo` with and without `avx2`, with `hypervisor`, arm `Features`; `cpu.max` quota file; macOS sysctl outputs including `proc_translated=1`.

### host.sysctl (M1-late)
- **Measures:** kernel parameters and file limits against the spec, and whether a live value survives a reboot.
- **Source:** L: `/proc/sys/<dotted name with dots as slashes>`; persistence from `/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/usr/lib/sysctl.d/*.conf`, `/run/sysctl.d/*.conf` (later file wins); limits from `/etc/systemd/system.conf` and `system.conf.d` (`DefaultLimitNOFILE`), `/proc/sys/fs/nr_open`, `/proc/sys/fs/file-max`, own `RLIMIT_NOFILE` through `rustix`. M: `/usr/sbin/sysctl -n <name>`. W: not applicable.
- **Needs:** none, timeout 2s.
- **Thresholds:** no built-in defaults, the spec lists them: `expect: {vm.max_map_count: ">=262144", net.ipv4.ip_forward: "1", fs.inotify.max_user_watches: ">=524288"}`, `limits: {nofile: ">=65536"}`. Wrong live value: block. Right live value but not persisted: warn.
- **Fix:** "`vm.max_map_count` is `{have}`, need `262144`. Run `sysctl -w vm.max_map_count=262144` and persist it: `echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/90-acme.conf && sudo sysctl --system`."
- **Fixture:** fake `/proc/sys` tree, `sysctl.d` files with a later file overriding an earlier one, `system.conf`.

### host.container_runtime (M1-late)
- **Measures:** which runtime is present, its version, cgroup driver, storage driver, daemon proxy settings, rootless mode, and that the socket is reachable.
- **Source:** L: sockets `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/podman/podman.sock`, `/var/run/crio/crio.sock` (stat, then connect); Docker Engine API over the unix socket (`GET /version`, `GET /info`); `/etc/docker/daemon.json`; `/etc/containerd/config.toml` (`SystemdCgroup`, runtimes); systemd drop-ins `/etc/systemd/system/{docker,containerd}.service.d/*.conf` (proxy `Environment=`). M: `~/.docker/run/docker.sock`, `/var/run/docker.sock`. W: named pipe `\\.\pipe\docker_engine` (`GET /version`).
- **Needs:** root optional (socket group), timeout 5s. Without access: "runtime present, API not readable, add the user to the `docker` group or run as root".
- **Thresholds:** spec `runtime: [docker, containerd]` (any of), `min_version`, `cgroup_driver: systemd`, `storage_driver: overlay2`. No runtime: block. Version or driver mismatch: block.
- **Fix:** "containerd uses cgroupfs but kubelet uses systemd. Set `SystemdCgroup = true` under `[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]` in `/etc/containerd/config.toml`, then `systemctl restart containerd`."
- **Fixture:** `daemon.json` and `config.toml` variants, drop-in files, recorded Docker API JSON replayed by a mock unix-socket server.

### host.cgroups (M1-late)
- **Measures:** cgroup version, which controllers are available and delegated, kernel boot options.
- **Source:** L: `/sys/fs/cgroup/cgroup.controllers` (present means v2), `/sys/fs/cgroup/cgroup.subtree_control`, `/proc/cgroups` (v1, `enabled` column), `/proc/self/mountinfo` (`cgroup2` or `cgroup`), `/proc/cmdline`. M, W: not applicable.
- **Needs:** none, timeout 2s.
- **Thresholds:** spec `version: v2|v1|any`, `controllers: [cpu, memory, io, pids]`. A required controller missing: block. Wrong version: block.
- **Fix:** "Boot with `systemd.unified_cgroup_hierarchy=1`: add it to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `grub2-mkconfig -o /boot/grub2/grub.cfg`, reboot. On Raspberry Pi OS add `cgroup_memory=1 cgroup_enable=memory` to `/boot/firmware/cmdline.txt`."
- **Fixture:** fake `/sys/fs/cgroup` trees (v1 hybrid, v2, memory controller off), `/proc/cgroups`, `/proc/cmdline`.

### host.os (M1)
- **Measures:** distro, version, architecture, init system, container or WSL, FIPS mode.
- **Source:** L: `/etc/os-release` (`ID`, `ID_LIKE`, `VERSION_ID`), `uname` through `rustix`, `/run/systemd/system`, `/.dockerenv`, `/proc/sys/kernel/osrelease` (contains `microsoft` under WSL), `/proc/sys/crypto/fips_enabled`. M: `/System/Library/CoreServices/SystemVersion.plist`. W: registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`CurrentBuild`, `UBR`, `DisplayVersion`, `InstallationType`; use the build number, since `ProductName` says Windows 10 on Windows 11).
- **Needs:** none, timeout 2s.
- **Thresholds:** spec `supported: [{id: rhel, versions: ["8", "9"]}, {id: ubuntu, versions: ["22.04", "24.04"]}]` (matches `ID` then `ID_LIKE`), `arch`, `fips: forbid|require|any`, `windows_min_build`. Unsupported distro or version: block. FIPS mismatch: block. Running inside a container or WSL when the spec expects bare metal: warn.
- **Fix:** "This product supports RHEL 8 and 9, found `{pretty_name}`. Use a supported image or ask the vendor about `{id}`."
- **Fixture:** `os-release` files (RHEL 9, Ubuntu 22.04, Amazon Linux 2023, Alpine, Rocky as `ID_LIKE=rhel`), `SystemVersion.plist`, registry JSON for Server 2022 and Windows 11.

### host.kernel (M1-late)
- **Measures:** kernel version and whether needed modules and features exist.
- **Source:** L: `uname` release through `rustix` (parse `5.14.0-362.el9.x86_64` as `5.14.0`); modules from `/proc/modules` (loaded), `/lib/modules/<release>/modules.builtin` (built in), `/lib/modules/<release>/modules.dep` (available, loadable); BTF at `/sys/kernel/btf/vmlinux`. M, W: not applicable (see `host.os`).
- **Needs:** none, timeout 2s.
- **Thresholds:** spec `min: "5.4"`, `distro_min: {rhel: "4.18.0-305"}` (vendor kernels backport features, so the upstream number can mislead), `modules: [overlay, br_netfilter, nf_conntrack]`, `btf: true`. Kernel below minimum: block. Module absent: block. Module available but not loaded: warn.
- **Fix:** "Load `br_netfilter` now and at boot: `modprobe br_netfilter && echo br_netfilter | sudo tee /etc/modules-load.d/acme.conf`."
- **Fixture:** `uname` strings, `/proc/modules`, small `modules.builtin` and `modules.dep` excerpts.

## 3. Network family (`rdy-checks-net`)

All network checks run in process on every OS, so the Source line is the same for L, M and W unless stated. They probe from the machine running `rdy`. That is not the same as a cluster node. See `k8s.egress_probe` in "Reserved ids".

Shared library code: a custom `tokio-rustls` connector (not `reqwest`, because `reqwest` does not expose the peer certificate chain), `rustls-native-certs` for the OS trust store, `webpki-roots` as the public baseline, `x509-parser` for certificates, `hickory-resolver` for direct DNS. Plan correction recorded below.

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `net.egress` | M1 | none | TCP, TLS and HTTP to required endpoints, direct and via proxy |
| 2 | `net.proxy` | M1 | none | The proxy settings the product would really see |
| 3 | `net.tls_intercept` | M1 | none | Is a middlebox re-signing TLS |
| 4 | `net.dns` | M1-late | none | Names resolve, by the system and by each nameserver |
| 5 | `net.registry` | M1-late | none | OCI registry API, token host and blob host |
| 6 | `net.mtu` | M1-late | none | Interface MTU and overlay headroom |
| 7 | `net.bandwidth` | M1-late | none | Download throughput sample |

### net.egress (M1)
- **Measures:** for each endpoint: DNS, TCP connect, TLS handshake (chain, SNI, ALPN), optional HTTP request; direct and through the proxy; latency; clock skew from the HTTP `Date` header; every host contacted while following redirects (so the spec author learns CDN hosts from one run).
- **Source:** in process. Endpoint forms: `host:port` or a URL. Proxy resolution comes from `net.proxy`. HTTP proxies use `CONNECT`; Basic auth only, from the proxy URL. 407 with `Negotiate` or `NTLM` is reported, not attempted. Trust store: system, with the bundled public roots as fallback, and the evidence says which was used. Redirects: up to 5, host list recorded.
- **Needs:** none, connect plus TLS 10s per endpoint, HTTP 15s, 8 endpoints in parallel, 60s total.
- **Thresholds:** spec `endpoints: [str | {url, expect_status: [200, 401], optional, method: HEAD|GET, via_proxy}]`, `via_proxy: auto|direct|proxy_only` (`auto` tries what the product would do and, if that fails but the other path works, says so), `trust: system|bundled`, `max_latency` (default warn above 2s connect). An unreachable required endpoint: block. An `optional` endpoint: warn. Date skew above 300s: warn. Failure classes, each with its own text: `dns`, `refused`, `blackhole` (SYN unanswered), `tls_unknown_issuer` (points to `net.tls_intercept`), `tls_alert`, `reset_after_hello` (SNI filtering), `proxy_407`, `proxy_403` (CONNECT denied by allow-list), `http_status`.
- **Fix:** per class. Blackhole: "No reply to SYN from `{ip}:{port}` in 10s, a firewall is dropping it. Ask the network team to allow tcp/`{port}` to `{host}` from `{source_ip}`." Proxy 403: "The proxy refused CONNECT to `{host}:{port}`. Ask the proxy team to add it to the allow list." Direct fails, proxy works: "Set `HTTPS_PROXY={proxy}` for the product service, not only your shell."
- **Fixture:** an injectable connector driven by a JSON script of outcomes per `host:port` for unit tests. For integration tests, loopback servers from the shared test support module: TLS server with a generated test CA (`rcgen`), CONNECT proxy with modes `ok|403|407-basic|407-negotiate`, a closed port, a listener that never accepts, a server that resets after ClientHello, a 302 to a second loopback port.

### net.proxy (M1)
- **Measures:** the proxy configuration in effect, where each setting comes from, whether daemons have it too, whether `NO_PROXY` covers internal destinations, whether the proxy is reachable.
- **Source:** L: process environment (`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`, `no_proxy`; flag upper and lower case that disagree); `/etc/environment`, `/etc/profile.d/*.sh` (lines matching `proxy`), `/etc/apt/apt.conf.d/*`, `/etc/dnf/dnf.conf` and `/etc/yum.conf` (`proxy=`), `/etc/systemd/system.conf` (`DefaultEnvironment`), drop-ins for `docker`, `containerd`, `kubelet` units, `~/.docker/config.json` (`proxies`). M: `/usr/sbin/scutil --proxy` (parse `HTTPSEnable`, `HTTPSProxy`, `HTTPSPort`, `ProxyAutoConfigURLString`, `ExceptionsList`). W: registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`), and the WinHTTP machine proxy blob in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings`. PAC files: fetched (cap 256 KiB) and listed, not evaluated, because that needs a JavaScript engine.
- **Needs:** none, timeout 5s. Userinfo in any proxy URL is stripped before recording.
- **Thresholds:** spec `required_no_proxy: [".svc", ".cluster.local", "10.0.0.0/8", "169.254.169.254"]`, `daemons_need_proxy: true|false`. Proxy TCP unreachable: block. Required `NO_PROXY` entry missing: warn (block if the spec says so). Proxy set for the shell but not for docker, containerd or kubelet while they are present: warn (block with `daemons_need_proxy`). PAC in use: warn "rdy cannot evaluate PAC" and list the `PROXY host:port` strings found in it as candidates.
- **Fix:** "Docker does not see the proxy. Create `/etc/systemd/system/docker.service.d/http-proxy.conf` with `[Service]` and `Environment=\"HTTPS_PROXY={proxy}\" \"NO_PROXY={no_proxy}\"`, then `systemctl daemon-reload && systemctl restart docker`."
- **Fixture:** environment maps, fake `/etc` trees with and without drop-ins, `scutil --proxy` output, registry JSON including a WinHTTP blob, a sample PAC file.

### net.tls_intercept (M1)
- **Measures:** whether TLS to each host is terminated by a middlebox, who issued the presented chain, and whether that issuer is trusted on this machine.
- **Source:** one handshake per host with a probe verifier that records the chain and then closes without sending any application data. Classification: (a) chain validates to a bundled public root: no interception; (b) validates only against the OS store and the root is not in the bundled set: a private CA is trusted locally, likely an inspection proxy; (c) validates nowhere: interception CA not installed, product HTTP clients will fail. Evidence: issuer and subject names, chain depth, SHA-256 of the root, validity dates, SAN match, which OS store file holds the root. Also reports which other trust stores exist on the box (Java `cacerts` under `/usr/lib/jvm/*/lib/security/`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`) because each runtime keeps its own. The probe verifier is the only place `rdy` accepts an unverified chain. See ADR list.
- **Needs:** none, same limits as `net.egress`. Hosts default to the hosts in the spec's `net.egress` endpoints.
- **Thresholds:** spec `hosts`, `expected_issuer: <regex>`, `pin_sha256: [..]`, `forbid_interception: true|false`. (a): pass. (b): warn, block if `forbid_interception` (vendors with certificate pinning or mutual TLS cannot cross an inspecting proxy). (c): block. Issuer not matching `expected_issuer`: block.
- **Fix:** "`{host}` is re-signed by `{issuer}`. Either ask the network team to bypass inspection for `{host}`, or install that CA. Debian and Ubuntu: copy it to `/usr/local/share/ca-certificates/acme-inspection.crt`, run `update-ca-certificates`. RHEL: copy to `/etc/pki/ca-trust/source/anchors/`, run `update-ca-trust`. Container images and Java do not read the host store: add the CA to each."
- **Fixture:** DER chains generated at test time with `rcgen`: public-style chain, private-CA chain whose root is in a fake system store directory, unknown-CA chain. Recorded handshakes are replayed through the injectable connector. Unit test: the probe sends zero application bytes.

### net.dns (M1-late)
- **Measures:** whether required names resolve the way the product's own resolver would resolve them, whether each configured nameserver agrees, latency, and the resolver settings that cause trouble.
- **Source:** L: system lookup through `getent ahostsv4 <name>` (glibc behaviour: `nsswitch.conf`, `search`, mDNS and sssd, which a static musl `getaddrinfo` does not honour); direct lookups with `hickory-resolver` against each nameserver in `/etc/resolv.conf`, or `/run/systemd/resolve/resolv.conf` when the first one is the `127.0.0.53` stub; `nsswitch.conf` `hosts:` line (flag `mdns4_minimal [NOTFOUND=return]` in front of `dns`). M: `getaddrinfo` in process, nameservers from `/usr/sbin/scutil --dns`. W: `getaddrinfo` in process, nameservers from registry `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*` (`NameServer`, `DhcpNameServer`).
- **Needs:** none, 5s per lookup, 8 names in parallel.
- **Thresholds:** spec `names: [str | {name, expect_in: ["10.0.0.0/8"], expect_public: true}]`, `max_ms` (default warn above 500). System lookup fails: block. Direct and system answers differ (split horizon): warn. A nameserver times out while another answers: warn "slow first hop adds a timeout to every lookup". `expect_in` not satisfied: block (private endpoint resolving to a public address).
- **Fix:** "`{name}` does not resolve through `{resolver}`: nameserver `{ip}` answered `{rcode}`. Ask the DNS team for a conditional forwarder for `{zone}`, or add a temporary line to `/etc/hosts`."
- **Fixture:** `resolv.conf` (stub and real), `nsswitch.conf`, recorded `getent` output (found, not found, timeout), an in-process scripted DNS server (`hickory-server`, dev dependency) with zones for NXDOMAIN, SERVFAIL, delayed and split answers.

### net.registry (M1-late)
- **Measures:** an OCI registry works end to end: API ping, auth token host, manifest, and the host that serves layer blobs.
- **Source:** `GET https://<host>/v2/` (200 or 401); parse `WWW-Authenticate: Bearer realm=...,service=...` and probe the realm host; for spec images that are public, anonymous token then `HEAD /v2/<repo>/manifests/<tag>` and `HEAD` on the first blob, following the redirect and probing that host. Never reads or sends credentials. Reports registry mirror settings found in `/etc/docker/daemon.json` and `/etc/containerd/certs.d/*`. Docker Hub rate-limit headers when present.
- **Needs:** none, 15s per step.
- **Thresholds:** spec `registries: [host | {host, images: [repo:tag], optional}]`. `/v2/` fails: block. Token realm or blob redirect host unreachable: block (the classic: manifests work, layers hang). Private image answers 401: warn "needs credentials, not verifiable". Rate limit remaining below 10: warn.
- **Fix:** "`{registry}` answers but its blob store `{cdn}` is blocked, so pulls fail on layers with timeouts or `unexpected EOF`. Allow `{cdn}:443`."
- **Fixture:** loopback registry mock: 401 with a Bearer header, token endpoint, manifest `HEAD`, blob `307` to a second loopback port that is open or closed.

### net.mtu (M1-late)
- **Measures:** MTU of the default-route interface and other up interfaces, VPN and tunnel interfaces, and headroom for an overlay network. It does not measure path MTU (see `net.pmtu`, reserved).
- **Source:** L: `/sys/class/net/<if>/{mtu,operstate,type}`, default route from `/proc/net/route` and `/proc/net/ipv6_route`. M: `/sbin/ifconfig -a` (`mtu` field), default route from `/usr/sbin/netstat -rn -f inet`. W: `powershell.exe -NoProfile -NonInteractive -Command "Get-NetIPInterface | Select InterfaceAlias,AddressFamily,NlMtu | ConvertTo-Json"`.
- **Needs:** none, timeout 3s.
- **Thresholds:** spec `min_mtu`, `overlay: vxlan|geneve|wireguard|ipip` (overhead 50, 58, 80, 20 bytes). Default interface MTU below `min_mtu`, or below 1400 with no spec: warn. Interface MTU minus overlay overhead below `min_mtu`: block. Interface MTU above 1500 (for example 9001 in AWS): warn "traffic leaving the network clamps to 1500, make sure ICMP 'fragmentation needed' is not filtered".
- **Fix:** "`eth0` has MTU 1450 and VXLAN needs 50 bytes, so the pod network must use 1400 or less. Set the CNI MTU to `{n}`."
- **Fixture:** `/sys/class/net` trees, `/proc/net/route`, `ifconfig` output, PowerShell JSON.

### net.bandwidth (M1-late)
- **Measures:** single-stream download rate and time to first byte from a vendor-chosen URL.
- **Source:** in process GET through the resolved proxy, stopped at `bytes` (default 10 MiB, max 100 MiB) or 10s. No upload in any case. No default URL: nothing leaves the box that the spec did not name.
- **Needs:** none, 15s.
- **Thresholds:** spec `url`, `bytes`, `min_mbps` (block), `recommended_mbps` (warn). No thresholds in the spec: informational.
- **Fix:** "`{x}` Mbit/s to `{host}`. Pulling `{size}` takes about `{t}`. Use a registry mirror in this region or the offline bundle."
- **Fixture:** loopback server throttled by a token bucket; the test asserts the measured rate within 20% of the configured one.

## 4. Kubernetes family (`rdy-checks-k8s`)

Client: `kube` with rustls. Kubeconfig order is `--kubeconfig`, `KUBECONFIG`, `~/.kube/config`, then in-cluster. `--context` and `--namespace` flags. Calls are GET and LIST only, with `limit=500` pagination and a 5000 object cap per list, plus two review APIs that are POSTs but store nothing: `SelfSubjectAccessReview` and `SelfSubjectReview`. Every other check depends on `k8s.access` and becomes `skipped: no cluster access` if it fails. Exec credential plugins named in the kubeconfig (`aws`, `gke-gcloud-auth-plugin`, `kubelogin`) are run by `kube` as that file says; the report names which binary was run.

Fixtures for all of them: a directory of recorded API responses (`api/v1/nodes.json`, `apis/storage.k8s.io/v1/storageclasses.json`, and so on, captured with `kubectl get --raw` and rewritten to acme names) served by a `tower` mock service, so no sockets and no cluster are needed.

Common RBAC degrade: a `403` on a list call turns that check partial with the exact verb, group and resource that was denied, so the customer can grant it or run with a broader identity.

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `k8s.access` | M1 | kube context | Kubeconfig, API reachable, auth works |
| 2 | `k8s.storageclass` | M1 | kube read | Default class, CSI driver present, binding mode, access modes |
| 3 | `k8s.rbac` | M1 | kube context | Can the install identity do what the installer does |
| 4 | `k8s.admission` | M1-late | kube read | What can reject our pods: PSA, webhooks, policy engines |
| 5 | `k8s.nodes` | M1 | kube read (nodes, pods) | Allocatable and free capacity, conditions, zones, taints |
| 6 | `k8s.version` | M1 | none beyond access | Server version, API availability |
| 7 | `k8s.namespace` | M1-late | kube read | Namespace, quota, limit range |
| 8 | `k8s.ingress` | M1-late | kube read | IngressClass, Gateway API, LoadBalancer works |
| 9 | `k8s.crds` | M1-late | kube read | Required CRDs and operators |
| 10 | `k8s.cni` | M1-late | kube read | CNI, NetworkPolicy support, default-deny, CIDRs |
| 11 | `k8s.dns` | M1-late | kube read | CoreDNS healthy, no forward loop |
| 12 | `k8s.device_plugins` | M1-late | kube read | Extended resources such as `nvidia.com/gpu` |

### k8s.access (M1)
- **Measures:** kubeconfig found, current context, API server reachable, credentials accepted, server certificate verified, credential expiry, latency, and whether a proxy sits in the path.
- **Source:** `kube::Config::infer`; `GET /version` and `GET /api` (open to `system:public-info-viewer`), `GET /readyz?verbose` when allowed. Client certificate `notAfter` and a JWT `exp` claim are read locally, the token itself is never recorded. `insecure-skip-tls-verify`, `proxy-url`, and `HTTPS_PROXY`/`NO_PROXY` handling are reported (an API server reached through a corporate proxy by accident is a common failure). Same on L, M and W; kubeconfig path rules differ only by home directory.
- **Needs:** kube context, timeout 10s.
- **Thresholds:** spec `context_pattern` (regex, guard against the wrong cluster), `max_latency`. No kubeconfig, unreachable, 401 or 403: block. `insecure-skip-tls-verify: true`: warn. Credential expires in under 7 days: warn. Context not matching `context_pattern`: block.
- **Fix:** "`x509: certificate signed by unknown authority`: the kubeconfig CA does not match, or a proxy re-signs TLS (run `net.tls_intercept`). `Unauthorized`: credentials expired. EKS: `aws eks update-kubeconfig --name {cluster} --region {region}`. GKE: `gcloud container clusters get-credentials {cluster}`. AKS: `az aks get-credentials -g {rg} -n {cluster}`."
- **Fixture:** synthetic kubeconfigs (token, client cert, exec plugin, no file), mock responses: `/version`, 401 and 403 `Status` bodies, TLS failure, slow reply.

### k8s.storageclass (M1)
- **Measures:** a usable default `StorageClass`, the named class if the spec names one, that a CSI driver exists for each CSI provisioner, binding mode, expansion, and whether the class can serve the required access modes.
- **Source:** `storage.k8s.io/v1` `StorageClass` list (default marker annotation `storageclass.kubernetes.io/is-default-class`, legacy `storageclass.beta.kubernetes.io/is-default-class`), `CSIDriver` list (`storage.k8s.io/v1`). If listing is forbidden, GET by name when the spec names a class, else partial. Access modes cannot be read from a class, so they come from the shipped provisioner table (Appendix B): for example `ebs.csi.aws.com`, `pd.csi.storage.gke.io` and `disk.csi.azure.com` give RWO; `efs.csi.aws.com`, `file.csi.azure.com`, `nfs.csi.k8s.io` and CephFS give RWX. Unknown provisioner: the result says "access modes not verified". A canary PVC is not created (read-only rule).
- **Needs:** kube read on storageclasses and csidrivers, timeout 30s.
- **Thresholds:** spec `class`, `needs: [ReadWriteOnce, ReadWriteMany]`, `volume_mode`, `binding: WaitForFirstConsumer`, `expansion: true`. No default and no named class: block. Named class missing: block. Required access mode not supported: block (the plan example uses `severity: warn`). CSI provisioner without a `CSIDriver`: block. More than one default: warn (behaviour differs by version). `Immediate` binding on a zonal provisioner in a multi-zone cluster: warn. Expansion wanted but off: warn.
- **Fix:** "No default StorageClass, so a PVC without a class stays Pending. Mark one: `kubectl patch storageclass {name} -p '{\"metadata\":{\"annotations\":{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}'`. No CSI driver: install it. EKS: `aws eks create-addon --cluster-name {c} --addon-name aws-ebs-csi-driver`."
- **Fixture:** `StorageClass` lists: none, one non-default, two defaults, `Immediate` zonal, `kubernetes.io/no-provisioner`, unknown provisioner; `CSIDriver` lists with and without the driver.

### k8s.rbac (M1)
- **Measures:** whether the identity in the kubeconfig can do each thing the installer does, and who that identity is.
- **Source:** `authentication.k8s.io/v1` `SelfSubjectReview` (GA in 1.28) for user and groups; `authorization.k8s.io/v1` `SelfSubjectAccessReview` per spec item (create only, nothing stored, up to 100 per run, 8 at a time). Item shape `{verb, group, resource, subresource?, namespace?, name?}`. `SelfSubjectRulesReview` is used only to print what the identity can do in the target namespace when something is denied. Optional `--as` sends `Impersonate-User`. Also adds `escalate` and `bind` probes when the spec creates `ClusterRole` or `ClusterRoleBinding` objects, because RBAC escalation prevention fails an installer that holds `create` but not the rights it grants.
- **Needs:** kube context, timeout 30s.
- **Thresholds:** spec `can: [...]`. Any item denied: block, listed with the reviewer's `reason`. `evaluationError` set: warn.
- **Fix:** "`{user}` cannot `{verb}` `{resource}` in `{ns}`. Ask the cluster admin for a binding. Vendor minimal role: `kubectl apply -f {role_url}`; quick test only: `kubectl create clusterrolebinding acme-installer --clusterrole=cluster-admin --user={user}`."
- **Fixture:** a table mapping review attributes to allowed or denied (the mock answers per request), `SelfSubjectReview` JSON, a case with `evaluationError`.

### k8s.admission (M1-late)
- **Measures:** what can reject the product's pods or objects: Pod Security Admission levels on the namespace, admission webhooks and whether their backends are up, `ValidatingAdmissionPolicy`, Kyverno, Gatekeeper, OpenShift SCCs.
- **Source:** `Namespace` labels `pod-security.kubernetes.io/{enforce,audit,warn}` and `-version`; `admissionregistration.k8s.io/v1` `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`, `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding` (GA 1.30); for each webhook with `failurePolicy: Fail` that matches the namespace, the `Service` and `discovery.k8s.io/v1` `EndpointSlice` behind it (no ready endpoint blocks every create); engine presence by discovery of `kyverno.io`, `templates.gatekeeper.sh`, `constraints.gatekeeper.sh`, `security.openshift.io`, listing enforcing policies only by name. The cluster-wide PSA default lives in the API server config and is not readable; the check says so. Optional mode `dry_run: true`: server-side dry-run create (`?dryRun=All`) of the spec's `probe_pod` manifest, which runs the whole admission chain and returns the real denial text. Default off, see ADR list.
- **Needs:** kube read, timeout 30s. Without list rights on cluster-scoped webhook configs the check reports PSA and discovery only, partial.
- **Thresholds:** spec `needs_pod_security: privileged|baseline|restricted`, `namespace`, `probe_pod`, `dry_run`. PSA `enforce` stricter than needed: block. `warn` or `audit` stricter: warn. `Fail` webhook with no ready endpoint matching the namespace: block. Enforcing Kyverno or Gatekeeper policies present: warn "policy engine present, N enforcing policies, review". OpenShift detected: warn with the SCC text unless the spec states `scc`.
- **Fix:** "Namespace `{ns}` enforces `restricted`; the product needs `baseline` (hostPath volumes). Either `kubectl label ns {ns} pod-security.kubernetes.io/enforce=baseline --overwrite` or ask the vendor for restricted-compatible chart values." OpenShift: "`oc adm policy add-scc-to-user {scc} -z {sa} -n {ns}`."
- **Fixture:** `Namespace` JSON with label variants, webhook configs with `EndpointSlice` present and empty, a `ValidatingAdmissionPolicy`, discovery documents for Kyverno, Gatekeeper and OpenShift, recorded dry-run denial `Status` bodies (`violates PodSecurity "restricted:latest"`).

### k8s.nodes (M1)
- **Measures:** ready nodes, allocatable and free capacity on the nodes the product can use, conditions, taints, zones, architecture and OS, kubelet and runtime versions.
- **Source:** `v1` `Node` list: `status.allocatable` and `capacity` (`cpu`, `memory`, `ephemeral-storage`, `pods`, `hugepages-*`), `status.conditions` (`Ready`, `MemoryPressure`, `DiskPressure`, `PIDPressure`, `NetworkUnavailable`), `spec.taints`, `spec.unschedulable`, labels `topology.kubernetes.io/zone`, `kubernetes.io/arch`, `kubernetes.io/os`, `node.kubernetes.io/instance-type`, `status.nodeInfo` (`kubeletVersion`, `containerRuntimeVersion`, `kernelVersion`). Free capacity is allocatable minus the requests of non-terminal pods, from a `v1` `Pod` list across namespaces (capped; if forbidden, the check compares allocatable only and says so). Nodes count only if they match the spec `selector` and the product tolerates their taints.
- **Needs:** kube read on nodes, pods optional, timeout 30s.
- **Thresholds:** spec `nodes: {min_ready: 3, min_zones: 3, per_node: {cpu: 8, memory: 32Gi, ephemeral: 100Gi}, free: {cpu: 16, memory: 64Gi}, arch: [amd64], selector: {...}, tolerations: [...]}`. Fewer ready matching nodes, per-node size too small, or free capacity short: block (warn below 120% of need). `NotReady` or pressure on a matching node: warn. Fewer zones than `min_zones`: warn. No node with the required arch: block.
- **Fix:** "Only `{n}` of `{m}` nodes have `{mem}` allocatable memory. Add a node group (EKS: `eksctl create nodegroup --cluster {c} --nodes 3 --node-type m6i.2xlarge`) or lower the product's requests."
- **Fixture:** `Node` lists: three healthy, one `NotReady`, tainted GPU pool, mixed arm64 and amd64, single zone; `Pod` list with requests that eat 90% of CPU.

### k8s.version (M1)
- **Measures:** server version, distribution, kubelet skew, and whether the API versions the product uses are served.
- **Source:** `GET /version` (`gitVersion` such as `v1.29.4-eks-abc123`; use it, not `major`/`minor`, which carry a `+`); distribution from suffixes `-eks-`, `-gke.`, `+k3s`, `+rke2`, and OpenShift by discovery of `config.openshift.io`; `GET /apis` and `GET /apis/<group>/<version>` discovery (open to all authenticated users) for spec `apis`; node `kubeletVersion` from `k8s.nodes` data.
- **Needs:** none beyond access, timeout 10s.
- **Thresholds:** spec `min`, `max`, `max_severity`, `apis: ["networking.k8s.io/v1 Ingress", "batch/v1 CronJob", "autoscaling/v2 HorizontalPodAutoscaler"]`. Below `min`: block. Above `max`: warn (spec `max_severity: block` makes it block). A required API not served: block. Kubelet more than three minors behind the API server: warn.
- **Fix:** "Cluster is `{v}`, product needs `{min}` or newer. Upgrade the control plane (EKS: `aws eks update-cluster-version --name {c} --kubernetes-version {v}`)."
- **Fixture:** `/version` JSON for EKS, GKE, k3s, vanilla; discovery documents with and without `autoscaling/v2`.

### k8s.namespace (M1-late)
- **Measures:** target namespace exists or can be created, is not stuck terminating, quota headroom, limit range effects.
- **Source:** `v1` `Namespace` GET, `ResourceQuota` list (hard and used), `LimitRange` list in the namespace; `SelfSubjectAccessReview` for `create namespaces` when missing.
- **Needs:** kube read, timeout 15s.
- **Thresholds:** spec `namespace`, `quota_needs: {requests.cpu: 16, requests.memory: 64Gi, pods: 100, persistentvolumeclaims: 10, requests.storage: 500Gi}`, `limit_needs: {container_max_memory: 16Gi}`. Namespace `Terminating`: block. Missing and not creatable: block. Quota remaining below need: block. `LimitRange` maximum below a container the product needs: block. A default limit lower than the product's requests: warn.
- **Fix:** "Quota `compute` in `{ns}` allows 8 CPU of requests and 6 are used, `{need}` needed. Ask an admin: `kubectl edit resourcequota compute -n {ns}`."
- **Fixture:** `Namespace`, `ResourceQuota` and `LimitRange` JSON, including a terminating namespace.

### k8s.ingress (M1-late)
- **Measures:** an ingress path exists: `IngressClass`, Gateway API classes, LoadBalancer services can get an address.
- **Source:** `networking.k8s.io/v1` `IngressClass` list (default marker `ingressclass.kubernetes.io/is-default-class`, `spec.controller`); Gateway API by discovery of `gateway.networking.k8s.io/v1` and `GatewayClass` condition `Accepted`; `v1` `Service` list filtered to `type=LoadBalancer`, looking for ones with no `status.loadBalancer.ingress` after 10 minutes; MetalLB by discovery of `metallb.io`.
- **Needs:** kube read, timeout 30s.
- **Thresholds:** spec `ingress: {class: nginx|any, gateway_api: required|optional, loadbalancer: true}`. Required class or API missing: block. No default class: warn. A LoadBalancer service pending beyond 10 minutes: warn "load balancer provisioning looks broken".
- **Fix:** "No IngressClass `{class}`. Install an ingress controller your platform team supports, or give us the class that exists. Pending LoadBalancer: on bare metal install MetalLB and an `IPAddressPool`; in a cloud check the cloud controller manager logs."
- **Fixture:** `IngressClass` lists, `Service` lists with pending and assigned load balancers, `GatewayClass` list.

### k8s.crds (M1-late)
- **Measures:** required CRDs are installed at the needed version, and their operators run at an acceptable version.
- **Source:** discovery `GET /apis/<group>/<version>` (open) for served versions; `apiextensions.k8s.io/v1` `CustomResourceDefinition` GET by name for `Established` and `storage` version when allowed; `apps/v1` `Deployment` GET for each spec operator (ready replicas, image tag or label `app.kubernetes.io/version`).
- **Needs:** kube read, timeout 20s.
- **Thresholds:** spec `crds: [{name, versions: [v1]}]`, `operators: [{namespace, deployment, min_version}]`. CRD or version missing: block. Operator not ready: warn. Operator below `min_version`: block.
- **Fix:** "cert-manager CRDs are missing. Install: `helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set crds.enabled=true`."
- **Fixture:** discovery documents, CRD JSON with `Established` true and false, `Deployment` JSON with ready and zero replicas.

### k8s.cni (M1-late)
- **Measures:** which CNI runs, whether NetworkPolicy is enforced, default-deny policies in the target namespace, pod and service CIDRs.
- **Source:** `apps/v1` `DaemonSet` list for known CNI names (`calico-node`, `cilium`, `aws-node`, `kube-flannel-ds`, `weave-net`, `antrea-agent`, `ovnkube-node`, `azure-cns`); node annotations; `networking.k8s.io/v1` `NetworkPolicy` list in the namespace (policy selecting all pods with no rules, in `Ingress` or `Egress`); CIDRs from `kubeadm-config` ConfigMap in `kube-system` (`ClusterConfiguration.networking`) or `Node.spec.podCIDR`. Enforcement from a shipped CNI table (Appendix B); `aws-node` and unknown ones give "enforcement not verified".
- **Needs:** kube read, timeout 20s.
- **Thresholds:** spec `network_policy: enforced`, `needs_egress: [host:port]`, `avoid_cidrs: [...]`. Default-deny present while the product needs egress or ingress it does not list: warn. `enforced` required but the CNI does not enforce: block. Pod or service CIDR overlapping `avoid_cidrs`: block.
- **Fix:** "Namespace `{ns}` has a default-deny egress policy. Add a policy allowing `{host}:{port}` from the product's pods (vendor sample: `{url}`)."
- **Fixture:** `DaemonSet` lists per CNI, `NetworkPolicy` lists with default-deny, `kubeadm-config` ConfigMap.

### k8s.dns (M1-late)
- **Measures:** CoreDNS (or kube-dns) is running, serves a ClusterIP, and its upstream is not a loop.
- **Source:** `apps/v1` `Deployment` `coredns` (label `k8s-app=kube-dns`) ready versus desired; `v1` `Service` `kube-dns`; `v1` `ConfigMap` `coredns` Corefile (`forward . /etc/resolv.conf`, `loop` plugin); `node-local-dns` DaemonSet presence; pod restart counts from the `Pod` list. If upstream is `/etc/resolv.conf` and the node uses the `127.0.0.53` stub, the check warns (CoreDNS crash-loops with "Loop detected").
- **Needs:** kube read, timeout 15s.
- **Thresholds:** CoreDNS not fully ready: block. Restart count above 5: warn. Loop risk: warn.
- **Fix:** "CoreDNS forwards to `/etc/resolv.conf`, which on these nodes is the systemd-resolved stub. Edit the `coredns` ConfigMap to `forward . {upstream}` or point kubelet `--resolv-conf` at `/run/systemd/resolve/resolv.conf`."
- **Fixture:** `Deployment`, `Service`, `ConfigMap` and `Pod` JSON, including a crash-looping CoreDNS.

### k8s.device_plugins (M1-late; gpu-expert reviews)
- **Measures:** extended resources are advertised on nodes (`nvidia.com/gpu`, `nvidia.com/mig-*`, `amd.com/gpu`, `hugepages-*`, RDMA), the plugin or operator that provides them is healthy, and GPU sharing mode.
- **Source:** `v1` `Node` `status.allocatable` and `capacity` for any resource name containing `/` outside `kubernetes.io`; labels from NVIDIA GPU Feature Discovery (`nvidia.com/gpu.present`, `nvidia.com/gpu.product`, `nvidia.com/gpu.count`, `nvidia.com/gpu.memory`, `nvidia.com/gpu.replicas`, `nvidia.com/mig.strategy`, and the CUDA driver labels, which exist under two spellings, `nvidia.com/cuda.driver-version.major` and `nvidia.com/cuda.driver.major`, both are read); `apps/v1` `DaemonSet` `nvidia-device-plugin-daemonset` and the GPU Operator `nvidia.com/v1` `ClusterPolicy` `status.state`; `node.k8s.io/v1` `RuntimeClass` `nvidia`; plugin pod restarts from the `Pod` list.
- **Needs:** kube read, timeout 20s.
- **Thresholds:** spec `resources: [{name: nvidia.com/gpu, min_total: 8, min_per_node: 4, nodes: 2}]`, `sharing: exclusive|any`, `runtime_class: nvidia`. Total or per-node below need: block. Nodes labelled `gpu.present=true` with zero allocatable: block "plugin not running or driver problem". Time-sliced replicas above 1 while `exclusive`: warn. Product requests `nvidia.com/gpu` but MIG strategy exposes `nvidia.com/mig-*`: block.
- **Fix:** "Nodes `{list}` have GPUs but advertise 0 `nvidia.com/gpu`. Check the plugin pod: `kubectl -n {ns} logs ds/nvidia-device-plugin-daemonset`. A 'driver/library version mismatch' means reboot the node after the driver upgrade."
- **Fixture:** `Node` lists with 8 GPUs allocatable, with GFD labels but zero allocatable, MIG mixed strategy, time-slicing replicas; a crash-looping plugin `DaemonSet` and `Pod`.

## 5. Cloud family (`rdy-checks-cloud`, AWS first, M3)

Ids use the provider prefix: `aws.*` now, `gcp.*` and `azure.*` reserved. All AWS checks use the Rust SDK (`aws-config` credential chain: environment, shared profile, SSO cache, container and instance credentials, web identity) on rustls. They never shell out to the `aws` CLI, never write, and never read or log credential values.

**Common spec fields for every `aws.*` check:** `region`, `profile`, `account` (expected account id, mismatch blocks), and `assume: {role_arn, external_id_env, session_name}`. With `assume`, `rdy` calls `sts:AssumeRole` (900s session, session name `rdy-readiness`, `ExternalId` read from the named environment variable) and runs the checks as that role. This is the BYOC case: the customer created the cross-account role for the vendor, and the check proves the role works before install day. The `AssumeRole` call shows up in CloudTrail, which the report says up front.

**No credentials:** every `aws.*` check returns `skipped: no AWS credentials`. A spec can set `require: true` so skipped counts as a block. Fix text: "Run `aws sso login --profile {p}` then `export AWS_PROFILE={p}`, or export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`."

**Fixtures for all of them:** recorded HTTP exchanges replayed through the SDK's static replay client (`aws-smithy-runtime` test util), one directory per case, secrets replaced with `AKIAIOSFODNN7EXAMPLE` style values and account `111122223333`.

**IAM actions `rdy` itself needs** (the "reader policy" the docs publish; every one is read-only): `sts:GetCallerIdentity` (needs no grant), `iam:GetRole`, `iam:SimulatePrincipalPolicy`, `iam:ListOpenIDConnectProviders`, `servicequotas:GetServiceQuota`, `servicequotas:GetAWSDefaultServiceQuota`, `servicequotas:ListServiceQuotas`, `cloudwatch:GetMetricData`, `ec2:DescribeRegions`, `ec2:DescribeAvailabilityZones`, `ec2:DescribeInstanceTypes`, `ec2:DescribeInstanceTypeOfferings`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeNatGateways`, `ec2:DescribeInternetGateways`, `ec2:DescribeVpcAttribute`, `ec2:DescribeVpcEndpoints`, `eks:DescribeCluster`, `eks:ListAddons`, `eks:DescribeAddon`, `eks:ListNodegroups`, `eks:DescribeNodegroup`, `eks:ListAccessEntries`, `eks:ListAssociatedAccessPolicies`, `ssm:GetParameter` on `arn:aws:ssm:*::parameter/aws/service/global-infrastructure/*`. Each check lists the subset it uses. A missing read permission makes that check partial with the action named.

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `aws.iam` | M3 | `iam:SimulatePrincipalPolicy` or EC2 dry-run | The install principal can do what the installer does |
| 2 | `aws.quota` | M3 | `servicequotas:*` read | vCPU, EIP, VPC, NAT, EKS quotas have headroom |
| 3 | `aws.vpc` | M3 | `ec2:Describe*` | Subnets have free IPs, routes, DNS attributes, endpoints |
| 4 | `aws.region` | M3 | `ec2:Describe*` | Region enabled, AZs, instance types offered |
| 5 | `aws.eks` | M3 | `eks:Describe*` | Cluster endpoint access, OIDC provider, add-ons, access entries |
| 6 | `aws.identity` | M3 | none | Who am I, which account, how long do credentials last |

`aws.identity` runs first in practice (the others use its result) but catches the fewest failures by itself.

### aws.iam (M3; cloud-iam-expert reviews)
- **Measures:** whether the principal the installer will use is allowed each listed action, on the listed resources, with the listed context.
- **Source:** `iam:SimulatePrincipalPolicy`, with `PolicySourceArn` set to the user or role ARN, `ActionNames` from the spec in batches of 50, `ResourceArns` from the spec (default `*`), `ContextEntries` from the spec (for example `aws:RequestedRegion`), `MaxItems` 1000, paged. Details that matter: (1) the API accepts a user, group or role ARN, not an assumed-role session ARN, so for `arn:aws:sts::111122223333:assumed-role/NAME/session` the check calls `iam:GetRole` for `NAME` and uses the role's real ARN, which includes its path (IAM Identity Center roles live under `/aws-reserved/sso.amazonaws.com/`); (2) the caller needs `iam:SimulatePrincipalPolicy` on that principal, which install roles often lack; (3) per the API reference the simulator evaluates identity policies, permissions boundaries and service control policies, and takes only what the call supplies as context, so a decision that depends on a missing context key comes back with `MissingContextValues`; it never evaluates session policies passed at `AssumeRole`. Fallback when (2) fails and the action is an EC2 action: call the EC2 API with `DryRun=true` (`DryRunOperation` means allowed, `UnauthorizedOperation` means denied). A dry run goes through real authorization, including SCPs and conditions, and creates nothing. Parameters are throwaway placeholders; for `RunInstances` the spec gives `ami` and `instance_type`. Non-EC2 actions with no simulate permission are `unknown`.
- **Needs:** AWS credentials; `iam:GetRole` and `iam:SimulatePrincipalPolicy`, or the EC2 dry-run path. Timeout 30s, at most 20 API calls with SDK standard retry.
- **Thresholds:** spec `simulate: [actions]` (plan example), `resources: [arns]`, `context: {key: value}`, `probe: auto|simulate|dry_run`, `principal: <arn>` (check a role other than the caller). Decision `implicitDeny` or `explicitDeny`: block. `allowed`: pass. Denied but `MissingContextValues` not empty: warn "depends on `{keys}`, supply them in `context`". Cannot probe at all: warn, never block.
- **Fix:** "`{principal}` is not allowed `ec2:CreateSecurityGroup` (implicit deny). Add it to the role's policy: `{\"Effect\":\"Allow\",\"Action\":\"ec2:CreateSecurityGroup\",\"Resource\":\"*\"}`." If `OrganizationsDecisionDetail.AllowedByOrganizations` is false: "A service control policy blocks this. Ask the AWS Organizations admin." If `PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary` is false: "The role's permissions boundary does not allow it."
- **Fixture:** `SimulatePrincipalPolicy` responses: all allowed, one `implicitDeny`, `explicitDeny` with the org detail false, `MissingContextValues`, `AccessDenied` on the simulate call; `GetRole` for an SSO path; EC2 `DryRunOperation` (412) and `UnauthorizedOperation` (403) responses.

### aws.quota (M3)
- **Measures:** limit, current use and headroom for the quotas the product consumes.
- **Source:** `servicequotas:GetServiceQuota` (applied value; on `NoSuchResourceException` use `GetAWSDefaultServiceQuota`). Use from CloudWatch `GetMetricData`, namespace `AWS/Usage`, metric `ResourceCount`, dimensions `Service`, `Type=Resource`, `Resource`, `Class` (for EC2 vCPUs: `Resource=vCPU`, `Class=Standard/OnDemand`). Quotas not found by code are looked up by name with `ListServiceQuotas`. Built-in code table: `L-1216C47A` Running On-Demand Standard instances (vCPUs), `L-DB2E81BA` Running On-Demand G and VT instances, `L-417A185B` Running On-Demand P instances, `L-0263D0A3` EC2-VPC Elastic IPs, `L-F678F1CE` VPCs per Region, `L-FE5A380F` NAT gateways per Availability Zone, `L-A4707A72` Internet gateways per Region, `L-1194D53C` EKS clusters. Codes are checked against a live `ListServiceQuotas` response at implementation time (reviewer item).
- **Needs:** `servicequotas:GetServiceQuota`, `servicequotas:GetAWSDefaultServiceQuota`, `servicequotas:ListServiceQuotas`; `cloudwatch:GetMetricData` optional. Without CloudWatch, use is unknown, the check compares need to limit only and says "usage not measured". Timeout 20s.
- **Thresholds:** spec `quotas: [{service: ec2, code: L-1216C47A, need: 64}, {service: eks, name: "Clusters", need: 1}]`, `headroom` (default 20%). `limit - used < need`: block. Under `need` times `headroom`: warn.
- **Fix:** "Running On-Demand Standard vCPUs: limit `{l}`, used `{u}`, need `{n}`. Request an increase now, it can take days: `aws service-quotas request-service-quota-increase --service-code ec2 --quota-code L-1216C47A --desired-value {v} --region {r}`."
- **Fixture:** `GetServiceQuota` and `GetAWSDefaultServiceQuota` responses, `GetMetricData` series, a `NoSuchResourceException`.

### aws.vpc (M3)
- **Measures:** subnet capacity and layout, routes, VPC DNS attributes, private endpoints.
- **Source:** `ec2:DescribeVpcs` (CIDR associations), `DescribeSubnets` (`AvailableIpAddressCount`, AZ, tags `kubernetes.io/role/elb`, `kubernetes.io/role/internal-elb`, `kubernetes.io/cluster/<name>`), `DescribeRouteTables` (default route target: `igw-`, `nat-`, `tgw-`, `vpce-`), `DescribeNatGateways`, `DescribeInternetGateways`, `DescribeVpcAttribute` (`enableDnsSupport`, `enableDnsHostnames`), `DescribeVpcEndpoints` (service names, `PrivateDnsEnabled`, state).
- **Needs:** the `ec2:Describe*` actions above, timeout 20s.
- **Thresholds:** spec `vpc_id` or `subnet_ids`, `min_azs`, `min_free_ips` (per subnet), `internet: nat|igw|none`, `endpoints: [com.amazonaws.<region>.ecr.api, ...ecr.dkr, ...s3, ...sts, ...ec2]`, `dns_hostnames: true`. Too few AZs or free IPs, missing route, DNS attribute off, endpoint missing or not `available`: block. A `/24` subnet for pod networking: warn.
- **Fix:** "Subnet `{id}` in `{az}` has `{n}` free IPs, `{need}` needed. Add a secondary CIDR (`aws ec2 associate-vpc-cidr-block --vpc-id {v} --cidr-block 100.64.0.0/16`) and new subnets, or enable prefix delegation on the VPC CNI."
- **Fixture:** EC2 XML responses: roomy subnets, two subnets in one AZ, 9 free IPs, no NAT route, DNS hostnames off, endpoint pending.

### aws.region (M3)
- **Measures:** region is enabled for the account, enough AZs, instance types offered in enough AZs, services available in the region.
- **Source:** `ec2:DescribeRegions` with `AllRegions=true` (`OptInStatus`), `DescribeAvailabilityZones`, `DescribeInstanceTypeOfferings` with `LocationType=availability-zone` and filter `instance-type`, `DescribeInstanceTypes` (vCPU, memory, GPU, architecture), public parameter `/aws/service/global-infrastructure/regions/<region>/services/<service>` through `ssm:GetParameter` (exact path verified at implementation).
- **Needs:** `ec2:Describe*` actions, `ssm:GetParameter` optional, timeout 20s.
- **Thresholds:** spec `region`, `min_azs`, `instance_types: [g5.xlarge, m6i.2xlarge]`, `services: [eks, bedrock]`. Region `not-opted-in`: block. Instance type offered in fewer than `min_azs` AZs: block (GPU types often are offered in only some AZs). Service missing: block.
- **Fix:** "Region `{r}` is not enabled for this account. Enable it (Account settings, AWS Regions) or `aws account enable-region --region-name {r}`; it takes minutes to hours."
- **Fixture:** `DescribeRegions` with an opt-in region, offerings for `g5.xlarge` in two of three AZs, a missing SSM parameter.

### aws.eks (M3)
- **Measures:** an existing EKS cluster fits the product: version, endpoint access, OIDC provider for IRSA, add-ons, node groups, access entries.
- **Source:** `eks:DescribeCluster` (`version`, `status`, `endpointPublicAccess`, `endpointPrivateAccess`, `publicAccessCidrs`, `identity.oidc.issuer`, `accessConfig.authenticationMode`, subnets, security groups), `ListAddons` and `DescribeAddon` (`vpc-cni`, `coredns`, `kube-proxy`, `aws-ebs-csi-driver`, `eks-pod-identity-agent`: status, version), `ListNodegroups` and `DescribeNodegroup` (instance types, scaling, AMI type), `ListAccessEntries` and `ListAssociatedAccessPolicies` when the authentication mode includes `API`, `iam:ListOpenIDConnectProviders` to match the issuer. The client's public IP is not looked up (nothing leaves unasked); the allowed CIDR list is printed for the customer to compare.
- **Needs:** the `eks:*` read actions above, `iam:ListOpenIDConnectProviders`, timeout 20s.
- **Thresholds:** spec `cluster`, `min_version`, `oidc: true`, `addons: [{name, min_version}]`, `auth_mode`, `endpoint: private_ok`. Cluster not `ACTIVE`, below `min_version`, OIDC provider absent, add-on missing or degraded: block. Private-only endpoint while `k8s.access` cannot connect: block with "run from inside the VPC or a bastion".
- **Fix:** "No IAM OIDC provider for `{issuer}`, so IAM roles for service accounts fail. Run `eksctl utils associate-iam-oidc-provider --cluster {c} --approve`."
- **Fixture:** `DescribeCluster` variants (public, private only, `CONFIG_MAP` mode), add-on responses with one `DEGRADED`, OIDC provider lists with and without a match.

### aws.identity (M3)
- **Measures:** account, principal type, role name, credential lifetime.
- **Source:** `sts:GetCallerIdentity` (needs no permission). Principal type from the ARN (`user`, `assumed-role`, `federated-user`, root). Credential expiry from the SDK credentials object.
- **Needs:** credentials, timeout 10s.
- **Thresholds:** spec `account`, `principal_pattern`. Account mismatch: block. Root user: warn. Credentials expiring within 15 minutes: warn.
- **Fix:** "Running in account `{a}`, spec expects `{b}`. Check `AWS_PROFILE`; `aws sts get-caller-identity` shows the same answer."
- **Fixture:** `GetCallerIdentity` for a user, an SSO assumed role, root, a wrong account; expiry set by the replay clock.

### Reserved: GCP and Azure (after M3, data sources decided now so the spec shape stays stable)
| Id | Source |
| --- | --- |
| `gcp.iam` | `cloudresourcemanager` `projects.testIamPermissions` (up to 100 permissions per call) |
| `gcp.quota` | `compute.regions.get` quotas array; Service Usage `consumerQuotaMetrics` |
| `gcp.apis` | Service Usage `services.batchGet`, state `ENABLED` |
| `azure.rbac` | ARM `GET {scope}/providers/Microsoft.Authorization/permissions` (actions and notActions, wildcard match; deny assignments and ABAC conditions are not covered) |
| `azure.quota` | `Microsoft.Compute/locations/{loc}/usages`, `Microsoft.Network/locations/{loc}/usages` |
| `azure.providers` | `GET /subscriptions/{id}/providers/{namespace}` `registrationState` |

## 6. GPU family (`rdy-checks-gpu`, M4)

GPU checks are Linux and Windows. macOS: not applicable (no CUDA). WSL2: detected; the driver lives on the Windows host, `nvidia-smi` is at `/usr/lib/wsl/lib/nvidia-smi`.

**Data source decision.** The primary source is one call, `nvidia-smi -q -x` (XML, whole-system, output capped at 2 MiB, timeout 10s), parsed once and shared by the checks below, plus `/proc` and `/sys` reads. NVML is the library behind `nvidia-smi`, but a fully static musl binary cannot `dlopen` a glibc `libnvidia-ml.so.1`, so the plan's "nvml-wrapper with nvidia-smi fallback" cannot work in the shipped Linux binary. See "Plan corrections found". Every Source line names the NVML call that returns the same value, so a later glibc build with an `nvml` feature can swap sources without changing results. The XML parser tolerates missing tags (older drivers) and values such as `N/A` and `[Not Supported]`.

**Tool failure strings, classified once for all GPU checks:** `couldn't communicate with the NVIDIA driver` (driver not loaded), `Failed to initialize NVML: Driver/library version mismatch` (kernel module and user libraries differ after an upgrade without a reboot), `No devices were found`, `Failed to initialize NVML: Unknown Error` (often container device access), `GPU is lost` or `Unable to determine the device handle` (GPU fell off the bus), and a timeout (a wedged GPU can hang `nvidia-smi` in an unkillable state; the check abandons it and reports that). No `nvidia-smi` binary: `skipped: no NVIDIA tooling` plus `lspci -nn` style hint from `/sys/bus/pci/devices/*/vendor` (`0x10de`) so "GPU present, no driver" is distinguishable from "no GPU".

NVIDIA, AMD and Intel: only NVIDIA at launch. `gpu.rocm` is reserved.

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `gpu.driver` | M4 | none | Driver loaded, version, module flavour, nouveau, Secure Boot |
| 2 | `gpu.cuda` | M4 | none | CUDA version the driver supports, toolkit if present |
| 3 | `gpu.vram` | M4 | none | VRAM per GPU, free now |
| 4 | `gpu.runtime` | M4 | root optional | Container toolkit and runtime registration |
| 5 | `gpu.devices` | M4 | none | Count, model, compute capability, MIG, compute mode, PCIe |
| 6 | `gpu.model_egress` | M4 | none | Model hub reachable, CDN hosts, ranged download |
| 7 | `gpu.health` | M4 | root optional | ECC, retired pages, row remap, throttling, Xid |
| 8 | `gpu.fabric` | M4 | root optional | NVLink, NVSwitch fabric manager, InfiniBand, GPUDirect, NCCL prerequisites |

`k8s.device_plugins` (section 4) covers the in-cluster half. The first five are cheap and could be pulled forward to M2 if a design partner ships GPU software.

### gpu.driver (M4)
- **Measures:** driver loaded and working, version, open or proprietary kernel module, `nouveau` conflict, Secure Boot state, persistence daemon.
- **Source:** L: `/proc/driver/nvidia/version` (line `NVRM version: NVIDIA UNIX Open Kernel Module ...` or `NVIDIA UNIX x86_64 Kernel Module ...`), `/sys/module/nvidia/version`, `/proc/modules` (`nvidia`, `nvidia_uvm`, `nvidia_modeset`, `nouveau`), device nodes `/dev/nvidiactl`, `/dev/nvidia0`, `/dev/nvidia-uvm`, Secure Boot from `/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c` (fifth byte `1`), `nvidia-persistenced` process; XML `driver_version` and `attached_gpus`. Mismatch: `/sys/module/nvidia/version` against the XML `driver_version`. NVML: `nvmlSystemGetDriverVersion`, `nvmlSystemGetNVMLVersion`, `nvmlDeviceGetCount_v2`. W: `nvidia-smi.exe` (in `System32`, or `C:\Program Files\NVIDIA Corporation\NVSMI`), same XML; `Win32_VideoController` is not used because its version string is in a different format. M: not applicable.
- **Needs:** none, timeout 10s.
- **Thresholds:** spec `min: "535.104"`, `kernel_module: open|proprietary|any`, `persistence: required|any`. Driver not loaded, below `min`, or version mismatch: block. `nouveau` loaded: block. Secure Boot on with unsigned `nvidia` module symptom (driver absent, `nvidia` not in `/proc/modules`): block with the signing text. Wrong module flavour: block. No persistence daemon: warn.
- **Fix:** "`nvidia-smi` reports a driver/library version mismatch: the kernel module is `{k}` and the libraries are `{u}`. Reboot, or unload and reload the modules (`rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia`)." Nouveau: "Create `/etc/modprobe.d/blacklist-nouveau.conf` with `blacklist nouveau` and `options nouveau modeset=0`, run `dracut --force` (RHEL) or `update-initramfs -u` (Debian), reboot."
- **Fixture:** recorded `nvidia-smi -q -x` for a healthy node (open module, 550.x), every failure string above as stdout and exit code, `/proc/driver/nvidia/version` for both flavours, a fake `efivars` file, a runner that sleeps forever (timeout case).

### gpu.cuda (M4)
- **Measures:** the CUDA version the installed driver supports. This is what the plan's `gpu.cuda min: "12.4"` can only mean on a bare node, so the spec says which one it wants. Optional: the CUDA toolkit installed on the host.
- **Source:** XML `cuda_version` (NVML: `nvmlSystemGetCudaDriverVersion_v2`, integer `12040` means 12.4). The plain `nvidia-smi` header line is not parsed, since newer drivers are moving that field. Toolkit (`source: toolkit`): `/usr/local/cuda/version.json` (`cuda.version`), older `version.txt`, `nvcc --version` ("release 12.4"), `libcudart.so.*` in `/usr/local/cuda*/lib64` and the distro library directory, and forward-compat libraries at `/usr/local/cuda/compat/libcuda.so.*`. W: same through `nvidia-smi.exe` and `%CUDA_PATH%\version.json`.
- **Needs:** none, timeout 10s.
- **Thresholds:** spec `min`, `max`, `source: driver|toolkit` (default `driver`), `compat_ok: true` (accept a toolkit newer than the driver supports when the compat package covers it; datacenter GPUs only). Below `min`: block. Above `max`: warn.
- **Fix:** "The driver supports CUDA `{have}`, the product needs `{min}`. Upgrade the driver: CUDA 12.2 needs 535.54.03 or newer, CUDA 12.4 needs 550.54.14 or newer (table in Appendix B, from NVIDIA's release notes)."
- **Fixture:** XML for drivers 525, 535, 550; `version.json`; `nvcc --version` output; a compat directory.

### gpu.vram (M4)
- **Measures:** VRAM per GPU, how many GPUs meet the need, free VRAM right now, MIG instance sizes.
- **Source:** XML `fb_memory_usage` (`total`, `reserved`, `used`, `free`, in MiB) per GPU; for MIG, the per-instance memory in the `mig_devices` section. NVML: `nvmlDeviceGetMemoryInfo_v2` (`total`, `reserved`, `free`, `used`), `nvmlDeviceGetMigMode`. Real values show why the nominal band exists: A100 80GB reports 81920 MiB, H100 80GB about 81559 MiB, L4 and A10G about 23000 MiB for "24 GB".
- **Needs:** none, timeout 10s (shared XML call).
- **Thresholds:** spec `min_per_gpu: 24Gi`, `count: 4` (how many GPUs must meet it), `min_total`, `min_free`, `band` (default 8%, counts as warn). Fewer than `count` GPUs meeting `min_per_gpu`: block. Within the band: warn. Free below `min_free` or more than 10% used by other processes: warn "GPU is busy".
- **Fix:** "GPU 0 (`{name}`) has `{have}`, the product needs `{min}`. Use a larger GPU class (48 GB or 80 GB) or reduce per-GPU model size with tensor parallelism." Busy: "`nvidia-smi` shows processes `{list}` holding memory."
- **Fixture:** XML for H100 (81559 MiB), A100 (81920), L4 (23034), a MIG-enabled A100 with 1g.10gb instances, a GPU with 40% used.

### gpu.runtime (M4)
- **Measures:** NVIDIA Container Toolkit installed and registered with the runtime the product uses.
- **Source:** L: `/usr/bin/nvidia-ctk` and `/usr/bin/nvidia-container-runtime` present, `nvidia-ctk --version`; `/etc/nvidia-container-runtime/config.toml`; Docker `/etc/docker/daemon.json` (`runtimes.nvidia`, `default-runtime`); containerd `/etc/containerd/config.toml` (a `runtimes.nvidia` table, `default_runtime_name`); CDI specs `/etc/cdi/nvidia.yaml` and `/var/run/cdi/nvidia.yaml`; CRI-O `/etc/crio/crio.conf.d/*`. W, M: not applicable (Docker Desktop GPU support is out of scope).
- **Needs:** root optional (some configs are root only), timeout 5s.
- **Thresholds:** spec `container_runtime: docker|containerd|crio`, `min_toolkit: "1.14"`, `cdi: required|any`. Toolkit missing while containers are in scope: block. Installed but not registered with the active runtime: block. Version below `min_toolkit`: warn.
- **Fix:** "Register the runtime: `nvidia-ctk runtime configure --runtime=containerd --set-as-default && systemctl restart containerd` (use `--runtime=docker` for Docker). For CDI: `nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml`."
- **Fixture:** daemon and containerd config variants, toolkit files, CDI YAML.

### gpu.devices (M4)
- **Measures:** GPU count, models, architecture, compute capability, MIG mode, compute mode, persistence, virtualization mode, PCIe link state.
- **Source:** XML per GPU: `product_name`, `product_architecture`, `uuid`, `pci_bus_id`, `compute_mode`, `persistence_mode`, `mig_mode` (`current_mig`, `pending_mig`), `virtualization_mode`, PCIe `current_link_gen`, `max_link_gen`, `current_link_width`, `max_link_width`. Compute capability: `nvidia-smi --query-gpu=index,compute_cap --format=csv,noheader` where the driver supports `compute_cap`, else the architecture table (Appendix B). NVML: `nvmlDeviceGetName`, `nvmlDeviceGetArchitecture`, `nvmlDeviceGetCudaComputeCapability`, `nvmlDeviceGetMigMode`, `nvmlDeviceGetComputeMode`, `nvmlDeviceGetPersistenceMode`, `nvmlDeviceGetVirtualizationMode`, `nvmlDeviceGetCurrPcieLinkGeneration`, `nvmlDeviceGetCurrPcieLinkWidth`. UUIDs are shortened to a hash in the report.
- **Needs:** none, timeout 10s.
- **Thresholds:** spec `count`, `models: [regex]`, `compute_capability: "8.0"`, `mig: forbid|require|any`, `compute_mode: default`, `virtualization: passthrough|vgpu|any`. Count short, model not allowed, capability below minimum, MIG state wrong: block. Compute mode `Exclusive_Process` or `Prohibited` when `default` wanted: warn. PCIe width below max: warn.
- **Fix:** "MIG is enabled on GPU 0 but the product needs whole GPUs. Disable it with no workloads running: `nvidia-smi -i 0 -mig 0`, then reset the GPU or reboot." Compute mode: "`nvidia-smi -i 0 -c DEFAULT`."
- **Fixture:** XML for 8x H100 SXM, 4x L4, T4 (capability 7.5), MIG on, vGPU guest, a GPU at PCIe x8.

### gpu.model_egress (M4)
- **Measures:** model hubs and registries are reachable from here, which CDN hosts they redirect to, ranged download works, and the model cache path has room.
- **Source:** library calls into `net.egress`, `net.tls_intercept`, `net.bandwidth` and `host.disk` (so `rdy-checks-gpu` depends on `rdy-checks-net` and `rdy-checks-host` as libraries, not through the engine). For each spec source URL: unauthenticated `GET` with `Range: bytes=0-{range_bytes}` (default 8 MiB), follow redirects, record every host, expect `206` or `200`. Reports `HF_ENDPOINT`, `HF_HOME`, `HF_HUB_OFFLINE`, `TRANSFORMERS_OFFLINE` by name. Never reads or sends a token; a gated model answering 401 or 403 is `warn: needs a token, cannot verify`.
- **Needs:** none, 30s per source.
- **Thresholds:** spec `sources: [url]`, `cache_path` and `cache_need`, `range_bytes`, `min_mbps`. Source unreachable or a redirect host blocked: block, naming the host. No range support: warn (resumable downloads fail). Under `min_mbps`: warn. Cache disk short: block.
- **Fix:** "`{hub}` is reachable but the file is served from `{cdn}`, which the proxy blocks. Allow `{cdn}:443`. The list of every host contacted is in the report; give it to the network team."
- **Fixture:** loopback server with `302` to a second loopback host, `206` and `200` modes, a `401` gated file; a fake cache directory.

### gpu.health (M4)
- **Measures:** signs a GPU or its memory is failing, and recent kernel Xid errors.
- **Source:** XML: `ecc_mode` (`current_ecc`), `ecc_errors` (volatile and aggregate, uncorrectable counters), `retired_pages` (pending retirement, double-bit), `remapped_rows` (`remap_failure`, `remap_pending`, correctable and uncorrectable counts), `clocks_event_reasons` (older drivers: `clocks_throttle_reasons`: hardware slowdown, thermal slowdown, power brake), `temperature`, `gpu_power_readings`. NVML: `nvmlDeviceGetTotalEccErrors` (uncorrected, aggregate), `nvmlDeviceGetRetiredPages`, `nvmlDeviceGetRemappedRows`, `nvmlDeviceGetCurrentClocksEventReasons`, `nvmlDeviceGetTemperature`. Xid: lines `NVRM: Xid` from `/dev/kmsg` tail (needs root or `kernel.dmesg_restrict=0`), last 1 MiB, window from the spec.
- **Needs:** root optional (Xid), timeout 10s. Without root: hardware counters only, "kernel log not inspected".
- **Thresholds:** spec `xid_window: 24h`, `block_xids: [48, 79, 95]`, `ecc_uncorrected_max: 0`. Row remap failure, pending retirement, or a blocking Xid in the window (48 double-bit ECC, 79 GPU fell off the bus, 95 uncontained ECC): block. Uncorrected ECC above max, other Xids (13, 31, 63, 64, 74): warn. Hardware or thermal slowdown active while idle: warn.
- **Fix:** "GPU `{i}` reports `{symptom}`. Drain the node, then `nvidia-smi -q -d ECC,ROW_REMAPPER -i {i}` for detail and `nvidia-smi --gpu-reset -i {i}` if allowed. If it returns, open a hardware case with the node vendor."
- **Fixture:** XML with clean counters and with remap failure, synthetic `kmsg` lines such as `NVRM: Xid (PCI:0000:3b:00): 79, pid=1234, GPU has fallen off the bus.`, a root-less run.

### gpu.fabric (M4)
- **Measures:** GPU interconnect and cluster-fabric prerequisites: NVLink links, NVSwitch fabric manager, InfiniBand ports, GPUDirect RDMA, NCCL library and shared memory.
- **Source:** L: `nvidia-smi nvlink -s` (link up and speed), `nvidia-smi topo -m` (matrix of `NV#`, `PIX`, `PXB`, `PHB`, `NODE`, `SYS`); NVSwitch presence `/proc/driver/nvidia-nvswitch/` and `/dev/nvidia-nvswitch*`; fabric manager process `nv-fabricmanager`, its version from `nv-fabricmanager -v` against the driver version, and XML `fabric` state (`Completed`, status `Success`); InfiniBand `/sys/class/infiniband/*/ports/*/{state,rate,link_layer}` (`4: ACTIVE`, `400 Gb/sec (4X NDR)`); GPUDirect RDMA from `/proc/modules` (`nvidia_peermem`, legacy `nv_peer_mem`); `libnccl.so.2` presence and the version in its file name; environment variables by name (`NCCL_SOCKET_IFNAME`, `NCCL_IB_DISABLE`); `/dev/shm` size by `statvfs` (a 64 MiB container default breaks NCCL). NVML: `nvmlDeviceGetNvLinkState`, `nvmlDeviceGetGpuFabricInfo`. W, M: not applicable. A real all-reduce test is not a built-in check: it runs a vendor binary, so it is a `custom.script` recipe (`all_reduce_perf -b 8 -e 128M -f 2 -g {n}`, with a `busbw` threshold) shipped in `examples/specs/`.
- **Needs:** root optional (`topo -m` P2P and `lspci` ACS detail), timeout 15s.
- **Thresholds:** spec `nvlink: required|any|none`, `fabric_manager: required`, `ib: {ports: 4, min_gbps: 200}`, `peermem: required`, `shm_min: 1Gi`. NVSwitch present but fabric manager down or version-mismatched: block (symptom: CUDA error 802, system not ready). NVLink down where required: block. IB port not `ACTIVE`: block (`INIT` usually means no subnet manager). `nvidia_peermem` missing: block when required. `/dev/shm` small: warn.
- **Fix:** "NVSwitch system, `nvidia-fabricmanager` is not running. Install the package that matches driver `{v}` and start it: `systemctl enable --now nvidia-fabricmanager`. The fabric manager version must equal the driver version."
- **Fixture:** fake `sys/class/infiniband` trees (active, init, down), recorded `nvlink -s` and `topo -m` output, fabric manager version strings, `proc/modules` with and without `nvidia_peermem`.

## 7. Data store checks (`store`, M3)

Placement: no crate is reserved for these. Proposal: module `rdy-checks-net::store` behind a cargo feature, off in M1 so the alpha binary stays small. Credentials come from environment variables named in the spec (`dsn_env`, `url_env`), never from the spec text. All sessions are read-only (`default_transaction_read_only = on` for Postgres, no write commands for Redis, no `PutObject` for S3).

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `store.postgres` | M3 | db credentials from env | Reachable, TLS, version, extensions, grants |
| 2 | `store.s3` | M3 | s3 credentials from env | Bucket reachable, listable, versioning, S3-compatible quirks |
| 3 | `store.redis` | M3 | optional credentials | Reachable, TLS, version, memory policy, ACL |

`store.kafka` is reserved (Reserved ids).

### store.postgres (M3)
- **Measures:** TCP, TLS support, authentication, `server_version_num`, available and installed extensions, the grants an installer needs, a few settings.
- **Source:** `tokio-postgres` with `tokio-postgres-rustls`. Without credentials the check stops after the TLS answer to an `SSLRequest` (`S` or `N`). With credentials: `SHOW server_version_num`, `SELECT name, installed_version FROM pg_available_extensions WHERE name = ANY($1)`, `SELECT rolcreatedb, rolcreaterole, rolsuper FROM pg_roles WHERE rolname = current_user`, `SELECT has_database_privilege(current_user, current_database(), 'CREATE')`, `SELECT has_schema_privilege(current_user, 'public', 'CREATE')` (PostgreSQL 15 removed the default `CREATE` on `public`), `SHOW wal_level`, `SHOW max_connections`.
- **Needs:** env DSN, timeout 10s connect and 5s per query, 20s total.
- **Thresholds:** spec `dsn_env`, `min_version: 14`, `extensions: [vector, pg_trgm]`, `public_create: true`, `wal_level: logical`, `min_max_connections: 200`, `tls: required`. Missing version, extension, grant or wal level: block. Low `max_connections`: warn. Server requires TLS but DSN has `sslmode=disable`: block with that text.
- **Fix:** "PostgreSQL 15 and later: run `GRANT CREATE ON SCHEMA public TO acme_app;` as the schema owner. Missing extension: `CREATE EXTENSION vector;` as a superuser (on RDS, a member of `rds_superuser`)."
- **Fixture:** a scripted Postgres wire server (`pgwire`, dev dependency) replaying recorded sessions: v13, v16, no `pgvector`, no `CREATE` on `public`, TLS-only server, auth failure. One optional CI job runs against a service-container Postgres with synthetic data.

### store.s3 (M3)
- **Measures:** S3 or S3-compatible endpoint (MinIO, Ceph RGW, R2): TLS, auth, bucket exists, region, listing, versioning, object lock, encryption setting, clock skew.
- **Source:** `aws-sdk-s3` with endpoint override, `force_path_style` option and `RequestChecksumCalculation::WhenRequired` (recent SDK defaults send CRC32 trailer checksums that many S3-compatible servers reject). Calls: `HeadBucket` (reads `x-amz-bucket-region`), `GetBucketVersioning`, `GetBucketEncryption`, `GetObjectLockConfiguration`, `ListObjectsV2` with `max-keys=1`, `HeadObject` on spec `probe_object`. Credentials from the SDK chain or `AWS_ACCESS_KEY_ID` style variables.
- **Needs:** credentials, timeout 10s per call.
- **Thresholds:** spec `endpoint`, `bucket`, `region`, `path_style`, `versioning: required`, `object_lock`, `ca_bundle`. Cannot reach, auth fails or bucket missing: block. Versioning or lock mismatch: block. Write permission cannot be verified without writing, so the result always carries "write access not verified" as a warn unless the spec accepts it (`write_unverified: ok`).
- **Fix:** "`RequestTimeTooSkewed`: the clock is off by `{n}`, fix `host.time_sync`. `SignatureDoesNotMatch` on MinIO: set `path_style: true`. `NoSuchBucket`: create it or fix the name."
- **Fixture:** recorded S3 XML responses via the SDK static replay client, including `RequestTimeTooSkewed`, `NoSuchBucket`, `403` and a 501 for the checksum header.

### store.redis (M3)
- **Measures:** TCP, TLS, auth, version (and Valkey), mode (standalone, cluster, sentinel), role, memory policy, persistence status, ACL rights for named commands.
- **Source:** `redis` crate with rustls. `PING`, `HELLO` or `AUTH` from `url_env`, `INFO server`, `INFO memory`, `INFO persistence`, `INFO cluster`, `CONFIG GET maxmemory-policy` (managed services often disable `CONFIG`; then `skipped`), `ACL DRYRUN <user> <command> <args>` (Redis 7) for spec commands. No writes.
- **Needs:** optional credentials, timeout 5s per call, 15s total.
- **Thresholds:** spec `url_env`, `min_version`, `mode`, `maxmemory_policy: noeviction`, `commands: ["SET", "XADD"]`, `tls: required`. Version, mode or policy mismatch: block. Command denied by ACL: block. Last RDB save failed: warn.
- **Fix:** "`maxmemory-policy` is `allkeys-lru`; the product stores queues and needs `noeviction`. Run `CONFIG SET maxmemory-policy noeviction` and persist it in `redis.conf` (managed service: change the parameter group)."
- **Fixture:** a scripted RESP server replaying recorded `INFO` outputs (Redis 6.2, 7.2, Valkey, cluster), `-NOAUTH`, `-ERR unknown command 'CONFIG'`, ACL dry-run denials.


## 8. Custom checks (`custom`)

Placement: no crate is reserved. Proposal: `custom.file` in `rdy-checks-host` (it only reads files), `custom.script` in `rdy-engine` next to the executor, because it is an engine feature that runs vendor code, not a measurement.

| Order | Id | Tier | Privilege | One line |
| --- | --- | --- | --- | --- |
| 1 | `custom.file` | M2 | reads only | File exists, mode, owner, content, certificate expiry |
| 2 | `custom.script` | M4 | whatever the script needs | Run a vendor command, compare exit code and output |

### custom.file (M2)
- **Measures:** vendor-specific files: a license, a config, a certificate.
- **Source:** `std::fs` metadata and bounded reads. Unix mode and owner through `rustix`. Content: regex over the first 64 KiB (the `regex` crate, linear time); YAML and JSON path assertions (for example `.license.expires` later than now); SHA-256 equality; PEM certificate `notAfter` through `x509-parser`. Glob matches capped at 100. Windows: mode and owner are not applicable (read-only attribute only); ACL checks are M5. macOS as Linux.
- **Needs:** read access to the path, timeout 5s. Unreadable: `partial`, with "run as the service user".
- **Thresholds:** spec `path`, `exists`, `type`, `mode_max: "0640"`, `owner`, `size_min`, `matches: <regex>`, `json_path`, `sha256`, `cert: {warn_days: 30, block_days: 7}`. Any assertion failing: the spec severity. The check never records file content except capture groups the spec names, and those pass through redaction.
- **Fix:** required in the spec for this check; `rdy spec lint` warns when it is missing.
- **Fixture:** a fake file tree with a good license, an expired one, a world-readable key, a certificate expiring in 10 days, an unreadable file.

### custom.script (M4, behind an ADR)
- **Measures:** whatever the vendor's command prints or returns.
- **Source:** the spec carries `command: [argv...]` (never a shell string) or an inline `script` with a named interpreter and a mandatory `sha256` pin. Environment is scrubbed to an allow-list, stdin closed, working directory a fresh temp directory, timeout default 30s (max 120s), stdout and stderr capped at 64 KiB, process group killed on timeout. Contained execution, not a sandbox: Linux `no_new_privs`, `setrlimit` limits and a read-only `landlock` ruleset where the kernel has it (5.13 or newer); macOS `sandbox-exec` profile denying writes and network; Windows job object with kill-on-close and a memory limit through a safe crate. No network isolation on Linux or Windows in M4, and the docs say so.
- **Needs:** whatever the script needs. Consent: skipped unless the run has `--allow-custom`, or the user types `y` after the script text is shown. Unsigned specs never run custom scripts, even with `--allow-unsigned`.
- **Thresholds:** spec `expect: {exit: 0, stdout_regex, stdout_json: {path, op, value}}`. Any mismatch: the spec severity. Timeout: `timeout` result.
- **Fix:** required in the spec.
- **Fixture:** synthetic scripts: prints `ok`; exits 3; sleeps forever; prints 10 MiB; tries to write `/etc/acme-test`; tries to read the environment for `AWS_`. Run on all four CI targets.

## 9. Reserved ids (not built at launch, names fixed so specs stay stable)

| Id | What it will do | Why not now |
| --- | --- | --- |
| `net.pmtu` | True path MTU to an endpoint | Needs DF-bit probing: raw ICMP needs root, unprivileged ICMP sockets depend on `ping_group_range`, and `rdy` forbids `unsafe`. Needs a design note. |
| `k8s.egress_probe` | Egress from inside the cluster (node network, not the laptop) | Needs a short-lived pod, which is a write. ADR. |
| `k8s.metrics` | `metrics.k8s.io` APIService available | Small; after M1. |
| `k8s.snapshots` | `VolumeSnapshotClass` for the CSI driver (`snapshot.storage.k8s.io/v1`) | Small; after M1. |
| `store.kafka` | Broker reachable, `ApiVersions`, metadata, SASL mechanism | Wire protocol work; M5. |
| `aws.imds` | Hop limit and IMDSv2 for pods (`ec2:DescribeInstances` `MetadataOptions.HttpPutResponseHopLimit`, pods need 2) | After `aws.eks`. |
| `gpu.vgpu_license` | vGPU licence state | Needs a licensed host to build against; M5. |
| `gpu.rocm` | AMD GPUs through `rocm-smi` | No design partner asked. |
| `host.virtualization` | `/dev/kvm`, nested virtualization flags | No design partner asked. |
| `host.hostname` | Valid, resolvable hostname | Folded into `net.dns` later. |

## Appendix A. Shell-out inventory

Every external command any check runs, for security review. All by fixed argv, scrubbed environment, capped output, killed on timeout. "No alternative" means no file or API gives the same answer without root or `unsafe`.

| Command | Check | OS | Why no file or API |
| --- | --- | --- | --- |
| `getent ahostsv4 <name>` | `net.dns` | L | Only glibc's resolver shows what glibc-linked products see; a static musl `getaddrinfo` ignores `nsswitch.conf` |
| `xfs_info <mount>` | `host.disk` | L | `ftype` is not in `/proc`; optional |
| `/sbin/mount` | `host.disk` | M | Mount flags such as `noexec` |
| `timedatectl show -p NTPSynchronized -p NTP -p Timezone` | `host.time_sync` | L | Daemon-independent sync flag; `adjtimex` is the primary |
| `chronyc -n tracking` | `host.time_sync` | L | Offset and leap status |
| `firewall-cmd --state`, `firewall-cmd --list-all` | `host.firewall` | L | firewalld state is in its D-Bus API only |
| `/usr/sbin/scutil --proxy`, `/usr/sbin/scutil --dns` | `net.proxy`, `net.dns` | M | SystemConfiguration has no file |
| `/usr/sbin/netstat -anv -p tcp\|udp`, `-rn -f inet` | `host.ports`, `net.mtu` | M | Socket table and routes |
| `/sbin/ifconfig -a` | `net.mtu` | M | Interface MTU |
| `systemextensionsctl list` | `host.security_agents` | M | System extension list |
| `/usr/sbin/sysctl -n <name>` | `host.cpu`, `host.sysctl` | M | sysctl namespace |
| `C:\Windows\System32\NETSTAT.EXE -ano` | `host.ports` | W | Socket table with PIDs |
| `netsh int ipv4 show excludedportrange protocol=tcp` | `host.ports` | W | Reserved port ranges |
| `powershell.exe -NoProfile -NonInteractive -Command "<fixed string>"` | `net.mtu` (and fallback for registry-less data) | W | `Get-NetIPInterface`; output is JSON, not localized text |
| `nvidia-smi -q -x`, `nvidia-smi nvlink -s`, `nvidia-smi topo -m`, `nvidia-smi --query-gpu=index,compute_cap --format=csv,noheader` | `gpu.*` | L, W | NVML is not loadable from a static musl binary |
| `nvidia-ctk --version`, `nvcc --version`, `nv-fabricmanager -v` | `gpu.runtime`, `gpu.cuda`, `gpu.fabric` | L | Versions only printed by the tools |

Windows registry and WMI are read in process (`winreg`, `wmi`), not through PowerShell.

## Appendix B. Data files shipped inside the binary

Embedded at build time, versioned with the release, one unit test per entry. Each entry carries `source` (URL of the public documentation it came from) and `checked_on` (date). CI warns when `checked_on` is older than 180 days. Updating them between releases is an ADR item.

| File | Used by | Contents |
| --- | --- | --- |
| `agents.toml` | `host.security_agents` | Product id, display name, process names, directories, service names, kernel modules per OS, and a plain note on what the agent hooks and which paths to exclude |
| `provisioners.toml` | `k8s.storageclass` | CSI provisioner name to supported access modes, zonal or not: `ebs.csi.aws.com` RWO zonal, `pd.csi.storage.gke.io` RWO zonal, `disk.csi.azure.com` RWO zonal, `efs.csi.aws.com` RWX, `file.csi.azure.com` RWX, `nfs.csi.k8s.io` RWX, `cephfs.csi.ceph.com` RWX, `rbd.csi.ceph.com` RWO (RWX for raw block only) |
| `cni.toml` | `k8s.cni` | CNI DaemonSet names and whether NetworkPolicy is enforced (Calico, Cilium, Antrea, Weave, OVN-Kubernetes yes; Flannel alone no; AWS VPC CNI "depends on configuration") |
| `cuda_driver_min.toml` | `gpu.cuda` | CUDA version to minimum Linux driver. Seeded with 12.2 to 535.54.03 and 12.4 to 550.54.14; gpu-expert completes it from NVIDIA's release notes |
| `gpu_arch.toml` | `gpu.devices` | Product architecture to compute capability, used only when `compute_cap` is unavailable. It is one to many (Ampere is 8.0 for A100 and 8.6 for the A10 family), so the fallback returns a range, not a number |
| `aws_quotas.toml` | `aws.quota` | Service, quota code and name, as listed in `aws.quota` |

## Plan corrections found

- `docs/plan/rdy-plan.md`, "Rust build plan", crate table, row `rdy-checks-gpu` ("nvml-wrapper (optional), nvidia-smi fallback"): NVML is reached by `dlopen` of `libnvidia-ml.so.1`, and a fully static musl binary cannot load glibc shared libraries. Fix: primary source is `nvidia-smi -q -x`; `nvml-wrapper` only in an optional glibc-linked build (ADR).
- `docs/plan/rdy-plan.md`, same table, row `rdy-checks-host` ("sysinfo, nix, windows-sys"), against `CLAUDE.md` "Engineering standards" (`#![forbid(unsafe_code)]` in every crate except FFI): direct `windows-sys` calls need `unsafe`. Fix: use `sysinfo`, `rustix`, `winreg`, `wmi`, which expose safe APIs, and keep any remaining FFI in one documented crate.
- `docs/plan/rdy-plan.md`, same table, row `rdy-checks-net` ("reqwest with rustls, hickory-resolver"): `reqwest` does not expose the peer certificate chain, so TLS interception detection needs a custom `tokio-rustls` connector; `hickory-resolver` does not behave like the system resolver, so the "does it resolve for the product" answer needs `getent` on Linux. Fix: list `tokio-rustls`, `rustls-native-certs`, `webpki-roots`, `x509-parser` and the `getent` shell-out.
- `docs/plan/rdy-plan.md`, "Check families at launch" (Data stores, Custom), `CLAUDE.md` repo layout, and the milestone table: these two families have no crate and no milestone. Fix: stores as a feature-gated module in `rdy-checks-net` (M3), `custom.file` in `rdy-checks-host` (M2), `custom.script` in `rdy-engine` (M4, ADR). Also `CLAUDE.md` lists "device plugin" and "VRAM per node" under `rdy-checks-gpu`; the in-cluster half lives in `rdy-checks-k8s` as `k8s.device_plugins`, the host half in `gpu.vram`.
- `docs/plan/rdy-plan.md`, "Example spec": `gpu.cuda min: "12.4"` does not say driver-supported CUDA or installed toolkit (fix: add `source: driver|toolkit`, default `driver`); `host.memory min: 32Gi` would block a nominal 32 GiB VM that reports 31.3 GiB (fix: the nominal band, section 1); `aws.iam simulate:` needs the caller to hold `iam:SimulatePrincipalPolicy` and cannot take an assumed-role ARN (fix: EC2 dry-run fallback, role ARN lookup via `iam:GetRole`). The plan's phrase "IAM permissions dry-run" should say "simulation, with EC2 dry-run as fallback".
- `docs/plan/rdy-plan.md`, "Milestones" and "Build order inside M1", and `KICKOFF.md` ("M1 is six weeks"): the check work alone is about 58 hours for the minimum useful set and about 130 hours for all M1 families, against a window of 18 to 48 hours after workspace, spec, engine, report, signing and release work. Fix: either M1 becomes eight to ten weeks, or only the `M1` tier ships in M1 and `M1-late` becomes the first milestone after it. Cut order if hours run short: `k8s.nodes`, `k8s.rbac`, `net.tls_intercept`, `host.os`. See the ticket list for the totals.
- `CLAUDE.md`, "Engineering standards", Cross-platform bullet ("from day one ... CI runs all four"): with the hours above, data sources for macOS and Windows cannot all land in M1. Fix wording: every check compiles and runs on all four targets from day one and returns `skipped` with a clear reason where the data source is missing; sources arrive per ticket.
- `CLAUDE.md`, "Engineering standards", Async bullet ("naturally blocking checks run on `spawn_blocking` ... every check has a timeout"): a blocked syscall (NFS `statvfs`, a wedged `nvidia-smi`) cannot be cancelled, and dropping a Tokio runtime waits for blocking tasks. Fix: the runner must end the process with `Runtime::shutdown_timeout` or `process::exit` after the report is written, so one hung mount cannot hang `rdy`. For `rust-architect` to put in `02-engine-design.md`.

## Decisions needing an ADR

Conservative choice taken in this catalog is listed first in each item.

- Server-side dry-run in `k8s.admission`: off by default and enabled only by spec `dry_run: true` plus a user flag. It stores nothing, and the API server refuses webhooks that are not dry-run safe, but it is a `create` call and appears in audit logs. Alternatives: on by default; never.
- The TLS probe verifier in `net.tls_intercept` (accepts any chain, records it, sends zero application bytes, used nowhere else). Alternative: infer interception only from verification failures, which misses the case where the proxy CA is already trusted.
- `custom.script`: skipped without `--allow-custom`, never with an unsigned spec, called "contained" rather than "sandboxed". Alternatives: no scripts at all until a real sandbox exists; scripts allowed with signed specs without a prompt.
- GPU data source: `nvidia-smi` only in the static musl binary. Alternative: an optional glibc build with an `nvml` feature.
- Writes are excluded everywhere (canary PVC, egress pod, S3 `PutObject`). Alternative: an explicit `--allow-writes` flag that unlocks `k8s.egress_probe`, a PVC canary and `store.s3` write probe.
- `getent` shell-out for Linux system DNS, with in-process lookups only as fallback. Alternative: in-process only, with a documented difference from glibc.
- Embedded data files (Appendix B) updated only by release. Alternative: signed catalog updates fetched or carried in the spec.
- `assume` in `aws.*` checks performs `sts:AssumeRole` on a role named in the vendor's spec. Conservative: requires the user to pass `--allow-assume-role` or confirm interactively. Alternative: implied by the signed spec.
- Placement of `store.*` and `custom.*` in existing crates (see corrections) versus new crates.

## Tickets implied

Hours: M1 tier is 58 (plumbing 14, host 15, net 14, k8s 15), M1-late is 73, reviews 6. `engine: Check trait and runner` is the rust-architect ticket from `02-engine-design.md`; map the title when `11-backlog.md` is merged.

Plumbing (M1)
- [M1] Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | owner: rust-engineer | est: 3h | depends on: engine: Check trait and runner | exit test: a fake command that sleeps and one that prints 5 MiB both return `timeout` and a capped result in a unit test, and a recorded `chronyc` output replays byte for byte.
- [M1] Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | owner: rust-engineer | est: 3h | depends on: Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | exit test: a toy check reads `root/proc/meminfo` and its result equals `expect.json`; changing the fixture fails the test.
- [M1] Units and threshold helpers (Gi parsing, dotted version compare, nominal band, severity cap) | owner: check-author | est: 2h | depends on: engine: Check trait and runner | exit test: table tests pass, including 31.3 GiB against `min: 32Gi` giving pass with a note and `severity: warn` capping a block.
- [M1] Loopback network test support (TLS server with generated CA, CONNECT proxy modes, closed port, never-accepting listener, reset after ClientHello) | owner: rust-engineer | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a smoke test starts each server and a raw client observes the expected behaviour on Linux, macOS and Windows CI.
- [M1] Kube mock harness (tower service replaying `api/` JSON, review-table answers) | owner: rust-engineer | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a `kube::Client` built on the mock lists a recorded `nodes.json` and answers a `SelfSubjectAccessReview` from a table.

Host (M1)
- [M1] host.disk (Linux: statvfs, mountinfo, noexec, fstype, timeout on hung mounts) | owner: check-author | est: 4h | depends on: Units and threshold helpers (Gi parsing, dotted version compare, nominal band, severity cap); Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: golden results for plenty, tight, full inodes, `noexec` /tmp, NFS and hung-mount fixtures.
- [M1] host.memory (meminfo, swap, cgroup limit, nominal band) | owner: check-author | est: 3h | depends on: Units and threshold helpers (Gi parsing, dotted version compare, nominal band, severity cap); Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a 31.3 GiB meminfo against `min: 32Gi` passes with a note, 24 GiB blocks, `swap: off` with swap blocks.
- [M1] host.cpu (cores with cgroup quota, arch, flags, hypervisor) | owner: check-author | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a cpuinfo without `avx2` blocks with the passthrough fix text; a `cpu.max` quota of 200000/100000 reports 2 cores.
- [M1] host.ports (Linux /proc/net parsing, owner lookup, bind fallback, ephemeral overlap) | owner: check-author | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: fixtures with 6443 held by a named process blocks, the same without root reports owner unknown, an allowed owner passes.
- [M1] host.os (os-release, uname, FIPS, container and WSL detection) | owner: check-author | est: 2h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: RHEL 9, Ubuntu 22.04, Alpine and Rocky (`ID_LIKE`) fixtures match or miss a `supported` list as expected.

Network (M1)
- [M1] net.egress core (DNS, TCP, TLS, HTTP, failure classes, injectable connector) | owner: check-author | est: 4h | depends on: Units and threshold helpers (Gi parsing, dotted version compare, nominal band, severity cap); Loopback network test support (TLS server with generated CA, CONNECT proxy modes, closed port, never-accepting listener, reset after ClientHello) | exit test: loopback cases classify refused, blackhole, TLS unknown issuer, reset after hello and HTTP status correctly.
- [M1] net.egress via proxy and redirect host list | owner: check-author | est: 3h | depends on: net.egress core (DNS, TCP, TLS, HTTP, failure classes, injectable connector) | exit test: CONNECT proxy modes ok, 403 and 407 give the right text; a 302 to a second host lists both hosts.
- [M1] net.proxy (Linux env and config files, daemon drop-ins, NO_PROXY coverage, reachability) | owner: check-author | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a fixture with a shell proxy but no docker drop-in warns and prints the drop-in text; userinfo never appears in the result.
- [M1] net.tls_intercept (probe verifier, chain classification, trust store report) | owner: check-author | est: 4h | depends on: net.egress core (DNS, TCP, TLS, HTTP, failure classes, injectable connector) | exit test: generated chains classify as public, private-CA-trusted and unknown-CA; a test proves zero application bytes are written.

Kubernetes (M1)
- [M1] k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | owner: check-author | est: 3h | depends on: Kube mock harness (tower service replaying `api/` JSON, review-table answers) | exit test: fixtures for good, 401, 403, x509 error, expired cert and wrong context all give the expected result and fix text.
- [M1] k8s.version (gitVersion parse, distro, discovery API availability) | owner: check-author | est: 2h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: EKS `v1.29.4-eks-abc123` parses to 1.29, a missing `autoscaling/v2` blocks.
- [M1] k8s.storageclass (default class, CSI driver, binding mode, provisioner table) | owner: check-author | est: 3h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: none, two-default, Immediate-zonal and no-CSIDriver fixtures give the expected levels.
- [M1] k8s.rbac (SelfSubjectReview, access reviews, escalate and bind probes) | owner: check-author | est: 3h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: a table with two denied items blocks and lists both with reasons.
- [M1] k8s.nodes (allocatable, free capacity from pods, conditions, taints, zones) | owner: check-author | est: 4h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: a 3-node fixture where requests use 90% of CPU blocks a 16 CPU free requirement; a forbidden pod list gives a partial result.

Host M1-late
- [M1] host.lsm (SELinux, AppArmor, audit log denials) (M1-late) | owner: check-author | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: enforcing with two AVC lines for a watched context blocks; unreadable audit log gives partial.
- [M1] host.security_agents with `agents.toml` catalog (Linux and macOS detection) (M1-late) | owner: check-author | est: 4h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: each catalog entry has a fixture that detects it; `forbid` blocks and `allow` silences.
- [M1] host.firewall (firewalld, ufw, macOS ALF plist, Windows registry profiles) (M1-late) | owner: check-author | est: 3h | depends on: Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | exit test: a closed port in a recorded `--list-all` blocks; a root-less run warns.
- [M1] host.time_sync (adjtimex, timedatectl, chronyc, SNTP client) (M1-late) | owner: check-author | est: 4h | depends on: Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | exit test: a scripted SNTP responder with a 400s offset blocks; an unsynchronized `adjtimex` fixture warns.
- [M1] host.sysctl (live and persisted values, systemd limits) (M1-late) | owner: check-author | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: right live value with no `sysctl.d` entry warns "not persisted".
- [M1] host.container_runtime (sockets, daemon.json, containerd config, drop-ins, API) (M1-late) | owner: check-author | est: 4h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a cgroupfs/systemd mismatch fixture blocks with the `SystemdCgroup` fix.
- [M1] host.cgroups (M1-late) | owner: check-author | est: 2h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: v1, v2 and memory-controller-off fixtures give the expected levels.
- [M1] host.kernel (version and modules) (M1-late) | owner: check-author | est: 3h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: a module present only in `modules.dep` warns, absent blocks, `distro_min` overrides the upstream compare.
- [M1] macOS data sources for host.disk, memory, cpu, ports, os (M1-late) | owner: check-author | est: 3h | depends on: host.disk (Linux: statvfs, mountinfo, noexec, fstype, timeout on hung mounts) | exit test: recorded macOS `mount`, `netstat`, `sysctl` and plist fixtures pass on the macOS CI job.
- [M1] Windows data sources for host.disk, memory, cpu (registry helper included) (M1-late) | owner: check-author | est: 3h | depends on: host.disk (Linux: statvfs, mountinfo, noexec, fstype, timeout on hung mounts) | exit test: recorded registry JSON and `sysinfo`-style fixtures pass on the Windows CI job.
- [M1] Windows data sources for host.ports and host.os (M1-late) | owner: check-author | est: 2h | depends on: Windows data sources for host.disk, memory, cpu (registry helper included) (M1-late) | exit test: recorded `NETSTAT`, excluded-port-range and `CurrentVersion` registry fixtures pass on the Windows CI job.
- [M1] macOS and Windows sources for security_agents, firewall, time_sync (M1-late) | owner: check-author | est: 3h | depends on: host.security_agents with `agents.toml` catalog (Linux and macOS detection) (M1-late) | exit test: Defender-exclusion, ALF and W32Time fixtures give expected results.

Network M1-late
- [M1] net.dns (getent, hickory direct lookups, resolv.conf and nsswitch analysis, scripted DNS server) (M1-late) | owner: check-author | est: 4h | depends on: net.egress core (DNS, TCP, TLS, HTTP, failure classes, injectable connector) | exit test: split-horizon and slow-first-nameserver fixtures warn; NXDOMAIN blocks.
- [M1] net.registry (v2 ping, token realm, manifest and blob host) (M1-late) | owner: check-author | est: 3h | depends on: net.egress via proxy and redirect host list | exit test: a mock whose blob redirect host is closed blocks and names that host.
- [M1] net.mtu (Linux sysfs, overlay overhead) (M1-late) | owner: check-author | est: 2h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: MTU 1450 with `overlay: vxlan` and `min_mtu: 1400` blocks; MTU 9001 warns.
- [M1] net.bandwidth (capped GET sample) (M1-late) | owner: check-author | est: 2h | depends on: net.egress via proxy and redirect host list | exit test: a throttled loopback server measures within 20% of its rate.
- [M1] macOS and Windows sources for net.proxy, net.dns, net.mtu (M1-late) | owner: check-author | est: 3h | depends on: net.proxy (Linux env and config files, daemon drop-ins, NO_PROXY coverage, reachability) | exit test: `scutil` and registry fixtures parse to the expected proxy and nameserver lists.
- [M1] Evidence redaction helpers (proxy userinfo, env allow-list) with security-reviewer sign-off (M1-late) | owner: check-author | est: 2h | depends on: net.proxy (Linux env and config files, daemon drop-ins, NO_PROXY coverage, reachability) | exit test: golden results contain none of the planted `REDACTED-TEST-TOKEN`, password or userinfo strings.

Kubernetes M1-late
- [M1] k8s.admission (PSA labels, webhooks with endpoint check, policy engine and SCC discovery) (M1-late) | owner: check-author | est: 4h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: a `restricted` namespace blocks a `baseline` need; a Fail webhook with an empty EndpointSlice blocks; forbidden webhook lists give partial.
- [M1] k8s.namespace (existence, terminating, quota, limit range) (M1-late) | owner: check-author | est: 2h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: a quota with 2 CPU left blocks a 16 CPU need.
- [M1] k8s.ingress (IngressClass, Gateway API, pending LoadBalancer) (M1-late) | owner: check-author | est: 3h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: missing class blocks; a 20-minute-old pending LB warns.
- [M1] k8s.crds (CRDs, served versions, operator version) (M1-late) | owner: check-author | est: 3h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: missing CRD blocks with the Helm fix; operator below `min_version` blocks.
- [M1] k8s.cni (CNI detection, NetworkPolicy, default-deny, CIDRs, `cni.toml`) (M1-late) | owner: check-author | est: 3h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: Flannel with `network_policy: enforced` blocks; default-deny egress warns.
- [M1] k8s.dns (CoreDNS readiness, Corefile loop risk) (M1-late) | owner: check-author | est: 2h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: a crash-looping CoreDNS with `forward . /etc/resolv.conf` blocks with the loop text.
- [M1] k8s.device_plugins (extended resources, GFD labels, operator state) (M1-late) | owner: check-author | est: 3h | depends on: k8s.nodes (allocatable, free capacity from pods, conditions, taints, zones) | exit test: GPU-labelled nodes with zero allocatable block; MIG mixed strategy against `nvidia.com/gpu` blocks.

Reviews (M1)
- [M1] Review k8s checks and fixtures (semantics, API groups, RBAC degrade) | owner: k8s-expert | est: 3h | depends on: k8s.nodes (allocatable, free capacity from pods, conditions, taints, zones) | exit test: written review with every finding fixed or filed.
- [M1] Security review of the TLS probe verifier and the shell-out inventory | owner: security-reviewer | est: 3h | depends on: net.tls_intercept (probe verifier, chain classification, trust store report) | exit test: review signed off, Appendix A matches the code.

Later milestones
- [M2] custom.file | owner: check-author | est: 4h | depends on: host.disk (Linux: statvfs, mountinfo, noexec, fstype, timeout on hung mounts) | exit test: good, expired, world-readable and unreadable fixtures give expected results.
- [M2] k8s.admission dry-run mode, after its ADR | owner: check-author | est: 3h | depends on: k8s.admission (PSA labels, webhooks with endpoint check, policy engine and SCC discovery) (M1-late) | exit test: recorded dry-run denial bodies surface the denial text; default run makes no create call.
- [M2] host.firewall raw nft and iptables parsing, Windows inbound rules | owner: check-author | est: 4h | depends on: host.firewall (firewalld, ufw, macOS ALF plist, Windows registry profiles) (M1-late) | exit test: recorded `nft list ruleset` with a drop policy blocks.
- [M2] k8s.metrics and k8s.snapshots | owner: check-author | est: 4h | depends on: k8s.access (kubeconfig, version, auth classes, expiry, proxy and TLS flags) | exit test: missing APIService and missing VolumeSnapshotClass fixtures warn.
- [M3] AWS common: credential chain, assume role, replay harness, degrade rules | owner: check-author | est: 5h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: no-credentials run returns skipped for every `aws.*`; assume-role fixture runs as the assumed identity.
- [M3] aws.identity | owner: check-author | est: 2h | depends on: AWS common: credential chain, assume role, replay harness, degrade rules | exit test: wrong-account fixture blocks.
- [M3] aws.iam (simulate, role ARN resolution, EC2 dry-run fallback) | owner: check-author | est: 6h | depends on: aws.identity | exit test: implicit deny, org-SCP deny, missing context, SSO path role and dry-run fixtures all classify correctly.
- [M3] aws.quota with `aws_quotas.toml` | owner: check-author | est: 5h | depends on: AWS common: credential chain, assume role, replay harness, degrade rules | exit test: 64 vCPU need against a 32 vCPU limit blocks with the CLI fix.
- [M3] aws.vpc | owner: check-author | est: 5h | depends on: AWS common: credential chain, assume role, replay harness, degrade rules | exit test: 9-free-IP subnet and missing NAT route block.
- [M3] aws.region | owner: check-author | est: 4h | depends on: AWS common: credential chain, assume role, replay harness, degrade rules | exit test: opt-in region not enabled blocks; instance type in one of three AZs blocks `min_azs: 2`.
- [M3] aws.eks | owner: check-author | est: 5h | depends on: aws.vpc | exit test: private-only endpoint and missing OIDC provider fixtures block.
- [M3] Review AWS checks (actions, simulator caveats, quota codes) | owner: cloud-iam-expert | est: 3h | depends on: aws.eks | exit test: written review with every finding fixed or filed; quota codes confirmed against a live listing.
- [M3] store.postgres | owner: check-author | est: 6h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: PG 15 without `CREATE` on `public` and a missing extension block.
- [M3] store.s3 | owner: check-author | est: 5h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: skew, missing bucket and checksum-rejecting server classify correctly.
- [M3] store.redis | owner: check-author | est: 4h | depends on: Fixture loader and golden compare (`root/`, `commands/`, `api/`, `expect.json`) | exit test: `allkeys-lru` against `noeviction` blocks; disabled `CONFIG` gives skipped.
- [M4] GPU shared layer: `nvidia-smi -q -x` runner, tolerant XML parser, failure classifier, fixtures for 5 driver generations | owner: check-author | est: 6h | depends on: Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | exit test: every failure string and a hung run classify; XML from 535 and 550 parse to the same model.
- [M4] gpu.driver and gpu.cuda with `cuda_driver_min.toml` | owner: check-author | est: 6h | depends on: GPU shared layer: `nvidia-smi -q -x` runner, tolerant XML parser, failure classifier, fixtures for 5 driver generations | exit test: version mismatch blocks with reboot text; driver supporting 12.2 against `min: "12.4"` blocks with the 550.54.14 hint.
- [M4] gpu.vram and gpu.devices with `gpu_arch.toml` | owner: check-author | est: 6h | depends on: GPU shared layer: `nvidia-smi -q -x` runner, tolerant XML parser, failure classifier, fixtures for 5 driver generations | exit test: L4 at 23034 MiB against `24Gi` warns inside the band; MIG-on blocks `mig: forbid`.
- [M4] gpu.runtime | owner: check-author | est: 3h | depends on: GPU shared layer: `nvidia-smi -q -x` runner, tolerant XML parser, failure classifier, fixtures for 5 driver generations | exit test: toolkit present but not registered with containerd blocks with the `nvidia-ctk` fix.
- [M4] gpu.health | owner: check-author | est: 4h | depends on: GPU shared layer: `nvidia-smi -q -x` runner, tolerant XML parser, failure classifier, fixtures for 5 driver generations | exit test: Xid 79 in the window blocks; root-less run is partial.
- [M4] gpu.fabric | owner: check-author | est: 6h | depends on: GPU shared layer: `nvidia-smi -q -x` runner, tolerant XML parser, failure classifier, fixtures for 5 driver generations | exit test: NVSwitch with no fabric manager blocks; IB port `INIT` blocks.
- [M4] gpu.model_egress | owner: check-author | est: 4h | depends on: net.egress via proxy and redirect host list | exit test: blocked CDN redirect host is named in the block.
- [M4] Review GPU checks (NVML fields, nvidia-smi tags, driver table, Xid list) and complete `cuda_driver_min.toml` | owner: gpu-expert | est: 4h | depends on: gpu.fabric | exit test: written review with every finding fixed or filed.
- [M4] custom.script: contained executor, consent gate, sandbox tests on four OSes, after its ADR | owner: rust-engineer | est: 12h | depends on: custom.file | exit test: the six synthetic scripts behave as specified on Linux, macOS and Windows CI, and unsigned specs never run them.
- [M5] gcp.iam, gcp.quota, gcp.apis | owner: check-author | est: 12h | depends on: AWS common: credential chain, assume role, replay harness, degrade rules | exit test: recorded REST responses for allowed, denied and quota-short cases.
- [M5] azure.rbac, azure.quota, azure.providers | owner: check-author | est: 12h | depends on: AWS common: credential chain, assume role, replay harness, degrade rules | exit test: recorded ARM responses for allowed, denied and quota-short cases.
- [M5] store.kafka and gpu.vgpu_license | owner: check-author | est: 9h | depends on: store.redis | exit test: recorded broker and licence fixtures classify correctly.
