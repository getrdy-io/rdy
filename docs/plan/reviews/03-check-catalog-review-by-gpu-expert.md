# Review of the GPU family in the check catalog, by gpu-expert

Scope: section 6 (`gpu.*`), the GPU rows of Appendix A and B, and `k8s.device_plugins` in section 4, in `/home/user/rdy/docs/plan/03-check-catalog.md`. Read against `CLAUDE.md`, the plan milestones and ADR 0006. The catalog was not edited.

## Verdict

Approve with changes. The structure is good: one shared `nvidia-smi -q -x` call, a failure classifier, tolerant parsing, the degrade rule, and the "no kernel module, no workload" posture. The data source decision is right. But eight things would give wrong answers on real customer sites (false green, false block, or a broken invariant), and several are cheap to fix on paper now and expensive after the M1 engine ships.

Counts: **must fix 8**, should fix 25, nit 8.

## Lookups done (the items the author flagged as unconfirmed)

| Item | Result |
| --- | --- |
| CUDA to minimum driver table | Both seeded rows are correct for the GA release on Linux: 12.2 needs 535.54.03, 12.4 needs 550.54.14 (NVIDIA CUDA release notes, Table 4). But they are the driver each toolkit shipped with, not the minimum a CUDA app needs to run. The minimum for minor version compatibility is a separate table (Table 3): 11.x needs 450 or newer, 12.x needs 525 or newer, 13.x needs 580 or newer. See finding 1 for full rows. |
| Xid list | 48, 79, 95, 74, 13, 31 are named correctly. 63 is informational ("IGNORE" in NVIDIA's catalog) and 64 is a failure (reset needed), so the author has them the wrong way round. Missing: 119 and 120 (GSP timeout and error), 140 (uncorrectable ECC escape). See finding 12. |
| GFD label spellings | Both driver spellings are real. `nvidia.com/cuda.driver.major/minor/rev` are deprecated; the current ones are `nvidia.com/cuda.driver-version.major/minor/revision/full` (note `revision`, not `rev`). Same for `cuda.runtime.*` (deprecated) and `cuda.runtime-version.*`. `gpu.product`, `gpu.memory` (MiB), `gpu.count`, `gpu.replicas`, `gpu.compute.major/minor`, `gpu.family`, `mig.strategy` are correct. `nvidia.com/gpu.present` is NOT a GFD output label. Detect GPU nodes with `feature.node.kubernetes.io/pci-10de.present=true` (NFD). See finding 6. |
| nvidia-smi XML tag names | NVIDIA publishes no tag list. The only contract is the DTD, printed by `nvidia-smi -q -x --dtd` (confirmed in NVIDIA docs). I could not fetch a full sample here. From recollection of the DTD, several tags in the catalog are wrong. See finding 7. Treat my corrections as likely, and check them against a recorded `--dtd` file before coding. |
| nvidia-smi exit codes | Confirmed from NVIDIA docs: 9 driver not loaded, 12 NVML library not found, 14 infoROM corrupted, 15 GPU fell off the bus, 4 no permission, 255 other. The classifier should key on exit code first and strings second. See finding 11. |
| nvidia-modprobe | Confirmed: NVIDIA's MIG guide says nvidia-smi automatically invokes nvidia-modprobe, and nvidia-modprobe loads the kernel module. See finding 5. |

## Static musl and the data source decision

Confirmed. A static musl binary cannot `dlopen` `libnvidia-ml.so.1`. The library is glibc-only, and a static musl process has no dynamic loader. Even a dynamic musl build (Alpine) cannot load it. `nvidia-smi` itself is a normal glibc binary, so running it as a child process works from a static `rdy`, including inside scratch or Alpine containers when the container toolkit mounts it. ADR 0006 section 5 already decides this, so the catalog's "Decisions needing an ADR" item for the GPU data source is stale (see "Plan corrections found").

Glibc build variant: not worth it. Every host that has `libnvidia-ml` also has `nvidia-smi` (same package), so NVML gives no new coverage, only structured data and speed. A second glibc artifact doubles signing, install-script and support work for a part-time founder, and ADR 0006 already rejected shipping both. Revisit only if a design partner needs something `nvidia-smi` cannot print (for example `nvmlDeviceGetGpuFabricInfo` detail on a new fabric, or per-process MIG accounting), or if probe time under one second becomes a hard need.

Tiny helper (a separate glibc binary that links NVML and prints JSON): also not worth it now. Same coverage as `nvidia-smi`, a second executable to sign and to explain to a security reviewer, and it breaks the "one binary" message. If NVML is ever needed, a helper beats a second full build, but only after a partner asks. Record both as revisit triggers, not as work.

What makes the `nvidia-smi` path safe: parse by tag name, never by position; record the DTD version (the `DOCTYPE` line) in evidence; keep a fixture per driver generation; capture `--dtd` with each fixture so tag names are checked, not guessed.

## Findings, ranked

### Must fix

**1. `gpu.cuda`: the compatibility logic is wrong for the common case.**
Problem: the check blocks when the driver-reported CUDA version is below the product's `min` (the exit test: a driver supporting 12.2 against `min: "12.4"` blocks with the 550.54.14 hint). That is false for most real products. CUDA minor version compatibility lets an app built with any 12.x toolkit run on any driver of 525 or newer (Linux), with limits (no PTX JIT of newer code, some newer features unavailable). Forward compatibility (the `cuda-compat` package) is a separate mechanism for crossing major versions or running on drivers below the floor, and it is supported only on data centre GPUs and some kernel driver branches. The catalog mixes the two in `compat_ok`, and says the compat libraries live in `/usr/local/cuda/compat` on the host, when in practice they ship inside the product's container. The table is Linux only and has two rows. Windows numbers differ (12.4 GA is 551.61 on Windows).
Fix:
- Spec `built_with: "12.4"` (replaces the ambiguous `min`) and `compat: minor|strict|forward`, default `minor`.
- `minor`: pass if the driver is at or above the major-version floor (11.x: 450, 12.x: 525.60.13, 13.x: 580), with a note that PTX JIT and newer features are not covered. `strict`: use the GA row. `forward`: pass if the GPU is data centre class (add `datacenter: true` to `gpu_arch.toml`; do not infer it from `product_brand`, which reads only "NVIDIA" on current cards) and the product declares it ships `cuda-compat`. Say plainly that Rdy cannot see inside the container, so this is "plausible", not "verified".
- Compare driver versions numerically per component (`535.54.03` is below `535.104.05`; `05` equals `5`). Windows has two parts (`551.61`).
- Two columns in `cuda_driver_min.toml`, Linux and Windows. GA rows from the release notes (Linux / Windows): 12.0 525.60.13 / 527.41; 12.1 530.30.02 / 531.14; 12.2 535.54.03 / 536.25; 12.3 545.23.06 / 545.84; 12.4 550.54.14 / 551.61; 12.5 555.42.02 / 555.85; 12.6 560.28.03 / 560.76; 12.8 570.26 / 570.65; 12.9 575.51.03 / 576.02. The page I read had no 13.0 shipped-driver row, so leave it empty until read; the 13.x floor of 580 is confirmed. Each row keeps `source` and `checked_on`.
- Change the ticket exit test to: "driver reporting 12.2, product built with 12.4, `compat: minor`, passes with a note; with `compat: strict` blocks with the 550.54.14 hint".

**2. `gpu.vram`: the nominal band makes the most common good case warn.**
Problem: the band counts as warn, but `host.memory` counts it as pass with a note. For a product that needs `80Gi`, an A100 80GB reports 81920 MiB and passes, while an H100 80GB reports 81559 MiB (79.65 GiB) and warns. Same class of card, different result, and every H100 customer gets exit code 1. The exit test (L4 at 23034 MiB against `24Gi` warns) bakes this in.
Fix: inside the band is pass with a note, as for memory. Keep the 8% default (L4 is 6.3% under, T4 6.25% under, A10G about 7.5% under, so 8% is tight but right; do not widen it). Offer `band_result: warn` for vendors who want it. Say in the spec docs that `min_per_gpu` should be the real need, not the marketing size.

**3. Operator-managed hosts: tool and runtime paths are wrong, so a healthy GPU node reads as "no NVIDIA tooling" or "toolkit missing".**
Problem: with the NVIDIA GPU Operator the driver can run in a container, so `nvidia-smi` is at `/run/nvidia/driver/usr/bin/nvidia-smi`, not on the host `PATH`. The operator also installs the container toolkit under `/usr/local/nvidia/toolkit/`, not `/usr/bin`. The catalog's fixed `PATH` and its `/usr/bin/nvidia-ctk` check will report "skipped: no NVIDIA tooling" and "toolkit missing: block" on these nodes. Managed clouds add more locations (`/usr/local/nvidia/bin` on GKE, `/home/kubernetes/bin/nvidia`).
Fix: an ordered search list for `nvidia-smi` and `nvidia-ctk`: `/usr/bin`, `/usr/local/nvidia/bin`, `/usr/local/nvidia/toolkit`, `/run/nvidia/driver/usr/bin`, `/home/kubernetes/bin/nvidia`, `/usr/lib/wsl/lib`, then Windows paths. Record which one was used. If `/proc/driver/nvidia` exists but no `nvidia-smi` is found, say "driver loaded, tool not found", not "no tooling". Add a fixture with the operator layout.

**4. "Skipped" on a host with no GPU hides a blocker and reads as green.**
Problem: no `nvidia-smi` gives `skipped: no NVIDIA tooling`, plus a PCI hint. If the spec requires `gpu.devices count: 4` and someone runs `rdy` on a CPU node, a laptop or the wrong VM, those checks skip and the run can exit 0. The same happens on the dominant Kubernetes path: `rdy` runs on a laptop with a kubeconfig, so every host `gpu.*` check skips and the report shows GPU readiness as fine when nothing was examined. Also, vendor `0x10de` alone matches a GPU's HDMI audio function and NVSwitch bridges, not only GPUs.
Fix:
- Split the result: `not_applicable` (OS, or spec `optional: true`) versus `unverified` (a required thing could not be examined). The score must treat `unverified` as not ready, and the report must say "GPU hardware was not examined on this machine".
- The PCI scan reads `class` as well as `vendor`: count display and 3D controller classes (`0x03xxxx`) only. Report `NVIDIA GPU present, no driver`, `no NVIDIA GPU`, and `GPU bound to vfio-pci` (a hypervisor host, valid) as three different results. If the spec requires GPUs and none is present: block.
- This needs the result model to carry the reason (finding 8).

**5. `nvidia-smi` can load the kernel module, which breaks the "never load a kernel module" rule.**
Problem: NVIDIA's MIG guide says nvidia-smi automatically invokes `nvidia-modprobe` to create device nodes, and `nvidia-modprobe` (setuid root) loads the kernel module. So running `nvidia-smi` on a node where the driver is installed but not loaded can load the module and create `/dev/nvidia*` as a side effect. That changes the machine, and it can mask the very failure Rdy exists to report ("driver not loaded"). I confirmed the general behaviour; I did not confirm the exact trigger inside `libnvidia-ml`, so treat the trigger as likely.
Fix: gate every `nvidia-smi` call on the kernel side already being present: `/proc/driver/nvidia/version` readable or `/sys/module/nvidia` exists. If not, classify "driver not loaded" from files alone and do not run the tool. Add this to the command policy in section 1: "GPU tools only run after the kernel side is seen". Add a fixture where the module is absent and the runner asserts it was never called.

**6. `k8s.device_plugins`: no VRAM or GPU-class check, wrong detection label, no free-capacity logic, and it will false-block on DRA nodes.**
Problem: the plan puts "VRAM per node" in the GPU family, but the host `gpu.vram` only runs on the GPU node. On Kubernetes, where most GPU installs happen, the only VRAM data `rdy` can see is the GFD labels, and the catalog uses none of them for a threshold. Also:
- (a) `nvidia.com/gpu.present` is not a GFD label (it is a manual or operator label). The reliable signals are `feature.node.kubernetes.io/pci-10de.present=true` and a non-empty `nvidia.com/gpu.product`.
- (b) The check compares `allocatable`, but the most common scheduling failure is `Insufficient nvidia.com/gpu` because other pods hold all GPUs. Free = allocatable minus pod requests.
- (c) With the NVIDIA DRA driver (DRA is GA in recent Kubernetes), GPUs appear as `ResourceSlice` objects for driver `gpu.nvidia.com`, and `nvidia.com/gpu` allocatable can legitimately be zero. "Labelled GPU node with zero allocatable: block" would false-block.
- (d) Under MIG `single`, the plugin reports MIG slices as `nvidia.com/gpu` and GFD overrides `gpu.product`, `gpu.count` and `gpu.memory` with slice values; only `mixed` creates `nvidia.com/mig-*`. The threshold text does not say it is `mixed` only.
- (e) Time-sliced replicas multiply the `nvidia.com/gpu` count, so "8 GPUs" can be 2 real ones. With `renameByDefault` the resource becomes `nvidia.com/gpu.shared`.
Fix:
- Add spec fields: `memory_per_gpu` (with the nominal band, from `nvidia.com/gpu.memory` in MiB), `products: [regex]` (from `gpu.product`), `compute_capability` (from `gpu.compute.major/minor`), `driver_min` (from `cuda.driver-version.full`, falling back to the old spelling), `allocation: device_plugin|dra|any`.
- Default `sharing: exclusive`. Use `gpu.count` and `gpu.replicas` to separate physical from advertised GPUs.
- Count free GPUs from pod requests (reuse the `k8s.nodes` sum).
- Detect by pci-10de or `gpu.product`. Read `ResourceSlice` when the API exists; if slices are present and the plugin is absent, do not block on zero allocatable.
- Find the plugin by label (`app=nvidia-device-plugin-daemonset` for the operator, `app.kubernetes.io/name=nvidia-device-plugin` for the Helm chart), not by one DaemonSet name. Treat both label sets as unconfirmed until a fixture proves them.
- Read the operator's `nvidia-operator-validator` pod init containers (driver, toolkit, cuda and plugin validation): the one that fails names the broken layer, and it is the best single remediation signal.
- Surface taints on GPU nodes in evidence (managed clouds taint GPU nodes, and a product without the toleration never schedules).
- Put the comparison helpers (quantity with band, driver version compare) where `rdy-checks-k8s` can use them without depending on `rdy-checks-gpu` (finding 8f).

**7. XML tag names in the catalog are partly wrong, and a tolerant parser turns a wrong tag into a silent pass.**
Problem: from my recollection of the DTD (not confirmed against a file): the row remap tags are `remapped_rows/remapped_row_failure`, `remapped_row_pending`, `remapped_row_corr`, `remapped_row_unc`, not `remap_failure` and `remap_pending`. Virtualization is `gpu_virtualization_mode/virtualization_mode` (plus `host_vgpu_mode`), and the values are `None`, `Pass-Through`, `VGPU`, `Host VGPU`, not `passthrough|vgpu`. PCIe is nested: `pci/pci_gpu_link_info/pcie_gen/{max_link_gen,current_link_gen}` and `link_widths/{max_link_width,current_link_width}`, with values like `16x`; `pci_bus_id` sits under `pci`. `fb_memory_usage` with `total`, `reserved`, `used`, `free` is right (third-party parsers agree); `reserved` is missing on older drivers. `clocks_event_reasons` (children `clocks_event_reason_*`, values `Active` and `Not Active`) is right, with the older `clocks_throttle_reasons`. `ecc_errors` has two layouts across drivers (`volatile` and `aggregate` with `sram_*` and `dram_*`, or older `single_bit` and `double_bit`). `retired_pages` has `pending_blacklist` on older drivers. I cannot confirm the `fabric` layout. If `gpu.health` looks for `remap_failure`, finds nothing, and the tolerant parser says "absent", the check passes on a GPU with a row remap failure. That is the worst possible error for a health check.
Fix:
- Run `nvidia-smi -q -x --dtd` on every machine where a fixture is recorded and commit the DTD next to the XML. Add a test that every tag path the code reads exists in the DTD of each fixture generation.
- Distinguish three states in the model: value present, value `N/A` or `Not Supported`, tag absent. "Tag absent" on a check that needs it makes the result `partial` with "this driver does not report X", never pass.
- Parse units (`81559 MiB`, `34 C`, `16x`, `[N/A]`, `Not Supported`).
- Use an XML parser that does not fetch the external DTD or expand entities (`quick-xml` or `roxmltree`).

**8. What the M1 engine must keep open (the GPU family needs these; they are cheap now and costly later).**
Problem: the catalog assumes engine behaviour that `02-engine-design.md` does not yet promise.
Fix, as requirements on the M1 engine and result model:
- (a) Command runner: kill on timeout must not wait for the child. A `nvidia-smi` stuck in uninterruptible sleep survives SIGKILL, and awaiting it hangs `rdy`. Return `Hung { pid }`, never `wait()` after kill, close the pipes, and let the process exit path (the `shutdown_timeout` or `process::exit` item already in the catalog) cover it. Run the child in its own process group. Capture stdout, stderr and the exit code separately: `nvidia-smi` prints some errors on stdout.
- (b) Shared per-run data: the eight `gpu.*` checks run in parallel and share one XML call. The engine needs a per-run memoised collector keyed by argv, owned by a detached task, so a per-check timeout drops only that check's wait and not the shared call. Check registration must accept an `Arc` of shared state (not static unit structs).
- (c) Root cause links: if `gpu.driver` fails, the other seven should not each print a block. The result needs `skipped` with a `caused_by: <check id>` field, rendered as one block and seven "depends on gpu.driver" lines. Do not build a dependency scheduler in M1; keep the field and let the check return it.
- (d) `partial` and the `not_applicable` versus `unverified` split from finding 4, both in the JSON schema from M1.
- (e) A circuit breaker in the GPU shared layer, not the engine: after the first `nvidia-smi` hang, do not start `nvlink -s`, `topo -m` or the `compute_cap` query (each would leak another stuck process).
- (f) Version, quantity and band comparison helpers live in a crate that both `rdy-checks-k8s` and `rdy-checks-gpu` can use.
- (g) Keep per-check spec params open (strict per check kind, behind a spec version gate), so adding `compat`, `allocation` and `band_result` later is not a spec major bump.

### Should fix

**9. `gpu.driver`: the top real-world cause is missing, and the mismatch text has no data source.**
Problem: the most frequent "driver installed, not working" case is a kernel update where DKMS did not rebuild the module (no module for the running kernel, or no kernel headers). The catalog covers nouveau, Secure Boot and version mismatch, not this. The mismatch fix text uses `{u}` (user-space version) but names no source, and `nvidia-smi` fails entirely in that state. The `NVRM version` pattern names x86_64 only.
Fix: check `/lib/modules/$(uname -r)/` for `nvidia.ko*` (under `updates/dkms` and `kernel/drivers/video`) and report "module built for another kernel: run `dkms status` and `dkms autoinstall`". Get the user-space version from the file name `libnvidia-ml.so.<ver>` by directory listing (no loading). Make the `NVRM` pattern architecture-agnostic (`for aarch64` appears on Grace). Do not run `modinfo` or any command that touches the module.

**10. `gpu.driver`: open versus proprietary needs a GPU architecture rule.**
Problem: open kernel modules support Turing and newer only; Blackwell supports only the open module; Pascal and Volta need the proprietary one. A spec `kernel_module: open` on a V100 box can never pass, and the fix text should say so. CUDA 13 also dropped support for compute capability below 7.5 (Maxwell, Pascal, Volta); R580 is the last driver branch for those cards.
Fix: add `min_driver` and `open_module_ok` columns to `gpu_arch.toml`; warn in `gpu.devices` when the spec's `built_with` is 13.x and the card is below 7.5.

**11. Failure classifier: use exit codes first.**
Problem: the classifier keys on strings only. Locale and wording change between drivers. Confirmed exit codes: 9 driver not loaded, 12 NVML library missing, 14 infoROM corrupted, 15 GPU fell off the bus, 4 permission, 255 other. `-x` on error prints text, not XML.
Fix: classify by exit code, then by string, then check that stdout starts with `<?xml`. Add code 12 (inside a container it usually means `NVIDIA_DRIVER_CAPABILITIES` lacks `utility`) and code 4. One fixture per code.

**12. `gpu.health`: the Xid sets are partly inverted, and the list belongs in a data file.**
Problem (checked against NVIDIA's Xid catalog): 63 is informational (row remap or page retirement recorded) and the catalog warns on it; 64 is a remap or retirement failure needing a GPU reset and the catalog only warns; 13 and 31 are almost always application faults (NVIDIA: restart the app), so a warn on a readiness check is noise; 95 is correct (uncontained ECC, reset); 48 and 79 are correct; 74 (NVLink) is serious on NVSwitch systems. Missing: 119 and 120 (GSP RPC timeout and GSP error, reset needed), 140 (unrecoverable ECC escape), 94 (contained, app), 92 (high single-bit rate), 45 (pre-emptive removal, ignore).
Fix: ship `xid.toml` in Appendix B with `source` and `checked_on`. Default block: 48, 64, 79, 95, 119, 120, 140. Default warn: 74, 92. Default info: 13, 31, 43, 45, 63, 94. Spec `block_xids` overrides. Parse `Xid \(PCI:([0-9a-f:.]+)\): (\d+)` rather than the whole line, since the trailing text differs by driver.

**13. `gpu.health`: reading `/dev/kmsg` is a hazard, and the window logic is wrong.**
Problem: opening `/dev/kmsg` without `O_NONBLOCK` blocks forever at the end of the buffer, and a blocked `spawn_blocking` task cannot be cancelled. Records come one per read, so "last 1 MiB" does not apply; each starts `priority,seq,timestamp_us,flags;`. Timestamps are microseconds since boot, so a 24 h window needs `/proc/uptime`. Also, a GPU reset or driver reload does not clear the ring, so "Xid 79 in the last 24 h: block" is wrong when `nvidia-smi` now answers normally.
Fix: open with `O_NONBLOCK`, read until `EAGAIN`, cap at 1 MiB total, convert timestamps with uptime. If `nvidia-smi` is healthy after the Xid, warn with "seen at T, GPU responds now". Fall back to `/var/log/kern.log` and `/var/log/messages` when `dmesg_restrict` blocks the read. In containers say "kernel log not visible".

**14. `gpu.health`: ECC thresholds use the wrong counter.**
Problem: `ecc_uncorrected_max: 0` on aggregate (lifetime) counters warns on GPUs that retired a page years ago and are fine. Pending page retirement or pending row remap means a reset is needed, not that the GPU is bad.
Fix: warn on volatile uncorrectable counters (since last reset), show aggregate as info. `remapped_row_failure: Yes` blocks. Pending remap or retirement: warn with the reset text. Many retired pages: warn (NVIDIA has an RMA count guideline; read it from current release notes before hard-coding a number).

**15. `gpu.fabric`: process matching by name will false-block every HGX.**
Problem: `/proc/<pid>/comm` holds 15 characters. `nv-fabricmanager` is 16, so `comm` reads `nv-fabricmanage`; `nvidia-persistenced` reads `nvidia-persiste`. An exact match on `comm` never finds either, so "fabric manager down: block" fires on healthy systems.
Fix: match on the first token of `/proc/<pid>/cmdline` (readable without root), or on the systemd unit state. Make the XML `fabric` state and status (`Completed`, `Success`; layout still to confirm) the primary evidence and the process the secondary. State the version rule exactly: fabric manager version must equal the driver version.

**16. `gpu.fabric`: inventory and root claims disagree.**
Problem: the Needs line cites `lspci` for ACS detail, but `lspci` is not in Appendix A. `nvidia-smi topo -m` does not need root. `/dev/shm` on the host says nothing about the 64 MiB container default that breaks NCCL in pods. A missing host `libnccl.so.2` is normal when the product bundles NCCL (PyTorch wheels do).
Fix: add `lspci -vv` to Appendix A or drop ACS from M4. Mark `topo -m` as no root. Say in the fix text that the real fix for pods is an `emptyDir` with `medium: Memory` or `--shm-size`. Never fail on a missing host `libnccl`; only report it.

**17. `gpu.runtime`: containerd config reading will miss many installs.**
Problem: `nvidia-ctk` 1.17 and later writes a drop-in (`/etc/containerd/conf.d/`), so reading only `config.toml` reports "not registered". Rancher distros keep the file elsewhere (k3s `/var/lib/rancher/k3s/agent/etc/containerd/config.toml`, RKE2 `config.toml.tmpl`). The config schema differs between version 2 and 3. CDI also needs `enable_cdi = true` (containerd) or `features.cdi` (Docker). A stale `/etc/cdi/nvidia.yaml` after a driver upgrade (library paths with the old version) is a frequent failure.
Fix: parse TOML (not grep), follow `imports`, search the Rancher paths, support both schema versions. For CDI, check the enable flag and compare the driver version inside the spec file to the loaded driver. Fix text: `nvidia-ctk cdi generate` after any driver change. Treat the 1.17 drop-in detail as unconfirmed until a fixture shows it.

**18. `gpu.runtime`: unreadable config has no stated result.**
Problem: "root optional" is fine, but no rule says what the check reports when it can read none of the files.
Fix: follow the degrade rule explicitly: unreadable config gives `partial` with "run as root to read X", never block.

**19. MIG handling is thin.**
Problem: the thresholds only handle `mig: forbid|require|any`. Missing: `pending_mig` set but not active (needs a reset); MIG enabled but zero GPU instances (no usable device); per-instance memory versus `min_per_gpu` (a `1g.10gb` slice is about 9.75 GiB); what `count` means (GPUs or instances).
Fix: when MIG is `Enabled`, evaluate `min_per_gpu` and `count` against instances and say so; block when MIG is on with no instances and the product needs GPUs; warn on `pending_mig != current_mig`. Check on the MIG fixture what the parent `fb_memory_usage` shows. Fix text for disabling MIG says "drain workloads, then run X" and states that Rdy never runs it.

**20. vGPU handling is thin.**
Problem: in a vGPU guest the product name is a profile name, VRAM is the profile size, ECC, retired pages and NVLink are `N/A`, and MIG is usually unavailable. An unlicensed guest is throttled by the driver after a grace period, which looks like a performance bug later. The licence state is plain text in `nvidia-smi -q` (a "vGPU Software Licensed Product" section; XML tag to confirm via the DTD), so waiting for M5 `gpu.vgpu_license` is unnecessary for the read-only part.
Fix: in M4, when `virtualization_mode` is `VGPU`, mark ECC and fabric health `not_applicable`, evaluate VRAM against the profile, and surface licence status as evidence with a warn if unlicensed. Keep the full check in M5.

**21. `gpu.devices`: smaller threshold gaps.**
Problem: `count` is ambiguous (all GPUs or matching GPUs); mixed models on one node break tensor parallelism; `CUDA_VISIBLE_DEVICES` or `NVIDIA_VISIBLE_DEVICES` set to a wrong value hides GPUs; PCIe link generation drops at idle, so only width may be compared (the catalog does this right, but does not say why).
Fix: define `count` as GPUs matching `models`; warn on mixed models when `count > 1`; record those two variables by name and value class (empty, `all`, a list) in evidence; add the one-line note "link generation is not compared, it drops at idle".

**22. Timeout: 10 s is too short for the shared call, and the timeout result is undefined.**
Problem: with persistence mode off, the first `nvidia-smi -q` on an 8 GPU HGX can take well over 10 s (cold GPU init, fabric manager starting). A healthy node would read as "wedged GPU".
Fix: 30 s for the shared XML call and 15 s for the others; a progress line after 5 s ("nvidia-smi is slow; persistence mode off?"); define the result: timeout is `warn: indeterminate` unless a second attempt also hangs or `/proc/driver/nvidia/gpus/*/information` is unreadable, then block "GPU or driver is wedged, check dmesg for Xid". Report the abandoned PID in evidence.

**23. `gpu.model_egress`: air-gapped sites are the main persona and are not handled.**
Problem: with `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1` or an internal mirror, the check only "reports by name" and then probes the public hub, which fails by design. Air-gapped installs need the opposite check: is the model on local disk, with the expected files and size.
Fix: spec `offline_paths: [{path, files, min_size}]`. If an offline variable is set or `HF_ENDPOINT` points at a mirror, probe the mirror (not the public hub) or check the local path, and say which mode ran. Read-only: file sizes and `statvfs` only.

**24. `gpu.model_egress`: the redirect-host approach is right but incomplete.**
Problem: (a) Hugging Face now serves large files through Xet storage. The Python client `hf_xet` talks to the Xet hosts directly (`cas-server.xethub.hf.co`, `transfer.xethub.hf.co`, per public vendor allow lists), not through the redirect that a plain `Range` GET follows. The probe can pass while the pod's download is blocked. The published allow lists disagree and the hosts change, so I could not pin a definitive list. (b) Python HTTP clients do not use the OS trust store; behind TLS interception the probe (rustls with native roots) passes and the pod fails with a certificate error unless `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` is set in the container. (c) Redirect URLs carry signed query strings; they must not enter evidence. (d) `min_mbps` from an 8 MiB sample measures TCP slow start, not throughput. (e) OCI registry sources (container images, NGC) need a registry ping and a token realm check, which is `net.registry`, not a ranged GET.
Fix: record redirect hosts only, never paths or queries; add a line "the Python client may use different hosts (Xet) and a different trust store"; check the three CA variables by name; sample at least 32 MiB or 10 s for speed; delegate registry sources to `net.registry`; name `HF_HUB_DISABLE_XET=1` as a documented workaround in the fix text, not as a recommendation.

**25. Remediation text has risky advice and leaks.**
Problem: `rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia` in the fix text fails or hangs while persistenced, DCGM, fabric manager or containers hold the modules. `nvidia-smi -i 0 -mig 0` and `--gpu-reset` are destructive. `processes {list}` puts customer process names and PIDs into the report and the uploaded bundle. The XML also holds serial number, board id, part number and UUIDs.
Fix: prefix every destructive command with "stop services that use the GPU first" and put reboot first. Record process count and total memory, not names, in JSON; names only in local HTML if the user asks. Do not record serial, board id or part number; hash UUIDs as planned. Add these to the redaction golden tests.

**26. Fixtures: where the recorded output comes from is not planned.**
Problem: the ticket needs "fixtures for 5 driver generations" and the catalog lists H100, A100, L4, T4, MIG, vGPU and 8x H100, but the founder has no GPUs, and CLAUDE.md says fixtures are synthetic. Raw XML carries UUIDs, serials, bus ids and process lists.
Fix: add a ticket before the shared layer: capture on rented machines (a T4, A10G or L4 instance for a few dollars an hour; one A100 on a cloud that allows MIG; an HGX capture from a design partner using the scrub script), always with `-q -x --dtd`. Ship `tools/scrub-nvidia-xml` that replaces UUID, serial, board id, part number, bus id and process names with fixed fake values, plus a test that fails if a committed fixture contains a real-shaped UUID. Hand-edit the failure cases (row remap failure, lost GPU) from a clean capture.

**27. Ordering: re-rank by how often the check catches a real install failure.**
Problem: the author's order is driver, cuda, vram, runtime, devices, model_egress, health, fabric. My field order differs. At customer sites an unregistered container runtime is far more common than a CUDA mismatch, and blocked model egress is common and cheap to catch, while VRAM class and GPU count are usually known at purchase.
Fix: (1) `gpu.driver`, (2) `gpu.runtime`, (3) `gpu.cuda`, (4) `gpu.model_egress`, (5) `gpu.devices` with `gpu.vram` (same data, one ticket), (6) `gpu.fabric` (rare, but costly for multi-node), (7) `gpu.health`. On Kubernetes, `k8s.device_plugins` ranks first of all. Re-rank with portal data after M2.

**28. Tickets: estimate and order.**
Problem: the shared layer at 6 h covers the runner, tolerant parser, classifier and five generations of fixtures; with findings 5, 7, 8 and 26 it is closer to 12 h. The gpu-expert review ticket sits after `gpu.fabric`, so the parser would be written before the tag names are checked.
Fix: move the review and the DTD capture before the shared layer ticket; raise the shared layer to 10 to 12 h; add tickets for `xid.toml`, the `k8s.device_plugins` GFD thresholds, `offline_paths` and the scrub tool.

**29. WSL2 and special hosts are named but not branched.**
Problem: the section says WSL2 is "detected", but `gpu.driver` still reads `/proc/driver/nvidia`, `/proc/modules`, nouveau and Secure Boot, none of which exist there. It would report "driver not loaded". Jetson and DGX Spark class machines use unified memory, so `fb_memory_usage` is `N/A`.
Fix: detect WSL2 (`/proc/sys/kernel/osrelease` contains `microsoft`, `/dev/dxg` exists) and run only the XML path, with kernel module, nouveau, Secure Boot and persistence marked `not_applicable`. When VRAM is `N/A` (unified memory), return `partial` and say so; do not block.

**30. `gpu.driver`: persistence default.**
Problem: "no persistence daemon: warn" is stated as unconditional while the spec default for `persistence` is `any`.
Fix: warn only when `persistence: required`, or when a first call took over 5 s (finding 22), where it explains the slow call.

**31. Data file hygiene.**
Problem: Appendix B lists `cuda_driver_min.toml` and `gpu_arch.toml` only.
Fix: add `xid.toml`; add to `gpu_arch.toml` the columns `compute_capability` (a range for families), `datacenter`, `min_driver`, `open_module_ok`, `cuda13_supported`. Keep the 180 day `checked_on` rule.

**32. `gpu.model_egress` crate dependencies.**
Problem: `rdy-checks-gpu` depends on `rdy-checks-net` and `rdy-checks-host` as libraries. That pulls two other check crates into a crate that otherwise needs only a command runner, and makes the dependency graph in CLAUDE.md harder to hold.
Fix: move the shared pieces (HTTP client builder, redirect recorder, `statvfs`) into `rdy-engine` helpers or a small shared module, and have the GPU crate depend on that. Same for `rdy-checks-k8s` (finding 6).

**33. Windows driver details.**
Problem: the Windows branch says "same XML". It is, but the driver string has two parts, the table needs its own column (finding 1), and the container story differs (Windows containers do not use `nvidia-ctk`).
Fix: `gpu.runtime` returns `not_applicable` on Windows with a reason; document the two-part version in the compare helper.

### Nit

**34.** `gpu.driver`: the Secure Boot rule infers "unsigned module" from "driver absent and `nvidia` not in `/proc/modules`". Also read `/sys/kernel/security/lockdown` and look for the module file in `/lib/modules`. If the file exists, Secure Boot is on and the module is not loaded, the diagnosis is solid.

**35.** `gpu.cuda`: `nvcc --version` with a fixed `PATH` will not find `/usr/local/cuda/bin/nvcc`. Prefer `version.json`; call `nvcc` by absolute path only as a fallback.

**36.** `k8s.device_plugins` uses `gpu.present=true` in the threshold line and `nvidia.com/gpu.present` in the source line. Replace both (finding 6).

**37.** The real VRAM figures in the `gpu.vram` source line are good. Add H200 (about 143771 MiB for "141 GB") and A10G (about 22731 MiB) to the fixtures. Both are from memory; confirm on capture.

**38.** `gpu.fabric`: IB `INIT` meaning "no subnet manager" holds for InfiniBand only. On RoCE (`link_layer` Ethernet) use `ACTIVE` plus a note that PFC and ECN cannot be seen from the host. Skip IB checks unless the spec asks.

**39.** `gpu.devices`: PCIe `max_link_width` in a VM can read oddly; skip the width warning when `virtualization_mode` is not `None`.

**40.** The `nvidia-smi -q -x` output cap of 2 MiB is fine for 8 GPUs; a MIG box with many instances and processes can be larger. Keep the cap, report `truncated`, mark the result `partial`, and never parse cut XML.

**41.** The catalog says the first five checks could move to M2 for a GPU-heavy design partner. Agree, with the Kubernetes GFD thresholds (finding 6) first, because that covers the case where nobody can SSH to the node.

## Graceful degradation, kernel modules, workloads (summary)

- No GPU: fine only after findings 4 and 5. A required GPU that is absent must block, not skip.
- Kernel modules: Rdy itself never loads one. The one hole is `nvidia-smi` via `nvidia-modprobe` (finding 5).
- Running workloads: all reads are passive. `nvidia-smi` initialising a non-persistent GPU is harmless but slow on the first call; findings 22 and 8(e) cover the rest. Never call `--gpu-reset`, `-mig`, `-pm`, `-c`, or `dcgmi diag` (the last one runs a workload).

## Plan corrections found

- `/home/user/rdy/docs/plan/03-check-catalog.md`, "Decisions needing an ADR", the GPU data source item: stale. ADR 0006 section 5 already decides `nvidia-smi` and `/proc/driver/nvidia` only, with no glibc build in v1. Fix: cite ADR 0006 and move the glibc build and the helper to "revisit triggers".
- `/home/user/rdy/docs/plan/03-check-catalog.md`, `gpu.cuda` ticket exit test: encodes the minor-version-compatibility false positive. Fix: finding 1.
- `/home/user/rdy/docs/plan/03-check-catalog.md`, `gpu.vram` ticket exit test: encodes the band-as-warn rule. Fix: finding 2.
- `/home/user/rdy/docs/plan/03-check-catalog.md`, Appendix A: `lspci` is used by `gpu.fabric` but not listed. Fix: add it or drop the ACS read.
- `/home/user/rdy/docs/plan/03-check-catalog.md`, `k8s.device_plugins`: the plan's "VRAM per node" has no Kubernetes implementation. Fix: finding 6.
- `/home/user/rdy/CLAUDE.md`, repo layout, `rdy-checks-gpu` row: the in-cluster half and VRAM per node (from GFD labels) belong in `rdy-checks-k8s`. The catalog's correction text covers the plugin; add VRAM.
- `/home/user/rdy/docs/plan/rdy-plan.md`, example spec `gpu.cuda min: "12.4"`: still ambiguous after the catalog's `source: driver|toolkit`. It also needs `built_with` and `compat` (finding 1).

## Sources checked

- NVIDIA CUDA Toolkit release notes (shipped driver per toolkit, minor version compatibility floors): https://docs.nvidia.com/cuda/cuda-toolkit-release-notes/index.html
- NVIDIA Xid catalog: https://docs.nvidia.com/deploy/xid-errors/analyzing-xid-catalog.html
- NVIDIA nvidia-smi documentation (return codes, `-x`, `--dtd`): https://docs.nvidia.com/deploy/nvidia-smi/index.html
- GPU Feature Discovery labels and k8s-device-plugin README: https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/main/docs/gpu-feature-discovery/README.md and https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/main/README.md
- NVIDIA MIG user guide, device nodes (nvidia-smi calls nvidia-modprobe): https://docs.nvidia.com/datacenter/tesla/mig-user-guide/latest/device-nodes-and-capabilities.html
- Hugging Face hub environment variables (`HF_HUB_DISABLE_XET`); community allow lists are not authoritative: https://huggingface.co/docs/huggingface_hub/v0.31.2/en/package_reference/environment_variables
- Kubernetes Dynamic Resource Allocation: https://www.kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation

Still unverified, to close with a recorded `--dtd` capture: the exact XML tag names in finding 7, the `fabric` section layout, the vGPU licence tag, the CUDA 13.0 GA shipped-driver row, the NVIDIA RMA retired-page count, the plugin pod label sets, the toolkit drop-in version, and whether `libnvidia-ml` (not only `nvidia-smi`) triggers `nvidia-modprobe`.
