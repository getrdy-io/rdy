code-reviewer #70 (M1-066) at c2330a8: CHANGES REQUIRED. CI red on windows-x64 (5 tests) and macos-x64 (5 tests).
1 HIGH table/tests.rs:283, 308, 407, 428, 514 call cmd() (current OS) on Linux-only entries: use cmd_for(Os::Linux, ..) and validate_for(Os::Linux, ..); :510 becomes #[cfg(target_os = "linux")]. On Windows entry("nvidia-smi") also matches the Linux entry.
2 HIGH table/tests.rs:209-226 calls prepare on Windows with POSIX GPU dirs: skip entries where !entry.runs_on(current_os()).
3 HIGH shipped fix text is not audited: add a test running fixtext::check on every HostFamily CheckMeta.remediation; add `journalctl` to commands.txt (crates/rdy-checks-host/src/family.rs:101 ships `journalctl -k`).
4 MED API for #58: make policy::run pub(crate) or testing-gated (same as sec 1); consider moving table data and validation out of the runtime gate so the probe gate can call validate_for(ctx.os, ..) and replay denies and logs an unlisted command. Merge #70 before #58; #58 then uses CommandEntry::cmd and table::run.
5 LOW ADR 0028 status Proposed until security-reviewer signs off.
6 LOW widened REFUSED_PROGRAMS: keep, with security sign-off.
7 LOW command_table.rs:184-199 compare the Expected exit column; check invented paths (nvidia-smi.exe in System32, /usr/bin/nvidia-ctk) against a doc path.
8 NIT fixtext.rs:376-380 `sudo -u root foo` reads root as the command.
