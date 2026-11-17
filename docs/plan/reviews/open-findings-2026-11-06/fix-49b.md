PR #49 confirm: 1, 3, 4 fixed. Do (merge origin/main, NEVER rebase; resolve run_cmd.rs where M1-086 changed host_facts to host_os_family()):
1. Now that M1-086 (#42) is on main, add the header tests here: a RHEL 9.4 fixture prints `rhel 9.4` in the run header (terminal.rs host_value via untrusted()), and no os-release prints `linux`. Drop the deviation from the 12-progress line.
2. Rewrap the os.rs doc line on read_os_facts (143 chars).
Full cargo test --workspace, push, cargo clean, reply with head.
