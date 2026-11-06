PR #39 main-merge round (after PR #35 host.time_sync merges). Both reviewers approve at 21e76efe. Do:
1. Merge origin/main (never rebase). Implement the host.time_sync part of correction-39 (now possible): treat RULE_NO_NETWORK as soft like RULE_UDP_ADDRESS ("offset not measured, --no-network is set"), keep the timedatectl result, do not run chronyc offline (the table already refuses it; the check must not end in error because of that refusal). Test it through map_outcome: an offline run with ntp_servers gives timedatectl's verdict plus the note, no datagram, no chronyc.
2. (security low) ProbeHub starts with the network NOT allowed (fail closed) or takes it as a constructor argument; every caller sets it explicitly.
3. (security low) offline_tests.rs: add a direct `http` and a `tls_chain` case.
4. (code low) say in 02 (or the module doc) that a Denied entry is a refused call, not a connection, and tighten the tests to "no connect entry whose outcome is not Denied".
5. (code nit) `reaches_network` in check.rs uses an exhaustive match over PeerClass.
Gate (incl. root_* strace test locally with RDY_REQUIRE_STRACE=1 if possible), push, cargo clean, reply with head.
