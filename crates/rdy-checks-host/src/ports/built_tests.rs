//! Tests of `host.ports` on machines built in memory, for sizes a fixture file may not have (the fixture
//! lint caps a file at 256 KiB): a socket table past the 1 MiB read limit, and a walk over busy processes.

use rdy_engine::check::{Check, CheckOutcome, Level, Need, Os};
use rdy_engine::probe::{ActionLogOutput, DirEntry};
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

const HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

fn row(port: u16, state: &str, inode: u64) -> String {
    format!(
        "   0: 00000000:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )
}

/// The entries `0` to `count - 1` of an fd directory. A `count` of 31 or more adds the fd `31`, which the
/// tests make a socket.
fn fds(count: u32) -> Vec<DirEntry> {
    let mut entries: Vec<DirEntry> = (0..count.min(30))
        .map(|fd| DirEntry::new(fd.to_string(), false))
        .collect();
    if count > 30 {
        entries.push(DirEntry::new("31", false));
    }
    entries
}

/// A listing of `/proc` with the process directories `1` to `last`.
fn listed(replay: Replay, last: u32) -> Replay {
    replay.dir(
        "/proc",
        (1..=last)
            .map(|pid| DirEntry::new(pid.to_string(), true))
            .collect(),
    )
}

fn execute(replay: Replay, root: bool, entry: &Value) -> (CheckOutcome, ActionLogOutput) {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    let CheckParams::HostPorts(params) = spec.decode_params() else {
        panic!("not host.ports");
    };
    let test_run = TestRun::new(replay);
    let needs = if root { vec![Need::Root] } else { Vec::new() };
    let ctx = test_run.context_for(&INFO, "host.ports", Os::Linux, needs);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(Ports::from_params(&params).run(&ctx));
    (outcome, test_run.action_log())
}

/// More than 1 MiB: 9,000 rows of about 140 bytes.
fn rows(state: &str) -> String {
    (0..9000u64)
        .map(|i| row(20_000 + (i % 1000) as u16, state, 500_000 + i))
        .collect()
}

#[test]
fn a_table_cut_among_the_listeners_does_not_prove_a_port_free() {
    let table = format!("{HEAD}{}", rows("0A"));
    assert!(table.len() > 1 << 20);
    let (outcome, _) = execute(
        Replay::new().file("/proc/net/tcp", table),
        true,
        &json!({"id": "host.ports", "free": [8080]}),
    );
    let f = outcome.expect("a finding");
    assert_eq!(f.level, Level::Warn);
    assert!(
        f.message
            .contains("/proc/net/tcp is longer than the 1 MiB rdy reads"),
        "{}",
        f.message
    );
    assert!(f.partial.is_some());
}

#[test]
fn a_table_cut_among_the_established_rows_loses_no_listener() {
    // The kernel lists listening sockets first.
    let table = format!("{HEAD}{}{}", row(8080, "0A", 77), rows("01"));
    assert!(table.len() > 1 << 20);
    let free = json!({"id": "host.ports", "free": [8081]});
    let (outcome, _) = execute(
        Replay::new().file("/proc/net/tcp", table.clone()),
        true,
        &free,
    );
    let f = outcome.expect("a finding");
    assert_eq!(f.level, Level::Pass, "{}", f.message);
    let held = json!({"id": "host.ports", "free": [8080]});
    let (outcome, _) = execute(Replay::new().file("/proc/net/tcp", table), true, &held);
    let f = outcome.expect("a finding");
    assert_eq!(f.level, Level::Fail, "{}", f.message);
}

#[test]
fn a_walk_over_a_busy_control_plane_node_finds_the_holder_without_filling_the_log() {
    // 200 processes with 30 files and pipes each, 6,000 refused links. The holder is the last process.
    let mut replay = Replay::new().file(
        "/proc/net/tcp",
        format!("{HEAD}{}", row(6443, "0A", 424_242)),
    );
    for pid in 1..=200u32 {
        replay = replay.file(format!("/proc/{pid}/comm"), format!("p{pid}\n"));
        for fd in 0..30u32 {
            replay = replay.symlink(format!("/proc/{pid}/fd/{fd}"), "/dev/null");
        }
        replay = replay.dir(format!("/proc/{pid}/fd"), fds(30));
    }
    replay = replay.symlink("/proc/200/fd/31", "socket:[424242]");
    replay = replay.dir("/proc/200/fd", fds(31));
    replay = listed(replay, 200);
    let (outcome, log) = execute(replay, true, &json!({"id": "host.ports", "free": [6443]}));
    let f = outcome.expect("a finding");
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message.contains("held by `p200` (pid 200)"),
        "{}",
        f.message
    );
    assert!(f.partial.is_none(), "{:?}", f.partial);
    // The refusals fold under one key for the check: 20 written and one entry that counts the rest.
    let denied: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.outcome == ActionOutcome::Denied)
        .collect();
    assert_eq!(denied.len(), 21, "{} denied entries", denied.len());
    assert_eq!(log.last_resort_drops, 0);
    assert!(log.actions.len() < 1000, "{} entries", log.actions.len());
    // Every process up to the holder was listed.
    let listed = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::ReadDir)
        .count();
    assert_eq!(listed, 1 + 200);
}

#[test]
fn a_walk_that_finds_a_socket_late_still_gets_its_owner() {
    let mut replay = Replay::new().file(
        "/proc/net/tcp",
        format!("{HEAD}{}", row(6443, "0A", 424_242)),
    );
    for pid in 1..=10u32 {
        replay = replay.file(format!("/proc/{pid}/comm"), format!("p{pid}\n"));
        replay = replay.symlink(format!("/proc/{pid}/fd/0"), "/dev/null");
        if pid < 10 {
            replay = replay.dir(format!("/proc/{pid}/fd"), vec![DirEntry::new("0", false)]);
        }
    }
    replay = replay.symlink("/proc/10/fd/3", "socket:[424242]");
    replay = replay.dir(
        "/proc/10/fd",
        vec![DirEntry::new("0", false), DirEntry::new("3", false)],
    );
    replay = listed(replay, 10);
    let (outcome, _) = execute(replay, true, &json!({"id": "host.ports", "free": [6443]}));
    let f = outcome.expect("a finding");
    assert!(
        f.message.contains("held by `p10` (pid 10)"),
        "{}",
        f.message
    );
}
