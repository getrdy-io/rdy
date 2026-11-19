//! Tests of the direct nameserver lookups of `net.dns` (M1-155).
//!
//! Machines are the `net.dns/` fixtures (`/etc/resolv.conf`, `/etc/nsswitch.conf`, recorded `getent`
//! output) plus scripted DNS servers on the replay backend. Servers sit at the addresses of the fixture's
//! `resolv.conf`. Time is paused, so a 2 s delay costs nothing.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use rdy_engine::check::{Level, Os};
use rdy_engine::probe::sock::{DnsTransport, RULE_NS_ADDRESS};
use rdy_engine::testing::{DnsScript, Replay, TestRun};
use rdy_spec::result::{ActionKind, ActionOutcome, Status};
use serde_json::{Value, json};

use super::split::SSS_WARNING;
use super::tests::{NET, Ran, case, run_on, run_with, run_with_deadline};

const NS1: &str = "192.0.2.53:53";
const NS2: &str = "192.0.2.54:53";

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

/// A server that answers the names in `zone` with these addresses and NXDOMAIN for any other name. The
/// reply repeats the query's ID and question, as a real server does.
fn zone(
    entries: &'static [(&'static str, &'static [&'static str])],
) -> impl Fn(&[u8], DnsTransport) -> DnsScript + Send + Sync + 'static {
    move |payload, _| {
        let query = Message::from_vec(payload).expect("the check sent a DNS query");
        let asked: &Query = &query.queries[0];
        let name = asked.name().to_ascii().trim_end_matches('.').to_owned();
        let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
        reply.add_query(asked.clone());
        match entries.iter().find(|(n, _)| *n == name) {
            None => reply.metadata.response_code = ResponseCode::NXDomain,
            Some((_, addrs)) => {
                for text in *addrs {
                    let ip: IpAddr = text.parse().expect("an address");
                    let data = match (ip, asked.query_type()) {
                        (IpAddr::V4(v4), RecordType::A) => RData::A(A(v4)),
                        (IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA(AAAA(v6)),
                        _ => continue,
                    };
                    reply.add_answer(Record::from_rdata(asked.name().clone(), 60, data));
                }
            }
        }
        DnsScript::Answer(reply.to_vec().expect("encodes"))
    }
}

/// The scripted nameservers of a golden case, at the addresses of its `resolv.conf`.
pub(super) fn with_servers(case: &str, replay: Replay) -> Replay {
    const WEB: &[(&str, &[&str])] = &[("web.acme.test", &["192.0.2.10"])];
    match case {
        "split-horizon" => replay
            .dns_server(addr(NS1), zone(WEB))
            .dns_server(addr(NS2), zone(&[("web.acme.test", &["198.51.100.7"])])),
        "slow-first-nameserver" => replay
            .dns_server(addr(NS1), zone(WEB))
            .dns_server(addr(NS2), zone(WEB))
            .dns_delay(addr(NS1), Duration::from_millis(2000)),
        "direct-nxdomain" => replay
            .dns_server(addr(NS1), zone(&[]))
            .dns_server(addr(NS2), zone(&[])),
        "nsswitch-sss-mdns" => replay
            .dns_server(addr(NS1), zone(&[("svc.cluster.local", &["192.0.2.20"])]))
            .dns_server(addr(NS2), zone(&[("svc.cluster.local", &["192.0.2.20"])])),
        _ => replay,
    }
}

fn names(list: &[&str]) -> Value {
    json!(list)
}

fn positions(ran: &Ran, at: usize) -> Value {
    ran.name(at)["nameservers"].clone()
}

#[tokio::test(start_paused = true)]
async fn agreeing_nameservers_pass_and_the_evidence_names_positions_only() {
    let replay = case("split-horizon")
        .dns_server(addr(NS1), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let rows = positions(&ran, 0);
    assert_eq!(rows[0]["position"], 1);
    assert_eq!(rows[0]["status"], "replied");
    assert_eq!(rows[0]["rcode"], "NOERROR");
    assert_eq!(rows[1]["position"], 2);
    assert_eq!(finding.observed["direct"]["nameservers_asked"], 2);
    let text = ran.result_text();
    // The nameserver addresses are never copied into the result or the log text.
    assert!(
        !text.contains("192.0.2.53") && !text.contains("192.0.2.54"),
        "{text}"
    );
    // Two nameservers, A each (the system answer has no IPv6, so no AAAA).
    let dns = ran
        .run
        .action_log()
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Dns)
        .count();
    assert_eq!(dns, 2);
}

#[tokio::test(start_paused = true)]
async fn split_horizon_warns() {
    let replay = case("split-horizon")
        .dns_server(addr(NS1), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["198.51.100.7"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.contains("split horizon"),
        "{}",
        finding.message
    );
    assert!(
        finding.message.contains("nameserver 2"),
        "{}",
        finding.message
    );
    assert!(
        !finding.message.contains("nameserver 1"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("/etc/resolv.conf"), "{fix}");
    assert_eq!(ran.result().status, Status::Warn);
    // The addresses of the answers are evidence. The nameservers' own addresses are not.
    assert_eq!(positions(&ran, 0)[1]["addresses"], json!(["198.51.100.7"]));
    assert!(!ran.result_text().contains("192.0.2.54"));
}

#[tokio::test(start_paused = true)]
async fn a_slow_first_nameserver_warns() {
    let replay = case("slow-first-nameserver")
        .dns_server(addr(NS1), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_delay(addr(NS1), Duration::from_millis(2000));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.contains("nameserver 1 took 2000 ms")
            && finding.message.contains("slow first hop"),
        "{}",
        finding.message
    );
    assert_eq!(positions(&ran, 0)[0]["ms"], 2000);
    assert_eq!(positions(&ran, 0)[1]["ms"], 0);
}

#[tokio::test(start_paused = true)]
async fn a_silent_first_nameserver_warns_with_the_timeout_text() {
    let replay = case("slow-first-nameserver")
        .dns_silent(addr(NS1))
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding
            .message
            .contains("nameserver 1 did not answer in time")
            && finding
                .message
                .contains("slow first hop adds a timeout to every lookup"),
        "{}",
        finding.message
    );
    assert_eq!(positions(&ran, 0)[0]["status"], "timeout");
    assert_eq!(positions(&ran, 0)[0]["ms"], 3000);
    assert_eq!(positions(&ran, 0)[1]["status"], "replied");
}

#[tokio::test(start_paused = true)]
async fn nxdomain_from_every_nameserver_blocks_and_the_fix_names_the_code() {
    let replay = case("direct-nxdomain")
        .dns_server(addr(NS1), zone(&[]))
        .dns_server(addr(NS2), zone(&[]));
    let ran = run_on(replay, names(&["gone.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(ran.result().status, Status::Block);
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("nameservers 1, 2 answered NXDOMAIN") && fix.contains("`acme.test`"),
        "{fix}"
    );
    assert_eq!(positions(&ran, 0)[0]["rcode"], "NXDOMAIN");
}

#[tokio::test(start_paused = true)]
async fn nxdomain_while_the_system_finds_the_name_warns() {
    let replay = case("split-horizon")
        .dns_server(addr(NS1), zone(&[]))
        .dns_server(addr(NS2), zone(&[]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.contains("answered NXDOMAIN"),
        "{}",
        finding.message
    );
    assert!(
        finding.message.contains("/etc/hosts"),
        "{}",
        finding.message
    );
}

#[tokio::test(start_paused = true)]
async fn a_truncated_udp_reply_is_asked_again_over_tcp() {
    let seen_tcp = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen_tcp);
    let full = zone(&[("web.acme.test", &["192.0.2.10"])]);
    let truncating = move |q: &[u8], t: DnsTransport| {
        if t == DnsTransport::Tcp {
            counter.fetch_add(1, Ordering::SeqCst);
            return full(q, t);
        }
        let mut m = Message::from_vec(q).expect("query");
        m.metadata.message_type = MessageType::Response;
        m.metadata.truncation = true;
        DnsScript::Answer(m.to_vec().expect("encodes"))
    };
    let replay = case("split-horizon")
        .dns_server(addr(NS1), truncating)
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
    assert_eq!(seen_tcp.load(Ordering::SeqCst), 1);
    assert_eq!(positions(&ran, 0)[0]["transport"], "tcp");
}

#[tokio::test(start_paused = true)]
async fn a_reply_to_another_question_is_a_bad_reply_not_an_answer() {
    // Replies with the right ID and question but the other name's answer would pass. This one answers
    // with a wrong ID, as a stray datagram would.
    let wrong_id = |q: &[u8], _: DnsTransport| {
        let query = Message::from_vec(q).expect("query");
        let mut reply = Message::response(query.metadata.id ^ 0xffff, query.metadata.op_code);
        reply.add_query(query.queries[0].clone());
        DnsScript::Answer(reply.to_vec().expect("encodes"))
    };
    let replay = case("split-horizon")
        .dns_server(addr(NS1), wrong_id)
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let rows = positions(&ran, 0);
    assert_eq!(rows[0]["status"], "bad_reply");
    assert_eq!(rows[0]["reason"], "the reply carries another message ID");
    assert_eq!(ran.finding().level, Level::Warn);
}

#[tokio::test(start_paused = true)]
async fn garbage_from_a_nameserver_is_a_bad_reply() {
    let replay = case("split-horizon")
        .dns_server(addr(NS1), |_, _| {
            DnsScript::Answer(vec![0xde, 0xad, 0xbe, 0xef])
        })
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(positions(&ran, 0)[0]["status"], "bad_reply");
}

#[tokio::test(start_paused = true)]
async fn a_nameserver_in_a_refused_range_is_skipped_with_the_facade_text() {
    // The GCE metadata server is a resolver there. The scripted server at that address would answer if the
    // call reached the backend, so a count of zero proves it did not.
    let reached = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&reached);
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 169.254.169.254\n")
        .file("/etc/nsswitch.conf", "hosts: files dns\n")
        .command(
            "getent",
            &["ahosts", "--", "web.acme.test"],
            0,
            "192.0.2.10 STREAM web.acme.test\n192.0.2.10 DGRAM\n192.0.2.10 RAW\n",
        )
        .dns_server(addr("169.254.169.254:53"), move |_, _| {
            seen.fetch_add(1, Ordering::SeqCst);
            DnsScript::Answer(vec![0; 12])
        });
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    let finding = ran.finding();
    // The system answer is still reported, and the check is not skipped as a whole.
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(ran.name(0)["result"], "found");
    let row = &positions(&ran, 0)[0];
    assert_eq!(row["status"], "skipped");
    assert_eq!(row["reason"], RULE_NS_ADDRESS);
    assert_eq!(row["reason"], "nameserver in a refused range");
    let partial = finding.partial.as_ref().expect("a partial result");
    assert!(
        partial
            .note
            .contains("nameserver 1 was not queried directly: nameserver in a refused range"),
        "{}",
        partial.note
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("nameserver in a refused range"))
    );
    // The facade logged the refusal as a denied dns call.
    let denied = ran
        .run
        .action_log()
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Dns && a.outcome == ActionOutcome::Denied)
        .count();
    assert_eq!(denied, 1);
    assert!(!ran.result_text().contains("169.254.169.254"));
    assert!(ran.result().partial.is_some());
}

#[tokio::test(start_paused = true)]
async fn the_azure_nameserver_is_asked_and_never_named() {
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 168.63.129.16\n")
        .file("/etc/nsswitch.conf", "hosts: files dns\n")
        .command(
            "getent",
            &["ahosts", "--", "web.acme.test"],
            0,
            "192.0.2.10 STREAM web.acme.test\n",
        )
        .dns_server(
            addr("168.63.129.16:53"),
            zone(&[("web.acme.test", &["192.0.2.10"])]),
        );
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
    assert_eq!(positions(&ran, 0)[0]["status"], "replied");
    assert!(!ran.result_text().contains("168.63.129.16"));
}

#[tokio::test(start_paused = true)]
async fn a_name_with_aaaa_is_compared_in_both_families() {
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        .file("/etc/nsswitch.conf", "hosts: files dns\n")
        .command(
            "getent",
            &["ahosts", "--", "web.acme.test"],
            0,
            "2001:db8::10 STREAM web.acme.test\n192.0.2.10 STREAM\n",
        )
        .dns_server(
            addr(NS1),
            zone(&[("web.acme.test", &["192.0.2.10", "2001:db8::10"])]),
        );
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
    assert_eq!(positions(&ran, 0)[0]["aaaa_asked"], true);
    assert_eq!(positions(&ran, 0)[0]["addresses_total"], 2);
}

#[tokio::test(start_paused = true)]
async fn nsswitch_mdns_with_a_local_name_and_sss_warn() {
    let replay = case("nsswitch-sss-mdns")
        .dns_server(addr(NS1), zone(&[("svc.cluster.local", &["192.0.2.20"])]))
        .dns_server(addr(NS2), zone(&[("svc.cluster.local", &["192.0.2.20"])]));
    let ran = run_on(replay, names(&["svc.cluster.local"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding
            .message
            .contains("`svc.cluster.local` ends in `.local`")
            && finding.message.contains("[NOTFOUND=return]"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("hosts: files dns"), "{fix}");
    // sss is only a note while every name resolves quickly.
    assert!(
        finding.notes.iter().any(|n| n.contains("`sss`")),
        "{:?}",
        finding.notes
    );
    assert!(!finding.message.contains("sss"));
    assert_eq!(finding.observed["direct"]["nsswitch_hosts"]["sss"], true);
    assert_eq!(
        finding.observed["direct"]["nsswitch_hosts"]["mdns_return_before_dns"],
        true
    );
}

#[tokio::test(start_paused = true)]
async fn sss_warns_when_a_name_does_not_resolve() {
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        .file("/etc/nsswitch.conf", "hosts: files sss dns\n")
        .command("getent", &["ahosts", "--", "gone.acme.test"], 2, "")
        .dns_server(addr(NS1), zone(&[]));
    let ran = run_on(replay, names(&["gone.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("systemctl status sssd"))
    );
}

#[tokio::test(start_paused = true)]
async fn the_stub_and_a_long_list_are_notes() {
    let replay = Replay::for_os(Os::Linux)
        .file(
            "/etc/resolv.conf",
            "nameserver 127.0.0.53\nnameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\n",
        )
        .command(
            "getent",
            &["ahosts", "--", "web.acme.test"],
            0,
            "192.0.2.10 STREAM web.acme.test\n",
        )
        .dns_server(addr("127.0.0.53:53"), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_server(addr("192.0.2.1:53"), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_server(addr("192.0.2.2:53"), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("systemd-resolved stub"))
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("lists 4 nameservers"))
    );
    assert_eq!(finding.observed["direct"]["nameservers_asked"], 3);
    assert_eq!(
        finding.observed["direct"]["resolv_conf"]["stub_first"],
        true
    );
}

#[tokio::test(start_paused = true)]
async fn nothing_is_asked_without_network_and_off_linux() {
    // `--no-network`: the need is missing, so the check is skipped before any query.
    let replay =
        case("split-horizon").dns_server(addr(NS1), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let ran = run_with(
        TestRun::new(replay),
        names(&["web.acme.test"]),
        json!({}),
        Os::Linux,
        &[],
    )
    .await;
    assert!(ran.outcome.is_err());
    let dns = ran
        .run
        .action_log()
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Dns)
        .count();
    assert_eq!(dns, 0);

    // macOS has no nameserver source yet: the system answer only, no direct rows.
    let replay = case("getent-missing");
    let ran = run_with(
        TestRun::new(replay),
        names(&["web.acme.test"]),
        json!({}),
        Os::Macos,
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert!(ran.name(0).get("nameservers").is_none());
    assert!(ran.finding().observed.get("direct").is_none());
}

#[tokio::test(start_paused = true)]
async fn the_query_names_only_a_spec_host_over_the_wire() {
    // Every query the scripted server sees is for the spec name and nothing else.
    let seen: Arc<std::sync::Mutex<Vec<(String, RecordType)>>> = Arc::default();
    let log = Arc::clone(&seen);
    let inner = zone(&[("web.acme.test", &["192.0.2.10"])]);
    let spy = move |q: &[u8], t: DnsTransport| {
        let m = Message::from_vec(q).expect("query");
        let qu = &m.queries[0];
        log.lock()
            .expect("lock")
            .push((qu.name().to_ascii(), qu.query_type()));
        assert_eq!(m.queries.len(), 1);
        assert!(
            m.additionals.is_empty() && m.edns.is_none(),
            "no OPT record is sent"
        );
        inner(q, t)
    };
    let replay = case("split-horizon")
        .dns_server(addr(NS1), spy)
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]));
    let _ = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let seen = seen.lock().expect("lock");
    assert_eq!(
        seen.as_slice(),
        [("web.acme.test.".to_owned(), RecordType::A)]
    );
}

#[tokio::test(start_paused = true)]
async fn nameservers_that_overlap_the_system_answer_are_not_split_horizon() {
    // A CDN or round-robin name: another resolver returns a different but overlapping set.
    let replay = case("split-horizon")
        .dns_server(
            addr(NS1),
            zone(&[("web.acme.test", &["192.0.2.10", "192.0.2.11"])]),
        )
        .dns_server(
            addr(NS2),
            zone(&[("web.acme.test", &["192.0.2.10", "198.51.100.7"])]),
        );
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
}

#[tokio::test(start_paused = true)]
async fn the_checks_own_budget_running_out_is_not_a_nameserver_timeout() {
    // 4 s left and 2 s kept for the result leave 2 s for the direct lookups. Nameserver 1 answers after
    // 2.5 s, which is inside the facade's 3 s but past the check's budget.
    let replay = case("slow-first-nameserver")
        .dns_server(addr(NS1), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_server(addr(NS2), zone(&[("web.acme.test", &["192.0.2.10"])]))
        .dns_delay(addr(NS1), Duration::from_millis(2500));
    let ran = run_with_deadline(
        TestRun::new(replay),
        names(&["web.acme.test"]),
        json!({}),
        Os::Linux,
        NET,
        Duration::from_secs(4),
    )
    .await;
    let rows = positions(&ran, 0);
    assert_eq!(rows[0]["status"], "not_tried", "{rows}");
    assert!(
        !ran.finding().message.contains("did not answer in time"),
        "{}",
        ran.finding().message
    );
}

#[tokio::test(start_paused = true)]
async fn latency_is_the_first_question_only() {
    // The second question (AAAA) of a nameserver that answers A at once must not add to its latency:
    // nameserver 1 delays every answer by 400 ms, so A plus AAAA is 800 ms and the first question 400 ms.
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        .file("/etc/nsswitch.conf", "hosts: files dns\n")
        .command(
            "getent",
            &["ahosts", "--", "web.acme.test"],
            0,
            "2001:db8::10 STREAM web.acme.test\n192.0.2.10 STREAM\n",
        )
        .dns_server(
            addr(NS1),
            zone(&[("web.acme.test", &["192.0.2.10", "2001:db8::10"])]),
        )
        .dns_delay(addr(NS1), Duration::from_millis(400));
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    assert_eq!(positions(&ran, 0)[0]["aaaa_asked"], true);
    assert_eq!(positions(&ran, 0)[0]["ms"], 400);
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
}

#[tokio::test(start_paused = true)]
async fn the_sss_text_is_fixed() {
    assert_eq!(
        SSS_WARNING,
        "The `hosts:` line of `/etc/nsswitch.conf` lists `sss`: every lookup asks sssd first, and a stopped or slow sssd stalls them"
    );
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        .file("/etc/nsswitch.conf", "hosts: files sss dns\n")
        .command("getent", &["ahosts", "--", "gone.acme.test"], 2, "")
        .dns_server(addr(NS1), zone(&[]));
    let ran = run_on(replay, names(&["gone.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert!(finding.message.is_empty() || !finding.message.contains("sss"));
    assert!(
        finding.notes.iter().any(|n| n == SSS_WARNING),
        "{:?}",
        finding.notes
    );
}

#[tokio::test(start_paused = true)]
async fn off_linux_a_note_says_direct_lookups_were_skipped() {
    let ran = run_with(
        TestRun::new(case("getent-missing")),
        names(&["web.acme.test"]),
        json!({}),
        Os::Macos,
        NET,
    )
    .await;
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("rdy sent no direct nameserver queries") && n.contains("M2-010")),
        "{:?}",
        ran.finding().notes
    );
}

#[tokio::test(start_paused = true)]
async fn an_ipv6_only_system_answer_with_a_failed_aaaa_is_not_compared() {
    // The system answer is IPv6 only. The nameserver says NOERROR with no A record and then fails the AAAA
    // question, so the families asked leave nothing of the system answer to compare: no split-horizon warning.
    let first = std::sync::atomic::AtomicUsize::new(0);
    let flaky = move |q: &[u8], t: DnsTransport| {
        if first.fetch_add(1, Ordering::SeqCst) == 0 {
            zone(&[("web.acme.test", &[])])(q, t)
        } else {
            DnsScript::Refused
        }
    };
    let replay = Replay::for_os(Os::Linux)
        .file("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        .file("/etc/nsswitch.conf", "hosts: files dns\n")
        .command(
            "getent",
            &["ahosts", "--", "web.acme.test"],
            0,
            "2001:db8::10 STREAM web.acme.test\n",
        )
        .dns_server(addr(NS1), flaky);
    let ran = run_on(replay, names(&["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(positions(&ran, 0)[0]["aaaa_asked"], false);
    assert!(
        !finding.message.contains("split horizon"),
        "{}",
        finding.message
    );
    assert_ne!(finding.level, Level::Fail, "{finding:?}");
}
