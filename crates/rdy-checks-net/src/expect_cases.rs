//! Every fixture case of `net.egress` against its reviewed `expect.json` (M1-096).
//!
//! Each directory under `tests/fixtures/checks/net.egress/` runs through the real scheduler on a paused
//! clock, with no socket, and is compared with its `expect.json` through
//! `rdy_engine::testing::assert_cases_with`. The `serve` entries of the cases name in-process servers,
//! which this module registers: a plain HTTP server that answers a fixed status, and one that does not
//! speak HTTP. The TLS cases (a chain, an expired certificate, a reset after the hello) need real sockets
//! and the real clock, so the tests in `egress/tests.rs` hold them.

use rdy_engine::family::{Built, Family};
use rdy_engine::testing::{Replay, assert_cases_with};
use rdy_spec::parse_unverified;
use rdy_spec::spec::{CheckSpec, Spec};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::NetFamily;

/// The least a spec says. The check reads nothing from it, so the entry decides everything.
const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\n  version: \">=4.2\"\nchecks:\n  - id: host.cpu\n    min: 1\n";

/// The check the family builds for `entry`, with its hosts, as `rdy run` builds it.
fn build(entry: &CheckSpec) -> Built {
    let spec: Spec = parse_unverified(SPEC.as_bytes()).expect("the example spec parses");
    NetFamily
        .build(entry, entry.decode_params(), &spec)
        .expect("the family builds the entry")
}

/// Reads the request head, then writes `reply` and closes.
async fn answer(mut stream: DuplexStream, reply: &'static [u8]) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 512];
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
    }
    let _ = stream.write_all(reply).await;
    let _ = stream.shutdown().await;
}

/// The servers the cases name.
fn servers(replay: Replay) -> Replay {
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const UNAUTHORIZED: &[u8] =
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const NOT_FOUND: &[u8] =
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const UNAVAILABLE: &[u8] =
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const NOT_HTTP: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
    replay
        .serve_duplex("web", |s| answer(s, OK))
        .serve_duplex("web-401", |s| answer(s, UNAUTHORIZED))
        .serve_duplex("web-404", |s| answer(s, NOT_FOUND))
        .serve_duplex("web-503", |s| answer(s, UNAVAILABLE))
        .serve_duplex("not-http", |s| answer(s, NOT_HTTP))
}

#[test]
fn net_egress_cases_match_their_expect_json() {
    let cases = assert_cases_with("net.egress", build, servers);
    // A new case directory changes the count, so adding or deleting one is a deliberate edit.
    assert_eq!(cases.len(), 11, "the cases are {cases:?}");
}
