//! The generated-chain rig for the fixture cases of `net.tls_intercept` (M1-100, 03 "net.tls_intercept",
//! 08 section 2).
//!
//! A static fixture cannot hold a certificate chain: it would be a committed key, and a validity window
//! that goes stale. So a case names the chain it wants in `chain.json`, and this rig builds it at test
//! time with the generated CA of `rdy_engine::testing::loopback` (rcgen on ring), serves it from a
//! loopback server, and points the case's scripted host at that server. Nothing is committed that looks
//! like a key, and nothing reaches the network.
//!
//! ```json
//! { "host": "web.acme.test", "chain": "machine_only" }
//! ```
//!
//! `chain` is one of:
//!
//! | `chain` | The server sends | The OS store holds | The clock |
//! | --- | --- | --- | --- |
//! | `public` | leaf, issuing CA | an unrelated root | the bundled public roots hold the root (`trust_as_public`) |
//! | `machine_only` | leaf, issuing CA | the root | real |
//! | `unknown_ca` | leaf, issuing CA | another CA | real |
//! | `expired` | an expired leaf (2020 to 2021), issuing CA | the root | pinned to `clock`: after the notAfter it is `clock_or_expiry`, inside the window it is `machine_only` |
//! | `silent` | nothing: a listener opens TCP and never answers the ClientHello | an empty store | paused, so the 5 s handshake limit costs nothing |
//!
//! Optional keys: `clock` (`2022-06-01T00:00:00Z`, required by `expired`), `os_store` (`"empty"` for a
//! machine with no trust store), `sources` (the places the OS roots were read from, the `system_roots`
//! form of a fixture: `kind`, `location` and an optional `env`), and `home` (the value of `HOME`). The
//! root is "Acme Test Root CA" and the issuing CA is "Acme Test Issuing CA", so the issuer shown is
//! `CN=Acme Test Issuing CA`.
//!
//! A case's `entry` in `expect.json` may hold `<leaf>`, `<issuing>`, `<root>` or `<other>` as a
//! `pin_sha256` item. The rig swaps in the SHA-256 of that generated certificate (`<other>` is a digest
//! no certificate has) before the check is built. The golden keeps the placeholder in the entry, and a
//! 64 digit hash anywhere in the result is written as `<sha256>`, so the golden holds the same bytes on
//! every run (08 Appendix C). A case with no `chain.json` is a static scripted case (`refused`,
//! `handshake-never-completes`): it runs on a paused clock, because nothing in it is a real socket.
//!
//! Every case is run through the real scheduler and compared with its reviewed `expect.json` by
//! `assert_golden`. The check is built by `NetFamily`, as `rdy run` builds it.

use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use rdy_checks_net::NetFamily;
use rdy_engine::check::Check;
use rdy_engine::family::Family;
use rdy_engine::probe::{
    NativeCall, NativeValue, StoreKind, StoreOrigin, StoreSource, SystemRoots,
};
use rdy_engine::sched::Planned;
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::loopback::{HttpOptions, HttpServer, NeverAccepts, TestCa, Validity};
use rdy_engine::testing::{
    Fixture, Replay, TcpScript, TestRun, assert_within_manifest, expect_bytes,
};
use rdy_spec::check::CheckParams;
use rdy_spec::parse_unverified;
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::Value;

use super::driver::pinned_time;

/// The least a spec says. `net.tls_intercept` reads its hosts from the entry.
const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\n  version: \">=4.2\"\nchecks:\n  - id: net.tls_intercept\n    hosts:\n      - web.acme.test\n";

/// The address every generated host resolves to. A documentation address: no packet goes there, because
/// the replay machine routes it to the loopback server.
const ADDR: &str = "192.0.2.7:443";

/// The id of the check these cases answer.
const ID: &str = "net.tls_intercept";

/// What `chain.json` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Public,
    MachineOnly,
    UnknownCa,
    Expired,
    Silent,
}

/// A parsed `chain.json`.
struct Wanted {
    host: String,
    kind: Kind,
    clock: Option<String>,
    empty_store: bool,
    sources: Vec<StoreSource>,
    home: Option<String>,
}

fn text<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match obj.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("chain.json: `{key}` must be a string")),
    }
}

/// Reads `chain.json`. An unknown key is an error, so a typo cannot silently drop a requirement.
fn parse_wanted(bytes: &str) -> Result<Wanted, String> {
    let value: Value = serde_json::from_str(bytes).map_err(|e| format!("chain.json: {e}"))?;
    let obj = value.as_object().ok_or("chain.json: must be an object")?;
    for key in obj.keys() {
        if !["host", "chain", "clock", "os_store", "sources", "home"].contains(&key.as_str()) {
            return Err(format!("chain.json: unknown key `{key}`"));
        }
    }
    let host = text(obj, "host")?
        .ok_or("chain.json: `host` is missing")?
        .to_owned();
    let kind = match text(obj, "chain")?.ok_or("chain.json: `chain` is missing")? {
        "public" => Kind::Public,
        "machine_only" => Kind::MachineOnly,
        "unknown_ca" => Kind::UnknownCa,
        "expired" => Kind::Expired,
        "silent" => Kind::Silent,
        other => {
            return Err(format!(
                "chain.json: `chain` is `{other}`; it must be public, machine_only, unknown_ca, expired or silent"
            ));
        }
    };
    let clock = text(obj, "clock")?.map(str::to_owned);
    if (kind == Kind::Expired) != clock.is_some() {
        return Err("chain.json: `clock` is required by `expired` and by nothing else".to_owned());
    }
    let empty_store = match text(obj, "os_store")? {
        None => false,
        Some("empty") => true,
        Some(other) => return Err(format!("chain.json: `os_store` is `{other}`; only `empty`")),
    };
    let mut sources = Vec::new();
    for item in obj
        .get("sources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let item = item
            .as_object()
            .ok_or("chain.json: a source is an object")?;
        let kind = match text(item, "kind")?.ok_or("chain.json: a source needs `kind`")? {
            "bundle" => StoreKind::Bundle,
            "directory" => StoreKind::Directory,
            "os" => StoreKind::OsStore,
            other => return Err(format!("chain.json: a source `kind` is `{other}`")),
        };
        let location = text(item, "location")?.ok_or("chain.json: a source needs `location`")?;
        let origin = match text(item, "env")? {
            None => StoreOrigin::Standard,
            Some("SSL_CERT_FILE") => StoreOrigin::Env("SSL_CERT_FILE"),
            Some("SSL_CERT_DIR") => StoreOrigin::Env("SSL_CERT_DIR"),
            Some(other) => return Err(format!("chain.json: a source `env` is `{other}`")),
        };
        sources.push(StoreSource::new(kind, location).origin(origin));
    }
    Ok(Wanted {
        host,
        kind,
        clock,
        empty_store,
        sources,
        home: text(obj, "home")?.map(str::to_owned),
    })
}

/// The SHA-256 of a certificate as 64 lowercase hex digits.
fn hex(der: &[u8]) -> String {
    rdy_engine::probe::net::TrustStore::hex(&rdy_engine::probe::net::TrustStore::hash(der))
}

/// The generated certificates of one case, and the server that sends them.
struct Rig {
    run: TestRun,
    pins: [(&'static str, String); 4],
    /// The server, held until the check has ended.
    server: Box<dyn std::any::Any>,
}

/// Builds the chain `wanted` asks for and the machine that sees it.
async fn build(wanted: &Wanted, fixture: &Fixture) -> Result<Rig, String> {
    let addr: std::net::SocketAddr = ADDR.parse().map_err(|e| format!("{e}"))?;
    if wanted.kind == Kind::Silent {
        // TCP opens (the kernel completes it) and nothing ever reads the ClientHello.
        let silent = NeverAccepts::start()
            .await
            .map_err(|e| format!("the listener did not start: {e}"))?;
        let replay = fixture
            .replay()
            .clone()
            .host(&wanted.host, [addr.ip()])
            .tcp(addr, TcpScript::Serve("silent".to_owned()))
            .serve_tcp("silent", silent.addr())
            .native(
                NativeCall::SystemRoots,
                NativeValue::SystemRoots(SystemRoots::new(Vec::new(), Vec::new())),
            );
        return Ok(Rig {
            run: TestRun::new(replay),
            pins: [
                ("<leaf>", String::new()),
                ("<issuing>", String::new()),
                ("<root>", String::new()),
                ("<other>", "ab".repeat(32)),
            ],
            server: Box::new(silent),
        });
    }
    let root = TestCa::root("Acme Test Root CA");
    let issuing = root.intermediate("Acme Test Issuing CA");
    let validity = if wanted.kind == Kind::Expired {
        Validity::Expired
    } else {
        Validity::Always
    };
    let leaf = issuing.issue(&[wanted.host.as_str()], validity);
    let leaf_hash = hex(leaf.chain()[0].as_ref());
    let options = HttpOptions::tls(&leaf).alpn(&["h2", "http/1.1"]);
    let server = HttpServer::start(options)
        .await
        .map_err(|e| format!("the loopback server did not start: {e}"))?;

    let other = TestCa::root("Acme Other Root CA");
    let der = |ca: &TestCa| ca.root_der().as_ref().to_vec();
    let certs: Vec<Vec<u8>> = if wanted.empty_store {
        Vec::new()
    } else {
        match wanted.kind {
            // The OS store holds an unrelated root: the public roots decide this chain.
            Kind::Public => vec![der(&other)],
            Kind::MachineOnly | Kind::Expired => vec![der(&root)],
            Kind::UnknownCa => vec![der(&other)],
            Kind::Silent => Vec::new(),
        }
    };
    let mut replay: Replay = fixture
        .replay()
        .clone()
        .host(&wanted.host, [addr.ip()])
        .tcp(addr, TcpScript::Serve("tls".to_owned()))
        .serve_tcp("tls", server.addr())
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(SystemRoots::new(certs, wanted.sources.clone())),
        );
    if let Some(home) = &wanted.home {
        replay = replay.env("HOME", home);
    }
    let run = TestRun::new(replay);
    if wanted.kind == Kind::Public {
        run.trust_as_public(&der(&root));
    }
    if let Some(clock) = &wanted.clock {
        let at = pinned_time(clock)?
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("the pinned clock is before 1970: {e}"))?;
        run.pin_clock(at);
    }
    Ok(Rig {
        run,
        pins: [
            ("<leaf>", leaf_hash),
            ("<issuing>", hex(issuing.der().as_ref())),
            ("<root>", hex(root.root_der().as_ref())),
            ("<other>", "ab".repeat(32)),
        ],
        server: Box::new(server),
    })
}

/// `entry` with each `<leaf>`, `<issuing>`, `<root>` and `<other>` item of `pin_sha256` replaced.
fn with_pins(entry: &Value, pins: &[(&'static str, String)]) -> Value {
    let mut out = entry.clone();
    if let Some(list) = out.get_mut("pin_sha256").and_then(Value::as_array_mut) {
        for item in list {
            let swapped = item
                .as_str()
                .and_then(|name| pins.iter().find(|(token, _)| *token == name))
                .map(|(_, digest)| digest.clone());
            if let Some(digest) = swapped {
                *item = Value::String(digest);
            }
        }
    }
    out
}

/// `bytes` with every run of exactly 64 lowercase hex digits written as `<sha256>`, the placeholder of
/// 08 Appendix C. The digest of a generated certificate is different on every run.
fn placeholder_hashes(bytes: &str) -> String {
    let chars: Vec<char> = bytes.chars().collect();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < chars.len() {
        let run = chars[i..]
            .iter()
            .take_while(|c| matches!(c, '0'..='9' | 'a'..='f'))
            .count();
        if run == 64 {
            out.push_str("<sha256>");
            i += 64;
        } else if run > 0 {
            out.extend(&chars[i..i + run]);
            i += run;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Runs the case `case` of `net.tls_intercept` under the fixtures in `root` and compares the result with
/// its `expect.json`. Returns the way the case ended, for the tests that read it.
pub fn run_case(root: &Path, case: &str) -> Result<Value, String> {
    let name = format!("checks/{ID}/{case}");
    let dir = root.join("checks").join(ID).join(case);
    let fixture = Fixture::load(root, &name).map_err(|e| format!("{name} does not load: {e}"))?;
    fixture
        .ensure_answers(ID)
        .map_err(|e| format!("{name} must answer {ID}: {e}"))?;
    let expect_path = dir.join("expect.json");
    let golden: Value =
        serde_json::from_str(&std::fs::read_to_string(&expect_path).map_err(|e| {
            format!("{name}/expect.json: {e}. Fix: write the entry, then run with UPDATE_GOLDENS=1")
        })?)
        .map_err(|e| format!("{name}/expect.json: {e}"))?;
    let entry = golden
        .get("entry")
        .ok_or_else(|| format!("{name}/expect.json has no `entry`"))?;
    let chain_path = dir.join("chain.json");
    let wanted = if chain_path.is_file() {
        let bytes = std::fs::read_to_string(&chain_path).map_err(|e| format!("{name}: {e}"))?;
        Some(parse_wanted(&bytes).map_err(|e| format!("{name}: {e}"))?)
    } else {
        None
    };

    // Real sockets need a real clock. A static case holds no socket, so its hang costs nothing on a
    // paused one.
    let mut runtime = tokio::runtime::Builder::new_current_thread();
    runtime.enable_all();
    // A silent listener is a hang, and under a paused clock its 5 s limit costs nothing.
    if wanted.as_ref().is_none_or(|w| w.kind == Kind::Silent) {
        runtime.start_paused(true);
    }
    let runtime = runtime
        .build()
        .map_err(|e| format!("cannot build a runtime: {e}"))?;
    let end = runtime.block_on(async {
        // The server is held until the check has ended.
        let mut _server = None;
        let (run, real_entry) = match &wanted {
            Some(wanted) => {
                let rig = build(wanted, &fixture).await?;
                let real = with_pins(entry, &rig.pins);
                _server = Some(rig.server);
                (rig.run, real)
            }
            None => (TestRun::for_fixture(&fixture), entry.clone()),
        };
        let spec_entry: CheckSpec = serde_json::from_value(real_entry)
            .map_err(|e| format!("{name}/expect.json `entry` is not a check entry: {e}"))?;
        let spec: Spec = parse_unverified(SPEC.as_bytes())
            .map_err(|e| format!("the spec does not parse: {e}"))?;
        let params: CheckParams = spec_entry.decode_params();
        let built = NetFamily
            .build(&spec_entry, params, &spec)
            .map_err(|e| format!("{name}: the family does not build the entry: {e}"))?;
        let check: Arc<dyn Check> = Arc::from(built.check);
        let info = check.info();
        let scheduler = run.scheduler(1, fixture.os(), fixture.available_needs());
        let mut ran = scheduler
            .run(vec![Planned::new(check, ID).with_hosts(built.hosts)])
            .await;
        let end = ran.remove(0).end;
        assert_within_manifest(&name, info, &run.action_log());
        Ok::<_, String>(end)
    })?;

    let bytes = placeholder_hashes(&expect_bytes(entry, &end));
    assert_golden(&expect_path, &bytes);
    let written: Value = serde_json::from_str(&bytes).map_err(|e| format!("{e}"))?;
    Ok(written.get("result").cloned().unwrap_or(Value::Null))
}

/// The names of the cases of `net.tls_intercept` under `root`, sorted.
pub fn case_names(root: &Path) -> Result<Vec<String>, String> {
    let dir = root.join("checks").join(ID);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        if entry.path().is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_become_placeholders_and_other_hex_does_not() {
        let digest = "ab".repeat(32);
        let text = format!("x{digest}y {digest} {}", "cd".repeat(31));
        assert_eq!(
            placeholder_hashes(&text),
            format!("x<sha256>y <sha256> {}", "cd".repeat(31))
        );
        // 65 digits is not a digest.
        assert_eq!(placeholder_hashes(&"a".repeat(65)), "a".repeat(65));
    }

    #[test]
    fn a_chain_file_with_an_unknown_key_or_a_missing_clock_is_refused() {
        assert!(parse_wanted(r#"{"host":"a.test","chain":"public"}"#).is_ok());
        assert!(parse_wanted(r#"{"host":"a.test","chain":"public","clok":"x"}"#).is_err());
        assert!(parse_wanted(r#"{"host":"a.test","chain":"expired"}"#).is_err());
        assert!(
            parse_wanted(r#"{"host":"a.test","chain":"expired","clock":"2022-06-01T00:00:00Z"}"#)
                .is_ok()
        );
        assert!(
            parse_wanted(r#"{"host":"a.test","chain":"public","clock":"2022-06-01T00:00:00Z"}"#)
                .is_err()
        );
        assert!(parse_wanted(r#"{"host":"a.test","chain":"self_signed"}"#).is_err());
    }
}
