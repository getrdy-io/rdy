//! M1-026: semantic validation and structural limits, on the fixtures in `tests/fixtures/specs/invalid/`.
//!
//! Every refusal is an `Err(SpecError)` with the wording of 01 section 2.5. The CLI maps all of them to
//! exit 64 (a spec content error). Helpers here avoid `unwrap` and `expect` because clippy only allows
//! them inside `#[test]` functions.
//!
//! This file pins the clock with `load_at`, which the CLI may not call (clippy.toml).

#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rdy_spec::sig::{Policy, TrustStore};
use rdy_spec::{MAX_CHECKS, MAX_ENDPOINTS, MAX_HOSTS, SpecError, load, load_at, parse_unverified};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/specs")
        .join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

fn refused(name: &str) -> SpecError {
    match parse_unverified(&fixture(name)) {
        Ok(_) => panic!("{name} should be refused"),
        Err(e) => e,
    }
}

fn place(e: &SpecError) -> Option<(u32, u32)> {
    e.location().map(|l| (l.line, l.column))
}

/// Every refusal has a one-line message and a fix line, with no control characters.
fn assert_printable(e: &SpecError) {
    for text in [e.to_string(), e.fix()] {
        assert!(!text.is_empty());
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
}

#[test]
fn the_limits_are_the_documented_numbers() {
    assert_eq!(MAX_CHECKS, 256);
    assert_eq!(MAX_HOSTS, 64);
}

#[test]
fn a_spec_of_257_checks_is_refused_with_the_count_and_the_limit() {
    let e = refused("invalid/too-many-checks.yaml");
    assert_eq!(
        e,
        SpecError::TooManyChecks {
            count: 257,
            limit: 256
        }
    );
    assert_eq!(e.to_string(), "257 checks. The limit is 256");
    assert_eq!(e.fix(), "split the spec in two, or remove checks.");
    assert_printable(&e);
}

#[test]
fn a_spec_of_256_checks_is_read() {
    let yaml = String::from_utf8(fixture("invalid/too-many-checks.yaml")).unwrap_or_default();
    // Drop the last entry: three lines.
    let lines: Vec<&str> = yaml.lines().collect();
    let kept = lines[..lines.len() - 3].join("\n");
    match parse_unverified(kept.as_bytes()) {
        Ok(spec) => assert_eq!(spec.checks.len(), 256),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn the_reported_count_is_the_real_one_however_long_the_list_is() {
    let mut yaml =
        String::from("apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n");
    for i in 0..3000 {
        yaml.push_str(&format!("  - id: host.cpu\n    name: c{i}\n    min: 2\n"));
    }
    match parse_unverified(yaml.as_bytes()) {
        Err(SpecError::TooManyChecks { count: 3000, .. }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_empty_checks_list_is_refused() {
    let yaml = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks: []\n";
    match parse_unverified(yaml.as_bytes()) {
        Err(e) => {
            assert_eq!(e, SpecError::NoChecks);
            assert_printable(&e);
        }
        Ok(_) => panic!("an empty list should be refused"),
    }
}

#[test]
fn sixty_five_endpoints_in_one_check_are_refused() {
    let e = refused("invalid/too-many-endpoints.yaml");
    assert_eq!(
        e,
        SpecError::TooManyHosts {
            count: 65,
            limit: 64
        }
    );
    assert_eq!(e.to_string(), "65 endpoints. The limit is 64");
    assert_printable(&e);
}

#[test]
fn hosts_are_counted_across_egress_tls_and_dns_checks() {
    // 30 egress endpoints, 30 TLS hosts and 5 DNS names, all different: 65 hosts, no check over its own
    // limit of 64.
    let e = refused("invalid/too-many-hosts-across-checks.yaml");
    assert_eq!(
        e,
        SpecError::TooManyHosts {
            count: 65,
            limit: 64
        }
    );
}

#[test]
fn host_and_port_pairs_are_counted_across_checks() {
    // 4 hosts with 64 ports each is 256 pairs and passes. One more pair on a known host is refused, and
    // the host count (4) is nowhere near its limit.
    let e = refused("invalid/too-many-endpoint-pairs.yaml");
    assert_eq!(
        e,
        SpecError::TooManyEndpoints {
            count: 257,
            limit: 256
        }
    );
    assert_eq!(MAX_ENDPOINTS, 256);
    assert_eq!(e.to_string(), "257 host and port pairs. The limit is 256");
    assert_eq!(
        e.fix(),
        "remove endpoints, or split the spec in two. A host and port counts once, however many checks name it."
    );
    assert_printable(&e);
}

#[test]
fn a_duplicate_key_is_refused_at_its_place() {
    let e = refused("malformed/duplicate-key-check.yaml");
    assert!(matches!(e.kind(), SpecError::DuplicateKey { .. }), "{e:?}");
    assert!(place(&e).is_some());
    assert_printable(&e);
}

#[test]
fn a_bad_product_name_is_refused_with_its_place() {
    let e = refused("invalid/bad-product.yaml");
    assert_eq!(e.to_string(), "'Acme Platform' is not a valid product name");
    assert_eq!(place(&e), Some((4, 12)));
    assert_eq!(
        e.fix(),
        "use lowercase letters, digits and hyphens, such as 'acme-platform'."
    );
}

#[test]
fn an_unknown_metadata_key_names_the_block() {
    let e = refused("invalid/unknown-metadata-key.yaml");
    assert_eq!(e.to_string(), "unknown key 'prodcut' in metadata");
    assert_eq!(place(&e), Some((5, 3)));
    assert_printable(&e);
}

#[test]
fn an_unknown_bundle_key_names_the_block() {
    let e = refused("invalid/unknown-bundle-key.yaml");
    assert_eq!(e.to_string(), "unknown key 'colect' in bundle");
    assert_eq!(place(&e), Some((10, 3)));
    assert_printable(&e);
}

#[test]
fn a_relative_file_collector_is_refused_at_its_item() {
    let e = refused("invalid/relative-file-collector.yaml");
    let text = e.to_string();
    assert!(text.contains("file:etc/acme/app.yaml"), "{text}");
    assert!(text.contains("the path is not absolute"), "{text}");
    assert_eq!(place(&e), Some((11, 7)));
    assert_printable(&e);
}

#[test]
fn collectors_follow_the_grammar_of_the_bundle_section() {
    let spec = |item: &str| {
        format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 2\nbundle:\n  collect: [{item}]\n"
        )
    };
    let ok = |item: &str| match parse_unverified(spec(item).as_bytes()) {
        Ok(_) => {}
        Err(e) => panic!("{item}: {e}"),
    };
    let bad = |item: &str| {
        let e = match parse_unverified(spec(item).as_bytes()) {
            Ok(_) => panic!("{item} should be refused"),
            Err(e) => e,
        };
        assert!(matches!(e.kind(), SpecError::InvalidValue { .. }), "{e:?}");
        assert_eq!(place(&e), Some((9, 13)), "{item}");
        assert_printable(&e);
    };
    for item in [
        "\"journal:7d\"",
        "\"journal:90m\"",
        "\"k8s:events\"",
        "\"file:/etc/acme/*.yaml\"",
        "\"file:/var/log/..acme/x\"",
    ] {
        ok(item);
    }
    for item in [
        "\"journal:\"",
        "\"journal:7\"",
        "\"journal:7 d\"",
        "\"k8s:events:x\"",
        "\"k8s:pods\"",
        "\"file:\"",
        "\"file:relative/path\"",
        "\"file:./x\"",
        "\"file:/etc/../shadow\"",
        "\"file:/etc/acme/..\"",
        "'file:C:\\acme\\x'",
        "'file:/etc/acme\\x'",
        "'file:/etc/acme/\\..\\x'",
        "\"file:/etc/a\\u0085b\"",
        "\"file:/etc/a\\tb\"",
        "\"exec:ls\"",
        "\"\"",
    ] {
        bad(item);
    }
}

#[test]
fn bundle_lists_have_their_limits() {
    let head = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 2\nbundle:\n";
    let list = |n: usize, item: &str| format!("[{}]", vec![item; n].join(", "));
    let run = |body: String| parse_unverified(format!("{head}{body}\n").as_bytes());
    assert!(run(format!("  collect: {}", list(64, "\"k8s:events\""))).is_ok());
    assert!(run(format!("  redact: {}", list(64, "aws_keys"))).is_ok());
    let e = match run(format!("  collect: {}", list(65, "\"k8s:events\""))) {
        Err(e) => e,
        Ok(_) => panic!("65 collectors should be refused"),
    };
    assert_eq!(
        e.to_string(),
        "bundle.collect has 65 entries. The limit is 64"
    );
    assert!(place(&e).is_some());
    let e = match run(format!("  redact: {}", list(65, "aws_keys"))) {
        Err(e) => e,
        Ok(_) => panic!("65 redact groups should be refused"),
    };
    assert_eq!(
        e.to_string(),
        "bundle.redact has 65 entries. The limit is 64"
    );
    for bad in ["Aws_Keys", "1abc", "a-b", "", "a\"\\u0000\"", "aws keys"] {
        let name = format!("  redact: [\"{bad}\"]");
        assert!(run(name).is_err(), "redact group {bad:?}");
        let name = format!("  redact_patterns: [{{name: \"{bad}\", regex: 'x'}}]");
        assert!(run(name).is_err(), "pattern name {bad:?}");
    }
    assert!(run("  redact: [aws_keys, a1_b]".to_owned()).is_ok());
    assert!(
        run(format!(
            "  redact_patterns: [{{name: {}, regex: 'x'}}]",
            "a".repeat(32)
        ))
        .is_ok()
    );
    assert!(
        run(format!(
            "  redact_patterns: [{{name: {}, regex: 'x'}}]",
            "a".repeat(33)
        ))
        .is_err()
    );
    let patterns = |n: usize| {
        let one = "{name: p, regex: 'ACME-[A-Z]+'}";
        format!("  redact_patterns: {}", list(n, one))
    };
    assert!(run(patterns(32)).is_ok());
    assert!(run(patterns(33)).is_err());
    let long = format!(
        "  redact_patterns: [{{name: p, regex: '{}'}}]",
        "a".repeat(257)
    );
    assert!(run(long).is_err());
}

#[test]
fn metadata_lengths_and_annotations_have_their_limits() {
    let spec = |meta: &str| {
        format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\n{meta}checks:\n  - id: host.cpu\n    min: 2\n"
        )
    };
    let run = |meta: String| parse_unverified(spec(&meta).as_bytes());
    assert!(run(format!("  version: \"{}\"\n", "v".repeat(64))).is_ok());
    let e = match run(format!("  version: \"{}\"\n", "v".repeat(65))) {
        Err(e) => e,
        Ok(_) => panic!("a 65 character version should be refused"),
    };
    assert_eq!(
        e.to_string(),
        "metadata.version is 65 characters. The limit is 64"
    );
    assert_eq!(place(&e), Some((5, 12)));
    let e = match run("  version: \"\"\n".to_owned()) {
        Err(e) => e,
        Ok(_) => panic!("an empty version should be refused"),
    };
    assert!(
        e.to_string().starts_with("metadata.version is empty"),
        "{e}"
    );
    assert_eq!(place(&e), Some((5, 12)));
    assert!(run(format!("  contact: \"{}\"\n", "c".repeat(256))).is_ok());
    assert!(run(format!("  contact: \"{}\"\n", "c".repeat(257))).is_err());
    let annotations = |n: usize| {
        let mut s = String::from("  annotations:\n");
        for i in 0..n {
            s.push_str(&format!("    k{i}: v\n"));
        }
        s
    };
    assert!(run(annotations(32)).is_ok());
    let e = match run(annotations(33)) {
        Err(e) => e,
        Ok(_) => panic!("33 annotations should be refused"),
    };
    assert_eq!(
        e.to_string(),
        "metadata.annotations has 33 entries. The limit is 32"
    );
    assert_eq!(place(&e), Some((6, 5)));
}

#[test]
fn expires_must_be_the_full_utc_form() {
    let e = refused("invalid/bad-expires.yaml");
    assert_eq!(e.kind(), &SpecError::BadExpires);
    assert_eq!(e.to_string(), "expires must be a full UTC time");
    assert_eq!(place(&e), Some((5, 12)));
    assert_eq!(e.fix(), "write it like 'expires: 2027-01-31T00:00:00Z'.");
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn an_expired_spec_is_refused_by_load_with_both_dates() {
    let bytes = fixture("invalid/expired.yaml");
    // The parser has no clock, so it reads the file.
    assert!(parse_unverified(&bytes).is_ok());
    // 2020-02-03T00:00:00Z.
    let now = at(1_580_428_800 + 3 * 86_400);
    let e = match load_at(&bytes, None, &TrustStore::new(), Policy::AllowUnsigned, now) {
        Err(e) => e,
        Ok(_) => panic!("an expired spec should be refused"),
    };
    assert_eq!(
        e,
        SpecError::Expired {
            expired_on: "2020-01-31".to_owned(),
            today: "2020-02-03".to_owned()
        }
    );
    assert_eq!(
        e.to_string(),
        "expired on 2020-01-31. This machine's clock says 2020-02-03"
    );
    assert_eq!(
        e.fix(),
        "ask the vendor for a current spec. If this machine's clock is wrong, set it and run again."
    );
}

#[test]
fn a_spec_is_loaded_until_the_second_it_names() {
    let bytes = fixture("invalid/expired.yaml");
    let trust = TrustStore::new();
    let load_now = |now| load_at(&bytes, None, &trust, Policy::AllowUnsigned, now);
    assert!(load_now(at(1_580_428_800)).is_ok());
    assert!(load_now(at(1_580_428_801)).is_err());
}

#[test]
fn load_reads_the_real_clock() {
    // The fixture expired in January 2020, before any date this test can run on with a sane clock. Only
    // the fail-closed half is pinned: an old date is refused, and a spec with no expiry is never refused
    // for it.
    let old = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\n  expires: \"2001-01-01T00:00:00Z\"\nchecks:\n  - id: host.cpu\n    min: 2\n";
    match load(
        old.as_bytes(),
        None,
        &TrustStore::new(),
        Policy::AllowUnsigned,
    ) {
        Err(SpecError::Expired { expired_on, .. }) => assert_eq!(expired_on, "2001-01-01"),
        other => panic!("{other:?}"),
    }
    let none = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 2\n";
    assert!(
        load(
            none.as_bytes(),
            None,
            &TrustStore::new(),
            Policy::AllowUnsigned
        )
        .is_ok()
    );
}

#[test]
fn an_annotation_must_fit_the_schema() {
    let spec = |annotation: &str| {
        format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\n  annotations:\n    {annotation}\nchecks:\n  - id: host.cpu\n    min: 2\n"
        )
    };
    for ok in ["portal.id: abc", "a/b-c_d.e: \"\"", "k: \"vvv\""] {
        assert!(parse_unverified(spec(ok).as_bytes()).is_ok(), "{ok}");
    }
    for bad in [
        "Portal: x".to_owned(),
        "-a: x".to_owned(),
        "a b: x".to_owned(),
        format!("{}: x", "k".repeat(64)),
        format!("k: \"{}\"", "v".repeat(257)),
    ] {
        match parse_unverified(spec(&bad).as_bytes()) {
            Err(e) => {
                assert!(matches!(e.kind(), SpecError::InvalidValue { .. }), "{e:?}");
                assert_eq!(place(&e), Some((6, 5)));
                assert_printable(&e);
            }
            Ok(_) => panic!("{bad} should be refused"),
        }
    }
}
