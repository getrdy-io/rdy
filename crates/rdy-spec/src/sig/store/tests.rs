//! Tests for the `trust.yaml` format. Keys are synthetic and made in each test.

use super::super::base64;
use super::*;
use crate::result::Signature;
use crate::sig::{Policy, SignatureState};

const ADDED: &str = "2026-11-30T16:20:00Z";

fn slug(text: &str) -> ProductSlug {
    ProductSlug::new(text).expect("slug")
}

/// A synthetic key pair.
struct Pair {
    secret: minisign::SecretKey,
    public: minisign::PublicKey,
}

impl Pair {
    fn new() -> Self {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().expect("keypair");
        Self {
            secret: pair.sk,
            public: pair.pk,
        }
    }

    fn text(&self) -> String {
        self.public.to_base64()
    }

    fn key(&self) -> PublicKey {
        PublicKey::from_base64(&self.text()).expect("key")
    }

    fn sign(&self, bytes: &[u8], comment: &str) -> String {
        minisign::sign(
            Some(&self.public),
            &self.secret,
            std::io::Cursor::new(bytes),
            Some(comment),
            None,
        )
        .expect("sign")
        .into_string()
    }
}

fn file(entries: &str) -> String {
    format!("apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n{entries}")
}

fn entry(product: &str, key: &str) -> String {
    format!("  - product: {product}\n    key: {key}\n    added_at: {ADDED}\n")
}

fn read(text: &str) -> Result<TrustStore, TrustFileError> {
    TrustStore::from_yaml(text.as_bytes(), TrustSource::User)
}

#[test]
fn the_documented_file_reads_with_its_note() {
    let pair = Pair::new();
    let text = file(&format!(
        "{}    note: \"Acme security page, fingerprint read back by phone\"\n",
        entry("acme-platform", &pair.text())
    ));
    let store = read(&text).expect("reads");
    assert_eq!(store.pins.len(), 1);
    let pin = &store.pins[0];
    assert_eq!(pin.product.as_str(), "acme-platform");
    assert_eq!(pin.key, pair.key());
    assert_eq!(pin.source, TrustSource::User);
    assert_eq!(pin.added_at.as_deref(), Some(ADDED));
    assert_eq!(
        pin.note.as_deref(),
        Some("Acme security page, fingerprint read back by phone")
    );
}

#[test]
fn a_store_reads_back_to_the_same_pins() {
    let (a, b) = (Pair::new(), Pair::new());
    let notes = [
        None,
        Some("plain note"),
        Some("quote \" backslash \\ colon: hash # dash - brace {x} 'single'"),
        Some("unicode \u{e9}\u{4e2d}\u{1f512}"),
    ];
    let mut text = String::from("apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n");
    for (i, note) in notes.iter().enumerate() {
        let pair = if i % 2 == 0 { &a } else { &b };
        let product = format!("prod-{i}");
        text.push_str(&entry(&product, &pair.text()));
        if let Some(note) = note {
            text.push_str(&format!("    note: {}\n", quoted(note)));
        }
    }
    let store = read(&text).expect("reads");
    let written = store.to_yaml();
    let again = read(&written).expect("the written text reads back");
    assert_eq!(again, store);
    assert_eq!(again.to_yaml(), written);
}

#[test]
fn a_note_cannot_add_a_key_to_the_written_file() {
    let pair = Pair::new();
    let mut store = TrustStore::new();
    store.pins.push(Pin {
        product: slug("acme-platform"),
        key: pair.key(),
        source: TrustSource::User,
        added_at: Some(ADDED.to_owned()),
        note: Some("x\"\n  - product: evil\n    key: y".to_owned()),
    });
    // The writer escapes the newline, so the file has one entry. The reader then refuses the note,
    // because it has control characters. Either way, no second entry appears.
    let text = store.to_yaml();
    assert_eq!(text.matches("product:").count(), 2, "{text}");
    assert_eq!(text.lines().count(), 7, "{text}");
    assert!(matches!(
        read(&text),
        Err(TrustFileError::Entry { index: 1, .. })
    ));
}

#[test]
fn an_empty_store_is_written_as_an_empty_list_and_reads_back() {
    let text = TrustStore::new().to_yaml();
    assert_eq!(text, "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n");
    assert_eq!(read(&text).expect("reads"), TrustStore::new());
}

#[test]
fn a_one_run_key_is_never_written() {
    let pair = Pair::new();
    let mut store = TrustStore::new();
    store.pin(slug("acme-platform"), pair.key(), TrustSource::Flag);
    assert_eq!(store.to_yaml(), TrustStore::new().to_yaml());
    assert!(!store.to_yaml().contains(&pair.text()));
}

#[test]
fn the_source_is_the_one_the_caller_gives() {
    let pair = Pair::new();
    let text = file(&entry("acme-platform", &pair.text()));
    for source in [TrustSource::System, TrustSource::User] {
        let store = TrustStore::from_yaml(text.as_bytes(), source).expect("reads");
        assert!(store.pins.iter().all(|pin| pin.source == source));
    }
}

#[test]
fn extend_keeps_each_pins_source() {
    let (a, b) = (Pair::new(), Pair::new());
    let mut user = TrustStore::from_yaml(
        file(&entry("acme-platform", &a.text())).as_bytes(),
        TrustSource::User,
    )
    .expect("user");
    let system = TrustStore::from_yaml(
        file(&entry("acme-platform", &b.text())).as_bytes(),
        TrustSource::System,
    )
    .expect("system");
    user.extend(system);
    let sources: Vec<TrustSource> = user.pins.iter().map(|pin| pin.source).collect();
    assert_eq!(sources, [TrustSource::User, TrustSource::System]);
}

#[test]
fn an_unknown_key_is_an_error_with_a_place_and_the_documented_fix() {
    let pair = Pair::new();
    for text in [
        format!(
            "apiVersion: rdy/v1\nkind: TrustStore\nextra: 1\nkeys:\n{}",
            entry("acme-platform", &pair.text())
        ),
        file(&format!(
            "{}    fingerprint: abc\n",
            entry("acme-platform", &pair.text())
        )),
    ] {
        let error = read(&text).expect_err("must fail");
        assert!(
            matches!(error, TrustFileError::UnknownField { .. }),
            "{error:?}"
        );
        assert!(error.location().is_some(), "{error:?}");
        assert_eq!(
            error.hint(),
            "remove that line, or run rdy trust list to see what rdy wrote"
        );
    }
}

#[test]
fn the_header_must_be_rdy_v1_and_trust_store() {
    assert_eq!(
        read("apiVersion: rdy/v2\nkind: TrustStore\nkeys: []\n").unwrap_err(),
        TrustFileError::Header {
            field: "apiVersion"
        }
    );
    assert_eq!(
        read("apiVersion: rdy/v1\nkind: Readiness\nkeys: []\n").unwrap_err(),
        TrustFileError::Header { field: "kind" }
    );
    assert!(matches!(
        read("apiVersion: rdy/v1\nkind: TrustStore\n").unwrap_err(),
        TrustFileError::Invalid { .. }
    ));
}

#[test]
fn a_bad_entry_fails_the_whole_file() {
    let pair = Pair::new();
    let good = entry("acme-platform", &pair.text());
    // A second entry is bad in each way. The first, good entry is never returned on its own.
    let cases: Vec<(String, &str)> = vec![
        (entry("Not A Slug", &pair.text()), "product"),
        (
            format!(
                "  - product: other\n    key: {}\n    added_at: yesterday\n",
                pair.text()
            ),
            "added_at",
        ),
        (
            format!(
                "  - product: other\n    key: {}\n    added_at: {ADDED}\n    note: \"a\\u0007b\"\n",
                pair.text()
            ),
            "control",
        ),
        (
            format!(
                "  - product: other\n    key: {}\n    added_at: {ADDED}\n    note: \"{}\"\n",
                pair.text(),
                "x".repeat(513)
            ),
            "512",
        ),
    ];
    for (bad, what) in cases {
        let error = read(&file(&format!("{good}{bad}"))).expect_err(what);
        match &error {
            TrustFileError::Entry { index: 2, reason } => {
                assert!(reason.contains(what) || what == "product", "{error}");
            }
            other => panic!("{what}: {other:?}"),
        }
    }
}

#[test]
fn malformed_and_weak_keys_are_refused() {
    let pair = Pair::new();
    let good = entry("acme-platform", &pair.text());
    let mut identity = vec![b'E', b'd'];
    identity.extend_from_slice(&[7u8; 8]);
    let mut point = [0u8; 32];
    point[0] = 1;
    identity.extend_from_slice(&point);
    let weak = base64::encode(&identity);
    for (bad, want_weak) in [
        ("not-a-key".to_owned(), false),
        (format!("{} ", pair.text()), false),
        (weak, true),
    ] {
        let error = read(&file(&format!(
            "{good}{}",
            entry("other", &format!("\"{bad}\""))
        )))
        .expect_err("must fail");
        match error {
            TrustFileError::Key { index: 2, source } => {
                assert_eq!(source == SignatureError::WeakKey, want_weak, "{source:?}");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn two_keys_with_one_id_for_one_product_are_refused() {
    // Anyone can make a key with a given id, so a file with two of them cannot say which signed.
    let pair = Pair::new();
    // Same id, different key bytes.
    let impostor = Pair::new();
    let mut bytes = base64::decode(&impostor.text()).expect("base64");
    let genuine = base64::decode(&pair.text()).expect("base64");
    bytes[2..10].copy_from_slice(&genuine[2..10]);
    let forged = base64::encode(&bytes);
    let text = file(&format!(
        "{}{}",
        entry("acme-platform", &pair.text()),
        entry("acme-platform", &forged)
    ));
    assert!(matches!(
        read(&text).unwrap_err(),
        TrustFileError::DuplicateKeyId { .. }
    ));
    // The same key for two products is normal.
    let text = file(&format!(
        "{}{}",
        entry("acme-platform", &pair.text()),
        entry("acme-edge", &pair.text())
    ));
    assert_eq!(read(&text).expect("reads").pins.len(), 2);
}

#[test]
fn yaml_that_a_trust_file_must_not_use_is_refused() {
    let pair = Pair::new();
    let key = pair.text();
    let cases = [
        // anchors and aliases
        format!("apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n  - &a\n    product: acme-platform\n    key: {key}\n    added_at: {ADDED}\n"),
        "apiVersion: &v rdy/v1\nkind: TrustStore\nkeys: []\nnote: *v\n".to_owned(),
        // merge key
        format!("apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n  - <<: {{product: acme-platform}}\n    key: {key}\n    added_at: {ADDED}\n"),
        // a tag
        "apiVersion: rdy/v1\nkind: !custom TrustStore\nkeys: []\n".to_owned(),
        // duplicate key
        "apiVersion: rdy/v1\nkind: TrustStore\nkind: TrustStore\nkeys: []\n".to_owned(),
        // two documents
        "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n---\napiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n".to_owned(),
        // not a map
        "- a\n- b\n".to_owned(),
        String::new(),
    ];
    for text in cases {
        assert!(read(&text).is_err(), "{text}");
    }
}

#[test]
fn deep_nesting_is_refused() {
    let deep = format!(
        "apiVersion: rdy/v1\nkind: TrustStore\nkeys: {}{}\n",
        "[".repeat(40),
        "]".repeat(40)
    );
    assert!(read(&deep).is_err());
}

#[test]
fn the_size_cap_is_exact_and_text_is_checked_before_parsing() {
    let big = vec![b'#'; MAX_TRUST_BYTES + 1];
    assert!(matches!(
        TrustStore::from_yaml(&big, TrustSource::User).unwrap_err(),
        TrustFileError::TooLarge {
            limit: MAX_TRUST_BYTES,
            ..
        }
    ));
    // A comment-only file of exactly the limit is not too large. It is not a trust store either.
    let at_limit = vec![b'#'; MAX_TRUST_BYTES];
    assert!(matches!(
        TrustStore::from_yaml(&at_limit, TrustSource::User).unwrap_err(),
        TrustFileError::Invalid { .. }
    ));
    assert_eq!(
        TrustStore::from_yaml(&[0xFF, 0xFE, b'a'], TrustSource::User).unwrap_err(),
        TrustFileError::NotUtf8
    );
}

#[test]
fn errors_do_not_echo_control_characters() {
    let text = "apiVersion: rdy/v1\nkind: TrustStore\n\"\u{1b}[2Jevil\": 1\nkeys: []\n";
    let error = read(text).expect_err("must fail");
    assert!(!error.to_string().contains('\u{1b}'), "{error:?}");
}

#[test]
fn every_error_has_a_hint() {
    let pair = Pair::new();
    let errors = [
        TrustFileError::TooLarge { size: 1, limit: 1 },
        TrustFileError::NotUtf8,
        TrustFileError::UnknownField {
            key: "x".into(),
            at: None,
        },
        TrustFileError::Invalid {
            reason: "x".into(),
            at: None,
        },
        TrustFileError::Header { field: "kind" },
        TrustFileError::Entry {
            index: 1,
            reason: "x",
        },
        TrustFileError::Key {
            index: 1,
            source: SignatureError::WeakKey,
        },
        TrustFileError::DuplicateKeyId {
            product: slug("acme-platform"),
            key_id: pair.key().key_id(),
        },
    ];
    for error in errors {
        assert!(!error.hint().is_empty(), "{error:?}");
        assert!(!error.to_string().is_empty(), "{error:?}");
    }
}

#[test]
fn a_public_key_round_trips_through_base64() {
    let pair = Pair::new();
    assert_eq!(pair.key().to_base64(), pair.text());
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n";
const COMMENT: &str = "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z";

#[test]
fn the_result_carries_the_fingerprint_and_the_users_note() {
    let pair = Pair::new();
    let text = file(&format!(
        "{}    note: \"read back by phone\"\n",
        entry("acme-platform", &pair.text())
    ));
    let trust = TrustStore::from_yaml(text.as_bytes(), TrustSource::System).expect("reads");
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let loaded = crate::load(
        SPEC.as_bytes(),
        Some(sidecar.as_bytes()),
        &trust,
        Policy::RequireSigned,
    )
    .expect("loads");
    let signature = Signature::from(loaded.signature());
    assert_eq!(signature.state, crate::result::SignatureState::Verified);
    assert_eq!(
        signature.key_fingerprint.as_deref(),
        Some(pair.key().fingerprint().as_str())
    );
    assert_eq!(
        signature.key_id.as_deref(),
        Some(pair.key().key_id().to_string().as_str())
    );
    assert_eq!(signature.product.as_deref(), Some("acme-platform"));
    assert_eq!(signature.signed_at.as_deref(), Some("2026-11-30T16:02:11Z"));
    assert_eq!(signature.trust_note.as_deref(), Some("read back by phone"));
    assert_eq!(
        signature.trust_source,
        Some(crate::result::TrustSource::System)
    );
}

#[test]
fn a_forged_key_with_the_vendors_key_id_fails_against_a_loaded_store() {
    // SEC-61. The attacker copies the vendor's key id into a signature made with their own key.
    let vendor = Pair::new();
    let attacker = Pair::new();
    let text = file(&entry("acme-platform", &vendor.text()));
    let trust = TrustStore::from_yaml(text.as_bytes(), TrustSource::System).expect("reads");
    let signed = attacker.sign(SPEC.as_bytes(), COMMENT);
    let lines: Vec<&str> = signed.lines().collect();
    let mut line = base64::decode(lines[1]).expect("sig line");
    let vendor_bytes = base64::decode(&vendor.text()).expect("key");
    line[2..10].copy_from_slice(&vendor_bytes[2..10]);
    let forged = format!(
        "{}\n{}\n{}\n{}\n",
        lines[0],
        base64::encode(&line),
        lines[2],
        lines[3]
    );
    let error = crate::load(
        SPEC.as_bytes(),
        Some(forged.as_bytes()),
        &trust,
        Policy::RequireSigned,
    )
    .expect_err("a forged key must fail");
    assert!(matches!(
        error,
        crate::SpecError::Signature(SignatureError::Tampered { .. })
    ));
    // The attacker's own key is not in the store, so it is an unknown key.
    let own = crate::load(
        SPEC.as_bytes(),
        Some(signed.as_bytes()),
        &trust,
        Policy::RequireSigned,
    )
    .expect_err("an unpinned key must fail");
    assert!(matches!(
        own,
        crate::SpecError::Signature(SignatureError::UnknownKey { .. })
    ));
}

#[test]
fn an_unsigned_spec_converts_to_an_unsigned_signature() {
    let signature = Signature::from(&SignatureState::Unsigned);
    assert_eq!(signature, Signature::unsigned());
}
