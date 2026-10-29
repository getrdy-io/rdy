//! Signature file tests. The checks that matter are done by other code: `rdy_spec::load` (what a
//! customer's rdy runs) and the stock `minisign` crate (what `minisign -V` runs).

use std::io::Cursor;

use ct_codecs::Decoder;
use rdy_spec::SpecError;
use rdy_spec::sig::{Policy, PublicKey, SignatureError, SignatureState, TrustSource, TrustStore};

use super::*;
use crate::signing::key::KdfCost;

const SPEC: &[u8] = b"apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n";
const SIGNED_AT: &str = "2026-11-30T16:02:11Z";

fn product() -> ProductSlug {
    ProductSlug::new("acme-platform").expect("slug")
}

fn trust(key: &SecretKey) -> TrustStore {
    let mut store = TrustStore::new();
    let public = PublicKey::from_base64(&key.public_key_base64()).expect("public key");
    store.pin(product(), public, TrustSource::User);
    store
}

fn load_with(
    bytes: &[u8],
    sidecar: &str,
    trust: &TrustStore,
) -> Result<rdy_spec::LoadedSpec, SpecError> {
    rdy_spec::load(
        bytes,
        Some(sidecar.as_bytes()),
        trust,
        Policy::RequireSigned,
    )
}

#[test]
fn a_signature_verifies_with_the_loader_a_customer_runs() {
    let key = SecretKey::generate().expect("key");
    let text = sign(&key, &product(), SIGNED_AT, SPEC);
    let loaded = load_with(SPEC, &text, &trust(&key)).expect("verifies");
    match loaded.signature() {
        SignatureState::Verified {
            key_id,
            product: signed_product,
            signed_at,
            trust_source,
            ..
        } => {
            assert_eq!(*key_id, key.key_id());
            assert_eq!(signed_product.to_string(), "acme-platform");
            assert_eq!(signed_at, SIGNED_AT);
            assert_eq!(*trust_source, TrustSource::User);
        }
        other => panic!("not verified: {other:?}"),
    }
}

#[test]
fn the_file_has_four_lines_in_the_documented_form() {
    let key = SecretKey::generate().expect("key");
    let text = sign(&key, &product(), SIGNED_AT, SPEC);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "{text}");
    assert!(text.ends_with('\n'));
    assert_eq!(
        lines[0],
        format!(
            "untrusted comment: rdy spec signature for acme-platform, key {}",
            key.key_id()
        )
    );
    assert_eq!(
        lines[2],
        "trusted comment: rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z"
    );
    let line = Base64::decode_to_vec(lines[1], None).expect("base64");
    assert_eq!(line.len(), 74);
    assert_eq!(&line[..2], b"ED", "prehashed, never the legacy form");
    assert_eq!(&line[2..10], &key.keynum());
    assert_eq!(
        Base64::decode_to_vec(lines[3], None).expect("base64").len(),
        64
    );
}

#[test]
fn stock_minisign_verifies_an_rdy_signature() {
    let key = SecretKey::generate().expect("key");
    let text = sign(&key, &product(), SIGNED_AT, SPEC);
    let public = minisign::PublicKey::from_base64(&key.public_key_base64()).expect("public key");
    let sig = minisign::SignatureBox::from_string(&text).expect("stock crate reads the file");
    // `allow_legacy = false`: the signature must be the prehashed form.
    minisign::verify(&public, &sig, Cursor::new(SPEC), true, false, false)
        .expect("stock minisign verifies");
    // The trusted comment is what rdy signed.
    assert_eq!(
        sig.trusted_comment().expect("trusted comment"),
        format!("rdy-spec-v1 product=acme-platform signed_at={SIGNED_AT}")
    );
    // And it fails on other bytes.
    let mut other = SPEC.to_vec();
    other.push(b'\n');
    assert!(minisign::verify(&public, &sig, Cursor::new(other), true, false, false).is_err());
}

#[test]
fn rdy_verifies_a_signature_stock_minisign_made_with_the_documented_comment() {
    // 01 section 4.5: a spec signed with `minisign -S -t "rdy-spec-v1 product=... signed_at=..."`
    // verifies in rdy.
    let pair = minisign::KeyPair::generate_unencrypted_keypair().expect("stock key pair");
    let comment = format!("rdy-spec-v1 product=acme-platform signed_at={SIGNED_AT}");
    let theirs = minisign::sign(
        Some(&pair.pk),
        &pair.sk,
        Cursor::new(SPEC),
        Some(&comment),
        Some("signed by stock minisign"),
    )
    .expect("stock sign")
    .into_string();
    let mut store = TrustStore::new();
    store.pin(
        product(),
        PublicKey::from_base64(&pair.pk.to_base64()).expect("public key"),
        TrustSource::User,
    );
    load_with(SPEC, &theirs, &store).expect("rdy verifies the stock signature");
}

#[test]
fn signing_is_deterministic() {
    let key = SecretKey::generate().expect("key");
    assert_eq!(
        sign(&key, &product(), SIGNED_AT, SPEC),
        sign(&key, &product(), SIGNED_AT, SPEC)
    );
}

#[test]
fn a_changed_file_comment_or_key_does_not_verify() {
    let key = SecretKey::generate().expect("key");
    let store = trust(&key);
    let text = sign(&key, &product(), SIGNED_AT, SPEC);

    let mut changed = SPEC.to_vec();
    changed[0] ^= 1;
    assert!(matches!(
        load_with(&changed, &text, &store),
        Err(SpecError::Signature(SignatureError::Tampered { .. }))
    ));

    let later = text.replace("signed_at=2026-11-30", "signed_at=2026-12-30");
    assert!(matches!(
        load_with(SPEC, &later, &store),
        Err(SpecError::Signature(SignatureError::CommentTampered))
    ));

    let other = SecretKey::generate().expect("other key");
    assert!(matches!(
        load_with(SPEC, &text, &trust(&other)),
        Err(SpecError::Signature(SignatureError::UnknownKey { .. }))
    ));
}

#[test]
fn a_signature_for_one_product_does_not_verify_a_spec_for_another() {
    let key = SecretKey::generate().expect("key");
    let edge = ProductSlug::new("acme-edge").expect("slug");
    let text = sign(&key, &edge, SIGNED_AT, SPEC);
    let mut store = TrustStore::new();
    store.pin(
        edge,
        PublicKey::from_base64(&key.public_key_base64()).expect("public key"),
        TrustSource::User,
    );
    // The key is pinned for acme-edge, and the spec says acme-platform.
    assert!(matches!(
        load_with(SPEC, &text, &store),
        Err(SpecError::Signature(SignatureError::ProductMismatch { .. }))
    ));
}

#[test]
fn a_key_that_has_been_through_a_key_file_signs_the_same_way() {
    let key = SecretKey::generate().expect("key");
    let file = key
        .key_file(Some("pw"), KdfCost::new(32_768, 1 << 20))
        .expect("key file");
    let reopened = crate::signing::key::StoredKey::parse(&file)
        .expect("parse")
        .unlock(Some("pw"))
        .expect("unlock");
    assert_eq!(
        sign(&key, &product(), SIGNED_AT, SPEC),
        sign(&reopened, &product(), SIGNED_AT, SPEC)
    );
}
