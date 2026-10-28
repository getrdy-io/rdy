//! Tests on the committed signed fixture in `tests/fixtures/signed/`.
//!
//! The key is synthetic. Its secret half was thrown away when the fixture was made, and nothing in the
//! repo can sign with it. To make a new fixture, run
//! `cargo test -p rdy-spec --test signed_fixture -- --ignored regenerate`. It makes a new key pair in
//! memory, signs the spec file as it is, and writes the `.minisig` and `.pub` files.
//!
//! Helpers in this file avoid `unwrap` and `expect` because clippy only allows them inside `#[test]`
//! functions.

use std::io::Cursor;
use std::path::PathBuf;

use rdy_spec::SpecError;
use rdy_spec::sig::{Policy, PublicKey, SignatureError, SignatureState, TrustStore};
use rdy_spec::spec::ProductSlug;

const PRODUCT: &str = "acme-platform";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed")
}

fn read(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

/// The key of the committed `.pub` file: its second line.
fn pinned_key() -> PublicKey {
    let text = String::from_utf8(read("acme-platform.pub")).unwrap_or_default();
    let Some(line) = text.lines().nth(1) else {
        panic!("the .pub file has no key line");
    };
    match PublicKey::from_base64(line) {
        Ok(key) => key,
        Err(e) => panic!("bad key: {e}"),
    }
}

fn slug(text: &str) -> ProductSlug {
    match ProductSlug::new(text) {
        Ok(slug) => slug,
        Err(e) => panic!("bad slug: {e}"),
    }
}

fn store_for(product: &str) -> TrustStore {
    let mut store = TrustStore::new();
    store.pin(slug(product), pinned_key());
    store
}

#[test]
fn the_committed_fixture_verifies_with_its_public_key() {
    let spec = read("acme-platform.yaml");
    let sig = read("acme-platform.yaml.minisig");
    let key = pinned_key();
    let loaded = rdy_spec::load(
        &spec,
        Some(&sig),
        &store_for(PRODUCT),
        Policy::RequireSigned,
    );
    let Ok(loaded) = loaded else {
        panic!("the fixture must verify: {loaded:?}");
    };
    assert_eq!(loaded.spec().metadata.product.as_str(), PRODUCT);
    let SignatureState::Verified {
        key_id,
        fingerprint,
        product,
        signed_at,
        ..
    } = loaded.signature()
    else {
        panic!("expected a verified signature");
    };
    assert_eq!(*key_id, key.key_id());
    assert_eq!(fingerprint, &key.fingerprint());
    assert_eq!(product.as_str(), PRODUCT);
    assert_eq!(signed_at, "2026-10-28T12:00:00Z");
    assert_eq!(loaded.sha256().len(), 64);
}

#[test]
fn the_committed_fixture_fails_for_a_product_the_key_is_not_pinned_for() {
    let spec = read("acme-platform.yaml");
    let sig = read("acme-platform.yaml.minisig");
    let err = rdy_spec::load(
        &spec,
        Some(&sig),
        &store_for("acme-edge"),
        Policy::RequireSigned,
    )
    .unwrap_err();
    assert!(
        matches!(err, SpecError::Signature(SignatureError::UnknownKey { .. })),
        "{err:?}"
    );
}

/// Git must not change the bytes that were signed. On Windows with `core.autocrlf true` a missing
/// `-text` attribute would turn every LF into CR LF and this test would fail.
#[test]
fn the_fixture_files_have_unix_line_endings() {
    for name in [
        "acme-platform.yaml",
        "acme-platform.yaml.minisig",
        "acme-platform.pub",
    ] {
        assert!(!read(name).contains(&b'\r'), "{name} has a CR");
    }
}

#[test]
fn the_fixture_spec_is_the_example_spec() {
    let path = fixture_dir().join("../../../examples/specs/acme-platform.yaml");
    let example = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read the example spec: {e}"),
    };
    // The fixture is a frozen copy. If the example changes on purpose, this test says so and the
    // fixture is regenerated from the new example.
    assert_eq!(
        read("acme-platform.yaml"),
        example,
        "examples/specs/acme-platform.yaml changed. Copy it over the fixture and run the ignored regenerate test"
    );
}

#[test]
#[ignore = "writes the fixture files. See the module docs"]
fn regenerate() {
    let spec = read("acme-platform.yaml");
    let pair = match minisign::KeyPair::generate_unencrypted_keypair() {
        Ok(pair) => pair,
        Err(e) => panic!("cannot make a key: {e}"),
    };
    let comment = format!("rdy-spec-v1 product={PRODUCT} signed_at=2026-10-28T12:00:00Z");
    let sig = match minisign::sign(
        Some(&pair.pk),
        &pair.sk,
        Cursor::new(&spec),
        Some(&comment),
        Some("synthetic test fixture. The secret key was discarded"),
    ) {
        Ok(sig) => sig,
        Err(e) => panic!("cannot sign: {e}"),
    };
    let pub_text = format!(
        "untrusted comment: synthetic test key for rdy-spec fixtures. The secret key was discarded\n{}\n",
        pair.pk.to_base64()
    );
    let write = |name: &str, text: &str| {
        if let Err(e) = std::fs::write(fixture_dir().join(name), text) {
            panic!("cannot write {name}: {e}");
        }
    };
    write("acme-platform.yaml.minisig", &sig.into_string());
    write("acme-platform.pub", &pub_text);
}
