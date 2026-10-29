//! The spec copy in the report folder is the bytes that were verified, under fixed names (SEC-19,
//! ADR 0016 decision 4). This test uses the committed signed fixture and only the public API.

use std::path::PathBuf;

use rdy_engine::output::OutputDir;
use rdy_spec::sig::{Policy, PublicKey, TrustSource, TrustStore};
use rdy_spec::spec::ProductSlug;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/signed")
        .join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

fn trust() -> TrustStore {
    let text = String::from_utf8(fixture("acme-platform.pub")).unwrap_or_default();
    let key = match PublicKey::from_key_file_text(&text) {
        Ok(key) => key,
        Err(e) => panic!("bad key: {e}"),
    };
    let product = match ProductSlug::new("acme-platform") {
        Ok(slug) => slug,
        Err(e) => panic!("bad slug: {e}"),
    };
    let mut store = TrustStore::new();
    store.pin(product, key, TrustSource::User);
    store
}

#[test]
fn a_signed_spec_is_copied_with_its_signature_byte_for_byte() {
    let yaml = fixture("acme-platform.yaml");
    let sig = fixture("acme-platform.yaml.minisig");
    let loaded = rdy_spec::load(&yaml, Some(&sig), &trust(), Policy::RequireSigned).expect("load");

    let parent = tempfile::tempdir().expect("temp dir");
    let out =
        OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z").expect("create");
    let written = out.write_spec(loaded.verified_bytes()).expect("write");

    assert_eq!(
        written,
        [
            out.path().join("spec.yaml"),
            out.path().join("spec.yaml.minisig")
        ]
    );
    assert_eq!(std::fs::read(&written[0]).expect("read"), yaml);
    assert_eq!(std::fs::read(&written[1]).expect("read"), sig);
}

#[test]
fn the_copy_does_not_depend_on_the_file_on_disk_after_verification() {
    // The bytes come from the buffers `load` verified, so a file that changes later cannot change
    // the copy. Here the buffer is the only thing there is: it is built from a local Vec.
    let mut yaml = fixture("acme-platform.yaml");
    let sig = fixture("acme-platform.yaml.minisig");
    let loaded = rdy_spec::load(&yaml, Some(&sig), &trust(), Policy::RequireSigned).expect("load");
    let verified = yaml.clone();
    yaml.extend_from_slice(b"\n# changed after verification\n");

    let parent = tempfile::tempdir().expect("temp dir");
    let out =
        OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z").expect("create");
    let written = out.write_spec(loaded.verified_bytes()).expect("write");
    assert_eq!(std::fs::read(&written[0]).expect("read"), verified);
    assert_ne!(std::fs::read(&written[0]).expect("read"), yaml);
}
