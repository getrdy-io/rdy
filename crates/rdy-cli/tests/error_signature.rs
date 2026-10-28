//! Signature errors reach their own codes, never `spec_invalid` (M1-021, 01 section 4.8).
//!
//! The first test builds every `SignatureError` variant. The second loads the committed signed fixture
//! in `tests/fixtures/signed/` the way `rdy-spec`'s own tests do, so the errors come out of `load`.

use std::path::PathBuf;

use rdy_cli::error::{CliError, ErrorCode};
use rdy_spec::SpecError;
use rdy_spec::sig::{KeyId, Policy, PublicKey, SignatureError, TrustSource, TrustStore};
use rdy_spec::spec::ProductSlug;

fn slug(text: &str) -> ProductSlug {
    match ProductSlug::new(text) {
        Ok(slug) => slug,
        Err(e) => panic!("bad slug: {e}"),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/signed")
        .join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

fn store_for(product: &str) -> TrustStore {
    let text = String::from_utf8(fixture("acme-platform.pub")).unwrap_or_default();
    let Some(line) = text.lines().nth(1) else {
        panic!("the .pub file has no key line");
    };
    let key = match PublicKey::from_base64(line) {
        Ok(key) => key,
        Err(e) => panic!("bad key: {e}"),
    };
    let mut store = TrustStore::new();
    store.pin(slug(product), key, TrustSource::User);
    store
}

fn every_signature_error() -> Vec<(SignatureError, ErrorCode)> {
    use ErrorCode::{SpecKeyUnknown, SpecSignatureInvalid, SpecUnsigned};
    vec![
        (SignatureError::Missing, SpecUnsigned),
        (
            SignatureError::SidecarTooLarge {
                size: 5000,
                limit: 4096,
            },
            SpecSignatureInvalid,
        ),
        (
            SignatureError::Malformed { reason: "x" },
            SpecSignatureInvalid,
        ),
        (SignatureError::LegacyAlgorithm, SpecSignatureInvalid),
        (
            SignatureError::BadComment { reason: "x" },
            SpecSignatureInvalid,
        ),
        (
            SignatureError::UnknownKey {
                key_id: KeyId::from_bytes([1; 8]),
                product: slug("acme-platform"),
            },
            SpecKeyUnknown,
        ),
        (
            SignatureError::Tampered { crlf: false },
            SpecSignatureInvalid,
        ),
        (
            SignatureError::Tampered { crlf: true },
            SpecSignatureInvalid,
        ),
        (SignatureError::CommentTampered, SpecSignatureInvalid),
        (
            SignatureError::ProductMismatch {
                signed: slug("a"),
                spec: slug("b"),
            },
            SpecSignatureInvalid,
        ),
        (SignatureError::BadKey { reason: "x" }, SpecSignatureInvalid),
        (SignatureError::WeakKey, SpecSignatureInvalid),
    ]
}

#[test]
fn every_signature_error_has_its_own_code_a_fix_and_exit_64() {
    for (error, want) in every_signature_error() {
        let cli = CliError::spec("acme-platform.yaml", SpecError::Signature(error.clone()));
        assert_eq!(cli.code(), want, "{error:?}");
        assert_ne!(cli.code(), ErrorCode::SpecInvalid, "{error:?}");
        assert_eq!(cli.exit_code().code(), 64, "{error:?}");
        // The fix is the one that knows the product, not the placeholder.
        assert_eq!(cli.hint(), error.fix(), "{error:?}");
        assert!(!cli.hint().is_empty());
        assert!(!cli.hint().contains("<product>"), "{}", cli.hint());
        // Neither line names a flag that weakens the check.
        let text = cli.render().text();
        assert!(!text.contains("--allow-unsigned"), "{text}");
        assert!(!text.contains("run --key"), "{text}");
        assert_eq!(text.lines().count(), 2, "{text:?}");
    }
}

#[test]
fn an_unknown_key_fix_names_the_product_to_pin() {
    let error = SignatureError::UnknownKey {
        key_id: KeyId::from_bytes([1; 8]),
        product: slug("acme-platform"),
    };
    let cli = CliError::spec("acme-platform.yaml", SpecError::Signature(error));
    assert!(
        cli.hint()
            .contains("rdy trust add acme-platform --key <file>"),
        "{}",
        cli.hint()
    );
}

/// A signature error is not a parse error: no position, and the code is not `spec_parse`.
#[test]
fn a_signature_error_has_no_position() {
    let cli = CliError::spec(
        "acme-platform.yaml",
        SpecError::Signature(SignatureError::Missing),
    );
    let r = cli.render();
    assert_eq!((r.line, r.column), (None, None));
    assert_eq!(r.file.as_deref(), Some("acme-platform.yaml"));
}

fn load_error(spec: &[u8], sig: Option<&[u8]>, store: &TrustStore, policy: Policy) -> CliError {
    match rdy_spec::load(spec, sig, store, policy) {
        Ok(_) => panic!("load must fail"),
        Err(e) => CliError::spec("acme-platform.yaml", e),
    }
}

#[test]
fn errors_from_load_on_the_signed_fixture_map_to_signature_codes() {
    let spec = fixture("acme-platform.yaml");
    let sig = fixture("acme-platform.yaml.minisig");
    let store = store_for("acme-platform");

    // No signature file under the default policy.
    let e = load_error(&spec, None, &store, Policy::RequireSigned);
    assert_eq!(e.code(), ErrorCode::SpecUnsigned);

    // A key pinned for another product.
    let e = load_error(
        &spec,
        Some(&sig),
        &store_for("acme-edge"),
        Policy::RequireSigned,
    );
    assert_eq!(e.code(), ErrorCode::SpecKeyUnknown);

    // One changed byte in the spec.
    let mut tampered = spec.clone();
    tampered.push(b'#');
    let e = load_error(&tampered, Some(&sig), &store, Policy::RequireSigned);
    assert_eq!(e.code(), ErrorCode::SpecSignatureInvalid);
    // A bad signature fails the same way even when unsigned specs are allowed.
    let e = load_error(&tampered, Some(&sig), &store, Policy::AllowUnsigned);
    assert_eq!(e.code(), ErrorCode::SpecSignatureInvalid);

    // A signature file that is not a signature.
    let e = load_error(
        &spec,
        Some(b"not a signature"),
        &store,
        Policy::RequireSigned,
    );
    assert_eq!(e.code(), ErrorCode::SpecSignatureInvalid);

    for e in [
        load_error(&spec, None, &store, Policy::RequireSigned),
        load_error(&tampered, Some(&sig), &store, Policy::RequireSigned),
    ] {
        assert_eq!(e.exit_code().code(), 64);
        assert!(!e.hint().is_empty());
    }
}
