//! Tests for spec signatures.
//!
//! Keys are synthetic and made in each test. Signatures come from the stock `minisign` crate, so every
//! good signature here is one that real minisign tooling would write. The parser spy counts how often the
//! YAML reader started on this thread (threat model INV-01).

use std::io::Cursor;
use std::path::PathBuf;

use proptest::prelude::*;
use sha2::{Digest, Sha256};

use super::*;
use crate::parse::spy;
use crate::{SpecError, load};

const PRODUCT: &str = "acme-platform";
const COMMENT: &str = "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z";

/// A small valid spec for `acme-platform`.
const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n";

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

    /// The key as the verifier sees it.
    fn key(&self) -> PublicKey {
        PublicKey::from_base64(&self.public.to_base64()).expect("public key")
    }

    /// A signature file over `bytes` with the given signed comment.
    fn sign(&self, bytes: &[u8], comment: &str) -> String {
        minisign::sign(
            Some(&self.public),
            &self.secret,
            Cursor::new(bytes),
            Some(comment),
            None,
        )
        .expect("sign")
        .into_string()
    }
}

fn store(entries: &[(&str, &Pair)]) -> TrustStore {
    let mut store = TrustStore::new();
    for (product, pair) in entries {
        store.pin(slug(product), pair.key(), TrustSource::User);
    }
    store
}

/// Runs `load` and counts how often the YAML reader started during the call.
fn run(
    bytes: &[u8],
    sig: Option<&[u8]>,
    trust: &TrustStore,
    policy: Policy,
) -> (Result<crate::LoadedSpec, SpecError>, usize) {
    let before = spy::calls();
    let result = load(bytes, sig, trust, policy);
    (result, spy::calls() - before)
}

/// The signature error inside a failed load.
fn sig_error(result: Result<crate::LoadedSpec, SpecError>) -> SignatureError {
    match result {
        Err(SpecError::Signature(e)) => e,
        other => panic!("expected a signature error, got {other:?}"),
    }
}

/// Edits the three binary parts of a sidecar: the 74-byte signature line and the 64-byte global one.
fn edit_sidecar(sidecar: &str, edit: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>)) -> String {
    let lines: Vec<&str> = sidecar.lines().collect();
    let mut line = base64::decode(lines[1]).expect("sig line");
    let mut global = base64::decode(lines[3]).expect("global line");
    edit(&mut line, &mut global);
    format!(
        "{}\n{}\n{}\n{}\n",
        lines[0],
        base64::encode(&line),
        lines[2],
        base64::encode(&global)
    )
}

#[test]
fn a_good_signature_verifies_and_records_its_provenance() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(sidecar.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    let loaded = result.expect("must load");
    assert_eq!(parses, 1);
    assert_eq!(loaded.spec().metadata.product.as_str(), PRODUCT);
    assert_eq!(
        loaded.signature(),
        &SignatureState::Verified {
            key_id: pair.key().key_id(),
            fingerprint: pair.key().fingerprint(),
            product: slug(PRODUCT),
            signed_at: "2026-11-30T16:02:11Z".to_owned(),
            trust_source: TrustSource::User,
        }
    );
    assert_eq!(loaded.sha256(), hex(&Sha256::digest(SPEC.as_bytes())));
}

#[test]
fn the_policy_does_not_change_a_good_signature() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    for policy in [Policy::RequireSigned, Policy::AllowUnsigned] {
        let (result, _) = run(
            SPEC.as_bytes(),
            Some(sidecar.as_bytes()),
            &store(&[(PRODUCT, &pair)]),
            policy,
        );
        assert!(matches!(
            result.expect("loads").signature(),
            SignatureState::Verified { .. }
        ));
    }
}

#[test]
fn a_changed_byte_is_tampered_and_the_parser_never_runs() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let mut bytes = SPEC.as_bytes().to_vec();
    let at = SPEC.find("min: 8").expect("text") + 5;
    bytes[at] = b'1';
    assert_ne!(bytes, SPEC.as_bytes());
    for policy in [Policy::RequireSigned, Policy::AllowUnsigned] {
        let (result, parses) = run(
            &bytes,
            Some(sidecar.as_bytes()),
            &store(&[(PRODUCT, &pair)]),
            policy,
        );
        assert_eq!(sig_error(result), SignatureError::Tampered { crlf: false });
        assert_eq!(parses, 0);
    }
}

#[test]
fn windows_line_endings_are_tampered_and_the_error_says_so() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let crlf = SPEC.replace('\n', "\r\n");
    let (result, parses) = run(
        crlf.as_bytes(),
        Some(sidecar.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    let error = sig_error(result);
    assert_eq!(error, SignatureError::Tampered { crlf: true });
    assert!(
        error.to_string().contains("Windows line endings"),
        "{error}"
    );
    assert_eq!(parses, 0);
}

#[test]
fn a_changed_comment_is_comment_tampered() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    // Same form, different time. The signature over the comment no longer matches.
    let edited = sidecar.replace("2026-11-30T16:02:11Z", "2026-11-30T16:02:12Z");
    assert_ne!(edited, sidecar);
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(edited.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    assert_eq!(sig_error(result), SignatureError::CommentTampered);
    assert_eq!(parses, 0);
}

#[test]
fn a_comment_moved_to_another_product_is_comment_tampered_not_a_mismatch() {
    // The attacker keeps the real signature and edits the product in the comment to one that the
    // victim pinned. The key is pinned for both. Only the signature over the comment catches it.
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let edited = sidecar.replace("product=acme-platform", "product=acme-edge");
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(edited.as_bytes()),
        &store(&[(PRODUCT, &pair), ("acme-edge", &pair)]),
        Policy::RequireSigned,
    );
    assert_eq!(sig_error(result), SignatureError::CommentTampered);
    assert_eq!(parses, 0);
}

#[test]
fn a_legacy_signature_is_refused_by_its_form() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let legacy = edit_sidecar(&sidecar, |line, _| line[..2].copy_from_slice(b"Ed"));
    for policy in [Policy::RequireSigned, Policy::AllowUnsigned] {
        let (result, parses) = run(
            SPEC.as_bytes(),
            Some(legacy.as_bytes()),
            &store(&[(PRODUCT, &pair)]),
            policy,
        );
        assert_eq!(sig_error(result), SignatureError::LegacyAlgorithm);
        assert_eq!(parses, 0);
    }
    // Any other algorithm is a malformed signature.
    let other = edit_sidecar(&sidecar, |line, _| line[..2].copy_from_slice(b"XX"));
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(other.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    assert!(matches!(
        sig_error(result),
        SignatureError::Malformed { .. }
    ));
}

#[test]
fn a_signed_comment_that_is_not_the_exact_form_is_refused() {
    let pair = Pair::new();
    let trust = store(&[(PRODUCT, &pair), ("acme-edge", &pair)]);
    let bad_comments = [
        // Minisign's own default comment: no prefix.
        "timestamp:1700000000\tfile:acme-platform.yaml",
        "product=acme-platform signed_at=2026-11-30T16:02:11Z",
        // The prefix with another version, another case or no space after it.
        "rdy-spec-v2 product=acme-platform signed_at=2026-11-30T16:02:11Z",
        "RDY-SPEC-V1 product=acme-platform signed_at=2026-11-30T16:02:11Z",
        "rdy-spec-v1product=acme-platform signed_at=2026-11-30T16:02:11Z",
        "xrdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z",
        // Missing and misordered fields, extra text, odd spacing.
        "rdy-spec-v1",
        "rdy-spec-v1 product=acme-platform",
        "rdy-spec-v1 signed_at=2026-11-30T16:02:11Z product=acme-platform",
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z extra=1",
        "rdy-spec-v1  product=acme-platform signed_at=2026-11-30T16:02:11Z",
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z ",
        "rdy-spec-v1 product=acme-platform\tsigned_at=2026-11-30T16:02:11Z",
        // A bad product.
        "rdy-spec-v1 product=Acme-Platform signed_at=2026-11-30T16:02:11Z",
        "rdy-spec-v1 product= signed_at=2026-11-30T16:02:11Z",
        "rdy-spec-v1 product=-acme signed_at=2026-11-30T16:02:11Z",
        "rdy-spec-v1 product=acme_platform signed_at=2026-11-30T16:02:11Z",
        // A bad time.
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11+00:00",
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30 16:02:11Z",
        "rdy-spec-v1 product=acme-platform signed_at=2026-13-30T16:02:11Z",
        "rdy-spec-v1 product=acme-platform signed_at=2026-02-29T16:02:11Z",
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T24:02:11Z",
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11.5Z",
        "rdy-spec-v1 product=acme-platform signed_at=2026-11-30t16:02:11z",
        "rdy-spec-v1 product=acme-platform signed_at=",
    ];
    for comment in bad_comments {
        let sidecar = pair.sign(SPEC.as_bytes(), comment);
        let (result, parses) = run(
            SPEC.as_bytes(),
            Some(sidecar.as_bytes()),
            &trust,
            Policy::RequireSigned,
        );
        assert!(
            matches!(sig_error(result), SignatureError::BadComment { .. }),
            "{comment:?}"
        );
        assert_eq!(parses, 0, "{comment:?}");
    }
}

#[test]
fn leap_day_and_the_edges_of_a_day_are_good_times() {
    for ok in [
        "2024-02-29T00:00:00Z",
        "2000-02-29T23:59:59Z",
        "2026-12-31T23:59:59Z",
        "2026-01-01T00:00:00Z",
    ] {
        assert!(valid_timestamp(ok), "{ok}");
    }
    for bad in [
        "1900-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-01-00T00:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
    ] {
        assert!(!valid_timestamp(bad), "{bad}");
    }
}

#[test]
fn a_key_nobody_pinned_is_unknown() {
    let signer = Pair::new();
    let other = Pair::new();
    let sidecar = signer.sign(SPEC.as_bytes(), COMMENT);
    for trust in [TrustStore::new(), store(&[(PRODUCT, &other)])] {
        for policy in [Policy::RequireSigned, Policy::AllowUnsigned] {
            let (result, parses) = run(SPEC.as_bytes(), Some(sidecar.as_bytes()), &trust, policy);
            assert_eq!(
                sig_error(result),
                SignatureError::UnknownKey {
                    key_id: signer.key().key_id(),
                    product: slug(PRODUCT),
                }
            );
            assert_eq!(parses, 0);
        }
    }
}

#[test]
fn a_key_pinned_for_another_product_is_unknown() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(sidecar.as_bytes()),
        &store(&[("acme-edge", &pair)]),
        Policy::RequireSigned,
    );
    let error = sig_error(result);
    assert!(
        matches!(error, SignatureError::UnknownKey { .. }),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("not trusted for acme-platform"),
        "{error}"
    );
    assert_eq!(parses, 0);
}

#[test]
fn a_wrong_key_with_the_right_key_id_does_not_verify() {
    // Key ids are random bytes anyone can copy. The attacker signs with their own key and writes the
    // pinned key's id into the signature. Preselection finds the pinned key, and the math rejects it.
    let pinned = Pair::new();
    let attacker = Pair::new();
    let forged = edit_sidecar(&attacker.sign(SPEC.as_bytes(), COMMENT), |line, _| {
        line[2..10].copy_from_slice(&pinned.public.to_bytes()[2..10]);
    });
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(forged.as_bytes()),
        &store(&[(PRODUCT, &pinned)]),
        Policy::RequireSigned,
    );
    assert_eq!(sig_error(result), SignatureError::Tampered { crlf: false });
    assert_eq!(parses, 0);
}

#[test]
fn the_trust_source_of_the_key_that_verified_is_recorded() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    for source in [TrustSource::System, TrustSource::User, TrustSource::Flag] {
        let mut trust = TrustStore::new();
        trust.pin(slug(PRODUCT), pair.key(), source);
        let (result, _) = run(
            SPEC.as_bytes(),
            Some(sidecar.as_bytes()),
            &trust,
            Policy::RequireSigned,
        );
        let loaded = result.expect("loads");
        let SignatureState::Verified { trust_source, .. } = loaded.signature() else {
            panic!("expected a verified signature");
        };
        assert_eq!(*trust_source, source);
    }
}

#[test]
fn one_key_pinned_from_several_places_reports_the_strongest() {
    let pair = Pair::new();
    let sidecar = pair.sign(SPEC.as_bytes(), COMMENT);
    use TrustSource::{Flag, System, User};
    for order in [
        [Flag, User, System],
        [System, User, Flag],
        [User, Flag, System],
        [Flag, System, User],
    ] {
        let mut trust = TrustStore::new();
        for source in order {
            trust.pin(slug(PRODUCT), pair.key(), source);
        }
        let (result, _) = run(
            SPEC.as_bytes(),
            Some(sidecar.as_bytes()),
            &trust,
            Policy::RequireSigned,
        );
        let loaded = result.expect("loads");
        let SignatureState::Verified { trust_source, .. } = loaded.signature() else {
            panic!("expected a verified signature");
        };
        assert_eq!(*trust_source, System, "{order:?}");
    }
    let mut trust = TrustStore::new();
    trust.pin(slug(PRODUCT), pair.key(), Flag);
    trust.pin(slug(PRODUCT), pair.key(), User);
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(sidecar.as_bytes()),
        &trust,
        Policy::RequireSigned,
    );
    let loaded = result.expect("loads");
    assert!(matches!(
        loaded.signature(),
        SignatureState::Verified {
            trust_source: User,
            ..
        }
    ));
}

#[test]
fn an_unknown_key_fix_names_the_product_to_pin() {
    let error = SignatureError::UnknownKey {
        key_id: KeyId::from_bytes([1; 8]),
        product: slug(PRODUCT),
    };
    assert!(
        error
            .fix()
            .ends_with("rdy trust add acme-platform --key <file>"),
        "{}",
        error.fix()
    );
    assert!(
        error
            .hint()
            .contains("rdy trust add <product> --key <file>")
    );
    assert_eq!(SpecError::from(error.clone()).fix(), error.fix());
    assert_eq!(
        SignatureError::Missing.fix(),
        SignatureError::Missing.hint()
    );
}

#[test]
fn the_right_key_among_several_pins_is_found() {
    let first = Pair::new();
    let second = Pair::new();
    let sidecar = second.sign(SPEC.as_bytes(), COMMENT);
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(sidecar.as_bytes()),
        &store(&[(PRODUCT, &first), (PRODUCT, &second), ("acme-edge", &first)]),
        Policy::RequireSigned,
    );
    let loaded = result.expect("loads");
    let SignatureState::Verified { fingerprint, .. } = loaded.signature() else {
        panic!("expected a verified signature");
    };
    assert_eq!(fingerprint, &second.key().fingerprint());
}

#[test]
fn a_product_mismatch_is_refused_after_the_signature_verified() {
    let pair = Pair::new();
    let signed_for_edge = "rdy-spec-v1 product=acme-edge signed_at=2026-11-30T16:02:11Z";
    let sidecar = pair.sign(SPEC.as_bytes(), signed_for_edge);
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(sidecar.as_bytes()),
        &store(&[("acme-edge", &pair)]),
        Policy::RequireSigned,
    );
    let error = sig_error(result);
    assert_eq!(
        error,
        SignatureError::ProductMismatch {
            signed: slug("acme-edge"),
            spec: slug(PRODUCT),
        }
    );
    assert_eq!(
        error.to_string(),
        "the spec is signed for product 'acme-edge', but it says 'acme-platform'"
    );
    // The bytes were verified, so reading them to find the product is allowed.
    assert_eq!(parses, 1);
}

#[test]
fn a_missing_signature_follows_the_policy() {
    let trust = TrustStore::new();
    let (result, parses) = run(SPEC.as_bytes(), None, &trust, Policy::RequireSigned);
    assert_eq!(sig_error(result), SignatureError::Missing);
    assert_eq!(parses, 0);

    let (result, parses) = run(SPEC.as_bytes(), None, &trust, Policy::AllowUnsigned);
    let loaded = result.expect("unsigned is allowed");
    assert_eq!(loaded.signature(), &SignatureState::Unsigned);
    assert_eq!(parses, 1);
    assert_eq!(loaded.sha256(), hex(&Sha256::digest(SPEC.as_bytes())));
}

#[test]
fn an_unsigned_spec_that_does_not_parse_is_still_an_error() {
    let (result, parses) = run(
        b"not: [a spec",
        None,
        &TrustStore::new(),
        Policy::AllowUnsigned,
    );
    assert!(result.is_err());
    assert_eq!(parses, 1);
}

#[test]
fn a_signature_that_is_present_but_empty_is_not_a_missing_signature() {
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(b""),
        &TrustStore::new(),
        Policy::AllowUnsigned,
    );
    assert!(matches!(
        sig_error(result),
        SignatureError::Malformed { .. }
    ));
    assert_eq!(parses, 0);
}

#[test]
fn malformed_signature_files_are_refused() {
    let pair = Pair::new();
    let good = pair.sign(SPEC.as_bytes(), COMMENT);
    let lines: Vec<&str> = good.lines().collect();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", b"hello".to_vec()),
        ("not utf-8", vec![0xFF, 0xFE, 0x00, b'\n', 0x80]),
        ("three lines", lines[..3].join("\n").into_bytes()),
        ("five lines", format!("{good}extra\n").into_bytes()),
        ("blank line at the end", format!("{good}\n").into_bytes()),
        (
            "no untrusted label",
            format!("comment\n{}\n{}\n{}\n", lines[1], lines[2], lines[3]).into_bytes(),
        ),
        (
            "no trusted label",
            format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], COMMENT, lines[3]).into_bytes(),
        ),
        (
            "signature not base64",
            format!("{}\n!!!!\n{}\n{}\n", lines[0], lines[2], lines[3]).into_bytes(),
        ),
        (
            "signature too short",
            format!(
                "{}\n{}\n{}\n{}\n",
                lines[0],
                base64::encode(&[b'E', b'D', 1, 2, 3]),
                lines[2],
                lines[3]
            )
            .into_bytes(),
        ),
        (
            "global signature too short",
            format!(
                "{}\n{}\n{}\n{}\n",
                lines[0],
                lines[1],
                lines[2],
                base64::encode(&[1, 2, 3])
            )
            .into_bytes(),
        ),
        (
            "global signature not base64",
            format!("{}\n{}\n{}\nx\n", lines[0], lines[1], lines[2]).into_bytes(),
        ),
        (
            "signature line with a trailing space",
            format!("{}\n{} \n{}\n{}\n", lines[0], lines[1], lines[2], lines[3]).into_bytes(),
        ),
        (
            "signature line with a stray byte",
            format!("{}\n{}!\n{}\n{}\n", lines[0], lines[1], lines[2], lines[3]).into_bytes(),
        ),
    ];
    for (name, sidecar) in cases {
        let (result, parses) = run(
            SPEC.as_bytes(),
            Some(&sidecar),
            &store(&[(PRODUCT, &pair)]),
            Policy::AllowUnsigned,
        );
        assert!(
            matches!(sig_error(result), SignatureError::Malformed { .. }),
            "{name}"
        );
        assert_eq!(parses, 0, "{name}");
    }
}

#[test]
fn signature_files_with_windows_line_endings_or_no_final_newline_still_verify() {
    // Only the line breaks of the signature file change. The signed bytes and the comment do not.
    let pair = Pair::new();
    let good = pair.sign(SPEC.as_bytes(), COMMENT);
    for variant in [good.replace('\n', "\r\n"), good.trim_end().to_owned()] {
        let (result, _) = run(
            SPEC.as_bytes(),
            Some(variant.as_bytes()),
            &store(&[(PRODUCT, &pair)]),
            Policy::RequireSigned,
        );
        assert!(result.is_ok(), "{variant:?}");
    }
}

#[test]
fn an_oversized_signature_file_is_refused_before_it_is_read() {
    let pair = Pair::new();
    let big = vec![b'a'; MAX_SIGNATURE_BYTES + 1];
    let (result, parses) = run(
        SPEC.as_bytes(),
        Some(&big),
        &store(&[(PRODUCT, &pair)]),
        Policy::AllowUnsigned,
    );
    assert_eq!(
        sig_error(result),
        SignatureError::SidecarTooLarge {
            size: MAX_SIGNATURE_BYTES + 1,
            limit: MAX_SIGNATURE_BYTES,
        }
    );
    assert_eq!(parses, 0);
    // The limit itself is not too large. This one is just garbage.
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(&big[..MAX_SIGNATURE_BYTES]),
        &TrustStore::new(),
        Policy::AllowUnsigned,
    );
    assert!(matches!(
        sig_error(result),
        SignatureError::Malformed { .. }
    ));
}

#[test]
fn an_oversized_spec_is_refused_under_every_policy_before_anything_else() {
    let pair = Pair::new();
    let mut big = SPEC.as_bytes().to_vec();
    big.resize(crate::MAX_SPEC_BYTES + 1, b'#');
    let sidecar = pair.sign(&big, COMMENT);
    for (sig, policy) in [
        (Some(sidecar.as_bytes()), Policy::RequireSigned),
        (Some(sidecar.as_bytes()), Policy::AllowUnsigned),
        (None, Policy::RequireSigned),
        (None, Policy::AllowUnsigned),
    ] {
        let (result, parses) = run(&big, sig, &store(&[(PRODUCT, &pair)]), policy);
        assert_eq!(
            result.unwrap_err(),
            SpecError::TooLarge {
                size: crate::MAX_SPEC_BYTES + 1,
                limit: crate::MAX_SPEC_BYTES,
            }
        );
        assert_eq!(parses, 0);
    }
}

#[test]
fn a_spec_of_exactly_the_limit_can_verify() {
    let pair = Pair::new();
    let mut big = SPEC.as_bytes().to_vec();
    big.resize(crate::MAX_SPEC_BYTES, b'#');
    big.pop();
    big.push(b'\n');
    let sidecar = pair.sign(&big, COMMENT);
    let (result, _) = run(
        &big,
        Some(sidecar.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    assert!(result.is_ok(), "{result:?}");
}

/// Adding the group order L to S makes a second encoding of the same signature. A strict verifier
/// refuses it. Minisign-style envelopes make this matter twice: for the file and for the comment.
#[test]
fn malleable_signatures_are_refused() {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    fn add_l(s: &mut [u8]) {
        let mut carry = 0u16;
        for (byte, l) in s.iter_mut().zip(L) {
            let sum = u16::from(*byte) + u16::from(l) + carry;
            *byte = u8::try_from(sum & 0xFF).expect("byte");
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + L must fit in 32 bytes");
    }
    let pair = Pair::new();
    let good = pair.sign(SPEC.as_bytes(), COMMENT);
    let on_file = edit_sidecar(&good, |line, _| add_l(&mut line[42..74]));
    let on_comment = edit_sidecar(&good, |_, global| add_l(&mut global[32..64]));
    for (name, sidecar, expected) in [
        ("file", on_file, SignatureError::Tampered { crlf: false }),
        ("comment", on_comment, SignatureError::CommentTampered),
    ] {
        assert_ne!(sidecar, good);
        let (result, parses) = run(
            SPEC.as_bytes(),
            Some(sidecar.as_bytes()),
            &store(&[(PRODUCT, &pair)]),
            Policy::RequireSigned,
        );
        assert_eq!(sig_error(result), expected, "{name}");
        assert_eq!(parses, 0, "{name}");
    }
}

#[test]
fn swapping_the_two_signatures_or_reusing_another_files_signature_fails() {
    let pair = Pair::new();
    let good = pair.sign(SPEC.as_bytes(), COMMENT);
    let swapped = edit_sidecar(&good, |line, global| {
        let file_sig = line[10..74].to_vec();
        line[10..74].copy_from_slice(global);
        global.copy_from_slice(&file_sig);
    });
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(swapped.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    assert_eq!(sig_error(result), SignatureError::Tampered { crlf: false });
    // A good signature for a different file.
    let other = pair.sign(b"apiVersion: rdy/v1\n", COMMENT);
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(other.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    assert_eq!(sig_error(result), SignatureError::Tampered { crlf: false });
}

#[test]
fn the_untrusted_comment_is_never_read() {
    let pair = Pair::new();
    let good = pair.sign(SPEC.as_bytes(), COMMENT);
    let lines: Vec<&str> = good.lines().collect();
    let edited = format!(
        "untrusted comment: product=acme-edge, pinned by the vendor, trust me\n{}\n{}\n{}\n",
        lines[1], lines[2], lines[3]
    );
    let (result, _) = run(
        SPEC.as_bytes(),
        Some(edited.as_bytes()),
        &store(&[(PRODUCT, &pair)]),
        Policy::RequireSigned,
    );
    assert!(result.is_ok());
}

#[test]
fn no_error_message_or_hint_names_the_flags_that_weaken_the_check() {
    let all = [
        SignatureError::Missing,
        SignatureError::SidecarTooLarge {
            size: 5000,
            limit: 4096,
        },
        SignatureError::Malformed { reason: "x" },
        SignatureError::LegacyAlgorithm,
        SignatureError::BadComment { reason: "x" },
        SignatureError::UnknownKey {
            key_id: KeyId::from_bytes([1; 8]),
            product: slug(PRODUCT),
        },
        SignatureError::Tampered { crlf: false },
        SignatureError::Tampered { crlf: true },
        SignatureError::CommentTampered,
        SignatureError::ProductMismatch {
            signed: slug("a"),
            spec: slug("b"),
        },
        SignatureError::BadKey { reason: "x" },
        SignatureError::WeakKey,
    ];
    for error in all {
        for text in [error.to_string(), error.hint().to_owned()] {
            assert!(!text.is_empty());
            assert!(!text.contains("--allow-unsigned"), "{text}");
            assert!(!text.contains("rdy run --key"), "{text}");
            assert!(!text.contains("--trust-key"), "{text}");
            assert!(!text.contains("allow_unsigned"), "{text}");
        }
        let wrapped = SpecError::from(error.clone());
        assert_eq!(wrapped.hint(), error.hint());
        assert_eq!(wrapped.to_string(), error.to_string());
    }
}

#[test]
fn only_a_missing_signature_hint_points_at_the_unsigned_docs() {
    assert!(
        SignatureError::Missing
            .hint()
            .contains("https://docs.getrdy.io/unsigned")
    );
    assert!(
        !SignatureError::Tampered { crlf: false }
            .hint()
            .contains("unsigned")
    );
    assert!(
        SignatureError::Tampered { crlf: false }
            .hint()
            .contains("Do not run this file")
    );
}

// Wycheproof (C2SP/wycheproof, testvectors_v1/ed25519_test.json). Every vector runs through the same
// key parser and strict verifier that `load` uses.

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn wycheproof_ed25519_vectors() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/wycheproof/ed25519_test.json");
    let text = std::fs::read_to_string(&path).expect("vector file");
    let file: serde_json::Value = serde_json::from_str(&text).expect("json");
    let mut ran = 0usize;
    let mut valid_checked = 0usize;
    let mut invalid_refused = 0usize;
    for group in file["testGroups"].as_array().expect("groups") {
        let pk = from_hex(group["publicKey"]["pk"].as_str().expect("pk"));
        for case in group["tests"].as_array().expect("tests") {
            let id = case["tcId"].as_u64().expect("id");
            let msg = from_hex(case["msg"].as_str().expect("msg"));
            let sig = from_hex(case["sig"].as_str().expect("sig"));
            // A signature of the wrong length can never verify.
            let accepted = match (<[u8; 32]>::try_from(pk.clone()), <[u8; 64]>::try_from(sig)) {
                (Ok(pk), Ok(sig)) => {
                    key::parse_verifying_key(&pk).is_ok_and(|key| ed25519_verify(&key, &msg, &sig))
                }
                _ => false,
            };
            match case["result"].as_str().expect("result") {
                "valid" => {
                    assert!(accepted, "tcId {id} is valid and was refused");
                    valid_checked += 1;
                }
                "invalid" => {
                    assert!(!accepted, "tcId {id} is invalid and was accepted");
                    invalid_refused += 1;
                }
                // The vectors that real implementations disagree on. Either answer is fine.
                "acceptable" => {}
                other => panic!("unknown result {other}"),
            }
            ran += 1;
        }
    }
    assert_eq!(ran, 210);
    assert_eq!(valid_checked, 117);
    assert_eq!(invalid_refused, 64);
}

/// Strictness beyond the "acceptable" slack: the vectors that real libraries wrongly accept.
#[test]
fn wycheproof_small_order_and_malleable_vectors_are_all_refused() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/wycheproof/ed25519_test.json");
    let text = std::fs::read_to_string(&path).expect("vector file");
    let file: serde_json::Value = serde_json::from_str(&text).expect("json");
    let mut strict_cases = 0usize;
    for group in file["testGroups"].as_array().expect("groups") {
        let pk = <[u8; 32]>::try_from(from_hex(group["publicKey"]["pk"].as_str().expect("pk")))
            .expect("32 bytes");
        for case in group["tests"].as_array().expect("tests") {
            let flags: Vec<&str> = case["flags"]
                .as_array()
                .expect("flags")
                .iter()
                .filter_map(|f| f.as_str())
                .collect();
            if !flags
                .iter()
                .any(|f| matches!(*f, "SignatureMalleability" | "SmallOrderPublicKey"))
            {
                continue;
            }
            let msg = from_hex(case["msg"].as_str().expect("msg"));
            let Ok(sig) = <[u8; 64]>::try_from(from_hex(case["sig"].as_str().expect("sig"))) else {
                continue;
            };
            let accepted =
                key::parse_verifying_key(&pk).is_ok_and(|key| ed25519_verify(&key, &msg, &sig));
            assert!(!accepted, "tcId {} {flags:?} was accepted", case["tcId"]);
            strict_cases += 1;
        }
    }
    assert!(strict_cases >= 16, "{strict_cases}");
}

// The committed fixture, mutated.

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/signed")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn fixture_trust() -> TrustStore {
    let pub_file = String::from_utf8(fixture("acme-platform.pub")).expect("utf-8");
    let key = PublicKey::from_base64(pub_file.lines().nth(1).expect("key line")).expect("key");
    let mut trust = TrustStore::new();
    trust.pin(slug(PRODUCT), key, TrustSource::System);
    trust
}

#[test]
fn the_unmodified_fixture_verifies() {
    let (result, parses) = run(
        &fixture("acme-platform.yaml"),
        Some(&fixture("acme-platform.yaml.minisig")),
        &fixture_trust(),
        Policy::RequireSigned,
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(parses, 1);
}

/// The settings of the property tests (08 section 4): 256 cases, a fixed seed so an unrelated PR never
/// fails on a fresh draw (`PROPTEST_RNG_SEED` replaces it), and shrinking that ends before nextest's
/// kill. A failure is saved under `proptest-regressions/` in this crate, and that file is committed.
fn property_config() -> ProptestConfig {
    use proptest::test_runner::RngSeed;
    let mut config = ProptestConfig::with_cases(256);
    config.max_shrink_time = 30_000;
    if config.rng_seed == RngSeed::Random {
        // The bytes of `rdy_spec`, the same seed as `tests/parse_properties.rs`.
        config.rng_seed = RngSeed::Fixed(0x7264_795F_7370_6563);
    }
    config
}

proptest! {
    #![proptest_config(property_config())]

    /// Any change to the signed bytes, whether a changed byte, a cut or an addition, is a signature
    /// error, and the parser spy stays at zero.
    #[test]
    fn any_change_to_the_signed_fixture_is_a_signature_error(
        index in 0usize..1988,
        replacement in any::<u8>(),
        extra in proptest::collection::vec(any::<u8>(), 1..8),
        kind in 0u8..3,
    ) {
        let original = fixture("acme-platform.yaml");
        let sidecar = fixture("acme-platform.yaml.minisig");
        let index = index % original.len();
        let mut changed = original.clone();
        match kind {
            0 => {
                // Change one byte to a different value.
                changed[index] = if replacement == original[index] {
                    replacement ^ 0x01
                } else {
                    replacement
                };
            }
            1 => changed.truncate(index),
            _ => {
                changed.extend_from_slice(&extra);
            }
        }
        prop_assert_ne!(&changed, &original);
        let (result, parses) = run(&changed, Some(&sidecar), &fixture_trust(), Policy::RequireSigned);
        prop_assert!(
            matches!(result, Err(SpecError::Signature(SignatureError::Tampered { .. }))),
            "{:?}",
            result
        );
        prop_assert_eq!(parses, 0);
    }
}
