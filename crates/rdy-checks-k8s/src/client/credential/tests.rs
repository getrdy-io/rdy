//! Tests of the credential facts: the `exp` claim, the certificate `notAfter`, and what they refuse.

use rcgen::{CertificateParams, KeyPair, date_time_ymd};

use super::*;

/// 2026-10-30 00:00:00 UTC.
const NOW: i64 = 1_793_318_400;
const DAY: i64 = 86_400;

/// A token with these claims. The payload is base64url by hand: the test must not use the decoder it
/// checks.
fn jwt(claims: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let url = |text: &str| {
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| {
                acc | (u32::from(*b) << (16 - 8 * u32::try_from(i).expect("small")))
            });
            for i in 0..=chunk.len() {
                let index =
                    usize::try_from((n >> (18 - 6 * u32::try_from(i).expect("small"))) & 63)
                        .expect("six bits");
                out.push(char::from(ALPHABET[index]));
            }
        }
        out
    };
    format!("{}.{}.sig", url(r#"{"alg":"RS256"}"#), url(claims))
}

fn cert_pem(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> String {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["admin.acme.example".to_owned()]).expect("params");
    params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
    params.self_signed(&key).expect("cert").pem()
}

#[test]
fn a_jwt_exp_is_the_time_left() {
    let token = jwt(&format!(r#"{{"sub":"u","exp":{}}}"#, NOW + 3 * DAY));
    assert_eq!(token_expires_in(&token, NOW), Some(3 * DAY));
}

#[test]
fn an_expired_jwt_has_a_negative_time_left() {
    let token = jwt(&format!(r#"{{"exp":{}}}"#, NOW - 10));
    assert_eq!(token_expires_in(&token, NOW), Some(-10));
}

#[test]
fn a_float_exp_counts_in_whole_seconds() {
    let token = jwt(&format!(r#"{{"exp":{}.5}}"#, NOW + 100));
    assert_eq!(token_expires_in(&token, NOW), Some(100));
}

#[test]
fn a_token_that_is_not_a_jwt_with_an_exp_has_no_known_end() {
    let no_exp = jwt(r#"{"sub":"u"}"#);
    let text_exp = jwt(r#"{"exp":"tomorrow"}"#);
    let array = jwt("[1,2]");
    let not_json = jwt("not json");
    for token in [
        "plain-opaque-token",
        "a.b",
        "a.b.c.d",
        "..",
        "sha256~abcdef",
        &no_exp,
        &text_exp,
        &array,
        &not_json,
        "eyJhbGciOiJSUzI1NiJ9.!!!.sig",
    ] {
        assert_eq!(token_expires_in(token, NOW), None, "{token}");
    }
    let huge = format!("a.{}.c", "A".repeat(MAX_TOKEN_BYTES));
    assert_eq!(token_expires_in(&huge, NOW), None);
}

#[test]
fn a_huge_exp_does_not_overflow() {
    let token = jwt(&format!(r#"{{"exp":{}}}"#, i64::MAX));
    assert_eq!(token_expires_in(&token, i64::MIN), None);
    assert_eq!(token_expires_in(&token, NOW), Some(i64::MAX - NOW));
}

#[test]
fn a_certificate_not_after_is_read_from_its_der() {
    let pem = cert_pem((2024, 1, 1), (2030, 3, 15));
    let want = days_from_civil(2030, 3, 15) * DAY;
    assert_eq!(certificate_expires_in(&pem, NOW), Some(want - NOW));
}

#[test]
fn an_expired_certificate_has_a_negative_time_left() {
    let pem = cert_pem((2020, 1, 1), (2021, 6, 30));
    let left = certificate_expires_in(&pem, NOW).expect("a date");
    assert!(left < -(4 * 365 * DAY), "{left}");
}

#[test]
fn a_date_past_2049_uses_the_generalized_time_form() {
    // RFC 5280 writes dates from 2050 on as GeneralizedTime. The reader takes both forms.
    let pem = cert_pem((2024, 1, 1), (2060, 12, 31));
    let want = days_from_civil(2060, 12, 31) * DAY;
    assert_eq!(certificate_expires_in(&pem, NOW), Some(want - NOW));
}

#[test]
fn only_the_first_certificate_of_a_bundle_counts() {
    let first = cert_pem((2024, 1, 1), (2027, 1, 1));
    let second = cert_pem((2024, 1, 1), (2035, 1, 1));
    let bundle = format!("{first}\n{second}");
    let want = days_from_civil(2027, 1, 1) * DAY;
    assert_eq!(certificate_expires_in(&bundle, NOW), Some(want - NOW));
}

#[test]
fn text_that_is_not_a_certificate_has_no_known_end() {
    let pem = cert_pem((2024, 1, 1), (2030, 1, 1));
    let truncated = &pem[..pem.len() / 2];
    for text in [
        "",
        "not pem",
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----",
        // A valid base64 body that is not a certificate.
        "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----",
        truncated,
    ] {
        assert_eq!(certificate_expires_in(text, NOW), None, "{text:?}");
    }
    let huge = format!("{}{}", pem, "x".repeat(MAX_CERT_BYTES));
    assert_eq!(certificate_expires_in(&huge, NOW), None);
}

#[test]
fn the_der_reader_refuses_lengths_that_run_past_the_input() {
    // A SEQUENCE that claims 200 bytes and holds 2, an indefinite length, a four byte length, a tag with
    // no length and nothing.
    for bad in [
        &[0x30, 0x81, 0xc8, 0x01, 0x02][..],
        &[0x30, 0x80, 0x00, 0x00][..],
        &[0x30, 0x84, 0x00, 0x00, 0x00, 0x01, 0x00][..],
        &[0x30][..],
        &[][..],
    ] {
        assert!(read(bad).is_none(), "{bad:?}");
    }
    assert!(not_after(&[0x30, 0x00]).is_none());
}

#[test]
fn asn1_times_convert_to_unix_seconds() {
    assert_eq!(asn1_time(0x17, b"700101000000Z"), Some(0));
    assert_eq!(asn1_time(0x17, b"491231235959Z"), Some(2_524_607_999));
    assert_eq!(asn1_time(0x17, b"500101000000Z"), Some(-631_152_000));
    assert_eq!(asn1_time(0x18, b"20400229120000Z"), Some(2_214_129_600));
    for bad in [
        (0x17, &b"7001010000Z"[..]),
        (0x17, b"701301000000Z"),
        (0x17, b"700101240000Z"),
        (0x17, b"700101000000+0100"),
        (0x17, b"70010100000aZ"),
        (0x18, b"700101000000Z"),
        (0x04, b"700101000000Z"),
    ] {
        assert_eq!(asn1_time(bad.0, bad.1), None, "{bad:?}");
    }
}

#[test]
fn debug_shows_numbers_and_a_file_name_only() {
    let plugin = Credential::Plugin {
        binary: "aws".to_owned(),
    };
    assert_eq!(format!("{plugin:?}"), "Plugin(aws)");
    assert_eq!(plugin.expires_in(), None);
    assert_eq!(
        Credential::Token {
            expires_in: Some(5)
        }
        .expires_in(),
        Some(5)
    );
}
