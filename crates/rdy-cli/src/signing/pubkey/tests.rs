//! Tests for key arguments. Keys are synthetic and made in each test.

use ct_codecs::{Base64, Encoder};

use super::*;
use crate::signing::key::{KdfCost, SecretKey};

const CHEAP: KdfCost = KdfCost::new(32_768, 1 << 20);

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// A public key file text and a secret key file text, from one key.
fn pair() -> (SecretKey, String, String) {
    let key = SecretKey::generate().expect("key");
    let public = key.public_key_file();
    let secret = key.key_file(None, CHEAP).expect("key file").to_string();
    (key, public, secret)
}

#[test]
fn a_pub_file_a_bare_key_and_the_key_text_give_the_same_key() {
    let d = dir();
    let (key, public, _) = pair();
    let path = d.path().join("acme.pub");
    std::fs::write(&path, &public).expect("write");
    let from_file = resolve(path.to_str().expect("utf8")).expect("file");
    assert_eq!(from_file.origin, Origin::File(path));
    assert_eq!(from_file.key.key_id(), key.key_id());
    let from_text = resolve(&public).expect("text");
    assert_eq!(from_text.origin, Origin::Text);
    assert_eq!(from_text.key, from_file.key);
    let bare = resolve(&key.public_key_base64()).expect("bare key");
    assert_eq!(bare.origin, Origin::Text);
    assert_eq!(bare.key, from_file.key);
}

#[test]
fn a_secret_key_file_is_refused_and_named_by_its_origin() {
    let d = dir();
    let (_, _, secret) = pair();
    let path = d.path().join("acme.key");
    std::fs::write(&path, &secret).expect("write");
    let err = resolve(path.to_str().expect("utf8")).expect_err("secret");
    assert!(matches!(
        err,
        GivenKeyError::SecretKey { origin: Origin::File(ref p) } if *p == path
    ));
}

#[test]
fn secret_key_text_on_the_command_line_is_refused_without_echo() {
    let (_, _, secret) = pair();
    let line = secret.lines().nth(1).expect("key line").to_owned();
    for text in [secret.clone(), line.clone()] {
        let err = resolve(&text).expect_err("secret");
        assert!(matches!(
            err,
            GivenKeyError::SecretKey {
                origin: Origin::Text
            }
        ));
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(&line), "{shown}");
    }
    assert!(matches!(
        resolve("untrusted comment: rdy secret key ..."),
        Err(GivenKeyError::SecretKey {
            origin: Origin::Text
        })
    ));
}

#[test]
fn secret_key_text_with_stray_white_space_is_still_text_and_never_echoed() {
    let (_, _, secret) = pair();
    let line = secret.lines().nth(1).expect("key line").to_owned();
    for (what, arg) in [
        ("leading space", format!(" {line}")),
        ("trailing space", format!("{line} ")),
        ("trailing carriage return", format!("{line}\r")),
    ] {
        let err = resolve(&arg).expect_err(what);
        assert!(
            matches!(
                err,
                GivenKeyError::SecretKey {
                    origin: Origin::Text
                }
            ),
            "{what}: {err:?}"
        );
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(&line), "{what}: {shown}");
    }
}

#[test]
fn secret_key_text_with_quotes_or_punctuation_around_it_is_still_refused_and_never_echoed() {
    let (_, _, secret) = pair();
    let line = secret.lines().nth(1).expect("key line").to_owned();
    for (what, arg) in [
        ("smart quotes", format!("\u{201c}{line}\u{201d}")),
        ("single quotes", format!("'{line}'")),
        ("ellipsis", format!("\u{2026}{line}\u{2026}")),
        ("trailing comma", format!("{line},")),
        ("trailing full stop", format!("{line}.")),
        ("quotes and a space", format!(" \"{line}\" ")),
        (
            "the comment line in quotes",
            "\u{201c}untrusted comment: rdy secret key\u{201d}".to_owned(),
        ),
    ] {
        let err = resolve(&arg).expect_err(what);
        assert!(
            matches!(
                err,
                GivenKeyError::SecretKey {
                    origin: Origin::Text
                }
            ),
            "{what}: {err:?}"
        );
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(&line), "{what}: {shown}");
    }
}

#[test]
fn a_file_name_with_dots_and_slashes_is_not_taken_for_a_secret_key() {
    let d = dir();
    let missing = d.path().join("acme.key.pub");
    assert!(matches!(
        resolve(missing.to_str().expect("utf8")),
        Err(GivenKeyError::File { .. })
    ));
}

#[test]
fn a_public_key_with_stray_white_space_is_text() {
    let (key, _, _) = pair();
    let line = key.public_key_base64();
    for arg in [
        format!(" {line}"),
        format!("{line} "),
        format!("{line}\r\n"),
    ] {
        let given = resolve(&arg).expect("public key text");
        assert_eq!(given.origin, Origin::Text);
        assert_eq!(given.key.key_id(), key.key_id());
    }
}

#[test]
fn a_public_key_comment_that_mentions_a_secret_key_is_still_a_public_key() {
    let (key, _, _) = pair();
    let text = format!(
        "untrusted comment: synthetic key. The secret key was discarded\n{}\n",
        key.public_key_base64()
    );
    assert_eq!(resolve(&text).expect("public").key.key_id(), key.key_id());
}

#[test]
fn text_that_is_not_a_public_key_is_refused_without_echo() {
    let err = resolve("untrusted comment: x\nthis is not a key\n").expect_err("not a key");
    assert!(matches!(
        err,
        GivenKeyError::NotPublic {
            origin: Origin::Text,
            ..
        }
    ));
    assert!(!format!("{err}").contains("this is not a key"));
    let long = format!("RW{}", "A".repeat(2000));
    assert!(matches!(
        resolve(&long),
        Err(GivenKeyError::NotPublic { .. })
    ));
}

#[test]
fn a_weak_key_is_refused() {
    // Algorithm bytes, a key id, and the identity point: a key of small order.
    let mut bytes = b"Ed".to_vec();
    bytes.extend_from_slice(&[7; 8]);
    let mut identity = [0u8; 32];
    identity[0] = 1;
    bytes.extend_from_slice(&identity);
    let text = Base64::encode_to_string(&bytes).expect("encode");
    assert!(matches!(
        resolve(&text),
        Err(GivenKeyError::NotPublic {
            source: SignatureError::WeakKey,
            ..
        })
    ));
}

#[test]
fn a_missing_file_a_folder_and_a_binary_file_are_refused() {
    let d = dir();
    let missing = d.path().join("nope.pub");
    assert!(matches!(
        resolve(missing.to_str().expect("utf8")),
        Err(GivenKeyError::File { .. })
    ));
    assert!(matches!(
        resolve(d.path().to_str().expect("utf8")),
        Err(GivenKeyError::File { .. })
    ));
    let binary = d.path().join("bin");
    std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x80]).expect("write");
    assert!(matches!(
        resolve(binary.to_str().expect("utf8")),
        Err(GivenKeyError::NotText { .. })
    ));
    let big = d.path().join("big.pub");
    std::fs::write(&big, vec![b'a'; MAX_KEY_FILE_BYTES + 1]).expect("write");
    assert!(matches!(
        resolve(big.to_str().expect("utf8")),
        Err(GivenKeyError::File {
            source: FileError::TooLarge,
            ..
        })
    ));
}

#[test]
fn file_names_are_not_mistaken_for_key_text() {
    for name in [
        "acme-platform.pub",
        "./RWkeys/acme.pub",
        "keys/acme-platform-public-key",
        "RW.pub",
        "C:\\keys\\acme.pub",
        "a",
    ] {
        assert!(!is_key_text(name), "{name}");
    }
    for text in [
        "untrusted comment: minisign public key X",
        "line one\nline two",
        &format!("RW{}", "A".repeat(54)),
    ] {
        assert!(is_key_text(text), "{text}");
    }
}
