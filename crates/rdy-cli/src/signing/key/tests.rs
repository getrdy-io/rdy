//! Tests for the secret key file. Passwords and keys here are synthetic.
//!
//! Most tests use a cheap key derivation so they run fast. One test runs the real cost. The stock
//! `minisign` crate is the second implementation: rdy must read its keys, and it must read rdy's.

use super::*;

/// A password that must never show up in an error or a debug print.
const PASSWORD: &str = "CANARY-correct horse battery staple";

/// Cheap enough for many tests: scrypt N = 2^10.
const CHEAP: KdfCost = KdfCost::new(32_768, 1 << 20);

fn encrypted(key: &SecretKey) -> Zeroizing<String> {
    key.key_file(Some(PASSWORD), CHEAP).expect("key file")
}

/// The decoded record of a key file, to edit.
fn record_of(text: &str) -> Vec<u8> {
    let line = text.lines().nth(1).expect("key line");
    Base64::decode_to_vec(line, None).expect("base64")
}

fn text_of(record: &[u8]) -> String {
    format!(
        "untrusted comment: test\n{}\n",
        Base64::encode_to_string(record).expect("encode")
    )
}

#[test]
fn an_encrypted_key_opens_with_its_password_and_has_the_same_public_key() {
    let key = SecretKey::generate().expect("key");
    let text = encrypted(&key);
    let stored = StoredKey::parse(&text).expect("parse");
    assert!(stored.is_encrypted());
    let opened = stored.unlock(Some(PASSWORD)).expect("unlock");
    assert_eq!(opened.public_key_base64(), key.public_key_base64());
    assert_eq!(opened.key_id(), key.key_id());
}

#[test]
fn a_wrong_or_missing_password_is_told_apart_and_nothing_is_signed() {
    let key = SecretKey::generate().expect("key");
    let stored = StoredKey::parse(&encrypted(&key)).expect("parse");
    for wrong in ["", "x", &format!("{PASSWORD} "), &PASSWORD.to_lowercase()] {
        assert_eq!(
            stored.unlock(Some(wrong)).unwrap_err(),
            KeyError::WrongPassword,
            "{wrong:?}"
        );
    }
    assert_eq!(stored.unlock(None).unwrap_err(), KeyError::NeedsPassword);
}

#[test]
fn an_unencrypted_key_round_trips_and_ignores_a_password() {
    let key = SecretKey::generate().expect("key");
    let text = key.key_file(None, CHEAP).expect("key file");
    let stored = StoredKey::parse(&text).expect("parse");
    assert!(!stored.is_encrypted());
    for password in [None, Some("ignored")] {
        let opened = stored.unlock(password).expect("unlock");
        assert_eq!(opened.public_key_base64(), key.public_key_base64());
    }
}

#[test]
fn the_file_has_the_minisign_shape() {
    let key = SecretKey::generate().expect("key");
    let text = encrypted(&key);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "untrusted comment: rdy encrypted secret key");
    assert!(text.ends_with('\n'));
    let record = record_of(&text);
    assert_eq!(record.len(), RECORD_BYTES);
    assert_eq!(&record[..6], b"EdScB2");
    assert_eq!(&record[38..46], &CHEAP.opslimit.to_le_bytes());
    assert_eq!(&record[46..54], &CHEAP.memlimit.to_le_bytes());
    // The encrypted part does not hold the key id in the clear.
    assert_ne!(&record[54..62], &key.keynum());
}

#[test]
fn the_standard_cost_is_what_stock_minisign_writes() {
    let params = scrypt_params(KdfCost::STANDARD.opslimit, KdfCost::STANDARD.memlimit)
        .expect("standard params");
    assert_eq!(params.log_n(), 20);
    assert_eq!(params.r(), 8);
    assert_eq!(params.p(), 1);
    assert_eq!(KdfCost::STANDARD.opslimit, 33_554_432);
    assert_eq!(KdfCost::STANDARD.memlimit, 1_073_741_824);
}

#[test]
fn a_key_made_at_the_standard_cost_opens_and_signs() {
    // The one unit test at the real cost: scrypt N = 2^20 needs 1 GiB. Its name is in the `real-kdf`
    // test group in .config/nextest.toml, so it never runs beside another 1 GiB test.
    let key = SecretKey::generate().expect("key");
    let text = key
        .key_file(Some(PASSWORD), KdfCost::STANDARD)
        .expect("key file");
    let record = record_of(&text);
    assert_eq!(&record[38..46], &33_554_432u64.to_le_bytes());
    assert_eq!(&record[46..54], &1_073_741_824u64.to_le_bytes());
    let opened = StoredKey::parse(&text)
        .expect("parse")
        .unlock(Some(PASSWORD))
        .expect("unlock");
    assert_eq!(opened.public_key_base64(), key.public_key_base64());
}

#[test]
fn the_stock_crate_opens_a_key_rdy_wrote() {
    let key = SecretKey::generate().expect("key");
    let text = encrypted(&key);
    let theirs = minisign::SecretKeyBox::from_string(&text)
        .expect("box")
        .into_secret_key(Some(PASSWORD.to_owned()))
        .expect("stock crate opens rdy's key");
    let their_public = minisign::PublicKey::from_secret_key(&theirs).expect("public");
    assert_eq!(their_public.to_base64(), key.public_key_base64());
    // And the wrong password fails there too.
    assert!(
        minisign::SecretKeyBox::from_string(&text)
            .expect("box")
            .into_secret_key(Some("wrong".to_owned()))
            .is_err()
    );
    // The unencrypted form.
    let plain = key.key_file(None, CHEAP).expect("key file");
    let theirs = minisign::SecretKeyBox::from_string(&plain)
        .expect("box")
        .into_unencrypted_secret_key()
        .expect("stock crate opens an unprotected rdy key");
    assert_eq!(
        minisign::PublicKey::from_secret_key(&theirs)
            .expect("public")
            .to_base64(),
        key.public_key_base64()
    );
}

#[test]
fn rdy_opens_keys_the_stock_crate_wrote() {
    // The stock crate's cost is lower than rdy's (N = 2^15). Reading it must work.
    let pair = minisign::KeyPair::generate_encrypted_keypair(Some(PASSWORD.to_owned()))
        .expect("stock key pair");
    let text = pair.sk.to_box(None).expect("box").into_string();
    let opened = StoredKey::parse(&text)
        .expect("parse")
        .unlock(Some(PASSWORD))
        .expect("rdy opens the stock key");
    assert_eq!(opened.public_key_base64(), pair.pk.to_base64());

    let plain = minisign::KeyPair::generate_unencrypted_keypair().expect("stock key pair");
    let text = plain.sk.to_box(None).expect("box").into_string();
    let opened = StoredKey::parse(&text)
        .expect("parse")
        .unlock(None)
        .expect("rdy opens the unprotected stock key");
    assert_eq!(opened.public_key_base64(), plain.pk.to_base64());
}

#[test]
fn a_key_file_may_not_ask_for_more_than_the_standard_cost() {
    let key = SecretKey::generate().expect("key");
    let good = record_of(&encrypted(&key));
    let with = |ops: u64, mem: u64| {
        let mut record = good.clone();
        record[38..46].copy_from_slice(&ops.to_le_bytes());
        record[46..54].copy_from_slice(&mem.to_le_bytes());
        text_of(&record)
    };
    for (ops, mem) in [
        (MAX_OPSLIMIT + 1, MAX_MEMLIMIT),
        (MAX_OPSLIMIT, MAX_MEMLIMIT + 1),
        (u64::MAX, MAX_MEMLIMIT),
        (MAX_OPSLIMIT, u64::MAX),
        (u64::MAX, u64::MAX),
        // Within both limits, but libsodium's rule turns these into N = 2 and p far above 1.
        (MAX_OPSLIMIT, 0),
        (MAX_OPSLIMIT, 1 << 20),
        (0, 0),
    ] {
        assert_eq!(
            StoredKey::parse(&with(ops, mem)).unwrap_err(),
            KeyError::TooCostly,
            "{ops} {mem}"
        );
    }
    // Writing is held to the same limit.
    assert_eq!(
        key.key_file(Some("x"), KdfCost::new(MAX_OPSLIMIT + 1, MAX_MEMLIMIT))
            .unwrap_err(),
        KeyError::TooCostly
    );
    // The limits themselves are fine, and so is the cost of the `minisign` crate's own keys
    // (opslimit 1,048,576 and memlimit 33,554,432: 32 MiB, N = 2^15, p = 1).
    assert!(StoredKey::parse(&with(MAX_OPSLIMIT, MAX_MEMLIMIT)).is_ok());
    assert!(StoredKey::parse(&with(1_048_576, 33_554_432)).is_ok());
}

#[test]
fn malformed_files_are_refused_with_a_reason() {
    let key = SecretKey::generate().expect("key");
    let good = encrypted(&key);
    let record = record_of(&good);
    let line = good.lines().nth(1).expect("line").to_owned();
    let edit = |at: usize, value: u8| {
        let mut changed = record.clone();
        changed[at] = value;
        text_of(&changed)
    };
    for (what, text) in [
        ("empty", String::new()),
        ("one line", "untrusted comment: x\n".to_owned()),
        ("no comment", format!("{line}\n{line}\n")),
        ("extra line", format!("{}extra\n", good.as_str())),
        ("not base64", "untrusted comment: x\n!!!!\n".to_owned()),
        ("short", text_of(&record[..RECORD_BYTES - 1])),
        ("long", text_of(&[&record[..], &[0u8]].concat())),
    ] {
        assert!(
            matches!(StoredKey::parse(&text), Err(KeyError::Malformed(_))),
            "{what}: {:?}",
            StoredKey::parse(&text)
        );
    }
    for (what, text) in [
        ("signature algorithm", edit(0, b'X')),
        ("kdf algorithm", edit(2, b'Z')),
        ("checksum algorithm", edit(4, b'X')),
    ] {
        assert!(
            matches!(StoredKey::parse(&text), Err(KeyError::Unsupported(_))),
            "{what}"
        );
    }
}

#[test]
fn a_damaged_unprotected_key_is_damaged_not_a_wrong_password() {
    let key = SecretKey::generate().expect("key");
    let record = record_of(&key.key_file(None, CHEAP).expect("key file"));
    // Flip one bit in the key id, in the seed, and in the checksum.
    for at in [54, 70, RECORD_BYTES - 1] {
        let mut changed = record.clone();
        changed[at] ^= 1;
        let stored = StoredKey::parse(&text_of(&changed)).expect("parse");
        assert_eq!(stored.unlock(None).unwrap_err(), KeyError::Damaged, "{at}");
    }
}

#[test]
fn a_key_whose_public_half_disagrees_with_its_seed_is_refused() {
    let key = SecretKey::generate().expect("key");
    let other = SecretKey::generate().expect("other key");
    let mut record = record_of(&key.key_file(None, CHEAP).expect("key file"));
    // Put the other key's public half in the second half of the secret key, with a valid checksum.
    let other_record = record_of(&other.key_file(None, CHEAP).expect("key file"));
    let public_at = 54 + KEYNUM_BYTES + 32;
    record[public_at..public_at + 32].copy_from_slice(&other_record[public_at..public_at + 32]);
    let keynum: [u8; KEYNUM_BYTES] = array_at(&record, 54);
    let sk: [u8; SK_BYTES] = array_at(&record, 54 + KEYNUM_BYTES);
    let chk = checksum(&keynum, &sk);
    let chk_at = 54 + KEYNUM_BYTES + SK_BYTES;
    record[chk_at..].copy_from_slice(&chk);
    let stored = StoredKey::parse(&text_of(&record)).expect("parse");
    assert_eq!(stored.unlock(None).unwrap_err(), KeyError::Damaged);
}

#[test]
fn secrets_never_appear_in_debug_output_or_errors() {
    let key = SecretKey::generate().expect("key");
    let text = encrypted(&key);
    let stored = StoredKey::parse(&text).expect("parse");
    let mut shown = format!("{key:?} {stored:?}");
    for err in [
        KeyError::NeedsPassword,
        KeyError::WrongPassword,
        KeyError::Damaged,
        KeyError::TooCostly,
        KeyError::Random,
        KeyError::Malformed("x"),
        KeyError::Unsupported("y"),
    ] {
        shown.push_str(&format!("{err} {err:?}"));
    }
    assert!(!shown.contains("CANARY"));
    let key_line = text.lines().nth(1).expect("line");
    assert!(!shown.contains(key_line));
}

#[test]
fn two_keys_have_different_ids_seeds_and_salts() {
    let a = SecretKey::generate().expect("a");
    let b = SecretKey::generate().expect("b");
    assert_ne!(a.public_key_base64(), b.public_key_base64());
    assert_ne!(a.keynum(), b.keynum());
    let first = record_of(&a.key_file(Some("p"), CHEAP).expect("file"));
    let second = record_of(&a.key_file(Some("p"), CHEAP).expect("file"));
    assert_ne!(first[6..38], second[6..38], "the salt is fresh each time");
    assert_ne!(first[54..], second[54..]);
}

#[test]
fn the_public_key_file_is_what_stock_minisign_writes() {
    let key = SecretKey::generate().expect("key");
    let text = key.public_key_file();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        format!("untrusted comment: minisign public key {}", key.key_id())
    );
    assert_eq!(lines[1], key.public_key_base64());
    // rdy's own reader and the stock reader accept it, and both see the same key id.
    let ours = rdy_spec::sig::PublicKey::from_base64(lines[1]).expect("rdy reads it");
    assert_eq!(ours.key_id(), key.key_id());
    let theirs = minisign::PublicKeyBox::from_string(&text)
        .expect("box")
        .into_public_key()
        .expect("stock crate reads it");
    assert_eq!(theirs.to_base64(), lines[1]);
}
