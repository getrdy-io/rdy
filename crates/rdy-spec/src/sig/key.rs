//! Public keys and key ids.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::SignatureError;
use super::base64;

/// The bytes of a minisign public key: two algorithm bytes, an 8-byte key id and a 32-byte ed25519 key.
const PUBLIC_KEY_BYTES: usize = 42;

/// The algorithm bytes of every minisign public key. Prehashed signing uses the same key bytes.
const KEY_ALGORITHM: [u8; 2] = *b"Ed";

/// The most bytes of a key file that rdy reads. A real `.pub` file is about 100 bytes.
pub const MAX_KEY_FILE_BYTES: usize = 1024;

/// The 8-byte id that a minisign key writes into its signatures.
///
/// It is chosen at random when the key is made, so anyone can make a key with a given id. It only
/// preselects a key. The identity of a key is its [`PublicKey::fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 8]);

impl KeyId {
    /// A key id from its 8 bytes in file order.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for KeyId {
    /// 16 uppercase hex digits, the way minisign prints a key id (the bytes in reverse order).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Lowercase hex text of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A minisign public key: an ed25519 key and the id that its signatures carry.
///
/// A key that is malformed or of small order is refused when it is built, so every `PublicKey` is one
/// that [`crate::sig::TrustStore`] may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    key_id: KeyId,
    key: VerifyingKey,
}

impl PublicKey {
    /// Reads a key from the base64 line of a minisign `.pub` file, such as `RWQf6LRC...`.
    ///
    /// The text must be exactly the base64, with no whitespace around it. The key must be a canonical
    /// encoding of a curve point.
    ///
    /// # Errors
    ///
    /// [`SignatureError::BadKey`] if the text is not a minisign ed25519 public key, and
    /// [`SignatureError::WeakKey`] if the key has small order.
    pub fn from_base64(text: &str) -> Result<Self, SignatureError> {
        let bytes = base64::decode(text)
            .filter(|bytes| bytes.len() == PUBLIC_KEY_BYTES)
            .ok_or(SignatureError::BadKey {
                reason: "it is not a minisign public key",
            })?;
        if bytes[..2] != KEY_ALGORITHM {
            return Err(SignatureError::BadKey {
                reason: "it is not an ed25519 key",
            });
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes[2..10]);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes[10..]);
        let key = parse_verifying_key(&raw)?;
        Ok(Self {
            key_id: KeyId(id),
            key,
        })
    }

    /// Reads a key from the text of a key file: either a minisign `.pub` file (the `untrusted comment:`
    /// line, then the key line) or the bare base64 line. One final line ending is allowed, LF or CR LF.
    ///
    /// The comment line is checked for its label only and never read. This is for `rdy trust add --key`
    /// and `rdy run --key`. Callers read at most [`MAX_KEY_FILE_BYTES`] bytes.
    ///
    /// # Errors
    ///
    /// [`SignatureError::BadKey`] if the text is longer than that, has the wrong number of lines or is
    /// not a minisign ed25519 public key, and [`SignatureError::WeakKey`] if the key has small order.
    pub fn from_key_file_text(text: &str) -> Result<Self, SignatureError> {
        let bad = |reason| SignatureError::BadKey { reason };
        if text.len() > MAX_KEY_FILE_BYTES {
            return Err(bad("the key file is too long"));
        }
        let text = text.strip_suffix('\n').unwrap_or(text);
        let text = text.strip_suffix('\r').unwrap_or(text);
        let mut lines = text
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line));
        match (lines.next(), lines.next(), lines.next()) {
            (Some(key), None, _) => Self::from_base64(key),
            (Some(comment), Some(key), None) if comment.starts_with("untrusted comment:") => {
                Self::from_base64(key)
            }
            _ => Err(bad("it is not a minisign public key file")),
        }
    }

    /// The key as the base64 line of a minisign `.pub` file. [`PublicKey::from_base64`] reads it back.
    #[must_use]
    pub fn to_base64(&self) -> String {
        let mut bytes = Vec::with_capacity(PUBLIC_KEY_BYTES);
        bytes.extend_from_slice(&KEY_ALGORITHM);
        bytes.extend_from_slice(&self.key_id.0);
        bytes.extend_from_slice(self.key.as_bytes());
        base64::encode(&bytes)
    }

    /// The id that signatures by this key carry.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The fingerprint: 64 lowercase hex digits of SHA-256 over the 32-byte ed25519 key.
    ///
    /// This is what a person compares with the vendor's published value.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        hex(&Sha256::digest(self.key.as_bytes()))
    }

    /// The ed25519 key, for the verifier in this crate.
    pub(super) fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Reads 32 bytes as an ed25519 key and refuses malformed and small-order keys.
pub(super) fn parse_verifying_key(raw: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
    let key = VerifyingKey::from_bytes(raw).map_err(|_| SignatureError::BadKey {
        reason: "it is not a point on the curve",
    })?;
    // A second encoding of the same point would behave the same and have a different fingerprint.
    if key.to_edwards().compress().to_bytes() != *raw {
        return Err(SignatureError::BadKey {
            reason: "it is not the canonical encoding of the key",
        });
    }
    if key.is_weak() {
        return Err(SignatureError::WeakKey);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public key made by stock minisign. Its `.pub` file says `minisign public key E7620F1842B4E81F`.
    const STOCK_KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    #[test]
    fn a_key_id_prints_in_minisign_order() {
        let key = PublicKey::from_base64(STOCK_KEY).expect("stock key");
        assert_eq!(key.key_id().to_string(), "E7620F1842B4E81F");
        assert_eq!(
            key.key_id(),
            KeyId::from_bytes([0x1F, 0xE8, 0xB4, 0x42, 0x18, 0x0F, 0x62, 0xE7])
        );
    }

    #[test]
    fn the_fingerprint_is_sha256_of_the_32_key_bytes() {
        let key = PublicKey::from_base64(STOCK_KEY).expect("stock key");
        let raw = base64::decode(STOCK_KEY).expect("base64");
        assert_eq!(key.fingerprint(), hex(&Sha256::digest(&raw[10..])));
        assert_eq!(key.fingerprint().len(), 64);
    }

    #[test]
    fn a_key_file_is_a_pub_file_or_a_bare_key() {
        let comment = "untrusted comment: minisign public key: E7620F1842B4E81F";
        let want = PublicKey::from_base64(STOCK_KEY).expect("stock key");
        for text in [
            format!("{comment}\n{STOCK_KEY}\n"),
            format!("{comment}\n{STOCK_KEY}"),
            format!("{comment}\r\n{STOCK_KEY}\r\n"),
            format!("{STOCK_KEY}\n"),
            STOCK_KEY.to_owned(),
            // The comment is never read, only its label.
            format!("untrusted comment:\u{1b}[2J\n{STOCK_KEY}\n"),
        ] {
            assert_eq!(
                PublicKey::from_key_file_text(&text).expect("reads"),
                want,
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_key_file_with_anything_else_is_refused() {
        let comment = "untrusted comment: x";
        let mut too_long = format!("{comment}\n{STOCK_KEY}\n");
        too_long.push_str(&"#".repeat(MAX_KEY_FILE_BYTES));
        for text in [
            String::new(),
            "\n".to_owned(),
            format!("{comment}\n"),
            format!("{comment}\n\n{STOCK_KEY}\n"),
            format!("{comment}\n{STOCK_KEY}\nextra\n"),
            format!("{comment}\n{STOCK_KEY}\n\n"),
            format!("comment\n{STOCK_KEY}\n"),
            format!("{STOCK_KEY}\n{STOCK_KEY}\n"),
            format!(" {STOCK_KEY}\n"),
            format!("{comment}\n{STOCK_KEY} \n"),
            too_long,
        ] {
            assert!(
                matches!(
                    PublicKey::from_key_file_text(&text),
                    Err(SignatureError::BadKey { .. })
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn whitespace_around_a_key_is_refused() {
        for text in [
            format!(" {STOCK_KEY}"),
            format!("{STOCK_KEY} "),
            format!("{STOCK_KEY}\n"),
            format!("\t{STOCK_KEY}\r\n"),
        ] {
            assert!(
                matches!(
                    PublicKey::from_base64(&text).unwrap_err(),
                    SignatureError::BadKey { .. }
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_non_canonical_encoding_of_a_good_key_is_refused() {
        // y and y + p are the same field element. For y below 19, y + p still fits in 255 bits, so the
        // same point has a second encoding.
        let mut found = 0;
        for y in 2u8..19 {
            let mut canonical = [0u8; 32];
            canonical[0] = y;
            if parse_verifying_key(&canonical).is_err() {
                continue;
            }
            let mut second = [0xFFu8; 32];
            second[0] = 0xED + y;
            second[31] = 0x7F;
            assert!(
                matches!(
                    parse_verifying_key(&second),
                    Err(SignatureError::BadKey { .. })
                ),
                "y = {y}"
            );
            found += 1;
        }
        assert!(found > 0, "no small y is on the curve");
    }

    #[test]
    fn malformed_and_weak_keys_are_refused() {
        let key_with = |alg: &[u8; 2], point: [u8; 32]| {
            let mut bytes = alg.to_vec();
            bytes.extend_from_slice(&[7u8; 8]);
            bytes.extend_from_slice(&point);
            PublicKey::from_base64(&base64::encode(&bytes))
        };
        // The identity point (y = 1) has order 1. The point (0, -1), y = p - 1, has order 2.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut order_two = [0xFFu8; 32];
        order_two[0] = 0xEC;
        order_two[31] = 0x7F;
        assert_eq!(
            key_with(b"Ed", identity).unwrap_err(),
            SignatureError::WeakKey
        );
        assert_eq!(
            key_with(b"Ed", order_two).unwrap_err(),
            SignatureError::WeakKey
        );
        // Not a minisign ed25519 key.
        assert!(matches!(
            key_with(b"XX", [9u8; 32]).unwrap_err(),
            SignatureError::BadKey { .. }
        ));
        // Too short, too long, not base64, empty.
        for bad in [
            "",
            "AAAA",
            &STOCK_KEY[4..],
            &format!("{STOCK_KEY}AAAA"),
            "not base64!",
        ] {
            assert!(
                matches!(
                    PublicKey::from_base64(bad).unwrap_err(),
                    SignatureError::BadKey { .. }
                ),
                "{bad:?}"
            );
        }
    }
}
