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
    /// Surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// [`SignatureError::BadKey`] if the text is not a minisign ed25519 public key, and
    /// [`SignatureError::WeakKey`] if the key has small order.
    pub fn from_base64(text: &str) -> Result<Self, SignatureError> {
        let bytes = base64::decode(text.trim())
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
        let key = PublicKey::from_base64(&format!("  {STOCK_KEY}\n")).expect("stock key");
        let raw = base64::decode(STOCK_KEY).expect("base64");
        assert_eq!(key.fingerprint(), hex(&Sha256::digest(&raw[10..])));
        assert_eq!(key.fingerprint().len(), 64);
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
