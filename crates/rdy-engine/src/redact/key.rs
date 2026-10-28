//! The per-run tag key and the tag function (04 section 3.3).
//!
//! The key is 32 random bytes held inside a `ring` HMAC key. It is never written, logged or put in an
//! error. The tag is the first 4 bytes of HMAC-SHA256 over the secret bytes, as 8 lowercase hex digits.

use ring::hmac;
use ring::rand::SystemRandom;

use super::RedactError;

/// The number of tag bytes kept from the HMAC output. Four bytes give eight hex digits.
const TAG_BYTES: usize = 4;

/// The secret key that makes placeholder tags unguessable.
///
/// Make one per process with [`TagKey::generate`] and share it between the report, the logs and any
/// bundle entry, so equal secrets get equal tags everywhere in one run. A second process gets a different
/// key, so tags from two runs do not match.
#[derive(Clone)]
pub struct TagKey {
    key: hmac::Key,
}

impl TagKey {
    /// Makes a key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`RedactError::NoRandomness`] if the OS cannot supply random bytes. The caller must then
    /// exit with code 70. There is no weaker fallback.
    pub fn generate() -> Result<Self, RedactError> {
        let rng = SystemRandom::new();
        let key =
            hmac::Key::generate(hmac::HMAC_SHA256, &rng).map_err(|_| RedactError::NoRandomness)?;
        Ok(Self { key })
    }

    /// Makes a key from fixed bytes, so tests get the same tags every time.
    ///
    /// Only built with the `testing` feature (or in this crate's own tests). CI keeps the feature out of
    /// the release binary.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn fixed(bytes: [u8; 32]) -> Self {
        Self::from_bytes(&bytes)
    }

    #[cfg(any(test, feature = "testing"))]
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, bytes),
        }
    }

    /// The tag for these secret bytes: 8 lowercase hex digits.
    pub(crate) fn tag(&self, secret: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let full = hmac::sign(&self.key, secret);
        let mut out = String::with_capacity(TAG_BYTES * 2);
        for byte in full.as_ref().iter().take(TAG_BYTES) {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }
}

impl std::fmt::Debug for TagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material, even in a debug dump.
        f.write_str("TagKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_matches_the_rfc_4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        // The full HMAC-SHA256 is 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843.
        let key = TagKey::from_bytes(b"Jefe");
        assert_eq!(key.tag(b"what do ya want for nothing?"), "5bdcc146");
    }

    #[test]
    fn tag_is_stable_for_one_key_and_differs_across_keys() {
        let a = TagKey::fixed([1; 32]);
        let b = TagKey::fixed([2; 32]);
        assert_eq!(a.tag(b"hunter2"), a.tag(b"hunter2"));
        assert_ne!(a.tag(b"hunter2"), b.tag(b"hunter2"));
        assert_ne!(a.tag(b"hunter2"), a.tag(b"hunter3"));
        assert_eq!(a.tag(b"hunter2").len(), 8);
    }

    #[test]
    fn generated_keys_work_and_debug_hides_the_key() {
        let key = TagKey::generate().expect("the test host has a random source");
        let tag = key.tag(b"x");
        assert!(
            tag.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(format!("{key:?}"), "TagKey(..)");
    }
}
