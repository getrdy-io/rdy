//! The signature file (`<spec>.minisig`), in the minisign form (01 section 4.1 and 4.2).
//!
//! ```text
//! untrusted comment: rdy spec signature for acme-platform, key 9F3A6C21D4E87B05
//! <base64: "ED" || key id || ed25519 signature of BLAKE2b-512(file)>
//! trusted comment: rdy-spec-v1 product=acme-platform signed_at=2026-11-30T16:02:11Z
//! <base64: ed25519 signature of (first signature || trusted comment)>
//! ```
//!
//! The second signature is what makes the trusted comment trustworthy: it covers the comment, so the
//! comment cannot be edited without the key. The reader is `rdy_spec::sig`, and `rdy spec sign`
//! checks each file it makes with `rdy_spec::load` before it writes it.

use blake2::{Blake2b512, Digest};
use ct_codecs::{Base64, Encoder};
use rdy_spec::spec::ProductSlug;

use super::key::SecretKey;

/// The prefix that separates rdy spec signatures from anything else the same key signs.
const COMMENT_PREFIX: &str = "rdy-spec-v1";

/// The trusted comment for `product`, signed at `signed_at`: `rdy-spec-v1 product=<slug>
/// signed_at=<time>`.
#[must_use]
pub fn trusted_comment(product: &ProductSlug, signed_at: &str) -> String {
    format!("{COMMENT_PREFIX} product={product} signed_at={signed_at}")
}

/// The signature file for `bytes`, signed with `key`.
///
/// `bytes` are the spec exactly as read. `signed_at` is `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn sign(key: &SecretKey, product: &ProductSlug, signed_at: &str, bytes: &[u8]) -> String {
    let prehash = Blake2b512::digest(bytes);
    let signature = key.sign(&prehash);

    let comment = trusted_comment(product, signed_at);
    let mut covered = Vec::with_capacity(signature.len() + comment.len());
    covered.extend_from_slice(&signature);
    covered.extend_from_slice(comment.as_bytes());
    let global = key.sign(&covered);

    let mut line = Vec::with_capacity(74);
    line.extend_from_slice(b"ED");
    line.extend_from_slice(&key.keynum());
    line.extend_from_slice(&signature);
    format!(
        "untrusted comment: rdy spec signature for {product}, key {}\n{}\ntrusted comment: {comment}\n{}\n",
        key.key_id(),
        b64(&line),
        b64(&global),
    )
}

/// Standard base64 with padding.
fn b64(bytes: &[u8]) -> String {
    // The encoder sizes its own output, so this cannot fail for any input length.
    Base64::encode_to_string(bytes).unwrap_or_default()
}

#[cfg(test)]
mod tests;
