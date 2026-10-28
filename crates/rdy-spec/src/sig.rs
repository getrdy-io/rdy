//! Spec signatures: minisign over the raw bytes, keys pinned per product (ADR 0002, ADR 0018).
//!
//! [`crate::load`] checks the signature before it lets any byte reach the YAML reader. The rules,
//! from `docs/plan/01-spec-format.md` section 4:
//!
//! - The signature is a detached minisign signature. Only the prehashed form (`ED`: ed25519 over the
//!   BLAKE2b-512 hash of the file) is accepted. The legacy form (`Ed`) is refused.
//! - The signed bytes are the file exactly as read. No line-ending or BOM handling.
//! - The signed comment is exactly `rdy-spec-v1 product=<slug> signed_at=<RFC 3339 UTC>`. The prefix is the
//!   domain separation: a signature by the same key for anything else has a different comment.
//! - The key must be pinned in the [`TrustStore`] for the product the comment names. The key id only
//!   preselects. Verification then runs against the full key.
//! - Both ed25519 checks use `verify_strict`: no malleable `S`, no small-order `R` or key. That is why
//!   this module verifies minisign's envelope itself and does not use a minisign verifier crate (ADR 0018).
//! - The untrusted comment line is never read.

mod base64;
mod error;
mod key;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::spec::ProductSlug;
pub use error::SignatureError;
pub(crate) use key::hex;
pub use key::{KeyId, PublicKey};

/// The largest signature file rdy reads, 4 KiB (threat model INV-02).
pub const MAX_SIGNATURE_BYTES: usize = 4096;

/// The prefix of every signed comment. It is the domain separation of rdy specs.
const COMMENT_PREFIX: &str = "rdy-spec-v1";

/// The bytes of a minisign signature line: two algorithm bytes, an 8-byte key id and a 64-byte signature.
const SIGNATURE_LINE_BYTES: usize = 74;

/// What `load` does with a spec that has no signature.
///
/// A signature that is present is always checked, whatever the policy. A signature that fails never
/// falls back to unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Policy {
    /// A missing signature is an error ([`SignatureError::Missing`]). This is the default for every run.
    RequireSigned,
    /// A missing signature is allowed, and the result says [`SignatureState::Unsigned`]. The CLI sets
    /// this only for `--allow-unsigned`, read from argv alone.
    AllowUnsigned,
}

/// Where a trusted key came from, strongest first (`System` is less than `User` is less than `Flag`).
/// Reports record it, and the CLI shows KEY NOT PINNED for [`Self::Flag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TrustSource {
    /// Pinned in the system store (`/etc/rdy/trust.yaml` or its Windows twin).
    System,
    /// Pinned in the user's store.
    User,
    /// Given for this one run only, with the `--key` flag. Nothing was pinned.
    Flag,
}

/// How a loaded spec was authenticated.
///
/// This is the provenance that reports record (threat model R1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureState {
    /// A key pinned for the product signed these exact bytes.
    #[non_exhaustive]
    Verified {
        /// The key id the signature carries.
        key_id: KeyId,
        /// The fingerprint of the key that verified: SHA-256 over the 32-byte ed25519 key, in hex.
        fingerprint: String,
        /// The product the signed comment names. It equals `metadata.product`.
        product: ProductSlug,
        /// The `signed_at` of the signed comment, `YYYY-MM-DDTHH:MM:SSZ`.
        signed_at: String,
        /// Where the key that verified came from.
        trust_source: TrustSource,
    },
    /// The spec had no signature and the policy allowed that. Nothing says who wrote it.
    Unsigned,
}

/// One pinned key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    product: ProductSlug,
    key: PublicKey,
    source: TrustSource,
}

/// Keys that are trusted, each for named products.
///
/// A key is trusted for a product only if it was pinned for that product. This type is the in-memory
/// pin list. Reading and writing `trust.yaml` is the trust store ticket (M1-121).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustStore {
    pins: Vec<Pin>,
}

impl TrustStore {
    /// A store with no pins. Every signature fails with [`SignatureError::UnknownKey`] against it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `key` for `product`, and records where the key came from. The same key can be pinned for
    /// several products.
    pub fn pin(&mut self, product: ProductSlug, key: PublicKey, source: TrustSource) {
        self.pins.push(Pin {
            product,
            key,
            source,
        });
    }

    /// The pins for `product`.
    fn pins_for<'a>(&'a self, product: &'a ProductSlug) -> impl Iterator<Item = &'a Pin> {
        self.pins.iter().filter(move |pin| pin.product == *product)
    }
}

/// The parts of a signature file that verification needs.
struct Sidecar<'a> {
    key_id: KeyId,
    signature: [u8; 64],
    comment: &'a str,
    global_signature: [u8; 64],
    product: ProductSlug,
    signed_at: String,
}

fn malformed(reason: &'static str) -> SignatureError {
    SignatureError::Malformed { reason }
}

/// Splits the signature file into its four lines.
fn four_lines(text: &str) -> Result<[&str; 4], SignatureError> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    // One final newline is normal. Anything after it is not.
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let lines: Vec<&str> = lines
        .into_iter()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    <[&str; 4]>::try_from(lines).map_err(|_| malformed("it does not have four lines"))
}

/// Reads one base64 line into exactly `N` bytes.
fn fixed_bytes<const N: usize>(
    line: &str,
    reason: &'static str,
) -> Result<[u8; N], SignatureError> {
    base64::decode(line)
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
        .ok_or_else(|| malformed(reason))
}

/// Reads and checks the form of the signature file. Nothing is verified yet.
fn parse_sidecar(sidecar: &[u8]) -> Result<Sidecar<'_>, SignatureError> {
    if sidecar.len() > MAX_SIGNATURE_BYTES {
        return Err(SignatureError::SidecarTooLarge {
            size: sidecar.len(),
            limit: MAX_SIGNATURE_BYTES,
        });
    }
    let text = std::str::from_utf8(sidecar).map_err(|_| malformed("it is not text"))?;
    let [untrusted, signature_line, trusted, global_line] = four_lines(text)?;
    // The untrusted comment is only checked for its label. Its content is never read.
    if !untrusted.starts_with("untrusted comment:") {
        return Err(malformed("the first line is not an untrusted comment"));
    }
    let line: [u8; SIGNATURE_LINE_BYTES] = fixed_bytes(
        signature_line,
        "the signature line is not base64 of the right length",
    )?;
    match &line[..2] {
        b"ED" => {}
        b"Ed" => return Err(SignatureError::LegacyAlgorithm),
        _ => return Err(malformed("it is not an ed25519 signature")),
    }
    let comment = trusted
        .strip_prefix("trusted comment: ")
        .ok_or_else(|| malformed("the third line is not a trusted comment"))?;
    let (product, signed_at) = parse_comment(comment)?;
    let global_signature = fixed_bytes(
        global_line,
        "the global signature is not base64 of the right length",
    )?;
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&line[2..10]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&line[10..]);
    Ok(Sidecar {
        key_id: KeyId::from_bytes(key_id),
        signature,
        comment,
        global_signature,
        product,
        signed_at,
    })
}

fn bad_comment(reason: &'static str) -> SignatureError {
    SignatureError::BadComment { reason }
}

/// Parses `rdy-spec-v1 product=<slug> signed_at=<time>`, exactly. Single spaces, nothing else.
fn parse_comment(comment: &str) -> Result<(ProductSlug, String), SignatureError> {
    let mut parts = comment.split(' ');
    if parts.next() != Some(COMMENT_PREFIX) {
        return Err(bad_comment(
            "the signed comment does not start with rdy-spec-v1",
        ));
    }
    let product = parts
        .next()
        .and_then(|part| part.strip_prefix("product="))
        .ok_or_else(|| bad_comment("the signed comment has no product"))?;
    let signed_at = parts
        .next()
        .and_then(|part| part.strip_prefix("signed_at="))
        .ok_or_else(|| bad_comment("the signed comment has no signed_at"))?;
    if parts.next().is_some() {
        return Err(bad_comment("the signed comment has extra text"));
    }
    let product = ProductSlug::new(product)
        .map_err(|_| bad_comment("the signed comment names an invalid product"))?;
    if !valid_timestamp(signed_at) {
        return Err(bad_comment(
            "signed_at is not a time like 2026-11-30T16:02:11Z",
        ));
    }
    Ok((product, signed_at.to_owned()))
}

/// True for `YYYY-MM-DDTHH:MM:SSZ` with a real date and time of day. Nothing else, not even `+00:00`.
pub(crate) fn valid_timestamp(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 20 {
        return false;
    }
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    let fits = b.iter().zip(shape).all(|(&c, &s)| match s {
        b'd' => c.is_ascii_digit(),
        other => c == other,
    });
    if !fits {
        return false;
    }
    let num = |from: usize, to: usize| -> u32 {
        b[from..to]
            .iter()
            .fold(0, |n, &c| n * 10 + u32::from(c - b'0'))
    };
    let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && num(11, 13) < 24 && num(14, 16) < 60 && num(17, 19) < 60
}

/// Strict ed25519 verification: `S` must be canonical, and a small-order `R` or key is refused.
fn ed25519_verify(key: &VerifyingKey, message: &[u8], signature: &[u8; 64]) -> bool {
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// BLAKE2b-512 of `bytes`, the message that a prehashed minisign signature covers.
fn prehash(bytes: &[u8]) -> [u8; 64] {
    use blake2::{Blake2b512, Digest};
    Blake2b512::digest(bytes).into()
}

/// What checking one pinned key against a signature found.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyCheck {
    /// The file and the comment both verify.
    Verified,
    /// The signature over the file verifies, and the signature over the trusted comment does not.
    CommentDoesNotMatch,
    /// The signature over the file does not verify.
    FileDoesNotMatch,
}

/// Checks that a pinned key signed `bytes` with the signed comment in `sidecar`.
fn verify_with(key: &PublicKey, bytes: &[u8], sidecar: &Sidecar<'_>) -> KeyCheck {
    if !ed25519_verify(key.verifying_key(), &prehash(bytes), &sidecar.signature) {
        return KeyCheck::FileDoesNotMatch;
    }
    // The global signature covers the signature and the trusted comment, so the comment is signed.
    let mut global = Vec::with_capacity(64 + sidecar.comment.len());
    global.extend_from_slice(&sidecar.signature);
    global.extend_from_slice(sidecar.comment.as_bytes());
    if ed25519_verify(key.verifying_key(), &global, &sidecar.global_signature) {
        KeyCheck::Verified
    } else {
        KeyCheck::CommentDoesNotMatch
    }
}

/// Verifies `bytes` against the signature file `sidecar` and returns the provenance.
///
/// This reads and verifies. It never parses YAML. `bytes` are the raw spec bytes exactly as read.
pub(crate) fn verify_sidecar(
    bytes: &[u8],
    sidecar: &[u8],
    trust: &TrustStore,
) -> Result<SignatureState, SignatureError> {
    let parsed = parse_sidecar(sidecar)?;
    // The comment is not trusted yet. It only picks which pinned keys to try.
    let candidates: Vec<&Pin> = trust
        .pins_for(&parsed.product)
        .filter(|pin| pin.key.key_id() == parsed.key_id)
        .collect();
    if candidates.is_empty() {
        return Err(SignatureError::UnknownKey {
            key_id: parsed.key_id,
            product: parsed.product,
        });
    }
    let mut comment_failed = false;
    // When one key is pinned from several places, report the strongest place, not the first one tried.
    let mut best: Option<&Pin> = None;
    for pin in candidates {
        match verify_with(&pin.key, bytes, &parsed) {
            KeyCheck::Verified => {
                if best.is_none_or(|b| pin.source < b.source) {
                    best = Some(pin);
                }
            }
            KeyCheck::CommentDoesNotMatch => comment_failed = true,
            KeyCheck::FileDoesNotMatch => {}
        }
    }
    if let Some(pin) = best {
        return Ok(SignatureState::Verified {
            key_id: parsed.key_id,
            fingerprint: pin.key.fingerprint(),
            product: parsed.product.clone(),
            signed_at: parsed.signed_at.clone(),
            trust_source: pin.source,
        });
    }
    if comment_failed {
        // The file is what the key signed. The edit is in the signed comment.
        Err(SignatureError::CommentTampered)
    } else {
        Err(SignatureError::Tampered {
            crlf: bytes.windows(2).any(|pair| pair == b"\r\n"),
        })
    }
}

#[cfg(test)]
mod tests;
