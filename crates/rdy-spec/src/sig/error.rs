//! Why a signature was refused.

use thiserror::Error;

use super::KeyId;
use crate::spec::ProductSlug;

/// Why a spec signature, or a public key, was refused.
///
/// Each variant is one distinct cause, so a caller can map them to the error codes of
/// `docs/plan/01-spec-format.md` section 4.8 and a test can tell them apart. All of them are exit 64.
/// [`SignatureError::hint`] is never empty.
///
/// No message and no hint names the flag that allows an unsigned spec, or the flag that trusts a key for
/// one run. A present signature that fails is never something to wave through (ADR 0002 decision 7).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The spec has no signature, and the policy needs one. Code `spec_unsigned`.
    #[error("the spec has no signature")]
    Missing,
    /// The signature file is larger than 4 KiB.
    #[error("the signature file is {size} bytes. The limit is {limit} bytes")]
    SidecarTooLarge {
        /// The size of the signature file in bytes.
        size: usize,
        /// The largest signature file rdy reads, in bytes.
        limit: usize,
    },
    /// The signature file is not a minisign signature. Code `spec_signature_invalid`, form.
    #[error("the signature is not in the form rdy accepts: {reason}")]
    Malformed {
        /// What is wrong, in fixed words.
        reason: &'static str,
    },
    /// The signature is a legacy `Ed` signature, which signs the file without hashing it first.
    #[error("the signature is not in the form rdy accepts: it is a legacy signature")]
    LegacyAlgorithm,
    /// The signed comment is not `rdy-spec-v1 product=<slug> signed_at=<time>`.
    #[error("the signature is not in the form rdy accepts: {reason}")]
    BadComment {
        /// What is wrong, in fixed words.
        reason: &'static str,
    },
    /// No key pinned for the signed product has the key id of the signature.
    #[error("the spec is signed with key {key_id}, which you have not trusted for {product}")]
    UnknownKey {
        /// The key id the signature carries.
        key_id: KeyId,
        /// The product the signed comment names.
        product: ProductSlug,
    },
    /// The file, or the signed comment, does not match the signature.
    #[error(
        "the signature does not match the file. It may have been changed after signing.{}",
        if *.crlf { " The file has Windows line endings. If it went through Git or email, ask for the original." } else { "" }
    )]
    Tampered {
        /// The file holds a CR LF pair. Line-ending conversion is the usual honest cause.
        crlf: bool,
    },
    /// The product in the signed comment is not the product in the spec.
    #[error("the spec is signed for product '{signed}', but it says '{spec}'")]
    ProductMismatch {
        /// The product the signed comment names.
        signed: ProductSlug,
        /// The product `metadata.product` names.
        spec: ProductSlug,
    },
    /// A public key is not a minisign ed25519 key.
    #[error("the public key is not usable: {reason}")]
    BadKey {
        /// What is wrong, in fixed words.
        reason: &'static str,
    },
    /// A public key has small order, so it would accept signatures that nobody made.
    #[error("the public key is a weak key and cannot be trusted")]
    WeakKey,
}

impl SignatureError {
    /// The fix line for this error. Never empty, and never names a flag that skips or weakens the check.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Missing => {
                "ask the vendor for the .minisig file and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned"
            }
            Self::UnknownKey { .. } => {
                "get the vendor's public key from their docs, compare its fingerprint with what the vendor tells you, then pin it with rdy trust add."
            }
            Self::BadKey { .. } | Self::WeakKey => {
                "get the public key again from the vendor's docs. Do not use a key from anywhere else."
            }
            Self::SidecarTooLarge { .. }
            | Self::Malformed { .. }
            | Self::LegacyAlgorithm
            | Self::BadComment { .. }
            | Self::Tampered { .. }
            | Self::ProductMismatch { .. } => {
                "get a fresh copy and its .minisig from the vendor. Do not run this file."
            }
        }
    }
}
