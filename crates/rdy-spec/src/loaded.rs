//! `LoadedSpec` and the one function that is allowed to build it.
//!
//! The guarantee (ADR 0002 and ADR 0012): a [`LoadedSpec`] only comes from [`load`], which verifies the
//! raw bytes before it parses them. The guarantee is enforced by Rust privacy and not by convention.
//! `LoadedSpec` has a private field and one private constructor, and both live in this module next to
//! `load`, so no other code in this crate or outside it can build one. The type has no `Default`, no
//! `From<Spec>` and no `Deserialize`.
//!
//! The compile-fail tests in `tests/compile_fail/` pin each way of getting this wrong: a struct literal,
//! the private constructor, `From<Spec>` and `Default`. The unit test below pins `Deserialize`.

use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::SpecError;
use crate::expiry::check_not_expired;
use crate::parse::{MAX_SPEC_BYTES, parse_bytes};
use crate::sig::{Policy, SignatureError, SignatureState, TrustStore, verify_sidecar};
use crate::spec::Spec;

/// The exact bytes [`load`] verified: the spec text and, for a signed spec, its `.minisig` sidecar.
///
/// The report folder holds a copy of these bytes (ADR 0016 decision 4), so the copy is what was
/// verified and not what the file holds a moment later. Like [`LoadedSpec`] this type has a private
/// field, no public constructor, no `Default`, no `From` and no `Deserialize`; [`load`] is the only
/// code that builds one. Read it through [`LoadedSpec::verified_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpecBytes {
    yaml: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl VerifiedSpecBytes {
    /// The spec text, byte for byte as it was verified and parsed.
    #[must_use]
    pub fn yaml(&self) -> &[u8] {
        &self.yaml
    }

    /// The `.minisig` sidecar that verified, byte for byte, or `None` for an unsigned spec.
    #[must_use]
    pub fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }
}

/// A spec that [`load`] verified and parsed. This is the only kind of spec the engine runs.
///
/// There is no public way to build one except [`load`]. See the module docs for the compile-fail tests
/// that keep it that way. A [`Spec`] from the unverified parser is a different type and never converts
/// into this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSpec {
    spec: Spec,
    signature: SignatureState,
    sha256: String,
    bytes: VerifiedSpecBytes,
}

impl LoadedSpec {
    /// The only constructor. It is private to this module, and so only [`load`] can call it.
    fn new(
        spec: Spec,
        signature: SignatureState,
        sha256: String,
        bytes: VerifiedSpecBytes,
    ) -> Self {
        Self {
            spec,
            signature,
            sha256,
            bytes,
        }
    }

    /// The verified spec.
    #[must_use]
    pub fn spec(&self) -> &Spec {
        &self.spec
    }

    /// How the spec was authenticated: verified with a pinned key, or unsigned and allowed.
    #[must_use]
    pub fn signature(&self) -> &SignatureState {
        &self.signature
    }

    /// SHA-256 of the raw spec bytes, 64 lowercase hex digits. Reports record it (threat model R1).
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The exact bytes that were verified, for the copy in the report folder.
    #[must_use]
    pub fn verified_bytes(&self) -> &VerifiedSpecBytes {
        &self.bytes
    }
}

/// The only way to get a [`LoadedSpec`]: check the signature on the raw bytes, then parse, then check
/// the product.
///
/// The order is the security property (ADR 0002, threat model INV-01):
///
/// 1. The spec is at most [`MAX_SPEC_BYTES`], or the call fails with [`SpecError::TooLarge`].
/// 2. With a signature (`sig` is the contents of the `.minisig` file), the file must verify. The signature
///    file must be in the minisign form, the signed comment must be `rdy-spec-v1 product=<slug>
///    signed_at=<time>`, and a key pinned in `trust` for that product must verify the exact bytes. This
///    happens whatever the policy says. A signature that fails is never treated as a missing one.
/// 3. Without a signature, [`Policy::RequireSigned`] fails with [`SignatureError::Missing`] and
///    [`Policy::AllowUnsigned`] goes on, and the result says [`SignatureState::Unsigned`].
/// 4. Only now are the bytes parsed. A spec that was refused above is never given to the YAML reader.
/// 5. For a signed spec, `metadata.product` must equal the product in the signed comment.
///
/// 6. Last, `metadata.expires` is compared with this machine's clock. A spec that has expired is refused
///    with [`SpecError::Expired`], for a signed spec and an unsigned one alike. There is no override.
///
/// Tests that must pin the clock use [`load_at`].
///
/// # Errors
///
/// [`SpecError::Signature`] for every signature problem, the usual parse errors of
/// [`crate::parse_unverified`] after that, and [`SpecError::Expired`] for a spec past its `expires`.
pub fn load(
    bytes: &[u8],
    sig: Option<&[u8]>,
    trust: &TrustStore,
    policy: Policy,
) -> Result<LoadedSpec, SpecError> {
    load_with_clock(bytes, sig, trust, policy, SystemTime::now())
}

/// [`load`] with the clock given, so a test decides what "now" is.
///
/// Only tests should call this. A caller that chooses the clock can defeat `metadata.expires`, so
/// `clippy.toml` bans it in the rest of the workspace (`disallowed-methods`). Test code allows it with
/// `#[allow(clippy::disallowed_methods)]`.
///
/// # Errors
///
/// The same as [`load`].
pub fn load_at(
    bytes: &[u8],
    sig: Option<&[u8]>,
    trust: &TrustStore,
    policy: Policy,
    now: SystemTime,
) -> Result<LoadedSpec, SpecError> {
    load_with_clock(bytes, sig, trust, policy, now)
}

fn load_with_clock(
    bytes: &[u8],
    sig: Option<&[u8]>,
    trust: &TrustStore,
    policy: Policy,
    now: SystemTime,
) -> Result<LoadedSpec, SpecError> {
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(SpecError::TooLarge {
            size: bytes.len(),
            limit: MAX_SPEC_BYTES,
        });
    }
    let signature = match (sig, policy) {
        (Some(sidecar), _) => verify_sidecar(bytes, sidecar, trust)?,
        (None, Policy::AllowUnsigned) => SignatureState::Unsigned,
        (None, Policy::RequireSigned) => return Err(SignatureError::Missing.into()),
    };
    let spec = parse_bytes(bytes)?;
    if let SignatureState::Verified { product, .. } = &signature
        && *product != spec.metadata.product
    {
        return Err(SignatureError::ProductMismatch {
            signed: product.clone(),
            spec: spec.metadata.product.clone(),
        }
        .into());
    }
    check_not_expired(spec.metadata.expires.as_deref(), now)?;
    let sha256 = crate::sig::hex(&Sha256::digest(bytes));
    let bytes = VerifiedSpecBytes {
        yaml: bytes.to_vec(),
        signature: sig.map(<[u8]>::to_vec),
    };
    Ok(LoadedSpec::new(spec, signature, sha256, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{CheckId, CheckSpec, Metadata, ProductSlug};

    fn sample() -> Spec {
        let product = ProductSlug::new("acme-platform").expect("slug");
        let check = CheckSpec::new(CheckId::new("host.cpu").expect("id"));
        Spec::new(Metadata::new(product), vec![check])
    }

    #[test]
    fn load_fails_closed_without_a_pinned_key() {
        let yaml = b"apiVersion: rdy/v1\nkind: Readiness\n";
        let trust = TrustStore::new();
        // No signature under the strict policy.
        assert_eq!(
            load(yaml, None, &trust, Policy::RequireSigned).unwrap_err(),
            SpecError::Signature(SignatureError::Missing)
        );
        // A signature that is not a signature never becomes "unsigned".
        for policy in [Policy::RequireSigned, Policy::AllowUnsigned] {
            for sig in [&b""[..], b"sig", b"untrusted comment: x\n"] {
                assert!(matches!(
                    load(yaml, Some(sig), &trust, policy).unwrap_err(),
                    SpecError::Signature(SignatureError::Malformed { .. })
                ));
            }
        }
    }

    /// Fails to compile if `LoadedSpec` ever implements `Deserialize`. Two blanket impls give the call
    /// below an ambiguous choice only when the type has the trait.
    #[test]
    fn loaded_spec_does_not_implement_deserialize() {
        trait AmbiguousIfDeserialize<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
        impl<T: for<'de> serde::Deserialize<'de>> AmbiguousIfDeserialize<u8> for T {}
        <LoadedSpec as AmbiguousIfDeserialize<_>>::check();
    }

    #[test]
    fn the_accessor_returns_what_the_constructor_was_given() {
        let loaded = LoadedSpec::new(
            sample(),
            SignatureState::Unsigned,
            "ab".to_owned(),
            VerifiedSpecBytes {
                yaml: b"x".to_vec(),
                signature: None,
            },
        );
        assert_eq!(loaded.spec(), &sample());
        assert_eq!(loaded.signature(), &SignatureState::Unsigned);
        assert_eq!(loaded.sha256(), "ab");
        assert_eq!(loaded.verified_bytes().yaml(), b"x");
        assert_eq!(loaded.verified_bytes().signature(), None);
    }
}
