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

use crate::SpecError;
use crate::spec::Spec;

/// A spec that [`load`] verified and parsed. This is the only kind of spec the engine runs.
///
/// There is no public way to build one except [`load`]. See the module docs for the compile-fail tests
/// that keep it that way. A [`Spec`] from the unverified parser is a different type and never converts
/// into this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSpec {
    spec: Spec,
}

impl LoadedSpec {
    /// The only constructor. It is private to this module, and so only [`load`] can call it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "load() cannot verify or parse yet. M1-017 and M1-120 wire it and remove this attribute"
        )
    )]
    fn new(spec: Spec) -> Self {
        Self { spec }
    }

    /// The verified spec.
    #[must_use]
    pub fn spec(&self) -> &Spec {
        &self.spec
    }
}

/// The only way to get a [`LoadedSpec`]: verify the raw bytes, then parse, then validate.
///
/// This is a stub. Signature checking (M1-120) and the YAML parser (M1-017) are not wired in, and `load`
/// must never hand back a spec that nothing verified. So for now it always fails closed with
/// [`SpecError::LoadNotWired`]. The final signature also takes the trust store and the signature policy.
///
/// # Errors
///
/// Always [`SpecError::LoadNotWired`] in this build.
pub fn load(_bytes: &[u8], _sig: Option<&[u8]>) -> Result<LoadedSpec, SpecError> {
    Err(SpecError::LoadNotWired)
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
    fn the_stub_fails_closed_for_every_input() {
        let yaml = b"apiVersion: rdy/v1\nkind: Readiness\n";
        assert_eq!(load(yaml, None).unwrap_err(), SpecError::LoadNotWired);
        assert_eq!(
            load(yaml, Some(b"sig")).unwrap_err(),
            SpecError::LoadNotWired
        );
        assert_eq!(load(b"", None).unwrap_err(), SpecError::LoadNotWired);
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
        let loaded = LoadedSpec::new(sample());
        assert_eq!(loaded.spec(), &sample());
    }
}
