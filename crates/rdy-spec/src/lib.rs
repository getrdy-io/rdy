//! The `rdy/v1` spec and result formats.
//!
//! This crate is the source of truth for the wire types. Today it holds the spec types in [`spec`], the
//! typed scalars in [`scalar`], the YAML reader [`parse_unverified`], the two-step check decoding in
//! [`check`], the signature checks in [`sig`], the result types and the verdict rule in [`result`], and
//! the [`LoadedSpec`] guarantee. [`reserved`] lists the check ids that are reserved and [`lint`] turns a
//! decoded entry into a finding. The JSON schemas arrive in later M1 tickets.
//!
//! Two kinds of spec value exist, on purpose:
//!
//! - [`spec::Spec`] is what a file says. It is untrusted. Nothing proves who wrote it.
//! - [`LoadedSpec`] is a spec that [`load`] verified before parsing it. Only `load` can build one.
//!
//! [`load`] takes the raw bytes, the contents of the `.minisig` file if there is one, a [`sig::TrustStore`]
//! and a [`sig::Policy`]. It checks the minisign signature on the raw bytes, then the signed product, and
//! only then parses. The result records how the spec was authenticated ([`sig::SignatureState`]).
//!
//! [`parse_unverified`] reads a file into the first kind. It is for `rdy spec lint` and `rdy verify`
//! diagnostics only. A run, including an `--allow-unsigned` run, goes through [`load`] with
//! [`sig::Policy::AllowUnsigned`]. Nothing turns the result of `parse_unverified` into a [`LoadedSpec`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod check;
mod error;
pub mod lint;
mod loaded;
mod parse;
pub mod reserved;
pub mod result;
pub mod scalar;
pub mod sig;
pub mod spec;

pub use error::{Location, SpecError, echo_capped};
pub use loaded::{LoadedSpec, load};
pub use parse::{MAX_DEPTH, MAX_SPEC_BYTES, parse_unverified};
pub use scalar::{Duration, Quantity, ScalarError, Target, Version};

/// The `apiVersion` every `rdy/v1` document carries.
pub const API_VERSION: &str = "rdy/v1";
