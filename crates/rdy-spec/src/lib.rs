//! The `rdy/v1` spec and result formats.
//!
//! This crate is the source of truth for the wire types. Today it holds the spec types in [`spec`], the
//! typed scalars in [`scalar`], the YAML reader [`parse_unverified`], the two-step check decoding in
//! [`check`], the signature checks in [`sig`], the result types and the verdict rule in [`result`], and
//! the [`LoadedSpec`] guarantee. [`reserved`] lists the check ids that are reserved and [`lint`] turns a
//! decoded entry into a finding and a spec file into a [`lint::LintReport`] with a line and column for
//! each finding. The JSON schemas of the spec and the result are generated from these types by the
//! `schema` module, which the `schema` feature turns on.
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
mod expiry;
mod limits;
pub mod lint;
mod loaded;
mod parse;
#[doc(hidden)]
pub mod pattern;
pub mod reserved;
pub mod result;
pub mod scalar;
#[cfg(feature = "schema")]
pub mod schema;
pub mod sig;
pub mod spec;
mod suggest;

#[doc(hidden)]
pub use error::echo_capped;
pub use error::{Location, SpecError};
pub use limits::{MAX_CHECKS, MAX_ENDPOINTS, MAX_HOSTS};
pub use loaded::{LoadedSpec, load, load_at};
pub use parse::{MAX_DEPTH, MAX_SPEC_BYTES, parse_unverified};
pub use scalar::{Duration, Quantity, ScalarError, Target, Version};
#[doc(hidden)]
pub use suggest::did_you_mean;

/// The `apiVersion` every `rdy/v1` document carries.
pub const API_VERSION: &str = "rdy/v1";

/// The version of this crate, such as `0.1.0`. A result records it as `producer.rdy_spec`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
