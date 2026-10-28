//! The `rdy/v1` spec and result formats.
//!
//! This crate is the source of truth for the wire types. Today it holds the spec types in [`spec`], the
//! YAML reader [`parse_unverified`] and the [`LoadedSpec`] guarantee. The scalar types, signature checks,
//! the result model and the JSON schemas arrive in later M1 tickets.
//!
//! Two kinds of spec value exist, on purpose:
//!
//! - [`spec::Spec`] is what a file says. It is untrusted. Nothing proves who wrote it.
//! - [`LoadedSpec`] is a spec that [`load`] verified before parsing it. Only `load` can build one.
//!
//! [`parse_unverified`] reads a file into the first kind, for `rdy spec lint` and `--allow-unsigned`
//! runs. Nothing turns its result into the second kind.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod loaded;
mod parse;
pub mod spec;

pub use error::{Location, SpecError};
pub use loaded::{LoadedSpec, load};
pub use parse::{MAX_DEPTH, MAX_SPEC_BYTES, parse_unverified};

/// The `apiVersion` every `rdy/v1` document carries.
pub const API_VERSION: &str = "rdy/v1";
