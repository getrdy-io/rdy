//! The `rdy/v1` spec and result formats.
//!
//! This crate is the source of truth for the wire types. Today it holds the spec types in [`spec`], the
//! typed scalars in [`scalar`] and the [`LoadedSpec`] guarantee. The YAML parser, signature checks, the
//! result model and the JSON schemas arrive in later M1 tickets.
//!
//! Two kinds of spec value exist, on purpose:
//!
//! - [`spec::Spec`] is what a file says. It is untrusted. Nothing proves who wrote it.
//! - [`LoadedSpec`] is a spec that [`load`] verified before parsing it. Only `load` can build one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod loaded;
pub mod scalar;
pub mod spec;

pub use error::SpecError;
pub use loaded::{LoadedSpec, load};
pub use scalar::{Duration, Quantity, ScalarError, Target, Version};

/// The `apiVersion` every `rdy/v1` document carries.
pub const API_VERSION: &str = "rdy/v1";
