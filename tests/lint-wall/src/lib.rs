//! The lint wall test crate (M1-044, INV-07, ADR 0014 decision 7).
//!
//! The library is empty on purpose. With the `use-all` feature it holds `uses.rs`, which uses every item
//! the clippy.toml files ban, once each. `tests/clippy_wall.rs` runs clippy on it and expects each use to
//! be reported. See the Cargo.toml for why the feature is off by default.
//!
//! The other tests here are `tests/allow_grep.rs` (an allow attribute outside the allowlisted files) and
//! `tests/deny_wrappers.rs` (a check crate that depends on `socket2` or `walkdir`).

#![forbid(unsafe_code)]

#[cfg(feature = "use-all")]
mod uses;
