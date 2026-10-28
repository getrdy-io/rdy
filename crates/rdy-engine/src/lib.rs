//! The rdy check engine.
//!
//! It runs checks, applies timeouts and renders reports. It is a skeleton for now.
//! The [`check`] module holds the check contract and [`outcome`] maps what a check returns to a result
//! entry. The scheduler, the probe facade and the renderers
//! arrive in later M1 tickets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod check;
pub mod outcome;
