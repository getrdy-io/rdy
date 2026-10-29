//! The `net.*` check family.
//!
//! Internal to rdy. No API stability promise. This is a skeleton for now.

#![forbid(unsafe_code)]
// A check writes its answer in a Finding, never to the terminal (M1-044, 02 "Lint wall"). The print macros
// are also in clippy.toml `disallowed-macros`; these lints are the second line.
#![deny(clippy::print_stdout, clippy::print_stderr)]
#![warn(missing_docs)]
