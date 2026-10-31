//! The `net.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds [`MtuCheck`] (`net.mtu`, M1-157) and [`NetFamily`], which builds it from its
//! spec entry. The family lists only the checks that exist: the other `net.*` ids are reserved, so the
//! planner skips them with `skip_kind: not_in_build` until their tickets add them here. Every check
//! compiles on every target. Where a data source is not built, the check is `NotYet` on that OS, and the
//! planner skips it with `skip_kind: not_yet_on_os` before it runs.
//!
//! The OS comes from the run, never from the compiler, so a Linux fixture runs the Linux code on every CI
//! leg.

#![forbid(unsafe_code)]
// A check writes its answer in a Finding, never to the terminal (M1-044, 02 "Lint wall"). The print macros
// are also in clippy.toml `disallowed-macros`; these lints are the second line.
#![deny(clippy::print_stdout, clippy::print_stderr)]
// The wall is not for a check to lift. `forbid` makes any `allow`, `expect` or `warn` of these lints a
// compile error under clippy, including one a macro builds from tokens (M1-044, 02 "Lint wall"). The
// token grep in tests/lint-wall/tests/allow_grep.rs is the second layer.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
#![warn(missing_docs)]

mod family;
mod mtu;
mod text;

pub use family::NetFamily;
pub use mtu::MtuCheck;
