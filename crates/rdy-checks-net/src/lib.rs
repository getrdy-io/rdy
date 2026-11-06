//! The `net.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! Built so far: `net.egress` (staged: lookup, dual-stack connect, TLS and ALPN, M1-095). Every call
//! goes through the probe facade, which owns the sockets, the address policy and the trust roots.

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

mod egress;
mod family;

pub use egress::EgressCheck;
pub use family::NetFamily;
