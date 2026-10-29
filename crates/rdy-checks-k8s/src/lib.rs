//! The `k8s.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds the [`client`] module: it finds the operator's kubeconfig (or the in-cluster
//! config), builds the kube client with rustls and timeouts, and shows which cluster rdy is about to
//! touch. The read-only guard ([`client::guard`], M1-103) sits in front of every request and logs each one;
//! the checks (M1-106 and later) build on both.

#![forbid(unsafe_code)]
// A check writes its answer in a Finding, never to the terminal (M1-044, 02 "Lint wall"). The print macros
// are also in clippy.toml `disallowed-macros`; these lints are the second line.
#![deny(clippy::print_stdout, clippy::print_stderr)]
#![warn(missing_docs)]
// The wall is not for a check to lift, and `client` is the one module that may (it builds the one guarded
// kube client). A `forbid` at the root would make the `allow` in `client` an error, so the root has none
// and every other module carries it: `#[forbid(clippy::disallowed_methods, clippy::disallowed_types,
// clippy::disallowed_macros)] mod checks;`. It makes any `allow`, `expect` or `warn` of those lints a
// compile error under clippy, including one a macro builds from tokens. The lint-wall test
// `a_check_crate_forbids_the_disallowed_lints_so_no_macro_can_allow_them` requires it, and allows only
// `mod` and `use` items at this root.

pub mod client;
