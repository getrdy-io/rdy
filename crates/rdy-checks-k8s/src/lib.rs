//! The `k8s.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds the [`client`] module: it finds the operator's kubeconfig (or the in-cluster
//! config), builds the kube client with rustls and timeouts, and shows which cluster rdy is about to
//! touch. The read-only guard (M1-103) and the checks (M1-106 and later) build on it.

#![forbid(unsafe_code)]
// A check writes its answer in a Finding, never to the terminal (M1-044, 02 "Lint wall"). The print macros
// are also in clippy.toml `disallowed-macros`; these lints are the second line.
#![deny(clippy::print_stdout, clippy::print_stderr)]
#![warn(missing_docs)]

pub mod client;
