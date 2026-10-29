//! The `k8s.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds the [`client`] module: it finds the operator's kubeconfig (or the in-cluster
//! config), builds the kube client with rustls and timeouts, and shows which cluster rdy is about to
//! touch. The read-only guard (M1-103) and the checks (M1-106 and later) build on it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
