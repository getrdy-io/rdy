//! The `k8s.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds the [`client`] module: it finds the operator's kubeconfig (or the in-cluster
//! config), builds the kube client with rustls and timeouts, and shows which cluster rdy is about to
//! touch. The read-only guard ([`client::guard`], M1-103) sits in front of every request and logs each one;
//! the checks (M1-106 and later) build on both.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
