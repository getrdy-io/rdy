//! The `k8s.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! This crate holds the [`client`] module, the checks, and the [`Cluster`] a check reads. The client finds the
//! operator's kubeconfig (or the in-cluster config), builds the kube client with rustls and timeouts, and
//! shows which cluster rdy is about to touch. The read-only guard ([`client::guard`], M1-103) sits in front
//! of every request and logs each one. The checks build on both: `k8s.version` ([`VersionCheck`], M1-106),
//! `k8s.access` ([`AccessCheck`], M1-109, which reads a [`Dial`] because it must report a connection
//! that failed), `k8s.storageclass` ([`StorageClassCheck`], M1-110), `k8s.rbac` ([`RbacCheck`], M1-111,
//! which can test as the spec's `as:` user) and `k8s.admission` ([`AdmissionCheck`], M1-114, the Pod
//! Security, policy engine and SCC half) and `k8s.namespace` ([`NamespaceCheck`], M1-161, existence,
//! terminating, quota and limit range), `k8s.dns` ([`DnsCheck`], M1-162, the cluster DNS workload,
//! Service, Corefile and restart evidence) and `k8s.ingress` ([`IngressCheck`], M1-163, ingress classes by
//! controller, the Gateway API, the OpenShift Route API and pending load balancers) and `k8s.crds`
//! ([`CrdsCheck`], M1-164, definitions, served versions and operator versions) are built, and the
//! others follow. [`K8sFamily`] (M1-107) lists them,
//! builds `k8s.version` and `k8s.access` from a spec entry, and probes the `kube_context` need once per run.
//!
//! The `testing` feature (M1-185) adds the `testing` module: a scripted cluster that serves a fixture's `api/`
//! tree in process, with the guard in front, for the env harness of `rdy`. The shipped binary never builds it.

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

#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod access;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod admission;
pub mod client;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod cluster;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod crds;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod dns;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod family;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod ingress;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod namespace;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod nodes;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod provisioners;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod rbac;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod registry;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod storageclass;
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
mod version;

// The scripted cluster of the env harness (M1-185). Only with the `testing` feature, which the shipped
// binary never enables (the module holds the release-build guard).
#[cfg(any(test, feature = "testing"))]
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
pub mod testing;

pub use access::{AccessCheck, Dial, DialOutcome, Dialed, PatternError};
pub use admission::AdmissionCheck;
pub use cluster::Cluster;
pub use crds::CrdsCheck;
pub use dns::DnsCheck;
pub use family::K8sFamily;
pub use ingress::IngressCheck;
pub use namespace::NamespaceCheck;
pub use nodes::NodesCheck;
pub use rbac::RbacCheck;
pub use storageclass::StorageClassCheck;
pub use version::VersionCheck;
