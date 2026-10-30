//! The registry of the checks this crate has built.

use rdy_engine::check::CheckInfo;

use crate::{rbac, version};

/// Every `k8s.*` check this crate has built, in catalog order.
static INFOS: [&CheckInfo; 2] = [&rbac::INFO, &version::INFO];

/// The `CheckInfo` of every `k8s.*` check this crate has built.
///
/// Every k8s check registers its info here. The citation test in `client/guard/tests/parser.rs` reads
/// this list and requires that each check id cited by `ALLOWED` is either here or on its `NOT_BUILT_YET`
/// list, and never both. So each check ticket (M1-110, M1-111, M1-113 and M1-114 are still to come) adds
/// its info here and removes its id from `NOT_BUILT_YET` in the same change. M1-115 requires
/// `NOT_BUILT_YET` to be empty.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the k8s family (M1-107) reads it")
)]
pub(crate) fn infos() -> &'static [&'static CheckInfo] {
    &INFOS
}
