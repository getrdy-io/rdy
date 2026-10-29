//! The registry of the checks this crate has built.

use rdy_engine::check::CheckInfo;

/// The `CheckInfo` of every `k8s.*` check this crate has built.
///
/// Every k8s check registers its info here. The citation test in `client/guard/tests/parser.rs` reads
/// this list and requires that each check id cited by `ALLOWED` is either here or on its `NOT_BUILT_YET`
/// list, and never both. So each check ticket (M1-106, M1-110, M1-111, M1-113 and M1-114) adds its info
/// here and removes its id from `NOT_BUILT_YET` in the same change. M1-115 requires `NOT_BUILT_YET` to be
/// empty. The crate has no check yet, so the list is empty.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the first k8s check (M1-106) reads it")
)]
pub(crate) fn infos() -> &'static [&'static CheckInfo] {
    &[]
}
