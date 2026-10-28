//! Proves that code outside the crate cannot build a `LoadedSpec`.
//!
//! Each file in `compile_fail/` must fail to compile, and its `.stderr` file records the exact error. A
//! rustdoc `compile_fail` test would not do alone, because stable rustdoc does not check the error code,
//! so a typo in such a test would pass for the wrong reason.
//!
//! After a toolchain bump, refresh the `.stderr` files with `TRYBUILD=overwrite` and read the diff.

#[test]
fn loaded_spec_cannot_be_built_outside_load() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
}
