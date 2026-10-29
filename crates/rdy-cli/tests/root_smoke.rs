//! Canary for the `root` CI job (docs/plan/08-testing.md, section 6).
//!
//! The name starts with `root_`, so `.config/nextest.toml` keeps this test out of every nextest run
//! except the `root` profile. The `root` job in `ci.yml` runs that profile under `sudo` and sets
//! `RDY_REQUIRE_ROOT=1`. If the job ever stops running as root, this test goes red. If the `root_`
//! filter ever matches nothing, the job goes red too, because it passes `--no-tests=fail`. Keep this
//! test for as long as the job exists.
//!
//! Plain `cargo test` has no name filter. Without `RDY_REQUIRE_ROOT`, a non-root run returns early, so
//! `cargo test --workspace` stays green for a normal user. Every `root_*` test follows this rule.

#![cfg(target_os = "linux")]

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn root_whoami_is_zero() {
    if std::env::var_os("RDY_REQUIRE_ROOT").is_none() && !is_root() {
        eprintln!("skipped: needs uid 0 (the root job sets RDY_REQUIRE_ROOT=1)");
        return;
    }
    assert!(is_root(), "euid is not 0; the root job must run under sudo");
}
