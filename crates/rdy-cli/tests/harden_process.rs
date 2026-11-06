//! `startup::harden_process` (M1-058, security review S3), in a process of its own.
//!
//! The call lowers the core-file limit and marks the process not dumpable for good, so it runs here and
//! not in the unit-test process. No privilege is needed.
#![cfg(unix)]
// A failed OS call must fail the test.
#![allow(clippy::expect_used)]

use rustix::process::{Resource, getrlimit};

#[test]
fn harden_process_turns_core_dumps_off() {
    rdy_cli::startup::harden_process();
    let limit = getrlimit(Resource::Core);
    assert_eq!(limit.current, Some(0), "soft core limit");
    assert_eq!(limit.maximum, Some(0), "hard core limit");
    #[cfg(target_os = "linux")]
    assert_eq!(
        rustix::process::dumpable_behavior().expect("read the dumpable flag"),
        rustix::process::DumpableBehavior::NotDumpable
    );
}
