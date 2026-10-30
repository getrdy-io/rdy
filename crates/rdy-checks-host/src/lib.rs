//! The `host.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds the OS support table, a stub for each host check that is not written yet
//! (M1-067), [`Firewall`] (`host.firewall`, M1-147) and [`CpuCheck`] (`host.cpu`, M1-071), which the
//! family builds from their spec entries (M1-172), and the cgroup helper ([`cgroup`], M1-065) that
//! `host.memory`, `host.cpu` and `host.cgroups` share. The real checks replace the stubs one ticket at a time (M1-068 and later). Every check
//! compiles on every target. Where a data source is not built, the check is `NotYet` on that OS, and the
//! planner skips it with `skip_kind: not_yet_on_os` before it runs.
//!
//! Rule: do not register [`HostFamily`] in the CLI while [`HostFamily::stub_ids`] is not empty. On Linux
//! a stub reports `error` with `check_failed`, which reads as a fault on the customer's machine. The
//! registering ticket (M1-057) must first drop the stubs or have the engine add a `not_in_build` skip.
//!
//! The OS comes from the run, never from the compiler. The planner takes it as an argument and the
//! stubs read it from `CheckContext::os`, so a Linux fixture runs the Linux code on every CI leg. When
//! the real checks arrive, only the closures that call the OS (the `native` probe calls) are gated with
//! `#[cfg(target_os = ..)]`.

#![forbid(unsafe_code)]
// A check writes its answer in a Finding, never to the terminal (M1-044, 02 "Lint wall"). The print macros
// are also in clippy.toml `disallowed-macros`; these lints are the second line.
#![deny(clippy::print_stdout, clippy::print_stderr)]
// The wall is not for a check to lift. `forbid` makes any `allow`, `expect` or `warn` of these lints a
// compile error under clippy, including one a macro builds from tokens (M1-044, 02 "Lint wall"). The
// token grep in tests/lint-wall/tests/allow_grep.rs is the second layer.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
#![warn(missing_docs)]

pub mod cgroup;
mod cpu;
mod family;
mod firewall;

pub use cpu::CpuCheck;
pub use family::HostFamily;
pub use firewall::Firewall;
