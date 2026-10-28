//! The `host.*` check family.
//!
//! Internal to rdy. No API stability promise.
//!
//! So far this crate holds the OS support table and a stub for each host check (M1-067). The real
//! checks replace the stubs one ticket at a time (M1-068 and later). Every check compiles on every
//! target. Where a data source is not built, the check is `NotYet` on that OS, and the planner skips
//! it with `skip_kind: not_yet_on_os` before it runs.
//!
//! The OS comes from the run, never from the compiler. The planner takes it as an argument and the
//! stubs read it from `CheckContext::os`, so a Linux fixture runs the Linux code on every CI leg. When
//! the real checks arrive, only the closures that call the OS (the `native` probe calls) are gated with
//! `#[cfg(target_os = ..)]`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod family;

pub use family::HostFamily;
