//! The README transcript goldens that M1-135 makes in process from the Replay envs.
//!
//! This file is the one list. `env_harness/readme.rs` makes each golden from its env and compares it
//! with the file. `docs_test.rs` checks a README block against the same file, and lets a golden that no
//! block uses stand only when it is listed here.

/// The golden files under `tests/fixtures/readme/` that the generator owns.
pub const GENERATED: &[&str] = &[
    "refusal-unsigned.txt",
    "run-not-ready.txt",
    "run-ready.txt",
    "run-platform.txt",
];
