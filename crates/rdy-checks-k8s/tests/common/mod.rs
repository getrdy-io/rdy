//! Helpers the integration tests share.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers, write kubeconfigs and run plugin
// scripts, which the lint wall bans in the rest of this crate (INV-07). This file is on the allowlist of
// tests/lint-wall/tests/allow_grep.rs. A test of a check does not belong here: use the probe.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

// ---- child processes ---------------------------------------------------------------------------------
//
// Some rules depend on the process environment (HTTPS_PROXY, RDY_TOKEN) or on stdin and stderr not being
// terminals. A test cannot change its own environment without `unsafe`, so it runs itself again as a
// child with the environment set. The child is the same test binary, told to run one test by name.

/// True in the child process.
pub fn is_child() -> bool {
    std::env::var_os("RDY_TEST_CHILD").is_some()
}

/// Runs the test `name` again in a child process with `envs` set. The child has no terminal: stdin is
/// null and stdout and stderr are pipes.
pub fn run_child(name: &str, envs: &[(&str, &str)]) -> std::process::Output {
    let exe = std::env::current_exe().expect("current exe");
    let output = std::process::Command::new(exe)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("RDY_TEST_CHILD", "1")
        .envs(envs.iter().copied())
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "the child failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    output
}
