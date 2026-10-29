//! Start-up hardening on the real binary (M1-168, ADR 0023).
//!
//! The shell hands the binary descriptor 7 with `exec ... 7>/dev/null`, which leaves it open without
//! close-on-exec. That is how an operator's shell leaks one, and it needs no `unsafe` here.
//!
//! The runner may leave descriptors of its own open, so these tests look only at the descriptor
//! numbers they set up, and read the numbers out of the warning exactly.

mod common;

/// The descriptor numbers named in one warning line. The tail `and N more` is not a descriptor.
#[cfg(unix)]
fn listed(line: &str) -> Vec<u32> {
    let after = line
        .split_once("rdy inherited open file descriptor")
        .map_or("", |(_, rest)| rest);
    // "descriptor 7, and the ..." or "descriptors 3, 7, and the ...": skip an optional "s".
    let list = after
        .trim_start_matches('s')
        .split_once(", and the commands")
        .map_or("", |(list, _)| list);
    list.split(',')
        .filter_map(|part| part.split_whitespace().next()?.parse().ok())
        .collect()
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Output};

    use super::{common, listed};

    const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n    severity: block\n    fix: Use a node with at least 8 vCPUs.\n";

    fn rdy_via_sh(script: &str, args: &[&str]) -> Output {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg(env!("CARGO_BIN_EXE_rdy"))
            .args(args)
            .env_remove("RDY_PROGRESS")
            .output()
            .unwrap_or_else(|e| panic!("sh did not start rdy: {e}"))
    }

    fn rdy_with_fd7(args: &[&str]) -> Output {
        rdy_via_sh(r#"exec "$0" "$@" 7>/dev/null"#, args)
    }

    fn warning_lines(stderr: &str) -> Vec<&str> {
        stderr
            .lines()
            .filter(|l| l.starts_with(common::FD_WARNING_PREFIX))
            .collect()
    }

    #[test]
    fn an_inherited_descriptor_gets_one_warning_on_stderr() {
        let out = rdy_with_fd7(&["version"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let warnings = warning_lines(&stderr);
        assert_eq!(warnings.len(), 1, "{stderr}");
        assert!(listed(warnings[0]).contains(&7), "{}", warnings[0]);
        assert!(warnings[0].contains("7>&-"), "{}", warnings[0]);
        assert_eq!(out.status.code(), Some(0), "{stderr}");
    }

    #[test]
    fn the_warning_never_reaches_stdout_with_json() {
        let out = rdy_with_fd7(&["version", "--json"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(warning_lines(&stderr).len(), 1, "{stderr}");
        assert!(!stdout.contains("warning"), "{stdout}");
        let value: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON: {e}: {stdout}"));
        assert!(value.is_object(), "{stdout}");
    }

    #[test]
    fn a_closed_descriptor_gets_no_warning_about_it() {
        let out = rdy_via_sh(r#"exec "$0" "$@" 7>&-"#, &["version"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The test harness may leave its own descriptors open, so only descriptor 7 is checked.
        for line in warning_lines(&stderr) {
            assert!(!listed(line).contains(&7), "{line}");
        }
    }

    #[test]
    fn the_warning_lines_are_the_only_thing_the_test_helper_drops() {
        let out = rdy_with_fd7(&["--bogus"]);
        let quiet = common::without_fd_warning(&out.stderr);
        let quiet = String::from_utf8_lossy(&quiet);
        assert_eq!(quiet.lines().count(), 2, "{quiet}");
        assert!(quiet.starts_with("error: "), "{quiet}");
        assert!(quiet.contains("\nfix: "), "{quiet}");
        assert_eq!(
            common::without_fd_warning(b"warning: rdy inherited open file descriptors 3, 4, and the commands it runs inherit them.\nerror: x\n"),
            b"error: x\n"
        );
        assert_eq!(
            common::without_fd_warning(b"warning: something else\n"),
            b"warning: something else\n"
        );
    }

    #[test]
    fn the_listed_numbers_are_parsed_exactly() {
        let line = "warning: rdy inherited open file descriptors 3, 70, and the commands it runs inherit them.";
        assert_eq!(listed(line), [3, 70]);
        assert!(!listed(line).contains(&7));
        let capped = "warning: rdy inherited open file descriptors 3, 4, 5, 6, 7, 8, 9, 10 and 12 more, and the commands it runs inherit them.";
        assert_eq!(listed(capped), [3, 4, 5, 6, 7, 8, 9, 10]);
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o7777
    }

    /// File modes are exact under umask 000, the loosest there is: 0600 for the secret key, 0644 for
    /// the public key and the signature. The modes are set explicitly, so this does not prove that
    /// `harden_umask` ran. `startup_umask.rs` proves the 077.
    #[test]
    fn files_rdy_creates_ignore_a_umask_of_000() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        std::fs::write(dir.path().join("acme-platform.yaml"), SPEC)
            .unwrap_or_else(|e| panic!("write spec: {e}"));
        let run = |args: &[&str]| {
            let out = common::quiet(
                Command::new("sh")
                    .arg("-c")
                    .arg(r#"umask 000; exec "$0" "$@""#)
                    .arg(env!("CARGO_BIN_EXE_rdy"))
                    .args(args)
                    .current_dir(dir.path())
                    .env_remove("RDY_PROGRESS")
                    .env_remove("RDY_KEY_PASSWORD")
                    .output()
                    .unwrap_or_else(|e| panic!("sh did not start rdy: {e}")),
            );
            assert_eq!(
                out.status.code(),
                Some(0),
                "rdy {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["spec", "keygen", "k", "--unencrypted"]);
        run(&[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
        ]);
        assert_eq!(mode_of(&dir.path().join("k.key")), 0o600);
        assert_eq!(mode_of(&dir.path().join("k.pub")), 0o644);
        assert_eq!(
            mode_of(&dir.path().join("acme-platform.yaml.minisig")),
            0o644
        );
    }
}

/// Windows has no descriptor directory, so the warning never prints there.
#[cfg(windows)]
mod windows {
    use std::process::Command;

    use super::common;

    #[test]
    fn the_inherited_descriptor_warning_never_prints() {
        let out = Command::new(env!("CARGO_BIN_EXE_rdy"))
            .arg("version")
            .env_remove("RDY_PROGRESS")
            .output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        assert!(!stderr.contains("rdy inherited"), "{stderr}");
        assert!(!stderr.contains(common::FD_WARNING_PREFIX), "{stderr}");
    }
}
