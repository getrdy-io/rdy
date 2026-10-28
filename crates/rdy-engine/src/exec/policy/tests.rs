//! Command policy tests. The rules that run before resolution are portable. The resolution tests run
//! real programs (`env`, `true`) and are Unix only; the Windows rule has its own test.

use super::*;

const SECOND: Duration = Duration::from_secs(1);

fn cmd(program: &'static str) -> Cmd {
    Cmd::new(program, SECOND)
}

#[test]
fn shells_and_the_sudo_family_are_refused_in_every_spelling() {
    for name in [
        "sh",
        "bash",
        "zsh",
        "dash",
        "cmd",
        "powershell",
        "pwsh",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "runas",
        "cmd.exe",
        "PowerShell.exe",
        "BASH",
        "Sudo",
    ] {
        let error = prepare(&cmd(name)).expect_err(name);
        assert_eq!(error, PolicyError::Refused { program: name }, "{name}");
    }
}

#[test]
fn the_refusal_names_a_fix() {
    let text = prepare(&cmd("sudo")).expect_err("refused").to_string();
    assert!(text.contains("Fix:"), "{text}");
}

#[test]
fn a_program_name_is_a_plain_file_name() {
    for name in [
        "",
        "/bin/true",
        "./true",
        "../true",
        "bin/true",
        r"..\true",
        "-true",
        ".hidden",
        "true;ls",
        "a b",
        "true\n",
        "tru\u{e9}",
        "a|b",
    ] {
        let error = prepare(&cmd(name)).expect_err(name);
        assert_eq!(
            error,
            PolicyError::InvalidProgram { program: name },
            "{name:?}"
        );
    }
}

#[test]
fn declared_variables_that_change_loading_are_refused() {
    for name in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "ld_preload",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PATH",
        "path",
        "LC_ALL",
        "IFS",
        "BASH_ENV",
        "LOCPATH",
        "HOSTALIASES",
    ] {
        let error = prepare(&cmd("true").env([(name, "x")])).expect_err(name);
        assert_eq!(error, PolicyError::RefusedEnv { name }, "{name}");
    }
}

#[test]
fn declared_variable_names_have_a_grammar_and_are_unique() {
    for name in ["", "1X", "A-B", "A=B", "A B", "A\u{e9}"] {
        let error = prepare(&cmd("true").env([(name, "x")])).expect_err(name);
        assert_eq!(error, PolicyError::InvalidEnv { name }, "{name:?}");
    }
    let error = prepare(&cmd("true").env([("HTTPS_PROXY", "a"), ("https_proxy", "b")]))
        .expect_err("duplicate");
    assert_eq!(
        error,
        PolicyError::DuplicateEnv {
            name: "https_proxy"
        }
    );
}

#[test]
fn the_stdout_cap_has_a_ceiling() {
    let error = prepare(&cmd("true").stdout_cap(MAX_STDOUT_CAP + 1)).expect_err("too large");
    assert_eq!(
        error,
        PolicyError::CapTooLarge {
            cap: MAX_STDOUT_CAP + 1
        }
    );
}

#[test]
fn the_fixed_search_path_matches_the_design() {
    assert_eq!(SEARCH_PATH, "/usr/sbin:/usr/bin:/sbin:/bin");
    assert_eq!(SEARCH_DIRS.join(":"), SEARCH_PATH);
    assert_eq!(MAX_STDOUT_CAP, 4 * 1024 * 1024);
}

#[test]
fn only_whoami_runs_on_windows_in_m1() {
    for name in ["whoami", "whoami.exe", "WHOAMI.EXE"] {
        assert_eq!(
            windows_program(name),
            Ok(PathBuf::from(r"C:\Windows\System32\whoami.exe")),
            "{name}"
        );
    }
    for name in ["ipconfig", "systeminfo.exe", "whoami2", "getenforce"] {
        assert_eq!(
            windows_program(name),
            Err(PolicyError::NotAllowedOnWindows { program: name }),
            "{name}"
        );
    }
}

#[cfg(windows)]
#[test]
fn on_windows_a_command_resolves_to_the_constant_path_only() {
    let spec = prepare(&cmd("whoami")).expect("whoami runs");
    assert!(format!("{spec:?}").contains("whoami.exe"));
    assert!(matches!(
        prepare(&cmd("ipconfig")),
        Err(PolicyError::NotAllowedOnWindows { .. })
    ));
}

#[test]
fn debug_output_shows_env_names_and_never_values() {
    let text = format!(
        "{:?}",
        cmd("true").env([("HTTPS_PROXY", "http://user:hunter2@proxy:3128")])
    );
    assert!(text.contains("HTTPS_PROXY"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::process::Command;

    use super::*;

    /// Leaks a string so it can stand in for a source constant. Tests only.
    fn constant(text: &Path) -> &'static str {
        Box::leak(
            text.to_str()
                .expect("utf-8 temp path")
                .to_owned()
                .into_boxed_str(),
        )
    }

    fn constants(dir: &'static str) -> &'static [&'static str] {
        Box::leak(Box::new([dir]))
    }

    fn write_exec(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    /// A temp directory that is not writable by others.
    fn trusted_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");
        dir
    }

    fn lines(out: &ExecOutput) -> Vec<String> {
        let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        lines
    }

    #[test]
    fn the_first_directory_in_the_list_wins() {
        let first = trusted_dir();
        let second = trusted_dir();
        write_exec(first.path(), "tool", "#!/bin/true\n");
        write_exec(second.path(), "tool", "#!/bin/true\n");
        let dirs = [first.path().to_path_buf(), second.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), Ok(first.path().join("tool")));
        assert_eq!(
            resolve_in("tool", &dirs[1..]),
            Ok(second.path().join("tool"))
        );
    }

    #[test]
    fn a_directory_that_is_not_listed_is_never_searched() {
        let fake = trusted_dir();
        let listed = trusted_dir();
        write_exec(fake.path(), "tool", "#!/bin/true\n");
        let dirs = [listed.path().to_path_buf()];
        assert_eq!(
            resolve_in("tool", &dirs),
            Err(PolicyError::NotFound { program: "tool" })
        );
    }

    #[test]
    fn a_file_that_is_not_executable_is_skipped() {
        let dir = trusted_dir();
        let path = dir.path().join("tool");
        fs::write(&path, "x").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let dirs = [dir.path().to_path_buf()];
        assert_eq!(
            resolve_in("tool", &dirs),
            Err(PolicyError::NotFound { program: "tool" })
        );
    }

    #[test]
    fn a_world_writable_file_or_directory_is_untrusted() {
        let dir = trusted_dir();
        let path = write_exec(dir.path(), "tool", "#!/bin/true\n");
        let dirs = [dir.path().to_path_buf()];
        fs::set_permissions(&path, fs::Permissions::from_mode(0o757)).expect("chmod");
        assert_eq!(
            resolve_in("tool", &dirs),
            Err(PolicyError::Untrusted { program: "tool" })
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).expect("chmod");
        assert_eq!(
            resolve_in("tool", &dirs),
            Err(PolicyError::Untrusted { program: "tool" })
        );
    }

    #[test]
    fn a_bad_declared_directory_is_refused() {
        for dir in ["relative/bin", "", "/opt/../etc", "/opt/./bin", "."] {
            let error = prepare(&cmd("true").extra_dirs(constants(dir))).expect_err(dir);
            assert_eq!(error, PolicyError::InvalidDir { dir }, "{dir:?}");
        }
    }

    #[test]
    fn a_declared_directory_resolves_after_the_fixed_ones() {
        let extra = trusted_dir();
        write_exec(extra.path(), "rdy-policy-probe-tool", "#!/bin/true\n");
        write_exec(extra.path(), "true", "#!/bin/true\n");
        let dir = constant(extra.path());
        let dirs = constants(dir);

        // A tool only the declared directory has resolves there.
        let spec = prepare(&cmd("rdy-policy-probe-tool").extra_dirs(dirs)).expect("resolves");
        assert!(
            format!("{spec:?}").contains(&format!("{dir}/rdy-policy-probe-tool")),
            "{spec:?}"
        );
        // A system tool of the same name is not shadowed.
        let spec = prepare(&cmd("true").extra_dirs(dirs)).expect("resolves");
        assert!(!format!("{spec:?}").contains(dir), "{spec:?}");
    }

    #[test]
    fn a_link_to_a_shell_is_refused() {
        let Ok(shell) = fs::canonicalize("/bin/sh") else {
            return;
        };
        let name = shell.file_name().and_then(|name| name.to_str()).map(stem);
        if !name.is_some_and(|name| is_refused(&name)) {
            // A multi-call binary such as busybox: its name is not on the list by design.
            return;
        }
        let extra = trusted_dir();
        symlink(&shell, extra.path().join("rdy-policy-link")).expect("symlink");
        let error = prepare(&cmd("rdy-policy-link").extra_dirs(constants(constant(extra.path()))))
            .expect_err("refused");
        assert_eq!(
            error,
            PolicyError::Refused {
                program: "rdy-policy-link"
            }
        );
    }

    #[test]
    fn a_missing_program_is_not_found_with_a_fix() {
        let error = prepare(&cmd("rdy-no-such-program")).expect_err("missing");
        assert_eq!(
            error,
            PolicyError::NotFound {
                program: "rdy-no-such-program"
            }
        );
        assert!(error.to_string().contains("Fix:"), "{error}");
    }

    #[tokio::test]
    async fn the_child_gets_the_fixed_environment_and_nothing_else() {
        let out = run(cmd("env").env([("HTTPS_PROXY", "http://proxy.invalid:3128")]))
            .await
            .expect("env runs");
        assert_eq!(
            lines(&out),
            [
                "HTTPS_PROXY=http://proxy.invalid:3128",
                "LC_ALL=C",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
            ]
        );
    }

    #[tokio::test]
    async fn the_output_caps_come_from_the_command() {
        let out = run(cmd("env").stdout_cap(8)).await.expect("env runs");
        assert_eq!(out.stdout.len(), 8);
        assert!(out.stdout_truncated);
    }

    #[tokio::test]
    async fn a_refused_command_starts_nothing() {
        let error = run(cmd("sh").args(["-c", "touch /nonexistent-rdy"]))
            .await
            .expect_err("refused");
        assert!(matches!(
            error,
            CommandError::Policy(PolicyError::Refused { .. })
        ));
    }

    /// The child role of the next test. It does nothing unless the parent set the marker.
    #[tokio::test]
    async fn parent_environment_probe() {
        let Some(fake_dir) = std::env::var_os("RDY_POLICY_FAKE_DIR") else {
            return;
        };
        // The set-up holds: this process has the hostile variables and a fake `env` first in PATH.
        assert!(std::env::var_os("LD_PRELOAD").is_some());
        let path = std::env::var_os("PATH").expect("PATH");
        assert!(
            path.to_string_lossy()
                .starts_with(&*fake_dir.to_string_lossy())
        );
        let out = run(cmd("env")).await.expect("env runs");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("FAKE"), "the fake env ran: {text}");
        assert!(!text.contains("LD_"), "{text}");
        assert!(!text.contains("DYLD_"), "{text}");
        assert!(
            text.contains("PATH=/usr/sbin:/usr/bin:/sbin:/bin"),
            "{text}"
        );
        println!("policy probe ok");
    }

    #[test]
    fn a_hostile_parent_environment_never_reaches_a_child() {
        let fake = trusted_dir();
        write_exec(fake.path(), "env", "#!/bin/echo FAKE\n");
        let fake_dir = fake.path().to_str().expect("utf-8");
        let exe = std::env::current_exe().expect("test binary");
        let output = Command::new(exe)
            .args([
                "--exact",
                "exec::policy::tests::unix::parent_environment_probe",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RDY_POLICY_FAKE_DIR", fake_dir)
            .env("PATH", format!("{fake_dir}:/usr/bin:/bin"))
            .env("LD_PRELOAD", "/nonexistent/rdy-hostile.so")
            .env("LD_LIBRARY_PATH", "/nonexistent")
            .env("DYLD_LIBRARY_PATH", "/nonexistent")
            .output()
            .expect("start the test binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(
            stdout.contains("policy probe ok"),
            "the probe did not run: {stdout}"
        );
    }
}
