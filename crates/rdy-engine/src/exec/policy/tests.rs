//! Command policy tests. The rules that run before resolution are portable. The resolution tests run
//! real programs (`printenv`, `true`) and are Unix only; the Windows rule has its own test.

use super::*;

const SECOND: Duration = Duration::from_secs(1);

fn cmd(program: &'static str) -> Cmd {
    Cmd::new(program, SECOND)
}

#[test]
fn shells_the_sudo_family_and_exec_wrappers_are_refused_in_every_spelling() {
    for name in [
        "sh",
        "bash",
        "zsh",
        "dash",
        "hush",
        "msh",
        "mksh",
        "yash",
        "rbash",
        "posh",
        "oksh",
        "loksh",
        "cmd",
        "powershell",
        "pwsh",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "runas",
        "run0",
        "sudoedit",
        "runuser",
        "setpriv",
        "sg",
        "newgrp",
        "ksu",
        "machinectl",
        "systemd-run",
        "env",
        "xargs",
        "nice",
        "nohup",
        "timeout",
        "setsid",
        "chroot",
        "nsenter",
        "unshare",
        "stdbuf",
        "taskset",
        "ionice",
        "chrt",
        "numactl",
        "prlimit",
        "flock",
        "watch",
        "capsh",
        "script",
        "strace",
        "ltrace",
        "gdb",
        "cgexec",
        "bwrap",
        "firejail",
        "systemd-nspawn",
        "busybox",
        "toybox",
        "BusyBox",
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
        "SystemRoot",
        "GLIBC_TUNABLES",
        "MALLOC_ARENA_MAX",
        "malloc_perturb_",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "OPENSSL_ENGINES",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PERL5LIB",
        "PERL5OPT",
        "RUBYLIB",
        "RUBYOPT",
        "NODE_OPTIONS",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "LESSOPEN",
        "PAGER",
        "EDITOR",
        "VISUAL",
        "SYSTEMD_PAGER",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "LUA_INIT",
        "LUA_PATH",
        "LUA_CPATH",
        "PERLLIB",
        "PERL5DB",
        "NODE_PATH",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_GLOBAL",
        "SSH_ASKPASS",
        "SUDO_ASKPASS",
        "BROWSER",
        "TERMINFO",
        "TERMINFO_DIRS",
        "KUBECONFIG",
        "DOTNET_STARTUP_HOOKS",
        "COR_PROFILER",
        "COR_PROFILER_PATH",
        "CORECLR_PROFILER",
        "CORECLR_PROFILER_PATH",
        "COMSPEC",
        "PATHEXT",
        "CUDA_INJECTION64_PATH",
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

#[cfg(windows)]
#[tokio::test]
async fn on_windows_whoami_runs_through_the_policy_and_cmd_is_refused() {
    let whoami = Cmd::new("whoami", Duration::from_secs(10));
    let out = run(whoami).await.expect("whoami runs");
    assert!(out.status.success(), "{out:?}");
    assert!(!out.stdout.is_empty());
    for name in ["cmd", "cmd.exe", "powershell"] {
        let error = run(cmd(name)).await.expect_err(name);
        assert!(
            matches!(error, CommandError::Policy(PolicyError::Refused { .. })),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn the_base_environment_fits_the_target() {
    let env = base_env();
    let names: Vec<String> = env
        .iter()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    if cfg!(unix) {
        assert_eq!(names, ["LC_ALL", "PATH"]);
        assert_eq!(env[1].1, OsString::from(SEARCH_PATH));
    } else {
        assert_eq!(names, ["SystemRoot", "PATH"]);
        assert_eq!(env[0].1, OsString::from(WINDOWS_SYSTEM_ROOT));
        assert_eq!(env[1].1, OsString::from(WINDOWS_PATH));
    }
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

    /// What `resolve_in` returns for a file: its real path.
    fn real(path: &Path) -> PathBuf {
        fs::canonicalize(path).expect("canonical")
    }

    fn mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn untrusted(program: &'static str) -> Result<PathBuf, PolicyError> {
        Err(PolicyError::Untrusted { program })
    }

    /// A uid that is neither root nor the user running the tests.
    const STRANGER: u32 = 31_337;

    /// Gives `path` to another user. Only root may; `false` means the test cannot run here.
    fn give_away(path: &Path) -> bool {
        std::os::unix::fs::chown(path, Some(STRANGER), None).is_ok()
    }

    #[test]
    fn the_first_directory_in_the_list_wins() {
        let first = trusted_dir();
        let second = trusted_dir();
        write_exec(first.path(), "tool", "#!/bin/true\n");
        write_exec(second.path(), "tool", "#!/bin/true\n");
        let dirs = [first.path().to_path_buf(), second.path().to_path_buf()];
        assert_eq!(
            resolve_in("tool", &dirs),
            Ok(real(&first.path().join("tool")))
        );
        assert_eq!(
            resolve_in("tool", &dirs[1..]),
            Ok(real(&second.path().join("tool")))
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
        mode(&path, 0o644);
        let dirs = [dir.path().to_path_buf()];
        assert_eq!(
            resolve_in("tool", &dirs),
            Err(PolicyError::NotFound { program: "tool" })
        );
    }

    #[test]
    fn a_world_or_group_writable_file_is_untrusted() {
        for bad in [0o757, 0o775, 0o777] {
            let dir = trusted_dir();
            let path = write_exec(dir.path(), "tool", "#!/bin/true\n");
            let dirs = [dir.path().to_path_buf()];
            mode(&path, bad);
            assert_eq!(resolve_in("tool", &dirs), untrusted("tool"), "{bad:o}");
        }
    }

    #[test]
    fn a_world_or_group_writable_directory_is_untrusted() {
        for bad in [0o777, 0o757, 0o775, 0o770] {
            let dir = trusted_dir();
            write_exec(dir.path(), "tool", "#!/bin/true\n");
            let dirs = [dir.path().to_path_buf()];
            mode(dir.path(), bad);
            assert_eq!(resolve_in("tool", &dirs), untrusted("tool"), "{bad:o}");
        }
    }

    #[test]
    fn a_sticky_writable_directory_is_accepted_only_above_the_files_own_directory() {
        let outer = trusted_dir();
        let inner = outer.path().join("inner");
        fs::create_dir(&inner).expect("mkdir");
        mode(&inner, 0o755);
        let path = write_exec(&inner, "tool", "#!/bin/true\n");
        let dirs = [inner.clone()];
        for sticky in [0o1777, 0o1775] {
            // One level up, like /tmp above a directory of ours: accepted.
            mode(outer.path(), sticky);
            assert_eq!(resolve_in("tool", &dirs), Ok(real(&path)), "{sticky:o}");
        }
        // The file's own directory is never excused: a hard link to a trusted file could be planted.
        mode(outer.path(), 0o755);
        for sticky in [0o1777, 0o1775] {
            mode(&inner, sticky);
            assert_eq!(resolve_in("tool", &dirs), untrusted("tool"), "{sticky:o}");
        }
        // The file is never excused either: a sticky bit does not help a writable leaf.
        mode(&inner, 0o755);
        mode(&path, 0o777);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
    }

    #[test]
    fn the_trust_rule_as_a_table() {
        const ME: u32 = 1000;
        // (uid, mode, sticky_excused, trusted)
        let table = [
            (0, 0o755, false, true),
            (ME, 0o755, false, true),
            (ME, 0o700, false, true),
            (STRANGER, 0o755, false, false),
            (STRANGER, 0o755, true, false),
            (0, 0o775, false, false),
            (0, 0o757, false, false),
            (0, 0o777, true, false),
            (0, 0o1777, false, false),
            (0, 0o1777, true, true),
            (0, 0o1775, true, true),
            (ME, 0o1757, true, true),
            (STRANGER, 0o1777, true, false),
            (0, 0o1755, false, true),
        ];
        for (uid, mode, sticky_excused, expected) in table {
            assert_eq!(
                trusted(uid, mode, ME, sticky_excused),
                expected,
                "uid {uid} mode {mode:o} excused {sticky_excused}"
            );
        }
        // Root is trusted even when the running user is someone else.
        assert!(trusted(0, 0o755, ME, false));
        assert!(!trusted(ME, 0o755, 2000, false));
    }

    #[test]
    fn a_writable_directory_higher_up_makes_the_file_untrusted() {
        let outer = trusted_dir();
        let inner = outer.path().join("inner");
        fs::create_dir(&inner).expect("mkdir");
        mode(&inner, 0o755);
        write_exec(&inner, "tool", "#!/bin/true\n");
        let dirs = [inner.clone()];
        assert!(resolve_in("tool", &dirs).is_ok());
        mode(outer.path(), 0o775);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
        mode(outer.path(), 0o757);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
    }

    /// Needs root to set up. The root job in CI sets `RDY_REQUIRE_ROOT`, and there a failure to give a
    /// file away is a failure of the test, not a reason to skip it.
    #[test]
    fn root_a_file_or_directory_owned_by_someone_else_is_untrusted() {
        let dir = trusted_dir();
        let path = write_exec(dir.path(), "tool", "#!/bin/true\n");
        let dirs = [dir.path().to_path_buf()];
        if !give_away(&path) {
            assert!(
                std::env::var_os("RDY_REQUIRE_ROOT").is_none(),
                "RDY_REQUIRE_ROOT is set but chown failed: this job is not root"
            );
            // Not root: giving a file away is not allowed, so the case cannot be set up.
            return;
        }
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));

        let other = trusted_dir();
        write_exec(other.path(), "tool", "#!/bin/true\n");
        assert!(give_away(other.path()));
        let dirs = [other.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
    }

    #[test]
    fn a_link_into_a_writable_tree_is_judged_by_where_it_points() {
        let safe = trusted_dir();
        let writable = trusted_dir();
        let target = write_exec(writable.path(), "real-tool", "#!/bin/true\n");
        symlink(&target, safe.path().join("tool")).expect("symlink");
        let dirs = [safe.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), Ok(real(&target)));
        // The link and its directory are fine. The tree it points into is not.
        mode(writable.path(), 0o777);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
        mode(writable.path(), 0o755);
        mode(&target, 0o777);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
        mode(&target, 0o755);
        // The directory that holds the link is judged as well.
        mode(safe.path(), 0o775);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
    }

    #[test]
    fn the_directory_that_holds_a_link_is_judged_like_the_directory_that_holds_the_file() {
        let safe = trusted_dir();
        let target = write_exec(safe.path(), "real-tool", "#!/bin/true\n");
        // The search directory holds the link. Group-writable, someone could re-point it.
        let holder = trusted_dir();
        symlink(&target, holder.path().join("tool")).expect("symlink");
        let dirs = [holder.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), Ok(real(&target)));
        mode(holder.path(), 0o775);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
        mode(holder.path(), 0o755);

        // A link in the middle of a chain: tool -> hop/second -> real-tool.
        let hop = trusted_dir();
        symlink(&target, hop.path().join("second")).expect("symlink");
        let first = trusted_dir();
        symlink(hop.path().join("second"), first.path().join("tool")).expect("symlink");
        let dirs = [first.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), Ok(real(&target)));
        mode(hop.path(), 0o777);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
        mode(hop.path(), 0o755);

        // A link in a directory on the way: tool -> linked-dir/real-tool, linked-dir -> safe.
        let via = trusted_dir();
        symlink(safe.path(), via.path().join("linked-dir")).expect("symlink");
        let first = trusted_dir();
        symlink(
            via.path().join("linked-dir").join("real-tool"),
            first.path().join("tool"),
        )
        .expect("symlink");
        let dirs = [first.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), Ok(real(&target)));
        mode(via.path(), 0o775);
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
    }

    #[test]
    fn a_relative_link_is_followed_from_its_own_directory() {
        let dir = trusted_dir();
        let target = write_exec(dir.path(), "real-tool", "#!/bin/true\n");
        fs::create_dir(dir.path().join("sub")).expect("mkdir");
        mode(&dir.path().join("sub"), 0o755);
        symlink("../real-tool", dir.path().join("sub").join("tool")).expect("symlink");
        let dirs = [dir.path().join("sub")];
        assert_eq!(resolve_in("tool", &dirs), Ok(real(&target)));
    }

    #[test]
    fn a_chain_of_more_than_forty_links_is_refused() {
        let dir = trusted_dir();
        let mut previous = write_exec(dir.path(), "end", "#!/bin/true\n");
        for index in 0..=MAX_LINK_HOPS {
            let link = dir.path().join(format!("link{index}"));
            symlink(&previous, &link).expect("symlink");
            previous = link;
        }
        assert_eq!(real_path_checked(&previous), None);
        assert!(real_path_checked(&dir.path().join("link1")).is_some());
        // A loop never reaches a file, so the candidate is skipped before the walk.
        symlink("b", dir.path().join("a")).expect("symlink");
        symlink("a", dir.path().join("b")).expect("symlink");
        assert_eq!(real_path_checked(&dir.path().join("a")), None);
    }

    #[test]
    fn an_untrusted_candidate_ends_the_search() {
        let first = trusted_dir();
        let second = trusted_dir();
        let bad = write_exec(first.path(), "tool", "#!/bin/true\n");
        write_exec(second.path(), "tool", "#!/bin/true\n");
        mode(&bad, 0o777);
        let dirs = [first.path().to_path_buf(), second.path().to_path_buf()];
        assert_eq!(resolve_in("tool", &dirs), untrusted("tool"));
    }

    #[test]
    fn the_program_starts_from_its_real_path_with_the_name_as_argv0() {
        let dir = trusted_dir();
        let target = write_exec(dir.path(), "real-name", "#!/bin/true\n");
        let extra = trusted_dir();
        symlink(&target, extra.path().join("rdy-policy-argv0")).expect("symlink");
        let spec = prepare(&cmd("rdy-policy-argv0").extra_dirs(constants(constant(extra.path()))))
            .expect("resolves");
        let text = format!("{spec:?}");
        assert!(
            text.contains(&format!("{}", real(&target).display())),
            "{text}"
        );
        assert!(text.contains("arg0: Some(\"rdy-policy-argv0\")"), "{text}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_multi_call_applet_sees_the_name_it_was_asked_for() {
        let Ok(cat) = fs::canonicalize("/usr/bin/cat") else {
            return;
        };
        if cat.file_name().is_some_and(|name| name != "cat") {
            // A multi-call build (busybox, coreutils) picks the tool from argv[0] itself.
            return;
        }
        let extra = trusted_dir();
        symlink(&cat, extra.path().join("rdy-policy-applet")).expect("symlink");
        let out = run(cmd("rdy-policy-applet")
            .extra_dirs(constants(constant(extra.path())))
            .args(["/proc/self/cmdline"]))
        .await
        .expect("runs");
        assert_eq!(out.stdout, b"rdy-policy-applet\0/proc/self/cmdline\0");
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
    fn a_link_to_a_file_named_like_a_shell_is_refused() {
        let shells = trusted_dir();
        let target = write_exec(shells.path(), "dash", "#!/bin/true\n");
        let extra = trusted_dir();
        symlink(&target, extra.path().join("rdy-policy-link")).expect("symlink");
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
        let out = run(cmd("printenv").env([("HTTPS_PROXY", "http://proxy.invalid:3128")]))
            .await
            .expect("printenv runs");
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
        let out = run(cmd("printenv").stdout_cap(8))
            .await
            .expect("printenv runs");
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
        // The set-up holds: this process has the hostile variables and a fake `printenv` first in PATH.
        assert!(std::env::var_os("LD_PRELOAD").is_some());
        let path = std::env::var_os("PATH").expect("PATH");
        assert!(
            path.to_string_lossy()
                .starts_with(&*fake_dir.to_string_lossy())
        );
        let out = run(cmd("printenv")).await.expect("printenv runs");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("FAKE"), "the fake printenv ran: {text}");
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
        write_exec(fake.path(), "printenv", "#!/bin/echo FAKE\n");
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
