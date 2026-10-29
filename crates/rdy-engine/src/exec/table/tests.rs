//! Command table tests: every entry is well formed, spec text cannot become an option, and the
//! names that never get listed are not.

use super::super::policy::{
    MAX_STDOUT_CAP, PolicyError, SEARCH_DIRS, WINDOWS_SYSTEM_ROOT, is_refused_name, prepare,
};
use super::*;

const SECOND: Duration = Duration::from_secs(1);

/// A value that passes the rule of each param kind.
fn sample(param: Param) -> &'static str {
    match param {
        Param::HostName => "registry.example",
        Param::Zone => "public",
    }
}

/// Sample values for the params of a form, in order.
fn samples(form: &Form) -> Vec<&'static str> {
    form.args
        .iter()
        .filter_map(|arg| match arg {
            Arg::Param(param) | Arg::Joined(_, param) => Some(sample(*param)),
            Arg::Lit(_) => None,
        })
        .collect()
}

/// A command for a form of a Linux entry, built for Linux whatever OS the tests run on.
fn linux(program: &str, form: &str, params: &[&str]) -> Cmd {
    entry(program)
        .expect("entry")
        .cmd_for(Os::Linux, form, params)
        .expect("builds")
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or_default()
}

#[test]
fn the_table_covers_every_row_of_appendix_a_by_program() {
    let programs: Vec<&str> = entries().iter().map(|e| e.program).collect();
    for want in [
        "getent",
        "timedatectl",
        "chronyc",
        "firewall-cmd",
        "containerd",
        "crio",
        "scutil",
        "netstat",
        "sysctl",
        "NETSTAT.EXE",
        "netsh.exe",
        "nvidia-smi",
        "nvidia-smi.exe",
        "nvidia-ctk",
        "nvcc",
        "nv-fabricmanager",
        "whoami.exe",
    ] {
        assert!(programs.contains(&want), "{want} has no entry");
    }
    assert_eq!(programs.len(), 17);
}

#[test]
fn programs_and_form_ids_are_unique() {
    let mut seen: Vec<String> = Vec::new();
    for entry in entries() {
        let name = entry.program.to_ascii_lowercase();
        assert!(!seen.contains(&name), "{name} is listed twice");
        seen.push(name);
        let mut ids: Vec<&str> = entry.forms.iter().map(|f| f.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "{} repeats a form id", entry.program);
        assert!(!entry.forms.is_empty(), "{} has no form", entry.program);
        assert!(!entry.os.is_empty(), "{} has no OS", entry.program);
        assert!(!entry.checks.is_empty(), "{} has no check", entry.program);
    }
}

#[test]
fn every_path_is_absolute_and_ends_in_the_program_name() {
    for entry in entries() {
        assert!(
            file_name(entry.path).eq_ignore_ascii_case(entry.program),
            "{} has path {}",
            entry.program,
            entry.path
        );
        if entry.runs_on(Os::Windows) {
            let system32 = format!(r"{WINDOWS_SYSTEM_ROOT}\System32\");
            assert!(entry.path.starts_with(&system32), "{}", entry.path);
            assert!(entry.os == [Os::Windows], "{} mixes OSes", entry.program);
        } else {
            let dir = entry.path.rsplit_once('/').map_or("", |(dir, _)| dir);
            assert!(entry.path.starts_with('/'), "{}", entry.path);
            assert!(
                SEARCH_DIRS.contains(&dir) || entry.extra_dirs.contains(&dir),
                "{} is in neither a search directory nor a declared one",
                entry.path
            );
        }
    }
}

#[test]
fn limits_are_within_the_catalog_bounds() {
    for entry in entries() {
        for form in entry.forms {
            let who = format!("{} {}", entry.program, form.id);
            assert!(form.timeout > Duration::ZERO, "{who}");
            assert!(form.timeout <= Duration::from_secs(30), "{who}");
            assert!(
                form.stdout_cap > 0 && form.stdout_cap <= MAX_STDOUT_CAP,
                "{who}"
            );
            assert_eq!(form.classify(0), Some(ExitClass::Ok), "{who}");
        }
    }
}

#[test]
fn only_the_gpu_xml_has_a_bigger_cap_than_one_mib() {
    for entry in entries() {
        for form in entry.forms {
            let big = form.stdout_cap > DEFAULT_STDOUT_CAP;
            let xml = form.id == "query-xml";
            assert_eq!(big, xml, "{} {}", entry.program, form.id);
            if xml {
                assert_eq!(form.stdout_cap, 2 * 1024 * 1024);
                assert_eq!(form.timeout, Duration::from_secs(30));
            }
        }
    }
}

#[test]
fn no_entry_declares_an_environment_variable() {
    for entry in entries() {
        assert!(entry.env.is_empty(), "{}", entry.program);
    }
}

#[test]
fn extra_directories_are_absolute_plain_and_only_for_gpu_tools() {
    for entry in entries() {
        for dir in entry.extra_dirs {
            assert!(dir.starts_with('/'), "{dir}");
            assert!(!dir.contains("//") && !dir.ends_with('/'), "{dir}");
            assert!(
                !dir.split('/').any(|part| part == ".." || part == "."),
                "{dir}"
            );
            assert!(
                entry.checks.iter().any(|check| check.starts_with("gpu.")),
                "{} declares {dir} but is not a GPU tool",
                entry.program
            );
        }
    }
}

#[test]
fn nothing_that_takes_code_or_a_command_line_is_listed() {
    for entry in entries() {
        assert!(!is_refused_name(entry.program), "{}", entry.program);
        assert!(!is_refused_name(file_name(entry.path)), "{}", entry.path);
    }
    for name in [
        "env",
        "xargs",
        "nohup",
        "timeout",
        "time",
        "setarch",
        "linux32",
        "linux64",
        "chpst",
        "start-stop-daemon",
        "run-parts",
        "python",
        "python3",
        "python3.12",
        "perl",
        "awk",
        "gawk",
        "mawk",
        "ruby",
        "node",
        "lua",
        "php",
        "busybox",
        "toybox",
        "sh",
        "bash",
        "cmd",
        "powershell",
        "pwsh",
        "sudo",
        "su",
        "find",
        "sed",
        "m4",
        "dc",
        "ed",
        "ex",
        "vi",
        "vim",
        "ip",
        "ssh",
        "git",
        "tar",
        "rsync",
        "make",
        "perf",
        "valgrind",
        "lldb",
        "faketime",
        "fakeroot",
        "unbuffer",
        "parallel",
        "sqlite3",
        "bpftrace",
        "java",
        "jshell",
        "irb",
        "jruby",
        "deno",
        "bun",
        "docker",
        "podman",
        "nerdctl",
        "ctr",
        "crictl",
        "arch",
        "caffeinate",
        "launchctl",
        "sandbox-exec",
        "xcrun",
        "cscript",
        "wscript",
        "mshta",
        "rundll32",
        "forfiles",
        "wsl",
        "pypy3",
        "ld-linux-x86-64.so.2",
        "ld-musl-x86_64.so.1",
    ] {
        assert!(is_refused_name(name), "{name} should be refused by name");
        assert!(entry(name).is_none(), "{name} must not have an entry");
    }
}

#[test]
fn the_policy_accepts_every_listed_command_up_to_resolution() {
    // `prepare` also looks the program up on this machine, so NotFound and the Windows rule are
    // fine here. Anything about the name, the directories or the caps is not.
    for entry in entries() {
        // The policy resolves for the OS it runs on, and refuses the paths of another OS.
        if !entry.runs_on(current_os()) {
            continue;
        }
        for form in entry.forms {
            let params = samples(form);
            let cmd = entry
                .cmd_for(entry.os[0], form.id, &params)
                .expect("builds");
            if let Err(error) = prepare(&cmd) {
                assert!(
                    matches!(
                        error,
                        PolicyError::NotFound { .. } | PolicyError::NotAllowedOnWindows { .. }
                    ),
                    "{} {}: {error}",
                    entry.program,
                    form.id
                );
            }
        }
    }
}

#[test]
fn a_built_command_validates_to_its_own_entry_and_form() {
    for entry in entries() {
        for os in entry.os {
            for form in entry.forms {
                let cmd = entry.cmd_for(*os, form.id, &samples(form)).expect("builds");
                let listed = validate_for(*os, &cmd).expect("valid");
                assert_eq!(listed.entry.program, entry.program);
                assert_eq!(listed.form.id, form.id);
                assert_eq!(cmd.time_limit(), form.timeout);
                assert_eq!(cmd.output_cap(), form.stdout_cap);
            }
        }
    }
}

#[test]
fn the_same_command_is_refused_on_an_os_that_does_not_list_it() {
    let scutil = entry("scutil").expect("entry");
    let cmd = scutil.cmd_for(Os::Macos, "proxy", &[]).expect("builds");
    assert!(validate_for(Os::Macos, &cmd).is_ok());
    assert_eq!(
        validate_for(Os::Linux, &cmd).expect_err("linux"),
        TableError::NotOnThisOs { program: "scutil" }
    );
    assert_eq!(
        scutil.cmd_for(Os::Linux, "proxy", &[]).expect_err("linux"),
        TableError::NotOnThisOs { program: "scutil" }
    );
    // `sysctl` is a macOS row only. Linux hosts read /proc/sys.
    let sysctl = entry("sysctl").expect("entry");
    assert!(!sysctl.runs_on(Os::Linux));
}

#[test]
fn spec_text_cannot_become_an_option_or_carry_a_separator() {
    let getent = entry("getent").expect("entry");
    let build = |value: &str| getent.cmd_for(Os::Linux, "ahosts", &[value]);
    for bad in [
        "-x",
        "--help",
        "-",
        "",
        "a b",
        "a;b",
        "a|b",
        "a&b",
        "$(id)",
        "`id`",
        "a/b",
        "a\nb",
        "h\u{f6}st",
        "a=b",
    ] {
        let error = build(bad).expect_err(bad);
        assert!(
            matches!(error, TableError::BadParam { param: "name", .. }),
            "{bad:?}: {error}"
        );
    }
    let too_long = "a".repeat(MAX_HOST_NAME_LEN + 1);
    assert!(build(&too_long).is_err());
    let longest = "a".repeat(MAX_HOST_NAME_LEN);
    assert!(build(&longest).is_ok());
    for good in [
        "localhost",
        "registry.example",
        "a-b_c.d",
        "10.0.0.1",
        "a--b",
        "1",
    ] {
        assert!(build(good).is_ok(), "{good}");
    }
}

#[test]
fn a_zone_is_one_joined_argument_with_a_stricter_rule() {
    let firewall = entry("firewall-cmd").expect("entry");
    let cmd = firewall
        .cmd_for(Os::Linux, "list-all", &["public"])
        .expect("builds");
    assert_eq!(cmd.arguments(), ["--list-all", "--zone=public"]);
    for bad in ["-x", "", "a.b", "_a", "a b", "a=b", "a/b", "--zone=x"] {
        assert!(
            firewall.cmd_for(Os::Linux, "list-all", &[bad]).is_err(),
            "{bad:?}"
        );
    }
    let long = "z".repeat(MAX_ZONE_LEN + 1);
    assert!(firewall.cmd_for(Os::Linux, "list-all", &[&long]).is_err());
    // The same rule when someone builds the command by hand.
    let by_hand = Cmd::new("firewall-cmd", SECOND).args(["--list-all", "--zone=-bad"]);
    assert!(matches!(
        validate_for(Os::Linux, &by_hand),
        Err(TableError::BadParam { param: "zone", .. })
    ));
    let no_prefix = Cmd::new("firewall-cmd", SECOND).args(["--list-all", "public"]);
    assert_eq!(
        validate_for(Os::Linux, &no_prefix).expect_err("shape"),
        TableError::ArgsNotAllowed {
            program: "firewall-cmd"
        }
    );
}

#[test]
fn a_command_built_by_hand_must_match_a_form() {
    let leading_dash = Cmd::new("getent", SECOND).args(["ahosts", "--", "-x"]);
    assert!(matches!(
        validate_for(Os::Linux, &leading_dash),
        Err(TableError::BadParam { param: "name", .. })
    ));
    for args in [
        vec!["ahosts"],
        vec!["ahosts", "a"],
        vec!["ahosts", "-x"],
        vec!["ahosts", "--", "a", "b"],
        vec!["passwd", "root"],
        Vec::new(),
    ] {
        let cmd = Cmd::new("getent", SECOND).args(args.clone());
        assert_eq!(
            validate_for(Os::Linux, &cmd).expect_err("shape"),
            TableError::ArgsNotAllowed { program: "getent" },
            "{args:?}"
        );
    }
}

#[test]
fn an_unlisted_program_is_refused_with_a_fix() {
    let cmd = Cmd::new("ls", SECOND).args(["/"]);
    let error = validate_for(Os::Linux, &cmd).expect_err("unlisted");
    assert_eq!(error, TableError::UnknownProgram { program: "ls" });
    assert!(error.to_string().contains("Fix:"), "{error}");
}

#[test]
fn time_cap_directories_and_variables_cannot_exceed_the_entry() {
    let ok = Cmd::new("getent", Duration::from_secs(5)).args(["ahosts", "--", "localhost"]);
    assert!(validate_for(Os::Linux, &ok).is_ok());

    let slow = Cmd::new("getent", Duration::from_secs(6)).args(["ahosts", "--", "localhost"]);
    assert_eq!(
        validate_for(Os::Linux, &slow).expect_err("slow"),
        TableError::TimeoutTooLong {
            program: "getent",
            limit_secs: 5
        }
    );

    let big = ok.clone().stdout_cap(DEFAULT_STDOUT_CAP + 1);
    assert_eq!(
        validate_for(Os::Linux, &big).expect_err("big"),
        TableError::CapTooLarge {
            program: "getent",
            limit: DEFAULT_STDOUT_CAP
        }
    );

    let dir = ok.clone().extra_dirs(&["/opt/tools/bin"]);
    assert_eq!(
        validate_for(Os::Linux, &dir).expect_err("dir"),
        TableError::DirNotAllowed {
            program: "getent",
            dir: "/opt/tools/bin"
        }
    );

    for name in ["HTTPS_PROXY", "RDY_ANYTHING"] {
        let env = ok.clone().env([(name, "x")]);
        assert_eq!(
            validate_for(Os::Linux, &env).expect_err("env"),
            TableError::EnvNotAllowed {
                program: "getent",
                name
            }
        );
    }
}

#[test]
fn gpu_tools_may_search_their_declared_directories_and_nothing_else() {
    let smi = entry("nvidia-smi").expect("entry");
    let cmd = linux("nvidia-smi", "query-xml", &[]);
    assert_eq!(cmd.declared_dirs(), smi.extra_dirs);
    assert_eq!(cmd.output_cap(), 2 * 1024 * 1024);
    assert!(validate_for(Os::Linux, &cmd).is_ok());
    let wider = cmd.clone().stdout_cap(3 * 1024 * 1024);
    assert!(matches!(
        validate_for(Os::Linux, &wider),
        Err(TableError::CapTooLarge { .. })
    ));
    // The other forms are capped at 1 MiB.
    let topo = linux("nvidia-smi", "topo", &[]);
    assert_eq!(topo.output_cap(), DEFAULT_STDOUT_CAP);
    assert_eq!(topo.time_limit(), Duration::from_secs(15));
    // Operator-managed nvcc is searched only in the CUDA directory.
    let nvcc = entry("nvcc").expect("entry");
    assert_eq!(nvcc.extra_dirs, ["/usr/local/cuda/bin"]);
}

#[test]
fn the_wrong_value_count_and_unknown_forms_are_refused() {
    let getent = entry("getent").expect("entry");
    assert_eq!(
        getent.cmd_for(Os::Linux, "ahosts", &[]).expect_err("none"),
        TableError::ParamCount {
            program: "getent",
            want: 1,
            got: 0
        }
    );
    assert!(matches!(
        getent.cmd_for(Os::Linux, "ahosts", &["a", "b"]),
        Err(TableError::ParamCount { got: 2, .. })
    ));
    assert_eq!(
        getent.cmd_for(Os::Linux, "nope", &[]).expect_err("form"),
        TableError::UnknownForm { program: "getent" }
    );
}

#[test]
fn lookup_is_exact_except_for_windows_programs() {
    // Unix file names are case sensitive, so `Getent` is not `getent`.
    for name in ["Getent", "GETENT", "Nvidia-Smi", "FIREWALL-CMD", "Scutil"] {
        assert!(entry(name).is_none(), "{name}");
    }
    assert!(entry("getent").is_some());
    // `NETSTAT.EXE` (Windows) and `netstat` (macOS) are two entries.
    assert!(entry("netstat").is_some_and(|e| e.runs_on(Os::Macos)));
    assert!(entry("netstat.exe").is_some());
    assert!(entry("NETSTAT.EXE").is_some());
    assert!(entry("Whoami.exe").is_some());
    assert!(entry("netstat.exe").is_some_and(|e| e.runs_on(Os::Windows)));
    assert!(entry("nope").is_none());
}

#[test]
fn exit_codes_have_the_meanings_appendix_a_gives() {
    let getent = entry("getent")
        .and_then(|e| e.form("ahosts"))
        .expect("form");
    assert_eq!(getent.classify(0), Some(ExitClass::Ok));
    assert_eq!(getent.classify(2), Some(ExitClass::NotFound));
    assert_eq!(getent.classify(1), None);
    assert_eq!(getent.classify(127), None);
    for id in ["state", "active-zones", "list-all"] {
        let form = entry("firewall-cmd")
            .and_then(|e| e.form(id))
            .expect("form");
        assert_eq!(form.classify(252), Some(ExitClass::NotRunning), "{id}");
        assert_eq!(form.classify(1), None, "{id}");
    }
    let rosetta = entry("sysctl")
        .and_then(|e| e.form("rosetta"))
        .expect("form");
    assert_eq!(rosetta.classify(1), Some(ExitClass::KeyMissing));
    assert_eq!(rosetta.classify(2), None);
}

#[test]
fn a_form_renders_the_way_appendix_a_writes_it() {
    let render = |program: &str, id: &str| {
        entry(program)
            .and_then(|e| e.form(id))
            .map(Form::render)
            .unwrap_or_default()
    };
    assert_eq!(render("getent", "ahosts"), "ahosts -- <name>");
    assert_eq!(
        render("firewall-cmd", "list-all"),
        "--list-all --zone=<zone>"
    );
    assert_eq!(render("chronyc", "tracking"), "-n -c -t 3 tracking");
    assert_eq!(
        render("timedatectl", "show"),
        "show -p NTPSynchronized -p NTP -p Timezone"
    );
}

#[tokio::test]
async fn run_refuses_an_unlisted_command_before_anything_starts() {
    let error = run(Cmd::new("true", SECOND)).await.expect_err("unlisted");
    assert!(
        matches!(
            error,
            CommandError::Table(TableError::UnknownProgram { program: "true" })
        ),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn run_starts_a_listed_command_under_the_policy() {
    let cmd = linux("getent", "ahosts", &["localhost"]);
    // Where getent is missing the policy says so, which still proves the table let it through.
    match run(cmd).await {
        Ok(_) => {}
        Err(CommandError::Policy(PolicyError::NotFound { program })) => {
            assert_eq!(program, "getent");
        }
        Err(other) => panic!("{other}"),
    }
}

/// One argv that fits a form: its literals, with a sample value for each param.
fn argv_of(form: &Form) -> Vec<String> {
    form.args
        .iter()
        .map(|arg| match arg {
            Arg::Lit(text) => (*text).to_owned(),
            Arg::Param(param) => sample(*param).to_owned(),
            Arg::Joined(prefix, param) => format!("{prefix}{}", sample(*param)),
        })
        .collect()
}

#[test]
fn no_argv_matches_two_forms_of_one_entry() {
    for entry in entries() {
        for form in entry.forms {
            let argv: Vec<std::ffi::OsString> = argv_of(form).into_iter().map(Into::into).collect();
            let matching: Vec<&str> = entry
                .forms
                .iter()
                .filter(|other| other.matches(&argv).is_ok())
                .map(|other| other.id)
                .collect();
            assert_eq!(
                matching,
                [form.id],
                "{} {}: the sample argv fits {matching:?}",
                entry.program,
                form.id
            );
        }
    }
}

#[test]
fn the_validated_form_is_the_one_the_command_was_built_from() {
    // `validate_for` takes the first form that fits, so two forms that overlap would make the
    // limits depend on the order of the list. The test above proves they do not overlap.
    for entry in entries() {
        for form in entry.forms {
            let cmd = entry
                .cmd_for(entry.os[0], form.id, &samples(form))
                .expect("builds");
            let listed = validate_for(entry.os[0], &cmd).expect("valid");
            assert_eq!(listed.form.id, form.id, "{}", entry.program);
        }
    }
}
