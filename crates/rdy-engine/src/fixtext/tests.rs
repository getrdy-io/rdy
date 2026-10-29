//! Fix-text audit tests: the files are well formed, and typos fail.

use super::*;

fn embedded_violations(text: &str) -> Vec<(Kind, String)> {
    audit(text, AllowLists::embedded())
        .into_iter()
        .map(|v| (v.kind, v.name))
        .collect()
}

/// Lines of an allow-list file that are entries: not blank, not a comment.
fn entries(file: &str) -> Vec<&str> {
    file.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn the_embedded_files_parse_and_are_not_empty() {
    let parsed = AllowLists::parse(COMMANDS_FILE, SYSCTLS_FILE, LITERALS_FILE);
    assert!(parsed.is_ok(), "{parsed:?}");
    assert_ne!(AllowLists::embedded(), &AllowLists::default());
    assert!(AllowLists::embedded().commands().count() > 20);
    assert!(AllowLists::embedded().sysctls().count() >= 2);
}

#[test]
fn every_file_is_sorted_by_byte_without_repeats() {
    for (name, file) in [
        ("commands.txt", COMMANDS_FILE),
        ("sysctls.txt", SYSCTLS_FILE),
        ("literals.txt", LITERALS_FILE),
    ] {
        let lines = entries(file);
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(lines, sorted, "{name} must be sorted and have no repeats");
    }
}

#[test]
fn no_shell_privilege_tool_or_program_runner_is_a_listed_fix_command() {
    #[cfg(feature = "runtime")]
    for name in AllowLists::embedded().commands() {
        assert!(
            !crate::exec::policy::is_refused_name(name),
            "`{name}` must not be a fix command"
        );
    }
    // `sudo` is skipped in text, so it must not be listed either.
    assert!(!AllowLists::embedded().allows_command("sudo"));
}

#[test]
fn a_literal_is_one_span_without_backticks() {
    for literal in AllowLists::embedded().literals() {
        assert!(!literal.trim().is_empty());
        assert!(!literal.contains('`'), "{literal}");
    }
}

#[test]
fn correct_fix_text_passes() {
    let text = "Run `sudo sysctl -w vm.max_map_count=262144` and persist it: \
        `echo 'vm.max_map_count = 262144' | sudo tee /etc/sysctl.d/90-acme.conf && sudo sysctl --system`. \
        Then `systemctl restart {unit}`. Remove `noexec` from `/etc/fstab`.";
    assert_eq!(check(text), Ok(()));
}

#[test]
fn a_typo_in_a_command_fails() {
    let found = embedded_violations("Run `systemclt restart containerd`.");
    assert_eq!(found, [(Kind::Command, "systemclt".to_owned())]);
    let error = check("Run `systemclt restart containerd`.").expect_err("typo");
    let text = error.to_string();
    assert!(text.contains("commands.txt"), "{text}");
    assert!(text.contains("Fix:"), "{text}");
}

#[test]
fn a_command_missing_from_the_list_fails_even_after_sudo_or_a_pipe() {
    for text in [
        "`sudo frobnicate --now`",
        "`echo x | sudo -E frobnicate y`",
        "`systemctl stop a && frobnicate b`",
        "`LC_ALL=C frobnicate b`",
    ] {
        assert_eq!(
            embedded_violations(text),
            [(Kind::Command, "frobnicate".to_owned())],
            "{text}"
        );
    }
}

#[test]
fn a_command_given_by_absolute_path_is_judged_by_its_file_name() {
    assert_eq!(embedded_violations("`/usr/sbin/swapoff -a`"), []);
    assert_eq!(
        embedded_violations("`/opt/acme/bin/frobnicate -a`"),
        [(Kind::Command, "frobnicate".to_owned())]
    );
}

#[test]
fn a_typo_in_a_sysctl_fails_wherever_it_stands() {
    let want = [(Kind::Sysctl, "vm.max_map_cuont".to_owned())];
    assert_eq!(embedded_violations("`vm.max_map_cuont` is low"), want);
    assert_eq!(embedded_violations("`sysctl -w vm.max_map_cuont=1`"), want);
    assert_eq!(
        embedded_violations("`echo 'vm.max_map_cuont = 1' | tee /etc/sysctl.d/x.conf`"),
        want
    );
}

#[test]
fn the_words_of_sysctl_are_names_whatever_they_start_with() {
    assert_eq!(
        embedded_violations("`sysctl -w kern.foo=1`"),
        [(Kind::Sysctl, "kern.foo".to_owned())]
    );
    assert_eq!(embedded_violations("`sysctl -p /etc/sysctl.d/90.conf`"), []);
    assert_eq!(embedded_violations("`sudo sysctl --system`"), []);
}

#[test]
fn things_that_only_look_like_sysctls_or_commands_pass() {
    for text in [
        "`net.dns` failed",
        "`net.tls_intercept` found it",
        "`user.slice` is not a parameter",
        "`fs.conf`",
        "`noexec` and `GRUB_CMDLINE_LINUX` and `{unit}`",
        "`<cpu mode='host-passthrough'/>`",
        "`SystemdCgroup = true`",
        "`[plugins.\"x\"]`",
        "`:Z`",
        "`GRANT CREATE ON SCHEMA public TO acme_app;`",
        "`CONFIG SET maxmemory-policy noeviction`",
        "`cgroup_memory=1 cgroup_enable=memory`",
        "`Environment=\"HTTP_PROXY={proxy}\" \"NO_PROXY={no_proxy}\"`",
        "prose with vm.max_map_cuont outside any backticks",
        "an `unpaired backtick",
        "``",
    ] {
        assert_eq!(embedded_violations(text), [], "{text}");
    }
}

#[test]
fn a_quoted_pipe_does_not_start_a_new_command() {
    assert_eq!(embedded_violations("`echo 'a | frobnicate b' | tee f`"), []);
    assert_eq!(embedded_violations("`echo \"a && frobnicate b\"`"), []);
}

#[test]
fn a_listed_literal_is_not_read() {
    assert_eq!(embedded_violations("`unexpected EOF`"), []);
    assert_eq!(
        embedded_violations("`unexpected EOF now`"),
        [(Kind::Command, "unexpected".to_owned())]
    );
}

#[test]
fn a_placeholder_stays_in_a_sysctl_name_as_written() {
    let allow =
        AllowLists::parse("sysctl\n", "net.ipv4.conf.{iface}.rp_filter\n", "").expect("parse");
    assert_eq!(
        audit("`sysctl -w net.ipv4.conf.{iface}.rp_filter=2`", &allow),
        []
    );
    assert_eq!(
        audit("`sysctl -w net.ipv4.conf.{iface}.log_martians=1`", &allow).len(),
        1
    );
}

#[test]
fn repeats_are_reported_once_and_the_list_is_bounded() {
    let found = embedded_violations("`frob a` and `frob a`");
    assert_eq!(found.len(), 1);
    let many: String = (0..300).map(|n| format!("`frob{n} a` ")).collect();
    assert_eq!(embedded_violations(&many).len(), MAX_VIOLATIONS);
}

#[test]
fn a_bad_line_in_a_file_names_the_file_and_line() {
    let error = AllowLists::parse("df\nrm -rf\n", "", "").expect_err("bad line");
    let text = error.to_string();
    assert!(text.contains("commands.txt line 2"), "{text}");
    assert!(text.contains("Fix:"), "{text}");
    assert!(AllowLists::parse("", "Vm.Max\n", "").is_err());
    assert!(AllowLists::parse("# only a comment\n\n  df  # trailing\n", "", "").is_ok());
}

#[test]
fn empty_lists_fail_closed() {
    let empty = AllowLists::default();
    assert_eq!(audit("`df -h /`", &empty).len(), 1);
}
