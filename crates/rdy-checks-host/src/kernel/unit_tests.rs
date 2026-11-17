//! Boundary tests of the release reader, the version compare, the module-name scans and the judgement of
//! `host.kernel`. No probe, no runtime.

use std::collections::BTreeSet;

use proptest::prelude::*;
use rdy_engine::check::Level;
use rdy_engine::probe::{FileBytes, MAX_READ};
use rdy_spec::check::KernelVersion;
use serde_json::json;

use super::judge::{Facts, Got, Modules, Rules, State, judge, state_of};
use super::modules::{self, Dep};
use super::version::{self, Standing};

fn want(text: &str) -> KernelVersion {
    serde_json::from_value(json!(text)).expect("a kernel version")
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

// ---- the release string ------------------------------------------------------------------------

#[test]
fn a_release_string_is_read_down_to_its_numbers() {
    // (text, base, build)
    type Row = (&'static str, &'static [u32], Option<&'static [u32]>);
    let table: &[Row] = &[
        ("5.14.0-362.el9.x86_64", &[5, 14, 0], Some(&[362])),
        ("4.18.0-305.el8.x86_64", &[4, 18, 0], Some(&[305])),
        ("6.8.0-1021-aws", &[6, 8, 0], Some(&[1021])),
        ("5.15.0-91-generic", &[5, 15, 0], Some(&[91])),
        ("6.1.0-18-amd64", &[6, 1, 0], Some(&[18])),
        (
            "4.14.336-257.562.amzn2.x86_64",
            &[4, 14, 336],
            Some(&[257, 562]),
        ),
        (
            "5.14.21-150500.55.19-default",
            &[5, 14, 21],
            Some(&[150500, 55, 19]),
        ),
        ("5.15.0-1.2.3.el9uek", &[5, 15, 0], Some(&[1, 2, 3])),
        ("5.10.102.1-microsoft-standard-WSL2", &[5, 10, 102, 1], None),
        ("6.1.0", &[6, 1, 0], None),
        ("5.4.0+", &[5, 4, 0], None),
        ("6.1.0-rc3", &[6, 1, 0], None),
        ("6.1.0.rc3", &[6, 1, 0], None),
        ("5", &[5], None),
        ("5.4.1.2.3", &[5, 4, 1, 2], None),
        ("  5.4.0-1 ", &[5, 4, 0], Some(&[1])),
    ];
    for (text, base, build) in table {
        let release = version::parse(text).unwrap_or_else(|| panic!("{text} does not parse"));
        assert_eq!(release.base.components(), *base, "{text}");
        assert_eq!(
            release.build.as_ref().map(rdy_spec::Version::components),
            *build,
            "{text}"
        );
    }
}

#[test]
fn text_that_is_not_a_release_is_refused() {
    let long = "5.".repeat(100);
    for text in [
        "",
        " ",
        "garbage",
        "v5.4",
        ".5.4",
        "-5.4",
        "99999999999.1",
        long.as_str(),
    ] {
        assert_eq!(version::parse(text), None, "{text:?}");
    }
}

#[test]
fn a_build_number_that_is_too_large_is_dropped_not_fatal() {
    let release = version::parse("5.14.0-99999999999.el9").expect("the base reads");
    assert_eq!(release.build, None);
}

#[test]
fn the_compare_is_numeric_part_by_part() {
    let table: &[(&str, &str, Standing)] = &[
        ("5.14.0-362.el9.x86_64", "5.4", Standing::AtLeast),
        ("5.14.0-362.el9.x86_64", "5.14", Standing::AtLeast),
        ("5.14.0-362.el9.x86_64", "5.14.0", Standing::AtLeast),
        ("5.14.0-362.el9.x86_64", "5.14.1", Standing::Below),
        ("5.14.0-362.el9.x86_64", "5.14.0-362", Standing::AtLeast),
        ("5.14.0-362.el9.x86_64", "5.14.0-363", Standing::Below),
        ("5.14.0-362.el9.x86_64", "5.14.0-99", Standing::AtLeast),
        // The build number is compared as a number, not as text.
        ("4.18.0-1000.el8", "4.18.0-305", Standing::AtLeast),
        ("4.18.0-99.el8", "4.18.0-305", Standing::Below),
        ("4.18.0-305.el8", "4.18.0-305", Standing::AtLeast),
        ("4.18.0-304.el8", "4.18.0-305", Standing::Below),
        // A higher base wins whatever the build says.
        ("5.15.0-1", "4.18.0-305", Standing::AtLeast),
        ("4.9.0-1", "4.18", Standing::Below),
        ("10.0.0", "9.9", Standing::AtLeast),
        ("5.4.0", "5.4", Standing::AtLeast),
        // No build number on the machine to compare with the spec's.
        ("5.14.0", "5.14.0-362", Standing::NoBuild),
        (
            "5.10.102.1-microsoft-standard-WSL2",
            "5.10.102.1-5",
            Standing::NoBuild,
        ),
        // The build numbers compare as dotted versions: 150500.55.19 against 150500.55.7.
        (
            "5.14.21-150500.55.19-default",
            "5.14.21-150500.55.7",
            Standing::AtLeast,
        ),
        (
            "5.14.21-150500.55.19-default",
            "5.14.21-150500.55.19",
            Standing::AtLeast,
        ),
        (
            "5.14.21-150500.55.19-default",
            "5.14.21-150500.55.20",
            Standing::Below,
        ),
    ];
    for (have, wanted, expected) in table {
        let release = version::parse(have).unwrap_or_else(|| panic!("{have}"));
        assert_eq!(
            version::compare(&release, &want(wanted)),
            *expected,
            "{have} against {wanted}"
        );
    }
}

#[test]
fn a_release_is_path_safe_only_with_plain_characters() {
    for safe in [
        "5.14.0-362.el9.x86_64",
        "6.8.0-1021-aws",
        "5.4.0+",
        "6.1.0~rc1",
    ] {
        assert!(version::is_path_safe(safe), "{safe}");
    }
    let long65 = "5".repeat(65);
    for unsafe_text in [
        "",
        ".hidden",
        "..",
        "5.14.0-1/../../etc",
        "5.14.0\\x",
        "5.14.0 x",
        "5.14.0\n",
        "5.14.0\u{1b}[2J",
        long65.as_str(),
    ] {
        assert!(!version::is_path_safe(unsafe_text), "{unsafe_text:?}");
    }
}

// ---- module names --------------------------------------------------------------------------------

#[test]
fn a_module_path_gives_its_name_for_every_compression() {
    for path in [
        "kernel/fs/overlayfs/overlay.ko",
        "kernel/fs/overlayfs/overlay.ko.xz",
        "kernel/fs/overlayfs/overlay.ko.zst",
        "kernel/fs/overlayfs/overlay.ko.gz",
        "overlay.ko",
    ] {
        assert_eq!(
            modules::name_of_path(path).as_deref(),
            Some("overlay"),
            "{path}"
        );
    }
    assert_eq!(
        modules::name_of_path("kernel/net/bridge/br-netfilter.ko.xz").as_deref(),
        Some("br_netfilter")
    );
    assert_eq!(
        modules::name_of_path("kernel/net/netfilter/xt_TCPMSS.ko.xz").as_deref(),
        Some("xt_TCPMSS")
    );
    for path in [
        "",
        "kernel/",
        "kernel/overlay.o",
        "kernel/overlay.ko.bz2",
        "kernel/.ko",
        "overlay",
    ] {
        assert_eq!(modules::name_of_path(path), None, "{path}");
    }
}

#[test]
fn only_the_part_before_the_colon_names_a_module() {
    let wanted = set(&["overlay", "llc", "bridge"]);
    let text = "kernel/net/bridge/bridge.ko.xz: kernel/net/llc/llc.ko.xz\nkernel/fs/overlayfs/overlay.ko.xz:\n";
    assert_eq!(
        modules::scan_paths(text, &wanted),
        set(&["bridge", "overlay"])
    );
    // Without a colon (modules.builtin) the whole line is the path.
    assert_eq!(
        modules::scan_paths("kernel/net/llc/llc.ko\n", &wanted),
        set(&["llc"])
    );
}

#[test]
fn proc_modules_gives_the_first_word_of_each_line() {
    let text = "overlay 188416 2 - Live 0x0000000000000000\nbr_netfilter 32768 0 - Live 0x0\nxt_TCPMSS 16384 0 - Live 0x0\n";
    let wanted = set(&["overlay", "xt_TCPMSS", "xt_tcpmss", "nf_conntrack"]);
    assert_eq!(
        modules::scan_loaded(text, &wanted),
        set(&["overlay", "xt_TCPMSS"])
    );
}

fn file(text: &str, head_cut: bool, tail_cut: bool) -> FileBytes {
    let mut file = FileBytes::new(text.as_bytes().to_vec());
    file.truncated_head = head_cut;
    file.truncated_tail = tail_cut;
    file
}

#[test]
fn a_whole_modules_dep_is_complete() {
    let wanted = set(&["overlay", "ip_vs"]);
    let head = file("kernel/fs/overlayfs/overlay.ko.xz:\n", false, false);
    let dep = modules::scan_dep(&head, None, None, &wanted);
    assert_eq!(dep.found, set(&["overlay"]));
    assert!(dep.complete);
}

#[test]
fn a_cut_modules_dep_is_read_from_both_ends_and_a_half_line_names_nothing() {
    let wanted = set(&["overlay", "ip_vs", "nf_conntrack"]);
    // The head ends in the middle of "overlay.ko.xz:". Cut at ".ko" it would read as a whole module.
    let head = file(
        "kernel/net/netfilter/nf_conntrack.ko.xz:\nkernel/fs/overlayfs/overlay.ko",
        false,
        true,
    );
    let tail = file(
        "s/ip_vs.ko.xz:\nkernel/net/ipvs/ip_vs.ko.xz:\n",
        true,
        false,
    );
    let len = Some(u64::try_from(MAX_READ).expect("fits") + 1000);
    let dep = modules::scan_dep(&head, Some(&tail), len, &wanted);
    assert_eq!(dep.found, set(&["ip_vs", "nf_conntrack"]));
    assert!(dep.complete);
}

#[test]
fn a_modules_dep_the_two_reads_may_not_cover_is_incomplete() {
    let wanted = set(&["overlay"]);
    let head = file("kernel/a.ko:\nkernel/b.k", false, true);
    let tail = file("o:\nkernel/c.ko:\n", true, false);
    let reach = 2 * u64::try_from(MAX_READ).expect("fits");
    // No size: unknown, so incomplete.
    assert!(!modules::scan_dep(&head, Some(&tail), None, &wanted).complete);
    // Too large for two reads, or too close to the limit for a long line between them.
    assert!(!modules::scan_dep(&head, Some(&tail), Some(reach + 1), &wanted).complete);
    assert!(!modules::scan_dep(&head, Some(&tail), Some(reach), &wanted).complete);
    // The tail could not be read.
    assert!(!modules::scan_dep(&head, None, Some(10), &wanted).complete);
    // Well inside the reach.
    assert!(modules::scan_dep(&head, Some(&tail), Some(reach - 128 * 1024), &wanted).complete);
}

// ---- states --------------------------------------------------------------------------------------

fn facts_for(
    loaded: Got<BTreeSet<String>>,
    builtin: Got<BTreeSet<String>>,
    dep: Got<Dep>,
) -> Modules {
    Modules {
        dir: "/lib/modules/5.14.0-362.el9.x86_64".to_owned(),
        path_safe: true,
        loaded,
        builtin,
        dep,
    }
}

fn dep(names: &[&str], complete: bool) -> Got<Dep> {
    Got::Value(Dep {
        found: set(names),
        complete,
    })
}

#[test]
fn a_module_is_loaded_then_built_in_then_available_then_absent() {
    let m = facts_for(
        Got::Value(set(&["a"])),
        Got::Value(set(&["a", "b"])),
        dep(&["a", "b", "c"], true),
    );
    assert_eq!(state_of(&m, "a"), State::Loaded);
    assert_eq!(state_of(&m, "b"), State::BuiltIn);
    assert_eq!(state_of(&m, "c"), State::Available);
    assert_eq!(state_of(&m, "d"), State::Absent);
}

#[test]
fn a_missing_builtin_file_is_an_empty_list_but_an_unreadable_one_is_unknown() {
    let missing = facts_for(Got::Value(set(&[])), Got::Absent, dep(&[], true));
    assert_eq!(state_of(&missing, "x"), State::Absent);
    let unreadable = facts_for(
        Got::Value(set(&[])),
        Got::Failed("permission denied".to_owned()),
        dep(&[], true),
    );
    let State::Unknown(_, why) = state_of(&unreadable, "x") else {
        panic!("not unknown");
    };
    assert!(
        why.contains("modules.builtin could not be read (permission denied)"),
        "{why}"
    );
}

#[test]
fn a_module_is_never_absent_when_a_source_could_not_settle_it() {
    let cases = [
        // /proc/modules is missing or unreadable: a module loaded from outside /lib/modules is invisible.
        facts_for(Got::Absent, Got::Value(set(&[])), dep(&[], true)),
        facts_for(
            Got::Failed("x".to_owned()),
            Got::Value(set(&[])),
            dep(&[], true),
        ),
        // modules.dep is missing, unreadable or only partly read.
        facts_for(Got::Value(set(&[])), Got::Value(set(&[])), Got::Absent),
        facts_for(
            Got::Value(set(&[])),
            Got::Value(set(&[])),
            Got::Failed("x".to_owned()),
        ),
        facts_for(Got::Value(set(&[])), Got::Value(set(&[])), dep(&[], false)),
    ];
    for m in cases {
        assert!(matches!(state_of(&m, "x"), State::Unknown(..)), "{m:?}");
    }
    let mut unsafe_dir = facts_for(Got::Value(set(&[])), Got::Value(set(&[])), dep(&[], true));
    unsafe_dir.path_safe = false;
    assert!(matches!(state_of(&unsafe_dir, "x"), State::Unknown(..)));
}

#[test]
fn the_fix_for_an_unknown_module_follows_the_source_that_failed() {
    let large = facts_for(Got::Value(set(&[])), Got::Value(set(&[])), dep(&[], false));
    let finding = judge(&rules_with_modules(&["x"]), &facts(large));
    assert_eq!(finding.level, Level::Warn);
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.starts_with("rdy could not search the whole module list."),
        "{fix}"
    );
    assert!(
        finding.message.contains("is larger than rdy reads"),
        "{}",
        finding.message
    );

    let proc = facts_for(Got::Absent, Got::Value(set(&[])), dep(&[], true));
    let fix = judge(&rules_with_modules(&["x"]), &facts(proc))
        .fix
        .expect("a fix");
    assert!(fix.contains("not inside a container"), "{fix}");
    for text in [
        fix.as_str(),
        "rdy could not search the whole module list. To check by hand, run `sudo modprobe -n -v x`.",
    ] {
        rdy_engine::fixtext::check(text).unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn an_installed_module_is_available_even_when_the_loaded_list_cannot_be_read() {
    let m = facts_for(Got::Absent, Got::Value(set(&[])), dep(&["c"], true));
    assert_eq!(state_of(&m, "c"), State::Available);
}

// ---- the judgement -------------------------------------------------------------------------------

fn rules_with_modules(names: &[&str]) -> Rules {
    Rules {
        modules: names.iter().map(|n| (*n).to_owned()).collect(),
        ..Rules::default()
    }
}

fn facts(modules: Modules) -> Facts {
    Facts {
        release: Got::Value("5.14.0-362.el9.x86_64".to_owned()),
        distro: Got::Absent,
        modules: Some(modules),
        btf: None,
    }
}

#[test]
fn a_long_list_of_modules_is_cut_in_the_message_but_not_in_the_fix() {
    let names: Vec<String> = (0..12).map(|i| format!("mod_{i:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let all: Vec<&str> = refs.clone();
    let m = facts_for(Got::Value(set(&[])), Got::Value(set(&[])), dep(&all, true));
    let finding = judge(&rules_with_modules(&refs), &facts(m));
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("and 4 more"),
        "{}",
        finding.message
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("mod_00") && fix.contains("mod_11"), "{fix}");
    rdy_engine::fixtext::check(&fix).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn an_absent_module_and_an_available_one_are_both_reported_and_the_worse_level_wins() {
    let m = facts_for(
        Got::Value(set(&["overlay"])),
        Got::Value(set(&[])),
        dep(&["br_netfilter"], true),
    );
    let finding = judge(
        &rules_with_modules(&["overlay", "br_netfilter", "ip_vs"]),
        &facts(m),
    );
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("`ip_vs` is not available"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .message
            .contains("`br_netfilter` is installed but not loaded"),
        "{}",
        finding.message
    );
}

#[test]
fn the_pass_message_counts_the_modules() {
    let m = facts_for(
        Got::Value(set(&["a", "b"])),
        Got::Value(set(&[])),
        dep(&[], true),
    );
    let finding = judge(&rules_with_modules(&["a", "b"]), &facts(m));
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(
        finding.message,
        "All 2 required modules are loaded or built in."
    );
    let m = facts_for(
        Got::Value(set(&["a"])),
        Got::Value(set(&[])),
        dep(&[], true),
    );
    let finding = judge(&rules_with_modules(&["a"]), &facts(m));
    assert_eq!(
        finding.message,
        "The required module is loaded or built in."
    );
}

#[test]
fn an_unreadable_release_warns_and_does_not_block() {
    let rules = Rules {
        min: Some(want("5.4")),
        ..Rules::default()
    };
    for release in [
        Got::Absent,
        Got::Failed("permission denied".to_owned()),
        Got::Value("weird".to_owned()),
    ] {
        let finding = judge(
            &rules,
            &Facts {
                release,
                distro: Got::Absent,
                modules: None,
                btf: None,
            },
        );
        assert_eq!(finding.level, Level::Warn);
        assert!(
            finding
                .message
                .starts_with("The kernel version was not checked"),
            "{}",
            finding.message
        );
    }
}

#[test]
fn btf_is_judged_from_the_file() {
    let rules = Rules {
        btf: true,
        ..Rules::default()
    };
    let with = |btf| Facts {
        release: Got::Value("5.14.0-362.el9.x86_64".to_owned()),
        distro: Got::Absent,
        modules: None,
        btf: Some(btf),
    };
    assert_eq!(judge(&rules, &with(Got::Value(true))).level, Level::Pass);
    assert_eq!(judge(&rules, &with(Got::Absent)).level, Level::Fail);
    assert_eq!(judge(&rules, &with(Got::Value(false))).level, Level::Fail);
    assert_eq!(
        judge(&rules, &with(Got::Failed("permission denied".to_owned()))).level,
        Level::Warn
    );
}

#[test]
fn the_fix_follows_the_distribution_family() {
    let rules = Rules {
        min: Some(want("6.0")),
        ..Rules::default()
    };
    let with = |os_release: &str| Facts {
        release: Got::Value("5.14.0-362.el9.x86_64".to_owned()),
        distro: crate::os::release::parse(os_release).map_or(Got::Absent, Got::Value),
        modules: None,
        btf: None,
    };
    // The family comes from ID and ID_LIKE.
    let rhel = judge(&rules, &with("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"));
    assert!(
        rhel.fix
            .as_deref()
            .expect("fix")
            .contains("dnf upgrade kernel")
    );
    let ubuntu = judge(&rules, &with("ID=ubuntu\nID_LIKE=debian\n"));
    assert!(
        ubuntu
            .fix
            .as_deref()
            .expect("fix")
            .contains("apt full-upgrade")
    );
    let mint = judge(&rules, &with("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"));
    assert!(
        mint.fix
            .as_deref()
            .expect("fix")
            .contains("apt full-upgrade")
    );
    let other = judge(&rules, &with("ID=alpine\n"));
    assert!(
        other
            .fix
            .as_deref()
            .expect("fix")
            .contains("from the OS vendor")
    );
    for finding in [&rhel, &ubuntu, &mint, &other] {
        rdy_engine::fixtext::check(finding.fix.as_deref().expect("fix"))
            .unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn a_hostile_release_is_shown_escaped() {
    let rules = Rules {
        min: Some(want("6.0")),
        ..Rules::default()
    };
    let finding = judge(
        &rules,
        &Facts {
            release: Got::Value("5.4.0\u{1b}[2J\u{202e}x".to_owned()),
            distro: Got::Absent,
            modules: None,
            btf: None,
        },
    );
    assert!(!finding.message.contains('\u{1b}') && !finding.message.contains('\u{202e}'));
    assert!(finding.message.contains("\\x1b"), "{}", finding.message);
    assert!(!finding.observed.to_string().contains('\u{1b}'));
}

// ---- no input panics -----------------------------------------------------------------------------

proptest! {
    #[test]
    fn the_release_reader_and_compare_never_panic(text in ".{0,200}", spec in "[0-9]{1,3}(\\.[0-9]{1,3}){0,2}(-[0-9]{1,4})?") {
        if let Some(release) = version::parse(&text) {
            let _ = version::compare(&release, &want(&spec));
        }
        let _ = version::is_path_safe(&text);
    }

    #[test]
    fn the_scans_never_panic_and_report_only_wanted_names(text in ".{0,400}") {
        let wanted = set(&["overlay", "br_netfilter"]);
        for found in [
            modules::scan_loaded(&text, &wanted),
            modules::scan_paths(&text, &wanted),
        ] {
            prop_assert!(found.is_subset(&wanted));
        }
        let cut = file(&text, true, true);
        let dep = modules::scan_dep(&cut, Some(&cut), Some(10), &wanted);
        prop_assert!(dep.found.is_subset(&wanted));
        if let Some(name) = modules::name_of_path(&text) {
            prop_assert!(!name.contains('-'));
        }
    }
}
