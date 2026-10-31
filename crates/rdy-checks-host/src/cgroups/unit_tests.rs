//! Tests of the pure parts of `host.cgroups`: the two parsers, the fix text and the judgement. None of
//! them touches the machine or a fixture.

use std::collections::BTreeSet;

use rdy_engine::check::Level;

use super::fix::{self, Boot, Disabled, Edit};
use super::judge::{Facts, Rules, Wanted, judge};
use super::parse::{ProcController, disabling_word, parse_cmdline, parse_proc_cgroups, word_value};
use crate::cgroup::{Controllers, Layout, V2Controllers};
use crate::os::release;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn rules(version: Wanted, controllers: &[&str]) -> Rules {
    Rules {
        version,
        controllers: controllers.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn v2_host(available: &[&str], enabled: &[&str]) -> Controllers {
    Controllers {
        layout: Layout::V2,
        v2: Some(V2Controllers {
            top_available: Some(set(available)),
            top_enabled: Some(set(enabled)),
            own_available: None,
            own_enabled: None,
        }),
        v1: BTreeSet::new(),
    }
}

fn v1_host(controllers: &[&str]) -> Controllers {
    Controllers {
        layout: Layout::V1,
        v2: None,
        v1: set(controllers),
    }
}

fn proc_row(name: &str, hierarchy: u32, enabled: bool) -> ProcController {
    ProcController {
        name: name.to_owned(),
        hierarchy,
        enabled,
    }
}

fn facts(controllers: Controllers) -> Facts {
    Facts {
        controllers: Some(controllers),
        ..Facts::default()
    }
}

// ---- /proc/cgroups -------------------------------------------------------------------------------

#[test]
fn proc_cgroups_rows_are_read_and_the_header_is_skipped() {
    let rows = parse_proc_cgroups(
        "#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t0\t1\t1\nmemory\t0\t1\t0\nblkio\t4\t12\t1\n",
    );
    assert_eq!(
        rows,
        [
            proc_row("cpuset", 0, true),
            proc_row("memory", 0, false),
            proc_row("blkio", 4, true)
        ]
    );
}

#[test]
fn proc_cgroups_skips_a_row_that_does_not_fit() {
    let rows = parse_proc_cgroups(
        "memory 0 1 2\nCPU 0 1 1\npids x 1 1\ncpu 0\nnet_cls 0 1 1\n\n\0\u{202e} 0 1 1\n",
    );
    assert_eq!(rows, [proc_row("net_cls", 0, true)]);
}

#[test]
fn proc_cgroups_is_bounded() {
    let text = "cpu 0 1 1\n".repeat(100_000);
    assert_eq!(parse_proc_cgroups(&text).len(), 128);
}

// ---- /proc/cmdline -------------------------------------------------------------------------------

#[test]
fn only_cgroup_words_of_the_command_line_are_kept() {
    let words = parse_cmdline(
        "BOOT_IMAGE=/vmlinuz root=UUID=1234 ro ip=10.0.0.5::10.0.0.1:255.255.255.0 \
         password=hunter2 cgroup_disable=memory,pids systemd.unified_cgroup_hierarchy=1 quiet\n",
    );
    assert_eq!(
        words,
        [
            "cgroup_disable=memory,pids",
            "systemd.unified_cgroup_hierarchy=1"
        ]
    );
}

#[test]
fn a_cgroup_word_with_odd_characters_or_a_long_value_is_dropped() {
    let long = format!("cgroup_enable={}", "a".repeat(100));
    let text = format!(
        "cgroup_disable=mem`ory cgroup_enable=$(id) cgroup_memory=1;rm {long} cgroup_disable=\u{202e}x cgroup_enable=memory"
    );
    assert_eq!(parse_cmdline(&text), ["cgroup_enable=memory"]);
}

#[test]
fn the_command_line_is_bounded() {
    let text = "cgroup_enable=memory ".repeat(10_000);
    assert_eq!(parse_cmdline(&text).len(), 16);
}

#[test]
fn the_disabling_word_matches_either_name_of_a_controller() {
    let words = parse_cmdline("cgroup_disable=blkio,memory");
    assert_eq!(
        disabling_word(&words, ["blkio", "io"]),
        Some("cgroup_disable=blkio,memory")
    );
    assert_eq!(disabling_word(&words, ["pids", "pids"]), None);
    assert_eq!(
        word_value(
            &parse_cmdline("systemd.unified_cgroup_hierarchy=0 systemd.unified_cgroup_hierarchy=1"),
            "systemd.unified_cgroup_hierarchy="
        ),
        Some("1")
    );
}

// ---- the fix text follows host.os ----------------------------------------------------------------

fn boot_of(os_release: &str, raspberry_pi: bool) -> Boot {
    fix::boot_for(release::parse(os_release).as_ref(), raspberry_pi)
}

#[test]
fn the_boot_edit_follows_os_release_and_the_device_tree() {
    assert_eq!(boot_of("ID=rhel\nID_LIKE=fedora\n", false), Boot::Grubby);
    assert_eq!(
        boot_of("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", false),
        Boot::Grubby
    );
    assert_eq!(boot_of("ID=ol\nID_LIKE=fedora\n", false), Boot::Grubby);
    assert_eq!(
        boot_of("ID=amzn\nID_LIKE=\"centos rhel fedora\"\n", false),
        Boot::Grubby
    );
    assert_eq!(boot_of("ID=ubuntu\nID_LIKE=debian\n", false), Boot::Grub);
    assert_eq!(
        boot_of("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", false),
        Boot::Grub
    );
    assert_eq!(boot_of("ID=debian\n", false), Boot::Grub);
    assert_eq!(
        boot_of("ID=raspbian\nID_LIKE=debian\n", false),
        Boot::CmdlineTxt
    );
    assert_eq!(boot_of("ID=debian\n", true), Boot::CmdlineTxt);
    assert_eq!(boot_of("ID=sles\nID_LIKE=suse\n", false), Boot::Other);
    assert_eq!(fix::boot_for(None, false), Boot::Other);
    assert_eq!(fix::boot_for(None, true), Boot::CmdlineTxt);
}

#[test]
fn every_boot_edit_names_the_argument_and_a_reboot() {
    for boot in [Boot::Grubby, Boot::Grub, Boot::CmdlineTxt, Boot::Other] {
        for edit in [Edit::Add, Edit::Remove] {
            let text = fix::edit_cmdline(boot, edit, "cgroup_enable=memory");
            assert!(text.contains("cgroup_enable=memory"), "{text}");
            assert!(text.ends_with("reboot."), "{text}");
            if let Err(error) = rdy_engine::fixtext::check(&text) {
                panic!("{boot:?} {edit:?}: {error}");
            }
        }
    }
}

#[test]
fn a_disabled_controller_without_a_boot_word_is_turned_on_and_memory_on_a_pi_needs_two() {
    let off = [Disabled {
        controller: "memory".to_owned(),
        word: None,
    }];
    assert_eq!(
        fix::disabled_fix(Boot::Grubby, &off),
        "Run `grubby --update-kernel=ALL --args=\"cgroup_enable=memory\"` and reboot."
    );
    assert!(
        fix::disabled_fix(Boot::CmdlineTxt, &off)
            .contains("`cgroup_memory=1 cgroup_enable=memory`")
    );
}

#[test]
fn two_controllers_off_by_one_word_remove_it_once() {
    let off = [
        Disabled {
            controller: "memory".to_owned(),
            word: Some("cgroup_disable=memory,pids".to_owned()),
        },
        Disabled {
            controller: "pids".to_owned(),
            word: Some("cgroup_disable=memory,pids".to_owned()),
        },
    ];
    let text = fix::disabled_fix(Boot::Grub, &off);
    assert_eq!(
        text.matches("cgroup_disable=memory,pids").count(),
        1,
        "{text}"
    );
}

#[test]
fn a_list_reads_like_a_sentence() {
    let names = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(fix::list(&names(&[])), "");
    assert_eq!(fix::list(&names(&["a"])), "a");
    assert_eq!(fix::list(&names(&["a", "b"])), "a and b");
    assert_eq!(fix::list(&names(&["a", "b", "c"])), "a, b and c");
}

// ---- the judgement -------------------------------------------------------------------------------

#[test]
fn v2_wanted_on_v2_with_every_controller_passes() {
    let f = judge(
        &rules(Wanted::V2, &["cpu", "memory", "io", "pids"]),
        &facts(v2_host(
            &["cpu", "io", "memory", "pids"],
            &["cpu", "io", "memory", "pids"],
        )),
    );
    assert_eq!(f.level, Level::Pass);
    assert_eq!(
        f.message,
        "cgroup v2 in use, controllers `cpu`, `memory`, `io` and `pids` available"
    );
    assert_eq!(f.fix, None);
    assert!(f.notes.is_empty(), "{:?}", f.notes);
}

#[test]
fn the_v1_name_blkio_is_accepted_on_v2_and_io_on_v1() {
    let on_v2 = judge(
        &rules(Wanted::Any, &["blkio"]),
        &facts(v2_host(&["io"], &["io"])),
    );
    assert_eq!(on_v2.level, Level::Pass);

    let mut machine = facts(v1_host(&["blkio", "cpu", "cpuacct"]));
    machine.proc_cgroups = Some(vec![proc_row("blkio", 4, true)]);
    let on_v1 = judge(&rules(Wanted::Any, &["io", "cpu"]), &machine);
    assert_eq!(on_v1.level, Level::Pass);
}

#[test]
fn a_controller_the_proc_file_does_not_list_is_missing_on_v1() {
    let mut machine = facts(v1_host(&["cpu", "cpuacct"]));
    machine.proc_cgroups = Some(vec![proc_row("cpu", 7, true)]);
    let f = judge(&rules(Wanted::Any, &["misc"]), &machine);
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.notes.iter().any(|n| n.contains("does not list it")),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_controller_attached_to_v1_is_not_offered_by_v2() {
    let mut machine = facts(v2_host(&["cpu"], &["cpu"]));
    machine.proc_cgroups = Some(vec![proc_row("memory", 5, true)]);
    let f = judge(&rules(Wanted::Any, &["memory"]), &machine);
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("attached to a cgroup v1 hierarchy")),
        "{:?}",
        f.notes
    );
}

#[test]
fn unreadable_v2_lists_are_not_confirmed_not_missing() {
    let mut host = v2_host(&[], &[]);
    host.v2 = Some(V2Controllers {
        top_available: None,
        top_enabled: None,
        own_available: None,
        own_enabled: None,
    });
    let f = judge(&rules(Wanted::V2, &["memory"]), &facts(host));
    assert_eq!(f.level, Level::Warn);
    assert_eq!(f.observed["controllers"]["memory"], "not_confirmed");

    // The own cgroup's list stands in when the top one is unreadable.
    let mut host = v2_host(&[], &[]);
    host.v2 = Some(V2Controllers {
        top_available: None,
        top_enabled: None,
        own_available: Some(set(&["memory"])),
        own_enabled: None,
    });
    assert_eq!(
        judge(&rules(Wanted::V2, &["memory"]), &facts(host)).level,
        Level::Pass
    );
}

#[test]
fn a_fail_outranks_a_warn_and_both_are_said() {
    let mut machine = facts(v1_host(&["cpu"]));
    machine.proc_cgroups = Some(vec![
        proc_row("memory", 5, true),
        proc_row("pids", 6, false),
    ]);
    let f = judge(&rules(Wanted::V2, &["memory", "pids"]), &machine);
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "cgroup v1 in use, v2 needed, controller `pids` is missing, could not confirm `memory`"
    );
}

#[test]
fn no_cgroup_files_with_nothing_asked_passes_and_with_something_asked_warns() {
    let none = Facts::default();
    let f = judge(&rules(Wanted::Any, &[]), &none);
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.fix, None);
    let f = judge(&rules(Wanted::Any, &["memory"]), &none);
    assert_eq!(f.level, Level::Warn);
    assert!(f.fix.is_some());
    let unmounted = Controllers {
        layout: Layout::Unmounted,
        v2: None,
        v1: BTreeSet::new(),
    };
    assert_eq!(
        judge(&rules(Wanted::V1, &[]), &facts(unmounted)).level,
        Level::Warn
    );
}

#[test]
fn a_hostile_cgroup_word_cannot_reach_the_fix_text() {
    let mut machine = facts(v2_host(&["cpu"], &["cpu"]));
    machine.cmdline = parse_cmdline("cgroup_disable=memory`;reboot");
    machine.proc_cgroups = Some(vec![proc_row("memory", 0, false)]);
    let f = judge(&rules(Wanted::V2, &["memory"]), &machine);
    let fix = f.fix.expect("a fix");
    assert!(!fix.contains(';') && !fix.contains("reboot`"), "{fix}");
    assert!(fix.contains("cgroup_enable=memory"), "{fix}");
}
