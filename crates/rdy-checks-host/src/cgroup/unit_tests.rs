//! Table tests of the parsers, and in-memory machines for the shapes a fixture directory cannot hold
//! well: a container with its own cgroup namespace, a bind-mounted subtree, a cgroup outside the mount,
//! unreadable and garbled files.

use rdy_engine::check::Os;
use rdy_engine::testing::{Replay, TestRun};

use super::parse::{
    components, parse_bytes, parse_cfs, parse_cpu_max, parse_mountinfo, parse_proc_cgroup, unescape,
};
use super::tests::{INFO, block_on, context};
use super::*;

#[test]
fn bytes_max_and_both_page_size_sentinels_are_unlimited() {
    assert_eq!(parse_bytes("max\n"), Ok(None));
    assert_eq!(parse_bytes("9223372036854771712\n"), Ok(None));
    assert_eq!(parse_bytes("9223372036854710272\n"), Ok(None));
    assert_eq!(parse_bytes("9223372036854775807"), Ok(None));
    assert_eq!(parse_bytes("18446744073709551615"), Ok(None));
    assert_eq!(parse_bytes("4294967296\n"), Ok(Some(4_294_967_296)));
    // Zero is a real limit: `memory.swap.max` of 0 turns swap off for the cgroup.
    assert_eq!(parse_bytes("0\n"), Ok(Some(0)));
    assert!(parse_bytes("").is_err());
    assert!(parse_bytes("-1").is_err());
    assert!(parse_bytes("4G").is_err());
}

#[test]
fn cpu_max_reads_quota_and_period() {
    let two = CpuQuota {
        quota_us: 200_000,
        period_us: 100_000,
    };
    assert_eq!(parse_cpu_max("200000 100000\n"), Ok(Some(two)));
    assert_eq!(parse_cpu_max("max 100000\n"), Ok(None));
    assert_eq!(parse_cpu_max("max\n"), Ok(None));
    assert_eq!(
        parse_cpu_max("50000 100000"),
        Ok(Some(CpuQuota {
            quota_us: 50_000,
            period_us: 100_000
        }))
    );
    assert!(parse_cpu_max("").is_err());
    assert!(parse_cpu_max("0 100000").is_err());
    assert!(parse_cpu_max("200000 0").is_err());
    assert!(parse_cpu_max("200000 100000 1").is_err());
    assert!(parse_cpu_max("lots 100000").is_err());
}

#[test]
fn cfs_quota_minus_one_is_unlimited() {
    assert_eq!(parse_cfs("-1\n", "100000\n"), Ok(None));
    assert_eq!(
        parse_cfs("150000\n", "100000\n"),
        Ok(Some(CpuQuota {
            quota_us: 150_000,
            period_us: 100_000
        }))
    );
    assert!(parse_cfs("-2", "100000").is_err());
    assert!(parse_cfs("150000", "0").is_err());
    assert!(parse_cfs("150000", "").is_err());
}

#[test]
fn quotas_compare_by_cores_not_by_microseconds() {
    let a = CpuQuota {
        quota_us: 50_000,
        period_us: 50_000,
    };
    let b = CpuQuota {
        quota_us: 150_000,
        period_us: 100_000,
    };
    assert!(a.less_than(&b));
    assert!(!b.less_than(&a));
    assert!(!a.less_than(&a));
    // Large numbers do not overflow the comparison.
    let big = CpuQuota {
        quota_us: u64::MAX,
        period_us: 1,
    };
    assert!(b.less_than(&big));
}

#[test]
fn proc_cgroup_lines_parse() {
    let lines = parse_proc_cgroup(
        "11:cpu,cpuacct:/a/b\n1:name=systemd:/a\n0::/a/b (deleted)\n\n5:memory:/we:ird\n",
    )
    .expect("parses");
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0].controllers, ["cpu", "cpuacct"]);
    assert_eq!(lines[0].path, "/a/b");
    assert_eq!(lines[1].controllers, ["name=systemd"]);
    assert!(lines[2].controllers.is_empty());
    assert_eq!(
        lines[2].path, "/a/b",
        "the deleted marker is not part of the path"
    );
    assert_eq!(
        lines[3].path, "/we:ird",
        "a colon in the path stays in the path"
    );
}

#[test]
fn malformed_proc_cgroup_is_named_by_line() {
    for bad in [
        "nonsense\n",
        "x:memory:/a\n",
        "1:memory:relative\n",
        "0::/a\n7\n",
    ] {
        assert!(parse_proc_cgroup(bad).is_err(), "{bad:?}");
    }
    let reason = parse_proc_cgroup("0::/a\n7\n").expect_err("bad");
    assert!(reason.contains("line 2"), "{reason}");
}

#[test]
fn mountinfo_keeps_only_cgroup_mounts_and_unescapes_paths() {
    let text = "\
21 28 0:5 / /proc rw,nosuid shared:12 - proc proc rw
23 22 0:22 /docker/abc /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup2 rw,nsdelegate
24 23 0:23 / /sys/fs/cgroup/cpu\\040set rw master:3 shared:4 - cgroup cgroup rw,cpu,cpuacct
25 23 0:24 / /sys/fs/cgroup/odd rw - tmpfs tmpfs rw
broken line
";
    let mounts = parse_mountinfo(text);
    assert_eq!(mounts.len(), 2);
    assert!(mounts[0].v2);
    assert_eq!(mounts[0].root, "/docker/abc");
    assert_eq!(mounts[0].point, "/sys/fs/cgroup");
    assert_eq!(mounts[0].super_opts, ["rw", "nsdelegate"]);
    assert!(!mounts[1].v2);
    assert_eq!(mounts[1].point, "/sys/fs/cgroup/cpu set");
    assert_eq!(mounts[1].super_opts, ["rw", "cpu", "cpuacct"]);
}

#[test]
fn octal_escapes_are_undone() {
    assert_eq!(unescape("a\\040b"), "a b");
    assert_eq!(unescape("a\\134b"), "a\\b");
    assert_eq!(unescape("a\\011b\\012"), "a\tb\n");
    // Not an escape: too short, or not octal.
    assert_eq!(unescape("a\\04"), "a\\04");
    assert_eq!(unescape("a\\089"), "a\\089");
    assert_eq!(
        unescape("\\400"),
        "\\400",
        "a value above 255 is not a byte"
    );
}

#[test]
fn dot_components_make_a_path_not_visible() {
    assert_eq!(components("/a//b/"), Some(vec!["a", "b"]));
    assert_eq!(components("/"), Some(vec![]));
    assert_eq!(components("/../x"), None);
    assert_eq!(components("/a/./b"), None);
}

/// A Linux machine with the given files.
fn machine(cgroup: &str, mountinfo: &str, files: &[(&str, &str)]) -> Replay {
    files.iter().fold(
        Replay::new()
            .file("/proc/self/cgroup", cgroup)
            .file("/proc/self/mountinfo", mountinfo),
        |replay, (path, text)| replay.file(path, *text),
    )
}

const V2_AT_ROOT: &str = "23 22 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";

fn discover(replay: Replay) -> (Cgroups, rdy_engine::check::CheckContext, TestRun) {
    let run = TestRun::new(replay);
    let ctx = context(&run, &INFO, Os::Linux);
    let cgroups = block_on(Cgroups::discover(ctx.probe()))
        .expect("discovery")
        .expect("cgroups");
    (cgroups, ctx, run)
}

#[test]
fn a_container_in_its_own_cgroup_namespace_reads_the_top_of_the_mount() {
    // `/proc/self/cgroup` says `/`: the container cgroup is the root the mount shows.
    let (cgroups, ctx, _) = discover(machine(
        "0::/\n",
        V2_AT_ROOT,
        &[
            ("/sys/fs/cgroup/memory.max", "536870912\n"),
            ("/sys/fs/cgroup/memory.swap.max", "0\n"),
            ("/sys/fs/cgroup/cpu.max", "50000 100000\n"),
        ],
    ));
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(
        memory.limit.min.as_ref().map(|b| (b.value, b.at.as_str())),
        Some((536_870_912, "/"))
    );
    // A swap limit of 0 is a finite limit, not "unlimited".
    assert_eq!(memory.swap.min.as_ref().map(|b| b.value), Some(0));
    assert!(!memory.limit.hidden_above);
    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert!((cpu.quota.min.expect("quota").value.cores() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn a_bind_mounted_subtree_stops_at_its_root_and_says_what_is_hidden() {
    // Host cgroup namespace, the runtime mounted only `/docker/abc`.
    let (cgroups, ctx, _) = discover(machine(
        "0::/docker/abc/app\n",
        "23 22 0:22 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
        &[
            ("/sys/fs/cgroup/memory.max", "2147483648\n"),
            ("/sys/fs/cgroup/app/memory.max", "max\n"),
        ],
    ));
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    let min = memory.limit.min.expect("a limit");
    assert_eq!(min.at, "/docker/abc");
    assert_eq!(min.value, 2_147_483_648);
    assert_eq!(memory.limit.levels_read, 2);
    assert!(memory.limit.hidden_above);
}

#[test]
fn a_cgroup_outside_every_visible_mount_gives_no_answer() {
    for (cgroup, mount) in [
        // The mount shows a subtree this process is not in.
        (
            "0::/system.slice/x\n",
            "23 22 0:22 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
        ),
        // A cgroup outside the cgroup namespace.
        ("0::/../../x\n", V2_AT_ROOT),
    ] {
        let (cgroups, ctx, run) = discover(machine(
            cgroup,
            mount,
            &[("/sys/fs/cgroup/memory.max", "1048576\n")],
        ));
        let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
        assert_eq!(memory.hierarchy, None, "{cgroup}");
        assert!(!memory.limit.is_present());
        // Nothing was read under the mount.
        assert!(
            run.action_log()
                .actions
                .iter()
                .all(|a| a.fields.get("path").and_then(|p| p.as_str())
                    != Some("/sys/fs/cgroup/memory.max")),
            "{cgroup}"
        );
    }
}

#[test]
fn equal_limits_report_the_cgroup_nearest_the_process() {
    let (cgroups, ctx, _) = discover(machine(
        "0::/a/b\n",
        V2_AT_ROOT,
        &[
            ("/sys/fs/cgroup/a/memory.max", "1048576\n"),
            ("/sys/fs/cgroup/a/b/memory.max", "1048576\n"),
        ],
    ));
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.limit.min.expect("limit").at, "/a/b");
}

#[test]
fn a_level_that_cannot_be_read_or_understood_is_counted_not_hidden() {
    let replay = machine(
        "0::/a/b/c\n",
        V2_AT_ROOT,
        &[
            ("/sys/fs/cgroup/a/memory.max", "4194304\n"),
            ("/sys/fs/cgroup/a/b/memory.max", "garbage\n"),
            ("/sys/fs/cgroup/a/b/c/memory.max", "max\n"),
        ],
    )
    .unreadable("/sys/fs/cgroup/a/b/c/memory.swap.max")
    .file("/sys/fs/cgroup/a/b/c/memory.swap.max", "1\n");
    let (cgroups, ctx, _) = discover(replay);
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    // The garbled level is counted, and the rest still gives the minimum.
    assert_eq!(memory.limit.unreadable, 1);
    assert_eq!(memory.limit.levels_read, 2);
    assert!(!memory.limit.is_complete());
    assert_eq!(memory.limit.min.expect("limit").at, "/a");
    assert_eq!(memory.swap.unreadable, 1);
}

#[test]
fn an_unreadable_directory_below_the_top_counts_each_level_under_it() {
    let replay = machine(
        "0::/a/b\n",
        V2_AT_ROOT,
        &[
            ("/sys/fs/cgroup/memory.max", "max\n"),
            ("/sys/fs/cgroup/a/memory.max", "max\n"),
            ("/sys/fs/cgroup/a/b/memory.max", "max\n"),
        ],
    )
    .unreadable("/sys/fs/cgroup/a");
    let (cgroups, ctx, _) = discover(replay);
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.limit.unreadable, 2);
    assert_eq!(memory.limit.levels_read, 1);
}

#[test]
fn v1_cpu_quota_without_a_period_file_is_unreadable() {
    let (cgroups, ctx, _) = discover(machine(
        "3:cpu,cpuacct:/a\n",
        "24 23 0:23 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n",
        &[("/sys/fs/cgroup/cpu,cpuacct/a/cpu.cfs_quota_us", "50000\n")],
    ));
    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert_eq!(cpu.hierarchy, Some(Hierarchy::V1));
    assert_eq!(cpu.quota.unreadable, 1);
    assert_eq!(cpu.quota.min, None);
}

#[test]
fn a_malformed_proc_cgroup_is_an_error_with_a_fix_hint() {
    let run = TestRun::new(machine("not a cgroup file\n", V2_AT_ROOT, &[]));
    let ctx = context(&run, &INFO, Os::Linux);
    let error = block_on(Cgroups::discover(ctx.probe())).expect_err("malformed");
    assert!(matches!(error, CgroupError::Malformed { .. }), "{error:?}");
    let text = error.to_string();
    assert!(text.contains("Fix:"), "{text}");
    assert!(
        !text.contains("not a cgroup file"),
        "the error never echoes file content"
    );
}

#[test]
fn no_mountinfo_means_unmounted_and_no_answers() {
    let run = TestRun::new(Replay::new().file("/proc/self/cgroup", "0::/a\n"));
    let ctx = context(&run, &INFO, Os::Linux);
    let cgroups = block_on(Cgroups::discover(ctx.probe()))
        .expect("discovery")
        .expect("cgroups");
    assert_eq!(cgroups.layout(), Layout::Unmounted);
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, None);
    let found = block_on(cgroups.controllers(ctx.probe())).expect("controllers");
    assert_eq!(found.v2, None);
    assert!(found.v1.is_empty());
}

#[test]
fn a_path_with_a_backslash_in_a_unit_name_is_read_as_written() {
    // systemd escapes `-` in unit names as `\x2d`, so a real cgroup path holds a backslash. The helper
    // joins path text with `/` and never treats a backslash as a separator. A fixture directory cannot
    // hold this name on a Windows checkout, so this checks the path text and reads no file.
    let (cgroups, _, _) = discover(machine(
        "0::/system.slice/acme\\x2dapi.service\n",
        V2_AT_ROOT,
        &[],
    ));
    let place = cgroups.v2.as_ref().expect("a placement");
    assert_eq!(place.comps, ["system.slice", "acme\\x2dapi.service"]);
    let levels = place.levels();
    assert_eq!(levels[0].at, "/system.slice/acme\\x2dapi.service");
    assert_eq!(
        levels[0].dir,
        "/sys/fs/cgroup/system.slice/acme\\x2dapi.service"
    );
    assert_eq!(levels.last().map(|l| l.at.as_str()), Some("/"));
    assert_eq!(
        levels.last().map(|l| l.dir.as_str()),
        Some("/sys/fs/cgroup")
    );
}
