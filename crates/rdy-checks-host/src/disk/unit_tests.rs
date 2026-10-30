//! Unit tests of the mount table rules and of the judgement, with no probe and no fixture.

use rdy_engine::check::Level;
use rdy_engine::probe::StatvfsInfo;

use super::mountinfo::{self, Lookup};
use super::*;

const GIB: u64 = 1 << 30;

fn mount(dev: (u32, u32), point: &str, options: &str, fstype: &str, source: &str) -> Mount {
    Mount {
        dev,
        point: point.to_owned(),
        options: options.split(',').map(str::to_owned).collect(),
        fstype: fstype.to_owned(),
        source: source.to_owned(),
    }
}

fn found_btrfs(lookup: Lookup<'_>) -> &str {
    match lookup {
        Lookup::BtrfsByPath(m) => &m.point,
        other => panic!("not a btrfs match: {other:?}"),
    }
}

fn found(lookup: Lookup<'_>) -> &str {
    match lookup {
        Lookup::Found(m) => &m.point,
        other => panic!("not found: {other:?}"),
    }
}

// ---- mountinfo ----------------------------------------------------------------------------------

#[test]
fn a_line_is_read_field_by_field_with_escapes_decoded() {
    let text = "27 22 253:2 / /mnt/acme\\040data rw,nosuid,relatime shared:8 master:1 - xfs /dev/mapper/rl-acme rw,seclabel\n";
    let parsed = mountinfo::parse(text);
    assert_eq!(parsed.skipped, 0);
    assert_eq!(
        parsed.mounts,
        [mount(
            (253, 2),
            "/mnt/acme data",
            "rw,nosuid,relatime",
            "xfs",
            "/dev/mapper/rl-acme"
        )]
    );
}

#[test]
fn octal_escapes_cover_a_tab_a_newline_and_a_backslash() {
    let text = "1 0 8:1 / /a\\011b\\012c\\134d rw - ext4 /dev/sda1 rw\n";
    let parsed = mountinfo::parse(text);
    assert_eq!(parsed.mounts[0].point, "/a\tb\nc\\d");
}

#[test]
fn a_line_with_no_optional_fields_still_reads() {
    let parsed = mountinfo::parse("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
    assert_eq!(parsed.mounts.len(), 1);
    assert_eq!(parsed.mounts[0].fstype, "ext4");
}

#[test]
fn damaged_lines_are_counted_and_left_out() {
    let text = "garbage\n1 0 8:x / / rw - ext4 /dev/sda1 rw\n1 0 8:1 / / rw ext4\n1 0 8:1 / / rw - \n\n2 1 8:2 / /data rw - xfs /dev/sdb rw\n";
    let parsed = mountinfo::parse(text);
    assert_eq!(parsed.mounts.len(), 1);
    assert_eq!(parsed.skipped, 4);
}

#[test]
fn a_device_is_two_decimal_numbers() {
    assert_eq!(mountinfo::device("253:1"), Some((253, 1)));
    for bad in [
        "", "253", "253:", ":1", "a:1", "1:b", "1:2:3", "-1:2", "+1:2",
    ] {
        assert_eq!(mountinfo::device(bad), None, "{bad}");
    }
}

#[test]
fn components_drop_empty_parts_and_dots_and_refuse_dotdot() {
    assert_eq!(
        mountinfo::components("/var//lib/./acme/"),
        Some(vec!["var", "lib", "acme"])
    );
    assert_eq!(mountinfo::components("/"), Some(vec![]));
    assert_eq!(mountinfo::components("/var/../etc"), None);
}

#[test]
fn the_longest_whole_component_mount_wins() {
    let mounts = [
        mount((8, 1), "/", "rw", "xfs", "/dev/sda1"),
        mount((8, 1), "/var", "rw", "xfs", "/dev/sda1"),
        mount((8, 1), "/var/lib", "rw", "xfs", "/dev/sda1"),
    ];
    assert_eq!(
        found(mountinfo::find(&mounts, (8, 1), &["var", "lib", "acme"])),
        "/var/lib"
    );
    assert_eq!(
        found(mountinfo::find(&mounts, (8, 1), &["var", "tmp"])),
        "/var"
    );
}

#[test]
fn var_does_not_match_variable() {
    let mounts = [
        mount((8, 1), "/", "rw", "xfs", "/dev/sda1"),
        mount((8, 1), "/var", "rw,nodev", "xfs", "/dev/sda1"),
    ];
    assert_eq!(
        found(mountinfo::find(&mounts, (8, 1), &["variable", "x"])),
        "/"
    );
}

#[test]
fn only_lines_with_the_device_count() {
    let mounts = [
        mount((8, 1), "/", "rw", "xfs", "/dev/sda1"),
        mount((8, 2), "/var", "rw", "ext4", "/dev/sda2"),
    ];
    // The deeper mount point is on another device, so it is not the answer.
    assert_eq!(
        found(mountinfo::find(&mounts, (8, 1), &["var", "lib"])),
        "/"
    );
    assert_eq!(mountinfo::find(&mounts, (9, 9), &["var"]), Lookup::NoDevice);
}

#[test]
fn a_later_line_wins_a_tie_because_it_was_mounted_over_the_earlier() {
    let mounts = [
        mount((8, 1), "/data", "rw", "xfs", "/dev/sda1"),
        mount((8, 1), "/data", "ro", "xfs", "/dev/sda1"),
    ];
    let Lookup::Found(m) = mountinfo::find(&mounts, (8, 1), &["data", "x"]) else {
        panic!("not found");
    };
    assert!(m.has_option("ro"));
}

#[test]
fn a_path_through_a_link_uses_the_only_line_of_the_device() {
    // The path was written through a link, so no mount point is above it. One line has the device, and
    // the device names the file system.
    let mounts = [
        mount((8, 1), "/", "rw", "xfs", "/dev/sda1"),
        mount((8, 2), "/data", "rw", "ext4", "/dev/sdb1"),
    ];
    assert_eq!(
        found(mountinfo::find(&mounts, (8, 2), &["srv", "acme"])),
        "/data"
    );
}

#[test]
fn several_lines_and_no_prefix_is_not_known() {
    let mounts = [
        mount((8, 2), "/data", "rw", "ext4", "/dev/sdb1"),
        mount((8, 2), "/backup", "rw", "ext4", "/dev/sdb1"),
    ];
    assert_eq!(
        mountinfo::find(&mounts, (8, 2), &["srv", "acme"]),
        Lookup::Ambiguous
    );
}

#[test]
fn a_dotdot_mount_point_is_never_a_prefix() {
    let mounts = [
        mount((8, 1), "/a/../b", "rw", "xfs", "/dev/sda1"),
        mount((8, 1), "/c", "rw", "xfs", "/dev/sda1"),
    ];
    assert_eq!(
        mountinfo::find(&mounts, (8, 1), &["a", "x"]),
        Lookup::Ambiguous
    );
}

#[test]
fn listed_types_cover_their_variants() {
    assert!(mountinfo::type_matches("nfs", "nfs"));
    assert!(mountinfo::type_matches("nfs", "nfs4"));
    assert!(mountinfo::type_matches("fuse", "fuse.sshfs"));
    assert!(mountinfo::type_matches("fuse.sshfs", "fuse.sshfs"));
    assert!(!mountinfo::type_matches("fuse", "fuseblk"));
    assert!(!mountinfo::type_matches("ext", "ext4"));
    assert!(!mountinfo::type_matches("nfs4", "nfs"));
    assert!(mountinfo::is_network("nfs4"));
    assert!(mountinfo::is_network("cifs"));
    assert!(!mountinfo::is_network("xfs"));
}

// ---- the judgement ------------------------------------------------------------------------------

fn rules() -> Rules {
    Rules {
        min: 20 * GIB,
        recommended: 24 * GIB,
        min_inodes: 100_000,
        forbid: Vec::new(),
        forbid_fstypes: Vec::new(),
    }
}

fn stat(free_gib: u64) -> StatvfsInfo {
    let mut stat = StatvfsInfo::default();
    stat.fragment_size = 4096;
    stat.blocks = 400 * GIB / 4096;
    stat.blocks_free = free_gib * GIB / 4096;
    stat.blocks_available = free_gib * GIB / 4096;
    stat.files = 1_000_000;
    stat.files_free = 900_000;
    stat.no_exec = Some(false);
    stat.dev = Some((253, 1));
    stat
}

fn var_mount() -> MountState {
    MountState::Found(mount(
        (253, 1),
        "/var",
        "rw,relatime",
        "ext4",
        "/dev/mapper/rl-var",
    ))
}

fn facts(stat: StatvfsInfo, mount: MountState) -> Facts<'static> {
    Facts {
        requested: "/var/lib/acme",
        measured: "/var/lib/acme".to_owned(),
        stat,
        mount,
        reading: Vec::new(),
        root: false,
    }
}

#[test]
fn free_space_has_three_bands() {
    let at = |gib: u64| judge(&rules(), &facts(stat(gib), var_mount())).level;
    assert_eq!(at(30), Level::Pass);
    assert_eq!(at(24), Level::Pass);
    assert_eq!(at(23), Level::Warn);
    assert_eq!(at(20), Level::Warn);
    assert_eq!(at(19), Level::Fail);
    assert_eq!(at(0), Level::Fail);
}

#[test]
fn free_space_is_what_an_ordinary_user_can_use() {
    // `blocks_free` counts root's reserve. Only `blocks_available` decides.
    let mut s = stat(10);
    s.blocks_free = 50 * GIB / 4096;
    let finding = judge(&rules(), &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(finding.observed["free_bytes"], 10 * GIB);
}

#[test]
fn a_huge_count_does_not_overflow() {
    let mut s = stat(10);
    s.fragment_size = u64::MAX;
    s.blocks_available = u64::MAX;
    s.blocks = u64::MAX;
    let finding = judge(&rules(), &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.observed["free_bytes"], Quantity::MAX_BYTES);
}

#[test]
fn a_zero_block_size_is_not_verified_never_a_block() {
    let mut s = stat(10);
    s.fragment_size = 0;
    let finding = judge(&rules(), &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.partial.is_some());
}

#[test]
fn inodes_default_to_a_hundred_thousand_and_are_skipped_without_accounting() {
    let mut s = stat(100);
    s.files_free = 99_999;
    assert_eq!(judge(&rules(), &facts(s, var_mount())).level, Level::Fail);
    s.files_free = 100_000;
    assert_eq!(judge(&rules(), &facts(s, var_mount())).level, Level::Pass);
    s.files = 0;
    s.files_free = 0;
    let finding = judge(&rules(), &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.notes.iter().any(|n| n.contains("no inode count")));
    assert_eq!(finding.observed["free_inodes"], Value::Null);
}

#[test]
fn flags_fail_only_when_the_spec_forbids_them() {
    let mut s = stat(100);
    s.no_exec = Some(true);
    s.no_suid = true;
    assert_eq!(judge(&rules(), &facts(s, var_mount())).level, Level::Pass);
    for (option, word) in [
        (MountOption::Noexec, "noexec"),
        (MountOption::Nosuid, "nosuid"),
    ] {
        let mut r = rules();
        r.forbid = vec![option];
        let finding = judge(&r, &facts(s, var_mount()));
        assert_eq!(finding.level, Level::Fail, "{word}");
        assert!(finding.message.contains(word));
        let fix = finding.fix.expect("a fix");
        assert!(fix.contains("mount -o remount,"), "{fix}");
        assert!(fix.contains("/var"), "{fix}");
    }
}

#[test]
fn nodev_comes_from_the_mount_line() {
    let mut r = rules();
    r.forbid = vec![MountOption::Nodev];
    let with = MountState::Found(mount((253, 1), "/var", "rw,nodev", "ext4", "/dev/x"));
    assert_eq!(judge(&r, &facts(stat(100), with)).level, Level::Fail);
    assert_eq!(judge(&r, &facts(stat(100), var_mount())).level, Level::Pass);
    let unknown = MountState::Unknown("no line".to_owned());
    let finding = judge(&r, &facts(stat(100), unknown));
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.partial.is_some());
}

#[test]
fn an_unknown_noexec_is_not_a_pass() {
    // macOS reports no `noexec`: unknown, which a forbid must not read as "not set".
    let mut s = stat(100);
    s.no_exec = None;
    let mut r = rules();
    r.forbid = vec![MountOption::Noexec];
    let finding = judge(&r, &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("Not verified"));
    // Without the forbid it is nothing to report.
    assert_eq!(judge(&rules(), &facts(s, var_mount())).level, Level::Pass);
}

#[test]
fn read_only_is_evidence_and_fails_only_when_the_spec_forbids_it() {
    let mut s = stat(100);
    s.read_only = true;
    // The spec did not forbid `ro`, so the check stays quiet and only records it.
    let finding = judge(&rules(), &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Pass);
    assert!(!finding.message.contains("read-only"));
    assert_eq!(finding.observed["read_only"], true);
    let mut r = rules();
    r.forbid = vec![MountOption::Ro];
    let finding = judge(&r, &facts(s, var_mount()));
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.fix.expect("a fix").contains("remount,rw /var"));
}

#[test]
fn a_forbidden_type_fails_and_an_unknown_type_cannot_pass() {
    let mut r = rules();
    r.forbid_fstypes = vec!["ext4".to_owned()];
    assert_eq!(judge(&r, &facts(stat(100), var_mount())).level, Level::Fail);
    let unknown = MountState::Unknown("no line".to_owned());
    assert_eq!(judge(&r, &facts(stat(100), unknown)).level, Level::Warn);
    r.forbid_fstypes = vec!["nfs".to_owned()];
    assert_eq!(judge(&r, &facts(stat(100), var_mount())).level, Level::Pass);
}

#[test]
fn a_fail_and_an_unverified_part_together_still_block_and_carry_the_partial() {
    let mut r = rules();
    r.forbid = vec![MountOption::Nodev];
    let unknown = MountState::Unknown("no line".to_owned());
    let finding = judge(&r, &facts(stat(5), unknown));
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.partial.is_some());
}

#[test]
fn the_root_note_is_there_only_for_root() {
    let mut f = facts(stat(100), var_mount());
    assert!(judge(&rules(), &f).notes.is_empty());
    f.root = true;
    let notes = judge(&rules(), &f).notes;
    assert_eq!(notes.len(), 1);
    assert!(notes[0].contains("reserved for root"));
}

#[test]
fn the_expected_block_holds_the_effective_thresholds() {
    let finding = judge(&rules(), &facts(stat(100), var_mount()));
    assert_eq!(finding.expected["min"], 20 * GIB);
    assert_eq!(finding.expected["recommended"], 24 * GIB);
    assert_eq!(finding.expected["min_inodes"], 100_000);
}

// ---- the spec -----------------------------------------------------------------------------------

fn params(value: Value) -> Disk {
    let spec: rdy_spec::spec::CheckSpec = serde_json::from_value(value).expect("an entry");
    match spec.decode_params() {
        rdy_spec::check::CheckParams::HostDisk(p) => Disk::new(&p),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_spec_sets_the_thresholds_and_the_defaults_fill_the_rest() {
    let d = params(json!({"id": "host.disk", "path": "/var/lib/acme", "min": "20Gi"}));
    assert_eq!(d.path(), "/var/lib/acme");
    assert_eq!(d.rules.min, 20 * GIB);
    assert_eq!(d.rules.recommended, 24 * GIB);
    assert_eq!(d.rules.min_inodes, 100_000);
    assert!(d.rules.forbid.is_empty() && d.rules.forbid_fstypes.is_empty());

    let d = params(json!({
        "id": "host.disk", "path": "/data", "min": "10Gi", "recommended": "50Gi",
        "min_inodes": 5, "forbid_options": ["noexec", "ro"], "forbid_fstypes": ["nfs", "cifs"]
    }));
    assert_eq!(d.rules.recommended, 50 * GIB);
    assert_eq!(d.rules.min_inodes, 5);
    assert_eq!(d.rules.forbid, [MountOption::Noexec, MountOption::Ro]);
    assert_eq!(d.rules.forbid_fstypes, ["nfs", "cifs"]);

    // A recommended level under the minimum cannot make the check warn below its own fail level.
    let d =
        params(json!({"id": "host.disk", "path": "/data", "min": "10Gi", "recommended": "5Gi"}));
    assert_eq!(d.rules.recommended, 10 * GIB);
}

// ---- the text -----------------------------------------------------------------------------------

#[test]
fn a_word_is_quoted_or_refused_never_passed_through() {
    assert_eq!(word("/var/lib/acme").as_deref(), Some("/var/lib/acme"));
    assert_eq!(word("/mnt/acme data").as_deref(), Some("'/mnt/acme data'"));
    assert_eq!(word("/a;rm -rf ~").as_deref(), Some("'/a;rm -rf ~'"));
    assert_eq!(word("/a$(id)").as_deref(), Some("'/a$(id)'"));
    for bad in [
        "",
        "/a'b",
        "/a`b",
        "/a\nb",
        "/a\tb",
        "/a\u{202e}b",
        "/a\u{200b}b",
        "/a\u{feff}b",
        "/a\u{fffd}b",
    ] {
        assert_eq!(word(bad), None, "{bad:?}");
    }
}

#[test]
fn a_hostile_mount_point_never_reaches_a_command() {
    let mut r = rules();
    r.forbid = vec![MountOption::Noexec];
    let mut s = stat(100);
    s.no_exec = Some(true);
    for point in ["/mnt/x`id`", "/mnt/x'; id; '", "/mnt/x\nid"] {
        let m = MountState::Found(mount((253, 1), point, "rw", "ext4", "/dev/mapper/a`b"));
        let finding = judge(&r, &facts(s, m));
        let fix = finding.fix.expect("a fix");
        assert!(!fix.contains("mount -o"), "{fix}");
    }
}

#[test]
fn the_fix_text_names_only_allowed_commands() {
    let text = INFO.meta.remediation;
    rdy_engine::fixtext::check(text).unwrap_or_else(|e| panic!("{e}"));

    let mut r = rules();
    r.forbid = vec![
        MountOption::Noexec,
        MountOption::Nosuid,
        MountOption::Nodev,
        MountOption::Ro,
    ];
    r.forbid_fstypes = vec!["ext4".to_owned()];
    let mut s = stat(5);
    s.no_exec = Some(true);
    s.no_suid = true;
    s.read_only = true;
    s.files_free = 3;
    let m = MountState::Found(mount(
        (253, 1),
        "/mnt/acme data",
        "rw,nodev",
        "ext4",
        "/dev/mapper/rl-acme",
    ));
    for (state, forbid) in [(m, r.clone()), (MountState::Unknown("why".to_owned()), r)] {
        let finding = judge(&forbid, &facts(s, state));
        let fix = finding.fix.expect("a fix");
        rdy_engine::fixtext::check(&fix).unwrap_or_else(|e| panic!("{fix}: {e}"));
        assert!(!fix.contains('{') && !fix.contains('}'), "{fix}");
    }
}

#[test]
fn an_lvm_volume_gets_a_grow_command_sized_to_the_gap() {
    let finding = judge(&rules(), &facts(stat(10), var_mount()));
    let fix = finding.fix.expect("a fix");
    // 24 GiB recommended, 10 GiB free: 14 GiB more.
    assert!(
        fix.contains("If `/dev/mapper/rl-var` is an LVM volume, grow it with `lvextend -r -L +14G /dev/mapper/rl-var`"),
        "{fix}"
    );
    assert!(fix.contains("df -h /var/lib/acme"), "{fix}");
    // A plain disk gets no invented volume name.
    let plain = MountState::Found(mount((253, 1), "/var", "rw", "ext4", "/dev/sda3"));
    let fix = judge(&rules(), &facts(stat(10), plain)).fix.expect("a fix");
    assert!(!fix.contains("lvextend"), "{fix}");
}

#[test]
fn lvextend_is_for_a_growable_type_on_a_mapper_source_that_is_not_encrypted() {
    let fix_for = |fstype: &str, source: &str| {
        let m = MountState::Found(mount((253, 1), "/var", "rw", fstype, source));
        judge(&rules(), &facts(stat(10), m)).fix.expect("a fix")
    };
    assert!(fix_for("xfs", "/dev/mapper/rl-var").contains("lvextend"));
    assert!(fix_for("ext3", "/dev/mapper/rl-var").contains("lvextend"));
    // A FUSE mount can name any source, a type lvextend cannot grow gets no advice, and an encrypted
    // container is not a logical volume.
    for (fstype, source) in [
        ("fuse.sshfs", "/dev/mapper/x"),
        ("nfs4", "/dev/mapper/x"),
        ("btrfs", "/dev/mapper/x"),
        ("ext4", "/dev/mapper/luks-0a1b2c3d"),
        ("ext4", "/dev/sda3"),
        ("ext4", "/dev/mapper/"),
    ] {
        let fix = fix_for(fstype, source);
        assert!(!fix.contains("lvextend"), "{fstype} {source}: {fix}");
    }
}

#[test]
fn a_noexec_mount_leads_with_moving_the_install_and_remounts_second() {
    let mut r = rules();
    r.forbid = vec![MountOption::Noexec];
    let mut s = stat(100);
    s.no_exec = Some(true);
    let fix = judge(&r, &facts(s, var_mount())).fix.expect("a fix");
    let move_at = fix.find("Move the install path").expect("move first");
    let tmpdir_at = fix.find("TMPDIR").expect("TMPDIR");
    let remount_at = fix.find("remount,exec /var").expect("remount");
    assert!(move_at < tmpdir_at && tmpdir_at < remount_at, "{fix}");
    assert!(fix.contains("security team"), "{fix}");
}

#[test]
fn the_nearest_btrfs_mount_answers_for_a_device_mountinfo_does_not_show() {
    let mounts = [
        mount((0, 26), "/", "rw", "btrfs", "/dev/vda2"),
        mount((0, 5), "/proc", "rw", "proc", "proc"),
        mount((253, 1), "/boot", "rw", "ext4", "/dev/vda1"),
    ];
    // A subvolume has an anonymous device of its own: no line has it.
    assert_eq!(
        found_btrfs(mountinfo::find(&mounts, (0, 45), &["opt", "acme"])),
        "/"
    );
    // The longest whole-component prefix, not just the root.
    let nested = [
        mount((0, 26), "/", "rw", "btrfs", "/dev/vda2"),
        mount((0, 26), "/home", "rw", "btrfs", "/dev/vda2"),
    ];
    assert_eq!(
        found_btrfs(mountinfo::find(&nested, (0, 45), &["home", "u"])),
        "/home"
    );
    // `/home` is not above `/homework`.
    assert_eq!(
        found_btrfs(mountinfo::find(&nested, (0, 45), &["homework"])),
        "/"
    );
}

#[test]
fn a_missing_device_is_not_guessed_when_the_nearest_mount_is_not_btrfs() {
    let mounts = [
        mount((8, 1), "/", "rw", "ext4", "/dev/sda1"),
        mount((0, 26), "/data", "rw", "btrfs", "/dev/vdb1"),
    ];
    // The nearest mount above the path is ext4, so the missing device stays unknown.
    assert_eq!(
        mountinfo::find(&mounts, (0, 45), &["srv", "acme"]),
        Lookup::NoDevice
    );
    // A btrfs mount that is not above the path does not count either.
    assert_eq!(
        mountinfo::find(&mounts, (0, 45), &["srv"]),
        Lookup::NoDevice
    );
    // A deeper non-btrfs mount hides a shallower btrfs one.
    let mounts = [
        mount((0, 26), "/", "rw", "btrfs", "/dev/vda2"),
        mount((8, 3), "/srv", "rw", "ext4", "/dev/sdc1"),
    ];
    assert_eq!(
        mountinfo::find(&mounts, (0, 45), &["srv", "x"]),
        Lookup::NoDevice
    );
    // No mounts at all.
    assert_eq!(mountinfo::find(&[], (0, 45), &["srv"]), Lookup::NoDevice);
}

#[test]
fn a_device_that_mountinfo_shows_still_wins_over_the_btrfs_fallback() {
    let mounts = [
        mount((0, 26), "/", "rw", "btrfs", "/dev/vda2"),
        mount((8, 1), "/data", "rw", "xfs", "/dev/sdb1"),
    ];
    assert_eq!(
        found(mountinfo::find(&mounts, (8, 1), &["data", "x"])),
        "/data"
    );
}

#[test]
fn the_parse_counts_the_lines_it_cut() {
    let line = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
    let exact = line.repeat(mountinfo::MAX_LINES);
    let parsed = mountinfo::parse(&exact);
    assert_eq!(parsed.mounts.len(), mountinfo::MAX_LINES);
    assert!(!parsed.cut);
    let over = format!("{exact}{line}");
    let parsed = mountinfo::parse(&over);
    assert_eq!(parsed.mounts.len(), mountinfo::MAX_LINES);
    assert!(parsed.cut);
    // Blank lines after the limit are nothing to report.
    assert!(!mountinfo::parse(&format!("{exact}\n\n")).cut);
}

#[test]
fn reading_notes_reach_the_finding() {
    let mut f = facts(stat(100), var_mount());
    f.reading = vec!["2 line(s) were left out.".to_owned()];
    let finding = judge(&rules(), &f);
    assert_eq!(finding.notes, ["2 line(s) were left out."]);
}

#[test]
fn the_display_of_a_hostile_path_or_mount_point_cannot_break_a_code_span() {
    let hostile = mount((253, 1), "/mnt/x`id`\nA", "rw", "ext4", "/dev/sda3");
    let mut f = facts(stat(5), MountState::Found(hostile));
    f.requested = "/srv/a`b\u{202e}c";
    f.measured = "/srv".to_owned();
    let finding = judge(&rules(), &f);
    let text = format!("{} {}", finding.message, finding.fix.expect("a fix"));
    // Text with a backtick is shown bare, escaped, so no backtick of the text can close a span.
    assert!(text.contains("/srv/a`b\\u{202e}c has"), "{text}");
    assert!(text.contains("/mnt/x`id`\\x0aA (ext4)"), "{text}");
    assert!(!text.contains('\n') && !text.contains('\u{202e}'), "{text}");
    // A path with no backtick keeps the code span but escapes controls.
    f.requested = "/srv/a\u{1b}[2Jb";
    let finding = judge(&rules(), &f);
    assert!(
        finding.message.contains("`/srv/a\\x1b[2Jb` has"),
        "{}",
        finding.message
    );
}
