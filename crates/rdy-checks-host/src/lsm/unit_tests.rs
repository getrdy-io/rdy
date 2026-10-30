//! Unit tests of the `host.lsm` parsers. The text is invented.

use rdy_spec::check::SelinuxMode;

use super::apparmor::{parse_enabled, parse_profiles};
use super::audit::{scan, stamp};
use super::selinux::{
    Configured, Mount, mount_words, parse_config, parse_enforce, root_is_overlay, selinux_mount,
};
use super::{age, join_or, plural};

fn avc(at: u64, source: &str, target: &str, class: &str, comm: &str) -> String {
    format!(
        "type=AVC msg=audit({at}.100:7): avc:  denied  {{ read }} for  pid=9 comm=\"{comm}\" scontext=system_u:system_r:{source}:s0:c1,c2 tcontext=system_u:object_r:{target}:s0 tclass={class} permissive=0\n"
    )
}

fn watch(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[test]
fn enforce_is_one_or_zero() {
    assert_eq!(parse_enforce("1\n"), Some(SelinuxMode::Enforcing));
    assert_eq!(parse_enforce("0"), Some(SelinuxMode::Permissive));
    for bad in ["", "2", "enforcing", "10", "\n"] {
        assert_eq!(parse_enforce(bad), None, "{bad:?}");
    }
}

#[test]
fn config_takes_the_first_known_selinux_line_as_libselinux_does() {
    let text =
        "# SELINUX=disabled\nSELINUXTYPE=targeted\nSELINUX=permissive\nSELINUX=Enforcing # now\n";
    assert_eq!(
        parse_config(text),
        Configured::Mode(SelinuxMode::Permissive)
    );
    // An unknown value is skipped, a leading space hides the line, and case does not matter.
    assert_eq!(
        parse_config("SELINUX=strict\n  SELINUX=disabled\nSELINUX=ENFORCING\n"),
        Configured::Mode(SelinuxMode::Enforcing)
    );
    assert_eq!(parse_config(" SELINUX=enforcing\n"), Configured::Unset);
    // White space after the `=` is skipped, and the value is matched by its start.
    assert_eq!(
        parse_config("SELINUX= disabled\n"),
        Configured::Mode(SelinuxMode::Disabled)
    );
    assert_eq!(
        parse_config("SELINUX=enforcing # comment\n"),
        Configured::Mode(SelinuxMode::Enforcing)
    );
    // The first unknown value is the one reported when no line is known.
    assert_eq!(
        parse_config("SELINUX=strict\nSELINUX=other\n"),
        Configured::Other("strict".to_owned())
    );
    assert_eq!(parse_config("SELINUXTYPE=mls\n"), Configured::Unset);
    assert_eq!(parse_config(""), Configured::Unset);
    assert_eq!(
        parse_config("SELINUX=strict\n"),
        Configured::Other("strict".to_owned())
    );
    // A long value is cut.
    let Configured::Other(cut) = parse_config(&format!("SELINUX={}\n", "a".repeat(500))) else {
        panic!("not other");
    };
    assert_eq!(cut.len(), 32);
}

#[test]
fn mountinfo_finds_the_topmost_mount_on_the_selinux_directory() {
    let plain = "24 1 8:2 / / rw - ext4 /dev/sda2 rw\n";
    assert_eq!(selinux_mount(plain), None);

    let real = "31 27 0:27 / /sys/fs/selinux rw,nosuid shared:12 - selinuxfs selinuxfs rw\n";
    assert_eq!(selinux_mount(real), Some(Mount::Selinuxfs));

    // A runtime puts an empty file system over it, later in the file.
    let both = format!("{real}514 513 0:45 / /sys/fs/selinux ro - tmpfs tmpfs rw\n");
    assert_eq!(
        selinux_mount(&both),
        Some(Mount::Masked("tmpfs".to_owned()))
    );

    // Octal escapes in the mount point are undone, and other paths are not matched.
    let escaped = "1 0 0:1 / /sys/fs/selinux\\040x rw - tmpfs t rw\n";
    assert_eq!(selinux_mount(escaped), None);
    let near = "1 0 0:1 / /sys/fs/selinux2 rw - tmpfs t rw\n";
    assert_eq!(selinux_mount(near), None);
    let escaped_dir = "1 0 0:1 / /sys/fs/\\163elinux rw - tmpfs t rw\n";
    assert_eq!(
        selinux_mount(escaped_dir),
        Some(Mount::Masked("tmpfs".to_owned()))
    );
}

#[test]
fn an_overlay_root_is_the_last_mount_on_slash() {
    let overlay = "601 391 0:55 / / rw - overlay overlay rw,lowerdir=/a\n";
    assert!(root_is_overlay(overlay));
    assert!(!root_is_overlay("24 1 8:2 / / rw - ext4 /dev/sda2 rw\n"));
    // An overlay mounted elsewhere is not the root.
    assert!(!root_is_overlay(
        "24 1 8:2 / / rw - ext4 /dev/sda2 rw\n25 24 0:5 / /var/lib/x rw - overlay overlay rw\n"
    ));
    // The topmost mount on `/` wins.
    assert!(!root_is_overlay(&format!(
        "{overlay}602 601 8:2 / / rw - ext4 /dev/sda2 rw\n"
    )));
    for text in ["", "garbage\n", "1 0 0:1 / / rw\n", "1 0 0:1 / / rw - \n"] {
        assert!(!root_is_overlay(text), "{text:?}");
    }
}

#[test]
fn only_plain_mount_types_are_repeated() {
    assert_eq!(mount_words("tmpfs"), "a tmpfs mount");
    assert_eq!(mount_words("fuse.sshfs-2_x"), "a fuse.sshfs-2_x mount");
    for odd in [
        "",
        "Tmpfs",
        "fuse.\u{1b}[2J",
        "a\u{202e}b",
        "evil fs",
        "x/y",
    ] {
        assert_eq!(mount_words(odd), "another file system", "{odd:?}");
    }
}

#[test]
fn mountinfo_lines_that_do_not_parse_are_skipped() {
    for text in [
        "",
        "garbage\n",
        "1 0 0:1 / /sys/fs/selinux rw\n",
        "1 0 0:1 / /sys/fs/selinux rw - \n",
        "- \n",
        "\u{0}\u{0}\n",
    ] {
        assert_eq!(selinux_mount(text), None, "{text:?}");
    }
    // A very long file system type is cut.
    let long = format!("1 0 0:1 / /sys/fs/selinux rw - {} t rw\n", "f".repeat(300));
    let Some(Mount::Masked(fstype)) = selinux_mount(&long) else {
        panic!("not masked");
    };
    assert_eq!(fstype.len(), 32);
}

#[test]
fn stamps_come_from_the_audit_header() {
    assert_eq!(
        stamp("type=AVC msg=audit(1729990001.210:4102): x"),
        Some(1_729_990_001)
    );
    assert_eq!(stamp("node=h type=AVC msg=audit(5.1:2): x"), Some(5));
    for bad in [
        "",
        "no stamp",
        "msg=audit(): x",
        "msg=audit(abc.1:2)",
        "msg=audit(-5.1:2)",
        "msg=audit(1234567890123.1:2)",
    ] {
        assert_eq!(stamp(bad), None, "{bad:?}");
    }
}

#[test]
fn only_denials_inside_the_window_count() {
    let text = [
        avc(100, "acme_t", "var_lib_t", "file", "agent"),
        avc(200, "acme_t", "var_lib_t", "file", "agent"),
        avc(300, "init_t", "etc_t", "dir", "systemd"),
        "type=SYSCALL msg=audit(300.000:8): comm=\"agent\"\n".to_owned(),
        "type=AVC msg=audit(310.000:9): avc:  granted  { read } for  pid=9\n".to_owned(),
    ]
    .concat();
    let out = scan(&text, 200, &[]);
    assert_eq!(out.total, 2);
    assert_eq!(out.oldest, Some(100));
    assert_eq!(out.permissive, 0);
    let names: Vec<(&str, usize)> = out
        .groups
        .iter()
        .map(|g| (g.source.as_str(), g.count))
        .collect();
    assert_eq!(names, [("acme_t", 1), ("init_t", 1)]);
    // A stamp equal to the cutoff counts.
    assert_eq!(scan(&text, 300, &[]).total, 1);
    assert_eq!(scan(&text, 301, &[]).total, 0);
}

#[test]
fn a_watch_entry_matches_a_type_a_context_or_a_program() {
    let text = avc(500, "acme_t", "var_lib_t", "file", "acme-agent");
    for (entry, hit) in [
        ("acme_t", true),
        ("var_lib_t", true),
        ("system_u:system_r:acme_t:s0:c1,c2", true),
        ("system_u:object_r:var_lib_t:s0", true),
        ("acme-agent", true),
        ("acme", false),
        ("ACME_T", false),
        ("file", false),
        ("container_t", false),
    ] {
        let out = scan(&text, 0, &watch(&[entry]));
        assert_eq!(out.watched_total, usize::from(hit), "{entry}");
        assert_eq!(
            out.watched.get(entry).copied().unwrap_or(0),
            usize::from(hit),
            "{entry}"
        );
    }
    // A denial that matches two entries is one watched denial.
    let out = scan(&text, 0, &watch(&["acme_t", "acme-agent"]));
    assert_eq!((out.total, out.watched_total), (1, 1));
    assert_eq!(out.watched.len(), 2);
}

#[test]
fn permissive_denials_are_counted_apart() {
    let text = format!(
        "{}{}",
        avc(10, "a_t", "b_t", "file", "x").replace("permissive=0", "permissive=1"),
        avc(11, "a_t", "b_t", "file", "x")
    );
    let out = scan(&text, 0, &[]);
    assert_eq!((out.total, out.permissive), (2, 1));
}

#[test]
fn record_type_1400_and_a_node_prefix_are_denials_too() {
    let line = avc(10, "a_t", "b_t", "file", "x");
    let numeric = line.replace("type=AVC", "type=1400");
    assert_eq!(scan(&numeric, 0, &[]).total, 1);
    let node = format!("node=host1 {line}");
    assert_eq!(scan(&node, 0, &[]).total, 1);
    // Not a denial: another record type that mentions the words.
    let other = line.replace("type=AVC", "type=USER_AVC");
    assert_eq!(scan(&other, 0, &[]).total, 0);
    let subj = line.replace("type=AVC", "subj_type=AVC");
    assert_eq!(scan(&subj, 0, &[]).total, 0);
}

#[test]
fn a_field_that_fails_the_character_test_never_reaches_the_groups() {
    let hostile = "type=AVC msg=audit(10.1:2): avc:  denied  { read } for  comm=\"a b\" scontext=system_u:system_r:evil<script>:s0 tcontext=system_u:object_r:ok_t:s0 tclass=fi\u{1b}le permissive=0\n";
    let out = scan(hostile, 0, &watch(&["a b", "evil<script>"]));
    assert_eq!(out.total, 1);
    assert_eq!(out.groups.len(), 1);
    let group = &out.groups[0];
    assert_eq!(
        (
            group.source.as_str(),
            group.target.as_str(),
            group.class.as_str()
        ),
        ("unknown", "ok_t", "unknown")
    );
    // The hostile program name and context were dropped before the watch match.
    assert_eq!(out.watched_total, 0);

    // A hex-encoded program name (the audit system's form for odd names) is not quoted, so it is skipped.
    let hex = "type=AVC msg=audit(10.1:2): avc:  denied  { read } comm=6120622062 scontext=a:b:c_t:s0 tcontext=a:b:d_t:s0 tclass=file\n";
    assert_eq!(scan(hex, 0, &watch(&["6120622062"])).watched_total, 0);
}

#[test]
fn many_distinct_types_cannot_grow_the_groups_past_the_cap() {
    let text: String = (0..200)
        .map(|i| avc(10, &format!("t{i}_t"), "x_t", "file", "w"))
        .collect();
    let out = scan(&text, 0, &[]);
    assert_eq!(out.total, 200);
    assert_eq!(out.groups.len(), 64);
}

#[test]
fn a_denial_with_no_fields_still_counts() {
    let line = "type=AVC msg=audit(10.1:2): avc:  denied  { read }\n";
    let out = scan(line, 0, &[]);
    assert_eq!(out.total, 1);
    assert_eq!(out.groups[0].source, "unknown");
}

#[test]
fn groups_are_most_frequent_first() {
    let text = format!(
        "{}{}{}",
        avc(10, "a_t", "x_t", "file", "w"),
        avc(10, "b_t", "x_t", "file", "w"),
        avc(10, "b_t", "x_t", "file", "w")
    );
    let out = scan(&text, 0, &[]);
    let order: Vec<&str> = out.groups.iter().map(|g| g.source.as_str()).collect();
    assert_eq!(order, ["b_t", "a_t"]);
}

#[test]
fn apparmor_enabled_is_y_or_n() {
    assert_eq!(parse_enabled("Y\n"), Some(true));
    assert_eq!(parse_enabled("N"), Some(false));
    for bad in ["", "yes", "1", "YN"] {
        assert_eq!(parse_enabled(bad), None, "{bad:?}");
    }
}

#[test]
fn profile_lines_give_names_and_modes() {
    let text = "docker-default (enforce)\n/usr/sbin/chronyd (enforce)\nmy profile (complain)\nbroken line\n(enforce)\nx (unconfined)\n";
    let out = parse_profiles(text);
    assert_eq!(out.enforce, 2);
    assert_eq!(out.complain, 1);
    assert!(out.names.contains("my profile"));
    assert!(out.names.contains("x"));
    assert!(!out.names.contains("broken line"));
    assert_eq!(out.names.len(), 4);
    assert!(!out.cut);
}

#[test]
fn a_profile_list_past_the_cap_is_cut() {
    let text: String = (0..5000).map(|i| format!("p{i} (enforce)\n")).collect();
    let out = parse_profiles(&text);
    assert!(out.cut);
    assert_eq!(out.names.len(), 4096);
}

#[test]
fn small_text_helpers() {
    assert_eq!(age(59), "0m");
    assert_eq!(age(3600), "1h 0m");
    assert_eq!(age(3 * 3600 + 20 * 60), "3h 20m");
    assert_eq!(age(2 * 86_400 + 4 * 3600), "2d 4h");
    assert_eq!(plural(1, "action", "actions"), "1 action");
    assert_eq!(plural(2, "action", "actions"), "2 actions");
    assert_eq!(join_or([]), "no mode");
    assert_eq!(join_or(["a"]), "a");
    assert_eq!(join_or(["a", "b", "c"]), "a, b or c");
}
