//! Unit tests of the parsers and the judgement of `host.container_runtime`. They take text, so they run
//! the same on every OS. The fixture cases are in `tests.rs`.

use proptest::prelude::*;
use rdy_engine::check::{Level, Need};
use rdy_spec::check::{CgroupDriver, ContainerRuntime};

use super::containerd::{self, TABLE_V2, TABLE_V3_RUNTIME};
use super::engine::{self, Product};
use super::files;
use super::judge::{self, Api, Seen, same_storage};
use super::{ContainerRuntimeCheck, Kubelet, SOCK_DOCKER, api_failure, clip};
use rdy_engine::probe::ProbeError;

// --- Engine API ---

#[test]
fn docker_version_reads_the_engine_component() {
    let text = r#"{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"containerd","Version":"1.6.26"},{"Name":"Engine","Version":"24.0.7"}],"Version":"24.0.7-ce","ApiVersion":"1.43"}"#;
    let reply = engine::parse_version(text).expect("a reply");
    assert_eq!(reply.product, Product::Docker);
    assert_eq!(reply.version.as_deref(), Some("24.0.7"));
}

#[test]
fn podman_is_told_by_its_component_name() {
    let text = r#"{"Components":[{"Name":"Podman Engine","Version":"4.9.4"}],"Version":"4.9.4"}"#;
    assert_eq!(
        engine::parse_version(text).expect("a reply").product,
        Product::Podman
    );
}

#[test]
fn version_without_components_falls_back_to_the_top_level_field() {
    let reply = engine::parse_version(r#"{"Version":"27.1.1"}"#).expect("a reply");
    assert_eq!(reply.version.as_deref(), Some("27.1.1"));
}

#[test]
fn what_is_not_a_json_object_is_not_a_reply() {
    for text in ["", "[]", "\"x\"", "null", "{", "<html>502</html>", "OK"] {
        assert_eq!(engine::parse_version(text), None, "{text:?}");
        assert_eq!(engine::parse_info(text), None, "{text:?}");
    }
}

#[test]
fn info_reads_the_fields_the_check_needs_and_nothing_else() {
    let text = r#"{
        "Driver": "overlay2",
        "DriverStatus": [["Backing Filesystem","extfs"],["Supports d_type","true"]],
        "CgroupDriver": "systemd",
        "ServerVersion": "24.0.7",
        "SecurityOptions": ["name=seccomp,profile=builtin","name=rootless"],
        "HttpProxy": "http://proxy.acme.example:3128",
        "NoProxy": "",
        "Name": "host-01.acme.example"
    }"#;
    let info = engine::parse_info(text).expect("a reply");
    assert_eq!(info.storage_driver.as_deref(), Some("overlay2"));
    assert_eq!(info.cgroup_driver, Some(CgroupDriver::Systemd));
    assert_eq!(info.d_type, Some(true));
    assert_eq!(info.rootless, Some(true));
    assert_eq!(info.server_version.as_deref(), Some("24.0.7"));
    assert_eq!(
        info.http_proxy.as_deref(),
        Some("http://proxy.acme.example:3128")
    );
    assert_eq!(info.https_proxy, None);
    assert_eq!(info.no_proxy, None, "an empty string is no proxy");
}

#[test]
fn d_type_false_and_a_driver_that_does_not_report_it() {
    let off = r#"{"DriverStatus":[["Supports d_type","false"]]}"#;
    assert_eq!(
        engine::parse_info(off).expect("a reply").d_type,
        Some(false)
    );
    let none = r#"{"Driver":"vfs","DriverStatus":[]}"#;
    assert_eq!(engine::parse_info(none).expect("a reply").d_type, None);
    let odd = r#"{"DriverStatus":[["Supports d_type","maybe"],"x",[1,2],[]]}"#;
    assert_eq!(engine::parse_info(odd).expect("a reply").d_type, None);
}

#[test]
fn rootless_needs_the_option_list_to_be_there() {
    let without = engine::parse_info(r#"{"Driver":"overlay2"}"#).expect("a reply");
    assert_eq!(without.rootless, None);
    let list = engine::parse_info(r#"{"SecurityOptions":["name=seccomp,profile=builtin"]}"#)
        .expect("a reply");
    assert_eq!(list.rootless, Some(false));
}

#[test]
fn a_cgroup_driver_that_is_neither_word_is_unknown() {
    let info = engine::parse_info(r#"{"CgroupDriver":"none"}"#).expect("a reply");
    assert_eq!(info.cgroup_driver, None);
    assert_eq!(
        engine::driver_word(" SystemD "),
        Some(CgroupDriver::Systemd)
    );
}

// --- daemon.json, drop-ins, kubelet ---

#[test]
fn daemon_json_gives_the_last_cgroup_driver_and_the_storage_driver() {
    let text = r#"{
        "exec-opts": ["native.cgroupdriver=cgroupfs", "native.cgroupdriver=systemd", "other=1"],
        "storage-driver": "overlay2",
        "proxies": {"http-proxy": "http://p.acme.example:1", "no-proxy": "localhost"}
    }"#;
    let daemon = files::parse_daemon_json(text).expect("valid");
    assert_eq!(daemon.cgroup_driver, Some(CgroupDriver::Systemd));
    assert_eq!(daemon.storage_driver.as_deref(), Some("overlay2"));
    assert_eq!(
        daemon.proxy.http.as_deref(),
        Some("http://p.acme.example:1")
    );
    assert_eq!(daemon.proxy.no_proxy.as_deref(), Some("localhost"));
}

#[test]
fn an_empty_daemon_json_is_an_empty_object_and_a_broken_one_says_where() {
    assert_eq!(
        files::parse_daemon_json("  \n"),
        Ok(files::DaemonJson::default())
    );
    let error = files::parse_daemon_json("{\n\"a\": 1\n\"b\": 2\n}").expect_err("broken");
    assert!(
        error.contains("not valid JSON") && error.contains("line 3"),
        "{error}"
    );
    assert!(files::parse_daemon_json("[1]").is_err());
}

#[test]
fn a_systemd_drop_in_gives_the_proxy_variables_and_later_lines_win() {
    let text = "[Service]\n\
        # a comment\n\
        Environment=\"HTTP_PROXY=http://one.acme.example:1\" \"NO_PROXY=localhost,.cluster.local\"\n\
        Environment=HTTPS_PROXY=http://two.acme.example:2 FOO=bar\n\
        Environment='http_proxy=http://three.acme.example:3'\n\
        ExecStart=/bin/true\n";
    let proxy = files::parse_dropin(text);
    assert_eq!(proxy.http.as_deref(), Some("http://three.acme.example:3"));
    assert_eq!(proxy.https.as_deref(), Some("http://two.acme.example:2"));
    assert_eq!(proxy.no_proxy.as_deref(), Some("localhost,.cluster.local"));
    assert!(files::parse_dropin("[Service]\nEnvironment=\n").is_empty());
}

#[test]
fn the_kubelet_driver_is_a_top_level_key_only() {
    assert_eq!(
        files::kubelet_driver("kind: KubeletConfiguration\ncgroupDriver: systemd\n"),
        Some(CgroupDriver::Systemd)
    );
    assert_eq!(
        files::kubelet_driver("cgroupDriver: \"cgroupfs\"  # default\n"),
        Some(CgroupDriver::Cgroupfs)
    );
    // Indented keys belong to some other object.
    assert_eq!(
        files::kubelet_driver("nested:\n  cgroupDriver: systemd\n"),
        None
    );
    assert_eq!(files::kubelet_driver("cgroupDriver: weird\n"), None);
    assert_eq!(files::kubelet_driver(""), None);
}

#[test]
fn versions_are_read_from_the_ways_each_tool_prints_them() {
    for (text, want) in [
        (
            "containerd github.com/containerd/containerd v1.7.13 7c3aca7a\n",
            "1.7.13",
        ),
        ("containerd containerd.io 1.6.31 e377cd56\n", "1.6.31"),
        (
            "containerd github.com/containerd/containerd/v2 v2.0.0-rc.3 abc\n",
            "2.0.0",
        ),
        (
            "containerd github.com/containerd/containerd v1.7.13+unknown x\n",
            "1.7.13",
        ),
    ] {
        assert_eq!(
            files::containerd_version(text).as_deref(),
            Some(want),
            "{text}"
        );
    }
    assert_eq!(
        files::containerd_version("containerd: command not found"),
        None
    );
    assert_eq!(files::containerd_version(""), None);
    assert_eq!(
        files::crio_version("crio version 1.29.1\nVersion: 1.29.1\n").as_deref(),
        Some("1.29.1")
    );
    assert_eq!(files::crio_version("crio version\n"), None);
    assert_eq!(files::leading_number("24.0.7-ce"), Some("24.0.7"));
    assert_eq!(files::leading_number("v1.2."), Some("1.2"));
    assert_eq!(files::leading_number("abc"), None);
    assert_eq!(files::leading_number(".5"), None);
}

// --- containerd ---

const V2: &str = r#"
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
"#;

#[test]
fn a_version_2_file_is_read_from_the_grpc_table() {
    let config = containerd::parse(V2).expect("valid");
    assert_eq!(config.version, 2);
    assert_eq!(config.cgroup, Some(CgroupDriver::Systemd));
    assert_eq!(config.snapshotter.as_deref(), Some("overlayfs"));
    assert_eq!(config.misplaced, None);
    assert!(config.from_file);
}

#[test]
fn a_version_3_file_is_read_from_the_runtime_table_and_the_images_snapshotter() {
    let text = r"
version = 3
[plugins.'io.containerd.cri.v1.images']
  snapshotter = 'native'
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
  SystemdCgroup = true
";
    let config = containerd::parse(text).expect("valid");
    assert_eq!(config.version, 3);
    assert_eq!(config.cgroup, Some(CgroupDriver::Systemd));
    assert_eq!(config.snapshotter.as_deref(), Some("native"));
}

#[test]
fn a_value_under_the_other_versions_table_is_ignored_and_reported() {
    let v3_with_v2_table = V2.replace("version = 2", "version = 3");
    let config = containerd::parse(&v3_with_v2_table).expect("valid");
    assert_eq!(
        config.cgroup,
        Some(CgroupDriver::Cgroupfs),
        "version 3 does not read the v2 table"
    );
    assert_eq!(config.misplaced, Some(TABLE_V2));
    assert!(
        config
            .notes
            .iter()
            .any(|n| n.contains("version 3 file does not read"))
    );

    let v2_with_v3_table = r"
version = 2
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
  SystemdCgroup = true
";
    let config = containerd::parse(v2_with_v3_table).expect("valid");
    assert_eq!(config.cgroup, Some(CgroupDriver::Cgroupfs));
    assert_eq!(config.misplaced, Some(TABLE_V3_RUNTIME));
}

#[test]
fn a_file_with_no_version_reads_the_short_table_and_the_long_one() {
    let short = "[plugins.cri.containerd.runtimes.runc.options]\n  SystemdCgroup = true\n";
    let config = containerd::parse(short).expect("valid");
    assert_eq!(
        (config.version, config.cgroup),
        (1, Some(CgroupDriver::Systemd))
    );
    let long = V2.replace("version = 2\n", "");
    let config = containerd::parse(&long).expect("valid");
    assert_eq!(
        (config.version, config.cgroup),
        (1, Some(CgroupDriver::Systemd))
    );
    assert_eq!(config.misplaced, None);
}

#[test]
fn an_unset_value_is_the_default_off_unless_imports_or_another_runtime_hide_it() {
    let config = containerd::parse("version = 2\n").expect("valid");
    assert_eq!(config.cgroup, Some(CgroupDriver::Cgroupfs));
    assert_eq!(config.snapshotter.as_deref(), Some("overlayfs"));

    let imports = containerd::parse("version = 2\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n")
        .expect("valid");
    assert_eq!(imports.cgroup, None);
    assert_eq!(imports.snapshotter, None);

    let kata = r#"
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "kata"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
"#;
    let config = containerd::parse(kata).expect("valid");
    assert_eq!(config.cgroup, None);
    assert!(config.notes.iter().any(|n| n.contains("not runc")));

    let undefined = "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd]\n  default_runtime_name = \"gone\"\n";
    assert_eq!(containerd::parse(undefined).expect("valid").cgroup, None);
}

#[test]
fn the_default_runtime_is_the_one_whose_options_count() {
    let text = r#"
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "crun"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = false
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.crun]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.crun.options]
  SystemdCgroup = true
"#;
    let config = containerd::parse(text).expect("valid");
    assert_eq!(config.runtime_name, "crun");
    assert_eq!(config.cgroup, Some(CgroupDriver::Systemd));
}

#[test]
fn broken_toml_is_an_error_with_a_short_reason() {
    for text in ["version = ", "[plugins", "a = = 1"] {
        let error = containerd::parse(text).expect_err(text);
        assert!(error.starts_with("it is not valid TOML"), "{error}");
        assert!(!error.contains('\n'), "{error:?}");
    }
}

#[test]
fn table_names_and_the_built_in_default_follow_the_config_version() {
    assert_eq!(containerd::table_name(1), "cri");
    assert_eq!(containerd::table_name(2), TABLE_V2);
    assert_eq!(containerd::table_name(3), TABLE_V3_RUNTIME);
    assert_eq!(containerd::table_name(4), TABLE_V3_RUNTIME);
    assert_eq!(containerd::built_in(Some(2)).version, 3);
    assert_eq!(containerd::built_in(Some(1)).version, 2);
    assert_eq!(containerd::built_in(None).version, 2);
    let default = containerd::built_in(None);
    assert!(!default.from_file);
    assert_eq!(default.cgroup, Some(CgroupDriver::Cgroupfs));
}

// --- judgement ---

fn running(kind: ContainerRuntime, driver: Option<CgroupDriver>) -> Seen {
    let mut seen = Seen::new(kind, false, SOCK_DOCKER);
    seen.socket_present = true;
    seen.api = if matches!(kind, ContainerRuntime::Docker | ContainerRuntime::Podman) {
        Api::Read
    } else {
        Api::NotAsked
    };
    seen.version = Some("24.0.7".to_owned());
    seen.cgroup = driver.map(|d| (d, "docker info"));
    seen
}

fn kubelet(driver: Option<CgroupDriver>) -> Kubelet {
    Kubelet {
        present: driver.is_some(),
        driver,
        unreadable: None,
    }
}

#[test]
fn storage_names_compare_without_case_and_overlay_means_overlayfs() {
    assert!(same_storage("overlay2", "OVERLAY2"));
    assert!(same_storage("overlayfs", "overlay2"));
    assert!(same_storage("overlay2", "overlayfs"));
    assert!(!same_storage("overlay", "overlay2"));
    assert!(!same_storage("vfs", "overlay2"));
}

#[test]
fn a_runtime_that_is_not_in_the_spec_list_is_not_judged() {
    let check = ContainerRuntimeCheck {
        runtimes: Some(vec![ContainerRuntime::Containerd]),
        ..ContainerRuntimeCheck::default()
    };
    // Docker is present and wrong, but the spec does not allow it, so it is neither judged nor listed
    // as a way to pass.
    let seen = [running(
        ContainerRuntime::Docker,
        Some(CgroupDriver::Cgroupfs),
    )];
    let finding = judge::judge(&check, &seen, &kubelet(Some(CgroupDriver::Systemd)), true);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("The spec needs containerd, but only docker was found."),
        "{}",
        finding.message
    );
}

#[test]
fn with_no_spec_keys_a_present_runtime_passes_and_an_absent_one_fails() {
    let check = ContainerRuntimeCheck::default();
    let ok = judge::judge(
        &check,
        &[running(ContainerRuntime::Docker, None)],
        &Kubelet::default(),
        true,
    );
    assert_eq!(ok.level, Level::Pass);
    assert!(ok.fix.is_none());
    let none = judge::judge(
        &check,
        &[Seen::new(ContainerRuntime::Docker, false, SOCK_DOCKER)],
        &Kubelet::default(),
        true,
    );
    assert_eq!(none.level, Level::Fail);
}

#[test]
fn an_unknown_driver_against_the_kubelet_warns_except_for_a_runtime_rdy_cannot_read() {
    let check = ContainerRuntimeCheck::default();
    let kube = kubelet(Some(CgroupDriver::Systemd));
    let docker = judge::judge(
        &check,
        &[running(ContainerRuntime::Docker, None)],
        &kube,
        true,
    );
    assert_eq!(docker.level, Level::Warn);
    let mut crio = running(ContainerRuntime::Crio, None);
    crio.blind = true;
    let finding = judge::judge(&check, &[crio], &kube, true);
    assert_eq!(finding.level, Level::Pass);
}

#[test]
fn both_the_spec_and_the_kubelet_can_object_and_one_fix_covers_both() {
    let check = ContainerRuntimeCheck {
        cgroup_driver: Some(CgroupDriver::Cgroupfs),
        ..ContainerRuntimeCheck::default()
    };
    // Docker on systemd, kubelet on systemd, spec wants cgroupfs: docker and the kubelet both change.
    let seen = [running(
        ContainerRuntime::Docker,
        Some(CgroupDriver::Systemd),
    )];
    let finding = judge::judge(&check, &seen, &kubelet(Some(CgroupDriver::Systemd)), true);
    assert_eq!(finding.level, Level::Fail);
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("native.cgroupdriver=cgroupfs"), "{fix}");
    assert!(fix.contains("cgroupDriver: cgroupfs"), "{fix}");
}

#[test]
fn a_runtime_on_systemd_with_a_kubelet_on_cgroupfs_changes_the_kubelet() {
    let seen = [running(
        ContainerRuntime::Containerd,
        Some(CgroupDriver::Systemd),
    )];
    let finding = judge::judge(
        &ContainerRuntimeCheck::default(),
        &seen,
        &kubelet(Some(CgroupDriver::Cgroupfs)),
        true,
    );
    assert_eq!(finding.level, Level::Fail);
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("cgroupDriver: systemd") && fix.contains("systemctl restart kubelet"),
        "{fix}"
    );
    assert!(!fix.contains("SystemdCgroup"), "{fix}");
}

#[test]
fn min_version_compares_numbers_part_by_part() {
    let check = |min: &str| ContainerRuntimeCheck {
        runtimes: Some(vec![ContainerRuntime::Docker]),
        min_version: Some(rdy_spec::scalar::Version::parse(min).expect("a version")),
        ..ContainerRuntimeCheck::default()
    };
    let mut seen = running(ContainerRuntime::Docker, None);
    seen.version = Some("24.0.7".to_owned());
    for (min, level) in [
        ("24.0.7", Level::Pass),
        ("24.0.8", Level::Fail),
        ("24.0", Level::Pass),
        ("9", Level::Pass),
        ("100", Level::Fail),
    ] {
        let finding = judge::judge(
            &check(min),
            std::slice::from_ref(&seen),
            &Kubelet::default(),
            true,
        );
        assert_eq!(finding.level, level, "{min}");
    }
    seen.version = None;
    let finding = judge::judge(&check("24"), &[seen], &Kubelet::default(), true);
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("not verified"));
}

#[test]
fn a_denied_socket_adds_a_partial_only_without_root() {
    let mut seen = running(ContainerRuntime::Docker, None);
    seen.api = Api::Denied;
    let check = ContainerRuntimeCheck::default();
    let without = judge::judge(
        &check,
        std::slice::from_ref(&seen),
        &Kubelet::default(),
        false,
    );
    assert_eq!(without.level, Level::Warn);
    assert_eq!(without.partial.expect("partial").missing, [Need::Root]);
    let with = judge::judge(&check, &[seen], &Kubelet::default(), true);
    assert_eq!(with.level, Level::Warn);
    assert!(with.partial.is_none());
}

#[test]
fn socket_failures_map_to_the_states_the_check_reports() {
    let state = |error| api_failure(error, false).expect("a state");
    assert_eq!(state(ProbeError::PermissionDenied), Api::Denied);
    assert_eq!(state(ProbeError::NotFound), Api::NotListening);
    // A refused connection is its own error kind, not text to be searched.
    assert_eq!(state(ProbeError::ConnectionRefused), Api::NotListening);
    assert!(matches!(
        state(ProbeError::Io(
            "Connection refused (os error 111)".to_owned()
        )),
        Api::Odd(_)
    ));
    assert_eq!(
        api_failure(ProbeError::NotFound, true).expect("a state"),
        Api::Missing,
        "a rootless socket is not stat-ed first, so not found means absent"
    );
    assert!(matches!(
        state(ProbeError::Io("Broken pipe".to_owned())),
        Api::Odd(_)
    ));
    // The request limit of the check ended the call: the arm is reached, and it names the limit.
    assert_eq!(state(ProbeError::Timeout), Api::Silent);
    // The facade's refusal of a rootless socket of another user is a state; for any other socket it is a
    // fault of the check.
    let refused = || ProbeError::Denied {
        rule: "unix socket not declared by the check",
        what: "x".to_owned(),
    };
    assert!(matches!(api_failure(refused(), true), Ok(Api::Odd(_))));
    assert!(api_failure(refused(), false).is_err());
}

#[test]
fn evidence_text_is_cut_and_has_no_control_characters() {
    assert_eq!(clip("a\u{1b}[2Jb\nc"), "a [2Jb c");
    assert_eq!(clip(&"x".repeat(500)).chars().count(), 200);
}

#[test]
fn deeply_nested_input_is_an_error_not_a_crash() {
    let arrays = format!("a = {}", "[".repeat(20_000));
    assert!(containerd::parse(&arrays).is_err());
    let dotted = format!("{} = 1\n", vec!["a"; 5_000].join("."));
    let _ = containerd::parse(&dotted);
    let json = format!("{}{}", "[".repeat(20_000), "]".repeat(20_000));
    assert!(files::parse_daemon_json(&json).is_err());
    assert_eq!(engine::parse_info(&json), None);
    assert_eq!(engine::parse_version(&json), None);
}

proptest! {
    // The parsers read text from the machine. None of them may panic on any input.
    #[test]
    fn parsers_never_panic(text in "\\PC{0,400}") {
        let _ = engine::parse_version(&text);
        let _ = engine::parse_info(&text);
        let _ = files::parse_daemon_json(&text);
        let _ = files::parse_dropin(&text);
        let _ = files::kubelet_driver(&text);
        let _ = files::containerd_version(&text);
        let _ = files::crio_version(&text);
        let _ = files::leading_number(&text);
        let _ = containerd::parse(&text);
    }

    #[test]
    fn bytes_of_any_shape_do_not_panic_the_parsers(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = containerd::parse(&text);
        let _ = files::parse_daemon_json(&text);
    }
}
