//! Tests of the provisioner table: the shipped file entry by entry, the lookup rules, and one refusal per
//! rule of the parser.

use rdy_spec::check::AccessMode::{ReadOnlyMany, ReadWriteMany, ReadWriteOnce};

use super::*;

fn shipped() -> &'static Catalog {
    Catalog::shipped().expect("the shipped table parses")
}

/// What the table must say about one shipped driver, written out so a change to the file is a change here.
struct Row {
    name: &'static str,
    suffix: bool,
    csi: bool,
    modes: &'static [AccessMode],
    conditional: &'static [AccessMode],
    condition: Option<&'static str>,
    topology: Topology,
}

const ROWS: &[Row] = &[
    Row {
        name: "ebs.csi.aws.com",
        suffix: false,
        csi: true,
        modes: &[ReadWriteOnce],
        conditional: &[ReadWriteMany],
        condition: Some("raw block volumes on a multi-attach volume type"),
        topology: Topology::Zone,
    },
    Row {
        name: "ebs.csi.eks.amazonaws.com",
        suffix: false,
        csi: true,
        modes: &[ReadWriteOnce],
        conditional: &[],
        condition: None,
        topology: Topology::Zone,
    },
    Row {
        name: "pd.csi.storage.gke.io",
        suffix: false,
        csi: true,
        modes: &[ReadWriteOnce, ReadOnlyMany],
        conditional: &[],
        condition: None,
        topology: Topology::Zone,
    },
    Row {
        name: "filestore.csi.storage.gke.io",
        suffix: false,
        csi: true,
        modes: &[ReadWriteMany, ReadWriteOnce, ReadOnlyMany],
        conditional: &[],
        condition: None,
        topology: Topology::None,
    },
    Row {
        name: "disk.csi.azure.com",
        suffix: false,
        csi: true,
        modes: &[ReadWriteOnce],
        conditional: &[ReadWriteMany],
        condition: Some("raw block volumes on a shared disk"),
        topology: Topology::Zone,
    },
    Row {
        name: "file.csi.azure.com",
        suffix: false,
        csi: true,
        modes: &[ReadWriteMany, ReadWriteOnce, ReadOnlyMany],
        conditional: &[],
        condition: None,
        topology: Topology::None,
    },
    Row {
        name: "efs.csi.aws.com",
        suffix: false,
        csi: true,
        modes: &[ReadWriteMany, ReadWriteOnce, ReadOnlyMany],
        conditional: &[],
        condition: None,
        topology: Topology::None,
    },
    Row {
        name: "nfs.csi.k8s.io",
        suffix: false,
        csi: true,
        modes: &[ReadWriteMany, ReadWriteOnce, ReadOnlyMany],
        conditional: &[],
        condition: None,
        topology: Topology::None,
    },
    Row {
        name: "driver.longhorn.io",
        suffix: false,
        csi: true,
        modes: &[ReadWriteOnce, ReadWriteMany],
        conditional: &[],
        condition: None,
        topology: Topology::None,
    },
    Row {
        name: "cephfs.csi.ceph.com",
        suffix: true,
        csi: true,
        modes: &[ReadWriteMany, ReadWriteOnce, ReadOnlyMany],
        conditional: &[],
        condition: None,
        topology: Topology::None,
    },
    Row {
        name: "rbd.csi.ceph.com",
        suffix: true,
        csi: true,
        modes: &[ReadWriteOnce, ReadOnlyMany],
        conditional: &[ReadWriteMany],
        condition: Some("raw block volumes"),
        topology: Topology::None,
    },
    Row {
        name: "rancher.io/local-path",
        suffix: false,
        csi: false,
        modes: &[ReadWriteOnce],
        conditional: &[],
        condition: None,
        topology: Topology::Node,
    },
];

#[test]
fn the_shipped_table_parses() {
    let catalog = Catalog::shipped();
    assert!(catalog.is_ok(), "{catalog:?}");
}

/// One check per entry of the shipped file (03 Appendix B: one unit test per entry). The file and the
/// table above must list the same drivers in the same order.
#[test]
fn every_shipped_driver_says_what_the_table_here_says() {
    let drivers = shipped().drivers();
    assert_eq!(drivers.len(), ROWS.len(), "a driver was added or removed");
    for (driver, row) in drivers.iter().zip(ROWS) {
        let name = row.name;
        assert_eq!(driver.name(), name);
        assert_eq!(driver.matching == Match::Suffix, row.suffix, "{name}");
        assert_eq!(driver.is_csi(), row.csi, "{name}");
        assert_eq!(driver.modes(), row.modes, "{name}");
        assert_eq!(driver.conditional_modes(), row.conditional, "{name}");
        assert_eq!(driver.condition(), row.condition, "{name}");
        assert_eq!(driver.topology(), row.topology, "{name}");
        assert!(driver.source.starts_with("https://"), "{name}");
        assert!(driver.checked_on.starts_with("20"), "{name}");
    }
}

#[test]
fn the_in_tree_map_has_the_six_names_of_the_catalog() {
    let pairs: Vec<(&str, &str)> = shipped().in_tree_pairs().collect();
    assert_eq!(
        pairs,
        [
            ("kubernetes.io/aws-ebs", "ebs.csi.aws.com"),
            ("kubernetes.io/gce-pd", "pd.csi.storage.gke.io"),
            ("kubernetes.io/azure-disk", "disk.csi.azure.com"),
            ("kubernetes.io/azure-file", "file.csi.azure.com"),
            ("kubernetes.io/cinder", "cinder.csi.openstack.org"),
            ("kubernetes.io/vsphere-volume", "csi.vsphere.vmware.com"),
        ]
    );
}

#[test]
fn an_in_tree_name_is_normalised_to_its_csi_driver() {
    let catalog = shipped();
    let ebs = catalog.normalise("kubernetes.io/aws-ebs");
    assert_eq!((ebs.name, ebs.migrated), ("ebs.csi.aws.com", true));
    let same = catalog.normalise("ebs.csi.aws.com");
    assert_eq!((same.name, same.migrated), ("ebs.csi.aws.com", false));
    let other = catalog.normalise("csi.acme.example");
    assert_eq!((other.name, other.migrated), ("csi.acme.example", false));
}

#[test]
fn a_suffix_entry_matches_the_name_or_a_dotted_prefix_of_it() {
    let catalog = shipped();
    let rbd = |name: &str| catalog.driver(name).map(Driver::name);
    assert_eq!(rbd("rbd.csi.ceph.com"), Some("rbd.csi.ceph.com"));
    assert_eq!(
        rbd("openshift-storage.rbd.csi.ceph.com"),
        Some("rbd.csi.ceph.com")
    );
    assert_eq!(rbd("rook-ceph.rbd.csi.ceph.com"), Some("rbd.csi.ceph.com"));
    assert_eq!(
        rbd("openshift-storage.cephfs.csi.ceph.com"),
        Some("cephfs.csi.ceph.com")
    );
    // A name that merely ends with the same letters is another driver.
    assert_eq!(rbd("xrbd.csi.ceph.com"), None);
    assert_eq!(rbd("acme-rbd.csi.ceph.com"), None);
    assert_eq!(rbd("rbd.csi.ceph.com.evil.example"), None);
}

#[test]
fn an_exact_entry_does_not_match_a_longer_name() {
    let catalog = shipped();
    assert!(catalog.driver("ebs.csi.aws.com").is_some());
    assert!(catalog.driver("x.ebs.csi.aws.com").is_none());
    assert!(catalog.driver("ebs.csi.aws.com.x").is_none());
    assert!(catalog.driver("").is_none());
}

#[test]
fn classify_sorts_a_provisioner_into_one_kind() {
    let catalog = shipped();
    let kind = |name: &'static str| catalog.classify(name).1;
    assert_eq!(kind(NO_PROVISIONER), Kind::NoProvisioner);
    assert!(matches!(kind("rancher.io/local-path"), Kind::NotCsi(_)));
    assert!(matches!(kind("ebs.csi.aws.com"), Kind::Csi(_)));
    // The in-tree name is looked up as its CSI driver.
    let (normalised, migrated) = catalog.classify("kubernetes.io/aws-ebs");
    assert_eq!(normalised.name, "ebs.csi.aws.com");
    assert!(matches!(migrated, Kind::Csi(driver) if driver.name() == "ebs.csi.aws.com"));
    // A migrated name with no entry of its own is still a CSI driver.
    assert_eq!(kind_of(catalog, "kubernetes.io/vsphere-volume"), "migrated");
    assert!(matches!(kind("csi.acme.example"), Kind::Unknown));
    assert!(matches!(
        kind("openshift-storage.rbd.csi.ceph.com"),
        Kind::Csi(_)
    ));
}

fn kind_of(catalog: &Catalog, name: &str) -> &'static str {
    match catalog.classify(name).1 {
        Kind::MigratedCsi => "migrated",
        Kind::Unknown => "unknown",
        _ => "other",
    }
}

// ---- the parser refuses what it should -------------------------------------------------------------------

const GOOD: &str = r#"
schema = 1

[[driver]]
name = "csi.acme.example"
match = "exact"
csi = true
modes = ["ReadWriteOnce"]
topology = "none"
source = "https://docs.acme.example/csi"
checked_on = "2026-10-30"
"#;

fn refused(text: &str) -> String {
    Catalog::parse(text)
        .expect_err("the table is refused")
        .to_string()
}

#[test]
fn a_minimal_table_parses() {
    let catalog = Catalog::parse(GOOD).expect("parses");
    assert_eq!(catalog.drivers().len(), 1);
}

#[test]
fn each_rule_of_the_parser_refuses_its_case() {
    let cases: &[(&str, &str, &str)] = &[
        ("schema = 1", "schema = 2", "schema 2 is not the 1"),
        (
            "schema = 1",
            "schema = 1\nextra = 1",
            "not in the expected form",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = []",
            "at least one access mode",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = [\"ReadWriteOnce\", \"ReadWriteOnce\"]",
            "listed twice",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = [\"ReadWriteOnce\"]\nconditional_modes = [\"ReadWriteOnce\"]\ncondition = \"x\"",
            "listed twice",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = [\"ReadWriteSome\"]",
            "not in the expected form",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = [\"ReadWriteOnce\"]\nconditional_modes = [\"ReadWriteMany\"]",
            "need a condition",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = [\"ReadWriteOnce\"]\ncondition = \"raw block\"",
            "condition needs conditional_modes",
        ),
        (
            "modes = [\"ReadWriteOnce\"]",
            "modes = [\"ReadWriteOnce\"]\nconditional_modes = [\"ReadWriteMany\"]\ncondition = \"a `b`\"",
            "condition must be",
        ),
        (
            "csi = true",
            "csi = false\nmodes_extra = 1",
            "not in the expected form",
        ),
        (
            "topology = \"none\"",
            "topology = \"region\"",
            "not in the expected form",
        ),
        (
            "match = \"exact\"",
            "match = \"prefix\"",
            "not in the expected form",
        ),
        (
            "name = \"csi.acme.example\"",
            "name = \"csi acme\"",
            "name must be 1 to 253",
        ),
        (
            "name = \"csi.acme.example\"",
            "name = \"\"",
            "name must be 1 to 253",
        ),
        (
            "https://docs.acme.example/csi",
            "http://docs.acme.example/csi",
            "source must be a plain https URL",
        ),
        (
            "https://docs.acme.example/csi",
            "https://user@docs.acme.example/csi",
            "source must be a plain https URL",
        ),
        (
            "https://docs.acme.example/csi",
            "https://docs.acme.example/csi?x=1",
            "source must be a plain https URL",
        ),
        ("2026-10-30", "2026-13-01", "checked_on must be a date"),
        ("2026-10-30", "2026-2-3", "checked_on must be a date"),
        ("2026-10-30", "30/10/2026", "checked_on must be a date"),
    ];
    for (from, to, expected) in cases {
        assert!(GOOD.contains(from), "{from} is not in the base table");
        let text = GOOD.replacen(from, to, 1);
        let message = refused(&text);
        assert!(
            message.contains(expected),
            "`{to}` gave `{message}`, wanted `{expected}`"
        );
    }
}

#[test]
fn a_name_twice_is_refused_even_as_exact_and_suffix() {
    let twice = format!("{GOOD}{}", GOOD.replace("schema = 1", ""));
    assert!(refused(&twice).contains("used twice"));
    let both = format!(
        "{GOOD}\n[[driver]]\nname = \"csi.acme.example\"\nmatch = \"suffix\"\ncsi = true\nmodes = [\"ReadWriteOnce\"]\ntopology = \"none\"\nsource = \"https://docs.acme.example/csi\"\nchecked_on = \"2026-10-30\"\n"
    );
    assert!(refused(&both).contains("used twice"));
}

#[test]
fn read_write_once_pod_is_for_csi_drivers_only() {
    let text = GOOD
        .replace("csi = true", "csi = false")
        .replace("[\"ReadWriteOnce\"]", "[\"ReadWriteOncePod\"]");
    assert!(refused(&text).contains("ReadWriteOncePod is for CSI volumes only"));
}

#[test]
fn a_csi_driver_name_has_no_slash_and_a_suffix_has_none() {
    let csi = GOOD.replace("csi.acme.example", "acme.example/csi");
    assert!(refused(&csi).contains("a CSI driver name has no /"));
    let suffix = GOOD
        .replace("csi = true", "csi = false")
        .replace("match = \"exact\"", "match = \"suffix\"")
        .replace("csi.acme.example", "acme.example/csi");
    assert!(refused(&suffix).contains("a suffix entry cannot hold a /"));
}

#[test]
fn an_in_tree_name_is_a_provisioner_name_mapped_once() {
    let map =
        |from: &str, to: &str| format!("{GOOD}\n[[in_tree]]\nfrom = \"{from}\"\nto = \"{to}\"\n");
    assert!(Catalog::parse(&map("kubernetes.io/x", "csi.acme.example")).is_ok());
    assert!(refused(&map("", "csi.acme.example")).contains("from must be"));
    assert!(refused(&map("kubernetes.io/x", "a b")).contains("to must be"));
    let twice = format!(
        "{}\n[[in_tree]]\nfrom = \"kubernetes.io/x\"\nto = \"csi.acme.example\"\n",
        map("kubernetes.io/x", "csi.acme.example")
    );
    assert!(refused(&twice).contains("mapped twice"));
    // A driver cannot be named like an in-tree name.
    let clash = format!(
        "{}\n[[in_tree]]\nfrom = \"csi.acme.example\"\nto = \"csi.acme.example\"\n",
        GOOD
    );
    assert!(refused(&clash).contains("an in-tree name"));
}

#[test]
fn the_table_has_a_size_limit() {
    let mut text = String::from("schema = 1\n");
    for n in 0..=MAX_ENTRIES {
        text.push_str(&format!(
            "[[driver]]\nname = \"csi{n}.acme.example\"\nmatch = \"exact\"\ncsi = true\nmodes = [\"ReadWriteOnce\"]\ntopology = \"none\"\nsource = \"https://docs.acme.example/csi\"\nchecked_on = \"2026-10-30\"\n"
        ));
    }
    assert!(refused(&text).contains("more than 200 entries"));
}

#[test]
fn text_that_is_not_toml_is_refused_with_one_short_line() {
    for text in [
        "",
        "schema",
        "[[driver",
        "\u{0}\u{1}",
        "schema = 1\n[[driver]]\nname = 3",
    ] {
        let message = Catalog::parse(text).map(|_| ()).unwrap_err().to_string();
        assert!(message.contains("Fix: use a build of rdy"), "{message}");
        assert!(message.lines().count() <= 2, "{message}");
    }
}
