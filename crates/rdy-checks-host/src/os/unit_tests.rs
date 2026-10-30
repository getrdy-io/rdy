//! Tests of the pure parts of `host.os`: the `os-release` parser and the match rules.

use super::release::{self, Release};
use super::rules::{self, Match, Procedure, Wanted};

fn release(id: &str, like: &[&str], version: Option<&str>) -> Release {
    Release {
        id: id.to_owned(),
        id_like: like.iter().map(|w| (*w).to_owned()).collect(),
        version_id: version.map(str::to_owned),
        name: None,
        pretty_name: None,
    }
}

fn want(id: &str, versions: Option<&[&str]>) -> Wanted {
    Wanted {
        id: id.to_owned(),
        versions: versions.map(|vs| vs.iter().map(|v| (*v).to_owned()).collect()),
    }
}

// ---- the parser ----

#[test]
fn quotes_comments_and_crlf_are_read() {
    let text = "# a comment\r\nNAME=\"Acme Linux\"\r\nID='acme'\r\nVERSION_ID=\"1.2\"\r\nPRETTY_NAME=\"Acme \\\"One\\\" \\$HOME\"\r\n";
    let r = release::parse(text).expect("a release");
    assert_eq!(r.id, "acme");
    assert_eq!(r.version_id.as_deref(), Some("1.2"));
    assert_eq!(r.name.as_deref(), Some("Acme Linux"));
    assert_eq!(r.pretty_name.as_deref(), Some("Acme \"One\" $HOME"));
}

#[test]
fn unquoted_values_stop_at_whitespace_and_single_quotes_keep_backslashes() {
    let r = release::parse("ID=acme trailing\nNAME='A\\b'\n").expect("a release");
    assert_eq!(r.id, "acme");
    assert_eq!(r.name.as_deref(), Some("A\\b"));
}

#[test]
fn the_last_line_for_a_key_wins() {
    let r = release::parse("ID=first\nID=second\n").expect("a release");
    assert_eq!(r.id, "second");
}

#[test]
fn id_defaults_to_linux_and_id_like_is_split_and_lowered() {
    let r = release::parse("NAME=\"Odd\"\nID_LIKE=\"RHEL  Fedora\"\n").expect("a release");
    assert_eq!(r.id, "linux");
    assert_eq!(r.id_like, ["rhel", "fedora"]);
    assert_eq!(r.version_id, None);
    assert_eq!(r.display(), "Odd");
}

#[test]
fn text_with_none_of_the_keys_is_not_a_release() {
    assert_eq!(release::parse(""), None);
    assert_eq!(release::parse("hello\nworld=1\n# ID=rhel\n"), None);
    assert_eq!(release::parse("\0\u{1}\u{2}"), None);
}

#[test]
fn an_unterminated_quote_takes_the_rest_of_the_line() {
    let r = release::parse("ID=acme\nNAME=\"Open\n").expect("a release");
    assert_eq!(r.name.as_deref(), Some("Open"));
}

#[test]
fn a_hostile_file_is_bounded() {
    let long = "x".repeat(10_000);
    let r = release::parse(&format!(
        "ID={long}\nNAME=\"{long}\"\nID_LIKE=\"{}\"\n",
        "a ".repeat(500)
    ))
    .expect("a release");
    assert_eq!(r.id.chars().count(), 128);
    assert_eq!(r.name.as_deref().map(|n| n.chars().count()), Some(128));
    assert_eq!(r.id_like.len(), 8);

    // Lines past the 256th are not read.
    let mut text = "NAME=\"early\"\n".to_owned();
    text.push_str(&"# padding\n".repeat(300));
    text.push_str("ID=late\n");
    let r = release::parse(&text).expect("a release");
    assert_eq!(r.id, "linux");
}

#[test]
fn display_prefers_the_pretty_name() {
    let mut r = release("rhel", &[], Some("9.2"));
    assert_eq!(r.display(), "rhel 9.2");
    r.name = Some("Red Hat".to_owned());
    assert_eq!(r.display(), "Red Hat 9.2");
    r.pretty_name = Some("Red Hat 9.2 (Plow)".to_owned());
    assert_eq!(r.display(), "Red Hat 9.2 (Plow)");
}

// ---- the rules ----

#[test]
fn version_rules() {
    for (wanted, have, ok) in [
        ("8", "8", true),
        ("8", "8.6", true),
        ("8", "80", false),
        ("8", "18.04", false),
        ("22.04", "22.04", true),
        ("22.04", "22.04.3", false),
        ("22", "22.04", true),
        ("9.2", "9.2", true),
        ("9.2", "9.20", false),
        ("2", "2023", false),
        (" 9 ", "9.1", true),
        ("", "9", false),
    ] {
        assert_eq!(
            rules::version_matches(wanted, have),
            ok,
            "{wanted:?} vs {have:?}"
        );
    }
}

#[test]
fn id_is_exact_and_id_like_counts_only_for_rebuilds_of_rhel_and_centos() {
    let rhel = [want("rhel", Some(&["9"]))];
    let rocky = release("rocky", &["rhel", "centos", "fedora"], Some("9.3"));
    assert_eq!(
        rules::matches(&rocky, &rhel),
        Match::Yes {
            via: Some("rocky".to_owned())
        }
    );
    let alma = release("almalinux", &["rhel", "centos", "fedora"], Some("9.2"));
    assert!(matches!(
        rules::matches(&alma, &rhel),
        Match::Yes { via: Some(_) }
    ));
    let centos = release("centos", &["rhel", "fedora"], Some("9"));
    assert!(matches!(
        rules::matches(&centos, &rhel),
        Match::Yes { via: Some(_) }
    ));
    // Oracle Linux says ID_LIKE=fedora, and fedora is not a parent that counts. `ol` maps to `rhel`.
    let oracle = release("ol", &["fedora"], Some("9.3"));
    assert_eq!(
        rules::matches(&oracle, &rhel),
        Match::Yes {
            via: Some("ol".to_owned())
        }
    );
    assert_eq!(rules::matches(&oracle, &[want("centos", None)]), Match::No);
    assert_eq!(rules::matches(&oracle, &[want("fedora", None)]), Match::No);
    // Not a rebuild.
    let amzn = release("amzn", &["centos", "rhel", "fedora"], Some("2"));
    assert_eq!(rules::matches(&amzn, &rhel), Match::No);
    assert_eq!(rules::matches(&amzn, &[want("rhel", None)]), Match::No);
    let mint = release("linuxmint", &["ubuntu", "debian"], Some("21.3"));
    assert_eq!(rules::matches(&mint, &[want("ubuntu", None)]), Match::No);
    assert_eq!(rules::matches(&mint, &[want("debian", None)]), Match::No);
}

#[test]
fn a_direct_match_wins_over_one_through_id_like() {
    let rocky = release("rocky", &["rhel"], Some("9.3"));
    let both = [want("rhel", None), want("rocky", Some(&["9"]))];
    assert_eq!(rules::matches(&rocky, &both), Match::Yes { via: None });
}

#[test]
fn an_id_like_match_still_needs_the_version_to_fit() {
    let rocky = release("rocky", &["rhel"], Some("9.3"));
    assert_eq!(
        rules::matches(&rocky, &[want("rhel", Some(&["8"]))]),
        Match::No
    );
    assert_eq!(
        rules::matches(
            &rocky,
            &[want("rhel", Some(&["8"])), want("rhel", Some(&["9"]))]
        ),
        Match::Yes {
            via: Some("rocky".to_owned())
        }
    );
}

#[test]
fn a_missing_version_id_is_unknown_not_a_miss() {
    let arch = release("arch", &[], None);
    assert_eq!(
        rules::matches(&arch, &[want("arch", Some(&["1"]))]),
        Match::VersionUnknown
    );
    assert_eq!(
        rules::matches(&arch, &[want("arch", None)]),
        Match::Yes { via: None }
    );
    assert_eq!(
        rules::matches(&arch, &[want("rhel", Some(&["1"]))]),
        Match::No
    );
    // Another entry that fits settles it.
    assert_eq!(
        rules::matches(&arch, &[want("arch", Some(&["1"])), want("arch", None)]),
        Match::Yes { via: None }
    );
}

#[test]
fn an_empty_list_matches_nothing() {
    assert_eq!(
        rules::matches(&release("rhel", &[], Some("9")), &[]),
        Match::No
    );
}

#[test]
fn arch_names_are_made_canonical() {
    assert_eq!(rules::canonical_arch("amd64"), "x86_64");
    assert_eq!(rules::canonical_arch("arm64"), "aarch64");
    assert_eq!(rules::canonical_arch("x86_64"), "x86_64");
    assert_eq!(rules::canonical_arch("armv7l"), "armv7l");
}

#[test]
fn the_supported_list_reads_as_a_sentence_and_is_capped() {
    assert_eq!(
        rules::list_supported(&[
            want("rhel", Some(&["8", "9"])),
            want("ubuntu", Some(&["22.04"])),
            want("sles", None),
            want("debian", Some(&["10", "11", "12"])),
        ]),
        "rhel 8 or 9, ubuntu 22.04, sles (any version), debian 10, 11 or 12"
    );
    let many: Vec<Wanted> = (0..20).map(|i| want(&format!("d{i}"), None)).collect();
    let text = rules::list_supported(&many);
    assert!(text.ends_with("12 more"), "{text}");
    assert_eq!(text.matches("any version").count(), 8);
}

#[test]
fn the_procedure_comes_from_id_id_like_and_the_major_version() {
    let p = |id: &str, like: &[&str], version: Option<&str>| {
        rules::procedure(&release(id, like, version))
    };
    assert_eq!(p("rhel", &[], Some("9.2")), Procedure::ModeSetup);
    assert_eq!(p("rocky", &["rhel"], Some("8")), Procedure::ModeSetup);
    assert_eq!(p("ol", &["fedora"], Some("9.3")), Procedure::ModeSetup);
    assert_eq!(p("rhel", &[], Some("10.0")), Procedure::InstallOnly);
    assert_eq!(
        p("almalinux", &["rhel"], Some("10")),
        Procedure::InstallOnly
    );
    assert_eq!(p("centos", &["rhel"], Some("7")), Procedure::Vendor);
    assert_eq!(p("rhel", &[], None), Procedure::Vendor);
    assert_eq!(
        p("amzn", &["rhel", "fedora"], Some("2")),
        Procedure::AmazonLinux2
    );
    assert_eq!(p("amzn", &["fedora"], Some("2023")), Procedure::ModeSetup);
    assert_eq!(p("amzn", &[], Some("1")), Procedure::Vendor);
    assert_eq!(p("fedora", &[], Some("40")), Procedure::Vendor);
    assert_eq!(
        p("ubuntu", &["debian"], Some("22.04")),
        Procedure::UbuntuPro
    );
    assert_eq!(p("linuxmint", &["ubuntu"], None), Procedure::UbuntuPro);
    assert_eq!(p("alpine", &[], None), Procedure::Vendor);
    assert_eq!(p("debian", &[], None), Procedure::Vendor);
}

#[test]
fn the_prefix_trap_finds_dotted_prefixes_only() {
    let v = |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
    assert_eq!(
        rules::prefix_trap(&v(&["3.19", "3.18"]), "3.19.1"),
        ["3.19"]
    );
    assert!(rules::prefix_trap(&v(&["3"]), "3.19.1").is_empty());
    assert!(rules::prefix_trap(&v(&["3.19.1"]), "3.19.1").is_empty());
    assert!(rules::prefix_trap(&v(&["3.1"]), "3.19.1").is_empty());
}
