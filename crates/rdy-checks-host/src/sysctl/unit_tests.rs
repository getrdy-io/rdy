//! Unit tests of the pure parts of `host.sysctl`: value comparison, the sysctl.d line parser, wildcard
//! keys, the systemd limit reader and the wording helpers.

use std::collections::BTreeSet;

use proptest::prelude::*;
use rdy_spec::check::{Compare, ValueRule};
use serde_json::json;

use super::layers::Layer;
use super::limits::{self, Configured, Facts, Limit, Nofile};
use super::persist::{Line, Settings, canonical_key, glob_matches, parse_line};
use super::value::{self, Judged};
use super::*;

/// A rule built the way a spec writes it.
fn rule(text: &str) -> ValueRule {
    serde_json::from_value(json!(text)).expect("a value rule")
}

fn int_rule(n: i64) -> ValueRule {
    serde_json::from_value(json!(n)).expect("a value rule")
}

// ---- values --------------------------------------------------------------------------------------

#[test]
fn white_space_runs_are_one_space() {
    assert_eq!(
        value::normalise("4096\t131072\t6291456\n"),
        "4096 131072 6291456"
    );
    assert_eq!(value::normalise("  a \t\t b  "), "a b");
    assert_eq!(value::normalise(""), "");
}

#[test]
fn a_tab_and_a_space_are_the_same_in_a_text_value() {
    let wanted = rule("4096 87380 6291456");
    assert_eq!(value::judge(&wanted, "4096\t87380\t6291456\n"), Judged::Met);
    assert_eq!(value::judge(&wanted, "4096  87380   6291456"), Judged::Met);
    assert_eq!(value::judge(&wanted, "4096 87380 6291457"), Judged::Unmet);
    // The spec itself cannot hold a tab: rdy-spec refuses control characters in a value.
    assert!(serde_json::from_value::<ValueRule>(json!("4096\t87380")).is_err());
}

#[test]
fn whole_numbers_compare_as_numbers_in_128_bits() {
    assert_eq!(
        value::whole("18446744073709551615"),
        Some(i128::from(u64::MAX))
    );
    assert_eq!(value::whole("-1"), Some(-1));
    assert_eq!(value::whole("+1"), None);
    assert_eq!(value::whole("1.5"), None);
    assert_eq!(value::whole(""), None);
    assert_eq!(value::whole("-"), None);
    assert_eq!(value::whole(&"9".repeat(31)), None);
    let at_least = rule(">=4294967296");
    assert_eq!(value::judge(&at_least, "18446744073709551615"), Judged::Met);
    assert_eq!(value::judge(&at_least, "4294967295"), Judged::Unmet);
    assert_eq!(value::judge(&rule("<=1024"), "1024"), Judged::Met);
    assert_eq!(value::judge(&rule("<=1024"), "1025"), Judged::Unmet);
    assert_eq!(value::judge(&rule(">= -1"), "-1"), Judged::Met);
}

#[test]
fn equal_numbers_ignore_leading_zeros_and_text_stays_text() {
    assert_eq!(value::judge(&int_rule(1), "1"), Judged::Met);
    assert_eq!(value::judge(&int_rule(1), "01"), Judged::Met);
    assert_eq!(value::judge(&int_rule(0), "1"), Judged::Unmet);
    assert_eq!(value::judge(&rule("bbr"), "bbr\n"), Judged::Met);
    assert_eq!(value::judge(&rule("bbr"), "BBR"), Judged::Unmet);
}

#[test]
fn a_numeric_rule_on_a_value_that_is_not_a_number_cannot_be_judged() {
    assert_eq!(
        value::judge(&rule(">=1"), "4096 131072 6291456"),
        Judged::NotNumber
    );
    assert_eq!(value::judge(&rule("<=1"), "bbr"), Judged::NotNumber);
    assert_eq!(value::judge(&rule(">=1"), ""), Judged::NotNumber);
}

#[test]
fn rules_read_back_as_the_spec_wrote_them() {
    assert_eq!(value::rule_text(&rule(">=262144")), ">=262144");
    assert_eq!(value::rule_text(&rule(">= 5")), ">=5");
    assert_eq!(value::rule_text(&rule("<=1024")), "<=1024");
    assert_eq!(value::rule_text(&rule("1")), "1");
    assert_eq!(value::need_words(&rule(">=262144")), "at least 262144");
    assert_eq!(value::need_words(&rule("<=1024")), "at most 1024");
    assert_eq!(value::need_words(&rule("bbr")), "bbr");
    assert_eq!(rule(">=5").compare, Compare::AtLeast);
}

#[test]
fn only_plain_values_may_go_inside_quotes() {
    for ok in ["262144", "4096 87380 6291456", "bbr", "a.b_c-d:e,f+g"] {
        assert!(value::is_quotable(ok), "{ok}");
    }
    for bad in [
        "", "a'b", "a;b", "a$b", "a`b", "a\"b", "a\\b", "a|b", "a&b", "a/b", "a%b", "x\n",
    ] {
        assert!(!value::is_quotable(bad), "{bad:?}");
    }
    assert!(!value::is_quotable(&"a".repeat(129)));
}

#[test]
fn clip_cuts_on_characters() {
    assert_eq!(value::clip("abc", 3), "abc");
    assert_eq!(value::clip("abcd", 3), "abc...");
    assert_eq!(value::clip("ééé", 2), "éé...");
}

// ---- sysctl.d lines ------------------------------------------------------------------------------

fn set(key: &str, value: &str) -> Option<Line> {
    Some(Line::Set {
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

#[test]
fn comments_blank_lines_and_junk_are_ignored() {
    for line in [
        "",
        "   ",
        "# a",
        "  # a",
        "; a",
        "\t; a",
        "no equals sign",
        "= 5",
        " =",
        "-",
        "- ",
    ] {
        assert_eq!(parse_line(line), None, "{line:?}");
    }
}

#[test]
fn a_line_is_key_equals_value_with_any_spaces_around_it() {
    assert_eq!(
        parse_line("vm.max_map_count = 262144"),
        set("vm/max_map_count", "262144")
    );
    assert_eq!(
        parse_line("vm.max_map_count=262144"),
        set("vm/max_map_count", "262144")
    );
    assert_eq!(
        parse_line("\tvm.max_map_count\t=\t262144  \n"),
        set("vm/max_map_count", "262144")
    );
    assert_eq!(
        parse_line("net.ipv4.tcp_rmem = 4096\t131072   6291456"),
        set("net/ipv4/tcp_rmem", "4096 131072 6291456")
    );
    // Only the first equals sign splits the line.
    assert_eq!(parse_line("a.b = x=y"), set("a/b", "x=y"));
    // An empty value is a value.
    assert_eq!(parse_line("a.b ="), set("a/b", ""));
}

#[test]
fn the_ignore_errors_mark_does_not_change_the_value() {
    assert_eq!(
        parse_line("-net.ipv4.ip_forward = 1"),
        set("net/ipv4/ip_forward", "1")
    );
    assert_eq!(
        parse_line("- net.ipv4.ip_forward = 1"),
        set("net/ipv4/ip_forward", "1")
    );
}

#[test]
fn a_minus_line_with_no_value_leaves_a_key_out_of_wildcards() {
    assert_eq!(
        parse_line("-net.ipv4.conf.lo.rp_filter"),
        Some(Line::Exclude {
            key: "net/ipv4/conf/lo/rp_filter".to_owned()
        })
    );
}

#[test]
fn the_first_separator_decides_how_a_key_is_read() {
    assert_eq!(canonical_key("vm.max_map_count"), "vm/max_map_count");
    assert_eq!(canonical_key("vm/max_map_count"), "vm/max_map_count");
    assert_eq!(
        canonical_key("net.ipv4.conf.eth0/100.rp_filter"),
        "net/ipv4/conf/eth0.100/rp_filter"
    );
    assert_eq!(
        canonical_key("net/ipv4/conf/eth0.100/rp_filter"),
        "net/ipv4/conf/eth0.100/rp_filter"
    );
    assert_eq!(canonical_key("plain"), "plain");
    assert_eq!(canonical_key(""), "");
    // The spec's own form agrees for the two forms a spec may use.
    for text in ["vm.max_map_count", "net/ipv4/conf/eth0.100/rp_filter"] {
        let name: SysctlNameProbe = SysctlNameProbe::new(text);
        assert_eq!(canonical_key(text), name.0, "{text}");
    }
}

/// `SysctlName::canonical` for a name that the spec accepts, read through the spec's own parser.
struct SysctlNameProbe(String);

impl SysctlNameProbe {
    fn new(text: &str) -> Self {
        let params: rdy_spec::check::HostSysctl =
            serde_json::from_value(json!({"expect": {text: 1}})).expect("a parameter");
        let name = params
            .expect
            .as_ref()
            .and_then(|map| map.keys().next())
            .expect("a name")
            .canonical();
        Self(name)
    }
}

// ---- wildcards -----------------------------------------------------------------------------------

#[test]
fn a_wildcard_stays_inside_one_part() {
    assert!(glob_matches(
        "net/ipv4/conf/*/rp_filter",
        "net/ipv4/conf/eth0/rp_filter"
    ));
    assert!(glob_matches(
        "net/ipv4/conf/*/rp_filter",
        "net/ipv4/conf/eth0.100/rp_filter"
    ));
    assert!(glob_matches(
        "net/ipv4/conf/eth?/rp_filter",
        "net/ipv4/conf/eth0/rp_filter"
    ));
    assert!(glob_matches(
        "net/ipv4/conf/eth*/rp_filter",
        "net/ipv4/conf/eth0/rp_filter"
    ));
    assert!(
        !glob_matches("net/ipv4/*", "net/ipv4/conf/all"),
        "a star does not cross a slash"
    );
    assert!(!glob_matches(
        "net/ipv4/conf/*/rp_filter",
        "net/ipv4/conf/rp_filter"
    ));
    assert!(!glob_matches(
        "net/ipv4/conf/eth?/rp_filter",
        "net/ipv4/conf/eth10/rp_filter"
    ));
    assert!(!glob_matches("a/b", "a/b/c"));
    assert!(glob_matches("a/*b*/c", "a/xbx/c"));
    assert!(glob_matches("a/**/c", "a/x/c"));
    assert!(glob_matches("*", "anything"));
}

#[test]
fn a_character_class_never_matches_and_is_counted() {
    assert!(!glob_matches(
        "net/ipv4/conf/eth[0-9]/rp_filter",
        "net/ipv4/conf/eth0/rp_filter"
    ));
    let mut settings = Settings::new(BTreeSet::from(["net/ipv4/conf/eth0/rp_filter".to_owned()]));
    settings.ingest(
        "/etc/sysctl.d/a.conf",
        "net.ipv4.conf.eth[0-9].rp_filter = 1\n",
    );
    assert_eq!(settings.skipped_globs, 1);
    assert!(settings.get("net/ipv4/conf/eth0/rp_filter").is_none());
}

// ---- settings ------------------------------------------------------------------------------------

fn settings(wanted: &[&str]) -> Settings {
    Settings::new(wanted.iter().map(|w| (*w).to_owned()).collect())
}

#[test]
fn a_later_file_replaces_an_earlier_setting() {
    let mut s = settings(&["vm/max_map_count"]);
    s.ingest("/etc/sysctl.d/10-a.conf", "vm.max_map_count = 1\n");
    s.ingest(
        "/usr/lib/sysctl.d/90-b.conf",
        "vm.max_map_count = 2\nvm.max_map_count = 3\n",
    );
    let got = s.get("vm/max_map_count").expect("set");
    assert_eq!(got.value, "3");
    assert_eq!(got.file, "/usr/lib/sysctl.d/90-b.conf");
}

#[test]
fn only_the_asked_about_keys_are_kept() {
    let mut s = settings(&["vm/max_map_count"]);
    s.ingest(
        "/etc/sysctl.d/10-a.conf",
        "vm.swappiness = 1\nkernel.core_pattern = |/bin/x\n",
    );
    assert!(s.get("vm/swappiness").is_none());
    assert!(s.get("kernel/core_pattern").is_none());
}

#[test]
fn an_explicit_line_beats_a_wildcard_and_the_last_wildcard_wins() {
    let mut s = settings(&[
        "net/ipv4/conf/eth0/rp_filter",
        "net/ipv4/conf/eth1/rp_filter",
    ]);
    s.ingest(
        "/etc/sysctl.d/10.conf",
        "net.ipv4.conf.*.rp_filter = 2\nnet.ipv4.conf.eth0.rp_filter = 1\n",
    );
    s.ingest(
        "/etc/sysctl.d/20.conf",
        "net.ipv4.conf.eth?.rp_filter = 0\n",
    );
    assert_eq!(
        s.get("net/ipv4/conf/eth0/rp_filter")
            .map(|x| x.value.as_str()),
        Some("1")
    );
    assert_eq!(
        s.get("net/ipv4/conf/eth1/rp_filter")
            .map(|x| x.value.as_str()),
        Some("0")
    );
}

#[test]
fn the_number_of_wildcard_lines_is_bounded() {
    let mut s = settings(&["a/b"]);
    let text: String = (0..400).map(|i| format!("x{i}.*.z = 1\n")).collect();
    s.ingest("/etc/sysctl.d/big.conf", &text);
    assert_eq!(s.skipped_globs, 400 - 256);
}

// ---- systemd limits ------------------------------------------------------------------------------

fn layer(path: &str, text: &str) -> Layer {
    Layer {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

#[test]
fn the_limit_forms_are_a_number_a_pair_and_infinity() {
    let n = |x| Limit::Count(x);
    assert_eq!(
        limits::parse_nofile("1024"),
        Some(Nofile {
            soft: n(1024),
            hard: n(1024)
        })
    );
    assert_eq!(
        limits::parse_nofile("1024:524288"),
        Some(Nofile {
            soft: n(1024),
            hard: n(524_288)
        })
    );
    assert_eq!(
        limits::parse_nofile("infinity"),
        Some(Nofile {
            soft: Limit::Infinity,
            hard: Limit::Infinity
        })
    );
    assert_eq!(
        limits::parse_nofile("65536:Infinity"),
        Some(Nofile {
            soft: n(65_536),
            hard: Limit::Infinity
        })
    );
    for bad in ["", "abc", "1k", "-1", "1:", ":1", "1:2:3", "1.5"] {
        assert_eq!(limits::parse_nofile(bad), None, "{bad:?}");
    }
}

#[test]
fn the_assignment_must_be_in_the_manager_section() {
    assert_eq!(
        limits::assignment("[Manager]\nDefaultLimitNOFILE=1024\n"),
        Some(Some("1024".to_owned()))
    );
    assert_eq!(
        limits::assignment("DefaultLimitNOFILE=1024\n"),
        None,
        "no section"
    );
    assert_eq!(
        limits::assignment("[Other]\nDefaultLimitNOFILE=1024\n"),
        None
    );
    assert_eq!(
        limits::assignment("[Manager]\n#DefaultLimitNOFILE=1024\n"),
        None
    );
    assert_eq!(
        limits::assignment("[Manager]\n; DefaultLimitNOFILE=1024\n"),
        None
    );
    // The last one wins, and an empty one puts the built-in default back.
    assert_eq!(
        limits::assignment("[Manager]\nDefaultLimitNOFILE=1\nDefaultLimitNOFILE = 2\n"),
        Some(Some("2".to_owned()))
    );
    assert_eq!(
        limits::assignment("[Manager]\nDefaultLimitNOFILE=1\nDefaultLimitNOFILE=\n"),
        Some(None)
    );
    assert_eq!(
        limits::assignment("[Manager]\nDefaultLimitNOFILEX=1\n"),
        None
    );
}

#[test]
fn the_last_file_that_sets_the_limit_wins() {
    let files = [
        layer(
            "/etc/systemd/system.conf",
            "[Manager]\nDefaultLimitNOFILE=1024\n",
        ),
        layer(
            "/etc/systemd/system.conf.d/10.conf",
            "[Manager]\nDefaultLimitNOFILE=4096\n",
        ),
        layer(
            "/etc/systemd/system.conf.d/20.conf",
            "[Manager]\n# nothing\n",
        ),
    ];
    let got = limits::configured(&files).expect("set");
    assert_eq!(got.raw, "4096");
    assert_eq!(got.file, "/etc/systemd/system.conf.d/10.conf");
    let reset = [
        layer("/a", "[Manager]\nDefaultLimitNOFILE=4096\n"),
        layer("/b", "[Manager]\nDefaultLimitNOFILE=\n"),
    ];
    assert_eq!(limits::configured(&reset), None);
}

fn facts(configured: Option<&str>) -> Facts {
    Facts {
        configured: configured.map(|raw| Configured {
            raw: raw.to_owned(),
            value: limits::parse_nofile(raw),
            file: "/etc/systemd/system.conf".to_owned(),
        }),
        nr_open: Some(1_048_576),
        file_max: Some(9_000_000),
        shell: Some((Some(1024), Some(1_048_576))),
        unknown: Vec::new(),
    }
}

fn level(rule_text: &str, facts: &Facts) -> Option<Level> {
    limits::judge(&rule(rule_text), facts)
        .problem
        .map(|p| p.level)
}

#[test]
fn a_configured_limit_is_judged_on_the_soft_value() {
    assert_eq!(level(">=65536", &facts(Some("65536"))), None);
    assert_eq!(level(">=65536", &facts(Some("65536:524288"))), None);
    assert_eq!(
        level(">=65536", &facts(Some("1024:524288"))),
        Some(Level::Fail)
    );
    assert_eq!(level("<=1024", &facts(Some("1024"))), None);
    assert_eq!(level("<=1024", &facts(Some("2048"))), Some(Level::Fail));
    assert_eq!(level("65536", &facts(Some("65536"))), None);
    assert_eq!(level("65536", &facts(Some("65537"))), Some(Level::Fail));
}

#[test]
fn infinity_means_the_kernel_ceiling() {
    assert_eq!(level(">=1000000", &facts(Some("infinity"))), None);
    let mut low = facts(Some("infinity"));
    low.nr_open = Some(4096);
    assert_eq!(level(">=65536", &low), Some(Level::Fail));
}

#[test]
fn a_limit_above_nr_open_blocks_whatever_is_configured() {
    let judgement = limits::judge(&rule(">=2000000"), &facts(Some("infinity")));
    let problem = judgement.problem.expect("a problem");
    assert_eq!(problem.level, Level::Fail);
    assert!(problem.text.contains("`fs.nr_open` is 1048576"));
    // An upper bound is not a ceiling problem.
    assert_eq!(level("<=2000000", &facts(Some("65536"))), None);
}

#[test]
fn an_unset_limit_is_judged_against_what_every_systemd_gives() {
    let unset = facts(None);
    // 1024 on systemd 240 and newer, and never more than 4096: these are certain.
    assert_eq!(level(">=65536", &unset), Some(Level::Fail));
    assert_eq!(level(">=4097", &unset), Some(Level::Fail));
    assert_eq!(level(">=1024", &unset), None);
    assert_eq!(level(">=512", &unset), None);
    assert_eq!(level("<=4096", &unset), None);
    assert_eq!(level("<=512", &unset), Some(Level::Fail));
    assert_eq!(level("65536", &unset), Some(Level::Fail));
    // These depend on the version: not verified, never a block.
    assert_eq!(level(">=2048", &unset), Some(Level::Warn));
    assert_eq!(level("<=2048", &unset), Some(Level::Warn));
    let judgement = limits::judge(&rule(">=2048"), &unset);
    assert!(judgement.unverified.is_some());
}

#[test]
fn an_unset_limit_with_an_unread_file_is_not_verified() {
    let mut unread = facts(None);
    unread.unknown =
        vec!["/etc/systemd/system.conf could not be read (permission denied)".to_owned()];
    let judgement = limits::judge(&rule(">=65536"), &unread);
    assert_eq!(judgement.problem.map(|p| p.level), Some(Level::Warn));
    assert!(judgement.unverified.is_some());
}

#[test]
fn a_value_rdy_does_not_understand_is_not_verified() {
    let judgement = limits::judge(&rule(">=65536"), &facts(Some("64K")));
    assert_eq!(judgement.problem.map(|p| p.level), Some(Level::Warn));
    assert!(judgement.unverified.is_some());
}

#[test]
fn a_limit_rule_that_is_not_a_number_is_not_verified() {
    let judgement = limits::judge(&rule("lots"), &facts(Some("65536")));
    assert_eq!(judgement.problem.map(|p| p.level), Some(Level::Warn));
    assert!(judgement.unverified.is_some());
}

#[test]
fn the_shell_limit_is_labelled_and_not_judged() {
    let judgement = limits::judge(&rule(">=65536"), &facts(Some("65536")));
    assert!(judgement.problem.is_none());
    assert!(judgement.notes[0].contains("(soft)") && judgement.notes[0].contains("shell limit"));
    assert_eq!(
        judgement.observed["shell_limit"],
        json!({"soft": 1024, "hard": 1_048_576})
    );
    let mut none = facts(Some("65536"));
    none.shell = None;
    assert!(limits::judge(&rule(">=65536"), &none).notes.is_empty());
}

// ---- wording -------------------------------------------------------------------------------------

#[test]
fn modules_that_provide_a_family_of_parameters_are_named() {
    assert!(missing_fix("net.bridge.bridge-nf-call-iptables").contains("modprobe br_netfilter"));
    assert!(missing_fix("net/bridge/bridge-nf-call-ip6tables").contains("br_netfilter"));
    assert!(missing_fix("net.netfilter.nf_conntrack_max").contains("modprobe nf_conntrack"));
    assert!(missing_fix("vm.nonesuch").contains("vendor's documentation"));
    for name in ["net.bridge.x", "net.netfilter.y", "vm.nonesuch"] {
        if let Err(error) = rdy_engine::fixtext::check(&missing_fix(name)) {
            panic!("{name}: {error}");
        }
    }
}

#[test]
fn more_than_three_problems_name_three_and_count_the_rest() {
    let problems: Vec<Problem> = (0..5)
        .map(|i| Problem {
            level: Level::Warn,
            text: format!("p{i}"),
            fix: Some(format!("f{i}.")),
            apply: i == 4,
        })
        .collect();
    let refs: Vec<&Problem> = problems.iter().collect();
    let fix = fix_text(&refs).expect("a fix");
    assert!(fix.starts_with("f0. f1. f2."), "{fix}");
    assert!(!fix.contains("f3."));
    assert!(fix.contains("Do the same for the other 2."), "{fix}");
    assert!(
        fix.contains("sysctl --system"),
        "the apply step is counted over all problems"
    );
    assert_eq!(fix_text(&[]), None);
}

// ---- parsers never panic -------------------------------------------------------------------------

proptest! {
    #[test]
    fn line_parsing_never_panics_on_arbitrary_text(text in ".{0,600}") {
        let _ = parse_line(&text);
    }

    #[test]
    fn ingesting_arbitrary_text_never_panics(text in "(.|\n){0,2000}") {
        let mut s = settings(&["vm/max_map_count"]);
        s.ingest("/etc/sysctl.d/x.conf", &text);
        let _ = s.get("vm/max_map_count");
    }

    #[test]
    fn globs_never_panic_and_a_key_matches_itself(
        pattern in "[a-z*?\\[/.]{0,20}",
        key in "[a-z0-9/.]{0,20}",
    ) {
        let _ = glob_matches(&pattern, &key);
        if !key.contains(['*', '?', '[']) {
            prop_assert!(glob_matches(&key, &key));
        }
    }

    #[test]
    fn a_key_is_the_same_after_one_more_pass_of_the_slash_form(key in "[a-z0-9_.-]{1,12}(\\.[a-z0-9_-]{1,8}){0,4}") {
        // A key that is only dots reads as dots; its slash form reads as itself.
        let once = canonical_key(&key);
        prop_assert_eq!(canonical_key(&once), once.clone());
    }

    #[test]
    fn value_judging_never_panics(have in ".{0,80}", want in ".{1,40}") {
        if let Ok(r) = serde_json::from_value::<ValueRule>(json!(want)) {
            let _ = value::judge(&r, &have);
        }
    }

    #[test]
    fn systemd_config_reading_never_panics(text in "(.|\n){0,1200}") {
        let _ = limits::assignment(&text);
        let _ = limits::parse_nofile(&text);
    }
}
