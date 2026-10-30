//! Tests of the security-software catalog: the shipped file, each rule of the parser, and the name match.

use rdy_engine::testing::{Fixture, fixtures_dir};

use super::*;

fn shipped() -> &'static Catalog {
    catalog().expect("the shipped agents.toml parses")
}

/// One valid entry to break one rule at a time.
const GOOD: &str = r#"
schema = 1

[[agent]]
id = "acme-guard"
display_name = "Acme Guard"
category = "edr"
process_names = ["acme-guardd"]
source = "https://docs.example/guard"
checked_on = "2026-10-30"
"#;

fn refused(text: &str) -> String {
    Catalog::parse(text)
        .expect_err("the text is refused")
        .to_string()
}

fn with(field: &str, line: &str) -> String {
    GOOD.lines()
        .map(|l| {
            if l.starts_with(field) {
                line.to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_shipped_list_is_a_seed_of_ten_to_fifteen_entries() {
    let count = shipped().agents().len();
    assert!((10..=15).contains(&count), "{count} entries");
}

#[test]
fn every_shipped_entry_has_a_fixture_that_the_loader_reads() {
    // Each catalog entry has a synthetic machine (tests/fixtures/checks/host.security_agents/agent-<id>)
    // that runs the entry's processes. The check tests run the check against each one.
    for agent in shipped().agents() {
        let name = format!("checks/host.security_agents/agent-{}", agent.id);
        let fixture = Fixture::load(&fixtures_dir(), &name)
            .unwrap_or_else(|e| panic!("{} has no fixture: {e}", agent.id));
        fixture
            .ensure_answers("host.security_agents")
            .expect("it answers the check");
    }
}

#[test]
fn every_shipped_entry_names_its_source_and_a_real_date() {
    for agent in shipped().agents() {
        assert!(agent.source.starts_with("https://"), "{}", agent.id);
        assert!(days(&agent.checked_on).is_some(), "{}", agent.id);
        assert!(!agent.process_names.is_empty(), "{}", agent.id);
    }
}

#[test]
fn every_process_name_matches_itself_as_the_kernel_shows_it_and_nothing_shorter() {
    for agent in shipped().agents() {
        for name in &agent.process_names {
            let shown: String = name.chars().take(COMM_MAX).collect();
            assert!(agent.matches_comm(&shown), "{} / {name}", agent.id);
            if name.len() > COMM_MAX {
                // A cut name needs all 15 bytes: 14 bytes of it is some other program.
                let shorter: String = name.chars().take(COMM_MAX - 1).collect();
                assert!(!agent.matches_comm(&shorter), "{} / {name}", agent.id);
            }
        }
    }
}

#[test]
fn no_process_name_belongs_to_two_entries() {
    let mut seen = BTreeSet::new();
    for agent in shipped().agents() {
        for name in &agent.process_names {
            assert!(seen.insert(name.as_str()), "{name} is used twice");
        }
    }
}

#[test]
fn the_catalog_ids_are_the_known_ids_in_file_order() {
    let ids: Vec<&str> = shipped().ids().collect();
    assert_eq!(ids.first(), Some(&"microsoft-defender-endpoint-linux"));
    assert!(shipped().get("falco").is_some());
    assert!(shipped().get("nothing").is_none());
}

#[test]
fn a_comm_of_fifteen_bytes_matches_a_longer_name_that_starts_with_it() {
    assert!(comm_matches("elastic-endpoin", "elastic-endpoint"));
    assert!(comm_matches("sophos_threat_d", "sophos_threat_detector"));
    // Exactly 15 bytes: no cut, whole match only.
    assert!(comm_matches("wazuh-syscheckd", "wazuh-syscheckd"));
    assert!(!comm_matches("wazuh-syscheckx", "wazuh-syscheckd"));
}

#[test]
fn a_short_comm_must_match_whole_and_a_cut_comm_must_have_all_fifteen_bytes() {
    assert!(!comm_matches("clam", "clamd"));
    assert!(!comm_matches("clamdx", "clamd"));
    assert!(!comm_matches("elastic-endpoix", "elastic-endpoint"));
    assert!(!comm_matches("elastic-endpoi", "elastic-endpoint"));
    assert!(!comm_matches("", "clamd"));
    assert!(!comm_matches("CLAMD", "clamd"));
}

#[test]
fn the_good_entry_parses() {
    let catalog = Catalog::parse(GOOD).expect("it parses");
    assert_eq!(catalog.agents().len(), 1);
    assert_eq!(catalog.agents()[0].category, Category::Edr);
    assert_eq!(catalog.agents()[0].exclusion_docs_url, None);
}

#[test]
fn a_catalog_with_no_entries_parses() {
    assert_eq!(
        Catalog::parse("schema = 1\n")
            .expect("empty")
            .agents()
            .len(),
        0
    );
}

#[test]
fn the_parser_refuses_what_the_rules_say() {
    for (what, text, want) in [
        (
            "a schema that is not 1",
            GOOD.replace("schema = 1", "schema = 2"),
            "schema 2",
        ),
        (
            "no schema",
            GOOD.replace("schema = 1\n", ""),
            "not in the expected form",
        ),
        (
            "an unknown key",
            format!("{GOOD}colour = \"red\"\n"),
            "not in the expected form",
        ),
        (
            "an upper case id",
            with("id", "id = \"Acme\""),
            "id must be",
        ),
        ("an id with a dot", with("id", "id = \"a.b\""), "id must be"),
        ("an empty id", with("id", "id = \"\""), "id must be"),
        (
            "an empty display name",
            with("display_name", "display_name = \"\""),
            "display_name",
        ),
        (
            "a display name with a control character",
            with("display_name", "display_name = \"Acme\\u0007\""),
            "display_name",
        ),
        (
            "an unknown category",
            with("category", "category = \"rootkit\""),
            "not in the expected form",
        ),
        (
            "no process names",
            with("process_names", "process_names = []"),
            "1 to 8",
        ),
        (
            "nine process names",
            with(
                "process_names",
                "process_names = [\"a1\",\"a2\",\"a3\",\"a4\",\"a5\",\"a6\",\"a7\",\"a8\",\"a9\"]",
            ),
            "1 to 8",
        ),
        (
            "a process name with a space",
            with("process_names", "process_names = [\"a b\"]"),
            "ASCII",
        ),
        (
            "a process name with a slash",
            with("process_names", "process_names = [\"/bin/x\"]"),
            "ASCII",
        ),
        (
            "a non ASCII process name",
            with("process_names", "process_names = [\"caf\u{e9}\"]"),
            "ASCII",
        ),
        (
            "an empty process name",
            with("process_names", "process_names = [\"\"]"),
            "ASCII",
        ),
        (
            "a repeated process name",
            with("process_names", "process_names = [\"x\", \"x\"]"),
            "listed twice",
        ),
        (
            "a source over http",
            with("source", "source = \"http://docs.example/g\""),
            "https",
        ),
        (
            "a source with a user",
            with("source", "source = \"https://u:p@docs.example/g\""),
            "plain https",
        ),
        (
            "a source with a query",
            with("source", "source = \"https://docs.example/g?x=1\""),
            "plain https",
        ),
        (
            "a source with a fragment",
            with("source", "source = \"https://docs.example/g#x\""),
            "plain https",
        ),
        (
            "a source with a space",
            with("source", "source = \"https://docs.example/a b\""),
            "plain https",
        ),
        (
            "a source with no host",
            with("source", "source = \"https:///g\""),
            "plain https",
        ),
        (
            "a date in the wrong form",
            with("checked_on", "checked_on = \"30/10/2026\""),
            "YYYY-MM-DD",
        ),
        (
            "a date that does not exist",
            with("checked_on", "checked_on = \"2026-02-30\""),
            "YYYY-MM-DD",
        ),
        (
            "month 13",
            with("checked_on", "checked_on = \"2026-13-01\""),
            "YYYY-MM-DD",
        ),
        (
            "a date before 1970",
            with("checked_on", "checked_on = \"1969-12-31\""),
            "YYYY-MM-DD",
        ),
        (
            "a bad exclusion URL",
            format!("{GOOD}exclusion_docs_url = \"ftp://docs.example/x\"\n"),
            "exclusion_docs_url must start",
        ),
        (
            "a free text note",
            format!("{GOOD}risk = \"slow\"\n"),
            "not in the expected form",
        ),
    ] {
        let message = refused(&text);
        assert!(message.contains(want), "{what}: {message}");
        assert!(message.contains("Fix:"), "{what}: {message}");
    }
}

#[test]
fn the_parser_refuses_a_second_use_of_an_id_or_a_process_name() {
    let twice = format!("{GOOD}\n{}", GOOD.replace("schema = 1\n", ""));
    assert!(refused(&twice).contains("id is used twice"));
    let other_id = format!(
        "{GOOD}\n{}",
        GOOD.replace("schema = 1\n", "")
            .replace("acme-guard\"", "acme-other\"")
    );
    assert!(refused(&other_id).contains("used by another name"));
}

/// A catalog of two entries whose process names are `first` and `second`.
fn two_entries(first: &str, second: &str) -> String {
    let entry = |id: &str, name: &str| {
        format!(
            "[[agent]]\nid = \"{id}\"\ndisplay_name = \"Acme\"\ncategory = \"edr\"\nprocess_names = [\"{name}\"]\nsource = \"https://docs.example/guard\"\nchecked_on = \"2026-10-30\"\n"
        )
    };
    format!(
        "schema = 1\n\n{}\n{}",
        entry("acme-one", first),
        entry("acme-two", second)
    )
}

#[test]
fn the_parser_refuses_names_that_share_their_first_15_bytes() {
    // `comm` keeps 15 bytes, so these would both match one process.
    let (a, b) = ("acme-guard-daemon-a", "acme-guard-daemon-b");
    assert_eq!(a[..15], b[..15]);
    let message = refused(&two_entries(a, b));
    assert!(message.contains("same first 15 bytes"), "{message}");
    // A name that is itself the 15 byte cut of another collides too.
    assert!(refused(&two_entries(a, &a[..15])).contains("same first 15 bytes"));
    // Names that differ inside the first 15 bytes are fine.
    assert!(Catalog::parse(&two_entries(a, "acme-other-daemon")).is_ok());
}

#[test]
fn a_leap_day_is_a_date_and_other_february_29ths_are_not() {
    assert!(days("2028-02-29").is_some());
    assert!(days("2026-02-29").is_none());
    assert!(days("2100-02-29").is_none());
    assert!(days("2000-02-29").is_some());
}

#[test]
fn days_counts_from_the_epoch() {
    assert_eq!(days("1970-01-01"), Some(0));
    assert_eq!(days("1970-01-02"), Some(1));
    assert_eq!(days("2000-03-01"), Some(11_017));
    assert_eq!(
        days("2026-10-30")
            .zip(days("2026-10-29"))
            .map(|(a, b)| a - b),
        Some(1)
    );
}

#[test]
fn an_entry_is_stale_after_the_limit_and_not_before() {
    let catalog = Catalog::parse(GOOD).expect("it parses");
    // 2026-10-30 plus 180 days is 2027-04-28.
    assert!(catalog.stale("2027-04-28", 180).is_empty());
    assert_eq!(catalog.stale("2027-04-29", 180).len(), 1);
    // A `today` that is not a date finds nothing rather than flagging every entry.
    assert!(catalog.stale("yesterday", 180).is_empty());
}

#[test]
fn the_shipped_list_is_fresh_on_the_day_it_was_checked() {
    // Not a clock test: the date is fixed. The release workflow calls `stale` with the real date.
    assert!(shipped().stale("2026-10-30", 180).is_empty());
}

#[test]
fn the_shipped_file_has_no_dash_that_the_docs_lint_refuses() {
    assert!(!EMBEDDED.contains('\u{2014}'));
}
