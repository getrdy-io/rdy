//! `cargo xtask checks`: lists every registered check and validates its `CheckMeta` (ADR 0026).
//!
//! The list goes to stdout, one tab-separated row per check: id, family, title and remediation. The
//! rows follow the registry's families in registration order and each family's checks in catalog
//! order, which is the order the docs pages use (docs/plan/09-docs-site.md, section 6).
//!
//! A title or remediation that is blank or holds a control character is a problem. So is a check other
//! than `host.ports` that lists `FD_WALK` in `reads`: only the port check may walk the fd directory of
//! another process (ADR 0040). Each problem goes to stderr with the check id, and the command exits 1.
//! `cargo xtask docs-lint` runs the same validation.

use anyhow::{Result, anyhow};
use rdy_engine::check::{CheckInfo, FD_WALK};
use rdy_engine::family::Registry;

/// The one check that may declare the fd walk (ADR 0040).
const FD_WALK_CHECK: &str = "host.ports";

/// The header row of the listing.
const HEADER: &str = "id\tfamily\ttitle\tremediation";

/// The families of this build: the list `rdy run` plans against (`rdy_cli::registry`, ADR 0026 decision
/// 5), so the docs and the binary read one registry.
pub fn registry() -> Result<Registry> {
    rdy_cli::registry::registry().map_err(|err| anyhow!("cannot build the check registry: {err}"))
}

/// Every registered check, families in registration order and checks in catalog order.
pub fn ordered(registry: &Registry) -> Vec<&'static CheckInfo> {
    registry
        .families()
        .flat_map(|family| family.checks().iter().copied())
        .collect()
}

/// The listing: a header row, then one tab-separated row per check.
pub fn render(infos: &[&CheckInfo]) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    for info in infos {
        let row = [info.id, info.family, info.meta.title, info.meta.remediation].join("\t");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// What is wrong with the `CheckMeta` and the declared `reads` of each check, one line per problem,
/// each naming the check.
pub fn problems(infos: &[&CheckInfo]) -> Vec<String> {
    let mut found = Vec::new();
    for info in infos {
        if info.id != FD_WALK_CHECK && info.reads.contains(&FD_WALK) {
            found.push(format!(
                "check {} lists the fd walk ({FD_WALK}) in its reads. Only {FD_WALK_CHECK} may. Remove it.",
                info.id
            ));
        }
        for (field, text) in [
            ("title", info.meta.title),
            ("remediation", info.meta.remediation),
        ] {
            if text.trim().is_empty() {
                found.push(format!(
                    "check {} has an empty {field}. Write one in its CheckMeta.",
                    info.id
                ));
            } else if text.chars().any(char::is_control) {
                found.push(format!(
                    "check {} has a control character (a tab or a line break, for example) in its {field}. Keep it to one line of plain text.",
                    info.id
                ));
            }
        }
    }
    found
}

/// Prints each problem to stderr. Returns `true` when there is none.
pub fn report(infos: &[&CheckInfo]) -> bool {
    let found = problems(infos);
    for problem in &found {
        eprintln!("{problem}");
    }
    found.is_empty()
}

/// Runs `cargo xtask checks`. Returns `true` when every check's metadata is valid.
pub fn run() -> Result<bool> {
    let registry = registry()?;
    let infos = ordered(&registry);
    print!("{}", render(&infos));
    let passed = report(&infos);
    if passed {
        eprintln!(
            "checks: {} registered check(s), each with a title and a remediation.",
            infos.len()
        );
    } else {
        eprintln!("checks: fix each check named above.");
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdy_engine::check::{CheckMeta, OsSupport, Support};

    use super::*;

    const fn fake(id: &'static str, title: &'static str, remediation: &'static str) -> CheckInfo {
        CheckInfo {
            id,
            family: "host",
            summary: "A fake check.",
            meta: CheckMeta { title, remediation },
            needs: &[],
            wants: &[],
            default_timeout: Some(Duration::from_secs(1)),
            os: OsSupport {
                linux: Support::Full,
                macos: Support::Full,
                windows: Support::Full,
            },
            reads: &[],
            statfs: &[],
            env: &[],
            commands: &[],
            peers: &[],
        }
    }

    static GOOD: CheckInfo = fake("host.good", "Good", "Do the thing.");
    static NO_REMEDIATION: CheckInfo = fake("host.bare", "Bare", "");
    static BLANK_REMEDIATION: CheckInfo = fake("host.blank", "Blank", "  ");
    static NO_TITLE: CheckInfo = fake("host.untitled", "", "Do the thing.");
    static TWO_LINES: CheckInfo = fake("host.wrapped", "Wrapped", "Do this.\nThen that.");

    static WALKS: CheckInfo = CheckInfo {
        reads: &[FD_WALK],
        ..fake("host.nosy", "Nosy", "Do the thing.")
    };
    static PORTS: CheckInfo = CheckInfo {
        reads: &["/proc/net", FD_WALK],
        ..fake("host.ports", "Ports", "Do the thing.")
    };

    #[test]
    fn only_the_port_check_may_declare_the_fd_walk() {
        assert!(problems(&[&PORTS]).is_empty());
        assert_eq!(
            problems(&[&WALKS]),
            [
                "check host.nosy lists the fd walk (/proc/<pid>/fd) in its reads. Only host.ports may. Remove it."
            ]
        );
    }

    #[test]
    fn a_valid_check_has_no_problem() {
        assert!(problems(&[&GOOD]).is_empty());
    }

    #[test]
    fn an_empty_or_blank_remediation_fails_and_names_the_check() {
        let found = problems(&[&GOOD, &NO_REMEDIATION, &BLANK_REMEDIATION]);
        assert_eq!(
            found,
            [
                "check host.bare has an empty remediation. Write one in its CheckMeta.",
                "check host.blank has an empty remediation. Write one in its CheckMeta.",
            ]
        );
        assert!(!report(&[&NO_REMEDIATION]));
    }

    #[test]
    fn an_empty_title_fails() {
        let found = problems(&[&NO_TITLE]);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("host.untitled has an empty title"));
    }

    #[test]
    fn a_line_break_fails_because_each_check_is_one_row() {
        let found = problems(&[&TWO_LINES]);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("host.wrapped has a control character"));
    }

    #[test]
    fn the_listing_has_one_row_per_check_with_id_family_title_and_remediation() {
        assert_eq!(
            render(&[&GOOD, &NO_TITLE]),
            "id\tfamily\ttitle\tremediation\n\
             host.good\thost\tGood\tDo the thing.\n\
             host.untitled\thost\t\tDo the thing.\n"
        );
    }

    #[test]
    fn every_check_of_this_build_has_valid_metadata() {
        let registry = registry().expect("the registry builds");
        let infos = ordered(&registry);
        assert_eq!(problems(&infos), Vec::<String>::new());
        assert_eq!(
            infos.len(),
            registry.infos().count(),
            "every registered check is listed once"
        );
    }
}
