//! `cargo xtask agents-stale`: fails when an entry of the security-software catalog was last checked more
//! than 180 days ago (docs/plan/03-check-catalog.md Appendix B, M1-173).
//!
//! The release workflow runs it (`check-release-artifacts.yml`), not the pull request workflow. A date
//! limit in the pull request workflow would turn every pull request red on day 181. A release is the
//! moment someone must have read each vendor page again.
//!
//! The command reads the catalog that the `rdy-checks-host` crate embeds, which is the file the binary
//! ships. The workflow passes `--today`, so a test can pin the day.

use anyhow::{Result, anyhow};
use rdy_checks_host::agents::{catalog, parse_date};

/// How old a `checked_on` date may be at release time, in days.
pub const MAX_AGE_DAYS: i64 = 180;

/// Reads `--today`. A value that is not a real `YYYY-MM-DD` date is a usage error (exit 64), because
/// `Catalog::stale` finds nothing for a bad date and the gate would pass.
pub fn parse_today(text: &str) -> Result<String, String> {
    if parse_date(text).is_some() {
        Ok(text.to_owned())
    } else {
        Err(format!(
            "`{text}` is not a date. Pass YYYY-MM-DD, for example `--today \"$(date -u +%F)\"`"
        ))
    }
}

/// Checks the shipped catalog. `today` is `YYYY-MM-DD`. Returns `Ok(true)` when no entry is stale.
pub fn run(today: &str, max_days: i64) -> Result<bool> {
    let catalog =
        catalog().map_err(|err| anyhow!("the shipped agents.toml does not parse: {err}"))?;
    if catalog.agents().is_empty() {
        return Err(anyhow!(
            "the shipped agents.toml has no entries. Restore crates/rdy-checks-host/data/agents.toml."
        ));
    }
    let stale = catalog.stale(today, max_days);
    if stale.is_empty() {
        eprintln!(
            "agents-stale: {} catalog entries, none checked more than {max_days} days before {today}.",
            catalog.agents().len()
        );
        return Ok(true);
    }
    for agent in &stale {
        eprintln!(
            "agents-stale: {} was checked on {}, more than {max_days} days before {today}. Read {} again, fix the process names if they changed, and set checked_on in crates/rdy-checks-host/data/agents.toml.",
            agent.id, agent.checked_on, agent.source
        );
    }
    eprintln!(
        "agents-stale: {} stale entr{}. The release stops here. Review each entry and re-date it, then tag again.",
        stale.len(),
        if stale.len() == 1 { "y" } else { "ies" }
    );
    Ok(false)
}
