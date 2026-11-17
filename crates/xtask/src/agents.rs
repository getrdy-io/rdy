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
use rdy_checks_host::agents::catalog;

/// How old a `checked_on` date may be at release time, in days.
pub const MAX_AGE_DAYS: i64 = 180;

/// Checks the shipped catalog. `today` is `YYYY-MM-DD`. Returns `Ok(true)` when no entry is stale.
pub fn run(today: &str, max_days: i64) -> Result<bool> {
    let catalog =
        catalog().map_err(|err| anyhow!("the shipped agents.toml does not parse: {err}"))?;
    if catalog.agents().is_empty() {
        return Err(anyhow!(
            "the shipped agents.toml has no entries. Restore crates/rdy-checks-host/data/agents.toml."
        ));
    }
    // `Catalog::stale` gives no entries for a `today` that is not a date. A gate that passes on a typo
    // is no gate, so ask it for every entry first: an empty answer from a non-empty catalog means the
    // date was not read.
    if catalog.stale(today, i64::MIN).is_empty() {
        return Err(anyhow!(
            "`{today}` is not a date. Pass --today as YYYY-MM-DD, for example `--today \"$(date -u +%F)\"`."
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
