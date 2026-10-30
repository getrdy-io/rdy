//! Fitting the document under the cap by shedding action log entries (01 section 5.4 and 5.5).
//!
//! The action log is the only part of a report that can be cut without making it wrong: results are
//! never cut, and the facade has already kept the entries that matter in the order of its tiers
//! ([`crate::probe::Tier`]). The writer sheds in the same order, newest first inside a tier:
//! `ok` file calls, then `failed` ones, then every other entry, and `denied` entries last. It sheds at
//! least what is over 5000 entries, and more only when the written bytes are over the cap. The size is
//! measured on the final bytes after the escapes, with the counters the shedding itself adds.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use rdy_spec::result::{Action, Report};

use super::bound::{MAX_ACTIONS, MAX_SMALL_MAP, cap_keys};
use super::{HtmlSafeJson, JsonError, MAX_REPORT_BYTES, render};
use crate::probe::{Tier, dropped_calls, tier};

/// Writes `report`, shedding action entries until it fits. `report` is already within the other caps.
pub(super) fn fit(report: Report) -> Result<HtmlSafeJson, JsonError> {
    let over_count = report.actions.len().saturating_sub(MAX_ACTIONS);
    if over_count == 0 {
        let json = render(&report)?;
        if json.len() <= MAX_REPORT_BYTES {
            return Ok(json);
        }
    }
    Shedder::new(report).fit(over_count)
}

struct Shedder {
    report: Report,
    /// Every entry the report started with, in order.
    actions: Vec<Action>,
    /// Indexes into `actions`, in the order they go.
    order: Vec<usize>,
    dropped: BTreeMap<String, u64>,
    truncated: bool,
}

impl Shedder {
    fn new(mut report: Report) -> Self {
        let actions = std::mem::take(&mut report.actions);
        let mut ranked: Vec<(u8, Reverse<usize>)> = actions
            .iter()
            .enumerate()
            .map(|(index, action)| (tier(action) as u8, Reverse(index)))
            .collect();
        ranked.sort_unstable();
        Self {
            dropped: report.actions_dropped.clone(),
            truncated: report.actions_truncated,
            order: ranked
                .into_iter()
                .map(|(_, Reverse(index))| index)
                .collect(),
            actions,
            report,
        }
    }

    /// The smallest number of entries to shed, at least `least`, that brings the bytes under the cap.
    fn fit(mut self, least: usize) -> Result<HtmlSafeJson, JsonError> {
        let all = self.order.len();
        let first = self.render_without(least)?;
        if first.len() <= MAX_REPORT_BYTES {
            self.warn_if_last_resort(least);
            return Ok(first);
        }
        let mut best = self.render_without(all)?;
        if best.len() > MAX_REPORT_BYTES {
            return Err(JsonError::TooLarge {
                bytes: best.len(),
                max: MAX_REPORT_BYTES,
            });
        }
        // `best` fits and `lo` does not. Narrow until they meet.
        let (mut lo, mut hi) = (least, all);
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            let json = self.render_without(mid)?;
            if json.len() <= MAX_REPORT_BYTES {
                hi = mid;
                best = json;
            } else {
                lo = mid;
            }
        }
        self.warn_if_last_resort(hi);
        Ok(best)
    }

    /// Renders the report without its first `count` entries in shedding order.
    fn render_without(&mut self, count: usize) -> Result<HtmlSafeJson, JsonError> {
        let mut gone = vec![false; self.actions.len()];
        let mut dropped = self.dropped.clone();
        for &index in self.order.iter().take(count) {
            if let Some(flag) = gone.get_mut(index) {
                *flag = true;
            }
            if let Some(action) = self.actions.get(index) {
                let (kind, calls) = dropped_calls(action);
                *dropped.entry(kind).or_insert(0) += calls;
            }
        }
        cap_keys(&mut dropped, MAX_SMALL_MAP);
        self.report.actions = self
            .actions
            .iter()
            .zip(&gone)
            .filter(|(_, gone)| !**gone)
            .map(|(action, _)| action.clone())
            .collect();
        self.report.actions_dropped = dropped;
        self.report.actions_truncated = self.truncated || count > 0;
        render(&self.report)
    }

    /// A tracing warning when shedding reached an entry that retention keeps to the end. It carries
    /// counts only.
    fn warn_if_last_resort(&self, count: usize) {
        let spare = self
            .order
            .iter()
            .take(count)
            .filter(|&&index| {
                self.actions
                    .get(index)
                    .is_some_and(|action| tier(action) as u8 >= Tier::Spare as u8)
            })
            .count();
        if spare > 0 {
            tracing::warn!(
                shed = count,
                kept_tier_shed = spare,
                "the report was over its size cap and the writer shed action entries that retention keeps"
            );
        }
    }
}
