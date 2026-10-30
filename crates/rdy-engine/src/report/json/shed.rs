//! Fitting the document under the cap (01 section 5.4 and 5.5). There are two stages.
//!
//! **Stage one sheds action log entries.** The action log is the part of a report that can be cut
//! without making it wrong: the facade has already kept the entries that matter in the order of its
//! tiers ([`crate::probe::Tier`]). The writer sheds in the same order, newest first inside a tier: `ok`
//! file calls, then `failed` ones, then every other entry. It sheds at least what is over 5000 entries,
//! and more only when the written bytes are over the cap. The size is measured on the final bytes after
//! the escapes, with the counters the shedding itself adds.
//!
//! A `denied` entry is a refused call: it is evidence that a spec asked for something it was not
//! allowed. It is never shed to make room. (Only the schema's 5000 entry cap can force one out, and the
//! facade's own log never holds more than that.)
//!
//! **Stage two clears measured values.** When the report is still over the cap with every entry that may
//! go shed, `observed` and `expected` are set to `null` on the checks that hold the most of them, largest
//! first, and each of those checks gets `truncated: true`. The verdict, the status, the message and the
//! fix of a check are never touched. Only if the report is still over the cap with every `observed` and
//! `expected` cleared is [`JsonError::TooLarge`] returned.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use rdy_spec::result::{Action, CheckResult, Report};

use super::bound::{MAX_ACTIONS, MAX_SMALL_MAP, fold_counts};
use super::{HtmlSafeJson, JsonError, MAX_REPORT_BYTES, escape_html, render};
use crate::probe::{Tier, dropped_calls, tier};

/// How many check keys the `TooLarge` message names.
const NAMED: usize = 3;

/// Writes `report`, shedding until it fits. `report` is already within the other caps.
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
    /// How many of `order` the size may shed: every entry but the `denied` ones, which come last.
    sheddable: usize,
    dropped: BTreeMap<String, u64>,
    truncated: bool,
    /// The results as they were, for stage two to clear a copy of.
    checks: Vec<CheckResult>,
    /// Indexes into `checks` of the results that hold `observed` or `expected`, largest first.
    clear_order: Vec<usize>,
    /// The keys of the largest results, for the message of `TooLarge`.
    largest: String,
}

/// What one render drops: the first `actions` entries in shedding order, and `observed` and `expected`
/// of the first `cleared` results in clearing order.
#[derive(Clone, Copy)]
struct Cut {
    actions: usize,
    cleared: usize,
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
        let sheddable = ranked
            .iter()
            .take_while(|(rank, _)| *rank < Tier::Denied as u8)
            .count();
        let checks = std::mem::take(&mut report.checks);
        let clear_order = clear_order(&checks);
        let largest = largest_keys(&checks);
        Self {
            dropped: report.actions_dropped.clone(),
            truncated: report.actions_truncated,
            order: ranked
                .into_iter()
                .map(|(_, Reverse(index))| index)
                .collect(),
            sheddable,
            actions,
            checks,
            clear_order,
            largest,
            report,
        }
    }

    /// The smallest cut, with at least `least` entries shed, that brings the bytes under the cap.
    fn fit(mut self, least: usize) -> Result<HtmlSafeJson, JsonError> {
        let first = self.render_cut(Cut {
            actions: least,
            cleared: 0,
        })?;
        if first.len() <= MAX_REPORT_BYTES {
            self.warn_if_last_resort(least);
            return Ok(first);
        }
        // Stage one. `all` is every entry but the `denied` ones. It is more than that only when the
        // schema's cap on the list forces `least` past it.
        let all = self.sheddable.max(least);
        let best = self.render_cut(Cut {
            actions: all,
            cleared: 0,
        })?;
        if best.len() <= MAX_REPORT_BYTES {
            // `least` was tried above and did not fit, so `all` is more than `least`.
            let (count, best) = self.narrow(least + 1, all, best, |actions| Cut {
                actions,
                cleared: 0,
            })?;
            self.warn_if_last_resort(count);
            return Ok(best);
        }
        // Stage two: every entry is shed, clear `observed` and `expected` largest first.
        let every = self.clear_order.len();
        let best = self.render_cut(Cut {
            actions: all,
            cleared: every,
        })?;
        if best.len() > MAX_REPORT_BYTES {
            return Err(JsonError::TooLarge {
                bytes: best.len(),
                max: MAX_REPORT_BYTES,
                largest: self.largest.clone(),
            });
        }
        let (_, best) = self.narrow(1, every, best, |cleared| Cut {
            actions: all,
            cleared,
        })?;
        self.warn_if_last_resort(all);
        Ok(best)
    }

    /// Finds the smallest `n` in `lo..=hi` whose cut fits, given that `hi` fits and `best` is its
    /// render. It assumes a bigger `n` is never bigger in bytes: each step removes a whole entry or a
    /// whole value and adds at most one counter. If that ever failed, `hi` still fits at every step, so
    /// the cap holds and only the minimum is lost.
    fn narrow(
        &mut self,
        lo: usize,
        hi: usize,
        best: HtmlSafeJson,
        cut: impl Fn(usize) -> Cut,
    ) -> Result<(usize, HtmlSafeJson), JsonError> {
        let (mut lo, mut hi, mut best) = (lo, hi, best);
        // The answer is in `lo..=hi`. `hi` always fits and `best` is its render, so `mid < hi` is a
        // count that was not tried yet.
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let json = self.render_cut(cut(mid))?;
            if json.len() <= MAX_REPORT_BYTES {
                hi = mid;
                best = json;
            } else {
                lo = mid + 1;
            }
        }
        Ok((hi, best))
    }

    /// Renders the report without the first `cut.actions` entries in shedding order, and with the first
    /// `cut.cleared` results of the clearing order stripped of `observed` and `expected`.
    fn render_cut(&mut self, cut: Cut) -> Result<HtmlSafeJson, JsonError> {
        let mut gone = vec![false; self.actions.len()];
        let mut dropped = self.dropped.clone();
        for &index in self.order.iter().take(cut.actions) {
            if let Some(flag) = gone.get_mut(index) {
                *flag = true;
            }
            if let Some(action) = self.actions.get(index) {
                let (kind, calls) = dropped_calls(action);
                *dropped.entry(kind).or_insert(0) += calls;
            }
        }
        fold_counts(&mut dropped, MAX_SMALL_MAP);
        self.report.actions = self
            .actions
            .iter()
            .zip(&gone)
            .filter(|(_, gone)| !**gone)
            .map(|(action, _)| action.clone())
            .collect();
        self.report.actions_dropped = dropped;
        self.report.actions_truncated = self.truncated || cut.actions > 0;
        self.report.checks = self.checks.clone();
        for &index in self.clear_order.iter().take(cut.cleared) {
            if let Some(check) = self.report.checks.get_mut(index) {
                check.observed = None;
                check.expected = None;
                check.truncated = true;
            }
        }
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

/// The size of `observed` and `expected` of a result, escaped as they are written.
fn free_form_len(check: &CheckResult) -> usize {
    [&check.observed, &check.expected]
        .into_iter()
        .flatten()
        .filter_map(|map| serde_json::to_string(map).ok())
        .map(|text| escape_html(&text).len())
        .sum()
}

/// Indexes of the results that hold `observed` or `expected`, the largest first (the first index wins a
/// tie, so the order is the same on every run).
fn clear_order(checks: &[CheckResult]) -> Vec<usize> {
    let mut ranked: Vec<(Reverse<usize>, usize)> = checks
        .iter()
        .enumerate()
        .filter(|(_, check)| check.observed.is_some() || check.expected.is_some())
        .map(|(index, check)| (Reverse(free_form_len(check)), index))
        .collect();
    ranked.sort_unstable();
    ranked.into_iter().map(|(_, index)| index).collect()
}

/// The keys of the results that weigh the most as written, for the message of `TooLarge`. A key is a
/// check id the spec declared, not a measured value.
fn largest_keys(checks: &[CheckResult]) -> String {
    let mut ranked: Vec<(Reverse<usize>, usize)> = checks
        .iter()
        .enumerate()
        .map(|(index, check)| {
            let size = serde_json::to_string(check).map_or(0, |text| escape_html(&text).len());
            (Reverse(size), index)
        })
        .collect();
    ranked.sort_unstable();
    let keys: Vec<&str> = ranked
        .iter()
        .take(NAMED)
        .filter_map(|(_, index)| checks.get(*index))
        .map(|check| check.key.as_str())
        .collect();
    keys.join(", ")
}
