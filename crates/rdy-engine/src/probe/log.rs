//! The action log: one entry for every side effect the facade performs (01 section 5.4, 02).
//!
//! The facade writes every entry. A check cannot skip it, because a check has no other way to read a
//! file or start a command. An entry is opened before the work starts ([`ActionLog::begin`] reserves its
//! `seq`) and closed when the work ends. A [`Pending`] that is dropped without being closed, which is
//! what happens when the scheduler aborts a check at its timeout, is recorded as `timeout`.
//!
//! **Redaction.** Every string in an entry passes the [`Redactor`] when the entry is closed, and the
//! log counts what each rule did. [`ActionLogOutput::apply`] adds those counts to a report's
//! `redaction` summary. Paths under the home directory start with `~`. In `argv`, an element that
//! follows a secret flag is redacted too: `["--password", "hunter2"]` leaks nothing, not only
//! `["--password=hunter2"]`.
//!
//! **Retention.** Three limits keep the log bounded and the entries that matter in it.
//!
//! - *Coalescing.* A `denied` or `failed` `read`, `read_dir` or `stat` is written as it happens, up to
//!   [`COALESCE_AFTER`] times for one (check, kind, rule or error, parent directory). The calls after
//!   that fold into one `coalesced` entry that carries a `count`. It takes the `seq` of the first call
//!   it folded, and the folded calls leave a gap in `seq`. The limit is per key, so a flood of failures
//!   under one directory costs 21 entries, and a denied call is still in the log.
//! - *Quota.* A check may hold [`CHECK_QUOTA`] entries, and the log [`MAX_ENTRIES`]. At either limit
//!   the log drops, in this order: a new `ok` `read`, `read_dir` or `stat` (the oldest are kept), then
//!   `ok` ones already held, then `failed` ones (`read`, `read_dir`, `stat` and `coalesced`).
//!   `actions_dropped` counts them by kind.
//! - *Last resort.* A `denied` entry is never dropped to make room for anything else. When the limit is
//!   reached and nothing above can go, the log drops the newest other kept entry (`exec`, `connect`,
//!   `tls`, `http`, `kube`, a timed out read), and only if there is none the new entry. Each of these is
//!   counted in [`ActionLogOutput::last_resort_drops`] and warned about with `tracing`. The volume of
//!   those kinds is bounded by the spec (hosts, ports) and by the fixed command set, so it should not
//!   happen.
//!
//! Size-based truncation of the whole document (2 MiB) and the coalescing of `ok` reads past 200 per
//! directory belong to the report writer and to M1-041.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rdy_spec::result::{Action, ActionKind, ActionOutcome, Report};
use serde_json::{Map, Value};

use crate::redact::{Redactor, RuleCounts};

/// The most entries a report carries. The result schema allows 5000 (01 section 5.4).
pub const MAX_ENTRIES: usize = 5000;

/// The most entries one check may hold.
pub const CHECK_QUOTA: usize = 1000;

/// How many `denied` or `failed` file calls for one key are written one by one before they fold.
pub const COALESCE_AFTER: usize = 20;

/// The most distinct coalescing keys the log tracks. Past it a new key is not folded, only subject to
/// the quotas, so memory stays bounded.
const MAX_COALESCE_KEYS: usize = 20_000;

/// The limits of one log.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) max_entries: usize,
    pub(crate) check_quota: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            check_quota: CHECK_QUOTA,
        }
    }
}

/// The action log of one run, shared by every probe handle.
#[derive(Clone)]
pub(crate) struct ActionLog {
    shared: Arc<Shared>,
}

struct Shared {
    origin: Instant,
    home: Option<PathBuf>,
    redactor: Redactor,
    limits: Limits,
    state: Mutex<State>,
}

/// How retention ranks an entry. The lower the number, the sooner it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// `ok` `read`, `read_dir` and `stat`.
    Ok = 0,
    /// `failed` `read`, `read_dir`, `stat` and `coalesced`.
    Failed = 1,
    /// Everything else that is not `denied`. Only a last resort drops it.
    Spare = 2,
    /// `denied`, including a `coalesced` one. Never dropped to make room.
    Denied = 3,
}

/// The entries of one scope (the whole log, or one check) by tier.
#[derive(Default)]
struct Tiers {
    sets: [BTreeSet<u64>; 3],
}

impl Tiers {
    fn insert(&mut self, tier: Tier, seq: u64) {
        if let Some(set) = self.sets.get_mut(tier as usize) {
            set.insert(seq);
        }
    }

    fn remove(&mut self, tier: Tier, seq: u64) {
        if let Some(set) = self.sets.get_mut(tier as usize) {
            set.remove(&seq);
        }
    }

    /// The newest entry of the lowest tier up to `up_to`, as `(tier, seq)`.
    fn victim(&self, up_to: Tier) -> Option<(Tier, u64)> {
        [Tier::Ok, Tier::Failed, Tier::Spare]
            .into_iter()
            .take_while(|tier| *tier as usize <= up_to as usize)
            .find_map(|tier| {
                self.sets
                    .get(tier as usize)
                    .and_then(|set| set.last())
                    .map(|seq| (tier, *seq))
            })
    }
}

#[derive(Default)]
struct CheckSlots {
    count: usize,
    tiers: Tiers,
}

/// What identifies a run of similar failed or denied file calls.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FoldKey {
    check: Option<String>,
    kind: String,
    denied: bool,
    reason: String,
    dir: String,
}

#[derive(Default)]
struct Folded {
    /// Calls seen for this key, written or folded.
    seen: usize,
    /// The `seq` of the `coalesced` entry, once there is one.
    entry: Option<u64>,
}

#[derive(Default)]
struct State {
    next_seq: u64,
    entries: BTreeMap<u64, Action>,
    all: Tiers,
    checks: HashMap<Option<String>, CheckSlots>,
    folds: HashMap<FoldKey, Folded>,
    dropped: BTreeMap<String, u64>,
    truncated: bool,
    last_resort: u64,
    counts: RuleCounts,
}

/// What the log holds at one moment, ready to go into a report.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ActionLogOutput {
    /// The entries, in `seq` order. A gap in `seq` is a dropped or folded entry.
    pub actions: Vec<Action>,
    /// `true` when retention dropped anything.
    pub truncated: bool,
    /// How many entries of each kind retention dropped.
    pub dropped: BTreeMap<String, u64>,
    /// How many entries the last resort rule dropped. It is already in `dropped`; a nonzero value
    /// here is a bug in a check or a spec far outside the limits.
    pub last_resort_drops: u64,
    /// What the redactor did to the log's strings. Counts only, never matched text.
    pub redaction: RuleCounts,
}

impl ActionLogOutput {
    /// Puts the log into `report`: the entries, the truncation fields, and the redaction counts added
    /// to the report's `redaction` summary.
    pub fn apply(self, report: &mut Report) {
        report.actions = self.actions;
        report.actions_truncated = self.truncated;
        report.actions_dropped = self.dropped;
        report.redaction.total += self.redaction.total();
        for (rule, count) in self.redaction.iter() {
            *report.redaction.by_rule.entry(rule.to_owned()).or_insert(0) += count;
        }
    }
}

impl ActionLog {
    /// An empty log. `home` is the directory that paths are shown relative to, as `~`.
    pub(crate) fn new(redactor: Redactor, home: Option<PathBuf>, limits: Limits) -> Self {
        Self {
            shared: Arc::new(Shared {
                origin: Instant::now(),
                home,
                redactor,
                limits,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// The redactor this log uses.
    pub(crate) fn redactor(&self) -> &Redactor {
        &self.shared.redactor
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A panic while the lock was held cannot leave the maps half updated in a way that matters:
        // every update is one insert or remove. Keep logging.
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Poisons the lock, to test that logging goes on.
    #[cfg(test)]
    pub(super) fn poison(&self) {
        let log = self.clone();
        let joined = std::thread::spawn(move || {
            let _guard = log.state();
            panic!("a thread died holding the action log");
        })
        .join();
        assert!(joined.is_err());
    }

    /// Opens an entry for `kind`. It is closed with [`Pending::finish`], or recorded as `timeout` when
    /// it is dropped first.
    pub(crate) fn begin(
        &self,
        check: Option<&str>,
        kind: ActionKind,
        fields: Map<String, Value>,
    ) -> Pending {
        let seq = {
            let mut state = self.state();
            state.next_seq += 1;
            state.next_seq
        };
        Pending {
            log: self.clone(),
            seq,
            check: check.map(str::to_owned),
            kind,
            fields,
            started: Instant::now(),
            closed: false,
        }
    }

    /// The path as the log shows it: `~/rest` under the home directory, else as given. Use it for every
    /// path that can reach a message, so a home directory name never leaves through an error.
    pub(crate) fn display_path(&self, path: &Path) -> String {
        if let Some(home) = &self.shared.home
            && let Ok(rest) = path.strip_prefix(home)
        {
            return if rest.as_os_str().is_empty() {
                "~".to_owned()
            } else {
                format!("~/{}", rest.to_string_lossy())
            };
        }
        path.to_string_lossy().into_owned()
    }

    /// A copy of the log as it is now.
    pub(crate) fn snapshot(&self) -> ActionLogOutput {
        let state = self.state();
        ActionLogOutput {
            actions: state.entries.values().cloned().collect(),
            truncated: state.truncated,
            dropped: state.dropped.clone(),
            last_resort_drops: state.last_resort,
            redaction: state.counts.clone(),
        }
    }

    fn close(&self, pending: &mut Pending, outcome: ActionOutcome) {
        let shared = &self.shared;
        let at = pending.started.saturating_duration_since(shared.origin);
        let took = pending.started.elapsed();
        let mut action = Action::new(
            pending.seq,
            pending.check.take(),
            millis(at),
            millis(took),
            pending.kind.clone(),
            outcome,
        );
        action.fields = std::mem::take(&mut pending.fields);

        let mut state = self.state();
        let State { counts, .. } = &mut *state;
        for (name, value) in &mut action.fields {
            if name == "argv" {
                redact_argv(&shared.redactor, value, counts);
            } else {
                redact_value(&shared.redactor, value, counts);
            }
        }
        // A check key is spec text (`id/name`), so it is redacted too.
        if let Some(check) = action.check.take() {
            action.check = Some(
                shared
                    .redactor
                    .redact_str_counted(&check, counts)
                    .to_string(),
            );
        }
        record(&mut state, action, shared.limits);
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn redact_value(redactor: &Redactor, value: &mut Value, counts: &mut RuleCounts) {
    match value {
        Value::String(text) => *text = redactor.redact_str_counted(text, counts).to_string(),
        Value::Array(items) => {
            for item in items {
                redact_value(redactor, item, counts);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                redact_value(redactor, item, counts);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Redacts an argv. Each element passes the redactor on its own, and the element after a secret flag
/// is redacted as that flag's value: `--password hunter2` is two elements and the second is the secret.
fn redact_argv(redactor: &Redactor, value: &mut Value, counts: &mut RuleCounts) {
    let Value::Array(items) = value else {
        redact_value(redactor, value, counts);
        return;
    };
    // Flags are read from the original text: a value that was just redacted must not stop the element
    // after it from being seen as the value of a flag of its own.
    let original: Vec<Option<String>> = items
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect();
    for index in 0..items.len() {
        if let Some(Some(flag)) = original.get(index)
            && flag.starts_with('-')
            && !flag.contains('=')
            && is_secret_flag(redactor, flag)
            && let Some(Some(text)) = original.get(index + 1)
            && let Some(next) = items.get_mut(index + 1)
        {
            let prefix = format!("{flag}=");
            let joined = format!("{prefix}{text}");
            let redacted = redactor.redact_str_counted(&joined, counts).to_string();
            let kept = redacted.strip_prefix(&prefix).unwrap_or(&redacted);
            *next = Value::String(kept.to_owned());
        }
        if let Some(item) = items.get_mut(index) {
            redact_value(redactor, item, counts);
        }
    }
}

/// Whether the redactor treats `flag=<value>` as a secret assignment. It asks with a throwaway value,
/// so the rule table stays the one source of truth for which names are secret.
fn is_secret_flag(redactor: &Redactor, flag: &str) -> bool {
    let probe = format!("{flag}=probe-value-7f3a1c");
    redactor.redact_str(&probe).to_string() != probe
}

/// How retention ranks an entry.
fn tier(action: &Action) -> Tier {
    let files = matches!(
        action.kind,
        ActionKind::Read | ActionKind::ReadDir | ActionKind::Stat | ActionKind::Coalesced
    );
    match action.outcome {
        ActionOutcome::Denied => Tier::Denied,
        ActionOutcome::Ok if files && action.kind != ActionKind::Coalesced => Tier::Ok,
        ActionOutcome::Failed if files => Tier::Failed,
        _ => Tier::Spare,
    }
}

/// The key a `denied` or `failed` file call folds under, or `None` for any other entry.
fn fold_key(action: &Action) -> Option<FoldKey> {
    if !matches!(
        action.kind,
        ActionKind::Read | ActionKind::ReadDir | ActionKind::Stat
    ) {
        return None;
    }
    let (denied, reason_field) = match action.outcome {
        ActionOutcome::Denied => (true, "rule"),
        ActionOutcome::Failed => (false, "error"),
        _ => return None,
    };
    let text = |name: &str| {
        action
            .fields
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let path = text("path");
    let dir = path
        .rsplit_once('/')
        .map_or(String::new(), |(dir, _)| dir.to_owned());
    Some(FoldKey {
        check: action.check.clone(),
        kind: action.kind.as_str().to_owned(),
        denied,
        reason: text(reason_field),
        dir,
    })
}

/// The `coalesced` entry that stands for `first` and the calls after it.
fn folded_entry(key: &FoldKey, first: &Action) -> Action {
    let mut entry = Action::new(
        first.seq,
        first.check.clone(),
        first.at_ms,
        0,
        ActionKind::Coalesced,
        first.outcome.clone(),
    );
    entry
        .fields
        .insert("of".to_owned(), key.kind.clone().into());
    entry
        .fields
        .insert("under".to_owned(), key.dir.clone().into());
    let reason = if key.denied { "rule" } else { "error" };
    entry
        .fields
        .insert(reason.to_owned(), key.reason.clone().into());
    entry.fields.insert("count".to_owned(), 1.into());
    entry
}

/// Adds a closed entry to the log: folds it if it repeats, then places it under the limits.
fn record(state: &mut State, action: Action, limits: Limits) {
    let Some(key) = fold_key(&action) else {
        place(state, action, limits);
        return;
    };
    if !state.folds.contains_key(&key) && state.folds.len() >= MAX_COALESCE_KEYS {
        place(state, action, limits);
        return;
    }
    let slot = state.folds.entry(key.clone()).or_default();
    slot.seen += 1;
    if slot.seen <= COALESCE_AFTER {
        place(state, action, limits);
        return;
    }
    // Past the limit: add to the coalesced entry, or start one if it is gone (dropped by retention).
    let existing = slot.entry;
    if let Some(entry) = existing.and_then(|seq| state.entries.get_mut(&seq)) {
        let count = entry
            .fields
            .get("count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        entry
            .fields
            .insert("count".to_owned(), count.saturating_add(1).into());
        return;
    }
    let entry = folded_entry(&key, &action);
    if let Some(slot) = state.folds.get_mut(&key) {
        slot.entry = Some(entry.seq);
    }
    place(state, entry, limits);
}

fn count_drop(state: &mut State, kind: &ActionKind) {
    *state.dropped.entry(kind.as_str().to_owned()).or_insert(0) += 1;
    state.truncated = true;
}

/// Records a drop that the order of tiers did not allow for, and warns.
fn count_last_resort(state: &mut State, kind: &ActionKind) {
    state.last_resort += 1;
    // The first one, then every thousandth, so a runaway check does not flood the log.
    if state.last_resort == 1 || state.last_resort.is_multiple_of(1000) {
        tracing::warn!(
            kind = kind.as_str(),
            total = state.last_resort,
            "the action log was full and dropped an entry it should keep"
        );
    }
}

/// Removes entry `seq` from every index and counts it as dropped.
fn evict(state: &mut State, seq: u64, tier: Tier) {
    let Some(removed) = state.entries.remove(&seq) else {
        return;
    };
    state.all.remove(tier, seq);
    if let Some(slots) = state.checks.get_mut(&removed.check) {
        slots.count = slots.count.saturating_sub(1);
        slots.tiers.remove(tier, seq);
    }
    count_drop(state, &removed.kind);
    if tier == Tier::Spare {
        count_last_resort(state, &removed.kind);
    }
}

/// Which scope of the log is full.
#[derive(Clone, Copy)]
enum Scope<'a> {
    /// The whole log.
    Log,
    /// One check's share.
    Check(&'a Option<String>),
}

/// Frees one slot in `scope` for an entry of `incoming` tier. `false` means the new entry itself is
/// the one to drop. Nothing here ever drops a `Denied` entry that is already held.
fn make_room(state: &mut State, scope: Scope<'_>, incoming: Tier) -> bool {
    let victim = match (scope, incoming) {
        // A new `ok` file entry never displaces an older one: the early evidence stays.
        (_, Tier::Ok) => return false,
        // A new `failed` entry may displace an `ok` one, nothing else.
        (Scope::Log, Tier::Failed) => state.all.victim(Tier::Ok),
        (Scope::Check(check), Tier::Failed) => state
            .checks
            .get(check)
            .and_then(|slots| slots.tiers.victim(Tier::Ok)),
        // Anything else displaces `ok`, then `failed`, then (last resort) a spare entry.
        (Scope::Log, Tier::Spare | Tier::Denied) => state.all.victim(if incoming == Tier::Denied {
            Tier::Spare
        } else {
            Tier::Failed
        }),
        (Scope::Check(check), Tier::Spare | Tier::Denied) => {
            state.checks.get(check).and_then(|slots| {
                slots.tiers.victim(if incoming == Tier::Denied {
                    Tier::Spare
                } else {
                    Tier::Failed
                })
            })
        }
    };
    match victim {
        Some((tier, seq)) => {
            evict(state, seq, tier);
            true
        }
        None => false,
    }
}

/// Puts an entry in the log, making room under the limits first.
fn place(state: &mut State, action: Action, limits: Limits) {
    let tier = tier(&action);
    let check = action.check.clone();
    let held = state.checks.get(&check).map_or(0, |slots| slots.count);
    let full = (held >= limits.check_quota && !make_room(state, Scope::Check(&check), tier))
        || (state.entries.len() >= limits.max_entries && !make_room(state, Scope::Log, tier));
    if full {
        count_drop(state, &action.kind);
        if matches!(tier, Tier::Spare | Tier::Denied) {
            count_last_resort(state, &action.kind);
        }
        return;
    }
    let seq = action.seq;
    if tier != Tier::Denied {
        state.all.insert(tier, seq);
    }
    let slots = state.checks.entry(check).or_default();
    slots.count += 1;
    if tier != Tier::Denied {
        slots.tiers.insert(tier, seq);
    }
    state.entries.insert(seq, action);
}

/// An entry that has been opened and not yet closed.
///
/// Add fields with [`Pending::set`], then close it with [`Pending::finish`]. Dropping it first records
/// the entry as `timeout`.
pub(crate) struct Pending {
    log: ActionLog,
    seq: u64,
    check: Option<String>,
    kind: ActionKind,
    fields: Map<String, Value>,
    started: Instant,
    closed: bool,
}

impl Pending {
    /// Sets one field of the entry.
    pub(crate) fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.fields.insert(key.to_owned(), value.into());
    }

    /// Closes the entry with `outcome`.
    pub(crate) fn finish(mut self, outcome: ActionOutcome) {
        self.closed = true;
        let log = self.log.clone();
        log.close(&mut self, outcome);
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let log = self.log.clone();
            log.close(self, ActionOutcome::Timeout);
        }
    }
}
