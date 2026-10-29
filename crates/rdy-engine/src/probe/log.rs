//! The action log: one entry for every side effect the facade performs (01 section 5.4, 02).
//!
//! The facade writes every entry. A check cannot skip it, because a check has no other way to read a
//! file or start a command. An entry is opened before the work starts ([`ActionLog::begin`] reserves its
//! `seq`) and closed when the work ends. A [`Pending`] that is dropped without being closed, which is
//! what happens when the scheduler aborts a check at its timeout, is recorded as `timeout`.
//!
//! **Redaction.** Every string in an entry passes the [`Redactor`] when the entry is closed, and the
//! log counts what each rule did. [`ActionLogOutput::apply`] adds those counts to a report's
//! `redaction` summary. Paths under the home directory start with `~`.
//!
//! **Retention.** The log holds at most [`MAX_ENTRIES`] entries. Only `read`, `read_dir` and `stat`
//! entries with outcome `ok` are ever dropped. At the cap, a new droppable entry is dropped and
//! counted, and any other new entry makes room by dropping the newest droppable one. `exec`,
//! `connect`, `tls`, `http`, `dns`, `lookup`, `kube` and `native` entries and every `denied`, `failed`
//! or `timeout` entry are kept. Their volume is bounded by the spec (hosts, ports) and by the fixed
//! command set. One case can still overflow: a log that holds nothing droppable and is full. Then the
//! new entry is dropped and counted in `actions_dropped`, so memory stays bounded and the report still
//! fits its schema. The drops show up as gaps in `seq`.
//!
//! Size-based truncation of the whole document (2 MiB) and the coalescing of reads past 200 per
//! directory belong to the report writer and to M1-041.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rdy_spec::result::{Action, ActionKind, ActionOutcome, Report};
use serde_json::{Map, Value};

use crate::redact::{Redactor, RuleCounts};

/// The most entries a report carries. The result schema allows 5000 (01 section 5.4).
pub const MAX_ENTRIES: usize = 5000;

/// The action log of one run, shared by every probe handle.
#[derive(Clone)]
pub(crate) struct ActionLog {
    shared: Arc<Shared>,
}

struct Shared {
    origin: Instant,
    home: Option<PathBuf>,
    redactor: Redactor,
    max_entries: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    next_seq: u64,
    entries: BTreeMap<u64, Action>,
    /// The `seq` of every entry that retention may drop.
    droppable: BTreeSet<u64>,
    dropped: BTreeMap<String, u64>,
    truncated: bool,
    counts: RuleCounts,
}

/// What the log holds at one moment, ready to go into a report.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ActionLogOutput {
    /// The entries, in `seq` order. A gap in `seq` is a dropped entry.
    pub actions: Vec<Action>,
    /// `true` when retention dropped anything.
    pub truncated: bool,
    /// How many entries of each kind retention dropped.
    pub dropped: BTreeMap<String, u64>,
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
    pub(crate) fn new(redactor: Redactor, home: Option<PathBuf>, max_entries: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                origin: Instant::now(),
                home,
                redactor,
                max_entries,
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

    /// The path as the log shows it: `~/rest` under the home directory, else as given.
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
        for value in action.fields.values_mut() {
            redact_value(&shared.redactor, value, counts);
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
        insert(&mut state, action, shared.max_entries);
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

/// Whether retention may drop this entry. Only a successful read, directory listing or stat.
fn is_droppable(kind: &ActionKind, outcome: &ActionOutcome) -> bool {
    matches!(
        kind,
        ActionKind::Read | ActionKind::ReadDir | ActionKind::Stat
    ) && *outcome == ActionOutcome::Ok
}

fn count_drop(state: &mut State, kind: &ActionKind) {
    *state.dropped.entry(kind.as_str().to_owned()).or_insert(0) += 1;
    state.truncated = true;
}

fn insert(state: &mut State, action: Action, max_entries: usize) {
    let droppable = is_droppable(&action.kind, &action.outcome);
    if state.entries.len() >= max_entries {
        if droppable {
            count_drop(state, &action.kind);
            return;
        }
        // Make room by dropping the newest droppable entry.
        let Some(victim) = state.droppable.pop_last() else {
            // Nothing may be dropped and the log is full. Keep memory bounded and say so.
            count_drop(state, &action.kind);
            return;
        };
        if let Some(removed) = state.entries.remove(&victim) {
            count_drop(state, &removed.kind);
        }
    }
    if droppable {
        state.droppable.insert(action.seq);
    }
    state.entries.insert(action.seq, action);
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
