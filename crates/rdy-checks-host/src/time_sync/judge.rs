//! The judgement of `host.time_sync`: a pure function of the facts the sources gave.
//!
//! The sources are `timedatectl` and `chronyc` (sync state) and the SNTP exchange (offset). Each can be
//! missing, so every fact is optional and the text says which one is. The levels follow 03:
//!
//! - an offset above `max_skew` (default 300 s): block;
//! - not synchronized with `require_sync`: block;
//! - an offset above `recommended_skew` (default 5 s, never above `max_skew`): warn;
//! - not synchronized, or the sources disagree: warn;
//! - the vendor asked for an offset and none was measured: warn, with `partial`;
//! - otherwise pass. With no `ntp_servers` and no skew keys the offset is simply "not measured".

use rdy_engine::check::{Finding, Level, Partial};
use serde_json::{Value, json};

use super::parse::{Timedate, Tracking};
use super::sntp::{Reject, Sample};
use crate::text::code;

/// The block level when the spec sets no `max_skew`: AWS signing, Kerberos and TLS validity fail near
/// five minutes.
pub(crate) const DEFAULT_MAX_SKEW: f64 = 300.0;

/// The warn level when the spec sets no `recommended_skew`.
pub(crate) const DEFAULT_RECOMMENDED_SKEW: f64 = 5.0;

/// A half round trip above this many seconds is called out: the offset cannot be better than that.
const LONG_BOUND: f64 = 1.0;

/// How long one server gets, for the text. The probe's own limit is the same.
const SNTP_WAIT: &str = "3 s";

/// What running a tool gave.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Tool<T> {
    /// It ran and its output parsed.
    Got(T),
    /// The program is not installed.
    Absent,
    /// It ran but gave nothing usable. The text says why.
    Unusable(String),
}

impl<T> Tool<T> {
    fn word(&self) -> String {
        match self {
            Self::Got(_) => "ok".to_owned(),
            Self::Absent => "not installed".to_owned(),
            Self::Unusable(why) => format!("unusable: {why}"),
        }
    }
}

/// What asking one server gave.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Attempt {
    /// A valid reply.
    Sample(Sample),
    /// A reply that was refused.
    Rejected(Reject),
    /// The probe refused the address: it is in a refused range.
    Refused,
    /// No reply in time.
    Silent,
    /// The lookup or the socket failed. The text says how.
    Failed(String),
    /// Not asked: an earlier server answered, or the check budget had no room.
    NotAsked(&'static str),
}

/// Everything the sources gave.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Facts {
    pub timedatectl: Tool<Timedate>,
    pub chronyc: Tool<Tracking>,
    /// The servers in spec order, as the spec wrote them, with what each gave.
    pub servers: Vec<(String, Attempt)>,
}

/// The thresholds and flags, with the defaults applied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Limits {
    /// Block above this many seconds.
    pub max: f64,
    /// Warn above this many seconds. Never above `max`.
    pub warn: f64,
    pub require_sync: bool,
    /// The spec set `max_skew` or `recommended_skew`.
    pub skew_set: bool,
}

impl Limits {
    pub(crate) fn new(max: Option<f64>, recommended: Option<f64>, require_sync: bool) -> Self {
        let max_value = max.unwrap_or(DEFAULT_MAX_SKEW);
        let warn = recommended
            .unwrap_or(DEFAULT_RECOMMENDED_SKEW)
            .min(max_value);
        Self {
            max: max_value,
            warn,
            require_sync,
            skew_set: max.is_some() || recommended.is_some(),
        }
    }
}

/// The synchronization state the sources agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Synchronized,
    NotSynchronized,
    Conflict,
    Unknown,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            Self::Synchronized => "synchronized",
            Self::NotSynchronized => "not_synchronized",
            Self::Conflict => "conflict",
            Self::Unknown => "unknown",
        }
    }
}

/// Where the offset came from.
#[derive(Debug, Clone, PartialEq)]
enum Source {
    /// An SNTP reply from this server. The offset is signed: server minus local.
    Sntp(String),
    /// `chronyc tracking`. The offset is a size only. The text is the reference chrony names.
    Chrony(Option<String>),
}

#[derive(Debug, Clone, PartialEq)]
struct Offset {
    seconds: f64,
    source: Source,
}

impl Offset {
    fn size(&self) -> f64 {
        self.seconds.abs()
    }

    /// `6 min 40 s behind `192.0.2.10``, or `12 ms away from chrony's reference `ntp.acme.example``.
    fn describe(&self) -> String {
        let size = seconds_text(self.size());
        match &self.source {
            Source::Sntp(server) => {
                // Positive: the server is ahead, so our clock is behind it.
                let way = if self.seconds >= 0.0 {
                    "behind"
                } else {
                    "ahead of"
                };
                format!("{size} {way} {}", code(server))
            }
            Source::Chrony(Some(reference)) => {
                format!("{size} away from chrony's reference {}", code(reference))
            }
            Source::Chrony(None) => format!("{size} away from chrony's reference"),
        }
    }

    fn reference(&self) -> Option<&str> {
        match &self.source {
            Source::Sntp(server) => Some(server),
            Source::Chrony(reference) => reference.as_deref(),
        }
    }
}

/// A span of seconds in words: `850 ms`, `12.5 s`, `6 min 40 s`, `2 h 3 min`.
pub(crate) fn seconds_text(seconds: f64) -> String {
    let s = seconds.abs();
    if !s.is_finite() {
        return "an unknown span".to_owned();
    }
    if s < 0.001 {
        return "under 1 ms".to_owned();
    }
    if s < 1.0 {
        return format!("{} ms", whole(s * 1000.0));
    }
    if s < 120.0 {
        let tenths = (s * 10.0).round() / 10.0;
        return if (tenths - tenths.trunc()).abs() < f64::EPSILON {
            format!("{} s", whole(tenths))
        } else {
            format!("{tenths:.1} s")
        };
    }
    let total = whole(s);
    if total < 7200 {
        let (min, sec) = (total / 60, total % 60);
        return if sec == 0 {
            format!("{min} min")
        } else {
            format!("{min} min {sec} s")
        };
    }
    let (hours, min) = (total / 3600, (total % 3600) / 60);
    if min == 0 {
        format!("{hours} h")
    } else {
        format!("{hours} h {min} min")
    }
}

/// A non-negative number rounded to a whole number.
fn whole(value: f64) -> u64 {
    // `as` saturates for out of range values and gives 0 for NaN, so this cannot panic.
    value.round() as u64
}

fn round6(value: f64) -> f64 {
    (value * 1e6).round() / 1e6
}

const SYNC_FIX: &str = "Run `timedatectl set-ntp true`, or install chrony (`dnf install chrony && systemctl enable --now chronyd`, then `chronyc makestep`). On VMs also enable host time sync (VMware Tools, Hyper-V integration services).";

const UNKNOWN_FIX: &str = "Install chrony (`dnf install chrony && systemctl enable --now chronyd`), or run `timedatectl status` and check that systemd-timesyncd or chronyd is running. Inside a container the host clock applies, so run rdy on the host.";

const REFUSED_FIX: &str = "rdy does not query link-local or cloud metadata time addresses. Name a time server outside those ranges in `ntp_servers`, or run `chronyc tracking` and read the offset by hand.";

const SILENT_FIX: &str = "Check that UDP port 123 is open to the time server (`chronyc sources -v` shows whether chrony reaches its sources), or name another server in `ntp_servers`.";

/// Judges the facts.
pub(crate) fn judge(facts: &Facts, limits: Limits) -> Finding {
    let state = state_of(facts);
    let offset = offset_of(facts);
    let wanted = !facts.servers.is_empty() || limits.skew_set;
    let notes = notes_of(facts, state);

    let mut finding = decide(facts, limits, state, offset.as_ref(), wanted);
    finding.observed = observed(facts, state, offset.as_ref());
    finding.expected = json!({
        "max_skew_seconds": limits.max,
        "recommended_skew_seconds": limits.warn,
        "require_sync": limits.require_sync,
    });
    finding.notes = notes;
    finding
}

fn decide(
    facts: &Facts,
    limits: Limits,
    state: State,
    offset: Option<&Offset>,
    wanted: bool,
) -> Finding {
    let off_text = offset.map(Offset::describe);
    if let Some(o) = offset
        && o.size() > limits.max
    {
        return fail_or_warn(
            Level::Fail,
            format!(
                "Clock is {}, over the {} limit.",
                o.describe(),
                seconds_text(limits.max)
            ),
            clock_fix(Some(o), state),
        );
    }
    if limits.require_sync && state == State::NotSynchronized {
        let message = match &off_text {
            Some(text) => format!("Clock is not synchronized. It is {text}."),
            None => "Clock is not synchronized.".to_owned(),
        };
        return fail_or_warn(Level::Fail, message, clock_fix(offset, state));
    }
    if let Some(o) = offset
        && o.size() > limits.warn
    {
        return fail_or_warn(
            Level::Warn,
            format!(
                "Clock is {}, over the {} recommended limit.",
                o.describe(),
                seconds_text(limits.warn)
            ),
            clock_fix(Some(o), state),
        );
    }
    match state {
        State::NotSynchronized => {
            let message = match &off_text {
                Some(text) => format!("Clock is not synchronized. It is {text}."),
                None => "Clock is not synchronized.".to_owned(),
            };
            return fail_or_warn(Level::Warn, message, clock_fix(offset, state));
        }
        State::Conflict => {
            return unverified(
                "Clock sync sources disagree: timedatectl and chronyc give different answers.",
                SYNC_FIX.to_owned(),
                "the sync state is not settled",
            );
        }
        State::Unknown if limits.require_sync || offset.is_none() => {
            return unverified(
                "Clock sync state could not be read.",
                UNKNOWN_FIX.to_owned(),
                "neither timedatectl nor chronyc gave a sync state",
            );
        }
        State::Unknown | State::Synchronized => {}
    }
    if offset.is_none() && wanted {
        return not_measured(facts);
    }
    pass(state, offset, wanted)
}

fn fail_or_warn(level: Level, message: String, fix: String) -> Finding {
    let mut finding = Finding::new(level, message);
    finding.fix = Some(fix);
    finding
}

fn unverified(message: &str, fix: String, note: &str) -> Finding {
    let mut finding = Finding::warn(message);
    finding.fix = Some(fix);
    finding.partial = Some(Partial::new(Vec::new(), note));
    finding
}

/// The vendor asked for an offset and no source gave one.
fn not_measured(facts: &Facts) -> Finding {
    let attempts: Vec<&Attempt> = facts.servers.iter().map(|(_, a)| a).collect();
    let all_refused =
        !attempts.is_empty() && attempts.iter().all(|a| matches!(a, Attempt::Refused));
    let any_refused = attempts.iter().any(|a| matches!(a, Attempt::Refused));
    let (message, fix) = if all_refused {
        (
            "Offset not measured, server in a refused range.",
            REFUSED_FIX,
        )
    } else if attempts.is_empty() {
        (
            "Offset not measured: the spec sets a skew limit but lists no ntp_servers, and chronyc gave none.",
            "Add `ntp_servers: [ntp.example.com]` to the host.time_sync entry, or install chrony and run `chronyc tracking`.",
        )
    } else if any_refused {
        (
            "Offset not measured: no time server gave a usable reply, and one is in a refused range.",
            REFUSED_FIX,
        )
    } else {
        (
            "Offset not measured: no time server gave a usable reply.",
            SILENT_FIX,
        )
    };
    unverified(message, fix.to_owned(), "the clock offset was not measured")
}

fn pass(state: State, offset: Option<&Offset>, wanted: bool) -> Finding {
    let synced = match state {
        State::Synchronized => "Clock is synchronized",
        _ => "Clock offset is within limits, sync state not read",
    };
    let message = match offset {
        Some(o) => format!("{synced}, {}.", o.describe()),
        None if wanted => format!("{synced}."),
        None => format!("{synced}. Offset not measured: the spec lists no ntp_servers."),
    };
    Finding::pass(message)
}

/// The fix for a clock that is off or not synchronized, with the values filled in.
fn clock_fix(offset: Option<&Offset>, state: State) -> String {
    let and_unsynced = if state == State::NotSynchronized {
        " and not synchronized"
    } else {
        ""
    };
    match offset {
        Some(o) => {
            let reference = o
                .reference()
                .map_or_else(String::new, |r| format!(" from {}", code(r)));
            format!(
                "Clock is {} away{reference}{and_unsynced}. {SYNC_FIX}",
                seconds_text(o.size())
            )
        }
        None => format!("Clock is not synchronized. {SYNC_FIX}"),
    }
}

fn state_of(facts: &Facts) -> State {
    let mut votes = Vec::new();
    if let Tool::Got(t) = &facts.timedatectl
        && let Some(s) = t.synchronized
    {
        votes.push(s);
    }
    if let Tool::Got(c) = &facts.chronyc {
        votes.push(c.synchronized);
    }
    match (votes.contains(&true), votes.contains(&false)) {
        (true, false) => State::Synchronized,
        (false, true) => State::NotSynchronized,
        (true, true) => State::Conflict,
        (false, false) => State::Unknown,
    }
}

/// The first valid SNTP offset in spec order, else chrony's when chronyd tracks a real source.
fn offset_of(facts: &Facts) -> Option<Offset> {
    for (server, attempt) in &facts.servers {
        if let Attempt::Sample(sample) = attempt {
            return Some(Offset {
                seconds: sample.offset,
                source: Source::Sntp(server.clone()),
            });
        }
    }
    // The offset of a chronyd that has no source is not a measurement of anything.
    if let Tool::Got(c) = &facts.chronyc
        && c.synchronized
    {
        return Some(Offset {
            seconds: c.offset,
            source: Source::Chrony(c.reference.clone()),
        });
    }
    None
}

fn notes_of(facts: &Facts, state: State) -> Vec<String> {
    let mut notes = Vec::new();
    for (server, attempt) in &facts.servers {
        let who = code(server);
        match attempt {
            Attempt::Sample(sample) => {
                let bound = sample.delay / 2.0;
                let long = if bound > LONG_BOUND {
                    ". The round trip is long, so the offset is uncertain"
                } else {
                    ""
                };
                notes.push(format!(
                    "{who}: stratum {}, round trip {}, offset known to within {}{long}.",
                    sample.stratum,
                    seconds_text(sample.delay),
                    seconds_text(bound),
                ));
            }
            Attempt::Refused => {
                // Only when the offset in use really is chronyc's: it must track a real source, and no
                // other server gave a sample.
                let uses_chrony = matches!(&facts.chronyc, Tool::Got(c) if c.synchronized)
                    && !facts
                        .servers
                        .iter()
                        .any(|(_, a)| matches!(a, Attempt::Sample(_)));
                let tail = if uses_chrony {
                    ". Using the offset from chronyc instead."
                } else {
                    "."
                };
                notes.push(format!(
                    "{who}: offset not measured, server in a refused range{tail}"
                ));
            }
            Attempt::Silent => notes.push(format!("{who}: no reply within {SNTP_WAIT}.")),
            Attempt::NotAsked(why) => notes.push(format!("{who}: not measured, {why}.")),
            Attempt::Rejected(why) => notes.push(format!("{who}: {why}.")),
            Attempt::Failed(why) => notes.push(format!("{who}: {why}.")),
        }
    }
    if let Tool::Got(c) = &facts.chronyc {
        if c.local_reference {
            notes.push(
                "chronyd is running on its own local clock (local directive), not on a time source."
                    .to_owned(),
            );
        }
        if c.stratum == 0 || c.stratum >= 16 {
            notes.push(format!("chronyc reports stratum {}.", c.stratum));
        }
    }
    if let Tool::Got(t) = &facts.timedatectl
        && t.ntp_enabled == Some(false)
        && state != State::Synchronized
    {
        notes.push(
            "Network time is turned off in systemd (`timedatectl set-ntp true` turns it on)."
                .to_owned(),
        );
    }
    if let Tool::Unusable(why) = &facts.timedatectl {
        notes.push(format!("timedatectl gave no answer: {why}."));
    }
    if let Tool::Unusable(why) = &facts.chronyc {
        notes.push(format!("chronyc gave no answer: {why}."));
    }
    notes
}

fn observed(facts: &Facts, state: State, offset: Option<&Offset>) -> Value {
    let td = match &facts.timedatectl {
        Tool::Got(t) => Some(t),
        _ => None,
    };
    let chrony = match &facts.chronyc {
        Tool::Got(c) => Some(json!({
            "stratum": c.stratum,
            "reference": c.reference,
            "leap": c.leap,
            "offset_seconds": round6(c.offset),
            "synchronized": c.synchronized,
        })),
        _ => None,
    };
    let servers: Vec<Value> = facts
        .servers
        .iter()
        .map(|(server, attempt)| server_json(server, attempt))
        .collect();
    json!({
        "state": state.word(),
        "ntp_enabled": td.and_then(|t| t.ntp_enabled),
        "timezone": td.and_then(|t| t.timezone.clone()),
        "timedatectl": facts.timedatectl.word(),
        "chronyc": facts.chronyc.word(),
        "chrony": chrony,
        "offset_seconds": offset.map(|o| round6(o.seconds)),
        "offset_source": offset.map(|o| match o.source {
            Source::Sntp(_) => "sntp",
            Source::Chrony(_) => "chronyc",
        }),
        "reference": offset.and_then(Offset::reference),
        "servers": servers,
    })
}

fn server_json(server: &str, attempt: &Attempt) -> Value {
    match attempt {
        Attempt::Sample(s) => json!({
            "server": server,
            "result": "ok",
            "offset_seconds": round6(s.offset),
            "delay_seconds": round6(s.delay),
            "error_bound_seconds": round6(s.delay / 2.0),
            "stratum": s.stratum,
        }),
        Attempt::Rejected(why) => json!({
            "server": server, "result": "rejected", "detail": why.to_string(),
        }),
        Attempt::Refused => json!({
            "server": server,
            "result": "refused_range",
            "detail": "offset not measured, server in a refused range",
        }),
        Attempt::Silent => json!({"server": server, "result": "silent"}),
        Attempt::NotAsked(why) => {
            json!({"server": server, "result": "not_measured", "detail": why})
        }
        Attempt::Failed(why) => json!({"server": server, "result": "failed", "detail": why}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_read_in_words() {
        assert_eq!(seconds_text(0.0), "under 1 ms");
        assert_eq!(seconds_text(0.0123), "12 ms");
        assert_eq!(seconds_text(1.0), "1 s");
        assert_eq!(seconds_text(12.5), "12.5 s");
        assert_eq!(seconds_text(300.0), "5 min");
        assert_eq!(seconds_text(400.0), "6 min 40 s");
        assert_eq!(seconds_text(-400.0), "6 min 40 s");
        assert_eq!(seconds_text(7260.0), "2 h 1 min");
        assert_eq!(seconds_text(f64::NAN), "an unknown span");
        assert_eq!(seconds_text(f64::INFINITY), "an unknown span");
    }

    #[test]
    fn the_warn_level_never_exceeds_the_block_level() {
        let l = Limits::new(Some(2.0), None, false);
        assert!((l.warn - 2.0).abs() < f64::EPSILON && (l.max - 2.0).abs() < f64::EPSILON);
        let l = Limits::new(None, Some(600.0), false);
        assert!((l.max - 300.0).abs() < f64::EPSILON);
        assert!((l.warn - 300.0).abs() < f64::EPSILON);
        assert!(l.skew_set);
        let l = Limits::new(None, None, false);
        assert!(!l.skew_set);
    }
}
