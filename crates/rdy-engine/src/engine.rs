//! The engine: from a verified spec to the results of a run (02, "Checks, families and the run plan",
//! "Privilege and needs" and "Scheduling").
//!
//! [`Engine::execute`] does the middle of `rdy run`, in this order:
//!
//! 1. **Plan.** [`Engine::plan`] maps every entry to a built check or a skip, with no I/O.
//! 2. **Needs.** [`capabilities`] probes only the needs the plan holds, through the run-level probe. The
//!    needs it finds met are the ones the scheduler hands to the checks. `kube_context` is the
//!    Kubernetes family's probe (M1-107). Until then it is never met, so a check that needs it ends as a
//!    `missing_need` skip.
//! 3. **Schedule.** The [`Scheduler`] runs the checks that can run, with a probe from the run's hub for
//!    each.
//! 4. **Map.** Every end becomes a `CheckResult`: a finding through [`map_outcome`], a timeout, a panic,
//!    a missed deadline or a cancel through the fixed results of [`crate::outcome`]. A skip from the plan
//!    is its own result. The `<spec>` of the root fix is replaced by the spec as the user typed it.
//! 5. **Redact.** Each result passes [`crate::redact::Redactor::redact_check`], and the counts are kept for the final
//!    pass.
//!
//! The caller owns everything around it: the report folder, the facts of the run (producer, host,
//! identity, signature), the final `redact_report_counted` and the writers. The engine takes a
//! [`LoadedSpec`], so a spec that was not verified before it was parsed cannot run (INV-01).
//!
//! The hosts of a check's spec entry are not handed to its probe here: that is M1-095, with the first
//! live socket check. Until then no check can reach a host.

use std::sync::Arc;
use std::time::Duration;

use rdy_spec::LoadedSpec;
use rdy_spec::result::{Capability, CheckResult, Report, Severity, Status};
use rdy_spec::spec::{CheckSpec, Lenient};

use crate::check::{CheckContext, CheckInfo, Finding, Need, Os};
use crate::family::Registry;
use crate::outcome::{
    SPEC_PLACEHOLDER, cancelled_result, map_outcome, panicked_result, run_deadline_result,
    timeout_result, unfinished_result,
};
use crate::plan::{PlanAction, RunPlan};
use crate::privilege::{Privilege, capabilities};
use crate::probe::{ActionLogOutput, ProbeHub};
use crate::redact::RuleCounts;
use crate::sched::{DEFAULT_DEADLINE, DEFAULT_JOBS, End, Observer, Planned, Ran, Scheduler};
use crate::watchdog::Board;

#[cfg(test)]
mod hosts_tests;
#[cfg(test)]
mod tests;

/// What shapes one run.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunOptions {
    /// How many checks run at once. [`Scheduler::new`] holds it to 1 to 32.
    pub jobs: usize,
    /// How long the whole run may take.
    pub deadline: Duration,
    /// Whether sockets are allowed. With `false`, the `network` need is not met.
    pub network: bool,
    /// The spec as the user typed it, quoted for a shell and safe to print. It replaces `<spec>` in the
    /// fix of a check that needs root. That fix is in the report, so the typed path stays in a report
    /// that is uploaded or shared. A home folder name in it is not redacted (04, what stays).
    pub spec_arg: String,
    /// The instant the deadline is counted from. `None` counts from the start of the run.
    pub origin: Option<std::time::Instant>,
    /// The watchdog's board for this run, made by [`Engine::board`] from the same plan before the
    /// run started (M1-176). [`Engine::execute`] tells it about every start and end. `None` runs
    /// without one.
    pub board: Option<Arc<Board>>,
}

/// Sends the scheduler's positions to the board's slots. The scheduler counts only the checks it runs;
/// the board has a slot for every spec entry.
struct SlotObserver {
    board: Arc<Board>,
    slot_of: Vec<usize>,
}

impl Observer for SlotObserver {
    fn started(&self, index: usize, at: Duration, timeout: Duration) {
        if let Some(slot) = self.slot_of.get(index) {
            self.board.started(*slot, at, timeout);
        }
    }

    fn finished(&self, index: usize, ran: &Ran) {
        if let Some(slot) = self.slot_of.get(index) {
            self.board.finished(*slot, ran);
        }
    }
}

/// What the board keeps of one scheduled check to map its end by itself.
struct Owned {
    info: &'static CheckInfo,
    spec_entry: CheckSpec,
    ctx: CheckContext,
    template: CheckResult,
}

impl RunOptions {
    /// The defaults: 8 checks at once, a 5 minute deadline, sockets allowed, no spec name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jobs: DEFAULT_JOBS,
            deadline: DEFAULT_DEADLINE,
            network: true,
            spec_arg: "<spec>".to_owned(),
            origin: None,
            board: None,
        }
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// What [`Engine::execute`] hands back.
#[derive(Debug)]
#[non_exhaustive]
pub struct Executed {
    /// One redacted result per spec entry, in spec order.
    pub results: Vec<CheckResult>,
    /// What was probed before the checks ran.
    pub capabilities: Vec<Capability>,
    /// The action log of the whole run, the run-level entries from before the engine started included.
    /// Put it in the report with [`ActionLogOutput::apply`].
    pub log: ActionLogOutput,
    /// What the redactor did to the results and to the action log. Pass it to
    /// `Redactor::redact_report_counted`: that call rebuilds the report's `redaction` block from this
    /// and its own walk, so a count the log made would be lost without it.
    pub counts: RuleCounts,
}

/// The families of this build and the hub of this run.
#[derive(Debug)]
pub struct Engine {
    registry: Registry,
    hub: ProbeHub,
}

impl Engine {
    /// An engine over `registry`. Every check reaches the machine through a probe from `hub`.
    #[must_use]
    pub fn new(registry: Registry, hub: ProbeHub) -> Self {
        Self { registry, hub }
    }

    /// The registry of this build.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The hub of this run, for the action log.
    #[must_use]
    pub fn hub(&self) -> &ProbeHub {
        &self.hub
    }

    /// Plans a run of `spec` on `os`. Pure: no I/O. See [`Registry::plan`].
    #[must_use]
    pub fn plan(&self, spec: &LoadedSpec, os: Os, rdy_version: &str) -> RunPlan {
        self.registry.plan(spec.spec(), os, rdy_version)
    }

    /// The watchdog's board for a run of `plan` (made from `spec`), built before the run starts so the
    /// caller can arm the watchdog as soon as the report folder exists (M1-176). Pure: no I/O.
    ///
    /// One slot per spec entry, in spec order, with the results of the entries the plan skips already
    /// in it. `base` is the report without its results. Pass the board to [`Engine::execute`] through
    /// [`RunOptions::board`]; that call gives it the way to map an end.
    #[must_use]
    pub fn board(
        &self,
        spec: &LoadedSpec,
        plan: &RunPlan,
        base: Report,
        deadline: Duration,
        spec_arg: &str,
    ) -> Arc<Board> {
        let os = plan.os();
        let mut templates: Vec<CheckResult> = Vec::with_capacity(plan.entries().len());
        // The result an entry has before any check runs, if it has one.
        let mut settled: Vec<Option<CheckResult>> = Vec::with_capacity(plan.entries().len());
        for entry in plan.entries() {
            if let Some(result) = entry.skip_result() {
                templates.push(result.clone());
                settled.push(Some(result));
                continue;
            }
            match (&entry.action, spec.spec().checks.get(entry.index)) {
                (PlanAction::Run(built), Some(spec_entry)) => {
                    // Only the identity of the template is read, so the needs do not matter here.
                    let item = Item {
                        info: built.check.info(),
                        spec_entry,
                        ctx: CheckContext::new(entry.key.clone(), os, std::iter::empty()),
                    };
                    templates.push(item.template());
                    settled.push(None);
                }
                _ => {
                    // The same entry `execute` turns into "not finished".
                    let template = identity(&entry.key, &entry.id, &entry.family, &entry.severity);
                    settled.push(Some(unfinished_result(&template)));
                    templates.push(template);
                }
            }
        }
        let board = Arc::new(Board::pending(
            base,
            templates,
            self.hub.redactor().clone(),
            deadline,
        ));
        for (slot, result) in settled.into_iter().enumerate() {
            if let Some(mut result) = result {
                fill_spec_arg(&mut result, spec_arg);
                board.record(slot, result);
            }
        }
        board
    }

    /// Runs `plan` (made from `spec`) and returns the redacted result of every entry.
    ///
    /// Never fails: a check that times out, panics or cannot start is a result, and a result that
    /// cannot be redacted is replaced by a fixed "not finished" result.
    pub async fn execute(
        &self,
        spec: &LoadedSpec,
        plan: RunPlan,
        privilege: &Privilege,
        options: &RunOptions,
    ) -> Executed {
        let os = plan.os();
        let entries = plan.into_entries();

        // Needs: probe only what the runnable checks hold.
        let mut wanted: Vec<Need> = Vec::new();
        for entry in &entries {
            if let PlanAction::Run(built) = &entry.action {
                let info = built.check.info();
                wanted.extend(info.needs.iter().cloned());
                wanted.extend(info.wants.iter().map(|want| want.need.clone()));
            }
        }
        let found = capabilities(&self.hub.run_probe(), privilege, &wanted, options.network).await;
        let available: Vec<Need> = wanted
            .iter()
            .filter(|need| {
                found.iter().any(|cap| {
                    cap.available && cap.need == need.wire() && cap.name.as_deref() == need.name()
                })
            })
            .cloned()
            .collect();

        // Split the plan: a skip is a finished result, a runnable entry goes to the scheduler.
        let mut slots: Vec<Slot> = Vec::with_capacity(entries.len());
        let mut planned: Vec<Planned> = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        for entry in entries {
            if let Some(result) = entry.skip_result() {
                slots.push(Slot::Skipped(Box::new(result)));
                continue;
            }
            // A skip was handled above, and the plan was made from this spec, so both of these hold. If
            // one did not, the entry still gets a result that counts as not run: an entry is never
            // dropped, because a dropped required check could turn the verdict to READY.
            let spec_entry = spec.spec().checks.get(entry.index);
            let (built, spec_entry) = match (entry.action, spec_entry) {
                (PlanAction::Run(built), Some(spec_entry)) => (built, spec_entry),
                _ => {
                    let template = identity(&entry.key, &entry.id, &entry.family, &entry.severity);
                    slots.push(Slot::Skipped(Box::new(unfinished_result(&template))));
                    continue;
                }
            };
            let info = built.check.info();
            let ctx = CheckContext::new(entry.key.clone(), os, available.iter().cloned());
            // The check's probe gets the hosts its own entry lists, and no others (INV-11). Without this a
            // real run refuses every connect and datagram (M1-095).
            let mut run = Planned::new(Arc::from(built.check), entry.key).with_hosts(built.hosts);
            if let Some(timeout) = spec_timeout(spec_entry) {
                run = run.with_timeout(timeout);
            }
            let item = Item {
                info,
                spec_entry,
                ctx,
            };
            slots.push(Slot::Ran(Box::new(item.template())));
            planned.push(run);
            items.push(item);
        }

        // The board for the watchdog, when the caller made one: give it the way to map an end, and the
        // scheduler's positions to its slots.
        let observer = options.board.as_ref().map(|board| {
            let mut owned: Vec<Option<Owned>> = Vec::with_capacity(slots.len());
            let mut slot_of: Vec<usize> = Vec::new();
            let mut kept = items.iter();
            for (slot, entry) in slots.iter().enumerate() {
                match entry {
                    Slot::Skipped(_) => owned.push(None),
                    Slot::Ran(template) => {
                        owned.push(kept.next().map(|item| Owned {
                            info: item.info,
                            spec_entry: item.spec_entry.clone(),
                            ctx: item.ctx.clone(),
                            template: (**template).clone(),
                        }));
                        slot_of.push(slot);
                    }
                }
            }
            let deadline = options.deadline;
            let spec_arg = options.spec_arg.clone();
            board.set_map(Box::new(move |slot, ran| {
                let Some(Some(owned)) = owned.get(slot) else {
                    // The scheduler only reports the slots it was given, so this cannot happen. If it
                    // did, the entry would count as not run, never as passed.
                    return unfinished_result(&identity("", "", "", &Severity::Block));
                };
                let mut result = map_end(
                    owned.info,
                    &owned.spec_entry,
                    &owned.ctx,
                    &owned.template,
                    ran.clone(),
                    deadline,
                );
                fill_spec_arg(&mut result, &spec_arg);
                result
            }));
            SlotObserver {
                board: Arc::clone(board),
                slot_of,
            }
        });

        let mut scheduler = Scheduler::new(options.jobs, os, available)
            .with_deadline(options.deadline)
            .with_probes(self.hub.clone());
        if let Some(origin) = options.origin {
            scheduler = scheduler.with_origin(origin);
        }
        let ran = match observer {
            Some(observer) => scheduler.run_observed(planned, Arc::new(observer)).await,
            None => scheduler.run(planned).await,
        };

        // One result per item, in order. A result the scheduler did not hand back is "not finished", never
        // a missing entry.
        let mut ran = ran.into_iter();
        let mapped: Vec<CheckResult> = items
            .iter()
            .map(|item| {
                let template = item.template();
                let Some(ran) = ran.next() else {
                    return unfinished_result(&template);
                };
                map_end(
                    item.info,
                    item.spec_entry,
                    &item.ctx,
                    &template,
                    ran,
                    options.deadline,
                )
            })
            .collect();

        let redactor = self.hub.redactor();
        let mut counts = RuleCounts::default();
        let mut mapped = mapped.into_iter();
        let results = slots
            .into_iter()
            .map(|slot| {
                let mut result = match slot {
                    Slot::Skipped(result) => *result,
                    // `mapped` has one result per `Ran` slot, in the same order. A miss cannot happen.
                    // If it did, the check would count as not run, never as passed, and never vanish.
                    Slot::Ran(template) => mapped
                        .next()
                        .unwrap_or_else(|| unfinished_result(&template)),
                };
                fill_spec_arg(&mut result, &options.spec_arg);
                match redactor.redact_check(result.clone(), &mut counts) {
                    Ok(redacted) => (*redacted).clone(),
                    // The result no longer read as a result. Keep none of its text.
                    Err(_) => unfinished_result(&result),
                }
            })
            .collect();

        let log = self.hub.action_log();
        counts.merge(&log.redaction);
        Executed {
            results,
            capabilities: found,
            log,
            counts,
        }
    }
}

/// Where a spec entry's result comes from.
enum Slot {
    /// The plan skipped it.
    Skipped(Box<CheckResult>),
    /// The scheduler ran it. The next result of the run is this entry's. The result here holds only its
    /// identity, for the "not finished" result if that one is ever missing.
    Ran(Box<CheckResult>),
}

/// A result that holds only the identity of one spec entry (see [`crate::outcome`]).
fn identity(key: &str, id: &str, family: &str, severity: &Severity) -> CheckResult {
    let mut result = CheckResult::new(id, family, severity.clone(), Status::Error);
    result.key = key.to_owned();
    result
}

/// What the engine keeps of one scheduled check, to map its end.
struct Item<'a> {
    info: &'static CheckInfo,
    spec_entry: &'a CheckSpec,
    ctx: CheckContext,
}

impl Item<'_> {
    /// A result of the same entry, from which only the identity is kept (see [`crate::outcome`]).
    fn template(&self) -> CheckResult {
        map_outcome(
            self.info,
            self.spec_entry,
            &self.ctx,
            Ok(Finding::pass("")),
            0,
            0,
        )
    }
}

/// The spec's `timeout` for an entry, when it has a readable one.
fn spec_timeout(entry: &CheckSpec) -> Option<Duration> {
    entry
        .timeout
        .as_ref()
        .and_then(Lenient::valid)
        .map(|timeout| timeout.as_duration().to_std())
}

/// Turns how a scheduled check ended into its result.
fn map_end(
    info: &'static CheckInfo,
    spec_entry: &CheckSpec,
    ctx: &CheckContext,
    template: &CheckResult,
    ran: Ran,
    deadline: Duration,
) -> CheckResult {
    match ran.end {
        End::Done(outcome) => map_outcome(
            info,
            spec_entry,
            ctx,
            *outcome,
            millis(ran.started),
            millis(ran.elapsed),
        ),
        End::TimedOut { after } => timeout_result(template, after, ran.started),
        End::Panicked { .. } => panicked_result(template),
        End::RunDeadline => run_deadline_result(template, deadline),
        End::Cancelled => cancelled_result(template),
    }
}

/// Puts the user's own spelling of the spec file where the root fix says `<spec>`.
fn fill_spec_arg(result: &mut CheckResult, spec_arg: &str) {
    if let Some(fix) = &mut result.fix
        && fix.contains(SPEC_PLACEHOLDER)
    {
        *fix = fix.replace(SPEC_PLACEHOLDER, spec_arg);
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
