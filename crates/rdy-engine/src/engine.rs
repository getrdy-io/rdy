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
use rdy_spec::result::{Capability, CheckResult};
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
use crate::sched::{DEFAULT_DEADLINE, DEFAULT_JOBS, End, Planned, Scheduler};

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
    /// fix of a check that needs root.
    pub spec_arg: String,
    /// The instant the deadline is counted from. `None` counts from the start of the run.
    pub origin: Option<std::time::Instant>,
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
            let PlanAction::Run(built) = entry.action else {
                continue;
            };
            let Some(spec_entry) = spec.spec().checks.get(entry.index) else {
                continue;
            };
            let info = built.check.info();
            let ctx = CheckContext::new(entry.key.clone(), os, available.iter().cloned());
            let mut run = Planned::new(Arc::from(built.check), entry.key);
            if let Some(timeout) = spec_timeout(spec_entry) {
                run = run.with_timeout(timeout);
            }
            slots.push(Slot::Ran(items.len()));
            planned.push(run);
            items.push(Item {
                info,
                spec_entry,
                ctx,
            });
        }

        let mut scheduler = Scheduler::new(options.jobs, os, available)
            .with_deadline(options.deadline)
            .with_probes(self.hub.clone());
        if let Some(origin) = options.origin {
            scheduler = scheduler.with_origin(origin);
        }
        let ran = scheduler.run(planned).await;

        let mapped: Vec<CheckResult> = items
            .iter()
            .zip(ran)
            .map(|(item, ran)| {
                let template = item.template();
                match ran.end {
                    End::Done(outcome) => map_outcome(
                        item.info,
                        item.spec_entry,
                        &item.ctx,
                        *outcome,
                        millis(ran.started),
                        millis(ran.elapsed),
                    ),
                    End::TimedOut { after } => timeout_result(&template, after, ran.started),
                    End::Panicked { .. } => panicked_result(&template),
                    End::RunDeadline => run_deadline_result(&template, options.deadline),
                    End::Cancelled => cancelled_result(&template),
                }
            })
            .collect();

        let redactor = self.hub.redactor();
        let mut counts = RuleCounts::default();
        let results = slots
            .into_iter()
            .filter_map(|slot| {
                let mut result = match slot {
                    Slot::Skipped(result) => *result,
                    // `slots`, `items` and `mapped` are built together, so a miss cannot happen. If it
                    // did, the check would count as not run, never as passed.
                    Slot::Ran(at) => match mapped.get(at) {
                        Some(result) => result.clone(),
                        None => unfinished_result(&items.get(at)?.template()),
                    },
                };
                fill_spec_arg(&mut result, &options.spec_arg);
                Some(match redactor.redact_check(result.clone(), &mut counts) {
                    Ok(redacted) => (*redacted).clone(),
                    // The result no longer read as a result. Keep none of its text.
                    Err(_) => unfinished_result(&result),
                })
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
    /// The scheduler ran it, at this position of its list.
    Ran(usize),
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
