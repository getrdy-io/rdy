code-reviewer #58 (M1-040) at 6c5109c: CHANGES REQUIRED.
1 HIGH probe.rs:309,530, replay.rs:95-101: Backend::spawn(&Cmd) takes an unresolved command, so resolution and policy sit below the seam; ADR 0014 line 77 and 02 say policy sits above Backend and Replay drives all of it (a fixture can "run" sh or sudo). Backend never sees CheckInfo; #53's policy::Cmd needs declared extra_dirs, env, stdout_cap. Fix: Probe resolves through exec::policy (#53 prepare) and calls Backend::spawn(&ResolvedCmd); return Result<Output, ProbeError> is fine. Record change in 13-plan-corrections. One Cmd type (drop probe::Cmd duplicate of exec::policy::Cmd).
2 HIGH log.rs:253-256, tests.rs:454-465: same as sec F1 (coalesce; never drop denied; fallback last resort with tracing::warn; 13-plan-corrections entry amending 01 s5.4 and the exit test wording if needed).
3 MED probe.rs:546 `what` is the raw path; reaches result.message via CheckError::Probe (outcome.rs:216): home path leak. Use hub.log.display_path(path); test denied ~/.ssh/id_rsa read with with_home.
4 MED tests.rs:599-662 validate the exit test's JSON report against crates/rdy-spec/schema/result.v1.schema.json (workspace jsonschema dev-dep).
5 LOW tests.rs:654 identity assertion reads the 01 sample: remove or label (same as sec F6).
6 LOW probe.rs:432,452 end() is AtomicBool not cancellation token: in-flight call finishes and logs ok after check ended. Race a cancel signal against the backend call, or record deferral.
7 LOW policy.rs:81,112 refuse /dev for read only (allow stat/read_dir) [CONFLICTS with sec which approves /dev stat denial: coordinator decision: keep sec ruling, deny /dev for stat too in M1; M4 adds closed stat-only list]; add /etc/master.passwd (macOS) and /proc/*/cwd.
8 LOW tests.rs:540-551 test parses docs/plan/01 at run time; src/** is packaged; move the sample into a fixture under tests/fixtures.
9 NIT probe.rs:367-370 run_probe dead code on Windows: cfg not(all(test, feature = "runtime", unix)).
Correction-08 note: #53's exec::policy::run is public, ungated, writes no log entry: M1-044 should list it too, or make it pub(crate) once the live backend lands.
