//! The command table (SEC-18, INV-08): every external command a check may run, as typed data.
//!
//! This is 03 Appendix A in code. A [`CommandEntry`] is one program: its name, the absolute path the
//! appendix gives, the operating systems it runs on, the checks that use it, and the argument
//! [`Form`]s that are allowed. A [`Form`] is one argv shape with its own wall-clock limit, stdout cap
//! and exit-code meanings. Nothing else is a command: a program that is not here has no entry, and an
//! argument list that matches no form is refused.
//!
//! - **Typed arguments.** An [`Arg`] is a literal, a spec-derived [`Param`], or a literal prefix joined
//!   to a param (`--zone=<zone>`). A param passes its own validator before it reaches argv: a host
//!   name or a zone is `A-Za-z0-9._-` (zones without the dot), never empty, never longer than its
//!   cap, and never starts with `-`. So spec text cannot become an option.
//! - **Absolute path.** [`CommandEntry::path`] is the path 03 names. The policy still resolves the
//!   program by name from the fixed search path (see [`super::policy`]), because the same tool lives in
//!   `/usr/bin` or `/bin` depending on the distribution and a merged `/usr` makes them one file. The
//!   path is what reports and the security review read, and a test keeps it in a search directory (or
//!   in a declared extra directory) under the program's own name.
//! - **Extra directories and variables.** Only the GPU tools declare extra directories (03 section 6).
//!   No entry declares an environment variable: 03 gives every command the base environment and
//!   nothing else ([`CommandEntry::env`] is empty for all of them, and [`validate`] refuses a declared
//!   name that is not listed).
//! - **Windows.** The Windows rows are typed entries now. The policy runs only `whoami.exe` there until
//!   job objects land (M2-006), so [`validate`] accepts them and the policy runner still refuses
//!   the others.
//! - **Never listed.** A program that is refused by name ([`super::policy::is_refused_name`]) can not
//!   have an entry. A test walks the table to prove it.
//!
//! The probe builds commands with [`CommandEntry::cmd`] and runs them with [`run`], which calls
//! [`validate`] first. [`run`] is the only public command runner: the policy runner under it is
//! crate-private, so a command that is not in the table cannot start. A check crate that built its own
//! [`Cmd`] gets the same answer from [`validate`]. The entries and [`validate_for`] do not need the
//! `runtime` feature, so a probe gate without a runtime (replay) can refuse an unlisted command too.

use std::time::Duration;

use super::DEFAULT_STDOUT_CAP;
#[cfg(feature = "runtime")]
use super::ExecOutput;
#[cfg(feature = "runtime")]
use super::policy::CommandError;
use super::policy::{Cmd, WINDOWS_WHOAMI};
use crate::check::{Os, current_os};

#[cfg(test)]
mod tests;

/// The longest host name a param accepts, in bytes (the DNS limit).
pub const MAX_HOST_NAME_LEN: usize = 253;

/// The longest firewall zone name a param accepts, in bytes.
pub const MAX_ZONE_LEN: usize = 64;

/// A spec-derived argument and the rule it must pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Param {
    /// A name to resolve: `^[A-Za-z0-9._-]+$`, at most [`MAX_HOST_NAME_LEN`] bytes, no leading `-`.
    HostName,
    /// A firewalld zone: `^[A-Za-z0-9][A-Za-z0-9_-]*$`, at most [`MAX_ZONE_LEN`] bytes.
    Zone,
}

impl Param {
    /// The name used in messages and in the rendered form.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HostName => "name",
            Self::Zone => "zone",
        }
    }

    /// Checks one value.
    ///
    /// # Errors
    ///
    /// The reason the value is refused. The value itself is never echoed.
    pub fn validate(self, value: &str) -> Result<(), &'static str> {
        let (max, dot_ok) = match self {
            Self::HostName => (MAX_HOST_NAME_LEN, true),
            Self::Zone => (MAX_ZONE_LEN, false),
        };
        if value.is_empty() {
            return Err("it is empty");
        }
        if value.len() > max {
            return Err("it is too long");
        }
        if value.starts_with('-') {
            return Err("it starts with `-`, so a tool would read it as an option");
        }
        let plain =
            |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-' || (dot_ok && c == '.');
        if !value.chars().all(plain) {
            return Err("it has a character outside the allowed set");
        }
        if self == Self::Zone && !value.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            return Err("it must start with a letter or digit");
        }
        Ok(())
    }
}

/// One argument position of a [`Form`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Arg {
    /// Exactly this text.
    Lit(&'static str),
    /// A value from the caller that passes the [`Param`] rule.
    Param(Param),
    /// This text followed by a value that passes the rule, in one argv element (`--zone=<zone>`).
    Joined(&'static str, Param),
}

/// What an exit code means for a command. Any code a form does not list is a tool error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitClass {
    /// The command did its job.
    Ok,
    /// The thing asked about does not exist (`getent` exit 2).
    NotFound,
    /// The service the tool talks to is not running (`firewall-cmd` exit 252).
    NotRunning,
    /// A key is missing, which the caller treats as 0 (`sysctl` on an Intel Mac).
    KeyMissing,
}

/// One exit code and its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExitRule {
    /// The exit code.
    pub code: i32,
    /// What it means.
    pub class: ExitClass,
}

/// One allowed argv shape of a program, with its limits.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Form {
    /// A short id, unique within the entry.
    pub id: &'static str,
    /// The arguments after the program name.
    pub args: &'static [Arg],
    /// The wall-clock limit. A command may ask for less, never for more.
    pub timeout: Duration,
    /// The stdout cap in bytes. A command may ask for less, never for more.
    pub stdout_cap: usize,
    /// The exit codes with a meaning. Others are tool errors.
    pub exits: &'static [ExitRule],
}

impl Form {
    /// What an exit code means, or `None` for a tool error.
    #[must_use]
    pub fn classify(&self, code: i32) -> Option<ExitClass> {
        self.exits
            .iter()
            .find(|rule| rule.code == code)
            .map(|rule| rule.class)
    }

    /// The number of caller values this form takes.
    #[must_use]
    pub fn param_count(&self) -> usize {
        self.args
            .iter()
            .filter(|arg| matches!(arg, Arg::Param(_) | Arg::Joined(..)))
            .count()
    }

    /// The arguments as text, with params shown as `<name>`. Used by the docs check and by tests.
    #[must_use]
    pub fn render(&self) -> String {
        let parts: Vec<String> = self
            .args
            .iter()
            .map(|arg| match arg {
                Arg::Lit(text) => (*text).to_owned(),
                Arg::Param(param) => format!("<{}>", param.label()),
                Arg::Joined(prefix, param) => format!("{prefix}<{}>", param.label()),
            })
            .collect();
        parts.join(" ")
    }

    fn matches(&self, args: &[std::ffi::OsString]) -> Result<(), Mismatch> {
        if args.len() != self.args.len() {
            return Err(Mismatch::Shape);
        }
        for (want, got) in self.args.iter().zip(args) {
            let Some(got) = got.to_str() else {
                return Err(Mismatch::Shape);
            };
            match want {
                Arg::Lit(text) => {
                    if got != *text {
                        return Err(Mismatch::Shape);
                    }
                }
                Arg::Param(param) => {
                    param
                        .validate(got)
                        .map_err(|reason| Mismatch::Param(*param, reason))?;
                }
                Arg::Joined(prefix, param) => {
                    let Some(value) = got.strip_prefix(prefix) else {
                        return Err(Mismatch::Shape);
                    };
                    param
                        .validate(value)
                        .map_err(|reason| Mismatch::Param(*param, reason))?;
                }
            }
        }
        Ok(())
    }
}

enum Mismatch {
    Shape,
    Param(Param, &'static str),
}

/// One program in the table (03 Appendix A).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CommandEntry {
    /// The program name the policy resolves, a source constant.
    pub program: &'static str,
    /// The absolute path 03 names. Windows paths use `C:\Windows` for `%SystemRoot%`, the same
    /// constant the policy uses.
    pub path: &'static str,
    /// The operating systems the command runs on.
    pub os: &'static [Os],
    /// The check ids that use it (`gpu.*` stands for the family).
    pub checks: &'static [&'static str],
    /// Absolute directories searched after the fixed search path, for operator-managed tools.
    pub extra_dirs: &'static [&'static str],
    /// The only environment variable names a command may declare. Empty for every entry.
    pub env: &'static [&'static str],
    /// The allowed argv shapes.
    pub forms: &'static [Form],
}

impl CommandEntry {
    /// Whether the command runs on `os`.
    #[must_use]
    pub fn runs_on(&self, os: Os) -> bool {
        self.os.contains(&os)
    }

    /// The form with this id.
    #[must_use]
    pub fn form(&self, id: &str) -> Option<&'static Form> {
        self.forms.iter().find(|form| form.id == id)
    }

    /// Builds the command for a form on this machine's OS. `params` fill the form's [`Param`]
    /// positions in order.
    ///
    /// # Errors
    ///
    /// [`TableError`] when the entry does not run here, the form does not exist, the number of
    /// values is wrong, or a value fails its rule.
    pub fn cmd(&self, form: &str, params: &[&str]) -> Result<Cmd, TableError> {
        self.cmd_for(current_os(), form, params)
    }

    /// Like [`Self::cmd`], for an explicit OS. Tests use it to build a command for another OS.
    ///
    /// # Errors
    ///
    /// See [`Self::cmd`].
    pub fn cmd_for(&self, os: Os, form: &str, params: &[&str]) -> Result<Cmd, TableError> {
        if !self.runs_on(os) {
            return Err(TableError::NotOnThisOs {
                program: self.program,
            });
        }
        let form = self.form(form).ok_or(TableError::UnknownForm {
            program: self.program,
        })?;
        if form.param_count() != params.len() {
            return Err(TableError::ParamCount {
                program: self.program,
                want: form.param_count(),
                got: params.len(),
            });
        }
        let mut values = params.iter();
        let mut args: Vec<String> = Vec::with_capacity(form.args.len());
        for arg in form.args {
            match arg {
                Arg::Lit(text) => args.push((*text).to_owned()),
                Arg::Param(param) => {
                    let value = values.next().copied().unwrap_or_default();
                    param
                        .validate(value)
                        .map_err(|reason| TableError::BadParam {
                            program: self.program,
                            param: param.label(),
                            reason,
                        })?;
                    args.push(value.to_owned());
                }
                Arg::Joined(prefix, param) => {
                    let value = values.next().copied().unwrap_or_default();
                    param
                        .validate(value)
                        .map_err(|reason| TableError::BadParam {
                            program: self.program,
                            param: param.label(),
                            reason,
                        })?;
                    args.push(format!("{prefix}{value}"));
                }
            }
        }
        Ok(Cmd::new(self.program, form.timeout)
            .args(args)
            .extra_dirs(self.extra_dirs)
            .stdout_cap(form.stdout_cap))
    }
}

/// Why the table refused a command. Every message ends with what to do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TableError {
    /// The program has no entry.
    #[error(
        "`{program}` is not in the command table. Fix: add a typed entry for it to crates/rdy-engine/src/exec/table.rs and 03 Appendix A, with its security review"
    )]
    UnknownProgram {
        /// The name that was given.
        program: &'static str,
    },
    /// The entry exists for other operating systems.
    #[error(
        "`{program}` is not listed for this operating system. Fix: use the entry for this OS, or report the check as not applicable here"
    )]
    NotOnThisOs {
        /// The name that was given.
        program: &'static str,
    },
    /// The entry has no form with that id.
    #[error("`{program}` has no form with that id. Fix: use an id from the entry's forms")]
    UnknownForm {
        /// The name that was given.
        program: &'static str,
    },
    /// The caller gave a different number of values than the form takes.
    #[error(
        "`{program}` takes {want} value(s) for this form and got {got}. Fix: pass one value per `<param>`"
    )]
    ParamCount {
        /// The name that was given.
        program: &'static str,
        /// How many values the form takes.
        want: usize,
        /// How many were given.
        got: usize,
    },
    /// A value failed its rule.
    #[error(
        "the {param} given to `{program}` is refused: {reason}. Fix: use letters, digits and `-` `_` (and `.` in a name), starting with a letter or digit"
    )]
    BadParam {
        /// The name that was given.
        program: &'static str,
        /// Which value.
        param: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// The arguments match no form of the entry.
    #[error(
        "the arguments given to `{program}` match none of its allowed forms. Fix: build the command with `CommandEntry::cmd` and a form id"
    )]
    ArgsNotAllowed {
        /// The name that was given.
        program: &'static str,
    },
    /// The command asks for more time than the form allows.
    #[error(
        "the time limit for `{program}` is above the table's limit of {limit_secs}s. Fix: lower it"
    )]
    TimeoutTooLong {
        /// The name that was given.
        program: &'static str,
        /// The form's limit in seconds.
        limit_secs: u64,
    },
    /// The command asks for a bigger stdout cap than the form allows.
    #[error(
        "the stdout cap for `{program}` is above the table's limit of {limit} bytes. Fix: lower it"
    )]
    CapTooLarge {
        /// The name that was given.
        program: &'static str,
        /// The form's cap.
        limit: usize,
    },
    /// The command declares an environment variable the entry does not list.
    #[error(
        "`{program}` may not declare the environment variable `{name}`. Fix: remove it; 03 Appendix A gives every command the base environment only"
    )]
    EnvNotAllowed {
        /// The name that was given.
        program: &'static str,
        /// The variable name.
        name: &'static str,
    },
    /// The command declares a search directory the entry does not list.
    #[error(
        "`{program}` may not search `{dir}`. Fix: remove it; only the directories in the table are searched"
    )]
    DirNotAllowed {
        /// The name that was given.
        program: &'static str,
        /// The directory.
        dir: &'static str,
    },
}

/// A command that passed [`validate`]: its entry and the form it matched.
#[derive(Debug, Clone, Copy)]
pub struct Listed {
    /// The program's entry.
    pub entry: &'static CommandEntry,
    /// The form the arguments matched.
    pub form: &'static Form,
}

/// Every command a check may run (03 Appendix A), in the order of the appendix.
#[must_use]
pub fn entries() -> &'static [CommandEntry] {
    COMMANDS
}

/// The entry for a program name. The match is exact, except for Windows entries, where case does not
/// matter (`NETSTAT.EXE` and `netstat.exe` are one file there). On Unix `Getent` is not `getent`.
#[must_use]
pub fn entry(program: &str) -> Option<&'static CommandEntry> {
    COMMANDS.iter().find(|entry| {
        if entry.runs_on(Os::Windows) {
            entry.program.eq_ignore_ascii_case(program)
        } else {
            entry.program == program
        }
    })
}

/// Checks `cmd` against the table for this machine's OS.
///
/// # Errors
///
/// The first [`TableError`] the command earns.
pub fn validate(cmd: &Cmd) -> Result<Listed, TableError> {
    validate_for(current_os(), cmd)
}

/// Checks `cmd` against the table for `os`: the program has an entry that runs there, the arguments
/// match one form (spec-derived values pass their rules, so a leading `-` is refused), and the time
/// limit, stdout cap, search directories and environment names are within the entry.
///
/// # Errors
///
/// The first [`TableError`] the command earns.
pub fn validate_for(os: Os, cmd: &Cmd) -> Result<Listed, TableError> {
    let program = cmd.program();
    let entry = entry(program).ok_or(TableError::UnknownProgram { program })?;
    if !entry.runs_on(os) {
        return Err(TableError::NotOnThisOs { program });
    }
    let mut param_error = None;
    let mut matched = None;
    for form in entry.forms {
        match form.matches(cmd.arguments()) {
            Ok(()) => {
                matched = Some(form);
                break;
            }
            Err(Mismatch::Param(param, reason)) => {
                param_error.get_or_insert(TableError::BadParam {
                    program,
                    param: param.label(),
                    reason,
                });
            }
            Err(Mismatch::Shape) => {}
        }
    }
    let Some(form) = matched else {
        return Err(param_error.unwrap_or(TableError::ArgsNotAllowed { program }));
    };
    if cmd.time_limit() > form.timeout {
        return Err(TableError::TimeoutTooLong {
            program,
            limit_secs: form.timeout.as_secs(),
        });
    }
    if cmd.output_cap() > form.stdout_cap {
        return Err(TableError::CapTooLarge {
            program,
            limit: form.stdout_cap,
        });
    }
    if let Some(name) = cmd
        .declared_env_names()
        .find(|name| !entry.env.iter().any(|own| own.eq_ignore_ascii_case(name)))
    {
        return Err(TableError::EnvNotAllowed { program, name });
    }
    if let Some(dir) = cmd
        .declared_dirs()
        .iter()
        .find(|dir| !entry.extra_dirs.contains(dir))
    {
        return Err(TableError::DirNotAllowed { program, dir });
    }
    Ok(Listed { entry, form })
}

/// Runs `cmd` if the table lists it, then under the command policy. This is the only public way to run
/// a command: the policy runner is crate-private, so a check cannot skip the table.
///
/// # Errors
///
/// [`CommandError::Table`] when the table refuses, then [`CommandError::Policy`] or
/// [`CommandError::Exec`] from the policy and the runner.
#[cfg(feature = "runtime")]
pub async fn run(cmd: Cmd) -> Result<ExecOutput, CommandError> {
    validate(&cmd)?;
    super::policy::run(cmd).await
}

const ONE_MIB: usize = DEFAULT_STDOUT_CAP;
const GPU_XML_CAP: usize = 2 * 1024 * 1024;

const SECS_3: Duration = Duration::from_secs(3);
const SECS_5: Duration = Duration::from_secs(5);
const SECS_15: Duration = Duration::from_secs(15);
const SECS_30: Duration = Duration::from_secs(30);

const fn ok() -> ExitRule {
    ExitRule {
        code: 0,
        class: ExitClass::Ok,
    }
}

const EXIT_OK: &[ExitRule] = &[ok()];
const EXIT_GETENT: &[ExitRule] = &[
    ok(),
    ExitRule {
        code: 2,
        class: ExitClass::NotFound,
    },
];
const EXIT_FIREWALLD: &[ExitRule] = &[
    ok(),
    ExitRule {
        code: 252,
        class: ExitClass::NotRunning,
    },
];
const EXIT_SYSCTL_MAC: &[ExitRule] = &[
    ok(),
    ExitRule {
        code: 1,
        class: ExitClass::KeyMissing,
    },
];

/// A form with the default stdout cap and exit 0 only.
const fn form(id: &'static str, args: &'static [Arg], timeout: Duration) -> Form {
    Form {
        id,
        args,
        timeout,
        stdout_cap: ONE_MIB,
        exits: EXIT_OK,
    }
}

const fn lit(text: &'static str) -> Arg {
    Arg::Lit(text)
}

/// Where operator-managed NVIDIA tools live, after the fixed search path (03 section 6).
const GPU_DIRS: &[&str] = &[
    "/usr/local/nvidia/bin",
    "/usr/local/nvidia/toolkit",
    "/run/nvidia/driver/usr/bin",
    "/home/kubernetes/bin/nvidia",
    "/usr/lib/wsl/lib",
];

const LINUX: &[Os] = &[Os::Linux];
const MACOS: &[Os] = &[Os::Macos];
const WINDOWS: &[Os] = &[Os::Windows];

/// 03 Appendix A, one entry per program. The rows of the appendix are checked against this table by
/// `tests/command_table.rs`, and `docs/plan/03-check-catalog.md` is where a reviewer reads them.
static COMMANDS: &[CommandEntry] = &[
    CommandEntry {
        program: "getent",
        path: "/usr/bin/getent",
        os: LINUX,
        checks: &["net.dns"],
        extra_dirs: &[],
        env: &[],
        forms: &[Form {
            id: "ahosts",
            args: &[lit("ahosts"), lit("--"), Arg::Param(Param::HostName)],
            timeout: SECS_5,
            stdout_cap: ONE_MIB,
            exits: EXIT_GETENT,
        }],
    },
    CommandEntry {
        program: "timedatectl",
        path: "/usr/bin/timedatectl",
        os: LINUX,
        checks: &["host.time_sync"],
        extra_dirs: &[],
        env: &[],
        forms: &[
            form(
                "show",
                &[
                    lit("show"),
                    lit("-p"),
                    lit("NTPSynchronized"),
                    lit("-p"),
                    lit("NTP"),
                    lit("-p"),
                    lit("Timezone"),
                ],
                SECS_5,
            ),
            form("status", &[lit("status")], SECS_5),
        ],
    },
    CommandEntry {
        program: "chronyc",
        path: "/usr/bin/chronyc",
        os: LINUX,
        checks: &["host.time_sync"],
        extra_dirs: &[],
        env: &[],
        forms: &[form(
            "tracking",
            &[lit("-n"), lit("-c"), lit("-t"), lit("3"), lit("tracking")],
            SECS_5,
        )],
    },
    CommandEntry {
        program: "firewall-cmd",
        path: "/usr/bin/firewall-cmd",
        os: LINUX,
        checks: &["host.firewall"],
        extra_dirs: &[],
        env: &[],
        forms: &[
            Form {
                id: "state",
                args: &[lit("--state")],
                timeout: SECS_5,
                stdout_cap: ONE_MIB,
                exits: EXIT_FIREWALLD,
            },
            Form {
                id: "active-zones",
                args: &[lit("--get-active-zones")],
                timeout: SECS_5,
                stdout_cap: ONE_MIB,
                exits: EXIT_FIREWALLD,
            },
            Form {
                id: "list-all",
                args: &[lit("--list-all"), Arg::Joined("--zone=", Param::Zone)],
                timeout: SECS_5,
                stdout_cap: ONE_MIB,
                exits: EXIT_FIREWALLD,
            },
        ],
    },
    CommandEntry {
        program: "containerd",
        path: "/usr/bin/containerd",
        os: LINUX,
        checks: &["host.container_runtime"],
        extra_dirs: &[],
        env: &[],
        forms: &[form("version", &[lit("--version")], SECS_3)],
    },
    CommandEntry {
        program: "crio",
        path: "/usr/bin/crio",
        os: LINUX,
        checks: &["host.container_runtime"],
        extra_dirs: &[],
        env: &[],
        forms: &[form("version", &[lit("--version")], SECS_3)],
    },
    CommandEntry {
        program: "scutil",
        path: "/usr/sbin/scutil",
        os: MACOS,
        checks: &["net.proxy", "net.dns"],
        extra_dirs: &[],
        env: &[],
        forms: &[
            form("proxy", &[lit("--proxy")], SECS_5),
            form("dns", &[lit("--dns")], SECS_5),
        ],
    },
    CommandEntry {
        program: "netstat",
        path: "/usr/sbin/netstat",
        os: MACOS,
        checks: &["host.ports"],
        extra_dirs: &[],
        env: &[],
        forms: &[
            form("tcp", &[lit("-anv"), lit("-p"), lit("tcp")], SECS_5),
            form("udp", &[lit("-anv"), lit("-p"), lit("udp")], SECS_5),
        ],
    },
    CommandEntry {
        program: "sysctl",
        path: "/usr/sbin/sysctl",
        os: MACOS,
        checks: &["host.cpu"],
        extra_dirs: &[],
        env: &[],
        forms: &[Form {
            id: "rosetta",
            args: &[
                lit("-n"),
                lit("sysctl.proc_translated"),
                lit("hw.optional.arm64"),
            ],
            timeout: SECS_3,
            stdout_cap: ONE_MIB,
            exits: EXIT_SYSCTL_MAC,
        }],
    },
    CommandEntry {
        program: "NETSTAT.EXE",
        path: r"C:\Windows\System32\NETSTAT.EXE",
        os: WINDOWS,
        checks: &["host.ports"],
        extra_dirs: &[],
        env: &[],
        forms: &[form("ano", &[lit("-ano")], SECS_5)],
    },
    CommandEntry {
        program: "netsh.exe",
        path: r"C:\Windows\System32\netsh.exe",
        os: WINDOWS,
        checks: &["host.ports"],
        extra_dirs: &[],
        env: &[],
        forms: &[form(
            "excluded-port-range",
            &[
                lit("int"),
                lit("ipv4"),
                lit("show"),
                lit("excludedportrange"),
                lit("protocol=tcp"),
            ],
            SECS_5,
        )],
    },
    CommandEntry {
        program: "nvidia-smi",
        path: "/usr/bin/nvidia-smi",
        os: LINUX,
        checks: &["gpu.*"],
        extra_dirs: GPU_DIRS,
        env: &[],
        forms: &[
            Form {
                id: "query-xml",
                args: &[lit("-q"), lit("-x")],
                timeout: SECS_30,
                stdout_cap: GPU_XML_CAP,
                exits: EXIT_OK,
            },
            form("nvlink", &[lit("nvlink"), lit("-s")], SECS_15),
            form("topo", &[lit("topo"), lit("-m")], SECS_15),
            form(
                "compute-cap",
                &[
                    lit("--query-gpu=index,compute_cap"),
                    lit("--format=csv,noheader"),
                ],
                SECS_15,
            ),
        ],
    },
    CommandEntry {
        program: "nvidia-smi.exe",
        path: r"C:\Windows\System32\nvidia-smi.exe",
        os: WINDOWS,
        checks: &["gpu.*"],
        extra_dirs: &[],
        env: &[],
        forms: &[Form {
            id: "query-xml",
            args: &[lit("-q"), lit("-x")],
            timeout: SECS_30,
            stdout_cap: GPU_XML_CAP,
            exits: EXIT_OK,
        }],
    },
    CommandEntry {
        program: "nvidia-ctk",
        path: "/usr/bin/nvidia-ctk",
        os: LINUX,
        checks: &["gpu.runtime"],
        extra_dirs: GPU_DIRS,
        env: &[],
        forms: &[form("version", &[lit("--version")], SECS_5)],
    },
    CommandEntry {
        program: "nvcc",
        path: "/usr/local/cuda/bin/nvcc",
        os: LINUX,
        checks: &["gpu.cuda"],
        extra_dirs: &["/usr/local/cuda/bin"],
        env: &[],
        forms: &[form("version", &[lit("--version")], SECS_5)],
    },
    CommandEntry {
        program: "nv-fabricmanager",
        path: "/usr/bin/nv-fabricmanager",
        os: LINUX,
        checks: &["gpu.fabric"],
        extra_dirs: GPU_DIRS,
        env: &[],
        forms: &[form("version", &[lit("-v")], SECS_5)],
    },
    CommandEntry {
        program: "whoami.exe",
        path: WINDOWS_WHOAMI,
        os: WINDOWS,
        checks: &["engine.root"],
        extra_dirs: &[],
        env: &[],
        forms: &[form(
            "groups",
            &[lit("/groups"), lit("/fo"), lit("csv")],
            SECS_5,
        )],
    },
];
