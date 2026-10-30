//! The command policy (SEC-18, INV-08): what may run, from where, with what environment.
//!
//! The facade runs a [`Cmd`] through `table::run`, which checks the command table first. Nothing here trusts the caller's environment.
//!
//! - **Program names are constants.** [`Cmd::new`] takes a `&'static str`, so spec text cannot name a
//!   program. The name must be a plain file name, with no separator.
//! - **Fixed search path.** A name resolves from [`SEARCH_PATH`] (`/usr/sbin:/usr/bin:/sbin:/bin`) on
//!   every run, root or not. The parent's `PATH` is never read. Only after those four directories does
//!   it try the check's declared extra directories ([`Cmd::extra_dirs`]), which are absolute constants
//!   for operator-managed tools. An extra directory can never shadow a system tool.
//! - **Refusals.** Three groups never run, by name: shells (`sh`, `bash`, `zsh`, `dash`, `cmd`,
//!   `powershell`, `pwsh` and a few more), the privilege tools (`sudo`, `su`, `doas`, `pkexec`, `runas`,
//!   `run0`, `sudoedit`, `runuser`, `setpriv`, `sg`, `newgrp`, `ksu`, `machinectl`, `systemd-run`) and
//!   the programs that run another program or take code in their arguments (`env`, `xargs`, `nice`,
//!   `nohup`, `timeout`, `time`, `setsid`, `setarch`, `chroot`, `nsenter`, `unshare`, `stdbuf`,
//!   `taskset`, `flock`, `strace`, `gdb`, `bwrap`, `awk`, `python3`, `perl` and more).
//!   See [`REFUSED_PROGRAMS`] and [`REFUSED_PROGRAM_PREFIXES`]. The check is on the name and on the file the name resolves to, so a
//!   link named `tool` that points at `bash` is refused too. The multi-call binaries `busybox` and
//!   `toybox` are refused by the name a check asks for and not by the file it resolves to: on a
//!   system built from one, every tool is a link to it, and the applet is picked by `argv[0]`, which
//!   is the requested name, so a link cannot become a shell. Arguments go to the program as argv, so
//!   no shell parses spec text.
//! - **Trust.** The name resolves to a real path one component at a time. Every link on the way, and
//!   the file, and every directory above them up to `/`, must be owned by root or by the user `rdy`
//!   runs as, and none may be writable by the group or by others. The directory that holds a link is
//!   judged like the directory that holds the file: whoever can write there can re-point the link.
//!   A writable directory with the sticky bit (like `/tmp`) is accepted only above that directory,
//!   never as the holder of the file or a link. More than 40 links, or anything that cannot be read,
//!   is refused. The program starts from the real path with `argv[0]` set to the name.
//! - **Environment.** Cleared, then the base variables and the declared names. On Unix the base is
//!   `LC_ALL=C` and the fixed `PATH`; on Windows it is `SystemRoot` and `PATH` set to constants. `LD_*`,
//!   `DYLD_*`, `MALLOC_*`, `PYTHON*` and a list of other variables that change how a program loads
//!   code, resolves names or starts helpers are refused as declared names (see [`PolicyError::RefusedEnv`]).
//!   The parent's `LD_PRELOAD` never reaches a child because the parent's environment is never copied.
//! - **Caps.** Stdout defaults to 1 MiB and is at most 4 MiB. Stderr is 64 KiB.
//! - **The command table.** This module says what can never run. [`super::table`] says what may: the
//!   typed entries of 03 Appendix A, each with its argument forms, limits and exit-code meanings.
//!   [`Cmd`] does not require a table entry, so the policy tests can run `true`. The probe runs
//!   commands through `table::run`, which checks the table first.
//! - **Windows.** In M1 only `C:\Windows\System32\whoami.exe` runs, until job objects land (M2-006).
//!
//! Resolution and start are two steps. The trust rule above makes the gap small, because no one but
//! root and the running user can change a directory on the path. It does not close it against a
//! process of the running user itself.

// Without the `runtime` feature the name rules and the command type compile and the resolver does not,
// so the helpers that only the resolver calls are unused there.
#![cfg_attr(not(feature = "runtime"), allow(dead_code))]

use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use super::DEFAULT_STDOUT_CAP;
#[cfg(feature = "runtime")]
use super::{DEFAULT_STDERR_CAP, ExecError, ExecOutput, ExecSpec};

#[cfg(test)]
mod tests;

/// The fixed search path, in order. The same string is the child's `PATH`.
pub const SEARCH_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// The directories of [`SEARCH_PATH`], in order.
pub const SEARCH_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// The only program that runs on Windows in M1.
pub const WINDOWS_WHOAMI: &str = r"C:\Windows\System32\whoami.exe";

/// The most stdout a command may keep: 4 MiB (02, "Exec").
pub const MAX_STDOUT_CAP: usize = 4 * 1024 * 1024;

/// Programs that never run, by name without extension and in lower case: shells, the tools that raise
/// privilege, and the programs that run another program from their arguments.
pub const REFUSED_PROGRAMS: &[&str] = &[
    // Shells and command interpreters.
    "sh",
    "bash",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "hush",
    "msh",
    "mksh",
    "yash",
    "rbash",
    "posh",
    "oksh",
    "loksh",
    "cmd",
    "powershell",
    "pwsh",
    // Privilege tools.
    "sudo",
    "su",
    "doas",
    "pkexec",
    "runas",
    "run0",
    "sudoedit",
    "runuser",
    "setpriv",
    "sg",
    "newgrp",
    "ksu",
    "machinectl",
    "systemd-run",
    // Programs that run another program from their arguments. A spec-controlled argument would
    // reach a shell through them.
    "env",
    "xargs",
    "nice",
    "nohup",
    "timeout",
    "setsid",
    "chroot",
    "nsenter",
    "unshare",
    "stdbuf",
    "taskset",
    "ionice",
    "chrt",
    "numactl",
    "prlimit",
    "flock",
    "watch",
    "capsh",
    "script",
    "strace",
    "ltrace",
    "gdb",
    "cgexec",
    "bwrap",
    "firejail",
    "systemd-nspawn",
    // Programs that take code or a whole command line in their arguments (M1-066). `time`,
    // `setarch`, `linux32`, `linux64`, `chpst`, `start-stop-daemon` and `run-parts` run another
    // program. The interpreters run text that a spec-controlled argument could carry (`python3 -c`,
    // `perl -e`, `awk 'BEGIN{system(..)}'`). Versioned names such as `python3.12` are caught by
    // [`REFUSED_PROGRAM_PREFIXES`].
    "time",
    "setarch",
    "linux32",
    "linux64",
    "chpst",
    "start-stop-daemon",
    "run-parts",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "node",
    "expect",
    "osascript",
    // Programs that run a command from their arguments, or edit or fetch files, and that no catalog
    // check needs (M1-066 review). `find -exec`, `sed e`, `m4 syscmd`, `dc !`, `ed !`, `ex` and `vi`
    // and `vim` (`:!`), `ssh` (`ProxyCommand`), `git` (hooks, aliases), `tar --to-command`, `rsync -e`,
    // `make`, `perf`, `valgrind`, `lldb`, `faketime`, `fakeroot`, `unbuffer`, `parallel`, `sqlite3`
    // (`.shell`), `bpftrace`, and the language runtimes `java`, `jshell`, `irb`, `jruby`, `deno`, `bun`.
    "find",
    "sed",
    "m4",
    "dc",
    "ed",
    "ex",
    "vi",
    "vim",
    "ip",
    "ssh",
    "git",
    "tar",
    "rsync",
    "make",
    "perf",
    "valgrind",
    "lldb",
    "faketime",
    "fakeroot",
    "unbuffer",
    "parallel",
    "sqlite3",
    "bpftrace",
    "java",
    "jshell",
    "irb",
    "jruby",
    "deno",
    "bun",
    // Container clients. They run a command in a container, and the Docker socket has its own
    // GET-only guard in M2.
    "docker",
    "podman",
    "nerdctl",
    "ctr",
    "crictl",
    // macOS and Windows tools that run another program or a script.
    "arch",
    "caffeinate",
    "launchctl",
    "sandbox-exec",
    "xcrun",
    "cscript",
    "wscript",
    "mshta",
    "rundll32",
    "forfiles",
    "wsl",
    // Network relays and file copiers that open a connection or run a command (`socat EXEC:`,
    // `nc -e`, `scp -S`, `sftp -S`), and `emacs`, which runs code (`--eval`) (M1-066 final review).
    "socat",
    "nc",
    "ncat",
    "scp",
    "sftp",
    "emacs",
];

/// Prefixes of refused program names, in lower case: the interpreters, whatever version suffix the
/// distribution gives them (`python3.12`, `perl5.36.0`, `ruby3.2`, `lua5.4`, `php8.2`, `pypy3`), and
/// the dynamic loaders (`ld-linux-x86-64.so.2`, `ld-musl-x86_64.so.1`, `ld.so.1`, `ld64.so.1`,
/// `ld-2.31.so`), which run any file given as
/// the first argument.
pub const REFUSED_PROGRAM_PREFIXES: &[&str] = &[
    "python", "pypy", "perl", "ruby", "lua", "php", "tclsh", "nodejs", "ld-linux", "ld-musl",
    "ld.so", "ld64.so", "ld-2",
];

/// Multi-call binaries. Refused by the name a check asks for, never by the file a name resolves to:
/// on a system built from one, `ls` and `cat` are links to it, and refusing the target would refuse
/// every tool. The applet is picked by `argv[0]`, which is the requested name, so a link cannot turn
/// into `busybox sh -c`. A check that names `busybox` itself is the one that could.
const REFUSED_BY_REQUESTED_NAME: &[&str] = &["busybox", "toybox"];

/// Variables that change how a program loads code, resolves names or starts helpers. Refused as
/// declared names, in upper case. The prefixes in `REFUSED_ENV_PREFIXES` are refused as well.
const REFUSED_ENV: &[&str] = &[
    // Set by the policy.
    "PATH",
    "LC_ALL",
    "SYSTEMROOT",
    // The C library and the resolver.
    "GCONV_PATH",
    "GETCONF_DIR",
    "GLIBC_TUNABLES",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "NIS_PATH",
    "NLSPATH",
    "RES_OPTIONS",
    "RESOLV_HOST_CONF",
    "TZDIR",
    // Shells and shell startup.
    "BASH_ENV",
    "BASHOPTS",
    "CDPATH",
    "ENV",
    "IFS",
    "PROMPT_COMMAND",
    "PS4",
    "SHELLOPTS",
    "ZDOTDIR",
    // TLS libraries.
    "OPENSSL_CONF",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    // Language runtimes.
    "LUA_INIT",
    "LUA_PATH",
    "LUA_CPATH",
    "PERLLIB",
    "PERL5DB",
    "NODE_PATH",
    "DOTNET_STARTUP_HOOKS",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "COMSPEC",
    "PATHEXT",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "NODE_OPTIONS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    // Helpers a program starts on its own.
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "BROWSER",
    "TERMINFO",
    "TERMINFO_DIRS",
    "KUBECONFIG",
    "LESSOPEN",
    "PAGER",
    "EDITOR",
    "VISUAL",
    "SYSTEMD_PAGER",
    // GPU tooling.
    "CUDA_INJECTION64_PATH",
];

/// Prefixes of refused variable names, in upper case.
const REFUSED_ENV_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "MALLOC_",
    "PYTHON",
    "GIT_",
    "CORECLR_PROFILER",
];

/// The `SystemRoot` a Windows child gets.
pub const WINDOWS_SYSTEM_ROOT: &str = r"C:\Windows";

/// The `PATH` a Windows child gets.
pub const WINDOWS_PATH: &str = r"C:\Windows\System32";

const MAX_NAME_LEN: usize = 64;

/// Why the policy refused a command. Every message ends with what to do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The program is not a plain file name.
    #[error("`{program}` is not a plain program name. Fix: pass a bare name such as `getenforce`")]
    InvalidProgram {
        /// The name that was given.
        program: &'static str,
    },
    /// A shell or a privilege tool.
    #[error(
        "`{program}` is refused: shells and privilege tools never run. Fix: run the tool itself with its own arguments"
    )]
    Refused {
        /// The name that was given.
        program: &'static str,
    },
    /// No directory of the search path or the declared directories has it.
    #[error(
        "`{program}` was not found in {SEARCH_PATH} or the declared directories. Fix: install it, or let the check report it as missing"
    )]
    NotFound {
        /// The name that was given.
        program: &'static str,
    },
    /// The file was found but is writable by everyone, or its directory is.
    #[error(
        "`{program}` was found in a directory or as a file that anyone can write. Fix: change its mode to 0755 or stricter"
    )]
    Untrusted {
        /// The name that was given.
        program: &'static str,
    },
    /// A declared directory is not an absolute path made of plain components.
    #[error(
        "the declared directory `{dir}` is not an absolute path. Fix: declare a path such as `/opt/tools/bin`"
    )]
    InvalidDir {
        /// The directory that was given.
        dir: &'static str,
    },
    /// A declared environment name is empty, too long or has characters outside `A-Z a-z 0-9 _`.
    #[error("the environment name `{name}` is not valid. Fix: use letters, digits and `_`")]
    InvalidEnv {
        /// The name that was given.
        name: &'static str,
    },
    /// A declared environment name is one the policy sets itself or one that changes program loading.
    #[error(
        "the environment name `{name}` is refused. Fix: remove it; the policy sets the search path itself and refuses names that change how programs load code, such as `LD_*`, `DYLD_*` and `PYTHON*`"
    )]
    RefusedEnv {
        /// The name that was given.
        name: &'static str,
    },
    /// The same environment name was declared twice.
    #[error("the environment name `{name}` is declared twice. Fix: declare it once")]
    DuplicateEnv {
        /// The name that was given.
        name: &'static str,
    },
    /// The stdout cap is above [`MAX_STDOUT_CAP`].
    #[error("the stdout cap {cap} is above the limit of {MAX_STDOUT_CAP} bytes. Fix: lower it")]
    CapTooLarge {
        /// The cap that was given.
        cap: usize,
    },
    /// Windows runs only `whoami` in M1.
    #[error(
        "`{program}` does not run on Windows in this version. Fix: only `whoami.exe` is allowed until job objects land"
    )]
    NotAllowedOnWindows {
        /// The name that was given.
        program: &'static str,
    },
}

/// Why a command gave no output: the table or the policy said no, or the runner failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommandError {
    /// The command was refused before anything started.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The command is not in the command table (03 Appendix A), or does not fit its entry.
    #[error(transparent)]
    Table(#[from] super::table::TableError),
    /// The command was allowed and failed to run to the end.
    #[cfg(feature = "runtime")]
    #[error(transparent)]
    Exec(#[from] ExecError),
}

/// One command, as a check asks for it. Build it with [`super::table::CommandEntry::cmd`], then run it
/// with `table::run`.
#[derive(Clone)]
pub struct Cmd {
    program: &'static str,
    args: Vec<OsString>,
    extra_dirs: &'static [&'static str],
    env: Vec<(&'static str, OsString)>,
    timeout: Duration,
    stdout_cap: usize,
}

impl fmt::Debug for Cmd {
    /// Prints environment variable names only. Values can be secrets and never reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(name, _)| *name).collect();
        f.debug_struct("Cmd")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("extra_dirs", &self.extra_dirs)
            .field("env_names", &names)
            .field("timeout", &self.timeout)
            .field("stdout_cap", &self.stdout_cap)
            .finish()
    }
}

impl Cmd {
    /// A command by program name, with no arguments, no declared directories or variables, and the
    /// default caps. The name is a source constant.
    #[must_use]
    pub fn new(program: &'static str, timeout: Duration) -> Self {
        Self {
            program,
            args: Vec::new(),
            extra_dirs: &[],
            env: Vec::new(),
            timeout,
            stdout_cap: DEFAULT_STDOUT_CAP,
        }
    }

    /// Sets the arguments. They go to the program as argv. No shell sees them.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Declares absolute directories to search after [`SEARCH_DIRS`], for operator-managed tools.
    #[must_use]
    pub fn extra_dirs(mut self, dirs: &'static [&'static str]) -> Self {
        self.extra_dirs = dirs;
        self
    }

    /// Declares environment variables for the child. Names are constants; values may come from the
    /// spec or the host. The child gets nothing else but the base variables (`LC_ALL` and `PATH` on
    /// Unix, `SystemRoot` and `PATH` on Windows).
    #[must_use]
    pub fn env<I, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, V)>,
        V: Into<OsString>,
    {
        self.env = vars
            .into_iter()
            .map(|(name, value)| (name, value.into()))
            .collect();
        self
    }

    /// Sets how many bytes of stdout to keep. At most [`MAX_STDOUT_CAP`].
    #[must_use]
    pub fn stdout_cap(mut self, bytes: usize) -> Self {
        self.stdout_cap = bytes;
        self
    }

    /// The program name this command asks for.
    #[must_use]
    pub fn program(&self) -> &'static str {
        self.program
    }

    /// The arguments, as set.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    /// The wall-clock limit.
    #[must_use]
    pub fn time_limit(&self) -> Duration {
        self.timeout
    }

    /// The stdout cap in bytes.
    #[must_use]
    pub fn output_cap(&self) -> usize {
        self.stdout_cap
    }

    /// The declared extra search directories.
    #[must_use]
    pub fn declared_dirs(&self) -> &'static [&'static str] {
        self.extra_dirs
    }

    /// The declared environment variable names. Never the values.
    pub fn declared_env_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.env.iter().map(|(name, _)| *name)
    }
}

/// Checks `cmd` against the policy and turns it into a runnable [`ExecSpec`].
///
/// # Errors
///
/// A [`PolicyError`] for the first rule the command breaks.
#[cfg(feature = "runtime")]
pub(crate) fn prepare(cmd: &Cmd) -> Result<ExecSpec, PolicyError> {
    check_name(cmd.program)?;
    check_env(&cmd.env)?;
    if cmd.stdout_cap > MAX_STDOUT_CAP {
        return Err(PolicyError::CapTooLarge {
            cap: cmd.stdout_cap,
        });
    }
    let path = resolve(cmd.program, cmd.extra_dirs)?;

    let mut env = base_env();
    env.extend(
        cmd.env
            .iter()
            .map(|(name, value)| (OsString::from(*name), value.clone())),
    );
    #[allow(
        clippy::disallowed_methods,
        reason = "the policy is the one place that builds the raw spec, after its checks. `allow`, not `expect`: the lint path exists only in builds with the `testing` feature"
    )]
    let spec = ExecSpec::new(path, cmd.timeout);
    Ok(spec
        .arg0(cmd.program)
        .args(cmd.args.iter().cloned())
        .env(env)
        .caps(cmd.stdout_cap, DEFAULT_STDERR_CAP))
}

/// The variables every child gets before the declared ones.
#[cfg(feature = "runtime")]
fn base_env() -> Vec<(OsString, OsString)> {
    #[cfg(unix)]
    {
        vec![
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("PATH"), OsString::from(SEARCH_PATH)),
        ]
    }
    #[cfg(not(unix))]
    {
        // Windows programs need `SystemRoot`. A Unix `PATH` would mean nothing there.
        vec![
            (
                OsString::from("SystemRoot"),
                OsString::from(WINDOWS_SYSTEM_ROOT),
            ),
            (OsString::from("PATH"), OsString::from(WINDOWS_PATH)),
        ]
    }
}

#[cfg(feature = "runtime")]
/// Runs `cmd` under the policy: checks it, resolves the program, and starts it with the process runner.
///
/// # Errors
///
/// [`CommandError::Policy`] when the policy refuses, [`CommandError::Exec`] for start, timeout and
/// read failures.
pub(crate) async fn run(cmd: Cmd) -> Result<ExecOutput, CommandError> {
    let spec = prepare(&cmd)?;
    #[allow(
        clippy::disallowed_methods,
        reason = "the policy runner is the one caller of the raw runner, after the policy checks. `allow`, not `expect`: the lint path exists only in builds with the `testing` feature"
    )]
    let running = super::runner::run(spec);
    Ok(running.await?)
}

/// The shape and refusal checks on a program name.
fn check_name(program: &'static str) -> Result<(), PolicyError> {
    let plain = !program.is_empty()
        && program.len() <= MAX_NAME_LEN
        && program.starts_with(|c: char| c.is_ascii_alphanumeric())
        && program
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'));
    if !plain {
        return Err(PolicyError::InvalidProgram { program });
    }
    let stem = stem(program);
    if is_refused(&stem) || REFUSED_BY_REQUESTED_NAME.contains(&stem.as_str()) {
        return Err(PolicyError::Refused { program });
    }
    Ok(())
}

/// Lower case, without a trailing `.exe`.
pub(crate) fn stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
}

fn is_refused(stem: &str) -> bool {
    REFUSED_PROGRAMS.contains(&stem)
        || REFUSED_PROGRAM_PREFIXES
            .iter()
            .any(|prefix| stem.starts_with(prefix))
}

/// Whether a program name is refused by name: a shell, a privilege tool, a program that runs another
/// program or takes code in its arguments, or a multi-call binary. Case and a `.exe` suffix do not
/// matter. The command table uses it to keep such names out of the list.
#[must_use]
pub fn is_refused_name(program: &str) -> bool {
    let stem = stem(program);
    is_refused(&stem) || REFUSED_BY_REQUESTED_NAME.contains(&stem.as_str())
}

fn check_env(vars: &[(&'static str, OsString)]) -> Result<(), PolicyError> {
    for (index, (name, _)) in vars.iter().enumerate() {
        let name: &'static str = name;
        let valid = !name.is_empty()
            && name.len() <= MAX_NAME_LEN
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(PolicyError::InvalidEnv { name });
        }
        let upper = name.to_ascii_uppercase();
        if REFUSED_ENV_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
            || REFUSED_ENV.contains(&upper.as_str())
        {
            return Err(PolicyError::RefusedEnv { name });
        }
        let duplicate = vars
            .iter()
            .take(index)
            .any(|(earlier, _)| earlier.eq_ignore_ascii_case(name));
        if duplicate {
            return Err(PolicyError::DuplicateEnv { name });
        }
    }
    Ok(())
}

/// A declared directory must be absolute and spelled plainly: no `.`, no `..`, no empty segment.
/// `Path::components` hides `.` and `//`, so the text is checked as well.
pub(crate) fn check_dir(dir: &'static str) -> Result<PathBuf, PolicyError> {
    let path = Path::new(dir);
    let spelled_plainly = dir
        .split(['/', '\\'])
        .skip(1)
        .all(|part| !part.is_empty() && part != "." && part != "..");
    let plain = path.is_absolute()
        && spelled_plainly
        && path.components().all(|part| {
            matches!(
                part,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        });
    if plain {
        Ok(path.to_path_buf())
    } else {
        Err(PolicyError::InvalidDir { dir })
    }
}

/// Windows M1: the one constant path, whatever spelling of `whoami` was asked for.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_program(program: &'static str) -> Result<PathBuf, PolicyError> {
    if stem(program) == "whoami" {
        Ok(PathBuf::from(WINDOWS_WHOAMI))
    } else {
        Err(PolicyError::NotAllowedOnWindows { program })
    }
}

#[cfg(all(not(unix), feature = "runtime"))]
fn resolve(program: &'static str, extra: &'static [&'static str]) -> Result<PathBuf, PolicyError> {
    for dir in extra {
        check_dir(dir)?;
    }
    windows_program(program)
}

#[cfg(all(unix, feature = "runtime"))]
fn resolve(program: &'static str, extra: &'static [&'static str]) -> Result<PathBuf, PolicyError> {
    let mut dirs: Vec<PathBuf> = SEARCH_DIRS.iter().map(PathBuf::from).collect();
    for dir in extra {
        dirs.push(check_dir(dir)?);
    }
    resolve_in(program, &dirs)
}

/// The first directory in `dirs` that holds an executable `program`, as a real path that passed the
/// trust rule. The order is the whole policy: the caller puts the fixed directories first.
///
/// A candidate that exists but cannot be resolved, or whose real name is a refused program, or whose
/// file, links or directories are not trusted, ends the search with an error. It does not fall through
/// to a later directory.
#[cfg(all(unix, feature = "runtime"))]
fn resolve_in(program: &'static str, dirs: &[PathBuf]) -> Result<PathBuf, PolicyError> {
    use std::os::unix::fs::PermissionsExt;
    for dir in dirs {
        let candidate = dir.join(program);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        // A link named like a harmless tool must not lead to a shell, and the trust rule is about the
        // file that runs, not the link. Failing to find the real path is a refusal.
        let real = real_path_checked(&candidate).ok_or(PolicyError::Untrusted { program })?;
        if real
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| is_refused(&stem(name)))
        {
            return Err(PolicyError::Refused { program });
        }
        if !is_trusted(&real) {
            return Err(PolicyError::Untrusted { program });
        }
        return Ok(real);
    }
    Err(PolicyError::NotFound { program })
}

/// The most links followed while resolving one candidate. The same bound as the kernel's.
#[cfg(all(unix, feature = "runtime"))]
const MAX_LINK_HOPS: usize = 40;

/// Resolves `path` to a real path one component at a time, like `realpath`, and applies the directory
/// rule to the directory that holds every link it follows. A link is only as safe as the directory
/// that holds it: someone who can write there can point it anywhere. `None` means a component is
/// missing, a link could not be read, there were more than [`MAX_LINK_HOPS`] links, or a directory
/// holding a link is not trusted.
#[cfg(all(unix, feature = "runtime"))]
fn real_path_checked(path: &Path) -> Option<PathBuf> {
    use std::collections::VecDeque;
    let euid = rustix::process::geteuid().as_raw();
    let mut pending: VecDeque<std::ffi::OsString> = path
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    let mut real = PathBuf::new();
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        if part == "/" {
            real = PathBuf::from("/");
        } else if part == "." {
            continue;
        } else if part == ".." {
            // `real` holds no links, so removing its last name is the true parent.
            real.pop();
        } else {
            let next = real.join(&part);
            if std::fs::symlink_metadata(&next).ok()?.is_symlink() {
                hops += 1;
                if hops > MAX_LINK_HOPS || !dir_is_trusted(&real, euid) {
                    return None;
                }
                let target = std::fs::read_link(&next).ok()?;
                for name in target.components().rev() {
                    pending.push_front(name.as_os_str().to_owned());
                }
            } else {
                real = next;
            }
        }
    }
    Some(real)
}

/// The rule for one file or directory: owned by root or by `euid`, and not writable by the group or
/// others. `sticky_excused` lets a writable directory with the sticky bit through (`/tmp` is `1777`),
/// because the sticky bit stops others from renaming or removing an entry they do not own.
#[cfg(all(unix, feature = "runtime"))]
fn trusted(uid: u32, mode: u32, euid: u32, sticky_excused: bool) -> bool {
    let owner_ok = uid == 0 || uid == euid;
    let writable_ok = mode & 0o022 == 0 || (sticky_excused && mode & 0o1000 != 0);
    owner_ok && writable_ok
}

/// Whether the real directory `dir` is safe to hold something that runs, or a link to it. The
/// directory itself is never excused for being sticky: a hard link to a trusted file could be planted
/// in it, or a link placed there. The directories above it are, as `/tmp` is.
#[cfg(all(unix, feature = "runtime"))]
fn dir_is_trusted(dir: &Path, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    dir.ancestors().enumerate().all(|(depth, ancestor)| {
        std::fs::metadata(ancestor)
            .is_ok_and(|meta| trusted(meta.uid(), meta.mode(), euid, depth > 0))
    })
}

/// Whether the file at the real path `real`, and every directory above it, is safe to run from. See
/// [`trusted`] and [`dir_is_trusted`]. Anything that cannot be read is untrusted.
#[cfg(all(unix, feature = "runtime"))]
fn is_trusted(real: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = rustix::process::geteuid().as_raw();
    let Ok(file) = std::fs::metadata(real) else {
        return false;
    };
    trusted(file.uid(), file.mode(), euid, false)
        && real.parent().is_some_and(|dir| dir_is_trusted(dir, euid))
}
