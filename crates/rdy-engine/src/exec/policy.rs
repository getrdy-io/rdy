//! The command policy (SEC-18, INV-08): what may run, from where, with what environment.
//!
//! The facade runs a [`Cmd`] through [`run`]. Nothing here trusts the caller's environment.
//!
//! - **Program names are constants.** [`Cmd::new`] takes a `&'static str`, so spec text cannot name a
//!   program. The name must be a plain file name, with no separator.
//! - **Fixed search path.** A name resolves from [`SEARCH_PATH`] (`/usr/sbin:/usr/bin:/sbin:/bin`) on
//!   every run, root or not. The parent's `PATH` is never read. Only after those four directories does
//!   it try the check's declared extra directories ([`Cmd::extra_dirs`]), which are absolute constants
//!   for operator-managed tools. An extra directory can never shadow a system tool.
//! - **Refusals.** Shells (`sh`, `bash`, `zsh`, `dash`, `cmd`, `powershell`, `pwsh` and a few more) and
//!   the privilege tools (`sudo`, `su`, `doas`, `pkexec`, `runas`) never run. The check is on the name
//!   and on the file the name resolves to, so a link named `tool` that points at `bash` is refused too.
//!   Arguments go to the program as argv, so no shell parses spec text.
//! - **Environment.** Cleared, then `LC_ALL=C`, `PATH=<fixed>` and the declared names. `LD_*`,
//!   `DYLD_*` and a short list of other variables that change how a program loads or resolves are
//!   refused as declared names. The parent's `LD_PRELOAD` never reaches a child because the parent's
//!   environment is never copied.
//! - **Caps.** Stdout defaults to 1 MiB and is at most 4 MiB. Stderr is 64 KiB.
//! - **Windows.** In M1 only `C:\Windows\System32\whoami.exe` runs, until job objects land (M2-006).
//!
//! A resolved binary must be executable and not writable by everyone (neither the file nor its
//! directory). Resolution and start are two steps, so a root-owned search directory is assumed; a
//! writable one is the host's own problem and is refused above for world-writable cases only.

use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use super::{DEFAULT_STDERR_CAP, DEFAULT_STDOUT_CAP, ExecError, ExecOutput, ExecSpec};

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

/// Programs that never run, by name without extension and in lower case. Shells and the tools that
/// raise privilege.
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
    "cmd",
    "powershell",
    "pwsh",
    // Privilege tools.
    "sudo",
    "su",
    "doas",
    "pkexec",
    "runas",
];

/// Variables that change how a program loads code or resolves names. Refused as declared names, in
/// upper case. `LD_*` and `DYLD_*` are refused by prefix.
const REFUSED_ENV: &[&str] = &[
    "PATH",
    "LC_ALL",
    "GCONV_PATH",
    "GETCONF_DIR",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "MALLOC_TRACE",
    "NIS_PATH",
    "NLSPATH",
    "RES_OPTIONS",
    "RESOLV_HOST_CONF",
    "TZDIR",
    "BASH_ENV",
    "BASHOPTS",
    "CDPATH",
    "ENV",
    "IFS",
    "PS4",
    "SHELLOPTS",
];

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
        "the environment name `{name}` is refused. Fix: remove it; the policy sets `PATH` and `LC_ALL` and refuses `LD_*` and `DYLD_*`"
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

/// Why [`run`] gave no output: the policy said no, or the runner failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommandError {
    /// The command was refused before anything started.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The command was allowed and failed to run to the end.
    #[error(transparent)]
    Exec(#[from] ExecError),
}

/// One command, as a check asks for it. Build it, then [`run`] it.
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
    /// spec or the host. The child gets nothing else but `LC_ALL` and `PATH`.
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
}

/// Checks `cmd` against the policy and turns it into a runnable [`ExecSpec`].
///
/// # Errors
///
/// A [`PolicyError`] for the first rule the command breaks.
pub fn prepare(cmd: &Cmd) -> Result<ExecSpec, PolicyError> {
    check_name(cmd.program)?;
    check_env(&cmd.env)?;
    if cmd.stdout_cap > MAX_STDOUT_CAP {
        return Err(PolicyError::CapTooLarge {
            cap: cmd.stdout_cap,
        });
    }
    let path = resolve(cmd.program, cmd.extra_dirs)?;

    let mut env: Vec<(OsString, OsString)> = vec![
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("PATH"), OsString::from(SEARCH_PATH)),
    ];
    env.extend(
        cmd.env
            .iter()
            .map(|(name, value)| (OsString::from(*name), value.clone())),
    );
    Ok(ExecSpec::new(path, cmd.timeout)
        .args(cmd.args.iter().cloned())
        .env(env)
        .caps(cmd.stdout_cap, DEFAULT_STDERR_CAP))
}

/// Runs `cmd` under the policy: checks it, resolves the program, and starts it with [`super::run`].
///
/// # Errors
///
/// [`CommandError::Policy`] when the policy refuses, [`CommandError::Exec`] for start, timeout and
/// read failures.
pub async fn run(cmd: Cmd) -> Result<ExecOutput, CommandError> {
    let spec = prepare(&cmd)?;
    Ok(super::run(spec).await?)
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
    if is_refused(&stem(program)) {
        return Err(PolicyError::Refused { program });
    }
    Ok(())
}

/// Lower case, without a trailing `.exe`.
fn stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
}

fn is_refused(stem: &str) -> bool {
    REFUSED_PROGRAMS.contains(&stem)
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
        if upper.starts_with("LD_")
            || upper.starts_with("DYLD_")
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
fn check_dir(dir: &'static str) -> Result<PathBuf, PolicyError> {
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

#[cfg(not(unix))]
fn resolve(program: &'static str, extra: &'static [&'static str]) -> Result<PathBuf, PolicyError> {
    for dir in extra {
        check_dir(dir)?;
    }
    windows_program(program)
}

#[cfg(unix)]
fn resolve(program: &'static str, extra: &'static [&'static str]) -> Result<PathBuf, PolicyError> {
    let mut dirs: Vec<PathBuf> = SEARCH_DIRS.iter().map(PathBuf::from).collect();
    for dir in extra {
        dirs.push(check_dir(dir)?);
    }
    let found = resolve_in(program, &dirs)?;
    // A link named like a harmless tool must not lead to a shell.
    if let Ok(real) = std::fs::canonicalize(&found)
        && let Some(name) = real.file_name().and_then(|name| name.to_str())
        && is_refused(&stem(name))
    {
        return Err(PolicyError::Refused { program });
    }
    Ok(found)
}

/// The first directory in `dirs` that holds an executable `program`. The order is the whole policy:
/// the caller puts the fixed directories first.
#[cfg(unix)]
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
        let dir_writable = std::fs::metadata(dir)
            .map(|dir_meta| dir_meta.permissions().mode() & 0o002 != 0)
            .unwrap_or(true);
        if meta.permissions().mode() & 0o002 != 0 || dir_writable {
            return Err(PolicyError::Untrusted { program });
        }
        return Ok(candidate);
    }
    Err(PolicyError::NotFound { program })
}
