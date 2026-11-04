//! `host.kernel`: the running kernel's version, the modules it needs and BTF, against the spec.
//!
//! Linux only. macOS and Windows have no kernel modules in this sense (ADR 0013), and the check is
//! `NotYet` there like the rest of the host family. The sources are read-only files, no command is run:
//!
//! - the release from `uname` through the facade, then `/proc/sys/kernel/osrelease` if `uname` fails;
//! - `/etc/os-release` (then `/usr/lib/os-release`) for the distribution id, which picks the entry of
//!   `distro_min` and the fix text;
//! - `/proc/modules` (loaded), `modules.builtin` (built in) and `modules.dep` (installed) under
//!   `/lib/modules/<release>` (then `/usr/lib/modules/<release>`), only when the spec lists modules;
//! - `stat` of `/sys/kernel/btf/vmlinux`, only when the spec has `btf: true`.
//!
//! **No privilege needed.** Every source is world readable, so the check declares no want. Root would
//! add nothing, and a result is never downgraded for lack of it.
//!
//! A source that cannot be read makes the answer "cannot tell", which warns and says why. It never makes
//! it "absent", which blocks. The judgement is a pure function in `judge`, the release reader and the
//! version compare are in `version`, and the module-name scans are in `modules`.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Os,
};
use rdy_engine::probe::{FileBytes, MAX_READ, NativeCall, NativeValue, ProbeError};
use rdy_spec::check::HostKernel;

use crate::family::OS;
use crate::os::release as os_release;
use crate::text::short;

mod judge;
mod modules;
mod version;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{Facts, Got, Modules, Rules, judge};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads Linux files and has no data source on this OS yet";

const KERNEL_RELEASE: &str = "/proc/sys/kernel/osrelease";
const PROC_MODULES: &str = "/proc/modules";
const OS_RELEASE: &str = "/etc/os-release";
const OS_RELEASE_USR: &str = "/usr/lib/os-release";
const MODULES_DIRS: [&str; 2] = ["/lib/modules", "/usr/lib/modules"];
const BTF_DIR: &str = "/sys/kernel/btf";
const BTF_VMLINUX: &str = "/sys/kernel/btf/vmlinux";

/// The most characters kept of a kernel release string.
const MAX_RELEASE: usize = 128;

/// The static facts about `host.kernel` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.kernel",
    family: "host",
    summary: "Kernel version and modules",
    meta: CheckMeta {
        title: "Kernel",
        remediation: "Use a kernel at or above the minimum. Load a missing module now and at boot with `modprobe br_netfilter && echo br_netfilter | sudo tee /etc/modules-load.d/vendor.conf`, using the module from the result.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: OS,
    reads: &[
        KERNEL_RELEASE,
        PROC_MODULES,
        OS_RELEASE,
        OS_RELEASE_USR,
        MODULES_DIRS[0],
        MODULES_DIRS[1],
        BTF_DIR,
    ],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `host.kernel`.
///
/// Built from the spec entry's `min`, `distro_min`, `modules` and `btf` ([`Kernel::from_params`]).
#[derive(Debug, Clone)]
pub struct Kernel {
    rules: Rules,
}

impl Kernel {
    /// The check for these spec parameters.
    #[must_use]
    pub fn from_params(params: &HostKernel) -> Self {
        Self {
            rules: Rules {
                min: params.min.clone(),
                distro_min: params
                    .distro_min
                    .iter()
                    .flatten()
                    .map(|(id, want)| (id.as_str().to_owned(), want.clone()))
                    .collect(),
                modules: params
                    .modules
                    .iter()
                    .flatten()
                    .map(|name| name.as_str().to_owned())
                    .collect(),
                btf: params.btf,
            },
        }
    }
}

impl Check for Kernel {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            if ctx.os() != Os::Linux {
                return Err(CheckError::Unsupported(NO_SOURCE));
            }
            let facts = read_facts(&self.rules, ctx).await?;
            Ok(judge(&self.rules, &facts))
        })
    }
}

/// Reads what the rules need and nothing else. The distribution is always read: `distro_min` needs it
/// and the fix text follows it.
async fn read_facts(rules: &Rules, ctx: &CheckContext) -> Result<Facts, CheckError> {
    let release = read_release(ctx).await?;
    let distro = read_distro(ctx).await?;
    let modules = if rules.modules.is_empty() {
        None
    } else {
        Some(read_modules(rules, ctx, &release).await?)
    };
    let btf = if rules.btf {
        Some(read_btf(ctx).await?)
    } else {
        None
    };
    Ok(Facts {
        release,
        distro,
        modules,
        btf,
    })
}

/// What a probe error means for one source. A refusal by rdy's own policy and a fixture that lacks an
/// answer end the check, because both are bugs in the check or its test. Every other error (not found,
/// denied by the OS, timed out) only weakens one answer.
fn weak<T>(error: ProbeError) -> Result<Got<T>, CheckError> {
    match error {
        ProbeError::Denied { .. }
        | ProbeError::Policy(_)
        | ProbeError::Table(_)
        | ProbeError::NotRecorded(_) => Err(CheckError::Probe(error)),
        ProbeError::NotFound => Ok(Got::Absent),
        other => Ok(Got::Failed(short(&other))),
    }
}

async fn read_file(ctx: &CheckContext, path: &str) -> Result<Got<FileBytes>, CheckError> {
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => Ok(Got::Value(file)),
        Err(error) => weak(error),
    }
}

/// The first word of `text`, cut to [`MAX_RELEASE`] characters.
fn first_word(text: &str) -> String {
    text.split_whitespace()
        .next()
        .unwrap_or_default()
        .chars()
        .take(MAX_RELEASE)
        .collect()
}

/// The running kernel's release: `uname`, then `/proc/sys/kernel/osrelease`.
async fn read_release(ctx: &CheckContext) -> Result<Got<String>, CheckError> {
    match ctx.probe().native(NativeCall::Uname).await {
        Ok(NativeValue::Uname(info)) => {
            let release = first_word(&info.release);
            if !release.is_empty() {
                return Ok(Got::Value(release));
            }
        }
        Ok(_) => {}
        Err(error) => {
            // The same rule as every other source: only a bug in the check or its test ends the run.
            // Anything else falls through to the file.
            weak::<()>(error)?;
        }
    }
    Ok(match read_file(ctx, KERNEL_RELEASE).await? {
        Got::Value(file) => {
            let release = first_word(&String::from_utf8_lossy(&file.bytes));
            if release.is_empty() {
                Got::Failed("it is empty".to_owned())
            } else {
                Got::Value(release)
            }
        }
        Got::Absent => Got::Absent,
        Got::Failed(why) => Got::Failed(why),
    })
}

/// `/etc/os-release`, then `/usr/lib/os-release`.
async fn read_distro(ctx: &CheckContext) -> Result<Got<os_release::Release>, CheckError> {
    let mut failed = None;
    for path in [OS_RELEASE, OS_RELEASE_USR] {
        match read_file(ctx, path).await? {
            Got::Value(file) => {
                if let Some(release) = os_release::parse(&String::from_utf8_lossy(&file.bytes)) {
                    return Ok(Got::Value(release));
                }
                failed = Some(format!("{path} holds no release fields"));
            }
            Got::Absent => {}
            Got::Failed(why) => failed = Some(format!("{path} could not be read ({why})")),
        }
    }
    Ok(failed.map_or(Got::Absent, Got::Failed))
}

/// The module sources for the names the spec lists.
async fn read_modules(
    rules: &Rules,
    ctx: &CheckContext,
    release: &Got<String>,
) -> Result<Modules, CheckError> {
    let wanted: BTreeSet<String> = rules
        .modules
        .iter()
        .map(|m| modules::normalize(m))
        .collect();
    let loaded = match read_file(ctx, PROC_MODULES).await? {
        Got::Value(file) if file.truncated() => {
            Got::Failed("it is larger than rdy reads".to_owned())
        }
        Got::Value(file) => Got::Value(modules::scan_loaded(
            &String::from_utf8_lossy(&file.bytes),
            &wanted,
        )),
        Got::Absent => Got::Absent,
        Got::Failed(why) => Got::Failed(why),
    };

    let release = release.value().filter(|r| version::is_path_safe(r));
    let Some(release) = release else {
        return Ok(Modules {
            dir: MODULES_DIRS[0].to_owned(),
            path_safe: false,
            loaded,
            builtin: Got::Absent,
            dep: Got::Absent,
        });
    };

    // The first directory that has a modules.dep decides. A merged-usr system has both names for one
    // directory, and an older one has only `/lib/modules`.
    let mut dir = format!("{}/{release}", MODULES_DIRS[0]);
    let mut dep_file = Got::Absent;
    for base in MODULES_DIRS {
        let candidate = format!("{base}/{release}");
        let file = read_file(ctx, &format!("{candidate}/modules.dep")).await?;
        if matches!(file, Got::Absent) {
            continue;
        }
        dir = candidate;
        dep_file = file;
        break;
    }

    let dep = match dep_file {
        Got::Value(head) => Got::Value(scan_dep_file(ctx, &dir, &head, &wanted).await?),
        Got::Absent => Got::Absent,
        Got::Failed(why) => Got::Failed(why),
    };
    let builtin = if matches!(dep, Got::Absent) {
        Got::Absent
    } else {
        match read_file(ctx, &format!("{dir}/modules.builtin")).await? {
            Got::Value(file) if file.truncated() => {
                Got::Failed("it is larger than rdy reads".to_owned())
            }
            Got::Value(file) => Got::Value(modules::scan_paths(
                &String::from_utf8_lossy(&file.bytes),
                &wanted,
            )),
            Got::Absent => Got::Absent,
            Got::Failed(why) => Got::Failed(why),
        }
    };
    Ok(Modules {
        dir,
        path_safe: true,
        loaded,
        builtin,
        dep,
    })
}

/// Scans `modules.dep`. A file longer than one read is read again from its end, and its size decides
/// whether the two reads cover it.
async fn scan_dep_file(
    ctx: &CheckContext,
    dir: &str,
    head: &FileBytes,
    wanted: &BTreeSet<String>,
) -> Result<modules::Dep, CheckError> {
    if !head.truncated_tail {
        return Ok(modules::scan_dep(head, None, None, wanted));
    }
    let path = format!("{dir}/modules.dep");
    let tail = match ctx.probe().read_tail(Path::new(&path), MAX_READ).await {
        Ok(tail) => Some(tail),
        Err(error) => {
            weak::<()>(error)?;
            None
        }
    };
    let len = match ctx.probe().stat(Path::new(&path)).await {
        Ok(Some(meta)) => Some(meta.len),
        Ok(None) => None,
        Err(error) => {
            weak::<()>(error)?;
            None
        }
    };
    Ok(modules::scan_dep(head, tail.as_ref(), len, wanted))
}

/// Whether `/sys/kernel/btf/vmlinux` is a file.
async fn read_btf(ctx: &CheckContext) -> Result<Got<bool>, CheckError> {
    match ctx.probe().stat(Path::new(BTF_VMLINUX)).await {
        Ok(Some(meta)) => Ok(Got::Value(meta.is_file)),
        Ok(None) => Ok(Got::Absent),
        Err(error) => weak(error),
    }
}
