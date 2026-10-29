//! `--out-dir` and `--no-report` for `rdy run` (07 section 3, ADR 0016).
//!
//! [`open_report_dir`] is the one call `rdy run` makes right after the spec is verified and before the
//! first check. It returns `None` for `--no-report`, which creates nothing and does not look at
//! `--out-dir`. Otherwise it makes `rdy-report-<product>-<time>/` under `--out-dir` (default `.` on
//! Unix) and returns the open handle, or the exit-70 error of 07 section 9 row 6.
//!
//! The M1-057 ticket wires this into `run`: call it with the parsed [`RunArgs`], the verified
//! `metadata.product` and `SystemTime::now()`, hold the handle for the whole run, and write the report
//! files through it.

use std::path::Path;
use std::time::SystemTime;

use rdy_engine::output::{OutputDir, ReportError, default_parent, report_timestamp};

use crate::cli::RunArgs;
use crate::error::{CliError, IoReason, ReportStep};

/// Makes the report folder for this run, or `None` when `--no-report` was given.
///
/// # Errors
///
/// [`CliError::ReportWrite`] (exit 70, code `report_write`) when the folder cannot be made, with the
/// fix "use --out-dir <a folder you can write to>, or --no-report to skip the files".
pub fn open_report_dir(
    args: &RunArgs,
    product: &str,
    now: SystemTime,
) -> Result<Option<OutputDir>, CliError> {
    if args.no_report {
        return Ok(None);
    }
    let parent = args.out_dir.clone().unwrap_or_else(default_parent);
    let ts = report_timestamp(now);
    OutputDir::create_new(&parent, product, &ts)
        .map(Some)
        .map_err(|err| report_error(ReportStep::CreateFolder, &parent, err))
}

/// Maps an output directory error to the CLI error. `shown` is the path to name when the error has
/// none of its own.
///
/// A name that failed validation can only be a bug in rdy here: the spec was verified and parsed
/// before this runs, so it says so and prints no more.
#[must_use]
pub fn report_error(step: ReportStep, shown: &Path, err: ReportError) -> CliError {
    let (path, reason) = match err {
        ReportError::Io { path, source, .. } => (path, IoReason::from_io(&source)),
        ReportError::NotOwner { path, .. } | ReportError::NotPrivate { path, .. } => {
            (path, IoReason::PermissionDenied)
        }
        ReportError::NameTaken { parent } => (parent, IoReason::Other),
        ReportError::FileExists { path } => (path, IoReason::Other),
        _ => return CliError::bug(),
    };
    let path = if path.as_os_str().is_empty() {
        shown
    } else {
        &path
    };
    CliError::ReportWrite {
        step,
        path: path.display().to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests;
