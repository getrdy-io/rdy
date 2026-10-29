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

use rdy_engine::output::{
    OPEN_PARENT, OutputDir, ReportError, default_parent, report_folder_name, report_timestamp,
};

use crate::cli::RunArgs;
use crate::error::{CliError, IoReason, ReportReason, ReportStep};

/// Makes the report folder for this run, or `None` when `--no-report` was given.
///
/// # Errors
///
/// [`CliError::ReportWrite`] (exit 70, code `report_write`) when the folder cannot be made, with the
/// fix "use `--out-dir <a folder you can write to>`, or `--no-report` to skip the files".
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
        .map_err(|err| {
            let shown = parent.join(report_folder_name(product, &ts));
            report_error(ReportStep::CreateFolder, &shown, err)
        })
}

/// Maps an output directory error to the CLI error. `shown` is the folder as rdy names it, the
/// parent and then the folder name, such as `./rdy-report-acme-20270309T101502Z`.
///
/// A missing or unreadable `--out-dir` fails while opening the parent, and is shown as the folder
/// that could not be made (07 section 9, row 6). A name that failed validation can only be a bug in
/// rdy here: the spec was verified and parsed before this runs, so it says so and prints no more.
#[must_use]
pub fn report_error(step: ReportStep, shown: &Path, err: ReportError) -> CliError {
    let (path, reason) = match err {
        ReportError::Io {
            action,
            path,
            source,
        } => {
            let path = if action == OPEN_PARENT {
                shown.to_path_buf()
            } else {
                path
            };
            (path, ReportReason::Io(IoReason::from_io(&source)))
        }
        ReportError::NotOwner { path, .. } => (path, ReportReason::NotOwner),
        ReportError::NotPrivate { path, .. } => (path, ReportReason::NotPrivate),
        ReportError::NameTaken { parent } => (parent, ReportReason::NameTaken),
        ReportError::FileExists { path } => (path, ReportReason::FileExists),
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
