//! `--out-dir` and `--no-report` for `rdy run` (07 section 3, ADR 0016).
//!
//! [`open_report_dir`] is the one call `rdy run` makes right after the spec is verified and before the
//! first check. It returns `None` for `--no-report`, which creates nothing and does not look at
//! `--out-dir`. Otherwise it makes `rdy-report-<product>-<time>/` under `--out-dir` (default `.` on
//! Unix, `%USERPROFILE%\rdy-reports` on Windows) and returns the open handle, or the exit-70 error of 07 section 9 row 6.
//!
//! `rdy run` (M1-057) calls it with the parsed [`RunArgs`], the verified `metadata.product` and the run
//! clock, holds the handle for the whole run, and writes the report files through it.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rdy_engine::output::{
    OPEN_PARENT, OutputDir, ReportError, default_report_parent, report_folder_name,
    report_timestamp,
};

use crate::cli::RunArgs;
use crate::error::{CliError, IoReason, ReportReason, ReportStep};

/// The default folder as 07 names it, for an error where the real path is not known.
const DEFAULT_LABEL: &str = r"%USERPROFILE%\rdy-reports";

/// How an error names the default folder when its real path is not known: `%USERPROFILE%\rdy-reports`
/// on Windows, and the report folder in the working folder (`unix_folder`) elsewhere.
fn default_label(windows: bool, unix_folder: PathBuf) -> PathBuf {
    if windows {
        PathBuf::from(DEFAULT_LABEL)
    } else {
        unix_folder
    }
}

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
    let ts = report_timestamp(now);
    let shown = |parent: &Path| parent.join(report_folder_name(product, &ts));
    let made = match &args.out_dir {
        Some(dir) => OutputDir::create_new(dir, product, &ts)
            .map_err(|err| report_error(ReportStep::CreateFolder, &shown(dir), err)),
        // Windows: opens `%USERPROFILE%\rdy-reports` without following a link and refuses a
        // redirect there. On Unix it opens `.`, which fails for a working folder that cannot be
        // read, so both OSes name the folder in the error.
        None => {
            let label = default_label(cfg!(windows), shown(Path::new(".")));
            let parent = default_report_parent()
                .map_err(|err| report_error(ReportStep::CreateFolder, &label, err))?;
            OutputDir::create_new_in(&parent, product, &ts)
                .map_err(|err| report_error(ReportStep::CreateFolder, &shown(parent.path()), err))
        }
    };
    made.map(Some)
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
        ReportError::NotPlainFolder { path } => (path, ReportReason::NotPlainFolder),
        ReportError::NoDefaultFolder => (shown.to_path_buf(), ReportReason::NoDefaultFolder),
        ReportError::NameTaken { parent } => (parent, ReportReason::NameTaken),
        ReportError::FileExists { path } => (path, ReportReason::FileExists),
        // The writer's own refusals (a report over the cap, a broken stream) say so in its words.
        // Any other writer error is a bug in rdy.
        ReportError::Json(json) => {
            return CliError::report_writer(&json).unwrap_or_else(CliError::bug);
        }
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
