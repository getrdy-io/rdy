//! Two helpers for host checks that read files through the probe and can work around a failed read.

use rdy_engine::check::CheckError;
use rdy_engine::probe::ProbeError;

/// A probe error the check can work around. A refusal by rdy's own policy is a bug in the check's
/// manifest or command, and ends the check.
pub(crate) fn soft(error: ProbeError) -> Result<ProbeError, CheckError> {
    match error {
        ProbeError::Denied { .. } | ProbeError::Policy(_) | ProbeError::Table(_) => {
            Err(CheckError::Probe(error))
        }
        other => Ok(other),
    }
}

/// A short reason for a probe failure, for a note.
pub(crate) fn short(error: &ProbeError) -> String {
    match error {
        ProbeError::NotFound => "not found".to_owned(),
        ProbeError::PermissionDenied => "permission denied".to_owned(),
        ProbeError::Timeout => "timed out".to_owned(),
        other => other
            .to_string()
            .split(". Fix:")
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}
