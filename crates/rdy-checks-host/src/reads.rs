//! Small helpers the host checks share for reading a file through the probe.

use std::path::Path;

use rdy_engine::check::{CheckContext, CheckError};
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

/// What reading a text file gave.
pub(crate) enum Read {
    Text(String),
    Absent,
    Unreadable(String),
}

pub(crate) async fn read_text(ctx: &CheckContext, path: &str) -> Result<Read, CheckError> {
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => Ok(Read::Text(
            String::from_utf8_lossy(&file.bytes).into_owned(),
        )),
        Err(error) => match soft(error)? {
            ProbeError::NotFound => Ok(Read::Absent),
            other => Ok(Read::Unreadable(short(&other))),
        },
    }
}
