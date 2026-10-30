//! Reading a text file through the probe, for the host checks. The error helpers are in `crate::text`.

use std::path::Path;

use rdy_engine::check::{CheckContext, CheckError};
use rdy_engine::probe::ProbeError;

use crate::text::{short, soft};

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
