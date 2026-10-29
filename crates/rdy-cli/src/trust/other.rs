//! Trust stores on systems where rdy cannot check who may change a file (Windows, ADR 0027).
//!
//! The rule is to refuse what cannot be verified. A store that exists is refused. A store that does not
//! exist is empty. Writing is not supported.

use std::path::Path;

use super::{Insecurity, Layout, Scope, TrustStoreError};
use crate::error::IoReason;

/// There is no effective uid to compare with here. The value is never equal to 0, so the process is
/// never taken for root.
pub(super) fn effective_uid() -> u32 {
    u32::MAX
}

/// Refuses a store that exists. `None` when there is no file.
pub(super) fn read(
    path: &Path,
    scope: Scope,
    _layout: &Layout,
) -> Result<Option<Vec<u8>>, TrustStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(TrustStoreError::Insecure {
            path: path.to_path_buf(),
            scope,
            why: Insecurity::Unverifiable,
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(TrustStoreError::Unreadable {
            path: path.to_path_buf(),
            reason: IoReason::from_io(&err),
        }),
    }
}

/// Writing is not supported yet.
pub(super) fn write(
    _path: &Path,
    _scope: Scope,
    _layout: &Layout,
    _bytes: &[u8],
) -> Result<(), TrustStoreError> {
    Err(TrustStoreError::Unsupported)
}
