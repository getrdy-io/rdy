//! The object `rdy version --json` prints (07 section 4.3, C.11).

use serde::{Deserialize, Serialize};

use crate::API_VERSION;

/// The `rdy` binary's own identity, as `rdy version --json` prints it.
///
/// Like the other `rdy/v1` objects it only grows: a later release may add fields, and a reader ignores
/// the ones it does not know. `commit` and `date` are `null` when the build had no trustworthy git
/// information, for example a build from a source tarball.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "Version", transform = crate::schema::version_rules))]
#[non_exhaustive]
pub struct VersionInfo {
    /// Always `rdy`.
    #[cfg_attr(feature = "schema", schemars(extend("const" = "rdy")))]
    pub name: String,
    /// Version of the rdy binary, such as `0.1.0` or `0.1.0-alpha.3`.
    pub version: String,
    /// Short git commit of the build: the first 7 hex digits of the hash.
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^[0-9a-f]{7,40}$")))]
    pub commit: Option<String>,
    /// Date of that commit in UTC, as `YYYY-MM-DD`.
    #[cfg_attr(
        feature = "schema",
        schemars(regex(pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
    )]
    pub date: Option<String>,
    /// Rust target triple the binary was built for.
    pub target: String,
    /// Version of the rdy-spec crate inside this binary.
    pub rdy_spec: String,
    /// The wire format this binary reads and writes. Always `rdy/v1` in this release line.
    #[cfg_attr(feature = "schema", schemars(extend("const" = "rdy/v1")))]
    pub api_version: String,
}

impl VersionInfo {
    /// The identity of a build with no commit and no date.
    ///
    /// `name` is `rdy` and `api_version` is `rdy/v1`. Set `commit` and `date` when the build knows them.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        target: impl Into<String>,
        rdy_spec: impl Into<String>,
    ) -> Self {
        Self {
            name: "rdy".to_owned(),
            version: version.into(),
            commit: None,
            date: None,
            target: target.into(),
            rdy_spec: rdy_spec.into(),
            api_version: API_VERSION.to_owned(),
        }
    }
}
