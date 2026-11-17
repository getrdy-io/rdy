//! Reading a spec and its signature, and verifying them: the one path of `rdy run` and `rdy verify`
//! (M1-126, 01 sections 4.4 and 4.7).
//!
//! The order is the security property:
//!
//! 1. The `--key` argument, when given, is read first. A bad key is a usage error and nothing else is
//!    opened.
//! 2. The spec is read once, then the sidecar is read once. [`rdy_spec::load`] verifies and parses those
//!    two buffers, and nothing here reopens either path.
//! 3. A sidecar that is there but cannot be read is never "no signature". It reaches the loader as an
//!    empty file, which fails as a signature that is not in the form rdy accepts, even with
//!    `--allow-unsigned`. Only a sidecar that does not exist at its default path is no signature at all.
//!    A `--sig` file that does not exist is a usage error.
//! 4. With `--key`, the trust stores are never read ([`TrustStore::for_one_run`], ADR 0027), so a store
//!    that is refused or planted cannot stop the run. Without it, the stores are read only when there is a
//!    sidecar to check.
//! 5. A key given with `--key` means the person wants the signature checked. A spec with no signature is
//!    refused then, whatever `--allow-unsigned` says.
//!
//! The flag `--allow-unsigned` never reaches this module as anything but a `bool` read from argv.

use std::path::{Path, PathBuf};

use rdy_spec::LoadedSpec;
use rdy_spec::load;
use rdy_spec::sig::{MAX_SIGNATURE_BYTES, Policy, TrustStore};

use crate::error::{CliError, IoReason};
use crate::lint;
use crate::signing::files::{FileError, read_public};
use crate::signing::pubkey::{self, GivenKeyError};
use crate::trust::{self, Layout};

/// What the command line says about the spec and how to trust it.
pub(crate) struct Given<'a> {
    /// The spec file.
    pub(crate) spec: &'a Path,
    /// `--sig`.
    pub(crate) sig: Option<&'a Path>,
    /// `--key`: a public key file or key text, for this run only.
    pub(crate) key: Option<&'a str>,
    /// `--allow-unsigned`. `rdy verify` has no such flag and passes `false`.
    pub(crate) allow_unsigned: bool,
}

/// Reads, verifies and parses the spec. `name` is the spec path as typed. `layout` says where the trust
/// stores are, and is not touched when `--key` is given.
///
/// # Errors
///
/// A [`CliError`], exit 64: the spec or the key cannot be read, the signature is missing or does not
/// verify, the spec is invalid or expired, or a trust store is unsafe.
pub(crate) fn load_spec(
    given: &Given<'_>,
    name: &str,
    layout: &Layout,
) -> Result<LoadedSpec, CliError> {
    let key = given
        .key
        .map(|arg| pubkey::resolve(arg).map_err(|err| key_error(&err)))
        .transpose()?;
    let bytes = lint::read_spec(given.spec, name)?;
    let sidecar = read_sidecar(given.spec, given.sig)?;
    // A root run with no `--key` reads only the system store, and says so when it finds no key (01
    // section 4.3).
    let root = key.is_none() && layout.is_root();
    let spec_error = |error| {
        let error = CliError::spec_in(name, error, &bytes);
        if root { error.as_root() } else { error }
    };
    let (trust, policy) = match (&key, &sidecar) {
        // The key decides which store there is. No store is read (ADR 0027).
        (Some(key), Some(sidecar)) => (
            TrustStore::for_one_run(sidecar, key.key.clone())
                .map_err(|error| spec_error(error.into()))?,
            Policy::RequireSigned,
        ),
        (Some(_), None) => (TrustStore::new(), Policy::RequireSigned),
        (None, Some(_)) => (trust::load(layout)?, policy_of(given.allow_unsigned)),
        (None, None) => (TrustStore::new(), policy_of(given.allow_unsigned)),
    };
    load(&bytes, sidecar.as_deref(), &trust, policy).map_err(spec_error)
}

fn policy_of(allow_unsigned: bool) -> Policy {
    if allow_unsigned {
        Policy::AllowUnsigned
    } else {
        Policy::RequireSigned
    }
}

/// The refusal for a `--key` argument. The same words as `rdy trust add` (07 C.10).
fn key_error(error: &GivenKeyError) -> CliError {
    crate::trust_cmds::key_error(error)
}

/// The signature sidecar: `--sig`, else `<SPEC>.minisig`, read once.
///
/// `None` means there is no signature: the default file does not exist. A `--sig` file that does not
/// exist is a usage error. Any other failure to read a file that is there (no permission, a folder, a
/// device, a link to nothing) gives an empty buffer, which the loader refuses as a malformed signature.
fn read_sidecar(spec: &Path, sig: Option<&Path>) -> Result<Option<Vec<u8>>, CliError> {
    let (path, explicit) = match sig {
        Some(path) => (path.to_path_buf(), true),
        None => {
            let mut name = spec.as_os_str().to_owned();
            name.push(".minisig");
            (PathBuf::from(name), false)
        }
    };
    // One byte past the limit is enough for the loader to say "too large".
    match read_public(&path, MAX_SIGNATURE_BYTES + 1) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(FileError::Unreadable {
            reason: IoReason::NoSuchFile,
        }) if absent(&path) => {
            if explicit {
                Err(CliError::usage(
                    format!(
                        "cannot read the signature file {}: no such file",
                        crate::error::escape_untrusted(&path.to_string_lossy())
                    ),
                    "check the file name of the signature, or leave it out to use the .minisig file next to the spec",
                ))
            } else {
                Ok(None)
            }
        }
        // Present but not readable. It is a signature that fails, never a missing one.
        Err(_) => Ok(Some(Vec::new())),
    }
}

/// True when nothing is at `path`, not even a link. A link to nothing is a file that is there.
fn absent(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound
    )
}
