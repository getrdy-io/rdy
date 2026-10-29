//! A public key that the user hands to rdy, as a file name or as the key text (M1-131).
//!
//! `rdy trust add --key <key>` takes either. M1-126 gives `run --key` and `verify --key` the same
//! argument, so the rule for telling them apart lives here once.
//!
//! The argument is key text when it has a line break, starts with `untrusted comment:` or looks like
//! the one-line base64 of a minisign key (it starts with `RW`, which is how the algorithm bytes `Ed`
//! encode, and holds only base64 characters). Anything else is a file name. A real file name does not
//! look like that, so the two never get mixed up.
//!
//! A secret key is never accepted, from a file or as text. Someone who gives `trust add` the wrong
//! file has a key that is now in their shell history or in an email. [`GivenKeyError::SecretKey`]
//! says so, and the caller words the refusal.
//!
//! Nothing here echoes key text. An error names the file the user gave, or says "the key you typed".

use std::path::{Path, PathBuf};

use rdy_spec::sig::{MAX_KEY_FILE_BYTES, PublicKey, SignatureError};
use zeroize::Zeroizing;

use super::files::{self, FileError};
use super::key::looks_like_secret_key;

/// Where a key came from, for messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The key was read from this file, named as the user typed it.
    File(PathBuf),
    /// The key text was given on the command line.
    Text,
}

/// A public key and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GivenKey {
    /// The key. It is a valid ed25519 key of full order.
    pub key: PublicKey,
    /// Where it came from.
    pub origin: Origin,
}

/// Why a key argument was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GivenKeyError {
    /// The key file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    File {
        /// The file as typed.
        path: PathBuf,
        /// What is wrong with it.
        source: FileError,
    },
    /// It is a secret key. Nothing of it is kept or echoed.
    #[error("it is a secret key, not a public key")]
    SecretKey {
        /// Where it came from.
        origin: Origin,
    },
    /// It is text but not a public key, or it is a public key that must not be trusted.
    #[error("it is not a usable public key: {source}")]
    NotPublic {
        /// Where it came from.
        origin: Origin,
        /// Why.
        source: SignatureError,
    },
    /// The file is not text.
    #[error("it is not a public key file")]
    NotText {
        /// Where it came from.
        origin: Origin,
    },
}

/// True when `arg` is key text and not a file name.
#[must_use]
pub fn is_key_text(arg: &str) -> bool {
    let one_line_key = arg.starts_with("RW")
        && arg.len() >= 40
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    arg.contains('\n') || arg.starts_with("untrusted comment:") || one_line_key
}

/// Reads the public key that `arg` names or holds.
///
/// # Errors
///
/// A [`GivenKeyError`]: the file cannot be read, the text is a secret key, or it is not a public key
/// that rdy may trust (not a minisign ed25519 key, not a canonical point, or of small order).
pub fn resolve(arg: &str) -> Result<GivenKey, GivenKeyError> {
    if is_key_text(arg) {
        return parse(arg, Origin::Text);
    }
    let path = Path::new(arg);
    let origin = Origin::File(path.to_path_buf());
    let bytes = files::read_public(path, MAX_KEY_FILE_BYTES)
        .map(Zeroizing::new)
        .map_err(|source| GivenKeyError::File {
            path: path.to_path_buf(),
            source,
        })?;
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Err(GivenKeyError::NotText { origin });
    };
    parse(text, origin)
}

fn parse(text: &str, origin: Origin) -> Result<GivenKey, GivenKeyError> {
    if looks_like_secret_key(text) {
        return Err(GivenKeyError::SecretKey { origin });
    }
    match PublicKey::from_key_file_text(text) {
        Ok(key) => Ok(GivenKey { key, origin }),
        Err(source) => Err(GivenKeyError::NotPublic { origin, source }),
    }
}

#[cfg(test)]
mod tests;
