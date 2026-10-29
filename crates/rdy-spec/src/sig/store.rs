//! The `trust.yaml` file format (01 section 4.3).
//!
//! This module reads and writes the bytes of one trust file. It does no file access: where the file
//! lives, who may own it and how it is opened are the CLI's job (M1-121). The rules here:
//!
//! - The file is at most 256 KiB, valid UTF-8, one YAML document, with no anchors, aliases, merge keys,
//!   tags or duplicate keys.
//! - Unknown keys are an error. `apiVersion` is `rdy/v1` and `kind` is `TrustStore`.
//! - Every key goes through [`PublicKey::from_base64`], so a malformed, non-canonical or small-order key
//!   makes the whole file an error. A file is never half-read.
//! - Two entries for the same product with the same key id are an error: the key id would not say which
//!   key signed.
//! - The key id and the fingerprint are never stored. They come from `key`.

use std::fmt::Write as _;

use serde::Deserialize;
use serde_saphyr::budget::BudgetBreach;
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};
use serde_saphyr::{Budget, NonFiniteFloatPolicy};
use thiserror::Error;

use super::{KeyId, Pin, PublicKey, SignatureError, TrustSource, TrustStore, valid_timestamp};
use crate::error::{echo_capped, echo_reason};
use crate::spec::ProductSlug;
use crate::{API_VERSION, Location};

/// The largest `trust.yaml` rdy reads, 256 KiB (threat model INV-02).
pub const MAX_TRUST_BYTES: usize = 256 * 1024;

/// The `kind` of a trust file.
const KIND: &str = "TrustStore";

/// The deepest nesting a trust file may have. The real file is three levels deep.
const MAX_DEPTH: usize = 8;

/// The longest `note`, in characters.
const MAX_NOTE_CHARS: usize = 512;

/// The most characters of a reason from the YAML reader that an error keeps.
const MAX_REASON_CHARS: usize = 160;

/// Why a `trust.yaml` was refused.
///
/// Every case is exit 64. [`TrustFileError::hint`] is never empty, and no message echoes more than a
/// short, escaped piece of the file.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TrustFileError {
    /// The file is larger than 256 KiB.
    #[error("the trust file is larger than {limit} bytes")]
    TooLarge {
        /// How many bytes were read, at least. Reading stops one byte past the limit.
        size: usize,
        /// The limit in bytes.
        limit: usize,
    },
    /// The file is not UTF-8 text.
    #[error("the trust file is not UTF-8 text")]
    NotUtf8,
    /// A key that rdy does not know.
    #[error("the trust file has an unknown key '{key}'")]
    UnknownField {
        /// The key, escaped and cut.
        key: String,
        /// Where it is.
        at: Option<Location>,
    },
    /// The file is not valid YAML for a trust store.
    #[error("the trust file is not valid: {reason}")]
    Invalid {
        /// What is wrong, escaped and cut.
        reason: String,
        /// Where it is.
        at: Option<Location>,
    },
    /// `apiVersion` or `kind` is not what a trust file has.
    #[error("the trust file has the wrong {field}")]
    Header {
        /// `apiVersion` or `kind`.
        field: &'static str,
    },
    /// One entry is not usable. `index` counts from 1.
    #[error("entry {index} of the trust file is not usable: {reason}")]
    Entry {
        /// The place of the entry in the list, from 1.
        index: usize,
        /// What is wrong, in fixed words.
        reason: &'static str,
    },
    /// The key of one entry is malformed or weak. `index` counts from 1.
    #[error("entry {index} of the trust file has a key that cannot be used: {source}")]
    Key {
        /// The place of the entry in the list, from 1.
        index: usize,
        /// Why the key was refused.
        source: SignatureError,
    },
    /// Two keys pinned for one product have the same key id.
    #[error("the trust file pins two keys with the id {key_id} for {product}")]
    DuplicateKeyId {
        /// The product both entries name.
        product: ProductSlug,
        /// The id they share.
        key_id: KeyId,
    },
}

impl TrustFileError {
    /// The place in the file, when the error has one.
    #[must_use]
    pub fn location(&self) -> Option<Location> {
        match self {
            Self::UnknownField { at, .. } | Self::Invalid { at, .. } => *at,
            _ => None,
        }
    }

    /// The fix line. Never empty.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match self {
            Self::UnknownField { .. } => {
                "remove that line, or run rdy trust list to see what rdy wrote"
            }
            Self::Key { .. } => {
                "remove that entry, then pin the key again with rdy trust add after you check its fingerprint with the vendor"
            }
            Self::DuplicateKeyId { .. } => {
                "remove one of the two entries with rdy trust remove, then pin the key you trust again"
            }
            _ => "fix the file, or remove it and pin your keys again with rdy trust add",
        }
    }
}

/// The file as it is written, before any value is checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    keys: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    product: String,
    key: String,
    added_at: String,
    #[serde(default)]
    note: Option<String>,
}

impl TrustStore {
    /// Reads the bytes of one `trust.yaml`. Every pin gets `source`: [`TrustSource::System`] for the
    /// system file and [`TrustSource::User`] for the user's file.
    ///
    /// Callers read at most [`MAX_TRUST_BYTES`] plus one byte, so a larger file is told apart from one
    /// of exactly the limit.
    ///
    /// # Errors
    ///
    /// A [`TrustFileError`] if the file is too large, is not UTF-8, is not a valid trust store, has an
    /// unknown key, or holds a key that is malformed or of small order. Nothing is returned for a file
    /// that is only partly good.
    pub fn from_yaml(bytes: &[u8], source: TrustSource) -> Result<Self, TrustFileError> {
        if bytes.len() > MAX_TRUST_BYTES {
            return Err(TrustFileError::TooLarge {
                size: bytes.len(),
                limit: MAX_TRUST_BYTES,
            });
        }
        let text = std::str::from_utf8(bytes).map_err(|_| TrustFileError::NotUtf8)?;
        let raw = typed_read(text)?;
        if raw.api_version != API_VERSION {
            return Err(TrustFileError::Header {
                field: "apiVersion",
            });
        }
        if raw.kind != KIND {
            return Err(TrustFileError::Header { field: "kind" });
        }
        let mut store = Self::new();
        for (i, entry) in raw.keys.into_iter().enumerate() {
            let index = i + 1;
            let product = ProductSlug::new(entry.product).map_err(|_| TrustFileError::Entry {
                index,
                reason: "the product is not a valid product name",
            })?;
            let key = PublicKey::from_base64(&entry.key)
                .map_err(|source| TrustFileError::Key { index, source })?;
            if !valid_timestamp(&entry.added_at) {
                return Err(TrustFileError::Entry {
                    index,
                    reason: "added_at is not a time like 2026-11-30T16:20:00Z",
                });
            }
            let note = entry.note.filter(|note| !note.is_empty());
            if let Some(note) = &note {
                check_note(note).map_err(|reason| TrustFileError::Entry { index, reason })?;
            }
            if store
                .pins_for(&product)
                .any(|pin| pin.key.key_id() == key.key_id())
            {
                return Err(TrustFileError::DuplicateKeyId {
                    product,
                    key_id: key.key_id(),
                });
            }
            store.pins.push(Pin {
                product,
                key,
                source,
                added_at: Some(entry.added_at),
                note,
            });
        }
        Ok(store)
    }

    /// Writes the store as the text of a `trust.yaml`, with a final newline.
    ///
    /// Only pins that were read from a file are written. A one-run key made with [`TrustStore::pin`]
    /// has no `added_at` and is never written: pinning is `rdy trust add` alone. The text reads back
    /// with [`TrustStore::from_yaml`] to the same pins. A `note` is written as a double-quoted string,
    /// so no text in it can add a key.
    #[must_use]
    pub fn to_yaml(&self) -> String {
        let mut out = format!("apiVersion: {API_VERSION}\nkind: {KIND}\n");
        let persisted: Vec<&Pin> = self
            .pins
            .iter()
            .filter(|pin| pin.added_at.is_some())
            .collect();
        if persisted.is_empty() {
            out.push_str("keys: []\n");
            return out;
        }
        out.push_str("keys:\n");
        for pin in persisted {
            // Writing to a `String` cannot fail.
            let _ = writeln!(out, "  - product: {}", pin.product.as_str());
            let _ = writeln!(out, "    key: {}", pin.key.to_base64());
            if let Some(added_at) = &pin.added_at {
                let _ = writeln!(out, "    added_at: {added_at}");
            }
            if let Some(note) = &pin.note {
                let _ = writeln!(out, "    note: {}", quoted(note));
            }
        }
        out
    }

    /// Adds every pin of `other` after the pins of `self`.
    ///
    /// The CLI reads the user file and the system file separately, so each pin keeps its own source.
    pub fn extend(&mut self, other: Self) {
        self.pins.extend(other.pins);
    }

    /// The pins that are kept in a file: those read by [`TrustStore::from_yaml`] and those made with
    /// [`TrustStore::add`], in file order. One-run keys made with [`TrustStore::pin`] are not listed,
    /// for the same reason [`TrustStore::to_yaml`] never writes them.
    pub fn entries(&self) -> impl Iterator<Item = TrustEntry<'_>> {
        self.pins
            .iter()
            .filter(|pin| pin.added_at.is_some())
            .map(|pin| TrustEntry { pin })
    }

    /// Pins `key` for `product` as a kept entry: it is written by [`TrustStore::to_yaml`].
    ///
    /// `added_at` is `YYYY-MM-DDTHH:MM:SSZ`. An empty `note` is no note. The checks are the ones
    /// [`TrustStore::from_yaml`] makes, so the text this store writes always reads back.
    ///
    /// # Errors
    ///
    /// [`TrustAddError`] if `product` already has a key with this key id (a second key with one id would
    /// make the id useless for picking the key), if `added_at` is not a time of that form, or if the note
    /// is longer than 512 characters or has a control character. The store is unchanged on an error.
    pub fn add(
        &mut self,
        product: ProductSlug,
        key: PublicKey,
        source: TrustSource,
        added_at: &str,
        note: Option<&str>,
    ) -> Result<(), TrustAddError> {
        if !valid_timestamp(added_at) {
            return Err(TrustAddError::BadTime);
        }
        let note = note.filter(|note| !note.is_empty());
        if let Some(note) = note {
            check_note(note).map_err(|reason| TrustAddError::BadNote { reason })?;
        }
        let clash = self
            .pins_for(&product)
            .find(|pin| pin.key.key_id() == key.key_id())
            .map(|pin| pin.key == key);
        if let Some(same_key) = clash {
            return Err(TrustAddError::DuplicateKeyId {
                product,
                key_id: key.key_id(),
                same_key,
            });
        }
        self.pins.push(Pin {
            product,
            key,
            source,
            added_at: Some(added_at.to_owned()),
            note: note.map(str::to_owned),
        });
        Ok(())
    }

    /// Removes the kept entry for `product` with this key id. Returns true if there was one.
    ///
    /// A key id is unique within a product in a store, so at most one entry goes.
    pub fn remove(&mut self, product: &ProductSlug, key_id: KeyId) -> bool {
        let before = self.pins.len();
        self.pins.retain(|pin| {
            !(pin.added_at.is_some() && pin.product == *product && pin.key.key_id() == key_id)
        });
        self.pins.len() != before
    }
}

/// One kept entry of a [`TrustStore`], as `rdy trust list` shows it.
#[derive(Debug, Clone, Copy)]
pub struct TrustEntry<'a> {
    pin: &'a Pin,
}

impl<'a> TrustEntry<'a> {
    /// The product the key is trusted for.
    #[must_use]
    pub fn product(&self) -> &'a ProductSlug {
        &self.pin.product
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &'a PublicKey {
        &self.pin.key
    }

    /// The store the entry came from.
    #[must_use]
    pub fn source(&self) -> TrustSource {
        self.pin.source
    }

    /// When the key was pinned, `YYYY-MM-DDTHH:MM:SSZ`.
    #[must_use]
    pub fn added_at(&self) -> &'a str {
        self.pin.added_at.as_deref().unwrap_or_default()
    }

    /// The note the user wrote, if any.
    #[must_use]
    pub fn note(&self) -> Option<&'a str> {
        self.pin.note.as_deref()
    }
}

/// Why [`TrustStore::add`] refused an entry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TrustAddError {
    /// The product already has a key with this key id.
    #[error("{product} already has a key with the id {key_id}")]
    DuplicateKeyId {
        /// The product.
        product: ProductSlug,
        /// The id both keys have.
        key_id: KeyId,
        /// True when the two keys are the same key. False when only the id matches, which anyone can
        /// arrange, so the fingerprints must be compared.
        same_key: bool,
    },
    /// `added_at` is not a time like `2026-11-30T16:20:00Z`.
    #[error("the time of the entry is not a time like 2026-11-30T16:20:00Z")]
    BadTime,
    /// The note cannot be written to a trust file.
    #[error("the note is not usable: {reason}")]
    BadNote {
        /// What is wrong, in fixed words.
        reason: &'static str,
    },
}

/// The rules for a note, shared by the reader and [`TrustStore::add`].
fn check_note(note: &str) -> Result<(), &'static str> {
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err("the note is longer than 512 characters");
    }
    if note.chars().any(char::is_control) {
        return Err("the note has a control character");
    }
    Ok(())
}

/// A double-quoted YAML string. JSON string syntax is valid YAML, and it escapes every control
/// character, quote and backslash.
fn quoted(text: &str) -> String {
    // A string cannot fail to serialize. The fallback is an empty string, which reads back as no note.
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
}

fn typed_read(text: &str) -> Result<RawFile, TrustFileError> {
    let mut budget = Budget::default();
    budget.max_depth = MAX_DEPTH;
    budget.max_documents = 1;
    budget.max_anchors = 0;
    budget.max_aliases = 0;
    budget.max_merge_keys = 0;
    // A value takes at least one byte, so a file of the size limit holds at most that many nodes.
    budget.max_nodes = MAX_TRUST_BYTES;
    budget.max_events = MAX_TRUST_BYTES.saturating_mul(4);
    budget.flow_nesting_limit = MAX_DEPTH;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.duplicate_keys = DuplicateKeyPolicy::Error;
    options.merge_keys = MergeKeyPolicy::Error;
    options.reject_unsupported_tags = true;
    options.non_finite_float_policy = NonFiniteFloatPolicy::Reject;
    options.legacy_octal_numbers = false;
    options.strict_booleans = true;
    options.with_snippet = false;
    serde_saphyr::from_str_with_options::<RawFile>(text, options).map_err(map_read_error)
}

fn map_read_error(error: serde_saphyr::Error) -> TrustFileError {
    use serde_saphyr::Error as E;
    let error = error.without_snippet();
    let at = error.location().map(|l| {
        let clamp = |n: u64| u32::try_from(n).unwrap_or(u32::MAX).max(1);
        Location::new(clamp(l.line()), clamp(l.column()))
    });
    let invalid = |reason: &str| TrustFileError::Invalid {
        reason: reason.to_owned(),
        at,
    };
    match &error {
        E::SerdeUnknownField { field, .. } => TrustFileError::UnknownField {
            key: echo_capped(field, 64),
            at,
        },
        E::SerdeMissingField { field, .. } => TrustFileError::Invalid {
            reason: format!("it has no {}", echo_capped(field, 64)),
            at,
        },
        E::DuplicateMappingKey { .. } => invalid("a key appears twice"),
        E::MultipleDocuments { .. } => invalid("it has more than one document"),
        E::MergeKeyNotAllowed { .. } => invalid("it uses a merge key"),
        E::InvalidUtf8Input => TrustFileError::NotUtf8,
        E::Budget {
            breach: BudgetBreach::Depth { .. },
            ..
        } => invalid("it is nested too deeply"),
        E::Budget { .. } => invalid("it has more values than rdy reads"),
        other => {
            let text = other.to_string();
            let first = text.lines().next().unwrap_or_default();
            let first = first.rfind(" at line ").map_or(first, |i| &first[..i]);
            TrustFileError::Invalid {
                reason: echo_reason(first, MAX_REASON_CHARS),
                at,
            }
        }
    }
}

#[cfg(test)]
mod tests;
