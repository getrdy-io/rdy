//! The YAML reader behind [`parse_unverified`].
//!
//! ADR 0001 sets the rules and `docs/plan/01-spec-format.md` section 2 lists them. This module is the
//! only place that names the YAML crates. Nothing here appears in a public signature.
//!
//! The reader makes two passes over text that is already in memory.
//!
//! 1. **The guard.** It reads the YAML event stream and refuses everything a spec must not contain:
//!    directives, tags, anchors, aliases, merge keys, a second document, duplicate keys, nesting past 64
//!    levels, non-finite numbers and unquoted decimals. Each refusal carries a line and column. The guard
//!    keeps its own rules so that a spec cannot depend on how the YAML crate happens to treat a corner.
//! 2. **The typed read.** `serde-saphyr` reads the text into [`Spec`] with the same limits set again as a
//!    second line of defence (no anchors, no aliases, one document, depth 64, errors on duplicate keys,
//!    merge keys and unknown tags, errors on non-finite numbers).
//!
//! Check parameters are read into `serde_json::Value`, which keeps the last of two equal keys and turns a
//! non-finite number into `null`. So only after the guard has passed is the typed read allowed to run.
//!
//! Nothing here proves who wrote the bytes. The result is a [`Spec`], never a [`crate::LoadedSpec`].

use std::collections::HashSet;

use serde_saphyr::budget::BudgetBreach;
use serde_saphyr::granit_parser::{
    ErrorKind, Event, Marker, Options as ParserOptions, Parser, ScalarStyle, Scanner, Span,
    StrInput, Tag, TokenType,
};
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};
use serde_saphyr::{Budget, NonFiniteFloatPolicy};

use crate::check::find_duplicate;
use crate::error::echo_reason;
use crate::error::echo_safe;
use crate::limits::{
    self, MAX_CHECKS, PLACED_COLLECT_ITEMS, PLACED_METADATA_KEYS, PLACED_REGEX_ITEMS, Places,
};
use crate::spec::Spec;
use crate::{API_VERSION, Location, SpecError};

/// The largest spec file rdy reads, 1 MiB (ADR 0001).
pub const MAX_SPEC_BYTES: usize = 1024 * 1024;

/// The deepest nesting of lists and maps rdy reads (ADR 0001). The top-level map is level 1.
pub const MAX_DEPTH: usize = 64;

/// The most characters of a reason from the YAML reader that an error keeps.
const MAX_REASON_CHARS: usize = 160;

/// Reads spec text into a [`Spec`] without checking who wrote it.
///
/// This is for `rdy spec lint` and `rdy verify` diagnostics only. It never returns a
/// [`crate::LoadedSpec`], and no function turns the [`Spec`] it returns into one. A run, including an
/// `--allow-unsigned` run, goes through [`crate::load`] with an unsigned policy (M1-120), which checks the
/// signature state before it parses.
///
/// The limits (ADR 0001, `docs/plan/01-spec-format.md` section 2):
///
/// - at most 1 MiB, checked before any parsing, and valid UTF-8;
/// - one YAML document, nesting at most 64 levels deep;
/// - no duplicate keys at any depth, including inside the parameters of a check;
/// - no anchors, aliases, merge keys (`<<`), explicit tags (`!!binary`, `!custom`) or directives
///   (`%YAML`, `%TAG`);
/// - no `.nan`, `.inf` or other number that is not finite;
/// - no unquoted decimal such as `12.10`, which YAML would read as the number 12.1, and no whole number
///   with a leading zero (`0755`) or outside the range of `i64` and `u64`. Write `"12.10"`;
/// - `apiVersion` is `rdy/v1`. A later version, such as `rdy/v2`, gets its own error, and once the file
///   has said `rdy/v2` that error replaces any refusal further down.
///
/// Whatever the bytes hold, this returns a value or an error. It does not panic.
///
/// # Errors
///
/// A [`SpecError`] for each case above, and for YAML that does not read, a key the format does not
/// have, a missing key or a value of the wrong shape. Almost every error is a [`SpecError::Located`],
/// so [`SpecError::location`] gives the line and column. A refused value in a message is cut to 64
/// characters and escaped, so it is safe to print.
pub fn parse_unverified(bytes: &[u8]) -> Result<Spec, SpecError> {
    parse_bytes(bytes)
}

/// The shared reader. [`crate::load`] will call it with bytes that were verified first.
pub(crate) fn parse_bytes(bytes: &[u8]) -> Result<Spec, SpecError> {
    #[cfg(test)]
    spy::record_call();
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(SpecError::TooLarge {
            size: bytes.len(),
            limit: MAX_SPEC_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| SpecError::NotUtf8.at(location_of_byte(bytes, e.valid_up_to())))?;
    let GuardOutcome { facts, error } = guard(text);
    let error = match (find_lexical(text), error) {
        (None, error) => error,
        (Some(lexical), None) => Some(lexical),
        // Both found something. The one nearer the top of the file is the one to fix first.
        (Some(lexical), Some(guarded)) => Some(earlier(lexical, guarded)),
    };
    if let Some(error) = error {
        // Once the file has said it is for a later rdy/v, nothing after that is worth reporting.
        return Err(facts.later_version_before(&error).unwrap_or(error));
    }
    facts.check_api_version()?;
    // The guard counted the entries, so a huge list is refused before the typed read builds it.
    facts.check_entry_count()?;
    let spec = typed_read(text).map_err(|e| facts.entry_without_id(&e).unwrap_or(e))?;
    // A duplicate entry key is a fact about the whole list, so it is told after the typed read. The
    // guard saw the entries in file order, which is the order of `spec.checks`.
    if let Some((index, error)) = find_duplicate(&spec.checks) {
        return Err(match facts.entries.get(index) {
            Some(entry) if facts.entries.len() == spec.checks.len() => error.at(entry.at),
            _ => error,
        });
    }
    if spec.api_version != API_VERSION {
        // The guard checked this already. Keep the check here so the rule holds on its own.
        return Err(SpecError::BadApiVersion {
            found: Some(echo_safe(&spec.api_version)),
        }
        .at(Location::new(1, 1)));
    }
    limits::validate(&spec, &facts.places)?;
    Ok(spec)
}

pub(crate) fn location_of(marker: &Marker) -> Location {
    let to_u32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    // The reader counts columns from 0 and lines from 1.
    Location::new(
        to_u32(marker.line()),
        to_u32(marker.col().saturating_add(1)),
    )
}

/// The line and column of the byte at `offset`, for text that is not valid UTF-8 from there on.
fn location_of_byte(bytes: &[u8], offset: usize) -> Location {
    let valid = String::from_utf8_lossy(&bytes[..offset.min(bytes.len())]);
    let mut line: u32 = 1;
    let mut column: u32 = 1;
    let mut chars = valid.chars().peekable();
    while let Some(c) = chars.next() {
        let is_break = c == '\n' || (c == '\r' && chars.peek() != Some(&'\n'));
        if is_break {
            line = line.saturating_add(1);
            column = 1;
        } else if c != '\r' {
            column = column.saturating_add(1);
        }
    }
    Location::new(line, column)
}

/// The reader's errors about a tab.
fn is_tab_error(kind: &ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::TabNotAllowed
            | ErrorKind::TabInBlockIndentation
            | ErrorKind::TabInIndentation
            | ErrorKind::TabAtBlockScalarStart
            | ErrorKind::TabInPlainScalar
    )
}

/// The reader reports a tab error one column past the tab, because it has already read the tab. Point at the
/// tab itself, but only when the character just before `at` really is a tab.
fn back_onto_tab(text: &str, at: Location) -> Location {
    let line = usize::try_from(at.line)
        .unwrap_or(usize::MAX)
        .saturating_sub(1);
    let before = usize::try_from(at.column)
        .unwrap_or(usize::MAX)
        .saturating_sub(2);
    // Column 1 has no character before it, so the reader already points at the tab.
    let is_tab = at.column >= 2
        && text
            .split('\n')
            .nth(line)
            .and_then(|l| l.chars().nth(before))
            == Some('\t');
    if is_tab {
        Location::new(at.line, at.column - 1)
    } else {
        at
    }
}

/// A place as a value that sorts in file order.
fn position_key(at: Location) -> (u32, u32) {
    (at.line, at.column)
}

/// The error whose place is nearer the top of the file. A tie goes to `first`.
fn earlier(first: SpecError, second: SpecError) -> SpecError {
    let key = |e: &SpecError| e.location().map_or((u32::MAX, u32::MAX), position_key);
    if key(&second) < key(&first) {
        second
    } else {
        first
    }
}

/// Finds the first directive, tag, anchor or alias, by reading tokens.
///
/// A directive is not an event, and an alias to an unknown anchor stops the event reader before it
/// reaches the alias. Tokens have none of these gaps, and they give the exact place of the `%`, `!`, `&`
/// or `*`. A scan error ends the search. The guard reports it as a syntax error.
fn find_lexical(text: &str) -> Option<SpecError> {
    let mut options = ParserOptions::default();
    options.set_emit_comments(false);
    options.block_nesting_limit = MAX_DEPTH * 2;
    options.flow_nesting_limit = MAX_DEPTH * 2;
    let scanner = Scanner::with_options(StrInput::new(text), options);
    for token in scanner {
        let token = token.ok()?;
        let at = location_of(&token.span().start);
        match token.token_type() {
            TokenType::VersionDirective(..)
            | TokenType::TagDirective(..)
            | TokenType::ReservedDirective(..) => return Some(SpecError::Directive.at(at)),
            TokenType::Tag(handle, suffix) => {
                return Some(
                    SpecError::Tag {
                        tag: echo_safe(&format!("{handle}{suffix}")),
                    }
                    .at(at),
                );
            }
            TokenType::Anchor(_) => return Some(SpecError::Anchor.at(at)),
            TokenType::Alias(_) => return Some(SpecError::Alias.at(at)),
            _ => {}
        }
    }
    None
}

/// What the guard learned about `apiVersion`.
enum ApiVersionFact {
    /// The root is a map and has no `apiVersion` key.
    Missing,
    /// The value is a scalar, with the text and where it starts.
    Text(String, Location),
    /// The value is a list or a map, where it starts.
    NotText(Location),
}

/// Where a check entry starts and whether it has an `id` key.
struct EntryFact {
    at: Location,
    has_id: bool,
}

/// What the guard learned while it read the whole file.
struct Facts {
    api_version: Option<ApiVersionFact>,
    /// The entries of the top-level `checks` list, in file order. At most [`MAX_CHECKS`] plus one are
    /// kept: a list over the limit is refused, and its tail is never read for anything else.
    entries: Vec<EntryFact>,
    /// How many entries the top-level `checks` list has, counted without keeping them.
    entry_count: usize,
    /// Where a few values start, for the errors of [`limits::validate`].
    places: Places,
}

impl Facts {
    /// `TooManyChecks` when the `checks` list has more entries than the limit. The count is the real
    /// one, even though only the first 257 entries are kept.
    fn check_entry_count(&self) -> Result<(), SpecError> {
        if self.entry_count > MAX_CHECKS {
            return Err(SpecError::TooManyChecks {
                count: self.entry_count,
                limit: MAX_CHECKS,
            });
        }
        Ok(())
    }

    /// `MissingCheckId` at the first entry with no `id` key, when `error` is the typed read saying an
    /// `id` is missing. The typed read walks the file in order, so the first such entry is the one it
    /// stopped at. The typed read does not know the position of the entry in the list. The guard does.
    fn entry_without_id(&self, error: &SpecError) -> Option<SpecError> {
        if !matches!(error.kind(), SpecError::MissingField { field } if field == "id") {
            return None;
        }
        let (index, entry) = self.entries.iter().enumerate().find(|(_, e)| !e.has_id)?;
        Some(
            SpecError::MissingCheckId {
                number: index.saturating_add(1),
            }
            .at(entry.at),
        )
    }

    /// `UnsupportedApiVersion` when `apiVersion` named a later version at a place above `error`. A file for
    /// a later rdy can hold keys and values this rdy refuses, so the advice is to upgrade (ADR 0001).
    fn later_version_before(&self, error: &SpecError) -> Option<SpecError> {
        let Some(ApiVersionFact::Text(text, at)) = &self.api_version else {
            return None;
        };
        let nearer_top = error
            .location()
            .is_none_or(|e| position_key(*at) < position_key(e));
        (is_later_version(text) && nearer_top).then(|| {
            SpecError::UnsupportedApiVersion {
                found: echo_safe(text),
            }
            .at(*at)
        })
    }

    /// Runs the `apiVersion` rule of 01 section 3.1 before the typed read, so a later version is told to
    /// upgrade instead of being told about every key it adds.
    fn check_api_version(&self) -> Result<(), SpecError> {
        match &self.api_version {
            Some(ApiVersionFact::Text(text, at)) => {
                if text == API_VERSION {
                    Ok(())
                } else if is_later_version(text) {
                    Err(SpecError::UnsupportedApiVersion {
                        found: echo_safe(text),
                    }
                    .at(*at))
                } else {
                    Err(SpecError::BadApiVersion {
                        found: Some(echo_safe(text)),
                    }
                    .at(*at))
                }
            }
            Some(ApiVersionFact::NotText(at)) => {
                Err(SpecError::BadApiVersion { found: None }.at(*at))
            }
            Some(ApiVersionFact::Missing) => {
                Err(SpecError::BadApiVersion { found: None }.at(Location::new(1, 1)))
            }
            // The root is not a map. The typed read says so.
            None => Ok(()),
        }
    }
}

/// `rdy/v2`, `rdy/v10` and so on: the group is ours and the number is above 1.
fn is_later_version(text: &str) -> bool {
    let Some(digits) = text.strip_prefix("rdy/v") else {
        return false;
    };
    !digits.is_empty()
        && digits.len() <= 9
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.parse::<u32>().is_ok_and(|n| n >= 2)
}

enum Frame {
    Seq,
    Map {
        /// The next node is a key.
        expecting_key: bool,
        /// The key whose value is being read.
        key: Option<String>,
        /// Every key of this map so far.
        seen: HashSet<String>,
    },
}

/// The node kinds the guard checks.
enum Node<'a> {
    Scalar { value: &'a str, style: ScalarStyle },
    SeqStart,
    MapStart,
}

struct Guard {
    frames: Vec<Frame>,
    documents: usize,
    root_is_map: bool,
    seen_root: bool,
    /// The next value belongs to the top-level `apiVersion` key.
    api_next: bool,
    api_version: Option<ApiVersionFact>,
    /// The first entries of the top-level `checks` list. See [`Facts::entries`].
    entries: Vec<EntryFact>,
    /// How many entries the top-level `checks` list has had so far.
    entry_count: usize,
    places: Places,
}

/// What the guard found: the facts it learned before it stopped, and the first thing it refused.
struct GuardOutcome {
    facts: Facts,
    error: Option<SpecError>,
}

/// Reads the whole event stream and refuses what a spec must not contain.
///
/// It keeps the `apiVersion` fact even when it refuses something later in the file.
fn guard(text: &str) -> GuardOutcome {
    let mut g = Guard {
        frames: Vec::new(),
        documents: 0,
        root_is_map: false,
        seen_root: false,
        api_next: false,
        api_version: None,
        entries: Vec::new(),
        entry_count: 0,
        places: Places::default(),
    };
    let error = read_events(&mut g, text).err();
    if error.is_none() && g.root_is_map && g.api_version.is_none() {
        g.api_version = Some(ApiVersionFact::Missing);
    }
    GuardOutcome {
        facts: Facts {
            api_version: g.api_version,
            entries: g.entries,
            entry_count: g.entry_count,
            places: g.places,
        },
        error,
    }
}

fn read_events(g: &mut Guard, text: &str) -> Result<(), SpecError> {
    let mut options = ParserOptions::default();
    options.set_emit_comments(false);
    // Our own depth rule fires first. The reader's limits only keep its stack bounded.
    options.block_nesting_limit = MAX_DEPTH * 2;
    options.flow_nesting_limit = MAX_DEPTH * 2;
    let parser = Parser::new_from_str_with_options(text, options);
    for item in parser {
        let (event, span) = item.map_err(|e| {
            let error = match e.kind() {
                ErrorKind::RecursionLimitExceeded => SpecError::TooDeep { limit: MAX_DEPTH },
                ErrorKind::UnknownAnchor => SpecError::Alias,
                _ => SpecError::Syntax {
                    reason: echo_reason(&e.info(), MAX_REASON_CHARS),
                },
            };
            let at = location_of(e.marker());
            let at = if is_tab_error(e.kind()) {
                back_onto_tab(text, at)
            } else {
                at
            };
            error.at(at)
        })?;
        let at = location_of(&span.start);
        match event {
            Event::DocumentStart(..) => {
                g.documents += 1;
                if g.documents > 1 {
                    return Err(SpecError::MultipleDocuments.at(at));
                }
            }
            Event::Alias(_) => return Err(SpecError::Alias.at(at)),
            Event::Scalar(value, style, anchor, tag) => {
                g.refuse_decoration(anchor, tag.as_deref(), &span)?;
                g.node(
                    &Node::Scalar {
                        value: &value,
                        style,
                    },
                    at,
                )?;
            }
            Event::SequenceStart(_, anchor, tag) => {
                g.refuse_decoration(anchor, tag.as_deref(), &span)?;
                g.node(&Node::SeqStart, at)?;
            }
            Event::MappingStart(_, anchor, tag) => {
                g.refuse_decoration(anchor, tag.as_deref(), &span)?;
                g.node(&Node::MapStart, at)?;
            }
            Event::SequenceEnd | Event::MappingEnd => g.close(),
            Event::StreamEnd if g.documents == 0 => {
                return Err(SpecError::Syntax {
                    reason: "the file has no YAML document".to_owned(),
                }
                .at(Location::new(1, 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

impl Guard {
    /// Refuses an anchor or an explicit tag on a node.
    fn refuse_decoration(
        &self,
        anchor: usize,
        tag: Option<&Tag>,
        span: &Span,
    ) -> Result<(), SpecError> {
        if anchor != 0 {
            return Err(SpecError::Anchor.at(location_of(&span.start)));
        }
        if let Some(tag) = tag {
            let written = format!("{}{}", tag.original_handle(), tag.suffix());
            let at = location_of(span.tag_start.as_ref().unwrap_or(&span.start));
            return Err(SpecError::Tag {
                tag: echo_safe(&written),
            }
            .at(at));
        }
        Ok(())
    }

    /// Closes a list or a map. The map that holds it is ready for its next key.
    fn close(&mut self) {
        self.frames.pop();
        if let Some(Frame::Map { expecting_key, .. }) = self.frames.last_mut() {
            *expecting_key = true;
        }
    }

    /// The key of the nearest enclosing map entry, for messages.
    fn current_key(&self) -> Option<&str> {
        self.frames.iter().rev().find_map(|f| match f {
            Frame::Map { key: Some(k), .. } => Some(k.as_str()),
            _ => None,
        })
    }

    /// The top-level `checks` list is open and nothing inside it is: the next map starts an entry.
    fn in_checks_list(&self) -> bool {
        matches!(
            self.frames.as_slice(),
            [Frame::Map { key: Some(k), .. }, Frame::Seq] if k == "checks"
        )
    }

    /// Remembers where a metadata value, a `bundle.collect` item or a redact pattern's regex starts. The reader sees a node before
    /// it knows whether it is a key, so this runs first and looks at the frames.
    fn note_place(&mut self, at: Location) {
        match self.frames.as_slice() {
            [
                Frame::Map { key: Some(top), .. },
                Frame::Map {
                    expecting_key: false,
                    key: Some(k),
                    ..
                },
            ] if top == "metadata" => {
                if let Some(name) = PLACED_METADATA_KEYS.iter().find(|n| **n == k) {
                    self.places.metadata.entry(name).or_insert(at);
                }
            }
            [
                Frame::Map { key: Some(top), .. },
                Frame::Map {
                    key: Some(inner), ..
                },
                Frame::Seq,
            ] if top == "bundle"
                && inner == "collect"
                && self.places.collect.len() < PLACED_COLLECT_ITEMS =>
            {
                self.places.collect.push(at);
            }
            [
                Frame::Map { key: Some(top), .. },
                Frame::Map {
                    key: Some(inner), ..
                },
                Frame::Seq,
                Frame::Map {
                    expecting_key: false,
                    key: Some(k),
                    ..
                },
            ] if top == "bundle"
                && inner == "redact_patterns"
                && k == "regex"
                && self.places.regex.len() < PLACED_REGEX_ITEMS =>
            {
                self.places.regex.push(at);
            }
            _ => {}
        }
    }

    /// The map being read is an entry of the top-level `checks` list.
    fn in_check_entry(&self) -> bool {
        matches!(
            self.frames.as_slice(),
            [Frame::Map { key: Some(k), .. }, Frame::Seq, Frame::Map { .. }] if k == "checks"
        )
    }

    fn node(&mut self, node: &Node<'_>, at: Location) -> Result<(), SpecError> {
        if matches!(node, Node::SeqStart | Node::MapStart) && self.frames.len() >= MAX_DEPTH {
            return Err(SpecError::TooDeep { limit: MAX_DEPTH }.at(at));
        }
        if matches!(node, Node::MapStart) && self.in_checks_list() {
            self.entry_count = self.entry_count.saturating_add(1);
            // Keep one entry past the limit, which is enough to point at it. Nothing later is stored.
            if self.entries.len() <= MAX_CHECKS {
                self.entries.push(EntryFact { at, has_id: false });
            }
        }
        self.note_place(at);
        let in_entry = self.in_check_entry();
        let is_root = !self.seen_root;
        self.seen_root = true;
        let in_root_map = self.frames.len() == 1;
        let mut value_of_api_version = false;
        match self.frames.last_mut() {
            Some(Frame::Map {
                expecting_key: expecting_key @ true,
                key,
                seen,
            }) => {
                let Node::Scalar { value, style } = node else {
                    return Err(SpecError::InvalidValue {
                        reason: "a key must be plain text".to_owned(),
                    }
                    .at(at));
                };
                if *style == ScalarStyle::Plain {
                    if *value == "<<" {
                        return Err(SpecError::MergeKey.at(at));
                    }
                    if number_kind(value) == Some(NumberKind::NonFinite) {
                        return Err(SpecError::NonFiniteNumber {
                            text: echo_safe(value),
                        }
                        .at(at));
                    }
                }
                if !seen.insert((*value).to_owned()) {
                    return Err(SpecError::DuplicateKey {
                        key: echo_safe(value),
                    }
                    .at(at));
                }
                *key = Some((*value).to_owned());
                *expecting_key = false;
                self.api_next = in_root_map && *value == "apiVersion";
                if in_entry
                    && *value == "id"
                    && let Some(entry) = self.entries.last_mut()
                {
                    entry.has_id = true;
                }
                self.push_if_collection(node);
                return Ok(());
            }
            Some(Frame::Map { .. }) => {
                value_of_api_version = std::mem::take(&mut self.api_next);
            }
            Some(Frame::Seq) | None => {}
        }
        if is_root {
            self.root_is_map = matches!(node, Node::MapStart);
            if !self.root_is_map {
                return Err(SpecError::InvalidValue {
                    reason: "a spec file must be a map of keys, starting with apiVersion"
                        .to_owned(),
                }
                .at(at));
            }
        }
        if let Node::Scalar {
            value,
            style: ScalarStyle::Plain,
        } = node
        {
            match number_kind(value) {
                Some(NumberKind::NonFinite) => {
                    return Err(SpecError::NonFiniteNumber {
                        text: echo_safe(value),
                    }
                    .at(at));
                }
                Some(NumberKind::Decimal) => {
                    return Err(SpecError::UnquotedDecimal {
                        key: self.current_key().map(echo_safe),
                        text: echo_safe(value),
                    }
                    .at(at));
                }
                None => {}
            }
        }
        if value_of_api_version {
            self.api_version = Some(match node {
                Node::Scalar { value, .. } => ApiVersionFact::Text((*value).to_owned(), at),
                Node::SeqStart | Node::MapStart => ApiVersionFact::NotText(at),
            });
        }
        let is_scalar = matches!(node, Node::Scalar { .. });
        self.push_if_collection(node);
        // A scalar value ends its entry. A collection ends it when it closes.
        if is_scalar && let Some(Frame::Map { expecting_key, .. }) = self.frames.last_mut() {
            *expecting_key = true;
        }
        Ok(())
    }

    fn push_if_collection(&mut self, node: &Node<'_>) {
        match node {
            Node::SeqStart => self.frames.push(Frame::Seq),
            Node::MapStart => self.frames.push(Frame::Map {
                expecting_key: true,
                key: None,
                seen: HashSet::new(),
            }),
            Node::Scalar { .. } => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumberKind {
    /// `.nan`, `.inf`, `-.inf`, or a decimal too large for a 64-bit float.
    NonFinite,
    /// A number that would not keep its text: one with a fraction or an exponent (`12.10`, `1e3`), a whole
    /// number with a leading zero (`0755`), or a whole number too large for `i64` and `u64`.
    Decimal,
}

/// Classifies a plain scalar by the YAML 1.2 core schema. Whole numbers are `None`, because they keep
/// their value. `inf` and `nan` without a dot are text in YAML 1.2, so they are `None` too.
fn number_kind(text: &str) -> Option<NumberKind> {
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    if matches!(
        unsigned,
        ".inf" | ".Inf" | ".INF" | ".nan" | ".NaN" | ".NAN"
    ) {
        return Some(NumberKind::NonFinite);
    }
    if unsigned.bytes().all(|b| b.is_ascii_digit()) && !unsigned.is_empty() {
        // A whole number. It must read back exactly: no leading zero (YAML 1.1 reads it as octal) and
        // within i64 or u64, or the reader would turn it into a float and lose digits.
        let leading_zero = unsigned.len() > 1 && unsigned.starts_with('0');
        let fits = text.trim_start_matches('+').parse::<i64>().is_ok()
            || text.trim_start_matches('+').parse::<u64>().is_ok();
        return (leading_zero || !fits).then_some(NumberKind::Decimal);
    }
    if !is_core_float(unsigned) {
        return None;
    }
    // Rust parses everything the grammar above lets through. Infinity means the number overflowed.
    match text.parse::<f64>() {
        Ok(f) if f.is_finite() => Some(NumberKind::Decimal),
        _ => Some(NumberKind::NonFinite),
    }
}

/// `(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?` with a `.` or an exponent in it. The sign is already
/// removed.
fn is_core_float(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |from: usize| b[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut i = digits(0);
    let int_digits = i;
    let mut has_point = false;
    let mut frac_digits = 0;
    if b.get(i) == Some(&b'.') {
        has_point = true;
        frac_digits = digits(i + 1);
        i += 1 + frac_digits;
    }
    if int_digits == 0 && frac_digits == 0 {
        return false;
    }
    let mut has_exp = false;
    if matches!(b.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(b.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let exp_digits = digits(j);
        if exp_digits == 0 {
            return false;
        }
        has_exp = true;
        i = j + exp_digits;
    }
    i == b.len() && (has_point || has_exp)
}

/// The second pass: `serde-saphyr` reads the text into the typed [`Spec`], with the limits set again.
fn typed_read(text: &str) -> Result<Spec, SpecError> {
    let mut budget = Budget::default();
    budget.max_depth = MAX_DEPTH;
    budget.max_documents = 1;
    budget.max_anchors = 0;
    budget.max_aliases = 0;
    budget.max_merge_keys = 0;
    // A value takes at least one byte, so a file of the size limit holds at most that many nodes. Raise
    // the crate's own caps to match, so a valid file of the size limit is never refused for its count.
    budget.max_nodes = MAX_SPEC_BYTES;
    budget.max_events = MAX_SPEC_BYTES.saturating_mul(4);
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
    serde_saphyr::from_str_with_options::<Spec>(text, options).map_err(map_read_error)
}

/// Turns an error of the typed read into a [`SpecError`] with no text of the YAML crate in it, except a
/// reason that is cut and escaped.
fn map_read_error(error: serde_saphyr::Error) -> SpecError {
    use serde_saphyr::Error as E;
    let error = error.without_snippet();
    let at = error
        .location()
        .map(|l| Location::new(clamp(l.line()), clamp(l.column())));
    let kind = match error {
        E::SerdeUnknownField {
            field, expected, ..
        } => unknown_key(echo_safe(field), expected),
        E::SerdeMissingField { field, .. } if *field == "apiVersion" => {
            SpecError::BadApiVersion { found: None }
        }
        E::SerdeMissingField { field, .. } => SpecError::MissingField {
            field: echo_safe(field),
        },
        E::DuplicateMappingKey { key, .. } => SpecError::DuplicateKey {
            key: echo_safe(key.as_deref().unwrap_or("?")),
        },
        E::MultipleDocuments { .. } => SpecError::MultipleDocuments,
        E::MergeKeyNotAllowed { .. } => SpecError::MergeKey,
        E::InvalidUtf8Input => SpecError::NotUtf8,
        E::Budget {
            breach: BudgetBreach::Depth { .. },
            ..
        } => SpecError::TooDeep { limit: MAX_DEPTH },
        E::Budget { .. } => SpecError::InvalidValue {
            reason: "the file has more values than rdy reads".to_owned(),
        },
        E::NonFiniteFloat { value, .. } => SpecError::NonFiniteNumber {
            text: echo_safe(value),
        },
        E::Message { msg, .. } => classify_custom(msg),
        other => SpecError::InvalidValue {
            reason: echo_reason(&reason_of(other), MAX_REASON_CHARS),
        },
    };
    match at {
        Some(at) => kind.at(at),
        None => kind,
    }
}

/// An unknown key, with the block it is in when that is not the top level. The reader lists the keys it
/// expected there, and each block has a key no other block has.
fn unknown_key(key: String, expected: &[&str]) -> SpecError {
    let section = if expected.contains(&"product") {
        Some("metadata")
    } else if expected.contains(&"collect") {
        Some("bundle")
    } else if expected.contains(&"regex") {
        Some("a redact pattern")
    } else {
        None
    };
    match section {
        Some(section) => SpecError::UnknownKeyIn { key, section },
        None => SpecError::UnknownKey { key },
    }
}

fn clamp(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX).max(1)
}

/// The text of an error of the YAML crate without the position it adds, on one line.
fn reason_of(error: &serde_saphyr::Error) -> String {
    let text = error.to_string();
    let first = text.lines().next().unwrap_or_default();
    // The position is added by us from `location`, so drop the crate's own "at line N column M".
    match first.rfind(" at line ") {
        Some(i) => first[..i].to_owned(),
        None => first.to_owned(),
    }
}

/// Turns the messages of this crate's own `Deserialize` impls back into their error. Their text is
/// already escaped and capped.
fn classify_custom(msg: &str) -> SpecError {
    if let Some(value) = msg
        .strip_prefix('\'')
        .and_then(|m| m.strip_suffix("' is not a valid product name"))
    {
        return SpecError::InvalidProduct {
            value: value.to_owned(),
        };
    }
    if let Some(value) = msg
        .strip_prefix("serial ")
        .and_then(|m| m.strip_suffix(" is too large"))
        .and_then(|n| n.parse::<u64>().ok())
    {
        return SpecError::InvalidSerial { value };
    }
    SpecError::InvalidValue {
        reason: echo_reason(msg, MAX_REASON_CHARS),
    }
}

#[cfg(test)]
mod tests;

/// The parser spy (threat model INV-01). Tests count how many times the reader started on this thread, to
/// prove that [`crate::load`] never gives it a spec that failed verification.
#[cfg(test)]
pub(crate) mod spy {
    use std::cell::Cell;

    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record_call() {
        CALLS.with(|calls| calls.set(calls.get() + 1));
    }

    /// How many times the reader started on this thread so far.
    pub(crate) fn calls() -> usize {
        CALLS.with(Cell::get)
    }
}
