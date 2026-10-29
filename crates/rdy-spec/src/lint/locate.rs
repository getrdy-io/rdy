//! Finds the line and column of lint findings.
//!
//! [`crate::parse_unverified`] gives a [`crate::spec::Spec`] with no positions, because the values of a
//! check pass through `serde_json::Value`. Lint needs them only for the few entries that have a finding,
//! so a second read of the text, run after the parse succeeded, finds them. It reads the YAML event
//! stream, keeps the path of the node it is on, and records the position of the keys and values that a
//! finding points at. Nothing else is stored, so the cost is the read itself.
//!
//! A path is the one in a finding: `mn`, or `free[0].prot` for a key inside a list of blocks, counted
//! from the top of the check entry. It is compared in its escaped and cut form, as it is printed.

use std::collections::{HashMap, HashSet};

use serde_saphyr::granit_parser::{Event, Options as ParserOptions, Parser};

use super::Spot;
use crate::Location;
use crate::error::echo_safe;
use crate::parse::{MAX_DEPTH, location_of};

/// One step from a node to a node inside it.
#[derive(Debug, Clone)]
enum Seg {
    Key(String),
    Index(usize),
}

/// The kinds of node the walk tells apart.
enum Node<'a> {
    Scalar(&'a str),
    Seq,
    Map,
}

/// A list or a map being read.
enum Frame {
    Map {
        /// The next node is a key.
        expecting_key: bool,
        /// The key whose value is being read.
        key: Option<String>,
    },
    Seq {
        /// The index of the next item.
        next: usize,
    },
}

/// The positions found for the wanted entries.
#[derive(Debug, Default)]
pub(crate) struct Places {
    entries: HashMap<usize, Location>,
    keys: HashMap<(usize, String), Location>,
    values: HashMap<(usize, String), Location>,
}

impl Places {
    /// The position a finding about entry `index` points at, or the start of the entry when the exact
    /// place is not known.
    pub(crate) fn of(&self, index: usize, spot: &Spot) -> Option<Location> {
        let entry = self.entries.get(&index).copied();
        match spot {
            Spot::Entry => entry,
            Spot::Id => self
                .values
                .get(&(index, "id".to_owned()))
                .copied()
                .or(entry),
            Spot::Key(path) => self.keys.get(&(index, path.clone())).copied().or(entry),
            Spot::Value(path) => self
                .values
                .get(&(index, path.clone()))
                .or_else(|| self.keys.get(&(index, path.clone())))
                .copied()
                .or(entry),
        }
    }
}

/// Reads `text`, which parsed as a spec, and finds the positions that the `wanted` findings need.
pub(crate) fn locate(text: &str, wanted: &[(usize, &Spot)]) -> Places {
    let mut walker = Walker {
        frames: Vec::new(),
        path: Vec::new(),
        entries: wanted.iter().map(|(index, _)| *index).collect(),
        paths: wanted
            .iter()
            .filter_map(|(index, spot)| match spot {
                Spot::Key(path) | Spot::Value(path) => Some((*index, path.clone())),
                Spot::Id => Some((*index, "id".to_owned())),
                Spot::Entry => None,
            })
            .collect(),
        found: Places::default(),
    };
    let mut options = ParserOptions::default();
    options.set_emit_comments(false);
    options.block_nesting_limit = MAX_DEPTH * 2;
    options.flow_nesting_limit = MAX_DEPTH * 2;
    for item in Parser::new_from_str_with_options(text, options) {
        let Ok((event, span)) = item else {
            break;
        };
        let at = location_of(&span.start);
        match event {
            Event::Scalar(value, ..) => walker.node(&Node::Scalar(&value), at),
            Event::SequenceStart(..) => walker.node(&Node::Seq, at),
            Event::MappingStart(..) => walker.node(&Node::Map, at),
            Event::SequenceEnd | Event::MappingEnd => walker.close(),
            _ => {}
        }
    }
    walker.found
}

struct Walker {
    frames: Vec<Frame>,
    /// How each open list or map was reached, from the root. The root has no step.
    path: Vec<Seg>,
    /// The entries that have a finding.
    entries: HashSet<usize>,
    /// The escaped paths that findings point at, with their entries.
    paths: HashSet<(usize, String)>,
    found: Places,
}

impl Walker {
    /// A scalar, or the start of a list or a map.
    fn node(&mut self, node: &Node<'_>, at: Location) {
        let step = match self.frames.last_mut() {
            None => None,
            Some(Frame::Map { expecting_key, key }) if *expecting_key => {
                // A key. Only a plain text key can be one; anything else was refused by the parser.
                if let Node::Scalar(text) = node {
                    *key = Some((*text).to_owned());
                    *expecting_key = false;
                    self.record(Some(Seg::Key((*text).to_owned())), at, true);
                }
                return;
            }
            Some(Frame::Map { key, .. }) => Some(Seg::Key(key.clone().unwrap_or_default())),
            Some(Frame::Seq { next }) => {
                let index = *next;
                *next += 1;
                Some(Seg::Index(index))
            }
        };
        self.record(step.clone(), at, false);
        let frame = match node {
            Node::Seq => Frame::Seq { next: 0 },
            Node::Map => Frame::Map {
                expecting_key: true,
                key: None,
            },
            Node::Scalar(_) => {
                // A scalar value ends its entry.
                if let Some(Frame::Map { expecting_key, .. }) = self.frames.last_mut() {
                    *expecting_key = true;
                }
                return;
            }
        };
        self.frames.push(frame);
        if let Some(step) = step {
            self.path.push(step);
        }
    }

    /// The end of a list or a map.
    fn close(&mut self) {
        if self.frames.len() > 1 {
            self.path.pop();
        }
        self.frames.pop();
        if let Some(Frame::Map { expecting_key, .. }) = self.frames.last_mut() {
            *expecting_key = true;
        }
    }

    /// Notes the position of the node reached from the open collections by `step`, when it is a wanted
    /// entry, or a key or value in one.
    fn record(&mut self, step: Option<Seg>, at: Location, is_key: bool) {
        let Some(step) = step else { return };
        let mut steps = self.path.iter().chain(std::iter::once(&step));
        let (Some(Seg::Key(top)), Some(Seg::Index(index))) = (steps.next(), steps.next()) else {
            return;
        };
        if top != "checks" || !self.entries.contains(index) {
            return;
        }
        let rest: Vec<&Seg> = steps.collect();
        if rest.is_empty() {
            if !is_key {
                self.found.entries.insert(*index, at);
            }
            return;
        }
        let path = echo_safe(&render(&rest));
        if self.paths.contains(&(*index, path.clone())) {
            let map = if is_key {
                &mut self.found.keys
            } else {
                &mut self.found.values
            };
            map.insert((*index, path), at);
        }
    }
}

/// `mn`, `free[0].prot`: a key first, then `.key` and `[index]` steps.
fn render(steps: &[&Seg]) -> String {
    let mut out = String::new();
    for step in steps {
        match step {
            Seg::Key(key) if out.is_empty() => out.push_str(key),
            Seg::Key(key) => {
                out.push('.');
                out.push_str(key);
            }
            Seg::Index(i) => out.push_str(&format!("[{i}]")),
        }
    }
    out
}
