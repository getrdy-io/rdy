//! Layered configuration directories: which files apply, in which order.
//!
//! `sysctl.d` and `system.conf.d` follow one rule (`sysctl.d(5)`, `systemd-system.conf(5)`):
//!
//! - the directories have a priority, `/etc` highest;
//! - a file name in a higher-priority directory hides the same name in a lower one, and a link to
//!   `/dev/null` hides it and adds nothing;
//! - the files that remain apply in the order of their base names, whatever directory holds them, so
//!   the last one to set a key wins.
//!
//! This module reads the files and returns them in that order. It does not parse them. Every read goes
//! through the probe, is bounded (256 files, 8 MiB of text in all) and is read-only.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::Path;

use rdy_engine::check::{CheckContext, CheckError};
use rdy_engine::probe::ProbeError;
use rdy_engine::text::escape_untrusted;

use crate::text::{short, soft};

/// The most files one run reads from the directories, winners and hidden ones together.
const MAX_FILES: usize = 256;
/// The most text one run reads from the files.
const MAX_TOTAL: usize = 8 << 20;
/// How the read rules name a refusal to read a device. A link to `/dev/null` ends here.
const DEVICE_RULE: &str = "device files";

/// A file that applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Layer {
    /// The path as read, with `/` separators.
    pub path: String,
    /// The text.
    pub text: String,
}

/// A file that a same-named file in a higher-priority directory hides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Hidden {
    /// The file that has no effect.
    pub path: String,
    /// The file of the same name that took its place.
    pub by: String,
    /// What the hidden file says, kept to tell the customer what they lost.
    pub text: String,
}

/// What the directories hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Layers {
    /// The files that apply, first to last.
    pub files: Vec<Layer>,
    /// The files that a higher directory hides.
    pub hidden: Vec<Hidden>,
    /// The paths that are links to `/dev/null`: they hide a lower file and say nothing.
    pub null_masks: Vec<String>,
    /// Why the list may be incomplete: a directory or a file rdy could not read. A key could be set in
    /// what was not read, so an answer of "not set" is not safe while this is not empty.
    pub unknown: Vec<String>,
}

/// What reading one file gave.
enum One {
    Text(String),
    NullMask,
    Gone,
    Unknown(String),
}

/// A directory listing: the file names it holds, or why it is not listed.
enum Listing {
    Names(Vec<String>),
    Absent,
    Unknown(String),
}

async fn list(ctx: &CheckContext, dir: &str, suffix: &str) -> Result<Listing, CheckError> {
    match ctx.probe().read_dir(Path::new(dir)).await {
        Ok(entries) => Ok(Listing::Names(
            entries
                .into_iter()
                .filter(|e| !e.is_dir && e.name.ends_with(suffix) && !e.name.contains('/'))
                .map(|e| e.name)
                .collect(),
        )),
        Err(error) => Ok(match soft(error)? {
            ProbeError::NotFound => Listing::Absent,
            ProbeError::PermissionDenied => {
                Listing::Unknown(format!("{dir} could not be read (permission denied)"))
            }
            other => Listing::Unknown(format!("{dir} could not be read ({})", short(&other))),
        }),
    }
}

async fn read_one(ctx: &CheckContext, path: &str, budget: &mut usize) -> Result<One, CheckError> {
    // A file name comes from the machine, so it is shown escaped.
    let shown = escape_untrusted(path);
    if *budget == 0 {
        return Ok(One::Unknown(format!(
            "{shown} was not read: rdy reads at most 8 MiB of configuration"
        )));
    }
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => {
            *budget = budget.saturating_sub(file.bytes.len());
            if file.truncated() {
                Ok(One::Unknown(format!(
                    "{shown} is longer than rdy reads (1 MiB)"
                )))
            } else {
                Ok(One::Text(String::from_utf8_lossy(&file.bytes).into_owned()))
            }
        }
        Err(ProbeError::Denied { rule, .. }) if rule.starts_with(DEVICE_RULE) => Ok(One::NullMask),
        Err(ProbeError::Denied { .. }) => Ok(One::Unknown(format!(
            "{shown} leads somewhere rdy's read rules do not allow"
        ))),
        Err(error) => Ok(match soft(error)? {
            ProbeError::NotFound => One::Gone,
            ProbeError::PermissionDenied => {
                One::Unknown(format!("{shown} could not be read (permission denied)"))
            }
            other => One::Unknown(format!("{shown} could not be read ({})", short(&other))),
        }),
    }
}

/// Reads the first of `paths` that exists (the main `system.conf`: only the first file found is used).
/// A file that cannot be read ends the search, because a lower file would not be the one systemd uses.
///
/// # Errors
///
/// [`CheckError`] only for a refusal by rdy's own policy, which is a fault in the check's manifest.
pub(super) async fn read_first(
    ctx: &CheckContext,
    paths: &[&str],
) -> Result<(Option<Layer>, Vec<String>), CheckError> {
    let mut budget = MAX_TOTAL;
    for path in paths {
        match read_one(ctx, path, &mut budget).await? {
            One::Text(text) => {
                let layer = Layer {
                    path: (*path).to_owned(),
                    text,
                };
                return Ok((Some(layer), Vec::new()));
            }
            One::NullMask => return Ok((None, Vec::new())),
            One::Gone => {}
            One::Unknown(why) => return Ok((None, vec![why])),
        }
    }
    Ok((None, Vec::new()))
}

/// Reads the files of `dirs` (highest priority first) that end in `suffix`, then the files in `tail`
/// (`/etc/sysctl.conf`), which apply after all of them.
///
/// With `keep_hidden`, the files that a higher directory hides are read too, so the caller can say what
/// a hidden file would have set. A hidden file with the same text as the file that hides it is the same
/// file seen through a link (`/lib` is `/usr/lib` on most systems) and is dropped.
///
/// # Errors
///
/// [`CheckError`] only for a refusal by rdy's own policy, which is a fault in the check's manifest.
pub(super) async fn read_layers(
    ctx: &CheckContext,
    dirs: &[&str],
    suffix: &str,
    tail: &[&str],
    keep_hidden: bool,
) -> Result<Layers, CheckError> {
    let mut layers = Layers::default();
    // Base name to the directory that wins it, and the lower directories that lose it.
    let mut winners: BTreeMap<String, String> = BTreeMap::new();
    let mut losers: Vec<(String, String)> = Vec::new();
    let mut counted = 0_usize;
    for dir in dirs {
        match list(ctx, dir, suffix).await? {
            Listing::Names(names) => {
                for name in names {
                    counted += 1;
                    if counted > MAX_FILES {
                        layers
                            .unknown
                            .push(format!("{dir} has more files than rdy reads ({MAX_FILES})"));
                        break;
                    }
                    match winners.entry(name) {
                        Entry::Vacant(slot) => {
                            slot.insert((*dir).to_owned());
                        }
                        Entry::Occupied(taken) => {
                            losers.push((taken.key().clone(), (*dir).to_owned()));
                        }
                    }
                }
            }
            Listing::Absent => {}
            Listing::Unknown(why) => layers.unknown.push(why),
        }
    }

    let mut budget = MAX_TOTAL;
    let mut paths: Vec<(String, String)> = winners
        .iter()
        .map(|(name, dir)| (format!("{dir}/{name}"), name.clone()))
        .collect();
    // A name is a base name, so the sort above is the order of application. The tail follows.
    paths.extend(tail.iter().map(|p| ((*p).to_owned(), String::new())));
    let mut winner_text: BTreeMap<String, String> = BTreeMap::new();
    for (path, name) in paths {
        match read_one(ctx, &path, &mut budget).await? {
            One::Text(text) => {
                if name.is_empty() {
                    // A tail file that a directory file already holds, word for word, is the same file
                    // seen through a link (Debian links `/etc/sysctl.d/99-sysctl.conf` to
                    // `/etc/sysctl.conf`). The directory applies it in its place, so it is not applied
                    // a second time and does not take over the file name. Two files that merely hold
                    // the same text also meet this test: applying either is the same, so only the
                    // label of the winning file can be wrong, never a value.
                    if winner_text.values().any(|seen| *seen == text) {
                        continue;
                    }
                } else {
                    winner_text.insert(name, text.clone());
                }
                layers.files.push(Layer { path, text });
            }
            One::NullMask => layers.null_masks.push(path),
            One::Gone => {}
            One::Unknown(why) => layers.unknown.push(why),
        }
    }

    if keep_hidden {
        for (name, dir) in losers {
            let Some(by_dir) = winners.get(&name) else {
                continue;
            };
            let by = format!("{by_dir}/{name}");
            let path = format!("{dir}/{name}");
            // A hidden file never changes the answer, so a read that fails is dropped without a word.
            if let One::Text(text) = read_one(ctx, &path, &mut budget).await?
                && winner_text.get(&name) != Some(&text)
            {
                layers.hidden.push(Hidden { path, by, text });
            }
        }
    }
    Ok(layers)
}
