//! `rdy trust add`, `rdy trust list` and `rdy trust remove` (M1-131, 07 sections A.9 to A.11 and C.10).
//!
//! The commands are split in two so tests can drive them without a terminal or the process environment:
//!
//! - [`run_add`], [`run_list`] and [`run_remove`] read the real environment and terminal
//!   ([`Layout::detect`], [`Prompter::stdio`]) and print errors the rdy way ([`emit`]).
//! - [`add`], [`list`] and [`remove`] do the work. They take the [`Layout`], the clock value and the
//!   prompt as arguments.
//!
//! Where output goes: `trust list` writes to stdout, because it is the answer. `trust add` and `trust
//! remove` print to stderr, like every command that has no result to pipe (07 section 1). An error is the
//! two lines on stderr.
//!
//! The rules, from 01 section 4.3 and ADR 0002:
//!
//! - **Pinning is the only way a key becomes trusted, and it needs a person.** `trust add` shows the key
//!   id and the fingerprint and asks `[y/N]`. With no terminal and no `--yes` it refuses with exit 64
//!   before it prints the key. `--yes` is read from argv only (INV-05): the clap flag has no `env`.
//! - **Root writes only the system store, a normal user only the user store.** The [`Layout`] decides.
//!   A root run never builds a path under a user's home (INV-04), so `sudo rdy trust add` does not
//!   touch `~/.config/rdy`.
//! - **A store that would be refused on read is not changed.** `trust add` and `trust remove` load the
//!   store they write first, so an unsafe store stops them with `trust_store_insecure`. `trust add` loads
//!   it again after the yes and saves that copy, so a change made while the question was open is kept.
//! - **A key given with `--key` on `run` or `verify` is never saved** (01 section 4.3, one-run keys). Only
//!   `trust add` calls [`trust::save`].
//! - **Windows refuses.** A Windows store cannot be checked or written in M1 (ADR 0027), so `trust add`
//!   and `trust remove` exit 64 with "not supported", before they read the key or ask anything.
//!
//! Text from argv or from a store file is escaped before it is printed ([`escape_untrusted`]). Key text
//! is never echoed.

use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use rdy_spec::sig::{KeyId, PublicKey, TrustAddError, TrustEntry, TrustSource, TrustStore};
use rdy_spec::spec::ProductSlug;

use crate::cli::{TrustAddArgs, TrustRemoveArgs};
use crate::error::{CliError, emit, escape_untrusted, shell_word};
use crate::prompt::{PromptError, Prompter, Terminal};
use crate::signing::files::FileError;
use crate::signing::pubkey::{self, GivenKeyError, Origin};
use crate::signing::time;
use crate::spec_cmds::fingerprint_lines;
use crate::trust::{self, Layout, Scope, TrustStoreError};

/// The fix line of the question, when there is no terminal to ask it on.
const NO_TERMINAL_FIX: &str =
    "check the key's fingerprint with the vendor, then run again with --yes";

/// What `trust add` did when nothing went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// The key was saved.
    Saved,
    /// The person answered no. Nothing was changed. The exit code is 64 (ADR 0002 decision 5), so a
    /// script chained with `&&` stops.
    Declined,
}

// ---------------------------------------------------------------------------------------------
// Entry points on the real terminal and environment
// ---------------------------------------------------------------------------------------------

/// Runs `rdy trust add` on the real terminal, environment and clock.
pub fn run_add(
    args: &TrustAddArgs,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    // The product is a name from the command line, and the key is never logged.
    tracing::debug!(product = %escape_untrusted(&args.product), yes = args.yes, "trust add requested");
    let layout = Layout::detect();
    let mut prompter = Prompter::stdio();
    let result = now()
        .and_then(|now| add(args, &layout, &now, &mut prompter, &mut *stderr))
        .map(|outcome| match outcome {
            AddOutcome::Saved => crate::EXIT_OK,
            AddOutcome::Declined => crate::EXIT_USAGE,
        });
    finish(result, json, stdout, stderr)
}

/// Runs `rdy trust list` on the real environment.
pub fn run_list(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let layout = Layout::detect();
    let mut text = Vec::new();
    let result = list(&layout, &mut text).map(|()| crate::EXIT_OK);
    // The listing is written only when the whole of it was read, so a refused store prints no keys.
    if result.is_ok() && stdout.write_all(&text).is_err() {
        let err = CliError::Internal(crate::error::InternalKind::OutputClosed);
        return emit(&err, false, &mut std::io::sink(), stderr);
    }
    finish(result, json, stdout, stderr)
}

/// Runs `rdy trust remove` on the real environment.
pub fn run_remove(
    args: &TrustRemoveArgs,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    tracing::debug!(product = %escape_untrusted(&args.product), "trust remove requested");
    let layout = Layout::detect();
    let result = remove(args, &layout, &mut *stderr).map(|()| crate::EXIT_OK);
    finish(result, json, stdout, stderr)
}

fn now() -> Result<String, CliError> {
    time::timestamp(SystemTime::now())
        .map_err(|e| CliError::usage(e.to_string(), "set the clock, then run again"))
}

/// The exit code of a result, after printing the error if there is one.
fn finish(
    result: Result<u8, CliError>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match result {
        Ok(code) => code,
        Err(err) => emit(&err, json, stdout, stderr),
    }
}

// ---------------------------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------------------------

/// Pins the key in `--key` for the product, after the person has compared the fingerprint.
///
/// The order matters. Everything that can fail without asking comes first (the platform, the product
/// name, the key, the note, the store and a duplicate), so nobody is asked about a key that cannot be
/// saved. Then, with no terminal and no `--yes`, the command refuses before it prints the key. Only
/// then does it show the key and ask. The store is read again after a yes, the key is added to that
/// copy and it is written. Nothing is written before the yes.
///
/// `now` is the `added_at` stamp (`YYYY-MM-DDTHH:MM:SSZ`). Progress and results go to `out`. The
/// question goes to the prompt stream of `prompter`.
///
/// # Errors
///
/// A [`CliError`], exit 64: not supported on this system, a product name or key that is not usable, a
/// secret key, a note that cannot be stored, an unsafe or invalid store, a key id that is already
/// pinned for the product, or no terminal and no `--yes`. A store that cannot be written is exit 64
/// too (ADR 0021 decision 6).
pub fn add<T: Terminal>(
    args: &TrustAddArgs,
    layout: &Layout,
    now: &str,
    prompter: &mut Prompter<T>,
    out: &mut dyn Write,
) -> Result<AddOutcome, CliError> {
    ensure_supported()?;
    let product = product_slug(&args.product)?;
    let given = pubkey::resolve(&args.key).map_err(|e| key_error(&e))?;
    let scope = layout.write_scope();
    let path = layout.path(scope).ok_or(TrustStoreError::NoUserStore)?;

    // The store is read, and refused if unsafe, before anyone is asked. The new entry goes into this
    // copy, so a duplicate id or a bad note stops the command before the question. The copy is not
    // saved: the person may take minutes to answer, and the file can change in that time.
    let mut checked = trust::load_scope(layout, scope)?;
    checked
        .add(
            product.clone(),
            given.key.clone(),
            scope.source(),
            now,
            args.note.as_deref(),
        )
        .map_err(|e| add_error(&e, path))?;

    if !args.yes && !prompter.is_interactive() {
        return Err(PromptError::NoTerminalConfirm {
            fix: NO_TERMINAL_FIX.to_owned(),
        }
        .into());
    }

    let _ = write!(out, "{}", key_summary(&product, &given.key, &given.origin));
    if !args.yes {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Compare this fingerprint with the one the vendor published on their site or\ntold you by phone. If it differs, answer n."
        );
        let _ = writeln!(out);
    }
    let question = format!("Trust this key for {product}?");
    if !prompter.confirm(&question, args.yes, NO_TERMINAL_FIX)? {
        let _ = writeln!(out, "Not trusted. Nothing was changed.");
        return Ok(AddOutcome::Declined);
    }

    // After the answer, the store is read again and the key is added to what is on disk now. A key that
    // was removed while the question was open (after a compromise, say) is not brought back by a save
    // of the copy from before. The duplicate check runs again too.
    let mut store = trust::load_scope(layout, scope)?;
    store
        .add(
            product.clone(),
            given.key.clone(),
            scope.source(),
            now,
            args.note.as_deref(),
        )
        .map_err(|e| add_error(&e, path))?;
    let saved = trust::save(layout, &store)?;
    if args.yes {
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "Trusted key {} for {product}.", given.key.key_id());
    let _ = writeln!(out, "Saved to {}", display(&saved));
    if args.note.as_deref().is_some_and(|note| !note.is_empty()) {
        let _ = writeln!(out, "Your note appears in every report you send.");
    }
    Ok(AddOutcome::Saved)
}

/// Windows and other systems without file modes and owners cannot keep a trust store in M1 (ADR 0027).
fn ensure_supported() -> Result<(), CliError> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(TrustStoreError::Unsupported.into())
    }
}

/// The product name as a slug, or a usage error.
fn product_slug(text: &str) -> Result<ProductSlug, CliError> {
    ProductSlug::new(text).map_err(|_| {
        CliError::usage(
            format!(
                "{} is not a valid product name",
                crate::error::echo(text)
            ),
            "use the product name from the vendor's docs: lowercase letters, digits and hyphens, such as acme-platform",
        )
    })
}

/// The product, key id, fingerprint and key source, as in 07 C.10.
fn key_summary(product: &ProductSlug, key: &PublicKey, origin: &Origin) -> String {
    let (first, second) = fingerprint_lines(&key.fingerprint());
    let file = match origin {
        Origin::File(path) => display(path),
        Origin::Text => "(key text from the command line)".to_owned(),
    };
    format!(
        "product      {product}\nkey id       {}\nfingerprint  {first}\n             {second}\nfile         {file}\n",
        key.key_id()
    )
}

/// The refusal for a key argument. The wording of 07 C.10: it names the file, or says "that" for text,
/// and never repeats key text.
fn key_error(err: &GivenKeyError) -> CliError {
    let name = |origin: &Origin| match origin {
        Origin::File(path) => display(path),
        Origin::Text => "that".to_owned(),
    };
    match err {
        GivenKeyError::File { path, source } => {
            let file = display(path);
            let message = match source {
                FileError::Unreadable { reason } => format!("cannot read {file}: {reason}"),
                FileError::TooLarge => format!("{file} is too large to be a public key file"),
                _ => format!("{file} is not a regular file"),
            };
            CliError::usage(
                message,
                "give the path of the vendor's .pub file, or the key text in quotes",
            )
        }
        GivenKeyError::SecretKey { origin } => {
            let message = format!("{} is a secret key, not a public key", name(origin));
            let mut fix = "give trust add the .pub file. Never share the .key file.".to_owned();
            if *origin == Origin::Text {
                // The text was typed on the command line, so the shell has it now.
                fix.push_str(" It is now in your shell history. Make a new key pair.");
            }
            CliError::usage(message, fix)
        }
        GivenKeyError::NotPublic { origin, source } => {
            let message = match origin {
                Origin::File(path) => format!("{}: {source}", display(path)),
                Origin::Text => source.to_string(),
            };
            CliError::usage(message, source.hint())
        }
        GivenKeyError::NotText { origin } => CliError::usage(
            format!("{} is not a public key file", name(origin)),
            "give the vendor's .pub file, a text file with the key in it",
        ),
    }
}

/// The refusal when the store already has the key id for the product, or a value cannot be stored.
fn add_error(err: &TrustAddError, store: &Path) -> CliError {
    let file = display(store);
    match err {
        TrustAddError::DuplicateKeyId {
            product,
            key_id,
            same_key: true,
        } => CliError::usage(
            format!("key {key_id} is already trusted for {product} in {file}"),
            "nothing to do. Run rdy trust list to see it.",
        ),
        TrustAddError::DuplicateKeyId {
            product,
            key_id,
            same_key: false,
        } => CliError::usage(
            format!("{product} already has a different key with the id {key_id} in {file}"),
            format!(
                "compare both fingerprints with rdy trust list. If the old key is wrong, run: rdy trust remove {product} --key-id {key_id}, then add this key again"
            ),
        ),
        TrustAddError::BadNote { reason } => CliError::usage(
            *reason,
            "give a note of at most 512 characters, with no line breaks or control characters",
        ),
        // `now` comes from the clock and is always in the form. A new error is rdy's, not the user's.
        _ => CliError::bug(),
    }
}

// ---------------------------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------------------------

/// Prints every trusted key: the user store, then the system store. A root run has only the system
/// store (the [`Layout`] has no user path for it).
///
/// # Errors
///
/// A [`CliError`] if a store is unsafe, cannot be read or is not valid. Nothing is printed then.
pub fn list(layout: &Layout, out: &mut dyn Write) -> Result<(), CliError> {
    let store = trust::load(layout)?;
    let text = listing(&store, layout);
    let _ = write!(out, "{text}");
    Ok(())
}

/// The text of `trust list`, in the blocks of 07 C.10.
fn listing(store: &TrustStore, layout: &Layout) -> String {
    let entries: Vec<TrustEntry<'_>> = store.entries().collect();
    if entries.is_empty() {
        return empty_listing(cfg!(unix));
    }
    let blocks: Vec<String> = entries
        .iter()
        .map(|entry| entry_block(entry, layout))
        .collect();
    blocks.join("\n")
}

/// What `trust list` says when no key is trusted. Where keys cannot be saved, it does not suggest the
/// command that saves them (ADR 0027).
fn empty_listing(can_save: bool) -> String {
    if can_save {
        "No keys are trusted yet.\nTo trust a vendor key: rdy trust add <product> --key <file>\n"
            .to_owned()
    } else {
        "No keys are trusted yet.\nrdy cannot save trusted keys on this system yet. See https://docs.getrdy.io/unsigned\n"
            .to_owned()
    }
}

fn entry_block(entry: &TrustEntry<'_>, layout: &Layout) -> String {
    let key = entry.key();
    let (first, second) = fingerprint_lines(&key.fingerprint());
    // `added_at` is `YYYY-MM-DDTHH:MM:SSZ`. The list shows the day.
    let added = entry
        .added_at()
        .get(..10)
        .unwrap_or_else(|| entry.added_at());
    let scope = match entry.source() {
        TrustSource::System => Scope::System,
        _ => Scope::User,
    };
    let file = layout.path(scope).map_or_else(String::new, display);
    let mut block = format!(
        "{}\n  key id       {}\n  fingerprint  {first}\n               {second}\n  added        {added}\n",
        entry.product(),
        key.key_id()
    );
    if let Some(note) = entry.note() {
        block.push_str(&format!("  note         {}\n", escape_untrusted(note)));
    }
    block.push_str(&format!("  file         {file}\n"));
    block
}

// ---------------------------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------------------------

/// Removes the key for a product from the store this process writes: the user store as a normal user, the
/// system store as root.
///
/// With two keys for the product, `--key-id` says which one. It matches the id as `trust list` shows it,
/// in any case. A key that is in the other store is not touched: a normal user cannot change
/// `/etc/rdy/trust.yaml`, and the error says so.
///
/// # Errors
///
/// A [`CliError`], exit 64: not supported on this system, an unsafe or invalid store, no such key, or two
/// keys and no `--key-id`.
pub fn remove(
    args: &TrustRemoveArgs,
    layout: &Layout,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    ensure_supported()?;
    let product = product_slug(&args.product)?;
    let scope = layout.write_scope();
    let path = layout.path(scope).ok_or(TrustStoreError::NoUserStore)?;
    let mut store = trust::load_scope(layout, scope)?;

    let ids: Vec<KeyId> = store
        .entries()
        .filter(|entry| *entry.product() == product)
        .map(|entry| entry.key().key_id())
        .collect();
    let id = match (&args.key_id, ids.as_slice()) {
        (wanted, []) => {
            // No key for the product here. The id is passed on so the fix can name it for `sudo`.
            let asked = wanted.as_deref().map(|id| (id, &[][..]));
            return Err(no_such_key(&product, path, layout, scope, asked));
        }
        (None, [only]) => *only,
        (None, many) => {
            return Err(CliError::usage(
                format!("{product} has {} trusted keys", many.len()),
                format!("say which one to remove with --key-id: {}", id_list(many)),
            ));
        }
        (Some(wanted), ids) => match ids
            .iter()
            .find(|id| id.to_string().eq_ignore_ascii_case(wanted))
        {
            Some(id) => *id,
            None => {
                return Err(no_such_key(
                    &product,
                    path,
                    layout,
                    scope,
                    Some((wanted, ids)),
                ));
            }
        },
    };
    if !store.remove(&product, id) {
        // The id came from this store a moment ago.
        return Err(CliError::bug());
    }
    trust::save(layout, &store)?;
    let _ = writeln!(out, "Removed key {id} for {product}.");
    Ok(())
}

fn id_list(ids: &[KeyId]) -> String {
    ids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The refusal when the store has no such key. `asked` is the `--key-id` and the ids the product has.
fn no_such_key(
    product: &ProductSlug,
    path: &Path,
    layout: &Layout,
    scope: Scope,
    asked: Option<(&str, &[KeyId])>,
) -> CliError {
    let file = display(path);
    let message = match asked {
        // A key id is hex. Anything else is not echoed.
        Some((wanted, _)) if is_key_id_text(wanted) => {
            format!(
                "{product} has no trusted key with the id {} in {file}",
                wanted.to_ascii_uppercase()
            )
        }
        Some(_) => format!("{product} has no trusted key with that id in {file}"),
        None => format!("{product} has no trusted key in {file}"),
    };
    let fix = match asked {
        Some((_, ids)) if !ids.is_empty() => {
            format!("pick one of these key ids: {}", id_list(ids))
        }
        _ if in_other_store(layout, scope, product, asked.map(|(wanted, _)| wanted)) => {
            // `--key-id` is repeated only when it is 16 hex digits. Other text is never echoed.
            let key_id = asked
                .map(|(wanted, _)| wanted)
                .filter(|wanted| is_key_id_text(wanted))
                .map_or_else(String::new, |wanted| {
                    format!(" --key-id {}", wanted.to_ascii_uppercase())
                });
            format!(
                "the key is in the system store, {}. To remove it, run as root: sudo rdy trust remove {product}{key_id}",
                layout
                    .path(Scope::System)
                    .map_or_else(String::new, |path| shell_word(&path.to_string_lossy()))
            )
        }
        _ => "run rdy trust list to see which keys are trusted".to_owned(),
    };
    CliError::usage(message, fix)
}

/// True for 16 hex digits.
fn is_key_id_text(text: &str) -> bool {
    text.len() == 16 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when a normal user has no such key in the user store but the system store has it: a key for the
/// product, and with `key_id` given, one with that id. It is read only for a user run, and only to word
/// the fix line. A store that cannot be read is no.
fn in_other_store(
    layout: &Layout,
    scope: Scope,
    product: &ProductSlug,
    key_id: Option<&str>,
) -> bool {
    if scope != Scope::User {
        return false;
    }
    trust::load_scope(layout, Scope::System).is_ok_and(|system| {
        system.entries().any(|entry| {
            entry.product() == product
                && key_id.is_none_or(|wanted| {
                    entry
                        .key()
                        .key_id()
                        .to_string()
                        .eq_ignore_ascii_case(wanted)
                })
        })
    })
}

/// A path as the user will read it, safe to print.
fn display(path: &Path) -> String {
    escape_untrusted(&path.display().to_string())
}

#[cfg(all(test, unix))]
mod tests;

/// Where saving is not supported (ADR 0027). Runs on Windows CI. The rest of the tests need Unix modes.
#[cfg(all(test, not(unix)))]
mod unsupported_tests {
    use super::*;
    use crate::trust::Vars;

    /// A terminal that must not be asked anything.
    struct Unused;

    impl Terminal for Unused {
        fn is_interactive(&self) -> bool {
            panic!("the command asked before it refused")
        }
        fn write_prompt(&mut self, _: &str) -> std::io::Result<()> {
            panic!("the command asked before it refused")
        }
        fn read_line(&mut self) -> std::io::Result<Option<String>> {
            panic!("the command asked before it refused")
        }
        fn read_hidden(&mut self) -> Result<crate::prompt::Secret, PromptError> {
            panic!("the command asked before it refused")
        }
    }

    #[test]
    fn add_and_remove_are_not_supported_and_read_nothing() {
        let layout = Layout::from_env(&Vars::default(), 0);
        let args = TrustAddArgs {
            product: "acme-platform".to_owned(),
            key: "no-such-file.pub".to_owned(),
            yes: true,
            note: None,
        };
        let err = add(
            &args,
            &layout,
            "2026-11-30T16:20:00Z",
            &mut Prompter::new(Unused),
            &mut std::io::sink(),
        )
        .expect_err("unsupported");
        assert_eq!(err.exit_code().code(), 64);
        assert!(
            err.to_string().contains("cannot write a trust store"),
            "{err}"
        );
        let args = TrustRemoveArgs {
            product: "acme-platform".to_owned(),
            key_id: None,
        };
        let err = remove(&args, &layout, &mut std::io::sink()).expect_err("unsupported");
        assert_eq!(err.exit_code().code(), 64);
    }
}
