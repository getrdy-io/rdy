//! Start-up hardening (M1-168, ADR 0023).
//!
//! [`crate::entry::main_code`] calls [`rdy_engine::exec::harden_umask`] first, so every file `rdy`
//! creates is private, and lists the inherited descriptors before it opens anything of its own. When
//! the list is not empty, [`warn_inherited`] prints one `warning:` line on stderr. It never goes to
//! stdout, so `--json` output stays clean. Closing the descriptors is M2-104.
//!
//! ## The privilege gate (M1-042, INV-10)
//!
//! After the redacting log layer and before the spec is read, the run takes one privilege snapshot
//! through the run-level probe ([`rdy_engine::privilege::Privilege::snapshot`]). [`privilege_gate`]
//! turns a snapshot that shows extra privilege, or that could not be taken, into a [`CliError`]: exit 70
//! with the hint, as every other internal error prints. [`gate_then`] runs the next step (reading the
//! spec) only when the gate passes, so a refused run never opens the spec file.
//!
//! [`crate::run`] calls it for every command except help and version, so a refused run never opens a
//! spec, a key or the trust store. `rdy run` (M1-057) keeps the order: it calls [`privilege_gate`] first, then reads
//! the spec, and it puts [`rdy_engine::privilege::Privilege::identity`] into the report. It is async, so it
//! does not use [`gate_then`].

use std::io::Write;

use rdy_engine::privilege::{Privilege, PrivilegeError};

use crate::error::{CliError, InternalKind, emit, escape_untrusted};
use crate::redaction;

/// Maps a privilege snapshot to the error of INV-10, or hands the snapshot back when it is clean.
///
/// A snapshot that could not be taken is an error too: without it rdy cannot show that the binary
/// carries no privilege.
///
/// # Errors
///
/// [`CliError::Internal`] with [`InternalKind::Privilege`], exit 70.
pub fn privilege_gate(snapshot: Result<Privilege, PrivilegeError>) -> Result<Privilege, CliError> {
    let privilege = snapshot.map_err(|error| CliError::Internal(InternalKind::Privilege(error)))?;
    privilege
        .check()
        .map_err(|error| CliError::Internal(InternalKind::Privilege(error)))?;
    Ok(privilege)
}

/// Runs `next` with the clean snapshot, or prints the refusal and returns its exit code without
/// running `next`. `next` is the step that reads the spec, so a refused run never opens it.
pub fn gate_then(
    snapshot: Result<Privilege, PrivilegeError>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    next: impl FnOnce(&Privilege, &mut dyn Write, &mut dyn Write) -> u8,
) -> u8 {
    match privilege_gate(snapshot) {
        Ok(privilege) => next(&privilege, stdout, stderr),
        Err(error) => emit(&error, json, stdout, stderr),
    }
}

/// The most descriptor numbers the warning names. The rest are counted.
const MAX_LISTED: usize = 8;

/// The `warning:` text for `fds`, or `None` when there are none. It has no line break.
///
/// It names at most 8 descriptors and counts the rest, with a hint to close those too.
#[must_use]
pub fn inherited_fd_warning(fds: &[u32]) -> Option<String> {
    if fds.is_empty() {
        return None;
    }
    let listed: Vec<String> = fds.iter().take(MAX_LISTED).map(u32::to_string).collect();
    let more = fds.len().saturating_sub(MAX_LISTED);
    let mut numbers = listed.join(", ");
    if more > 0 {
        numbers.push_str(&format!(" and {more} more"));
    }
    let closers: Vec<String> = fds
        .iter()
        .take(MAX_LISTED)
        .map(|fd| format!("{fd}>&-"))
        .collect();
    let noun = if fds.len() == 1 {
        "descriptor"
    } else {
        "descriptors"
    };
    let rest = if more > 0 {
        " and close the rest the same way"
    } else {
        ""
    };
    Some(format!(
        "warning: rdy inherited open file {noun} {numbers}, and the commands it runs inherit them. To start without, close them in the shell: rdy ... {}{rest}",
        closers.join(" ")
    ))
}

/// Prints the inherited-descriptor warning to `stderr`, redacted and escaped like every other CLI
/// line. Prints nothing when `fds` is empty. A write error is ignored.
pub fn warn_inherited(fds: &[u32], stderr: &mut dyn Write) {
    if let Some(text) = inherited_fd_warning(fds) {
        let line = redaction::redact_text_then(&text, escape_untrusted);
        let _ = writeln!(stderr, "{line}");
    }
}

#[cfg(test)]
mod gate_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_descriptors_no_warning() {
        assert_eq!(inherited_fd_warning(&[]), None);
        let mut out = Vec::new();
        warn_inherited(&[], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn one_descriptor_is_named_on_one_line() {
        let text = inherited_fd_warning(&[3]).unwrap_or_default();
        assert!(text.starts_with("warning: "), "{text}");
        assert!(text.contains("descriptor 3,"), "{text}");
        assert!(text.ends_with("rdy ... 3>&-"), "{text}");
        assert!(!text.contains('\n'));
    }

    #[test]
    fn many_descriptors_are_capped() {
        let fds: Vec<u32> = (3..23).collect();
        let text = inherited_fd_warning(&fds).unwrap_or_default();
        assert!(
            text.contains("3, 4, 5, 6, 7, 8, 9, 10 and 12 more"),
            "{text}"
        );
        assert!(!text.contains("11,"), "{text}");
        assert!(
            text.ends_with(
                "rdy ... 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 10>&- and close the rest the same way"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_printed_line_ends_with_one_newline() {
        let mut out = Vec::new();
        warn_inherited(&[3, 7], &mut out);
        let shown = String::from_utf8(out).unwrap_or_default();
        assert_eq!(shown.lines().count(), 1, "{shown}");
        assert!(shown.starts_with("warning: rdy inherited open file descriptors 3, 7,"));
        assert!(shown.ends_with('\n'));
    }
}
