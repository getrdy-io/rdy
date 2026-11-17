//! `rdy verify` (M1-126, 01 section 4.6, 07 section C.4).
//!
//! It runs the verification of 01 section 4.4 and no checks. It never prompts and has no
//! `--allow-unsigned`: exit 0 means "`rdy run` would accept this file with no override", and any other
//! answer is exit 64 with a code from 01 section 4.8. It uses the same loader as `rdy run`
//! ([`crate::spec_load`]), so the two cannot disagree.
//!
//! - The text goes to stderr (07 decision 1): the facts of the spec and its signature, then `VERIFIED`.
//!   A key given with `--key` prints the KEY NOT PINNED banner first and ends `VERIFIED, KEY NOT PINNED`.
//! - With `--json`, stdout gets one `Verification` object (result schema `$defs`). On a refusal it gets
//!   an `ErrorOutput` instead, as every command does.
//! - Text from the spec (version, contact, annotations) and the local trust note go through the
//!   redactor, and the text lines are escaped for the terminal.

use std::io::{IsTerminal, Write};

use rdy_engine::privilege::Privilege;
use rdy_spec::LoadedSpec;
use rdy_spec::result::{Producer, Signature, SpecRef, TrustSource};
use serde::Serialize;

use crate::cli::{ColorChoice, VerifyArgs};
use crate::error::{CliError, InternalKind, emit, escape_untrusted};
use crate::redaction::redact_text;
use crate::run_cmd::{producer, spec_ref};
use crate::spec_cmds::fingerprint_lines;
use crate::spec_load::{self, Given};
use crate::style::{StyleEnv, Styler, use_color, write_styled};
use crate::terminal::banner;
use crate::trust::{Layout, Scope, Vars};

/// What `rdy verify --json` prints when the spec is accepted (`$defs/Verification`).
#[derive(Debug, Serialize)]
struct Verification {
    api_version: &'static str,
    kind: &'static str,
    producer: Producer,
    spec: SpecRef,
    signature: Signature,
}

/// Runs `rdy verify` and returns the exit code: 0, 64 or 70.
pub(crate) fn run(
    args: &VerifyArgs,
    privilege: &Privilege,
    color: ColorChoice,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    // A user-supplied value in the log: the redactor has to cover it (threat model I2).
    tracing::debug!(spec = %args.spec.display(), "verify requested");
    let name = args.spec.to_string_lossy().into_owned();
    let layout = Layout::from_env(&Vars::from_process(), privilege.euid().unwrap_or(u32::MAX));
    let given = Given {
        spec: &args.spec,
        sig: args.sig.as_deref(),
        key: args.key.as_deref(),
        allow_unsigned: false,
    };
    let loaded = match spec_load::load_spec(&given, &name, &layout) {
        Ok(loaded) => loaded,
        Err(error) => return emit(&error, json, stdout, stderr),
    };
    let verification = build(&loaded, &args.spec);
    if json {
        let text = match json_text(&verification) {
            Some(text) => text,
            None => return emit(&CliError::bug(), false, stdout, stderr),
        };
        if stdout
            .write_all(text.as_bytes())
            .and_then(|()| stdout.flush())
            .is_err()
        {
            let error = CliError::Internal(InternalKind::OutputClosed);
            return emit(&error, false, &mut std::io::sink(), stderr);
        }
    }
    let colored = use_color(
        color,
        &StyleEnv::from_process(),
        std::io::stderr().is_terminal(),
    );
    let pinned = verification.signature.trust_source != Some(TrustSource::Flag);
    if let Some(text) = banner(&verification.signature, &name, Styler::new(colored)) {
        let _ = write_styled(stderr, colored, &format!("{text}\n"));
    }
    let text = lines(&verification, &name, &layout, pinned);
    let _ = write_styled(stderr, colored, &text);
    crate::EXIT_OK
}

fn build(loaded: &LoadedSpec, path: &std::path::Path) -> Verification {
    let mut spec = spec_ref(loaded, path);
    // The text of the spec and the local note are redacted before anything is printed.
    spec.version = spec.version.map(|text| redact_text(&text));
    spec.contact = spec.contact.map(|text| redact_text(&text));
    spec.file_name = redact_text(&spec.file_name);
    for value in spec.annotations.values_mut() {
        *value = redact_text(value);
    }
    let mut signature = Signature::from(loaded.signature());
    signature.trust_note = signature.trust_note.map(|text| redact_text(&text));
    Verification {
        api_version: rdy_spec::API_VERSION,
        kind: "Verification",
        producer: producer(),
        spec,
        signature,
    }
}

/// The document and a final newline. `<`, `>` and `&` are written as escapes, like every document rdy
/// prints (01 section 5.5). `None` only if serializing fails, which the plain types here cannot do.
fn json_text(verification: &Verification) -> Option<String> {
    let text = serde_json::to_string_pretty(verification).ok()?;
    let mut out = text
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    out.push('\n');
    Some(out)
}

/// The text of 07 section C.4, each line ending in a newline.
fn lines(verification: &Verification, name: &str, layout: &Layout, pinned: bool) -> String {
    let signature = &verification.signature;
    let spec = &verification.spec;
    let or = |value: &Option<String>, fallback: &str| {
        value
            .as_deref()
            .map_or_else(|| fallback.to_owned(), escape_untrusted)
    };
    let (first, second) = signature
        .key_fingerprint
        .as_deref()
        .map(fingerprint_lines)
        .unwrap_or_default();
    let trust = match signature.trust_source {
        Some(TrustSource::System) => stored(layout, Scope::System),
        Some(TrustSource::User) => stored(layout, Scope::User),
        _ => "key given with --key, not pinned".to_owned(),
    };
    let revision = spec
        .serial
        .map_or_else(|| "none".to_owned(), |serial| serial.to_string());
    let mut out = String::new();
    let mut row = |label: &str, value: &str| {
        out.push_str(&format!("{label:<13}{value}\n"));
    };
    row("spec", &escape_untrusted(name));
    row("product", &or(&signature.product, "unknown"));
    row("sha256", &spec.sha256);
    row("signed on", &or(&signature.signed_at, "unknown"));
    row("signing key", &or(&signature.key_id, "unknown"));
    row("fingerprint", &first);
    row("", &second);
    row("trust", &trust);
    if pinned {
        row("note", &or(&signature.trust_note, "none"));
    }
    row("revision", &revision);
    row("expires", &or(&spec.expires, "never"));
    out.push('\n');
    out.push_str(if pinned {
        "VERIFIED\n"
    } else {
        "VERIFIED, KEY NOT PINNED\n"
    });
    out
}

/// `trusted on this machine (/etc/rdy/trust.yaml)`.
fn stored(layout: &Layout, scope: Scope) -> String {
    match layout.path(scope) {
        Some(path) => format!(
            "trusted on this machine ({})",
            escape_untrusted(&path.to_string_lossy())
        ),
        None => "trusted on this machine".to_owned(),
    }
}

#[cfg(all(test, unix))]
// Test helpers: a failed fixture must fail the test.
#[allow(clippy::expect_used)]
mod tests {
    use rdy_spec::load;
    use rdy_spec::sig::{Policy, PublicKey, TrustSource, TrustStore};
    use rdy_spec::spec::ProductSlug;

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/signed")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn verified(source: TrustSource, note: Option<&str>) -> Verification {
        let text = String::from_utf8(fixture("acme-platform.pub")).expect("utf8");
        let key = PublicKey::from_base64(text.lines().nth(1).expect("key line")).expect("key");
        let product = ProductSlug::new("acme-platform").expect("slug");
        let mut store = TrustStore::new();
        match source {
            TrustSource::Flag => store.pin(product, key, source),
            _ => store
                .add(product, key, source, "2026-11-30T16:02:11Z", note)
                .expect("added"),
        }
        let loaded = load(
            &fixture("acme-platform.yaml"),
            Some(&fixture("acme-platform.yaml.minisig")),
            &store,
            Policy::RequireSigned,
        )
        .expect("loads");
        build(&loaded, std::path::Path::new("acme-platform.yaml"))
    }

    fn layout() -> Layout {
        // A normal user: the system store is /etc/rdy/trust.yaml and the user store is under HOME.
        let vars = Vars {
            home: Some("/home/jdoe".into()),
            ..Vars::default()
        };
        Layout::from_env(&vars, 1000)
    }

    #[test]
    fn a_pinned_key_prints_the_c4_sample_and_no_banner() {
        let v = verified(TrustSource::System, Some("Acme security page"));
        assert_eq!(
            lines(&v, "acme-platform.yaml", &layout(), true),
            "\
spec         acme-platform.yaml
product      acme-platform
sha256       231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f
signed on    2026-10-28T12:00:00Z
signing key  F117C76E2F56B162
fingerprint  5214 b48f 44f0 9f5b 1bc6 1114 4469 c07e
             6025 9022 9ae8 6240 d118 42c7 2571 7e4a
trust        trusted on this machine (/etc/rdy/trust.yaml)
note         Acme security page
revision     none
expires      never

VERIFIED
"
        );
        assert!(banner(&v.signature, "acme-platform.yaml", Styler::new(false)).is_none());
    }

    #[test]
    fn a_user_pin_names_the_user_store_and_a_missing_note_reads_none() {
        let v = verified(TrustSource::User, None);
        let text = lines(&v, "acme-platform.yaml", &layout(), true);
        assert!(
            text.contains(
                "trust        trusted on this machine (/home/jdoe/.config/rdy/trust.yaml)\n"
            ),
            "{text}"
        );
        assert!(text.contains("note         none\n"), "{text}");
    }

    #[test]
    fn a_one_run_key_ends_verified_key_not_pinned_and_has_no_note_line() {
        let v = verified(TrustSource::Flag, None);
        let text = lines(&v, "acme-platform.yaml", &layout(), false);
        assert!(
            text.contains("trust        key given with --key, not pinned\n"),
            "{text}"
        );
        assert!(!text.contains("note "), "{text}");
        assert!(text.ends_with("\nVERIFIED, KEY NOT PINNED\n"), "{text}");
        let shown = banner(&v.signature, "acme-platform.yaml", Styler::new(false)).expect("banner");
        assert!(shown.starts_with("WARNING: KEY NOT PINNED\n"), "{shown}");
    }

    #[test]
    fn text_from_the_spec_name_is_escaped() {
        let v = verified(TrustSource::System, None);
        let text = lines(&v, "\u{1b}[2J.yaml", &layout(), true);
        assert!(!text.contains('\u{1b}'), "{text}");
    }
}
