//! The evidence of `net.tls_intercept`: who issued a chain, where this machine's trust store is, and the
//! two rules a spec may set on a chain (03 section 3, M1-100).
//!
//! Everything here reads text the peer or the environment chose, so everything is cut and cleaned before
//! it reaches a report: control characters, every invisible or reordering code point
//! (`rdy_engine::text::is_invisible`) and backticks are removed, and a name is cut at [`SHOWN_CHARS`]. A
//! path that came from `SSL_CERT_FILE` or `SSL_CERT_DIR` shows the variable and the path with the home
//! directory collapsed to `~`, because it can hold a user name and no redaction rule rewrites a path (05,
//! `system_roots`).
//!
//! Nothing here panics on any input: a certificate that does not parse, or is over [`MAX_ROOT_BYTES`], has
//! no names, and a proptest feeds arbitrary bytes and text.

use rdy_engine::probe::net::TrustStore;
use rdy_engine::probe::{MAX_ROOT_BYTES, ProbeError, StoreKind, StoreOrigin, StoreSource};
use rdy_engine::text::is_invisible;
use serde_json::{Value, json};
use x509_parser::prelude::{FromDer, X509Certificate};

/// The most characters of a certificate name or a path a report shows.
pub(super) const SHOWN_CHARS: usize = 160;

/// The most characters of an issuer that `expected_issuer` is matched against. A longer issuer is a miss:
/// matching a prefix could pass a name that only starts like the expected one.
const MATCHED_CHARS: usize = 1024;

/// The most certificates of one chain that are hashed for `pin_sha256`.
const MAX_PINNED: usize = 32;

/// The most trust store sources a report lists.
const MAX_SOURCES: usize = 8;

/// `text` without control characters, invisible code points and backticks, cut to `max` characters (`...`
/// marks a cut).
pub(super) fn clean(text: &str, max: usize) -> String {
    let kept: String = text
        .chars()
        .filter(|c| !c.is_control() && !is_invisible(*c) && *c != '`')
        .collect();
    if kept.chars().count() <= max {
        return kept;
    }
    let mut cut: String = kept.chars().take(max.saturating_sub(3)).collect();
    cut.push_str("...");
    cut
}

/// The names of one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Names {
    /// The issuer as x509-parser writes it, `C=..., O=..., CN=...` in certificate order, with control
    /// characters removed. Not cut.
    pub(super) issuer: String,
    /// The subject, in the same form.
    pub(super) subject: String,
    /// Whether the certificate names itself as its issuer, which is what a root looks like.
    pub(super) self_signed: bool,
}

/// The names in `der`, or `None` when it is over [`MAX_ROOT_BYTES`] or not a certificate x509-parser can
/// read.
pub(super) fn names_of(der: &[u8]) -> Option<Names> {
    if der.len() > MAX_ROOT_BYTES {
        return None;
    }
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let plain = |text: String| -> String { text.chars().filter(|c| !c.is_control()).collect() };
    Some(Names {
        issuer: plain(cert.issuer().to_string()),
        subject: plain(cert.subject().to_string()),
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
    })
}

/// How a chain stands against `pin_sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PinState {
    /// The leaf, the one certificate the server proves it holds the key of, is pinned.
    Leaf,
    /// Only a later certificate of the chain is pinned. The server can append any public certificate, so
    /// this proves nothing about the path that was verified.
    CaOnly,
    /// No certificate the server sent is pinned.
    Miss,
}

/// What a chain shows, read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChainEvidence {
    /// The issuer of the leaf, or `None` when the leaf could not be read.
    pub(super) issuer: Option<String>,
    /// The subject of the leaf.
    pub(super) subject: Option<String>,
    /// The SHA-256 of the last certificate the server sent, as 64 hex digits.
    pub(super) last_sha256: Option<String>,
    /// The same hash, only when that certificate is self-signed, which is what a root is. A server rarely
    /// sends the root, so this is usually `None`.
    pub(super) root_sha256: Option<String>,
    /// The raw hash of the root, for the lookup in the OS store.
    pub(super) root_hash: Option<[u8; 32]>,
    /// The SHA-256 of every certificate sent (the first [`MAX_PINNED`]), as hex, the leaf first.
    pub(super) hashes: Vec<String>,
}

impl ChainEvidence {
    /// The evidence of `certs`, the DER of each certificate the server sent, its own first.
    pub(super) fn of(certs: &[Vec<u8>]) -> Self {
        let leaf = certs.first().and_then(|der| names_of(der));
        let last = certs.last();
        let last_hash = last.map(|der| TrustStore::hash(der));
        let self_signed = last
            .and_then(|der| names_of(der))
            .is_some_and(|n| n.self_signed);
        Self {
            issuer: leaf.as_ref().map(|n| n.issuer.clone()),
            subject: leaf.map(|n| n.subject),
            last_sha256: last_hash.as_ref().map(TrustStore::hex),
            root_sha256: last_hash
                .as_ref()
                .filter(|_| self_signed)
                .map(TrustStore::hex),
            root_hash: last_hash.filter(|_| self_signed),
            hashes: certs
                .iter()
                .take(MAX_PINNED)
                .map(|der| TrustStore::hex(&TrustStore::hash(der)))
                .collect(),
        }
    }

    /// Whether the issuer text satisfies `matches`. An issuer that could not be read, or is over
    /// [`MATCHED_CHARS`], is a miss.
    pub(super) fn issuer_matches(&self, matches: &dyn Fn(&str) -> bool) -> bool {
        self.issuer
            .as_deref()
            .is_some_and(|issuer| issuer.chars().count() <= MATCHED_CHARS && matches(issuer))
    }

    /// Where the chain stands against `pins`. Only the leaf proves anything: a server can append any
    /// certificate it likes after its own.
    pub(super) fn pin_state(&self, pins: &[String]) -> PinState {
        let mut hashes = self.hashes.iter();
        if hashes.next().is_some_and(|leaf| pins.contains(leaf)) {
            PinState::Leaf
        } else if hashes.any(|hash| pins.contains(hash)) {
            PinState::CaOnly
        } else {
            PinState::Miss
        }
    }

    /// The issuer as a report shows it.
    pub(super) fn shown_issuer(&self) -> Option<String> {
        self.issuer.as_deref().map(|s| clean(s, SHOWN_CHARS))
    }

    /// The subject as a report shows it.
    pub(super) fn shown_subject(&self) -> Option<String> {
        self.subject.as_deref().map(|s| clean(s, SHOWN_CHARS))
    }
}

/// A path that came from an environment variable, as a report shows it: control characters and invisible
/// code points removed first (so `/ho\u{0}me/alice` cannot slip past the next step), then the usual home
/// places collapsed to `~`, then the `homes` values, then cut.
///
/// The usual places are `/home/<name>`, `/Users/<name>`, `/root` and `<drive>:\Users\<name>`. They go
/// first, so a `HOME` of `/home` cannot turn `/home/alice` into `~/alice`. `homes` are the values of
/// `HOME` as the check read them. A user name outside a home place (`/srv/alice`), or the invoking user's
/// home under `sudo` with `HOME=/root`, still shows (05, `system_roots`).
pub(super) fn show_env_path(path: &str, homes: &[String]) -> String {
    let flat = clean(path, usize::MAX);
    let usual = collapse_usual_home(&flat);
    if usual != flat {
        return clean(&usual, SHOWN_CHARS);
    }
    for home in homes {
        let home = clean(home, usize::MAX);
        let home = home.trim_end_matches(['/', '\\']);
        if home.is_empty() {
            continue;
        }
        if let Some(rest) = flat.strip_prefix(home)
            && (rest.is_empty() || rest.starts_with(['/', '\\']))
        {
            return clean(&format!("~{rest}"), SHOWN_CHARS);
        }
    }
    clean(&flat, SHOWN_CHARS)
}

/// `~` in place of `/home/<name>`, `/Users/<name>`, `/root` or `<drive>:\Users\<name>` at the start.
fn collapse_usual_home(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    // The text after the user name, from the separator that ends it. `from` is a byte offset into an
    // ASCII prefix of `path`, so it is a character boundary.
    let after_name = |from: usize| -> String {
        let tail = path.get(from..).unwrap_or_default();
        let end = tail.find(['/', '\\']).unwrap_or(tail.len());
        format!("~{}", tail.get(end..).unwrap_or_default())
    };
    for prefix in ["/home/", "/users/"] {
        if lower.starts_with(prefix) {
            return after_name(prefix.len());
        }
    }
    if lower == "/root" || lower.starts_with("/root/") {
        return format!("~{}", path.get("/root".len()..).unwrap_or_default());
    }
    let bytes = lower.as_bytes();
    let drive = bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'\\' | b'/'));
    if drive
        && let Some(rest) = lower.get(3..)
        && (rest.starts_with("users\\") || rest.starts_with("users/"))
    {
        return after_name(3 + "users\\".len());
    }
    path.to_owned()
}

/// One source of the trust store as a report shows it: its kind, the place, and the variable that named
/// it, if one did.
fn source_json(source: &StoreSource, homes: &[String]) -> Value {
    let kind = match source.kind {
        StoreKind::Bundle => "bundle",
        StoreKind::Directory => "directory",
        StoreKind::OsStore => "os_store",
        _ => "other",
    };
    match source.origin {
        StoreOrigin::Env(name) => json!({
            "kind": kind,
            "from": clean(name, 32),
            "location": show_env_path(&source.location, homes),
        }),
        _ => json!({"kind": kind, "location": clean(&source.location, SHOWN_CHARS)}),
    }
}

/// Whether any source of `answer` was named by an environment variable, so a path may need collapsing.
pub(super) fn names_a_variable(answer: &Result<TrustStore, ProbeError>) -> bool {
    answer.as_ref().is_ok_and(|store| {
        store
            .sources
            .iter()
            .any(|s| matches!(s.origin, StoreOrigin::Env(_)))
    })
}

/// The trust store section of the report: where the OS roots came from, how many there are, or why there
/// are none. `answer` is what `Probe::trust_store` gave.
pub(super) fn store_json(answer: &Result<TrustStore, ProbeError>, homes: &[String]) -> Value {
    match answer {
        Ok(store) => {
            let sources: Vec<Value> = store
                .sources
                .iter()
                .take(MAX_SOURCES)
                .map(|s| source_json(s, homes))
                .collect();
            let mut out = json!({
                "status": if store.missing.is_some() { "missing" } else { "found" },
                "roots": store.roots.len(),
                "sources": sources,
            });
            if store.sources.len() > MAX_SOURCES {
                out["more_sources"] = (store.sources.len() - MAX_SOURCES).into();
            }
            if let Some(why) = store.missing {
                out["reason"] = why.phrase().into();
            }
            out
        }
        Err(_) => json!({
            "status": "not_read",
            "reason": "the OS trust store was not read for this run",
        }),
    }
}
