//! The evidence of `net.tls_intercept`: who issued a chain, where this machine's trust store is, and the
//! two rules a spec may set on a chain (03 section 3, M1-100).
//!
//! Everything here reads text the peer or the environment chose, so everything is cut and cleaned before
//! it reaches a report: control characters, bidirectional and zero-width marks and backticks are removed,
//! and a name is cut at [`SHOWN_CHARS`]. A path that came from `SSL_CERT_FILE` or `SSL_CERT_DIR` shows the
//! variable and the path with the home directory collapsed to `~`, because it can hold a user name and no
//! redaction rule rewrites a path (05, `system_roots`).

use rdy_engine::probe::net::TrustStore;
use rdy_engine::probe::{ProbeError, StoreKind, StoreOrigin, StoreSource};
use serde_json::{Value, json};
use x509_parser::prelude::{FromDer, X509Certificate};

/// The most characters of a certificate name or a path a report shows.
pub(super) const SHOWN_CHARS: usize = 160;

/// The most characters of the issuer text that `expected_issuer` is matched against.
const MATCHED_CHARS: usize = 1024;

/// The most certificates of one chain that are hashed for `pin_sha256`.
const MAX_PINNED: usize = 32;

/// The most trust store sources a report lists.
const MAX_SOURCES: usize = 8;

/// Marks that change how text is drawn or hide it: bidirectional controls, zero-width characters and the
/// byte order mark. They are not control characters, so `char::is_control` misses them.
fn is_mark(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// `text` without control characters, marks and backticks, cut to `max` characters (`...` marks a cut).
pub(super) fn clean(text: &str, max: usize) -> String {
    let kept: String = text
        .chars()
        .filter(|c| !c.is_control() && !is_mark(*c) && *c != '`')
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
    /// The issuer as `CN=..., O=...`, with control characters removed. Not cut.
    pub(super) issuer: String,
    /// The subject, in the same form.
    pub(super) subject: String,
    /// Whether the certificate names itself as its issuer, which is what a root looks like.
    pub(super) self_signed: bool,
}

/// The names in `der`, or `None` when it is not a certificate x509-parser can read.
pub(super) fn names_of(der: &[u8]) -> Option<Names> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let plain = |text: String| -> String { text.chars().filter(|c| !c.is_control()).collect() };
    Some(Names {
        issuer: plain(cert.issuer().to_string()),
        subject: plain(cert.subject().to_string()),
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
    })
}

/// What a chain shows, read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChainEvidence {
    /// The issuer of the leaf, or `None` when the leaf could not be read.
    pub(super) issuer: Option<String>,
    /// The subject of the leaf.
    pub(super) subject: Option<String>,
    /// The SHA-256 of the last certificate the server sent, as 64 hex digits. It is the root itself only
    /// when the server sent it, which is not the rule.
    pub(super) root_sha256: Option<String>,
    /// Whether that last certificate is self-signed.
    pub(super) root_self_signed: bool,
    /// The raw hash of that certificate, for the lookup in the OS store.
    pub(super) root_hash: Option<[u8; 32]>,
    /// The SHA-256 of every certificate sent (the first [`MAX_PINNED`]), as hex.
    pub(super) hashes: Vec<String>,
}

impl ChainEvidence {
    /// The evidence of `certs`, the DER of each certificate the server sent, its own first.
    pub(super) fn of(certs: &[Vec<u8>]) -> Self {
        let leaf = certs.first().and_then(|der| names_of(der));
        let last = certs.last();
        let root_hash = last.map(|der| TrustStore::hash(der));
        Self {
            issuer: leaf.as_ref().map(|n| n.issuer.clone()),
            subject: leaf.map(|n| n.subject),
            root_sha256: root_hash.as_ref().map(TrustStore::hex),
            root_self_signed: last
                .and_then(|der| names_of(der))
                .is_some_and(|n| n.self_signed),
            root_hash,
            hashes: certs
                .iter()
                .take(MAX_PINNED)
                .map(|der| TrustStore::hex(&TrustStore::hash(der)))
                .collect(),
        }
    }

    /// Whether the issuer text satisfies `matches`. An issuer that could not be read is a miss.
    pub(super) fn issuer_matches(&self, matches: &dyn Fn(&str) -> bool) -> bool {
        self.issuer.as_deref().is_some_and(|issuer| {
            let text: String = issuer.chars().take(MATCHED_CHARS).collect();
            matches(&text)
        })
    }

    /// Whether any certificate of the chain has a SHA-256 that is in `pins`.
    pub(super) fn pinned(&self, pins: &[String]) -> bool {
        self.hashes.iter().any(|hash| pins.contains(hash))
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

/// A path that came from an environment variable, as a report shows it: control characters and marks
/// removed first (so `/ho\u{0}me/alice` cannot slip past the next step), then the home directory
/// collapsed to `~`, then cut.
///
/// `homes` are the values of `HOME` and `USERPROFILE` as the check read them. Without them the usual
/// places still collapse: `/home/<name>`, `/Users/<name>`, `/root` and `<drive>:\Users\<name>`.
pub(super) fn show_env_path(path: &str, homes: &[String]) -> String {
    let flat = clean(path, usize::MAX);
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
    clean(&collapse_usual_home(&flat), SHOWN_CHARS)
}

/// `~` in place of `/home/<name>`, `/Users/<name>`, `/root` or `<drive>:\Users\<name>` at the start.
fn collapse_usual_home(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    // The text after the user name, from the separator that ends it.
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
