//! The M1 redaction corpus and its gate (M1-063, SEC-26, 04 section 4 and Appendix D).
//!
//! The corpus is `tests/fixtures/redaction/<category>/<case>.{in,expected,toml}`. All values are synthetic.
//! Secrets that a scanner would flag are stored as parts in `synthetic.toml` and joined here
//! (`${SYN:name}`). A case's `.toml` says what it is:
//!
//! ```toml
//! polarity = "positive"        # or "negative"
//! since = "m1"
//! rulesets = ["report"]        # the M1 report set; the bundle set arrives with M2
//! rules = ["url_userinfo"]     # rules that must fire (positive), none (negative)
//! forms = ["proxy"]            # the syntax form the case covers (positive)
//! exclusions = ["suffix_name"] # the key-name exclusions the case proves (negative)
//! controls = [["suffix_name", "secretName: x", "secret: x", "secret: x"]]
//!                              # per exclusion: [name, text in .in, replacement, text that must be hidden]
//! secrets = ["..."]            # strings that must not appear in the output (positive)
//! note = "..."                 # optional, for the reader
//! ```
//!
//! The harness redacts `.in` with a fixed key, replaces each tag with its ordinal in the file (`~1` for the
//! first distinct tag, `~2` for the next, the same tag the same number) and compares the result with
//! `.expected` byte for byte through `assert_golden`, which never writes under `tests/fixtures/redaction`.
//! `.expected` is blessed by hand. On its own the harness also checks that no `secrets` string survives
//! and that no 6-character run of one does either, once the placeholders are cut out (the oracle that
//! catches a wrongly blessed file), that every `rules` entry fired, that a second pass changes nothing and
//! finds nothing outside a placeholder, and that a negative comes out unchanged. A `controls` entry swaps
//! an excluded value for one that the redactor must hide, so an exclusion case cannot pass for the wrong
//! reason.
//!
//! The gate is coverage, not count. It fails on a survivor, a rule that did not fire, an `.expected`
//! mismatch, an idempotence or residual failure, a rule or a syntax form with no positive case, a key-name
//! exclusion with no negative or no control, or fewer cases than `FLOOR`. The rule list comes from the
//! engine (`built_in_rule_names`) and is checked against the M1 rows of 04 Appendix B. So is the form list:
//! `MATCHES` names every backticked item of a row's Matches cell and says which forms cover it, so a new
//! item in Appendix B fails the gate until a case covers it or it is listed as not claimed.
//! The loader refuses an empty piece in `synthetic.toml`, and any case file that holds a whole PEM header,
//! JWT, share token or AWS key id (except the vendor-documented one) instead of `${SYN:..}`.
//!
//! What this corpus does not claim (`NOT_CLAIMED`, repeated in `tests/fixtures/README.md`, where a test
//! checks that every entry stands word for word). These are the forms M1-060 left to M2, a few it never handled, and what the
//! redactor does with `valueFrom`. They have no case here. M2-061 adds them as `known_gap` cases with the
//! ledger. A case that claimed one would be a case that hides a miss.
//!
//! - Left to M2 by M1-060: `Cookie` and `Set-Cookie`; a 40-character secret by proximity; a one-line JSON
//!   object after a secret key (it loses the rest of its line); a space in URL userinfo; `curl -u` and
//!   `--user`; `-pPASS`; a URL password with a raw `/` after an all-digit head (`app:1234/x@db`);
//!   base64-armored keys (`LS0tLS1CRUdJTi`); bare DER keys (`MIIEvQIBADANBg`); SSH2 keys
//!   (`---- BEGIN SSH2 ... PRIVATE KEY ----`); a crafted `BEGIN` line inside a closed block of another
//!   label; a PEM block split over log events; a Kubernetes env list (`- name: DB_PASSWORD` then
//!   `value: x`, and its JSON form `{"name":"DB_PASSWORD","value":"x"}`), which `redact_str` leaves
//!   as it is; `-H '...' url` and `--password=x` followed by another flag (the rest of the line goes too);
//!   `Authorization header: Basic <b64>` in prose; crafted bracket and quote escapes and stray apostrophes.
//! - Never handled: `MYSQL_PWD=` and `pwd=` (no stem matches `pwd`).
//! - Connection strings: the `secret_by_key` row of 04 Appendix B says "connection strings" in prose, which
//!   the `MATCHES` gate does not read. Appendix D plans their cases for M2, so M1 does not claim them.
//! - `valueFrom` and `secretKeyRef`: the redactor has no such exclusion. `DB_PASSWORD:` then `valueFrom:`
//!   then `secretKeyRef:` comes out as one placeholder. That fails safe, and it is not claimed.
//! - Known over-redactions for M2-061 (no failing case): `max_tokens: 4096`, `secretary: bob` and
//!   `compass: north` are redacted because the stems `token`, `secret` and `pass` match inside the key.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use rdy_engine::redact::{Redactor, RuleCounts, TagKey, built_in_rule_names};
use rdy_engine::testing::{fixtures_dir, golden::assert_golden};
use regex::Regex;

/// The M1 minimum. `FLOOR` may rise, never fall below this (04 section 4).
const M1_FLOOR: usize = 28;

/// The syntax forms each rule claims in M1 (04 Appendix B, "Matches", and Appendix D). Every pair needs a
/// positive case. A rule of the engine with no row here fails the gate: say which forms it claims.
const CLAIMS: &[(&str, &[&str])] = &[
    ("pem_private_key", &["plain", "json_escaped", "no_end"]),
    (
        "aws_access_key_id",
        &["log_line", "json", "ini", "abia", "acca"],
    ),
    ("rdy_share_token", &["text"]),
    ("jwt", &["text"]),
    (
        "auth_header",
        &["bearer", "basic", "proxy", "curl_header", "bare_bearer"],
    ),
    ("api_key_header", &["header", "x_auth_token"]),
    (
        "url_userinfo",
        &["proxy", "dsn", "percent_encoded", "token_userinfo"],
    ),
    ("aws_secret_access_key", &["env", "ini", "json"]),
    ("aws_session_token", &["json", "ini", "env", "header"]),
    (
        "kubeconfig_credential",
        &[
            "token",
            "client_key_data",
            "password",
            "client_secret",
            "id_token",
            "refresh_token",
            "access_token",
        ],
    ),
    (
        "secret_by_key",
        &[
            "env",
            "yaml",
            "json",
            "ini",
            "flag",
            "systemd",
            "placeholder_prefix",
            "ansi",
            "stem_pass",
            "stem_secret",
            "stem_token",
            "stem_api_key",
            "stem_access_key",
            "stem_private_key",
            "stem_credential",
            "stem_auth",
            "stem_bearer",
            "stem_dsn",
        ],
    ),
];

/// What a backticked item of an Appendix B "Matches" cell needs from the corpus.
enum Claim {
    /// The corpus covers it with these forms. Each must be listed for the rule in `CLAIMS`.
    Forms(&'static [&'static str]),
    /// The corpus does not claim it, for this reason.
    Not(&'static str),
}

/// Every backticked item in the "Matches" cell of an M1 row of 04 Appendix B, with the forms that cover
/// it. The items are compared with the document, so an item added there fails the gate until it has a row
/// here, and an item removed or renamed there fails it too. Prose in a Matches cell (`percent-encoded`,
/// `any scheme`, `connection strings`) is not an item and is not gated: its forms are in `CLAIMS` all the
/// same, and a prose claim with no form there is not tested. `connection strings` is such a claim, and
/// `NOT_CLAIMED` says so.
const MATCHES: &[(&str, &str, Claim)] = &[
    (
        "url_userinfo",
        "scheme://user:pass@host",
        Claim::Forms(&["proxy", "dsn", "percent_encoded"]),
    ),
    (
        "url_userinfo",
        "scheme://token@host",
        Claim::Forms(&["token_userinfo"]),
    ),
    (
        "auth_header",
        "Authorization:",
        Claim::Forms(&["bearer", "basic"]),
    ),
    (
        "auth_header",
        "Proxy-Authorization:",
        Claim::Forms(&["proxy"]),
    ),
    (
        "auth_header",
        "-H 'Authorization: ...'",
        Claim::Forms(&["curl_header"]),
    ),
    (
        "auth_header",
        "Bearer <token>",
        Claim::Forms(&["bare_bearer"]),
    ),
    ("api_key_header", "X-Api-Key", Claim::Forms(&["header"])),
    (
        "api_key_header",
        "X-Auth-Token",
        Claim::Forms(&["x_auth_token"]),
    ),
    (
        "api_key_header",
        "Cookie",
        Claim::Not("M2: Cookie and Set-Cookie are not built"),
    ),
    (
        "api_key_header",
        "Set-Cookie",
        Claim::Not("M2: Cookie and Set-Cookie are not built"),
    ),
    (
        "aws_access_key_id",
        "(AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}",
        Claim::Forms(&["log_line", "json", "ini", "abia", "acca"]),
    ),
    (
        "aws_secret_access_key",
        "aws_secret_access_key",
        Claim::Forms(&["env", "ini"]),
    ),
    (
        "aws_secret_access_key",
        "SecretAccessKey",
        Claim::Forms(&["json"]),
    ),
    (
        "aws_session_token",
        "aws_session_token",
        Claim::Forms(&["ini", "env"]),
    ),
    ("aws_session_token", "SessionToken", Claim::Forms(&["json"])),
    (
        "aws_session_token",
        "x-amz-security-token",
        Claim::Forms(&["header"]),
    ),
    (
        "pem_private_key",
        "-----BEGIN [A-Z0-9 ]*PRIVATE KEY...-----",
        Claim::Forms(&["plain", "no_end"]),
    ),
    ("pem_private_key", "\\n", Claim::Forms(&["json_escaped"])),
    ("kubeconfig_credential", "token", Claim::Forms(&["token"])),
    (
        "kubeconfig_credential",
        "client-key-data",
        Claim::Forms(&["client_key_data"]),
    ),
    (
        "kubeconfig_credential",
        "password",
        Claim::Forms(&["password"]),
    ),
    (
        "kubeconfig_credential",
        "access-token",
        Claim::Forms(&["access_token"]),
    ),
    (
        "kubeconfig_credential",
        "refresh-token",
        Claim::Forms(&["refresh_token"]),
    ),
    (
        "kubeconfig_credential",
        "id-token",
        Claim::Forms(&["id_token"]),
    ),
    (
        "kubeconfig_credential",
        "client-secret",
        Claim::Forms(&["client_secret"]),
    ),
    (
        "rdy_share_token",
        "rdy_st_[A-Za-z0-9]{20,}",
        Claim::Forms(&["text"]),
    ),
    ("jwt", "eyJ...", Claim::Forms(&["text"])),
    ("secret_by_key", "pass", Claim::Forms(&["stem_pass"])),
    ("secret_by_key", "secret", Claim::Forms(&["stem_secret"])),
    ("secret_by_key", "token", Claim::Forms(&["stem_token"])),
    ("secret_by_key", "api_key", Claim::Forms(&["stem_api_key"])),
    (
        "secret_by_key",
        "access_key",
        Claim::Forms(&["stem_access_key"]),
    ),
    (
        "secret_by_key",
        "private_key",
        Claim::Forms(&["stem_private_key"]),
    ),
    (
        "secret_by_key",
        "credential",
        Claim::Forms(&["stem_credential"]),
    ),
    ("secret_by_key", "auth", Claim::Forms(&["stem_auth"])),
    ("secret_by_key", "bearer", Claim::Forms(&["stem_bearer"])),
    ("secret_by_key", "dsn", Claim::Forms(&["stem_dsn"])),
    ("secret_by_key", "=", Claim::Forms(&["env", "ini"])),
    ("secret_by_key", ":", Claim::Forms(&["yaml", "json"])),
    ("secret_by_key", "--flag=x", Claim::Forms(&["flag"])),
    ("secret_by_key", "Environment=", Claim::Forms(&["systemd"])),
];

/// What the corpus does not claim. Each entry must appear word for word in `tests/fixtures/README.md`
/// (a test checks), and the module header says why. A form the redactor does not handle goes here, never
/// into a case that would pass for the wrong reason.
const NOT_CLAIMED: &[&str] = &[
    "`Cookie` and `Set-Cookie`",
    "a 40-character secret by proximity",
    "a one-line JSON object after a secret key",
    "a space in URL userinfo",
    "`curl -u` and `--user`",
    "`-pPASS`",
    "`app:1234/x@db`",
    "base64-armored keys",
    "bare DER keys",
    "SSH2 keys",
    "a crafted `BEGIN` line",
    "a PEM block split over log events",
    "a Kubernetes env list",
    "`-H '...' url`",
    "`--password=x` followed by another flag",
    "`Authorization header: Basic <b64>`",
    "crafted bracket and quote escapes",
    "connection strings (Appendix D: M2)",
    "`MYSQL_PWD=`",
    "`pwd=`",
    "`valueFrom` and `secretKeyRef`",
    "`max_tokens: 4096`",
    "`secretary: bob`",
    "`compass: north`",
];

/// The key-name exclusions of 04 Appendix B that the redactor implements. Each needs a negative case with
/// a control. `valueFrom` and `secretKeyRef` blocks are in the appendix and not here: the redactor has no
/// such exclusion (see `NOT_CLAIMED`).
const EXCLUSIONS: &[&str] = &[
    "empty",
    "null",
    "true",
    "false",
    "none",
    "required",
    "shell_reference",
    "command_substitution",
    "template",
    "suffix_name",
    "suffix_ref",
    "suffix_file",
    "suffix_path",
    "suffix_namespace",
    "run_secrets",
];

/// Every item of the "Key-name exclusions" paragraph of 04 Appendix B (backticks removed), with the
/// `EXCLUSIONS` ids that cover it. The items are compared with the document, so an exclusion added there
/// fails the gate until it is mapped here, and one removed or renamed there fails it too. `Claim::Forms`
/// holds exclusion ids in this table.
const EXCLUSION_ITEMS: &[(&str, Claim)] = &[
    ("empty", Claim::Forms(&["empty"])),
    ("null", Claim::Forms(&["null"])),
    ("true", Claim::Forms(&["true"])),
    ("false", Claim::Forms(&["false"])),
    ("none", Claim::Forms(&["none"])),
    ("required", Claim::Forms(&["required"])),
    ("${X}", Claim::Forms(&["shell_reference"])),
    ("$(...)", Claim::Forms(&["command_substitution"])),
    ("{{ ... }}", Claim::Forms(&["template"])),
    (
        "valueFrom and secretKeyRef blocks",
        Claim::Not(
            "the redactor has no such exclusion; a block comes out redacted, which fails safe",
        ),
    ),
    ("keys ending in name", Claim::Forms(&["suffix_name"])),
    ("ref", Claim::Forms(&["suffix_ref"])),
    ("file", Claim::Forms(&["suffix_file"])),
    ("path", Claim::Forms(&["suffix_path"])),
    ("namespace", Claim::Forms(&["suffix_namespace"])),
    ("paths under /run/secrets/", Claim::Forms(&["run_secrets"])),
];

/// The keys a case `.toml` may hold. Anything else is a typo and fails.
const TOML_KEYS: &[&str] = &[
    "polarity",
    "since",
    "rulesets",
    "rules",
    "forms",
    "exclusions",
    "controls",
    "secrets",
    "note",
];

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([9; 32]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polarity {
    Positive,
    Negative,
}

/// One case, with its text already expanded.
#[derive(Debug, Clone)]
struct Case {
    /// `category/case`.
    id: String,
    polarity: Polarity,
    rules: Vec<String>,
    forms: Vec<String>,
    exclusions: Vec<String>,
    /// Per exclusion, an edit of the input that the redactor must then hide (negative cases).
    controls: Vec<Control>,
    secrets: Vec<String>,
    input: String,
    /// The `.expected` file. The golden helper reads it.
    expected_path: PathBuf,
}

/// One control of an exclusion: replace `from` (once) in the input with `to`, and the redactor must then
/// hide `hidden`, which is part of `to`.
#[derive(Debug, Clone)]
struct Control {
    exclusion: String,
    from: String,
    to: String,
    hidden: String,
}

/// Everything under `tests/fixtures/redaction`.
#[derive(Debug)]
struct Corpus {
    floor: usize,
    cases: Vec<Case>,
    /// Parts of `synthetic.toml` that no case used.
    unused_parts: Vec<String>,
}

static SYN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{SYN:([a-z0-9_]+)\}")
        .unwrap_or_else(|e| panic!("the SYN pattern is valid: {e}"))
});

static TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[REDACTED:([a-z0-9_.]+):([0-9a-f]{8})\]")
        .unwrap_or_else(|e| panic!("the tag pattern is valid: {e}"))
});

/// The text with every tag replaced by its ordinal in this text: `~1` for the first distinct tag, `~2` for
/// the next. The same tag gets the same number wherever it stands, so a golden pins which spans share a
/// secret (04 section 3.3) and which do not.
fn normalized(text: &str) -> String {
    let mut seen: Vec<String> = Vec::new();
    TAG.replace_all(text, |caps: &regex::Captures<'_>| {
        let tag = &caps[2];
        let ordinal = match seen.iter().position(|t| t == tag) {
            Some(i) => i + 1,
            None => {
                seen.push(tag.to_owned());
                seen.len()
            }
        };
        format!("[REDACTED:{}:~{ordinal}]", &caps[1])
    })
    .into_owned()
}

/// Whole secrets that a scanner would flag. The corpus keeps these as parts; a raw one is a mistake.
/// `strict` is for case files, which may not hold even the bare `rdy_st_` prefix. `synthetic.toml` holds
/// that prefix as a piece of a part, so there only a whole token counts.
fn whole_secret_shapes(text: &str, strict: bool) -> Vec<&'static str> {
    static PEM: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
            .unwrap_or_else(|e| panic!("the PEM pattern is valid: {e}"))
    });
    static JWT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
            .unwrap_or_else(|e| panic!("the JWT pattern is valid: {e}"))
    });
    static SHARE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"rdy_st_[A-Za-z0-9]{20,}")
            .unwrap_or_else(|e| panic!("the share token pattern is valid: {e}"))
    });
    static AWS_ID: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}")
            .unwrap_or_else(|e| panic!("the AWS id pattern is valid: {e}"))
    });
    let mut found = Vec::new();
    if PEM.is_match(text) {
        found.push("a PEM private-key header");
    }
    if JWT.is_match(text) {
        found.push("a JWT");
    }
    if (strict && text.contains("rdy_st_")) || SHARE.is_match(text) {
        found.push("an rdy_st_ share token");
    }
    if AWS_ID
        .find_iter(text)
        .any(|m| m.as_str() != DOCUMENTED_AWS_ID)
    {
        found.push("an AWS key id other than the documented example");
    }
    found
}

/// The one key id that may stand whole in a fixture: the vendor-documented example.
const DOCUMENTED_AWS_ID: &str = "AKIAIOSFODNN7EXAMPLE";

/// The first run of `min(len, 6)` characters of `secret` that is still in `stripped`, which is the output
/// with every placeholder cut out. A whole-secret check misses a prefix or a suffix left behind.
fn surviving_fragment(secret: &str, stripped: &str) -> Option<String> {
    let chars: Vec<char> = secret.chars().collect();
    let width = chars.len().min(6);
    if width == 0 {
        return None;
    }
    chars
        .windows(width)
        .map(|w| w.iter().collect::<String>())
        .find(|w| stripped.contains(w.as_str()))
}

fn corpus_dir() -> PathBuf {
    fixtures_dir().join("redaction")
}

// ---- loading ----

fn str_list(table: &toml::Table, key: &str, what: &str) -> Result<Vec<String>, String> {
    let Some(value) = table.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(format!("{what}: `{key}` must be a list of strings"));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{what}: `{key}` must be a list of strings"))
        })
        .collect()
}

/// Joins the parts of `synthetic.toml`.
fn load_parts(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = dir.join("synthetic.toml");
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e| format!("synthetic.toml does not parse: {e}"))?;
    if let Some(shape) = whole_secret_shapes(&text, false).first() {
        return Err(format!(
            "synthetic.toml holds {shape} in one piece. Split it so a scanner never sees it whole"
        ));
    }
    let mut keys = table.keys().filter(|k| *k != "parts");
    if let Some(key) = keys.next() {
        return Err(format!("synthetic.toml: unknown top-level key `{key}`"));
    }
    let Some(parts) = table.get("parts").and_then(toml::Value::as_table) else {
        return Err("synthetic.toml: a [parts] table is required".to_owned());
    };
    let mut joined = BTreeMap::new();
    for name in parts.keys() {
        let list = str_list(parts, name, "synthetic.toml")?;
        if list.len() < 2 {
            return Err(format!(
                "synthetic.toml: `{name}` has fewer than 2 parts, so a scanner would see it whole"
            ));
        }
        if list.iter().any(String::is_empty) {
            return Err(format!(
                "synthetic.toml: `{name}` has an empty part, which would hide a whole secret in one piece"
            ));
        }
        joined.insert(name.clone(), list.concat());
    }
    Ok(joined)
}

/// Replaces `${SYN:name}`. An unknown name is a problem, never an empty string.
fn expand(
    text: &str,
    parts: &BTreeMap<String, String>,
    used: &mut BTreeSet<String>,
) -> Result<String, String> {
    let mut missing = Vec::new();
    let out = SYN.replace_all(text, |caps: &regex::Captures<'_>| {
        let name = &caps[1];
        match parts.get(name) {
            Some(value) => {
                used.insert(name.to_owned());
                value.clone()
            }
            None => {
                missing.push(name.to_owned());
                String::new()
            }
        }
    });
    if missing.is_empty() {
        Ok(out.into_owned())
    } else {
        Err(format!(
            "unknown synthetic part(s): {} (add them to synthetic.toml)",
            missing.join(", ")
        ))
    }
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn load_case(
    id: &str,
    dir: &Path,
    stem: &str,
    parts: &BTreeMap<String, String>,
    used: &mut BTreeSet<String>,
) -> Result<Case, String> {
    let meta_text = read_text(&dir.join(format!("{stem}.toml")))?;
    let table: toml::Table = meta_text
        .parse()
        .map_err(|e| format!("{id}: the .toml does not parse: {e}"))?;
    for key in table.keys() {
        if !TOML_KEYS.contains(&key.as_str()) {
            return Err(format!("{id}: unknown key `{key}` in the .toml"));
        }
    }
    let polarity = match table.get("polarity").and_then(toml::Value::as_str) {
        Some("positive") => Polarity::Positive,
        Some("negative") => Polarity::Negative,
        Some("known_gap") => {
            return Err(format!(
                "{id}: `known_gap` cases arrive with the M2 ledger (M2-061). M1 does not claim a gap"
            ));
        }
        other => {
            return Err(format!(
                "{id}: polarity must be \"positive\" or \"negative\", not {other:?}"
            ));
        }
    };
    match table.get("since").and_then(toml::Value::as_str) {
        Some("m1") => {}
        other => {
            return Err(format!(
                "{id}: since must be \"m1\" in this harness, not {other:?}. M2 cases need the bundle set"
            ));
        }
    }
    let rulesets = str_list(&table, "rulesets", id)?;
    if rulesets != ["report"] {
        return Err(format!(
            "{id}: rulesets must be [\"report\"] in M1, not {rulesets:?}"
        ));
    }
    let rules = str_list(&table, "rules", id)?;
    let forms = str_list(&table, "forms", id)?;
    let exclusions = str_list(&table, "exclusions", id)?;
    let raw_secrets = str_list(&table, "secrets", id)?;
    let secrets = raw_secrets
        .iter()
        .map(|s| expand(s, parts, used).map_err(|e| format!("{id}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let controls = controls_of(&table, id)?;
    let input_raw = read_text(&dir.join(format!("{stem}.in")))?;
    let input = expand(&input_raw, parts, used).map_err(|e| format!("{id}: {e}"))?;
    let expected_path = dir.join(format!("{stem}.expected"));
    let expected = read_text(&expected_path)?;
    for (file, raw) in [
        ("in", &input_raw),
        ("toml", &meta_text),
        ("expected", &expected),
    ] {
        if let Some(shape) = whole_secret_shapes(raw, true).first() {
            return Err(format!(
                "{id}: the .{file} file holds {shape}. Write it as `${{SYN:..}}` parts in synthetic.toml"
            ));
        }
    }
    if SYN.is_match(&expected) {
        return Err(format!(
            "{id}: .expected holds a `${{SYN:..}}` reference. It holds placeholders only and is compared as it is"
        ));
    }
    Ok(Case {
        id: id.to_owned(),
        polarity,
        rules,
        forms,
        exclusions,
        controls,
        secrets,
        input,
        expected_path,
    })
}

/// Reads `controls`: a list of `[exclusion, from, to, hidden]`.
fn controls_of(table: &toml::Table, id: &str) -> Result<Vec<Control>, String> {
    let bad =
        || format!("{id}: `controls` must be a list of [exclusion, from, to, hidden] string lists");
    let Some(value) = table.get("controls") else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or_else(bad)?;
    let mut controls = Vec::new();
    for item in items {
        let fields: Vec<&str> = item
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .map(|f| f.as_str().ok_or_else(bad))
            .collect::<Result<_, _>>()?;
        let [exclusion, from, to, hidden] = fields[..] else {
            return Err(bad());
        };
        controls.push(Control {
            exclusion: exclusion.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            hidden: hidden.to_owned(),
        });
    }
    Ok(controls)
}

fn sorted_entries(dir: &Path) -> Result<Vec<fs::DirEntry>, String> {
    let mut entries = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

/// Reads the whole corpus. Every problem with the files is collected, so one run shows them all.
fn load_corpus(dir: &Path) -> Result<Corpus, Vec<String>> {
    let mut problems = Vec::new();
    let parts = load_parts(dir).unwrap_or_else(|e| {
        problems.push(e);
        BTreeMap::new()
    });
    let floor = read_text(&dir.join("FLOOR"))
        .and_then(|t| {
            t.trim()
                .parse::<usize>()
                .map_err(|e| format!("FLOOR must hold one number: {e}"))
        })
        .unwrap_or_else(|e| {
            problems.push(e);
            0
        });
    let mut used = BTreeSet::new();
    let mut cases = Vec::new();
    let entries = match sorted_entries(dir) {
        Ok(entries) => entries,
        Err(e) => {
            problems.push(e);
            return Err(problems);
        }
    };
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_file() {
            if name != "FLOOR" && name != "synthetic.toml" {
                problems.push(format!(
                    "stray file `{name}` at the top of the corpus (only FLOOR and synthetic.toml belong there)"
                ));
            }
            continue;
        }
        let files = match sorted_entries(&path) {
            Ok(files) => files,
            Err(e) => {
                problems.push(e);
                continue;
            }
        };
        let mut stems: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for file in files {
            let file_name = file.file_name().to_string_lossy().into_owned();
            match file_name.rsplit_once('.') {
                Some((stem, ext @ ("in" | "expected" | "toml"))) if file.path().is_file() => {
                    stems
                        .entry(stem.to_owned())
                        .or_default()
                        .insert(ext.to_owned());
                }
                _ => problems.push(format!(
                    "{name}/{file_name}: not a case file (only .in, .expected and .toml)"
                )),
            }
        }
        for (stem, exts) in stems {
            let id = format!("{name}/{stem}");
            let missing: Vec<&str> = ["in", "expected", "toml"]
                .into_iter()
                .filter(|ext| !exts.contains(*ext))
                .collect();
            if !missing.is_empty() {
                problems.push(format!(
                    "{id}: missing .{} (a case has .in, .expected and .toml)",
                    missing.join(" and .")
                ));
                continue;
            }
            match load_case(&id, &path, &stem, &parts, &mut used) {
                Ok(case) => cases.push(case),
                Err(e) => problems.push(e),
            }
        }
    }
    let unused_parts = parts
        .keys()
        .filter(|name| !used.contains(*name))
        .cloned()
        .collect();
    if problems.is_empty() {
        Ok(Corpus {
            floor,
            cases,
            unused_parts,
        })
    } else {
        Err(problems)
    }
}

// ---- running one case ----

/// The oracle checks of one case. Returns the problems and the normalized output (for the golden).
fn run_case(r: &Redactor, case: &Case) -> (Vec<String>, String) {
    let id = &case.id;
    let mut problems = Vec::new();
    let out = r.redact_str(&case.input);
    let out_text: &str = &out;

    // The grammar: every `[REDACTED:` opens a well-formed placeholder.
    let opened = out_text.matches("[REDACTED:").count();
    let formed = TAG.find_iter(out_text).count();
    if opened != formed {
        problems.push(format!("{id}: a malformed placeholder in the output"));
    }
    let fired: BTreeSet<String> = TAG
        .captures_iter(out_text)
        .map(|c| c[1].to_owned())
        .collect();

    match case.polarity {
        Polarity::Positive => {
            if case.secrets.is_empty() {
                problems.push(format!("{id}: a positive case lists no `secrets`"));
            }
            if case.rules.is_empty() {
                problems.push(format!("{id}: a positive case lists no `rules`"));
            }
            if case.forms.is_empty() {
                problems.push(format!("{id}: a positive case lists no `forms`"));
            }
            if !case.exclusions.is_empty() || !case.controls.is_empty() {
                problems.push(format!(
                    "{id}: only a negative case lists `exclusions` and `controls`"
                ));
            }
            let stripped = TAG.replace_all(out_text, "");
            for secret in &case.secrets {
                if secret.is_empty() {
                    problems.push(format!("{id}: an empty string in `secrets`"));
                } else if !case.input.contains(secret.as_str()) {
                    problems.push(format!(
                        "{id}: a `secrets` entry is not in the input, so it proves nothing: {secret}"
                    ));
                } else if out_text.contains(secret.as_str()) {
                    problems.push(format!("{id}: the secret survived: {secret}"));
                } else if let Some(piece) = surviving_fragment(secret, &stripped) {
                    problems.push(format!(
                        "{id}: a piece of the secret survived: `{piece}` (of {secret})"
                    ));
                }
            }
            for rule in &case.rules {
                if !fired.contains(rule) {
                    problems.push(format!(
                        "{id}: rule `{rule}` did not fire (the output has: {})",
                        fired.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }
        Polarity::Negative => {
            if !case.rules.is_empty() || !case.secrets.is_empty() || !case.forms.is_empty() {
                problems.push(format!(
                    "{id}: a negative case must not list `rules`, `forms` or `secrets`"
                ));
            }
            if out_text != case.input {
                problems.push(format!(
                    "{id}: a negative changed. It must come out as it went in"
                ));
            }
            problems.extend(control_problems(r, case));
        }
    }

    // A second pass changes nothing and finds no span outside a placeholder.
    let mut again = RuleCounts::default();
    let twice = r.redact_str_counted(out_text, &mut again);
    if *twice != *out_text {
        problems.push(format!("{id}: a second pass changed the output"));
    }
    if again.total() != 0 {
        problems.push(format!(
            "{id}: the rules found {} span(s) outside the placeholders of the output",
            again.total()
        ));
    }
    (problems, normalized(out_text))
}

/// The mutation guard of a negative case: every exclusion has a control, and each control, applied to the
/// input, makes the redactor hide its `hidden` text. If it does not, the exclusion is not what kept the
/// original value, and the case proves nothing.
fn control_problems(r: &Redactor, case: &Case) -> Vec<String> {
    let id = &case.id;
    let mut problems = Vec::new();
    for exclusion in &case.exclusions {
        if !case.controls.iter().any(|c| &c.exclusion == exclusion) {
            problems.push(format!(
                "{id}: the exclusion `{exclusion}` has no control, so nothing shows it matters"
            ));
        }
    }
    for control in &case.controls {
        let name = &control.exclusion;
        if !case.exclusions.contains(name) {
            problems.push(format!(
                "{id}: a control names `{name}`, which the case does not list in `exclusions`"
            ));
        }
        if control.hidden.is_empty() || !control.to.contains(&control.hidden) {
            problems.push(format!(
                "{id}: the control of `{name}` must hide a non-empty part of its replacement"
            ));
            continue;
        }
        if !case.input.contains(&control.from) {
            problems.push(format!(
                "{id}: the control of `{name}` edits text that is not in the input: {}",
                control.from
            ));
            continue;
        }
        let edited = case.input.replacen(&control.from, &control.to, 1);
        let out = r.redact_str(&edited);
        if out.contains(&control.hidden) {
            problems.push(format!(
                "{id}: the control of `{name}` was not hidden, so the exclusion proves nothing: {}",
                control.hidden
            ));
        }
    }
    problems
}

/// Compares `actual` with the case's `.expected` through the golden helper. The helper panics on a
/// difference (and parks the output in `target/goldens-actual`), so the panic text is the problem.
fn golden_problem(case: &Case, actual: &str) -> Option<String> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        assert_golden(&case.expected_path, actual.as_bytes());
    }));
    result.err().map(|payload| {
        let text = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "the golden helper panicked".to_owned());
        format!("{}: .expected mismatch\n{text}", case.id)
    })
}

// ---- the coverage gate ----

/// What the corpus must cover, given the rules of the engine.
fn coverage(cases: &[Case], floor: usize, rules: &[&str]) -> Vec<String> {
    let mut problems = Vec::new();
    if floor < M1_FLOOR {
        problems.push(format!(
            "FLOOR is {floor}. It may not be lower than {M1_FLOOR} (04 section 4)"
        ));
    }
    if cases.len() < floor.max(M1_FLOOR) {
        problems.push(format!(
            "the corpus has {} case(s), fewer than FLOOR ({}). Add cases, do not lower FLOOR",
            cases.len(),
            floor.max(M1_FLOOR)
        ));
    }
    let positives = || cases.iter().filter(|c| c.polarity == Polarity::Positive);
    let known: BTreeSet<&str> = rules.iter().copied().collect();

    for case in cases {
        for rule in &case.rules {
            if !known.contains(rule.as_str()) {
                problems.push(format!("{}: `{rule}` is not a rule of the engine", case.id));
            }
        }
        for form in &case.forms {
            if !CLAIMS
                .iter()
                .any(|(_, forms)| forms.contains(&form.as_str()))
            {
                problems.push(format!(
                    "{}: `{form}` is not a form any rule claims (a typo, or a new form: add it to CLAIMS)",
                    case.id
                ));
            }
        }
        for exclusion in &case.exclusions {
            if !EXCLUSIONS.contains(&exclusion.as_str()) {
                problems.push(format!(
                    "{}: `{exclusion}` is not a key-name exclusion of 04 Appendix B",
                    case.id
                ));
            }
        }
    }

    for rule in rules {
        if !positives().any(|c| c.rules.iter().any(|r| r == rule)) {
            problems.push(format!("rule `{rule}` has no positive case"));
        }
        let Some((_, claimed)) = CLAIMS.iter().find(|(name, _)| name == rule) else {
            problems.push(format!(
                "rule `{rule}` has no row in CLAIMS: say which syntax forms it claims"
            ));
            continue;
        };
        for form in *claimed {
            let covered = positives()
                .any(|c| c.rules.iter().any(|r| r == rule) && c.forms.iter().any(|f| f == form));
            if !covered {
                problems.push(format!(
                    "rule `{rule}` has no positive case for the `{form}` form"
                ));
            }
        }
    }
    for (name, _) in CLAIMS {
        if !known.contains(name) {
            problems.push(format!(
                "CLAIMS names `{name}`, which is not a rule of the engine"
            ));
        }
    }
    for exclusion in EXCLUSIONS {
        let covered = cases.iter().any(|c| {
            c.polarity == Polarity::Negative && c.exclusions.iter().any(|e| e == exclusion)
        });
        if !covered {
            problems.push(format!(
                "the key-name exclusion `{exclusion}` has no negative case"
            ));
        }
    }
    problems
}

/// One M1 rule of 04 Appendix B with the backticked items of its "Matches" cell.
#[derive(Debug, PartialEq, Eq)]
struct AppendixRow {
    rule: String,
    items: Vec<String>,
}

/// The M1 rows of 04 Appendix B. A `\|` inside a cell (the key id pattern) is read as a plain `|`.
fn appendix_b_m1_rows(doc: &str) -> Vec<AppendixRow> {
    let mut in_appendix = false;
    let mut rows = Vec::new();
    for line in doc.lines() {
        if line.starts_with("## Appendix B") {
            in_appendix = true;
            continue;
        }
        if in_appendix && line.starts_with("## ") {
            break;
        }
        if !in_appendix || !line.starts_with("| `") {
            continue;
        }
        let line = line.replace("\\|", "\u{1}");
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().replace('\u{1}', "|"))
            .collect();
        if cells.len() >= 4 && cells[2] == "1" {
            let items: Vec<String> = cells[3]
                .split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect();
            for rule in cells[0].split('`').skip(1).step_by(2) {
                rows.push(AppendixRow {
                    rule: rule.to_owned(),
                    items: items.clone(),
                });
            }
        }
    }
    rows
}

/// The rule names that 04 Appendix B marks for milestone 1.
fn appendix_b_m1_rules(doc: &str) -> Vec<String> {
    appendix_b_m1_rows(doc)
        .into_iter()
        .map(|row| row.rule)
        .collect()
}

/// The items of the "Key-name exclusions" paragraph of 04 Appendix B, backticks removed. The paragraph
/// starts at `Key-name exclusions (`, the list follows `): ` and ends before `Stems match`. Commas and
/// semicolons separate items.
fn appendix_b_exclusion_items(doc: &str) -> Vec<String> {
    let mut paragraph = String::new();
    let mut in_paragraph = false;
    for line in doc.lines() {
        if line.starts_with("Key-name exclusions (") {
            in_paragraph = true;
        } else if line.trim().is_empty() {
            in_paragraph = false;
        }
        if in_paragraph {
            paragraph.push_str(line.trim());
            paragraph.push(' ');
        }
    }
    let Some((_, list)) = paragraph.split_once("): ") else {
        return Vec::new();
    };
    let list = list.split("Stems match").next().unwrap_or(list);
    list.trim()
        .trim_end_matches('.')
        .split([',', ';'])
        .map(|item| item.replace('`', "").trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Compares the exclusion items of the document with `items`, and the ids they name with `exclusions`.
fn exclusion_gaps(
    doc_items: &[String],
    items: &[(&str, Claim)],
    exclusions: &[&str],
) -> Vec<String> {
    let mut problems = Vec::new();
    for item in doc_items {
        if !items.iter().any(|(text, _)| text == item) {
            problems.push(format!(
                "04 Appendix B lists the key-name exclusion `{item}` and EXCLUSION_ITEMS has no entry for it. \
                 Give it a negative case with a control and an id in EXCLUSIONS, or mark it Claim::Not with the reason"
            ));
        }
    }
    let mut named: BTreeSet<&str> = BTreeSet::new();
    for (text, claim) in items {
        if !doc_items.iter().any(|item| item == text) {
            problems.push(format!(
                "EXCLUSION_ITEMS names `{text}`, which 04 Appendix B does not list (renamed or removed?)"
            ));
        }
        match claim {
            Claim::Not("") => problems.push(format!(
                "EXCLUSION_ITEMS marks `{text}` as not claimed with no reason"
            )),
            Claim::Not(_) => {}
            Claim::Forms(ids) => {
                if ids.is_empty() {
                    problems.push(format!("EXCLUSION_ITEMS maps `{text}` to no exclusion id"));
                }
                for id in *ids {
                    if !exclusions.contains(id) {
                        problems.push(format!(
                            "EXCLUSION_ITEMS maps `{text}` to `{id}`, which is not in EXCLUSIONS"
                        ));
                    }
                    named.insert(id);
                }
            }
        }
    }
    for id in exclusions {
        if !named.contains(id) {
            problems.push(format!(
                "EXCLUSIONS lists `{id}`, which no item of 04 Appendix B maps to"
            ));
        }
    }
    problems
}

/// Compares the items of the Matches cells with `matches` and the forms with `claims`.
fn matches_gaps(
    rows: &[AppendixRow],
    matches: &[(&str, &str, Claim)],
    claims: &[(&str, &[&str])],
) -> Vec<String> {
    let mut problems = Vec::new();
    for row in rows {
        for item in &row.items {
            if !matches
                .iter()
                .any(|(rule, text, _)| *rule == row.rule && text == item)
            {
                problems.push(format!(
                    "04 Appendix B lists `{item}` for `{}` and MATCHES has no entry for it. Cover it \
                     with a case and name its forms there, or mark it Claim::Not with the reason",
                    row.rule
                ));
            }
        }
    }
    for (rule, text, claim) in matches {
        let listed = rows
            .iter()
            .any(|row| row.rule == *rule && row.items.iter().any(|i| i == text));
        if !listed {
            problems.push(format!(
                "MATCHES names `{text}` for `{rule}`, which 04 Appendix B does not list (renamed or removed?)"
            ));
        }
        if let Claim::Not(reason) = claim
            && reason.is_empty()
        {
            problems.push(format!(
                "MATCHES marks `{text}` of `{rule}` as not claimed with no reason"
            ));
        }
        if let Claim::Forms(forms) = claim {
            let claimed = claims
                .iter()
                .find(|(name, _)| name == rule)
                .map_or(&[][..], |(_, forms)| *forms);
            if forms.is_empty() {
                problems.push(format!("MATCHES lists no form for `{text}` of `{rule}`"));
            }
            for form in *forms {
                if !claimed.contains(form) {
                    problems.push(format!(
                        "MATCHES covers `{text}` of `{rule}` with the `{form}` form, which CLAIMS does not list for the rule"
                    ));
                }
            }
        }
    }
    problems
}

// ---- the tests ----

fn load_or_panic() -> Corpus {
    load_corpus(&corpus_dir()).unwrap_or_else(|problems| {
        panic!(
            "the redaction corpus does not load:\n  {}",
            problems.join("\n  ")
        )
    })
}

#[test]
fn every_case_passes_its_oracles_and_matches_its_golden() {
    let corpus = load_or_panic();
    let r = redactor();
    let mut problems = Vec::new();
    for case in &corpus.cases {
        let (mut found, output) = run_case(&r, case);
        problems.append(&mut found);
        problems.extend(golden_problem(case, &output));
    }
    assert!(
        problems.is_empty(),
        "{} redaction problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn the_corpus_covers_every_rule_form_and_exclusion() {
    let corpus = load_or_panic();
    let rules = built_in_rule_names();
    let mut problems = coverage(&corpus.cases, corpus.floor, &rules);
    for part in &corpus.unused_parts {
        problems.push(format!("synthetic.toml: part `{part}` is used by no case"));
    }
    assert!(
        problems.is_empty(),
        "the corpus gate failed:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn appendix_b_and_the_engine_name_the_same_m1_rules() {
    let path = fixtures_dir().join("../../docs/plan/04-bundle-and-redaction.md");
    let doc = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let in_doc: BTreeSet<String> = appendix_b_m1_rules(&doc).into_iter().collect();
    let in_engine: BTreeSet<String> = built_in_rule_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert!(
        !in_doc.is_empty(),
        "no M1 rule found in 04 Appendix B (did the table change shape?)"
    );
    assert_eq!(
        in_doc, in_engine,
        "04 Appendix B (left) and the engine's rule table (right) disagree on the M1 rules. \
         Fix the table or add the rule, and give it corpus cases"
    );
}

#[test]
fn appendix_b_matches_are_all_claimed_or_listed_as_not_claimed() {
    let path = fixtures_dir().join("../../docs/plan/04-bundle-and-redaction.md");
    let doc = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let rows = appendix_b_m1_rows(&doc);
    assert!(
        rows.iter().all(|row| !row.items.is_empty()),
        "an M1 row of 04 Appendix B has no backticked item in its Matches cell (did the table change shape?)"
    );
    let problems = matches_gaps(&rows, MATCHES, CLAIMS);
    assert!(
        problems.is_empty(),
        "04 Appendix B and the form gate disagree:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn appendix_b_key_name_exclusions_are_all_mapped_or_listed_as_not_claimed() {
    let path = fixtures_dir().join("../../docs/plan/04-bundle-and-redaction.md");
    let doc = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc_items = appendix_b_exclusion_items(&doc);
    assert!(
        doc_items.len() >= EXCLUSION_ITEMS.len(),
        "found {} key-name exclusions in 04 Appendix B (did the paragraph change shape?): {doc_items:?}",
        doc_items.len()
    );
    let problems = exclusion_gaps(&doc_items, EXCLUSION_ITEMS, EXCLUSIONS);
    assert!(
        problems.is_empty(),
        "04 Appendix B and the exclusion gate disagree:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_readme_lists_what_the_corpus_does_not_claim() {
    let path = fixtures_dir().join("README.md");
    let readme = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let missing: Vec<&str> = NOT_CLAIMED
        .iter()
        .copied()
        .filter(|entry| !readme.contains(entry))
        .collect();
    assert!(
        missing.is_empty(),
        "tests/fixtures/README.md must list these not-claimed forms word for word: {missing:?}"
    );
}

// ---- the gate fails when it should ----

fn positive(id: &str, input: &str, secrets: &[&str], rules: &[&str], forms: &[&str]) -> Case {
    Case {
        id: id.to_owned(),
        polarity: Polarity::Positive,
        rules: rules.iter().map(|s| (*s).to_owned()).collect(),
        forms: forms.iter().map(|s| (*s).to_owned()).collect(),
        exclusions: Vec::new(),
        controls: Vec::new(),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        input: input.to_owned(),
        expected_path: PathBuf::from("unused.expected"),
    }
}

fn control(exclusion: &str, from: &str, to: &str, hidden: &str) -> Control {
    Control {
        exclusion: exclusion.to_owned(),
        from: from.to_owned(),
        to: to.to_owned(),
        hidden: hidden.to_owned(),
    }
}

fn negative(id: &str, input: &str, exclusions: &[&str]) -> Case {
    Case {
        polarity: Polarity::Negative,
        rules: Vec::new(),
        forms: Vec::new(),
        secrets: Vec::new(),
        exclusions: exclusions.iter().map(|s| (*s).to_owned()).collect(),
        ..positive(id, input, &[], &[], &[])
    }
}

fn has(problems: &[String], needle: &str) -> bool {
    problems.iter().any(|p| p.contains(needle))
}

#[test]
fn a_secret_that_survives_fails_the_case() {
    // `leak-canary-77` has no key and no shape, so no rule takes it: a survivor.
    let case = positive(
        "t/survivor",
        "the value leak-canary-77 is in the log\n",
        &["leak-canary-77"],
        &["secret_by_key"],
        &["env"],
    );
    let (problems, _) = run_case(&redactor(), &case);
    assert!(has(&problems, "the secret survived"), "{problems:?}");
    assert!(has(&problems, "did not fire"), "{problems:?}");
}

#[test]
fn a_secret_that_is_not_in_the_input_proves_nothing() {
    let case = positive(
        "t/vacuous",
        "DB_PASSWORD=hunter2\n",
        &["not-in-the-input"],
        &["secret_by_key"],
        &["env"],
    );
    let (problems, _) = run_case(&redactor(), &case);
    assert!(has(&problems, "proves nothing"), "{problems:?}");
}

#[test]
fn a_rule_that_did_not_fire_fails_the_case() {
    let case = positive(
        "t/wrong-rule",
        "DB_PASSWORD=hunter2\n",
        &["hunter2"],
        &["jwt"],
        &["text"],
    );
    let (problems, _) = run_case(&redactor(), &case);
    assert!(has(&problems, "rule `jwt` did not fire"), "{problems:?}");
    assert!(!has(&problems, "survived"), "{problems:?}");
}

#[test]
fn a_negative_that_changes_fails_the_case() {
    let (problems, _) = run_case(
        &redactor(),
        &negative("t/changed", "DB_PASSWORD=hunter2\n", &[]),
    );
    assert!(has(&problems, "a negative changed"), "{problems:?}");
}

#[test]
fn a_clean_positive_and_a_clean_negative_pass() {
    let r = redactor();
    let (problems, output) = run_case(
        &r,
        &positive(
            "t/ok",
            "DB_PASSWORD=hunter2\n",
            &["hunter2"],
            &["secret_by_key"],
            &["env"],
        ),
    );
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(output, "DB_PASSWORD=[REDACTED:secret_by_key:~1]\n");
    let (problems, _) = run_case(&r, &negative("t/ok-neg", "passed: 12\n", &[]));
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn a_piece_of_a_secret_that_survives_fails_the_case() {
    // The whole `hunter2xyz` is taken with its line, but `hunter2` stands alone in the note.
    let case = positive(
        "t/fragment",
        "DB_PASSWORD=hunter2xyz tail\nnote: hunter2 here\n",
        &["hunter2xyz"],
        &["secret_by_key"],
        &["env"],
    );
    let (problems, _) = run_case(&redactor(), &case);
    assert!(
        has(&problems, "a piece of the secret survived: `hunter`"),
        "{problems:?}"
    );
    assert!(
        !has(&problems, "t/fragment: the secret survived"),
        "{problems:?}"
    );
}

#[test]
fn a_short_secret_is_checked_whole_and_a_long_one_by_six_character_runs() {
    assert_eq!(surviving_fragment("pa55", "a pa55 b"), Some("pa55".into()));
    assert_eq!(surviving_fragment("pa55", "a pa5 b"), None);
    assert_eq!(
        surviving_fragment("abcdefghij", "x cdefgh y"),
        Some("cdefgh".into())
    );
    assert_eq!(surviving_fragment("abcdefghij", "x cdefg y"), None);
    assert_eq!(surviving_fragment("", "anything"), None);
}

#[test]
fn tags_are_numbered_by_first_appearance_and_one_secret_keeps_one_number() {
    let case = positive(
        "t/ordinals",
        "A_TOKEN=abc12345\nB_TOKEN=def67890\nC_TOKEN=abc12345\n",
        &["abc12345", "def67890"],
        &["secret_by_key"],
        &["env"],
    );
    let (problems, output) = run_case(&redactor(), &case);
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(
        output,
        "A_TOKEN=[REDACTED:secret_by_key:~1]\nB_TOKEN=[REDACTED:secret_by_key:~2]\n\
         C_TOKEN=[REDACTED:secret_by_key:~1]\n"
    );
}

#[test]
fn an_exclusion_with_a_working_control_passes() {
    let mut case = negative("t/ctl", "secretName: acme-tls\n", &["suffix_name"]);
    case.controls = vec![control(
        "suffix_name",
        "secretName: acme-tls",
        "secret: acme-tls",
        "acme-tls",
    )];
    let (problems, _) = run_case(&redactor(), &case);
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn an_exclusion_whose_control_is_not_hidden_proves_nothing() {
    // `note` is no secret key, so the edited text is not redacted and the exclusion is not what kept it.
    let mut case = negative("t/vacuous-ctl", "note: hello\n", &["suffix_name"]);
    case.controls = vec![control(
        "suffix_name",
        "note: hello",
        "note: hello2",
        "hello2",
    )];
    let (problems, _) = run_case(&redactor(), &case);
    assert!(
        has(&problems, "the exclusion proves nothing"),
        "{problems:?}"
    );
}

#[test]
fn an_exclusion_with_no_control_or_a_stray_control_fails_the_case() {
    let case = negative("t/no-ctl", "secretName: acme-tls\n", &["suffix_name"]);
    let (problems, _) = run_case(&redactor(), &case);
    assert!(
        has(&problems, "`suffix_name` has no control"),
        "{problems:?}"
    );

    let mut case = negative("t/stray", "secretName: acme-tls\n", &[]);
    case.controls = vec![control(
        "suffix_name",
        "secretName: acme-tls",
        "secret: acme-tls",
        "acme-tls",
    )];
    let (problems, _) = run_case(&redactor(), &case);
    assert!(
        has(&problems, "does not list in `exclusions`"),
        "{problems:?}"
    );

    let mut case = negative("t/gone", "secretName: acme-tls\n", &["suffix_name"]);
    case.controls = vec![control(
        "suffix_name",
        "tokenName: x",
        "token: x",
        "token: x",
    )];
    let (problems, _) = run_case(&redactor(), &case);
    assert!(has(&problems, "not in the input"), "{problems:?}");
}

#[test]
fn a_control_on_a_positive_case_fails_the_case() {
    let mut case = positive(
        "t/pos-ctl",
        "DB_PASSWORD=hunter2\n",
        &["hunter2"],
        &["secret_by_key"],
        &["env"],
    );
    case.controls = vec![control("empty", "a", "b", "b")];
    let (problems, _) = run_case(&redactor(), &case);
    assert!(
        has(
            &problems,
            "only a negative case lists `exclusions` and `controls`"
        ),
        "{problems:?}"
    );
}

#[test]
fn a_value_from_block_is_not_a_claimed_exclusion() {
    // The redactor has no `valueFrom` exclusion, so the gate must not pretend to test one.
    assert!(!EXCLUSIONS.contains(&"value_from"));
    assert!(NOT_CLAIMED.contains(&"`valueFrom` and `secretKeyRef`"));
}

#[test]
fn the_exclusion_reader_takes_the_items_of_the_paragraph() {
    let doc = "Intro.\n\nKey-name exclusions (each has a negative): empty, `null`; `${X}`, `{{ ... }}`;\n`valueFrom` and `secretKeyRef` blocks; keys ending in `name`, `ref`; paths under `/run/secrets/`.\nStems match only in free-form text.\n\nOther text, here.\n";
    assert_eq!(
        appendix_b_exclusion_items(doc),
        [
            "empty",
            "null",
            "${X}",
            "{{ ... }}",
            "valueFrom and secretKeyRef blocks",
            "keys ending in name",
            "ref",
            "paths under /run/secrets/"
        ]
    );
}

#[test]
fn a_new_key_name_exclusion_in_the_appendix_fails_the_exclusion_gate() {
    let items = [("empty", Claim::Forms(&["empty"]))];
    let doc: Vec<String> = ["empty", "brand new"].map(str::to_owned).to_vec();
    let problems = exclusion_gaps(&doc, &items, &["empty"]);
    assert!(
        has(&problems, "lists the key-name exclusion `brand new`"),
        "{problems:?}"
    );
}

#[test]
fn a_dropped_exclusion_or_an_unmapped_id_fails_the_exclusion_gate() {
    let items = [
        ("empty", Claim::Forms(&["empty"])),
        ("gone", Claim::Forms(&["missing_id"])),
        ("bare", Claim::Not("")),
    ];
    let doc: Vec<String> = vec!["empty".to_owned(), "bare".to_owned()];
    let problems = exclusion_gaps(&doc, &items, &["empty", "orphan"]);
    assert!(has(&problems, "names `gone`"), "{problems:?}");
    assert!(has(&problems, "to `missing_id`"), "{problems:?}");
    assert!(has(&problems, "`orphan`, which no item"), "{problems:?}");
    assert!(
        has(&problems, "`bare` as not claimed with no reason"),
        "{problems:?}"
    );
}

// ---- the form gate follows 04 Appendix B ----

fn row(rule: &str, items: &[&str]) -> AppendixRow {
    AppendixRow {
        rule: rule.to_owned(),
        items: items.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[test]
fn a_matches_item_that_is_claimed_passes_the_form_gate() {
    let matches = [
        ("r", "a", Claim::Forms(&["f1"])),
        ("r", "b", Claim::Not("later")),
    ];
    let claims: &[(&str, &[&str])] = &[("r", &["f1"])];
    let problems = matches_gaps(&[row("r", &["a", "b"])], &matches, claims);
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn a_new_matches_item_in_the_appendix_fails_the_form_gate() {
    let matches = [("r", "a", Claim::Forms(&["f1"]))];
    let claims: &[(&str, &[&str])] = &[("r", &["f1"])];
    let problems = matches_gaps(&[row("r", &["a", "newly added"])], &matches, claims);
    assert!(
        has(
            &problems,
            "lists `newly added` for `r` and MATCHES has no entry"
        ),
        "{problems:?}"
    );
}

#[test]
fn an_item_the_appendix_dropped_or_renamed_fails_the_form_gate() {
    let matches = [("r", "a", Claim::Forms(&["f1"]))];
    let claims: &[(&str, &[&str])] = &[("r", &["f1"])];
    let problems = matches_gaps(&[row("r", &["a2"])], &matches, claims);
    assert!(has(&problems, "names `a` for `r`"), "{problems:?}");
    assert!(has(&problems, "lists `a2` for `r`"), "{problems:?}");
}

#[test]
fn a_form_missing_from_claims_or_a_bare_not_claimed_fails_the_form_gate() {
    let matches = [
        ("r", "a", Claim::Forms(&["f2"])),
        ("r", "b", Claim::Not("")),
        ("r", "c", Claim::Forms(&[])),
    ];
    let claims: &[(&str, &[&str])] = &[("r", &["f1"])];
    let problems = matches_gaps(&[row("r", &["a", "b", "c"])], &matches, claims);
    assert!(has(&problems, "the `f2` form"), "{problems:?}");
    assert!(has(&problems, "with no reason"), "{problems:?}");
    assert!(has(&problems, "lists no form for `c`"), "{problems:?}");
}

#[test]
fn every_form_that_matches_names_is_a_claimed_form_of_its_rule() {
    // The same check on the real tables, without the document, so a typo in a form shows at once.
    for (rule, text, claim) in MATCHES {
        if let Claim::Forms(forms) = claim {
            let claimed = CLAIMS
                .iter()
                .find(|(name, _)| name == rule)
                .map_or(&[][..], |(_, forms)| *forms);
            for form in *forms {
                assert!(claimed.contains(form), "{rule}: `{text}` names `{form}`");
            }
        }
    }
}

/// A set of cases that covers everything `coverage` asks for, built from the tables above, so the
/// failure tests below can remove one thing at a time.
fn full_cover() -> (Vec<Case>, Vec<&'static str>) {
    let mut cases = Vec::new();
    for (rule, forms) in CLAIMS {
        for form in *forms {
            cases.push(positive(
                &format!("t/{rule}-{form}"),
                "x",
                &["x"],
                &[rule],
                &[form],
            ));
        }
    }
    cases.push(negative("t/neg", "x", EXCLUSIONS));
    while cases.len() < M1_FLOOR {
        cases.push(negative(&format!("t/pad{}", cases.len()), "x", &[]));
    }
    (cases, CLAIMS.iter().map(|(rule, _)| *rule).collect())
}

#[test]
fn full_coverage_passes_the_gate() {
    let (cases, rules) = full_cover();
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn a_rule_with_no_positive_case_fails_the_gate() {
    let (mut cases, rules) = full_cover();
    cases.retain(|c| !c.rules.iter().any(|r| r == "jwt"));
    while cases.len() < M1_FLOOR {
        cases.push(negative(&format!("t/more{}", cases.len()), "x", &[]));
    }
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(
        has(&problems, "rule `jwt` has no positive case"),
        "{problems:?}"
    );
}

#[test]
fn a_rule_the_gate_does_not_know_fails_the_gate() {
    let (cases, mut rules) = full_cover();
    rules.push("new_rule");
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(
        has(&problems, "rule `new_rule` has no positive case"),
        "{problems:?}"
    );
    assert!(has(&problems, "no row in CLAIMS"), "{problems:?}");
}

#[test]
fn a_syntax_form_with_no_positive_case_fails_the_gate() {
    let (mut cases, rules) = full_cover();
    cases.retain(|c| !(c.rules == ["secret_by_key"] && c.forms == ["ini"]));
    while cases.len() < M1_FLOOR {
        cases.push(negative(&format!("t/more{}", cases.len()), "x", &[]));
    }
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(
        has(
            &problems,
            "rule `secret_by_key` has no positive case for the `ini` form"
        ),
        "{problems:?}"
    );
}

#[test]
fn a_form_on_the_wrong_rule_does_not_count() {
    // The `ini` form of the AWS key id is not the `ini` form of the key rule.
    let (mut cases, rules) = full_cover();
    cases.retain(|c| !(c.rules == ["secret_by_key"] && c.forms == ["ini"]));
    cases.push(positive(
        "t/wrong",
        "x",
        &["x"],
        &["aws_access_key_id"],
        &["ini"],
    ));
    while cases.len() < M1_FLOOR {
        cases.push(negative(&format!("t/more{}", cases.len()), "x", &[]));
    }
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(
        has(
            &problems,
            "rule `secret_by_key` has no positive case for the `ini` form"
        ),
        "{problems:?}"
    );
}

#[test]
fn an_exclusion_with_no_negative_fails_the_gate() {
    let (mut cases, rules) = full_cover();
    for case in &mut cases {
        case.exclusions.retain(|e| e != "suffix_ref");
    }
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(
        has(&problems, "exclusion `suffix_ref` has no negative case"),
        "{problems:?}"
    );
}

#[test]
fn a_typo_in_a_form_or_an_exclusion_fails_the_gate() {
    let (mut cases, rules) = full_cover();
    cases.push(positive("t/typo", "x", &["x"], &["jwt"], &["tekst"]));
    cases.push(negative("t/typo2", "x", &["suffix_nmae"]));
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(has(&problems, "`tekst` is not a form"), "{problems:?}");
    assert!(
        has(&problems, "`suffix_nmae` is not a key-name exclusion"),
        "{problems:?}"
    );
}

#[test]
fn fewer_cases_than_the_floor_fail_the_gate() {
    let (mut cases, rules) = full_cover();
    cases.truncate(M1_FLOOR - 1);
    let problems = coverage(&cases, M1_FLOOR, &rules);
    assert!(has(&problems, "fewer than FLOOR"), "{problems:?}");
}

#[test]
fn a_floor_below_the_m1_minimum_fails_the_gate() {
    let (cases, rules) = full_cover();
    let problems = coverage(&cases, 5, &rules);
    assert!(has(&problems, "FLOOR is 5"), "{problems:?}");
}

#[test]
fn the_appendix_b_reader_takes_the_m1_rows_only() {
    let doc = "## Appendix B: redaction rules\n\n| Rule | Group | M | Matches | Span |\n| --- | --- | --- | --- | --- |\n\
               | `a_rule` | `g` | 1 | x | y |\n| `b_rule`, `c_rule` | `g` | 2 | x | y |\n| `d_rule` | `g` | 1 | x | y |\n\n\
               ## Appendix C: next\n\n| `e_rule` | `g` | 1 | x | y |\n";
    assert_eq!(appendix_b_m1_rules(doc), ["a_rule", "d_rule"]);
}

#[test]
fn the_appendix_b_reader_takes_the_backticked_matches_items_and_unescapes_pipes() {
    let doc = "## Appendix B: redaction rules\n\n| Rule | Group | M | Matches | Span |\n| --- | --- | --- | --- | --- |\n\
               | `a_rule` | `g` | 1 | `one`, prose, `(A\\|B)[x]{2}` and `Two:` | y |\n\
               | `b_rule` | `g` | 2 | `skipped` | y |\n";
    assert_eq!(
        appendix_b_m1_rows(doc),
        [row("a_rule", &["one", "(A|B)[x]{2}", "Two:"])]
    );
}

// ---- the loader fails on bad files ----

/// A corpus folder with one valid case and whatever the test adds. `FLOOR` is 1 here: the loader does not
/// judge the count.
fn temp_corpus() -> Result<tempfile::TempDir, std::io::Error> {
    let tmp = tempfile::tempdir()?;
    fs::write(tmp.path().join("FLOOR"), "1\n")?;
    fs::write(
        tmp.path().join("synthetic.toml"),
        "[parts]\nsecret_one = [\"canary-\", \"one-1234\"]\nunused = [\"a\", \"b\"]\n",
    )?;
    fs::create_dir(tmp.path().join("cat"))?;
    fs::write(
        tmp.path().join("cat/ok.in"),
        "DB_PASSWORD=${SYN:secret_one}\n",
    )?;
    fs::write(
        tmp.path().join("cat/ok.expected"),
        "DB_PASSWORD=[REDACTED:secret_by_key:~1]\n",
    )?;
    fs::write(
        tmp.path().join("cat/ok.toml"),
        "polarity = \"positive\"\nsince = \"m1\"\nrulesets = [\"report\"]\nrules = [\"secret_by_key\"]\n\
         forms = [\"env\"]\nsecrets = [\"${SYN:secret_one}\"]\n",
    )?;
    Ok(tmp)
}

fn load_error(dir: &Path) -> String {
    match load_corpus(dir) {
        Ok(_) => String::new(),
        Err(problems) => problems.join("\n"),
    }
}

#[test]
fn the_loader_expands_parts_and_reports_the_unused_ones() -> Result<(), Box<dyn std::error::Error>>
{
    let tmp = temp_corpus()?;
    let corpus = load_corpus(tmp.path()).map_err(|p| p.join("\n"))?;
    assert_eq!(corpus.cases.len(), 1);
    assert_eq!(corpus.cases[0].input, "DB_PASSWORD=canary-one-1234\n");
    assert_eq!(corpus.cases[0].secrets, ["canary-one-1234"]);
    assert_eq!(corpus.unused_parts, ["unused"]);
    let (problems, _) = run_case(&redactor(), &corpus.cases[0]);
    assert!(problems.is_empty(), "{problems:?}");
    Ok(())
}

#[test]
fn a_case_file_without_its_siblings_fails_the_load() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    fs::write(tmp.path().join("cat/lonely.in"), "x\n")?;
    let error = load_error(tmp.path());
    assert!(
        error.contains("cat/lonely: missing .expected and .toml"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_stray_file_fails_the_load() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    fs::write(tmp.path().join("cat/ok.expected.actual"), "x\n")?;
    fs::write(tmp.path().join("notes.txt"), "x\n")?;
    let error = load_error(tmp.path());
    assert!(error.contains("not a case file"), "{error}");
    assert!(error.contains("stray file `notes.txt`"), "{error}");
    Ok(())
}

#[test]
fn an_unknown_key_or_an_unknown_part_fails_the_load() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    let meta = tmp.path().join("cat/ok.toml");
    let text = fs::read_to_string(&meta)?;
    fs::write(&meta, format!("{text}secert = [\"x\"]\n"))?;
    assert!(load_error(tmp.path()).contains("unknown key `secert`"));
    fs::write(&meta, text)?;
    fs::write(tmp.path().join("cat/ok.in"), "DB_PASSWORD=${SYN:nope}\n")?;
    assert!(load_error(tmp.path()).contains("unknown synthetic part(s): nope"));
    Ok(())
}

#[test]
fn a_known_gap_or_an_m2_case_is_refused_in_m1() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    let meta = tmp.path().join("cat/ok.toml");
    let text = fs::read_to_string(&meta)?;
    fs::write(&meta, text.replace("\"positive\"", "\"known_gap\""))?;
    assert!(load_error(tmp.path()).contains("known_gap"));
    fs::write(&meta, text.replace("\"m1\"", "\"m2\""))?;
    assert!(load_error(tmp.path()).contains("since must be"));
    Ok(())
}

#[test]
fn a_part_with_one_piece_or_an_expected_with_a_reference_fails_the_load()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    fs::write(
        tmp.path().join("cat/ok.expected"),
        "DB_PASSWORD=${SYN:secret_one}\n",
    )?;
    assert!(load_error(tmp.path()).contains(".expected holds a"));
    fs::write(
        tmp.path().join("synthetic.toml"),
        "[parts]\nsecret_one = [\"whole-token\"]\n",
    )?;
    assert!(load_error(tmp.path()).contains("fewer than 2 parts"));
    Ok(())
}

#[test]
fn an_empty_piece_in_a_part_fails_the_load() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    fs::write(
        tmp.path().join("synthetic.toml"),
        "[parts]\nsecret_one = [\"\", \"whole-token\"]\n",
    )?;
    assert!(load_error(tmp.path()).contains("has an empty part"));
    Ok(())
}

// Whole secrets, built here from pieces so this file never holds one.

fn whole_pem_header() -> String {
    ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat()
}

fn whole_jwt() -> String {
    [
        "eyJhbGciOiJSUzI1NiJ9",
        ".",
        "eyJzdWIiOiJ4In0",
        ".",
        "c2lnbmF0dXJl",
    ]
    .concat()
}

fn whole_share_token() -> String {
    ["rdy_st_", "Zk3v9Qx7canaryShareTok01"].concat()
}

fn other_aws_id() -> String {
    ["ASIA", "ABCDEFGHIJKLMNOP"].concat()
}

#[test]
fn a_whole_secret_in_a_case_file_fails_the_load() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (whole_pem_header(), "a PEM private-key header"),
        (whole_jwt(), "a JWT"),
        (whole_share_token(), "an rdy_st_ share token"),
        ("rdy_st_".to_owned(), "an rdy_st_ share token"),
        (other_aws_id(), "an AWS key id other than"),
    ];
    for (secret, what) in cases {
        for file in ["ok.in", "ok.toml", "ok.expected"] {
            let tmp = temp_corpus()?;
            let path = tmp.path().join("cat").join(file);
            let text = fs::read_to_string(&path)?;
            let comment = if file.ends_with("toml") { "# " } else { "" };
            fs::write(&path, format!("{text}{comment}{secret}\n"))?;
            let error = load_error(tmp.path());
            assert!(error.contains(what), "{file} with {what}: {error}");
        }
    }
    Ok(())
}

#[test]
fn the_documented_aws_example_id_is_allowed_whole() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    let path = tmp.path().join("cat/ok.in");
    let text = fs::read_to_string(&path)?;
    fs::write(&path, format!("{text}key {DOCUMENTED_AWS_ID}\n"))?;
    assert_eq!(load_error(tmp.path()), "");
    Ok(())
}

#[test]
fn a_whole_secret_in_synthetic_toml_fails_the_load_but_a_bare_prefix_piece_does_not()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_corpus()?;
    let synthetic = tmp.path().join("synthetic.toml");
    fs::write(
        &synthetic,
        format!(
            "[parts]\nsecret_one = [\"canary-\", \"one-1234\"]\nshare = [\"rdy_st_\", \"x\"]\n\
             whole = [\"a\", \"{}\"]\n",
            other_aws_id()
        ),
    )?;
    let error = load_error(tmp.path());
    assert!(error.contains("an AWS key id other than"), "{error}");
    assert!(error.contains("in one piece"), "{error}");
    fs::write(
        &synthetic,
        "[parts]\nsecret_one = [\"canary-\", \"one-1234\"]\nshare = [\"rdy_st_\", \"x\"]\n",
    )?;
    // `share` is used by no case, which `load_corpus` reports only through `unused_parts`.
    assert_eq!(load_error(tmp.path()), "");
    Ok(())
}
