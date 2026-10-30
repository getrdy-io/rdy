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
//! secrets = ["..."]            # strings that must not appear in the output (positive)
//! note = "..."                 # optional, for the reader
//! ```
//!
//! The harness redacts `.in` with a fixed key, replaces every tag with `~` and compares the result with
//! `.expected` byte for byte through `assert_golden`, which never writes under `tests/fixtures/redaction`.
//! `.expected` is blessed by hand. On its own the harness also checks that no `secrets` string survives
//! (the oracle that catches a wrongly blessed file), that every `rules` entry fired, that a second pass
//! changes nothing and finds nothing outside a placeholder, and that a negative comes out unchanged.
//!
//! The gate is coverage, not count. It fails on a survivor, a rule that did not fire, an `.expected`
//! mismatch, an idempotence or residual failure, a rule or a syntax form with no positive case, a key-name
//! exclusion with no negative, or fewer cases than `FLOOR`. The rule list comes from the engine
//! (`built_in_rule_names`) and is checked against the M1 rows of 04 Appendix B.
//!
//! What this corpus does not claim: the forms M1-060 left to M2 (`Cookie` and `Set-Cookie`, a 40-character
//! secret by proximity, a one-line JSON object after a secret key, a space in URL userinfo, `curl -u`,
//! base64-armored or bare DER keys, a PEM block split over log events). They have no case here. M2-061 adds
//! them as `known_gap` cases with the ledger. A case that claimed one would be a case that hides a miss.

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
    ("pem_private_key", &["plain", "json_escaped"]),
    ("aws_access_key_id", &["log_line", "json", "ini"]),
    ("rdy_share_token", &["text"]),
    ("jwt", &["text"]),
    ("auth_header", &["bearer", "basic", "proxy"]),
    ("api_key_header", &["header"]),
    ("url_userinfo", &["proxy", "dsn", "percent_encoded"]),
    ("aws_secret_access_key", &["env", "ini"]),
    ("aws_session_token", &["json"]),
    ("kubeconfig_credential", &["token", "client_key_data"]),
    (
        "secret_by_key",
        &[
            "env",
            "yaml",
            "json",
            "ini",
            "flag",
            "placeholder_prefix",
            "ansi",
        ],
    ),
];

/// The key-name exclusions of 04 Appendix B. Each needs a negative case.
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
    "value_from",
    "suffix_name",
    "suffix_ref",
    "suffix_file",
    "suffix_path",
    "suffix_namespace",
    "run_secrets",
];

/// The keys a case `.toml` may hold. Anything else is a typo and fails.
const TOML_KEYS: &[&str] = &[
    "polarity",
    "since",
    "rulesets",
    "rules",
    "forms",
    "exclusions",
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
    secrets: Vec<String>,
    input: String,
    /// The `.expected` file. The golden helper reads it.
    expected_path: PathBuf,
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
    Regex::new(r"\[REDACTED:([a-z0-9_.]+):[0-9a-f]{8}\]")
        .unwrap_or_else(|e| panic!("the tag pattern is valid: {e}"))
});

/// The text with every tag replaced by `~`.
fn normalized(text: &str) -> String {
    TAG.replace_all(text, "[REDACTED:$1:~]").into_owned()
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
    let input_raw = read_text(&dir.join(format!("{stem}.in")))?;
    let input = expand(&input_raw, parts, used).map_err(|e| format!("{id}: {e}"))?;
    let expected_path = dir.join(format!("{stem}.expected"));
    let expected = read_text(&expected_path)?;
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
        secrets,
        input,
        expected_path,
    })
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
            if !case.exclusions.is_empty() {
                problems.push(format!("{id}: only a negative case lists `exclusions`"));
            }
            for secret in &case.secrets {
                if secret.is_empty() {
                    problems.push(format!("{id}: an empty string in `secrets`"));
                } else if !case.input.contains(secret.as_str()) {
                    problems.push(format!(
                        "{id}: a `secrets` entry is not in the input, so it proves nothing: {secret}"
                    ));
                } else if out_text.contains(secret.as_str()) {
                    problems.push(format!("{id}: the secret survived: {secret}"));
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
                    "{id}: a negative case lists no `rules`, `forms` or `secrets`"
                ));
            }
            if out_text != case.input {
                problems.push(format!(
                    "{id}: a negative changed. It must come out as it went in"
                ));
            }
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

/// The rule names that 04 Appendix B marks for milestone 1.
fn appendix_b_m1_rules(doc: &str) -> Vec<String> {
    let mut in_appendix = false;
    let mut names = Vec::new();
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
        let cells: Vec<&str> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() >= 3 && cells[2] == "1" {
            names.extend(cells[0].split('`').skip(1).step_by(2).map(str::to_owned));
        }
    }
    names
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

// ---- the gate fails when it should ----

fn positive(id: &str, input: &str, secrets: &[&str], rules: &[&str], forms: &[&str]) -> Case {
    Case {
        id: id.to_owned(),
        polarity: Polarity::Positive,
        rules: rules.iter().map(|s| (*s).to_owned()).collect(),
        forms: forms.iter().map(|s| (*s).to_owned()).collect(),
        exclusions: Vec::new(),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        input: input.to_owned(),
        expected_path: PathBuf::from("unused.expected"),
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
    assert_eq!(output, "DB_PASSWORD=[REDACTED:secret_by_key:~]\n");
    let (problems, _) = run_case(&r, &negative("t/ok-neg", "passed: 12\n", &[]));
    assert!(problems.is_empty(), "{problems:?}");
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
        "DB_PASSWORD=[REDACTED:secret_by_key:~]\n",
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
