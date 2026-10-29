//! The command table and the fix-text lists against the check catalog (docs/plan/03-check-catalog.md).
//!
//! 1. Every row of 03 Appendix A is a typed entry in the command table, with the same program, path,
//!    arguments, operating systems, timeout, exit-code meanings and stdout cap, and the table holds no
//!    command the appendix lacks. A path the appendix does not give must come from the GPU tool
//!    search list of section 6.
//! 2. The fix bullets of the catalog name only commands and sysctls that are in the allow-list files.
//!
//! The catalog is in the workspace and not in the published crate, so these tests live in `tests/`,
//! which `cargo package` leaves out.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rdy_engine::check::Os;
use rdy_engine::exec::table::{self, ExitClass};
use rdy_engine::fixtext::{self, AllowLists};

fn catalog() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/plan/03-check-catalog.md");
    match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => panic!("cannot read {}: {err}", path.display()),
    }
}

/// One command of Appendix A: program stem, arguments as written, and the absolute path if given.
struct DocCommand {
    stem: String,
    args: String,
    path: Option<String>,
}

fn stem_of(program: &str) -> String {
    let base = program.rsplit(['/', '\\']).next().unwrap_or_default();
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
}

/// The backtick spans of a cell, outside parentheses (the notes there quote patterns, not commands).
fn backtick_spans(cell: &str) -> Vec<String> {
    let mut plain = String::new();
    let mut depth = 0_u32;
    for c in cell.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            c if depth == 0 => plain.push(c),
            _ => {}
        }
    }
    plain
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The commands of one Command cell. A span that starts with `-` continues the previous command and
/// replaces as many trailing arguments as it has words (`-p udp` after `-anv -p tcp`).
fn doc_commands(cell: &str) -> Vec<DocCommand> {
    let mut out: Vec<(String, Vec<String>, Option<String>)> = Vec::new();
    for span in backtick_spans(cell) {
        let words: Vec<String> = span.split_whitespace().map(str::to_owned).collect();
        let Some(first) = words.first() else {
            continue;
        };
        if first.starts_with('-') {
            let Some((stem, previous, path)) = out.last().cloned() else {
                panic!("Appendix A cell starts with an argument: {cell}");
            };
            let keep = previous.len().saturating_sub(words.len());
            let mut args = previous[..keep].to_vec();
            args.extend(words);
            out.push((stem, args, path));
        } else {
            let absolute = first.starts_with('/') || first.starts_with("%SystemRoot%");
            let path = absolute.then(|| first.replace("%SystemRoot%", r"C:\Windows"));
            out.push((stem_of(first), words[1..].to_vec(), path));
        }
    }
    out.into_iter()
        .map(|(stem, args, path)| DocCommand {
            stem,
            args: args.join(" "),
            path,
        })
        .collect()
}

fn os_letter(os: Os) -> char {
    match os {
        Os::Linux => 'L',
        Os::Macos => 'M',
        Os::Windows => 'W',
        _ => '?',
    }
}

type Key = (String, String);

#[derive(Debug, PartialEq, Eq)]
struct Facts {
    os: BTreeSet<char>,
    timeout_secs: BTreeSet<u64>,
    /// Exit code and what it means.
    exits: BTreeSet<(i32, &'static str)>,
    /// Stdout cap in bytes.
    caps: BTreeSet<usize>,
}

const MIB: usize = 1024 * 1024;

fn class_label(class: ExitClass) -> &'static str {
    match class {
        ExitClass::Ok => "ok",
        ExitClass::NotFound => "not found",
        ExitClass::NotRunning => "not running",
        ExitClass::KeyMissing => "key missing",
        _ => "other",
    }
}

/// The exit codes of an "Expected exit" cell: `0`, `0 found, 2 not found, other = tool error`,
/// `0, 252 = not running`. Text in parentheses is a note. A segment with no leading number
/// (`other = tool error`) says what every unlisted code is, which the table models by not listing it.
fn doc_exits(cell: &str) -> BTreeSet<(i32, &'static str)> {
    let mut plain = String::new();
    let mut depth = 0_u32;
    for c in cell.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            c if depth == 0 => plain.push(c),
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    for segment in plain.split(',') {
        let segment = segment.trim();
        let Some(code) = segment
            .split_whitespace()
            .next()
            .and_then(|word| word.parse::<i32>().ok())
        else {
            continue;
        };
        let label = if code == 0 {
            "ok"
        } else if segment.contains("not found") {
            "not found"
        } else if segment.contains("not running") {
            "not running"
        } else if segment.contains("missing") {
            "key missing"
        } else {
            panic!("Appendix A exit segment `{segment}` has no known meaning")
        };
        out.insert((code, label));
    }
    out
}

fn appendix_a_facts(catalog: &str) -> (BTreeMap<Key, Facts>, BTreeMap<Key, BTreeSet<String>>) {
    // The caps are in the prose above the table. Hold the sentence, so an edit to it is an edit here.
    assert!(
        catalog.contains("stdout capped at 1 MiB (2 MiB for the GPU XML, a per-command cap)"),
        "the stdout cap sentence of Appendix A changed; update the caps in this test"
    );
    let mut facts: BTreeMap<Key, Facts> = BTreeMap::new();
    let mut paths: BTreeMap<Key, BTreeSet<String>> = BTreeMap::new();
    let mut in_appendix = false;
    for line in catalog.lines() {
        if line.starts_with("## Appendix A.") {
            in_appendix = true;
            continue;
        }
        if in_appendix && line.starts_with("## ") {
            break;
        }
        if !in_appendix || !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let (command, oses, timeout, exit) = (cells[1], cells[3], cells[4], cells[5]);
        let secs: u64 = timeout.trim_end_matches('s').parse().unwrap_or(0);
        assert!(secs > 0, "bad timeout `{timeout}` in: {line}");
        for doc in doc_commands(command) {
            let gpu_xml = doc.stem == "nvidia-smi" && doc.args == "-q -x";
            let key = (doc.stem, doc.args);
            let entry = facts.entry(key.clone()).or_insert_with(|| Facts {
                os: BTreeSet::new(),
                timeout_secs: BTreeSet::new(),
                exits: BTreeSet::new(),
                caps: BTreeSet::new(),
            });
            entry.exits.extend(doc_exits(exit));
            entry.caps.insert(if gpu_xml { 2 * MIB } else { MIB });
            entry.os.extend(
                oses.split(',')
                    .map(|part| part.trim().chars().next().unwrap_or('?')),
            );
            entry.timeout_secs.insert(secs);
            if let Some(path) = doc.path {
                paths.entry(key).or_default().insert(path);
            }
        }
    }
    (facts, paths)
}

fn table_facts() -> (BTreeMap<Key, Facts>, BTreeMap<Key, BTreeSet<String>>) {
    let mut facts: BTreeMap<Key, Facts> = BTreeMap::new();
    let mut paths: BTreeMap<Key, BTreeSet<String>> = BTreeMap::new();
    for entry in table::entries() {
        for form in entry.forms {
            let key = (stem_of(entry.program), form.render());
            let slot = facts.entry(key.clone()).or_insert_with(|| Facts {
                os: BTreeSet::new(),
                timeout_secs: BTreeSet::new(),
                exits: BTreeSet::new(),
                caps: BTreeSet::new(),
            });
            slot.os.extend(entry.os.iter().map(|os| os_letter(*os)));
            slot.timeout_secs.insert(form.timeout.as_secs());
            slot.caps.insert(form.stdout_cap);
            slot.exits.extend(
                form.exits
                    .iter()
                    .map(|rule| (rule.code, class_label(rule.class))),
            );
            paths.entry(key).or_default().insert(entry.path.to_owned());
        }
    }
    (facts, paths)
}

#[test]
fn every_appendix_a_row_is_a_typed_entry_with_the_same_os_timeout_exits_and_cap() {
    let catalog = catalog();
    let (doc, doc_paths) = appendix_a_facts(&catalog);
    let (code, code_paths) = table_facts();
    assert!(
        doc.len() >= 20,
        "Appendix A parsed to only {} commands",
        doc.len()
    );
    let only_doc: Vec<_> = doc.keys().filter(|key| !code.contains_key(*key)).collect();
    let only_code: Vec<_> = code.keys().filter(|key| !doc.contains_key(*key)).collect();
    assert!(
        only_doc.is_empty(),
        "in Appendix A, not in the table: {only_doc:?}"
    );
    assert!(
        only_code.is_empty(),
        "in the table, not in Appendix A: {only_code:?}"
    );
    for (key, want) in &doc {
        assert_eq!(
            code.get(key),
            Some(want),
            "OS, timeout, exit codes or stdout cap differ for {key:?}"
        );
    }
    for (key, paths) in &doc_paths {
        let have = &code_paths[key];
        for path in paths {
            assert!(
                have.contains(path),
                "Appendix A gives {path} for {key:?}, the table has {have:?}"
            );
        }
    }
    // A command the appendix gives no path for gets the one section 6 implies: the first directory of
    // the GPU tool search list, or `System32` on Windows. A path invented outside that list fails.
    let search_list = catalog
        .lines()
        .find(|line| line.starts_with("- **Tool search list**"))
        .expect("section 6 has the tool search list");
    for (key, have) in &code_paths {
        if doc_paths.contains_key(key) {
            continue;
        }
        for path in have {
            let ok = if let Some(rest) = path.strip_prefix(r"C:\Windows\") {
                search_list.contains("`System32`") && rest.starts_with(r"System32\")
            } else {
                let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
                search_list.contains(&format!("`{dir}`"))
            };
            assert!(
                ok,
                "{path} for {key:?} is not in Appendix A or in the section 6 search list"
            );
        }
    }
}

#[test]
fn the_fix_bullets_of_the_catalog_name_only_listed_commands_and_sysctls() {
    let catalog = catalog();
    let bullets: Vec<String> = catalog
        .lines()
        .filter(|line| {
            line.starts_with("- **Fix:")
                || line.starts_with("- **Fix ")
                || line.starts_with("- **Fix,")
        })
        .map(|line| line.replace("\\\"", "\""))
        .collect();
    assert!(
        bullets.len() > 20,
        "found only {} fix bullets",
        bullets.len()
    );
    let mut problems = Vec::new();
    for bullet in &bullets {
        for violation in fixtext::audit(bullet, AllowLists::embedded()) {
            problems.push(violation.to_string());
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
