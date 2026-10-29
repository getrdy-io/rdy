//! Property tests for `rdy_spec::parse_unverified` and `rdy_spec::load` (docs/plan/08-testing.md, section 4).
//!
//! One test per row of the table in that section, plus the "verify before parse" row, which lives in
//! `src/sig/tests.rs` because the parser spy it needs is private to the crate.
//!
//! | Invariant | Test |
//! | --- | --- |
//! | Never panics, `hint()` set, a line and column for YAML failures | `bytes_never_panic`, `yaml_soup_never_panics`, `mutated_examples_never_panic` |
//! | Over 1 MiB is refused first, depth 64 passes and 65 fails | `over_one_mib_is_refused_before_parsing`, `depth_64_passes_and_65_fails` |
//! | Anchors, aliases, merge keys, duplicate keys, a second document: each its own error | `each_poison_step_gets_its_own_error` |
//! | Round trip through JSON | `a_generated_spec_survives_a_json_round_trip`, `example_specs_survive_a_round_trip` |
//! | Forward compatibility | `unknown_ids_fields_and_severities_skip_one_check` |
//! | Version-like text is kept | `quoted_versions_keep_their_text`, `unquoted_two_part_versions_are_refused` |
//! | Verify before parse | `any_change_to_the_signed_fixture_is_a_signature_error` in `src/sig/tests.rs` |
//!
//! # Settings
//!
//! - **Cases.** Set per test with `ProptestConfig`, never with `PROPTEST_CASES`: 10,000 for the "never
//!   panics" and "limits" rows, 256 for the rest.
//! - **Seed.** Fixed, so an unrelated PR never fails on a fresh draw. To hunt with other draws, set
//!   `PROPTEST_RNG_SEED=<number>`; a seed set that way wins. The nightly job (M2) does that.
//! - **Size caps.** A generated input is at most 4 KiB and a generated list at most 64 items.
//! - **Shrinking.** `max_shrink_time` is 30 s, so a failure finishes shrinking before nextest's kill.
//! - **Regressions.** A failure is saved to `proptest-regressions/parse_properties.txt` in this crate.
//!   Commit that file. It is read before the fixed-seed cases on every run. To replay by hand, run
//!   `cargo test -p rdy-spec --test parse_properties`.
//!
//! Helpers in this file avoid `unwrap` and `expect` because clippy only allows them inside `#[test]`
//! functions.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use proptest::test_runner::{FileFailurePersistence, RngSeed};
use rdy_spec::check::{CheckParams, KNOWN_IDS, UnsupportedReason};
use rdy_spec::reserved::{RESERVED_IDS, UnknownKind};
use rdy_spec::sig::{Policy, TrustStore};
use rdy_spec::spec::{
    BundleSpec, CheckName, CheckSpec, CheckTimeout, FixText, Lenient, Metadata, OsFamily,
    ProductSlug, Severity, Spec,
};
use rdy_spec::{MAX_SPEC_BYTES, SpecError, load, parse_unverified};
use serde_json::Value;

/// Cases for "never panics" and "limits" (08 section 4).
const MANY: u32 = 10_000;
/// Cases for every other property.
const FEW: u32 = 256;
/// The largest generated input, in bytes.
const MAX_INPUT: usize = 4096;
/// The largest generated list.
const MAX_ITEMS: usize = 64;
/// The seed pull requests use. It is the bytes of `rdy_spec`.
const PR_SEED: u64 = 0x7264_795F_7370_6563;
/// Where failures are saved, relative to the crate. Cargo and nextest both run a test from there.
const REGRESSIONS: &str = "proptest-regressions/parse_properties.txt";

/// The settings of every property here.
fn config(cases: u32) -> ProptestConfig {
    // `with_cases` starts from the default, which reads `PROPTEST_RNG_SEED`. Only an unset seed becomes
    // the fixed one.
    let mut config = ProptestConfig::with_cases(cases);
    config.max_shrink_time = 30_000;
    config.failure_persistence = Some(Box::new(FileFailurePersistence::Direct(REGRESSIONS)));
    if config.rng_seed == RngSeed::Random {
        config.rng_seed = RngSeed::Fixed(PR_SEED);
    }
    config
}

// ---- files --------------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.yaml` file of a directory of the repo, sorted by name so the order never depends on the
/// file system.
fn yaml_files(dir: &str) -> Vec<(String, Vec<u8>)> {
    let path = repo_root().join(dir);
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|file| match std::fs::read(&file) {
            Ok(bytes) => (file.display().to_string(), bytes),
            Err(e) => panic!("cannot read {}: {e}", file.display()),
        })
        .collect()
}

/// The example specs.
fn examples() -> Vec<(String, Vec<u8>)> {
    yaml_files("examples/specs")
}

/// The seeds for mutation: the examples and the synthetic invalid and malformed fixtures.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        [
            "examples/specs",
            "tests/fixtures/specs/invalid",
            "tests/fixtures/specs/malformed",
        ]
        .into_iter()
        .flat_map(yaml_files)
        .map(|(_, bytes)| bytes)
        .collect()
    })
}

#[test]
fn the_regression_file_is_committed() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(REGRESSIONS);
    assert!(
        path.is_file(),
        "{} is missing. Keep it in git",
        path.display()
    );
}

#[test]
fn the_mutation_corpus_holds_the_examples_and_the_fixtures() {
    assert!(examples().len() >= 5, "examples/specs lost files");
    assert!(corpus().len() >= 20, "only {} seed files", corpus().len());
}

// ---- row 1: never panics ------------------------------------------------------------------------

/// Pieces of YAML that stress the reader: brackets, anchors, tags, merge keys, NUL, a BOM, CRLF, tabs,
/// document markers, directives, odd numbers, and the start of a real spec.
const SOUP: &[&str] = &[
    "[",
    "]",
    "{",
    "}",
    "- ",
    "&a ",
    "*a",
    "!!",
    "!tag ",
    "<<",
    "<<: ",
    "\0",
    "\u{feff}",
    "\r\n",
    "\r",
    "\t",
    "\n",
    ": ",
    ":",
    "? ",
    "---\n",
    "...\n",
    "%YAML 1.2\n",
    "'",
    "\"",
    "|\n",
    ">\n",
    "#",
    ",",
    "apiVersion: rdy/v1\n",
    "kind: Readiness\n",
    "metadata:\n  product: acme\n",
    "checks:\n",
    "  - id: host.cpu\n",
    "    min: ",
    ".nan",
    ".inf",
    "12.10",
    "0755",
    "\\",
    "\\u0000",
    "\u{e9}",
    "\u{202e}",
    " ",
    "  ",
    "key",
    "id: net.egress\n",
    "endpoints: ",
];

/// The first lines of a valid spec, so some soup gets past the header.
const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

/// Mostly short inputs, which is where the reader's error paths are, and sometimes the full 4 KiB.
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => vec(any::<u8>(), 0..=256),
        1 => vec(any::<u8>(), 0..=MAX_INPUT),
    ]
}

fn yaml_soup() -> impl Strategy<Value = Vec<u8>> {
    (any::<bool>(), vec(select(SOUP), 0..=MAX_ITEMS)).prop_map(|(with_head, pieces)| {
        let mut text = String::new();
        if with_head {
            text.push_str(HEAD);
            text.push_str("  - id: host.cpu\n    ");
        }
        text.push_str(&pieces.concat());
        text.into_bytes()
    })
}

/// One change to a seed file, written as data so a failing case shrinks to the few edits that matter.
#[derive(Debug, Clone)]
struct Edit {
    kind: u8,
    at: usize,
    len: usize,
    byte: u8,
    piece: &'static str,
}

fn edit() -> impl Strategy<Value = Edit> {
    (
        0u8..6,
        any::<usize>(),
        0usize..=16,
        any::<u8>(),
        select(SOUP),
    )
        .prop_map(|(kind, at, len, byte, piece)| Edit {
            kind,
            at,
            len,
            byte,
            piece,
        })
}

fn apply(mut bytes: Vec<u8>, edits: &[Edit]) -> Vec<u8> {
    for e in edits {
        let at = e.at % (bytes.len() + 1);
        let end = (at + e.len).min(bytes.len());
        match e.kind {
            0 => {
                if let Some(b) = bytes.get_mut(at) {
                    *b ^= 1 << (e.byte % 8);
                }
            }
            1 => {
                if let Some(b) = bytes.get_mut(at) {
                    *b = e.byte;
                }
            }
            2 => {
                bytes.splice(at..at, e.piece.bytes());
            }
            3 => {
                bytes.drain(at..end);
            }
            4 => {
                let chunk = bytes[at..end].to_vec();
                bytes.splice(end..end, chunk);
            }
            _ => bytes.truncate(at),
        }
    }
    bytes
}

fn mutated_seed() -> impl Strategy<Value = Vec<u8>> {
    (0..corpus().len(), vec(edit(), 1..=8))
        .prop_map(|(seed, edits)| apply(corpus()[seed].clone(), &edits))
}

/// Whether an error is about the text of the file, which always has a line and column. The size limit
/// is checked before the text is read, so it has none. The rules about the whole spec have none either.
fn is_yaml_failure(kind: &SpecError) -> bool {
    matches!(
        kind,
        SpecError::NotUtf8
            | SpecError::Syntax { .. }
            | SpecError::TooDeep { .. }
            | SpecError::MultipleDocuments
            | SpecError::Directive
            | SpecError::Tag { .. }
            | SpecError::Anchor
            | SpecError::Alias
            | SpecError::MergeKey
            | SpecError::DuplicateKey { .. }
            | SpecError::NonFiniteNumber { .. }
            | SpecError::UnquotedDecimal { .. }
    )
}

/// What every input must do, whatever its bytes.
///
/// `parse_unverified` returns a spec or an error with a fix line and, for a failure of the YAML text, a
/// line and column. The error text is printable. `load` without a signature agrees with it. The only
/// difference is that `load` may also refuse a spec that has expired, so a clock cannot flip this test.
fn assert_sound(bytes: &[u8]) -> Result<(), TestCaseError> {
    let parsed = parse_unverified(bytes);
    if let Err(e) = &parsed {
        prop_assert!(!e.hint().is_empty(), "{e:?}");
        let text = e.to_string();
        prop_assert!(!text.chars().any(char::is_control), "{text:?}");
        prop_assert!(text.chars().count() < 400, "{} chars", text.chars().count());
        match e.location() {
            Some(at) => prop_assert!(at.line >= 1 && at.column >= 1, "{e:?}"),
            // A rule about the whole spec, such as "no checks", has no line to point at.
            None => prop_assert!(!is_yaml_failure(e.kind()), "no place on {e:?}"),
        }
    }
    let loaded = load(bytes, None, &TrustStore::new(), Policy::AllowUnsigned);
    match (&parsed, &loaded) {
        (Ok(spec), Ok(loaded)) => prop_assert_eq!(spec, loaded.spec()),
        (Ok(_), Err(e)) => prop_assert!(matches!(e.kind(), SpecError::Expired { .. }), "{e:?}"),
        (Err(a), Err(b)) => prop_assert_eq!(a, b),
        (Err(e), Ok(_)) => prop_assert!(false, "parse refused {e:?} and load accepted"),
    }
    Ok(())
}

proptest! {
    #![proptest_config(config(MANY))]

    /// Arbitrary bytes. A signature that is not one never turns into a spec: with no pinned key, `load`
    /// refuses with a signature error whatever the spec says.
    #[test]
    fn bytes_never_panic(bytes in arbitrary_bytes(), sidecar in vec(any::<u8>(), 0..=256)) {
        assert_sound(&bytes)?;
        let result = load(&bytes, Some(&sidecar), &TrustStore::new(), Policy::AllowUnsigned);
        prop_assert!(
            matches!(&result, Err(SpecError::Signature(_))),
            "{:?}",
            result.map(|l| l.sha256().to_owned())
        );
    }

    #[test]
    fn yaml_soup_never_panics(bytes in yaml_soup()) {
        assert_sound(&bytes)?;
    }

    #[test]
    fn mutated_examples_never_panic(bytes in mutated_seed()) {
        assert_sound(&bytes)?;
    }
}

// ---- row 2: limits ------------------------------------------------------------------------------

/// How a generated nesting is written.
#[derive(Debug, Clone, Copy)]
enum Nesting {
    FlowList,
    FlowMap,
    BlockMap,
}

/// A spec whose deepest value sits `depth` levels down. The top-level map is level 1, `checks` is 2 and
/// the entry is 3 (the same count as ADR 0001 and `tests/parse.rs`).
fn spec_with_depth(shape: Nesting, depth: usize) -> String {
    let mut text = format!("{HEAD}  - id: host.cpu\n    p:");
    match shape {
        Nesting::FlowList => {
            let n = depth - 3;
            text.push(' ');
            text.push_str(&"[".repeat(n));
            text.push_str(&"]".repeat(n));
        }
        Nesting::FlowMap => {
            let n = depth - 3;
            text.push(' ');
            text.push_str(&"{a: ".repeat(n - 1));
            text.push_str("{}");
            text.push_str(&"}".repeat(n - 1));
        }
        Nesting::BlockMap => {
            // `p` holds a map (level 4). Each `k` line adds one more level, and `v: 1` sits in the last.
            let n = depth - 4;
            text.push('\n');
            for i in 0..n {
                text.push_str(&format!("{}k{i}:\n", " ".repeat(6 + i)));
            }
            text.push_str(&format!("{}v: 1", " ".repeat(6 + n)));
        }
    }
    text.push('\n');
    text
}

proptest! {
    #![proptest_config(config(MANY))]

    /// Past 1 MiB the file is refused with the size error, before it is read as text, so bytes that are
    /// not UTF-8 get the same answer. `load` refuses first too, whatever its signature input is.
    #[test]
    fn over_one_mib_is_refused_before_parsing(
        extra in 1usize..=4096,
        fill in select(vec![b' ', b'a', b'\n', 0, 0xFF, b'#', b'[']),
        sidecar in vec(any::<u8>(), 0..=8),
    ) {
        let bytes = vec![fill; MAX_SPEC_BYTES + extra];
        let want = SpecError::TooLarge { size: bytes.len(), limit: MAX_SPEC_BYTES };
        let parsed = parse_unverified(&bytes);
        prop_assert!(
            matches!(&parsed, Err(e) if e.kind() == &want),
            "{:?}", parsed.map(|_| ())
        );
        let loaded = load(&bytes, Some(&sidecar), &TrustStore::new(), Policy::RequireSigned);
        prop_assert!(
            matches!(&loaded, Err(e) if e.kind() == &want),
            "{:?}", loaded.map(|l| l.sha256().to_owned())
        );
    }

    /// Nesting up to 64 levels is read. 65 and deeper is refused with the depth error and a place.
    #[test]
    fn depth_64_passes_and_65_fails(
        // Half the draws sit around the limit, where the answer changes.
        depth in prop_oneof![1 => 5usize..=200, 1 => 56usize..=72],
        shape in select(vec![Nesting::FlowList, Nesting::FlowMap, Nesting::BlockMap]),
    ) {
        let yaml = spec_with_depth(shape, depth);
        let parsed = parse_unverified(yaml.as_bytes());
        if depth <= 64 {
            prop_assert!(parsed.is_ok(), "{shape:?} {depth}: {:?}", parsed.err());
        } else {
            match parsed {
                Err(e) => {
                    prop_assert!(
                        matches!(e.kind(), SpecError::TooDeep { limit: 64 }),
                        "{shape:?} {depth}: {e:?}"
                    );
                    prop_assert!(e.location().is_some_and(|at| at.line >= 6), "{e:?}");
                }
                Ok(_) => prop_assert!(false, "{shape:?} {depth} was read"),
            }
        }
    }
}

/// The boundary of the size limit, exactly. One parse each, so they are plain tests.
#[test]
fn a_file_of_exactly_one_mib_is_read_and_one_more_byte_is_not() {
    let mut yaml = format!("{HEAD}  - id: host.cpu\n    min: 4\n").into_bytes();
    yaml.push(b'#');
    yaml.resize(MAX_SPEC_BYTES, b'x');
    assert_eq!(yaml.len(), MAX_SPEC_BYTES);
    assert!(parse_unverified(&yaml).is_ok());
    yaml.push(b'x');
    assert!(matches!(
        parse_unverified(&yaml),
        Err(SpecError::TooLarge { size, limit: MAX_SPEC_BYTES }) if size == MAX_SPEC_BYTES + 1
    ));
}

// ---- row 3: poison steps ------------------------------------------------------------------------

/// The text of one valid entry, as lines. `n` is its number, which keeps names unique.
fn entry_lines(kind: u8, n: usize, value: u32) -> Vec<String> {
    let mut lines = vec![format!("  - name: e{n}")];
    match kind % 4 {
        0 => {
            lines.push("    id: host.cpu".to_owned());
            lines.push(format!("    min: {}", value % 512 + 1));
        }
        1 => {
            lines.push("    id: host.memory".to_owned());
            lines.push(format!("    min: {}Gi", value % 512 + 1));
        }
        2 => {
            lines.push("    id: host.disk".to_owned());
            lines.push("    path: /var".to_owned());
            lines.push(format!("    min: {}Gi", value % 512 + 1));
        }
        _ => {
            lines.push("    id: net.egress".to_owned());
            lines.push(format!(
                "    endpoints: [\"registry{}.acme.example:443\"]",
                value % 100
            ));
        }
    }
    lines
}

/// What a poison step must be refused as.
#[derive(Debug, Clone, Copy)]
enum Poison {
    Anchor,
    Alias,
    MergeKey,
    DuplicateKey,
    Tag,
    Directive,
    SecondDocument,
}

fn is_error_for(poison: Poison, e: &SpecError) -> bool {
    matches!(
        (poison, e.kind()),
        (Poison::Anchor, SpecError::Anchor)
            | (Poison::Alias, SpecError::Alias)
            | (Poison::MergeKey, SpecError::MergeKey)
            | (Poison::DuplicateKey, SpecError::DuplicateKey { .. })
            | (Poison::Tag, SpecError::Tag { .. })
            | (Poison::Directive, SpecError::Directive)
            | (Poison::SecondDocument, SpecError::MultipleDocuments)
    )
}

proptest! {
    #![proptest_config(config(FEW))]

    /// A valid spec parses. The same spec with one poison step is refused with the error of that step,
    /// at the line of the step.
    #[test]
    fn each_poison_step_gets_its_own_error(
        entries in vec((any::<u8>(), any::<u32>()), 1..=6),
        poison in select(vec![
            Poison::Anchor, Poison::Alias, Poison::MergeKey, Poison::DuplicateKey,
            Poison::Tag, Poison::Directive, Poison::SecondDocument,
        ]),
        target in any::<usize>(),
    ) {
        let mut lines: Vec<String> = HEAD.lines().map(str::to_owned).collect();
        let mut ends = Vec::new();
        for (n, (kind, value)) in entries.iter().enumerate() {
            lines.extend(entry_lines(*kind, n, *value));
            ends.push(lines.len());
        }
        let clean = format!("{}\n", lines.join("\n"));
        let spec = parse_unverified(clean.as_bytes());
        prop_assert!(spec.as_ref().is_ok_and(|s| s.checks.len() == entries.len()), "{spec:?}");

        // The line (1-based) the poison step starts on.
        let end = ends[target % ends.len()];
        let line = match poison {
            Poison::Anchor => { lines.insert(end, "    note: &a 1".to_owned()); end + 1 }
            Poison::Alias => { lines.insert(end, "    note: *a".to_owned()); end + 1 }
            Poison::MergeKey => { lines.insert(end, "    <<: {x: 1}".to_owned()); end + 1 }
            Poison::Tag => { lines.insert(end, "    note: !!str 1".to_owned()); end + 1 }
            Poison::DuplicateKey => {
                let last = lines[end - 1].clone();
                lines.insert(end, last);
                end + 1
            }
            Poison::Directive => { lines.insert(0, "%YAML 1.2".to_owned()); 1 }
            Poison::SecondDocument => {
                let marker = lines.len() + 1;
                lines.push("---".to_owned());
                lines.extend(HEAD.lines().map(str::to_owned));
                lines.extend(entry_lines(0, 99, 1));
                marker
            }
        };
        let poisoned = format!("{}\n", lines.join("\n"));
        match parse_unverified(poisoned.as_bytes()) {
            Ok(_) => prop_assert!(false, "{poison:?} was accepted:\n{poisoned}"),
            Err(e) => {
                prop_assert!(is_error_for(poison, &e), "{poison:?} gave {e:?}:\n{poisoned}");
                let at = e.location().map(|at| at.line);
                prop_assert_eq!(at, u32::try_from(line).ok(), "{:?}:\n{}", poison, poisoned);
            }
        }
    }
}

// ---- generated specs, rows 4 and 5 --------------------------------------------------------------

fn text_strategy(pattern: &'static str) -> impl Strategy<Value = String> {
    pattern
}

/// A known check with parameters that decode, and some of the common fields. The flag asks for a name.
fn known_check() -> impl Strategy<Value = (CheckSpec, bool)> {
    (
        0u8..5,
        1u32..=512,
        any::<bool>(),
        proptest::option::of(select(vec![Severity::Block, Severity::Warn])),
        proptest::option::of(text_strategy("[ -~\u{e9}\u{2603}]{1,60}")),
        proptest::option::of(1u32..=60),
        proptest::option::of(subsequence(
            vec![OsFamily::Linux, OsFamily::Macos, OsFamily::Windows],
            1..=3,
        )),
    )
        .prop_map(|(kind, n, named, severity, fix, timeout, os)| {
            let (id, params) = match kind {
                0 => ("host.cpu", serde_json::json!({ "min": n })),
                1 => (
                    "host.memory",
                    serde_json::json!({ "min": format!("{n}Gi") }),
                ),
                2 => (
                    "host.disk",
                    serde_json::json!({ "path": "/var/lib/acme", "min": format!("{n}Gi") }),
                ),
                3 => (
                    "net.egress",
                    serde_json::json!({ "endpoints": [format!("registry{n}.acme.example:443")] }),
                ),
                _ => (
                    "k8s.version",
                    serde_json::json!({ "min": format!("1.{}", n % 40) }),
                ),
            };
            let mut check = CheckSpec::new(id);
            if let Value::Object(map) = params {
                check.params = map;
            }
            check.severity = severity.map(Lenient::Valid);
            check.fix = fix
                .and_then(|text| FixText::new(text).ok())
                .map(Lenient::Valid);
            check.timeout = timeout
                .and_then(|secs| CheckTimeout::parse(&format!("{secs}s")).ok())
                .map(Lenient::Valid);
            check.os = os.map(Lenient::Valid);
            (check, named)
        })
}

/// Gives every entry a key that no other entry has: a name where the id repeats or one was asked for.
fn with_unique_names(checks: Vec<(CheckSpec, bool)>) -> Vec<CheckSpec> {
    let mut seen: Vec<String> = Vec::new();
    checks
        .into_iter()
        .enumerate()
        .map(|(i, (mut check, asked))| {
            if (asked || seen.contains(&check.id))
                && let Ok(name) = CheckName::new(format!("c{i}"))
            {
                check.name = Some(Lenient::Valid(name));
            }
            seen.push(check.id.clone());
            check
        })
        .collect()
}

fn metadata() -> impl Strategy<Value = Metadata> {
    (
        text_strategy("[a-z0-9][a-z0-9-]{0,20}"),
        proptest::option::of(text_strategy(">=[0-9]{1,2}\\.[0-9]{1,2}")),
        proptest::option::of(text_strategy("[ -~]{0,40}")),
        proptest::option::of(0..=rdy_spec::spec::MAX_SERIAL),
        btree_map(
            text_strategy("[a-z0-9][a-z0-9._/-]{0,10}"),
            text_strategy("[ -~]{0,20}"),
            0..=4,
        ),
    )
        .prop_map(|(product, version, contact, serial, annotations)| {
            let slug = ProductSlug::new(product).unwrap_or_else(|e| panic!("bad slug: {e}"));
            let mut metadata = Metadata::new(slug);
            // An empty version is refused, so an empty draw means "no version".
            metadata.version = version.filter(|v| !v.is_empty());
            metadata.contact = contact;
            metadata.serial = serial;
            metadata.annotations = annotations.into_iter().collect::<BTreeMap<_, _>>();
            metadata
        })
}

/// A valid spec: 1 to 8 known checks, any common fields that fit, sometimes a `bundle` block.
fn valid_spec() -> impl Strategy<Value = Spec> {
    (metadata(), vec(known_check(), 1..=8), any::<bool>()).prop_map(|(metadata, checks, bundle)| {
        let mut spec = Spec::new(metadata, with_unique_names(checks));
        if bundle {
            let mut block = BundleSpec::new();
            block.collect = vec!["k8s:events".to_owned()];
            spec.bundle = Some(block);
        }
        spec
    })
}

fn emit(spec: &Spec, pretty: bool) -> Vec<u8> {
    let result = if pretty {
        serde_json::to_vec_pretty(spec)
    } else {
        serde_json::to_vec(spec)
    };
    match result {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot write JSON: {e}"),
    }
}

fn parse_ok(bytes: &[u8]) -> Result<Spec, TestCaseError> {
    parse_unverified(bytes).map_err(|e| {
        TestCaseError::fail(format!(
            "{e:?}\n{}",
            String::from_utf8_lossy(bytes)
                .chars()
                .take(600)
                .collect::<String>()
        ))
    })
}

// ---- row 4: round trip --------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(FEW))]

    /// `Spec` to JSON (which is valid YAML 1.2) and back is equal, written compact or indented.
    #[test]
    fn a_generated_spec_survives_a_json_round_trip(spec in valid_spec(), pretty in any::<bool>()) {
        let once = emit(&spec, pretty);
        let back = parse_ok(&once)?;
        prop_assert_eq!(&back, &spec);
        // And writing what was read gives the same bytes again.
        prop_assert_eq!(emit(&back, pretty), once);
    }
}

#[test]
fn example_specs_survive_a_round_trip() {
    for (name, bytes) in examples() {
        let spec = match parse_unverified(&bytes) {
            Ok(spec) => spec,
            Err(e) => panic!("{name}: {e:?}"),
        };
        for pretty in [false, true] {
            match parse_unverified(&emit(&spec, pretty)) {
                Ok(again) => assert_eq!(again, spec, "{name} (pretty: {pretty})"),
                Err(e) => panic!("{name} (pretty: {pretty}): {e:?}"),
            }
        }
    }
}

// ---- row 5: forward compatibility ---------------------------------------------------------------

/// The one thing added to a valid spec.
#[derive(Debug, Clone)]
enum Insertion {
    /// A new entry with an id no rdy has, and parameters of any shape.
    UnknownId(String, BTreeMap<String, i64>),
    /// A new entry with an id on the reserved list that this build does not implement.
    ReservedId(&'static str),
    /// A parameter the check does not have, on an entry that exists.
    UnknownField(String),
    /// A severity this rdy does not know, on an entry that exists.
    UnknownSeverity(&'static str),
    /// The same on a new entry with an unknown id.
    UnknownSeverityOnUnknownId(&'static str),
}

fn insertion() -> impl Strategy<Value = Insertion> {
    let reserved: Vec<&'static str> = RESERVED_IDS
        .iter()
        .copied()
        .filter(|id| !KNOWN_IDS.contains(id))
        .collect();
    let severities = vec!["info", "critical", "fatal", "none", "BLOCK", "warning"];
    prop_oneof![
        (
            text_strategy("zz\\.[a-z][a-z0-9_]{0,20}"),
            btree_map(text_strategy("p_[a-z]{1,6}"), -100i64..100, 0..=4)
        )
            .prop_map(|(id, params)| Insertion::UnknownId(id, params)),
        select(reserved).prop_map(Insertion::ReservedId),
        text_strategy("future_[a-z]{1,10}").prop_map(Insertion::UnknownField),
        select(severities.clone()).prop_map(Insertion::UnknownSeverity),
        select(severities).prop_map(Insertion::UnknownSeverityOnUnknownId),
    ]
}

/// Whether rdy would run this entry. `Unknown` and `Unsupported` are both skips.
fn runs(params: &CheckParams) -> bool {
    !matches!(
        params,
        CheckParams::Unknown { .. } | CheckParams::Unsupported { .. }
    )
}

proptest! {
    #![proptest_config(config(FEW))]

    /// A valid spec plus one unknown id, field or severity still parses, equal to what was written.
    /// That one check is a skip and never a run, the others still run, and an unknown severity
    /// counts as block.
    #[test]
    fn unknown_ids_fields_and_severities_skip_one_check(
        mut spec in valid_spec(),
        insertion in insertion(),
        target in any::<usize>(),
    ) {
        let base = spec.checks.len();
        let at = target % base;
        let skipped = match &insertion {
            Insertion::UnknownId(id, params) => {
                let mut check = CheckSpec::new(id.clone());
                for (key, value) in params {
                    check.params.insert(key.clone(), Value::from(*value));
                }
                spec.checks.push(check);
                base
            }
            Insertion::ReservedId(id) => {
                spec.checks.push(CheckSpec::new(*id));
                base
            }
            Insertion::UnknownField(key) => {
                spec.checks[at].params.insert(key.clone(), Value::from(1));
                at
            }
            Insertion::UnknownSeverity(text) => {
                spec.checks[at].severity = Some(Lenient::Invalid(Value::from(*text)));
                at
            }
            Insertion::UnknownSeverityOnUnknownId(text) => {
                let mut check = CheckSpec::new("zz.future");
                check.severity = Some(Lenient::Invalid(Value::from(*text)));
                spec.checks.push(check);
                base
            }
        };
        let back = parse_ok(&emit(&spec, false))?;
        prop_assert_eq!(&back, &spec);
        let decoded = match back.decode_checks() {
            Ok(decoded) => decoded,
            Err(e) => return Err(TestCaseError::fail(format!("{e:?}"))),
        };
        prop_assert_eq!(decoded.len(), back.checks.len());
        for (index, params) in decoded.iter().enumerate() {
            prop_assert_eq!(runs(params), index != skipped, "entry {}: {:?}", index, params);
        }
        let entry = &back.checks[skipped];
        match &insertion {
            Insertion::UnknownId(..) => {
                prop_assert_eq!(decoded[skipped].unknown_kind(), Some(UnknownKind::UnknownCheck));
            }
            Insertion::ReservedId(_) => {
                prop_assert_eq!(decoded[skipped].unknown_kind(), Some(UnknownKind::NotInBuild));
            }
            Insertion::UnknownField(key) => {
                prop_assert!(
                    matches!(
                        &decoded[skipped],
                        CheckParams::Unsupported { reason: UnsupportedReason::UnknownField { .. }, .. }
                    ),
                    "{key}: {:?}", decoded[skipped]
                );
            }
            Insertion::UnknownSeverity(_) => {
                prop_assert!(
                    matches!(
                        &decoded[skipped],
                        CheckParams::Unsupported {
                            reason: UnsupportedReason::BadCommonField { field: "severity" }, ..
                        }
                    ),
                    "{:?}", decoded[skipped]
                );
                prop_assert_eq!(entry.effective_severity(), Severity::Block);
            }
            Insertion::UnknownSeverityOnUnknownId(_) => {
                prop_assert_eq!(decoded[skipped].unknown_kind(), Some(UnknownKind::UnknownCheck));
                prop_assert_eq!(entry.effective_severity(), Severity::Block);
            }
        }
    }
}

// ---- row 6: version-like text -------------------------------------------------------------------

/// A version-like text and whether it has two parts, which YAML would read as a number if unquoted.
fn version_like() -> impl Strategy<Value = (String, bool)> {
    (
        text_strategy("[0-9]{1,3}"),
        text_strategy("[0-9]{1,3}"),
        proptest::option::of(text_strategy("[0-9]{1,3}")),
    )
        .prop_map(|(major, minor, patch)| match patch {
            Some(patch) => (format!("{major}.{minor}.{patch}"), false),
            None => (format!("{major}.{minor}"), true),
        })
}

/// Where the version-like text sits in the spec.
#[derive(Debug, Clone, Copy)]
enum Place {
    MetadataVersion,
    ParamScalar,
    ParamInList,
}

/// A spec with `written` (already quoted, or not) in `place`. The line it is on is 6 for `metadata` and
/// 8 for a parameter.
fn spec_with_version(place: Place, written: &str) -> String {
    match place {
        Place::MetadataVersion => format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\n  version: {written}\nchecks:\n  - id: host.cpu\n    min: 4\n"
        ),
        Place::ParamScalar => format!("{HEAD}  - id: zz.future\n    cuda: {written}\n"),
        Place::ParamInList => format!("{HEAD}  - id: zz.future\n    cuda: [{written}, x]\n"),
    }
}

fn the_text(place: Place, spec: &Spec) -> Option<Value> {
    match place {
        Place::MetadataVersion => spec.metadata.version.clone().map(Value::String),
        Place::ParamScalar => spec.checks[0].params.get("cuda").cloned(),
        Place::ParamInList => match spec.checks[0].params.get("cuda") {
            Some(Value::Array(items)) => items.first().cloned(),
            _ => None,
        },
    }
}

proptest! {
    #![proptest_config(config(FEW))]

    /// `"12.10"` quoted stays `"12.10"`, in the metadata and in a parameter, with either kind of quote.
    #[test]
    fn quoted_versions_keep_their_text(
        (text, _) in version_like(),
        place in select(vec![Place::MetadataVersion, Place::ParamScalar, Place::ParamInList]),
        quote in select(vec!['"', '\'']),
    ) {
        let yaml = spec_with_version(place, &format!("{quote}{text}{quote}"));
        let spec = parse_ok(yaml.as_bytes())?;
        prop_assert_eq!(the_text(place, &spec), Some(Value::String(text)));
    }

    /// Unquoted, a two-part version is a number to YAML. It is refused where it is written, with a fix
    /// that says to quote it. A three-part one is text already, and is kept.
    #[test]
    fn unquoted_two_part_versions_are_refused(
        (text, two_part) in version_like(),
        place in select(vec![Place::MetadataVersion, Place::ParamScalar, Place::ParamInList]),
    ) {
        let yaml = spec_with_version(place, &text);
        let parsed = parse_unverified(yaml.as_bytes());
        if two_part {
            match parsed {
                Err(e) => {
                    prop_assert!(matches!(e.kind(), SpecError::UnquotedDecimal { .. }), "{e:?}");
                    let line = match place { Place::MetadataVersion => 5, _ => 7 };
                    prop_assert_eq!(e.location().map(|at| at.line), Some(line), "{:?}", e);
                    prop_assert!(e.hint().contains("quote"), "{}", e.hint());
                }
                Ok(_) => prop_assert!(false, "{text} was read as a number"),
            }
        } else {
            let spec = parse_ok(yaml.as_bytes())?;
            prop_assert_eq!(the_text(place, &spec), Some(Value::String(text)));
        }
    }
}
