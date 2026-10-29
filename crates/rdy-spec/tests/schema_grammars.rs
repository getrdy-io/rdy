//! The grammar of each checked value is written twice: as a parser in Rust and as a pattern in the
//! generated schema. This test feeds both the same inputs and requires the same answer, so one cannot
//! change without the other.
//!
//! The inputs are seeded and fixed, so a failure reproduces. They are built from the characters that
//! matter to each grammar, plus the valid forms of the plan's examples.

use std::error::Error;
use std::path::Path;

use jsonschema::Validator;
use rdy_spec::spec::{CheckId, CheckName, FixText, ProductSlug};
use rdy_spec::{Duration, Quantity, Target, Version};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// xorshift64*, enough for test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64).max(1)).unwrap_or(0)
    }

    /// A string of `len` characters from `alphabet`.
    fn string(&mut self, alphabet: &[&str], len: usize) -> String {
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }
}

fn def_validator(def: &str) -> TestResult<Validator> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/spec.v1.schema.json"),
    )?;
    let whole: Value = serde_json::from_str(&text)?;
    Ok(jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("#/$defs/{def}"),
            "$defs": whole["$defs"],
        }))?)
}

/// How the schema may differ from the parser.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// The same answer on every input.
    Exact,
    /// The schema never refuses what the parser reads, and may accept more. A pattern cannot say
    /// everything a parser checks (a sum of units, the labels of a host name), so the parser has the last
    /// word on the extra values, at lint and at load.
    SchemaMayBeLooser,
}

/// Runs `inputs` through the parser and the schema and fails on the first disagreement the fit forbids.
fn agree(
    what: &str,
    fit: Fit,
    inputs: &[Value],
    parser_accepts: impl Fn(&Value) -> bool,
    schema_check: &Validator,
) {
    let mut accepted = 0;
    for input in inputs {
        let by_parser = parser_accepts(input);
        let by_schema = schema_check.is_valid(input);
        let allowed = by_parser == by_schema || (fit == Fit::SchemaMayBeLooser && by_schema);
        assert!(
            allowed,
            "{what}: the parser says {by_parser} and the schema says {by_schema} for {input}"
        );
        accepted += usize::from(by_parser);
    }
    assert!(
        accepted > 20 && accepted < inputs.len(),
        "{what}: the inputs must include both valid and invalid values ({accepted} of {})",
        inputs.len()
    );
}

fn as_str(v: &Value) -> Option<&str> {
    v.as_str()
}

fn texts(
    rng: &mut Rng,
    alphabet: &[&str],
    valid: &[&str],
    rounds: usize,
    max_len: usize,
) -> Vec<Value> {
    let mut out: Vec<Value> = valid.iter().map(|s| json!(s)).collect();
    for _ in 0..rounds {
        let len = rng.below(max_len + 1);
        out.push(json!(rng.string(alphabet, len)));
    }
    // A near miss of each valid value: one character dropped, doubled or swapped for a bad one.
    for s in valid {
        for cut in 0..s.len() {
            if s.is_char_boundary(cut) && s.is_char_boundary(cut + 1) {
                out.push(json!(format!("{}{}", &s[..cut], &s[cut + 1..])));
                out.push(json!(format!(
                    "{}{}{}",
                    &s[..=cut],
                    &s[cut..=cut],
                    &s[cut + 1..]
                )));
                out.push(json!(format!("{}~{}", &s[..cut], &s[cut + 1..])));
            }
        }
        out.push(json!(format!("{s}\n")));
        out.push(json!(format!(" {s}")));
    }
    out
}

#[test]
fn duration_parser_and_pattern_agree() -> TestResult {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let alphabet = [
        "0", "1", "5", "9", "m", "s", "h", "d", " ", ".", "-", "+", "x",
    ];
    let valid = [
        "500ms",
        "10s",
        "7d",
        "1m",
        "60s",
        "1h",
        "999999999d",
        "1000000000d",
    ];
    let inputs = texts(&mut rng, &alphabet, &valid, 6000, 7);
    agree(
        "Duration",
        Fit::Exact,
        &inputs,
        |v| as_str(v).is_some_and(|s| Duration::parse(s).is_ok()),
        &def_validator("Duration")?,
    );
    Ok(())
}

#[test]
fn quantity_parser_and_pattern_agree() -> TestResult {
    let mut rng = Rng(0x0F0F_1234_5678_9ABC);
    let alphabet = [
        "0", "1", "7", "9", "K", "M", "G", "T", "P", "i", "B", " ", ".", "-",
    ];
    let valid = [
        "32Gi",
        "1048576",
        "200Mi",
        "0",
        "999999999999999",
        "1Ki",
        "5Pi",
    ];
    let mut inputs = texts(&mut rng, &alphabet, &valid, 6000, 7);
    for n in [
        json!(0),
        json!(1),
        json!(999_999_999_999_999u64),
        json!(1_000_000_000_000_000u64),
        json!(-1),
        json!(1.5),
        json!(2.0),
        json!(true),
        json!(null),
        json!([]),
    ] {
        inputs.push(n);
    }
    agree(
        "Quantity",
        Fit::SchemaMayBeLooser,
        &inputs,
        |v| serde_json::from_value::<Quantity>(v.clone()).is_ok(),
        &def_validator("Quantity")?,
    );
    Ok(())
}

#[test]
fn version_parser_and_pattern_agree() -> TestResult {
    let mut rng = Rng(0xDEAD_BEEF_0000_0001);
    let alphabet = ["0", "1", "2", "9", ".", "v", "V", "-", " ", "x", "+"];
    let valid = [
        "1.28",
        "5.10",
        "12.4",
        "v1.2.3",
        "1.2.3.4",
        "14",
        "0",
        "999999999.1",
    ];
    let mut inputs = texts(&mut rng, &alphabet, &valid, 6000, 9);
    for n in [
        json!(14),
        json!(0),
        json!(-1),
        json!(1.5),
        json!(1.30),
        json!(null),
    ] {
        inputs.push(n);
    }
    agree(
        "Version",
        Fit::Exact,
        &inputs,
        |v| serde_json::from_value::<Version>(v.clone()).is_ok(),
        &def_validator("Version")?,
    );
    Ok(())
}

#[test]
fn target_parser_and_pattern_agree() -> TestResult {
    let mut rng = Rng(0x7777_AAAA_5555_0033);
    let alphabet = [
        "a",
        "b",
        "Z",
        "0",
        "9",
        ".",
        "-",
        ":",
        "/",
        "@",
        "[",
        "]",
        " ",
        "#",
        "?",
        "_",
        "http://",
        "https://",
        "443",
        "65535",
        "65536",
        "0",
        "::1",
        "host.example",
    ];
    let valid = [
        "registry.acme.example:443",
        "https://registry.acme.example",
        "http://a.example/path/x?y=1",
        "[::1]:443",
        "[2001:db8::1]:8443",
        "10.0.0.1:80",
        "host:1",
        "host:65535",
    ];
    let inputs = texts(&mut rng, &alphabet, &valid, 12000, 8);
    agree(
        "Target",
        Fit::SchemaMayBeLooser,
        &inputs,
        |v| as_str(v).is_some_and(|s| Target::parse(s).is_ok()),
        &def_validator("Target")?,
    );
    Ok(())
}

#[test]
fn product_check_id_and_check_name_parsers_and_patterns_agree() -> TestResult {
    let spec = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/spec.v1.schema.json"),
    )?;
    let whole: Value = serde_json::from_str(&spec)?;
    // The three names have no definition of their own except the check id. The others are checked
    // through the property that uses them.
    let property = |pointer: &str| -> TestResult<Validator> {
        let schema = whole
            .pointer(pointer)
            .ok_or_else(|| format!("no {pointer}"))?
            .clone();
        let mut wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": whole["$defs"],
        });
        if let (Some(target), Some(source)) = (wrapper.as_object_mut(), schema.as_object()) {
            for (k, v) in source {
                if k != "description" {
                    target.insert(k.clone(), v.clone());
                }
            }
        }
        Ok(jsonschema::draft202012::options().build(&wrapper)?)
    };

    let mut rng = Rng(0x0BAD_CAFE_F00D_0001);
    let slug_alphabet = ["a", "z", "0", "9", "-", "_", ".", "A", " ", "é"];
    let slug_valid = ["acme-platform", "a", "0-9", &"a".repeat(63)];
    let mut inputs = texts(&mut rng, &slug_alphabet, &slug_valid, 5000, 8);
    inputs.push(json!("a".repeat(64)));
    agree(
        "ProductSlug",
        Fit::Exact,
        &inputs,
        |v| as_str(v).is_some_and(|s| ProductSlug::new(s).is_ok()),
        &property("/$defs/Metadata/properties/product")?,
    );

    let id_alphabet = ["a", "z", "0", "9", "_", ".", "-", "A", " "];
    let id_valid = [
        "host.memory",
        "k8s.storageclass",
        "host.security_agents",
        "gpu.cuda",
    ];
    let mut inputs = texts(&mut rng, &id_alphabet, &id_valid, 8000, 9);
    inputs.push(json!(format!("{}.x", "a".repeat(16))));
    inputs.push(json!(format!("{}.x", "a".repeat(17))));
    inputs.push(json!(format!("a.{}", "x".repeat(48))));
    inputs.push(json!(format!("a.{}", "x".repeat(49))));
    agree(
        "CheckId",
        Fit::Exact,
        &inputs,
        |v| as_str(v).is_some_and(|s| CheckId::new(s).is_ok()),
        &def_validator("CheckId")?,
    );

    let name_valid = ["data", "data-windows", "a_b", "0", &"a".repeat(63)];
    let mut inputs = texts(&mut rng, &slug_alphabet, &name_valid, 5000, 8);
    inputs.push(json!("a".repeat(64)));
    agree(
        "CheckName",
        Fit::Exact,
        &inputs,
        |v| as_str(v).is_some_and(|s| CheckName::new(s).is_ok()),
        &property("/$defs/Check/properties/name")?,
    );

    // The fix text is a length rule: 1 to 2000 characters, counted as characters and not bytes.
    let fix = property("/$defs/Check/properties/fix")?;
    let inputs: Vec<Value> = [
        String::new(),
        "a".to_owned(),
        "a".repeat(2000),
        "a".repeat(2001),
        "\u{e9}".repeat(2000),
        "\u{e9}".repeat(2001),
        "\u{1f600}".repeat(2000),
        "\u{1f600}".repeat(2001),
        "Add RAM.".to_owned(),
    ]
    .into_iter()
    .map(Value::String)
    .collect();
    for input in &inputs {
        let by_parser = input.as_str().is_some_and(|s| FixText::new(s).is_ok());
        assert_eq!(
            by_parser,
            fix.is_valid(input),
            "FixText for a text of {} characters",
            input.as_str().map_or(0, |s| s.chars().count())
        );
    }
    Ok(())
}
