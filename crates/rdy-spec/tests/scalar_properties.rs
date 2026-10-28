//! Property-style tests for the scalar types.
//!
//! There is no property-test crate in the workspace yet, so these use a small seeded generator. The
//! seed is fixed, so a failure reproduces. Each test checks one law over a few thousand values:
//!
//! - `Display` then `parse` gives back an equal value.
//! - `serde_json` then back gives an equal value.
//! - A near miss of a valid value is refused.
//! - No input panics, and no error echoes more than 64 characters of input.

use rdy_spec::{Duration, Quantity, ScalarError, Target, Version};

/// xorshift64*, enough for test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[usize::try_from(self.below(items.len() as u64)).unwrap_or(0)]
    }
}

const ROUNDS: usize = 4000;

fn round_trips<T>(text: &str)
where
    T: std::str::FromStr<Err = ScalarError>
        + std::fmt::Display
        + PartialEq
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    let value: T = text.parse().unwrap_or_else(|e| panic!("{text:?}: {e}"));
    let shown = value.to_string();
    let again: T = shown.parse().unwrap_or_else(|e| panic!("{shown:?}: {e}"));
    assert_eq!(value, again, "{text:?} -> {shown:?}");
    assert_eq!(
        shown,
        again.to_string(),
        "display is not stable for {text:?}"
    );
    let json = serde_json::to_string(&value).unwrap_or_else(|e| panic!("{text:?}: {e}"));
    let back: T = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
    assert_eq!(value, back, "{json}");
}

#[test]
fn quantity_round_trips() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let units = ["", "Ki", "Mi", "Gi", "Ti", "Pi"];
    let mut accepted = 0;
    for _ in 0..ROUNDS {
        let digits = 1 + rng.below(15);
        let n = rng.next() % 10_u64.pow(u32::try_from(digits).unwrap());
        let text = format!("{n}{}", rng.pick(&units));
        if Quantity::parse(&text).is_ok() {
            round_trips::<Quantity>(&text);
            accepted += 1;
        }
    }
    assert!(accepted > ROUNDS / 4, "only {accepted} accepted");
}

#[test]
fn quantity_overflow_is_an_error_not_a_wrap() {
    let mut rng = Rng(7);
    let (mut ok, mut refused) = (0, 0);
    for _ in 0..ROUNDS {
        let digits = 1 + rng.below(15);
        let n = rng.next() % 10_u64.pow(u32::try_from(digits).unwrap());
        let (unit, size) = *rng.pick(&[
            ("Ki", 1_u128 << 10),
            ("Mi", 1 << 20),
            ("Gi", 1 << 30),
            ("Ti", 1 << 40),
            ("Pi", 1 << 50),
        ]);
        let text = format!("{n}{unit}");
        let exact = u128::from(n) * size;
        match Quantity::parse(&text) {
            Ok(q) => {
                assert_eq!(u128::from(q.bytes()), exact, "{text}");
                assert!(q.bytes() <= Quantity::MAX_BYTES);
                ok += 1;
            }
            Err(e) => {
                assert!(exact > u128::from(Quantity::MAX_BYTES), "{text}: {e}");
                refused += 1;
            }
        }
    }
    assert!(ok > 100 && refused > 100, "ok {ok}, refused {refused}");
}

#[test]
fn duration_round_trips() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let units = ["ms", "s", "m", "h", "d"];
    for _ in 0..ROUNDS {
        let digits = 1 + rng.below(9);
        let n = 1 + rng.next() % (10_u64.pow(u32::try_from(digits).unwrap()) - 1).max(1);
        let text = format!("{n}{}", rng.pick(&units));
        round_trips::<Duration>(&text);
    }
}

#[test]
fn version_round_trips() {
    let mut rng = Rng(0xA076_1D64_78BD_642F);
    for _ in 0..ROUNDS {
        let parts = 1 + rng.below(4);
        let body: Vec<String> = (0..parts)
            .map(|_| (rng.next() % 1_000_000_000).to_string())
            .collect();
        let text = format!(
            "{}{}",
            if rng.below(2) == 0 { "" } else { "v" },
            body.join(".")
        );
        round_trips::<Version>(&text);
        let v: Version = text.parse().unwrap();
        assert_eq!(v.components().len(), usize::try_from(parts).unwrap());
    }
}

#[test]
fn target_round_trips() {
    let mut rng = Rng(0xE703_7ED1_A0B4_28DB);
    let labels = ["registry", "License", "a-b", "x1", "proxy", "corp", "ACME"];
    let tails = ["", "/", "/v2/", "/a/b?c=d", "?q=1", "/a@b"];
    for _ in 0..ROUNDS {
        let host = (0..1 + rng.below(4))
            .map(|_| *rng.pick(&labels))
            .collect::<Vec<_>>()
            .join(".");
        let port = 1 + rng.below(65535);
        let text = match rng.below(5) {
            0 => format!("{host}:{port}"),
            1 => format!("[2001:db8::{:x}]:{port}", rng.below(65536)),
            2 => format!("https://{host}{}", rng.pick(&tails)),
            3 => format!("http://{host}:{port}{}", rng.pick(&tails)),
            _ => format!(
                "https://[2001:db8::{:x}]:{port}{}",
                rng.below(65536),
                rng.pick(&tails)
            ),
        };
        round_trips::<Target>(&text);
    }
}

#[test]
fn ipv6_forms_of_ipv4_addresses_are_refused() {
    let mut rng = Rng(0x0F0F_1234_ABCD_9876);
    for _ in 0..ROUNDS {
        let (hi, lo) = (rng.below(65536), rng.below(65536));
        let port = 1 + rng.below(65535);
        let forms = [
            format!("[::ffff:{hi:x}:{lo:x}]:{port}"),
            format!("[::FFFF:{hi:X}:{lo:X}]:{port}"),
            format!("[0:0:0:0:0:ffff:{hi:x}:{lo:x}]:{port}"),
            format!("https://[::ffff:{hi:x}:{lo:x}]:{port}/p"),
            format!("[::{hi:x}:{lo:x}]:{port}"),
        ];
        for form in forms {
            // `::0:0` is `::`, and `::0:1` is `::1`. Those two are not IPv4 forms.
            let bare = form.starts_with("[::") && !form.to_lowercase().contains("ffff");
            if bare && hi == 0 && lo <= 1 {
                continue;
            }
            let e = Target::parse(&form).unwrap_err();
            assert!(
                e.to_string().contains("wraps an IPv4 address"),
                "{form}: {e}"
            );
            assert!(e.hint().contains("IPv4"), "{form}");
        }
    }
}

#[test]
fn single_character_edits_of_a_valid_value_are_refused_or_still_valid() {
    // Mutating a valid string must never panic. Specific near misses are in the unit tests.
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let seeds = [
        "32Gi",
        "10s",
        "1.30",
        "registry.acme.example:443",
        "https://h/p",
    ];
    let noise = [
        ' ', '\t', '\u{0}', '\u{1b}', '\u{e9}', '#', '@', '\\', ':', '.', '[', ']', '-', '9',
    ];
    for _ in 0..ROUNDS {
        let mut chars: Vec<char> = rng.pick(&seeds).chars().collect();
        let at = usize::try_from(rng.below(chars.len() as u64)).unwrap();
        match rng.below(3) {
            0 => {
                chars.remove(at);
            }
            1 => chars.insert(at, *rng.pick(&noise)),
            _ => chars[at] = *rng.pick(&noise),
        }
        let text: String = chars.into_iter().collect();
        for result in [
            Quantity::parse(&text).err(),
            Duration::parse(&text).err(),
            Version::parse(&text).err(),
            Target::parse(&text).err(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!result.hint().is_empty());
            assert!(
                !result.to_string().chars().any(char::is_control),
                "{result:?}"
            );
        }
    }
}

#[test]
fn errors_never_echo_more_than_64_characters() {
    let mut rng = Rng(42);
    for len in [65, 100, 1000, 100_000] {
        let text: String = (0..len)
            .map(|_| *rng.pick(&['9', 'a', ':', '.', '\u{1b}', '\u{3042}', ' ']))
            .collect();
        for e in [
            Quantity::parse(&text).unwrap_err(),
            Duration::parse(&text).unwrap_err(),
            Version::parse(&text).unwrap_err(),
            Target::parse(&text).unwrap_err(),
        ] {
            let message = e.to_string();
            assert!(message.len() < 600, "{} bytes", message.len());
            assert!(!message.chars().any(char::is_control), "{message:?}");
        }
    }
}

/// The exit test of the ticket, spelled out.
#[test]
fn the_ticket_examples() {
    assert!("32G".parse::<Quantity>().is_err());
    // An unquoted 1.30 reaches the type as the number 1.3.
    assert!(serde_json::from_str::<Version>("1.30").is_err());
    assert!("10 s".parse::<Duration>().is_err());
    assert!("host:99999".parse::<Target>().is_err());
    assert!("https://u:p@host/".parse::<Target>().is_err());

    assert!("32Gi".parse::<Quantity>().is_ok());
    assert!(serde_json::from_str::<Version>("\"1.30\"").is_ok());
    assert!(serde_json::from_str::<Version>("14").is_ok());
    assert!("7d".parse::<Duration>().is_ok());
    assert!("[::1]:443".parse::<Target>().is_ok());
}
