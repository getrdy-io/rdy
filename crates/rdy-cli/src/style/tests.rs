//! Table tests for the colour rules of 07 section 6, the width rules, and the escaping of untrusted text.

use std::ffi::OsString;

use super::*;

/// A `StyleEnv` from `NAME=value` pairs, without touching the process environment.
fn env(vars: &[(&str, &str)]) -> StyleEnv {
    StyleEnv::from_lookup(|name| {
        vars.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(value))
    })
}

/// A case of the colour table: name, choice, variables, stream is a terminal, colour?
type Row = (
    &'static str,
    ColorChoice,
    &'static [(&'static str, &'static str)],
    bool,
    bool,
);

#[test]
fn colour_rules_first_match_wins() {
    use ColorChoice::{Always, Auto, Never};
    // (rule of 07 section 6, choice, variables, stream is a terminal, colour?)
    let table: &[Row] = &[
        // Rule 1: the flag beats every variable and the stream.
        ("1 always, pipe", Always, &[], false, true),
        (
            "1 always beats NO_COLOR",
            Always,
            &[("NO_COLOR", "1")],
            false,
            true,
        ),
        (
            "1 always beats TERM=dumb",
            Always,
            &[("TERM", "dumb")],
            true,
            true,
        ),
        ("1 never, terminal", Never, &[], true, false),
        (
            "1 never beats CLICOLOR_FORCE",
            Never,
            &[("CLICOLOR_FORCE", "1")],
            true,
            false,
        ),
        // Rule 2: NO_COLOR, any non-empty value, beats rules 3 to 5.
        ("2 NO_COLOR=1", Auto, &[("NO_COLOR", "1")], true, false),
        (
            "2 NO_COLOR=0 still counts",
            Auto,
            &[("NO_COLOR", "0")],
            true,
            false,
        ),
        (
            "2 NO_COLOR=anything",
            Auto,
            &[("NO_COLOR", "no thanks")],
            true,
            false,
        ),
        (
            "2 NO_COLOR beats CLICOLOR_FORCE",
            Auto,
            &[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")],
            true,
            false,
        ),
        (
            "2 empty NO_COLOR is not set",
            Auto,
            &[("NO_COLOR", "")],
            true,
            true,
        ),
        // Rule 3: CLICOLOR_FORCE, anything but 0, beats rules 4 and 5.
        (
            "3 force on a pipe",
            Auto,
            &[("CLICOLOR_FORCE", "1")],
            false,
            true,
        ),
        (
            "3 force=yes",
            Auto,
            &[("CLICOLOR_FORCE", "yes")],
            false,
            true,
        ),
        (
            "3 force=0 is off, pipe",
            Auto,
            &[("CLICOLOR_FORCE", "0")],
            false,
            false,
        ),
        (
            "3 force=0 is off, terminal",
            Auto,
            &[("CLICOLOR_FORCE", "0")],
            true,
            true,
        ),
        (
            "3 empty force is not set",
            Auto,
            &[("CLICOLOR_FORCE", "")],
            false,
            false,
        ),
        (
            "3 force beats CLICOLOR=0",
            Auto,
            &[("CLICOLOR_FORCE", "1"), ("CLICOLOR", "0")],
            true,
            true,
        ),
        (
            "3 force beats TERM=dumb",
            Auto,
            &[("CLICOLOR_FORCE", "1"), ("TERM", "dumb")],
            false,
            true,
        ),
        // Rule 4: CLICOLOR=0 or TERM=dumb beat the terminal.
        ("4 CLICOLOR=0", Auto, &[("CLICOLOR", "0")], true, false),
        (
            "4 CLICOLOR=1 changes nothing",
            Auto,
            &[("CLICOLOR", "1")],
            true,
            true,
        ),
        ("4 TERM=dumb", Auto, &[("TERM", "dumb")], true, false),
        (
            "4 TERM=xterm changes nothing",
            Auto,
            &[("TERM", "xterm-256color")],
            true,
            true,
        ),
        // Rule 5: the stream decides.
        ("5 terminal", Auto, &[], true, true),
        ("5 pipe", Auto, &[], false, false),
    ];
    for (name, choice, vars, tty, want) in table {
        assert_eq!(
            use_color(*choice, &env(vars), *tty),
            *want,
            "{name}: {choice:?} {vars:?} terminal={tty}"
        );
    }
}

#[test]
fn width_follows_the_terminal_then_columns_then_100_and_is_clamped() {
    // (terminal columns, COLUMNS, width)
    let table: &[(Option<usize>, Option<&str>, usize)] = &[
        // The terminal wins over COLUMNS.
        (Some(80), Some("70"), 80),
        (Some(100), None, 100),
        // Not a terminal: COLUMNS, then 100.
        (None, Some("72"), 72),
        (None, None, 100),
        // Clamped to 60 to 100, from either source.
        (Some(300), None, 100),
        (Some(40), None, 60),
        (None, Some("500"), 100),
        (None, Some("20"), 60),
        (None, Some("60"), 60),
        (None, Some("61"), 61),
        // A terminal that reports no size has no width. COLUMNS that is not a positive number is ignored.
        (Some(0), Some("90"), 90),
        (Some(0), None, 100),
        (None, Some("0"), 100),
        (None, Some(""), 100),
        (None, Some("wide"), 100),
        (None, Some("-5"), 100),
        (None, Some("99999999999999999999999"), 100),
        (None, Some(" 75 "), 75),
    ];
    for (terminal, columns, want) in table {
        let vars: Vec<(&str, &str)> = columns.iter().map(|v| ("COLUMNS", *v)).collect();
        assert_eq!(
            wrap_width(*terminal, &env(&vars)),
            *want,
            "terminal={terminal:?} COLUMNS={columns:?}"
        );
    }
}

#[test]
fn term_dumb_turns_colour_off_only_when_nothing_stronger_applies() {
    let dumb = env(&[("TERM", "dumb")]);
    assert!(!use_color(ColorChoice::Auto, &dumb, true));
    assert!(use_color(ColorChoice::Always, &dumb, true));
    // TERM=dumb does not change the width.
    assert_eq!(wrap_width(None, &dumb), 100);
}

#[test]
fn a_hostname_with_an_escape_and_a_bidi_override_prints_as_text() {
    let host = "web-01\u{1b}[31m.acme\u{202e}.test";
    assert_eq!(untrusted(host), "web-01\\x1b[31m.acme\\u{202e}.test");
    // Never styled, and no styler can reach it: `paint` only takes `&'static str`.
    let styler = Styler::new(true);
    let line = format!("{} {}", styler.paint(Role::Warn, "WARN"), untrusted(host));
    let after_status = line.split(RESET).nth(1).expect("status ends with a reset");
    assert_eq!(after_status, " web-01\\x1b[31m.acme\\u{202e}.test");
    assert!(!after_status.contains('\u{1b}'));
    assert!(!after_status.contains('\u{202e}'));
}

#[test]
fn no_character_survives_untrusted_as_a_control_or_invisible_one() {
    for code in 0..=0x10_ffff_u32 {
        let Some(c) = char::from_u32(code) else {
            continue;
        };
        let escaped = untrusted(&c.to_string());
        assert!(
            !escaped
                .chars()
                .any(|e| e.is_control() || rdy_engine::text::is_invisible(e)),
            "U+{code:04X} is still active after escaping: {escaped:?}"
        );
    }
}

#[test]
fn painting_wraps_a_word_in_ansi_16_codes_and_off_returns_it_unchanged() {
    let on = Styler::new(true);
    let off = Styler::new(false);
    assert!(on.is_enabled());
    assert!(!off.is_enabled());
    assert_eq!(on.paint(Role::Pass, "PASS"), "\u{1b}[32mPASS\u{1b}[0m");
    assert_eq!(on.paint(Role::Block, "BLOCK"), "\u{1b}[1;31mBLOCK\u{1b}[0m");
    assert_eq!(on.paint(Role::Pass, ""), "");
    for role in Role::ALL {
        assert_eq!(off.paint(role, "WARN"), "WARN", "{role:?}");
        let painted = on.paint(role, "WARN");
        assert!(painted.starts_with("\u{1b}["), "{role:?}");
        assert!(painted.ends_with("\u{1b}[0m"), "{role:?}");
        assert!(painted.contains("WARN"), "{role:?}");
        // ANSI 16 only: every parameter is bold, dim, or a foreground colour 31 to 33.
        let params = &painted[2..painted.find('m').expect("sgr end")];
        for p in params.split(';') {
            assert!(
                matches!(p, "1" | "2" | "31" | "32" | "33"),
                "{role:?} uses SGR {p}"
            );
        }
    }
}

#[test]
fn the_styler_follows_the_colour_choice() {
    let none = env(&[]);
    assert!(Styler::for_stderr(ColorChoice::Always, &none).is_enabled());
    assert!(!Styler::for_stderr(ColorChoice::Never, &none).is_enabled());
    assert!(!Styler::for_stderr(ColorChoice::Auto, &env(&[("NO_COLOR", "1")])).is_enabled());
}

#[test]
fn width_counts_cells_not_bytes_or_characters() {
    assert_eq!(display_width("PASS"), 4);
    assert_eq!(display_width("caf\u{e9}"), 4);
    assert_eq!(display_width("\u{4e2d}\u{6587}"), 4);
    // A combining accent takes no cell.
    assert_eq!(display_width("e\u{301}"), 1);
    assert_eq!(pad_end("PASS", 7), "PASS   ");
    assert_eq!(pad_end("\u{4e2d}", 4), "\u{4e2d}  ");
    assert_eq!(pad_end("toolong", 3), "toolong");
}

#[test]
fn cut_shortens_with_three_dots_and_never_splits_an_escape() {
    assert_eq!(cut("short", 10), "short");
    assert_eq!(cut("exactly10!", 10), "exactly10!");
    assert_eq!(cut("abcdefghijkl", 10), "abcdefg...");
    assert_eq!(display_width(&cut("abcdefghijkl", 10)), 10);
    // The marker is three ASCII dots, never an ellipsis character.
    assert!(cut("abcdefghijkl", 10).is_ascii());
    assert!(!cut("\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}", 7).contains('\u{2026}'));
    // Too narrow for the marker.
    assert_eq!(cut("abcdef", 2), "..");
    assert_eq!(cut("abcdef", 0), "");
    // `\x1b` is four cells and goes whole or not at all.
    assert_eq!(cut("a\u{1b}[31mb", 20), "a\\x1b[31mb");
    assert_eq!(cut("a\u{1b}[31mbcdefg", 7), "a...");
    assert_eq!(cut("a\u{1b}[31mbcdefg", 8), "a\\x1b...");
    // Wide characters are not split in half: a budget of 4 cells holds two of them.
    assert_eq!(
        cut("\u{4e2d}\u{6587}\u{4e2d}\u{6587}", 7),
        "\u{4e2d}\u{6587}..."
    );
    assert_eq!(cut("\u{4e2d}\u{6587}\u{4e2d}\u{6587}", 6), "\u{4e2d}...");
    // A combining mark stays with its letter.
    assert_eq!(cut("e\u{301}xxxxxxxxxx", 5), "e\u{301}x...");
    // Escaping comes first, so the result never holds a control character.
    assert!(!cut("\u{1b}[2J\u{202e}hidden text that is long", 12).contains(['\u{1b}', '\u{202e}']));
}

#[test]
fn the_style_codes_and_the_cut_marker_are_ascii() {
    assert!(CUT_MARKER.is_ascii());
    for role in Role::ALL {
        assert!(Styler::new(true).paint(role, "X").is_ascii(), "{role:?}");
    }
}
