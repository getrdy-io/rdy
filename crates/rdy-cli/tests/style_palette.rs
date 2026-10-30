//! The palette of 07 D.1 as bytes. The golden shows each role painted on and off, with the escape byte
//! written as `\x1b` so the file is plain ASCII. A changed code fails with a diff (M1-070).
//!
//! This test needs no privilege and runs on every OS.

use std::path::PathBuf;

use rdy_cli::style::{Role, Styler, untrusted};
use rdy_engine::testing::golden::assert_golden;

#[test]
fn palette_matches_its_golden() {
    let on = Styler::new(true);
    let off = Styler::new(false);
    let mut text = String::new();
    for role in Role::ALL {
        text.push_str(&format!(
            "{role:?}: on={} off={}\n",
            untrusted(&on.paint(role, "WORD")),
            off.paint(role, "WORD"),
        ));
    }
    // Untrusted text next to a styled word: escaped, and never inside the styled run.
    text.push_str(&format!(
        "line: {} {}\n",
        untrusted(&on.paint(Role::Warn, "WARN")),
        untrusted("web-01\u{1b}[31m.acme\u{202e}.test")
    ));
    assert!(text.is_ascii());
    assert_golden(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/style-palette.txt"),
        text,
    );
}
