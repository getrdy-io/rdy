//! Every crate ships its own copy of the root LICENSE so `cargo package` includes it.
//! The copies must not drift.

use std::fs;
use std::path::Path;

#[test]
fn every_crate_license_matches_the_root_license() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let want = fs::read(root.join("LICENSE")).expect("root LICENSE exists");
    let mut checked = 0;
    for entry in fs::read_dir(root.join("crates")).expect("crates/ exists") {
        let dir = entry.expect("readable entry").path();
        if !dir.join("Cargo.toml").is_file() {
            continue;
        }
        let got = fs::read(dir.join("LICENSE"))
            .unwrap_or_else(|e| panic!("{} has no LICENSE: {e}", dir.display()));
        assert!(
            got == want,
            "{} differs from the root LICENSE; copy it again",
            dir.join("LICENSE").display()
        );
        checked += 1;
    }
    assert!(checked >= 6, "expected at least 6 crates, found {checked}");
}
