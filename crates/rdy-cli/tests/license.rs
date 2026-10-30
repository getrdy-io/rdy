//! Every crate ships its own copy of the root LICENSE and NOTICE so `cargo package` includes them
//! (Apache-2.0 section 4(d) asks for NOTICE with every redistribution). The copies must not drift.

use std::fs;
use std::path::Path;

#[test]
fn every_crate_license_and_notice_match_the_root_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for name in ["LICENSE", "NOTICE"] {
        let want = fs::read(root.join(name)).unwrap_or_else(|e| panic!("root {name} exists: {e}"));
        let mut checked = 0;
        for entry in fs::read_dir(root.join("crates")).expect("crates/ exists") {
            let dir = entry.expect("readable entry").path();
            if !dir.join("Cargo.toml").is_file() {
                continue;
            }
            let got = fs::read(dir.join(name))
                .unwrap_or_else(|e| panic!("{} has no {name}: {e}", dir.display()));
            assert!(
                got == want,
                "{} differs from the root {name}; copy it again",
                dir.join(name).display()
            );
            checked += 1;
        }
        assert!(checked >= 6, "expected at least 6 crates, found {checked}");
    }
}
