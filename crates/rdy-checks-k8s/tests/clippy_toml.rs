//! Drift guard: this crate's `clippy.toml` replaces the root one, so it must repeat every entry of it.
//!
//! The root file carries the rules every crate lives under (the clap exit paths, the clock). If someone
//! adds an entry there and forgets this crate's file, the wall has a hole here and nothing else says so.

#![allow(clippy::expect_used)]

use std::path::Path;

/// The `path = "..."` values of a clippy.toml, in file order.
fn paths(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let rest = line.split_once("path = \"")?.1;
            Some(rest.split_once('"')?.0.to_owned())
        })
        .collect()
}

#[test]
fn the_crate_clippy_toml_repeats_every_root_entry() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root =
        std::fs::read_to_string(manifest.join("../../clippy.toml")).expect("root clippy.toml");
    let own = std::fs::read_to_string(manifest.join("clippy.toml")).expect("crate clippy.toml");

    let root_paths = paths(&root);
    assert!(
        !root_paths.is_empty(),
        "the root clippy.toml has no entries?"
    );
    let own_paths = paths(&own);
    for path in &root_paths {
        assert!(
            own_paths.contains(path),
            "crates/rdy-checks-k8s/clippy.toml is missing the root entry `{path}`: copy it, with `allow-invalid = true`"
        );
    }
    for setting in [
        "allow-unwrap-in-tests = true",
        "allow-expect-in-tests = true",
    ] {
        assert!(root.contains(setting) && own.contains(setting), "{setting}");
    }
}
