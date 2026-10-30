//! Tests of the golden helper (M1-052). They drive `compare`, `Mode::parse`, `record_used` and the diff
//! directly, so none reads or sets a process variable and none depends on whether the developer is
//! running with `UPDATE_GOLDENS=1`.

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

/// A temporary repo-shaped folder.
struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    /// Where the output of a protected golden is parked.
    fn parked(&self) -> PathBuf {
        self.path("target/goldens-actual")
    }

    fn compare(&self, path: &Path, actual: &[u8], update: bool) -> Result<Done, String> {
        compare(path, actual, update, &self.parked())
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
}

fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_string())
    }
}

// ---- compare --------------------------------------------------------------------------------

#[test]
fn equal_bytes_pass_and_delete_a_stale_actual_file() {
    let tree = Tree::new();
    let golden = tree.write("golden/report.json", b"{\"a\":1}\n");
    let stale = tree.write("golden/report.json.actual", b"old failure");
    assert_eq!(
        tree.compare(&golden, b"{\"a\":1}\n", false),
        Ok(Done::Matched)
    );
    assert!(!stale.exists());
}

#[test]
fn changed_output_fails_with_a_diff_and_an_actual_file() {
    let tree = Tree::new();
    let golden = tree.write("golden/terminal.txt", b"one\ntwo\nthree\n");
    let err = tree
        .compare(&golden, b"one\n2\nthree\n", false)
        .unwrap_err();
    assert!(err.starts_with("golden differs: "), "{err}");
    assert!(err.contains("golden/terminal.txt"), "{err}");
    assert!(
        err.contains("--- golden\n+++ output\n@@ -1,3 +1,3 @@\n one\n-two\n+2\n three\n"),
        "{err}"
    );
    assert!(err.contains("terminal.txt.actual"), "{err}");
    assert!(err.contains("UPDATE_GOLDENS=1 cargo nextest run"), "{err}");
    // The actual file holds the new bytes. The golden is untouched.
    assert_eq!(
        fs::read(tree.path("golden/terminal.txt.actual")).unwrap(),
        b"one\n2\nthree\n"
    );
    assert_eq!(fs::read(&golden).unwrap(), b"one\ntwo\nthree\n");
}

#[test]
fn a_missing_golden_fails_and_is_not_created() {
    let tree = Tree::new();
    let golden = tree.path("golden/report.html");
    let err = tree.compare(&golden, b"<html>\n", false).unwrap_err();
    assert!(err.starts_with("golden missing: "), "{err}");
    assert!(err.contains("7 bytes"), "{err}");
    assert!(err.contains("UPDATE_GOLDENS=1 cargo nextest run"), "{err}");
    assert!(!golden.exists());
    // The output is kept for review even though there is nothing to diff.
    assert_eq!(
        fs::read(tree.path("golden/report.html.actual")).unwrap(),
        b"<html>\n"
    );
}

#[test]
fn a_golden_that_is_a_folder_fails_and_names_the_path() {
    let tree = Tree::new();
    let folder = tree.path("golden");
    fs::create_dir_all(&folder).unwrap();
    let err = tree.compare(&folder, b"x", false).unwrap_err();
    assert!(err.starts_with("golden unreadable: "), "{err}");
}

#[test]
fn update_writes_a_missing_golden_with_its_folders_and_a_changed_one() {
    let tree = Tree::new();
    let fresh = tree.path("envs/all-pass/golden/report.json");
    assert_eq!(tree.compare(&fresh, b"{}\n", true), Ok(Done::Written));
    assert_eq!(fs::read(&fresh).unwrap(), b"{}\n");

    let stale = tree.write("envs/all-pass/golden/terminal.txt", b"old\n");
    let sidecar = tree.write("envs/all-pass/golden/terminal.txt.actual", b"older\n");
    assert_eq!(tree.compare(&stale, b"new\n", true), Ok(Done::Written));
    assert_eq!(fs::read(&stale).unwrap(), b"new\n");
    assert!(
        !sidecar.exists(),
        "an accepted golden leaves no .actual file"
    );

    // A second update with the same bytes writes nothing and still passes.
    assert_eq!(tree.compare(&stale, b"new\n", true), Ok(Done::Matched));
}

/// Every file and folder below `dir`, as sorted `/`-separated text relative to `dir`.
fn listing(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(base).unwrap();
            out.push(rel.to_string_lossy().replace('\\', "/"));
            if path.is_dir() {
                walk(&path, base, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn update_never_touches_the_redaction_folder() {
    let tree = Tree::new();
    let expected = tree.write(
        "tests/fixtures/redaction/url/proxy.expected",
        b"http://~@h\n",
    );
    let redaction = tree.path("tests/fixtures/redaction");
    let before = listing(&redaction);
    let err = tree
        .compare(&expected, b"http://other\n", true)
        .unwrap_err();
    assert!(err.starts_with("golden differs: "), "{err}");
    assert!(
        err.contains("never writes under tests/fixtures/redaction"),
        "{err}"
    );
    assert!(
        !err.contains("cargo nextest"),
        "no accept command for a hand-edited file: {err}"
    );
    assert_eq!(fs::read(&expected).unwrap(), b"http://~@h\n");
    // The new bytes are parked under target, and nothing was created in the protected tree.
    assert!(err.contains("goldens-actual"), "{err}");
    let parked = listing(&tree.parked());
    assert!(
        parked
            .iter()
            .any(|p| p.ends_with("tests/fixtures/redaction/url/proxy.expected.actual")),
        "{parked:?}"
    );
    assert_eq!(listing(&redaction), before);

    // A missing file is not created either, and neither is its folder.
    let missing = tree.path("tests/fixtures/redaction/fresh/new.expected");
    let err = tree.compare(&missing, b"x\n", true).unwrap_err();
    assert!(err.starts_with("golden missing: "), "{err}");
    assert!(!missing.exists());
    assert_eq!(listing(&redaction), before);
    assert!(!redaction.join("fresh").exists());
}

#[test]
fn a_matching_protected_golden_clears_its_parked_output() {
    let tree = Tree::new();
    let expected = tree.write("tests/fixtures/redaction/url/proxy.expected", b"ok\n");
    tree.compare(&expected, b"bad\n", false).unwrap_err();
    assert!(!listing(&tree.parked()).is_empty());
    assert_eq!(tree.compare(&expected, b"ok\n", false), Ok(Done::Matched));
    assert!(
        listing(&tree.parked())
            .iter()
            .all(|p| !p.ends_with(".actual")),
        "{:?}",
        listing(&tree.parked())
    );
}

#[test]
fn update_never_touches_released_result_files() {
    let tree = Tree::new();
    let result = tree.write("tests/fixtures/results/0.1.0-alpha.1/ready.json", b"{}\n");
    let err = tree.compare(&result, b"{\"x\":1}\n", true).unwrap_err();
    assert!(
        err.contains("never writes under tests/fixtures/redaction or tests/fixtures/results"),
        "{err}"
    );
    assert_eq!(fs::read(&result).unwrap(), b"{}\n");
}

#[test]
fn a_protected_golden_that_matches_passes_under_update() {
    // `UPDATE_GOLDENS=1 cargo nextest run --workspace` must not fail the corpus when nothing changed.
    let tree = Tree::new();
    let expected = tree.write("tests/fixtures/redaction/url/proxy.expected", b"ok\n");
    assert_eq!(tree.compare(&expected, b"ok\n", true), Ok(Done::Matched));
}

#[test]
fn a_dotdot_path_into_the_redaction_folder_is_still_protected() {
    let tree = Tree::new();
    tree.write("tests/fixtures/redaction/url/proxy.expected", b"ok\n");
    let sneaky = tree.path("crates/x/../../tests/fixtures/redaction/url/proxy.expected");
    assert!(is_protected(&sneaky));
    let err = tree.compare(&sneaky, b"changed\n", true).unwrap_err();
    assert!(err.contains("never writes"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_symlink_into_the_redaction_folder_is_still_protected() {
    let tree = Tree::new();
    tree.write("tests/fixtures/redaction/url/proxy.expected", b"ok\n");
    std::os::unix::fs::symlink(tree.path("tests/fixtures/redaction"), tree.path("innocent"))
        .unwrap();
    let through_link = tree.path("innocent/url/proxy.expected");
    assert!(is_protected(&through_link));
    let err = tree.compare(&through_link, b"changed\n", true).unwrap_err();
    assert!(err.contains("never writes"), "{err}");
    assert_eq!(
        fs::read(tree.path("tests/fixtures/redaction/url/proxy.expected")).unwrap(),
        b"ok\n"
    );
    // A new file below the link is protected too, though it does not exist yet.
    assert!(is_protected(&tree.path("innocent/url/new.expected")));
}

#[cfg(unix)]
#[test]
fn dotdot_after_a_symlink_is_judged_after_the_link_is_followed() {
    let tree = Tree::new();
    tree.write("tests/fixtures/redaction/url/proxy.expected", b"ok\n");
    // `innocent/..` is `tests/fixtures/redaction`, though its text is the tree root.
    std::os::unix::fs::symlink(
        tree.path("tests/fixtures/redaction/url"),
        tree.path("innocent"),
    )
    .unwrap();
    let sneaky = tree.path("innocent/../new.expected");
    assert!(is_protected(&sneaky));
    let err = tree.compare(&sneaky, b"x\n", true).unwrap_err();
    assert!(err.contains("never writes"), "{err}");
    assert!(!tree.path("tests/fixtures/redaction/new.expected").exists());
}

#[cfg(unix)]
#[test]
fn update_refuses_to_write_through_a_symlink_even_a_dangling_one() {
    let tree = Tree::new();
    fs::create_dir_all(tree.path("golden")).unwrap();
    let target = tree.path("elsewhere/out.json");
    let link = tree.path("golden/report.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = tree.compare(&link, b"{}\n", true).unwrap_err();
    assert!(err.starts_with("golden is a symlink: "), "{err}");
    assert!(!target.exists(), "the write must not follow the link");
    assert!(!tree.path("elsewhere").exists());

    // A link to a real file is refused too, and the file keeps its bytes.
    let real = tree.write("real.json", b"old\n");
    let link2 = tree.path("golden/other.json");
    std::os::unix::fs::symlink(&real, &link2).unwrap();
    let err = tree.compare(&link2, b"new\n", true).unwrap_err();
    assert!(err.starts_with("golden is a symlink: "), "{err}");
    assert_eq!(fs::read(&real).unwrap(), b"old\n");
    // Comparing through the link still works when nothing is written.
    assert_eq!(tree.compare(&link2, b"old\n", true), Ok(Done::Matched));
}

#[test]
fn only_the_two_folders_below_tests_fixtures_are_protected() {
    let tree = Tree::new();
    for yes in [
        "tests/fixtures/redaction/a/b.expected",
        "tests/fixtures/results/0.1.0/r.json",
    ] {
        assert!(is_protected(&tree.path(yes)), "{yes}");
    }
    for no in [
        "tests/fixtures/envs/all-pass/golden/report.json",
        "tests/fixtures/checks/host.memory/pass/expect.json",
        "redaction/a.expected",
        "tests/redaction/a.expected",
        "tests/fixtures/redactions/a.expected",
    ] {
        assert!(!is_protected(&tree.path(no)), "{no}");
    }
}

// ---- the environment ------------------------------------------------------------------------

#[test]
fn update_golden_is_off_unless_it_is_one() {
    for pairs in [
        &[][..],
        &[("UPDATE_GOLDENS", "")],
        &[("UPDATE_GOLDENS", "0")],
        &[("CI", "true")],
    ] {
        assert_eq!(Mode::parse(env(pairs)), Ok(Mode { update: false }));
    }
    assert_eq!(
        Mode::parse(env(&[("UPDATE_GOLDENS", "1")])),
        Ok(Mode { update: true })
    );
}

#[test]
fn update_golden_is_refused_when_ci_is_set() {
    for ci in ["true", "1", "0", "false", "yes"] {
        let err = Mode::parse(|name| match name {
            "UPDATE_GOLDENS" => Some("1".to_string()),
            "CI" => Some(ci.to_string()),
            _ => None,
        })
        .unwrap_err();
        assert!(
            err.contains("UPDATE_GOLDENS=1 is refused when CI is set"),
            "{err}"
        );
    }
    // An empty CI (a shell that exported it blank) is not a pipeline.
    assert_eq!(
        Mode::parse(env(&[("UPDATE_GOLDENS", "1"), ("CI", "")])),
        Ok(Mode { update: true })
    );
}

#[test]
fn an_unknown_update_value_is_an_error_not_a_silent_pass() {
    for value in ["true", "yes", "2", "on", " 1"] {
        let err =
            Mode::parse(|name| (name == "UPDATE_GOLDENS").then(|| value.to_string())).unwrap_err();
        assert!(err.contains("Set it to 1"), "{value}: {err}");
    }
}

// ---- the used record ------------------------------------------------------------------------

#[test]
fn a_path_inside_the_repo_is_shown_and_recorded_relative_to_it() {
    let inside = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/envs/all-pass/golden/report.json");
    assert_eq!(
        shown(&inside),
        "tests/fixtures/envs/all-pass/golden/report.json"
    );

    let tree = Tree::new();
    let outside = tree.path("a/b.txt");
    let text = shown(&outside);
    assert!(text.ends_with("/a/b.txt"), "{text}");
    assert!(
        !text.contains('\\') && !text.contains("/./") && !text.contains(".."),
        "{text}"
    );
}

#[test]
fn every_path_is_appended_to_the_pid_file_once_per_call() {
    let tree = Tree::new();
    let used = tree.path("goldens-used");
    let inside = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/x/golden/a.json");
    record_used(&used, &inside).unwrap();
    record_used(&used, &inside).unwrap();
    record_used(&used, &tree.path("other.txt")).unwrap();
    let file = used.join(format!("{}.txt", std::process::id()));
    let lines: Vec<String> = fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "tests/fixtures/x/golden/a.json");
    assert_eq!(lines[1], lines[0]);
    assert!(lines[2].ends_with("/other.txt"), "{lines:?}");
}

#[test]
fn the_used_folder_is_in_the_target_folder() {
    let used = used_dir();
    assert!(used.ends_with("goldens-used"), "{}", used.display());
}

#[test]
fn lexical_resolves_dots_and_separators() {
    assert_eq!(lexical("/a/b/../c/./d"), "/a/c/d");
    assert_eq!(lexical("C:\\a\\b\\..\\c"), "C:/a/c");
    assert_eq!(lexical("/a//b/"), "/a/b");
    assert_eq!(lexical("/../a"), "/a");
}

// ---- the diff -------------------------------------------------------------------------------

#[test]
fn the_diff_has_three_lines_of_context_and_splits_distant_changes() {
    let old: String = (1..=20).map(|n| format!("line {n}\n")).collect();
    let new = old
        .replace("line 2\n", "two\n")
        .replace("line 19\n", "nineteen\n");
    let diff = unified_diff(&old, &new);
    assert_eq!(
        diff,
        "--- golden\n+++ output\n\
         @@ -1,5 +1,5 @@\n line 1\n-line 2\n+two\n line 3\n line 4\n line 5\n\
         @@ -16,5 +16,5 @@\n line 16\n line 17\n line 18\n-line 19\n+nineteen\n line 20\n"
    );
}

#[test]
fn nearby_changes_share_one_hunk() {
    let diff = unified_diff("a\nb\nc\nd\ne\nf\ng\n", "a\nB\nc\nd\ne\nF\ng\n");
    assert_eq!(diff.matches("@@").count(), 2, "{diff}");
    assert!(diff.contains("@@ -1,7 +1,7 @@"), "{diff}");
}

#[test]
fn an_added_and_a_removed_line_are_shown() {
    assert_eq!(
        unified_diff("a\nc\n", "a\nb\nc\n"),
        "--- golden\n+++ output\n@@ -1,2 +1,3 @@\n a\n+b\n c\n"
    );
    assert_eq!(
        unified_diff("a\nb\nc\n", "a\nc\n"),
        "--- golden\n+++ output\n@@ -1,3 +1,2 @@\n a\n-b\n c\n"
    );
}

#[test]
fn a_missing_final_newline_and_a_carriage_return_are_visible() {
    let diff = unified_diff("a\nb\n", "a\nb");
    assert!(
        diff.contains("-b\n+b\n\\ No newline at end of file\n"),
        "{diff}"
    );
    let crlf = unified_diff("a\nb\n", "a\r\nb\n");
    assert!(crlf.contains("-a\n+a\\r\n"), "{crlf}");
}

#[test]
fn the_failure_message_carries_the_first_forty_diff_lines() {
    let old: String = (0..100).map(|n| format!("old {n}\n")).collect();
    let new: String = (0..100).map(|n| format!("new {n}\n")).collect();
    let head = diff_head(old.as_bytes(), new.as_bytes());
    let lines: Vec<&str> = head.lines().collect();
    assert_eq!(lines.len(), 41, "{head}");
    assert_eq!(lines[0], "--- golden");
    assert!(lines[40].starts_with("... "), "{}", lines[40]);
    assert!(lines[40].ends_with("more diff lines"), "{}", lines[40]);
    // A short diff is shown whole, with no trailing marker.
    let short = diff_head(b"a\n", b"b\n");
    assert_eq!(short, "--- golden\n+++ output\n@@ -1,1 +1,1 @@\n-a\n+b");
}

#[test]
fn files_that_are_not_text_report_the_first_differing_byte() {
    let head = diff_head(&[1, 2, 3, 0xff], &[1, 2, 9, 0xff, 7]);
    assert!(head.contains("not both UTF-8 text"), "{head}");
    assert!(
        head.contains("Golden: 4 bytes. Output: 5 bytes. First difference at byte 2."),
        "{head}"
    );
}

#[test]
fn a_huge_diff_falls_back_to_one_block_and_stays_fast() {
    // 3000 x 3000 middle lines is past MAX_CELLS. Every line differs, so there is no common prefix.
    let old: String = (0..3000).map(|n| format!("a{n}\n")).collect();
    let new: String = (0..3000).map(|n| format!("b{n}\n")).collect();
    let diff = unified_diff(&old, &new);
    assert!(diff.contains("@@ -1,3000 +1,3000 @@"), "{}", &diff[..80]);
    assert_eq!(diff.lines().filter(|l| l.starts_with('-')).count(), 3001); // 3000 lines and `---`.
}

#[test]
fn a_one_line_change_in_a_large_file_is_found_without_the_table() {
    // The common prefix and suffix are peeled off, so a 20,000-line report diffs in one line.
    let old: String = (0..20_000).map(|n| format!("row {n}\n")).collect();
    let new = old.replace("row 10000\n", "row ten thousand\n");
    let diff = unified_diff(&old, &new);
    assert!(diff.contains("-row 10000\n+row ten thousand\n"), "{diff}");
    assert_eq!(diff.matches("@@").count(), 2);
}
