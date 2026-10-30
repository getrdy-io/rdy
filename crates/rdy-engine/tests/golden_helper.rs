//! `assert_golden` end to end, with its real environment (M1-052). A test cannot set a variable of its own
//! process (`forbid(unsafe_code)`), so each case runs this test binary again as a child with the variables
//! it needs. The child is the ignored test `child`, which does nothing unless `GOLDEN_CASE_PATH` is set.
//! `CARGO_TARGET_DIR` points at a temporary folder, so the record of used goldens stays out of `target/`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use rdy_engine::testing::golden::assert_golden;

/// The child. Run by `case` below, never by itself.
#[test]
#[ignore = "run by the cases in this file as a child process"]
fn child() {
    let Some(path) = std::env::var_os("GOLDEN_CASE_PATH") else {
        return;
    };
    let bytes = std::env::var("GOLDEN_CASE_BYTES").unwrap_or_default();
    assert_golden(Path::new(&path), bytes.as_bytes());
}

struct Case<'a> {
    golden: &'a Path,
    bytes: &'a str,
    update: Option<&'a str>,
    ci: Option<&'a str>,
    target: &'a Path,
}

fn case(case: &Case<'_>) -> std::io::Result<Output> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(["--ignored", "--exact", "child", "--nocapture"])
        .env("GOLDEN_CASE_PATH", case.golden)
        .env("GOLDEN_CASE_BYTES", case.bytes)
        .env("CARGO_TARGET_DIR", case.target)
        .env_remove("UPDATE_GOLDENS")
        .env_remove("CI");
    if let Some(value) = case.update {
        cmd.env("UPDATE_GOLDENS", value);
    }
    if let Some(value) = case.ci {
        cmd.env("CI", value);
    }
    cmd.output()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A golden file in a temporary folder, and the temporary target folder.
fn setup(
    golden: &str,
    bytes: Option<&str>,
) -> std::io::Result<(tempfile::TempDir, std::path::PathBuf)> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(golden);
    if let Some(bytes) = bytes {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)?;
    }
    Ok((dir, path))
}

#[test]
fn equal_output_passes_and_the_path_is_recorded() {
    let (dir, golden) = setup("golden/report.json", Some("{}\n")).unwrap();
    let target = dir.path().join("target");
    let out = case(&Case {
        golden: &golden,
        bytes: "{}\n",
        update: None,
        ci: Some("true"),
        target: &target,
    })
    .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));

    let used = target.join("goldens-used");
    let files: Vec<_> = fs::read_dir(&used)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1, "one file per process: {files:?}");
    let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.ends_with(".txt") && name[..name.len() - 4].chars().all(|c| c.is_ascii_digit()),
        "{name}"
    );
    let text = fs::read_to_string(&files[0]).unwrap();
    assert!(text.trim_end().ends_with("/golden/report.json"), "{text}");
}

#[test]
fn changed_output_fails_with_a_diff_and_an_actual_file() {
    let (dir, golden) = setup("golden/terminal.txt", Some("ready\n")).unwrap();
    let target = dir.path().join("target");
    let out = case(&Case {
        golden: &golden,
        bytes: "blocked\n",
        update: None,
        ci: None,
        target: &target,
    })
    .unwrap();
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("golden differs"), "{err}");
    assert!(err.contains("-ready\n+blocked"), "{err}");
    assert!(
        err.contains("UPDATE_GOLDENS=1 cargo nextest run -p rdy-engine"),
        "{err}"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("golden/terminal.txt.actual")).unwrap(),
        "blocked\n"
    );
    assert_eq!(fs::read_to_string(&golden).unwrap(), "ready\n");
    // The path is recorded even though the test failed.
    assert!(target.join("goldens-used").is_dir());
}

#[test]
fn a_missing_golden_fails() {
    let (dir, golden) = setup("golden/report.html", None).unwrap();
    let target = dir.path().join("target");
    let out = case(&Case {
        golden: &golden,
        bytes: "<html>",
        update: None,
        ci: None,
        target: &target,
    })
    .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("golden missing"), "{}", stderr(&out));
    assert!(!golden.exists());
}

#[test]
fn update_goldens_writes_the_golden_and_passes() {
    let (dir, golden) = setup("envs/all-pass/golden/report.json", None).unwrap();
    let target = dir.path().join("target");
    let out = case(&Case {
        golden: &golden,
        bytes: "{\"v\":1}\n",
        update: Some("1"),
        ci: None,
        target: &target,
    })
    .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("golden written: "),
        "each written file is listed: {}",
        stderr(&out)
    );
    assert_eq!(fs::read_to_string(&golden).unwrap(), "{\"v\":1}\n");
}

#[test]
fn update_goldens_is_refused_when_ci_is_set_even_for_an_equal_golden() {
    let (dir, golden) = setup("golden/report.json", Some("same\n")).unwrap();
    let target = dir.path().join("target");
    for ci in ["true", "1"] {
        let out = case(&Case {
            golden: &golden,
            bytes: "same\n",
            update: Some("1"),
            ci: Some(ci),
            target: &target,
        })
        .unwrap();
        assert!(!out.status.success(), "CI={ci}");
        assert!(
            stderr(&out).contains("UPDATE_GOLDENS=1 is refused when CI is set"),
            "{}",
            stderr(&out)
        );
    }
    // And a changed output is not written.
    let out = case(&Case {
        golden: &golden,
        bytes: "other\n",
        update: Some("1"),
        ci: Some("true"),
        target: &target,
    })
    .unwrap();
    assert!(!out.status.success());
    assert_eq!(fs::read_to_string(&golden).unwrap(), "same\n");
}

#[test]
fn update_goldens_never_writes_under_the_redaction_folder() {
    let (dir, golden) = setup(
        "tests/fixtures/redaction/url/proxy.expected",
        Some("kept\n"),
    )
    .unwrap();
    let target = dir.path().join("target");
    let out = case(&Case {
        golden: &golden,
        bytes: "changed\n",
        update: Some("1"),
        ci: None,
        target: &target,
    })
    .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("never writes under tests/fixtures/redaction"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fs::read_to_string(&golden).unwrap(), "kept\n");
}

#[test]
fn a_typo_in_update_goldens_fails_the_test() {
    let (dir, golden) = setup("golden/report.json", Some("same\n")).unwrap();
    let target = dir.path().join("target");
    let out = case(&Case {
        golden: &golden,
        bytes: "same\n",
        update: Some("true"),
        ci: None,
        target: &target,
    })
    .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Set it to 1"), "{}", stderr(&out));
}
