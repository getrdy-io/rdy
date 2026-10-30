//! Runs the `xtask` binary against temporary repos. Each test has its own repo, so the tests do
//! not touch the real tree. The planted banned token is synthetic and is built from two pieces.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};

/// The synthetic banned token. Built from two pieces so this file never holds it whole.
const BANNED: &str = concat!("banned", "token");

/// A temporary git repo. The directory goes away when the value drops.
struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        git(dir.path(), &["init", "-q"])?;
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, relative: &str, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
        let target = self.path().join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, contents)?;
        Ok(target)
    }

    /// Stages every file, so `git ls-files` lists it.
    fn track_all(&self) -> Result<()> {
        git(self.path(), &["add", "-A"])
    }
}

fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .context("cannot run git")?;
    if !status.success() {
        bail!("git {args:?} failed in {}", dir.display());
    }
    Ok(())
}

/// Runs `xtask --root <root> <args>`.
fn xtask(root: &Path, args: &[&str]) -> Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .context("cannot run the xtask binary")
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const DOCS_PAGE: &str = "docs/src/content/docs/reference/spec/index.md";
const RESULT_PAGE: &str = "docs/src/content/docs/reference/result/index.md";
const SPEC_INTRO: &str = "docs/intro/reference-spec.md";
const RESULT_INTRO: &str = "docs/intro/reference-result.md";

/// The committed text of a file in this repo, read at test time.
fn committed(relative: &str) -> Result<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    Ok(fs::read_to_string(root.join(relative))?)
}

/// A temporary repo with the schema files written, as `cargo xtask schema` leaves them, and the two
/// hand-written intros copied in. The docs pages render from those files, so every docs test starts here.
fn repo_with_schema() -> Result<Repo> {
    let repo = Repo::new()?;
    let out = xtask(repo.path(), &["schema"])?;
    if code(&out) != Some(0) {
        bail!("xtask schema failed: {}", stderr(&out));
    }
    repo.write(SPEC_INTRO, committed(SPEC_INTRO)?)?;
    repo.write(RESULT_INTRO, committed(RESULT_INTRO)?)?;
    Ok(repo)
}

#[test]
fn docs_writes_the_spec_and_result_reference_pages() -> Result<()> {
    let repo = repo_with_schema()?;
    assert_eq!(code(&xtask(repo.path(), &["docs"])?), Some(0));
    assert!(repo.path().join(DOCS_PAGE).is_file());
    let result = repo.path().join(RESULT_PAGE);
    assert!(result.is_file());
    assert!(fs::read_to_string(&result)?.contains("Always `Report`."));
    Ok(())
}

#[test]
fn docs_exits_70_and_names_the_intro_file_when_it_is_missing() -> Result<()> {
    let repo = repo_with_schema()?;
    fs::remove_file(repo.path().join(RESULT_INTRO))?;
    let out = xtask(repo.path(), &["docs"])?;
    assert_eq!(code(&out), Some(70), "{}", stderr(&out));
    assert!(stderr(&out).contains(RESULT_INTRO), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("hand-written intro"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn docs_refuses_to_render_without_the_schema_and_names_the_fix() -> Result<()> {
    let repo = Repo::new()?;
    let docs = xtask(repo.path(), &["docs"])?;
    assert_eq!(code(&docs), Some(70), "{}", stderr(&docs));
    assert!(
        stderr(&docs).contains("cargo xtask schema"),
        "{}",
        stderr(&docs)
    );
    Ok(())
}

#[test]
fn docs_check_passes_on_a_clean_tree() -> Result<()> {
    let repo = repo_with_schema()?;
    assert_eq!(code(&xtask(repo.path(), &["docs"])?), Some(0));
    let check = xtask(repo.path(), &["docs", "--check"])?;
    assert_eq!(code(&check), Some(0), "{}", stderr(&check));
    Ok(())
}

#[test]
fn docs_check_exits_one_after_a_hand_edit_and_zero_on_a_clean_tree() -> Result<()> {
    let repo = repo_with_schema()?;
    assert_eq!(code(&xtask(repo.path(), &["docs"])?), Some(0));
    assert_eq!(code(&xtask(repo.path(), &["docs", "--check"])?), Some(0));

    let page = repo.path().join(DOCS_PAGE);
    let mut edited = fs::read_to_string(&page)?;
    edited.push_str("A hand edit.\n");
    fs::write(&page, edited)?;

    let stale = xtask(repo.path(), &["docs", "--check"])?;
    assert_eq!(code(&stale), Some(1), "{}", stderr(&stale));
    assert!(stderr(&stale).contains(DOCS_PAGE), "{}", stderr(&stale));
    assert!(stderr(&stale).contains("Do not edit"), "{}", stderr(&stale));

    // Regenerating restores a clean tree.
    assert_eq!(code(&xtask(repo.path(), &["docs"])?), Some(0));
    assert_eq!(code(&xtask(repo.path(), &["docs", "--check"])?), Some(0));
    Ok(())
}

#[test]
fn docs_check_fails_when_a_generated_page_is_missing() -> Result<()> {
    let repo = repo_with_schema()?;
    assert_eq!(code(&xtask(repo.path(), &["docs"])?), Some(0));
    fs::remove_file(repo.path().join(DOCS_PAGE))?;
    let check = xtask(repo.path(), &["docs", "--check"])?;
    assert_eq!(code(&check), Some(1), "{}", stderr(&check));
    assert!(stderr(&check).contains("missing"), "{}", stderr(&check));
    Ok(())
}

#[test]
fn docs_check_passes_on_a_crlf_checkout() -> Result<()> {
    let repo = repo_with_schema()?;
    assert_eq!(code(&xtask(repo.path(), &["docs"])?), Some(0));
    let page = repo.path().join(DOCS_PAGE);
    let lf = fs::read_to_string(&page)?;
    fs::write(&page, lf.replace('\n', "\r\n"))?;
    let check = xtask(repo.path(), &["docs", "--check"])?;
    assert_eq!(code(&check), Some(0), "{}", stderr(&check));
    Ok(())
}

const SPEC_SCHEMA: &str = "crates/rdy-spec/schema/spec.v1.schema.json";
const RESULT_SCHEMA: &str = "crates/rdy-spec/schema/result.v1.schema.json";

#[test]
fn schema_writes_both_files_and_check_passes_on_them() -> Result<()> {
    let repo = Repo::new()?;
    assert_eq!(code(&xtask(repo.path(), &["schema"])?), Some(0));
    for file in [SPEC_SCHEMA, RESULT_SCHEMA] {
        let text = fs::read_to_string(repo.path().join(file))?;
        assert!(text.starts_with("{\n  \"$schema\""), "{file}");
        assert!(text.ends_with("}\n"), "{file}");
    }
    let check = xtask(repo.path(), &["schema", "--check"])?;
    assert_eq!(code(&check), Some(0), "{}", stderr(&check));
    Ok(())
}

#[test]
fn schema_check_fails_on_a_missing_file_and_names_the_fix() -> Result<()> {
    let repo = Repo::new()?;
    let check = xtask(repo.path(), &["schema", "--check"])?;
    assert_eq!(code(&check), Some(1), "{}", stderr(&check));
    assert!(stderr(&check).contains(SPEC_SCHEMA), "{}", stderr(&check));
    assert!(
        stderr(&check).contains("cargo xtask schema"),
        "{}",
        stderr(&check)
    );
    Ok(())
}

#[test]
fn schema_check_fails_on_a_stale_file_and_a_rewrite_fixes_it() -> Result<()> {
    let repo = Repo::new()?;
    assert_eq!(code(&xtask(repo.path(), &["schema"])?), Some(0));
    // A hand edit stands in for a type or doc comment change that was not regenerated.
    let target = repo.path().join(RESULT_SCHEMA);
    let text = fs::read_to_string(&target)?;
    fs::write(&target, text.replacen("One side effect", "One effect", 1))?;
    let check = xtask(repo.path(), &["schema", "--check"])?;
    assert_eq!(code(&check), Some(1), "{}", stderr(&check));
    assert!(stderr(&check).contains(RESULT_SCHEMA), "{}", stderr(&check));
    assert_eq!(code(&xtask(repo.path(), &["schema"])?), Some(0));
    assert_eq!(code(&xtask(repo.path(), &["schema", "--check"])?), Some(0));
    Ok(())
}

#[test]
fn docs_lint_passes_on_a_clean_tree() -> Result<()> {
    let repo = Repo::new()?;
    repo.write("docs/install.md", "Install the binary.\nRun it.\n")?;
    repo.track_all()?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(0), "{}", stderr(&lint));
    Ok(())
}

#[test]
fn docs_lint_fails_on_a_planted_em_dash() -> Result<()> {
    let repo = Repo::new()?;
    repo.write(
        "docs/install.md",
        "First line.\nInstall \u{2014} then run.\n",
    )?;
    repo.track_all()?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(1), "{}", stderr(&lint));
    assert!(
        stderr(&lint).contains("docs/install.md:2"),
        "{}",
        stderr(&lint)
    );
    assert!(stderr(&lint).contains("em dash"), "{}", stderr(&lint));
    Ok(())
}

#[test]
fn docs_lint_fails_on_a_planted_en_dash() -> Result<()> {
    let repo = Repo::new()?;
    repo.write("docs/install.md", "Versions 1\u{2013}2.\n")?;
    repo.track_all()?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(1), "{}", stderr(&lint));
    assert!(stderr(&lint).contains("en dash"), "{}", stderr(&lint));
    Ok(())
}

#[test]
fn docs_lint_fails_on_a_planted_banned_token_hash_match() -> Result<()> {
    let repo = Repo::new()?;
    repo.write(
        "docs/install.md",
        format!("First line.\nUse {BANNED} here.\n"),
    )?;
    repo.track_all()?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(1), "{}", stderr(&lint));
    assert!(
        stderr(&lint).contains("docs/install.md:2"),
        "{}",
        stderr(&lint)
    );
    assert!(stderr(&lint).contains("banned token"), "{}", stderr(&lint));
    // The lint holds hashes only, so its output never repeats the word.
    assert!(
        !stderr(&lint).to_lowercase().contains(BANNED),
        "{}",
        stderr(&lint)
    );
    Ok(())
}

#[test]
fn docs_lint_checks_a_latin1_file_for_an_em_dash() -> Result<()> {
    let repo = Repo::new()?;
    // 0xE9 is Latin-1 and not valid UTF-8. The em dash after it must still be found.
    repo.write("docs/legacy.txt", b"Caf\xe9 \xe2\x80\x94 open\n")?;
    repo.track_all()?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(1), "{}", stderr(&lint));
    assert!(
        stderr(&lint).contains("docs/legacy.txt:1"),
        "{}",
        stderr(&lint)
    );
    assert!(stderr(&lint).contains("em dash"), "{}", stderr(&lint));
    Ok(())
}

#[test]
fn docs_lint_ignores_untracked_files() -> Result<()> {
    let repo = Repo::new()?;
    repo.write("docs/notes.md", "Install \u{2014} then run.\n")?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(0), "{}", stderr(&lint));
    Ok(())
}

#[test]
fn docs_lint_skips_binary_files() -> Result<()> {
    let repo = Repo::new()?;
    repo.write("docs/image.bin", b"\0\0 \xe2\x80\x94 \0")?;
    repo.track_all()?;
    let lint = xtask(repo.path(), &["docs-lint"])?;
    assert_eq!(code(&lint), Some(0), "{}", stderr(&lint));
    Ok(())
}

#[test]
fn dist_is_off_and_refuses_with_a_message() -> Result<()> {
    let repo = Repo::new()?;
    let dist = xtask(repo.path(), &["dist"])?;
    assert_eq!(code(&dist), Some(64));
    assert!(
        stderr(&dist).contains("off in this build"),
        "{}",
        stderr(&dist)
    );
    assert!(stderr(&dist).contains("M1-007"), "{}", stderr(&dist));
    Ok(())
}

#[test]
fn publish_is_off_and_refuses_with_a_message() -> Result<()> {
    let repo = Repo::new()?;
    let publish = xtask(repo.path(), &["publish"])?;
    assert_eq!(code(&publish), Some(64));
    assert!(
        stderr(&publish).contains("off in this build"),
        "{}",
        stderr(&publish)
    );
    assert!(stderr(&publish).contains("M2-015"), "{}", stderr(&publish));
    Ok(())
}

#[test]
fn unknown_command_is_a_usage_error() -> Result<()> {
    let repo = Repo::new()?;
    assert_eq!(code(&xtask(repo.path(), &["nope"])?), Some(64));
    Ok(())
}

#[test]
fn help_exits_zero() -> Result<()> {
    let repo = Repo::new()?;
    assert_eq!(code(&xtask(repo.path(), &["--help"])?), Some(0));
    Ok(())
}

/// The empty-remediation failure is a unit test in `src/checks.rs`: the registry is compiled in, so
/// only a fake registry can plant one.
#[test]
fn checks_lists_each_registered_check_with_id_family_title_and_remediation() -> Result<()> {
    let repo = Repo::new()?;
    let listed = xtask(repo.path(), &["checks"])?;
    assert_eq!(code(&listed), Some(0), "{}", stderr(&listed));
    let stdout = String::from_utf8(listed.stdout)?;
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("id\tfamily\ttitle\tremediation"));
    let rows: Vec<Vec<&str>> = lines.map(|line| line.split('\t').collect()).collect();
    assert!(
        rows.iter().any(|row| row.first() == Some(&"host.disk")),
        "{stdout}"
    );
    for row in &rows {
        assert_eq!(row.len(), 4, "{row:?}");
        assert!(row.iter().all(|field| !field.is_empty()), "{row:?}");
        assert!(row[0].starts_with(&format!("{}.", row[1])), "{row:?}");
    }
    Ok(())
}

#[test]
fn docs_exits_70_and_names_the_path_of_a_property_without_a_description() -> Result<()> {
    // The exit test of docs/plan/09-docs-site.md, section 5: a property with no description fails the
    // docs build with its path. The repo has the schema the types write, and one description is removed.
    let repo = repo_with_schema()?;
    let schema_path = repo
        .path()
        .join("crates/rdy-spec/schema/spec.v1.schema.json");
    let mut schema: serde_json::Value = serde_json::from_str(&fs::read_to_string(&schema_path)?)?;
    let arch = schema["$defs"]["HostCpuParams"]["properties"]["arch"]
        .as_object_mut()
        .context("the host.cpu arch property is missing from the schema")?;
    arch.remove("description")
        .context("the host.cpu arch property has no description to remove")?;
    fs::write(&schema_path, serde_json::to_string_pretty(&schema)?)?;

    let out = xtask(repo.path(), &["docs", "--check"])?;
    assert_eq!(code(&out), Some(70), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("checks[id=host.cpu].arch has no description"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

// ---- goldens check ----------------------------------------------------------------------------

const GOLDEN_JSON: &str = "tests/fixtures/envs/all-pass/golden/report.json";
const GOLDEN_TEXT: &str = "tests/fixtures/envs/all-pass/golden/terminal.txt";
const GOLDEN_EXPECT: &str = "tests/fixtures/checks/host.memory/pass/expect.json";
const GOLDEN_REDACTED: &str = "tests/fixtures/redaction/url/proxy.expected";

/// Writes a record the way `assert_golden` does: one repo-relative path per line in `<pid>.txt`.
fn record(repo: &Repo, pid: u32, lines: &[&str]) -> Result<()> {
    repo.write(
        &format!("used/{pid}.txt"),
        lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
    )?;
    Ok(())
}

fn goldens_check(repo: &Repo) -> Result<Output> {
    let used = repo.path().join("used");
    xtask(
        repo.path(),
        &["goldens", "check", "--used-dir", &used.to_string_lossy()],
    )
}

#[test]
fn goldens_check_fails_on_an_orphan_and_names_it() -> Result<()> {
    let repo = Repo::new()?;
    repo.write(GOLDEN_JSON, "{}\n")?;
    repo.write(GOLDEN_TEXT, "ready\n")?;
    record(&repo, 100, &[GOLDEN_JSON])?;
    let out = goldens_check(&repo)?;
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!("goldens: orphan {GOLDEN_TEXT}")),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains(&format!("orphan {GOLDEN_JSON}")));
    Ok(())
}

#[test]
fn goldens_check_passes_when_every_golden_is_used_across_records() -> Result<()> {
    let repo = Repo::new()?;
    for path in [GOLDEN_JSON, GOLDEN_TEXT, GOLDEN_EXPECT, GOLDEN_REDACTED] {
        repo.write(path, "x\n")?;
    }
    record(&repo, 1, &[GOLDEN_JSON, GOLDEN_TEXT])?;
    // The tests of one package run in several processes, so the used paths are split across files.
    record(
        &repo,
        2,
        &[GOLDEN_EXPECT, "/tmp/.tmpAbC/golden/a.json", GOLDEN_JSON],
    )?;
    record(&repo, 3, &[GOLDEN_REDACTED])?;
    let out = goldens_check(&repo)?;
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("4 golden file(s) on disk, none orphaned"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn goldens_check_asks_for_a_test_run_when_nothing_was_recorded() -> Result<()> {
    let repo = Repo::new()?;
    repo.write(GOLDEN_JSON, "{}\n")?;
    let out = goldens_check(&repo)?;
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Run the tests first"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn goldens_check_passes_with_no_goldens_and_no_records() -> Result<()> {
    let repo = Repo::new()?;
    let out = goldens_check(&repo)?;
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    Ok(())
}

#[test]
fn goldens_check_ignores_inputs_sidecars_and_released_results() -> Result<()> {
    let repo = Repo::new()?;
    for path in [
        "tests/fixtures/envs/all-pass/golden/report.json.actual",
        "tests/fixtures/envs/all-pass/spec.yaml",
        "tests/fixtures/checks/host.memory/pass/root/proc/meminfo",
        "tests/fixtures/redaction/url/proxy.in",
        "tests/fixtures/results/0.1.0-alpha.1/ready.json",
        "crates/x/golden/report.json",
    ] {
        repo.write(path, "x\n")?;
    }
    let out = goldens_check(&repo)?;
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    Ok(())
}

#[test]
fn goldens_check_reads_target_goldens_used_by_default() -> Result<()> {
    let repo = Repo::new()?;
    repo.write(GOLDEN_JSON, "{}\n")?;
    repo.write("target/goldens-used/7.txt", format!("{GOLDEN_JSON}\n"))?;
    let run = |target: Option<&str>| -> Result<Output> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xtask"));
        cmd.arg("--root")
            .arg(repo.path())
            .args(["goldens", "check"])
            .env_remove("CARGO_TARGET_DIR");
        if let Some(target) = target {
            cmd.env("CARGO_TARGET_DIR", target);
        }
        Ok(cmd.output()?)
    };
    let out = run(None)?;
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    // A relative CARGO_TARGET_DIR is taken from the repo root, where the record is not.
    let out = run(Some("elsewhere"))?;
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    repo.write("elsewhere/goldens-used/7.txt", format!("{GOLDEN_JSON}\n"))?;
    let out = run(Some("elsewhere"))?;
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    Ok(())
}

#[test]
fn goldens_without_an_action_is_a_usage_error() -> Result<()> {
    let repo = Repo::new()?;
    let out = xtask(repo.path(), &["goldens"])?;
    assert_eq!(code(&out), Some(64), "{}", stderr(&out));
    Ok(())
}
