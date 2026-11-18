//! The HTML page in the report folder (M1-181): its bytes are `render_html` of the report, its
//! `data-sha256` is the SHA-256 of the `.json` file, it is private from creation, no temp file is left,
//! and a file under the final name is never replaced.

use std::error::Error;
use std::fmt::Write as _;
use std::path::Path;

use rdy_engine::output::{OutputDir, ReportError};
use rdy_engine::redact::{RedactedReport, Redactor, TagKey};
use rdy_engine::report::{render_html, render_page};
use rdy_spec::result::Report;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn sample() -> TestResult<RedactedReport> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/reports/not-ready-7.2.json");
    let report: Report = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    Ok(Redactor::new(TagKey::fixed([5; 32])).redact_report(report)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn names(dir: &Path) -> TestResult<Vec<String>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        found.push(entry?.file_name().to_string_lossy().into_owned());
    }
    found.sort();
    Ok(found)
}

#[test]
fn the_file_is_render_html_and_hashes_the_json_file() -> TestResult {
    let report = sample()?;
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let page = render_page(&report)?;
    let html_path = out.write_html(&page)?.path().to_path_buf();
    let json_path = out.write_json(&report)?;
    assert!(html_path.ends_with("rdy-report-acme-platform-20270309T143005Z.html"));

    let html = std::fs::read(&html_path)?;
    assert_eq!(html, render_html(&report)?.into_bytes());
    let json = std::fs::read(&json_path)?;
    let text = String::from_utf8(html)?;
    assert!(text.contains(&format!("data-sha256=\"{}\"", sha256_hex(&json))));
    // The folder holds the two files and no temp file.
    assert_eq!(
        names(out.path())?,
        [
            "rdy-report-acme-platform-20270309T143005Z.html",
            "rdy-report-acme-platform-20270309T143005Z.json"
        ]
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn the_file_is_0600() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let report = sample()?;
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let path = out.write_html(&render_page(&report)?)?.path().to_path_buf();
    assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}

#[test]
fn a_page_is_never_written_over_a_file_that_is_there() -> TestResult {
    let report = sample()?;
    let page = render_page(&report)?;
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let path = out.write_html(&page)?.path().to_path_buf();
    let before = std::fs::read(&path)?;
    let again = out.write_html(&page);
    assert!(
        matches!(again, Err(ReportError::FileExists { .. })),
        "{again:?}"
    );
    assert_eq!(std::fs::read(&path)?, before);
    // The failed write left no `.tmp`.
    assert_eq!(names(out.path())?.len(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn remove_html_takes_back_its_own_file_and_leaves_a_swapped_one() -> TestResult {
    let report = sample()?;
    let page = render_page(&report)?;

    // Its own file goes.
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let written = out.write_html(&page)?;
    out.remove_html(&written);
    assert!(!written.path().exists());

    // A file put under the name after the write stays. The planted file is made first, so it has its own
    // inode even when the file system reuses the numbers of removed files.
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let written = out.write_html(&page)?;
    let planted = out.path().join("planted");
    std::fs::write(&planted, b"planted")?;
    std::fs::rename(&planted, written.path())?;
    out.remove_html(&written);
    assert_eq!(std::fs::read(written.path())?, b"planted");

    // So does a symlink.
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let written = out.write_html(&page)?;
    std::fs::remove_file(written.path())?;
    std::os::unix::fs::symlink("elsewhere", written.path())?;
    out.remove_html(&written);
    assert!(std::fs::symlink_metadata(written.path()).is_ok());
    Ok(())
}
