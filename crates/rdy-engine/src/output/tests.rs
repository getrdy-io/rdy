//! Tests for the output directory. The Unix mode tests are `cfg(unix)`; the name and no-overwrite
//! tests run everywhere.

use std::fs;
use std::path::Path;

use super::*;
use crate::redact::{Redactor, TagKey};

const TS: &str = "20270309T143005Z";

fn redacted(text: &str) -> Redacted<String> {
    let key = TagKey::generate().expect("random key");
    Redactor::new(key).redact_str(text)
}

fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

#[test]
fn a_product_that_is_not_a_slug_fails_validation_and_creates_nothing() {
    let parent = tempfile::tempdir().expect("temp dir");
    let long = "a".repeat(64);
    for bad in [
        "../x",
        "..",
        "a/b",
        "a\\b",
        "/etc/cron.d/x",
        "Acme",
        "-acme",
        "ac me",
        "acme\0",
        "",
        long.as_str(),
    ] {
        let err = OutputDir::create_new(parent.path(), bad, TS).expect_err(bad);
        assert!(matches!(err, ReportError::BadProduct), "{bad:?}: {err}");
    }
    assert!(names(parent.path()).is_empty());
}

#[test]
fn a_timestamp_that_is_not_the_exact_form_fails() {
    let parent = tempfile::tempdir().expect("temp dir");
    for bad in [
        "",
        "../x",
        "2027-03-09T14:30:05Z",
        "20270309T143005",
        "20270309T143005Zx",
        "2027030AT143005Z",
        "20270309t143005Z",
    ] {
        let err = OutputDir::create_new(parent.path(), "acme", bad).expect_err(bad);
        assert!(matches!(err, ReportError::BadTimestamp), "{bad:?}: {err}");
    }
    assert!(names(parent.path()).is_empty());
}

#[test]
fn the_folder_is_named_for_the_product_and_time() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme-platform", TS).expect("create");
    assert_eq!(out.name(), "rdy-report-acme-platform-20270309T143005Z");
    assert_eq!(out.path(), parent.path().join(out.name()));
    assert_eq!(
        out.report_file_name("json"),
        "rdy-report-acme-platform-20270309T143005Z.json"
    );
    assert_eq!(names(parent.path()), [out.name()]);
}

#[test]
fn a_missing_parent_is_an_io_error_and_is_not_created() {
    let parent = tempfile::tempdir().expect("temp dir");
    let missing = parent.path().join("nope").join("deeper");
    let err = OutputDir::create_new(&missing, "acme", TS).expect_err("missing");
    assert_eq!(
        err.io_error().map(io::Error::kind),
        Some(io::ErrorKind::NotFound)
    );
    assert!(!parent.path().join("nope").exists());
}

#[test]
fn a_taken_name_moves_to_2_up_to_9_then_gives_up() {
    let parent = tempfile::tempdir().expect("temp dir");
    let mut seen = Vec::new();
    for _ in 0..9 {
        let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
        seen.push(out.name().to_owned());
    }
    let base = "rdy-report-acme-20270309T143005Z";
    assert_eq!(seen[0], base);
    assert_eq!(seen[1], format!("{base}-2"));
    assert_eq!(seen[8], format!("{base}-9"));
    let err = OutputDir::create_new(parent.path(), "acme", TS).expect_err("tenth");
    assert!(matches!(err, ReportError::NameTaken { .. }), "{err}");
    assert_eq!(names(parent.path()).len(), 9);
}

#[test]
fn an_existing_file_or_folder_with_the_name_is_left_alone() {
    let parent = tempfile::tempdir().expect("temp dir");
    let base = "rdy-report-acme-20270309T143005Z";
    fs::write(parent.path().join(base), b"keep me").expect("plant file");
    fs::create_dir(parent.path().join(format!("{base}-2"))).expect("plant dir");
    fs::write(parent.path().join(format!("{base}-2")).join("old"), b"old").expect("plant");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    assert_eq!(out.name(), format!("{base}-3"));
    assert_eq!(
        fs::read(parent.path().join(base)).expect("read"),
        b"keep me"
    );
    assert_eq!(
        names(&parent.path().join(format!("{base}-2"))),
        ["old"],
        "the old folder got no new file"
    );
}

#[test]
fn write_atomic_writes_the_text_and_leaves_no_temp_file() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    let path = out
        .write_atomic("report.json", &redacted("{\"a\":1}\n"))
        .expect("write");
    assert_eq!(path, out.path().join("report.json"));
    assert_eq!(fs::read(&path).expect("read"), b"{\"a\":1}\n");
    assert_eq!(names(out.path()), ["report.json"]);
}

#[test]
fn an_existing_file_is_never_overwritten() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    out.write_atomic("report.json", &redacted("first"))
        .expect("first");
    let err = out
        .write_atomic("report.json", &redacted("second"))
        .expect_err("second");
    assert!(matches!(err, ReportError::FileExists { .. }), "{err}");
    assert_eq!(
        fs::read(out.path().join("report.json")).expect("read"),
        b"first"
    );
    assert_eq!(names(out.path()), ["report.json"], "no temp file is left");
}

#[test]
fn a_file_planted_under_the_final_name_is_never_replaced() {
    // The folder is private and new, so this is only possible for the same user. It still must hold.
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    fs::write(out.path().join("report.html"), b"planted").expect("plant");
    let err = out
        .write_atomic("report.html", &redacted("new"))
        .expect_err("planted");
    assert!(matches!(err, ReportError::FileExists { .. }), "{err}");
    assert_eq!(
        fs::read(out.path().join("report.html")).expect("read"),
        b"planted"
    );
}

#[test]
fn unsafe_file_names_are_refused() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    let long = "a".repeat(129);
    for bad in [
        "",
        ".",
        "..",
        "../x",
        "a/b",
        "a\\b",
        ".hidden",
        ".report.json.tmp",
        "sp ace",
        "nul\0",
        "caf\u{e9}",
        long.as_str(),
    ] {
        let err = out
            .write_atomic(bad, &redacted("x"))
            .expect_err(&format!("{bad:?}"));
        assert!(matches!(err, ReportError::BadFileName), "{bad:?}: {err}");
    }
    assert!(names(out.path()).is_empty());
    assert!(
        names(parent.path()).len() == 1,
        "nothing outside the folder"
    );
}

#[test]
fn the_default_parent_is_the_current_folder_and_the_timestamp_has_the_documented_form() {
    assert_eq!(default_parent(), Path::new("."));
    let at = |secs: u64| UNIX_EPOCH + std::time::Duration::from_secs(secs);
    assert_eq!(report_timestamp(at(0)), "19700101T000000Z");
    assert_eq!(report_timestamp(at(1_709_999_999)), "20240309T155959Z");
    // 2000-02-29 and 2100-03-01 (2100 is not a leap year).
    assert_eq!(report_timestamp(at(951_782_400)), "20000229T000000Z");
    assert_eq!(report_timestamp(at(4_107_542_400)), "21000301T000000Z");
    assert_eq!(
        report_timestamp(UNIX_EPOCH - std::time::Duration::from_secs(5)),
        "19700101T000000Z"
    );
    assert_eq!(
        report_timestamp(at(u64::MAX / 4)),
        "99991231T235959Z",
        "a clock past year 9999 still gives a valid stamp"
    );
    assert!(is_timestamp(&report_timestamp(SystemTime::now())));
}

/// Runs this test binary again for one named test, with `envs` set. A child that dies by a signal or
/// exits non-zero is returned as is.
fn run_child(test: &str, envs: &[(&str, &Path)]) -> std::process::Output {
    let exe = std::env::current_exe().expect("test exe");
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"]);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("run child")
}

const KILL_ENV: &str = "RDY_OUTPUT_TEST_KILL_PARENT";

/// The child side of the kill test. With the variable unset this is a no-op that passes.
#[test]
fn child_dies_in_the_middle_of_a_write() {
    let Some(parent) = std::env::var_os(KILL_ENV) else {
        return;
    };
    let out = OutputDir::create_new(Path::new(&parent), "acme", TS).expect("create");
    out.write_atomic("report.json", &redacted("complete"))
        .expect("first file");
    let _ = out.write_with("report.html", |file| {
        file.write_all(b"half of a repo")?;
        // A kill at this point: the bytes are not flushed or renamed.
        std::process::abort()
    });
    unreachable!("abort does not return");
}

#[test]
fn a_killed_run_leaves_no_file_under_a_final_name_for_the_file_it_was_writing() {
    let parent = tempfile::tempdir().expect("temp dir");
    let output = run_child(
        "output::tests::child_dies_in_the_middle_of_a_write",
        &[(KILL_ENV, parent.path())],
    );
    assert!(!output.status.success(), "the child must die");
    let folders = names(parent.path());
    assert_eq!(folders.len(), 1);
    let dir = parent.path().join(&folders[0]);
    // The first file finished and has its final name with all its bytes. The second one is only a
    // temp file.
    assert_eq!(names(&dir), [".report.html.tmp", "report.json"]);
    assert_eq!(
        fs::read(dir.join("report.json")).expect("read"),
        b"complete"
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).expect("stat").mode() & 0o7777
    }

    #[test]
    fn a_pre_planted_symlink_with_the_name_is_not_followed() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let base = "rdy-report-acme-20270309T143005Z";
        // A symlink to a folder somewhere else, and a dangling one for the next name.
        symlink(elsewhere.path(), parent.path().join(base)).expect("symlink");
        symlink(
            elsewhere.path().join("not-there"),
            parent.path().join(format!("{base}-2")),
        )
        .expect("dangling symlink");
        let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
        assert_eq!(out.name(), format!("{base}-3"));
        out.write_atomic("report.json", &redacted("x"))
            .expect("write");
        out.write_spec(&spec_bytes()).expect("spec");
        assert!(
            names(elsewhere.path()).is_empty(),
            "nothing was written through the symlink"
        );
        assert!(
            !elsewhere.path().join("not-there").exists(),
            "the dangling target was not created"
        );
        assert!(
            fs::symlink_metadata(parent.path().join(base))
                .expect("stat")
                .is_symlink()
        );
    }

    #[test]
    fn a_name_swapped_for_a_symlink_after_mkdir_is_refused() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        symlink(elsewhere.path(), parent.path().join("swapped")).expect("symlink");
        let dir = Dir::open_ambient_dir(parent.path(), ambient_authority()).expect("open");
        let err = open_new_dir(&dir, "swapped").expect_err("must not follow");
        assert_ne!(err.kind(), io::ErrorKind::NotFound, "{err}");
        // A real folder opens.
        fs::create_dir(parent.path().join("real")).expect("mkdir");
        open_new_dir(&dir, "real").expect("a real folder opens");
    }

    #[test]
    fn modes_are_0700_and_0600_under_a_setgid_parent() {
        let parent = tempfile::tempdir().expect("temp dir");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o2775)).expect("chmod");
        assert_eq!(
            mode(parent.path()),
            0o2775,
            "the parent is setgid, or this test proves nothing"
        );
        let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
        out.write_atomic("report.json", &redacted("x"))
            .expect("write");
        out.write_spec(&spec_bytes()).expect("spec");
        assert_eq!(mode(out.path()), 0o700, "setgid is cleared");
        for name in ["report.json", SPEC_COPY_NAME] {
            assert_eq!(mode(&out.path().join(name)), 0o600, "{name}");
        }
    }

    #[test]
    fn a_looser_umask_cannot_loosen_and_a_tighter_one_cannot_break_the_modes() {
        let parent = tempfile::tempdir().expect("temp dir");
        let output = run_child(
            "output::tests::unix::child_runs_under_a_strange_umask",
            &[(UMASK_ENV, parent.path())],
        );
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let folders = names(parent.path());
        assert_eq!(folders.len(), 1);
        let dir = parent.path().join(&folders[0]);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("report.json")), 0o600);
    }

    const UMASK_ENV: &str = "RDY_OUTPUT_TEST_UMASK_PARENT";

    /// The child side. umask 0o277 would make `mkdir` give 0500 and `create` give 0400 if rdy relied
    /// on the requested modes alone. With the variable unset this is a no-op.
    #[test]
    fn child_runs_under_a_strange_umask() {
        let Some(parent) = std::env::var_os(UMASK_ENV) else {
            return;
        };
        rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o277));
        let out = OutputDir::create_new(Path::new(&parent), "acme", TS).expect("create");
        out.write_atomic("report.json", &redacted("x"))
            .expect("write");
    }

    #[test]
    fn a_folder_owned_by_someone_else_is_refused() {
        if rustix::process::geteuid().is_root() {
            eprintln!(
                "skipped: root owns the root folder; root_a_folder_owned_by_another_user_is_refused covers root"
            );
            return;
        }
        let root = Dir::open_ambient_dir("/", ambient_authority()).expect("open /");
        let dir = open_new_dir(&root, ".").expect("open /");
        let err = harden(&dir, Path::new("/")).expect_err("not ours");
        assert!(
            matches!(err, ReportError::NotOwner { owner: 0, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("root_squash"), "{err}");
        assert_eq!(mode(Path::new("/")) & 0o022, 0, "harden did not chmod /");
    }

    #[test]
    fn a_file_is_not_a_report_folder() {
        let parent = tempfile::tempdir().expect("temp dir");
        fs::write(parent.path().join("f"), b"x").expect("file");
        let dir = Dir::open_ambient_dir(parent.path(), ambient_authority()).expect("open");
        assert!(open_new_dir(&dir, "f").is_err());
    }

    /// Root only. The `root` CI job runs it (name starts with `root_`; see tests/root_smoke.rs of
    /// the CLI crate). Plain `cargo test` returns early for a normal user.
    #[test]
    fn root_a_folder_owned_by_another_user_is_refused() {
        let is_root = rustix::process::geteuid().is_root();
        if std::env::var_os("RDY_REQUIRE_ROOT").is_none() && !is_root {
            eprintln!("skipped: needs uid 0 (the root job sets RDY_REQUIRE_ROOT=1)");
            return;
        }
        assert!(is_root, "the root job must run under sudo");
        let parent = tempfile::tempdir().expect("temp dir");
        let folder = parent.path().join("theirs");
        fs::create_dir(&folder).expect("mkdir");
        rustix::fs::chown(&folder, Some(rustix::fs::Uid::from_raw(31_337)), None).expect("chown");
        let parent_dir = Dir::open_ambient_dir(parent.path(), ambient_authority()).expect("open");
        let dir = open_new_dir(&parent_dir, "theirs").expect("open theirs");
        let before = mode(&folder);
        let err = harden(&dir, &folder).expect_err("not ours");
        assert!(
            matches!(
                err,
                ReportError::NotOwner {
                    owner: 31_337,
                    euid: 0,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            mode(&folder),
            before,
            "a folder that is not ours is not chmod'ed"
        );
        // Root as the owner: the same call succeeds and sets 0700.
        let mine = parent.path().join("mine");
        fs::create_dir(&mine).expect("mkdir");
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o2777)).expect("chmod");
        let dir = open_new_dir(&parent_dir, "mine").expect("open mine");
        harden(&dir, &mine).expect("ours");
        assert_eq!(mode(&mine), 0o700);
    }
}

/// A verified spec from the unsigned path, with bytes that a parse-and-print round trip would change.
fn spec_bytes() -> VerifiedSpecBytes {
    let yaml = "# a comment\r\napiVersion: rdy/v1\r\nkind: Readiness\r\nmetadata:\r\n  product: acme\r\nchecks:\r\n  - id: host.cpu\r\n    min: 2\r\n";
    let trust = rdy_spec::sig::TrustStore::new();
    let loaded = rdy_spec::load(
        yaml.as_bytes(),
        None,
        &trust,
        rdy_spec::sig::Policy::AllowUnsigned,
    )
    .expect("load");
    loaded.verified_bytes().clone()
}

#[test]
fn the_spec_copy_is_the_verified_bytes_under_fixed_names() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    let spec = spec_bytes();
    let written = out.write_spec(&spec).expect("write spec");
    // Unsigned: only the spec, no signature file.
    assert_eq!(written, [out.path().join("spec.yaml")]);
    assert_eq!(names(out.path()), ["spec.yaml"]);
    assert_eq!(fs::read(&written[0]).expect("read"), spec.yaml());
    assert!(spec.yaml().windows(2).any(|w| w == b"\r\n"), "CRLF kept");
    // A second copy never replaces the first.
    assert!(matches!(
        out.write_spec(&spec),
        Err(ReportError::FileExists { .. })
    ));
}
