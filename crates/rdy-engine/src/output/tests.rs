//! Tests for the output directory. The Unix mode tests are `cfg(unix)`; the name and no-overwrite
//! tests run everywhere.

use std::fs;
use std::path::Path;

use super::*;
use crate::redact::{Redactor, TagKey};

const TS: &str = "20270309T143005Z";

type Hook = Box<dyn Fn(&Path, &str)>;

thread_local! {
    /// A test hook that runs right after `mkdir` and before the open, to swap the new folder for
    /// something else the way an attacker would. Per thread, so parallel tests do not see it.
    pub(super) static AFTER_MAKE_DIR: std::cell::RefCell<Option<Hook>> =
        const { std::cell::RefCell::new(None) };
}

/// Called by `OutputDir::create_new` in test builds.
pub(super) fn after_make_dir(parent: &Path, name: &str) {
    AFTER_MAKE_DIR.with(|hook| {
        if let Some(swap) = &*hook.borrow() {
            swap(parent, name);
        }
    });
}

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

#[cfg(not(windows))]
#[test]
fn the_default_parent_is_the_current_folder_off_windows() {
    assert_eq!(
        default_report_parent().expect("default").path(),
        Path::new(".")
    );
}

#[test]
fn the_timestamp_has_the_documented_form() {
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
    // One day past the last second of year 9999. Every OS can hold this time (Windows cannot hold
    // `u64::MAX / 4` seconds), so `checked_add` makes it, and a failure is a failure of the test.
    let past_9999 = UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(253_402_300_799 + 86_400))
        .expect("a time just past year 9999 fits in SystemTime");
    assert_eq!(
        report_timestamp(past_9999),
        "99991231T235959Z",
        "a clock past year 9999 still gives a valid stamp"
    );
    assert!(is_timestamp(&report_timestamp(SystemTime::now())));
}

/// Runs `create_new` with `swap` between the `mkdir` and the open, and removes the hook after.
fn create_new_with_swap(
    parent: &Path,
    swap: impl Fn(&Path, &str) + 'static,
) -> Result<OutputDir, ReportError> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            AFTER_MAKE_DIR.with(|hook| *hook.borrow_mut() = None);
        }
    }
    AFTER_MAKE_DIR.with(|hook| *hook.borrow_mut() = Some(Box::new(swap)));
    let _reset = Reset;
    OutputDir::create_new(parent, "acme", TS)
}

/// Makes `link` lead to `target` the way an attacker would: a symlink on Unix and a junction on
/// Windows (`mklink /J` needs no admin rights).
fn plant_redirect(link: &Path, target: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("symlink");
    #[cfg(windows)]
    windows::junction(link, target);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (link, target);
        unreachable!("no redirect on this OS");
    }
}

#[test]
fn the_attribute_bits_tell_a_plain_folder_from_a_reparse_point() {
    const DIR: u32 = 0x10;
    const REPARSE: u32 = 0x400;
    const OTHER: u32 = 0x1 | 0x2 | 0x20 | 0x2000;
    assert!(plain_folder_attributes(DIR));
    assert!(
        plain_folder_attributes(DIR | OTHER),
        "hidden or archive is fine"
    );
    // A junction or a directory symlink: directory and reparse point.
    assert!(!plain_folder_attributes(DIR | REPARSE));
    // Any other reparse tag, such as a cloud placeholder, is refused too.
    assert!(!plain_folder_attributes(DIR | REPARSE | OTHER));
    // A file, or a file symlink.
    assert!(!plain_folder_attributes(0x80));
    assert!(!plain_folder_attributes(REPARSE));
    assert!(!plain_folder_attributes(0));
}

#[test]
fn the_default_folder_is_made_when_it_is_missing_and_reused_when_it_is_there() {
    let profile = tempfile::tempdir().expect("temp dir");
    let want = profile.path().join("rdy-reports");
    assert_eq!(
        open_default_in(profile.path(), profile.path())
            .expect("make")
            .path(),
        want
    );
    assert!(want.is_dir());
    fs::write(want.join("keep"), b"old").expect("plant");
    let parent = open_default_in(profile.path(), profile.path()).expect("reuse");
    assert_eq!(parent.path(), want);
    assert_eq!(names(&want), ["keep"], "nothing was removed or added");
    // The run folder goes under the held handle, and shows under the folder's name.
    let out = OutputDir::create_new_in(&parent, "acme", TS).expect("create");
    assert_eq!(out.path().parent(), Some(want.as_path()));
    assert_eq!(names(&want), ["keep", out.name()]);
}

#[test]
fn the_default_folder_is_not_made_when_the_profile_is_missing() {
    let profile = tempfile::tempdir().expect("temp dir");
    let missing = profile.path().join("no-profile");
    let err = open_default_in(&missing, &missing).expect_err("no profile");
    assert!(matches!(err, ReportError::Io { .. }), "{err}");
    assert!(!missing.exists(), "the profile folder is never made");
}

#[test]
fn a_default_folder_that_is_a_link_or_a_junction_is_refused_and_not_followed() {
    let profile = tempfile::tempdir().expect("temp dir");
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let link = profile.path().join("rdy-reports");
    plant_redirect(&link, elsewhere.path());
    let err =
        open_default_in(profile.path(), profile.path()).expect_err("a redirect must be refused");
    assert!(
        matches!(&err, ReportError::NotPlainFolder { path } if *path == link),
        "{err}"
    );
    assert!(names(elsewhere.path()).is_empty(), "nothing was made there");
}

#[test]
fn a_default_folder_that_is_a_file_is_refused() {
    let profile = tempfile::tempdir().expect("temp dir");
    fs::write(profile.path().join("rdy-reports"), b"a file").expect("plant");
    let err = open_default_in(profile.path(), profile.path()).expect_err("a file");
    assert!(matches!(err, ReportError::NotPlainFolder { .. }), "{err}");
}

#[test]
fn the_final_path_check_accepts_a_real_folder_and_refuses_a_redirect() {
    let parent = tempfile::tempdir().expect("temp dir");
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let real = parent.path().join("real");
    fs::create_dir(&real).expect("mkdir");
    assert!(final_path_is_expected(&real).expect("real"));
    let link = parent.path().join("linked");
    plant_redirect(&link, elsewhere.path());
    assert!(!final_path_is_expected(&link).expect("link"));
    // A name that is not there is an error, not a pass.
    assert!(final_path_is_expected(&parent.path().join("gone")).is_err());
    // A path with no parent or no name cannot be the expected one.
    assert!(!final_path_is_expected(Path::new("/")).expect("root"));
}

/// The exit test of M1-037, redirect at the target name: a junction (Windows) or symlink (Unix)
/// with the folder name is never followed. The name counts as taken and the report goes to `-2`.
#[test]
fn a_redirect_with_the_target_name_is_not_followed_and_the_name_moves_on() {
    let parent = tempfile::tempdir().expect("temp dir");
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let base = "rdy-report-acme-20270309T143005Z";
    let link = parent.path().join(base);
    plant_redirect(&link, elsewhere.path());
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    assert_eq!(out.name(), format!("{base}-2"));
    out.write_atomic("report.json", &redacted("x"))
        .expect("write");
    assert!(
        names(elsewhere.path()).is_empty(),
        "nothing went through the redirect"
    );
    assert!(
        fs::symlink_metadata(&link).expect("stat").is_symlink(),
        "the planted redirect is untouched"
    );
}

/// The exit test of M1-037, redirect swapped in after the `mkdir`: refused before the first check,
/// and nothing is written or changed behind it.
#[test]
fn a_folder_swapped_for_a_redirect_after_mkdir_is_refused_and_nothing_is_written() {
    let parent = tempfile::tempdir().expect("temp dir");
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let target = elsewhere.path().to_path_buf();
    let err = create_new_with_swap(parent.path(), move |dir, name| {
        fs::remove_dir(dir.join(name)).expect("rmdir");
        plant_redirect(&dir.join(name), &target);
    })
    .expect_err("a redirect must be refused");
    let planted = parent.path().join("rdy-report-acme-20270309T143005Z");
    assert!(
        matches!(&err, ReportError::NotPlainFolder { path } if *path == planted),
        "{err:?}"
    );
    assert!(
        names(elsewhere.path()).is_empty(),
        "nothing was written there"
    );
    // The best-effort cleanup may remove the planted link (Windows does, Unix cannot). A real folder
    // under the name would be wrong either way.
    for left in names(parent.path()) {
        assert!(
            fs::symlink_metadata(parent.path().join(left))
                .expect("stat")
                .is_symlink(),
            "only the planted redirect may be left"
        );
    }
}

/// Runs this test binary again for one named test, with `envs` set. A child that dies by a signal or
/// exits non-zero is returned as is.
fn run_child(
    test: &str,
    path_envs: &[(&str, &Path)],
    text_envs: &[(&str, &str)],
) -> std::process::Output {
    let exe = std::env::current_exe().expect("test exe");
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"]);
    for (key, value) in path_envs {
        cmd.env(key, value);
    }
    for (key, value) in text_envs {
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
        file.write_all(b"half of a report")?;
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
        &[],
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

#[test]
fn the_rename_fallback_refuses_to_replace_and_moves_a_free_name() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    fs::write(out.path().join(".a.tmp"), b"new").expect("tmp");
    fs::write(out.path().join("a"), b"planted").expect("planted");
    let err = out
        .rename_no_replace(".a.tmp", "a", &out.path().join("a"))
        .expect_err("exists");
    assert!(matches!(err, ReportError::FileExists { .. }), "{err}");
    assert_eq!(fs::read(out.path().join("a")).expect("read"), b"planted");
    out.rename_no_replace(".a.tmp", "b", &out.path().join("b"))
        .expect("free name");
    assert_eq!(fs::read(out.path().join("b")).expect("read"), b"new");
    assert!(!out.path().join(".a.tmp").exists());
}

/// The check-plus-rename step on its own, so that it runs on every OS, Windows included, and on
/// Linux and macOS where the kernel path in `rename_no_replace` would take over first.
#[test]
fn check_then_rename_refuses_an_existing_name_and_moves_to_a_free_one() {
    let parent = tempfile::tempdir().expect("temp dir");
    let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
    fs::write(out.path().join(".a.tmp"), b"new").expect("tmp");
    fs::write(out.path().join("a"), b"planted").expect("planted");
    let err = out
        .check_then_rename(".a.tmp", "a", &out.path().join("a"))
        .expect_err("exists");
    assert!(matches!(err, ReportError::FileExists { .. }), "{err}");
    assert_eq!(fs::read(out.path().join("a")).expect("read"), b"planted");
    assert_eq!(
        fs::read(out.path().join(".a.tmp")).expect("read"),
        b"new",
        "the temp file is left for the caller to remove"
    );
    out.check_then_rename(".a.tmp", "b", &out.path().join("b"))
        .expect("free name");
    assert_eq!(fs::read(out.path().join("b")).expect("read"), b"new");
    assert!(!out.path().join(".a.tmp").exists());
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).expect("stat").mode() & 0o7777
    }

    /// `O_NOFOLLOW | O_DIRECTORY` on a symlink fails with `ELOOP` on macOS and with `ENOTDIR` on
    /// Linux. Anything else, `ENOENT` above all, would mean the link was followed or not seen.
    fn assert_refused_as_symlink(err: &io::Error) {
        use rustix::io::Errno;
        let got = err.raw_os_error();
        assert!(
            got == Some(Errno::LOOP.raw_os_error()) || got == Some(Errno::NOTDIR.raw_os_error()),
            "{err}"
        );
    }

    /// True in the CI root job (`RDY_REQUIRE_ROOT` set), where the test must run as uid 0. Anywhere
    /// else the `root_*` tests return early, so a plain `cargo test` as root or not is the same.
    fn root_job() -> bool {
        if std::env::var_os("RDY_REQUIRE_ROOT").is_none() {
            eprintln!("skipped: the root job sets RDY_REQUIRE_ROOT=1");
            return false;
        }
        assert!(
            rustix::process::geteuid().is_root(),
            "the root job must run under sudo"
        );
        true
    }

    #[test]
    fn a_folder_swapped_for_a_symlink_between_mkdir_and_open_is_refused_end_to_end() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        // Not the 0700 a temp dir starts with, so a chmod through the symlink would show.
        fs::set_permissions(elsewhere.path(), fs::Permissions::from_mode(0o755)).expect("chmod");
        let target = elsewhere.path().to_path_buf();
        let err = create_new_with_swap(parent.path(), move |dir, name| {
            fs::remove_dir(dir.join(name)).expect("rmdir");
            symlink(&target, dir.join(name)).expect("symlink");
        })
        .expect_err("a symlink must be refused");
        assert!(
            matches!(&err, ReportError::NotPlainFolder { .. }),
            "{err:?}"
        );
        assert!(
            names(elsewhere.path()).is_empty(),
            "nothing was written there"
        );
        assert_eq!(
            mode(elsewhere.path()) & 0o777,
            0o755,
            "the other folder was not chmod'ed"
        );
        // Only the planted symlink is in the parent, and it is still a symlink.
        let left = names(parent.path());
        assert_eq!(left, ["rdy-report-acme-20270309T143005Z"]);
        assert!(
            fs::symlink_metadata(parent.path().join(&left[0]))
                .expect("stat")
                .is_symlink()
        );
    }

    /// Root only (the `root` CI job). The folder is swapped for one that another user owns, with a
    /// file in it so that the cleanup `rmdir` leaves it, and the test can see it was not touched.
    #[test]
    fn root_a_folder_swapped_for_one_owned_by_another_user_is_refused_end_to_end() {
        if !root_job() {
            return;
        }
        let parent = tempfile::tempdir().expect("temp dir");
        let theirs = parent.path().join("rdy-report-acme-20270309T143005Z");
        let err = create_new_with_swap(parent.path(), move |dir, name| {
            let path = dir.join(name);
            fs::remove_dir(&path).expect("rmdir");
            fs::create_dir(&path).expect("mkdir");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o2755)).expect("chmod");
            fs::write(path.join("theirs"), b"keep").expect("file");
            rustix::fs::chown(&path, Some(rustix::fs::Uid::from_raw(31_337)), None).expect("chown");
        })
        .expect_err("a folder owned by someone else must be refused");
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
        assert_eq!(mode(&theirs), 0o2755, "their folder was not chmod'ed");
        assert_eq!(names(&theirs), ["theirs"], "nothing was written into it");
        assert_eq!(names(parent.path()).len(), 1, "nothing else in the parent");
    }

    #[test]
    fn only_the_documented_link_errors_fall_back_to_a_rename() {
        use rustix::io::Errno;
        let os = |e: Errno| io::Error::from_raw_os_error(e.raw_os_error());
        for e in [
            Errno::PERM,
            Errno::OPNOTSUPP,
            Errno::NOTSUP,
            Errno::MLINK,
            Errno::NOSYS,
        ] {
            assert!(no_hard_links(&os(e)), "{e}");
        }
        for e in [
            Errno::ACCESS,
            Errno::IO,
            Errno::NOSPC,
            Errno::ROFS,
            Errno::XDEV,
            Errno::NOENT,
        ] {
            assert!(!no_hard_links(&os(e)), "{e}");
        }
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
        assert_refused_as_symlink(&err);
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
        // Linux passes setgid on to new folders. macOS and the BSDs do not, so there the folder was
        // never setgid; the 0700 assertion below is true either way and `harden` clears it where it is.
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
    fn the_modes_are_0700_and_0600_under_a_tight_and_a_loose_umask() {
        // 0o277 would make `mkdir` give 0500 and `create` give 0400 if rdy relied on the requested
        // modes alone. 0 would give 0777 and 0666 if rdy did not set the modes itself.
        for umask in ["277", "0"] {
            let parent = tempfile::tempdir().expect("temp dir");
            let output = run_child(
                "output::tests::unix::child_runs_under_a_strange_umask",
                &[(UMASK_ENV, parent.path())],
                &[(UMASK_VALUE_ENV, umask)],
            );
            assert!(
                output.status.success(),
                "umask {umask}: child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let folders = names(parent.path());
            assert_eq!(folders.len(), 1, "umask {umask}");
            let dir = parent.path().join(&folders[0]);
            assert_eq!(mode(&dir), 0o700, "umask {umask}");
            assert_eq!(mode(&dir.join("report.json")), 0o600, "umask {umask}");
        }
    }

    const UMASK_ENV: &str = "RDY_OUTPUT_TEST_UMASK_PARENT";
    const UMASK_VALUE_ENV: &str = "RDY_OUTPUT_TEST_UMASK_VALUE";

    /// The child side. The umask is the octal text in `UMASK_VALUE_ENV`. With the parent variable
    /// unset this is a no-op.
    #[test]
    fn child_runs_under_a_strange_umask() {
        let Some(parent) = std::env::var_os(UMASK_ENV) else {
            return;
        };
        let value = std::env::var(UMASK_VALUE_ENV).expect("umask value");
        // `RawMode` is u16 on macOS and u32 on Linux.
        let bits = rustix::fs::RawMode::from_str_radix(&value, 8).expect("octal umask");
        rustix::process::umask(rustix::fs::Mode::from_bits_truncate(bits));
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
        let before = mode(Path::new("/"));
        let err = harden(&dir, Path::new("/")).expect_err("not ours");
        assert!(
            matches!(err, ReportError::NotOwner { owner: 0, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("root_squash"), "{err}");
        assert_eq!(mode(Path::new("/")), before, "harden did not chmod /");
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
        if !root_job() {
            return;
        }
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

/// The Windows half of the M1-037 exit test. These run on the windows-x64 CI leg only.
#[cfg(windows)]
mod windows {
    use std::process::Command;

    use super::*;

    /// Makes a junction with `mklink /J`, which needs no admin rights.
    pub(super) fn junction(link: &Path, target: &Path) {
        let out = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .expect("run cmd");
        assert!(
            out.status.success(),
            "mklink /J failed: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `ERROR_PRIVILEGE_NOT_HELD`: a plain user without Developer Mode cannot make a symlink.
    const NO_SYMLINK_PRIVILEGE: i32 = 1314;

    /// Makes a directory symlink. Without the privilege this fails the test with the fix, and does
    /// not skip: the symlink half of the exit test must run on the CI leg.
    fn symlink_dir(link: &Path, target: &Path) {
        if let Err(e) = std::os::windows::fs::symlink_dir(target, link) {
            assert_ne!(
                e.raw_os_error(),
                Some(NO_SYMLINK_PRIVILEGE),
                "this user cannot create symlinks. Fix: turn on Developer Mode (Settings, For \
                 developers) or run the tests from an elevated shell. The CI runner is an \
                 administrator, so this test must run there"
            );
            panic!("symlink_dir failed: {e}");
        }
    }

    fn is_reparse_point(path: &Path) -> bool {
        use std::os::windows::fs::MetadataExt as _;
        fs::symlink_metadata(path).expect("stat").file_attributes() & 0x400 != 0
    }

    const CASE_ENV: &str = "RDY_OUTPUT_TEST_DEFAULT_CASE";

    /// The child side of the default folder tests. `USERPROFILE` is set by the parent, so the real
    /// profile is never touched. With `CASE_ENV` unset this is a no-op that passes.
    #[test]
    fn child_default_parent() {
        let Ok(case) = std::env::var(CASE_ENV) else {
            return;
        };
        let got = default_report_parent();
        match case.as_str() {
            "ok" => {
                let parent = got.expect("default");
                let out = OutputDir::create_new_in(&parent, "acme", TS).expect("create");
                assert_eq!(out.path().parent(), Some(parent.path()));
                out.write_atomic("report.json", &redacted("x"))
                    .expect("write");
            }
            "refused" => assert!(matches!(got, Err(ReportError::NoDefaultFolder)), "{got:?}"),
            "redirect" => assert!(
                matches!(got, Err(ReportError::NotPlainFolder { .. })),
                "{got:?}"
            ),
            other => panic!("unknown case {other}"),
        }
    }

    fn child(case: &str, userprofile: &dyn AsRef<std::ffi::OsStr>) -> std::process::Output {
        let mut cmd = Command::new(std::env::current_exe().expect("test exe"));
        cmd.args([
            "--exact",
            "output::tests::windows::child_default_parent",
            "--nocapture",
            "--test-threads=1",
        ]);
        cmd.env(CASE_ENV, case).env("USERPROFILE", userprofile);
        cmd.output().expect("run child")
    }

    fn assert_ok(out: &std::process::Output) {
        assert!(
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "child failed or ran no test: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Exit test: the default lands under `%USERPROFILE%\rdy-reports`. The profile is a temp folder,
    /// so nothing is left in the real one.
    #[test]
    fn the_default_parent_is_under_userprofile() {
        let profile = tempfile::tempdir().expect("temp dir");
        assert_ok(&child("ok", &profile.path()));
        let reports = profile.path().join("rdy-reports");
        let folders = names(&reports);
        assert_eq!(folders, ["rdy-report-acme-20270309T143005Z"]);
        assert!(!is_reparse_point(&reports));
        assert!(reports.join(&folders[0]).join("report.json").is_file());
    }

    #[test]
    fn a_default_folder_that_is_a_junction_is_refused_by_the_real_entry_point() {
        let profile = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        junction(&profile.path().join("rdy-reports"), elsewhere.path());
        assert_ok(&child("redirect", &profile.path()));
        assert!(names(elsewhere.path()).is_empty());
    }

    #[test]
    fn a_userprofile_that_is_not_a_local_full_path_gives_no_default_folder() {
        for bad in [
            "",
            "profile",
            r"..\profile",
            r"\\server\share\profile",
            r"\\?\UNC\server\share\profile",
        ] {
            assert_ok(&child("refused", &bad));
        }
    }

    #[test]
    fn a_junction_with_the_target_name_is_not_followed_and_is_a_reparse_point() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let link = parent.path().join("rdy-report-acme-20270309T143005Z");
        junction(&link, elsewhere.path());
        assert!(
            is_reparse_point(&link),
            "the planted junction is a reparse point"
        );
        let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
        assert_eq!(out.name(), "rdy-report-acme-20270309T143005Z-2");
        out.write_atomic("report.json", &redacted("x"))
            .expect("write");
        assert!(names(elsewhere.path()).is_empty());
        assert!(is_reparse_point(&link));
    }

    #[test]
    fn a_symlink_with_the_target_name_is_not_followed() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let link = parent.path().join("rdy-report-acme-20270309T143005Z");
        symlink_dir(&link, elsewhere.path());
        let out = OutputDir::create_new(parent.path(), "acme", TS).expect("create");
        assert_eq!(out.name(), "rdy-report-acme-20270309T143005Z-2");
        out.write_atomic("report.json", &redacted("x"))
            .expect("write");
        assert!(names(elsewhere.path()).is_empty());
        assert!(is_reparse_point(&link));
    }

    #[test]
    fn a_folder_swapped_for_a_symlink_after_mkdir_is_refused() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let target = elsewhere.path().to_path_buf();
        let err = create_new_with_swap(parent.path(), move |dir, name| {
            fs::remove_dir(dir.join(name)).expect("rmdir");
            symlink_dir(&dir.join(name), &target);
        })
        .expect_err("a symlink must be refused");
        assert!(
            matches!(&err, ReportError::NotPlainFolder { .. }),
            "{err:?}"
        );
        assert!(names(elsewhere.path()).is_empty());
    }

    /// `harden` on its own: a handle that followed a junction is a plain folder by attributes, so
    /// only the final path check can refuse it. A real folder passes.
    #[test]
    fn harden_refuses_a_handle_that_followed_a_junction_and_passes_a_real_folder() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let real = parent.path().join("real");
        fs::create_dir(&real).expect("mkdir");
        let dir = Dir::open_ambient_dir(&real, ambient_authority()).expect("open");
        harden(&dir, &real).expect("a real folder passes");

        let link = parent.path().join("linked");
        junction(&link, elsewhere.path());
        let followed = Dir::open_ambient_dir(&link, ambient_authority()).expect("open");
        let err = harden(&followed, &link).expect_err("a junction must be refused");
        assert!(matches!(err, ReportError::NotPlainFolder { .. }), "{err}");
    }

    /// `open_new_dir` on a junction must not follow it: the open fails with
    /// `ERROR_STOPPED_ON_SYMLINK` (681), and `open_error` names that as a redirect.
    #[test]
    fn a_junction_opened_by_name_fails_to_open_and_is_named_a_redirect() {
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let link = parent.path().join("linked");
        junction(&link, elsewhere.path());
        let dir = Dir::open_ambient_dir(parent.path(), ambient_authority()).expect("open");
        let err = match open_new_dir(&dir, "linked") {
            Ok(_) => panic!("the junction must not open as a folder"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(681), "{err}");
        let named = open_error("open", &dir, "linked", &link, err);
        assert!(
            matches!(named, ReportError::NotPlainFolder { .. }),
            "{named:?}"
        );
    }

    /// A handle on the junction itself (opened with `FILE_FLAG_OPEN_REPARSE_POINT`), the handle the
    /// attribute check exists for. `check_plain_folder` must refuse it by its reparse bit, and a
    /// handle on a real folder opened the same way must pass.
    #[test]
    fn a_handle_on_a_reparse_point_is_refused_by_its_attributes() {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let open_itself = |path: &Path| {
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
                .open(path)
                .expect("open the entry itself")
        };
        let parent = tempfile::tempdir().expect("temp dir");
        let elsewhere = tempfile::tempdir().expect("temp dir");
        let real = parent.path().join("real");
        fs::create_dir(&real).expect("mkdir");
        let file = open_itself(&real);
        assert_eq!(file.metadata().expect("stat").file_attributes() & 0x400, 0);
        check_plain_folder(&Dir::from_std_file(file), &real).expect("a real folder passes");

        let link = parent.path().join("linked");
        junction(&link, elsewhere.path());
        let file = open_itself(&link);
        assert_ne!(
            file.metadata().expect("stat").file_attributes() & 0x400,
            0,
            "the handle is on the junction itself"
        );
        let err = check_plain_folder(&Dir::from_std_file(file), &link)
            .expect_err("a reparse handle must be refused");
        assert!(matches!(err, ReportError::NotPlainFolder { .. }), "{err:?}");
    }
}
