//! Tests of the trust store layout, the ownership rules and the atomic write (M1-121).
//!
//! The owner of the system store is normally root, and a test cannot make a root-owned file. So the
//! layout takes the owner as a parameter in tests: the right owner is the current user, and the wrong
//! one is any other uid. The rules run the same way.

use std::ffi::OsString;
use std::path::PathBuf;

use rdy_spec::sig::{TrustFileError, TrustStore};

use super::*;

/// Two synthetic public keys with different ids.
#[cfg(unix)]
const KEY_A: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
#[cfg(unix)]
const KEY_B: &str = "RWRisVYvbscX8T+fpAU7YfuJEX375tuZ+vrUzbuOSlRvvc4YV/jqrPpr";

fn os(text: &str) -> Option<OsString> {
    Some(OsString::from(text))
}

/// A path that is absolute on this platform: `/home/alice` on Unix, `C:/home/alice` on Windows.
fn abs(path: &str) -> String {
    if cfg!(windows) {
        format!("C:{path}")
    } else {
        path.to_owned()
    }
}

/// `abs(base)` joined with the parts, the way the layout joins them.
fn under(base: &str, parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(abs(base));
    path.extend(parts);
    path
}

fn vars(home: Option<&str>, xdg: Option<&str>) -> Vars {
    Vars {
        home: home.and_then(os),
        xdg_config_home: xdg.and_then(os),
        program_data: None,
    }
}

#[cfg(unix)]
fn trust_text(product: &str, key: &str, note: Option<&str>) -> String {
    let mut text = format!(
        "apiVersion: rdy/v1\nkind: TrustStore\nkeys:\n  - product: {product}\n    key: {key}\n    added_at: 2026-11-30T16:20:00Z\n"
    );
    if let Some(note) = note {
        text.push_str(&format!("    note: \"{note}\"\n"));
    }
    text
}

#[test]
fn a_root_run_has_no_user_path_whatever_the_environment_says() {
    // INV-04. HOME, XDG_CONFIG_HOME and (not even read) SUDO_USER cannot add a path under a home.
    // `Layout::unix` is what a Unix euid 0 gets. It is compiled on every platform, so this runs on all.
    for v in [
        vars(Some(&abs("/home/alice")), Some(&abs("/home/alice/.config"))),
        vars(Some(&abs("/root")), None),
        vars(None, Some(&abs("/home/alice/.config"))),
        vars(None, None),
    ] {
        let layout = Layout::unix(&v, 0);
        assert_eq!(layout.path(Scope::User), None, "{v:?}");
        assert_eq!(layout.path(Scope::System), Some(Path::new(SYSTEM_STORE)));
        assert_eq!(layout.write_scope(), Scope::System);
    }
}

#[test]
fn a_user_run_reads_xdg_then_home_config_then_the_system_store() {
    let home = abs("/home/alice");
    let layout = Layout::unix(&vars(Some(&home), Some(&abs("/xdg"))), 1000);
    assert_eq!(
        layout.path(Scope::User),
        Some(under("/xdg", &["rdy", "trust.yaml"]).as_path())
    );
    let layout = Layout::unix(&vars(Some(&home), None), 1000);
    assert_eq!(
        layout.path(Scope::User),
        Some(under("/home/alice", &[".config", "rdy", "trust.yaml"]).as_path())
    );
    assert_eq!(layout.path(Scope::System), Some(Path::new(SYSTEM_STORE)));
    assert_eq!(layout.write_scope(), Scope::User);
}

#[test]
fn a_relative_or_empty_home_gives_no_user_store() {
    for v in [
        vars(Some("home/alice"), None),
        vars(Some(""), Some("")),
        vars(Some("home"), Some("relative/xdg")),
        vars(None, None),
    ] {
        let layout = Layout::unix(&v, 1000);
        assert_eq!(layout.path(Scope::User), None, "{v:?}");
    }
    // An empty or relative XDG value is ignored, as the XDG spec says, and HOME is used.
    let layout = Layout::unix(&vars(Some(&abs("/home/alice")), Some("relative")), 1000);
    assert_eq!(
        layout.path(Scope::User),
        Some(under("/home/alice", &[".config", "rdy", "trust.yaml"]).as_path())
    );
}

#[test]
fn the_windows_layout_has_programdata_and_no_user_path() {
    // HOME and XDG_CONFIG_HOME are set too: a Windows layout ignores them as well (ADR 0027).
    let v = Vars {
        program_data: os(&abs("/programdata")),
        ..vars(Some(&abs("/home/alice")), Some(&abs("/home/alice/.config")))
    };
    let layout = Layout::windows(&v);
    assert_eq!(layout.path(Scope::User), None);
    assert_eq!(
        layout.path(Scope::System),
        Some(under("/programdata", &["rdy", "trust.yaml"]).as_path())
    );
    // Elevation is never detected, and there is no user store, so the only store to write is the system one.
    assert_eq!(layout.write_scope(), Scope::System);
    // The Unix layout keeps its own answer on every host, Windows included.
    let unix = Layout::unix(&v, 1000);
    assert_eq!(unix.write_scope(), Scope::User);
    assert_eq!(Layout::unix(&v, 0).write_scope(), Scope::System);
}

#[test]
fn the_windows_layout_without_programdata_has_no_store_at_all() {
    let layout = Layout::windows(&Vars::default());
    assert_eq!(layout.path(Scope::User), None);
    assert_eq!(layout.path(Scope::System), None);
}

#[test]
fn the_unverifiable_fix_points_at_an_administrator_and_the_docs() {
    let path = PathBuf::from("/etc/rdy/trust.yaml");
    let error = TrustStoreError::Insecure {
        path,
        scope: Scope::System,
        why: Insecurity::Unverifiable,
    };
    let fix = error.fix();
    assert!(fix.starts_with("ask an administrator to remove "), "{fix}");
    assert!(fix.contains("https://docs.getrdy.io/unsigned"), "{fix}");
    // 07 rule 8: no fix line suggests the flags that weaken the check.
    assert!(
        !fix.contains("--key") && !fix.contains("--allow-unsigned"),
        "{fix}"
    );
}

#[test]
fn every_error_has_a_message_a_fix_and_a_code() {
    let path = PathBuf::from("/etc/rdy/trust.yaml");
    let mut errors = vec![
        TrustStoreError::NoUserStore,
        TrustStoreError::Unsupported,
        TrustStoreError::Unreadable {
            path: path.clone(),
            reason: IoReason::PermissionDenied,
        },
        TrustStoreError::Invalid {
            path: path.clone(),
            source: TrustFileError::NotUtf8,
        },
    ];
    for why in [
        Insecurity::Symlink,
        Insecurity::NotRegular,
        Insecurity::NotOwned,
        Insecurity::Writable,
        Insecurity::DirSymlink,
        Insecurity::DirNotDirectory,
        Insecurity::DirNotOwned,
        Insecurity::DirWritable,
        Insecurity::Unverifiable,
    ] {
        for scope in [Scope::System, Scope::User] {
            errors.push(TrustStoreError::Insecure {
                path: path.clone(),
                scope,
                why,
            });
        }
    }
    for reason in [
        IoReason::NoSuchFile,
        IoReason::PermissionDenied,
        IoReason::NotAFile,
        IoReason::DiskFull,
        IoReason::Other,
    ] {
        for scope in [Scope::System, Scope::User] {
            errors.push(TrustStoreError::Write {
                path: path.clone(),
                scope,
                reason,
            });
        }
        errors.push(TrustStoreError::Unreadable {
            path: path.clone(),
            reason,
        });
    }
    for error in errors {
        assert!(!error.to_string().is_empty(), "{error:?}");
        assert!(!error.fix().is_empty(), "{error:?}");
        let want = if matches!(error, TrustStoreError::Insecure { .. }) {
            ErrorCode::TrustStoreInsecure
        } else {
            ErrorCode::Usage
        };
        assert_eq!(error.code(), want, "{error:?}");
    }
}

#[test]
fn a_fix_line_quotes_a_path_with_spaces() {
    let error = TrustStoreError::Insecure {
        path: PathBuf::from("/home/a b/.config/rdy/trust.yaml"),
        scope: Scope::User,
        why: Insecurity::Writable,
    };
    assert_eq!(error.fix(), "chmod 600 '/home/a b/.config/rdy/trust.yaml'");
}

/// The file system rules. They need Unix modes and owners.
#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::Path;

    use rdy_spec::sig::TrustSource;
    use tempfile::TempDir;

    use super::*;

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// The gate for every `root_*` test (docs/plan/08-testing.md, section 6). True when the process is
    /// root. A non-root run returns false and the test returns early, unless `RDY_REQUIRE_ROOT` is set
    /// (the `root` CI job sets it). Then not being root is a failure, so the job cannot go green by
    /// skipping.
    fn is_root_or_skip() -> bool {
        if me() == 0 {
            return true;
        }
        assert!(
            std::env::var_os("RDY_REQUIRE_ROOT").is_none(),
            "euid is not 0; the root job must run under sudo"
        );
        eprintln!("skipped: needs uid 0 (the root job sets RDY_REQUIRE_ROOT=1)");
        false
    }

    /// An effective uid for a user-run layout. It is never 0, because a root layout has no user path.
    /// A user store owned by the current user passes for this uid, or, when the tests run as root, as
    /// a store that root owns.
    fn user_euid() -> u32 {
        me().max(1)
    }

    fn mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// A temp folder, a system store in `sys/rdy/trust.yaml` and a layout whose system owner is the
    /// current user. `euid` is the effective uid the layout pretends to have.
    struct Fixture {
        root: TempDir,
        euid: u32,
    }

    impl Fixture {
        fn new(euid: u32) -> Self {
            Self {
                root: tempfile::tempdir().expect("tempdir"),
                euid,
            }
        }

        fn sys_dir(&self) -> PathBuf {
            self.root.path().join("sys").join("rdy")
        }

        fn sys_file(&self) -> PathBuf {
            self.sys_dir().join("trust.yaml")
        }

        fn home(&self) -> PathBuf {
            self.root.path().join("home")
        }

        fn user_file(&self) -> PathBuf {
            self.home().join(".config").join("rdy").join("trust.yaml")
        }

        fn layout(&self) -> Layout {
            self.layout_owned_by(me())
        }

        fn layout_owned_by(&self, owner: u32) -> Layout {
            Layout::from_env(&self.vars(), self.euid).with_system_file(self.sys_file(), owner)
        }

        /// HOME and XDG_CONFIG_HOME both point at the user's folders, as in a login shell.
        fn vars(&self) -> Vars {
            let xdg = self.home().join(".config");
            vars(self.home().to_str(), xdg.to_str())
        }

        /// A well-formed system store: folder 0755, file 0644.
        fn write_system(&self, text: &str) {
            fs::create_dir_all(self.sys_dir()).expect("mkdir");
            mode(&self.sys_dir(), 0o755);
            fs::write(self.sys_file(), text).expect("write");
            mode(&self.sys_file(), 0o644);
        }

        fn write_user(&self, text: &str) {
            let file = self.user_file();
            let dir = file.parent().expect("parent");
            fs::create_dir_all(dir).expect("mkdir");
            mode(dir, 0o700);
            fs::write(&file, text).expect("write");
            mode(&file, 0o600);
        }
    }

    fn insecure(error: &TrustStoreError) -> Insecurity {
        match error {
            TrustStoreError::Insecure { why, .. } => *why,
            other => panic!("expected an insecure store, got {other:?}"),
        }
    }

    #[test]
    fn root_real_process_has_no_user_path() {
        // Only meaningful when the tests run as root (the `root` CI job, the sudo leg of INV-04). The
        // process environment is whatever it is, with a HOME and perhaps an XDG_CONFIG_HOME, and a root
        // layout ignores both. sudo resets HOME and XDG_CONFIG_HOME, so this test builds nothing from them.
        if !is_root_or_skip() {
            return;
        }
        let layout = Layout::detect();
        assert_eq!(layout.path(Scope::User), None);
        assert_eq!(layout.path(Scope::System), Some(Path::new(SYSTEM_STORE)));
        assert_eq!(layout.write_scope(), Scope::System);
    }

    #[test]
    fn a_missing_store_and_a_missing_folder_are_empty() {
        let f = Fixture::new(1000);
        let store = load(&f.layout()).expect("loads");
        assert_eq!(store, TrustStore::new());
        // The folder exists and the file does not.
        fs::create_dir_all(f.sys_dir()).expect("mkdir");
        mode(&f.sys_dir(), 0o755);
        assert_eq!(load(&f.layout()).expect("loads"), TrustStore::new());
    }

    #[test]
    fn as_root_only_the_system_store_is_read_and_the_user_store_is_never_opened() {
        // INV-04, M1-121 exit test. The environment points at a user store with a pin. A root run does
        // not have that path. To prove it is not even opened, the user file is made insecure: if it were
        // read, the load would fail.
        let f = Fixture::new(0);
        f.write_system(&trust_text("acme-platform", KEY_A, Some("system")));
        f.write_user(&trust_text("acme-platform", KEY_B, Some("user")));
        mode(&f.user_file(), 0o666);
        let layout = f.layout();
        assert_eq!(layout.path(Scope::User), None);
        let store = load(&layout).expect("the system store loads");
        let expected = TrustStore::from_yaml(
            trust_text("acme-platform", KEY_A, Some("system")).as_bytes(),
            TrustSource::System,
        )
        .expect("expected");
        assert_eq!(store, expected);
    }

    #[test]
    fn as_a_user_the_user_store_comes_first_then_the_system_store() {
        let f = Fixture::new(user_euid());
        f.write_system(&trust_text("acme-platform", KEY_A, Some("system")));
        f.write_user(&trust_text("acme-platform", KEY_B, Some("user")));
        let store = load(&f.layout()).expect("loads");
        let mut expected = TrustStore::from_yaml(
            trust_text("acme-platform", KEY_B, Some("user")).as_bytes(),
            TrustSource::User,
        )
        .expect("user");
        expected.extend(
            TrustStore::from_yaml(
                trust_text("acme-platform", KEY_A, Some("system")).as_bytes(),
                TrustSource::System,
            )
            .expect("system"),
        );
        assert_eq!(store, expected);
    }

    #[test]
    fn a_system_store_that_is_a_symlink_is_refused() {
        let f = Fixture::new(1000);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        let real = f.sys_dir().join("real.yaml");
        fs::rename(f.sys_file(), &real).expect("rename");
        symlink(&real, f.sys_file()).expect("symlink");
        let error = load(&f.layout()).expect_err("must be refused");
        assert_eq!(insecure(&error), Insecurity::Symlink);
        assert_eq!(error.code(), ErrorCode::TrustStoreInsecure);
    }

    #[test]
    fn a_user_store_that_is_a_symlink_is_refused() {
        let f = Fixture::new(user_euid());
        f.write_user(&trust_text("acme-platform", KEY_A, None));
        let real = f.user_file().with_file_name("real.yaml");
        fs::rename(f.user_file(), &real).expect("rename");
        symlink(&real, f.user_file()).expect("symlink");
        let error = load(&f.layout()).expect_err("must be refused");
        assert_eq!(insecure(&error), Insecurity::Symlink);
    }

    #[test]
    fn a_system_folder_owned_by_someone_other_than_root_is_refused() {
        let f = Fixture::new(1000);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        let error = load(&f.layout_owned_by(me().wrapping_add(1))).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirNotOwned);
        assert!(error.to_string().contains("not owned by root"), "{error}");
        assert_eq!(error.fix(), format!("chown root {}", f.sys_dir().display()));
    }

    #[test]
    fn a_system_store_owned_by_someone_other_than_root_is_refused() {
        // The folder passes (its owner is the current user) and the file fails (its owner is any other
        // uid), so the file rule is the one that is tested. No root is needed.
        let f = Fixture::new(1000);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        let layout = f.layout().with_system_file_owner(me().wrapping_add(1));
        let error = load(&layout).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::NotOwned);
        assert!(error.to_string().contains("not owned by root"), "{error}");
        assert_eq!(
            error.fix(),
            format!("chown root {}", f.sys_file().display())
        );
    }

    #[test]
    fn a_user_store_folder_owned_by_another_user_is_refused() {
        // Root may own a user store, so there is nothing to refuse when the tests run as root.
        if me() == 0 {
            return;
        }
        let f = Fixture::new(me().wrapping_add(1));
        f.write_user(&trust_text("acme-platform", KEY_A, None));
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirNotOwned);
        assert!(
            error.to_string().contains("owned by another user"),
            "{error}"
        );
        assert!(error.fix().contains("check who put"), "{}", error.fix());
    }

    #[test]
    fn root_user_store_owned_by_another_user_is_refused() {
        // Giving a file to another user needs root, so this runs only when the tests run as root (the
        // `root` CI job). The folder stays root's, which a user layout accepts, so the file is the one
        // that fails. The layout comes from the fixture, never from HOME or XDG_CONFIG_HOME, because sudo
        // resets both.
        if !is_root_or_skip() {
            return;
        }
        let f = Fixture::new(1000);
        f.write_user(&trust_text("acme-platform", KEY_A, None));
        std::os::unix::fs::chown(f.user_file(), Some(4242), None).expect("chown");
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::NotOwned);
        assert!(error.to_string().contains("another user"), "{error}");
    }

    #[test]
    fn a_user_store_folder_that_is_a_symlink_is_refused() {
        let f = Fixture::new(user_euid());
        f.write_user(&trust_text("acme-platform", KEY_A, None));
        let dir = f.user_file().parent().expect("parent").to_path_buf();
        let real = dir.with_file_name("real");
        fs::rename(&dir, &real).expect("rename");
        symlink(&real, &dir).expect("symlink");
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirSymlink);
        assert_eq!(
            error.fix(),
            format!("replace {} with a real folder that you own", dir.display())
        );
        // Saving does not follow the link either.
        let error = save(&f.layout(), &TrustStore::new()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirSymlink);
    }

    #[test]
    fn a_user_store_folder_that_others_can_write_is_refused() {
        for bad in [0o775, 0o757, 0o777] {
            let f = Fixture::new(user_euid());
            f.write_user(&trust_text("acme-platform", KEY_A, None));
            let dir = f.user_file().parent().expect("parent").to_path_buf();
            mode(&dir, bad);
            let error = load(&f.layout()).expect_err("refused");
            assert_eq!(insecure(&error), Insecurity::DirWritable, "{bad:o}");
            assert_eq!(error.fix(), format!("chmod 700 {}", dir.display()));
            let error = save(&f.layout(), &TrustStore::new()).expect_err("refused");
            assert_eq!(insecure(&error), Insecurity::DirWritable, "{bad:o}");
        }
    }

    #[test]
    fn a_user_store_folder_that_is_a_file_is_refused() {
        let f = Fixture::new(user_euid());
        let dir = f.user_file().parent().expect("parent").to_path_buf();
        fs::create_dir_all(dir.parent().expect("parent")).expect("mkdir");
        fs::write(&dir, "x").expect("write");
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirNotDirectory);
    }

    #[test]
    fn a_store_that_group_or_others_can_write_is_refused() {
        for bad in [0o664, 0o646, 0o666, 0o620, 0o602] {
            let f = Fixture::new(1000);
            f.write_system(&trust_text("acme-platform", KEY_A, None));
            mode(&f.sys_file(), bad);
            let error = load(&f.layout()).expect_err("refused");
            assert_eq!(insecure(&error), Insecurity::Writable, "{bad:o}");
            assert_eq!(
                error.to_string(),
                format!("{} is writable by other users", f.sys_file().display())
            );
            assert_eq!(error.fix(), format!("chmod 644 {}", f.sys_file().display()));

            let f = Fixture::new(user_euid());
            f.write_user(&trust_text("acme-platform", KEY_A, None));
            mode(&f.user_file(), bad);
            let error = load(&f.layout()).expect_err("refused");
            assert_eq!(insecure(&error), Insecurity::Writable, "{bad:o}");
        }
    }

    #[test]
    fn a_store_that_others_can_read_but_not_write_is_fine() {
        let f = Fixture::new(user_euid());
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        f.write_user(&trust_text("acme-platform", KEY_B, None));
        mode(&f.user_file(), 0o644);
        mode(&f.sys_file(), 0o644);
        assert!(load(&f.layout()).is_ok());
    }

    #[test]
    fn a_system_folder_that_others_can_write_is_refused() {
        for bad in [0o775, 0o757, 0o777] {
            let f = Fixture::new(1000);
            f.write_system(&trust_text("acme-platform", KEY_A, None));
            mode(&f.sys_dir(), bad);
            let error = load(&f.layout()).expect_err("refused");
            assert_eq!(insecure(&error), Insecurity::DirWritable, "{bad:o}");
            assert_eq!(error.fix(), format!("chmod 755 {}", f.sys_dir().display()));
        }
    }

    #[test]
    fn a_system_folder_that_is_a_symlink_is_refused() {
        let f = Fixture::new(1000);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        let real = f.root.path().join("sys").join("real");
        fs::rename(f.sys_dir(), &real).expect("rename");
        symlink(&real, f.sys_dir()).expect("symlink");
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirSymlink);
    }

    #[test]
    fn a_system_folder_that_is_a_file_is_refused() {
        let f = Fixture::new(1000);
        fs::create_dir_all(f.root.path().join("sys")).expect("mkdir");
        fs::write(f.sys_dir(), "x").expect("write");
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirNotDirectory);
    }

    #[test]
    fn a_folder_or_a_pipe_is_not_a_store_and_is_not_read() {
        let f = Fixture::new(1000);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        fs::remove_file(f.sys_file()).expect("rm");
        fs::create_dir(f.sys_file()).expect("mkdir");
        mode(&f.sys_file(), 0o755);
        assert_eq!(
            insecure(&load(&f.layout()).expect_err("dir")),
            Insecurity::NotRegular
        );
        fs::remove_dir(f.sys_file()).expect("rmdir");
        let made = std::process::Command::new("mkfifo")
            .arg(f.sys_file())
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        // The open does not block on a pipe with no writer, and the type is checked before any read.
        let started = std::time::Instant::now();
        assert_eq!(
            insecure(&load(&f.layout()).expect_err("fifo")),
            Insecurity::NotRegular
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn a_device_is_not_a_store_and_is_not_read() {
        // INV-02. `/dev/zero` never ends. The read is already capped, so this test does not rely on the
        // cap. It proves the type check refuses a device before any read. Its folder is `/dev`, which
        // root owns, so the folder passes and the type check is what refuses it.
        let f = Fixture::new(1000);
        let layout = f.layout().with_system_file(PathBuf::from("/dev/zero"), 0);
        let started = std::time::Instant::now();
        assert_eq!(
            insecure(&load(&layout).expect_err("device")),
            Insecurity::NotRegular
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn a_store_over_256_kib_is_refused_and_one_at_the_limit_is_not_too_large() {
        let f = Fixture::new(1000);
        f.write_system(&"#".repeat(MAX_TRUST_BYTES + 1));
        let error = load(&f.layout()).expect_err("too large");
        assert!(
            matches!(
                error,
                TrustStoreError::Invalid {
                    source: TrustFileError::TooLarge { .. },
                    ..
                }
            ),
            "{error:?}"
        );
        f.write_system(&"#".repeat(MAX_TRUST_BYTES));
        let error = load(&f.layout()).expect_err("not a store");
        assert!(
            !matches!(
                error,
                TrustStoreError::Invalid {
                    source: TrustFileError::TooLarge { .. },
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn an_invalid_store_names_its_file_and_stops_the_load() {
        let f = Fixture::new(user_euid());
        f.write_user("apiVersion: rdy/v1\nkind: TrustStore\nbogus: 1\nkeys: []\n");
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        let error = load(&f.layout()).expect_err("invalid");
        assert_eq!(error.file(), Some(f.user_file().as_path()));
        assert!(error.location().is_some());
        assert_eq!(error.code(), ErrorCode::Usage);
        assert!(error.fix().contains("rdy trust list"));
    }

    #[test]
    fn save_writes_the_user_store_with_private_modes_and_reads_back() {
        let f = Fixture::new(user_euid());
        let layout = f.layout();
        let text = trust_text("acme-platform", KEY_A, Some("a note: with \\\"quotes\\\""));
        let store = TrustStore::from_yaml(text.as_bytes(), TrustSource::User).expect("parse");
        let path = save(&layout, &store).expect("saves");
        assert_eq!(path, f.user_file());
        let meta = fs::metadata(&path).expect("meta");
        assert_eq!(meta.mode() & 0o777, 0o600);
        let dir_meta = fs::metadata(path.parent().expect("parent")).expect("meta");
        assert_eq!(dir_meta.mode() & 0o777, 0o700);
        assert_eq!(load_scope(&layout, Scope::User).expect("loads"), store);
        // Saving again replaces the file and leaves no temporary file behind.
        save(&layout, &store).expect("saves again");
        let names: Vec<String> = fs::read_dir(path.parent().expect("parent"))
            .expect("ls")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["trust.yaml"]);
    }

    #[test]
    fn save_as_root_writes_the_system_store_with_mode_0644_and_creates_its_folder() {
        let f = Fixture::new(0);
        fs::create_dir_all(f.root.path().join("sys")).expect("mkdir");
        let layout = f.layout();
        let store = TrustStore::from_yaml(
            trust_text("acme-platform", KEY_A, None).as_bytes(),
            TrustSource::System,
        )
        .expect("parse");
        let path = save(&layout, &store).expect("saves");
        assert_eq!(path, f.sys_file());
        assert_eq!(fs::metadata(&path).expect("meta").mode() & 0o777, 0o644);
        assert_eq!(
            fs::metadata(f.sys_dir()).expect("meta").mode() & 0o777,
            0o755
        );
        assert_eq!(load_scope(&layout, Scope::System).expect("loads"), store);
        // No user path was made.
        assert!(!f.home().exists());
    }

    #[test]
    fn save_does_not_replace_a_store_that_would_be_refused() {
        let f = Fixture::new(user_euid());
        f.write_user(&trust_text("acme-platform", KEY_B, None));
        mode(&f.user_file(), 0o666);
        let before = fs::read(f.user_file()).expect("read");
        let store = TrustStore::new();
        let error = save(&f.layout(), &store).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::Writable);
        assert_eq!(fs::read(f.user_file()).expect("read"), before);
    }

    #[test]
    fn save_refuses_a_system_folder_that_others_can_write() {
        let f = Fixture::new(0);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        mode(&f.sys_dir(), 0o777);
        let error = save(&f.layout(), &TrustStore::new()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::DirWritable);
    }

    #[test]
    fn save_without_a_home_says_where_to_look() {
        let layout = Layout::from_env(&Vars::default(), 1000);
        let error = save(&layout, &TrustStore::new()).expect_err("no place");
        assert!(matches!(error, TrustStoreError::NoUserStore));
        assert!(error.fix().contains("HOME"));
    }

    #[test]
    fn a_one_run_key_is_not_saved() {
        let f = Fixture::new(user_euid());
        let key = rdy_spec::sig::PublicKey::from_base64(KEY_A).expect("key");
        let mut store = TrustStore::new();
        store.pin(
            rdy_spec::spec::ProductSlug::new("acme-platform").expect("slug"),
            key,
            TrustSource::Flag,
        );
        let path = save(&f.layout(), &store).expect("saves");
        let text = fs::read_to_string(path).expect("read");
        assert!(!text.contains(KEY_A), "{text}");
    }
}

/// Without Unix modes and owners, a store that exists is refused and a missing one is empty. A temp
/// folder stands in for `C:\ProgramData` through `Vars::program_data`. These are the exit test of M1-122
/// on Windows: a store that exists exits 64 with `trust_store_insecure`, whoever made it. A hosted CI
/// runner user is an administrator, so these tests cannot make a non-admin store. They show that no
/// store passes, which covers the non-admin case, and that a Users write ACE changes nothing.
#[cfg(not(unix))]
mod other {
    use super::*;

    const EMPTY: &str = "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n";

    fn layout(dir: &tempfile::TempDir) -> Layout {
        let v = Vars {
            program_data: Some(dir.path().as_os_str().to_owned()),
            ..vars(dir.path().to_str(), dir.path().join(".config").to_str())
        };
        Layout::from_env(&v, 0)
    }

    fn make_store(layout: &Layout) -> PathBuf {
        let path = layout
            .path(Scope::System)
            .expect("system path")
            .to_path_buf();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, EMPTY).expect("write");
        path
    }

    fn assert_refused(layout: &Layout) {
        match load(layout) {
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        TrustStoreError::Insecure {
                            why: Insecurity::Unverifiable,
                            scope: Scope::System,
                            ..
                        }
                    ),
                    "{error:?}"
                );
                assert_eq!(error.code(), ErrorCode::TrustStoreInsecure);
                assert_eq!(error.code().exit_code().code(), 64);
                assert!(!error.fix().is_empty());
            }
            Ok(store) => panic!("a Windows store was read: {store:?}"),
        }
    }

    #[test]
    fn a_missing_store_is_empty_and_there_is_no_user_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = layout(&dir);
        assert_eq!(layout.path(Scope::User), None);
        assert_eq!(load(&layout).expect("missing is empty"), TrustStore::new());
        // A folder that exists with no file in it is still an empty store.
        std::fs::create_dir_all(dir.path().join("rdy")).expect("mkdir");
        assert_eq!(load(&layout).expect("empty folder"), TrustStore::new());
    }

    #[test]
    fn a_store_made_by_the_current_user_is_refused() {
        // The temp folder and the file belong to the user who runs the test. On a hosted runner that user
        // is an administrator and the store is still refused, because nothing is verified.
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = layout(&dir);
        make_store(&layout);
        assert_refused(&layout);
    }

    #[cfg(windows)]
    #[test]
    fn the_real_environment_gives_no_user_path() {
        // A hosted runner has a real %APPDATA%, so the detected layout is what proves it is not used.
        let layout = Layout::detect();
        assert_eq!(layout.path(Scope::User), None);
    }

    /// Grants the Users group write access (S-1-5-32-545, so it works in any language) with `icacls`,
    /// which every Windows image has. The store must still be refused.
    #[cfg(windows)]
    #[test]
    fn a_store_with_a_users_write_ace_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = layout(&dir);
        let path = make_store(&layout);
        for target in [path.parent().expect("parent"), path.as_path()] {
            let status = std::process::Command::new("icacls")
                .arg(target)
                .args(["/grant", "*S-1-5-32-545:(W)"])
                .status()
                .expect("icacls runs");
            assert!(status.success(), "icacls failed: {status}");
        }
        assert_refused(&layout);
    }

    #[test]
    fn saving_is_unsupported_even_without_a_place_to_write() {
        let layout = Layout::from_env(&Vars::default(), 0);
        assert!(matches!(
            save(&layout, &TrustStore::new()),
            Err(TrustStoreError::Unsupported)
        ));
    }

    #[test]
    fn saving_is_unsupported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = layout(&dir);
        assert!(matches!(
            save(&layout, &TrustStore::new()),
            Err(TrustStoreError::Unsupported)
        ));
    }
}
