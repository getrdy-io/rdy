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

fn vars(home: Option<&str>, xdg: Option<&str>) -> Vars {
    Vars {
        home: home.and_then(os),
        xdg_config_home: xdg.and_then(os),
        appdata: None,
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
    for v in [
        vars(Some("/home/alice"), Some("/home/alice/.config")),
        vars(Some("/root"), None),
        vars(None, Some("/home/alice/.config")),
        vars(None, None),
    ] {
        let layout = Layout::from_env(&v, 0);
        assert_eq!(layout.path(Scope::User), None, "{v:?}");
        assert_eq!(layout.path(Scope::System), Some(Path::new(SYSTEM_STORE)));
        assert_eq!(layout.write_scope(), Scope::System);
    }
}

#[test]
fn a_user_run_reads_xdg_then_home_config_then_the_system_store() {
    let layout = Layout::from_env(&vars(Some("/home/alice"), Some("/xdg")), 1000);
    assert_eq!(
        layout.path(Scope::User),
        Some(Path::new("/xdg/rdy/trust.yaml"))
    );
    let layout = Layout::from_env(&vars(Some("/home/alice"), None), 1000);
    assert_eq!(
        layout.path(Scope::User),
        Some(Path::new("/home/alice/.config/rdy/trust.yaml"))
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
        let layout = Layout::from_env(&v, 1000);
        assert_eq!(layout.path(Scope::User), None, "{v:?}");
    }
    // An empty or relative XDG value is ignored, as the XDG spec says, and HOME is used.
    let layout = Layout::from_env(&vars(Some("/home/alice"), Some("relative")), 1000);
    assert_eq!(
        layout.path(Scope::User),
        Some(Path::new("/home/alice/.config/rdy/trust.yaml"))
    );
}

#[test]
fn the_windows_layout_uses_appdata_and_programdata() {
    let v = Vars {
        appdata: os("/appdata"),
        program_data: os("/programdata"),
        ..Vars::default()
    };
    let layout = Layout::windows(&v);
    assert_eq!(
        layout.path(Scope::User),
        Some(Path::new("/appdata/rdy/trust.yaml"))
    );
    assert_eq!(
        layout.path(Scope::System),
        Some(Path::new("/programdata/rdy/trust.yaml"))
    );
    // Elevation cannot be told here, so a Windows run writes the user store.
    assert_eq!(layout.write_scope(), Scope::User);
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
            let v = vars(self.home().to_str(), None);
            Layout::from_env(&v, self.euid).with_system_file(self.sys_file(), owner)
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
            fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
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
    fn a_real_root_process_has_no_user_path_whatever_its_environment_is() {
        // Only meaningful when the tests run as root (the sudo leg of INV-04). The process environment is
        // whatever it is, with a HOME and perhaps an XDG_CONFIG_HOME, and a root layout ignores both.
        if me() != 0 {
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
        // Giving a file to another user needs root, so this runs only when the tests run as root. The
        // folder stays root's, so the file is the one that fails.
        if me() != 0 {
            return;
        }
        let f = Fixture::new(1000);
        f.write_system(&trust_text("acme-platform", KEY_A, None));
        std::os::unix::fs::chown(f.sys_file(), Some(4242), None).expect("chown");
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::NotOwned);
        assert!(error.to_string().contains("not owned by root"), "{error}");
    }

    #[test]
    fn a_user_store_owned_by_another_user_is_refused() {
        // Root may own a user store, so there is nothing to refuse when the tests run as root.
        if me() == 0 {
            return;
        }
        let f = Fixture::new(me().wrapping_add(1));
        f.write_user(&trust_text("acme-platform", KEY_A, None));
        let error = load(&f.layout()).expect_err("refused");
        assert_eq!(insecure(&error), Insecurity::NotOwned);
        assert!(error.to_string().contains("another user"), "{error}");
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
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
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

/// Without Unix modes and owners, a store that exists is refused and a missing one is empty.
#[cfg(not(unix))]
mod other {
    use super::*;

    #[test]
    fn an_existing_store_is_unverifiable_and_saving_is_unsupported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let v = Vars {
            appdata: Some(dir.path().as_os_str().to_owned()),
            program_data: Some(dir.path().as_os_str().to_owned()),
            ..Vars::default()
        };
        let layout = Layout::from_env(&v, 0);
        assert_eq!(load(&layout).expect("missing is empty"), TrustStore::new());
        let path = layout.path(Scope::User).expect("user path").to_path_buf();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n").expect("write");
        match load(&layout) {
            Err(TrustStoreError::Insecure {
                why: Insecurity::Unverifiable,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            save(&layout, &TrustStore::new()),
            Err(TrustStoreError::Unsupported)
        ));
    }
}
