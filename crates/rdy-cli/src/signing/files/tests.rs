//! Tests for key file opening and creation. The mode checks run on Unix. Windows runs the type checks.

use super::*;
use crate::error::IoReason;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod: {e}"));
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat: {e}"))
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn a_private_regular_file_is_read() {
    let d = dir();
    let path = d.path().join("k");
    std::fs::write(&path, "key text").expect("write");
    #[cfg(unix)]
    set_mode(&path, 0o600);
    assert_eq!(&**read_private(&path, 64).expect("read"), b"key text");
}

#[test]
fn a_missing_file_is_unreadable_with_a_plain_reason() {
    let d = dir();
    let err = read_private(&d.path().join("nope"), 64).unwrap_err();
    assert!(matches!(
        err,
        FileError::Unreadable {
            reason: IoReason::NoSuchFile
        }
    ));
}

#[test]
fn a_folder_is_not_a_regular_file() {
    let d = dir();
    let err = read_private(d.path(), 64).unwrap_err();
    assert!(
        matches!(err, FileError::NotRegular | FileError::Unreadable { .. }),
        "{err:?}"
    );
}

#[test]
fn a_file_over_the_cap_is_refused_without_reading_it_all() {
    let d = dir();
    let path = d.path().join("k");
    std::fs::write(&path, vec![b'x'; 65]).expect("write");
    #[cfg(unix)]
    set_mode(&path, 0o600);
    assert!(matches!(
        read_private(&path, 64).unwrap_err(),
        FileError::TooLarge
    ));
    assert!(read_private(&path, 65).is_ok());
}

#[cfg(unix)]
#[test]
fn any_group_or_other_access_is_refused() {
    let d = dir();
    let path = d.path().join("k");
    std::fs::write(&path, "key").expect("write");
    for mode in [
        0o640, 0o604, 0o644, 0o660, 0o606, 0o666, 0o610, 0o601, 0o602, 0o620,
    ] {
        set_mode(&path, mode);
        assert!(
            matches!(read_private(&path, 64).unwrap_err(), FileError::TooOpen),
            "{mode:o}"
        );
    }
    for mode in [0o600, 0o400] {
        set_mode(&path, mode);
        assert!(read_private(&path, 64).is_ok(), "{mode:o}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_is_refused_even_to_a_good_file() {
    let d = dir();
    let real = d.path().join("real");
    std::fs::write(&real, "key").expect("write");
    set_mode(&real, 0o600);
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    assert!(matches!(
        read_private(&link, 64).unwrap_err(),
        FileError::Symlink
    ));
}

#[cfg(unix)]
#[test]
fn a_named_pipe_is_refused_and_does_not_block() {
    let d = dir();
    let fifo = d.path().join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|s| s.success());
    if made.unwrap_or(false) {
        set_mode(&fifo, 0o600);
        assert!(matches!(
            read_private(&fifo, 64).unwrap_err(),
            FileError::NotRegular
        ));
    }
}

#[test]
fn create_new_never_replaces_a_file() {
    let d = dir();
    let path = d.path().join("k");
    drop(create_new_private(&path).expect("first"));
    let err = create_new_private(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    let err = create_new_public(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
}

#[cfg(unix)]
#[test]
fn create_new_does_not_follow_a_symlink_even_a_dangling_one() {
    let d = dir();
    let link = d.path().join("link");
    std::os::unix::fs::symlink(d.path().join("target"), &link).expect("symlink");
    let err = create_new_private(&link).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert!(!d.path().join("target").exists());
}

#[cfg(unix)]
#[test]
fn a_new_private_file_is_owner_only_from_the_first_byte() {
    let d = dir();
    let path = d.path().join("k");
    let file = create_new_private(&path).expect("create");
    // Checked on the open handle, before anything is written.
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata().expect("stat").permissions().mode() & 0o7777;
    assert_eq!(mode & 0o077, 0, "{mode:o}");
    assert_eq!(mode_of(&path) & 0o077, 0);
}

#[test]
fn write_and_sync_writes_everything() {
    let d = dir();
    let path = d.path().join("k");
    let mut file = create_new_public(&path).expect("create");
    write_and_sync(&mut file, b"hello").expect("write");
    assert_eq!(std::fs::read(&path).expect("read"), b"hello");
}

#[test]
fn a_public_file_is_read_whatever_its_mode() {
    let d = dir();
    let path = d.path().join("k.pub");
    std::fs::write(&path, "public text").expect("write");
    #[cfg(unix)]
    set_mode(&path, 0o644);
    assert_eq!(read_public(&path, 64).expect("read"), b"public text");
}

#[cfg(unix)]
#[test]
fn a_public_file_may_be_a_symlink_to_a_regular_file() {
    let d = dir();
    let real = d.path().join("real.pub");
    std::fs::write(&real, "public text").expect("write");
    let link = d.path().join("link.pub");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    assert_eq!(read_public(&link, 64).expect("read"), b"public text");
}

#[test]
fn a_public_file_that_is_missing_a_folder_or_too_large_is_refused() {
    let d = dir();
    let err = read_public(&d.path().join("nope"), 64).unwrap_err();
    assert!(matches!(
        err,
        FileError::Unreadable {
            reason: IoReason::NoSuchFile
        }
    ));
    assert!(matches!(
        read_public(d.path(), 64).unwrap_err(),
        FileError::NotRegular | FileError::Unreadable { .. }
    ));
    let big = d.path().join("big");
    std::fs::write(&big, vec![b'a'; 65]).expect("write");
    assert!(matches!(
        read_public(&big, 64).unwrap_err(),
        FileError::TooLarge
    ));
    std::fs::write(&big, vec![b'a'; 64]).expect("write");
    assert_eq!(read_public(&big, 64).expect("exactly the cap").len(), 64);
}

#[cfg(unix)]
#[test]
fn a_named_pipe_is_refused_and_does_not_hang() {
    let d = dir();
    let path = d.path().join("fifo");
    // `rustix` has no `mknodat` on Apple targets. `mkfifo` is on every Unix CI image.
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo runs");
    assert!(made.success());
    assert!(matches!(
        read_public(&path, 64).unwrap_err(),
        FileError::NotRegular
    ));
}

#[cfg(unix)]
#[test]
fn a_device_is_refused_by_stat_and_a_link_to_one_too() {
    // /dev/null is a character device on every Unix. The refusal comes from `stat`, before any open.
    assert!(matches!(
        read_public(Path::new("/dev/null"), 64).unwrap_err(),
        FileError::NotRegular
    ));
    let d = dir();
    let link = d.path().join("null.pub");
    std::os::unix::fs::symlink("/dev/null", &link).expect("symlink");
    assert!(matches!(
        read_public(&link, 64).unwrap_err(),
        FileError::NotRegular
    ));
}

#[cfg(unix)]
#[test]
fn a_unix_socket_is_refused_by_stat_not_by_a_failed_open() {
    // Opening a socket fails with ENXIO, so code that opens first reports it as unreadable. Only a
    // `stat` before the open can say it is not a regular file.
    let d = dir();
    let path = d.path().join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    assert!(matches!(
        read_public(&path, 64).unwrap_err(),
        FileError::NotRegular
    ));
}

#[cfg(unix)]
#[test]
fn a_handle_that_is_not_the_file_stat_saw_is_refused() {
    let d = dir();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    std::fs::write(&a, "one").expect("write");
    std::fs::write(&b, "two").expect("write");
    let seen = std::fs::metadata(&a).expect("stat");
    let other = File::open(&b).expect("open").metadata().expect("fstat");
    let same = File::open(&a).expect("open").metadata().expect("fstat");
    assert!(!same_file(&seen, &other));
    assert!(same_file(&seen, &same));
}
