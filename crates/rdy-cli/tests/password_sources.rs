//! The CI paths for a key password through the public helper (M1-112): the variable and
//! `--password-file -` give a password with no prompt. `spec sign` itself is M1-125.

use std::ffi::OsString;
use std::io::Cursor;
use std::path::Path;

use rdy_cli::password::{
    KeyPassword, MAX_PASSWORD_BYTES, Origin, PasswordError, read_key_password_from,
};

fn read(
    file: Option<&Path>,
    env: Option<&str>,
    stdin: &[u8],
) -> Result<Option<KeyPassword>, PasswordError> {
    let env = env.map(OsString::from);
    read_key_password_from(
        file,
        env,
        &mut Cursor::new(stdin.to_vec()),
        &mut std::io::sink(),
    )
}

fn password(result: Result<Option<KeyPassword>, PasswordError>) -> String {
    match result {
        Ok(Some(p)) => p.expose().to_string(),
        other => panic!("want a password, got {other:?}"),
    }
}

#[test]
fn the_variable_gives_a_password_without_a_prompt() {
    assert_eq!(password(read(None, Some("ci-secret"), b"")), "ci-secret");
}

#[test]
fn password_file_dash_reads_standard_input() {
    let got = read(Some(Path::new("-")), None, b"ci-secret\n");
    assert_eq!(password(got), "ci-secret");
}

#[test]
fn no_source_means_the_caller_prompts() {
    assert!(matches!(read(None, None, b"ignored"), Ok(None)));
}

#[test]
fn a_too_large_standard_input_is_refused() {
    let big = vec![b'x'; MAX_PASSWORD_BYTES * 100];
    let e = read(Some(Path::new("-")), None, &big).err();
    assert!(
        matches!(e, Some(PasswordError::TooLarge(Origin::Stdin))),
        "{e:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_file_is_read_when_private_and_refused_when_not() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let path = dir.path().join("pw");
    std::fs::write(&path, "ci-secret\n").unwrap_or_else(|e| panic!("write: {e}"));
    let set = |mode| {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod: {e}"));
    };
    set(0o600);
    assert_eq!(password(read(Some(&path), None, b"")), "ci-secret");
    set(0o644);
    let e = read(Some(&path), None, b"").err();
    assert!(matches!(e, Some(PasswordError::TooOpen(_))), "{e:?}");
}
