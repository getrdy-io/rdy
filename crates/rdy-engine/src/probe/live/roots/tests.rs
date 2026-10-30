//! The rule that decides whether `rustls-native-certs` may be asked for the OS store.

use std::ffi::OsStr;

use super::overrides;

#[test]
fn the_os_store_is_asked_only_when_the_crate_would_not_read_a_variable() {
    let some = |text: &'static str| Some(OsStr::new(text));
    // Neither variable: the OS store.
    assert!(!overrides(None, None));
    // `SSL_CERT_FILE` counts when it is set at all, even empty: the crate would try to read "".
    assert!(overrides(some("/etc/ssl/ca.pem"), None));
    assert!(overrides(some(""), None));
    // `SSL_CERT_DIR` counts when it names a directory. Empty entries are dropped, as the crate drops them.
    assert!(overrides(None, some("/etc/ssl/certs")));
    assert!(!overrides(None, some("")));
    // The list separator is `:` on Unix and `;` on Windows.
    let sep = if cfg!(windows) { ";" } else { ":" };
    assert!(!overrides(None, Some(OsStr::new(sep))));
    assert!(overrides(None, Some(OsStr::new(&format!("a{sep}b")))));
    assert!(overrides(some(""), Some(OsStr::new(sep))));
}
