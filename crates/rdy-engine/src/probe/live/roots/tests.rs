//! The rule that decides whether `rustls-native-certs` may be asked for the OS store.

use std::ffi::OsStr;
use std::io;

use super::{guarded, overrides};

#[test]
fn the_os_store_is_asked_only_when_neither_variable_is_set() {
    let some = |text: &'static str| Some(OsStr::new(text));
    // Neither variable: the OS store.
    assert!(!overrides(None, None));
    // Either variable set at all counts, even empty: every 0.8.x rule of the crate reads at least that.
    assert!(overrides(some("/etc/ssl/ca.pem"), None));
    assert!(overrides(some(""), None));
    assert!(overrides(None, some("/etc/ssl/certs")));
    assert!(overrides(None, some("")));
    assert!(overrides(some(""), some("")));
}

#[test]
fn a_panic_in_the_os_store_read_is_an_error_and_not_a_crash() {
    let error = guarded(|| -> io::Result<Vec<Vec<u8>>> { panic!("the reader unwrapped") })
        .expect_err("a panic is an error");
    assert_eq!(error.to_string(), "the OS trust store could not be read");
    // A read that does not panic passes through, answer or error.
    assert_eq!(guarded(|| Ok(vec![vec![1u8]])).expect("ok"), [vec![1u8]]);
    let kept = guarded(|| -> io::Result<()> { Err(io::Error::other("no")) }).expect_err("error");
    assert_eq!(kept.to_string(), "no");
}
