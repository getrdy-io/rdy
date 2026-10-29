//! Blocking helper tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;

#[tokio::test]
async fn returns_the_value() {
    let got = blocking(|| Ok(21 * 2)).await;
    assert_eq!(got, Ok(42));
}

#[tokio::test]
async fn passes_the_error_through() {
    let got: Result<(), CheckError> = blocking(|| Err(CheckError::Unsupported("no source"))).await;
    assert_eq!(got, Err(CheckError::Unsupported("no source")));
}

#[tokio::test]
async fn a_panic_is_resumed_in_the_caller() {
    let task = tokio::spawn(async {
        let _: Result<(), CheckError> = blocking(|| panic!("blocking boom")).await;
    });
    let error = task.await.expect_err("the task panics");
    assert!(error.is_panic());
    let payload = error.into_panic();
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"blocking boom"));
}

#[tokio::test]
async fn nothing_runs_before_the_first_poll() {
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let future = blocking(move || {
        flag.store(true, Ordering::SeqCst);
        Ok(())
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!ran.load(Ordering::SeqCst));
    future.await.expect("runs");
    assert!(ran.load(Ordering::SeqCst));
}
