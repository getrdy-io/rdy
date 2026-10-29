//! The blocking helper: runs CPU-bound or blocking work off the async workers.
//!
//! Checks do no blocking work themselves (02, "Checks, families and the run plan"). When one has pure
//! CPU work over a big input, it calls [`blocking`]. The closure runs on tokio's blocking pool and the
//! returned future resolves with its result.
//!
//! Two limits, both from tokio, shape how to use it:
//!
//! - **A blocking thread cannot be stopped.** If the scheduler aborts the check at its timeout, the
//!   future returned here is dropped, but the closure keeps running until it returns. Keep closures
//!   short and bounded by their input.
//! - **Never start a process from a blocking closure.** An abandoned thread cannot kill its child.
//!   Run commands through [`crate::exec`], which kills the whole process group when its future is
//!   dropped, on timeout or on abort.
//!
//! A panic in the closure is resumed in the awaiting task, so the scheduler reports the check as
//! panicked, the same as a panic in the check's own code.

use crate::check::{BoxFuture, CheckError};

/// Runs `f` on the blocking pool and returns its result.
///
/// Nothing runs until the future is first polled. It must be polled inside a tokio runtime.
///
/// # Panics
///
/// Resumes the closure's panic in the caller, so the scheduler's panic isolation handles it.
pub fn blocking<T, F>(f: F) -> BoxFuture<'static, Result<T, CheckError>>
where
    F: FnOnce() -> Result<T, CheckError> + Send + 'static,
    T: Send + 'static,
{
    Box::pin(async move {
        match tokio::task::spawn_blocking(f).await {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(CheckError::Failed {
                message: "the blocking work was cancelled because the runtime is shutting down"
                    .to_owned(),
                hint: "Run the command again.".to_owned(),
            }),
        }
    })
}

#[cfg(test)]
mod tests;
