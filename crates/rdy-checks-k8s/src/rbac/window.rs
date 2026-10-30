//! Runs futures a few at a time, on the task that polls it.
//!
//! `k8s.rbac` sends up to 100 reviews, 8 at a time (03). A check starts no task of its own, so this polls
//! a sliding window of futures from one `poll_fn`. A finished future makes room for the next one at once.
//! Results come back in the order the futures were given.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// Polls `jobs` with at most `limit` in flight, and returns their outputs in the order of `jobs`.
///
/// A job is not created until a slot is free, so a lazy iterator costs nothing for the jobs it has not
/// yielded. `limit` of 0 is treated as 1.
pub(super) async fn windowed<F, I>(limit: usize, jobs: I) -> Vec<F::Output>
where
    F: Future,
    I: IntoIterator<Item = F>,
{
    let limit = limit.max(1);
    let mut jobs = jobs.into_iter();
    let mut active: Vec<(usize, Pin<Box<F>>)> = Vec::with_capacity(limit);
    let mut done: Vec<(usize, F::Output)> = Vec::new();
    let mut started = 0;
    poll_fn(|cx| {
        loop {
            while active.len() < limit {
                let Some(job) = jobs.next() else { break };
                active.push((started, Box::pin(job)));
                started += 1;
            }
            if active.is_empty() {
                return Poll::Ready(());
            }
            let mut finished = false;
            let mut at = 0;
            while at < active.len() {
                match active[at].1.as_mut().poll(cx) {
                    Poll::Ready(output) => {
                        let (index, _) = active.swap_remove(at);
                        done.push((index, output));
                        finished = true;
                    }
                    Poll::Pending => at += 1,
                }
            }
            if !finished {
                return Poll::Pending;
            }
        }
    })
    .await;
    done.sort_by_key(|(index, _)| *index);
    done.into_iter().map(|(_, output)| output).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::future::Future;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};

    use super::windowed;

    /// Returns `Pending` this many times (waking itself each time), then `Ready`.
    struct Turns(u32);

    impl Future for Turns {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 == 0 {
                return Poll::Ready(());
            }
            self.0 -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[derive(Default)]
    struct Seen {
        live: Cell<usize>,
        peak: Cell<usize>,
        /// `(id, jobs in flight when it started)`.
        starts: RefCell<Vec<(usize, usize)>>,
    }

    async fn job(id: usize, turns: u32, seen: Rc<Seen>) -> usize {
        seen.live.set(seen.live.get() + 1);
        seen.peak.set(seen.peak.get().max(seen.live.get()));
        seen.starts.borrow_mut().push((id, seen.live.get()));
        Turns(turns).await;
        seen.live.set(seen.live.get() - 1);
        id
    }

    #[tokio::test]
    async fn at_most_the_limit_run_at_once_and_results_keep_their_order() {
        let seen = Rc::new(Seen::default());
        // The first job is slow, so the later ones finish before it.
        let out = windowed(
            3,
            (0..10).map(|id| job(id, if id == 0 { 50 } else { 2 }, seen.clone())),
        )
        .await;
        assert_eq!(out, (0..10).collect::<Vec<_>>());
        assert_eq!(seen.peak.get(), 3, "the window was full and never over");
        assert_eq!(seen.live.get(), 0);
    }

    #[tokio::test]
    async fn a_finished_job_makes_room_at_once() {
        let seen = Rc::new(Seen::default());
        // Two slots. Job 0 stays for a long time, so every later job runs in the other slot, and each one
        // starts as soon as the one before it is done: the window is full whenever a job starts.
        let _ = windowed(
            2,
            (0..5).map(|id| job(id, if id == 0 { 100 } else { 1 }, seen.clone())),
        )
        .await;
        let starts = seen.starts.borrow();
        assert_eq!(starts.len(), 5);
        assert!(
            starts.iter().skip(1).all(|(_, live)| *live == 2),
            "{starts:?}"
        );
    }

    #[tokio::test]
    async fn no_jobs_and_a_zero_limit_are_fine() {
        let none: Vec<u8> = windowed(0, Vec::<std::future::Ready<u8>>::new()).await;
        assert!(none.is_empty());
        let one = windowed(0, [std::future::ready(7)]).await;
        assert_eq!(one, [7]);
    }
}
