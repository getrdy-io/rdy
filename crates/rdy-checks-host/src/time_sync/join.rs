//! Running a few futures at once without a runtime dependency.
//!
//! `host.time_sync` asks `timedatectl`, `chronyc` and up to eight time servers. Run one after the other
//! they could need more than the check's 5 s, so they are polled together. The futures are polled in
//! the order they are given, so a fixture run logs in a fixed order.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// Waits for both futures.
pub(crate) async fn join2<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = Box::pin(a);
    let mut b = Box::pin(b);
    let mut done_a = None;
    let mut done_b = None;
    poll_fn(move |cx| {
        if done_a.is_none()
            && let Poll::Ready(value) = a.as_mut().poll(cx)
        {
            done_a = Some(value);
        }
        if done_b.is_none()
            && let Poll::Ready(value) = b.as_mut().poll(cx)
        {
            done_b = Some(value);
        }
        if done_a.is_some()
            && done_b.is_some()
            && let (Some(x), Some(y)) = (done_a.take(), done_b.take())
        {
            return Poll::Ready((x, y));
        }
        Poll::Pending
    })
    .await
}

/// Waits for every future and returns the outputs in the order the futures were given.
pub(crate) async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut pending: Vec<Option<Pin<Box<F>>>> =
        futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut done: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    poll_fn(move |cx| {
        let mut waiting = false;
        for (slot, out) in pending.iter_mut().zip(done.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        *out = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => waiting = true,
                }
            }
        }
        if waiting {
            Poll::Pending
        } else {
            Poll::Ready(done.iter_mut().filter_map(Option::take).collect())
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A future that is pending `n` times and then gives `value`.
    fn after<T>(n: usize, value: T) -> impl Future<Output = T> {
        let mut left = n;
        let mut value = Some(value);
        poll_fn(move |cx| {
            if left == 0 {
                match value.take() {
                    Some(v) => Poll::Ready(v),
                    None => Poll::Pending,
                }
            } else {
                left -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
    }

    #[tokio::test]
    async fn join2_waits_for_the_slower_future() {
        assert_eq!(join2(after(3, 1), after(0, "b")).await, (1, "b"));
    }

    #[tokio::test]
    async fn join_all_keeps_the_given_order() {
        let out = join_all(vec![after(5, 'a'), after(0, 'b'), after(2, 'c')]).await;
        assert_eq!(out, ['a', 'b', 'c']);
        assert!(
            join_all(Vec::<std::future::Ready<u8>>::new())
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_futures_make_progress_together() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counted = |polls: Arc<AtomicUsize>| async move {
            after(2, ()).await;
            polls.fetch_add(1, Ordering::SeqCst);
        };
        join_all(vec![counted(polls.clone()), counted(polls.clone())]).await;
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }
}
