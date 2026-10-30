//! The two small adapters between hyper and the facade's streams. Safe code only.
//!
//! hyper has its own `Read` and `Write` traits. [`Io`] lends a tokio stream to hyper through them,
//! reading into a stack buffer and copying with `put_slice`, so it needs no `unsafe`. [`NoBody`] is the
//! body of a request that has none.

use std::convert::Infallible;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::{Body, Frame, SizeHint};
use hyper::rt::{Read, ReadBufCursor, Write};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most bytes one read takes from the stream.
const CHUNK: usize = 16 * 1024;

/// A tokio stream that hyper can read and write.
pub(super) struct Io<T>(T);

impl<T> Io<T> {
    pub(super) fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: AsyncRead + Unpin> Read for Io<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut scratch = [0_u8; CHUNK];
        let want = buf.remaining().min(CHUNK);
        let mut read = ReadBuf::new(&mut scratch[..want]);
        match Pin::new(&mut self.0).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for Io<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
}

/// The body of a `GET` or `HEAD`: empty, and known to be.
pub(super) struct NoBody;

impl Body for NoBody {
    type Data = &'static [u8];
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(0)
    }
}
