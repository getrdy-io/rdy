//! The live backend: reads real files and the real environment (ADR 0014, 02 "Files").
//!
//! [`live_backend`] is the only way to get it. Check crates may not call it (it is on their clippy
//! deny list); the engine and the CLI do.
//!
//! **How a file is opened.** The probe has already refused the path as written. This module then
//! settles what the path really is, without running anything on it, and decides again:
//!
//! 1. Linux: open the path with `O_PATH`. That follows links, opens no device and blocks on no FIFO.
//!    Read the real path from `/proc/self/fd/<n>`, run [`ReadGuard::admit_real`] on it, and `fstat` the
//!    descriptor. A FIFO, socket, device or directory is refused here, before anything opens it.
//! 2. Open the same descriptor again through `/proc/self/fd/<n>` with `O_RDONLY | O_NONBLOCK`, and
//!    `fstat` the result. It must be the same file (device and inode) as the first. A rename or a link
//!    swap after step 1 cannot change which file is read, because the check and the read share one
//!    inode.
//!
//! macOS has no `O_PATH`: the path is resolved with `realpath` and the real path is checked. It is then
//! opened with `O_NOFOLLOW_ANY` (no link anywhere along the path, so a directory swapped for a link
//! after the check cannot redirect the open), the type is read from the descriptor with `fstat`, and
//! the path of the descriptor (`F_GETPATH`) is judged again. The descriptor must have the same device
//! and inode as the first look. A file with no names left (`st_nlink` of 0) is refused, and so is any
//! file with the device and inode of a password or sudo file, whatever its name. Windows has no file
//! reads in M1: every file call fails with a typed error.
//!
//! **Sockets (M1-144).** `resolve`, `udp_exchange` and `unix_get` do the socket work and nothing else:
//! the probe has already applied the peer, address and path policy. A datagram is read into a
//! 65535-byte buffer and cut to the cap here. A unix socket reply is read by a small HTTP/1.x client
//! (`dockerhttp`) that sends one fixed `GET`. The unix socket is not built on Windows.
//!
//! **Bounds.** A read returns at most `MAX_READ` bytes. A directory listing holds at most
//! `MAX_DIR_ENTRIES` entries. The work runs on the blocking pool; a call that outlives its check's
//! timeout leaves a thread that ends when the read does, and only regular files are ever opened, so
//! that read cannot wait on a writer. A file on a hung network mount can still stall a thread.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::sealed::Sealed;
use super::sock::{UdpReply, UnixResponse};
use super::{Backend, DirEntry, FileBytes, FileMeta, ProbeError, ReadGuard, ReadRange};
use crate::check::BoxFuture;

#[cfg(unix)]
mod dockerhttp;
#[cfg(unix)]
mod files;
mod netio;

/// The backend that reads the real machine.
///
/// Files and the environment are real. `exec` uses the provided `spawn`, which runs
/// `exec::table::run`.
#[must_use]
pub fn live_backend() -> Arc<dyn Backend> {
    Arc::new(Live {
        #[cfg(unix)]
        secrets: files::Secrets::collect(),
    })
}

#[derive(Debug)]
struct Live {
    /// The password and sudo files by inode, so a hard link or a bind mount is refused too.
    #[cfg(unix)]
    secrets: files::Secrets,
}

impl Sealed for Live {}

#[cfg(not(unix))]
fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file reads are not available on this OS in this version of rdy",
    ))
}

/// Runs `work` on the blocking pool. A panic in it is resumed in the caller, like `blocking`.
#[cfg(unix)]
async fn on_pool<T: Send + 'static>(
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(io::Error::other(
            "the file work was cancelled because the runtime is shutting down",
        )),
    }
}

impl Backend for Live {
    fn open_read<'a>(
        &'a self,
        path: &'a Path,
        range: ReadRange,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<FileBytes>> {
        let path = path.to_owned();
        let guard = *guard;
        #[cfg(unix)]
        let secrets = self.secrets.clone();
        Box::pin(async move {
            #[cfg(unix)]
            {
                on_pool(move || files::read(&path, range, &guard, &secrets)).await
            }
            #[cfg(not(unix))]
            {
                let _ = (path, range, guard);
                unsupported()
            }
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        let path = path.to_owned();
        let guard = *guard;
        #[cfg(unix)]
        let secrets = self.secrets.clone();
        Box::pin(async move {
            #[cfg(unix)]
            {
                on_pool(move || files::read_dir(&path, &guard, &secrets)).await
            }
            #[cfg(not(unix))]
            {
                let _ = (path, guard);
                unsupported()
            }
        })
    }

    fn stat<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
        let path = path.to_owned();
        let guard = *guard;
        #[cfg(unix)]
        let secrets = self.secrets.clone();
        Box::pin(async move {
            #[cfg(unix)]
            {
                on_pool(move || files::stat(&path, &guard, &secrets)).await
            }
            #[cfg(not(unix))]
            {
                let _ = (path, guard);
                unsupported()
            }
        })
    }

    fn env(&self, name: &str) -> Option<String> {
        // The probe checked the name: declared, not empty, no `=` and no NUL.
        std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
    }

    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(netio::resolve(host, port, timeout))
    }

    fn udp_exchange<'a>(
        &'a self,
        to: SocketAddr,
        payload: &'a [u8],
        max_reply: usize,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<UdpReply, ProbeError>> {
        Box::pin(netio::udp(to, payload, max_reply, timeout))
    }

    fn unix_get<'a>(
        &'a self,
        socket: &'a Path,
        path: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<UnixResponse, ProbeError>> {
        #[cfg(unix)]
        {
            Box::pin(netio::unix_get(socket, path, timeout))
        }
        #[cfg(not(unix))]
        {
            let _ = (socket, path, timeout);
            Box::pin(async {
                Err(ProbeError::Io(
                    "this build of rdy cannot open unix sockets on this platform".to_owned(),
                ))
            })
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
