//! The recorded half of the TCP calls: the servers a `net.json` `serve` entry can reach (M1-091).
//!
//! `net.json` says what connecting to an address does (`refused`, `reset`, `blackhole` or `serve`). A
//! `serve` entry names a server the test registered with [`Replay::serve`], [`Replay::serve_tcp`] or
//! [`Replay::serve_duplex`]. When the facade connects to that address, the replay backend runs the
//! named factory and hands the stream it returns to the caller, so a check's connect reaches the
//! started server (the `ConnectProxy`, `HttpServer` and the others of `testing::loopback`).
//!
//! The replay backend never reaches past the machine: `serve_tcp` connects to loopback only, and an
//! address that `net.json` does not hold, or a name nobody registered, is "not recorded".

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::DuplexStream;

use super::BoxedStream;
use crate::check::BoxFuture;
use crate::probe::replay::{Replay, TcpScript, Unrecorded};

/// The buffer of each direction of a duplex pipe.
const DUPLEX_BUFFER: usize = 64 * 1024;

/// Opens one connection to a registered server.
type Factory = Arc<dyn Fn() -> BoxFuture<'static, io::Result<BoxedStream>> + Send + Sync>;

/// The server factories of a [`Replay`], by name.
#[derive(Clone, Default)]
pub(crate) struct Servers(HashMap<String, Factory>);

impl fmt::Debug for Servers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

impl Servers {
    /// A new connection to the server named `name`, or "not recorded" when nobody registered it.
    pub(crate) async fn open(&self, name: &str) -> io::Result<BoxedStream> {
        match self.0.get(name) {
            Some(factory) => factory().await,
            None => Err(Unrecorded::error(format!("a server named {name}"))),
        }
    }
}

impl Replay {
    /// Scripts what connecting to `addr` does, as a `net.json` `tcp` entry does. A later call for the
    /// same address replaces the earlier one.
    #[must_use]
    pub fn tcp(mut self, addr: SocketAddr, script: TcpScript) -> Self {
        self.script.insert_tcp(addr, script);
        self
    }

    /// Registers the server `name`. Each connection to an address scripted as `serve: name` calls
    /// `open`, which returns the stream the caller gets. A test usually wants [`Replay::serve_tcp`] or
    /// [`Replay::serve_duplex`]; this is the general form.
    #[must_use]
    pub fn serve<F, Fut>(mut self, name: &str, open: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<BoxedStream>> + Send + 'static,
    {
        self.servers
            .0
            .insert(name.to_owned(), Arc::new(move || Box::pin(open())));
        self
    }

    /// Registers the server `name` as a server that is already listening on loopback, such as an
    /// `HttpServer` or a `ConnectProxy` of `testing::loopback`. Each connection to an address scripted
    /// as `serve: name` opens a real connection to `server`.
    ///
    /// # Panics
    ///
    /// If `server` is not a loopback address. A replay never reaches the network.
    #[must_use]
    pub fn serve_tcp(self, name: &str, server: SocketAddr) -> Self {
        assert!(
            server.ip().is_loopback(),
            "serve_tcp reaches loopback only, and {server} is not a loopback address"
        );
        self.serve(name, move || async move {
            let stream = tokio::net::TcpStream::connect(server).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxedStream)
        })
    }

    /// Registers the server `name` as an in-process task. Each connection makes a duplex pipe, runs
    /// `serve` on one end in a new task and gives the other end to the caller. The task ends when
    /// `serve` returns or when either end is dropped.
    #[must_use]
    pub fn serve_duplex<F, Fut>(self, name: &str, serve: F) -> Self
    where
        F: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let serve = Arc::new(serve);
        self.serve(name, move || {
            let serve = Arc::clone(&serve);
            async move {
                let (client, server) = tokio::io::duplex(DUPLEX_BUFFER);
                tokio::spawn(async move { serve(server).await });
                Ok(Box::new(client) as BoxedStream)
            }
        })
    }

    /// The stream a connection to `addr` gets under the script: the named server, or the scripted
    /// failure.
    pub(crate) fn connect_to(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<BoxedStream>> {
        Box::pin(async move {
            let name = self.dial(addr).await?;
            self.servers.open(&name).await
        })
    }
}
