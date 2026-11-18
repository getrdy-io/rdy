//! A scripted DNS server on loopback, over UDP and TCP (M1-155).
//!
//! It exists to test the live socket code under `Backend::dns_exchange`: the length prefix of TCP, the
//! reply caps and the timeouts. The facade's own calls go to port 53 of an address from the OS list,
//! which a test cannot bind, so these tests call the backend with this server's address.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::{Guard, serve};
use crate::probe::sock::DnsTransport;

/// What the server does with a query. `None` is silence.
type Script = Arc<dyn Fn(&[u8], DnsTransport) -> Option<Vec<u8>> + Send + Sync>;

/// A DNS server on `127.0.0.1`, one port for UDP and the same port for TCP. It stops when dropped.
#[derive(Debug)]
pub struct DnsServer {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    _udp: Guard,
    _tcp: Guard,
}

impl DnsServer {
    /// Starts the server. `script` gets each query (for TCP, without the length prefix) and the
    /// transport, and returns the reply message, or `None` to stay silent. A TCP reply is sent with the
    /// length prefix, and a reply longer than 65535 bytes is sent as a prefix that is too short, which
    /// a client must not trust.
    ///
    /// # Errors
    ///
    /// If no port can be bound for both UDP and TCP.
    pub async fn start(
        script: impl Fn(&[u8], DnsTransport) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let script: Script = Arc::new(script);
        let queries = Arc::new(AtomicUsize::new(0));
        let mut last = io::Error::other("no port");
        for _ in 0..20 {
            let tcp = TcpListener::bind(("127.0.0.1", 0)).await?;
            let addr = tcp.local_addr()?;
            let udp = match UdpSocket::bind(addr).await {
                Ok(udp) => udp,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let (s, q) = (Arc::clone(&script), Arc::clone(&queries));
            let udp_task = tokio::spawn(async move {
                let mut buf = vec![0_u8; 65_535];
                while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                    q.fetch_add(1, Ordering::SeqCst);
                    if let Some(reply) = s(&buf[..n], DnsTransport::Udp) {
                        let _ = udp.send_to(&reply, from).await;
                    }
                }
            });
            let (s, q) = (Arc::clone(&script), Arc::clone(&queries));
            let tcp_guard = serve(tcp, move |stream| {
                tcp_conn(stream, Arc::clone(&s), Arc::clone(&q))
            });
            return Ok(Self {
                addr,
                queries,
                _udp: Guard(udp_task.abort_handle()),
                _tcp: tcp_guard,
            });
        }
        Err(last)
    }

    /// The address of both listeners.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Queries received over both transports.
    #[must_use]
    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

async fn tcp_conn(mut stream: TcpStream, script: Script, queries: Arc<AtomicUsize>) {
    let mut prefix = [0_u8; 2];
    if stream.read_exact(&mut prefix).await.is_err() {
        return;
    }
    let mut query = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    if stream.read_exact(&mut query).await.is_err() {
        return;
    }
    queries.fetch_add(1, Ordering::SeqCst);
    let Some(reply) = script(&query, DnsTransport::Tcp) else {
        // Silent: hold the connection open until the client gives up.
        let mut sink = [0_u8; 1];
        let _ = stream.read(&mut sink).await;
        return;
    };
    let length = u16::try_from(reply.len()).unwrap_or(u16::MAX);
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(&reply);
    let _ = stream.write_all(&framed).await;
}
