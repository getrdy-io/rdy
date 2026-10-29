//! The live socket I/O under `Backend::resolve`, `Backend::udp_exchange` and `Backend::unix_get`.
//!
//! These functions enforce no policy and write no log: `Probe` has already done both. They bound every
//! wait by the timeout they are given and never read more than the caps in [`super::sock`] and
//! [`super::dockerhttp`]. Without feature `runtime` there is no timer and no socket, and each call
//! fails.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use super::ProbeError;
use super::sock::{UdpReply, UnixResponse};

#[cfg(not(feature = "runtime"))]
fn off() -> ProbeError {
    ProbeError::Io(
        "this build of rdy-engine cannot open sockets (feature `runtime` is off)".to_owned(),
    )
}

/// Resolves a spec host name through the system resolver.
#[cfg(feature = "runtime")]
pub(super) async fn resolve(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<IpAddr>> {
    let lookup = tokio::net::lookup_host((host, port));
    match tokio::time::timeout(timeout, lookup).await {
        Ok(found) => {
            let mut ips: Vec<IpAddr> = Vec::new();
            for addr in found? {
                if !ips.contains(&addr.ip()) {
                    ips.push(addr.ip());
                }
            }
            Ok(ips)
        }
        Err(_elapsed) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// Without the runtime there is no resolver.
#[cfg(not(feature = "runtime"))]
pub(super) async fn resolve(
    _host: &str,
    _port: u16,
    _timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    Err(io::Error::other(off().to_string()))
}

/// Sends one datagram from a fresh socket that is connected to `to`, so only `to` can answer, and
/// reads one reply.
#[cfg(feature = "runtime")]
pub(super) async fn udp(
    to: SocketAddr,
    payload: &[u8],
    max_reply: usize,
    timeout: Duration,
) -> Result<UdpReply, ProbeError> {
    use tokio::net::UdpSocket;

    let local = SocketAddr::new(
        if to.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let exchange = async {
        let socket = UdpSocket::bind(local).await?;
        socket.connect(to).await?;
        socket.send(payload).await?;
        // One byte more than asked for tells whether the reply was cut.
        let mut buf = vec![0_u8; max_reply.saturating_add(1)];
        let n = socket.recv(&mut buf).await?;
        io::Result::Ok((buf, n))
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok((mut buf, n))) => {
            let truncated = n > max_reply;
            buf.truncate(n.min(max_reply));
            let mut reply = UdpReply::new(buf, to.ip());
            reply.truncated = truncated;
            Ok(reply)
        }
        Ok(Err(error)) => Err(ProbeError::from_io(&error)),
        Err(_elapsed) => Err(ProbeError::Timeout),
    }
}

/// Without the runtime there is no socket.
#[cfg(not(feature = "runtime"))]
pub(super) async fn udp(
    _to: SocketAddr,
    _payload: &[u8],
    _max_reply: usize,
    _timeout: Duration,
) -> Result<UdpReply, ProbeError> {
    Err(off())
}

/// Sends the fixed `GET` over the unix socket and reads one HTTP/1.x reply.
#[cfg(all(feature = "runtime", unix))]
pub(super) async fn unix_get(
    socket: &Path,
    path: &str,
    timeout: Duration,
) -> Result<UnixResponse, ProbeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::dockerhttp::{self, HttpError, RAW_CAP};

    let malformed = |error: HttpError| ProbeError::Io(error.to_string());
    let exchange = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|e| ProbeError::from_io(&e))?;
        stream
            .write_all(&dockerhttp::request(path))
            .await
            .map_err(|e| ProbeError::from_io(&e))?;
        let mut raw: Vec<u8> = Vec::new();
        let mut head = None;
        let mut chunk = [0_u8; 8192];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| ProbeError::from_io(&e))?;
            let eof = n == 0;
            raw.extend_from_slice(&chunk[..n]);
            if head.is_none() {
                head = dockerhttp::parse_head(&raw).map_err(malformed)?;
            }
            if let Some(head) = &head {
                let rest = &raw[head.len..];
                if dockerhttp::finished(head, rest, eof).map_err(malformed)? {
                    let body = dockerhttp::body(head, rest, eof).map_err(malformed)?;
                    let mut reply = UnixResponse::new(head.status, body.bytes);
                    reply.truncated = body.truncated;
                    return Ok(reply);
                }
            } else if eof {
                return Err(ProbeError::Io(
                    "the socket closed without a reply".to_owned(),
                ));
            }
            if raw.len() >= RAW_CAP {
                // The caps are reached: a head is parsed by now, or HeadTooLarge was returned.
                return Err(ProbeError::Io(
                    "the reply is larger than rdy reads".to_owned(),
                ));
            }
        }
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProbeError::Timeout),
    }
}

/// Without unix sockets (Windows) or the runtime, the call fails. `Probe` refuses on Windows first.
#[cfg(not(all(feature = "runtime", unix)))]
pub(super) async fn unix_get(
    _socket: &Path,
    _path: &str,
    _timeout: Duration,
) -> Result<UnixResponse, ProbeError> {
    Err(ProbeError::Io(
        "this build of rdy cannot open unix sockets on this platform".to_owned(),
    ))
}
