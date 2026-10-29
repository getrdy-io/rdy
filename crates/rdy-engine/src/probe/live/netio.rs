//! The live socket I/O under `Backend::resolve`, `Backend::udp_exchange` and `Backend::unix_get`.
//!
//! These functions enforce no policy and write no log: `Probe` has already done both. They bound every
//! wait by the timeout they are given and never read more than the caps in [`crate::probe::sock`] and
//! `dockerhttp`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::probe::ProbeError;
use crate::probe::sock::UdpReply;

/// Resolves a spec host name through the system resolver.
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

/// The largest UDP payload. A buffer of this size never loses bytes on any OS: Windows fails a `recv`
/// into a smaller buffer with `WSAEMSGSIZE`, and Unix cuts silently. So the cut to the cap is made
/// here in user space, the same way on every OS.
const DATAGRAM_MAX: usize = 65_535;

/// Sends one datagram from a fresh socket that is connected to `to`, so only `to` can answer, and
/// reads one reply.
pub(super) async fn udp(
    to: SocketAddr,
    payload: &[u8],
    max_reply: usize,
    timeout: Duration,
) -> Result<UdpReply, ProbeError> {
    use tokio::net::UdpSocket;

    let local = SocketAddr::new(
        if to.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let exchange = async {
        let socket = UdpSocket::bind(local).await?;
        socket.connect(to).await?;
        socket.send(payload).await?;
        let mut buf = vec![0_u8; DATAGRAM_MAX];
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

/// Sends the fixed `GET` over the unix socket and reads one HTTP/1.x reply.
#[cfg(unix)]
pub(super) async fn unix_get(
    socket: &std::path::Path,
    path: &str,
    timeout: Duration,
) -> Result<crate::probe::sock::UnixResponse, ProbeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::dockerhttp::{self, HEAD_CAP, HttpError, RAW_CAP};
    use crate::probe::sock::UnixResponse;

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
            // Look for the end of the head only in the new bytes and the three before them.
            let from = raw.len().saturating_sub(3);
            raw.extend_from_slice(&chunk[..n]);
            if head.is_none()
                && (eof
                    || raw.len() >= HEAD_CAP
                    || raw[from..].windows(4).any(|w| w == b"\r\n\r\n"))
            {
                head = dockerhttp::parse_head(&raw).map_err(malformed)?;
            }
            if let Some(head) = &head {
                let rest = &raw[head.len..];
                // The body is parsed once, when the loop is done.
                if dockerhttp::finished(head, rest, eof) {
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
                // Not reachable for a well framed reply: `finished` stops first.
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
