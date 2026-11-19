//! The live socket I/O under `Backend::resolve`, `Backend::udp_exchange` and `Backend::unix_get`.
//!
//! These functions enforce no policy and write no log: `Probe` has already done both. They bound every
//! wait by the timeout they are given and never read more than the caps in [`crate::probe::sock`] and
//! `dockerhttp`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::probe::ProbeError;
use crate::probe::sock::{DnsTransport, UdpReply};

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

/// Opens a TCP stream. The probe has vetted the address and bounds the wait.
pub(super) async fn connect(addr: SocketAddr) -> io::Result<crate::probe::net::BoxedStream> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    // Small writes (a `CONNECT`, a TLS record) should not wait for more. A failure here is harmless.
    let _ = stream.set_nodelay(true);
    Ok(Box::new(stream))
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
        Ok(Err(error)) => Err(udp_error(&error)),
        Err(_elapsed) => Err(ProbeError::Timeout),
    }
}

/// Sends one DNS query and reads one reply. UDP is [`udp`]. TCP adds the two byte length prefix of
/// RFC 1035 and reads the prefix of the reply, then at most `max_reply` bytes of the message. A reply
/// cut at the cap sets `truncated`, and the connection is dropped. The whole call, connect included,
/// takes at most `timeout`.
pub(super) async fn dns(
    to: SocketAddr,
    payload: &[u8],
    transport: DnsTransport,
    max_reply: usize,
    timeout: Duration,
) -> Result<UdpReply, ProbeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    if transport == DnsTransport::Udp {
        return udp(to, payload, max_reply, timeout).await;
    }
    let exchange = async {
        let length = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
        let mut stream = TcpStream::connect(to).await?;
        let _ = stream.set_nodelay(true);
        let mut framed = Vec::with_capacity(payload.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(payload);
        stream.write_all(&framed).await?;
        let mut prefix = [0_u8; 2];
        stream.read_exact(&mut prefix).await?;
        let size = usize::from(u16::from_be_bytes(prefix));
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the server sent an empty message",
            ));
        }
        let keep = size.min(max_reply);
        let mut buf = vec![0_u8; keep];
        stream.read_exact(&mut buf).await?;
        io::Result::Ok((buf, size > keep))
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok((bytes, truncated))) => {
            let mut reply = UdpReply::new(bytes, to.ip());
            reply.truncated = truncated;
            Ok(reply)
        }
        Ok(Err(error)) => Err(ProbeError::from_io(&error)),
        Err(_elapsed) => Err(ProbeError::Timeout),
    }
}

/// The error of a failed UDP exchange. ICMP port unreachable on a connected UDP socket is
/// `ECONNREFUSED` on Unix and `WSAECONNRESET` on Windows, which is `ConnectionReset`. Both read as a
/// refusal, so the answer is the same on every OS. TCP does not use this and is unchanged.
fn udp_error(error: &io::Error) -> ProbeError {
    if error.kind() == io::ErrorKind::ConnectionReset {
        ProbeError::ConnectionRefused
    } else {
        ProbeError::from_io(error)
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

#[cfg(test)]
mod udp_error_tests {
    use super::*;

    #[test]
    fn a_reset_from_the_udp_path_reads_as_a_refusal() {
        let reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(udp_error(&reset), ProbeError::ConnectionRefused);
        // The other kinds keep their usual mapping, and the shared mapping itself is unchanged.
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(udp_error(&refused), ProbeError::ConnectionRefused);
        let other = io::Error::from(io::ErrorKind::BrokenPipe);
        assert_eq!(udp_error(&other), ProbeError::from_io(&other));
        assert!(matches!(ProbeError::from_io(&reset), ProbeError::Io(_)));
    }
}
