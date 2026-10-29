//! The smallest HTTP/1.1 client that `Probe::unix_get` needs, as pure functions over bytes.
//!
//! It writes one fixed request (`GET`, a path from the allowlist in [`crate::probe::sock`], `Connection:
//! close`) and reads one response. It has no I/O, so the live backend and the tests share it. Nothing
//! here follows a redirect, sends a body or keeps a connection.
//!
//! Limits: the head is at most [`HEAD_CAP`] bytes and the body at most [`BODY_CAP`]. A longer body is
//! cut and flagged, not an error. A response that is not HTTP/1.x, or whose framing contradicts
//! itself, is [`HttpError`].
//!
//! A chunked body is read until its terminal chunk, the end of the stream, or [`BODY_CAP`] plus
//! [`CHUNK_SLACK`] raw bytes. The slack pays for chunk framing. A reply of many tiny chunks can use
//! all of it before [`BODY_CAP`] body bytes arrive. The read then stops and the reply is flagged
//! truncated.

/// The most bytes of status line and headers read.
pub(crate) const HEAD_CAP: usize = 16 * 1024;

/// The most body bytes kept.
pub(crate) const BODY_CAP: usize = crate::probe::sock::BODY_LIMIT;

/// The most raw bytes read from the socket in all: head, body and chunk framing.
pub(crate) const RAW_CAP: usize = HEAD_CAP + BODY_CAP + CHUNK_SLACK;

/// Extra raw bytes read past [`BODY_CAP`] for a chunked body, so that the chunk framing does not eat
/// into the bytes kept.
pub(crate) const CHUNK_SLACK: usize = 4096;

/// Why a response could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HttpError {
    /// The head is longer than [`HEAD_CAP`].
    #[error("the reply head is longer than {HEAD_CAP} bytes")]
    HeadTooLarge,
    /// Not HTTP/1.x, or the framing is inconsistent.
    #[error("the reply is not a well formed HTTP/1.x response ({0})")]
    Malformed(&'static str),
}

/// What the head says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    /// The status code.
    pub status: u16,
    /// Bytes of status line and headers, blank line included.
    pub len: usize,
    framing: Framing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Length(u64),
    Chunked,
    UntilClose,
}

/// A body read so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Body {
    /// The bytes kept, at most [`BODY_CAP`].
    pub bytes: Vec<u8>,
    /// `true` when the server sent more than was kept.
    pub truncated: bool,
    /// `true` when the framing says the body is whole. A body framed by connection close is complete
    /// only at end of stream.
    pub complete: bool,
}

/// The request for `path`. The caller has checked `path` against the allowlist, so it holds no space,
/// control character or query string.
pub(crate) fn request(path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: rdy\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Reads the head from the bytes so far. `Ok(None)` means the head is not complete yet.
///
/// # Errors
///
/// [`HttpError`] when the bytes cannot be an HTTP/1.x head.
pub(crate) fn parse_head(buf: &[u8]) -> Result<Option<Head>, HttpError> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= HEAD_CAP {
            Err(HttpError::HeadTooLarge)
        } else {
            Ok(None)
        };
    };
    let len = end + 4;
    if len > HEAD_CAP {
        return Err(HttpError::HeadTooLarge);
    }
    let text =
        std::str::from_utf8(&buf[..end]).map_err(|_| HttpError::Malformed("head is not text"))?;
    let mut lines = text.split("\r\n");
    let status = status_of(lines.next().unwrap_or_default())?;

    let mut length: Option<u64> = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(HttpError::Malformed("header without a colon"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            // Digits only: `u64::parse` would also take a leading `+`.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::Malformed("bad content-length"));
            }
            let n: u64 = value
                .parse()
                .map_err(|_| HttpError::Malformed("bad content-length"))?;
            if length.is_some_and(|seen| seen != n) {
                return Err(HttpError::Malformed("conflicting content-length"));
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // The last coding must be chunked. Any other coding is not supported.
            let last = value.rsplit(',').next().unwrap_or_default().trim();
            if last.eq_ignore_ascii_case("chunked") && !value.contains(',') {
                chunked = true;
            } else {
                return Err(HttpError::Malformed("unsupported transfer-encoding"));
            }
        }
    }
    // A reply with both is ambiguous framing, the root of response smuggling (RFC 9112 6.3).
    if chunked && length.is_some() {
        return Err(HttpError::Malformed(
            "both content-length and transfer-encoding",
        ));
    }
    // A body-less status has no body at all.
    let framing = if status == 204 || status == 304 {
        Framing::Length(0)
    } else if chunked {
        Framing::Chunked
    } else if let Some(n) = length {
        Framing::Length(n)
    } else {
        Framing::UntilClose
    };
    Ok(Some(Head {
        status,
        len,
        framing,
    }))
}

fn status_of(line: &str) -> Result<u16, HttpError> {
    let rest = line
        .strip_prefix("HTTP/1.")
        .ok_or(HttpError::Malformed("no HTTP/1.x status line"))?;
    let mut parts = rest.splitn(3, ' ');
    let minor = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !(minor == "0" || minor == "1")
        || code.len() != 3
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(HttpError::Malformed("bad status line"));
    }
    let status: u16 = code
        .parse()
        .map_err(|_| HttpError::Malformed("bad status code"))?;
    if status < 200 {
        return Err(HttpError::Malformed("informational status"));
    }
    Ok(status)
}

/// Reads the body from the bytes after the head. `eof` says the server closed the stream.
///
/// The caller runs this once, when [`finished`] says to stop, not on every read. `truncated` is set
/// only when the body kept is cut short of what the server declared or sent: the cap was reached and
/// more follows, or the stream ended before the framing was whole.
///
/// # Errors
///
/// [`HttpError::Malformed`] when chunk framing is broken.
pub(crate) fn body(head: &Head, rest: &[u8], eof: bool) -> Result<Body, HttpError> {
    match head.framing {
        Framing::Length(n) => {
            let have = u64::try_from(rest.len()).unwrap_or(u64::MAX);
            let complete = have >= n;
            let keep = usize::try_from(n.min(have))
                .unwrap_or(usize::MAX)
                .min(BODY_CAP);
            Ok(Body {
                bytes: rest[..keep].to_vec(),
                truncated: (keep == BODY_CAP && n > BODY_CAP as u64) || (eof && !complete),
                complete: complete || eof,
            })
        }
        Framing::UntilClose => {
            let keep = rest.len().min(BODY_CAP);
            Ok(Body {
                bytes: rest[..keep].to_vec(),
                truncated: rest.len() > BODY_CAP,
                complete: eof,
            })
        }
        Framing::Chunked => chunked(rest, eof),
    }
}

/// Whether the read loop can stop and read the body: the stream ended, or what is here cannot grow
/// into a longer kept body. It looks at lengths only, so a one byte per read server costs nothing
/// extra. A chunked body is read to the end of the stream (the request says `Connection: close`) or to
/// [`BODY_CAP`] plus [`CHUNK_SLACK`] raw bytes.
pub(crate) fn finished(head: &Head, rest: &[u8], eof: bool) -> bool {
    if eof {
        return true;
    }
    match head.framing {
        Framing::Length(n) => {
            u64::try_from(rest.len()).unwrap_or(u64::MAX) >= n || rest.len() > BODY_CAP
        }
        Framing::UntilClose => rest.len() > BODY_CAP,
        Framing::Chunked => {
            if rest.len() >= BODY_CAP + CHUNK_SLACK {
                return true;
            }
            // A body that ends in a blank line may be whole: stop at the terminal chunk instead of
            // waiting for a server that keeps the connection open. A framing error also stops the read,
            // so that `body` reports it.
            rest.ends_with(b"\r\n\r\n") && chunked(rest, false).map_or(true, |body| body.complete)
        }
    }
}

fn chunked(mut rest: &[u8], eof: bool) -> Result<Body, HttpError> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    // The read loop stopped at its raw limit with the body still open: it is cut, not just early.
    let at_limit = eof || rest.len() >= BODY_CAP + CHUNK_SLACK;
    loop {
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else {
            return if rest.len() > 64 {
                Err(HttpError::Malformed("chunk size line too long"))
            } else {
                Ok(Body {
                    bytes,
                    truncated: truncated || at_limit,
                    complete: false,
                })
            };
        };
        let line = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| HttpError::Malformed("bad chunk size"))?;
        // Spaces are allowed only between the size and a `;` that starts chunk extensions.
        let digits = match line.split_once(';') {
            Some((size, _extensions)) => size.trim_end_matches([' ', '\t']),
            None => line,
        };
        // Hex digits only: `from_str_radix` would also take a leading `+`.
        if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(HttpError::Malformed("bad chunk size"));
        }
        let size = usize::try_from(
            u64::from_str_radix(digits, 16).map_err(|_| HttpError::Malformed("bad chunk size"))?,
        )
        .map_err(|_| HttpError::Malformed("bad chunk size"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            // Trailers, if any, are ignored. The terminal chunk makes the body whole.
            return Ok(Body {
                bytes,
                truncated,
                complete: true,
            });
        }
        let room = BODY_CAP.saturating_sub(bytes.len());
        if rest.len() < size.saturating_add(2) {
            // Part of a chunk: keep what fits and wait for the rest.
            let take = rest.len().min(size).min(room);
            bytes.extend_from_slice(&rest[..take]);
            // Cut only when the cap is full and the chunk declares more than fitted.
            truncated |= bytes.len() == BODY_CAP && size > take;
            return Ok(Body {
                bytes,
                truncated: truncated || at_limit,
                complete: false,
            });
        }
        if &rest[size..size + 2] != b"\r\n" {
            return Err(HttpError::Malformed("chunk is not followed by CRLF"));
        }
        let take = size.min(room);
        bytes.extend_from_slice(&rest[..take]);
        if take < size {
            truncated = true;
        }
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(raw: &[u8]) -> Head {
        parse_head(raw).expect("parses").expect("complete")
    }

    #[test]
    fn request_is_a_fixed_get() {
        let text = String::from_utf8(request("/info")).expect("text");
        assert!(text.starts_with("GET /info HTTP/1.1\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.contains("Authorization"));
    }

    #[test]
    fn content_length_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nhello";
        let head = head_of(raw);
        assert_eq!(head.status, 200);
        let done = body(&head, &raw[head.len..], false).expect("body");
        assert_eq!(done.bytes, b"hello");
        assert!(done.complete && !done.truncated);
    }

    #[test]
    fn short_body_is_not_complete_until_eof() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
        let head = head_of(raw);
        let early = body(&head, &raw[head.len..], false).expect("body");
        assert!(!early.complete);
        let late = body(&head, &raw[head.len..], true).expect("body");
        assert!(late.complete && late.truncated);
    }

    #[test]
    fn chunked_body_is_joined() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n";
        let head = head_of(raw);
        let done = body(&head, &raw[head.len..], false).expect("body");
        assert_eq!(done.bytes, b"abcde");
        assert!(done.complete && !done.truncated);
    }

    #[test]
    fn chunked_body_finishes_at_the_terminal_chunk_without_eof() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let head = head_of(raw);
        assert!(finished(&head, &raw[head.len..], false));
        let open = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n";
        let head = head_of(open);
        assert!(!finished(&head, &open[head.len..], false));
        // Chunk data that happens to end in a blank line is not the end.
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\r\n\r\n\r\n";
        let head = head_of(data);
        assert!(!finished(&head, &data[head.len..], false));
    }

    #[test]
    fn chunk_size_allows_space_only_before_extensions() {
        let ok = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 ;x=1\r\nhi\r\n0\r\n\r\n";
        let head = head_of(ok);
        let done = body(&head, &ok[head.len..], false).expect("body");
        assert_eq!(done.bytes, b"hi");
        for bad in [
            &b" 5\r\nhello\r\n0\r\n\r\n"[..],
            b"5 \r\nhello\r\n0\r\n\r\n",
        ] {
            let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            raw.extend_from_slice(bad);
            let head = head_of(&raw);
            assert_eq!(
                body(&head, &raw[head.len..], false),
                Err(HttpError::Malformed("bad chunk size"))
            );
        }
    }

    #[test]
    fn chunked_body_waits_for_the_terminal_chunk() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nd";
        let head = head_of(raw);
        let part = body(&head, &raw[head.len..], false).expect("body");
        assert!(!part.complete);
        assert_eq!(part.bytes, b"abcd");
    }

    #[test]
    fn body_past_the_cap_is_cut_and_flagged() {
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            BODY_CAP + 10
        )
        .into_bytes();
        raw.extend(std::iter::repeat_n(b'x', BODY_CAP + 10));
        let head = head_of(&raw);
        let done = body(&head, &raw[head.len..], false).expect("body");
        assert_eq!(done.bytes.len(), BODY_CAP);
        assert!(done.truncated);
        assert!(finished(&head, &raw[head.len..], false));
    }

    #[test]
    fn bad_replies_are_errors() {
        for raw in [
            &b"SSH-2.0-OpenSSH_9.6\r\n\r\n"[..],
            b"HTTP/2 200\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
        ] {
            assert!(
                parse_head(raw).is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
        let long = vec![b'a'; HEAD_CAP];
        assert_eq!(parse_head(&long), Err(HttpError::HeadTooLarge));
        assert_eq!(parse_head(b"HTTP/1.1 200"), Ok(None));
    }

    #[test]
    fn broken_chunk_framing_is_an_error() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
        let head = head_of(raw);
        assert!(body(&head, &raw[head.len..], false).is_err());
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n";
        let head = head_of(raw);
        assert!(body(&head, &raw[head.len..], false).is_err());
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+3\r\nabc\r\n0\r\n\r\n";
        let head = head_of(raw);
        assert!(body(&head, &raw[head.len..], true).is_err());
    }

    #[test]
    fn no_content_status_has_no_body() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let head = head_of(raw);
        let done = body(&head, &[], false).expect("body");
        assert!(done.complete && done.bytes.is_empty());
    }

    /// Feeds `raw` the way the read loop does, in pieces of `step` bytes, and returns the body.
    fn feed(raw: &[u8], step: usize) -> Body {
        let mut seen = 0;
        let mut head = None;
        loop {
            seen = (seen + step).min(raw.len());
            let eof = seen == raw.len();
            let part = &raw[..seen];
            if head.is_none() {
                head = parse_head(part).expect("head");
            }
            if let Some(head) = &head
                && finished(head, &part[head.len..], eof)
            {
                return body(head, &part[head.len..], eof).expect("body");
            }
            assert!(!eof, "the loop must stop at the end of the stream");
        }
    }

    #[test]
    fn a_big_length_body_is_kept_to_the_cap_when_fed_in_pieces() {
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            BODY_CAP + 10
        )
        .into_bytes();
        raw.extend(std::iter::repeat_n(b'x', BODY_CAP + 10));
        let done = feed(&raw, 8192);
        assert_eq!(done.bytes.len(), BODY_CAP);
        assert!(done.truncated);
    }

    #[test]
    fn a_big_chunk_is_kept_to_the_cap_when_fed_in_pieces() {
        let size = BODY_CAP + 10;
        let mut raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n")
            .into_bytes();
        raw.extend(std::iter::repeat_n(b'x', size));
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let done = feed(&raw, 8192);
        assert_eq!(done.bytes.len(), BODY_CAP);
        assert!(done.truncated);
    }

    #[test]
    fn a_body_that_fits_is_whole_and_not_flagged_when_fed_in_pieces() {
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_CAP}\r\n\r\n").into_bytes();
        raw.extend(std::iter::repeat_n(b'x', BODY_CAP));
        let done = feed(&raw, 8192);
        assert_eq!(done.bytes.len(), BODY_CAP);
        assert!(!done.truncated && done.complete);
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{BODY_CAP:x}\r\n");
        let mut raw = raw.into_bytes();
        raw.extend(std::iter::repeat_n(b'x', BODY_CAP));
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let done = feed(&raw, 8192);
        assert_eq!(done.bytes.len(), BODY_CAP);
        assert!(!done.truncated && done.complete);
    }

    #[test]
    fn a_partial_big_chunk_is_not_flagged_before_the_cap_is_full() {
        let size = BODY_CAP + 10;
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\nabc");
        let head = head_of(raw.as_bytes());
        let part = body(&head, &raw.as_bytes()[head.len..], false).expect("body");
        assert_eq!(part.bytes, b"abc");
        assert!(!part.truncated && !part.complete);
    }
}
