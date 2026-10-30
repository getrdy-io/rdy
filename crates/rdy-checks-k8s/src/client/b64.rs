//! A base64 decoder for one job: reading the PEM text inside a kubeconfig's `client-key-data`, so that
//! the lines of the key are known secrets as well as the base64 (ADR 0015 decision 3). It lives here
//! instead of a crate because a check crate may not add a dependency without a review (INV-07), and
//! this is thirty lines with no I/O.

/// Decodes standard base64 (RFC 4648 section 4). White space is skipped and padding is optional. Any
/// other byte, or a length that cannot be base64, gives `None`.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut bits: u32 = 0;
    let mut have: u32 = 0;
    let mut padding = 0;
    for byte in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            // Data after padding.
            return None;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push(u8::try_from((bits >> have) & 0xff).ok()?);
            bits &= (1 << have) - 1;
        }
    }
    // One leftover character (6 bits) cannot be a byte, and more than two padding characters is wrong.
    (have < 6 && padding <= 2).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn it_decodes_with_and_without_padding_and_white_space() {
        assert_eq!(decode("aGk=").as_deref(), Some(&b"hi"[..]));
        assert_eq!(decode("aGk").as_deref(), Some(&b"hi"[..]));
        assert_eq!(decode("aGVs\nbG8h\r\n").as_deref(), Some(&b"hello!"[..]));
        assert_eq!(decode("").as_deref(), Some(&b""[..]));
        assert_eq!(decode("+/+/").as_deref(), Some(&[0xfb, 0xff, 0xbf][..]));
    }

    #[test]
    fn it_refuses_what_is_not_base64() {
        for bad in ["not base64 !", "aGk=x", "a", "aGk===", "aGk-", "a\u{e9}"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }
}
