//! A strict base64 decoder for the minisign envelope.
//!
//! Standard alphabet, padding required, no whitespace, and unused trailing bits must be zero. So every
//! value has exactly one accepted text, and a signature cannot be written two ways.

/// The value of one base64 digit, or `None` for any other byte.
fn digit(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes `text`, or returns `None` if it is not canonical padded base64.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - pad];
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in body {
        acc = (acc << 6) | digit(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    // What is left over is padding bits. A canonical text has them all zero.
    (acc == 0).then_some(out)
}

/// Encodes `bytes` as canonical padded base64. Tests only: the verifier never writes base64.
#[cfg(test)]
pub(super) fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn encode_and_decode_round_trip() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 7 % 256).unwrap_or(0))
                .collect();
            if len == 0 {
                assert_eq!(encode(&data), "");
            } else {
                assert_eq!(decode(&encode(&data)), Some(data), "{len}");
            }
        }
    }

    #[test]
    fn decodes_the_rfc_4648_vectors() {
        assert_eq!(decode("Zg=="), Some(b"f".to_vec()));
        assert_eq!(decode("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(decode("Zm9v"), Some(b"foo".to_vec()));
        assert_eq!(decode("Zm9vYg=="), Some(b"foob".to_vec()));
        assert_eq!(decode("Zm9vYmE="), Some(b"fooba".to_vec()));
        assert_eq!(decode("Zm9vYmFy"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn refuses_everything_that_is_not_canonical() {
        for bad in [
            "",
            "Zg",
            "Zg=",
            "Zg===",
            "Z===",
            "Zm9",
            "Zh==",
            "Zm9=",
            "Zm 9v",
            "Zm9v\n",
            "Zm=v",
            "Zm9v====",
            "Zm9*",
            "Zm9\u{e9}",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }
}
