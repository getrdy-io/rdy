//! Standard base64 with padding, for `stdout_b64` and the DER certificates of a native fixture.
//!
//! Strict: no whitespace, no missing padding, no stray bits. A fixture is a test input, and a mistake in
//! it should fail the load.

/// Decodes `text`, or says what is wrong.
pub(super) fn decode(text: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 text must be padded to a multiple of 4 characters");
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (index, group) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let mut bits = 0u32;
        let mut pad = 0usize;
        for (place, &byte) in group.iter().enumerate() {
            let value = if byte == b'=' {
                // Padding ends the text: the last one or two characters of the last group.
                if index + 1 != groups || place < 2 {
                    return Err("misplaced base64 padding");
                }
                pad += 1;
                0
            } else {
                if pad > 0 {
                    return Err("misplaced base64 padding");
                }
                sextet(byte).ok_or("not a base64 character")?
            };
            bits = (bits << 6) | value;
        }
        let triple = bits.to_be_bytes();
        // `triple` is [0, b0, b1, b2]. The bytes the padding leaves out must be zero.
        if pad > 0 && triple.get(4 - pad).copied().unwrap_or(0) != 0 {
            return Err("base64 text has stray bits before the padding");
        }
        out.extend_from_slice(triple.get(1..4 - pad).unwrap_or_default());
    }
    Ok(out)
}

fn sextet(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
