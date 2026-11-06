//! The SNTP client of `host.time_sync`: one request packet, and the judgement of one reply.
//!
//! The packet work is pure. The check sends the bytes through `Probe::udp_exchange`, which owns the
//! socket, the peer list and the address policy.
//!
//! A reply is accepted only when all of these hold:
//!
//! - it is at least 48 bytes and its mode is 4 (server). Mode 5 (broadcast), 3 (client), 1 and 2
//!   (symmetric) and 6 and 7 (control and private) are refused;
//! - its origin timestamp equals the random transmit timestamp we sent. That is the only proof the reply
//!   answers this request and not a packet an attacker made up or replayed;
//! - the stratum is 1 to 15. Stratum 0 is a kiss-o'-death or an unspecified server, and 16 or more is a
//!   server that is not synchronized;
//! - the leap indicator is not 3 (the server's own clock is unsynchronized);
//! - its receive and transmit timestamps are not zero, and the round trip is not negative.
//!
//! The offset is `((T2 - T1) + (T3 - T4)) / 2` (RFC 4330 section 5). T1 and T4 are read from the local
//! clock around the exchange. The transmit timestamp on the wire is random and is not T1, so the packet
//! gives away nothing about the local clock to an observer who is not the server.

/// Seconds from 1900-01-01 (the NTP epoch) to 1970-01-01 (the Unix epoch).
const NTP_TO_UNIX: i128 = 2_208_988_800;

/// One NTP era in seconds.
const ERA: i128 = 1 << 32;

/// The length of a request and the shortest reply, in bytes.
pub(crate) const PACKET: usize = 48;

/// A time in seconds since the Unix epoch with a 32 bit fraction (the NTP timestamp format, but on the
/// Unix epoch so it does not wrap in 2036).
pub(crate) type Fixed = i128;

/// Reads `time` as a [`Fixed`]. `None` for a clock before 1970.
pub(crate) fn fixed_from(time: std::time::SystemTime) -> Option<Fixed> {
    let since = time.duration_since(std::time::UNIX_EPOCH).ok()?;
    let secs = i128::from(since.as_secs());
    let frac = (i128::from(since.subsec_nanos()) << 32) / 1_000_000_000;
    Some((secs << 32) | frac)
}

/// A request packet and what is needed to judge its reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    /// The datagram to send.
    pub bytes: [u8; PACKET],
    /// The random transmit timestamp the reply must echo.
    nonce: [u8; 8],
    /// T1: the local time when the request left.
    t1: Fixed,
}

impl Request {
    /// A version 4 client request (mode 3) whose transmit timestamp is `nonce`, sent at local time `t1`.
    pub(crate) fn new(nonce: u64, t1: Fixed) -> Self {
        let mut bytes = [0_u8; PACKET];
        // Leap indicator 0, version 4, mode 3 (client).
        bytes[0] = 0b00_100_011;
        let nonce = nonce.max(1).to_be_bytes();
        bytes[40..48].copy_from_slice(&nonce);
        Self { bytes, nonce, t1 }
    }
}

/// What a valid reply says.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Sample {
    /// The server's clock minus ours, in seconds. Positive means our clock is behind.
    pub offset: f64,
    /// The round trip without the server's processing time, in seconds.
    pub delay: f64,
    /// The server's stratum, 1 to 15.
    pub stratum: u8,
}

/// Why a reply was not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reject {
    /// Fewer than 48 bytes.
    Short(usize),
    /// Not mode 4. The number is the mode the packet carried.
    Mode(u8),
    /// The origin timestamp is not the one we sent.
    Echo,
    /// Stratum 0. A kiss code, when the packet carries a plain upper case one.
    Stratum0(Option<String>),
    /// Stratum 16 or more: the server says it is not synchronized.
    Unsynchronized(u8),
    /// Leap indicator 3: the server's clock is not synchronized.
    Alarm,
    /// A version outside 1 to 4.
    Version(u8),
    /// A zero receive or transmit timestamp.
    NoTimestamp,
    /// The server held the packet longer than the round trip took, so the clocks cannot be right.
    Delay,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short(n) => write!(f, "the reply was {n} bytes, an NTP packet is 48"),
            Self::Mode(m) => write!(f, "the reply was mode {m}, not a server reply (mode 4)"),
            Self::Echo => f.write_str("the reply did not echo the request, so it was ignored"),
            Self::Stratum0(Some(code)) => {
                write!(f, "the server refused to answer (kiss code {code})")
            }
            Self::Stratum0(None) => f.write_str("the server answered with stratum 0"),
            Self::Unsynchronized(s) => {
                write!(
                    f,
                    "the server reports stratum {s}, which is not synchronized"
                )
            }
            Self::Alarm => f.write_str("the server reports that its own clock is not synchronized"),
            Self::Version(v) => write!(f, "the reply was NTP version {v}"),
            Self::NoTimestamp => f.write_str("the reply carries a zero timestamp"),
            Self::Delay => f.write_str("the reply timestamps are not possible for this round trip"),
        }
    }
}

/// Judges `reply` against `request`. `t4` is the local time when the reply arrived.
///
/// Bytes after the first 48 (extension fields, a MAC) are ignored.
pub(crate) fn judge(request: &Request, reply: &[u8], t4: Fixed) -> Result<Sample, Reject> {
    let Some(head) = reply.get(..PACKET) else {
        return Err(Reject::Short(reply.len()));
    };
    let mode = head[0] & 0b111;
    if mode != 4 {
        return Err(Reject::Mode(mode));
    }
    // The echo comes before every other field, so a packet that did not come from the server cannot
    // make rdy print anything specific about the server.
    if head[24..32] != request.nonce {
        return Err(Reject::Echo);
    }
    let stratum = head[1];
    if stratum == 0 {
        return Err(Reject::Stratum0(kiss_code(&head[12..16])));
    }
    if stratum >= 16 {
        return Err(Reject::Unsynchronized(stratum));
    }
    if head[0] >> 6 == 3 {
        return Err(Reject::Alarm);
    }
    let version = (head[0] >> 3) & 0b111;
    if !(1..=4).contains(&version) {
        return Err(Reject::Version(version));
    }
    let (rx, tx) = (&head[32..40], &head[40..48]);
    if rx.iter().all(|b| *b == 0) || tx.iter().all(|b| *b == 0) {
        return Err(Reject::NoTimestamp);
    }
    let t2 = wire_time(rx, request.t1);
    let t3 = wire_time(tx, request.t1);
    let sum = (t2 - request.t1) + (t3 - t4);
    let offset = to_seconds(sum) / 2.0;
    let delay = to_seconds((t4 - request.t1) - (t3 - t2));
    // A server cannot hold a packet longer than the round trip. A little slack covers the clock
    // resolution of the two ends.
    if delay < -0.05 || !offset.is_finite() {
        return Err(Reject::Delay);
    }
    Ok(Sample {
        offset,
        delay: delay.max(0.0),
        stratum,
    })
}

/// The four ASCII upper case letters of a kiss code, or `None` for anything else.
fn kiss_code(bytes: &[u8]) -> Option<String> {
    let code: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| char::from(*b))
        .collect();
    (!code.is_empty() && code.chars().all(|c| c.is_ascii_uppercase())).then_some(code)
}

/// A wire timestamp (32 bit seconds since 1900, 32 bit fraction) on the Unix epoch, in the era closest
/// to `near`. After 7 February 2036 the seconds wrap, and this keeps the answer right.
fn wire_time(bytes: &[u8], near: Fixed) -> Fixed {
    let mut secs = [0_u8; 4];
    let mut frac = [0_u8; 4];
    secs.copy_from_slice(&bytes[..4]);
    frac.copy_from_slice(&bytes[4..8]);
    let base = i128::from(u32::from_be_bytes(secs)) - NTP_TO_UNIX;
    let near_secs = near >> 32;
    let era = (near_secs - base + ERA / 2).div_euclid(ERA);
    ((base + era * ERA) << 32) | i128::from(u32::from_be_bytes(frac))
}

fn to_seconds(fixed: Fixed) -> f64 {
    fixed as f64 / 4_294_967_296.0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fixed local time: 2026-11-02 09:00:00 UTC.
    const NOW: Fixed = 1_793_005_200_i128 << 32;

    /// A server reply to the datagram `sent` at server time `server` (T2 = T3), with the given first
    /// byte and stratum. The origin timestamp is copied from the request, as a real server does.
    pub(crate) fn reply_to(sent: &[u8], server: Fixed, first: u8, stratum: u8) -> Vec<u8> {
        let mut bytes = vec![0_u8; PACKET];
        bytes[0] = first;
        bytes[1] = stratum;
        if let Some(origin) = sent.get(40..48) {
            bytes[24..32].copy_from_slice(origin);
        }
        let wire = wire_bytes(server);
        bytes[32..40].copy_from_slice(&wire);
        bytes[40..48].copy_from_slice(&wire);
        bytes
    }

    fn reply(request: &Request, server: Fixed, first: u8, stratum: u8) -> Vec<u8> {
        reply_to(&request.bytes, server, first, stratum)
    }

    pub(crate) fn wire_bytes(unix: Fixed) -> [u8; 8] {
        let secs = u32::try_from(((unix >> 32) + NTP_TO_UNIX).rem_euclid(ERA)).unwrap_or(0);
        let frac = u32::try_from(unix & 0xffff_ffff).unwrap_or(0);
        let mut out = [0_u8; 8];
        out[..4].copy_from_slice(&secs.to_be_bytes());
        out[4..].copy_from_slice(&frac.to_be_bytes());
        out
    }

    const SERVER_V4: u8 = 0b00_100_100;

    #[test]
    fn the_request_is_a_client_packet_with_the_nonce_as_transmit_time() {
        let request = Request::new(0x0102_0304_0506_0708, NOW);
        assert_eq!(request.bytes.len(), 48);
        assert_eq!(request.bytes[0], 0x23);
        assert_eq!(&request.bytes[40..48], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(request.bytes[1..40].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_zero_nonce_is_never_sent() {
        let request = Request::new(0, NOW);
        assert_ne!(request.nonce, [0; 8]);
    }

    #[test]
    fn the_offset_is_server_minus_client() {
        let request = Request::new(7, NOW);
        let bytes = reply(&request, NOW + (400_i128 << 32), SERVER_V4, 2);
        let sample = judge(&request, &bytes, NOW).expect("a valid reply");
        assert!((sample.offset - 400.0).abs() < 1e-6, "{sample:?}");
        assert!(sample.delay.abs() < 1e-6);
        assert_eq!(sample.stratum, 2);
    }

    #[test]
    fn a_slow_client_clock_gives_a_negative_offset() {
        let request = Request::new(7, NOW);
        let bytes = reply(&request, NOW - (12_i128 << 32), SERVER_V4, 3);
        let sample = judge(&request, &bytes, NOW).expect("a valid reply");
        assert!((sample.offset + 12.0).abs() < 1e-6);
    }

    #[test]
    fn the_formula_uses_both_legs_of_the_trip() {
        // T1 = 0, server holds the packet for 1 s after 2 s, T4 = 6 s: delay = 6 - 1 = 5 s.
        // T2 = T1 + 100 + 2.5 (server ahead by 100 s, outbound 2.5 s), T3 = T2 + 1.
        let request = Request::new(7, NOW);
        let mut bytes = reply(&request, NOW, SERVER_V4, 2);
        let t2 = NOW + (102_i128 << 32) + (1_i128 << 31);
        let t3 = t2 + (1_i128 << 32);
        bytes[32..40].copy_from_slice(&wire_bytes(t2));
        bytes[40..48].copy_from_slice(&wire_bytes(t3));
        let t4 = NOW + (6_i128 << 32);
        let sample = judge(&request, &bytes, t4).expect("a valid reply");
        // ((T2-T1) + (T3-T4)) / 2 = ((102.5) + (103.5 - 6)) / 2 = 100.
        assert!((sample.offset - 100.0).abs() < 1e-6, "{sample:?}");
        assert!((sample.delay - 5.0).abs() < 1e-6, "{sample:?}");
    }

    #[test]
    fn a_reply_that_does_not_echo_the_nonce_is_refused() {
        let request = Request::new(7, NOW);
        let mut bytes = reply(&request, NOW, SERVER_V4, 2);
        bytes[31] ^= 1;
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Echo));
        // A reply to another request is the same thing.
        let other = Request::new(8, NOW);
        let bytes = reply(&other, NOW, SERVER_V4, 2);
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Echo));
    }

    #[test]
    fn only_mode_4_is_accepted() {
        let request = Request::new(7, NOW);
        for mode in [0_u8, 1, 2, 3, 5, 6, 7] {
            let bytes = reply(&request, NOW, 0b00_100_000 | mode, 2);
            assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Mode(mode)));
        }
    }

    #[test]
    fn stratum_0_and_16_are_refused_and_15_and_1_are_not() {
        let request = Request::new(7, NOW);
        let bytes = reply(&request, NOW, SERVER_V4, 0);
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Stratum0(None)));
        for stratum in [16_u8, 17, 255] {
            let bytes = reply(&request, NOW, SERVER_V4, stratum);
            assert_eq!(
                judge(&request, &bytes, NOW),
                Err(Reject::Unsynchronized(stratum))
            );
        }
        for stratum in [1_u8, 15] {
            let bytes = reply(&request, NOW, SERVER_V4, stratum);
            assert!(judge(&request, &bytes, NOW).is_ok(), "{stratum}");
        }
    }

    #[test]
    fn a_kiss_code_is_named_only_when_it_is_plain_upper_case() {
        let request = Request::new(7, NOW);
        let mut bytes = reply(&request, NOW, SERVER_V4, 0);
        bytes[12..16].copy_from_slice(b"RATE");
        assert_eq!(
            judge(&request, &bytes, NOW),
            Err(Reject::Stratum0(Some("RATE".to_owned())))
        );
        bytes[12..16].copy_from_slice(b"\x1b[2J");
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Stratum0(None)));
    }

    #[test]
    fn an_alarm_leap_indicator_is_refused() {
        let request = Request::new(7, NOW);
        let bytes = reply(&request, NOW, 0b11_100_100, 2);
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Alarm));
        // Leap 1 and 2 (a leap second tonight) are fine.
        let bytes = reply(&request, NOW, 0b01_100_100, 2);
        assert!(judge(&request, &bytes, NOW).is_ok());
    }

    #[test]
    fn versions_one_to_four_are_accepted_and_others_refused() {
        let request = Request::new(7, NOW);
        for version in 1_u8..=4 {
            let bytes = reply(&request, NOW, (version << 3) | 4, 2);
            assert!(judge(&request, &bytes, NOW).is_ok(), "{version}");
        }
        for version in [0_u8, 5, 6, 7] {
            let bytes = reply(&request, NOW, (version << 3) | 4, 2);
            assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Version(version)));
        }
    }

    #[test]
    fn short_and_empty_replies_are_refused() {
        let request = Request::new(7, NOW);
        assert_eq!(judge(&request, &[], NOW), Err(Reject::Short(0)));
        assert_eq!(judge(&request, &[0x24; 47], NOW), Err(Reject::Short(47)));
    }

    #[test]
    fn a_zero_receive_or_transmit_timestamp_is_refused() {
        let request = Request::new(7, NOW);
        let mut bytes = reply(&request, NOW, SERVER_V4, 2);
        bytes[40..48].fill(0);
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::NoTimestamp));
        let mut bytes = reply(&request, NOW, SERVER_V4, 2);
        bytes[32..40].fill(0);
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::NoTimestamp));
    }

    #[test]
    fn a_server_that_held_the_packet_longer_than_the_trip_is_refused() {
        let request = Request::new(7, NOW);
        let mut bytes = reply(&request, NOW, SERVER_V4, 2);
        // T3 is 10 s after T2 but the whole trip took 0 s.
        bytes[40..48].copy_from_slice(&wire_bytes(NOW + (10_i128 << 32)));
        assert_eq!(judge(&request, &bytes, NOW), Err(Reject::Delay));
    }

    #[test]
    fn extra_bytes_after_the_packet_are_ignored() {
        let request = Request::new(7, NOW);
        let mut bytes = reply(&request, NOW + (1_i128 << 32), SERVER_V4, 2);
        bytes.extend_from_slice(&[0xff; 20]);
        assert!(judge(&request, &bytes, NOW).is_ok());
    }

    #[test]
    fn the_era_wraps_after_2036_without_a_bogus_offset() {
        // 2040-01-01 00:00:00 UTC is past the first NTP era. The seconds field wraps to a small number.
        let late: Fixed = 2_208_988_800_i128 + 2_000_000_000 + 400_000_000;
        let local = (late - NTP_TO_UNIX) << 32;
        let request = Request::new(9, local);
        let bytes = reply(&request, local + (400_i128 << 32), SERVER_V4, 2);
        let wire_secs = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        assert!(
            i128::from(wire_secs) < late,
            "the wire seconds wrapped: {wire_secs}"
        );
        let sample = judge(&request, &bytes, local).expect("a valid reply");
        assert!((sample.offset - 400.0).abs() < 1e-6, "{sample:?}");
    }

    #[test]
    fn a_clock_before_1970_has_no_fixed_time() {
        let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(fixed_from(before), None);
        let after = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1500);
        let fixed = fixed_from(after).expect("a time");
        assert_eq!(fixed >> 32, 1);
        assert!((to_seconds(fixed) - 1.5).abs() < 1e-6);
    }

    proptest::proptest! {
        #[test]
        fn no_reply_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            let request = Request::new(7, NOW);
            let _ = judge(&request, &bytes, NOW);
        }
    }
}
