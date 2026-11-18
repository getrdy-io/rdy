//! The DNS wire format of `net.dns` (M1-155): the one query this check sends and the reply it reads.
//!
//! Both are written by hand, about 150 lines each way, because the reply is text from the network and a
//! general DNS library decodes every record type (some of them parse URLs and the like). This reader looks
//! only at what it needs. The bytes travel through `Probe::nameserver_exchange`, whose admission rules this
//! module is built to fit (ADR 0051): one question, class IN, type A or AAAA, recursion desired, no OPT
//! record, no compression in the query, and a name that is one of the check's own. The facade picks the
//! message ID (the query is built with ID 0 and the facade overwrites it).
//!
//! **Reading a reply.** Every read is checked against the buffer. The header must be a response (QR 1,
//! opcode 0) with the expected ID and exactly one question that is ours (name compared without case, same
//! type, class IN). Then the answer section is read, up to [`MAX_RECORDS`] records. A record of type A (4
//! bytes), AAAA (16 bytes) or CNAME (a name) is kept; any other type is skipped by its RDLENGTH. The
//! authority and additional sections are never read. A reply with the TC bit is not read past the question: it is
//! cut anywhere, and the caller asks again over TCP. A compression pointer must point strictly backwards
//! (to an offset below the first byte of the pointer), and at most [`MAX_HOPS`] pointers are followed in one
//! name, so a loop cannot run. A label with the top bits `01` or `10` is refused. A name longer than 255
//! bytes is refused.
//!
//! **The answer is the chain.** Starting at the question name, a CNAME whose owner is the current name moves
//! the current name to its target, at most [`MAX_CHAIN`] times. An A or AAAA record counts only when its class
//! is IN and its owner is on that chain. So a record for another name, which a hostile or confused server
//! may add, never becomes an address of ours.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The most addresses kept from one reply.
pub(super) const MAX_ADDRS: usize = 64;

/// The most answer records read.
const MAX_RECORDS: usize = 128;

/// The most compression pointers followed in one name.
const MAX_HOPS: usize = 16;

/// The most CNAME links followed.
const MAX_CHAIN: usize = 8;

/// The record type asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Qtype {
    A,
    Aaaa,
}

impl Qtype {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// The response code of a reply, reduced to the ones that mean something to this check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rcode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    /// Any other code, with its number.
    Other(u8),
}

impl Rcode {
    fn of(low4: u8) -> Self {
        match low4 {
            0 => Self::NoError,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            5 => Self::Refused,
            n => Self::Other(n),
        }
    }

    /// The name a DNS engineer knows it by.
    pub(super) fn text(self) -> String {
        match self {
            Self::NoError => "NOERROR".to_owned(),
            Self::NxDomain => "NXDOMAIN".to_owned(),
            Self::ServFail => "SERVFAIL".to_owned(),
            Self::Refused => "REFUSED".to_owned(),
            Self::Other(n) => format!("RCODE {n}"),
        }
    }
}

/// What a reply said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reply {
    pub(super) rcode: Rcode,
    /// The server cut the answer (TC): ask again over TCP.
    pub(super) truncated: bool,
    /// The A or AAAA addresses on the CNAME chain of the question, without repeats, at most [`MAX_ADDRS`].
    pub(super) addrs: Vec<IpAddr>,
}

/// The query for `name`: header with ID 0 (the facade sets the real one), recursion desired, one question,
/// class IN. A trailing dot is ignored.
///
/// # Errors
///
/// A short phrase when the name is empty, has an empty label or a label over 63 bytes, is over 253 bytes, or
/// has a byte other than a letter, digit, `-` or `_`.
pub(super) fn build_query(name: &str, qtype: Qtype) -> Result<Vec<u8>, &'static str> {
    const BAD: &str = "the name is not a valid DNS name";
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err(BAD);
    }
    let mut out = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(BAD);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.code().to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    Ok(out)
}

/// A bounds-checked reader over the reply.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.buf.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A name at the cursor, lowercase and dotted, and the cursor moves past it (past the first pointer, if
    /// there is one). A byte that is not a letter, digit, `-` or `_` becomes U+FFFD, which is never in a
    /// name the check asked for, so such a name matches nothing.
    fn name(&mut self) -> Option<String> {
        let (name, next) = name_at(self.buf, self.at)?;
        self.at = next;
        Some(name)
    }
}

/// Decodes the name at `start` and returns it with the offset just after it in the original place.
fn name_at(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut at = start;
    let mut after: Option<usize> = None;
    let mut hops = 0;
    loop {
        let len = *buf.get(at)?;
        match len {
            0 => {
                at += 1;
                break;
            }
            1..=63 => {
                let label = buf.get(at + 1..at + 1 + usize::from(len))?;
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in label {
                    out.push(if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                        char::from(b.to_ascii_lowercase())
                    } else {
                        '\u{fffd}'
                    });
                }
                at += 1 + usize::from(len);
                if out.len() > 255 {
                    return None;
                }
            }
            0xc0..=0xff => {
                let low = *buf.get(at + 1)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                // Strictly backwards: a pointer to itself or forwards would loop or read ahead.
                if target >= at {
                    return None;
                }
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                after.get_or_insert(at + 2);
                at = target;
            }
            // 0x40..=0xbf: extended or reserved label types.
            _ => return None,
        }
    }
    Some((out, after.unwrap_or(at)))
}

/// One answer record that this check looks at.
enum Data {
    Addr(IpAddr),
    Cname(String),
}

/// Reads a reply to the query `(id, name, qtype)`.
///
/// # Errors
///
/// A short phrase for a note when the bytes are not a well-formed DNS response, carry another ID, opcode or
/// question, or when the facade cut them (`cut`).
pub(super) fn parse_reply(
    bytes: &[u8],
    cut: bool,
    id: u16,
    name: &str,
    qtype: Qtype,
) -> Result<Reply, &'static str> {
    const BROKEN: &str = "the reply is not a DNS message";
    if cut {
        return Err("the reply was longer than rdy reads");
    }
    let mut r = Reader { buf: bytes, at: 0 };
    let got_id = r.u16().ok_or(BROKEN)?;
    let flags = r.u16().ok_or(BROKEN)?;
    let qd = r.u16().ok_or(BROKEN)?;
    let an = r.u16().ok_or(BROKEN)?;
    r.take(4).ok_or(BROKEN)?;
    if flags & 0x8000 == 0 {
        return Err("the reply is not a response");
    }
    if got_id != id {
        return Err("the reply carries another message ID");
    }
    if (flags >> 11) & 0xf != 0 {
        return Err("the reply carries another opcode");
    }
    if qd != 1 {
        return Err("the reply does not repeat exactly one question");
    }
    let asked = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let qname = r.name().ok_or(BROKEN)?;
    let qtype_got = r.u16().ok_or(BROKEN)?;
    let qclass = r.u16().ok_or(BROKEN)?;
    if qname != asked || qtype_got != qtype.code() || qclass != 1 {
        return Err("the reply answers another question");
    }
    let rcode = Rcode::of((flags & 0xf) as u8);
    // A truncated reply is cut anywhere, so its answers are not read. The caller asks again over TCP.
    if flags & 0x0200 != 0 {
        return Ok(Reply {
            rcode,
            truncated: true,
            addrs: Vec::new(),
        });
    }
    let mut records: Vec<(String, Data)> = Vec::new();
    for _ in 0..usize::from(an).min(MAX_RECORDS) {
        let owner = r.name().ok_or(BROKEN)?;
        let rtype = r.u16().ok_or(BROKEN)?;
        let class = r.u16().ok_or(BROKEN)?;
        r.u32().ok_or(BROKEN)?;
        let len = usize::from(r.u16().ok_or(BROKEN)?);
        let start = r.at;
        let rdata = r.take(len).ok_or(BROKEN)?;
        if class != 1 {
            continue;
        }
        let data = match (rtype, len) {
            (1, 4) => Data::Addr(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (28, 16) => {
                let mut b = [0_u8; 16];
                b.copy_from_slice(rdata);
                let v6 = Ipv6Addr::from(b);
                // An IPv4-mapped answer is the IPv4 address it carries, as in the `getent` reader.
                Data::Addr(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4))
            }
            // A or AAAA with the wrong length is a broken record, not a skipped one.
            (1 | 28, _) => return Err(BROKEN),
            (5, _) => {
                // The target may point back into the message, so it is decoded in place. It must end
                // inside the RDATA.
                let (target, end) = name_at(bytes, start).ok_or(BROKEN)?;
                if end > start + len {
                    return Err(BROKEN);
                }
                Data::Cname(target)
            }
            _ => continue,
        };
        records.push((owner, data));
    }
    // Follow the chain from the question name.
    let mut chain: Vec<String> = vec![asked];
    for _ in 0..MAX_CHAIN {
        let current = chain.last().cloned().unwrap_or_default();
        let next = records.iter().find_map(|(owner, data)| match data {
            Data::Cname(target) if *owner == current && !chain.contains(target) => {
                Some(target.clone())
            }
            _ => None,
        });
        match next {
            Some(target) => chain.push(target),
            None => break,
        }
    }
    let mut addrs: Vec<IpAddr> = Vec::new();
    for (owner, data) in &records {
        if let Data::Addr(ip) = data
            && chain.contains(owner)
            && !addrs.contains(ip)
            && addrs.len() < MAX_ADDRS
        {
            addrs.push(*ip);
        }
    }
    Ok(Reply {
        rcode,
        truncated: false,
        addrs,
    })
}

#[cfg(test)]
pub(super) mod tests {
    //! `hickory-proto` is the test oracle only (a dev-dependency): it encodes replies and decodes our
    //! queries, and the hand-written code must agree with it.

    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use proptest::prelude::*;

    fn rtype(q: Qtype) -> RecordType {
        match q {
            Qtype::A => RecordType::A,
            Qtype::Aaaa => RecordType::AAAA,
        }
    }

    fn n(text: &str) -> Name {
        Name::from_ascii(text).expect("a name")
    }

    /// A reply to `(id, name, qtype)` with these answers, owned by the question name.
    pub(in crate::dns) fn reply_bytes(
        id: u16,
        name: &str,
        qtype: Qtype,
        rcode: ResponseCode,
        answers: Vec<RData>,
    ) -> Vec<u8> {
        let owned: Vec<(&str, RData)> = answers.into_iter().map(|d| (name, d)).collect();
        reply_with_owners(id, name, qtype, rcode, owned)
    }

    /// Like `reply_bytes`, with an owner name for each answer.
    pub(in crate::dns) fn reply_with_owners(
        id: u16,
        name: &str,
        qtype: Qtype,
        rcode: ResponseCode,
        answers: Vec<(&str, RData)>,
    ) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.metadata.recursion_available = true;
        m.add_query(Query::query(n(name), rtype(qtype)));
        for (owner, data) in answers {
            m.add_answer(Record::from_rdata(n(owner), 60, data));
        }
        m.to_vec().expect("encodes")
    }

    fn v4(text: &str) -> RData {
        RData::A(A(text.parse().expect("ip")))
    }

    fn cname(to: &str) -> RData {
        RData::CNAME(CNAME(n(to)))
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    #[test]
    fn the_query_is_one_plain_question_and_the_oracle_reads_it_the_same() {
        for (name, qtype) in [
            ("Web.Acme.Test", Qtype::A),
            ("a-b_c.x.example", Qtype::Aaaa),
        ] {
            let bytes = build_query(name, qtype).expect("a query");
            assert_eq!(&bytes[..2], &[0, 0], "the facade sets the ID");
            assert!(bytes.len() <= 512);
            // The oracle decodes it to the one question and nothing else.
            let m = Message::from_vec(&bytes).expect("the oracle reads our query");
            assert_eq!(m.metadata.message_type, MessageType::Query);
            assert_eq!(m.metadata.op_code, OpCode::Query);
            assert!(m.metadata.recursion_desired);
            assert_eq!(m.queries.len(), 1);
            assert!(m.answers.is_empty() && m.authorities.is_empty() && m.additionals.is_empty());
            assert!(m.edns.is_none(), "no OPT record");
            assert_eq!(
                m.queries[0].name().to_ascii().to_lowercase(),
                format!("{}.", name.to_lowercase())
            );
            assert_eq!(m.queries[0].query_type(), rtype(qtype));
            assert_eq!(m.queries[0].query_class(), DNSClass::IN);
        }
        let with_dot = build_query("web.acme.test.", Qtype::A).expect("a query");
        assert_eq!(
            with_dot,
            build_query("web.acme.test", Qtype::A).expect("a query")
        );
    }

    #[test]
    fn a_bad_name_is_refused_before_it_is_sent() {
        let long = format!("{}.test", "a.".repeat(130));
        for bad in [
            "",
            "a..b",
            ".",
            &"a".repeat(64),
            &long,
            "a b",
            "a/b",
            "a\u{e9}.test",
            "-",
        ] {
            let want_err = bad != "-";
            assert_eq!(build_query(bad, Qtype::A).is_err(), want_err, "{bad:?}");
        }
    }

    #[test]
    fn a_matching_reply_gives_its_addresses_once() {
        let bytes = reply_bytes(
            7,
            "web.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![
                v4("192.0.2.10"),
                v4("192.0.2.10"),
                RData::AAAA(AAAA("::ffff:192.0.2.11".parse().expect("ip"))),
            ],
        );
        let reply = parse_reply(&bytes, false, 7, "WEB.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.rcode, Rcode::NoError);
        assert!(!reply.truncated);
        assert_eq!(reply.addrs, [ip("192.0.2.10"), ip("192.0.2.11")]);
    }

    #[test]
    fn the_codes_that_matter_are_named() {
        for (code, want) in [
            (ResponseCode::NXDomain, Rcode::NxDomain),
            (ResponseCode::ServFail, Rcode::ServFail),
            (ResponseCode::Refused, Rcode::Refused),
            (ResponseCode::NotImp, Rcode::Other(4)),
        ] {
            let bytes = reply_bytes(9, "a.acme.test", Qtype::A, code, vec![]);
            let reply = parse_reply(&bytes, false, 9, "a.acme.test", Qtype::A).expect("a reply");
            assert_eq!(reply.rcode, want);
            assert!(reply.addrs.is_empty());
        }
        assert_eq!(Rcode::NxDomain.text(), "NXDOMAIN");
        assert_eq!(Rcode::Other(4).text(), "RCODE 4");
    }

    #[test]
    fn a_reply_to_another_id_name_type_or_class_is_refused() {
        let good = reply_bytes(
            5,
            "a.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![v4("192.0.2.1")],
        );
        assert!(parse_reply(&good, false, 5, "a.acme.test", Qtype::A).is_ok());
        assert_eq!(
            parse_reply(&good, false, 6, "a.acme.test", Qtype::A),
            Err("the reply carries another message ID")
        );
        assert_eq!(
            parse_reply(&good, false, 5, "b.acme.test", Qtype::A),
            Err("the reply answers another question")
        );
        assert_eq!(
            parse_reply(&good, false, 5, "a.acme.test", Qtype::Aaaa),
            Err("the reply answers another question")
        );
        let mut query = build_query("a.acme.test", Qtype::A).expect("a query");
        query[..2].copy_from_slice(&5_u16.to_be_bytes());
        assert_eq!(
            parse_reply(&query, false, 5, "a.acme.test", Qtype::A),
            Err("the reply is not a response")
        );
        // Class CH, the byte after the type.
        let mut chaos = good.clone();
        let at = 12 + "a.acme.test".len() + 2 + 2;
        chaos[at + 1] = 3;
        assert_eq!(
            parse_reply(&chaos, false, 5, "a.acme.test", Qtype::A),
            Err("the reply answers another question")
        );
        let mut none = good.clone();
        none[4..6].copy_from_slice(&[0, 0]);
        assert!(parse_reply(&none, false, 5, "a.acme.test", Qtype::A).is_err());
        let mut notify = good;
        notify[2] |= 4 << 3;
        assert_eq!(
            parse_reply(&notify, false, 5, "a.acme.test", Qtype::A),
            Err("the reply carries another opcode")
        );
    }

    #[test]
    fn a_cut_or_broken_reply_is_an_error() {
        let good = reply_bytes(
            5,
            "a.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![v4("192.0.2.1")],
        );
        assert_eq!(
            parse_reply(&good, true, 5, "a.acme.test", Qtype::A),
            Err("the reply was longer than rdy reads")
        );
        // Every proper prefix is an error, never a panic and never an address.
        for end in 0..good.len() {
            assert!(
                parse_reply(&good[..end], false, 5, "a.acme.test", Qtype::A).is_err(),
                "{end}"
            );
        }
    }

    #[test]
    fn a_truncated_reply_is_not_read_past_the_question() {
        // TC set, then bytes that would be a broken answer: the answer is not read, so it is not an error.
        let mut bytes = with_tail(&[0xde, 0xad, 0xbe, 0xef]);
        bytes[2] |= 0x02;
        let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert!(reply.truncated && reply.addrs.is_empty());
    }

    #[test]
    fn the_truncation_flag_is_kept() {
        let mut bytes = reply_bytes(5, "a.acme.test", Qtype::A, ResponseCode::NoError, vec![]);
        bytes[2] |= 0x02;
        let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert!(reply.truncated);
    }

    #[test]
    fn answers_are_capped() {
        let many: Vec<RData> = (0..200_u32)
            .map(|k| RData::A(A(std::net::Ipv4Addr::from(0xc000_0200 + k))))
            .collect();
        let bytes = reply_bytes(5, "a.acme.test", Qtype::A, ResponseCode::NoError, many);
        let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.addrs.len(), MAX_ADDRS);
    }

    #[test]
    fn other_record_types_are_skipped_by_their_length() {
        let bytes = reply_bytes(
            5,
            "a.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![
                RData::TXT(TXT::new(vec!["hello".to_owned()])),
                v4("192.0.2.1"),
            ],
        );
        let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.addrs, [ip("192.0.2.1")]);
    }

    #[test]
    fn the_cname_chain_is_followed_and_other_owners_do_not_count() {
        let bytes = reply_with_owners(
            5,
            "web.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![
                ("web.acme.test", cname("lb.acme.test")),
                ("lb.acme.test", cname("edge.other.test")),
                ("edge.other.test", v4("192.0.2.10")),
                // Not on the chain: a hostile or confused server adds a record for another name.
                ("evil.acme.test", v4("203.0.113.66")),
                ("lb.acme.test", v4("192.0.2.11")),
            ],
        );
        let reply = parse_reply(&bytes, false, 5, "web.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.addrs, [ip("192.0.2.10"), ip("192.0.2.11")]);
        // Answers listed before the CNAME that leads to them still count.
        let backwards = reply_with_owners(
            5,
            "web.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![
                ("lb.acme.test", v4("192.0.2.12")),
                ("web.acme.test", cname("lb.acme.test")),
            ],
        );
        let reply = parse_reply(&backwards, false, 5, "web.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.addrs, [ip("192.0.2.12")]);
    }

    #[test]
    fn a_chain_longer_than_eight_links_stops_and_a_loop_cannot_run() {
        let mut links: Vec<(String, RData)> = (0..12)
            .map(|k| {
                (
                    format!("c{k}.acme.test"),
                    cname(&format!("c{}.acme.test", k + 1)),
                )
            })
            .collect();
        links.push(("c12.acme.test".to_owned(), v4("192.0.2.99")));
        let owned: Vec<(&str, RData)> =
            links.iter().map(|(o, d)| (o.as_str(), d.clone())).collect();
        let mut all = vec![("web.acme.test", cname("c0.acme.test"))];
        all.extend(owned);
        let bytes = reply_with_owners(5, "web.acme.test", Qtype::A, ResponseCode::NoError, all);
        let reply = parse_reply(&bytes, false, 5, "web.acme.test", Qtype::A).expect("a reply");
        assert!(
            reply.addrs.is_empty(),
            "the address is more than eight links away"
        );

        let looped = reply_with_owners(
            5,
            "a.acme.test",
            Qtype::A,
            ResponseCode::NoError,
            vec![
                ("a.acme.test", cname("b.acme.test")),
                ("b.acme.test", cname("a.acme.test")),
            ],
        );
        let reply = parse_reply(&looped, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert!(reply.addrs.is_empty());
    }

    #[test]
    fn a_record_of_another_class_does_not_count() {
        let mut m = Message::new(5, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(n("a.acme.test"), RecordType::A));
        let mut rec = Record::from_rdata(n("a.acme.test"), 60, v4("192.0.2.1"));
        rec.dns_class = DNSClass::CH;
        m.add_answer(rec);
        let bytes = m.to_vec().expect("encodes");
        let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert!(reply.addrs.is_empty());
    }

    /// A reply with a header and the question, then `tail` as the answer section (one answer claimed).
    fn with_tail(tail: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 5, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in ["a", "acme", "test"] {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out.extend_from_slice(tail);
        out
    }

    #[test]
    fn compression_pointers_must_point_backwards_and_cannot_loop() {
        // Owner is a pointer to the question name at offset 12 (backwards): fine.
        let ok = with_tail(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        let reply = parse_reply(&ok, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.addrs, [ip("192.0.2.7")]);
        let at = ok.len() - 16;
        // A pointer to itself, to a later offset, and one into the header region that loops back.
        for target in [at, at + 2, 0x3fff] {
            let mut bad = ok.clone();
            bad[at] = 0xc0 | (target >> 8) as u8;
            bad[at + 1] = target as u8;
            assert!(
                parse_reply(&bad, false, 5, "a.acme.test", Qtype::A).is_err(),
                "{target}"
            );
        }
        // Seventeen pointers in a row exceed the hop cap even though each points backwards.
        let mut chain = with_tail(&[]);
        let mut first = chain.len();
        chain.extend_from_slice(&[0xc0, 12]);
        for _ in 0..17 {
            let here = chain.len();
            chain.extend_from_slice(&[0xc0 | (first >> 8) as u8, first as u8]);
            first = here;
        }
        chain.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 8]);
        // The answer's owner is the last pointer; that name is 18 hops from the question.
        let start = chain.len() - 14 - 2;
        let owner_ptr = [0xc0 | (first >> 8) as u8, first as u8];
        chain.splice(start..start + 2, owner_ptr);
        assert!(parse_reply(&chain, false, 5, "a.acme.test", Qtype::A).is_err());
    }

    #[test]
    fn label_types_and_lengths_that_are_not_plain_are_refused() {
        // 0x40 (extended label) and 0x80 as the first byte of the owner.
        for first in [0x40_u8, 0x80] {
            let bad = with_tail(&[first, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
            assert!(parse_reply(&bad, false, 5, "a.acme.test", Qtype::A).is_err());
        }
        // An A record with RDLENGTH 3, and an RDLENGTH past the end of the buffer.
        let short = with_tail(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 3, 1, 2, 3]);
        assert!(parse_reply(&short, false, 5, "a.acme.test", Qtype::A).is_err());
        let past = with_tail(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 200, 1, 2, 3]);
        assert!(parse_reply(&past, false, 5, "a.acme.test", Qtype::A).is_err());
    }

    #[test]
    fn a_name_with_an_odd_byte_matches_nothing() {
        let mut odd = with_tail(&[]);
        // One answer whose owner is `a.acme.te<space>t`, with an A record.
        odd.extend_from_slice(&[
            1, b'a', 4, b'a', b'c', b'm', b'e', 4, b't', b'e', b' ', b't', 0,
        ]);
        odd.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let reply = parse_reply(&odd, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert!(reply.addrs.is_empty());
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_reply(&bytes, false, 1, "a.acme.test", Qtype::A);
        }

        #[test]
        fn a_flipped_byte_never_panics(at in 0_usize..80, bit in 0_u8..8) {
            let mut bytes = reply_bytes(5, "a.acme.test", Qtype::A, ResponseCode::NoError, vec![v4("192.0.2.1"), cname("x.acme.test")]);
            let at = at % bytes.len();
            bytes[at] ^= 1 << bit;
            let _ = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A);
        }

        /// A valid header and question, then anything: the reader never panics, stays bounded, and never
        /// returns more than the cap.
        #[test]
        fn a_valid_start_followed_by_random_bytes_is_bounded(
            an in 0_u16..=u16::MAX,
            tail in proptest::collection::vec(any::<u8>(), 0..600),
        ) {
            let mut bytes = with_tail(&tail);
            bytes[6..8].copy_from_slice(&an.to_be_bytes());
            if let Ok(reply) = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A) {
                prop_assert!(reply.addrs.len() <= MAX_ADDRS);
            }
        }

        /// The oracle encodes, the hand reader reads, and they agree on the addresses.
        #[test]
        fn the_reader_agrees_with_the_oracle(
            v4s in proptest::collection::vec(any::<u32>(), 0..20),
            v6s in proptest::collection::vec(any::<u128>(), 0..6),
            via_cname in any::<bool>(),
        ) {
            let owner = if via_cname { "lb.acme.test" } else { "a.acme.test" };
            let mut answers: Vec<(&str, RData)> = Vec::new();
            if via_cname {
                answers.push(("a.acme.test", cname("lb.acme.test")));
            }
            let mut want: Vec<IpAddr> = Vec::new();
            for b in &v4s {
                let a = std::net::Ipv4Addr::from(*b);
                answers.push((owner, RData::A(A(a))));
                want.push(IpAddr::V4(a));
            }
            for b in &v6s {
                let a = std::net::Ipv6Addr::from(*b);
                answers.push((owner, RData::AAAA(AAAA(a))));
                want.push(a.to_ipv4_mapped().map_or(IpAddr::V6(a), IpAddr::V4));
            }
            let bytes = reply_with_owners(5, "a.acme.test", Qtype::A, ResponseCode::NoError, answers);
            let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
            let mut dedup: Vec<IpAddr> = Vec::new();
            for ip in want { if !dedup.contains(&ip) { dedup.push(ip); } }
            prop_assert_eq!(reply.addrs, dedup);
        }
    }
}
