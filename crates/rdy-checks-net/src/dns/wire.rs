//! The DNS wire format of `net.dns` (M1-155): the one query this check sends and the reply it reads.
//!
//! `hickory-proto` (default features off) does the encoding and decoding. It is a codec: it opens no socket
//! and reads no file. The bytes travel through `Probe::nameserver_exchange`, whose admission rules this
//! module is built to fit (ADR 0051): one question, class IN, type A or AAAA, recursion desired, no OPT
//! record, no compression in the query, and a name that is one of the check's own.
//!
//! **The reply is hostile text.** The server on the other end is whatever the network gives the machine.
//! A reply is accepted only when it is a response with our ID, the opcode of a query, and exactly our
//! question (name compared without case, same type, class IN). A mismatch is an error, never a guess:
//! that is what stops a stray datagram or a middlebox's canned reply from being read as the answer. The
//! decoder bounds every read by the buffer, the facade bounds the buffer (16 KiB), and the address list is
//! cut at [`MAX_ADDRS`].

use std::net::IpAddr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

/// The most addresses kept from one reply.
pub(super) const MAX_ADDRS: usize = 64;

/// The record type asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Qtype {
    A,
    Aaaa,
}

impl Qtype {
    fn record_type(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
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
    fn of(code: ResponseCode) -> Self {
        match code.low() {
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
    /// The A or AAAA addresses of the answer section, without repeats, at most [`MAX_ADDRS`]. A CNAME
    /// chain is followed by the server, so these are the addresses at the end of it.
    pub(super) addrs: Vec<IpAddr>,
}

/// The query for `name`: one question, class IN, recursion desired, no other section.
///
/// `name` must already be a valid spec name (see `parse::validate`). The ID is the caller's.
///
/// # Errors
///
/// A short phrase when the name is not a valid DNS name (an empty label, a label over 63 bytes, a name
/// over 253 bytes).
pub(super) fn build_query(name: &str, qtype: Qtype, id: u16) -> Result<Vec<u8>, &'static str> {
    let name = Name::from_ascii(name).map_err(|_| "the name is not a valid DNS name")?;
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, qtype.record_type()));
    message
        .to_vec()
        .map_err(|_| "the query could not be encoded")
}

/// Reads a reply to the query `(id, name, qtype)`.
///
/// # Errors
///
/// A short phrase for a note when the bytes are not a DNS message, are not a response, carry another ID,
/// opcode or question, or when the facade cut them (`cut`).
pub(super) fn parse_reply(
    bytes: &[u8],
    cut: bool,
    id: u16,
    name: &str,
    qtype: Qtype,
) -> Result<Reply, &'static str> {
    if cut {
        return Err("the reply was longer than rdy reads");
    }
    let message = Message::from_vec(bytes).map_err(|_| "the reply is not a DNS message")?;
    let meta = &message.metadata;
    if meta.message_type != MessageType::Response {
        return Err("the reply is not a response");
    }
    if meta.id != id {
        return Err("the reply carries another message ID");
    }
    if meta.op_code != OpCode::Query {
        return Err("the reply carries another opcode");
    }
    let asked = Name::from_ascii(name).map_err(|_| "the name is not a valid DNS name")?;
    let [question] = message.queries.as_slice() else {
        return Err("the reply does not repeat exactly one question");
    };
    if question.query_type() != qtype.record_type()
        || question.query_class() != DNSClass::IN
        || !question.name().eq_ignore_root_case(&asked)
    {
        return Err("the reply answers another question");
    }
    let mut addrs: Vec<IpAddr> = Vec::new();
    for record in &message.answers {
        let ip = match &record.data {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(a) => IpAddr::V6(a.0),
            _ => continue,
        };
        // An IPv4-mapped IPv6 answer is the IPv4 address it carries, as in the `getent` reader.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        if !addrs.contains(&ip) && addrs.len() < MAX_ADDRS {
            addrs.push(ip);
        }
    }
    Ok(Reply {
        rcode: Rcode::of(meta.response_code),
        truncated: meta.truncation,
        addrs,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use proptest::prelude::*;

    /// A well-formed reply to the query of `(id, name, qtype)` with these answers.
    pub(in crate::dns) fn reply_bytes(
        id: u16,
        name: &str,
        qtype: Qtype,
        rcode: ResponseCode,
        answers: Vec<RData>,
    ) -> Vec<u8> {
        let owner = Name::from_ascii(name).expect("a name");
        let mut m = Message::new(id, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.metadata.recursion_available = true;
        m.add_query(Query::query(owner.clone(), qtype.record_type()));
        for data in answers {
            m.add_answer(Record::from_rdata(owner.clone(), 60, data));
        }
        m.to_vec().expect("encodes")
    }

    fn v4(text: &str) -> RData {
        RData::A(A(text.parse().expect("ip")))
    }

    #[test]
    fn the_query_is_one_plain_question_the_facade_admits() {
        let bytes = build_query("Web.Acme.Test", Qtype::A, 0x1234).expect("a query");
        assert_eq!(&bytes[..2], &[0x12, 0x34]);
        // Flags: query, opcode 0, RD. Counts: one question, nothing else.
        assert_eq!(&bytes[2..4], &[0x01, 0x00]);
        assert_eq!(&bytes[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(bytes.len() <= 512);
        // The tail is QTYPE A and QCLASS IN, and there is no OPT record after it.
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 1, 0, 1]);
        let aaaa = build_query("web.acme.test", Qtype::Aaaa, 1).expect("a query");
        assert_eq!(&aaaa[aaaa.len() - 4..], &[0, 28, 0, 1]);
    }

    #[test]
    fn a_bad_name_is_refused_before_it_is_sent() {
        for bad in [
            "",
            "a..b",
            &"a".repeat(64),
            &format!("{}.test", "a.".repeat(130)),
        ] {
            assert!(build_query(bad, Qtype::A, 1).is_err(), "{bad:?}");
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
                RData::CNAME(CNAME(Name::from_ascii("lb.acme.test").expect("name"))),
                v4("192.0.2.10"),
                v4("192.0.2.10"),
                RData::AAAA(AAAA("::ffff:192.0.2.11".parse().expect("ip"))),
            ],
        );
        let reply = parse_reply(&bytes, false, 7, "WEB.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.rcode, Rcode::NoError);
        assert!(!reply.truncated);
        let want: Vec<IpAddr> = ["192.0.2.10", "192.0.2.11"]
            .iter()
            .map(|t| t.parse().expect("ip"))
            .collect();
        assert_eq!(reply.addrs, want);
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
        // A query is not a response.
        let query = build_query("a.acme.test", Qtype::A, 5).expect("a query");
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
        // No question at all.
        let mut none = good.clone();
        none[4..6].copy_from_slice(&[0, 0]);
        assert!(parse_reply(&none, false, 5, "a.acme.test", Qtype::A).is_err());
        // Another opcode.
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
        assert!(parse_reply(&good[..20], false, 5, "a.acme.test", Qtype::A).is_err());
        assert!(parse_reply(&[], false, 5, "a.acme.test", Qtype::A).is_err());
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
            .map(|n| RData::A(A(std::net::Ipv4Addr::from(0xc000_0200 + n))))
            .collect();
        let bytes = reply_bytes(5, "a.acme.test", Qtype::A, ResponseCode::NoError, many);
        let reply = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A).expect("a reply");
        assert_eq!(reply.addrs.len(), MAX_ADDRS);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_reply(&bytes, false, 1, "a.acme.test", Qtype::A);
        }

        #[test]
        fn a_flipped_byte_never_panics(at in 0_usize..60, bit in 0_u8..8) {
            let mut bytes = reply_bytes(5, "a.acme.test", Qtype::A, ResponseCode::NoError, vec![v4("192.0.2.1")]);
            let at = at % bytes.len();
            bytes[at] ^= 1 << bit;
            let _ = parse_reply(&bytes, false, 5, "a.acme.test", Qtype::A);
        }
    }
}
