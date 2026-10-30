//! What the kubeconfig user offers the server, and when it stops working (03 `k8s.access`).
//!
//! The facts are read at load time, from the kubeconfig and the files it names, with no request. They are
//! the kinds of credential and, where rdy can know it without asking anyone, the time left:
//!
//! - a static token that is a JWT: the `exp` claim. Nothing else of the token is read, and the token
//!   itself is never kept in a fact;
//! - a client certificate: the `notAfter` date, read with a small DER walk (a check crate may not depend
//!   on an X.509 crate, and this is one field);
//! - an exec credential plugin: no expiry. The plugin hands out short-lived tokens and refreshes them, so
//!   there is nothing to warn about, and the evidence says which binary does it;
//! - the pod's service account (in-cluster): no expiry. The kubelet rotates the token.
//!
//! Times are whole seconds from "now" at load: negative means already expired. "Now" comes from
//! [`Env::now_unix`](super::Env), so tests pin it.

use std::fmt;

use super::b64;

/// The longest token rdy looks into for an `exp` claim. A real JWT is under 8 KiB.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// The longest certificate text rdy parses.
const MAX_CERT_BYTES: usize = 64 * 1024;

/// One thing the kubeconfig user sends to the server.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Credential {
    /// A bearer token, inline or from a token file.
    Token {
        /// Seconds until the `exp` claim, when the token is a JWT that has one. Negative: expired.
        expires_in: Option<i64>,
    },
    /// A client certificate and key.
    ClientCertificate {
        /// Seconds until the certificate's `notAfter`, when it could be read. Negative: expired.
        expires_in: Option<i64>,
    },
    /// A user name and password.
    Password,
    /// An exec credential plugin. The text is its file name, escaped.
    Plugin {
        /// The plugin's file name, never its arguments.
        binary: String,
    },
    /// The pod's service account token.
    ServiceAccount,
}

impl Credential {
    /// Seconds left, for a credential that has a known end.
    #[must_use]
    pub fn expires_in(&self) -> Option<i64> {
        match self {
            Self::Token { expires_in } | Self::ClientCertificate { expires_in } => *expires_in,
            Self::Password | Self::Plugin { .. } | Self::ServiceAccount => None,
        }
    }
}

impl fmt::Debug for Credential {
    // The fields are numbers and a file name, so the derived text would be safe. It is written by hand
    // so a future field cannot start printing a secret by accident.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token { expires_in } => write!(f, "Token(expires_in: {expires_in:?})"),
            Self::ClientCertificate { expires_in } => {
                write!(f, "ClientCertificate(expires_in: {expires_in:?})")
            }
            Self::Password => f.write_str("Password"),
            Self::Plugin { binary } => write!(f, "Plugin({binary})"),
            Self::ServiceAccount => f.write_str("ServiceAccount"),
        }
    }
}

/// Seconds until the `exp` claim of `token`, if it is a JWT with one. `now` is Unix seconds.
///
/// A token that is not three dot-separated parts, whose payload is not base64url JSON, or that has no
/// numeric `exp`, has no known end: `None`.
pub(crate) fn token_expires_in(token: &str, now: i64) -> Option<i64> {
    let token = token.trim();
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || payload.is_empty() {
        return None;
    }
    // base64url without padding. The decoder takes the standard alphabet, so the two letters are swapped.
    let standard: String = payload
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let bytes = b64::decode(&standard)?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp")?;
    let exp = exp
        .as_i64()
        // A float `exp` is allowed by RFC 7519 ("NumericDate"). Whole seconds are enough.
        .or_else(|| exp.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))?;
    exp.checked_sub(now)
}

/// Seconds until the first certificate of `pem` expires. `now` is Unix seconds.
///
/// `None` when the text holds no certificate, the DER is not the shape of an X.509 certificate, or the
/// date is not one of the two ASN.1 time forms.
pub(crate) fn certificate_expires_in(pem: &str, now: i64) -> Option<i64> {
    if pem.len() > MAX_CERT_BYTES {
        return None;
    }
    let der = first_certificate(pem)?;
    not_after(&der)?.checked_sub(now)
}

/// The DER bytes of the first `CERTIFICATE` block of a PEM text.
fn first_certificate(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let end = start + pem.get(start..)?.find(END)?;
    b64::decode(pem.get(start..end)?)
}

/// One DER element: its tag, its content, and what follows it.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
}

/// Reads one DER element. Only definite lengths of up to three bytes are accepted: a certificate is far
/// under 16 MiB, and BER's indefinite form does not occur in DER.
fn read(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    // A multi-byte tag number (low five bits all set) does not occur in a certificate's header fields.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, after_len) = after_tag.split_first()?;
    let (len, body) = if first < 0x80 {
        (usize::from(first), after_len)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 || after_len.len() < count {
            return None;
        }
        let len = after_len[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &after_len[count..])
    };
    if body.len() < len {
        return None;
    }
    Some(Tlv {
        tag,
        content: &body[..len],
        rest: &body[len..],
    })
}

/// `notAfter` of a DER certificate as Unix seconds.
///
/// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
/// issuer, validity SEQUENCE { notBefore, notAfter }, ... }, ... }
fn not_after(der: &[u8]) -> Option<i64> {
    let certificate = read(der)?;
    if certificate.tag != 0x30 {
        return None;
    }
    let tbs = read(certificate.content)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut cursor = tbs.content;
    let mut element = read(cursor)?;
    if element.tag == 0xa0 {
        // The explicit version.
        cursor = element.rest;
        element = read(cursor)?;
    }
    // `element` is the serial number. Then the signature algorithm, the issuer and the validity.
    if element.tag != 0x02 {
        return None;
    }
    let signature = read(element.rest)?;
    let issuer = read(signature.rest)?;
    let validity = read(issuer.rest)?;
    if validity.tag != 0x30 {
        return None;
    }
    let not_before = read(validity.content)?;
    let not_after = read(not_before.rest)?;
    asn1_time(not_after.tag, not_after.content)
}

/// An ASN.1 `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) as Unix seconds. Only
/// the `Z` form with seconds is accepted, which is what DER requires.
fn asn1_time(tag: u8, content: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(content).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number =
        |from: usize, len: usize| -> Option<i64> { digits.get(from..from + len)?.parse().ok() };
    let (year, rest) = match tag {
        0x17 if digits.len() == 12 => {
            let yy = number(0, 2)?;
            // RFC 5280: 50 to 99 mean 1950 to 1999, 00 to 49 mean 2000 to 2049.
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        0x18 if digits.len() == 14 => (number(0, 4)?, 4),
        _ => return None,
    };
    let month = number(rest, 2)?;
    let day = number(rest + 2, 2)?;
    let hour = number(rest + 4, 2)?;
    let minute = number(rest + 6, 2)?;
    let second = number(rest + 8, 2)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests;
