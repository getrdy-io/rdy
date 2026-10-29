//! Port numbers and ranges as the firewall tools write them.

/// An inclusive range of TCP or UDP ports. One port is a range of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PortRange {
    lo: u16,
    hi: u16,
}

impl PortRange {
    /// Reads `6443`, or `30000-32767` (firewalld) or `6000:6010` (ufw) with `sep` as the range
    /// separator. Port 0, a reversed range and anything else is `None`.
    pub(super) fn parse(text: &str, sep: char) -> Option<Self> {
        let text = text.trim();
        let (lo, hi) = match text.split_once(sep) {
            Some((lo, hi)) => (
                lo.trim().parse::<u16>().ok()?,
                hi.trim().parse::<u16>().ok()?,
            ),
            None => {
                let one = text.parse::<u16>().ok()?;
                (one, one)
            }
        };
        (lo >= 1 && lo <= hi).then_some(Self { lo, hi })
    }

    /// Every port.
    pub(super) fn all() -> Self {
        Self {
            lo: 1,
            hi: u16::MAX,
        }
    }

    /// Whether `port` is in the range.
    pub(super) fn covers(self, port: u16) -> bool {
        (self.lo..=self.hi).contains(&port)
    }
}
