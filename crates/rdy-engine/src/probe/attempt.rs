//! What one connection attempt did, as a type (M1-091, M1-093).
//!
//! It sits outside the `net` module because [`NetFailure::NotConnected`](super::NetFailure) names it and
//! `NetFailure` is built in every configuration of the crate. `probe::net` re-exports it, where the
//! network facade documents it.

#[cfg(any(feature = "runtime", feature = "loopback"))]
use std::io;

/// What one connection attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttemptOutcome {
    /// The connection opened.
    Connected,
    /// The host answered with a refusal (a closed port, or a firewall that rejects).
    Refused,
    /// The connection was reset.
    Reset,
    /// No answer within `ATTEMPT_TIMEOUT`: a firewall that drops packets looks like this.
    TimedOut,
    /// No route to the network or the host.
    Unreachable,
    /// Another failure.
    Failed,
    /// Another address connected first, so this attempt was cut while it was still running.
    Abandoned,
}

impl AttemptOutcome {
    #[cfg(any(feature = "runtime", feature = "loopback"))]
    pub(super) fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => Self::Reset,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown => Self::Unreachable,
            _ => Self::Failed,
        }
    }

    /// A fixed phrase for the log and for the `reason` of a [`NetFailure::NotConnected`](super::NetFailure::NotConnected). A check does
    /// not compare phrases: it reads the typed `outcome` of [`NetFailure::NotConnected`](super::NetFailure::NotConnected).
    #[must_use]
    pub fn phrase(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Refused => "connection refused",
            Self::Reset => "connection reset",
            Self::TimedOut => "no answer in time",
            Self::Unreachable => "network or host unreachable",
            Self::Failed => "connection failed",
            Self::Abandoned => "cut because another address connected",
        }
    }
}
