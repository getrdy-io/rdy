//! The kernel's socket tables: `/proc/net/tcp`, `tcp6`, `udp` and `udp6`.
//!
//! One row per socket:
//!
//! ```text
//!   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//!    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 8841 1
//! ```
//!
//! An address is hex, one 32-bit word at a time in the byte order of the machine, so `0100007F` is
//! 127.0.0.1 on a little-endian machine. Every release target of rdy is little-endian. The parser never
//! panics on odd text: a row it cannot read is counted and left out.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The state of a listening TCP socket.
pub(crate) const LISTEN: u8 = 0x0A;

/// The most rows read from one table. A 1 MiB table holds about 7,000.
const MAX_ROWS: usize = 50_000;

/// What kind of address a socket is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// `0.0.0.0` or `::`: every address.
    Unspecified,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// Any other address.
    Other,
}

/// One socket from a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Socket {
    /// The local address.
    pub addr: IpAddr,
    /// The table it came from was an IPv6 table (`tcp6`, `udp6`).
    pub v6_table: bool,
    pub port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

impl Socket {
    /// The kind of address. An IPv4-mapped IPv6 address counts as the IPv4 address it wraps.
    pub(crate) fn scope(&self) -> Scope {
        let addr = match self.addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        if addr.is_unspecified() {
            Scope::Unspecified
        } else if addr.is_loopback() {
            Scope::Loopback
        } else {
            Scope::Other
        }
    }

    /// The address as people write it with a port: `127.0.0.1` or `[::1]`.
    pub(crate) fn shown(&self) -> String {
        match self.addr {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        }
    }
}

/// The rows of one table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Table {
    pub sockets: Vec<Socket>,
    /// Lines that looked like rows and could not be read.
    pub skipped: usize,
    /// The state of the last row read.
    pub last_state: Option<u8>,
}

/// Parses the text of a table. `cut` says the file was read only up to a size limit, so its last line
/// may be partial and is dropped.
pub(crate) fn parse(text: &str, v6_table: bool, cut: bool) -> Table {
    let mut lines: Vec<&str> = text.lines().collect();
    if cut && !text.ends_with('\n') {
        lines.pop();
    }
    let mut table = Table::default();
    // The first line is the header.
    for line in lines.into_iter().skip(1) {
        if table.sockets.len() >= MAX_ROWS {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        match row(line, v6_table) {
            Some(socket) => {
                table.last_state = Some(socket.state);
                table.sockets.push(socket);
            }
            None => table.skipped += 1,
        }
    }
    table
}

fn row(line: &str, v6_table: bool) -> Option<Socket> {
    let mut fields = line.split_whitespace();
    let _index = fields.next()?;
    let (addr, port) = address(fields.next()?, v6_table)?;
    let _remote = fields.next()?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    // Skip tx_queue:rx_queue, tr:tm->when and retrnsmt.
    let uid = fields.nth(3)?.parse::<u32>().ok()?;
    let _timeout = fields.next()?;
    let inode = fields.next()?.parse::<u64>().ok()?;
    Some(Socket {
        addr,
        v6_table,
        port,
        state,
        uid,
        inode,
    })
}

/// `0100007F:1F90` or `00000000000000000000000001000000:1F90`.
fn address(text: &str, v6_table: bool) -> Option<(IpAddr, u16)> {
    let (hex, port) = text.split_once(':')?;
    if port.len() != 4 {
        return None;
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let addr = match (hex.len(), v6_table) {
        (8, false) => IpAddr::V4(Ipv4Addr::from(word(hex)?)),
        (32, true) => {
            let mut bits: u128 = 0;
            for i in 0..4 {
                bits = (bits << 32) | u128::from(word(hex.get(i * 8..i * 8 + 8)?)?);
            }
            IpAddr::V6(Ipv6Addr::from(bits))
        }
        _ => return None,
    };
    Some((addr, port))
}

/// One 8-digit word, turned from the machine's byte order into network order.
fn word(hex: &str) -> Option<u32> {
    u32::from_str_radix(hex, 16).ok().map(u32::swap_bytes)
}
