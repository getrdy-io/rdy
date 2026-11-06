//! Which process holds a socket: the lazy walk of `/proc/<pid>/fd`.
//!
//! The walk runs only for the sockets that conflict with a required port, so a free port costs nothing.
//! It lists the processes in id order and looks at the fd links of each until every wanted socket
//! inode is found, then stops. It does not read `cmdline` (the read policy refuses it, ADR 0036): the
//! name is `/proc/<pid>/comm`, which the kernel cuts to 15 bytes.
//!
//! A link that is not a socket is refused by the facade (ADR 0040), and every refusal is a `denied` entry
//! in the action log. The log folds all of them under one key per check, so a long walk costs 21 entries
//! and cannot fill the quota. The walk is bounded by the number of processes, the number of links and
//! the check's time, and says so when one of them stops it.
//!
//! Without root, another user's `/proc/<pid>/fd` cannot be listed, and trying would only leave denials in
//! the audit log of the machine. A socket whose owner is another user is not searched for at all, and
//! only the processes of rdy's own user are listed. When rdy's own uid cannot be read, no process is
//! listed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{CheckContext, CheckError};
use rdy_engine::probe::{ProbeError, RULE_FD_TARGET};

use super::{PROC, SELF_STATUS};
use crate::reads::{Read, read_text};
use crate::security_agents::{MAX_PIDS, comm_of};
use crate::text::soft;

/// The walk stops when less than this is left of the check's time.
const STOP_BEFORE: Duration = Duration::from_millis(250);
/// The most fd links read in one run. A host with more has more fds than any service needs to be found.
const MAX_LINKS: usize = 200_000;
/// The most fd links read in one process.
const MAX_FDS: usize = 8192;
/// The longest unit name shown.
const MAX_UNIT: usize = 128;

/// The process that holds a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Owner {
    pub pid: u64,
    /// The name from `comm`, cut to 15 bytes by the kernel. `None` when it could not be read.
    pub name: Option<String>,
    /// The systemd service the process runs in, from `/proc/<pid>/cgroup`.
    pub unit: Option<String>,
}

/// Why a socket has no owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gap {
    /// The socket belongs to another user and rdy is not root.
    OtherUser,
    /// Some process directories could not be listed.
    Unreadable,
    /// The walk stopped early: time, the refusal limit or the process limit.
    Cut,
    /// Every process rdy could see was searched and none holds it.
    NotFound,
}

/// What the walk found.
#[derive(Debug, Default)]
pub(crate) struct Found {
    /// The owner of each socket inode that was found.
    pub owners: BTreeMap<u64, Owner>,
    /// Why each other inode has none.
    pub gaps: BTreeMap<u64, Gap>,
    /// Processes whose fd directory was listed.
    pub walked: usize,
}

/// Looks for the owners of `wanted`, a map from socket inode to the uid that owns the socket.
pub(crate) async fn find(
    ctx: &CheckContext,
    root: bool,
    wanted: &BTreeMap<u64, u32>,
) -> Result<Found, CheckError> {
    let mut found = Found::default();
    let mut left: BTreeSet<u64> = BTreeSet::new();
    let me = if root { None } else { own_uid(ctx).await? };
    if !root && me.is_none() {
        // Not root and not sure whose processes may be listed: list none.
        for inode in wanted.keys() {
            found.gaps.insert(*inode, Gap::Unreadable);
        }
        return Ok(found);
    }
    for (inode, uid) in wanted {
        match me {
            Some(me) if me != *uid => {
                found.gaps.insert(*inode, Gap::OtherUser);
            }
            _ => {
                left.insert(*inode);
            }
        }
    }
    if left.is_empty() {
        return Ok(found);
    }

    let probe = ctx.probe();
    let pids = match probe.read_dir(Path::new(PROC)).await {
        Ok(entries) => {
            let mut pids: Vec<u64> = entries
                .into_iter()
                .filter(|entry| entry.is_dir && entry.name.bytes().all(|b| b.is_ascii_digit()))
                .filter_map(|entry| entry.name.parse().ok())
                .collect();
            pids.sort_unstable();
            pids
        }
        Err(error) => {
            soft(error)?;
            for inode in left {
                found.gaps.insert(inode, Gap::Unreadable);
            }
            return Ok(found);
        }
    };

    let mut cut = pids.len() > MAX_PIDS;
    let mut unreadable = 0usize;
    let mut links = 0usize;
    let mut hits: Vec<(u64, u64)> = Vec::new();
    'pids: for pid in pids.into_iter().take(MAX_PIDS) {
        if ctx.remaining() < STOP_BEFORE || links >= MAX_LINKS {
            cut = true;
            break;
        }
        // Without root only the processes of rdy's own user can be listed. Asking for another user's
        // directory is refused by the kernel and noted in the machine's audit log.
        if let Some(me) = me {
            match read_text(ctx, &format!("{PROC}/{pid}/status")).await? {
                Read::Text(text) if owned_by(&text, me) => {}
                Read::Text(_) | Read::Absent => continue,
                Read::Unreadable(_) => {
                    unreadable += 1;
                    continue;
                }
            }
        }
        let dir = format!("{PROC}/{pid}/fd");
        let entries = match probe.read_dir(Path::new(&dir)).await {
            Ok(entries) => entries,
            Err(error) => {
                // A process that ended since the listing is not a gap.
                if soft(error)? != ProbeError::NotFound {
                    unreadable += 1;
                }
                continue;
            }
        };
        found.walked += 1;
        let mut fds: Vec<u64> = entries
            .iter()
            .filter_map(|entry| entry.name.parse().ok())
            .collect();
        fds.sort_unstable();
        fds.truncate(MAX_FDS);
        for fd in fds {
            // The caps are checked for every link, not once per process.
            if ctx.remaining() < STOP_BEFORE || links >= MAX_LINKS {
                cut = true;
                break 'pids;
            }
            links += 1;
            match probe.read_link(Path::new(&format!("{dir}/{fd}"))).await {
                Ok(link) => {
                    if let Some(inode) = socket_inode(&link.bytes)
                        && left.remove(&inode)
                    {
                        hits.push((inode, pid));
                        if left.is_empty() {
                            break 'pids;
                        }
                    }
                }
                Err(error) if is_fd_refusal(&error) => {}
                Err(error) => match soft(error)? {
                    // The fd was closed since the listing.
                    ProbeError::NotFound => {}
                    _ => {
                        unreadable += 1;
                        continue 'pids;
                    }
                },
            }
        }
    }

    for (inode, pid) in hits {
        found.owners.insert(inode, owner_of(ctx, pid).await?);
    }
    let gap = if cut {
        Gap::Cut
    } else if unreadable > 0 {
        Gap::Unreadable
    } else {
        Gap::NotFound
    };
    for inode in left {
        found.gaps.insert(inode, gap);
    }
    Ok(found)
}

/// The effective uid of rdy, from `/proc/self/status`. `None` when it cannot be read.
async fn own_uid(ctx: &CheckContext) -> Result<Option<u32>, CheckError> {
    Ok(match read_text(ctx, SELF_STATUS).await? {
        Read::Text(text) => effective_uid(&text),
        Read::Absent | Read::Unreadable(_) => None,
    })
}

/// The numbers of the `Uid:` line: real, effective, saved, file system.
fn uids(status: &str) -> Option<[u32; 4]> {
    let line = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let mut numbers = line.split_whitespace().map(|n| n.parse::<u32>().ok());
    Some([
        numbers.next()??,
        numbers.next()??,
        numbers.next()??,
        numbers.next()??,
    ])
}

/// The effective uid, the second number of the `Uid:` line.
pub(crate) fn effective_uid(status: &str) -> Option<u32> {
    uids(status).map(|ids| ids[1])
}

/// Whether the process with this status text runs entirely as `me`: real, effective and saved uid. Those
/// are the ids the kernel compares before it lets a user list a process's fd directory.
pub(crate) fn owned_by(status: &str, me: u32) -> bool {
    uids(status).is_some_and(|ids| ids[..3].iter().all(|id| *id == me))
}

/// Whether the facade refused the link because its target is not a socket.
fn is_fd_refusal(error: &ProbeError) -> bool {
    matches!(error, ProbeError::Denied { rule, .. } if *rule == RULE_FD_TARGET)
}

/// The inode in `socket:[8841]`.
pub(crate) fn socket_inode(target: &[u8]) -> Option<u64> {
    let digits = target.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    if digits.is_empty() || digits.len() > 20 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// The name and the unit of a process. A file that cannot be read leaves the field empty: the process
/// may have ended since the walk found it.
async fn owner_of(ctx: &CheckContext, pid: u64) -> Result<Owner, CheckError> {
    let name = match ctx
        .probe()
        .read(Path::new(&format!("{PROC}/{pid}/comm")))
        .await
    {
        Ok(file) => comm_of(&file.bytes),
        Err(error) => {
            soft(error)?;
            None
        }
    };
    let unit = match read_text(ctx, &format!("{PROC}/{pid}/cgroup")).await? {
        Read::Text(text) => unit_of(&text),
        Read::Absent | Read::Unreadable(_) => None,
    };
    Ok(Owner { pid, name, unit })
}

/// The systemd service in the text of `/proc/<pid>/cgroup`, when the process runs directly under one.
///
/// Version 2 has one line, `0::/system.slice/kubelet.service`. Version 1 has the systemd hierarchy on a
/// `name=systemd` line. The unit is the first component that is not a slice, and only when every
/// component before it is a slice. Anything below that point is a subtree the service handed to
/// someone else (a container, an nspawn machine, a user session), and a `.service` name found there
/// belongs to another system. A user service (`user@1000.service`) is left out, because `systemctl stop`
/// needs `--user` for it. A name must start with a letter or a digit, so it can never read as an option,
/// and must be plain text, so it needs no quoting.
pub(crate) fn unit_of(cgroup: &str) -> Option<String> {
    let line = cgroup
        .lines()
        .find(|line| line.starts_with("0::"))
        .or_else(|| cgroup.lines().find(|line| line.contains(":name=systemd:")))?;
    let path = line.splitn(3, ':').nth(2)?;
    let unit = path
        .split('/')
        .filter(|part| !part.is_empty())
        .find(|part| !part.ends_with(".slice"))?;
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':');
    let starts = unit
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    (unit.ends_with(".service")
        && !unit.starts_with("user@")
        && starts
        && unit.len() <= MAX_UNIT
        && unit.chars().all(plain))
    .then(|| unit.to_owned())
}
