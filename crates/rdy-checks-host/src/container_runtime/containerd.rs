//! `/etc/containerd/config.toml`: the config version, the default runtime's `SystemdCgroup` and the
//! snapshotter.
//!
//! The same setting lives in a different table for each config version:
//!
//! | `version` | table that holds the CRI runtime settings |
//! | --- | --- |
//! | 1 (no `version` line) | `plugins.cri` (the long name of version 2 is read too) |
//! | 2 | `plugins."io.containerd.grpc.v1.cri"` |
//! | 3 | `plugins."io.containerd.cri.v1.runtime"` (the snapshotter is in `...cri.v1.images`) |
//!
//! A setting written under the table of the wrong version is ignored by containerd. That is a common
//! cause of "I set SystemdCgroup and nothing changed", so the parser reports it.

use rdy_spec::check::CgroupDriver;
use toml::Value;

use super::clip;

pub(super) const TABLE_V2: &str = "io.containerd.grpc.v1.cri";
pub(super) const TABLE_V3_RUNTIME: &str = "io.containerd.cri.v1.runtime";
const TABLE_V3_IMAGES: &str = "io.containerd.cri.v1.images";
const TABLE_V1: &str = "cri";

/// What the file (or the built-in default) says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Config {
    /// The `version` of the file; 1 when the line is missing.
    pub version: i64,
    /// `false` for the built-in default used when there is no file.
    pub from_file: bool,
    /// The default runtime's name, `runc` unless the file says otherwise.
    pub runtime_name: String,
    /// The cgroup driver, or `None` when the file does not settle it.
    pub cgroup: Option<CgroupDriver>,
    /// Why `cgroup` is `None`, or a warning about the file.
    pub notes: Vec<String>,
    /// The table of another config version that holds `SystemdCgroup`, which this version ignores.
    pub misplaced: Option<&'static str>,
    pub snapshotter: Option<String>,
}

/// The CRI table name for a config version, as it is written in `[plugins."..."]`.
pub(super) fn table_name(version: i64) -> &'static str {
    match version {
        3.. => TABLE_V3_RUNTIME,
        2 => TABLE_V2,
        _ => TABLE_V1,
    }
}

/// The config that containerd runs with when there is no file: the default runtime `runc` with
/// `SystemdCgroup` off, and the `overlayfs` snapshotter. `major` is the containerd major version, if
/// known: 2 and later write a version 3 file, earlier ones version 2.
pub(super) fn built_in(major: Option<u32>) -> Config {
    Config {
        version: if major.is_some_and(|m| m >= 2) { 3 } else { 2 },
        from_file: false,
        runtime_name: "runc".to_owned(),
        cgroup: Some(CgroupDriver::Cgroupfs),
        notes: Vec::new(),
        misplaced: None,
        snapshotter: Some("overlayfs".to_owned()),
    }
}

fn dig<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(root, |value, key| value.get(*key))
}

/// The table that holds the CRI runtime settings (`...containerd`) for `version`.
fn runtime_table(root: &Value, version: i64) -> Option<&Value> {
    let get = |name: &str| dig(root, &["plugins", name, "containerd"]);
    match version {
        3.. => get(TABLE_V3_RUNTIME),
        2 => get(TABLE_V2),
        _ => get(TABLE_V1).or_else(|| get(TABLE_V2)),
    }
}

fn runtime_name(table: Option<&Value>) -> String {
    table
        .and_then(|t| t.get("default_runtime_name"))
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty() && n.len() <= 64)
        .map_or_else(|| "runc".to_owned(), str::to_owned)
}

fn systemd_cgroup(table: Option<&Value>, name: &str) -> Option<bool> {
    table?
        .get("runtimes")?
        .get(name)?
        .get("options")?
        .get("SystemdCgroup")?
        .as_bool()
}

/// Reads a `config.toml`.
///
/// # Errors
///
/// A short reason when the text is not TOML.
pub(super) fn parse(text: &str) -> Result<Config, String> {
    let root: Value = toml::from_str(text).map_err(|e| {
        let first = e.message().lines().next().unwrap_or("it is not valid TOML");
        format!("it is not valid TOML ({})", clip(first))
    })?;
    let version = root.get("version").and_then(Value::as_integer).unwrap_or(1);
    let table = runtime_table(&root, version);
    let name = runtime_name(table);
    let mut notes = Vec::new();

    let imports = root
        .get("imports")
        .and_then(Value::as_array)
        .is_some_and(|list| !list.is_empty());
    let runtime = table
        .and_then(|t| t.get("runtimes"))
        .and_then(|r| r.get(&name));
    let runtime_type = runtime
        .and_then(|r| r.get("runtime_type"))
        .and_then(Value::as_str);

    let set = systemd_cgroup(table, &name);
    let cgroup = match set {
        Some(true) => Some(CgroupDriver::Systemd),
        Some(false) => Some(CgroupDriver::Cgroupfs),
        None if imports => {
            notes.push(
                "the file imports other files, which rdy does not read, so SystemdCgroup may be set there"
                    .to_owned(),
            );
            None
        }
        None if runtime_type.is_some_and(|t| !t.starts_with("io.containerd.runc.")) => {
            notes.push(format!(
                "the default runtime {} is not runc, and rdy reads SystemdCgroup only for runc",
                clip(&name)
            ));
            None
        }
        None if runtime.is_none() && name != "runc" => {
            notes.push(format!(
                "the default runtime {} is not defined in the file",
                clip(&name)
            ));
            None
        }
        // Not set: containerd's default is off.
        None => Some(CgroupDriver::Cgroupfs),
    };

    // A value under another version's table is ignored by this version. A version 1 file reads the
    // version 2 table too, so only the version 3 table can be misplaced there.
    let others: &[&'static str] = if version >= 3 {
        &[TABLE_V2]
    } else {
        &[TABLE_V3_RUNTIME]
    };
    let misplaced = others.iter().filter(|_| set.is_none()).find_map(|name| {
        let other = dig(&root, &["plugins", name, "containerd"]);
        systemd_cgroup(other, &runtime_name(other)).map(|_| *name)
    });
    if let Some(other) = misplaced {
        notes.push(format!(
            "SystemdCgroup is set under plugins.\"{other}\", which a version {version} file does not read"
        ));
    }

    let snapshotter = if version >= 3 {
        dig(&root, &["plugins", TABLE_V3_IMAGES, "snapshotter"])
    } else {
        table.and_then(|t| t.get("snapshotter"))
    }
    .and_then(Value::as_str)
    .filter(|s| !s.is_empty())
    .map(clip)
    // containerd's default snapshotter on Linux.
    .or_else(|| (!imports).then(|| "overlayfs".to_owned()));

    Ok(Config {
        version,
        from_file: true,
        runtime_name: name,
        cgroup,
        notes,
        misplaced,
        snapshotter,
    })
}
