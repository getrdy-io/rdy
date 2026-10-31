//! The fix text of `host.cgroups`. It follows the OS (03, "host.cgroups"): the RHEL family has
//! `grubby`, Debian and Ubuntu edit `/etc/default/grub`, Raspberry Pi OS edits `cmdline.txt`.
//!
//! Every command in here is on the fix-text allow-list, and a test runs the audit over each template.

use crate::os::release::Release;

/// How this machine's kernel command line is edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Boot {
    /// RHEL, CentOS, Fedora, Rocky, Alma, Oracle Linux, Amazon Linux: `grubby`.
    Grubby,
    /// Debian, Ubuntu and their derivatives: `/etc/default/grub`.
    Grub,
    /// Raspberry Pi OS: the single line in `cmdline.txt`.
    CmdlineTxt,
    /// Anything else.
    Other,
}

/// Whether to add words to the command line or take them off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Edit {
    Add,
    Remove,
}

const RHEL_LIKE: &[&str] = &[
    "rhel",
    "centos",
    "fedora",
    "rocky",
    "almalinux",
    "ol",
    "amzn",
];
const DEBIAN_LIKE: &[&str] = &["debian", "ubuntu"];

/// Picks the way to edit the command line from `os-release` and, when it is known, from the device
/// tree model (a Raspberry Pi running a plain Debian image says `debian` in `os-release`).
pub(super) fn boot_for(release: Option<&Release>, raspberry_pi: bool) -> Boot {
    let Some(release) = release else {
        return if raspberry_pi {
            Boot::CmdlineTxt
        } else {
            Boot::Other
        };
    };
    let has = |names: &[&str]| {
        names.contains(&release.id.as_str())
            || release
                .id_like
                .iter()
                .any(|like| names.contains(&like.as_str()))
    };
    if raspberry_pi || has(&["raspbian"]) {
        Boot::CmdlineTxt
    } else if has(RHEL_LIKE) {
        Boot::Grubby
    } else if has(DEBIAN_LIKE) {
        Boot::Grub
    } else {
        Boot::Other
    }
}

/// One sentence that edits the kernel command line. `args` is one or more words, all built from a
/// fixed set or checked against a narrow character set by the caller.
pub(super) fn edit_cmdline(boot: Boot, edit: Edit, args: &str) -> String {
    match (boot, edit) {
        (Boot::Grubby, Edit::Add) => {
            format!("Run `grubby --update-kernel=ALL --args=\"{args}\"` and reboot.")
        }
        (Boot::Grubby, Edit::Remove) => {
            format!("Run `grubby --update-kernel=ALL --remove-args=\"{args}\"` and reboot.")
        }
        (Boot::Grub, Edit::Add) => format!(
            "Add `{args}` to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `update-grub` and reboot."
        ),
        (Boot::Grub, Edit::Remove) => format!(
            "Remove `{args}` from `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `update-grub` and reboot."
        ),
        (Boot::CmdlineTxt, Edit::Add) => format!(
            "Add `{args}` to the single line in `/boot/firmware/cmdline.txt` (`/boot/cmdline.txt` before Debian 12) and reboot."
        ),
        (Boot::CmdlineTxt, Edit::Remove) => format!(
            "Remove `{args}` from the single line in `/boot/firmware/cmdline.txt` (`/boot/cmdline.txt` before Debian 12) and reboot."
        ),
        (Boot::Other, Edit::Add) => format!(
            "Add `{args}` to the kernel command line in your boot loader's configuration and reboot."
        ),
        (Boot::Other, Edit::Remove) => format!(
            "Remove `{args}` from the kernel command line in your boot loader's configuration and reboot."
        ),
    }
}

/// The fix for the wrong cgroup version. `v2` is the version the vendor wants.
pub(super) fn version_fix(boot: Boot, v2: bool) -> String {
    let arg = if v2 {
        "systemd.unified_cgroup_hierarchy=1"
    } else {
        "systemd.unified_cgroup_hierarchy=0"
    };
    let mut text = edit_cmdline(boot, Edit::Add, arg);
    if !v2 {
        text.push_str(
            " systemd 256 and later also needs `SYSTEMD_CGROUP_ENABLE_LEGACY_FORCE=1` on the command line.",
        );
    }
    text
}

/// A controller the kernel has turned off, and the `cgroup_disable=` word that did it when the
/// command line shows one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Disabled {
    pub controller: String,
    pub word: Option<String>,
}

/// The fix for controllers that are turned off in the kernel. A `cgroup_disable=` word is taken off.
/// Without one the OS default is off, so `cgroup_enable=` turns it on (and on Raspberry Pi OS the
/// memory controller needs `cgroup_memory=1` too).
pub(super) fn disabled_fix(boot: Boot, disabled: &[Disabled]) -> String {
    let mut words: Vec<&str> = Vec::new();
    for item in disabled {
        if let Some(word) = &item.word
            && !words.contains(&word.as_str())
        {
            words.push(word);
        }
    }
    let mut parts = Vec::new();
    if !words.is_empty() {
        parts.push(edit_cmdline(boot, Edit::Remove, &words.join(" ")));
    }
    let mut enable: Vec<String> = Vec::new();
    for item in disabled.iter().filter(|d| d.word.is_none()) {
        if item.controller == "memory" && boot == Boot::CmdlineTxt {
            enable.push("cgroup_memory=1".to_owned());
        }
        enable.push(format!("cgroup_enable={}", item.controller));
    }
    enable.dedup();
    if !enable.is_empty() {
        parts.push(edit_cmdline(boot, Edit::Add, &enable.join(" ")));
    }
    parts.join(" ")
}

/// The fix for controllers that are missing and that no boot option turns on. `names` are already
/// quoted.
pub(super) fn not_offered_fix(names: &[String]) -> String {
    format!(
        "Not available: {}. Use a kernel built with it, or, inside a container, ask the host admin to delegate it to this cgroup.",
        list(names)
    )
}

/// `a`, `a and b`, `a, b and c`.
pub(super) fn list(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}
