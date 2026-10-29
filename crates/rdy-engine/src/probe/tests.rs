//! Tests for the probe facade: the read denylist, the command seam, the action log and the per-check
//! handle.
//!
//! The fixture run at the bottom is the exit test of M1-040.

// `Probe::kube_call` is on the lint wall for check crates. The engine tests exercise it directly.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::sync::Arc;
#[cfg(feature = "runtime")]
use std::time::Duration;

use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::{Value, json};

use super::replay::Replay;
use super::sealed::Sealed;
use super::*;
use crate::check::{BoxFuture, CheckContext, CheckError, Os};
use crate::redact::TagKey;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([3; 32]))
}

fn hub(replay: Replay) -> ProbeHub {
    ProbeHub::new(Arc::new(replay), redactor())
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

/// A table command for `getent ahosts -- <name>`, built the way a check builds it.
#[cfg(feature = "runtime")]
fn getent(name: &str) -> Cmd {
    table::entry("getent")
        .expect("getent is in the table")
        .cmd_for(Os::Linux, "ahosts", &[name])
        .expect("a valid name")
}

/// The argv of `getent ahosts -- <name>`, as the fixture keys it.
#[cfg(feature = "runtime")]
fn getent_args(name: &str) -> [&str; 3] {
    ["ahosts", "--", name]
}

#[test]
fn probe_errors_are_clone_eq_like_check_errors() {
    fn needs<T: Clone + PartialEq + Eq>() {}
    needs::<ProbeError>();
    needs::<CheckError>();
    let error = CheckError::from(ProbeError::NotFound);
    assert_eq!(error, error.clone());
    assert_eq!(error.skip_kind(), None);
}

#[test]
fn every_probe_error_tells_the_user_what_to_do() {
    use crate::exec::policy::PolicyError;
    let errors = [
        ProbeError::denied("some rule", "~/x"),
        ProbeError::Policy(PolicyError::Refused { program: "sh" }),
        ProbeError::Table(TableError::UnknownProgram { program: "sh" }),
        ProbeError::NotFound,
        ProbeError::PermissionDenied,
        ProbeError::Timeout,
        ProbeError::Hung { pid: 7 },
        ProbeError::Io("broken pipe".to_owned()),
    ];
    for error in errors {
        assert!(error.to_string().contains("Fix:"), "{error}");
    }
}

#[test]
fn a_declared_program_matches_the_way_the_table_does() {
    // A Windows entry ignores case, as the table's lookup does. A Unix name must match exactly.
    assert!(same_program("NETSTAT.EXE", "netstat.exe"));
    assert!(same_program("getent", "getent"));
    assert!(!same_program("getent", "GETENT"));
    assert!(!same_program("getent", "chronyc"));
}

// ---- the read denylist -------------------------------------------------------------------------

mod denylist {
    use super::*;
    use crate::probe::policy::{
        RULE_CREDENTIALS, RULE_DEVICE, RULE_DOT_DOT, RULE_KERNEL, RULE_KUBECONFIG,
        RULE_MACHINE_ID_FILE, RULE_PRIVATE_KEY, RULE_PROC, RULE_RELATIVE, RULE_SSH,
        RULE_SYSTEM_SECRET, check_names,
    };

    fn verdict(path: &str) -> Result<(), &'static str> {
        check_names(Path::new(path), false)
    }

    #[test]
    fn the_listed_files_are_refused_with_their_rule() {
        let cases = [
            // Password and sudo files, at the root.
            ("/etc/shadow", RULE_SYSTEM_SECRET),
            ("/etc/shadow-", RULE_SYSTEM_SECRET),
            ("/etc/gshadow", RULE_SYSTEM_SECRET),
            ("/etc/sudoers", RULE_SYSTEM_SECRET),
            ("/etc/sudoers.d/90-cloud-init", RULE_SYSTEM_SECRET),
            ("/etc/security/opasswd", RULE_SYSTEM_SECRET),
            ("/etc/master.passwd", RULE_SYSTEM_SECRET),
            (
                "/var/db/dslocal/nodes/Default/users/root.plist",
                RULE_SYSTEM_SECRET,
            ),
            // The machine id: stable per host, so only the engine's salted `host_id` may leave it.
            ("/etc/machine-id", RULE_MACHINE_ID_FILE),
            ("/var/lib/dbus/machine-id", RULE_MACHINE_ID_FILE),
            ("/etc/machine-id.bak", RULE_MACHINE_ID_FILE),
            ("/host/etc/machine-id", RULE_MACHINE_ID_FILE),
            ("/host/var/lib/dbus/machine-id", RULE_MACHINE_ID_FILE),
            (
                "/var/lib/docker/overlay2/ab12/diff/etc/machine-id",
                RULE_MACHINE_ID_FILE,
            ),
            // The same files under a mount, a container layer and a data volume.
            ("/host/etc/shadow", RULE_SYSTEM_SECRET),
            (
                "/var/lib/docker/overlay2/ab12/diff/etc/shadow",
                RULE_SYSTEM_SECRET,
            ),
            (
                "/System/Volumes/Data/private/etc/sudoers",
                RULE_SYSTEM_SECRET,
            ),
            ("/host/etc/ssl/private/site.pem", RULE_PRIVATE_KEY),
            ("/host/etc/pki/tls/private/site.pem", RULE_PRIVATE_KEY),
            // ssh and kube directories.
            ("/home/ada/.ssh/id_ed25519", RULE_SSH),
            ("/home/ada/.ssh", RULE_SSH),
            ("/root/.kube/config", RULE_KUBECONFIG),
            ("/home/ada/.kube/cache/discovery/x.json", RULE_KUBECONFIG),
            // Credential files.
            ("/home/ada/.aws/credentials", RULE_CREDENTIALS),
            ("/home/ada/.azure/accessTokens.json", RULE_CREDENTIALS),
            ("/home/ada/.config/gcloud/credentials.db", RULE_CREDENTIALS),
            ("/home/ada/.gnupg/private-keys-v1.d/x", RULE_CREDENTIALS),
            ("/home/ada/.docker/config.json", RULE_CREDENTIALS),
            ("/home/ada/.netrc", RULE_CREDENTIALS),
            ("/home/ada/.git-credentials", RULE_CREDENTIALS),
            ("/home/ada/.pgpass", RULE_CREDENTIALS),
            ("/home/ada/.vault-token", RULE_CREDENTIALS),
            ("/etc/krb5.keytab", RULE_PRIVATE_KEY),
            (
                "/Users/ada/Library/Keychains/login.keychain-db",
                RULE_PRIVATE_KEY,
            ),
            (
                "/Users/ada/Library/Keychains/old.keychain",
                RULE_PRIVATE_KEY,
            ),
            // Cluster credentials.
            ("/etc/kubernetes/admin.conf", RULE_KUBECONFIG),
            ("/etc/kubernetes/kubelet.conf", RULE_KUBECONFIG),
            ("/etc/rancher/k3s/k3s.yaml", RULE_KUBECONFIG),
            ("/etc/rancher/rke2/rke2.yaml", RULE_KUBECONFIG),
            ("/var/lib/kubelet/kubeconfig", RULE_KUBECONFIG),
            ("/var/lib/etcd/member/snap/db", RULE_KUBECONFIG),
            ("/var/lib/rancher/k3s/server/token", RULE_KUBECONFIG),
            ("/var/lib/rancher/rke2/server/cred/passwd", RULE_KUBECONFIG),
            (
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                RULE_KUBECONFIG,
            ),
            // Process entries off the allowlist, including the links that reach other files.
            ("/proc/1/environ", RULE_PROC),
            ("/proc/self/environ", RULE_PROC),
            ("/proc/1/cmdline", RULE_PROC),
            ("/proc/1/mem", RULE_PROC),
            ("/proc/1/fd", RULE_PROC),
            ("/proc/1/fd/3", RULE_PROC),
            ("/proc/1/root/etc/passwd", RULE_PROC),
            ("/proc/1/cwd", RULE_PROC),
            ("/proc/1/cwd/etc/shadow", RULE_PROC),
            ("/proc/self/exe", RULE_PROC),
            // auxv is for `self` only: another process's auxv shows its load addresses.
            ("/proc/1/auxv", RULE_PROC),
            ("/proc/1234/auxv", RULE_PROC),
            ("/proc/self/task/1/auxv", RULE_PROC),
            ("/proc/thread-self/auxv", RULE_PROC),
            ("/proc/1/map_files/7f00-7f01", RULE_PROC),
            ("/proc/1/maps", RULE_PROC),
            ("/proc/1/ns/mnt", RULE_PROC),
            ("/proc/1/task/1/environ", RULE_PROC),
            ("/host/proc/1/environ", RULE_PROC),
            // Kernel files.
            ("/proc/kcore", RULE_KERNEL),
            ("/proc/kmsg", RULE_KERNEL),
            ("/proc/vmcore", RULE_KERNEL),
            ("/proc/kpagecount", RULE_KERNEL),
            ("/proc/kpageflags", RULE_KERNEL),
            ("/proc/kallsyms", RULE_KERNEL),
            ("/sys/kernel/debug", RULE_KERNEL),
            ("/sys/kernel/debug/tracing/trace", RULE_KERNEL),
            ("/sys/kernel/tracing/trace", RULE_KERNEL),
            // Devices, for stat and read_dir too.
            ("/dev/mem", RULE_DEVICE),
            ("/dev/null", RULE_DEVICE),
            ("/dev/nvidia0", RULE_DEVICE),
            ("/dev", RULE_DEVICE),
            // Private keys by name.
            ("/etc/ssl/private/site.pem", RULE_PRIVATE_KEY),
            // Key files in PEM form, by name and by directory.
            ("/srv/app/tls/privkey.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/privkey1.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/server-key.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/server_key.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/key.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/server.key.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/tls-privkey.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/my.privkey.pem", RULE_PRIVATE_KEY),
            ("/srv/app/tls/private-ca.pem", RULE_PRIVATE_KEY),
            (
                "/etc/letsencrypt/live/example.test/cert.pem",
                RULE_PRIVATE_KEY,
            ),
            (
                "/etc/letsencrypt/archive/example.test/chain1.pem",
                RULE_PRIVATE_KEY,
            ),
            (
                "/var/lib/kubelet/pki/kubelet-client-current.pem",
                RULE_KUBECONFIG,
            ),
            ("/run/secrets/db_password", RULE_CREDENTIALS),
            ("/var/run/secrets/db_password", RULE_CREDENTIALS),
            // `auxv` is ours only under the real /proc, not under a mount of another one.
            ("/host/proc/self/auxv", RULE_PROC),
            ("/etc/pki/tls/private/site.pem", RULE_PRIVATE_KEY),
            ("/srv/app/server.key", RULE_PRIVATE_KEY),
            ("/srv/app/SERVER.KEY", RULE_PRIVATE_KEY),
            ("/srv/app/store.p12", RULE_PRIVATE_KEY),
            ("/srv/app/id_rsa", RULE_PRIVATE_KEY),
            ("/etc/ssh/ssh_host_ed25519_key", RULE_PRIVATE_KEY),
        ];
        for (path, rule) in cases {
            assert_eq!(verdict(path), Err(rule), "{path}");
        }
    }

    #[test]
    fn spelling_tricks_do_not_get_past_the_list() {
        for path in [
            "/etc//shadow",
            "/etc/./shadow",
            "/etc/shadow/",
            "//etc/shadow",
            "/proc//1/./environ",
        ] {
            assert!(verdict(path).is_err(), "{path} was allowed");
        }
        assert_eq!(verdict("/tmp/../etc/shadow"), Err(RULE_DOT_DOT));
        assert_eq!(verdict("/proc/1/../1/status"), Err(RULE_DOT_DOT));
        assert_eq!(verdict("etc/passwd"), Err(RULE_RELATIVE));
        assert_eq!(verdict(""), Err(RULE_RELATIVE));
    }

    #[test]
    fn what_checks_need_is_not_refused() {
        for path in [
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/net/tcp",
            "/proc/1",
            "/proc/1/status",
            "/proc/1/limits",
            "/proc/1/task",
            "/proc/1/task/1/status",
            "/proc/self/mountinfo",
            "/proc/self/auxv",
            "/proc/self/cgroup",
            "/proc/self/net/dev",
            "/proc/sys/kernel/osrelease",
            "/sys/fs/cgroup/cpu.max",
            "/sys/kernel/mm/transparent_hugepage/enabled",
            "/etc/os-release",
            "/etc/passwd",
            "/etc/sudo.conf",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/openssl.cnf",
            "/etc/ssh/ssh_host_ed25519_key.pub",
            "/etc/kubernetes/manifests/kube-apiserver.yaml",
            "/etc/kubernetes/pki/ca.crt",
            "/var/lib/kubelet/config.yaml",
            "/var/run/secrets/kubernetes.io",
            "/etc/letsencrypt/renewal/example.test.conf",
            "/srv/app/tls/fullchain.pem",
            "/srv/app/tls/cert.pem",
            "/run/secrets",
            "/home/ada/.docker",
            "/home/ada/.config/helm/repositories.yaml",
            "/home/ada/id_rsa.pub",
            "/usr/share/ca-certificates/site.crt",
        ] {
            assert_eq!(verdict(path), Ok(()), "{path}");
        }
    }

    #[test]
    fn the_machine_id_guard_admits_the_two_files_and_nothing_else() {
        let guard = ReadGuard::machine_id_files();
        for file in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            assert!(guard.admit_real(Path::new(file)).is_ok(), "{file}");
        }
        for other in [
            "/etc/shadow",
            "/etc/hostname",
            "/etc/machine-id.bak",
            "/host/etc/machine-id",
            "/var/lib/dbus",
            "/",
            "etc/machine-id",
        ] {
            assert!(guard.admit_real(Path::new(other)).is_err(), "{other}");
        }
        // The same two files are refused to a guard that is not this one, with or without prefixes.
        for guard in [
            ReadGuard::new(Os::Linux, None),
            ReadGuard::new(Os::Linux, Some(&["/"])),
        ] {
            for file in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
                let refused = guard.admit_real(Path::new(file)).expect_err("refused");
                assert_eq!(refused.rule, RULE_MACHINE_ID_FILE);
            }
        }
    }

    #[test]
    fn macos_ignores_case_and_the_private_prefix() {
        let mac = |path: &str| check_names(Path::new(path), true);
        assert_eq!(mac("/ETC/Shadow"), Err(RULE_SYSTEM_SECRET));
        assert_eq!(mac("/private/etc/sudoers"), Err(RULE_SYSTEM_SECRET));
        assert_eq!(mac("/private/etc/master.passwd"), Err(RULE_SYSTEM_SECRET));
        assert_eq!(mac("/Users/ada/.SSH/id_rsa"), Err(RULE_SSH));
        // On a case-sensitive file system these are other files. Only the any-depth rule still sees
        // the second one, because `etc` is not at the root there.
        assert_eq!(verdict("/ETC/Shadow"), Ok(()));
        assert_eq!(verdict("/private/etc/sudoers"), Err(RULE_SYSTEM_SECRET));
    }

    #[tokio::test]
    async fn a_denied_read_never_reaches_the_backend_and_is_logged() {
        // The fixture holds the file, so a read that got through would succeed.
        let replay = Replay::new()
            .file("/proc/1/environ", "AWS_SECRET_ACCESS_KEY=xyz")
            .file("/etc/shadow", "root:$6$salt$hash::");
        let hub = hub(replay);
        let probe = hub.check_probe("host.cpu", Os::Linux, None);

        let error = probe
            .read(Path::new("/proc/1/environ"))
            .await
            .expect_err("refused");
        assert_eq!(
            error,
            ProbeError::Denied {
                rule: policy::RULE_PROC,
                what: "/proc/1/environ".to_owned()
            }
        );
        assert!(probe.read_dir(Path::new("/proc/1/fd")).await.is_err());
        assert!(probe.stat(Path::new("/etc/shadow")).await.is_err());
        assert!(probe.stat(Path::new("/dev/nvidia0")).await.is_err());
        assert!(probe.read_dir(Path::new("/dev")).await.is_err());

        let log = hub.action_log();
        let kinds: Vec<_> = log.actions.iter().map(|a| a.kind.to_string()).collect();
        assert_eq!(kinds, ["read", "read_dir", "stat", "stat", "read_dir"]);
        for action in &log.actions {
            assert_eq!(action.outcome, ActionOutcome::Denied);
            assert_eq!(action.check.as_deref(), Some("host.cpu"));
            assert!(field(action, "rule").and_then(Value::as_str).is_some());
        }
        let first = &log.actions[0];
        assert_eq!(field(first, "path"), Some(&json!("/proc/1/environ")));
        assert!(field(first, "bytes").is_none(), "no bytes were read");
    }

    #[tokio::test]
    async fn a_denied_error_names_the_path_the_way_the_log_does() {
        // The error becomes a result message. A home directory must not be in it.
        let hub =
            hub(Replay::new().file("/home/tester/.ssh/id_rsa", "KEY")).with_home("/home/tester");
        let probe = hub.check_probe("host.cpu", Os::Linux, None);
        let error = probe
            .read(Path::new("/home/tester/.ssh/id_rsa"))
            .await
            .expect_err("refused");
        assert_eq!(
            error,
            ProbeError::Denied {
                rule: policy::RULE_SSH,
                what: "~/.ssh/id_rsa".to_owned()
            }
        );
        let message = CheckError::from(error).to_string();
        assert!(!message.contains("/home/tester"), "{message}");
        assert!(message.contains("~/.ssh/id_rsa"), "{message}");

        let log = hub.action_log();
        assert_eq!(
            field(&log.actions[0], "path"),
            Some(&json!("~/.ssh/id_rsa"))
        );
    }

    #[tokio::test]
    async fn reads_show_home_paths_with_a_tilde() {
        let hub = hub(Replay::new().file("/home/tester/notes.txt", "hi")).with_home("/home/tester");
        let probe = hub.check_probe("host.cpu", Os::Linux, None);
        probe
            .read(Path::new("/home/tester/notes.txt"))
            .await
            .expect("read");
        let log = hub.action_log();
        assert_eq!(field(&log.actions[0], "path"), Some(&json!("~/notes.txt")));
    }

    #[tokio::test]
    async fn read_dir_stat_and_missing_files_are_recorded() {
        let replay = Replay::new().file("/proc/cpuinfo", "processor : 0\n").dir(
            "/sys/class/net",
            vec![DirEntry::new("eth0", true), DirEntry::new("lo", true)],
        );
        let hub = hub(replay);
        let probe = hub.check_probe("host.cpu", Os::Linux, None);

        assert_eq!(
            probe
                .read(Path::new("/proc/cpuinfo"))
                .await
                .expect("read")
                .bytes,
            b"processor : 0\n"
        );
        assert_eq!(
            probe
                .read_dir(Path::new("/sys/class/net"))
                .await
                .expect("dir")
                .len(),
            2
        );
        assert!(
            probe
                .stat(Path::new("/proc/cpuinfo"))
                .await
                .expect("stat")
                .is_some_and(|m| m.is_file && m.len == 14)
        );
        assert_eq!(probe.stat(Path::new("/nope")).await, Ok(None));
        assert_eq!(
            probe.read(Path::new("/nope")).await,
            Err(ProbeError::NotFound)
        );

        let log = hub.action_log();
        let seen: Vec<_> = log
            .actions
            .iter()
            .map(|a| (a.kind.to_string(), a.outcome.to_string()))
            .collect();
        assert_eq!(
            seen,
            [
                ("read", "ok"),
                ("read_dir", "ok"),
                ("stat", "ok"),
                ("stat", "ok"),
                ("read", "failed")
            ]
            .map(|(k, o)| (k.to_owned(), o.to_owned()))
        );
        assert_eq!(field(&log.actions[0], "bytes"), Some(&json!(14)));
        assert_eq!(field(&log.actions[0], "truncated"), Some(&json!(false)));
        assert_eq!(field(&log.actions[1], "entries"), Some(&json!(2)));
        assert!(field(&log.actions[4], "error").is_some());
        let seqs: Vec<u64> = log.actions.iter().map(|a| a.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
    }
}

#[tokio::test]
async fn a_windows_check_reads_no_files_on_any_host() {
    // The policy follows the check's OS, not the machine rdy runs on.
    let hub = hub(Replay::new().file("/proc/cpuinfo", "y"));
    let probe = hub.check_probe("host.cpu", Os::Windows, None);
    let error = probe
        .read(Path::new("/proc/cpuinfo"))
        .await
        .expect_err("refused");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: policy::RULE_WINDOWS,
            ..
        }
    ));
}

// ---- the reads prefixes, size caps and env (M1-045) -------------------------------------------

/// These run on every host, the Windows leg included: the policy follows the check's OS, and the replay
/// backend is a map.
mod reads {
    use super::*;
    use crate::check::{CheckInfo, CheckMeta, OsSupport, Support};
    use crate::probe::policy::{RULE_OUTSIDE_READS, RULE_PROC, ReadGuard};

    static READER: CheckInfo = CheckInfo {
        id: "host.fixture",
        family: "host",
        summary: "Reads a few files and one variable.",
        meta: CheckMeta {
            title: "Fixture check",
            remediation: "Nothing to fix. This check is a test double.",
        },
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OsSupport {
            linux: Support::Full,
            macos: Support::Full,
            windows: Support::NotYet,
        },
        reads: &["/proc", "/etc/os-release"],
        env: &["HTTPS_PROXY"],
        commands: &[],
        peers: &[],
    };

    fn rule_of(error: &ProbeError) -> &'static str {
        match error {
            ProbeError::Denied { rule, .. } => rule,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_read_outside_the_declared_prefixes_is_refused_and_logged() {
        let hub = hub(Replay::new()
            .file("/proc/cpuinfo", "cpu")
            .file("/etc/os-release", "ID=fixture")
            .file("/var/log/syslog", "boot")
            .file("/procfoo/x", "no")
            .file("/etc/os-release.d/x", "no"));
        let probe = hub.check_probe("host.fixture", Os::Linux, Some(&READER));

        assert!(probe.read(Path::new("/proc/cpuinfo")).await.is_ok());
        assert!(probe.read(Path::new("/etc/os-release")).await.is_ok());
        for path in ["/var/log/syslog", "/procfoo/x", "/etc/os-release.d/x"] {
            let error = probe.read(Path::new(path)).await.expect_err("refused");
            assert_eq!(rule_of(&error), RULE_OUTSIDE_READS, "{path}");
        }
        assert!(probe.stat(Path::new("/var/log")).await.is_err());
        assert!(probe.read_dir(Path::new("/var/log")).await.is_err());
        assert!(
            probe
                .read_tail(Path::new("/var/log/syslog"), 4)
                .await
                .is_err()
        );

        let log = hub.action_log();
        let denied: Vec<_> = log
            .actions
            .iter()
            .filter(|a| a.outcome == ActionOutcome::Denied)
            .collect();
        assert_eq!(denied.len(), 6, "every refusal is logged");
        for action in denied {
            assert_eq!(field(action, "rule"), Some(&json!(RULE_OUTSIDE_READS)));
        }
    }

    #[tokio::test]
    async fn the_denylist_wins_inside_a_declared_prefix() {
        let hub = hub(Replay::new().file("/proc/1/environ", "SECRET=1"));
        let probe = hub.check_probe("host.fixture", Os::Linux, Some(&READER));
        let error = probe
            .read(Path::new("/proc/1/environ"))
            .await
            .expect_err("refused");
        assert_eq!(rule_of(&error), RULE_PROC);
    }

    #[tokio::test]
    async fn a_probe_with_no_manifest_keeps_the_denylist_and_has_no_prefixes() {
        let hub = hub(Replay::new().file("/var/log/syslog", "boot"));
        let probe = hub.check_probe("host.fixture", Os::Linux, None);
        assert!(probe.read(Path::new("/var/log/syslog")).await.is_ok());
    }

    #[tokio::test]
    async fn a_two_mib_file_returns_one_mib_with_truncated_true() {
        let mut big = vec![b'a'; MAX_READ];
        big.extend(vec![b'b'; MAX_READ]);
        let hub = hub(Replay::new().file("/proc/big", big));
        let probe = hub.check_probe("host.fixture", Os::Linux, Some(&READER));

        let file = probe.read(Path::new("/proc/big")).await.expect("read");
        assert_eq!(file.bytes.len(), MAX_READ);
        assert!(file.truncated_tail && file.truncated());
        let tail = probe
            .read_tail(Path::new("/proc/big"), 8)
            .await
            .expect("tail");
        assert_eq!(tail.bytes, b"bbbbbbbb");
        assert!(tail.truncated_head && !tail.truncated_tail);

        let log = hub.action_log();
        assert_eq!(field(&log.actions[0], "bytes"), Some(&json!(MAX_READ)));
        assert_eq!(field(&log.actions[0], "truncated"), Some(&json!(true)));
    }

    #[test]
    fn only_our_own_pid_reads_auxv_on_a_real_path() {
        let guard = ReadGuard::new(Os::Linux, None);
        let own = std::process::id();
        let path = |pid: u32| format!("/proc/{pid}/auxv");
        assert_eq!(guard.admit_real(Path::new(&path(own))), Ok(()));
        // Never "any pid".
        let other = path(own.wrapping_add(1));
        let error = guard
            .admit_real(Path::new(&other))
            .expect_err("another pid");
        assert_eq!(error.rule, RULE_PROC);
        assert!(guard.admit_real(Path::new("/proc/1/environ")).is_err());
        // As written, only `self` passes; a pid in the text does not.
        assert!(guard.admit(Path::new("/proc/self/auxv")).is_ok());
        assert!(guard.admit(Path::new(&path(own))).is_err());
    }

    #[test]
    fn our_pid_in_a_path_as_written_does_not_depend_on_the_host() {
        let guard = ReadGuard::new(Os::Linux, Some(&["/proc/self/mountinfo"]));
        let own = format!("/proc/{}/mountinfo", std::process::id());
        // As written, a pid is just a pid: a replay run decides the same on every host.
        assert_eq!(
            guard.admit(Path::new(&own)),
            Err(RULE_OUTSIDE_READS),
            "{own}"
        );
        // On a real path `/proc/self` has become our pid, and the same declaration covers it.
        assert_eq!(guard.admit_real(Path::new(&own)), Ok(()));
        assert!(guard.admit(Path::new("/proc/self/mountinfo")).is_ok());
    }

    #[test]
    fn the_decision_follows_the_checks_os_and_not_the_host() {
        let linux = ReadGuard::new(Os::Linux, Some(&["/proc"]));
        assert_eq!(linux.admit(Path::new("/proc/cpuinfo")), Ok(()));
        let windows = ReadGuard::new(Os::Windows, None);
        assert_eq!(
            windows.admit(Path::new("/proc/cpuinfo")),
            Err(policy::RULE_WINDOWS)
        );
        // Names compare without case only for a macOS check.
        let mac = ReadGuard::new(Os::Macos, Some(&["/Library"]));
        assert_eq!(mac.admit(Path::new("/library/x")), Ok(()));
        assert!(linux.admit(Path::new("/PROC/cpuinfo")).is_err());
    }

    #[tokio::test]
    async fn an_undeclared_env_name_is_refused_and_logged_without_a_value() {
        let hub = hub(Replay::new()
            .env("HTTPS_PROXY", "http://proxy.example:3128")
            .env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI-secret"));
        let probe = hub.check_probe("host.fixture", Os::Linux, Some(&READER));

        let value = probe.env("HTTPS_PROXY").expect("declared");
        assert_eq!(value.as_deref(), Some("http://proxy.example:3128"));
        let error = probe.env("AWS_SECRET_ACCESS_KEY").expect_err("refused");
        assert_eq!(rule_of(&error), RULE_ENV_NOT_DECLARED);
        for bad in ["", "A=B", "A\0B"] {
            let error = probe.env(bad).expect_err("not a name");
            assert_eq!(rule_of(&error), RULE_ENV_BAD_NAME, "{bad:?}");
        }

        let log = hub.action_log();
        assert!(log.actions.iter().all(|a| a.kind.to_string() == "env"));
        assert_eq!(log.actions[0].outcome, ActionOutcome::Ok);
        assert_eq!(field(&log.actions[0], "name"), Some(&json!("HTTPS_PROXY")));
        assert!(
            log.actions[1..]
                .iter()
                .all(|a| a.outcome == ActionOutcome::Denied)
        );
        let text = serde_json::to_string(&log.actions).expect("json");
        assert!(!text.contains("proxy.example"), "the value is never logged");
        assert!(!text.contains("wJalrXUtnFEMI"));
    }

    #[tokio::test]
    async fn an_env_call_after_the_check_ended_is_refused() {
        let hub = hub(Replay::new().env("HTTPS_PROXY", "x"));
        let probe = hub.check_probe("host.fixture", Os::Linux, Some(&READER));
        probe.end();
        let error = probe.env("HTTPS_PROXY").expect_err("ended");
        assert_eq!(rule_of(&error), RULE_CHECK_FINISHED);
        assert!(Probe::closed().env("HTTPS_PROXY").is_err());
    }
}

// ---- exec --------------------------------------------------------------------------------------

#[cfg(feature = "runtime")]
mod commands {
    use std::sync::Mutex;

    use super::*;
    use crate::check::CommandSpec;
    use crate::check::{CheckInfo, CheckMeta, OsSupport, Support};
    use crate::exec::ExecError;
    use crate::exec::policy::CommandError;

    const META: CheckMeta = CheckMeta {
        title: "Fixture check",
        remediation: "Nothing to fix. This check is a test double.",
    };

    const ALL_OS: OsSupport = OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    };

    /// A check that declares getent, with a small cap and one environment name.
    static GETENT_ONLY: CheckInfo = CheckInfo {
        id: "net.dns",
        family: "net",
        summary: "Runs getent.",
        meta: META,
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: ALL_OS,
        reads: &[],
        env: &[],
        commands: &[CommandSpec {
            program: "getent",
            extra_dirs: &[],
            max_stdout: 4096,
            env: &["ACME_REGION"],
        }],
        peers: &[],
    };

    /// A check that declares a search directory that no table entry lists.
    static WIDE_DIRS: CheckInfo = CheckInfo {
        id: "gpu.driver",
        family: "gpu",
        summary: "Runs nvidia-smi from a directory of its own.",
        meta: META,
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: ALL_OS,
        reads: &[],
        env: &[],
        commands: &[CommandSpec {
            program: "nvidia-smi",
            extra_dirs: &["/opt/acme/bin"],
            max_stdout: 4096,
            env: &[],
        }],
        peers: &[],
    };

    /// A backend that records what it was asked to run. It overrides `spawn`, so any command that
    /// reaches it passed the probe's gate.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<(String, Vec<String>, usize)>>,
    }

    impl Sealed for Recorder {}

    impl Backend for Recorder {
        fn open_read<'a>(
            &'a self,
            _: &'a Path,
            _: ReadRange,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<FileBytes>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
        fn read_dir<'a>(
            &'a self,
            _: &'a Path,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
        fn stat<'a>(
            &'a self,
            _: &'a Path,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
            Box::pin(async { Ok(None) })
        }
        fn env(&self, _: &str) -> Option<String> {
            None
        }
        fn native<'a>(
            &'a self,
            _: &'a NativeCall,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<NativeValue>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
        fn spawn<'a>(&'a self, cmd: Cmd) -> BoxFuture<'a, Result<Output, ProbeError>> {
            Box::pin(async move {
                let args = cmd
                    .arguments()
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect();
                self.seen.lock().expect("lock").push((
                    cmd.program().to_owned(),
                    args,
                    cmd.output_cap(),
                ));
                Ok(Output::new(Some(0), b"ok".to_vec()))
            })
        }
    }

    /// A backend that keeps the provided `spawn`, which is the live path.
    struct Live;

    impl Sealed for Live {}

    impl Backend for Live {
        fn open_read<'a>(
            &'a self,
            _: &'a Path,
            _: ReadRange,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<FileBytes>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
        fn read_dir<'a>(
            &'a self,
            _: &'a Path,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
        fn stat<'a>(
            &'a self,
            _: &'a Path,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
            Box::pin(async { Ok(None) })
        }
        fn env(&self, _: &str) -> Option<String> {
            None
        }
        fn native<'a>(
            &'a self,
            _: &'a NativeCall,
            _: &'a ReadGuard,
        ) -> BoxFuture<'a, io::Result<NativeValue>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
    }

    fn recording_hub() -> (ProbeHub, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        let backend: Arc<dyn Backend> = recorder.clone();
        (ProbeHub::new(backend, redactor()), recorder)
    }

    #[tokio::test]
    async fn a_command_is_logged_with_its_program_form_argv_and_exit() {
        let hub = hub(Replay::new().command(
            "getent",
            &getent_args("registry.acme.example"),
            0,
            "10.0.0.7 STREAM\n",
        ));
        let probe = hub.check_probe("net.dns", Os::Linux, None);
        let output = probe
            .exec(getent("registry.acme.example"))
            .await
            .expect("ran");
        assert_eq!(output.exit, Some(0));
        assert_eq!(output.stdout, b"10.0.0.7 STREAM\n");

        let missing = probe.exec(getent("other.acme.example")).await;
        assert_eq!(missing, Err(ProbeError::NotFound));

        let log = hub.action_log();
        let ok = &log.actions[0];
        assert_eq!(ok.kind, ActionKind::Exec);
        assert_eq!(ok.outcome, ActionOutcome::Ok);
        assert_eq!(field(ok, "program"), Some(&json!("getent")));
        assert_eq!(field(ok, "form"), Some(&json!("ahosts")));
        assert_eq!(
            field(ok, "argv"),
            Some(&json!(["ahosts", "--", "registry.acme.example"]))
        );
        assert_eq!(field(ok, "exit"), Some(&json!(0)));
        assert_eq!(field(ok, "stdout_bytes"), Some(&json!(16)));
        let failed = &log.actions[1];
        assert_eq!(failed.outcome, ActionOutcome::Failed);
        assert_eq!(field(failed, "program"), Some(&json!("getent")));
    }

    #[tokio::test]
    async fn a_command_the_table_does_not_list_never_reaches_the_backend() {
        // The fixture holds output for a shell, a privilege tool and table programs with arguments
        // that fit no form, so only the table stands between the check and them.
        let hub = hub(Replay::new()
            .command("sh", &["-c", "id"], 0, "uid=0")
            .command("sudo", &["id"], 0, "uid=0")
            .command("getent", &["passwd"], 0, "root:x:0:0")
            .command("getent", &["ahosts", "--", "a b"], 0, "x")
            .command("getent", &["ahosts", "--", "-x"], 0, "x"));
        let probe = hub.check_probe("net.dns", Os::Linux, None);
        let secs = Duration::from_secs(5);
        let cases = [
            Cmd::new("sh", secs).args(["-c", "id"]),
            Cmd::new("sudo", secs).args(["id"]),
            Cmd::new("getent", secs).args(["passwd"]),
            Cmd::new("getent", secs).args(["ahosts", "--", "a b"]),
            Cmd::new("getent", secs).args(["ahosts", "--", "-x"]),
            // Past the form's time limit.
            Cmd::new("getent", Duration::from_secs(600)).args(["ahosts", "--", "h"]),
        ];
        for cmd in cases {
            let name = format!("{cmd:?}");
            let error = probe.exec(cmd).await.expect_err(&name);
            assert!(matches!(error, ProbeError::Table(_)), "{name}: {error:?}");
            assert!(error.to_string().contains("Fix:"), "{error}");
        }
        // Not listed for this OS: getent is a Linux row.
        let mac = hub.check_probe("net.dns", Os::Macos, None);
        let error = mac
            .exec(getent("registry.acme.example"))
            .await
            .expect_err("macos");
        assert!(matches!(
            error,
            ProbeError::Table(TableError::NotOnThisOs { .. })
        ));

        let log = hub.action_log();
        assert_eq!(log.actions.len(), 7);
        for action in &log.actions {
            assert_eq!(action.outcome, ActionOutcome::Denied);
            assert!(
                field(action, "rule")
                    .and_then(Value::as_str)
                    .is_some_and(|rule| rule.contains("refused")),
                "{action:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_checks_declaration_decides_directories_cap_and_env() {
        let (hub, recorder) = recording_hub();
        let probe = hub.check_probe("net.dns", Os::Linux, Some(&GETENT_ONLY));

        // A declared command runs with the declared cap, which can only narrow the table's.
        probe
            .exec(getent("a.acme.example"))
            .await
            .expect("declared");
        probe
            .exec(getent("b.acme.example").stdout_cap(1))
            .await
            .expect("a lower cap stays lower");
        // An undeclared program and an undeclared env name are denied, and the backend sees neither.
        let timedatectl = table::entry("timedatectl")
            .expect("entry")
            .cmd_for(Os::Linux, "status", &[])
            .expect("cmd");
        let undeclared = probe.exec(timedatectl).await.expect_err("undeclared");
        assert!(matches!(
            undeclared,
            ProbeError::Denied {
                rule: RULE_COMMAND_UNDECLARED,
                ..
            }
        ));
        let env = probe
            .exec(getent("c.acme.example").env([("HTTPS_PROXY", "http://proxy.invalid:3128")]))
            .await
            .expect_err("env");
        assert!(matches!(
            env,
            ProbeError::Denied { rule: RULE_ENV_UNDECLARED, what } if what == "HTTPS_PROXY"
        ));
        // A declared name is not enough: the table gives every command the base environment only.
        let declared_env = probe
            .exec(getent("d.acme.example").env([("ACME_REGION", "eu-west-1")]))
            .await
            .expect_err("table env");
        assert!(matches!(
            declared_env,
            ProbeError::Table(TableError::EnvNotAllowed { .. })
        ));
        // A check cannot add a search directory the table does not list.
        let smi = table::entry("nvidia-smi")
            .expect("entry")
            .cmd_for(Os::Linux, "query-xml", &[])
            .expect("cmd");
        let wide = hub.check_probe("gpu.driver", Os::Linux, Some(&WIDE_DIRS));
        let error = wide.exec(smi).await.expect_err("dirs");
        assert!(matches!(
            error,
            ProbeError::Table(TableError::DirNotAllowed { .. })
        ));

        let seen = recorder.seen.lock().expect("lock").clone();
        let want = |name: &str, cap: usize| {
            (
                "getent".to_owned(),
                getent_args(name).map(str::to_owned).to_vec(),
                cap,
            )
        };
        assert_eq!(
            seen,
            [want("a.acme.example", 4096), want("b.acme.example", 1)]
        );

        let log = hub.action_log();
        let outcomes: Vec<_> = log.actions.iter().map(|a| a.outcome.to_string()).collect();
        assert_eq!(
            outcomes,
            ["ok", "ok", "denied", "denied", "denied", "denied"]
        );
        assert_eq!(
            field(&log.actions[2], "rule"),
            Some(&json!(RULE_COMMAND_UNDECLARED))
        );
    }

    #[tokio::test]
    async fn a_thousand_and_one_denied_execs_fold_and_none_is_dropped() {
        let hub = hub(Replay::new());
        let probe = hub.check_probe("net.dns", Os::Linux, Some(&GETENT_ONLY));
        let undeclared = |program: &str, form: &str| {
            table::entry(program)
                .expect("entry")
                .cmd_for(Os::Linux, form, &[])
                .expect("a table command")
        };
        for _ in 0..=CHECK_QUOTA {
            let error = probe
                .exec(undeclared("timedatectl", "status"))
                .await
                .expect_err("undeclared");
            assert!(matches!(
                error,
                ProbeError::Denied {
                    rule: RULE_COMMAND_UNDECLARED,
                    ..
                }
            ));
        }
        // A different program is its own key.
        probe
            .exec(undeclared("crio", "version"))
            .await
            .expect_err("undeclared");

        let log = hub.action_log();
        assert_eq!(log.last_resort_drops, 0);
        assert!(!log.truncated, "nothing was dropped: {:?}", log.dropped);
        // 20 written, one coalesced entry, and the other program.
        assert_eq!(log.actions.len(), COALESCE_AFTER + 1 + 1);
        let folded: Vec<_> = log
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::Coalesced)
            .collect();
        assert_eq!(folded.len(), 1);
        assert_eq!(field(folded[0], "of"), Some(&json!("exec")));
        assert_eq!(field(folded[0], "under"), Some(&json!("timedatectl")));
        assert_eq!(
            field(folded[0], "count"),
            Some(&json!(CHECK_QUOTA + 1 - COALESCE_AFTER))
        );
        assert_eq!(folded[0].outcome, ActionOutcome::Denied);
    }

    #[tokio::test]
    async fn the_provided_spawn_runs_commands_through_the_table_runner() {
        // `table::run` refuses an unlisted program before anything starts, so this proves the live
        // path goes through the table without starting a process.
        let error = Live
            .spawn(Cmd::new("sh", Duration::from_secs(5)).args(["-c", "id"]))
            .await
            .expect_err("refused");
        assert!(
            matches!(error, ProbeError::Table(TableError::UnknownProgram { .. })),
            "{error:?}"
        );
        // The probe's own gate stops the same command before the backend is asked.
        let hub = ProbeHub::new(Arc::new(Live), redactor());
        let probe = hub.check_probe("net.dns", Os::Linux, None);
        let error = probe
            .exec(Cmd::new("sh", Duration::from_secs(5)))
            .await
            .expect_err("gate");
        assert!(matches!(error, ProbeError::Table(_)));
    }

    #[test]
    fn runner_errors_map_to_probe_errors() {
        let spawn_failed = ExecError::Spawn(io::Error::from(io::ErrorKind::NotFound));
        let cases = [
            (CommandError::Exec(ExecError::Timeout), ProbeError::Timeout),
            (
                CommandError::Exec(ExecError::Hung { pid: 7 }),
                ProbeError::Hung { pid: 7 },
            ),
            (CommandError::Exec(spawn_failed), ProbeError::NotFound),
            (
                CommandError::Exec(ExecError::Io("pipe".to_owned())),
                ProbeError::Io("pipe".to_owned()),
            ),
        ];
        for (error, want) in cases {
            assert_eq!(ProbeError::from_command(error), want);
        }
        assert!(matches!(
            ProbeError::from_command(CommandError::Exec(ExecError::TooMany)),
            ProbeError::Io(_)
        ));
        let table = CommandError::Table(TableError::UnknownProgram { program: "sh" });
        assert!(matches!(
            ProbeError::from_command(table),
            ProbeError::Table(_)
        ));
    }

    #[tokio::test]
    async fn the_element_after_a_secret_flag_is_redacted() {
        // No table form has a secret flag, so the entries are written the way the network tickets
        // write theirs: through `begin`. The argv logic is the log's, not the command's.
        let hub = hub(Replay::new());
        let probe = hub.check_probe("net.dns", Os::Linux, None);
        let write = |argv: &[&str]| {
            let mut fields = Map::new();
            fields.insert("argv".to_owned(), json!(argv));
            let (_, entry) = probe
                .begin(ActionKind::Exec, fields, "getent")
                .expect("live");
            entry.finish(ActionOutcome::Ok);
        };
        write(&["--password", "hunter2hunter2", "addr"]);
        write(&["--token", "tok-abc-123", "--name", "plain"]);
        write(&["--api-key", "--token", "k-1", "z"]);
        write(&["--password"]);
        let log = hub.action_log();
        let argv = |index: usize| -> Vec<String> {
            field(&log.actions[index], "argv")
                .and_then(Value::as_array)
                .expect("argv")
                .iter()
                .map(|v| v.as_str().expect("text").to_owned())
                .collect()
        };
        let first = argv(0);
        assert_eq!(first[0], "--password");
        assert!(
            first[1].starts_with("[REDACTED:secret_by_key:"),
            "{first:?}"
        );
        assert_eq!(first[2], "addr");
        let second = argv(1);
        assert!(
            second[1].starts_with("[REDACTED:secret_by_key:"),
            "{second:?}"
        );
        assert_eq!(second[2], "--name");
        assert_eq!(second[3], "plain", "a non-secret flag keeps its value");
        // A secret flag followed by another secret flag does not hide the second one's value.
        let third = argv(2);
        assert!(
            third[2].starts_with("[REDACTED:secret_by_key:"),
            "{third:?}"
        );
        assert_eq!(argv(3), ["--password"]);

        let text = serde_json::to_string(&log.actions).expect("json");
        for secret in ["hunter2hunter2", "tok-abc-123", "k-1"] {
            assert!(!text.contains(secret), "{secret} reached the log");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_command_dropped_before_it_finished_is_logged_as_a_timeout() {
        let hub = ProbeHub::new(Arc::new(Hanging), redactor());
        let probe = hub.check_probe("net.dns", Os::Linux, None);
        let outcome =
            tokio::time::timeout(Duration::from_secs(1), probe.exec(getent("acme.example"))).await;
        assert!(outcome.is_err(), "the call hangs");

        let log = hub.action_log();
        assert_eq!(log.actions.len(), 1);
        assert_eq!(log.actions[0].outcome, ActionOutcome::Timeout);
        assert_eq!(field(&log.actions[0], "program"), Some(&json!("getent")));
    }
}

// ---- the handle's life -------------------------------------------------------------------------

#[tokio::test]
async fn a_closed_probe_refuses_everything() {
    let probe = Probe::closed();
    let error = probe
        .stat(Path::new("/proc/cpuinfo"))
        .await
        .expect_err("refused");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: RULE_NO_PROBE,
            ..
        }
    ));
    // A bare context, as the existing tests build, has this probe.
    let ctx = CheckContext::new("fake.plain", Os::Linux, []);
    assert!(ctx.probe().stat(Path::new("/proc")).await.is_err());
}

#[tokio::test]
async fn a_call_after_the_check_ended_is_denied_and_logged() {
    let hub = hub(Replay::new().file("/proc/cpuinfo", "x"));
    let probe = hub.check_probe("host.cpu", Os::Linux, None);
    let straggler = probe.clone();
    probe
        .read(Path::new("/proc/cpuinfo"))
        .await
        .expect("before the end");
    probe.end();

    let error = straggler
        .read(Path::new("/proc/cpuinfo"))
        .await
        .expect_err("after the end");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: RULE_CHECK_FINISHED,
            ..
        }
    ));
    assert!(probe.stat(Path::new("/proc")).await.is_err());
    assert!(probe.begin(ActionKind::Connect, Map::new(), "h").is_err());

    let log = hub.action_log();
    assert_eq!(log.actions.len(), 4);
    let late = &log.actions[1];
    assert_eq!(late.outcome, ActionOutcome::Denied);
    assert_eq!(late.check.as_deref(), Some("host.cpu"));
    assert_eq!(field(late, "rule"), Some(&json!(RULE_CHECK_FINISHED)));
    assert_eq!(field(late, "path"), Some(&json!("/proc/cpuinfo")));
}

#[test]
fn a_failed_kube_status_carries_a_fixed_error_and_a_redirect_is_not_ok() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("k8s.nodes", Os::Linux, None);
    for status in [200_u16, 204, 302, 403, 503] {
        probe
            .kube_call("GET", "/api/v1/nodes")
            .expect("open")
            .answered(status);
    }
    probe
        .kube_call("GET", "/api/v1/nodes")
        .expect("open")
        .refused_header("a header rule", "authorization");
    let log = hub.action_log();
    let outcomes: Vec<_> = log.actions.iter().map(|a| a.outcome.clone()).collect();
    assert_eq!(
        outcomes,
        [
            ActionOutcome::Ok,
            ActionOutcome::Ok,
            ActionOutcome::Failed,
            ActionOutcome::Failed,
            ActionOutcome::Failed,
            ActionOutcome::Denied,
        ]
    );
    assert_eq!(field(&log.actions[0], "error"), None);
    assert_eq!(field(&log.actions[1], "error"), None);
    for entry in &log.actions[2..5] {
        let error = field(entry, "error")
            .and_then(|v| v.as_str())
            .expect("error");
        assert!(error.starts_with("the server answered"), "{error}");
    }
    assert!(
        field(&log.actions[2], "error")
            .and_then(|v| v.as_str())
            .is_some_and(|e| e.contains("redirect"))
    );
    // A refused header is named, with the rule, and has no value and no error.
    assert_eq!(
        field(&log.actions[5], "header"),
        Some(&json!("authorization"))
    );
    assert_eq!(
        field(&log.actions[5], "rule"),
        Some(&json!("a header rule"))
    );
    assert_eq!(field(&log.actions[5], "error"), None);
}

#[test]
fn a_kube_call_writes_one_entry_under_its_check() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("k8s.nodes", Os::Linux, None);
    probe
        .kube_call("GET", "/api/v1/nodes")
        .expect("open")
        .answered(200);
    probe
        .kube_call("GET", "/api/v1/pods")
        .expect("open")
        .answered(503);
    probe
        .kube_call("DELETE", "/api/v1/nodes/n1")
        .expect("open")
        .refused("a rule");
    probe
        .kube_call("GET", "/version")
        .expect("open")
        .failed("the request failed");
    // Dropped before it is closed: a cancelled request still leaves its entry.
    drop(probe.kube_call("GET", "/apis").expect("open"));

    let log = hub.action_log();
    let seen: Vec<_> = log
        .actions
        .iter()
        .map(|a| (a.kind.clone(), a.outcome.clone(), a.check.clone()))
        .collect();
    assert_eq!(
        seen,
        [
            (
                ActionKind::Kube,
                ActionOutcome::Ok,
                Some("k8s.nodes".to_owned())
            ),
            (
                ActionKind::Kube,
                ActionOutcome::Failed,
                Some("k8s.nodes".to_owned())
            ),
            (
                ActionKind::Kube,
                ActionOutcome::Denied,
                Some("k8s.nodes".to_owned())
            ),
            (
                ActionKind::Kube,
                ActionOutcome::Failed,
                Some("k8s.nodes".to_owned())
            ),
            (
                ActionKind::Kube,
                ActionOutcome::Timeout,
                Some("k8s.nodes".to_owned())
            ),
        ]
    );
    assert_eq!(field(&log.actions[0], "status"), Some(&json!(200)));
    assert_eq!(field(&log.actions[0], "method"), Some(&json!("GET")));
    assert_eq!(field(&log.actions[2], "rule"), Some(&json!("a rule")));
    assert_eq!(
        field(&log.actions[2], "path"),
        Some(&json!("/api/v1/nodes/n1"))
    );

    // A run-level probe logs `check: null`. An ended probe refuses, and the refusal is logged.
    hub.run_probe()
        .kube_call("GET", "/version")
        .expect("open")
        .answered(200);
    probe.end();
    let error = probe.kube_call("GET", "/api").expect_err("ended");
    assert!(matches!(
        error,
        ProbeError::Denied {
            rule: RULE_CHECK_FINISHED,
            ..
        }
    ));
    // A probe with no hub has nothing to log in, so it refuses and writes nothing.
    assert!(matches!(
        Probe::closed().kube_call("GET", "/version"),
        Err(ProbeError::Denied {
            rule: RULE_NO_PROBE,
            ..
        })
    ));
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 7);
    assert_eq!(log.actions[5].check, None);
    assert_eq!(log.actions[6].outcome, ActionOutcome::Denied);
    assert_eq!(
        field(&log.actions[6], "rule"),
        Some(&json!(RULE_CHECK_FINISHED))
    );
}

/// A backend whose calls never finish, to stand in for a check that the scheduler aborts.
struct Hanging;

impl Sealed for Hanging {}

impl Backend for Hanging {
    fn open_read<'a>(
        &'a self,
        _: &'a Path,
        _: ReadRange,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<FileBytes>> {
        Box::pin(std::future::pending())
    }
    fn read_dir<'a>(
        &'a self,
        _: &'a Path,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        Box::pin(std::future::pending())
    }
    fn stat<'a>(
        &'a self,
        _: &'a Path,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
        Box::pin(std::future::pending())
    }
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn native<'a>(
        &'a self,
        _: &'a NativeCall,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<NativeValue>> {
        Box::pin(std::future::pending())
    }
    fn spawn<'a>(&'a self, _: Cmd) -> BoxFuture<'a, Result<Output, ProbeError>> {
        Box::pin(std::future::pending())
    }
}

#[test]
fn run_env_is_for_run_level_probes_and_never_logs_the_value() {
    let hub = hub(Replay::new().env("SystemRoot", r"C:\Windows"));
    let run = hub.run_probe_for(Os::Windows);
    assert_eq!(
        run.run_env("SystemRoot"),
        Ok(Some(r"C:\Windows".to_owned()))
    );
    assert_eq!(run.run_env("Unset"), Ok(None));
    let check = hub.check_probe("host.os", Os::Windows, None);
    assert!(matches!(
        check.run_env("SystemRoot"),
        Err(ProbeError::Denied {
            rule: RULE_ENV_UNDECLARED,
            ..
        })
    ));
    let log = hub.action_log();
    let outcomes: Vec<(&str, ActionOutcome)> = log
        .actions
        .iter()
        .map(|a| (a.kind.as_str(), a.outcome.clone()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("env", ActionOutcome::Ok),
            ("env", ActionOutcome::Ok),
            ("env", ActionOutcome::Denied)
        ]
    );
    let text = serde_json::to_string(&log.actions).expect("log");
    assert!(!text.contains(r"C:\\Windows"), "{text}");
}

/// The provided `Backend::process_ids` is the live path (M1-042): the real and effective ids of this
/// process, with the saved and filesystem ids reported as the effective one.
#[cfg(unix)]
#[tokio::test]
async fn the_provided_process_ids_are_real_and_effective_with_the_rest_copied() {
    let ids = Hanging.process_ids().await.expect("ids");
    let (uid, euid) = (
        rustix::process::getuid().as_raw(),
        rustix::process::geteuid().as_raw(),
    );
    assert_eq!(ids.uid, [uid, euid, euid, euid]);
    assert_eq!(ids.gid[1], rustix::process::getegid().as_raw());
    assert_eq!(ids.gid[1], ids.gid[3]);
}

#[tokio::test(start_paused = true)]
async fn a_call_dropped_before_it_finished_is_logged_as_a_timeout() {
    let hub = ProbeHub::new(Arc::new(Hanging), redactor());
    let probe = hub.check_probe("net.dns", Os::Linux, None);
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.read(Path::new("/proc/cpuinfo")),
    )
    .await;
    assert!(outcome.is_err(), "the call hangs");

    let log = hub.action_log();
    assert_eq!(log.actions.len(), 1);
    assert_eq!(log.actions[0].outcome, ActionOutcome::Timeout);
    assert_eq!(
        field(&log.actions[0], "path"),
        Some(&json!("/proc/cpuinfo"))
    );
}

#[cfg(feature = "runtime")]
#[tokio::test]
async fn a_call_still_running_when_the_check_ends_is_cut_off_and_logged_denied() {
    let hub = ProbeHub::new(Arc::new(Hanging), redactor());
    let probe = hub.check_probe("net.dns", Os::Linux, None);
    let ender = probe.clone();
    let (result, ()) = tokio::join!(probe.read(Path::new("/proc/cpuinfo")), async move {
        tokio::task::yield_now().await;
        ender.end();
    });
    assert!(matches!(
        result,
        Err(ProbeError::Denied {
            rule: RULE_CHECK_FINISHED,
            ..
        })
    ));
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 1);
    assert_eq!(log.actions[0].outcome, ActionOutcome::Denied);
    assert_eq!(
        field(&log.actions[0], "rule"),
        Some(&json!(RULE_CHECK_FINISHED))
    );
}

// ---- retention ---------------------------------------------------------------------------------

/// Writes one entry of `kind` with `outcome` straight into the log, as a facade method would.
fn put(probe: &Probe, kind: ActionKind, outcome: ActionOutcome) {
    put_at(probe, kind, outcome, None, "");
}

/// The same, with the path and the reason the entry folds under.
fn put_at(probe: &Probe, kind: ActionKind, outcome: ActionOutcome, path: Option<&str>, why: &str) {
    let (_, mut entry) = probe
        .begin(kind, Map::new(), "fixture")
        .expect("probe is live");
    if let Some(path) = path {
        entry.set("path", path);
    }
    match outcome {
        ActionOutcome::Denied => entry.set("rule", why),
        ActionOutcome::Failed => entry.set("error", why),
        _ => {}
    }
    entry.finish(outcome);
}

fn count_of(log: &ActionLogOutput, kind: &str, outcome: ActionOutcome) -> usize {
    log.actions
        .iter()
        .filter(|a| a.kind.as_str() == kind && a.outcome == outcome)
        .count()
}

fn is_droppable_kind(kind: &str) -> bool {
    matches!(kind, "read" | "read_dir" | "stat")
}

#[test]
fn ok_reads_go_first_and_everything_else_stays() {
    let hub = hub(Replay::new()).with_limits(20, 1000);
    let probe = hub.check_probe("fixture.flood", Os::Linux, None);
    let keep = [
        (ActionKind::Exec, ActionOutcome::Ok),
        (ActionKind::Connect, ActionOutcome::Ok),
        (ActionKind::Connect, ActionOutcome::Failed),
        (ActionKind::Tls, ActionOutcome::Ok),
        (ActionKind::Http, ActionOutcome::Timeout),
        (ActionKind::Kube, ActionOutcome::Ok),
        (ActionKind::Lookup, ActionOutcome::Ok),
        (ActionKind::Native, ActionOutcome::Ok),
        (ActionKind::Read, ActionOutcome::Denied),
        (ActionKind::ReadDir, ActionOutcome::Timeout),
    ];
    // A flood of ok reads first, then the entries that must survive, then more flood.
    for _ in 0..20 {
        put(&probe, ActionKind::Read, ActionOutcome::Ok);
        put(&probe, ActionKind::ReadDir, ActionOutcome::Ok);
        put(&probe, ActionKind::Stat, ActionOutcome::Ok);
    }
    for (kind, outcome) in keep.clone() {
        put(&probe, kind, outcome);
    }
    for _ in 0..20 {
        put(&probe, ActionKind::Read, ActionOutcome::Ok);
    }

    let log = hub.action_log();
    let kept: Vec<(ActionKind, ActionOutcome)> = log
        .actions
        .iter()
        .filter(|a| !(is_droppable_kind(a.kind.as_str()) && a.outcome == ActionOutcome::Ok))
        .map(|a| (a.kind.clone(), a.outcome.clone()))
        .collect();
    // Every entry that may not be dropped is still there, in order.
    assert_eq!(kept, keep.to_vec());

    assert!(log.truncated);
    for kind in log.dropped.keys() {
        assert!(is_droppable_kind(kind), "dropped a {kind} entry");
    }
    assert_eq!(log.last_resort_drops, 0);
    assert_eq!(log.actions.len(), 20, "the log holds exactly its cap");
    // Every dropped entry is a gap in seq: 60 + 10 + 20 entries were made, 20 are left.
    let total_dropped: u64 = log.dropped.values().sum();
    assert_eq!(total_dropped + 20, 60 + 10 + 20);
    let seqs: Vec<u64> = log.actions.iter().map(|a| a.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn failed_reads_go_second_and_never_for_an_ok_read() {
    let hub = hub(Replay::new()).with_limits(10, 1000);
    let probe = hub.check_probe("fixture.flood", Os::Linux, None);
    // Ten failed reads, each under its own directory so none fold.
    for i in 0..10 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Failed,
            Some(&format!("/d{i}/f")),
            "not found",
        );
    }
    // A new ok read does not displace a failed one.
    put(&probe, ActionKind::Read, ActionOutcome::Ok);
    assert_eq!(
        count_of(&hub.action_log(), "read", ActionOutcome::Failed),
        10
    );
    // An exec and a denied read each displace one failed read.
    put(&probe, ActionKind::Exec, ActionOutcome::Ok);
    put_at(
        &probe,
        ActionKind::Read,
        ActionOutcome::Denied,
        Some("/etc/shadow"),
        "password and sudo files are never read",
    );
    let log = hub.action_log();
    assert_eq!(count_of(&log, "read", ActionOutcome::Failed), 8);
    assert_eq!(count_of(&log, "exec", ActionOutcome::Ok), 1);
    assert_eq!(count_of(&log, "read", ActionOutcome::Denied), 1);
    assert_eq!(log.last_resort_drops, 0);
    assert_eq!(log.dropped.get("read"), Some(&3), "1 ok read and 2 failed");
}

#[test]
fn many_failed_reads_under_one_directory_fold_into_one_entry() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("fixture.flood", Os::Linux, None);
    for i in 0..(COALESCE_AFTER + 30) {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Failed,
            Some(&format!("/sys/class/net/eth0/f{i}")),
            "not found",
        );
    }
    // A different reason under the same directory is another key.
    put_at(
        &probe,
        ActionKind::Read,
        ActionOutcome::Failed,
        Some("/sys/class/net/eth0/g"),
        "permission denied",
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), COALESCE_AFTER + 1 + 1);
    let folded = log
        .actions
        .iter()
        .find(|a| a.kind == ActionKind::Coalesced)
        .expect("a coalesced entry");
    assert_eq!(folded.outcome, ActionOutcome::Failed);
    assert_eq!(folded.check.as_deref(), Some("fixture.flood"));
    assert_eq!(field(folded, "of"), Some(&json!("read")));
    assert_eq!(field(folded, "under"), Some(&json!("/sys/class/net/eth0")));
    assert_eq!(field(folded, "error"), Some(&json!("not found")));
    assert_eq!(field(folded, "count"), Some(&json!(30)));
    assert!(!log.truncated, "folding is not dropping");
}

#[test]
fn a_flood_of_denied_reads_folds_and_nothing_is_dropped() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("fixture.flood", Os::Linux, None);
    for i in 0..6000 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Denied,
            Some(&format!("/home/ada/.ssh/k{i}")),
            "ssh directories are never read",
        );
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), COALESCE_AFTER + 1);
    assert!(log.dropped.is_empty());
    assert_eq!(log.last_resort_drops, 0);
    let folded = log.actions.last().expect("entry");
    assert_eq!(folded.kind, ActionKind::Coalesced);
    assert_eq!(folded.outcome, ActionOutcome::Denied);
    assert_eq!(
        field(folded, "rule"),
        Some(&json!("ssh directories are never read"))
    );
    assert_eq!(field(folded, "count"), Some(&json!(6000 - COALESCE_AFTER)));
}

#[test]
fn six_thousand_failed_reads_then_a_denied_read_keeps_the_denied_entry() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("host.flood", Os::Linux, None);
    for i in 0..6000 {
        // A directory each, so folding does not help and retention has to.
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Failed,
            Some(&format!("/d{i}/f")),
            "not found",
        );
    }
    let before = hub.action_log();
    assert_eq!(before.actions.len(), CHECK_QUOTA, "the quota holds");
    assert!(before.truncated);

    put_at(
        &probe,
        ActionKind::Read,
        ActionOutcome::Denied,
        Some("/etc/shadow"),
        "password and sudo files are never read",
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), CHECK_QUOTA);
    assert_eq!(count_of(&log, "read", ActionOutcome::Denied), 1);
    assert_eq!(
        field(log.actions.last().expect("entry"), "path"),
        Some(&json!("/etc/shadow"))
    );
    assert_eq!(
        log.last_resort_drops, 0,
        "failed reads gave way, not the last resort"
    );
    assert_eq!(log.dropped.get("read"), Some(&(6001 - CHECK_QUOTA as u64)));
}

/// Writes one `denied` entry of `kind` that names `target` in `field`, straight into the log.
fn deny(probe: &Probe, kind: ActionKind, field: &str, target: &str) {
    let (_, mut entry) = probe
        .begin(kind, Map::new(), "fixture")
        .expect("probe is live");
    entry.set(field, target);
    entry.set("rule", "refused for the test");
    entry.finish(ActionOutcome::Denied);
}

#[test]
fn denied_calls_past_the_target_cap_share_one_entry_under_a_star() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("net.flood", Os::Linux, None);
    for i in 0..DENIED_TARGETS + 50 {
        deny(
            &probe,
            ActionKind::Connect,
            "host",
            &format!("h{i}.acme.example"),
        );
    }
    let log = hub.action_log();
    assert_eq!(log.last_resort_drops, 0);
    assert!(!log.truncated, "{:?}", log.dropped);
    // 100 targets kept apart, then 20 written under the star key and the rest folded into one entry.
    assert_eq!(log.actions.len(), DENIED_TARGETS + COALESCE_AFTER + 1);
    let folded: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Coalesced)
        .collect();
    assert_eq!(folded.len(), 1);
    assert_eq!(field(folded[0], "under"), Some(&json!("*")));
    assert_eq!(field(folded[0], "of"), Some(&json!("connect")));
    assert_eq!(field(folded[0], "count"), Some(&json!(30)));
    // Another kind has its own targets.
    deny(&probe, ActionKind::Exec, "program", "timedatectl");
    assert_eq!(
        hub.action_log().actions.len(),
        DENIED_TARGETS + COALESCE_AFTER + 2
    );
}

#[test]
fn one_checks_flood_of_denials_does_not_evict_another_checks_entries() {
    let hub = hub(Replay::new()).with_limits(40, 1000);
    let quiet = hub.check_probe("host.quiet", Os::Linux, None);
    let noisy = hub.check_probe("net.noisy", Os::Linux, None);
    for _ in 0..5 {
        put(&quiet, ActionKind::Exec, ActionOutcome::Ok);
        put(&quiet, ActionKind::Connect, ActionOutcome::Ok);
    }
    for i in 0..90 {
        deny(
            &noisy,
            ActionKind::Connect,
            "host",
            &format!("h{i}.acme.example"),
        );
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 40, "the log cap holds");
    let kept = |check: &str, kind: &str| {
        log.actions
            .iter()
            .filter(|a| a.check.as_deref() == Some(check) && a.kind.as_str() == kind)
            .count()
    };
    assert_eq!(kept("host.quiet", "exec"), 5);
    assert_eq!(kept("host.quiet", "connect"), 5);
    // The flood was dropped, counted and warned about, and the first denials are still there.
    assert_eq!(kept("net.noisy", "connect"), 30);
    assert_eq!(log.last_resort_drops, 60);
}

#[test]
fn the_whole_log_cap_holds_across_checks_and_still_keeps_a_denied_entry() {
    let hub = hub(Replay::new());
    // Six checks at their quota is 6000 failed reads, more than the 5000 the log may hold.
    for check in 0..6 {
        let probe = hub.check_probe(&format!("host.c{check}"), Os::Linux, None);
        for i in 0..CHECK_QUOTA {
            put_at(
                &probe,
                ActionKind::Stat,
                ActionOutcome::Failed,
                Some(&format!("/c{check}/d{i}/f")),
                "not found",
            );
        }
    }
    assert_eq!(hub.action_log().actions.len(), MAX_ENTRIES);
    let late = hub.check_probe("host.late", Os::Linux, None);
    put_at(
        &late,
        ActionKind::Read,
        ActionOutcome::Denied,
        Some("/etc/shadow"),
        "password and sudo files are never read",
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), MAX_ENTRIES);
    assert_eq!(count_of(&log, "read", ActionOutcome::Denied), 1);
    assert_eq!(log.last_resort_drops, 0);
}

#[test]
fn one_check_cannot_use_more_than_its_quota() {
    let hub = hub(Replay::new()).with_limits(5000, 3);
    let noisy = hub.check_probe("host.noisy", Os::Linux, None);
    let quiet = hub.check_probe("host.quiet", Os::Linux, None);
    for _ in 0..10 {
        put(&noisy, ActionKind::Read, ActionOutcome::Ok);
    }
    put(&quiet, ActionKind::Exec, ActionOutcome::Ok);
    let log = hub.action_log();
    let by = |key: &str| {
        log.actions
            .iter()
            .filter(|a| a.check.as_deref() == Some(key))
            .count()
    };
    assert_eq!(by("host.noisy"), 3);
    assert_eq!(by("host.quiet"), 1);
}

#[test]
fn the_last_resort_drops_other_entries_before_a_denied_one_and_counts_it() {
    let hub = hub(Replay::new()).with_limits(3, 1000);
    let probe = hub.check_probe("fixture.flood", Os::Linux, None);
    for _ in 0..3 {
        put(&probe, ActionKind::Connect, ActionOutcome::Ok);
    }
    // A new spare entry has nothing to displace: it is the one dropped.
    put(&probe, ActionKind::Connect, ActionOutcome::Ok);
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 3);
    assert_eq!(log.dropped.get("connect"), Some(&1));
    assert_eq!(log.last_resort_drops, 1);

    // A denied entry displaces the newest spare one.
    put_at(
        &probe,
        ActionKind::Read,
        ActionOutcome::Denied,
        Some("/etc/shadow"),
        "password and sudo files are never read",
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 3);
    assert_eq!(count_of(&log, "read", ActionOutcome::Denied), 1);
    assert_eq!(count_of(&log, "connect", ActionOutcome::Ok), 2);
    assert_eq!(log.last_resort_drops, 2);
}

#[test]
fn a_denied_entry_at_log_scope_evicts_another_checks_ok_and_failed_file_entries() {
    let hub = hub(Replay::new()).with_limits(5, 1000);
    let other = hub.check_probe("host.other", Os::Linux, None);
    let noisy = hub.check_probe("net.noisy", Os::Linux, None);
    for i in 0..3 {
        put_at(
            &other,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/etc/a{i}")),
            "",
        );
    }
    for i in 0..2 {
        put_at(
            &other,
            ActionKind::Stat,
            ActionOutcome::Failed,
            Some(&format!("/opt/d{i}/f")),
            "not found",
        );
    }
    assert_eq!(hub.action_log().actions.len(), 5);
    // Four denials: the three ok entries go first, then one failed entry.
    for i in 0..4 {
        deny(
            &noisy,
            ActionKind::Connect,
            "host",
            &format!("h{i}.acme.example"),
        );
    }
    let log = hub.action_log();
    let of = |check: &str, kind: &str, outcome: ActionOutcome| {
        log.actions
            .iter()
            .filter(|a| {
                a.check.as_deref() == Some(check) && a.kind.as_str() == kind && a.outcome == outcome
            })
            .count()
    };
    assert_eq!(log.actions.len(), 5, "the log cap holds");
    assert_eq!(of("net.noisy", "connect", ActionOutcome::Denied), 4);
    assert_eq!(of("host.other", "read", ActionOutcome::Ok), 0);
    assert_eq!(of("host.other", "stat", ActionOutcome::Failed), 1);
    assert_eq!(log.dropped.get("read"), Some(&3));
    assert_eq!(log.dropped.get("stat"), Some(&1));
    // Evicting file entries is the rule, not the last resort.
    assert_eq!(log.last_resort_drops, 0);
}

#[test]
fn a_denied_entry_at_log_scope_evicts_only_its_own_checks_spare_entry() {
    let hub = hub(Replay::new()).with_limits(4, 1000);
    let own = hub.check_probe("net.own", Os::Linux, None);
    let neighbour = hub.check_probe("net.neighbour", Os::Linux, None);
    let bare = hub.check_probe("net.bare", Os::Linux, None);
    // The neighbour's entries are the newest, so a rule that took the newest spare entry of any check
    // would take one of them.
    for _ in 0..2 {
        put(&own, ActionKind::Connect, ActionOutcome::Ok);
    }
    for _ in 0..2 {
        put(&neighbour, ActionKind::Connect, ActionOutcome::Ok);
    }
    assert_eq!(hub.action_log().actions.len(), 4);

    // No file entry anywhere: the check gives up its own newest connect entry.
    deny(&own, ActionKind::Exec, "program", "timedatectl");
    let log = hub.action_log();
    let held = |check: &str, kind: &str| {
        log.actions
            .iter()
            .filter(|a| a.check.as_deref() == Some(check) && a.kind.as_str() == kind)
            .count()
    };
    assert_eq!(held("net.own", "connect"), 1);
    assert_eq!(held("net.own", "exec"), 1);
    assert_eq!(
        held("net.neighbour", "connect"),
        2,
        "the neighbour keeps both"
    );
    assert_eq!(log.last_resort_drops, 1);

    // A check with no spare entry of its own has nothing to give up: its denial is the one dropped.
    deny(&bare, ActionKind::Exec, "program", "timedatectl");
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 4);
    assert_eq!(held_by(&log, "net.bare"), 0);
    assert_eq!(held_by(&log, "net.neighbour"), 2);
    assert_eq!(held_by(&log, "net.own"), 2);
    assert_eq!(log.dropped.get("exec"), Some(&1));
    assert_eq!(log.last_resort_drops, 2);
}

fn held_by(log: &ActionLogOutput, check: &str) -> usize {
    log.actions
        .iter()
        .filter(|a| a.check.as_deref() == Some(check))
        .count()
}

#[test]
fn the_denied_key_budget_is_two_thousand_and_a_new_key_past_it_is_written_unfolded() {
    let hub = hub(Replay::new());
    // 20 checks with 100 targets each are 2000 distinct keys.
    let probes: Vec<Probe> = (0..21)
        .map(|n| hub.check_probe(&format!("net.c{n}"), Os::Linux, None))
        .collect();
    for probe in &probes[..20] {
        for i in 0..DENIED_TARGETS {
            deny(
                probe,
                ActionKind::Connect,
                "host",
                &format!("h{i}.acme.example"),
            );
        }
    }
    assert_eq!(hub.action_log().actions.len(), 2000);

    // The 2001st key is past the budget: 30 calls are 30 entries, none folded.
    for _ in 0..30 {
        deny(&probes[20], ActionKind::Connect, "host", "new.acme.example");
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 2030);
    assert_eq!(count_of(&log, "coalesced", ActionOutcome::Denied), 0);

    // The first and the 2000th key are tracked and still fold: 1 call held, 19 more written, 10 folded.
    for (probe, host) in [
        (&probes[0], "h0.acme.example"),
        (&probes[19], "h99.acme.example"),
    ] {
        for _ in 0..29 {
            deny(probe, ActionKind::Connect, "host", host);
        }
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 2030 + 2 * (19 + 1));
    let folded: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Coalesced)
        .collect();
    assert_eq!(folded.len(), 2);
    for entry in folded {
        assert_eq!(field(entry, "count"), Some(&json!(10)));
    }
    assert_eq!(log.last_resort_drops, 0);
    assert!(!log.truncated);
}

#[test]
fn ok_reads_past_two_hundred_per_directory_fold_into_one_ok_entry() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    for i in 0..COALESCE_OK_AFTER + 50 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/sys/class/net/eth0/f{i}")),
            "",
        );
    }
    // Another directory has its own count.
    put_at(
        &probe,
        ActionKind::Read,
        ActionOutcome::Ok,
        Some("/sys/class/net/eth1/f"),
        "",
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), COALESCE_OK_AFTER + 1 + 1);
    assert!(!log.truncated, "folding is not dropping");
    let folded = log
        .actions
        .iter()
        .find(|a| a.kind == ActionKind::Coalesced)
        .expect("a coalesced entry");
    assert_eq!(folded.outcome, ActionOutcome::Ok);
    assert_eq!(field(folded, "of"), Some(&json!("read")));
    assert_eq!(field(folded, "under"), Some(&json!("/sys/class/net/eth0")));
    assert_eq!(field(folded, "count"), Some(&json!(50)));
    assert_eq!(field(folded, "rule"), None);
    assert_eq!(field(folded, "error"), None);
}

#[test]
fn ok_reads_fold_per_directory_on_windows_paths_too() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    for dir in ["C:\\Windows\\System32", "C:\\Windows\\Logs"] {
        for i in 0..COALESCE_OK_AFTER + 10 {
            put_at(
                &probe,
                ActionKind::Read,
                ActionOutcome::Ok,
                Some(&format!("{dir}\\f{i}")),
                "",
            );
        }
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 2 * (COALESCE_OK_AFTER + 1));
    let unders: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Coalesced)
        .map(|a| (field(a, "under").cloned(), field(a, "count").cloned()))
        .collect();
    assert_eq!(
        unders,
        vec![
            (Some(json!("C:\\Windows\\System32")), Some(json!(10))),
            (Some(json!("C:\\Windows\\Logs")), Some(json!(10))),
        ]
    );
}

#[test]
fn a_backslash_in_a_unix_name_does_not_split_the_directory() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    // Each name has a backslash in it. Split there, every call would be a directory of its own.
    for i in 0..COALESCE_OK_AFTER + 10 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/opt/d/x{i}\\f")),
            "",
        );
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), COALESCE_OK_AFTER + 1);
    let folded = log
        .actions
        .iter()
        .find(|a| a.kind == ActionKind::Coalesced)
        .expect("a coalesced entry");
    assert_eq!(field(folded, "under"), Some(&json!("/opt/d")));
    assert_eq!(field(folded, "count"), Some(&json!(10)));
}

#[test]
fn a_denied_read_in_a_folded_directory_is_its_own_entry() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    for i in 0..COALESCE_OK_AFTER + 20 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/etc/f{i}")),
            "",
        );
    }
    put_at(
        &probe,
        ActionKind::Read,
        ActionOutcome::Denied,
        Some("/etc/shadow"),
        "password and sudo files are never read",
    );
    let log = hub.action_log();
    assert_eq!(count_of(&log, "read", ActionOutcome::Denied), 1);
    assert_eq!(count_of(&log, "coalesced", ActionOutcome::Ok), 1);
    assert_eq!(count_of(&log, "coalesced", ActionOutcome::Denied), 0);
    assert!(!log.truncated);
}

#[test]
fn the_ok_key_budget_is_twenty_thousand_and_does_not_use_up_the_failed_keys() {
    let hub = hub(Replay::new()).with_limits(100_000, 100_000);
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    // 20 000 directories are 20 000 ok keys.
    for i in 0..20_000 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/d{i}/f")),
            "",
        );
    }
    // The budget of failed keys is untouched: a failed flood still folds.
    for i in 0..COALESCE_AFTER + 5 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Failed,
            Some(&format!("/gone/f{i}")),
            "not found",
        );
    }
    // A new ok key is past the budget and is written unfolded.
    for i in 0..COALESCE_OK_AFTER + 10 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/new/f{i}")),
            "",
        );
    }
    // A key already tracked still folds: 1 held, 199 more written, 11 folded.
    for i in 0..COALESCE_OK_AFTER + 10 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/d0/g{i}")),
            "",
        );
    }
    let log = hub.action_log();
    let folded: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Coalesced)
        .map(|a| (a.outcome.clone(), field(a, "under").cloned()))
        .collect();
    assert_eq!(
        folded,
        vec![
            (ActionOutcome::Failed, Some(json!("/gone"))),
            (ActionOutcome::Ok, Some(json!("/d0"))),
        ]
    );
    let new_dir = log
        .actions
        .iter()
        .filter(|a| {
            field(a, "path").is_some_and(|p| p.as_str().is_some_and(|p| p.starts_with("/new/")))
        })
        .count();
    assert_eq!(new_dir, COALESCE_OK_AFTER + 10);
    assert!(!log.truncated);
}

#[test]
fn ok_and_failed_file_calls_fold_under_their_own_keys() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    // The same directory and kind, two outcomes: two keys, each with its own limit (20 and 200).
    for i in 0..COALESCE_AFTER + 5 {
        put_at(
            &probe,
            ActionKind::Stat,
            ActionOutcome::Failed,
            Some(&format!("/opt/d/f{i}")),
            "not found",
        );
    }
    for i in 0..COALESCE_OK_AFTER + 5 {
        put_at(
            &probe,
            ActionKind::Stat,
            ActionOutcome::Ok,
            Some(&format!("/opt/d/g{i}")),
            "",
        );
    }
    let log = hub.action_log();
    let folded: Vec<_> = log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Coalesced)
        .map(|a| (a.outcome.clone(), field(a, "count").cloned()))
        .collect();
    assert_eq!(
        folded,
        vec![
            (ActionOutcome::Failed, Some(json!(5))),
            (ActionOutcome::Ok, Some(json!(5))),
        ]
    );
}

#[test]
fn a_folded_ok_entry_is_dropped_with_the_ok_reads_and_before_anything_else() {
    let hub = hub(Replay::new()).with_limits(COALESCE_OK_AFTER + 2, 1000);
    let probe = hub.check_probe("host.walker", Os::Linux, None);
    for i in 0..COALESCE_OK_AFTER + 5 {
        put_at(
            &probe,
            ActionKind::Read,
            ActionOutcome::Ok,
            Some(&format!("/proc/sys/f{i}")),
            "",
        );
    }
    put(&probe, ActionKind::Exec, ActionOutcome::Ok);
    // Full: 200 ok reads, one folded entry and the exec. A failed read pushes out the newest ok one.
    put_at(
        &probe,
        ActionKind::Stat,
        ActionOutcome::Failed,
        Some("/x/y"),
        "not found",
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), COALESCE_OK_AFTER + 2);
    assert_eq!(count_of(&log, "exec", ActionOutcome::Ok), 1);
    assert_eq!(count_of(&log, "stat", ActionOutcome::Failed), 1);
    assert_eq!(count_of(&log, "coalesced", ActionOutcome::Ok), 0);
    // The folded entry stood for 5 reads, so 5 reads are counted as dropped, and none as `coalesced`.
    assert_eq!(log.dropped.get("read"), Some(&5));
    assert_eq!(log.dropped.get("coalesced"), None);
    assert_eq!(log.last_resort_drops, 0);
}

// ---- the fixture run, through the scheduler -------------------------------------------------------

#[cfg(all(feature = "runtime", unix))]
mod scheduled {
    use std::sync::Mutex;

    use rdy_spec::result::Report;

    use super::*;
    use crate::check::{Check, CheckContext, CheckInfo, CheckOutcome, Finding};
    use crate::check::{CheckMeta, CommandSpec, Need, Os, OsSupport, Support};
    use crate::sched::{End, Planned, Scheduler};

    static WALKER: CheckInfo = CheckInfo {
        id: "fixture.walker",
        family: "fixture",
        summary: "Reads, runs, connects and calls the cluster, then leaks its probe.",
        meta: CheckMeta {
            title: "Fixture walker",
            remediation: "Nothing to fix. This check is a test double.",
        },
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OsSupport {
            linux: Support::Full,
            macos: Support::Full,
            windows: Support::Full,
        },
        reads: &["/proc", "/home/tester"],
        env: &[],
        commands: &[CommandSpec {
            program: "getent",
            extra_dirs: &[],
            max_stdout: 4096,
            env: &[],
        }],
        peers: &[],
    };

    /// A check that does every kind of side effect and keeps a clone of its probe.
    struct Walker {
        leaked: Arc<Mutex<Option<Probe>>>,
    }

    impl Check for Walker {
        fn info(&self) -> &'static CheckInfo {
            &WALKER
        }

        fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
            Box::pin(async move {
                let probe = ctx.probe();
                *self.leaked.lock().expect("lock") = Some(probe.clone());

                probe.read(Path::new("/proc/cpuinfo")).await?;
                let refused = probe.read(Path::new("/proc/1/environ")).await;
                assert!(matches!(refused, Err(ProbeError::Denied { .. })));
                let refused = probe.read(Path::new("/home/tester/.ssh/id_rsa")).await;
                assert!(
                    matches!(&refused, Err(ProbeError::Denied { what, .. }) if what == "~/.ssh/id_rsa"),
                    "{refused:?}"
                );
                probe.exec(getent("registry.acme.example")).await?;

                // The network and kube tickets open their entries through the same door. Until
                // their methods exist (M1-091, M1-103), the rows are written by hand here, and those
                // tickets inherit "every tcp, http and kube call writes exactly one entry".
                let (_, mut connect) =
                    probe.begin(ActionKind::Connect, Map::new(), "registry.acme.example")?;
                connect.set("host", "registry.acme.example");
                connect.set("port", 443);
                connect.set("addr", Value::Null);
                connect.set("via_proxy", Value::Null);
                connect.finish(ActionOutcome::Ok);
                let (_, mut kube) = probe.begin(ActionKind::Kube, Map::new(), "/version")?;
                kube.set("method", "GET");
                kube.set("path", "/version?access_token=s3cr3t-value-123");
                kube.set("status", 200);
                kube.finish(ActionOutcome::Ok);

                Ok(Finding::pass("walked"))
            })
        }
    }

    /// The report of 01 section 7.2, as a fixture. The run puts its own action log into it.
    fn sample_report() -> Report {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/reports/not-ready-7.2.json");
        let text = std::fs::read_to_string(path).expect("the fixture is in the repo");
        serde_json::from_str(&text).expect("the sample is a report")
    }

    /// The result schema, as the generator wrote it.
    fn assert_matches_result_schema(report: &Value) {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
        let schema: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("schema file"))
                .expect("schema json");
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(report)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "the report fails the schema: {errors:#?}"
        );
    }

    #[tokio::test]
    async fn the_fixture_run_lists_every_side_effect_in_the_json_report() {
        let leaked = Arc::new(Mutex::new(None));
        let replay = Replay::new()
            .file("/proc/cpuinfo", "processor : 0\n")
            // The fixture has these files. Only the denylist stands between the check and them.
            .file("/proc/1/environ", "TOKEN=abc")
            .file("/home/tester/.ssh/id_rsa", "KEY")
            .command(
                "getent",
                &getent_args("registry.acme.example"),
                0,
                "10.0.0.7 STREAM\n",
            );
        let hub = hub(replay).with_home("/home/tester");

        // Run-level work: the engine reads the kubeconfig itself and logs it with `check: null`.
        // The real read goes through the run probe once M1-102 settles the path: the denylist
        // refuses `.kube` for every probe, so the engine's own kubeconfig read needs an exception.
        let run = hub.run_probe();
        let (_, mut kubeconfig) = run
            .begin(ActionKind::Read, Map::new(), "~/.kube/config")
            .expect("run probe");
        kubeconfig.set("path", "~/.kube/config");
        kubeconfig.set("bytes", 5412);
        kubeconfig.set("truncated", false);
        kubeconfig.finish(ActionOutcome::Ok);

        let scheduler = Scheduler::new(2, Os::Linux, [Need::Network]).with_probes(hub.clone());
        let walker = Walker {
            leaked: Arc::clone(&leaked),
        };
        let ran = scheduler
            .run(vec![Planned::new(Arc::new(walker), "host.cpu")])
            .await;
        assert!(
            matches!(&ran[0].end, End::Done(outcome) if outcome.is_ok()),
            "{:?}",
            ran[0].end
        );

        // The check is over. A call from a clone of its probe is denied and logged.
        let straggler = leaked.lock().expect("lock").take().expect("leaked probe");
        let late = straggler.read(Path::new("/proc/cpuinfo")).await;
        assert!(matches!(
            late,
            Err(ProbeError::Denied {
                rule: RULE_CHECK_FINISHED,
                ..
            })
        ));

        // The report is the 7.2 sample with the fixture run's log put in.
        let mut report = sample_report();
        assert_eq!(report.redaction.total, 0);
        hub.action_log().apply(&mut report);
        let json = serde_json::to_value(&report).expect("report");
        let text = serde_json::to_string(&json).expect("text");
        assert_matches_result_schema(&json);

        let actions = json["actions"].as_array().expect("actions");
        let seen: Vec<(Option<&str>, &str, &str)> = actions
            .iter()
            .map(|a| {
                (
                    a["check"].as_str(),
                    a["kind"].as_str().expect("kind"),
                    a["outcome"].as_str().expect("outcome"),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (None, "read", "ok"),
                (Some("host.cpu"), "read", "ok"),
                (Some("host.cpu"), "read", "denied"),
                (Some("host.cpu"), "read", "denied"),
                (Some("host.cpu"), "exec", "ok"),
                (Some("host.cpu"), "connect", "ok"),
                (Some("host.cpu"), "kube", "ok"),
                (Some("host.cpu"), "read", "denied"),
            ]
        );
        // seq runs from 1 and the entries sit in seq order.
        let seqs: Vec<u64> = actions.iter().filter_map(|a| a["seq"].as_u64()).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5, 6, 7, 8]);

        // A file, and the refused reads with their rules. The home directory shows as `~`.
        assert_eq!(actions[1]["path"], "/proc/cpuinfo");
        assert_eq!(actions[2]["path"], "/proc/1/environ");
        assert_eq!(actions[2]["rule"], policy::RULE_PROC);
        assert!(actions[2].get("bytes").is_none());
        assert_eq!(actions[3]["path"], "~/.ssh/id_rsa");
        assert_eq!(actions[3]["rule"], policy::RULE_SSH);
        assert!(
            !text.contains("/home/tester"),
            "a home path reached the report"
        );
        // A command: the program, the table form and the argv.
        assert_eq!(actions[4]["program"], "getent");
        assert_eq!(actions[4]["form"], "ahosts");
        assert_eq!(
            actions[4]["argv"],
            json!(["ahosts", "--", "registry.acme.example"])
        );
        assert!(
            !text.contains("s3cr3t-value"),
            "a secret reached the report"
        );
        // An endpoint and a kube request.
        assert_eq!(actions[5]["host"], "registry.acme.example");
        assert_eq!(actions[5]["port"], 443);
        assert!(
            actions[6]["path"]
                .as_str()
                .is_some_and(|p| p.starts_with("/version?access_token=[REDACTED:")),
            "{}",
            actions[6]["path"]
        );
        // The late call names the check and the rule.
        assert_eq!(actions[7]["rule"], RULE_CHECK_FINISHED);

        // The redaction count includes what the log redacted.
        assert_eq!(json["redaction"]["total"], 1);
        assert_eq!(json["redaction"]["by_rule"]["secret_by_key"], 1);
        assert_eq!(json["actions_truncated"], false);

        // It is still a report.
        let again: Report = serde_json::from_value(json).expect("round trip");
        assert_eq!(again.actions.len(), 8);
        assert_eq!(hub.action_log().actions.len(), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn the_scheduler_ends_the_probe_when_the_check_times_out() {
        /// Hands its probe out, then waits forever.
        struct Sleeper {
            leaked: Arc<Mutex<Option<Probe>>>,
        }
        impl Check for Sleeper {
            fn info(&self) -> &'static CheckInfo {
                &WALKER
            }
            fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
                Box::pin(async move {
                    *self.leaked.lock().expect("lock") = Some(ctx.probe().clone());
                    std::future::pending::<CheckOutcome>().await
                })
            }
        }
        let leaked = Arc::new(Mutex::new(None));
        let hub = hub(Replay::new().file("/proc/cpuinfo", "x"));
        let scheduler = Scheduler::new(1, Os::Linux, []).with_probes(hub.clone());
        let planned = Planned::new(
            Arc::new(Sleeper {
                leaked: Arc::clone(&leaked),
            }),
            "fixture.walker",
        )
        .with_timeout(Duration::from_secs(1));
        let ran = scheduler.run(vec![planned]).await;
        assert!(matches!(ran[0].end, End::TimedOut { .. }));

        let probe = leaked.lock().expect("lock").take().expect("leaked");
        let error = probe
            .stat(Path::new("/proc/cpuinfo"))
            .await
            .expect_err("ended");
        assert!(matches!(
            error,
            ProbeError::Denied {
                rule: RULE_CHECK_FINISHED,
                ..
            }
        ));
    }
}

#[test]
fn the_log_survives_a_poisoned_lock() {
    let hub = hub(Replay::new());
    let probe = hub.check_probe("fixture.walker", Os::Linux, None);
    hub.log.poison();
    put(&probe, ActionKind::Exec, ActionOutcome::Ok);
    assert_eq!(hub.action_log().actions.len(), 1);
}
