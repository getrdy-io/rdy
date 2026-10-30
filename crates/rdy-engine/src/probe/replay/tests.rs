//! Tests for the replay backend and the fixture loader (M1-049).
//!
//! Nothing here is Unix-only unless a test says so: the fixtures load and replay on the Windows leg too.
//! The fixtures under `tests/fixtures/checks/` are real files, so the exit tests also prove that a
//! default Windows checkout (`core.autocrlf true`) leaves them loadable.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rdy_spec::result::{ActionKind, ActionOutcome};
use tempfile::TempDir;

use super::*;
use crate::check::{CheckInfo, CheckMeta, Need, OsSupport, Support};
use crate::exec::policy::{Cmd, PolicyError};
use crate::exec::table;
use crate::probe::policy::{
    RULE_NOT_DIR, RULE_NOT_REGULAR, RULE_OUTSIDE_READS, RULE_SYSTEM_SECRET,
};
use crate::probe::{Resource, RlimitInfo, StatvfsInfo};
use crate::testing::{TestRun, fixtures_dir, matches_placeholders};

const META: CheckMeta = CheckMeta {
    title: "Fixture check",
    remediation: "Nothing to fix. This check is a test double.",
};

const OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::NotYet,
};

const fn reader(id: &'static str, reads: &'static [&'static str]) -> CheckInfo {
    CheckInfo {
        id,
        family: "host",
        summary: "Reads files.",
        meta: META,
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OS,
        reads,
        statfs: reads,
        env: &[],
        commands: &[],
        peers: &[],
    }
}

static MEMORY: CheckInfo = reader("host.memory", &["/proc"]);
static ACME: CheckInfo = reader("host.fixture", &["/etc/acme"]);
static ENTRIES: CheckInfo = reader(
    "host.fixture",
    &["/proc", "/etc", "/usr/lib", "/var/log", "/var/lib"],
);

fn guard() -> ReadGuard {
    ReadGuard::new(Os::Linux, None)
}

fn manifest_text(os: &str, top: &str) -> String {
    format!(
        "schema = 1\nname = \"x\"\nsummary = \"A test machine\"\norigin = \"hand\"\nos = \"{os}\"\n\
         arch = \"x86_64\"\nanswers = [\"host.memory\"]\n{top}\n\
         [caps]\nroot = true\nnetwork = true\nkube = false\n"
    )
}

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().expect("a parent")).expect("create dirs");
    fs::write(path, content).expect("write");
}

/// Writes `files` below `envs/<name>` and adds a manifest unless one is given.
fn put(root: &Path, name: &str, os: &str, top: &str, files: &[(&str, &str)]) {
    let dir = format!("envs/{name}");
    if !files.iter().any(|(rel, _)| *rel == "fixture.toml") {
        write(
            root,
            &format!("{dir}/fixture.toml"),
            &manifest_text(os, top),
        );
    }
    for (rel, content) in files {
        write(root, &format!("{dir}/{rel}"), content);
    }
}

fn load_os(os: &str, files: &[(&str, &str)]) -> Result<Fixture, FixtureError> {
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "x", os, "", files);
    Fixture::load(dir.path(), "envs/x")
}

fn load(files: &[(&str, &str)]) -> Result<Fixture, FixtureError> {
    load_os("linux", files)
}

fn load_pair(
    base: &[(&str, &str)],
    top: &str,
    child: &[(&str, &str)],
) -> Result<Fixture, FixtureError> {
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "base", "linux", "", base);
    put(dir.path(), "x", "linux", top, child);
    Fixture::load(dir.path(), "envs/x")
}

fn invalid_path(error: &FixtureError) -> &str {
    match error {
        FixtureError::Invalid { path, .. } | FixtureError::Read { path, .. } => path,
        other => panic!("expected an invalid or unreadable file, got {other:?}"),
    }
}

/// Fixture files, the file the error must name, and a phrase the error must hold.
type FileCase<'a> = (&'a [(&'a str, &'a str)], &'a str, &'a str);

fn getent(host: &str) -> Cmd {
    table::entry("getent")
        .expect("getent is in the table")
        .cmd_for(Os::Linux, "ahosts", &[host])
        .expect("a valid name")
}

fn rule_of(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---- the exit tests ----------------------------------------------------------------------------

#[tokio::test]
async fn a_host_memory_fixture_runs_with_no_real_file_read() {
    let fixture =
        Fixture::load(&fixtures_dir(), "checks/host.memory/pass").expect("the fixture loads");
    fixture.ensure_answers("host.memory").expect("answers it");
    assert!(matches!(
        fixture.ensure_answers("host.os"),
        Err(FixtureError::DoesNotAnswer { .. })
    ));
    assert_eq!(fixture.manifest().origin, Origin::Hand);

    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(
        &MEMORY,
        "host.memory",
        fixture.os(),
        fixture.available_needs(),
    );
    let meminfo = ctx
        .probe()
        .read(Path::new("/proc/meminfo"))
        .await
        .expect("the fixture has it");
    let text = String::from_utf8(meminfo.bytes).expect("utf8");
    assert!(text.starts_with("MemTotal:       32820428 kB\n"), "{text}");
    // Linux has /proc/version and /proc/cpuinfo. The fixture does not, so a read that fell through to
    // the machine running the test would succeed.
    for path in ["/proc/version", "/proc/cpuinfo", "/proc/self/status"] {
        assert_eq!(
            ctx.probe().read(Path::new(path)).await,
            Err(ProbeError::NotFound),
            "{path}"
        );
    }
    let log = run.action_log();
    assert_eq!(log.actions.len(), 4);
    assert_eq!(log.actions[0].kind, ActionKind::Read);
    assert_eq!(log.actions[0].outcome, ActionOutcome::Ok);
    assert!(
        log.actions[1..]
            .iter()
            .all(|a| a.outcome == ActionOutcome::Failed)
    );
}

#[tokio::test]
async fn an_unrecorded_argv_fails_with_not_recorded() {
    let fixture = load(&[(
        "commands/getent.json",
        r#"{"argv":["/usr/bin/getent","ahosts","--","registry.acme.example"],
            "stdout":"192.0.2.10 STREAM registry.acme.example\n","exit":0}"#,
    )])
    .expect("loads");
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context("net.dns", Os::Linux, []);

    let done = ctx
        .probe()
        .exec(getent("registry.acme.example"))
        .await
        .expect("recorded");
    assert_eq!(done.exit, Some(0));
    assert_eq!(done.stdout, b"192.0.2.10 STREAM registry.acme.example\n");

    let error = ctx
        .probe()
        .exec(getent("other.acme.example"))
        .await
        .expect_err("not recorded");
    assert!(
        matches!(&error, ProbeError::NotRecorded(what) if what.contains("getent ahosts -- other.acme.example")),
        "{error:?}"
    );
    assert!(error.to_string().contains("Fix:"), "{error}");
    let log = run.action_log();
    assert_eq!(log.actions.len(), 2);
    assert_eq!(log.actions[1].outcome, ActionOutcome::Failed);
    // The table still comes first: a shell never reaches the fixture.
    assert!(matches!(
        ctx.probe()
            .exec(Cmd::new("sh", Duration::from_secs(1)).args(["-c", "id"]))
            .await,
        Err(ProbeError::Table(_) | ProbeError::Policy(_))
    ));
}

#[test]
fn a_link_local_answer_loads_so_the_address_rule_can_run_in_every_net_fixture() {
    // The loader records the forbidden answer as it is. The facade's address rule refuses it when a
    // check looks the name up (`Probe::lookup`, M1-094, in `probe/net/lookup/tests.rs`).
    let fixture = load(&[(
        "net.json",
        r#"{"dns": {"Metadata.acme.example": ["169.254.169.254", "fd00:ec2::254"],
                    "gone.acme.example": "NXDOMAIN"},
            "tcp": {"192.0.2.10:443": {"serve": "tls-private-ca"},
                    "192.0.2.11:443": "refused",
                    "192.0.2.12:443": "blackhole",
                    "[2001:db8::13]:443": "reset"}}"#,
    )])
    .expect("loads");
    let replay = fixture.replay();
    let net = replay.net();
    // Keys are lower case, and the compare ignores case.
    assert_eq!(
        replay.dns("METADATA.acme.example"),
        Some(&DnsAnswer::Addrs(vec![
            "169.254.169.254".parse().expect("ip"),
            "fd00:ec2::254".parse().expect("ip"),
        ]))
    );
    assert_eq!(replay.dns("gone.acme.example"), Some(&DnsAnswer::NxDomain));
    assert_eq!(replay.dns("unknown.acme.example"), None);
    assert_eq!(
        net.tcp("192.0.2.10:443".parse().expect("addr")),
        Some(&TcpScript::Serve("tls-private-ca".to_owned()))
    );
}

#[tokio::test]
async fn a_manifest_symlink_to_etc_shadow_is_denied() {
    let fixture = Fixture::load(&fixtures_dir(), "checks/_policy/symlink-to-shadow")
        .expect("the fixture loads");
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(&ACME, "host.fixture", Os::Linux, []);

    // The name passes the denylist and the check's `reads`. The real path does not.
    let error = ctx
        .probe()
        .read(Path::new("/etc/acme/license.link"))
        .await
        .expect_err("denied");
    assert_eq!(rule_of(&error), RULE_SYSTEM_SECRET, "{error:?}");
    let error = ctx
        .probe()
        .stat(Path::new("/etc/acme/license.link"))
        .await
        .expect_err("denied");
    assert_eq!(rule_of(&error), RULE_SYSTEM_SECRET, "{error:?}");
    let log = run.action_log();
    assert_eq!(log.actions[0].outcome, ActionOutcome::Denied);
    assert_eq!(
        log.actions[0].fields.get("rule").and_then(|r| r.as_str()),
        Some(RULE_SYSTEM_SECRET)
    );

    // The file next to it reads fine, so the refusal is the link's.
    let conf = ctx.probe().read(Path::new("/etc/acme/app.conf")).await;
    assert!(conf.is_ok(), "{conf:?}");
}

#[tokio::test]
async fn a_link_out_of_the_declared_reads_is_denied_too() {
    // /etc/os-release is a link to /usr/lib/os-release: a check that declares only /etc is refused,
    // which is why check-author declares both.
    let fixture = Fixture::load(&fixtures_dir(), "checks/_loader/manifest-entries")
        .expect("the fixture loads");
    let run = TestRun::for_fixture(&fixture);
    static ETC_ONLY: CheckInfo = reader("host.fixture", &["/etc"]);
    let narrow = run.context_for(&ETC_ONLY, "host.fixture", Os::Linux, []);
    let error = narrow
        .probe()
        .read(Path::new("/etc/os-release"))
        .await
        .expect_err("denied");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_READS, "{error:?}");

    let wide = run.context_for(&ENTRIES, "host.fixture", Os::Linux, []);
    let file = wide
        .probe()
        .read(Path::new("/etc/os-release"))
        .await
        .expect("both declared");
    assert_eq!(file.bytes, b"ID=rhel\nVERSION_ID=\"9.4\"\n");
}

#[tokio::test]
async fn the_manifest_entries_fixture_loads_and_replays_on_every_runner() {
    let fixture = Fixture::load(&fixtures_dir(), "checks/_loader/manifest-entries")
        .expect("the fixture loads");
    let replay = fixture.replay();
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(&ENTRIES, "host.fixture", Os::Linux, []);

    // An unreadable audit log is there, and a user without the right cannot read it.
    let log = Path::new("/var/log/audit/audit.log");
    assert_eq!(
        ctx.probe().read(log).await,
        Err(ProbeError::PermissionDenied)
    );
    assert!(
        ctx.probe()
            .stat(log)
            .await
            .expect("stat works")
            .is_some_and(|meta| meta.is_file)
    );

    // The /proc/<pid>/fd link shows a socket: not a file and not a directory.
    let fd = Path::new("/proc/1234/fd/7");
    let meta = replay
        .stat(fd, &guard())
        .await
        .expect("stat")
        .expect("there");
    assert!(!meta.is_file && !meta.is_dir);
    let error = replay
        .open_read(fd, ReadRange::Head(16), &guard())
        .await
        .expect_err("not a regular file");
    assert_eq!(
        Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_NOT_REGULAR)
    );
    let error = replay.read_dir(fd, &guard()).await.expect_err("not a dir");
    assert_eq!(Refused::from_io(&error).map(|r| r.rule), Some(RULE_NOT_DIR));

    // Directories exist because the files under them do, or because the manifest lists them.
    let names = |entries: Vec<DirEntry>| -> Vec<(String, bool)> {
        entries.into_iter().map(|e| (e.name, e.is_dir)).collect()
    };
    assert_eq!(
        names(
            replay
                .read_dir(Path::new("/proc/1234"), &guard())
                .await
                .expect("dir")
        ),
        [("comm".to_owned(), false), ("fd".to_owned(), true)]
    );
    assert_eq!(
        names(
            replay
                .read_dir(Path::new("/proc/1234/fd"), &guard())
                .await
                .expect("dir")
        ),
        [("7".to_owned(), false)]
    );
    assert!(
        replay
            .read_dir(Path::new("/var/lib/acme"), &guard())
            .await
            .expect("an empty directory")
            .is_empty()
    );
    // A file is not a directory and a directory is not a file.
    let error = replay
        .read_dir(Path::new("/proc/1234/comm"), &guard())
        .await
        .expect_err("a file");
    assert_eq!(Refused::from_io(&error).map(|r| r.rule), Some(RULE_NOT_DIR));
    let error = replay
        .open_read(Path::new("/proc/1234"), ReadRange::Head(16), &guard())
        .await
        .expect_err("a directory");
    assert_eq!(
        Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_NOT_REGULAR)
    );

    assert_eq!(replay.mode("/etc/acme/license.dat"), Some(0o640));
    assert_eq!(replay.mode("/etc/acme/other"), None);
}

#[test]
fn placeholders_compare_equal_across_runs() {
    let golden = r#"{"serial":"<serial>","root_sha256":"<sha256>","issuer":"Acme Test CA"}"#;
    let run = |serial: &str, digest: &str| {
        format!(r#"{{"serial":"{serial}","root_sha256":"{digest}","issuer":"Acme Test CA"}}"#)
    };
    let first = run("4f1c9a02", &"ab12".repeat(16));
    let second = run("0000a7e3d19c5b4f2288", &"09fe".repeat(16));
    assert_ne!(first, second);
    assert!(matches_placeholders(golden, &first));
    assert!(matches_placeholders(golden, &second));
    // Anything else still has to match.
    assert!(!matches_placeholders(
        golden,
        &run("4f1c9a02", &"ab12".repeat(16)).replace("Acme Test CA", "Other CA")
    ));
    // A digest has 64 lower case hex digits, no more and no fewer.
    for bad in [
        "ab12".repeat(15),
        "ab12".repeat(17),
        "AB12".repeat(16),
        "zz12".repeat(16),
        String::new(),
    ] {
        assert!(!matches_placeholders("<sha256>", &bad), "{bad}");
    }
    assert!(!matches_placeholders("<serial>", "a"));
    assert!(matches_placeholders(
        "a<serial>-<sha256>",
        &format!("a0F-{}", "0".repeat(64))
    ));
    assert!(matches_placeholders("no placeholder", "no placeholder"));
    assert!(!matches_placeholders("no placeholder", "no placeholders"));
}

// ---- base, remove and answers ------------------------------------------------------------------

#[tokio::test]
async fn a_fixture_with_base_remove_and_answers_loads() {
    let base = [
        ("root/etc/a", "base-a"),
        ("root/etc/b", "base-b"),
        ("root/etc/docker/daemon.json", "{}"),
        ("root/etc/docker/key.json", "{}"),
        ("root/opt/old", "old"),
        (
            "commands/chronyc.json",
            r#"{"argv":["/usr/bin/chronyc","-n","-c","tracking"],"stdout":"base\n"}"#,
        ),
        (
            "env.json",
            r#"{"HTTPS_PROXY":"http://proxy.acme.example:3128"}"#,
        ),
    ];
    let child = [
        ("root/etc/a", "child-a"),
        ("root/etc/c", "child-c"),
        (
            "commands/chronyc.json",
            r#"{"argv":["/usr/bin/chronyc","-n","-c","tracking"],"stdout":"child\n"}"#,
        ),
    ];
    let fixture = load_pair(
        &base,
        "base = \"base\"\nremove = [\"root/etc/docker\", \"root/opt/old\"]",
        &child,
    )
    .expect("loads");
    assert_eq!(fixture.manifest().base.as_deref(), Some("base"));
    assert_eq!(fixture.manifest().remove.len(), 2);
    fixture.ensure_answers("host.memory").expect("listed");

    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context("host.fixture", Os::Linux, []);
    let read = |path: &'static str| {
        let ctx = ctx.clone();
        async move { ctx.probe().read(Path::new(path)).await.map(|f| f.bytes) }
    };
    assert_eq!(
        read("/etc/a").await,
        Ok(b"child-a".to_vec()),
        "child replaces base"
    );
    assert_eq!(read("/etc/b").await, Ok(b"base-b".to_vec()), "base is kept");
    assert_eq!(read("/etc/c").await, Ok(b"child-c".to_vec()), "child adds");
    for removed in [
        "/etc/docker/daemon.json",
        "/etc/docker/key.json",
        "/opt/old",
    ] {
        assert_eq!(read(removed).await, Err(ProbeError::NotFound), "{removed}");
    }
    // The removed directory is gone from its parent's listing.
    let etc: Vec<String> = fixture
        .replay()
        .read_dir(Path::new("/etc"), &guard())
        .await
        .expect("dir")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(etc, ["a", "b", "c"]);

    let done = fixture
        .replay()
        .spawn(Cmd::new("chronyc", Duration::from_secs(5)).args(["-n", "-c", "tracking"]))
        .await
        .expect("recorded");
    assert_eq!(done.stdout, b"child\n", "same path, child wins");
    assert_eq!(
        fixture.replay().env.get("HTTPS_PROXY").map(String::as_str),
        Some("http://proxy.acme.example:3128"),
        "a file only the base has is kept"
    );
}

#[test]
fn base_and_remove_errors_name_the_file() {
    let base = [("root/etc/a", "a")];
    let error = load_pair(&base, "base = \"base\"\nremove = [\"root/etc/zzz\"]", &[])
        .expect_err("nothing to remove");
    assert_eq!(invalid_path(&error), "fixture.toml");
    assert!(error.to_string().contains("root/etc/zzz"), "{error}");

    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "x", "linux", "remove = [\"root/etc/a\"]", &[]);
    let error = Fixture::load(dir.path(), "envs/x").expect_err("no base");
    assert!(error.to_string().contains("needs a `base`"), "{error}");

    // One level only.
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "grand", "linux", "", &[]);
    put(dir.path(), "base", "linux", "base = \"grand\"", &[]);
    put(dir.path(), "x", "linux", "base = \"base\"", &[]);
    let error = Fixture::load(dir.path(), "envs/x").expect_err("two levels");
    assert!(error.to_string().contains("one level"), "{error}");

    // The base is a name under envs/, not a path.
    let error = load_pair(&base, "base = \"../base\"", &[]).expect_err("a path");
    assert_eq!(invalid_path(&error), "fixture.toml");
    let error = load_pair(&base, "base = \"missing\"", &[]).expect_err("no such env");
    assert!(matches!(error, FixtureError::Read { .. }), "{error:?}");

    // A base on another OS is a different machine.
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "base", "windows", "", &[]);
    put(dir.path(), "x", "linux", "base = \"base\"", &[]);
    let error = Fixture::load(dir.path(), "envs/x").expect_err("os differs");
    assert!(error.to_string().contains("`os` differs"), "{error}");
}

#[test]
fn a_duplicate_argv_names_both_files_even_across_base_and_child() {
    let one = r#"{"argv":["/usr/bin/chronyc","tracking"],"stdout":"a"}"#;
    let error = load(&[("commands/a.json", one), ("commands/b.json", one)]).expect_err("dup");
    assert_eq!(
        error,
        FixtureError::Duplicate {
            fixture: "envs/x".to_owned(),
            key: "/usr/bin/chronyc tracking".to_owned(),
            first: "commands/a.json".to_owned(),
            second: "commands/b.json".to_owned(),
        }
    );
    assert!(error.to_string().contains("Fix:"));
    // The same path spelled another way is the same program.
    let spelled = r#"{"argv":["/usr//bin/./chronyc","tracking"],"stdout":"b"}"#;
    assert!(matches!(
        load(&[("commands/a.json", one), ("commands/b.json", spelled)]),
        Err(FixtureError::Duplicate { .. })
    ));
    // Another directory is another program: the live runner finds the first on its search path.
    let other = r#"{"argv":["/bin/chronyc","tracking"],"stdout":"b"}"#;
    assert!(load(&[("commands/a.json", one), ("commands/b.json", other)]).is_ok());
    // A child file with another slug does not replace the base file: both are indexed.
    let error = load_pair(
        &[("commands/a.json", one)],
        "base = \"base\"",
        &[("commands/b.json", one)],
    )
    .expect_err("dup");
    assert!(matches!(error, FixtureError::Duplicate { .. }), "{error:?}");
    // The same slug replaces it.
    assert!(
        load_pair(
            &[("commands/a.json", one)],
            "base = \"base\"",
            &[("commands/a.json", other)]
        )
        .is_ok()
    );
}

// ---- strictness --------------------------------------------------------------------------------

#[test]
fn a_bad_manifest_is_refused_with_the_reason() {
    let cases: [(&str, &str); 9] = [
        ("schema = 2\n", "`schema` must be 1"),
        ("not toml at all [", "fixture.toml"),
        ("schema = 1\nname = \"x\"\n", "`summary` is missing"),
        (
            "schema = 1\nname = \"x\"\nsummary = \"s\"\norigin = \"laptop\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = []\n[caps]\nroot = true\nnetwork = true\nkube = true\n",
            "`origin` is `laptop`",
        ),
        (
            "schema = 1\nname = \"x\"\nsummary = \"s\"\norigin = \"hand\"\nos = \"solaris\"\narch = \"x86_64\"\nanswers = []\n[caps]\nroot = true\nnetwork = true\nkube = true\n",
            "`os` is `solaris`",
        ),
        (
            "schema = 1\nname = \"x\"\nsummary = \"s\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = []\n",
            "`[caps]` is missing",
        ),
        (
            "schema = 1\nname = \"x\"\nsummary = \"s\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = []\nbse = \"x\"\n[caps]\nroot = true\nnetwork = true\nkube = true\n",
            "`bse` is not a key",
        ),
        (
            "schema = 1\nname = \"x\"\nsummary = \"s\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = []\n[caps]\nroot = true\nnetwork = true\nkube = true\nsudo = true\n",
            "`caps.sudo` is not a key",
        ),
        (
            "schema = 1\nname = \"x\"\nsummary = \"s\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = []\n[caps]\nroot = true\nnetwork = true\nkube = true\n[run]\njobs = 0\n",
            "`run.jobs` must be 1 or more",
        ),
    ];
    for (text, want) in cases {
        let error = load(&[("fixture.toml", text)]).expect_err(want);
        assert_eq!(invalid_path(&error), "fixture.toml", "{want}");
        assert!(error.to_string().contains(want), "{want}: {error}");
    }
}

#[test]
fn a_full_manifest_keeps_every_field() {
    let top = "base = \"base\"\ncrlf = [\"root/c/x.txt\"]\nspec = \"my-spec.yaml\"\n";
    let tables = "\n[run]\nclock = \"2026-11-02T09:00:00Z\"\nrun_id = \"00000000-0000-4000-8000-000000000001\"\njobs = 8\ndeadline_ms = 20000\n\n[expect]\nverdict = \"not_ready\"\nexit_code = 2\n\n[matrix]\nos_family = \"ubuntu\"\n";
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "base", "linux", "", &[]);
    let manifest = format!("{}{tables}", manifest_text("linux", top));
    put(
        dir.path(),
        "x",
        "linux",
        "",
        &[("fixture.toml", &manifest), ("my-spec.yaml", "x: 1\n")],
    );
    let fixture = Fixture::load(dir.path(), "envs/x").expect("loads");
    let manifest = fixture.manifest();
    assert_eq!(manifest.crlf, ["root/c/x.txt"]);
    assert_eq!(manifest.spec.as_deref(), Some("my-spec.yaml"));
    assert_eq!(manifest.run.clock.as_deref(), Some("2026-11-02T09:00:00Z"));
    assert_eq!(manifest.run.jobs, Some(8));
    assert_eq!(manifest.run.deadline_ms, Some(20_000));
    assert_eq!(
        manifest.expect,
        Some(Expect {
            verdict: "not_ready".to_owned(),
            exit_code: 2
        })
    );
    assert_eq!(
        manifest.matrix.get("os_family").map(String::as_str),
        Some("ubuntu")
    );
    assert_eq!(
        fixture.available_needs(),
        [Need::Root, Need::Network],
        "[caps] decides the needs"
    );
}

#[test]
fn the_output_of_a_failed_golden_compare_does_not_break_the_load() {
    load(&[("expect.json", "{}"), ("expect.json.actual", "{}")]).expect("loads");
}

#[test]
fn the_tree_and_the_json_files_are_checked() {
    let cases: [FileCase; 14] = [
        (
            &[("surprise.txt", "x")],
            "surprise.txt",
            "not part of the fixture format",
        ),
        (
            &[("command/a.json", "{}")],
            "command",
            "not part of the fixture format",
        ),
        (
            &[("commands/a.txt", "x")],
            "commands/a.txt",
            "only .json files",
        ),
        (
            &[("commands/sub/a.json", "{}")],
            "commands/sub/a.json",
            "only .json files",
        ),
        (
            &[("commands/a.json", "{")],
            "commands/a.json",
            "not valid JSON",
        ),
        (
            &[("commands/a.json", "[]")],
            "commands/a.json",
            "one JSON object",
        ),
        (
            &[("commands/a.json", r#"{"argv":["chronyc","tracking"]}"#)],
            "commands/a.json",
            "absolute path",
        ),
        (
            &[(
                "commands/a.json",
                r#"{"argv":["/usr/bin/chronyc"],"delay":5}"#,
            )],
            "commands/a.json",
            "`delay` is not a key",
        ),
        (
            &[(
                "commands/a.json",
                r#"{"argv":["/usr/bin/chronyc"],"stdout":"a","stdout_b64":"YQ=="}"#,
            )],
            "commands/a.json",
            "exclusive",
        ),
        (
            &[(
                "commands/a.json",
                r#"{"argv":["/usr/bin/chronyc"],"stdout_b64":"not base64!"}"#,
            )],
            "commands/a.json",
            "stdout_b64",
        ),
        (
            &[("env.json", r#"{"A":1}"#)],
            "env.json",
            "`A` must be a string",
        ),
        (
            &[("net.json", r#"{"tcp":{"192.0.2.1:1":"closed"}}"#)],
            "net.json",
            "refused, blackhole",
        ),
        (
            &[("net.json", r#"{"dns":{"a.example":["not-an-ip"]}}"#)],
            "net.json",
            "IP addresses",
        ),
        (
            &[("root.manifest.json", r#"{"links":{}}"#)],
            "root.manifest.json",
            "`links` is not a key",
        ),
    ];
    for (files, path, want) in cases {
        let error = load(files).expect_err(want);
        assert_eq!(invalid_path(&error), path, "{want}");
        assert!(error.to_string().contains(want), "{want}: {error}");
        assert!(error.to_string().contains("Fix:"), "{error}");
    }
}

#[test]
fn the_root_manifest_must_name_things_that_exist() {
    let cases: [(&str, &str); 6] = [
        (
            r#"{"unreadable":["var/log/audit.log"]}"#,
            "is not in the tree",
        ),
        (r#"{"modes":{"etc/b":"0640"}}"#, "is not in the tree"),
        (r#"{"modes":{"etc/a":"rwx"}}"#, "octal string"),
        (r#"{"symlinks":{"../escape":"/x"}}"#, "plain components"),
        (r#"{"unreadable":[""]}"#, "plain components"),
        (r#"{"symlinks":{"etc/a":"/x"}}"#, "also a file"),
    ];
    for (manifest, want) in cases {
        let error = load(&[("root/etc/a", "a"), ("root.manifest.json", manifest)]).expect_err(want);
        assert_eq!(invalid_path(&error), "root.manifest.json", "{manifest}");
        assert!(error.to_string().contains(want), "{manifest}: {error}");
    }
    // A directory listed as a file path is refused.
    let error = load(&[
        ("root/etc/a", "a"),
        ("root.manifest.json", r#"{"dirs":["etc/a"]}"#),
    ])
    .expect_err("dir on a file");
    assert!(error.to_string().contains("is a file"), "{error}");
}

#[test]
fn a_fixture_name_is_a_plain_relative_path() {
    for name in [
        "",
        "..",
        "../x",
        "/etc",
        "envs//x",
        "envs/.hidden",
        "a b",
        "envs\\x",
    ] {
        let error = Fixture::load(&fixtures_dir(), name).expect_err(name);
        assert!(
            matches!(error, FixtureError::Invalid { .. }),
            "{name}: {error:?}"
        );
    }
    let error = Fixture::load(&fixtures_dir(), "checks/host.memory/nothing").expect_err("missing");
    assert!(matches!(error, FixtureError::Read { .. }), "{error:?}");
}

#[cfg(unix)]
#[test]
fn a_symlink_or_an_odd_name_in_the_tree_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "x", "linux", "", &[("root/etc/a", "a")]);
    let link = dir.path().join("envs/x/root/etc/link");
    std::os::unix::fs::symlink("/etc/shadow", &link).expect("symlink");
    let error = Fixture::load(dir.path(), "envs/x").expect_err("a symlink");
    assert_eq!(invalid_path(&error), "root/etc/link");
    assert!(error.to_string().contains("root.manifest.json"), "{error}");
    fs::remove_file(&link).expect("remove");

    write(dir.path(), "envs/x/root/etc/socket:[1]", "x");
    let error = Fixture::load(dir.path(), "envs/x").expect_err("a bad name");
    assert_eq!(invalid_path(&error), "root/etc/socket:[1]");
}

#[test]
fn a_file_over_the_cap_is_refused_and_named() {
    let big = "x".repeat(usize::try_from(fixture::MAX_FILE_BYTES).expect("fits") + 1);
    let error = load(&[("root/big.bin", &big)]).expect_err("too big");
    assert_eq!(invalid_path(&error), "root/big.bin");
    assert!(error.to_string().contains("over"), "{error}");
}

// ---- the backend -------------------------------------------------------------------------------

#[tokio::test]
async fn paths_are_posix_text_whatever_the_runner_is() {
    let replay = Replay::new().file("/proc/net/dev", "dev");
    // A Windows runner joins with a backslash. A Unix runner never makes this path, but the key must
    // be the same when it does.
    let read = |text: &str| {
        let path = PathBuf::from(text);
        let replay = replay.clone();
        async move { replay.open_read(&path, ReadRange::Head(8), &guard()).await }
    };
    for text in ["/proc/net/dev", "/proc//net/./dev", "/proc/net/dev/"] {
        assert!(read(text).await.is_ok(), "{text}");
    }
    if cfg!(windows) {
        assert!(read(r"/proc\net\dev").await.is_ok());
    }
    // A Windows fixture is written with backslashes and compares without case.
    let windows = Replay::for_os(Os::Windows).file(r"C:\Windows\System32\drivers\etc\HOSTS", "h");
    for text in [
        r"c:\windows\system32\drivers\etc\hosts",
        "C:/WINDOWS/System32/drivers/etc/hosts",
    ] {
        let got = windows
            .open_read(
                Path::new(text),
                ReadRange::Head(8),
                &ReadGuard::new(Os::Windows, None),
            )
            .await;
        assert!(got.is_ok(), "{text}");
    }
}

#[tokio::test]
async fn drive_files_map_to_lower_case_keys_only_for_a_windows_fixture() {
    let file = (
        "root/c/Windows/System32/drivers/etc/hosts",
        "127.0.0.1 localhost\n",
    );
    let windows = load_os("windows", &[file]).expect("loads");
    let g = ReadGuard::new(Os::Windows, None);
    for text in [
        r"C:\Windows\System32\drivers\etc\hosts",
        "c:/windows/system32/DRIVERS/etc/hosts",
    ] {
        let got = windows
            .replay()
            .open_read(Path::new(text), ReadRange::Head(64), &g)
            .await
            .expect(text);
        assert_eq!(got.bytes, b"127.0.0.1 localhost\n");
    }
    let drive = windows
        .replay()
        .read_dir(Path::new("c:/windows"), &g)
        .await
        .expect("the drive tree has directories");
    assert_eq!(drive, [DirEntry::new("system32", true)]);

    // A Linux fixture has no drive, and keeps case.
    let linux = load_os("linux", &[file]).expect("loads");
    let g = guard();
    let ok = linux
        .replay()
        .open_read(
            Path::new("/c/Windows/System32/drivers/etc/hosts"),
            ReadRange::Head(64),
            &g,
        )
        .await;
    assert!(ok.is_ok());
    for text in [
        "c:/windows/system32/drivers/etc/hosts",
        "/c/windows/system32/drivers/etc/hosts",
    ] {
        let got = linux
            .replay()
            .open_read(Path::new(text), ReadRange::Head(64), &g)
            .await;
        assert_eq!(
            got.expect_err(text).kind(),
            std::io::ErrorKind::NotFound,
            "{text}"
        );
    }
}

#[tokio::test]
async fn a_windows_program_name_compares_without_case_and_only_whoami_runs() {
    let fixture = load_os(
        "windows",
        &[
            (
                "commands/whoami.json",
                r#"{"argv":["C:\\Windows\\System32\\WHOAMI.EXE","/groups"],"stdout":"Everyone\r\n","exit":0}"#,
            ),
            (
                "commands/netstat.json",
                r#"{"argv":["C:\\Windows\\System32\\netstat.exe","-ano"],"stdout":"x"}"#,
            ),
        ],
    )
    .expect("loads");
    let done = fixture
        .replay()
        .spawn(Cmd::new("whoami.exe", Duration::from_secs(5)).args(["/groups"]))
        .await
        .expect("recorded");
    assert_eq!(done.stdout, b"Everyone\r\n");
    // The live runner runs nothing else on Windows in M1, whatever the fixture holds.
    assert!(matches!(
        fixture
            .replay()
            .spawn(Cmd::new("netstat.exe", Duration::from_secs(5)).args(["-ano"]))
            .await,
        Err(ProbeError::Policy(PolicyError::NotAllowedOnWindows { .. }))
    ));
    // A Linux fixture compares exactly.
    let linux = load(&[(
        "commands/chronyc.json",
        r#"{"argv":["/usr/bin/chronyc","tracking"]}"#,
    )])
    .expect("loads");
    assert!(
        linux
            .replay()
            .spawn(Cmd::new("chronyc", Duration::from_secs(5)).args(["tracking"]))
            .await
            .is_ok()
    );
    assert!(matches!(
        linux
            .replay()
            .spawn(Cmd::new("Chronyc", Duration::from_secs(5)).args(["tracking"]))
            .await,
        Err(ProbeError::NotRecorded(_))
    ));
}

#[tokio::test]
async fn command_output_has_stderr_binary_stdout_a_signal_and_the_caps() {
    let big = "y".repeat(100);
    let fixture = load(&[
        (
            "commands/a.json",
            r#"{"argv":["/usr/bin/getent","a"],"stdout_b64":"/wCA","stderr":"warn\n","exit":2}"#,
        ),
        (
            "commands/b.json",
            r#"{"argv":["/usr/bin/getent","b"],"exit":null}"#,
        ),
        (
            "commands/c.json",
            &format!(r#"{{"argv":["/usr/bin/getent","c"],"stdout":"{big}","stderr":"{big}"}}"#),
        ),
    ])
    .expect("loads");
    let run = |args: &'static [&'static str], cap: usize| {
        let replay = fixture.replay().clone();
        async move {
            replay
                .spawn(
                    Cmd::new("getent", Duration::from_secs(5))
                        .args(args.iter().copied())
                        .stdout_cap(cap),
                )
                .await
        }
    };
    let a = run(&["a"], 4096).await.expect("recorded");
    assert_eq!(
        (a.exit, a.stdout.as_slice(), a.stderr.as_slice()),
        (Some(2), &[0xff, 0x00, 0x80][..], &b"warn\n"[..])
    );
    assert_eq!(run(&["b"], 4096).await.expect("recorded").exit, None);
    let c = run(&["c"], 10).await.expect("recorded");
    assert_eq!(c.stdout.len(), 10);
    assert!(c.stdout_truncated);
    assert!(!c.stderr_truncated);
}

#[tokio::test]
async fn a_symlink_chain_resolves_and_a_loop_fails() {
    let replay = Replay::new()
        .file("/real/target", "t")
        .symlink("/a", "/b")
        .symlink("/b", "real/../real/target")
        .symlink("/dir-link", "/real")
        .symlink("/loop1", "/loop2")
        .symlink("/loop2", "/loop1");
    let read = |text: &'static str| {
        let replay = replay.clone();
        async move {
            replay
                .open_read(Path::new(text), ReadRange::Head(8), &guard())
                .await
        }
    };
    // `/b` is relative to `/`, so `real/../real/target` is `/real/target`.
    assert_eq!(read("/a").await.expect("chain").bytes, b"t");
    assert_eq!(
        read("/dir-link/target").await.expect("dir link").bytes,
        b"t"
    );
    let error = read("/loop1").await.expect_err("loop");
    assert!(error.to_string().contains("symbolic links"), "{error}");
    assert_eq!(
        read("/dir-link/missing").await.expect_err("missing").kind(),
        std::io::ErrorKind::NotFound
    );
}

// ---- native, api, env --------------------------------------------------------------------------

#[tokio::test]
async fn a_system_roots_value_may_name_where_the_roots_were_read_from() {
    use crate::probe::{StoreKind, StoreOrigin, StoreSource};
    let fixture = load(&[(
        "native/roots.json",
        r#"{"call":"system_roots","value":{"certs":["AQID","BAUG"],"sources":[
            {"kind":"bundle","location":"/etc/pki/tls/certs/ca-bundle.crt"},
            {"kind":"directory","location":"/etc/ssl/certs","env":"SSL_CERT_DIR"},
            {"kind":"os","location":"System keychain"}]}}"#,
    )])
    .expect("loads");
    let run = TestRun::for_fixture(&fixture);
    let check = run.context("net.tls_intercept", Os::Linux, []);
    assert_eq!(
        check.probe().native(NativeCall::SystemRoots).await,
        Ok(NativeValue::SystemRoots(crate::probe::SystemRoots::new(
            vec![vec![1, 2, 3], vec![4, 5, 6]],
            vec![
                StoreSource::new(StoreKind::Bundle, "/etc/pki/tls/certs/ca-bundle.crt"),
                StoreSource::new(StoreKind::Directory, "/etc/ssl/certs")
                    .origin(StoreOrigin::Env("SSL_CERT_DIR")),
                StoreSource::new(StoreKind::OsStore, "System keychain"),
            ]
        )))
    );

    // The list form has no named source.
    let fixture = load(&[(
        "native/roots.json",
        r#"{"call":"system_roots","value":["AQID"]}"#,
    )])
    .expect("loads");
    let run = TestRun::for_fixture(&fixture);
    let check = run.context("net.tls_intercept", Os::Linux, []);
    let Ok(NativeValue::SystemRoots(found)) = check.probe().native(NativeCall::SystemRoots).await
    else {
        panic!("a recorded answer");
    };
    assert!(found.sources.is_empty());

    for (text, want) in [
        (
            r#"{"call":"system_roots","value":{"sources":[]}}"#,
            "needs `certs`",
        ),
        (
            r#"{"call":"system_roots","value":{"certs":["AQID"],"sources":"x"}}"#,
            "`sources` must be a list",
        ),
        (
            r#"{"call":"system_roots","value":{"certs":["AQID"],"sources":[{"kind":"file","location":"/x"}]}}"#,
            "must be bundle, directory or os",
        ),
        (
            r#"{"call":"system_roots","value":{"certs":["AQID"],"sources":[{"kind":"bundle"}]}}"#,
            "location",
        ),
        (
            r#"{"call":"system_roots","value":{"certs":["AQID"],"sources":[{"kind":"bundle","location":"/x","env":"HOME"}]}}"#,
            "must be SSL_CERT_FILE or SSL_CERT_DIR",
        ),
        (
            r#"{"call":"system_roots","value":{"certs":["AQID"],"extra":1}}"#,
            "extra",
        ),
        (
            r#"{"call":"system_roots","value":{"certs":"AQID"}}"#,
            "list of base64",
        ),
    ] {
        let error = load(&[("native/a.json", text)]).expect_err(want);
        assert_eq!(invalid_path(&error), "native/a.json", "{want}");
        assert!(error.to_string().contains(want), "{want}: {error}");
    }
}

#[tokio::test]
async fn native_files_answer_each_call_and_unrecorded_calls_fail() {
    let fixture = load(&[
        (
            "native/statvfs.json",
            r#"{"call":"statvfs","path":"/var/lib/acme","value":{"fragment_size":4096,"blocks":1000,"blocks_free":500,"blocks_available":400,"files":0,"files_free":0,"read_only":false,"no_exec":true,"no_suid":false,"dev":"8:1"}}"#,
        ),
        (
            "native/uname.json",
            r##"{"call":"uname","value":{"sysname":"Linux","release":"5.14.0-362.el9.x86_64","version":"#1 SMP","machine":"x86_64"}}"##,
        ),
        (
            "native/nofile.json",
            r#"{"call":"rlimit","resource":"nofile","value":{"soft":1024,"hard":null}}"#,
        ),
        (
            "native/hostname.json",
            r#"{"call":"hostname","value":"host-01.acme.example"}"#,
        ),
        (
            "native/machine-id.json",
            r#"{"call":"machine_id","value":"0123456789abcdef0123456789abcdef"}"#,
        ),
        (
            "native/roots.json",
            r#"{"call":"system_roots","value":["AQID"]}"#,
        ),
        (
            "native/license.json",
            r#"{"call":"statvfs","path":"/etc/acme/license.link","error":"permission_denied"}"#,
        ),
    ])
    .expect("loads");
    let run = TestRun::for_fixture(&fixture);
    let check = run.context("host.disk", Os::Linux, []);
    let probe = check.probe();

    let statvfs = probe
        .native(NativeCall::Statvfs {
            path: "/var/lib/acme/".into(),
        })
        .await
        .expect("recorded");
    assert_eq!(
        statvfs,
        NativeValue::Statvfs(StatvfsInfo {
            fragment_size: 4096,
            blocks: 1000,
            blocks_free: 500,
            blocks_available: 400,
            files: 0,
            files_free: 0,
            read_only: false,
            no_exec: Some(true),
            no_suid: false,
            dev: Some((8, 1)),
        })
    );
    match probe.native(NativeCall::Uname).await.expect("recorded") {
        NativeValue::Uname(info) => assert_eq!(info.release, "5.14.0-362.el9.x86_64"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        probe.native(NativeCall::Rlimit(Resource::Nofile)).await,
        Ok(NativeValue::Rlimit(RlimitInfo {
            soft: Some(1024),
            hard: None
        }))
    );
    assert_eq!(
        probe.native(NativeCall::Hostname).await,
        Ok(NativeValue::Hostname("host-01.acme.example".to_owned()))
    );
    assert_eq!(
        probe.native(NativeCall::SystemRoots).await,
        Ok(NativeValue::SystemRoots(vec![vec![1, 2, 3]].into()))
    );
    // The machine id is run-level only, and the fixture caller is what makes one.
    match run
        .run_probe(Os::Linux)
        .native(NativeCall::MachineId)
        .await
        .expect("recorded")
    {
        NativeValue::MachineId(id) => assert_eq!(id.expose(), "0123456789abcdef0123456789abcdef"),
        other => panic!("{other:?}"),
    }

    // Anything else is not recorded, and so is a path the fixture has no statvfs for.
    for call in [
        NativeCall::Rlimit(Resource::Core),
        NativeCall::Statvfs {
            path: "/data".into(),
        },
    ] {
        let error = probe.native(call).await.expect_err("not recorded");
        assert!(matches!(error, ProbeError::NotRecorded(_)), "{error:?}");
        assert!(error.to_string().contains("Fix:"));
    }
    // A recorded failure comes back as that failure.
    assert_eq!(
        probe
            .native(NativeCall::Statvfs {
                path: "/etc/acme/license.link".into()
            })
            .await,
        Err(ProbeError::PermissionDenied)
    );
}

#[tokio::test]
async fn a_statvfs_through_a_link_to_the_password_file_is_denied() {
    let fixture = Fixture::load(&fixtures_dir(), "checks/_policy/symlink-to-shadow")
        .expect("the fixture loads");
    let replay = fixture.replay().clone().native(
        NativeCall::Statvfs {
            path: "/etc/acme/license.link".into(),
        },
        NativeValue::Statvfs(StatvfsInfo::default()),
    );
    let run = TestRun::new(replay);
    let ctx = run.context_for(&ACME, "host.fixture", Os::Linux, []);
    let error = ctx
        .probe()
        .native(NativeCall::Statvfs {
            path: "/etc/acme/license.link".into(),
        })
        .await
        .expect_err("denied");
    assert_eq!(rule_of(&error), RULE_SYSTEM_SECRET, "{error:?}");
}

#[test]
fn native_files_are_checked() {
    let cases: [(&str, &str); 10] = [
        (r#"{"call":"cpuid","value":1}"#, "`call` is `cpuid`"),
        (r#"{"call":"uname"}"#, "needs a `value` or an `error`"),
        (
            r#"{"call":"uname","value":{},"error":"unsupported"}"#,
            "exclusive",
        ),
        (
            r#"{"call":"uname","error":"broken"}"#,
            "`error` is `broken`",
        ),
        (
            r#"{"call":"rlimit","resource":"cpu","value":{"soft":1,"hard":1}}"#,
            "`resource` is `cpu`",
        ),
        (
            r#"{"call":"uname","value":{"sysname":"Linux"}}"#,
            "`release` is missing",
        ),
        (r#"{"call":"statvfs","path":"var","value":{}}"#, "absolute"),
        (
            r#"{"call":"statvfs","path":"/var","value":{"fragment_size":1,"blocks":1,"blocks_free":1,"blocks_available":1,"files":1,"files_free":1,"read_only":false,"no_exec":false,"no_suid":false}}"#,
            "`dev` is missing",
        ),
        (
            r#"{"call":"statvfs","path":"/var","value":{"fragment_size":1,"blocks":1,"blocks_free":1,"blocks_available":1,"files":1,"files_free":1,"read_only":false,"no_exec":false,"no_suid":false,"dev":"8-1"}}"#,
            "`dev` must be a text like",
        ),
        (
            r#"{"call":"statvfs","path":"/var","value":{"fragment_size":1,"blocks":1,"blocks_free":1,"blocks_available":1,"files":1,"files_free":1,"read_only":false,"no_exec":false,"no_suid":false,"dev":"8:x"}}"#,
            "`dev` must be a text like",
        ),
    ];
    for (text, want) in cases {
        let error = load(&[("native/a.json", text)]).expect_err(want);
        assert_eq!(invalid_path(&error), "native/a.json", "{want}");
        assert!(error.to_string().contains(want), "{want}: {error}");
    }
    let one = r#"{"call":"hostname","value":"a.acme.example"}"#;
    assert!(matches!(
        load(&[("native/a.json", one), ("native/b.json", one)]),
        Err(FixtureError::Duplicate { .. })
    ));
}

#[test]
fn api_and_env_files_are_indexed_by_what_is_inside() {
    let fixture = load(&[
        (
            "api/version.json",
            r#"{"request":{"method":"get","path":"/version"},"status":200,"body":{"gitVersion":"v1.30.2"}}"#,
        ),
        (
            "api/nodes-page-2.json",
            r#"{"request":{"method":"GET","path":"/api/v1/nodes","query":"continue=abc&limit=2"},"status":200,"body":{"items":[]},"delay_ms":250}"#,
        ),
        (
            "api/reviews.json",
            r#"{"get nodes":{"allowed":true,"reason":""},"create secrets":{"allowed":false,"reason":"no"}}"#,
        ),
        ("env.json", r#"{"HTTPS_PROXY":"http://proxy.acme.example:3128"}"#),
    ])
    .expect("loads");
    let replay = fixture.replay();
    let version = replay.api("GET", "/version", "").expect("recorded");
    assert_eq!((version.status, version.delay), (200, Duration::ZERO));
    assert_eq!(version.body["gitVersion"], "v1.30.2");
    let page = replay
        .api("get", "/api/v1/nodes", "continue=abc&limit=2")
        .expect("recorded");
    assert_eq!(page.delay, Duration::from_millis(250));
    assert!(replay.api("GET", "/api/v1/nodes", "").is_none());
    // The records come back sorted by method, path and query, with the request they answer.
    let all: Vec<_> = replay
        .api_records()
        .map(|(method, path, query, record)| (method, path, query, record.status))
        .collect();
    assert_eq!(
        all,
        [
            ("GET", "/api/v1/nodes", "continue=abc&limit=2", 200),
            ("GET", "/version", "", 200)
        ]
    );
    assert_eq!(
        replay.reviews().expect("table")["create secrets"]["allowed"],
        false
    );
    assert_eq!(
        replay.env.get("HTTPS_PROXY").map(String::as_str),
        Some("http://proxy.acme.example:3128")
    );

    let one = r#"{"request":{"method":"GET","path":"/version"},"status":200}"#;
    let error = load(&[("api/a.json", one), ("api/b.json", one)]).expect_err("dup");
    assert!(
        matches!(&error, FixtureError::Duplicate { key, .. } if key == "GET /version"),
        "{error:?}"
    );
    let error = load(&[(
        "api/a.json",
        r#"{"request":{"method":"GET","path":"/v"},"status":99}"#,
    )])
    .expect_err("bad status");
    assert_eq!(invalid_path(&error), "api/a.json");
}

/// `net.json` is the table that `Backend::resolve` reads: the facade's lookup gets the recorded answer,
/// the link-local one included, so the address rule (M1-094) can refuse it.
#[tokio::test]
async fn a_recorded_name_answer_is_what_the_backend_resolves() {
    let fixture = load(&[(
        "net.json",
        r#"{"dns": {"Metadata.acme.example": ["169.254.169.254"],
                    "gone.acme.example": "NXDOMAIN"}}"#,
    )])
    .expect("loads");
    let replay = fixture.replay();
    let wait = Duration::from_secs(1);
    let got = Backend::resolve(replay, "metadata.ACME.example", 123, wait)
        .await
        .expect("recorded");
    assert_eq!(got, vec!["169.254.169.254".parse::<IpAddr>().expect("ip")]);
    let gone = Backend::resolve(replay, "gone.acme.example", 123, wait)
        .await
        .expect_err("NXDOMAIN");
    assert_eq!(gone.kind(), io::ErrorKind::NotFound);
    assert!(Unrecorded::from_io(&gone).is_none(), "NXDOMAIN is recorded");
    // A name the fixture does not hold is not recorded, which is not the same as not found.
    let missing = Backend::resolve(replay, "other.acme.example", 123, wait)
        .await
        .expect_err("unrecorded");
    assert!(Unrecorded::from_io(&missing).is_some(), "{missing}");
    assert!(matches!(
        ProbeError::from_io(&missing),
        ProbeError::NotRecorded(_)
    ));
}

/// Through the probe: a spec host that a fixture records at a link-local address is refused.
#[tokio::test]
async fn a_fixture_name_at_a_link_local_address_is_refused_by_the_probe() {
    use crate::check::PeerClass;
    use crate::family::HostSet;
    use crate::probe::ProbeHub;
    use crate::probe::sock::RULE_UDP_ADDRESS;
    use crate::redact::{Redactor, TagKey};

    static TIME: CheckInfo = CheckInfo {
        id: "host.time_sync",
        family: "host",
        summary: "Asks a time server.",
        meta: META,
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OS,
        reads: &[],
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[PeerClass::NtpServers],
    };
    let fixture = load(&[(
        "net.json",
        r#"{"dns": {"Meta.acme.example": ["169.254.169.254"]}}"#,
    )])
    .expect("loads");
    let hub = ProbeHub::new(
        Arc::new(fixture.into_replay()),
        Redactor::new(TagKey::fixed([3; 32])),
    );
    let probe = hub.check_probe(TIME.id, Os::Linux, Some(&TIME));
    let server = rdy_spec::Target::parse("meta.acme.example:123").expect("target");
    probe.permit_hosts(HostSet::new([server.clone()]));
    let error = probe
        .udp_exchange(&server, &[0; 48], 48)
        .await
        .expect_err("a link-local answer");
    assert!(
        matches!(error, ProbeError::Denied { rule, .. } if rule == RULE_UDP_ADDRESS),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_recording_answers_only_where_the_live_runner_would_find_the_program() {
    static DIRS: &[&str] = &["/opt/tools/bin"];
    let tool = |args: &'static [&'static str]| {
        Cmd::new("chronyc", Duration::from_secs(5))
            .args(args.iter().copied())
            .extra_dirs(DIRS)
    };
    let plain = |args: &'static [&'static str]| {
        Cmd::new("chronyc", Duration::from_secs(5)).args(args.iter().copied())
    };
    let fixture = load(&[
        (
            "commands/outside.json",
            r#"{"argv":["/opt/x/chronyc","tracking"],"stdout":"outside\n"}"#,
        ),
        (
            "commands/declared.json",
            r#"{"argv":["/opt/tools/bin/chronyc","sources"],"stdout":"declared\n"}"#,
        ),
        (
            "commands/late.json",
            r#"{"argv":["/bin/chronyc","tracking"],"stdout":"late\n"}"#,
        ),
        (
            "commands/early.json",
            r#"{"argv":["/usr/sbin/chronyc","sources"],"stdout":"early\n"}"#,
        ),
    ])
    .expect("loads");
    let replay = fixture.replay();

    // The search stops at the first directory that holds the program, as the live runner does: with
    // `chronyc` in /usr/sbin, the one in /bin is never run, so `tracking` is not recorded for it.
    let early = replay.spawn(plain(&["sources"])).await.expect("early");
    assert_eq!(early.stdout, b"early\n");
    let got = replay.spawn(plain(&["tracking"])).await;
    assert!(matches!(got, Err(ProbeError::NotRecorded(_))), "{got:?}");
    // A declared directory is searched after the fixed ones, so the early one still wins.
    let got = replay.spawn(tool(&["sources"])).await.expect("early wins");
    assert_eq!(got.stdout, b"early\n");

    // With nothing in the fixed directories, the declared one answers.
    let only = load(&[
        (
            "commands/outside.json",
            r#"{"argv":["/opt/x/chronyc","tracking"],"stdout":"outside\n"}"#,
        ),
        (
            "commands/declared.json",
            r#"{"argv":["/opt/tools/bin/chronyc","tracking"],"stdout":"declared\n"}"#,
        ),
    ])
    .expect("loads");
    assert_eq!(
        only.replay()
            .spawn(tool(&["tracking"]))
            .await
            .expect("declared")
            .stdout,
        b"declared\n"
    );
    // /opt/x is not a search directory and the check declared none, so it answers nothing.
    let got = only.replay().spawn(plain(&["tracking"])).await;
    assert!(matches!(got, Err(ProbeError::NotRecorded(_))), "{got:?}");
    let error = got.expect_err("not recorded").to_string();
    assert!(error.contains("no recorded answer"), "{error}");
    // Two recordings are in directories that are not searched here; the first by path is named.
    assert!(
        error.contains("/opt/tools/bin/chronyc")
            && error.contains("does not search that directory"),
        "{error}"
    );
    // A command that is recorded nowhere gets no such hint.
    let got = only
        .replay()
        .spawn(plain(&["sources"]))
        .await
        .expect_err("not recorded");
    assert!(!got.to_string().contains("does not search"), "{got}");

    // A declared directory the live runner would refuse is refused here too. The fixture is Linux, so
    // it is judged as Linux text on every runner: `/opt/tools/bin` above is absolute even on a Windows
    // runner, and a drive path is not absolute here even though a Windows runner would accept it.
    static BAD: &[&str] = &["/opt/../etc"];
    static DRIVE: &[&str] = &["C:/tools/bin"];
    static RELATIVE: &[&str] = &["tools/bin"];
    for dirs in [BAD, DRIVE, RELATIVE] {
        let bad = Cmd::new("chronyc", Duration::from_secs(5)).extra_dirs(dirs);
        let got = only.replay().spawn(bad).await;
        assert!(
            matches!(got, Err(ProbeError::Policy(PolicyError::InvalidDir { .. }))),
            "{dirs:?}: {got:?}"
        );
    }

    // /bin is a search directory.
    let bin = load(&[(
        "commands/late.json",
        r#"{"argv":["/bin/chronyc","tracking"],"stdout":"late\n"}"#,
    )])
    .expect("loads");
    assert_eq!(
        bin.replay()
            .spawn(plain(&["tracking"]))
            .await
            .expect("bin")
            .stdout,
        b"late\n"
    );
}

#[tokio::test]
async fn the_builder_records_a_missing_program_like_the_fixture_does() {
    let replay = Replay::new().missing("chronyc");
    let got = replay
        .spawn(Cmd::new("chronyc", Duration::from_secs(5)).args(["tracking"]))
        .await;
    assert!(
        matches!(&got, Err(ProbeError::Policy(PolicyError::NotFound { program })) if *program == "chronyc"),
        "{got:?}"
    );
    assert!(matches!(
        replay
            .spawn(Cmd::new("getent", Duration::from_secs(5)).args(["hosts"]))
            .await,
        Err(ProbeError::NotRecorded(_))
    ));
}

#[tokio::test]
async fn a_missing_program_fails_as_the_live_runner_does() {
    let fixture = load(&[
        (
            "commands/chronyc.json",
            r#"{"argv":["chronyc"],"missing":true}"#,
        ),
        (
            "commands/getent.json",
            r#"{"argv":["/usr/bin/getent","ahosts","--","a.acme.example"],"stdout":"x"}"#,
        ),
    ])
    .expect("loads");
    let replay = fixture.replay();
    let got = replay
        .spawn(Cmd::new("chronyc", Duration::from_secs(5)).args(["tracking"]))
        .await;
    assert!(
        matches!(&got, Err(ProbeError::Policy(PolicyError::NotFound { program })) if *program == "chronyc"),
        "{got:?}"
    );
    // Only the named program is missing; others stay "not recorded".
    assert!(matches!(
        replay
            .spawn(Cmd::new("getent", Duration::from_secs(5)).args(["hosts"]))
            .await,
        Err(ProbeError::NotRecorded(_))
    ));

    let cases: [(&[(&str, &str)], &str); 5] = [
        (
            &[(
                "commands/a.json",
                r#"{"argv":["/usr/bin/chronyc"],"missing":true}"#,
            )],
            "bare name",
        ),
        (
            &[(
                "commands/a.json",
                r#"{"argv":["chronyc","tracking"],"missing":true}"#,
            )],
            "bare name",
        ),
        (
            &[(
                "commands/a.json",
                r#"{"argv":["chronyc"],"missing":true,"stdout":"x"}"#,
            )],
            "`stdout` is not a key",
        ),
        (
            &[("commands/a.json", r#"{"argv":["chronyc"],"missing":false}"#)],
            "only ever true",
        ),
        (
            &[
                ("commands/a.json", r#"{"argv":["chronyc"],"missing":true}"#),
                ("commands/b.json", r#"{"argv":["chronyc"],"missing":true}"#),
            ],
            "both record",
        ),
    ];
    for (files, want) in cases {
        let error = load(files).expect_err(want);
        assert!(error.to_string().contains(want), "{want}: {error}");
    }
    // Missing and installed at once is a contradiction.
    let error = load(&[
        ("commands/a.json", r#"{"argv":["chronyc"],"missing":true}"#),
        (
            "commands/b.json",
            r#"{"argv":["/usr/bin/chronyc","tracking"]}"#,
        ),
    ])
    .expect_err("contradiction");
    assert_eq!(invalid_path(&error), "commands/a.json");
    assert!(error.to_string().contains("commands/b.json"), "{error}");
    // A child can replace the base's recording with a missing one by using the same file name.
    let child = load_pair(
        &[("commands/chronyc.json", r#"{"argv":["/usr/bin/chronyc"]}"#)],
        "base = \"base\"",
        &[(
            "commands/chronyc.json",
            r#"{"argv":["chronyc"],"missing":true}"#,
        )],
    )
    .expect("loads");
    assert!(matches!(
        child
            .replay()
            .spawn(Cmd::new("chronyc", Duration::from_secs(5)))
            .await,
        Err(ProbeError::Policy(PolicyError::NotFound { .. }))
    ));
}

#[test]
fn argv_zero_must_be_a_plain_absolute_path() {
    for argv0 in ["/usr/bin/../bin/chronyc", "/"] {
        let text = format!(r#"{{"argv":["{argv0}"]}}"#);
        let error = load(&[("commands/a.json", &text)]).expect_err(argv0);
        assert_eq!(invalid_path(&error), "commands/a.json", "{argv0}");
    }
}

#[test]
fn caps_json_is_refused_with_a_pointer_to_the_manifest() {
    let error = load(&[("caps.json", r#"{"root":true}"#)]).expect_err("retired");
    assert_eq!(invalid_path(&error), "caps.json");
    assert!(
        error.to_string().contains("use [caps] in fixture.toml"),
        "{error}"
    );
}

#[tokio::test]
async fn an_unreadable_directory_hides_what_is_under_it() {
    let fixture = load(&[
        ("root/var/log/audit/audit.log", "entry\n"),
        ("root/var/log/syslog", "line\n"),
        ("root.manifest.json", r#"{"unreadable":["var/log/audit"]}"#),
    ])
    .expect("loads");
    let replay = fixture.replay();
    for path in ["/var/log/audit/audit.log", "/var/log/audit/missing"] {
        let error = replay
            .open_read(Path::new(path), ReadRange::Head(8), &guard())
            .await
            .expect_err(path);
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied, "{path}");
        let error = replay
            .stat(Path::new(path), &guard())
            .await
            .expect_err(path);
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied, "{path}");
    }
    // The directory itself still stats, and its neighbour reads.
    let meta = replay
        .stat(Path::new("/var/log/audit"), &guard())
        .await
        .expect("stat")
        .expect("there");
    assert!(meta.is_dir);
    assert!(
        replay
            .open_read(Path::new("/var/log/syslog"), ReadRange::Head(8), &guard())
            .await
            .is_ok()
    );
    let error = replay
        .read_dir(Path::new("/var/log/audit"), &guard())
        .await
        .expect_err("unreadable");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn process_ids_that_are_not_recorded_say_so() {
    let error = Replay::new()
        .process_ids()
        .await
        .expect_err("none recorded");
    assert!(
        matches!(&error, ProbeError::NotRecorded(what) if what == "the process ids"),
        "{error:?}"
    );
    assert!(
        Replay::new()
            .ids([1; 4], [2; 4])
            .process_ids()
            .await
            .is_ok()
    );
}

#[test]
fn a_proc_self_link_is_refused_so_the_runners_pid_never_decides() {
    let error = load(&[
        ("root/proc/1234/status", "x"),
        ("root.manifest.json", r#"{"symlinks":{"proc/self":"1234"}}"#),
    ])
    .expect_err("proc/self");
    assert_eq!(invalid_path(&error), "root.manifest.json");
    assert!(error.to_string().contains("proc/self"), "{error}");
    // Plain files under proc/self are fine: the read policy sees `self` as written.
    assert!(load(&[("root/proc/self/status", "x")]).is_ok());
}

#[test]
fn keys_that_are_one_entry_after_normalising_are_duplicates() {
    let cases: [(&str, &str, &str, &str); 6] = [
        (
            "net.json",
            r#"{"dns":{"Registry.acme.example":["192.0.2.1"],"registry.ACME.example":["192.0.2.2"]}}"#,
            "net.json",
            "Registry.acme.example",
        ),
        (
            "net.json",
            r#"{"tcp":{"[::1]:443":"refused","[0:0:0:0:0:0:0:1]:443":"reset"}}"#,
            "net.json",
            "[0:0:0:0:0:0:0:1]:443",
        ),
        (
            "net.json",
            r#"{"tcp":{"192.0.2.1:443":"refused","192.0.2.1:443":"reset"}}"#,
            "net.json",
            "appears twice",
        ),
        (
            "env.json",
            r#"{"HTTPS_PROXY":"a","HTTPS_PROXY":"b"}"#,
            "env.json",
            "`HTTPS_PROXY` appears twice",
        ),
        (
            "commands/a.json",
            r#"{"argv":["/usr/bin/chronyc"],"stdout":"a","stdout":"b"}"#,
            "commands/a.json",
            "`stdout` appears twice",
        ),
        (
            "api/reviews.json",
            r#"{"get nodes":{"allowed":true},"get nodes":{"allowed":false}}"#,
            "api/reviews.json",
            "`get nodes` appears twice",
        ),
    ];
    for (file, text, path, want) in cases {
        let error = load(&[(file, text)]).expect_err(file);
        assert_eq!(invalid_path(&error), path, "{file}");
        assert!(error.to_string().contains(want), "{file}: {error}");
    }
    // Inside a nested object too.
    let error = load(&[("root.manifest.json", r#"{"symlinks":{"a":"/x","a":"/y"}}"#)])
        .expect_err("repeated");
    assert!(error.to_string().contains("appears twice"), "{error}");
    // On a Windows fixture a path compares without case.
    let error = load_os(
        "windows",
        &[
            ("root/c/x", "x"),
            (
                "root.manifest.json",
                r#"{"symlinks":{"c/Windows/A":"c:/x","c/windows/a":"c:/x"}}"#,
            ),
        ],
    )
    .expect_err("same path");
    assert!(error.to_string().contains("same entry"), "{error}");
    let error = load_os(
        "windows",
        &[
            ("root/c/x", "x"),
            (
                "root.manifest.json",
                r#"{"modes":{"c/X":"0640","c/x":"0600"}}"#,
            ),
        ],
    )
    .expect_err("same path");
    assert!(error.to_string().contains("same entry"), "{error}");
}

#[test]
fn a_base_on_another_arch_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "base", "linux", "", &[]);
    let text = manifest_text("linux", "base = \"base\"").replace("x86_64", "aarch64");
    put(
        dir.path(),
        "x",
        "linux",
        "",
        &[("fixture.toml", text.as_str())],
    );
    let error = Fixture::load(dir.path(), "envs/x").expect_err("arch differs");
    assert!(error.to_string().contains("`arch` differs"), "{error}");
}

#[test]
fn a_child_manifest_replaces_the_whole_root_manifest_of_the_base() {
    // 08's replace by path, kept as is: the child's root.manifest.json is the manifest.
    let base = [
        ("root/etc/a", "a"),
        ("root/etc/b", "b"),
        (
            "root.manifest.json",
            r#"{"unreadable":["etc/a"],"modes":{"etc/b":"0600"}}"#,
        ),
    ];
    let kept = load_pair(&base, "base = \"base\"", &[]).expect("loads");
    assert_eq!(kept.replay().mode("/etc/b"), Some(0o600));
    let replaced = load_pair(
        &base,
        "base = \"base\"",
        &[("root.manifest.json", r#"{"dirs":["var"]}"#)],
    )
    .expect("loads");
    assert_eq!(
        replaced.replay().mode("/etc/b"),
        None,
        "the base's modes are gone"
    );
    // Removing a file the base manifest names leaves the name dangling, and that fails.
    let error =
        load_pair(&base, "base = \"base\"\nremove = [\"root/etc/a\"]", &[]).expect_err("dangling");
    assert_eq!(invalid_path(&error), "root.manifest.json");
    assert!(error.to_string().contains("is not in the tree"), "{error}");
}

#[test]
fn a_fixture_over_the_file_or_byte_budget_is_refused() {
    // The loader takes its limits as an argument, so a few small files prove both checks. A limit of
    // three files is under the four this fixture holds (the manifest and three more).
    let dir = TempDir::new().expect("temp dir");
    put(dir.path(), "x", "linux", "", &[]);
    let root = dir.path().join("envs/x/root/many");
    fs::create_dir_all(&root).expect("dirs");
    for n in 0..3 {
        fs::write(root.join(format!("f{n}")), "").expect("write");
    }
    let error = Fixture::load_with(dir.path(), "envs/x", fixture::Budget::limited(3, u64::MAX))
        .expect_err("too many files");
    assert!(error.to_string().contains("over 3 files"), "{error}");
    Fixture::load_with(dir.path(), "envs/x", fixture::Budget::limited(5, u64::MAX))
        .expect("within the file limit");

    // Bytes: a limit under the size of one file.
    let dir = TempDir::new().expect("temp dir");
    put(
        dir.path(),
        "x",
        "linux",
        "",
        &[("root/big", &"x".repeat(4096))],
    );
    let error = Fixture::load_with(dir.path(), "envs/x", fixture::Budget::limited(100, 2048))
        .expect_err("too many bytes");
    assert!(error.to_string().contains("2048 bytes"), "{error}");
    Fixture::load_with(dir.path(), "envs/x", fixture::Budget::limited(100, 1 << 20))
        .expect("within the byte limit");
}

#[test]
fn run_clock_can_be_a_toml_datetime() {
    let top = "";
    let tables = "\n[run]\nclock = 2026-11-02T09:00:00Z\n";
    let manifest = format!("{}{tables}", manifest_text("linux", top));
    let fixture = load(&[("fixture.toml", &manifest)]).expect("loads");
    assert_eq!(
        fixture.manifest().run.clock.as_deref(),
        Some("2026-11-02T09:00:00Z")
    );
    let manifest = format!("{}\n[run]\nclock = 5\n", manifest_text("linux", top));
    let error = load(&[("fixture.toml", &manifest)]).expect_err("not a time");
    assert!(error.to_string().contains("`run.clock`"), "{error}");
}

#[tokio::test]
async fn a_windows_runner_does_not_rewrite_a_linux_links_backslashes() {
    // A Linux fixture holds a file whose name has a backslash, reached through a link. Only the path
    // a check asks for is read by the runner; the stored target is read by the fixture's os.
    let target = r"/data/odd\name";
    assert_eq!(paths::components(Os::Linux, target), ["data", r"odd\name"]);
    assert!(!paths::is_absolute(Os::Linux, r"\\server\share"));
    assert_eq!(
        paths::components(Os::Windows, r"C:\Data\X"),
        ["c:", "data", "x"]
    );
    // The asked path is read by the runner as well.
    let asked = paths::asked_key(Os::Linux, r"/proc\net");
    assert_eq!(
        asked,
        if cfg!(windows) {
            "/proc/net"
        } else {
            r"/proc\net"
        }
    );
}

// ---- time ----------------------------------------------------------------------------------------

#[cfg(feature = "runtime")]
mod clock {
    use tokio::time::{Instant, timeout};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_command_delay_runs_on_the_tokio_clock_and_a_long_one_times_out() {
        let limit = getent("a.acme.example").time_limit();
        let slow = limit.as_millis() + 1_000;
        let fixture = load(&[
            (
                "commands/quick.json",
                r#"{"argv":["/usr/bin/getent","ahosts","--","quick.acme.example"],"stdout":"ok\n","delay_ms":100}"#,
            ),
            (
                "commands/slow.json",
                &format!(
                    r#"{{"argv":["/usr/bin/getent","ahosts","--","slow.acme.example"],"stdout":"late\n","delay_ms":{slow}}}"#
                ),
            ),
        ])
        .expect("loads");
        let run = TestRun::for_fixture(&fixture);
        let ctx = run.context("net.dns", Os::Linux, []);

        let start = Instant::now();
        let done = ctx
            .probe()
            .exec(getent("quick.acme.example"))
            .await
            .expect("done");
        assert_eq!(done.stdout, b"ok\n");
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(100),
            "virtual time, no real wait"
        );

        let start = Instant::now();
        let error = ctx
            .probe()
            .exec(getent("slow.acme.example"))
            .await
            .expect_err("timeout");
        assert_eq!(error, ProbeError::Timeout);
        assert_eq!(start.elapsed(), limit, "the limit and no longer");
        assert_eq!(run.action_log().actions[1].outcome, ActionOutcome::Timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_native_delay_waits_for_the_caller_to_give_up() {
        let fixture = load(&[(
            "native/hung.json",
            r#"{"call":"statvfs","path":"/mnt/nfs","delay_ms":3600000,"value":{"fragment_size":4096,"blocks":1,"blocks_free":1,"blocks_available":1,"files":1,"files_free":1,"read_only":false,"no_exec":false,"no_suid":false,"dev":null}}"#,
        )])
        .expect("loads");
        let run = TestRun::for_fixture(&fixture);
        let ctx = run.context("host.disk", Os::Linux, []);
        let start = Instant::now();
        let hung = timeout(
            Duration::from_secs(1),
            ctx.probe().native(NativeCall::Statvfs {
                path: "/mnt/nfs".into(),
            }),
        )
        .await;
        assert!(hung.is_err(), "the caller's timeout ends it");
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn dial_follows_net_json_and_a_blackhole_never_completes() {
        let fixture = load(&[(
            "net.json",
            r#"{"tcp":{"192.0.2.10:443":{"serve":"tls-private-ca"},"192.0.2.11:443":"refused","192.0.2.12:443":"blackhole","192.0.2.13:443":"reset"}}"#,
        )])
        .expect("loads");
        let replay = fixture.replay();
        let addr = |text: &str| text.parse::<SocketAddr>().expect("addr");

        assert_eq!(
            replay.dial(addr("192.0.2.10:443")).await.expect("served"),
            "tls-private-ca"
        );
        assert_eq!(
            replay
                .dial(addr("192.0.2.11:443"))
                .await
                .expect_err("refused")
                .kind(),
            std::io::ErrorKind::ConnectionRefused
        );
        assert_eq!(
            replay
                .dial(addr("192.0.2.13:443"))
                .await
                .expect_err("reset")
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );
        let error = replay
            .dial(addr("192.0.2.99:443"))
            .await
            .expect_err("not recorded");
        assert!(Unrecorded::from_io(&error).is_some());
        assert_eq!(
            ProbeError::from_io(&error),
            ProbeError::NotRecorded("a connection to 192.0.2.99:443".to_owned())
        );

        // The black hole holds no timer: only the caller's timeout moves the clock.
        let start = Instant::now();
        let waited = timeout(Duration::from_secs(60), replay.dial(addr("192.0.2.12:443"))).await;
        assert!(waited.is_err(), "it never completes");
        assert_eq!(start.elapsed(), Duration::from_secs(60));
    }
}

// ---- small pieces --------------------------------------------------------------------------------

#[test]
fn base64_follows_rfc_4648_and_refuses_everything_else() {
    for (text, bytes) in [
        ("", &b""[..]),
        ("Zg==", b"f"),
        ("Zm8=", b"fo"),
        ("Zm9v", b"foo"),
        ("Zm9vYg==", b"foob"),
        ("Zm9vYmE=", b"fooba"),
        ("Zm9vYmFy", b"foobar"),
        ("+/8=", &[0xfb, 0xff]),
    ] {
        assert_eq!(b64::decode(text).as_deref(), Ok(bytes), "{text}");
    }
    for bad in [
        "Zg", "Zg=", "Z===", "=Zg=", "Zg==Zg==", "Zh==", "Zm9=", "Zm 9", "Zm9\n", "Zm9-",
    ] {
        assert!(b64::decode(bad).is_err(), "{bad}");
    }
}

#[test]
fn keys_are_built_the_same_way_everywhere() {
    use paths::{components, is_special_target, join, key, tree_key};
    assert_eq!(key(Os::Linux, "/proc//net/./dev/"), "/proc/net/dev");
    assert_eq!(key(Os::Linux, "/"), "/");
    assert_eq!(
        key(Os::Windows, r"C:\Windows\System32"),
        "c:/windows/system32"
    );
    assert_eq!(key(Os::Windows, "c:"), "c:/");
    assert_eq!(tree_key(Os::Windows, "c/Windows/x"), "c:/windows/x");
    assert_eq!(tree_key(Os::Windows, "Program Files/x"), "/program files/x");
    assert_eq!(tree_key(Os::Linux, "c/Windows/x"), "/c/Windows/x");
    assert_eq!(
        join(Os::Macos, &components(Os::Macos, "/Users/Acme")),
        "/Users/Acme"
    );
    assert!(is_special_target("socket:[8841]"));
    assert!(is_special_target("anon_inode:[eventpoll]"));
    assert!(!is_special_target("/dev/null"));
    assert!(!is_special_target("socket:[8841]/x"));
    assert!(!is_special_target(":[1]"));
    assert!(!is_special_target("a:b"));
}

#[test]
fn a_replay_error_is_cloneable_and_tells_the_user_what_to_do() {
    let error = ProbeError::NotRecorded("the command `getent a`".to_owned());
    assert_eq!(error, error.clone());
    assert!(error.to_string().contains("Fix:"));
    assert_eq!(error.outcome(), ActionOutcome::Failed);
}
