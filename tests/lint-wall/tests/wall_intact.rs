//! The wall cannot be turned down without a test failing (M1-044, INV-07).
//!
//! The drift tests of `clippy_wall.rs` compare the check crates to each other. These tests close the ways
//! to weaken all of them at once: a hardcoded floor of the 02 Appendix A entries, a `.clippy.toml` that
//! replaces `clippy.toml`, `CLIPPY_CONF_DIR`, `rustflags`, a wrapper or an alias from a Cargo config,
//! flags in a workflow, a clippy step that does not end in `-- -D warnings`, and a lint override in a
//! manifest. Manifests and configs are read as TOML, so the spelling of a key does not matter.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{Kind, check_crates, entries, name, root};
use std::path::{Path, PathBuf};

/// The floor: every non-kube entry of 02 Appendix A, as of M1-044 and PC-47. A check crate's clippy.toml may
/// have more. It may not have fewer.
const FLOOR: &[(Kind, &str)] = &[
    (Kind::Type, "std::process::Command"),
    (Kind::Type, "std::fs::File"),
    (Kind::Type, "std::fs::OpenOptions"),
    (Kind::Type, "std::fs::DirBuilder"),
    (Kind::Type, "std::net::TcpStream"),
    (Kind::Type, "std::net::TcpListener"),
    (Kind::Type, "std::net::UdpSocket"),
    (Kind::Type, "std::os::unix::net::UnixStream"),
    (Kind::Type, "std::os::unix::net::UnixListener"),
    (Kind::Type, "std::os::unix::net::UnixDatagram"),
    (Kind::Type, "socket2::Socket"),
    (Kind::Type, "std::thread::Builder"),
    (Kind::Type, "rdy_engine::watchdog::ProcessEffects"),
    (Kind::Method, "clap::Parser::parse"),
    (Kind::Method, "clap::Parser::parse_from"),
    (Kind::Method, "clap::Command::get_matches"),
    (Kind::Method, "clap::Command::get_matches_from"),
    (Kind::Method, "clap::Command::get_matches_mut"),
    (Kind::Method, "clap::Parser::update_from"),
    (Kind::Method, "clap::error::Error::print"),
    (Kind::Method, "clap::error::Error::exit"),
    (Kind::Method, "rdy_spec::load_at"),
    (Kind::Method, "std::process::Command::new"),
    (Kind::Method, "std::process::exit"),
    (Kind::Method, "std::process::abort"),
    (Kind::Method, "tokio::process::Command::new"),
    (Kind::Method, "std::fs::read"),
    (Kind::Method, "std::fs::read_to_string"),
    (Kind::Method, "std::fs::read_dir"),
    (Kind::Method, "std::fs::read_link"),
    (Kind::Method, "std::fs::metadata"),
    (Kind::Method, "std::fs::symlink_metadata"),
    (Kind::Method, "std::fs::canonicalize"),
    (Kind::Method, "std::fs::exists"),
    (Kind::Method, "std::fs::write"),
    (Kind::Method, "std::fs::copy"),
    (Kind::Method, "std::fs::rename"),
    (Kind::Method, "std::fs::remove_file"),
    (Kind::Method, "std::fs::remove_dir"),
    (Kind::Method, "std::fs::remove_dir_all"),
    (Kind::Method, "std::fs::create_dir"),
    (Kind::Method, "std::fs::create_dir_all"),
    (Kind::Method, "std::fs::File::open"),
    (Kind::Method, "std::fs::File::create"),
    (Kind::Method, "std::fs::File::create_new"),
    (Kind::Method, "std::fs::OpenOptions::new"),
    (Kind::Method, "std::path::Path::metadata"),
    (Kind::Method, "std::path::Path::symlink_metadata"),
    (Kind::Method, "std::path::Path::canonicalize"),
    (Kind::Method, "std::path::Path::read_link"),
    (Kind::Method, "std::path::Path::read_dir"),
    (Kind::Method, "std::path::Path::exists"),
    (Kind::Method, "std::path::Path::try_exists"),
    (Kind::Method, "std::path::Path::is_file"),
    (Kind::Method, "std::path::Path::is_dir"),
    (Kind::Method, "std::path::Path::is_symlink"),
    (Kind::Method, "std::fs::hard_link"),
    (Kind::Method, "std::fs::soft_link"),
    (Kind::Method, "std::fs::set_permissions"),
    (Kind::Method, "std::os::unix::fs::symlink"),
    (Kind::Method, "std::os::unix::fs::chown"),
    (Kind::Method, "std::os::unix::fs::fchown"),
    (Kind::Method, "std::os::unix::fs::lchown"),
    (Kind::Method, "std::os::unix::fs::chroot"),
    (Kind::Method, "std::os::windows::fs::symlink_file"),
    (Kind::Method, "std::os::windows::fs::symlink_dir"),
    (Kind::Method, "std::net::TcpStream::connect"),
    (Kind::Method, "std::net::TcpStream::connect_timeout"),
    (Kind::Method, "std::net::TcpListener::bind"),
    (Kind::Method, "std::net::UdpSocket::bind"),
    (Kind::Method, "std::net::ToSocketAddrs::to_socket_addrs"),
    (Kind::Method, "std::os::unix::net::UnixStream::connect"),
    (Kind::Method, "std::os::unix::net::UnixStream::connect_addr"),
    (Kind::Method, "std::os::unix::net::UnixStream::pair"),
    (Kind::Method, "std::os::unix::net::UnixListener::bind"),
    (Kind::Method, "std::os::unix::net::UnixListener::bind_addr"),
    (Kind::Method, "std::os::unix::net::UnixDatagram::bind"),
    (Kind::Method, "std::os::unix::net::UnixDatagram::bind_addr"),
    (Kind::Method, "std::os::unix::net::UnixDatagram::unbound"),
    (Kind::Method, "std::os::unix::net::UnixDatagram::pair"),
    (Kind::Method, "tokio::net::TcpStream::connect"),
    (Kind::Method, "tokio::net::UdpSocket::bind"),
    (Kind::Method, "tokio::net::TcpListener::bind"),
    (Kind::Method, "tokio::net::lookup_host"),
    (Kind::Method, "tokio::net::UnixStream::connect"),
    (Kind::Method, "std::thread::spawn"),
    (Kind::Method, "std::thread::scope"),
    (Kind::Method, "std::thread::Builder::spawn"),
    (Kind::Method, "std::thread::Builder::spawn_scoped"),
    (Kind::Method, "tokio::spawn"),
    (Kind::Method, "tokio::task::spawn_blocking"),
    (Kind::Method, "std::env::var"),
    (Kind::Method, "std::env::var_os"),
    (Kind::Method, "std::env::vars"),
    (Kind::Method, "std::env::vars_os"),
    (Kind::Method, "std::env::current_dir"),
    (Kind::Method, "std::env::current_exe"),
    (Kind::Method, "std::env::home_dir"),
    (Kind::Method, "std::env::temp_dir"),
    (Kind::Method, "std::env::args"),
    (Kind::Method, "std::env::args_os"),
    (Kind::Method, "std::env::set_var"),
    (Kind::Method, "std::env::remove_var"),
    (Kind::Method, "std::env::set_current_dir"),
    (Kind::Method, "std::boxed::Box::leak"),
    (Kind::Method, "std::string::String::leak"),
    (Kind::Method, "std::vec::Vec::leak"),
    (Kind::Method, "std::io::stdout"),
    (Kind::Method, "std::io::stderr"),
    (Kind::Method, "std::io::stdin"),
    (Kind::Method, "rdy_engine::live_backend"),
    (Kind::Method, "rdy_engine::exec::table::run"),
    (Kind::Method, "rdy_engine::exec::run"),
    (Kind::Method, "rdy_engine::exec::ExecSpec::new"),
    (Kind::Method, "rdy_engine::testing::TestRun::context"),
    (Kind::Method, "rdy_engine::output::ReportParent::open"),
    (Kind::Method, "rdy_engine::output::OutputDir::create_new"),
    (Kind::Method, "rdy_engine::output::OutputDir::create_new_in"),
    (Kind::Method, "rdy_engine::output::OutputDir::write_atomic"),
    (Kind::Method, "rdy_engine::output::OutputDir::write_spec"),
    (Kind::Method, "rdy_engine::output::default_report_parent"),
    (Kind::Method, "rdy_engine::exec::kill_all_groups"),
    (Kind::Method, "rdy_engine::exec::harden_umask"),
    (Kind::Method, "rdy_engine::exec::inherited_fds"),
    (Kind::Method, "rdy_engine::watchdog::Effects::exit"),
    (Kind::Method, "rdy_engine::watchdog::Effects::kill_groups"),
    (Kind::Method, "rdy_engine::watchdog::Effects::notice"),
    (Kind::Method, "rdy_engine::watchdog::Watchdog::start"),
    (Kind::Method, "rdy_engine::watchdog::WriteState::claim"),
    (
        Kind::Method,
        "rdy_engine::watchdog::WriteState::claim_or_park",
    ),
    (Kind::Method, "rdy_engine::watchdog::WriteState::finish"),
    (Kind::Method, "rdy_engine::exec::live_groups"),
    (Kind::Method, "rdy_spec::load"),
    (Kind::Macro, "std::print"),
    (Kind::Macro, "std::println"),
    (Kind::Macro, "std::eprint"),
    (Kind::Macro, "std::eprintln"),
];

const KUBE_FLOOR: &[(Kind, &str)] = &[
    (Kind::Type, "kube::Client"),
    (Kind::Type, "kube::Config"),
    (Kind::Type, "kube::client::ClientBuilder"),
    (Kind::Type, "kube::config::Kubeconfig"),
    (Kind::Method, "kube::Client::new"),
    (Kind::Method, "kube::Client::try_default"),
    (Kind::Method, "kube::client::ClientBuilder::new"),
    (Kind::Method, "kube::Config::new"),
    (Kind::Method, "kube::Config::infer"),
    (Kind::Method, "kube::Config::incluster"),
    (Kind::Method, "kube::Config::incluster_env"),
    (Kind::Method, "kube::Config::incluster_dns"),
    (Kind::Method, "kube::Config::from_kubeconfig"),
    (Kind::Method, "kube::Config::from_custom_kubeconfig"),
    (Kind::Method, "kube::config::Kubeconfig::read"),
    (Kind::Method, "kube::config::Kubeconfig::read_from"),
    (Kind::Method, "kube::config::Kubeconfig::from_env"),
    (Kind::Method, "kube::config::Kubeconfig::from_yaml"),
];

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn toml_of(path: &Path) -> toml::Table {
    read(path)
        .parse::<toml::Table>()
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_check_crate_lists_every_appendix_a_entry() {
    // The drift tests compare the check crates to each other, so removing an entry from all of them would
    // pass them. This list is the floor, written out here. Removing a line from it is a change to
    // /tests/lint-wall/, which is in CODEOWNERS.
    for dir in check_crates() {
        let list = entries(&dir.join("clippy.toml"));
        for (kind, path) in FLOOR {
            assert!(
                list.iter().any(|e| e.kind == *kind && e.path == *path),
                "{}/clippy.toml lost the entry `{path}`",
                name(&dir)
            );
        }
        if name(&dir) == "rdy-checks-k8s" {
            for (kind, path) in KUBE_FLOOR {
                assert!(
                    list.iter().any(|e| e.kind == *kind && e.path == *path),
                    "{}/clippy.toml lost the kube entry `{path}`",
                    name(&dir)
                );
            }
        }
    }
}

/// Every file named `wanted` under `dir`, in every directory.
fn files_named(dir: &Path, wanted: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            files_named(&path, wanted, out);
        } else if path.file_name().is_some_and(|n| n == wanted) {
            out.push(path);
        }
    }
}

/// The directories to search for configuration: the repo, minus build output and the local checkouts.
fn config_roots() -> Vec<PathBuf> {
    let base = root();
    let mut roots = Vec::new();
    for entry in std::fs::read_dir(&base).expect("read root") {
        let path = entry.expect("entry").path();
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() && n != "target" && n != ".git" && n != ".claude" {
            roots.push(path);
        }
    }
    roots
}

#[test]
fn no_dot_clippy_toml_overrides_a_clippy_toml() {
    // Clippy reads `.clippy.toml` before `clippy.toml`, so one in a check crate replaces the wall.
    let mut found = Vec::new();
    for dir in config_roots() {
        files_named(&dir, ".clippy.toml", &mut found);
    }
    if root().join(".clippy.toml").exists() {
        found.push(root().join(".clippy.toml"));
    }
    assert!(
        found.is_empty(),
        "a .clippy.toml replaces the wall: {found:?}"
    );
}

/// Every Cargo config file of the repo: `.cargo/config.toml` and `.cargo/config`.
fn cargo_configs() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in config_roots() {
        for wanted in ["config.toml", "config"] {
            files_named(&dir, wanted, &mut found);
        }
    }
    for wanted in ["config.toml", "config"] {
        let own = root().join(".cargo").join(wanted);
        if own.exists() {
            found.push(own);
        }
    }
    found.retain(|p| p.parent().is_some_and(|d| d.ends_with(".cargo")));
    found.sort();
    found.dedup();
    found
}

/// The keys of a TOML table at every depth, with their dotted path.
fn all_keys(table: &toml::Table, prefix: &str, out: &mut Vec<String>) {
    for (key, value) in table {
        let full = format!("{prefix}{key}");
        out.push(full.clone());
        if let Some(inner) = value.as_table() {
            all_keys(inner, &format!("{full}."), out);
        }
    }
}

#[test]
fn no_cargo_config_weakens_clippy_or_the_flags_it_runs_with() {
    // `CLIPPY_CONF_DIR` in `[env]` moves the lookup of clippy.toml. `rustflags` can say `-A
    // clippy::disallowed_methods` or `--cap-lints warn`. A wrapper can replace clippy-driver. An alias
    // can replace `cargo clippy`.
    let configs = cargo_configs();
    assert!(
        configs.iter().any(|p| p.ends_with(".cargo/config.toml")),
        "found no .cargo/config.toml?"
    );
    for config in configs {
        let text = read(&config);
        for banned in [
            "CLIPPY_CONF_DIR",
            "CLIPPY_ARGS",
            "CLIPPY_DISABLE_DOCS_LINKS",
        ] {
            assert!(
                !text.contains(banned),
                "{} sets {banned}, which can move or weaken clippy.toml",
                config.display()
            );
        }
        let mut keys = Vec::new();
        all_keys(&toml_of(&config), "", &mut keys);
        for key in keys {
            let last = key.rsplit('.').next().unwrap_or("");
            assert!(
                !matches!(
                    last,
                    "rustflags" | "rustc-wrapper" | "rustc-workspace-wrapper"
                ),
                "{} sets `{key}`: a check crate takes the flags of the CI steps as they are",
                config.display()
            );
            assert!(
                !(key.starts_with("env.")
                    && matches!(
                        last,
                        "RUSTFLAGS"
                            | "CARGO_ENCODED_RUSTFLAGS"
                            | "RUSTC_WRAPPER"
                            | "RUSTC_WORKSPACE_WRAPPER"
                    )),
                "{} sets the environment variable {last}",
                config.display()
            );
            assert!(
                key != "alias.clippy",
                "{} defines an alias for `clippy`",
                config.display()
            );
        }
    }
}

/// The lines of a workflow file or action with the YAML comments cut off.
fn workflow_code(path: &Path) -> Vec<String> {
    read(path)
        .lines()
        .map(|l| {
            // A `#` starts a comment at the start of a line or after a space.
            let mut cut = l.len();
            for (i, _) in l.match_indices('#') {
                if i == 0 || l[..i].ends_with(' ') {
                    cut = i;
                    break;
                }
            }
            l[..cut].trim_end().to_owned()
        })
        .collect()
}

fn workflow_files() -> Vec<PathBuf> {
    let mut found = Vec::new();
    files_named_ext(&root().join(".github"), &mut found);
    found.sort();
    found
}

fn files_named_ext(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            files_named_ext(&path, out);
        } else if path.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            out.push(path);
        }
    }
}

#[test]
fn no_workflow_sets_flags_and_every_clippy_step_ends_in_deny_warnings() {
    let files = workflow_files();
    assert!(files.len() >= 4, "found only {files:?}");
    let mut clippy_steps = 0;
    for file in files {
        for line in workflow_code(&file) {
            for banned in [
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_BUILD_RUSTFLAGS",
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "CLIPPY_CONF_DIR",
                "CLIPPY_ARGS",
            ] {
                assert!(
                    !line.contains(banned),
                    "{} sets {banned}: `{line}`. Flags come from rust-toolchain.toml and the steps, nothing else",
                    file.display()
                );
            }
            // A command: `run: cargo clippy ..` or a line of a script that starts with it. A step name that
            // mentions clippy is not one.
            let command = line.trim_start().trim_start_matches("run: ");
            if command.starts_with("cargo clippy") {
                clippy_steps += 1;
                assert!(
                    line.trim_end().ends_with(" -- -D warnings")
                        && line.matches(" -- ").count() == 1,
                    "{}: a clippy step must end in exactly ` -- -D warnings`: `{line}`",
                    file.display()
                );
            }
        }
    }
    assert!(clippy_steps >= 3, "found only {clippy_steps} clippy steps");
}

/// The level of a lint entry of a manifest: `"allow"`, or `{ level = "allow", .. }`.
fn level(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => t
            .get("level")
            .and_then(|l| l.as_str())
            .unwrap_or("")
            .to_owned(),
        _ => String::new(),
    }
}

/// Whether a lint entry turns off something the wall rests on: `disallowed_*`, the groups that hold them,
/// and `warnings`.
fn turns_the_wall_down(key: &str, value: &toml::Value) -> bool {
    let key = key.strip_prefix("clippy::").unwrap_or(key);
    let relaxing = level(value) == "allow";
    relaxing && (key.starts_with("disallowed_") || matches!(key, "all" | "style" | "warnings"))
}

/// The lints of a `[lints]`-like table, `clippy` and `rust` tool tables flattened.
fn lint_entries(lints: &toml::Table) -> Vec<(String, &toml::Value)> {
    let mut out = Vec::new();
    for (tool, value) in lints {
        match value.as_table() {
            Some(table) if tool == "clippy" || tool == "rust" => {
                for (k, v) in table {
                    out.push((k.clone(), v));
                }
            }
            _ => out.push((tool.clone(), value)),
        }
    }
    out
}

#[test]
fn the_workspace_lints_do_not_turn_the_wall_down() {
    // Read as TOML, so a quoted key, a dotted key under `[workspace.lints]` and an inline table all
    // resolve to the same value as the plain form.
    let manifest = toml_of(&root().join("Cargo.toml"));
    if let Some(lints) = manifest
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .and_then(|l| l.as_table())
    {
        for (key, value) in lint_entries(lints) {
            assert!(
                !turns_the_wall_down(&key, value),
                "root Cargo.toml [workspace.lints] sets `{key}` to {value:?}, which turns the wall down"
            );
        }
    }
    assert!(
        manifest.get("lints").is_none(),
        "root Cargo.toml has a top-level `lints` table; the workspace lints are the only ones"
    );
}

#[test]
fn a_check_crate_takes_the_workspace_lints_as_they_are() {
    for dir in check_crates() {
        let manifest = toml_of(&dir.join("Cargo.toml"));
        let lints = manifest
            .get("lints")
            .and_then(|l| l.as_table())
            .unwrap_or_else(|| panic!("{}: Cargo.toml has no [lints]", name(&dir)));
        // Resolved: whatever the spelling (`[lints]`, `lints.workspace = true`, an inline table), the table is
        // exactly `workspace = true`. A commented `# [lints]` does not make one.
        let only_workspace =
            lints.len() == 1 && lints.get("workspace") == Some(&toml::Value::Boolean(true));
        assert!(
            only_workspace,
            "{}: `lints` must be exactly `workspace = true`, not {lints:?}",
            name(&dir)
        );
        // No platform table can carry lints (cargo has none), but make the resolved-value rule explicit.
        for (key, value) in lint_entries(lints) {
            assert!(!turns_the_wall_down(&key, value), "{}: {key}", name(&dir));
        }
    }
}

#[test]
fn the_lint_readers_see_every_spelling() {
    let parse = |s: &str| s.parse::<toml::Table>().expect("toml");
    let down = |text: &str| {
        let t = parse(text);
        let lints = t["workspace"]["lints"].as_table().expect("lints").clone();
        lint_entries(&lints)
            .iter()
            .any(|(k, v)| turns_the_wall_down(k, v))
    };
    for (what, text) in [
        (
            "plain",
            "[workspace.lints.clippy]\ndisallowed_methods = \"allow\"\n",
        ),
        (
            "quoted key",
            "[workspace.lints.clippy]\n\"disallowed_methods\" = \"allow\"\n",
        ),
        (
            "dotted key",
            "[workspace.lints]\nclippy.disallowed_methods = \"allow\"\n",
        ),
        (
            "inline table",
            "[workspace.lints.clippy]\ndisallowed_types = { level = \"allow\", priority = 1 }\n",
        ),
        (
            "the all group",
            "[workspace.lints.clippy]\nall = \"allow\"\n",
        ),
        ("warnings", "[workspace.lints.rust]\nwarnings = \"allow\"\n"),
        (
            "a tool prefix",
            "[workspace.lints.rust]\n\"clippy::disallowed_macros\" = \"allow\"\n",
        ),
    ] {
        assert!(down(text), "missed: {what}");
    }
    for (what, text) in [
        ("deny", "[workspace.lints.clippy]\nunwrap_used = \"deny\"\n"),
        (
            "warn",
            "[workspace.lints.clippy]\ndisallowed_methods = \"warn\"\n",
        ),
        (
            "unrelated allow",
            "[workspace.lints.clippy]\nmodule_name_repetitions = \"allow\"\n",
        ),
    ] {
        assert!(!down(text), "flagged: {what}");
    }
    // A check crate manifest whose `[lints]` is commented out has no `lints` table at all.
    let t = parse("# [lints]\nworkspace = true\n[package]\nname = \"x\"\n");
    assert!(t.get("lints").is_none());
    let t = parse("[lints]\nworkspace = true\n[lints.clippy]\ndisallowed_methods = \"allow\"\n");
    assert_ne!(t["lints"].as_table().map(|l| l.len()), Some(1));
    let t = parse("lints.workspace = true\n");
    assert_eq!(t["lints"].as_table().map(|l| l.len()), Some(1));
}

#[test]
fn a_check_crate_denies_the_print_lints() {
    // The print macros are in disallowed-macros too. These are the lints the carried M1-044 note names.
    for dir in check_crates() {
        let lib = read(&dir.join("src/lib.rs"));
        let stripped: String = lib.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            stripped.contains("#![deny(clippy::print_stdout,clippy::print_stderr)]"),
            "{}/src/lib.rs must say `#![deny(clippy::print_stdout, clippy::print_stderr)]`",
            name(&dir)
        );
    }
}
