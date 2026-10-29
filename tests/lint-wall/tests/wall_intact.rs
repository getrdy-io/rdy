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

/// The floor: every non-kube entry of 02 Appendix A, as of M1-044 and PC-48. A check crate's clippy.toml may
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
    (Kind::Method, "rdy_engine::probe::Probe::kube_call"),
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
    (Kind::Method, "rdy_engine::probe::ProbeHub::new"),
    (Kind::Method, "rdy_engine::probe::ProbeHub::run_probe"),
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

/// What is wrong with the text of one Cargo config, as one line each. Empty when it is fine.
///
/// `CLIPPY_CONF_DIR` in `[env]` moves the lookup of clippy.toml. `rustflags` can say `-A
/// clippy::disallowed_methods` or `--cap-lints warn`. A wrapper can replace clippy-driver. An alias can
/// replace `cargo clippy`. `paths`, `[source]` and `[patch]` swap the code of a dependency for other code.
fn config_problems(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for banned in [
        "CLIPPY_CONF_DIR",
        "CLIPPY_ARGS",
        "CLIPPY_DISABLE_DOCS_LINKS",
    ] {
        if text.contains(banned) {
            problems.push(format!(
                "sets {banned}, which can move or weaken clippy.toml"
            ));
        }
    }
    let table = match text.parse::<toml::Table>() {
        Ok(t) => t,
        Err(e) => return vec![format!("is not TOML: {e}")],
    };
    let mut keys = Vec::new();
    all_keys(&table, "", &mut keys);
    for key in keys {
        let last = key.rsplit('.').next().unwrap_or("");
        if matches!(
            last,
            "rustflags" | "rustc-wrapper" | "rustc-workspace-wrapper"
        ) {
            problems.push(format!(
                "sets `{key}`: a check crate takes the flags of the CI steps as they are"
            ));
        }
        if key.starts_with("env.")
            && matches!(
                last,
                "RUSTFLAGS"
                    | "CARGO_ENCODED_RUSTFLAGS"
                    | "RUSTC_WRAPPER"
                    | "RUSTC_WORKSPACE_WRAPPER"
            )
        {
            problems.push(format!("sets the environment variable {last}"));
        }
        if key == "alias.clippy" {
            problems.push("defines an alias for `clippy`".to_owned());
        }
        // Top-level tables that replace where a dependency's code comes from.
        if matches!(key.split('.').next(), Some("paths" | "source" | "patch")) {
            problems.push(format!(
                "sets `{key}`, which swaps the code of a dependency"
            ));
        }
    }
    problems
}

#[test]
fn no_cargo_config_weakens_clippy_or_the_flags_it_runs_with() {
    let configs = cargo_configs();
    assert!(
        configs.iter().any(|p| p.ends_with(".cargo/config.toml")),
        "found no .cargo/config.toml?"
    );
    for config in configs {
        let problems = config_problems(&read(&config));
        assert!(problems.is_empty(), "{}: {problems:?}", config.display());
    }
}

#[test]
fn the_config_reader_sees_every_way_to_weaken_clippy() {
    for (what, text) in [
        (
            "rustflags in build",
            "[build]\nrustflags = [\"-A\", \"clippy::disallowed_methods\"]\n",
        ),
        (
            "rustflags for a target",
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"--cap-lints\", \"warn\"]\n",
        ),
        (
            "a target cfg",
            "[target.'cfg(unix)']\nrustflags = [\"-A\", \"warnings\"]\n",
        ),
        (
            "a compiler wrapper",
            "[build]\nrustc-wrapper = \"/tmp/w\"\n",
        ),
        (
            "a workspace wrapper",
            "[build]\nrustc-workspace-wrapper = \"/tmp/w\"\n",
        ),
        ("CLIPPY_CONF_DIR", "[env]\nCLIPPY_CONF_DIR = \"/tmp/x\"\n"),
        ("RUSTFLAGS in env", "[env]\nRUSTFLAGS = \"-A warnings\"\n"),
        ("an alias for clippy", "[alias]\nclippy = \"check\"\n"),
        ("paths", "paths = [\"/tmp/fake\"]\n"),
        (
            "a source replacement",
            "[source.crates-io]\nreplace-with = \"mine\"\n[source.mine]\ndirectory = \"/tmp/v\"\n",
        ),
        (
            "a patch",
            "[patch.crates-io]\nkube = { path = \"/tmp/kube\" }\n",
        ),
        ("not TOML", "[build\n"),
    ] {
        assert!(!config_problems(text).is_empty(), "missed: {what}");
    }
    for (what, text) in [
        (
            "rustdocflags",
            "[build]\nrustdocflags = [\"-D\", \"warnings\"]\n",
        ),
        (
            "a linker",
            "[target.aarch64-unknown-linux-musl]\nlinker = \"scripts/musl-pie-linker.sh\"\n",
        ),
        (
            "an unrelated alias",
            "[alias]\nxtask = \"run --quiet --package xtask --\"\n",
        ),
        ("empty", ""),
    ] {
        assert!(config_problems(text).is_empty(), "flagged: {what}");
    }
}

/// The lines of a workflow file or action with the YAML comments cut off.
fn workflow_lines(text: &str) -> Vec<String> {
    text.lines()
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

/// The three clippy commands of CI, exactly. A fourth, or a change to one (`--config`, `--exclude`,
/// `--cap-lints`, a dropped `--all-targets`), is a change to this list, which is in CODEOWNERS.
const CLIPPY_COMMANDS: &[&str] = &[
    "cargo clippy --workspace --all-targets --locked -- -D warnings",
    "cargo clippy --locked -p rdy-engine --no-default-features --all-targets -- -D warnings",
    "cargo clippy --locked -p rdy-engine --no-default-features --features testing --all-targets -- -D warnings",
];

/// Names a workflow may not carry: flags and wrappers that change how clippy judges, `continue-on-error`,
/// which lets a red step pass, `--config`, which sets a Cargo alias or flags on the command line, and
/// `GITHUB_PATH`, which puts another `cargo` or `clippy-driver` first. Compared in lower case.
const WORKFLOW_BANNED: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CLIPPY_CONF_DIR",
    "CLIPPY_ARGS",
    "continue-on-error",
    "GITHUB_PATH",
    "--config",
];

/// The `CARGO_` environment names a workflow may set: output and speed knobs, the profile's debug level
/// (any `CARGO_PROFILE_*`) and the network retry count. These are the ones `.github/` uses today
/// (`CARGO_TERM_COLOR`, `CARGO_INCREMENTAL`, `CARGO_PROFILE_DEV_DEBUG`, `CARGO_NET_RETRY`). Every other
/// `CARGO_` name can change what `cargo clippy` runs: `CARGO_ALIAS_CLIPPY`, `CARGO_HOME` (another
/// config), `CARGO_SOURCE_*` and `CARGO_PATCH_*` (other code), `CARGO_BUILD_*`, `CARGO_TARGET_*`.
const CARGO_ENV_ALLOWED: &[&str] = &["CARGO_TERM_COLOR", "CARGO_INCREMENTAL", "CARGO_NET_RETRY"];

fn cargo_env_allowed(name: &str) -> bool {
    CARGO_ENV_ALLOWED.contains(&name) || name.starts_with("CARGO_PROFILE_")
}

/// What is wrong with one workflow: banned names (any case), `CARGO_` names off the allowlist and a
/// clippy run that is not a `cargo clippy` command; and, appended to `commands`, every clippy command in
/// it (`run: cargo clippy ..` and `- run: cargo clippy ..`).
fn workflow_problems(text: &str, commands: &mut Vec<String>) -> Vec<String> {
    let mut problems = Vec::new();
    for line in workflow_lines(text) {
        let lower = line.to_lowercase();
        for banned in WORKFLOW_BANNED {
            if lower.contains(&banned.to_lowercase()) {
                problems.push(format!("`{line}` carries {banned}"));
            }
        }
        // A word is a run of letters, digits and `_`. `RDY_REQUIRE_CARGO_DENY` is one word that does not
        // start with `CARGO_`.
        for word in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            let upper = word.to_uppercase();
            if upper.starts_with("CARGO_") && !cargo_env_allowed(&upper) {
                problems.push(format!("`{line}` sets or reads {word}"));
            }
        }
        // A command: `run: cargo clippy ..`, `- run: cargo clippy ..` or a line of a script that starts
        // with it. A step name that mentions clippy is not one. Any other line that runs clippy is not
        // one of the pinned commands, so it is a problem.
        let trimmed = line.trim_start();
        let item = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let command = item.strip_prefix("run: ").unwrap_or(item);
        if command.starts_with("cargo clippy") {
            commands.push(command.trim_end().to_owned());
        } else if lower.contains("clippy") && !item.starts_with("name:") {
            problems.push(format!("`{line}` runs clippy in a way the pin cannot see"));
        }
    }
    problems
}

#[test]
fn no_workflow_sets_flags_and_the_clippy_steps_are_the_three_pinned_ones() {
    let files = workflow_files();
    assert!(files.len() >= 4, "found only {files:?}");
    let mut commands = Vec::new();
    for file in &files {
        let problems = workflow_problems(&read(file), &mut commands);
        assert!(
            problems.is_empty(),
            "{}: {problems:?}. Flags come from rust-toolchain.toml and the steps, nothing else",
            file.display()
        );
    }
    commands.sort();
    let mut want: Vec<String> = CLIPPY_COMMANDS.iter().map(|c| (*c).to_owned()).collect();
    want.sort();
    assert_eq!(
        commands, want,
        "the clippy commands of the workflows must be exactly the pinned ones (CLIPPY_COMMANDS in wall_intact.rs)"
    );
    for c in &commands {
        assert!(
            c.ends_with(" -- -D warnings") && c.matches(" -- ").count() == 1,
            "{c}"
        );
    }
}

#[test]
fn the_workflow_reader_sees_what_it_must() {
    let check = |text: &str| {
        let mut commands = Vec::new();
        let problems = workflow_problems(text, &mut commands);
        (problems, commands)
    };
    for (what, text) in [
        ("RUSTFLAGS", "    env:\n      RUSTFLAGS: -A warnings\n"),
        (
            "RUSTFLAGS in another case",
            "    env:\n      rustflags: -A warnings\n",
        ),
        ("a wrapper", "    env:\n      Rustc_Wrapper: x\n"),
        ("continue-on-error", "    continue-on-error: true\n"),
        (
            "continue-on-error in upper case",
            "    CONTINUE-ON-ERROR: true\n",
        ),
        ("CLIPPY_CONF_DIR", "      CLIPPY_CONF_DIR: /tmp\n"),
        (
            "a Cargo alias",
            "      CARGO_ALIAS_CLIPPY: clippy -A warnings\n",
        ),
        ("an alias in lower case", "      cargo_alias_clippy: x\n"),
        ("CARGO_HOME", "      CARGO_HOME: /tmp/evil\n"),
        (
            "CARGO_SOURCE",
            "      CARGO_SOURCE_CRATES_IO_REPLACE_WITH: x\n",
        ),
        ("CARGO_PATCH", "      CARGO_PATCH_CRATES_IO: x\n"),
        ("CARGO_BUILD_RUSTC", "      CARGO_BUILD_RUSTC: x\n"),
        (
            "CARGO_HOME in a script",
            "        run: CARGO_HOME=/tmp cargo test\n",
        ),
        (
            "CARGO_HOME read in a script",
            "        run: ls \"${CARGO_HOME}\"\n",
        ),
        (
            "a write to GITHUB_PATH",
            "          echo /tmp/bin >> \"$GITHUB_PATH\"\n",
        ),
        (
            "a write to GITHUB_PATH, lower case",
            "          echo x >> $github_path\n",
        ),
        (
            "--config",
            "        run: cargo --config alias.clippy=\"x\" test\n",
        ),
        (
            "clippy run by another command",
            "        run: sh -c 'cargo clippy'\n",
        ),
        ("clippy-driver", "        run: clippy-driver --version\n"),
    ] {
        assert!(!check(text).0.is_empty(), "missed: {what}");
    }
    // A comment is not code.
    assert!(
        check("# RUSTFLAGS and continue-on-error are banned\n")
            .0
            .is_empty()
    );
    let (_, commands) =
        check("        run: cargo clippy --workspace --exclude rdy -- -D warnings\n");
    assert_eq!(commands.len(), 1);
    assert!(!CLIPPY_COMMANDS.contains(&commands[0].as_str()));
    let (problems, commands) = check("      - name: cargo clippy\n");
    assert!(commands.is_empty() && problems.is_empty());
    // A list item with `run:` is a command too.
    let (_, commands) = check("      - run: cargo clippy --workspace -- -D warnings\n");
    assert_eq!(commands, ["cargo clippy --workspace -- -D warnings"]);
    let (_, commands) =
        check("      - run: cargo clippy --workspace --exclude rdy -- -D warnings\n");
    assert!(!CLIPPY_COMMANDS.contains(&commands[0].as_str()));
    // What `.github/` sets today passes, and so does a variable that only contains the word.
    for ok in [
        "  CARGO_TERM_COLOR: always\n",
        "  CARGO_INCREMENTAL: \"0\"\n",
        "  CARGO_PROFILE_DEV_DEBUG: line-tables-only\n",
        "  CARGO_PROFILE_TEST_DEBUG: 0\n",
        "  CARGO_NET_RETRY: \"3\"\n",
        "          RDY_REQUIRE_CARGO_DENY: \"1\"\n",
        "          sudo --preserve-env=RUST_BACKTRACE,CARGO_TERM_COLOR,RDY_REQUIRE_ROOT \\\n",
        "          echo \"CC_x=musl-gcc\" >> \"$GITHUB_ENV\"\n",
    ] {
        assert!(check(ok).0.is_empty(), "flagged: {ok}");
    }
}

#[test]
fn the_root_manifest_replaces_no_dependency() {
    // `[patch]` and `[replace]` swap the code of a dependency by name, below the allowlist and deny.
    let manifest = toml_of(&root().join("Cargo.toml"));
    for key in ["patch", "replace"] {
        assert!(
            manifest.get(key).is_none(),
            "root Cargo.toml has [{key}]: it swaps the code of a dependency"
        );
    }
    assert!(
        manifest
            .get("workspace")
            .and_then(|w| w.get("patch").or_else(|| w.get("replace")))
            .is_none(),
        "root Cargo.toml has a patch or replace under [workspace]"
    );
}

#[test]
fn no_agent_checkout_is_tracked() {
    // The walks skip `.claude/worktrees/` because it holds other copies of this repository on a
    // developer's machine. That is only safe while git never tracks anything under it.
    if !root().join(".git").exists() {
        eprintln!("SKIPPED: not a git checkout");
        return;
    }
    let out = std::process::Command::new("git")
        .current_dir(root())
        .args(["ls-files", "--", ".claude/worktrees"])
        .output()
        .expect("start git");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tracked = String::from_utf8_lossy(&out.stdout);
    assert!(
        tracked.trim().is_empty(),
        "files under .claude/worktrees are tracked, and the wall's walks skip that directory: {tracked}"
    );
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

/// The three lints of the wall. A check crate forbids them, so the compiler refuses an `allow`,
/// `expect` or `warn` of any of them, however a macro builds it (E0453 under clippy). The grep of
/// `allow_grep.rs` is the second layer: it reads tokens and cannot model `macro_rules!`.
const WALL_LINTS: [&str; 3] = [
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
    "clippy::disallowed_macros",
];

/// The check crates whose `lib.rs` cannot carry the forbid at the root, with the modules that hold the
/// exception. A forbid at the root makes an `allow` in a child an error, so the root has none and every
/// other module has it. `rdy-checks-k8s::client` builds the one guarded kube client (ADR 0010, 0031).
const MODULE_WISE: &[(&str, &[&str])] = &[("rdy-checks-k8s", &["client"])];

/// Integration test roots that are not forbidden: the k8s client tests, which start mock API servers and
/// plugin scripts. They are on the allowlist of `allow_grep.rs` for the same reason.
const TEST_ROOTS_EXEMPT: &[&str] = &[
    "rdy-checks-k8s/tests/client.rs",
    "rdy-checks-k8s/tests/guard.rs",
    "rdy-checks-k8s/tests/rbac_example.rs",
    "rdy-checks-k8s/tests/live_cluster.rs",
    "rdy-checks-k8s/tests/tls.rs",
];

/// Whether one of the attributes is `forbid(..)` of all three wall lints. An attribute inside `cfg_attr`
/// does not count: it can be switched off.
fn forbids_the_wall(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("forbid") {
            return false;
        }
        let Ok(paths) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        ) else {
            return false;
        };
        let named: Vec<String> = paths
            .iter()
            .map(|p| {
                p.segments
                    .iter()
                    .map(|s| s.ident.to_string().replace("r#", ""))
                    .collect::<Vec<_>>()
                    .join("::")
            })
            .collect();
        WALL_LINTS.iter().all(|l| named.iter().any(|n| n == l))
    })
}

/// What is wrong with the root file of a crate that forbids at the root.
fn root_problem(source: &str) -> Option<String> {
    match syn::parse_file(source) {
        Ok(file) if forbids_the_wall(&file.attrs) => None,
        Ok(_) => Some(
            "no `#![forbid(clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]`"
                .to_owned(),
        ),
        Err(e) => Some(format!("does not parse: {e}")),
    }
}

/// What is wrong with a `lib.rs` that forbids module by module: an item that is not a `mod` or a `use`
/// (it would sit at the root with no forbid) and a module outside `exempt` with no forbid on it.
fn module_problems(source: &str, exempt: &[&str]) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(e) => return vec![format!("does not parse: {e}")],
    };
    let mut problems = Vec::new();
    for item in &file.items {
        match item {
            syn::Item::Mod(m) => {
                let name = m.ident.to_string().replace("r#", "");
                if !exempt.contains(&name.as_str()) && !forbids_the_wall(&m.attrs) {
                    problems.push(format!("module `{name}` has no forbid"));
                }
            }
            syn::Item::Use(_) => {}
            _ => problems.push(
                "an item other than `mod` or `use` at the root, where the forbid cannot reach it"
                    .to_owned(),
            ),
        }
    }
    problems
}

/// Every Rust file that is the root of a target of a check crate: `src/lib.rs`, `src/main.rs`,
/// `src/bin/`, `build.rs`, and the `.rs` files (and `main.rs` of a folder) under `tests/`, `benches/`
/// and `examples/`.
fn target_roots(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for fixed in ["src/lib.rs", "src/main.rs", "build.rs"] {
        if dir.join(fixed).is_file() {
            found.push(dir.join(fixed));
        }
    }
    for sub in ["src/bin", "tests", "benches", "examples"] {
        let Ok(read_dir) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for entry in read_dir {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|x| x == "rs") && path.is_file() {
                found.push(path);
            } else if path.join("main.rs").is_file() {
                found.push(path.join("main.rs"));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn a_check_crate_forbids_the_disallowed_lints_so_no_macro_can_allow_them() {
    for dir in check_crates() {
        let crate_name = name(&dir);
        let manifest = toml_of(&dir.join("Cargo.toml"));
        for table in ["bin", "test", "bench", "example"] {
            assert!(
                manifest.get(table).is_none(),
                "{crate_name}: a [[{table}]] target can name any file as a root. Use the default layout"
            );
        }
        assert!(
            manifest
                .get("lib")
                .and_then(|l| l.as_table())
                .is_none_or(|l| l.get("path").is_none()),
            "{crate_name}: [lib] path moves the root of the crate"
        );
        let module_wise = MODULE_WISE.iter().find(|(c, _)| *c == crate_name);
        for root_file in target_roots(&dir) {
            let relative = root_file
                .strip_prefix(dir.parent().expect("crates/"))
                .expect("under crates/")
                .to_string_lossy()
                .replace('\\', "/");
            let source = read(&root_file);
            if relative.ends_with("/src/lib.rs")
                && let Some((_, exempt)) = module_wise
            {
                assert!(
                    root_problem(&source).is_some(),
                    "{relative}: forbids at the root, so remove {crate_name} from MODULE_WISE"
                );
                let problems = module_problems(&source, exempt);
                assert!(problems.is_empty(), "{relative}: {problems:?}");
            } else if TEST_ROOTS_EXEMPT.contains(&relative.as_str()) {
                continue;
            } else if let Some(problem) = root_problem(&source) {
                panic!(
                    "{relative}: {problem}. The compiler must refuse an allow of the wall, \
                     including one a macro builds (M1-044, 02 \"Lint wall\")"
                );
            }
        }
    }
    for exempt in TEST_ROOTS_EXEMPT {
        assert!(
            root().join("crates").join(exempt).is_file(),
            "{exempt} is exempt but missing: remove it from TEST_ROOTS_EXEMPT"
        );
    }
}

#[test]
fn the_forbid_reader_sees_what_it_must() {
    let all = "clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros";
    for (what, source) in [
        ("all three", format!("#![forbid({all})]")),
        (
            "other lints around them",
            format!("#![forbid(unsafe_code, {all})]"),
        ),
        (
            "spaces and a newline",
            "#![forbid(clippy :: disallowed_methods,\n clippy::disallowed_types, clippy::r#disallowed_macros)]"
                .to_owned(),
        ),
        (
            "two attributes",
            format!("#![forbid({all})]\n#![forbid(unsafe_code)]"),
        ),
    ] {
        assert!(root_problem(&source).is_none(), "refused: {what}");
    }
    for (what, source) in [
        ("nothing", String::new()),
        ("deny", format!("#![deny({all})]")),
        (
            "two of three",
            "#![forbid(clippy::disallowed_methods, clippy::disallowed_types)]".to_owned(),
        ),
        ("in a comment", format!("// #![forbid({all})]\nfn f() {{}}")),
        ("in cfg_attr", format!("#![cfg_attr(test, forbid({all}))]")),
        (
            "on a function, not the crate",
            format!("#[forbid({all})] fn f() {{}}"),
        ),
        (
            "the print lints only",
            "#![deny(clippy::print_stdout, clippy::print_stderr)]".to_owned(),
        ),
        ("a file that does not parse", "#![forbid(".to_owned()),
    ] {
        assert!(root_problem(&source).is_some(), "accepted: {what}");
    }

    // Module by module.
    let ok = format!("//! doc\nuse std::fmt;\n#[forbid({all})]\nmod a;\npub mod client;\n");
    assert!(module_problems(&ok, &["client"]).is_empty());
    for (what, source) in [
        (
            "a module with no forbid",
            "mod a;\npub mod client;\n".to_owned(),
        ),
        ("a module with a deny", format!("#[deny({all})]\nmod a;\n")),
        (
            "a function at the root",
            "pub mod client;\nfn f() {}\n".to_owned(),
        ),
        (
            "a macro at the root",
            "pub mod client;\nmacro_rules! m { () => {}; }\n".to_owned(),
        ),
        (
            "an inline module with no forbid",
            "mod a { pub fn f() {} }\n".to_owned(),
        ),
        ("a file that does not parse", "mod a".to_owned()),
    ] {
        assert!(
            !module_problems(&source, &["client"]).is_empty(),
            "accepted: {what}"
        );
    }
}
