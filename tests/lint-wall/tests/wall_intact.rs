//! The wall cannot be turned down without a test failing (M1-044, INV-07).
//!
//! The drift tests of `clippy_wall.rs` compare the check crates to each other. These tests close the ways
//! to weaken all of them at once: a hardcoded floor of the 02 Appendix A entries, a `.clippy.toml` that
//! replaces `clippy.toml`, `CLIPPY_CONF_DIR` set from a Cargo config, and a lint override in the root
//! manifest.

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

/// Every file named `name` under `dir`, in every directory.
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

#[test]
fn no_dot_clippy_toml_overrides_a_clippy_toml() {
    // Clippy reads `.clippy.toml` before `clippy.toml`, so one in a check crate replaces the wall.
    let base = root();
    let mut found = Vec::new();
    for top in ["crates", "tests", "ci"] {
        files_named(&base.join(top), ".clippy.toml", &mut found);
    }
    if base.join(".clippy.toml").exists() {
        found.push(base.join(".clippy.toml"));
    }
    assert!(
        found.is_empty(),
        "a .clippy.toml replaces the wall: {found:?}"
    );
}

#[test]
fn no_cargo_config_points_clippy_at_another_directory() {
    // `CLIPPY_CONF_DIR` in a `[env]` table of a Cargo config moves the lookup of clippy.toml.
    let base = root();
    let mut configs = Vec::new();
    for wanted in ["config.toml", "config"] {
        for top in [".cargo", "crates", "tests", "ci"] {
            let mut found = Vec::new();
            files_named(&base.join(top), wanted, &mut found);
            configs.extend(
                found
                    .into_iter()
                    .filter(|p| p.parent().is_some_and(|d| d.ends_with(".cargo"))),
            );
        }
    }
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
    }
}

/// The lines of the table `[header]` of a manifest, with comments cut off.
fn table_lines(text: &str, header: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.starts_with('[') {
            inside = t == format!("[{header}]");
            continue;
        }
        if inside && !t.is_empty() {
            out.push(t.to_owned());
        }
    }
    out
}

#[test]
fn the_workspace_lints_do_not_turn_the_wall_down() {
    let manifest = read(&root().join("Cargo.toml"));
    for header in ["workspace.lints.clippy", "workspace.lints.rust"] {
        for line in table_lines(&manifest, header) {
            let key = line.split('=').next().unwrap_or("").trim().to_owned();
            assert!(
                !key.starts_with("disallowed_")
                    && key != "all"
                    && key != "style"
                    && key != "warnings"
                    && !key.starts_with("clippy::"),
                "root Cargo.toml [{header}] has `{line}`, which changes how the wall is judged"
            );
        }
    }
    // A check crate takes the workspace lints as they are (allow_grep.rs checks its manifest too), and its
    // lib.rs must not say otherwise at the top.
    assert!(
        !manifest.contains("[workspace.lints.clippy.disallowed"),
        "a disallowed_* lint table in the root manifest"
    );
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
