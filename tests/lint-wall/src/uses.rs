//! One use of every item the lint wall bans (M1-044).
//!
//! Nothing here runs. Each use names the item as a value (a function pointer) or as a type in a
//! signature, which is enough for clippy's `disallowed_methods` and `disallowed_types` to report it.
//! `tests/clippy_wall.rs` runs clippy over this file under the root `clippy.toml` and under the
//! `clippy.toml` of each check crate, and fails if any entry does not report its item, or if a path in a
//! file stops resolving. A use is exact: the paths below are the paths of the clippy.toml entries.
//!
//! Adding an entry to a clippy.toml means adding its use here, in the same change.
//!
//! The kube entries are not here. `crates/rdy-checks-k8s/lint-wall/kube-use.rs.txt` holds them and
//! M1-107 carries their proof (backlog correction-11), because `kube` may only be a dependency of
//! `rdy-checks-k8s`.
//!
//! `rdy_engine::live_backend` does not exist yet (M1-045 builds it). Its use is added there, and until
//! then `tests/clippy_wall.rs` lists it as pending.

#![allow(dead_code, unused, deprecated)]

// ---- Process ------------------------------------------------------------------------------------

fn type_process_command(_: Option<std::process::Command>) {}
fn process_command_new() {
    let _ = std::process::Command::new::<&str>;
}
fn process_exit() {
    let _ = std::process::exit;
}
fn process_abort() {
    let _ = std::process::abort;
}
fn tokio_process_command_new() {
    let _ = tokio::process::Command::new::<&str>;
}

// ---- Files and directories ----------------------------------------------------------------------

fn type_fs_file(_: Option<std::fs::File>) {}
fn type_fs_open_options(_: Option<std::fs::OpenOptions>) {}
fn type_fs_dir_builder(_: Option<std::fs::DirBuilder>) {}
fn fs_read() {
    let _ = std::fs::read::<&str>;
}
fn fs_read_to_string() {
    let _ = std::fs::read_to_string::<&str>;
}
fn fs_read_dir() {
    let _ = std::fs::read_dir::<&str>;
}
fn fs_read_link() {
    let _ = std::fs::read_link::<&str>;
}
fn fs_metadata() {
    let _ = std::fs::metadata::<&str>;
}
fn fs_symlink_metadata() {
    let _ = std::fs::symlink_metadata::<&str>;
}
fn fs_canonicalize() {
    let _ = std::fs::canonicalize::<&str>;
}
fn fs_exists() {
    let _ = std::fs::exists::<&str>;
}
fn fs_write() {
    let _ = std::fs::write::<&str, &str>;
}
fn fs_copy() {
    let _ = std::fs::copy::<&str, &str>;
}
fn fs_rename() {
    let _ = std::fs::rename::<&str, &str>;
}
fn fs_remove_file() {
    let _ = std::fs::remove_file::<&str>;
}
fn fs_remove_dir() {
    let _ = std::fs::remove_dir::<&str>;
}
fn fs_remove_dir_all() {
    let _ = std::fs::remove_dir_all::<&str>;
}
fn fs_create_dir() {
    let _ = std::fs::create_dir::<&str>;
}
fn fs_create_dir_all() {
    let _ = std::fs::create_dir_all::<&str>;
}
fn fs_file_open() {
    let _ = std::fs::File::open::<&str>;
}
fn fs_file_create() {
    let _ = std::fs::File::create::<&str>;
}
fn fs_file_create_new() {
    let _ = std::fs::File::create_new::<&str>;
}
fn fs_open_options_new() {
    let _ = std::fs::OpenOptions::new;
}

// ---- Paths that touch the file system -----------------------------------------------------------

fn path_metadata() {
    let _ = std::path::Path::metadata;
}
fn path_symlink_metadata() {
    let _ = std::path::Path::symlink_metadata;
}
fn path_canonicalize() {
    let _ = std::path::Path::canonicalize;
}
fn path_read_link() {
    let _ = std::path::Path::read_link;
}
fn path_read_dir() {
    let _ = std::path::Path::read_dir;
}
fn path_exists() {
    let _ = std::path::Path::exists;
}
fn path_try_exists() {
    let _ = std::path::Path::try_exists;
}
fn path_is_file() {
    let _ = std::path::Path::is_file;
}
fn path_is_dir() {
    let _ = std::path::Path::is_dir;
}
fn path_is_symlink() {
    let _ = std::path::Path::is_symlink;
}

// ---- Links and permissions ----------------------------------------------------------------------

fn fs_hard_link() {
    let _ = std::fs::hard_link::<&str, &str>;
}
fn fs_soft_link() {
    let _ = std::fs::soft_link::<&str, &str>;
}
fn fs_set_permissions() {
    let _ = std::fs::set_permissions::<&str>;
}

#[cfg(unix)]
mod unix_links {
    fn unix_fs_symlink() {
        let _ = std::os::unix::fs::symlink::<&str, &str>;
    }
    fn unix_fs_chown() {
        let _ = std::os::unix::fs::chown::<&str>;
    }
    fn unix_fs_fchown() {
        let _ = std::os::unix::fs::fchown::<std::fs::File>;
    }
    fn unix_fs_lchown() {
        let _ = std::os::unix::fs::lchown::<&str>;
    }
    fn unix_fs_chroot() {
        let _ = std::os::unix::fs::chroot::<&str>;
    }
}

#[cfg(windows)]
mod windows_links {
    fn windows_fs_symlink_file() {
        let _ = std::os::windows::fs::symlink_file::<&str, &str>;
    }
    fn windows_fs_symlink_dir() {
        let _ = std::os::windows::fs::symlink_dir::<&str, &str>;
    }
}

// ---- Sockets ------------------------------------------------------------------------------------

fn type_tcp_stream(_: Option<std::net::TcpStream>) {}
fn type_tcp_listener(_: Option<std::net::TcpListener>) {}
fn type_udp_socket(_: Option<std::net::UdpSocket>) {}
fn type_socket2_socket(_: Option<socket2::Socket>) {}
fn tcp_stream_connect() {
    let _ = std::net::TcpStream::connect::<&str>;
}
fn tcp_stream_connect_timeout() {
    let _ = std::net::TcpStream::connect_timeout;
}
fn tcp_listener_bind() {
    let _ = std::net::TcpListener::bind::<&str>;
}
fn udp_socket_bind() {
    let _ = std::net::UdpSocket::bind::<&str>;
}
fn to_socket_addrs() {
    let _ = <&str as std::net::ToSocketAddrs>::to_socket_addrs;
}
fn tokio_tcp_stream_connect() {
    let _ = tokio::net::TcpStream::connect::<&str>;
}
fn tokio_udp_socket_bind() {
    let _ = tokio::net::UdpSocket::bind::<&str>;
}
fn tokio_tcp_listener_bind() {
    let _ = tokio::net::TcpListener::bind::<&str>;
}
fn tokio_lookup_host() {
    let _ = tokio::net::lookup_host::<&str>;
}

#[cfg(unix)]
mod unix_sockets {
    fn type_unix_stream(_: Option<std::os::unix::net::UnixStream>) {}
    fn type_unix_listener(_: Option<std::os::unix::net::UnixListener>) {}
    fn type_unix_datagram(_: Option<std::os::unix::net::UnixDatagram>) {}
    fn unix_stream_connect() {
        let _ = std::os::unix::net::UnixStream::connect::<&str>;
    }
    fn unix_stream_connect_addr() {
        let _ = std::os::unix::net::UnixStream::connect_addr;
    }
    fn unix_stream_pair() {
        let _ = std::os::unix::net::UnixStream::pair;
    }
    fn unix_listener_bind() {
        let _ = std::os::unix::net::UnixListener::bind::<&str>;
    }
    fn unix_listener_bind_addr() {
        let _ = std::os::unix::net::UnixListener::bind_addr;
    }
    fn unix_datagram_bind() {
        let _ = std::os::unix::net::UnixDatagram::bind::<&str>;
    }
    fn unix_datagram_bind_addr() {
        let _ = std::os::unix::net::UnixDatagram::bind_addr;
    }
    fn unix_datagram_unbound() {
        let _ = std::os::unix::net::UnixDatagram::unbound;
    }
    fn unix_datagram_pair() {
        let _ = std::os::unix::net::UnixDatagram::pair;
    }
    fn tokio_unix_stream_connect() {
        let _ = tokio::net::UnixStream::connect::<&str>;
    }
}

// ---- Threads and tasks --------------------------------------------------------------------------

fn type_thread_builder(_: Option<std::thread::Builder>) {}
fn thread_spawn() {
    let _ = std::thread::spawn::<fn(), ()>;
}
fn thread_scope() {
    let _ = std::thread::scope::<fn(&std::thread::Scope<'_, '_>), ()>;
}
fn thread_builder_spawn() {
    let _ = std::thread::Builder::spawn::<fn(), ()>;
}
fn thread_builder_spawn_scoped() {
    let _ = std::thread::Builder::spawn_scoped::<fn(), ()>;
}
fn tokio_spawn() {
    let _ = tokio::spawn::<std::future::Ready<()>>;
}
fn tokio_spawn_blocking() {
    let _ = tokio::task::spawn_blocking::<fn(), ()>;
}

// ---- Environment --------------------------------------------------------------------------------

fn env_var() {
    let _ = std::env::var::<&str>;
}
fn env_var_os() {
    let _ = std::env::var_os::<&str>;
}
fn env_vars() {
    let _ = std::env::vars;
}
fn env_vars_os() {
    let _ = std::env::vars_os;
}
fn env_current_dir() {
    let _ = std::env::current_dir;
}
fn env_current_exe() {
    let _ = std::env::current_exe;
}
fn env_home_dir() {
    let _ = std::env::home_dir;
}
fn env_temp_dir() {
    let _ = std::env::temp_dir;
}
fn env_args() {
    let _ = std::env::args;
}
fn env_args_os() {
    let _ = std::env::args_os;
}
// `set_var` and `remove_var` are `unsafe fn`. Naming one as a value needs no `unsafe` block.
fn env_set_var() {
    let _ = std::env::set_var::<&str, &str>;
}
fn env_remove_var() {
    let _ = std::env::remove_var::<&str>;
}
fn env_set_current_dir() {
    let _ = std::env::set_current_dir::<&str>;
}

// ---- Leaks --------------------------------------------------------------------------------------

fn box_leak() {
    let _ = Box::<u8>::leak;
}
fn string_leak() {
    let _ = String::leak;
}
fn vec_leak() {
    let _ = Vec::<u8>::leak;
}

// ---- Terminal -----------------------------------------------------------------------------------

fn io_stdout() {
    let _ = std::io::stdout;
}
fn io_stderr() {
    let _ = std::io::stderr;
}
fn io_stdin() {
    let _ = std::io::stdin;
}
fn macro_print() {
    print!("");
}
fn macro_println() {
    println!();
}
fn macro_eprint() {
    eprint!("");
}
fn macro_eprintln() {
    eprintln!();
}

// ---- Root clippy.toml: clap, the clock -----------------------------------------------------------

#[derive(clap::Parser)]
struct Cli {}

fn clap_parser_parse() {
    let _ = <Cli as clap::Parser>::parse;
}
fn clap_parser_parse_from() {
    let _ = <Cli as clap::Parser>::parse_from::<Vec<&str>, &str>;
}
fn clap_command_get_matches() {
    let _ = clap::Command::get_matches;
}
fn clap_command_get_matches_from() {
    let _ = clap::Command::get_matches_from::<Vec<&str>, &str>;
}
fn clap_command_get_matches_mut() {
    let _ = clap::Command::get_matches_mut;
}
fn clap_parser_update_from() {
    let _ = <Cli as clap::Parser>::update_from::<Vec<&str>, &str>;
}
fn clap_error_print() {
    let _ = clap::error::Error::<clap::error::RichFormatter>::print;
}
fn clap_error_exit() {
    let _ = clap::error::Error::<clap::error::RichFormatter>::exit;
}
fn spec_load_at() {
    let _ = rdy_spec::load_at;
}

// ---- Engine -------------------------------------------------------------------------------------

fn engine_table_run() {
    let _ = rdy_engine::exec::table::run;
}
fn engine_exec_run() {
    let _ = rdy_engine::exec::run;
}
// `impl Trait` arguments cannot take a turbofish, so these two are calls. Nothing calls the functions.
fn engine_exec_spec_new() {
    let _ = rdy_engine::exec::ExecSpec::new("x", std::time::Duration::ZERO);
}
fn engine_test_run_context(run: &rdy_engine::testing::TestRun, os: rdy_engine::check::Os) {
    let _ = run.context("x", os, Vec::<rdy_engine::check::Need>::new());
}

// ---- First-party escapes (PC-47) ----------------------------------------------------------------
// The run owns the output folder, the process-wide effects and the spec. A check owns none of them.

fn output_report_parent_open() {
    let _ = rdy_engine::output::ReportParent::open;
}
fn output_create_new() {
    let _ = rdy_engine::output::OutputDir::create_new;
}
fn output_create_new_in() {
    let _ = rdy_engine::output::OutputDir::create_new_in;
}
fn output_write_atomic() {
    let _ = rdy_engine::output::OutputDir::write_atomic::<Vec<u8>>;
}
fn output_write_spec() {
    let _ = rdy_engine::output::OutputDir::write_spec;
}
fn output_default_report_parent() {
    let _ = rdy_engine::output::default_report_parent;
}
fn exec_kill_all_groups() {
    let _ = rdy_engine::exec::kill_all_groups;
}
fn exec_harden_umask() {
    let _ = rdy_engine::exec::harden_umask;
}
fn exec_inherited_fds() {
    let _ = rdy_engine::exec::inherited_fds;
}
fn spec_load() {
    let _ = rdy_spec::load;
}
fn type_watchdog_process_effects(_: Option<rdy_engine::watchdog::ProcessEffects>) {}
fn watchdog_effects_exit(effects: &dyn rdy_engine::watchdog::Effects) {
    effects.exit(0);
}
fn watchdog_effects_kill_groups(effects: &dyn rdy_engine::watchdog::Effects) {
    effects.kill_groups();
}
fn watchdog_effects_notice(effects: &dyn rdy_engine::watchdog::Effects) {
    effects.notice();
}
fn watchdog_start() {
    let _ = rdy_engine::watchdog::Watchdog::start;
}
fn watchdog_write_state_claim() {
    let _ = rdy_engine::watchdog::WriteState::claim;
}
fn watchdog_write_state_claim_or_park() {
    let _ = rdy_engine::watchdog::WriteState::claim_or_park;
}
fn watchdog_write_state_finish() {
    let _ = rdy_engine::watchdog::WriteState::finish;
}
fn exec_live_groups() {
    let _ = rdy_engine::exec::live_groups;
}
