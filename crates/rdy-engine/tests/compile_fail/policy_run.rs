use rdy_engine::exec::policy::{Cmd, run};
use std::time::Duration;

// The policy runner does not look at the command table. Only `exec::table::run` is public, so a check
// crate cannot start a command that has no entry.
fn main() {
    let cmd = Cmd::new("true", Duration::from_secs(1));
    let _ = run(cmd);
}
