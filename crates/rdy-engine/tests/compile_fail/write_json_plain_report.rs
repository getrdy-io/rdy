// The real writer takes a `RedactedReport` and nothing else (ADR 0015 decision 4, M1-055). A plain
// `Report`, which no redactor has seen, must not fit `json_bytes` or `write_json`.
use rdy_engine::report::{json_bytes, write_json};
use rdy_spec::result::Report;

fn plain(report: &Report) {
    let _ = json_bytes(report);
    let _ = write_json(report, &mut std::io::sink());
}

fn main() {
    let _ = plain;
}
