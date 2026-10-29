use rdy_engine::redact::RedactedReport;
use rdy_spec::result::Report;

fn launder(report: Report) -> RedactedReport {
    report.into()
}

fn main() {
    let _ = launder;
}
