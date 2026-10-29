use rdy_engine::redact::RedactedReport;

fn edit(mut report: RedactedReport) {
    report.complete = false;
}

fn main() {
    let _ = edit;
}
