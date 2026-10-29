// Stand-ins with the signatures of the writers and renderers (02 "output, report, redact", ADR 0015
// decision 4). The real ones take `&RedactedReport` and nothing else, so a plain `Report` must not fit.
use rdy_engine::redact::RedactedReport;
use rdy_spec::result::Report;

fn write_json(_report: &RedactedReport) {}
fn render_html(_report: &RedactedReport) {}
fn render_terminal(_report: &RedactedReport) {}

fn all_three(report: &Report) {
    write_json(report);
    render_html(report);
    render_terminal(report);
}

fn main() {
    let _ = all_three;
}
