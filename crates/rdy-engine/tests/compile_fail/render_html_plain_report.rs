// The real renderer takes a `RedactedReport` and nothing else (ADR 0015 decision 4, M1-077). A plain
// `Report`, which no redactor has seen, must not fit `render_html`.
use rdy_engine::report::render_html;
use rdy_spec::result::Report;

fn plain(report: &Report) {
    let _ = render_html(report);
}

fn main() {
    let _ = plain;
}
