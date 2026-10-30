// Only the writer builds an `HtmlSafeJson`: its text has been through the escapes. A caller cannot wrap
// raw text in one.
use rdy_engine::report::HtmlSafeJson;

fn main() {
    let _ = HtmlSafeJson("</script>".to_owned());
}
