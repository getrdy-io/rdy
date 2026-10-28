use rdy_engine::redact::Redacted;

fn main() {
    let _: Redacted<String> = "raw text".to_string().into();
}
