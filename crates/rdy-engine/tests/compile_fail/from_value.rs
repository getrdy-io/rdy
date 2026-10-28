use rdy_engine::redact::Redacted;

fn main() {
    let _: Redacted<String> = Redacted::from("raw text".to_string());
}
