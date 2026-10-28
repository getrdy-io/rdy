use rdy_engine::redact::{Redactor, TagKey};

fn main() {
    let Ok(key) = TagKey::generate() else { return };
    let mut out = Redactor::new(key).redact_str("hello");
    out.push_str("raw text");
}
