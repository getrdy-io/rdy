use rdy_engine::redact::Redacted;

fn needs_deserialize<T: serde::de::DeserializeOwned>() {}

fn main() {
    needs_deserialize::<Redacted<String>>();
}
