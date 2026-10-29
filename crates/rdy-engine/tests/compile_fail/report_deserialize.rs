use rdy_engine::redact::RedactedReport;

fn needs_deserialize<T: serde::de::DeserializeOwned>() {}

fn main() {
    needs_deserialize::<RedactedReport>();
}
