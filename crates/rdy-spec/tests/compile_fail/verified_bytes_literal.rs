use rdy_spec::VerifiedSpecBytes;

fn main() {
    let _ = VerifiedSpecBytes {
        yaml: b"apiVersion: rdy/v1".to_vec(),
        signature: None,
    };
}
