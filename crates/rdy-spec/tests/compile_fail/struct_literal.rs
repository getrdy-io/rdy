use rdy_spec::spec::{CheckId, CheckSpec, Metadata, ProductSlug, Spec};
use rdy_spec::sig::SignatureState;
use rdy_spec::{LoadedSpec, VerifiedSpecBytes};

fn sample() -> Spec {
    let product = ProductSlug::new("acme-platform").unwrap();
    let check = CheckSpec::new(CheckId::new("host.cpu").unwrap());
    Spec::new(Metadata::new(product), vec![check])
}

// There is no public way to get one, so this is never called.
fn bytes() -> VerifiedSpecBytes {
    unreachable!()
}

fn main() {
    let _ = LoadedSpec {
        spec: sample(),
        signature: SignatureState::Unsigned,
        sha256: String::new(),
        bytes: bytes(),
    };
}
