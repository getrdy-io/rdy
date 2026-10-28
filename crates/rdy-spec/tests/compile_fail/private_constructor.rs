use rdy_spec::spec::{CheckId, CheckSpec, Metadata, ProductSlug, Spec};
use rdy_spec::LoadedSpec;

fn sample() -> Spec {
    let product = ProductSlug::new("acme-platform").unwrap();
    let check = CheckSpec::new(CheckId::new("host.cpu").unwrap());
    Spec::new(Metadata::new(product), vec![check])
}

fn main() {
    let _ = LoadedSpec::new(sample());
}
