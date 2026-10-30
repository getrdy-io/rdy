//! A throwaway certificate authority for the TLS tests (rcgen on ring, 03 net.tls_intercept).

use std::net::IpAddr;

use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, date_time_ymd,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// When a generated leaf certificate is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// 1975 to 4096, which is rcgen's default. Valid on any clock a test uses.
    Always,
    /// 2020-01-01 to 2021-01-01. Expired on the real clock. A test that pins its clock to a time
    /// inside this window sees it valid.
    Expired,
    /// 4000-01-01 to 4001-01-01. Not yet valid on the real clock.
    NotYetValid,
}

/// A certificate authority made in memory: a root, or an intermediate below one.
#[derive(Debug)]
pub struct TestCa {
    params: CertificateParams,
    key: KeyPair,
    der: CertificateDer<'static>,
    /// The CAs between this one and the root, this CA first. Empty for a root.
    chain_to_root: Vec<CertificateDer<'static>>,
    root_der: CertificateDer<'static>,
    root_pem: String,
}

/// A server certificate with the CA certificates a server sends with it, and its private key.
#[derive(Debug)]
pub struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key_pkcs8: Vec<u8>,
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA certificate params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
}

impl TestCa {
    /// A new self-signed root with the common name `common_name`.
    ///
    /// # Panics
    ///
    /// If the crypto provider cannot make a key or sign, which is a broken build and not a test result.
    #[must_use]
    pub fn root(common_name: &str) -> Self {
        let params = ca_params(common_name);
        let key = KeyPair::generate().expect("generate the CA key");
        let cert = params.self_signed(&key).expect("self-sign the root");
        Self {
            der: cert.der().clone(),
            root_der: cert.der().clone(),
            root_pem: cert.pem(),
            chain_to_root: Vec::new(),
            params,
            key,
        }
    }

    /// A new intermediate CA signed by this one. A leaf it issues carries the intermediate and any
    /// CAs above it, so the chain a server sends is as deep as the CAs are nested.
    ///
    /// # Panics
    ///
    /// If signing fails (see [`TestCa::root`]).
    #[must_use]
    pub fn intermediate(&self, common_name: &str) -> Self {
        let params = ca_params(common_name);
        let key = KeyPair::generate().expect("generate the intermediate key");
        let cert = params
            .signed_by(&key, &self.issuer())
            .expect("sign the intermediate");
        let mut chain_to_root = vec![cert.der().clone()];
        chain_to_root.extend(self.chain_to_root.iter().cloned());
        Self {
            der: cert.der().clone(),
            root_der: self.root_der.clone(),
            root_pem: self.root_pem.clone(),
            chain_to_root,
            params,
            key,
        }
    }

    fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key)
    }

    /// The DER of this CA's own certificate.
    #[must_use]
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// The DER of the root. A client trusts the chain when it holds this certificate.
    #[must_use]
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root_der
    }

    /// The PEM of the root, for a test that writes a fake system bundle.
    #[must_use]
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// A server certificate for `names` (DNS names or IP addresses) signed by this CA.
    ///
    /// # Panics
    ///
    /// If a name is not a valid DNS name or IP address, or signing fails.
    #[must_use]
    pub fn issue(&self, names: &[&str], validity: Validity) -> Leaf {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.subject_alt_names = names
            .iter()
            .map(|name| match name.parse::<IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName(
                    Ia5String::try_from((*name).to_owned()).expect("an ASCII DNS name"),
                ),
            })
            .collect();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if let Some(first) = names.first() {
            params.distinguished_name.push(DnType::CommonName, *first);
        }
        match validity {
            Validity::Always => {}
            Validity::Expired => {
                params.not_before = date_time_ymd(2020, 1, 1);
                params.not_after = date_time_ymd(2021, 1, 1);
            }
            Validity::NotYetValid => {
                params.not_before = date_time_ymd(4000, 1, 1);
                params.not_after = date_time_ymd(4001, 1, 1);
            }
        }
        let key = KeyPair::generate().expect("generate the leaf key");
        let cert = params
            .signed_by(&key, &self.issuer())
            .expect("sign the leaf");
        let mut chain = vec![cert.der().clone()];
        // A root is not sent (its list is empty). An intermediate and the ones above it are, nearest first.
        chain.extend(self.chain_to_root.iter().cloned());
        Leaf {
            chain,
            key_pkcs8: key.serialize_der(),
        }
    }
}

impl Leaf {
    /// The certificates a server sends: the leaf, then each intermediate. Never the root.
    #[must_use]
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The leaf's private key.
    pub(super) fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()))
    }
}
