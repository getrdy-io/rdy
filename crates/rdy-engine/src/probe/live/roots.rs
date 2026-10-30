//! The OS trust roots for `NativeCall::SystemRoots` (M1-092, ADR 0014 decision 3).
//!
//! - **Linux and the other Unix systems except macOS** read PEM bundles through the facade's file
//!   rules, so a bundle is judged on its real path like any read and `/etc/shadow` cannot be named
//!   through a link. The sources are, in order: the file `SSL_CERT_FILE`; the directories in
//!   `SSL_CERT_DIR` (colon separated). When neither variable is set, the first of the standard bundle
//!   paths that reads, and if none does, the standard directories. A trust store that only an NSS
//!   database or a Java keystore holds is invisible here (05, "TLS").
//! - **macOS and Windows** ask the OS through `rustls-native-certs`, which reads the keychains and the
//!   Windows root store.
//!
//! Both bound their work with the caps of the native call: at most [`MAX_SYSTEM_ROOTS`] certificates,
//! each at most [`MAX_ROOT_BYTES`] bytes, and at most [`MAX_FILES`] files of a directory are read. A
//! certificate that is listed twice (the hashed names of a directory repeat the bundle) is kept once.

#[cfg(all(unix, not(target_os = "macos")))]
pub(super) use pem::{Sources, load};

#[cfg(any(target_os = "macos", windows))]
pub(super) use native_store::load;

/// The most files of a certificate directory that are read.
#[cfg(all(unix, not(target_os = "macos")))]
const MAX_FILES: usize = 2048;

#[cfg(all(unix, not(target_os = "macos")))]
mod pem {
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    use super::MAX_FILES;
    use crate::check::current_os;
    use crate::probe::live::files::{self, Secrets};
    use crate::probe::{MAX_READ, MAX_ROOT_BYTES, MAX_SYSTEM_ROOTS, ReadGuard, ReadRange};

    /// The bundle files of the common distributions, in the order they are tried. Debian and Ubuntu,
    /// RHEL and Fedora, SUSE, Alpine and older RHEL, Arch, and the BSDs.
    const BUNDLES: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
        "/usr/local/share/certs/ca-root-nss.crt",
    ];

    /// The directories that hold one certificate per file, tried when no bundle reads.
    const DIRS: &[&str] = &["/etc/ssl/certs", "/etc/pki/tls/certs"];

    /// Where the PEM bundles are looked for.
    #[derive(Debug, Clone, Default)]
    pub(in crate::probe::live) struct Sources {
        /// `SSL_CERT_FILE`.
        file: Option<PathBuf>,
        /// `SSL_CERT_DIR`, split at `:`.
        dirs: Vec<PathBuf>,
        /// Tried when neither of the two above is set.
        bundles: Vec<PathBuf>,
        standard_dirs: Vec<PathBuf>,
    }

    impl Sources {
        /// The two variables as the process has them, and the standard paths.
        pub(in crate::probe::live) fn from_env() -> Self {
            Self::new(
                std::env::var_os("SSL_CERT_FILE"),
                std::env::var_os("SSL_CERT_DIR"),
            )
        }

        /// The sources for these values of `SSL_CERT_FILE` and `SSL_CERT_DIR`. An empty value is not set.
        pub(in crate::probe::live) fn new(file: Option<OsString>, dirs: Option<OsString>) -> Self {
            Self {
                file: file.filter(|v| !v.is_empty()).map(PathBuf::from),
                dirs: dirs
                    .map(|v| std::env::split_paths(&v).collect::<Vec<_>>())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect(),
                bundles: BUNDLES.iter().map(PathBuf::from).collect(),
                standard_dirs: DIRS.iter().map(PathBuf::from).collect(),
            }
        }

        /// The same, with these standard paths. For the tests, which have no `/etc` of their own.
        #[cfg(test)]
        pub(in crate::probe::live) fn with_standard(
            mut self,
            bundles: Vec<PathBuf>,
            dirs: Vec<PathBuf>,
        ) -> Self {
            self.bundles = bundles;
            self.standard_dirs = dirs;
            self
        }
    }

    /// The certificates collected so far, capped and without repeats.
    #[derive(Default)]
    struct Collected {
        certs: Vec<Vec<u8>>,
        /// A certificate was dropped for its size or because the list was full.
        dropped: usize,
    }

    impl Collected {
        fn full(&self) -> bool {
            self.certs.len() >= MAX_SYSTEM_ROOTS
        }

        fn add(&mut self, der: &[u8]) {
            if der.is_empty() || der.len() > MAX_ROOT_BYTES || self.full() {
                self.dropped += 1;
            } else if !self.certs.iter().any(|known| known == der) {
                self.certs.push(der.to_vec());
            }
        }
    }

    /// Reads the roots from the PEM sources. Blocking: the caller puts it on the blocking pool.
    ///
    /// An empty list is an answer (a scratch image with no `ca-certificates`). An error means that a
    /// source the operator named, or the only source there was, could not be read.
    pub(in crate::probe::live) fn load(
        sources: &Sources,
        secrets: &Secrets,
    ) -> io::Result<Vec<Vec<u8>>> {
        // The denylist applies; no prefix does. `/etc/shadow` is refused on its real path as for any read.
        let guard = ReadGuard::new(current_os(), None);
        let mut found = Collected::default();
        let explicit = sources.file.is_some() || !sources.dirs.is_empty();
        let mut last_error = None;
        if explicit {
            if let Some(file) = &sources.file {
                note(
                    read_bundle(file, &guard, secrets, &mut found),
                    &mut last_error,
                );
            }
            for dir in &sources.dirs {
                note(read_dir(dir, &guard, secrets, &mut found), &mut last_error);
            }
        } else {
            let bundle = sources
                .bundles
                .iter()
                .find(|path| read_bundle(path, &guard, secrets, &mut found).is_ok());
            if bundle.is_none() {
                for dir in &sources.standard_dirs {
                    // A directory that is not there is not a failure: most systems have only one.
                    let _ = read_dir(dir, &guard, secrets, &mut found);
                }
            }
        }
        if found.dropped > 0 {
            tracing::warn!(
                dropped = found.dropped,
                "certificates of the OS trust store were dropped by the size or count cap"
            );
        }
        match (found.certs.is_empty(), last_error) {
            (true, Some(error)) => Err(error),
            _ => Ok(found.certs),
        }
    }

    fn note(result: io::Result<()>, last: &mut Option<io::Error>) {
        if let Err(error) = result {
            *last = Some(error);
        }
    }

    /// Reads one PEM file and adds every certificate in it.
    fn read_bundle(
        path: &Path,
        guard: &ReadGuard,
        secrets: &Secrets,
        found: &mut Collected,
    ) -> io::Result<()> {
        let file = files::read(path, ReadRange::Head(MAX_READ), guard, secrets)?;
        if file.truncated() {
            tracing::warn!(
                "a trust store file is longer than the read cap, so its end was not read"
            );
        }
        // A block that does not parse ends the iteration: what came before it is kept.
        for cert in CertificateDer::pem_slice_iter(&file.bytes).map_while(Result::ok) {
            found.add(cert.as_ref());
            if found.full() {
                break;
            }
        }
        Ok(())
    }

    /// Reads the certificate files of a directory: `*.pem`, `*.crt`, `*.cer` and the hashed names
    /// (`1a2b3c4d.0`) that `c_rehash` makes. A file that does not read is skipped.
    fn read_dir(
        dir: &Path,
        guard: &ReadGuard,
        secrets: &Secrets,
        found: &mut Collected,
    ) -> io::Result<()> {
        let entries = files::read_dir(dir, guard, secrets)?;
        for entry in entries
            .iter()
            .filter(|e| !e.is_dir && certificate_name(&e.name))
            .take(MAX_FILES)
        {
            if found.full() {
                break;
            }
            let _ = read_bundle(&dir.join(&entry.name), guard, secrets, found);
        }
        Ok(())
    }

    /// Whether a directory entry is named like a certificate file.
    fn certificate_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        if [".pem", ".crt", ".cer"]
            .iter()
            .any(|ext| lower.ends_with(ext))
        {
            return true;
        }
        // `c_rehash` links: eight hex digits, a dot, a decimal counter.
        name.split_once('.').is_some_and(|(hash, counter)| {
            hash.len() == 8
                && hash.bytes().all(|b| b.is_ascii_hexdigit())
                && !counter.is_empty()
                && counter.bytes().all(|b| b.is_ascii_digit())
        })
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(any(target_os = "macos", windows))]
mod native_store {
    use std::io;

    use crate::probe::{MAX_ROOT_BYTES, MAX_SYSTEM_ROOTS};

    /// Asks the OS for its trust roots. Blocking: the caller puts it on the blocking pool.
    ///
    /// An error means the OS gave nothing and said why; a store that is simply empty is an empty list.
    pub(in crate::probe::live) fn load() -> io::Result<Vec<Vec<u8>>> {
        let result = rustls_native_certs::load_native_certs();
        let mut certs: Vec<Vec<u8>> = Vec::new();
        for cert in &result.certs {
            let der: &[u8] = cert.as_ref();
            if !der.is_empty()
                && der.len() <= MAX_ROOT_BYTES
                && certs.len() < MAX_SYSTEM_ROOTS
                && !certs.iter().any(|known| known == der)
            {
                certs.push(der.to_vec());
            }
        }
        if certs.is_empty() && !result.errors.is_empty() {
            return Err(io::Error::other(
                "the OS trust store could not be read".to_owned(),
            ));
        }
        Ok(certs)
    }
}
