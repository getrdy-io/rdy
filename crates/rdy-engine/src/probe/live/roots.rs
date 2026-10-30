//! The OS trust roots for `NativeCall::SystemRoots` (M1-092, ADR 0014 decision 3).
//!
//! - **Unix (Linux, macOS, the BSDs)** reads PEM bundles through the facade's file rules, so a bundle is
//!   judged on its real path like any read and `/etc/shadow` cannot be named through a link. The
//!   sources are, in order: the file `SSL_CERT_FILE`; the directories in `SSL_CERT_DIR` (colon
//!   separated). When neither variable is set, the first of the standard bundle paths that holds a
//!   certificate, and if none does, the standard directories. A trust store that only an NSS database or
//!   a Java keystore holds is invisible here (05, "TLS").
//! - **macOS and Windows with neither variable set** ask the OS through `rustls-native-certs`, which
//!   reads the keychains and the Windows root store. That crate reads the two variables with plain
//!   `std::fs` (no rules, no caps) and skips the OS store when either is set, so this module never calls
//!   it while one is set: on macOS the PEM reader above takes over, and on Windows, which has no file
//!   reads in M1, the call fails with a typed error that says to unset the variable.
//!
//! Both bound their work with the caps of the native call: at most [`MAX_SYSTEM_ROOTS`] certificates,
//! each at most [`MAX_ROOT_BYTES`] bytes. The PEM reader also reads at most [`MAX_FILES`] files of a
//! directory and at most [`MAX_TOTAL_BYTES`] bytes in all. A certificate that is listed twice (the hashed
//! names of a directory repeat the bundle) is kept once.

use std::io;

#[cfg(any(unix, windows))]
use crate::probe::{MAX_ROOT_BYTES, MAX_SYSTEM_ROOTS, StoreKind, StoreSource, SystemRoots};

/// The most files of a certificate directory that are read.
#[cfg(unix)]
const MAX_FILES: usize = 2048;

/// The most bytes all the files of one load add up to: eight times the read cap of one file. A
/// directory of 2048 files of 1 MiB cannot make the facade read 2 GiB.
#[cfg(unix)]
const MAX_TOTAL_BYTES: usize = 8 << 20;

/// The environment variables that `rustls-native-certs` reads with plain `std::fs`.
#[cfg(any(target_os = "macos", windows))]
const CERT_FILE_VAR: &str = "SSL_CERT_FILE";
#[cfg(any(target_os = "macos", windows))]
const CERT_DIR_VAR: &str = "SSL_CERT_DIR";

/// Whether `rustls-native-certs` might read these values instead of the OS store. Either variable set
/// at all, even empty, counts. Every 0.8.x release reads at least that much (0.8.5 skips the OS store
/// for a set file and for a directory list with a non-empty entry), so this covers all of them. It is
/// the rule of the crate, copied; the workspace pins the crate with `=` so a bump forces a re-review.
#[cfg(any(target_os = "macos", windows, test))]
fn overrides(file: Option<&std::ffi::OsStr>, dirs: Option<&std::ffi::OsStr>) -> bool {
    file.is_some() || dirs.is_some()
}

/// [`overrides`] for the values the process has.
#[cfg(any(target_os = "macos", windows))]
fn env_overrides() -> bool {
    overrides(
        std::env::var_os(CERT_FILE_VAR).as_deref(),
        std::env::var_os(CERT_DIR_VAR).as_deref(),
    )
}

/// The OS trust roots as DER, on a Unix system. Blocking: the caller puts it on the blocking pool.
#[cfg(unix)]
pub(super) fn system_roots(secrets: &super::files::Secrets) -> io::Result<SystemRoots> {
    // macOS keeps its roots in the keychains. The PEM reader takes over only when a variable names a
    // source, so that the crate never reads a variable itself.
    #[cfg(target_os = "macos")]
    if !env_overrides() {
        return native_store::load();
    }
    pem::load(&pem::Sources::from_env(), secrets)
}

/// The OS trust roots as DER, on Windows. Blocking: the caller puts it on the blocking pool.
///
/// Windows has no file reads in M1, and `rustls-native-certs` would read `SSL_CERT_FILE` and
/// `SSL_CERT_DIR` without any rule, so with either set this is a typed error
/// (`RootsOverridden`) and the verdict is `NoRoots::Overridden`, which carries the "unset it" hint.
#[cfg(windows)]
pub(super) fn system_roots() -> io::Result<SystemRoots> {
    if env_overrides() {
        return Err(crate::probe::native::RootsOverridden::error());
    }
    native_store::load()
}

/// Runs the read of the OS store and turns a panic inside it into an error. `rustls-native-certs` 0.8
/// unwraps inside its Windows reader, and a panic must not end the run or leave the roots asked twice:
/// the error becomes one cached "could not be read" verdict.
#[cfg(any(target_os = "macos", windows, test))]
fn guarded<T>(read: impl FnOnce() -> io::Result<T> + std::panic::UnwindSafe) -> io::Result<T> {
    std::panic::catch_unwind(read)
        .unwrap_or_else(|_| Err(io::Error::other("the OS trust store could not be read")))
}

/// The certificates collected so far: capped in count and size, and without repeats.
#[cfg(any(unix, windows))]
struct Collected {
    certs: Vec<Vec<u8>>,
    /// The files, directories or OS store that held a certificate, in the order they were read.
    sources: Vec<StoreSource>,
    known: std::collections::HashSet<Vec<u8>>,
    /// A certificate or file was left out for a cap.
    dropped: usize,
    /// The bytes of the files read so far.
    #[cfg(unix)]
    read: usize,
}

#[cfg(any(unix, windows))]
impl Collected {
    fn new() -> Self {
        Self {
            certs: Vec::new(),
            sources: Vec::new(),
            known: std::collections::HashSet::new(),
            dropped: 0,
            #[cfg(unix)]
            read: 0,
        }
    }

    fn full(&self) -> bool {
        self.certs.len() >= MAX_SYSTEM_ROOTS
    }

    fn add(&mut self, der: &[u8]) {
        if der.is_empty() || der.len() > MAX_ROOT_BYTES || self.full() {
            self.dropped += 1;
        } else if self.known.insert(der.to_vec()) {
            self.certs.push(der.to_vec());
        }
    }

    fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// How many more bytes of files may be read.
    #[cfg(unix)]
    fn budget(&self) -> usize {
        MAX_TOTAL_BYTES.saturating_sub(self.read)
    }

    /// Notes a place that held a certificate. The same place is noted once.
    fn source(&mut self, kind: StoreKind, location: String) {
        if !self
            .sources
            .iter()
            .any(|s| s.kind == kind && s.location == location)
        {
            self.sources.push(StoreSource::new(kind, location));
        }
    }

    /// The answer, after a warning in the tracing log if anything was left out.
    fn finish(self) -> SystemRoots {
        if self.dropped > 0 {
            tracing::warn!(
                dropped = self.dropped,
                "certificates of the OS trust store were dropped by a size, count or byte cap"
            );
        }
        SystemRoots::new(self.certs, self.sources)
    }
}

#[cfg(unix)]
mod pem {
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    use super::{Collected, MAX_FILES};
    use crate::check::current_os;
    use crate::probe::live::files::{self, Secrets};
    use crate::probe::{MAX_READ, ReadGuard, ReadRange, StoreKind, SystemRoots};

    /// The bundle files of the common distributions, in the order they are tried. Debian and Ubuntu,
    /// RHEL and Fedora, SUSE, Alpine and older RHEL, Arch, the BSDs, and the file macOS ships.
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

    /// Reads the roots from the PEM sources. Blocking: the caller puts it on the blocking pool.
    ///
    /// `SSL_CERT_FILE` and `SSL_CERT_DIR` may name any path the file rules allow, so a probe can read the
    /// certificates of a file outside the usual trust store paths. Only `CERTIFICATE` blocks are kept;
    /// every other block of the file (a private key, say) is dropped unread.
    ///
    /// An empty list is an answer (a scratch image with no `ca-certificates`). An error means that a
    /// source the operator named, or the only source there was, could not be read.
    pub(in crate::probe::live) fn load(
        sources: &Sources,
        secrets: &Secrets,
    ) -> io::Result<SystemRoots> {
        // The denylist applies; no prefix does. `/etc/shadow` is refused on its real path as for any read.
        let guard = ReadGuard::new(current_os(), None);
        let mut found = Collected::new();
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
            // A bundle that reads but holds no certificate does not end the search.
            let bundle = sources.bundles.iter().find(|path| {
                matches!(read_bundle(path, &guard, secrets, &mut found), Ok(count) if count > 0)
            });
            if bundle.is_none() {
                for dir in &sources.standard_dirs {
                    // A directory that is not there is not a failure: most systems have only one.
                    let _ = read_dir(dir, &guard, secrets, &mut found);
                }
            }
        }
        if found.is_empty()
            && let Some(error) = last_error
        {
            return Err(error);
        }
        Ok(found.finish())
    }

    fn note<T>(result: io::Result<T>, last: &mut Option<io::Error>) {
        if let Err(error) = result {
            *last = Some(error);
        }
    }

    /// Reads one PEM file and adds every certificate in it. Returns how many certificates the file held.
    /// A file that held one is noted as a source.
    fn read_bundle(
        path: &Path,
        guard: &ReadGuard,
        secrets: &Secrets,
        found: &mut Collected,
    ) -> io::Result<usize> {
        let budget = found.budget();
        if budget == 0 {
            found.dropped += 1;
            return Ok(0);
        }
        let file = files::read(path, ReadRange::Head(MAX_READ.min(budget)), guard, secrets)?;
        found.read = found.read.saturating_add(file.bytes.len());
        if file.truncated() {
            tracing::warn!(
                "a trust store file is longer than the read cap, so its end was not read"
            );
        }
        // A block that does not parse ends the iteration: what came before it is kept.
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(&file.bytes).map_while(Result::ok) {
            count += 1;
            found.add(cert.as_ref());
            if found.full() {
                break;
            }
        }
        if count > 0 {
            found.source(StoreKind::Bundle, path.to_string_lossy().into_owned());
        }
        Ok(count)
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
        // The directory is the source, not each of its (up to 2048) files: drop the notes the files
        // make and note the directory once if any of them held a certificate.
        let notes = found.sources.len();
        for entry in entries
            .iter()
            .filter(|e| !e.is_dir && certificate_name(&e.name))
            .take(MAX_FILES)
        {
            if found.full() || found.budget() == 0 {
                break;
            }
            let _ = read_bundle(&dir.join(&entry.name), guard, secrets, found);
        }
        if found.sources.len() > notes {
            found.sources.truncate(notes);
            found.source(StoreKind::Directory, dir.to_string_lossy().into_owned());
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

    use super::Collected;
    use crate::probe::{StoreKind, SystemRoots};

    /// Asks the OS for its trust roots. Blocking: the caller puts it on the blocking pool.
    ///
    /// The caller has checked that neither `SSL_CERT_FILE` nor `SSL_CERT_DIR` is set, so
    /// `rustls-native-certs` goes to the keychains or the root store and reads no file of its own.
    /// An error means the OS gave nothing and said why; a store that is simply empty is an empty list.
    pub(super) fn load() -> io::Result<SystemRoots> {
        super::guarded(read)
    }

    /// The fixed name of the store on this OS, for the answer's source.
    const STORE: &str = if cfg!(windows) {
        "the Windows root certificate store"
    } else {
        "the macOS keychains"
    };

    fn read() -> io::Result<SystemRoots> {
        let result = rustls_native_certs::load_native_certs();
        let mut found = Collected::new();
        for cert in &result.certs {
            found.add(cert.as_ref());
        }
        if !found.is_empty() {
            found.source(StoreKind::OsStore, STORE.to_owned());
        }
        if found.is_empty() && !result.errors.is_empty() {
            return Err(io::Error::other(
                "the OS trust store could not be read".to_owned(),
            ));
        }
        Ok(found.finish())
    }
}

#[cfg(test)]
mod tests;
