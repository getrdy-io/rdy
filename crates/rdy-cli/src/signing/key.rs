//! The secret key file, in the minisign format (ADR 0022).
//!
//! A key file is two lines. The first is `untrusted comment: <text>`. The second is base64 of 158
//! bytes:
//!
//! ```text
//! "Ed"  signature algorithm                      2
//! kdf   "Sc" (scrypt) or two zero bytes          2
//! "B2"  checksum algorithm                       2
//! salt  scrypt salt                              32
//! ops   scrypt opslimit, little endian           8
//! mem   scrypt memlimit, little endian           8
//! then, XORed with a scrypt stream when the key is encrypted:
//! keynum  the key id                             8
//! sk      ed25519 seed, then public key          64
//! chk     BLAKE2b-256 of "Ed" || keynum || sk    32
//! ```
//!
//! A new key is encrypted at [`KdfCost::STANDARD`], the cost stock minisign uses: scrypt with
//! N = 2^20, r = 8, p = 1, which needs 1 GiB of memory. That is deliberately the highest cost a
//! key file may ask for, and p must be 1. [`StoredKey::parse`] refuses a file that asks for more,
//! so a key file from someone else cannot make `rdy spec sign` run out of memory or time.
//!
//! The password is checked by the checksum. A wrong password and a damaged file are told apart
//! only by whether the key is encrypted.

use std::fmt::Write as _;

use blake2::Blake2b;
use blake2::digest::{Digest, consts::U32};
use ct_codecs::{Base64, Decoder, Encoder};
use ed25519_dalek::{Signer, SigningKey};
use rdy_spec::sig::KeyId;
use zeroize::Zeroizing;

/// Signature algorithm bytes of every minisign key.
const SIG_ALG: [u8; 2] = *b"Ed";
/// Key derivation algorithm bytes for scrypt.
const KDF_SCRYPT: [u8; 2] = *b"Sc";
/// Key derivation bytes for a key with no password.
const KDF_NONE: [u8; 2] = [0, 0];
/// Checksum algorithm bytes: BLAKE2b with a 32-byte output.
const CHK_ALG: [u8; 2] = *b"B2";
const SALT_BYTES: usize = 32;
const KEYNUM_BYTES: usize = 8;
const SK_BYTES: usize = 64;
const CHK_BYTES: usize = 32;
/// The bytes that are encrypted: key id, secret key, checksum.
const PROTECTED_BYTES: usize = KEYNUM_BYTES + SK_BYTES + CHK_BYTES;
/// The decoded size of the second line of a key file.
const RECORD_BYTES: usize = 2 + 2 + 2 + SALT_BYTES + 8 + 8 + PROTECTED_BYTES;
/// A key file is about 250 bytes. Nothing near this size is a key file.
pub const MAX_KEY_FILE_BYTES: usize = 1024;
/// The untrusted comment rdy writes in a public key file. It matches stock minisign.
const PUBLIC_COMMENT: &str = "minisign public key";

/// The most work a key file may ask for, which is also what rdy asks for when it writes one.
const MAX_OPSLIMIT: u64 = 33_554_432;
/// See [`MAX_OPSLIMIT`]. 1 GiB.
const MAX_MEMLIMIT: u64 = 1_073_741_824;
/// scrypt `N` is 2 to this power. 20 is 1 GiB with r = 8.
const MAX_LOG_N: u8 = 20;
/// scrypt block size, as minisign sets it.
const SCRYPT_R: u32 = 8;
/// The password-protected record of an encrypted key must be this long (the stream length).
const STREAM_BYTES: usize = PROTECTED_BYTES;

/// How much work the key derivation does, in the units stock minisign writes into a key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    opslimit: u64,
    memlimit: u64,
}

impl KdfCost {
    /// What stock minisign writes and what rdy writes: scrypt N = 2^20, r = 8, p = 1, 1 GiB.
    pub const STANDARD: Self = Self {
        opslimit: MAX_OPSLIMIT,
        memlimit: MAX_MEMLIMIT,
    };

    /// A cost from minisign's two limits. Tests use a small one so they run fast.
    #[must_use]
    pub const fn new(opslimit: u64, memlimit: u64) -> Self {
        Self { opslimit, memlimit }
    }
}

/// Why a key could not be made, read or opened. No variant holds a password or key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The text is not a minisign secret key file.
    #[error("it is not a secret key made by rdy or minisign ({0})")]
    Malformed(&'static str),
    /// A key type or protection that rdy does not support.
    #[error("it uses {0}, which rdy does not support")]
    Unsupported(&'static str),
    /// The file asks for more scrypt work than rdy allows.
    #[error("it asks for more memory or time to open than rdy allows")]
    TooCostly,
    /// The key is encrypted and no password was given.
    #[error("it is protected by a password")]
    NeedsPassword,
    /// The password does not open the key.
    #[error("the password is wrong")]
    WrongPassword,
    /// An unprotected key whose checksum or public half does not match.
    #[error("it is damaged")]
    Damaged,
    /// The system could not give random bytes.
    #[error("the system could not give random bytes")]
    Random,
}

impl KeyError {
    /// True when the user's input must change (every case except [`KeyError::Random`]).
    #[must_use]
    pub fn is_user_error(&self) -> bool {
        !matches!(self, Self::Random)
    }
}

/// A key file that has been read and checked for form, and may still be encrypted.
///
/// The protected bytes are kept as they are on disk: encrypted for a protected key.
pub struct StoredKey {
    kdf: Kdf,
    protected: Zeroizing<[u8; PROTECTED_BYTES]>,
}

#[derive(Clone, Copy)]
enum Kdf {
    None,
    Scrypt {
        salt: [u8; SALT_BYTES],
        opslimit: u64,
        memlimit: u64,
    },
}

/// The comments that rdy and minisign write at the top of a secret key file. A public key file may
/// say "secret key" in its comment for another reason ("the secret key was discarded"), so only these
/// openings count.
const SECRET_COMMENTS: [&str; 4] = [
    "rdy secret key",
    "rdy encrypted secret key",
    "minisign secret key",
    "minisign encrypted secret key",
];

/// True when `text` is, or is meant to be, a secret key file: a line that decodes to the 158 bytes of a
/// secret key record, or a comment line that opens like the ones rdy and minisign write for one.
///
/// This is for a command that was given a key to trust and must not take a secret key by mistake
/// (`rdy trust add`). It reads only the form, never a password, and it does not fail on a damaged or
/// too costly key: those are secret keys too.
#[must_use]
pub fn looks_like_secret_key(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        let comment = line.strip_prefix("untrusted comment:").is_some_and(|rest| {
            SECRET_COMMENTS
                .iter()
                .any(|c| rest.trim_start().starts_with(c))
        });
        comment
            || Base64::decode_to_vec(line, None)
                .map(Zeroizing::new)
                .is_ok_and(|record| record.len() == RECORD_BYTES)
    })
}

impl StoredKey {
    /// Reads the text of a key file.
    ///
    /// # Errors
    ///
    /// [`KeyError::Malformed`] if it is not a two-line minisign secret key,
    /// [`KeyError::Unsupported`] for another algorithm, and [`KeyError::TooCostly`] if the key
    /// derivation it asks for is above [`KdfCost::STANDARD`] or has a parallelism other than 1.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let mut lines = text.lines();
        let comment = lines.next().ok_or(KeyError::Malformed("it is empty"))?;
        if !comment.starts_with("untrusted comment:") {
            return Err(KeyError::Malformed("the first line is not a comment"));
        }
        let encoded = lines
            .next()
            .ok_or(KeyError::Malformed("it has no key line"))?;
        if lines.any(|extra| !extra.trim().is_empty()) {
            return Err(KeyError::Malformed("it has more than two lines"));
        }
        let record = Zeroizing::new(
            Base64::decode_to_vec(encoded, None)
                .map_err(|_| KeyError::Malformed("the key line is not base64"))?,
        );
        let record: &[u8; RECORD_BYTES] = record
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Malformed("the key line has the wrong length"))?;
        if record[..2] != SIG_ALG {
            return Err(KeyError::Unsupported(
                "a signature algorithm other than Ed25519",
            ));
        }
        if record[4..6] != CHK_ALG {
            return Err(KeyError::Unsupported("a checksum other than BLAKE2b"));
        }
        let kdf = match [record[2], record[3]] {
            KDF_NONE => Kdf::None,
            KDF_SCRYPT => {
                let mut salt = [0u8; SALT_BYTES];
                salt.copy_from_slice(&record[6..6 + SALT_BYTES]);
                let at = 6 + SALT_BYTES;
                let opslimit = u64::from_le_bytes(array_at(record, at));
                let memlimit = u64::from_le_bytes(array_at(record, at + 8));
                // Refuse before any work is done.
                let _checked = scrypt_params(opslimit, memlimit)?;
                Kdf::Scrypt {
                    salt,
                    opslimit,
                    memlimit,
                }
            }
            _ => return Err(KeyError::Unsupported("a key protection other than scrypt")),
        };
        let mut protected = Zeroizing::new([0u8; PROTECTED_BYTES]);
        protected.copy_from_slice(&record[RECORD_BYTES - PROTECTED_BYTES..]);
        Ok(Self { kdf, protected })
    }

    /// True when a password is needed to open the key.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        !matches!(self.kdf, Kdf::None)
    }

    /// Opens the key.
    ///
    /// `password` is ignored for a key that has none.
    ///
    /// # Errors
    ///
    /// [`KeyError::NeedsPassword`] if the key is encrypted and `password` is `None`,
    /// [`KeyError::WrongPassword`] if the checksum does not match after decryption, and
    /// [`KeyError::Damaged`] if an unprotected key does not match its own checksum or public half.
    pub fn unlock(&self, password: Option<&str>) -> Result<SecretKey, KeyError> {
        let mut plain = self.protected.clone();
        let wrong = match self.kdf {
            Kdf::None => KeyError::Damaged,
            Kdf::Scrypt {
                salt,
                opslimit,
                memlimit,
            } => {
                let password = password.ok_or(KeyError::NeedsPassword)?;
                let stream = derive_stream(password, &salt, opslimit, memlimit)?;
                xor_in_place(&mut plain, &stream);
                KeyError::WrongPassword
            }
        };
        let keynum: [u8; KEYNUM_BYTES] = array_at(&plain[..], 0);
        let sk: Zeroizing<[u8; SK_BYTES]> = Zeroizing::new(array_at(&plain[..], KEYNUM_BYTES));
        let stored_chk: [u8; CHK_BYTES] = array_at(&plain[..], KEYNUM_BYTES + SK_BYTES);
        if !equal(&checksum(&keynum, &sk), &stored_chk) {
            return Err(wrong);
        }
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(array_at(&sk[..], 0));
        let signing = SigningKey::from_bytes(&seed);
        // The second half of the secret key is the public key. A key whose halves disagree would
        // sign with one and publish the other.
        if !equal(
            &signing.verifying_key().to_bytes(),
            &array_at::<32>(&sk[..], 32),
        ) {
            return Err(KeyError::Damaged);
        }
        Ok(SecretKey { keynum, signing })
    }
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredKey(..)")
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// An ed25519 signing key and the key id that its signatures carry. The seed is wiped on drop.
pub struct SecretKey {
    keynum: [u8; KEYNUM_BYTES],
    signing: SigningKey,
}

impl SecretKey {
    /// Makes a new random key.
    ///
    /// # Errors
    ///
    /// [`KeyError::Random`] if the system cannot give random bytes.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).map_err(|_| KeyError::Random)?;
        let mut keynum = [0u8; KEYNUM_BYTES];
        getrandom::fill(&mut keynum).map_err(|_| KeyError::Random)?;
        Ok(Self {
            keynum,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The key id, which signatures made with this key carry.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::from_bytes(self.keynum)
    }

    /// The 8 key id bytes in file order.
    pub(super) fn keynum(&self) -> [u8; KEYNUM_BYTES] {
        self.keynum
    }

    /// Signs `message` with ed25519. The result is 64 bytes.
    pub(super) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// The base64 line of the public key (`RW...`): `Ed`, the key id and the 32 key bytes.
    ///
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        let mut bytes = Vec::with_capacity(42);
        bytes.extend_from_slice(&SIG_ALG);
        bytes.extend_from_slice(&self.keynum);
        bytes.extend_from_slice(&self.signing.verifying_key().to_bytes());
        encode(&bytes).to_string()
    }

    /// The text of a `.pub` file: a comment line and the key line.
    #[must_use]
    pub fn public_key_file(&self) -> String {
        format!(
            "untrusted comment: {PUBLIC_COMMENT} {}\n{}\n",
            self.key_id(),
            self.public_key_base64()
        )
    }

    /// The text of a secret key file. With `password` it is encrypted at `cost`. With `None` it is
    /// not protected at all.
    ///
    /// # Errors
    ///
    /// [`KeyError::Random`] if the system cannot give a salt, and [`KeyError::TooCostly`] if `cost`
    /// is above [`KdfCost::STANDARD`].
    pub fn key_file(
        &self,
        password: Option<&str>,
        cost: KdfCost,
    ) -> Result<Zeroizing<String>, KeyError> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        let mut sk = Zeroizing::new([0u8; SK_BYTES]);
        sk[..32].copy_from_slice(&seed[..]);
        sk[32..].copy_from_slice(&self.signing.verifying_key().to_bytes());
        let mut protected = Zeroizing::new([0u8; PROTECTED_BYTES]);
        protected[..KEYNUM_BYTES].copy_from_slice(&self.keynum);
        protected[KEYNUM_BYTES..KEYNUM_BYTES + SK_BYTES].copy_from_slice(&sk[..]);
        protected[KEYNUM_BYTES + SK_BYTES..].copy_from_slice(&checksum(&self.keynum, &sk));

        let mut record = Zeroizing::new(Vec::with_capacity(RECORD_BYTES));
        record.extend_from_slice(&SIG_ALG);
        let comment;
        if let Some(password) = password {
            let mut salt = [0u8; SALT_BYTES];
            getrandom::fill(&mut salt).map_err(|_| KeyError::Random)?;
            let stream = derive_stream(password, &salt, cost.opslimit, cost.memlimit)?;
            xor_in_place(&mut protected, &stream);
            record.extend_from_slice(&KDF_SCRYPT);
            record.extend_from_slice(&CHK_ALG);
            record.extend_from_slice(&salt);
            record.extend_from_slice(&cost.opslimit.to_le_bytes());
            record.extend_from_slice(&cost.memlimit.to_le_bytes());
            comment = "rdy encrypted secret key";
        } else {
            record.extend_from_slice(&KDF_NONE);
            record.extend_from_slice(&CHK_ALG);
            record.extend_from_slice(&[0u8; SALT_BYTES]);
            record.extend_from_slice(&[0u8; 16]);
            comment = "rdy secret key, not password protected";
        }
        record.extend_from_slice(&protected[..]);
        let mut text = Zeroizing::new(String::with_capacity(512));
        // Writing to a `String` cannot fail.
        let _ = write!(
            text,
            "untrusted comment: {comment}\n{}\n",
            encode(&record).as_str()
        );
        Ok(text)
    }
}

/// Standard base64 with padding. The secret bytes may pass through here, so the encoder is a
/// constant-time one and the text is wiped when dropped.
fn encode(bytes: &[u8]) -> Zeroizing<String> {
    // The encoder sizes its own output, so this cannot fail for any input length.
    Zeroizing::new(Base64::encode_to_string(bytes).unwrap_or_default())
}

/// Copies `N` bytes out of `bytes` at `at`. The callers pass constant offsets inside fixed arrays.
fn array_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// BLAKE2b-256 of `Ed || keynum || sk`, the checksum that proves a password was right.
fn checksum(keynum: &[u8; KEYNUM_BYTES], sk: &[u8; SK_BYTES]) -> [u8; CHK_BYTES] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(SIG_ALG);
    hasher.update(keynum);
    hasher.update(sk);
    hasher.finalize().into()
}

/// Equality that does not stop at the first difference.
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn xor_in_place(data: &mut [u8; PROTECTED_BYTES], stream: &[u8; STREAM_BYTES]) {
    for (byte, mask) in data.iter_mut().zip(stream) {
        *byte ^= mask;
    }
}

/// The 104 bytes of scrypt output that protect the key.
fn derive_stream(
    password: &str,
    salt: &[u8; SALT_BYTES],
    opslimit: u64,
    memlimit: u64,
) -> Result<Zeroizing<[u8; STREAM_BYTES]>, KeyError> {
    let params = scrypt_params(opslimit, memlimit)?;
    let mut stream = Zeroizing::new([0u8; STREAM_BYTES]);
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut stream[..])
        .map_err(|_| KeyError::Malformed("the key derivation settings are not valid"))?;
    Ok(stream)
}

/// Turns minisign's two limits into scrypt parameters, the way libsodium's `pickparams` does, and
/// refuses anything above [`KdfCost::STANDARD`] or with a parallelism other than 1.
fn scrypt_params(opslimit: u64, memlimit: u64) -> Result<scrypt::Params, KeyError> {
    if opslimit > MAX_OPSLIMIT || memlimit > MAX_MEMLIMIT {
        return Err(KeyError::TooCostly);
    }
    let opslimit = opslimit.max(32_768);
    let r = u64::from(SCRYPT_R);
    let smallest_log_n = |max_n: u64| {
        let mut log_n = 1u8;
        while log_n < 63 && (1u64 << log_n) <= max_n / 2 {
            log_n += 1;
        }
        log_n
    };
    let (log_n, p) = if opslimit < memlimit / 32 {
        (smallest_log_n(opslimit / (r * 4)), 1u64)
    } else {
        let log_n = smallest_log_n(memlimit / (r * 128));
        let max_rp = ((opslimit / 4) >> log_n).min(0x3fff_ffff);
        (log_n, max_rp / r)
    };
    if log_n > MAX_LOG_N {
        return Err(KeyError::TooCostly);
    }
    // Stock minisign and the `minisign` crate always write p = 1. A file with a larger p (a big
    // opslimit with a tiny memlimit gives one) would make the key derivation run for hours at
    // little memory, so it is refused like any other file that asks for too much.
    if p == 0 {
        return Err(KeyError::Malformed(
            "the key derivation settings are not valid",
        ));
    }
    if p != 1 {
        return Err(KeyError::TooCostly);
    }
    scrypt::Params::new(log_n, SCRYPT_R, 1, scrypt::Params::RECOMMENDED_LEN)
        .map_err(|_| KeyError::Malformed("the key derivation settings are not valid"))
}

#[cfg(test)]
mod tests;
