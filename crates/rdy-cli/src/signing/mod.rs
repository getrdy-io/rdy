//! Making keys and signatures for `rdy spec keygen` and `rdy spec sign` (M1-125, ADR 0022).
//!
//! Four small pieces, all in the minisign formats so stock tooling can read what rdy writes:
//!
//! - [`key`]: the secret key file. A new key is encrypted with scrypt at the cost stock minisign
//!   uses (1 GiB, N = 2^20). A key file may ask for no more than that.
//! - [`sidecar`]: the signature file. Prehashed `ED` over BLAKE2b-512, and a signed trusted comment
//!   in the form `rdy-spec-v1 product=<slug> signed_at=<time>` (01 section 4.2).
//! - [`files`]: opening and creating key files without following links, with owner-only modes.
//! - [`time`]: the `signed_at` stamp.
//!
//! Verification is not here. It is `rdy_spec::load`, and `rdy spec sign` runs it on its own output
//! before it writes anything.
//!
//! Secrets in this module (passwords, seeds, decrypted key bytes) live in `zeroize` wrappers and are
//! never printed, logged or put in an error.

pub mod files;
pub mod key;
pub mod sidecar;
pub mod time;
