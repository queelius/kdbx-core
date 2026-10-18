//! Keyed fingerprints of secret values.
//!
//! A fingerprint lets two snapshots (or a log line and a vault) be compared
//! for equality of a secret without exposing it. An unkeyed hash of a
//! low-entropy secret is a dictionary oracle (a 4-digit PIN falls in 10,000
//! tries), so every fingerprint here is an HMAC-SHA256 under a
//! [`FingerprintKey`]:
//!
//! ```text
//! fingerprint = HMAC-SHA256(key, domain || bytes)
//! ```
//!
//! The [`Domain`] separates uses, so equal bytes in different roles (a field
//! value and an attachment) do not correlate. Domain labels are prefix-free,
//! so `domain || bytes` is unambiguous.
//!
//! Two ways to get a key:
//!
//! - [`FingerprintKey::from_bytes`] with fresh random bytes, for comparisons
//!   within one process (a stage diff). Costs nothing.
//! - `FingerprintKey::derive` (feature `kdf`), an Argon2id derivation from the
//!   vault's key material, when fingerprints must be stable across processes
//!   (git textconv, verifiable audit logs). Breaking such a fingerprint costs
//!   at least as much as attacking a vault protected with KeePassXC-default
//!   Argon2 parameters.
//!
//! ```
//! use kdbx_core::fingerprint::{Domain, FingerprintKey};
//!
//! let key = FingerprintKey::from_bytes([7; 32]);
//! let a = key.fingerprint(Domain::Field, b"hunter2");
//! let b = key.fingerprint(Domain::Field, b"hunter2");
//! assert_eq!(a, b);
//! assert_ne!(a, key.fingerprint(Domain::Attachment, b"hunter2"));
//! assert_eq!(a.short().len(), 8);
//! assert_eq!(a.to_hex().len(), 64);
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(feature = "kdf")]
use uuid::Uuid;

/// The role of the bytes being fingerprinted. Part of the `v1` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Domain {
    /// An entry field value (UTF-8 bytes, exactly as stored).
    Field,
    /// An attachment's content.
    Attachment,
    /// A custom-data value (UTF-8 bytes of a string value, or the raw bytes of
    /// a binary one).
    CustomData,
    /// A custom icon's image data.
    CustomIcon,
}

impl Domain {
    /// Every domain.
    pub const ALL: [Domain; 4] = [
        Domain::Field,
        Domain::Attachment,
        Domain::CustomData,
        Domain::CustomIcon,
    ];

    /// The domain label prepended to the fingerprinted bytes.
    pub fn label(self) -> &'static str {
        match self {
            Domain::Field => "kdbx-core/field/v1",
            Domain::Attachment => "kdbx-core/attachment/v1",
            Domain::CustomData => "kdbx-core/custom-data/v1",
            Domain::CustomIcon => "kdbx-core/custom-icon/v1",
        }
    }
}

/// The 32-byte HMAC key fingerprints are computed under.
///
/// Wiped on drop. `Debug` never prints the bytes. Deliberately not `Clone`:
/// share it by reference.
pub struct FingerprintKey([u8; 32]);

impl FingerprintKey {
    /// A key from caller-supplied bytes. Use fresh random bytes per session
    /// for in-process comparisons; the crate itself never draws randomness.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        FingerprintKey(bytes)
    }

    /// The fingerprint of `bytes` in role `domain`.
    pub fn fingerprint(&self, domain: Domain, bytes: &[u8]) -> Fingerprint {
        // HMAC accepts keys of any length, so this cannot fail.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0)
            .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
        mac.update(domain.label().as_bytes());
        mac.update(bytes);
        Fingerprint(mac.finalize().into_bytes().into())
    }
}

impl Drop for FingerprintKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FingerprintKey(<redacted>)")
    }
}

/// A 32-byte keyed fingerprint.
///
/// Equality compares all 32 bytes in constant time. Only display truncates:
/// [`Fingerprint::short`] (and `Display`) give 8 hex characters, while
/// serialization and [`Fingerprint::to_hex`] give all 64.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Number of hex characters in the display form.
    pub const SHORT_LEN: usize = 8;

    /// A fingerprint from its raw bytes (for example one read from a log).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Fingerprint(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// All 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        HEXLOWER.encode(&self.0)
    }

    /// The first 8 lowercase hex characters, for display only. Never compare
    /// fingerprints by their short form.
    pub fn short(&self) -> String {
        HEXLOWER.encode(&self.0[..Self::SHORT_LEN / 2])
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Fingerprint {}

impl Hash for Fingerprint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

/// Displays the short (8 hex character) form.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

/// The error of parsing a [`Fingerprint`] from anything but 64 hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFingerprintError;

impl fmt::Display for ParseFingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a fingerprint is exactly 64 hex characters")
    }
}

impl std::error::Error for ParseFingerprintError {}

/// Parses the full 64-hex-character form (either case).
impl FromStr for Fingerprint {
    type Err = ParseFingerprintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(|_| ParseFingerprintError)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| ParseFingerprintError)?;
        Ok(Fingerprint(bytes))
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The vault key material a stable [`FingerprintKey`] is derived from.
///
/// `keyfile` is the key file's raw bytes, exactly as stored on disk.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct KeyMaterial<'a> {
    /// The master password's bytes, if the vault has one.
    pub password: Option<&'a [u8]>,
    /// The key file's raw bytes, if the vault has one.
    pub keyfile: Option<&'a [u8]>,
}

impl<'a> KeyMaterial<'a> {
    /// Key material from an optional password and an optional key file.
    pub fn new(password: Option<&'a [u8]>, keyfile: Option<&'a [u8]>) -> Self {
        KeyMaterial { password, keyfile }
    }
}

impl fmt::Debug for KeyMaterial<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("keyfile", &self.keyfile.map(|_| "<redacted>"))
            .finish()
    }
}

/// Fixed Argon2id parameters of `FingerprintKey::derive` (part of the `v1`
/// format): 64 MiB, 3 passes, 1 lane, 32-byte output.
#[cfg(feature = "kdf")]
pub mod kdf_params {
    /// Memory cost in KiB (64 MiB).
    pub const MEMORY_KIB: u32 = 64 * 1024;
    /// Number of passes.
    pub const PASSES: u32 = 3;
    /// Degree of parallelism.
    pub const LANES: u32 = 1;
    /// The salt prefix; the vault's root-group UUID bytes follow it.
    pub const SALT_PREFIX: &[u8] = b"kdbx-core/fingerprint/v1";
}

/// Why `FingerprintKey::derive` failed.
#[cfg(feature = "kdf")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfError {
    /// Neither a password nor a key file was supplied. A key derived from no
    /// secret would make fingerprints a dictionary oracle again.
    NoKeyMaterial,
    /// The Argon2 backend rejected its input. Unreachable with the fixed
    /// parameters; kept so a backend change cannot panic.
    Backend,
}

#[cfg(feature = "kdf")]
impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::NoKeyMaterial => f.write_str("no password or key file to derive a key from"),
            KdfError::Backend => f.write_str("Argon2 rejected the derivation input"),
        }
    }
}

#[cfg(feature = "kdf")]
impl std::error::Error for KdfError {}

#[cfg(feature = "kdf")]
impl FingerprintKey {
    /// Derive a process-stable key from the vault's key material.
    ///
    /// Argon2id ([`kdf_params`]) over `SHA-256(password) || SHA-256(keyfile)`,
    /// an absent part contributing 32 zero bytes, salted with
    /// `"kdbx-core/fingerprint/v1" || salt`. Pass the root group's UUID as
    /// `salt`: it is stable across saves and distinct per vault.
    pub fn derive(material: &KeyMaterial<'_>, salt: Uuid) -> Result<Self, KdfError> {
        use argon2::{Algorithm, Argon2, Block, Params, Version};
        use sha2::Digest;
        use zeroize::Zeroizing;

        if material.password.is_none() && material.keyfile.is_none() {
            return Err(KdfError::NoKeyMaterial);
        }
        let digest_or_zero =
            |part: Option<&[u8]>| part.map_or([0u8; 32], |bytes| Sha256::digest(bytes).into());
        let mut input = Zeroizing::new([0u8; 64]);
        input[..32].copy_from_slice(&digest_or_zero(material.password));
        input[32..].copy_from_slice(&digest_or_zero(material.keyfile));

        let mut full_salt = Vec::with_capacity(kdf_params::SALT_PREFIX.len() + 16);
        full_salt.extend_from_slice(kdf_params::SALT_PREFIX);
        full_salt.extend_from_slice(salt.as_bytes());

        let params = Params::new(
            kdf_params::MEMORY_KIB,
            kdf_params::PASSES,
            kdf_params::LANES,
            Some(32),
        )
        .map_err(|_| KdfError::Backend)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut blocks = vec![Block::default(); argon.params().block_count()];
        let mut out = [0u8; 32];
        let result = argon.hash_password_into_with_memory(
            input.as_slice(),
            &full_salt,
            &mut out,
            &mut blocks,
        );
        // The working memory holds intermediate state derived from the secret.
        for block in &mut blocks {
            *block = Block::default();
        }
        result.map_err(|_| KdfError::Backend)?;
        Ok(FingerprintKey(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> FingerprintKey {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        FingerprintKey::from_bytes(bytes)
    }

    /// Known answers, cross-checked with Python's `hmac` module:
    /// `hmac.new(bytes(range(1, 33)), label + msg, hashlib.sha256)`.
    #[test]
    fn hmac_known_answers_per_domain() {
        let key = test_key();
        let cases: [(Domain, &[u8], &str); 4] = [
            (
                Domain::Field,
                b"hunter2",
                "8b08c4294d24f79298874b0fed8095007c1caa0ca20ccd763ecd40c7b6a2952b",
            ),
            (
                Domain::Attachment,
                b"hunter2",
                "0b92d24316e5f358862cb814d1d4c6e946a58cefb0d63a850e6e61dcd11f0bf7",
            ),
            (
                Domain::CustomData,
                b"",
                "762d1f245c01c5986db7a32772c59a8dac125116b2229ea98a2d0ec3858e5047",
            ),
            (
                Domain::CustomIcon,
                b"\x89PNG",
                "d811278410e344fed488158b21c809ce321b3631c150f7012767388b4d28c5e6",
            ),
        ];
        for (domain, msg, want) in cases {
            assert_eq!(key.fingerprint(domain, msg).to_hex(), want, "{domain:?}");
        }
    }

    #[test]
    fn domain_labels_are_prefix_free_and_versioned() {
        for a in Domain::ALL {
            assert!(a.label().starts_with("kdbx-core/") && a.label().ends_with("/v1"));
            for b in Domain::ALL {
                if a != b {
                    assert!(!b.label().starts_with(a.label()), "{a:?} prefixes {b:?}");
                }
            }
        }
    }

    #[test]
    fn different_keys_give_different_fingerprints() {
        let a = FingerprintKey::from_bytes([1; 32]).fingerprint(Domain::Field, b"1234");
        let b = FingerprintKey::from_bytes([2; 32]).fingerprint(Domain::Field, b"1234");
        assert_ne!(a, b);
    }

    #[test]
    fn short_is_the_hex_prefix_and_display_uses_it() {
        let fp = test_key().fingerprint(Domain::Field, b"hunter2");
        assert_eq!(fp.short(), "8b08c429");
        assert_eq!(fp.to_string(), "8b08c429");
        assert!(format!("{fp:?}").contains(&fp.to_hex()));
    }

    #[test]
    fn hex_parse_and_serde_round_trip() {
        let fp = test_key().fingerprint(Domain::Field, b"hunter2");
        assert_eq!(fp.to_hex().parse::<Fingerprint>(), Ok(fp));
        assert_eq!(fp.to_hex().to_uppercase().parse::<Fingerprint>(), Ok(fp));
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(json, format!("\"{}\"", fp.to_hex()));
        assert_eq!(serde_json::from_str::<Fingerprint>(&json).unwrap(), fp);
        for bad in [
            "",
            "8b08c429",
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(66),
        ] {
            assert_eq!(
                bad.parse::<Fingerprint>(),
                Err(ParseFingerprintError),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn equality_uses_all_bytes() {
        let mut bytes = [0u8; 32];
        let a = Fingerprint::from_bytes(bytes);
        bytes[31] = 1;
        let b = Fingerprint::from_bytes(bytes);
        assert_eq!(a.short(), b.short());
        assert_ne!(a, b);
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = FingerprintKey::from_bytes([0xAB; 32]);
        let shown = format!("{key:?}");
        assert_eq!(shown, "FingerprintKey(<redacted>)");
        let material = KeyMaterial::new(Some(b"hunter2"), Some(b"keyfile"));
        let shown = format!("{material:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("keyfile\""),
            "{shown}"
        );
    }

    #[cfg(feature = "kdf")]
    mod kdf {
        use super::*;

        const SALT: Uuid = Uuid::from_u128(0x0000_0001_d1ff_4000_8000_0000_0000_0000);

        fn sha256(bytes: &[u8]) -> [u8; 32] {
            use sha2::Digest;
            Sha256::digest(bytes).into()
        }

        /// Derive the key bytes with an independent Argon2 implementation
        /// (rust-argon2, the one keepass uses) from the documented recipe.
        fn reference_key_bytes(password: Option<&[u8]>, keyfile: Option<&[u8]>) -> Vec<u8> {
            let mut input = Vec::new();
            input.extend(password.map_or([0; 32], sha256));
            input.extend(keyfile.map_or([0; 32], sha256));
            let mut salt = kdf_params::SALT_PREFIX.to_vec();
            salt.extend_from_slice(SALT.as_bytes());
            let config = rust_argon2::Config {
                variant: rust_argon2::Variant::Argon2id,
                version: rust_argon2::Version::Version13,
                mem_cost: kdf_params::MEMORY_KIB,
                time_cost: kdf_params::PASSES,
                lanes: kdf_params::LANES,
                hash_length: 32,
                ..rust_argon2::Config::default()
            };
            rust_argon2::hash_raw(&input, &salt, &config).unwrap()
        }

        fn key_bytes(key: &FingerprintKey) -> &[u8; 32] {
            &key.0
        }

        #[test]
        fn derive_matches_the_documented_recipe_and_pinned_vector() {
            let material = KeyMaterial::new(Some(b"test-password-do-not-use"), None);
            let key = FingerprintKey::derive(&material, SALT).unwrap();
            let reference = reference_key_bytes(Some(b"test-password-do-not-use"), None);
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());
            // Pinned so the v1 format can never drift silently.
            assert_eq!(HEXLOWER.encode(key_bytes(&key)), PINNED_PASSWORD_ONLY);
            assert_eq!(
                key.fingerprint(Domain::Field, b"1234").to_hex(),
                PINNED_PIN_FINGERPRINT
            );
        }

        #[test]
        fn derive_with_keyfile_matches_the_reference() {
            let material = KeyMaterial::new(Some(b"pw"), Some(b"<KeyFile/>"));
            let key = FingerprintKey::derive(&material, SALT).unwrap();
            let reference = reference_key_bytes(Some(b"pw"), Some(b"<KeyFile/>"));
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());

            let keyfile_only = KeyMaterial::new(None, Some(b"<KeyFile/>"));
            let key = FingerprintKey::derive(&keyfile_only, SALT).unwrap();
            let reference = reference_key_bytes(None, Some(b"<KeyFile/>"));
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());
        }

        #[test]
        fn derive_depends_on_salt() {
            let material = KeyMaterial::new(Some(b"pw"), None);
            let a = FingerprintKey::derive(&material, SALT).unwrap();
            let b = FingerprintKey::derive(&material, Uuid::from_u128(2)).unwrap();
            assert_ne!(key_bytes(&a), key_bytes(&b));
        }

        #[test]
        fn derive_refuses_empty_key_material() {
            assert_eq!(
                FingerprintKey::derive(&KeyMaterial::default(), SALT).unwrap_err(),
                KdfError::NoKeyMaterial
            );
        }

        const PINNED_PASSWORD_ONLY: &str =
            "f0fb42b4dcdfe75e9f38791729c3feb45172ae70e225cf6f0389069ecb42f6af";
        const PINNED_PIN_FINGERPRINT: &str =
            "380586ba3b18b1f5d9739b56eb47028e720451843598fe5078472f07dd93e93c";
    }
}
