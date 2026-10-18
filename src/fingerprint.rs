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
//!   (git textconv, verifiable audit logs). Its [`DeriveParams`] are, per
//!   component, the maximum of a 64 MiB / 3 passes / 1 lane floor and the
//!   vault's own Argon2 parameters ([`DeriveParams::for_snapshot`]), so
//!   breaking such a fingerprint costs at least as much as attacking the vault
//!   through its own KDF (for an AES-KDF vault, at least the Argon2id floor).
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

use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(feature = "kdf")]
use uuid::Uuid;

use crate::model::{HeaderInfo, KdfInfo, Snapshot};

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
    /// Every domain. A slice, not an array, so adding a domain to this
    /// `#[non_exhaustive]` enum is not a breaking change.
    pub const ALL: &'static [Domain] = &[
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
    ///
    /// The array is taken by value (it is `Copy`): the key wipes its own copy
    /// on drop, but the caller's source buffer is the caller's to wipe.
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
        crate::codec::hex_encode(&self.0)
    }

    /// The first 8 lowercase hex characters, for display only. Never compare
    /// fingerprints by their short form.
    pub fn short(&self) -> String {
        crate::codec::hex_encode(&self.0[..Self::SHORT_LEN / 2])
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
        let bytes = crate::codec::hex_decode(s).ok_or(ParseFingerprintError)?;
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

/// The salt prefix of `FingerprintKey::derive` (part of the `v1` format); the
/// vault's root-group UUID bytes follow it.
pub const DERIVE_SALT_PREFIX: &[u8] = b"kdbx-core/fingerprint/v1";

/// The Argon2id parameters of a fingerprint key derivation.
///
/// Never below [`DeriveParams::FLOOR`] (64 MiB, 3 passes, 1 lane) in any
/// component, and, via [`DeriveParams::for_snapshot`], never below the vault's
/// own Argon2 parameters, so a fingerprint is never a cheaper oracle on the
/// master password than the vault itself.
///
/// The parameters are part of what a verifier must reproduce: record them
/// next to the fingerprints (`Display` gives a PHC-style string, serde a
/// structured form).
///
/// ```
/// use kdbx_core::fingerprint::DeriveParams;
///
/// let p = DeriveParams::new(1 << 20, 2, 4);
/// assert_eq!(p.to_string(), "argon2id$v=19$m=1048576,t=3,p=4");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "DeriveParamsRepr", into = "DeriveParamsRepr")]
pub struct DeriveParams {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

/// The serialized form of [`DeriveParams`], checked against the floor on the
/// way in.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeriveParamsRepr {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl DeriveParams {
    /// The floor: 64 MiB, 3 passes, 1 lane.
    pub const FLOOR: DeriveParams = DeriveParams {
        memory_kib: 64 * 1024,
        iterations: 3,
        lanes: 1,
    };

    /// Parameters with each component raised to at least the floor.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Self {
        DeriveParams {
            memory_kib: memory_kib.max(Self::FLOOR.memory_kib),
            iterations: iterations.max(Self::FLOOR.iterations),
            lanes: lanes.max(Self::FLOOR.lanes),
        }
    }

    /// The parameters for a vault using `kdf`: per component, the maximum of
    /// the floor and the vault's Argon2 parameters (always run as Argon2id).
    /// AES-KDF and unrecognized KDFs get the floor.
    pub fn for_kdf(kdf: &KdfInfo) -> Self {
        match kdf {
            KdfInfo::Argon2(a) => {
                let saturate = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
                Self::new(
                    saturate(a.memory_bytes.div_ceil(1024)),
                    saturate(a.iterations),
                    a.parallelism,
                )
            }
            KdfInfo::Aes { .. } | KdfInfo::Unrecognized => Self::FLOOR,
        }
    }

    /// [`DeriveParams::for_kdf`] of a captured header, or the floor without one.
    pub fn for_header(header: Option<&HeaderInfo>) -> Self {
        header.map_or(Self::FLOOR, |h| Self::for_kdf(&h.kdf))
    }

    /// The parameters for the vault `snap` was captured from.
    pub fn for_snapshot(snap: &Snapshot) -> Self {
        Self::for_header(snap.header.as_ref())
    }

    /// Memory cost in KiB.
    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Number of passes.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Degree of parallelism.
    pub fn lanes(&self) -> u32 {
        self.lanes
    }
}

/// PHC-style: `argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>`.
impl fmt::Display for DeriveParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "argon2id$v=19$m={},t={},p={}",
            self.memory_kib, self.iterations, self.lanes
        )
    }
}

/// The error of deserializing [`DeriveParams`] below the floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BelowFloorError;

impl fmt::Display for BelowFloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "derivation parameters below the floor {}",
            DeriveParams::FLOOR
        )
    }
}

impl std::error::Error for BelowFloorError {}

impl TryFrom<DeriveParamsRepr> for DeriveParams {
    type Error = BelowFloorError;

    fn try_from(r: DeriveParamsRepr) -> Result<Self, Self::Error> {
        let params = DeriveParams::new(r.memory_kib, r.iterations, r.lanes);
        let raw = DeriveParams {
            memory_kib: r.memory_kib,
            iterations: r.iterations,
            lanes: r.lanes,
        };
        if params == raw {
            Ok(params)
        } else {
            Err(BelowFloorError)
        }
    }
}

impl From<DeriveParams> for DeriveParamsRepr {
    fn from(p: DeriveParams) -> Self {
        DeriveParamsRepr {
            memory_kib: p.memory_kib,
            iterations: p.iterations,
            lanes: p.lanes,
        }
    }
}

/// Why `FingerprintKey::derive` failed.
#[cfg(feature = "kdf")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfError {
    /// Neither a password nor a key file was supplied. A key derived from no
    /// secret would make fingerprints a dictionary oracle again.
    NoKeyMaterial,
    /// Argon2 rejected the parameters (for example more lanes than it
    /// supports, or more memory than the platform can address).
    InvalidParams,
    /// The Argon2 backend failed on otherwise valid input. Kept so a backend
    /// change cannot panic.
    Backend,
}

#[cfg(feature = "kdf")]
impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::NoKeyMaterial => f.write_str("no password or key file to derive a key from"),
            KdfError::InvalidParams => f.write_str("Argon2 rejected the derivation parameters"),
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
    /// Argon2id with `params` over `SHA-256(password) || SHA-256(keyfile)`, an
    /// absent part contributing 32 zero bytes, salted with
    /// [`DERIVE_SALT_PREFIX`] `|| salt`. Pass the root group's UUID as `salt`
    /// (stable across saves, distinct per vault) and
    /// [`DeriveParams::for_snapshot`] as `params`, and record `params` next to
    /// the fingerprints so a verifier can reproduce the key.
    ///
    /// The input, the output and Argon2's working memory are wiped. The
    /// SHA-256 hasher states that absorbed the password and key file are not:
    /// sha2 0.10 offers no zeroization.
    pub fn derive(
        material: &KeyMaterial<'_>,
        salt: Uuid,
        params: &DeriveParams,
    ) -> Result<Self, KdfError> {
        use argon2::{Algorithm, Argon2, Block, Params, Version};
        use sha2::Digest;
        use sha2::digest::generic_array::GenericArray;
        use zeroize::Zeroizing;

        if material.password.is_none() && material.keyfile.is_none() {
            return Err(KdfError::NoKeyMaterial);
        }
        // Checked before Params::new, which overflows (and panics in debug
        // builds) on a lane count beyond Argon2's limit.
        if params.lanes() > Params::MAX_P_COST
            || u64::from(params.memory_kib()) < 8 * u64::from(params.lanes())
        {
            return Err(KdfError::InvalidParams);
        }
        let argon_params = Params::new(
            params.memory_kib(),
            params.iterations(),
            params.lanes(),
            Some(32),
        )
        .map_err(|_| KdfError::InvalidParams)?;

        // Hash straight into the wiped input buffer: no digest temporaries.
        let mut input = Zeroizing::new([0u8; 64]);
        let (pw_half, kf_half) = input.split_at_mut(32);
        for (part, half) in [(material.password, pw_half), (material.keyfile, kf_half)] {
            if let Some(bytes) = part {
                Sha256::new_with_prefix(bytes).finalize_into(GenericArray::from_mut_slice(half));
            }
        }

        let mut full_salt = Vec::with_capacity(DERIVE_SALT_PREFIX.len() + 16);
        full_salt.extend_from_slice(DERIVE_SALT_PREFIX);
        full_salt.extend_from_slice(salt.as_bytes());

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
        // Fallible allocation: a vault's memory cost comes from its file.
        let block_count = argon.params().block_count();
        let mut blocks = Zeroizing::new(Vec::new());
        blocks
            .try_reserve_exact(block_count)
            .map_err(|_| KdfError::InvalidParams)?;
        blocks.resize(block_count, Block::default());
        let mut out = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into_with_memory(
                input.as_slice(),
                &full_salt,
                out.as_mut(),
                blocks.as_mut_slice(),
            )
            .map_err(|_| KdfError::Backend)?;
        Ok(FingerprintKey(*out))
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
    fn all_is_a_slice_so_new_domains_are_not_a_breaking_change() {
        let all: &'static [Domain] = Domain::ALL;
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn domain_labels_are_prefix_free_and_versioned() {
        for &a in Domain::ALL {
            assert!(a.label().starts_with("kdbx-core/") && a.label().ends_with("/v1"));
            for &b in Domain::ALL {
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

    mod derive_params {
        use super::*;
        use crate::model::{
            Argon2Info, Argon2Variant, Compression, FormatVersion, Group, HeaderInfo, InnerCipher,
            KdfInfo, Meta, OuterCipher, Snapshot,
        };

        fn argon2(memory_bytes: u64, iterations: u64, parallelism: u32) -> KdfInfo {
            KdfInfo::Argon2(Argon2Info::new(
                Argon2Variant::Argon2d,
                memory_bytes,
                iterations,
                parallelism,
                0x13,
            ))
        }

        fn snapshot_with(kdf: Option<KdfInfo>) -> Snapshot {
            let mut snap = Snapshot::new(
                FormatVersion::KDBX_4_0,
                Meta::default(),
                Group::new(uuid::Uuid::nil(), "Root"),
            );
            snap.header = kdf.map(|kdf| {
                HeaderInfo::new(
                    kdf,
                    OuterCipher::Aes256,
                    InnerCipher::ChaCha20,
                    Compression::GZip,
                )
            });
            snap
        }

        fn triple(p: DeriveParams) -> (u32, u32, u32) {
            (p.memory_kib(), p.iterations(), p.lanes())
        }

        #[test]
        fn floor_is_64_mib_3_passes_1_lane() {
            assert_eq!(triple(DeriveParams::FLOOR), (64 * 1024, 3, 1));
        }

        #[test]
        fn params_are_the_per_component_max_of_floor_and_vault() {
            let cases = [
                // No header, AES-KDF, or an unknown KDF: the floor.
                (None, (65_536, 3, 1)),
                (Some(KdfInfo::Aes { rounds: 60_000 }), (65_536, 3, 1)),
                (Some(KdfInfo::Unrecognized), (65_536, 3, 1)),
                // keepass's default Argon2d: 1 MiB, 50 passes, 4 lanes.
                (Some(argon2(1 << 20, 50, 4)), (65_536, 50, 4)),
                // A memory-heavy vault: 256 MiB, 2 passes.
                (Some(argon2(256 << 20, 2, 1)), (262_144, 3, 1)),
                // Odd byte counts round up to whole KiB.
                (Some(argon2((128 << 20) + 1, 3, 1)), (131_073, 3, 1)),
            ];
            for (kdf, want) in cases {
                assert_eq!(
                    triple(DeriveParams::for_snapshot(&snapshot_with(kdf))),
                    want,
                    "{kdf:?}"
                );
            }
            // Absurd values saturate instead of wrapping.
            assert_eq!(
                triple(DeriveParams::for_kdf(&argon2(u64::MAX, u64::MAX, 2))),
                (u32::MAX, u32::MAX, 2)
            );
        }

        #[test]
        fn new_raises_each_component_to_the_floor() {
            assert_eq!(triple(DeriveParams::new(1, 1, 0)), (65_536, 3, 1));
            assert_eq!(triple(DeriveParams::new(1 << 20, 2, 8)), (1 << 20, 3, 8));
        }

        #[test]
        fn params_display_and_serialize_for_recording() {
            let p = DeriveParams::new(1 << 20, 50, 4);
            assert_eq!(p.to_string(), "argon2id$v=19$m=1048576,t=50,p=4");
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, r#"{"memory_kib":1048576,"iterations":50,"lanes":4}"#);
            assert_eq!(serde_json::from_str::<DeriveParams>(&json).unwrap(), p);
            // Recorded params below the floor were never produced by derive.
            assert!(
                serde_json::from_str::<DeriveParams>(
                    r#"{"memory_kib":1024,"iterations":3,"lanes":1}"#
                )
                .is_err()
            );
        }
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
        fn reference_key_bytes(
            password: Option<&[u8]>,
            keyfile: Option<&[u8]>,
            params: &DeriveParams,
        ) -> Vec<u8> {
            let mut input = Vec::new();
            input.extend(password.map_or([0; 32], sha256));
            input.extend(keyfile.map_or([0; 32], sha256));
            let mut salt = DERIVE_SALT_PREFIX.to_vec();
            salt.extend_from_slice(SALT.as_bytes());
            let config = rust_argon2::Config {
                variant: rust_argon2::Variant::Argon2id,
                version: rust_argon2::Version::Version13,
                mem_cost: params.memory_kib(),
                time_cost: params.iterations(),
                lanes: params.lanes(),
                hash_length: 32,
                ..rust_argon2::Config::default()
            };
            rust_argon2::hash_raw(&input, &salt, &config).unwrap()
        }

        fn key_bytes(key: &FingerprintKey) -> &[u8; 32] {
            &key.0
        }

        #[test]
        fn derive_at_the_floor_matches_the_reference_and_pinned_vector() {
            let material = KeyMaterial::new(Some(b"test-password-do-not-use"), None);
            let params = DeriveParams::FLOOR;
            let key = FingerprintKey::derive(&material, SALT, &params).unwrap();
            let reference = reference_key_bytes(Some(b"test-password-do-not-use"), None, &params);
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());
            // Pinned so the v1 format can never drift silently.
            assert_eq!(crate::codec::hex_encode(key_bytes(&key)), PINNED_FLOOR);
            assert_eq!(
                key.fingerprint(Domain::Field, b"1234").to_hex(),
                PINNED_FLOOR_PIN_FINGERPRINT
            );
        }

        #[test]
        fn derive_above_the_floor_matches_the_reference_and_pinned_vector() {
            let material = KeyMaterial::new(Some(b"test-password-do-not-use"), None);
            let params = DeriveParams::new(96 * 1024, 4, 2);
            let key = FingerprintKey::derive(&material, SALT, &params).unwrap();
            let reference = reference_key_bytes(Some(b"test-password-do-not-use"), None, &params);
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());
            assert_eq!(crate::codec::hex_encode(key_bytes(&key)), PINNED_M96_T4_P2);
        }

        #[test]
        fn derive_with_keyfile_matches_the_reference() {
            let params = DeriveParams::FLOOR;
            let material = KeyMaterial::new(Some(b"pw"), Some(b"<KeyFile/>"));
            let key = FingerprintKey::derive(&material, SALT, &params).unwrap();
            let reference = reference_key_bytes(Some(b"pw"), Some(b"<KeyFile/>"), &params);
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());

            let keyfile_only = KeyMaterial::new(None, Some(b"<KeyFile/>"));
            let key = FingerprintKey::derive(&keyfile_only, SALT, &params).unwrap();
            let reference = reference_key_bytes(None, Some(b"<KeyFile/>"), &params);
            assert_eq!(key_bytes(&key).as_slice(), reference.as_slice());
        }

        #[test]
        fn derive_depends_on_salt_and_params() {
            let material = KeyMaterial::new(Some(b"pw"), None);
            let floor = DeriveParams::FLOOR;
            let a = FingerprintKey::derive(&material, SALT, &floor).unwrap();
            let b = FingerprintKey::derive(&material, Uuid::from_u128(2), &floor).unwrap();
            let c = FingerprintKey::derive(&material, SALT, &DeriveParams::new(0, 4, 1)).unwrap();
            assert_ne!(key_bytes(&a), key_bytes(&b));
            assert_ne!(key_bytes(&a), key_bytes(&c));
        }

        #[test]
        fn derive_refuses_empty_key_material() {
            assert_eq!(
                FingerprintKey::derive(&KeyMaterial::default(), SALT, &DeriveParams::FLOOR)
                    .unwrap_err(),
                KdfError::NoKeyMaterial
            );
        }

        #[test]
        fn derive_reports_parameters_argon2_rejects() {
            // More lanes than Argon2 allows.
            let params = DeriveParams::new(0, 0, u32::MAX);
            assert_eq!(
                FingerprintKey::derive(&KeyMaterial::new(Some(b"pw"), None), SALT, &params)
                    .unwrap_err(),
                KdfError::InvalidParams
            );
        }

        const PINNED_FLOOR: &str =
            "f0fb42b4dcdfe75e9f38791729c3feb45172ae70e225cf6f0389069ecb42f6af";
        const PINNED_FLOOR_PIN_FINGERPRINT: &str =
            "380586ba3b18b1f5d9739b56eb47028e720451843598fe5078472f07dd93e93c";
        const PINNED_M96_T4_P2: &str =
            "73d3fb59f607ad267c2cc92d07fee5642a3cf58bbd11f0e21b11abb993b6871b";
    }
}
