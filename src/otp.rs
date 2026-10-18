//! TOTP resolution and code computation.
//!
//! An entry can carry a TOTP configuration in three historical encodings,
//! each a set of fields named by [`OtpField`]. They are tried in order; a
//! source that is present but malformed falls through to the next, and if no
//! present source is usable the result is [`OtpError::Malformed`] (never a
//! silent "no OTP"):
//!
//! 1. the `otp` field, an `otpauth://totp/...` URI (KeePassXC);
//! 2. KeePass 2's native `TimeOtp-*` fields (the `{TIMEOTP}` placeholder);
//! 3. the legacy `TOTP Seed` plus `TOTP Settings` pair (KeeOtp, older
//!    KeePassXC).
//!
//! [`resolve`] reads them from a snapshot [`Entry`]; it needs the plaintext,
//! so it reports [`OtpError::Sealed`] for a fingerprint-sealed snapshot.
//! Callers that capture under fingerprint sealing take the OTP fields from
//! the live keepass entry instead (`capture::keepass_0_*::otp_fields`) and
//! call [`resolve_fields`].
//!
//! The module never reads a clock: [`TotpConfig::code_at`] takes the time, so
//! it runs unchanged in WASM. Untrusted parameters are bounds-checked (a zero
//! period or an unbounded digit count is rejected, not computed), and unknown
//! algorithms or encoders are rejected rather than guessed. Steam Guard codes
//! ([`TotpEncoding::Steam`]) are supported as KeePassXC writes them.
//!
//! ```
//! use kdbx_core::otp::{resolve_fields, OtpField, OtpFields};
//!
//! let fields: OtpFields = [(OtpField::Uri, "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")]
//!     .into_iter()
//!     .collect();
//! let config = resolve_fields(&fields).unwrap().expect("configured");
//! let code = config.code_at(59);
//! assert_eq!(code.code(), "287082"); // RFC 6238, SHA-1, T = 59
//! assert_eq!(code.valid_for_seconds(), 1);
//! ```
//!
//! Ported from mcp-kdbx's `totp.rs`, made keepass-free.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use data_encoding::{BASE64, Encoding, HEXLOWER_PERMISSIVE, Specification};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::model::{Entry, Value};

/// An entry field that carries TOTP configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OtpField {
    /// `otp`: an `otpauth://totp/...` URI (KeePassXC).
    Uri,
    /// `TOTP Seed`: base32 secret (KeeOtp, older KeePassXC).
    LegacySeed,
    /// `TOTP Settings`: `period;digits` (KeeOtp, older KeePassXC).
    LegacySettings,
    /// `TimeOtp-Secret`: the secret as UTF-8 text (KeePass 2.47+).
    NativeSecret,
    /// `TimeOtp-Secret-Hex`: the secret, hex-encoded.
    NativeSecretHex,
    /// `TimeOtp-Secret-Base32`: the secret, base32-encoded.
    NativeSecretBase32,
    /// `TimeOtp-Secret-Base64`: the secret, base64-encoded.
    NativeSecretBase64,
    /// `TimeOtp-Length`: code length (default 6, at most 8).
    NativeLength,
    /// `TimeOtp-Period`: time step in seconds (default 30).
    NativePeriod,
    /// `TimeOtp-Algorithm`: `HMAC-SHA-1` (default), `HMAC-SHA-256` or
    /// `HMAC-SHA-512`.
    NativeAlgorithm,
}

impl OtpField {
    /// Every OTP field. A slice, not an array, so adding a field to this
    /// `#[non_exhaustive]` enum is not a breaking change.
    pub const ALL: &'static [OtpField] = &[
        OtpField::Uri,
        OtpField::LegacySeed,
        OtpField::LegacySettings,
        OtpField::NativeSecret,
        OtpField::NativeSecretHex,
        OtpField::NativeSecretBase32,
        OtpField::NativeSecretBase64,
        OtpField::NativeLength,
        OtpField::NativePeriod,
        OtpField::NativeAlgorithm,
    ];

    /// The field's name as stored in KDBX.
    pub fn kdbx_name(self) -> &'static str {
        match self {
            OtpField::Uri => "otp",
            OtpField::LegacySeed => "TOTP Seed",
            OtpField::LegacySettings => "TOTP Settings",
            OtpField::NativeSecret => "TimeOtp-Secret",
            OtpField::NativeSecretHex => "TimeOtp-Secret-Hex",
            OtpField::NativeSecretBase32 => "TimeOtp-Secret-Base32",
            OtpField::NativeSecretBase64 => "TimeOtp-Secret-Base64",
            OtpField::NativeLength => "TimeOtp-Length",
            OtpField::NativePeriod => "TimeOtp-Period",
            OtpField::NativeAlgorithm => "TimeOtp-Algorithm",
        }
    }

    /// The OTP field stored under `name`, if any (exact match).
    pub fn from_kdbx_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.kdbx_name() == name)
    }
}

/// Serializes as the KDBX field name.
impl Serialize for OtpField {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.kdbx_name())
    }
}

impl<'de> Deserialize<'de> for OtpField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        OtpField::from_kdbx_name(&name)
            .ok_or_else(|| serde::de::Error::custom(format!("'{name}' is not an OTP field")))
    }
}

impl fmt::Display for OtpField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kdbx_name())
    }
}

/// The plaintext of an entry's OTP-related fields, and nothing else.
///
/// Values are wiped on drop; `Debug` shows which fields are present, never
/// their values.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OtpFields(BTreeMap<OtpField, Zeroizing<String>>);

impl OtpFields {
    /// No fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `field` to `value`.
    pub fn insert(&mut self, field: OtpField, value: impl Into<String>) {
        self.0.insert(field, Zeroizing::new(value.into()));
    }

    /// The value of `field`, if present.
    pub fn get(&self, field: OtpField) -> Option<&str> {
        self.0.get(&field).map(|v| v.as_str())
    }

    /// Whether no OTP field is present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The fields present, in [`OtpField`] order.
    pub fn fields(&self) -> impl Iterator<Item = OtpField> + '_ {
        self.0.keys().copied()
    }
}

impl<S: Into<String>> FromIterator<(OtpField, S)> for OtpFields {
    fn from_iter<I: IntoIterator<Item = (OtpField, S)>>(iter: I) -> Self {
        let mut out = OtpFields::new();
        for (field, value) in iter {
            out.insert(field, value);
        }
        out
    }
}

impl fmt::Debug for OtpFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.fields()).finish()
    }
}

/// The HMAC hash a TOTP configuration uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 (the default when a source names none).
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// How the truncated HMAC value becomes the displayed code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TotpEncoding {
    /// Decimal digits, zero-padded (RFC 6238).
    #[default]
    Decimal,
    /// Steam Guard: five characters of `23456789BCDFGHJKMNPQRTVWXY`, least
    /// significant first (KeePassXC's `encoder=steam`, or `S` digits in the
    /// legacy `TOTP Settings`).
    Steam,
}

impl TotpEncoding {
    /// The Steam alphabet.
    pub const STEAM_ALPHABET: &'static str = "23456789BCDFGHJKMNPQRTVWXY";
    /// The length of a Steam code.
    pub const STEAM_DIGITS: u32 = 5;
}

/// Which of the three encodings an OTP configuration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum OtpSource {
    /// The `otp` field's `otpauth://` URI.
    Uri,
    /// KeePass 2's `TimeOtp-*` fields.
    #[serde(rename = "keepass_native")]
    KeePassNative,
    /// The legacy `TOTP Seed` / `TOTP Settings` pair.
    Legacy,
}

/// Why an OTP source that is present could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum MalformedReason {
    /// Not an `otpauth://` URI.
    NotAnOtpauthUri,
    /// An `otpauth://` URI of another type (`hotp`).
    NotTotp,
    /// No secret is given.
    MissingSecret,
    /// The secret does not decode, or decodes to nothing.
    InvalidSecret,
    /// More than one `TimeOtp-Secret*` field is set.
    MultipleSecrets,
    /// The period is not a positive integer.
    InvalidPeriod,
    /// The digit count is not an integer in range.
    InvalidDigits,
    /// An algorithm other than SHA-1, SHA-256 or SHA-512.
    UnknownAlgorithm,
    /// An `encoder` other than `steam`.
    UnknownEncoder,
    /// `TOTP Settings` is not `period;digits` (optionally `;url`).
    InvalidSettings,
    /// One field of a pair is missing.
    MissingField(OtpField),
}

/// A usable TOTP configuration: the decoded secret and its parameters.
///
/// The secret is wiped on drop and never shown by `Debug`.
#[derive(Clone)]
pub struct TotpConfig {
    secret: Zeroizing<Vec<u8>>,
    period: u32,
    digits: u32,
    algorithm: TotpAlgorithm,
    encoding: TotpEncoding,
}

/// A computed code and its remaining lifetime. `Debug` hides the code.
#[derive(Clone)]
pub struct TotpCode {
    code: Zeroizing<String>,
    valid_for_seconds: u32,
    period_seconds: u32,
}

/// Why an entry's TOTP configuration could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum OtpError {
    /// An OTP field is sealed in the snapshot, so its plaintext is not
    /// available. Resolve from the live entry's `otp_fields` instead, or
    /// capture under `Sealing::Reveal`.
    Sealed(OtpField),
    /// OTP is configured but no source is usable; this is the first
    /// malformed source in precedence order.
    Malformed {
        /// The source that is malformed.
        source: OtpSource,
        /// What is wrong with it.
        reason: MalformedReason,
    },
}

impl fmt::Display for MalformedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MalformedReason::NotAnOtpauthUri => f.write_str("not an otpauth:// URI"),
            MalformedReason::NotTotp => f.write_str("not a TOTP (otpauth://totp/) URI"),
            MalformedReason::MissingSecret => f.write_str("no secret"),
            MalformedReason::InvalidSecret => f.write_str("the secret does not decode"),
            MalformedReason::MultipleSecrets => f.write_str("more than one TimeOtp-Secret field"),
            MalformedReason::InvalidPeriod => f.write_str("invalid period"),
            MalformedReason::InvalidDigits => f.write_str("invalid digit count"),
            MalformedReason::UnknownAlgorithm => f.write_str("unknown algorithm"),
            MalformedReason::UnknownEncoder => f.write_str("unknown encoder"),
            MalformedReason::InvalidSettings => f.write_str("TOTP Settings is not period;digits"),
            MalformedReason::MissingField(field) => write!(f, "missing field '{field}'"),
        }
    }
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpError::Sealed(field) => write!(f, "OTP field '{field}' is sealed in this snapshot"),
            OtpError::Malformed { source, reason } => {
                write!(f, "malformed OTP configuration ({source}): {reason}")
            }
        }
    }
}

impl std::error::Error for OtpError {}

impl fmt::Display for OtpSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OtpSource::Uri => "otpauth URI",
            OtpSource::KeePassNative => "KeePass TimeOtp fields",
            OtpSource::Legacy => "legacy TOTP Seed/Settings",
        })
    }
}

/// The TOTP configuration of a snapshot entry: `Ok(None)` when it has none,
/// an error when an OTP field is sealed or the configuration is malformed.
pub fn resolve(entry: &Entry) -> Result<Option<TotpConfig>, OtpError> {
    let mut fields = OtpFields::new();
    for (name, field) in &entry.fields {
        let Some(otp_field) = OtpField::from_kdbx_name(name) else {
            continue;
        };
        match &field.value {
            Value::Plain(text) => fields.insert(otp_field, text.as_str()),
            Value::Sealed(_) => return Err(OtpError::Sealed(otp_field)),
        }
    }
    resolve_fields(&fields)
}

/// The TOTP configuration carried by `fields`.
///
/// Sources are tried in precedence order (URI, KeePass 2 native fields,
/// legacy pair); a source counts as present when any of its fields is
/// non-empty. The first well-formed present source wins, so a malformed
/// source falls through to a later one. `Ok(None)` when no source is present;
/// [`OtpError::Malformed`] (for the first malformed source) when sources are
/// present but none is usable.
pub fn resolve_fields(fields: &OtpFields) -> Result<Option<TotpConfig>, OtpError> {
    let mut first_error = None;
    for &source in OtpSource::PRECEDENCE {
        if !source.is_present(fields) {
            continue;
        }
        match source.parse(fields) {
            Ok(config) => return Ok(Some(config)),
            Err(reason) => {
                first_error.get_or_insert(OtpError::Malformed { source, reason });
            }
        }
    }
    first_error.map_or(Ok(None), Err)
}

impl OtpSource {
    /// The sources in the order [`resolve_fields`] tries them.
    pub const PRECEDENCE: &'static [OtpSource] =
        &[OtpSource::Uri, OtpSource::KeePassNative, OtpSource::Legacy];

    /// Whether any of this source's fields is non-empty in `fields`.
    pub fn is_present(self, fields: &OtpFields) -> bool {
        self.fields()
            .iter()
            .any(|&field| fields.get(field).is_some_and(|v| !v.is_empty()))
    }

    /// Read this source's configuration from `fields`.
    pub fn parse(self, fields: &OtpFields) -> Result<TotpConfig, MalformedReason> {
        match self {
            OtpSource::Uri => TotpConfig::from_uri(fields.get(OtpField::Uri).unwrap_or("")),
            OtpSource::KeePassNative => TotpConfig::from_keepass_native(fields),
            OtpSource::Legacy => {
                // KeePassXC (`Totp::parseSettings`) falls back to its defaults
                // when `TOTP Settings` is absent or empty, so a lone seed is a
                // valid 30-second, 6-digit configuration. Settings that are
                // present but malformed stay an error (never a guessed code).
                let seed = fields
                    .get(OtpField::LegacySeed)
                    .filter(|v| !v.is_empty())
                    .ok_or(MalformedReason::MissingField(OtpField::LegacySeed))?;
                let settings = fields
                    .get(OtpField::LegacySettings)
                    .filter(|v| !v.is_empty())
                    .unwrap_or(TotpConfig::LEGACY_DEFAULT_SETTINGS);
                TotpConfig::from_legacy(seed, settings)
            }
        }
    }

    /// The fields this source reads.
    pub fn fields(self) -> &'static [OtpField] {
        match self {
            OtpSource::Uri => &[OtpField::Uri],
            OtpSource::KeePassNative => &[
                OtpField::NativeSecret,
                OtpField::NativeSecretHex,
                OtpField::NativeSecretBase32,
                OtpField::NativeSecretBase64,
                OtpField::NativeLength,
                OtpField::NativePeriod,
                OtpField::NativeAlgorithm,
            ],
            OtpSource::Legacy => &[OtpField::LegacySeed, OtpField::LegacySettings],
        }
    }
}

impl TotpConfig {
    /// Smallest accepted period: a zero period would divide by zero.
    pub const MIN_PERIOD: u32 = 1;
    /// Largest accepted digit count: `10^digits` must fit the code arithmetic,
    /// and real sources use 6 to 8.
    pub const MAX_DIGITS: u32 = 10;
    /// KeePass's own cap on `TimeOtp-Length`.
    pub const NATIVE_MAX_DIGITS: u32 = 8;

    /// Parse an `otpauth://totp/...` URI.
    ///
    /// A base32 `secret` is required. `period` (default 30), `digits`
    /// (default 6), `algorithm` (`SHA1` default, `SHA256`, `SHA512`) and
    /// `encoder` (only `steam`, which yields five Steam characters) are
    /// optional; any other algorithm or encoder is rejected rather than
    /// guessed.
    pub fn from_uri(uri: &str) -> Result<Self, MalformedReason> {
        use MalformedReason::*;
        // RFC 3986 generic syntax: scheme "://" authority path ["?" query]
        // ["#" fragment]. For otpauth the authority is the OTP type.
        let (scheme, rest) = uri.split_once("://").ok_or(NotAnOtpauthUri)?;
        if !scheme.eq_ignore_ascii_case("otpauth") {
            return Err(NotAnOtpauthUri);
        }
        let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
        let (authority_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let authority = authority_and_path
            .split_once('/')
            .map_or(authority_and_path, |(authority, _)| authority);
        if !authority.eq_ignore_ascii_case("totp") {
            return Err(NotTotp);
        }

        let mut secret = None;
        let mut period = 30u32;
        let mut digits = 6u32;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut encoding = TotpEncoding::Decimal;
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "secret" => secret = Some(decode_base32_secret(&value).ok_or(InvalidSecret)?),
                "period" => period = value.trim().parse().map_err(|_| InvalidPeriod)?,
                "digits" => digits = value.trim().parse().map_err(|_| InvalidDigits)?,
                "algorithm" => algorithm = uri_algorithm(&value)?,
                "encoder" if value.eq_ignore_ascii_case("steam") => encoding = TotpEncoding::Steam,
                "encoder" => return Err(UnknownEncoder),
                _ => {}
            }
        }
        if encoding == TotpEncoding::Steam {
            digits = TotpEncoding::STEAM_DIGITS;
        }
        Self::checked(
            secret.ok_or(MissingSecret)?,
            period,
            digits,
            algorithm,
            encoding,
        )
    }

    /// The `TOTP Settings` value KeePassXC assumes when the field is absent
    /// or empty: a 30-second period and 6 digits.
    pub const LEGACY_DEFAULT_SETTINGS: &'static str = "30;6";

    /// Build from the legacy pair: a base32 `TOTP Seed` and a `TOTP Settings`
    /// string `period;digits`, where digits `S` means Steam (KeePassXC). A
    /// third part (KeeTrayTOTP's time-correction URL) is ignored. Always SHA-1.
    pub fn from_legacy(seed: &str, settings: &str) -> Result<Self, MalformedReason> {
        use MalformedReason::*;
        let secret = decode_base32_secret(seed).ok_or(InvalidSecret)?;
        let parts: Vec<&str> = settings.split(';').map(str::trim).collect();
        let (period, digits) = match parts.as_slice() {
            [period, digits] | [period, digits, _] => (*period, *digits),
            _ => return Err(InvalidSettings),
        };
        let period = period.parse().map_err(|_| InvalidPeriod)?;
        let (digits, encoding) = if digits == "S" {
            (TotpEncoding::STEAM_DIGITS, TotpEncoding::Steam)
        } else {
            (
                digits.parse().map_err(|_| InvalidDigits)?,
                TotpEncoding::Decimal,
            )
        };
        Self::checked(secret, period, digits, TotpAlgorithm::Sha1, encoding)
    }

    /// Build from KeePass 2's native `TimeOtp-*` fields. Exactly one non-empty
    /// secret field must be present (an empty one is skipped, as KeePass
    /// does); length (1..=8, default 6), period (default 30) and algorithm
    /// (`HMAC-SHA-1` default, `HMAC-SHA-256`, `HMAC-SHA-512`) are optional.
    pub fn from_keepass_native(fields: &OtpFields) -> Result<Self, MalformedReason> {
        use MalformedReason::*;
        let decoders: [(OtpField, SecretDecoder); 4] = [
            (OtpField::NativeSecret, |v| Some(v.as_bytes().to_vec())),
            (OtpField::NativeSecretHex, |v| {
                HEXLOWER_PERMISSIVE.decode(compact(v).as_bytes()).ok()
            }),
            (OtpField::NativeSecretBase32, decode_base32_secret),
            (OtpField::NativeSecretBase64, |v| {
                BASE64.decode(compact(v).as_bytes()).ok()
            }),
        ];
        let mut present = decoders.iter().filter_map(|(field, decode)| {
            fields
                .get(*field)
                .filter(|v| !v.is_empty())
                .map(|v| (*decode, v))
        });
        let (decode, value) = present.next().ok_or(MissingSecret)?;
        if present.next().is_some() {
            return Err(MultipleSecrets);
        }
        let secret = decode(value).ok_or(InvalidSecret)?;

        let digits = match fields.get(OtpField::NativeLength) {
            Some(v) => v
                .trim()
                .parse()
                .ok()
                .filter(|d| *d <= Self::NATIVE_MAX_DIGITS)
                .ok_or(InvalidDigits)?,
            None => 6,
        };
        let period = match fields.get(OtpField::NativePeriod) {
            Some(v) => v.trim().parse().map_err(|_| InvalidPeriod)?,
            None => 30,
        };
        let algorithm = match fields.get(OtpField::NativeAlgorithm).map(str::trim) {
            None | Some("HMAC-SHA-1") => TotpAlgorithm::Sha1,
            Some("HMAC-SHA-256") => TotpAlgorithm::Sha256,
            Some("HMAC-SHA-512") => TotpAlgorithm::Sha512,
            Some(_) => return Err(UnknownAlgorithm),
        };
        Self::checked(secret, period, digits, algorithm, TotpEncoding::Decimal)
    }

    /// A config, or the reason it is unusable: an empty secret, or a
    /// parameter that would make the computation divide by zero or overflow.
    fn checked(
        secret: Vec<u8>,
        period: u32,
        digits: u32,
        algorithm: TotpAlgorithm,
        encoding: TotpEncoding,
    ) -> Result<Self, MalformedReason> {
        let secret = Zeroizing::new(secret);
        if secret.is_empty() {
            return Err(MalformedReason::InvalidSecret);
        }
        if period < Self::MIN_PERIOD {
            return Err(MalformedReason::InvalidPeriod);
        }
        if !(1..=Self::MAX_DIGITS).contains(&digits) {
            return Err(MalformedReason::InvalidDigits);
        }
        Ok(TotpConfig {
            secret,
            period,
            digits,
            algorithm,
            encoding,
        })
    }

    /// The time step in seconds.
    pub fn period(&self) -> u32 {
        self.period
    }

    /// The code length.
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// The HMAC hash.
    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// How codes are rendered.
    pub fn encoding(&self) -> TotpEncoding {
        self.encoding
    }

    /// The code for the time step containing `unix_time` (RFC 6238).
    pub fn code_at(&self, unix_time: u64) -> TotpCode {
        let period = u64::from(self.period);
        let counter = (unix_time / period).to_be_bytes();
        let mac = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac::<Hmac<Sha1>>(&self.secret, &counter),
            TotpAlgorithm::Sha256 => hmac::<Hmac<Sha256>>(&self.secret, &counter),
            TotpAlgorithm::Sha512 => hmac::<Hmac<Sha512>>(&self.secret, &counter),
        };
        // RFC 4226 dynamic truncation.
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let truncated = u32::from_be_bytes([
            mac[offset],
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]) & 0x7fff_ffff;
        let code = match self.encoding {
            TotpEncoding::Decimal => {
                let value = u64::from(truncated) % 10u64.pow(self.digits);
                let width = self.digits as usize;
                format!("{value:0width$}")
            }
            TotpEncoding::Steam => {
                let alphabet = TotpEncoding::STEAM_ALPHABET.as_bytes();
                let base = alphabet.len() as u32;
                let mut value = truncated;
                (0..self.digits)
                    .map(|_| {
                        let c = char::from(alphabet[(value % base) as usize]);
                        value /= base;
                        c
                    })
                    .collect()
            }
        };
        // `period - elapsed` is in 1..=period, so it fits u32.
        let valid_for = u32::try_from(period - unix_time % period).unwrap_or(self.period);
        TotpCode {
            code: Zeroizing::new(code),
            valid_for_seconds: valid_for,
            period_seconds: self.period,
        }
    }

    /// The time to compute a code at when a caller asked for `requested`
    /// (`None`: now), clamped to `now` plus or minus one period. Callers can
    /// get the previous or next code (clock skew) but never harvest codes for
    /// far-off steps.
    pub fn evaluation_time(&self, requested: Option<u64>, now: u64) -> u64 {
        let period = u64::from(self.period);
        requested
            .unwrap_or(now)
            .clamp(now.saturating_sub(period), now.saturating_add(period))
    }
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &"<redacted>")
            .field("period", &self.period)
            .field("digits", &self.digits)
            .field("algorithm", &self.algorithm)
            .field("encoding", &self.encoding)
            .finish()
    }
}

impl TotpCode {
    /// The code (digits, or Steam characters).
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Seconds until the code rolls over (the period at the start of a step,
    /// 1 in its last second).
    pub fn valid_for_seconds(&self) -> u32 {
        self.valid_for_seconds
    }

    /// The step length, for progress displays.
    pub fn period_seconds(&self) -> u32 {
        self.period_seconds
    }
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"<redacted>")
            .field("valid_for_seconds", &self.valid_for_seconds)
            .field("period_seconds", &self.period_seconds)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Implementation.

/// Decodes one encoding of a KeePass native TOTP secret field.
type SecretDecoder = fn(&str) -> Option<Vec<u8>>;

/// RFC 4648 base32 without padding, tolerating non-zero trailing bits (some
/// generators leave them set).
static BASE32_LENIENT: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.check_trailing_bits = false;
    spec.encoding()
        .unwrap_or_else(|_| unreachable!("a valid base32 specification"))
});

/// `s` without any whitespace.
fn compact(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Decode a base32 secret after normalizing it: whitespace removed, letters
/// uppercased, trailing `=` padding dropped. Secrets arrive lowercase, grouped
/// in blocks of four, or padded, and a strict decoder rejects all three.
/// Empty secrets are rejected.
fn decode_base32_secret(s: &str) -> Option<Vec<u8>> {
    let normalized = compact(s).to_ascii_uppercase();
    let bytes = BASE32_LENIENT
        .decode(normalized.trim_end_matches('=').as_bytes())
        .ok()?;
    (!bytes.is_empty()).then_some(bytes)
}

/// An otpauth `algorithm` value, case-insensitively.
fn uri_algorithm(value: &str) -> Result<TotpAlgorithm, MalformedReason> {
    [
        ("SHA1", TotpAlgorithm::Sha1),
        ("SHA256", TotpAlgorithm::Sha256),
        ("SHA512", TotpAlgorithm::Sha512),
    ]
    .into_iter()
    .find(|(name, _)| value.trim().eq_ignore_ascii_case(name))
    .map(|(_, algorithm)| algorithm)
    .ok_or(MalformedReason::UnknownAlgorithm)
}

/// HMAC of `message` under `key` with the MAC type `M`.
fn hmac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length.
    let mut mac = <M as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_a_slice_so_new_fields_are_not_a_breaking_change() {
        let all: &'static [OtpField] = OtpField::ALL;
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn field_names_round_trip_and_include_keepass_otp() {
        for &f in OtpField::ALL {
            assert_eq!(OtpField::from_kdbx_name(f.kdbx_name()), Some(f));
        }
        assert_eq!(OtpField::Uri.kdbx_name(), keepass_0_15::db::fields::OTP);
        assert_eq!(OtpField::from_kdbx_name("Password"), None);
        assert_eq!(OtpField::from_kdbx_name("OTP"), None);
    }

    #[test]
    fn errors_display_human_readably_and_serialize_with_snake_case_tags() {
        let err = OtpError::Malformed {
            source: OtpSource::KeePassNative,
            reason: MalformedReason::UnknownAlgorithm,
        };
        assert_eq!(
            err.to_string(),
            "malformed OTP configuration (KeePass TimeOtp fields): unknown algorithm"
        );
        assert_eq!(OtpSource::Uri.to_string(), "otpauth URI");
        assert_eq!(OtpSource::Legacy.to_string(), "legacy TOTP Seed/Settings");
        assert_eq!(
            serde_json::to_string(&err).unwrap(),
            r#"{"malformed":{"source":"keepass_native","reason":"unknown_algorithm"}}"#
        );
        let missing = OtpError::Malformed {
            source: OtpSource::Legacy,
            reason: MalformedReason::MissingField(OtpField::LegacySettings),
        };
        assert_eq!(
            serde_json::to_string(&missing).unwrap(),
            r#"{"malformed":{"source":"legacy","reason":{"missing_field":"TOTP Settings"}}}"#
        );
        let sealed = OtpError::Sealed(OtpField::Uri);
        assert_eq!(
            serde_json::to_string(&sealed).unwrap(),
            r#"{"sealed":"otp"}"#
        );
        for e in [err, missing, sealed] {
            let back: OtpError = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
            assert_eq!(back, e);
        }
        assert!(serde_json::from_str::<OtpField>(r#""Password""#).is_err());
    }

    #[test]
    fn otp_fields_debug_hides_values() {
        let fields: OtpFields = [(OtpField::LegacySeed, "JBSWY3DPEHPK3PXP")]
            .into_iter()
            .collect();
        assert_eq!(fields.get(OtpField::LegacySeed), Some("JBSWY3DPEHPK3PXP"));
        let shown = format!("{fields:?}");
        assert!(!shown.contains("JBSW"), "{shown}");
        assert!(shown.contains("LegacySeed"), "{shown}");
    }

    // TOTP: ported from mcp-kdbx's totp.rs tests, plus Steam and typed errors.

    const SAMPLE_URI: &str =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    /// RFC 6238 SHA-1 secret "12345678901234567890" in base32.
    const RFC_SHA1_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    /// RFC 6238 SHA-1 at T = 59, six digits.
    const RFC_SHA1_AT_59: &str = "287082";

    fn uri(params: &str) -> Result<TotpConfig, MalformedReason> {
        TotpConfig::from_uri(&format!("otpauth://totp/Test?{params}"))
    }

    fn by_name(spec: &[(&str, &str)]) -> OtpFields {
        spec.iter()
            .map(|(name, value)| {
                (
                    OtpField::from_kdbx_name(name).expect("an OTP field"),
                    *value,
                )
            })
            .collect()
    }

    fn resolve_spec(spec: &[(&str, &str)]) -> Result<Option<TotpConfig>, OtpError> {
        resolve_fields(&by_name(spec))
    }

    fn configured(spec: &[(&str, &str)]) -> TotpConfig {
        resolve_spec(spec)
            .expect("well-formed")
            .expect("configured")
    }

    fn malformed(source: OtpSource, reason: MalformedReason) -> OtpError {
        OtpError::Malformed { source, reason }
    }

    #[test]
    fn parses_minimal_otpauth_uri() {
        let cfg = TotpConfig::from_uri(SAMPLE_URI).expect("parse");
        assert_eq!(cfg.period(), 30);
        assert_eq!(cfg.digits(), 6);
        assert_eq!(cfg.algorithm(), TotpAlgorithm::Sha1);
        assert_eq!(cfg.encoding(), TotpEncoding::Decimal);
    }

    #[test]
    fn evaluation_time_is_clamped_to_one_period_around_now() {
        let cfg = TotpConfig::from_uri(SAMPLE_URI).expect("parse");
        let now = 2_000_000_000u64;
        assert_eq!(cfg.evaluation_time(Some(now - 30), now), now - 30);
        assert_eq!(cfg.evaluation_time(Some(now + 30), now), now + 30);
        assert_eq!(cfg.evaluation_time(None, now), now);
        assert_eq!(cfg.evaluation_time(Some(0), now), now - 30);
        assert_eq!(cfg.evaluation_time(Some(u64::MAX), now), now + 30);
        assert_eq!(cfg.evaluation_time(Some(0), 10), 0);
    }

    #[test]
    fn rejects_non_otpauth_and_hotp_and_non_url_with_reasons() {
        use MalformedReason::*;
        assert_eq!(
            TotpConfig::from_uri("https://example.com/").unwrap_err(),
            NotAnOtpauthUri
        );
        assert_eq!(
            TotpConfig::from_uri("not a url").unwrap_err(),
            NotAnOtpauthUri
        );
        assert_eq!(TotpConfig::from_uri("").unwrap_err(), NotAnOtpauthUri);
        assert_eq!(
            TotpConfig::from_uri("otpauth:totp?secret=JBSWY3DPEHPK3PXP").unwrap_err(),
            NotAnOtpauthUri
        );
        assert_eq!(
            TotpConfig::from_uri("otpauth://hotp/foo?secret=JBSWY3DPEHPK3PXP").unwrap_err(),
            NotTotp
        );
    }

    #[test]
    fn uri_scheme_and_type_are_case_insensitive_and_fragment_is_ignored() {
        let cfg =
            TotpConfig::from_uri("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP#frag").expect("parse");
        assert_eq!(cfg.period(), 30);
        assert_eq!(
            TotpConfig::from_uri("otpauth://totp/x#?secret=JBSWY3DPEHPK3PXP").unwrap_err(),
            MalformedReason::MissingSecret
        );
    }

    #[test]
    fn uri_query_is_percent_decoded() {
        let cfg =
            TotpConfig::from_uri(&format!("otpauth://totp/a%2Fb?secret={RFC_SHA1_B32}%3D%3D"))
                .expect("percent-encoded padding decodes");
        assert_eq!(cfg.code_at(59).code(), RFC_SHA1_AT_59);
    }

    #[test]
    fn missing_or_bad_secrets_are_distinguished() {
        assert_eq!(
            uri("period=30").unwrap_err(),
            MalformedReason::MissingSecret
        );
        assert_eq!(uri("secret=").unwrap_err(), MalformedReason::InvalidSecret);
        assert_eq!(
            uri("secret=not-base32!").unwrap_err(),
            MalformedReason::InvalidSecret
        );
    }

    #[test]
    fn parses_custom_period_digits_and_algorithm() {
        let cfg = uri("secret=JBSWY3DPEHPK3PXP&period=60&digits=8").expect("parse");
        assert_eq!((cfg.period(), cfg.digits()), (60, 8));
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&algorithm=SHA256")
                .unwrap()
                .algorithm(),
            TotpAlgorithm::Sha256
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&algorithm=sha512")
                .unwrap()
                .algorithm(),
            TotpAlgorithm::Sha512
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&algorithm=SHA1")
                .unwrap()
                .algorithm(),
            TotpAlgorithm::Sha1
        );
    }

    #[test]
    fn unknown_algorithms_and_encoders_are_rejected_not_guessed() {
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&algorithm=SHA3-256").unwrap_err(),
            MalformedReason::UnknownAlgorithm
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&algorithm=MD5").unwrap_err(),
            MalformedReason::UnknownAlgorithm
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&encoder=base26").unwrap_err(),
            MalformedReason::UnknownEncoder
        );
    }

    #[test]
    fn steam_uri_produces_five_steam_characters() {
        // Vectors computed independently (Python hmac) from KeePassXC's Steam
        // encoder: RFC 4226 dynamic truncation, then five characters of
        // "23456789BCDFGHJKMNPQRTVWXY", least significant first.
        let cfg = uri(&format!(
            "secret={RFC_SHA1_B32}&digits=5&issuer=Steam&encoder=steam"
        ))
        .expect("steam");
        assert_eq!(cfg.encoding(), TotpEncoding::Steam);
        assert_eq!(cfg.digits(), 5);
        for (t, want) in [
            (59, "PV9M4"),
            (1_111_111_109, "PY4YB"),
            (1_234_567_890, "VHHQY"),
            (2_000_000_000, "9N776"),
        ] {
            assert_eq!(cfg.code_at(t).code(), want, "t = {t}");
        }
        // The Steam encoder always yields five characters.
        assert_eq!(
            uri(&format!("secret={RFC_SHA1_B32}&encoder=Steam"))
                .unwrap()
                .digits(),
            5
        );
    }

    #[test]
    fn steam_legacy_settings() {
        // KeePassXC's legacy TOTP Settings write "S" for Steam digits.
        let cfg = TotpConfig::from_legacy(RFC_SHA1_B32, "30;S").expect("steam legacy");
        assert_eq!(cfg.encoding(), TotpEncoding::Steam);
        assert_eq!(cfg.code_at(59).code(), "PV9M4");
    }

    #[test]
    fn rfc_6238_vectors() {
        let sha1 = "12345678901234567890";
        let sha256 = "12345678901234567890123456789012";
        let sha512 = "1234567890123456789012345678901234567890123456789012345678901234";
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, want1, want256, want512) in cases {
            for (secret, algorithm, want) in [
                (sha1, "HMAC-SHA-1", want1),
                (sha256, "HMAC-SHA-256", want256),
                (sha512, "HMAC-SHA-512", want512),
            ] {
                let cfg = configured(&[
                    ("TimeOtp-Secret", secret),
                    ("TimeOtp-Length", "8"),
                    ("TimeOtp-Algorithm", algorithm),
                ]);
                assert_eq!(cfg.code_at(t).code(), want, "{algorithm} at {t}");
            }
        }
    }

    #[test]
    fn code_at_known_vector_and_windows() {
        let cfg = uri(&format!("secret={RFC_SHA1_B32}")).expect("parse");
        let code = cfg.code_at(59);
        assert_eq!(code.code(), RFC_SHA1_AT_59);
        assert_eq!(code.period_seconds(), 30);
        assert_eq!(cfg.code_at(0).valid_for_seconds(), 30);
        assert_eq!(cfg.code_at(29).valid_for_seconds(), 1);
        assert_eq!(cfg.code_at(30).valid_for_seconds(), 30);
        let cfg = uri("secret=JBSWY3DPEHPK3PXP&period=45").expect("parse");
        assert_eq!(cfg.code_at(0).period_seconds(), 45);
        assert_eq!(cfg.code_at(0).valid_for_seconds(), 45);
    }

    #[test]
    fn codes_are_zero_padded() {
        let cfg = configured(&[
            ("TimeOtp-Secret", "12345678901234567890"),
            ("TimeOtp-Length", "8"),
        ]);
        assert_eq!(cfg.code_at(1_111_111_109).code(), "07081804");
    }

    #[test]
    fn from_legacy_parses_settings_and_computes() {
        let cfg = TotpConfig::from_legacy(RFC_SHA1_B32, "30;6").expect("legacy parse");
        assert_eq!(
            (cfg.period(), cfg.digits(), cfg.algorithm()),
            (30, 6, TotpAlgorithm::Sha1)
        );
        assert_eq!(cfg.code_at(59).code(), RFC_SHA1_AT_59);
        let cfg = TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", " 60 ; 8 ").expect("whitespace");
        assert_eq!((cfg.period(), cfg.digits()), (60, 8));
        // KeeTrayTOTP appends a time-correction URL; it is ignored (no clock).
        let cfg = TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;6;https://time.example")
            .expect("3 parts");
        assert_eq!(cfg.digits(), 6);
    }

    #[test]
    fn from_legacy_rejects_empty_or_malformed() {
        use MalformedReason::*;
        assert_eq!(
            TotpConfig::from_legacy("", "30;6").unwrap_err(),
            InvalidSecret
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30").unwrap_err(),
            InvalidSettings
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "thirty;six").unwrap_err(),
            InvalidPeriod
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;six").unwrap_err(),
            InvalidDigits
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;6;x;y").unwrap_err(),
            InvalidSettings
        );
    }

    #[test]
    fn dangerous_parameters_are_rejected_without_panic() {
        use MalformedReason::*;
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&period=0").unwrap_err(),
            InvalidPeriod
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&period=abc").unwrap_err(),
            InvalidPeriod
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&digits=20").unwrap_err(),
            InvalidDigits
        );
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&digits=0").unwrap_err(),
            InvalidDigits
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "0;6").unwrap_err(),
            InvalidPeriod
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;20").unwrap_err(),
            InvalidDigits
        );
        assert_eq!(
            TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;0").unwrap_err(),
            InvalidDigits
        );
    }

    #[test]
    fn digit_bounds_are_accepted_and_compute() {
        let one = uri("secret=JBSWY3DPEHPK3PXP&digits=1").expect("one");
        let ten = uri("secret=JBSWY3DPEHPK3PXP&digits=10").expect("ten");
        assert_eq!(one.code_at(59).code().len(), 1);
        assert_eq!(ten.code_at(59).code().len(), 10);
        assert_eq!(
            uri("secret=JBSWY3DPEHPK3PXP&period=4294967295")
                .unwrap()
                .code_at(u64::MAX)
                .code()
                .len(),
            6
        );
    }

    #[test]
    fn resolve_prefers_otpauth_then_native_then_legacy() {
        let modern = ("otp", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP");
        let legacy = [("TOTP Seed", "JBSWY3DPEHPK3PXP"), ("TOTP Settings", "30;6")];
        assert!(resolve_spec(&[modern]).unwrap().is_some());
        assert!(resolve_spec(&legacy).unwrap().is_some());
        // A malformed source falls through to a later well-formed one.
        let mut fallthrough = vec![("otp", "not-an-otpauth-uri")];
        fallthrough.extend_from_slice(&legacy);
        assert!(resolve_spec(&fallthrough).unwrap().is_some());
        let both = [
            ("TimeOtp-Secret", "12345678901234567890"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "30;8"),
        ];
        assert_eq!(configured(&both).code_at(59).code(), RFC_SHA1_AT_59);
    }

    #[test]
    fn no_otp_is_ok_none_and_malformed_otp_is_an_error() {
        use MalformedReason::*;
        assert!(resolve_spec(&[]).unwrap().is_none());
        // Empty fields are absent, as KeePass treats them.
        assert!(
            resolve_spec(&[("otp", ""), ("TimeOtp-Secret-Hex", "")])
                .unwrap()
                .is_none()
        );
        assert_eq!(
            resolve_spec(&[("otp", "not-an-otpauth-uri")]).unwrap_err(),
            malformed(OtpSource::Uri, NotAnOtpauthUri)
        );
        // A lone seed uses KeePassXC's default settings (30 s, 6 digits).
        let lone = resolve_spec(&[("TOTP Seed", "JBSWY3DPEHPK3PXP")])
            .unwrap()
            .expect("a lone legacy seed is a valid configuration");
        assert_eq!((lone.period(), lone.digits()), (30, 6));
        let empty = resolve_spec(&[("TOTP Seed", "JBSWY3DPEHPK3PXP"), ("TOTP Settings", "")])
            .unwrap()
            .expect("empty settings fall back to the defaults");
        assert_eq!((empty.period(), empty.digits()), (30, 6));
        // Present but malformed settings remain an error.
        assert_eq!(
            resolve_spec(&[
                ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
                ("TOTP Settings", "thirty")
            ])
            .unwrap_err(),
            malformed(OtpSource::Legacy, InvalidSettings)
        );
        assert_eq!(
            resolve_spec(&[("TOTP Settings", "30;6")]).unwrap_err(),
            malformed(OtpSource::Legacy, MissingField(OtpField::LegacySeed))
        );
        assert_eq!(
            resolve_spec(&[("TimeOtp-Length", "8")]).unwrap_err(),
            malformed(OtpSource::KeePassNative, MissingSecret)
        );
        // With several malformed sources, the first in precedence is reported.
        assert_eq!(
            resolve_spec(&[
                (
                    "otp",
                    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA3-256"
                ),
                ("TOTP Seed", "!")
            ])
            .unwrap_err(),
            malformed(OtpSource::Uri, UnknownAlgorithm)
        );
    }

    #[test]
    fn keepass_native_secret_encodings_all_decode_to_the_same_key() {
        for (field, value) in [
            ("TimeOtp-Secret", "12345678901234567890"),
            (
                "TimeOtp-Secret-Hex",
                "3132333435363738393031323334353637383930",
            ),
            ("TimeOtp-Secret-Base32", RFC_SHA1_B32),
            ("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="),
        ] {
            let cfg = configured(&[(field, value)]);
            assert_eq!((cfg.period(), cfg.digits()), (30, 6), "{field} defaults");
            assert_eq!(cfg.code_at(59).code(), RFC_SHA1_AT_59, "{field}");
        }
    }

    #[test]
    fn empty_native_secret_fields_are_ignored_when_counting() {
        let cfg = configured(&[
            ("TimeOtp-Secret", ""),
            ("TimeOtp-Secret-Base32", RFC_SHA1_B32),
        ]);
        assert_eq!(cfg.code_at(59).code(), RFC_SHA1_AT_59);
    }

    #[test]
    fn keepass_native_length_period_and_algorithm() {
        use MalformedReason::*;
        let cfg = configured(&[
            ("TimeOtp-Secret", "12345678901234567890123456789012"),
            ("TimeOtp-Length", "8"),
            ("TimeOtp-Period", "30"),
            ("TimeOtp-Algorithm", "HMAC-SHA-256"),
        ]);
        assert_eq!(cfg.algorithm(), TotpAlgorithm::Sha256);
        assert_eq!(cfg.code_at(59).code(), "46119246");
        let native = |reason| malformed(OtpSource::KeePassNative, reason);
        assert_eq!(
            resolve_spec(&[("TimeOtp-Secret", "x"), ("TimeOtp-Length", "9")]).unwrap_err(),
            native(InvalidDigits)
        );
        assert_eq!(
            resolve_spec(&[("TimeOtp-Secret", "x"), ("TimeOtp-Algorithm", "MD5")]).unwrap_err(),
            native(UnknownAlgorithm)
        );
        assert_eq!(
            resolve_spec(&[("TimeOtp-Secret", "x"), ("TimeOtp-Secret-Hex", "78")]).unwrap_err(),
            native(MultipleSecrets)
        );
        assert_eq!(
            resolve_spec(&[("TimeOtp-Secret", "x"), ("TimeOtp-Period", "0")]).unwrap_err(),
            native(InvalidPeriod)
        );
        assert_eq!(
            resolve_spec(&[("TimeOtp-Secret-Hex", "zz")]).unwrap_err(),
            native(InvalidSecret)
        );
    }

    #[test]
    fn base32_secrets_are_normalized_before_decoding() {
        let canonical = decode_base32_secret("JBSWY3DPEHPK3PXP").expect("canonical");
        for messy in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSWY3DPEHPK3PXP====",
            " jbsw\ty3dp ehpk3pxp\n",
        ] {
            assert_eq!(
                decode_base32_secret(messy).as_ref(),
                Some(&canonical),
                "{messy:?}"
            );
        }
        let cfg = TotpConfig::from_uri("otpauth://totp/X?secret=jbswy3dpehpk3pxp")
            .expect("lowercase uri");
        assert_eq!(cfg.secret.as_slice(), canonical.as_slice());
    }

    #[test]
    fn base32_tolerates_nonzero_trailing_bits() {
        let a = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGQ").expect("zero trailing bits");
        let b = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGR").expect("non-zero trailing bits");
        assert_eq!(a, b);
    }

    #[test]
    fn debug_never_shows_secrets_or_codes() {
        let cfg = uri(&format!("secret={RFC_SHA1_B32}")).unwrap();
        let shown = format!("{cfg:?} {:?}", cfg.code_at(59));
        assert!(!shown.contains(RFC_SHA1_AT_59), "{shown}");
        assert!(!shown.contains("49, 50"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn resolve_reads_a_revealed_snapshot_entry_and_refuses_a_sealed_one() {
        use crate::fingerprint::FingerprintKey;
        use crate::model::Sealing;
        let key = FingerprintKey::from_bytes([3; 32]);
        let build = |sealing: Sealing<'_>| {
            Entry::new(uuid::Uuid::nil())
                .with_field("Title", sealing.field("Title", false, "Mail"))
                .with_field(
                    "otp",
                    sealing.field(
                        "otp",
                        true,
                        &format!("otpauth://totp/m?secret={RFC_SHA1_B32}"),
                    ),
                )
        };
        let cfg = resolve(&build(Sealing::Reveal(&key)))
            .unwrap()
            .expect("configured");
        assert_eq!(cfg.code_at(59).code(), RFC_SHA1_AT_59);
        assert_eq!(
            resolve(&build(Sealing::Fingerprint(&key))).unwrap_err(),
            OtpError::Sealed(OtpField::Uri)
        );
        assert!(resolve(&Entry::new(uuid::Uuid::nil())).unwrap().is_none());
    }
}
