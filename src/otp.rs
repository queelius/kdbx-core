//! TOTP resolution and code computation.
//!
//! An entry can carry a TOTP configuration in three historical encodings,
//! each a set of fields named by [`OtpField`]. [`OtpFields`] holds the
//! plaintext of exactly those fields (the capture adapters produce it with
//! `otp_fields`, so OTP works even under fingerprint sealing).

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

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
    /// Every OTP field.
    pub const ALL: [OtpField; 10] = [
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
        Self::ALL.into_iter().find(|f| f.kdbx_name() == name)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_round_trip_and_include_keepass_otp() {
        for f in OtpField::ALL {
            assert_eq!(OtpField::from_kdbx_name(f.kdbx_name()), Some(f));
        }
        assert_eq!(OtpField::Uri.kdbx_name(), keepass_0_15::db::fields::OTP);
        assert_eq!(OtpField::from_kdbx_name("Password"), None);
        assert_eq!(OtpField::from_kdbx_name("OTP"), None);
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
}
