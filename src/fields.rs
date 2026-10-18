//! The KDBX standard-field schema.
//!
//! KDBX defines exactly five standard entry fields. Their names are a format
//! constant, not an application-maintained list: every other field name is a
//! custom field. [`StandardField::ALL`] is the single source for those names;
//! name lookup, serialization and [`traits_of`] all derive from it.
//!
//! ```
//! use kdbx_core::fields::{traits_of, StandardField};
//!
//! assert_eq!(StandardField::Url.kdbx_name(), "URL");
//! assert_eq!(StandardField::from_kdbx_name("UserName"), Some(StandardField::UserName));
//! assert!(StandardField::Password.traits().protected_by_default);
//! assert!(traits_of("Notes").multiline);
//! assert!(!traits_of("PIN").protected_by_default);
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// One of the five KDBX standard entry fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StandardField {
    /// `Title`: the entry's name, and its address in a vault path.
    Title,
    /// `UserName`.
    UserName,
    /// `Password`: protected by default.
    Password,
    /// `URL`.
    Url,
    /// `Notes`: multi-line.
    Notes,
}

/// Default presentation and protection traits of a field.
///
/// Traits describe defaults, not the stored state: any field can carry the
/// KDBX protection flag, and a single-line field whose value contains a line
/// feed is still rendered as multi-line by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FieldTraits {
    /// The field usually holds several lines of text.
    pub multiline: bool,
    /// KeePass clients protect the field unless the user says otherwise.
    pub protected_by_default: bool,
}

impl FieldTraits {
    /// The traits of every custom (non-standard) field: single-line, not
    /// protected by default.
    pub const CUSTOM: FieldTraits = FieldTraits {
        multiline: false,
        protected_by_default: false,
    };
}

impl StandardField {
    /// Every standard field, in KDBX canonical order.
    pub const ALL: [StandardField; 5] = [
        StandardField::Title,
        StandardField::UserName,
        StandardField::Password,
        StandardField::Url,
        StandardField::Notes,
    ];

    /// The field's name as stored in KDBX (`Title`, `UserName`, `Password`,
    /// `URL`, `Notes`).
    pub fn kdbx_name(self) -> &'static str {
        match self {
            StandardField::Title => "Title",
            StandardField::UserName => "UserName",
            StandardField::Password => "Password",
            StandardField::Url => "URL",
            StandardField::Notes => "Notes",
        }
    }

    /// The standard field stored under `name`, or `None` for a custom field.
    /// Matching is exact (KDBX field names are case-sensitive).
    pub fn from_kdbx_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.kdbx_name() == name)
    }

    /// The field's default traits.
    pub fn traits(self) -> FieldTraits {
        FieldTraits {
            multiline: matches!(self, StandardField::Notes),
            protected_by_default: matches!(self, StandardField::Password),
        }
    }
}

/// The default traits of the field stored under `name`: the standard field's
/// traits, or [`FieldTraits::CUSTOM`].
pub fn traits_of(name: &str) -> FieldTraits {
    StandardField::from_kdbx_name(name).map_or(FieldTraits::CUSTOM, StandardField::traits)
}

impl fmt::Display for StandardField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kdbx_name())
    }
}

/// The error of parsing a [`StandardField`] from a name that is not one of the
/// five standard names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAStandardField(pub String);

impl fmt::Display for NotAStandardField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}' is not a KDBX standard field name", self.0)
    }
}

impl std::error::Error for NotAStandardField {}

impl FromStr for StandardField {
    type Err = NotAStandardField;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_kdbx_name(s).ok_or_else(|| NotAStandardField(s.to_owned()))
    }
}

/// Serializes as the KDBX name, so the wire form and [`StandardField::kdbx_name`]
/// cannot diverge.
impl Serialize for StandardField {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.kdbx_name())
    }
}

impl<'de> Deserialize<'de> for StandardField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdbx_names_are_the_format_constants() {
        let names: Vec<_> = StandardField::ALL.map(StandardField::kdbx_name).to_vec();
        assert_eq!(names, ["Title", "UserName", "Password", "URL", "Notes"]);
    }

    #[test]
    fn names_agree_with_keepass_0_12() {
        assert_eq!(
            StandardField::ALL.map(StandardField::kdbx_name),
            keepass_0_12::db::fields::KNOWN_FIELDS
        );
    }

    #[test]
    fn names_agree_with_keepass_0_15() {
        assert_eq!(
            StandardField::ALL.map(StandardField::kdbx_name),
            keepass_0_15::db::fields::KNOWN_FIELDS
        );
    }

    #[test]
    fn name_lookup_round_trips_and_is_case_sensitive() {
        for f in StandardField::ALL {
            assert_eq!(StandardField::from_kdbx_name(f.kdbx_name()), Some(f));
            assert_eq!(f.to_string().parse::<StandardField>(), Ok(f));
        }
        assert_eq!(StandardField::from_kdbx_name("notes"), None);
        assert_eq!(StandardField::from_kdbx_name("Url"), None);
        assert_eq!(StandardField::from_kdbx_name("otp"), None);
        assert!("PIN".parse::<StandardField>().is_err());
    }

    #[test]
    fn traits_of_standard_fields() {
        for f in StandardField::ALL {
            let t = f.traits();
            assert_eq!(t.multiline, f == StandardField::Notes, "{f}");
            assert_eq!(t.protected_by_default, f == StandardField::Password, "{f}");
            assert_eq!(traits_of(f.kdbx_name()), t);
        }
    }

    #[test]
    fn custom_fields_default_to_single_line_unprotected() {
        assert_eq!(traits_of("PIN"), FieldTraits::CUSTOM);
        assert_eq!(traits_of("otp"), FieldTraits::CUSTOM);
        assert_eq!(traits_of("password"), FieldTraits::CUSTOM);
        assert_eq!(FieldTraits::CUSTOM, FieldTraits::default());
    }

    #[test]
    fn field_traits_serialize() {
        let json = serde_json::to_string(&StandardField::Notes.traits()).unwrap();
        assert_eq!(json, r#"{"multiline":true,"protected_by_default":false}"#);
        let back: FieldTraits = serde_json::from_str(&json).unwrap();
        assert_eq!(back, StandardField::Notes.traits());
    }

    #[test]
    fn serializes_as_the_kdbx_name() {
        let json = serde_json::to_string(&StandardField::ALL).unwrap();
        assert_eq!(json, r#"["Title","UserName","Password","URL","Notes"]"#);
        let back: Vec<StandardField> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, StandardField::ALL);
        assert!(serde_json::from_str::<StandardField>(r#""Url""#).is_err());
    }
}
