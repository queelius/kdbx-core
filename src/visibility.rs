//! The one rule for which field values may leave the vault as metadata.
//!
//! KDBX protection is a per-field flag, not a property of the field's name:
//! the Password is protected by default, but KeePassXC and KeePass 2 can
//! protect any field. So "is this value a secret" is answered from the stored
//! flag, never from a list of names.
//!
//! Every member uses [`metadata_value`] both for the values it displays and
//! for the values it searches, so a value is searchable exactly when it is
//! visible: search can never become an oracle on a hidden value.
//!
//! The one exception is the Title. It is the entry's address in a vault path,
//! and every member already exposes paths, so hiding a protected Title would
//! protect nothing. It is reported as metadata regardless of its flag.
//!
//! Under [`Sealing::Fingerprint`](crate::model::Sealing::Fingerprint) the rule
//! holds structurally (sealed values have no text). The flag check makes it
//! hold for [`Sealing::Reveal`](crate::model::Sealing::Reveal) snapshots too,
//! so a revealed snapshot used for display still hides protected values unless
//! a caller reveals one explicitly.
//!
//! ```
//! use kdbx_core::model::{Entry, Field, Value};
//! use kdbx_core::visibility::metadata_value;
//! use uuid::Uuid;
//!
//! let entry = Entry::new(Uuid::nil())
//!     .with_field("Title", Field::new(true, Value::Plain("Bank".into())))
//!     .with_field("UserName", Field::new(true, Value::Plain("alice".into())));
//! assert_eq!(metadata_value(&entry, "Title"), Some("Bank"));
//! assert_eq!(metadata_value(&entry, "UserName"), None);
//! ```

use crate::fields::StandardField;
use crate::model::{Entry, Field};

/// Whether field `name` is the entry's address (the Title), the one field
/// that is never a secret. Matching is exact: `title` is a custom field.
pub fn is_address(name: &str) -> bool {
    StandardField::from_kdbx_name(name) == Some(StandardField::Title)
}

/// Whether field `name` holding `field` may be exposed as metadata: its value
/// is plain, and it is either unprotected or the Title.
pub fn is_visible(field: &Field, name: &str) -> bool {
    field.value.as_plain().is_some() && (!field.protected || is_address(name))
}

/// The plaintext of field `name` when it may be exposed as metadata (see
/// [`is_visible`]); `None` for an absent field and for any hidden one.
pub fn metadata_value<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    let field = entry.field(name)?;
    if is_visible(field, name) {
        field.value.as_plain()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintKey;
    use crate::model::{Sealing, Value};
    use uuid::Uuid;

    /// An entry captured from `(name, value, protected)` triples under
    /// `sealing`.
    fn entry(sealing: Sealing<'_>, spec: &[(&str, &str, bool)]) -> Entry {
        spec.iter()
            .fold(Entry::new(Uuid::nil()), |e, (name, value, protected)| {
                e.with_field(*name, sealing.field(name, *protected, value))
            })
    }

    #[test]
    fn unprotected_values_are_visible() {
        let key = FingerprintKey::from_bytes([1; 32]);
        for sealing in [Sealing::Fingerprint(&key), Sealing::Reveal(&key)] {
            let e = entry(
                sealing,
                &[("UserName", "alice", false), ("Port", "22", false)],
            );
            assert_eq!(metadata_value(&e, "UserName"), Some("alice"));
            assert_eq!(metadata_value(&e, "Port"), Some("22"));
        }
    }

    #[test]
    fn protected_values_are_hidden_whatever_the_field_name_and_sealing() {
        let key = FingerprintKey::from_bytes([1; 32]);
        let spec = [
            ("UserName", "alice", true),
            ("URL", "https://x.example", true),
            ("Notes", "n", true),
            ("Password", "pw", true),
            ("PIN", "4321", true),
        ];
        for sealing in [Sealing::Fingerprint(&key), Sealing::Reveal(&key)] {
            let e = entry(sealing, &spec);
            for (name, _, _) in spec {
                assert_eq!(metadata_value(&e, name), None, "{name} leaked");
                assert!(!is_visible(e.field(name).unwrap(), name));
            }
        }
    }

    #[test]
    fn protected_title_is_the_address_exception() {
        let key = FingerprintKey::from_bytes([1; 32]);
        for sealing in [Sealing::Fingerprint(&key), Sealing::Reveal(&key)] {
            let e = entry(sealing, &[("Title", "Addressed", true)]);
            assert_eq!(metadata_value(&e, "Title"), Some("Addressed"));
        }
    }

    #[test]
    fn sealed_values_are_never_visible() {
        // Even an unprotected field (or a Title) built sealed by hand has no
        // text to show.
        let key = FingerprintKey::from_bytes([1; 32]);
        let sealed = Value::Sealed(key.fingerprint(crate::fingerprint::Domain::Field, b"x"));
        let e = Entry::new(Uuid::nil())
            .with_field("Title", Field::new(false, sealed.clone()))
            .with_field("Custom", Field::new(false, sealed));
        assert_eq!(metadata_value(&e, "Title"), None);
        assert_eq!(metadata_value(&e, "Custom"), None);
    }

    #[test]
    fn absent_field_is_none_and_names_are_case_sensitive() {
        let key = FingerprintKey::from_bytes([1; 32]);
        let e = entry(Sealing::Reveal(&key), &[("title", "lower", true)]);
        assert_eq!(metadata_value(&e, "URL"), None);
        // "title" is a custom field, not the Title, so its flag hides it.
        assert_eq!(metadata_value(&e, "title"), None);
    }
}
