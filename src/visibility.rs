//! The one rule for which field values are secrets.
//!
//! [`is_secret`] decides, for a field's name and stored KDBX protection flag,
//! whether its value is a secret. Both consumers of that question use it:
//!
//! - **sealing** ([`Sealing::field`](crate::model::Sealing::field)) seals
//!   exactly the secret fields under fingerprint sealing, and
//! - **visibility** ([`metadata_value`]) exposes exactly the non-secret ones,
//!
//! so the two can never disagree. Every member also searches through
//! [`metadata_value`], so a value is searchable exactly when it is visible.
//!
//! A field is secret when it is protected, or when its name is protected by
//! default ([`FieldTraits::protected_by_default`](crate::fields::FieldTraits),
//! that is the Password): turning off a Password's protection flag does not
//! make it metadata. The one exception is the Title. It is the entry's address
//! in a vault path, and every member already exposes paths, so hiding a
//! protected Title would protect nothing; it is never a secret.
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

use crate::fields::{StandardField, traits_of};
use crate::model::{Entry, Field};

/// Whether field `name` is the entry's address (the Title), the one field
/// that is never a secret. Matching is exact: `title` is a custom field.
pub fn is_address(name: &str) -> bool {
    StandardField::from_kdbx_name(name) == Some(StandardField::Title)
}

/// Whether the field stored under `name`, with KDBX protection flag
/// `protected`, holds a secret:
///
/// ```text
/// is_secret = name != Title && (protected || traits_of(name).protected_by_default)
/// ```
///
/// The single predicate behind both sealing and visibility.
pub fn is_secret(name: &str, protected: bool) -> bool {
    !is_address(name) && (protected || traits_of(name).protected_by_default)
}

/// Whether field `name` holding `field` may be exposed as metadata: its value
/// is plain and it is not a secret ([`is_secret`]).
pub fn is_visible(field: &Field, name: &str) -> bool {
    field.value.as_plain().is_some() && !is_secret(name, field.protected)
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
    fn unprotected_password_is_still_a_secret() {
        // Turning off a Password's protection flag does not make it metadata:
        // the Password is protected by default (FieldTraits), and sealing and
        // visibility share the one is_secret predicate.
        let key = FingerprintKey::from_bytes([1; 32]);
        assert!(is_secret("Password", false));
        let sealed = entry(
            Sealing::Fingerprint(&key),
            &[("Password", "hunter2", false)],
        );
        assert!(sealed.field("Password").unwrap().value.is_sealed());
        assert!(
            !sealed.field("Password").unwrap().protected,
            "the flag is kept"
        );
        assert_eq!(metadata_value(&sealed, "Password"), None);
        let revealed = entry(Sealing::Reveal(&key), &[("Password", "hunter2", false)]);
        assert_eq!(
            revealed.field("Password").unwrap().value.as_plain(),
            Some("hunter2")
        );
        assert_eq!(metadata_value(&revealed, "Password"), None);
    }

    #[test]
    fn is_secret_truth_table() {
        assert!(!is_secret("Title", true));
        assert!(!is_secret("Title", false));
        assert!(is_secret("Password", false));
        assert!(is_secret("Password", true));
        assert!(is_secret("PIN", true));
        assert!(!is_secret("PIN", false));
        assert!(!is_secret("UserName", false));
        assert!(is_secret("UserName", true));
        assert!(
            is_secret("title", true),
            "only the exact Title is an address"
        );
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
