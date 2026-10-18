//! Capture from keepass 0.15.
#![cfg(feature = "keepass-0_15")]

mod common;

use common::*;
use kdbx_core::capture::keepass_0_15::{capture, otp_fields};
use kdbx_core::model::{Sealing, Value};
use kdbx_core::otp::OtpField;
use keepass_0_15 as kp;

#[test]
fn full_snapshot_under_fingerprint_sealing() {
    let (db, icon) = rich_db();
    let key = key();
    let sealing = Sealing::Fingerprint(&key);
    assert_eq!(capture(&db, &sealing), expected(&sealing, icon));
}

#[test]
fn full_snapshot_under_reveal() {
    let (db, icon) = rich_db();
    let key = key();
    let sealing = Sealing::Reveal(&key);
    let snap = capture(&db, &sealing);
    assert_eq!(snap, expected(&sealing, icon));
    let bank = snap.find_entry(BANK).unwrap();
    assert_eq!(
        bank.field("Password").unwrap().value.as_plain(),
        Some("hunter2")
    );
    assert!(bank.field("Password").unwrap().protected);
}

#[test]
fn fingerprint_capture_contains_no_protected_plaintext() {
    let (db, _) = rich_db();
    let key = key();
    let snap = capture(&db, &Sealing::Fingerprint(&key));
    assert_no_secrets(&snap);
    // The protected Title stays an address.
    let bank = snap.find_entry(BANK).unwrap();
    assert_eq!(bank.title(), Some("Bank"));
    assert!(bank.field("Title").unwrap().protected);
    assert!(matches!(
        bank.field("UserName").unwrap().value,
        Value::Sealed(_)
    ));
}

#[test]
fn saved_file_captures_like_the_in_memory_database() {
    let (db, icon) = rich_db();
    let bytes = save(&db);
    let reopened =
        kp::Database::parse(&bytes, kp::DatabaseKey::new().with_password(PASSWORD)).unwrap();
    let key = key();
    let sealing = Sealing::Fingerprint(&key);
    let snap = capture(&reopened, &sealing);
    let mut want = expected(&sealing, icon);
    // Saving stamps the writer into <Generator>.
    want.meta.generator = snap.meta.generator.clone();
    assert_eq!(snap, want);
}

#[test]
fn header_alone_matches_the_captured_header_and_sets_derive_params() {
    use kdbx_core::capture::keepass_0_15::header;
    use kdbx_core::fingerprint::DeriveParams;
    let (db, _) = rich_db();
    let key = key();
    let snap = capture(&db, &Sealing::Fingerprint(&key));
    assert_eq!(Some(header(&db)), snap.header);
    // AES-KDF vault: the derivation floor.
    assert_eq!(
        DeriveParams::for_header(Some(&header(&db))),
        DeriveParams::FLOOR
    );
    assert_eq!(DeriveParams::for_snapshot(&snap), DeriveParams::FLOOR);
    // keepass's default config is Argon2d, 1 MiB, 50 passes, 4 lanes.
    let params = DeriveParams::for_header(Some(&header(&kp::Database::new())));
    assert_eq!(
        (params.memory_kib(), params.iterations(), params.lanes()),
        (65_536, 50, 4)
    );
}

#[test]
fn capture_is_deterministic() {
    let (db, _) = rich_db();
    let key = key();
    let a = serde_json::to_string(&capture(&db, &Sealing::Fingerprint(&key))).unwrap();
    let b = serde_json::to_string(&capture(&db.clone(), &Sealing::Fingerprint(&key))).unwrap();
    assert_eq!(a, b);
}

#[test]
fn otp_fields_returns_only_otp_plaintext() {
    let mut db = kp::Database::new();
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Mail");
        e.set_protected("Password", "not-otp");
        e.set_protected("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
        e.set_protected("TOTP Seed", "JBSWY3DPEHPK3PXP");
        e.set_unprotected("TOTP Settings", "30;6");
        e.id()
    };
    let entry = db.entry(id).unwrap();
    let fields = otp_fields(&entry);
    assert_eq!(
        fields.fields().collect::<Vec<_>>(),
        [
            OtpField::Uri,
            OtpField::LegacySeed,
            OtpField::LegacySettings
        ]
    );
    assert_eq!(fields.get(OtpField::LegacySeed), Some("JBSWY3DPEHPK3PXP"));
}

#[test]
fn format_version_is_reported() {
    let key = key();
    let snap = capture(&kp::Database::new(), &Sealing::Fingerprint(&key));
    assert_eq!(snap.format.to_string(), "4.1");
    assert!(snap.root.entries.is_empty() && snap.root.groups.is_empty());
}
