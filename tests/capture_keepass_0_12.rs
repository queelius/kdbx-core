//! Capture from keepass 0.12.
//!
//! keepass 0.12 cannot pin UUIDs, so the full-equality test reads the file
//! keepass 0.15 writes from the shared fixture (keepass 0.12 reads KDBX 4.1)
//! and compares against the same expected snapshot, minus what 0.12 cannot
//! represent.
#![cfg(feature = "keepass-0_12")]

mod common;

use common::*;
use kdbx_core::capture::keepass_0_12::{capture, otp_fields};
use kdbx_core::model::{AutoTypeObfuscation, Sealing, Value};
use kdbx_core::otp::OtpField;
use keepass_0_12 as kp;

/// The shared fixture as keepass 0.12 can read it: keepass 0.12 fails to
/// parse a KDBX 4.1 file whose groups carry `<Tags>` or whose records carry
/// `<PreviousParentGroup>`, so those are omitted.
fn fixture_bytes() -> (Vec<u8>, uuid::Uuid) {
    let (db15, icon) = rich_db_with(Kdbx41Extras::Omit);
    (save(&db15), icon)
}

#[test]
fn keepass_0_12_cannot_read_kdbx41_group_tags_or_previous_parents() {
    // Pinned so a keepass 0.12 fix (or a regression in this knowledge) shows.
    let (db15, _) = rich_db();
    let err = kp::Database::parse(&save(&db15), kp::DatabaseKey::new().with_password(PASSWORD))
        .expect_err("keepass 0.12 rejects the file");
    assert!(err.to_string().contains("unknown variant"), "{err}");
}

/// keepass 0.12's read gaps on a file keepass 0.15 wrote: it does not parse
/// `<QualityCheck>` (so every entry reads as quality-checked) nor
/// `<DeletionTime>` (so tombstones lose their time).
fn as_read_by_keepass_0_12(mut snap: kdbx_core::model::Snapshot) -> kdbx_core::model::Snapshot {
    fn group(g: &mut kdbx_core::model::Group) {
        for e in &mut g.entries {
            e.quality_check = true;
            for h in &mut e.history {
                h.quality_check = true;
            }
        }
        g.groups.iter_mut().for_each(group);
    }
    group(&mut snap.root);
    for when in snap.deleted_objects.values_mut() {
        *when = None;
    }
    snap
}

fn open(bytes: &[u8]) -> kp::Database {
    kp::Database::parse(bytes, kp::DatabaseKey::new().with_password(PASSWORD)).expect("open")
}

#[test]
fn reads_the_shared_fixture_to_the_expected_snapshot() {
    let (bytes, icon) = fixture_bytes();
    let db = open(&bytes);
    let key = key();
    for sealing in [Sealing::Fingerprint(&key), Sealing::Reveal(&key)] {
        let snap = capture(&db, &sealing);
        let mut want = as_read_by_keepass_0_12(without_kdbx41_extras(expected(&sealing, icon)));
        want.meta.generator = snap.meta.generator.clone();
        assert_eq!(snap, want, "reveal = {}", sealing.reveals());
    }
}

#[test]
fn fingerprint_capture_contains_no_protected_plaintext() {
    let (bytes, _) = fixture_bytes();
    let db = open(&bytes);
    let key = key();
    assert_no_secrets(&capture(&db, &Sealing::Fingerprint(&key)));
}

#[test]
fn in_memory_database_seals_and_maps_version_differences() {
    let mut db = kp::Database::new();
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_protected("Title", "Bank");
        e.set_protected("Password", "hunter2");
        e.set_unprotected("URL", "https://bank.example");
        e.autotype = Some(kp::db::AutoType {
            data_transfer_obfuscation: Some(true),
            ..Default::default()
        });
        e.id()
    };
    let key = key();
    let snap = capture(&db, &Sealing::Fingerprint(&key));
    assert_eq!(snap.format.to_string(), "4.0");
    let entry = snap.find_entry(id.uuid()).unwrap();
    assert_eq!(entry.title(), Some("Bank"));
    assert!(matches!(
        entry.field("Password").unwrap().value,
        Value::Sealed(_)
    ));
    assert_eq!(
        entry.field("URL").unwrap().value.as_plain(),
        Some("https://bank.example")
    );
    // keepass 0.12's absent QualityCheck means on.
    assert!(entry.quality_check);
    assert_eq!(
        entry.autotype.as_ref().unwrap().obfuscation,
        AutoTypeObfuscation::UseClipboard
    );
}

#[test]
fn children_are_sorted_by_uuid_because_document_order_is_lost() {
    let mut db = kp::Database::new();
    for i in 0..16 {
        db.root_mut()
            .add_entry()
            .set_unprotected("Title", format!("e{i}"));
        db.root_mut().add_group().name = format!("g{i}");
    }
    let key = key();
    let snap = capture(&db, &Sealing::Fingerprint(&key));
    let entry_ids: Vec<_> = snap.root.entries.iter().map(|e| e.uuid).collect();
    let group_ids: Vec<_> = snap.root.groups.iter().map(|g| g.uuid).collect();
    assert!(entry_ids.is_sorted(), "{entry_ids:?}");
    assert!(group_ids.is_sorted(), "{group_ids:?}");
    // And so a capture is reproducible across processes and clones.
    assert_eq!(capture(&db.clone(), &Sealing::Fingerprint(&key)), snap);
}

#[test]
fn tags_are_split_with_the_kdbx_grammar() {
    // keepass 0.12 itself splits `<Tags>` on ',' only, so "money;finance"
    // would read as one tag; the adapter re-splits.
    let mut db = kp::Database::new();
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.tags = vec!["money;finance".into(), " work ".into(), String::new()];
        e.id()
    };
    let key = key();
    let snap = capture(&db, &Sealing::Fingerprint(&key));
    let tags: Vec<_> = snap
        .find_entry(id.uuid())
        .unwrap()
        .tags
        .iter()
        .cloned()
        .collect();
    assert_eq!(tags, ["finance", "money", "work"]);
}

#[test]
fn otp_fields_returns_only_otp_plaintext() {
    let mut db = kp::Database::new();
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_protected("Password", "not-otp");
        e.set_protected("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ");
        e.id()
    };
    let entry = db.entry(id).unwrap();
    let fields = otp_fields(&entry);
    assert_eq!(
        fields.fields().collect::<Vec<_>>(),
        [OtpField::NativeSecretBase32]
    );
    assert_eq!(
        fields.get(OtpField::NativeSecretBase32),
        Some("GEZDGNBVGY3TQOJQ")
    );
}

/// Both adapters read the same file to the same snapshot, up to keepass
/// 0.12's documented read gaps.
#[cfg(feature = "keepass-0_15")]
#[test]
fn both_keepass_versions_capture_the_same_file_alike() {
    let (bytes, _) = fixture_bytes();
    let db15 = ::keepass_0_15::Database::parse(
        &bytes,
        ::keepass_0_15::DatabaseKey::new().with_password(PASSWORD),
    )
    .unwrap();
    let key = key();
    let sealing = Sealing::Fingerprint(&key);
    let via_0_15 =
        as_read_by_keepass_0_12(kdbx_core::capture::keepass_0_15::capture(&db15, &sealing));
    let via_0_12 = capture(&open(&bytes), &sealing);
    assert_eq!(via_0_12, via_0_15);
}
