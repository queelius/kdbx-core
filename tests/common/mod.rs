//! Shared fixtures for the capture tests: a feature-rich database built with
//! keepass 0.15 and fixed UUIDs, and the snapshot it must capture to.
#![allow(dead_code)]

use chrono::NaiveDateTime;
use kdbx_core::fingerprint::FingerprintKey;
use kdbx_core::model::{
    AutoType, AutoTypeAssociation, AutoTypeObfuscation, Compression, Entry, Field, FormatVersion,
    Group, HeaderInfo, Icon, InnerCipher, KdfInfo, MemoryProtection, Meta, OuterCipher, Rgb,
    Sealing, Snapshot, Times, Timestamp,
};
use keepass_0_15 as kp;
use kp::db::{CustomDataItem, CustomDataValue, EntryId, GroupId};
use uuid::Uuid;

pub const PASSWORD: &str = "kdbx-core-test-password";

/// Fixed identities `0000000n-c0de-4000-8000-000000000000`.
pub const fn id(n: u128) -> Uuid {
    Uuid::from_u128((n << 96) | 0x0000_0000_c0de_4000_8000_0000_0000_0000)
}

pub const ROOT: Uuid = id(0x01);
pub const PERSONAL: Uuid = id(0x02);
pub const WORK: Uuid = id(0x03);
pub const ARCHIVE: Uuid = id(0x04);
pub const RECYCLE_BIN: Uuid = id(0x09);
pub const BANK: Uuid = id(0x11);
pub const VPN: Uuid = id(0x13);
pub const DELETED: Uuid = id(0x99);

/// 2026-01-01T09:00:00Z.
pub const T0: i64 = 1_767_258_000;
pub const DAY: i64 = 86_400;

/// Every plaintext that must never appear in a fingerprint-sealed capture.
/// Each contains a character outside `[0-9a-f]`, so none can occur by chance
/// inside the hex fingerprints of the serialized snapshot.
pub const SECRETS: &[&str] = &[
    "hunter2",
    "alice-protected",
    "pin-zq-4821",
    "old-password-1",
    "old-password-2",
    "vpn-secret",
    "codes-v1",
    "browser-secret",
    "group-secret",
    "entry-secret",
];

pub fn key() -> FingerprintKey {
    FingerprintKey::from_bytes([0x5A; 32])
}

pub fn ndt(secs: i64) -> NaiveDateTime {
    chrono::DateTime::from_timestamp(secs, 0)
        .expect("in range")
        .naive_utc()
}

pub fn ts(secs: i64) -> Option<Timestamp> {
    Timestamp::from_unix(secs)
}

fn kp_times(secs: i64) -> kp::db::Times {
    let mut t = kp::db::Times::default();
    t.creation = Some(ndt(secs));
    t.last_modification = Some(ndt(secs + 1));
    t.last_access = Some(ndt(secs + 2));
    t.expiry = Some(ndt(secs + 3));
    t.location_changed = Some(ndt(secs + 4));
    t.expires = Some(false);
    t.usage_count = Some(3);
    t
}

/// The model image of [`kp_times`].
pub fn times(secs: i64) -> Times {
    let mut t = Times::default();
    t.creation = ts(secs);
    t.last_modification = ts(secs + 1);
    t.last_access = ts(secs + 2);
    t.expiry = ts(secs + 3);
    t.location_changed = ts(secs + 4);
    t.expires = Some(false);
    t.usage_count = Some(3);
    t
}

fn custom_item(value: CustomDataValue, secs: i64) -> CustomDataItem {
    CustomDataItem {
        value: Some(value),
        last_modification_time: Some(ndt(secs)),
    }
}

/// A database exercising every model field keepass 0.15 can express:
///
/// ```text
/// Root (01)                     meta: name, description, colors, custom data, ...
/// ├── Personal (02)             notes, tags, icon, flags, custom data
/// │   └── Bank (11)             protected Title/UserName/Password/PIN, attachments,
/// │                             custom icon, colors, auto-type, 2 history items,
/// │                             moved here from Work
/// ├── Work (03)
/// │   └── VPN (13)
/// └── Archive (04)              moved here from Work
/// ```
///
/// Returns the database and the UUID of Bank's custom icon (keepass draws it
/// at random).
pub fn rich_db() -> (kp::Database, Uuid) {
    rich_db_with(Kdbx41Extras::Include)
}

/// Whether [`rich_db_with`] uses the KDBX 4.1 features keepass 0.12 cannot
/// parse: group `<Tags>` and `<PreviousParentGroup>` (keepass 0.12 rejects
/// both as "unknown variant").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdbx41Extras {
    Include,
    Omit,
}

/// [`rich_db`], optionally without group tags and moves (Bank is created in
/// Personal and Archive at the root directly), so keepass 0.12 can read it.
pub fn rich_db_with(extras: Kdbx41Extras) -> (kp::Database, Uuid) {
    let include = extras == Kdbx41Extras::Include;
    let bank_home = if include { WORK } else { PERSONAL };
    let archive_home = if include { WORK } else { ROOT };
    let mut db = kp::Database::new_with_root_id(GroupId::from_uuid(ROOT));
    db.config.kdf_config = kp::config::KdfConfig::Aes { rounds: 64 };
    let mut public = kp::config::VariantDictionary::new();
    public.set("kdbx-core-plugin", 42u32);
    db.config.public_custom_data = Some(public);

    let m = &mut db.meta;
    m.database_name = Some("kdbx-core capture test".into());
    m.database_name_changed = Some(ndt(T0));
    m.database_description = Some("a description".into());
    m.default_username = Some("alice".into());
    m.color = Some("#112233".parse().unwrap());
    m.maintenance_history_days = Some(365);
    m.master_key_changed = Some(ndt(T0));
    m.master_key_change_rec = Some(-1);
    m.recyclebin_enabled = Some(true);
    m.recyclebin_uuid = Some(RECYCLE_BIN);
    m.history_max_items = Some(10);
    m.history_max_size = Some(6_291_456);
    m.memory_protection = Some(kp::db::MemoryProtection {
        protect_username: true,
        ..Default::default()
    });
    m.custom_data.insert(
        "KPXC_BROWSER_key".into(),
        custom_item(CustomDataValue::String("browser-secret".into()), T0),
    );
    m.custom_data.insert(
        "binary".into(),
        custom_item(CustomDataValue::Binary(vec![0, 1, 2]), T0),
    );

    {
        let mut root = db.root_mut();
        root.name = "Root".into();
        let mut personal = root
            .add_group_with_id(GroupId::from_uuid(PERSONAL))
            .unwrap();
        personal.name = "Personal".into();
        personal.notes = Some("personal notes".into());
        if include {
            personal.tags = vec!["home".into()];
        }
        personal.set_icon_builtin(48);
        personal.is_expanded = false;
        personal.enable_searching = Some(false);
        personal.enable_autotype = Some(true);
        personal.default_autotype_sequence = Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into());
        personal.custom_data.insert(
            "group-key".into(),
            custom_item(CustomDataValue::String("group-secret".into()), T0),
        );
    }
    db.root_mut()
        .add_group_with_id(GroupId::from_uuid(WORK))
        .unwrap()
        .name = "Work".into();
    {
        let mut work = db.group_mut(GroupId::from_uuid(WORK)).unwrap();
        let mut vpn = work.add_entry_with_id(EntryId::from_uuid(VPN)).unwrap();
        vpn.set_unprotected("Title", "VPN");
        vpn.set_unprotected("UserName", "bob");
        vpn.set_protected("Password", "vpn-secret");
    }
    {
        let mut home = db.group_mut(GroupId::from_uuid(bank_home)).unwrap();
        let mut bank = home.add_entry_with_id(EntryId::from_uuid(BANK)).unwrap();
        bank.set_protected("Title", "Bank");
        bank.set_protected("UserName", "alice-protected");
        bank.set_protected("Password", "hunter2");
        bank.set_unprotected("URL", "https://bank.example");
        bank.set_unprotected("Notes", "line one\nline two");
        bank.set_protected("PIN", "pin-zq-4821");
        bank.tags = vec!["money".into(), "finance".into()];
    }
    // History: two earlier versions differing in their password, cloned
    // before the entry gains attachments and moves.
    for (n, password) in [(1, "old-password-1"), (2, "old-password-2")] {
        let mut old: kp::db::Entry = (*db.entry(EntryId::from_uuid(BANK)).unwrap()).clone();
        old.set_protected("Password", password);
        old.times = kp_times(T0 - (3 - n) * DAY);
        db.entry_mut(EntryId::from_uuid(BANK))
            .unwrap()
            .history
            .get_or_insert_default()
            .add_entry(old);
    }
    let icon = {
        let mut bank = db.entry_mut(EntryId::from_uuid(BANK)).unwrap();
        bank.add_attachment(
            "recovery.txt",
            kp::db::Value::protected(b"codes-v1".to_vec()),
        );
        bank.add_attachment(
            "statement.pdf",
            kp::db::Value::unprotected(b"pdf-bytes".to_vec()),
        );
        bank.custom_data.insert(
            "entry-key".into(),
            custom_item(CustomDataValue::String("entry-secret".into()), T0),
        );
        bank.foreground_color = Some("#FF0000".parse().unwrap());
        bank.background_color = Some("#00FF00".parse().unwrap());
        bank.override_url = Some("cmd://open".into());
        bank.quality_check = false;
        let at = kp::db::AutoType {
            enabled: true,
            default_sequence: Some("{PASSWORD}".into()),
            data_transfer_obfuscation: kp::db::DataTransferObfuscation::UseClipboard,
            associations: vec![kp::db::AutoTypeAssociation {
                window: "Bank*".into(),
                sequence: "{USERNAME}".into(),
            }],
        };
        bank.autotype = Some(at);
        let mut icon = bank.set_icon_custom_new(b"\x89PNG-icon".to_vec());
        icon.last_modification_time = None;
        icon.id().uuid()
    };
    {
        let mut home = db.group_mut(GroupId::from_uuid(archive_home)).unwrap();
        home.add_group_with_id(GroupId::from_uuid(ARCHIVE))
            .unwrap()
            .name = "Archive".into();
    }
    if include {
        db.entry_mut(EntryId::from_uuid(BANK))
            .unwrap()
            .move_to(GroupId::from_uuid(PERSONAL))
            .unwrap();
        db.group_mut(GroupId::from_uuid(ARCHIVE))
            .unwrap()
            .move_to(GroupId::from_uuid(ROOT))
            .unwrap();
    }
    db.deleted_objects.insert(DELETED, Some(ndt(T0)));

    // Pin every live timestamp, so the expected snapshot is fixed.
    let groups: Vec<GroupId> = db.iter_all_groups().map(|g| g.id()).collect();
    for g in groups {
        db.group_mut(g).unwrap().times = kp_times(T0);
    }
    let entries: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
    for e in entries {
        db.entry_mut(e).unwrap().times = kp_times(T0 + DAY);
    }
    (db, icon)
}

/// Save with a cheap KDF and return the KDBX 4.1 bytes.
pub fn save(db: &kp::Database) -> Vec<u8> {
    let mut out = Vec::new();
    db.save(&mut out, kp::DatabaseKey::new().with_password(PASSWORD))
        .expect("save");
    out
}

/// The snapshot [`rich_db`] captures to under `sealing` (via keepass 0.15,
/// in memory).
pub fn expected(sealing: &Sealing<'_>, icon: Uuid) -> Snapshot {
    let mut meta = Meta::default();
    meta.database_name = Some("kdbx-core capture test".into());
    meta.database_name_changed = ts(T0);
    meta.database_description = Some("a description".into());
    meta.default_username = Some("alice".into());
    meta.color = Some(Rgb {
        r: 0x11,
        g: 0x22,
        b: 0x33,
    });
    meta.maintenance_history_days = Some(365);
    meta.master_key_changed = ts(T0);
    meta.master_key_change_rec = Some(-1);
    meta.recycle_bin_enabled = Some(true);
    meta.recycle_bin = Some(RECYCLE_BIN);
    meta.history_max_items = Some(10);
    meta.history_max_size = Some(6_291_456);
    let mut mp = MemoryProtection::default();
    mp.user_name = true;
    meta.memory_protection = Some(mp);
    meta.custom_data.insert(
        "KPXC_BROWSER_key".into(),
        sealing.custom_text("browser-secret", ts(T0)),
    );
    meta.custom_data
        .insert("binary".into(), sealing.custom_binary(&[0, 1, 2], ts(T0)));
    meta.custom_icons
        .insert(icon, sealing.custom_icon(b"\x89PNG-icon", None, None));

    let bank_fields = |password: &str| {
        [
            ("Title", true, "Bank"),
            ("UserName", true, "alice-protected"),
            ("Password", true, password),
            ("URL", false, "https://bank.example"),
            ("Notes", false, "line one\nline two"),
            ("PIN", true, "pin-zq-4821"),
        ]
        .into_iter()
        .map(|(name, protected, value)| (name.to_owned(), sealing.field(name, protected, value)))
        .collect::<std::collections::BTreeMap<_, _>>()
    };
    let history_item = |password: &str, secs: i64| {
        let mut e = Entry::new(BANK);
        e.fields = bank_fields(password);
        e.tags = ["finance", "money"].map(String::from).into();
        e.times = times(secs);
        e
    };

    let mut bank = Entry::new(BANK);
    bank.fields = bank_fields("hunter2");
    bank.tags = ["finance", "money"].map(String::from).into();
    bank.attachments
        .insert("recovery.txt".into(), sealing.attachment(b"codes-v1", true));
    bank.attachments.insert(
        "statement.pdf".into(),
        sealing.attachment(b"pdf-bytes", false),
    );
    bank.times = times(T0 + DAY);
    bank.icon = Some(Icon::Custom(icon));
    bank.foreground = Some(Rgb {
        r: 0xFF,
        g: 0,
        b: 0,
    });
    bank.background = Some(Rgb {
        r: 0,
        g: 0xFF,
        b: 0,
    });
    bank.override_url = Some("cmd://open".into());
    bank.quality_check = false;
    let mut at = AutoType::default();
    at.enabled = true;
    at.default_sequence = Some("{PASSWORD}".into());
    at.obfuscation = AutoTypeObfuscation::UseClipboard;
    at.associations
        .push(AutoTypeAssociation::new("Bank*", "{USERNAME}"));
    bank.autotype = Some(at);
    bank.custom_data.insert(
        "entry-key".into(),
        sealing.custom_text("entry-secret", ts(T0)),
    );
    bank.previous_parent = Some(WORK);
    // keepass's History::add_entry prepends: newest first.
    bank.history = vec![
        history_item("old-password-2", T0 - DAY),
        history_item("old-password-1", T0 - 2 * DAY),
    ];

    let mut personal = Group::new(PERSONAL, "Personal").with_entry(bank);
    personal.notes = Some("personal notes".into());
    personal.tags = ["home".to_owned()].into();
    personal.icon = Some(Icon::Standard(48));
    personal.times = times(T0);
    personal.flags.is_expanded = false;
    personal.flags.enable_searching = Some(false);
    personal.flags.enable_autotype = Some(true);
    personal.flags.default_autotype_sequence = Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into());
    personal.custom_data.insert(
        "group-key".into(),
        sealing.custom_text("group-secret", ts(T0)),
    );

    let mut vpn = Entry::new(VPN)
        .with_field("Title", Field::plain("VPN"))
        .with_field("UserName", Field::plain("bob"))
        .with_field("Password", sealing.field("Password", true, "vpn-secret"));
    vpn.times = times(T0 + DAY);

    let mut work = Group::new(WORK, "Work").with_entry(vpn);
    work.times = times(T0);
    let mut archive = Group::new(ARCHIVE, "Archive");
    archive.times = times(T0);
    archive.previous_parent = Some(WORK);

    let mut root = Group::new(ROOT, "Root")
        .with_group(personal)
        .with_group(work)
        .with_group(archive);
    root.times = times(T0);

    let mut snap = Snapshot::new(FormatVersion::KDBX_4_1, meta, root);
    snap.deleted_objects.insert(DELETED, ts(T0));
    let mut header = HeaderInfo::new(
        KdfInfo::Aes { rounds: 64 },
        OuterCipher::Aes256,
        InnerCipher::ChaCha20,
        Compression::GZip,
    );
    header.public_custom_data.insert("kdbx-core-plugin".into());
    snap.header = Some(header);
    snap
}

/// Clear what keepass 0.12 cannot represent (KDBX 4.1 group tags, previous
/// parents, custom icon names and times).
pub fn without_kdbx41_extras(mut snap: Snapshot) -> Snapshot {
    fn group(g: &mut Group) {
        g.tags.clear();
        g.previous_parent = None;
        for e in &mut g.entries {
            e.previous_parent = None;
            for h in &mut e.history {
                h.previous_parent = None;
            }
        }
        g.groups.iter_mut().for_each(group);
    }
    group(&mut snap.root);
    for icon in snap.meta.custom_icons.values_mut() {
        icon.name = None;
        icon.modified = None;
    }
    snap
}

/// Assert no secret plaintext appears anywhere in the serialized snapshot.
pub fn assert_no_secrets(snap: &Snapshot) {
    for secret in SECRETS {
        assert!(
            !secret.chars().all(|c| c.is_ascii_hexdigit()),
            "{secret:?} could match inside a hex fingerprint"
        );
    }
    let json = serde_json::to_string(snap).expect("serializes");
    for secret in SECRETS {
        assert!(
            !json.contains(secret),
            "secret {secret:?} leaked into {json}"
        );
    }
}
