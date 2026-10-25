//! The serialized names of every public serializable type, pinned.
//!
//! diff-kdbx's versioned JSON (`format_version` 1) embeds these forms, so
//! they are a stability contract: changing one is a breaking change for that
//! JSON and must bump kdbx-core's minor version and be coordinated with
//! diff-kdbx. Each enum's variant list is checked by an exhaustive `match`
//! (possible inside the crate despite `#[non_exhaustive]`), so adding a
//! variant fails to compile here until its serialized name is pinned too.
// Values are built the way downstream crates must build `#[non_exhaustive]`
// structs: a constructor or `default()`, then field assignment.
#![allow(clippy::field_reassign_with_default)]

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use uuid::Uuid;

use crate::fields::{FieldTraits, StandardField};
use crate::fingerprint::{DeriveParams, Fingerprint};
use crate::model::*;
use crate::otp::{MalformedReason, OtpError, OtpField, OtpSource};
use crate::path::VaultPath;

/// `value` serializes to exactly `expected` (compact JSON) and back.
fn pinned<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T, expected: &str) {
    let json = serde_json::to_string(&value).expect("serializes");
    assert_eq!(json, expected, "serialized form of {value:?} changed");
    let back: T = serde_json::from_str(expected).expect("deserializes");
    assert_eq!(
        back, value,
        "{expected} no longer deserializes to {value:?}"
    );
}

fn fp() -> Fingerprint {
    Fingerprint::from_bytes([0xAB; 32])
}

const FP_HEX: &str = "abababababababababababababababababababababababababababababababab";

#[test]
fn standard_fields() {
    for f in StandardField::ALL {
        let name = match f {
            StandardField::Title => "Title",
            StandardField::UserName => "UserName",
            StandardField::Password => "Password",
            StandardField::Url => "URL",
            StandardField::Notes => "Notes",
        };
        pinned(f, &format!("\"{name}\""));
    }
}

#[test]
fn field_traits() {
    pinned(
        StandardField::Notes.traits(),
        r#"{"multiline":true,"protected_by_default":false}"#,
    );
    pinned(
        FieldTraits::CUSTOM,
        r#"{"multiline":false,"protected_by_default":false}"#,
    );
}

#[test]
fn scalars() {
    pinned(fp(), &format!("\"{FP_HEX}\""));
    pinned(
        DeriveParams::FLOOR,
        r#"{"memory_kib":65536,"iterations":3,"lanes":1}"#,
    );
    pinned(
        Timestamp::from_unix(1_767_258_000).unwrap(),
        r#""2026-01-01T09:00:00Z""#,
    );
    pinned(
        Rgb {
            r: 0x0A,
            g: 0xBC,
            b: 0xFF,
        },
        r##""#0ABCFF""##,
    );
    pinned(FormatVersion::KDBX_4_1, r#"{"major":4,"minor":1}"#);
    pinned(VaultPath::parse("/Web/Dup:2").unwrap(), r#""/Web/Dup:2""#);
    pinned(VaultPath::parse("/Web/").unwrap(), r#""/Web/""#);
    pinned(VaultPath::root(), r#""/""#);
}

#[test]
fn value() {
    for v in [Value::Plain("x".into()), Value::Sealed(fp())] {
        let expected = match &v {
            Value::Plain(_) => r#"{"plain":"x"}"#.to_owned(),
            Value::Sealed(_) => format!(r#"{{"sealed":"{FP_HEX}"}}"#),
        };
        pinned(v, &expected);
    }
}

#[test]
fn icon() {
    let uuid = Uuid::from_u128(7);
    for icon in [Icon::Standard(48), Icon::Custom(uuid)] {
        let expected = match icon {
            Icon::Standard(_) => r#"{"standard":48}"#,
            Icon::Custom(_) => r#"{"custom":"00000000-0000-0000-0000-000000000007"}"#,
        };
        pinned(icon, expected);
    }
}

#[test]
fn unit_enums() {
    for v in [AutoTypeObfuscation::None, AutoTypeObfuscation::UseClipboard] {
        let name = match v {
            AutoTypeObfuscation::None => "none",
            AutoTypeObfuscation::UseClipboard => "use_clipboard",
        };
        pinned(v, &format!("\"{name}\""));
    }
    for v in [NodeKind::Group, NodeKind::Entry] {
        let name = match v {
            NodeKind::Group => "group",
            NodeKind::Entry => "entry",
        };
        pinned(v, &format!("\"{name}\""));
    }
    for v in [Argon2Variant::Argon2d, Argon2Variant::Argon2id] {
        let name = match v {
            Argon2Variant::Argon2d => "argon2d",
            Argon2Variant::Argon2id => "argon2id",
        };
        pinned(v, &format!("\"{name}\""));
    }
    for v in [
        OuterCipher::Aes256,
        OuterCipher::Twofish,
        OuterCipher::ChaCha20,
        OuterCipher::Unrecognized,
    ] {
        let name = match v {
            OuterCipher::Aes256 => "aes256",
            OuterCipher::Twofish => "twofish",
            OuterCipher::ChaCha20 => "chacha20",
            OuterCipher::Unrecognized => "unrecognized",
        };
        pinned(v, &format!("\"{name}\""));
    }
    for v in [
        InnerCipher::Plain,
        InnerCipher::Salsa20,
        InnerCipher::ChaCha20,
        InnerCipher::Unrecognized,
    ] {
        let name = match v {
            InnerCipher::Plain => "plain",
            InnerCipher::Salsa20 => "salsa20",
            InnerCipher::ChaCha20 => "chacha20",
            InnerCipher::Unrecognized => "unrecognized",
        };
        pinned(v, &format!("\"{name}\""));
    }
    for v in [
        Compression::None,
        Compression::GZip,
        Compression::Unrecognized,
    ] {
        let name = match v {
            Compression::None => "none",
            Compression::GZip => "gzip",
            Compression::Unrecognized => "unrecognized",
        };
        pinned(v, &format!("\"{name}\""));
    }
}

#[test]
fn save_support() {
    for loss in SaveLoss::ALL {
        let name = match loss {
            SaveLoss::DeletionRecords => "deletion_records",
            SaveLoss::ChildOrder => "child_order",
            SaveLoss::EmptyFields => "empty_fields",
            SaveLoss::Kdbx41EntryData => "kdbx41_entry_data",
        };
        pinned(loss, &format!("\"{name}\""));
    }
    let lossy = SaveSupport::with_losses(
        FormatVersion::KDBX_4_0,
        [SaveLoss::EmptyFields, SaveLoss::ChildOrder].into(),
    );
    for support in [
        SaveSupport::Lossless,
        lossy,
        SaveSupport::Unsupported {
            format: FormatVersion::KDBX_3_1,
        },
    ] {
        let expected = match support {
            SaveSupport::Lossless => r#"{"kind":"lossless"}"#,
            SaveSupport::Lossy { .. } => {
                r#"{"kind":"lossy","format":{"major":4,"minor":0},"losses":["child_order","empty_fields"]}"#
            }
            SaveSupport::Unsupported { .. } => {
                r#"{"kind":"unsupported","format":{"major":3,"minor":1}}"#
            }
        };
        pinned(support, expected);
    }
}

#[test]
fn kdf_info() {
    let argon2 = Argon2Info::new(Argon2Variant::Argon2id, 67_108_864, 10, 2, 0x13);
    for kdf in [
        KdfInfo::Aes { rounds: 60_000 },
        KdfInfo::Argon2(argon2),
        KdfInfo::Unrecognized,
    ] {
        let expected = match kdf {
            KdfInfo::Aes { .. } => r#"{"aes":{"rounds":60000}}"#,
            KdfInfo::Argon2(_) => {
                r#"{"argon2":{"variant":"argon2id","memory_bytes":67108864,"iterations":10,"parallelism":2,"version":19}}"#
            }
            KdfInfo::Unrecognized => r#""unrecognized""#,
        };
        pinned(kdf, expected);
    }
}

#[test]
fn otp_names() {
    for &f in OtpField::ALL {
        let name = match f {
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
        };
        pinned(f, &format!("\"{name}\""));
    }
    for &s in OtpSource::PRECEDENCE {
        let name = match s {
            OtpSource::Uri => "uri",
            OtpSource::KeePassNative => "keepass_native",
            OtpSource::Legacy => "legacy",
        };
        pinned(s, &format!("\"{name}\""));
    }
    use MalformedReason::*;
    for r in [
        NotAnOtpauthUri,
        NotTotp,
        MissingSecret,
        InvalidSecret,
        MultipleSecrets,
        InvalidPeriod,
        InvalidDigits,
        UnknownAlgorithm,
        UnknownEncoder,
        InvalidSettings,
        MissingField(OtpField::LegacySeed),
    ] {
        let expected = match r {
            NotAnOtpauthUri => r#""not_an_otpauth_uri""#,
            NotTotp => r#""not_totp""#,
            MissingSecret => r#""missing_secret""#,
            InvalidSecret => r#""invalid_secret""#,
            MultipleSecrets => r#""multiple_secrets""#,
            InvalidPeriod => r#""invalid_period""#,
            InvalidDigits => r#""invalid_digits""#,
            UnknownAlgorithm => r#""unknown_algorithm""#,
            UnknownEncoder => r#""unknown_encoder""#,
            InvalidSettings => r#""invalid_settings""#,
            MissingField(_) => r#"{"missing_field":"TOTP Seed"}"#,
        };
        pinned(r, expected);
    }
    for e in [
        OtpError::Sealed(OtpField::Uri),
        OtpError::Malformed {
            source: OtpSource::Uri,
            reason: NotTotp,
        },
    ] {
        let expected = match e {
            OtpError::Sealed(_) => r#"{"sealed":"otp"}"#,
            OtpError::Malformed { .. } => r#"{"malformed":{"source":"uri","reason":"not_totp"}}"#,
        };
        pinned(e, expected);
    }
}

/// A snapshot with every struct field populated, pinning every struct's field
/// names (Snapshot, Meta, MemoryProtection, CustomValue, CustomIconInfo,
/// Group, GroupFlags, Times, Entry, Field, AttachmentInfo, AutoType,
/// AutoTypeAssociation, HeaderInfo, Argon2Info). A new field fails the
/// comparison until it is pinned here.
#[test]
fn snapshot_field_names() {
    let id = Uuid::from_u128;
    let t = Timestamp::from_unix(0);
    let custom = CustomValue::new(Value::Plain("v".into()), t);

    let mut times = Times::default();
    times.creation = t;
    times.last_modification = t;
    times.last_access = t;
    times.expiry = t;
    times.location_changed = t;
    times.expires = Some(false);
    times.usage_count = Some(1);

    let mut meta = Meta::default();
    meta.generator = Some("g".into());
    meta.database_name = Some("n".into());
    meta.database_name_changed = t;
    meta.database_description = Some("d".into());
    meta.database_description_changed = t;
    meta.default_username = Some("u".into());
    meta.default_username_changed = t;
    meta.maintenance_history_days = Some(365);
    meta.color = Some(Rgb { r: 1, g: 2, b: 3 });
    meta.master_key_changed = t;
    meta.master_key_change_rec = Some(-1);
    meta.master_key_change_force = Some(-1);
    meta.memory_protection = Some(MemoryProtection::default());
    meta.recycle_bin_enabled = Some(true);
    meta.recycle_bin = Some(id(9));
    meta.recycle_bin_changed = t;
    meta.entry_templates_group = Some(id(8));
    meta.entry_templates_group_changed = t;
    meta.last_selected_group = Some(id(1));
    meta.last_top_visible_group = Some(id(1));
    meta.history_max_items = Some(10);
    meta.history_max_size = Some(1024);
    meta.settings_changed = t;
    meta.custom_data.insert("k".into(), custom.clone());
    meta.custom_icons
        .insert(id(7), CustomIconInfo::new(4, fp(), Some("i".into()), t));

    let mut autotype = AutoType::default();
    autotype.enabled = true;
    autotype.default_sequence = Some("{PASSWORD}".into());
    autotype.obfuscation = AutoTypeObfuscation::UseClipboard;
    autotype
        .associations
        .push(AutoTypeAssociation::new("w", "s"));

    let mut entry = Entry::new(id(3)).with_field("Title", Field::plain("e"));
    entry.tags.insert("tag".into());
    entry
        .attachments
        .insert("a.txt".into(), AttachmentInfo::new(1, fp(), true));
    entry.times = times.clone();
    entry.icon = Some(Icon::Standard(0));
    entry.foreground = Some(Rgb { r: 0, g: 0, b: 0 });
    entry.background = Some(Rgb {
        r: 255,
        g: 255,
        b: 255,
    });
    entry.override_url = Some("cmd://x".into());
    entry.quality_check = false;
    entry.autotype = Some(autotype);
    entry.custom_data.insert("k".into(), custom.clone());
    entry.previous_parent = Some(id(2));
    entry.history.push(Entry::new(id(3)));

    let mut root = Group::new(id(1), "Root").with_entry(entry);
    root.notes = Some("notes".into());
    root.tags.insert("tag".into());
    root.icon = Some(Icon::Custom(id(7)));
    root.times = times;
    root.custom_data.insert("k".into(), custom);
    root.flags.is_expanded = false;
    root.flags.enable_autotype = Some(true);
    root.flags.enable_searching = Some(false);
    root.flags.default_autotype_sequence = Some("{USERNAME}".into());
    root.previous_parent = Some(id(2));

    let mut snap = Snapshot::new(FormatVersion::KDBX_4_1, meta, root);
    snap.deleted_objects.insert(id(99), t);
    let mut header = HeaderInfo::new(
        KdfInfo::Argon2(Argon2Info::new(
            Argon2Variant::Argon2d,
            1_048_576,
            50,
            4,
            0x13,
        )),
        OuterCipher::ChaCha20,
        InnerCipher::ChaCha20,
        Compression::GZip,
    );
    header.public_custom_data.insert("plugin".into());
    snap.header = Some(header);

    let expected: serde_json::Value = serde_json::from_str(PINNED_SNAPSHOT).unwrap();
    assert_eq!(serde_json::to_value(&snap).unwrap(), expected);
    let back: Snapshot = serde_json::from_str(PINNED_SNAPSHOT).unwrap();
    assert_eq!(back, snap);
}

const PINNED_SNAPSHOT: &str = r##"{
  "format": {
    "major": 4,
    "minor": 1
  },
  "meta": {
    "generator": "g",
    "database_name": "n",
    "database_name_changed": "1970-01-01T00:00:00Z",
    "database_description": "d",
    "database_description_changed": "1970-01-01T00:00:00Z",
    "default_username": "u",
    "default_username_changed": "1970-01-01T00:00:00Z",
    "maintenance_history_days": 365,
    "color": "#010203",
    "master_key_changed": "1970-01-01T00:00:00Z",
    "master_key_change_rec": -1,
    "master_key_change_force": -1,
    "memory_protection": {
      "title": false,
      "user_name": false,
      "password": true,
      "url": false,
      "notes": false
    },
    "recycle_bin_enabled": true,
    "recycle_bin": "00000000-0000-0000-0000-000000000009",
    "recycle_bin_changed": "1970-01-01T00:00:00Z",
    "entry_templates_group": "00000000-0000-0000-0000-000000000008",
    "entry_templates_group_changed": "1970-01-01T00:00:00Z",
    "last_selected_group": "00000000-0000-0000-0000-000000000001",
    "last_top_visible_group": "00000000-0000-0000-0000-000000000001",
    "history_max_items": 10,
    "history_max_size": 1024,
    "settings_changed": "1970-01-01T00:00:00Z",
    "custom_data": {
      "k": {
        "value": {
          "plain": "v"
        },
        "modified": "1970-01-01T00:00:00Z"
      }
    },
    "custom_icons": {
      "00000000-0000-0000-0000-000000000007": {
        "size": 4,
        "fingerprint": "abababababababababababababababababababababababababababababababab",
        "name": "i",
        "modified": "1970-01-01T00:00:00Z"
      }
    }
  },
  "root": {
    "uuid": "00000000-0000-0000-0000-000000000001",
    "name": "Root",
    "notes": "notes",
    "tags": [
      "tag"
    ],
    "icon": {
      "custom": "00000000-0000-0000-0000-000000000007"
    },
    "times": {
      "creation": "1970-01-01T00:00:00Z",
      "last_modification": "1970-01-01T00:00:00Z",
      "last_access": "1970-01-01T00:00:00Z",
      "expiry": "1970-01-01T00:00:00Z",
      "location_changed": "1970-01-01T00:00:00Z",
      "expires": false,
      "usage_count": 1
    },
    "custom_data": {
      "k": {
        "value": {
          "plain": "v"
        },
        "modified": "1970-01-01T00:00:00Z"
      }
    },
    "flags": {
      "is_expanded": false,
      "enable_autotype": true,
      "enable_searching": false,
      "default_autotype_sequence": "{USERNAME}"
    },
    "previous_parent": "00000000-0000-0000-0000-000000000002",
    "groups": [],
    "entries": [
      {
        "uuid": "00000000-0000-0000-0000-000000000003",
        "fields": {
          "Title": {
            "protected": false,
            "value": {
              "plain": "e"
            }
          }
        },
        "tags": [
          "tag"
        ],
        "attachments": {
          "a.txt": {
            "size": 1,
            "fingerprint": "abababababababababababababababababababababababababababababababab",
            "protected": true
          }
        },
        "times": {
          "creation": "1970-01-01T00:00:00Z",
          "last_modification": "1970-01-01T00:00:00Z",
          "last_access": "1970-01-01T00:00:00Z",
          "expiry": "1970-01-01T00:00:00Z",
          "location_changed": "1970-01-01T00:00:00Z",
          "expires": false,
          "usage_count": 1
        },
        "icon": {
          "standard": 0
        },
        "foreground": "#000000",
        "background": "#FFFFFF",
        "override_url": "cmd://x",
        "quality_check": false,
        "autotype": {
          "enabled": true,
          "default_sequence": "{PASSWORD}",
          "obfuscation": "use_clipboard",
          "associations": [
            {
              "window": "w",
              "sequence": "s"
            }
          ]
        },
        "custom_data": {
          "k": {
            "value": {
              "plain": "v"
            },
            "modified": "1970-01-01T00:00:00Z"
          }
        },
        "previous_parent": "00000000-0000-0000-0000-000000000002",
        "history": [
          {
            "uuid": "00000000-0000-0000-0000-000000000003",
            "fields": {},
            "tags": [],
            "attachments": {},
            "times": {
              "creation": null,
              "last_modification": null,
              "last_access": null,
              "expiry": null,
              "location_changed": null,
              "expires": null,
              "usage_count": null
            },
            "icon": null,
            "foreground": null,
            "background": null,
            "override_url": null,
            "quality_check": true,
            "autotype": null,
            "custom_data": {},
            "previous_parent": null,
            "history": []
          }
        ]
      }
    ]
  },
  "deleted_objects": {
    "00000000-0000-0000-0000-000000000063": "1970-01-01T00:00:00Z"
  },
  "header": {
    "kdf": {
      "argon2": {
        "variant": "argon2d",
        "memory_bytes": 1048576,
        "iterations": 50,
        "parallelism": 4,
        "version": 19
      }
    },
    "outer_cipher": "chacha20",
    "inner_cipher": "chacha20",
    "compression": "gzip",
    "public_custom_data": [
      "plugin"
    ]
  }
}"##;
