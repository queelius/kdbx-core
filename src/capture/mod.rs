//! Adapters that capture a [`Snapshot`](crate::model::Snapshot) from a keepass
//! `Database`.
//!
//! Each supported keepass version is an additive feature (`keepass-0_12`,
//! `keepass-0_15`) with its own module exposing the same four functions:
//!
//! - `capture(&Database, &Sealing) -> Snapshot`: a pure, infallible
//!   transformation of an already-opened database. Every model field is
//!   mapped; [`Sealing`](crate::model::Sealing) decides what plaintext is
//!   copied.
//! - `header(&Database) -> HeaderInfo`: the outer header's security
//!   configuration alone, so a stable fingerprint key can be derived with
//!   `DeriveParams::for_header` before capturing.
//! - `otp_fields(&Entry) -> OtpFields`: the plaintext of an entry's
//!   OTP-related fields only, so callers that capture under fingerprint sealing
//!   can still compute TOTP codes (see [`crate::otp`]).
//! - `save_support(&Database) -> SaveSupport`: whether this keepass version
//!   can save the database without losing data, so every writer applies one
//!   rule (see [`SaveSupport`](crate::model::SaveSupport)).
//!
//! Both modules are generated from one body; the handful of differences
//! between keepass versions live in small per-version shims:
//!
//! | | keepass 0.12 | keepass 0.15 |
//! |---|---|---|
//! | child order | lost (hash set): sorted by UUID | document order |
//! | group tags | not supported: empty | captured |
//! | previous parent | not supported: `None` | captured |
//! | quality check | `Option<bool>` (absent means on) | `bool` |
//! | auto-type obfuscation | `Option<bool>` | enum |
//! | custom icon name and time | not supported: `None` | captured |
//! | saves losslessly | KDBX 4.0 (4.1 loses entry-level 4.1 data) | KDBX 4.1 only |
//!
//! Gaps in both versions, because keepass keeps the data crate-private
//! (candidates for upstream accessors):
//!
//! - `previous_parent` comes from keepass's `previous_parent()`, a lookup
//!   that returns `None` when the old parent group no longer exists, so the
//!   UUID of a deleted previous parent is lost.
//! - A group's `LastTopVisibleEntry` (UI state) is not exposed at all.
//!
//! Default features pull in no keepass.
//!
//! ```
//! # #[cfg(feature = "keepass-0_15")]
//! # {
//! use kdbx_core::capture::keepass_0_15::{capture, otp_fields};
//! use kdbx_core::fingerprint::FingerprintKey;
//! use kdbx_core::model::Sealing;
//! use kdbx_core::otp::resolve_fields;
//! use keepass_0_15::Database;
//!
//! let mut db = Database::new();
//! let id = {
//!     let mut root = db.root_mut();
//!     let mut entry = root.add_entry();
//!     entry.set_unprotected("Title", "Mail");
//!     entry.set_protected("Password", "hunter2");
//!     entry.set_protected("otp", "otpauth://totp/m?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
//!     entry.id()
//! };
//!
//! // A per-session random key in real use.
//! let key = FingerprintKey::from_bytes([7; 32]);
//! let snap = capture(&db, &Sealing::Fingerprint(&key));
//! let mail = snap.find_entry(id.uuid()).unwrap();
//! assert!(mail.field("Password").unwrap().value.is_sealed());
//!
//! // OTP still works: read the OTP fields from the live entry.
//! let config = resolve_fields(&otp_fields(&db.entry(id).unwrap())).unwrap().unwrap();
//! assert_eq!(config.code_at(59).code(), "287082");
//! # }
//! ```

/// The adapter body shared by every keepass version. `$kp` is the extern
/// crate name; the invoking module defines the shim functions it calls.
#[cfg(any(feature = "keepass-0_12", feature = "keepass-0_15"))]
macro_rules! keepass_adapter {
    ($kp:ident) => {
        use std::collections::{BTreeMap, BTreeSet};

        use ::$kp::config::DatabaseVersion;
        use ::$kp::db::{
            Color, CustomDataItem, CustomDataValue, EntryRef, GroupRef, Icon as KpIcon,
            Times as KpTimes,
        };
        use uuid::Uuid;

        use $crate::model::{
            Argon2Info, Argon2Variant, AutoType, AutoTypeAssociation, Compression, CustomValue,
            Entry, FormatVersion, Group, GroupFlags, HeaderInfo, Icon, InnerCipher, KdfInfo,
            MemoryProtection, Meta, OuterCipher, Rgb, SaveSupport, Sealing, Snapshot, Times,
            Timestamp,
        };
        use $crate::otp::{OtpField, OtpFields};

        /// Capture `db` as a [`Snapshot`], sealing per `sealing`.
        ///
        /// Pure and infallible: the database is already open and decrypted.
        pub fn capture(db: &::$kp::Database, sealing: &Sealing<'_>) -> Snapshot {
            let mut snap = Snapshot::new(
                format_version(&db.config.version),
                meta(db, sealing),
                group(db.root(), sealing),
            );
            snap.header = Some(header(db));
            snap.deleted_objects = db
                .deleted_objects
                .iter()
                .map(|(uuid, when)| (*uuid, when.as_ref().and_then(timestamp)))
                .collect();
            snap
        }

        /// The plaintext of `entry`'s OTP-related fields (and of no other
        /// field), whatever the sealing of any snapshot of it.
        pub fn otp_fields(entry: &::$kp::db::Entry) -> OtpFields {
            entry
                .fields
                .iter()
                .filter_map(|(name, value)| {
                    OtpField::from_kdbx_name(name).map(|f| (f, value.get().as_str()))
                })
                .collect()
        }

        /// Whether this keepass version can save `db` without losing data
        /// (see [`SaveSupport`]). Decided by the file's format version alone:
        /// what this keepass read of a newer format is already gone.
        pub fn save_support(db: &::$kp::Database) -> SaveSupport {
            save_support_for(format_version(&db.config.version))
        }

        fn format_version(version: &DatabaseVersion) -> FormatVersion {
            match *version {
                DatabaseVersion::KDB(minor) => FormatVersion::new(1, minor),
                DatabaseVersion::KDB2(minor) => FormatVersion::new(2, minor),
                DatabaseVersion::KDB3(minor) => FormatVersion::new(3, minor),
                DatabaseVersion::KDB4(minor) => FormatVersion::new(4, minor),
            }
        }

        /// The outer header's security configuration, without capturing the
        /// rest: what `DeriveParams::for_header` needs before a fingerprint
        /// key (and so a capture) exists.
        pub fn header(db: &::$kp::Database) -> HeaderInfo {
            let config = &db.config;
            use ::$kp::config::{
                CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig,
            };
            let argon2 = |variant, memory: u64, iterations: u64, parallelism: u32, version: u32| {
                KdfInfo::Argon2(Argon2Info::new(
                    variant,
                    memory,
                    iterations,
                    parallelism,
                    version,
                ))
            };
            // keepass marks these enums #[non_exhaustive]; a variant it adds
            // later is reported as Unrecognized until the adapter learns it.
            let kdf = match &config.kdf_config {
                KdfConfig::Aes { rounds } => KdfInfo::Aes { rounds: *rounds },
                KdfConfig::Argon2 {
                    iterations,
                    memory,
                    parallelism,
                    version,
                } => argon2(
                    Argon2Variant::Argon2d,
                    *memory,
                    *iterations,
                    *parallelism,
                    version.as_u32(),
                ),
                KdfConfig::Argon2id {
                    iterations,
                    memory,
                    parallelism,
                    version,
                } => argon2(
                    Argon2Variant::Argon2id,
                    *memory,
                    *iterations,
                    *parallelism,
                    version.as_u32(),
                ),
                _ => KdfInfo::Unrecognized,
            };
            let outer = match config.outer_cipher_config {
                OuterCipherConfig::AES256 => OuterCipher::Aes256,
                OuterCipherConfig::Twofish => OuterCipher::Twofish,
                OuterCipherConfig::ChaCha20 => OuterCipher::ChaCha20,
                _ => OuterCipher::Unrecognized,
            };
            let inner = match config.inner_cipher_config {
                InnerCipherConfig::Plain => InnerCipher::Plain,
                InnerCipherConfig::Salsa20 => InnerCipher::Salsa20,
                InnerCipherConfig::ChaCha20 => InnerCipher::ChaCha20,
                _ => InnerCipher::Unrecognized,
            };
            let compression = match config.compression_config {
                CompressionConfig::None => Compression::None,
                CompressionConfig::GZip => Compression::GZip,
                _ => Compression::Unrecognized,
            };
            let mut header = HeaderInfo::new(kdf, outer, inner, compression);
            header.public_custom_data = public_custom_data_keys(config);
            header
        }

        fn meta(db: &::$kp::Database, sealing: &Sealing<'_>) -> Meta {
            let m = &db.meta;
            let mut out = Meta::default();
            out.generator = m.generator.clone();
            out.database_name = m.database_name.clone();
            out.database_name_changed = m.database_name_changed.as_ref().and_then(timestamp);
            out.database_description = m.database_description.clone();
            out.database_description_changed =
                m.database_description_changed.as_ref().and_then(timestamp);
            out.default_username = m.default_username.clone();
            out.default_username_changed = m.default_username_changed.as_ref().and_then(timestamp);
            out.maintenance_history_days = m.maintenance_history_days.map(to_u64);
            out.color = m.color.as_ref().map(rgb);
            out.master_key_changed = m.master_key_changed.as_ref().and_then(timestamp);
            out.master_key_change_rec = m.master_key_change_rec.map(to_i64);
            out.master_key_change_force = m.master_key_change_force.map(to_i64);
            out.memory_protection = m.memory_protection.as_ref().map(|p| {
                let mut mp = MemoryProtection::default();
                mp.title = p.protect_title;
                mp.user_name = p.protect_username;
                mp.password = p.protect_password;
                mp.url = p.protect_url;
                mp.notes = p.protect_notes;
                mp
            });
            out.recycle_bin_enabled = m.recyclebin_enabled;
            out.recycle_bin = m.recyclebin_uuid;
            out.recycle_bin_changed = m.recyclebin_changed.as_ref().and_then(timestamp);
            out.entry_templates_group = m.entry_templates_group;
            out.entry_templates_group_changed =
                m.entry_templates_group_changed.as_ref().and_then(timestamp);
            out.last_selected_group = m.last_selected_group;
            out.last_top_visible_group = m.last_top_visible_group;
            out.history_max_items = m.history_max_items.map(to_i64);
            out.history_max_size = m.history_max_size.map(to_i64);
            out.settings_changed = m.settings_changed.as_ref().and_then(timestamp);
            out.custom_data = custom_data(&m.custom_data, sealing);
            out.custom_icons = db
                .iter_all_custom_icons()
                .map(|icon| {
                    let (name, modified) = custom_icon_meta(&icon);
                    (
                        icon.id().uuid(),
                        sealing.custom_icon(&icon.data, name, modified),
                    )
                })
                .collect();
            out
        }

        fn group(g: GroupRef<'_>, sealing: &Sealing<'_>) -> Group {
            let mut out = Group::new(g.id().uuid(), g.name.clone());
            out.notes = g.notes.clone();
            out.tags = group_tags(&g);
            out.icon = g.icon().map(icon);
            out.times = times(&g.times);
            out.custom_data = custom_data(&g.custom_data, sealing);
            let mut flags = GroupFlags::default();
            flags.is_expanded = g.is_expanded;
            flags.enable_autotype = g.enable_autotype;
            flags.enable_searching = g.enable_searching;
            flags.default_autotype_sequence = g.default_autotype_sequence.clone();
            out.flags = flags;
            out.previous_parent = group_previous_parent(&g);
            out.groups = child_groups(&g)
                .into_iter()
                .map(|c| group(c, sealing))
                .collect();
            out.entries = child_entries(&g)
                .iter()
                .map(|e| entry(e, sealing, true))
                .collect();
            out
        }

        fn entry(e: &EntryRef<'_>, sealing: &Sealing<'_>, with_history: bool) -> Entry {
            let mut out = Entry::new(e.id().uuid());
            out.fields = e
                .fields
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        sealing.field(name, value.is_protected(), value.get()),
                    )
                })
                .collect();
            out.tags = tag_set(&e.tags);
            out.attachments = e
                .attachments_named()
                .map(|(name, att)| {
                    (
                        name.to_owned(),
                        sealing.attachment(att.data.get(), att.data.is_protected()),
                    )
                })
                .collect();
            out.times = times(&e.times);
            out.icon = e.icon().map(icon);
            out.foreground = e.foreground_color.as_ref().map(rgb);
            out.background = e.background_color.as_ref().map(rgb);
            out.override_url = e.override_url.clone();
            out.quality_check = quality_check(e);
            out.autotype = e.autotype.as_ref().map(|a| {
                let mut at = AutoType::default();
                at.enabled = a.enabled;
                at.default_sequence = a.default_sequence.clone();
                at.obfuscation = obfuscation(a);
                at.associations = a
                    .associations
                    .iter()
                    .map(|assoc| {
                        AutoTypeAssociation::new(assoc.window.clone(), assoc.sequence.clone())
                    })
                    .collect();
                at
            });
            out.custom_data = custom_data(&e.custom_data, sealing);
            out.previous_parent = entry_previous_parent(e);
            if with_history {
                let len = e.history.as_ref().map_or(0, |h| h.get_entries().len());
                out.history = (0..len)
                    .filter_map(|i| e.historical(i))
                    .map(|h| entry(&h, sealing, false))
                    .collect();
            }
            out
        }

        fn custom_data(
            items: &std::collections::HashMap<String, CustomDataItem>,
            sealing: &Sealing<'_>,
        ) -> BTreeMap<String, CustomValue> {
            items
                .iter()
                .map(|(key, item)| {
                    let modified = item.last_modification_time.as_ref().and_then(timestamp);
                    let value = match &item.value {
                        Some(CustomDataValue::String(s)) => sealing.custom_text(s, modified),
                        Some(CustomDataValue::Binary(b)) => sealing.custom_binary(b, modified),
                        // An item with no value element reads as an empty string.
                        None => sealing.custom_text("", modified),
                    };
                    (key.clone(), value)
                })
                .collect()
        }

        /// keepass's tag strings as a model tag set. keepass 0.12 splits
        /// `<Tags>` on `,` only (KeePass writes `;`), so every string is
        /// re-split with the KDBX tag-list grammar; for keepass 0.15 this is a
        /// no-op.
        fn tag_set(tags: &[String]) -> BTreeSet<String> {
            tags.iter()
                .flat_map(|t| $crate::model::parse_tags(t))
                .collect()
        }

        fn times(t: &KpTimes) -> Times {
            let mut out = Times::default();
            out.creation = t.creation.as_ref().and_then(timestamp);
            out.last_modification = t.last_modification.as_ref().and_then(timestamp);
            out.last_access = t.last_access.as_ref().and_then(timestamp);
            out.expiry = t.expiry.as_ref().and_then(timestamp);
            out.location_changed = t.location_changed.as_ref().and_then(timestamp);
            out.expires = t.expires;
            out.usage_count = t.usage_count.map(to_u64);
            out
        }

        fn icon(i: &KpIcon) -> Icon {
            match i {
                // KDBX stores icon indices as 32-bit integers.
                KpIcon::BuiltIn(n) => Icon::Standard(u32::try_from(*n).unwrap_or(u32::MAX)),
                KpIcon::Custom(id) => Icon::Custom(id.uuid()),
            }
        }

        fn rgb(c: &Color) -> Rgb {
            Rgb {
                r: c.r,
                g: c.g,
                b: c.b,
            }
        }

        fn timestamp(t: &chrono::NaiveDateTime) -> Option<Timestamp> {
            Timestamp::from_unix(t.and_utc().timestamp())
        }

        fn to_u64(n: usize) -> u64 {
            u64::try_from(n).unwrap_or(u64::MAX)
        }

        fn to_i64(n: isize) -> i64 {
            i64::try_from(n).unwrap_or(if n < 0 { i64::MIN } else { i64::MAX })
        }
    };
}

/// Capture from keepass 0.12 (`keepass-0_12` feature).
#[cfg(feature = "keepass-0_12")]
pub mod keepass_0_12 {
    keepass_adapter!(keepass_0_12);

    // Per-version shims.

    /// keepass 0.12 keeps children in a randomized hash set, so document
    /// order is lost; sort by UUID for a deterministic snapshot.
    fn child_groups<'a>(g: &'a GroupRef<'a>) -> Vec<GroupRef<'a>> {
        let mut out: Vec<_> = g.groups().collect();
        out.sort_by_key(|c| c.id().uuid());
        out
    }

    fn child_entries<'a>(g: &'a GroupRef<'a>) -> Vec<EntryRef<'a>> {
        let mut out: Vec<_> = g.entries().collect();
        out.sort_by_key(|e| e.id().uuid());
        out
    }

    fn group_tags(_: &GroupRef<'_>) -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// keepass 0.12 writes KDBX 4 with the 4.0 element set: a 4.0 file
    /// round-trips, and a 4.1 file loses its entry-level 4.1 data (previous
    /// parent, QualityCheck, custom icon name and time), which it reads
    /// without keeping. A later minor is unknown, so not claimed.
    fn save_support_for(format: FormatVersion) -> SaveSupport {
        match format {
            FormatVersion::KDBX_4_0 => SaveSupport::Lossless,
            FormatVersion::KDBX_4_1 => SaveSupport::Lossy { format },
            _ => SaveSupport::Unsupported { format },
        }
    }

    fn group_previous_parent(_: &GroupRef<'_>) -> Option<Uuid> {
        None
    }

    fn entry_previous_parent(_: &EntryRef<'_>) -> Option<Uuid> {
        None
    }

    /// An absent `QualityCheck` means on (the KDBX default).
    fn quality_check(e: &EntryRef<'_>) -> bool {
        e.quality_check.unwrap_or(true)
    }

    fn obfuscation(a: &::keepass_0_12::db::AutoType) -> crate::model::AutoTypeObfuscation {
        match a.data_transfer_obfuscation {
            Some(true) => crate::model::AutoTypeObfuscation::UseClipboard,
            Some(false) | None => crate::model::AutoTypeObfuscation::None,
        }
    }

    fn custom_icon_meta(
        _: &::keepass_0_12::db::CustomIconRef<'_>,
    ) -> (Option<String>, Option<Timestamp>) {
        (None, None)
    }

    fn public_custom_data_keys(
        config: &::keepass_0_12::config::DatabaseConfig,
    ) -> BTreeSet<String> {
        config
            .public_custom_data
            .as_ref()
            .map(|d| d.data.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Capture from keepass 0.15 (`keepass-0_15` feature).
#[cfg(feature = "keepass-0_15")]
pub mod keepass_0_15 {
    keepass_adapter!(keepass_0_15);

    // Per-version shims.

    fn child_groups<'a>(g: &'a GroupRef<'a>) -> Vec<GroupRef<'a>> {
        g.groups().collect()
    }

    fn child_entries<'a>(g: &'a GroupRef<'a>) -> Vec<EntryRef<'a>> {
        g.entries().collect()
    }

    fn group_tags(g: &GroupRef<'_>) -> BTreeSet<String> {
        tag_set(&g.tags)
    }

    /// keepass 0.15 writes KDBX 4.1 only: a 4.1 file round-trips, and it
    /// refuses to save anything else (4.0 included, upstream #373).
    fn save_support_for(format: FormatVersion) -> SaveSupport {
        match format {
            FormatVersion::KDBX_4_1 => SaveSupport::Lossless,
            _ => SaveSupport::Unsupported { format },
        }
    }

    fn group_previous_parent(g: &GroupRef<'_>) -> Option<Uuid> {
        g.previous_parent().map(|p| p.id().uuid())
    }

    fn entry_previous_parent(e: &EntryRef<'_>) -> Option<Uuid> {
        e.previous_parent().map(|p| p.id().uuid())
    }

    fn quality_check(e: &EntryRef<'_>) -> bool {
        e.quality_check
    }

    fn obfuscation(a: &::keepass_0_15::db::AutoType) -> crate::model::AutoTypeObfuscation {
        use ::keepass_0_15::db::DataTransferObfuscation;
        match a.data_transfer_obfuscation {
            DataTransferObfuscation::UseClipboard => {
                crate::model::AutoTypeObfuscation::UseClipboard
            }
            DataTransferObfuscation::None => crate::model::AutoTypeObfuscation::None,
        }
    }

    fn custom_icon_meta(
        icon: &::keepass_0_15::db::CustomIconRef<'_>,
    ) -> (Option<String>, Option<Timestamp>) {
        (
            icon.name.clone(),
            icon.last_modification_time.as_ref().and_then(timestamp),
        )
    }

    fn public_custom_data_keys(
        config: &::keepass_0_15::config::DatabaseConfig,
    ) -> BTreeSet<String> {
        config
            .public_custom_data
            .as_ref()
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default()
    }
}
