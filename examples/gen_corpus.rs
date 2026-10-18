//! Generates the kdbx-core corpus vaults under `tests/corpus/`.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example gen_corpus
//! ```
//!
//! Writes `kdbx-core_corpus_v41.kdbx` (keepass 0.15, KDBX 4.1) and
//! `kdbx-core_corpus_v40.kdbx` (the same vault re-saved by keepass 0.12,
//! which writes KDBX 4.0). keepass 0.12 cannot pin UUIDs, so the vault is
//! built once with keepass 0.15 and fixed UUIDs, and keepass 0.12 only
//! re-encodes it; both files hold the same records with the same UUIDs.
//!
//! Content is reproducible (fixed UUIDs and timestamps); the encrypted bytes
//! are not (KDBX draws fresh seeds and IVs on every save), so regenerating
//! always changes the checksums in `tests/corpus/manifest.json` and
//! `MANIFEST.md`, which must then be updated. Master password:
//! `kdbx-core-corpus-do-not-use`.

use std::fs;
use std::path::Path;

use keepass_0_15 as kp;
use kp::db::{EntryId, GroupId};
use uuid::Uuid;

const PASSWORD: &str = "kdbx-core-corpus-do-not-use";
const OUT_DIR: &str = "tests/corpus";

/// Fixed identities `0000000n-c0de-4000-8000-000000000000`.
const fn id(n: u128) -> Uuid {
    Uuid::from_u128((n << 96) | 0x0000_0000_c0de_4000_8000_0000_0000_0000)
}

/// 2026-01-01T09:00:00Z.
const T0: i64 = 1_767_258_000;

fn at(secs: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(secs, 0)
        .expect("in range")
        .naive_utc()
}

fn fixed_times(secs: i64) -> kp::db::Times {
    let mut t = kp::db::Times::default();
    t.creation = Some(at(secs));
    t.last_modification = Some(at(secs));
    t.last_access = Some(at(secs));
    t.expiry = Some(at(secs));
    t.location_changed = Some(at(secs));
    t.expires = Some(false);
    t.usage_count = Some(0);
    t
}

/// ```text
/// Corpus (01)
/// ├── Protected (02)
/// │   └── Protected Fields (11)  Title, UserName, Password, URL, Notes all protected
/// ├── OTP (03)
/// │   ├── otpauth (21)           protected otp URI (RFC 6238 SHA-1 secret)
/// │   ├── Legacy TOTP (22)       protected TOTP Seed + TOTP Settings "30;6"
/// │   └── KeePass native (23)    TimeOtp-Secret (protected), Length 8, HMAC-SHA-256
/// ├── Duplicates (04)
/// │   ├── Twin (32)              listed first, larger UUID: path /Duplicates/Twin:2
/// │   ├── Twin (31)              path /Duplicates/Twin:1
/// │   └── (untitled) (33)        no path
/// └── History (05)
///     └── Rotated (41)           12 history items, passwords rotation-01..rotation-12
/// ```
fn build() -> kp::Database {
    let mut db = kp::Database::new_with_root_id(GroupId::from_uuid(id(0x01)));
    db.config.kdf_config = kp::config::KdfConfig::Aes { rounds: 64 };
    db.meta.database_name = Some("kdbx-core corpus".into());
    db.root_mut().name = "Corpus".into();
    for (n, name) in [
        (0x02, "Protected"),
        (0x03, "OTP"),
        (0x04, "Duplicates"),
        (0x05, "History"),
    ] {
        db.root_mut()
            .add_group_with_id(GroupId::from_uuid(id(n)))
            .expect("fresh id")
            .name = name.into();
    }

    let mut add = |group: u128, entry: u128, fields: &[(&str, &str, bool)]| {
        let mut g = db.group_mut(GroupId::from_uuid(id(group))).expect("group");
        let mut e = g
            .add_entry_with_id(EntryId::from_uuid(id(entry)))
            .expect("fresh id");
        for (name, value, protected) in fields {
            if *protected {
                e.set_protected(*name, *value);
            } else {
                e.set_unprotected(*name, *value);
            }
        }
    };
    add(
        0x02,
        0x11,
        &[
            ("Title", "Protected Fields", true),
            ("UserName", "protected-user", true),
            ("Password", "protected-password", true),
            ("URL", "https://protected.example", true),
            ("Notes", "protected\nnotes", true),
        ],
    );
    add(
        0x03,
        0x21,
        &[
            ("Title", "otpauth", false),
            (
                "otp",
                "otpauth://totp/corpus?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                true,
            ),
        ],
    );
    add(
        0x03,
        0x22,
        &[
            ("Title", "Legacy TOTP", false),
            ("TOTP Seed", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", true),
            ("TOTP Settings", "30;6", false),
        ],
    );
    add(
        0x03,
        0x23,
        &[
            ("Title", "KeePass native", false),
            ("TimeOtp-Secret", "12345678901234567890123456789012", true),
            ("TimeOtp-Length", "8", false),
            ("TimeOtp-Algorithm", "HMAC-SHA-256", false),
        ],
    );
    add(
        0x04,
        0x32,
        &[("Title", "Twin", false), ("UserName", "second", false)],
    );
    add(
        0x04,
        0x31,
        &[("Title", "Twin", false), ("UserName", "first", false)],
    );
    add(
        0x04,
        0x33,
        &[
            ("UserName", "nobody", false),
            ("Password", "untitled-secret", true),
        ],
    );
    add(
        0x05,
        0x41,
        &[
            ("Title", "Rotated", false),
            ("Password", "rotation-13", true),
        ],
    );

    // Twelve earlier versions, oldest first in time.
    for n in 1..=12 {
        let mut old: kp::db::Entry =
            (*db.entry(EntryId::from_uuid(id(0x41))).expect("entry")).clone();
        old.set_protected("Password", format!("rotation-{n:02}"));
        old.times = fixed_times(T0 + n * 3600);
        db.entry_mut(EntryId::from_uuid(id(0x41)))
            .expect("entry")
            .history
            .get_or_insert_default()
            .add_entry(old);
    }

    let groups: Vec<GroupId> = db.iter_all_groups().map(|g| g.id()).collect();
    for g in groups {
        db.group_mut(g).expect("group").times = fixed_times(T0);
    }
    let entries: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
    for e in entries {
        db.entry_mut(e).expect("entry").times = fixed_times(T0 + 13 * 3600);
    }
    db
}

fn main() {
    let out = Path::new(OUT_DIR);
    fs::create_dir_all(out).expect("create output directory");

    let mut v41 = Vec::new();
    build()
        .save(&mut v41, kp::DatabaseKey::new().with_password(PASSWORD))
        .expect("save KDBX 4.1");
    fs::write(out.join("kdbx-core_corpus_v41.kdbx"), &v41).expect("write v41");

    let mut db12 = keepass_0_12::Database::parse(
        &v41,
        keepass_0_12::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("keepass 0.12 reads the 4.1 vault");
    db12.config.version = keepass_0_12::config::DatabaseVersion::KDB4(0);
    let mut v40 = Vec::new();
    db12.save(
        &mut v40,
        keepass_0_12::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("save KDBX 4.0");
    fs::write(out.join("kdbx-core_corpus_v40.kdbx"), &v40).expect("write v40");

    println!("wrote {OUT_DIR}/kdbx-core_corpus_v41.kdbx and kdbx-core_corpus_v40.kdbx");
    println!("update the sha256 values in {OUT_DIR}/manifest.json and MANIFEST.md");
}
