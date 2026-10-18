//! The frozen, checksummed conformance corpus under `tests/corpus/`.
//!
//! `manifest.json` is the structured record of every file (origin, license,
//! key material, KDBX version, which keepass versions can read it, SHA-256);
//! `MANIFEST.md` is its human-readable twin. The tests here verify the
//! checksums, then open every vault with every enabled keepass adapter and
//! check what each must capture.
// Without a keepass feature only the checksum tests run, and the capture
// helpers they would share go unused.
#![cfg_attr(
    not(any(feature = "keepass-0_12", feature = "keepass-0_15")),
    allow(dead_code, unused_imports)
)]

use std::fs;
use std::path::{Path, PathBuf};

use kdbx_core::fingerprint::{Domain, FingerprintKey};
use kdbx_core::model::{FormatVersion, Sealing, Snapshot, Value};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    files: Vec<CorpusFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CorpusFile {
    file: String,
    kind: Kind,
    kdbx_version: Option<FormatVersion>,
    password: Option<String>,
    keyfile: Option<String>,
    origin: String,
    license: String,
    exercises: Vec<String>,
    sha256: String,
    readers: Vec<Reader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Vault,
    Keyfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum Reader {
    #[serde(rename = "keepass-0_12")]
    Keepass012,
    #[serde(rename = "keepass-0_15")]
    Keepass015,
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn manifest() -> Manifest {
    let raw = fs::read_to_string(corpus_dir().join("manifest.json")).expect("manifest.json");
    serde_json::from_str(&raw).expect("manifest.json parses")
}

fn read(name: &str) -> Vec<u8> {
    fs::read(corpus_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn vaults() -> impl Iterator<Item = CorpusFile> {
    manifest()
        .files
        .into_iter()
        .filter(|f| f.kind == Kind::Vault)
}

fn by_name(name: &str) -> CorpusFile {
    manifest()
        .files
        .into_iter()
        .find(|f| f.file == name)
        .unwrap_or_else(|| panic!("{name} is not in the manifest"))
}

#[test]
fn every_checksum_matches() {
    for f in manifest().files {
        let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(read(&f.file)));
        assert_eq!(digest, f.sha256, "{} changed on disk", f.file);
    }
}

#[test]
fn manifest_lists_exactly_the_corpus_files_and_the_markdown_agrees() {
    let manifest = manifest();
    let mut listed: Vec<&str> = manifest.files.iter().map(|f| f.file.as_str()).collect();
    listed.sort_unstable();
    let mut on_disk: Vec<String> = fs::read_dir(corpus_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n != "manifest.json" && n != "MANIFEST.md")
        .collect();
    on_disk.sort_unstable();
    assert_eq!(listed, on_disk);

    let markdown = fs::read_to_string(corpus_dir().join("MANIFEST.md")).unwrap();
    for f in &manifest.files {
        assert!(
            markdown.contains(&f.file),
            "MANIFEST.md does not mention {}",
            f.file
        );
        assert!(
            markdown.contains(&f.sha256),
            "MANIFEST.md has a stale checksum for {}",
            f.file
        );
        if let Some(keyfile) = &f.keyfile {
            assert!(
                listed.contains(&keyfile.as_str()),
                "{keyfile} is not in the corpus"
            );
        }
        assert_eq!(
            f.kind == Kind::Vault,
            f.kdbx_version.is_some(),
            "{}",
            f.file
        );
        assert_eq!(f.kind == Kind::Vault, f.password.is_some(), "{}", f.file);
    }
}

fn key() -> FingerprintKey {
    FingerprintKey::from_bytes([0xC0; 32])
}

/// Checks every adapter must pass on every vault it can read: the format
/// version matches the manifest, every secret field (`visibility::is_secret`)
/// is sealed to the fingerprint of its revealed plaintext, and no other field
/// is sealed.
fn check_capture(f: &CorpusFile, sealed: &Snapshot, revealed: &Snapshot, key: &FingerprintKey) {
    assert_eq!(Some(sealed.format), f.kdbx_version, "{}", f.file);
    for (s, r) in sealed.entries().zip(revealed.entries()) {
        assert_eq!(s.uuid, r.uuid);
        let items = std::iter::once((s, r)).chain(s.history.iter().zip(&r.history));
        for (s, r) in items {
            for (name, field) in &s.fields {
                let plain = r.fields[name].value.as_plain().expect("revealed");
                match (
                    &field.value,
                    kdbx_core::visibility::is_secret(name, field.protected),
                ) {
                    (Value::Sealed(fp), true) => {
                        assert_eq!(*fp, key.fingerprint(Domain::Field, plain.as_bytes()));
                    }
                    (Value::Plain(p), false) => assert_eq!(p, plain),
                    (value, should_seal) => {
                        panic!(
                            "{}: {name} sealed wrongly ({value:?}, {should_seal})",
                            f.file
                        )
                    }
                }
            }
        }
    }
}

/// The per-adapter checks, generated for each keepass version so both run the
/// same assertions.
macro_rules! adapter_tests {
    ($module:ident, $kp:ident, $feature:literal, $reader:expr, $generated:literal) => {
        #[cfg(feature = $feature)]
        mod $module {
            use super::*;
            use kdbx_core::capture::$kp::{capture, otp_fields};

            pub(super) fn open(f: &CorpusFile) -> Result<::$kp::Database, String> {
                let mut key = ::$kp::DatabaseKey::new();
                if let Some(pw) = &f.password {
                    key = key.with_password(pw);
                }
                if let Some(kf) = &f.keyfile {
                    key = key
                        .with_keyfile(&mut read(kf).as_slice())
                        .map_err(|e| e.to_string())?;
                }
                ::$kp::Database::parse(&read(&f.file), key).map_err(|e| e.to_string())
            }

            pub(super) fn snapshots(f: &CorpusFile) -> (Snapshot, Snapshot) {
                let db = open(f).unwrap_or_else(|e| panic!("{}: {e}", f.file));
                let key = key();
                (
                    capture(&db, &Sealing::Fingerprint(&key)),
                    capture(&db, &Sealing::Reveal(&key)),
                )
            }

            #[test]
            fn every_vault_opens_exactly_when_the_manifest_says_so() {
                for f in vaults() {
                    let readable = f.readers.contains(&$reader);
                    match open(&f) {
                        Ok(db) => {
                            assert!(
                                readable,
                                "{} opened but the manifest says it cannot",
                                f.file
                            );
                            let key = key();
                            let sealed = capture(&db, &Sealing::Fingerprint(&key));
                            let revealed = capture(&db, &Sealing::Reveal(&key));
                            check_capture(&f, &sealed, &revealed, &key);
                        }
                        Err(e) => assert!(!readable, "{}: {e}", f.file),
                    }
                }
            }

            #[test]
            fn generated_corpus_facts() {
                let f = by_name($generated);
                let (sealed, _) = snapshots(&f);
                generated_facts(&sealed);
                // OTP from the live entries, whatever the snapshot sealing.
                let db = open(&f).unwrap();
                let codes: Vec<String> = db
                    .iter_all_entries()
                    .filter_map(|e| {
                        kdbx_core::otp::resolve_fields(&otp_fields(&e)).expect("well-formed OTP")
                    })
                    .map(|c| c.code_at(59).code().to_owned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                assert_eq!(codes, ["287082", "46119246"]);
            }

            #[test]
            fn keepass_rs_totp_entry_resolves() {
                let f = by_name("keepass-rs_test_db_kdbx4_with_totp_entry.kdbx");
                let db = open(&f).unwrap();
                let configs: Vec<_> = db
                    .iter_all_entries()
                    .filter_map(|e| {
                        kdbx_core::otp::resolve_fields(&otp_fields(&e)).expect("well-formed OTP")
                    })
                    .collect();
                assert_eq!(configs.len(), 1);
                assert_eq!(
                    configs[0].code_at(59).code().len(),
                    configs[0].digits() as usize
                );
            }

            #[test]
            fn kdbx3_attachments_are_fingerprinted() {
                let f = by_name("keepass-rs_test_db_kdbx3_with_attachments.kdbx");
                if !f.readers.contains(&$reader) {
                    return; // pinned by every_vault_opens_exactly_when_the_manifest_says_so
                }
                let (sealed, revealed) = snapshots(&f);
                let attachments: usize = sealed.entries().map(|e| e.attachments.len()).sum();
                assert!(attachments > 0);
                // Attachments are fingerprinted under either sealing.
                for (s, r) in sealed.entries().zip(revealed.entries()) {
                    assert_eq!(s.attachments, r.attachments);
                }
            }

            #[test]
            fn deleted_entry_sits_in_the_recycle_bin() {
                let (sealed, _) = snapshots(&by_name(
                    "keepass-rs_test_db_kdbx4_with_password_deleted_entry.kdbx",
                ));
                let bin = sealed.meta.recycle_bin.expect("a recycle bin");
                let bin = sealed
                    .find_group(bin)
                    .expect("the recycle bin group exists");
                assert_eq!(bin.name, "Recycle Bin");
                let titles: Vec<_> = bin.entries.iter().filter_map(|e| e.title()).collect();
                assert_eq!(titles, ["deleted entry"]);
                // The vault also holds an entry whose Title is empty (keepass
                // 0.12 drops the empty field, 0.15 keeps it): no path either way.
                let untitled = sealed
                    .entries()
                    .find(|e| e.title().is_none_or(str::is_empty))
                    .expect("an untitled entry");
                assert!(kdbx_core::path::path_of(&sealed, untitled.uuid).is_none());
            }

            #[test]
            fn header_configuration_is_captured() {
                use kdbx_core::model::{Argon2Variant, InnerCipher, KdfInfo};
                for f in vaults().filter(|f| f.readers.contains(&$reader)) {
                    let (sealed, _) = snapshots(&f);
                    let header = sealed.header.as_ref().expect("captured from a file");
                    match &f.file[..] {
                        "keepass-rs_test_db_kdbx4_with_password_argon2.kdbx" => {
                            let KdfInfo::Argon2(a) = header.kdf else {
                                panic!("{}: {:?}", f.file, header.kdf)
                            };
                            assert_eq!(a.variant, Argon2Variant::Argon2d);
                            assert_eq!(a.version, 0x13);
                        }
                        "keepass-rs_test_db_kdbx3_with_attachments.kdbx" => {
                            assert!(
                                matches!(header.kdf, KdfInfo::Aes { .. }),
                                "{:?}",
                                header.kdf
                            );
                            assert_eq!(header.inner_cipher, InnerCipher::Salsa20);
                        }
                        "kdbx-core_corpus_v40.kdbx" | "kdbx-core_corpus_v41.kdbx" => {
                            assert_eq!(header.kdf, KdfInfo::Aes { rounds: 64 });
                        }
                        _ => {}
                    }
                }
            }

            #[test]
            fn diff_kdbx_legacy_vault() {
                let (sealed, _) = snapshots(&by_name("diff-kdbx_legacy_kdbx40.kdbx"));
                assert_eq!(sealed.root.name, "");
                let entry = sealed.entries().next().expect("one entry");
                assert_eq!(entry.title(), Some("Test Entry"));
                assert!(entry.field("Password").unwrap().value.is_sealed());
                assert_eq!(
                    kdbx_core::path::path_of(&sealed, entry.uuid)
                        .unwrap()
                        .format(),
                    "/Test Entry"
                );
            }
        }
    };
}

// Each adapter checks the generated vault of its own era: keepass 0.12 the
// KDBX 4.0 file, keepass 0.15 the 4.1 file.
adapter_tests!(
    via_keepass_0_12,
    keepass_0_12,
    "keepass-0_12",
    Reader::Keepass012,
    "kdbx-core_corpus_v40.kdbx"
);
adapter_tests!(
    via_keepass_0_15,
    keepass_0_15,
    "keepass-0_15",
    Reader::Keepass015,
    "kdbx-core_corpus_v41.kdbx"
);

fn generated_facts(snap: &Snapshot) {
    use kdbx_core::path::{VaultPath, path_of};
    use kdbx_core::visibility::metadata_value;
    let id = |n: u128| uuid::Uuid::from_u128((n << 96) | 0x0000_0000_c0de_4000_8000_0000_0000_0000);

    let protected = snap.find_entry(id(0x11)).unwrap();
    assert_eq!(protected.title(), Some("Protected Fields"));
    for name in ["UserName", "Password", "URL", "Notes"] {
        assert!(protected.field(name).unwrap().value.is_sealed(), "{name}");
        assert_eq!(metadata_value(protected, name), None, "{name}");
    }
    assert_eq!(metadata_value(protected, "Title"), Some("Protected Fields"));

    let resolve = |p: &str| VaultPath::parse(p).unwrap().resolve(snap).map(|n| n.uuid());
    assert_eq!(resolve("/Duplicates/Twin:1"), Ok(id(0x31)));
    assert_eq!(resolve("/Duplicates/Twin:2"), Ok(id(0x32)));
    assert_eq!(
        path_of(snap, id(0x32)).unwrap().format(),
        "/Duplicates/Twin:2"
    );
    assert!(
        path_of(snap, id(0x33)).is_none(),
        "untitled entry has no path"
    );

    let rotated = snap.find_entry(id(0x41)).unwrap();
    assert_eq!(rotated.history.len(), 12);
    assert!(rotated.history.iter().all(|h| h.history.is_empty()));

    let json = serde_json::to_string(snap).unwrap();
    for secret in [
        "protected-user",
        "protected-password",
        "protected.example",
        "untitled-secret",
        "rotation-01",
        "rotation-13",
        "GEZDGNBVGY3TQOJQ",
        "12345678901234567890123456789012",
    ] {
        assert!(!json.contains(secret), "{secret} leaked");
    }
}

/// The two generated files hold the same records: keepass 0.12 reading the
/// 4.0 file and keepass 0.15 reading the 4.1 file agree on everything but the
/// format version and the writer stamp.
#[cfg(all(feature = "keepass-0_12", feature = "keepass-0_15"))]
#[test]
fn generated_v40_and_v41_capture_alike() {
    let (mut v40, _) = via_keepass_0_12::snapshots(&by_name("kdbx-core_corpus_v40.kdbx"));
    let (v41, _) = via_keepass_0_15::snapshots(&by_name("kdbx-core_corpus_v41.kdbx"));
    assert_eq!(v40.format, FormatVersion::KDBX_4_0);
    assert_eq!(v41.format, FormatVersion::KDBX_4_1);
    v40.format = v41.format;
    v40.meta.generator.clone_from(&v41.meta.generator);
    // keepass 0.12 loses document order (its adapter sorts by UUID).
    assert_eq!(v40, sorted_by_uuid(v41));
}

#[cfg(all(feature = "keepass-0_12", feature = "keepass-0_15"))]
fn sorted_by_uuid(mut snap: Snapshot) -> Snapshot {
    fn sort(g: &mut kdbx_core::model::Group) {
        g.entries.sort_by_key(|e| e.uuid);
        g.groups.sort_by_key(|g| g.uuid);
        g.groups.iter_mut().for_each(sort);
    }
    sort(&mut snap.root);
    snap
}
