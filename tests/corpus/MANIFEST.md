# kdbx-core conformance corpus

Frozen KDBX files that every `*-kdbx` member can test against. The files are
bytes only: never edit them in place. `manifest.json` is the structured record
the tests read (`tests/corpus.rs` verifies every checksum, that this directory
holds exactly the listed files, and that this document mentions every file and
its current checksum); this document is its human-readable twin.

The `keepass-rs_*` files are MIT-licensed by their authors; the license text
with its copyright notice is `LICENSE-keepass-rs`, which ships with them.

All passwords here are published test credentials. Never put anything
resembling real data in a corpus file.

## Regenerating the generated vaults

`kdbx-core_corpus_v41.kdbx` and `kdbx-core_corpus_v40.kdbx` come from
`cargo run --example gen_corpus` (see `examples/gen_corpus.rs`). Content is
reproducible (fixed UUIDs and timestamps), but KDBX draws fresh seeds and IVs
on every save, so regenerating changes both checksums: update them in
`manifest.json` and below in the same commit.

The other files are copies or were built once with KeePassXC, and are never
regenerated.

## Known keepass limitations the corpus pins

- keepass 0.12 cannot parse `keepass-rs_test_db_kdbx3_with_attachments.kdbx`
  (an empty attachment: "missing field `$value`"); keepass 0.15 can.
- keepass 0.12 drops a field whose value is empty (the empty Title in
  `keepass-rs_test_db_kdbx4_with_password_deleted_entry.kdbx`); keepass 0.15
  keeps it.
- keepass 0.12 loses child document order; the kdbx-core adapter sorts
  children by UUID.
- keepass 0.12 reads `<DeletionTime>` as absent, so a vault it saves keeps
  deletion records without a time, which KeePassXC discards
  (`keepassxc_v40_save_losses.kdbx`).

## Files

### `keepass-rs_test_db_kdbx41_features.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.1 |
| Key | password `demopass` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | KDBX 4.1 written by a real KeePassXC build |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; file last changed upstream in 9b8e2cf (#317). Written by KeePassXC 2.7.12. |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `b3c9b3f3df36f71421e4075f038d1cf7d72f14fdbb5abf10a0a4b5308c93adb9` |

### `keepass-rs_test_db_kdbx4_with_password_argon2.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `demopass` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | KDBX 4.0, Argon2d KDF |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; last changed in 9b8e2cf (#317). |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `4c8c11173f1f5894d6ba606e2f58da07b50a66d79486bac2daa1f23b7e3ca3cf` |

### `keepass-rs_test_db_kdbx4_with_totp_entry.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `test` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | otpauth URI in the otp field |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; last changed in 0aface3 (#84). |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `01de128cb6c2257b7f308e3be17ce96b5e203a3e6ca105df28026b39508e70c5` |

### `keepass-rs_test_db_kdbx4_with_keyfile_v2.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `demopass` + key file `keepass-rs_test_db_kdbx4_with_keyfile_v2.keyx` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | password plus a version 2 XML key file |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; last changed in 9b8e2cf (#317). |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `b2c36cb02ac0c785ce20d24cafc7d28b14e62d83d82b07f57627779e3b46581a` |

### `keepass-rs_test_db_kdbx4_with_keyfile_v2.keyx`

| | |
|---|---|
| Kind | keyfile |
| KDBX version | n/a |
| Key | n/a |
| Readable by | n/a |
| Exercises | key file of keepass-rs_test_db_kdbx4_with_keyfile_v2.kdbx |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; last changed in b50d395 (#213). |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `1f03ba4f0f36aea54774240844cbc7f74f23e145220054aa65e6ef8a6c928bb1` |

### `keepass-rs_test_db_kdbx3_with_attachments.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 3.1 |
| Key | password `demopass` |
| Readable by | keepass-0_15 |
| Exercises | KDBX 3.1; attachments, including an empty one |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; last changed in 28c078c (#384). |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `014421cf9f49a951670b70f03002c279c85567a1a4fcc201cc387eb4b8c1d57c` |

### `keepass-rs_test_db_kdbx4_with_password_deleted_entry.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `demopass` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | an entry moved to the recycle bin; an entry with an empty Title |
| Origin | Copied unmodified from tests/resources/ of keepass-rs (https://github.com/sseemayer/keepass-rs), MIT, via the queelius/keepass-rs fork at commit 9fda3c5; last changed in 9b8e2cf (#317). |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` |
| SHA-256 | `cdf0ddb068961b5fef7f17db5c1ef313fb2baeda166b13a11a7ba1de1b2f7f80` |

### `diff-kdbx_legacy_kdbx40.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `test-password-do-not-use` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | KDBX 4.0 written by keepass 0.12; unnamed root group; random UUIDs |
| Origin | Copied unmodified from diff-kdbx tests/fixtures/legacy_kdbx40/vault.kdbx (commit 948429c): written by keepass 0.12, frozen. |
| License | MIT (diff-kdbx) |
| SHA-256 | `f9b801354d91ceead955485edf1e4df8c5daac4d8f22e7654e2150f9d10ab816` |

### `kdbx-core_corpus_v41.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.1 |
| Key | password `kdbx-core-corpus-do-not-use` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | protected Title, UserName, URL and Notes; otpauth URI; legacy TOTP Seed and TOTP Settings; KeePass 2 TimeOtp-* fields; duplicate titles; untitled entry; 12 history items |
| Origin | Generated by examples/gen_corpus.rs with keepass 0.15 and fixed UUIDs. |
| License | MIT (kdbx-core) |
| SHA-256 | `6d4ef0be897039452de2b9c583dc676f04566786bff69197c4a0d9bf0827214a` |

### `kdbx-core_corpus_v40.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `kdbx-core-corpus-do-not-use` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | the v41 corpus vault as KDBX 4.0 |
| Origin | Generated by examples/gen_corpus.rs: kdbx-core_corpus_v41.kdbx re-saved by keepass 0.12 (same records and UUIDs). |
| License | MIT (kdbx-core) |
| SHA-256 | `5af9f50d2ea232078d056c10ae289bcb39f3a42637cc77944536dc33e4888e6a` |

### `keepassxc_v40_save_losses.kdbx`

| | |
|---|---|
| Kind | vault |
| KDBX version | 4.0 |
| Key | password `demopass` |
| Readable by | keepass-0_12, keepass-0_15 |
| Exercises | a deletion record (DeletedObject with a DeletionTime); a group whose entries are not in UUID order; an empty custom field |
| Origin | Written by KeePassXC 2.7.9 (keepassxc-cli) from keepass-rs_test_db_kdbx4_with_password_argon2.kdbx: added group Work with entries zeta, alpha, mid and doomed, deleted doomed and emptied the recycle bin, then merged in an entry whose Placeholder field is empty (from a KeePassXC XML import). Built 2026-10-24 to measure what keepass 0.12 loses on save. |
| License | MIT, Copyright (c) 2019 Stefan Seemayer (keepass-rs); full text in `LICENSE-keepass-rs` (derived from a keepass-rs test file) |
| SHA-256 | `2a046ca74fe6d933dfdf484d4e17e3827071063ad71fae2a83d69bc0bca265cb` |

### `LICENSE-keepass-rs`

| | |
|---|---|
| Kind | license |
| Covers | every `keepass-rs_*` file above |
| Origin | Copied unmodified from the LICENSE file of keepass-rs (queelius/keepass-rs fork at commit 9fda3c5) |
| SHA-256 | `4c1db422db5330e34880d573f18435f8893ec1e35b5172051919b7f693fb96b5` |
