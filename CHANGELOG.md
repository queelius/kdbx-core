# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-24

### Changed (breaking)

- `SaveSupport::Lossy` now carries `losses: BTreeSet<SaveLoss>`, what saving
  that vault would lose, and `SaveSupport` is no longer `Copy`
  (`is_lossless` takes `&self`). keepass 0.12's verdicts were wrong in 0.1.1:
  it reported KDBX 4.0 as lossless, but saving any vault drops empty-valued
  fields, saving one with deletion records loses them (KeePassXC then sees
  none, so a merge can bring deleted entries back), and saving one whose
  groups hold two subgroups or two entries loses their order. All measured
  against KeePassXC 2.7.9; keepass 0.15 keeps all three.

### Added

- `model::SaveLoss` (`DeletionRecords`, `ChildOrder`, `EmptyFields`,
  `Kdbx41EntryData`) with `ALL`, `is_cosmetic` and `description`.
- `SaveSupport::allows_save` (the ecosystem's save rule: every loss
  cosmetic), `losses()` and `with_losses`. `SaveSupport` and `SaveLoss` now
  serialize (pinned in the serde contract).
- Corpus vault `keepassxc_v40_save_losses.kdbx` (written by KeePassXC), and
  corpus tests that save every savable vault with each keepass version and
  check the read-back loses only what `save_support` reported.

## [0.1.1] - 2026-10-21

### Added

- `model::SaveSupport` (`Lossless`, `Lossy { format }`, `Unsupported { format }`)
  and `save_support(&Database)` in both keepass adapters: whether that keepass
  version can save a database without losing data. keepass 0.12 saves KDBX 4.0
  losslessly and 4.1 lossily (it reads a 4.1 file's entry-level 4.1 data, the
  previous parent, QualityCheck and custom icon name and time, without keeping
  it); keepass 0.15 saves 4.1 only. Writers share this one rule, and it changes
  with the adapter feature they build against. Tests check it against what
  keepass's own save accepts.

## [0.1.0] - 2026-10-19

### Added

- `model`: the keepass-free `Snapshot` (format version, meta, group tree,
  entries with history, attachments and custom data as fingerprints,
  deleted-object tombstones) with serde derives (shape unstable before 1.0),
  constructors, `walk`/`find`/`parent_of`, and `Sealing`, which decides at
  capture time what plaintext a snapshot may hold.
- `fields`: `StandardField`, `FieldTraits`, `traits_of`.
- `visibility`: `metadata_value`, `is_visible`, `is_address` (the Title rule).
- `path`: the ecosystem `VaultPath` grammar (ported from mcp-kdbx) with typed
  `PathError`/`ResolveError`, resolution against a snapshot, and `path_of`.
  Group paths format with a trailing `/`, so `parse(format(p)) == p`.
- `fingerprint`: keyed HMAC-SHA256 `Fingerprint`s under a `FingerprintKey`
  (domains for fields, attachments, custom data and custom icons), and
  `FingerprintKey::derive` (Argon2id; feature `kdf`, on by default).
- `text`: `escape_inline`, `unescape_inline`, `continuation_lines`,
  `needs_escape`.
- `otp`: TOTP from otpauth URIs, KeePass 2 `TimeOtp-*` fields and the legacy
  `TOTP Seed`/`TOTP Settings` pair (ported from mcp-kdbx); no clock access.
- `capture`: `keepass_0_12` and `keepass_0_15` adapters (features
  `keepass-0_12`, `keepass-0_15`) with `capture` and `otp_fields`.
- A frozen, checksummed conformance corpus under `tests/corpus/` and its
  generator, `examples/gen_corpus.rs`, shipped with the keepass-rs license.
- `model::HeaderInfo` (KDF, ciphers, compression) captured into
  `Snapshot::header`; `capture::*::header`.
- `fingerprint::DeriveParams`: derivation parameters never below the vault's
  own Argon2 parameters nor a 64 MiB / 3 / 1 floor.
- `visibility::is_secret`, the one predicate behind sealing and visibility
  (an unprotected Password is still a secret).
- `path::PathIndex` for computing every path in one pass.
- Steam Guard TOTP codes and typed `OtpError::Malformed` errors, with
  human-readable Display and serde for `OtpError`, `OtpSource` and
  `MalformedReason`.
- serde for `FieldTraits`.

### Changed

- Serialized names are pinned as a contract (`src/serde_contract.rs`);
  `chacha20` and `gzip` replace the mechanical `cha_cha20` and `g_zip`.
- `DeriveParams` compares whole Argon2 cost (memory x passes) against the
  floor instead of taking a per-component maximum; `DeriveParams::cost` and
  `DeriveParams::stronger` added.

- Smaller WASM: a compact Cc/Cf/Zl/Zp table replaces the
  `unicode-properties` lookup, and built-in hex/base32/base64 decoders replace
  `data-encoding` (both now dev-dependencies only).
