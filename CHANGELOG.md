# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

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
- Steam Guard TOTP codes and typed `OtpError::Malformed` errors.
