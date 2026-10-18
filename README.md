# kdbx-core

The shared vault model and rules of the `*-kdbx` ecosystem: one small, stable
crate that every member (diff-kdbx, mcp-kdbx, web-kdbx) depends on instead of
carrying its own copy of the path grammar, the visibility rule, the field
schema, the fingerprint scheme, the text escaping and TOTP.

It depends on no keepass version by default. Snapshot capture from a
`keepass::Database` lives behind additive features, one per keepass version, so
a keepass bump is a new feature, not a breaking release of anything.

## Layering

```text
keepass 0.12 ─┐                       (optional, additive features)
keepass 0.15 ─┴─> kdbx-core::capture ─┐
                                      v
              kdbx-core (no keepass by default)
                model · fields · visibility · path · fingerprint · text · otp
                                      ^
             ┌────────────────────────┼─────────────────────┐
         diff-kdbx (lib: pure)    mcp-kdbx               web-kdbx
         diff-kdbx (cli: keepass-0_15)
```

## Features

| Feature | Default | What it adds |
|---|---|---|
| `kdf` | yes | `FingerprintKey::derive`: an Argon2id-derived, process-stable fingerprint key (pulls in `argon2`) |
| `keepass-0_12` | no | `capture::keepass_0_12`: capture a snapshot from a keepass 0.12 `Database` |
| `keepass-0_15` | no | `capture::keepass_0_15`: capture a snapshot from a keepass 0.15 `Database` |

Enabling both keepass features is legal; Cargo builds both versions.

The library performs no I/O, reads no clock, and builds for
`wasm32-unknown-unknown` with and without `kdf`.

## Modules

| Module | What it owns |
|---|---|
| `model` | `Snapshot`: an owned, serializable, keepass-free image of a database, sealed at capture (`Sealing::Fingerprint` or `Sealing::Reveal`) |
| `fields` | `StandardField`: the five KDBX standard fields and their traits |
| `visibility` | `metadata_value`: the one rule for which values may leave the vault (protected values hidden, the Title always visible) |
| `path` | `VaultPath`: the one path grammar (`/Group/Entry:2`, `/Group/`), parse, format, resolve, `path_of` |
| `fingerprint` | `FingerprintKey`, `Fingerprint`: keyed HMAC-SHA256 fingerprints; Argon2id-derived stable keys (`kdf`) |
| `text` | `escape_inline`, `continuation_lines`: rendering that no value can break out of |
| `otp` | `resolve`, `TotpConfig::code_at`: TOTP from otpauth URIs, KeePass 2 `TimeOtp-*` fields, or the legacy pair |
| `capture` | `keepass_0_12::capture`, `keepass_0_15::capture`, `otp_fields` |

## Example

```rust
use kdbx_core::capture::keepass_0_15::{capture, header};
use kdbx_core::fingerprint::{DeriveParams, FingerprintKey, KeyMaterial};
use kdbx_core::model::Sealing;
use kdbx_core::path::path_of;
use kdbx_core::visibility::metadata_value;

let db: keepass_0_15::Database = open_somehow();

// A key stable across processes (feature `kdf`), salted with the root UUID,
// never cheaper to attack than the vault's own KDF. Record `params` next to
// any fingerprint you publish: a verifier needs them.
let params = DeriveParams::for_header(Some(&header(&db)));
let key = FingerprintKey::derive(
    &KeyMaterial::new(Some(b"master password"), None),
    db.root().id().uuid(),
    &params,
)?;
let snap = capture(&db, &Sealing::Fingerprint(&key));

for entry in snap.entries() {
    let path = path_of(&snap, entry.uuid).map(|p| p.format());
    let user = metadata_value(entry, "UserName"); // None when protected
    println!("{path:?} {user:?}");
}
```

Protected values never enter `snap` in plaintext: they are fingerprints, and
`Debug`, serde and every view built on the snapshot can only show those.

## Testing

`tests/corpus/` is a frozen, checksummed conformance corpus (KeePassXC and
keepass-rs fixtures plus generated vaults) described by `manifest.json` and
`MANIFEST.md`. Run every gate with:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
cargo build --target wasm32-unknown-unknown --no-default-features
cargo build --target wasm32-unknown-unknown --no-default-features --features kdf
```

## License

MIT. See [LICENSE](LICENSE).
