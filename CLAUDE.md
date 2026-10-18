# CLAUDE.md

Orientation for working in `kdbx-core`, the shared crate of the `*-kdbx`
ecosystem (see `~/github/kdbx/CLAUDE.md` and `~/github/kdbx/DESIGN.md`).

## What it is

A keepass-free vault model (`Snapshot`) plus the ecosystem's shared rules:
field schema, visibility, path grammar, keyed fingerprints, line-safe text
escaping, TOTP. keepass adapters are optional additive features
(`keepass-0_12`, `keepass-0_15`).

- Design spec (canonical): `docs/superpowers/specs/2026-10-18-kdbx-core-design.md`
- Implementation plan: `docs/superpowers/plans/2026-10-18-kdbx-core-0.1.md`

## Invariants (do not break)

- Plaintext of a secret value enters a snapshot only under `Sealing::Reveal`.
- One secret predicate, `visibility::is_secret` (protected or a Password,
  never the Title), drives both sealing and visibility.
- Title is an address, never a secret (spec 3.1).
- Fingerprint key derivation never runs below the vault's own Argon2
  parameters nor the 64 MiB / 3 / 1 floor (`DeriveParams`).
- One visibility rule, one path grammar, one escape function: no member
  re-implements them.
- Fingerprints are keyed. Nothing in the crate exposes an unkeyed hash of a
  secret.
- Default features pull in no keepass.
- The library does no I/O and reads no clock; it builds for
  `wasm32-unknown-unknown` with `--no-default-features` and with `kdf`.

## Commands (the gates; run all before every commit)

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
cargo build --target wasm32-unknown-unknown --no-default-features
cargo build --target wasm32-unknown-unknown --no-default-features --features kdf
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

MSRV is 1.89 (keepass 0.15 requires it): `cargo +1.89.0 test --all-features`.

## Tests (as of 0.1.0)

177 with `--all-features`: 132 unit (text, fields, fingerprint incl. 6 `kdf`
tests, model, visibility, path incl. property tests and the PathIndex bulk
test, otp), 8 + 8 capture integration tests (`tests/capture_keepass_0_12.rs`,
`tests/capture_keepass_0_15.rs`, shared fixture in `tests/common/mod.rs`), 18
corpus tests (`tests/corpus.rs`), 11 doc tests. `--no-default-features`: 126
unit, 3 corpus tests (checksums, manifest, license), 11 doc tests.

The corpus (`tests/corpus/`) is bytes only: never edit a file in place.
`manifest.json` is the typed record the tests read; keep `MANIFEST.md` in step
(a test checks it mentions every file and checksum). Regenerate the generated
vaults with `cargo run --example gen_corpus` and update both checksums.

## Known keepass 0.12 limitations (pinned by tests)

It cannot parse KDBX 4.1 group `<Tags>` or `<PreviousParentGroup>`, ignores
`<QualityCheck>` and `<DeletionTime>`, splits `<Tags>` on `,` only (the adapter
re-splits), loses child document order (the adapter sorts by UUID), drops
empty-valued fields, and cannot read the KDBX 3.1 empty-attachment fixture.

## Conventions

- `#[non_exhaustive]` on every public struct and enum that may grow.
- Typed enums and serde derives, never stringly-typed interfaces.
- No em-dash characters anywhere.
- Conventional commits, one per task.
