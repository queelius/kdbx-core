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

- Plaintext of a protected value enters a snapshot only under `Sealing::Reveal`.
- Title is an address, never a secret (spec 3.1).
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

## Conventions

- `#[non_exhaustive]` on every public struct and enum that may grow.
- Typed enums and serde derives, never stringly-typed interfaces.
- No em-dash characters anywhere.
- Conventional commits, one per task.
