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

## License

MIT. See [LICENSE](LICENSE).
