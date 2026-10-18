//! Shared vault model and rules for the `*-kdbx` ecosystem.
//!
//! `kdbx-core` owns the parts every member of the ecosystem (diff-kdbx,
//! mcp-kdbx, web-kdbx) must agree on, so none of them re-implements them:
//!
//! - [`model`]: an owned, serializable, keepass-free [`Snapshot`](model::Snapshot)
//!   of a database. Secrets are sealed at capture time, so nothing downstream
//!   can leak a protected value by mistake.
//! - [`fields`]: the five KDBX standard fields and their traits.
//! - [`visibility`]: the one rule for which field values may leave the vault.
//! - [`path`]: the one vault path grammar (`/Group/Entry:2`).
//! - [`fingerprint`]: keyed fingerprints of secrets, never an unkeyed hash.
//! - [`text`]: line-safe escaping for anything rendered line by line.
//! - [`otp`]: TOTP resolution and code computation, with no clock access.
//! - [`capture`]: adapters from keepass 0.12 and 0.15 databases (optional
//!   features `keepass-0_12` and `keepass-0_15`).
//!
//! The library performs no I/O and builds for `wasm32-unknown-unknown`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capture;
mod codec;
pub mod fields;
pub mod fingerprint;
pub mod model;
pub mod otp;
pub mod path;
pub mod text;
pub mod visibility;
