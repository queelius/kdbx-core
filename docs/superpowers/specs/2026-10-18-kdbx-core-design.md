# kdbx-core and the snapshot redesign of diff-kdbx

Date: 2026-10-18. Status: approved direction (owner chose "snapshot + shared crate", name `kdbx-core`), design under review.

## 1. Why

Four independent reviews of the `*-kdbx` ecosystem (diff-kdbx, mcp-kdbx, web-kdbx, and a cross-ecosystem architecture pass, all 2026-10-18) converged on one structural problem and several drifted contracts.

**Structural problem.** diff-kdbx's public API takes `&keepass::Database`. keepass-rs is pre-1.0 and breaks at every minor, so every keepass bump forces a new diff-kdbx minor line, and every consumer must resolve the same keepass version as diff-kdbx. That already forced two release lines (0.1.x on keepass 0.12, 0.2.x on keepass 0.15) before the first publish. The engine internals (`tree_walk`, `symmetric_diff`, `field_diff_entry`, `LocatedNode`) are also public, and nothing is `#[non_exhaustive]`.

**Drifted contracts.** The three members each re-implement, differently:

| Contract | diff-kdbx | mcp-kdbx | web-kdbx (before its fix batch) |
|---|---|---|---|
| Path syntax | display-only, includes root name, escapes control chars | full grammar: parse/format, `\/ \\ \:` escapes, `:N` ordinals by UUID, NFC, no root name | unescaped, includes root name |
| Field visibility | mask if protected, Password always | stored flag, Title excepted | ignored the flag (leak) |
| Secret fingerprints | unkeyed SHA-256, 32-bit prefix | unkeyed SHA-256 with domain prefix (audit) | "N chars" hint |
| Standard field list | hardcoded twice | `keepass::db::fields::KNOWN_FIELDS` | hardcoded three times |
| TOTP | none | ~750 LOC | near-copy of mcp's |

An unkeyed hash of a low-entropy secret is a lookup oracle: a reviewer recovered a fixture's 4-digit PIN from mcp-kdbx's audit hash in under 10,000 tries, and diff-kdbx's `<hash:xxxxxxxx>` identifies a PIN the same way.

**Goal.** One small, stable crate owns the vault model and the ecosystem's shared rules. diff-kdbx becomes a pure function of two snapshots. mcp-kdbx and web-kdbx adopt the shared rules instead of carrying copies.

## 2. Crate layering

```
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

- **kdbx-core** depends on no keepass by default. Its keepass adapters live behind additive features `keepass-0_12` and `keepass-0_15`, each a package-renamed optional dependency (`keepass_0_12 = { package = "keepass", version = "0.12", optional = true }`). Enabling both is legal; Cargo builds both versions. A future keepass version is a new additive feature, not a semver-major release of anything.
- **diff-kdbx (library)** depends on kdbx-core only. It never names a keepass type. Its API is `compute(&Snapshot, &Snapshot, &DiffOptions) -> ChangeSet` and `dump(&Snapshot, &DumpOptions) -> String`.
- **diff-kdbx (CLI, feature `cli`)** opens files with keepass 0.15 (reads 4.0 and 4.1; diff-kdbx never writes) through `kdbx-core/keepass-0_15`.
- **mcp-kdbx** enables `kdbx-core/keepass-0_12` today and switches the feature when it bumps keepass. Its diff dependency stops constraining its keepass version.
- **web-kdbx** uses kdbx-core for paths, visibility, field schema and OTP.

Consequences: one diff-kdbx release line; `release/0.1` and the local `v0.1.0`/`v0.2.0` tags are deleted (none were pushed or published). diff-kdbx's first publish is 0.1.0 with the new API.

## 3. kdbx-core modules

### 3.1 `model`: the snapshot

An owned, serializable, keepass-free image of a database, captured once. All collections are ordered (`BTreeMap`, `Vec` in document order), so iteration is deterministic by construction.

```rust
#[non_exhaustive] pub struct Snapshot { pub format: FormatVersion, pub meta: Meta, pub root: Group }
#[non_exhaustive] pub struct FormatVersion { pub major: u16, pub minor: u16 } // KDBX 3.1, 4.0, 4.1
#[non_exhaustive] pub struct Group {
    pub uuid: Uuid, pub name: String, pub notes: Option<String>, pub tags: BTreeSet<String>,
    pub icon: Option<Icon>, pub times: Times, pub custom_data: BTreeMap<String, CustomValue>,
    pub flags: GroupFlags,               // is_expanded, enable_autotype, enable_searching, default_autotype_sequence
    pub previous_parent: Option<Uuid>,   // 4.1; None when captured from keepass 0.12
    pub groups: Vec<Group>, pub entries: Vec<Entry>,
}
#[non_exhaustive] pub struct Entry {
    pub uuid: Uuid, pub fields: BTreeMap<String, Field>, pub tags: BTreeSet<String>,
    pub attachments: BTreeMap<String, AttachmentInfo>, pub times: Times,
    pub icon: Option<Icon>, pub foreground: Option<Rgb>, pub background: Option<Rgb>,
    pub override_url: Option<String>, pub quality_check: bool, pub autotype: Option<AutoType>,
    pub custom_data: BTreeMap<String, CustomValue>, pub previous_parent: Option<Uuid>,
    pub history: Vec<Entry>,             // history items have empty history
}
#[non_exhaustive] pub struct Field { pub protected: bool, pub value: Value }
#[non_exhaustive] pub enum Value { Plain(String), Sealed(Fingerprint) }
pub struct AttachmentInfo { pub size: u64, pub fingerprint: Fingerprint, pub protected: bool }
pub struct CustomValue { pub value: Value, pub modified: Option<Timestamp> }
```

`Meta` mirrors the KDBX `<Meta>` element (database name and description, default username, color, maintenance days, master-key change times and policy, memory-protection flags, recycle bin enabled/uuid, templates group, history limits, custom data, custom icons as fingerprints). `Times` holds the seven `<Times>` values. `Timestamp` is a UTC second-resolution newtype that formats as `YYYY-MM-DDTHH:MM:SSZ`.

**Sealing happens at capture.** `capture(&db, &Sealing)` decides once, structurally, what plaintext the snapshot may hold:

```rust
pub enum Sealing<'k> { Fingerprint(&'k FingerprintKey), Reveal }
```

Under `Fingerprint`, every protected field value, every attachment's content, and every custom-data value becomes `Value::Sealed`. Plaintext of a protected value is never copied into the snapshot, so nothing downstream (diff, dump, views, serialization) can leak it by mistake. `Reveal` exists for `--show-secrets` and is the only way plaintext protected values enter a snapshot.

Two deliberate choices:

1. **Title is always plain.** The Title is the entry's address in a path. Every member already exposes it through paths, so sealing it would protect nothing while breaking addressing. This is the rule mcp-kdbx settled on (commit 5380f35). KDBX's `protect_title` memory-protection flag is honored as metadata (`Field::protected` is still true) but not as secrecy. Users who need secret titles are out of scope, and the docs say so.
2. **Custom data values are sealed.** They are not flagged protected in KDBX, but KeePassXC keeps browser-integration keys there. Keys are visible, values are fingerprints. Attachments are sealed for the same reason (SSH keys, recovery files).

### 3.2 `fields`: the standard-field schema

```rust
#[non_exhaustive] pub enum StandardField { Title, UserName, Password, Url, Notes }
impl StandardField {
    pub const ALL: [StandardField; 5];
    pub fn kdbx_name(self) -> &'static str;          // "Title", "UserName", "Password", "URL", "Notes"
    pub fn from_kdbx_name(name: &str) -> Option<Self>;
    pub fn traits(self) -> FieldTraits;              // { multiline, protected_by_default }
}
pub fn traits_of(name: &str) -> FieldTraits;          // standard traits, or the custom-field default
```

The five KDBX names are a format constant, not an app-maintained list. With a keepass feature on, a test asserts `ALL.map(kdbx_name) == keepass::db::fields::KNOWN_FIELDS`, so the two can never drift. web-kdbx exports this schema to JS instead of keeping JS-side lists.

### 3.3 `visibility`: the one exposure rule

```rust
pub fn metadata_value<'a>(entry: &'a Entry, name: &str) -> Option<&'a str>;
```

Returns the plain value when the field may cross out of the vault as metadata: present, and either unprotected or the Title. Under `Sealing::Fingerprint` this is structural (sealed values have no string), and the function also checks the flag, so a `Reveal` snapshot used for display still hides protected values unless a caller reveals explicitly. Search in every member uses the same function, so a value is searchable exactly when it is visible.

### 3.4 `path`: one grammar for the ecosystem

mcp-kdbx's `VaultPath` grammar becomes the ecosystem grammar, moved here with its tests:

- Rooted at `/`, which is the root group; the root group's own name is never part of a path.
- `/` separates segments. Escapes: `\/`, `\\`, `\:` (literal colon), plus the control-character escapes `\n`, `\t`, `\r` and `\u{XXXX}` for any other Unicode `Cc` or `Cf` character, so a formatted path is always one printable line.
- `:N` (1-based) disambiguates same-name siblings, ordered by UUID. UUID order, not document order, because the ordinal meaning is already a published contract in mcp-kdbx and must not depend on keepass's container type.
- Trailing `/` marks a group path. Names compare case-sensitively after NFC.
- A node with an empty name has no path (`Option::None`), because an empty segment would alias its parent (the bug fixed in mcp-kdbx 98d6338). Callers address such nodes by UUID.

```rust
pub struct VaultPath { /* segments, is_group */ }
impl VaultPath {
    pub fn parse(s: &str) -> Result<VaultPath, PathError>;   // PathError is a typed enum
    pub fn format(&self) -> String;
    pub fn resolve(&self, snap: &Snapshot) -> Result<NodeRef<'_>, ResolveError>;
}
pub fn path_of(snap: &Snapshot, uuid: Uuid) -> Option<VaultPath>;
```

Resolution is against a `Snapshot`. mcp-kdbx resolves to a UUID via a snapshot and then looks the UUID up in its live `keepass::Database`. The cost is one capture per tool call, linear in vault size, which is negligible next to the KDF at unlock. (A path index can be cached per snapshot later if profiling says so.)

### 3.5 `fingerprint`: keyed, never a dictionary oracle

```rust
pub struct FingerprintKey(/* 32 bytes, zeroized on drop, redacting Debug */);
pub struct Fingerprint([u8; 32]);                       // HMAC-SHA256(key, domain || bytes)
impl Fingerprint { pub fn short(&self) -> String }      // 8 hex chars, for display only
impl FingerprintKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self;         // caller-supplied (random, per session)
    #[cfg(feature = "kdf")]
    pub fn derive(material: &KeyMaterial, salt: Uuid) -> Result<Self, KdfError>;
}
pub struct KeyMaterial<'a> { pub password: Option<&'a [u8]>, pub keyfile: Option<&'a [u8]> }
```

Equality between fingerprints uses all 32 bytes; only display truncates. Domains separate uses (`kdbx-core/field/v1`, `kdbx-core/attachment/v1`, `kdbx-core/custom-data/v1`), so the same bytes in different roles do not correlate.

**Why derivation goes through Argon2.** A fingerprint must be stable across processes (git textconv dumps each blob separately, and mcp-kdbx's audit hashes must be verifiable later), so the key cannot be random per run. keepass keeps its composite and transformed keys crate-private (`get_key_elements` is `pub(crate)` in 0.12 and 0.15), so we cannot borrow the vault's own derived key. Deriving the HMAC key from the password with a fast hash would be worse than the unkeyed hash for strong passwords: anyone holding a fingerprint and knowing one protected value (a shared Wi-Fi password, say) could brute-force the master password at GPU speed, bypassing the vault's KDF. So `derive` runs Argon2id over `SHA-256(password) || SHA-256(keyfile)` with a fixed parameter set (64 MiB, 3 passes, 1 lane; part of the `v1` domain) and the root group's UUID as salt (stable across saves, distinct per vault). Breaking a fingerprint then costs at least as much as attacking a vault protected with KeePassXC-default Argon2 parameters.

The cost is one extra Argon2 run per process that needs stable fingerprints (diff-kdbx CLI per opened file; mcp-kdbx once per unlock). Uses that only compare within one process (mcp-kdbx's stage diff) use `from_bytes` with a random key and pay nothing.

Known trade-off, documented: when the master password changes between two commits, every sealed value's fingerprint changes in textconv output. diff-kdbx's `compute` mode reports this precisely anyway (it sees the `master_key_changed` meta time move).

`kdf` is a default feature; web-kdbx can disable it (it shows no fingerprints) to keep `argon2` out of its WASM.

### 3.6 `text`: safe line-oriented rendering

Every member that prints vault content line by line (diff text, textconv dump, mcp-kdbx log lines) must use one function, so no value can forge an output line:

```rust
pub fn escape_inline(s: &str) -> Cow<'_, str>;                // control chars -> \n \t \u{..}
pub fn continuation_lines<'a>(s: &'a str, prefix: &'a str) -> impl Iterator<Item = Cow<'a, str>>;
```

Single-line contexts (names, tags, paths, short values) use `escape_inline`. Multi-line values (Notes) render as a first line plus continuation lines that each start with a fixed prefix (`    | `), so git still diffs Notes line by line, and no value line can begin like a structural line (`+ ENTRY`, `~ Notes:`).

### 3.7 `otp`: one TOTP implementation

mcp-kdbx's `totp.rs` (the more complete copy: `otpauth://` URI, KeePassXC's legacy `TOTP Seed`/`TOTP Settings` pair, KeePass 2's native `TimeOtp-*` fields, bounds checks that avoid the division-by-zero and unbounded-digits bugs in keepass's own `otp.rs`) moves here, keepass-free:

```rust
pub fn resolve(entry: &Entry) -> Result<Option<TotpConfig>, OtpError>;   // from the snapshot's fields
impl TotpConfig { pub fn code_at(&self, unix_time: u64) -> TotpCode }  // no clock access: WASM-safe
```

`resolve` needs the secret, so it requires a `Reveal` snapshot or a field-level reveal; callers that capture under `Fingerprint` resolve OTP from the live keepass entry through a small adapter (`capture::otp_fields(&entry)`), which returns only the OTP-related fields in plaintext.

### 3.8 `capture`: the keepass adapters

```rust
#[cfg(feature = "keepass-0_12")] pub mod keepass_0_12 { pub fn capture(db: &Database, s: &Sealing) -> Snapshot; ... }
#[cfg(feature = "keepass-0_15")] pub mod keepass_0_15 { pub fn capture(db: &Database, s: &Sealing) -> Snapshot; ... }
```

The two keepass versions differ only in a handful of places (group tags, `previous_parent_group`, `quality_check: Option<bool>` vs `bool`, `IndexSet` children, the autotype obfuscation type). One `macro_rules!` body generates both modules, with the differences isolated in small per-version shims. Children are captured in document order; consumers that need a canonical order sort explicitly (diff-kdbx sorts by path then UUID, as today).

Capture is infallible: it is a pure transformation of an already-opened database.

## 4. diff-kdbx on kdbx-core

### 4.1 One algorithm for diff and dump: properties

Each snapshot node (meta, group, entry) exposes its state as an ordered property map derived from the model's structure:

```rust
pub(crate) fn properties(entry: &Entry) -> BTreeMap<Property, PropValue>;
#[non_exhaustive] pub enum Property {
    Field(String), Tag(String), Attachment(String), Time(TimeField), Icon, Color(ColorRole),
    OverrideUrl, QualityCheck, AutoType(AutoTypeKey), CustomData(String), HistoryItem(HistoryKey),
    Name, Notes, GroupFlag(GroupFlag), Meta(MetaKey), ...
}
```

`dump` prints every node's properties in canonical order. `compute` merge-joins the two property maps of each matched node. Because both derive from the same function, the dump and the diff cannot disagree again (today the dump omits expiry, protection flags and history contents that the diff reports). Adding a model field means adding one `Property` variant and one line in `properties`, and both outputs pick it up.

History items are keyed by their last-modification time (with an index tiebreak for duplicates), so trimming at the history cap and editing at the cap are both reported as precise additions and removals instead of a length comparison.

### 4.2 The change set: one record per node

```rust
#[non_exhaustive] pub struct ChangeSet { pub changes: Vec<Change>, pub summary: Summary, pub warnings: Vec<DiffWarning> }
#[non_exhaustive] pub enum Change {
    Database { changes: Vec<PropertyChange> },
    Group(NodeChange),
    Entry(NodeChange),
}
#[non_exhaustive] pub struct NodeChange { pub uuid: Uuid, pub path: Option<VaultPath>, pub status: NodeStatus }
#[non_exhaustive] pub enum NodeStatus {
    Added, Removed,
    Modified { moved_from: Option<VaultPath>, changes: Vec<PropertyChange> },
}
#[non_exhaustive] pub struct PropertyChange { pub property: Property, pub before: Option<Shown>, pub after: Option<Shown> }
#[non_exhaustive] pub enum Shown { Text(String), Sealed(Fingerprint), Bool(bool), Int(i64), Time(Timestamp), Uuid(Uuid), Color(Rgb), ... }
```

- `path` is the after-path (the before-path for `Removed`). A move is `moved_from`, not a second record, so a moved-and-edited entry is one record and counts once in `Summary`.
- A group rename is a `Name` property change on the group's record.
- Protection toggles are visible: a field's `Shown` carries its protection, so turning off protection on an unchanged `otp` value is reported.
- Colors render as `#RRGGBB`. Fingerprints serialize as 64 hex chars and render as 8.
- `Summary` is computed from `changes`; every counter is live (no dead fields).
- Noise suppression (`TimeField::is_noise`, kept from 0.2) happens at compute time; suppressed counts are reported in `Summary`.

### 4.3 Options and outputs

```rust
#[non_exhaustive] #[derive(Default)] pub struct DiffOptions { pub noise: Noise, pub recycle_bin: RecycleBin }
#[non_exhaustive] #[derive(Default)] pub struct DumpOptions { pub noise: Noise, pub recycle_bin: RecycleBin }
pub enum Noise { #[default] Suppress, Show }       // --strict = Show, in both modes
pub enum RecycleBin { #[default] Exclude, Include }
```

`show_secrets` leaves the options: it is a capture-time decision (`Sealing::Reveal`). `RenderOptions.color` and `--color` are removed (they did nothing). `--strict` now means the same thing in diff and dump: show timestamp noise. The recycle-bin rule ignores a recycle-bin UUID that points at the root group.

- **Text renderer** uses `kdbx_core::text` for every value, name and tag.
- **JSON renderer** emits `{"format_version": 1, "changes": [...], "summary": {...}, "warnings": [...]}`. The shape is a documented contract, pinned by `insta` snapshot tests; breaking it bumps `format_version`.

### 4.4 Public surface

The crate root re-exports the whole API (`compute`, `dump`, `render_text`, `render_json`, `ChangeSet`, options, and the kdbx-core types it uses, via `pub use kdbx_core`). Engine internals are `pub(crate)`. A `cargo public-api` diff (or a doc test listing) is part of the release checklist.

### 4.5 CLI

- Opens files with keepass 0.15. Key file only: an empty interactive password with `--key-file` means "no password" (fixes the key-file-only vault failure); `--no-password` makes it explicit.
- Derives one `FingerprintKey` per file (textconv) or per invocation (diff: from side A's material, so unchanged secrets compare equal even if B's password differs; the master-key change is reported separately).
- `gen-fixtures` moves to `examples/`, so `cargo install` no longer installs it, and `save_kdbx4` is enabled only for that example (dev-dependency feature).
- Exit codes unchanged: 0 no changes, 1 changes, 2 error.

## 5. Adoption by mcp-kdbx and web-kdbx

**mcp-kdbx**: depend on `kdbx-core` (`keepass-0_12`) and diff-kdbx 0.1.
- Replace `kdbx_core::path`, `visibility`, `totp` and the field constants with kdbx-core's. Keep its error codes; map `PathError`/`ResolveError` into them.
- The stage diff captures canonical and working with one random `FingerprintKey` per stage and calls diff-kdbx `compute`. Its exhaustive `match` on diff-kdbx enums gets wildcard arms (required by `#[non_exhaustive]`).
- Audit reveal hashes become keyed fingerprints with a key derived at unlock. This changes the audit format, so the JSONL event gains `fingerprint_v` and the field is renamed from `sha256` to `fingerprint`; the pinned-format test is updated deliberately and the change is documented in `docs/operations.md`. diff-kdbx gains a `diff-kdbx fingerprint` subcommand so an operator holding the vault can verify a logged fingerprint. The attachment `sha256` in `kdbx_list_attachments` becomes a keyed fingerprint too.
- Its internal crate module `kdbx_core` is renamed (to `core_ops` or similar) to avoid confusion with the external crate.

**web-kdbx**: depend on `kdbx-core` without `kdf`.
- Paths: display uses `VaultPath` (no root-group name, escaped).
- Visibility and field schema: its `visibility.rs` and the exported field schema come from kdbx-core.
- OTP: replace `totp.rs` with kdbx-core's `otp`.
- Remove the `"N chars"` hint (it leaks length); show a fixed mask.

## 6. Testing

- kdbx-core: unit tests per module (path grammar tests move from mcp-kdbx unchanged, plus escapes and the empty-name rule); capture tests for both keepass versions against shared fixtures (KDBX 4.0, 4.1 from KeePassXC, 3.1, protected UserName, legacy TOTP, duplicate titles, history, attachments); property tests (`proptest`): path `parse(format(p)) == p`, `escape_inline` output has no control characters, `continuation_lines` never yields a line that does not start with the prefix.
- A frozen, checksummed conformance corpus under `kdbx-core/tests/corpus/` (bytes only), later exposed through a `corpus` feature for other members' dev-dependencies.
- diff-kdbx: port the 97 existing tests to the new API; add JSON snapshot tests, property tests (`compute(a, a)` is empty; `compute(a, b)` and `compute(b, a)` are mirror images; output is identical across processes), and the reviewer's regression cases (protected Title policy, multi-line injection, moved-and-edited counted once, moved-and-renamed group, protection toggle, history at the cap, recycle bin pointing at root, key-file-only vault).

## 7. Sequencing

1. **kdbx-core 0.1** (this repo): model, fields, visibility, text, path, fingerprint, capture (both versions), otp. Corpus fixtures.
2. **diff-kdbx 0.1 (new API)** on kdbx-core: properties, compute, change set, renderers, dump, CLI. Delete `release/0.1` and the local tags.
3. **mcp-kdbx adoption** (after its review-fix branch merges).
4. **web-kdbx adoption** (after its review-fix branch merges).
5. **Publish** kdbx-core 0.1.0 then diff-kdbx 0.1.0 (owner confirms each; the crates.io token must be widened to include `kdbx-core`). Then mcp-kdbx switches its path dependency to crates.io.

Independently: the upstream keepass-rs #373 PR (KDBX 4.0 save) awaits the owner's review. When it ships, mcp-kdbx and web-kdbx flip their kdbx-core feature to `keepass-0_15` and bump keepass.

## 8. Open questions

- The Argon2 parameter set for `FingerprintKey::derive`: 64 MiB / 3 passes matches KeePassXC's default for new databases (to be confirmed against current KeePassXC source before release).
- Whether `Snapshot` should implement `serde::Serialize` publicly in 0.1 (useful for arkiv-kdbx later) or wait until the shape has settled. Proposal: derive it, but document the serialized shape as unstable until 1.0.
