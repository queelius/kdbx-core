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

## 9. Decisions made during implementation

Recorded while implementing kdbx-core 0.1 (plan tasks 1 to 11). Each is the
most principled reading of a point the sections above leave open or get
slightly wrong.

**Model and sealing (3.1)**

1. **`Sealing::Reveal` carries the key**: `enum Sealing<'k> { Fingerprint(&'k FingerprintKey), Reveal(&'k FingerprintKey) }`. Attachments, binary custom-data values and custom icons are never inlined, so they are fingerprinted under either variant; a unit `Reveal` would have forced either an unkeyed hash (breaking the "fingerprints are keyed" invariant) or inlined bytes. diff-kdbx's `--show-secrets` derives a key anyway.
2. **Binary custom data stays sealed under `Reveal`**; only text values are revealed. A custom-data item with no value element is captured as an empty string.
3. **`Sealing` owns the sealing rule** (`field`, `custom_text`, `custom_binary`, `attachment`, `custom_icon`), so every adapter, present or future, applies it identically. The secret rule is `visibility::is_secret`, shared with `metadata_value` (see 26).
4. **Fourth fingerprint domain** `kdbx-core/custom-icon/v1`, for `Meta::custom_icons: BTreeMap<Uuid, CustomIconInfo { size, fingerprint, name, modified }>`.
5. **`Snapshot::deleted_objects`** (the `<DeletedObjects>` tombstones) is part of the image. `Meta` also keeps `generator`, `last_selected_group` and `last_top_visible_group` for fidelity; consumers decide what is noise.
6. **Faithful optionality**: the seven `Times` values stay `Option` (KDBX can omit them); `quality_check` is a `bool` (absent means on); `Icon::Standard(u32)` saturates the (never seen) out-of-range index.
7. **Tags use the KDBX tag-list grammar** (`model::parse_tags`, `model::TAG_DELIMITERS`: `;`, `,`, tab; trimmed; empty tags dropped). This also repairs keepass 0.12, which splits `<Tags>` on `,` only.
8. **No `test-util` feature**: constructors (`Snapshot::new`, `Group::new`, `Entry::new`, `Field::plain`, `with_*` helpers) are always available, which is all a downstream crate needs to build `#[non_exhaustive]` values without keepass.
9. **`Snapshot::walk` yields `(NodeRef, Option<&Group>)`** (the parent itself rather than its UUID), in pre-order with a group's entries before its child groups.

**Fingerprints (3.5)**

10. **Exact bytes, no NFC**: field fingerprints cover the stored UTF-8 bytes (diff-kdbx 0.2 NFC-normalized first). For a secret, equality must mean byte equality.
11. **`derive` refuses empty key material** (`KdfError::NoKeyMaterial`): a key derived from no secret would reopen the dictionary oracle. The key file contributes `SHA-256` of its raw bytes. The parameters are `fingerprint::DeriveParams` (see 24); known answers are cross-checked against Python's `hmac` and against rust-argon2.
12. `Fingerprint` displays its 8-character short form, parses and serializes the 64-character form, and has a public `from_bytes` (so a logged fingerprint can be verified).

**Paths (3.4)**

13. **`VaultPath::format` is exact: group paths keep their trailing `/`** (`/Web/`), the root is `/`. mcp-kdbx's canonical form dropped the slash, which made `parse(format(p)) != p` for group paths and let a group's emitted path re-resolve as an entry. With the slash, every `path_of` result resolves back to its node through the generic `resolve` (property-tested).
14. **Escapes are strict**: an unknown escape (`\q`) or a bad `\u{...}` is a `PathError::Escape`. mcp-kdbx decoded `\x` to `x`, so `\n` used to mean the letter `n`; it now means a line feed, consistent with `text::escape_inline`.
15. Typed errors: `PathError` (`MissingLeadingSlash`, `EmptySegment`, `Escape(UnescapeError)`, `ZeroOrdinal`, `OrdinalOverflow`, `EmptyEntryPath`) and `ResolveError` (`GroupNotFound { segment }`, `EntryNotFound`, `GroupShapedPath`, the last being mcp-kdbx's "trailing slash never names an entry" rule, which it reported as `EntryNotFound`).
16. `Segment` is public with a validating constructor; `VaultPath::{root, group, entry}` build paths; `NodeKind` names group versus entry. Groups and entries have separate ordinal namespaces (as in mcp-kdbx).

**Text (3.6)**

17. **The escape set is Cc, Cf, Zl and Zp**: U+2028 and U+2029 break lines in some renderers, so leaving them would violate "always one printable line". `\u{XXXX}` uses uppercase hex with at least four digits; `unescape_inline` is public and exact.

**OTP (3.7)**

18. **Typed OTP fields**: `otp::OtpField` names the ten OTP-related fields; `capture::*::otp_fields` returns `OtpFields` (a `BTreeMap<OtpField, Zeroizing<String>>` with redacting `Debug`) instead of a `BTreeMap<String, String>`. `resolve(&Entry) -> Result<Option<TotpConfig>, OtpError>` fails with `OtpError::Sealed(field)` rather than guessing; `resolve_fields(&OtpFields)` serves the live-entry path (both return typed malformed errors, see 28).
19. **Stricter URIs**: a malformed `period` or `digits` rejects the otpauth URI (mcp-kdbx silently used the default, computing a wrong code), and so does an unknown `algorithm` or `encoder` (see 28). Scheme and type compare case-insensitively; base32 tolerates non-zero trailing bits.
20. **Leaner dependencies than mcp-kdbx**: RFC 6238 over `hmac` with `sha1`/`sha2` (no totp-lite), `data-encoding` for base32/base64/hex, and an RFC 3986 split plus `form_urlencoded` for the URI (no `url`, whose IDNA tables would land in WASM). `compute_now`/`unix_now` are gone (no clock); `evaluation_time` stays.

**Capture (3.8) and corpus (6)**

21. keepass 0.12 keeps children in a randomized hash set, so its adapter sorts children by UUID (document order is unrecoverable); keepass 0.15 keeps document order.
22. keepass 0.12 cannot pin UUIDs, so `examples/gen_corpus.rs` builds the vault with keepass 0.15 and fixed UUIDs and has keepass 0.12 re-save it as KDBX 4.0. `tests/corpus/manifest.json` is the typed record the tests read; `MANIFEST.md` is its human-readable twin (the tests check that it mentions every file and checksum).
23. Both keepass versions are dev-dependencies (with `save_kdbx4`), so tests build keepass even under `--no-default-features`; library users never see them.

**Review follow-up (owner decisions, 2026-10-18)**

24. **KDF floor**: `FingerprintKey::derive(material, salt, &DeriveParams)`. `DeriveParams` is, per component (memory, passes, lanes), the maximum of the floor (64 MiB, 3, 1) and the vault's own Argon2 parameters, always run as Argon2id; AES-KDF and unrecognized KDFs get the floor. So a fingerprint is never a cheaper oracle on the master password than the vault's own KDF. `DeriveParams::{for_kdf, for_header, for_snapshot}` compute it; `capture::*::header(&Database)` provides the header before a key (and so a capture) exists. The parameters are part of what a verifier must reproduce: record them next to fingerprints (`Display`: `argon2id$v=19$m=..,t=..,p=..`; serde: a struct that refuses values below the floor). Known answers are pinned for two parameter sets. The earlier claim that the fixed parameters matched KeePassXC defaults is withdrawn.
25. **Header capture**: `Snapshot::header: Option<HeaderInfo>` records the KDF and its parameters (`KdfInfo`), outer cipher, inner stream cipher, compression, and public-custom-data keys. diff-kdbx reports changes here (KDF downgrades). keepass marks the corresponding enums `#[non_exhaustive]`, so a variant it adds later maps to `Unrecognized`.
26. **One secret predicate**: `visibility::is_secret(name, protected) = name != Title && (protected || traits_of(name).protected_by_default)`, used by both `Sealing::field` and `metadata_value`, so sealing and visibility cannot disagree. A Password whose protection flag is off is sealed and hidden (old diff-kdbx always masked the Password). `Entry`'s `Debug` redacts secret plaintext by this rule (a bare `Field` redacts protected plaintext), so a `Reveal` snapshot does not print secrets via `Debug`.
27. **Bulk paths**: `path::PathIndex` computes every node's path in one pass (each name NFC-normalized once, ordinals per sibling list); `path_of` is the single-lookup convenience and shares the same sibling computation, so the two agree by construction (first node in walk order wins for duplicate UUIDs).
28. **OTP errors and Steam**: `resolve_fields` returns `Result<Option<TotpConfig>, OtpError>`; `Ok(None)` means no source is present (empty fields count as absent), `OtpError::Malformed { source: OtpSource, reason: MalformedReason }` means sources are present but none is usable. A malformed source still falls through to a later well-formed one. Unknown algorithms and encoders are rejected. `TotpEncoding::Steam` implements KeePassXC's `encoder=steam` and the legacy `S` digits (five characters of `23456789BCDFGHJKMNPQRTVWXY` from the RFC 4226 truncated value, least significant first; the vectors were computed independently with Python, not taken from KeePassXC itself). A legacy `TOTP Seed` without `TOTP Settings` (or with empty settings) uses KeePassXC's defaults, 30 seconds and 6 digits, as `Totp::parseSettings` does (commit 001853f); settings that are present but malformed remain an error.
29. **Canonical paths**: `Segment::new` stores the NFC name and treats ordinal 1 as none, so paths that resolve alike compare equal and format identically; `path_of` writes the first of several same-named siblings bare (`/Web/Dup`, then `/Web/Dup:2`). `parse` accepts some non-canonical spellings; `format` emits the canonical one.
30. **Constants as slices**: `Domain::ALL` and `OtpField::ALL` are `&'static [T]` (an array length on a `#[non_exhaustive]` enum is a semver hazard); `StandardField::ALL` stays an array (a format constant).
31. **Zeroization in derive**: the input is hashed straight into a wiped buffer, and the output and Argon2 working memory are wiped (`Zeroizing`). The SHA-256 hasher state cannot be wiped (sha2 0.10 has no zeroization). `FingerprintKey::from_bytes` takes its array by value; the caller wipes its own source.
32. **Auto-type sequences stay plain** under either sealing: KDBX does not protect them, and they are user-authored macros that reference fields by placeholder.
33. **Upstream gaps (keepass keeps the data crate-private; accessor requests for keepass-rs)**: `previous_parent` is read through keepass's `previous_parent()` lookup, which returns `None` when the old parent group no longer exists, so a deleted previous parent's UUID is lost; a group's `LastTopVisibleEntry` is not capturable at all.
34. **Packaging**: the keepass-rs MIT license text ships as `tests/corpus/LICENSE-keepass-rs` and is referenced from the manifest; the package excludes `docs/superpowers/` and `proptest-regressions/`; CI runs `cargo publish --dry-run`.

**WASM size follow-up (web-kdbx adoption)**

35. **No general-purpose tables in the library**: `text::needs_escape` uses a 23-range table of the Cc/Cf/Zl/Zp code points (Unicode 17.0.0, `ESCAPE_TABLE_UNICODE_VERSION`), checked against `unicode-properties` (now a dev-dependency) for every code point; and the crate's own RFC 4648 codecs (hex, base32, base64, in the private `codec` module) replace `data-encoding` (now a dev-dependency for differential tests). A release wasm32 size probe (no default features, opt-level s, LTO) went from 146,412 to 105,494 bytes (escape table) to 61,261 bytes (codecs). `unicode-normalization` stays: NFC is what makes ordinals identical across members. Base64 secrets now decode with or without padding.

**keepass 0.12 limitations found (pinned by tests)**

- It **cannot parse KDBX 4.1 files whose groups carry `<Tags>` or whose records carry `<PreviousParentGroup>`** ("unknown variant"). KeePassXC writes both, so mcp-kdbx and web-kdbx on keepass 0.12 cannot open such vaults today.
- It ignores `<QualityCheck>` and `<DeletionTime>`, cannot read the KDBX 3.1 fixture with an empty attachment, and drops fields whose value is empty.
