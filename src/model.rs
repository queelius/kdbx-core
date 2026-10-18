//! The keepass-free snapshot of a database.
//!
//! A [`Snapshot`] is an owned, serializable image of a KDBX database, captured
//! once (see [`crate::capture`]) and then read by everything downstream: diff,
//! dump, views, search. All collections are ordered (`BTreeMap`, `BTreeSet`,
//! or `Vec` in document order), so iteration is deterministic by construction.
//!
//! **Sealing happens at capture.** A [`Sealing`] decides once, structurally,
//! what plaintext a snapshot may hold. Under [`Sealing::Fingerprint`] every
//! secret field value ([`crate::visibility::is_secret`]: protected or a
//! Password, never the Title), every custom-data value, every
//! attachment's content and every custom icon becomes a keyed
//! [`Fingerprint`]; the plaintext is never copied in, so nothing downstream
//! can leak it by mistake. [`Sealing::Reveal`] is the only way plaintext
//! protected values enter a snapshot.
//!
//! The serialized shape (serde) is **unstable before 1.0**.
//!
//! Every struct here is `#[non_exhaustive]`: build values with the provided
//! constructors (for example [`Entry::new`], [`Group::new`]) and then set the
//! public fields.
//!
//! ```
//! use kdbx_core::model::{Entry, Field, FormatVersion, Group, Meta, Snapshot, Value};
//! use uuid::Uuid;
//!
//! let entry = Entry::new(Uuid::from_u128(2))
//!     .with_field("Title", Field::plain("Bank"))
//!     .with_field("UserName", Field::plain("alice"));
//! let root = Group::new(Uuid::from_u128(1), "Root").with_entry(entry);
//! let snap = Snapshot::new(FormatVersion::KDBX_4_1, Meta::default(), root);
//!
//! let bank = snap.find_entry(Uuid::from_u128(2)).unwrap();
//! assert_eq!(bank.title(), Some("Bank"));
//! assert_eq!(snap.walk().count(), 2);
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::fields::StandardField;
use crate::fingerprint::{Domain, Fingerprint, FingerprintKey};

/// An owned, keepass-free image of a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Snapshot {
    /// The KDBX file format version the database was read from.
    pub format: FormatVersion,
    /// The `<Meta>` element.
    pub meta: Meta,
    /// The root group (its own name is never part of a vault path).
    pub root: Group,
    /// The `<DeletedObjects>` tombstones: UUID of a deleted record, and when
    /// it was deleted.
    pub deleted_objects: BTreeMap<Uuid, Option<Timestamp>>,
    /// The outer KDBX header's security configuration (KDF, ciphers,
    /// compression), when captured from a file. `None` for a snapshot built
    /// by hand.
    pub header: Option<HeaderInfo>,
}

/// The security configuration in a KDBX file's outer header.
///
/// diff-kdbx reports changes here (a KDF downgrade, say), and fingerprint key
/// derivation reads the KDF so a fingerprint key is never cheaper to attack
/// than the vault itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HeaderInfo {
    /// The key derivation function and its parameters.
    pub kdf: KdfInfo,
    /// The cipher encrypting the database payload.
    pub outer_cipher: OuterCipher,
    /// The stream cipher protecting protected values inside the payload.
    pub inner_cipher: InnerCipher,
    /// Payload compression.
    pub compression: Compression,
    /// The keys of the header's public custom data (plugin metadata; values
    /// are not captured).
    pub public_custom_data: BTreeSet<String>,
}

/// A KDBX key derivation function and its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KdfInfo {
    /// AES-KDF (KDBX 3.1 and older 4.x vaults).
    Aes {
        /// Transformation rounds.
        rounds: u64,
    },
    /// Argon2d or Argon2id.
    Argon2(Argon2Info),
    /// A KDF the capturing keepass version does not name.
    Unrecognized,
}

/// The parameters of an Argon2 KDF as stored in a KDBX header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Argon2Info {
    /// Argon2d or Argon2id.
    pub variant: Argon2Variant,
    /// Memory cost in bytes (as KDBX stores it).
    pub memory_bytes: u64,
    /// Number of passes.
    pub iterations: u64,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
    /// Argon2 version (`0x13` = 19, or `0x10`).
    pub version: u32,
}

/// The Argon2 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Argon2Variant {
    /// Argon2d (KeePass's original choice).
    Argon2d,
    /// Argon2id.
    Argon2id,
}

/// The KDBX outer (payload) cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OuterCipher {
    /// AES-256-CBC.
    Aes256,
    /// Twofish-CBC.
    Twofish,
    /// ChaCha20.
    ChaCha20,
    /// A cipher the capturing keepass version does not name.
    Unrecognized,
}

/// The KDBX inner (protected-value) stream cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InnerCipher {
    /// No inner encryption.
    Plain,
    /// Salsa20 (KDBX 3.1).
    Salsa20,
    /// ChaCha20 (KDBX 4).
    ChaCha20,
    /// A cipher the capturing keepass version does not name.
    Unrecognized,
}

/// KDBX payload compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Compression {
    /// Uncompressed.
    None,
    /// GZip.
    GZip,
    /// A compression the capturing keepass version does not name.
    Unrecognized,
}

impl HeaderInfo {
    /// A header description with no public custom data.
    pub fn new(
        kdf: KdfInfo,
        outer_cipher: OuterCipher,
        inner_cipher: InnerCipher,
        compression: Compression,
    ) -> Self {
        HeaderInfo {
            kdf,
            outer_cipher,
            inner_cipher,
            compression,
            public_custom_data: BTreeSet::new(),
        }
    }
}

impl Argon2Info {
    /// Argon2 parameters as a KDBX header stores them.
    pub fn new(
        variant: Argon2Variant,
        memory_bytes: u64,
        iterations: u64,
        parallelism: u32,
        version: u32,
    ) -> Self {
        Argon2Info {
            variant,
            memory_bytes,
            iterations,
            parallelism,
            version,
        }
    }
}

/// A KDBX file format version (3.1, 4.0, 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FormatVersion {
    /// Major version (3 or 4 for KDBX; 1 and 2 for older KeePass formats).
    pub major: u16,
    /// Minor version.
    pub minor: u16,
}

/// The KDBX `<Meta>` element.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Meta {
    /// The application that last wrote the file.
    pub generator: Option<String>,
    /// Database name.
    pub database_name: Option<String>,
    /// When the database name last changed.
    pub database_name_changed: Option<Timestamp>,
    /// Database description.
    pub database_description: Option<String>,
    /// When the description last changed.
    pub database_description_changed: Option<Timestamp>,
    /// Default user name for new entries.
    pub default_username: Option<String>,
    /// When the default user name last changed.
    pub default_username_changed: Option<Timestamp>,
    /// Days a deleted history item is kept.
    pub maintenance_history_days: Option<u64>,
    /// Database color.
    pub color: Option<Rgb>,
    /// When the master key last changed.
    pub master_key_changed: Option<Timestamp>,
    /// Days after which a master-key change is recommended (`-1`: never).
    pub master_key_change_rec: Option<i64>,
    /// Days after which a master-key change is forced (`-1`: never).
    pub master_key_change_force: Option<i64>,
    /// Which standard fields clients protect in memory by default.
    pub memory_protection: Option<MemoryProtection>,
    /// Whether deleting moves records to the recycle bin.
    pub recycle_bin_enabled: Option<bool>,
    /// The recycle-bin group.
    pub recycle_bin: Option<Uuid>,
    /// When the recycle-bin setting last changed.
    pub recycle_bin_changed: Option<Timestamp>,
    /// The entry-templates group.
    pub entry_templates_group: Option<Uuid>,
    /// When the entry-templates group last changed.
    pub entry_templates_group_changed: Option<Timestamp>,
    /// The group selected when the database was last closed (UI state).
    pub last_selected_group: Option<Uuid>,
    /// The group scrolled to when the database was last closed (UI state).
    pub last_top_visible_group: Option<Uuid>,
    /// Maximum history items per entry (`-1`: unlimited).
    pub history_max_items: Option<i64>,
    /// Maximum history size per entry in bytes (`-1`: unlimited).
    pub history_max_size: Option<i64>,
    /// When the database settings last changed.
    pub settings_changed: Option<Timestamp>,
    /// Database-level custom data. Values are sealed under
    /// [`Sealing::Fingerprint`] (KeePassXC keeps browser-integration keys here).
    pub custom_data: BTreeMap<String, CustomValue>,
    /// Custom icons, by UUID, as fingerprints of their image data.
    pub custom_icons: BTreeMap<Uuid, CustomIconInfo>,
}

/// The KDBX `<MemoryProtection>` flags: which standard fields clients protect
/// by default.
///
/// `title` is honored as metadata only: a Title is an address, never a secret
/// (see [`crate::visibility`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryProtection {
    /// Protect `Title`.
    pub title: bool,
    /// Protect `UserName`.
    pub user_name: bool,
    /// Protect `Password`.
    pub password: bool,
    /// Protect `URL`.
    pub url: bool,
    /// Protect `Notes`.
    pub notes: bool,
}

/// A group (folder) and its subtree.
///
/// KDBX's `LastTopVisibleEntry` (UI scroll state) is not captured: keepass
/// keeps it crate-private.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Group {
    /// Record identity.
    pub uuid: Uuid,
    /// Group name (a vault path segment).
    pub name: String,
    /// Group notes.
    pub notes: Option<String>,
    /// Tags (KDBX 4.1; empty when captured from keepass 0.12).
    pub tags: BTreeSet<String>,
    /// Icon.
    pub icon: Option<Icon>,
    /// The seven `<Times>` values.
    pub times: Times,
    /// Group custom data (values sealed under [`Sealing::Fingerprint`]).
    pub custom_data: BTreeMap<String, CustomValue>,
    /// Behavior flags.
    pub flags: GroupFlags,
    /// The group this one was moved out of (KDBX 4.1; `None` when captured
    /// from keepass 0.12). Also `None` when that group no longer exists:
    /// keepass only exposes the previous parent through a lookup that fails
    /// for a deleted group (the raw UUID is crate-private upstream).
    pub previous_parent: Option<Uuid>,
    /// Child groups, in document order.
    pub groups: Vec<Group>,
    /// Entries, in document order.
    pub entries: Vec<Entry>,
}

/// Group behavior flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GroupFlags {
    /// Whether the group is expanded in the tree view.
    pub is_expanded: bool,
    /// Auto-type enabled (`None`: inherit from the parent).
    pub enable_autotype: Option<bool>,
    /// Searching enabled (`None`: inherit from the parent).
    pub enable_searching: Option<bool>,
    /// Default auto-type sequence for entries in this group.
    pub default_autotype_sequence: Option<String>,
}

/// An entry (a credential record).
///
/// `Debug` redacts the plaintext of every secret field
/// ([`crate::visibility::is_secret`]), so a `Reveal` snapshot does not print
/// secrets through `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Entry {
    /// Record identity (history items share their entry's UUID).
    pub uuid: Uuid,
    /// Fields by name: the standard fields plus custom ones.
    pub fields: BTreeMap<String, Field>,
    /// Tags.
    pub tags: BTreeSet<String>,
    /// Attachments by name.
    pub attachments: BTreeMap<String, AttachmentInfo>,
    /// The seven `<Times>` values.
    pub times: Times,
    /// Icon.
    pub icon: Option<Icon>,
    /// Foreground color.
    pub foreground: Option<Rgb>,
    /// Background color.
    pub background: Option<Rgb>,
    /// URL override (a command line, for example).
    pub override_url: Option<String>,
    /// Whether the password counts toward quality reports.
    pub quality_check: bool,
    /// Auto-type settings.
    pub autotype: Option<AutoType>,
    /// Entry custom data (values sealed under [`Sealing::Fingerprint`]).
    pub custom_data: BTreeMap<String, CustomValue>,
    /// The group this entry was moved out of (KDBX 4.1; `None` when captured
    /// from keepass 0.12). Also `None` when that group no longer exists (see
    /// [`Group::previous_parent`]).
    pub previous_parent: Option<Uuid>,
    /// Earlier versions of this entry, in document order. History items have
    /// empty history.
    pub history: Vec<Entry>,
}

/// One entry field: its KDBX protection flag and its (possibly sealed) value.
///
/// `Debug` redacts a plaintext value whose protection flag is set (a bare
/// field does not know its name; [`Entry`]'s `Debug` applies the full
/// name-aware rule).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Field {
    /// The stored KDBX protection flag.
    pub protected: bool,
    /// The value, plain or sealed.
    pub value: Value,
}

/// A value that is either plaintext or a keyed fingerprint of the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Value {
    /// The plaintext.
    Plain(String),
    /// A fingerprint standing in for a sealed plaintext.
    Sealed(Fingerprint),
}

/// An attachment, described without its content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttachmentInfo {
    /// Content length in bytes.
    pub size: u64,
    /// Fingerprint of the content (always sealed: content is never inlined).
    pub fingerprint: Fingerprint,
    /// The stored KDBX protection flag.
    pub protected: bool,
}

/// A custom-data value and its last-modification time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CustomValue {
    /// The value, plain or sealed.
    pub value: Value,
    /// When the item last changed (KDBX 4.1).
    pub modified: Option<Timestamp>,
}

/// A custom icon, described by a fingerprint of its image data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CustomIconInfo {
    /// Image size in bytes.
    pub size: u64,
    /// Fingerprint of the image data.
    pub fingerprint: Fingerprint,
    /// Icon name (KDBX 4.1).
    pub name: Option<String>,
    /// When the icon last changed (KDBX 4.1).
    pub modified: Option<Timestamp>,
}

/// The KDBX `<Times>` element.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Times {
    /// `CreationTime`.
    pub creation: Option<Timestamp>,
    /// `LastModificationTime`.
    pub last_modification: Option<Timestamp>,
    /// `LastAccessTime`.
    pub last_access: Option<Timestamp>,
    /// `ExpiryTime`.
    pub expiry: Option<Timestamp>,
    /// `LocationChanged`.
    pub location_changed: Option<Timestamp>,
    /// `Expires`: whether `expiry` is in force.
    pub expires: Option<bool>,
    /// `UsageCount`.
    pub usage_count: Option<u64>,
}

/// A UTC instant with one-second resolution.
///
/// Displays, parses and serializes as `YYYY-MM-DDTHH:MM:SSZ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

/// An icon: one of KeePass's built-in icons, or a custom one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Icon {
    /// A built-in icon by index.
    Standard(u32),
    /// A custom icon by UUID (see [`Meta::custom_icons`]).
    Custom(Uuid),
}

/// An RGB color. Displays, parses and serializes as `#RRGGBB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rgb {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
}

/// Auto-type settings of an entry.
///
/// Sequences are always captured in plaintext, under either sealing: KDBX
/// does not protect them, and they are user-authored keystroke macros that
/// reference fields by placeholder (`{PASSWORD}`) rather than holding values.
/// A user who types a literal secret into a sequence has stored it
/// unprotected in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AutoType {
    /// Whether auto-type is enabled for the entry.
    pub enabled: bool,
    /// The entry's default keystroke sequence.
    pub default_sequence: Option<String>,
    /// How keystrokes are transferred.
    pub obfuscation: AutoTypeObfuscation,
    /// Window-specific sequences.
    pub associations: Vec<AutoTypeAssociation>,
}

/// The KDBX `<DataTransferObfuscation>` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AutoTypeObfuscation {
    /// Type keystrokes directly.
    #[default]
    None,
    /// Transfer partly through the clipboard.
    UseClipboard,
}

/// One window-specific auto-type sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AutoTypeAssociation {
    /// Window title pattern.
    pub window: String,
    /// Keystroke sequence for matching windows.
    pub sequence: String,
}

/// What plaintext a capture may copy into a snapshot.
///
/// Both variants carry a [`FingerprintKey`], because content that is never
/// inlined (attachments, binary custom data, custom icons) is fingerprinted
/// under either.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Sealing<'k> {
    /// Seal every secret field value (protected or a Password, never the
    /// Title), every custom-data value, and all binary content.
    Fingerprint(&'k FingerprintKey),
    /// Keep text values in plaintext (for `--show-secrets`). Binary content is
    /// still fingerprinted.
    Reveal(&'k FingerprintKey),
}

/// A borrowed group or entry of a [`Snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRef<'a> {
    /// A group.
    Group(&'a Group),
    /// An entry.
    Entry(&'a Entry),
}

/// Whether a node is a group or an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// A group.
    Group,
    /// An entry.
    Entry,
}

/// The characters that separate tags in a KDBX `<Tags>` value. KeePass writes
/// `;`; readers also accept `,` and tab.
pub const TAG_DELIMITERS: [char; 3] = [';', ',', '\t'];

/// Parse a KDBX tag list: split on [`TAG_DELIMITERS`], trim each tag, and drop
/// empty ones.
///
/// ```
/// use kdbx_core::model::parse_tags;
///
/// let tags = parse_tags("money; finance,,\twork");
/// assert_eq!(tags.into_iter().collect::<Vec<_>>(), ["finance", "money", "work"]);
/// ```
pub fn parse_tags(raw: &str) -> BTreeSet<String> {
    raw.split(TAG_DELIMITERS)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Constructors and accessors.

impl Snapshot {
    /// A snapshot with no deleted-object tombstones.
    pub fn new(format: FormatVersion, meta: Meta, root: Group) -> Self {
        Snapshot {
            format,
            meta,
            root,
            deleted_objects: BTreeMap::new(),
            header: None,
        }
    }

    /// Every group and entry, in document order (pre-order: a group, then its
    /// entries, then each child group's subtree), each with its parent group
    /// (`None` for the root). History items are not visited.
    pub fn walk(&self) -> Walk<'_> {
        Walk {
            stack: vec![(NodeRef::Group(&self.root), None)],
        }
    }

    /// The group or entry with `uuid`, if any (history items are not
    /// searched).
    pub fn find(&self, uuid: Uuid) -> Option<NodeRef<'_>> {
        self.walk()
            .map(|(node, _)| node)
            .find(|node| node.uuid() == uuid)
    }

    /// The group with `uuid`, if any.
    pub fn find_group(&self, uuid: Uuid) -> Option<&Group> {
        match self.find(uuid)? {
            NodeRef::Group(g) => Some(g),
            NodeRef::Entry(_) => None,
        }
    }

    /// The entry with `uuid`, if any.
    pub fn find_entry(&self, uuid: Uuid) -> Option<&Entry> {
        match self.find(uuid)? {
            NodeRef::Entry(e) => Some(e),
            NodeRef::Group(_) => None,
        }
    }

    /// The group containing the node with `uuid` (`None` for the root and for
    /// unknown UUIDs).
    pub fn parent_of(&self, uuid: Uuid) -> Option<&Group> {
        self.walk()
            .find(|(node, _)| node.uuid() == uuid)
            .and_then(|(_, parent)| parent)
    }

    /// Every entry (not history items), in document order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> + '_ {
        self.walk().filter_map(|(node, _)| match node {
            NodeRef::Entry(e) => Some(e),
            NodeRef::Group(_) => None,
        })
    }

    /// Every group, the root first, in document order.
    pub fn groups(&self) -> impl Iterator<Item = &Group> + '_ {
        self.walk().filter_map(|(node, _)| match node {
            NodeRef::Group(g) => Some(g),
            NodeRef::Entry(_) => None,
        })
    }
}

/// Iterator returned by [`Snapshot::walk`].
#[derive(Debug, Clone)]
pub struct Walk<'a> {
    stack: Vec<(NodeRef<'a>, Option<&'a Group>)>,
}

impl<'a> Iterator for Walk<'a> {
    type Item = (NodeRef<'a>, Option<&'a Group>);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.stack.pop()?;
        if let (NodeRef::Group(group), _) = item {
            // Pushed in reverse so they pop in document order: the entries
            // first, then each child group (whose subtree is visited before
            // its next sibling).
            let parent = Some(group);
            self.stack.extend(
                group
                    .groups
                    .iter()
                    .rev()
                    .map(|g| (NodeRef::Group(g), parent)),
            );
            self.stack.extend(
                group
                    .entries
                    .iter()
                    .rev()
                    .map(|e| (NodeRef::Entry(e), parent)),
            );
        }
        Some(item)
    }
}

impl FormatVersion {
    /// KDBX 3.1.
    pub const KDBX_3_1: FormatVersion = FormatVersion::new(3, 1);
    /// KDBX 4.0.
    pub const KDBX_4_0: FormatVersion = FormatVersion::new(4, 0);
    /// KDBX 4.1.
    pub const KDBX_4_1: FormatVersion = FormatVersion::new(4, 1);

    /// A format version.
    pub const fn new(major: u16, minor: u16) -> Self {
        FormatVersion { major, minor }
    }
}

impl fmt::Display for FormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl MemoryProtection {
    /// Whether clients protect `field` by default.
    pub fn protects(&self, field: StandardField) -> bool {
        match field {
            StandardField::Title => self.title,
            StandardField::UserName => self.user_name,
            StandardField::Password => self.password,
            StandardField::Url => self.url,
            StandardField::Notes => self.notes,
        }
    }
}

/// The KDBX default: only the Password is protected.
impl Default for MemoryProtection {
    fn default() -> Self {
        MemoryProtection {
            title: false,
            user_name: false,
            password: true,
            url: false,
            notes: false,
        }
    }
}

impl Group {
    /// An empty group with default times and flags.
    pub fn new(uuid: Uuid, name: impl Into<String>) -> Self {
        Group {
            uuid,
            name: name.into(),
            notes: None,
            tags: BTreeSet::new(),
            icon: None,
            times: Times::default(),
            custom_data: BTreeMap::new(),
            flags: GroupFlags::default(),
            previous_parent: None,
            groups: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// This group with `group` appended to its child groups.
    pub fn with_group(mut self, group: Group) -> Self {
        self.groups.push(group);
        self
    }

    /// This group with `entry` appended to its entries.
    pub fn with_entry(mut self, entry: Entry) -> Self {
        self.entries.push(entry);
        self
    }
}

/// KDBX defaults: expanded, everything else inherited.
impl Default for GroupFlags {
    fn default() -> Self {
        GroupFlags {
            is_expanded: true,
            enable_autotype: None,
            enable_searching: None,
            default_autotype_sequence: None,
        }
    }
}

impl Entry {
    /// An entry with no fields, default times, and quality check on (the KDBX
    /// default).
    pub fn new(uuid: Uuid) -> Self {
        Entry {
            uuid,
            fields: BTreeMap::new(),
            tags: BTreeSet::new(),
            attachments: BTreeMap::new(),
            times: Times::default(),
            icon: None,
            foreground: None,
            background: None,
            override_url: None,
            quality_check: true,
            autotype: None,
            custom_data: BTreeMap::new(),
            previous_parent: None,
            history: Vec::new(),
        }
    }

    /// This entry with field `name` set to `field`.
    pub fn with_field(mut self, name: impl Into<String>, field: Field) -> Self {
        self.fields.insert(name.into(), field);
        self
    }

    /// The field stored under `name`.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.get(name)
    }

    /// The standard field `field`.
    pub fn standard(&self, field: StandardField) -> Option<&Field> {
        self.field(field.kdbx_name())
    }

    /// The Title's plaintext. Titles are never sealed, so this is `None` only
    /// when the entry has no Title field.
    pub fn title(&self) -> Option<&str> {
        self.standard(StandardField::Title)?.value.as_plain()
    }
}

impl Field {
    /// An unprotected plaintext field.
    pub fn plain(value: impl Into<String>) -> Self {
        Field {
            protected: false,
            value: Value::Plain(value.into()),
        }
    }

    /// A field with the given protection flag and value.
    pub fn new(protected: bool, value: Value) -> Self {
        Field { protected, value }
    }
}

impl Value {
    /// The plaintext, or `None` when sealed.
    pub fn as_plain(&self) -> Option<&str> {
        match self {
            Value::Plain(s) => Some(s),
            Value::Sealed(_) => None,
        }
    }

    /// Whether the value is sealed.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Value::Sealed(_))
    }
}

impl AttachmentInfo {
    /// An attachment description.
    pub fn new(size: u64, fingerprint: Fingerprint, protected: bool) -> Self {
        AttachmentInfo {
            size,
            fingerprint,
            protected,
        }
    }
}

impl CustomValue {
    /// A custom-data value.
    pub fn new(value: Value, modified: Option<Timestamp>) -> Self {
        CustomValue { value, modified }
    }
}

impl CustomIconInfo {
    /// A custom-icon description.
    pub fn new(
        size: u64,
        fingerprint: Fingerprint,
        name: Option<String>,
        modified: Option<Timestamp>,
    ) -> Self {
        CustomIconInfo {
            size,
            fingerprint,
            name,
            modified,
        }
    }
}

impl AutoTypeAssociation {
    /// A window-specific sequence.
    pub fn new(window: impl Into<String>, sequence: impl Into<String>) -> Self {
        AutoTypeAssociation {
            window: window.into(),
            sequence: sequence.into(),
        }
    }
}

impl<'a> NodeRef<'a> {
    /// The node's UUID.
    pub fn uuid(self) -> Uuid {
        match self {
            NodeRef::Group(g) => g.uuid,
            NodeRef::Entry(e) => e.uuid,
        }
    }

    /// Group or entry.
    pub fn kind(self) -> NodeKind {
        match self {
            NodeRef::Group(_) => NodeKind::Group,
            NodeRef::Entry(_) => NodeKind::Entry,
        }
    }

    /// The node's name: a group's name, or an entry's Title (`None` when the
    /// entry has no Title).
    pub fn name(self) -> Option<&'a str> {
        match self {
            NodeRef::Group(g) => Some(&g.name),
            NodeRef::Entry(e) => e.title(),
        }
    }
}

// ---------------------------------------------------------------------------
// Debug without secrets.

/// Stands in for a redacted plaintext in `Debug` output.
const REDACTED: &str = "<redacted>";

/// A field rendered for `Debug`, with its plaintext hidden when `secret`.
struct FieldDebug<'a> {
    field: &'a Field,
    secret: bool,
}

impl fmt::Debug for FieldDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Field");
        s.field("protected", &self.field.protected);
        match &self.field.value {
            Value::Plain(_) if self.secret => s.field("value", &format_args!("Plain({REDACTED})")),
            value => s.field("value", value),
        };
        s.finish()
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        FieldDebug {
            field: self,
            secret: self.protected,
        }
        .fmt(f)
    }
}

/// An entry's fields rendered for `Debug` with the name-aware secret rule.
struct FieldsDebug<'a>(&'a BTreeMap<String, Field>);

impl fmt::Debug for FieldsDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(name, field)| {
                let secret = crate::visibility::is_secret(name, field.protected);
                (name, FieldDebug { field, secret })
            }))
            .finish()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("uuid", &self.uuid)
            .field("fields", &FieldsDebug(&self.fields))
            .field("tags", &self.tags)
            .field("attachments", &self.attachments)
            .field("times", &self.times)
            .field("icon", &self.icon)
            .field("foreground", &self.foreground)
            .field("background", &self.background)
            .field("override_url", &self.override_url)
            .field("quality_check", &self.quality_check)
            .field("autotype", &self.autotype)
            .field("custom_data", &self.custom_data)
            .field("previous_parent", &self.previous_parent)
            .field("history", &self.history)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Sealing: the one place that decides what plaintext a snapshot holds.

impl<'k> Sealing<'k> {
    /// The key fingerprints are computed under.
    pub fn key(&self) -> &'k FingerprintKey {
        match *self {
            Sealing::Fingerprint(key) | Sealing::Reveal(key) => key,
        }
    }

    /// Whether text values are revealed.
    pub fn reveals(&self) -> bool {
        matches!(self, Sealing::Reveal(_))
    }

    /// The snapshot form of the entry field `name` holding `plaintext`.
    ///
    /// Sealed exactly when sealing (not revealing) and the field is a secret
    /// per [`crate::visibility::is_secret`]: protected or a Password, and never
    /// the Title (an address, kept plain even when its flag is set). The
    /// protection flag is always kept as metadata.
    pub fn field(&self, name: &str, protected: bool, plaintext: &str) -> Field {
        let value = if !self.reveals() && crate::visibility::is_secret(name, protected) {
            Value::Sealed(self.key().fingerprint(Domain::Field, plaintext.as_bytes()))
        } else {
            Value::Plain(plaintext.to_owned())
        };
        Field { protected, value }
    }

    /// The snapshot form of a custom-data string value: sealed unless
    /// revealing.
    pub fn custom_text(&self, plaintext: &str, modified: Option<Timestamp>) -> CustomValue {
        let value = if self.reveals() {
            Value::Plain(plaintext.to_owned())
        } else {
            Value::Sealed(
                self.key()
                    .fingerprint(Domain::CustomData, plaintext.as_bytes()),
            )
        };
        CustomValue { value, modified }
    }

    /// The snapshot form of a custom-data binary value: always sealed (binary
    /// content is never inlined).
    pub fn custom_binary(&self, bytes: &[u8], modified: Option<Timestamp>) -> CustomValue {
        CustomValue {
            value: Value::Sealed(self.key().fingerprint(Domain::CustomData, bytes)),
            modified,
        }
    }

    /// The snapshot form of an attachment: always a fingerprint.
    pub fn attachment(&self, content: &[u8], protected: bool) -> AttachmentInfo {
        AttachmentInfo {
            size: byte_len(content),
            fingerprint: self.key().fingerprint(Domain::Attachment, content),
            protected,
        }
    }

    /// The snapshot form of a custom icon: always a fingerprint.
    pub fn custom_icon(
        &self,
        data: &[u8],
        name: Option<String>,
        modified: Option<Timestamp>,
    ) -> CustomIconInfo {
        CustomIconInfo {
            size: byte_len(data),
            fingerprint: self.key().fingerprint(Domain::CustomIcon, data),
            name,
            modified,
        }
    }
}

/// A byte length as `u64` (lossless on every supported target).
fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Timestamp and Rgb text forms.

impl Timestamp {
    /// The `chrono` format string of the text form.
    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

    /// The instant `secs` seconds after the Unix epoch, or `None` when outside
    /// the representable calendar range.
    pub fn from_unix(secs: i64) -> Option<Self> {
        chrono::DateTime::from_timestamp(secs, 0).map(|_| Timestamp(secs))
    }

    /// Seconds since the Unix epoch.
    pub fn unix(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match chrono::DateTime::from_timestamp(self.0, 0) {
            Some(t) => write!(f, "{}", t.format(Self::FORMAT)),
            // Unreachable: every Timestamp is constructed in range.
            None => Err(fmt::Error),
        }
    }
}

/// The error of parsing a [`Timestamp`] that is not `YYYY-MM-DDTHH:MM:SSZ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTimestampError;

impl fmt::Display for ParseTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a UTC timestamp of the form YYYY-MM-DDTHH:MM:SSZ")
    }
}

impl std::error::Error for ParseTimestampError {}

impl FromStr for Timestamp {
    type Err = ParseTimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = chrono::NaiveDateTime::parse_from_str(s, Self::FORMAT)
            .map_err(|_| ParseTimestampError)?;
        Ok(Timestamp(t.and_utc().timestamp()))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Rgb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }
}

/// The error of parsing an [`Rgb`] that is not `#RRGGBB`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRgbError;

impl fmt::Display for ParseRgbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a color of the form #RRGGBB")
    }
}

impl std::error::Error for ParseRgbError {}

/// Parses `#RRGGBB` (hex digits in either case).
impl FromStr for Rgb {
    type Err = ParseRgbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix('#').ok_or(ParseRgbError)?;
        let bytes = crate::codec::hex_decode(hex).ok_or(ParseRgbError)?;
        match bytes.as_slice() {
            [r, g, b] => Ok(Rgb {
                r: *r,
                g: *g,
                b: *b,
            }),
            _ => Err(ParseRgbError),
        }
    }
}

impl Serialize for Rgb {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Rgb {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn key() -> FingerprintKey {
        FingerprintKey::from_bytes([9; 32])
    }

    /// ```text
    /// Root (1)
    /// ├── e10 "A"
    /// ├── Web (2)
    /// │   ├── e20 "B"
    /// │   └── Deep (3)
    /// │       └── e30 "C"
    /// └── Mail (4)
    /// ```
    fn sample() -> Snapshot {
        let deep = Group::new(id(3), "Deep")
            .with_entry(Entry::new(id(30)).with_field("Title", Field::plain("C")));
        let web = Group::new(id(2), "Web")
            .with_entry(Entry::new(id(20)).with_field("Title", Field::plain("B")))
            .with_group(deep);
        let root = Group::new(id(1), "Root")
            .with_entry(Entry::new(id(10)).with_field("Title", Field::plain("A")))
            .with_group(web)
            .with_group(Group::new(id(4), "Mail"));
        Snapshot::new(FormatVersion::KDBX_4_1, Meta::default(), root)
    }

    #[test]
    fn walk_is_pre_order_entries_before_subgroups() {
        let snap = sample();
        let order: Vec<(u128, Option<u128>)> = snap
            .walk()
            .map(|(n, p)| (n.uuid().as_u128(), p.map(|g| g.uuid.as_u128())))
            .collect();
        assert_eq!(
            order,
            [
                (1, None),
                (10, Some(1)),
                (2, Some(1)),
                (20, Some(2)),
                (3, Some(2)),
                (30, Some(3)),
                (4, Some(1)),
            ]
        );
    }

    #[test]
    fn find_and_parent_of() {
        let snap = sample();
        assert_eq!(snap.find(id(30)).map(NodeRef::kind), Some(NodeKind::Entry));
        assert_eq!(snap.find(id(3)).and_then(NodeRef::name), Some("Deep"));
        assert_eq!(snap.find_entry(id(20)).and_then(Entry::title), Some("B"));
        assert!(snap.find_group(id(20)).is_none());
        assert!(snap.find_entry(id(2)).is_none());
        assert!(snap.find(id(99)).is_none());
        assert_eq!(snap.parent_of(id(30)).map(|g| g.uuid), Some(id(3)));
        assert_eq!(snap.parent_of(id(2)).map(|g| g.uuid), Some(id(1)));
        assert!(snap.parent_of(id(1)).is_none());
        assert!(snap.parent_of(id(99)).is_none());
        assert_eq!(snap.entries().count(), 3);
        assert_eq!(snap.groups().count(), 4);
    }

    #[test]
    fn history_items_are_not_walked() {
        let mut snap = sample();
        let old = Entry::new(id(10)).with_field("Title", Field::plain("A-old"));
        snap.root.entries[0].history.push(old);
        assert_eq!(snap.walk().count(), 7);
        assert_eq!(snap.find_entry(id(10)).and_then(Entry::title), Some("A"));
    }

    #[test]
    fn timestamp_text_form() {
        let t = Timestamp::from_unix(1_767_258_000).unwrap();
        assert_eq!(t.to_string(), "2026-01-01T09:00:00Z");
        assert_eq!("2026-01-01T09:00:00Z".parse::<Timestamp>(), Ok(t));
        assert_eq!(
            Timestamp::from_unix(0).unwrap().to_string(),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(t.unix(), 1_767_258_000);
        for bad in [
            "2026-01-01 09:00:00",
            "2026-01-01T09:00:00",
            "2026-13-01T09:00:00Z",
            "",
        ] {
            assert_eq!(
                bad.parse::<Timestamp>(),
                Err(ParseTimestampError),
                "{bad:?}"
            );
        }
        assert!(Timestamp::from_unix(i64::MAX).is_none());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"2026-01-01T09:00:00Z\"");
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), t);
    }

    #[test]
    fn rgb_text_form() {
        let c = Rgb {
            r: 0x0A,
            g: 0xBC,
            b: 0xFF,
        };
        assert_eq!(c.to_string(), "#0ABCFF");
        assert_eq!("#0abcff".parse::<Rgb>(), Ok(c));
        for bad in ["0ABCFF", "#0ABCF", "#0ABCFFF", "#GGGGGG", "#+1+1+1"] {
            assert_eq!(bad.parse::<Rgb>(), Err(ParseRgbError), "{bad:?}");
        }
        assert_eq!(serde_json::to_string(&c).unwrap(), "\"#0ABCFF\"");
    }

    #[test]
    fn sealing_fingerprint_seals_protected_fields_except_title() {
        let key = key();
        let s = Sealing::Fingerprint(&key);
        let pw = s.field("Password", true, "hunter2");
        assert!(pw.protected);
        assert_eq!(
            pw.value,
            Value::Sealed(key.fingerprint(Domain::Field, b"hunter2"))
        );
        let user = s.field("UserName", false, "alice");
        assert_eq!(user, Field::plain("alice"));
        let title = s.field("Title", true, "Bank");
        assert!(title.protected, "the flag is kept as metadata");
        assert_eq!(title.value, Value::Plain("Bank".into()));
        let pin = s.field("PIN", true, "1234");
        assert!(pin.value.is_sealed());
    }

    #[test]
    fn debug_of_a_revealed_entry_redacts_secrets() {
        let key = key();
        let s = Sealing::Reveal(&key);
        let entry = Entry::new(id(1))
            .with_field("Title", s.field("Title", true, "Bank-title"))
            .with_field("Password", s.field("Password", false, "hunter2-zq"))
            .with_field("PIN", s.field("PIN", true, "pin-zq-4821"))
            .with_field("UserName", s.field("UserName", false, "alice-zq"));
        let shown = format!("{entry:?}");
        assert!(!shown.contains("hunter2-zq"), "{shown}");
        assert!(!shown.contains("pin-zq-4821"), "{shown}");
        assert!(
            shown.contains("Bank-title") && shown.contains("alice-zq"),
            "{shown}"
        );
        // A bare Field cannot know its name, so it redacts any protected
        // plaintext.
        let field = s.field("PIN", true, "pin-zq-4821");
        assert!(!format!("{field:?}").contains("pin-zq-4821"));
        assert!(format!("{:?}", s.field("URL", false, "u-zq")).contains("u-zq"));
    }

    #[test]
    fn sealing_reveal_keeps_text_plain() {
        let key = key();
        let s = Sealing::Reveal(&key);
        assert!(s.reveals());
        let pw = s.field("Password", true, "hunter2");
        assert!(pw.protected);
        assert_eq!(pw.value.as_plain(), Some("hunter2"));
        assert_eq!(s.custom_text("v", None).value.as_plain(), Some("v"));
    }

    #[test]
    fn custom_data_and_binary_content_sealing() {
        let key = key();
        let modified = Timestamp::from_unix(5);
        for s in [Sealing::Fingerprint(&key), Sealing::Reveal(&key)] {
            let bin = s.custom_binary(b"\x00\x01", modified);
            assert_eq!(
                bin.value,
                Value::Sealed(key.fingerprint(Domain::CustomData, b"\x00\x01"))
            );
            assert_eq!(bin.modified, modified);
            let att = s.attachment(b"codes-v1", true);
            assert_eq!(
                att,
                AttachmentInfo::new(8, key.fingerprint(Domain::Attachment, b"codes-v1"), true)
            );
            let icon = s.custom_icon(b"\x89PNG", Some("i".into()), None);
            assert_eq!(
                icon.fingerprint,
                key.fingerprint(Domain::CustomIcon, b"\x89PNG")
            );
            assert_eq!(icon.size, 4);
        }
        let sealed = Sealing::Fingerprint(&key).custom_text("browser-key", None);
        assert_eq!(
            sealed.value,
            Value::Sealed(key.fingerprint(Domain::CustomData, b"browser-key"))
        );
    }

    #[test]
    fn serde_round_trip_and_value_shape() {
        let key = key();
        let mut snap = sample();
        snap.root.entries[0].fields.insert(
            "Password".into(),
            Sealing::Fingerprint(&key).field("Password", true, "pw"),
        );
        snap.root.entries[0].foreground = Some(Rgb { r: 1, g: 2, b: 3 });
        snap.root.icon = Some(Icon::Custom(id(7)));
        snap.root.times.creation = Timestamp::from_unix(0);
        snap.deleted_objects.insert(id(77), Timestamp::from_unix(1));
        let mut header = HeaderInfo::new(
            KdfInfo::Argon2(Argon2Info::new(
                Argon2Variant::Argon2id,
                64 << 20,
                3,
                2,
                0x13,
            )),
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
            Compression::GZip,
        );
        header.public_custom_data.insert("plugin".into());
        snap.header = Some(header);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains(r#""value":{"plain":"A"}"#), "{json}");
        assert!(json.contains(r#""value":{"sealed":""#), "{json}");
        assert!(!json.contains("\"pw\""), "{json}");
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn defaults_follow_kdbx() {
        let e = Entry::new(id(1));
        assert!(e.quality_check);
        assert_eq!(e.title(), None);
        assert!(GroupFlags::default().is_expanded);
        let mp = MemoryProtection::default();
        for f in StandardField::ALL {
            assert_eq!(mp.protects(f), f == StandardField::Password, "{f}");
        }
        assert_eq!(FormatVersion::KDBX_4_0.to_string(), "4.0");
        assert!(FormatVersion::KDBX_3_1 < FormatVersion::KDBX_4_0);
    }
}
