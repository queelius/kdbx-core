//! The ecosystem's vault path grammar.
//!
//! A vault path addresses a group or an entry of a [`Snapshot`] the way a
//! filesystem path addresses a file. Every member parses, formats and resolves
//! paths through this module, so a path printed by one member means the same
//! record in every other.
//!
//! # Grammar
//!
//! - A path starts with `/`, which is the root group. The root group's own
//!   name is never part of a path.
//! - `/` separates segments. A group segment is the group's name; an entry
//!   segment is the entry's Title.
//! - Inside a segment, `\/` is a literal slash, `\\` a literal backslash and
//!   `\:` a literal colon. The control-character escapes of
//!   [`crate::text`] (`\n`, `\t`, `\r`, `\u{XXXX}`) also apply, so a formatted
//!   path is always one printable line.
//! - A segment may end in `:N` (1-based) to pick among same-named siblings of
//!   the same kind, ordered by UUID (not document order, so the meaning of an
//!   ordinal never depends on how a database stores its children). A bare
//!   name means `:1`.
//! - A trailing `/` marks a group path. The root path `/` is a group path.
//! - Names compare case-sensitively after Unicode NFC normalization.
//! - A node with an empty name, or under a group with an empty name, has no
//!   path ([`path_of`] returns `None`): an empty segment would alias its
//!   parent. Such nodes are addressed by UUID.
//!
//! [`VaultPath::format`] is canonical and exact: `parse(format(p)) == p`, and
//! group paths keep their trailing `/`. Paths are canonical values: names are
//! held NFC-normalized and `:1` is held as a bare name, so paths that resolve
//! alike compare equal and format identically. `parse` accepts some
//! non-canonical spellings (raw control characters, lowercase or
//! unnecessary `\u{...}` escapes, `\:` on a colon that needs no escape,
//! `:1`), and `format` always emits the canonical one.
//!
//! Resolution never touches a filesystem: `/../../etc` is just a group named
//! `..` that does not exist.
//!
//! ```
//! use kdbx_core::model::{Entry, Field, FormatVersion, Group, Meta, Snapshot};
//! use kdbx_core::path::{path_of, VaultPath};
//! use uuid::Uuid;
//!
//! let web = Group::new(Uuid::from_u128(2), "Web")
//!     .with_entry(Entry::new(Uuid::from_u128(3)).with_field("Title", Field::plain("a/b")));
//! let snap = Snapshot::new(
//!     FormatVersion::KDBX_4_1,
//!     Meta::default(),
//!     Group::new(Uuid::from_u128(1), "Root").with_group(web),
//! );
//!
//! let path = path_of(&snap, Uuid::from_u128(3)).unwrap();
//! assert_eq!(path.format(), "/Web/a\\/b");
//! let found = VaultPath::parse("/Web/a\\/b").unwrap().resolve(&snap).unwrap();
//! assert_eq!(found.uuid(), Uuid::from_u128(3));
//! assert_eq!(path_of(&snap, Uuid::from_u128(2)).unwrap().format(), "/Web/");
//! ```

use std::fmt;
use std::str::{Chars, FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::model::{Entry, Group, NodeKind, NodeRef, Snapshot};
use crate::text::{self, UnescapeError};

/// A parsed vault path: segments root-first, plus whether it addresses a group
/// or an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultPath {
    segments: Vec<Segment>,
    kind: NodeKind,
}

/// One path segment: a non-empty record name and an optional 1-based ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Segment {
    name: String,
    ordinal: Option<usize>,
}

/// Why a path string (or a segment) is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathError {
    /// The path does not start with `/`.
    MissingLeadingSlash,
    /// The path contains an empty segment (`//`), or a segment was built with
    /// an empty name.
    EmptySegment,
    /// A backslash escape is malformed (dangling, unknown, or a bad
    /// `\u{...}`).
    Escape(UnescapeError),
    /// A `:0` ordinal (ordinals are 1-based).
    ZeroOrdinal,
    /// An ordinal too large to represent.
    OrdinalOverflow,
    /// An entry path was built with no segments (only the root group has the
    /// empty path).
    EmptyEntryPath,
}

/// Why a well-formed path matched nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolveError {
    /// Segment `segment` (0-based) names no group at its level.
    GroupNotFound {
        /// Index of the segment that matched no group.
        segment: usize,
    },
    /// The final segment names no entry in its group.
    EntryNotFound,
    /// An entry was required but the path is group-shaped (it ends in `/`, or
    /// it is the root path): a trailing slash never names an entry.
    GroupShapedPath,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::MissingLeadingSlash => f.write_str("path must start with '/'"),
            PathError::EmptySegment => f.write_str("path contains an empty segment"),
            PathError::Escape(e) => write!(f, "malformed escape in path: {e}"),
            PathError::ZeroOrdinal => f.write_str("ordinal ':N' is 1-based; ':0' is not valid"),
            PathError::OrdinalOverflow => f.write_str("ordinal ':N' is too large"),
            PathError::EmptyEntryPath => f.write_str("an entry path needs at least one segment"),
        }
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PathError::Escape(e) => Some(e),
            _ => None,
        }
    }
}

impl From<UnescapeError> for PathError {
    fn from(e: UnescapeError) -> Self {
        PathError::Escape(e)
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::GroupNotFound { segment } => {
                write!(f, "path segment {} names no group", segment + 1)
            }
            ResolveError::EntryNotFound => f.write_str("the final path segment names no entry"),
            ResolveError::GroupShapedPath => {
                f.write_str("a path ending in '/' addresses a group, not an entry")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

impl Segment {
    /// A segment named `name`, optionally with a 1-based ordinal.
    ///
    /// Segments are canonical: the name is stored NFC-normalized and an
    /// ordinal of 1 is stored as none (a bare name means `:1`), so two
    /// segments that resolve alike compare equal and format identically.
    pub fn new(name: impl Into<String>, ordinal: Option<usize>) -> Result<Self, PathError> {
        let name: String = name.into();
        if name.is_empty() {
            return Err(PathError::EmptySegment);
        }
        let ordinal = match ordinal {
            Some(0) => return Err(PathError::ZeroOrdinal),
            Some(1) | None => None,
            Some(n) => Some(n),
        };
        Ok(Segment {
            name: nfc(&name),
            ordinal,
        })
    }

    /// The record name (escapes decoded, ordinal stripped).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `:N` ordinal when it is 2 or more; `None` means the first (or only)
    /// sibling of that name.
    pub fn ordinal(&self) -> Option<usize> {
        self.ordinal
    }
}

impl VaultPath {
    /// The root path `/`.
    pub fn root() -> Self {
        VaultPath {
            segments: Vec::new(),
            kind: NodeKind::Group,
        }
    }

    /// The group path with these segments (no segments: the root).
    pub fn group(segments: Vec<Segment>) -> Self {
        VaultPath {
            segments,
            kind: NodeKind::Group,
        }
    }

    /// The entry path with these segments; at least one is required.
    pub fn entry(segments: Vec<Segment>) -> Result<Self, PathError> {
        if segments.is_empty() {
            return Err(PathError::EmptyEntryPath);
        }
        Ok(VaultPath {
            segments,
            kind: NodeKind::Entry,
        })
    }

    /// Parse a path string.
    pub fn parse(input: &str) -> Result<Self, PathError> {
        parse(input)
    }

    /// The canonical string form. Exact inverse of [`VaultPath::parse`]: group
    /// paths other than the root end in `/`.
    pub fn format(&self) -> String {
        format_path(self)
    }

    /// The segments, root-first.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether the path addresses a group or an entry.
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// True for a group path (it ends in `/`, or it is the root).
    pub fn is_group_path(&self) -> bool {
        self.kind == NodeKind::Group
    }

    /// True for the root path `/`.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// The containing group's path (the root's parent is the root).
    pub fn parent(&self) -> VaultPath {
        let mut segments = self.segments.clone();
        segments.pop();
        VaultPath::group(segments)
    }

    /// Resolve against `snap`: a group path to a group, an entry path to an
    /// entry.
    pub fn resolve<'s>(&self, snap: &'s Snapshot) -> Result<NodeRef<'s>, ResolveError> {
        match self.kind {
            NodeKind::Group => self.resolve_group(snap).map(NodeRef::Group),
            NodeKind::Entry => self.resolve_entry(snap).map(NodeRef::Entry),
        }
    }

    /// Resolve every segment, including the last, as a group. An entry-shaped
    /// path is accepted: `/Web` and `/Web/` both name the group `Web` here.
    pub fn resolve_group<'s>(&self, snap: &'s Snapshot) -> Result<&'s Group, ResolveError> {
        resolve_groups(&snap.root, &self.segments)
    }

    /// Resolve to an entry. Group-shaped paths are refused with
    /// [`ResolveError::GroupShapedPath`].
    pub fn resolve_entry<'s>(&self, snap: &'s Snapshot) -> Result<&'s Entry, ResolveError> {
        let Some((last, groups)) = self.segments.split_last() else {
            return Err(ResolveError::GroupShapedPath);
        };
        if self.kind == NodeKind::Group {
            return Err(ResolveError::GroupShapedPath);
        }
        let parent = resolve_groups(&snap.root, groups)?;
        pick(&parent.entries, last, entry_name, |e| e.uuid).ok_or(ResolveError::EntryNotFound)
    }
}

/// The canonical path of the group or entry `uuid`, or `None` when `uuid` is
/// unknown or the node (or an ancestor) has an empty name.
///
/// The returned path formats, parses and resolves back to exactly this node,
/// in this snapshot and in any snapshot with the same tree.
pub fn path_of(snap: &Snapshot, uuid: Uuid) -> Option<VaultPath> {
    if snap.root.uuid == uuid {
        return Some(VaultPath::root());
    }
    let mut chain = Vec::new();
    let node = locate(&snap.root, uuid, &mut chain)?;
    // chain[0] is the root (never named); each later group is named among its
    // parent's child groups.
    let mut segments = chain
        .windows(2)
        .map(|pair| {
            let (parent, group) = (pair[0], pair[1]);
            segment_for(&parent.groups, group.uuid, &group.name, group_name, |g| {
                g.uuid
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let parent = chain.last()?;
    match node {
        NodeRef::Group(g) => {
            segments.push(segment_for(
                &parent.groups,
                g.uuid,
                &g.name,
                group_name,
                |g| g.uuid,
            )?);
            Some(VaultPath::group(segments))
        }
        NodeRef::Entry(e) => {
            let title = entry_name(e);
            segments.push(segment_for(
                &parent.entries,
                e.uuid,
                title,
                entry_name,
                |e| e.uuid,
            )?);
            VaultPath::entry(segments).ok()
        }
    }
}

impl fmt::Display for VaultPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format())
    }
}

impl FromStr for VaultPath {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VaultPath::parse(s)
    }
}

/// Serializes as the canonical string form.
impl Serialize for VaultPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.format())
    }
}

impl<'de> Deserialize<'de> for VaultPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Implementation.

fn parse(input: &str) -> Result<VaultPath, PathError> {
    let rest = input
        .strip_prefix('/')
        .ok_or(PathError::MissingLeadingSlash)?;

    // Split at unescaped `/`, keeping escape sequences verbatim in each raw
    // segment: decoding happens per segment, after the ordinal scan, so that
    // scan can tell an escaped colon (`\:`) from an ordinal separator.
    let mut raw_segments: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '/' {
            raw_segments.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if escaped {
        return Err(UnescapeError::DanglingBackslash.into());
    }
    raw_segments.push(current);

    // A trailing slash leaves a final empty raw segment: the group marker. The
    // bare root `/` leaves exactly that one empty segment.
    let kind = if raw_segments.last().is_some_and(String::is_empty) {
        raw_segments.pop();
        NodeKind::Group
    } else {
        NodeKind::Entry
    };
    // Any other empty raw segment is a `//`: a name the grammar cannot spell.
    if raw_segments.iter().any(String::is_empty) {
        return Err(PathError::EmptySegment);
    }

    let segments = raw_segments
        .iter()
        .map(|raw| parse_segment(raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VaultPath { segments, kind })
}

/// Parse one raw (still escaped, non-empty) segment into a name and ordinal.
///
/// The `:N` suffix is an unescaped colon followed by ASCII digits, with a
/// non-empty name before it; anything else is part of the name.
fn parse_segment(raw: &str) -> Result<Segment, PathError> {
    let (name, ordinal) = match split_ordinal_suffix(raw) {
        Some((name, digits)) => {
            let n: usize = digits.parse().map_err(|_| PathError::OrdinalOverflow)?;
            if n == 0 {
                return Err(PathError::ZeroOrdinal);
            }
            (name, Some(n))
        }
        None => (raw, None),
    };
    Segment::new(unescape_segment(name)?, ordinal)
}

/// Split `raw` into `(name, digits)` when it ends in an unescaped `:` followed
/// by one or more ASCII digits and preceded by a non-empty name.
fn split_ordinal_suffix(raw: &str) -> Option<(&str, &str)> {
    let colon = raw.rfind(':')?;
    if colon == 0 || colon_is_escaped(raw, colon) {
        return None;
    }
    let digits = &raw[colon + 1..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&raw[..colon], digits))
}

/// True when the colon at byte `colon` is preceded by an odd run of
/// backslashes (so it is the escape `\:`).
fn colon_is_escaped(raw: &str, colon: usize) -> bool {
    let backslashes = raw[..colon]
        .bytes()
        .rev()
        .take_while(|&b| b == b'\\')
        .count();
    backslashes % 2 == 1
}

/// Decode a raw segment's escapes: the path grammar's own `\/` and `\:`, then
/// the shared escapes of [`crate::text`].
fn unescape_segment(raw: &str) -> Result<String, PathError> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let next = chars.next().ok_or(UnescapeError::DanglingBackslash)?;
        let decoded = match next {
            '/' | ':' => next,
            _ => decode_shared_escape(next, &mut chars)?,
        };
        out.push(decoded);
    }
    Ok(out)
}

fn decode_shared_escape(next: char, rest: &mut Chars<'_>) -> Result<char, PathError> {
    let decoded =
        text::decode_escape(next, rest).unwrap_or(Err(UnescapeError::UnknownEscape(next)));
    Ok(decoded?)
}

fn format_path(path: &VaultPath) -> String {
    let mut out = String::new();
    for seg in &path.segments {
        out.push('/');
        format_segment(seg, &mut out);
    }
    if path.kind == NodeKind::Group || path.segments.is_empty() {
        out.push('/');
    }
    out
}

/// Append a segment's escaped form: `/` as `\/`, everything else through
/// [`text`]'s escape, and the `:N` suffix. A name that itself ends in
/// `:<digits>` gets that colon escaped so it cannot re-parse as an ordinal.
fn format_segment(seg: &Segment, out: &mut String) {
    let start = out.len();
    for ch in seg.name.chars() {
        if ch == '/' {
            out.push_str("\\/");
        } else {
            text::push_escaped(ch, out);
        }
    }
    if seg.ordinal.is_none() && name_ends_like_ordinal(&seg.name) {
        // Escapes never produce a colon, so the last colon written is the
        // name's own trailing one.
        if let Some(colon) = out[start..].rfind(':') {
            out.insert(start + colon, '\\');
        }
    }
    if let Some(n) = seg.ordinal {
        out.push(':');
        out.push_str(&n.to_string());
    }
}

/// True when `name`, written with no ordinal, would re-parse as carrying one.
fn name_ends_like_ordinal(name: &str) -> bool {
    match name.rfind(':') {
        Some(colon) if colon > 0 => {
            let digits = &name[colon + 1..];
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// A group's path name.
fn group_name(g: &Group) -> &str {
    &g.name
}

/// An entry's path name: its Title, or empty (unaddressable) without one.
fn entry_name(e: &Entry) -> &str {
    e.title().unwrap_or("")
}

/// Unicode NFC, the normalization names are compared under.
fn nfc(s: &str) -> String {
    s.nfc().collect()
}

fn resolve_groups<'s>(root: &'s Group, segments: &[Segment]) -> Result<&'s Group, ResolveError> {
    segments
        .iter()
        .enumerate()
        .try_fold(root, |group, (index, seg)| {
            pick(&group.groups, seg, group_name, |g| g.uuid)
                .ok_or(ResolveError::GroupNotFound { segment: index })
        })
}

/// The sibling named by `seg`: among `items` whose name (under `name_of`)
/// equals the segment's name after NFC, ordered by UUID, the one at the
/// segment's ordinal.
fn pick<'s, T>(
    items: &'s [T],
    seg: &Segment,
    name_of: impl Fn(&T) -> &str,
    uuid_of: impl Fn(&T) -> Uuid,
) -> Option<&'s T> {
    let wanted = nfc(&seg.name);
    let mut matches: Vec<&T> = items
        .iter()
        .filter(|it| nfc(name_of(it)) == wanted)
        .collect();
    matches.sort_by_key(|it| uuid_of(it));
    matches.get(seg.ordinal.unwrap_or(1) - 1).copied()
}

/// The segment naming `target` among `siblings`: its name, plus an ordinal
/// only when another sibling shares the name. `None` for an empty name.
fn segment_for<T>(
    siblings: &[T],
    target: Uuid,
    name: &str,
    name_of: impl Fn(&T) -> &str,
    uuid_of: impl Fn(&T) -> Uuid,
) -> Option<Segment> {
    if name.is_empty() {
        return None;
    }
    let wanted = nfc(name);
    let mut same: Vec<Uuid> = siblings
        .iter()
        .filter(|it| nfc(name_of(it)) == wanted)
        .map(uuid_of)
        .collect();
    same.sort();
    let ordinal = match same.len() {
        0 | 1 => None,
        _ => Some(same.iter().position(|u| *u == target)? + 1),
    };
    Segment::new(name, ordinal).ok()
}

/// Find `target` under `group`, pushing each group descended into onto
/// `chain` (left holding the target's ancestors, root first).
fn locate<'s>(group: &'s Group, target: Uuid, chain: &mut Vec<&'s Group>) -> Option<NodeRef<'s>> {
    chain.push(group);
    if let Some(entry) = group.entries.iter().find(|e| e.uuid == target) {
        return Some(NodeRef::Entry(entry));
    }
    for child in &group.groups {
        if child.uuid == target {
            return Some(NodeRef::Group(child));
        }
        if let Some(found) = locate(child, target, chain) {
            return Some(found);
        }
    }
    chain.pop();
    None
}

#[cfg(test)]
mod tests;
