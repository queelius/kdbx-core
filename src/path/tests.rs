//! Path grammar tests. The parse/format/resolve cases are ported from
//! mcp-kdbx's `kdbx_core::path` (fix-branch version), adapted from keepass
//! databases to snapshots.

use super::*;
use crate::model::{Field, FormatVersion, Meta};
use proptest::prelude::*;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn titled(uuid: u128, title: &str) -> Entry {
    Entry::new(id(uuid)).with_field("Title", Field::plain(title))
}

fn snapshot(root: Group) -> Snapshot {
    Snapshot::new(FormatVersion::KDBX_4_1, Meta::default(), root)
}

fn names(p: &VaultPath) -> Vec<&str> {
    p.segments().iter().map(Segment::name).collect()
}

// Parsing and formatting.

#[test]
fn root_path_parses_to_empty_group_path() {
    let p = VaultPath::parse("/").expect("root parses");
    assert!(p.is_root());
    assert!(p.is_group_path());
    assert_eq!(p.format(), "/");
    assert_eq!(p, VaultPath::root());
}

#[test]
fn simple_path_round_trips() {
    let p = VaultPath::parse("/Web/Banking/MyBank").expect("parse");
    assert!(!p.is_group_path());
    assert_eq!(p.kind(), NodeKind::Entry);
    assert_eq!(p.format(), "/Web/Banking/MyBank");
}

#[test]
fn trailing_slash_marks_group_and_round_trips() {
    let with_slash = VaultPath::parse("/Web/Banking/").expect("parse group path");
    let without = VaultPath::parse("/Web/Banking").expect("parse entry path");
    assert!(with_slash.is_group_path());
    assert!(!without.is_group_path());
    // Canonical form is exact: the group marker survives formatting.
    assert_eq!(with_slash.format(), "/Web/Banking/");
    assert_eq!(without.format(), "/Web/Banking");
    assert_ne!(with_slash, without);
}

#[test]
fn escaped_slash_is_literal_in_a_segment() {
    let p = VaultPath::parse("/Web/a\\/b").expect("parse escaped slash");
    assert_eq!(p.format(), "/Web/a\\/b");
    assert_eq!(names(&p), ["Web", "a/b"]);
}

#[test]
fn escaped_backslash_is_literal_backslash() {
    let p = VaultPath::parse("/a\\\\b").expect("parse escaped backslash");
    assert_eq!(names(&p), ["a\\b"]);
    assert_eq!(p.format(), "/a\\\\b");
}

#[test]
fn ordinal_suffix_parses_and_round_trips() {
    let p = VaultPath::parse("/Web/MyBank:2").expect("parse ordinal");
    assert_eq!(names(&p), ["Web", "MyBank"]);
    assert_eq!(p.segments()[1].ordinal(), Some(2));
    assert_eq!(p.format(), "/Web/MyBank:2");
}

#[test]
fn colon_without_trailing_digits_is_part_of_the_name() {
    let p = VaultPath::parse("/http:port").expect("parse colon name");
    assert_eq!(names(&p), ["http:port"]);
    assert_eq!(p.segments()[0].ordinal(), None);
}

#[test]
fn control_characters_are_escaped_and_round_trip() {
    let p = VaultPath::group(vec![
        Segment::new("line\nbreak", None).unwrap(),
        Segment::new("tab\there\r", None).unwrap(),
        Segment::new("bidi\u{202E}esc\u{1B}", Some(2)).unwrap(),
    ]);
    let s = p.format();
    assert_eq!(
        s,
        "/line\\nbreak/tab\\there\\r/bidi\\u{202E}esc\\u{001B}:2/"
    );
    assert!(!s.chars().any(text::needs_escape));
    assert_eq!(VaultPath::parse(&s).unwrap(), p);
    // Lowercase hex is accepted on input.
    assert_eq!(names(&VaultPath::parse("/a\\u{1b}").unwrap()), ["a\u{1B}"]);
}

#[test]
fn raw_control_characters_are_accepted_on_input() {
    // Forgiving on input, canonical on output.
    let p = VaultPath::parse("/a\nb").unwrap();
    assert_eq!(names(&p), ["a\nb"]);
    assert_eq!(p.format(), "/a\\nb");
}

// Malformed input.

#[test]
fn missing_leading_slash_is_rejected() {
    assert_eq!(
        VaultPath::parse("Web/Banking"),
        Err(PathError::MissingLeadingSlash)
    );
    assert_eq!(VaultPath::parse(""), Err(PathError::MissingLeadingSlash));
}

#[test]
fn double_slash_is_rejected() {
    assert_eq!(
        VaultPath::parse("/Web//Banking"),
        Err(PathError::EmptySegment)
    );
    assert_eq!(VaultPath::parse("//"), Err(PathError::EmptySegment));
}

#[test]
fn dangling_backslash_is_rejected() {
    assert_eq!(
        VaultPath::parse("/Web/a\\"),
        Err(PathError::Escape(UnescapeError::DanglingBackslash))
    );
}

#[test]
fn unknown_and_malformed_escapes_are_rejected() {
    assert_eq!(
        VaultPath::parse("/a\\qb"),
        Err(PathError::Escape(UnescapeError::UnknownEscape('q')))
    );
    assert_eq!(
        VaultPath::parse("/a\\u{110000}"),
        Err(PathError::Escape(UnescapeError::InvalidCodePoint))
    );
}

#[test]
fn zero_and_huge_ordinals_are_rejected() {
    assert_eq!(
        VaultPath::parse("/Web/MyBank:0"),
        Err(PathError::ZeroOrdinal)
    );
    assert_eq!(
        VaultPath::parse("/Web/MyBank:99999999999999999999999999"),
        Err(PathError::OrdinalOverflow)
    );
}

#[test]
fn constructors_validate() {
    assert_eq!(Segment::new("", None), Err(PathError::EmptySegment));
    assert_eq!(Segment::new("a", Some(0)), Err(PathError::ZeroOrdinal));
    assert_eq!(VaultPath::entry(vec![]), Err(PathError::EmptyEntryPath));
    assert_eq!(VaultPath::group(vec![]), VaultPath::root());
}

// NFC normalization, isolated from a snapshot.

#[test]
fn nfc_composes_decomposed_accent() {
    let decomposed = "Caf\u{0065}\u{0301}";
    let precomposed = "Caf\u{00e9}";
    assert_ne!(decomposed, precomposed);
    assert_eq!(nfc(decomposed), nfc(precomposed));
    assert_eq!(nfc(decomposed), precomposed);
}

#[test]
fn nfc_handles_non_latin_and_multi_mark_cases() {
    let a = "q\u{0323}\u{0301}";
    let b = "q\u{0301}\u{0323}";
    assert_ne!(a, b);
    assert_eq!(nfc(a), nfc(b));
    let decomposed = "\u{03B1}\u{0301}";
    let precomposed = "\u{03AC}";
    assert_eq!(nfc(decomposed), precomposed);
}

// Resolution against a snapshot.

/// ```text
/// /                     root (1)
/// /Web/                 group (2)
/// /Web/Banking/         group (3)
/// /Web/Banking/MyBank   entry (30)
/// /Web/Dup              entry (21, username "first")
/// /Web/Dup              entry (20, username "second"; smaller UUID, listed later)
/// /Café/                group (4), name stored precomposed
/// ```
fn build_snap() -> Snapshot {
    let banking = Group::new(id(3), "Banking").with_entry(titled(30, "MyBank"));
    let web = Group::new(id(2), "Web")
        .with_group(banking)
        .with_entry(titled(21, "Dup").with_field("UserName", Field::plain("first")))
        .with_entry(titled(20, "Dup").with_field("UserName", Field::plain("second")));
    let root = Group::new(id(1), "Root")
        .with_group(web)
        .with_group(Group::new(id(4), "Caf\u{00e9}"));
    snapshot(root)
}

fn resolve_uuid(snap: &Snapshot, path: &str) -> Result<Uuid, ResolveError> {
    VaultPath::parse(path)
        .unwrap()
        .resolve(snap)
        .map(NodeRef::uuid)
}

#[test]
fn root_resolves_to_root_group() {
    let snap = build_snap();
    assert_eq!(resolve_uuid(&snap, "/"), Ok(id(1)));
}

#[test]
fn nested_group_path_resolves() {
    let snap = build_snap();
    let node = VaultPath::parse("/Web/Banking/")
        .unwrap()
        .resolve(&snap)
        .unwrap();
    assert_eq!(node.kind(), NodeKind::Group);
    assert_eq!(node.name(), Some("Banking"));
}

#[test]
fn group_without_trailing_slash_still_resolves_via_resolve_group() {
    let snap = build_snap();
    // The generic resolve() respects the kind: no trailing slash means an
    // entry, and there is no entry named Banking.
    assert_eq!(
        resolve_uuid(&snap, "/Web/Banking"),
        Err(ResolveError::EntryNotFound)
    );
    for p in ["/Web", "/Web/", "/Web/Banking", "/Web/Banking/"] {
        let g = VaultPath::parse(p)
            .unwrap()
            .resolve_group(&snap)
            .unwrap_or_else(|e| panic!("{p}: {e}"));
        assert!(
            g.name == "Web" || g.name == "Banking",
            "{p} resolved to {}",
            g.name
        );
    }
    assert_eq!(VaultPath::root().resolve_group(&snap).unwrap().uuid, id(1));
}

#[test]
fn resolve_entry_forces_entry_kind() {
    let snap = build_snap();
    assert_eq!(
        VaultPath::parse("/Web").unwrap().resolve_entry(&snap),
        Err(ResolveError::EntryNotFound)
    );
    assert_eq!(
        VaultPath::parse("/Web/Banking/MyBank")
            .unwrap()
            .resolve_entry(&snap)
            .unwrap()
            .uuid,
        id(30)
    );
    assert_eq!(
        VaultPath::root().resolve_entry(&snap),
        Err(ResolveError::GroupShapedPath)
    );
}

#[test]
fn missing_group_segment_is_group_not_found_with_its_index() {
    let snap = build_snap();
    assert_eq!(
        resolve_uuid(&snap, "/Web/Nope/MyBank"),
        Err(ResolveError::GroupNotFound { segment: 1 })
    );
    assert_eq!(
        resolve_uuid(&snap, "/Nope/"),
        Err(ResolveError::GroupNotFound { segment: 0 })
    );
}

#[test]
fn missing_entry_is_entry_not_found() {
    let snap = build_snap();
    assert_eq!(
        resolve_uuid(&snap, "/Web/Banking/Ghost"),
        Err(ResolveError::EntryNotFound)
    );
}

#[test]
fn path_injection_simply_fails_to_resolve() {
    let snap = build_snap();
    assert_eq!(
        resolve_uuid(&snap, "/../../etc"),
        Err(ResolveError::GroupNotFound { segment: 0 })
    );
    assert_eq!(
        resolve_uuid(&snap, "/Web/..%2F..%2Fetc%2Fpasswd"),
        Err(ResolveError::EntryNotFound)
    );
    // An escaped slash is part of one name, never a traversal.
    assert_eq!(
        resolve_uuid(&snap, "/Web\\/Banking/MyBank"),
        Err(ResolveError::GroupNotFound { segment: 0 })
    );
}

#[test]
fn duplicate_siblings_are_ordered_by_uuid_not_document_order() {
    let snap = build_snap();
    // Entry 20 is listed after 21 but has the smaller UUID, so it is :1.
    assert_eq!(resolve_uuid(&snap, "/Web/Dup"), Ok(id(20)));
    assert_eq!(resolve_uuid(&snap, "/Web/Dup:1"), Ok(id(20)));
    assert_eq!(resolve_uuid(&snap, "/Web/Dup:2"), Ok(id(21)));
    assert_eq!(
        resolve_uuid(&snap, "/Web/Dup:3"),
        Err(ResolveError::EntryNotFound)
    );
}

#[test]
fn ordinals_are_clone_consistent() {
    let snap = build_snap();
    let clone = snap.clone();
    for p in ["/Web/Dup:1", "/Web/Dup:2"] {
        assert_eq!(resolve_uuid(&snap, p), resolve_uuid(&clone, p));
    }
}

#[test]
fn nfc_normalized_group_name_resolves() {
    let snap = build_snap();
    let g = VaultPath::parse("/Caf\u{0065}\u{0301}/")
        .unwrap()
        .resolve_group(&snap)
        .expect("decomposed name resolves to precomposed group");
    assert_eq!(g.uuid, id(4));
}

#[test]
fn literal_colon_digit_title_round_trips() {
    for (input, want_name) in [
        ("/A/Build\\:2", "Build:2"),
        ("/Server\\:8080", "Server:8080"),
    ] {
        let once = VaultPath::parse(input).expect("parse");
        let last = once.segments().last().expect("a segment");
        assert_eq!(last.name(), want_name);
        assert!(last.ordinal().is_none(), "{input}");
        let formatted = once.format();
        assert_eq!(
            VaultPath::parse(&formatted).unwrap(),
            once,
            "{input} -> {formatted}"
        );
    }
}

#[test]
fn escaped_colon_is_a_literal_colon_not_an_ordinal() {
    let p = VaultPath::parse("/Build\\:2").expect("parse escaped colon");
    assert_eq!(names(&p), ["Build:2"]);
    assert_eq!(p.segments()[0].ordinal(), None);
    assert_eq!(p.format(), "/Build\\:2");
}

#[test]
fn literal_colon_digit_title_resolves_to_that_entry_not_an_ordinal() {
    let a = Group::new(id(2), "A")
        .with_entry(titled(10, "Build:2").with_field("UserName", Field::plain("literal")))
        .with_entry(titled(11, "Build"))
        .with_entry(titled(12, "Build"));
    let snap = snapshot(Group::new(id(1), "Root").with_group(a));
    assert_eq!(resolve_uuid(&snap, "/A/Build:2"), Ok(id(12)));
    assert_eq!(resolve_uuid(&snap, "/A/Build\\:2"), Ok(id(10)));
    assert_eq!(path_of(&snap, id(10)).unwrap().format(), "/A/Build\\:2");
    assert_eq!(path_of(&snap, id(12)).unwrap().format(), "/A/Build:2");
}

// Inverse: path_of.

#[test]
fn path_of_entry_round_trips_and_resolves_back() {
    let snap = build_snap();
    let path = path_of(&snap, id(30)).expect("entry has a path");
    assert_eq!(path.format(), "/Web/Banking/MyBank");
    assert!(!path.is_group_path());
    assert_eq!(path.resolve(&snap).map(NodeRef::uuid), Ok(id(30)));
}

#[test]
fn path_of_group_round_trips_and_root_is_slash() {
    let snap = build_snap();
    let path = path_of(&snap, id(3)).expect("group has a path");
    assert_eq!(path.format(), "/Web/Banking/");
    assert!(path.is_group_path());
    assert_eq!(path.resolve(&snap).map(NodeRef::uuid), Ok(id(3)));
    let root = path_of(&snap, id(1)).expect("root path");
    assert!(root.is_root());
    assert_eq!(root.format(), "/");
}

#[test]
fn path_of_disambiguates_duplicate_siblings() {
    let snap = build_snap();
    assert_eq!(path_of(&snap, id(20)).unwrap().format(), "/Web/Dup:1");
    assert_eq!(path_of(&snap, id(21)).unwrap().format(), "/Web/Dup:2");
}

#[test]
fn groups_and_entries_have_separate_ordinal_namespaces() {
    // A group and an entry sharing a name need no ordinal: the trailing slash
    // tells them apart.
    let root = Group::new(id(1), "Root")
        .with_group(Group::new(id(2), "Email"))
        .with_entry(titled(3, "Email"));
    let snap = snapshot(root);
    assert_eq!(path_of(&snap, id(2)).unwrap().format(), "/Email/");
    assert_eq!(path_of(&snap, id(3)).unwrap().format(), "/Email");
    assert_eq!(resolve_uuid(&snap, "/Email/"), Ok(id(2)));
    assert_eq!(resolve_uuid(&snap, "/Email"), Ok(id(3)));
}

#[test]
fn parent_drops_last_segment_as_group_path() {
    let entry = VaultPath::parse("/Web/Banking/MyBank").unwrap();
    let parent = entry.parent();
    assert!(parent.is_group_path());
    assert_eq!(parent.format(), "/Web/Banking/");
    assert_eq!(VaultPath::parse("/MyBank").unwrap().parent().format(), "/");
    assert!(VaultPath::root().parent().is_root());
}

// Aliasing: an emitted path never resolves to a different record.

/// A root entry titled "Email" plus a group "Email" holding an untitled
/// entry (the shape of the mcp-kdbx review probe).
fn snap_with_untitled_entry_in_same_named_group() -> Snapshot {
    let email = Group::new(id(2), "Email").with_entry(Entry::new(id(20)));
    snapshot(
        Group::new(id(1), "Root")
            .with_entry(titled(10, "Email"))
            .with_group(email),
    )
}

#[test]
fn untitled_entry_has_no_path() {
    let snap = snap_with_untitled_entry_in_same_named_group();
    assert!(path_of(&snap, id(20)).is_none());
    // An entry whose Title is present but empty has none either.
    let mut snap = snap;
    snap.root.groups[0].entries[0]
        .fields
        .insert("Title".into(), Field::plain(""));
    assert!(path_of(&snap, id(20)).is_none());
}

#[test]
fn unnamed_group_has_no_path_and_neither_do_its_entries() {
    let unnamed = Group::new(id(2), "").with_entry(titled(20, "Inside"));
    let snap = snapshot(Group::new(id(1), "Root").with_group(unnamed));
    assert!(path_of(&snap, id(2)).is_none());
    assert!(path_of(&snap, id(20)).is_none());
}

#[test]
fn root_name_is_never_part_of_a_path() {
    // Even an unnamed root has the root path.
    let snap = snapshot(Group::new(id(1), "").with_entry(titled(2, "A")));
    assert_eq!(path_of(&snap, id(1)).unwrap().format(), "/");
    assert_eq!(path_of(&snap, id(2)).unwrap().format(), "/A");
}

#[test]
fn resolve_entry_rejects_a_group_shaped_path() {
    let snap = snap_with_untitled_entry_in_same_named_group();
    assert_eq!(
        VaultPath::parse("/Email/").unwrap().resolve_entry(&snap),
        Err(ResolveError::GroupShapedPath)
    );
    assert_eq!(resolve_uuid(&snap, "/Email"), Ok(id(10)));
}

#[test]
fn every_emitted_path_resolves_back_to_its_own_node() {
    let awkward = [
        "a/b",
        "back\\slash",
        "Build:2",
        ":3",
        "Email",
        "Email",
        "trailing ",
        "new\nline",
        "\u{202E}rtl",
    ];
    let mut root = Group::new(id(1), "Root").with_entry(titled(10, "Email"));
    for (i, title) in awkward.iter().enumerate() {
        root = root.with_entry(titled(100 + i as u128, title));
        root = root.with_group(Group::new(id(200 + i as u128), *title));
    }
    root = root
        .with_group(Group::new(id(2), "Email").with_entry(Entry::new(id(20))))
        .with_group(Group::new(id(3), "").with_entry(titled(30, "Lost")));
    let snap = snapshot(root);

    let mut with_path = 0;
    for (node, _) in snap.walk() {
        if let Some(p) = path_of(&snap, node.uuid()) {
            with_path += 1;
            let reparsed = VaultPath::parse(&p.format()).expect("emitted path parses");
            assert_eq!(reparsed, p);
            assert_eq!(
                reparsed.resolve(&snap).map(NodeRef::uuid),
                Ok(node.uuid()),
                "path {p} aliases another node"
            );
        }
    }
    // Root, root "Email", 9 awkward entries, 9 awkward groups, group "Email".
    // The untitled entry, the unnamed group, and its entry have none.
    assert_eq!(with_path, 21);
}

#[test]
fn unknown_uuid_has_no_path() {
    let snap = build_snap();
    assert!(path_of(&snap, id(999)).is_none());
}

#[test]
fn serde_uses_the_canonical_string() {
    let p = VaultPath::parse("/Web/Dup:2").unwrap();
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(json, r#""/Web/Dup:2""#);
    assert_eq!(serde_json::from_str::<VaultPath>(&json).unwrap(), p);
    assert!(serde_json::from_str::<VaultPath>(r#""no-slash""#).is_err());
}

// Property tests.

fn segment() -> impl Strategy<Value = Segment> {
    let name = prop_oneof![
        any::<String>(),
        "[a-c/:\\\\0-9 ]{1,6}",
        "[a-c]{1,3}:[0-9]{1,3}",
    ]
    .prop_filter("non-empty", |s| !s.is_empty());
    (name, proptest::option::of(1usize..1000))
        .prop_map(|(name, ordinal)| Segment::new(name, ordinal).expect("valid segment"))
}

fn vault_path() -> impl Strategy<Value = VaultPath> {
    (proptest::collection::vec(segment(), 0..5), any::<bool>()).prop_map(|(segments, group)| {
        if group || segments.is_empty() {
            VaultPath::group(segments)
        } else {
            VaultPath::entry(segments).expect("non-empty")
        }
    })
}

proptest! {
    #[test]
    fn parse_inverts_format(p in vault_path()) {
        let s = p.format();
        prop_assert!(!s.chars().any(text::needs_escape), "{s:?}");
        prop_assert_eq!(VaultPath::parse(&s), Ok(p));
    }

    #[test]
    fn sibling_paths_never_alias(
        entry_names in proptest::collection::vec("[ab:1/\\\\]{0,3}", 0..8),
        group_names in proptest::collection::vec("[ab:1/\\\\]{0,3}", 0..8),
    ) {
        let mut inner = Group::new(id(2), "inner");
        let mut root = Group::new(id(1), "Root");
        for (i, name) in entry_names.iter().enumerate() {
            // Interleave UUID order against document order.
            let n = 1000 - i as u128;
            root = root.with_entry(titled(n, name));
            inner = inner.with_entry(titled(n + 5000, name));
        }
        for (i, name) in group_names.iter().enumerate() {
            root = root.with_group(Group::new(id(2000 + i as u128), name.as_str()));
        }
        let snap = snapshot(root.with_group(inner));
        for (node, parent) in snap.walk() {
            let named = node.name().is_some_and(|n| !n.is_empty())
                && parent.is_none_or(|p| p.uuid == id(1) || !p.name.is_empty());
            match path_of(&snap, node.uuid()) {
                Some(p) => {
                    prop_assert!(named || node.uuid() == id(1));
                    let back = VaultPath::parse(&p.format()).unwrap().resolve(&snap).map(NodeRef::uuid);
                    prop_assert_eq!(back, Ok(node.uuid()), "{}", p);
                }
                None => prop_assert!(!named),
            }
        }
    }
}
