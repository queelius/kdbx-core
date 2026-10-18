//! Line-safe rendering of vault text.
//!
//! Every member that prints vault content line by line (a diff, a textconv
//! dump, a log line) renders values through this module, so no value can forge
//! an output line or smuggle a terminal control sequence.
//!
//! - Single-line contexts (names, tags, paths, short values) use
//!   [`escape_inline`]: the result is always one printable line.
//! - Multi-line values (Notes) use [`continuation_lines`]: one output line per
//!   value line, each starting with a fixed caller-chosen prefix, so git still
//!   diffs the value line by line and no value line can begin like a
//!   structural line.
//!
//! # Escapes
//!
//! | Input | Output |
//! |---|---|
//! | `\` | `\\` |
//! | line feed | `\n` |
//! | tab | `\t` |
//! | carriage return | `\r` |
//! | any other character that [`needs_escape`] | `\u{XXXX}` (uppercase hex, at least 4 digits) |
//!
//! [`unescape_inline`] reverses [`escape_inline`] exactly.
//!
//! ```
//! use kdbx_core::text::{continuation_lines, escape_inline, unescape_inline};
//!
//! assert_eq!(escape_inline("a\nb\u{202E}"), "a\\nb\\u{202E}");
//! assert_eq!(unescape_inline("a\\nb\\u{202E}").unwrap(), "a\nb\u{202E}");
//!
//! let lines: Vec<_> = continuation_lines("first\n+ ENTRY forged", "    | ").collect();
//! assert_eq!(lines, ["    | first", "    | + ENTRY forged"]);
//! ```

use std::borrow::Cow;
use std::fmt;
use std::str::Chars;

/// The Unicode version the escape table behind [`needs_escape`] was generated
/// from.
pub const ESCAPE_TABLE_UNICODE_VERSION: (u64, u64, u64) = (17, 0, 0);

/// Every code point in General_Category `Cc`, `Cf`, `Zl` or `Zp`, as sorted,
/// disjoint, inclusive ranges (Unicode 17.0.0).
///
/// A compact table instead of a general-category lookup keeps a full
/// Unicode property table out of WASM builds. A test compares it against
/// `unicode-properties` for every code point, and fails when that crate moves
/// to another Unicode version, so the table cannot drift silently.
const ESCAPE_RANGES: &[(char, char)] = &[
    ('\u{0}', '\u{1F}'),
    ('\u{7F}', '\u{9F}'),
    ('\u{AD}', '\u{AD}'),
    ('\u{600}', '\u{605}'),
    ('\u{61C}', '\u{61C}'),
    ('\u{6DD}', '\u{6DD}'),
    ('\u{70F}', '\u{70F}'),
    ('\u{890}', '\u{891}'),
    ('\u{8E2}', '\u{8E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// True when `c` may not appear verbatim in a rendered line.
///
/// That is every character in Unicode General_Category `Cc` (controls,
/// including line feed and the ANSI escape), `Cf` (format characters,
/// including the bidirectional overrides that reorder displayed text), `Zl`
/// (line separator) and `Zp` (paragraph separator), per Unicode 17.0.0. The
/// backslash is not in this set: it is escaped as `\\` because it introduces
/// escapes, not because it is unsafe to display.
pub fn needs_escape(c: char) -> bool {
    ESCAPE_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Escape `s` so it renders as exactly one printable line.
///
/// Borrows `s` unchanged when nothing needs escaping. See the module docs for
/// the escape table; [`unescape_inline`] is the exact inverse.
pub fn escape_inline(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| c == '\\' || needs_escape(c)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        push_escaped(c, &mut out);
    }
    Cow::Owned(out)
}

/// Render `s` as one line per value line, each beginning with `prefix`.
///
/// `s` is split on line feeds and each piece is passed through
/// [`escape_inline`], so no yielded line contains a line break and each starts
/// with `prefix`. Stripping the prefix, unescaping and joining the lines with
/// `\n` gives back `s`. An empty `s` yields one line holding just the prefix.
///
/// The prefix is written verbatim; callers choose a fixed, printable one (for
/// example `"    | "`).
pub fn continuation_lines<'a>(
    s: &'a str,
    prefix: &'a str,
) -> impl Iterator<Item = Cow<'a, str>> + 'a {
    s.split('\n').map(move |line| {
        let body = escape_inline(line);
        if prefix.is_empty() {
            body
        } else {
            let mut out = String::with_capacity(prefix.len() + body.len());
            out.push_str(prefix);
            out.push_str(&body);
            Cow::Owned(out)
        }
    })
}

/// Reverse [`escape_inline`].
///
/// Fails on a dangling backslash, an unknown escape, or a `\u{...}` that is
/// not a Unicode scalar value written in 1 to 6 hex digits.
pub fn unescape_inline(s: &str) -> Result<Cow<'_, str>, UnescapeError> {
    if !s.contains('\\') {
        return Ok(Cow::Borrowed(s));
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let next = chars.next().ok_or(UnescapeError::DanglingBackslash)?;
        let decoded =
            decode_escape(next, &mut chars).unwrap_or(Err(UnescapeError::UnknownEscape(next)))?;
        out.push(decoded);
    }
    Ok(Cow::Owned(out))
}

/// Why [`unescape_inline`] rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnescapeError {
    /// The input ends in a lone backslash.
    DanglingBackslash,
    /// A backslash is followed by a character that starts no known escape.
    UnknownEscape(char),
    /// A `\u{...}` escape is malformed or names no Unicode scalar value.
    InvalidCodePoint,
}

impl fmt::Display for UnescapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnescapeError::DanglingBackslash => f.write_str("input ends with a dangling '\\'"),
            UnescapeError::UnknownEscape(c) => write!(f, "unknown escape '\\{c}'"),
            UnescapeError::InvalidCodePoint => f.write_str("malformed '\\u{...}' escape"),
        }
    }
}

impl std::error::Error for UnescapeError {}

/// Append the escaped form of `c` to `out` (the single-character core of
/// [`escape_inline`], shared with the path formatter).
pub(crate) fn push_escaped(c: char, out: &mut String) {
    use std::fmt::Write as _;
    match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\t' => out.push_str("\\t"),
        '\r' => out.push_str("\\r"),
        c if needs_escape(c) => {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
        }
        c => out.push(c),
    }
}

/// Decode the escape whose introducing backslash has been consumed and whose
/// next character is `next`, reading any further characters from `rest`.
///
/// Returns `None` when `next` starts none of the escapes this module defines,
/// so a caller with extra escapes of its own (the path grammar's `\/` and
/// `\:`) can handle them.
pub(crate) fn decode_escape(
    next: char,
    rest: &mut Chars<'_>,
) -> Option<Result<char, UnescapeError>> {
    Some(match next {
        '\\' => Ok('\\'),
        'n' => Ok('\n'),
        't' => Ok('\t'),
        'r' => Ok('\r'),
        'u' => decode_code_point(rest),
        _ => return None,
    })
}

/// Decode the `{XXXX}` part of a `\u{XXXX}` escape: 1 to 6 hex digits naming a
/// Unicode scalar value.
fn decode_code_point(rest: &mut Chars<'_>) -> Result<char, UnescapeError> {
    const MAX_DIGITS: usize = 6;
    if rest.next() != Some('{') {
        return Err(UnescapeError::InvalidCodePoint);
    }
    let mut value: u32 = 0;
    let mut digits = 0usize;
    loop {
        match rest.next() {
            Some('}') => break,
            Some(c) => {
                let d = c.to_digit(16).ok_or(UnescapeError::InvalidCodePoint)?;
                digits += 1;
                if digits > MAX_DIGITS {
                    return Err(UnescapeError::InvalidCodePoint);
                }
                value = value * 16 + d;
            }
            None => return Err(UnescapeError::InvalidCodePoint),
        }
    }
    if digits == 0 {
        return Err(UnescapeError::InvalidCodePoint);
    }
    char::from_u32(value).ok_or(UnescapeError::InvalidCodePoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn escape_table_agrees_with_unicode_general_category_for_every_char() {
        use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};
        // The table is a snapshot of one Unicode version; a dependency bump
        // to another version must be a deliberate table regeneration.
        let (major, minor, update) = unicode_properties::UNICODE_VERSION;
        assert_eq!(
            (major, minor, update),
            ESCAPE_TABLE_UNICODE_VERSION,
            "regenerate ESCAPE_RANGES for the new Unicode version"
        );
        for c in (0..=0x10FFFF_u32).filter_map(char::from_u32) {
            let expected = matches!(
                c.general_category(),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            );
            assert_eq!(needs_escape(c), expected, "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn escape_table_is_sorted_and_disjoint() {
        for pair in ESCAPE_RANGES.windows(2) {
            let ((a_lo, a_hi), (b_lo, _)) = (pair[0], pair[1]);
            assert!(
                a_lo <= a_hi && u32::from(a_hi) + 1 < u32::from(b_lo),
                "{pair:?}"
            );
        }
    }

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        let out = escape_inline("Bank of Example");
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "Bank of Example");
    }

    #[test]
    fn named_escapes() {
        assert_eq!(escape_inline("a\\b"), "a\\\\b");
        assert_eq!(escape_inline("a\nb"), "a\\nb");
        assert_eq!(escape_inline("a\tb"), "a\\tb");
        assert_eq!(escape_inline("a\r\nb"), "a\\r\\nb");
    }

    #[test]
    fn other_controls_and_formats_use_braced_hex() {
        // BEL (Cc), ESC (Cc, the start of ANSI sequences), DEL (Cc).
        assert_eq!(
            escape_inline("\u{7}\u{1B}[31m\u{7F}"),
            "\\u{0007}\\u{001B}[31m\\u{007F}"
        );
        // RIGHT-TO-LEFT OVERRIDE and ZERO WIDTH SPACE are Cf.
        assert_eq!(escape_inline("\u{202E}x\u{200B}"), "\\u{202E}x\\u{200B}");
        // LINE SEPARATOR (Zl) and PARAGRAPH SEPARATOR (Zp) break lines in
        // some renderers.
        assert_eq!(escape_inline("\u{2028}\u{2029}"), "\\u{2028}\\u{2029}");
        // A Cf character beyond the BMP keeps all of its digits.
        assert_eq!(escape_inline("\u{E0001}"), "\\u{E0001}");
    }

    #[test]
    fn printable_non_ascii_passes_through() {
        assert_eq!(
            escape_inline("Caf\u{e9} \u{1F600} \u{3B1}"),
            "Caf\u{e9} \u{1F600} \u{3B1}"
        );
    }

    #[test]
    fn unescape_reverses_known_escapes() {
        assert_eq!(unescape_inline("a\\\\b\\n\\t\\r").unwrap(), "a\\b\n\t\r");
        assert_eq!(
            unescape_inline("\\u{1b}\\u{202e}").unwrap(),
            "\u{1B}\u{202E}"
        );
        assert!(matches!(
            unescape_inline("plain").unwrap(),
            Cow::Borrowed("plain")
        ));
    }

    #[test]
    fn unescape_rejects_malformed_input() {
        assert_eq!(
            unescape_inline("a\\"),
            Err(UnescapeError::DanglingBackslash)
        );
        assert_eq!(
            unescape_inline("\\q"),
            Err(UnescapeError::UnknownEscape('q'))
        );
        for bad in [
            "\\u",
            "\\u{",
            "\\u{}",
            "\\u{41",
            "\\u41",
            "\\u{1234567}",
            "\\u{D800}",
            "\\u{110000}",
            "\\u{zz}",
        ] {
            assert_eq!(
                unescape_inline(bad),
                Err(UnescapeError::InvalidCodePoint),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn continuation_lines_prefix_every_line() {
        let lines: Vec<_> = continuation_lines("one\ntwo\n", "    | ").collect();
        assert_eq!(lines, ["    | one", "    | two", "    | "]);
    }

    #[test]
    fn continuation_lines_of_empty_value_is_one_bare_prefix() {
        let lines: Vec<_> = continuation_lines("", "  | ").collect();
        assert_eq!(lines, ["  | "]);
    }

    #[test]
    fn continuation_lines_cannot_forge_structure() {
        // A value line shaped like a diff header stays behind the prefix, and
        // a carriage return or line separator cannot start a fresh line.
        let lines: Vec<_> = continuation_lines("x\r+ ENTRY /Evil\u{2028}~ Notes:", "| ").collect();
        assert_eq!(lines, ["| x\\r+ ENTRY /Evil\\u{2028}~ Notes:"]);
    }

    #[test]
    fn continuation_lines_borrow_when_prefix_is_empty_and_clean() {
        let lines: Vec<_> = continuation_lines("a\nb", "").collect();
        assert!(lines.iter().all(|l| matches!(l, Cow::Borrowed(_))));
    }

    fn rejoin(lines: &[Cow<'_, str>], prefix: &str) -> String {
        lines
            .iter()
            .map(|l| {
                let body = l.strip_prefix(prefix).expect("prefixed");
                unescape_inline(body).expect("unescapes").into_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    proptest! {
        #[test]
        fn escaped_output_has_no_unsafe_characters(s in any::<String>()) {
            let out = escape_inline(&s);
            prop_assert!(!out.chars().any(needs_escape), "{out:?}");
        }

        #[test]
        fn unescape_inverts_escape(s in any::<String>()) {
            let escaped = escape_inline(&s);
            prop_assert_eq!(unescape_inline(&escaped).unwrap(), s.as_str());
        }

        #[test]
        fn continuation_lines_are_prefixed_and_reversible(
            s in any::<String>(),
            prefix in "[ |>#-]{0,6}",
        ) {
            let lines: Vec<_> = continuation_lines(&s, &prefix).collect();
            for line in &lines {
                prop_assert!(line.starts_with(prefix.as_str()), "{line:?}");
                prop_assert!(!line.chars().any(needs_escape), "{line:?}");
            }
            prop_assert_eq!(rejoin(&lines, &prefix), s);
        }
    }
}
