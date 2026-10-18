//! Small, purpose-specific RFC 4648 codecs: hex (fingerprints, colors,
//! KeePass `TimeOtp-Secret-Hex`), base32 (otpauth and legacy TOTP secrets)
//! and base64 (`TimeOtp-Secret-Base64`).
//!
//! The library needs only these decoders (and hex encoding), so a general
//! encoding crate would cost far more WASM than it saves. The decoders are
//! lenient exactly where real vault data needs it and strict elsewhere.

/// Lowercase hex of `bytes`.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decode hex digits (either case). `None` on an odd length or any other
/// character, whitespace included.
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let nibble = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    pairs
        .iter()
        .map(|&[hi, lo]| Some((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

/// Decode RFC 4648 base32 (`A-Z2-7`), case-insensitively, ignoring ASCII
/// whitespace and trailing `=` padding, and tolerating non-zero trailing bits
/// (some secret generators leave them set). `None` on any other character,
/// padding before the end, or an impossible length.
pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => Some(c - b'A'),
            c @ b'2'..=b'7' => Some(c - b'2' + 26),
            _ => None,
        }
    }
    // A final group of 8 symbols carries 0, 2, 4, 5 or 7 data symbols.
    decode_radix(s, 5, value, 6, |n| matches!(n % 8, 0 | 2 | 4 | 5 | 7))
}

/// Decode RFC 4648 base64 (standard alphabet `A-Za-z0-9+/`), ignoring ASCII
/// whitespace, with or without trailing `=` padding, tolerating non-zero
/// trailing bits. `None` on any other character, padding before the end,
/// more than two padding characters, or an impossible length.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    // A final group of 4 symbols carries 0, 2 or 3 data symbols.
    decode_radix(s, 6, value, 2, |n| matches!(n % 4, 0 | 2 | 3))
}

/// Shared RFC 4648 decoding: each symbol (mapped by `value`) contributes
/// `bits` bits, ASCII whitespace is skipped, up to `max_padding` `=` may end
/// the input, `valid_count` checks the number of data symbols, and leftover
/// bits that do not fill a byte are dropped (the leniency on trailing bits).
fn decode_radix(
    s: &str,
    bits: u32,
    value: fn(u8) -> Option<u8>,
    max_padding: usize,
    valid_count: fn(usize) -> bool,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * bits as usize / 8);
    let (mut acc, mut acc_bits) = (0u32, 0u32);
    let (mut symbols, mut padding) = (0usize, 0usize);
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return None;
        }
        acc = (acc << bits) | u32::from(value(c)?);
        acc_bits += bits;
        symbols += 1;
        if acc_bits >= 8 {
            acc_bits -= 8;
            out.push(u8::try_from(acc >> acc_bits).ok()?);
            acc &= (1 << acc_bits) - 1;
        }
    }
    (padding <= max_padding && valid_count(symbols)).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RFC 4648 section 10 test vectors.
    const RFC4648: [(&str, &str, &str, &str); 7] = [
        ("", "", "", ""),
        ("f", "66", "MY======", "Zg=="),
        ("fo", "666F", "MZXQ====", "Zm8="),
        ("foo", "666F6F", "MZXW6===", "Zm9v"),
        ("foob", "666F6F62", "MZXW6YQ=", "Zm9vYg=="),
        ("fooba", "666F6F6261", "MZXW6YTB", "Zm9vYmE="),
        ("foobar", "666F6F626172", "MZXW6YTBOI======", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_vectors() {
        for (plain, b16, b32, b64) in RFC4648 {
            let plain = plain.as_bytes();
            assert_eq!(hex_encode(plain), b16.to_lowercase());
            assert_eq!(hex_decode(b16).as_deref(), Some(plain), "{b16}");
            assert_eq!(
                hex_decode(&b16.to_lowercase()).as_deref(),
                Some(plain),
                "{b16}"
            );
            assert_eq!(base32_decode(b32).as_deref(), Some(plain), "{b32}");
            assert_eq!(base64_decode(b64).as_deref(), Some(plain), "{b64}");
        }
    }

    #[test]
    fn padding_case_and_whitespace_tolerance() {
        for (plain, _, b32, b64) in RFC4648 {
            let plain = plain.as_bytes();
            let unpadded32 = b32.trim_end_matches('=');
            assert_eq!(base32_decode(unpadded32).as_deref(), Some(plain), "{b32}");
            assert_eq!(
                base32_decode(&b32.to_lowercase()).as_deref(),
                Some(plain),
                "{b32}"
            );
            let unpadded64 = b64.trim_end_matches('=');
            assert_eq!(base64_decode(unpadded64).as_deref(), Some(plain), "{b64}");
        }
        assert_eq!(
            base32_decode(" mzxw 6ytb\toi\n").as_deref(),
            Some(&b"foobar"[..])
        );
        assert_eq!(base64_decode("Zm9v\nYmFy").as_deref(), Some(&b"foobar"[..]));
    }

    #[test]
    fn malformed_input_is_rejected() {
        // Hex: odd length, non-hex, whitespace.
        for bad in ["6", "6g", "66 6f", "+0"] {
            assert_eq!(hex_decode(bad), None, "{bad:?}");
        }
        // Base32: alphabet, inner padding, impossible lengths (1, 3, 6 mod 8).
        for bad in ["MZXW1", "MZ=XW", "M", "MZX", "MZXW6Y", "MZXW6YTBO", "MZ+W"] {
            assert_eq!(base32_decode(bad), None, "{bad:?}");
        }
        // Base64: alphabet (URL-safe is not standard), inner padding, too much
        // padding, impossible length (1 mod 4).
        for bad in ["Zm9v_", "Zm9-", "Zg=a", "Z===", "Zm9vY", "Zg==="] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn nonzero_trailing_bits_are_tolerated() {
        // "MY" and "MZ" differ only in the 2 trailing bits after "f".
        assert_eq!(base32_decode("MZ").as_deref(), Some(&b"f"[..]));
        // "Zg" and "Zh" differ only in the 4 trailing bits after "f".
        assert_eq!(base64_decode("Zh==").as_deref(), Some(&b"f"[..]));
    }

    proptest! {
        /// Differential: data-encoding (dev-dependency only) encodes, ours
        /// decodes.
        #[test]
        fn decoders_agree_with_a_reference_encoder(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(hex_encode(&bytes), data_encoding::HEXLOWER.encode(&bytes));
            prop_assert_eq!(hex_decode(&data_encoding::HEXUPPER.encode(&bytes)), Some(bytes.clone()));
            prop_assert_eq!(base32_decode(&data_encoding::BASE32.encode(&bytes)), Some(bytes.clone()));
            prop_assert_eq!(base32_decode(&data_encoding::BASE32_NOPAD.encode(&bytes)), Some(bytes.clone()));
            prop_assert_eq!(base64_decode(&data_encoding::BASE64.encode(&bytes)), Some(bytes.clone()));
            prop_assert_eq!(base64_decode(&data_encoding::BASE64_NOPAD.encode(&bytes)), Some(bytes));
        }

        #[test]
        fn decoders_never_panic(s in any::<String>()) {
            let _ = (hex_decode(&s), base32_decode(&s), base64_decode(&s));
        }
    }
}
