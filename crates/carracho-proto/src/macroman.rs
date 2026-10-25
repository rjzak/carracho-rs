//! Conversion between Mac OS Roman, the text encoding used on the wire, and
//! Rust strings.

use encoding_rs::MACINTOSH;

/// Decode Mac OS Roman bytes. Every byte maps to a character, so this never fails.
pub fn decode(bytes: &[u8]) -> String {
    MACINTOSH.decode_without_bom_handling(bytes).0.into_owned()
}

/// Encode to Mac OS Roman, replacing characters it cannot represent with `?`.
pub fn encode(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| {
            let mut buf = [0u8; 4];
            let (bytes, _, had_errors) = MACINTOSH.encode(c.encode_utf8(&mut buf));
            if had_errors || bytes.len() != 1 { b'?' } else { bytes[0] }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_mac_specific_characters() {
        // 0xA5 is the bullet and 0xD2/0xD3 are curly double quotes in Mac Roman.
        let bytes = [0xA5, b' ', 0xD2, b'h', b'i', 0xD3];
        let text = decode(&bytes);
        assert_eq!(text, "• “hi”");
        assert_eq!(encode(&text), bytes);
    }

    #[test]
    fn unrepresentable_characters_become_question_marks() {
        assert_eq!(encode("日本"), b"??");
    }
}
