//! The strings of an image, read out of the bytes of its data sections.
//!
//! A string is a run of text that ends in a NUL: the way a string looks in
//! a program image. The scanner reads the text as ASCII, as UTF-16 and
//! UTF-32 of either byte order, and as the code pages cp932, GBK and
//! EUC-KR, so a greeting is found whether the program holds it as `hello`,
//! as `h\0e\0l\0l\0o\0`, or as the bytes its code page spells it with.

use crate::ImageString;

/// The encoding a string is held in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// One byte per character, the ASCII text of a C string.
    Ascii,
    /// Two bytes per character, least significant byte first.
    Utf16Le,
    /// Two bytes per character, most significant byte first.
    Utf16Be,
    /// Four bytes per character, least significant byte first.
    Utf32Le,
    /// Four bytes per character, most significant byte first.
    Utf32Be,
    /// The Japanese code page: Shift_JIS as Windows spells it, Windows-31J.
    Cp932,
    /// The simplified-Chinese code page.
    Gbk,
    /// The Korean code page, read with the Windows-949 extensions.
    EucKr,
}

impl StringEncoding {
    /// Every encoding the scanner reads.
    pub const ALL: [StringEncoding; 8] = [
        StringEncoding::Ascii,
        StringEncoding::Utf16Le,
        StringEncoding::Utf16Be,
        StringEncoding::Utf32Le,
        StringEncoding::Utf32Be,
        StringEncoding::Cp932,
        StringEncoding::Gbk,
        StringEncoding::EucKr,
    ];

    /// The encodings reported beside the ASCII and UTF-16LE strings: the
    /// big-endian wide strings, the UTF-32 strings and the code pages.
    pub const ENCODED: [StringEncoding; 6] = [
        StringEncoding::Utf16Be,
        StringEncoding::Utf32Le,
        StringEncoding::Utf32Be,
        StringEncoding::Cp932,
        StringEncoding::Gbk,
        StringEncoding::EucKr,
    ];

    /// The name the encoding is reported and asked for by.
    pub fn name(self) -> &'static str {
        match self {
            StringEncoding::Ascii => "ascii",
            StringEncoding::Utf16Le => "utf16le",
            StringEncoding::Utf16Be => "utf16be",
            StringEncoding::Utf32Le => "utf32le",
            StringEncoding::Utf32Be => "utf32be",
            StringEncoding::Cp932 => "cp932",
            StringEncoding::Gbk => "gbk",
            StringEncoding::EucKr => "euc-kr",
        }
    }

    /// The encoding a name asks for, when it names one.
    ///
    /// The name is read without regard to case, and the hyphens and
    /// underscores it may carry are left out: `UTF-16BE`, `utf16be` and
    /// `utf16_be` all name the same encoding. `utf16` and `utf32` mean the
    /// little-endian ones, the way the wide strings have always been read;
    /// `shift-jis` and `sjis` name cp932, `cp936` GBK, and `cp949` EUC-KR.
    pub fn of_name(name: &str) -> Option<StringEncoding> {
        let normalized: String = name
            .chars()
            .filter(|character| *character != '-' && *character != '_')
            .flat_map(|character| character.to_lowercase())
            .collect();
        match normalized.as_str() {
            "ascii" => Some(StringEncoding::Ascii),
            "utf16" | "utf16le" => Some(StringEncoding::Utf16Le),
            "utf16be" => Some(StringEncoding::Utf16Be),
            "utf32" | "utf32le" => Some(StringEncoding::Utf32Le),
            "utf32be" => Some(StringEncoding::Utf32Be),
            "cp932" | "shiftjis" | "sjis" | "windows31j" => Some(StringEncoding::Cp932),
            "gbk" | "cp936" => Some(StringEncoding::Gbk),
            "euckr" | "cp949" | "windows949" => Some(StringEncoding::EucKr),
            _ => None,
        }
    }

    /// The code page's table, when the encoding is one.
    fn code_page(self) -> Option<&'static encoding_rs::Encoding> {
        match self {
            StringEncoding::Cp932 => Some(encoding_rs::SHIFT_JIS),
            StringEncoding::Gbk => Some(encoding_rs::GBK),
            StringEncoding::EucKr => Some(encoding_rs::EUC_KR),
            _ => None,
        }
    }
}

/// The shortest string the scanner reports, in bytes, the terminator included.
const MIN_STRING: usize = 5;

/// The strings of one section's bytes: the ASCII ones, the UTF-16LE ones,
/// and the ones held in the other encodings, each tagged with its own.
///
/// The encodings are read one after another over the same bytes, so a run
/// may be found by more than one: a UTF-16LE string's low bytes are ASCII
/// text too, but its NULs break the ASCII run, and a code-page run is only
/// reported when it uses the page, so the buckets do not repeat each other.
pub(crate) fn scan_section(
    bytes: &[u8],
    base: u64,
    section: &str,
) -> (Vec<ImageString>, Vec<ImageString>, Vec<ImageString>) {
    let ascii = scan_ascii(bytes, base, section);
    let wide = scan_fixed(bytes, base, section, 2, 0, StringEncoding::Utf16Le);

    let mut encoded = Vec::new();
    for encoding in StringEncoding::ENCODED {
        encoded.extend(match encoding {
            StringEncoding::Utf16Be => scan_fixed(bytes, base, section, 2, 1, encoding),
            StringEncoding::Utf32Le => scan_fixed(bytes, base, section, 4, 0, encoding),
            StringEncoding::Utf32Be => scan_fixed(bytes, base, section, 4, 3, encoding),
            _ => scan_code_page(bytes, base, section, encoding),
        });
    }
    // One address order across the encodings, as the other buckets read.
    encoded.sort_by_key(|string| string.address);

    (ascii, wide, encoded)
}

/// The strings of a run of bytes.
///
/// A string is a run of text that ends in a NUL, and the NUL is part of it.
/// A tab, a newline and a carriage return count as text, because a format
/// string holds them.
fn scan_ascii(bytes: &[u8], base: u64, section: &str) -> Vec<ImageString> {
    let mut strings = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if !is_text(bytes[index]) {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && is_text(bytes[index]) {
            index += 1;
        }

        // A string ends in a NUL, and it is long enough to be one.
        let length = index - start;
        if length + 1 < MIN_STRING || index >= bytes.len() || bytes[index] != 0 {
            continue;
        }

        strings.push(ImageString {
            address: base + start as u64,
            section: section.to_string(),
            text: escape(&bytes[start..index]),
            length: (length + 1) as u64,
            encoding: StringEncoding::Ascii,
        });
    }

    strings
}

/// The wide strings of a run of bytes, read `width` bytes at a time.
///
/// A wide string is a run of characters that each take one byte of text and
/// NULs for the rest of their unit — the ASCII range of UTF-16 and UTF-32,
/// the way the wide strings have always been read — and that ends in a unit
/// of NULs. The text byte sits at `text_at` within the unit: first for the
/// little-endian encodings, last for the big-endian ones.
fn scan_fixed(
    bytes: &[u8],
    base: u64,
    section: &str,
    width: usize,
    text_at: usize,
    encoding: StringEncoding,
) -> Vec<ImageString> {
    let mut strings = Vec::new();
    let mut index = 0;

    // One character of the string: text at its own byte, NULs at the rest.
    let unit = |at: usize| {
        (0..width).all(|offset| {
            let byte = bytes[at + offset];
            if offset == text_at {
                is_text(byte)
            } else {
                byte == 0
            }
        })
    };

    while index + width <= bytes.len() {
        if !unit(index) {
            index += 1;
            continue;
        }

        let start = index;
        while index + width <= bytes.len() && unit(index) {
            index += width;
        }

        // A wide string ends in a unit of NULs, and it is long enough to be
        // one.
        let length = index - start;
        if length + width < MIN_STRING
            || index + width > bytes.len()
            || bytes[index..index + width].iter().any(|byte| *byte != 0)
        {
            continue;
        }

        let text: String = bytes[start..index]
            .iter()
            .skip(text_at)
            .step_by(width)
            .map(|byte| escape(&[*byte]))
            .collect();

        strings.push(ImageString {
            address: base + start as u64,
            section: section.to_string(),
            text,
            length: (length + width) as u64,
            encoding,
        });

        index += width;
    }

    strings
}

/// The strings of a run of bytes held in a code page.
///
/// A code-page string is a run of the page's text that ends in a NUL, and
/// that uses the page: at least one of its characters is one the page
/// spells with a byte of its own, not ASCII. A run of ASCII is the ASCII
/// scanner's to report, and is left out here so the buckets do not repeat
/// each other.
fn scan_code_page(
    bytes: &[u8],
    base: u64,
    section: &str,
    encoding: StringEncoding,
) -> Vec<ImageString> {
    let Some(page) = encoding.code_page() else {
        return Vec::new();
    };
    let mut strings = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if text_unit(bytes, index, page).is_none() {
            index += 1;
            continue;
        }

        let start = index;
        let mut uses_page = false;
        while let Some(width) = text_unit(bytes, index, page) {
            uses_page |= bytes[index] >= 0x80;
            index += width;
        }

        // A code-page string ends in a NUL, and it is long enough to be one.
        let length = index - start;
        if !uses_page || length + 1 < MIN_STRING || index >= bytes.len() || bytes[index] != 0 {
            continue;
        }

        let (text, _, errors) = page.decode(&bytes[start..index]);
        if errors || !text.chars().all(is_page_text) {
            continue;
        }

        strings.push(ImageString {
            address: base + start as u64,
            section: section.to_string(),
            text: escape_text(&text),
            length: (length + 1) as u64,
            encoding,
        });
    }

    strings
}

/// One character of a code page's text at `at`, and the bytes it takes.
///
/// ASCII text stands as it does everywhere; a byte of the page itself is
/// read as the character it spells alone — cp932's half-width katakana —
/// or as the lead byte of the two it spells with the trail that follows.
fn text_unit(bytes: &[u8], at: usize, page: &'static encoding_rs::Encoding) -> Option<usize> {
    if at >= bytes.len() {
        return None;
    }
    let byte = bytes[at];
    if is_text(byte) {
        return Some(1);
    }
    if byte < 0x80 {
        return None;
    }

    for width in 1..=2 {
        if at + width > bytes.len() {
            break;
        }
        let (text, _, errors) = page.decode(&bytes[at..at + width]);
        if !errors && text.chars().count() == 1 && text.chars().all(is_page_text) {
            return Some(width);
        }
    }
    None
}

/// Whether a byte is part of the text of a string.
pub(crate) fn is_text(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Whether a character is text a string may hold: anything but a control
/// character, save the tab, newline and carriage return a format string
/// carries.
fn is_page_text(character: char) -> bool {
    !character.is_control() || matches!(character, '\t' | '\n' | '\r')
}

/// The text of a string, with the control characters written out.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());

    for &byte in bytes {
        match byte {
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            byte if byte.is_ascii_graphic() || byte == b' ' => out.push(byte as char),
            byte => out.push_str(&format!("\\x{byte:02x}")),
        }
    }

    out
}

/// The text a code page decoded, with the control characters written out.
///
/// The characters the page spells beyond ASCII stand as they are: the text
/// is read as Unicode, and `日本語` is reported as `日本語`.
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for character in text.chars() {
        match character {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            character if character.is_control() => {
                out.push_str(&format!("\\u{{{:x}}}", character as u32));
            }
            character => out.push(character),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The texts of the strings found, in the order they were found.
    fn texts(strings: &[ImageString]) -> Vec<&str> {
        strings.iter().map(|string| string.text.as_str()).collect()
    }

    #[test]
    fn an_ascii_string_ends_in_a_nul() {
        let found = scan_ascii(b"helloworld", 0x1000, ".rodata");
        assert!(found.is_empty(), "a run without a NUL is not a string");

        let found = scan_ascii(b"hello\0", 0x1000, ".rodata");
        assert_eq!(texts(&found), ["hello"]);
        assert_eq!(found[0].address, 0x1000);
        assert_eq!(found[0].section, ".rodata");
        assert_eq!(found[0].length, 6, "the NUL is part of the string");
        assert_eq!(found[0].encoding, StringEncoding::Ascii);
    }

    #[test]
    fn a_short_ascii_run_is_not_a_string() {
        // Four bytes with the NUL: one short of the shortest string.
        assert!(scan_ascii(b"abc\0", 0x1000, ".rodata").is_empty());
        assert_eq!(texts(&scan_ascii(b"abcd\0", 0x1000, ".rodata")), ["abcd"]);
    }

    #[test]
    fn ascii_control_characters_are_written_out() {
        let found = scan_ascii(b"a\tb\nc\rd\0", 0x1000, ".rodata");
        assert_eq!(texts(&found), ["a\\tb\\nc\\rd"]);
    }

    #[test]
    fn a_newline_in_a_string_is_part_of_it() {
        let strings = scan_ascii(b"%ld\n\0", 0x2004, ".rodata");

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].text, "%ld\\n", "the newline is written out");
        assert_eq!(strings[0].length, 5);
    }

    #[test]
    fn a_wide_string_is_scanned_as_a_wide_one() {
        let strings = scan_fixed(
            b"h\0e\0l\0l\0o\0\0\0",
            0x3000,
            ".data",
            2,
            0,
            StringEncoding::Utf16Le,
        );

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].address, 0x3000);
        assert_eq!(strings[0].text, "hello");
        assert_eq!(strings[0].length, 12, "the two NULs are part of it");
    }

    #[test]
    fn a_wide_string_is_not_scanned_as_a_narrow_one() {
        assert!(
            scan_ascii(b"h\0e\0l\0l\0o\0\0\0", 0x3000, ".data").is_empty(),
            "the NULs between the characters break the run"
        );
    }

    #[test]
    fn a_wide_string_is_read_little_endian() {
        let found = scan_fixed(
            b"h\0i\0\0\0",
            0x1000,
            ".rdata",
            2,
            0,
            StringEncoding::Utf16Le,
        );
        assert_eq!(texts(&found), ["hi"]);
        assert_eq!(found[0].address, 0x1000);
        assert_eq!(found[0].length, 6, "two characters and their NUL");
        assert_eq!(found[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn a_wide_string_may_start_at_an_odd_offset() {
        let found = scan_fixed(
            b"\x01h\0i\0\0\0",
            0x1000,
            ".rdata",
            2,
            0,
            StringEncoding::Utf16Le,
        );
        assert_eq!(texts(&found), ["hi"]);
        assert_eq!(found[0].address, 0x1001);
    }

    #[test]
    fn one_wide_character_is_too_short() {
        // One character and its NUL: four bytes, one short of the shortest.
        assert!(scan_fixed(b"a\0\0\0", 0x1000, ".rdata", 2, 0, StringEncoding::Utf16Le).is_empty());
    }

    #[test]
    fn a_wide_string_is_read_big_endian() {
        let found = scan_fixed(
            b"\0h\0i\0\0",
            0x1000,
            ".rdata",
            2,
            1,
            StringEncoding::Utf16Be,
        );
        assert_eq!(texts(&found), ["hi"]);
        assert_eq!(found[0].address, 0x1000);
        assert_eq!(found[0].length, 6);
        assert_eq!(found[0].encoding, StringEncoding::Utf16Be);

        // The little-endian reading of the same bytes is not a string: the
        // text byte sits where the NUL belongs.
        assert!(scan_fixed(
            b"\0h\0i\0\0",
            0x1000,
            ".rdata",
            2,
            0,
            StringEncoding::Utf16Le
        )
        .is_empty());
    }

    #[test]
    fn a_utf32_string_is_read_little_endian() {
        let bytes = b"h\0\0\0i\0\0\0\0\0\0\0";
        let found = scan_fixed(bytes, 0x1000, ".rdata", 4, 0, StringEncoding::Utf32Le);
        assert_eq!(texts(&found), ["hi"]);
        assert_eq!(found[0].address, 0x1000);
        assert_eq!(found[0].length, 12, "two characters and their NUL");
        assert_eq!(found[0].encoding, StringEncoding::Utf32Le);
    }

    #[test]
    fn a_utf32_string_is_read_big_endian() {
        let bytes = b"\0\0\0h\0\0\0i\0\0\0\0";
        let found = scan_fixed(bytes, 0x1000, ".rdata", 4, 3, StringEncoding::Utf32Be);
        assert_eq!(texts(&found), ["hi"]);
        assert_eq!(found[0].length, 12);
        assert_eq!(found[0].encoding, StringEncoding::Utf32Be);
    }

    #[test]
    fn one_utf32_character_is_a_string() {
        // One character and its NUL are eight bytes: long enough, where one
        // wide character's four are not.
        let found = scan_fixed(
            b"a\0\0\0\0\0\0\0",
            0x1000,
            ".rdata",
            4,
            0,
            StringEncoding::Utf32Le,
        );
        assert_eq!(texts(&found), ["a"]);
        assert_eq!(found[0].length, 8);
    }

    #[test]
    fn a_cp932_string_is_read() {
        // 日本語 as cp932 spells it.
        let bytes = [0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea, 0x00];
        let found = scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Cp932);
        assert_eq!(texts(&found), ["日本語"]);
        assert_eq!(found[0].address, 0x2000);
        assert_eq!(found[0].length, 7, "six bytes and the NUL");
        assert_eq!(found[0].encoding, StringEncoding::Cp932);
    }

    #[test]
    fn a_gbk_string_is_read() {
        // 中文 as GBK spells it.
        let bytes = [0xd6, 0xd0, 0xce, 0xc4, 0x00];
        let found = scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Gbk);
        assert_eq!(texts(&found), ["中文"]);
        assert_eq!(found[0].length, 5);
        assert_eq!(found[0].encoding, StringEncoding::Gbk);
    }

    #[test]
    fn an_euc_kr_string_is_read() {
        // 한국어 as EUC-KR spells it.
        let bytes = [0xc7, 0xd1, 0xb1, 0xb9, 0xbe, 0xee, 0x00];
        let found = scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::EucKr);
        assert_eq!(texts(&found), ["한국어"]);
        assert_eq!(found[0].length, 7);
        assert_eq!(found[0].encoding, StringEncoding::EucKr);
    }

    #[test]
    fn half_width_katakana_is_cp932_text() {
        // ｱｲｳｴ: one byte each, the page's own, not ASCII.
        let bytes = [0xb1, 0xb2, 0xb3, 0xb4, 0x00];
        let found = scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Cp932);
        assert_eq!(texts(&found), ["ｱｲｳｴ"]);
    }

    #[test]
    fn a_code_page_string_keeps_the_ascii_it_holds() {
        // A日本語B: the page's characters with ASCII around them.
        let bytes = [0x41, 0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea, 0x42, 0x00];
        let found = scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Cp932);
        assert_eq!(texts(&found), ["A日本語B"]);
    }

    #[test]
    fn an_ascii_run_is_left_to_the_ascii_scanner() {
        assert!(scan_code_page(b"hello\0", 0x2000, ".rdata", StringEncoding::Cp932).is_empty());
        assert!(scan_code_page(b"hello\0", 0x2000, ".rdata", StringEncoding::Gbk).is_empty());
        assert!(scan_code_page(b"hello\0", 0x2000, ".rdata", StringEncoding::EucKr).is_empty());
    }

    #[test]
    fn a_code_page_string_ends_in_a_nul() {
        let bytes = [0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea];
        assert!(scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Cp932).is_empty());
    }

    #[test]
    fn a_bad_trail_byte_ends_the_run() {
        // 'A', a lead byte with no trail it can take, then " B": no run is
        // long enough, and none ends in a NUL where the page's text does.
        let bytes = [0x41, 0x93, 0x20, 0x42, 0x00];
        assert!(scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Cp932).is_empty());
    }

    #[test]
    fn a_short_code_page_run_is_not_a_string() {
        // One character and its NUL: three bytes, too short.
        let bytes = [0xd6, 0xd0, 0x00];
        assert!(scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Gbk).is_empty());
    }

    #[test]
    fn a_code_page_string_may_start_at_an_offset() {
        let bytes = [0x00, 0xd6, 0xd0, 0xce, 0xc4, 0x00];
        let found = scan_code_page(&bytes, 0x2000, ".rdata", StringEncoding::Gbk);
        assert_eq!(texts(&found), ["中文"]);
        assert_eq!(found[0].address, 0x2001);
    }

    #[test]
    fn the_buckets_hold_their_encodings() {
        // One run of each encoding, separated by bytes that are text in none
        // of them, so a run of one does not reach into the next. The same
        // bytes may read under more than one encoding — a code page's bytes
        // are often another's too — so the encoded bucket is checked for the
        // runs it must hold, not for holding only those.
        let mut bytes = b"hello\0".to_vec();
        let mut put = |run: &[u8]| {
            bytes.extend_from_slice(&[0xff, 0xff]);
            let at = bytes.len() as u64;
            bytes.extend_from_slice(run);
            at
        };
        let utf16le = put(b"h\0i\0\0\0");
        let utf16be = put(b"\0h\0i\0\0");
        let utf32le = put(b"h\0\0\0i\0\0\0\0\0\0\0");
        let utf32be = put(b"\0\0\0h\0\0\0i\0\0\0\0");
        let gbk = put(&[0xd6, 0xd0, 0xce, 0xc4, 0x00]);

        let (ascii, wide, encoded) = scan_section(&bytes, 0x1000, ".rdata");
        assert_eq!(texts(&ascii), ["hello"]);
        assert_eq!(texts(&wide), ["hi"]);
        assert_eq!(wide[0].address, 0x1000 + utf16le);

        let holds = |text: &str, encoding: StringEncoding, at: u64| {
            encoded.iter().any(|string| {
                string.text == text && string.encoding == encoding && string.address == 0x1000 + at
            })
        };
        assert!(holds("hi", StringEncoding::Utf16Be, utf16be), "{encoded:?}");
        assert!(holds("hi", StringEncoding::Utf32Le, utf32le), "{encoded:?}");
        assert!(holds("hi", StringEncoding::Utf32Be, utf32be), "{encoded:?}");
        assert!(holds("中文", StringEncoding::Gbk, gbk), "{encoded:?}");

        // The encoded bucket reads in address order across the encodings.
        assert!(
            encoded
                .windows(2)
                .all(|pair| pair[0].address <= pair[1].address),
            "{encoded:?}"
        );
    }

    #[test]
    fn encodings_are_named_and_parsed() {
        for encoding in StringEncoding::ALL {
            assert_eq!(StringEncoding::of_name(encoding.name()), Some(encoding));
        }
        assert_eq!(
            StringEncoding::of_name("UTF-16BE"),
            Some(StringEncoding::Utf16Be)
        );
        assert_eq!(
            StringEncoding::of_name("utf16"),
            Some(StringEncoding::Utf16Le)
        );
        assert_eq!(
            StringEncoding::of_name("utf32"),
            Some(StringEncoding::Utf32Le)
        );
        assert_eq!(
            StringEncoding::of_name("utf32_le"),
            Some(StringEncoding::Utf32Le)
        );
        assert_eq!(
            StringEncoding::of_name("shift-jis"),
            Some(StringEncoding::Cp932)
        );
        assert_eq!(StringEncoding::of_name("SJIS"), Some(StringEncoding::Cp932));
        assert_eq!(StringEncoding::of_name("cp936"), Some(StringEncoding::Gbk));
        assert_eq!(
            StringEncoding::of_name("cp949"),
            Some(StringEncoding::EucKr)
        );
        assert_eq!(
            StringEncoding::of_name("EUC_KR"),
            Some(StringEncoding::EucKr)
        );
    }

    #[test]
    fn an_unknown_name_is_not_an_encoding() {
        assert_eq!(StringEncoding::of_name("utf8"), None);
        assert_eq!(StringEncoding::of_name("latin1"), None);
        assert_eq!(StringEncoding::of_name(""), None);
    }
}
