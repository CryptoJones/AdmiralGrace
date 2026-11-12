//! Byte-pattern signature libraries (#397).
//!
//! The whole-function hash ([`super::function_hash`]) is exact, and it needs
//! to know where the function ends and to decode it the same way twice. The
//! classic signature is looser and self-contained: the function's opening
//! bytes written out as they are, with the bytes that carry an address left
//! as **wildcards**, so matching is a masked compare of bytes and needs no
//! decoder, no name and no relocation table. That is what recognises library
//! code linked statically into a stripped program.
//!
//! # The pattern
//!
//! A [`Pattern`] is three checks, read in order:
//!
//! - the **head** — the function's first [`HEAD`] bytes (all of it, when it
//!   is shorter), as hex, a variable byte written `..`;
//! - a **CRC-32** of the run of bytes that follows the head, up to the first
//!   variable byte or [`CRC_MAX`] bytes, whichever comes first — so the
//!   function is told from another that opens alike;
//! - the function's **length**: a function known to be of another length is
//!   not a match, and one whose end is not known must at least have room
//!   for it.
//!
//! The variable bytes are the ones the hash masks — a relative branch's
//! offset, a RIP-relative or absolute displacement — and, for a pattern, an
//! immediate whose value is an address of the image it was taken from: code
//! that is not position-independent says `mov edi, 0x404010`, and the link
//! decides that number. They are found once, when the pattern is made
//! ([`Pattern::of`]); the pattern carries them, so a match never decodes.
//!
//! A pattern with too few fixed bytes ([`MIN_FIXED`]) would match half the
//! programs it met, so none is made of such a function.
//!
//! # The library
//!
//! A pattern library (`.agpat`) is JSON, shaped like a signature file with
//! `patterns` where that has `signatures`. [`PatternDb`] reads and writes
//! it; [`PatternSet`] holds several and answers a function's bytes with
//! every pattern that fits, the most specific first.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The pattern-library format this module reads and writes.
pub const FORMAT: u32 = 1;

/// How many of a function's opening bytes the head spells out.
pub const HEAD: usize = 32;

/// The longest run after the head the CRC is taken over.
pub const CRC_MAX: usize = 255;

/// The most bytes a match reads from a function's entry: the head and the
/// CRC run. A caller hands [`PatternSet::candidates`] this many, or as many
/// as there are.
pub const PROBE: usize = HEAD + CRC_MAX;

/// The fewest fixed bytes — in the head and the CRC run together — a pattern
/// is made with. Fewer, and the pattern is a coincidence waiting to happen.
pub const MIN_FIXED: usize = 8;

/// One function's byte pattern and what a match knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pattern {
    /// The function's opening bytes as hex, two characters a byte, a
    /// variable byte written `..`: `554889e5e8........c3`.
    pub head: String,
    /// How many bytes after the head the CRC is taken over.
    #[serde(default)]
    pub crc_length: u32,
    /// The CRC-32 of those bytes, as eight hex characters.
    #[serde(default = "zero_crc")]
    pub crc: String,
    /// The function's length in bytes.
    pub length: u64,
    /// The name the match gives the function.
    pub name: String,
    /// The C prototype the match applies, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    /// The comment the match leaves on the function, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The CRC of no bytes, as a pattern writes it.
fn zero_crc() -> String {
    "00000000".to_string()
}

impl Pattern {
    /// The pattern of the function `bytes` under `arch` at `base`, named
    /// `name`. `is_address` says whether a value is an address of the image
    /// the bytes came from, so an immediate that holds one is left variable;
    /// `&|_| false` when nothing is known. `None` when the function has
    /// fewer than [`MIN_FIXED`] fixed bytes to be told by.
    pub fn of(
        arch: &str,
        bytes: &[u8],
        base: u64,
        is_address: &dyn Fn(u64) -> bool,
        name: &str,
    ) -> Option<Pattern> {
        let variable = variable_bytes(arch, bytes, base, is_address);
        let head_len = bytes.len().min(HEAD);
        let mut head = String::with_capacity(head_len * 2);
        let mut fixed = 0usize;
        for at in 0..head_len {
            if variable[at] {
                head.push_str("..");
            } else {
                use std::fmt::Write as _;
                let _ = write!(head, "{:02x}", bytes[at]);
                fixed += 1;
            }
        }
        let run = variable[head_len..]
            .iter()
            .take(CRC_MAX)
            .take_while(|variable| !**variable)
            .count();
        fixed += run;
        if fixed < MIN_FIXED {
            return None;
        }
        Some(Pattern {
            head,
            crc_length: run as u32,
            crc: format!("{:08x}", crc32(&bytes[head_len..head_len + run])),
            length: bytes.len() as u64,
            name: name.to_string(),
            prototype: None,
            comment: None,
        })
    }

    /// Whether two patterns are the same test — the same head, CRC and
    /// length — whatever they name.
    pub fn same_test(&self, other: &Pattern) -> bool {
        self.head == other.head
            && self.crc_length == other.crc_length
            && self.crc == other.crc
            && self.length == other.length
    }
}

/// Which of `bytes` are variable: `true` at each byte that carries an
/// address ([`super::address_spans`]). All `false` on an architecture the
/// masker does not read, where a pattern is the bytes as they stand.
pub fn variable_bytes(
    arch: &str,
    bytes: &[u8],
    base: u64,
    is_address: &dyn Fn(u64) -> bool,
) -> Vec<bool> {
    let mut variable = vec![false; bytes.len()];
    for (at, len) in super::address_spans(arch, bytes, base, is_address) {
        let end = at.saturating_add(len).min(variable.len());
        for flag in &mut variable[at.min(end)..end] {
            *flag = true;
        }
    }
    variable
}

/// The CRC-32 (IEEE, reflected) of `bytes`.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A head read into bytes and a mask: `Some(byte)` fixed, `None` variable.
fn parse_head(head: &str) -> Result<Vec<Option<u8>>, String> {
    let text = head.as_bytes();
    if text.is_empty() || !text.len().is_multiple_of(2) || text.len() > HEAD * 2 {
        return Err(format!(
            "a pattern's head is 1 to {HEAD} bytes of hex, not {head:?}"
        ));
    }
    text.chunks(2)
        .map(|pair| {
            if pair == b".." {
                return Ok(None);
            }
            std::str::from_utf8(pair)
                .ok()
                .filter(|pair| pair.bytes().all(|c| c.is_ascii_hexdigit()))
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .map(Some)
                .ok_or_else(|| format!("a pattern's head is hex and `..`, not {head:?}"))
        })
        .collect()
}

/// One library's pattern file: its name, its architecture, where it came
/// from, and its patterns. The JSON form is what `.agpat` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternDb {
    /// The format version; [`FORMAT`] is what this module writes.
    pub format: u32,
    /// The library's name.
    pub library: String,
    /// The architecture the patterns were taken under: `x86-64`, `x86`.
    pub arch: String,
    /// Where the patterns came from, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The patterns, one a function.
    pub patterns: Vec<Pattern>,
}

impl PatternDb {
    /// An empty library for `library` under `arch`.
    pub fn new(library: &str, arch: &str) -> PatternDb {
        PatternDb {
            format: FORMAT,
            library: library.to_string(),
            arch: arch.to_string(),
            source: None,
            patterns: Vec::new(),
        }
    }

    /// Read a pattern library's JSON. A format newer than this module knows
    /// is refused, and so is a pattern that is not one — a head that is not
    /// hex, a CRC that is not a CRC, a CRC run longer than is read.
    pub fn parse(source: &str) -> Result<PatternDb, String> {
        let db: PatternDb =
            serde_json::from_str(source).map_err(|e| format!("not a pattern library: {e}"))?;
        if db.format > FORMAT {
            return Err(format!(
                "pattern format {} is newer than this program reads ({FORMAT})",
                db.format
            ));
        }
        for pattern in &db.patterns {
            let head = parse_head(&pattern.head).map_err(|e| format!("{}: {e}", pattern.name))?;
            if pattern.crc_length as usize > CRC_MAX {
                return Err(format!(
                    "{}: a CRC run of {} bytes is longer than is read ({CRC_MAX})",
                    pattern.name, pattern.crc_length
                ));
            }
            if pattern.crc.len() != 8 || u32::from_str_radix(&pattern.crc, 16).is_err() {
                return Err(format!(
                    "{}: a pattern's CRC is eight hex characters, not {:?}",
                    pattern.name, pattern.crc
                ));
            }
            if pattern.length < (head.len() as u64).saturating_add(pattern.crc_length.into()) {
                return Err(format!(
                    "{}: the function is {} bytes, shorter than its own pattern",
                    pattern.name, pattern.length
                ));
            }
        }
        Ok(db)
    }

    /// Write the library as the JSON a `.agpat` file holds, with a trailing
    /// newline.
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// How many patterns the library holds.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether the library holds no patterns.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// One pattern a function fits, with the library that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternCandidate<'a> {
    /// The library the pattern came from.
    pub library: &'a str,
    /// The pattern itself.
    pub pattern: &'a Pattern,
}

/// A pattern made ready to match: its head as bytes and a mask.
#[derive(Debug, Clone)]
struct Compiled {
    /// The library and the pattern, as indexes into the set.
    db: usize,
    pattern: usize,
    head: Vec<Option<u8>>,
    crc_length: usize,
    crc: u32,
    length: u64,
    /// How many bytes the pattern pins down: the more, the better a match.
    fixed: usize,
}

impl Compiled {
    /// Whether the function `bytes` — its opening bytes, [`PROBE`] of them
    /// or as many as there are — fits. `available` is how many bytes lie
    /// between the entry and the end of its section; `extent` is the
    /// function's length, when the image knows it.
    fn fits(&self, bytes: &[u8], available: u64, extent: Option<u64>) -> bool {
        let sized = match extent {
            Some(extent) => self.length == extent,
            None => self.length <= available,
        };
        let end = self.head.len() + self.crc_length;
        sized
            && bytes.len() >= end
            && self
                .head
                .iter()
                .zip(bytes)
                .all(|(want, have)| want.is_none_or(|want| want == *have))
            && crc32(&bytes[self.head.len()..end]) == self.crc
    }
}

/// Several pattern libraries, made ready to match and bucketed by first
/// byte, so a function is tried against the few patterns that open as it
/// does and not against them all.
#[derive(Debug, Clone, Default)]
pub struct PatternSet {
    /// The libraries, in the order they are consulted.
    pub databases: Vec<PatternDb>,
    compiled: Vec<Compiled>,
    /// The patterns that open with each fixed byte.
    by_first: BTreeMap<u8, Vec<usize>>,
    /// The patterns whose first byte is variable.
    any_first: Vec<usize>,
}

impl PatternSet {
    /// Make `databases` ready to match. A pattern that does not read — one
    /// [`PatternDb::parse`] would have refused — is left out.
    pub fn new(databases: Vec<PatternDb>) -> PatternSet {
        let mut set = PatternSet {
            databases,
            ..PatternSet::default()
        };
        for (db, database) in set.databases.iter().enumerate() {
            for (at, pattern) in database.patterns.iter().enumerate() {
                let (Ok(head), Ok(crc)) = (
                    parse_head(&pattern.head),
                    u32::from_str_radix(&pattern.crc, 16),
                ) else {
                    continue;
                };
                let crc_length = pattern.crc_length as usize;
                if crc_length > CRC_MAX {
                    continue;
                }
                let fixed = head.iter().flatten().count() + crc_length;
                let index = set.compiled.len();
                match head[0] {
                    Some(first) => set.by_first.entry(first).or_default().push(index),
                    None => set.any_first.push(index),
                }
                set.compiled.push(Compiled {
                    db,
                    pattern: at,
                    head,
                    crc_length,
                    crc,
                    length: pattern.length,
                    fixed,
                });
            }
        }
        set
    }

    /// Every pattern of `arch` the function fits, each with its library:
    /// the one that pins down the most bytes first, then in the order the
    /// libraries are consulted. `bytes` is the function's opening bytes —
    /// [`PROBE`] of them, or as many as there are; `available` is how many
    /// bytes lie between its entry and the end of its section; `extent` is
    /// its length, when the image knows where it ends. A function of known
    /// length fits only a pattern of that length; one of unknown length
    /// fits any pattern there is room for. Empty when no pattern fits.
    pub fn candidates(
        &self,
        arch: &str,
        bytes: &[u8],
        available: u64,
        extent: Option<u64>,
    ) -> Vec<PatternCandidate<'_>> {
        let Some(first) = bytes.first() else {
            return Vec::new();
        };
        let mut fitting: Vec<&Compiled> = self
            .by_first
            .get(first)
            .into_iter()
            .flatten()
            .chain(&self.any_first)
            .map(|index| &self.compiled[*index])
            .filter(|compiled| self.databases[compiled.db].arch == arch)
            .filter(|compiled| compiled.fits(bytes, available, extent))
            .collect();
        fitting.sort_by_key(|compiled| {
            (
                std::cmp::Reverse(compiled.fixed),
                compiled.db,
                compiled.pattern,
            )
        });
        fitting
            .into_iter()
            .map(|compiled| {
                let database = &self.databases[compiled.db];
                PatternCandidate {
                    library: &database.library,
                    pattern: &database.patterns[compiled.pattern],
                }
            })
            .collect()
    }

    /// How many patterns the set holds across its libraries.
    pub fn len(&self) -> usize {
        self.databases.iter().map(PatternDb::len).sum()
    }

    /// Whether the set holds no patterns.
    pub fn is_empty(&self) -> bool {
        self.databases.iter().all(PatternDb::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTHING: &dyn Fn(u64) -> bool = &|_| false;

    /// push rbp; mov rbp, rsp; call rel32; mov eax, imm32; pop rbp; ret —
    /// with the call's offset and the immediate given.
    fn body(call: u32, imm: u32) -> Vec<u8> {
        let mut bytes = vec![0x55, 0x48, 0x89, 0xE5, 0xE8];
        bytes.extend_from_slice(&call.to_le_bytes());
        bytes.push(0xB8);
        bytes.extend_from_slice(&imm.to_le_bytes());
        bytes.extend_from_slice(&[0x5D, 0xC3]);
        bytes
    }

    fn db(patterns: Vec<Pattern>) -> PatternDb {
        PatternDb {
            patterns,
            ..PatternDb::new("lib", "x86-64")
        }
    }

    #[test]
    fn the_crc_is_the_ieee_crc32() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn a_branch_offset_is_a_wildcard_and_the_code_is_spelled_out() {
        let pattern = Pattern::of("x86-64", &body(0x1234, 7), 0x1000, NOTHING, "f").unwrap();
        assert_eq!(pattern.head, "554889e5e8........b8070000005dc3");
        assert_eq!(pattern.crc_length, 0);
        assert_eq!(pattern.crc, "00000000");
        assert_eq!(pattern.length, 16);
    }

    #[test]
    fn an_immediate_that_is_an_address_of_the_image_is_a_wildcard() {
        let in_image = |value: u64| (0x40_0000..0x41_0000).contains(&value);
        let pattern = Pattern::of(
            "x86-64",
            &body(0x1234, 0x40_4010),
            0x40_1000,
            &in_image,
            "f",
        )
        .unwrap();
        assert_eq!(pattern.head, "554889e5e8........b8........5dc3");
        // The same immediate is the function's own code when it is no
        // address, and when nobody says what an address is.
        let pattern = Pattern::of("x86-64", &body(0x1234, 7), 0x40_1000, &in_image, "f").unwrap();
        assert_eq!(pattern.head, "554889e5e8........b8070000005dc3");
    }

    #[test]
    fn the_crc_runs_from_the_head_to_the_first_variable_byte() {
        // 40 bytes of code no address touches, a call, and a ret.
        let mut bytes = vec![0x90; 40];
        bytes.extend_from_slice(&[0xE8, 1, 2, 3, 4, 0xC3]);
        let pattern = Pattern::of("x86-64", &bytes, 0, NOTHING, "f").unwrap();
        assert_eq!(pattern.head, "90".repeat(32));
        // Eight nops and the call's opcode, stopping at its offset.
        assert_eq!(pattern.crc_length, 9);
        assert_eq!(pattern.crc, format!("{:08x}", crc32(&bytes[32..41])));
        assert_eq!(pattern.length, 46);
    }

    #[test]
    fn a_function_with_too_few_fixed_bytes_makes_no_pattern() {
        // jmp rel32 — a thunk: one fixed byte.
        assert!(Pattern::of("x86-64", &[0xE9, 1, 2, 3, 4], 0, NOTHING, "thunk").is_none());
        assert!(Pattern::of("x86-64", &[0xC3], 0, NOTHING, "ret").is_none());
    }

    #[test]
    fn a_pattern_matches_the_function_wherever_it_is_linked() {
        let pattern = Pattern::of("x86-64", &body(0x1234, 7), 0x1000, NOTHING, "f").unwrap();
        let set = PatternSet::new(vec![db(vec![pattern])]);
        // The same code in another program: the call goes somewhere else.
        let moved = body(0xFFFF_F00D, 7);
        let found = set.candidates("x86-64", &moved, 64, Some(16));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].library, "lib");
        assert_eq!(found[0].pattern.name, "f");
        // Other code is not the function.
        assert!(set
            .candidates("x86-64", &body(0x1234, 8), 64, Some(16))
            .is_empty());
        // Nor is the same code under another architecture.
        assert!(set.candidates("x86", &moved, 64, Some(16)).is_empty());
    }

    #[test]
    fn a_known_length_must_be_the_patterns_and_an_unknown_one_needs_room() {
        let pattern = Pattern::of("x86-64", &body(0, 7), 0, NOTHING, "f").unwrap();
        let set = PatternSet::new(vec![db(vec![pattern])]);
        let bytes = body(0, 7);
        assert_eq!(set.candidates("x86-64", &bytes, 64, Some(16)).len(), 1);
        // A longer function that merely opens the same way is another one.
        assert!(set.candidates("x86-64", &bytes, 64, Some(40)).is_empty());
        // The end is not known: the pattern fits where there is room …
        assert_eq!(set.candidates("x86-64", &bytes, 16, None).len(), 1);
        // … and not where the section ends before the function would.
        assert!(set.candidates("x86-64", &bytes, 15, None).is_empty());
    }

    #[test]
    fn the_crc_tells_apart_functions_that_open_alike() {
        let mut one = vec![0x90; 40];
        one.push(0xC3);
        let mut other = vec![0x90; 39];
        other.extend_from_slice(&[0xCC, 0xC3]);
        let set = PatternSet::new(vec![db(vec![
            Pattern::of("x86-64", &one, 0, NOTHING, "one").unwrap(),
            Pattern::of("x86-64", &other, 0, NOTHING, "other").unwrap(),
        ])]);
        let found = set.candidates("x86-64", &other, 41, Some(41));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pattern.name, "other");
    }

    #[test]
    fn the_pattern_that_pins_down_the_most_comes_first() {
        let bytes = body(0x1234, 7);
        let exact = Pattern::of("x86-64", &bytes, 0, NOTHING, "exact").unwrap();
        // The same function with its immediate left variable: looser.
        let loose = Pattern::of("x86-64", &bytes, 0, &|value| value == 7, "loose").unwrap();
        let set = PatternSet::new(vec![db(vec![loose]), db(vec![exact])]);
        let names: Vec<&str> = set
            .candidates("x86-64", &bytes, 16, Some(16))
            .iter()
            .map(|candidate| candidate.pattern.name.as_str())
            .collect();
        assert_eq!(names, ["exact", "loose"]);
    }

    #[test]
    fn a_library_round_trips_and_a_bad_one_is_refused() {
        let mut library = db(vec![
            Pattern::of("x86-64", &body(1, 7), 0, NOTHING, "f").unwrap()
        ]);
        library.source = Some("a test".to_string());
        assert_eq!(PatternDb::parse(&library.to_json()).unwrap(), library);

        let mut newer = library.clone();
        newer.format = FORMAT + 1;
        assert!(PatternDb::parse(&newer.to_json())
            .unwrap_err()
            .contains("newer"));

        for (head, crc) in [("5", "00000000"), ("zz", "00000000"), ("55", "xyz")] {
            let mut bad = library.clone();
            bad.patterns[0].head = head.to_string();
            bad.patterns[0].crc = crc.to_string();
            assert!(PatternDb::parse(&bad.to_json()).is_err(), "{head} {crc}");
        }
        // A whole-function signature file is not a pattern library.
        assert!(PatternDb::parse(&crate::funcid::SignatureDb::new("l", "x86").to_json()).is_err());
    }

    #[test]
    fn another_architecture_is_spelled_out_as_it_stands() {
        let bytes = [0xFD, 0x7B, 0xBF, 0xA9, 0x00, 0x00, 0x00, 0x94];
        let pattern = Pattern::of("aarch64", &bytes, 0, NOTHING, "f").unwrap();
        assert_eq!(pattern.head, "fd7bbfa900000094");
    }
}
