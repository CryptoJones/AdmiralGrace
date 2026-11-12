//! Load an external debug info file (#407).
//!
//! A debug info file is what another tool already knows about a program —
//! the names of its functions and data, their types and prototypes, the
//! source they came from — kept beside the image rather than in it.
//! [`parse`] reads one through the first parser that recognizes it: a
//! parser a plugin registered ([`crate::plugin::DebugInfoParser`]), before
//! the engine's own. The result is a [`DebugInfo`] — the functions, the
//! data, the C types and the notes, in the file's own order — which a
//! project keeps as the analyst's names, prototypes, comments and types.
//!
//! Two parsers are built in. `map` reads a linker map file: GNU ld's
//! `Linker script and memory map` (the symbols at their addresses, under
//! the output sections that say which are code) and MSVC's `Publics by
//! Value` (the publics at their Rva+Base, the section table's `CODE`
//! class saying which are functions). `json` reads a JSON document of the
//! shape a parser command answers with — the interchange a tool of another
//! kind exports to, and a parser of its own writes. A format the engine
//! does not read — a PDB, a DWARF file of another tool's making — is a
//! parser a plugin adds, in Rust or as a command declared in a manifest
//! (`docs/plugins.md`).
//!
//! What a file gets wrong is held back rather than guessed at: a symbol
//! whose address another symbol holds already is left out with a note, a
//! row of a JSON document without an address or a name is refused with its
//! place. Mangled names are demangled as the listing reads them; a name
//! that is not mangled is kept as the file spells it.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::plugin::{self, DebugInfoParser};

/// The debug info registry is the whole process's, so the tests that
/// register a parser and the ones that read what is registered take turns:
/// one test's parsers are not another's surprise. Shared with the manifest
/// test in `plugin`.
#[cfg(test)]
pub(crate) static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What a debug info file says about a program: the functions and the data
/// at their addresses, the C types they use, and the notes left on the way
/// through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugInfo {
    /// The functions, in the order the file declares them.
    pub functions: Vec<DebugFunction>,
    /// The data symbols, in the order the file declares them.
    pub data: Vec<DebugData>,
    /// The C type definitions, in the order C reads them.
    pub types: Vec<String>,
    /// Notes left on the way through: symbols held back, names mended.
    pub notes: Vec<String>,
}

/// One function a debug info file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugFunction {
    /// The function's entry address.
    pub address: u64,
    /// Its name, demangled when it was mangled.
    pub name: String,
    /// Its extent in bytes, when the file knows one.
    pub size: Option<u64>,
    /// Its C prototype — `int f(int n, char *s)` — when the file gives one.
    pub prototype: Option<String>,
    /// Where it was written, `file.c:42`, when the file says.
    pub source: Option<String>,
}

/// One data symbol a debug info file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugData {
    /// The address the data sits at.
    pub address: u64,
    /// Its name, demangled when it was mangled.
    pub name: String,
    /// Its extent in bytes, when the file knows one.
    pub size: Option<u64>,
    /// Its C type — `int`, `struct point *` — when the file gives one.
    pub ctype: Option<String>,
}

/// A debug info file read: the parser that read it, and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The name of the parser that read the file.
    pub parser: String,
    /// What the file said.
    pub info: DebugInfo,
}

/// The built-in parsers, in the order they are offered a file.
fn builtins() -> Vec<Arc<dyn DebugInfoParser>> {
    vec![Arc::new(MapParser), Arc::new(JsonParser)]
}

/// Every parser, the ones registered first, in the order they were, then
/// the built-in ones no registered parser shadows by name: what a listing
/// shows and a file is offered to.
pub fn available_parsers() -> Vec<Arc<dyn DebugInfoParser>> {
    let registered = plugin::debug_info_parsers();
    let mut all = registered.clone();
    all.extend(
        builtins()
            .into_iter()
            .filter(|parser| !registered.iter().any(|known| known.name() == parser.name())),
    );
    all
}

/// Every parser's name, the registered ones first: what `--format` takes.
pub fn available() -> Vec<String> {
    available_parsers()
        .iter()
        .map(|parser| parser.name().to_string())
        .collect()
}

/// Read a debug info file.
///
/// With `format`, the parser of that name reads it — a registered one
/// before a built-in of the same name — and its failure is the read's
/// failure. Without one, the file is offered to every parser that
/// recognizes it, the registered ones first: the first that reads it wins,
/// and one that recognizes but fails is reported on standard error and
/// the next is tried. A file no parser recognizes, or none reads, is an
/// error naming the parsers there are.
pub fn parse(name: &str, bytes: &[u8], format: Option<&str>) -> Result<Parsed, String> {
    if let Some(wanted) = format {
        let parser = plugin::debug_info_parsers()
            .into_iter()
            .find(|parser| parser.name() == wanted)
            .or_else(|| {
                builtins()
                    .into_iter()
                    .find(|parser| parser.name() == wanted)
            });
        let Some(parser) = parser else {
            return Err(format!(
                "no debug info parser is called {wanted:?}; the parsers are {}",
                available().join(", ")
            ));
        };
        let info = parser
            .parse(name, bytes)
            .map_err(|error| format!("the debug info parser {}: {error}", parser.name()))?;
        return Ok(Parsed {
            parser: parser.name().to_string(),
            info,
        });
    }
    let offered: Vec<Arc<dyn DebugInfoParser>> = available_parsers()
        .into_iter()
        .filter(|parser| parser.recognizes(bytes))
        .collect();
    if offered.is_empty() {
        return Err(format!(
            "no debug info parser recognizes {name}; the parsers are {}",
            available().join(", ")
        ));
    }
    let mut failures = Vec::new();
    for parser in offered {
        match parser.parse(name, bytes) {
            Ok(info) => {
                return Ok(Parsed {
                    parser: parser.name().to_string(),
                    info,
                });
            }
            Err(error) => {
                eprintln!("warning: the debug info parser {}: {error}", parser.name());
                failures.push(format!("{}: {error}", parser.name()));
            }
        }
    }
    Err(format!(
        "no debug info parser reads {name}: {}",
        failures.join("; ")
    ))
}

/// The name as the listing reads it: demangled when it is mangled, as the
/// file spells it otherwise.
fn plain_name(name: &str) -> String {
    crate::demangle::demangle(name).unwrap_or_else(|| name.to_string())
}

/// A symbol held back because another is at its address already, noted.
fn held_back(
    notes: &mut Vec<String>,
    seen: &BTreeMap<u64, String>,
    address: u64,
    name: &str,
) -> bool {
    match seen.get(&address) {
        Some(first) => {
            notes.push(format!(
                "{address:#x}: {name} held back: {first} is there already"
            ));
            true
        }
        None => false,
    }
}

// ---- The built-in `map` parser: a linker map file. ----

/// A linker map file: GNU ld's memory map, or MSVC's publics by value.
struct MapParser;

impl DebugInfoParser for MapParser {
    fn name(&self) -> &str {
        "map"
    }

    fn description(&self) -> &str {
        "A linker map file: GNU ld's `Linker script and memory map`, or MSVC's `Publics by Value`."
    }

    fn recognizes(&self, bytes: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return false;
        };
        text.contains("Linker script and memory map")
            || (text.contains("Publics by Value") && text.contains("Rva+Base"))
    }

    fn parse(&self, name: &str, bytes: &[u8]) -> Result<DebugInfo, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| format!("{name}: a map file is text"))?;
        let info = if text.contains("Linker script and memory map") {
            gnu_map(text)
        } else {
            msvc_map(text)
        };
        if info.functions.is_empty() && info.data.is_empty() {
            return Err(format!("{name}: no symbols found in the map"));
        }
        Ok(info)
    }
}

/// A token as the hex address it spells, `0x` said: `0x401000`.
fn hex_address(token: &str) -> Option<u64> {
    let digits = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// A token as bare hex, without the `0x`: MSVC's `00401000`.
fn bare_hex(token: &str) -> Option<u64> {
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(token, 16).ok()
}

/// Whether an output section holds code, by the name linkers give it.
fn code_section(name: &str) -> bool {
    name.starts_with(".text")
        || name == ".init"
        || name.starts_with(".init.")
        || name == ".fini"
        || name.starts_with(".fini.")
        || name == ".plt"
        || name.starts_with(".plt.")
        || name.starts_with(".gnu.linkonce.t")
}

/// A symbol's name as a map spells it, when it is one worth keeping: not
/// an ARM mapping symbol (`$t`, `$d`), not a section's own name.
fn map_symbol_name(name: &str, sections: &[(String, u64, u64)]) -> bool {
    !name.is_empty()
        && !name.starts_with('$')
        && !sections.iter().any(|(section, _, _)| section == name)
}

/// GNU ld's map: the output sections at their addresses, and the symbols
/// under them — a symbol in a code section a function, the rest data.
fn gnu_map(text: &str) -> DebugInfo {
    let mut sections: Vec<(String, u64, u64)> = Vec::new();
    let mut info = DebugInfo::default();
    let mut seen: BTreeMap<u64, String> = BTreeMap::new();
    // A long section name stands on a line of its own, its address and
    // size on the next.
    let mut pending: Option<String> = None;
    let body = text
        .split_once("Linker script and memory map")
        .map(|(_, rest)| rest)
        .unwrap_or(text);
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let mut tokens = trimmed.split_whitespace();
        let first = tokens.next().expect("a non-empty line has a token");
        if !indented {
            // An output section: `.text 0x401000 0x1a2`, a file after.
            let second = tokens.next();
            let third = tokens.next();
            if let (Some(address), Some(size)) =
                (second.and_then(hex_address), third.and_then(hex_address))
            {
                sections.push((first.to_string(), address, size));
                pending = None;
            } else if first.starts_with('.') && second.is_none() {
                pending = Some(first.to_string());
            }
            continue;
        }
        let Some(address) = hex_address(first) else {
            // An input section, a fill, a pattern: not a symbol.
            continue;
        };
        let second = tokens.next();
        let third = tokens.next();
        let (name, size) = match (second, third) {
            (Some(size), Some(name))
                if hex_address(size).is_some() && hex_address(name).is_none() =>
            {
                // `0x401000 0x2f main`: a symbol with its size.
                (name, hex_address(size))
            }
            (Some(size), None) if pending.is_some() && hex_address(size).is_some() => {
                sections.push((
                    pending.take().expect("pending"),
                    address,
                    hex_address(size).expect("hex"),
                ));
                continue;
            }
            (Some(name), _) if hex_address(name).is_none() => (name, None),
            _ => continue,
        };
        if !map_symbol_name(name, &sections) {
            continue;
        }
        if held_back(&mut info.notes, &seen, address, name) {
            continue;
        }
        seen.insert(address, name.to_string());
        let name = plain_name(name);
        let code = sections
            .iter()
            .find(|(_, start, size)| address >= *start && address < start + size)
            .is_some_and(|(section, _, _)| code_section(section));
        if code {
            info.functions.push(DebugFunction {
                address,
                name,
                size,
                prototype: None,
                source: None,
            });
        } else {
            info.data.push(DebugData {
                address,
                name,
                size,
                ctype: None,
            });
        }
    }
    info
}

/// A `0001:00000000` segment:offset token's segment number.
fn segment_of(token: &str) -> Option<u32> {
    let (segment, offset) = token.split_once(':')?;
    if segment.is_empty()
        || offset.is_empty()
        || !segment.chars().all(|c| c.is_ascii_digit())
        || !offset.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    segment.parse().ok()
}

/// MSVC's map: the section table's classes, then the publics at their
/// Rva+Base — a public in a `CODE` section a function, the rest data.
fn msvc_map(text: &str) -> DebugInfo {
    let mut classes: BTreeMap<u32, String> = BTreeMap::new();
    let mut info = DebugInfo::default();
    let mut seen: BTreeMap<u64, String> = BTreeMap::new();
    let mut in_publics = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("Publics by Value") {
            in_publics = true;
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }
        // A section table row: `0001:00000000 000001a2H .text CODE`.
        if tokens.len() >= 4 && tokens[1].ends_with('H') && tokens[2].starts_with('.') {
            if let (Some(segment), Some(_)) = (
                segment_of(tokens[0]),
                bare_hex(&tokens[1][..tokens[1].len() - 1]),
            ) {
                classes.insert(segment, tokens[3].to_string());
                continue;
            }
        }
        if !in_publics {
            continue;
        }
        // A public: `0001:00000000 _main 00401000 hello.obj`.
        let (Some(segment), Some(address)) = (segment_of(tokens[0]), bare_hex(tokens[2])) else {
            continue;
        };
        let name = tokens[1];
        if !map_symbol_name(name, &[]) {
            continue;
        }
        if held_back(&mut info.notes, &seen, address, name) {
            continue;
        }
        seen.insert(address, name.to_string());
        let name = plain_name(name);
        // Without a section table there is nothing to tell code from
        // data, and a public is more often a function than not.
        let code = classes.is_empty() || classes.get(&segment).is_some_and(|class| class == "CODE");
        if code {
            info.functions.push(DebugFunction {
                address,
                name,
                size: None,
                prototype: None,
                source: None,
            });
        } else {
            info.data.push(DebugData {
                address,
                name,
                size: None,
                ctype: None,
            });
        }
    }
    info
}

// ---- The built-in `json` parser: the interchange document. ----

/// A JSON document of the shape a parser command answers with.
struct JsonParser;

impl DebugInfoParser for JsonParser {
    fn name(&self) -> &str {
        "json"
    }

    fn description(&self) -> &str {
        "A JSON document of functions, data and types — the shape a parser command answers with."
    }

    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| *byte == b'{')
    }

    fn parse(&self, name: &str, bytes: &[u8]) -> Result<DebugInfo, String> {
        let answer: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| format!("{name}: not JSON: {error}"))?;
        let object = answer
            .as_object()
            .ok_or_else(|| format!("{name}: a debug info document is a JSON object"))?;
        if !["functions", "data", "types"]
            .iter()
            .any(|key| object.contains_key(*key))
        {
            return Err(format!(
                "{name}: not a debug info document: no functions, data or types"
            ));
        }
        plugin::debug_info_of(&answer).map_err(|error| format!("{name}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GNU ld map of the sample's own layout: `.text` at 0x1060, `.data`
    /// at 0x4000, `.bss` at 0x4010.
    const GNU_MAP: &str = "\
Archive member included to satisfy reference by file (symbol)

Memory Configuration

Name             Origin             Length             Attributes
*default*        0x0000000000000000 0xffffffffffffffff

Linker script and memory map

LOAD sample.o
                0x0000000000000000                __executable_start
.init           0x0000000000001000      0x1b
 .init          0x0000000000001000      0x1b crti.o
                0x0000000000001000                _init
.text           0x0000000000001060     0x18c
 *(.text.unlikely .text.*_unlikely .text.unlikely.*)
 .text          0x0000000000001060      0x40 sample.o
                0x0000000000001060                _start
                0x0000000000001149                add
                0x0000000000001161                sum_to
                0x0000000000001198                main
 *fill*         0x00000000000011e0      0xc
.fini           0x00000000000011ec       0xd
                0x00000000000011ec                _fini
.rodata         0x0000000000002000       0x8
 .rodata        0x0000000000002000       0x8 sample.o
                0x0000000000002000                .LC0
.data           0x0000000000004000       0x8
 .data          0x0000000000004000       0x8 sample.o
                0x0000000000004000                __data_start
                0x0000000000004008                __dso_handle
.bss            0x0000000000004010       0x8
                0x0000000000004010                completed.0
                0x0000000000004018                _end
OUTPUT(sample.elf elf64-x86-64)
";

    #[test]
    fn a_gnu_map_reads_its_symbols_under_their_sections() {
        let parser = MapParser;
        assert!(parser.recognizes(GNU_MAP.as_bytes()));
        let info = parser.parse("sample.map", GNU_MAP.as_bytes()).unwrap();
        let functions: Vec<(u64, &str)> = info
            .functions
            .iter()
            .map(|f| (f.address, f.name.as_str()))
            .collect();
        assert_eq!(
            functions,
            vec![
                (0x1000, "_init"),
                (0x1060, "_start"),
                (0x1149, "add"),
                (0x1161, "sum_to"),
                (0x1198, "main"),
                (0x11ec, "_fini"),
            ]
        );
        let data: Vec<(u64, &str)> = info
            .data
            .iter()
            .map(|d| (d.address, d.name.as_str()))
            .collect();
        assert_eq!(
            data,
            vec![
                (0x0, "__executable_start"),
                (0x2000, ".LC0"),
                (0x4000, "__data_start"),
                (0x4008, "__dso_handle"),
                (0x4010, "completed.0"),
                (0x4018, "_end"),
            ]
        );
        assert!(info.notes.is_empty(), "{:?}", info.notes);
    }

    #[test]
    fn a_gnu_map_holds_back_a_second_symbol_at_one_address() {
        let text =
            format!("{GNU_MAP}                0x0000000000001198                main_alias\n");
        let info = MapParser.parse("sample.map", text.as_bytes()).unwrap();
        assert!(info.functions.iter().all(|f| f.name != "main_alias"));
        assert_eq!(info.notes.len(), 1);
        assert!(
            info.notes[0].contains("main_alias held back"),
            "{:?}",
            info.notes
        );
        assert!(info.notes[0].contains("main"), "{:?}", info.notes);
    }

    #[test]
    fn a_gnu_map_reads_a_wrapped_section_name_and_a_symbol_with_a_size() {
        let text = "\
Linker script and memory map

.a.very.long.section.name
                0x0000000000005000      0x10
                0x0000000000005000      0x10                table
";
        let info = MapParser.parse("long.map", text.as_bytes()).unwrap();
        assert_eq!(info.data.len(), 1);
        assert_eq!(info.data[0].name, "table");
        assert_eq!(info.data[0].size, Some(0x10));
    }

    #[test]
    fn a_gnu_map_demangles_the_names_it_reads() {
        let text = "\
Linker script and memory map

.text           0x0000000000001000      0x10
                0x0000000000001000                _ZN8geometry4areaEii
";
        let info = MapParser.parse("cxx.map", text.as_bytes()).unwrap();
        assert_eq!(info.functions[0].name, "geometry::area(int, int)");
    }

    #[test]
    fn a_gnu_map_skips_mapping_symbols_and_section_names() {
        let text = "\
Linker script and memory map

.text           0x0000000000001000      0x20
                0x0000000000001000                $t
                0x0000000000001004                .text
                0x0000000000001008                real
";
        let info = MapParser.parse("arm.map", text.as_bytes()).unwrap();
        assert_eq!(info.functions.len(), 1);
        assert_eq!(info.functions[0].name, "real");
    }

    /// An MSVC map: the section table, then the publics by value.
    const MSVC_MAP: &str = "\
Microsoft (R) Incremental Linker Version 14.29.30151.0
Copyright (C) Microsoft Corporation.  All rights reserved.

 Start         Length     Name                   Class
 0001:00000000 000001a2H .text                   CODE
 0002:00000000 00000010H .data                   DATA
 0003:00000000 00000008H .bss                    BSS

 Address         Publics by Value              Rva+Base               Lib:Object

 0000:00000000       ___ImageBase               00400000     <linker-defined>
 0001:00000000       _main                      00401000     hello.obj
 0001:00000050       ?area@geometry@@YAHHH@Z    00401050     hello.obj
 0002:00000000       _counter                   00403000     hello.obj
 0003:00000000       _flag                      00404000     hello.obj

 entry point at 0001:00000000
";

    #[test]
    fn an_msvc_map_reads_its_publics_by_the_section_classes() {
        let parser = MapParser;
        assert!(parser.recognizes(MSVC_MAP.as_bytes()));
        let info = parser.parse("hello.map", MSVC_MAP.as_bytes()).unwrap();
        let functions: Vec<(u64, &str)> = info
            .functions
            .iter()
            .map(|f| (f.address, f.name.as_str()))
            .collect();
        assert_eq!(
            functions,
            vec![(0x401000, "_main"), (0x401050, "geometry::area(int, int)"),]
        );
        let data: Vec<(u64, &str)> = info
            .data
            .iter()
            .map(|d| (d.address, d.name.as_str()))
            .collect();
        assert_eq!(
            data,
            vec![
                (0x400000, "___ImageBase"),
                (0x403000, "_counter"),
                (0x404000, "_flag"),
            ]
        );
    }

    #[test]
    fn a_map_without_symbols_is_refused() {
        let text = "Linker script and memory map\n\nLOAD sample.o\n";
        let error = MapParser.parse("empty.map", text.as_bytes()).unwrap_err();
        assert!(error.contains("no symbols"), "{error}");
    }

    #[test]
    fn a_map_is_not_recognized_in_bytes_that_are_not_text() {
        assert!(!MapParser.recognizes(&[0xff, 0xfe, 0x00, 0x01]));
        assert!(!MapParser.recognizes(b"just some text"));
    }

    const JSON: &str = r#"{
        "functions": [
            { "address": "0x1198", "name": "main", "size": 52,
              "prototype": "int main(int argc, char **argv)", "source": "main.c:10" },
            { "address": 4425, "name": "add" }
        ],
        "data": [ { "address": "0x4008", "name": "__dso_handle", "size": 8, "type": "void *" } ],
        "types": [ "struct point { int x; int y; };" ],
        "notes": [ "a note" ]
    }"#;

    #[test]
    fn a_json_document_reads_every_field() {
        let parser = JsonParser;
        assert!(parser.recognizes(JSON.as_bytes()));
        assert!(parser.recognizes(b"\n\t  {"));
        assert!(!parser.recognizes(b"[1, 2]"));
        let info = parser.parse("debug.json", JSON.as_bytes()).unwrap();
        assert_eq!(info.functions.len(), 2);
        assert_eq!(info.functions[0].address, 0x1198);
        assert_eq!(info.functions[0].size, Some(52));
        assert_eq!(
            info.functions[0].prototype.as_deref(),
            Some("int main(int argc, char **argv)")
        );
        assert_eq!(info.functions[0].source.as_deref(), Some("main.c:10"));
        assert_eq!(info.functions[1].address, 0x1149);
        assert_eq!(info.functions[1].prototype, None);
        assert_eq!(info.data[0].ctype.as_deref(), Some("void *"));
        assert_eq!(info.types, vec!["struct point { int x; int y; };"]);
        assert_eq!(info.notes, vec!["a note"]);
    }

    #[test]
    fn a_json_object_that_is_not_debug_info_is_refused() {
        let error = JsonParser
            .parse("config.json", br#"{"setting": true}"#)
            .unwrap_err();
        assert!(error.contains("not a debug info document"), "{error}");
        let error = JsonParser.parse("bad.json", b"{").unwrap_err();
        assert!(error.contains("not JSON"), "{error}");
    }

    #[test]
    fn parse_offers_the_builtins_and_names_the_parser() {
        let _guard = REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let parsed = parse("sample.map", GNU_MAP.as_bytes(), None).unwrap();
        assert_eq!(parsed.parser, "map");
        assert!(!parsed.info.functions.is_empty());
        let parsed = parse("debug.json", JSON.as_bytes(), None).unwrap();
        assert_eq!(parsed.parser, "json");
        // A format by name reads even a file the parser would not claim.
        let parsed = parse("odd.bin", JSON.as_bytes(), Some("json")).unwrap();
        assert_eq!(parsed.parser, "json");
        let error = parse("odd.bin", b"nonsense", None).unwrap_err();
        assert!(error.contains("no debug info parser recognizes"), "{error}");
        assert!(error.contains("map, json"), "{error}");
        let error = parse("x", b"{}", Some("nope")).unwrap_err();
        assert!(error.contains("no debug info parser is called"), "{error}");
    }

    /// A parser of a test's own, registered under a name.
    struct TestParser {
        name: &'static str,
        claims: bool,
        reads: bool,
    }

    impl DebugInfoParser for TestParser {
        fn name(&self) -> &str {
            self.name
        }
        fn recognizes(&self, _bytes: &[u8]) -> bool {
            self.claims
        }
        fn parse(&self, _name: &str, _bytes: &[u8]) -> Result<DebugInfo, String> {
            if self.reads {
                Ok(DebugInfo {
                    functions: vec![DebugFunction {
                        address: 0x1000,
                        name: "from_the_plugin".to_string(),
                        size: None,
                        prototype: None,
                        source: None,
                    }],
                    ..Default::default()
                })
            } else {
                Err("it does not read".to_string())
            }
        }
    }

    #[test]
    fn a_registered_parser_is_offered_first_and_may_shadow_a_builtin() {
        let _guard = REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        plugin::register_debug_info_parser(Arc::new(TestParser {
            name: "test-first",
            claims: true,
            reads: true,
        }));
        let parsed = parse("sample.map", GNU_MAP.as_bytes(), None).unwrap();
        assert_eq!(parsed.parser, "test-first");
        assert_eq!(parsed.info.functions[0].name, "from_the_plugin");
        assert!(available().starts_with(&["test-first".to_string()]));
        plugin::unregister_debug_info_parser("test-first");

        // A parser that claims the file but fails leaves it to the next.
        plugin::register_debug_info_parser(Arc::new(TestParser {
            name: "test-fails",
            claims: true,
            reads: false,
        }));
        let parsed = parse("sample.map", GNU_MAP.as_bytes(), None).unwrap();
        assert_eq!(parsed.parser, "map");
        // By name, its failure is the read's failure.
        let error = parse("sample.map", GNU_MAP.as_bytes(), Some("test-fails")).unwrap_err();
        assert!(error.contains("test-fails"), "{error}");
        plugin::unregister_debug_info_parser("test-fails");

        // A registered `map` shadows the built-in one.
        plugin::register_debug_info_parser(Arc::new(TestParser {
            name: "map",
            claims: true,
            reads: true,
        }));
        let parsed = parse("sample.map", GNU_MAP.as_bytes(), None).unwrap();
        assert_eq!(parsed.info.functions[0].name, "from_the_plugin");
        assert_eq!(
            available().iter().filter(|name| *name == "map").count(),
            1,
            "the built-in map is shadowed, not listed twice"
        );
        plugin::unregister_debug_info_parser("map");
        assert_eq!(available(), vec!["map".to_string(), "json".to_string()]);
    }
}
