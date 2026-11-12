//! `ag image … gzf`: the analysis for Ghidra, run against the sample ELF.
//! The file is read back here as an XML document, by a small parser written
//! for the test — an independent reader, not the writer's own tables — and
//! the memory sidecar is checked against the image's own bytes.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

/// A unique temporary path stem, so parallel tests do not share a file.
fn stem(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ag-cli-gzf-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Run `ag` with `args`, returning its stdout, and assert it succeeded.
fn ag(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(args)
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "ag {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ---------------------------------------------------------------------
// A small XML reader, enough for the document the writer writes: processing
// instructions, elements with attributes, nested children, and text. No
// DTD, no namespaces, no CDATA — the writer emits none of them.

/// One element: its name, its attributes in order, its children, and its
/// text (the whitespace between children for a parent, the content for a
/// leaf).
#[derive(Debug, Clone)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Element>,
    text: String,
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
    fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }
    fn children_named(&self, name: &str) -> Vec<&Element> {
        self.children
            .iter()
            .filter(|child| child.name == name)
            .collect()
    }
    /// Every element of `name` in the tree, this one included.
    fn all(&self, name: &str) -> Vec<&Element> {
        let mut out = Vec::new();
        if self.name == name {
            out.push(self);
        }
        for child in &self.children {
            out.extend(child.all(name));
        }
        out
    }
    /// The first element of `name` whose `attr` equals `value`.
    fn find(&self, name: &str, attr: &str, value: &str) -> Option<&Element> {
        self.all(name)
            .into_iter()
            .find(|element| element.attr(attr) == Some(value))
    }
    /// An address attribute, read as the hexadecimal the writer writes.
    fn addr(&self, attr: &str) -> u64 {
        u64::from_str_radix(self.attr(attr).expect("an address attribute"), 16)
            .expect("a hexadecimal address")
    }
}

/// The character references the writer escapes, read back to characters.
fn unescape(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let mut entity = String::new();
        for next in chars.by_ref() {
            if next == ';' {
                break;
            }
            entity.push(next);
        }
        match entity.as_str() {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                out.push('&');
                out.push_str(&entity);
                out.push(';');
            }
        }
    }
    out
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Parser {
            bytes: text.as_bytes(),
            at: 0,
        }
    }
    fn starts(&self, pattern: &str) -> bool {
        self.bytes[self.at..].starts_with(pattern.as_bytes())
    }
    fn whitespace(&mut self) {
        while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_whitespace() {
            self.at += 1;
        }
    }
    fn skip_past(&mut self, end: &str) {
        let from = self.at;
        let rest = &self.bytes[from..];
        let found = rest
            .windows(end.len())
            .position(|window| window == end.as_bytes())
            .expect("a closing delimiter");
        self.at = from + found + end.len();
    }
    /// The document: its leading processing instructions, then the root.
    fn document(&mut self) -> Element {
        loop {
            self.whitespace();
            if self.starts("<?") {
                self.skip_past("?>");
            } else if self.starts("<!--") {
                self.skip_past("-->");
            } else {
                break;
            }
        }
        self.element()
    }
    /// One element, from its `<` to its `>` or `/>`.
    fn element(&mut self) -> Element {
        assert!(self.starts("<"), "an element opens");
        self.at += 1;
        let name = self.name();
        let attrs = self.attrs();
        if self.starts("/>") {
            self.at += 2;
            return Element {
                name,
                attrs,
                children: Vec::new(),
                text: String::new(),
            };
        }
        assert!(self.starts(">"), "the start tag closes");
        self.at += 1;
        let mut children = Vec::new();
        let mut text = Vec::new();
        loop {
            if self.starts("</") {
                self.at += 2;
                let close = self.name();
                assert_eq!(close, name, "the end tag matches the start");
                self.whitespace();
                assert!(self.starts(">"), "the end tag closes");
                self.at += 1;
                break;
            } else if self.starts("<!--") {
                self.skip_past("-->");
            } else if self.starts("<?") {
                self.skip_past("?>");
            } else if self.starts("<") {
                children.push(self.element());
            } else {
                text.push(self.bytes[self.at]);
                self.at += 1;
            }
        }
        Element {
            name,
            attrs,
            children,
            text: unescape(&String::from_utf8_lossy(&text)),
        }
    }
    /// A tag or attribute name, up to the character that ends it.
    fn name(&mut self) -> String {
        let start = self.at;
        while self.at < self.bytes.len()
            && !matches!(
                self.bytes[self.at],
                b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/' | b'='
            )
        {
            self.at += 1;
        }
        String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned()
    }
    /// The attributes, up to the `>` or `/>` that ends the start tag.
    fn attrs(&mut self) -> Vec<(String, String)> {
        let mut attrs = Vec::new();
        loop {
            self.whitespace();
            if self.starts(">") || self.starts("/>") {
                break;
            }
            let name = self.name();
            self.whitespace();
            assert!(self.starts("="), "an attribute is assigned");
            self.at += 1;
            self.whitespace();
            assert!(self.starts("\""), "an attribute value is quoted");
            self.at += 1;
            let start = self.at;
            while self.at < self.bytes.len() && self.bytes[self.at] != b'"' {
                self.at += 1;
            }
            let value = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
            self.at += 1;
            attrs.push((name, unescape(&value)));
        }
        attrs
    }
}

fn parse(xml: &str) -> Element {
    Parser::new(xml).document()
}

#[test]
fn the_image_is_written_as_a_ghidra_xml_program() {
    let sample = fixture("sample.elf");
    let stem = stem("plain");
    let file = stem.with_extension("gzf");
    let sidecar = stem.with_extension("bytes");
    let said = ag(&[
        "image",
        sample.to_str().unwrap(),
        "gzf",
        file.to_str().unwrap(),
    ]);
    // Two lines: the program, and the memory beside it.
    assert_eq!(
        said.lines()
            .filter(|line| line.starts_with("wrote "))
            .count(),
        2,
        "{said}"
    );
    assert!(said.contains("functions"), "{said}");

    let xml = std::fs::read_to_string(&file).expect("the program was written");
    let bytes = std::fs::read(&sidecar).expect("the memory was written");
    let root = parse(&xml);
    assert_eq!(root.name, "PROGRAM");
    assert_eq!(root.attr("NAME"), Some("sample.elf"));

    // The processor: the SLEIGH language and compiler spec the image reads
    // under, and the byte order.
    let processor = root.child("PROCESSOR").expect("a processor");
    assert_eq!(processor.attr("NAME"), Some("x86"));
    assert_eq!(
        processor.attr("LANGUAGE_PROVIDER"),
        Some("x86:LE:64:default:gcc")
    );
    assert_eq!(processor.attr("ENDIAN"), Some("little"));
    assert_eq!(root.child("COMPILER").unwrap().attr("NAME"), Some("gcc"));
    assert!(root
        .child("INFO_SOURCE")
        .unwrap()
        .attr("TOOL")
        .unwrap()
        .starts_with("AdmiralGrace"));

    // The memory map: code is read-execute, constant data read, the rest
    // read-write; the zero-filled data is uninitialized.
    let map = root.child("MEMORY_MAP").expect("a memory map");
    let sections = map.children_named("MEMORY_SECTION");
    assert!(!sections.is_empty());
    // The container's metadata sections, which all sit at zero, are left
    // out: mapped, they would overlap one another.
    assert!(sections.iter().all(|s| s.attr("START_ADDR") != Some("0")));
    assert_eq!(
        root.find("MEMORY_SECTION", "NAME", ".text")
            .unwrap()
            .attr("PERMISSIONS"),
        Some("rx")
    );
    assert_eq!(
        root.find("MEMORY_SECTION", "NAME", ".rodata")
            .unwrap()
            .attr("PERMISSIONS"),
        Some("r")
    );
    assert_eq!(
        root.find("MEMORY_SECTION", "NAME", ".data")
            .unwrap()
            .attr("PERMISSIONS"),
        Some("rw")
    );
    let bss = root.find("MEMORY_SECTION", "NAME", ".bss").unwrap();
    assert_eq!(bss.attr("PERMISSIONS"), Some("rw"));
    assert!(
        bss.child("MEMORY_CONTENTS").is_none(),
        ".bss holds no file bytes"
    );

    // The sidecar: every section's contents are the image's own bytes at
    // its address, laid end to end, and the sidecar holds exactly them.
    let image = ag_image::Binary::open(&sample).expect("the sample loads");
    let sidecar_name = sidecar.file_name().unwrap().to_str().unwrap();
    let mut offset = 0usize;
    for section in &sections {
        let Some(contents) = section.child("MEMORY_CONTENTS") else {
            continue;
        };
        assert_eq!(contents.attr("FILE_NAME"), Some(sidecar_name));
        let file_offset = contents
            .attr("FILE_OFFSET")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let length = contents.attr("LENGTH").unwrap().parse::<usize>().unwrap();
        assert_eq!(file_offset, offset, "the contents are laid end to end");
        let expected = image
            .bytes_at(section.addr("START_ADDR"), length)
            .expect("the image holds the section's bytes");
        assert_eq!(
            &bytes[file_offset..file_offset + length],
            expected.as_slice(),
            "the bytes of {}",
            section.attr("NAME").unwrap()
        );
        offset += length;
    }
    assert_eq!(
        offset,
        bytes.len(),
        "the sidecar holds exactly the contents"
    );
    // Independent of the writer: the interpreter path the ELF names is in
    // the sidecar's first bytes.
    assert!(bytes.starts_with(b"/lib64/ld-linux-x86-64.so.2"));

    // The code ranges cover main, so Ghidra disassembles it on import.
    let code = root.child("CODE").expect("code");
    let blocks = code.children_named("CODE_BLOCK");
    assert!(!blocks.is_empty());
    assert!(blocks
        .iter()
        .any(|block| block.addr("START") <= 0x1198 && 0x1198 <= block.addr("END")));

    // The entry point is the image's.
    let entry = root
        .child("PROGRAM_ENTRY_POINTS")
        .unwrap()
        .child("PROGRAM_ENTRY_POINT")
        .unwrap();
    assert_eq!(entry.attr("ADDRESS"), Some("1060"));

    // The symbol table: main under the analysis, the import under the
    // loader, at their own addresses.
    let main_symbol = root.find("SYMBOL", "ADDRESS", "1198").expect("main");
    assert_eq!(main_symbol.attr("NAME"), Some("main"));
    assert_eq!(main_symbol.attr("SOURCE_TYPE"), Some("ANALYSIS"));
    let import = root.find("SYMBOL", "ADDRESS", "3fd0").expect("the import");
    assert_eq!(import.attr("NAME"), Some("printf"));
    assert_eq!(import.attr("SOURCE_TYPE"), Some("IMPORTED"));

    // The function: its name, its body, a return type.
    let main = root.find("FUNCTION", "ENTRY_POINT", "1198").expect("main");
    assert_eq!(main.attr("NAME"), Some("main"));
    assert_eq!(main.attr("LIBRARY_FUNCTION"), Some("n"));
    assert!(main.child("RETURN_TYPE").is_some());
    assert_eq!(
        main.child("ADDRESS_RANGE").unwrap().attr("START"),
        Some("1198")
    );

    // The platform's types travel with the program.
    assert!(root.find("STRUCTURE", "NAME", "timeval").is_some());

    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(&sidecar);
}

#[test]
fn the_projects_names_comments_types_and_prototypes_are_written() {
    let sample = fixture("sample.elf");
    let stem = stem("project");
    let project = stem.with_extension("agproj");
    let file = stem.with_extension("gzf");
    let sidecar = stem.with_extension("bytes");
    let _ = std::fs::remove_file(&project);
    let target = sample.to_str().unwrap();
    let path = project.to_str().unwrap();

    ag(&[
        "project",
        target,
        "rename",
        "--file",
        path,
        "0x1198",
        "entry_point",
    ]);
    ag(&[
        "project",
        target,
        "comment",
        "--file",
        path,
        "0x11b5",
        "adds three",
    ]);
    // A comment above the address, with markup the writer must escape.
    ag(&[
        "project",
        target,
        "comment",
        "--file",
        path,
        "0x1198",
        "the <entry> & \"exit\"",
        "--above",
    ]);
    ag(&[
        "project",
        target,
        "types",
        "--file",
        path,
        "add",
        "struct point { int x; int y; }; enum color { RED, GREEN = 5, BLUE }; typedef struct point point_t;",
    ]);
    ag(&[
        "project",
        target,
        "function-props",
        "--file",
        path,
        "0x1198",
        "--prototype",
        "int entry_point(int argc, char **argv)",
    ]);
    ag(&[
        "project", target, "rename", "--file", path, "0x4010", "g_counts",
    ]);

    ag(&[
        "image",
        target,
        "gzf",
        file.to_str().unwrap(),
        "--project",
        path,
    ]);
    let root = parse(&std::fs::read_to_string(&file).expect("the program was written"));

    // The rename: the function and its symbol under the analyst's name,
    // marked as the analyst's own.
    let entry = root
        .find("FUNCTION", "ENTRY_POINT", "1198")
        .expect("the function");
    assert_eq!(entry.attr("NAME"), Some("entry_point"));
    let symbol = root.find("SYMBOL", "ADDRESS", "1198").unwrap();
    assert_eq!(symbol.attr("NAME"), Some("entry_point"));
    assert_eq!(symbol.attr("SOURCE_TYPE"), Some("USER_DEFINED"));

    // The whole prototype travels as the type-information comment Ghidra
    // parses, parameters and all.
    let typeinfo = entry.child("TYPEINFO_CMT").expect("the prototype");
    assert_eq!(typeinfo.text, "int entry_point(int argc, char **argv)");

    // The comments: one beside the address, one above it, the markup read
    // back as the analyst wrote it.
    let eol = root
        .find("COMMENT", "ADDRESS", "11b5")
        .expect("the comment");
    assert_eq!(eol.attr("TYPE"), Some("end-of-line"));
    assert_eq!(eol.text, "adds three");
    let pre = root
        .find("COMMENT", "ADDRESS", "1198")
        .expect("the comment");
    assert_eq!(pre.attr("TYPE"), Some("pre"));
    assert_eq!(pre.text, "the <entry> & \"exit\"");

    // The structure: its size, and its members at their offsets.
    let point = root.find("STRUCTURE", "NAME", "point").expect("point");
    assert_eq!(point.attr("SIZE"), Some("8"));
    let members = point.children_named("MEMBER");
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].attr("NAME"), Some("x"));
    assert_eq!(members[0].attr("OFFSET"), Some("0"));
    assert_eq!(members[0].attr("DATATYPE"), Some("int"));
    assert_eq!(members[1].attr("NAME"), Some("y"));
    assert_eq!(members[1].attr("OFFSET"), Some("4"));

    // The enumeration: its enumerators and their values.
    let color = root.find("ENUM", "NAME", "color").expect("color");
    let entries = color.children_named("ENUM_ENTRY");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].attr("NAME"), Some("RED"));
    assert_eq!(entries[0].attr("VALUE"), Some("0"));
    assert_eq!(entries[1].attr("VALUE"), Some("5"));
    assert_eq!(entries[2].attr("VALUE"), Some("6"));

    // The typedef names the structure.
    let typedef = root.find("TYPE_DEF", "NAME", "point_t").expect("point_t");
    assert_eq!(typedef.attr("DATATYPE"), Some("point"));

    // The data rename.
    let counts = root.find("SYMBOL", "ADDRESS", "4010").expect("g_counts");
    assert_eq!(counts.attr("NAME"), Some("g_counts"));
    assert_eq!(counts.attr("SOURCE_TYPE"), Some("USER_DEFINED"));

    let _ = std::fs::remove_file(&project);
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(&sidecar);
}

#[test]
fn a_thirty_two_bit_image_writes_a_thirty_two_bit_program() {
    let sample = fixture("boundaries32.elf");
    let stem = stem("bits32");
    let file = stem.with_extension("gzf");
    let sidecar = stem.with_extension("bytes");
    ag(&[
        "image",
        sample.to_str().unwrap(),
        "gzf",
        file.to_str().unwrap(),
    ]);
    let root = parse(&std::fs::read_to_string(&file).expect("the program was written"));
    assert_eq!(root.attr("NAME"), Some("boundaries32.elf"));
    let processor = root.child("PROCESSOR").expect("a processor");
    assert_eq!(processor.attr("NAME"), Some("x86"));
    assert_eq!(processor.attr("ENDIAN"), Some("little"));
    let provider = processor.attr("LANGUAGE_PROVIDER").unwrap();
    assert!(provider.contains(":32:"), "{provider}");

    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(&sidecar);
}
