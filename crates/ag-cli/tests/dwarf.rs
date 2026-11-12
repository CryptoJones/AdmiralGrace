//! `ag image … dwarf`: the analysis as DWARF debug information, run
//! against the sample ELF. The file is read back here as an ELF container
//! and a DWARF unit, by the bytes the DWARF 4 specification lays out — an
//! independent reader, not the writer's own tables.

use std::collections::HashMap;
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
        "ag-cli-dwarf-{tag}-{}-{:?}",
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

// The DWARF constants the reader needs, as the specification numbers them.
const TAG_ARRAY: u64 = 0x01;
const TAG_ENUM: u64 = 0x04;
const TAG_FORMAL: u64 = 0x05;
const TAG_MEMBER: u64 = 0x0d;
const TAG_POINTER: u64 = 0x0f;
const TAG_UNIT: u64 = 0x11;
const TAG_STRUCT: u64 = 0x13;
const TAG_TYPEDEF: u64 = 0x16;
const TAG_SUBRANGE: u64 = 0x21;
const TAG_BASE: u64 = 0x24;
const TAG_ENUMERATOR: u64 = 0x28;
const TAG_SUBPROGRAM: u64 = 0x2e;
const TAG_VARIABLE: u64 = 0x34;

const AT_LOCATION: u64 = 0x02;
const AT_NAME: u64 = 0x03;
const AT_BYTE_SIZE: u64 = 0x0b;
const AT_BIT_SIZE: u64 = 0x0d;
const AT_LOW_PC: u64 = 0x11;
const AT_HIGH_PC: u64 = 0x12;
const AT_CONST_VALUE: u64 = 0x1c;
const AT_COUNT: u64 = 0x37;
const AT_MEMBER_LOCATION: u64 = 0x38;
const AT_ENCODING: u64 = 0x3e;
const AT_TYPE: u64 = 0x49;
const AT_BIT_OFFSET: u64 = 0x6b;

/// One section table entry: name offset, type, file offset, size, link,
/// info, and entry size.
type Section = (u32, u32, usize, usize, usize, usize, usize);

/// One abbreviation: its tag, whether it has children, and its attributes,
/// each an attribute name and the form its value is written in.
type Abbrev = (u64, bool, Vec<(u64, u64)>);

/// One attribute's value, as the reader reads it off the wire.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Addr(u64),
    Unsigned(u64),
    Signed(i64),
    Str(String),
    Ref(u64),
    Flag,
    Block(Vec<u8>),
}

/// One DIE the reader read: its tag, its offset in the unit, the offset of
/// its parent (`None` for the unit), and its attributes.
#[derive(Debug, Clone)]
struct Die {
    tag: u64,
    offset: u64,
    parent: Option<u64>,
    attrs: HashMap<u64, Value>,
}

impl Die {
    fn name(&self) -> Option<&str> {
        match self.attrs.get(&AT_NAME) {
            Some(Value::Str(name)) => Some(name),
            _ => None,
        }
    }
    fn unsigned(&self, at: u64) -> Option<u64> {
        match self.attrs.get(&at) {
            Some(Value::Unsigned(value)) => Some(*value),
            _ => None,
        }
    }
    fn reference(&self, at: u64) -> Option<u64> {
        match self.attrs.get(&at) {
            Some(Value::Ref(offset)) => Some(*offset),
            _ => None,
        }
    }
}

/// The file read back: its ELF facts, its DIEs by offset, and its symbols.
struct Read {
    elf64: bool,
    little_endian: bool,
    machine: u16,
    address_size: u8,
    dies: Vec<Die>,
    by_offset: HashMap<u64, Die>,
    symbols: Vec<(String, u64, u64, bool)>,
}

impl Read {
    fn die(&self, offset: u64) -> &Die {
        self.by_offset.get(&offset).expect("a DIE at the offset")
    }

    /// The first DIE of `tag` under `name`.
    fn named(&self, tag: u64, name: &str) -> &Die {
        self.dies
            .iter()
            .find(|die| die.tag == tag && die.name() == Some(name))
            .unwrap_or_else(|| panic!("no {tag:#x} named {name}"))
    }

    /// The children of the DIE at `offset`, in the order they stand.
    fn children(&self, offset: u64) -> Vec<&Die> {
        self.dies
            .iter()
            .filter(|die| die.parent == Some(offset))
            .collect()
    }
}

/// A cursor over the bytes, reading the integers of the format.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    le: bool,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], le: bool) -> Self {
        Cursor { bytes, at: 0, le }
    }
    fn u8(&mut self) -> u8 {
        let byte = self.bytes[self.at];
        self.at += 1;
        byte
    }
    fn fixed(&mut self, width: usize) -> u64 {
        let slice = &self.bytes[self.at..self.at + width];
        self.at += width;
        let mut buf = [0u8; 8];
        if self.le {
            buf[..width].copy_from_slice(slice);
            u64::from_le_bytes(buf)
        } else {
            buf[8 - width..].copy_from_slice(slice);
            u64::from_be_bytes(buf)
        }
    }
    fn uleb(&mut self) -> u64 {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.u8();
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }
    fn sleb(&mut self) -> i64 {
        let mut value = 0i64;
        let mut shift = 0;
        loop {
            let byte = self.u8();
            value |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if byte & 0x40 != 0 && shift < 64 {
                    value |= -1i64 << shift;
                }
                return value;
            }
        }
    }
    fn take(&mut self, len: usize) -> &'a [u8] {
        let slice = &self.bytes[self.at..self.at + len];
        self.at += len;
        slice
    }
}

/// Read the file as an ELF container holding a DWARF unit.
fn read(bytes: &[u8]) -> Read {
    assert_eq!(&bytes[..4], b"\x7fELF", "an ELF file");
    let elf64 = bytes[4] == 2;
    let le = bytes[5] == 1;
    let mut header = Cursor::new(bytes, le);
    header.at = 16;
    let _type = header.fixed(2);
    let machine = header.fixed(2) as u16;
    let _version = header.fixed(4);
    let address_size = if elf64 { 8 } else { 4 };
    let _entry = header.fixed(address_size);
    let _phoff = header.fixed(if elf64 { 8 } else { 4 });
    let shoff = header.fixed(if elf64 { 8 } else { 4 }) as usize;
    let _flags = header.fixed(4);
    let _ehsize = header.fixed(2);
    let _phentsize = header.fixed(2);
    let _phnum = header.fixed(2);
    let shentsize = header.fixed(2) as usize;
    let shnum = header.fixed(2) as usize;
    let shstrndx = header.fixed(2) as usize;

    // The section table: each section's name offset, type, offset, size,
    // link, info, alignment and entry size.
    let mut sections = Vec::new();
    for index in 0..shnum {
        let mut entry = Cursor::new(&bytes[shoff + index * shentsize..], le);
        let name = entry.fixed(4) as u32;
        let kind = entry.fixed(4) as u32;
        let _flags = entry.fixed(if elf64 { 8 } else { 4 });
        let _addr = entry.fixed(if elf64 { 8 } else { 4 });
        let offset = entry.fixed(if elf64 { 8 } else { 4 }) as usize;
        let size = entry.fixed(if elf64 { 8 } else { 4 }) as usize;
        let link = entry.fixed(4) as usize;
        let info = entry.fixed(4) as usize;
        let _align = entry.fixed(if elf64 { 8 } else { 4 });
        let entsize = entry.fixed(if elf64 { 8 } else { 4 }) as usize;
        sections.push((name, kind, offset, size, link, info, entsize));
    }
    let shstr = sections[shstrndx];
    let shstr_bytes = &bytes[shstr.2..shstr.2 + shstr.3];
    let name_of = |offset: u32| -> String {
        let start = offset as usize;
        let end = shstr_bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap()
            + start;
        String::from_utf8_lossy(&shstr_bytes[start..end]).into_owned()
    };
    let section =
        |name: &str| -> Option<&Section> { sections.iter().find(|entry| name_of(entry.0) == name) };

    // The string table the DWARF strings point into.
    let debug_str = section(".debug_str").expect("a .debug_str section");
    let strings = &bytes[debug_str.2..debug_str.2 + debug_str.3];
    let string_at = |offset: u64| -> String {
        let start = offset as usize;
        let end = strings[start..].iter().position(|byte| *byte == 0).unwrap() + start;
        String::from_utf8_lossy(&strings[start..end]).into_owned()
    };

    // The abbreviation table: code -> (tag, has children, attributes).
    let abbrev = section(".debug_abbrev").expect("a .debug_abbrev section");
    let mut abbrevs: HashMap<u64, Abbrev> = HashMap::new();
    let mut cursor = Cursor::new(&bytes[abbrev.2..abbrev.2 + abbrev.3], le);
    loop {
        let code = cursor.uleb();
        if code == 0 {
            break;
        }
        let tag = cursor.uleb();
        let children = cursor.u8() != 0;
        let mut attrs = Vec::new();
        loop {
            let at = cursor.uleb();
            let form = cursor.uleb();
            if at == 0 && form == 0 {
                break;
            }
            attrs.push((at, form));
        }
        abbrevs.insert(code, (tag, children, attrs));
    }

    // The unit: its header, then its DIEs under the abbreviations.
    let info = section(".debug_info").expect("a .debug_info section");
    let info_bytes = &bytes[info.2..info.2 + info.3];
    let mut unit = Cursor::new(info_bytes, le);
    let length = unit.fixed(4) as usize;
    let version = unit.fixed(2);
    let _abbrev_offset = unit.fixed(4);
    let unit_address_size = unit.u8();
    assert_eq!(version, 4, "DWARF 4");
    assert_eq!(length + 4, info_bytes.len(), "the unit spans the section");
    let end = 4 + length;
    let mut dies = Vec::new();
    let mut by_offset = HashMap::new();
    // The ancestor at each depth, so a DIE finds its parent.
    let mut ancestors: Vec<u64> = Vec::new();
    let mut depth = 0usize;
    while unit.at < end {
        let offset = unit.at as u64;
        let code = unit.uleb();
        if code == 0 {
            depth -= 1;
            continue;
        }
        let (tag, children, attrs) = abbrevs.get(&code).expect("a known abbreviation");
        let mut values = HashMap::new();
        for (at, form) in attrs {
            let value = match form {
                0x01 => Value::Addr(unit.fixed(unit_address_size as usize)),
                0x0b => Value::Unsigned(u64::from(unit.u8())),
                0x0d => Value::Signed(unit.sleb()),
                0x0e => Value::Str(string_at(unit.fixed(4))),
                0x0f => Value::Unsigned(unit.uleb()),
                0x13 => Value::Ref(unit.fixed(4)),
                0x18 => {
                    let len = unit.uleb() as usize;
                    Value::Block(unit.take(len).to_vec())
                }
                0x19 => Value::Flag,
                other => panic!("form {other:#x} is not one the writer uses"),
            };
            values.insert(*at, value);
        }
        let parent = if depth == 0 {
            None
        } else {
            Some(ancestors[depth - 1])
        };
        let die = Die {
            tag: *tag,
            offset,
            parent,
            attrs: values,
        };
        ancestors.truncate(depth);
        ancestors.push(offset);
        by_offset.insert(offset, die.clone());
        dies.push(die);
        if *children {
            depth += 1;
        }
    }
    assert_eq!(depth, 0, "every child list is closed");

    // The symbol table: the functions and the data, global and absolute.
    let mut symbols = Vec::new();
    if let Some(symtab) = section(".symtab") {
        let strtab = sections[symtab.4];
        let strtab_bytes = &bytes[strtab.2..strtab.2 + strtab.3];
        let symbol_name = |offset: u32| -> String {
            let start = offset as usize;
            let end = strtab_bytes[start..]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap()
                + start;
            String::from_utf8_lossy(&strtab_bytes[start..end]).into_owned()
        };
        let entsize = symtab.6;
        let count = symtab.3 / entsize;
        for index in symtab.5..count {
            let mut entry = Cursor::new(&bytes[symtab.2 + index * entsize..], le);
            let name = entry.fixed(4) as u32;
            let (value, size, info) = if elf64 {
                let info = entry.u8();
                let _other = entry.u8();
                let _shndx = entry.fixed(2);
                (entry.fixed(8), entry.fixed(8), info)
            } else {
                let value = entry.fixed(4);
                let size = entry.fixed(4);
                let info = entry.u8();
                (value, size, info)
            };
            let kind = info & 0xf;
            if kind == 1 || kind == 2 {
                symbols.push((symbol_name(name), value, size, kind == 2));
            }
        }
    }

    Read {
        elf64,
        little_endian: le,
        machine,
        address_size: unit_address_size,
        dies,
        by_offset,
        symbols,
    }
}

#[test]
fn the_image_is_written_as_dwarf_debug_information() {
    let sample = fixture("sample.elf");
    let file = stem("plain").with_extension("debug");
    let said = ag(&[
        "image",
        sample.to_str().unwrap(),
        "dwarf",
        file.to_str().unwrap(),
    ]);
    assert!(said.starts_with("wrote "), "{said}");
    assert!(said.contains("functions"), "{said}");
    assert!(said.contains("types"), "{said}");

    let bytes = std::fs::read(&file).expect("the file was written");
    assert!(said.contains(&format!("{} bytes", bytes.len())), "{said}");
    let read = read(&bytes);
    assert!(read.elf64);
    assert!(read.little_endian);
    assert_eq!(read.machine, 62, "EM_X86_64");
    assert_eq!(read.address_size, 8);

    // One compile unit, named for the binary, produced by this program.
    let unit = read
        .dies
        .iter()
        .find(|die| die.tag == TAG_UNIT)
        .expect("a unit");
    assert_eq!(unit.name(), Some("sample.elf"));
    assert_eq!(unit.parent, None);

    // main stands where the image puts it, with an extent and a return type.
    let main = read.named(TAG_SUBPROGRAM, "main");
    assert_eq!(main.attrs.get(&AT_LOW_PC), Some(&Value::Addr(0x1198)));
    assert!(main.unsigned(AT_HIGH_PC).expect("an extent") > 0);
    let ret = read.die(main.reference(AT_TYPE).expect("a return type"));
    assert_eq!(ret.tag, TAG_BASE);

    // The platform's int is a four-byte signed base type.
    let int = read.named(TAG_BASE, "int");
    assert_eq!(int.unsigned(AT_BYTE_SIZE), Some(4));
    assert_eq!(int.unsigned(AT_ENCODING), Some(5), "DW_ATE_signed");

    // The symbol table carries main beside the DWARF.
    assert!(read
        .symbols
        .iter()
        .any(|(name, address, size, function)| name == "main"
            && *address == 0x1198
            && *size > 0
            && *function));

    let _ = std::fs::remove_file(&file);
}

#[test]
fn the_projects_names_types_and_prototypes_are_written() {
    let sample = fixture("sample.elf");
    let stem = stem("project");
    let project = stem.with_extension("agproj");
    let file = stem.with_extension("debug");
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
        "project",
        target,
        "mark",
        "--file",
        path,
        "0x4010",
        "data:4[8]",
    ]);
    ag(&[
        "project", target, "rename", "--file", path, "0x4010", "g_counts",
    ]);

    ag(&[
        "image",
        target,
        "dwarf",
        file.to_str().unwrap(),
        "--project",
        path,
    ]);
    let read = read(&std::fs::read(&file).expect("the file was written"));

    // The rename and the prototype: the function under the analyst's name,
    // with the parameters the prototype names.
    let entry = read.named(TAG_SUBPROGRAM, "entry_point");
    assert_eq!(entry.attrs.get(&AT_LOW_PC), Some(&Value::Addr(0x1198)));
    let params = read.children(entry.offset);
    assert_eq!(params.len(), 2);
    assert_eq!(params[0].tag, TAG_FORMAL);
    assert_eq!(params[0].name(), Some("argc"));
    assert_eq!(params[1].name(), Some("argv"));
    let argv_ty = read.die(params[1].reference(AT_TYPE).expect("argv's type"));
    assert_eq!(argv_ty.tag, TAG_POINTER);

    // The structure: its size and its members at their offsets.
    let point = read.named(TAG_STRUCT, "point");
    assert_eq!(point.unsigned(AT_BYTE_SIZE), Some(8));
    let members = read.children(point.offset);
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].tag, TAG_MEMBER);
    assert_eq!(members[0].name(), Some("x"));
    assert_eq!(members[0].unsigned(AT_MEMBER_LOCATION), Some(0));
    assert_eq!(members[1].name(), Some("y"));
    assert_eq!(members[1].unsigned(AT_MEMBER_LOCATION), Some(4));

    // The enumeration: its enumerators and their values.
    let color = read.named(TAG_ENUM, "color");
    let enumerators = read.children(color.offset);
    assert_eq!(enumerators.len(), 3);
    assert_eq!(enumerators[0].tag, TAG_ENUMERATOR);
    assert_eq!(enumerators[0].name(), Some("RED"));
    assert_eq!(
        enumerators[0].attrs.get(&AT_CONST_VALUE),
        Some(&Value::Signed(0))
    );
    assert_eq!(
        enumerators[1].attrs.get(&AT_CONST_VALUE),
        Some(&Value::Signed(5))
    );
    assert_eq!(
        enumerators[2].attrs.get(&AT_CONST_VALUE),
        Some(&Value::Signed(6))
    );

    // The typedef names the structure.
    let typedef = read.named(TAG_TYPEDEF, "point_t");
    let target_die = read.die(typedef.reference(AT_TYPE).expect("the alias"));
    assert_eq!(target_die.tag, TAG_STRUCT);
    assert_eq!(target_die.name(), Some("point"));

    // The data mark: the datum under the analyst's name, at its address,
    // an array of eight four-byte numbers.
    let counts = read.named(TAG_VARIABLE, "g_counts");
    let location = match counts.attrs.get(&AT_LOCATION) {
        Some(Value::Block(block)) => block.clone(),
        other => panic!("a location, not {other:?}"),
    };
    assert_eq!(location[0], 0x03, "DW_OP_addr");
    assert_eq!(
        u64::from_le_bytes(location[1..9].try_into().unwrap()),
        0x4010
    );
    let array = read.die(counts.reference(AT_TYPE).expect("the datum's type"));
    assert_eq!(array.tag, TAG_ARRAY);
    let subrange = read
        .children(array.offset)
        .into_iter()
        .find(|die| die.tag == TAG_SUBRANGE)
        .expect("a subrange");
    assert_eq!(subrange.unsigned(AT_COUNT), Some(8));
    let element = read.die(array.reference(AT_TYPE).expect("the element type"));
    assert_eq!(element.tag, TAG_BASE);
    assert_eq!(element.unsigned(AT_BYTE_SIZE), Some(4));
    assert_eq!(element.unsigned(AT_ENCODING), Some(7), "DW_ATE_unsigned");

    let _ = std::fs::remove_file(&project);
    let _ = std::fs::remove_file(&file);
}

#[test]
fn a_bit_field_keeps_its_width_and_place() {
    let sample = fixture("sample.elf");
    let stem = stem("bits");
    let project = stem.with_extension("agproj");
    let file = stem.with_extension("debug");
    let _ = std::fs::remove_file(&project);
    let target = sample.to_str().unwrap();
    let path = project.to_str().unwrap();
    ag(&[
        "project",
        target,
        "types",
        "--file",
        path,
        "add",
        "struct flags { unsigned a : 3; unsigned b : 5; unsigned : 0; unsigned c : 4; };",
    ]);
    ag(&[
        "image",
        target,
        "dwarf",
        file.to_str().unwrap(),
        "--project",
        path,
    ]);
    let read = read(&std::fs::read(&file).expect("the file was written"));

    let flags = read.named(TAG_STRUCT, "flags");
    let bits = read.children(flags.offset);
    assert_eq!(bits.len(), 3);
    assert_eq!(bits[0].name(), Some("a"));
    assert_eq!(bits[0].unsigned(AT_BIT_SIZE), Some(3));
    assert_eq!(bits[0].unsigned(AT_BIT_OFFSET), Some(0));
    assert_eq!(bits[1].name(), Some("b"));
    assert_eq!(bits[1].unsigned(AT_BIT_SIZE), Some(5));
    assert_eq!(bits[1].unsigned(AT_BIT_OFFSET), Some(3));
    // The zero-width field moved c to the next unit.
    assert_eq!(bits[2].name(), Some("c"));
    assert_eq!(bits[2].unsigned(AT_BIT_OFFSET), Some(32));

    let _ = std::fs::remove_file(&project);
    let _ = std::fs::remove_file(&file);
}

#[test]
fn a_thirty_two_bit_image_writes_a_thirty_two_bit_file() {
    let sample = fixture("boundaries32.elf");
    let file = stem("bits32").with_extension("debug");
    ag(&[
        "image",
        sample.to_str().unwrap(),
        "dwarf",
        file.to_str().unwrap(),
    ]);
    let read = read(&std::fs::read(&file).expect("the file was written"));
    assert!(!read.elf64, "ELF32");
    assert_eq!(read.machine, 3, "EM_386");
    assert_eq!(read.address_size, 4);
    let unit = read
        .dies
        .iter()
        .find(|die| die.tag == TAG_UNIT)
        .expect("a unit");
    assert_eq!(unit.name(), Some("boundaries32.elf"));
    let _ = std::fs::remove_file(&file);
}
