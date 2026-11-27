//! Importing DWARF debug information (#401).
//!
//! DWARF is what a compiler leaves behind about a program: the names of
//! its functions and data, their types and prototypes, the source lines
//! they came from, and the locals that stand in each function's frame.
//! [`read`] reads it from an ELF, Mach-O or PE image — the debug sections
//! embedded in it, or a file holding them alone (`objcopy
//! --only-keep-debug`, a dSYM) — into a [`DebugInfo`], the same shape the
//! other debug info parsers answer with ([`crate::debuginfo`]): the
//! functions with their prototypes and source, the data with their types,
//! the C definitions, and the locals at their offsets from the entry
//! stack pointer, as the lift's `local_<hex>` names count them.
//!
//! [`locate`] finds the DWARF of an image wherever it lives, in the order
//! a debugger looks:
//!
//! 1. the image itself, when its debug sections are still in it;
//! 2. the file its `.gnu_debuglink` section names — beside the image, in
//!    a `.debug` directory beside it, or under a global debug directory
//!    (`/usr/lib/debug`) at the image's own path — its CRC checked;
//! 3. a sibling file: `<image>.debug`, `<image>.debuginfo`,
//!    `<image>.dwarf`, or the same with the image's extension replaced;
//! 4. a dSYM bundle beside the image: `<image>.dSYM/Contents/Resources/
//!    DWARF/<image>`;
//! 5. the image's build ID (`.note.gnu.build-id`): a build-ID directory
//!    (`/usr/lib/debug/.build-id/xx/yyyy.debug`), the debuginfod client
//!    cache, or a debuginfod server named in `DEBUGINFOD_URLS`.
//!
//! What the DWARF does not say is left out rather than guessed at: a
//! function with no code address is a declaration and imports nothing, a
//! local whose location is a register or an expression this reader does
//! not evaluate is held back with a note, and a structure whose layout
//! the C parser would not reproduce is imported with a note saying so.
//! The frame base is read as the call-frame CFA, which is what compilers
//! emit; a function whose frame base is something else keeps its name and
//! prototype but not its locals. The CFA stands above the entry stack
//! pointer by the return address the call pushed — eight bytes on
//! x86-64, four on i386, nothing where a link register returns — so a
//! local's offset from the entry stack pointer is its offset from the
//! CFA plus that.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use gimli::{
    constants, AttributeValue, DebuggingInformationEntry, Dwarf, DwarfSections, EndianSlice,
    Expression, LineProgramHeader, Operation, RunTimeEndian, SectionId, Unit,
};

use object::{Object, ObjectSection};

use crate::debuginfo::{DebugData, DebugFunction, DebugInfo, DebugLocal};
use crate::plugin::DebugInfoParser;

/// The reader's slice: the file's bytes, in the file's byte order.
type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

// ---------------------------------------------------------------------
// The built-in parser.

/// The built-in `dwarf` parser: the DWARF debug information of an image.
pub struct DwarfParser;

impl DebugInfoParser for DwarfParser {
    fn name(&self) -> &str {
        "dwarf"
    }

    fn description(&self) -> &str {
        "DWARF debug information in an ELF, Mach-O or PE image: names, types, prototypes and locals."
    }

    fn recognizes(&self, bytes: &[u8]) -> bool {
        has_dwarf(bytes)
    }

    fn parse(&self, name: &str, bytes: &[u8]) -> Result<DebugInfo, String> {
        read(name, bytes)
    }
}

/// Whether the bytes are an image with DWARF debug sections in it.
pub fn has_dwarf(bytes: &[u8]) -> bool {
    parse_object(bytes).is_some_and(|file| {
        file.sections().any(|section| {
            section
                .name()
                .is_ok_and(|name| debug_section_name(name) == Some(".debug_info"))
                && section.data().is_ok_and(|data| !data.is_empty())
        })
    })
}

/// Parse a thin object file, or the first slice of a universal Mach-O that
/// carries `.debug_info` (or its first readable slice otherwise).
fn parse_object(bytes: &[u8]) -> Option<object::File<'_>> {
    if let Ok(file) = object::File::parse(bytes) {
        return Some(file);
    }
    let slices = crate::image::fat_slices(bytes)?;
    let mut fallback = None;
    for slice in slices {
        let start = usize::try_from(slice.offset).ok()?;
        let end = start.checked_add(usize::try_from(slice.size).ok()?)?;
        let Some(slice_bytes) = bytes.get(start..end) else {
            continue;
        };
        if let Ok(file) = object::File::parse(slice_bytes) {
            if file.sections().any(|section| {
                section
                    .name()
                    .is_ok_and(|name| debug_section_name(name) == Some(".debug_info"))
                    && section.data().is_ok_and(|data| !data.is_empty())
            }) {
                return Some(file);
            }
            if fallback.is_none() {
                fallback = Some(file);
            }
        }
    }
    fallback
}

/// A section's name as the standard DWARF section it is, when it is one:
/// a Mach-O's `__debug_info` is the `.debug_info` an ELF spells.
fn debug_section_name(name: &str) -> Option<&'static str> {
    let plain = name.strip_prefix("__").unwrap_or(name);
    let plain = plain.strip_prefix('.').unwrap_or(plain);
    Some(match plain {
        "debug_info" => ".debug_info",
        "debug_abbrev" => ".debug_abbrev",
        "debug_str" => ".debug_str",
        "debug_line" => ".debug_line",
        "debug_line_str" => ".debug_line_str",
        "debug_addr" => ".debug_addr",
        "debug_str_offsets" => ".debug_str_offsets",
        "debug_loc" => ".debug_loc",
        "debug_loclists" => ".debug_loclists",
        "debug_ranges" => ".debug_ranges",
        "debug_rnglists" => ".debug_rnglists",
        "debug_aranges" => ".debug_aranges",
        "debug_frame" => ".debug_frame",
        "debug_types" => ".debug_types",
        "debug_macro" => ".debug_macro",
        "debug_macinfo" => ".debug_macinfo",
        "debug_names" => ".debug_names",
        "debug_pubnames" => ".debug_pubnames",
        "debug_pubtypes" => ".debug_pubtypes",
        _ => return None,
    })
}

// ---------------------------------------------------------------------
// Reading the DWARF.

/// Read the DWARF debug information of an image into the functions, data,
/// locals and C types it names. `name` names the file in the errors and
/// notes.
pub fn read(name: &str, bytes: &[u8]) -> Result<DebugInfo, String> {
    let file = match parse_object(bytes) {
        Some(file) => file,
        None => {
            let error = object::File::parse(bytes)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no readable slice in universal Mach-O".to_string());
            return Err(format!("{name}: not an ELF, Mach-O or PE image: {error}"));
        }
    };
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    // The debug sections, by their standard names.
    let mut sections: HashMap<&str, &[u8]> = HashMap::new();
    let mut compressed = false;
    for section in file.sections() {
        let Ok(section_name) = section.name() else {
            continue;
        };
        if section_name.starts_with(".zdebug") || section_name.starts_with("__zdebug") {
            compressed = true;
            continue;
        }
        if let Some(key) = debug_section_name(section_name) {
            if let Ok(data) = section.data() {
                sections.insert(key, data);
            }
        }
    }
    if !sections.contains_key(".debug_info") {
        return Err(if compressed {
            format!("{name}: the DWARF sections are compressed; this reader reads them uncompressed")
        } else {
            format!("{name}: no .debug_info section")
        });
    }
    let loaded = DwarfSections::load(|id: SectionId| -> Result<&[u8], gimli::Error> {
        Ok(sections.get(id.name()).copied().unwrap_or(&[]))
    })
    .map_err(|error| format!("{name}: {error}"))?;
    let dwarf = loaded.borrow(|data| EndianSlice::new(data, endian));
    let little_endian = matches!(endian, RunTimeEndian::Little);

    // The return address the call pushed on the stack: the CFA stands
    // above it, so a local's offset from the entry stack pointer is its
    // offset from the CFA less this. Architectures that return through a
    // link register push nothing.
    let cfa_adjust = match file.architecture() {
        object::Architecture::X86_64 => 8,
        object::Architecture::X86_64_X32 | object::Architecture::I386 => 4,
        _ => 0,
    };

    let mut info = DebugInfo::default();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().map_err(|e| format!("{name}: {e}"))? {
        let unit = dwarf.unit(header).map_err(|e| format!("{name}: {e}"))?;
        let mut reader = UnitReader::new(&dwarf, &unit, cfa_adjust, little_endian, name);
        reader.read_unit(&mut info);
    }
    dedup(name, &mut info);
    Ok(info)
}

/// Hold back the second function or datum at one address, and the second
/// local at one offset of one function, with a note — as the map parser
/// holds back its symbols.
fn dedup(name: &str, info: &mut DebugInfo) {
    let mut seen: BTreeMap<u64, String> = BTreeMap::new();
    let mut functions = Vec::new();
    for function in info.functions.drain(..) {
        match seen.get(&function.address) {
            Some(first) => info.notes.push(format!(
                "{name}: {:#x}: {} held back: {first} is there already",
                function.address, function.name
            )),
            None => {
                seen.insert(function.address, function.name.clone());
                functions.push(function);
            }
        }
    }
    info.functions = functions;
    let mut data = Vec::new();
    for symbol in info.data.drain(..) {
        match seen.get(&symbol.address) {
            Some(first) => info.notes.push(format!(
                "{name}: {:#x}: {} held back: {first} is there already",
                symbol.address, symbol.name
            )),
            None => {
                seen.insert(symbol.address, symbol.name.clone());
                data.push(symbol);
            }
        }
    }
    info.data = data;
    let mut offsets: BTreeMap<(u64, i64), String> = BTreeMap::new();
    let mut locals = Vec::new();
    for local in info.locals.drain(..) {
        match offsets.get(&(local.function, local.offset)) {
            Some(first) => info.notes.push(format!(
                "{name}: {:#x}: local {} held back: {first} is at that offset already",
                local.function, local.name
            )),
            None => {
                offsets.insert((local.function, local.offset), local.name.clone());
                locals.push(local);
            }
        }
    }
    info.locals = locals;
}

/// One DIE of the unit, as the reader keeps it: its tag, its attributes
/// with their forms, and its place in the tree. The whole unit is
/// collected once, so the type renderer can reach any DIE by its offset
/// without walking the tree again.
#[derive(Clone)]
struct Die<'a> {
    offset: usize,
    tag: constants::DwTag,
    attrs: Vec<(constants::DwAt, constants::DwForm, AttributeValue<Slice<'a>>)>,
    children: Vec<usize>,
}

impl<'a> Die<'a> {
    fn attr(&self, at: constants::DwAt) -> Option<&AttributeValue<Slice<'a>>> {
        self.attrs
            .iter()
            .find(|(name, _, _)| *name == at)
            .map(|(_, _, value)| value)
    }

    fn form(&self, at: constants::DwAt) -> Option<constants::DwForm> {
        self.attrs
            .iter()
            .find(|(name, _, _)| *name == at)
            .map(|(_, form, _)| *form)
    }

    /// An attribute as an unsigned number, the data forms and `udata`
    /// alike.
    fn number(&self, at: constants::DwAt) -> Option<u64> {
        self.attr(at).and_then(number_of)
    }

    /// An attribute as a signed number: `sdata` as it stands, the data
    /// forms as the unsigned numbers they are.
    fn signed(&self, at: constants::DwAt) -> Option<i64> {
        match self.attr(at)? {
            AttributeValue::Sdata(value) => Some(*value),
            value => number_of(value).map(|value| value as i64),
        }
    }

    fn flag(&self, at: constants::DwAt) -> bool {
        match self.attr(at) {
            Some(AttributeValue::Flag(set)) => *set,
            Some(value) => number_of(value).is_some_and(|value| value != 0),
            None => false,
        }
    }

    fn reference(&self, at: constants::DwAt) -> Option<usize> {
        match self.attr(at)? {
            AttributeValue::UnitRef(offset) => Some(offset.0),
            _ => None,
        }
    }
}

/// An attribute value as an unsigned number.
fn number_of(value: &AttributeValue<Slice<'_>>) -> Option<u64> {
    match value {
        AttributeValue::Data1(value) => Some(u64::from(*value)),
        AttributeValue::Data2(value) => Some(u64::from(*value)),
        AttributeValue::Data4(value) => Some(u64::from(*value)),
        AttributeValue::Data8(value) => Some(*value),
        AttributeValue::Udata(value) => Some(*value),
        AttributeValue::FileIndex(value) => Some(*value),
        _ => None,
    }
}

/// Where a variable stands: an address in memory, or an offset from the
/// entry stack pointer.
enum Placement {
    Address(u64),
    Stack(i64),
    /// A register — a parameter passed in one, which the prototype
    /// carries; no stack slot to make.
    Register,
}

/// The frame base of a function: the call-frame CFA, or something this
/// reader does not evaluate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameBase {
    Cfa,
    Other,
    None,
}

/// A C type as the reader spells it: the words before a declarator's name
/// and the words after — `int` and nothing, `char` and `[16]`, `int (*`
/// and `)(int)`. Together they are the type as [`crate::ctype::parse_type`]
/// reads it; with a name between them, the declaration C writes.
#[derive(Clone, Default)]
struct Spell {
    before: String,
    after: String,
}

impl Spell {
    fn plain(text: &str) -> Spell {
        Spell {
            before: text.to_string(),
            after: String::new(),
        }
    }

    /// The type expression, with no name: `int`, `char[16]`,
    /// `int (*)(int)`.
    fn expr(&self) -> String {
        format!("{}{}", self.before, self.after)
    }

    /// The declaration of `name` of this type, as C writes it.
    fn declare(&self, name: &str) -> String {
        crate::ctype::declarator(&self.expr(), name)
    }
}

/// One member of a structure or union, as the DWARF places it.
struct Member {
    name: Option<String>,
    ty: usize,
    /// The byte offset, when the member is no bit-field.
    offset: Option<u64>,
    /// The bit-field's first bit from the structure's start (counted as
    /// the engine counts them, from the low end on a little-endian
    /// target) and its width.
    bits: Option<(u64, u32)>,
    size: u64,
    align: u64,
    /// A base class, rendered in the header rather than the body.
    base: bool,
}

/// The reader of one compile unit.
struct UnitReader<'a> {
    dwarf: &'a Dwarf<Slice<'a>>,
    unit: &'a Unit<Slice<'a>>,
    dies: Vec<Die<'a>>,
    by_offset: HashMap<usize, usize>,
    line: Option<LineProgramHeader<Slice<'a>>>,
    cfa_adjust: u64,
    little_endian: bool,
    name: &'a str,
    /// The spelling of each type already rendered.
    spells: HashMap<usize, Spell>,
    /// The size and alignment of each type already measured.
    sizes: HashMap<usize, Option<(u64, u64)>>,
    /// The definitions already written, and the ones being written.
    emitted: HashSet<usize>,
    writing: HashSet<usize>,
    /// Whether a type reaches itself through its members.
    cyclic: HashMap<usize, bool>,
    /// The C definitions, in the order they were written.
    types: Vec<String>,
    notes: Vec<String>,
}

impl<'a> UnitReader<'a> {
    fn new(
        dwarf: &'a Dwarf<Slice<'a>>,
        unit: &'a Unit<Slice<'a>>,
        cfa_adjust: u64,
        little_endian: bool,
        name: &'a str,
    ) -> UnitReader<'a> {
        // Collect the unit's DIEs into the arena, the compile unit first.
        let mut dies: Vec<Die<'a>> = Vec::new();
        let mut by_offset = HashMap::new();
        if let Ok(mut tree) = unit.entries_tree(None) {
            if let Ok(root) = tree.root() {
                collect_die(root, &mut dies, &mut by_offset, 0);
            }
        }
        // The line program, for the source files and lines.
        let line = dies.first().and_then(|cu| {
            let offset = match cu.attr(constants::DW_AT_stmt_list)? {
                AttributeValue::DebugLineRef(offset) => offset.0 as u64,
                AttributeValue::SecOffset(offset) => *offset as u64,
                value => number_of(value)?,
            };
            let comp_dir = cu
                .attr(constants::DW_AT_comp_dir)
                .and_then(|value| dwarf.attr_string(unit, *value).ok());
            let comp_name = cu
                .attr(constants::DW_AT_name)
                .and_then(|value| dwarf.attr_string(unit, *value).ok());
            dwarf
                .debug_line
                .program(
                    gimli::DebugLineOffset(offset as usize),
                    unit.encoding().address_size,
                    comp_dir,
                    comp_name,
                )
                .ok()
                .map(|program| program.header().clone())
        });
        UnitReader {
            dwarf,
            unit,
            dies,
            by_offset,
            line,
            cfa_adjust,
            little_endian,
            name,
            spells: HashMap::new(),
            sizes: HashMap::new(),
            emitted: HashSet::new(),
            writing: HashSet::new(),
            cyclic: HashMap::new(),
            types: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn note(&mut self, text: String) {
        self.notes.push(format!("{}: {text}", self.name));
    }

    /// The index of the DIE at a unit offset, when the unit holds it.
    fn at(&self, offset: usize) -> Option<usize> {
        self.by_offset.get(&offset).copied()
    }

    /// An attribute as an address: `DW_FORM_addr` as it stands,
    /// `DW_FORM_addrx` through the unit's `.debug_addr` base.
    fn address(&self, die: &Die<'a>, at: constants::DwAt) -> Option<u64> {
        match die.attr(at)? {
            AttributeValue::Addr(address) => Some(*address),
            AttributeValue::DebugAddrIndex(index) => self.dwarf.address(self.unit, *index).ok(),
            _ => None,
        }
    }

    /// An attribute as a string, through `.debug_str`,
    /// `.debug_str_offsets` or `.debug_line_str` as its form says.
    fn string(&self, die: &Die<'a>, at: constants::DwAt) -> Option<String> {
        let value = die.attr(at)?;
        let text = self.dwarf.attr_string(self.unit, *value).ok()?;
        Some(text.to_string_lossy().into_owned())
    }

    /// The DIE a `DW_AT_abstract_origin` or `DW_AT_specification` names,
    /// following the chain a few steps.
    fn origin(&self, mut index: usize) -> Option<usize> {
        let mut walked = false;
        for _ in 0..8 {
            let die = &self.dies[index];
            let Some(next) = die
                .reference(constants::DW_AT_abstract_origin)
                .or_else(|| die.reference(constants::DW_AT_specification))
            else {
                return walked.then_some(index);
            };
            index = self.at(next)?;
            walked = true;
        }
        Some(index)
    }

    /// The type a DIE's `DW_AT_type` names, or its origin's.
    fn type_of(&self, index: usize) -> Option<usize> {
        let die = &self.dies[index];
        if let Some(offset) = die.reference(constants::DW_AT_type) {
            return self.at(offset);
        }
        let origin = self.origin(index)?;
        let offset = self.dies[origin].reference(constants::DW_AT_type)?;
        self.at(offset)
    }

    // ---- The unit's functions, data and locals. ----

    fn read_unit(&mut self, info: &mut DebugInfo) {
        let Some(root) = self.dies.first().map(|die| die.children.clone()) else {
            return;
        };
        // The unit's own named types first, in the order the source
        // declares them — the program's structures, enumerations and
        // typedefs, whether its code uses them or not.
        self.collect_named_types(&root);
        self.collect_unit_items(&root, info);
        info.types.append(&mut self.types);
        info.notes.append(&mut self.notes);
    }

    fn collect_named_types(&mut self, children: &[usize]) {
        for &index in children {
            let tag = self.dies[index].tag;
            let has_name = self.dies[index].attr(constants::DW_AT_name).is_some();
            if matches!(
                tag,
                constants::DW_TAG_structure_type
                    | constants::DW_TAG_union_type
                    | constants::DW_TAG_class_type
                    | constants::DW_TAG_enumeration_type
                    | constants::DW_TAG_typedef
            ) && has_name
            {
                self.spell(index);
            }
            if matches!(tag, constants::DW_TAG_namespace | constants::DW_TAG_module) {
                let nested = self.dies[index].children.clone();
                self.collect_named_types(&nested);
            }
        }
    }

    fn collect_unit_items(&mut self, children: &[usize], info: &mut DebugInfo) {
        for &index in children {
            let tag = self.dies[index].tag;
            match tag {
                constants::DW_TAG_subprogram => self.subprogram(index, info),
                constants::DW_TAG_variable => self.global(index, info),
                constants::DW_TAG_namespace
                | constants::DW_TAG_module
                | constants::DW_TAG_structure_type
                | constants::DW_TAG_class_type
                | constants::DW_TAG_union_type => {
                    let nested = self.dies[index].children.clone();
                    self.collect_unit_items(&nested, info);
                }
                _ => {}
            }
        }
    }

    /// The name of a function or datum: its own `DW_AT_name`, its
    /// origin's, or its linkage name demangled.
    fn die_name(&self, index: usize) -> Option<String> {
        let die = &self.dies[index];
        if let Some(name) = self.string(die, constants::DW_AT_name) {
            return Some(name);
        }
        if let Some(origin) = self.origin(index) {
            if let Some(name) = self.string(&self.dies[origin], constants::DW_AT_name) {
                return Some(name);
            }
        }
        let linkage = self
            .string(die, constants::DW_AT_linkage_name)
            .or_else(|| {
                self.origin(index)
                    .and_then(|origin| self.string(&self.dies[origin], constants::DW_AT_linkage_name))
            })?;
        Some(crate::demangle::demangle(&linkage).unwrap_or(linkage))
    }

    /// The source place of a DIE: `file.c:42`, from its declaration file
    /// and line through the unit's line program.
    fn source_of(&self, die: &Die<'a>) -> Option<String> {
        let file = die.number(constants::DW_AT_decl_file)?;
        let line = die.number(constants::DW_AT_decl_line)?;
        let header = self.line.as_ref()?;
        // DWARF 5 counts the file table from zero; before it, from one.
        let index = if header.version() <= 4 {
            file.checked_sub(1)?
        } else {
            file
        };
        let entry = header.file(index)?;
        let name = self
            .dwarf
            .attr_string(self.unit, entry.path_name())
            .ok()?;
        let name = name.to_string_lossy();
        let name = name.rsplit('/').next().unwrap_or(&name);
        Some(format!("{name}:{line}"))
    }

    /// How many bytes a function spans: its `DW_AT_high_pc` — an address
    /// before DWARF 4, a length from it on — or the span of its ranges.
    fn extent_of(&self, die: &Die<'a>, low: u64) -> Option<u64> {
        if let Some(high) = die.attr(constants::DW_AT_high_pc) {
            return match die.form(constants::DW_AT_high_pc) {
                Some(constants::DW_FORM_addr) => match high {
                    AttributeValue::Addr(high) => high.checked_sub(low),
                    _ => None,
                },
                _ => number_of(high),
            };
        }
        let ranges = *die.attr(constants::DW_AT_ranges)?;
        let mut iter = self.dwarf.attr_ranges(self.unit, ranges).ok()??;
        let mut end = low;
        while let Some(range) = iter.next().ok()? {
            end = end.max(range.end);
        }
        end.checked_sub(low)
    }

    fn subprogram(&mut self, index: usize, info: &mut DebugInfo) {
        let die = &self.dies[index];
        let low = self.address(die, constants::DW_AT_low_pc).or_else(|| {
            let ranges = *die.attr(constants::DW_AT_ranges)?;
            let mut iter = self.dwarf.attr_ranges(self.unit, ranges).ok()??;
            let mut min_begin: Option<u64> = None;
            while let Some(range) = iter.next().ok()? {
                if range.begin < range.end {
                    min_begin = Some(min_begin.map_or(range.begin, |m| m.min(range.begin)));
                }
            }
            min_begin
        });
        let Some(low) = low else {
            // A declaration, or an abstract instance: no code of its own.
            return;
        };
        let name = self
            .die_name(index)
            .unwrap_or_else(|| format!("sub_{low:x}"));
        let size = self.extent_of(die, low);
        let source = self.source_of(die);

        // The parameters: the DIE's own children, or its origin's when a
        // concrete instance points at an abstract one for them.
        let params_from = if die.children.iter().any(|child| {
            self.dies[*child].tag == constants::DW_TAG_formal_parameter
        }) {
            index
        } else {
            self.origin(index).unwrap_or(index)
        };
        let mut params: Vec<(Option<usize>, Option<String>)> = Vec::new();
        let mut variadic = false;
        for child in self.dies[params_from].children.clone() {
            match self.dies[child].tag {
                constants::DW_TAG_formal_parameter => {
                    let ty = self.type_of(child);
                    let name = self.string(&self.dies[child], constants::DW_AT_name);
                    params.push((ty, name));
                }
                constants::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }
        let prototyped = die.flag(constants::DW_AT_prototyped)
            || self
                .origin(index)
                .is_some_and(|origin| self.dies[origin].flag(constants::DW_AT_prototyped));

        // The prototype, when the function is prototyped and its name is
        // one C can spell.
        let mut prototype = None;
        if (prototyped || !params.is_empty()) && is_identifier(&name) {
            let ret = self
                .type_of(index)
                .map(|ty| self.spell(ty))
                .unwrap_or_else(|| Spell::plain("void"));
            let mut words: Vec<String> = Vec::new();
            let mut complete = true;
            for (ty, param_name) in &params {
                match ty {
                    Some(ty) => {
                        let spell = self.spell(*ty);
                        words.push(spell.declare(param_name.as_deref().unwrap_or("")));
                    }
                    None => complete = false,
                }
            }
            if variadic {
                words.push("...".to_string());
            }
            if words.is_empty() && !variadic {
                words.push("void".to_string());
            }
            if complete {
                prototype = Some(format!("{}({})", ret.declare(&name), words.join(", ")));
            }
        }

        info.functions.push(DebugFunction {
            address: low,
            name: name.clone(),
            size,
            prototype,
            source,
        });

        // The frame base, and the locals under the function — its
        // parameters spilled to the frame, its variables, and the ones
        // of its lexical blocks and inlined subroutines.
        let frame_base = self.frame_base_of(index);
        let children = self.dies[index].children.clone();
        self.locals_under(&children, low, frame_base, info);
    }

    /// The frame base of a function: the call-frame CFA when its
    /// `DW_AT_frame_base` says so, and nothing otherwise.
    fn frame_base_of(&self, index: usize) -> FrameBase {
        let Some(value) = self.dies[index].attr(constants::DW_AT_frame_base) else {
            return FrameBase::None;
        };
        let AttributeValue::Exprloc(expression) = value else {
            return FrameBase::Other;
        };
        let mut ops = (*expression).operations(self.unit.encoding());
        match ops.next() {
            Ok(Some(Operation::CallFrameCFA)) => FrameBase::Cfa,
            _ => FrameBase::Other,
        }
    }

    /// The locals under a function's children, at any depth of lexical
    /// block or inlined subroutine.
    fn locals_under(
        &mut self,
        children: &[usize],
        function: u64,
        frame_base: FrameBase,
        info: &mut DebugInfo,
    ) {
        for &index in children {
            let die = &self.dies[index];
            match die.tag {
                constants::DW_TAG_lexical_block | constants::DW_TAG_inlined_subroutine => {
                    let nested = die.children.clone();
                    self.locals_under(&nested, function, frame_base, info);
                }
                constants::DW_TAG_variable | constants::DW_TAG_formal_parameter => {
                    self.local(index, function, frame_base, info);
                }
                _ => {}
            }
        }
    }

    /// One local: a variable or parameter of the function at `function`.
    /// A stack slot becomes a local of the frame; an address, a datum
    /// (a function's static variable stands in memory); a register,
    /// nothing — the prototype carries the parameter.
    fn local(
        &mut self,
        index: usize,
        function: u64,
        frame_base: FrameBase,
        info: &mut DebugInfo,
    ) {
        let Some(name) = self.die_name(index) else {
            // An artificial variable, with no name of its own.
            return;
        };
        let Some(ty) = self.type_of(index) else {
            return;
        };
        let Some(placement) = self.location_of(index, function, frame_base) else {
            return;
        };
        let spell = self.spell(ty);
        let size = self.size_align(ty).map(|(size, _)| size);
        match placement {
            Placement::Register => {}
            Placement::Address(address) => {
                info.data.push(DebugData {
                    address,
                    name,
                    size,
                    ctype: Some(spell.expr()),
                });
            }
            Placement::Stack(offset) => {
                let Some(size) = size.filter(|size| *size > 0 && *size <= u64::from(u32::MAX))
                else {
                    self.note(format!(
                        "{:#x}: local {name} held back: its type has no size",
                        function
                    ));
                    return;
                };
                info.locals.push(DebugLocal {
                    function,
                    name,
                    offset,
                    size: size as u32,
                    ctype: Some(spell.expr()),
                });
            }
        }
    }

    /// Where a DIE's `DW_AT_location` places it: a single expression, or
    /// the first entry of its location list that covers the function's
    /// entry (or the first entry at all).
    fn location_of(
        &mut self,
        index: usize,
        function: u64,
        frame_base: FrameBase,
    ) -> Option<Placement> {
        let die = &self.dies[index];
        let value = *die.attr(constants::DW_AT_location)?;
        let expression = match value {
            AttributeValue::Exprloc(expression) => Some(expression),
            other => {
                let mut iter = self.dwarf.attr_locations(self.unit, other).ok()??;
                let mut first: Option<Expression<Slice<'a>>> = None;
                let mut chosen = None;
                while let Some(entry) = iter.next().ok()? {
                    if first.is_none() {
                        first = Some(entry.data);
                    }
                    if entry.range.begin <= function && function < entry.range.end {
                        chosen = Some(entry.data);
                        break;
                    }
                }
                chosen.or(first)
            }
        }?;
        self.evaluate(expression, function, frame_base)
    }

    /// Evaluate a location expression: an address, a frame offset, or a
    /// register. Anything else — pieces, stack values, dereferences — is
    /// held back with a note.
    fn evaluate(
        &mut self,
        expression: Expression<Slice<'a>>,
        function: u64,
        frame_base: FrameBase,
    ) -> Option<Placement> {
        let mut ops = expression.operations(self.unit.encoding());
        let first = ops.next().ok()??;
        // A trailing nop changes nothing; anything else after the first
        // operation is an expression this reader does not evaluate.
        for rest in ops {
            match rest {
                Ok(Operation::Nop) => {}
                _ => {
                    self.note(format!(
                        "{function:#x}: a location expression is held back: it is more than one operation"
                    ));
                    return None;
                }
            }
        }
        match first {
            Operation::Address { address } => Some(Placement::Address(address)),
            Operation::AddressIndex { index } => self
                .dwarf
                .address(self.unit, index)
                .ok()
                .map(Placement::Address),
            Operation::FrameOffset { offset } => match frame_base {
                FrameBase::Cfa => Some(Placement::Stack(offset + self.cfa_adjust as i64)),
                FrameBase::Other => {
                    self.note(format!(
                        "{function:#x}: locals held back: the frame base is not the call-frame CFA"
                    ));
                    None
                }
                FrameBase::None => None,
            },
            Operation::Register { .. } | Operation::RegisterOffset { .. } => {
                Some(Placement::Register)
            }
            _ => {
                self.note(format!(
                    "{function:#x}: a location is held back: it is no address, frame offset or register"
                ));
                None
            }
        }
    }

    /// A unit-level variable: a datum at its address, under its type.
    fn global(&mut self, index: usize, info: &mut DebugInfo) {
        let Some(placement) = self.location_of(index, 0, FrameBase::None) else {
            return;
        };
        let Placement::Address(address) = placement else {
            return;
        };
        let Some(name) = self.die_name(index) else {
            return;
        };
        let ty = self.type_of(index);
        let ctype = ty.map(|ty| self.spell(ty).expr());
        let size = ty.and_then(|ty| self.size_align(ty)).map(|(size, _)| size);
        info.data.push(DebugData {
            address,
            name,
            size,
            ctype,
        });
    }

    // ---- The types, as C. ----

    /// The spelling of the type at `index`, written once; the definitions
    /// it needs are written as it is spelled.
    fn spell(&mut self, index: usize) -> Spell {
        if let Some(spell) = self.spells.get(&index) {
            return spell.clone();
        }
        let die = self.dies[index].clone();
        let spell = match die.tag {
            constants::DW_TAG_base_type => Spell::plain(&self.base_name(index)),
            constants::DW_TAG_pointer_type
            | constants::DW_TAG_reference_type
            | constants::DW_TAG_rvalue_reference_type
            | constants::DW_TAG_ptr_to_member_type => {
                if die.tag != constants::DW_TAG_pointer_type {
                    self.note(format!(
                        "a C++ reference or member pointer at {:#x} is read as a pointer",
                        die.offset
                    ));
                }
                match die.reference(constants::DW_AT_type).and_then(|o| self.at(o)) {
                    None => Spell::plain("void *"),
                    Some(inner) => {
                        let inner = self.spell(inner);
                        if inner.after.is_empty() {
                            let sep = if inner.before.ends_with('*') { "" } else { " " };
                            Spell {
                                before: format!("{}{sep}*", inner.before),
                                after: String::new(),
                            }
                        } else {
                            // A pointer to an array or a function: the
                            // declarator wraps in parentheses.
                            Spell {
                                before: format!("{}(*", inner.before),
                                after: format!("){}", inner.after),
                            }
                        }
                    }
                }
            }
            constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type
            | constants::DW_TAG_immutable_type => {
                // The engine's types keep no qualifiers.
                match die.reference(constants::DW_AT_type).and_then(|o| self.at(o)) {
                    Some(inner) => self.spell(inner),
                    None => Spell::plain("void"),
                }
            }
            constants::DW_TAG_typedef => {
                let name = self
                    .string(&die, constants::DW_AT_name)
                    .unwrap_or_else(|| format!("ag_typedef_{:x}", die.offset));
                if !self.emitted.contains(&index) {
                    self.emitted.insert(index);
                    let inner = die
                        .reference(constants::DW_AT_type)
                        .and_then(|o| self.at(o))
                        .map(|inner| self.spell(inner))
                        .unwrap_or_else(|| Spell::plain("int"));
                    self.types
                        .push(format!("typedef {};", inner.declare(&name)));
                }
                Spell::plain(&name)
            }
            constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_class_type => self.composite_spell(index),
            constants::DW_TAG_enumeration_type => self.enum_spell(index),
            constants::DW_TAG_array_type => {
                let element = die
                    .reference(constants::DW_AT_type)
                    .and_then(|o| self.at(o))
                    .map(|inner| self.spell(inner))
                    .unwrap_or_else(|| Spell::plain("char"));
                let count = self.array_count(index);
                Spell {
                    before: element.before,
                    after: format!(
                        "{}[{}]",
                        element.after,
                        count.map(|n| n.to_string()).unwrap_or_default()
                    ),
                }
            }
            constants::DW_TAG_subroutine_type => {
                let ret = die
                    .reference(constants::DW_AT_type)
                    .and_then(|o| self.at(o))
                    .map(|inner| self.spell(inner))
                    .unwrap_or_else(|| Spell::plain("void"));
                let mut params = Vec::new();
                let mut variadic = false;
                for child in die.children.clone() {
                    match self.dies[child].tag {
                        constants::DW_TAG_formal_parameter => {
                            let ty = self
                                .dies[child]
                                .reference(constants::DW_AT_type)
                                .and_then(|o| self.at(o))
                                .map(|inner| self.spell(inner))
                                .unwrap_or_else(|| Spell::plain("int"));
                            params.push(ty.expr());
                        }
                        constants::DW_TAG_unspecified_parameters => variadic = true,
                        _ => {}
                    }
                }
                if variadic {
                    params.push("...".to_string());
                }
                if params.is_empty() && !variadic {
                    params.push("void".to_string());
                }
                Spell {
                    before: format!("{} ", ret.before),
                    after: format!("({}){}", params.join(", "), ret.after),
                }
            }
            constants::DW_TAG_unspecified_type => Spell::plain("void"),
            _ => {
                self.note(format!(
                    "the type at {:#x} (tag {:#x}) is read as void",
                    die.offset, die.tag.0
                ));
                Spell::plain("void")
            }
        };
        self.spells.insert(index, spell.clone());
        spell
    }

    /// A base type's C name: the DWARF's own when it gives one, and a
    /// spelling of its encoding and size otherwise.
    fn base_name(&self, index: usize) -> String {
        let die = &self.dies[index];
        if let Some(name) = self.string(die, constants::DW_AT_name) {
            return name;
        }
        let size = die.number(constants::DW_AT_byte_size).unwrap_or(4);
        let encoding = match die.attr(constants::DW_AT_encoding) {
            Some(AttributeValue::Encoding(encoding)) => *encoding,
            _ => constants::DW_ATE_signed,
        };
        match encoding {
            constants::DW_ATE_boolean => "_Bool".to_string(),
            constants::DW_ATE_float => match size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                _ => "long double".to_string(),
            },
            constants::DW_ATE_signed_char => "signed char".to_string(),
            constants::DW_ATE_unsigned_char => "unsigned char".to_string(),
            constants::DW_ATE_signed => match size {
                1 => "signed char".to_string(),
                2 => "short".to_string(),
                8 => "long".to_string(),
                _ => "int".to_string(),
            },
            _ => match size {
                1 => "unsigned char".to_string(),
                2 => "unsigned short".to_string(),
                8 => "unsigned long".to_string(),
                _ => "unsigned int".to_string(),
            },
        }
    }

    /// The count of an array: its subrange's `DW_AT_count`, or its upper
    /// bound (less its lower bound) plus one. `None` for a flexible array.
    fn array_count(&self, index: usize) -> Option<u64> {
        for child in self.dies[index].children.clone() {
            let die = &self.dies[child];
            if die.tag != constants::DW_TAG_subrange_type {
                continue;
            }
            if let Some(count) = die.number(constants::DW_AT_count) {
                return Some(count);
            }
            if let Some(upper) = die.number(constants::DW_AT_upper_bound) {
                let lower = die.number(constants::DW_AT_lower_bound).unwrap_or(0);
                return Some(upper.saturating_sub(lower) + 1);
            }
            return None;
        }
        None
    }

    /// The keyword a composite is spelled with: a class is read as the
    /// structure it lays out as.
    fn composite_keyword(&self, index: usize) -> &'static str {
        if self.dies[index].tag == constants::DW_TAG_union_type {
            "union"
        } else {
            "struct"
        }
    }

    /// The spelling of a structure, union or class: its tag name when it
    /// has one — the definition written beside it — and its body inline
    /// when it is anonymous, unless it reaches itself, which C can only
    /// spell under a name.
    fn composite_spell(&mut self, index: usize) -> Spell {
        let keyword = self.composite_keyword(index);
        let name = self.string(&self.dies[index], constants::DW_AT_name);
        if let Some(name) = name {
            let key = format!("{keyword} {name}");
            self.define_composite(index, &key);
            return Spell::plain(&key);
        }
        if self.is_cyclic(index) {
            let key = format!("{keyword} ag_anon_{:x}", self.dies[index].offset);
            self.note(format!(
                "an anonymous {keyword} at {:#x} reaches itself; it is named {key}",
                self.dies[index].offset
            ));
            self.define_composite(index, &key);
            return Spell::plain(&key);
        }
        // Anonymous and acyclic: the body inline, as C writes it in a
        // member or a typedef.
        self.writing.insert(index);
        let (body, packed, header) = self.composite_body(index);
        self.writing.remove(&index);
        let attribute = if packed {
            " __attribute__((packed))"
        } else {
            ""
        };
        Spell::plain(&format!("{keyword}{attribute}{header} {{ {body} }}"))
    }

    /// Write the definition of a named composite once: a forward
    /// declaration first, so a member that names the structure itself
    /// finds it declared, then the body.
    fn define_composite(&mut self, index: usize, key: &str) {
        if self.emitted.contains(&index) || self.writing.contains(&index) {
            return;
        }
        self.writing.insert(index);
        self.types.push(format!("{key};"));
        let (body, packed, header) = self.composite_body(index);
        let attribute = if packed {
            " __attribute__((packed))"
        } else {
            ""
        };
        // The attribute stands before the name, as the C parser reads it.
        let (keyword, name) = key.split_once(' ').unwrap_or((key, ""));
        self.types
            .push(format!("{keyword}{attribute} {name}{header} {{ {body} }};"));
        self.writing.remove(&index);
        self.emitted.insert(index);
    }

    /// The members and bases of a composite, in the order the DWARF
    /// declares them, with the layout each is placed at.
    fn members_of(&mut self, index: usize) -> Vec<Member> {
        let mut members = Vec::new();
        for child in self.dies[index].children.clone() {
            let die = self.dies[child].clone();
            match die.tag {
                constants::DW_TAG_inheritance => {
                    let Some(ty) = die.reference(constants::DW_AT_type).and_then(|o| self.at(o))
                    else {
                        continue;
                    };
                    let (size, align) = self.size_align(ty).unwrap_or((0, 1));
                    members.push(Member {
                        name: None,
                        ty,
                        offset: die.number(constants::DW_AT_data_member_location),
                        bits: None,
                        size,
                        align,
                        base: true,
                    });
                }
                constants::DW_TAG_member => {
                    if die.flag(constants::DW_AT_declaration) {
                        continue;
                    }
                    // A static member stands in memory, not the layout.
                    if die.attr(constants::DW_AT_data_member_location).is_none()
                        && die.attr(constants::DW_AT_data_bit_offset).is_none()
                    {
                        continue;
                    }
                    let Some(ty) = die.reference(constants::DW_AT_type).and_then(|o| self.at(o))
                    else {
                        continue;
                    };
                    let name = self
                        .string(&die, constants::DW_AT_name)
                        .or_else(|| {
                            die.flag(constants::DW_AT_artificial)
                                .then(|| "_vptr".to_string())
                        });
                    let (size, align) = self.size_align(ty).unwrap_or((0, 1));
                    let bits = die.number(constants::DW_AT_bit_size).map(|width| {
                        if let Some(dbo) = die.number(constants::DW_AT_data_bit_offset) {
                            (self.engine_bit(dbo, width, size), width as u32)
                        } else {
                            let byte_offset = die
                                .number(constants::DW_AT_data_member_location)
                                .or_else(|| self.member_location_expr(&die))
                                .unwrap_or(0);
                            let bit_offset = die.number(constants::DW_AT_bit_offset).unwrap_or(0);
                            let storage_bytes = die.number(constants::DW_AT_byte_size).unwrap_or(size);
                            let storage_bits = storage_bytes * 8;
                            let lsb_in_unit = if self.little_endian {
                                storage_bits.saturating_sub(bit_offset + width)
                            } else {
                                bit_offset
                            };
                            let dbo = byte_offset * 8 + lsb_in_unit;
                            (self.engine_bit(dbo, width, storage_bytes), width as u32)
                        }
                    });
                    let offset = if bits.is_some() {
                        None
                    } else {
                        die.number(constants::DW_AT_data_member_location)
                            .or_else(|| self.member_location_expr(&die))
                    };
                    members.push(Member {
                        name,
                        ty,
                        offset,
                        bits,
                        size,
                        align,
                        base: false,
                    });
                }
                _ => {}
            }
        }
        members
    }

    /// A member's offset as a location expression spells it:
    /// `DW_OP_plus_uconst` after a push, the common spelling.
    fn member_location_expr(&self, die: &Die<'a>) -> Option<u64> {
        let AttributeValue::Exprloc(expression) = die.attr(constants::DW_AT_data_member_location)?
        else {
            return None;
        };
        let mut ops = (*expression).operations(self.unit.encoding());
        match ops.next() {
            Ok(Some(Operation::PlusConstant { value })) => Some(value),
            Ok(Some(Operation::UnsignedConstant { value })) => Some(value),
            _ => None,
        }
    }

    /// A bit-field's first bit as the engine counts it, from the low end
    /// of the structure on a little-endian target. On a big-endian one
    /// the DWARF counts from the high end of the field's unit; the count
    /// is turned around within that unit.
    fn engine_bit(&self, dbo: u64, width: u64, unit_size: u64) -> u64 {
        let unit = unit_size * 8;
        if self.little_endian || unit == 0 {
            return dbo;
        }
        let unit_offset = (dbo / unit) * unit_size;
        unit_offset * 8 + (unit - (dbo % unit) - width)
    }

    /// The body of a composite, whether it is packed, and the base-class
    /// header that follows its name: the members as C declarations at
    /// the offsets the DWARF gives them, bit-fields with unnamed padding
    /// to reach their bits.
    fn composite_body(&mut self, index: usize) -> (String, bool, String) {
        let members = self.members_of(index);
        let packed = !self.layout_matches(&members, false) && {
            if self.layout_matches(&members, true) {
                true
            } else {
                self.note(format!(
                    "the layout of the {} at {:#x} may differ from the DWARF's",
                    self.composite_keyword(index),
                    self.dies[index].offset
                ));
                false
            }
        };
        let mut words: Vec<String> = Vec::new();
        let mut bases: Vec<String> = Vec::new();
        let mut bit: u64 = 0;
        for member in &members {
            let spell = self.spell(member.ty);
            if member.base {
                bases.push(format!("public {}", spell.expr()));
                if let Some(offset) = member.offset {
                    bit = (offset + member.size) * 8;
                }
                continue;
            }
            match member.bits {
                Some((target, width)) => {
                    let unit = member.size.max(1) * 8;
                    // Unnamed padding to reach the field's first bit.
                    let mut guard = 0;
                    while bit < target && guard < 1024 {
                        guard += 1;
                        let room = if packed {
                            unit
                        } else {
                            round_up(bit + 1, unit) - bit
                        };
                        let pad = (target - bit).min(room).max(1);
                        words.push(format!("{} : {};", spell.expr().trim(), pad));
                        bit += pad;
                    }
                    if bit != target {
                        self.note(format!(
                            "the bit-field {} at {:#x} is placed at bit {bit}, not {target}",
                            member.name.as_deref().unwrap_or("(unnamed)"),
                            self.dies[index].offset
                        ));
                    }
                    let name = member.name.as_deref().unwrap_or("");
                    words.push(format!("{} : {width};", spell.declare(name).trim()));
                    bit = target + u64::from(width);
                }
                None => {
                    let name = member.name.as_deref().unwrap_or("");
                    words.push(format!("{};", spell.declare(name).trim()));
                    if let Some(offset) = member.offset {
                        bit = (offset + member.size) * 8;
                    } else {
                        bit += member.size * 8;
                    }
                }
            }
        }
        let header = if bases.is_empty() {
            String::new()
        } else {
            format!(" : {}", bases.join(", "))
        };
        (words.join(" "), packed, header)
    }

    /// Whether the C layout of the members — natural, or packed — places
    /// each at the offset the DWARF gives it.
    fn layout_matches(&self, members: &[Member], packed: bool) -> bool {
        let mut bit: u64 = 0;
        for member in members {
            match member.bits {
                Some((target, width)) => {
                    let unit = member.size.max(1) * 8;
                    let placed = if packed
                        || width == 0
                        || bit / unit == (bit + u64::from(width) - 1) / unit
                    {
                        bit
                    } else {
                        round_up(bit, unit)
                    };
                    if placed != target {
                        return false;
                    }
                    bit = target + u64::from(width);
                }
                None => {
                    let align = if packed { 1 } else { member.align.max(1) };
                    let offset = round_up(bit.div_ceil(8), align);
                    if let Some(dwarf_offset) = member.offset {
                        if offset != dwarf_offset {
                            return false;
                        }
                    }
                    bit = (offset + member.size) * 8;
                }
            }
        }
        true
    }

    /// Whether the type at `index` reaches itself through its members,
    /// following pointers, arrays, typedefs and qualifiers.
    fn is_cyclic(&mut self, index: usize) -> bool {
        if let Some(&cyclic) = self.cyclic.get(&index) {
            return cyclic;
        }
        let mut seen: HashSet<usize> = HashSet::new();
        let mut stack = vec![index];
        let mut found = false;
        while let Some(current) = stack.pop() {
            for reference in self.type_references(current) {
                if reference == index {
                    found = true;
                    break;
                }
                if seen.insert(reference) {
                    stack.push(reference);
                }
            }
            if found || seen.len() > 4096 {
                break;
            }
        }
        self.cyclic.insert(index, found);
        found
    }

    /// The composites a type's members or inner types name, following
    /// the wrappers (pointers, arrays, typedefs, qualifiers) through.
    fn type_references(&self, index: usize) -> Vec<usize> {
        let die = &self.dies[index];
        let mut roots = Vec::new();
        match die.tag {
            constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_class_type => {
                for child in &die.children {
                    let child = &self.dies[*child];
                    if matches!(
                        child.tag,
                        constants::DW_TAG_member | constants::DW_TAG_inheritance
                    ) {
                        if let Some(offset) = child.reference(constants::DW_AT_type) {
                            roots.push(offset);
                        }
                    }
                }
            }
            constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type
            | constants::DW_TAG_pointer_type
            | constants::DW_TAG_reference_type
            | constants::DW_TAG_array_type => {
                if let Some(offset) = die.reference(constants::DW_AT_type) {
                    roots.push(offset);
                }
            }
            constants::DW_TAG_subroutine_type => {
                if let Some(offset) = die.reference(constants::DW_AT_type) {
                    roots.push(offset);
                }
                for child in &die.children {
                    if let Some(offset) =
                        self.dies[*child].reference(constants::DW_AT_type)
                    {
                        roots.push(offset);
                    }
                }
            }
            _ => {}
        }
        let mut composites = Vec::new();
        for root in roots {
            let mut current = root;
            for _ in 0..64 {
                let Some(idx) = self.at(current) else { break };
                let die = &self.dies[idx];
                match die.tag {
                    constants::DW_TAG_structure_type
                    | constants::DW_TAG_union_type
                    | constants::DW_TAG_class_type
                    | constants::DW_TAG_enumeration_type => {
                        composites.push(idx);
                        break;
                    }
                    constants::DW_TAG_typedef
                    | constants::DW_TAG_const_type
                    | constants::DW_TAG_volatile_type
                    | constants::DW_TAG_restrict_type
                    | constants::DW_TAG_atomic_type
                    | constants::DW_TAG_pointer_type
                    | constants::DW_TAG_reference_type
                    | constants::DW_TAG_array_type => {
                        match die.reference(constants::DW_AT_type) {
                            Some(offset) => current = offset,
                            None => break,
                        }
                    }
                    _ => break,
                }
            }
        }
        composites
    }

    /// The spelling of an enumeration: its name and enumerators, the
    /// definition written once when it is named.
    fn enum_spell(&mut self, index: usize) -> Spell {
        let die = &self.dies[index];
        let mut enumerators = Vec::new();
        for child in die.children.clone() {
            let enumerator = &self.dies[child];
            if enumerator.tag != constants::DW_TAG_enumerator {
                continue;
            }
            let Some(name) = self.string(enumerator, constants::DW_AT_name) else {
                continue;
            };
            let value = enumerator.signed(constants::DW_AT_const_value).unwrap_or(0);
            enumerators.push(format!("{name} = {value}"));
        }
        let body = enumerators.join(", ");
        match self.string(die, constants::DW_AT_name) {
            Some(name) => {
                let key = format!("enum {name}");
                if !self.emitted.contains(&index) {
                    self.emitted.insert(index);
                    self.types.push(format!("{key} {{ {body} }};"));
                }
                Spell::plain(&key)
            }
            None => Spell::plain(&format!("enum {{ {body} }}")),
        }
    }

    /// The size and alignment of a type, as the DWARF measures them: a
    /// base type's byte size, a pointer's address size, an array's
    /// element times its count, a composite's byte size and the widest
    /// alignment of its members. `None` for a type with no size.
    fn size_align(&mut self, index: usize) -> Option<(u64, u64)> {
        if let Some(&measured) = self.sizes.get(&index) {
            return measured;
        }
        // A cycle of sizes has no measurement; the guard keeps the walk
        // from following one forever.
        self.sizes.insert(index, None);
        let die = &self.dies[index];
        let measured = match die.tag {
            constants::DW_TAG_base_type => {
                let size = die.number(constants::DW_AT_byte_size)?;
                Some((size, size.max(1)))
            }
            constants::DW_TAG_pointer_type
            | constants::DW_TAG_reference_type
            | constants::DW_TAG_rvalue_reference_type
            | constants::DW_TAG_ptr_to_member_type => {
                let size = u64::from(self.unit.encoding().address_size);
                Some((size, size))
            }
            constants::DW_TAG_array_type => {
                let inner = die.reference(constants::DW_AT_type).and_then(|o| self.at(o))?;
                let (size, align) = self.size_align(inner)?;
                let count = self.array_count(index)?;
                Some((size.checked_mul(count)?, align))
            }
            constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type
            | constants::DW_TAG_immutable_type => {
                let inner = die.reference(constants::DW_AT_type).and_then(|o| self.at(o))?;
                self.size_align(inner)
            }
            constants::DW_TAG_enumeration_type => {
                match die.reference(constants::DW_AT_type).and_then(|o| self.at(o)) {
                    Some(inner) => self.size_align(inner),
                    None => Some((4, 4)),
                }
            }
            constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_class_type => {
                let size = die.number(constants::DW_AT_byte_size)?;
                let mut align = 1u64;
                for child in die.children.clone() {
                    let child = &self.dies[child];
                    if !matches!(
                        child.tag,
                        constants::DW_TAG_member | constants::DW_TAG_inheritance
                    ) {
                        continue;
                    }
                    if let Some(ty) = child.reference(constants::DW_AT_type).and_then(|o| self.at(o))
                    {
                        if let Some((_, member_align)) = self.size_align(ty) {
                            align = align.max(member_align);
                        }
                    }
                }
                Some((size, align))
            }
            _ => None,
        };
        self.sizes.insert(index, measured);
        measured
    }
}

/// Collect one DIE and its subtree into the arena, depth first.
fn collect_die<'a>(
    node: gimli::EntriesTreeNode<'_, '_, Slice<'a>>,
    dies: &mut Vec<Die<'a>>,
    by_offset: &mut HashMap<usize, usize>,
    depth: usize,
) {
    if depth > 256 {
        return;
    }
    let entry: &DebuggingInformationEntry<Slice<'a>> = node.entry();
    let index = dies.len();
    by_offset.insert(entry.offset().0, index);
    dies.push(Die {
        offset: entry.offset().0,
        tag: entry.tag(),
        attrs: entry
            .attrs()
            .iter()
            .map(|attr| (attr.name(), attr.form(), attr.value()))
            .collect(),
        children: Vec::new(),
    });
    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        let child_index = dies.len();
        collect_die(child, dies, by_offset, depth + 1);
        // The child may have been dropped by the depth guard.
        if child_index < dies.len() {
            dies[index].children.push(child_index);
        }
    }
}

/// Whether a name is one C can spell: a letter or underscore, then
/// letters, digits and underscores.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Round `value` up to a multiple of `align`.
fn round_up(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

// ---------------------------------------------------------------------
// Finding the DWARF.

/// The DWARF of an image, found: its bytes, where they came from, and
/// the notes the search left.
#[derive(Debug, Clone)]
pub struct Located {
    /// The bytes of the file holding the DWARF.
    pub bytes: Vec<u8>,
    /// Where the DWARF was found, as one line says it.
    pub source: String,
    /// Notes left on the way: candidates held back, servers that failed.
    pub notes: Vec<String>,
}

/// Find the DWARF of the image at `image`, looking where a debugger
/// looks: the image itself, its `.gnu_debuglink`, a sibling file, a dSYM
/// bundle, a build-ID directory, the debuginfod cache, and the debuginfod
/// servers `DEBUGINFOD_URLS` names. The global debug directory is
/// `/usr/lib/debug`.
pub fn locate(image: &Path) -> Result<Located, String> {
    let urls = std::env::var("DEBUGINFOD_URLS").unwrap_or_default();
    let cache = default_cache_dir();
    locate_with(
        image,
        &[PathBuf::from("/usr/lib/debug")],
        &urls,
        cache.as_deref(),
    )
}

/// The debuginfod client cache: `DEBUGINFOD_CACHE_PATH`, or
/// `debuginfod_client` under the XDG cache home or `~/.cache`.
pub fn default_cache_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("DEBUGINFOD_CACHE_PATH") {
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    if let Ok(home) = std::env::var("XDG_CACHE_HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join("debuginfod_client"));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".cache").join("debuginfod_client"))
}

/// [`locate`] with the places to look given: the global debug directories,
/// the debuginfod URLs (space-separated, as `DEBUGINFOD_URLS` spells them),
/// and the debuginfod cache directory.
pub fn locate_with(
    image: &Path,
    debug_dirs: &[PathBuf],
    urls: &str,
    cache: Option<&Path>,
) -> Result<Located, String> {
    let bytes = std::fs::read(image)
        .map_err(|error| format!("{} cannot be read: {error}", image.display()))?;
    let mut notes = Vec::new();

    // The image itself.
    if has_dwarf(&bytes) {
        return Ok(Located {
            source: format!("{} (embedded)", image.display()),
            bytes,
            notes,
        });
    }

    let dir = image.parent().unwrap_or(Path::new("."));
    let file_name = image
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = image
        .file_stem()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| file_name.clone());
    let absolute = image.canonicalize().unwrap_or_else(|_| image.to_path_buf());
    let absolute_dir = absolute.parent().unwrap_or(Path::new("."));

    // The .gnu_debuglink: the file it names, beside the image, in a
    // .debug directory beside it, or under a global debug directory at
    // the image's own path — its CRC checked.
    if let Some((link, crc)) = debuglink(&bytes) {
        let mut candidates = vec![dir.join(&link), dir.join(".debug").join(&link)];
        for debug_dir in debug_dirs {
            // The image's path under the global debug directory, its
            // root stripped so the join keeps the directory.
            let under = absolute_dir.strip_prefix("/").unwrap_or(absolute_dir);
            candidates.push(debug_dir.join(under).join(&link));
        }
        for candidate in candidates {
            let Ok(found) = std::fs::read(&candidate) else {
                continue;
            };
            if crc32(&found) != crc {
                notes.push(format!(
                    "{}: the CRC does not match the .gnu_debuglink",
                    candidate.display()
                ));
                continue;
            }
            if has_dwarf(&found) {
                return Ok(Located {
                    source: format!("{} (gnu_debuglink)", candidate.display()),
                    bytes: found,
                    notes,
                });
            }
            notes.push(format!("{}: no DWARF in it", candidate.display()));
        }
    }

    // A sibling file: the image's name with a debug suffix, or its stem.
    let mut siblings = Vec::new();
    for suffix in ["debug", "debuginfo", "dwarf"] {
        siblings.push(dir.join(format!("{file_name}.{suffix}")));
        siblings.push(dir.join(format!("{stem}.{suffix}")));
    }
    for candidate in siblings {
        let Ok(found) = std::fs::read(&candidate) else {
            continue;
        };
        if has_dwarf(&found) {
            return Ok(Located {
                source: format!("{} (sibling file)", candidate.display()),
                bytes: found,
                notes,
            });
        }
        notes.push(format!("{}: no DWARF in it", candidate.display()));
    }

    // A dSYM bundle beside the image.
    for bundle in [format!("{file_name}.dSYM"), format!("{stem}.dSYM")] {
        let resources = dir.join(&bundle).join("Contents/Resources/DWARF");
        let mut candidates = vec![resources.join(&file_name), resources.join(&stem)];
        if let Ok(entries) = std::fs::read_dir(&resources) {
            candidates.extend(entries.flatten().map(|entry| entry.path()));
        }
        for candidate in candidates {
            let Ok(found) = std::fs::read(&candidate) else {
                continue;
            };
            if has_dwarf(&found) {
                return Ok(Located {
                    source: format!("{} (dSYM)", candidate.display()),
                    bytes: found,
                    notes,
                });
            }
        }
    }

    // The build ID: a build-ID directory, the debuginfod cache, then the
    // debuginfod servers.
    if let Some(build_id) = build_id(&bytes) {
        if build_id.len() >= 4 {
            for debug_dir in debug_dirs {
                let candidate = debug_dir
                    .join(".build-id")
                    .join(&build_id[..2])
                    .join(format!("{}.debug", &build_id[2..]));
                let Ok(found) = std::fs::read(&candidate) else {
                    continue;
                };
                if has_dwarf(&found) {
                    return Ok(Located {
                        source: format!("{} (build-ID directory)", candidate.display()),
                        bytes: found,
                        notes,
                    });
                }
                notes.push(format!("{}: no DWARF in it", candidate.display()));
            }
        }
        if let Some(cache) = cache {
            let candidate = cache.join(&build_id).join("debuginfo");
            if let Ok(found) = std::fs::read(&candidate) {
                if has_dwarf(&found) {
                    return Ok(Located {
                        source: format!("{} (debuginfod cache)", candidate.display()),
                        bytes: found,
                        notes,
                    });
                }
                notes.push(format!("{}: no DWARF in it", candidate.display()));
            }
        }
        for url in urls.split_whitespace() {
            match fetch_debuginfod(url, &build_id) {
                Ok(found) if has_dwarf(&found) => {
                    if let Some(cache_dir) = cache {
                        let dest = cache_dir.join(&build_id).join("debuginfo");
                        if let Some(parent) = dest.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let _ = std::fs::write(&dest, &found);
                    }
                    return Ok(Located {
                        source: format!("{url} (debuginfod, build ID {build_id})"),
                        bytes: found,
                        notes,
                    });
                }
                Ok(_) => notes.push(format!("{url}: the answer holds no DWARF")),
                Err(error) => notes.push(format!("{url}: {error}")),
            }
        }
    }

    Err(if notes.is_empty() {
        format!(
            "no DWARF debug info found for {}: not embedded, no sibling file, dSYM or build-ID match",
            image.display()
        )
    } else {
        format!(
            "no DWARF debug info found for {}: {}",
            image.display(),
            notes.join("; ")
        )
    })
}

/// The `.gnu_debuglink` section: the file name it names and the CRC of
/// its bytes.
fn debuglink(bytes: &[u8]) -> Option<(String, u32)> {
    let file = object::File::parse(bytes).ok()?;
    let section = file.section_by_name(".gnu_debuglink")?;
    let data = section.data().ok()?;
    let end = data.iter().position(|byte| *byte == 0)?;
    let name = std::str::from_utf8(&data[..end]).ok()?.to_string();
    let crc_at = round_up(end as u64 + 1, 4) as usize;
    let crc = data.get(crc_at..crc_at + 4)?;
    let crc = if file.is_little_endian() {
        u32::from_le_bytes(crc.try_into().ok()?)
    } else {
        u32::from_be_bytes(crc.try_into().ok()?)
    };
    Some((name, crc))
}

/// The image's GNU build ID, as hex: the `.note.gnu.build-id` note's
/// descriptor.
pub fn build_id(bytes: &[u8]) -> Option<String> {
    let file = object::File::parse(bytes).ok()?;
    let section = file.section_by_name(".note.gnu.build-id")?;
    let data = section.data().ok()?;
    let read_u32 = |at: usize| -> Option<u32> {
        let bytes = data.get(at..at + 4)?;
        Some(if file.is_little_endian() {
            u32::from_le_bytes(bytes.try_into().ok()?)
        } else {
            u32::from_be_bytes(bytes.try_into().ok()?)
        })
    };
    let namesz = read_u32(0)? as usize;
    let descsz = read_u32(4)? as usize;
    let kind = read_u32(8)?;
    let name_at = 12;
    let desc_at = name_at + round_up(namesz as u64, 4) as usize;
    if kind != 3 || data.get(name_at..name_at + namesz)? != b"GNU\0" {
        return None;
    }
    let desc = data.get(desc_at..desc_at + descsz)?;
    Some(desc.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The CRC-32 the `.gnu_debuglink` checks: the zlib polynomial,
/// reflected, as `objcopy` writes it.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Fetch a build ID's debuginfo from a debuginfod server:
/// `GET <url>/buildid/<hex>/debuginfo`. An `http://` URL is read directly;
/// an `https://` one through `curl`, which holds the TLS this reader has
/// no library for.
fn fetch_debuginfod(url: &str, build_id: &str) -> Result<Vec<u8>, String> {
    let full = format!(
        "{}/buildid/{}/debuginfo",
        url.trim_end_matches('/'),
        build_id
    );
    if let Some(rest) = full.strip_prefix("http://") {
        http_get(rest)
    } else if full.starts_with("https://") {
        let output = std::process::Command::new("curl")
            .args(["-fsSL", "--max-time", "30", &full])
            .output()
            .map_err(|_| "https needs curl, which is not installed".to_string())?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(format!(
                "curl: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    } else {
        Err("the URL is no http:// or https://".to_string())
    }
}

/// A plain HTTP GET, read to the close: the request says `Connection:
/// close`, so the body ends where the connection does.
fn http_get(rest: &str) -> Result<Vec<u8>, String> {
    use std::net::{TcpStream, ToSocketAddrs};
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| "a bad port")?),
        None => (host_port, 80),
    };
    let address = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|error| format!("{host}: {error}"))?
        .next()
        .ok_or_else(|| format!("{host}: no address"))?;
    let timeout = Duration::from_secs(10);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("connect: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("timeout: {error}"))?;
    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {host_port}\r\nUser-Agent: AdmiralGrace/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read: {error}"))?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "the answer has no header end".to_string())?;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    if status != "200" {
        return Err(format!("the answer is {status}"));
    }
    Ok(response[split + 4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        std::fs::read(fixture(name)).expect("the fixture reads")
    }

    fn read_fixture(name: &str) -> DebugInfo {
        read(name, &fixture_bytes(name)).expect("the DWARF reads")
    }

    fn function<'a>(info: &'a DebugInfo, name: &str) -> &'a DebugFunction {
        info.functions
            .iter()
            .find(|function| function.name == name)
            .unwrap_or_else(|| panic!("no function named {name}"))
    }

    fn datum<'a>(info: &'a DebugInfo, name: &str) -> &'a DebugData {
        info.data
            .iter()
            .find(|symbol| symbol.name == name)
            .unwrap_or_else(|| panic!("no datum named {name}"))
    }

    fn local<'a>(info: &'a DebugInfo, func: &str, name: &str) -> &'a DebugLocal {
        let address = function(info, func).address;
        info.locals
            .iter()
            .find(|local| local.function == address && local.name == name)
            .unwrap_or_else(|| panic!("no local {name} of {func}"))
    }

    #[test]
    fn the_sample_reads_its_functions_prototypes_and_locals() {
        let info = read_fixture("sample.elf");
        let add = function(&info, "add");
        assert_eq!(add.address, 0x1149);
        assert_eq!(add.size, Some(0x18));
        assert_eq!(add.prototype.as_deref(), Some("int add(int a, int b)"));
        assert_eq!(add.source.as_deref(), Some("sample.c:2"));
        let sum_to = function(&info, "sum_to");
        assert_eq!(sum_to.address, 0x1161);
        // The prototype's type is spelled as the engine's C parser
        // canonicalizes it: `long int` reads back as `long`.
        assert_eq!(sum_to.prototype.as_deref(), Some("long sum_to(int n)"));
        let main = function(&info, "main");
        assert_eq!(main.address, 0x1198);
        assert_eq!(main.size, Some(0x54));
        assert_eq!(
            main.prototype.as_deref(),
            Some("int main(int argc, char **argv)")
        );
        assert_eq!(main.source.as_deref(), Some("sample.c:8"));
        // printf is a declaration: no code, no import.
        assert!(!info.functions.iter().any(|f| f.name == "printf"));

        // The locals: the frame base is the CFA, which stands 8 above
        // the entry stack pointer on x86-64, so argc at CFA-36 is at
        // entry-28 — local_1c.
        assert_eq!(local(&info, "main", "argc").offset, -28);
        assert_eq!(local(&info, "main", "argc").size, 4);
        assert_eq!(local(&info, "main", "argc").ctype.as_deref(), Some("int"));
        assert_eq!(local(&info, "main", "argv").offset, -40);
        assert_eq!(
            local(&info, "main", "argv").ctype.as_deref(),
            Some("char **")
        );
        assert_eq!(local(&info, "main", "x").offset, -20);
        assert_eq!(local(&info, "main", "s").offset, -16);
        assert_eq!(local(&info, "main", "s").ctype.as_deref(), Some("long int"));
        // A local of a lexical block is the function's own.
        assert_eq!(local(&info, "sum_to", "i").offset, -20);
        assert_eq!(
            local(&info, "sum_to", "acc").ctype.as_deref(),
            Some("long int")
        );
        assert_eq!(local(&info, "add", "a").offset, -12);
    }

    #[test]
    fn the_dwarf_fixture_reads_its_types_globals_and_locals() {
        let info = read_fixture("dwarf.elf");

        // The functions and their prototypes.
        assert_eq!(
            function(&info, "add").prototype.as_deref(),
            Some("int add(int a, int b)")
        );
        assert_eq!(
            function(&info, "use_point").prototype.as_deref(),
            Some("int use_point(struct point *p, point_t q)")
        );
        assert_eq!(
            function(&info, "main").prototype.as_deref(),
            Some("int main(void)")
        );

        // The globals, at their addresses under their types.
        let count = datum(&info, "global_count");
        assert_eq!(count.address, 0x404040);
        assert_eq!(count.ctype.as_deref(), Some("int"));
        assert_eq!(count.size, Some(4));
        let point = datum(&info, "global_point");
        assert_eq!(point.address, 0x404048);
        assert_eq!(point.ctype.as_deref(), Some("struct point"));
        assert_eq!(point.size, Some(8));
        let table = datum(&info, "global_table");
        assert_eq!(table.ctype.as_deref(), Some("long int[4]"));
        assert_eq!(table.size, Some(32));
        assert_eq!(
            datum(&info, "global_color").ctype.as_deref(),
            Some("enum color")
        );
        // use_point's static stands in memory, not the frame.
        let calls = datum(&info, "calls");
        assert_eq!(calls.ctype.as_deref(), Some("int"));
        assert!(!info.locals.iter().any(|l| l.name == "calls"));

        // The locals of main: the structure, the enumeration, the
        // function-pointer typedef.
        let o = local(&info, "main", "o");
        assert_eq!(o.ctype.as_deref(), Some("struct outer"));
        assert_eq!(o.size, 24);
        assert_eq!(o.offset, -56);
        assert_eq!(local(&info, "main", "c").ctype.as_deref(), Some("enum color"));
        assert_eq!(local(&info, "main", "compare").ctype.as_deref(), Some("cmp_t"));
        assert_eq!(local(&info, "use_point", "local").ctype.as_deref(), Some("struct point"));

        // The definitions, in dependency order: point before outer,
        // node's self-reference declared first.
        let types = info.types.join("\n");
        assert!(types.contains("struct point { int x; int y; };"), "{types}");
        assert!(types.contains("struct node;"), "{types}");
        assert!(
            types.contains("struct node { int value; struct node *next; };"),
            "{types}"
        );
        assert!(
            types.contains("enum color { RED = 0, GREEN = 5, BLUE = 6 };"),
            "{types}"
        );
        assert!(types.contains("typedef struct point point_t;"), "{types}");
        assert!(
            types.contains("typedef int (*cmp_t)(int, int);"),
            "{types}"
        );
        assert!(
            types.contains("struct __attribute__((packed)) packed { char c; int i; short s; };"),
            "{types}"
        );
        assert!(
            types.contains("struct flags { unsigned int a : 3; unsigned int b : 5; unsigned int : 24; unsigned int c : 4; };"),
            "{types}"
        );
        assert!(
            types.contains("struct outer { struct point p; struct flags f; char name[8]; };"),
            "{types}"
        );
        // Every definition reads as C, and lays out as the DWARF says.
        let model = crate::types::DataModel::LP64;
        let texts: Vec<crate::ctype::TypeText> = info
            .types
            .iter()
            .enumerate()
            .map(|(index, c)| crate::ctype::TypeText {
                name: format!("type {index}"),
                c: c.clone(),
            })
            .collect();
        let (store, notes) = crate::ctype::build(model, &texts).expect("the types read");
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(store.size_of(&crate::types::Type::Named("struct packed".into())), Ok(7));
        assert_eq!(store.size_of(&crate::types::Type::Named("struct flags".into())), Ok(8));
        assert_eq!(store.size_of(&crate::types::Type::Named("struct outer".into())), Ok(24));
        let flags = store.layout("struct flags").unwrap();
        let a = flags.fields.iter().find(|f| f.name.as_deref() == Some("a")).unwrap();
        assert_eq!(a.bits, Some((0, 3)));
        let c = flags.fields.iter().find(|f| f.name.as_deref() == Some("c")).unwrap();
        assert_eq!(c.bits, Some((0, 4)));
        assert_eq!(c.offset, 4);
    }

    #[test]
    fn a_dwarf_four_file_reads_the_same_shape() {
        let info = read_fixture("dwarf4.elf");
        let main = function(&info, "main");
        assert_eq!(main.size, Some(0xa2));
        assert_eq!(main.source.as_deref(), Some("dwarf.c:49"));
        assert_eq!(
            main.prototype.as_deref(),
            Some("int main(void)")
        );
        assert_eq!(local(&info, "main", "o").offset, -56);
        assert!(info.types.iter().any(|t| t.contains("struct point { int x; int y; };")));
        assert!(
            info.types.iter().any(|t| t.contains("struct flags { unsigned int a : 3; unsigned int b : 5; unsigned int : 24; unsigned int c : 4; };")),
            "{:?}",
            info.types
        );
    }

    #[test]
    fn the_parser_recognizes_only_images_with_dwarf() {
        let parser = DwarfParser;
        assert!(parser.recognizes(&fixture_bytes("dwarf.elf")));
        assert!(parser.recognizes(&fixture_bytes("dwarf.debug")));
        assert!(!parser.recognizes(&fixture_bytes("dwarf_stripped.elf")));
        assert!(!parser.recognizes(b"a linker map is text"));
        assert!(!parser.recognizes(b"\x7fELF not really"));
        let _guard = crate::debuginfo::REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let parsed = crate::debuginfo::parse("dwarf.elf", &fixture_bytes("dwarf.elf"), None)
            .expect("the dwarf parser reads it");
        assert_eq!(parsed.parser, "dwarf");
        let error = read("empty.elf", &fixture_bytes("dwarf_stripped.elf")).unwrap_err();
        assert!(error.contains("no .debug_info"), "{error}");
    }

    #[test]
    fn a_second_symbol_at_one_address_is_held_back() {
        // The same DWARF twice: the second read's symbols are held back.
        let mut info = read_fixture("dwarf.elf");
        let twice = read_fixture("dwarf.elf");
        info.functions.extend(twice.functions);
        info.data.extend(twice.data);
        info.locals.extend(twice.locals);
        dedup("dwarf.elf", &mut info);
        assert!(info.notes.iter().any(|note| note.contains("held back")));
        let mains = info.functions.iter().filter(|f| f.name == "main").count();
        assert_eq!(mains, 1);
    }

    // ---- Finding the DWARF. ----

    /// A directory of one's own, removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "ag-dwarf-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("the temp dir is made");
            TempDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_embedded_dwarf_is_found_first() {
        let located = locate(&fixture("dwarf.elf")).expect("found");
        assert!(located.source.contains("embedded"), "{}", located.source);
        assert!(has_dwarf(&located.bytes));
    }

    #[test]
    fn a_sibling_debug_file_is_found() {
        let dir = TempDir::new("sibling");
        let image = dir.path().join("prog");
        std::fs::write(&image, fixture_bytes("dwarf_stripped.elf")).unwrap();
        // The debuglink's own name is tried first; give it nothing, and
        // a sibling under the stem's name instead.
        std::fs::write(dir.path().join("prog.debug"), fixture_bytes("dwarf.debug")).unwrap();
        let located = locate_with(&image, &[], "", None).expect("found");
        assert!(located.source.contains("sibling file"), "{}", located.source);
        assert!(has_dwarf(&located.bytes));
    }

    #[test]
    fn the_gnu_debuglink_is_followed_and_its_crc_checked() {
        let dir = TempDir::new("debuglink");
        let image = dir.path().join("prog");
        std::fs::write(&image, fixture_bytes("dwarf_stripped.elf")).unwrap();
        // The link names dwarf.debug; a wrong file under that name is
        // held back, and the right one in .debug/ is found.
        std::fs::write(dir.path().join("dwarf.debug"), b"not the debug info").unwrap();
        std::fs::create_dir_all(dir.path().join(".debug")).unwrap();
        std::fs::write(
            dir.path().join(".debug/dwarf.debug"),
            fixture_bytes("dwarf.debug"),
        )
        .unwrap();
        let located = locate_with(&image, &[], "", None).expect("found");
        assert!(located.source.contains("gnu_debuglink"), "{}", located.source);
        assert!(located.source.contains(".debug"), "{}", located.source);
        assert!(
            located.notes.iter().any(|note| note.contains("CRC")),
            "{:?}",
            located.notes
        );
    }

    #[test]
    fn a_global_debug_directory_is_searched_at_the_images_path() {
        let dir = TempDir::new("global");
        let image_dir = dir.path().join("bin");
        std::fs::create_dir_all(&image_dir).unwrap();
        let image = image_dir.join("prog");
        std::fs::write(&image, fixture_bytes("dwarf_stripped.elf")).unwrap();
        let debug_root = dir.path().join("usr/lib/debug");
        let linked = debug_root
            .join(image_dir.strip_prefix("/").unwrap())
            .join("dwarf.debug");
        std::fs::create_dir_all(linked.parent().unwrap()).unwrap();
        std::fs::write(&linked, fixture_bytes("dwarf.debug")).unwrap();
        let located = locate_with(&image, &[debug_root], "", None).expect("found");
        assert!(located.source.contains("gnu_debuglink"), "{}", located.source);
    }

    #[test]
    fn a_dsym_bundle_is_found() {
        let dir = TempDir::new("dsym");
        let image = dir.path().join("prog");
        std::fs::write(&image, fixture_bytes("dwarf_stripped.elf")).unwrap();
        let resources = dir.path().join("prog.dSYM/Contents/Resources/DWARF");
        std::fs::create_dir_all(&resources).unwrap();
        std::fs::write(resources.join("prog"), fixture_bytes("dwarf.debug")).unwrap();
        let located = locate_with(&image, &[], "", None).expect("found");
        assert!(located.source.contains("dSYM"), "{}", located.source);
    }

    #[test]
    fn a_build_id_directory_and_the_debuginfod_cache_are_found() {
        let bytes = fixture_bytes("dwarf_stripped.elf");
        let id = build_id(&bytes).expect("the fixture has a build ID");
        assert!(id.len() >= 4);

        let dir = TempDir::new("buildid");
        let image = dir.path().join("prog");
        std::fs::write(&image, &bytes).unwrap();
        let debug_root = dir.path().join("debug");
        let linked = debug_root
            .join(".build-id")
            .join(&id[..2])
            .join(format!("{}.debug", &id[2..]));
        std::fs::create_dir_all(linked.parent().unwrap()).unwrap();
        std::fs::write(&linked, fixture_bytes("dwarf.debug")).unwrap();
        let located = locate_with(&image, &[debug_root], "", None).expect("found");
        assert!(
            located.source.contains("build-ID directory"),
            "{}",
            located.source
        );

        // Without the directory, the cache holds it.
        let cache = dir.path().join("cache");
        let cached = cache.join(&id).join("debuginfo");
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, fixture_bytes("dwarf.debug")).unwrap();
        let located = locate_with(&image, &[], "", Some(&cache)).expect("found");
        assert!(
            located.source.contains("debuginfod cache"),
            "{}",
            located.source
        );
    }

    #[test]
    fn a_debuginfod_server_answers_the_build_id() {
        use std::net::TcpListener;
        let bytes = fixture_bytes("dwarf_stripped.elf");
        let id = build_id(&bytes).expect("the fixture has a build ID");
        let payload = fixture_bytes("dwarf.debug");

        let listener = TcpListener::bind("127.0.0.1:0").expect("the server binds");
        let port = listener.local_addr().unwrap().port();
        let expected = format!("/buildid/{id}/debuginfo");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("the request reads");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") || read == 0 {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&request);
            assert!(head.starts_with(&format!("GET {expected} ")), "{head}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&payload).unwrap();
        });

        let dir = TempDir::new("debuginfod");
        let cache = dir.path().join("cache");
        let image = dir.path().join("prog");
        std::fs::write(&image, &bytes).unwrap();
        let urls = format!("http://127.0.0.1:{port}");
        let located = locate_with(&image, &[], &urls, Some(&cache)).expect("found");
        assert!(located.source.contains("debuginfod"), "{}", located.source);
        assert!(has_dwarf(&located.bytes));
        server.join().expect("the server ends");

        // A second locate hits the populated cache without contacting a server.
        let cached = locate_with(&image, &[], "", Some(&cache)).expect("cached");
        assert!(cached.source.contains("debuginfod cache"), "{}", cached.source);
    }

    #[test]
    fn nothing_found_is_an_error_naming_the_places() {
        let dir = TempDir::new("nothing");
        let image = dir.path().join("prog");
        std::fs::write(&image, fixture_bytes("dwarf_stripped.elf")).unwrap();
        let error = locate_with(&image, &[], "", None).unwrap_err();
        assert!(error.contains("no DWARF debug info found"), "{error}");
    }

    #[test]
    fn the_crc_matches_objcopys() {
        // The debuglink's CRC is the CRC of the file it names.
        let bytes = fixture_bytes("dwarf_stripped.elf");
        let (_, crc) = debuglink(&bytes).expect("the fixture has a debuglink");
        assert_eq!(crc32(&fixture_bytes("dwarf.debug")), crc);
    }

    // ---- Synthetic DWARF builders for edge-case unit tests. ----

    fn push_uleb(buf: &mut Vec<u8>, mut val: u64) {
        loop {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    fn push_sleb(buf: &mut Vec<u8>, mut val: i64) {
        loop {
            let byte = (val & 0x7f) as u8;
            val >>= 7;
            let done = (val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0);
            buf.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
    }

    fn push_abbrev(buf: &mut Vec<u8>, code: u64, tag: u64, has_children: bool, attrs: &[(u64, u64)]) {
        push_uleb(buf, code);
        push_uleb(buf, tag);
        buf.push(u8::from(has_children));
        for &(at, form) in attrs {
            push_uleb(buf, at);
            push_uleb(buf, form);
        }
        buf.push(0);
        buf.push(0);
    }

    /// Wrap a DWARF 4 CU body (starting right after the 11-byte header)
    /// into a complete `.debug_info` section.
    fn finish_cu(body: &[u8]) -> Vec<u8> {
        let unit_len = (7 + body.len()) as u32;
        let mut out = Vec::with_capacity(11 + body.len());
        out.extend_from_slice(&unit_len.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes()); // version 4
        out.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
        out.push(8); // address_size
        out.extend_from_slice(body);
        out
    }

    /// Build a minimal little-endian ELF64 image holding the named sections.
    fn mini_elf64(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut shstrtab = vec![0u8];
        let mut shstr_offsets = Vec::with_capacity(sections.len() + 1);
        for &(name, _) in sections {
            shstr_offsets.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let shnum = sections.len() + 2;
        let shoff = 64u64;
        let mut data_off = shoff + (shnum as u64) * 64;

        let mut out = Vec::new();
        // Elf64_Ehdr (64 bytes)
        out.extend_from_slice(b"\x7fELF");
        out.extend_from_slice(&[2, 1, 1, 0]); // 64-bit, LE, v1, SysV
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        out.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out.extend_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        out.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        out.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        out.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        out.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        out.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        out.extend_from_slice(&(shnum as u16).to_le_bytes()); // e_shnum
        out.extend_from_slice(&((sections.len() + 1) as u16).to_le_bytes()); // e_shstrndx

        // Null section header
        out.extend_from_slice(&[0u8; 64]);
        for (i, &(_, payload)) in sections.iter().enumerate() {
            let mut shdr = [0u8; 64];
            shdr[0..4].copy_from_slice(&shstr_offsets[i].to_le_bytes());
            shdr[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
            shdr[24..32].copy_from_slice(&data_off.to_le_bytes());
            shdr[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
            shdr[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
            out.extend_from_slice(&shdr);
            data_off += payload.len() as u64;
        }
        // .shstrtab header
        let mut shdr = [0u8; 64];
        shdr[0..4].copy_from_slice(&shstrtab_name.to_le_bytes());
        shdr[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        shdr[24..32].copy_from_slice(&data_off.to_le_bytes());
        shdr[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
        shdr[48..56].copy_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&shdr);

        for &(_, payload) in sections {
            out.extend_from_slice(payload);
        }
        out.extend_from_slice(&shstrtab);
        out
    }

    /// Build a minimal little-endian 64-bit Mach-O carrying `__DWARF` sections.
    fn mini_macho64(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let sizeofcmds = 72 + sections.len() * 80;
        let header_and_cmds = 32 + sizeofcmds;
        let mut data_off = header_and_cmds;
        let total_data: usize = sections.iter().map(|(_, b)| b.len()).sum();

        let mut out = Vec::with_capacity(header_and_cmds + total_data);
        // mach_header_64 (32 bytes)
        out.extend_from_slice(&0xfeed_facfu32.to_le_bytes()); // MH_MAGIC_64
        out.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // CPU_TYPE_X86_64
        out.extend_from_slice(&3u32.to_le_bytes()); // CPU_SUBTYPE_X86_64_ALL
        out.extend_from_slice(&10u32.to_le_bytes()); // MH_DSYM
        out.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        out.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // segment_command_64 (72 bytes)
        out.extend_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
        out.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
        let mut segname = [0u8; 16];
        segname[..7].copy_from_slice(b"__DWARF");
        out.extend_from_slice(&segname);
        out.extend_from_slice(&0x1000u64.to_le_bytes()); // vmaddr
        out.extend_from_slice(&(total_data as u64).to_le_bytes()); // vmsize
        out.extend_from_slice(&(header_and_cmds as u64).to_le_bytes()); // fileoff
        out.extend_from_slice(&(total_data as u64).to_le_bytes()); // filesize
        out.extend_from_slice(&1u32.to_le_bytes()); // maxprot
        out.extend_from_slice(&1u32.to_le_bytes()); // initprot
        out.extend_from_slice(&(sections.len() as u32).to_le_bytes()); // nsects
        out.extend_from_slice(&0u32.to_le_bytes()); // flags

        // section_64 (80 bytes each)
        let mut vm = 0x1000u64;
        for &(name, payload) in sections {
            let mut sectname = [0u8; 16];
            let copy_len = name.len().min(16);
            sectname[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
            out.extend_from_slice(&sectname);
            out.extend_from_slice(&segname);
            out.extend_from_slice(&vm.to_le_bytes()); // addr
            out.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // size
            out.extend_from_slice(&(data_off as u32).to_le_bytes()); // offset
            out.extend_from_slice(&0u32.to_le_bytes()); // align
            out.extend_from_slice(&0u32.to_le_bytes()); // reloff
            out.extend_from_slice(&0u32.to_le_bytes()); // nreloc
            out.extend_from_slice(&0u32.to_le_bytes()); // flags
            out.extend_from_slice(&[0u8; 12]); // reserved1..3
            data_off += payload.len();
            vm += payload.len() as u64;
        }
        for &(_, payload) in sections {
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn origin_chain_resolves_abstract_origin_and_specification() {
        // DWARF 4 CU:
        //   [1] compile_unit
        //   [2] base_type "int" (4 bytes)
        //   [3] subprogram (declaration: name="compute", type=int, prototyped)
        //       [4] formal_parameter "x", type=int
        //   [5] subprogram (abstract_origin -> [3], specification -> unset; actually [5] uses
        //       specification -> [3] and carries local variable [6] "tmp" type=int)
        //   [7] subprogram (concrete: low_pc=0x401000, high_pc=0x20, frame_base=CFA,
        //       abstract_origin -> [5])
        //       [8] inlined_subroutine
        //           [9] variable (abstract_origin -> [6], location=DW_OP_fbreg(-24))
        const DW_FORM_STRING: u64 = 0x08;
        const DW_FORM_DATA1: u64 = 0x0b;
        const DW_FORM_REF4: u64 = 0x13;
        const DW_FORM_EXPRLOC: u64 = 0x18;
        const DW_FORM_FLAG_PRESENT: u64 = 0x19;
        const DW_FORM_ADDR: u64 = 0x01;
        const DW_FORM_UDATA: u64 = 0x0f;
        const DW_AT_SPECIFICATION: u64 = 0x47;
        const DW_AT_ABSTRACT_ORIGIN: u64 = 0x31;
        const DW_AT_FRAME_BASE: u64 = 0x40;
        const DW_TAG_INLINED_SUBROUTINE: u64 = 0x1d;

        let mut abbrev = Vec::new();
        push_abbrev(&mut abbrev, 1, 0x11, true, &[(0x03, DW_FORM_STRING)]); // CU
        push_abbrev(
            &mut abbrev,
            2,
            0x24,
            false,
            &[(0x03, DW_FORM_STRING), (0x0b, DW_FORM_DATA1), (0x3e, DW_FORM_DATA1)],
        ); // base_type
        push_abbrev(
            &mut abbrev,
            3,
            0x2e,
            true,
            &[
                (0x03, DW_FORM_STRING),
                (0x49, DW_FORM_REF4),
                (0x27, DW_FORM_FLAG_PRESENT),
                (0x3c, DW_FORM_FLAG_PRESENT),
            ],
        ); // subprogram decl
        push_abbrev(&mut abbrev, 4, 0x05, false, &[(0x03, DW_FORM_STRING), (0x49, DW_FORM_REF4)]); // formal_parameter
        push_abbrev(
            &mut abbrev,
            5,
            0x2e,
            true,
            &[(DW_AT_SPECIFICATION, DW_FORM_REF4)],
        ); // subprogram abstract instance -> spec
        push_abbrev(&mut abbrev, 6, 0x34, false, &[(0x03, DW_FORM_STRING), (0x49, DW_FORM_REF4)]); // abstract local
        push_abbrev(
            &mut abbrev,
            7,
            0x2e,
            true,
            &[
                (DW_AT_ABSTRACT_ORIGIN, DW_FORM_REF4),
                (0x11, DW_FORM_ADDR),
                (0x12, DW_FORM_UDATA),
                (DW_AT_FRAME_BASE, DW_FORM_EXPRLOC),
            ],
        ); // concrete subprogram -> abstract
        push_abbrev(&mut abbrev, 8, DW_TAG_INLINED_SUBROUTINE, true, &[]);
        push_abbrev(
            &mut abbrev,
            9,
            0x34,
            false,
            &[(DW_AT_ABSTRACT_ORIGIN, DW_FORM_REF4), (0x02, DW_FORM_EXPRLOC)],
        ); // concrete inlined variable
        abbrev.push(0);

        let mut body = Vec::new();
        // CU DIE at unit offset 11
        push_uleb(&mut body, 1);
        body.extend_from_slice(b"origin.c\0");

        // int base_type
        let int_off = (11 + body.len()) as u32;
        push_uleb(&mut body, 2);
        body.extend_from_slice(b"int\0");
        body.push(4);
        body.push(5); // DW_ATE_signed

        // Declaration subprogram [3]
        let decl_off = (11 + body.len()) as u32;
        push_uleb(&mut body, 3);
        body.extend_from_slice(b"compute\0");
        body.extend_from_slice(&int_off.to_le_bytes());
        // formal_parameter [4]
        push_uleb(&mut body, 4);
        body.extend_from_slice(b"x\0");
        body.extend_from_slice(&int_off.to_le_bytes());
        body.push(0); // end decl children

        // Intermediate abstract subprogram [5] -> specification [3]
        let mid_off = (11 + body.len()) as u32;
        push_uleb(&mut body, 5);
        body.extend_from_slice(&decl_off.to_le_bytes());
        // Abstract variable [6]
        let abs_var_off = (11 + body.len()) as u32;
        push_uleb(&mut body, 6);
        body.extend_from_slice(b"tmp\0");
        body.extend_from_slice(&int_off.to_le_bytes());
        body.push(0); // end mid children

        // Concrete subprogram [7] -> abstract_origin [5]
        push_uleb(&mut body, 7);
        body.extend_from_slice(&mid_off.to_le_bytes());
        body.extend_from_slice(&0x401000u64.to_le_bytes());
        push_uleb(&mut body, 0x20);
        // frame_base = DW_OP_call_frame_cfa (0x9c)
        push_uleb(&mut body, 1);
        body.push(0x9c);
        // inlined_subroutine [8]
        push_uleb(&mut body, 8);
        // concrete variable [9] -> abstract_origin [6], loc = DW_OP_fbreg(-24)
        push_uleb(&mut body, 9);
        body.extend_from_slice(&abs_var_off.to_le_bytes());
        let mut expr = vec![0x91u8]; // DW_OP_fbreg
        push_sleb(&mut expr, -24);
        push_uleb(&mut body, expr.len() as u64);
        body.extend_from_slice(&expr);
        body.push(0); // end inlined_subroutine
        body.push(0); // end concrete subprogram
        body.push(0); // end CU

        let debug_info = finish_cu(&body);
        let elf = mini_elf64(&[(".debug_info", &debug_info), (".debug_abbrev", &abbrev)]);
        let info = read("origin.elf", &elf).expect("origin DWARF reads");

        let f = function(&info, "compute");
        assert_eq!(f.address, 0x401000);
        assert_eq!(f.size, Some(0x20));
        assert_eq!(f.prototype.as_deref(), Some("int compute(int x)"));

        let tmp = local(&info, "compute", "tmp");
        assert_eq!(tmp.ctype.as_deref(), Some("int"));
        assert_eq!(tmp.size, 4);
        // CFA-24 + 8 (x86_64 return address) = -16
        assert_eq!(tmp.offset, -16);
    }

    #[test]
    fn nested_namespaces_and_classes_expose_types_functions_and_statics() {
        const DW_FORM_ADDR: u64 = 0x01;
        const DW_FORM_STRING: u64 = 0x08;
        const DW_FORM_DATA1: u64 = 0x0b;
        const DW_FORM_UDATA: u64 = 0x0f;
        const DW_FORM_REF4: u64 = 0x13;
        const DW_FORM_EXPRLOC: u64 = 0x18;
        const DW_TAG_NAMESPACE: u64 = 0x39;

        let mut abbrev = Vec::new();
        push_abbrev(&mut abbrev, 1, 0x11, true, &[(0x03, DW_FORM_STRING)]); // CU
        push_abbrev(
            &mut abbrev,
            2,
            0x24,
            false,
            &[(0x03, DW_FORM_STRING), (0x0b, DW_FORM_DATA1), (0x3e, DW_FORM_DATA1)],
        ); // base_type
        push_abbrev(&mut abbrev, 3, DW_TAG_NAMESPACE, true, &[(0x03, DW_FORM_STRING)]);
        push_abbrev(
            &mut abbrev,
            4,
            0x02, // DW_TAG_class_type
            true,
            &[(0x03, DW_FORM_STRING), (0x0b, DW_FORM_DATA1)],
        );
        push_abbrev(
            &mut abbrev,
            5,
            0x0d, // DW_TAG_member
            false,
            &[(0x03, DW_FORM_STRING), (0x49, DW_FORM_REF4), (0x38, DW_FORM_DATA1)],
        );
        push_abbrev(
            &mut abbrev,
            6,
            0x2e, // subprogram
            false,
            &[(0x03, DW_FORM_STRING), (0x11, DW_FORM_ADDR), (0x12, DW_FORM_UDATA)],
        );
        push_abbrev(
            &mut abbrev,
            7,
            0x34, // variable
            false,
            &[(0x03, DW_FORM_STRING), (0x49, DW_FORM_REF4), (0x02, DW_FORM_EXPRLOC)],
        );
        abbrev.push(0);

        let mut body = Vec::new();
        push_uleb(&mut body, 1);
        body.extend_from_slice(b"ns.cpp\0");

        let int_off = (11 + body.len()) as u32;
        push_uleb(&mut body, 2);
        body.extend_from_slice(b"int\0");
        body.push(4);
        body.push(5);

        // namespace math
        push_uleb(&mut body, 3);
        body.extend_from_slice(b"math\0");
        // class vec inside namespace math
        push_uleb(&mut body, 4);
        body.extend_from_slice(b"vec\0");
        body.push(4);
        // member x
        push_uleb(&mut body, 5);
        body.extend_from_slice(b"x\0");
        body.extend_from_slice(&int_off.to_le_bytes());
        body.push(0);
        // method nested inside class vec
        push_uleb(&mut body, 6);
        body.extend_from_slice(b"vec_len\0");
        body.extend_from_slice(&0x402000u64.to_le_bytes());
        push_uleb(&mut body, 0x10);
        body.push(0); // end class vec
        // free function inside namespace math
        push_uleb(&mut body, 6);
        body.extend_from_slice(b"helper\0");
        body.extend_from_slice(&0x402100u64.to_le_bytes());
        push_uleb(&mut body, 0x18);
        // global variable inside namespace math
        push_uleb(&mut body, 7);
        body.extend_from_slice(b"ns_counter\0");
        body.extend_from_slice(&int_off.to_le_bytes());
        push_uleb(&mut body, 9);
        body.push(0x03); // DW_OP_addr
        body.extend_from_slice(&0x405000u64.to_le_bytes());
        body.push(0); // end namespace math
        body.push(0); // end CU

        let debug_info = finish_cu(&body);
        let elf = mini_elf64(&[(".debug_info", &debug_info), (".debug_abbrev", &abbrev)]);
        let info = read("ns.elf", &elf).expect("namespace DWARF reads");

        assert_eq!(function(&info, "vec_len").address, 0x402000);
        assert_eq!(function(&info, "helper").address, 0x402100);
        assert_eq!(datum(&info, "ns_counter").address, 0x405000);
        assert!(
            info.types.iter().any(|t| t == "struct vec { int x; };"),
            "{:?}",
            info.types
        );
    }

    #[test]
    fn ranges_only_subprogram_recovers_entry_and_extent() {
        const DW_FORM_STRING: u64 = 0x08;
        const DW_FORM_SEC_OFFSET: u64 = 0x17;
        const DW_AT_RANGES: u64 = 0x55;

        let mut abbrev = Vec::new();
        push_abbrev(&mut abbrev, 1, 0x11, true, &[(0x03, DW_FORM_STRING)]);
        push_abbrev(
            &mut abbrev,
            2,
            0x2e,
            false,
            &[(0x03, DW_FORM_STRING), (DW_AT_RANGES, DW_FORM_SEC_OFFSET)],
        );
        abbrev.push(0);

        let mut body = Vec::new();
        push_uleb(&mut body, 1);
        body.extend_from_slice(b"ranges.c\0");
        push_uleb(&mut body, 2);
        body.extend_from_slice(b"split_fn\0");
        body.extend_from_slice(&0u32.to_le_bytes()); // offset 0 into .debug_ranges
        body.push(0);

        // .debug_ranges: two non-contiguous spans [0x403040, 0x403060) and [0x403010, 0x403020)
        // plus end-of-list (0, 0).
        let mut ranges = Vec::new();
        for addr in [0x403040u64, 0x403060, 0x403010, 0x403020, 0, 0] {
            ranges.extend_from_slice(&addr.to_le_bytes());
        }

        let debug_info = finish_cu(&body);
        let elf = mini_elf64(&[
            (".debug_info", &debug_info),
            (".debug_abbrev", &abbrev),
            (".debug_ranges", &ranges),
        ]);
        let info = read("ranges.elf", &elf).expect("ranges DWARF reads");

        let f = function(&info, "split_fn");
        assert_eq!(f.address, 0x403010);
        assert_eq!(f.size, Some(0x50));
    }

    #[test]
    fn universal_macho_dsym_slice_with_dwarf_is_read() {
        const DW_FORM_ADDR: u64 = 0x01;
        const DW_FORM_STRING: u64 = 0x08;
        const DW_FORM_UDATA: u64 = 0x0f;

        let mut abbrev = Vec::new();
        push_abbrev(&mut abbrev, 1, 0x11, true, &[(0x03, DW_FORM_STRING)]);
        push_abbrev(
            &mut abbrev,
            2,
            0x2e,
            false,
            &[(0x03, DW_FORM_STRING), (0x11, DW_FORM_ADDR), (0x12, DW_FORM_UDATA)],
        );
        abbrev.push(0);

        let mut body = Vec::new();
        push_uleb(&mut body, 1);
        body.extend_from_slice(b"macho.c\0");
        push_uleb(&mut body, 2);
        body.extend_from_slice(b"macho_fn\0");
        body.extend_from_slice(&0x0001_0000_1200_u64.to_le_bytes());
        push_uleb(&mut body, 0x30);
        body.push(0);

        let debug_info = finish_cu(&body);
        let slice0 = mini_macho64(&[]); // slice without DWARF
        let slice1 = mini_macho64(&[("__debug_info", &debug_info), ("__debug_abbrev", &abbrev)]);

        // Build a universal Mach-O (big-endian FatHeader + 2 FatArch entries).
        let header_size = 8 + 2 * 20;
        let off0 = header_size as u32;
        let off1 = off0 + slice0.len() as u32;
        let mut fat = Vec::with_capacity(off1 as usize + slice1.len());
        fat.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat.extend_from_slice(&2u32.to_be_bytes());
        // arch 0: arm64 (no DWARF)
        fat.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        fat.extend_from_slice(&0u32.to_be_bytes());
        fat.extend_from_slice(&off0.to_be_bytes());
        fat.extend_from_slice(&(slice0.len() as u32).to_be_bytes());
        fat.extend_from_slice(&0u32.to_be_bytes());
        // arch 1: x86_64 (with DWARF)
        fat.extend_from_slice(&0x0100_0007u32.to_be_bytes());
        fat.extend_from_slice(&3u32.to_be_bytes());
        fat.extend_from_slice(&off1.to_be_bytes());
        fat.extend_from_slice(&(slice1.len() as u32).to_be_bytes());
        fat.extend_from_slice(&0u32.to_be_bytes());
        fat.extend_from_slice(&slice0);
        fat.extend_from_slice(&slice1);

        assert!(has_dwarf(&fat));
        assert!(DwarfParser.recognizes(&fat));
        let info = read("prog.dSYM", &fat).expect("universal Mach-O DWARF reads");
        let f = function(&info, "macho_fn");
        assert_eq!(f.address, 0x0001_0000_1200);
        assert_eq!(f.size, Some(0x30));
    }
}
