//! Writing the analysis of a program image for Ghidra (#405).
//!
//! Ghidra is the other workbench a reverse engineer keeps open, so writing
//! the analysis for it hands the work done here — the names, the functions,
//! the types, the comments — across without typing it in again by hand.
//!
//! A `.gzf` ("Ghidra Zip File") as Ghidra itself exports one is the packed
//! native ProgramDB database: an internal storage engine, not a format to
//! write by hand. The format Ghidra reads and writes for interchange is its
//! **XML program format** (`PROGRAM.DTD`), and that is what this writes.
//! Ghidra's XML loader recognises a file by its content — it parses the
//! `<PROGRAM>` and `<PROCESSOR>` elements, not the extension — so the XML
//! written here imports whether it is named `.xml` or `.gzf`. The command
//! keeps the `.gzf` name the issue asks for; the bytes are the XML format.
//!
//! [`build`] reads a [`Binary`] into a [`Gzf`], the program as plain tables,
//! and [`Gzf::encode`] writes the tables as the XML document. The memory
//! bytes cannot live in the XML (Ghidra reads them from a sidecar), so they
//! are gathered into [`Gzf::bytes`], which the caller writes beside the XML
//! as `<name>.bytes`; each `MEMORY_CONTENTS` names that file and the offset
//! its section's bytes start at. The encoding is written out here by hand,
//! as the BinExport wire format is (#399) and the DWARF sections are
//! (#402): an element, an attribute, the escaping of a name.
//!
//! What the document holds:
//!
//! - the *program* — its name, its file, its image base — and its
//!   *processor*: the SLEIGH language id and compiler spec the image is
//!   read as, so Ghidra opens it under the right architecture;
//! - the *memory map*, one section a block, with the bytes of the file
//!   behind it and the permissions it is mapped with; a section the file
//!   holds no bytes for (`.bss`) is an uninitialized block. The container's
//!   debug and symbol sections, which the loader keeps out of memory, are
//!   left out, lest they overlap one another at the zero address they sit
//!   at;
//! - the *code* ranges, which Ghidra disassembles on import;
//! - the *data types* the image is read with — every structure, union,
//!   enumeration and typedef the store holds, the project's among them,
//!   each member at the offset the layout gives it;
//! - one *function* a function, at its entry, under the name the analysis
//!   gives it or the analyst's rename, with the return type of the
//!   analyst's prototype when one is recorded and the lift's own otherwise,
//!   and the extent of its body. The analyst's whole prototype travels as
//!   the type-information comment Ghidra parses on import, so the names and
//!   types they gave the parameters are set too, not just the return;
//! - the *symbol table* — the functions, the data and the imports — and the
//!   *comments* the analyst wrote, and the program's *entry point*.
//!
//! What the image does not say is left out: there is no stack frame for a
//! function (the lift's registers and slots are not a frame Ghidra reads),
//! no register variables, and no line information. A bit-field is written
//! as the integer that holds it, at its byte offset: the XML format has no
//! spelling for a field's bit place. A type Ghidra's parser cannot resolve
//! is logged and skipped on import, not fatal — the program still loads.

use std::collections::BTreeMap;

use ag_engine::platform::Os;
use ag_engine::types::{Definition, Prim, Type, TypeStore};

use crate::{Binary, Bitness, DataSymbol, Function, SectionInfo};

// ---------------------------------------------------------------------
// The program, as plain tables.

/// The analyst's words a file is written with, over the image's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes {
    /// The analyst's names, by address: a rename is the name the function
    /// or the datum is written with, so the names Ghidra shows are the ones
    /// the analysis reads.
    pub names: BTreeMap<u64, String>,
    /// The analyst's comments, by address: the text, and whether it stands
    /// above the address (`true`) or beside it (`false`).
    pub comments: BTreeMap<u64, (String, bool)>,
}

/// The byte order the target reads its bytes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    /// The least significant byte first.
    #[default]
    Little,
    /// The most significant byte first.
    Big,
}

/// Where a section's bytes sit in the sidecar: the offset they start at,
/// and how many of them there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contents {
    /// The offset in the `.bytes` sidecar.
    pub offset: u64,
    /// How many bytes the file holds for the section.
    pub length: u64,
}

/// One memory block: a section of the image, mapped at its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemSection {
    /// The section's name, as the container spells it.
    pub name: String,
    /// The address it maps to.
    pub start: u64,
    /// Its size in memory.
    pub length: u64,
    /// Its permissions, as Ghidra spells them: `r`, `rw`, `rx`, `rwx`.
    pub permissions: String,
    /// The bytes behind it, when the file holds any; `None` for a section
    /// that lives in memory only, which Ghidra leaves uninitialized.
    pub contents: Option<Contents>,
}

/// Where a name came from, as Ghidra's symbol table records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The analysis read it out of the image.
    Analysis,
    /// The analyst wrote it.
    UserDefined,
    /// The run-time loader fills it: an import.
    Imported,
}

/// One symbol of the symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The address it stands at.
    pub address: u64,
    /// The name it stands under.
    pub name: String,
    /// Whether it is global rather than local to a function.
    pub global: bool,
    /// Where the name came from.
    pub source: Source,
    /// Whether it is the primary name at its address.
    pub primary: bool,
    /// The mangled name, when the name was demangled and differs from it.
    pub mangled: Option<String>,
}

/// A return type: the C spelling Ghidra's parser reads, and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetType {
    /// The type, as Ghidra spells it: `int`, `char *`, `point`.
    pub datatype: String,
    /// Its size in bytes; 0 for `void`.
    pub size: u64,
}

/// One function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Func {
    /// The entry address.
    pub entry: u64,
    /// The name it stands under.
    pub name: String,
    /// Whether it is a library function rather than the program's own.
    pub library: bool,
    /// The return type, when the analyst or the lift gives one.
    pub ret: Option<RetType>,
    /// The analyst's prototype, as the C declaration they wrote, when one
    /// is recorded: the whole signature, which Ghidra parses on import.
    pub prototype: Option<String>,
    /// The body, as inclusive address ranges.
    pub body: Vec<(u64, u64)>,
}

/// Where a comment stands against its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// Above the address, before the instruction.
    Pre,
    /// Beside the address, at the end of the line.
    Eol,
}

/// One comment the analyst wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The address it is on.
    pub address: u64,
    /// Where it stands.
    pub kind: CommentKind,
    /// Its text.
    pub text: String,
}

/// One member of a structure or union, as the layout places it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its byte offset in the composite.
    pub offset: u64,
    /// Its name; `None` for an unnamed member.
    pub name: Option<String>,
    /// Its type, as Ghidra spells it.
    pub datatype: String,
    /// Its size in bytes.
    pub size: u64,
}

/// One enumerator of an enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumEntry {
    /// Its name.
    pub name: String,
    /// Its value.
    pub value: i64,
}

/// One data type the store defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataType {
    /// A structure (or a C++ class, which Ghidra reads as one).
    Structure {
        /// Its name.
        name: String,
        /// Its size in bytes.
        size: u64,
        /// Its members, in layout order.
        members: Vec<Member>,
    },
    /// A union.
    Union {
        /// Its name.
        name: String,
        /// Its size in bytes.
        size: u64,
        /// Its members, in layout order.
        members: Vec<Member>,
    },
    /// An enumeration.
    Enum {
        /// Its name.
        name: String,
        /// The size of the integer it is held in.
        size: u64,
        /// Its enumerators, in order.
        entries: Vec<EnumEntry>,
    },
    /// A typedef: a name for another type.
    Typedef {
        /// The name.
        name: String,
        /// The type it names, as Ghidra spells it.
        target: String,
    },
}

/// The program of one image, as the tables the XML is written from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gzf {
    /// The program's name: the binary's file name.
    pub name: String,
    /// The path of the binary it was read from.
    pub exe_path: String,
    /// The image base.
    pub image_base: u64,
    /// The processor's name: the first field of the language id.
    pub processor: String,
    /// The language provider: the SLEIGH language id and compiler spec,
    /// `x86:LE:64:default:gcc`.
    pub provider: String,
    /// The byte order.
    pub endian: Endian,
    /// The width of an address in bits: 16, 32 or 64.
    pub address_size: u32,
    /// When the file was written, in seconds since the Unix epoch.
    pub timestamp: i64,
    /// The name of the `.bytes` sidecar the memory contents point at.
    pub bytes_name: String,
    /// The memory map, in the container's order.
    pub sections: Vec<MemSection>,
    /// The bytes of the sidecar, gathered from the sections.
    pub bytes: Vec<u8>,
    /// The code ranges, as inclusive `(start, end)` addresses.
    pub code_blocks: Vec<(u64, u64)>,
    /// The symbol table, in address order.
    pub symbols: Vec<Symbol>,
    /// The functions, in address order.
    pub functions: Vec<Func>,
    /// The analyst's comments, in address order.
    pub comments: Vec<Comment>,
    /// The program's entry points.
    pub entry_points: Vec<u64>,
    /// The data types the store defines.
    pub data_types: Vec<DataType>,
}

// ---------------------------------------------------------------------
// Reading the image into the tables.

/// Read the image into the tables of a Ghidra XML program.
///
/// `name` is the binary's file name, which names the program. `bytes_name`
/// is the file name of the `.bytes` sidecar the caller writes beside the
/// XML, which the memory contents point at. The `notes` are the analyst's
/// renames and comments; the types and the prototypes are the image's own,
/// which a project has already been read into.
pub fn build(binary: &Binary, name: &str, bytes_name: &str, notes: &Notes) -> Gzf {
    let store = binary.types();
    let language = binary.language();
    let address_size = Bitness::of_language(language)
        .map(|bitness| bitness.bits())
        .unwrap_or(64);
    let endian = if language.split(':').nth(1) == Some("BE") {
        Endian::Big
    } else {
        Endian::Little
    };
    let processor = language.split(':').next().unwrap_or("").to_string();
    let provider = language_provider(language, binary.platform().map(|platform| platform.os));
    let image_base = binary
        .base()
        .or_else(|| binary.sections().iter().map(|section| section.vma).min())
        .unwrap_or(0);

    let mut functions: Vec<&Function> = binary.functions().iter().collect();
    functions.sort_by_key(|function| function.address);
    functions.dedup_by_key(|function| function.address);

    let return_types: BTreeMap<u64, Type> = functions
        .iter()
        .filter_map(|function| {
            Some((
                function.address,
                return_type_of(binary, &store, function.address)?,
            ))
        })
        .collect();

    // The memory map, and the sidecar its contents point at.
    let loads_higher = binary.sections().iter().any(|section| section.vma != 0);
    let mut sections = Vec::new();
    let mut bytes = Vec::new();
    for section in binary.sections() {
        if !maps_into_memory(section, loads_higher) {
            continue;
        }
        let contents = binary
            .bytes_at(section.vma, section.size as usize)
            .filter(|held| !held.is_empty())
            .map(|held| {
                let contents = Contents {
                    offset: bytes.len() as u64,
                    length: held.len() as u64,
                };
                bytes.extend_from_slice(&held);
                contents
            });
        sections.push(MemSection {
            name: section.name.clone(),
            start: section.vma,
            length: section.size,
            permissions: permissions_of(section),
            contents,
        });
    }

    let code_blocks = if binary.supports_disassembly() {
        code_blocks_of(binary, &functions)
    } else {
        Vec::new()
    };

    // The symbol table: the functions, the data and the imports.
    let mut symbols = Vec::new();
    for function in &functions {
        symbols.push(symbol_of(binary, notes, function.address, &function.name));
    }
    let mut data: Vec<&DataSymbol> = binary.data_symbols().iter().collect();
    data.sort_by_key(|symbol| symbol.address);
    data.dedup_by_key(|symbol| symbol.address);
    for symbol in data {
        symbols.push(symbol_of(binary, notes, symbol.address, &symbol.name));
    }
    for (slot, import) in binary.imports() {
        symbols.push(Symbol {
            address: *slot,
            name: import.clone(),
            global: true,
            source: Source::Imported,
            primary: true,
            mangled: None,
        });
    }
    symbols.sort_by_key(|symbol| symbol.address);

    // The functions, each with its return type and the extent of its body.
    let mut funcs = Vec::new();
    for (index, function) in functions.iter().enumerate() {
        let address = function.address;
        let next = functions.get(index + 1).map(|next| next.address);
        let name = notes
            .names
            .get(&address)
            .cloned()
            .unwrap_or_else(|| function.name.clone());
        let extent = extent_of(binary, address, next);
        let end = address + extent.unwrap_or(1) - 1;
        let ret = return_types.get(&address).map(|ty| RetType {
            datatype: ghidra_datatype(ty, &store),
            size: size_of(ty, &store),
        });
        funcs.push(Func {
            entry: address,
            name,
            library: false,
            ret,
            prototype: prototype_of(binary, address),
            body: vec![(address, end)],
        });
    }

    let comments = notes
        .comments
        .iter()
        .map(|(address, (text, above))| Comment {
            address: *address,
            kind: if *above {
                CommentKind::Pre
            } else {
                CommentKind::Eol
            },
            text: text.clone(),
        })
        .collect();

    let entry_points = binary.entry().into_iter().collect();
    let data_types = data_types_of(&store);

    Gzf {
        name: name.to_string(),
        exe_path: name.to_string(),
        image_base,
        processor,
        provider,
        endian,
        address_size,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0),
        bytes_name: bytes_name.to_string(),
        sections,
        bytes,
        code_blocks,
        symbols,
        functions: funcs,
        comments,
        entry_points,
        data_types,
    }
}

/// The symbol for the function or datum at `address`: the analyst's rename
/// when one is recorded, the image's own name otherwise, and the mangled
/// name beside it when the name was demangled.
fn symbol_of(binary: &Binary, notes: &Notes, address: u64, name: &str) -> Symbol {
    let renamed = notes.names.contains_key(&address);
    let name = notes
        .names
        .get(&address)
        .cloned()
        .unwrap_or_else(|| name.to_string());
    let mangled = binary
        .mangled_name(address)
        .filter(|mangled| *mangled != name)
        .map(str::to_string);
    Symbol {
        address,
        name,
        global: true,
        source: if renamed {
            Source::UserDefined
        } else {
            Source::Analysis
        },
        primary: true,
        mangled,
    }
}

/// The language provider Ghidra reads: the SLEIGH language id and the
/// compiler spec, `x86:LE:64:default:gcc`. The engine's id already carries
/// the spec as its fifth field; an id that stops at four is given one the
/// platform implies — `windows` for Windows, `gcc` for x86, `default`
/// elsewhere, which every language has.
fn language_provider(language: &str, os: Option<Os>) -> String {
    if language.split(':').count() >= 5 {
        return language.to_string();
    }
    let arch = language
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let spec = match os {
        Some(Os::Windows) => "windows",
        _ if arch == "x86" => "gcc",
        _ => "default",
    };
    format!("{language}:{spec}")
}

/// Whether a section is mapped into the program's memory. A container's
/// debug and symbol sections are not loaded: they sit at address zero,
/// the place the loader keeps its metadata out of memory, so they are left
/// out — mapped, they would overlap one another at zero. A section at zero
/// is kept when it holds code (a raw image is one such section, loaded at
/// its base) or when nothing loads higher (zero is then the image's base).
fn maps_into_memory(section: &SectionInfo, loads_higher: bool) -> bool {
    section.size != 0 && !(section.vma == 0 && !section.executable && loads_higher)
}

/// The permissions a section is mapped with: code is read and execute,
/// the writable data is read and write, the rest is read. The container's
/// section table says which sections hold code but not which hold writable
/// data, so the data is known by its name — the initialised and zero-filled
/// data, the global offset table the loader fills, the dynamic table — and
/// the other non-code sections (the constant pools, the symbol and string
/// tables, the notes, the unwind tables) are read-only.
fn permissions_of(section: &SectionInfo) -> String {
    if section.executable {
        return "rx".to_string();
    }
    let name = section.name.to_ascii_lowercase();
    if name.contains("rodata") || name.contains("rdata") || name.contains("__const") {
        return "r".to_string();
    }
    if name.contains("data")
        || name.contains("bss")
        || name.contains("got")
        || name.contains("dynamic")
    {
        return "rw".to_string();
    }
    "r".to_string()
}

/// The code ranges: every instruction the disassembly reaches, gathered
/// into the contiguous runs Ghidra disassembles on import, each an
/// inclusive `(start, end)`.
fn code_blocks_of(binary: &Binary, functions: &[&Function]) -> Vec<(u64, u64)> {
    let mut instructions: Vec<(u64, u64)> = Vec::new();
    for function in functions {
        let Some(disassembly) = binary.disassembly(function.address) else {
            continue;
        };
        for block in &disassembly.blocks {
            for instruction in &block.instructions {
                instructions.push((instruction.address, instruction.bytes.len() as u64));
            }
        }
    }
    instructions.sort_by_key(|(address, _)| *address);
    instructions.dedup_by_key(|(address, _)| *address);

    let mut blocks = Vec::new();
    let mut run: Option<(u64, u64)> = None;
    for (address, length) in instructions {
        let end = address + length;
        match run {
            Some((start, previous)) if previous == address => run = Some((start, end)),
            Some((start, previous)) => {
                blocks.push((start, previous - 1));
                run = Some((address, end));
            }
            None => run = Some((address, end)),
        }
    }
    if let Some((start, end)) = run {
        blocks.push((start, end - 1));
    }
    blocks
}

/// The data types the store defines: every structure, union, enumeration
/// and typedef, in the store's order. The primitives are Ghidra's own
/// built-ins, so they are not written; a type that names another finds it
/// among these, as Ghidra's reader resolves them in two passes.
fn data_types_of(store: &TypeStore) -> Vec<DataType> {
    let mut out = Vec::new();
    for key in store.keys() {
        match store.get(key) {
            Some(Definition::Struct(_)) => out.push(composite_of(key, false, store)),
            Some(Definition::Union(_)) => out.push(composite_of(key, true, store)),
            Some(Definition::Enum(enumeration)) => {
                let size = enumeration
                    .underlying
                    .layout(store.model())
                    .map(|(size, _)| size)
                    .unwrap_or(4);
                out.push(DataType::Enum {
                    name: definition_name(key, store),
                    size,
                    entries: enumeration
                        .values
                        .iter()
                        .map(|(name, value)| EnumEntry {
                            name: name.clone(),
                            value: *value,
                        })
                        .collect(),
                });
            }
            Some(Definition::Typedef(inner)) => out.push(DataType::Typedef {
                name: key.clone(),
                target: ghidra_datatype(inner, store),
            }),
            None => {}
        }
    }
    out
}

/// A structure or union as the layout places it: its name, its size, and
/// its members at their offsets. A definition with no body is written with
/// no members, a declaration of its size alone.
fn composite_of(key: &str, union: bool, store: &TypeStore) -> DataType {
    let name = definition_name(key, store);
    let layout = store.layout(key);
    let size = layout.map(|layout| layout.size).unwrap_or(0);
    let members = layout
        .map(|layout| {
            layout
                .fields
                .iter()
                .map(|field| Member {
                    offset: field.offset,
                    name: field.name.clone(),
                    datatype: ghidra_datatype(&field.ty, store),
                    size: field.size,
                })
                .collect()
        })
        .unwrap_or_default();
    if union {
        DataType::Union {
            name,
            size,
            members,
        }
    } else {
        DataType::Structure {
            name,
            size,
            members,
        }
    }
}

/// The name a definition goes by in Ghidra: the tag of a structure, union
/// or enumeration (`point` of `struct point`), the name of a typedef, and
/// the last word of the key for an anonymous one.
fn definition_name(key: &str, store: &TypeStore) -> String {
    let tag = match store.get(key) {
        Some(Definition::Struct(composite)) | Some(Definition::Union(composite)) => {
            composite.tag.clone()
        }
        Some(Definition::Enum(enumeration)) => enumeration.tag.clone(),
        Some(Definition::Typedef(_)) => return key.to_string(),
        None => None,
    };
    tag.unwrap_or_else(|| key.split(' ').next_back().unwrap_or(key).to_string())
}

/// A type as Ghidra's parser reads it: a primitive by its built-in name, a
/// pointer as `T *`, an array as `T[n]`, a name by the definition it names.
/// A function type used as a value is a callback, written as a pointer.
fn ghidra_datatype(ty: &Type, store: &TypeStore) -> String {
    match ty {
        Type::Prim(prim) => prim_name(*prim).to_string(),
        Type::Pointer(inner) | Type::BasedPointer { pointee: inner, .. } => {
            format!("{} *", ghidra_datatype(inner, store))
        }
        Type::Array(inner, Some(count)) => {
            format!("{}[{}]", ghidra_datatype(inner, store), count)
        }
        Type::Array(inner, None) => format!("{}[]", ghidra_datatype(inner, store)),
        Type::Function { .. } => "pointer".to_string(),
        Type::Named(key) => definition_name(key, store),
    }
}

/// A primitive by the name Ghidra's built-in data types go by. The sized
/// integers are written as the C types of their width and signedness,
/// which every Ghidra program has, rather than the `int32_t` typedefs that
/// only some do.
fn prim_name(prim: Prim) -> &'static str {
    match prim {
        Prim::Void => "void",
        Prim::Bool => "bool",
        Prim::Char | Prim::SChar | Prim::Int8 => "char",
        Prim::UChar | Prim::UInt8 => "uchar",
        Prim::Short | Prim::Int16 => "short",
        Prim::UShort | Prim::UInt16 => "ushort",
        Prim::Int | Prim::Int32 => "int",
        Prim::UInt | Prim::UInt32 => "uint",
        Prim::Long => "long",
        Prim::ULong => "ulong",
        Prim::LongLong | Prim::Int64 => "longlong",
        Prim::ULongLong | Prim::UInt64 => "ulonglong",
        Prim::Float => "float",
        Prim::Double => "double",
        Prim::LongDouble => "longdouble",
        Prim::WChar => "wchar_t",
        Prim::SizeT => "size_t",
        Prim::SSizeT => "ssize_t",
        Prim::IntPtr => "intptr_t",
        Prim::UIntPtr => "uintptr_t",
        Prim::PtrDiff => "ptrdiff_t",
    }
}

/// The size of a type in bytes, as the platform lays it out: 0 for `void`
/// and for a name the store does not define.
fn size_of(ty: &Type, store: &TypeStore) -> u64 {
    match ty {
        Type::Prim(prim) => prim
            .layout(store.model())
            .map(|(size, _)| size)
            .unwrap_or(0),
        Type::Pointer(_) | Type::BasedPointer { .. } | Type::Function { .. } => {
            store.model().pointer
        }
        Type::Array(inner, Some(count)) => size_of(inner, store).saturating_mul(*count),
        Type::Array(_, None) => 0,
        Type::Named(key) => match store.get(key) {
            Some(Definition::Struct(_)) | Some(Definition::Union(_)) => {
                store.layout(key).map(|layout| layout.size).unwrap_or(0)
            }
            Some(Definition::Enum(enumeration)) => enumeration
                .underlying
                .layout(store.model())
                .map(|(size, _)| size)
                .unwrap_or(0),
            Some(Definition::Typedef(inner)) => size_of(inner, store),
            None => 0,
        },
    }
}

/// The return type of the function at `address`: the analyst's prototype
/// when one is recorded, and the lift's own otherwise. `None` when neither
/// gives one.
fn return_type_of(binary: &Binary, store: &TypeStore, address: u64) -> Option<Type> {
    if let Some(prototype) = binary
        .function_properties(address)
        .prototype
        .as_deref()
        .and_then(|text| ag_engine::ctype::parse_prototype(store, text).ok())
    {
        return Some(prototype.ret);
    }
    if !binary.supports_pseudocode() {
        return None;
    }
    let stages = binary.stages(address).ok()?;
    ag_engine::ctype::parse_type(store, &stages.function.return_type).ok()
}

/// The analyst's prototype for the function at `address`, as the C
/// declaration they wrote: the whole signature, parameters and all. Ghidra
/// parses it on import to set the function's signature, so the names and
/// types the analyst gave the parameters travel with it. `None` when the
/// analyst recorded none.
fn prototype_of(binary: &Binary, address: u64) -> Option<String> {
    binary
        .function_properties(address)
        .prototype
        .filter(|text| !text.trim().is_empty())
}

/// How many bytes the function at `address` spans: to where the unwind
/// data says it ends, or to the last instruction the walk reached, capped
/// by the next function and the end of its section. `None` when nothing
/// says where it ends.
fn extent_of(binary: &Binary, address: u64, next: Option<u64>) -> Option<u64> {
    let mut end = binary.function_end(address);
    if end.is_none() {
        end = binary.disassembly(address).and_then(|disassembly| {
            disassembly
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .map(|instruction| instruction.address + instruction.bytes.len() as u64)
                .max()
        });
    }
    let mut end = end.unwrap_or(u64::MAX);
    if let Some(next) = next {
        end = end.min(next);
    }
    if let Some(section) = binary.section_of(address) {
        end = end.min(section.vma.saturating_add(section.size));
    }
    (end > address).then_some(end - address)
}

// ---------------------------------------------------------------------
// Writing the tables as the XML document.

/// An address as Ghidra spells it: hexadecimal, with no `0x`.
fn addr(address: u64) -> String {
    format!("{address:x}")
}

/// The attributes of an element, each a name and a value, in the order
/// they are written. The values are owned so a number can be formatted
/// into one and passed beside the borrowed names.
#[derive(Default)]
struct Attrs(Vec<(String, String)>);

impl Attrs {
    fn new() -> Self {
        Attrs(Vec::new())
    }
    fn add(mut self, name: &str, value: impl Into<String>) -> Self {
        self.0.push((name.to_string(), value.into()));
        self
    }
    fn add_opt(self, name: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(value) => self.add(name, value),
            None => self,
        }
    }
}

/// The XML document as it is written: elements indented four spaces a
/// level, as Ghidra's own writer indents them.
struct Xml {
    out: String,
    depth: usize,
}

impl Xml {
    fn new() -> Self {
        Xml {
            out: String::new(),
            depth: 0,
        }
    }
    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.out.push_str("    ");
        }
    }
    fn pi(&mut self, target: &str, data: &str) {
        self.out.push_str(&format!("<?{target} {data}?>\n"));
    }
    fn attributes(&mut self, attrs: &Attrs) {
        for (name, value) in &attrs.0 {
            self.out.push(' ');
            self.out.push_str(name);
            self.out.push_str("=\"");
            self.out.push_str(&escape_attr(value));
            self.out.push('"');
        }
    }
    fn start(&mut self, name: &str, attrs: &Attrs) {
        self.indent();
        self.out.push('<');
        self.out.push_str(name);
        self.attributes(attrs);
        self.out.push_str(">\n");
        self.depth += 1;
    }
    fn end(&mut self, name: &str) {
        self.depth -= 1;
        self.indent();
        self.out.push_str(&format!("</{name}>\n"));
    }
    fn empty(&mut self, name: &str, attrs: &Attrs) {
        self.indent();
        self.out.push('<');
        self.out.push_str(name);
        self.attributes(attrs);
        self.out.push_str(" />\n");
    }
    fn text(&mut self, name: &str, attrs: &Attrs, text: &str) {
        self.indent();
        self.out.push('<');
        self.out.push_str(name);
        self.attributes(attrs);
        self.out.push('>');
        self.out.push_str(&escape_text(text));
        self.out.push_str(&format!("</{name}>\n"));
    }
}

/// A string as an attribute value: the markup characters escaped, so a
/// C++ name's `<` and `>` and `&` do not break the document.
fn escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if is_xml_char(c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// A string as element text: the markup characters escaped.
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if is_xml_char(c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// Whether a character may stand in an XML 1.0 document: the tab, the
/// newline and the carriage return, and the printable ranges. The other
/// control characters may not, and are dropped.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}'
        | '\u{10000}'..='\u{10ffff}')
}

impl Gzf {
    /// The XML document, as the bytes of the file Ghidra imports.
    pub fn encode(&self) -> Vec<u8> {
        let mut x = Xml::new();
        x.pi("xml", "version=\"1.0\" encoding=\"UTF-8\"");
        // The version Ghidra's reader checks: without it the file is read
        // as the unsupported 2.0 XML and refused.
        x.pi("program_dtd", "version=\"1\"");

        x.start(
            "PROGRAM",
            &Attrs::new()
                .add("NAME", &self.name)
                .add("EXE_PATH", &self.exe_path)
                .add("IMAGE_BASE", addr(self.image_base)),
        );

        let tool = format!("AdmiralGrace {}", env!("CARGO_PKG_VERSION"));
        x.empty(
            "INFO_SOURCE",
            &Attrs::new()
                .add("TOOL", tool)
                .add("TIMESTAMP", format_timestamp(self.timestamp)),
        );

        let endian = match self.endian {
            Endian::Little => "little",
            Endian::Big => "big",
        };
        x.empty(
            "PROCESSOR",
            &Attrs::new()
                .add("NAME", &self.processor)
                .add("LANGUAGE_PROVIDER", &self.provider)
                .add("ENDIAN", endian),
        );
        let compiler = self.provider.rsplit(':').next().unwrap_or("default");
        x.empty("COMPILER", &Attrs::new().add("NAME", compiler));

        if !self.data_types.is_empty() {
            x.start("DATATYPES", &Attrs::new());
            for data_type in &self.data_types {
                write_data_type(&mut x, data_type);
            }
            x.end("DATATYPES");
        }

        x.start("MEMORY_MAP", &Attrs::new());
        for section in &self.sections {
            let attrs = Attrs::new()
                .add("NAME", &section.name)
                .add("START_ADDR", addr(section.start))
                .add("LENGTH", section.length.to_string())
                .add("PERMISSIONS", &section.permissions);
            x.start("MEMORY_SECTION", &attrs);
            if let Some(contents) = &section.contents {
                x.empty(
                    "MEMORY_CONTENTS",
                    &Attrs::new()
                        .add("FILE_NAME", &self.bytes_name)
                        .add("FILE_OFFSET", contents.offset.to_string())
                        .add("LENGTH", contents.length.to_string()),
                );
            }
            x.end("MEMORY_SECTION");
        }
        x.end("MEMORY_MAP");

        if !self.code_blocks.is_empty() {
            x.start("CODE", &Attrs::new());
            for (start, end) in &self.code_blocks {
                x.empty(
                    "CODE_BLOCK",
                    &Attrs::new()
                        .add("START", addr(*start))
                        .add("END", addr(*end)),
                );
            }
            x.end("CODE");
        }

        if !self.comments.is_empty() {
            x.start("COMMENTS", &Attrs::new());
            for comment in &self.comments {
                let kind = match comment.kind {
                    CommentKind::Pre => "pre",
                    CommentKind::Eol => "end-of-line",
                };
                x.text(
                    "COMMENT",
                    &Attrs::new()
                        .add("ADDRESS", addr(comment.address))
                        .add("TYPE", kind),
                    &comment.text,
                );
            }
            x.end("COMMENTS");
        }

        if !self.entry_points.is_empty() {
            x.start("PROGRAM_ENTRY_POINTS", &Attrs::new());
            for entry in &self.entry_points {
                x.empty(
                    "PROGRAM_ENTRY_POINT",
                    &Attrs::new().add("ADDRESS", addr(*entry)),
                );
            }
            x.end("PROGRAM_ENTRY_POINTS");
        }

        if !self.symbols.is_empty() {
            x.start("SYMBOL_TABLE", &Attrs::new());
            for symbol in &self.symbols {
                let source = match symbol.source {
                    Source::Analysis => "ANALYSIS",
                    Source::UserDefined => "USER_DEFINED",
                    Source::Imported => "IMPORTED",
                };
                let attrs = Attrs::new()
                    .add("ADDRESS", addr(symbol.address))
                    .add("NAME", &symbol.name)
                    .add("TYPE", if symbol.global { "global" } else { "local" })
                    .add("SOURCE_TYPE", source)
                    .add("PRIMARY", if symbol.primary { "y" } else { "n" })
                    .add_opt("MANGLED", symbol.mangled.as_deref());
                x.empty("SYMBOL", &attrs);
            }
            x.end("SYMBOL_TABLE");
        }

        if !self.functions.is_empty() {
            x.start("FUNCTIONS", &Attrs::new());
            for function in &self.functions {
                let attrs = Attrs::new()
                    .add("ENTRY_POINT", addr(function.entry))
                    .add("NAME", &function.name)
                    .add("LIBRARY_FUNCTION", if function.library { "y" } else { "n" });
                x.start("FUNCTION", &attrs);
                if let Some(ret) = &function.ret {
                    x.empty(
                        "RETURN_TYPE",
                        &Attrs::new()
                            .add("DATATYPE", &ret.datatype)
                            .add("DATATYPE_NAMESPACE", "/")
                            .add("SIZE", ret.size.to_string()),
                    );
                }
                for (start, end) in &function.body {
                    x.empty(
                        "ADDRESS_RANGE",
                        &Attrs::new()
                            .add("START", addr(*start))
                            .add("END", addr(*end)),
                    );
                }
                if let Some(prototype) = &function.prototype {
                    x.text("TYPEINFO_CMT", &Attrs::new(), prototype);
                }
                x.end("FUNCTION");
            }
            x.end("FUNCTIONS");
        }

        x.end("PROGRAM");
        x.out.into_bytes()
    }
}

/// One data type, as the element its kind is.
fn write_data_type(x: &mut Xml, data_type: &DataType) {
    match data_type {
        DataType::Structure {
            name,
            size,
            members,
        } => {
            x.start(
                "STRUCTURE",
                &Attrs::new()
                    .add("NAME", name)
                    .add("NAMESPACE", "/")
                    .add("SIZE", size.to_string()),
            );
            for member in members {
                write_member(x, member);
            }
            x.end("STRUCTURE");
        }
        DataType::Union {
            name,
            size,
            members,
        } => {
            x.start(
                "UNION",
                &Attrs::new()
                    .add("NAME", name)
                    .add("NAMESPACE", "/")
                    .add("SIZE", size.to_string()),
            );
            for member in members {
                write_member(x, member);
            }
            x.end("UNION");
        }
        DataType::Enum {
            name,
            size,
            entries,
        } => {
            x.start(
                "ENUM",
                &Attrs::new()
                    .add("NAME", name)
                    .add("NAMESPACE", "/")
                    .add("SIZE", size.to_string()),
            );
            for entry in entries {
                x.empty(
                    "ENUM_ENTRY",
                    &Attrs::new()
                        .add("NAME", &entry.name)
                        .add("VALUE", entry.value.to_string())
                        .add("COMMENT", ""),
                );
            }
            x.end("ENUM");
        }
        DataType::Typedef { name, target } => {
            x.empty(
                "TYPE_DEF",
                &Attrs::new()
                    .add("NAME", name)
                    .add("NAMESPACE", "/")
                    .add("DATATYPE", target)
                    .add("DATATYPE_NAMESPACE", "/"),
            );
        }
    }
}

/// One member of a structure or union.
fn write_member(x: &mut Xml, member: &Member) {
    x.empty(
        "MEMBER",
        &Attrs::new()
            .add("OFFSET", member.offset.to_string())
            .add("DATATYPE", &member.datatype)
            .add("DATATYPE_NAMESPACE", "/")
            .add_opt("NAME", member.name.as_deref())
            .add("SIZE", member.size.to_string()),
    );
}

/// A timestamp as Ghidra's reader parses it: `EEE MMM dd HH:mm:ss ZZZ
/// yyyy`, in UTC. The reader falls back to the epoch when it cannot parse
/// one, so this is for the creation date it shows, not for the import.
fn format_timestamp(seconds: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (hour, minute, second) = (time / 3600, (time % 3600) / 60, time % 60);
    let (year, month, day) = civil_from_days(days);
    // The Unix epoch, 1970-01-01, was a Thursday: weekday 4 with Sunday 0.
    let weekday = (days + 4).rem_euclid(7) as usize;
    format!(
        "{} {} {day:02} {hour:02}:{minute:02}:{second:02} +0000 {year}",
        WEEKDAYS[weekday],
        MONTHS[(month - 1) as usize],
    )
}

/// The year, month and day of a day count since the Unix epoch, by the
/// civil-from-days algorithm: the era of 400 years, the year within it,
/// the day within the year, and the month and day within that.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(name: &str, vma: u64, executable: bool) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            vma,
            size: 16,
            executable,
            file_offset: None,
            file_size: None,
        }
    }

    #[test]
    fn markup_in_a_name_is_escaped_and_a_quote_only_in_an_attribute() {
        let name = "std::vector<int>&";
        assert_eq!(escape_text(name), "std::vector&lt;int&gt;&amp;");
        assert_eq!(escape_attr("say \"hi\""), "say &quot;hi&quot;");
        assert_eq!(escape_text("\u{1}ok"), "ok");
        assert_eq!(addr(0x401000), "401000");
    }

    #[test]
    fn the_epoch_is_the_thursday_ghidra_parses() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(
            format_timestamp(0),
            "Thu Jan 01 00:00:00 +0000 1970"
        );
        // 2024-02-29 23:59:59 UTC.
        assert_eq!(civil_from_days(19782), (2024, 2, 29));
        assert_eq!(
            format_timestamp(1_709_251_199),
            "Thu Feb 29 23:59:59 +0000 2024"
        );
    }

    #[test]
    fn only_loaded_sections_are_mapped_and_named_for_their_permissions() {
        assert!(!maps_into_memory(&section(".debug", 0, false), true));
        assert!(maps_into_memory(&section(".text", 0, true), true));
        assert!(maps_into_memory(&section(".text", 0x1000, true), true));
        assert_eq!(permissions_of(&section(".text", 0x1000, true)), "rx");
        assert_eq!(permissions_of(&section(".rodata", 0x2000, false)), "r");
        assert_eq!(permissions_of(&section(".bss", 0x3000, false)), "rw");
        assert_eq!(permissions_of(&section(".got.plt", 0x4000, false)), "rw");
    }
}
