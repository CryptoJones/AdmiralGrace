//! Writing the analysis of a program image as DWARF (#402).
//!
//! DWARF is the debug information debuggers read: the names of the
//! functions and the data, where they stand in memory, and the types the
//! analyst gave them. Writing the analysis as DWARF hands the work done
//! here to a debugger — `gdb ./program -ex 'add-symbol-file
//! program.debug'` — without typing it in again by hand.
//!
//! [`build`] reads a [`Binary`] into a [`Dwarf`], the debug information as
//! a tree of plain tables, and [`Dwarf::encode`] writes the tables as the
//! bytes of an ELF file holding the DWARF sections. The format is small
//! and fixed where this writer uses it, so the encoding is written out
//! here by hand, as the BinExport wire format is (#399): a LEB128 integer,
//! an abbreviation, a DIE. The constants are the ones the DWARF 4
//! specification gives.
//!
//! What the file holds:
//!
//! - one *compile unit*, named for the binary, whose producer is this
//!   program;
//! - the *types* the image is read with — the platform's primitives and
//!   every definition the store holds, the project's among them: base
//!   types, pointers, arrays, structures, unions, enumerations, typedefs
//!   and function types, each member at the offset the layout gives it,
//!   bit-fields with their bit place;
//! - one *subprogram* a function, at the address it stands at, under the
//!   name the analysis gives it or the analyst's rename, with the return
//!   type and the parameters of the analyst's prototype when one is
//!   recorded, and of the lift's own signature otherwise;
//! - one *variable* a data symbol, at its address, under the analyst's
//!   type for it when one is marked;
//! - a *symbol table* beside the DWARF, so a reader that reads no DWARF
//!   still finds the names;
//! - an *address range table* (`.debug_aranges`), which names the compile
//!   unit an address belongs to.
//!
//! What the image does not say is left out: there is no line table (the
//! analysis has no source lines), no location for a parameter or a local
//! (the lift's registers and slots are not a frame the debugger reads),
//! and no calling convention (DWARF has no standard spelling for the
//! ones the analyst names). A function the decoder cannot reach keeps
//! its name and address with no extent.

// The constants below keep the DWARF specification's own spellings
// (`DW_TAG_compile_unit`, `DW_AT_name`), so they read against the spec.
#![allow(non_upper_case_globals)]

use std::collections::{BTreeMap, HashMap, HashSet};

use ag_engine::types::{Composite, Definition, Layout, Prim, Type, TypeStore};

use crate::Binary;

// ---------------------------------------------------------------------
// The DWARF 4 constants this writer uses.

/// A tag: what a DIE is.
pub const DW_TAG_array_type: u64 = 0x01;
pub const DW_TAG_class_type: u64 = 0x02;
pub const DW_TAG_enumeration_type: u64 = 0x04;
pub const DW_TAG_formal_parameter: u64 = 0x05;
pub const DW_TAG_member: u64 = 0x0d;
pub const DW_TAG_pointer_type: u64 = 0x0f;
pub const DW_TAG_compile_unit: u64 = 0x11;
pub const DW_TAG_structure_type: u64 = 0x13;
pub const DW_TAG_subroutine_type: u64 = 0x15;
pub const DW_TAG_typedef: u64 = 0x16;
pub const DW_TAG_union_type: u64 = 0x17;
pub const DW_TAG_unspecified_parameters: u64 = 0x18;
pub const DW_TAG_inheritance: u64 = 0x1c;
pub const DW_TAG_subrange_type: u64 = 0x21;
pub const DW_TAG_base_type: u64 = 0x24;
pub const DW_TAG_enumerator: u64 = 0x28;
pub const DW_TAG_subprogram: u64 = 0x2e;
pub const DW_TAG_variable: u64 = 0x34;
pub const DW_TAG_unspecified_type: u64 = 0x3b;

/// An attribute: one fact a DIE carries.
pub const DW_AT_location: u64 = 0x02;
pub const DW_AT_name: u64 = 0x03;
pub const DW_AT_byte_size: u64 = 0x0b;
pub const DW_AT_bit_size: u64 = 0x0d;
pub const DW_AT_low_pc: u64 = 0x11;
pub const DW_AT_high_pc: u64 = 0x12;
pub const DW_AT_language: u64 = 0x13;
pub const DW_AT_const_value: u64 = 0x1c;
pub const DW_AT_producer: u64 = 0x25;
pub const DW_AT_prototyped: u64 = 0x27;
pub const DW_AT_accessibility: u64 = 0x32;
pub const DW_AT_artificial: u64 = 0x34;
pub const DW_AT_count: u64 = 0x37;
pub const DW_AT_data_member_location: u64 = 0x38;
pub const DW_AT_declaration: u64 = 0x3c;
pub const DW_AT_encoding: u64 = 0x3e;
pub const DW_AT_external: u64 = 0x3f;
pub const DW_AT_type: u64 = 0x49;
pub const DW_AT_virtuality: u64 = 0x4c;
pub const DW_AT_main_subprogram: u64 = 0x6a;
pub const DW_AT_data_bit_offset: u64 = 0x6b;
pub const DW_AT_linkage_name: u64 = 0x6e;

/// A form: how an attribute's value is written.
pub const DW_FORM_addr: u64 = 0x01;
pub const DW_FORM_data1: u64 = 0x0b;
pub const DW_FORM_sdata: u64 = 0x0d;
pub const DW_FORM_strp: u64 = 0x0e;
pub const DW_FORM_udata: u64 = 0x0f;
pub const DW_FORM_ref4: u64 = 0x13;
pub const DW_FORM_exprloc: u64 = 0x18;
pub const DW_FORM_flag_present: u64 = 0x19;

/// An encoding: what a base type's bytes mean.
pub const DW_ATE_boolean: u8 = 0x02;
pub const DW_ATE_float: u8 = 0x04;
pub const DW_ATE_signed: u8 = 0x05;
pub const DW_ATE_signed_char: u8 = 0x06;
pub const DW_ATE_unsigned: u8 = 0x07;
pub const DW_ATE_unsigned_char: u8 = 0x08;

/// The language of the compile unit: C11, the C the definitions are read
/// as.
pub const DW_LANG_C11: u8 = 0x1d;

/// `DW_OP_addr`: the address that follows is the variable's own.
const DW_OP_addr: u8 = 0x03;

/// An inheritance's access: the bases the engine lays out are public.
const DW_ACCESS_public: u8 = 0x01;

/// A method's virtuality: it occupies a vtable slot.
const DW_VIRTUALITY_virtual: u8 = 0x01;

// ---------------------------------------------------------------------
// The debug information, as plain tables.

/// The analyst's words a file is written with, over the image's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes {
    /// The analyst's names, by address: a rename is the name the function
    /// or the datum is written with, so the names the debugger shows are
    /// the ones the analysis reads.
    pub names: BTreeMap<u64, String>,
    /// The analyst's types for the data, by address: the type the datum
    /// is written with, as the byte-type marks give it.
    pub data_types: BTreeMap<u64, Type>,
}

/// One attribute's value. The form it is written in follows from what it
/// is: an address in the target's width, a string by its offset in
/// `.debug_str`, a reference by the DIE's offset in the compile unit, a
/// number in LEB128, a flag by its presence alone, a location as the
/// bytes of its expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An address, `DW_FORM_addr`.
    Addr(u64),
    /// A string, `DW_FORM_strp`.
    Str(String),
    /// A reference to another DIE of the unit, by its index in
    /// [`Dwarf::dies`]; `DW_FORM_ref4`.
    Ref(usize),
    /// An unsigned number, `DW_FORM_udata`.
    Unsigned(u64),
    /// A signed number, `DW_FORM_sdata`.
    Signed(i64),
    /// One byte, `DW_FORM_data1`: an encoding, a language, an access.
    Byte(u8),
    /// A flag that is set, `DW_FORM_flag_present`: it takes no bytes.
    Flag,
    /// A location expression, `DW_FORM_exprloc`.
    Block(Vec<u8>),
}

impl Value {
    /// The form this value is written in.
    fn form(&self) -> u64 {
        match self {
            Value::Addr(_) => DW_FORM_addr,
            Value::Str(_) => DW_FORM_strp,
            Value::Ref(_) => DW_FORM_ref4,
            Value::Unsigned(_) => DW_FORM_udata,
            Value::Signed(_) => DW_FORM_sdata,
            Value::Byte(_) => DW_FORM_data1,
            Value::Flag => DW_FORM_flag_present,
            Value::Block(_) => DW_FORM_exprloc,
        }
    }
}

/// One DIE — a debugging information entry: a tag, the attributes it
/// carries, and the place it hangs in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Die {
    /// What the DIE is: a `DW_TAG_…`.
    pub tag: u64,
    /// The DIE this one is a child of, by its index in [`Dwarf::dies`];
    /// `None` for the compile unit, which is the root.
    pub parent: Option<usize>,
    /// The facts it carries, each a `DW_AT_…` and its value, in the order
    /// they are written.
    pub attrs: Vec<(u64, Value)>,
}

impl Die {
    /// The value of the attribute `at`, when the DIE carries it.
    pub fn attr(&self, at: u64) -> Option<&Value> {
        self.attrs
            .iter()
            .find(|(name, _)| *name == at)
            .map(|(_, value)| value)
    }

    /// The name the DIE carries, when it carries one.
    pub fn name(&self) -> Option<&str> {
        match self.attr(DW_AT_name) {
            Some(Value::Str(name)) => Some(name),
            _ => None,
        }
    }
}

/// One symbol of the file's symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The name the symbol stands under.
    pub name: String,
    /// The address it stands at.
    pub address: u64,
    /// How many bytes it spans; 0 when nothing says.
    pub size: u64,
    /// Whether it is a function rather than data.
    pub function: bool,
}

/// The debug information of one image: the DIEs of one compile unit, and
/// the symbols written beside them.
///
/// The DIEs stand in the order they were allocated — a parent before its
/// children, but not always a whole subtree before the next begins; the
/// encoding walks the tree itself, so a definition's members may be
/// allocated after the definitions that follow it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dwarf {
    /// The width of an address in bytes: 4 or 8.
    pub address_size: u8,
    /// Whether the target reads its bytes little-endian first.
    pub little_endian: bool,
    /// The machine, as ELF numbers it: `EM_X86_64`, `EM_386`, `EM_ARM`.
    pub machine: u16,
    /// The DIEs, the compile unit first.
    pub dies: Vec<Die>,
    /// The functions and the data, as the symbol table writes them.
    pub symbols: Vec<Symbol>,
}

/// The tags that name a type, for a reader that counts them.
pub const TYPE_TAGS: &[u64] = &[
    DW_TAG_array_type,
    DW_TAG_base_type,
    DW_TAG_class_type,
    DW_TAG_enumeration_type,
    DW_TAG_pointer_type,
    DW_TAG_structure_type,
    DW_TAG_subroutine_type,
    DW_TAG_typedef,
    DW_TAG_union_type,
    DW_TAG_unspecified_type,
];

/// The shape of an abbreviation: its tag, whether it has children, and its
/// attributes, each an attribute name and the form its value is written in.
type AbbrevShape = (u64, bool, Vec<(u64, u64)>);

// ---------------------------------------------------------------------
// Reading the image into the tables.

/// A function's signature as the analyst or the lift gives it: the return
/// type, the parameters' types and names in order, and whether more
/// arguments follow after them.
struct Signature {
    ret: Type,
    params: Vec<(Type, Option<String>)>,
    variadic: bool,
}

/// Read the image into the DIEs of a DWARF file.
///
/// `name` is the binary's file name, which names the compile unit. The
/// `notes` are the analyst's renames and data types; the types and the
/// prototypes are the image's own, which a project has already been read
/// into.
pub fn build(binary: &Binary, name: &str, notes: &Notes) -> Dwarf {
    let store = binary.types();
    let mut functions: Vec<&crate::Function> = binary.functions().iter().collect();
    functions.sort_by_key(|function| function.address);
    functions.dedup_by_key(|function| function.address);

    let mut builder = Builder {
        binary,
        store: &store,
        address_size: crate::Bitness::of_language(binary.language())
            .map(|bitness| bitness.byte_size() as u8)
            .unwrap_or(8),
        little_endian: !binary
            .language()
            .split(':')
            .nth(1)
            .is_some_and(|e| e == "BE"),
        machine: machine_of(binary.language()),
        dies: Vec::new(),
        symbols: Vec::new(),
        type_dies: HashMap::new(),
        definition_dies: HashMap::new(),
        filled: HashSet::new(),
    };

    // The signatures first: the types they name are written with the
    // store's own, before the functions that refer to them.
    let signatures: BTreeMap<u64, Signature> = functions
        .iter()
        .filter_map(|function| Some((function.address, builder.signature_of(function.address)?)))
        .collect();

    // The compile unit, the root of the tree.
    let unit = builder.die(DW_TAG_compile_unit, None);
    builder.attr(
        unit,
        DW_AT_producer,
        Value::Str(format!("AdmiralGrace {}", env!("CARGO_PKG_VERSION"))),
    );
    builder.attr(unit, DW_AT_language, Value::Byte(DW_LANG_C11));
    builder.attr(unit, DW_AT_name, Value::Str(name.to_string()));

    // The types: the primitives, then every definition the store holds —
    // each allocated its place before any is filled, so a definition that
    // names another stands beside it, not inside it — then the types the
    // signatures and the data name beyond those.
    for prim in Prim::ALL {
        builder.type_die(&Type::Prim(*prim), unit);
    }
    for key in builder.store.keys() {
        builder.allocate_definition(key, unit);
    }
    for key in builder.store.keys().to_vec() {
        builder.fill_definition(&key, unit);
    }
    for signature in signatures.values() {
        builder.type_die(&signature.ret, unit);
        for (ty, _) in &signature.params {
            builder.type_die(ty, unit);
        }
    }
    for ty in notes.data_types.values() {
        builder.type_die(ty, unit);
    }

    // The functions, in address order, each with its parameters.
    for (index, function) in functions.iter().enumerate() {
        let address = function.address;
        let next = functions.get(index + 1).map(|next| next.address);
        let name = notes
            .names
            .get(&address)
            .cloned()
            .unwrap_or_else(|| function.name.clone());
        let subprogram = builder.die(DW_TAG_subprogram, Some(unit));
        builder.attr(subprogram, DW_AT_name, Value::Str(name.clone()));
        if let Some(mangled) = binary.mangled_name(address) {
            if mangled != name {
                builder.attr(
                    subprogram,
                    DW_AT_linkage_name,
                    Value::Str(mangled.to_string()),
                );
            }
        }
        builder.attr(subprogram, DW_AT_external, Value::Flag);
        builder.attr(subprogram, DW_AT_low_pc, Value::Addr(address));
        let extent = builder.extent_of(address, next);
        if let Some(length) = extent {
            builder.attr(subprogram, DW_AT_high_pc, Value::Unsigned(length));
        }
        if name == "main" {
            builder.attr(subprogram, DW_AT_main_subprogram, Value::Flag);
        }
        if let Some(signature) = signatures.get(&address) {
            builder.attr(subprogram, DW_AT_prototyped, Value::Flag);
            if !matches!(signature.ret, Type::Prim(Prim::Void)) {
                let ret = builder.type_die(&signature.ret, unit);
                builder.attr(subprogram, DW_AT_type, Value::Ref(ret));
            }
            for (ty, param_name) in &signature.params {
                let param = builder.die(DW_TAG_formal_parameter, Some(subprogram));
                if let Some(param_name) = param_name {
                    builder.attr(param, DW_AT_name, Value::Str(param_name.clone()));
                }
                let ty = builder.type_die(ty, unit);
                builder.attr(param, DW_AT_type, Value::Ref(ty));
            }
            if signature.variadic {
                builder.die(DW_TAG_unspecified_parameters, Some(subprogram));
            }
        }
        builder.symbols.push(Symbol {
            name: binary
                .mangled_name(address)
                .filter(|_| !notes.names.contains_key(&address))
                .map(str::to_string)
                .unwrap_or(name),
            address,
            size: extent.unwrap_or(0),
            function: true,
        });
    }

    // The data, in address order, each at its address under the analyst's
    // type for it when one is marked.
    let mut data: Vec<&crate::DataSymbol> = binary.data_symbols().iter().collect();
    data.sort_by_key(|symbol| symbol.address);
    data.dedup_by_key(|symbol| symbol.address);
    for symbol in data {
        let name = notes
            .names
            .get(&symbol.address)
            .cloned()
            .unwrap_or_else(|| symbol.name.clone());
        let variable = builder.die(DW_TAG_variable, Some(unit));
        builder.attr(variable, DW_AT_name, Value::Str(name.clone()));
        builder.attr(variable, DW_AT_external, Value::Flag);
        let mut location = vec![DW_OP_addr];
        location.extend_from_slice(&address_bytes(
            symbol.address,
            builder.address_size,
            builder.little_endian,
        ));
        builder.attr(variable, DW_AT_location, Value::Block(location));
        if let Some(ty) = notes.data_types.get(&symbol.address) {
            let ty = builder.type_die(ty, unit);
            builder.attr(variable, DW_AT_type, Value::Ref(ty));
        }
        builder.symbols.push(Symbol {
            name,
            address: symbol.address,
            size: symbol.size,
            function: false,
        });
    }

    Dwarf {
        address_size: builder.address_size,
        little_endian: builder.little_endian,
        machine: builder.machine,
        dies: builder.dies,
        symbols: builder.symbols,
    }
}

/// The machine a language id names, as ELF numbers it: `EM_X86_64`,
/// `EM_386`, `EM_ARM`, `EM_AARCH64`, `EM_MIPS`, `EM_PPC`, `EM_PPC64`,
/// `EM_RISCV`, `EM_MSP430`; `EM_NONE` for a processor this writer has no
/// number for.
fn machine_of(language: &str) -> u16 {
    let processor = language
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let bits = crate::Bitness::of_language(language)
        .map(|bitness| bitness.bits())
        .unwrap_or(64);
    match processor.as_str() {
        "x86" => {
            if bits == 64 {
                62
            } else {
                3
            }
        }
        "arm" => 40,
        "aarch64" => 183,
        "mips" => 8,
        "powerpc" | "ppc" => {
            if bits == 64 {
                21
            } else {
                20
            }
        }
        "riscv" => 243,
        "ti_msp430" => 105,
        _ => 0,
    }
}

/// The builder: the DIEs as they are allocated, and the memo of the types
/// already written, so each distinct type stands once.
struct Builder<'a> {
    binary: &'a Binary,
    store: &'a TypeStore,
    address_size: u8,
    little_endian: bool,
    machine: u16,
    dies: Vec<Die>,
    symbols: Vec<Symbol>,
    /// The DIE of each distinct type, by the type itself.
    type_dies: HashMap<Type, usize>,
    /// The DIE of each definition, by its key.
    definition_dies: HashMap<String, usize>,
    /// The definitions already filled.
    filled: HashSet<usize>,
}

impl Builder<'_> {
    /// Allocate a DIE under `parent`, empty, and give its index.
    fn die(&mut self, tag: u64, parent: Option<usize>) -> usize {
        self.dies.push(Die {
            tag,
            parent,
            attrs: Vec::new(),
        });
        self.dies.len() - 1
    }

    /// Add one attribute to a DIE.
    fn attr(&mut self, die: usize, at: u64, value: Value) {
        self.dies[die].attrs.push((at, value));
    }

    /// The DIE of `ty`, written once: a primitive is a base type, a
    /// pointer, an array or a function type is its own DIE, and a name is
    /// the definition it names. A type that names itself — `struct node`
    /// through its `next` pointer — finds its place already allocated.
    fn type_die(&mut self, ty: &Type, unit: usize) -> usize {
        if let Some(&die) = self.type_dies.get(ty) {
            return die;
        }
        match ty {
            Type::Prim(prim) => {
                let die = if *prim == Prim::Void {
                    // `void` is no base type: it names a type with no
                    // values, as the specification's unspecified type.
                    let die = self.die(DW_TAG_unspecified_type, Some(unit));
                    self.attr(die, DW_AT_name, Value::Str("void".to_string()));
                    die
                } else {
                    let die = self.die(DW_TAG_base_type, Some(unit));
                    self.attr(die, DW_AT_name, Value::Str(prim.spelling().to_string()));
                    if let Some((size, _)) = prim.layout(self.store.model()) {
                        self.attr(die, DW_AT_byte_size, Value::Unsigned(size));
                    }
                    self.attr(die, DW_AT_encoding, Value::Byte(encoding_of(*prim)));
                    die
                };
                self.type_dies.insert(ty.clone(), die);
                die
            }
            Type::Pointer(inner) | Type::BasedPointer { pointee: inner, .. } => {
                // A based pointer is laid out as the platform pointer;
                // the base it is addressed by is an addressing detail
                // DWARF has no spelling for, and is left out.
                let die = self.die(DW_TAG_pointer_type, Some(unit));
                self.type_dies.insert(ty.clone(), die);
                self.attr(
                    die,
                    DW_AT_byte_size,
                    Value::Unsigned(self.store.model().pointer),
                );
                if !matches!(inner.as_ref(), Type::Prim(Prim::Void)) {
                    let pointee = self.type_die(inner, unit);
                    self.attr(die, DW_AT_type, Value::Ref(pointee));
                }
                die
            }
            Type::Array(inner, count) => {
                let die = self.die(DW_TAG_array_type, Some(unit));
                self.type_dies.insert(ty.clone(), die);
                let element = self.type_die(inner, unit);
                self.attr(die, DW_AT_type, Value::Ref(element));
                let subrange = self.die(DW_TAG_subrange_type, Some(die));
                if let Some(count) = count {
                    self.attr(subrange, DW_AT_count, Value::Unsigned(*count));
                }
                die
            }
            Type::Function {
                ret,
                params,
                variadic,
                ..
            } => {
                let die = self.die(DW_TAG_subroutine_type, Some(unit));
                self.type_dies.insert(ty.clone(), die);
                if !matches!(ret.as_ref(), Type::Prim(Prim::Void)) {
                    let ret = self.type_die(ret, unit);
                    self.attr(die, DW_AT_type, Value::Ref(ret));
                }
                for param in params {
                    let param_die = self.die(DW_TAG_formal_parameter, Some(die));
                    let param_ty = self.type_die(param, unit);
                    self.attr(param_die, DW_AT_type, Value::Ref(param_ty));
                }
                if *variadic {
                    self.die(DW_TAG_unspecified_parameters, Some(die));
                }
                die
            }
            Type::Named(key) => {
                let die = self.definition_die(key, unit);
                self.type_dies.insert(ty.clone(), die);
                die
            }
        }
    }

    /// The DIE of the definition `key` names, allocating its place before
    /// filling it so a cycle of definitions finds it already there.
    fn definition_die(&mut self, key: &str, unit: usize) -> usize {
        if let Some(&die) = self.definition_dies.get(key) {
            return die;
        }
        let die = self.allocate_definition(key, unit);
        self.fill_definition(key, unit);
        die
    }

    /// Allocate the DIE of `key` empty, under the unit, and memo it.
    fn allocate_definition(&mut self, key: &str, unit: usize) -> usize {
        if let Some(&die) = self.definition_dies.get(key) {
            return die;
        }
        let tag = match self.store.get(key) {
            Some(Definition::Struct(c)) if c.is_class => DW_TAG_class_type,
            Some(Definition::Struct(_)) => DW_TAG_structure_type,
            Some(Definition::Union(_)) => DW_TAG_union_type,
            Some(Definition::Enum(_)) => DW_TAG_enumeration_type,
            Some(Definition::Typedef(_)) => DW_TAG_typedef,
            // A name the store does not define: a type of no known size,
            // written as the unspecified type under the name it goes by.
            None => DW_TAG_unspecified_type,
        };
        let die = self.die(tag, Some(unit));
        self.definition_dies.insert(key.to_string(), die);
        die
    }

    /// Fill the DIE of `key` with what the definition says: its name, its
    /// size, and its members or enumerators or the type it aliases.
    fn fill_definition(&mut self, key: &str, unit: usize) {
        let Some(die) = self.definition_dies.get(key).copied() else {
            return;
        };
        // Filled once: the top-level pass and a reference may both reach
        // the same definition.
        if !self.filled.insert(die) {
            return;
        }
        let Some(definition) = self.store.get(key).cloned() else {
            // A name the store does not define: it keeps the name alone.
            if !self.store.is_anonymous(key) {
                let name = key.split(' ').next_back().unwrap_or(key).to_string();
                self.attr(die, DW_AT_name, Value::Str(name));
            }
            return;
        };
        match definition {
            Definition::Struct(composite) => {
                self.fill_composite(die, key, &composite, false, unit);
            }
            Definition::Union(composite) => {
                self.fill_composite(die, key, &composite, true, unit);
            }
            Definition::Enum(enumeration) => {
                if let Some(tag) = &enumeration.tag {
                    self.attr(die, DW_AT_name, Value::Str(tag.clone()));
                }
                if !enumeration.complete {
                    self.attr(die, DW_AT_declaration, Value::Flag);
                    return;
                }
                if let Some((size, _)) = enumeration.underlying.layout(self.store.model()) {
                    self.attr(die, DW_AT_byte_size, Value::Unsigned(size));
                }
                let underlying = self.type_die(&Type::Prim(enumeration.underlying), unit);
                self.attr(die, DW_AT_type, Value::Ref(underlying));
                for (name, value) in &enumeration.values {
                    let enumerator = self.die(DW_TAG_enumerator, Some(die));
                    self.attr(enumerator, DW_AT_name, Value::Str(name.clone()));
                    self.attr(enumerator, DW_AT_const_value, Value::Signed(*value));
                }
            }
            Definition::Typedef(inner) => {
                // A typedef's key is its name, with no keyword before it.
                self.attr(die, DW_AT_name, Value::Str(key.to_string()));
                let inner = self.type_die(&inner, unit);
                self.attr(die, DW_AT_type, Value::Ref(inner));
            }
        }
    }

    /// A structure or union: its name and size, and its members as the
    /// layout places them. A definition with no body is a declaration.
    fn fill_composite(
        &mut self,
        die: usize,
        key: &str,
        composite: &Composite,
        union: bool,
        unit: usize,
    ) {
        if let Some(tag) = &composite.tag {
            self.attr(die, DW_AT_name, Value::Str(tag.clone()));
        }
        let Some(layout) = self.store.layout(key).cloned() else {
            // Declared, not defined: `struct node;` on its own.
            self.attr(die, DW_AT_declaration, Value::Flag);
            return;
        };
        self.attr(die, DW_AT_byte_size, Value::Unsigned(layout.size));
        self.fill_members(die, composite, &layout, union, unit);
    }

    /// The members of a structure or union, as the layout places them:
    /// the base classes first, then the vtable pointer a class with
    /// virtual methods holds, then the members — an anonymous one under
    /// no name, a bit-field with its bit place.
    fn fill_members(
        &mut self,
        die: usize,
        composite: &Composite,
        layout: &Layout,
        union: bool,
        unit: usize,
    ) {
        let mut fields = layout.fields.iter().peekable();
        // The base classes, in order, each an inheritance at its offset.
        for base in &composite.base_classes {
            let Some(field) = fields.next() else { break };
            let inheritance = self.die(DW_TAG_inheritance, Some(die));
            let base_ty = self.type_die(&Type::Named(base.clone()), unit);
            self.attr(inheritance, DW_AT_type, Value::Ref(base_ty));
            self.attr(
                inheritance,
                DW_AT_data_member_location,
                Value::Unsigned(field.offset),
            );
            self.attr(
                inheritance,
                DW_AT_accessibility,
                Value::Byte(DW_ACCESS_public),
            );
        }
        // The vtable pointer: directly after the bases, a member of no
        // name whose type is `void *`, there only when this class holds
        // the vtable itself — a class whose base holds one has no field
        // of its own, and no member of no name is a `void *`.
        let holds_vtable = !union
            && composite.methods.iter().any(|method| method.is_virtual)
            && fields.peek().is_some_and(|field| {
                field.name.is_none()
                    && matches!(&field.ty, Type::Pointer(inner) if matches!(inner.as_ref(), Type::Prim(Prim::Void)))
            });
        if holds_vtable {
            let field = fields.next().expect("peeked");
            let vptr = self.die(DW_TAG_member, Some(die));
            self.attr(vptr, DW_AT_name, Value::Str("_vptr".to_string()));
            self.attr(vptr, DW_AT_artificial, Value::Flag);
            let ty = self.type_die(&field.ty, unit);
            self.attr(vptr, DW_AT_type, Value::Ref(ty));
            self.attr(
                vptr,
                DW_AT_data_member_location,
                Value::Unsigned(field.offset),
            );
        }
        for field in fields {
            let member = self.die(DW_TAG_member, Some(die));
            if let Some(name) = &field.name {
                self.attr(member, DW_AT_name, Value::Str(name.clone()));
            }
            let ty = self.type_die(&field.ty, unit);
            self.attr(member, DW_AT_type, Value::Ref(ty));
            match field.bits {
                Some((bit_offset, width)) => {
                    // A bit-field: its declared type's size, its width,
                    // and its first bit counted from the start of the
                    // structure — from the low end of the unit on a
                    // little-endian target, from the high end on a
                    // big-endian one, as DWARF counts them.
                    self.attr(member, DW_AT_byte_size, Value::Unsigned(field.size));
                    self.attr(member, DW_AT_bit_size, Value::Unsigned(u64::from(width)));
                    let bit = if self.little_endian {
                        u64::from(bit_offset)
                    } else {
                        field.size * 8 - u64::from(bit_offset) - u64::from(width)
                    };
                    self.attr(
                        member,
                        DW_AT_data_bit_offset,
                        Value::Unsigned(field.offset * 8 + bit),
                    );
                }
                None => {
                    self.attr(
                        member,
                        DW_AT_data_member_location,
                        Value::Unsigned(field.offset),
                    );
                }
            }
        }
        // The methods of a C++ class: declared, not defined here — their
        // code stands in the function list under their own names.
        for method in &composite.methods {
            let declaration = self.die(DW_TAG_subprogram, Some(die));
            self.attr(declaration, DW_AT_name, Value::Str(method.name.clone()));
            self.attr(declaration, DW_AT_declaration, Value::Flag);
            self.attr(declaration, DW_AT_external, Value::Flag);
            if method.is_virtual {
                self.attr(
                    declaration,
                    DW_AT_virtuality,
                    Value::Byte(DW_VIRTUALITY_virtual),
                );
            }
            let ty = self.type_die(&method.ty, unit);
            self.attr(declaration, DW_AT_type, Value::Ref(ty));
        }
    }

    /// The signature of the function at `address`: the analyst's
    /// prototype when one is recorded, and the lift's own otherwise —
    /// its return type and its parameters, as the pseudocode spells them.
    /// `None` when neither gives one.
    fn signature_of(&self, address: u64) -> Option<Signature> {
        if let Some(prototype) = self
            .binary
            .function_properties(address)
            .prototype
            .as_deref()
            .and_then(|text| ag_engine::ctype::parse_prototype(self.store, text).ok())
        {
            return Some(Signature {
                ret: prototype.ret,
                params: prototype.params,
                variadic: prototype.variadic,
            });
        }
        if !self.binary.supports_pseudocode() {
            return None;
        }
        let stages = self.binary.stages(address).ok()?;
        let function = &stages.function;
        let ret = ag_engine::ctype::parse_type(self.store, &function.return_type).ok()?;
        let mut params = Vec::new();
        for param in &function.params {
            let ty = ag_engine::ctype::parse_type(self.store, &param.ty).ok()?;
            params.push((ty, Some(param.name.clone())));
        }
        Some(Signature {
            ret,
            params,
            variadic: false,
        })
    }

    /// How many bytes the function at `address` spans: to where the
    /// unwind data says it ends, or to the last instruction the walk
    /// reached, capped by the next function and the end of its section —
    /// the extent the listing and the fingerprints read. `None` when
    /// nothing says where it ends.
    fn extent_of(&self, address: u64, next: Option<u64>) -> Option<u64> {
        let mut end = self.binary.function_end(address);
        if end.is_none() {
            end = self.binary.disassembly(address).and_then(|disassembly| {
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
        if let Some(section) = self.binary.section_of(address) {
            end = end.min(section.vma.saturating_add(section.size));
        }
        (end > address).then_some(end - address)
    }
}

/// The encoding of a primitive's bytes: what a reader makes of them.
fn encoding_of(prim: Prim) -> u8 {
    match prim {
        Prim::Bool => DW_ATE_boolean,
        Prim::Char | Prim::SChar => DW_ATE_signed_char,
        Prim::UChar => DW_ATE_unsigned_char,
        Prim::Float | Prim::Double | Prim::LongDouble => DW_ATE_float,
        prim if prim.is_signed() => DW_ATE_signed,
        _ => DW_ATE_unsigned,
    }
}

/// An address as the target's bytes: its width, its byte order.
fn address_bytes(address: u64, size: u8, little_endian: bool) -> Vec<u8> {
    if little_endian {
        address.to_le_bytes()[..usize::from(size)].to_vec()
    } else {
        address.to_be_bytes()[8 - usize::from(size)..].to_vec()
    }
}

// ---------------------------------------------------------------------
// LEB128, the integers of the format.

/// Write an unsigned LEB128 integer.
fn uleb(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Write a signed LEB128 integer.
fn sleb(out: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// How many bytes an unsigned LEB128 integer takes.
fn uleb_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

/// How many bytes a signed LEB128 integer takes.
fn sleb_len(mut value: i64) -> usize {
    let mut len = 1;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0) {
            return len;
        }
        len += 1;
    }
}

// ---------------------------------------------------------------------
// Writing the tables as the bytes of the file.

/// The sections of the file, in the order they are written, the null
/// section before them.
const SECTION_NAMES: &[&str] = &[
    ".debug_abbrev",
    ".debug_info",
    ".debug_str",
    ".debug_aranges",
    ".symtab",
    ".strtab",
    ".shstrtab",
];

/// The index of `.symtab` in the section table, the null section first.
const SYMTAB: usize = 5;
/// The index of `.strtab`.
const STRTAB: usize = 6;
/// The index of `.shstrtab`.
const SHSTRTAB: usize = 7;

/// The bytes of a fixed-width integer, in the file's byte order.
fn fixed(out: &mut Vec<u8>, value: u64, width: usize, little_endian: bool) {
    if little_endian {
        out.extend_from_slice(&value.to_le_bytes()[..width]);
    } else {
        out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
    }
}

impl Dwarf {
    /// Write the debug information as an ELF file: the DWARF sections,
    /// and a symbol table beside them. The file is of the target's width
    /// and byte order, an executable whose symbols stand at the addresses
    /// the image reads — a debugger loads it beside the program
    /// (`add-symbol-file` in gdb) and finds the names and the types at
    /// the addresses they stand at.
    pub fn encode(&self) -> Vec<u8> {
        let elf64 = self.address_size == 8;
        let le = self.little_endian;

        let (debug_str, string_offsets) = self.encode_str();
        let (debug_abbrev, debug_info) = self.encode_info(&string_offsets);
        let debug_aranges = self.encode_aranges();
        let (symtab, strtab) = self.encode_symbols(elf64, le);
        let shstrtab = section_names();

        let sections: [&[u8]; 7] = [
            &debug_abbrev,
            &debug_info,
            &debug_str,
            &debug_aranges,
            &symtab,
            &strtab,
            &shstrtab,
        ];

        // The layout: the header, then each section's bytes at its
        // alignment, then the section table.
        let header_size: usize = if elf64 { 64 } else { 52 };
        let entry_size: usize = if elf64 { 64 } else { 40 };
        let mut offsets = [0usize; 7];
        let mut at = header_size;
        for (index, bytes) in sections.iter().enumerate() {
            let align = if index + 1 == SYMTAB {
                if elf64 {
                    8
                } else {
                    4
                }
            } else {
                1
            };
            at = at.div_ceil(align) * align;
            offsets[index] = at;
            at += bytes.len();
        }
        let shoff = at;

        let mut out = Vec::new();
        // The ELF header.
        out.extend_from_slice(b"\x7fELF");
        out.push(if elf64 { 2 } else { 1 }); // EI_CLASS
        out.push(if le { 1 } else { 2 }); // EI_DATA
        out.push(1); // EI_VERSION
        out.push(0); // EI_OSABI: System V
        out.extend_from_slice(&[0; 8]); // the rest of e_ident
        let mut header = Vec::new();
        fixed(&mut header, 2, 2, le); // e_type: ET_EXEC
        fixed(&mut header, u64::from(self.machine), 2, le);
        fixed(&mut header, 1, 4, le); // e_version
        fixed(&mut header, 0, usize::from(self.address_size), le); // e_entry
        fixed(&mut header, 0, if elf64 { 8 } else { 4 }, le); // e_phoff
        fixed(&mut header, shoff as u64, if elf64 { 8 } else { 4 }, le);
        fixed(&mut header, 0, 4, le); // e_flags
        fixed(&mut header, header_size as u64, 2, le);
        fixed(&mut header, if elf64 { 56 } else { 32 }, 2, le); // e_phentsize
        fixed(&mut header, 0, 2, le); // e_phnum
        fixed(&mut header, entry_size as u64, 2, le);
        fixed(&mut header, 8, 2, le); // e_shnum: the null section and seven
        fixed(&mut header, SHSTRTAB as u64, 2, le);
        out.extend_from_slice(&header);

        // The sections' bytes.
        for (index, bytes) in sections.iter().enumerate() {
            while out.len() < offsets[index] {
                out.push(0);
            }
            out.extend_from_slice(bytes);
        }
        while out.len() < shoff {
            out.push(0);
        }

        // The section table: the null section, then the seven.
        let mut name_offsets = [0usize; 7];
        let mut shstr_offset = 1usize;
        for (index, name) in SECTION_NAMES.iter().enumerate() {
            name_offsets[index] = shstr_offset;
            shstr_offset += name.len() + 1;
        }
        let mut sh = vec![0u8; if elf64 { 64 } else { 40 }];
        for (index, bytes) in sections.iter().enumerate() {
            let kind = match index + 1 {
                SYMTAB => 2,            // SHT_SYMTAB
                STRTAB | SHSTRTAB => 3, // SHT_STRTAB
                _ => 1,                 // SHT_PROGBITS
            };
            let align = if index + 1 == SYMTAB {
                if elf64 {
                    8
                } else {
                    4
                }
            } else {
                1
            };
            let link = if index + 1 == SYMTAB { STRTAB } else { 0 };
            // sh_info of the symbol table: the first global symbol, past
            // the null and the seven section symbols.
            let info = if index + 1 == SYMTAB { 8 } else { 0 };
            let entsize = if index + 1 == SYMTAB {
                if elf64 {
                    24
                } else {
                    16
                }
            } else {
                0
            };
            let mut entry = Vec::new();
            fixed(&mut entry, name_offsets[index] as u64, 4, le); // sh_name
            fixed(&mut entry, kind, 4, le); // sh_type
            fixed(&mut entry, 0, if elf64 { 8 } else { 4 }, le); // sh_flags
            fixed(&mut entry, 0, if elf64 { 8 } else { 4 }, le); // sh_addr
            fixed(
                &mut entry,
                offsets[index] as u64,
                if elf64 { 8 } else { 4 },
                le,
            ); // sh_offset
            fixed(
                &mut entry,
                bytes.len() as u64,
                if elf64 { 8 } else { 4 },
                le,
            ); // sh_size
            fixed(&mut entry, link as u64, 4, le); // sh_link
            fixed(&mut entry, info, 4, le); // sh_info
            fixed(&mut entry, align, if elf64 { 8 } else { 4 }, le); // sh_addralign
            fixed(&mut entry, entsize, if elf64 { 8 } else { 4 }, le); // sh_entsize
            sh.extend_from_slice(&entry);
        }
        out.extend_from_slice(&sh);
        out
    }

    /// `.debug_str`: every distinct string, NUL-terminated, with each
    /// string's offset.
    fn encode_str(&self) -> (Vec<u8>, HashMap<String, u32>) {
        let mut out = Vec::new();
        let mut offsets = HashMap::new();
        for die in &self.dies {
            for (_, value) in &die.attrs {
                if let Value::Str(text) = value {
                    if offsets.contains_key(text) {
                        continue;
                    }
                    offsets.insert(text.clone(), out.len() as u32);
                    out.extend_from_slice(text.as_bytes());
                    out.push(0);
                }
            }
        }
        (out, offsets)
    }

    /// The DIEs in the order the format writes them: a depth-first walk
    /// of the tree, a parent before its children, each subtree whole
    /// before the next begins.
    fn walk(&self) -> Vec<usize> {
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); self.dies.len()];
        for (index, die) in self.dies.iter().enumerate() {
            if let Some(parent) = die.parent {
                children[parent].push(index);
            }
        }
        let mut order = Vec::with_capacity(self.dies.len());
        let mut stack = vec![0usize];
        while let Some(index) = stack.pop() {
            order.push(index);
            stack.extend(children[index].iter().rev());
        }
        order
    }

    /// How deep a DIE stands in the tree: the compile unit at 0.
    fn depth_of(&self, mut index: usize) -> usize {
        let mut depth = 0;
        while let Some(parent) = self.dies[index].parent {
            depth += 1;
            index = parent;
        }
        depth
    }

    /// `.debug_abbrev` and `.debug_info`: the abbreviations the DIEs use,
    /// each distinct shape once, and the DIEs under them.
    fn encode_info(&self, strings: &HashMap<String, u32>) -> (Vec<u8>, Vec<u8>) {
        let address_size = usize::from(self.address_size);
        let le = self.little_endian;
        let order = self.walk();

        // Which DIEs have children.
        let mut has_children = vec![false; self.dies.len()];
        for die in &self.dies {
            if let Some(parent) = die.parent {
                has_children[parent] = true;
            }
        }

        // The abbreviation of each DIE: its tag, whether it has children,
        // and its attributes with their forms. Each distinct shape takes
        // one code, in the order first used.
        let mut codes = vec![0u64; self.dies.len()];
        let mut abbrevs: Vec<AbbrevShape> = Vec::new();
        let mut abbrev_index: HashMap<AbbrevShape, u64> = HashMap::new();
        for &index in &order {
            let die = &self.dies[index];
            let shape = (
                die.tag,
                has_children[index],
                die.attrs
                    .iter()
                    .map(|(at, value)| (*at, value.form()))
                    .collect(),
            );
            let next = abbrevs.len() as u64 + 1;
            let code = *abbrev_index.entry(shape.clone()).or_insert_with(|| {
                abbrevs.push(shape);
                next
            });
            codes[index] = code;
        }

        // The null bytes that end the child lists before each DIE: the
        // previous DIE's own list, if it has children, and each
        // ancestor's up to where this DIE hangs. A leaf beside a leaf
        // ends nothing. The last DIE's ancestors close after it.
        let mut nulls_before = vec![0usize; self.dies.len()];
        let mut previous: Option<usize> = None;
        for &index in &order {
            if let Some(prev) = previous {
                let depth = self.depth_of(index);
                let prev_depth = self.depth_of(prev);
                nulls_before[index] = if depth > prev_depth {
                    0
                } else {
                    prev_depth - depth + usize::from(has_children[prev])
                };
            }
            previous = Some(index);
        }
        let trailing_nulls = previous
            .map(|last| self.depth_of(last) + usize::from(has_children[last]))
            .unwrap_or(0);

        // The size of each DIE, and so its offset in the unit: the header
        // is eleven bytes, then the nulls and each DIE's code and
        // attributes, in the order they are written.
        let value_size = |value: &Value| -> usize {
            match value {
                Value::Addr(_) => address_size,
                Value::Str(_) | Value::Ref(_) => 4,
                Value::Unsigned(number) => uleb_len(*number),
                Value::Signed(number) => sleb_len(*number),
                Value::Byte(_) => 1,
                Value::Flag => 0,
                Value::Block(bytes) => uleb_len(bytes.len() as u64) + bytes.len(),
            }
        };
        let mut offsets = vec![0usize; self.dies.len()];
        let mut at = 11usize;
        for &index in &order {
            at += nulls_before[index];
            offsets[index] = at;
            at += uleb_len(codes[index]);
            for (_, value) in &self.dies[index].attrs {
                at += value_size(value);
            }
        }
        at += trailing_nulls;
        let unit_length = at - 4;

        // The abbreviation table.
        let mut abbrev = Vec::new();
        for (code, (tag, children, attrs)) in abbrevs.iter().enumerate() {
            uleb(&mut abbrev, code as u64 + 1);
            uleb(&mut abbrev, *tag);
            abbrev.push(u8::from(*children));
            for (at, form) in attrs {
                uleb(&mut abbrev, *at);
                uleb(&mut abbrev, *form);
            }
            abbrev.extend_from_slice(&[0, 0]);
        }
        abbrev.push(0);

        // The unit: its header, then the DIEs in the walk's order, a null
        // byte after each subtree ends.
        let mut info = Vec::new();
        fixed(&mut info, unit_length as u64, 4, le);
        fixed(&mut info, 4, 2, le); // version
        fixed(&mut info, 0, 4, le); // the abbreviation table's offset
        info.push(self.address_size);
        for &index in &order {
            let die = &self.dies[index];
            info.resize(info.len() + nulls_before[index], 0);
            uleb(&mut info, codes[index]);
            for (_, value) in &die.attrs {
                match value {
                    Value::Addr(address) => fixed(&mut info, *address, address_size, le),
                    Value::Str(text) => fixed(&mut info, u64::from(strings[text]), 4, le),
                    Value::Ref(target) => fixed(&mut info, offsets[*target] as u64, 4, le),
                    Value::Unsigned(number) => uleb(&mut info, *number),
                    Value::Signed(number) => sleb(&mut info, *number),
                    Value::Byte(byte) => info.push(*byte),
                    Value::Flag => {}
                    Value::Block(bytes) => {
                        uleb(&mut info, bytes.len() as u64);
                        info.extend_from_slice(bytes);
                    }
                }
            }
        }
        info.resize(info.len() + trailing_nulls, 0);
        (abbrev, info)
    }

    /// `.debug_aranges`: the ranges of the functions, each naming the
    /// unit they belong to, so a reader finds the unit of an address
    /// without walking the DIEs.
    fn encode_aranges(&self) -> Vec<u8> {
        let address_size = usize::from(self.address_size);
        let le = self.little_endian;
        let mut ranges = Vec::new();
        for die in &self.dies {
            if die.tag != DW_TAG_subprogram {
                continue;
            }
            if let (Some(Value::Addr(low)), Some(Value::Unsigned(length))) =
                (die.attr(DW_AT_low_pc), die.attr(DW_AT_high_pc))
            {
                ranges.push((*low, *length));
            }
        }
        let mut out = Vec::new();
        // The header: length, version, unit offset, address width,
        // segment width — padded to a multiple of two addresses.
        let header = 12usize;
        let padded = header.div_ceil(2 * address_size) * (2 * address_size);
        let length = padded - 4 + (ranges.len() + 1) * 2 * address_size;
        fixed(&mut out, length as u64, 4, le);
        fixed(&mut out, 2, 2, le); // version
        fixed(&mut out, 0, 4, le); // the unit's offset in .debug_info
        out.push(self.address_size);
        out.push(0); // segment selector size
        while out.len() < padded {
            out.push(0);
        }
        for (low, length) in ranges {
            fixed(&mut out, low, address_size, le);
            fixed(&mut out, length, address_size, le);
        }
        fixed(&mut out, 0, address_size, le);
        fixed(&mut out, 0, address_size, le);
        out
    }

    /// `.symtab` and `.strtab`: the null symbol, one symbol a section,
    /// then the functions and the data as global symbols at their
    /// addresses — absolute, for the file holds no code sections of its
    /// own.
    fn encode_symbols(&self, elf64: bool, le: bool) -> (Vec<u8>, Vec<u8>) {
        let mut strtab = vec![0u8];
        let mut offsets: HashMap<String, u32> = HashMap::new();
        let mut symtab = Vec::new();
        let entry = |name: u32, info: u8, shndx: u16, value: u64, size: u64, out: &mut Vec<u8>| {
            if elf64 {
                fixed(out, u64::from(name), 4, le);
                out.push(info);
                out.push(0); // st_other
                fixed(out, u64::from(shndx), 2, le);
                fixed(out, value, 8, le);
                fixed(out, size, 8, le);
            } else {
                fixed(out, u64::from(name), 4, le);
                fixed(out, value, 4, le);
                fixed(out, size, 4, le);
                out.push(info);
                out.push(0);
                fixed(out, u64::from(shndx), 2, le);
            }
        };
        // The null symbol.
        entry(0, 0, 0, 0, 0, &mut symtab);
        // One symbol a section, local, as the convention asks.
        for section in 1..=7u16 {
            entry(0, 0x03, section, 0, 0, &mut symtab); // STB_LOCAL | STT_SECTION
        }
        // The functions and the data, in address order, global.
        let mut symbols: Vec<&Symbol> = self.symbols.iter().collect();
        symbols.sort_by_key(|symbol| (symbol.address, !symbol.function));
        for symbol in symbols {
            let name = match offsets.get(&symbol.name) {
                Some(&offset) => offset,
                None => {
                    let offset = strtab.len() as u32;
                    strtab.extend_from_slice(symbol.name.as_bytes());
                    strtab.push(0);
                    offsets.insert(symbol.name.clone(), offset);
                    offset
                }
            };
            let kind = if symbol.function { 2 } else { 1 }; // STT_FUNC / STT_OBJECT
                                                            // STB_GLOBAL | kind, SHN_ABS: the address is the address.
            entry(
                name,
                0x10 | kind,
                0xfff1,
                symbol.address,
                symbol.size,
                &mut symtab,
            );
        }
        (symtab, strtab)
    }
}

/// `.shstrtab`: the section names, NUL-terminated, the empty name first.
fn section_names() -> Vec<u8> {
    let mut out = vec![0u8];
    for name in SECTION_NAMES {
        out.extend_from_slice(name.as_bytes());
        out.push(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-engine/tests/fixtures/sample.elf")
    }

    fn sample() -> Dwarf {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        build(&binary, "sample.elf", &Notes::default())
    }

    /// The index of the DIE of one tag under one name.
    fn named_at(dwarf: &Dwarf, tag: u64, name: &str) -> usize {
        dwarf
            .dies
            .iter()
            .position(|die| die.tag == tag && die.name() == Some(name))
            .unwrap_or_else(|| panic!("no {tag:#x} named {name}"))
    }

    /// The children of one DIE.
    fn children(dwarf: &Dwarf, parent: usize) -> Vec<&Die> {
        dwarf
            .dies
            .iter()
            .filter(|die| die.parent == Some(parent))
            .collect()
    }

    #[test]
    fn the_leb128_integers_round_trip() {
        for value in [0, 1, 63, 64, 127, 128, 255, 256, 16_383, 16_384, u64::MAX] {
            let mut bytes = Vec::new();
            uleb(&mut bytes, value);
            assert_eq!(bytes.len(), uleb_len(value), "{value}");
            let mut read = 0u64;
            let mut shift = 0;
            for byte in &bytes {
                read |= u64::from(byte & 0x7f) << shift;
                shift += 7;
            }
            assert_eq!(read, value);
        }
        for value in [0, 1, -1, 63, -64, 64, -65, 127, -128, i64::MIN, i64::MAX] {
            let mut bytes = Vec::new();
            sleb(&mut bytes, value);
            assert_eq!(bytes.len(), sleb_len(value), "{value}");
            // Read the groups back as raw bits, truncating to 64, then
            // sign-extend from the last group's sign bit.
            let mut read = 0u64;
            let mut shift = 0u32;
            for byte in &bytes {
                read |= u64::from(byte & 0x7f).wrapping_shl(shift);
                shift += 7;
            }
            if bytes.last().unwrap() & 0x40 != 0 && shift < 64 {
                read |= !0u64 << shift;
            }
            assert_eq!(read as i64, value);
        }
    }

    #[test]
    fn the_sample_is_one_unit_of_functions_and_types() {
        let dwarf = sample();
        assert_eq!(dwarf.address_size, 8);
        assert!(dwarf.little_endian);
        assert_eq!(dwarf.machine, 62);
        assert_eq!(dwarf.dies[0].tag, DW_TAG_compile_unit);
        assert_eq!(dwarf.dies[0].name(), Some("sample.elf"));
        assert!(matches!(
            dwarf.dies[0].attr(DW_AT_producer),
            Some(Value::Str(producer)) if producer.starts_with("AdmiralGrace ")
        ));
        assert_eq!(
            dwarf.dies[0].attr(DW_AT_language),
            Some(&Value::Byte(DW_LANG_C11))
        );

        // main stands where the image puts it, with an extent.
        let main = named_at(&dwarf, DW_TAG_subprogram, "main");
        assert_eq!(
            dwarf.dies[main].attr(DW_AT_low_pc),
            Some(&Value::Addr(0x1198))
        );
        let Some(Value::Unsigned(length)) = dwarf.dies[main].attr(DW_AT_high_pc) else {
            panic!("main has no extent");
        };
        assert!(*length > 0);
        assert_eq!(
            dwarf.dies[main].attr(DW_AT_main_subprogram),
            Some(&Value::Flag)
        );

        // The lift's signature types it: the lift reads main's return as
        // long, and the writer writes what the lift says.
        let Some(Value::Ref(ret)) = dwarf.dies[main].attr(DW_AT_type) else {
            panic!("main has no return type");
        };
        assert_eq!(dwarf.dies[*ret].tag, DW_TAG_base_type);
        assert_eq!(dwarf.dies[*ret].name(), Some("long"));
        assert_eq!(
            dwarf.dies[*ret].attr(DW_AT_encoding),
            Some(&Value::Byte(DW_ATE_signed))
        );

        // The platform's primitives are base types of their sizes.
        let int = named_at(&dwarf, DW_TAG_base_type, "int");
        assert_eq!(
            dwarf.dies[int].attr(DW_AT_byte_size),
            Some(&Value::Unsigned(4))
        );
        assert_eq!(
            dwarf.dies[int].attr(DW_AT_encoding),
            Some(&Value::Byte(DW_ATE_signed))
        );
        let char = named_at(&dwarf, DW_TAG_base_type, "char");
        assert_eq!(
            dwarf.dies[char].attr(DW_AT_encoding),
            Some(&Value::Byte(DW_ATE_signed_char))
        );
        let size_t = named_at(&dwarf, DW_TAG_base_type, "size_t");
        assert_eq!(
            dwarf.dies[size_t].attr(DW_AT_byte_size),
            Some(&Value::Unsigned(8))
        );

        // The symbol table carries the functions beside the DWARF.
        assert!(dwarf.symbols.iter().any(|symbol| symbol.name == "main"
            && symbol.address == 0x1198
            && symbol.function
            && symbol.size > 0));
    }

    #[test]
    fn the_analysts_types_are_written_with_their_layout() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        binary
            .set_type_definitions(&[
                crate::TypeText {
                    name: "point".to_string(),
                    c: "struct point { int x; int y; };".to_string(),
                },
                crate::TypeText {
                    name: "node".to_string(),
                    c: "struct node { int value; struct node *next; };".to_string(),
                },
                crate::TypeText {
                    name: "color".to_string(),
                    c: "enum color { RED, GREEN = 5, BLUE };".to_string(),
                },
                crate::TypeText {
                    name: "point_t".to_string(),
                    c: "typedef struct point point_t;".to_string(),
                },
                crate::TypeText {
                    name: "flags".to_string(),
                    c: "struct flags { unsigned a : 3; unsigned b : 5; unsigned : 0; unsigned c : 4; };"
                        .to_string(),
                },
                crate::TypeText {
                    name: "value".to_string(),
                    c: "union value { int i; float f; };".to_string(),
                },
            ])
            .expect("the definitions read");
        let dwarf = build(&binary, "sample.elf", &Notes::default());

        // The structure: its size, and its members at their offsets.
        let point = named_at(&dwarf, DW_TAG_structure_type, "point");
        assert_eq!(
            dwarf.dies[point].attr(DW_AT_byte_size),
            Some(&Value::Unsigned(8))
        );
        let members = children(&dwarf, point);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].tag, DW_TAG_member);
        assert_eq!(members[0].name(), Some("x"));
        assert_eq!(
            members[0].attr(DW_AT_data_member_location),
            Some(&Value::Unsigned(0))
        );
        assert_eq!(members[1].name(), Some("y"));
        assert_eq!(
            members[1].attr(DW_AT_data_member_location),
            Some(&Value::Unsigned(4))
        );

        // The self-reference: node's next points back to node.
        let node = named_at(&dwarf, DW_TAG_structure_type, "node");
        let next = children(&dwarf, node)
            .into_iter()
            .find(|die| die.name() == Some("next"))
            .expect("node has a next member");
        let Some(Value::Ref(pointer)) = next.attr(DW_AT_type) else {
            panic!("next has no type");
        };
        assert_eq!(dwarf.dies[*pointer].tag, DW_TAG_pointer_type);
        let Some(Value::Ref(pointee)) = dwarf.dies[*pointer].attr(DW_AT_type) else {
            panic!("the pointer points at nothing");
        };
        assert_eq!(*pointee, node);

        // The enumeration: its underlying type and its enumerators.
        let color = named_at(&dwarf, DW_TAG_enumeration_type, "color");
        assert_eq!(
            dwarf.dies[color].attr(DW_AT_byte_size),
            Some(&Value::Unsigned(4))
        );
        let enumerators = children(&dwarf, color);
        assert_eq!(enumerators.len(), 3);
        assert_eq!(enumerators[0].tag, DW_TAG_enumerator);
        assert_eq!(enumerators[0].name(), Some("RED"));
        assert_eq!(
            enumerators[0].attr(DW_AT_const_value),
            Some(&Value::Signed(0))
        );
        assert_eq!(
            enumerators[1].attr(DW_AT_const_value),
            Some(&Value::Signed(5))
        );
        assert_eq!(
            enumerators[2].attr(DW_AT_const_value),
            Some(&Value::Signed(6))
        );

        // The typedef names the structure.
        let typedef = named_at(&dwarf, DW_TAG_typedef, "point_t");
        let Some(Value::Ref(target)) = dwarf.dies[typedef].attr(DW_AT_type) else {
            panic!("the typedef aliases nothing");
        };
        assert_eq!(dwarf.dies[*target].tag, DW_TAG_structure_type);
        assert_eq!(dwarf.dies[*target].name(), Some("point"));

        // The bit-fields: their widths and their bit places.
        let flags = named_at(&dwarf, DW_TAG_structure_type, "flags");
        let bits = children(&dwarf, flags);
        assert_eq!(bits.len(), 3);
        assert_eq!(bits[0].attr(DW_AT_bit_size), Some(&Value::Unsigned(3)));
        assert_eq!(
            bits[0].attr(DW_AT_data_bit_offset),
            Some(&Value::Unsigned(0))
        );
        assert_eq!(bits[1].attr(DW_AT_bit_size), Some(&Value::Unsigned(5)));
        assert_eq!(
            bits[1].attr(DW_AT_data_bit_offset),
            Some(&Value::Unsigned(3))
        );
        // The zero-width field moved c to the next unit.
        assert_eq!(bits[2].name(), Some("c"));
        assert_eq!(
            bits[2].attr(DW_AT_data_bit_offset),
            Some(&Value::Unsigned(32))
        );

        // The union: its members both at zero.
        let value = named_at(&dwarf, DW_TAG_union_type, "value");
        assert_eq!(
            dwarf.dies[value].attr(DW_AT_byte_size),
            Some(&Value::Unsigned(4))
        );
        for member in children(&dwarf, value) {
            assert_eq!(
                member.attr(DW_AT_data_member_location),
                Some(&Value::Unsigned(0))
            );
        }
    }

    #[test]
    fn a_rename_and_a_prototype_are_the_functions_words() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        let mut properties = BTreeMap::new();
        properties.insert(
            0x1198,
            crate::FunctionProperties {
                prototype: Some("int entry(int argc, char **argv)".to_string()),
                ..crate::FunctionProperties::default()
            },
        );
        binary.set_function_properties(properties);
        let notes = Notes {
            names: BTreeMap::from([(0x1198, "entry".to_string())]),
            ..Notes::default()
        };
        let dwarf = build(&binary, "sample.elf", &notes);
        let entry = named_at(&dwarf, DW_TAG_subprogram, "entry");
        assert_eq!(
            dwarf.dies[entry].attr(DW_AT_low_pc),
            Some(&Value::Addr(0x1198))
        );
        assert_eq!(dwarf.dies[entry].attr(DW_AT_prototyped), Some(&Value::Flag));
        assert!(dwarf.dies[entry].attr(DW_AT_main_subprogram).is_none());
        let params = children(&dwarf, entry);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].tag, DW_TAG_formal_parameter);
        assert_eq!(params[0].name(), Some("argc"));
        assert_eq!(params[1].name(), Some("argv"));
        let Some(Value::Ref(argv_ty)) = params[1].attr(DW_AT_type) else {
            panic!("argv has no type");
        };
        assert_eq!(dwarf.dies[*argv_ty].tag, DW_TAG_pointer_type);
        // The symbol table carries the rename too.
        assert!(dwarf
            .symbols
            .iter()
            .any(|symbol| symbol.name == "entry" && symbol.address == 0x1198));
    }

    #[test]
    fn the_data_stands_under_the_analysts_type() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        let Some(datum) = binary.data_symbols().first().cloned() else {
            panic!("the sample has data symbols");
        };
        let notes = Notes {
            names: BTreeMap::from([(datum.address, "renamed".to_string())]),
            data_types: BTreeMap::from([(
                datum.address,
                Type::Array(Box::new(Type::Prim(Prim::Int32)), Some(4)),
            )]),
        };
        let dwarf = build(&binary, "sample.elf", &notes);
        let variable = named_at(&dwarf, DW_TAG_variable, "renamed");
        let Some(Value::Block(location)) = dwarf.dies[variable].attr(DW_AT_location) else {
            panic!("the variable has no location");
        };
        assert_eq!(location[0], DW_OP_addr);
        assert_eq!(
            u64::from_le_bytes(location[1..9].try_into().unwrap()),
            datum.address
        );
        let Some(Value::Ref(ty)) = dwarf.dies[variable].attr(DW_AT_type) else {
            panic!("the variable has no type");
        };
        assert_eq!(dwarf.dies[*ty].tag, DW_TAG_array_type);
        let subrange = children(&dwarf, *ty)
            .into_iter()
            .find(|die| die.tag == DW_TAG_subrange_type)
            .expect("the array has a subrange");
        assert_eq!(subrange.attr(DW_AT_count), Some(&Value::Unsigned(4)));
    }

    #[test]
    fn the_file_encodes_as_elf_with_dwarf_sections() {
        let dwarf = sample();
        let bytes = dwarf.encode();
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(bytes[4], 2, "ELF64");
        assert_eq!(bytes[5], 1, "little-endian");
        assert_eq!(
            u16::from_le_bytes(bytes[16..18].try_into().unwrap()),
            2,
            "ET_EXEC"
        );
        assert_eq!(
            u16::from_le_bytes(bytes[18..20].try_into().unwrap()),
            62,
            "EM_X86_64"
        );

        // The section table names the DWARF sections.
        let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
        let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
        let shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;
        assert_eq!(shnum, 8);
        let section = |index: usize| -> (u32, u64, u64) {
            let at = shoff + index * shentsize;
            let entry = &bytes[at..at + shentsize];
            (
                u32::from_le_bytes(entry[0..4].try_into().unwrap()),
                u64::from_le_bytes(entry[24..32].try_into().unwrap()),
                u64::from_le_bytes(entry[32..40].try_into().unwrap()),
            )
        };
        let (_, shstr_offset, shstr_size) = section(shstrndx);
        let shstr = &bytes[shstr_offset as usize..(shstr_offset + shstr_size) as usize];
        let name = |offset: u32| -> &str {
            let start = offset as usize;
            let end = shstr[start..].iter().position(|byte| *byte == 0).unwrap() + start;
            std::str::from_utf8(&shstr[start..end]).unwrap()
        };
        let names: Vec<&str> = (1..shnum).map(|index| name(section(index).0)).collect();
        assert_eq!(
            names,
            [
                ".debug_abbrev",
                ".debug_info",
                ".debug_str",
                ".debug_aranges",
                ".symtab",
                ".strtab",
                ".shstrtab"
            ]
        );

        // The unit header: DWARF 4, eight-byte addresses.
        let (_, info_offset, info_size) = section(2);
        let info = &bytes[info_offset as usize..(info_offset + info_size) as usize];
        assert_eq!(
            u32::from_le_bytes(info[0..4].try_into().unwrap()) as usize,
            info.len() - 4
        );
        assert_eq!(u16::from_le_bytes(info[4..6].try_into().unwrap()), 4);
        assert_eq!(info[10], 8);
        // The first DIE is the compile unit, under abbreviation 1.
        assert_eq!(info[11], 1);

        // The symbol table: the null symbol, seven section symbols, then
        // the functions and the data, global and absolute.
        let (_, sym_offset, sym_size) = section(5);
        let symtab = &bytes[sym_offset as usize..(sym_offset + sym_size) as usize];
        assert_eq!(symtab.len() % 24, 0);
        assert!(symtab.len() / 24 > 8);
        let first_global = &symtab[8 * 24..9 * 24];
        assert_eq!(first_global[4] >> 4, 1, "STB_GLOBAL");
        assert_eq!(
            u16::from_le_bytes(first_global[6..8].try_into().unwrap()),
            0xfff1,
            "SHN_ABS"
        );
    }

    #[test]
    fn a_thirty_two_bit_image_writes_a_thirty_two_bit_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-engine/tests/fixtures/boundaries32.elf");
        let binary = Binary::open(&path).expect("the 32-bit sample opens");
        let dwarf = build(&binary, "boundaries32.elf", &Notes::default());
        assert_eq!(dwarf.address_size, 4);
        let bytes = dwarf.encode();
        assert_eq!(bytes[4], 1, "ELF32");
        assert_eq!(
            u16::from_le_bytes(bytes[18..20].try_into().unwrap()),
            3,
            "EM_386"
        );
        // The unit header says four-byte addresses.
        let shoff = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
        let info_header = &bytes[shoff + 2 * 40..shoff + 3 * 40];
        let info_offset = u32::from_le_bytes(info_header[16..20].try_into().unwrap()) as usize;
        assert_eq!(bytes[info_offset + 10], 4);
    }
}
