//! The Swift metadata a Mach-O carries, read from the image itself.
//!
//! A Swift binary describes its types in the `__swift5_*` sections, for the
//! runtime to find at load and for reflection to read: each nominal type's
//! context descriptor names it, its module and its kind, and points at its
//! field descriptor — the fields, each with its name and the mangled name
//! of its type — and, for a class, at its superclass and its vtable, the
//! methods it dispatches dynamically with the address of each
//! implementation. The protocols and the conformances are listed the same
//! way. All of it is reached through relative pointers from the records
//! themselves, and a type's name inside another record is a mangled name
//! that may hold a symbolic reference back to a descriptor; both are
//! followed here, the mangled names decoded by [`crate::swift_demangle`].
//!
//! The image is read through kuna's view of a Mach-O with the chained
//! fixups resolved, as the Objective-C metadata is. Every count and every
//! string is bounded against a crafted file, and the field records read
//! across the whole image with them; a field descriptor two types share
//! is read once. Only a 64-bit Mach-O is read; the records are read as the
//! Swift 5 runtime lays them out, and a class descriptor whose generic
//! header carries flags this reader does not know keeps its methods to
//! itself rather than name them wrong.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

use kuna_analysis::analyzers::objc::sections::MachoImage;
use kuna_analysis::loader::format::macho::resolve_chained_fixups;
use object::read::{Object, ObjectSection};

use crate::swift_demangle;

/// One field of a type: a stored property, or a case of an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftField {
    /// Its name: `count`, `circle`.
    pub name: String,
    /// Its type, decoded, when the record names one: `Swift.Int`. A case
    /// without a payload has none.
    pub type_name: Option<String>,
    /// Whether it is `var` rather than `let`; for a case, whether it is
    /// `indirect`.
    pub is_var: bool,
}

/// One method a class dispatches dynamically: an entry of its vtable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftMethod {
    /// The kind of entry: `method`, `init`, `getter`, `setter`, `modify`,
    /// `read`.
    pub kind: &'static str,
    /// Whether it is an instance method rather than a class method.
    pub is_instance: bool,
    /// The address of the implementation, when the class has one of its own.
    pub imp: Option<u64>,
}

/// The kind of a nominal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwiftKind {
    Class,
    Struct,
    Enum,
}

impl SwiftKind {
    /// The keyword.
    pub fn keyword(self) -> &'static str {
        match self {
            SwiftKind::Class => "class",
            SwiftKind::Struct => "struct",
            SwiftKind::Enum => "enum",
        }
    }
}

/// One nominal type the image describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftType {
    /// The address of its context descriptor.
    pub address: u64,
    pub kind: SwiftKind,
    /// Its qualified name: `sample.Derived`.
    pub name: String,
    /// Its module.
    pub module: String,
    /// Whether it is generic.
    pub generic: bool,
    /// Its superclass, for a class whose descriptor names one: `sample.Base`.
    pub superclass: Option<String>,
    /// Its fields, or its cases.
    pub fields: Vec<SwiftField>,
    /// The methods of its vtable, for a class.
    pub methods: Vec<SwiftMethod>,
    /// The protocols it conforms to, as the conformances name them.
    pub protocols: Vec<String>,
}

/// One protocol the image describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftProtocol {
    /// The address of its descriptor.
    pub address: u64,
    /// Its qualified name: `sample.Greeting`.
    pub name: String,
    /// How many requirements it has.
    pub requirements: u32,
}

/// Everything the image says about its Swift.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwiftMetadata {
    /// The types, in the order of `__swift5_types`.
    pub types: Vec<SwiftType>,
    /// The protocols, in the order of `__swift5_protos`.
    pub protocols: Vec<SwiftProtocol>,
}

impl SwiftMetadata {
    /// Whether the image says nothing of Swift.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty() && self.protocols.is_empty()
    }

    /// A name for each method implementation a class's vtable points at,
    /// by address, for the functions no symbol names: `sample.Derived.method#2`,
    /// `sample.Base.getter#0`. The first name an address gets is kept.
    pub fn method_names(&self) -> BTreeMap<u64, String> {
        let mut names = BTreeMap::new();
        for ty in &self.types {
            for (index, method) in ty.methods.iter().enumerate() {
                if let Some(imp) = method.imp {
                    names
                        .entry(imp)
                        .or_insert_with(|| format!("{}.{}#{index}", ty.name, method.kind));
                }
            }
        }
        names
    }

    /// Move every address — the descriptors and the implementations — by
    /// `delta`, as when the image is read at another base.
    pub fn shift(&mut self, delta: u64) {
        for ty in &mut self.types {
            ty.address = ty.address.wrapping_add(delta);
            for method in &mut ty.methods {
                if let Some(imp) = &mut method.imp {
                    *imp = imp.wrapping_add(delta);
                }
            }
        }
        for protocol in &mut self.protocols {
            protocol.address = protocol.address.wrapping_add(delta);
        }
    }

    /// No real list is longer: a bound on a corrupt count.
    pub const MOST_IN_A_LIST: u64 = 4096;
    /// No real name — a type, a field — is longer: a bound on a pointer
    /// into a crafted string section.
    pub const LONGEST_NAME: usize = 4096;
    /// No chain of contexts is deeper: a bound on a crafted parent loop.
    pub const DEEPEST_CONTEXT: usize = 32;
    /// No real image has more field records: a bound on the lists of a
    /// crafted one, across every type.
    pub const MOST_FIELDS: usize = 1 << 20;
}

/// The layouts of the runtime's records: byte offsets of the fields read.
mod layout {
    /// `ContextDescriptor`: flags, parent.
    pub const FLAGS: u64 = 0x00;
    pub const PARENT: u64 = 0x04;
    /// The kinds, in the low five bits of the flags.
    pub const KIND_MASK: u32 = 0x1f;
    pub const KIND_MODULE: u32 = 0;
    pub const KIND_EXTENSION: u32 = 1;
    pub const KIND_PROTOCOL: u32 = 3;
    pub const KIND_CLASS: u32 = 16;
    pub const KIND_STRUCT: u32 = 17;
    pub const KIND_ENUM: u32 = 18;
    /// The generic bit of the flags.
    pub const IS_GENERIC: u32 = 0x80;
    /// `ModuleContextDescriptor.name`, `TypeContextDescriptor.name`,
    /// `ProtocolDescriptor.name`.
    pub const NAME: u64 = 0x08;
    /// `TypeContextDescriptor.fields`.
    pub const FIELDS: u64 = 0x10;
    /// `ClassDescriptor`: superclassType, numImmediateMembers, numFields,
    /// fieldOffsetVectorOffset; then the trailing records.
    pub const CLASS_SUPERCLASS: u64 = 0x14;
    pub const CLASS_FIXED_SIZE: u64 = 0x2c;
    /// `ProtocolDescriptor.numRequirements`.
    pub const PROTOCOL_NUM_REQUIREMENTS: u64 = 0x10;
    /// The kind-specific flags of a class, in the high half of the flags.
    pub const CLASS_METADATA_INITIALIZATION: u32 = 0x3;
    pub const CLASS_HAS_RESILIENT_SUPERCLASS: u32 = 1 << 13;
    pub const CLASS_HAS_VTABLE: u32 = 1 << 15;
    /// `MethodDescriptor`: flags, impl.
    pub const METHOD_FLAGS: u64 = 0x00;
    pub const METHOD_IMPL: u64 = 0x04;
    pub const METHOD_SIZE: u64 = 8;
    pub const METHOD_KIND_MASK: u32 = 0x0f;
    pub const METHOD_IS_INSTANCE: u32 = 0x10;
    /// `FieldDescriptor`: mangledTypeName, superclass, kind, fieldRecordSize,
    /// numFields, then the records.
    pub const FIELD_DESCRIPTOR_RECORD_SIZE: u64 = 0x0a;
    pub const FIELD_DESCRIPTOR_COUNT: u64 = 0x0c;
    pub const FIELD_DESCRIPTOR_FIRST: u64 = 0x10;
    /// `FieldRecord`: flags, mangledTypeName, fieldName.
    pub const FIELD_FLAGS: u64 = 0x00;
    pub const FIELD_TYPE: u64 = 0x04;
    pub const FIELD_NAME: u64 = 0x08;
    pub const FIELD_RECORD_SIZE: u64 = 12;
    pub const FIELD_IS_INDIRECT_CASE: u32 = 0x1;
    pub const FIELD_IS_VAR: u32 = 0x2;
    /// `ProtocolConformanceDescriptor`: protocol, typeRef, witnessTable,
    /// flags.
    pub const CONFORMANCE_PROTOCOL: u64 = 0x00;
    pub const CONFORMANCE_TYPE: u64 = 0x04;
    pub const CONFORMANCE_FLAGS: u64 = 0x0c;
    /// The kind of the type reference, in bits 3 to 5 of the flags.
    pub const CONFORMANCE_TYPE_KIND_SHIFT: u32 = 3;
    pub const CONFORMANCE_TYPE_KIND_MASK: u32 = 0x7;
}

/// The image under the walk: kuna's view of it, the field descriptors read
/// so far by address, and the count of field records read against the
/// bound.
struct Walk<'a> {
    img: MachoImage<'a>,
    fields: RefCell<HashMap<u64, Vec<SwiftField>>>,
    field_records: Cell<usize>,
}

impl Walk<'_> {
    /// A relative pointer at `at`: the field's address plus the signed
    /// offset it holds. `None` when unmapped or zero.
    fn relative(&self, at: u64) -> Option<u64> {
        let offset = self.img.read_i32(at)?;
        (offset != 0).then(|| at.wrapping_add(offset as i64 as u64))
    }

    /// A relative pointer that may be indirect: an odd offset reaches a
    /// pointer, which is followed.
    fn relative_indirectable(&self, at: u64) -> Option<u64> {
        let offset = self.img.read_i32(at)?;
        if offset == 0 {
            return None;
        }
        let target = at.wrapping_add((offset & !1) as i64 as u64);
        if offset & 1 != 0 {
            self.img.read_ptr(target).filter(|pointer| *pointer != 0)
        } else {
            Some(target)
        }
    }

    /// The NUL-terminated string at `pointer`, bounded.
    fn name_at(&self, pointer: u64) -> Option<String> {
        let bytes = self.bytes_at(pointer, SwiftMetadata::LONGEST_NAME)?;
        let end = bytes.iter().position(|byte| *byte == 0)?;
        String::from_utf8(bytes[..end].to_vec()).ok()
    }

    /// Up to `most` bytes at `pointer`: all at once where the section has
    /// them, else as many as it has.
    fn bytes_at(&self, pointer: u64, most: usize) -> Option<Vec<u8>> {
        if pointer == 0 {
            return None;
        }
        if let Some(bytes) = self.img.read(pointer, most) {
            return Some(bytes.to_vec());
        }
        let mut bytes = Vec::new();
        while bytes.len() < most {
            match self.img.read(pointer.wrapping_add(bytes.len() as u64), 1) {
                Some(byte) => bytes.push(byte[0]),
                None => break,
            }
        }
        (!bytes.is_empty()).then_some(bytes)
    }

    /// The qualified name of the context descriptor at `descriptor`: its
    /// name under its parents' names, up to the module. `None` for an
    /// unreadable one.
    fn qualified_name(&self, descriptor: u64) -> Option<String> {
        let mut parts = Vec::new();
        let mut current = descriptor;
        for _ in 0..SwiftMetadata::DEEPEST_CONTEXT {
            let flags = self.img.read_u32(current.wrapping_add(layout::FLAGS))?;
            let kind = flags & layout::KIND_MASK;
            match kind {
                layout::KIND_MODULE
                | layout::KIND_PROTOCOL
                | layout::KIND_CLASS
                | layout::KIND_STRUCT
                | layout::KIND_ENUM => {
                    let name = self
                        .relative(current.wrapping_add(layout::NAME))
                        .and_then(|name| self.name_at(name))?;
                    parts.push(name);
                }
                // An extension names the type it extends, module and all,
                // as a mangled type name; the chain ends there.
                layout::KIND_EXTENSION => {
                    let extended = self
                        .relative(current.wrapping_add(layout::NAME))
                        .and_then(|name| self.type_name_at(name))?;
                    parts.push(extended);
                    break;
                }
                // An anonymous context names nothing here.
                _ => {}
            }
            if kind == layout::KIND_MODULE {
                break;
            }
            match self.relative_indirectable(current.wrapping_add(layout::PARENT)) {
                Some(parent) => current = parent,
                None => break,
            }
        }
        parts.reverse();
        (!parts.is_empty()).then(|| parts.join("."))
    }

    /// The module of the descriptor at `descriptor`: the top of its chain.
    fn module_of(&self, descriptor: u64) -> Option<String> {
        let mut current = descriptor;
        for _ in 0..SwiftMetadata::DEEPEST_CONTEXT {
            let flags = self.img.read_u32(current.wrapping_add(layout::FLAGS))?;
            if flags & layout::KIND_MASK == layout::KIND_MODULE {
                return self
                    .relative(current.wrapping_add(layout::NAME))
                    .and_then(|name| self.name_at(name));
            }
            current = self.relative_indirectable(current.wrapping_add(layout::PARENT))?;
        }
        None
    }

    /// The mangled path of the descriptor at `descriptor`, as a type's
    /// mangled name would spell it: `6sample7DerivedC`. What a symbolic
    /// reference inside a mangled name stands for.
    fn mangled_path(&self, descriptor: u64) -> Option<String> {
        let mut parts = Vec::new();
        let mut current = descriptor;
        for _ in 0..SwiftMetadata::DEEPEST_CONTEXT {
            let flags = self.img.read_u32(current.wrapping_add(layout::FLAGS))?;
            let kind = flags & layout::KIND_MASK;
            let letter = match kind {
                layout::KIND_MODULE => "",
                layout::KIND_PROTOCOL => "P",
                layout::KIND_CLASS => "C",
                layout::KIND_STRUCT => "V",
                layout::KIND_ENUM => "O",
                _ => return None,
            };
            let name = self
                .relative(current.wrapping_add(layout::NAME))
                .and_then(|name| self.name_at(name))?;
            parts.push(format!("{}{name}{letter}", name.len()));
            if kind == layout::KIND_MODULE {
                break;
            }
            current = self.relative_indirectable(current.wrapping_add(layout::PARENT))?;
        }
        parts.reverse();
        Some(parts.concat())
    }

    /// A mangled type name at `pointer`, decoded: the text as the runtime
    /// writes it, with each symbolic reference — a control byte and a
    /// relative offset to a descriptor — replaced by the descriptor's
    /// mangled path. `None` for an unreadable one.
    fn type_name_at(&self, pointer: u64) -> Option<String> {
        let bytes = self.bytes_at(pointer, SwiftMetadata::LONGEST_NAME)?;
        let mut mangled = String::new();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            match byte {
                0 => break,
                0x01 | 0x02 => {
                    let at = pointer.wrapping_add(index as u64 + 1);
                    let offset =
                        i32::from_le_bytes(bytes.get(index + 1..index + 5)?.try_into().ok()?);
                    let mut target = at.wrapping_add(offset as i64 as u64);
                    if byte == 0x02 {
                        target = self.img.read_ptr(target)?;
                    }
                    mangled.push_str(&self.mangled_path(target)?);
                    index += 5;
                }
                // The other symbolic references — accessors, keys — name
                // nothing a reader can follow here.
                0x03..=0x17 => return None,
                0x18..=0x1f => return None,
                _ => {
                    mangled.push(byte as char);
                    index += 1;
                }
            }
        }
        if mangled.is_empty() {
            return None;
        }
        swift_demangle::demangle_type(&mangled)
    }

    /// The fields of the field descriptor at `descriptor`, read once per
    /// descriptor.
    fn fields_at(&self, descriptor: u64) -> Vec<SwiftField> {
        if let Some(fields) = self.fields.borrow().get(&descriptor) {
            return fields.clone();
        }
        let fields = self.read_fields(descriptor);
        self.fields.borrow_mut().insert(descriptor, fields.clone());
        fields
    }

    fn read_fields(&self, descriptor: u64) -> Vec<SwiftField> {
        let mut fields = Vec::new();
        let Some(count) = self
            .img
            .read_u32(descriptor.wrapping_add(layout::FIELD_DESCRIPTOR_COUNT))
        else {
            return fields;
        };
        let record_size = self
            .img
            .read(
                descriptor.wrapping_add(layout::FIELD_DESCRIPTOR_RECORD_SIZE),
                2,
            )
            .map(|bytes| u64::from(u16::from_le_bytes([bytes[0], bytes[1]])))
            .unwrap_or(layout::FIELD_RECORD_SIZE);
        if record_size < layout::FIELD_RECORD_SIZE {
            return fields;
        }
        for index in 0..u64::from(count).min(SwiftMetadata::MOST_IN_A_LIST) {
            if self.field_records.get() >= SwiftMetadata::MOST_FIELDS {
                break;
            }
            self.field_records.set(self.field_records.get() + 1);
            let record =
                descriptor.wrapping_add(layout::FIELD_DESCRIPTOR_FIRST + index * record_size);
            let Some(flags) = self.img.read_u32(record.wrapping_add(layout::FIELD_FLAGS)) else {
                break;
            };
            let Some(name) = self
                .relative(record.wrapping_add(layout::FIELD_NAME))
                .and_then(|name| self.name_at(name))
            else {
                continue;
            };
            let type_name = self
                .relative(record.wrapping_add(layout::FIELD_TYPE))
                .and_then(|pointer| self.type_name_at(pointer));
            fields.push(SwiftField {
                name,
                type_name,
                is_var: flags & (layout::FIELD_IS_VAR | layout::FIELD_IS_INDIRECT_CASE) != 0,
            });
        }
        fields
    }

    /// The vtable of the class descriptor at `descriptor` whose flags are
    /// `flags`: the method descriptors after the fixed fields and the
    /// trailing records before them.
    fn methods_at(&self, descriptor: u64, flags: u32) -> Vec<SwiftMethod> {
        let mut methods = Vec::new();
        let class_flags = flags >> 16;
        if class_flags & layout::CLASS_HAS_VTABLE == 0 {
            return methods;
        }
        let mut at = descriptor.wrapping_add(layout::CLASS_FIXED_SIZE);
        if flags & layout::IS_GENERIC != 0 {
            // A type's generic context header: the instantiation cache and
            // pattern, then the counts of parameters and requirements; the
            // parameters one byte each, padded to four; the requirements
            // twelve bytes each. The header's flags announce trailing
            // records this reader does not know — parameter packs, inverted
            // protocols — after which the vtable cannot be placed.
            let Some(header_flags) = self.img.read(at.wrapping_add(14), 2) else {
                return methods;
            };
            if header_flags != [0, 0] {
                return methods;
            }
            let Some(params) = self.img.read(at.wrapping_add(8), 2) else {
                return methods;
            };
            let params = u64::from(u16::from_le_bytes([params[0], params[1]]));
            let Some(requirements) = self.img.read(at.wrapping_add(10), 2) else {
                return methods;
            };
            let requirements = u64::from(u16::from_le_bytes([requirements[0], requirements[1]]));
            if params > SwiftMetadata::MOST_IN_A_LIST
                || requirements > SwiftMetadata::MOST_IN_A_LIST
            {
                return methods;
            }
            at = at.wrapping_add(16 + params.div_ceil(4) * 4 + requirements * 12);
        }
        if class_flags & layout::CLASS_HAS_RESILIENT_SUPERCLASS != 0 {
            at = at.wrapping_add(4);
        }
        match class_flags & layout::CLASS_METADATA_INITIALIZATION {
            1 => at = at.wrapping_add(12),
            2 => at = at.wrapping_add(4),
            _ => {}
        }
        // The vtable header: the offset of the vtable in the metadata, and
        // its size.
        let Some(size) = self.img.read_u32(at.wrapping_add(4)) else {
            return methods;
        };
        let first = at.wrapping_add(8);
        for index in 0..u64::from(size).min(SwiftMetadata::MOST_IN_A_LIST) {
            let method = first.wrapping_add(index * layout::METHOD_SIZE);
            let Some(method_flags) = self.img.read_u32(method.wrapping_add(layout::METHOD_FLAGS))
            else {
                break;
            };
            let kind = match method_flags & layout::METHOD_KIND_MASK {
                0 => "method",
                1 => "init",
                2 => "getter",
                3 => "setter",
                4 => "modify",
                5 => "read",
                6 => "modify2",
                7 => "read2",
                _ => "unknown",
            };
            methods.push(SwiftMethod {
                kind,
                is_instance: method_flags & layout::METHOD_IS_INSTANCE != 0,
                imp: self.relative(method.wrapping_add(layout::METHOD_IMPL)),
            });
        }
        methods
    }
}

/// Read the Swift metadata of the Mach-O `bytes` are, when they are one and
/// it carries any; `None` for any other file, and for a Mach-O with no
/// Swift in it.
pub fn read(bytes: &[u8]) -> Option<SwiftMetadata> {
    let file = object::File::parse(bytes).ok()?;
    if file.format() != object::BinaryFormat::MachO || !file.is_64() {
        return None;
    }
    let walk = Walk {
        img: MachoImage::with_fixups(&file, resolve_chained_fixups(&file, bytes)),
        fields: RefCell::new(HashMap::new()),
        field_records: Cell::new(0),
    };
    let mut metadata = SwiftMetadata::default();

    // The records a `__swift5_*` section lists, each a relative pointer
    // from its own slot.
    let records = |section: &str| -> Vec<u64> {
        let Some(section) = file.section_by_name(section) else {
            return Vec::new();
        };
        let Ok(data) = section.data() else {
            return Vec::new();
        };
        let start = section.address();
        (0..data.len() as u64 / 4)
            .filter_map(|index| walk.relative(start.wrapping_add(index * 4)))
            .collect()
    };

    let mut seen = std::collections::BTreeSet::new();
    for descriptor in records("__swift5_types") {
        if !seen.insert(descriptor) {
            continue;
        }
        let Some(flags) = walk.img.read_u32(descriptor.wrapping_add(layout::FLAGS)) else {
            continue;
        };
        let kind = match flags & layout::KIND_MASK {
            layout::KIND_CLASS => SwiftKind::Class,
            layout::KIND_STRUCT => SwiftKind::Struct,
            layout::KIND_ENUM => SwiftKind::Enum,
            _ => continue,
        };
        let Some(name) = walk.qualified_name(descriptor) else {
            continue;
        };
        let module = walk.module_of(descriptor).unwrap_or_default();
        let fields = walk
            .relative(descriptor.wrapping_add(layout::FIELDS))
            .map(|fields| walk.fields_at(fields))
            .unwrap_or_default();
        let (superclass, methods) = if kind == SwiftKind::Class {
            (
                walk.relative(descriptor.wrapping_add(layout::CLASS_SUPERCLASS))
                    .and_then(|name| walk.type_name_at(name)),
                walk.methods_at(descriptor, flags),
            )
        } else {
            (None, Vec::new())
        };
        metadata.types.push(SwiftType {
            address: descriptor,
            kind,
            name,
            module,
            generic: flags & layout::IS_GENERIC != 0,
            superclass,
            fields,
            methods,
            protocols: Vec::new(),
        });
    }

    for descriptor in records("__swift5_protos") {
        let Some(flags) = walk.img.read_u32(descriptor.wrapping_add(layout::FLAGS)) else {
            continue;
        };
        if flags & layout::KIND_MASK != layout::KIND_PROTOCOL {
            continue;
        }
        let Some(name) = walk.qualified_name(descriptor) else {
            continue;
        };
        metadata.protocols.push(SwiftProtocol {
            address: descriptor,
            name,
            requirements: walk
                .img
                .read_u32(descriptor.wrapping_add(layout::PROTOCOL_NUM_REQUIREMENTS))
                .unwrap_or(0),
        });
    }

    // The conformances: each names a type and a protocol; the protocol may
    // be another image's, bound at load, and then names nothing here.
    let type_index: HashMap<u64, usize> = metadata
        .types
        .iter()
        .enumerate()
        .map(|(index, ty)| (ty.address, index))
        .collect();
    for conformance in records("__swift5_proto") {
        let Some(flags) = walk
            .img
            .read_u32(conformance.wrapping_add(layout::CONFORMANCE_FLAGS))
        else {
            continue;
        };
        let type_kind =
            (flags >> layout::CONFORMANCE_TYPE_KIND_SHIFT) & layout::CONFORMANCE_TYPE_KIND_MASK;
        let type_descriptor = match type_kind {
            0 => walk.relative(conformance.wrapping_add(layout::CONFORMANCE_TYPE)),
            1 => walk
                .relative(conformance.wrapping_add(layout::CONFORMANCE_TYPE))
                .and_then(|slot| walk.img.read_ptr(slot))
                .filter(|pointer| *pointer != 0),
            _ => None,
        };
        let Some(type_descriptor) = type_descriptor else {
            continue;
        };
        let Some(protocol) = walk
            .relative_indirectable(conformance.wrapping_add(layout::CONFORMANCE_PROTOCOL))
            .and_then(|protocol| walk.qualified_name(protocol))
        else {
            continue;
        };
        if let Some(ty) = type_index
            .get(&type_descriptor)
            .and_then(|index| metadata.types.get_mut(*index))
        {
            if !ty.protocols.contains(&protocol) {
                ty.protocols.push(protocol);
            }
        }
    }

    (!metadata.is_empty()).then_some(metadata)
}
