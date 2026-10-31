//! The Objective-C metadata a Mach-O carries, read from the image itself.
//!
//! An Objective-C binary describes its classes, categories and protocols in
//! the `__objc_*` sections, for the runtime to register at load: each class
//! names itself, its superclass, its protocols, its instance variables and
//! its methods — each method its selector, its type encoding and the address
//! of its implementation. That is what names a method's code `-[Class sel]`
//! or `+[Class sel]`, symbols or none, and what an analyst reads a class's
//! shape from.
//!
//! The image is read through kuna's view of a Mach-O (`analyzers::objc`),
//! with its chained fixups resolved first — every Mach-O linked for macOS 12
//! or iOS 15 and later holds its pointers as packed fixup chains, not
//! addresses, and so did arm64e before that — so each slot dereferences to
//! the address it will hold once loaded. The records themselves are walked
//! here by the runtime's own layouts, since a protocol's methods have no
//! code and kuna's walk keeps only methods with some. A slot bound to
//! another image at load — a superclass or a category's class in a
//! framework — resolves to nothing, and the thing it names is left unnamed.
//!
//! Every count and every string is bounded, since the records are read from
//! an untrusted file: no list is read past [`ObjcMetadata::MOST_IN_A_LIST`]
//! entries, no image past [`ObjcMetadata::MOST_METHODS`] methods, and no
//! name past [`ObjcMetadata::LONGEST_NAME`] bytes.

use std::cell::Cell;
use std::collections::BTreeMap;

use kuna_analysis::analyzers::objc::classt;
use kuna_analysis::analyzers::objc::sections::MachoImage;
use kuna_analysis::loader::format::macho::resolve_chained_fixups;
use object::read::{Object, ObjectSection};

/// One method of a class, a category or a protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcMethod {
    /// The selector: `greet:`.
    pub selector: String,
    /// The runtime's type encoding of the method, when it has one: `i20@0:8i16`.
    pub types: Option<String>,
    /// The address of the implementation; a protocol's methods have none.
    pub imp: Option<u64>,
}

/// One instance variable of a class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcIvar {
    /// Its name.
    pub name: String,
    /// The runtime's type encoding, when it has one: `#`, `i`, `@"Base"`.
    pub types: Option<String>,
    /// Its offset into an instance, when the image holds it.
    pub offset: Option<u32>,
}

/// One class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcClass {
    /// The address of the class object (`OBJC_CLASS_$_Name`).
    pub address: u64,
    /// Its name.
    pub name: String,
    /// Its superclass, when the image holds it; a superclass in another
    /// image is bound at load, and is not named here.
    pub superclass: Option<String>,
    /// The protocols it adopts.
    pub protocols: Vec<String>,
    /// Its instance methods (`-`).
    pub instance_methods: Vec<ObjcMethod>,
    /// Its class methods (`+`), from the metaclass.
    pub class_methods: Vec<ObjcMethod>,
    /// Its instance variables.
    pub ivars: Vec<ObjcIvar>,
}

/// One category: methods added to a class, this image's or another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcCategory {
    /// The address of the category record.
    pub address: u64,
    /// The category's name: `Extra` in `Base(Extra)`.
    pub name: String,
    /// The class the category is on, when the image holds it.
    pub class: Option<String>,
    /// The protocols it adopts.
    pub protocols: Vec<String>,
    /// Its instance methods (`-`).
    pub instance_methods: Vec<ObjcMethod>,
    /// Its class methods (`+`).
    pub class_methods: Vec<ObjcMethod>,
}

/// One protocol: selectors a class promises, with no code of their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcProtocol {
    /// The address of the protocol record.
    pub address: u64,
    /// Its name.
    pub name: String,
    /// The protocols it adopts.
    pub protocols: Vec<String>,
    /// Required instance methods.
    pub instance_methods: Vec<ObjcMethod>,
    /// Required class methods.
    pub class_methods: Vec<ObjcMethod>,
    /// Optional instance methods.
    pub optional_instance_methods: Vec<ObjcMethod>,
    /// Optional class methods.
    pub optional_class_methods: Vec<ObjcMethod>,
}

/// Everything the image says about its Objective-C.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjcMetadata {
    /// The classes, in the order of `__objc_classlist`.
    pub classes: Vec<ObjcClass>,
    /// The categories, in the order of `__objc_catlist`.
    pub categories: Vec<ObjcCategory>,
    /// The protocols, in the order of `__objc_protolist`.
    pub protocols: Vec<ObjcProtocol>,
}

impl ObjcMetadata {
    /// Whether the image says nothing of Objective-C.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.categories.is_empty() && self.protocols.is_empty()
    }

    /// The name of each method's implementation, by its address: `-[Base
    /// twice:]`, `+[Base answer]`, `-[Base(Extra) thrice:]` — the first name
    /// an address gets is kept. A category on a class the image does not
    /// hold names the class `?`.
    pub fn method_names(&self) -> BTreeMap<u64, String> {
        let mut names = BTreeMap::new();
        let mut name = |kind: char, owner: &str, methods: &[ObjcMethod]| {
            for method in methods {
                if let Some(imp) = method.imp {
                    names
                        .entry(imp)
                        .or_insert_with(|| format!("{kind}[{owner} {}]", method.selector));
                }
            }
        };
        for class in &self.classes {
            name('-', &class.name, &class.instance_methods);
            name('+', &class.name, &class.class_methods);
        }
        for category in &self.categories {
            let owner = format!(
                "{}({})",
                category.class.as_deref().unwrap_or("?"),
                category.name
            );
            name('-', &owner, &category.instance_methods);
            name('+', &owner, &category.class_methods);
        }
        names
    }

    /// The class objects, by address: `OBJC_CLASS_$_Name`, the data a class
    /// is to the loader.
    pub fn class_symbols(&self) -> Vec<(u64, String)> {
        self.classes
            .iter()
            .map(|class| (class.address, format!("OBJC_CLASS_$_{}", class.name)))
            .collect()
    }

    /// Move every address — the class objects, the categories, the protocols
    /// and the methods' implementations — by `delta`, as when the image is
    /// read at another base.
    pub fn shift(&mut self, delta: u64) {
        let shift = |address: &mut u64| *address = address.wrapping_add(delta);
        let shift_methods = |methods: &mut Vec<ObjcMethod>| {
            for method in methods {
                if let Some(imp) = &mut method.imp {
                    shift(imp);
                }
            }
        };
        for class in &mut self.classes {
            shift(&mut class.address);
            shift_methods(&mut class.instance_methods);
            shift_methods(&mut class.class_methods);
        }
        for category in &mut self.categories {
            shift(&mut category.address);
            shift_methods(&mut category.instance_methods);
            shift_methods(&mut category.class_methods);
        }
        for protocol in &mut self.protocols {
            shift(&mut protocol.address);
            shift_methods(&mut protocol.instance_methods);
            shift_methods(&mut protocol.class_methods);
            shift_methods(&mut protocol.optional_instance_methods);
            shift_methods(&mut protocol.optional_class_methods);
        }
    }

    /// The size of a class object (`class_t`) in a 64-bit image: the extent
    /// of the data symbol `OBJC_CLASS_$_Name`.
    pub const CLASS_OBJECT_SIZE: u64 = 0x28;
    /// No real list is longer: a bound on a corrupt count.
    pub const MOST_IN_A_LIST: u64 = 4096;
    /// No real image holds more methods: a bound on the lists of a crafted
    /// one, across every class, category and protocol.
    pub const MOST_METHODS: usize = 1 << 20;
    /// No real name — a class, a selector, a type encoding — is longer: a
    /// bound on a pointer into a crafted string section.
    pub const LONGEST_NAME: usize = 4096;
}

/// The layouts of the runtime's records, for a 64-bit image: byte offsets
/// of the fields read.
mod layout {
    /// `class_t.superclass`.
    pub const CLASS_SUPERCLASS: u64 = 0x08;
    /// `class_ro_t`: name, baseProtocols.
    pub const RO_NAME: u64 = 0x18;
    pub const RO_BASE_PROTOCOLS: u64 = 0x28;
    /// `category_t`: name, cls, instanceMethods, classMethods, protocols.
    pub const CATEGORY_NAME: u64 = 0x00;
    pub const CATEGORY_CLASS: u64 = 0x08;
    pub const CATEGORY_INSTANCE_METHODS: u64 = 0x10;
    pub const CATEGORY_CLASS_METHODS: u64 = 0x18;
    pub const CATEGORY_PROTOCOLS: u64 = 0x20;
    /// `protocol_t`: isa, mangledName, protocols, instanceMethods,
    /// classMethods, optionalInstanceMethods, optionalClassMethods.
    pub const PROTOCOL_NAME: u64 = 0x08;
    pub const PROTOCOL_PROTOCOLS: u64 = 0x10;
    pub const PROTOCOL_INSTANCE_METHODS: u64 = 0x18;
    pub const PROTOCOL_CLASS_METHODS: u64 = 0x20;
    pub const PROTOCOL_OPTIONAL_INSTANCE_METHODS: u64 = 0x28;
    pub const PROTOCOL_OPTIONAL_CLASS_METHODS: u64 = 0x30;
    /// `method_list_t` and `ivar_list_t`: entsize and flags, count, then the
    /// entries.
    pub const LIST_ENTSIZE_AND_FLAGS: u64 = 0x00;
    pub const LIST_COUNT: u64 = 0x04;
    pub const LIST_FIRST: u64 = 0x08;
    /// The runtime's mask of the entsize word: the low two bits and the high
    /// sixteen are flags.
    pub const LIST_ENTSIZE_MASK: u32 = !0xffff_0003;
    /// The flag that says a method list's entries are relative offsets, not
    /// pointers.
    pub const METHOD_LIST_RELATIVE: u32 = 0x8000_0000;
    /// The least entsize of a method: three pointers, or three offsets.
    pub const METHOD_SIZE: u64 = 24;
    pub const RELATIVE_METHOD_SIZE: u64 = 12;
    /// `ivar_t`: a pointer to the offset, the name, the type, then the
    /// alignment and the size.
    pub const IVAR_OFFSET: u64 = 0x00;
    pub const IVAR_NAME: u64 = 0x08;
    pub const IVAR_TYPE: u64 = 0x10;
    pub const IVAR_SIZE: u64 = 32;
}

/// The image under the walk: kuna's view of its sections with the chained
/// fixups resolved, and the count of methods read so far, against the bound.
struct Walk<'a> {
    img: MachoImage<'a>,
    methods: Cell<usize>,
}

impl Walk<'_> {
    /// The pointer-sized word at `at`, when it is mapped and not null.
    fn pointer(&self, at: u64) -> Option<u64> {
        self.img.read_ptr(at).filter(|pointer| *pointer != 0)
    }

    /// The NUL-terminated string at `pointer`, when it is mapped, ends within
    /// [`ObjcMetadata::LONGEST_NAME`] bytes and is UTF-8. Read in one piece
    /// where the section has that many bytes left, byte by byte near its end.
    fn name_at(&self, pointer: u64) -> Option<String> {
        if pointer == 0 {
            return None;
        }
        let text = match self.img.read(pointer, ObjcMetadata::LONGEST_NAME) {
            Some(bytes) => {
                let end = bytes.iter().position(|byte| *byte == 0)?;
                std::str::from_utf8(&bytes[..end]).ok()?.to_string()
            }
            None => {
                let mut bytes = Vec::new();
                loop {
                    if bytes.len() >= ObjcMetadata::LONGEST_NAME {
                        return None;
                    }
                    let at = pointer.wrapping_add(bytes.len() as u64);
                    match self.img.read(at, 1)?[0] {
                        0 => break,
                        byte => bytes.push(byte),
                    }
                }
                String::from_utf8(bytes).ok()?
            }
        };
        Some(text)
    }

    /// The header of a `method_list_t` or `ivar_list_t` at `list`: the
    /// entsize, and the count bounded by [`ObjcMetadata::MOST_IN_A_LIST`].
    fn list_header(&self, list: u64) -> Option<(u32, u64)> {
        let ent = self
            .img
            .read_u32(list.wrapping_add(layout::LIST_ENTSIZE_AND_FLAGS))?;
        let count = self.img.read_u32(list.wrapping_add(layout::LIST_COUNT))?;
        Some((ent, u64::from(count).min(ObjcMetadata::MOST_IN_A_LIST)))
    }

    /// The methods of a `method_list_t` at `list`: each entry a selector, a
    /// type encoding and an implementation, as three pointers in the classic
    /// layout, or as three offsets from each field's own address in the
    /// relative one — where the selector offset reaches a selector reference,
    /// a pointer to the string. A protocol's entries have no implementation.
    /// Nothing is read once the image's methods pass the bound.
    fn method_list(&self, list: u64) -> Vec<ObjcMethod> {
        let mut methods = Vec::new();
        if list == 0 {
            return methods;
        }
        let Some((ent, count)) = self.list_header(list) else {
            return methods;
        };
        let relative = ent & layout::METHOD_LIST_RELATIVE != 0;
        let entsize = u64::from(ent & layout::LIST_ENTSIZE_MASK);
        let least = if relative {
            layout::RELATIVE_METHOD_SIZE
        } else {
            layout::METHOD_SIZE
        };
        if entsize < least {
            return methods;
        }
        for index in 0..count {
            if self.methods.get() >= ObjcMetadata::MOST_METHODS {
                break;
            }
            self.methods.set(self.methods.get() + 1);
            let entry = list.wrapping_add(layout::LIST_FIRST + index * entsize);
            let (selector, types, imp) = if relative {
                let field = |offset: u64| -> Option<u64> {
                    let at = entry.wrapping_add(offset);
                    let delta = self.img.read_i32(at)?;
                    (delta != 0).then(|| at.wrapping_add(delta as i64 as u64))
                };
                (
                    field(0)
                        .and_then(|selref| self.pointer(selref))
                        .and_then(|name| self.name_at(name)),
                    field(4).and_then(|types| self.name_at(types)),
                    field(8),
                )
            } else {
                (
                    self.pointer(entry).and_then(|name| self.name_at(name)),
                    self.pointer(entry.wrapping_add(8))
                        .and_then(|types| self.name_at(types)),
                    self.pointer(entry.wrapping_add(16)),
                )
            };
            let Some(selector) = selector else { continue };
            methods.push(ObjcMethod {
                selector,
                types,
                imp,
            });
        }
        methods
    }

    /// The instance variables of an `ivar_list_t` at `list`: each a pointer
    /// to the offset the runtime keeps, a name and a type encoding.
    fn ivar_list(&self, list: u64) -> Vec<ObjcIvar> {
        let mut ivars = Vec::new();
        if list == 0 {
            return ivars;
        }
        let Some((ent, count)) = self.list_header(list) else {
            return ivars;
        };
        let entsize = u64::from(ent & layout::LIST_ENTSIZE_MASK);
        if entsize < layout::IVAR_SIZE {
            return ivars;
        }
        for index in 0..count {
            let entry = list.wrapping_add(layout::LIST_FIRST + index * entsize);
            let Some(name) = self
                .pointer(entry.wrapping_add(layout::IVAR_NAME))
                .and_then(|name| self.name_at(name))
            else {
                continue;
            };
            ivars.push(ObjcIvar {
                name,
                types: self
                    .pointer(entry.wrapping_add(layout::IVAR_TYPE))
                    .and_then(|types| self.name_at(types)),
                offset: self
                    .pointer(entry.wrapping_add(layout::IVAR_OFFSET))
                    .and_then(|offset| self.img.read_u32(offset)),
            });
        }
        ivars
    }

    /// The name of the class object at `class`, when the image holds it: a
    /// class of another image is bound at load, and its slot reads as
    /// nothing here.
    fn class_name_at(&self, class: u64) -> Option<String> {
        if class == 0 {
            return None;
        }
        let class = classt::read_class_t(&self.img, class)?;
        self.pointer(class.ro.wrapping_add(layout::RO_NAME))
            .and_then(|name| self.name_at(name))
    }

    /// The name of the protocol at `protocol`.
    fn protocol_name_at(&self, protocol: u64) -> Option<String> {
        if protocol == 0 {
            return None;
        }
        self.pointer(protocol.wrapping_add(layout::PROTOCOL_NAME))
            .and_then(|name| self.name_at(name))
    }

    /// The names of a `protocol_list_t` at `list`: a count, then that many
    /// `protocol_t*`.
    fn protocol_names_at(&self, list: u64) -> Vec<String> {
        if list == 0 {
            return Vec::new();
        }
        let Some(count) = self.img.read_ptr(list) else {
            return Vec::new();
        };
        (0..count.min(ObjcMetadata::MOST_IN_A_LIST))
            .filter_map(|index| self.pointer(list.wrapping_add(8 + index * 8)))
            .filter_map(|protocol| self.protocol_name_at(protocol))
            .collect()
    }
}

/// Read the Objective-C metadata of the Mach-O `bytes` are, when they are
/// one and it carries any; `None` for any other file, and for a Mach-O
/// with no Objective-C in it.
pub fn read(bytes: &[u8]) -> Option<ObjcMetadata> {
    let file = object::File::parse(bytes).ok()?;
    if file.format() != object::BinaryFormat::MachO || !file.is_64() {
        return None;
    }
    let walk = Walk {
        img: MachoImage::with_fixups(&file, resolve_chained_fixups(&file, bytes)),
        methods: Cell::new(0),
    };
    let mut metadata = ObjcMetadata::default();

    // The pointers a `__objc_*list` section holds, each read through the
    // fixups, as many as the file has bytes for.
    let pointers = |section: &str| -> Vec<u64> {
        let Some(section) = file.section_by_name(section) else {
            return Vec::new();
        };
        let Ok(data) = section.data() else {
            return Vec::new();
        };
        let start = section.address();
        (0..data.len() as u64 / 8)
            .filter_map(|index| walk.pointer(start.wrapping_add(index * 8)))
            .collect()
    };

    for class_ptr in pointers("__objc_classlist") {
        let Some(class) = classt::read_class_t(&walk.img, class_ptr) else {
            continue;
        };
        let Some(name) = walk.class_name_at(class_ptr) else {
            continue;
        };
        let superclass = walk
            .pointer(class.addr.wrapping_add(layout::CLASS_SUPERCLASS))
            .and_then(|superclass| walk.class_name_at(superclass));
        let protocols = walk
            .pointer(class.ro.wrapping_add(layout::RO_BASE_PROTOCOLS))
            .map(|list| walk.protocol_names_at(list))
            .unwrap_or_default();
        let instance_methods = classt::base_methods(&walk.img, class.ro)
            .map(|list| walk.method_list(list))
            .unwrap_or_default();
        let class_methods = classt::metaclass_ro(&walk.img, class.isa)
            .and_then(|meta_ro| classt::base_methods(&walk.img, meta_ro))
            .map(|list| walk.method_list(list))
            .unwrap_or_default();
        let ivars = classt::base_ivars(&walk.img, class.ro)
            .map(|list| walk.ivar_list(list))
            .unwrap_or_default();
        metadata.classes.push(ObjcClass {
            address: class.addr,
            name,
            superclass,
            protocols,
            instance_methods,
            class_methods,
            ivars,
        });
    }

    for category in pointers("__objc_catlist") {
        let field = |offset: u64| walk.pointer(category.wrapping_add(offset)).unwrap_or(0);
        let Some(name) = walk.name_at(field(layout::CATEGORY_NAME)) else {
            continue;
        };
        metadata.categories.push(ObjcCategory {
            address: category,
            name,
            class: walk.class_name_at(field(layout::CATEGORY_CLASS)),
            protocols: walk.protocol_names_at(field(layout::CATEGORY_PROTOCOLS)),
            instance_methods: walk.method_list(field(layout::CATEGORY_INSTANCE_METHODS)),
            class_methods: walk.method_list(field(layout::CATEGORY_CLASS_METHODS)),
        });
    }

    for protocol in pointers("__objc_protolist") {
        let Some(name) = walk.protocol_name_at(protocol) else {
            continue;
        };
        let field = |offset: u64| walk.pointer(protocol.wrapping_add(offset)).unwrap_or(0);
        metadata.protocols.push(ObjcProtocol {
            address: protocol,
            name,
            protocols: walk.protocol_names_at(field(layout::PROTOCOL_PROTOCOLS)),
            instance_methods: walk.method_list(field(layout::PROTOCOL_INSTANCE_METHODS)),
            class_methods: walk.method_list(field(layout::PROTOCOL_CLASS_METHODS)),
            optional_instance_methods: walk
                .method_list(field(layout::PROTOCOL_OPTIONAL_INSTANCE_METHODS)),
            optional_class_methods: walk
                .method_list(field(layout::PROTOCOL_OPTIONAL_CLASS_METHODS)),
        });
    }

    (!metadata.is_empty()).then_some(metadata)
}
