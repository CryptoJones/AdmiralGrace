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
//! The reading of classes is kuna's (`analyzers::objc`), the same walk its
//! decompiler takes; method lists, categories and protocols are walked here
//! by the runtime's own layouts, since a protocol's methods have no code and
//! kuna's walk keeps only methods with some. The pointers are read as the
//! file holds them, so an image whose pointers are chained fixups — arm64e —
//! reads nothing here yet.

use std::collections::BTreeMap;

use kuna_analysis::analyzers::objc::classt;
use kuna_analysis::analyzers::objc::sections::MachoImage;
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
}

/// The layouts of the runtime's records the kuna walk does not reach, for a
/// 64-bit image: byte offsets of the fields read.
mod layout {
    /// `class_t.superclass`.
    pub const CLASS_SUPERCLASS: u64 = 0x08;
    /// `class_ro_t.baseProtocols`.
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
    /// No real list is longer: a bound on a corrupt count.
    pub const MOST_IN_A_LIST: u64 = 4096;
    /// `method_list_t`: entsize and flags, count, then the entries.
    pub const METHOD_LIST_ENTSIZE_AND_FLAGS: u64 = 0x00;
    pub const METHOD_LIST_COUNT: u64 = 0x04;
    pub const METHOD_LIST_FIRST: u64 = 0x08;
    /// The flag that says the entries are relative offsets, not pointers.
    pub const METHOD_LIST_RELATIVE: u32 = 0x8000_0000;
}

/// The methods of a `method_list_t` at `list`: each entry a selector, a
/// type encoding and an implementation, as three pointers in the classic
/// layout, or as three offsets from each field's own address in the
/// relative one — where the selector offset reaches a selector reference,
/// a pointer to the string. A protocol's entries have no implementation.
fn method_list(img: &MachoImage, list: u64) -> Vec<ObjcMethod> {
    let mut methods = Vec::new();
    if list == 0 {
        return methods;
    }
    let (Some(ent), Some(count)) = (
        img.read_u32(list.wrapping_add(layout::METHOD_LIST_ENTSIZE_AND_FLAGS)),
        img.read_u32(list.wrapping_add(layout::METHOD_LIST_COUNT)),
    ) else {
        return methods;
    };
    let relative = ent & layout::METHOD_LIST_RELATIVE != 0;
    let entsize = u64::from(ent & 0xffff);
    if entsize == 0 {
        return methods;
    }
    let cstr = |pointer: u64| (pointer != 0).then(|| img.read_cstr(pointer)).flatten();
    for index in 0..u64::from(count).min(layout::MOST_IN_A_LIST) {
        let entry = list.wrapping_add(layout::METHOD_LIST_FIRST + index * entsize);
        let (selector, types, imp) = if relative {
            let field = |offset: u64| -> Option<u64> {
                let at = entry.wrapping_add(offset);
                let delta = img.read_i32(at)?;
                (delta != 0).then(|| at.wrapping_add(delta as i64 as u64))
            };
            (
                field(0)
                    .and_then(|selref| img.read_ptr(selref))
                    .and_then(cstr),
                field(4).and_then(cstr),
                field(8),
            )
        } else {
            (
                img.read_ptr(entry).and_then(cstr),
                img.read_ptr(entry.wrapping_add(8)).and_then(cstr),
                img.read_ptr(entry.wrapping_add(16)).filter(|imp| *imp != 0),
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

/// Read the Objective-C metadata of the Mach-O `bytes` are, when they are
/// one and it carries any; `None` for any other file, and for a Mach-O
/// with no Objective-C in it.
pub fn read(bytes: &[u8]) -> Option<ObjcMetadata> {
    let file = object::File::parse(bytes).ok()?;
    if file.format() != object::BinaryFormat::MachO || !file.is_64() {
        return None;
    }
    let img = MachoImage::new(&file);
    let mut metadata = ObjcMetadata::default();

    let pointers = |section: &str| -> Vec<u64> {
        let Some(section) = file.section_by_name(section) else {
            return Vec::new();
        };
        let Ok(data) = section.data() else {
            return Vec::new();
        };
        data.as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .filter(|pointer| *pointer != 0)
            .collect()
    };
    let methods_at = |list: u64| -> Vec<ObjcMethod> { method_list(&img, list) };
    let class_name_at = |class: u64| -> Option<String> {
        if class == 0 {
            return None;
        }
        let class = classt::read_class_t(&img, class)?;
        classt::class_name(&img, class.ro)
    };
    let protocol_name_at = |protocol: u64| -> Option<String> {
        if protocol == 0 {
            return None;
        }
        let name = img.read_ptr(protocol.wrapping_add(layout::PROTOCOL_NAME))?;
        if name == 0 {
            return None;
        }
        img.read_cstr(name)
    };
    // A `protocol_list_t`: a count, then that many `protocol_t*`.
    let protocol_names_at = |list: u64| -> Vec<String> {
        if list == 0 {
            return Vec::new();
        }
        let Some(count) = img.read_ptr(list) else {
            return Vec::new();
        };
        (0..count.min(layout::MOST_IN_A_LIST))
            .filter_map(|index| img.read_ptr(list.wrapping_add(8 + index * 8)))
            .filter_map(protocol_name_at)
            .collect()
    };

    for class_ptr in pointers("__objc_classlist") {
        let Some(class) = classt::read_class_t(&img, class_ptr) else {
            continue;
        };
        let Some(name) = classt::class_name(&img, class.ro) else {
            continue;
        };
        let superclass = img
            .read_ptr(class.addr.wrapping_add(layout::CLASS_SUPERCLASS))
            .and_then(class_name_at);
        let protocols = img
            .read_ptr(class.ro.wrapping_add(layout::RO_BASE_PROTOCOLS))
            .map(protocol_names_at)
            .unwrap_or_default();
        let instance_methods = classt::base_methods(&img, class.ro)
            .map(methods_at)
            .unwrap_or_default();
        let class_methods = classt::metaclass_ro(&img, class.isa)
            .and_then(|meta_ro| classt::base_methods(&img, meta_ro))
            .map(methods_at)
            .unwrap_or_default();
        let ivars = classt::base_ivars(&img, class.ro)
            .map(|list| {
                classt::walk_ivar_list(&img, list)
                    .into_iter()
                    .map(|ivar| ObjcIvar {
                        name: ivar.name,
                        types: ivar.types,
                        offset: (ivar.offset_va != 0)
                            .then(|| img.read_u32(ivar.offset_va))
                            .flatten(),
                    })
                    .collect()
            })
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
        let Some(name) = img
            .read_ptr(category.wrapping_add(layout::CATEGORY_NAME))
            .filter(|name| *name != 0)
            .and_then(|name| img.read_cstr(name))
        else {
            continue;
        };
        let class = img
            .read_ptr(category.wrapping_add(layout::CATEGORY_CLASS))
            .and_then(class_name_at);
        let field = |offset: u64| img.read_ptr(category.wrapping_add(offset)).unwrap_or(0);
        metadata.categories.push(ObjcCategory {
            address: category,
            name,
            class,
            protocols: protocol_names_at(field(layout::CATEGORY_PROTOCOLS)),
            instance_methods: methods_at(field(layout::CATEGORY_INSTANCE_METHODS)),
            class_methods: methods_at(field(layout::CATEGORY_CLASS_METHODS)),
        });
    }

    for protocol in pointers("__objc_protolist") {
        let Some(name) = protocol_name_at(protocol) else {
            continue;
        };
        let field = |offset: u64| img.read_ptr(protocol.wrapping_add(offset)).unwrap_or(0);
        metadata.protocols.push(ObjcProtocol {
            address: protocol,
            name,
            protocols: protocol_names_at(field(layout::PROTOCOL_PROTOCOLS)),
            instance_methods: methods_at(field(layout::PROTOCOL_INSTANCE_METHODS)),
            class_methods: methods_at(field(layout::PROTOCOL_CLASS_METHODS)),
            optional_instance_methods: methods_at(field(
                layout::PROTOCOL_OPTIONAL_INSTANCE_METHODS,
            )),
            optional_class_methods: methods_at(field(layout::PROTOCOL_OPTIONAL_CLASS_METHODS)),
        });
    }

    (!metadata.is_empty()).then_some(metadata)
}
