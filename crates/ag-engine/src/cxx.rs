//! C++ classes, their vtables and the names their templates spell.
//!
//! A C++ class the image holds names itself in the symbols its code
//! carries: the constructor and the methods say the class they belong
//! to, `base::f(int)`, and a vtable stands beside them. On ELF and
//! Mach-O a class's vtable is `_ZTV<class>`, its type information
//! `_ZTI<class>` and the name string the type information holds
//! `_ZTS<class>`; on a Windows (PE) image the vtable is
//! ``??_7<class>@@6B@`` and the type information ``??_R0?<class>@@@8``.
//! The vtable's words, after the offset to the top of its hierarchy and
//! the pointer to that type information, hold the addresses of the
//! implementations — one per virtual function, in the order the class
//! declares them. The type information carries the hierarchy: the
//! Itanium `si_class_type_info` (`_ZTI<class>`, three words) names the
//! single base; `vmi_class_type_info` packs the base count and, per
//! base, its type information with flags (public at bit 1, virtual at
//! bit 0) and the offset words, the signed offset above the pointer
//! and the offset to the top below. The Microsoft descriptor
//! ``??_R0?<class>@@@8`` names the class as `.?AV<class>@@`; the
//! complete object locator ``??_R4<class>@@6B@`` points at the
//! hierarchy descriptor, whose base-class array names every base with
//! its virtual disposition, displacement, protected displacement and
//! attributes (access at bits 0..=1, virtual at bit 3). A vtable with
//! several bases stands as several groups: the primary at the vtable
//! symbol, then one per secondary base, each headed by its offset to
//! the top and the type information of the base the group belongs to.
//! An image that holds no such symbols has no classes to speak of.
//!
//! [`CppMetadata`] is that reading: every class the image names, its
//! vtable's address, its type information's and its constructor's when
//! the image holds them, the base classes the RTTI names, the vtable's
//! groups, and the virtual functions in the order the vtable holds
//! them, each with the implementation it points at. It is read from the
//! image's bytes the way the Objective-C metadata is
//! ([`crate::objc`]), and kept on the
//! [`Image`](crate::image::Image) behind the same kind of one-cell
//! cache.
//!
//! [`simplify_template_name`] reads the other way a name is spelled: a
//! template instance's mangled name demangles with every argument
//! spelled out — `geometry::twice<int>(int)`,
//! `std::vector<std::pair<int, double>>` — where the code that calls it
//! The simplifier keeps those arguments whole, nested templates the same
//! way, with each `< >` pair spaced as the demangler spaces it:
//! `vector< std::pair< int, double > >` for the vector's, `std::pair< int,
//! double >` for the pair's.

use std::collections::BTreeMap;

use object::read::{Object, ObjectSection, ObjectSymbol};

/// The bounds a crafted image may not make this reader run past.
impl CppMetadata {
    /// No image holds more classes than this.
    pub const MOST_CLASSES: usize = 10_000;
    /// No vtable holds more slots than this.
    pub const MOST_SLOTS: usize = 1_000;
    /// No name is read past this many bytes.
    pub const LONGEST_NAME: usize = 4_096;
}

/// One virtual function of a class, as the class's vtable holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vfunc {
    /// The function's name, as its symbol demangles it: `derived::f(int)`.
    pub name: String,
    /// The implementation the slot holds, when it holds one: a function
    /// the image holds, or one bound at load. `None` for an empty slot.
    pub implementation: Option<u64>,
    /// The slot's, counted from the first virtual function, 0.
    pub slot: usize,
}

/// One group of a vtable: the slots one base class of the hierarchy
/// occupies. The primary group stands at the vtable symbol itself; each
/// secondary base follows, headed by its own offset to the top.
/// `offset_to_top` is the `this` adjustment that group applies, as the
/// header spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtableGroup {
    /// The address of the group's header — the primary group is the
    /// vtable's own address.
    pub address: u64,
    /// The offset to the top, as the group's header holds it: 0 for the
    /// primary, negative for a secondary base.
    pub offset_to_top: i64,
    /// Whose table the group is. The ABI stores the derived class's type
    /// information in every group header — the primary and each secondary
    /// alike — so this is the derived class for all of them.
    pub owner: String,
    /// The slots' indices into the class's vtable entries, in order.
    pub slots: Vec<usize>,
}

/// One base class the RTTI names, with how `this` reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RttiBase {
    /// The base class, as its type information names it.
    pub class: String,
    /// The offset of the base in the object, as the RTTI holds it: the
    /// primary base at 0, each secondary at its displacement.
    pub offset: i64,
    /// Whether the base is public (#375 reads the flag the ABI sets).
    pub is_public: bool,
    /// Whether the base is virtual: the subobject is shared.
    pub is_virtual: bool,
}

/// One C++ class the image names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppClass {
    /// The address of the class's vtable (`_ZTV<class>`), when the
    /// image holds one.
    pub vtable: Option<u64>,
    /// The class's name, as its symbols demangle it: `base`,
    /// `geometry::Shape`.
    pub name: String,
    /// The vtable's entries, in order, when the class has one.
    pub vfuncs: Vec<Vfunc>,
    /// The address of the type information (`_ZTI<class>`), when the
    /// image holds one.
    pub type_info: Option<u64>,
    /// The address of the constructor (`<class>::<class>`), when the
    /// image holds one.
    pub constructor: Option<u64>,
    /// The base classes the RTTI names, in RTTI order, each with its
    /// offset, access and virtual flags.
    pub base_classes: Vec<RttiBase>,
    /// The vtable's groups: the primary group first, then one per
    /// secondary base.
    pub vtable_groups: Vec<VtableGroup>,
}

/// The C++ classes an image carries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppMetadata {
    /// The classes, by name, in the order their vtable symbols are read.
    pub classes: BTreeMap<String, CppClass>,
    /// The addresses the classes' vtables hold, by the slot's address:
    /// which class and which index.
    pub vtable_refs: BTreeMap<u64, (String, usize)>,
    /// The symbols the vtables point at, by address: the demangled name
    /// of each virtual function the image holds.
    pub vfunc_names: BTreeMap<u64, String>,
}

impl CppMetadata {
    /// Move every address — the vtables, the type information, the
    /// constructors, the slots and the implementations — by `delta`, as
    /// when the image is read at another base.
    pub fn shift(&mut self, delta: u64) {
        let shift_opt = |address: &mut Option<u64>| {
            if let Some(addr) = address {
                *addr = addr.wrapping_add(delta);
            }
        };
        for class in self.classes.values_mut() {
            shift_opt(&mut class.vtable);
            shift_opt(&mut class.type_info);
            shift_opt(&mut class.constructor);
            for vfunc in &mut class.vfuncs {
                shift_opt(&mut vfunc.implementation);
            }
            for group in &mut class.vtable_groups {
                group.address = group.address.wrapping_add(delta);
            }
        }
        self.vtable_refs = std::mem::take(&mut self.vtable_refs)
            .into_iter()
            .map(|(addr, value)| (addr.wrapping_add(delta), value))
            .collect();
        self.vfunc_names = std::mem::take(&mut self.vfunc_names)
            .into_iter()
            .map(|(addr, name)| (addr.wrapping_add(delta), name))
            .collect();
    }
}

/// Read the classes of the image the `object` file at `bytes` holds.
///
/// Every defined symbol is walked once: every vtable one names — an
/// Itanium `_ZTV<class>` on ELF and Mach-O, a Microsoft ``??_7`` on
/// PE — gives a class. The class's vtable slots are the words after its
/// two header words, each read as the pointer the image's data model
/// lays down, in the image's byte order, named by the symbol at the
/// address it holds. The type information's address (`_ZTI<class>`)
/// and the constructor's are noted when the image holds them. A
/// relocatable object's addresses are the linker's to place, not the
/// file's, so it has no classes.
///
/// The width and byte order come from `model`, the image's data model:
/// the slots of a vtable are pointers, and a 32-bit image's are four
/// bytes. [`read`] reads under a 64-bit little-endian model; the engine
/// reads the image's own, via
/// [`Image::cxx`](crate::image::Image::cxx).
pub fn read(bytes: &[u8]) -> Option<CppMetadata> {
    read_with_model(bytes, crate::types::DataModel::LP64, true)
}

/// Read the classes of the image under `model`: see [`read`]. `little`
/// is the image's byte order.
pub(crate) fn read_with_model(
    bytes: &[u8],
    model: crate::types::DataModel,
    little: bool,
) -> Option<CppMetadata> {
    let Ok(file) = object::File::parse(bytes) else {
        return None;
    };
    if file.kind() == object::ObjectKind::Relocatable {
        return None;
    }
    let mut symbols: Vec<(u64, String)> = Vec::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if !symbol.is_definition() {
            continue;
        }
        if !matches!(
            symbol.kind(),
            object::SymbolKind::Text | object::SymbolKind::Data | object::SymbolKind::Unknown
        ) {
            continue;
        }
        if let Ok(name) = symbol.name() {
            symbols.push((symbol.address(), name.to_string()));
        }
    }
    let mut metadata = CppMetadata::default();
    // Each table's header: the Itanium ABI's two words, or the Microsoft
    // one, which is none — a Microsoft vtable begins at its first
    // virtual function.
    let mut tables: Vec<(String, u64, usize)> = Vec::new();
    for (address, name) in &symbols {
        let Some((class, header)) = vtable_class(name) else {
            continue;
        };
        if metadata.classes.contains_key(&class) {
            continue;
        }
        let type_info = type_info_address(&symbols, &class);
        let constructor = constructor_address(&symbols, &class);
        tables.push((class.clone(), *address, header));
        metadata.classes.insert(
            class.clone(),
            CppClass {
                vtable: Some(*address),
                name: class,
                vfuncs: Vec::new(),
                type_info,
                constructor,
                base_classes: Vec::new(),
                vtable_groups: Vec::new(),
            },
        );
        if metadata.classes.len() >= CppMetadata::MOST_CLASSES {
            break;
        }
    }
    if metadata.classes.is_empty() {
        return None;
    }
    let names: BTreeMap<u64, String> = symbols
        .iter()
        .filter_map(|(address, name)| {
            // A versioned name — `@@CXXABI_1.3` — demangles under its
            // stem.
            let stem = name.split('@').next().unwrap_or(name);
            demangle_symbol(stem).map(|plain| (*address, plain))
        })
        .collect();
    // The vtable's slots are the words after its two header words, and
    // nothing says how many a table holds. The table ends where the next
    // one begins: the next vtable symbol in the same section, or the
    // section's end. A word that is no function address ends the walk
    // first — a header, a type-information address, a word past the
    // table all fail that test.
    let mut sorted: Vec<u64> = tables.iter().map(|(_, a, _)| *a).collect();
    sorted.sort_unstable();
    let mut ends: BTreeMap<u64, u64> = BTreeMap::new();
    for (i, &address) in sorted.iter().enumerate() {
        let next = sorted.get(i + 1).copied();
        ends.insert(address, next.unwrap_or(u64::MAX));
    }
    // Every type information the image names, by address: an Itanium
    // `_ZTI<class>` (two words) or Microsoft ``??_R0`` (four), the class
    // each names. A vtable header or an RTTI base entry is one of these
    // addresses, so the check is the gate for reading further.
    let mut type_infos: BTreeMap<u64, String> = BTreeMap::new();
    for (address, name) in &symbols {
        if is_type_info(name) {
            if let Some(class) = type_info_class(name) {
                type_infos.entry(*address).or_insert(class);
            }
        }
    }
    // The class names come from RTTI where the image carries it: the
    // Itanium `si`/`vmi` layout or the Microsoft hierarchy. A class with
    // no RTTI has no bases to read and one vtable group.
    let microsoft = microsoft_hierarchy_bases(bytes, &symbols, little);
    for class in metadata.classes.values_mut() {
        let mut bases = Vec::new();
        if let Some(type_info) = class.type_info {
            bases = read_rtti_bases(bytes, type_info, model, little, &type_infos);
            if bases.is_empty() {
                // The Microsoft descriptor names only the class; the
                // hierarchy is read from its locator instead.
                bases = microsoft.get(&type_info).cloned().unwrap_or_default();
            }
        }
        class.base_classes = bases;
    }
    for (class, address, header) in &tables {
        let Some(mut bytes) = section_bytes_of(bytes, *address) else {
            continue;
        };
        if let Some(&end) = ends.get(address) {
            if end != u64::MAX && end > *address {
                bytes = bytes.get(..usize::try_from(end - *address).unwrap_or(0)).unwrap_or(&[]);
            }
        }
        let width = usize::try_from(model.pointer).unwrap_or(8);
        if width != 4 && width != 8 {
            continue;
        }
        // The vtable's words are the image's own pointers: the image's
        // byte order, its width.
        let words: Vec<u64> = bytes
            .chunks(width)
            .filter_map(|slot| {
                if slot.len() != width {
                    return None;
                }
                let raw: [u8; 8] = if width == 8 {
                    slot.try_into().ok()?
                } else if little {
                    let mut wide = [0u8; 8];
                    wide[..4].copy_from_slice(&slot[..4]);
                    wide
                } else {
                    let mut wide = [0u8; 8];
                    wide[4..].copy_from_slice(&slot[..4]);
                    wide
                };
                Some(if little {
                    u64::from_le_bytes(raw)
                } else {
                    u64::from_be_bytes(raw)
                })
            })
            .take(CppMetadata::MOST_SLOTS)
            .collect();
        // Walk the slots, breaking the vtable into its Itanium groups:
        // a secondary group opens with (negative offset, type
        // information) where the previous group closed, and its slots
        // continue the class's slot count. A Microsoft vtable is one
        // group, from the first virtual function.
        // A secondary group opens where the previous closed: its header
        // is (negative offset, type information) — neither of which is a
        // function the tables name. The group is recorded, with its
        // offset and the base it stands for, and the walk resumes at its
        // first slot; the slot count runs on across groups.
        let mut groups: Vec<VtableGroup> = Vec::new();
        let mut slot_index = 0usize;
        let mut cursor = *header;
        let mut pending: Option<VtableGroup> = Some(VtableGroup {
            address: *address,
            offset_to_top: 0,
            owner: class.clone(),
            slots: Vec::new(),
        });
        while cursor < words.len() {
            let word = words[cursor];
            if word == 0 {
                break;
            }
            // A word that names no function the tables name ends the
            // current group — and only opens a new one for an Itanium
            // secondary header, the (negative offset, type info) pair.
            if !names.contains_key(&word) {
                if *header != 2 || word as i64 >= 0 || cursor + 1 >= words.len() {
                    break;
                }
                let next = words[cursor + 1];
                let Some(owner) = type_infos.get(&next) else {
                    break;
                };
                if !pending.as_ref().is_none_or(|pending| pending.slots.is_empty()) {
                    groups.push(pending.take().expect("a pending group stands here"));
                }
                pending = Some(VtableGroup {
                    address: address + (cursor as u64) * width as u64,
                    offset_to_top: word as i64,
                    owner: owner.clone(),
                    slots: Vec::new(),
                });
                cursor += 2;
                continue;
            }
            let Some(name) = names.get(&word) else {
                break;
            };
            let name = name.clone();
            if name.starts_with("typeinfo") {
                break;
            }
            metadata
                .vtable_refs
                .insert(*address + (cursor as u64) * width as u64, (class.clone(), slot_index));
            metadata
                .vfunc_names
                .insert(word, name.clone());
            let entry = metadata.classes.get_mut(class);
            if let Some(entry) = entry {
                entry.vfuncs.push(Vfunc {
                    name,
                    implementation: Some(word),
                    slot: slot_index,
                });
            }
            if let Some(group) = pending.as_mut() {
                group.slots.push(slot_index);
            }
            slot_index += 1;
            cursor += 1;
        }
        if let Some(group) = pending {
            if !group.slots.is_empty() {
                // `pending` is `Some` while a group is being walked;
                // an empty tail group — a header the table ends
                // before — names no slots and is not a group.
                // (`take` above left it `None` only while a secondary
                // header is being consumed, which is also empty.)
                groups.push(group);
            }
        }
        if let Some(entry) = metadata.classes.get_mut(class) {
            entry.vtable_groups = groups;
        }
    }
    Some(metadata)
}

/// One word read: [`read_rtti_bases`] and the Microsoft hierarchy read
/// the image's words through this so both layouts share one cursor.
struct ImageWords<'a> {
    bytes: &'a [u8],
    width: usize,
    little: bool,
}

impl<'a> ImageWords<'a> {
    fn new(bytes: &'a [u8], width: usize, little: bool) -> Self {
        Self {
            bytes,
            width,
            little,
        }
    }

    fn word_at(&self, vma: u64) -> Option<u64> {
        let section = section_bytes_of(self.bytes, vma)?;
        let chunk = section.get(..self.width)?;
        let raw: [u8; 8] = if self.width == 8 {
            chunk.try_into().ok()?
        } else if self.little {
            let mut wide = [0u8; 8];
            wide[..4].copy_from_slice(&chunk[..4]);
            wide
        } else {
            let mut wide = [0u8; 8];
            wide[4..].copy_from_slice(&chunk[..4]);
            wide
        };
        Some(if self.little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    }

    /// The `n`-byte lane at `vma`: a 4-byte word of a 32-bit image, a
    /// 2-byte word, a byte — every lane is the image's own byte order.
    fn narrow_at(&self, vma: u64, n: usize) -> Option<u64> {
        let section = section_bytes_of(self.bytes, vma)?;
        let chunk = section.get(..n)?;
        let raw: [u8; 8] = if self.little {
            let mut wide = [0u8; 8];
            wide[..n].copy_from_slice(chunk);
            wide
        } else {
            let mut wide = [0u8; 8];
            wide[8 - n..].copy_from_slice(chunk);
            wide
        };
        Some(if self.little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    }

    /// The bytes at `vma` as a Latin-1 string, at most `max` long.
    fn string_at(&self, vma: u64, max: usize) -> Option<String> {
        let section = section_bytes_of(self.bytes, vma)?;
        let end = section.iter().position(|&b| b == 0).unwrap_or(section.len());
        let text = section.get(..end.min(max))?;
        Some(text.iter().map(|&b| b as char).collect())
    }
}

/// Read the base classes of the class whose type information stands at
/// `type_info`, in RTTI order. The Itanium `si_class_type_info` (`_ZTI`
/// with three words) names its single base; `vmi_class_type_info` packs
/// the base count into the high half of the third word and reads that
/// many (base type information, flag/offset) pairs, low bit 1 for
/// public, bit 0 for virtual. The Microsoft descriptor reads the
/// s dword at +8 in `.?AV<class>@@`; no base is named there, so the
/// hierarchy is read from ``??_R4`` instead and this path names none.
/// A type information with fewer than three words names no base.
fn read_rtti_bases(
    bytes: &[u8],
    type_info: u64,
    model: crate::types::DataModel,
    little: bool,
    type_infos: &BTreeMap<u64, String>,
) -> Vec<RttiBase> {
    let width = usize::try_from(model.pointer).unwrap_or(8);
    if width != 4 && width != 8 {
        return Vec::new();
    }
    let reader = ImageWords::new(bytes, width, little);
    let word = |index: u64| reader.word_at(type_info + index * width as u64);
    // Two words: `class_type_info` — vtable pointer, name — names no
    // base. Three: `si_class_type_info` names its one base in the third
    // word. `vmi_class_type_info` packs the base count into the third
    // word's high half (the low half carries the flags) and reads that
    // many (base type information, flag/offset) pairs after it.
    let Some(third) = word(2) else {
        return Vec::new();
    };
    // A counts word whose high half is a plausible base count is the packed
    // count; its pairs follow. The class-flag low half is 0 for a plain
    // class and nonzero when the class virtually inherits (the diamond's
    // header carries 0x2), so the branch is confirmed by the first pair's
    // base word naming a known type information. Any other third word that
    // is a known type information names that base alone; a two-word
    // `class_type_info` reads its neighbour's name pointer here, which
    // names no type information, so it still yields no base.
    let flags = third & 0xffff_ffff;
    let base_count = (third >> 32) as usize;
    let looks_vmi = (1..=64).contains(&base_count)
        && flags <= 0xff
        && word(3).is_some_and(|w| type_infos.contains_key(&w));
    if looks_vmi {
        let mut bases = Vec::new();
        for i in 0..base_count {
            let entry = 3 + 2 * i as u64;
            let Some(base_addr) = word(entry) else {
                break;
            };
            let Some(class) = type_infos.get(&base_addr) else {
                continue;
            };
            let Some(first) = word(entry + 1) else {
                break;
            };
            // The flag/offset word: the signed offset above the pointer,
            // the offset to the top below it; low bits 0x1 for virtual,
            // 0x2 for public — as cxxabi.h's masks write them.
            bases.push(RttiBase {
                class: class.clone(),
                offset: (first as i64) >> 8,
                is_public: first & 0x2 != 0,
                is_virtual: first & 0x1 != 0,
            });
        }
        return bases;
    }
    if let Some(class) = type_infos.get(&third) {
        return vec![RttiBase {
            class: class.clone(),
            offset: 0,
            // The si_class_type_info stores no access flag at all: the
            // ABI's single-base record carries only the base pointer, so
            // public is the contract this reader reports, not a read bit.
            is_public: true,
            is_virtual: false,
        }];
    }
    Vec::new()
}

/// The class the Microsoft type-name string `text` — the `.?AV<class>@@`
/// the ``??_R0?<class>@@@8`` descriptor holds at +8 — names: the class
/// before the closing `@@`, or the name it demangles to when the string
/// spells no `.?AV`. `None` when neither holds a class.
fn microsoft_name_class(text: &str) -> Option<String> {
    let stem = text.strip_prefix(".?A").unwrap_or(text);
    // The kind letter follows `.?A`: V names a class, U a struct or union.
    // It is part of the mangling, never part of the class's name.
    let stem = stem.strip_prefix(['V', 'U']).unwrap_or(stem);
    let stem = stem.strip_suffix("X{}").unwrap_or(stem);
    if let Some(class) = stem.strip_suffix("@@").or_else(|| stem.strip_suffix("@@@")) {
        // `Class@@`: the last `@@` closes the mangled name; a
        // templated name carries its arguments before it, as the
        // demangler spells them.
        let class = class.strip_suffix("@").unwrap_or(class);
        if class.is_empty() {
            return None;
        }
        if class.contains('@') && !class.contains('[') {
            // MSVC spells a scoped name innermost-first:
            // `.?AVShape@geometry@@` is `geometry::Shape`, and
            // `.?AVInner@Mid@Outer@@` is `Outer::Mid::Inner`.
            let parts: Vec<&str> = class.split('@').filter(|p| !p.is_empty()).collect();
            if parts.len() >= 2 {
                let full = parts.iter().rev().copied().collect::<Vec<_>>().join("::");
                if full != text {
                    return Some(full);
                }
            }
        }
        // A bare class: `base@@`, `Shape@@`. `type_info_class`'s
        // demangle of `??_R0?AVbase@@@8` reads `base` the same way.
        let plain = demangle_symbol(&format!("??_R0?AV{class}@@@8"))
            .and_then(|plain| {
                plain
                    .strip_prefix("`RTTI ")
                    .unwrap_or(&plain)
                    .strip_prefix("typeinfo name for ")
                    .unwrap_or(&plain)
                    .strip_prefix(".?AV")
                    .unwrap_or(&plain)
                    .split('[')
                    .next()
                    .map(str::to_string)
            })
            .unwrap_or_else(|| class.to_string());
        return (!plain.is_empty()).then_some(plain);
    }
    // The string itself is a demangled name: `base`, `geometry::Shape`.
    (!text.is_empty()).then_some(text.to_string())
}

/// The image base the RVAs stand against: the lowest non-zero section
/// address when the image links at one. `None` when the image has no
/// sections or none of them starts above zero.
fn image_base_of(bytes: &[u8]) -> Option<u64> {
    let Ok(file) = object::File::parse(bytes) else {
        return None;
    };
    let mut base = u64::MAX;
    for section in file.sections() {
        base = base.min(section.address());
    }
    (base != 0 && base != u64::MAX).then_some(base)
}

/// The Microsoft base classes for each class whose locator the image
/// holds, in hierarchy order, by the class's type-information address.
/// The locator ``??_R4<class>@@6B@`` holds `pHierarchyDescriptor` at
/// +16, the RVA of the hierarchy descriptor relative to the image base.
/// The hierarchy descriptor holds `numBaseClasses` at +8 and
/// `pBaseClassArray` at +12, an array of 6-word base-class descriptors
/// ({ `pTypeDescriptor` RVA, `numContainedBases`, `mdisp`, `pdisp`,
/// `vdisp`, `attributes` }); element 0 is the class itself. Each base's
/// ``??_R0`` names the base at +8. A class with no locator names no
/// bases, so this map holds none for it.
fn microsoft_hierarchy_bases(
    bytes: &[u8],
    symbols: &[(u64, String)],
    little: bool,
) -> BTreeMap<u64, Vec<RttiBase>> {
    let Some(base) = image_base_of(bytes) else {
        return BTreeMap::new();
    };
    let reader = ImageWords::new(bytes, 4, little);
    let mut result: BTreeMap<u64, Vec<RttiBase>> = BTreeMap::new();
    for (locator, name) in symbols {
        if !name.starts_with("??_R4") {
            continue;
        }
        let Some(class) = locator_class(name) else {
            continue;
        };
        let Some(type_info) = symbols
            .iter()
            .find(|(_, n)| is_type_info(n) && type_info_class(n).as_deref() == Some(class.as_str()))
            .map(|(a, _)| *a)
        else {
            continue;
        };
        result.insert(
            type_info,
            microsoft_bases_for(bytes, *locator, base, &reader, symbols),
        );
    }
    result
}

/// The bases of the class whose locator stands at `locator`. Element 0
/// of the array is the class itself and is skipped.
fn microsoft_bases_for(
    _bytes: &[u8],
    locator: u64,
    base: u64,
    reader: &ImageWords<'_>,
    symbols: &[(u64, String)],
) -> Vec<RttiBase> {
    let Some(hierarchy_rva) = reader.narrow_at(locator + 16, 4) else {
        return Vec::new();
    };
    let hierarchy = base + hierarchy_rva;
    let Some(num_bases) = reader.narrow_at(hierarchy + 8, 4) else {
        return Vec::new();
    };
    // The array holds one more entry than numBaseClasses; element 0 is
    // the class itself.
    let count = usize::try_from(num_bases).unwrap_or(0).min(16);
    let Some(array_rva) = reader.narrow_at(hierarchy + 12, 4) else {
        return Vec::new();
    };
    let array = base + array_rva;
    let mut bases = Vec::new();
    for index in 0..=count {
        let entry = array + index as u64 * 24;
        if index == 0 {
            continue;
        }
        let Some(descriptor_rva) = reader.narrow_at(entry, 4) else {
            break;
        };
        let Some(class) = descriptor_class_at(base + descriptor_rva, reader, symbols) else {
            continue;
        };
        let mdisp = reader.narrow_at(entry + 8, 4).unwrap_or(0);
        let attributes = reader.narrow_at(entry + 20, 4).unwrap_or(0);
        bases.push(RttiBase {
            class,
            offset: i64::from(mdisp as u32 as i32),
            is_public: (attributes & 0x3) == 2,
            is_virtual: attributes & 0x8 != 0,
        });
    }
    bases
}

/// The class the complete object locator `name` — ``??_R4<class>@@6B@``
/// — belongs to.
fn locator_class(name: &str) -> Option<String> {
    let plain = demangle_symbol(name)?;
    // The demangler spells `` `<class>::`vftable' `` for the locator's
    // table; the class stands before the table's `` ::` `` qualifier.
    if let Some((class, _)) = plain.rsplit_once("::`") {
        let class = class.trim();
        return (!class.is_empty()).then_some(class.to_string());
    }
    // `complete object locator for <class>` fallback.
    plain
        .split("complete object locator for ")
        .nth(1)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The class the base-class descriptor at `va` names, via its ``??_R0``
/// descriptor's name string at +8. `None` when the descriptor names none.
fn descriptor_class_at(
    va: u64,
    reader: &ImageWords<'_>,
    symbols: &[(u64, String)],
) -> Option<String> {
    // A PE type descriptor is { vftable, spare, name }: the `.?AV<class>@@`
    // string stands inline at +8. (An earlier branch read +8 as a 4-byte
    // pointer and resolved it as a VA, not an RVA — dead on a real PE,
    // where the name is inline, and removed.)
    if let Some(text) = reader.string_at(va + 8, 256) {
        if let Some(class) = microsoft_name_class(&text) {
            return Some(class);
        }
    }
    // Last resort: the symbol at `va`, if any, is the descriptor's own.
    symbols
        .iter()
        .find(|(a, _)| *a == va)
        .and_then(|(_, n)| type_info_class(n))
}

/// The name `mangled` demangles under, with a version suffix dropped. A
/// symbol version — the linker's `@@CXXABI_1.3` — makes the demangle
/// fail outright, and the suffix names the ABI version of the symbol it
/// versions, never the class. A Microsoft name's `@` is its scope's: it
/// stands before the class, so only an Itanium name's `@` is cut.
fn demangle_symbol(mangled: &str) -> Option<String> {
    let stem = if mangled.starts_with('?') {
        mangled
    } else {
        mangled.split('@').next().unwrap_or(mangled)
    }
    .split('.')
    .next()
    .unwrap_or(mangled);
    crate::demangle::demangle(stem)
}

/// The class the vtable symbol `name` belongs to, as the demangler
/// reads it back: `_ZTVbase` is `base`, `_ZTVN8geometry5ShapeE` is
/// `geometry::Shape`, ``??_7Shape@geometry@@6B@`` is `geometry::Shape`.
/// The Itanium demangler spells a vtable `{vtable(<class>)}`; the
/// Microsoft one `` `<class>::`vftable' ``.
///
/// Returns the class and the header words the ABI lays before the first
/// virtual function: the Itanium ABI's two (`offset_to_top` and the
/// type information), the Microsoft ABI's none.
fn vtable_class(name: &str) -> Option<(String, usize)> {
    let itanium = match name.strip_prefix('_') {
        Some(rest) if rest.starts_with("_ZTV") => rest,
        _ => name,
    };
    if itanium.starts_with("_ZTV") {
        let plain = demangle_symbol(itanium)?;
        // Read back under either spelling the demangler may use: the
        // closed `{vtable(<class>)}`, and the open `vtable for <class>`.
        for prefix in ["{vtable(", "vtable for "] {
            if let Some(class) = plain.strip_prefix(prefix) {
                let class = class
                    .strip_suffix('}')
                    .unwrap_or(class)
                    .strip_suffix(')')
                    .unwrap_or(class)
                    .trim();
                if !class.is_empty() {
                    // The ABI's own type-information classes are not
                    // classes of the program.
                    if class.starts_with("__cxxabiv1::") {
                        return None;
                    }
                    return Some((class.to_string(), 2));
                }
            }
        }
        return None;
    }
    if name.starts_with("??_7") {
        let plain = demangle_symbol(name)?;
        // `` <class>::`vftable' ``, and a base entry's
        // `` <class>::{vtable-in-`<class>'} `` — both end in the class
        // the table stands for. The class stands before the table's
        // `` ::` `` qualifier; without one, the name gives no class.
        if let Some((class, _)) = plain.rsplit_once("::`") {
            let class = class.trim();
            if !class.is_empty() && class != name {
                return Some((class.to_string(), 0));
            }
        }
        return None;
    }
    None
}

/// The address of the type information of `class`, by its symbol name,
/// when the image holds one. The type information proper (`_ZTI<class>`)
/// is preferred to the name string (`_ZTS<class>`) the type information
/// holds: the two agree on the class, and only one of them is the type
/// information.
fn type_info_address(symbols: &[(u64, String)], class: &str) -> Option<u64> {
    let find = |want_type_info: bool| {
        symbols.iter().find_map(|(address, name)| {
            if want_type_info && !is_type_info(name) {
                return None;
            }
            if !want_type_info && is_type_info(name) {
                return None;
            }
            let plain = type_info_class(name)?;
            (plain == class).then_some(*address)
        })
    };
    find(true).or_else(|| find(false))
}

/// Whether `name` stands for the type information itself: `_ZTI` on
/// Itanium, the `??_R0` descriptor on Microsoft. The descriptor's kin —
/// the per-base `??_R1…`, the arrays and hierarchy `??_R2`/`??_R3`, the
/// complete object locator `??_R4` — all name the same class, but none
/// of them is the type information.
fn is_type_info(name: &str) -> bool {
    let itanium = match name.strip_prefix('_') {
        Some(rest) if rest.starts_with("_ZTI") => rest,
        _ => name,
    };
    itanium.starts_with("_ZTI") || name.starts_with("??_R0")
}

/// The class the type-information symbol `name` belongs to.
fn type_info_class(name: &str) -> Option<String> {
    let itanium = match name.strip_prefix('_') {
        Some(rest) if rest.starts_with("_ZTI") || rest.starts_with("_ZTS") => rest,
        _ => name,
    };
    if itanium.starts_with("_ZTI") || itanium.starts_with("_ZTS") {
        let plain = demangle_symbol(itanium)?;
        let plain = plain.strip_prefix("typeinfo for ").unwrap_or(&plain);
        let plain = plain.strip_prefix("typeinfo name for ").unwrap_or(plain);
        if plain.starts_with("__cxxabiv1::") {
            return None;
        }
        return (!plain.is_empty()).then_some(plain.to_string());
    }
    if name.starts_with("??_R0") {
        let plain = demangle_symbol(name)?;
        let plain = plain
            .strip_prefix("`RTTI ")
            .unwrap_or(&plain)
            .strip_prefix("typeinfo name for ")
            .unwrap_or(&plain)
            .strip_prefix(".?AV")
            .unwrap_or(&plain);
        let plain = plain.split('[').next().unwrap_or(plain);
        return (!plain.is_empty()).then_some(plain.to_string());
    }
    None
}

/// The address of the constructor of `class`, named in the image as
/// `<class>::<class>`, when the image holds one.
fn constructor_address(symbols: &[(u64, String)], class: &str) -> Option<u64> {
    let wanted = format!("{class}::{class}");
    symbols.iter().find_map(|(address, name)| {
        let stem = name.split('@').next().unwrap_or(name);
        let short = crate::demangle::demangle_short(stem)?;
        (short == wanted).then_some(*address)
    })
}

/// The bytes of the section holding `vma`, from `vma` on.
fn section_bytes_of(bytes: &[u8], vma: u64) -> Option<&[u8]> {
    let Ok(file) = object::File::parse(bytes) else {
        return None;
    };
    let section = file
        .sections()
        .find(|section| vma >= section.address() && vma < section.address() + section.size())?;
    let data = section.data().ok()?;
    let skip = usize::try_from(vma - section.address()).ok()?;
    data.get(skip..)
}

/// A demangled name with its template arguments kept whole.
///
/// A mangled name spells every argument — `geometry::twice<int>(int)`,
/// with the `<int>` the instantiation fixed — where the code that reads
/// it wants the template's own name, arguments and all, nested the way
/// the source nests them: `geometry::twice< int >(int)`,
/// `std::vector< std::pair< int, double > >`. The rendering keeps each
/// `< >` pair around the arguments it holds, the inner one's pair
/// inside the outer's, so a template that takes a template stands as it
/// stands. A name with no template stands as it stands, and a `<` the
/// name leaves unbalanced stands as it stands.
pub fn simplify_template_name(name: &str) -> String {
    simplify(name)
}

fn simplify(name: &str) -> String {
    let mut out = String::new();
    let mut rest = name;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        // Find the matching `>`, counting nested ones.
        let after = &rest[open + 1..];
        let mut depth = 1usize;
        let mut close = None;
        for (index, c) in after.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            out.push_str(&rest[open..]);
            return out;
        };
        let arguments = &after[..close];
        out.push_str("< ");
        out.push_str(&simplify(arguments));
        out.push_str(" >");
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_name_keeps_its_arguments_whole() {
        assert_eq!(
            simplify_template_name("geometry::twice<int>(int)"),
            "geometry::twice< int >(int)"
        );
        assert_eq!(simplify_template_name("twice<int, float>"), "twice< int, float >");
        assert_eq!(
            simplify_template_name("std::vector<std::pair<int, double>>"),
            "std::vector< std::pair< int, double > >"
        );
        assert_eq!(
            simplify_template_name("vector<std::shared_ptr<int>>"),
            "vector< std::shared_ptr< int > >"
        );
        assert_eq!(simplify_template_name("a<b<c>>"), "a< b< c > >");
    }

    #[test]
    fn a_name_without_a_template_stands_as_it_stands() {
        assert_eq!(simplify_template_name("base::f(int)"), "base::f(int)");
        assert_eq!(simplify_template_name("no template here"), "no template here");
        // A `<` the name leaves unbalanced is not a template's.
        assert_eq!(simplify_template_name("x<y"), "x<y");
    }

    #[test]
    fn an_itanium_vtable_names_its_class() {
        assert_eq!(vtable_class("_ZTV4base"), Some(("base".to_string(), 2)));
        assert_eq!(
            vtable_class("_ZTVN8geometry5ShapeE"),
            Some(("geometry::Shape".to_string(), 2))
        );
    }

    #[test]
    fn the_abi_vtables_name_no_class_of_the_program() {
        assert_eq!(
            vtable_class("_ZTVN10__cxxabiv117__class_type_infoE@CXXABI_1.3"),
            None
        );
        assert_eq!(vtable_class("_ZTVN10__cxxabiv117__class_type_infoE"), None);
    }

    #[test]
    fn a_microsoft_vtable_names_its_class() {
        assert_eq!(
            vtable_class("??_7Shape@geometry@@6B@"),
            Some(("geometry::Shape".to_string(), 0))
        );
        assert_eq!(vtable_class("??_7Base@@6B@"), Some(("Base".to_string(), 0)));
    }

    #[test]
    fn type_information_names_its_class() {
        assert_eq!(type_info_class("_ZTI4base").as_deref(), Some("base"));
        assert_eq!(
            type_info_class("_ZTSN8geometry5ShapeE").as_deref(),
            Some("geometry::Shape")
        );
        assert_eq!(
            type_info_class("_ZTVN10__cxxabiv117__class_type_infoE"),
            None
        );
    }
}
