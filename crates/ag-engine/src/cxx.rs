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
//! declares them. An image that holds no such symbols has no classes to
//! speak of.
//!
//! [`CppMetadata`] is that reading: every class the image names, its
//! vtable's address, its type information's and its constructor's when
//! the image holds them, and the virtual functions in the order the
//! vtable holds them, each with the implementation it points at. It is
//! read from the image's bytes the way the Objective-C metadata is
//! ([`crate::objc`]), and kept on the [`Image`](crate::image::Image)
//! behind the same kind of one-cell cache.
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
    for (class, address, header) in &tables {
        let Some(mut bytes) = section_bytes_of(bytes, *address) else {
            continue;
        };
        if let Some(&end) = ends.get(address) {
            if end != u64::MAX && end > *address {
                bytes = bytes.get(..usize::try_from(end - *address).unwrap_or(0)).unwrap_or(&[]);
            }
        }
        let Some(entry) = metadata.classes.get_mut(class) else {
            continue;
        };
        let width = usize::try_from(model.pointer).unwrap_or(8);
        if width != 4 && width != 8 {
            continue;
        }
        for (index, slot) in bytes
            .get(header * width..)
            .unwrap_or(&[])
            .chunks(width)
            .take(CppMetadata::MOST_SLOTS)
            .enumerate()
        {
            if slot.len() != width {
                break;
            }
            // The vtable's words are the image's own pointers: the
            // image's byte order, its width.
            let implementation = match slot.try_into() {
                Ok(bytes) => {
                    let raw: [u8; 8] = if width == 8 {
                        bytes
                    } else if little {
                        let mut wide = [0u8; 8];
                        wide[..4].copy_from_slice(&bytes[..4]);
                        wide
                    } else {
                        let mut wide = [0u8; 8];
                        wide[4..].copy_from_slice(&bytes[..4]);
                        wide
                    };
                    if little {
                        u64::from_le_bytes(raw)
                    } else {
                        u64::from_be_bytes(raw)
                    }
                }
                Err(_) => continue,
            };
            if implementation == 0 {
                break;
            }
            // A slot holds an implementation, or a word past the table's
            // end. The next vtable's words fail here: a type-information
            // address is no function the tables name.
            let Some(name) = names.get(&implementation) else {
                break;
            };
            let name = name.clone();
            if name.starts_with("typeinfo") {
                break;
            }
            metadata
                .vtable_refs
                .insert(*address + (*header as u64) * width as u64 + index as u64 * width as u64, (class.clone(), index));
            metadata
                .vfunc_names
                .insert(implementation, name.clone());
            entry.vfuncs.push(Vfunc {
                name,
                implementation: Some(implementation),
                slot: index,
            });
        }
    }
    Some(metadata)
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
