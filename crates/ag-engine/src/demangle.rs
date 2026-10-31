//! Mangled names read back to the names the source spelled.
//!
//! A C++ or Rust compiler encodes a function's scope, its name and its
//! signature into one symbol — `_ZN8geometry4areaEii`, `?area@geometry@@YAHHH@Z`,
//! `_ZN4core3fmt5write17h…E` — so that overloads and generics each have a
//! name of their own. The listing is unreadable in that form. [`demangle`]
//! reads the four schemes back: Itanium C++ (ELF, Mach-O), Microsoft C++
//! (PE), Rust (legacy and v0) and Swift (see [`crate::swift_demangle`]),
//! and leaves every other name as it is — a C symbol, an Objective-C
//! method's `-[Class sel]`, a name of the loader's. The signature is kept,
//! since it is what tells two overloads apart.

use cpp_demangle::{DemangleOptions, Symbol};
use msvc_demangler::DemangleFlags;

/// No real mangled name is longer: a bound on what the demanglers are
/// handed from a crafted file, whose depth of nesting is not theirs to
/// refuse.
const LONGEST_NAME: usize = 4096;

/// The name `mangled` spells, when it is a mangled one, signature kept;
/// `None` for a name that is not, which is to be shown as it is.
pub fn demangle(mangled: &str) -> Option<String> {
    read(mangled, false)
}

/// The scope and the name alone — `geometry::area` for `geometry::area(int,
/// int)` — for the places a name stands in code, where a signature would
/// not read: the pseudocode, and the calls in it. `None` for a name that
/// is not mangled.
pub fn demangle_short(mangled: &str) -> Option<String> {
    read(mangled, true)
}

fn read(mangled: &str, short: bool) -> Option<String> {
    if mangled.len() > LONGEST_NAME {
        return None;
    }
    // Swift: a `$s` prefix, under a Mach-O's underscore or not.
    if crate::swift_demangle::is_swift(mangled) {
        return if short {
            crate::swift_demangle::demangle_short(mangled)
        } else {
            crate::swift_demangle::demangle(mangled)
        };
    }
    // Microsoft C++: a leading `?` belongs to no other scheme. The access,
    // the calling convention and the storage class are dropped; the scope,
    // the name, the signature and a method's `const` are kept.
    if mangled.starts_with('?') {
        let flags = if short {
            DemangleFlags::NAME_ONLY | DemangleFlags::NO_CLASS_TYPE
        } else {
            DemangleFlags::NO_ACCESS_SPECIFIERS
                | DemangleFlags::NO_MS_KEYWORDS
                | DemangleFlags::NO_FUNCTION_RETURNS
                | DemangleFlags::NO_MEMBER_TYPE
                | DemangleFlags::NO_MS_THISTYPE
                | DemangleFlags::NO_CLASS_TYPE
                | DemangleFlags::SPACE_AFTER_COMMA
        };
        return msvc_demangler::demangle(mangled, flags)
            .ok()
            .filter(|plain| !plain.is_empty() && plain != mangled);
    }
    // A Mach-O prefixes every symbol with `_`, the Itanium one included:
    // `__ZN…` is `_ZN…` to the demangler.
    let itanium = match mangled.strip_prefix('_') {
        Some(rest) if rest.starts_with("_Z") || rest.starts_with("_R") => rest,
        _ => mangled,
    };
    // Rust first where the symbol says it is Rust: a legacy Rust name is a
    // well-formed Itanium name too, which the C++ demangler would read with
    // the Rust escapes (`$LT$`, `..`) left in.
    if is_rust(itanium) {
        if let Some(plain) = rust(itanium) {
            return Some(plain);
        }
    }
    if itanium.starts_with("_Z") {
        let options = if short {
            DemangleOptions::new().no_params().no_return_type()
        } else {
            DemangleOptions::new()
        };
        if let Some(plain) = Symbol::new(itanium)
            .ok()
            .and_then(|symbol| symbol.demangle_with_options(&options).ok())
            .filter(|plain| !plain.is_empty() && plain != itanium)
        {
            return Some(plain);
        }
    }
    rust(itanium)
}

/// Whether `name` is a Rust symbol: v0 (`_R…`), or legacy (`_ZN…E` ending
/// in the `17h<16 hex digits>` hash the Rust compiler appends), either
/// before a suffix the linker added past a `.` (`.llvm.1234`). Read as
/// bytes, since a crafted name need not be ASCII.
fn is_rust(name: &str) -> bool {
    if name.starts_with("_R") {
        return true;
    }
    let name = name.split('.').next().unwrap_or(name);
    let Some(body) = name
        .strip_prefix("_ZN")
        .and_then(|rest| rest.strip_suffix('E'))
    else {
        return false;
    };
    let body = body.as_bytes();
    body.len() > 19
        && body[body.len() - 19..].starts_with(b"17h")
        && body[body.len() - 16..].iter().all(u8::is_ascii_hexdigit)
}

/// A Rust name, with the hash dropped.
fn rust(name: &str) -> Option<String> {
    let plain = format!("{:#}", rustc_demangle::try_demangle(name).ok()?);
    (!plain.is_empty() && plain != name).then_some(plain)
}

#[cfg(test)]
mod tests {
    use super::demangle;

    #[test]
    fn itanium_names_read_back_with_their_signatures() {
        assert_eq!(
            demangle("_ZN8geometry4areaEii").as_deref(),
            Some("geometry::area(int, int)")
        );
        assert_eq!(
            demangle("_ZN8geometry4areaEi").as_deref(),
            Some("geometry::area(int)")
        );
        assert_eq!(
            demangle("_ZNK8geometry5Shape6cornerEi").as_deref(),
            Some("geometry::Shape::corner(int) const")
        );
        assert_eq!(
            demangle("_ZN8geometry5ShapeC1Ei").as_deref(),
            Some("geometry::Shape::Shape(int)")
        );
        assert_eq!(
            demangle("_ZN8geometry5twiceIiEET_S1_").as_deref(),
            Some("int geometry::twice<int>(int)")
        );
        assert_eq!(
            demangle("_ZN8geometry5Shape5countE").as_deref(),
            Some("geometry::Shape::count")
        );
        // A Mach-O's leading underscore.
        assert_eq!(
            demangle("__ZN8geometry4areaEii").as_deref(),
            Some("geometry::area(int, int)")
        );
    }

    #[test]
    fn microsoft_names_read_back_without_the_decoration() {
        assert_eq!(
            demangle("?area@geometry@@YAHHH@Z").as_deref(),
            Some("geometry::area(int, int)")
        );
        assert_eq!(
            demangle("?sides@Shape@geometry@@QEBAHXZ").as_deref(),
            Some("geometry::Shape::sides(void) const")
        );
        assert_eq!(
            demangle("??0Shape@geometry@@QEAA@H@Z").as_deref(),
            Some("geometry::Shape::Shape(int)")
        );
        assert_eq!(
            demangle("?count@Shape@geometry@@2HA").as_deref(),
            Some("geometry::Shape::count")
        );
        assert_eq!(
            demangle("??$twice@H@geometry@@YAHH@Z").as_deref(),
            Some("geometry::twice<int>(int)")
        );
    }

    #[test]
    fn rust_names_read_back_without_the_hash() {
        assert_eq!(
            demangle("_ZN4core3fmt5write17h1234567890abcdefE").as_deref(),
            Some("core::fmt::write")
        );
        assert_eq!(
            demangle("_RNvCs1234_7mycrate4main").as_deref(),
            Some("mycrate::main")
        );
    }

    #[test]
    fn the_short_form_is_the_scope_and_the_name() {
        use super::demangle_short;
        assert_eq!(
            demangle_short("_ZN8geometry4areaEii").as_deref(),
            Some("geometry::area")
        );
        assert_eq!(
            demangle_short("_ZNK8geometry5Shape6cornerEi").as_deref(),
            Some("geometry::Shape::corner")
        );
        assert_eq!(
            demangle_short("?corner@Shape@geometry@@QEBA?AUPoint@2@H@Z").as_deref(),
            Some("geometry::Shape::corner")
        );
        assert_eq!(
            demangle_short("_ZN4core3fmt5write17h1234567890abcdefE").as_deref(),
            Some("core::fmt::write")
        );
        assert_eq!(demangle_short("main"), None);
    }

    #[test]
    fn a_rust_name_with_a_linker_suffix_is_still_rust() {
        assert_eq!(
            demangle("_ZN4core3fmt5write17h1234567890abcdefE.llvm.1234").as_deref(),
            Some("core::fmt::write")
        );
    }

    #[test]
    fn a_crafted_name_neither_panics_nor_demangles() {
        // A hash-length tail that is not ASCII must not be sliced inside a
        // character.
        assert_eq!(demangle("_ZNé012345678901234567E"), None);
        assert_eq!(demangle("_ZNééééééééééE"), None);
        let long = format!("?x@@3{}", "PEA".repeat(100_000));
        assert_eq!(demangle(&long), None);
        let long = format!("_Z{}", "N".repeat(10_000));
        assert_eq!(demangle(&long), None);
    }

    #[test]
    fn swift_names_read_back_too() {
        assert_eq!(
            demangle("_$s6sample7DerivedC5greet5timesS2i_tF").as_deref(),
            Some("sample.Derived.greet(times: Swift.Int) -> Swift.Int")
        );
        assert_eq!(
            super::demangle_short("_$s6sample7DerivedC5greet5timesS2i_tF").as_deref(),
            Some("sample.Derived.greet")
        );
        assert_eq!(
            demangle("$s6sample4BaseCMa").as_deref(),
            Some("type metadata accessor for sample.Base")
        );
    }

    #[test]
    fn names_that_are_not_mangled_are_left_alone() {
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("_main"), None);
        assert_eq!(demangle("add"), None);
        assert_eq!(demangle("-[Derived greet:]"), None);
        assert_eq!(demangle("+[Base answer]"), None);
        assert_eq!(demangle("OBJC_CLASS_$_Base"), None);
        assert_eq!(demangle("entry_0x401000"), None);
        assert_eq!(demangle("_Z"), None);
        assert_eq!(demangle("?"), None);
        assert_eq!(demangle(""), None);
    }
}
