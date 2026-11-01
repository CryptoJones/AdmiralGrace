//! Variables the analyst makes in a function's stack frame.
//!
//! The lift makes a stack local of each slot the code reads and writes at
//! one width, `local_14`, so a buffer the code fills a word at a time is
//! several locals, and a structure on the stack is one local a field. The
//! analyst says where a variable is — its offset from the stack pointer at
//! the function's entry, as the lift's `local_<hex>` names count it, its
//! size, and optionally its name and its C type — and the lift reads the
//! bytes `[offset, offset + size)` as that one variable.
//!
//! Every slot the code touches inside the variable is a real variable of
//! the lift — declared, with its stores emitted, never propagated away — so
//! the memory holds what the code put there, and a read at another width
//! reads that memory rather than refusing a value written in parts. Once
//! the function is lifted, each of the lift's locals inside the variable is
//! read as a part of it:
//!
//! - **the whole**: a local at the variable's offset and of its size is the
//!   variable itself, `buf`, with the variable's name and type;
//! - **an element**: in an array, `char[16]` or `int[4]`, a local at an
//!   element's offset and of the element's size is that element, `buf[2]`,
//!   and its address `&buf[2]`;
//! - **bytes at an offset**: anything else — a field of a structure, a word
//!   of a `char` array, a local at an offset no element starts at — is a
//!   load or store at that byte offset, `*(int *)((char *)&buf + 4)`, at the
//!   width of the lift's local, and its address `(int *)((char *)&buf +
//!   4)`. The lift knows no structure types, so a field reads this way.
//!
//! The lift's locals inside the variable are no longer declared; the
//! variable is, where the first of them was, its type spelled as C declares
//! it: `char buf[16];`. A local the code reads at two widths at one offset
//! keeps the lift's type of its first access.
//!
//! Without a name the variable is named as the lift names its slot,
//! `local_20`; without a type it is `char`, `short`, `int` or `long` for a
//! size of 1, 2, 4 or 8 bytes, and an array of `char` otherwise. A type of
//! a known size must be the variable's size — an array with no count,
//! `int[]`, takes the count the size gives — and a type the lift does not
//! know the size of, `struct point`, is taken at the size given. The name
//! is the variable's lift name: the analyst's renames, merges, splits,
//! versions and pinned values key on it.
//!
//! A variable that overlaps one made before it, in the order the analyst
//! gave them, is refused, and so is one whose type does not fit its size,
//! whose name is not a C identifier, or whose name the function declares
//! already outside it; the function's leading comments say why: `buf is
//! not made at [sp-0x20] 16 bytes: it overlaps key at [sp-0x18] 8 bytes`.
//! Taking the word back gives the lift's own locals again.

use std::collections::BTreeMap;

use crate::ast::{AstNode, BinaryOp};
use crate::lift::{LiftedFunction, Placement, Statement, StatementKind, Variable};
use crate::options::SlotNames;

/// A variable the analyst made in a function's stack frame: its offset from
/// the stack pointer at the function's entry, its size in bytes, and the
/// name and C type it is given, when they are.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackVar {
    pub offset: i64,
    pub size: u32,
    pub name: Option<String>,
    pub ty: Option<String>,
}

/// The intrinsic an element of an analyst's array reads through: `buf[2]`
/// is `__index(buf, 2)`. It is no call: a read or a store of memory.
pub const INDEX: &str = "__index";

/// The array and the index of an expression `__index(buf, 2)`, when it is
/// one.
pub fn indexed(node: &AstNode) -> Option<(&AstNode, &AstNode)> {
    match node {
        AstNode::Intrinsic { name, args } if name == INDEX => match args.as_slice() {
            [array, index] => Some((array, index)),
            _ => None,
        },
        _ => None,
    }
}

/// A C type as the analyst typed it, read as far as the lift needs: the
/// element type and count of an array, and the size of the element when
/// the lift knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedType {
    /// The type as it is declared: `int`, `char *`, `char[16]`.
    pub text: String,
    /// The type of an element, or the type itself when it is no array.
    pub element: String,
    /// Whether the type is an array: `char[16]`, `int[]`.
    pub array: bool,
    /// The count of an array, when it says one.
    pub count: Option<u32>,
    /// The size of the element in bytes, when the lift knows it: the
    /// integer, floating and pointer types, and `int32_t` and its kind.
    pub element_size: Option<u32>,
}

/// The type `text`: a C type, optionally an array of one, `char[16]` or
/// `int[]`. An array of arrays is refused.
pub fn parse_type(text: &str) -> Result<ParsedType, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("the type is empty".to_string());
    }
    let (element, array, count) = match text.find('[') {
        Some(open) => {
            let element = text[..open].trim();
            let rest = text[open + 1..].trim();
            let Some(inside) = rest.strip_suffix(']') else {
                return Err(format!("{text} has no closing ]"));
            };
            let inside = inside.trim();
            if inside.contains('[') || inside.contains(']') {
                return Err(format!("{text} is an array of arrays"));
            }
            let count = if inside.is_empty() {
                None
            } else {
                let parsed = match inside
                    .strip_prefix("0x")
                    .or_else(|| inside.strip_prefix("0X"))
                {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => inside.parse::<u32>(),
                };
                match parsed {
                    Ok(0) => return Err(format!("{text} has no elements")),
                    Ok(count) => Some(count),
                    Err(_) => return Err(format!("{inside:?} is not a count")),
                }
            };
            (element, true, count)
        }
        None => (text, false, None),
    };
    if element.is_empty() {
        return Err(format!("{text} names no element type"));
    }
    if element == "void" {
        return Err("a variable of type void holds nothing".to_string());
    }
    let element = normalized(element);
    let element_size = size_of(&element);
    let text = match (array, count) {
        (true, Some(count)) => format!("{element}[{count}]"),
        (true, None) => format!("{element}[]"),
        _ => element.clone(),
    };
    Ok(ParsedType {
        text,
        element,
        array,
        count,
        element_size,
    })
}

/// The type with its words single-spaced and its stars apart: `char*` is
/// `char *`.
fn normalized(ty: &str) -> String {
    let stars = ty.chars().filter(|&c| c == '*').count();
    let base = ty.replace('*', " ");
    let base = base.split_whitespace().collect::<Vec<_>>().join(" ");
    if stars == 0 {
        base
    } else {
        format!("{base} {}", "*".repeat(stars))
    }
}

/// The size in bytes of a type the lift knows; `None` for one it does not,
/// a structure or a name it has no definition of.
fn size_of(ty: &str) -> Option<u32> {
    if ty.ends_with('*') {
        return Some(8);
    }
    let words: Vec<&str> = ty
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "signed" | "unsigned"))
        .collect();
    let bare = ty
        .split_whitespace()
        .any(|word| matches!(word, "signed" | "unsigned"));
    Some(match words.join(" ").as_str() {
        "" if bare => 4,
        "char" | "_Bool" | "bool" | "int8_t" | "uint8_t" => 1,
        "short" | "short int" | "int16_t" | "uint16_t" => 2,
        "int" | "float" | "int32_t" | "uint32_t" => 4,
        "long" | "long int" | "long long" | "long long int" | "double" | "int64_t" | "uint64_t"
        | "size_t" | "ssize_t" | "intptr_t" | "uintptr_t" | "ptrdiff_t" => 8,
        "long double" => 16,
        _ => return None,
    })
}

/// The type of a size the analyst gave no type for: the integer of the
/// width, and an array of `char` otherwise.
fn default_type(size: u32) -> String {
    match size {
        1 => "char".to_string(),
        2 => "short".to_string(),
        4 => "int".to_string(),
        8 => "long".to_string(),
        size => format!("char[{size}]"),
    }
}

/// The declaration of `name` of type `ty` as C writes it: `int i`, `char
/// buf[16]`.
pub fn declarator(ty: &str, name: &str) -> String {
    match ty.find('[') {
        Some(open) => format!("{} {name}{}", ty[..open].trim_end(), &ty[open..]),
        None => format!("{ty} {name}"),
    }
}

/// Whether `name` is a C identifier.
fn identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// An analyst's variable the lift makes: where it is, its name and type,
/// and its element when it is an array of elements the lift knows the size
/// of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Made {
    pub(crate) offset: i64,
    pub(crate) size: u32,
    pub(crate) name: String,
    pub(crate) ty: String,
    /// The element's type and size.
    pub(crate) element: Option<(String, u32)>,
}

impl Made {
    fn placement(&self) -> Placement {
        Placement::Stack {
            offset: self.offset,
            size: self.size,
        }
    }

    fn end(&self) -> i64 {
        self.offset + i64::from(self.size)
    }

    /// Whether the slot at `offset` starts inside the variable.
    pub(crate) fn holds(&self, offset: i64) -> bool {
        self.offset <= offset && offset < self.end()
    }
}

/// The analyst's variables the lift makes, in the order given, and the
/// notes saying why the others are refused.
pub(crate) fn accept(words: &[StackVar], names: SlotNames) -> (Vec<Made>, Vec<String>) {
    let mut made: Vec<Made> = Vec::new();
    let mut notes = Vec::new();
    for word in words {
        let name = word
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| crate::lift::local_name(names, word.offset));
        let place = Placement::Stack {
            offset: word.offset,
            size: word.size,
        }
        .spelled();
        let refuse = |why: String| format!("{name} is not made at {place}: {why}");
        if word.size == 0 {
            notes.push(refuse("it has no size".to_string()));
            continue;
        }
        if !identifier(&name) {
            notes.push(refuse(format!("{name:?} is not a C identifier")));
            continue;
        }
        let (ty, element) = match word.ty.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            None => {
                let ty = default_type(word.size);
                let element =
                    (!matches!(word.size, 1 | 2 | 4 | 8)).then(|| ("char".to_string(), 1));
                (ty, element)
            }
            Some(text) => match fitted(text, word.size) {
                Ok(fit) => fit,
                Err(why) => {
                    notes.push(refuse(why));
                    continue;
                }
            },
        };
        let candidate = Made {
            offset: word.offset,
            size: word.size,
            name: name.clone(),
            ty,
            element,
        };
        if let Some(other) = made
            .iter()
            .find(|other| other.offset < candidate.end() && candidate.offset < other.end())
        {
            notes.push(refuse(format!(
                "it overlaps {} at {}",
                other.name,
                other.placement().spelled()
            )));
            continue;
        }
        if let Some(other) = made.iter().find(|other| other.name == candidate.name) {
            notes.push(refuse(format!(
                "{} is made at {} already",
                other.name,
                other.placement().spelled()
            )));
            continue;
        }
        made.push(candidate);
    }
    (made, notes)
}

/// The type `text` fitted to `size` bytes: its declared spelling, and the
/// element of an array whose element size the lift knows.
fn fitted(text: &str, size: u32) -> Result<(String, Option<(String, u32)>), String> {
    let parsed = parse_type(text)?;
    match (parsed.array, parsed.count, parsed.element_size) {
        (true, Some(count), Some(each)) => {
            let bytes = u64::from(count) * u64::from(each);
            if bytes != u64::from(size) {
                return Err(format!("{} is {bytes} bytes, not {size}", parsed.text));
            }
            Ok((parsed.text, Some((parsed.element, each))))
        }
        (true, None, Some(each)) => {
            if !size.is_multiple_of(each) {
                return Err(format!(
                    "{size} bytes are no whole number of {}, {each} bytes each",
                    parsed.element
                ));
            }
            Ok((
                format!("{}[{}]", parsed.element, size / each),
                Some((parsed.element, each)),
            ))
        }
        (true, _, None) => Ok((parsed.text, None)),
        (false, _, Some(bytes)) if bytes != size => {
            Err(format!("{} is {bytes} bytes, not {size}", parsed.text))
        }
        (false, _, _) => Ok((parsed.text, None)),
    }
}

/// Read the lift's locals inside each of `made` as parts of it, declare it
/// in their place, and note the ones refused because the function declares
/// their name already. The variables made, with their names and types.
pub(crate) fn make(function: &mut LiftedFunction, made: &[Made]) -> Vec<StackVar> {
    let mut done = Vec::new();
    if function.thunk.is_some() {
        return done;
    }
    let mut parts: BTreeMap<String, AstNode> = BTreeMap::new();
    let mut addresses: Vec<AstNode> = Vec::new();
    for variable in made {
        let inside: Vec<(String, i64, u32, String)> = function
            .locals
            .iter()
            .filter_map(|local| match local.placements.as_slice() {
                [Placement::Stack { offset, size }] if variable.holds(*offset) => {
                    Some((local.name.clone(), *offset, *size, local.ty.clone()))
                }
                _ => None,
            })
            .collect();
        let taken = function.params.iter().chain(&function.locals).any(|other| {
            other.name == variable.name && !inside.iter().any(|(name, ..)| *name == other.name)
        });
        if taken {
            function.notes.push(format!(
                "{} is not made at {}: {} declares {} already",
                variable.name,
                variable.placement().spelled(),
                function.name,
                variable.name
            ));
            continue;
        }
        for (name, offset, size, ty) in &inside {
            let part = part_of(variable, *offset - variable.offset, *size, ty);
            if let AstNode::Deref { target } = &part {
                addresses.push((**target).clone());
            }
            parts.insert(name.clone(), part);
        }
        // Declared where the first of its locals was; with none, among the
        // stack locals by offset, the nearest the frame first.
        let at = function
            .locals
            .iter()
            .position(|local| inside.iter().any(|(name, ..)| *name == local.name))
            .unwrap_or_else(|| {
                function
                    .locals
                    .iter()
                    .position(|local| match local.placements.as_slice() {
                        [Placement::Stack { offset, .. }] => *offset < variable.offset,
                        _ => !local
                            .placements
                            .iter()
                            .any(|p| matches!(p, Placement::Stack { .. })),
                    })
                    .unwrap_or(function.locals.len())
            });
        function
            .locals
            .retain(|local| !inside.iter().any(|(name, ..)| *name == local.name));
        let at = at.min(function.locals.len());
        function.locals.insert(
            at,
            Variable::new(variable.ty.clone(), variable.name.clone()).placed(variable.placement()),
        );
        done.push(StackVar {
            offset: variable.offset,
            size: variable.size,
            name: Some(variable.name.clone()),
            ty: Some(variable.ty.clone()),
        });
    }
    if parts.is_empty() {
        return done;
    }
    let mut rewrite = |node: AstNode| match node {
        AstNode::Var { name } => match parts.get(&name) {
            Some(part) => part.clone(),
            None => AstNode::Var { name },
        },
        // The address of bytes at an offset is the pointer they are read
        // through.
        AstNode::AddressOf { target } => match *target {
            AstNode::Deref { target: pointer } if addresses.contains(&*pointer) => *pointer,
            other => AstNode::AddressOf {
                target: Box::new(other),
            },
        },
        other => other,
    };
    rewrite_all(&mut function.body, &mut rewrite);
    done
}

/// The part of `variable` the lift's local `at` bytes into it, `size` bytes
/// wide and of type `ty`, reads as.
fn part_of(variable: &Made, at: i64, size: u32, ty: &str) -> AstNode {
    let whole = AstNode::var(variable.name.clone());
    if at == 0 && size == variable.size && variable.element.is_none() {
        return whole;
    }
    if let Some((_, each)) = &variable.element {
        if size == *each && at % i64::from(*each) == 0 {
            return AstNode::Intrinsic {
                name: INDEX.to_string(),
                args: vec![whole, AstNode::constant((at / i64::from(*each)) as u64, 8)],
            };
        }
    }
    let address = AstNode::AddressOf {
        target: Box::new(whole),
    };
    let pointer = if at == 0 {
        address
    } else {
        AstNode::binary(
            AstNode::Cast {
                ty: "char *".to_string(),
                target: Box::new(address),
            },
            BinaryOp::Add,
            AstNode::constant(at as u64, 8),
        )
    };
    AstNode::Deref {
        target: Box::new(AstNode::Cast {
            ty: format!("{ty} *"),
            target: Box::new(pointer),
        }),
    }
}

/// Rewrite every node of `statements` with `f`, innermost first: the
/// nested statements, and a `for`'s init and step.
fn rewrite_all(statements: &mut [Statement], f: &mut dyn FnMut(AstNode) -> AstNode) {
    for statement in statements {
        statement.node =
            crate::inline::map(std::mem::replace(&mut statement.node, AstNode::Break), f);
        if let StatementKind::For { init, step, .. } = &mut statement.kind {
            rewrite_all(std::slice::from_mut(init.as_mut()), f);
            rewrite_all(std::slice::from_mut(step.as_mut()), f);
        }
        for child in statement.children_mut() {
            rewrite_all(child, f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_type_is_read_with_its_array_and_element() {
        let parsed = parse_type("char[16]").unwrap();
        assert_eq!(parsed.text, "char[16]");
        assert_eq!(parsed.element, "char");
        assert_eq!(
            (parsed.array, parsed.count, parsed.element_size),
            (true, Some(16), Some(1))
        );
        let parsed = parse_type(" unsigned  int [ 0x4 ] ").unwrap();
        assert_eq!(parsed.text, "unsigned int[4]");
        assert_eq!(parsed.element_size, Some(4));
        assert_eq!(parse_type("char*").unwrap().text, "char *");
        assert_eq!(parse_type("char*").unwrap().element_size, Some(8));
        assert_eq!(parse_type("struct point").unwrap().element_size, None);
        assert_eq!(parse_type("int[]").unwrap().count, None);
        assert!(parse_type("int[2][2]").is_err());
        assert!(parse_type("int[0]").is_err());
        assert!(parse_type("void").is_err());
        assert!(parse_type("").is_err());
        assert_eq!(declarator("char[16]", "buf"), "char buf[16]");
        assert_eq!(declarator("int", "i"), "int i");
    }

    #[test]
    fn a_variable_is_refused_when_its_type_does_not_fit_or_it_overlaps_another() {
        let word = |offset: i64, size: u32, name: &str, ty: &str| StackVar {
            offset,
            size,
            name: (!name.is_empty()).then(|| name.to_string()),
            ty: (!ty.is_empty()).then(|| ty.to_string()),
        };
        let (made, notes) = accept(
            &[
                word(-0x20, 16, "buf", "char[]"),
                word(-0x18, 8, "key", ""),
                word(-0x28, 8, "", ""),
                word(-0x30, 8, "n", "int"),
                word(-0x30, 8, "w", "int[3]"),
                word(-0x30, 8, "2x", ""),
                word(-0x30, 0, "z", ""),
                word(-0x40, 12, "p", "struct point"),
                word(-0x48, 8, "buf", ""),
            ],
            SlotNames::Hex,
        );
        let names: Vec<(&str, &str)> = made
            .iter()
            .map(|m| (m.name.as_str(), m.ty.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("buf", "char[16]"),
                ("local_28", "long"),
                ("p", "struct point")
            ]
        );
        assert_eq!(made[0].element, Some(("char".to_string(), 1)));
        assert_eq!(
            notes,
            [
                "key is not made at [sp-0x18] 8 bytes: it overlaps buf at [sp-0x20] 16 bytes",
                "n is not made at [sp-0x30] 8 bytes: int is 4 bytes, not 8",
                "w is not made at [sp-0x30] 8 bytes: int[3] is 12 bytes, not 8",
                "2x is not made at [sp-0x30] 8 bytes: \"2x\" is not a C identifier",
                "z is not made at [sp-0x30] 0 bytes: it has no size",
                "buf is not made at [sp-0x48] 8 bytes: buf is made at [sp-0x20] 16 bytes already",
            ]
        );
    }
}
