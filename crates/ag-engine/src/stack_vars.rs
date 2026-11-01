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
//! - **a member**: in a structure or union the project's types define
//!   ([`crate::types`]), a local at a member's offset and of its size is
//!   that member, `p.x`, inside nested structures and arrays of them,
//!   `v.inner.g`, `v.a[2].f` — a union's first member the bytes fit, the
//!   choice per instruction being #371's — and its address `&p.x`;
//! - **bytes at an offset**: anything else — a word of a `char` array, a
//!   local at an offset no element or member starts at, or straddling two,
//!   a structure the types do not define — is a load or store at that
//!   byte offset, `*(int *)((char *)&buf + 4)`, at the width of the lift's
//!   local, and its address `(int *)((char *)&buf + 4)`.
//!
//! The lift's locals inside the variable are no longer declared; the
//! variable is, where the first of them was, its type spelled as C declares
//! it: `char buf[16];`, `struct point p;`. A local the code reads at two
//! widths at one offset keeps the lift's type of its first access.
//!
//! Without a name the variable is named as the lift names its slot,
//! `local_20`; without a type it is `char`, `short`, `int` or `long` for a
//! size of 1, 2, 4 or 8 bytes, and an array of `char` otherwise. The type
//! is read by the C parser ([`crate::ctype::parse_type`]) against the
//! project's types. A type of a known size must be the variable's size —
//! an array with no count, `int[]`, takes the count the size gives — and a
//! type the project does not define, `struct point`, is taken at the size
//! given. The name is the variable's lift name: the analyst's renames,
//! merges, splits, versions and pinned values key on it.
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
use crate::types::{Prim, Step, Type, TypeStore};

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
/// it is known.
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
    /// The size of the element in bytes, when it is known: the platform's
    /// primitives and pointers, and what the types define.
    pub element_size: Option<u32>,
}

/// The type `text`, `char[16]`, `int[]`, `struct point`, read against the
/// platform's primitives alone; see [`parse_type_in`].
pub fn parse_type(text: &str) -> Result<ParsedType, String> {
    parse_type_in(&TypeStore::default(), text)
}

/// The type `text` read against the types of `store`: a C type, an array
/// of one, `char[16]` or `int[]`, or a name the store does not define,
/// taken at no known size. `void`, a function, and an array of no
/// elements are refused.
pub fn parse_type_in(store: &TypeStore, text: &str) -> Result<ParsedType, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("the type is empty".to_string());
    }
    let ty = crate::ctype::parse_type(store, text).map_err(|error| error.message)?;
    variable_type(store, &ty)?;
    let (element, array, count) = match &ty {
        Type::Array(element, count) => {
            let count = match count {
                Some(0) => return Err(format!("{} has no elements", ty.spelled(store))),
                Some(n) => Some(
                    u32::try_from(*n).map_err(|_| format!("{} is too large", ty.spelled(store)))?,
                ),
                None => None,
            };
            ((**element).clone(), true, count)
        }
        other => (other.clone(), false, None),
    };
    let element_size = store
        .size_of(&element)
        .ok()
        .and_then(|size| u32::try_from(size).ok());
    Ok(ParsedType {
        text: ty.spelled(store),
        element: element.spelled(store),
        array,
        count,
        element_size,
    })
}

/// Why `ty` is no type a variable can have: `void`, or a function.
fn variable_type(store: &TypeStore, ty: &Type) -> Result<(), String> {
    match store.resolve(ty) {
        Type::Prim(Prim::Void) => Err("a variable of type void holds nothing".to_string()),
        Type::Function { .. } => Err(format!(
            "{} is a function: a variable is a pointer to one",
            ty.spelled(store)
        )),
        _ => Ok(()),
    }
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
/// buf[16]`, `int (*cb)(int)`.
pub fn declarator(ty: &str, name: &str) -> String {
    crate::ctype::declarator(ty, name)
}

/// Whether `name` is a C identifier.
fn identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// An analyst's variable the lift makes: where it is, its name, and its
/// type as declared and as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Made {
    pub(crate) offset: i64,
    pub(crate) size: u32,
    pub(crate) name: String,
    pub(crate) ty: String,
    /// The type read, when the store knows its size: what its parts are
    /// found in.
    pub(crate) parsed: Option<Type>,
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
pub(crate) fn accept(
    words: &[StackVar],
    names: SlotNames,
    store: &TypeStore,
) -> (Vec<Made>, Vec<String>) {
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
        let (ty, parsed) = match word.ty.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            None => {
                let ty = default_type(word.size);
                let parsed = crate::ctype::parse_type(store, &ty).ok();
                (ty, parsed)
            }
            Some(text) => match fitted(store, text, word.size) {
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
            parsed,
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
/// type read when its size is known.
fn fitted(store: &TypeStore, text: &str, size: u32) -> Result<(String, Option<Type>), String> {
    let parsed = parse_type_in(store, text)?;
    let ty = crate::ctype::parse_type(store, text).map_err(|error| error.message)?;
    match (parsed.array, parsed.count, parsed.element_size) {
        (true, Some(count), Some(each)) => {
            let bytes = u64::from(count) * u64::from(each);
            if bytes != u64::from(size) {
                return Err(format!("{} is {bytes} bytes, not {size}", parsed.text));
            }
            Ok((parsed.text, Some(ty)))
        }
        (true, None, Some(each)) => {
            if each == 0 || !size.is_multiple_of(each) {
                return Err(format!(
                    "{size} bytes are no whole number of {}, {each} bytes each",
                    parsed.element
                ));
            }
            let Type::Array(element, _) = ty else {
                unreachable!("an array read as one");
            };
            let whole = Type::Array(element, Some(u64::from(size / each)));
            Ok((whole.spelled(store), Some(whole)))
        }
        (true, _, None) => Ok((parsed.text, None)),
        (false, _, Some(bytes)) if bytes != size => {
            Err(format!("{} is {bytes} bytes, not {size}", parsed.text))
        }
        (false, _, Some(_)) => Ok((parsed.text, Some(ty))),
        (false, _, None) => Ok((parsed.text, None)),
    }
}

/// Read the lift's locals inside each of `made` as parts of it, declare it
/// in their place, and note the ones refused because the function declares
/// their name already. The variables made, with their names and types.
pub(crate) fn make(
    function: &mut LiftedFunction,
    made: &[Made],
    store: &TypeStore,
) -> Vec<StackVar> {
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
            let part = part_of(variable, *offset - variable.offset, *size, ty, store);
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
/// wide and of type `ty`, reads as: the whole, an element or a member the
/// bytes are exactly, or the bytes at the offset.
fn part_of(variable: &Made, at: i64, size: u32, ty: &str, store: &TypeStore) -> AstNode {
    let whole = AstNode::var(variable.name.clone());
    let path = variable.parsed.as_ref().and_then(|parsed| {
        let (path, leaf) = store.field_at(parsed, u64::try_from(at).ok()?, u64::from(size))?;
        // Bytes read whole as a scalar are no array of them.
        (!matches!(store.resolve(&leaf), Type::Array(..))).then_some(path)
    });
    match path {
        Some(path) => return parts_node(whole, &path),
        None if at == 0
            && size == variable.size
            && !matches!(variable.parsed, Some(Type::Array(..)))
            && !variable.ty.ends_with(']') =>
        {
            return whole;
        }
        None => {}
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

/// `base` followed along `path`: `base.inner.a[2]`, each member through
/// [`crate::typed::member`], each element through [`INDEX`].
pub(crate) fn parts_node(base: AstNode, path: &[Step]) -> AstNode {
    path.iter().fold(base, |node, step| match step {
        Step::Field(name) => crate::typed::member(node, name, false),
        Step::Index(index) => AstNode::Intrinsic {
            name: INDEX.to_string(),
            args: vec![node, AstNode::constant(*index, 8)],
        },
    })
}

/// The variable a part names, `buf` of `buf[2]` and of `v.a[1].f`: the
/// array or structure a run of elements and members starts from.
pub fn part_root(node: &AstNode) -> Option<&str> {
    match node {
        AstNode::Var { name } => Some(name),
        _ => {
            if let Some((array, _)) = indexed(node) {
                return part_root(array);
            }
            match crate::typed::member_of(node) {
                Some((base, _, false)) => part_root(base),
                _ => None,
            }
        }
    }
}

/// Whether `node` is a part of a variable the analyst made: an element,
/// `buf[2]`, or a member, `p.x`.
pub fn is_part(node: &AstNode) -> bool {
    indexed(node).is_some() || matches!(crate::typed::member_of(node), Some((_, _, false)))
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
        // An array of arrays is an array of its rows.
        assert_eq!(parse_type("int[2][3]").unwrap().element, "int[3]");
        assert_eq!(parse_type("int[2][3]").unwrap().element_size, Some(12));
        assert!(parse_type("int(int)").is_err());
        assert!(parse_type("int[0]").is_err());
        assert!(parse_type("void").is_err());
        assert!(parse_type("").is_err());
        assert_eq!(declarator("char[16]", "buf"), "char buf[16]");
        assert_eq!(declarator("int", "i"), "int i");
        // Against the project's types, a structure has its size.
        let mut store = TypeStore::default();
        crate::ctype::parse_into(&mut store, "struct point { int x, y; };").unwrap();
        assert_eq!(
            parse_type_in(&store, "struct point").unwrap().element_size,
            Some(8)
        );
        assert_eq!(
            parse_type_in(&store, "struct point[2]")
                .unwrap()
                .element_size,
            Some(8)
        );
    }

    #[test]
    fn a_variable_is_refused_when_its_type_does_not_fit_or_it_overlaps_another() {
        let word = |offset: i64, size: u32, name: &str, ty: &str| StackVar {
            offset,
            size,
            name: (!name.is_empty()).then(|| name.to_string()),
            ty: (!ty.is_empty()).then(|| ty.to_string()),
        };
        let mut store = TypeStore::default();
        crate::ctype::parse_into(&mut store, "struct pair { int a, b; };").unwrap();
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
                word(-0x58, 12, "q", "struct pair"),
                word(-0x58, 8, "q", "struct pair"),
            ],
            SlotNames::Hex,
            &store,
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
                ("p", "struct point"),
                ("q", "struct pair")
            ]
        );
        assert_eq!(
            made[0].parsed,
            Some(Type::Array(Box::new(Type::Prim(Prim::Char)), Some(16)))
        );
        // A structure the types do not define is read at the size given.
        assert_eq!(made[2].parsed, None);
        assert_eq!(
            notes,
            [
                "key is not made at [sp-0x18] 8 bytes: it overlaps buf at [sp-0x20] 16 bytes",
                "n is not made at [sp-0x30] 8 bytes: int is 4 bytes, not 8",
                "w is not made at [sp-0x30] 8 bytes: int[3] is 12 bytes, not 8",
                "2x is not made at [sp-0x30] 8 bytes: \"2x\" is not a C identifier",
                "z is not made at [sp-0x30] 0 bytes: it has no size",
                "buf is not made at [sp-0x48] 8 bytes: buf is made at [sp-0x20] 16 bytes already",
                "q is not made at [sp-0x58] 12 bytes: struct pair is 8 bytes, not 12",
            ]
        );
    }
}
