//! Type propagation: the types the code says of a function's variables
//! without the analyst's words, carried through copies, calls and returns
//! across the call graph, and the arrays and structures on the stack found
//! from how their slots are reached.
//!
//! The lift gives every variable the integer of its width. What the code
//! does with a value says more, and each such thing is a seed:
//!
//! - **a known prototype**: a value passed to `strlen` is a `char *`, the
//!   result of `fopen` a `FILE *` — the prototypes of the C library's,
//!   POSIX's and Windows' common functions, C text in `prototypes.h`, read
//!   by [`crate::ctype`] under the image's data model. A function of the
//!   image named as one of them takes its prototype's types itself;
//! - **the analyst's types** (`var_types`), which are never changed and
//!   are carried to what they reach;
//! - **an allocation**: the result of `malloc` and the other allocators
//!   [`crate::smart_struct`] knows is a pointer;
//! - **a string**: a variable assigned a string, or an argument that is
//!   one — a literal, or a constant address the image holds a string at —
//!   is a `char *`;
//! - **a dereference**: a value loaded or stored through, `*(int *)(p +
//!   8)`, is a pointer — to the type it is read at when every access is
//!   that width at a multiple of it, `int *`, else `void *`; a value
//!   compared with a pointer, or a pointer with a constant added, is one too;
//! - **an unsigned use**: a value read only through unsigned casts — an
//!   unsigned comparison, a zero extension — is the unsigned integer of
//!   its width.
//!
//! The seeds are carried both ways through copies (`b = a;`), from a
//! call's arguments into the callee's parameters and back — every call
//! site passing a `char *` in the first argument makes the callee's first
//! parameter a `char *`, and a callee's parameter known a `char *` makes
//! the argument variable one — and from a callee's return into the call's
//! result; a known prototype's types go into the arguments and the result
//! and do not come back. The facts of each function ([`Facts`]) are read
//! off its lift once; [`solve`] carries the types through them, over every
//! function given at once, to a fixed point or [`ROUNDS`] rounds.
//!
//! The evidence ranks: the analyst's above a prototype's, a string's, an
//! allocation's and what calls and returns carry; those above a
//! dereference's; and an unsigned use last. Evidence of a higher rank
//! replaces a lower; of one rank it joins: `void *` and `char *` are the
//! `char *`; two pointers to different types are `void *`, and a pointer
//! and an integer leave the variable the integer of its width — each with a
//! note in the function's leading comments.
//!
//! The arrays and structures on the stack ([`detect`]) are found before the
//! types, on a first lift that reads a slot's address plus an index as that
//! sum: a run of slots read through an index at a stride of the access's
//! width, `*(int *)((long)&local_38 + (long)i * 4)`, is an array of that
//! element, as long as a comparison of the index with a constant bounds it
//! or to the next slot the code reaches; a slot whose address is passed
//! where a prototype takes a buffer of a constant length (`/* size: N */`
//! in `prototypes.h`) is a `char` array of that length, or an array of the
//! prototype's element; one passed where a prototype or the analyst's type
//! of the callee's parameter takes a known structure is that structure;
//! and, under `auto-structs on`, an address-taken run reached at several
//! offsets is a structure drafted as [`crate::smart_struct::infer_struct`]
//! drafts one, `struct struct_<function>_<slot>`. Each is made a stack
//! variable as the analyst's are ([`crate::stack_vars`]), unless one of the
//! analyst's covers a byte of it, and the function is lifted again with
//! them.
//!
//! Every inference keeps where it came from, which the variables listing
//! shows: `from strlen's parameter 1`, `from the call at 0x401159 in
//! greet`, `dereferenced at 0x401010`, `indexed as an array at 0x401020`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ast::{AstNode, BinaryOp};
use crate::ctype::TypeText;
use crate::lift::{LiftedFunction, Placement, Statement, StatementKind};
use crate::stack_vars::StackVar;
use crate::types::{DataModel, Prim, Type, TypeStore};

/// The prototypes and the types they name, as C.
const PROTOTYPES: &str = include_str!("prototypes.h");

/// The most rounds [`solve`] carries the types over every link.
pub const ROUNDS: usize = 16;

/// A known function's prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prototype {
    /// The function's name.
    pub name: String,
    /// The type it returns.
    pub ret: Type,
    /// Its parameters' types, in order.
    pub params: Vec<Type>,
    /// Whether it takes more after them, `...`.
    pub variadic: bool,
    /// The buffers whose length other arguments give: the buffer's
    /// parameter and the parameters whose product is its length in bytes,
    /// each counted from 0.
    pub sizes: Vec<(usize, Vec<usize>)>,
}

/// The library of known prototypes under one data model, with the types
/// they name.
#[derive(Debug, Clone)]
pub struct Library {
    /// The definitions of the types the prototypes name, one declaration
    /// each, in order.
    pub definitions: Vec<TypeText>,
    /// The definitions, built.
    pub store: TypeStore,
    prototypes: BTreeMap<String, Prototype>,
}

impl Library {
    /// The prototype of the function `name`, under an import's or a stub's
    /// decoration: `strlen@plt`, `__imp_ReadFile`, `_strlen`, `j_strlen`.
    pub fn prototype(&self, name: &str) -> Option<&Prototype> {
        let full = name.trim();
        let bare = full.split('@').next().unwrap_or(full);
        if let Some(found) = self.prototypes.get(bare) {
            return Some(found);
        }
        for prefix in ["__imp__", "__imp_", "_imp_", "j_", "_"] {
            if let Some(rest) = bare.strip_prefix(prefix) {
                if let Some(found) = self.prototypes.get(rest) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Every prototype, by name.
    pub fn prototypes(&self) -> impl Iterator<Item = &Prototype> {
        self.prototypes.values()
    }
}

/// The libraries read so far, one a data model.
type Libraries = Mutex<Vec<(DataModel, Arc<Library>)>>;

/// The library under `model`, read once.
pub fn library(model: DataModel) -> Arc<Library> {
    static LIBRARIES: OnceLock<Libraries> = OnceLock::new();
    let libraries = LIBRARIES.get_or_init(|| Mutex::new(Vec::new()));
    let mut held = libraries.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, found)) = held.iter().find(|(m, _)| *m == model) {
        return Arc::clone(found);
    }
    let built = Arc::new(read_library(model));
    held.push((model, Arc::clone(&built)));
    built
}

/// The declarations of `source`, each without its `;`, with the comments
/// inside them kept: split at each `;` outside braces.
fn declarations(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for line in source.lines() {
        let line = match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        };
        for c in line.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                ';' if depth == 0 => {
                    let text = current.trim().to_string();
                    if !text.is_empty() {
                        out.push(text);
                    }
                    current.clear();
                    continue;
                }
                _ => {}
            }
            current.push(c);
        }
        current.push('\n');
    }
    out
}

fn read_library(model: DataModel) -> Library {
    let mut store = TypeStore::new(model);
    let mut definitions = Vec::new();
    let mut prototypes = BTreeMap::new();
    for declaration in declarations(PROTOTYPES) {
        let head = declaration.split_whitespace().next().unwrap_or("");
        if matches!(head, "struct" | "union" | "enum" | "typedef") {
            let c = format!("{declaration};");
            if crate::ctype::parse_into(&mut store, &c).is_ok() {
                let name = definition_name(&declaration);
                definitions.push(TypeText { name, c });
            }
            continue;
        }
        if let Some(prototype) = read_prototype(&store, &declaration) {
            prototypes
                .entry(prototype.name.clone())
                .or_insert(prototype);
        }
    }
    Library {
        definitions,
        store,
        prototypes,
    }
}

/// The name a type declaration defines: `struct timeval`, `FILE`.
fn definition_name(declaration: &str) -> String {
    let words: Vec<&str> = declaration
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    match words.first() {
        Some(&"typedef") => words.last().copied().unwrap_or("").to_string(),
        Some(kind) => format!("{kind} {}", words.get(1).copied().unwrap_or("")),
        None => String::new(),
    }
}

/// One prototype, `size_t strlen(const char *s)`, with its `/* size: N */`
/// annotations.
fn read_prototype(store: &TypeStore, declaration: &str) -> Option<Prototype> {
    let open = declaration.find('(')?;
    let close = declaration.rfind(')')?;
    let head = declaration[..open].trim_end();
    let name_start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |at| at + 1);
    let name = head[name_start..].to_string();
    let ret = crate::ctype::parse_type(store, head[..name_start].trim()).ok()?;
    let mut params = Vec::new();
    let mut variadic = false;
    let mut sizes = Vec::new();
    let inner = &declaration[open + 1..close];
    for (index, piece) in split_top(inner).into_iter().enumerate() {
        let (text, size) = annotation(&piece);
        let text = text.trim();
        if text == "..." {
            variadic = true;
            continue;
        }
        if text == "void" && index == 0 {
            continue;
        }
        let ty = crate::ctype::parse_type(store, &unnamed(text)).ok()?;
        if let Some(size) = size {
            sizes.push((index, size));
        }
        params.push(ty);
    }
    Some(Prototype {
        name,
        ret,
        params,
        variadic,
        sizes,
    })
}

/// The pieces of a parameter list, split at the commas outside
/// parentheses.
fn split_top(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// A parameter's text without its comments, and the arguments its
/// `/* size: N */` or `/* size: N*M */` names, from 0.
fn annotation(piece: &str) -> (String, Option<Vec<usize>>) {
    let mut text = String::new();
    let mut size = None;
    let mut rest = piece;
    while let Some(start) = rest.find("/*") {
        text.push_str(&rest[..start]);
        let Some(end) = rest[start..].find("*/") else {
            rest = "";
            break;
        };
        let comment = rest[start + 2..start + end].trim();
        if let Some(arguments) = comment.strip_prefix("size:") {
            let parsed: Option<Vec<usize>> = arguments
                .split('*')
                .map(|n| n.trim().parse::<usize>().ok()?.checked_sub(1))
                .collect();
            size = parsed;
        }
        rest = &rest[start + end + 2..];
    }
    text.push_str(rest);
    (text, size)
}

/// A parameter's type without its name: `const char *s` is `const char *`,
/// `int (*compare)(const void *)` is `int (*)(const void *)`.
fn unnamed(text: &str) -> String {
    if let Some(open) = text.find("(*") {
        let after = &text[open + 2..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        return format!("{}(*{}", &text[..open], &after[end..]);
    }
    let end = text.trim_end();
    let start = end
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |at| at + 1);
    end[..start].trim_end().to_string()
}

/// `store` with the library's types it does not define itself: what the
/// variables' inferred types name, `FILE *`, `struct timeval`.
pub fn with_library(store: &TypeStore) -> TypeStore {
    let library = library(*store.model());
    let mut out = store.clone();
    for definition in &library.definitions {
        if store.key_of(&definition.name).is_some() || store.get(&definition.name).is_some() {
            continue;
        }
        let _ = crate::ctype::parse_into(&mut out, &definition.c);
    }
    out
}

/// The library's definitions the types `names` need, in order, that
/// `store` does not define: what a program written from the inferred
/// types declares ahead of its functions.
pub fn library_definitions(store: &TypeStore) -> Vec<TypeText> {
    library(*store.model())
        .definitions
        .iter()
        .filter(|d| store.key_of(&d.name).is_none() && store.get(&d.name).is_none())
        .cloned()
        .collect()
}

// ---- the facts ------------------------------------------------------------

/// A place a type is inferred for in one function: a variable, by its lift
/// name, or the value the function returns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    Var(String),
    Return,
}

impl Slot {
    fn spelled(&self) -> String {
        match self {
            Slot::Var(name) => name.clone(),
            Slot::Return => "the return".to_string(),
        }
    }
}

/// What a use says of a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// It is of this type.
    Type(Type),
    /// It is a pointer, to nothing known.
    Pointer,
}

/// How much evidence weighs: the analyst's, then a prototype's, a
/// string's, an allocation's and what calls carry, then a dereference's,
/// then an unsigned use.
pub const ANALYST: u8 = 3;
pub const EXACT: u8 = 2;
pub const POINTER: u8 = 1;
pub const UNSIGNED: u8 = 0;

/// One seed: what is known of a slot, how much it weighs and where it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    pub slot: Slot,
    pub rank: u8,
    pub evidence: Evidence,
    pub source: String,
}

/// How a link carries a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// A copy, `b = a;`: the type, either way.
    Copy,
    /// A comparison of the two: a pointer, either way, at a dereference's
    /// rank.
    Compared,
    /// `to = from + k`: a pointer to a scalar as it is, another pointer as
    /// `void *`, from `from` to `to` only.
    Derived,
}

/// A link between two slots of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub from: Slot,
    pub to: Slot,
    pub kind: LinkKind,
    pub at: u64,
}

/// An argument of a call, as the facts read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// A variable of the caller.
    Var(String),
    /// A value whose type is known where it is: a string, an address.
    Seed(u8, Evidence, String),
    /// Anything else.
    Other,
}

/// A call the function makes to a function the image names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    /// The address of the call's statement.
    pub at: u64,
    /// The callee's address.
    pub callee: u64,
    /// The callee's name.
    pub name: String,
    pub args: Vec<Arg>,
    /// The variable the result is assigned to, when it is.
    pub result: Option<String>,
}

/// What one function's lift says of its variables' types: the slots and
/// their widths, the analyst's types, the seeds, the links between the
/// slots, and the calls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Facts {
    pub address: u64,
    pub name: String,
    /// The parameters' lift names, in order.
    pub params: Vec<String>,
    /// The width of each slot a type may be inferred for, in bytes.
    pub widths: BTreeMap<Slot, u64>,
    /// The slots the analyst typed, which keep their types.
    pub fixed: BTreeSet<Slot>,
    pub seeds: Vec<Seed>,
    pub links: Vec<Link>,
    pub calls: Vec<CallFact>,
}

/// The types the code says of a slot's value through one dereference.
#[derive(Debug, Clone)]
struct Deref {
    pointee: Type,
    width: u64,
    offset: i64,
    stride: Option<u64>,
    at: u64,
}

struct Reader<'a> {
    store: &'a TypeStore,
    /// The types of the stack variables made in the frame, by name.
    made: BTreeMap<String, Type>,
    strings: &'a dyn Fn(u64) -> Option<String>,
    facts: Facts,
    derefs: BTreeMap<String, Vec<Deref>>,
    /// Each variable's reads, and those of them through an unsigned cast,
    /// with the first address of one.
    reads: BTreeMap<String, (usize, usize, u64)>,
    /// The variables assigned an address, with the first address of one,
    /// and those assigned a constant other than 0: an address is a
    /// pointer's only where no number is assigned too.
    addressed: BTreeMap<String, u64>,
    numbered: BTreeSet<String>,
    /// The first address of the statement being read: where a
    /// dereference is said to be.
    first: u64,
}

/// The facts of `function`, as its body reads once the analyst's words are
/// made: `fixed` the variables the analyst typed, `made` the stack
/// variables, whose types are their own, and `strings` the string the
/// image holds at an address, when it holds one.
pub fn facts(
    function: &LiftedFunction,
    store: &TypeStore,
    fixed: &BTreeSet<String>,
    made: &[StackVar],
    strings: &dyn Fn(u64) -> Option<String>,
) -> Facts {
    let made_types = made
        .iter()
        .filter_map(|var| {
            let ty = crate::ctype::parse_type(store, var.ty.as_deref()?).ok()?;
            Some((var.name.clone()?, ty))
        })
        .collect();
    let mut reader = Reader {
        store,
        made: made_types,
        strings,
        facts: Facts {
            address: function.address,
            name: function.name.clone(),
            params: function.params.iter().map(|v| v.name.clone()).collect(),
            ..Facts::default()
        },
        derefs: BTreeMap::new(),
        reads: BTreeMap::new(),
        addressed: BTreeMap::new(),
        numbered: BTreeSet::new(),
        first: function.address,
    };
    if function.thunk.is_some() {
        return reader.facts;
    }
    for variable in function.params.iter().chain(&function.locals) {
        if variable.fragment.is_some()
            || made
                .iter()
                .any(|m| m.name.as_deref() == Some(variable.name.as_str()))
        {
            continue;
        }
        let Ok(ty) = crate::ctype::parse_type(store, &variable.ty) else {
            continue;
        };
        if !store.is_scalar(&ty) {
            continue;
        }
        let Ok(size) = store.size_of(&ty) else {
            continue;
        };
        let slot = Slot::Var(variable.name.clone());
        reader.facts.widths.insert(slot.clone(), size);
        if fixed.contains(&variable.name) {
            reader.facts.fixed.insert(slot.clone());
            reader.facts.seeds.push(Seed {
                slot,
                rank: ANALYST,
                evidence: evidence_of(store, ty),
                source: format!("from the analyst's type of {}", variable.name),
            });
        }
    }
    if function.return_type != "void" {
        if let Ok(ty) = crate::ctype::parse_type(store, &function.return_type) {
            if let Ok(size) = store.size_of(&ty) {
                reader.facts.widths.insert(Slot::Return, size);
                if fixed.contains(crate::typed::RETURN) {
                    reader.facts.fixed.insert(Slot::Return);
                }
            }
        }
    }
    reader.statements(&function.body, function.address);
    reader.finish();
    reader.facts
}

/// The evidence a type is: a pointer to `void` is a pointer to nothing
/// known.
fn evidence_of(store: &TypeStore, ty: Type) -> Evidence {
    match store.resolve(&ty) {
        Type::Pointer(pointee) if matches!(**pointee, Type::Prim(Prim::Void)) => Evidence::Pointer,
        _ => Evidence::Type(ty),
    }
}

/// The stack variable made in the frame an address is the start of — the
/// variable's own address, or its first member's, `&v.tv_sec` — and the
/// type it points at: the variable's, or an array's element.
fn made_address(
    node: &AstNode,
    made: &BTreeMap<String, Type>,
    store: &TypeStore,
) -> Option<(String, Type)> {
    let AstNode::AddressOf { target } = crate::slice::strip_casts(node) else {
        return None;
    };
    let mut path = Vec::new();
    let mut at = target.as_ref();
    loop {
        if let Some((base, field, false)) = crate::typed::member_of(at) {
            path.push(crate::types::Step::Field(field.to_string()));
            at = base;
        } else if let Some((array, AstNode::Constant { value: 0, .. })) =
            crate::stack_vars::indexed(at)
        {
            path.push(crate::types::Step::Index(0));
            at = array;
        } else {
            break;
        }
    }
    let AstNode::Var { name } = at else {
        return None;
    };
    let ty = made.get(name)?;
    path.reverse();
    if !path.is_empty() && store.path_offset(ty, &path)?.0 != 0 {
        return None;
    }
    let pointee = match store.resolve(ty) {
        Type::Array(element, _) => (**element).clone(),
        _ => ty.clone(),
    };
    Some((name.clone(), pointee))
}

/// The nodes directly inside `node`.
fn children(node: &AstNode) -> Vec<&AstNode> {
    match node {
        AstNode::Binary { lhs, rhs, .. } | AstNode::Assign { lhs, rhs } => vec![lhs, rhs],
        AstNode::Deref { target }
        | AstNode::AddressOf { target }
        | AstNode::Cast { target, .. } => {
            vec![target]
        }
        AstNode::Call { callee, args } => std::iter::once(callee.as_ref()).chain(args).collect(),
        AstNode::Intrinsic { args, .. } => args.iter().collect(),
        AstNode::StructInit { fields } => fields.iter().map(|f| &f.value).collect(),
        AstNode::Return { value } => value.iter().map(|v| v.as_ref()).collect(),
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => std::iter::once(cond.as_ref())
            .chain(std::iter::once(then_part.as_ref()))
            .chain(else_part.iter().map(|e| e.as_ref()))
            .collect(),
        AstNode::IfGoto { cond, .. } => vec![cond],
        AstNode::Loop { cond, body, .. } => cond
            .iter()
            .map(|c| c.as_ref())
            .chain(std::iter::once(body.as_ref()))
            .collect(),
        AstNode::ConstantCondition { compared, .. } => vec![compared],
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => vec![cond, then, otherwise],
        _ => Vec::new(),
    }
}

/// Every statement of `body` with the addresses it is at — the first of
/// its instructions and the last, the call or the store itself — the
/// statements of a `for`'s head included, in order.
fn each_statement<'a>(body: &'a [Statement], at: u64, out: &mut Vec<(&'a AstNode, u64, u64)>) {
    let ends = |statement: &Statement, or: u64| {
        (
            statement.addresses.iter().min().copied().unwrap_or(or),
            statement.addresses.iter().max().copied().unwrap_or(or),
        )
    };
    for statement in body {
        let (first, last) = ends(statement, at);
        if let StatementKind::For { init, step, .. } = &statement.kind {
            let (a, b) = ends(init, last);
            out.push((&init.node, a, b));
            out.push((&statement.node, first, last));
            let (a, b) = ends(step, last);
            out.push((&step.node, a, b));
        } else {
            out.push((&statement.node, first, last));
        }
        for child in statement.children() {
            each_statement(child, last, out);
        }
    }
}

/// Whether `op` compares.
fn compares(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Equal
            | BinaryOp::NotEqual
            | BinaryOp::Less
            | BinaryOp::LessEqual
            | BinaryOp::Greater
            | BinaryOp::GreaterEqual
    )
}

/// The type a cast names, when it is an unsigned integer.
fn unsigned_cast(store: &TypeStore, ty: &str) -> bool {
    crate::ctype::parse_type(store, ty).ok().is_some_and(
        |ty| matches!(store.resolve(&ty), Type::Prim(p) if p.is_integer() && !p.is_signed()),
    )
}

/// The terms of a sum, through the casts on it, each with whether it is
/// taken away.
fn terms(node: &AstNode, negative: bool, out: &mut Vec<(bool, AstNode)>) {
    match node {
        AstNode::Cast { target, .. } => terms(target, negative, out),
        AstNode::Binary {
            lhs,
            op: BinaryOp::Add,
            rhs,
        } => {
            terms(lhs, negative, out);
            terms(rhs, negative, out);
        }
        AstNode::Binary {
            lhs,
            op: BinaryOp::Sub,
            rhs,
        } => {
            terms(lhs, negative, out);
            terms(rhs, !negative, out);
        }
        other => out.push((negative, other.clone())),
    }
}

/// A scaled term, `i * 4` or `i << 2`: the index and the scale.
fn scaled(term: &AstNode) -> Option<(&AstNode, u64)> {
    match term {
        AstNode::Binary {
            lhs,
            op: BinaryOp::Mul,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (by, AstNode::Constant { value, .. }) | (AstNode::Constant { value, .. }, by) => {
                Some((by, *value))
            }
            _ => None,
        },
        AstNode::Binary {
            lhs,
            op: BinaryOp::Shl,
            rhs,
        } => match rhs.as_ref() {
            AstNode::Constant { value, .. } if *value < 32 => Some((lhs, 1u64 << value)),
            _ => None,
        },
        AstNode::Cast { target, .. } => scaled(target),
        _ => None,
    }
}

impl Reader<'_> {
    fn width(&self, name: &str) -> Option<u64> {
        self.facts.widths.get(&Slot::Var(name.to_string())).copied()
    }

    fn pointer_size(&self) -> u64 {
        self.store.model().pointer
    }

    fn char_pointer(&self) -> Type {
        Type::pointer(Type::Prim(Prim::Char))
    }

    fn seed(&mut self, slot: Slot, rank: u8, evidence: Evidence, source: String) {
        if self.facts.widths.contains_key(&slot) {
            self.facts.seeds.push(Seed {
                slot,
                rank,
                evidence,
                source,
            });
        }
    }

    /// The variable `node` is, under casts that keep its width.
    fn var_of<'n>(&self, node: &'n AstNode) -> Option<&'n str> {
        match node {
            AstNode::Var { name } => self.width(name).map(|_| name.as_str()),
            AstNode::Cast { ty, target } => {
                let inner = self.var_of(target)?;
                let cast = crate::ctype::parse_type(self.store, ty).ok()?;
                (self.store.size_of(&cast).ok()? == self.width(inner)?).then_some(inner)
            }
            _ => None,
        }
    }

    /// The string `node` is: a literal, or a constant address the image
    /// holds one at.
    fn string(&self, node: &AstNode) -> bool {
        match crate::slice::strip_casts(node) {
            AstNode::StringLiteral { .. } => true,
            AstNode::Constant { value, .. } => *value >= 0x1000 && (self.strings)(*value).is_some(),
            _ => false,
        }
    }

    fn statements(&mut self, body: &[Statement], at: u64) {
        let mut all = Vec::new();
        each_statement(body, at, &mut all);
        for (node, first, at) in all {
            self.first = first;
            self.node(node, at);
        }
    }

    fn node(&mut self, node: &AstNode, at: u64) {
        match node {
            AstNode::Assign { lhs, rhs } => {
                if let AstNode::Var { name } = lhs.as_ref() {
                    if self.width(name).is_some() {
                        self.assigned(name, rhs, at);
                        return;
                    }
                }
                self.node(lhs, at);
                self.node(rhs, at);
            }
            AstNode::Call { .. } => self.call(node, None, at),
            AstNode::Deref { target } => {
                if let AstNode::Cast {
                    ty,
                    target: address,
                } = target.as_ref()
                {
                    self.deref(ty, address, at);
                }
                self.node(target, at);
            }
            AstNode::Return { value: Some(value) } => {
                if self.facts.widths.contains_key(&Slot::Return) {
                    if let Some(var) = self.var_of(value) {
                        let var = var.to_string();
                        self.copy(Slot::Var(var), Slot::Return, at);
                    } else if self.string(value) {
                        let ty = self.char_pointer();
                        self.seed(
                            Slot::Return,
                            EXACT,
                            Evidence::Type(ty),
                            format!("a string returned at {at:#x}"),
                        );
                    }
                }
                self.node(value, at);
            }
            AstNode::Binary { lhs, op, rhs } if compares(*op) => {
                let pointer = self.pointer_size();
                if let (Some(a), Some(b)) = (self.var_of(lhs), self.var_of(rhs)) {
                    if a != b && self.width(a) == Some(pointer) && self.width(b) == Some(pointer) {
                        for (from, to) in [(a, b), (b, a)] {
                            self.facts.links.push(Link {
                                from: Slot::Var(from.to_string()),
                                to: Slot::Var(to.to_string()),
                                kind: LinkKind::Compared,
                                at,
                            });
                        }
                    }
                }
                self.node(lhs, at);
                self.node(rhs, at);
            }
            AstNode::Cast { ty, target } => {
                if let AstNode::Var { name } = target.as_ref() {
                    if self.width(name).is_some() {
                        let unsigned = unsigned_cast(self.store, ty);
                        let entry = self.reads.entry(name.clone()).or_insert((0, 0, at));
                        entry.0 += 1;
                        if unsigned {
                            if entry.1 == 0 {
                                entry.2 = at;
                            }
                            entry.1 += 1;
                        }
                        return;
                    }
                }
                self.node(target, at);
            }
            AstNode::Var { name } => {
                if self.width(name).is_some() {
                    self.reads.entry(name.clone()).or_insert((0, 0, at)).0 += 1;
                }
            }
            AstNode::AddressOf { target } if matches!(target.as_ref(), AstNode::Var { .. }) => {}
            other => {
                for child in children(other) {
                    self.node(child, at);
                }
            }
        }
    }

    fn copy(&mut self, a: Slot, b: Slot, at: u64) {
        for (from, to) in [(a.clone(), b.clone()), (b, a)] {
            self.facts.links.push(Link {
                from,
                to,
                kind: LinkKind::Copy,
                at,
            });
        }
    }

    /// `name = rhs;`
    fn assigned(&mut self, name: &str, rhs: &AstNode, at: u64) {
        let slot = Slot::Var(name.to_string());
        if let Some(from) = self.var_of(rhs) {
            if from != name {
                let from = from.to_string();
                self.copy(Slot::Var(from), slot, at);
            }
            self.node(rhs, at);
            return;
        }
        match crate::slice::strip_casts(rhs) {
            call @ AstNode::Call { .. } => {
                self.call(call, Some(name), at);
                return;
            }
            AstNode::AddressOf { .. } => {
                self.addressed.entry(name.to_string()).or_insert(at);
            }
            AstNode::Constant { value, .. } if *value != 0 && !self.string(rhs) => {
                self.numbered.insert(name.to_string());
            }
            AstNode::Binary {
                lhs,
                op: op @ (BinaryOp::Add | BinaryOp::Sub),
                rhs: other,
            } => {
                let sides: Vec<&AstNode> = if *op == BinaryOp::Add {
                    vec![lhs, other]
                } else {
                    vec![lhs]
                };
                let pointer = self.pointer_size();
                for side in sides {
                    if let Some(from) = self.var_of(side) {
                        if from != name && self.width(from) == Some(pointer) {
                            self.facts.links.push(Link {
                                from: Slot::Var(from.to_string()),
                                to: slot.clone(),
                                kind: LinkKind::Derived,
                                at,
                            });
                        }
                    }
                }
            }
            _ if self.string(rhs) => {
                let ty = self.char_pointer();
                self.seed(
                    slot,
                    EXACT,
                    Evidence::Type(ty),
                    format!("a string assigned at {at:#x}"),
                );
            }
            _ => {}
        }
        self.node(rhs, at);
    }

    fn call(&mut self, node: &AstNode, result: Option<&str>, at: u64) {
        let AstNode::Call { callee, args } = node else {
            return;
        };
        for arg in args {
            self.node(arg, at);
        }
        let AstNode::FunctionName { name, address } = callee.as_ref() else {
            self.node(callee, at);
            return;
        };
        if let Some(result) = result {
            if crate::smart_struct::is_allocator(name) {
                self.seed(
                    Slot::Var(result.to_string()),
                    EXACT,
                    Evidence::Pointer,
                    format!("allocated by {name} at {at:#x}"),
                );
            }
        }
        let args = args
            .iter()
            .map(|arg| {
                if let Some(var) = self.var_of(arg) {
                    Arg::Var(var.to_string())
                } else if self.string(arg) {
                    Arg::Seed(
                        EXACT,
                        Evidence::Type(self.char_pointer()),
                        format!("a string passed at {at:#x}"),
                    )
                } else if let Some((var, pointee)) = made_address(arg, &self.made, self.store) {
                    Arg::Seed(
                        EXACT,
                        evidence_of(self.store, Type::pointer(pointee)),
                        format!("the address of {var} passed at {at:#x}"),
                    )
                } else if matches!(crate::slice::strip_casts(arg), AstNode::AddressOf { .. }) {
                    Arg::Seed(
                        POINTER,
                        Evidence::Pointer,
                        format!("an address passed at {at:#x}"),
                    )
                } else {
                    Arg::Other
                }
            })
            .collect();
        self.facts.calls.push(CallFact {
            at,
            callee: *address,
            name: name.clone(),
            args,
            result: result.map(str::to_string),
        });
    }

    /// `*(ty)address`: a dereference of the pointer the address is
    /// computed from.
    fn deref(&mut self, ty: &str, address: &AstNode, at: u64) {
        let Ok(Type::Pointer(pointee)) = crate::ctype::parse_type(self.store, ty) else {
            return;
        };
        let Ok(width) = self.store.size_of(&pointee) else {
            return;
        };
        let mut found = Vec::new();
        terms(address, false, &mut found);
        let pointer = self.pointer_size();
        let mut base: Option<String> = None;
        let mut offset: i64 = 0;
        let mut stride: Option<u64> = None;
        let mut bases = 0;
        for (negative, term) in &found {
            match term {
                AstNode::Constant { value, .. } => {
                    let value = *value as i64;
                    offset = if *negative {
                        offset.wrapping_sub(value)
                    } else {
                        offset.wrapping_add(value)
                    };
                }
                AstNode::Var { name } if !negative && self.width(name) == Some(pointer) => {
                    bases += 1;
                    base = Some(name.clone());
                }
                other if !negative => match scaled(other) {
                    Some((_, scale)) => stride = Some(scale),
                    None => stride = stride.or(Some(1)),
                },
                _ => return,
            }
        }
        if bases != 1 {
            return;
        }
        let Some(base) = base else {
            return;
        };
        self.derefs.entry(base).or_default().push(Deref {
            pointee: (*pointee).clone(),
            width,
            offset,
            stride,
            at: self.first.min(at),
        });
    }

    /// The seeds the dereferences and the reads make, once the body is read.
    fn finish(&mut self) {
        let derefs = std::mem::take(&mut self.derefs);
        for (name, all) in derefs {
            let first = &all[0];
            let one = all.iter().all(|d| {
                d.width == first.width
                    && d.pointee == first.pointee
                    && d.offset.rem_euclid(d.width.max(1) as i64) == 0
                    && d.stride.is_none_or(|s| s == d.width)
            });
            let indexed = all.iter().find(|d| d.stride.is_some());
            let source = match indexed {
                Some(d) => format!("indexed as an array at {:#x}", d.at),
                None => format!("dereferenced at {:#x}", first.at),
            };
            let evidence = if one && self.store.is_scalar(&first.pointee) {
                Evidence::Type(Type::pointer(first.pointee.clone()))
            } else {
                Evidence::Pointer
            };
            self.seed(Slot::Var(name), POINTER, evidence, source);
        }
        let addressed = std::mem::take(&mut self.addressed);
        for (name, at) in addressed {
            if !self.numbered.contains(&name) {
                self.seed(
                    Slot::Var(name),
                    POINTER,
                    Evidence::Pointer,
                    format!("an address assigned at {at:#x}"),
                );
            }
        }
        let reads = std::mem::take(&mut self.reads);
        for (name, (all, unsigned, at)) in reads {
            if all == 0 || unsigned != all {
                continue;
            }
            let Some(width) = self.width(&name) else {
                continue;
            };
            let Some(ty) = unsigned_of(self.store, width) else {
                continue;
            };
            self.seed(
                Slot::Var(name),
                UNSIGNED,
                Evidence::Type(ty),
                format!("used unsigned at {at:#x}"),
            );
        }
    }
}

/// The unsigned integer of `width` bytes.
fn unsigned_of(store: &TypeStore, width: u64) -> Option<Type> {
    let model = store.model();
    Some(Type::Prim(match width {
        1 => Prim::UChar,
        2 => Prim::UShort,
        4 => Prim::UInt,
        8 if model.long == 8 => Prim::ULong,
        8 => Prim::ULongLong,
        _ => return None,
    }))
}

// ---- the solution ---------------------------------------------------------

/// What propagation found for one function: each slot's type, spelled,
/// with where it came from, the types of its callees' parameters, and the
/// notes on the evidence that disagreed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionTypes {
    pub variables: BTreeMap<String, (String, String)>,
    pub return_type: Option<(String, String)>,
    /// The parameters of each callee of the image, by its address, as the
    /// solution types them.
    pub callee_params: BTreeMap<u64, Vec<Option<String>>>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// A pointer to nothing known: `void *`.
    Pointer,
    Is(Type),
    /// Two pointers that disagree: `void *`.
    Pointers,
    /// A pointer and an integer, or two integers, that disagree: the
    /// integer of the width.
    Clash,
}

#[derive(Debug, Clone)]
struct State {
    rank: u8,
    value: Value,
    source: String,
}

type Key = (u64, Slot);

/// How a link across functions says where the type came from.
#[derive(Debug, Clone)]
enum Via {
    Keep,
    Text(String),
    /// Back from a callee's parameter: `from the call at 0x401234 to
    /// parse(char *)`.
    CallTo(u64, String),
}

#[derive(Debug, Clone)]
struct Edge {
    from: Key,
    to: Key,
    kind: LinkKind,
    via: Via,
}

struct Solver<'a> {
    store: &'a TypeStore,
    widths: BTreeMap<Key, u64>,
    fixed: BTreeSet<Key>,
    states: BTreeMap<Key, State>,
    names: BTreeMap<u64, String>,
    notes: BTreeMap<u64, Vec<String>>,
    noted: BTreeSet<Key>,
}

impl Solver<'_> {
    fn is_pointer(&self, ty: &Type) -> bool {
        matches!(self.store.resolve(ty), Type::Pointer(_))
    }

    fn same(&self, a: &Type, b: &Type) -> bool {
        a == b || self.store.resolve(a) == self.store.resolve(b)
    }

    /// Whether the evidence fits the slot's width.
    fn fits(&self, key: &Key, evidence: &Evidence) -> bool {
        let Some(&width) = self.widths.get(key) else {
            return false;
        };
        match evidence {
            Evidence::Pointer => width == self.store.model().pointer,
            Evidence::Type(ty) => {
                self.store.is_scalar(ty) && self.store.size_of(ty).ok() == Some(width)
            }
        }
    }

    /// Offer the slot `key` evidence of `rank` from `source`; whether its
    /// state changed.
    fn offer(&mut self, key: &Key, rank: u8, evidence: Evidence, source: String) -> bool {
        if !self.fits(key, &evidence) {
            return false;
        }
        let incoming = match evidence {
            Evidence::Pointer => Value::Pointer,
            Evidence::Type(ty) => Value::Is(ty),
        };
        let Some(state) = self.states.get(key).cloned() else {
            self.states.insert(
                key.clone(),
                State {
                    rank,
                    value: incoming,
                    source,
                },
            );
            return true;
        };
        if self.fixed.contains(key) || rank < state.rank {
            return false;
        }
        if rank > state.rank {
            self.states.insert(
                key.clone(),
                State {
                    rank,
                    value: incoming,
                    source,
                },
            );
            return true;
        }
        let joined = match (&state.value, &incoming) {
            (Value::Clash, _) => return false,
            (Value::Pointers, Value::Is(ty)) if !self.is_pointer(ty) => Value::Clash,
            (Value::Pointers, _) => return false,
            (Value::Pointer, Value::Pointer) => return false,
            (Value::Pointer, Value::Is(ty)) if self.is_pointer(ty) => {
                self.states.insert(
                    key.clone(),
                    State {
                        rank,
                        value: incoming,
                        source,
                    },
                );
                return true;
            }
            (Value::Is(ty), Value::Pointer) if self.is_pointer(ty) => return false,
            (Value::Is(a), Value::Is(b)) if self.same(a, b) => return false,
            (Value::Is(a), Value::Is(b)) if self.is_pointer(a) && self.is_pointer(b) => {
                Value::Pointers
            }
            _ => Value::Clash,
        };
        if self.noted.insert(key.clone()) {
            let spell = |value: &Value| match value {
                Value::Pointer | Value::Pointers => "void *".to_string(),
                Value::Is(ty) => ty.spelled(self.store),
                Value::Clash => "an integer".to_string(),
            };
            let name = key.1.spelled();
            let (old, new) = (spell(&state.value), spell(&incoming));
            let note = match &joined {
                Value::Pointers => {
                    format!("{name} is void *: {old} {}, {new} {source}", state.source)
                }
                _ => format!(
                    "{name} keeps the integer of its width: {old} {}, {new} {source}",
                    state.source
                ),
            };
            self.notes.entry(key.0).or_default().push(note);
        }
        self.states.insert(
            key.clone(),
            State {
                rank,
                value: joined,
                source: state.source,
            },
        );
        true
    }

    /// What a link carries out of the state of its slot.
    fn carried(&self, state: &State, kind: LinkKind) -> Option<(u8, Evidence)> {
        let evidence = match &state.value {
            Value::Is(ty) => Evidence::Type(ty.clone()),
            Value::Pointer | Value::Pointers => Evidence::Pointer,
            Value::Clash => return None,
        };
        let rank = state.rank.min(EXACT);
        match kind {
            LinkKind::Copy => Some((rank, evidence)),
            LinkKind::Compared | LinkKind::Derived => {
                let evidence = match evidence {
                    Evidence::Type(ty) => match self.store.resolve(&ty) {
                        Type::Pointer(pointee)
                            if kind == LinkKind::Compared
                                || (self.store.is_scalar(pointee)
                                    && !matches!(
                                        self.store.resolve(pointee),
                                        Type::Pointer(_)
                                    )) =>
                        {
                            Evidence::Type(ty.clone())
                        }
                        Type::Pointer(_) => Evidence::Pointer,
                        _ => return None,
                    },
                    Evidence::Pointer => Evidence::Pointer,
                };
                Some((rank.min(POINTER), evidence))
            }
        }
    }
}

/// The types of the slots of the functions `program` holds the facts of,
/// carried through every function's links and between the functions
/// through their calls, to a fixed point or [`ROUNDS`] rounds, by
/// function.
pub fn solve(program: &[&Facts], store: &TypeStore) -> BTreeMap<u64, FunctionTypes> {
    let library = library(*store.model());
    let mut solver = Solver {
        store,
        widths: BTreeMap::new(),
        fixed: BTreeSet::new(),
        states: BTreeMap::new(),
        names: BTreeMap::new(),
        notes: BTreeMap::new(),
        noted: BTreeSet::new(),
    };
    let by_address: BTreeMap<u64, &Facts> = program.iter().map(|f| (f.address, *f)).collect();
    // The analyst's and the prototypes' seeds first, so the sources they
    // give are the ones kept where another seed agrees.
    let mut first: Vec<(Key, u8, Evidence, String)> = Vec::new();
    let mut then: Vec<(Key, u8, Evidence, String)> = Vec::new();
    let mut edges: Vec<Edge> = Vec::new();
    for facts in program {
        let f = facts.address;
        solver.names.insert(f, facts.name.clone());
        for (slot, width) in &facts.widths {
            solver.widths.insert((f, slot.clone()), *width);
        }
        for slot in &facts.fixed {
            solver.fixed.insert((f, slot.clone()));
        }
        for seed in &facts.seeds {
            let entry = (
                (f, seed.slot.clone()),
                seed.rank,
                seed.evidence.clone(),
                seed.source.clone(),
            );
            if seed.rank == ANALYST {
                first.push(entry);
            } else {
                then.push(entry);
            }
        }
        // The function's own prototype, when it is a known one.
        if let Some(prototype) = library.prototype(&facts.name) {
            for (param, ty) in facts.params.iter().zip(&prototype.params) {
                first.push((
                    (f, Slot::Var(param.clone())),
                    EXACT,
                    evidence_of(store, ty.clone()),
                    format!("from {}'s prototype", prototype.name),
                ));
            }
            first.push((
                (f, Slot::Return),
                EXACT,
                evidence_of(store, prototype.ret.clone()),
                format!("from {}'s prototype", prototype.name),
            ));
        }
        for link in &facts.links {
            edges.push(Edge {
                from: (f, link.from.clone()),
                to: (f, link.to.clone()),
                kind: link.kind,
                via: match link.kind {
                    LinkKind::Copy => Via::Keep,
                    LinkKind::Compared => Via::Text(format!(
                        "compared with {} at {:#x}",
                        link.from.spelled(),
                        link.at
                    )),
                    LinkKind::Derived => Via::Text(format!(
                        "{} plus an offset at {:#x}",
                        link.from.spelled(),
                        link.at
                    )),
                },
            });
        }
        for call in &facts.calls {
            if let Some(prototype) = library.prototype(&call.name) {
                for (index, (arg, ty)) in call.args.iter().zip(&prototype.params).enumerate() {
                    if let Arg::Var(var) = arg {
                        first.push((
                            (f, Slot::Var(var.clone())),
                            EXACT,
                            evidence_of(store, ty.clone()),
                            format!("from {}'s parameter {}", prototype.name, index + 1),
                        ));
                    }
                }
                if let Some(result) = &call.result {
                    first.push((
                        (f, Slot::Var(result.clone())),
                        EXACT,
                        evidence_of(store, prototype.ret.clone()),
                        format!("returned by {} at {:#x}", prototype.name, call.at),
                    ));
                }
                continue;
            }
            let Some(callee) = by_address.get(&call.callee) else {
                continue;
            };
            let c = callee.address;
            for (arg, param) in call.args.iter().zip(&callee.params) {
                let param = (c, Slot::Var(param.clone()));
                match arg {
                    Arg::Var(var) => {
                        let var = (f, Slot::Var(var.clone()));
                        edges.push(Edge {
                            from: var.clone(),
                            to: param.clone(),
                            kind: LinkKind::Copy,
                            via: Via::Text(format!(
                                "from the call at {:#x} in {}",
                                call.at, facts.name
                            )),
                        });
                        edges.push(Edge {
                            from: param,
                            to: var,
                            kind: LinkKind::Copy,
                            via: Via::CallTo(call.at, callee.name.clone()),
                        });
                    }
                    Arg::Seed(rank, evidence, source) => then.push((
                        param,
                        *rank,
                        evidence.clone(),
                        format!("{source} in {}", facts.name),
                    )),
                    Arg::Other => {}
                }
            }
            if let Some(result) = &call.result {
                edges.push(Edge {
                    from: (c, Slot::Return),
                    to: (f, Slot::Var(result.clone())),
                    kind: LinkKind::Copy,
                    via: Via::Text(format!("returned by {} at {:#x}", callee.name, call.at)),
                });
            }
        }
    }
    for (key, rank, evidence, source) in first.into_iter().chain(then) {
        solver.offer(&key, rank, evidence, source);
    }
    for _ in 0..ROUNDS {
        let mut changed = false;
        for edge in &edges {
            let Some(state) = solver.states.get(&edge.from).cloned() else {
                continue;
            };
            let Some((rank, evidence)) = solver.carried(&state, edge.kind) else {
                continue;
            };
            let source = match &edge.via {
                Via::Keep => state.source.clone(),
                Via::Text(text) => text.clone(),
                Via::CallTo(at, callee) => {
                    let spelled = match &evidence {
                        Evidence::Pointer => "void *".to_string(),
                        Evidence::Type(ty) => ty.spelled(store),
                    };
                    format!("from the call at {at:#x} to {callee}({spelled})")
                }
            };
            changed |= solver.offer(&edge.to, rank, evidence, source);
        }
        if !changed {
            break;
        }
    }
    let spelled = |state: &State| match &state.value {
        Value::Pointer | Value::Pointers => Some("void *".to_string()),
        Value::Is(ty) => Some(ty.spelled(store)),
        Value::Clash => None,
    };
    let mut out: BTreeMap<u64, FunctionTypes> = BTreeMap::new();
    for facts in program {
        let f = facts.address;
        let mut types = FunctionTypes {
            notes: solver.notes.remove(&f).unwrap_or_default(),
            ..FunctionTypes::default()
        };
        for slot in facts.widths.keys() {
            let key = (f, slot.clone());
            if solver.fixed.contains(&key) {
                continue;
            }
            let Some(state) = solver.states.get(&key) else {
                continue;
            };
            let Some(ty) = spelled(state) else {
                continue;
            };
            match slot {
                Slot::Var(name) => {
                    types
                        .variables
                        .insert(name.clone(), (ty, state.source.clone()));
                }
                Slot::Return => types.return_type = Some((ty, state.source.clone())),
            }
        }
        for call in &facts.calls {
            if let Some(callee) = by_address.get(&call.callee) {
                let params = callee
                    .params
                    .iter()
                    .map(|param| {
                        let key = (callee.address, Slot::Var(param.clone()));
                        solver.states.get(&key).and_then(spelled)
                    })
                    .collect();
                types.callee_params.insert(callee.address, params);
            }
        }
        out.insert(f, types);
    }
    out
}

// ---- applied --------------------------------------------------------------

/// What propagation made of one function, for the variables listing: each
/// variable's inferred type and where it came from, the type the function
/// returns, the stack variables it made, the structures it drafted, and
/// the facts it read, for the image's solution across functions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inferred {
    /// The type each variable was given, by its lift name, and where it
    /// came from.
    pub variables: BTreeMap<String, (String, String)>,
    /// The type the function was given to return, and where it came from.
    pub return_type: Option<(String, String)>,
    /// The stack variables made, each with where it came from.
    pub stack_vars: Vec<(StackVar, String)>,
    /// The structures drafted for them, under `auto-structs on`.
    pub definitions: Vec<TypeText>,
    /// The variables the analyst typed, by lift name.
    pub analyst: BTreeSet<String>,
    /// The facts the function's lift gave, before any type was inferred.
    pub facts: Option<Arc<Facts>>,
}

impl Inferred {
    /// Where the type of the variable `name` came from: `analyst` for one
    /// the analyst typed or made, the inference's source for one inferred,
    /// `None` for the lift's own.
    pub fn source_of(&self, name: &str) -> Option<String> {
        if self.analyst.contains(name) {
            return Some("analyst".to_string());
        }
        if let Some((_, source)) = self.variables.get(name) {
            return Some(source.clone());
        }
        self.stack_vars
            .iter()
            .find(|(var, _)| var.name.as_deref() == Some(name))
            .map(|(_, source)| source.clone())
    }
}

/// Give the variables of `function` the types `types` infers, where the
/// analyst gave none and the type fits the variable's width, and its
/// return; spell the constant arguments the callees take as strings as
/// the strings; note the evidence that disagreed. What was given, with the
/// sources.
pub(crate) fn apply(
    function: &mut LiftedFunction,
    types: &FunctionTypes,
    store: &TypeStore,
    fixed: &BTreeSet<String>,
    made: &[StackVar],
    strings: &dyn Fn(u64) -> Option<String>,
) -> Inferred {
    let mut inferred = Inferred::default();
    let size = |text: &str| {
        crate::ctype::parse_type(store, text)
            .ok()
            .and_then(|ty| store.size_of(&ty).ok())
    };
    for variable in function.params.iter_mut().chain(function.locals.iter_mut()) {
        if fixed.contains(&variable.name)
            || variable.fragment.is_some()
            || made
                .iter()
                .any(|m| m.name.as_deref() == Some(variable.name.as_str()))
        {
            continue;
        }
        let Some((ty, source)) = types.variables.get(&variable.name) else {
            continue;
        };
        if *ty == variable.ty || size(ty).is_none() || size(ty) != size(&variable.ty) {
            continue;
        }
        variable.ty = ty.clone();
        inferred
            .variables
            .insert(variable.name.clone(), (ty.clone(), source.clone()));
    }
    if let Some((ty, source)) = &types.return_type {
        if function.return_type != "void"
            && !fixed.contains(crate::typed::RETURN)
            && *ty != function.return_type
            && size(ty).is_some()
            && size(ty) == size(&function.return_type)
        {
            function.return_type = ty.clone();
            inferred.return_type = Some((ty.clone(), source.clone()));
        }
    }
    function.notes.extend(types.notes.iter().cloned());
    // The constants passed where a string is taken are the strings.
    let library = library(*store.model());
    let takes_string = |callee: &str, address: u64, index: usize| {
        let ty = match library.prototype(callee) {
            Some(prototype) => prototype.params.get(index).cloned(),
            None => types
                .callee_params
                .get(&address)
                .and_then(|params| params.get(index).cloned().flatten())
                .and_then(|text| crate::ctype::parse_type(store, &text).ok()),
        };
        ty.is_some_and(|ty| match store.resolve(&ty) {
            Type::Pointer(pointee) => matches!(
                store.resolve(pointee),
                Type::Prim(Prim::Char | Prim::SChar | Prim::UChar)
            ),
            _ => false,
        })
    };
    let mut rewrite = |node: AstNode| match node {
        AstNode::Call { callee, args } => {
            let (name, address) = match callee.as_ref() {
                AstNode::FunctionName { name, address } => (name.clone(), *address),
                _ => return AstNode::Call { callee, args },
            };
            let args = args
                .into_iter()
                .enumerate()
                .map(|(index, arg)| match &arg {
                    AstNode::Constant { value, .. }
                        if *value >= 0x1000 && takes_string(&name, address, index) =>
                    {
                        match strings(*value) {
                            Some(text) => AstNode::StringLiteral { text },
                            None => arg,
                        }
                    }
                    _ => arg,
                })
                .collect();
            AstNode::Call { callee, args }
        }
        other => other,
    };
    rewrite_body(&mut function.body, &mut rewrite);
    inferred
}

/// Every node of `body` rewritten by `f`, innermost first.
fn rewrite_body(body: &mut [Statement], f: &mut dyn FnMut(AstNode) -> AstNode) {
    for statement in body {
        statement.node =
            crate::inline::map(std::mem::replace(&mut statement.node, AstNode::Break), f);
        if let StatementKind::For { init, step, .. } = &mut statement.kind {
            init.node = crate::inline::map(std::mem::replace(&mut init.node, AstNode::Break), f);
            step.node = crate::inline::map(std::mem::replace(&mut step.node, AstNode::Break), f);
        }
        for child in statement.children_mut() {
            rewrite_body(child, f);
        }
    }
}

/// Read the accesses to the arrays and structures made in the frame as
/// what they are: an element through an index, `*(int *)((long)&a + (long)i
/// * 4)` as `a[i]`, and an argument that is the address of one as the
/// array, `fgets(buf, 0x40, f)`, or the structure's address, `&tv`.
///
/// A member at offset 0 of a structure propagation made, `&v.tv_sec`,
/// passed is the structure's address, `&v`: the structure was made for
/// the parameter it is passed to; `auto` names those.
pub(crate) fn tidy(
    function: &mut LiftedFunction,
    made: &[StackVar],
    auto: &BTreeSet<String>,
    store: &TypeStore,
) {
    let arrays: BTreeMap<String, u64> = made
        .iter()
        .filter_map(|var| {
            let ty = crate::ctype::parse_type(store, var.ty.as_deref()?).ok()?;
            let Type::Array(element, _) = store.resolve(&ty) else {
                return None;
            };
            Some((var.name.clone()?, store.size_of(element).ok()?))
        })
        .collect();
    let names: BTreeSet<String> = made.iter().filter_map(|v| v.name.clone()).collect();
    if names.is_empty() {
        return;
    }
    let types: BTreeMap<String, Type> = made
        .iter()
        .filter_map(|var| {
            let ty = crate::ctype::parse_type(store, var.ty.as_deref()?).ok()?;
            Some((var.name.clone()?, ty))
        })
        .collect();
    // The variable a member is of, `v.a.b`, when every member on the way
    // is at offset 0: the address of the first member is the variable's.
    let first_member = |node: &AstNode| -> Option<String> {
        let mut path = Vec::new();
        let mut at = node;
        while let Some((base, field, false)) = crate::typed::member_of(at) {
            path.push(crate::types::Step::Field(field.to_string()));
            at = base;
        }
        let AstNode::Var { name } = at else {
            return None;
        };
        if path.is_empty() || !auto.contains(name) {
            return None;
        }
        path.reverse();
        let ty = types.get(name)?;
        let (offset, _) = store.path_offset(ty, &path)?;
        (offset == 0).then(|| name.clone())
    };
    // The variable an address is the start of, and the bytes into it.
    let base_of = |node: &AstNode| -> Option<(String, u64)> {
        match crate::slice::strip_casts(node) {
            AstNode::AddressOf { target } => match target.as_ref() {
                AstNode::Var { name } if names.contains(name) => Some((name.clone(), 0)),
                inner if first_member(inner).is_some() => first_member(inner).map(|n| (n, 0)),
                inner => {
                    let (array, index) = crate::stack_vars::indexed(inner)?;
                    let AstNode::Var { name } = array else {
                        return None;
                    };
                    let AstNode::Constant { value, .. } = index else {
                        return None;
                    };
                    Some((name.clone(), value * arrays.get(name)?))
                }
            },
            _ => None,
        }
    };
    let mut rewrite = |node: AstNode| match node {
        AstNode::Deref { target } => {
            if let AstNode::Cast {
                ty,
                target: address,
            } = target.as_ref()
            {
                if let Some(element) = element_of(ty, address, &arrays, store, &base_of) {
                    return element;
                }
            }
            AstNode::Deref { target }
        }
        AstNode::Call { callee, args } => {
            let args = args
                .into_iter()
                .map(|arg| match base_of(&arg) {
                    Some((name, 0)) if arrays.contains_key(&name) => AstNode::var(name),
                    Some((name, 0)) => AstNode::AddressOf {
                        target: Box::new(AstNode::var(name)),
                    },
                    _ => arg,
                })
                .collect();
            AstNode::Call { callee, args }
        }
        other => other,
    };
    rewrite_body(&mut function.body, &mut rewrite);
}

/// `*(ty)address` as the element of an array made in the frame, when the
/// address is the array's start, a constant and an index at the element's
/// stride.
fn element_of(
    ty: &str,
    address: &AstNode,
    arrays: &BTreeMap<String, u64>,
    store: &TypeStore,
    base_of: &dyn Fn(&AstNode) -> Option<(String, u64)>,
) -> Option<AstNode> {
    let Type::Pointer(pointee) = crate::ctype::parse_type(store, ty).ok()? else {
        return None;
    };
    let width = store.size_of(&pointee).ok()?;
    let mut found = Vec::new();
    terms(address, false, &mut found);
    let mut array = None;
    let mut offset: i64 = 0;
    let mut index: Option<AstNode> = None;
    for (negative, term) in &found {
        if let Some((name, bytes)) = base_of(term) {
            if *negative || array.replace(name).is_some() {
                return None;
            }
            offset += bytes as i64;
            continue;
        }
        match term {
            AstNode::Constant { value, .. } => {
                offset = if *negative {
                    offset.checked_sub(*value as i64)?
                } else {
                    offset.checked_add(*value as i64)?
                };
            }
            other if !negative && index.is_none() => match scaled(other) {
                Some((by, scale)) if scale == width => index = Some(by.clone()),
                Some(_) => return None,
                None if width == 1 => index = Some(other.clone()),
                None => return None,
            },
            _ => return None,
        }
    }
    let array = array?;
    let each = *arrays.get(&array)?;
    if each != width || offset.rem_euclid(width as i64) != 0 {
        return None;
    }
    let element = offset / width as i64;
    let index = match index {
        Some(index) if element == 0 => index,
        Some(index) if element > 0 => {
            AstNode::binary(index, BinaryOp::Add, AstNode::constant(element as u64, 8))
        }
        Some(index) => AstNode::binary(
            index,
            BinaryOp::Sub,
            AstNode::constant(element.unsigned_abs(), 8),
        ),
        None if element >= 0 => AstNode::constant(element as u64, 8),
        None => return None,
    };
    Some(AstNode::Intrinsic {
        name: crate::stack_vars::INDEX.to_string(),
        args: vec![AstNode::var(array), index],
    })
}

// ---- the frame ------------------------------------------------------------

/// A stack variable propagation makes, with where it came from and the
/// structure drafted for it, when one was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoVar {
    pub var: StackVar,
    pub source: String,
    pub definition: Option<TypeText>,
}

/// What the frame's first lift saw, for [`detect`].
pub struct Frame<'a> {
    pub accesses: &'a BTreeSet<(i64, u32, u64)>,
    pub address_taken: &'a BTreeSet<i64>,
    pub saved: &'a BTreeMap<i64, String>,
    /// The analyst's stack variables, which nothing made may overlap.
    pub analyst: &'a [StackVar],
    pub names: crate::options::SlotNames,
    /// Whether to draft structures no prototype types.
    pub auto_structs: bool,
}

/// The arrays and structures on the stack `function`'s first lift — the
/// analyst's variables made, a slot's address plus an index read as that
/// sum — says are there. `callee_param` is the analyst's type of a
/// callee's parameter, by the callee's address and the parameter's
/// position.
pub fn detect(
    function: &LiftedFunction,
    frame: &Frame,
    store: &TypeStore,
    callee_param: &dyn Fn(u64, usize) -> Option<Type>,
) -> Vec<AutoVar> {
    let library = library(*store.model());
    let offsets: BTreeMap<String, i64> = function
        .locals
        .iter()
        .filter_map(|local| match local.placements.as_slice() {
            [Placement::Stack { offset, .. }] if *offset < 0 => Some((local.name.clone(), *offset)),
            _ => None,
        })
        .collect();
    let taken = |node: &AstNode| -> Option<i64> {
        match crate::slice::strip_casts(node) {
            AstNode::AddressOf { target } => match target.as_ref() {
                AstNode::Var { name } => offsets.get(name).copied(),
                _ => None,
            },
            _ => None,
        }
    };
    // Candidates: start, size, type, source, definition.
    let mut wanted: Vec<(i64, u64, String, String, Option<TypeText>)> = Vec::new();
    let mut indexed: BTreeMap<i64, (Type, u64, BTreeSet<String>, u64)> = BTreeMap::new();
    let mut bounds: BTreeMap<String, u64> = BTreeMap::new();
    let mut all = Vec::new();
    each_statement(&function.body, function.address, &mut all);
    for (root, _, at) in all {
        crate::inline::visit(root, &mut |node| match node {
            AstNode::Deref { target } => {
                let AstNode::Cast {
                    ty,
                    target: address,
                } = target.as_ref()
                else {
                    return;
                };
                let Ok(Type::Pointer(pointee)) = crate::ctype::parse_type(store, ty) else {
                    return;
                };
                let Ok(width) = store.size_of(&pointee) else {
                    return;
                };
                let mut found = Vec::new();
                terms(address, false, &mut found);
                let mut start = None;
                let mut index = None;
                for (negative, term) in &found {
                    if let Some(offset) = taken(term) {
                        start = Some(offset);
                    } else if let Some((by, scale)) = scaled(term) {
                        if !negative && scale == width {
                            index = crate::slice::strip_casts(by).clone().into();
                        }
                    } else if width == 1 && !negative && !matches!(term, AstNode::Constant { .. }) {
                        index = Some(crate::slice::strip_casts(term).clone());
                    }
                }
                if let (Some(start), Some(index)) = (start, index) {
                    let entry = indexed.entry(start).or_insert((
                        (*pointee).clone(),
                        width,
                        BTreeSet::new(),
                        at,
                    ));
                    if entry.1 == width {
                        if let AstNode::Var { name } = index {
                            entry.2.insert(name);
                        }
                    }
                }
            }
            AstNode::Binary { lhs, op, rhs } if compares(*op) => {
                let pair = match (
                    crate::slice::strip_casts(lhs),
                    crate::slice::strip_casts(rhs),
                ) {
                    (AstNode::Var { name }, AstNode::Constant { value, .. }) => {
                        Some((name, *value, *op))
                    }
                    (AstNode::Constant { value, .. }, AstNode::Var { name }) => {
                        let flipped = match op {
                            BinaryOp::Greater => BinaryOp::Less,
                            BinaryOp::GreaterEqual => BinaryOp::LessEqual,
                            other => *other,
                        };
                        Some((name, *value, flipped))
                    }
                    _ => None,
                };
                if let Some((name, value, op)) = pair {
                    let count = match op {
                        BinaryOp::Less => Some(value),
                        BinaryOp::LessEqual => value.checked_add(1),
                        _ => None,
                    };
                    if let Some(count) = count.filter(|c| *c > 0 && *c <= 0x10000) {
                        let bound = bounds.entry(name.clone()).or_insert(count);
                        *bound = (*bound).max(count);
                    }
                }
            }
            AstNode::Call { callee, args } => {
                let AstNode::FunctionName { name, address } = callee.as_ref() else {
                    return;
                };
                let prototype = library.prototype(name);
                for (index, arg) in args.iter().enumerate() {
                    let Some(start) = taken(arg) else {
                        continue;
                    };
                    let param = match prototype {
                        Some(prototype) => prototype.params.get(index).cloned(),
                        None => callee_param(*address, index),
                    };
                    let Some(param) = param else {
                        continue;
                    };
                    let Type::Pointer(pointee) = store.resolve(&param).clone() else {
                        continue;
                    };
                    let whose = match prototype {
                        Some(prototype) => format!("{}'s parameter {}", prototype.name, index + 1),
                        None => format!("the analyst's type of {name}'s parameter {}", index + 1),
                    };
                    let sized = prototype.and_then(|p| {
                        let (_, by) = p.sizes.iter().find(|(at, _)| *at == index)?;
                        by.iter().try_fold(1u64, |bytes, at| {
                            match crate::slice::strip_casts(args.get(*at)?) {
                                AstNode::Constant { value, .. } => bytes.checked_mul(*value),
                                _ => None,
                            }
                        })
                    });
                    if let Some(bytes) = sized.filter(|b| *b > 1 && *b <= 0x10000) {
                        let element = match store.resolve(&pointee) {
                            Type::Prim(Prim::Void) => Type::Prim(Prim::Char),
                            _ => (*pointee).clone(),
                        };
                        let Ok(each) = store.size_of(&element) else {
                            continue;
                        };
                        if each == 0 || bytes % each != 0 || !store.is_scalar(&element) {
                            continue;
                        }
                        let ty = Type::Array(Box::new(element), Some(bytes / each));
                        wanted.push((
                            start,
                            bytes,
                            ty.spelled(store),
                            format!("from {whose}, {bytes:#x} bytes at {at:#x}"),
                            None,
                        ));
                    } else if let Some((composite, layout, _)) = store.composite(&pointee) {
                        let _ = composite;
                        if layout.size > 0 {
                            wanted.push((
                                start,
                                layout.size,
                                pointee.spelled(store),
                                format!("from {whose} at {at:#x}"),
                                None,
                            ));
                        }
                    }
                }
            }
            _ => {}
        });
    }
    // The bytes a run may reach from `start`: up to a saved register, the
    // return address, or — when `to_slot` — the next slot the code reaches.
    let limit = |start: i64, to_slot: bool| -> i64 {
        let mut end = 0i64;
        for &offset in frame.saved.keys() {
            if offset > start {
                end = end.min(offset);
            }
        }
        if to_slot {
            for &(offset, _, _) in frame.accesses {
                if offset > start {
                    end = end.min(offset);
                }
            }
        }
        end
    };
    for (start, (element, width, index, at)) in &indexed {
        let bounded = index.iter().filter_map(|i| bounds.get(i)).max().copied();
        let room = (limit(*start, bounded.is_none()) - start).max(0) as u64;
        let count = match bounded {
            Some(count) => count.min(room / width),
            None => room / width,
        };
        if count < 2 {
            continue;
        }
        let ty = Type::Array(Box::new(element.clone()), Some(count));
        wanted.push((
            *start,
            count * width,
            ty.spelled(store),
            format!("indexed as an array at {at:#x}"),
            None,
        ));
    }
    let mut made: Vec<AutoVar> = Vec::new();
    let overlaps = |start: i64, size: u64, made: &[AutoVar]| {
        let end = start + size as i64;
        frame
            .analyst
            .iter()
            .map(|v| (v.offset, v.offset + i64::from(v.size)))
            .chain(
                made.iter()
                    .map(|m| (m.var.offset, m.var.offset + i64::from(m.var.size))),
            )
            .any(|(a, b)| a < end && start < b)
    };
    for (start, size, ty, source, definition) in wanted {
        let Ok(size32) = u32::try_from(size) else {
            continue;
        };
        if start + size as i64 > limit(start, false) || overlaps(start, size, &made) {
            continue;
        }
        made.push(AutoVar {
            var: StackVar {
                offset: start,
                size: size32,
                name: None,
                ty: Some(ty),
            },
            source,
            definition,
        });
    }
    if frame.auto_structs {
        drafts(function, frame, store, &mut made, &limit, &overlaps);
    }
    made
}

/// The structures drafted for the address-taken runs of slots no
/// prototype types: each run from a slot whose address is taken to the
/// next such slot, a saved register or the return address, reached at two
/// offsets at least.
fn drafts(
    function: &LiftedFunction,
    frame: &Frame,
    store: &TypeStore,
    made: &mut Vec<AutoVar>,
    limit: &dyn Fn(i64, bool) -> i64,
    overlaps: &dyn Fn(i64, u64, &[AutoVar]) -> bool,
) {
    let mut drafted_store = store.clone();
    for &start in frame.address_taken {
        if start >= 0 {
            continue;
        }
        let mut end = limit(start, false);
        for &other in frame.address_taken {
            if other > start {
                end = end.min(other);
            }
        }
        let mut accesses: Vec<crate::smart_struct::Access> = Vec::new();
        let mut seen = BTreeSet::new();
        for &(offset, size, at) in frame.accesses {
            if offset >= start && offset + i64::from(size) <= end && seen.insert((offset, size)) {
                accesses.push(crate::smart_struct::Access {
                    offset: offset - start,
                    size: u64::from(size),
                    write: false,
                    hints: crate::smart_struct::Hints::default(),
                    at,
                    via: None,
                });
            }
        }
        let distinct: BTreeSet<i64> = accesses.iter().map(|a| a.offset).collect();
        if distinct.len() < 2 {
            continue;
        }
        let slot = crate::lift::local_name(frame.names, start);
        let tag = crate::smart_struct::default_tag(&drafted_store, &function.name, &slot);
        let Ok(draft) = crate::smart_struct::infer_struct(&tag, &accesses, None, &drafted_store)
        else {
            continue;
        };
        if overlaps(start, draft.size, made) || start + draft.size as i64 > end {
            continue;
        }
        let Ok(size) = u32::try_from(draft.size) else {
            continue;
        };
        if crate::ctype::parse_into(&mut drafted_store, &draft.c).is_err() {
            continue;
        }
        made.push(AutoVar {
            var: StackVar {
                offset: start,
                size,
                name: None,
                ty: Some(format!("struct {tag}")),
            },
            source: format!(
                "drafted from its accesses, its address taken at {:#x}",
                accesses[0].at
            ),
            definition: Some(TypeText {
                name: format!("struct {tag}"),
                c: draft.c,
            }),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::arch::Bitness;
    use crate::cfgwalk::{resolve_branches_among, NoEntries};
    use crate::cpu_context::X86IcedContext;
    use crate::lift::{lift_stages, Abi, Stages, Symbols};
    use crate::merge::VariableEdits;
    use crate::options::Options;
    use crate::pipeline::Disasm;

    const BASE: u64 = 0x1000;

    /// A world of one function at `BASE`, `strlen` at 0x2000, and the
    /// analyst's types of the function's variables.
    struct World {
        var_types: Vec<(String, String)>,
    }

    impl Symbols for World {
        fn function_name(&self, address: u64) -> Option<String> {
            (address == 0x2000).then(|| "strlen".to_string())
        }

        fn variable_edits(&self, address: u64) -> VariableEdits {
            VariableEdits {
                var_types: if address == BASE {
                    self.var_types.clone()
                } else {
                    Vec::new()
                },
                ..VariableEdits::default()
            }
        }
    }

    fn lifted(bytes: &[u8], var_types: &[(&str, &str)], options: &Options) -> Stages {
        let world = World {
            var_types: var_types
                .iter()
                .map(|(v, t)| (v.to_string(), t.to_string()))
                .collect(),
        };
        let mut ctx = X86IcedContext::default();
        let disasm = Disasm::decode(&mut ctx, bytes, BASE).expect("the code decodes");
        let cfg = resolve_branches_among(&disasm, BASE, &NoEntries);
        lift_stages(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits64,
            Abi::SystemV,
            &world,
            options,
        )
        .expect("the code lifts")
    }

    /// Each variable's name, type and where the type came from.
    fn listed(stages: &Stages) -> Vec<(String, String, Option<String>)> {
        stages
            .variables()
            .into_iter()
            .map(|v| (v.name, v.ty, v.source))
            .collect()
    }

    // mov rax, rdi; mov rdi, rax; call strlen; ret: the parameter, copied
    // through rax, is strlen's.
    const PASSES_TO_STRLEN: &[u8] = &[
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xc7, 0xe8, 0xf5, 0x0f, 0x00, 0x00, 0xc3,
    ];

    #[test]
    fn a_dereferenced_value_is_a_pointer_to_what_it_is_read_at() {
        // mov eax, [rdi]; ret
        let stages = lifted(&[0x8b, 0x07, 0xc3], &[], &Options::default());
        assert_eq!(
            listed(&stages),
            vec![(
                "a".to_string(),
                "int *".to_string(),
                Some("dereferenced at 0x1000".to_string())
            )]
        );
    }

    #[test]
    fn a_known_prototype_types_the_argument_through_its_copies() {
        let stages = lifted(PASSES_TO_STRLEN, &[], &Options::default());
        let a = &listed(&stages)[0];
        assert_eq!(a.1, "char *");
        assert_eq!(a.2.as_deref(), Some("from strlen's parameter 1"));
        let facts = stages.inferred.facts.as_ref().expect("the facts");
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name, "strlen");
    }

    #[test]
    fn the_analysts_type_wins_and_says_so() {
        let stages = lifted(PASSES_TO_STRLEN, &[("a", "long")], &Options::default());
        assert_eq!(
            listed(&stages)[0],
            (
                "a".to_string(),
                "long".to_string(),
                Some("analyst".to_string())
            )
        );
    }

    #[test]
    fn type_propagation_off_leaves_the_lifts_own_types() {
        let mut options = Options::default();
        options.set("type-propagation", "off").unwrap();
        let stages = lifted(PASSES_TO_STRLEN, &[], &options);
        assert_eq!(
            listed(&stages)[0],
            ("a".to_string(), "long".to_string(), None)
        );
        assert!(stages.inferred.facts.is_none());
        let stages = lifted(&[0x8b, 0x07, 0xc3], &[], &options);
        assert_eq!(stages.function.params[0].ty, "long");
    }

    #[test]
    fn a_value_read_only_unsigned_is_unsigned() {
        // cmp edi, 5; ja .big; xor eax, eax; ret; .big: mov eax, 1; ret
        let stages = lifted(
            &[
                0x83, 0xff, 0x05, 0x77, 0x03, 0x31, 0xc0, 0xc3, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
            ],
            &[],
            &Options::default(),
        );
        let a = &listed(&stages)[0];
        assert_eq!(a.1, "unsigned int");
        assert_eq!(a.2.as_deref(), Some("used unsigned at 0x1003"));
    }

    fn store() -> TypeStore {
        with_library(&TypeStore::new(DataModel::of_abi(
            crate::lift::Abi::SystemV,
        )))
    }

    #[test]
    fn the_library_reads_its_prototypes_and_their_types() {
        let store = store();
        let library = library(*store.model());
        let strlen = library.prototype("strlen").expect("strlen");
        assert_eq!(strlen.params.len(), 1);
        assert_eq!(strlen.params[0].spelled(&store), "char *");
        assert_eq!(strlen.ret.spelled(&store), "size_t");
        let fgets = library.prototype("fgets@plt").expect("fgets by its stub");
        assert_eq!(fgets.sizes, vec![(0, vec![1])]);
        assert_eq!(fgets.params[2].spelled(&store), "FILE *");
        let fread = library
            .prototype("__imp_fread")
            .expect("fread by its import");
        assert_eq!(fread.sizes, vec![(0, vec![1, 2])]);
        assert!(library.prototype("printf").expect("printf").variadic);
        assert!(library.prototype("_qsort").is_some());
        assert!(library.prototype("frobnicate").is_none());
        assert!(library.prototypes().count() > 60);
        assert!(store.layout("struct timeval").is_some_and(|l| l.size == 16));
        assert!(store
            .layout("struct sockaddr_in")
            .is_some_and(|l| l.size == 16));
    }

    #[test]
    fn a_project_definition_is_kept_over_the_librarys() {
        let mut project = TypeStore::new(DataModel::of_abi(crate::lift::Abi::SystemV));
        crate::ctype::parse_into(&mut project, "struct timeval { int a; };").unwrap();
        let both = with_library(&project);
        assert_eq!(both.layout("struct timeval").map(|l| l.size), Some(4));
        assert!(both.get("FILE").is_some());
        assert!(!library_definitions(&project)
            .iter()
            .any(|d| d.name == "struct timeval"));
    }

    fn facts_with(name: &str, address: u64, params: &[&str], widths: &[(&str, u64)]) -> Facts {
        Facts {
            address,
            name: name.to_string(),
            params: params.iter().map(|p| p.to_string()).collect(),
            widths: widths
                .iter()
                .map(|(n, w)| {
                    let slot = if *n == "return" {
                        Slot::Return
                    } else {
                        Slot::Var(n.to_string())
                    };
                    (slot, *w)
                })
                .collect(),
            ..Facts::default()
        }
    }

    fn var(name: &str) -> Slot {
        Slot::Var(name.to_string())
    }

    fn char_p() -> Evidence {
        Evidence::Type(Type::pointer(Type::Prim(Prim::Char)))
    }

    #[test]
    fn a_copy_carries_a_type_both_ways() {
        let store = store();
        let mut f = facts_with("f", 0x10, &["a"], &[("a", 8), ("b", 8), ("c", 8)]);
        f.links.push(Link {
            from: var("a"),
            to: var("b"),
            kind: LinkKind::Copy,
            at: 0x11,
        });
        f.links.push(Link {
            from: var("b"),
            to: var("c"),
            kind: LinkKind::Copy,
            at: 0x12,
        });
        f.seeds.push(Seed {
            slot: var("c"),
            rank: EXACT,
            evidence: char_p(),
            source: "a string assigned at 0x13".to_string(),
        });
        let mut back = f.clone();
        back.links = f
            .links
            .iter()
            .map(|l| Link {
                from: l.to.clone(),
                to: l.from.clone(),
                ..l.clone()
            })
            .collect();
        let solved = solve(&[&back], &store);
        let types = &solved[&0x10];
        assert_eq!(types.variables["a"].0, "char *");
        assert_eq!(types.variables["a"].1, "a string assigned at 0x13");
        assert_eq!(types.variables["b"].0, "char *");
    }

    #[test]
    fn every_call_site_types_the_callee_and_the_callee_types_the_caller() {
        let store = store();
        let mut callee = facts_with("parse", 0x100, &["a"], &[("a", 8)]);
        callee.seeds.push(Seed {
            slot: var("a"),
            rank: POINTER,
            evidence: Evidence::Type(Type::pointer(Type::Prim(Prim::Int))),
            source: "dereferenced at 0x104".to_string(),
        });
        let mut one = facts_with("one", 0x200, &[], &[]);
        one.calls.push(CallFact {
            at: 0x210,
            callee: 0x100,
            name: "parse".to_string(),
            args: vec![Arg::Seed(
                EXACT,
                char_p(),
                "a string passed at 0x210".to_string(),
            )],
            result: None,
        });
        let mut two = facts_with("two", 0x300, &[], &[("v", 8)]);
        two.calls.push(CallFact {
            at: 0x310,
            callee: 0x100,
            name: "parse".to_string(),
            args: vec![Arg::Var("v".to_string())],
            result: None,
        });
        let solved = solve(&[&callee, &one, &two], &store);
        assert_eq!(
            solved[&0x100].variables["a"],
            (
                "char *".to_string(),
                "a string passed at 0x210 in one".to_string()
            )
        );
        assert_eq!(
            solved[&0x300].variables["v"],
            (
                "char *".to_string(),
                "from the call at 0x310 to parse(char *)".to_string()
            )
        );
        assert_eq!(
            solved[&0x300].callee_params[&0x100],
            vec![Some("char *".to_string())]
        );
    }

    #[test]
    fn a_return_types_the_result_and_a_prototype_its_arguments() {
        let store = store();
        let mut make = facts_with("make", 0x100, &[], &[("return", 8), ("p", 8)]);
        make.calls.push(CallFact {
            at: 0x104,
            callee: 0x900,
            name: "malloc@plt".to_string(),
            args: vec![Arg::Other],
            result: Some("p".to_string()),
        });
        make.links.push(Link {
            from: var("p"),
            to: Slot::Return,
            kind: LinkKind::Copy,
            at: 0x108,
        });
        let mut user = facts_with("user", 0x200, &[], &[("r", 8), ("n", 8)]);
        user.calls.push(CallFact {
            at: 0x204,
            callee: 0x100,
            name: "make".to_string(),
            args: vec![],
            result: Some("r".to_string()),
        });
        user.calls.push(CallFact {
            at: 0x208,
            callee: 0x901,
            name: "strlen".to_string(),
            args: vec![Arg::Var("r".to_string())],
            result: Some("n".to_string()),
        });
        let solved = solve(&[&make, &user], &store);
        assert_eq!(solved[&0x100].return_type.as_ref().unwrap().0, "void *");
        assert_eq!(
            solved[&0x200].variables["r"],
            (
                "char *".to_string(),
                "from strlen's parameter 1".to_string()
            )
        );
        assert_eq!(
            solved[&0x200].variables["n"],
            (
                "size_t".to_string(),
                "returned by strlen at 0x208".to_string()
            )
        );
    }

    #[test]
    fn disagreeing_pointers_are_void_and_a_pointer_and_an_integer_the_integer() {
        let store = store();
        let mut f = facts_with("f", 0x10, &[], &[("p", 8), ("q", 8)]);
        for (slot, ty, at) in [
            ("p", Type::pointer(Type::Prim(Prim::Char)), 1),
            ("p", Type::pointer(Type::Prim(Prim::Int)), 2),
            ("q", Type::pointer(Type::Prim(Prim::Char)), 3),
            ("q", Type::Prim(Prim::Long), 4),
        ] {
            f.seeds.push(Seed {
                slot: var(slot),
                rank: EXACT,
                evidence: Evidence::Type(ty),
                source: format!("seen at {at:#x}"),
            });
        }
        let solved = solve(&[&f], &store);
        let types = &solved[&0x10];
        assert_eq!(types.variables["p"].0, "void *");
        assert!(!types.variables.contains_key("q"));
        assert_eq!(
            types.notes,
            vec![
                "p is void *: char * seen at 0x1, int * seen at 0x2".to_string(),
                "q keeps the integer of its width: char * seen at 0x3, long seen at 0x4"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn the_stronger_evidence_wins_and_the_analysts_is_never_changed() {
        let store = store();
        let mut f = facts_with("f", 0x10, &[], &[("p", 8), ("u", 4), ("k", 8)]);
        f.fixed.insert(var("k"));
        let seeds = [
            (
                "p",
                POINTER,
                Evidence::Type(Type::pointer(Type::Prim(Prim::Int))),
            ),
            ("p", EXACT, Evidence::Pointer),
            ("u", UNSIGNED, Evidence::Type(Type::Prim(Prim::UInt))),
            ("k", ANALYST, Evidence::Type(Type::Prim(Prim::Long))),
            ("k", EXACT, char_p()),
        ];
        for (slot, rank, evidence) in seeds {
            f.seeds.push(Seed {
                slot: var(slot),
                rank,
                evidence,
                source: "here".to_string(),
            });
        }
        let solved = solve(&[&f], &store);
        let types = &solved[&0x10];
        assert_eq!(types.variables["p"].0, "void *");
        assert_eq!(types.variables["u"].0, "unsigned int");
        assert!(!types.variables.contains_key("k"));
    }

    #[test]
    fn a_type_of_another_width_is_not_given() {
        let store = store();
        let mut f = facts_with("f", 0x10, &[], &[("n", 4)]);
        f.calls.push(CallFact {
            at: 0x12,
            callee: 0x99,
            name: "strlen".to_string(),
            args: vec![Arg::Var("n".to_string())],
            result: None,
        });
        assert!(solve(&[&f], &store)[&0x10].variables.is_empty());
    }

    #[test]
    fn a_derived_pointer_keeps_a_scalars_pointer() {
        let store = store();
        let mut f = facts_with("f", 0x10, &[], &[("p", 8), ("q", 8)]);
        f.seeds.push(Seed {
            slot: var("p"),
            rank: EXACT,
            evidence: char_p(),
            source: "from strlen's parameter 1".to_string(),
        });
        f.links.push(Link {
            from: var("p"),
            to: var("q"),
            kind: LinkKind::Derived,
            at: 0x14,
        });
        let solved = solve(&[&f], &store);
        assert_eq!(
            solved[&0x10].variables["q"],
            ("char *".to_string(), "p plus an offset at 0x14".to_string())
        );
    }
}
