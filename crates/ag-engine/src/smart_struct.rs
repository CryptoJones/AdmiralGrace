//! Smart structures: a structure drafted from what the code does through a
//! pointer.
//!
//! Before the analyst writes a structure, the code says much of it: a
//! pointer `p` is read and written at offsets, `*(int *)(p + 4)`, at
//! widths, with signs, and some of what it holds is itself dereferenced.
//! The accesses through a pointer variable ([`struct_accesses`]) are read
//! off the lifted body:
//!
//! - **through the variable**: a load or store `*(T *)(p + k)` is an
//!   access of `sizeof(T)` bytes at `k`; `*(T *)(p + k + i*s)`, an index
//!   by a variable, is one at a stride of `s`; a run of stores the lift
//!   reads as one struct initializer is one store a field. Through a
//!   pointer already typed, `p->f` and `p->a[i]` are the member's bytes;
//! - **through its copies**: a variable every assignment of which is the
//!   pointer, or the pointer and a constant — `q = p;`, `q = p + 8;` — is
//!   the pointer too, at that offset, and its accesses are the pointer's;
//! - **through the callees**, one level deep: the pointer, or one of its
//!   copies, passed to a function the image lifts is read in the callee
//!   the same way, through the parameter it arrives in, at the offset it
//!   was passed at. The callee's own callees are not followed.
//!
//! Each access carries what its uses say of the value: a load widened by
//! a signed cast is signed, one widened with zeros or compared unsigned is
//! unsigned; a loaded value that is dereferenced, or passed where a
//! pointer is expected — to a callee that dereferences the parameter, or
//! to `free`, `strlen`, `memcpy` and their like — is a pointer; a stored
//! value that is a string, an address, a function, a pointer variable or
//! an allocation is a pointer.
//!
//! The structure's size is the allocation's when the pointer is the
//! result of a known allocator with constant arguments — `malloc(0x18)`,
//! `calloc(2, 8)`, `operator new(0x20)`, `HeapAlloc(h, 0, 0x40)` — and
//! otherwise the extent of the accesses, the end of the last rounded up to
//! the alignment of the widest.
//!
//! The draft ([`infer_struct`]) has one member a distinct offset and width,
//! named `field_<offset in hex>`: `field_0`, `field_1c`. Its type is the
//! width's integer — `char`, `short`, `int`, `long` (`long long` where
//! `long` is 4 bytes) — unsigned where only unsigned uses are seen, or a
//! pointer where the value is used as one: `char *` when it is
//! dereferenced at one byte, `void *` when at no one width. An access
//! indexed by a variable at a stride of its own width is an array, `int
//! field_18[4]`, that runs to the next member or the structure's end. Two
//! accesses that share bytes — four bytes and eight at one offset — are
//! the wider, and the narrower is a note; a structure that is a union of
//! both is the analyst's to write. Bytes no access reaches where the
//! natural alignment would not leave them are `char gap_<offset>[n]`. A
//! member the natural alignment cannot place at its offset makes the
//! structure `__attribute__((packed))`, with every gap spelled out.
//!
//! The draft is C the type parser reads back ([`crate::ctype`]), and
//! [`update_struct`] merges new accesses into a structure already defined:
//! a member for each access in bytes no member holds, never renaming or
//! retyping one, an access that meets a member at other bytes a note.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{AstNode, BinaryOp};
use crate::ctype::TypeText;
use crate::lift::{LiftedFunction, Statement, StatementKind};
use crate::types::{DataModel, Prim, Step, Type, TypeStore};

/// What the uses of an access say of the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hints {
    /// Widened with its sign: the load cast to a wider signed integer.
    pub signed: bool,
    /// Widened with zeros, or compared unsigned: the load cast to an
    /// unsigned integer.
    pub unsigned: bool,
    /// Used as a pointer: dereferenced, passed where a pointer is
    /// expected, or a pointer stored.
    pub pointer: bool,
    /// The widths a pointer's value is dereferenced at.
    pub pointees: BTreeSet<u64>,
    /// The stride of the variable the access is indexed by, in bytes.
    pub stride: Option<u64>,
}

impl Hints {
    fn merge(&mut self, other: &Hints) {
        self.signed |= other.signed;
        self.unsigned |= other.unsigned;
        self.pointer |= other.pointer;
        self.pointees.extend(other.pointees.iter().copied());
        if self.stride.is_none() {
            self.stride = other.stride;
        }
    }

    fn pointer(pointees: impl IntoIterator<Item = u64>) -> Hints {
        Hints {
            pointer: true,
            pointees: pointees.into_iter().collect(),
            ..Hints::default()
        }
    }
}

/// One load or store through the pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// The offset from the pointer, in bytes.
    pub offset: i64,
    /// The width, in bytes.
    pub size: u64,
    /// Whether it is a store.
    pub write: bool,
    /// What its uses say of the value.
    pub hints: Hints,
    /// The address of the statement it is in.
    pub at: u64,
    /// The callee whose parameter it is through, when it is in one.
    pub via: Option<String>,
}

/// The allocation a pointer is the result of, and the size it asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// The allocator, as the call names it.
    pub callee: String,
    /// The bytes it is asked for.
    pub size: u64,
    /// The call as it asks: `malloc(0x28)`, `calloc(2, 8)`.
    pub call: String,
    /// The address of the call's statement.
    pub at: u64,
}

/// The accesses through a pointer variable of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accesses {
    /// The function, by its lift name.
    pub function: String,
    /// The variable, by its lift name.
    pub variable: String,
    /// The accesses, in the body's order, the callees' after the call.
    pub accesses: Vec<Access>,
    /// The allocation the pointer is the result of, when it is one.
    pub allocation: Option<Allocation>,
    /// The variables that are the pointer, each at its offset from it:
    /// the variable itself at 0, and its copies.
    pub pointers: Vec<(String, i64)>,
    /// The callees the pointer was followed into.
    pub followed: Vec<String>,
}

/// The accesses through the pointer `variable` of `function`, its copies
/// and the callees it is passed to — each callee's body by its address
/// from `callee` — and the allocation it is the result of. Refused for a
/// variable the function does not declare, or one no wider or narrower
/// than a pointer.
pub fn struct_accesses(
    function: &LiftedFunction,
    variable: &str,
    store: &TypeStore,
    callee: &dyn Fn(u64) -> Option<LiftedFunction>,
) -> Result<Accesses, String> {
    collect(function, variable, store, Some(callee))
}

fn collect(
    function: &LiftedFunction,
    variable: &str,
    store: &TypeStore,
    callee: Option<&dyn Fn(u64) -> Option<LiftedFunction>>,
) -> Result<Accesses, String> {
    let declared = function
        .params
        .iter()
        .chain(&function.locals)
        .find(|v| v.name == variable)
        .ok_or_else(|| format!("{} declares no {variable}", function.name))?;
    let width = crate::ctype::parse_type(store, &declared.ty)
        .ok()
        .and_then(|ty| store.size_of(&ty).ok());
    let pointer = store.model().pointer;
    if width != Some(pointer) {
        return Err(format!(
            "{variable} is {}, and a pointer is {pointer} bytes",
            declared.ty
        ));
    }
    let mut assigned = BTreeMap::new();
    assignments(&function.body, &mut assigned);
    let pointers = follow(variable, &assigned);
    let mut types = BTreeMap::new();
    let mut pointees = BTreeMap::new();
    for v in function.params.iter().chain(&function.locals) {
        types.insert(v.name.clone(), v.ty.clone());
        if pointers.contains_key(&v.name) {
            if let Ok(ty) = crate::ctype::parse_type(store, &v.ty) {
                if let Type::Pointer(pointee) = store.resolve(&ty) {
                    pointees.insert(v.name.clone(), (**pointee).clone());
                }
            }
        }
    }
    let mut walker = Walker {
        store,
        pointers: &pointers,
        pointees,
        types,
        callee,
        own: function.address,
        lifted: BTreeMap::new(),
        at: function.address,
        accesses: Vec::new(),
        followed: Vec::new(),
    };
    walker.statements(&function.body);
    let accesses = walker.accesses;
    let followed = walker.followed;
    Ok(Accesses {
        function: function.name.clone(),
        variable: variable.to_string(),
        accesses,
        allocation: allocation_of(variable, &assigned, 0),
        pointers: pointers.into_iter().collect(),
        followed,
    })
}

/// Every assignment to a variable in `statements`: its value and the
/// address of its statement, by the variable's name.
fn assignments<'a>(
    statements: &'a [Statement],
    out: &mut BTreeMap<String, Vec<(&'a AstNode, u64)>>,
) {
    for statement in statements {
        let at = statement.addresses.first().copied().unwrap_or(0);
        if let AstNode::Assign { lhs, rhs } = &statement.node {
            if let AstNode::Var { name } = lhs.as_ref() {
                out.entry(name.clone()).or_default().push((rhs, at));
            }
        }
        if let StatementKind::For { init, step, .. } = &statement.kind {
            assignments(std::slice::from_ref(init), out);
            assignments(std::slice::from_ref(step), out);
        }
        for child in statement.children() {
            assignments(child, out);
        }
    }
}

/// The variables that are the pointer `root`, each at its offset from it:
/// `root` at 0, and each variable every assignment of which is one of them
/// and the same constant.
fn follow(root: &str, assigned: &BTreeMap<String, Vec<(&AstNode, u64)>>) -> BTreeMap<String, i64> {
    let mut pointers = BTreeMap::from([(root.to_string(), 0i64)]);
    loop {
        let mut grew = false;
        for (name, values) in assigned {
            if pointers.contains_key(name) {
                continue;
            }
            let offsets: Option<Vec<i64>> = values
                .iter()
                .map(|(value, _)| match decompose(value, &pointers)? {
                    (base, offset, None) => pointers[&base].checked_add(offset),
                    _ => None,
                })
                .collect();
            if let Some(offsets) = offsets {
                if let Some(&first) = offsets.first() {
                    if offsets.iter().all(|&o| o == first) {
                        pointers.insert(name.clone(), first);
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            return pointers;
        }
    }
}

/// The allocation `name` is the result of: its one assignment a call to
/// a known allocator with constant arguments, or a copy of a variable
/// that is.
fn allocation_of(
    name: &str,
    assigned: &BTreeMap<String, Vec<(&AstNode, u64)>>,
    depth: usize,
) -> Option<Allocation> {
    let [(value, at)] = assigned.get(name)?.as_slice() else {
        return None;
    };
    match crate::slice::strip_casts(value) {
        AstNode::Call { callee, args } => {
            let callee = match callee.as_ref() {
                AstNode::FunctionName { name, .. } => name.clone(),
                AstNode::Var { name } => name.clone(),
                _ => return None,
            };
            let (size, asked) = allocation_size(&callee, args)?;
            let call = format!("{callee}({})", asked.join(", "));
            Some(Allocation {
                callee,
                size,
                call,
                at: *at,
            })
        }
        AstNode::Var { name } if depth < 4 => allocation_of(name, assigned, depth + 1),
        _ => None,
    }
}

/// Where a known allocator takes the size it allocates: one argument, or
/// the product of two.
#[derive(Clone, Copy)]
enum Sized {
    Arg(usize),
    Product(usize, usize),
}

/// The allocators by name, and where each takes its size.
const ALLOCATORS: &[(&str, Sized)] = &[
    ("malloc", Sized::Arg(0)),
    ("calloc", Sized::Product(0, 1)),
    ("realloc", Sized::Arg(1)),
    ("reallocarray", Sized::Product(1, 2)),
    ("aligned_alloc", Sized::Arg(1)),
    ("memalign", Sized::Arg(1)),
    ("valloc", Sized::Arg(0)),
    ("pvalloc", Sized::Arg(0)),
    ("xmalloc", Sized::Arg(0)),
    ("xzalloc", Sized::Arg(0)),
    ("xcalloc", Sized::Product(0, 1)),
    ("xrealloc", Sized::Arg(1)),
    ("g_malloc", Sized::Arg(0)),
    ("g_malloc0", Sized::Arg(0)),
    ("g_try_malloc", Sized::Arg(0)),
    ("g_try_malloc0", Sized::Arg(0)),
    ("g_malloc_n", Sized::Product(0, 1)),
    ("g_malloc0_n", Sized::Product(0, 1)),
    ("g_slice_alloc", Sized::Arg(0)),
    ("g_slice_alloc0", Sized::Arg(0)),
    ("kmalloc", Sized::Arg(0)),
    ("kzalloc", Sized::Arg(0)),
    ("kcalloc", Sized::Product(0, 1)),
    ("kmalloc_array", Sized::Product(0, 1)),
    ("kvmalloc", Sized::Arg(0)),
    ("kvzalloc", Sized::Arg(0)),
    ("vmalloc", Sized::Arg(0)),
    ("vzalloc", Sized::Arg(0)),
    ("devm_kmalloc", Sized::Arg(1)),
    ("devm_kzalloc", Sized::Arg(1)),
    ("HeapAlloc", Sized::Arg(2)),
    ("RtlAllocateHeap", Sized::Arg(2)),
    ("LocalAlloc", Sized::Arg(1)),
    ("GlobalAlloc", Sized::Arg(1)),
    ("VirtualAlloc", Sized::Arg(1)),
    ("CoTaskMemAlloc", Sized::Arg(0)),
    ("ExAllocatePool", Sized::Arg(1)),
    ("ExAllocatePoolWithTag", Sized::Arg(1)),
    ("ExAllocatePool2", Sized::Arg(1)),
    ("_Znwm", Sized::Arg(0)),
    ("_Znam", Sized::Arg(0)),
    ("_Znwj", Sized::Arg(0)),
    ("_Znaj", Sized::Arg(0)),
    ("??2@YAPEAX_K@Z", Sized::Arg(0)),
    ("??_U@YAPEAX_K@Z", Sized::Arg(0)),
    ("??2@YAPAXI@Z", Sized::Arg(0)),
    ("??_U@YAPAXI@Z", Sized::Arg(0)),
];

/// The allocator `name` is, under the decorations an import or a stub
/// adds: `malloc@plt`, `__imp_HeapAlloc`, `_malloc`, `j_malloc`, and
/// `operator new(unsigned long)` demangled.
fn allocator(name: &str) -> Option<Sized> {
    let full = name.trim();
    if full.starts_with("operator new") {
        return Some(Sized::Arg(0));
    }
    // An MSVC decoration keeps its `@`; another name drops what follows.
    let bare = full.split('@').next().unwrap_or(full);
    let mut candidates = vec![full, bare];
    for prefix in ["__imp_", "_imp_", "__imp__", "j_", "_"] {
        if let Some(rest) = bare.strip_prefix(prefix) {
            candidates.push(rest);
        }
    }
    candidates.iter().find_map(|candidate| {
        ALLOCATORS
            .iter()
            .find(|(known, _)| known == candidate)
            .map(|(_, sized)| *sized)
    })
}

/// Whether `name` is a known allocator.
pub fn is_allocator(name: &str) -> bool {
    allocator(name).is_some()
}

/// The size a call to the allocator `callee` asks for, when its arguments
/// are constants, and those arguments as the call spells them.
fn allocation_size(callee: &str, args: &[AstNode]) -> Option<(u64, Vec<String>)> {
    let sized = allocator(callee)?;
    let constant = |at: usize| match crate::slice::strip_casts(args.get(at)?) {
        AstNode::Constant { value, .. } => Some(*value),
        _ => None,
    };
    let spelled = |value: u64| {
        if value < 10 {
            value.to_string()
        } else {
            format!("{value:#x}")
        }
    };
    let (size, asked) = match sized {
        Sized::Arg(at) => {
            let size = constant(at)?;
            (size, vec![spelled(size)])
        }
        Sized::Product(a, b) => {
            let (a, b) = (constant(a)?, constant(b)?);
            (a.checked_mul(b)?, vec![spelled(a), spelled(b)])
        }
    };
    (size > 0).then_some((size, asked))
}

/// The functions whose arguments, by position, are pointers they read or
/// write through.
const POINTER_PARAMS: &[(&str, &[usize])] = &[
    ("free", &[0]),
    ("realloc", &[0]),
    ("strlen", &[0]),
    ("strnlen", &[0]),
    ("strcmp", &[0, 1]),
    ("strncmp", &[0, 1]),
    ("strcasecmp", &[0, 1]),
    ("strcpy", &[0, 1]),
    ("strncpy", &[0, 1]),
    ("strcat", &[0, 1]),
    ("strncat", &[0, 1]),
    ("strchr", &[0]),
    ("strrchr", &[0]),
    ("strstr", &[0, 1]),
    ("strdup", &[0]),
    ("memcpy", &[0, 1]),
    ("memmove", &[0, 1]),
    ("memcmp", &[0, 1]),
    ("memset", &[0]),
    ("memchr", &[0]),
    ("puts", &[0]),
    ("printf", &[0]),
    ("fputs", &[0, 1]),
    ("fclose", &[0]),
    ("fflush", &[0]),
    ("fread", &[0, 3]),
    ("fwrite", &[0, 3]),
    ("g_free", &[0]),
    ("kfree", &[0]),
    ("HeapFree", &[2]),
    ("LocalFree", &[0]),
    ("GlobalFree", &[0]),
    ("_ZdlPv", &[0]),
    ("_ZdaPv", &[0]),
];

/// Whether the function `name` takes a pointer as its argument `index`.
fn pointer_param(name: &str, index: usize) -> bool {
    let name = name.split('@').next().unwrap_or(name).trim();
    if name.starts_with("operator delete") {
        return index == 0;
    }
    let mut candidates = vec![name];
    for prefix in ["__imp_", "_imp_", "j_", "_"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            candidates.push(rest);
        }
    }
    candidates.iter().any(|candidate| {
        POINTER_PARAMS
            .iter()
            .any(|(known, at)| known == candidate && at.contains(&index))
    })
}

/// A load or store through one of the pointers: its offset from the
/// pointer, its width, the stride of its index, and the nodes inside it
/// that are read besides — its index.
struct Found<'a> {
    offset: i64,
    size: u64,
    stride: Option<u64>,
    inner: Vec<&'a AstNode>,
}

/// The walk over a body for the accesses through its pointers.
struct Walker<'s, 'p> {
    store: &'s TypeStore,
    pointers: &'p BTreeMap<String, i64>,
    /// The pointee of each pointer typed a pointer.
    pointees: BTreeMap<String, Type>,
    /// The C type of each variable.
    types: BTreeMap<String, String>,
    /// The callees' bodies, when callees are followed.
    callee: Option<&'s dyn Fn(u64) -> Option<LiftedFunction>>,
    /// The function's own address, which is not followed into.
    own: u64,
    lifted: BTreeMap<u64, Option<LiftedFunction>>,
    at: u64,
    accesses: Vec<Access>,
    followed: Vec<String>,
}

impl<'s, 'p> Walker<'s, 'p> {
    fn statements(&mut self, statements: &[Statement]) {
        for statement in statements {
            // The last instruction of a statement is its own: the first
            // may be where a value it reads was saved long before.
            if let Some(&last) = statement.addresses.iter().max() {
                self.at = last;
            }
            self.node(&statement.node);
            if let StatementKind::For { init, step, .. } = &statement.kind {
                self.statements(std::slice::from_ref(init));
                self.statements(std::slice::from_ref(step));
            }
            for child in statement.children() {
                self.statements(child);
            }
        }
    }

    fn record(&mut self, found: &Found, write: bool, mut hints: Hints) {
        hints.stride = found.stride;
        self.accesses.push(Access {
            offset: found.offset,
            size: found.size,
            write,
            hints,
            at: self.at,
            via: None,
        });
    }

    /// The access `node` is, when it is a load through one of the
    /// pointers.
    fn access<'n>(&self, node: &'n AstNode) -> Option<Found<'n>> {
        match node {
            AstNode::Deref { target } => match target.as_ref() {
                AstNode::Cast {
                    ty,
                    target: address,
                } => {
                    let size = pointee_size(self.store, ty)?;
                    let (base, offset, index) = decompose(address, self.pointers)?;
                    Some(Found {
                        offset: self.pointers[&base].checked_add(offset)?,
                        size,
                        stride: index.as_ref().map(|(_, scale)| *scale),
                        inner: index.map(|(node, _)| node).into_iter().collect(),
                    })
                }
                AstNode::Var { name } => {
                    let pointee = self.pointees.get(name)?;
                    Some(Found {
                        offset: self.pointers[name],
                        size: self.store.size_of(pointee).ok()?,
                        stride: None,
                        inner: Vec::new(),
                    })
                }
                _ => None,
            },
            AstNode::Intrinsic { .. } => {
                let (offset, ty, stride, inner) = self.typed(node)?;
                Some(Found {
                    offset,
                    size: self.store.size_of(&ty).ok()?,
                    stride,
                    inner,
                })
            }
            _ => None,
        }
    }

    /// A member or element through a typed pointer — `p->f`, `p->a[i]`,
    /// `p[1].x` — as its offset from the pointer, its type, the stride of
    /// its index and the index.
    #[allow(clippy::type_complexity)]
    fn typed<'n>(&self, node: &'n AstNode) -> Option<(i64, Type, Option<u64>, Vec<&'n AstNode>)> {
        if let Some((base, field, arrow)) = crate::typed::member_of(node) {
            let step = [Step::Field(field.to_string())];
            if arrow {
                let AstNode::Var { name } = base else {
                    return None;
                };
                let pointee = self.pointees.get(name)?;
                let (at, ty) = self.store.path_offset(pointee, &step)?;
                return Some((
                    self.pointers[name].checked_add(i64::try_from(at).ok()?)?,
                    ty,
                    None,
                    Vec::new(),
                ));
            }
            let (offset, ty, stride, inner) = self.typed(base)?;
            let (at, ty) = self.store.path_offset(&ty, &step)?;
            return Some((
                offset.checked_add(i64::try_from(at).ok()?)?,
                ty,
                stride,
                inner,
            ));
        }
        let (array, index) = crate::stack_vars::indexed(node)?;
        let (offset, element, stride, mut inner) = match array {
            AstNode::Var { name } => {
                let pointee = self.pointees.get(name)?;
                (self.pointers[name], pointee.clone(), None, Vec::new())
            }
            other => {
                let (offset, ty, stride, inner) = self.typed(other)?;
                let Type::Array(element, _) = self.store.resolve(&ty) else {
                    return None;
                };
                (offset, (**element).clone(), stride, inner)
            }
        };
        let each = self.store.size_of(&element).ok()?;
        match index {
            AstNode::Constant { value, .. } => {
                let by = i64::try_from(value.checked_mul(each)?).ok()?;
                Some((offset.checked_add(by)?, element, stride, inner))
            }
            other => {
                inner.push(other);
                Some((offset, element, Some(each), inner))
            }
        }
    }

    fn node(&mut self, node: &AstNode) {
        self.child(node, Hints::default());
    }

    /// Walk `node`, which its parent says `hints` of when it is an access.
    fn child(&mut self, node: &AstNode, hints: Hints) {
        if let Some(found) = self.access(node) {
            self.record(&found, false, hints);
            for inner in found.inner {
                self.node(inner);
            }
            return;
        }
        match node {
            AstNode::Assign { lhs, rhs } => self.assign(lhs, rhs),
            AstNode::Cast { ty, target } => {
                let hints = match self.access(target) {
                    Some(found) => cast_hints(self.store, ty, found.size),
                    None => Hints::default(),
                };
                self.child(target, hints);
            }
            AstNode::Deref { target } => self.address(target),
            AstNode::Call { callee, args } => self.call(callee, args),
            AstNode::Binary { lhs, rhs, .. } => {
                self.node(lhs);
                self.node(rhs);
            }
            AstNode::AddressOf { target } => self.node(target),
            AstNode::Intrinsic { args, .. } => {
                for arg in args {
                    self.node(arg);
                }
            }
            AstNode::StructInit { fields } => {
                for field in fields {
                    self.node(&field.value);
                }
            }
            AstNode::Return { value: Some(value) } => self.node(value),
            AstNode::If {
                cond,
                then_part,
                else_part,
                ..
            } => {
                self.node(cond);
                self.node(then_part);
                if let Some(else_part) = else_part {
                    self.node(else_part);
                }
            }
            AstNode::IfGoto { cond, .. } => self.node(cond),
            AstNode::Loop { cond, body, .. } => {
                if let Some(cond) = cond {
                    self.node(cond);
                }
                self.node(body);
            }
            AstNode::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.node(cond);
                self.node(then);
                self.node(otherwise);
            }
            AstNode::ConstantCondition { compared, .. } => self.node(compared),
            _ => {}
        }
    }

    /// `lhs = rhs`: a store through a pointer is an access written, each
    /// field of a struct initializer one.
    fn assign(&mut self, lhs: &AstNode, rhs: &AstNode) {
        // A struct initializer's type is the lift's own, `struct { int
        // at_0; … }`: only its address says where it is.
        let initialized = match (lhs, rhs) {
            (AstNode::Deref { target }, AstNode::StructInit { .. }) => match target.as_ref() {
                AstNode::Cast {
                    target: address, ..
                } => decompose(address, self.pointers).and_then(|(base, offset, index)| {
                    Some(Found {
                        offset: self.pointers[&base].checked_add(offset)?,
                        size: 0,
                        stride: index.as_ref().map(|(_, scale)| *scale),
                        inner: index.map(|(node, _)| node).into_iter().collect(),
                    })
                }),
                _ => None,
            },
            _ => None,
        };
        if let Some(found) = initialized.or_else(|| self.access(lhs)) {
            if let AstNode::StructInit { fields } = rhs {
                for field in fields {
                    let Some(size) = crate::ctype::parse_type(self.store, &field.ty)
                        .ok()
                        .and_then(|ty| self.store.size_of(&ty).ok())
                    else {
                        continue;
                    };
                    let Some(offset) = i64::try_from(field.offset)
                        .ok()
                        .and_then(|at| found.offset.checked_add(at))
                    else {
                        continue;
                    };
                    let one = Found {
                        offset,
                        size,
                        stride: found.stride,
                        inner: Vec::new(),
                    };
                    let hints = self.value_hints(&field.value);
                    self.record(&one, true, hints);
                    self.node(&field.value);
                }
            } else {
                let hints = self.value_hints(rhs);
                self.record(&found, true, hints);
                self.node(rhs);
            }
            for inner in found.inner {
                self.node(inner);
            }
            return;
        }
        if let AstNode::Deref { target } = lhs {
            self.address(target);
        } else if !matches!(lhs, AstNode::Var { .. }) {
            self.node(lhs);
        }
        self.node(rhs);
    }

    /// An address dereferenced that is no access through a pointer: a
    /// load in its sum is a pointer, dereferenced at the width the address
    /// is cast to.
    fn address(&mut self, target: &AstNode) {
        let (width, sum) = match target {
            AstNode::Cast { ty, target } => (pointee_size(self.store, ty), target.as_ref()),
            other => (None, other),
        };
        let mut terms = Vec::new();
        terms_of(sum, &mut terms);
        for term in terms {
            self.child(term, Hints::pointer(width));
        }
    }

    /// A call: the pointer passed on is followed into the callee, and a
    /// load passed where a pointer is expected is a pointer.
    fn call(&mut self, callee: &AstNode, args: &[AstNode]) {
        let named = match callee {
            AstNode::FunctionName { name, address } => Some((name.clone(), *address)),
            other => {
                self.node(other);
                None
            }
        };
        for (index, arg) in args.iter().enumerate() {
            let arg = crate::slice::strip_casts(arg);
            if let Some((name, address)) = &named {
                if let Some((base, offset, None)) = decompose(arg, self.pointers) {
                    if let Some(at) = self.pointers[&base].checked_add(offset) {
                        self.follow(*address, index, at);
                    }
                    continue;
                }
                if self.access(arg).is_some() {
                    let pointer = pointer_param(name, index)
                        || allocation_param(name, index)
                        || self.dereferences(*address, index);
                    let hints = if pointer {
                        Hints::pointer(None)
                    } else {
                        Hints::default()
                    };
                    self.child(arg, hints);
                    continue;
                }
            }
            self.node(arg);
        }
    }

    /// The body of the callee at `address`, when callees are followed.
    fn lifted(&mut self, address: u64) -> Option<&LiftedFunction> {
        let callee = self.callee?;
        if address == self.own {
            return None;
        }
        self.lifted
            .entry(address)
            .or_insert_with(|| callee(address))
            .as_ref()
    }

    /// The accesses of the callee at `address` through its parameter
    /// `index`, `offset` bytes into the pointer.
    fn follow(&mut self, address: u64, index: usize, offset: i64) {
        let store = self.store;
        let Some(function) = self.lifted(address) else {
            return;
        };
        let Some(param) = function.params.get(index) else {
            return;
        };
        let Ok(found) = collect(function, &param.name, store, None) else {
            return;
        };
        let name = function.name.clone();
        if !self.followed.contains(&name) {
            self.followed.push(name.clone());
        }
        for mut access in found.accesses {
            let Some(at) = access.offset.checked_add(offset) else {
                continue;
            };
            access.offset = at;
            access.via = Some(name.clone());
            self.accesses.push(access);
        }
    }

    /// Whether the callee at `address` reads or writes through its
    /// parameter `index`.
    fn dereferences(&mut self, address: u64, index: usize) -> bool {
        let store = self.store;
        let Some(function) = self.lifted(address) else {
            return false;
        };
        let Some(param) = function.params.get(index) else {
            return false;
        };
        collect(function, &param.name, store, None).is_ok_and(|found| !found.accesses.is_empty())
    }

    /// What a value stored says of the bytes it is stored in.
    fn value_hints(&self, value: &AstNode) -> Hints {
        match crate::slice::strip_casts(value) {
            AstNode::StringLiteral { .. } => Hints::pointer([1]),
            AstNode::AddressOf { .. } | AstNode::FunctionName { .. } => Hints::pointer(None),
            AstNode::Var { name } => {
                if self.pointers.contains_key(name) {
                    return Hints::pointer(None);
                }
                match self
                    .types
                    .get(name)
                    .and_then(|ty| crate::ctype::parse_type(self.store, ty).ok())
                {
                    Some(Type::Pointer(pointee)) => {
                        Hints::pointer(self.store.size_of(&pointee).ok().filter(|&s| s > 0))
                    }
                    _ => Hints::default(),
                }
            }
            AstNode::Call { callee, .. } => match callee.as_ref() {
                AstNode::FunctionName { name, .. } if is_allocator(name) => Hints::pointer(None),
                _ => Hints::default(),
            },
            _ => Hints::default(),
        }
    }
}

/// Whether argument `index` of the function `name` is the pointer an
/// allocator such as `realloc` takes back.
fn allocation_param(name: &str, index: usize) -> bool {
    index == 0 && matches!(allocator(name), Some(Sized::Arg(1))) && name.contains("realloc")
}

/// The width of the pointee of the pointer type `ty`, `int *` 4.
fn pointee_size(store: &TypeStore, ty: &str) -> Option<u64> {
    match crate::ctype::parse_type(store, ty).ok()? {
        Type::Pointer(pointee) => store.size_of(&pointee).ok().filter(|&size| size > 0),
        _ => None,
    }
}

/// What a cast to `ty` around a load of `size` bytes says of it: unsigned
/// for an unsigned integer, signed for a wider signed one.
fn cast_hints(store: &TypeStore, ty: &str, size: u64) -> Hints {
    let Ok(Type::Prim(prim)) = crate::ctype::parse_type(store, ty) else {
        return Hints::default();
    };
    if !prim.is_integer() {
        return Hints::default();
    }
    let wide = prim.layout(store.model()).map_or(0, |(s, _)| s);
    Hints {
        unsigned: !prim.is_signed(),
        signed: prim.is_signed() && wide > size,
        ..Hints::default()
    }
}

/// The terms of a sum, through its casts.
fn terms_of<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    match node {
        AstNode::Cast { target, .. } => terms_of(target, out),
        AstNode::Binary {
            lhs,
            op: BinaryOp::Add | BinaryOp::Sub,
            rhs,
        } => {
            terms_of(lhs, out);
            terms_of(rhs, out);
        }
        other => out.push(other),
    }
}

/// An address as one of the pointers, a constant offset in bytes, and an
/// index with its scale — `p + 8 + i*4`, `p + (i + 4)*4 + 8`, `p + i` —
/// when it is one.
#[allow(clippy::type_complexity)]
fn decompose<'a>(
    address: &'a AstNode,
    pointers: &BTreeMap<String, i64>,
) -> Option<(String, i64, Option<(&'a AstNode, u64)>)> {
    let mut terms = Vec::new();
    flatten(address, false, &mut terms)?;
    let mut base = None;
    let mut offset: i64 = 0;
    let mut index: Option<(&AstNode, u64)> = None;
    let mut others = Vec::new();
    for (negative, term) in terms {
        match term {
            AstNode::Var { name } if !negative && pointers.contains_key(name) => {
                if base.replace(name.clone()).is_some() {
                    return None;
                }
            }
            AstNode::Constant { value, .. } => {
                let value = *value as i64;
                offset = if negative {
                    offset.checked_sub(value)?
                } else {
                    offset.checked_add(value)?
                };
            }
            AstNode::Binary { lhs, op, rhs }
                if !negative && matches!(op, BinaryOp::Mul | BinaryOp::Shl) =>
            {
                let (by, scale) = match (op, lhs.as_ref(), rhs.as_ref()) {
                    (BinaryOp::Mul, by, AstNode::Constant { value, .. })
                    | (BinaryOp::Mul, AstNode::Constant { value, .. }, by) => (by, *value),
                    (BinaryOp::Shl, by, AstNode::Constant { value, .. }) => {
                        (by, 1u64.checked_shl(u32::try_from(*value).ok()?)?)
                    }
                    _ => return None,
                };
                // `(i + k) * s` is the index `i` and `k * s` bytes on.
                let (by, on) = match crate::slice::strip_casts(by) {
                    AstNode::Binary {
                        lhs,
                        op: BinaryOp::Add,
                        rhs,
                    } => match rhs.as_ref() {
                        AstNode::Constant { value, .. } => (lhs.as_ref(), *value as i64),
                        _ => (by, 0),
                    },
                    _ => (by, 0),
                };
                offset = offset.checked_add(on.checked_mul(i64::try_from(scale).ok()?)?)?;
                if index.replace((by, scale)).is_some() {
                    return None;
                }
            }
            other if !negative => others.push(other),
            _ => return None,
        }
    }
    let base = base?;
    // A term of no scale besides the pointer is an index of bytes.
    match others.as_slice() {
        [] => {}
        [one] if index.is_none() => index = Some((one, 1)),
        _ => return None,
    }
    Some((base, offset, index))
}

/// The terms of a sum, each with whether it is taken away, through the
/// casts on it.
fn flatten<'a>(
    node: &'a AstNode,
    negative: bool,
    out: &mut Vec<(bool, &'a AstNode)>,
) -> Option<()> {
    match node {
        AstNode::Cast { target, .. } => flatten(target, negative, out),
        AstNode::Binary {
            lhs,
            op: BinaryOp::Add,
            rhs,
        } => {
            flatten(lhs, negative, out)?;
            flatten(rhs, negative, out)
        }
        AstNode::Binary {
            lhs,
            op: BinaryOp::Sub,
            rhs,
        } if matches!(rhs.as_ref(), AstNode::Constant { .. }) => {
            flatten(lhs, negative, out)?;
            flatten(rhs, !negative, out)
        }
        other => {
            out.push((negative, other));
            Some(())
        }
    }
}

// ---------------------------------------------------------------------
// The draft.

/// One member of a drafted structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftMember {
    /// Its offset, in bytes.
    pub offset: u64,
    /// Its size, in bytes.
    pub size: u64,
    /// Its name: `field_8`, or `gap_7` for bytes no access reaches.
    pub name: String,
    /// Its C type as C spells it: `char *`, `int[4]`.
    pub ty: String,
    /// Whether it stands for bytes no access reaches.
    pub gap: bool,
    /// How many loads read it.
    pub reads: usize,
    /// How many stores write it.
    pub writes: usize,
    /// The addresses of the statements that read or write it.
    pub at: Vec<u64>,
    /// The callees it is read or written in, through their parameter.
    pub via: Vec<String>,
}

/// A structure drafted from the accesses through a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructDraft {
    /// Its tag: `struct_make_conn_v1`, `conn`.
    pub tag: String,
    /// Its size, in bytes.
    pub size: u64,
    /// What the size is: `malloc(0x28) at 0x4010a8`, `the extent of the
    /// accesses`.
    pub sized_by: String,
    /// Whether the members need it packed to lie at their offsets.
    pub packed: bool,
    /// The members, gaps among them, in offset order.
    pub members: Vec<DraftMember>,
    /// What was left out or chosen between, and why.
    pub notes: Vec<String>,
    /// The definition as C: `struct tag { … };`.
    pub c: String,
}

impl StructDraft {
    /// The key the structure is defined by: `struct tag`.
    pub fn key(&self) -> String {
        format!("struct {}", self.tag)
    }

    /// The type a pointer to it is: `struct tag *`.
    pub fn pointer(&self) -> String {
        format!("struct {} *", self.tag)
    }
}

/// The accesses at one offset and width, put together.
#[derive(Debug, Clone)]
struct Group {
    offset: u64,
    size: u64,
    hints: Hints,
    reads: usize,
    writes: usize,
    at: BTreeSet<u64>,
    via: BTreeSet<String>,
    /// For an array: the width of an element.
    element: Option<u64>,
}

impl Group {
    fn absorb(&mut self, other: &Group) {
        self.hints.merge(&other.hints);
        self.reads += other.reads;
        self.writes += other.writes;
        self.at.extend(other.at.iter().copied());
        self.via.extend(other.via.iter().cloned());
    }

    fn end(&self) -> u64 {
        self.offset + self.size
    }
}

/// The accesses at their offsets and widths, those past `limit` or before
/// the pointer left out with a note.
fn groups(accesses: &[Access], limit: Option<u64>, notes: &mut Vec<String>) -> Vec<Group> {
    let mut by: BTreeMap<(u64, u64), Group> = BTreeMap::new();
    for access in accesses {
        let Ok(offset) = u64::try_from(access.offset) else {
            notes.push(format!(
                "an access of {} bytes at -{:#x}, at {:#x}, lies before the pointer and is left out",
                access.size,
                access.offset.unsigned_abs(),
                access.at
            ));
            continue;
        };
        if access.size == 0 {
            continue;
        }
        if let Some(limit) = limit {
            if offset + access.size > limit {
                notes.push(format!(
                    "an access of {} bytes at {offset:#x}, at {:#x}, lies past the {limit:#x} bytes allocated and is left out",
                    access.size, access.at
                ));
                continue;
            }
        }
        let group = by.entry((offset, access.size)).or_insert_with(|| Group {
            offset,
            size: access.size,
            hints: Hints::default(),
            reads: 0,
            writes: 0,
            at: BTreeSet::new(),
            via: BTreeSet::new(),
            element: None,
        });
        group.hints.merge(&access.hints);
        if access.write {
            group.writes += 1;
        } else {
            group.reads += 1;
        }
        group.at.insert(access.at);
        if let Some(via) = &access.via {
            group.via.insert(via.clone());
        }
    }
    let mut out: Vec<Group> = by.into_values().collect();
    out.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));
    out
}

/// The groups with the arrays made: an access indexed at a stride of its
/// own width is an element, and the array runs from it over the accesses
/// of that width at that stride about it, to the next access of another
/// shape or to `limit`. An access indexed at another stride is noted.
fn arrays(mut groups: Vec<Group>, limit: Option<u64>, notes: &mut Vec<String>) -> Vec<Group> {
    let mut index = 0;
    while index < groups.len() {
        let g = groups[index].clone();
        match g.hints.stride {
            Some(stride) if stride == g.size && g.element.is_none() => {}
            Some(stride) if g.element.is_none() && stride != g.size => {
                notes.push(format!(
                    "{} is indexed at a stride of {stride} bytes, wider than its {}: an array of structures is the analyst's to write",
                    field_name(g.offset),
                    g.size
                ));
                index += 1;
                continue;
            }
            _ => {
                index += 1;
                continue;
            }
        }
        let each = g.size;
        let fits = |other: &Group, start: u64| {
            other.size == each
                && other.element.is_none()
                && other.offset >= start
                && (other.offset - start).is_multiple_of(each)
        };
        // Back over the elements before it.
        let mut start = g.offset;
        while start >= each
            && groups
                .iter()
                .any(|o| o.offset == start - each && o.size == each && o.element.is_none())
        {
            start -= each;
        }
        // On to the next access of another shape.
        let next = groups
            .iter()
            .filter(|o| o.offset >= start && o.end() > start && !fits(o, start))
            .map(|o| o.offset)
            .min();
        let seen_end = groups
            .iter()
            .filter(|o| fits(o, start))
            .map(Group::end)
            .max()
            .unwrap_or(g.end());
        let end = match (next, limit) {
            (Some(next), _) => next.max(seen_end),
            (None, Some(limit)) => limit.max(seen_end),
            (None, None) => seen_end,
        };
        let end = start + ((end - start) / each).max(1) * each;
        let mut array = Group {
            offset: start,
            size: end - start,
            element: Some(each),
            ..g.clone()
        };
        array.reads = 0;
        array.writes = 0;
        array.at.clear();
        array.via.clear();
        array.hints = Hints::default();
        let mut kept = Vec::new();
        for other in groups.drain(..) {
            if fits(&other, start) && other.end() <= end {
                array.absorb(&other);
            } else {
                kept.push(other);
            }
        }
        array.hints.stride = Some(each);
        kept.push(array);
        kept.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));
        groups = kept;
        index = 0;
    }
    groups
}

/// The groups that do not share bytes: the wider of two at one offset,
/// the first of two that overlap; the rest noted.
fn exclusive(groups: Vec<Group>, notes: &mut Vec<String>) -> Vec<Group> {
    let mut kept: Vec<Group> = Vec::new();
    for group in groups {
        match kept.last_mut() {
            Some(last) if group.offset < last.end() => {
                let reached = group
                    .at
                    .iter()
                    .map(|a| format!("{a:#x}"))
                    .collect::<Vec<_>>();
                if group.end() <= last.end() {
                    notes.push(format!(
                        "{} is reached as {} bytes at {:#x} too, at {}: the wider is kept",
                        field_name(last.offset),
                        group.size,
                        group.offset,
                        reached.join(", ")
                    ));
                    last.reads += group.reads;
                    last.writes += group.writes;
                    last.at.extend(group.at.iter().copied());
                    last.via.extend(group.via.iter().cloned());
                } else {
                    notes.push(format!(
                        "an access of {} bytes at {:#x}, at {}, overlaps {} and is left out",
                        group.size,
                        group.offset,
                        reached.join(", "),
                        field_name(last.offset)
                    ));
                }
            }
            _ => kept.push(group),
        }
    }
    kept
}

/// The name of the member at `offset`: `field_1c`.
pub fn field_name(offset: u64) -> String {
    format!("field_{offset:x}")
}

/// The name of the gap at `offset`: `gap_7`.
pub fn gap_name(offset: u64) -> String {
    format!("gap_{offset:x}")
}

/// The integer of `size` bytes under `model`, unsigned when `unsigned`.
fn integer(size: u64, unsigned: bool, model: &DataModel) -> Option<Prim> {
    Some(match (size, unsigned) {
        (1, false) => Prim::Char,
        (1, true) => Prim::UChar,
        (2, false) => Prim::Short,
        (2, true) => Prim::UShort,
        (4, false) => Prim::Int,
        (4, true) => Prim::UInt,
        (8, false) if model.long == 8 => Prim::Long,
        (8, true) if model.long == 8 => Prim::ULong,
        (8, false) => Prim::LongLong,
        (8, true) => Prim::ULongLong,
        _ => return None,
    })
}

/// The type of a value of `size` bytes its uses say `hints` of.
fn scalar(size: u64, hints: &Hints, model: &DataModel) -> Type {
    if hints.pointer && size == model.pointer {
        let pointee = match hints.pointees.iter().collect::<Vec<_>>().as_slice() {
            [one] => integer(**one, false, model).map_or(Type::Prim(Prim::Void), Type::Prim),
            _ => Type::Prim(Prim::Void),
        };
        return Type::pointer(pointee);
    }
    let unsigned = hints.unsigned && !hints.signed;
    match integer(size, unsigned, model) {
        Some(prim) => Type::Prim(prim),
        None => Type::Array(Box::new(Type::Prim(Prim::UChar)), Some(size)),
    }
}

/// The type of a group: its scalar, or an array of them.
fn group_type(group: &Group, model: &DataModel) -> Type {
    match group.element {
        Some(each) => {
            let mut hints = group.hints.clone();
            hints.stride = None;
            Type::Array(
                Box::new(scalar(each, &hints, model)),
                Some(group.size / each),
            )
        }
        None => scalar(group.size, &group.hints, model),
    }
}

fn member_of_group(group: &Group, model: &DataModel, store: &TypeStore) -> (DraftMember, Type) {
    let ty = group_type(group, model);
    (
        DraftMember {
            offset: group.offset,
            size: group.size,
            name: field_name(group.offset),
            ty: ty.spelled(store),
            gap: false,
            reads: group.reads,
            writes: group.writes,
            at: group.at.iter().copied().collect(),
            via: group.via.iter().cloned().collect(),
        },
        ty,
    )
}

fn gap(offset: u64, size: u64, store: &TypeStore) -> (DraftMember, Type) {
    let ty = Type::Array(Box::new(Type::Prim(Prim::Char)), Some(size));
    (
        DraftMember {
            offset,
            size,
            name: gap_name(offset),
            ty: ty.spelled(store),
            gap: true,
            reads: 0,
            writes: 0,
            at: Vec::new(),
            via: Vec::new(),
        },
        ty,
    )
}

fn round_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.div_ceil(align) * align
    }
}

/// The members laid out to `size` — packed, or by natural alignment — with
/// the gaps it takes; None when natural alignment cannot place a member at
/// its offset.
fn lay_out(
    members: &[(DraftMember, Type)],
    size: u64,
    packed: bool,
    store: &TypeStore,
) -> Option<(Vec<(DraftMember, Type)>, u64)> {
    let mut out = Vec::new();
    let mut cursor = 0u64;
    let mut widest = 1u64;
    for (member, ty) in members {
        let align = if packed { 1 } else { store.align_of(ty).ok()? };
        if round_up(cursor, align) != member.offset {
            if member.offset > cursor {
                out.push(gap(cursor, member.offset - cursor, store));
            }
            if !member.offset.is_multiple_of(align) {
                return None;
            }
        }
        out.push((member.clone(), ty.clone()));
        cursor = member.offset + member.size;
        widest = widest.max(align);
    }
    if size > cursor && (packed || round_up(cursor, widest) != size) {
        out.push(gap(cursor, size - cursor, store));
        cursor = size;
    }
    Some((out, round_up(cursor, widest)))
}

/// The C of a structure `tag` of `members`.
fn struct_text(
    tag: &str,
    members: &[(DraftMember, Type)],
    packed: bool,
    store: &TypeStore,
) -> String {
    let mut out = String::from("struct ");
    if packed {
        out.push_str("__attribute__((packed)) ");
    }
    out.push_str(tag);
    out.push_str(" {\n");
    for (member, ty) in members {
        out.push_str("    ");
        out.push_str(&crate::types::declaration(ty, &member.name, store));
        out.push_str(";\n");
    }
    out.push_str("};");
    out
}

/// A structure `tag` drafted from `accesses` under the types of `store`:
/// `size` bytes when an allocation says so, else the extent of the
/// accesses. Refused when no access is left and no size is known.
pub fn infer_struct(
    tag: &str,
    accesses: &[Access],
    size: Option<u64>,
    store: &TypeStore,
) -> Result<StructDraft, String> {
    let model = *store.model();
    let mut notes = Vec::new();
    let grouped = groups(accesses, size, &mut notes);
    let grouped = arrays(grouped, size, &mut notes);
    let kept = exclusive(grouped, &mut notes);
    let members: Vec<(DraftMember, Type)> = kept
        .iter()
        .map(|group| member_of_group(group, &model, store))
        .collect();
    let widest = members
        .iter()
        .filter_map(|(_, ty)| store.align_of(ty).ok())
        .max()
        .unwrap_or(1);
    let extent = members.iter().map(|(m, _)| m.offset + m.size).max();
    let (target, sized_by) = match (size, extent) {
        (Some(size), _) => (size, "the allocation".to_string()),
        (None, Some(extent)) => (
            round_up(extent, widest),
            "the extent of the accesses".to_string(),
        ),
        (None, None) => return Err("no access through the pointer is seen".to_string()),
    };
    let (laid, packed, total) = match lay_out(&members, target, false, store) {
        Some((laid, total)) if total == target => (laid, false, total),
        Some((laid, total)) => {
            notes.push(format!(
                "the {target:#x} bytes are no multiple of the members' alignment, {widest}: the structure is {total:#x}"
            ));
            (laid, false, total)
        }
        None => {
            let (laid, total) =
                lay_out(&members, target, true, store).ok_or("the members do not lay out")?;
            notes.push(
                "a member lies off its natural alignment: the structure is packed".to_string(),
            );
            (laid, true, total)
        }
    };
    let c = struct_text(tag, &laid, packed, store);
    // The draft must read back as it was laid out.
    let mut probe = store.clone();
    match crate::ctype::parse_into(&mut probe, &c) {
        Ok(_) => {
            let key = format!("struct {tag}");
            let fits = probe.layout(&key).is_some_and(|layout| {
                layout.size == total
                    && layout.fields.len() == laid.len()
                    && layout
                        .fields
                        .iter()
                        .zip(&laid)
                        .all(|(field, (member, _))| field.offset == member.offset)
            });
            if !fits {
                notes.push("the draft does not lay out at the offsets accessed".to_string());
            }
        }
        Err(error) => return Err(format!("the draft does not read: {error}")),
    }
    Ok(StructDraft {
        tag: tag.to_string(),
        size: total,
        sized_by,
        packed,
        members: laid.into_iter().map(|(member, _)| member).collect(),
        notes,
        c,
    })
}

/// The draft of the structure `tag` the accesses of `found` make, sized by
/// its allocation when there is one.
pub fn draft(found: &Accesses, tag: &str, store: &TypeStore) -> Result<StructDraft, String> {
    let size = found.allocation.as_ref().map(|a| a.size);
    let mut drafted = infer_struct(tag, &found.accesses, size, store)?;
    if let Some(allocation) = &found.allocation {
        drafted.sized_by = format!("{} at {:#x}", allocation.call, allocation.at);
    }
    Ok(drafted)
}

/// The tag a structure drafted from `variable` of `function` goes by when
/// the analyst names none: `struct_<function>_<variable>`, made an
/// identifier, and numbered past the ones `store` defines.
pub fn default_tag(store: &TypeStore, function: &str, variable: &str) -> String {
    let mut base = String::from("struct_");
    for c in format!("{function}_{variable}").chars() {
        if c.is_ascii_alphanumeric() {
            base.push(c);
        } else if !base.ends_with('_') {
            base.push('_');
        }
    }
    let base = base.trim_end_matches('_').to_string();
    unused_tag(store, &base)
}

/// `tag`, or `tag_2`, `tag_3` … when `store` defines it already.
pub fn unused_tag(store: &TypeStore, tag: &str) -> String {
    let taken = |tag: &str| {
        store.get(&format!("struct {tag}")).is_some()
            || store.get(&format!("union {tag}")).is_some()
            || store.get(tag).is_some()
    };
    if !taken(tag) {
        return tag.to_string();
    }
    (2..)
        .map(|n| format!("{tag}_{n}"))
        .find(|candidate| !taken(candidate))
        .unwrap_or_else(|| tag.to_string())
}

/// The tag a name the analyst gives stands for: `conn` or `struct conn`;
/// refused when it is no identifier.
pub fn tag_of(name: &str) -> Result<String, String> {
    let name = name.trim();
    let tag = name.strip_prefix("struct ").map(str::trim).unwrap_or(name);
    let identifier = tag
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if identifier {
        Ok(tag.to_string())
    } else {
        Err(format!("{name} is no name a structure can have"))
    }
}

/// The definitions with `drafted` after them; refused when its name is
/// defined already.
pub fn create_struct(
    model: DataModel,
    definitions: &[TypeText],
    drafted: &StructDraft,
) -> Result<Vec<TypeText>, String> {
    crate::ctype::add(model, definitions, &drafted.c).map(|(defined, _, _)| defined)
}

/// What an update of a structure from accesses did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The definitions, the structure's replaced when it changed.
    pub definitions: Vec<TypeText>,
    /// The structure's key: `struct conn`.
    pub key: String,
    /// The members added, gaps among them.
    pub added: Vec<DraftMember>,
    /// The accesses that met a member at other bytes, and what was not
    /// added and why.
    pub notes: Vec<String>,
    /// The structure's C after.
    pub c: String,
}

/// One member of a structure being updated: its declaration, where it
/// lies, and the member drafted when it is a new one.
#[derive(Clone)]
struct Item {
    text: String,
    name: Option<String>,
    offset: u64,
    end: u64,
    /// Whether it is a gap a draft left, `char gap_18[16]`: bytes no
    /// member holds, which a new member may take.
    gap: bool,
}

/// `definitions` with the structure `name` given a member for each access
/// of `found` in bytes no member of it holds — between them, in their
/// padding, or past its end — never renaming, retyping or moving one it
/// has. An access that meets a member at other bytes than the member's
/// own is a note, as is a member the layout cannot place at its offset.
pub fn update_struct(
    model: DataModel,
    definitions: &[TypeText],
    name: &str,
    found: &Accesses,
) -> Result<Merged, String> {
    let (store, _) = crate::ctype::build(model, definitions)?;
    let key = store
        .key_of(name)
        .ok_or_else(|| format!("no type is named {}", name.trim()))?;
    if !key.starts_with("struct ") {
        return Err(format!("{key} is no structure"));
    }
    let (head, members) = store
        .member_texts(&key)
        .ok_or_else(|| format!("{key} is declared and not defined"))?;
    let old_size = store
        .size_of(&Type::Named(key.clone()))
        .map_err(|why| format!("{key}: {why}"))?;
    let allocated = found.allocation.as_ref().map(|a| a.size);
    let limit = allocated.map(|a| a.max(old_size));
    let mut notes = Vec::new();
    let grouped = groups(&found.accesses, limit, &mut notes);
    let grouped = arrays(grouped, limit, &mut notes);
    let kept = exclusive(grouped, &mut notes);
    let mut items: Vec<Item> = members
        .iter()
        .map(|(text, field)| {
            let end = match field.bits {
                Some((bit, width)) => {
                    (field.offset * 8 + u64::from(bit) + u64::from(width)).div_ceil(8)
                }
                None => field.offset + field.size,
            };
            // A gap a draft left is bytes no member holds.
            let gap = field.bits.is_none()
                && field.name.as_deref().is_some_and(|name| {
                    name.strip_prefix("gap_")
                        .is_some_and(|hex| u64::from_str_radix(hex, 16) == Ok(field.offset))
                })
                && matches!(store.resolve(&field.ty), Type::Array(item, _)
                    if matches!(**item, Type::Prim(Prim::Char | Prim::UChar | Prim::SChar)));
            Item {
                text: text.clone(),
                name: field.name.clone(),
                offset: field.offset,
                end,
                gap,
            }
        })
        .collect();
    let mut candidates = Vec::new();
    for group in &kept {
        let meets: Vec<&Item> = items
            .iter()
            .filter(|item| !item.gap && group.offset < item.end && item.offset < group.end())
            .collect();
        match meets.as_slice() {
            [] => candidates.push(group),
            [item] if item.offset == group.offset && item.end == group.end() => {}
            _ => {
                let named: Vec<String> = meets
                    .iter()
                    .map(|item| {
                        item.name
                            .clone()
                            .unwrap_or_else(|| format!("the member at {:#x}", item.offset))
                    })
                    .collect();
                notes.push(format!(
                    "an access of {} bytes at {:#x} meets {} at other bytes: left as it is",
                    group.size,
                    group.offset,
                    named.join(", ")
                ));
            }
        }
    }
    let unique = |wanted: String, items: &[Item]| {
        let taken = |n: &str| items.iter().any(|item| item.name.as_deref() == Some(n));
        if !taken(&wanted) {
            return wanted;
        }
        (2..)
            .map(|n| format!("{wanted}_{n}"))
            .find(|c| !taken(c))
            .unwrap_or(wanted)
    };
    let pack = store.pack_of(&key);
    let render = |items: &[Item]| {
        let mut out = String::new();
        if let Some(pack) = pack {
            out.push_str(&format!("#pragma pack(push, {pack})\n"));
        }
        out.push_str(&head);
        out.push_str(" {\n");
        for item in items {
            out.push_str("    ");
            out.push_str(&item.text);
            out.push_str(";\n");
        }
        out.push_str("};");
        if pack.is_some() {
            out.push_str("\n#pragma pack(pop)");
        }
        out
    };
    // Whether the items lay out where they say, the structure no smaller.
    let lays_out = |items: &[Item]| -> Option<Vec<TypeText>> {
        let (defined, _) = crate::ctype::replace(model, definitions, &key, &render(items)).ok()?;
        let (built, _) = crate::ctype::build(model, &defined).ok()?;
        let layout = built.layout(&key)?;
        let fits = layout.size >= old_size
            && layout.fields.len() == items.len()
            && layout
                .fields
                .iter()
                .zip(items)
                .all(|(field, item)| field.offset == item.offset);
        fits.then_some(defined)
    };
    let made = |member: DraftMember, ty: &Type| Item {
        text: crate::types::declaration(ty, &member.name, &store),
        name: Some(member.name.clone()),
        offset: member.offset,
        end: member.offset + member.size,
        gap: member.gap,
    };
    let mut added = Vec::new();
    let mut current = definitions.to_vec();
    for group in candidates {
        // A gap the access lies in is split about it.
        let within = items
            .iter()
            .position(|item| item.gap && item.offset <= group.offset && group.end() <= item.end);
        // An array runs on to the next member, or to the end of its gap.
        let mut group = group.clone();
        if let Some(each) = group.element {
            let next = match within {
                Some(at) => Some(items[at].end),
                None => items
                    .iter()
                    .filter(|item| item.offset >= group.end())
                    .map(|item| item.offset)
                    .min(),
            };
            if let Some(next) = next {
                let size = (next - group.offset) / each * each;
                if size > group.size {
                    group.size = size;
                }
            }
        }
        let group = &group;
        let (mut member, ty) = member_of_group(group, &model, &store);
        let crossed = items
            .iter()
            .any(|item| item.gap && group.offset < item.end && item.offset < group.end());
        if crossed && within.is_none() {
            notes.push(format!(
                "an access of {} bytes at {:#x} runs over the end of a gap: left out",
                group.size, group.offset
            ));
            continue;
        }
        let (mut tried, at, before) = match within {
            Some(at) => {
                let mut tried = items.clone();
                let held = tried.remove(at);
                (tried, at, held.offset)
            }
            None => {
                let at = items
                    .iter()
                    .position(|item| {
                        item.offset > group.offset
                            || (item.offset == group.offset && item.end == item.offset)
                    })
                    .unwrap_or(items.len());
                let before = items[..at].iter().map(|item| item.end).max().unwrap_or(0);
                (items.clone(), at, before)
            }
        };
        let after = within.map(|at| items[at].end);
        let align = store.align_of(&ty).unwrap_or(1);
        let mut inserted = Vec::new();
        let mut at = at;
        if group.offset > before && (within.is_some() || round_up(before, align) != group.offset) {
            let (mut filler, filler_ty) = gap(before, group.offset - before, &store);
            filler.name = unique(filler.name.clone(), &tried);
            inserted.push(filler.clone());
            tried.insert(at, made(filler, &filler_ty));
            at += 1;
        }
        member.name = unique(member.name.clone(), &tried);
        inserted.push(member.clone());
        tried.insert(at, made(member.clone(), &ty));
        at += 1;
        if let Some(after) = after.filter(|&after| after > group.end()) {
            let (mut filler, filler_ty) = gap(group.end(), after - group.end(), &store);
            filler.name = unique(filler.name.clone(), &tried);
            inserted.push(filler.clone());
            tried.insert(at, made(filler, &filler_ty));
        }
        match lays_out(&tried) {
            Some(defined) => {
                items = tried;
                current = defined;
                added.extend(inserted);
            }
            None => notes.push(format!(
                "{} ({}) cannot lie at {:#x} in {key} without moving a member: left out",
                member.name, member.ty, member.offset
            )),
        }
    }
    let (built, _) = crate::ctype::build(model, &current)?;
    let c = built
        .definition_text(&key, false)
        .unwrap_or_else(|| render(&items));
    Ok(Merged {
        definitions: current,
        key,
        added,
        notes,
        c,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::StructField;
    use crate::lift::Variable;
    use crate::types::DataModel;

    fn store() -> TypeStore {
        TypeStore::new(DataModel::LP64)
    }

    fn var(name: &str) -> AstNode {
        AstNode::var(name)
    }

    fn k(value: u64) -> AstNode {
        AstNode::constant(value, 8)
    }

    fn plus(a: AstNode, b: AstNode) -> AstNode {
        AstNode::binary(a, BinaryOp::Add, b)
    }

    /// `*(ty)address`.
    fn at(ty: &str, address: AstNode) -> AstNode {
        AstNode::Deref {
            target: Box::new(AstNode::Cast {
                ty: ty.to_string(),
                target: Box::new(address),
            }),
        }
    }

    fn assign(lhs: AstNode, rhs: AstNode) -> AstNode {
        AstNode::Assign {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    fn call(name: &str, address: u64, args: Vec<AstNode>) -> AstNode {
        AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: name.to_string(),
                address,
            }),
            args,
        }
    }

    fn ret(value: AstNode) -> AstNode {
        AstNode::Return {
            value: Some(Box::new(value)),
        }
    }

    /// A function `f` at 0x1000 of `params` and `locals`, each `long`
    /// unless typed, whose statements are `nodes`, at 0x1000, 0x1004 ….
    fn function(
        params: &[(&str, &str)],
        locals: &[(&str, &str)],
        nodes: Vec<AstNode>,
    ) -> LiftedFunction {
        let made = |vars: &[(&str, &str)]| {
            vars.iter()
                .map(|(name, ty)| Variable::new(*ty, *name))
                .collect::<Vec<_>>()
        };
        LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "long".to_string(),
            params: made(params),
            locals: made(locals),
            body: nodes
                .into_iter()
                .enumerate()
                .map(|(i, node)| Statement::plain(node, vec![0x1000 + 4 * i as u64]))
                .collect(),
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        }
    }

    fn accesses(f: &LiftedFunction, variable: &str) -> Accesses {
        struct_accesses(f, variable, &store(), &|_| None).expect("the accesses are read")
    }

    fn shape(found: &Accesses) -> Vec<(i64, u64, bool)> {
        found
            .accesses
            .iter()
            .map(|a| (a.offset, a.size, a.write))
            .collect()
    }

    fn drafted(f: &LiftedFunction, variable: &str) -> StructDraft {
        draft(&accesses(f, variable), "s", &store()).expect("a draft")
    }

    #[test]
    fn accesses_through_a_parameter_are_its_offsets_and_widths() {
        let f = function(
            &[("a", "long")],
            &[],
            vec![
                assign(at("long *", plus(var("a"), k(8))), k(5)),
                ret(plus(
                    at("int *", plus(var("a"), k(4))),
                    at("int *", var("a")),
                )),
            ],
        );
        let found = accesses(&f, "a");
        assert_eq!(
            shape(&found),
            vec![(8, 8, true), (4, 4, false), (0, 4, false)]
        );
        assert_eq!(found.accesses[0].at, 0x1000);
        assert_eq!(found.accesses[1].at, 0x1004);
        assert_eq!(found.allocation, None);
        // A variable narrower than a pointer is refused.
        let narrow = function(&[("a", "int")], &[], vec![]);
        assert_eq!(
            struct_accesses(&narrow, "a", &store(), &|_| None).unwrap_err(),
            "a is int, and a pointer is 8 bytes"
        );
        assert_eq!(
            struct_accesses(&narrow, "z", &store(), &|_| None).unwrap_err(),
            "f declares no z"
        );
    }

    #[test]
    fn a_derived_pointer_and_a_copy_are_the_pointer_at_their_offsets() {
        let f = function(
            &[("a", "long")],
            &[("q", "long"), ("r", "long"), ("s", "long")],
            vec![
                assign(var("q"), plus(var("a"), k(8))),
                assign(at("int *", var("q")), k(1)),
                assign(at("int *", plus(var("q"), k(4))), k(2)),
                assign(
                    var("r"),
                    AstNode::Cast {
                        ty: "long".into(),
                        target: Box::new(var("a")),
                    },
                ),
                assign(at("short *", plus(var("r"), k(0x14))), k(3)),
                // Two assignments of other offsets: not the pointer.
                assign(var("s"), var("a")),
                assign(var("s"), plus(var("a"), k(1))),
                assign(at("char *", var("s")), k(4)),
            ],
        );
        let found = accesses(&f, "a");
        assert_eq!(
            shape(&found),
            vec![(8, 4, true), (12, 4, true), (0x14, 2, true)]
        );
        assert_eq!(
            found.pointers,
            vec![("a".into(), 0), ("q".into(), 8), ("r".into(), 0)]
        );
    }

    #[test]
    fn a_malloc_sizes_the_structure_and_the_rest_is_a_gap() {
        let f = function(
            &[],
            &[("v1", "long")],
            vec![
                assign(var("v1"), call("malloc", 0x2000, vec![k(0x18), var("b")])),
                assign(at("int *", var("v1")), k(1)),
                assign(at("long *", plus(var("v1"), k(8))), k(2)),
                ret(var("v1")),
            ],
        );
        let found = accesses(&f, "v1");
        let allocation = found.allocation.clone().expect("an allocation");
        assert_eq!((allocation.size, allocation.at), (0x18, 0x1000));
        assert_eq!(allocation.call, "malloc(0x18)");
        let made = draft(&found, "s", &store()).unwrap();
        assert_eq!(made.size, 0x18);
        assert_eq!(made.sized_by, "malloc(0x18) at 0x1000");
        assert_eq!(
            made.c,
            "struct s {\n    int field_0;\n    long field_8;\n    char gap_10[8];\n};"
        );
        // The draft reads back through the parser.
        let mut store = store();
        crate::ctype::parse_into(&mut store, &made.c).unwrap();
        assert_eq!(store.size_of(&Type::Named("struct s".into())), Ok(0x18));
        // An access past the allocation is left out with a note.
        let past = infer_struct("s", &found.accesses, Some(8), &super::tests::store()).unwrap();
        assert!(
            past.notes[0].contains("lies past the 0x8 bytes allocated"),
            "{:?}",
            past.notes
        );
    }

    #[test]
    fn a_calloc_sizes_the_structure_by_its_product() {
        let f = function(
            &[],
            &[("v1", "long")],
            vec![
                assign(var("v1"), call("calloc", 0x2000, vec![k(4), k(8)])),
                assign(at("long *", plus(var("v1"), k(0x18))), k(2)),
                ret(var("v1")),
            ],
        );
        let made = drafted(&f, "v1");
        assert_eq!(made.size, 0x20);
        assert_eq!(made.sized_by, "calloc(4, 8) at 0x1000");
        assert_eq!(
            made.c,
            "struct s {\n    char gap_0[24];\n    long field_18;\n};"
        );
        // A size that is not constant sizes nothing.
        let g = function(
            &[("n", "long")],
            &[("v1", "long")],
            vec![
                assign(var("v1"), call("calloc", 0x2000, vec![var("n"), k(8)])),
                assign(at("long *", var("v1")), k(2)),
            ],
        );
        assert_eq!(accesses(&g, "v1").allocation, None);
    }

    #[test]
    fn the_allocators_are_known_through_their_decorations() {
        for name in [
            "malloc",
            "malloc@plt",
            "_malloc",
            "__imp_HeapAlloc",
            "j_calloc",
            "_Znwm",
            "operator new(unsigned long)",
            "??2@YAPEAX_K@Z",
            "kzalloc",
            "g_malloc0",
        ] {
            assert!(is_allocator(name), "{name}");
        }
        assert!(!is_allocator("free"));
        assert_eq!(
            allocation_size("HeapAlloc", &[var("h"), k(0), k(0x40)]).map(|(s, _)| s),
            Some(0x40)
        );
        assert_eq!(
            allocation_size("_Znwm", &[k(0x20)]).map(|(s, _)| s),
            Some(0x20)
        );
    }

    #[test]
    fn the_extent_sizes_a_structure_rounded_to_its_widest_alignment() {
        let f = function(
            &[("a", "long")],
            &[],
            vec![
                assign(at("char *", var("a")), k(1)),
                assign(at("long *", plus(var("a"), k(8))), k(2)),
                assign(at("int *", plus(var("a"), k(0x10))), k(3)),
            ],
        );
        let made = drafted(&f, "a");
        assert_eq!(made.size, 0x18);
        assert_eq!(made.sized_by, "the extent of the accesses");
        // The padding natural alignment leaves needs no gap.
        assert_eq!(
            made.c,
            "struct s {\n    char field_0;\n    long field_8;\n    int field_10;\n};"
        );
        // A gap where natural alignment would not leave one.
        let g = function(
            &[("a", "long")],
            &[],
            vec![
                assign(at("char *", var("a")), k(1)),
                assign(at("int *", plus(var("a"), k(8))), k(2)),
            ],
        );
        let made = drafted(&g, "a");
        assert_eq!(
            made.c,
            "struct s {\n    char field_0;\n    char gap_1[7];\n    int field_8;\n};"
        );
        assert_eq!(made.size, 12);
        assert!(made.members[1].gap);
        // A member off its alignment packs the structure.
        let h = function(
            &[("a", "long")],
            &[],
            vec![assign(at("int *", plus(var("a"), k(2))), k(2))],
        );
        let made = drafted(&h, "a");
        assert!(made.packed);
        assert_eq!(
            made.c,
            "struct __attribute__((packed)) s {\n    char gap_0[2];\n    int field_2;\n    char gap_6[2];\n};"
        );
        assert_eq!(made.size, 8);
    }

    #[test]
    fn a_loaded_value_dereferenced_is_a_pointer() {
        let f = function(
            &[("a", "long")],
            &[],
            vec![
                ret(at("char *", at("long *", plus(var("a"), k(8))))),
                // Passed to free: a pointer of no known width.
                AstNode::Call {
                    callee: Box::new(AstNode::FunctionName {
                        name: "free".into(),
                        address: 0x3000,
                    }),
                    args: vec![at("long *", plus(var("a"), k(0x10)))],
                },
                // A string stored is a pointer to char.
                assign(
                    at("long *", plus(var("a"), k(0x18))),
                    AstNode::StringLiteral { text: "x".into() },
                ),
            ],
        );
        let made = drafted(&f, "a");
        assert_eq!(
            made.c,
            "struct s {\n    char gap_0[8];\n    char *field_8;\n    void *field_10;\n    char *field_18;\n};"
        );
    }

    #[test]
    fn signs_and_zero_extensions_type_the_integers() {
        let f = function(
            &[("a", "long")],
            &[],
            vec![
                ret(AstNode::Cast {
                    ty: "long".into(),
                    target: Box::new(at("int *", var("a"))),
                }),
                ret(AstNode::Cast {
                    ty: "unsigned int".into(),
                    target: Box::new(at("short *", plus(var("a"), k(4)))),
                }),
            ],
        );
        let made = drafted(&f, "a");
        assert_eq!(made.members[0].ty, "int");
        assert_eq!(made.members[1].ty, "unsigned short");
    }

    #[test]
    fn an_access_indexed_by_a_variable_is_an_array() {
        let index = |offset: u64| {
            plus(
                plus(var("a"), k(offset)),
                AstNode::binary(var("b"), BinaryOp::Mul, k(4)),
            )
        };
        let f = function(
            &[("a", "long"), ("b", "long")],
            &[],
            vec![
                ret(at("int *", var("a"))),
                ret(at("int *", index(8))),
                ret(at("long *", plus(var("a"), k(0x18)))),
            ],
        );
        let made = drafted(&f, "a");
        assert_eq!(
            made.c,
            "struct s {\n    int field_0;\n    char gap_4[4];\n    int field_8[4];\n    long field_18;\n};"
        );
        // `(b + 4) * 4 + 8` is the index b at 0x18.
        let g = function(
            &[("a", "long"), ("b", "long")],
            &[],
            vec![ret(at(
                "int *",
                plus(
                    plus(
                        var("a"),
                        AstNode::binary(plus(var("b"), k(4)), BinaryOp::Mul, k(4)),
                    ),
                    k(8),
                ),
            ))],
        );
        let found = accesses(&g, "a");
        assert_eq!(shape(&found), vec![(0x18, 4, false)]);
        assert_eq!(found.accesses[0].hints.stride, Some(4));
        // Sized by an allocation, the array runs to its end.
        let made = infer_struct("s", &found.accesses, Some(0x28), &store()).unwrap();
        assert_eq!(
            made.c,
            "struct s {\n    char gap_0[24];\n    int field_18[4];\n};"
        );
    }

    #[test]
    fn overlapping_accesses_keep_the_wider_with_a_note() {
        let f = function(
            &[("a", "long")],
            &[],
            vec![
                ret(at("int *", var("a"))),
                ret(at("long *", var("a"))),
                ret(at("int *", plus(var("a"), k(6)))),
            ],
        );
        let made = drafted(&f, "a");
        assert_eq!(made.c, "struct s {\n    long field_0;\n};");
        assert_eq!(made.members[0].reads, 2);
        assert_eq!(
            made.notes,
            vec![
                "field_0 is reached as 4 bytes at 0x0 too, at 0x1000: the wider is kept",
                "an access of 4 bytes at 0x6, at 0x1008, overlaps field_0 and is left out",
            ]
        );
    }

    #[test]
    fn a_struct_initializer_is_one_store_a_field() {
        let f = function(
            &[("a", "long"), ("b", "long")],
            &[],
            vec![assign(
                at("struct { int at_0; long at_8; } *", var("a")),
                AstNode::StructInit {
                    fields: vec![
                        StructField {
                            ty: "int".into(),
                            offset: 0,
                            value: k(1),
                        },
                        StructField {
                            ty: "long".into(),
                            offset: 8,
                            value: var("a"),
                        },
                    ],
                },
            )],
        );
        let made = drafted(&f, "a");
        // The pointer stored in itself is a pointer.
        assert_eq!(
            made.c,
            "struct s {\n    int field_0;\n    void *field_8;\n};"
        );
        assert_eq!(made.members[1].writes, 1);
    }

    #[test]
    fn the_pointer_passed_to_a_callee_is_followed_one_level() {
        let mut callee = function(
            &[("a", "long")],
            &[],
            vec![ret(at("int *", plus(var("a"), k(4))))],
        );
        callee.name = "g".into();
        callee.address = 0x3000;
        let f = function(
            &[("a", "long")],
            &[],
            vec![
                assign(at("long *", var("a")), k(0)),
                AstNode::Call {
                    callee: Box::new(AstNode::FunctionName {
                        name: "g".into(),
                        address: 0x3000,
                    }),
                    args: vec![plus(var("a"), k(8))],
                },
            ],
        );
        let lifted = |address: u64| (address == 0x3000).then(|| callee.clone());
        let found = struct_accesses(&f, "a", &store(), &lifted).unwrap();
        assert_eq!(shape(&found), vec![(0, 8, true), (12, 4, false)]);
        assert_eq!(found.accesses[1].via.as_deref(), Some("g"));
        assert_eq!(found.followed, vec!["g".to_string()]);
        let made = draft(&found, "s", &store()).unwrap();
        assert_eq!(
            made.members.last().map(|m| m.via.clone()),
            Some(vec!["g".to_string()])
        );
    }

    #[test]
    fn a_typed_pointers_members_are_their_bytes() {
        let mut store = store();
        crate::ctype::parse_into(&mut store, "struct point { int x; int y; long tag; };").unwrap();
        let f = function(
            &[("a", "struct point *")],
            &[],
            vec![
                ret(crate::typed::member(var("a"), "y", true)),
                ret(at("short *", plus(var("a"), k(0x12)))),
            ],
        );
        let found = struct_accesses(&f, "a", &store, &|_| None).unwrap();
        assert_eq!(shape(&found), vec![(4, 4, false), (0x12, 2, false)]);
    }

    #[test]
    fn eight_bytes_are_long_long_where_long_is_four() {
        let store = TypeStore::new(DataModel::ILP32);
        let access = Access {
            offset: 0,
            size: 8,
            write: false,
            hints: Hints::default(),
            at: 0,
            via: None,
        };
        let made = infer_struct("s", &[access], None, &store).unwrap();
        assert_eq!(made.c, "struct s {\n    long long field_0;\n};");
    }

    #[test]
    fn a_default_tag_is_the_function_and_variable_numbered_past_the_types() {
        let mut store = store();
        assert_eq!(
            default_tag(&store, "make_conn", "v1"),
            "struct_make_conn_v1"
        );
        assert_eq!(default_tag(&store, "ns::f(int)", "p"), "struct_ns_f_int_p");
        crate::ctype::parse_into(&mut store, "struct struct_f_p { int x; };").unwrap();
        assert_eq!(default_tag(&store, "f", "p"), "struct_f_p_2");
        assert_eq!(tag_of("struct conn"), Ok("conn".to_string()));
        assert!(tag_of("two words").is_err());
    }

    fn texts(c: &str) -> Vec<TypeText> {
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(&mut store, c)
            .unwrap()
            .declarations
            .into_iter()
            .map(|d| TypeText {
                name: d.name,
                c: d.text,
            })
            .collect()
    }

    fn found_of(shapes: &[(i64, u64)]) -> Accesses {
        Accesses {
            function: "f".into(),
            variable: "a".into(),
            accesses: shapes
                .iter()
                .map(|&(offset, size)| Access {
                    offset,
                    size,
                    write: false,
                    hints: Hints::default(),
                    at: 0x1000,
                    via: None,
                })
                .collect(),
            allocation: None,
            pointers: vec![("a".into(), 0)],
            followed: Vec::new(),
        }
    }

    #[test]
    fn an_update_adds_members_in_the_gaps_and_renames_none() {
        let held = texts("struct s { int x; long y; };");
        let found = found_of(&[(0, 4), (4, 2), (0xc, 4), (0x10, 8)]);
        let merged = update_struct(DataModel::LP64, &held, "s", &found).unwrap();
        assert_eq!(merged.key, "struct s");
        assert_eq!(
            merged.c,
            "struct s {\n    int x;\n    short field_4;\n    long y;\n    long field_10;\n};"
        );
        let added: Vec<&str> = merged.added.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(added, vec!["field_4", "field_10"]);
        assert_eq!(
            merged.notes,
            vec!["an access of 4 bytes at 0xc meets y at other bytes: left as it is"]
        );
        // A byte of padding off the natural place takes a gap before it.
        let found = found_of(&[(6, 1)]);
        let merged = update_struct(DataModel::LP64, &held, "s", &found).unwrap();
        assert_eq!(
            merged.c,
            "struct s {\n    int x;\n    char gap_4[2];\n    char field_6;\n    long y;\n};"
        );
        // A gap a draft left is split about the member.
        let held = texts("struct t { int a; char gap_4[12]; };");
        let found = found_of(&[(8, 4)]);
        let merged = update_struct(DataModel::LP64, &held, "t", &found).unwrap();
        assert_eq!(
            merged.c,
            "struct t {\n    int a;\n    char gap_4[4];\n    int field_8;\n    char gap_c[4];\n};"
        );
        // Nothing new: the definitions are as they were.
        let found = found_of(&[(0, 4)]);
        let merged = update_struct(DataModel::LP64, &held, "t", &found).unwrap();
        assert!(merged.added.is_empty());
        assert_eq!(merged.definitions, held);
        // A union, or no such type, is refused.
        let held = texts("union u { int a; long b; };");
        assert_eq!(
            update_struct(DataModel::LP64, &held, "u", &found).unwrap_err(),
            "union u is no structure"
        );
        assert_eq!(
            update_struct(DataModel::LP64, &held, "v", &found).unwrap_err(),
            "no type is named v"
        );
    }

    #[test]
    fn an_update_keeps_a_packed_structures_pragma() {
        let held = texts("#pragma pack(push, 1)\nstruct p { char c; int i; };\n#pragma pack(pop)");
        let found = found_of(&[(5, 2)]);
        let merged = update_struct(DataModel::LP64, &held, "p", &found).unwrap();
        let (store, _) = crate::ctype::build(DataModel::LP64, &merged.definitions).unwrap();
        let layout = store.layout("struct p").unwrap();
        let offsets: Vec<u64> = layout.fields.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, vec![0, 1, 5]);
    }

    #[test]
    fn create_struct_adds_the_draft_and_refuses_a_name_defined() {
        let f = function(&[("a", "long")], &[], vec![ret(at("int *", var("a")))]);
        let made = drafted(&f, "a");
        let defined = create_struct(DataModel::LP64, &[], &made).unwrap();
        assert_eq!(defined.len(), 1);
        assert_eq!(defined[0].name, "struct s");
        assert_eq!(
            create_struct(DataModel::LP64, &defined, &made).unwrap_err(),
            "1:10: struct s is defined already"
        );
        assert_eq!(made.pointer(), "struct s *");
    }
}
