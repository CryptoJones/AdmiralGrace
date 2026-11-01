//! The lifted body read through the types: a variable the analyst types,
//! and the members, elements and enumerators its type makes of the bytes.
//!
//! The analyst gives a variable of the lift a type by its lift name — `a`
//! is `struct point *`, `state` is `enum state` — and the lift declares it
//! so ([`apply_var_types`]). The type must be a scalar of the variable's
//! width: a pointer, an integer, a floating type or an enumeration in a
//! register or a slot the lift reads at that width; a structure on the
//! stack is a stack variable ([`crate::stack_vars`]). A type that does not
//! fit is refused with a note: `a is not typed char: char is 1 bytes, a
//! holds 8`.
//!
//! Once the body is lifted and the analyst's other words are made, the
//! types are read into it ([`read_types`]):
//!
//! - a load or a store through a pointer to a structure or union at a
//!   constant offset, `*(int *)(p + 4)`, is the member there, `p->y`,
//!   inside nested ones, `p->inner.g`, past the first, `p[1].x`, and in
//!   an array member with an index, `p + 8 + i*4`, `p->a[i]`; through a
//!   pointer to a scalar, `*(int *)(p + 8)` is `p[2]`. A union takes its
//!   first member the bytes fit;
//! - a run of stores through such a pointer, which the lift reads as one
//!   struct initializer, is the stores to its members, `p->x = b; p->y =
//!   2;`;
//! - byte arithmetic left on a typed pointer is said in bytes, `(char *)p +
//!   6`, for C would scale it by the pointee;
//! - a constant compared with an enumeration's variable, assigned to it,
//!   masked with it, or a `switch` case on it, is its enumerator, `state ==
//!   S_READY`, `case S_DONE:` — and in an enumeration of flags, the flags
//!   that make it up, `mode & (M_READ | M_WRITE)` — where the
//!   enumeration's values spell it one way only.
//!
//! The members and enumerators are intrinsics, as an analyst's array's
//! elements are: `p->y` is `__arrow(p, "y")`, `v.f` is `__member(v, "f")`,
//! `S_READY` is `__enumerator(1, "S_READY")`, the value kept beside the
//! name. The emitter prints them as C.

use std::collections::BTreeMap;

use crate::ast::{AstNode, BinaryOp};
use crate::lift::{LiftedFunction, Statement, StatementKind};
use crate::stack_vars::StackVar;
use crate::types::{Step, Type, TypeStore};

/// The intrinsic a member of a variable reads through: `v.f` is
/// `__member(v, "f")`.
pub const MEMBER: &str = "__member";

/// The intrinsic a member through a pointer reads through: `p->f` is
/// `__arrow(p, "f")`.
pub const ARROW: &str = "__arrow";

/// The intrinsic an enumerator stands as: `S_READY` is `__enumerator(1,
/// "S_READY")`, its value beside its name. It is no call, and no memory.
pub const ENUMERATOR: &str = "__enumerator";

/// The member `field` of `base`: `base.field`, or `base->field` when
/// `arrow`.
pub fn member(base: AstNode, field: &str, arrow: bool) -> AstNode {
    AstNode::Intrinsic {
        name: if arrow { ARROW } else { MEMBER }.to_string(),
        args: vec![
            base,
            AstNode::StringLiteral {
                text: field.to_string(),
            },
        ],
    }
}

/// The base, the member and whether through a pointer, of a member
/// `base.field` or `base->field`, when the node is one.
pub fn member_of(node: &AstNode) -> Option<(&AstNode, &str, bool)> {
    match node {
        AstNode::Intrinsic { name, args } if name == MEMBER || name == ARROW => {
            match args.as_slice() {
                [base, AstNode::StringLiteral { text }] => Some((base, text, name == ARROW)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The enumerator `name` of value `value`, `width` bytes wide.
pub fn enumerator(value: u64, width: u32, name: &str) -> AstNode {
    AstNode::Intrinsic {
        name: ENUMERATOR.to_string(),
        args: vec![
            AstNode::constant(value, width),
            AstNode::StringLiteral {
                text: name.to_string(),
            },
        ],
    }
}

/// The name of an enumerator, when the node is one.
pub fn enumerator_of(node: &AstNode) -> Option<&str> {
    match node {
        AstNode::Intrinsic { name, args } if name == ENUMERATOR => match args.as_slice() {
            [_, AstNode::StringLiteral { text }] => Some(text),
            _ => None,
        },
        _ => None,
    }
}

/// Whether the intrinsic `name` is a value, not a call: an enumerator.
pub fn is_value(name: &str) -> bool {
    name == ENUMERATOR
}

/// Give the variables of `function` the analyst's types, `(variable,
/// type)` by lift name, and note the ones refused. A variable `made` on
/// the stack takes its stack variable's type.
pub(crate) fn apply_var_types(
    function: &mut LiftedFunction,
    words: &[(String, String)],
    store: &TypeStore,
    made: &[StackVar],
) {
    let mut notes = Vec::new();
    for (variable, text) in words {
        let text = text.trim();
        let refuse = |why: String| format!("{variable} is not typed {text}: {why}");
        let declares = function.name.clone();
        let Some(held) = function
            .params
            .iter_mut()
            .chain(function.locals.iter_mut())
            .find(|v| v.name == *variable)
        else {
            notes.push(refuse(format!("{declares} declares no {variable}")));
            continue;
        };
        if made
            .iter()
            .any(|m| m.name.as_deref() == Some(variable.as_str()))
        {
            notes.push(refuse(
                "it is a stack variable, which has its own type".to_string(),
            ));
            continue;
        }
        let ty = match crate::ctype::parse_type(store, text) {
            Ok(ty) => ty,
            Err(error) => {
                notes.push(refuse(error.message));
                continue;
            }
        };
        let spelled = ty.spelled(store);
        let size = match store.size_of(&ty) {
            Ok(size) => size,
            Err(why) => {
                notes.push(refuse(why));
                continue;
            }
        };
        if !store.is_scalar(&ty) {
            notes.push(refuse(format!(
                "{spelled} is no scalar: a structure, union or array on the stack is a stack variable"
            )));
            continue;
        }
        let holds = crate::ctype::parse_type(store, &held.ty)
            .ok()
            .and_then(|old| store.size_of(&old).ok());
        match holds {
            Some(holds) if holds == size => held.ty = spelled,
            Some(holds) => notes.push(refuse(format!(
                "{spelled} is {size} bytes, {variable} holds {holds}"
            ))),
            None => notes.push(refuse(format!("the size of {} is not known", held.ty))),
        }
    }
    function.notes.extend(notes);
}

/// What the types say of the function's variables: the pointee of each
/// typed pointer, and the type of each enumeration's variable.
struct Typed<'a> {
    store: &'a TypeStore,
    pointers: BTreeMap<String, Type>,
    enums: BTreeMap<String, Type>,
}

/// Read the types of the variables of `function` into its body: the
/// members and elements through its typed pointers, the enumerators of its
/// enumerations' variables.
pub(crate) fn read_types(function: &mut LiftedFunction, store: &TypeStore) {
    let mut typed = Typed {
        store,
        pointers: BTreeMap::new(),
        enums: BTreeMap::new(),
    };
    for variable in function.params.iter().chain(&function.locals) {
        let Ok(ty) = crate::ctype::parse_type(store, &variable.ty) else {
            continue;
        };
        match store.resolve(&ty) {
            Type::Pointer(pointee) => {
                typed
                    .pointers
                    .insert(variable.name.clone(), (**pointee).clone());
            }
            _ if store.enumeration(&ty).is_some() => {
                typed.enums.insert(variable.name.clone(), ty.clone());
            }
            _ => {}
        }
    }
    if typed.pointers.is_empty() && typed.enums.is_empty() {
        return;
    }
    read_statements(&mut function.body, &typed);
}

fn read_statements(statements: &mut Vec<Statement>, typed: &Typed) {
    let mut out = Vec::with_capacity(statements.len());
    for mut statement in std::mem::take(statements) {
        if let Some(stores) = initializer_stores(&statement, typed) {
            out.extend(stores);
            continue;
        }
        statement.node = read_node(
            std::mem::replace(&mut statement.node, AstNode::Break),
            typed,
        );
        if let StatementKind::For { init, step, .. } = &mut statement.kind {
            init.node = read_node(std::mem::replace(&mut init.node, AstNode::Break), typed);
            step.node = read_node(std::mem::replace(&mut step.node, AstNode::Break), typed);
        }
        if let StatementKind::Switch { arms } = &mut statement.kind {
            if let Some(ty) = enum_var(&statement.node, typed) {
                for arm in arms.iter_mut() {
                    arm.labels = arm
                        .values
                        .iter()
                        .map(|value| match typed.store.enumerators_of(ty, *value) {
                            Some(names) if names.len() == 1 => names[0].clone(),
                            _ => value.to_string(),
                        })
                        .collect();
                }
            }
        }
        for child in statement.children_mut() {
            read_statements(child, typed);
        }
        out.push(statement);
    }
    *statements = out;
}

/// The stores a struct initializer through a typed pointer stands for,
/// each to its member, when every field is a member's.
fn initializer_stores(statement: &Statement, typed: &Typed) -> Option<Vec<Statement>> {
    let AstNode::Assign { lhs, rhs } = &statement.node else {
        return None;
    };
    let (AstNode::Deref { target }, AstNode::StructInit { fields }) = (lhs.as_ref(), rhs.as_ref())
    else {
        return None;
    };
    let AstNode::Cast { target: base, .. } = target.as_ref() else {
        return None;
    };
    let (pointer, offset, index) = decompose(base, typed)?;
    if index.is_some() {
        return None;
    }
    let mut stores = Vec::new();
    for field in fields {
        let ty = crate::ctype::parse_type(typed.store, &field.ty).ok()?;
        let size = typed.store.size_of(&ty).ok()?;
        let at = offset.checked_add(i64::try_from(field.offset).ok()?)?;
        let target = through(&pointer, at, size, None, typed)?;
        stores.push(Statement::plain(
            AstNode::Assign {
                lhs: Box::new(target),
                rhs: Box::new(read_node(field.value.clone(), typed)),
            },
            statement.addresses.clone(),
        ));
    }
    Some(stores)
}

/// `node` with the types read into it, innermost first.
fn read_node(node: AstNode, typed: &Typed) -> AstNode {
    let read = crate::inline::map(node, &mut |n| read_one(n, typed));
    // What is left of byte arithmetic on a typed pointer is said in bytes.
    crate::inline::map(read, &mut |n| match n {
        AstNode::Binary {
            lhs,
            op: op @ (BinaryOp::Add | BinaryOp::Sub),
            rhs,
        } => match lhs.as_ref() {
            AstNode::Var { name } if scales(name, typed) => AstNode::Binary {
                lhs: Box::new(AstNode::Cast {
                    ty: "char *".to_string(),
                    target: lhs,
                }),
                op,
                rhs,
            },
            _ => AstNode::Binary { lhs, op, rhs },
        },
        other => other,
    })
}

/// Whether arithmetic on the pointer `name` would scale: its pointee is
/// not one byte.
fn scales(name: &str, typed: &Typed) -> bool {
    typed
        .pointers
        .get(name)
        .is_some_and(|pointee| typed.store.size_of(pointee).ok() != Some(1))
}

fn read_one(node: AstNode, typed: &Typed) -> AstNode {
    match node {
        AstNode::Deref { target } => {
            if let AstNode::Cast {
                ty,
                target: address,
            } = target.as_ref()
            {
                if let Some(read) = load(ty, address, typed) {
                    return read;
                }
            }
            AstNode::Deref { target }
        }
        AstNode::Binary { lhs, op, rhs } => {
            let flags = matches!(op, BinaryOp::And | BinaryOp::Or | BinaryOp::Xor);
            if matches!(op, BinaryOp::Equal | BinaryOp::NotEqual) || flags {
                if let Some(ty) = enum_side(&lhs, typed) {
                    if let Some(named) = spelled_constant(&rhs, ty, typed) {
                        return AstNode::Binary {
                            lhs,
                            op,
                            rhs: Box::new(named),
                        };
                    }
                }
                if let Some(ty) = enum_side(&rhs, typed) {
                    if let Some(named) = spelled_constant(&lhs, ty, typed) {
                        return AstNode::Binary {
                            lhs: Box::new(named),
                            op,
                            rhs,
                        };
                    }
                }
            }
            AstNode::Binary { lhs, op, rhs }
        }
        AstNode::Assign { lhs, rhs } => {
            if let AstNode::Var { name } = lhs.as_ref() {
                if let Some(ty) = typed.enums.get(name) {
                    if let Some(named) = spelled_constant(&rhs, ty, typed) {
                        return AstNode::Assign {
                            lhs,
                            rhs: Box::new(named),
                        };
                    }
                }
            }
            AstNode::Assign { lhs, rhs }
        }
        other => other,
    }
}

/// The enumeration of the variable a side of an operation is, under its
/// casts — or of a mask of one, `state & 3`.
fn enum_side<'a>(node: &AstNode, typed: &'a Typed) -> Option<&'a Type> {
    match crate::slice::strip_casts(node) {
        AstNode::Var { name } => typed.enums.get(name),
        AstNode::Binary {
            lhs,
            op: BinaryOp::And | BinaryOp::Or,
            ..
        } => enum_side(lhs, typed),
        _ => None,
    }
}

/// The enumeration a switch's index is the variable of, under its casts.
fn enum_var<'a>(node: &AstNode, typed: &'a Typed) -> Option<&'a Type> {
    match crate::slice::strip_casts(node) {
        AstNode::Var { name } => typed.enums.get(name),
        _ => None,
    }
}

/// A constant of the enumeration `ty` spelled by its enumerators — one,
/// or the flags that make it up — when one spelling is unambiguous.
fn spelled_constant(node: &AstNode, ty: &Type, typed: &Typed) -> Option<AstNode> {
    let AstNode::Constant { value, width_bytes } = node else {
        return None;
    };
    let width = *width_bytes;
    let signed = sign_extended(*value, width);
    let names = typed
        .store
        .enumerators_of(ty, signed)
        .or_else(|| typed.store.enumerators_of(ty, *value as i64))?;
    let (_, enumeration) = typed.store.enumeration(ty)?;
    let value_of = |name: &str| {
        enumeration
            .values
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, v)| *v as u64)
    };
    let mut nodes = names
        .iter()
        .map(|name| enumerator(value_of(name), width, name));
    let first = nodes.next()?;
    Some(nodes.fold(first, |acc, next| AstNode::binary(acc, BinaryOp::Or, next)))
}

fn sign_extended(value: u64, width: u32) -> i64 {
    match width {
        1 => value as u8 as i8 as i64,
        2 => value as u16 as i16 as i64,
        4 => value as u32 as i32 as i64,
        _ => value as i64,
    }
}

/// A load or store `*(ty)address` read through a typed pointer: the
/// member or element the bytes are.
fn load(ty: &str, address: &AstNode, typed: &Typed) -> Option<AstNode> {
    let access = match crate::ctype::parse_type(typed.store, ty).ok()? {
        Type::Pointer(pointee) => *pointee,
        _ => return None,
    };
    let size = typed.store.size_of(&access).ok()?;
    let (pointer, offset, index) = decompose(address, typed)?;
    through(&pointer, offset, size, index, typed)
}

/// The `size` bytes `offset` past the typed pointer `pointer` — and `index`
/// elements of `scale` bytes on, when there is an index — as the member or
/// element they are.
fn through(
    pointer: &str,
    offset: i64,
    size: u64,
    index: Option<(AstNode, u64)>,
    typed: &Typed,
) -> Option<AstNode> {
    let pointee = typed.pointers.get(pointer)?;
    let store = typed.store;
    let each = store.size_of(pointee).ok().filter(|&each| each > 0)?;
    let offset = u64::try_from(offset).ok()?;
    let base = AstNode::var(pointer);
    let element = offset / each;
    let within = offset % each;
    match index {
        // `p[i]`, or `p[i + k]`, of the pointee's own size.
        Some((index, scale)) if scale == each => {
            let index = plus(index, element);
            let (path, _) = store.field_at(pointee, within, size)?;
            Some(crate::stack_vars::parts_node(
                AstNode::Intrinsic {
                    name: crate::stack_vars::INDEX.to_string(),
                    args: vec![base, index],
                },
                &path,
            ))
        }
        // An array member indexed: `p->a[i]`.
        Some((index, scale)) => {
            if element != 0 {
                return None;
            }
            let (_, layout, _) = store.composite(pointee)?;
            let field = layout.fields.iter().find(|field| {
                field.bits.is_none()
                    && field.name.is_some()
                    && field.offset <= within
                    && within < field.offset + field.size.max(1)
            })?;
            let Type::Array(item, _) = store.resolve(&field.ty) else {
                return None;
            };
            if store.size_of(item).ok()? != scale {
                return None;
            }
            let into = within - field.offset;
            let (path, _) = store.field_at(item, into % scale, size)?;
            let array = member(base, field.name.as_deref()?, true);
            let indexed = AstNode::Intrinsic {
                name: crate::stack_vars::INDEX.to_string(),
                args: vec![array, plus(index, into / scale)],
            };
            Some(crate::stack_vars::parts_node(indexed, &path))
        }
        None => {
            let (path, leaf) = store.field_at(pointee, within, size)?;
            if matches!(store.resolve(&leaf), Type::Array(..)) {
                return None;
            }
            if element == 0 {
                return Some(match path.split_first() {
                    // The whole pointee: `*p`.
                    None => AstNode::Deref {
                        target: Box::new(base),
                    },
                    Some((Step::Field(name), rest)) => {
                        crate::stack_vars::parts_node(member(base, name, true), rest)
                    }
                    Some((Step::Index(_), _)) => {
                        let first = AstNode::Intrinsic {
                            name: crate::stack_vars::INDEX.to_string(),
                            args: vec![base, AstNode::constant(0, 8)],
                        };
                        crate::stack_vars::parts_node(first, &path)
                    }
                });
            }
            let indexed = AstNode::Intrinsic {
                name: crate::stack_vars::INDEX.to_string(),
                args: vec![base, AstNode::constant(element, 8)],
            };
            Some(crate::stack_vars::parts_node(indexed, &path))
        }
    }
}

/// `index + k`, or `index` when `k` is 0.
fn plus(index: AstNode, k: u64) -> AstNode {
    if k == 0 {
        index
    } else {
        AstNode::binary(index, BinaryOp::Add, AstNode::constant(k, 8))
    }
}

/// A typed pointer, a constant offset in bytes, and an index with its
/// scale.
type Address = (String, i64, Option<(AstNode, u64)>);

/// An address as a typed pointer, a constant offset in bytes, and an index
/// with its scale, `p + 8 + i*4`, when it is one.
fn decompose(address: &AstNode, typed: &Typed) -> Option<Address> {
    let mut terms = Vec::new();
    flatten(address, false, &mut terms)?;
    let mut pointer = None;
    let mut offset: i64 = 0;
    let mut index = None;
    for (negative, term) in terms {
        match term {
            AstNode::Var { name } if !negative && typed.pointers.contains_key(name) => {
                if pointer.replace(name.clone()).is_some() {
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
            AstNode::Binary {
                lhs,
                op: BinaryOp::Mul,
                rhs,
            } if !negative => {
                let (by, scale) = match (lhs.as_ref(), rhs.as_ref()) {
                    (by, AstNode::Constant { value, .. }) => (by, *value),
                    (AstNode::Constant { value, .. }, by) => (by, *value),
                    _ => return None,
                };
                if index.replace((by.clone(), scale)).is_some() {
                    return None;
                }
            }
            AstNode::Binary {
                lhs,
                op: BinaryOp::Shl,
                rhs,
            } if !negative => {
                let AstNode::Constant { value, .. } = rhs.as_ref() else {
                    return None;
                };
                let scale = 1u64.checked_shl(u32::try_from(*value).ok()?)?;
                if index.replace(((**lhs).clone(), scale)).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some((pointer?, offset, index))
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::arch::Bitness;
    use crate::cfgwalk::{resolve_branches_among, NoEntries};
    use crate::cpu_context::X86IcedContext;
    use crate::emit::emit_function;
    use crate::lift::{lift_stages, Abi, Symbols};
    use crate::merge::VariableEdits;
    use crate::options::Options;
    use crate::pipeline::Disasm;
    use crate::stack_vars::StackVar;
    use crate::types::{DataModel, TypeStore};

    const BASE: u64 = 0x1000;

    /// The analyst's types, stack variables and variable types, as the
    /// image would give them.
    struct World {
        types: Arc<TypeStore>,
        stack_vars: Vec<StackVar>,
        var_types: Vec<(String, String)>,
    }

    impl Symbols for World {
        fn function_name(&self, _address: u64) -> Option<String> {
            None
        }

        fn variable_edits(&self, _address: u64) -> VariableEdits {
            VariableEdits {
                stack_vars: self.stack_vars.clone(),
                var_types: self.var_types.clone(),
                ..VariableEdits::default()
            }
        }

        fn types(&self) -> Option<Arc<TypeStore>> {
            Some(self.types.clone())
        }
    }

    const TYPES: &str = "struct pair { int a; int b; };\n\
        struct inner { int g; };\n\
        struct item { int f; };\n\
        struct outer { int id; struct inner in; struct item a[2]; };\n\
        union word { int i; float f; };\n\
        struct point { int x; int y; long tag; };\n\
        struct counts { long n; int a[4]; };\n\
        enum state { S_IDLE, S_READY, S_DONE };\n\
        enum mode { M_READ = 1, M_WRITE = 2, M_EXEC = 4 };";

    /// The pseudocode of `bytes` lifted as `f` under `TYPES`, with the
    /// analyst's stack variables and variable types, without the comment
    /// saying what decided the return type.
    fn c(
        bytes: &[u8],
        stack_vars: &[(i64, u32, &str, &str)],
        var_types: &[(&str, &str)],
    ) -> String {
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(&mut store, TYPES).unwrap();
        let world = World {
            types: Arc::new(store),
            stack_vars: stack_vars
                .iter()
                .map(|(offset, size, name, ty)| StackVar {
                    offset: *offset,
                    size: *size,
                    name: Some(name.to_string()),
                    ty: Some(ty.to_string()),
                })
                .collect(),
            var_types: var_types
                .iter()
                .map(|(v, t)| (v.to_string(), t.to_string()))
                .collect(),
        };
        let mut ctx = X86IcedContext::default();
        let disasm = Disasm::decode(&mut ctx, bytes, BASE).expect("the code decodes");
        let cfg = resolve_branches_among(&disasm, BASE, &NoEntries);
        let stages = lift_stages(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits64,
            Abi::SystemV,
            &world,
            &Options::default(),
        )
        .expect("the code lifts");
        emit_function(&stages.function, &Options::default())
            .lines
            .iter()
            .map(|line| line.text.as_str())
            .filter(|text| !(text.starts_with("// void: ") || text.starts_with("// returns ")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// push rbp; mov rbp, rsp; mov dword [rbp-0x10], 1; mov dword
    /// [rbp-0xc], 2; mov eax, [rbp-0x10]; add eax, [rbp-0xc]; pop rbp; ret
    const PAIR: [u8; 26] = [
        0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xf0, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf4, 0x02,
        0x00, 0x00, 0x00, 0x8b, 0x45, 0xf0, 0x03, 0x45, 0xf4, 0x5d, 0xc3,
    ];

    #[test]
    fn a_stack_variable_of_a_structure_reads_its_members() {
        assert_eq!(
            c(&PAIR, &[(-0x18, 8, "p", "struct pair")], &[]),
            "int f(void)\n{\n  struct pair p;\n\n  p.a = 1;\n  p.b = 2;\n  return p.a + p.b;\n}"
        );
        // push rbp; mov rbp, rsp; mov dword [rbp-0x10], 1; mov dword
        // [rbp-0xc], 2; mov dword [rbp-8], 3; mov eax, [rbp-4]; pop rbp; ret
        let nested = [
            0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xf0, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf4,
            0x02, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xfc,
            0x5d, 0xc3,
        ];
        assert_eq!(
            c(&nested, &[(-0x18, 16, "v", "struct outer")], &[]),
            "int f(void)\n{\n  struct outer v;\n\n  v.id = 1;\n  v.in.g = 2;\n  v.a[0].f = 3;\n  return v.a[1].f;\n}"
        );
        // A union reads its first member the bytes fit.
        let one = [
            0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xf0,
            0x5d, 0xc3,
        ];
        assert_eq!(
            c(&one, &[(-0x18, 4, "w", "union word")], &[]),
            "int f(void)\n{\n  union word w;\n\n  w.i = 1;\n  return w.i;\n}"
        );
        // An array of structures by element and member.
        assert_eq!(
            c(&PAIR, &[(-0x18, 8, "items", "struct item[2]")], &[]),
            "int f(void)\n{\n  struct item items[2];\n\n  items[0].f = 1;\n  items[1].f = 2;\n  return items[0].f + items[1].f;\n}"
        );
    }

    #[test]
    fn a_load_through_a_typed_pointer_is_its_member() {
        // mov eax, [rdi+4]; ret
        assert_eq!(
            c(&[0x8b, 0x47, 0x04, 0xc3], &[], &[("a", "struct point *")]),
            "int f(struct point *a)\n{\n  return a->y;\n}"
        );
        // mov eax, [rdi+0x14]; ret: past the first.
        assert_eq!(
            c(&[0x8b, 0x47, 0x14, 0xc3], &[], &[("a", "struct point *")]),
            "int f(struct point *a)\n{\n  return a[1].y;\n}"
        );
        // mov eax, [rdi+rsi*4+8]; ret: an array member indexed.
        assert_eq!(
            c(
                &[0x8b, 0x44, 0xb7, 0x08, 0xc3],
                &[],
                &[("a", "struct counts *")]
            ),
            "int f(struct counts *a, long b)\n{\n  return a->a[b];\n}"
        );
        // Through a pointer to a scalar: an element.
        assert_eq!(
            c(&[0x8b, 0x47, 0x08, 0xc3], &[], &[("a", "int *")]),
            "int f(int *a)\n{\n  return a[2];\n}"
        );
        // lea rax, [rdi+6]; ret: bytes on, said in bytes.
        assert_eq!(
            c(
                &[0x48, 0x8d, 0x47, 0x06, 0xc3],
                &[],
                &[("a", "struct point *")]
            ),
            "long f(struct point *a)\n{\n  return (char *)a + 6;\n}"
        );
    }

    #[test]
    fn a_run_of_stores_through_a_typed_pointer_is_its_members() {
        // mov [rdi], esi; mov dword [rdi+4], 2; mov qword [rdi+8], 7; ret
        let code = [
            0x89, 0x37, 0xc7, 0x47, 0x04, 0x02, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x47, 0x08, 0x07,
            0x00, 0x00, 0x00, 0xc3,
        ];
        assert_eq!(
            c(&code, &[], &[("a", "struct point *")]),
            "void f(struct point *a, int b)\n{\n  a->x = b;\n  a->y = 2;\n  a->tag = 7;\n  return;\n}"
        );
    }

    #[test]
    fn an_enumerations_constants_are_its_enumerators() {
        // cmp edi, 1; jne +6; mov eax, 10; ret; mov eax, 20; ret
        let code = [
            0x83, 0xff, 0x01, 0x75, 0x06, 0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x14, 0x00,
            0x00, 0x00, 0xc3,
        ];
        let text = c(&code, &[], &[("a", "enum state")]);
        assert!(text.starts_with("int f(enum state a)"), "{text}");
        assert!(
            text.contains("a == S_READY") || text.contains("a != S_READY"),
            "{text}"
        );
        // and edi, 5; cmp edi, 5; jne +6; mov eax, 1; ret; xor eax, eax; ret
        let flags = [
            0x83, 0xe7, 0x05, 0x83, 0xff, 0x05, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
            0x31, 0xc0, 0xc3,
        ];
        let text = c(&flags, &[], &[("a", "enum mode")]);
        assert!(text.contains("M_READ | M_EXEC"), "{text}");
        assert!(!text.contains('5'), "{text}");
        // An enumeration whose values do not spell 5 keeps the number.
        let text = c(&flags, &[], &[("a", "enum state")]);
        assert!(text.contains('5'), "{text}");
    }

    #[test]
    fn a_type_that_does_not_fit_is_refused_with_a_note() {
        let code = [0x8b, 0x47, 0x04, 0xc3];
        let text = c(
            &code,
            &[],
            &[
                ("a", "int"),
                ("a", "struct point"),
                ("zz", "int"),
                ("a", "struct nowhere *"),
            ],
        );
        assert!(
            text.contains("// a is not typed int: int is 4 bytes, a holds 8"),
            "{text}"
        );
        assert!(
            text.contains(
                "// a is not typed struct point: struct point is no scalar: a structure, union or array on the stack is a stack variable"
            ),
            "{text}"
        );
        assert!(
            text.contains("// zz is not typed int: f declares no zz"),
            "{text}"
        );
        // A pointer to a structure the types do not define is a pointer.
        assert!(text.contains("int f(struct nowhere *a)"), "{text}");
        assert!(text.contains("return *(int *)((char *)a + 4);"), "{text}");
    }
}
