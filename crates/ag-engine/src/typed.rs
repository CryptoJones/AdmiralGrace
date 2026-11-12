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

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{AstNode, BinaryOp};
use crate::lift::{LiftedFunction, Statement, StatementKind};
use crate::stack_vars::StackVar;
use crate::types::{Prim, Step, Type, TypeStore};

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

/// A bit-field read: [`member`] with the bit-field's first bit and
/// width beside the name — `__bits_arrow(p, "flags", 0, 3)` for a
/// three-bit field at bit 0. The emitter prints the plain member,
/// `p->flags`, in C: the value a bit-field is read as is the field
/// itself, and what shifts it into place is the machine's; the typed
/// medium keeps the expression.
/// The member `field` of `base`, a bit-field of `bits` bits at bit
/// `bit_offset`: `base.field` read as `(unit >> off) & mask`, or
/// `base->field` when `arrow`.
pub fn bits_member(base: AstNode, field: &str, bit_offset: u32, bits: u32, arrow: bool) -> AstNode {
    AstNode::Intrinsic {
        name: if arrow {
            crate::fragments::BITS_ARROW
        } else {
            crate::fragments::BITS_MEMBER
        }
        .to_string(),
        args: vec![
            base,
            AstNode::StringLiteral {
                text: field.to_string(),
            },
            AstNode::constant(u64::from(bit_offset), 8),
            AstNode::constant(u64::from(bits), 8),
        ],
    }
}

/// The base, the member, its first bit and its width, and whether
/// through a pointer, of a bit-field `base.field` or `base->field`,
/// when the node is one.
pub fn bits_member_of(node: &AstNode) -> Option<(&AstNode, &str, u32, u32, bool)> {
    match node {
        AstNode::Intrinsic { name, args }
            if name == crate::fragments::BITS_MEMBER || name == crate::fragments::BITS_ARROW =>
        {
            let (arrow, rest) = match name.as_str() {
                m if m == crate::fragments::BITS_ARROW => (true, args.as_slice()),
                _ => (false, args.as_slice()),
            };
            match rest {
                [
                    base,
                    AstNode::StringLiteral { text },
                    AstNode::Constant { value: bit_offset, .. },
                    AstNode::Constant { value: bits, .. },
                ] => Some((
                    base,
                    text.as_str(),
                    u32::try_from(*bit_offset).ok()?,
                    u32::try_from(*bits).ok()?,
                    arrow,
                )),
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

/// Whether the intrinsic `name` is a value, not a call: an enumerator,
/// or the bytes of several members annotated.
pub fn is_value(name: &str) -> bool {
    name == ENUMERATOR || name == crate::fragments::FRAGMENT
}

/// Give the variables of `function` the analyst's types, `(variable,
/// type)` by lift name, and note the ones refused. A variable `made` on
/// the stack takes its stack variable's type.
pub(crate) fn apply_var_types(
    function: &mut LiftedFunction,
    words: &[(String, String)],
    store: &TypeStore,
    made: &[StackVar],
    abi: crate::lift::Abi,
) {
    let mut notes = Vec::new();
    for (variable, text) in words {
        let text = text.trim();
        let refuse = |why: String| format!("{variable} is not typed {text}: {why}");
        let declares = function.name.clone();
        // The value the function returns, which its callers read.
        if variable == RETURN {
            if let Err(why) = return_type(store, text, abi) {
                notes.push(format!("the return is not typed {text}: {why}"));
            }
            continue;
        }
        // A structure passed by value, in its registers.
        if let Some(index) = function.params.iter().position(|v| v.name == *variable) {
            if let Ok(ty) = crate::ctype::parse_type(store, text) {
                if store.composite(&ty).is_some() {
                    if let Some(note) = by_value(function, index, &ty, store, abi) {
                        notes.push(refuse(note));
                    }
                    continue;
                }
            }
        }
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
            Some(holds) if holds == size => {
                held.ty = spelled;
                // A structure said of the variable before is said no more.
                if held.fragment.take().is_some() {
                    for param in &mut function.params {
                        if param.fragment.as_ref().and_then(|f| f.within.as_deref())
                            == Some(variable.as_str())
                        {
                            param.fragment = None;
                        }
                    }
                }
            }
            Some(holds) => notes.push(refuse(format!(
                "{spelled} is {size} bytes, {variable} holds {holds}"
            ))),
            None => notes.push(refuse(format!("the size of {} is not known", held.ty))),
        }
    }
    function.notes.extend(notes);
}

/// The name a function's returned value is typed by in `var_types`: a C
/// keyword, so no variable's.
pub const RETURN: &str = "return";

/// The structure `text` a function returns, as its callers read it: in
/// `rax`, at most eight bytes of it — under System V and Go a structure of
/// the INTEGER class, under Microsoft x64 one of 1, 2, 4 or 8 bytes, under
/// Pascal one that fits a register.
pub(crate) fn return_type(
    store: &TypeStore,
    text: &str,
    abi: crate::lift::Abi,
) -> Result<Type, String> {
    let ty = crate::ctype::parse_type(store, text).map_err(|error| error.message)?;
    let spelled = ty.spelled(store);
    if store.composite(&ty).is_none() {
        return Err(format!(
            "only a structure or union is read at the calls, and {spelled} is neither"
        ));
    }
    let size = match abi {
        crate::lift::Abi::SystemV => store.integer_class(&ty, "System V")?,
        crate::lift::Abi::Go => store.integer_class(&ty, "Go")?,
        crate::lift::Abi::Win64 => {
            let size = store.size_of(&ty)?;
            if !matches!(size, 1 | 2 | 4 | 8) {
                return Err(format!(
                    "Microsoft x64 returns {spelled}, of {size} bytes, through memory the caller passes"
                ));
            }
            size
        }
        crate::lift::Abi::Pascal => {
            let size = store.size_of(&ty)?;
            if size > 8 {
                return Err(format!(
                    "Pascal returns {spelled}, of {size} bytes, through memory the caller passes"
                ));
            }
            size
        }
    };
    if size > 8 {
        return Err(format!(
            "{spelled} is {size} bytes, returned in rax and rdx, and the calls read rax alone"
        ));
    }
    Ok(ty)
}

/// The structure `ty` passed by value in the parameter `index`: in its
/// registers as the convention passes it, or — under Microsoft x64, for a
/// size other than 1, 2, 4 or 8 bytes — by its address, the parameter a
/// pointer to it. Why it is not, when it is not.
fn by_value(
    function: &mut LiftedFunction,
    index: usize,
    ty: &Type,
    store: &TypeStore,
    abi: crate::lift::Abi,
) -> Option<String> {
    let spelled = ty.spelled(store);
    match abi {
        crate::lift::Abi::SystemV => {
            if let Err(why) = store.integer_class(ty, "System V") {
                return Some(why);
            }
        }
        crate::lift::Abi::Go => {
            if let Err(why) = store.integer_class(ty, "Go") {
                return Some(why);
            }
        }
        crate::lift::Abi::Win64 => {
            let size = match store.size_of(ty) {
                Ok(size) => size,
                Err(why) => return Some(why),
            };
            if !matches!(size, 1 | 2 | 4 | 8) {
                let param = &mut function.params[index];
                param.ty = Type::pointer(ty.clone()).spelled(store);
                function.notes.push(format!(
                    "{} is {}: Microsoft x64 passes {spelled}, of {size} bytes, by its address",
                    param.name, param.ty
                ));
                return None;
            }
        }
        crate::lift::Abi::Pascal => {
            // The Borland register convention passes a structure that fits
            // one register in it; a larger one goes on the stack, which the
            // lift does not read as a parameter.
            let size = match store.size_of(ty) {
                Ok(size) => size,
                Err(why) => return Some(why),
            };
            if size > 8 {
                return Some(format!(
                    "Pascal passes {spelled}, of {size} bytes, on the stack"
                ));
            }
        }
    }
    let registers = crate::fragments::argument_registers(abi);
    crate::fragments::pass_by_value(function, index, ty, store, registers).err()
}

/// What the types say of the function's variables: the pointee of each
/// typed pointer, and the type of each enumeration's variable.
struct Typed<'a> {
    store: &'a TypeStore,
    pointers: BTreeMap<String, Type>,
    enums: BTreeMap<String, Type>,
    /// The member of a union each instruction's access means, by the
    /// address of each instruction that said ([`crate::types::TypeStore::field_at_chosen`]).
    union_fields: &'a BTreeMap<u64, String>,
    /// The enumeration a constant in each instruction's operands is shown
    /// as a member of, by the address of each instruction that said.
    constant_enums: &'a BTreeMap<u64, String>,
}

/// Read the types of the variables of `function` into its body: the
/// members and elements through its typed pointers, the enumerators of its
/// enumerations' variables, and the fragments of structures its values and
/// variables hold ([`crate::fragments`]) — `returns` the structures the
/// functions it calls return, by address. A variable a fragment gives a
/// pointer's or an enumeration's type is read through it in turn.
/// `union_fields` is the analyst's word on which member of a union each
/// instruction's access means, by the address of each instruction that
/// said. `constant_enums` is the enumeration a constant in each
/// instruction's operands is shown as a member of, by address.
pub(crate) fn read_types(
    function: &mut LiftedFunction,
    store: &TypeStore,
    returns: &BTreeMap<u64, Type>,
    union_fields: &BTreeMap<u64, String>,
    constant_enums: &BTreeMap<u64, String>,
) {
    for _ in 0..3 {
        read_pointers(function, store, union_fields, constant_enums);
        if !crate::fragments::read(function, store, returns, union_fields) {
            break;
        }
    }
}

/// The members, elements and enumerators the typed pointers and
/// enumerations of `function` make of its body.
fn read_pointers(
    function: &mut LiftedFunction,
    store: &TypeStore,
    union_fields: &BTreeMap<u64, String>,
    constant_enums: &BTreeMap<u64, String>,
) {
    let mut typed = Typed {
        store,
        pointers: BTreeMap::new(),
        enums: BTreeMap::new(),
        union_fields,
        constant_enums,
    };
    for variable in function.params.iter().chain(&function.locals) {
        let Ok(ty) = crate::ctype::parse_type(store, &variable.ty) else {
            continue;
        };
        match store.resolve(&ty) {
            // A `void *` says nothing of what it points at: its loads and
            // its arithmetic stay as the lift reads them.
            Type::Pointer(pointee) if matches!(store.resolve(pointee), Type::Prim(Prim::Void)) => {}
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
    if typed.pointers.is_empty() && typed.enums.is_empty() && typed.constant_enums.is_empty() {
        return;
    }
    read_statements(&mut function.body, &typed);
}

fn read_statements(statements: &mut Vec<Statement>, typed: &Typed) {
    let mut out = Vec::with_capacity(statements.len());
    for mut statement in std::mem::take(statements) {
        let chosen = typed.chosen_at(&statement.addresses);
        let constant_enum = typed.constant_enum_at(&statement.addresses);
        if let Some(stores) = initializer_stores(&statement, typed, chosen) {
            out.extend(stores);
            continue;
        }
        statement.node = read_node(
            std::mem::replace(&mut statement.node, AstNode::Break),
            typed,
            chosen,
            constant_enum,
        );
        if let StatementKind::For { init, step, .. } = &mut statement.kind {
            init.node = read_node(
                std::mem::replace(&mut init.node, AstNode::Break),
                typed,
                chosen,
                constant_enum,
            );
            step.node = read_node(
                std::mem::replace(&mut step.node, AstNode::Break),
                typed,
                chosen,
                constant_enum,
            );
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

impl Typed<'_> {
    /// The member the analyst said the union access at one of the
    /// statement's instructions means: the word at the first of them that
    /// carries one.
    fn chosen_at(&self, addresses: &[u64]) -> Option<&str> {
        addresses
            .iter()
            .find_map(|address| self.union_fields.get(address))
            .map(String::as_str)
    }

    /// The enumeration the analyst said a constant at one of the
    /// statement's instructions is shown as a member of: the word at the
    /// first of them that carries one.
    fn constant_enum_at(&self, addresses: &[u64]) -> Option<&str> {
        addresses
            .iter()
            .find_map(|address| self.constant_enums.get(address))
            .map(String::as_str)
    }
}

/// The stores a struct initializer through a typed pointer stands for,
/// each to its member, when every field is a member's.
fn initializer_stores(
    statement: &Statement,
    typed: &Typed,
    chosen: Option<&str>,
) -> Option<Vec<Statement>> {
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
        let target = through(&pointer, at, size, None, typed, chosen)?;
        stores.push(Statement::plain(
            AstNode::Assign {
                lhs: Box::new(target),
                rhs: Box::new(read_node(field.value.clone(), typed, chosen, None)),
            },
            statement.addresses.clone(),
        ));
    }
    Some(stores)
}

/// `node` with the types read into it, innermost first. `chosen` is the
/// member the analyst said the union access at the statement means.
/// `constant_enum` is the enumeration a constant at the statement is shown
/// as a member of.
fn read_node(node: AstNode, typed: &Typed, chosen: Option<&str>, constant_enum: Option<&str>) -> AstNode {
    let read = crate::inline::map(node, &mut |n| read_one(n, typed, chosen, constant_enum));
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

fn read_one(node: AstNode, typed: &Typed, chosen: Option<&str>, constant_enum: Option<&str>) -> AstNode {
    match node {
        // A constant the analyst said is shown as a member of an
        // enumeration, when the enumeration has a member of that value.
        AstNode::Constant { .. } => {
            if let Some(key) = constant_enum {
                let ty = Type::Named(key.to_string());
                if let Some(named) = spelled_constant(&node, &ty, typed) {
                    return named;
                }
            }
            node
        }
        AstNode::Deref { target } => {
            if let AstNode::Cast {
                ty,
                target: address,
            } = target.as_ref()
            {
                if let Some(read) = load(ty, address, typed, chosen) {
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

/// One use of a type, or of one of its members or enumerators.
///
/// A use in code is a variable's type, the function's return, or a member
/// or enumerator the pseudocode reads — `__member`, `__arrow` (and the
/// bit-field forms) and `__enumerator`. A use in the types themselves is
/// another definition naming this one: a member's type, a typedef's
/// target, a base class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeUse {
    /// The definition: `struct point`, `enum state`.
    pub key: String,
    /// The member or enumerator, empty when the use is of the type itself.
    pub member: String,
    /// `variable`, `return`, `member`, `arrow`, `enumerator` or `definition`.
    pub kind: &'static str,
    /// The function the use is in; `0` for a use in another definition.
    pub function: u64,
    /// The instruction the use came from, when the statement has one.
    pub at: Option<u64>,
    /// The function's name, empty for a use in another definition.
    pub function_name: String,
    /// The variable, or where another definition names this type.
    pub detail: String,
}

/// The uses of types in `function`: its variables' and return's types, and
/// the members and enumerators its body reads.
///
/// `returns` is the return type of each function by the name a call prints,
/// so `make().y` is a use of that member. A name the store does not define
/// is left out, and so is an anonymous definition.
pub fn cross_references(
    function: &LiftedFunction,
    store: &TypeStore,
    returns: &BTreeMap<String, Type>,
) -> Vec<TypeUse> {
    let mut uses = BTreeSet::new();
    let mut vars = BTreeMap::new();
    for variable in function.params.iter().chain(function.locals.iter()) {
        let Some(text) = shown_type(variable, &function.params) else {
            continue;
        };
        if let Ok(ty) = crate::ctype::parse_type(store, text) {
            note_type(
                store,
                &ty,
                "variable",
                function,
                None,
                &variable.name,
                &mut uses,
            );
            vars.insert(variable.name.clone(), ty);
        }
    }
    if let Ok(ty) = crate::ctype::parse_type(store, &function.return_type) {
        note_type(store, &ty, "return", function, None, "", &mut uses);
    }
    walk_statements(&function.body, function, store, &vars, returns, &mut uses);
    uses.into_iter().collect()
}

/// Where the store's definitions name one another.
pub fn definition_uses(store: &TypeStore) -> Vec<TypeUse> {
    let mut uses = BTreeSet::new();
    for owner in store.names() {
        let Some(definition) = store.get(owner) else {
            continue;
        };
        match definition {
            crate::types::Definition::Struct(composite)
            | crate::types::Definition::Union(composite) => {
                if let Some(members) = &composite.members {
                    for member in members {
                        let detail = match &member.name {
                            Some(name) => format!("{name} of {owner}"),
                            None => format!("a member of {owner}"),
                        };
                        note_names(
                            store,
                            &member.ty,
                            UseSite {
                                kind: "definition",
                                function: 0,
                                at: None,
                                function_name: "",
                                detail: &detail,
                            },
                            &mut uses,
                        );
                    }
                }
                for method in &composite.methods {
                    let detail = format!("{} of {owner}", method.name);
                    note_names(
                        store,
                        &method.ty,
                        UseSite {
                            kind: "definition",
                            function: 0,
                            at: None,
                            function_name: "",
                            detail: &detail,
                        },
                        &mut uses,
                    );
                }
                for base in &composite.base_classes {
                    if store.get(base).is_some() && !store.is_anonymous(base) {
                        uses.insert(TypeUse {
                            key: base.clone(),
                            member: String::new(),
                            kind: "definition",
                            function: 0,
                            at: None,
                            function_name: String::new(),
                            detail: format!("base of {owner}"),
                        });
                    }
                }
            }
            crate::types::Definition::Typedef(target) => {
                let detail = format!("typedef {owner}");
                note_names(
                    store,
                    target,
                    UseSite {
                        kind: "definition",
                        function: 0,
                        at: None,
                        function_name: "",
                        detail: &detail,
                    },
                    &mut uses,
                );
            }
            crate::types::Definition::Enum(_) => {}
        }
    }
    uses.into_iter().collect()
}

/// The uses of `key` as text under its definition: the type's own uses,
/// then each member and enumerator with the places that read it.
pub fn format_type_uses(store: &TypeStore, key: &str, uses: &[TypeUse]) -> String {
    let body = underlying_key(store, key);
    let mut out = String::from("\nuses:\n");
    let own: Vec<&TypeUse> = uses
        .iter()
        .filter(|use_| (use_.key == key || use_.key == body) && use_.member.is_empty())
        .collect();
    if own.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for use_ in own {
            out.push_str(&format!("  {}\n", use_.spelled()));
        }
    }
    let mut listed = BTreeSet::new();
    if let Some(layout) = store.layout(body) {
        for field in &layout.fields {
            let Some(name) = &field.name else {
                continue;
            };
            listed.insert(name.clone());
            out.push_str(&member_uses(body, name, uses));
        }
    }
    if let Some(crate::types::Definition::Enum(enumeration)) = store.get(body) {
        for (name, _) in &enumeration.values {
            listed.insert(name.clone());
            out.push_str(&member_uses(body, name, uses));
        }
    }
    let mut extra: Vec<&str> = uses
        .iter()
        .filter(|use_| use_.key == body && !use_.member.is_empty() && !listed.contains(&use_.member))
        .map(|use_| use_.member.as_str())
        .collect();
    extra.sort_unstable();
    extra.dedup();
    for name in extra {
        out.push_str(&member_uses(body, name, uses));
    }
    out
}

/// The structure, union or enumeration a typedef names, or `key`.
pub fn underlying_key<'a>(store: &'a TypeStore, key: &'a str) -> &'a str {
    match store.get(key) {
        Some(crate::types::Definition::Typedef(ty)) => match store.resolve(ty) {
            Type::Named(name)
                if store.layout(name).is_some()
                    || matches!(store.get(name), Some(crate::types::Definition::Enum(_))) =>
            {
                name.as_str()
            }
            _ => key,
        },
        _ => key,
    }
}

/// The type a variable is declared as: the structure it holds whole, not
/// the integer the machine keeps those bytes in.
fn shown_type<'a>(variable: &'a crate::lift::Variable, params: &'a [crate::lift::Variable]) -> Option<&'a str> {
    match &variable.fragment {
        Some(fragment)
            if fragment.whole || fragment.within.as_deref() == Some(variable.name.as_str()) =>
        {
            Some(fragment.of.as_str())
        }
        Some(fragment) => match &fragment.within {
            Some(within) if params.iter().any(|param| param.name == *within) => None,
            _ => Some(variable.ty.as_str()),
        },
        None => Some(variable.ty.as_str()),
    }
}

/// The definition that declares the member `name`, through a base class or
/// an anonymous member. `bits` selects a bit-field.
fn declaring_key(store: &TypeStore, ty: &Type, name: &str, bits: bool) -> Option<String> {
    let Type::Named(key) = store.resolve(ty) else {
        return None;
    };
    let layout = store.layout(key)?;
    let direct = layout.fields.iter().any(|field| {
        field.name.as_deref() == Some(name) && field.bits.is_some() == bits
    });
    if direct {
        return Some(key.clone());
    }
    for field in &layout.fields {
        if field.name.is_none() {
            if let Some(found) = declaring_key(store, &field.ty, name, bits) {
                return Some(found);
            }
        }
    }
    None
}

fn member_uses(key: &str, name: &str, uses: &[TypeUse]) -> String {
    let found: Vec<&TypeUse> = uses
        .iter()
        .filter(|use_| use_.key == key && use_.member == name)
        .collect();
    let mut out = format!("{name}:\n");
    if found.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for use_ in found {
            out.push_str(&format!("  {}\n", use_.spelled()));
        }
    }
    out
}

impl TypeUse {
    /// The use as one line: `a of init`, `0x4010b0 in init`, `next of struct node`.
    pub fn spelled(&self) -> String {
        match self.kind {
            "variable" => format!("{} of {}", self.detail, self.function_name),
            "return" => format!("return of {}", self.function_name),
            "definition" => self.detail.clone(),
            _ => match self.at {
                Some(at) => format!("{at:#x} in {}", self.function_name),
                None => format!("in {}", self.function_name),
            },
        }
    }
}

struct UseSite<'a> {
    kind: &'static str,
    function: u64,
    at: Option<u64>,
    function_name: &'a str,
    detail: &'a str,
}

fn note_type(
    store: &TypeStore,
    ty: &Type,
    kind: &'static str,
    function: &LiftedFunction,
    at: Option<u64>,
    detail: &str,
    uses: &mut BTreeSet<TypeUse>,
) {
    note_names(
        store,
        ty,
        UseSite {
            kind,
            function: function.address,
            at,
            function_name: &function.name,
            detail,
        },
        uses,
    );
}

fn note_names(store: &TypeStore, ty: &Type, site: UseSite<'_>, uses: &mut BTreeSet<TypeUse>) {
    let mut names = BTreeSet::new();
    ty.names(&mut names);
    for key in names {
        if store.is_anonymous(&key) || store.get(&key).is_none() {
            continue;
        }
        uses.insert(TypeUse {
            key,
            member: String::new(),
            kind: site.kind,
            function: site.function,
            at: site.at,
            function_name: site.function_name.to_string(),
            detail: site.detail.to_string(),
        });
    }
}

fn walk_statements(
    statements: &[Statement],
    function: &LiftedFunction,
    store: &TypeStore,
    vars: &BTreeMap<String, Type>,
    returns: &BTreeMap<String, Type>,
    uses: &mut BTreeSet<TypeUse>,
) {
    for statement in statements {
        let at = statement.addresses.first().copied();
        walk_nodes(&statement.node, &mut |node| {
            record_node(node, at, function, store, vars, returns, uses);
        });
        match &statement.kind {
            StatementKind::For { init, step, body } => {
                walk_statements(std::slice::from_ref(init.as_ref()), function, store, vars, returns, uses);
                walk_statements(std::slice::from_ref(step.as_ref()), function, store, vars, returns, uses);
                walk_statements(body, function, store, vars, returns, uses);
            }
            StatementKind::Switch { arms } => {
                for arm in arms {
                    for label in &arm.labels {
                        if let Some((owner, _)) = store.constant(label) {
                            if !store.is_anonymous(owner) {
                                uses.insert(TypeUse {
                                    key: owner.to_string(),
                                    member: label.clone(),
                                    kind: "enumerator",
                                    function: function.address,
                                    at,
                                    function_name: function.name.clone(),
                                    detail: String::new(),
                                });
                            }
                        }
                    }
                    walk_statements(&arm.body, function, store, vars, returns, uses);
                }
            }
            _ => {
                for child in statement.children() {
                    walk_statements(child, function, store, vars, returns, uses);
                }
            }
        }
    }
}

fn record_node(
    node: &AstNode,
    at: Option<u64>,
    function: &LiftedFunction,
    store: &TypeStore,
    vars: &BTreeMap<String, Type>,
    returns: &BTreeMap<String, Type>,
    uses: &mut BTreeSet<TypeUse>,
) {
    let (field, arrow) = if let Some((_, field, arrow)) = member_of(node) {
        (field, arrow)
    } else if let Some((_, field, _, _, arrow)) = bits_member_of(node) {
        (field, arrow)
    } else if let Some(name) = enumerator_of(node) {
        if let Some((owner, _)) = store.constant(name) {
            if !store.is_anonymous(owner) {
                uses.insert(TypeUse {
                    key: owner.to_string(),
                    member: name.to_string(),
                    kind: "enumerator",
                    function: function.address,
                    at,
                    function_name: function.name.clone(),
                    detail: String::new(),
                });
            }
        }
        return;
    } else {
        return;
    };
    let Some(base) = node_base(node) else {
        return;
    };
    let Some(base_ty) = expr_type(base, store, vars, returns) else {
        return;
    };
    let Some(outer) = composite_key(store, &base_ty, arrow) else {
        return;
    };
    let bits = bits_member_of(node).is_some();
    let Some(owner) = declaring_key(store, &Type::Named(outer), field, bits) else {
        return;
    };
    uses.insert(TypeUse {
        key: owner,
        member: field.to_string(),
        kind: if arrow { "arrow" } else { "member" },
        function: function.address,
        at,
        function_name: function.name.clone(),
        detail: String::new(),
    });
}

fn node_base(node: &AstNode) -> Option<&AstNode> {
    member_of(node)
        .map(|(base, _, _)| base)
        .or_else(|| bits_member_of(node).map(|(base, _, _, _, _)| base))
}

fn composite_key(store: &TypeStore, ty: &Type, arrow: bool) -> Option<String> {
    let resolved = store.resolve(ty).clone();
    let chosen = if !arrow && store.composite(&resolved).is_some() {
        resolved
    } else {
        match &resolved {
            Type::Pointer(inner) | Type::Array(inner, _) => store.resolve(inner).clone(),
            other => other.clone(),
        }
    };
    match &chosen {
        Type::Named(key) if store.composite(&chosen).is_some() && !store.is_anonymous(key) => {
            Some(key.clone())
        }
        _ => None,
    }
}

fn expr_type(
    node: &AstNode,
    store: &TypeStore,
    vars: &BTreeMap<String, Type>,
    returns: &BTreeMap<String, Type>,
) -> Option<Type> {
    if let Some((base, field, arrow)) = member_of(node) {
        let base_ty = expr_type(base, store, vars, returns)?;
        let owner = composite_key(store, &base_ty, arrow)?;
        return store
            .path_offset(&Type::Named(owner), &[Step::Field(field.to_string())])
            .map(|(_, ty)| ty);
    }
    if let Some((base, field, bit, bits, arrow)) = bits_member_of(node) {
        let base_ty = expr_type(base, store, vars, returns)?;
        let owner = composite_key(store, &base_ty, arrow)?;
        return store
            .path_offset(
                &Type::Named(owner),
                &[Step::Bits {
                    name: field.to_string(),
                    bit_offset: bit,
                    bits,
                }],
            )
            .map(|(_, ty)| ty);
    }
    match node {
        AstNode::Var { name } => vars.get(name).cloned(),
        AstNode::Cast { ty, .. } => crate::ctype::parse_type(store, ty).ok(),
        AstNode::Deref { target } => match expr_type(target, store, vars, returns).as_ref() {
            Some(ty) => match store.resolve(ty) {
                Type::Pointer(inner) | Type::Array(inner, _) => Some((**inner).clone()),
                _ => None,
            },
            None => None,
        },
        AstNode::Binary {
            lhs,
            op: BinaryOp::Add | BinaryOp::Sub,
            ..
        } => expr_type(lhs, store, vars, returns),
        AstNode::Call { callee, .. } => {
            let name = match callee.as_ref() {
                AstNode::FunctionName { name, .. } | AstNode::Var { name } => Some(name.as_str()),
                _ => None,
            }?;
            returns.get(name).cloned()
        }
        _ => None,
    }
}

fn walk_nodes(node: &AstNode, visit: &mut dyn FnMut(&AstNode)) {
    visit(node);
    match node {
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => {
            walk_nodes(cond, visit);
            walk_nodes(then_part, visit);
            if let Some(else_part) = else_part {
                walk_nodes(else_part, visit);
            }
        }
        AstNode::IfGoto { cond, .. } => walk_nodes(cond, visit),
        AstNode::Loop { cond, body, .. } => {
            if let Some(cond) = cond {
                walk_nodes(cond, visit);
            }
            walk_nodes(body, visit);
        }
        AstNode::Assign { lhs, rhs } => {
            walk_nodes(lhs, visit);
            walk_nodes(rhs, visit);
        }
        AstNode::Binary { lhs, rhs, .. } => {
            walk_nodes(lhs, visit);
            walk_nodes(rhs, visit);
        }
        AstNode::Deref { target } | AstNode::AddressOf { target } | AstNode::Cast { target, .. } => {
            walk_nodes(target, visit);
        }
        AstNode::Call { callee, args } => {
            walk_nodes(callee, visit);
            for arg in args {
                walk_nodes(arg, visit);
            }
        }
        AstNode::Return { value: Some(value) } => walk_nodes(value, visit),
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => {
            walk_nodes(cond, visit);
            walk_nodes(then, visit);
            walk_nodes(otherwise, visit);
        }
        AstNode::Intrinsic { args, .. } => {
            for arg in args {
                walk_nodes(arg, visit);
            }
        }
        AstNode::StructInit { fields } => {
            for field in fields {
                walk_nodes(&field.value, visit);
            }
        }
        AstNode::ConstantCondition { compared, .. } => walk_nodes(compared, visit),
        _ => {}
    }
}

/// The members of the union the access at `address` reads, in declaration
/// order, for a view to cycle: the pointee of a typed pointer the
/// statement at the address reads through, or the type of the variable it
/// reads a part of. `None` when no statement is at the address or none of
/// its accesses reads a union.
pub fn union_access_at(
    function: &LiftedFunction,
    address: u64,
    store: &TypeStore,
) -> Option<Vec<String>> {
    fn find_at(
        statements: &[crate::lift::Statement],
        address: u64,
    ) -> Option<&crate::lift::Statement> {
        statements.iter().find_map(|statement| {
            if statement.addresses.contains(&address) {
                return Some(statement);
            }
            statement
                .children()
                .into_iter()
                .find_map(|child| find_at(child, address))
        })
    }
    let statement = find_at(&function.body, address)?;
    let declared = |name: &str| -> Option<Type> {
        let ty = function
            .params
            .iter()
            .chain(&function.locals)
            .find(|variable| variable.name == name)?
            .ty
            .clone();
        crate::ctype::parse_type(store, &ty).ok()
    };
    let found = std::cell::RefCell::new(None);
    statement.node.any(&|node| {
        let pointee = match node {
            AstNode::Deref { target } => match target.as_ref() {
                AstNode::Cast { ty, .. } => match crate::ctype::parse_type(store, ty).ok() {
                    Some(Type::Pointer(pointee)) => Some(*pointee),
                    _ => None,
                },
                _ => None,
            },
            // The variable itself is the union, or a pointer to one: the
            // member reads through it either way.
            AstNode::Var { name } => match declared(name).as_ref().map(|ty| store.resolve(ty)) {
                Some(Type::Pointer(pointee)) => Some((**pointee).clone()),
                Some(ty) => Some(ty.clone()),
                None => None,
            },
            _ => None,
        };
        if let Some(pointee) = pointee {
            if let Some(members) = store.union_members(&pointee) {
                *found.borrow_mut() = Some(members);
                return true;
            }
        }
        false
    });
    found.into_inner()
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
/// member or element the bytes are. `chosen` is the member the analyst
/// said the union access here means.
fn load(ty: &str, address: &AstNode, typed: &Typed, chosen: Option<&str>) -> Option<AstNode> {
    let access = match crate::ctype::parse_type(typed.store, ty).ok()? {
        Type::Pointer(pointee) => *pointee,
        _ => return None,
    };
    let size = typed.store.size_of(&access).ok()?;
    let (pointer, offset, index) = decompose(address, typed)?;
    through(&pointer, offset, size, index, typed, chosen)
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
    chosen: Option<&str>,
) -> Option<AstNode> {
    let pointee = typed.pointers.get(pointer)?;
    let store = typed.store;
    let each = store.size_of(pointee).ok().filter(|&each| each > 0)?;
    let base = AstNode::var(pointer);
    // An index a whole number of elements back, `p[i - 1]`.
    if offset < 0 {
        let (index, scale) = index?;
        let back = offset.unsigned_abs();
        if scale != each || !back.is_multiple_of(each) {
            return None;
        }
        let (path, _) = store.field_at_chosen(pointee, 0, size, chosen)?;
        let index = AstNode::binary(index, BinaryOp::Sub, AstNode::constant(back / each, 8));
        return Some(crate::stack_vars::parts_node(
            AstNode::Intrinsic {
                name: crate::stack_vars::INDEX.to_string(),
                args: vec![base, index],
            },
            &path,
        ));
    }
    let offset = u64::try_from(offset).ok()?;
    let element = offset / each;
    let within = offset % each;
    match index {
        // `p[i]`, or `p[i + k]`, of the pointee's own size.
        Some((index, scale)) if scale == each => {
            let index = plus(index, element);
            let (path, _) = store.field_at_chosen(pointee, within, size, chosen)?;
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
            let (path, _) = store.field_at_chosen(item, into % scale, size, chosen)?;
            let array = member(base, field.name.as_deref()?, true);
            let indexed = AstNode::Intrinsic {
                name: crate::stack_vars::INDEX.to_string(),
                args: vec![array, plus(index, into / scale)],
            };
            Some(crate::stack_vars::parts_node(indexed, &path))
        }
        None => {
            let (path, leaf) = store.field_at_chosen(pointee, within, size, chosen)?;
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
                    Some((
                        Step::Bits {
                            name,
                            bit_offset,
                            bits,
                        },
                        rest,
                    )) => {
                        // A bit-field is a scalar leaf: a path through
                        // it is no path.
                        if !rest.is_empty() {
                            return None;
                        }
                        bits_member(base, name, *bit_offset, *bits, true)
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
                // `(i + k) * s` is the index `i`, `k * s` bytes on.
                let by = match by {
                    AstNode::Binary {
                        lhs: inner,
                        op: BinaryOp::Add,
                        rhs: on,
                    } => match on.as_ref() {
                        AstNode::Constant { value, .. } => {
                            let on = (*value as i64).checked_mul(i64::try_from(scale).ok()?)?;
                            offset = offset.checked_add(on)?;
                            inner.as_ref()
                        }
                        _ => by,
                    },
                    _ => by,
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
            // A value added unscaled is an index of one byte, `p + i`.
            AstNode::Var { .. } | AstNode::Cast { .. } if !negative => {
                if index.replace((term.clone(), 1)).is_some() {
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
        versions: Vec<(String, u64)>,
        union_fields: Vec<(u64, String)>,
    }

    impl Symbols for World {
        fn function_name(&self, _address: u64) -> Option<String> {
            None
        }

        fn union_fields(&self) -> std::collections::BTreeMap<u64, String> {
            self.union_fields.clone().into_iter().collect()
        }

        fn variable_edits(&self, _address: u64) -> VariableEdits {
            VariableEdits {
                stack_vars: self.stack_vars.clone(),
                var_types: self.var_types.clone(),
                versions: self.versions.clone(),
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
        enum mode { M_READ = 1, M_WRITE = 2, M_EXEC = 4 };\n\
        struct node { struct node *next; int v; };\n\
        struct flags { unsigned flags : 3; unsigned mode : 5; };\n\
        struct solo { unsigned flags : 3; };";

    /// The pseudocode of `bytes` lifted as `f` under `TYPES`, with the
    /// analyst's stack variables and variable types, without the comment
    /// saying what decided the return type.
    fn c(
        bytes: &[u8],
        stack_vars: &[(i64, u32, &str, &str)],
        var_types: &[(&str, &str)],
    ) -> String {
        let (text, _) = lifted(bytes, stack_vars, var_types, &[]);
        text
    }

    /// [`c`], with the analyst's new versions, and the variables as the
    /// listing gives them: name and type.
    fn lifted(
        bytes: &[u8],
        stack_vars: &[(i64, u32, &str, &str)],
        var_types: &[(&str, &str)],
        versions: &[(&str, u64)],
    ) -> (String, Vec<(String, String)>) {
        lifted_union(bytes, stack_vars, var_types, versions, &[])
    }

    /// [`lifted`], with the analyst's word on which member of a union the
    /// access at each address means.
    fn lifted_union(
        bytes: &[u8],
        stack_vars: &[(i64, u32, &str, &str)],
        var_types: &[(&str, &str)],
        versions: &[(&str, u64)],
        union_fields: &[(u64, &str)],
    ) -> (String, Vec<(String, String)>) {
        lifted_abi(
            bytes,
            stack_vars,
            var_types,
            versions,
            union_fields,
            Abi::SystemV,
        )
    }

    /// [`lifted_union`], under the calling convention `abi`.
    fn lifted_abi(
        bytes: &[u8],
        stack_vars: &[(i64, u32, &str, &str)],
        var_types: &[(&str, &str)],
        versions: &[(&str, u64)],
        union_fields: &[(u64, &str)],
        abi: Abi,
    ) -> (String, Vec<(String, String)>) {
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
            versions: versions
                .iter()
                .map(|(v, at)| (v.to_string(), *at))
                .collect(),
            union_fields: union_fields
                .iter()
                .map(|(at, name)| (*at, name.to_string()))
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
            abi,
            &world,
            &Options::default(),
        )
        .expect("the code lifts");
        let text = emit_function(&stages.function, &Options::default())
            .lines
            .iter()
            .map(|line| line.text.as_str())
            .filter(|text| !(text.starts_with("// void: ") || text.starts_with("// returns ")))
            .collect::<Vec<_>>()
            .join("\n");
        let variables = stages
            .function
            .variables()
            .into_iter()
            .map(|v| (v.name, v.ty))
            .collect();
        (text, variables)
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
        // The analyst's word on which member the access means reads the
        // same code as `w.f`: the store at 0x1004 and the load at 0x100b.
        assert_eq!(
            lifted_union(
                &one,
                &[(-0x18, 4, "w", "union word")],
                &[],
                &[],
                &[(0x1004, "f"), (0x100b, "f")],
            )
            .0,
            "int f(void)\n{\n  union word w;\n\n  w.f = 1;\n  return w.f;\n}"
        );
        // A word naming a member the bytes are not (a float the code reads
        // as int) still moves the read to it; a word naming nothing the
        // union has leaves the first member.
        assert_eq!(
            lifted_union(
                &one,
                &[(-0x18, 4, "w", "union word")],
                &[],
                &[],
                &[(0x1004, "nope"), (0x100b, "nope")],
            )
            .0,
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
    fn an_access_to_a_bit_fields_unit_is_the_bit_field() {
        // `struct solo { unsigned flags : 3; }` — the sole named
        // bit-field in its int unit, so the access to the unit is the
        // field: the store through a typed pointer reads `a->flags`.
        assert_eq!(
            c(&[0x89, 0x37, 0xc3], &[], &[("a", "struct solo *")]),
            "void f(struct solo *a, int b)\n{\n  a->flags = b;\n  return;\n}"
        );
        // Two bit-fields in their int unit: the access is no one
        // member's, and the typed read declines it.
        assert_eq!(
            c(&[0x8b, 0x07, 0xc3], &[], &[("a", "struct flags *")]),
            "int f(struct flags *a)\n{\n  return *(int *)a;\n}"
        );
        // A stack variable of `struct solo`: its access is its field.
        // push rbp; mov rbp, rsp; mov dword [rbp-0x10], 1;
        // mov eax, [rbp-0x10]; pop rbp; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xf0,
            0x5d, 0xc3,
        ];
        assert_eq!(
            c(&code, &[(-0x18, 4, "s", "struct solo")], &[]),
            "int f(void)\n{\n  struct solo s;\n\n  s.flags = 1;\n  return s.flags;\n}"
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
                ("a", "union word"),
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
                "// a is not typed union word: union word has a member of floating type, which System V passes in vector registers"
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

    /// push rbp; mov rbp, rsp; mov dword [rbp-0x10], 1; mov dword
    /// [rbp-0xc], 2: a `struct pair p` at [sp-0x18] filled.
    const FILL: [u8; 18] = [
        0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xf0, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf4, 0x02,
        0x00, 0x00, 0x00,
    ];

    /// `FILL`, then `tail`.
    fn filled(tail: &[u8]) -> Vec<u8> {
        [&FILL[..], tail].concat()
    }

    const P: (i64, u32, &str, &str) = (-0x18, 8, "p", "struct pair");
    const Q: (i64, u32, &str, &str) = (-0x20, 8, "q", "struct pair");

    #[test]
    fn a_member_loaded_into_a_register_reads_as_the_member() {
        // mov ebx, [rbp-0xc]; call; mov eax, ebx; add eax, ebx; pop rbp; ret
        let code = filled(&[
            0x8b, 0x5d, 0xf4, 0xe8, 0x00, 0x01, 0x00, 0x00, 0x89, 0xd8, 0x01, 0xd8, 0x5d, 0xc3,
        ]);
        let text = c(&code, &[P], &[]);
        assert!(text.contains("return p.b + p.b;"), "{text}");
        // test esi, esi; je +5; mov rax, [rdi]; jmp +3; mov rax, [rdi]; mov
        // eax, [rax+8]; ret: the member is a pointer, which the register
        // both paths load it into takes as its type, and reads through.
        let code = [
            0x85, 0xf6, 0x74, 0x05, 0x48, 0x8b, 0x07, 0xeb, 0x03, 0x48, 0x8b, 0x07, 0x8b, 0x40,
            0x08, 0xc3,
        ];
        let text = c(&code, &[], &[("a", "struct node *")]);
        assert!(text.contains("return a->next->v;"), "{text}");
        // A register that holds the member, through a call: `b = a->next;
        // g(); return *(int *)(b + 8);` — the register takes the member's
        // type, and reads through it.
        use crate::ast::AstNode;
        use crate::lift::{LiftedFunction, Placement, Statement, Variable};
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(&mut store, TYPES).unwrap();
        let var = AstNode::var;
        let next = crate::typed::member(var("a"), "next", true);
        let body = vec![
            Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(var("b")),
                    rhs: Box::new(next),
                },
                vec![0x1000],
            ),
            Statement::plain(
                AstNode::Call {
                    callee: Box::new(var("g")),
                    args: Vec::new(),
                },
                vec![0x1004],
            ),
            Statement::plain(
                AstNode::Return {
                    value: Some(Box::new(AstNode::Deref {
                        target: Box::new(AstNode::Cast {
                            ty: "int *".to_string(),
                            target: Box::new(AstNode::binary(
                                var("b"),
                                crate::ast::BinaryOp::Add,
                                AstNode::constant(8, 8),
                            )),
                        }),
                    })),
                },
                vec![0x1009],
            ),
        ];
        let mut function = LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "int".to_string(),
            params: vec![Variable::new("struct node *", "a").placed(Placement::register(7, 64))],
            locals: vec![Variable::new("long", "b").placed(Placement::register(3, 64))],
            body,
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            decoded_strings: Vec::new(),
            rendered_constants: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        super::read_types(
            &mut function,
            &store,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );
        assert_eq!(function.locals[0].ty, "struct node *");
        let text = emit_function(&function, &Options::default())
            .lines
            .iter()
            .map(|line| line.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("  b = a->next;\n"), "{text}");
        assert!(text.contains("  return b->v;"), "{text}");
    }

    #[test]
    fn eight_bytes_shifted_right_by_32_are_the_second_member() {
        // mov rax, [rbp-0x10]; shr rax, 32; pop rbp; ret
        let code = filled(&[0x48, 0x8b, 0x45, 0xf0, 0x48, 0xc1, 0xe8, 0x20, 0x5d, 0xc3]);
        assert_eq!(
            c(&code, &[P], &[]),
            "long f(void)\n{\n  struct pair p;\n\n  p.a = 1;\n  p.b = 2;\n  return (unsigned long)(unsigned int)p.b;\n}"
        );
        // sar: the member with its sign.
        let code = filled(&[0x48, 0x8b, 0x45, 0xf0, 0x48, 0xc1, 0xf8, 0x20, 0x5d, 0xc3]);
        assert!(c(&code, &[P], &[]).contains("return (long)p.b;"));
        // Through a pointer: mov rax, [rdi]; shr rax, 32; mov eax, eax... as
        // the low half of the result.
        let code = [0x48, 0x8b, 0x07, 0x48, 0xc1, 0xe8, 0x20, 0xc3];
        assert!(c(&code, &[], &[("a", "struct pair *")])
            .contains("return (unsigned long)(unsigned int)a->b;"));
    }

    #[test]
    fn a_truncation_is_the_first_member() {
        // mov rax, [rbp-0x10]; mov [rbp-0x14], eax; mov eax, [rbp-0x14]
        let code = filled(&[
            0x48, 0x8b, 0x45, 0xf0, 0x89, 0x45, 0xec, 0x8b, 0x45, 0xec, 0x5d, 0xc3,
        ]);
        assert!(c(&code, &[P], &[]).contains("return p.a;"));
        // mov rax, [rbp-0x10]; and eax, 0xffffffff... as a mask: and rax,
        // 0xffff keeps the low two bytes, which are no member's.
        let code = filled(&[
            0x48, 0x8b, 0x45, 0xf0, 0x48, 0x25, 0xff, 0xff, 0x00, 0x00, 0x5d, 0xc3,
        ]);
        assert!(c(&code, &[P], &[]).contains("return p & 0xffff;"));
    }

    #[test]
    fn a_fragment_stored_into_a_structure_is_a_member_assigned_and_a_run_a_copy() {
        // mov rax, [rbp-0x10]; shr rax, 32; mov [rbp-0x14], eax; mov eax,
        // [rbp-0x18]
        let code = filled(&[
            0x48, 0x8b, 0x45, 0xf0, 0x48, 0xc1, 0xe8, 0x20, 0x89, 0x45, 0xec, 0x8b, 0x45, 0xe8,
            0x5d, 0xc3,
        ]);
        assert!(c(&code, &[P, Q], &[]).contains("  q.b = p.b;\n"));
        // mov eax, [rbp-0x10]; mov [rbp-0x18], eax; mov eax, [rbp-0xc];
        // mov [rbp-0x14], eax: two members in order, a copy.
        let code = filled(&[
            0x8b, 0x45, 0xf0, 0x89, 0x45, 0xe8, 0x8b, 0x45, 0xf4, 0x89, 0x45, 0xec, 0x8b, 0x45,
            0xe8, 0x5d, 0xc3,
        ]);
        assert_eq!(
            c(&code, &[P, Q], &[]),
            "int f(void)\n{\n  struct pair p;\n  struct pair q;\n\n  p.a = 1;\n  p.b = 2;\n  q = p;\n  return q.a;\n}"
        );
        // The members in the other order are two stores.
        let code = filled(&[
            0x8b, 0x45, 0xf4, 0x89, 0x45, 0xec, 0x8b, 0x45, 0xf0, 0x89, 0x45, 0xe8, 0x8b, 0x45,
            0xe8, 0x5d, 0xc3,
        ]);
        assert!(c(&code, &[P, Q], &[]).contains("q.b = p.b;\n  q.a = p.a;"));
        // Through pointers: mov eax, [rsi]; mov [rdi], eax; mov eax,
        // [rsi+4]; mov [rdi+4], eax; xor eax, eax; ret
        let code = [
            0x8b, 0x06, 0x89, 0x07, 0x8b, 0x46, 0x04, 0x89, 0x47, 0x04, 0x31, 0xc0, 0xc3,
        ];
        let text = c(
            &code,
            &[],
            &[("a", "struct pair *"), ("b", "struct pair *")],
        );
        assert!(text.contains("  *a = *b;\n"), "{text}");
    }

    #[test]
    fn two_members_joined_in_a_register_and_shifted_out_are_the_member() {
        // mov edx, [rsi+4]; shl rdx, 32; mov eax, [rsi]; or rax, rdx; sar
        // rax, 32; mov [rdi+4], eax; xor eax, eax; ret — GCC's copy of y.
        let code = [
            0x8b, 0x56, 0x04, 0x48, 0xc1, 0xe2, 0x20, 0x8b, 0x06, 0x48, 0x09, 0xd0, 0x48, 0xc1,
            0xf8, 0x20, 0x89, 0x47, 0x04, 0x31, 0xc0, 0xc3,
        ];
        let text = c(
            &code,
            &[],
            &[("a", "struct pair *"), ("b", "struct pair *")],
        );
        assert!(text.contains("  a->b = b->b;\n"), "{text}");
    }

    #[test]
    fn a_structure_passed_by_value_reads_its_members_from_its_registers() {
        // mov rax, rdi; sar rax, 32; lea eax, [rax+rax*2]; add eax, edi; ret
        let code = [
            0x48, 0x89, 0xf8, 0x48, 0xc1, 0xf8, 0x20, 0x8d, 0x04, 0x40, 0x01, 0xf8, 0xc3,
        ];
        let (text, variables) = lifted(&code, &[], &[("a", "struct pair")], &[]);
        assert_eq!(
            text,
            "int f(struct pair a)\n{\n  return (a.b + (a.b * 2)) + a.a;\n}"
        );
        assert_eq!(variables, [("a".to_string(), "struct pair".to_string())]);
        // Sixteen bytes in rdi and rsi: mov rax, rdi; shr rax, 32; add eax,
        // edi; add rax, rsi; ret
        let code = [
            0x48, 0x89, 0xf8, 0x48, 0xc1, 0xe8, 0x20, 0x01, 0xf8, 0x48, 0x01, 0xf0, 0xc3,
        ];
        let (text, variables) = lifted(&code, &[], &[("a", "struct point")], &[]);
        assert!(text.starts_with("long f(struct point a)\n"), "{text}");
        assert!(
            text.contains("(a.y + a.x)") && text.contains("+ a.tag;"),
            "{text}"
        );
        assert_eq!(
            variables,
            [
                ("a".to_string(), "struct point [0..8) (x, y)".to_string()),
                ("b".to_string(), "struct point [8..16) (tag)".to_string()),
            ]
        );
        // A new version of the parameter holds its bytes too.
        let (text, variables) = lifted(&code, &[], &[("a", "struct point")], &[("a", BASE + 7)]);
        assert!(text.contains("a_2 = a;"), "{text}");
        assert!(
            variables.contains(&("a_2".to_string(), "struct point [0..8) (x, y)".to_string())),
            "{variables:?}"
        );
    }

    #[test]
    fn a_go_structure_passed_by_value_reads_its_members_from_rax_and_rbx() {
        // Eight bytes in rax: mov rdx, rax; sar rdx, 32; mov eax, edx; ret
        let code = [0x48, 0x89, 0xc2, 0x48, 0xc1, 0xfa, 0x20, 0x89, 0xd0, 0xc3];
        let (text, variables) = lifted_abi(&code, &[], &[("a", "struct pair")], &[], &[], Abi::Go);
        assert_eq!(text, "int f(struct pair a)\n{\n  return a.b;\n}");
        assert_eq!(variables, [("a".to_string(), "struct pair".to_string())]);
        // Sixteen bytes in rax and rbx: mov rdx, rax; shr rdx, 32; add edx,
        // eax; add rdx, rbx; mov rax, rdx; ret
        let code = [
            0x48, 0x89, 0xc2, 0x48, 0xc1, 0xea, 0x20, 0x01, 0xc2, 0x48, 0x01, 0xda, 0x48, 0x89,
            0xd0, 0xc3,
        ];
        let (text, variables) = lifted_abi(&code, &[], &[("a", "struct point")], &[], &[], Abi::Go);
        assert!(text.starts_with("long f(struct point a)\n"), "{text}");
        assert!(
            text.contains("(a.y + a.x)") && text.contains("+ a.tag;"),
            "{text}"
        );
        assert_eq!(
            variables,
            [
                ("a".to_string(), "struct point [0..8) (x, y)".to_string()),
                ("b".to_string(), "struct point [8..16) (tag)".to_string()),
            ]
        );
        // A union of a floating member is not read, and says why.
        let (text, _) = lifted_abi(&code, &[], &[("a", "union word")], &[], &[], Abi::Go);
        assert!(
            text.contains(
                "union word has a member of floating type, which Go passes in vector registers"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_pascal_structure_passed_by_value_reads_its_members_from_rax() {
        // Eight bytes in rax: mov rdx, rax; sar rdx, 32; mov eax, edx; ret
        let code = [0x48, 0x89, 0xc2, 0x48, 0xc1, 0xfa, 0x20, 0x89, 0xd0, 0xc3];
        let (text, variables) =
            lifted_abi(&code, &[], &[("a", "struct pair")], &[], &[], Abi::Pascal);
        assert_eq!(text, "int f(struct pair a)\n{\n  return a.b;\n}");
        assert_eq!(variables, [("a".to_string(), "struct pair".to_string())]);
        // Larger than eight bytes goes on the stack, and the lift says so.
        let (text, _) = lifted_abi(&code, &[], &[("a", "struct point")], &[], &[], Abi::Pascal);
        assert!(
            text.contains("Pascal passes struct point, of 16 bytes, on the stack"),
            "{text}"
        );
    }

    #[test]
    fn a_structure_returned_in_rax_is_read_as_its_member_at_the_call() {
        // call 0x100a; shr rax, 32; ret; mov eax, edi; ret
        let code = [
            0xe8, 0x05, 0x00, 0x00, 0x00, 0x48, 0xc1, 0xe8, 0x20, 0xc3, 0x89, 0xf8, 0xc3,
        ];
        let text = c(&code, &[], &[("return", "struct pair")]);
        assert!(text.contains("sub_100a().b"), "{text}");
        // A return of floating members is not read, and says why.
        let text = c(&code, &[], &[("return", "union word")]);
        assert!(
            text.contains(
                "// the return is not typed union word: union word has a member of floating type"
            ),
            "{text}"
        );
    }

    #[test]
    fn bytes_of_several_members_read_from_the_first_with_the_members_in_a_comment() {
        // mov qword [rbp-8], 7; mov rax, [rbp-0x10]; pop rbp; ret
        let code = filled(&[
            0x48, 0xc7, 0x45, 0xf8, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x45, 0xf0, 0x5d, 0xc3,
        ]);
        let text = c(&code, &[(-0x18, 16, "p", "struct point")], &[]);
        assert!(
            text.contains("return *(long *)&p.x /* p.x, p.y */;"),
            "{text}"
        );
    }

    #[test]
    fn a_type_and_its_members_list_where_the_pseudocode_reads_them() {
        use crate::ast::AstNode;
        use crate::lift::{LiftedFunction, Statement, Variable};
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(&mut store, TYPES).unwrap();
        let body = vec![
            Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(super::member(AstNode::var("a"), "y", true)),
                    rhs: Box::new(AstNode::constant(2, 4)),
                },
                vec![0x4010],
            ),
            Statement::plain(
                AstNode::Return {
                    value: Some(Box::new(super::enumerator(1, 4, "S_READY"))),
                },
                vec![0x4014],
            ),
        ];
        let function = LiftedFunction {
            name: "init".to_string(),
            address: 0x4000,
            return_type: "enum state".to_string(),
            params: vec![Variable::new("struct point *", "a")],
            locals: Vec::new(),
            body,
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            decoded_strings: Vec::new(),
            rendered_constants: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        let uses = super::cross_references(&function, &store, &std::collections::BTreeMap::new());
        let spelled: Vec<String> = uses.iter().map(|use_| use_.spelled()).collect();
        assert!(spelled.iter().any(|line| line == "a of init"), "{spelled:?}");
        assert!(
            spelled.iter().any(|line| line == "return of init"),
            "{spelled:?}"
        );
        assert!(
            uses.iter().any(|use_| {
                use_.key == "struct point"
                    && use_.member == "y"
                    && use_.kind == "arrow"
                    && use_.at == Some(0x4010)
            }),
            "{uses:?}"
        );
        assert!(
            uses.iter().any(|use_| {
                use_.key == "enum state" && use_.member == "S_READY" && use_.at == Some(0x4014)
            }),
            "{uses:?}"
        );
        let text = super::format_type_uses(&store, "struct point", &uses);
        assert!(text.contains("a of init"), "{text}");
        assert!(text.contains("y:\n  0x4010 in init"), "{text}");
        assert!(text.contains("x:\n  (none)"), "{text}");
        let defined = super::definition_uses(&store);
        assert!(
            defined
                .iter()
                .any(|use_| use_.key == "struct node" && use_.detail == "next of struct node"),
            "{defined:?}"
        );
    }

    #[test]
    fn a_structure_held_by_value_and_a_base_field_are_uses_of_what_declares_them() {
        use crate::ast::AstNode;
        use crate::lift::{Fragment, LiftedFunction, Statement, Variable};
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(
            &mut store,
            "struct point { int x; int y; }; struct base { int x; }; struct derived : base { int y; };",
        )
        .unwrap();
        let mut held = Variable::new("long", "a");
        held.fragment = Some(Fragment {
            of: "struct point".to_string(),
            offset: 0,
            size: 8,
            members: Vec::new(),
            whole: true,
            within: Some("a".to_string()),
            signed: false,
        });
        let by_value = LiftedFunction {
            name: "pass".to_string(),
            address: 0x5000,
            return_type: "void".to_string(),
            params: vec![held],
            locals: Vec::new(),
            body: vec![Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(super::member(AstNode::var("a"), "x", false)),
                    rhs: Box::new(AstNode::constant(1, 4)),
                },
                vec![0x5000],
            )],
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            decoded_strings: Vec::new(),
            rendered_constants: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        let uses = super::cross_references(&by_value, &store, &std::collections::BTreeMap::new());
        assert!(
            uses.iter().any(|use_| {
                use_.key == "struct point" && use_.member.is_empty() && use_.detail == "a"
            }),
            "{uses:?}"
        );
        assert!(
            uses.iter()
                .any(|use_| use_.key == "struct point" && use_.member == "x" && use_.kind == "member"),
            "{uses:?}"
        );
        let derived = LiftedFunction {
            name: "touch".to_string(),
            address: 0x6000,
            return_type: "void".to_string(),
            params: vec![Variable::new("struct derived *", "d")],
            locals: Vec::new(),
            body: vec![Statement::plain(
                super::member(AstNode::var("d"), "x", true),
                vec![0x6004],
            )],
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            decoded_strings: Vec::new(),
            rendered_constants: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        let uses = super::cross_references(&derived, &store, &std::collections::BTreeMap::new());
        assert!(
            uses.iter()
                .any(|use_| use_.key == "struct base" && use_.member == "x"),
            "{uses:?}"
        );
        assert!(
            uses.iter()
                .all(|use_| !(use_.key == "struct derived" && use_.member == "x")),
            "{uses:?}"
        );
    }

    #[test]
    fn a_constant_shown_as_an_enum_member_by_the_analysts_word() {
        use crate::ast::AstNode;
        use crate::lift::{LiftedFunction, Statement};
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(&mut store, "enum state { S_IDLE = 0, S_READY = 1, S_DONE = 2 };")
            .unwrap();
        let body = vec![Statement::plain(
            AstNode::Return {
                value: Some(Box::new(AstNode::constant(1, 4))),
            },
            vec![0x4010],
        )];
        let mut function = LiftedFunction {
            name: "get_state".to_string(),
            address: 0x4000,
            return_type: "int".to_string(),
            params: vec![],
            locals: vec![],
            body,
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            decoded_strings: Vec::new(),
            rendered_constants: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        // Without the annotation, the constant is a number.
        let constant_enums = std::collections::BTreeMap::new();
        super::read_types(
            &mut function,
            &store,
            &Default::default(),
            &Default::default(),
            &constant_enums,
        );
        let text = emit_function(&function, &Options::default())
            .lines
            .iter()
            .map(|line| line.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("return 1;"), "{text}");
        // With the annotation, the constant is the enumerator.
        let body = vec![Statement::plain(
            AstNode::Return {
                value: Some(Box::new(AstNode::constant(1, 4))),
            },
            vec![0x4010],
        )];
        let mut function = LiftedFunction {
            name: "get_state".to_string(),
            address: 0x4000,
            return_type: "int".to_string(),
            params: vec![],
            locals: vec![],
            body,
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            decoded_strings: Vec::new(),
            rendered_constants: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        let mut constant_enums = std::collections::BTreeMap::new();
        constant_enums.insert(0x4010, "enum state".to_string());
        super::read_types(
            &mut function,
            &store,
            &Default::default(),
            &Default::default(),
            &constant_enums,
        );
        let text = emit_function(&function, &Options::default())
            .lines
            .iter()
            .map(|line| line.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("return S_READY;"), "{text}");
    }
}
