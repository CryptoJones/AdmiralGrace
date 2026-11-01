//! Type fragments: the bytes of a structure held in a register.
//!
//! Code moves a structure about in parts. `mov eax, [rbp-0x10]` loads the
//! member `p.x` of a `struct point p` on the stack; `mov rax, [rbp-0x10]`
//! loads `p.x` and `p.y` together as one eight-byte value, and `shr rax,
//! 32` then leaves `p.y`; System V passes a `struct point { int x, y; }`
//! by value in one register and returns it in `rax`. A fragment is the
//! type of such a value: the bytes `[offset, offset + size)` of a known
//! structure or union ([`crate::lift::Fragment`]) — `struct point [4..8)
//! (y)` is `p.y`, `[0..8)` the whole of `p`.
//!
//! The lifted body is read for the fragments in it once the members
//! through typed pointers are read ([`crate::typed::read_types`]):
//!
//! - **the source**: a typed stack variable, a member or element of one,
//!   bytes at an offset into one, `*(long *)&p`, the pointee of a typed
//!   pointer or bytes through it, `*(long *)a`, a parameter a structure is
//!   passed in, and the result of a call to a function whose `return` the
//!   analyst typed a structure, are bytes of a structure;
//! - **narrowing**: a shift right by whole bytes drops the low ones,
//!   `frag[0..8) >> 32` is `[4..8)`; a mask of the low bytes keeps them,
//!   `& 0xffffffff` is `[0..4)`; a cast to a narrower integer — `(int)x`,
//!   `eax` of `rax`, the source of a `movzx` or `movsx` — keeps the low
//!   bytes, `[0..4)`. A wider cast or a shift keeps the bytes and says
//!   whether the value above them is their sign or zeros;
//! - **joining**: `(long)b << 32 | (unsigned int)a`, where `a` and `b` are
//!   the neighbouring bytes of one source, is the bytes of both;
//! - **reading**: a fragment that is exactly one member reads as the
//!   member, `p.y`, `a->y`, `make(b, 5).y` — through the casts that say
//!   how it was widened when it is held wider than the member and the
//!   member's own type does not widen it so; a fragment of several
//!   members loaded or stored where it stands reads as the bytes from the
//!   first member it starts at, with the members it holds in a comment,
//!   `*(long *)&p.x /* p.x, p.y */`; a fragment of no member, or of bytes
//!   that are no member's, reads as before;
//! - **variables**: a variable assigned a fragment holds it. One that is
//!   exactly a member of pointer or enumeration type takes the member's
//!   type, and reads through it; one that holds a whole structure is
//!   declared as the structure and its parts read as its members, `v.y`,
//!   where every read of it is a member, a copy, an argument or a return;
//!   one that holds a part of a stack variable the function writes no
//!   more after the variable is assigned reads its parts as that
//!   variable's members, `p.y`; another keeps its integer, and the
//!   variables listing says what bytes it holds;
//! - **stores**: a fragment stored into a structure at the offset it came
//!   from is the member assigned, `q.y = p.y`, and a run of such stores
//!   that covers a structure from one source, in order, is a copy, `q =
//!   p;`, `*a = *b;`.
//!
//! A variable keeps its integer type, `ty`, whatever its fragment — the
//! medium level, which the transpiler writes, reads the bytes with the
//! machine's shifts and masks — and only the declarations the pseudocode
//! prints, and the variables listing, say the structure.

use std::collections::BTreeMap;

use crate::ast::{AstNode, BinaryOp};
use crate::lift::{Fragment, LiftedFunction, Placement, Statement, StatementKind};
use crate::types::{Step, Type, TypeStore};

/// The intrinsic a value of several members is annotated with: `*(long
/// *)&p.x /* p.x, p.y */` is `__fragment(*(long *)&p.x, "p.x, p.y")`. It
/// is the value, and no call.
pub const FRAGMENT: &str = "__fragment";

/// `node`, annotated as the members `members` of a structure.
pub fn annotated(node: AstNode, members: &str) -> AstNode {
    AstNode::Intrinsic {
        name: FRAGMENT.to_string(),
        args: vec![
            node,
            AstNode::StringLiteral {
                text: members.to_string(),
            },
        ],
    }
}

/// The value and the members of an annotated fragment, when the node is
/// one.
pub fn annotation_of(node: &AstNode) -> Option<(&AstNode, &str)> {
    match node {
        AstNode::Intrinsic { name, args } if name == FRAGMENT => match args.as_slice() {
            [value, AstNode::StringLiteral { text }] => Some((value, text)),
            _ => None,
        },
        _ => None,
    }
}

/// The System V argument registers, in order.
const SYSV_ARGUMENTS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

/// The structure passed by value in the parameter `index` of `function`,
/// `ty` of `size` bytes, as System V passes it: the parameter holds its
/// first eight bytes, and the parameter in the next argument register its
/// others. The notes say why it is not.
pub(crate) fn pass_by_value(
    function: &mut crate::lift::LiftedFunction,
    index: usize,
    ty: &Type,
    store: &TypeStore,
    registers: &[&str],
) -> Result<(), String> {
    let size = store.size_of(ty)?;
    let spelled = ty.spelled(store);
    let name = function.params[index].name.clone();
    let register = |variable: &crate::lift::Variable| {
        variable.placements.iter().find_map(|p| match p {
            Placement::Register { full, .. } => Some(full.clone()),
            _ => None,
        })
    };
    let first = register(&function.params[index])
        .and_then(|full| registers.iter().position(|r| *r == full))
        .ok_or_else(|| format!("{name} is in no argument register"))?;
    let second = if size > 8 {
        let Some(next) = registers.get(first + 1) else {
            return Err(format!(
                "{spelled} needs two registers and {name} is in the last, so it is passed in memory"
            ));
        };
        let at = function
            .params
            .iter()
            .position(|p| register(p).as_deref() == Some(*next));
        if let Some(at) = at {
            if function.params[at].fragment.is_some() {
                return Err(format!(
                    "{} holds a structure already",
                    function.params[at].name
                ));
            }
        }
        at
    } else {
        None
    };
    let low = size.min(8);
    function.params[index].fragment = Some(Fragment {
        of: spelled.clone(),
        offset: 0,
        size: low,
        members: store.members_in(ty, 0, low),
        whole: size <= 8,
        within: (size > 8).then(|| name.clone()),
        signed: false,
    });
    if let Some(at) = second {
        function.params[at].fragment = Some(Fragment {
            of: spelled,
            offset: 8,
            size: size - 8,
            members: store.members_in(ty, 8, size - 8),
            whole: false,
            within: Some(name),
            signed: false,
        });
    }
    Ok(())
}

/// The argument registers of `abi`, in order.
pub(crate) fn argument_registers(abi: crate::lift::Abi) -> &'static [&'static str] {
    match abi {
        crate::lift::Abi::SystemV => &SYSV_ARGUMENTS,
        crate::lift::Abi::Win64 => &["rcx", "rdx", "r8", "r9"],
    }
}

/// A value that is bytes of a structure: the structure's value `base`, of
/// type `of`; the `size` bytes at `offset` in it; held in a value `width`
/// bytes wide, of a signed type or not, the bytes above them their sign or
/// zeros.
#[derive(Debug, Clone)]
struct Piece {
    base: AstNode,
    of: Type,
    offset: u64,
    size: u64,
    width: u64,
    signed_ty: bool,
    sign_ext: bool,
}

impl Piece {
    /// The bytes held exactly: no wider than they are.
    fn exact(&self) -> bool {
        self.size == self.width
    }

    /// Whether the value above the bytes fits the bytes extended `signed`.
    fn extends(&self) -> bool {
        if self.exact() {
            self.signed_ty
        } else {
            self.sign_ext
        }
    }
}

/// What the function's variables are, for the fragments.
struct Reader<'a> {
    store: &'a TypeStore,
    /// Each variable's width in bytes, and whether its type is signed.
    widths: BTreeMap<String, (u64, bool)>,
    /// The variables that are a whole structure or union: a stack variable
    /// of one, a parameter one is passed in, a variable a whole one is
    /// assigned.
    structs: BTreeMap<String, Type>,
    /// The pointers to a structure or union, with the pointee.
    pointers: BTreeMap<String, Type>,
    /// The variables that hold a part of a structure another names: the
    /// structure's variable, its type, and the fragment.
    parts: BTreeMap<String, (String, Type, Fragment)>,
    /// The structures the calls to a function return, by its address.
    returns: &'a BTreeMap<u64, Type>,
}

/// The integer, enumeration or pointer type `ty` as a width in bytes and
/// whether it is signed; `None` for another type.
fn scalar_info(store: &TypeStore, ty: &Type) -> Option<(u64, bool)> {
    let size = store.size_of(ty).ok()?;
    match store.resolve(ty) {
        Type::Prim(p) if p.is_integer() => Some((size, p.is_signed())),
        Type::Pointer(_) => Some((size, false)),
        resolved => store
            .enumeration(resolved)
            .map(|(_, e)| (size, e.underlying.is_signed())),
    }
}

/// The width in bytes and the signedness of a C type spelled `text`.
fn text_info(store: &TypeStore, text: &str) -> Option<(u64, bool)> {
    scalar_info(store, &crate::ctype::parse_type(store, text).ok()?)
}

/// The integer type of `bytes` bytes, signed or not, as the lift spells it.
fn integer_name(bytes: u64, signed: bool) -> &'static str {
    let bits = u32::try_from(bytes * 8).unwrap_or(64);
    match (signed, bits) {
        (true, _) => crate::lift::type_name(bits),
        (false, 8) => "unsigned char",
        (false, 16) => "unsigned short",
        (false, 32) => "unsigned int",
        (false, _) => "unsigned long",
    }
}

impl Reader<'_> {
    /// The width and signedness of the value `node` is, when it says.
    fn info(&self, node: &AstNode) -> Option<(u64, bool)> {
        match node {
            AstNode::Cast { ty, .. } => text_info(self.store, ty),
            AstNode::Var { name } => self.widths.get(name).copied(),
            AstNode::Constant { width_bytes, .. } => Some((u64::from(*width_bytes), true)),
            AstNode::Binary { lhs, op, rhs } => match op {
                BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual
                | BinaryOp::LogicalAnd
                | BinaryOp::LogicalOr => Some((4, true)),
                BinaryOp::Shl | BinaryOp::Shr => self.info(lhs),
                _ => self.info(lhs).or_else(|| self.info(rhs)),
            },
            AstNode::Deref { target } => match target.as_ref() {
                AstNode::Cast { ty, .. } => {
                    let pointee = ty.trim_end().strip_suffix('*')?;
                    text_info(self.store, pointee.trim_end())
                }
                _ => None,
            },
            _ => {
                let (_, _, _, leaf) = self.located(node)?;
                scalar_info(self.store, &leaf)
            }
        }
    }

    /// The structure value `node` is part of, the structure's type, the
    /// offset of `node` in it and `node`'s own type: a structure variable
    /// itself, a pointee, a call's result, a member or element of one.
    fn located(&self, node: &AstNode) -> Option<(AstNode, Type, u64, Type)> {
        match node {
            AstNode::Var { name } => {
                let ty = self.structs.get(name)?;
                Some((node.clone(), ty.clone(), 0, ty.clone()))
            }
            AstNode::Deref { target } => match target.as_ref() {
                AstNode::Var { name } => {
                    let ty = self.pointers.get(name)?;
                    Some((node.clone(), ty.clone(), 0, ty.clone()))
                }
                _ => None,
            },
            AstNode::Call { callee, .. } => match callee.as_ref() {
                AstNode::FunctionName { address, .. } => {
                    let ty = self.returns.get(address)?;
                    Some((node.clone(), ty.clone(), 0, ty.clone()))
                }
                _ => None,
            },
            _ => {
                if let Some((base, field, arrow)) = crate::typed::member_of(node) {
                    let (root, of, offset, leaf) = if arrow {
                        let AstNode::Var { name } = base else {
                            return None;
                        };
                        let pointee = self.pointers.get(name)?;
                        let deref = AstNode::Deref {
                            target: Box::new(base.clone()),
                        };
                        (deref, pointee.clone(), 0, pointee.clone())
                    } else {
                        self.located(base)?
                    };
                    let (at, ty) = self
                        .store
                        .path_offset(&leaf, &[Step::Field(field.to_string())])?;
                    return Some((root, of, offset + at, ty));
                }
                if let Some((array, index)) = crate::stack_vars::indexed(node) {
                    let AstNode::Constant { value: index, .. } = index else {
                        return None;
                    };
                    // An element through a pointer is a structure itself.
                    if let AstNode::Var { name } = array {
                        if let Some(pointee) = self.pointers.get(name) {
                            return Some((node.clone(), pointee.clone(), 0, pointee.clone()));
                        }
                    }
                    let (root, of, offset, leaf) = self.located(array)?;
                    let (at, ty) = self.store.path_offset(&leaf, &[Step::Index(*index)])?;
                    return Some((root, of, offset + at, ty));
                }
                None
            }
        }
    }

    /// The structure an address points into, the structure's type and the
    /// offset: `&p`, `&p.y`, `(char *)&p + 4`, `a`, `(char *)a + 8`.
    fn address(&self, node: &AstNode) -> Option<(AstNode, Type, u64)> {
        match node {
            AstNode::AddressOf { target } => {
                let (root, of, offset, _) = self.located(target)?;
                Some((root, of, offset))
            }
            AstNode::Var { name } => {
                let pointee = self.pointers.get(name)?;
                let deref = AstNode::Deref {
                    target: Box::new(node.clone()),
                };
                Some((deref, pointee.clone(), 0))
            }
            AstNode::Binary {
                lhs,
                op: BinaryOp::Add,
                rhs,
            } => {
                let AstNode::Constant { value, .. } = rhs.as_ref() else {
                    return None;
                };
                let (root, of, offset) = self.address(lhs)?;
                Some((root, of, offset.checked_add(*value)?))
            }
            AstNode::Cast { target, .. } => self.address(target),
            // A member that is a pointer to a structure: `a->next`.
            other => {
                let (_, _, _, leaf) = self.located(other)?;
                let Type::Pointer(pointee) = self.store.resolve(&leaf) else {
                    return None;
                };
                self.store.composite(pointee)?;
                let deref = AstNode::Deref {
                    target: Box::new(other.clone()),
                };
                Some((deref, (**pointee).clone(), 0))
            }
        }
    }

    /// The bytes of a structure `node` is, when it is some.
    fn piece(&self, node: &AstNode) -> Option<Piece> {
        match node {
            AstNode::Var { name } => {
                if let Some(ty) = self.structs.get(name) {
                    let size = self.store.size_of(ty).ok()?;
                    // A structure held in an integer: the register's width
                    // and the type it is read with.
                    let (width, signed_ty) =
                        self.widths.get(name).copied().unwrap_or((size, false));
                    return Some(Piece {
                        base: node.clone(),
                        of: ty.clone(),
                        offset: 0,
                        size: size.min(width),
                        width,
                        signed_ty,
                        sign_ext: false,
                    });
                }
                let (holder, of, fragment) = self.parts.get(name)?;
                let (width, signed_ty) = *self.widths.get(name)?;
                Some(Piece {
                    base: AstNode::var(holder.clone()),
                    of: of.clone(),
                    offset: fragment.offset,
                    size: fragment.size.min(width),
                    width,
                    signed_ty,
                    sign_ext: fragment.signed,
                })
            }
            AstNode::Deref { target } => {
                if let AstNode::Cast {
                    ty,
                    target: address,
                } = target.as_ref()
                {
                    let pointee = ty.trim_end().strip_suffix('*')?.trim_end();
                    let (size, signed_ty) = text_info(self.store, pointee)?;
                    let (base, of, offset) = self.address(address)?;
                    return Some(Piece {
                        base,
                        of,
                        offset,
                        size,
                        width: size,
                        signed_ty,
                        sign_ext: false,
                    });
                }
                self.located_piece(node)
            }
            AstNode::Call { callee, .. } => {
                let AstNode::FunctionName { address, .. } = callee.as_ref() else {
                    return None;
                };
                let ty = self.returns.get(address)?;
                let size = self.store.size_of(ty).ok()?;
                Some(Piece {
                    base: node.clone(),
                    of: ty.clone(),
                    offset: 0,
                    size: size.min(8),
                    width: 8,
                    signed_ty: true,
                    sign_ext: false,
                })
            }
            AstNode::Cast { ty, target } => {
                let (width, signed_ty) = text_info(self.store, ty)?;
                let inner = self.piece(target)?;
                if width <= inner.width {
                    return Some(Piece {
                        size: inner.size.min(width),
                        width,
                        signed_ty,
                        ..inner
                    });
                }
                // Widened: the value above the bytes is extended by the
                // inner value's own type.
                if !inner.exact() && inner.sign_ext && !inner.signed_ty {
                    return None;
                }
                let sign_ext = inner.extends();
                Some(Piece {
                    width,
                    signed_ty,
                    sign_ext,
                    ..inner
                })
            }
            AstNode::Binary {
                lhs,
                op: BinaryOp::Shr,
                rhs,
            } => {
                let AstNode::Constant { value: bits, .. } = rhs.as_ref() else {
                    return None;
                };
                if bits % 8 != 0 {
                    return None;
                }
                let bytes = bits / 8;
                let inner = self.piece(lhs)?;
                if bytes >= inner.size {
                    return None;
                }
                // What comes in from the top: the sign for a signed type,
                // zeros for an unsigned one.
                let fill = inner.signed_ty;
                if !inner.exact() && inner.sign_ext && !fill {
                    return None;
                }
                let sign_ext = if inner.exact() { fill } else { inner.sign_ext };
                Some(Piece {
                    offset: inner.offset + bytes,
                    size: inner.size - bytes,
                    sign_ext,
                    ..inner
                })
            }
            AstNode::Binary {
                lhs,
                op: BinaryOp::And,
                rhs,
            } => {
                let (value, mask) = match (lhs.as_ref(), rhs.as_ref()) {
                    (value, AstNode::Constant { value: mask, .. })
                    | (AstNode::Constant { value: mask, .. }, value) => (value, *mask),
                    _ => return None,
                };
                let bytes = match mask {
                    0xff => 1,
                    0xffff => 2,
                    0xffff_ffff => 4,
                    _ => return None,
                };
                let inner = self.piece(value)?;
                if bytes >= inner.width {
                    return None;
                }
                if bytes <= inner.size {
                    return Some(Piece {
                        size: bytes,
                        sign_ext: false,
                        ..inner
                    });
                }
                (!inner.sign_ext).then_some(Piece {
                    sign_ext: false,
                    ..inner
                })
            }
            AstNode::Binary {
                op: BinaryOp::Or, ..
            } => self.joined(node),
            _ => self.located_piece(node),
        }
    }

    /// A member or element of a structure, or a whole one, as bytes of it.
    fn located_piece(&self, node: &AstNode) -> Option<Piece> {
        let (base, of, offset, leaf) = self.located(node)?;
        let size = self.store.size_of(&leaf).ok()?;
        let signed_ty = scalar_info(self.store, &leaf).is_some_and(|(_, s)| s);
        Some(Piece {
            base,
            of,
            offset,
            size,
            width: size,
            signed_ty,
            sign_ext: false,
        })
    }

    /// `(long)b << 32 | (unsigned int)a`: neighbouring bytes of one
    /// structure joined, each at the place in the value its offset gives it.
    fn joined(&self, node: &AstNode) -> Option<Piece> {
        let mut terms = Vec::new();
        or_terms(node, &mut terms);
        let width = self.info(node).map(|(w, _)| w)?;
        let mut placed: Vec<(u64, Piece)> = Vec::new();
        for term in terms {
            let (value, at) = match term {
                AstNode::Binary {
                    lhs,
                    op: BinaryOp::Shl,
                    rhs,
                } => match rhs.as_ref() {
                    AstNode::Constant { value: bits, .. } if bits % 8 == 0 => {
                        (lhs.as_ref(), bits / 8)
                    }
                    _ => return None,
                },
                other => (other, 0),
            };
            let piece = self.piece(value)?;
            // The bytes above the piece's, up to the top, are shifted out or
            // zeros.
            let zeros = piece.width == width && !piece.exact() && !piece.sign_ext;
            if at + piece.size < width && !zeros {
                return None;
            }
            placed.push((at, piece));
        }
        placed.sort_by_key(|(at, _)| *at);
        let (first_at, first) = placed.first()?.clone();
        if first_at != 0 || placed.len() < 2 {
            return None;
        }
        let mut end = 0u64;
        for (at, piece) in &placed {
            if *at != end
                || piece.base != first.base
                || piece.of != first.of
                || piece.offset != first.offset + at
            {
                return None;
            }
            end = at + piece.size;
        }
        if end > width {
            return None;
        }
        Some(Piece {
            size: end,
            width,
            signed_ty: self.info(node).is_some_and(|(_, s)| s),
            sign_ext: false,
            ..first
        })
    }

    /// The node a member path of `base` is: `p.inner.g`, `a->y`, `make(b).y`.
    fn path_node(&self, base: &AstNode, path: &[Step]) -> AstNode {
        if let AstNode::Deref { target } = base {
            if let Some((Step::Field(name), rest)) = path.split_first() {
                let first = crate::typed::member((**target).clone(), name, true);
                return crate::stack_vars::parts_node(first, rest);
            }
        }
        crate::stack_vars::parts_node(base.clone(), path)
    }

    /// The text a member path of `base` is, for an annotation: `p.x`,
    /// `a->x`.
    fn path_text(&self, base: &AstNode, path: &str) -> String {
        match base {
            AstNode::Deref { target } => match target.as_ref() {
                AstNode::Var { name } => format!("{name}->{path}"),
                other => format!("{}->{path}", crate::emit::emit_node_c(other).trim()),
            },
            AstNode::Var { name } => format!("{name}.{path}"),
            other => format!("{}.{path}", crate::emit::emit_node_c(other).trim()),
        }
    }

    /// The member a piece is exactly, read with the casts its width needs.
    fn member(&self, piece: &Piece) -> Option<AstNode> {
        let (path, leaf) = self.store.field_at(&piece.of, piece.offset, piece.size)?;
        if path.is_empty() {
            return None;
        }
        let (_, leaf_signed) = scalar_info(self.store, &leaf)?;
        let member = self.path_node(&piece.base, &path);
        if piece.exact() {
            return Some(member);
        }
        // Held wider: the member widened as the machine widened it, to the
        // type the value has — which C's promotion to `int` gives a
        // narrower one.
        let extended = if piece.sign_ext == leaf_signed {
            member
        } else {
            AstNode::Cast {
                ty: integer_name(piece.size, piece.sign_ext).to_string(),
                target: Box::new(member),
            }
        };
        if piece.width <= 4 {
            return Some(extended);
        }
        Some(AstNode::Cast {
            ty: integer_name(piece.width, piece.signed_ty).to_string(),
            target: Box::new(extended),
        })
    }

    /// A load or store of several members where it stands: the bytes from
    /// the first member, annotated with the members.
    fn spanning(&self, piece: &Piece, ty: &str) -> Option<AstNode> {
        let total = self.store.size_of(&piece.of).ok()?;
        if !piece.exact() || (piece.offset == 0 && piece.size == total) {
            return None;
        }
        let members = self.store.members_in(&piece.of, piece.offset, piece.size);
        if members.len() < 2 {
            return None;
        }
        let path = [1u64, 2, 4, 8, 16].iter().find_map(|&k| {
            let (path, leaf) = self.store.field_at(&piece.of, piece.offset, k)?;
            (!path.is_empty() && scalar_info(self.store, &leaf).is_some()).then_some(path)
        })?;
        let start = self.path_node(&piece.base, &path);
        let load = AstNode::Deref {
            target: Box::new(AstNode::Cast {
                ty: ty.to_string(),
                target: Box::new(AstNode::AddressOf {
                    target: Box::new(start),
                }),
            }),
        };
        let text = members
            .iter()
            .map(|member| self.path_text(&piece.base, member))
            .collect::<Vec<_>>()
            .join(", ");
        Some(annotated(load, &text))
    }

    /// `node` read for its fragments, outermost first.
    fn read(&self, node: AstNode) -> AstNode {
        crate::inline::map_outer(node, &mut |n| self.read_one(n))
    }

    fn read_one(&self, node: &AstNode) -> Option<AstNode> {
        let candidate = match node {
            AstNode::Cast { .. } | AstNode::Deref { .. } => true,
            AstNode::Binary { op, .. } => {
                matches!(op, BinaryOp::Shr | BinaryOp::And | BinaryOp::Or)
            }
            AstNode::Var { name } => {
                self.parts.contains_key(name)
                    || (self.structs.contains_key(name) && self.widths.contains_key(name))
            }
            _ => false,
        };
        if !candidate || annotation_of(node).is_some() {
            return None;
        }
        let piece = self.piece(node)?;
        if let Some(member) = self.member(&piece) {
            return Some(member);
        }
        if let AstNode::Deref { target } = node {
            if let AstNode::Cast { ty, .. } = target.as_ref() {
                return self.spanning(&piece, ty);
            }
        }
        None
    }

    /// A whole structure, as the value it is copied as.
    fn whole(&self, piece: &Piece) -> Option<AstNode> {
        let total = self.store.size_of(&piece.of).ok()?;
        (piece.offset == 0 && piece.size == total && piece.exact()).then(|| piece.base.clone())
    }

    /// An assignment read for its fragments: a whole structure copied, a
    /// member stored, the bytes of several.
    fn assignment(&self, lhs: AstNode, rhs: AstNode) -> AstNode {
        let to = match &lhs {
            AstNode::Var { name } if !self.structs.contains_key(name) => None,
            other => self.piece(other),
        };
        let from = self.piece(&rhs);
        // A whole structure copied: `q = p;`, `v = make(a, 5);`.
        if let (Some(to), Some(from)) = (&to, &from) {
            if to.of == from.of {
                if let (Some(target), Some(value)) = (self.whole(to), self.whole(from)) {
                    return AstNode::Assign {
                        lhs: Box::new(target),
                        rhs: Box::new(value),
                    };
                }
            }
        }
        let target = match &lhs {
            AstNode::Var { .. } => lhs,
            other => self.read(other.clone()),
        };
        AstNode::Assign {
            lhs: Box::new(target),
            rhs: Box::new(self.read(rhs)),
        }
    }

    fn statement_node(&self, node: AstNode) -> AstNode {
        match node {
            AstNode::Assign { lhs, rhs } => self.assignment(*lhs, *rhs),
            other => self.read(other),
        }
    }

    fn statements(&self, statements: &mut Vec<Statement>) {
        for statement in statements.iter_mut() {
            statement.node =
                self.statement_node(std::mem::replace(&mut statement.node, AstNode::Break));
            if let StatementKind::For { init, step, .. } = &mut statement.kind {
                init.node = self.statement_node(std::mem::replace(&mut init.node, AstNode::Break));
                step.node = self.statement_node(std::mem::replace(&mut step.node, AstNode::Break));
            }
            for child in statement.children_mut() {
                self.statements(child);
            }
        }
        self.copies(statements);
    }

    /// The runs of member stores that copy a whole structure from one
    /// source, in order, each made the one copy: `q = p;`.
    fn copies(&self, statements: &mut Vec<Statement>) {
        let mut out: Vec<Statement> = Vec::with_capacity(statements.len());
        let taken = std::mem::take(statements);
        let mut i = 0;
        while i < taken.len() {
            if let Some((end, copy)) = self.copy_run(&taken, i) {
                out.push(copy);
                i = end;
                continue;
            }
            out.push(taken[i].clone());
            i += 1;
        }
        *statements = out;
    }

    /// The copy the stores from `start` make, and where they end.
    fn copy_run(&self, statements: &[Statement], start: usize) -> Option<(usize, Statement)> {
        let mut covered = 0u64;
        let mut first: Option<(Piece, Piece)> = None;
        let mut addresses = Vec::new();
        for (i, statement) in statements.iter().enumerate().skip(start) {
            let stored = match (&statement.kind, &statement.node) {
                (StatementKind::Plain, AstNode::Assign { lhs, rhs }) => {
                    match (self.piece(lhs), self.piece(rhs)) {
                        (Some(to), Some(from)) if to.exact() && from.exact() => Some((to, from)),
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some((to, from)) = stored else {
                break;
            };
            let total = self.store.size_of(&to.of).ok()?;
            let fits = to.of == from.of
                && to.offset == from.offset
                && to.size == from.size
                && to.base != from.base
                && first
                    .as_ref()
                    .is_none_or(|(t, f)| t.base == to.base && f.base == from.base)
                && self.padding_to(&to.of, covered, to.offset)
                && (to.offset, to.size) != (0, total);
            if !fits {
                break;
            }
            first.get_or_insert_with(|| (to.clone(), from.clone()));
            addresses.extend(statement.addresses.iter().copied());
            covered = to.offset + to.size;
            if self.padding_to(&to.of, covered, total) && i > start {
                let (to, from) = first.expect("set above");
                addresses.sort_unstable();
                addresses.dedup();
                let copy = Statement::plain(
                    AstNode::Assign {
                        lhs: Box::new(to.base),
                        rhs: Box::new(from.base),
                    },
                    addresses,
                );
                return Some((i + 1, copy));
            }
        }
        None
    }

    /// Whether the bytes `[from, to)` of `ty` are padding: no member's.
    fn padding_to(&self, ty: &Type, from: u64, to: u64) -> bool {
        from == to || (from < to && self.store.members_in(ty, from, to - from).is_empty())
    }
}

/// The terms of an `|`, in order.
fn or_terms<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    match node {
        AstNode::Binary {
            lhs,
            op: BinaryOp::Or,
            rhs,
        } => {
            or_terms(lhs, out);
            or_terms(rhs, out);
        }
        other => out.push(other),
    }
}

/// A statement node of the body: the index of the statement at the top of
/// the body it is in, whether it is that statement's own, and the node.
type Site<'a> = (usize, bool, &'a AstNode);

/// Every statement node of the body `statements`, each with its site.
fn each_node(statements: &[Statement]) -> Vec<Site<'_>> {
    fn inner<'a>(statements: &'a [Statement], at: usize, out: &mut Vec<Site<'a>>) {
        for statement in statements {
            out.push((at, false, &statement.node));
            if let StatementKind::For { init, step, .. } = &statement.kind {
                out.push((at, false, &init.node));
                out.push((at, false, &step.node));
            }
            for child in statement.children() {
                inner(child, at, out);
            }
        }
    }
    let mut out = Vec::new();
    for (at, statement) in statements.iter().enumerate() {
        out.push((at, true, &statement.node));
        if let StatementKind::For { init, step, .. } = &statement.kind {
            out.push((at, false, &init.node));
            out.push((at, false, &step.node));
        }
        for child in statement.children() {
            inner(child, at, &mut out);
        }
    }
    out
}

/// The values assigned to the variable `name` at `sites`, each with its
/// site.
fn definitions<'a>(sites: &[Site<'a>], name: &str) -> Vec<(usize, bool, &'a AstNode)> {
    sites
        .iter()
        .filter_map(|&(at, top, node)| match node {
            AstNode::Assign { lhs, rhs }
                if matches!(lhs.as_ref(), AstNode::Var { name: n } if n == name) =>
            {
                Some((at, top, rhs.as_ref()))
            }
            _ => None,
        })
        .collect()
}

/// Whether a node writes the variable `name` or a part of it, or lets its
/// address go where a store or call may write through it.
fn writes(node: &AstNode, name: &str) -> bool {
    let named = |n: &AstNode| n.any(&|m| matches!(m, AstNode::Var { name: v } if v == name));
    node.any(&|n| match n {
        AstNode::Assign { lhs, rhs } => {
            (!matches!(lhs.as_ref(), AstNode::Var { .. }) && named(lhs))
                || matches!(lhs.as_ref(), AstNode::Var { name: v } if v == name)
                || matches!(rhs.as_ref(), AstNode::AddressOf { target } if named(target))
        }
        AstNode::Call { args, .. } => args
            .iter()
            .any(|arg| matches!(crate::slice::strip_casts(arg), AstNode::AddressOf { target } if named(target))),
        _ => false,
    })
}

/// Whether every read of the variable `name` in `node` is the base of a
/// member, a copy of the whole, an argument or a returned value — the reads
/// a variable declared as its structure is read with.
fn bare_read(node: &AstNode, name: &str, whole_allowed: bool) -> bool {
    let is_name = |n: &AstNode| matches!(n, AstNode::Var { name: v } if v == name);
    match node {
        AstNode::Var { .. } => is_name(node) && !whole_allowed,
        AstNode::Assign { lhs, rhs } => {
            (!is_name(lhs) && bare_read(lhs, name, false)) || bare_read(rhs, name, true)
        }
        AstNode::Call { callee, args } => {
            bare_read(callee, name, false) || args.iter().any(|arg| bare_read(arg, name, true))
        }
        AstNode::Return { value } => value.as_deref().is_some_and(|v| bare_read(v, name, true)),
        _ => {
            if let Some((base, _, false)) = crate::typed::member_of(node) {
                if is_name(base) {
                    return false;
                }
            }
            let mut found = false;
            crate::inline::each_child(node, &mut |child| {
                found |= bare_read(child, name, false);
            });
            found
        }
    }
}

/// What a local of the function is found to hold.
enum Found {
    /// Exactly a member of pointer or enumeration type: the variable takes
    /// its type.
    Typed(String, Type),
    /// Bytes of a structure.
    Held(String, Fragment),
}

/// Read the fragments of the body of `function`: the bytes of structures
/// its values and variables are ([`crate::fragments`]). `returns` are the
/// structures the functions it calls return, by their addresses. Whether a
/// variable took a pointer or enumeration type from a member, so the
/// members through it are to be read again.
pub(crate) fn read(
    function: &mut LiftedFunction,
    store: &TypeStore,
    returns: &BTreeMap<u64, Type>,
) -> bool {
    if function.thunk.is_some() || (store.keys().is_empty() && returns.is_empty()) {
        return false;
    }
    let mut reader = Reader {
        store,
        widths: BTreeMap::new(),
        structs: BTreeMap::new(),
        pointers: BTreeMap::new(),
        parts: BTreeMap::new(),
        returns,
    };
    let original = function.body.clone();
    let sites = each_node(&original);
    let written = |name: &str| sites.iter().any(|(_, _, node)| writes(node, name));
    for variable in function.params.iter().chain(&function.locals) {
        let Ok(ty) = crate::ctype::parse_type(store, &variable.ty) else {
            continue;
        };
        if let Some(info) = scalar_info(store, &ty) {
            reader.widths.insert(variable.name.clone(), info);
        }
        if store.composite(&ty).is_some() {
            reader.structs.insert(variable.name.clone(), ty.clone());
        }
        if let Type::Pointer(pointee) = store.resolve(&ty) {
            if store.composite(pointee).is_some() {
                reader
                    .pointers
                    .insert(variable.name.clone(), (**pointee).clone());
            }
        }
    }
    // The structures the parameters are passed in — while the body leaves
    // their registers as they came — and the fragments found before.
    for variable in function.params.iter().chain(&function.locals) {
        let Some(fragment) = &variable.fragment else {
            continue;
        };
        let Ok(of) = crate::ctype::parse_type(store, &fragment.of) else {
            continue;
        };
        if store.composite(&of).is_none() {
            continue;
        }
        let param = function.params.iter().any(|p| p.name == variable.name);
        if param && written(&variable.name) {
            continue;
        }
        if fragment.whole {
            reader.structs.insert(variable.name.clone(), of);
            continue;
        }
        let Some(within) = &fragment.within else {
            continue;
        };
        if param && written(within) {
            continue;
        }
        reader.parts.insert(
            variable.name.clone(),
            (within.clone(), of, fragment.clone()),
        );
    }
    // The locals assigned a fragment.
    let mut found: Vec<Found> = Vec::new();
    for local in &function.locals {
        if local.fragment.is_some()
            || reader.structs.contains_key(&local.name)
            || reader.pointers.contains_key(&local.name)
            || local
                .placements
                .iter()
                .any(|p| matches!(p, Placement::Stack { .. }))
        {
            continue;
        }
        let Some(&(width, _)) = reader.widths.get(&local.name) else {
            continue;
        };
        let defs = definitions(&sites, &local.name);
        let pieces: Option<Vec<Piece>> = defs.iter().map(|(_, _, rhs)| reader.piece(rhs)).collect();
        let Some(pieces) = pieces.filter(|p| !p.is_empty()) else {
            continue;
        };
        let first = &pieces[0];
        if first.width != width
            || pieces.iter().any(|p| {
                p.of != first.of
                    || p.offset != first.offset
                    || p.size != first.size
                    || p.exact() != first.exact()
                    || (!p.exact() && p.sign_ext != first.sign_ext)
            })
        {
            continue;
        }
        let total = store.size_of(&first.of).unwrap_or(0);
        let whole = first.offset == 0 && first.size == total && first.exact();
        if let Some((path, leaf)) = store.field_at(&first.of, first.offset, first.size) {
            if first.exact() && !path.is_empty() {
                let pointer = matches!(store.resolve(&leaf), Type::Pointer(_));
                if pointer || store.enumeration(&leaf).is_some() {
                    found.push(Found::Typed(local.name.clone(), leaf));
                    continue;
                }
                // An integer member is the integer the variable is.
                if matches!(store.resolve(&leaf), Type::Prim(p) if p.is_integer()) {
                    continue;
                }
            }
        }
        // A part of a structure's variable reads as its members where the
        // part is assigned once, at the top of the body, and the structure
        // is not written from there on.
        let within = match (&first.base, defs.as_slice()) {
            (AstNode::Var { name }, [(at, true, _)])
                if !whole
                    && reader.structs.contains_key(name)
                    && !sites
                        .iter()
                        .any(|(i, _, node)| i >= at && writes(node, name)) =>
            {
                Some(name.clone())
            }
            _ => None,
        };
        found.push(Found::Held(
            local.name.clone(),
            Fragment {
                of: first.of.spelled(store),
                offset: first.offset,
                size: first.size,
                members: store.members_in(&first.of, first.offset, first.size),
                whole,
                within,
                signed: !first.exact() && first.sign_ext,
            },
        ));
    }
    for found in &found {
        let Found::Held(name, fragment) = found else {
            continue;
        };
        let Ok(of) = crate::ctype::parse_type(store, &fragment.of) else {
            continue;
        };
        if fragment.whole {
            reader.structs.insert(name.clone(), of);
        } else if let Some(within) = &fragment.within {
            reader
                .parts
                .insert(name.clone(), (within.clone(), of, fragment.clone()));
        }
    }
    // A variable that holds a whole structure is declared as the
    // structure only where every read of it is one a structure is read
    // with; another stays its integer.
    let mut body = original.clone();
    reader.statements(&mut body);
    let demoted: Vec<String> = found
        .iter()
        .filter_map(|found| match found {
            Found::Held(name, fragment)
                if fragment.whole
                    && each_node(&body)
                        .iter()
                        .any(|(_, _, node)| bare_read(node, name, false)) =>
            {
                Some(name.clone())
            }
            _ => None,
        })
        .collect();
    if !demoted.is_empty() {
        for name in &demoted {
            reader.structs.remove(name);
        }
        body = original;
        reader.statements(&mut body);
    }
    function.body = body;
    let mut retyped = false;
    for found in found {
        match found {
            Found::Typed(name, leaf) => {
                if let Some(local) = function.locals.iter_mut().find(|l| l.name == name) {
                    local.ty = leaf.spelled(store);
                    retyped = true;
                }
            }
            Found::Held(name, mut fragment) => {
                if let Some(local) = function.locals.iter_mut().find(|l| l.name == name) {
                    if demoted.contains(&name) {
                        fragment.whole = false;
                    }
                    local.fragment = Some(fragment);
                }
            }
        }
    }
    retyped
}
