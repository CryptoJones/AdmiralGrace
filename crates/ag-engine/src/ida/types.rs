//! IDA's packed types, deserialized and rendered as C.
//!
//! A type is a byte string: a leading byte names the base type and its
//! flags, and what follows depends on it — a pointer's pointee, an array's
//! count and element, a function's convention, return and arguments, a
//! structure's members, an enumeration's values, a typedef's target. The
//! integers are packed (`dt`, `de`, `da`); attributes (`tah`, `sdacl`) ride
//! along and are read past. The tree is then turned into the engine's own
//! [`crate::types::Type`] and spelled with its declarator rules, so the C
//! the project keeps is the C the engine reads back.

use crate::types::{self as et, DataModel, Prim, TypeStore};

use super::til::{Til, TypeRecord};

/// Why a type did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeError(pub String);

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TypeError {}

fn err<T>(message: impl Into<String>) -> Result<T, TypeError> {
    Err(TypeError(message.into()))
}

// The base types (the low nibble of the leading byte).
const BT_UNK: u8 = 0x00;
const BT_VOID: u8 = 0x01;
const BT_INT8: u8 = 0x02;
const BT_INT16: u8 = 0x03;
const BT_INT32: u8 = 0x04;
const BT_INT64: u8 = 0x05;
const BT_INT128: u8 = 0x06;
const BT_INT: u8 = 0x07;
const BT_BOOL: u8 = 0x08;
const BT_FLOAT: u8 = 0x09;
const BT_PTR: u8 = 0x0A;
const BT_ARRAY: u8 = 0x0B;
const BT_FUNC: u8 = 0x0C;
const BT_COMPLEX: u8 = 0x0D;
const BT_BITFIELD: u8 = 0x0E;
const BT_RESERVED: u8 = 0x0F;

// The flags (bits 4-5 of the leading byte).
const BTMT_SIZE12: u8 = 0x10;
const BTMT_SIZE48: u8 = 0x20;
const BTMT_SIZE128: u8 = 0x30;
const BTMT_USIGNED: u8 = 0x20;
const BTMT_CHAR: u8 = 0x30;
const BTMT_NONBASED: u8 = 0x10;
const BTMT_CLOSURE: u8 = 0x30;
const BTMT_STRUCT: u8 = 0x00;
const BTMT_UNION: u8 = 0x10;
const BTMT_ENUM: u8 = 0x20;
const BTMT_TYPEDEF: u8 = 0x30;

const TYPE_BASE_MASK: u8 = 0x0F;
const TYPE_FLAGS_MASK: u8 = 0x30;
const TYPE_FULL_MASK: u8 = TYPE_BASE_MASK | TYPE_FLAGS_MASK;
const TYPE_MODIF_MASK: u8 = 0xC0;

const BTF_STRUCT: u8 = BT_COMPLEX | BTMT_STRUCT;
const BTF_UNION: u8 = BT_COMPLEX | BTMT_UNION;
const BTF_ENUM: u8 = BT_COMPLEX | BTMT_ENUM;
const BTF_TYPEDEF: u8 = BT_COMPLEX | BTMT_TYPEDEF;

const TAH_BYTE: u8 = 0xFE;
const TAH_HASATTRS: u32 = 0x0010;
const TAENUM_64BIT: u32 = 0x0020;
const BTE_BITFIELD: u8 = 0x10;
const FAH_BYTE: u8 = 0xFF;
const RESERVED_BYTE: u8 = 0xFF;

// The calling conventions (the high nibble of a function's cm byte).
const CM_CC_MASK: u8 = 0xF0;
const CM_CC_VOIDARG: u8 = 0x20;
const CM_CC_CDECL: u8 = 0x30;
const CM_CC_ELLIPSIS: u8 = 0x40;
const CM_CC_STDCALL: u8 = 0x50;
const CM_CC_FASTCALL: u8 = 0x70;
const CM_CC_THISCALL: u8 = 0x80;
const CM_CC_SPOILED: u8 = 0xA0;
const CM_CC_SPECIALE: u8 = 0xD0;
const CM_CC_SPECIALP: u8 = 0xE0;
const CM_CC_SPECIAL: u8 = 0xF0;

fn base_of(t: u8) -> u8 {
    t & TYPE_BASE_MASK
}
fn flags_of(t: u8) -> u8 {
    t & TYPE_FLAGS_MASK
}
fn full_of(t: u8) -> u8 {
    t & TYPE_FULL_MASK
}
fn is_typeid_last(t: u8) -> bool {
    base_of(t) <= BT_FLOAT
}
fn is_tah_byte(t: u8) -> bool {
    t == TAH_BYTE
}
fn is_sdacl_byte(t: u8) -> bool {
    ((t & !TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID
}

/// A deserialized IDA type.
#[derive(Debug, Clone)]
pub enum IdaType {
    /// A basic type, by its base and flags.
    Prim { base: u8, flags: u8 },
    /// A pointer to a type.
    Ptr(Box<IdaType>),
    /// An array of a count (0 when unknown).
    Array(Box<IdaType>, u64),
    /// A function: its return, its arguments and its calling convention.
    Func {
        ret: Box<IdaType>,
        args: Vec<(IdaType, Option<String>)>,
        cc: u8,
    },
    /// A structure or union and its members.
    Udt {
        is_union: bool,
        members: Vec<Member>,
        pack: u32,
    },
    /// An enumeration and its values.
    Enum {
        members: Vec<(String, i64)>,
        bte: u8,
        is64: bool,
    },
    /// A typedef, to a name or an ordinal.
    Typedef {
        name: Option<String>,
        ordinal: Option<u64>,
    },
    /// A bit-field of a width in bits.
    Bitfield {
        nbytes: u32,
        width: u32,
        unsigned: bool,
    },
}

/// One member of a structure or union.
#[derive(Debug, Clone)]
pub struct Member {
    /// The member's type.
    pub ty: IdaType,
    /// The member's name, when the record names it.
    pub name: Option<String>,
}

/// Deserialize a type from its packed bytes, with the field or argument
/// names the record carries.
pub fn deserialize(type_info: &[u8], fields: &[String]) -> Result<IdaType, TypeError> {
    let mut ts = TypeString::new(type_info);
    create(&mut ts, fields)
}

/// Read one type off the cursor.
fn create(ts: &mut TypeString, fields: &[String]) -> Result<IdaType, TypeError> {
    let typ = ts.peek_u8()?;
    if is_typeid_last(typ) || base_of(typ) == BT_RESERVED {
        ts.seek(1)?;
        return Ok(IdaType::Prim {
            base: base_of(typ),
            flags: flags_of(typ),
        });
    }
    match base_of(typ) {
        BT_PTR => pointer(ts, fields),
        BT_ARRAY => array(ts, fields),
        BT_FUNC => function(ts, fields),
        BT_COMPLEX => match full_of(typ) {
            BTF_TYPEDEF => typedef(ts),
            BTF_STRUCT | BTF_UNION => udt(ts, fields),
            BTF_ENUM => enumeration(ts, fields),
            _ => err(format!("unknown complex type {typ:#x}")),
        },
        BT_BITFIELD => bitfield(ts),
        other => err(format!("unknown base type {other:#x}")),
    }
}

fn pointer(ts: &mut TypeString, fields: &[String]) -> Result<IdaType, TypeError> {
    let typ = ts.u8()?;
    if flags_of(typ) == BTMT_CLOSURE {
        let next = ts.u8()?;
        if next == RESERVED_BYTE {
            let _closure = create(ts, fields)?;
        } else {
            let _based_size = ts.u8()?;
        }
    }
    ts.tah_attr()?;
    let pointee = create(ts, fields)?;
    Ok(IdaType::Ptr(Box::new(pointee)))
}

fn array(ts: &mut TypeString, fields: &[String]) -> Result<IdaType, TypeError> {
    let typ = ts.u8()?;
    let n_elems = if flags_of(typ) & BTMT_NONBASED != 0 {
        ts.dt()? as u64
    } else {
        let (_, nelem, _) = ts.da()?;
        nelem
    };
    ts.tah_attr()?;
    let elem = create(ts, fields)?;
    Ok(IdaType::Array(Box::new(elem), n_elems))
}

fn function(ts: &mut TypeString, fields: &[String]) -> Result<IdaType, TypeError> {
    let typ = ts.u8()?;
    let _ = typ;
    // Spoiled-register lists precede the convention byte.
    let mut cm = ts.peek_u8()?;
    while cm & CM_CC_MASK == CM_CC_SPOILED {
        ts.seek(1)?;
        let nspoiled = cm & !CM_CC_MASK;
        if nspoiled == 15 {
            let _ = ts.u8()?;
        } else {
            for _ in 0..nspoiled {
                let b = ts.u8()?;
                if b & 0x80 != 0 {
                    let _size = ts.u8()?;
                }
            }
        }
        cm = ts.peek_u8()?;
    }
    let cc = ts.u8()?;
    ts.tah_attr()?;
    let ret = create(ts, fields)?;
    let special = matches!(
        cc & CM_CC_MASK,
        CM_CC_SPECIAL | CM_CC_SPECIALP | CM_CC_SPECIALE
    );
    if special && !is_void(&ret) {
        argloc(ts)?;
    }
    let mut args = Vec::new();
    if cc & CM_CC_MASK == CM_CC_VOIDARG {
        return Ok(IdaType::Func {
            ret: Box::new(ret),
            args,
            cc,
        });
    }
    let n = ts.dt()?;
    for i in 0..n {
        if ts.has_next() && ts.peek_u8()? == FAH_BYTE {
            ts.seek(1)?;
            let _flags = ts.de()?;
        }
        let name = fields.get(i as usize).cloned();
        let arg = create(ts, fields)?;
        if special {
            argloc(ts)?;
        }
        args.push((arg, name));
    }
    Ok(IdaType::Func {
        ret: Box::new(ret),
        args,
        cc,
    })
}

/// Read past an argument location (the special calling conventions).
fn argloc(ts: &mut TypeString) -> Result<(), TypeError> {
    let t = ts.u8()?;
    if t == 0xFF {
        let typ = ts.dt()?;
        let typ0 = typ & 0xF;
        match typ0 {
            1 | 2 => {
                let _sval = ts.de()?;
            }
            3 => {
                let n = (typ >> 5) & 0x7;
                for _ in 0..n {
                    let _reg = ts.dt()?;
                    let _off = ts.dt()?;
                    let _size = ts.dt()?;
                }
            }
            4 => {
                let _r1 = ts.dt()?;
                let _r2 = ts.dt()?;
            }
            5 => {
                let _reg = ts.dt()?;
            }
            6 => {
                let _reg = ts.dt()?;
                let _off = ts.de()?;
            }
            _ => {}
        }
    } else if t > 0x80 {
        let _c = ts.u8()?;
    }
    Ok(())
}

fn udt(ts: &mut TypeString, fields: &[String]) -> Result<IdaType, TypeError> {
    let typ = ts.u8()?;
    let is_union = full_of(typ) == BTF_UNION;
    let mut n = ts.dt()?;
    if n == 0 {
        // A reference to a type defined elsewhere; read past it.
        let _ref = ts.pbytes()?;
        ts.sdacl_attr()?;
        return Ok(IdaType::Udt {
            is_union,
            members: Vec::new(),
            pack: 0,
        });
    }
    if n == 0x7FFE {
        n = ts.de()? as u32;
    }
    let alpow = n & 7;
    let member_cnt = n >> 3;
    let pack = if alpow == 0 { 0 } else { 1 << (alpow - 1) };
    ts.sdacl_attr()?;
    let mut members = Vec::new();
    let mut field_i = 0;
    for _ in 0..member_cnt {
        let ty = create(ts, fields)?;
        let attr = if !is_union { ts.sdacl_attr()? } else { 0 };
        let is_baseclass = attr & 0x0020 != 0;
        let name = if !is_baseclass {
            let name = fields.get(field_i).cloned();
            field_i += 1;
            name
        } else {
            None
        };
        members.push(Member { ty, name });
    }
    Ok(IdaType::Udt {
        is_union,
        members,
        pack,
    })
}

fn enumeration(ts: &mut TypeString, fields: &[String]) -> Result<IdaType, TypeError> {
    let typ = ts.u8()?;
    let _ = typ;
    let mut n = ts.dt()?;
    if n == 0 {
        let _ref = ts.pbytes()?;
        ts.sdacl_attr()?;
        return Ok(IdaType::Enum {
            members: Vec::new(),
            bte: 0,
            is64: false,
        });
    }
    if n == 0x7FFE {
        n = ts.de()? as u32;
    }
    let taenum = ts.tah_attr()?;
    let bte = ts.u8()?;
    let is64 = taenum & TAENUM_64BIT != 0;
    let mut members = Vec::new();
    let mut cur: i64 = 0;
    for i in 0..n {
        let lo = ts.de()?;
        let hi = if is64 { ts.de()? } else { 0 };
        if bte & BTE_BITFIELD != 0 {
            let _group = ts.dt()?;
        }
        cur = cur.wrapping_add((lo | (hi << 32)) as i64);
        let name = fields.get(i as usize).cloned().unwrap_or_default();
        members.push((name, cur));
    }
    Ok(IdaType::Enum { members, bte, is64 })
}

fn typedef(ts: &mut TypeString) -> Result<IdaType, TypeError> {
    let _typ = ts.u8()?;
    let buf = ts.pbytes()?;
    if buf.first() == Some(&b'#') {
        let mut inner = TypeString::new(&buf[1..]);
        let ordinal = inner.de()?;
        Ok(IdaType::Typedef {
            name: None,
            ordinal: Some(ordinal),
        })
    } else {
        let name = String::from_utf8_lossy(&buf).into_owned();
        Ok(IdaType::Typedef {
            name: Some(name),
            ordinal: None,
        })
    }
}

fn bitfield(ts: &mut TypeString) -> Result<IdaType, TypeError> {
    let typ = ts.u8()?;
    let nbytes = 1u32 << (flags_of(typ) >> 4);
    let dt = ts.dt()?;
    let width = dt >> 1;
    let unsigned = dt & 1 != 0;
    ts.tah_attr()?;
    Ok(IdaType::Bitfield {
        nbytes,
        width,
        unsigned,
    })
}

fn is_void(ty: &IdaType) -> bool {
    matches!(ty, IdaType::Prim { base, flags } if *base == BT_VOID && *flags == 0)
}

/// The packed-integer cursor: `dt`, `de`, `da`, the length-prefixed
/// strings, and the attribute readers.
struct TypeString<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TypeString<'a> {
    fn new(buf: &'a [u8]) -> TypeString<'a> {
        TypeString { buf, pos: 0 }
    }

    fn has_next(&self) -> bool {
        self.pos < self.buf.len()
    }

    fn seek(&mut self, n: usize) -> Result<(), TypeError> {
        self.pos += n;
        if self.pos > self.buf.len() {
            return err("type runs past its end");
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, TypeError> {
        let byte = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| TypeError("type runs past its end".into()))?;
        self.pos += 1;
        Ok(byte)
    }

    fn peek_u8(&self) -> Result<u8, TypeError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| TypeError("type runs past its end".into()))
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8], TypeError> {
        if self.pos + n > self.buf.len() {
            return err("type runs past its end");
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// A 1-2 byte number, stored one greater than its value.
    fn dt(&mut self) -> Result<u32, TypeError> {
        let mut val = self.u8()? as u32;
        if val & 0x80 != 0 {
            val = (val & 0x7F) | ((self.u8()? as u32) << 7);
        }
        Ok(val.wrapping_sub(1))
    }

    /// A variable-length number in six-bit groups.
    fn de(&mut self) -> Result<u64, TypeError> {
        let mut val: u64 = 0;
        loop {
            let hi = val << 6;
            let b = self.u8()?;
            if b & 0x80 == 0 {
                val = u64::from(b & 0x3F) | hi;
                break;
            } else {
                val = (2 * hi) | u64::from(b & 0x7F);
            }
        }
        Ok(val)
    }

    /// A based array's count and base.
    fn da(&mut self) -> Result<(bool, u64, u64), TypeError> {
        let mut a = 0;
        let mut b = 0;
        let mut da = 0u64;
        let mut base = 0u64;
        let mut nelem = 0u64;
        loop {
            let typ = self.peek_u8()?;
            if typ & 0x80 == 0 {
                break;
            }
            self.seek(1)?;
            da = (da << 7) | u64::from(typ & 0x7F);
            b += 1;
            if b >= 4 {
                let z = self.peek_u8()?;
                if z != 0 {
                    base = (0x10 * da) | u64::from(z & 0xF);
                }
                nelem = u64::from((self.u8()? >> 4) & 7);
                loop {
                    let y = self.peek_u8()?;
                    if y & 0x80 == 0 {
                        break;
                    }
                    self.seek(1)?;
                    nelem = (nelem << 7) | u64::from(y & 0x7F);
                    a += 1;
                    if a >= 4 {
                        return Ok((true, nelem, base));
                    }
                }
            }
        }
        Ok((false, nelem, base))
    }

    /// A length-prefixed string.
    fn pstring(&mut self) -> Result<String, TypeError> {
        let length = self.dt()? as usize;
        let bytes = self.read(length)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Length-prefixed bytes.
    fn pbytes(&mut self) -> Result<Vec<u8>, TypeError> {
        let length = self.dt()? as usize;
        Ok(self.read(length)?.to_vec())
    }

    /// A type attribute, when the next byte introduces one.
    fn tah_attr(&mut self) -> Result<u32, TypeError> {
        if self.has_next() && is_tah_byte(self.peek_u8()?) {
            self.type_attr()
        } else {
            Ok(0)
        }
    }

    /// A structure/field attribute, when the next byte introduces one.
    fn sdacl_attr(&mut self) -> Result<u32, TypeError> {
        if self.has_next() && is_sdacl_byte(self.peek_u8()?) {
            self.type_attr()
        } else {
            Ok(0)
        }
    }

    fn type_attr(&mut self) -> Result<u32, TypeError> {
        let mut val = 0u32;
        let tah = self.u8()?;
        let tmp = ((tah & 1) | ((tah >> 3) & 6)) + 1;
        if is_tah_byte(tah) || tmp == 8 {
            if tmp == 8 {
                val = 8;
            }
            let mut shift = 0;
            loop {
                let next = self.u8()?;
                if next == 0 {
                    return err("bad type attribute");
                }
                val |= u32::from(next & 0x7F) << shift;
                if next & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        if val & TAH_HASATTRS != 0 {
            let count = self.dt()?;
            for _ in 0..count {
                let _name = self.pstring()?;
                let skip = self.dt()? as usize;
                self.seek(skip)?;
            }
        }
        Ok(val)
    }
}

/// The engine primitive an IDA basic type names.
fn prim_of(base: u8, flags: u8) -> Prim {
    let unsigned = flags == BTMT_USIGNED;
    match base {
        BT_VOID => Prim::Void,
        BT_UNK => match flags {
            BTMT_SIZE12 => Prim::UInt8,
            BTMT_SIZE48 => Prim::UInt32,
            BTMT_SIZE128 => Prim::UInt64,
            _ => Prim::UInt8,
        },
        BT_INT8 => {
            if flags == BTMT_CHAR {
                Prim::Char
            } else if unsigned {
                Prim::UInt8
            } else {
                Prim::Int8
            }
        }
        BT_INT16 => {
            if unsigned {
                Prim::UInt16
            } else {
                Prim::Int16
            }
        }
        BT_INT32 => {
            if unsigned {
                Prim::UInt32
            } else {
                Prim::Int32
            }
        }
        BT_INT64 | BT_INT128 => {
            if unsigned {
                Prim::UInt64
            } else {
                Prim::Int64
            }
        }
        BT_INT => {
            if unsigned {
                Prim::UInt
            } else {
                Prim::Int
            }
        }
        BT_BOOL => Prim::Bool,
        BT_FLOAT => match flags {
            0x00 => Prim::Float,
            0x10 => Prim::Double,
            0x20 => Prim::LongDouble,
            _ => Prim::Float,
        },
        _ => Prim::Int,
    }
}

/// The calling convention a function's cm byte names, as C spells it.
fn convention_of(cc: u8) -> Option<String> {
    match cc & CM_CC_MASK {
        CM_CC_CDECL => Some("__cdecl".to_string()),
        CM_CC_STDCALL => Some("__stdcall".to_string()),
        CM_CC_FASTCALL => Some("__fastcall".to_string()),
        CM_CC_THISCALL => Some("__thiscall".to_string()),
        _ => None,
    }
}

/// The key a referenced type is spelled by: a structure, union or
/// enumeration keeps its keyword, so a member can name it inside the body
/// of its own definition (`struct _LIST_ENTRY *Flink`) where the bare
/// typedef name is not yet in scope.
fn named_key(target: &str, til: &Til) -> String {
    if let Some(record) = til.by_name(target) {
        if let Some(&first) = record.type_info.first() {
            match full_of(first) {
                BTF_STRUCT => return format!("struct {target}"),
                BTF_UNION => return format!("union {target}"),
                BTF_ENUM => return format!("enum {target}"),
                _ => {}
            }
        }
    }
    target.to_string()
}

/// Turn a deserialized type into the engine's type, resolving typedefs
/// against the library. A structure or enumeration member becomes a named
/// reference; an anonymous one is rendered inline by the caller.
pub fn to_engine_type(ty: &IdaType, til: &Til) -> et::Type {
    match ty {
        IdaType::Prim { base, flags } => et::Type::Prim(prim_of(*base, *flags)),
        IdaType::Ptr(inner) => et::Type::Pointer(Box::new(to_engine_type(inner, til))),
        IdaType::Array(elem, count) => {
            let count = if *count == 0 { None } else { Some(*count) };
            et::Type::Array(Box::new(to_engine_type(elem, til)), count)
        }
        IdaType::Func { ret, args, cc } => {
            let params: Vec<et::Type> = args.iter().map(|(t, _)| to_engine_type(t, til)).collect();
            let variadic = matches!(cc & CM_CC_MASK, CM_CC_ELLIPSIS | CM_CC_SPECIALE);
            et::Type::Function {
                ret: Box::new(to_engine_type(ret, til)),
                params,
                variadic,
                attrs: et::TypeAttrs {
                    calling_convention: convention_of(*cc),
                    ..Default::default()
                },
            }
        }
        IdaType::Typedef { name, ordinal } => {
            let target = name.clone().or_else(|| {
                ordinal
                    .and_then(|o| til.by_ordinal(o))
                    .map(|r| r.name.clone())
            });
            match target {
                Some(target) => et::Type::Named(named_key(&target, til)),
                None => et::Type::Named("void".to_string()),
            }
        }
        IdaType::Udt { is_union, .. } => {
            // A named reference; the definition is rendered separately.
            let keyword = if *is_union { "union" } else { "struct" };
            et::Type::Named(format!("{keyword} <anonymous>"))
        }
        IdaType::Enum { .. } => et::Type::Named("enum <anonymous>".to_string()),
        IdaType::Bitfield {
            nbytes, unsigned, ..
        } => {
            let prim = match (nbytes, unsigned) {
                (1, true) => Prim::UInt8,
                (1, false) => Prim::Int8,
                (2, true) => Prim::UInt16,
                (2, false) => Prim::Int16,
                (4, true) => Prim::UInt32,
                (4, false) => Prim::Int32,
                (8, true) => Prim::UInt64,
                (_, true) => Prim::UInt64,
                (_, false) => Prim::Int64,
            };
            et::Type::Prim(prim)
        }
    }
}

/// Render a function's prototype as C: `int f(_IO_FILE *fp)`. The packed
/// type is the function's, the argument names ride beside it, and `name`
/// is the function's name. `None` when the type does not read.
pub fn render_prototype(
    type_info: &[u8],
    arg_names: &[String],
    name: &str,
    til: &Til,
    model: DataModel,
) -> Option<String> {
    let ty = deserialize(type_info, arg_names).ok()?;
    let store = TypeStore::new(model);
    let IdaType::Func { ret, args, cc } = &ty else {
        let engine = to_engine_type(&ty, til);
        return Some(et::declaration(&engine, name, &store));
    };
    let ret_text = to_engine_type(ret, til).spelled(&store);
    let mut params = Vec::new();
    for (arg, arg_name) in args {
        let arg_ty = to_engine_type(arg, til);
        match arg_name {
            Some(n) if !n.is_empty() => params.push(et::declaration(&arg_ty, n, &store)),
            _ => params.push(arg_ty.spelled(&store)),
        }
    }
    if matches!(cc & CM_CC_MASK, CM_CC_ELLIPSIS | CM_CC_SPECIALE) {
        params.push("...".to_string());
    }
    if params.is_empty() {
        params.push("void".to_string());
    }
    let conv = convention_of(*cc)
        .map(|c| format!("{c} "))
        .unwrap_or_default();
    Some(format!("{ret_text} {conv}{name}({})", params.join(", ")))
}

/// Render one type record as a C definition the project can keep, or
/// `None` when it cannot be spelled. The record's name is the tag of a
/// structure, union or enumeration, and the name of a typedef otherwise.
pub fn render_record(record: &TypeRecord, til: &Til, model: DataModel) -> Option<String> {
    let ty = deserialize(&record.type_info, &record.fields).ok()?;
    let store = TypeStore::new(model);
    let name = &record.name;
    match &ty {
        IdaType::Udt {
            is_union,
            members,
            pack,
        } => {
            let keyword = if *is_union { "union" } else { "struct" };
            let mut body = String::new();
            if *pack != 0 {
                body.push_str(&format!("#pragma pack({pack})\n"));
            }
            // A typedef of the tag makes the name usable without the
            // keyword, the way IDA names a structure: `timespec st_atim`.
            body.push_str(&format!("typedef {keyword} {name} {{\n"));
            for (i, member) in members.iter().enumerate() {
                let member_name = member
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("field_{i:x}"));
                let line = render_member(&member.ty, &member_name, til, &store);
                body.push_str("  ");
                body.push_str(&line);
                body.push_str(";\n");
            }
            body.push_str(&format!("}} {name};"));
            if *pack != 0 {
                body.push_str("\n#pragma pack()");
            }
            Some(body)
        }
        IdaType::Enum { members, bte, is64 } => {
            let mut body = format!("typedef enum {name} {{\n");
            for (i, (member_name, value)) in members.iter().enumerate() {
                let member_name = if member_name.is_empty() {
                    format!("member_{i:x}")
                } else {
                    member_name.clone()
                };
                let value = render_enum_value(*value, *bte, *is64);
                body.push_str(&format!("  {member_name} = {value},\n"));
            }
            body.push_str(&format!("}} {name};"));
            Some(body)
        }
        IdaType::Typedef {
            name: target,
            ordinal,
        } => {
            let target_name = target.clone().or_else(|| {
                ordinal
                    .and_then(|o| til.by_ordinal(o))
                    .map(|r| r.name.clone())
            })?;
            let target_key = named_key(&target_name, til);
            Some(format!("typedef {target_key} {name};"))
        }
        _ => {
            let engine = to_engine_type(&ty, til);
            let decl = et::declaration(&engine, name, &store);
            Some(format!("typedef {decl};"))
        }
    }
}

/// Render one structure member: a bit-field spells its width, an anonymous
/// composite its body inline, anything else its declaration.
fn render_member(ty: &IdaType, name: &str, til: &Til, store: &TypeStore) -> String {
    if let IdaType::Bitfield {
        width, unsigned, ..
    } = ty
    {
        let keyword = if *unsigned { "unsigned int" } else { "int" };
        return format!("{keyword} {name} : {width}");
    }
    let engine = to_engine_type(ty, til);
    et::declaration(&engine, name, store)
}

/// An enumerator's value as C spells it: hex when the enum is a bit-field
/// of flags (BTE_HEX), decimal otherwise.
fn render_enum_value(value: i64, bte: u8, is64: bool) -> String {
    let _ = is64;
    if bte & 0x60 == 0x00 {
        format!("{value:#x}")
    } else {
        format!("{value}")
    }
}

/// Render every type of a library as C, ordered so a type comes after the
/// types it is built from. A member held by value needs its type defined
/// first; a pointer does not, so pointer edges are not dependencies.
pub fn render_all(til: &Til, model: DataModel) -> Vec<crate::ctype::TypeText> {
    use std::collections::{BTreeMap, BTreeSet};

    // Render each record, and gather the library types it depends on.
    let mut rendered: BTreeMap<String, String> = BTreeMap::new();
    let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let names: BTreeSet<String> = til.types.iter().map(|t| t.name.clone()).collect();
    for record in &til.types {
        let Some(c) = render_record(record, til, model) else {
            continue;
        };
        let mut depends = BTreeSet::new();
        if let Ok(ty) = deserialize(&record.type_info, &record.fields) {
            collect_deps(&ty, til, &names, &mut depends);
        }
        depends.remove(&record.name);
        rendered.insert(record.name.clone(), c);
        deps.insert(record.name.clone(), depends);
    }

    // Kahn's algorithm: a type follows the types it depends on. A cycle
    // (only possible through a value edge the parser would refuse anyway)
    // is broken by taking the remaining names in order.
    let mut ordered = Vec::new();
    let mut remaining: BTreeSet<String> = rendered.keys().cloned().collect();
    while !remaining.is_empty() {
        let ready: Vec<String> = remaining
            .iter()
            .filter(|name| {
                deps.get(*name)
                    .map(|d| d.iter().all(|dep| !remaining.contains(dep)))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let take = if ready.is_empty() {
            remaining
                .iter()
                .next()
                .cloned()
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            ready
        };
        for name in take {
            remaining.remove(&name);
            if let Some(c) = rendered.get(&name) {
                ordered.push(crate::ctype::TypeText {
                    name: name.clone(),
                    c: c.clone(),
                });
            }
        }
    }

    // Keep only the definitions the engine reads: a C++ class with base
    // classes or a scoped name is no plain C, and is held back rather than
    // failing the whole library. A type built on a held-back type fails in
    // turn, which is right.
    let mut store = TypeStore::new(model);
    let mut kept = Vec::new();
    for def in ordered {
        match crate::ctype::parse_into(&mut store, &def.c) {
            Ok(parsed) if !parsed.declarations.is_empty() => kept.push(def),
            _ => {}
        }
    }
    kept
}

/// The library types a type is built from by value, ignoring pointers
/// (which may forward-reference) and the type's own name.
fn collect_deps(
    ty: &IdaType,
    til: &Til,
    names: &std::collections::BTreeSet<String>,
    out: &mut std::collections::BTreeSet<String>,
) {
    match ty {
        IdaType::Ptr(_) => {}
        IdaType::Array(elem, _) => collect_deps(elem, til, names, out),
        IdaType::Func { ret, args, .. } => {
            collect_deps(ret, til, names, out);
            for (arg, _) in args {
                collect_deps(arg, til, names, out);
            }
        }
        IdaType::Udt { members, .. } => {
            for member in members {
                collect_deps(&member.ty, til, names, out);
            }
        }
        IdaType::Typedef { name, ordinal } => {
            let target = name.clone().or_else(|| {
                ordinal
                    .and_then(|o| til.by_ordinal(o))
                    .map(|r| r.name.clone())
            });
            if let Some(target) = target {
                if names.contains(&target) {
                    out.insert(target);
                }
            }
        }
        IdaType::Enum { .. } | IdaType::Prim { .. } | IdaType::Bitfield { .. } => {}
    }
}
