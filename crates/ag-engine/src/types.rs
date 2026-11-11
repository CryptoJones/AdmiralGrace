//! The type system: C's types as the analyst defines them, laid out as the
//! image's platform lays them out.
//!
//! A [`Type`] is a primitive — `int`, `unsigned long`, `uint32_t`, `size_t`
//! — a pointer, an array, a function, or a name a definition gives: a
//! structure, a union, an enumeration or a typedef. A [`TypeStore`] holds
//! the definitions by name, `struct point`, `union value`, `enum color`,
//! `node_t`, under one [`DataModel`]: the sizes and alignments of the
//! primitives on the image's platform.
//!
//! **Layout.** Each member of a structure is placed at the next offset its
//! alignment allows, and the structure's size is rounded up to its own
//! alignment, the greatest of its members'. A union's members all start at
//! 0, and its size is its largest member's, rounded the same way. Under
//! `#pragma pack(N)` a member's alignment is at most N, and under
//! `__attribute__((packed))` it is 1; `__attribute__((aligned(N)))` raises
//! the structure's alignment to N.
//!
//! **Bit-fields** follow the System V (GCC) rule on every data model: a
//! bit-field of declared type T goes at the next free bit when it fits in
//! the T-sized, T-aligned unit holding that bit, and at the start of the
//! next such unit otherwise; a zero-width bit-field moves to the next unit;
//! a named bit-field gives the structure T's alignment, an unnamed one does
//! not; packed — by the attribute or a `#pragma pack` — bit-fields follow
//! one another bit by bit, a zero width still moving to the next unit, as
//! GCC lays them out. Microsoft's rule differs, and is left to the
//! bit-field and attribute work (#372, #373).
//!
//! **Incomplete types.** A structure named before it is defined, `struct
//! node *next`, is incomplete: a pointer to it is whole, a member or a
//! variable of it is refused until it is defined. A structure that holds
//! itself by value, directly or through another, is refused the same way —
//! its definition is not complete where the member needs it.
//!
//! The definitions are read from C by [`crate::ctype`]; the C text the
//! analyst wrote is what the project keeps, and the store is built from it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// The sizes and alignments of C's primitives on one platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataModel {
    /// The model's usual name: `LP64`, `LLP64`, `ILP32`.
    pub name: &'static str,
    /// The size and alignment of a pointer, `size_t` and their kind.
    pub pointer: u64,
    /// The size and alignment of `long`.
    pub long: u64,
    /// The alignment of the 8-byte scalars — `long long`, `double`,
    /// `int64_t` — inside a structure: 4 on 32-bit x86 under System V.
    pub align8: u64,
    /// The size and alignment of `long double`.
    pub long_double: (u64, u64),
    /// The size of `wchar_t`.
    pub wchar: u64,
}

impl DataModel {
    /// LP64: 64-bit System V and Mach-O — x86-64 and AArch64 on Linux,
    /// the BSDs and macOS. `long` and pointers are 8 bytes.
    pub const LP64: DataModel = DataModel {
        name: "LP64",
        pointer: 8,
        long: 8,
        align8: 8,
        long_double: (16, 16),
        wchar: 4,
    };

    /// LLP64: 64-bit Windows. `long` is 4 bytes, pointers 8, `long double`
    /// is `double`, and `wchar_t` is 2 bytes.
    pub const LLP64: DataModel = DataModel {
        name: "LLP64",
        pointer: 8,
        long: 4,
        align8: 8,
        long_double: (8, 8),
        wchar: 2,
    };

    /// ILP32: 32-bit ARM, MIPS and Windows. `int`, `long` and pointers are
    /// 4 bytes; the 8-byte scalars align to 8.
    pub const ILP32: DataModel = DataModel {
        name: "ILP32",
        pointer: 4,
        long: 4,
        align8: 8,
        long_double: (8, 8),
        wchar: 4,
    };

    /// ILP32 as 32-bit x86 lays it out under System V: the 8-byte scalars
    /// align to 4 in a structure, and `long double` is 12 bytes.
    pub const ILP32_I386: DataModel = DataModel {
        name: "ILP32 (i386)",
        pointer: 4,
        long: 4,
        align8: 4,
        long_double: (12, 4),
        wchar: 4,
    };

    /// The data model of a language id, `x86:LE:64:default:windows`: its
    /// width, and Windows by the compiler field.
    pub fn of_language(language: &str) -> DataModel {
        let fields: Vec<&str> = language.split(':').collect();
        let processor = fields.first().copied().unwrap_or("").to_ascii_lowercase();
        let width = fields.get(2).copied().unwrap_or("64");
        let windows = fields.get(4).is_some_and(|c| *c == "windows");
        match (width, windows) {
            ("32" | "16", true) => DataModel {
                wchar: 2,
                ..DataModel::ILP32
            },
            ("32" | "16", false) if processor == "x86" => DataModel::ILP32_I386,
            ("32" | "16", false) => DataModel::ILP32,
            (_, true) => DataModel::LLP64,
            _ => DataModel::LP64,
        }
    }

    /// The data model the x86-64 lift reads a function under: LLP64 for
    /// the Microsoft convention, LP64 otherwise.
    pub fn of_abi(abi: crate::lift::Abi) -> DataModel {
        match abi {
            crate::lift::Abi::Win64 => DataModel::LLP64,
            crate::lift::Abi::SystemV | crate::lift::Abi::Go | crate::lift::Abi::Pascal => {
                DataModel::LP64
            }
        }
    }
}

/// A primitive type of C, and the platform typedefs the store knows
/// without a definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prim {
    Void,
    Bool,
    Char,
    SChar,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    LongDouble,
    WChar,
    SizeT,
    SSizeT,
    IntPtr,
    UIntPtr,
    PtrDiff,
}

impl Prim {
    /// Every primitive, in the order the types view lists them.
    pub const ALL: &'static [Prim] = &[
        Prim::Void,
        Prim::Bool,
        Prim::Char,
        Prim::SChar,
        Prim::UChar,
        Prim::Short,
        Prim::UShort,
        Prim::Int,
        Prim::UInt,
        Prim::Long,
        Prim::ULong,
        Prim::LongLong,
        Prim::ULongLong,
        Prim::Int8,
        Prim::UInt8,
        Prim::Int16,
        Prim::UInt16,
        Prim::Int32,
        Prim::UInt32,
        Prim::Int64,
        Prim::UInt64,
        Prim::Float,
        Prim::Double,
        Prim::LongDouble,
        Prim::WChar,
        Prim::SizeT,
        Prim::SSizeT,
        Prim::IntPtr,
        Prim::UIntPtr,
        Prim::PtrDiff,
    ];

    /// The type as C spells it.
    pub fn spelling(self) -> &'static str {
        match self {
            Prim::Void => "void",
            Prim::Bool => "_Bool",
            Prim::Char => "char",
            Prim::SChar => "signed char",
            Prim::UChar => "unsigned char",
            Prim::Short => "short",
            Prim::UShort => "unsigned short",
            Prim::Int => "int",
            Prim::UInt => "unsigned int",
            Prim::Long => "long",
            Prim::ULong => "unsigned long",
            Prim::LongLong => "long long",
            Prim::ULongLong => "unsigned long long",
            Prim::Int8 => "int8_t",
            Prim::UInt8 => "uint8_t",
            Prim::Int16 => "int16_t",
            Prim::UInt16 => "uint16_t",
            Prim::Int32 => "int32_t",
            Prim::UInt32 => "uint32_t",
            Prim::Int64 => "int64_t",
            Prim::UInt64 => "uint64_t",
            Prim::Float => "float",
            Prim::Double => "double",
            Prim::LongDouble => "long double",
            Prim::WChar => "wchar_t",
            Prim::SizeT => "size_t",
            Prim::SSizeT => "ssize_t",
            Prim::IntPtr => "intptr_t",
            Prim::UIntPtr => "uintptr_t",
            Prim::PtrDiff => "ptrdiff_t",
        }
    }

    /// The platform typedef a name is, when it is one: `size_t`,
    /// `uint32_t`, `bool`.
    pub fn named(name: &str) -> Option<Prim> {
        Some(match name {
            "bool" | "_Bool" => Prim::Bool,
            "int8_t" => Prim::Int8,
            "uint8_t" => Prim::UInt8,
            "int16_t" => Prim::Int16,
            "uint16_t" => Prim::UInt16,
            "int32_t" => Prim::Int32,
            "uint32_t" => Prim::UInt32,
            "int64_t" => Prim::Int64,
            "uint64_t" => Prim::UInt64,
            "wchar_t" => Prim::WChar,
            "size_t" => Prim::SizeT,
            "ssize_t" => Prim::SSizeT,
            "intptr_t" => Prim::IntPtr,
            "uintptr_t" => Prim::UIntPtr,
            "ptrdiff_t" => Prim::PtrDiff,
            _ => return None,
        })
    }

    /// Whether the type is an integer.
    pub fn is_integer(self) -> bool {
        !matches!(
            self,
            Prim::Void | Prim::Float | Prim::Double | Prim::LongDouble
        )
    }

    /// Whether the type is a signed integer.
    pub fn is_signed(self) -> bool {
        matches!(
            self,
            Prim::Char
                | Prim::SChar
                | Prim::Short
                | Prim::Int
                | Prim::Long
                | Prim::LongLong
                | Prim::Int8
                | Prim::Int16
                | Prim::Int32
                | Prim::Int64
                | Prim::SSizeT
                | Prim::IntPtr
                | Prim::PtrDiff
        )
    }

    /// The size and alignment under `model`; `None` for `void`.
    pub fn layout(self, model: &DataModel) -> Option<(u64, u64)> {
        let eight = (8, model.align8);
        Some(match self {
            Prim::Void => return None,
            Prim::Bool | Prim::Char | Prim::SChar | Prim::UChar | Prim::Int8 | Prim::UInt8 => {
                (1, 1)
            }
            Prim::Short | Prim::UShort | Prim::Int16 | Prim::UInt16 => (2, 2),
            Prim::Int | Prim::UInt | Prim::Int32 | Prim::UInt32 | Prim::Float => (4, 4),
            Prim::Long | Prim::ULong => match model.long {
                8 => eight,
                n => (n, n),
            },
            Prim::LongLong | Prim::ULongLong | Prim::Int64 | Prim::UInt64 | Prim::Double => eight,
            Prim::LongDouble => model.long_double,
            Prim::WChar => (model.wchar, model.wchar),
            Prim::SizeT | Prim::SSizeT | Prim::IntPtr | Prim::UIntPtr | Prim::PtrDiff => {
                match model.pointer {
                    8 => eight,
                    n => (n, n),
                }
            }
        })
    }
}

/// The attributes a function type carries: the calling convention it uses,
/// and whether it never returns (`noreturn`) or reads only the state its
/// arguments reach (`pure`).  #373.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TypeAttrs {
    /// The calling convention, MSVC's `__cdecl` and friends, or `None` for
    /// the default.
    pub calling_convention: Option<String>,
    /// `__attribute__((noreturn))`, `__declspec(noreturn)` or `_Noreturn`:
    /// the function never returns.
    pub noreturn: bool,
    /// `__attribute__((pure))` or `__declspec(noinline)`-kin: the result
    /// depends only on the arguments.
    pub pure: bool,
}

impl TypeAttrs {
    /// Whether any attribute is set.
    pub fn is_empty(&self) -> bool {
        self.calling_convention.is_none() && !self.noreturn && !self.pure
    }
}

/// A C type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    /// A primitive, or a platform typedef such as `size_t`.
    Prim(Prim),
    /// A pointer to the type.
    Pointer(Box<Type>),
    /// An array of the type, of a count when it says one: `int[4]`, `int[]`.
    Array(Box<Type>, Option<u64>),
    /// A based pointer, MSVC's `__based(ptr)`: the pointee addressed by
    /// `base` plus the stored offset. Laid out like the platform pointer.
    BasedPointer { base: Box<Type>, pointee: Box<Type> },
    /// A function: its return type, its parameters' types, and whether it
    /// takes more after them, `...`.
    Function {
        ret: Box<Type>,
        params: Vec<Type>,
        variadic: bool,
        attrs: TypeAttrs,
    },
    /// A type a definition names, by the definition's key: `struct point`,
    /// `union value`, `enum color`, or a typedef's name, `node_t`.
    Named(String),
}

impl Type {
    /// A pointer to `ty`.
    pub fn pointer(ty: Type) -> Type {
        Type::Pointer(Box::new(ty))
    }

    /// The type as C spells it with no name: `char *`, `int[4]`, `int
    /// (*)(char *, ...)`.
    pub fn spelled(&self, store: &TypeStore) -> String {
        declaration(self, "", store)
    }

    /// The definition keys the type names, directly or through pointers,
    /// arrays and functions.
    pub fn names(&self, out: &mut BTreeSet<String>) {
        match self {
            Type::Prim(_) => {}
            Type::Pointer(inner) | Type::Array(inner, _) => inner.names(out),
            Type::BasedPointer { base, pointee } => {
                base.names(out);
                pointee.names(out);
            }
            Type::Function { ret, params, .. } => {
                ret.names(out);
                for param in params {
                    param.names(out);
                }
            }
            Type::Named(name) => {
                out.insert(name.clone());
            }
        }
    }
}

/// One method of a C++ class, as defined. A method lives outside the layout:
/// it is not stored in the object, so it is no member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method {
    /// The method's name.
    pub name: String,
    /// The method's type, always a function type.
    pub ty: Type,
    /// Whether the method is virtual: it occupies a slot in the class's
    /// vtable, in the order the virtual methods are declared.
    pub is_virtual: bool,
}

/// One member of a structure or union, as defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member's name; `None` for an anonymous structure or union
    /// member, whose own members are reached through it as if they were
    /// the outer one's, and for an unnamed bit-field.
    pub name: Option<String>,
    pub ty: Type,
    /// The width of a bit-field, in bits.
    pub bits: Option<u32>,
}

/// A structure or a union.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Composite {
    /// The tag, `point` of `struct point`; `None` for an anonymous one.
    pub tag: Option<String>,
    /// The members, in order; `None` while it is only declared.
    pub members: Option<Vec<Member>>,
    /// The `#pragma pack(N)` in force where it was defined.
    pub pack: Option<u64>,
    /// `__attribute__((packed))`: every member aligned to 1.
    pub packed: bool,
    /// `__attribute__((aligned(N)))`: the alignment raised to N.
    pub aligned: Option<u64>,
    /// The base classes of a structure, `struct derived : public base`'s
    /// bases, in order. Laid out first, as the model puts the first
    /// non-empty base at offset 0 (#373; #374 adds the virtual function
    /// table and the methods).
    pub base_classes: Vec<String>,
    /// `class`, spelled where a structure would be: a C++ class.
    pub is_class: bool,
    /// The methods of a C++ class, in order. The virtual ones are also the
    /// vtable's slots, in the order they are declared.
    pub methods: Vec<Method>,
}

/// An enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The tag, `color` of `enum color`; `None` for an anonymous one.
    pub tag: Option<String>,
    /// The integer it is held in: `int`, unless a value does not fit it or
    /// the definition says, `enum e : unsigned char`.
    pub underlying: Prim,
    /// The enumerators and their values, in order; empty while it is only
    /// declared.
    pub values: Vec<(String, i64)>,
    /// Whether it was defined, not only declared.
    pub complete: bool,
}

/// What a name is defined as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    Struct(Composite),
    Union(Composite),
    Enum(Enumeration),
    /// `typedef ty name;`.
    Typedef(Type),
}

impl Definition {
    /// The kind, as the types view lists it: `struct`, `union`, `enum`,
    /// `typedef`.
    pub fn kind(&self) -> &'static str {
        match self {
            Definition::Struct(c) if c.is_class => "class",
            Definition::Struct(_) => "struct",
            Definition::Union(_) => "union",
            Definition::Enum(_) => "enum",
            Definition::Typedef(_) => "typedef",
        }
    }

    /// Whether the definition is a C++ class.
    pub fn is_class(&self) -> bool {
        matches!(self, Definition::Struct(c) if c.is_class)
    }

    /// Whether the definition is complete: a structure, union or
    /// enumeration with its body, or a typedef.
    pub fn is_complete(&self) -> bool {
        match self {
            Definition::Struct(c) | Definition::Union(c) => c.members.is_some(),
            Definition::Enum(e) => e.complete,
            Definition::Typedef(_) => true,
        }
    }
}

/// Where one member of a structure or union lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLayout {
    pub name: Option<String>,
    pub ty: Type,
    /// The offset in bytes; of a bit-field, the offset of the unit of its
    /// declared type that holds its first bit.
    pub offset: u64,
    /// The size in bytes; of a bit-field, its declared type's.
    pub size: u64,
    /// Of a bit-field: its first bit, counted from the unit at `offset`,
    /// and its width.
    pub bits: Option<(u32, u32)>,
}

/// Where the members of a structure or union lie, and its size and
/// alignment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    pub size: u64,
    pub align: u64,
    pub fields: Vec<FieldLayout>,
}

/// One step into a type: a member by name, an element by index, or a
/// named bit-field by name and its place in the unit of its declared
/// type — its first bit, counted from that unit, and its width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Field(String),
    Index(u64),
    Bits {
        name: String,
        bit_offset: u32,
        bits: u32,
    },
}

/// The path to bytes inside a type, `.inner.a[2].f`.
pub fn path_text(path: &[Step]) -> String {
    let mut out = String::new();
    for step in path {
        match step {
            Step::Field(name) => {
                out.push('.');
                out.push_str(name);
            }
            Step::Index(index) => {
                let _ = write!(out, "[{index}]");
            }
            Step::Bits { name, .. } => {
                out.push('.');
                out.push_str(name);
            }
        }
    }
    out
}

/// The definitions of one image's types, by name, under its data model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeStore {
    model: DataModel,
    definitions: BTreeMap<String, Definition>,
    /// The keys in the order they were defined: an order C reads them in.
    order: Vec<String>,
    /// The layout of every complete structure and union, by key.
    layouts: BTreeMap<String, Layout>,
    /// Every enumerator, with its enumeration's key and its value.
    constants: BTreeMap<String, (String, i64)>,
    /// How many anonymous definitions have been given a key.
    anonymous: usize,
}

impl Default for TypeStore {
    fn default() -> Self {
        TypeStore::new(DataModel::LP64)
    }
}

/// The key of the anonymous definitions starts with this, which no C name
/// does.
const ANONYMOUS: &str = "@";

impl TypeStore {
    /// A store of the platform's primitives alone, under `model`.
    pub fn new(model: DataModel) -> TypeStore {
        TypeStore {
            model,
            definitions: BTreeMap::new(),
            order: Vec::new(),
            layouts: BTreeMap::new(),
            constants: BTreeMap::new(),
            anonymous: 0,
        }
    }

    pub fn model(&self) -> &DataModel {
        &self.model
    }

    /// The definition of `key`: `struct point`, `node_t`.
    pub fn get(&self, key: &str) -> Option<&Definition> {
        self.definitions.get(key)
    }

    /// The keys of the named definitions, in the order they were defined;
    /// the anonymous ones, which stand inside another, are left out.
    pub fn names(&self) -> Vec<&str> {
        self.order
            .iter()
            .filter(|key| !is_anonymous(key))
            .map(String::as_str)
            .collect()
    }

    /// Every key, the anonymous ones too, in the order defined.
    pub fn keys(&self) -> &[String] {
        &self.order
    }

    /// Whether `key` is an anonymous definition's.
    pub fn is_anonymous(&self, key: &str) -> bool {
        is_anonymous(key)
    }

    /// The layout of the structure or union `key`, when it is complete.
    pub fn layout(&self, key: &str) -> Option<&Layout> {
        self.layouts.get(key)
    }

    /// The enumeration and value of the enumerator `name`.
    pub fn constant(&self, name: &str) -> Option<(&str, i64)> {
        self.constants
            .get(name)
            .map(|(owner, value)| (owner.as_str(), *value))
    }

    /// A fresh key for an anonymous definition of `kind`.
    pub(crate) fn anonymous_key(&mut self, kind: &str) -> String {
        self.anonymous += 1;
        format!("{kind} {ANONYMOUS}{}", self.anonymous)
    }

    /// Declare `key` as `definition` when it is not declared yet; a
    /// complete definition over a declaration completes it. A second
    /// complete definition is refused.
    pub(crate) fn define(&mut self, key: &str, definition: Definition) -> Result<(), String> {
        if let Some(held) = self.definitions.get(key) {
            if held.is_complete() && definition.is_complete() {
                if *held == definition {
                    return Ok(());
                }
                return Err(format!("{} is defined already", shown_key(key)));
            }
            if held.kind() != definition.kind() {
                return Err(format!("{} is a {} already", shown_key(key), held.kind()));
            }
            if !definition.is_complete() {
                return Ok(());
            }
            // Completed: it stands after what it was named by.
            self.order.retain(|held| held != key);
            self.order.push(key.to_string());
        } else {
            self.order.push(key.to_string());
        }
        if let Definition::Enum(e) = &definition {
            for (name, value) in &e.values {
                self.constants
                    .insert(name.clone(), (key.to_string(), *value));
            }
        }
        let composite = matches!(definition, Definition::Struct(_) | Definition::Union(_))
            && definition.is_complete();
        self.definitions.insert(key.to_string(), definition);
        if composite {
            match self.compute_layout(key) {
                Ok(layout) => {
                    self.layouts.insert(key.to_string(), layout);
                }
                Err(why) => {
                    // Not complete after all: back to a declaration.
                    if let Some(Definition::Struct(c) | Definition::Union(c)) =
                        self.definitions.get_mut(key)
                    {
                        c.members = None;
                    }
                    return Err(why);
                }
            }
        }
        Ok(())
    }

    /// The type under its typedefs: `node_t` is `struct node`.
    pub fn resolve<'a>(&'a self, ty: &'a Type) -> &'a Type {
        let mut ty = ty;
        for _ in 0..64 {
            match ty {
                Type::Named(key) => match self.definitions.get(key) {
                    Some(Definition::Typedef(inner)) => ty = inner,
                    _ => return ty,
                },
                _ => return ty,
            }
        }
        ty
    }

    /// The structure or union `ty` is, under its typedefs: its definition,
    /// its layout, and whether it is a union.
    pub fn composite(&self, ty: &Type) -> Option<(&Composite, &Layout, bool)> {
        let Type::Named(key) = self.resolve(ty) else {
            return None;
        };
        let layout = self.layouts.get(key)?;
        match self.definitions.get(key)? {
            Definition::Struct(c) => Some((c, layout, false)),
            Definition::Union(c) => Some((c, layout, true)),
            _ => None,
        }
    }

    /// The enumeration `ty` is, under its typedefs, and its key.
    pub fn enumeration(&self, ty: &Type) -> Option<(&str, &Enumeration)> {
        let Type::Named(key) = self.resolve(ty) else {
            return None;
        };
        match self.definitions.get_key_value(key)? {
            (key, Definition::Enum(e)) if e.complete => Some((key.as_str(), e)),
            _ => None,
        }
    }

    /// Whether `ty` is a scalar: an integer, a floating type, an
    /// enumeration or a pointer.
    pub fn is_scalar(&self, ty: &Type) -> bool {
        match self.resolve(ty) {
            Type::Prim(p) => *p != Prim::Void,
            Type::Pointer(_) | Type::BasedPointer { .. } => true,
            Type::Named(key) => matches!(self.definitions.get(key), Some(Definition::Enum(_))),
            _ => false,
        }
    }

    /// The size of `ty` in bytes, or why it has none.
    pub fn size_of(&self, ty: &Type) -> Result<u64, String> {
        self.size_align(ty).map(|(size, _)| size)
    }

    /// The alignment of `ty` in bytes, or why it has none.
    pub fn align_of(&self, ty: &Type) -> Result<u64, String> {
        self.size_align(ty).map(|(_, align)| align)
    }

    /// The size and alignment of `ty`.
    pub fn size_align(&self, ty: &Type) -> Result<(u64, u64), String> {
        match ty {
            Type::Prim(p) => p
                .layout(&self.model)
                .ok_or_else(|| "void has no size".to_string()),
            Type::Pointer(_) => Ok((self.model.pointer, self.model.pointer)),
            Type::BasedPointer { .. } => Ok((self.model.pointer, self.model.pointer)),
            Type::Array(inner, count) => {
                let (size, align) = self.size_align(inner)?;
                match count {
                    Some(count) => size
                        .checked_mul(*count)
                        .map(|total| (total, align))
                        .ok_or_else(|| "the array is too large".to_string()),
                    None => Err(format!("{} has no count", ty.spelled(self))),
                }
            }
            Type::Function { .. } => Err("a function has no size".to_string()),
            Type::Named(key) => match self.definitions.get(key) {
                None => Err(match key.split_once(' ') {
                    Some(_) => format!("{} is incomplete", shown_key(key)),
                    None => format!("{key} names no type"),
                }),
                Some(Definition::Typedef(inner)) => self.size_align(inner),
                Some(Definition::Enum(e)) => {
                    if !e.complete {
                        return Err(format!("{} is incomplete", shown_key(key)));
                    }
                    Ok(e.underlying.layout(&self.model).unwrap_or((4, 4)))
                }
                Some(Definition::Struct(_) | Definition::Union(_)) => self
                    .layouts
                    .get(key)
                    .map(|layout| (layout.size, layout.align))
                    .ok_or_else(|| format!("{} is incomplete", shown_key(key))),
            },
        }
    }

    /// Whether the structure or union `key` starts with a vtable pointer:
    /// a composite with virtual methods, or a composite whose base holds
    /// one.
    pub fn has_vtable(&self, key: &str) -> bool {
        let mut visited = std::collections::HashSet::new();
        self.has_vtable_seen(key, &mut visited)
    }

    fn has_vtable_seen(&self, key: &str, visited: &mut std::collections::HashSet<String>) -> bool {
        if !visited.insert(key.to_string()) {
            // A base that reaches back to itself: it holds no vtable of
            // its own, so the cycle adds nothing.
            return false;
        }
        let Some(c) = (match self.definitions.get(key) {
            Some(Definition::Struct(c)) => Some(c),
            _ => None,
        }) else {
            return false;
        };
        c.methods.iter().any(|m| m.is_virtual)
            || c.base_classes
                .iter()
                .any(|base| self.has_vtable_seen(base, visited))
    }

    /// Whether `key`'s own layout holds a vtable pointer: it has virtual
    /// methods and no base already holds one. A derived class shares its
    /// base's pointer at offset 0 and holds no second one.
    fn vtable_here(&self, composite: &Composite) -> bool {
        composite.methods.iter().any(|m| m.is_virtual)
            && !composite
                .base_classes
                .iter()
                .any(|base| self.has_vtable(base))
    }

    fn compute_layout(&self, key: &str) -> Result<Layout, String> {
        let (composite, union) = match self.definitions.get(key) {
            Some(Definition::Struct(c)) => (c, false),
            Some(Definition::Union(c)) => (c, true),
            _ => return Err(format!("{} is no structure", shown_key(key))),
        };
        let Some(members) = &composite.members else {
            return Err(format!("{} is incomplete", shown_key(key)));
        };
        if union && !composite.base_classes.is_empty() {
            return Err(format!(
                "{} is a union: a union has no base classes",
                shown_key(key)
            ));
        }
        if union && composite.methods.iter().any(|m| m.is_virtual) {
            return Err(format!(
                "{} is a union: a union has no virtual methods, and so no vtable pointer",
                shown_key(key)
            ));
        }
        // A class with virtual methods holds a vtable pointer. It is
        // laid out only when a base does not already hold one: the first
        // base that is non-empty carries it at its own start, so a
        // derived class shares the base's, at offset 0.
        let vtable = self.vtable_here(composite);
        let cap = if composite.packed {
            Some(1)
        } else {
            composite.pack
        };
        let capped = |align: u64| cap.map_or(align, |cap| align.min(cap.max(1)));
        let mut fields = Vec::new();
        let mut align = 1u64;
        // The next free bit, from the start.
        let mut bit: u64 = 0;
        let mut size: u64 = 0;
        // Base classes are laid out first, each at the next aligned
        // position; the first non-empty base thus stands at offset 0.
        for base in &composite.base_classes {
            let base_ty = Type::Named(base.clone());
            let (bsize, malign) = self
                .size_align(&base_ty)
                .map_err(|why| format!("a base of {} is not laid out: {why}", shown_key(key)))?;
            let malign = capped(malign);
            align = align.max(malign);
            let offset = if union {
                0
            } else {
                round_up(bit.div_ceil(8), malign)
            };
            fields.push(FieldLayout {
                name: None,
                ty: base_ty.clone(),
                offset,
                size: bsize,
                bits: None,
            });
            size = size.max(offset + bsize);
            if !union {
                bit = (offset + bsize) * 8;
            }
        }
        // The vtable pointer: directly after the base classes, at the
        // next aligned position — offset 0 unless a base is in the way.
        if vtable {
            let vptr = Type::Pointer(Box::new(Type::Prim(Prim::Void)));
            let (vsize, valign) = self
                .size_align(&vptr)
                .map_err(|why| format!("{} is not laid out: {why}", shown_key(key)))?;
            let valign = capped(valign);
            align = align.max(valign);
            let offset = if union {
                0
            } else {
                round_up(bit.div_ceil(8), valign)
            };
            fields.push(FieldLayout {
                name: None,
                ty: vptr,
                offset,
                size: vsize,
                bits: None,
            });
            size = size.max(offset + vsize);
            if !union {
                bit = (offset + vsize) * 8;
            }
        }
        let count = members.len();
        for (index, member) in members.iter().enumerate() {
            let what = || match &member.name {
                Some(name) => format!("{name} of {}", shown_key(key)),
                None => format!("a member of {}", shown_key(key)),
            };
            if let Type::Array(_, None) = &member.ty {
                // A flexible array member: the last, of no size.
                if index + 1 != count || union {
                    return Err(format!("{} has no count", what()));
                }
                let elem_align = match &member.ty {
                    Type::Array(inner, _) => self
                        .align_of(inner)
                        .map_err(|why| format!("{} is not laid out: {why}", what()))?,
                    _ => 1,
                };
                let elem_align = capped(elem_align);
                align = align.max(elem_align);
                let offset = round_up(bit.div_ceil(8), elem_align);
                fields.push(FieldLayout {
                    name: member.name.clone(),
                    ty: member.ty.clone(),
                    offset,
                    size: 0,
                    bits: None,
                });
                size = size.max(offset);
                bit = offset * 8;
                continue;
            }
            let (msize, malign) = self
                .size_align(&member.ty)
                .map_err(|why| format!("{} is not laid out: {why}", what()))?;
            if let Some(width) = member.bits {
                if !self.is_integer(&member.ty) {
                    return Err(format!("{} is a bit-field of no integer type", what()));
                }
                if u64::from(width) > msize * 8 {
                    return Err(format!(
                        "{} is {width} bits wide, wider than its {} bits",
                        what(),
                        msize * 8
                    ));
                }
                // Packed, the bits follow one another; else a bit-field
                // stays inside one unit of its type. A zero width moves to
                // the next unit either way.
                let contiguous = cap.is_some();
                let unit = msize * 8;
                let start = if union { 0 } else { bit };
                let placed = if width == 0 {
                    bit = round_up(start, unit);
                    size = size.max(bit.div_ceil(8));
                    continue;
                } else if contiguous || start / unit == (start + u64::from(width) - 1) / unit {
                    start
                } else {
                    round_up(start, unit)
                };
                if member.name.is_some() {
                    align = align.max(capped(malign));
                }
                let unit_offset = if contiguous {
                    placed / 8
                } else {
                    (placed / unit) * (unit / 8)
                };
                fields.push(FieldLayout {
                    name: member.name.clone(),
                    ty: member.ty.clone(),
                    offset: unit_offset,
                    size: msize,
                    bits: Some(((placed - unit_offset * 8) as u32, width)),
                });
                let end = placed + u64::from(width);
                if union {
                    size = size.max(end.div_ceil(8));
                } else {
                    bit = end;
                    size = size.max(end.div_ceil(8));
                }
                continue;
            }
            let malign = capped(malign);
            align = align.max(malign);
            let offset = if union {
                0
            } else {
                round_up(bit.div_ceil(8), malign)
            };
            fields.push(FieldLayout {
                name: member.name.clone(),
                ty: member.ty.clone(),
                offset,
                size: msize,
                bits: None,
            });
            let end = offset + msize;
            size = size.max(end);
            if !union {
                bit = end * 8;
            }
        }
        if let Some(aligned) = composite.aligned {
            align = align.max(aligned);
        }
        Ok(Layout {
            size: round_up(size, align),
            align,
            fields,
        })
    }

    /// Whether `ty` is an integer type: an integer primitive or an
    /// enumeration.
    pub fn is_integer(&self, ty: &Type) -> bool {
        match self.resolve(ty) {
            Type::Prim(p) => p.is_integer(),
            Type::Named(key) => matches!(self.definitions.get(key), Some(Definition::Enum(_))),
            _ => false,
        }
    }

    /// The path to the `size` bytes at `offset` inside `ty`, and the type
    /// they are: a member whose bytes they are exactly, `.f`, inside
    /// arrays and nested structures, `.a[2].f`, a bit-field whose unit
    /// the bytes are exactly — the unit the lift reads anything of it
    /// at, so what the code reads there is the bit-field, `(unit >> off)
    /// & mask` — or the whole of an aggregate when no member is. A
    /// union takes the first member the bytes fit. `None` when the
    /// bytes are no member's: they straddle two, are part of a scalar,
    /// or reach only part of a bit-field's unit, which no one member
    /// the bytes are exactly names.
    pub fn field_at(&self, ty: &Type, offset: u64, size: u64) -> Option<(Vec<Step>, Type)> {
        self.field_at_chosen(ty, offset, size, None)
    }

    /// [`TypeStore::field_at`], with the analyst's word: when the bytes
    /// reach a union and `chosen` names one of its members whose bytes
    /// they are, that member is taken where the walk would take the first
    /// the bytes fit — `u.f` where it would read `u.i`. A name no member
    /// answers with, or one whose bytes the access is not, is left alone:
    /// the first member the bytes fit is taken, as before.
    pub fn field_at_chosen(
        &self,
        ty: &Type,
        offset: u64,
        size: u64,
        chosen: Option<&str>,
    ) -> Option<(Vec<Step>, Type)> {
        let mut path = Vec::new();
        let leaf = self.walk(ty, offset, size, &mut path, 0, chosen)?;
        Some((path, leaf))
    }

    /// The members of the union `ty` is, under its typedefs, by name and
    /// in declaration order; `None` when `ty` is no union or names none
    /// of its members.
    pub fn union_members(&self, ty: &Type) -> Option<Vec<String>> {
        let (_, layout, union) = self.composite(ty)?;
        if !union {
            return None;
        }
        let names: Vec<String> = layout
            .fields
            .iter()
            .filter_map(|field| field.name.clone())
            .collect();
        (!names.is_empty()).then_some(names)
    }

    fn walk(
        &self,
        ty: &Type,
        offset: u64,
        size: u64,
        path: &mut Vec<Step>,
        depth: usize,
        chosen: Option<&str>,
    ) -> Option<Type> {
        if depth > 32 {
            return None;
        }
        let resolved = self.resolve(ty);
        let whole = self.size_of(resolved).ok()?;
        let covers_bit_unit = matches!(resolved, Type::Named(_))
            && self.composite(resolved).is_some_and(|(_, layout, _)| {
                layout.fields.iter().any(|field| {
                    field.bits.is_some() && offset == field.offset && size == field.size
                })
            });
        if offset + size > whole && !matches!(resolved, Type::Array(_, None)) {
            return None;
        }
        if self.is_scalar(resolved) {
            return (offset == 0 && size == whole).then(|| ty.clone());
        }
        match resolved {
            Type::Array(element, count) => {
                let each = self.size_of(element).ok().filter(|&each| each > 0)?;
                let index = offset / each;
                if count.is_some_and(|count| index >= count) {
                    return None;
                }
                path.push(Step::Index(index));
                if let Some(found) = self.walk(
                    element,
                    offset - index * each,
                    size,
                    path,
                    depth + 1,
                    chosen,
                ) {
                    return Some(found);
                }
                path.pop();
            }
            Type::Named(_) => {
                let (_, layout, union) = self.composite(resolved)?;
                // The analyst's word about a union comes before its
                // order, and it may name a bit-field as any member: the
                // named one first, the rest in declaration order.
                let order: Vec<&FieldLayout> = match chosen {
                    Some(name) if union => {
                        let mut fields: Vec<&FieldLayout> = Vec::new();
                        if let Some(field) = layout
                            .fields
                            .iter()
                            .find(|field| field.name.as_deref() == Some(name))
                        {
                            fields.push(field);
                        }
                        fields.extend(
                            layout
                                .fields
                                .iter()
                                .filter(|field| field.name.as_deref() != Some(name)),
                        );
                        fields
                    }
                    _ => layout.fields.iter().collect(),
                };
                for field in order {
                    if let Some((bit_offset, bits)) = field.bits {
                        // The bytes a named bit-field's is, the whole
                        // unit of its declared type: an access of the
                        // unit is the bit-field's, read with its first
                        // bit and width.
                        if !(offset == field.offset && size == field.size) {
                            continue;
                        }
                        // The unit is the bit-field's alone when no other
                        // bit-field overlaps it: every bit-field sharing
                        // its byte range, whatever declared type it came
                        // from, is a member the bytes also are.
                        if layout
                            .fields
                            .iter()
                            .filter(|held| held.bits.is_some())
                            .filter(|held| {
                                held.offset < field.offset + field.size
                                    && field.offset < held.offset + held.size
                            })
                            .count()
                            != 1
                        {
                            continue;
                        }
                        let Some(name) = &field.name else {
                            continue;
                        };
                        path.push(Step::Bits {
                            name: name.clone(),
                            bit_offset,
                            bits,
                        });
                        return Some(field.ty.clone());
                    }
                    let end = field.offset + field.size;
                    if field.offset <= offset && offset + size <= end {
                        let pushed = match &field.name {
                            Some(name) => {
                                path.push(Step::Field(name.clone()));
                                true
                            }
                            None => false,
                        };
                        if let Some(found) = self.walk(
                            &field.ty,
                            offset - field.offset,
                            size,
                            path,
                            depth + 1,
                            chosen,
                        ) {
                            return Some(found);
                        }
                        if pushed {
                            path.pop();
                        }
                    }
                }
            }
            _ => return None,
        }
        (offset == 0 && size == whole && !covers_bit_unit).then(|| ty.clone())
    }

    /// Where the member or element `path` leads inside `ty`: its offset in
    /// bytes and its type — the inverse of [`TypeStore::field_at`]. A
    /// member is reached through anonymous members as C reaches it.
    pub fn path_offset(&self, ty: &Type, path: &[Step]) -> Option<(u64, Type)> {
        let mut offset = 0u64;
        let mut ty = ty.clone();
        for step in path {
            let (at, inner) = match step {
                Step::Field(name) => self.member_offset(&ty, name, 0)?,
                Step::Bits {
                    name,
                    bit_offset,
                    bits,
                } => {
                    let (at, found) = self.bit_offset(&ty, name, 0)?;
                    // A step that no longer names this type's bit-field
                    // with the first bit and width it carries is stale:
                    // it resolves to nothing, not to whatever the name
                    // now means.
                    let Step::Bits {
                        bit_offset: at_bit,
                        bits: at_bits,
                        ..
                    } = found
                    else {
                        return None;
                    };
                    if at_bit != *bit_offset || at_bits != *bits {
                        return None;
                    }
                    // The step holds the bit-field's declared type, as
                    // `field_at` returns it for the leaf.
                    let inner = self.member_type(&ty, name).unwrap_or_else(|| ty.clone());
                    (at, inner)
                }
                Step::Index(index) => {
                    let Type::Array(element, _) = self.resolve(&ty) else {
                        return None;
                    };
                    let each = self.size_of(element).ok()?;
                    (each.checked_mul(*index)?, (**element).clone())
                }
            };
            offset = offset.checked_add(at)?;
            ty = inner;
        }
        Some((offset, ty))
    }

    /// The offset and type of the member `name` of the structure or union
    /// `ty`, through its anonymous members.
    fn member_offset(&self, ty: &Type, name: &str, depth: usize) -> Option<(u64, Type)> {
        if depth > 32 {
            return None;
        }
        let (_, layout, _) = self.composite(ty)?;
        // A named member of this struct shadows anything reachable through a
        // base class or an anonymous embed, so the named fields are scanned
        // before recursing into the unnamed ones.
        for field in &layout.fields {
            match &field.name {
                Some(own) if own == name && field.bits.is_none() => {
                    return Some((field.offset, field.ty.clone()));
                }
                Some(own) if own == name => {
                    return None;
                }
                _ => {}
            }
        }
        for field in &layout.fields {
            if field.name.is_none() && field.bits.is_none() {
                if let Some((at, inner)) = self.member_offset(&field.ty, name, depth + 1) {
                    return Some((field.offset + at, inner));
                }
            }
        }
        None
    }

    /// The named bit-field `name` of the structure or union `ty` as a
    /// path step, through its anonymous members; `None` when it is not
    /// one.
    pub fn bit_step(&self, ty: &Type, name: &str) -> Option<Step> {
        self.bit_offset(ty, name, 0).map(|(_, step)| step)
    }

    /// The offset in bytes and the step of the bit-field `name` of the
    /// structure or union `ty`, through its anonymous members.
    fn bit_offset(&self, ty: &Type, name: &str, depth: usize) -> Option<(u64, Step)> {
        if depth > 32 {
            return None;
        }
        let (_, layout, _) = self.composite(ty)?;
        for field in &layout.fields {
            match (&field.name, field.bits) {
                (Some(own), Some((bit_offset, bits))) if own == name => {
                    return Some((
                        field.offset,
                        Step::Bits {
                            name: name.to_string(),
                            bit_offset,
                            bits,
                        },
                    ));
                }
                (None, None) => {
                    // Only an anonymous member is searched: a named one
                    // is C's `member.bitfield`, not `bitfield`.
                    if let Some((at, step)) = self.bit_offset(&field.ty, name, depth + 1) {
                        return Some((field.offset + at, step));
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The members `[offset, offset + size)` of `ty` holds a byte of: each
    /// scalar member, inside nested structures and arrays, as its path
    /// spells it without the leading dot — `x`, `inner.g`, `a[2]` — in
    /// order. A union's members all lie at 0; each is named.
    pub fn members_in(&self, ty: &Type, offset: u64, size: u64) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_members(ty, offset, size, "", &mut out, 0);
        out
    }

    fn collect_members(
        &self,
        ty: &Type,
        offset: u64,
        size: u64,
        prefix: &str,
        out: &mut Vec<String>,
        depth: usize,
    ) {
        if depth > 32 || size == 0 {
            return;
        }
        let resolved = self.resolve(ty);
        match resolved {
            Type::Array(element, count) => {
                let Some(each) = self.size_of(element).ok().filter(|&each| each > 0) else {
                    return;
                };
                let first = offset / each;
                let mut last = (offset + size - 1) / each;
                if let Some(count) = count {
                    if *count == 0 {
                        return;
                    }
                    last = last.min(count - 1);
                }
                for index in first..=last {
                    let start = index * each;
                    let from = offset.max(start) - start;
                    let to = (offset + size).min(start + each) - start;
                    let path = format!("{prefix}[{index}]");
                    self.collect_members(element, from, to - from, &path, out, depth + 1);
                }
            }
            Type::Named(_) if self.composite(resolved).is_some() => {
                let (_, layout, _) = self.composite(resolved).expect("checked above");
                for field in &layout.fields {
                    let end = field.offset + field.size.max(1);
                    if end <= offset || offset + size <= field.offset {
                        continue;
                    }
                    let path = match &field.name {
                        Some(name) if prefix.is_empty() => name.clone(),
                        Some(name) => format!("{prefix}.{name}"),
                        None if field.bits.is_some() => continue,
                        None => prefix.to_string(),
                    };
                    if field.bits.is_some() {
                        if !out.contains(&path) {
                            out.push(path);
                        }
                        continue;
                    }
                    let from = offset.max(field.offset) - field.offset;
                    let to = (offset + size).min(field.offset + field.size) - field.offset;
                    self.collect_members(
                        &field.ty,
                        from,
                        to.saturating_sub(from),
                        &path,
                        out,
                        depth + 1,
                    );
                }
            }
            _ => {
                if !prefix.is_empty() && !out.iter().any(|p| p == prefix) {
                    out.push(prefix.to_string());
                }
            }
        }
    }

    /// The size of the structure or union `ty` when the x86-64 convention
    /// `convention` passes and returns it in general registers — the
    /// INTEGER class: at most 16 bytes, every member an integer, an
    /// enumeration or a pointer at its natural alignment — or why it does
    /// not: a member of floating type is passed in vector registers, and a
    /// larger structure, or one with a member out of its alignment, in
    /// memory. `convention` names the convention in the reasons, `System V`
    /// or `Go`.
    pub fn integer_class(&self, ty: &Type, convention: &str) -> Result<u64, String> {
        let spelled = ty.spelled(self);
        if self.composite(ty).is_none() {
            return Err(format!("{spelled} is no structure or union"));
        }
        let size = self.size_of(ty)?;
        if size > 16 {
            return Err(format!(
                "{spelled} is {size} bytes, which {convention} passes in memory"
            ));
        }
        self.integer_members(ty, &spelled, convention, 0)?;
        Ok(size)
    }

    fn integer_members(
        &self,
        ty: &Type,
        spelled: &str,
        convention: &str,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 32 {
            return Err(format!("{spelled} nests too deeply"));
        }
        match self.resolve(ty) {
            Type::Prim(p) if p.is_integer() => Ok(()),
            Type::Prim(_) => Err(format!(
                "{spelled} has a member of floating type, which {convention} passes in vector registers"
            )),
            Type::Pointer(_) | Type::BasedPointer { .. } => Ok(()),
            Type::Array(element, _) => self.integer_members(element, spelled, convention, depth + 1),
            resolved @ Type::Named(_) => {
                if self.enumeration(resolved).is_some() {
                    return Ok(());
                }
                let Some((_, layout, _)) = self.composite(resolved) else {
                    return Err(format!("{spelled} has a member of no known layout"));
                };
                for field in &layout.fields {
                    if field.bits.is_none() {
                        let align = self.align_of(&field.ty)?;
                        if align > 0 && field.offset % align != 0 {
                            return Err(format!(
                                "{spelled} has a member out of its alignment, which {convention} passes in memory"
                            ));
                        }
                    }
                    self.integer_members(&field.ty, spelled, convention, depth + 1)?;
                }
                Ok(())
            }
            Type::Function { .. } => Err(format!("{spelled} has a member of function type")),
        }
    }

    /// The type of the member `name` of the structure or union `ty`,
    /// reached through anonymous members as C reaches it.
    pub fn member_type(&self, ty: &Type, name: &str) -> Option<Type> {
        let (composite, _, _) = self.composite(ty)?;
        // Own members first, so a derived member shadows a base member of the
        // same name (C++ lookup): the base is consulted only when the struct's
        // own members — including anonymous embeds — do not name it.
        for member in composite.members.as_deref().unwrap_or(&[]) {
            match &member.name {
                Some(own) if own == name => return Some(member.ty.clone()),
                None => {
                    if let Some(found) = self.member_type(&member.ty, name) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        for base in &composite.base_classes {
            if let Some(found) = self.member_type(&Type::Named(base.clone()), name) {
                return Some(found);
            }
        }
        None
    }

    /// The enumerators an integer `value` of the enumeration `ty` is
    /// spelled by: the one enumerator of the value, or, in an enumeration
    /// of flags — every nonzero value a distinct power of two — the flags
    /// whose bits make it up, lowest first. `None` when no spelling is
    /// unambiguous: two enumerators share the value, or a bit is no flag's.
    pub fn enumerators_of(&self, ty: &Type, value: i64) -> Option<Vec<String>> {
        let (_, e) = self.enumeration(ty)?;
        let same: Vec<&String> = e
            .values
            .iter()
            .filter(|(_, v)| *v == value)
            .map(|(name, _)| name)
            .collect();
        match same.as_slice() {
            [one] => return Some(vec![(*one).clone()]),
            [] => {}
            _ => return None,
        }
        let flags: Vec<&(String, i64)> = e.values.iter().filter(|(_, v)| *v != 0).collect();
        let distinct: BTreeSet<i64> = flags.iter().map(|(_, v)| *v).collect();
        let are_flags = !flags.is_empty()
            && distinct.len() == flags.len()
            && flags
                .iter()
                .all(|(_, v)| *v > 0 && (*v as u64).is_power_of_two());
        if !are_flags || value <= 0 {
            return None;
        }
        let mut rest = value as u64;
        let mut names = Vec::new();
        let mut sorted: Vec<&&(String, i64)> = flags.iter().collect();
        sorted.sort_by_key(|(_, v)| *v);
        for (name, v) in sorted {
            let bit = *v as u64;
            if rest & bit != 0 {
                names.push(name.clone());
                rest &= !bit;
            }
        }
        (rest == 0 && names.len() > 1).then_some(names)
    }

    /// The definition `key` as C, one line: `struct point { int x; int y;
    /// }`, for a type spelled inline.
    fn inline_body(&self, key: &str) -> String {
        match self.definitions.get(key) {
            Some(Definition::Struct(c) | Definition::Union(c)) => {
                let kind = if c.is_class {
                    "class"
                } else {
                    key.split(' ').next().unwrap_or("struct")
                };
                let mut out = String::from(kind);
                if let Some(tag) = &c.tag {
                    out.push(' ');
                    out.push_str(tag);
                }
                if !c.base_classes.is_empty() {
                    out.push_str(" : ");
                    out.push_str(&c.base_classes.join(", "));
                }
                out.push_str(" {");
                for member in c.members.as_deref().unwrap_or(&[]) {
                    out.push(' ');
                    out.push_str(&member_text(member, self));
                    out.push(';');
                }
                out.push_str(" }");
                out
            }
            Some(Definition::Enum(e)) => {
                let mut out = String::from("enum");
                if let Some(tag) = &e.tag {
                    out.push(' ');
                    out.push_str(tag);
                }
                out.push_str(" { ");
                out.push_str(
                    &e.values
                        .iter()
                        .map(|(name, value)| format!("{name} = {value}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                out.push_str(" }");
                out
            }
            _ => key.to_string(),
        }
    }

    /// The definition `key` as C, with its layout in comments when
    /// `layout`: each member's offset before it, the padding between, and
    /// the size and alignment after.
    pub fn definition_text(&self, key: &str, layout: bool) -> Option<String> {
        let definition = self.definitions.get(key)?;
        let mut out = String::new();
        match definition {
            Definition::Typedef(ty) => {
                out.push_str("typedef ");
                let shown = self.typedef_target(ty, layout);
                out.push_str(&declaration_with(&shown, ty, key, self));
                out.push(';');
                if layout {
                    if let Ok((size, align)) = self.size_align(ty) {
                        let _ = write!(out, " /* size {size:#x}, align {align} */");
                    }
                }
            }
            Definition::Struct(_) | Definition::Union(_) | Definition::Enum(_) => {
                out.push_str(&self.body_text(key, layout, 0));
                out.push(';');
                if layout {
                    if let Ok((size, align)) = self.size_align(&Type::Named(key.to_string())) {
                        let _ = write!(out, " /* size {size:#x}, align {align} */");
                    }
                }
            }
        }
        Some(out)
    }

    /// A typedef's target as its definition prints it: an anonymous
    /// structure's body written out.
    fn typedef_target(&self, ty: &Type, layout: bool) -> Option<String> {
        match ty {
            Type::Named(key) if is_anonymous(key) => Some(self.body_text(key, layout, 0)),
            _ => None,
        }
    }

    /// The body of the structure, union or enumeration `key`, indented
    /// `depth` levels, without the closing `;`.
    fn body_text(&self, key: &str, layout: bool, depth: usize) -> String {
        let pad = "    ".repeat(depth + 1);
        let mut out = String::new();
        match self.definitions.get(key) {
            Some(Definition::Struct(c) | Definition::Union(c)) => {
                let kind = if c.is_class {
                    "class"
                } else {
                    key.split(' ').next().unwrap_or("struct")
                };
                out.push_str(kind);
                if c.packed {
                    out.push_str(" __attribute__((packed))");
                }
                if let Some(aligned) = c.aligned {
                    let _ = write!(out, " __attribute__((aligned({aligned})))");
                }
                if let Some(tag) = &c.tag {
                    out.push(' ');
                    out.push_str(tag);
                }
                if !c.base_classes.is_empty() {
                    out.push_str(" : ");
                    out.push_str(&c.base_classes.join(", "));
                }
                let Some(members) = &c.members else {
                    return out;
                };
                out.push_str(" {\n");
                // Base classes first: write each base's members as the base
                // appears at offset 0 (the first non-empty base).
                for base in &c.base_classes {
                    if let Some(Definition::Struct(bc) | Definition::Union(bc)) =
                        self.definitions.get(base)
                    {
                        if let Some(members) = &bc.members {
                            for member in members {
                                out.push_str(&pad);
                                out.push_str(&member_text_with(member, self, None));
                                out.push_str(";\n");
                            }
                        }
                    }
                }
                let fields = self.layouts.get(key).map(|l| &l.fields);
                let base_offset = c.base_classes.len() + usize::from(self.vtable_here(c));
                let mut end: u64 = if base_offset > 0 {
                    fields
                        .and_then(|f| f.get(base_offset - 1))
                        .map_or(0, |f| f.offset + f.size)
                } else {
                    0
                };
                for (index, member) in members.iter().enumerate() {
                    let field = fields.and_then(|f| f.get(index + base_offset));
                    if layout {
                        if let Some(field) = field {
                            if field.bits.is_none() && field.offset > end {
                                let _ = writeln!(
                                    out,
                                    "{pad}/* {:#04x}: {} bytes of padding */",
                                    end,
                                    field.offset - end
                                );
                            }
                        }
                    }
                    out.push_str(&pad);
                    if layout {
                        match field {
                            Some(FieldLayout {
                                offset,
                                bits: Some((bit, _)),
                                ..
                            }) => {
                                let _ = write!(out, "/* {offset:#04x}:{bit} */ ");
                            }
                            Some(field) => {
                                let _ = write!(out, "/* {:#04x} */ ", field.offset);
                            }
                            None => {}
                        }
                    }
                    let inline = match &member.ty {
                        Type::Named(inner) if is_anonymous(inner) => {
                            Some(self.body_text(inner, layout, depth + 1))
                        }
                        _ => None,
                    };
                    out.push_str(&match (&inline, &member.name) {
                        (Some(body), Some(name)) => format!("{body} {name}"),
                        (Some(body), None) => body.clone(),
                        (None, _) => member_text_with(member, self, None),
                    });
                    if inline.is_some() {
                        if let Some(bits) = member.bits {
                            let _ = write!(out, " : {bits}");
                        }
                    }
                    out.push_str(";\n");
                    if let Some(field) = field {
                        let field_end = match field.bits {
                            Some((bit, width)) => {
                                (field.offset * 8 + u64::from(bit) + u64::from(width)).div_ceil(8)
                            }
                            None => field.offset + field.size,
                        };
                        if !key.starts_with("union") {
                            end = end.max(field_end);
                        }
                    }
                }
                // Methods stand after the members; their declarations
                // hold no layout.
                for method in &c.methods {
                    out.push_str(&pad);
                    if method.is_virtual {
                        out.push_str("virtual ");
                    }
                    out.push_str(&member_text_with(
                        &Member {
                            name: Some(method.name.clone()),
                            ty: method.ty.clone(),
                            bits: None,
                        },
                        self,
                        None,
                    ));
                    out.push_str(";\n");
                }
                if layout && !key.starts_with("union") {
                    if let Some(l) = self.layouts.get(key) {
                        if l.size > end {
                            let _ = writeln!(
                                out,
                                "{pad}/* {:#04x}: {} bytes of padding */",
                                end,
                                l.size - end
                            );
                        }
                    }
                }
                out.push_str(&"    ".repeat(depth));
                out.push('}');
            }
            Some(Definition::Enum(e)) => {
                out.push_str("enum");
                if let Some(tag) = &e.tag {
                    out.push(' ');
                    out.push_str(tag);
                }
                if e.underlying != Prim::Int {
                    let _ = write!(out, " : {}", e.underlying.spelling());
                }
                if !e.complete {
                    return out;
                }
                out.push_str(" {\n");
                for (index, (name, value)) in e.values.iter().enumerate() {
                    let comma = if index + 1 < e.values.len() { "," } else { "" };
                    let _ = writeln!(out, "{pad}{name} = {}{comma}", enum_value_text(*value));
                }
                out.push_str(&"    ".repeat(depth));
                out.push('}');
            }
            _ => out.push_str(key),
        }
        out
    }

    /// The structure or union `key` as its definition writes it, apart:
    /// the head before its members — `struct conn`, `struct
    /// __attribute__((packed)) conn` — and each member's declaration
    /// without its `;`, an anonymous member's body written out, with the
    /// member's layout. None for no structure or union with members.
    pub fn member_texts(&self, key: &str) -> Option<(String, Vec<(String, FieldLayout)>)> {
        let (Definition::Struct(c) | Definition::Union(c)) = self.definitions.get(key)? else {
            return None;
        };
        let members = c.members.as_ref()?;
        let fields = &self.layouts.get(key)?.fields;
        // The vtable pointer is a field no member backs, at the head of
        // the members a class with one declares; the members pair with
        // the fields after it, the way the layout lays them.
        let base_offset = c.base_classes.len() + usize::from(self.vtable_here(c));
        let text = self.body_text(key, false, 0);
        let head = text.split(" {\n").next()?.to_string();
        let mut out = Vec::new();
        for (member, field) in members.iter().zip(fields.iter().skip(base_offset)) {
            let inline = match &member.ty {
                Type::Named(inner) if is_anonymous(inner) => Some(self.body_text(inner, false, 1)),
                _ => None,
            };
            let mut declared = match (&inline, &member.name) {
                (Some(body), Some(name)) => format!("{body} {name}"),
                (Some(body), None) => body.clone(),
                (None, _) => member_text_with(member, self, None),
            };
            if inline.is_some() {
                if let Some(bits) = member.bits {
                    let _ = write!(declared, " : {bits}");
                }
            }
            out.push((declared, field.clone()));
        }
        Some((head, out))
    }

    /// The `#pragma pack` the structure or union `key` was read under,
    /// when one was in force.
    pub fn pack_of(&self, key: &str) -> Option<u64> {
        match self.definitions.get(key)? {
            Definition::Struct(c) | Definition::Union(c) => c.pack,
            _ => None,
        }
    }

    /// Every named definition as C, written to be included by another
    /// header: a guard, `<stdint.h>` when a fixed-width type is spelled
    /// (and `<stddef.h>` when one of `size_t`, `wchar_t` and their kin is),
    /// and each [`definition_text`](Self::definition_text) in the order
    /// the store defined it — so a type that holds another by value comes
    /// after it. A definition read under `#pragma pack(N)` is wrapped in
    /// the pragma around it. C++ class definitions, which are not C,
    /// stand under `#ifdef __cplusplus`.
    pub fn header(&self) -> String {
        let names = self.names();
        let mut fixed = false;
        let mut standard = false;
        for key in names.iter().copied() {
            if let Some(text) = self.definition_text(key, false) {
                fixed |= needs_fixed(&text);
                standard |= needs_standard(&text);
            }
        }
        let mut out = String::new();
        out.push_str("// The types of the project, as C: written by AdmiralGrace\n");
        out.push_str("// under the data model the image's platform lays them out.\n");
        out.push_str("#ifndef ADMIRALGRACE_TYPES_H\n");
        out.push_str("#define ADMIRALGRACE_TYPES_H\n");
        if fixed {
            out.push_str("#include <stdint.h>\n");
        }
        if standard {
            out.push_str("#include <stddef.h>\n");
        }
        // Each C++ class definition stands under its own `#ifdef
        // __cplusplus`, in the store's order — so it never swallows the
        // C definitions that follow it (a C consumer then never sees
        // them), and a type that holds another by value still comes
        // after it.
        for key in names.iter().copied() {
            let Some(text) = self.definition_text(key, false) else {
                continue;
            };
            out.push('\n');
            let class = self
                .get(key)
                .is_some_and(|definition| definition.is_class());
            if class {
                out.push_str("#ifdef __cplusplus\n");
            }
            match self.pack_of(key) {
                Some(pack) => {
                    let _ = writeln!(out, "#pragma pack(push, {pack})");
                    let _ = writeln!(out, "{text}");
                    out.push_str("#pragma pack(pop)\n");
                }
                None => {
                    let _ = writeln!(out, "{text}");
                }
            }
            if class {
                out.push_str("#endif /* __cplusplus */\n");
            }
        }
        out.push_str("\n#endif /* ADMIRALGRACE_TYPES_H */\n");
        out
    }

    /// The definitions `ty` needs before it in C, their own needs first,
    /// in the order they were defined: every structure, union, enumeration
    /// and typedef it names, through pointers too.
    pub fn needed_by(&self, types: &[Type]) -> Vec<String> {
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        let mut queue: Vec<String> = Vec::new();
        for ty in types {
            let mut names = BTreeSet::new();
            ty.names(&mut names);
            queue.extend(names);
        }
        while let Some(key) = queue.pop() {
            if !wanted.insert(key.clone()) {
                continue;
            }
            for named in self.references_of(&key) {
                queue.push(named);
            }
        }
        self.order
            .iter()
            .filter(|key| wanted.contains(*key))
            .cloned()
            .collect()
    }

    /// The keys the definition `key` names: its members' and its target's
    /// types.
    pub fn references_of(&self, key: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        match self.definitions.get(key) {
            Some(Definition::Struct(c) | Definition::Union(c)) => {
                for member in c.members.as_deref().unwrap_or(&[]) {
                    member.ty.names(&mut names);
                }
                for base in &c.base_classes {
                    names.insert(base.clone());
                }
            }
            Some(Definition::Typedef(ty)) => ty.names(&mut names),
            _ => {}
        }
        names.remove(key);
        names
    }

    /// The members of `key` by name — a structure's and a union's members,
    /// the anonymous ones' within, an enumeration's enumerators — for a
    /// search.
    pub fn member_names(&self, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        match self.definitions.get(key) {
            Some(Definition::Struct(c) | Definition::Union(c)) => {
                for base in &c.base_classes {
                    out.extend(self.member_names(base));
                }
                for member in c.members.as_deref().unwrap_or(&[]) {
                    if let Some(name) = &member.name {
                        out.push(name.clone());
                    }
                    if let Type::Named(inner) = &member.ty {
                        if is_anonymous(inner) {
                            out.extend(self.member_names(inner));
                        }
                    }
                }
            }
            Some(Definition::Enum(e)) => out.extend(e.values.iter().map(|(n, _)| n.clone())),
            Some(Definition::Typedef(Type::Named(inner))) if is_anonymous(inner) => {
                out.extend(self.member_names(inner));
            }
            _ => {}
        }
        out
    }
}

/// What a search of the types looks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchIn {
    /// The definitions' names: `point` finds `struct point`.
    Name,
    /// Their members' and enumerators' names.
    Member,
    /// Their C, written out.
    Text,
    /// Any of them.
    Any,
}

impl SearchIn {
    /// What `text` names: `name`, `member`, `text` or `any`.
    pub fn parse(text: &str) -> Option<SearchIn> {
        Some(match text.trim() {
            "name" => SearchIn::Name,
            "member" => SearchIn::Member,
            "text" => SearchIn::Text,
            "any" | "" => SearchIn::Any,
            _ => return None,
        })
    }
}

impl TypeStore {
    /// The named definitions whose name, members or C hold `text`, in any
    /// case, in the order they were defined; every one for no text.
    pub fn search(&self, text: &str, within: SearchIn) -> Vec<String> {
        let wanted = text.trim().to_lowercase();
        self.names()
            .into_iter()
            .filter(|key| {
                if wanted.is_empty() {
                    return true;
                }
                let name = || key.to_lowercase().contains(&wanted);
                let member = || {
                    self.member_names(key)
                        .iter()
                        .any(|m| m.to_lowercase().contains(&wanted))
                };
                let body = || {
                    self.definition_text(key, false)
                        .is_some_and(|c| c.to_lowercase().contains(&wanted))
                };
                match within {
                    SearchIn::Name => name(),
                    SearchIn::Member => member(),
                    SearchIn::Text => body(),
                    SearchIn::Any => name() || member() || body(),
                }
            })
            .map(str::to_string)
            .collect()
    }

    /// The key `name` stands for: a definition's own, or the structure,
    /// union or enumeration it is the tag of when only one is — `point`
    /// is `struct point`.
    pub fn key_of(&self, name: &str) -> Option<String> {
        let name = name.trim();
        if self.definitions.contains_key(name) && !is_anonymous(name) {
            return Some(name.to_string());
        }
        let found: Vec<String> = ["struct", "union", "enum"]
            .iter()
            .map(|kind| format!("{kind} {name}"))
            .filter(|key| self.definitions.contains_key(key))
            .collect();
        match found.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        }
    }
}

/// Whether the C `text` spells a fixed-width type, which lives in
/// `<stdint.h>`.
fn needs_fixed(text: &str) -> bool {
    [
        "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t",
    ]
    .iter()
    .any(|ty| text.contains(ty))
}

/// Whether the C `text` spells a type `<stddef.h>` declares: `size_t`,
/// `ssize_t`, `wchar_t`, `ptrdiff_t`, `intptr_t` and `uintptr_t`.
fn needs_standard(text: &str) -> bool {
    [
        "size_t",
        "ssize_t",
        "wchar_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
    ]
    .iter()
    .any(|ty| text.contains(ty))
}

/// Whether `key` is an anonymous definition's.
fn is_anonymous(key: &str) -> bool {
    key.split(' ')
        .nth(1)
        .is_some_and(|rest| rest.starts_with(ANONYMOUS))
}

/// A key as the analyst reads it: an anonymous one as `anonymous struct`.
pub fn shown_key(key: &str) -> String {
    if is_anonymous(key) {
        format!("an anonymous {}", key.split(' ').next().unwrap_or("struct"))
    } else {
        key.to_string()
    }
}

/// An enumerator's value as its definition prints it: decimal, and hex
/// from 0x100 up, where flags usually are.
fn enum_value_text(value: i64) -> String {
    if value >= 0x100 {
        format!("{value:#x}")
    } else {
        value.to_string()
    }
}

fn round_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.div_ceil(align) * align
    }
}

/// A member as C declares it, without the `;`.
fn member_text(member: &Member, store: &TypeStore) -> String {
    member_text_with(member, store, None)
}

fn member_text_with(member: &Member, store: &TypeStore, base: Option<String>) -> String {
    let name = member.name.as_deref().unwrap_or("");
    let mut out = declaration_with(&base, &member.ty, name, store);
    if let Some(bits) = member.bits {
        let _ = write!(out, " : {bits}");
    }
    out
}

/// The declaration of `name` of type `ty` as C writes it — `int x`, `char
/// buf[16]`, `int (*cb)(char *, ...)` — or the type alone when `name` is
/// empty: `char *`, `int[4]`.
pub fn declaration(ty: &Type, name: &str, store: &TypeStore) -> String {
    declaration_with(&None, ty, name, store)
}

/// [`declaration`], the innermost type spelled `base` when given.
fn declaration_with(base: &Option<String>, ty: &Type, name: &str, store: &TypeStore) -> String {
    let mut inner = name.to_string();
    let mut ty = ty;
    loop {
        match ty {
            Type::Pointer(target) => {
                inner = format!("*{inner}");
                if matches!(**target, Type::Array(..) | Type::Function { .. }) {
                    inner = format!("({inner})");
                }
                ty = target;
            }
            Type::Array(element, count) => {
                match count {
                    Some(count) => {
                        let _ = write!(inner, "[{count}]");
                    }
                    None => inner.push_str("[]"),
                }
                ty = element;
            }
            Type::Function {
                ret,
                params,
                variadic,
                attrs,
            } => {
                let mut list: Vec<String> = params.iter().map(|p| p.spelled(store)).collect();
                if *variadic {
                    list.push("...".to_string());
                }
                if list.is_empty() {
                    list.push("void".to_string());
                }
                let params_text = list.join(", ");
                // A calling convention goes inside the pointer's parens,
                // `void (__stdcall *)(int)`, when the type is a pointer to
                // a function; `int __stdcall (int)` stays trailing.
                let conv_text = attrs.calling_convention.clone();
                if let Some(conv) = &conv_text {
                    if inner.starts_with("(*") {
                        let body = inner
                            .trim_start_matches('(')
                            .trim_end_matches(')')
                            .to_string();
                        inner = format!("({conv} {body})({params_text})");
                    } else if inner.is_empty() {
                        let _ = write!(inner, "{conv}({params_text})");
                    } else {
                        // A named function type spells the convention before
                        // the name, `int __stdcall f_t(int)` — glued to the
                        // name it would not reparse.
                        inner = format!("{conv} {inner}({params_text})");
                    }
                } else {
                    let _ = write!(inner, "({params_text})");
                }
                let mut suffix = String::new();
                if attrs.noreturn {
                    suffix.push_str(" __attribute__((noreturn))");
                }
                if attrs.pure {
                    suffix.push_str(" __attribute__((pure))");
                }
                if !suffix.is_empty() {
                    inner.push_str(&suffix);
                }
                ty = ret;
            }
            Type::BasedPointer { base, pointee } => {
                inner = if inner.is_empty() {
                    format!("__based({})", base.spelled(store))
                } else {
                    format!("__based({}) {inner}", base.spelled(store))
                };
                ty = pointee;
            }
            Type::Prim(_) | Type::Named(_) => break,
        }
    }
    let base_text = match (base, ty) {
        (Some(text), _) => text.clone(),
        (None, Type::Prim(p)) => p.spelling().to_string(),
        (None, Type::Named(key)) if is_anonymous(key) => store.inline_body(key),
        (None, Type::Named(key)) => key.clone(),
        (None, _) => String::new(),
    };
    if inner.is_empty() {
        base_text
    } else if inner.starts_with('[')
        || inner.starts_with('(') && !inner.starts_with("(*") && !inner.starts_with("(__")
    {
        format!("{base_text}{inner}")
    } else {
        format!("{base_text} {inner}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(model: DataModel, source: &str) -> TypeStore {
        let mut store = TypeStore::new(model);
        crate::ctype::parse_into(&mut store, source).unwrap();
        store
    }

    fn layout(store: &TypeStore, key: &str) -> (u64, u64, Vec<(String, u64)>) {
        let l = store.layout(key).unwrap();
        (
            l.size,
            l.align,
            l.fields
                .iter()
                .map(|f| (f.name.clone().unwrap_or_default(), f.offset))
                .collect(),
        )
    }

    fn named(fields: &[(&str, u64)]) -> Vec<(String, u64)> {
        fields.iter().map(|(n, o)| (n.to_string(), *o)).collect()
    }

    #[test]
    fn the_data_model_follows_the_language() {
        assert_eq!(DataModel::of_language("x86:LE:64:default").name, "LP64");
        assert_eq!(
            DataModel::of_language("x86:LE:64:default:windows").name,
            "LLP64"
        );
        assert_eq!(DataModel::of_language("AARCH64:LE:64:v8A").name, "LP64");
        assert_eq!(
            DataModel::of_language("x86:LE:32:default").name,
            "ILP32 (i386)"
        );
        assert_eq!(DataModel::of_language("ARM:LE:32:v8").name, "ILP32");
        assert_eq!(DataModel::of_language("MIPS:BE:32:default").name, "ILP32");
        assert_eq!(DataModel::of_language("x86:LE:32:default:windows").wchar, 2);
    }

    #[test]
    fn a_class_with_virtual_methods_holds_a_vtable_pointer_at_zero() {
        let store = store(
            DataModel::LP64,
            "class c { virtual int f(int); virtual int g(); int data; };",
        );
        // The vtable pointer at 0, the data after it, the size rounded.
        assert_eq!(
            layout(&store, "struct c"),
            (16, 8, named(&[("", 0), ("data", 8)]))
        );
        assert!(store.has_vtable("struct c"));
        assert!(store
            .definition_text("struct c", true)
            .unwrap()
            .find("class c")
            .is_some());
    }

    #[test]
    fn a_derived_class_shares_its_bases_vtable_pointer() {
        let store = store(
            DataModel::LP64,
            "class base { virtual int f(int); int a; };\n\
             class derived : public base { virtual int f(int); int b; };",
        );
        // One vtable pointer, the base's at 0, and no second.
        assert_eq!(
            layout(&store, "struct derived"),
            (24, 8, named(&[("", 0), ("b", 16)]))
        );
        assert!(store.has_vtable("struct derived"));
    }

    #[test]
    fn non_virtual_methods_add_no_vtable_pointer() {
        let store = store(
            DataModel::LP64,
            "class c { int f(int); int y; }; struct s { int h(void); int z; };",
        );
        assert_eq!(layout(&store, "struct c"), (4, 4, named(&[("y", 0)])));
        assert_eq!(layout(&store, "struct s"), (4, 4, named(&[("z", 0)])));
        assert!(!store.has_vtable("struct c"));
        assert!(!store.has_vtable("struct s"));
    }

    #[test]
    fn a_structure_is_padded_to_its_members_alignment_per_data_model() {
        let source = "struct s { char c; long l; short h; long long q; double d; };";
        let lp64 = store(DataModel::LP64, source);
        assert_eq!(
            layout(&lp64, "struct s"),
            (
                40,
                8,
                named(&[("c", 0), ("l", 8), ("h", 16), ("q", 24), ("d", 32)])
            )
        );
        let llp64 = store(DataModel::LLP64, source);
        assert_eq!(
            layout(&llp64, "struct s"),
            (
                32,
                8,
                named(&[("c", 0), ("l", 4), ("h", 8), ("q", 16), ("d", 24)])
            )
        );
        let ilp32 = store(DataModel::ILP32, source);
        assert_eq!(
            layout(&ilp32, "struct s"),
            (
                32,
                8,
                named(&[("c", 0), ("l", 4), ("h", 8), ("q", 16), ("d", 24)])
            )
        );
        let i386 = store(DataModel::ILP32_I386, source);
        assert_eq!(
            layout(&i386, "struct s"),
            (
                28,
                4,
                named(&[("c", 0), ("l", 4), ("h", 8), ("q", 12), ("d", 20)])
            )
        );
        // Pointers and long double follow the model.
        let source = "struct p { char c; void *p; long double ld; };";
        assert_eq!(layout(&store(DataModel::LP64, source), "struct p").0, 32);
        assert_eq!(layout(&store(DataModel::LLP64, source), "struct p").0, 24);
        assert_eq!(
            layout(&store(DataModel::ILP32_I386, source), "struct p").0,
            20
        );
    }

    #[test]
    fn packing_unions_and_arrays_are_laid_out() {
        let s = store(
            DataModel::LP64,
            "#pragma pack(push, 1)\n\
             struct a { char c; int i; };\n\
             #pragma pack(pop)\n\
             #pragma pack(2)\n\
             struct b { char c; int i; };\n\
             #pragma pack()\n\
             struct __attribute__((packed)) c { char c; long l; };\n\
             struct d { char c; int i; } __attribute__((aligned(16)));\n\
             union u { char c[5]; int i; short s; };\n\
             struct e { short s; struct a inner[3]; char tail; };\n\
             struct f { int n; char data[]; };",
        );
        assert_eq!(layout(&s, "struct a"), (5, 1, named(&[("c", 0), ("i", 1)])));
        assert_eq!(layout(&s, "struct b"), (6, 2, named(&[("c", 0), ("i", 2)])));
        assert_eq!(layout(&s, "struct c"), (9, 1, named(&[("c", 0), ("l", 1)])));
        assert_eq!(
            layout(&s, "struct d"),
            (16, 16, named(&[("c", 0), ("i", 4)]))
        );
        assert_eq!(
            layout(&s, "union u"),
            (8, 4, named(&[("c", 0), ("i", 0), ("s", 0)]))
        );
        assert_eq!(
            layout(&s, "struct e"),
            (18, 2, named(&[("s", 0), ("inner", 2), ("tail", 17)]))
        );
        assert_eq!(
            layout(&s, "struct f"),
            (4, 4, named(&[("n", 0), ("data", 4)]))
        );
    }

    #[test]
    fn bit_fields_share_their_declared_types_units() {
        let s = store(
            DataModel::LP64,
            "struct b { unsigned a : 3; unsigned b : 30; unsigned char c : 4; \
             unsigned : 0; unsigned char d : 2; };\n\
             struct n { char c; int : 4; };\n\
             struct __attribute__((packed)) p { unsigned a : 3; unsigned b : 30; };",
        );
        let l = s.layout("struct b").unwrap();
        let bits: Vec<(u64, Option<(u32, u32)>)> =
            l.fields.iter().map(|f| (f.offset, f.bits)).collect();
        // a in the first int; b does not fit after it, so the next int; c
        // does not fit in the byte b ends in, so the byte after; the zero
        // width moves to the next int.
        assert_eq!(
            bits,
            [
                (0, Some((0, 3))),
                (4, Some((0, 30))),
                (8, Some((0, 4))),
                (12, Some((0, 2)))
            ]
        );
        assert_eq!((l.size, l.align), (16, 4));
        // An unnamed bit-field gives the structure no alignment.
        let n = s.layout("struct n").unwrap();
        assert_eq!((n.size, n.align), (2, 1));
        // Packed, the bits follow one another.
        let p = s.layout("struct p").unwrap();
        assert_eq!(p.fields[1].bits, Some((3, 30)));
        assert_eq!((p.size, p.align), (5, 1));
    }

    #[test]
    fn an_access_to_a_bit_fields_unit_is_the_bit_field() {
        let s = store(
            DataModel::LP64,
            "struct solo { unsigned flags : 3; };\n\
             struct b { unsigned flags : 3; unsigned mode : 5; unsigned whole : 32; };\n\
             struct pair { int x; struct b inner; unsigned solo : 3; };\n\
             struct shared { unsigned a : 3; unsigned b : 30; };\n\
             struct shared_pair { long tail; unsigned a : 3, b : 5; };\n\
             struct full { unsigned a : 32; };\n\
             struct exactly_shared { unsigned a : 3, b : 29; };\n\
             struct mixed { unsigned char a : 3; unsigned b : 3; };\n\
             union bit_union { unsigned x; unsigned flags : 3; };\n\
             struct pack { struct __attribute__((packed)) { unsigned a : 3; unsigned b : 30; }; };",
        );
        let path = |key: &str, offset, size| {
            s.field_at(&Type::Named(key.to_string()), offset, size)
                .map(|(p, ty)| (path_text(&p), ty))
        };
        // The sole named bit-field in its int unit: the access is it,
        // with its first bit and width.
        assert_eq!(
            path("struct solo", 0, 4),
            Some((".flags".to_string(), Type::Prim(Prim::UInt)))
        );
        // `unsigned a:3; unsigned b:30;` does not share: `b` does not fit
        // in the 29 bits left after `a`, so `b` is at offset 4 and the
        // unit at 0 holds `a` alone — the access there is `.a`.
        assert_eq!(
            path("struct shared", 0, 4),
            Some((".a".to_string(), Type::Prim(Prim::UInt)))
        );
        assert_eq!(
            path("struct shared", 4, 4),
            Some((".b".to_string(), Type::Prim(Prim::UInt)))
        );
        // `a:3, b:5` do share one int unit: the access is no one member's.
        assert_eq!(path("struct shared_pair", 8, 4), None);
        // Part of a unit is no member either.
        assert_eq!(path("struct solo", 0, 2), None);
        // `struct b`'s flags and mode share the int at 0, so `pair.inner`
        // at 4 is no one member's; `pair.solo` at 12 is sole.
        assert_eq!(path("struct pair", 4, 4), None);
        assert_eq!(
            path("struct pair", 12, 4),
            Some((".solo".to_string(), Type::Prim(Prim::UInt)))
        );
        // A full-width bit-field (`a:32`) fills its unit alone.
        assert_eq!(
            path("struct full", 0, 4),
            Some((".a".to_string(), Type::Prim(Prim::UInt)))
        );
        // `a:3, b:29` exactly fill one int unit (3+29=32): two members
        // share it, so the access is no one member's.
        assert_eq!(path("struct exactly_shared", 0, 4), None);
        // `unsigned char a:3` at bit 0 followed by `unsigned b:3` with
        // start 3 fits in its 32-bit unit, so `b` also starts at byte
        // 0: the byte is shared whatever the declared types are, and
        // neither is sole in it.
        assert_eq!(path("struct mixed", 0, 1), None);
        // The analyst's word may name a union's bit-field member.
        assert_eq!(
            s.field_at_chosen(
                &Type::Named("union bit_union".to_string()),
                0,
                4,
                Some("flags")
            )
            .map(|(p, _)| path_text(&p)),
            Some(".flags".to_string())
        );
        // The path and the inverse agree, and a bit-field is found by
        // name through an anonymous member.
        let b = Type::Named("struct solo".to_string());
        let (path, _) = s.field_at(&b, 0, 4).unwrap();
        assert_eq!(s.path_offset(&b, &path).map(|(at, _)| at), Some(0));
        assert_eq!(
            s.bit_step(&Type::Named("struct pack".to_string()), "b"),
            Some(Step::Bits {
                name: "b".to_string(),
                bit_offset: 3,
                bits: 30,
            }),
            "the packed inner is an anonymous member, so `b` is the outer's"
        );
    }

    #[test]
    fn a_member_is_found_by_its_offset_and_size() {
        let s = store(
            DataModel::LP64,
            "struct inner { int g; int h; };\n\
             struct item { short k; int f; };\n\
             struct outer { long id; struct inner inner; struct item a[4]; \
             union { int x; float y; }; char name[8]; };",
        );
        let outer = Type::Named("struct outer".to_string());
        let path = |offset, size| s.field_at(&outer, offset, size).map(|(p, _)| path_text(&p));
        assert_eq!(path(0, 8), Some(".id".to_string()));
        assert_eq!(path(12, 4), Some(".inner.h".to_string()));
        assert_eq!(path(8, 8), Some(".inner".to_string()));
        assert_eq!(path(16 + 8 * 2 + 4, 4), Some(".a[2].f".to_string()));
        assert_eq!(path(16 + 8 * 3, 2), Some(".a[3].k".to_string()));
        // The anonymous union's members are the outer one's.
        assert_eq!(path(48, 4), Some(".x".to_string()));
        assert_eq!(path(52 + 3, 1), Some(".name[3]".to_string()));
        // Part of a scalar, padding, or across two members: no member.
        assert_eq!(path(2, 4), None);
        assert_eq!(path(16 + 2, 2), None);
        assert_eq!(path(4, 8), None);
        let (_, leaf) = s.field_at(&outer, 12, 4).unwrap();
        assert_eq!(leaf, Type::Prim(Prim::Int));
    }

    #[test]
    fn the_analysts_word_picks_which_union_member_an_access_means() {
        let s = store(
            DataModel::LP64,
            "union value { int i; float f; long l; };\n\
             struct holder { long id; union value v; };",
        );
        let holder = Type::Named("struct holder".to_string());
        let path = |offset, size, chosen: Option<&str>| {
            s.field_at_chosen(&holder, offset, size, chosen)
                .map(|(p, _)| path_text(&p))
        };
        // Without the word, the first member the bytes fit is taken.
        assert_eq!(path(8, 4, None), Some(".v.i".to_string()));
        // The word names another member the bytes are: the walk takes it.
        assert_eq!(path(8, 4, Some("f")), Some(".v.f".to_string()));
        // A member the bytes are not is left alone: 8 bytes are `l`'s
        // alone, so a word about `i` or `f` moves nothing.
        assert_eq!(path(8, 8, Some("i")), Some(".v.l".to_string()));
        // A name no member answers with is left alone too.
        assert_eq!(path(8, 4, Some("nope")), Some(".v.i".to_string()));
        // The word is only heard at a union: a structure's members are
        // taken by offset, as always.
        assert_eq!(path(0, 8, Some("f")), Some(".id".to_string()));
        // The members a view cycles, in declaration order.
        assert_eq!(
            s.union_members(&Type::Named("union value".to_string())),
            Some(vec!["i".to_string(), "f".to_string(), "l".to_string()])
        );
        assert_eq!(s.union_members(&holder), None, "a structure offers none");
    }

    #[test]
    fn a_range_of_bytes_names_its_members_and_a_path_its_offset() {
        let s = store(
            DataModel::LP64,
            "struct inner { int g; int h; };\n\
             struct outer { long id; struct inner inner; short a[4]; \
             union { int x; float y; }; };\n\
             struct pair { int x; int y; };\n\
             struct span { long lo; long hi; };\n\
             struct mixed { int n; float f; };\n\
             struct big { long a, b, c; };\n\
             struct __attribute__((packed)) odd { char c; int n; };",
        );
        let named = |key: &str| Type::Named(key.to_string());
        let outer = named("struct outer");
        assert_eq!(s.members_in(&outer, 4, 8), ["id", "inner.g"]);
        assert_eq!(s.members_in(&outer, 20, 4), ["a[2]", "a[3]"]);
        assert_eq!(s.members_in(&outer, 24, 4), ["x", "y"]);
        let path = |text: &[Step]| s.path_offset(&outer, text).map(|(at, _)| at);
        assert_eq!(
            path(&[Step::Field("inner".into()), Step::Field("h".into())]),
            Some(12)
        );
        assert_eq!(path(&[Step::Field("a".into()), Step::Index(3)]), Some(22));
        assert_eq!(path(&[Step::Field("x".into())]), Some(24));
        assert_eq!(path(&[Step::Field("nothing".into())]), None);
        // System V passes the INTEGER class in registers, and the rest not.
        assert_eq!(s.integer_class(&named("struct pair"), "System V"), Ok(8));
        assert_eq!(s.integer_class(&named("struct span"), "System V"), Ok(16));
        assert_eq!(
            s.integer_class(&named("struct mixed"), "System V"),
            Err("struct mixed has a member of floating type, which System V passes in vector registers".to_string())
        );
        assert_eq!(
            s.integer_class(&named("struct big"), "System V"),
            Err("struct big is 24 bytes, which System V passes in memory".to_string())
        );
        assert_eq!(
            s.integer_class(&named("struct odd"), "System V"),
            Err(
                "struct odd has a member out of its alignment, which System V passes in memory"
                    .to_string()
            )
        );
        // The reasons name the convention they are read under.
        assert_eq!(
            s.integer_class(&named("struct big"), "Go"),
            Err("struct big is 24 bytes, which Go passes in memory".to_string())
        );
    }

    #[test]
    fn flags_are_spelled_by_their_enumerators_when_unambiguous() {
        let s = store(
            DataModel::LP64,
            "enum mode { M_NONE = 0, M_READ = 1, M_WRITE = 2, M_EXEC = 4 };\n\
             enum state { S_IDLE, S_READY, S_DONE, S_ALIAS = 1 };",
        );
        let mode = Type::Named("enum mode".to_string());
        let state = Type::Named("enum state".to_string());
        assert_eq!(
            s.enumerators_of(&mode, 2),
            Some(vec!["M_WRITE".to_string()])
        );
        assert_eq!(
            s.enumerators_of(&mode, 5),
            Some(vec!["M_READ".to_string(), "M_EXEC".to_string()])
        );
        assert_eq!(s.enumerators_of(&mode, 8), None);
        assert_eq!(s.enumerators_of(&mode, 0), Some(vec!["M_NONE".to_string()]));
        assert_eq!(
            s.enumerators_of(&state, 2),
            Some(vec!["S_DONE".to_string()])
        );
        // Two names for 1, and no flags: no spelling.
        assert_eq!(s.enumerators_of(&state, 1), None);
        assert_eq!(s.enumerators_of(&state, 3), None);
    }

    #[test]
    fn the_types_are_searched_by_name_member_or_text() {
        let s = store(
            DataModel::LP64,
            "struct point { int x, y; };\n\
             struct node { struct point at; long weight; };\n\
             enum color { RED, GREEN };",
        );
        assert_eq!(s.search("POINT", SearchIn::Name), ["struct point"]);
        assert_eq!(s.search("weight", SearchIn::Member), ["struct node"]);
        assert_eq!(s.search("green", SearchIn::Member), ["enum color"]);
        assert_eq!(
            s.search("struct point", SearchIn::Text),
            ["struct point", "struct node"]
        );
        assert_eq!(s.search("", SearchIn::Any).len(), 3);
        assert_eq!(s.key_of("point"), Some("struct point".to_string()));
        assert_eq!(s.key_of("enum color"), Some("enum color".to_string()));
        assert_eq!(s.key_of("nothing"), None);
    }

    #[test]
    fn a_definition_prints_with_its_layout() {
        let s = store(
            DataModel::LP64,
            "struct node { int value; struct node *next; char tag; };\n\
             typedef struct node node_t;\n\
             typedef struct { int x, y; } point_t;\n\
             enum color { RED, GREEN = 4, BLUE = 0x200 };\n\
             typedef int (*cmp_t)(const void *, const void *);",
        );
        assert_eq!(
            s.definition_text("struct node", true).unwrap(),
            "struct node {\n    /* 0x00 */ int value;\n    /* 0x04: 4 bytes of padding */\n    \
             /* 0x08 */ struct node *next;\n    /* 0x10 */ char tag;\n    \
             /* 0x11: 7 bytes of padding */\n}; /* size 0x18, align 8 */"
        );
        assert_eq!(
            s.definition_text("node_t", false).unwrap(),
            "typedef struct node node_t;"
        );
        assert_eq!(
            s.definition_text("point_t", false).unwrap(),
            "typedef struct {\n    int x;\n    int y;\n} point_t;"
        );
        assert_eq!(
            s.definition_text("enum color", false).unwrap(),
            "enum color {\n    RED = 0,\n    GREEN = 4,\n    BLUE = 0x200\n};"
        );
        assert_eq!(
            s.definition_text("cmp_t", true).unwrap(),
            "typedef int (*cmp_t)(void *, void *); /* size 0x8, align 8 */"
        );
        let point = Type::Named("point_t".to_string());
        assert_eq!(Type::pointer(point).spelled(&s), "point_t *");
        assert_eq!(
            s.needed_by(&[Type::Named("node_t".to_string())]),
            ["struct node", "node_t"]
        );
    }

    #[test]
    fn a_header_is_the_definitions_in_the_stores_order_with_a_guard() {
        let s = store(
            DataModel::LP64,
            "struct node { int value; struct node *next; };\n\
             typedef struct node node_t;\n\
             typedef int32_t my_int;\n\
             typedef size_t count_t;",
        );
        let header = s.header();
        assert!(
            header.starts_with(
                "// The types of the project, as C: written by AdmiralGrace\n\
                 // under the data model the image's platform lays them out.\n\
                 #ifndef ADMIRALGRACE_TYPES_H\n\
                 #define ADMIRALGRACE_TYPES_H\n\
                 #include <stdint.h>\n\
                 #include <stddef.h>\n"
            ),
            "{header}"
        );
        assert!(
            header.contains("\nstruct node {\n    int value;\n    struct node *next;\n};\n"),
            "{header}"
        );
        assert!(
            header.contains("\ntypedef struct node node_t;\n"),
            "{header}"
        );
        assert!(header.contains("\ntypedef int32_t my_int;\n"), "{header}");
        assert!(header.contains("\ntypedef size_t count_t;\n"), "{header}");
        assert!(
            header.ends_with("\n#endif /* ADMIRALGRACE_TYPES_H */\n"),
            "{header}"
        );
        // In the store's order, as `definition_text` spells them.
        let node = header.find("struct node {").unwrap();
        let node_t = header.find("typedef struct node node_t;").unwrap();
        let my_int = header.find("typedef int32_t my_int;").unwrap();
        let count_t = header.find("typedef size_t count_t;").unwrap();
        assert!(
            node < node_t && node_t < my_int && my_int < count_t,
            "{header}"
        );
        assert!(!header.contains("/* 0x"), "{header}");
    }

    #[test]
    fn an_empty_store_has_a_guard_and_no_definitions() {
        let store = TypeStore::new(DataModel::LP64);
        let header = store.header();
        assert!(
            header.contains("#ifndef ADMIRALGRACE_TYPES_H\n"),
            "{header}"
        );
        assert!(
            header.contains("#define ADMIRALGRACE_TYPES_H\n"),
            "{header}"
        );
        assert!(
            header.contains("\n#endif /* ADMIRALGRACE_TYPES_H */\n"),
            "{header}"
        );
        assert!(!header.contains("#include <stdint.h>"), "{header}");
        assert!(!header.contains("#include <stddef.h>"), "{header}");
    }

    #[test]
    fn a_packed_definition_is_wrapped_in_its_pragma() {
        let s = store(
            DataModel::LP64,
            "#pragma pack(2)\nstruct odd { char c; int n; };\n#pragma pack()\n",
        );
        let header = s.header();
        assert!(
            header.contains(
                "#pragma pack(push, 2)\nstruct odd {\n    char c;\n    int n;\n};\n#pragma pack(pop)\n"
            ),
            "{header}"
        );
    }

    #[test]
    fn a_class_opens_the_cplusplus_section() {
        let s = store(
            DataModel::LP64,
            "class c { virtual int f(int); int data; };\nstruct s { int x; };",
        );
        let header = s.header();
        assert!(header.contains("#ifdef __cplusplus\n"), "{header}");
        assert!(header.contains("class c {"), "{header}");
        assert!(header.contains("#endif /* __cplusplus */\n"), "{header}");
        // The class sits under the guard, the C struct after the class
        // does not: the guard closes before anything else. Both come
        // in the store's order.
        let open = header.find("#ifdef __cplusplus").unwrap();
        let klass = header.find("class c {").unwrap();
        let close = header.find("#endif /* __cplusplus */").unwrap();
        let c_struct = header.find("struct s {").unwrap();
        assert!(
            open < klass && klass < close && close < c_struct,
            "{header}"
        );
    }

    #[test]
    fn an_ssize_t_spelling_needs_the_standard_include() {
        let s = store(DataModel::LP64, "typedef ssize_t my_ssize;");
        let header = s.header();
        assert!(header.contains("#include <stddef.h>\n"), "{header}");
    }
    #[test]
    fn function_attrs_and_based_pointers_layout() {
        let mut store = TypeStore::new(DataModel::LP64);
        crate::ctype::parse_into(
            &mut store,
            "typedef void __stdcall (*cb_t)(int);\n\
             struct seg { long *base; char __based(base) *bp; };\n\
             struct base { long x; }; struct derived : public base { long y; };",
        )
        .unwrap();
        assert_eq!(
            store.size_of(&Type::BasedPointer {
                base: Box::new(Type::Named("struct seg".into())),
                pointee: Box::new(Type::Prim(Prim::Char)),
            }),
            Ok(8)
        );
        assert!(store.is_scalar(&Type::BasedPointer {
            base: Box::new(Type::Prim(Prim::Void)),
            pointee: Box::new(Type::Prim(Prim::Char)),
        }));
        let layout = store.layout("struct derived").unwrap();
        assert_eq!(layout.size, 16);
        assert_eq!(layout.fields[0].offset, 0);
        assert_eq!(layout.fields[1].offset, 8);
        assert_eq!(layout.fields[1].name.as_deref(), Some("y"));
        let a = Type::Function {
            ret: Box::new(Type::Prim(Prim::Int)),
            params: vec![Type::Prim(Prim::Int)],
            variadic: false,
            attrs: TypeAttrs {
                calling_convention: Some("__cdecl".into()),
                noreturn: false,
                pure: true,
            },
        };
        let b = Type::Function {
            ret: Box::new(Type::Prim(Prim::Int)),
            params: vec![Type::Prim(Prim::Int)],
            variadic: false,
            attrs: TypeAttrs {
                calling_convention: Some("__cdecl".into()),
                noreturn: false,
                pure: true,
            },
        };
        assert_eq!(a, b);
        assert_eq!(a.spelled(&store), "int __cdecl(int) __attribute__((pure))");
    }

    #[test]
    fn a_derived_member_shadows_a_base_member() {
        let store = store(
            DataModel::LP64,
            "struct base { long x; long y; };\nstruct d : base { int x; };",
        );
        let d = Type::Named("struct d".into());
        // C++ lookup: the derived's own x wins over the base's.
        assert_eq!(store.member_type(&d, "x"), Some(Type::Prim(Prim::Int)));
        // and the offset path finds the derived's x at 16, not the base's at 0.
        assert_eq!(
            store.path_offset(&d, &[Step::Field("x".into())]),
            Some((16, Type::Prim(Prim::Int)))
        );
        // a name only the base has is still found through the base.
        assert_eq!(store.member_type(&d, "y"), Some(Type::Prim(Prim::Long)));
        assert_eq!(
            store.path_offset(&d, &[Step::Field("y".into())]),
            Some((8, Type::Prim(Prim::Long)))
        );
    }
}
