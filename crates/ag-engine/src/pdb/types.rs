//! PDB type information (TPI / IPI) rendered back as C (#400).
//!
//! Reads CodeView type records (`pdb::TypeData` and `pdb::IdData`) into
//! [`crate::types::Type`] and C definitions (`crate::ctype::TypeText`)
//! ordered so every value dependency is defined before its user. C++
//! constructs without a plain C representation (inheritance, vtables,
//! scoped/templated types, pointer-to-member) are held back and counted.

use std::collections::{BTreeMap, BTreeSet};

use pdb::{
    FallibleIterator, IdData, IdInformation, Indirection, PrimitiveKind, TypeData, TypeIndex,
    TypeInformation, Variant,
};

use crate::ctype::TypeText;
use crate::types::{self as et, DataModel, Prim, Type, TypeStore};

/// Whether `name` is a plain C identifier suitable for a tag, typedef,
/// member, or parameter name.
pub fn is_c_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// All type and ID records loaded from a PDB's TPI and IPI streams.
pub struct TypeCatalog<'a> {
    model: DataModel,
    store: TypeStore,
    records: BTreeMap<u32, TypeData<'a>>,
    ids: BTreeMap<u32, IdData<'a>>,
    full_structs: BTreeMap<String, u32>,
    full_unions: BTreeMap<String, u32>,
    full_enums: BTreeMap<String, u32>,
}

impl<'a> TypeCatalog<'a> {
    /// Load every recognized record from `tpi` and optional `ipi`.
    pub fn build<'s>(
        tpi: &'a TypeInformation<'s>,
        ipi: Option<&'a IdInformation<'s>>,
        model: DataModel,
    ) -> Result<Self, String> {
        let mut records = BTreeMap::new();
        let mut full_structs = BTreeMap::new();
        let mut full_unions = BTreeMap::new();
        let mut full_enums = BTreeMap::new();

        let mut iter = tpi.iter();
        while let Some(item) = iter.next().map_err(|e| format!("reading TPI types: {e}"))? {
            let index = item.index().0;
            match item.parse() {
                Ok(data) => {
                    match &data {
                        TypeData::Class(c) if !c.properties.forward_reference() => {
                            let name = c.name.to_string().into_owned();
                            if !name.is_empty() {
                                full_structs.entry(name).or_insert(index);
                            }
                            if let Some(unique) = c.unique_name {
                                full_structs
                                    .entry(unique.to_string().into_owned())
                                    .or_insert(index);
                            }
                        }
                        TypeData::Union(u) if !u.properties.forward_reference() => {
                            let name = u.name.to_string().into_owned();
                            if !name.is_empty() {
                                full_unions.entry(name).or_insert(index);
                            }
                            if let Some(unique) = u.unique_name {
                                full_unions
                                    .entry(unique.to_string().into_owned())
                                    .or_insert(index);
                            }
                        }
                        TypeData::Enumeration(e) if !e.properties.forward_reference() => {
                            let name = e.name.to_string().into_owned();
                            if !name.is_empty() {
                                full_enums.entry(name).or_insert(index);
                            }
                            if let Some(unique) = e.unique_name {
                                full_enums
                                    .entry(unique.to_string().into_owned())
                                    .or_insert(index);
                            }
                        }
                        _ => {}
                    }
                    records.insert(index, data);
                }
                Err(pdb::Error::UnimplementedTypeKind(_)) => {}
                Err(e) => return Err(format!("parsing TPI record {index:#x}: {e}")),
            }
        }

        let mut ids = BTreeMap::new();
        if let Some(ipi) = ipi {
            let mut iter = ipi.iter();
            while let Some(item) = iter.next().map_err(|e| format!("reading IPI ids: {e}"))? {
                let index = item.index().0;
                match item.parse() {
                    Ok(data) => {
                        ids.insert(index, data);
                    }
                    Err(pdb::Error::UnimplementedTypeKind(_)) => {}
                    Err(e) => return Err(format!("parsing IPI record {index:#x}: {e}")),
                }
            }
        }

        Ok(Self {
            model,
            store: TypeStore::new(model),
            records,
            ids,
            full_structs,
            full_unions,
            full_enums,
        })
    }

    /// Resolve forward references to their complete record index when present.
    fn resolve_index(&self, index: TypeIndex) -> TypeIndex {
        let Some(data) = self.records.get(&index.0) else {
            return index;
        };
        match data {
            TypeData::Class(c) if c.properties.forward_reference() => {
                if let Some(unique) = c.unique_name {
                    if let Some(&full) = self.full_structs.get(unique.to_string().as_ref()) {
                        return TypeIndex(full);
                    }
                }
                if let Some(&full) = self.full_structs.get(c.name.to_string().as_ref()) {
                    return TypeIndex(full);
                }
            }
            TypeData::Union(u) if u.properties.forward_reference() => {
                if let Some(unique) = u.unique_name {
                    if let Some(&full) = self.full_unions.get(unique.to_string().as_ref()) {
                        return TypeIndex(full);
                    }
                }
                if let Some(&full) = self.full_unions.get(u.name.to_string().as_ref()) {
                    return TypeIndex(full);
                }
            }
            TypeData::Enumeration(e) if e.properties.forward_reference() => {
                if let Some(unique) = e.unique_name {
                    if let Some(&full) = self.full_enums.get(unique.to_string().as_ref()) {
                        return TypeIndex(full);
                    }
                }
                if let Some(&full) = self.full_enums.get(e.name.to_string().as_ref()) {
                    return TypeIndex(full);
                }
            }
            _ => {}
        }
        index
    }

    /// Gather all `FieldList` entries across `LF_INDEX` continuation records.
    fn field_list(&self, start: TypeIndex) -> Vec<&TypeData<'a>> {
        let mut out = Vec::new();
        let mut cur = Some(start);
        let mut seen = BTreeSet::new();
        while let Some(idx) = cur {
            if !seen.insert(idx.0) {
                break;
            }
            let Some(TypeData::FieldList(list)) = self.records.get(&idx.0) else {
                break;
            };
            for field in &list.fields {
                out.push(field);
            }
            cur = list.continuation;
        }
        out
    }

    /// Size in bytes of a PDB type when known.
    pub fn type_size(&self, index: TypeIndex) -> Option<u64> {
        let mut visited = BTreeSet::new();
        self.type_size_inner(index, &mut visited)
    }

    fn type_size_inner(&self, index: TypeIndex, visited: &mut BTreeSet<u32>) -> Option<u64> {
        if index.0 < 0x1000 {
            return primitive_size(index.0, self.model);
        }
        let resolved = self.resolve_index(index);
        if !visited.insert(resolved.0) {
            return None;
        }
        let size = match self.records.get(&resolved.0)? {
            TypeData::Modifier(m) => self.type_size_inner(m.underlying_type, visited),
            TypeData::Pointer(p) => {
                let sz = u64::from(p.attributes.size());
                Some(if sz > 0 { sz } else { self.model.pointer })
            }
            TypeData::Array(arr) => arr.dimensions.last().copied().map(u64::from),
            TypeData::Class(c) => (!c.properties.forward_reference()).then_some(c.size),
            TypeData::Union(u) => (!u.properties.forward_reference()).then_some(u.size),
            TypeData::Enumeration(e) => self.type_size_inner(e.underlying_type, visited),
            TypeData::Bitfield(b) => self.type_size_inner(b.underlying_type, visited),
            _ => None,
        };
        visited.remove(&resolved.0);
        size
    }

    /// Convert a PDB type index into an engine [`Type`].
    pub fn to_engine_type(&self, index: TypeIndex) -> Option<Type> {
        let mut visited = BTreeSet::new();
        self.to_engine_type_inner(index, &mut visited)
    }

    fn to_engine_type_inner(&self, index: TypeIndex, visited: &mut BTreeSet<u32>) -> Option<Type> {
        if index.0 < 0x1000 {
            return primitive_to_engine(index.0);
        }
        let resolved = self.resolve_index(index);
        if !visited.insert(resolved.0) {
            return None;
        }
        let out = match self.records.get(&resolved.0)? {
            TypeData::Primitive(p) => primitive_data_to_engine(*p),
            TypeData::Modifier(m) => self.to_engine_type_inner(m.underlying_type, visited),
            TypeData::Pointer(p) => {
                if p.attributes.pointer_to_member() {
                    None
                } else {
                    let pointee = self
                        .to_engine_type_inner(p.underlying_type, visited)
                        .unwrap_or(Type::Prim(Prim::Void));
                    Some(Type::pointer(pointee))
                }
            }
            TypeData::Array(arr) => {
                let elem = self.to_engine_type_inner(arr.element_type, visited)?;
                let elem_size = self.type_size(arr.element_type)?;
                if elem_size == 0 || arr.dimensions.is_empty() {
                    return None;
                }
                let mut ty = elem;
                let mut prev = elem_size;
                for &dim_bytes in &arr.dimensions {
                    let dim = u64::from(dim_bytes);
                    if prev == 0 || dim == 0 || dim % prev != 0 {
                        return None;
                    }
                    let count = dim / prev;
                    ty = Type::Array(Box::new(ty), Some(count));
                    prev = dim;
                }
                Some(ty)
            }
            TypeData::Procedure(proc) => {
                let ret = proc
                    .return_type
                    .and_then(|r| self.to_engine_type_inner(r, visited))
                    .unwrap_or(Type::Prim(Prim::Void));
                let (params, variadic) = self.procedure_args(proc.argument_list, visited)?;
                let mut attrs = et::TypeAttrs::default();
                attrs.calling_convention = convention_name(
                    proc.attributes.calling_convention(),
                    self.model.pointer == 4,
                )
                .map(str::to_string);
                Some(Type::Function {
                    ret: Box::new(ret),
                    params,
                    variadic,
                    attrs,
                })
            }
            TypeData::Class(c) => {
                let name = c.name.to_string();
                is_c_identifier(&name).then(|| Type::Named(format!("struct {name}")))
            }
            TypeData::Union(u) => {
                let name = u.name.to_string();
                is_c_identifier(&name).then(|| Type::Named(format!("union {name}")))
            }
            TypeData::Enumeration(e) => {
                let name = e.name.to_string();
                is_c_identifier(&name).then(|| Type::Named(format!("enum {name}")))
            }
            TypeData::Bitfield(b) => self.to_engine_type_inner(b.underlying_type, visited),
            _ => None,
        };
        visited.remove(&resolved.0);
        out
    }

    fn procedure_args(
        &self,
        arglist_index: TypeIndex,
        visited: &mut BTreeSet<u32>,
    ) -> Option<(Vec<Type>, bool)> {
        if arglist_index.0 == 0 {
            return Some((Vec::new(), false));
        }
        let Some(TypeData::ArgumentList(list)) = self.records.get(&arglist_index.0) else {
            return None;
        };
        let mut params = Vec::new();
        let mut variadic = false;
        for (idx, &arg) in list.arguments.iter().enumerate() {
            // CodeView marks `...` with a trailing `T_NOTYPE` (0x0000).
            if arg.0 == 0 && idx + 1 == list.arguments.len() {
                variadic = true;
                break;
            }
            let ty = self.to_engine_type_inner(arg, visited)?;
            if ty == Type::Prim(Prim::Void) && list.arguments.len() == 1 {
                break;
            }
            params.push(ty);
        }
        Some((params, variadic))
    }

    /// Render a PDB type as a C type string (e.g. `int`, `struct point *`, `char[16]`).
    pub fn render_type(&self, index: TypeIndex) -> Option<String> {
        let ty = self.to_engine_type(index)?;
        Some(ty.spelled(&self.store))
    }

    /// Render a procedure's C prototype (`int add(int a, int b)`), reading
    /// parameter types from TPI (or IPI when `is_id` is true) and pairing
    /// them with parameter names collected from the procedure scope.
    pub fn render_prototype(
        &self,
        type_index: TypeIndex,
        is_id: bool,
        fn_name: &str,
        param_names: &[Option<String>],
    ) -> Option<String> {
        let proc_type_idx = if is_id {
            match self.ids.get(&type_index.0)? {
                IdData::Function(f) => f.function_type,
                IdData::MemberFunction(mf) => mf.function_type,
                _ => return None,
            }
        } else {
            type_index
        };

        let mut visited = BTreeSet::new();
        let (ret_idx, arglist_idx, cc, this_ptr) = match self.records.get(&proc_type_idx.0)? {
            TypeData::Procedure(p) => (
                p.return_type,
                p.argument_list,
                p.attributes.calling_convention(),
                None,
            ),
            TypeData::MemberFunction(mf) => (
                Some(mf.return_type),
                mf.argument_list,
                mf.attributes.calling_convention(),
                mf.this_pointer_type,
            ),
            _ => return None,
        };

        let ret_ty = ret_idx
            .and_then(|r| self.to_engine_type_inner(r, &mut visited))
            .unwrap_or(Type::Prim(Prim::Void));
        let (mut arg_types, variadic) = self.procedure_args(arglist_idx, &mut visited)?;
        if let Some(this_ty_idx) = this_ptr {
            let this_ty = self
                .to_engine_type_inner(this_ty_idx, &mut visited)
                .unwrap_or_else(|| Type::pointer(Type::Prim(Prim::Void)));
            arg_types.insert(0, this_ty);
        }

        let mut params = Vec::new();
        for (i, arg_ty) in arg_types.iter().enumerate() {
            let pname = param_names
                .get(i)
                .and_then(|n| n.as_deref())
                .filter(|n| is_c_identifier(n));
            match pname {
                Some(n) => params.push(et::declaration(arg_ty, n, &self.store)),
                None => params.push(arg_ty.spelled(&self.store)),
            }
        }
        if variadic {
            params.push("...".to_string());
        }
        if params.is_empty() {
            params.push("void".to_string());
        }

        let ret_text = ret_ty.spelled(&self.store);
        let conv = convention_name(cc, self.model.pointer == 4)
            .map(|c| format!("{c} "))
            .unwrap_or_default();
        // Prototype declaration name must be a plain identifier for `ctype::parse_prototype`.
        let proto_name = if is_c_identifier(fn_name) {
            fn_name
        } else {
            "fn"
        };
        Some(format!(
            "{ret_text} {conv}{proto_name}({})",
            params.join(", ")
        ))
    }

    /// Render every plain-C struct, union, enum, and `S_UDT` typedef in
    /// dependency order. Returns `(definitions, held_back_count)`.
    pub fn render_definitions(&self, udts: &[(String, TypeIndex)]) -> (Vec<TypeText>, usize) {
        let mut defs: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new();
        let mut held_back = 0usize;
        let mut defined_names: BTreeSet<String> = BTreeSet::new();

        for (&idx, data) in &self.records {
            match data {
                TypeData::Class(c) if !c.properties.forward_reference() => {
                    let name = c.name.to_string().into_owned();
                    if name.is_empty() {
                        continue;
                    }
                    if !is_c_identifier(&name)
                        || c.derived_from.is_some()
                        || c.vtable_shape.is_some()
                    {
                        held_back += 1;
                        continue;
                    }
                    if let Some((text, deps)) = self.render_composite(
                        "struct",
                        &name,
                        c.fields,
                        c.properties.packed(),
                    ) {
                        let key = format!("struct {name}");
                        defined_names.insert(name.clone());
                        defined_names.insert(key.clone());
                        defs.entry(key).or_insert((text, deps));
                    } else {
                        held_back += 1;
                    }
                }
                TypeData::Union(u) if !u.properties.forward_reference() => {
                    let name = u.name.to_string().into_owned();
                    if name.is_empty() {
                        continue;
                    }
                    if !is_c_identifier(&name) {
                        held_back += 1;
                        continue;
                    }
                    if let Some((text, deps)) = self.render_composite(
                        "union",
                        &name,
                        Some(u.fields),
                        u.properties.packed(),
                    ) {
                        let key = format!("union {name}");
                        defined_names.insert(name.clone());
                        defined_names.insert(key.clone());
                        defs.entry(key).or_insert((text, deps));
                    } else {
                        held_back += 1;
                    }
                }
                TypeData::Enumeration(e) if !e.properties.forward_reference() => {
                    let name = e.name.to_string().into_owned();
                    if name.is_empty() {
                        continue;
                    }
                    if !is_c_identifier(&name) {
                        held_back += 1;
                        continue;
                    }
                    if let Some(text) = self.render_enum(&name, e.fields) {
                        let key = format!("enum {name}");
                        defined_names.insert(name.clone());
                        defined_names.insert(key.clone());
                        defs.entry(key).or_insert((text, BTreeSet::new()));
                    } else {
                        held_back += 1;
                    }
                }
                _ => {
                    let _ = idx;
                }
            }
        }

        // Typedefs from `S_UDT` symbol records.
        for (name, target_idx) in udts {
            if !is_c_identifier(name) {
                held_back += 1;
                continue;
            }
            if defined_names.contains(name) {
                // Already defined as `typedef struct Name { ... } Name;`.
                continue;
            }
            let Some(ty) = self.to_engine_type(*target_idx) else {
                held_back += 1;
                continue;
            };
            // Avoid `typedef struct Foo Foo;` when `Foo` was held back or matches self.
            if let Type::Named(ref target_key) = ty {
                let short = target_key
                    .strip_prefix("struct ")
                    .or_else(|| target_key.strip_prefix("union "))
                    .or_else(|| target_key.strip_prefix("enum "))
                    .unwrap_or(target_key);
                if short == name && defs.contains_key(target_key) {
                    continue;
                }
                if !defs.contains_key(target_key) && !defined_names.contains(target_key) {
                    // Self-referential or incomplete C++ UDT not defined in C.
                    held_back += 1;
                    continue;
                }
            }
            let mut deps = BTreeSet::new();
            collect_value_deps(&ty, &mut deps);
            // Typedefs also depend on any named target directly (e.g. `typedef struct Foo *PFoo;`
            // can forward-reference `struct Foo`, whereas `typedef Foo Bar;` needs `Foo`).
            if let Type::Named(ref target_key) = ty {
                deps.insert(target_key.clone());
            }
            let decl = et::declaration(&ty, name, &self.store);
            let text = format!("typedef {decl};");
            defined_names.insert(name.clone());
            defs.entry(name.clone()).or_insert((text, deps));
        }

        let ordered = topo_sort(&defs);
        (ordered, held_back)
    }

    fn render_composite(
        &self,
        keyword: &str,
        name: &str,
        fields_idx: Option<TypeIndex>,
        packed: bool,
    ) -> Option<(String, BTreeSet<String>)> {
        let mut deps = BTreeSet::new();
        let mut body = String::new();
        if packed {
            body.push_str("#pragma pack(1)\n");
        }
        body.push_str(&format!("typedef {keyword} {name} {{\n"));
        let mut member_count = 0usize;
        if let Some(fidx) = fields_idx {
            for field in self.field_list(fidx) {
                match field {
                    TypeData::Member(m) => {
                        let mname = m.name.to_string();
                        if !is_c_identifier(&mname) {
                            return None;
                        }
                        let resolved = self.resolve_index(m.field_type);
                        if let Some(TypeData::Bitfield(bf)) = self.records.get(&resolved.0) {
                            let base_ty = self.to_engine_type(bf.underlying_type)?;
                            let base_str = base_ty.spelled(&self.store);
                            body.push_str(&format!("  {base_str} {mname} : {};\n", bf.length));
                        } else {
                            let ty = self.to_engine_type(m.field_type)?;
                            collect_value_deps(&ty, &mut deps);
                            let decl = et::declaration(&ty, &mname, &self.store);
                            body.push_str(&format!("  {decl};\n"));
                        }
                        member_count += 1;
                    }
                    TypeData::StaticMember(_) => {
                        // Static members do not contribute to the struct layout.
                    }
                    TypeData::BaseClass(_)
                    | TypeData::VirtualBaseClass(_)
                    | TypeData::VirtualFunctionTablePointer(_)
                    | TypeData::Method(_)
                    | TypeData::OverloadedMethod(_) => {
                        return None;
                    }
                    _ => {}
                }
            }
        }
        // An empty C struct (`struct foo {}`) is rejected by strict C parsers;
        // skip empty forward-like composites without fields.
        if member_count == 0 {
            return None;
        }
        body.push_str(&format!("}} {name};"));
        if packed {
            body.push_str("\n#pragma pack()");
        }
        deps.remove(&format!("{keyword} {name}"));
        deps.remove(name);
        Some((body, deps))
    }

    fn render_enum(&self, name: &str, fields_idx: TypeIndex) -> Option<String> {
        let mut body = format!("typedef enum {name} {{\n");
        let mut count = 0usize;
        for field in self.field_list(fields_idx) {
            if let TypeData::Enumerate(e) = field {
                let ename = e.name.to_string();
                if !is_c_identifier(&ename) {
                    return None;
                }
                let val = variant_string(e.value);
                body.push_str(&format!("  {ename} = {val},\n"));
                count += 1;
            }
        }
        if count == 0 {
            return None;
        }
        body.push_str(&format!("}} {name};"));
        Some(body)
    }
}

fn variant_string(v: Variant) -> String {
    match v {
        Variant::U8(x) => format!("{x}"),
        Variant::U16(x) => format!("{x}"),
        Variant::U32(x) => format!("{x}"),
        Variant::U64(x) => format!("{x}"),
        Variant::I8(x) => format!("{x}"),
        Variant::I16(x) => format!("{x}"),
        Variant::I32(x) => format!("{x}"),
        Variant::I64(x) => format!("{x}"),
    }
}

fn collect_value_deps(ty: &Type, deps: &mut BTreeSet<String>) {
    match ty {
        Type::Named(key) => {
            deps.insert(key.clone());
        }
        Type::Array(inner, _) => collect_value_deps(inner, deps),
        Type::Pointer(_) | Type::BasedPointer { .. } | Type::Function { .. } | Type::Prim(_) => {}
    }
}

fn topo_sort(defs: &BTreeMap<String, (String, BTreeSet<String>)>) -> Vec<TypeText> {
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut out = Vec::with_capacity(defs.len());

    fn visit(
        key: &str,
        defs: &BTreeMap<String, (String, BTreeSet<String>)>,
        visited: &mut BTreeSet<String>,
        active: &mut BTreeSet<String>,
        out: &mut Vec<TypeText>,
    ) {
        if visited.contains(key) || !active.insert(key.to_string()) {
            return;
        }
        if let Some((text, deps)) = defs.get(key) {
            for dep in deps {
                if defs.contains_key(dep) {
                    visit(dep, defs, visited, active, out);
                } else if let Some(prefixed) = ["struct ", "union ", "enum "]
                    .iter()
                    .map(|p| format!("{p}{dep}"))
                    .find(|k| defs.contains_key(k))
                {
                    visit(&prefixed, defs, visited, active, out);
                }
            }
            visited.insert(key.to_string());
            out.push(TypeText {
                name: key.to_string(),
                c: text.clone(),
            });
        }
        active.remove(key);
    }

    for key in defs.keys() {
        visit(key, defs, &mut visited, &mut active, &mut out);
    }
    out
}

fn convention_name(cc: u8, is_32bit: bool) -> Option<&'static str> {
    match cc {
        0x00 if is_32bit => Some("__cdecl"),
        0x07 => Some("__stdcall"),
        0x04 => Some("__fastcall"),
        0x0b => Some("__thiscall"),
        _ => None,
    }
}

fn primitive_size(raw: u32, model: DataModel) -> Option<u64> {
    let indirection = raw & 0xf00;
    if indirection != 0 {
        return match indirection {
            0x100 | 0x200 => Some(2),
            0x400 => Some(4),
            0x600 => Some(8),
            0x700 => Some(16),
            _ => Some(model.pointer),
        };
    }
    Some(match raw & 0xff {
        0x03 => 0,                  // Void
        0x08 => 4,                  // HRESULT
        0x10 | 0x20 | 0x68 | 0x69 | 0x70 | 0x30 => 1, // Char / I8 / U8 / Bool8
        0x71 | 0x7a => model.wchar, // WChar / RChar16
        0x11 | 0x21 | 0x72 | 0x73 | 0x31 => 2, // Short / I16 / U16 / Bool16
        0x12 | 0x22 | 0x74 | 0x75 | 0x32 | 0x40 | 0x7b => 4, // Long / I32 / U32 / Bool32 / F32 / RChar32
        0x13 | 0x23 | 0x76 | 0x77 | 0x33 | 0x41 => 8, // Quad / I64 / U64 / Bool64 / F64
        0x42 => model.long_double.0, // F80
        0x14 | 0x24 | 0x78 | 0x79 | 0x43 => 16, // Octa / I128 / F128
        _ => return None,
    })
}

fn primitive_to_engine(raw: u32) -> Option<Type> {
    let indirection = raw & 0xf00;
    let base = match raw & 0xff {
        0x00 => return None, // T_NOTYPE
        0x03 => Type::Prim(Prim::Void),
        0x08 => Type::Prim(Prim::Int32), // HRESULT
        0x10 | 0x70 => Type::Prim(Prim::Char),
        0x20 => Type::Prim(Prim::UChar),
        0x68 => Type::Prim(Prim::Int8),
        0x69 => Type::Prim(Prim::UInt8),
        0x71 | 0x7a => Type::Prim(Prim::WChar),
        0x7b => Type::Prim(Prim::UInt32),
        0x11 => Type::Prim(Prim::Short),
        0x21 => Type::Prim(Prim::UShort),
        0x72 => Type::Prim(Prim::Int16),
        0x73 => Type::Prim(Prim::UInt16),
        0x12 => Type::Prim(Prim::Long),
        0x22 => Type::Prim(Prim::ULong),
        0x74 => Type::Prim(Prim::Int32),
        0x75 => Type::Prim(Prim::UInt32),
        0x13 => Type::Prim(Prim::LongLong),
        0x23 => Type::Prim(Prim::ULongLong),
        0x76 => Type::Prim(Prim::Int64),
        0x77 => Type::Prim(Prim::UInt64),
        0x40 => Type::Prim(Prim::Float),
        0x41 => Type::Prim(Prim::Double),
        0x42 => Type::Prim(Prim::LongDouble),
        0x30 => Type::Prim(Prim::Bool),
        0x31 => Type::Prim(Prim::UInt16),
        0x32 => Type::Prim(Prim::Int32),
        0x33 => Type::Prim(Prim::UInt64),
        _ => return None,
    };
    if indirection != 0 {
        Some(Type::pointer(base))
    } else {
        Some(base)
    }
}

fn primitive_data_to_engine(p: pdb::PrimitiveType) -> Option<Type> {
    let base = match p.kind {
        PrimitiveKind::NoType => return None,
        PrimitiveKind::Void => Type::Prim(Prim::Void),
        PrimitiveKind::HRESULT => Type::Prim(Prim::Int32),
        PrimitiveKind::Char | PrimitiveKind::RChar => Type::Prim(Prim::Char),
        PrimitiveKind::UChar => Type::Prim(Prim::UChar),
        PrimitiveKind::I8 => Type::Prim(Prim::Int8),
        PrimitiveKind::U8 => Type::Prim(Prim::UInt8),
        PrimitiveKind::WChar | PrimitiveKind::RChar16 => Type::Prim(Prim::WChar),
        PrimitiveKind::RChar32 => Type::Prim(Prim::UInt32),
        PrimitiveKind::Short => Type::Prim(Prim::Short),
        PrimitiveKind::UShort => Type::Prim(Prim::UShort),
        PrimitiveKind::I16 => Type::Prim(Prim::Int16),
        PrimitiveKind::U16 => Type::Prim(Prim::UInt16),
        PrimitiveKind::Long => Type::Prim(Prim::Long),
        PrimitiveKind::ULong => Type::Prim(Prim::ULong),
        PrimitiveKind::I32 => Type::Prim(Prim::Int32),
        PrimitiveKind::U32 => Type::Prim(Prim::UInt32),
        PrimitiveKind::Quad => Type::Prim(Prim::LongLong),
        PrimitiveKind::UQuad => Type::Prim(Prim::ULongLong),
        PrimitiveKind::I64 => Type::Prim(Prim::Int64),
        PrimitiveKind::U64 => Type::Prim(Prim::UInt64),
        PrimitiveKind::F32 => Type::Prim(Prim::Float),
        PrimitiveKind::F64 => Type::Prim(Prim::Double),
        PrimitiveKind::F80 => Type::Prim(Prim::LongDouble),
        PrimitiveKind::Bool8 => Type::Prim(Prim::Bool),
        PrimitiveKind::Bool16 => Type::Prim(Prim::UInt16),
        PrimitiveKind::Bool32 => Type::Prim(Prim::Int32),
        PrimitiveKind::Bool64 => Type::Prim(Prim::UInt64),
        _ => return None,
    };
    match p.indirection {
        Some(Indirection::Near16)
        | Some(Indirection::Far16)
        | Some(Indirection::Huge16)
        | Some(Indirection::Near32)
        | Some(Indirection::Far32)
        | Some(Indirection::Near64)
        | Some(Indirection::Near128) => Some(Type::pointer(base)),
        None => Some(base),
    }
}
