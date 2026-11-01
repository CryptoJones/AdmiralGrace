//! The analyst's types as the commands and the MCP tools show them: the
//! project's definitions read into the image's store, each as C with its
//! layout or as JSON.

use ag_corpus::project::{ProjectFile, TypeDefinition};
use ag_image::{TypeDefinition as Definition, TypeStore, TypeText};
use serde_json::{json, Value};

/// The project's definitions as the engine reads them.
pub(crate) fn texts(project: &ProjectFile) -> Vec<TypeText> {
    project
        .types
        .iter()
        .map(|d| TypeText {
            name: d.name.clone(),
            c: d.c.clone(),
        })
        .collect()
}

/// The engine's definitions as the project keeps them.
pub(crate) fn definitions(texts: &[TypeText]) -> Vec<TypeDefinition> {
    texts
        .iter()
        .map(|t| TypeDefinition {
            name: t.name.clone(),
            c: t.c.clone(),
        })
        .collect()
}

/// The definition `key` as JSON: its kind, size and alignment, its
/// members with their offsets, its enumerators, its target, and its C.
pub(crate) fn type_json(store: &TypeStore, key: &str) -> Value {
    let definition = store.get(key);
    let ty = ag_image::Type::Named(key.to_string());
    let (size, align) = match store.size_align(&ty) {
        Ok((size, align)) => (json!(size), json!(align)),
        Err(_) => (Value::Null, Value::Null),
    };
    let mut out = json!({
        "name": key,
        "kind": definition.map(Definition::kind),
        "complete": definition.is_some_and(Definition::is_complete),
        "size": size,
        "align": align,
        "c": store.definition_text(key, false),
        "layout": store.definition_text(key, true),
    });
    match definition {
        Some(Definition::Struct(_) | Definition::Union(_)) => {
            if let Some(layout) = store.layout(key) {
                out["members"] = Value::Array(
                    layout
                        .fields
                        .iter()
                        .map(|field| {
                            let mut member = json!({
                                "name": field.name,
                                "type": field.ty.spelled(store),
                                "offset": field.offset,
                                "size": field.size,
                            });
                            if let Some((bit, width)) = field.bits {
                                member["bit_offset"] = json!(bit);
                                member["bits"] = json!(width);
                            }
                            member
                        })
                        .collect(),
                );
            }
        }
        Some(Definition::Enum(e)) => {
            out["underlying"] = json!(e.underlying.spelling());
            out["values"] = Value::Array(
                e.values
                    .iter()
                    .map(|(name, value)| json!({"name": name, "value": value}))
                    .collect(),
            );
        }
        Some(Definition::Typedef(target)) => {
            out["type"] = json!(target.spelled(store));
        }
        None => {}
    }
    out
}

/// One line for a definition in a list: its name, kind and size.
pub(crate) fn summary(store: &TypeStore, key: &str) -> String {
    let kind = store.get(key).map_or("?", Definition::kind);
    match store.size_of(&ag_image::Type::Named(key.to_string())) {
        Ok(size) => format!("{key}  ({kind}, {size:#x} bytes)"),
        Err(why) => format!("{key}  ({kind}, {why})"),
    }
}

/// The platform's primitives under the store's data model, a row each:
/// the spelling, the size and the alignment.
pub(crate) fn primitives_text(store: &TypeStore) -> String {
    let model = store.model();
    let mut out = format!("data model {}\n", model.name);
    for prim in ag_image::Prim::ALL {
        if let Some((size, align)) = prim.layout(model) {
            out.push_str(&format!(
                "  {:<20} size {size:>2}, align {align:>2}\n",
                prim.spelling()
            ));
        }
    }
    out.push_str(&format!(
        "  {:<20} size {:>2}, align {:>2}\n",
        "pointers", model.pointer, model.pointer
    ));
    out
}

/// The primitives as JSON.
pub(crate) fn primitives_json(store: &TypeStore) -> Value {
    let model = store.model();
    Value::Array(
        ag_image::Prim::ALL
            .iter()
            .filter_map(|prim| {
                let (size, align) = prim.layout(model)?;
                Some(json!({"name": prim.spelling(), "size": size, "align": align}))
            })
            .collect(),
    )
}

/// The types the project's variables are given, each with what it is the
/// type of — `a of init` — the function by the image's name for it where
/// the project gives none.
pub(crate) fn users(project: &ProjectFile, image: &ag_image::Binary) -> Vec<(String, String)> {
    project
        .type_users()
        .into_iter()
        .map(|(who, ty)| {
            let named = who.rsplit_once(" of ").and_then(|(variable, at)| {
                let address = ag_corpus::parse_addr(at).ok()?;
                let name = image.function_name(address)?;
                Some(format!("{variable} of {name}"))
            });
            (named.unwrap_or(who), ty)
        })
        .collect()
}

/// The lift name of `variable` in the function at `address`: the name
/// itself when the lift declares it, else the variable the project
/// renames so.
pub(crate) fn lift_variable(
    image: &ag_image::Binary,
    address: u64,
    project: Option<&ProjectFile>,
    variable: &str,
) -> Result<String, String> {
    let variable = variable.trim();
    if variable.is_empty() {
        return Err("the variable is empty".to_string());
    }
    let declared = image.variables(address).map_err(|error| error.reason)?;
    if declared.iter().any(|v| v.name == variable) {
        return Ok(variable.to_string());
    }
    let key = format!("{address:#x}");
    project
        .and_then(|project| {
            declared
                .iter()
                .find(|v| project.variable_name(&key, &v.name).as_deref() == Some(variable))
        })
        .map(|v| v.name.clone())
        .ok_or_else(|| {
            let name = image
                .function_name(address)
                .map_or_else(|| format!("sub_{address:x}"), str::to_string);
            format!("{name} declares no {variable}")
        })
}

/// The addresses a member was read or written at, as the reports spell
/// them: `0x4010b4, 0x40110c in read_conn`.
fn member_sources(member: &ag_image::DraftMember) -> String {
    let mut out = member
        .at
        .iter()
        .map(|at| format!("{at:#x}"))
        .collect::<Vec<_>>()
        .join(", ");
    if !member.via.is_empty() {
        out.push_str(&format!(" (through {})", member.via.join(", ")));
    }
    out
}

/// A drafted structure as text: its C, what sized it, each member with
/// the accesses it came from, and the notes.
pub(crate) fn draft_text(draft: &ag_image::StructDraft) -> String {
    let mut out = format!("{}\n\n", draft.c);
    out.push_str(&format!(
        "{}: {:#x} bytes, sized by {}{}\n",
        draft.key(),
        draft.size,
        draft.sized_by,
        if draft.packed { ", packed" } else { "" }
    ));
    for member in &draft.members {
        let what = if member.gap {
            "no access".to_string()
        } else {
            format!(
                "{} read{}, {} written, at {}",
                member.reads,
                if member.reads == 1 { "" } else { "s" },
                member.writes,
                member_sources(member)
            )
        };
        out.push_str(&format!(
            "  {:#06x}  {:<12} {:<16} {what}\n",
            member.offset, member.name, member.ty
        ));
    }
    for note in &draft.notes {
        out.push_str(&format!("note: {note}\n"));
    }
    out
}

/// A drafted member as JSON.
pub(crate) fn member_json(member: &ag_image::DraftMember) -> Value {
    json!({
        "offset": member.offset,
        "size": member.size,
        "name": member.name,
        "type": member.ty,
        "gap": member.gap,
        "reads": member.reads,
        "writes": member.writes,
        "at": member.at.iter().map(|at| format!("{at:#x}")).collect::<Vec<_>>(),
        "via": member.via,
    })
}

/// A drafted structure as JSON.
pub(crate) fn draft_json(draft: &ag_image::StructDraft) -> Value {
    json!({
        "name": draft.key(),
        "size": draft.size,
        "sized_by": draft.sized_by,
        "packed": draft.packed,
        "members": draft.members.iter().map(member_json).collect::<Vec<_>>(),
        "notes": draft.notes,
        "c": draft.c,
    })
}

/// A structure made or updated from a pointer: the project's definitions
/// after, the structure, the type the pointer is given, and what changed.
pub(crate) struct Applied {
    pub definitions: Vec<TypeText>,
    pub key: String,
    pub pointer: String,
    pub c: String,
    /// The draft, when the structure is a new one.
    pub draft: Option<ag_image::StructDraft>,
    /// The members an update added.
    pub added: Vec<ag_image::DraftMember>,
    pub notes: Vec<String>,
}

/// The structure the pointer `variable` — as the analyst names it — of
/// the function at `address` makes: a new one named `name`, or by default
/// `struct_<function>_<variable>`; or, with `update`, that structure
/// given the members its accesses add.
pub(crate) fn struct_from(
    image: &ag_image::Binary,
    project: &ProjectFile,
    address: u64,
    variable: &str,
    name: Option<&str>,
    update: Option<&str>,
) -> Result<(String, Applied), String> {
    let lift = lift_variable(image, address, Some(project), variable)?;
    let model = image.data_model();
    let held = texts(project);
    if let Some(update) = update {
        let found = image.struct_accesses(address, &lift)?;
        let merged = ag_image::smart_struct::update_struct(model, &held, update, &found)?;
        return Ok((
            lift,
            Applied {
                definitions: merged.definitions,
                pointer: format!("{} *", merged.key),
                key: merged.key,
                c: merged.c,
                draft: None,
                added: merged.added,
                notes: merged.notes,
            },
        ));
    }
    let store = image.types();
    let tag = match name {
        Some(name) => ag_image::smart_struct::tag_of(name)?,
        None => {
            let function = image
                .function_name(address)
                .map_or_else(|| format!("sub_{address:x}"), str::to_string);
            ag_image::smart_struct::default_tag(&store, &function, variable.trim())
        }
    };
    let draft = image.struct_draft(address, &lift, Some(&tag))?;
    let definitions = ag_image::smart_struct::create_struct(model, &held, &draft)?;
    Ok((
        lift,
        Applied {
            definitions,
            key: draft.key(),
            pointer: draft.pointer(),
            c: draft.c.clone(),
            notes: draft.notes.clone(),
            draft: Some(draft),
            added: Vec::new(),
        },
    ))
}

/// What an update added, as text.
pub(crate) fn added_text(applied: &Applied) -> String {
    let mut out = String::new();
    if applied.added.is_empty() {
        out.push_str(&format!("{}: no member added\n", applied.key));
    }
    for member in &applied.added {
        out.push_str(&format!(
            "  added {:#06x}  {:<12} {:<16} {}\n",
            member.offset,
            member.name,
            member.ty,
            if member.gap {
                "no access".to_string()
            } else {
                format!("at {}", member_sources(member))
            }
        ));
    }
    for note in &applied.notes {
        out.push_str(&format!("note: {note}\n"));
    }
    out
}
