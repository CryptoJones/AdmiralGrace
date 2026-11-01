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
