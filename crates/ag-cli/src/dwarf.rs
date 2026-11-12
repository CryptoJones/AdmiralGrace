//! `ag image … dwarf` — the analysis as DWARF debug information (#402).
//!
//! DWARF is what debuggers read, so writing one is how the names and the
//! types worked out here are handed to a debugger without typing them in
//! again: `gdb ./program -ex 'add-symbol-file program.debug'`. The file is
//! built by [`ag_image::dwarf`]; this reads the analyst's renames and byte
//! types from the project and writes it.

use std::path::Path;

use ag_corpus::project::{ByteType, DataKind, ProjectFile};
use ag_image::dwarf::{Notes, TYPE_TAGS};
use ag_image::{Binary, Prim, Type};
use anyhow::{Context, Result};

/// Write the image at `binary` to `file` as DWARF debug information, and
/// say in one line what was written.
pub fn run(
    image: &Binary,
    binary: &Path,
    file: &Path,
    project: Option<&ProjectFile>,
) -> Result<i32> {
    let name = binary
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let export = ag_image::dwarf::build(image, &name, &notes_of(project));
    let bytes = export.encode();
    if let Some(parent) = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| format!("making {}", parent.display()))?;
    }
    std::fs::write(file, &bytes).with_context(|| format!("writing {}", file.display()))?;
    let functions = export
        .dies
        .iter()
        .filter(|die| die.tag == ag_image::dwarf::DW_TAG_subprogram && die.parent == Some(0))
        .count();
    let types = export
        .dies
        .iter()
        .filter(|die| TYPE_TAGS.contains(&die.tag))
        .count();
    let variables = export
        .dies
        .iter()
        .filter(|die| die.tag == ag_image::dwarf::DW_TAG_variable)
        .count();
    println!(
        "wrote {}: {} functions, {} types, {} data symbols, {} bytes",
        file.display(),
        functions,
        types,
        variables,
        bytes.len()
    );
    Ok(0)
}

/// The analyst's words a project holds for the file: the renames of
/// functions and data, and the byte types marked on the data. A record on
/// a variable, a register or a block is none of these.
fn notes_of(project: Option<&ProjectFile>) -> Notes {
    let mut notes = Notes {
        names: crate::diff::renames_of(project),
        ..Notes::default()
    };
    for record in project.map(|p| p.annotations.as_slice()).unwrap_or(&[]) {
        if record.variable.is_some() || record.register.is_some() || record.block {
            continue;
        }
        let Some(byte_type) = record.byte_type() else {
            continue;
        };
        let Some(ty) = type_of(&byte_type) else {
            continue;
        };
        if let Ok(address) = ag_corpus::parse_addr(&record.address) {
            notes.data_types.insert(address, ty);
        }
    }
    notes
}

/// The engine type a byte-type mark names: a number of its width and
/// signedness, a character, an address, an array of `count` of them, or a
/// string of characters of no fixed length. Code, function entries and
/// undefined bytes name no type.
fn type_of(byte_type: &ByteType) -> Option<Type> {
    let (item, count) = match byte_type {
        ByteType::String => return Some(Type::Array(Box::new(Type::Prim(Prim::Char)), None)),
        ByteType::Data {
            width,
            count,
            kind,
            signed,
            ..
        } => {
            let item = match kind {
                DataKind::Pointer => Type::Pointer(Box::new(Type::Prim(Prim::Void))),
                DataKind::Char if *width == 1 => {
                    Type::Prim(if *signed { Prim::Char } else { Prim::UChar })
                }
                _ => {
                    let prim = match (width, signed) {
                        (1, true) => Prim::Int8,
                        (1, false) => Prim::UInt8,
                        (2, true) => Prim::Int16,
                        (2, false) => Prim::UInt16,
                        (4, true) => Prim::Int32,
                        (4, false) => Prim::UInt32,
                        (8, true) => Prim::Int64,
                        (8, false) => Prim::UInt64,
                        _ => return None,
                    };
                    Type::Prim(prim)
                }
            };
            (item, *count)
        }
        ByteType::Code | ByteType::Function | ByteType::Undefined => return None,
    };
    if count > 1 {
        Some(Type::Array(Box::new(item), Some(u64::from(count))))
    } else {
        Some(item)
    }
}
