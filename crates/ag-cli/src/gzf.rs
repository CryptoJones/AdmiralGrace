//! `ag image … gzf` — the analysis for Ghidra (#405).
//!
//! Ghidra is the other workbench a reverse engineer keeps open, so writing
//! the analysis for it hands the names, the functions, the types and the
//! comments across without typing them in again. The file is Ghidra's XML
//! program format — the format it reads and writes for interchange, which
//! its loader recognises by content whether the file is named `.xml` or
//! `.gzf`. The packed native database Ghidra itself exports as `.gzf` is an
//! internal storage engine, not a format to write by hand; the XML is the
//! importable analogue of the BinExport (#399) and DWARF (#402) exports.
//!
//! The memory bytes cannot live in the XML, so they are written beside it
//! as `<file>.bytes`, which the document's memory contents point at. Keep
//! the two together: Ghidra reads the sidecar from the XML's own directory.
//! The file is built by [`ag_image::gzf`]; this reads the analyst's renames
//! and comments from the project and writes both files.

use std::path::Path;

use ag_corpus::project::ProjectFile;
use ag_image::gzf::Notes;
use ag_image::Binary;
use anyhow::{Context, Result};

/// Write the image at `binary` to `file` as a Ghidra XML program, with its
/// memory bytes beside it as `<file>.bytes`, and say in two lines what was
/// written.
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
    let sidecar = file.with_extension("bytes");
    let bytes_name = sidecar
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "memory.bytes".to_string());
    let export = ag_image::gzf::build(image, &name, &bytes_name, &notes_of(project));
    let xml = export.encode();
    if let Some(parent) = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| format!("making {}", parent.display()))?;
    }
    std::fs::write(file, &xml).with_context(|| format!("writing {}", file.display()))?;
    std::fs::write(&sidecar, &export.bytes)
        .with_context(|| format!("writing {}", sidecar.display()))?;
    println!(
        "wrote {}: {} functions, {} types, {} symbols, {} bytes",
        file.display(),
        export.functions.len(),
        export.data_types.len(),
        export.symbols.len(),
        xml.len()
    );
    println!(
        "wrote {}: {} bytes of memory",
        sidecar.display(),
        export.bytes.len()
    );
    Ok(0)
}

/// The analyst's words a project holds for the file: the renames of
/// functions and data, and the comments on addresses. A record on a
/// variable, a register or a block is none of these.
fn notes_of(project: Option<&ProjectFile>) -> Notes {
    let mut notes = Notes {
        names: crate::diff::renames_of(project),
        ..Notes::default()
    };
    for record in project.map(|p| p.annotations.as_slice()).unwrap_or(&[]) {
        if record.variable.is_some() || record.register.is_some() || record.block {
            continue;
        }
        let Some(comment) = record.comment.as_deref().filter(|text| !text.is_empty()) else {
            continue;
        };
        if let Ok(address) = ag_corpus::parse_addr(&record.address) {
            notes
                .comments
                .insert(address, (comment.to_string(), record.comment_above));
        }
    }
    notes
}
