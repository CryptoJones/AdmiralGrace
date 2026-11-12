//! `ag image … binexport` — the analysis as a BinExport file (#399).
//!
//! BinExport is the format BinDiff compares, so writing one a version is
//! how two versions of a binary are handed to it: `bindiff old.BinExport
//! new.BinExport`. The file is built by [`ag_image::binexport`]; this names
//! the binary in it — the file's name, its SHA-256 — reads the analyst's
//! renames from the project, and writes it.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_corpus::project::{sha256_of, ProjectFile};
use ag_image::binexport::Notes;
use ag_image::Binary;
use anyhow::{Context, Result};

/// Write the image at `binary` to `file` as a BinExport file, and say in
/// one line what was written.
pub fn run(
    image: &Binary,
    binary: &Path,
    file: &Path,
    project: Option<&ProjectFile>,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "no decoder reads this image ({}), so there is no disassembly to write",
        image.language()
    );
    let name = binary
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let export = ag_image::binexport::build(
        image,
        &name,
        &sha256_of(binary)?,
        timestamp,
        &notes_of(project),
    );
    let bytes = export.encode();
    if let Some(parent) = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| format!("making {}", parent.display()))?;
    }
    std::fs::write(file, &bytes).with_context(|| format!("writing {}", file.display()))?;
    println!(
        "wrote {}: {} functions, {} flow graphs, {} basic blocks, {} instructions, {} bytes",
        file.display(),
        export.call_graph.vertices.len(),
        export.flow_graphs.len(),
        export.basic_blocks.len(),
        export.instructions.len(),
        bytes.len()
    );
    Ok(0)
}

/// The analyst's words a project holds for the file: the renames of
/// functions, and the comments on addresses. A record on a variable, a
/// register or a block is none of these.
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
