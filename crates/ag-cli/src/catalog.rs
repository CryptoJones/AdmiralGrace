//! `ag catalog` — the engine's option registry, as a document.
//!
//! The registry is [`ag_image::options::OPTIONS`], one row per judgment
//! call the engine makes. `--markdown` prints it as `docs/options.md` holds
//! it, the symptom index first; `--json` prints the same rows for a
//! program; `--check` reads the committed `docs/options.md` and fails when
//! it differs from what `--markdown` would print, so the document cannot go
//! stale without CI saying so. A test here does the same against the copy
//! compiled into the binary, so `cargo test` fails on drift too.

use std::fs;
use std::path::Path;

use ag_image::options::{catalog_json, catalog_markdown};
use anyhow::{Context, Result};

/// What `ag catalog` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The rows as JSON.
    Json,
    /// The document, symptom index first.
    Markdown,
}

/// Print the catalog in `format`, or, with `check`, compare the committed
/// document at `path` with the generated one: exit code 0 when they match,
/// 1 when they differ.
pub fn run(format: Format, check: Option<&Path>) -> Result<i32> {
    if let Some(path) = check {
        let committed =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return Ok(match drift(&committed) {
            None => {
                println!("{} is current", path.display());
                0
            }
            Some(line) => {
                eprintln!(
                    "error: {} is stale: it first differs from `ag catalog --markdown` at line {line}; regenerate it with `ag catalog --markdown > {}`",
                    path.display(),
                    path.display()
                );
                1
            }
        });
    }
    match format {
        Format::Json => print!("{}", catalog_json()),
        Format::Markdown => print!("{}", catalog_markdown()),
    }
    Ok(0)
}

/// The first line, counted from one, where `committed` differs from the
/// generated document; `None` when they are the same.
fn drift(committed: &str) -> Option<usize> {
    let generated = catalog_markdown();
    if committed == generated {
        return None;
    }
    let mut theirs = committed.lines();
    let mut ours = generated.lines();
    let mut line = 1;
    loop {
        match (theirs.next(), ours.next()) {
            (Some(a), Some(b)) if a == b => line += 1,
            (None, None) => return Some(line),
            _ => return Some(line),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document as committed, compiled in.
    const COMMITTED: &str = include_str!("../../../docs/options.md");

    #[test]
    fn the_committed_options_document_is_the_generated_one() {
        assert_eq!(
            drift(COMMITTED),
            None,
            "docs/options.md is stale: regenerate it with `cargo run --bin ag -- catalog --markdown > docs/options.md`"
        );
    }

    #[test]
    fn drift_names_the_first_line_that_differs() {
        let generated = catalog_markdown();
        let mut lines: Vec<&str> = generated.lines().collect();
        lines[2] = "something else";
        let edited = lines.join("\n") + "\n";
        assert_eq!(drift(&edited), Some(3));
        let truncated: String = generated.lines().take(5).collect::<Vec<_>>().join("\n");
        assert_eq!(drift(&truncated), Some(6));
    }

    #[test]
    fn the_markdown_opens_with_the_symptom_index() {
        let markdown = catalog_markdown();
        let index = markdown.find("## Symptom index").expect("an index");
        let lift = markdown.find("## Lift").expect("a lift section");
        assert!(index < lift);
        assert!(markdown.contains("If the output shows… | Try…"));
    }
}
