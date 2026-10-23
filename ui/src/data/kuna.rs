//! A [`Provider`] backed by a kuna project export.
//!
//! A kuna export carries the decompiled body of every function, the linear
//! listing of every code section, and the recovered prototypes. Both halves of
//! that are surfaced here: the listing comes from the `.asm`, sliced by the
//! function's label, and the pseudocode comes from the `.c`, resolved through
//! the export's index so a streamed export — whose `.c` is written in
//! decompile order — reads correctly.

use std::path::Path;

use ag_corpus::kuna::{KunaExport, KunaFunction};
use anyhow::Result;

use crate::data::{
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, HitKind, ListingLine, Problem, Provider,
    Reference, SearchHit, SectionCounts,
};
use crate::model::{Capabilities, Project, ProjectKind};

/// Reads analysis results from a kuna project export.
pub struct KunaProvider {
    export: KunaExport,
    project: Project,
}

impl KunaProvider {
    /// Load a kuna export from `root`.
    pub fn load(root: &Path) -> Result<Self> {
        let export = KunaExport::load(root)?;

        let project = Project {
            name: export.name.clone(),
            kind: ProjectKind::Kuna,
            root: Some(root.to_path_buf()),
            target_sha256: None,
            provider: "kuna".to_string(),
            architecture: None,
            format: None,
        };

        Ok(Self { export, project })
    }

    /// The display name of a function.
    fn display_name(f: &KunaFunction) -> String {
        if f.name.is_empty() {
            format!("sub_{:X}", f.address)
        } else {
            f.name.clone()
        }
    }

    /// Whether the function decompiled cleanly.
    fn status(f: &KunaFunction) -> String {
        if f.error.is_some() {
            "failed".to_string()
        } else {
            "written".to_string()
        }
    }
}

impl Provider for KunaProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            listing: self.export.asm_path.is_some(),
            pseudocode: true,
            ..Capabilities::NONE
        }
    }

    fn analysis_state(&self) -> AnalysisState {
        AnalysisState::Complete
    }

    fn functions(&self) -> Vec<FunctionRow> {
        self.export
            .functions
            .iter()
            .map(|f| FunctionRow {
                address: f.address,
                name: Self::display_name(f),
                status: Self::status(f),
                size: f.size,
                objc: false,
            })
            .collect()
    }

    fn function_detail(&self, address: u64) -> Option<FunctionDetail> {
        let f = self.export.function(address)?;
        let name = Self::display_name(f);

        let summary = match f.error.as_deref() {
            Some(error) => format!("Kuna could not decompile this function: {error}."),
            None => match self.export.function_listing(f) {
                Ok(Some(listing)) if !listing.lines.is_empty() => format!(
                    "Decompiled by kuna. {} instructions, {} variables.",
                    listing.lines.len(),
                    listing.variables.len()
                ),
                _ => "Decompiled by kuna.".to_string(),
            },
        };

        Some(FunctionDetail {
            name,
            status: Self::status(f),
            start: Some(f.address),
            end: f.size.map(|size| f.address.saturating_add(size)),
            provenance: "Kuna project export".to_string(),
            summary,
        })
    }

    fn listing(&self, address: u64) -> Option<Vec<ListingLine>> {
        let f = self.export.function(address)?;
        let listing = self.export.function_listing(f).ok()??;

        // The `; arg:` and `; stack:` notes sit under the function's label, so
        // they ride along with its first instruction.
        let notes = listing.variables.join(" · ");
        let mut lines: Vec<ListingLine> = listing
            .lines
            .iter()
            .map(|line| ListingLine {
                address: line.address,
                bytes: line.bytes.clone(),
                mnemonic: line.mnemonic.clone(),
                operands: line.operands.clone(),
                comment: None,
            })
            .collect();

        if let Some(first) = lines.first_mut() {
            first.comment = (!notes.is_empty()).then_some(notes);
        }

        Some(lines)
    }

    fn pseudocode(&self, address: u64) -> Option<String> {
        let f = self.export.function(address)?;
        self.export.function_body(f).ok().flatten()
    }

    fn bytes(&self, _address: u64) -> Option<Vec<ByteLine>> {
        None
    }

    fn references(&self, _address: u64) -> Vec<Reference> {
        Vec::new()
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts {
            functions: self.export.functions.len(),
            ..SectionCounts::default()
        }
    }

    fn search(&self, query: &str, deep: bool) -> Vec<SearchHit> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }

        let mut hits = Vec::new();

        for f in &self.export.functions {
            let name = Self::display_name(f);
            if name.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    address: f.address,
                    title: name.clone(),
                    detail: "Function".to_string(),
                    kind: HitKind::Function,
                });
            }

            if deep && f.error.is_none() {
                if let Ok(Some(body)) = self.export.function_body(f) {
                    if let Some(line) = body
                        .lines()
                        .find(|line| line.to_lowercase().contains(&needle))
                    {
                        hits.push(SearchHit {
                            address: f.address,
                            title: format!("{}: {}", name, line.trim()),
                            detail: "Body match".to_string(),
                            kind: HitKind::CodeRef,
                        });
                    }
                }
            }
        }

        hits
    }

    fn problems(&self) -> Vec<Problem> {
        let mut problems = Vec::new();

        let failed = self
            .export
            .functions
            .iter()
            .filter(|f| f.error.is_some())
            .count();
        if failed > 0 {
            problems.push(Problem {
                message: format!("{failed} functions failed to decompile"),
                address: None,
                action: Some("Re-run kuna on this target".into()),
            });
        }

        if self.export.streaming {
            problems.push(Problem {
                message: "The export is still being written".to_string(),
                address: None,
                action: Some("Reload once kuna finishes".into()),
            });
        }

        problems
    }
}

/// Whether the directory holds a kuna project export.
pub fn is_kuna_export(root: &Path) -> bool {
    ag_corpus::kuna::is_kuna_export(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// A `.c` with two functions, as a kuna export writes them.
    const C: &str = "#include \"a.h\"\n\n// Function: one @ 0x1000\nint one(void)\n{\n  return 1;\n}\n\n// Function: two @ 0x2000\nint two(void)\n{\n  return 2;\n}\n\n";

    /// The `.asm` of the same two functions.
    const ASM: &str = "\
; kuna decompile-project — a
; arch: x86:LE:64:default:gcc

; --- code section 0x1000..0x1010 ---

one:  ; 0x1000
; arg:   param_1 (int)
  00001000: 55                   PUSH       RBP
  00001001: c3                   RET

two:  ; 0x2000
  00002000: 90                   NOP
";

    /// The index that matches [`C`].
    fn index() -> String {
        let one = C.find("// Function: one").expect("the first block");
        let two = C.find("// Function: two").expect("the second block");

        format!(
            concat!(
                "{{\"seq\":0,\"name\":\"one\",\"addr\":\"0x1000\",\"size\":16,\"c_offset\":{one},\"c_len\":{one_len},\"error\":null}}\n",
                "{{\"seq\":1,\"name\":\"two\",\"addr\":\"0x2000\",\"size\":16,\"c_offset\":{two},\"c_len\":{two_len},\"error\":null}}\n",
            ),
            one = one,
            one_len = two - one,
            two = two,
            two_len = C.len() - two,
        )
    }

    /// A temporary export directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "ag-ui-kuna-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&path).expect("a temporary directory");
            TempDir(path)
        }

        fn write(&self, name: &str, contents: &str) {
            fs::write(self.0.join(name), contents).expect("contents");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A provider over a small export.
    fn provider() -> (TempDir, KunaProvider) {
        let dir = TempDir::new("provider");
        dir.write("a.c", C);
        dir.write("a.h", "int one(void);\n");
        dir.write("a.asm", ASM);
        dir.write("index.jsonl", &index());

        let provider = KunaProvider::load(&dir.0).expect("a provider");
        (dir, provider)
    }

    #[test]
    fn the_provider_reads_the_functions_of_an_export() {
        let (_dir, provider) = provider();

        let rows = provider.functions();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "one");
        assert_eq!(rows[0].address, 0x1000);
        assert_eq!(rows[0].status, "written");
        assert_eq!(rows[1].name, "two");
        assert_eq!(rows[1].address, 0x2000);
    }

    #[test]
    fn the_provider_advertises_the_listing_and_the_pseudocode() {
        let (_dir, provider) = provider();

        let capabilities = provider.capabilities();
        assert!(capabilities.listing);
        assert!(capabilities.pseudocode);
        assert!(!capabilities.graph);
    }

    #[test]
    fn the_provider_slices_the_listing_by_label() {
        let (_dir, provider) = provider();

        let listing = provider.listing(0x1000).expect("a listing");
        assert_eq!(listing.len(), 2);
        assert_eq!(listing[0].address, 0x1000);
        assert_eq!(listing[0].mnemonic, "PUSH");
        assert_eq!(listing[0].operands, "RBP");
        // The `; arg:` note rides along with the first instruction.
        assert_eq!(listing[0].comment.as_deref(), Some("arg:   param_1 (int)"));
    }

    #[test]
    fn the_provider_resolves_the_pseudocode_through_the_index() {
        let (_dir, provider) = provider();

        let body = provider.pseudocode(0x2000).expect("a body");
        assert_eq!(body, "int two(void)\n{\n  return 2;\n}");
    }

    #[test]
    fn a_failed_function_is_reported_as_a_problem() {
        let dir = TempDir::new("failed");
        dir.write("a.c", "// Function: one @ 0x1000  (error: boom)\n\n");
        dir.write(
            "index.jsonl",
            "{\"seq\":0,\"name\":\"one\",\"addr\":\"0x1000\",\"size\":0,\"c_offset\":0,\"c_len\":40,\"error\":\"boom\"}\n",
        );

        let provider = KunaProvider::load(&dir.0).expect("a provider");
        let rows = provider.functions();
        assert_eq!(rows[0].status, "failed");

        let problems = provider.problems();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("failed to decompile"));
    }

    #[test]
    fn the_provider_searches_names_and_bodies() {
        let (_dir, provider) = provider();

        let hits = provider.search("one", false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, 0x1000);

        let hits = provider.search("return", true);
        assert_eq!(hits.len(), 2);
    }
}
