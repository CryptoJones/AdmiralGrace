//! A [`Provider`] backed by a kuna project export.
//!
//! A kuna export carries the decompiled body of every function, the linear
//! listing of every code section, and the recovered prototypes. Both halves of
//! that are surfaced here: the listing comes from the `.asm`, sliced by the
//! function's label, and the pseudocode comes from the `.c`, resolved through
//! the export's index so a streamed export — whose `.c` is written in
//! decompile order — reads correctly.
//!
//! The export also records the binary it was made from, and the kuna CLI can
//! answer questions about that binary that the export cannot: which lines of
//! C came from which addresses, what refers to what, which strings it holds.
//! Those answers arrive over time, as the workbench asks the CLI for them, so
//! they are kept in a cache the workbench fills and this provider reads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ag_corpus::kuna::{KunaExport, KunaFunction};
use anyhow::Result;

use crate::data::kuna_json::{Direction, FunctionJson, KunaCli, StringJson, SummaryJson, XrefJson};
use crate::data::{
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, HitKind, ListingLine, Problem,
    ProjectSummary, Provider, Reference, ReferenceKind, SearchHit, SectionCounts, StringEntry,
};
use crate::model::{Capabilities, Project, ProjectKind};

/// What the kuna CLI has told the workbench so far.
///
/// The CLI answers slowly — every answer is a process run against the
/// binary — so the workbench asks in the background and drops the answers
/// here, where the provider reads them.
#[derive(Debug, Default)]
pub struct KunaCache {
    /// The shape of the program.
    pub summary: Option<SummaryJson>,
    /// The strings the binary holds.
    pub strings: Vec<StringJson>,
    /// The decompilation of each function the workbench has asked about.
    pub functions: BTreeMap<u64, FunctionJson>,
    /// The references each function makes.
    pub xrefs_from: BTreeMap<u64, Vec<XrefJson>>,
    /// The references made to each function.
    pub xrefs_to: BTreeMap<u64, Vec<XrefJson>>,
}

/// A handle on the cache, shared by the workbench and the provider.
pub type SharedCache = Arc<Mutex<KunaCache>>;

/// Reads analysis results from a kuna project export.
pub struct KunaProvider {
    export: KunaExport,
    project: Project,
    cli: Option<KunaCli>,
    /// The kuna executable this provider would run.
    program: PathBuf,
    /// Whether that executable is there to be run.
    program_missing: bool,
    cache: SharedCache,
}

impl KunaProvider {
    /// Load a kuna export from `root`.
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_with(root, KunaCli::program())
    }

    /// Load a kuna export from `root`, run with a named kuna executable.
    ///
    /// When the executable is not there — neither `AG_KUNA_BIN` nor the `PATH`
    /// names one — the export is still read in full; only the questions that
    /// need the CLI are left unanswered.
    pub fn load_with(root: &Path, program: PathBuf) -> Result<Self> {
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

        let program_missing = !KunaCli::available(&program);
        let cli = if program_missing {
            None
        } else {
            KunaCli::for_export(&export, program.clone())
        };

        Ok(Self {
            export,
            project,
            cli,
            program,
            program_missing,
            cache: Arc::new(Mutex::new(KunaCache::default())),
        })
    }

    /// The kuna CLI this provider can ask, when the export names a binary
    /// that is still there.
    pub fn cli(&self) -> Option<&KunaCli> {
        self.cli.as_ref()
    }

    /// The cache the kuna CLI's answers are kept in.
    pub fn cache(&self) -> SharedCache {
        Arc::clone(&self.cache)
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

    /// The cached decompilation of a function, when the CLI has answered.
    fn cached_function(&self, address: u64) -> Option<FunctionJson> {
        let cache = self.cache.lock().ok()?;
        cache.functions.get(&address).cloned()
    }
}

impl Provider for KunaProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        let json = self.cli.is_some();

        Capabilities {
            listing: self.export.asm_path.is_some(),
            pseudocode: true,
            references: json,
            strings: json,
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

    fn references(&self, address: u64) -> Vec<Reference> {
        let Ok(cache) = self.cache.lock() else {
            return Vec::new();
        };

        let mut references = Vec::new();

        // What the function refers to.
        for xref in cache.xrefs_from.get(&address).into_iter().flatten() {
            references.push(Reference {
                address: xref.to_address,
                label: xref_label(
                    xref.to_function.as_ref(),
                    xref.instruction.as_deref(),
                    xref.to_address,
                ),
                kind: reference_kind(&xref.kind, Direction::From),
            });
        }

        // What refers to the function.
        for xref in cache.xrefs_to.get(&address).into_iter().flatten() {
            references.push(Reference {
                address: xref.from_address,
                label: xref_label(
                    xref.from_function.as_ref(),
                    xref.instruction.as_deref(),
                    xref.from_address,
                ),
                kind: reference_kind(&xref.kind, Direction::To),
            });
        }

        references
    }

    fn strings(&self) -> Vec<StringEntry> {
        let Ok(cache) = self.cache.lock() else {
            return Vec::new();
        };

        cache
            .strings
            .iter()
            .map(|string| StringEntry {
                address: string.address,
                text: string.text.clone(),
                section: string.section.clone(),
                functions: string.functions.iter().map(|f| f.address).collect(),
            })
            .collect()
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts {
            functions: self.export.functions.len(),
            strings: self
                .cache
                .lock()
                .map(|cache| cache.strings.len())
                .unwrap_or(0),
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

        for string in self.strings() {
            if string.text.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    address: string.address,
                    title: string.text.clone(),
                    detail: string.section.unwrap_or_else(|| "String".to_string()),
                    kind: HitKind::String,
                });
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

        if let Ok(cache) = self.cache.lock() {
            if let Some(summary) = &cache.summary {
                if let Some(error) = &summary.error {
                    problems.push(Problem {
                        message: format!("kuna could not summarize the program: {error}"),
                        address: None,
                        action: None,
                    });
                }
                for warning in &summary.warnings {
                    problems.push(Problem {
                        message: format!("kuna warned: {warning}"),
                        address: None,
                        action: None,
                    });
                }
            }
        }

        if self.program_missing {
            problems.push(Problem {
                message: format!(
                    "kuna was not found, so its cross references, strings and line mappings are off — looked for {}",
                    self.program.display()
                ),
                address: None,
                action: Some(format!(
                    "Set {} to the kuna executable, or put kuna on the PATH",
                    crate::data::kuna_json::KUNA_BIN_ENV
                )),
            });
        } else if self.cli.is_none() {
            if let Some(binary) = &self.export.binary {
                problems.push(Problem {
                    message: format!(
                        "The analysed binary {} is not available, so kuna's cross references, strings and line mappings are off",
                        binary.display()
                    ),
                    address: None,
                    action: Some("Keep the binary beside the export to turn them on".into()),
                });
            }
        }

        problems
    }

    fn function_problems(&self, address: u64) -> Vec<Problem> {
        let mut problems = Vec::new();

        let Some(function) = self.cached_function(address) else {
            return problems;
        };

        if let Some(error) = &function.error {
            problems.push(Problem {
                message: format!("kuna could not decompile this function: {error}"),
                address: Some(address),
                action: None,
            });
        }

        if function.unstructured_gotos > 0 {
            problems.push(Problem {
                message: format!(
                    "{} unstructured goto{} in the decompiled body",
                    function.unstructured_gotos,
                    if function.unstructured_gotos == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
                address: Some(address),
                action: Some("The body does not follow the source's control flow".into()),
            });
        }

        problems
    }

    fn summary(&self) -> Option<ProjectSummary> {
        let cache = self.cache.lock().ok()?;
        let summary = cache.summary.as_ref()?;

        Some(ProjectSummary {
            entry: summary
                .summary
                .entry
                .as_ref()
                .map(|entry| (entry.name.clone(), entry.address)),
            main: summary
                .summary
                .main
                .as_ref()
                .map(|main| (main.name.clone(), main.address)),
            reachable: summary.summary.reachable_from_entry,
            no_callers: summary.summary.no_callers,
            code_bytes: summary.summary.code_bytes,
            functions: summary.total,
        })
    }
}

/// The label of a cross reference.
///
/// A reference to a named function is labelled with the name; a reference to
/// something unnamed is labelled with the instruction that makes it, which
/// says more than the address alone.
fn xref_label(
    function: Option<&crate::data::kuna_json::FunctionRef>,
    instruction: Option<&str>,
    address: u64,
) -> String {
    function
        .map(|function| function.name.clone())
        .filter(|name| !name.is_empty())
        .or_else(|| instruction.map(|instruction| instruction.to_string()))
        .unwrap_or_else(|| format!("{address:#x}"))
}

/// The kind of reference a cross reference is.
///
/// A reference out of the selection is a call it makes; a reference into it is
/// a call that reaches it. Everything that is not a call is a data reference.
fn reference_kind(kind: &str, direction: Direction) -> ReferenceKind {
    let is_code = matches!(kind, "call" | "jump");

    match (direction, is_code) {
        (Direction::From, true) => ReferenceKind::Calls,
        (Direction::To, true) => ReferenceKind::CalledBy,
        _ => ReferenceKind::Data,
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
        assert!(
            problems
                .iter()
                .any(|problem| problem.message.contains("failed to decompile")),
            "the failed function is reported: {problems:?}"
        );
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

    #[test]
    fn the_json_surfaces_are_off_without_a_binary() {
        let (_dir, provider) = provider();

        assert!(provider.cli().is_none());
        assert!(!provider.capabilities().references);
        assert!(!provider.capabilities().strings);
    }

    #[test]
    fn a_missing_kuna_leaves_the_export_readable_and_says_so() {
        let dir = TempDir::new("missing-kuna");
        dir.write("a.c", C);
        dir.write("a.h", "int one(void);\n");
        dir.write("index.jsonl", &index());
        // The export names a binary that is still there, so the only thing
        // missing is kuna itself.
        dir.write(
            "README.md",
            "# a — kuna project export\n\n## Binary\n\n| Field | Value |\n|---|---|\n| Path | `/bin/sh` |\n",
        );

        let provider = KunaProvider::load_with(&dir.0, PathBuf::from("/nonexistent/kuna"))
            .expect("a provider");

        // The export is still read in full.
        assert_eq!(provider.functions().len(), 2);
        assert!(provider.pseudocode(0x1000).is_some());

        // The questions that need the CLI are simply not answered.
        assert!(provider.cli().is_none());
        assert!(!provider.capabilities().references);
        assert!(!provider.capabilities().strings);
        assert!(provider.references(0x1000).is_empty());
        assert!(provider.strings().is_empty());
        assert!(provider.summary().is_none());

        // And one problem says why.
        let problems = provider.problems();
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].message.contains("kuna was not found"),
            "the problem names the missing kuna: {}",
            problems[0].message
        );
    }

    #[test]
    fn the_cross_references_become_references_to_and_from_the_selection() {
        let (_dir, provider) = provider();

        let cache = provider.cache();
        {
            let mut cache = cache.lock().expect("the cache");
            cache.xrefs_from.insert(
                0x1000,
                vec![XrefJson {
                    kind: "call".into(),
                    from_address: 0x1000,
                    to_address: 0x2000,
                    from_function: None,
                    to_function: Some(crate::data::kuna_json::FunctionRef {
                        name: "two".into(),
                        address: 0x2000,
                    }),
                    instruction: Some("CALL 0x2000".into()),
                }],
            );
            cache.xrefs_to.insert(
                0x1000,
                vec![XrefJson {
                    kind: "call".into(),
                    from_address: 0x3000,
                    to_address: 0x1000,
                    from_function: Some(crate::data::kuna_json::FunctionRef {
                        name: "three".into(),
                        address: 0x3000,
                    }),
                    to_function: None,
                    instruction: Some("CALL 0x1000".into()),
                }],
            );
        }

        let references = provider.references(0x1000);
        assert_eq!(references.len(), 2);
        assert_eq!(references[0].kind, ReferenceKind::Calls);
        assert_eq!(references[0].label, "two");
        assert_eq!(references[1].kind, ReferenceKind::CalledBy);
        assert_eq!(references[1].label, "three");
    }

    #[test]
    fn a_functions_error_and_gotos_become_problems() {
        let (_dir, provider) = provider();

        let cache = provider.cache();
        {
            let mut cache = cache.lock().expect("the cache");
            cache.functions.insert(
                0x1000,
                FunctionJson {
                    code: None,
                    error: Some("boom".into()),
                    unstructured_gotos: 2,
                    line_mappings: Vec::new(),
                },
            );
        }

        let problems = provider.function_problems(0x1000);
        assert_eq!(problems.len(), 2);
        assert!(problems[0].message.contains("boom"));
        assert!(problems[1].message.contains("2 unstructured gotos"));
        assert_eq!(problems[0].address, Some(0x1000));
    }

    #[test]
    fn the_strings_become_entries() {
        let (_dir, provider) = provider();

        let cache = provider.cache();
        {
            let mut cache = cache.lock().expect("the cache");
            cache.strings.push(StringJson {
                address: 0x2006,
                text: "%ld\n".into(),
                section: Some(".rodata".into()),
                functions: vec![crate::data::kuna_json::FunctionRef {
                    name: "one".into(),
                    address: 0x1000,
                }],
            });
        }

        let strings = provider.strings();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "%ld\n");
        assert_eq!(strings[0].functions, vec![0x1000]);
        assert_eq!(provider.counts().strings, 1);
    }
}
