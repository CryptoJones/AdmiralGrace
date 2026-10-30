//! Data access for the workbench.
//!
//! Every view reads through the [`Provider`] trait so the same UI can be
//! driven by a real corpus, a binary under analysis, or the bundled sample
//! data used to exercise the layout.

pub mod binary;
pub mod corpus;
pub mod empty;
pub mod kuna;
pub mod kuna_json;
pub mod sample;

use std::collections::BTreeMap;

use crate::model::{Capabilities, Project};

/// How far the analysis of the open project has progressed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AnalysisState {
    /// Analysis has not been started.
    Idle,
    /// Analysis is running.
    Running {
        /// Completion percentage in the range `0..=100`.
        percent: u8,
    },
    /// Analysis finished.
    Complete,
    /// Analysis stopped with an error.
    Failed(String),
}

impl AnalysisState {
    /// Short label for the status bar.
    pub fn label(&self) -> String {
        match self {
            AnalysisState::Idle => "Analysis idle".into(),
            AnalysisState::Running { percent } => format!("Analysing {percent}%"),
            AnalysisState::Complete => "Analysis complete".into(),
            AnalysisState::Failed(msg) => format!("Analysis failed: {msg}"),
        }
    }
}

/// A function in the project's function list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRow {
    /// Entry address.
    pub address: u64,
    /// The address space the source wrote the address in, when it named one.
    pub space: Option<String>,
    /// Best known name (symbol, Objective-C method, or generated).
    pub name: String,
    /// Analysis status reported for this function.
    pub status: String,
    /// Size of the function body in bytes, when known.
    pub size: Option<u64>,
    /// Whether the name came from an Objective-C method map.
    pub objc: bool,
}

impl FunctionRow {
    /// The address as the source wrote it: `EXTERNAL:0x1` when it names a
    /// space, plain `0x1` when it does not.
    pub fn display_address(&self) -> String {
        match &self.space {
            Some(space) => format!("{space}:{:#x}", self.address),
            None => format!("{:#x}", self.address),
        }
    }
}

/// Details about a single function, shown in the inspector.
#[derive(Debug, Clone, Default)]
pub struct FunctionDetail {
    /// Best known name.
    pub name: String,
    /// Analysis status reported for this function.
    pub status: String,
    /// Start of the function body.
    pub start: Option<u64>,
    /// End of the function body.
    pub end: Option<u64>,
    /// Where the name came from.
    pub provenance: String,
    /// Human-readable summary of the analysis state.
    pub summary: String,
}

/// One line of a linear disassembly listing.
#[derive(Debug, Clone)]
pub struct ListingLine {
    /// Address of the instruction.
    pub address: u64,
    /// Encoded bytes, hex formatted.
    pub bytes: String,
    /// Mnemonic.
    pub mnemonic: String,
    /// Operand text.
    pub operands: String,
    /// The function the operands name, when the line is a call to one.
    ///
    /// The listing shows a callee by name; the analyst's rename replaces
    /// that name, so the view needs to know which address the operand text
    /// stands for. A call through a GOT slot names the slot, not a
    /// function, and carries none.
    pub call_target: Option<u64>,
    /// The registers the operands name, spelled as they are spelled in
    /// `operands`.
    ///
    /// The analyst can rename a register within one function; the view
    /// replaces each name as a whole word, so it needs the spellings the
    /// disassembler put in the text rather than a guess from the id. A
    /// provider that names no registers leaves this empty.
    pub registers: Vec<String>,
    /// Optional trailing comment.
    pub comment: Option<String>,
}

/// One row of a hex dump.
#[derive(Debug, Clone)]
pub struct ByteLine {
    /// Address of the first byte in the row.
    pub address: u64,
    /// Raw bytes.
    pub bytes: Vec<u8>,
}

/// One basic block of a function's control-flow graph.
///
/// A block is the straight run of instructions between two branches: it
/// starts at an address, ends at an address, and goes on to the blocks that
/// follow it.
#[derive(Debug, Clone)]
pub struct GraphBlock {
    /// Where the block starts.
    pub from: u64,
    /// Where the block ends: the address of the instruction after it.
    pub to: u64,
    /// The addresses the block goes to.
    pub successors: Vec<u64>,
    /// The instructions of the block.
    pub instructions: Vec<ListingLine>,
}

/// The control-flow graph of a function.
///
/// The blocks come from the provider, and so do the edges between them:
/// the kind of an edge is worked out by the rule the CLI reports by, so
/// the workbench and the command line name an edge the same way.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    /// The blocks of the function, in the order the walk found them.
    pub blocks: Vec<GraphBlock>,
    /// The edges between the blocks, each with its kind.
    pub edges: Vec<ag_image::Edge>,
}

impl Graph {
    /// The edges that leave a block, worked out by the shared rule.
    ///
    /// A provider whose blocks did not come with their edges derives them
    /// here, so every graph names an edge the same way.
    pub fn edges_of_blocks(blocks: &[GraphBlock]) -> Vec<ag_image::Edge> {
        blocks
            .iter()
            .flat_map(|block| ag_image::edges_of(block.from, block.to, &block.successors))
            .collect()
    }
}

/// The kind of a cross reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    /// The selection calls this address.
    Calls,
    /// This address calls the selection.
    CalledBy,
    /// A data reference.
    Data,
    /// A string reference.
    String,
    /// The selection uses this string.
    UsedBy,
}

impl ReferenceKind {
    /// Uppercase label used in the inspector.
    pub fn label(self) -> &'static str {
        match self {
            ReferenceKind::Calls => "CALLS",
            ReferenceKind::CalledBy => "CALLED BY",
            ReferenceKind::Data => "DATA",
            ReferenceKind::String => "STRING",
            ReferenceKind::UsedBy => "USED BY",
        }
    }
}

/// A cross reference to or from the current selection.
#[derive(Debug, Clone)]
pub struct Reference {
    /// Address of the referenced location.
    pub address: u64,
    /// Display label.
    pub label: String,
    /// What kind of reference this is.
    pub kind: ReferenceKind,
}

/// The kind of search result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitKind {
    /// A function matched.
    Function,
    /// A string matched.
    String,
    /// A code reference matched.
    CodeRef,
    /// A named piece of data matched.
    Data,
}

impl HitKind {
    /// Short label for the result table.
    pub fn label(self) -> &'static str {
        match self {
            HitKind::Function => "Function",
            HitKind::String => "String",
            HitKind::CodeRef => "Code reference",
            HitKind::Data => "Data",
        }
    }
}

/// One search result.
#[derive(Debug, Clone)]
pub struct SearchHit {
    /// Address of the match.
    pub address: u64,
    /// Primary label.
    pub title: String,
    /// Secondary detail line.
    pub detail: String,
    /// What kind of thing matched.
    pub kind: HitKind,
}

/// A diagnostic reported by the analysis.
#[derive(Debug, Clone)]
pub struct Problem {
    /// Short description of the problem.
    pub message: String,
    /// Where the problem was detected, when known.
    pub address: Option<u64>,
    /// A suggested action.
    pub action: Option<String>,
}

/// A string the binary holds.
#[derive(Debug, Clone)]
pub struct StringEntry {
    /// Where the string lives.
    pub address: u64,
    /// The string itself.
    pub text: String,
    /// The section it lives in.
    pub section: Option<String>,
    /// The functions that refer to the string.
    pub functions: Vec<u64>,
}

/// The shape of the whole program.
#[derive(Debug, Clone, Default)]
pub struct ProjectSummary {
    /// The program's entry point, as a name and an address.
    pub entry: Option<(String, u64)>,
    /// The program's `main`, as a name and an address.
    pub main: Option<(String, u64)>,
    /// How many functions are reachable from the entry point.
    ///
    /// This needs the whole program read, so it is not known until the
    /// cross-reference index has been worked out.
    pub reachable: Option<usize>,
    /// How many functions nothing calls.
    ///
    /// This needs the whole program read, so it is not known until the
    /// cross-reference index has been worked out.
    pub no_callers: Option<usize>,
    /// How many bytes of code the program holds.
    pub code_bytes: u64,
    /// How many functions the program holds.
    pub functions: usize,
}

/// Row counts for the navigator's explore sections.
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionCounts {
    /// Number of functions.
    pub functions: usize,
    /// Number of imports.
    pub imports: usize,
    /// Number of exports.
    pub exports: usize,
    /// Number of strings.
    pub strings: usize,
    /// Number of segments.
    pub segments: usize,
    /// Number of recovered types.
    pub types: usize,
    /// Number of bookmarks.
    pub bookmarks: usize,
}

/// One section of the program image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentEntry {
    /// The section's name, as the container spells it.
    pub name: String,
    /// The address the section maps to.
    pub vma: u64,
    /// The section's size in memory.
    pub size: u64,
    /// Whether the section holds code.
    pub executable: bool,
    /// Whether the section is mapped into memory.
    ///
    /// A section that is not mapped — the debug information of an ELF, say
    /// — lives in the file only, and has no address to jump to.
    pub mapped: bool,
}

/// A named piece of data in the program image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbolEntry {
    /// Where the symbol lives.
    pub address: u64,
    /// Its name.
    pub name: String,
    /// How many bytes it holds, when the symbol says.
    pub size: Option<u64>,
    /// The section it lives in, when it is in one.
    pub section: Option<String>,
}

pub use corpus::is_corpus;
pub use kuna::is_kuna_export;

/// Read access to the open project.
pub trait Provider: Send + Sync {
    /// Identity of the project.
    fn project(&self) -> Project;

    /// Which artifacts this provider can supply.
    fn capabilities(&self) -> Capabilities;

    /// Analysis progress.
    fn analysis_state(&self) -> AnalysisState;

    /// Every function known to the project.
    fn functions(&self) -> Vec<FunctionRow>;

    /// Details for one function.
    fn function_detail(&self, address: u64) -> Option<FunctionDetail>;

    /// Linear disassembly for a function, when available.
    fn listing(&self, address: u64) -> Option<Vec<ListingLine>>;

    /// The control-flow graph of a function, when the provider has one.
    ///
    /// The blocks come back in the order the walk found them, and the edges
    /// between them carry the kind each edge has; the graph view lays them
    /// out itself.
    fn graph(&self, _address: u64) -> Option<Graph> {
        None
    }

    /// Decompiled pseudocode for a function, when available.
    fn pseudocode(&self, address: u64) -> Option<String>;

    /// The addresses each line of the pseudocode came from.
    ///
    /// The keys are line numbers counted from zero, so they line up with
    /// the lines of [`Provider::pseudocode`]. A provider that learns the
    /// mapping later — the kuna provider asks the CLI for it — answers with
    /// nothing here and fills it in when it arrives.
    fn line_addresses(&self, _address: u64) -> BTreeMap<usize, Vec<u64>> {
        BTreeMap::new()
    }

    /// Bytes around an address, when available.
    ///
    /// The rows hold the bytes of the file around the address, sixteen to a
    /// row, so a reader can see the bytes of the selection in place.
    fn bytes(&self, address: u64) -> Option<Vec<ByteLine>>;

    /// Cross references for an address.
    fn references(&self, address: u64) -> Vec<Reference>;

    /// Whether the provider is still working out its cross references.
    ///
    /// The references that go the other way — who calls this function — need
    /// the whole program read, so they arrive after the project opens.
    fn references_pending(&self) -> bool {
        false
    }

    /// The cross-reference index has been worked out.
    fn mark_references_ready(&self) {}

    /// The strings the project holds.
    fn strings(&self) -> Vec<StringEntry> {
        Vec::new()
    }

    /// Counts for the navigator sections.
    fn counts(&self) -> SectionCounts;

    /// The sections of the program image, when the project is one.
    fn segments(&self) -> Vec<SegmentEntry> {
        Vec::new()
    }

    /// The named data of the program image, when the project has some.
    fn data_symbols(&self) -> Vec<DataSymbolEntry> {
        Vec::new()
    }

    /// Search the project.
    ///
    /// `deep` also searches function bodies, which is more expensive than
    /// matching names.
    fn search(&self, query: &str, deep: bool) -> Vec<SearchHit>;

    /// Diagnostics reported by the analysis.
    fn problems(&self) -> Vec<Problem>;

    /// Diagnostics reported about one function.
    fn function_problems(&self, _address: u64) -> Vec<Problem> {
        Vec::new()
    }

    /// The shape of the whole project.
    fn summary(&self) -> Option<ProjectSummary> {
        None
    }
}
