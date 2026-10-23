//! Data access for the workbench.
//!
//! Every view reads through the [`Provider`] trait so the same UI can be
//! driven by a real corpus, a binary under analysis, or the bundled sample
//! data used to exercise the layout.

pub mod corpus;
pub mod empty;
pub mod kuna;
pub mod kuna_json;
pub mod sample;

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
    /// Best known name (symbol, Objective-C method, or generated).
    pub name: String,
    /// Analysis status reported for this function.
    pub status: String,
    /// Size of the function body in bytes, when known.
    pub size: Option<u64>,
    /// Whether the name came from an Objective-C method map.
    pub objc: bool,
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
}

impl ReferenceKind {
    /// Uppercase label used in the inspector.
    pub fn label(self) -> &'static str {
        match self {
            ReferenceKind::Calls => "CALLS",
            ReferenceKind::CalledBy => "CALLED BY",
            ReferenceKind::Data => "DATA",
            ReferenceKind::String => "STRING",
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
}

impl HitKind {
    /// Short label for the result table.
    pub fn label(self) -> &'static str {
        match self {
            HitKind::Function => "Function",
            HitKind::String => "String",
            HitKind::CodeRef => "Code reference",
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
    pub reachable: usize,
    /// How many functions nothing calls.
    pub no_callers: usize,
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

    /// Decompiled pseudocode for a function, when available.
    fn pseudocode(&self, address: u64) -> Option<String>;

    /// Bytes around an address, when available.
    fn bytes(&self, address: u64) -> Option<Vec<ByteLine>>;

    /// Cross references for an address.
    fn references(&self, address: u64) -> Vec<Reference>;

    /// The strings the project holds.
    fn strings(&self) -> Vec<StringEntry> {
        Vec::new()
    }

    /// Counts for the navigator sections.
    fn counts(&self) -> SectionCounts;

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
