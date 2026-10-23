//! The project currently open in the workbench.

use std::path::PathBuf;

/// Where the project data came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectKind {
    /// A decompilation corpus indexed by `decompile-index.json`.
    Corpus,
    /// A kuna project export (`index.jsonl` plus `.c`, `.h` and `.asm`).
    Kuna,
    /// A binary opened for static analysis.
    #[allow(dead_code)]
    Binary,
    /// Fabricated sample data used to exercise the layout.
    Sample,
}

impl ProjectKind {
    /// Short label shown in the navigator.
    pub fn label(self) -> &'static str {
        match self {
            ProjectKind::Corpus => "Corpus",
            ProjectKind::Kuna => "Kuna",
            ProjectKind::Binary => "Binary",
            ProjectKind::Sample => "Sample",
        }
    }
}

/// Identity and provenance of the open project.
#[derive(Debug, Clone)]
pub struct Project {
    /// Display name (usually the file or directory name).
    pub name: String,
    /// Which kind of project this is.
    pub kind: ProjectKind,
    /// Root directory or file path, when there is one.
    pub root: Option<PathBuf>,
    /// SHA-256 of the analysed target, when known.
    pub target_sha256: Option<String>,
    /// Name of the analysis provider that produced the results.
    pub provider: String,
    /// Target architecture, when known.
    pub architecture: Option<String>,
    /// Executable format, when known.
    pub format: Option<String>,
}

impl Project {
    /// One-line description used under the project heading.
    pub fn subtitle(&self) -> String {
        match self.architecture.as_ref() {
            Some(arch) => format!("{} · {}", self.name, arch),
            None => self.name.clone(),
        }
    }
}
