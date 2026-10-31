//! A [`Provider`] backed by a decompilation corpus.

use std::path::Path;

use ag_corpus::objc::{method_display, Overlay};
use ag_corpus::{BodyRange, Corpus, Function};
use anyhow::Result;

use crate::data::{
    AnalysisState, FunctionDetail, FunctionRow, HitKind, Problem, Provider, Reference, SearchHit,
    SectionCounts,
};
use crate::model::{Capabilities, Project, ProjectKind};

/// Reads analysis results from a `decompile-index.json` corpus.
pub struct CorpusProvider {
    corpus: Corpus,
    overlay: Option<Overlay>,
    project: Project,
}

impl CorpusProvider {
    /// Load a corpus from `root`.
    pub fn load(root: &Path, methods: Option<&Path>, shift: u64) -> Result<Self> {
        let corpus = Corpus::load(root)?;
        let overlay = match methods {
            Some(path) => {
                let map = ag_corpus::objc::load_map(path)?;
                Some(Overlay::new(map).with_shift(shift))
            }
            None => None,
        };

        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| root.display().to_string());

        let project = Project {
            name,
            kind: ProjectKind::Corpus,
            root: Some(root.to_path_buf()),
            target_sha256: Some(corpus.target_sha256.clone()),
            provider: format!("{} {}", corpus.provider.0, corpus.provider.1),
            architecture: None,
            format: None,
        };

        Ok(Self {
            corpus,
            overlay,
            project,
        })
    }

    /// The best known display name for a corpus function.
    fn display_name(&self, f: &Function) -> (String, bool) {
        if let Some(overlay) = &self.overlay {
            if let Some(method) = overlay.by_imp.get(&f.address) {
                return (method_display(method), true);
            }
        }

        match &f.name {
            Some(name) => (name.clone(), false),
            None => (format!("sub_{:X}", f.address), false),
        }
    }

    /// Body size of a function, when the corpus recorded a range.
    fn body_size(f: &Function) -> Option<u64> {
        match &f.range {
            Some(BodyRange::Contiguous { start, end }) => Some(end.saturating_sub(*start)),
            Some(BodyRange::NonContiguous { ranges }) => Some(
                ranges
                    .iter()
                    .map(|(s, e)| e.saturating_sub(*s))
                    .sum::<u64>(),
            ),
            None => None,
        }
    }
}

impl Provider for CorpusProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            pseudocode: true,
            objc_methods: self.overlay.is_some(),
            ..Capabilities::NONE
        }
    }

    fn analysis_state(&self) -> AnalysisState {
        AnalysisState::Complete
    }

    fn functions(&self) -> Vec<FunctionRow> {
        self.corpus
            .functions
            .iter()
            .map(|f| {
                let (name, objc) = self.display_name(f);
                FunctionRow {
                    address: f.address,
                    space: f.space.clone(),
                    name,
                    status: f.status.clone(),
                    size: Self::body_size(f),
                    objc,
                }
            })
            .collect()
    }

    fn function_detail(&self, address: u64) -> Option<FunctionDetail> {
        let index = *self.corpus.by_address.get(&address)?;
        let f = &self.corpus.functions[index];
        let (name, objc) = self.display_name(f);

        let (start, end) = match &f.range {
            Some(BodyRange::Contiguous { start, end }) => (Some(*start), Some(*end)),
            Some(BodyRange::NonContiguous { ranges }) => {
                let start = ranges.iter().map(|(s, _)| *s).min();
                let end = ranges.iter().map(|(_, e)| *e).max();
                (start, end)
            }
            None => (None, None),
        };

        let provenance = if objc {
            "Objective-C method map".to_string()
        } else if f.name.is_some() {
            "Imported symbol".to_string()
        } else {
            "Analysis inference".to_string()
        };

        let summary = match f.status.as_str() {
            "written" => "Decompiled output available.".to_string(),
            "failed" => "Decompilation failed for this function.".to_string(),
            other => format!("Corpus status: {other}."),
        };

        Some(FunctionDetail {
            name,
            status: f.status.clone(),
            start,
            end,
            provenance,
            mangled: None,
            summary,
        })
    }

    fn listing(&self, _address: u64) -> Option<Vec<crate::data::ListingLine>> {
        None
    }

    fn pseudocode(&self, address: u64) -> Option<String> {
        let index = *self.corpus.by_address.get(&address)?;
        let f = &self.corpus.functions[index];
        if !f.has_body() {
            return None;
        }
        self.corpus.function_body(f).ok()
    }

    fn bytes(&self, _address: u64) -> Option<Vec<crate::data::ByteLine>> {
        None
    }

    fn references(&self, _address: u64) -> Vec<Reference> {
        Vec::new()
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts {
            functions: self.corpus.functions.len(),
            ..SectionCounts::default()
        }
    }

    fn search(&self, query: &str, deep: bool) -> Vec<SearchHit> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }

        let mut hits = Vec::new();

        for (index, f) in self.corpus.functions.iter().enumerate() {
            let (name, _) = self.display_name(f);
            if name.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    address: f.address,
                    title: name.clone(),
                    detail: "Function".to_string(),
                    kind: HitKind::Function,
                });
            }

            if deep && f.has_body() {
                let _ = index;
                if let Ok(body) = self.corpus.function_body(f) {
                    if let Some(line) = body
                        .lines()
                        .find(|line| line.to_lowercase().contains(&needle))
                    {
                        let trimmed = line.trim();
                        hits.push(SearchHit {
                            address: f.address,
                            title: format!("{}: {}", name, trimmed),
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

        // What the loaders had to say about the data they read. Nothing was
        // dropped in silence, and the workbench says so too.
        for warning in &self.corpus.warnings {
            problems.push(Problem {
                message: warning.clone(),
                address: None,
                action: Some("Check the corpus index".into()),
            });
        }

        if let Some(overlay) = &self.overlay {
            for warning in &overlay.warnings {
                problems.push(Problem {
                    message: warning.clone(),
                    address: None,
                    action: Some("Check the method map".into()),
                });
            }
        }

        let failed = self
            .corpus
            .functions
            .iter()
            .filter(|f| f.status == "failed")
            .count();

        if failed > 0 {
            problems.push(Problem {
                message: format!("{failed} functions failed to decompile"),
                address: None,
                action: Some("Re-run the provider on this target".into()),
            });
        }

        problems
    }
}

/// Whether the corpus contains a usable index at `root`.
pub fn is_corpus(root: &Path) -> bool {
    root.join("decompile-index.json").is_file()
}
