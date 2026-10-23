//! A [`Provider`] for when no project is open.

use crate::data::{
    AnalysisState, FunctionDetail, FunctionRow, Problem, Provider, Reference, SearchHit,
    SectionCounts,
};
use crate::model::{Capabilities, Project, ProjectKind};

/// The empty project shown after the analyst closes a project.
pub struct EmptyProvider {
    project: Project,
}

impl EmptyProvider {
    /// Build the empty project.
    pub fn new() -> Self {
        Self {
            project: Project {
                name: "No project".into(),
                kind: ProjectKind::Binary,
                root: None,
                target_sha256: None,
                provider: "none".into(),
                architecture: None,
                format: None,
            },
        }
    }
}

impl Default for EmptyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for EmptyProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::NONE
    }

    fn analysis_state(&self) -> AnalysisState {
        AnalysisState::Idle
    }

    fn functions(&self) -> Vec<FunctionRow> {
        Vec::new()
    }

    fn function_detail(&self, _address: u64) -> Option<FunctionDetail> {
        None
    }

    fn listing(&self, _address: u64) -> Option<Vec<crate::data::ListingLine>> {
        None
    }

    fn pseudocode(&self, _address: u64) -> Option<String> {
        None
    }

    fn bytes(&self, _address: u64) -> Option<Vec<crate::data::ByteLine>> {
        None
    }

    fn references(&self, _address: u64) -> Vec<Reference> {
        Vec::new()
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts::default()
    }

    fn search(&self, _query: &str, _deep: bool) -> Vec<SearchHit> {
        Vec::new()
    }

    fn problems(&self) -> Vec<Problem> {
        Vec::new()
    }
}
