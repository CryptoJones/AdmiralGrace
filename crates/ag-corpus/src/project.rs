//! The portable project file: an analysis and the analyst's changes to it.
//!
//! A corpus or an image tells the workbench what the machine found. The
//! analyst's own work — a renamed function, a comment, a bookmark — has to
//! survive the session, travel between machines, and stay readable without
//! this program. That is this file: versioned JSON, named `.agproj`, holding
//! the target's identity, the analysis options the run used, and every
//! annotation, keyed by address.
//!
//! Addresses are written the way a corpus writes them, with the address
//! space when the record names one: `EXTERNAL:0x1`. [`crate::parse_addr_space`]
//! reads them back, so a project opened against a corpus finds the same
//! function the navigator shows.
//!
//! The file is a superset contract: a reader keeps what it knows and refuses
//! a `format` newer than [`FORMAT_VERSION`] rather than misreading it.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The format version this program writes and reads.
pub const FORMAT_VERSION: u32 = 1;

/// The file extension of a project file.
pub const PROJECT_EXTENSION: &str = "agproj";

/// What kind of thing an annotation is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// A function, keyed by its entry address.
    Function,
    /// A single address.
    Address,
    /// A run of bytes, keyed by its first address.
    Region,
}

/// A change the analyst made at one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    /// What the annotation is attached to.
    pub kind: TargetKind,
    /// The address the annotation is attached to.
    pub address: String,
    /// The analyst's name for the target, replacing the analysis's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The analyst's comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Whether the target is bookmarked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bookmark: bool,
    /// Tags carried by the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// A color for the target, as `#rrggbb`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// How the bytes at the target are classified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_type: Option<String>,
}

impl Annotation {
    /// An empty annotation at the address `address`, of kind `kind`.
    pub fn new(kind: TargetKind, address: &str) -> Self {
        Self {
            kind,
            address: address.to_string(),
            name: None,
            comment: None,
            bookmark: false,
            tags: Vec::new(),
            color: None,
            byte_type: None,
        }
    }

    /// Whether this annotation carries nothing; a carried-empty annotation
    /// would say the analyst changed nothing.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.comment.is_none()
            && !self.bookmark
            && self.tags.is_empty()
            && self.color.is_none()
            && self.byte_type.is_none()
    }

    /// The address and space this annotation is keyed on.
    pub fn parse(&self) -> Result<(u64, Option<String>)> {
        crate::parse_addr_space(&self.address)
            .with_context(|| format!("the annotation address {:?}", self.address))
    }
}

/// The identity of the target the analysis ran on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Where the target was when the project was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// SHA-256 of the target, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// A portable project: the analysis's identity and the analyst's changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFile {
    /// The format version. A reader refuses a newer version than it knows.
    pub format: u32,
    /// The target this project describes.
    #[serde(default)]
    pub target: Target,
    /// The analysis options the run used, as name to value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// The analyst's changes, in the order they were made.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<Annotation>,
}

impl ProjectFile {
    /// A new empty project for the target `target`.
    pub fn new(target: Target) -> Self {
        Self {
            format: FORMAT_VERSION,
            target,
            options: BTreeMap::new(),
            annotations: Vec::new(),
        }
    }

    /// The annotation keyed on `kind` at `address`, added when none is there.
    pub fn annotation_mut(&mut self, kind: TargetKind, address: &str) -> &mut Annotation {
        let found = self
            .annotations
            .iter()
            .position(|a| a.kind == kind && a.address == address);
        match found {
            Some(index) => &mut self.annotations[index],
            None => {
                self.annotations.push(Annotation::new(kind, address));
                self.annotations
                    .last_mut()
                    .expect("the annotation was just pushed")
            }
        }
    }

    /// Drop every annotation that carries nothing.
    pub fn prune(&mut self) {
        self.annotations.retain(|a| !a.is_empty());
    }

    /// Read a project file from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the project file {}", path.display()))?;
        Self::from_json(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    /// Write the project to `path` as pretty JSON with a trailing newline.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut text =
            serde_json::to_string_pretty(self).context("serializing the project file")?;
        text.push('\n');
        std::fs::write(path, text)
            .with_context(|| format!("writing the project file {}", path.display()))
    }

    /// Parse project JSON, refusing a format newer than this program reads.
    pub fn from_json(raw: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct FormatProbe {
            format: u32,
        }
        let probe: FormatProbe =
            serde_json::from_str(raw).context("the project file is not project JSON")?;
        if probe.format > FORMAT_VERSION {
            bail!(
                "project format {} is newer than this program reads ({}); upgrade",
                probe.format,
                FORMAT_VERSION
            );
        }
        serde_json::from_str(raw).context("parsing the project file")
    }

    /// The project as JSON text.
    pub fn to_json(&self) -> Result<String> {
        let mut text =
            serde_json::to_string_pretty(self).context("serializing the project file")?;
        text.push('\n');
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ag-project-{name}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&path);
        path
    }

    #[test]
    fn a_project_round_trips_through_disk() {
        let dir = temp("round-trip");
        let path = dir.join("sample.agproj");

        let mut project = ProjectFile::new(Target {
            path: Some("/bin/ls".into()),
            sha256: Some("9f86d0".into()),
        });
        project
            .options
            .insert("loop-form".into(), "while".into());
        project
            .annotation_mut(TargetKind::Function, "0x1000")
            .name = Some("main".into());
        project
            .annotation_mut(TargetKind::Function, "EXTERNAL:0x1")
            .comment = Some("imported qsort".into());
        project.save(&path).expect("save");

        let read = ProjectFile::load(&path).expect("load");
        assert_eq!(read, project);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_format_is_refused_not_misread() {
        let raw = r#"{"format": 99, "target": {}}"#;
        let error = ProjectFile::from_json(raw).expect_err("format 99 is unreadable");
        assert!(
            error.to_string().contains("newer"),
            "the error says what is wrong: {error}"
        );
    }

    #[test]
    fn an_empty_annotation_is_pruned() {
        let mut project = ProjectFile::new(Target::default());
        project.annotation_mut(TargetKind::Address, "0x10");
        assert!(project.annotations[0].is_empty());
        project.prune();
        assert!(project.annotations.is_empty());
    }

    #[test]
    fn an_annotation_address_keeps_its_space() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "EXTERNAL:0x1")
            .name = Some("qsort".into());
        let (address, space) = project.annotations[0].parse().expect("parses");
        assert_eq!(address, 0x1);
        assert_eq!(space.as_deref(), Some("EXTERNAL"));
    }

    #[test]
    fn a_malformed_annotation_address_is_refused() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Address, "not-an-address")
            .comment = Some("here".into());
        assert!(project.annotations[0].parse().is_err());
    }

    #[test]
    fn the_saved_file_is_readable_json() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "0x1000")
            .bookmark = true;
        let text = project.to_json().expect("json");
        assert!(text.contains("\"format\": 1"), "{text}");
        assert!(text.contains("\"bookmark\": true"), "{text}");
        // An empty name is not written at all.
        assert!(!text.contains("\"name\""), "{text}");
    }
}
