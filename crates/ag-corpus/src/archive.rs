//! A type archive shared across projects (#377).
//!
//! An archive is one file of types several projects sync with: entries of
//! the same shape [`crate::project::TypeDefinition`] keeps — a `name` and
//! its `c` — in one document, `.agarchive`. A project pushes its types
//! into the archive and pulls the archive's into itself; a per-type
//! [`TypeStatus`] says where a name stands between the two sides
//! ([`TypeStatus::InSync`], [`TypeStatus::ProjectOnly`],
//! [`TypeStatus::ArchiveOnly`], [`TypeStatus::Conflict`]); a conflict is
//! settled by the analyst, per type, with [`ConflictChoice::KeepProject`]
//! (the project side wins) or [`ConflictChoice::KeepArchive`] (the
//! archive side wins).
//!
//! Equality of a name across the two sides is on the definition itself —
//! the `name` and the `c` — so the archive is a plain list and the sync
//! is a three-way-free merge: there is no common ancestor, just the two
//! sides and the analyst's choice when they disagree.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::project::TypeDefinition;

/// The format version this program writes and reads.
pub const ARCHIVE_FORMAT_VERSION: u32 = 1;

/// The file extension of a type archive.
pub const ARCHIVE_EXTENSION: &str = "agarchive";

/// One type as several projects share it: the name it goes by and its C,
/// the same shape a project's `types` holds. An archive stores one of
/// these per name; a project stores them in its `types` list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveType {
    /// The name it goes by: a typedef's, or a tag's with its keyword.
    pub name: String,
    /// Its C: one declaration, as the project keeps it.
    pub c: String,
}

impl From<TypeDefinition> for ArchiveType {
    fn from(definition: TypeDefinition) -> Self {
        Self {
            name: definition.name,
            c: definition.c,
        }
    }
}

impl From<ArchiveType> for TypeDefinition {
    fn from(entry: ArchiveType) -> Self {
        Self {
            name: entry.name,
            c: entry.c,
        }
    }
}

/// A file of types several projects sync with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeArchive {
    /// The format version. A reader refuses a newer version than it knows.
    pub format: u32,
    /// The types the archive holds, in stored order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<ArchiveType>,
}

impl TypeArchive {
    /// A new empty archive.
    pub fn new() -> Self {
        Self {
            format: ARCHIVE_FORMAT_VERSION,
            types: Vec::new(),
        }
    }

    /// Read the archive at `path`; a missing file is an error — callers
    /// that create on first write check for it themselves.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the type archive {}", path.display()))?;
        Self::from_json(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    /// Write the archive to `path` as pretty JSON with a trailing newline.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut text =
            serde_json::to_string_pretty(self).context("serializing the type archive")?;
        text.push('\n');
        std::fs::write(path, text)
            .with_context(|| format!("writing the type archive {}", path.display()))
    }

    /// Parse archive JSON, refusing a format newer than this program reads.
    pub fn from_json(raw: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct FormatProbe {
            format: u32,
        }
        let probe: FormatProbe =
            serde_json::from_str(raw).context("the file is not a type-archive JSON")?;
        if probe.format > ARCHIVE_FORMAT_VERSION {
            bail!(
                "type-archive format {} is newer than this program reads ({}); upgrade",
                probe.format,
                ARCHIVE_FORMAT_VERSION
            );
        }
        let archive: TypeArchive = serde_json::from_str(raw).context("parsing the type archive")?;
        // Two entries of one name would collapse to the last in status();
        // a hand-edited file is refused rather than misread.
        let mut seen = std::collections::BTreeSet::new();
        for entry in &archive.types {
            if !seen.insert(entry.name.clone()) {
                bail!("the archive holds {} twice", entry.name);
            }
        }
        Ok(archive)
    }

    /// The archive as JSON text.
    pub fn to_json(&self) -> Result<String> {
        let mut text =
            serde_json::to_string_pretty(self).context("serializing the type archive")?;
        text.push('\n');
        Ok(text)
    }

    /// The entry by `name`, or `None`.
    pub fn get(&self, name: &str) -> Option<&ArchiveType> {
        let name = name.trim();
        self.types.iter().find(|entry| entry.name == name)
    }

    /// Set `entry` in the archive, replacing the one of its name in place
    /// or pushing it after the rest; the entry pushed is returned.
    pub fn set(&mut self, entry: ArchiveType) -> &ArchiveType {
        let at = self.types.iter().position(|held| held.name == entry.name);
        match at {
            Some(at) => {
                self.types[at] = entry;
                &self.types[at]
            }
            None => {
                self.types.push(entry);
                self.types.last().expect("just pushed")
            }
        }
    }

    /// Drop the entry by `name`; the entry dropped, or `None`.
    pub fn remove(&mut self, name: &str) -> Option<ArchiveType> {
        let name = name.trim();
        let at = self.types.iter().position(|entry| entry.name == name)?;
        Some(self.types.remove(at))
    }

    /// Names held, in stored order.
    pub fn names(&self) -> Vec<&str> {
        self.types.iter().map(|entry| entry.name.as_str()).collect()
    }
}

/// Where a type stands between a project and an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeStatus {
    /// Both sides hold the name with the same C.
    InSync,
    /// Only the project holds the name.
    ProjectOnly,
    /// Only the archive holds the name.
    ArchiveOnly,
    /// Both sides hold the name, with different C.
    Conflict,
}

impl TypeStatus {
    /// The word the status prints as.
    pub fn label(self) -> &'static str {
        match self {
            TypeStatus::InSync => "in-sync",
            TypeStatus::ProjectOnly => "project-only",
            TypeStatus::ArchiveOnly => "archive-only",
            TypeStatus::Conflict => "conflict",
        }
    }
}

/// How a conflict is settled: the project side keeps its C, or the
/// archive side's C wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// The project's C stays; the archive's is dropped from the project.
    KeepProject,
    /// The archive's C wins; the project's is replaced.
    KeepArchive,
}

impl ConflictChoice {
    /// The word the choice is given as: `project` or `archive`.
    pub fn label(self) -> &'static str {
        match self {
            ConflictChoice::KeepProject => "project",
            ConflictChoice::KeepArchive => "archive",
        }
    }

    /// The choice the word `project` or `archive` names.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "project" | "keep-project" | "keep_project" => Some(ConflictChoice::KeepProject),
            "archive" | "keep-archive" | "keep_archive" => Some(ConflictChoice::KeepArchive),
            _ => None,
        }
    }
}

/// One name's standing between the two sides: the status, and the C each
/// side holds when it holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeSync {
    /// The name.
    pub name: String,
    /// Where it stands.
    pub status: TypeStatus,
    /// The C the project holds, when it holds the name.
    pub project: Option<String>,
    /// The C the archive holds, when it holds the name.
    pub archive: Option<String>,
}

/// The standing of every name either side holds, in name order: for a
/// name both sides hold, in-sync when the definitions are equal — the
/// name and the C — and a conflict otherwise.
pub fn status(project: &[TypeDefinition], archive: &TypeArchive) -> Vec<TypeSync> {
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, (Option<&TypeDefinition>, Option<&ArchiveType>)> =
        BTreeMap::new();
    for definition in project {
        by_name.entry(definition.name.clone()).or_default().0 = Some(definition);
    }
    for entry in &archive.types {
        by_name.entry(entry.name.clone()).or_default().1 = Some(entry);
    }
    by_name
        .into_iter()
        .map(|(name, (in_project, in_archive))| {
            let status = match (in_project, in_archive) {
                (Some(project), Some(entry)) => {
                    if project.c == entry.c {
                        TypeStatus::InSync
                    } else {
                        TypeStatus::Conflict
                    }
                }
                (Some(_), None) => TypeStatus::ProjectOnly,
                (None, Some(_)) => TypeStatus::ArchiveOnly,
                (None, None) => unreachable!("in neither side"),
            };
            TypeSync {
                name,
                status,
                project: in_project.map(|d| d.c.clone()),
                archive: in_archive.map(|e| e.c.clone()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::ProjectFile;
    use crate::project::Target;

    fn project(types: &[(&str, &str)]) -> Vec<TypeDefinition> {
        types
            .iter()
            .map(|(name, c)| TypeDefinition {
                name: name.to_string(),
                c: c.to_string(),
            })
            .collect()
    }

    fn archive(types: &[(&str, &str)]) -> TypeArchive {
        TypeArchive {
            format: ARCHIVE_FORMAT_VERSION,
            types: types
                .iter()
                .map(|(name, c)| ArchiveType {
                    name: name.to_string(),
                    c: c.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_status_is_in_sync_for_the_same_c() {
        let archive = archive(&[("struct point", "struct point { int x, y; };")]);
        let sync = status(
            &project(&[("struct point", "struct point { int x, y; };")]),
            &archive,
        );
        assert_eq!(sync.len(), 1);
        assert_eq!(sync[0].status, TypeStatus::InSync);
        assert_eq!(sync[0].status.label(), "in-sync");
        assert_eq!(
            sync[0].project.as_deref(),
            Some("struct point { int x, y; };")
        );
        assert_eq!(
            sync[0].archive.as_deref(),
            Some("struct point { int x, y; };")
        );
    }

    #[test]
    fn a_status_is_a_conflict_for_the_same_name_with_different_c() {
        let archive = archive(&[("struct point", "struct point { long x, y; };")]);
        let sync = status(
            &project(&[("struct point", "struct point { int x, y; };")]),
            &archive,
        );
        assert_eq!(sync[0].status, TypeStatus::Conflict);
        assert_eq!(sync[0].status.label(), "conflict");
    }

    #[test]
    fn a_status_is_project_only_and_archive_only_per_side() {
        let archive = archive(&[
            ("struct point", "struct point { int x, y; };"),
            ("struct box", "struct box { int w; };"),
        ]);
        let sync = status(
            &project(&[
                ("struct point", "struct point { int x, y; };"),
                ("struct local_", "struct local_ { char c; };"),
            ]),
            &archive,
        );
        let by = |name: &str| sync.iter().find(|s| s.name == name).unwrap().status;
        assert_eq!(by("struct point"), TypeStatus::InSync);
        assert_eq!(by("struct local_"), TypeStatus::ProjectOnly);
        assert_eq!(by("struct box"), TypeStatus::ArchiveOnly);
        // in name order
        let names: Vec<_> = sync.iter().map(|s| s.name.clone()).collect();
        assert_eq!(names, ["struct box", "struct local_", "struct point"]);
    }

    #[test]
    fn an_archive_round_trips_through_json() {
        let archive = archive(&[("node_t", "typedef struct node { … } node_t;")]);
        let json = archive.to_json().unwrap();
        assert!(json.contains("\"format\": 1"), "{json}");
        let read = TypeArchive::from_json(&json).unwrap();
        assert_eq!(read, archive);
        // A newer format is refused, not misread.
        let newer = TypeArchive::from_json(r#"{"format": 9, "types": []}"#);
        assert!(newer.is_err());
        // A file without types reads empty.
        let bare = TypeArchive::from_json(r#"{"format": 1}"#).unwrap();
        assert!(bare.types.is_empty());
    }

    #[test]
    fn an_archive_set_replaces_in_place_and_remove_drops() {
        let mut archive = archive(&[("struct a", "struct a { int x; };")]);
        archive.set(ArchiveType {
            name: "struct a".to_string(),
            c: "struct a { long x; };".to_string(),
        });
        assert_eq!(archive.types.len(), 1);
        assert_eq!(archive.types[0].c, "struct a { long x; };");
        archive.set(ArchiveType {
            name: "struct b".to_string(),
            c: "struct b { int y; };".to_string(),
        });
        assert_eq!(archive.names(), ["struct a", "struct b"]);
        assert!(archive.get("struct a").is_some());
        assert!(archive.remove("struct a").is_some());
        assert!(archive.remove("struct a").is_none());
        assert_eq!(archive.names(), ["struct b"]);
    }

    #[test]
    fn a_choice_is_read_by_word() {
        assert_eq!(
            ConflictChoice::parse("project"),
            Some(ConflictChoice::KeepProject)
        );
        assert_eq!(
            ConflictChoice::parse("archive"),
            Some(ConflictChoice::KeepArchive)
        );
        assert_eq!(
            ConflictChoice::parse("keep-project"),
            Some(ConflictChoice::KeepProject)
        );
        assert!(ConflictChoice::parse("theirs").is_none());
        assert_eq!(ConflictChoice::KeepProject.label(), "project");
        assert_eq!(ConflictChoice::KeepArchive.label(), "archive");
    }

    #[test]
    fn an_archive_type_converts_both_ways() {
        let definition = TypeDefinition {
            name: "struct point".to_string(),
            c: "struct point { int x, y; };".to_string(),
        };
        let entry = ArchiveType::from(definition.clone());
        assert_eq!(entry.name, "struct point");
        assert_eq!(TypeDefinition::from(entry), definition);
    }

    #[test]
    fn a_project_file_keeps_an_archive_round_trip() {
        let mut project = ProjectFile::new(Target::default());
        project.types = vec![TypeDefinition {
            name: "struct point".to_string(),
            c: "struct point { int x, y; };".to_string(),
        }];
        let json = project.to_json().unwrap();
        let read = ProjectFile::from_json(&json).unwrap();
        let archive = TypeArchive::new();
        let sync = status(&read.types, &archive);
        assert_eq!(sync[0].status, TypeStatus::ProjectOnly);
    }
}
