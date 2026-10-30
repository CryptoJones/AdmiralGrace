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
pub const FORMAT_VERSION: u32 = 3;

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
    /// A local variable of the function at the address, keyed by its
    /// declared name.
    Variable,
    /// A register as one function's pseudocode and listing print it, keyed
    /// by the register's own name.
    Register,
}

impl TargetKind {
    /// The kind's label, as the CLI prints it.
    pub fn label(self) -> &'static str {
        match self {
            TargetKind::Function => "function",
            TargetKind::Address => "address",
            TargetKind::Region => "region",
            TargetKind::Variable => "variable",
            TargetKind::Register => "register",
        }
    }
}

/// The SHA-256 of the file at `path`, as lowercase hex.
///
/// The project file records the target's hash, so the format owner computes
/// it; the CLI and the workbench ask rather than each carrying a copy.
pub fn sha256_of(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The canonical spelling of an annotation address.
///
/// `0X10`, `0x10` and `10` all key the same function, and `external:0x1` and
/// `EXTERNAL:0x1` key the same import — the space is upper-cased and the
/// value printed as `{:#x}`, the way a corpus writes it. `None` when the
/// text names no address at all; such an address is keyed as written.
pub fn canonical_address(raw: &str) -> Option<String> {
    let (value, space) = crate::parse_addr_space(raw).ok()?;
    Some(match space {
        Some(space) => format!("{}:{value:#x}", space.to_ascii_uppercase()),
        None => format!("{value:#x}"),
    })
}

/// A change the analyst made at one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    /// What the annotation is attached to.
    pub kind: TargetKind,
    /// The address the annotation is attached to.
    pub address: String,
    /// The local variable this record names, when it names one.
    ///
    /// A function's entry and a label share one address and one record: the
    /// entry label *is* the function's name. A local variable is a different
    /// thing at that same address, so it carries its declared name here and
    /// gets a record of its own. Two records at one address are told apart
    /// by this field, never by the order they were written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    /// The register this record renames within one function, when it names
    /// one.
    ///
    /// A register is not a thing at an address the way a function or a label
    /// is; it is a name the one function's pseudocode and listing print. So a
    /// register record keys on the register's own name beside the function's
    /// entry address, and the rename reaches only that function — the same
    /// shape as a local variable's record, and told apart from it by which
    /// field is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
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
    /// An empty annotation for the local variable `variable` of the function
    /// at `address`.
    pub fn for_variable(address: &str, variable: &str) -> Self {
        Self {
            kind: TargetKind::Variable,
            address: address.to_string(),
            variable: Some(variable.to_string()),
            register: None,
            name: None,
            comment: None,
            bookmark: false,
            tags: Vec::new(),
            color: None,
            byte_type: None,
        }
    }

    /// An empty annotation for the register `register` of the function at
    /// `address`.
    pub fn for_register(address: &str, register: &str) -> Self {
        Self {
            kind: TargetKind::Register,
            address: address.to_string(),
            variable: None,
            register: Some(register.to_string()),
            name: None,
            comment: None,
            bookmark: false,
            tags: Vec::new(),
            color: None,
            byte_type: None,
        }
    }

    /// An empty annotation at the address `address`, of kind `kind`.
    pub fn new(kind: TargetKind, address: &str) -> Self {
        Self {
            kind,
            address: address.to_string(),
            variable: None,
            register: None,
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

    /// The annotation for the address `address`, added when none is there.
    ///
    /// One address carries one record: the lookup keys on the canonical
    /// spelling of the address (see [`canonical_address`]), so `0X10` and
    /// `0x10` reach the same record and a rename, a comment and a bookmark
    /// at one address live together rather than masking one another. The
    /// record's `kind` says what the most recent change was attached to.
    pub fn annotation_mut(&mut self, kind: TargetKind, address: &str) -> &mut Annotation {
        let key = canonical_address(address).unwrap_or_else(|| address.to_string());
        let found = self
            .annotations
            .iter()
            .position(|a| a.address == key && a.variable.is_none() && a.register.is_none());
        match found {
            Some(index) => {
                let annotation = &mut self.annotations[index];
                annotation.kind = kind;
                annotation
            }
            None => {
                self.annotations.push(Annotation::new(kind, &key));
                self.annotations
                    .last_mut()
                    .expect("the annotation was just pushed")
            }
        }
    }

    /// The annotation for the address `address`, when one is there.
    ///
    /// The lookup canonicalizes, so a caller holding any spelling of the
    /// address — `0X10`, `external:0x1` — finds the one record. A record
    /// that names a local variable or a register belongs to that thing, not
    /// the address, and is not found here; see [`ProjectFile::variable_for`]
    /// and [`ProjectFile::register_for`].
    pub fn annotation_for(&self, address: &str) -> Option<&Annotation> {
        let key = canonical_address(address).unwrap_or_else(|| address.to_string());
        self.annotations
            .iter()
            .find(|a| a.address == key && a.variable.is_none() && a.register.is_none())
    }

    /// The record naming the local variable `variable` at `address`, added
    /// when none is there.
    ///
    /// A variable is a different thing from the function or label at its
    /// function's entry, so it keys on its declared name beside the address
    /// and never shares the address's record.
    pub fn variable_mut(&mut self, address: &str, variable: &str) -> &mut Annotation {
        let key = canonical_address(address).unwrap_or_else(|| address.to_string());
        let found = self
            .annotations
            .iter()
            .position(|a| a.address == key && a.variable.as_deref() == Some(variable));
        match found {
            Some(index) => &mut self.annotations[index],
            None => {
                self.annotations
                    .push(Annotation::for_variable(&key, variable));
                self.annotations
                    .last_mut()
                    .expect("the annotation was just pushed")
            }
        }
    }

    /// The record naming the local variable `variable` at `address`.
    pub fn variable_for(&self, address: &str, variable: &str) -> Option<&Annotation> {
        let key = canonical_address(address).unwrap_or_else(|| address.to_string());
        self.annotations
            .iter()
            .find(|a| a.address == key && a.variable.as_deref() == Some(variable))
    }

    /// The analyst's name for the local variable `variable` at `address`.
    pub fn variable_name(&self, address: &str, variable: &str) -> Option<String> {
        self.variable_for(address, variable)
            .and_then(|a| a.name.clone())
    }

    /// The record renaming the register `register` within the function at
    /// `address`, added when none is there.
    ///
    /// A register belongs to no single address; it is printed across one
    /// function's pseudocode and listing. The record keys on the register's
    /// own name beside the function's entry address, so the rename reaches
    /// that function and no other.
    pub fn register_mut(&mut self, address: &str, register: &str) -> &mut Annotation {
        let key = canonical_address(address).unwrap_or_else(|| address.to_string());
        let found = self
            .annotations
            .iter()
            .position(|a| a.address == key && a.register.as_deref() == Some(register));
        match found {
            Some(index) => &mut self.annotations[index],
            None => {
                // A register record is new to a file written before version
                // 3: an older reader would misread it as the address's own
                // record, so the file must name a version that reader
                // refuses. Stamping the version this program writes is the
                // safe direction — a newer file is refused with a notice,
                // never misread.
                self.format = FORMAT_VERSION;
                self.annotations
                    .push(Annotation::for_register(&key, register));
                self.annotations
                    .last_mut()
                    .expect("the annotation was just pushed")
            }
        }
    }

    /// The record renaming the register `register` within the function at
    /// `address`.
    pub fn register_for(&self, address: &str, register: &str) -> Option<&Annotation> {
        let key = canonical_address(address).unwrap_or_else(|| address.to_string());
        self.annotations
            .iter()
            .find(|a| a.address == key && a.register.as_deref() == Some(register))
    }

    /// The analyst's name for the register `register` within the function at
    /// `address`.
    pub fn register_name(&self, address: &str, register: &str) -> Option<String> {
        self.register_for(address, register)
            .and_then(|a| a.name.clone())
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
        let (address, space) = crate::parse_addr_space(&project.annotations[0].address)
            .expect("the stored address parses");
        assert_eq!(address, 0x1);
        assert_eq!(space.as_deref(), Some("EXTERNAL"));
    }

    #[test]
    fn a_malformed_annotation_address_is_keyed_as_written() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Address, "not-an-address")
            .comment = Some("here".into());
        // A text that names no address is kept verbatim rather than dropped.
        assert_eq!(project.annotations[0].address, "not-an-address");
        assert!(canonical_address("not-an-address").is_none());
    }

    #[test]
    fn one_address_carries_one_record_whatever_the_spelling() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "0X10")
            .name = Some("main".into());
        // A comment at the same address, spelled differently, lands on the
        // same record rather than masking the rename.
        project
            .annotation_mut(TargetKind::Address, "0x10")
            .comment = Some("the entry".into());
        assert_eq!(project.annotations.len(), 1, "one record for one address");
        assert_eq!(project.annotations[0].address, "0x10", "stored canonical");
        let found = project.annotation_for("10").expect("any spelling finds it");
        assert_eq!(found.name.as_deref(), Some("main"));
        assert_eq!(found.comment.as_deref(), Some("the entry"));
    }

    #[test]
    fn a_spaced_address_keys_apart_from_the_bare_value() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "0x1")
            .name = Some("local".into());
        project
            .annotation_mut(TargetKind::Function, "external:0x1")
            .name = Some("qsort".into());
        assert_eq!(project.annotations.len(), 2, "the space keys apart");
        // The space is canonicalized, so a second spelling finds the import.
        project
            .annotation_mut(TargetKind::Function, "EXTERNAL:0x1")
            .bookmark = true;
        assert_eq!(project.annotations.len(), 2);
        assert_eq!(
            project.annotation_for("EXTERNAL:0x1").and_then(|a| a.name.as_deref()),
            Some("qsort")
        );
        assert_eq!(
            project.annotation_for("0x1").and_then(|a| a.name.as_deref()),
            Some("local")
        );
    }

    #[test]
    fn a_variable_record_does_not_share_the_address_record() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "0x1000")
            .name = Some("decode_frame".into());
        // The entry label and a local of the function at that entry are
        // different things: each keeps its own name.
        project
            .variable_mut("0x1000", "local_10")
            .name = Some("envelope".into());
        assert_eq!(project.annotations.len(), 2, "one address, two records");
        assert_eq!(
            project.annotation_for("0x1000").and_then(|a| a.name.as_deref()),
            Some("decode_frame"),
            "the address record is the function's"
        );
        assert_eq!(
            project.variable_name("0x1000", "local_10").as_deref(),
            Some("envelope")
        );
        // A second spelling of the address finds the same variable record.
        project.variable_mut("0X1000", "local_10").bookmark = true;
        assert_eq!(project.annotations.len(), 2);
        assert!(project.variable_for("0x1000", "local_10").is_some_and(|a| a.bookmark));
    }

    #[test]
    fn two_variables_at_one_address_key_apart_by_name() {
        let mut project = ProjectFile::new(Target::default());
        project.variable_mut("0x1000", "local_10").name = Some("envelope".into());
        project.variable_mut("0x1000", "local_14").name = Some("count".into());
        assert_eq!(project.annotations.len(), 2, "one record per variable");
        assert_eq!(
            project.variable_name("0x1000", "local_14").as_deref(),
            Some("count")
        );
        // An unnamed variable is pruned like any empty record.
        project.variable_mut("0x1000", "local_18");
        project.prune();
        assert_eq!(project.annotations.len(), 2);
    }

    #[test]
    fn a_variable_record_round_trips() {
        let mut project = ProjectFile::new(Target::default());
        project.variable_mut("0x1000", "local_10").name = Some("envelope".into());
        let text = project.to_json().expect("json");
        assert!(text.contains("\"variable\": \"local_10\""), "{text}");
        // A record that names no variable writes no variable field at all;
        // the kind's own value is not the field.
        assert_eq!(text.matches("\"variable\":").count(), 1, "{text}");
        let read = ProjectFile::from_json(&text).expect("the text reads back");
        assert_eq!(read, project);
    }

    #[test]
    fn a_register_record_keys_on_the_register_not_the_address() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "0x1000")
            .name = Some("decode_frame".into());
        // The register is a third thing at the entry address: its own
        // record, keyed on the register's name.
        project.register_mut("0x1000", "rax").name = Some("result".into());
        assert_eq!(project.annotations.len(), 2, "one address, two records");
        assert_eq!(
            project.annotation_for("0x1000").and_then(|a| a.name.as_deref()),
            Some("decode_frame"),
            "the address record is still the function's"
        );
        assert_eq!(project.register_name("0x1000", "rax").as_deref(), Some("result"));
        // A second spelling of the address finds the same register record.
        project.register_mut("0X1000", "rax").bookmark = true;
        assert_eq!(project.annotations.len(), 2);
        assert!(project.register_for("0x1000", "rax").is_some_and(|a| a.bookmark));
        // A register of another function keys apart, and so does a register
        // of the same function from another name.
        project.register_mut("0x2000", "rax").name = Some("total".into());
        assert_eq!(project.register_name("0x1000", "rax").as_deref(), Some("result"));
        assert_eq!(project.register_name("0x2000", "rax").as_deref(), Some("total"));
    }

    #[test]
    fn a_register_record_round_trips() {
        let mut project = ProjectFile::new(Target::default());
        project.register_mut("0x1000", "rax").name = Some("result".into());
        let text = project.to_json().expect("json");
        assert!(text.contains("\"register\": \"rax\""), "{text}");
        assert!(text.contains("\"kind\": \"register\""), "{text}");
        // A record that names no register writes no register field at all.
        assert_eq!(text.matches("\"register\":").count(), 1, "{text}");
        let read = ProjectFile::from_json(&text).expect("the text reads back");
        assert_eq!(read, project);
    }

    #[test]
    fn a_variable_and_a_register_of_the_same_name_keep_their_own_records() {
        // A pseudocode that names a local `rax` beside a renamed register
        // `rax` is unusual but legal: the two records key on different
        // fields and must not find one another.
        let mut project = ProjectFile::new(Target::default());
        project.variable_mut("0x1000", "rax").name = Some("count".into());
        project.register_mut("0x1000", "rax").name = Some("total".into());
        assert_eq!(project.annotations.len(), 2, "one name, two records");
        assert_eq!(
            project.variable_name("0x1000", "rax").as_deref(),
            Some("count"),
            "the variable record is the variable's"
        );
        assert_eq!(
            project.register_name("0x1000", "rax").as_deref(),
            Some("total"),
            "the register record is the register's"
        );
    }

    #[test]
    fn a_version_2_file_that_gains_a_register_is_written_as_3() {
        // A project written by the version that had variables but no
        // register records keeps its declared version across a load; once
        // the analyst renames a register, the file must name a version an
        // older reader refuses rather than one it would misread.
        let raw = r#"{"format": 2, "target": {}, "annotations": [
            {"kind": "variable", "address": "0x1000", "variable": "local_14", "name": "count"}
        ]}"#;
        let mut project = ProjectFile::from_json(raw).expect("a v2 file reads");
        assert_eq!(project.format, 2, "loading does not silently restamp");
        project.register_mut("0x1000", "rax").name = Some("result".into());
        let text = project.to_json().expect("json");
        assert!(text.contains("\"format\": 3"), "{text}");
        let read = ProjectFile::from_json(&text).expect("the text reads back");
        assert_eq!(read, project);
    }

    #[test]
    fn the_saved_file_is_readable_json() {
        let mut project = ProjectFile::new(Target::default());
        project
            .annotation_mut(TargetKind::Function, "0x1000")
            .bookmark = true;
        let text = project.to_json().expect("json");
        assert!(text.contains("\"format\": 3"), "{text}");
        assert!(text.contains("\"bookmark\": true"), "{text}");
        // An empty name is not written at all.
        assert!(!text.contains("\"name\""), "{text}");
    }
}
