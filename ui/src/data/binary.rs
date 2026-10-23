//! A [`Provider`] over a program image read by the engine.
//!
//! This is the native path: the file is parsed by the engine's own loader,
//! its code sections are decoded by the native decoder, and its control-flow
//! graph is walked by the engine. There is no lifter yet, so there is no
//! pseudocode — the workbench says so rather than showing an empty pane.

use std::path::Path;

use ag_image::Binary;
use anyhow::Result;

use crate::data::{
    AnalysisState, FunctionDetail, FunctionRow, HitKind, ListingLine, Problem, Provider, Reference,
    ReferenceKind, SearchHit, SectionCounts, SegmentEntry,
};
use crate::model::{Capabilities, Project, ProjectKind};

/// Reads a program image the engine loaded.
pub struct BinaryProvider {
    /// The image, read.
    binary: Binary,
    /// The project identity.
    project: Project,
    /// What the reader could not do, and why.
    warnings: Vec<String>,
}

impl BinaryProvider {
    /// Read the image in the file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let binary = Binary::open(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        let project = Project {
            name,
            kind: ProjectKind::Binary,
            root: Some(path.to_path_buf()),
            target_sha256: None,
            provider: "ag-engine".into(),
            architecture: Some(binary.language().to_string()),
            format: path
                .extension()
                .map(|extension| extension.to_string_lossy().to_uppercase()),
        };

        let mut warnings = Vec::new();
        if !binary.supports_disassembly() {
            warnings.push(format!(
                "The listing is off: the native decoder reads x86-64 and this image is {}.",
                binary.language()
            ));
        }

        Ok(Self {
            binary,
            project,
            warnings,
        })
    }

    /// The listing line of one instruction.
    ///
    /// A call to a function that has a symbol shows the symbol, the way a
    /// reader expects; a call to an address with no symbol shows the address.
    fn listing_line(instruction: &ag_image::Instruction) -> ListingLine {
        let operands = match instruction
            .call
            .as_ref()
            .and_then(|call| call.name.as_deref())
        {
            Some(name) => name.to_string(),
            None => instruction.operands.clone(),
        };

        ListingLine {
            address: instruction.address,
            bytes: instruction
                .bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            mnemonic: instruction.mnemonic.clone(),
            operands,
            comment: instruction.comment.clone(),
        }
    }
}

impl Provider for BinaryProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            listing: self.binary.supports_disassembly(),
            references: true,
            segments: true,
            ..Capabilities::NONE
        }
    }

    fn analysis_state(&self) -> AnalysisState {
        AnalysisState::Complete
    }

    fn functions(&self) -> Vec<FunctionRow> {
        self.binary
            .functions()
            .iter()
            .map(|function| FunctionRow {
                address: function.address,
                name: function.name.clone(),
                status: "Loaded".into(),
                size: None,
                objc: false,
            })
            .collect()
    }

    fn function_detail(&self, address: u64) -> Option<FunctionDetail> {
        let name = self.binary.function_name(address)?.to_string();
        let section = self
            .binary
            .sections()
            .iter()
            .find(|section| section.vma <= address && address < section.vma + section.size);

        let provenance = if section.is_some() {
            "Native decode".to_string()
        } else {
            "Symbol table".to_string()
        };

        let summary = match section {
            Some(section) if section.executable => {
                format!(
                    "Decoded from {} by the native x86-64 decoder.",
                    section.name
                )
            }
            Some(section) => format!("The symbol lives in {}.", section.name),
            None => "The symbol lives outside every section.".to_string(),
        };

        Some(FunctionDetail {
            name,
            status: "Loaded".into(),
            start: Some(address),
            end: section.map(|section| section.vma + section.size),
            provenance,
            summary,
        })
    }

    fn listing(&self, address: u64) -> Option<Vec<ListingLine>> {
        let disassembly = self.binary.disassembly(address)?;
        Some(
            disassembly
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .map(Self::listing_line)
                .collect(),
        )
    }

    fn pseudocode(&self, _address: u64) -> Option<String> {
        // There is no lifter yet, so there is no pseudocode to show.
        None
    }

    fn bytes(&self, _address: u64) -> Option<Vec<crate::data::ByteLine>> {
        None
    }

    fn references(&self, address: u64) -> Vec<Reference> {
        let mut references = Vec::new();

        // What the function calls.
        for call in self.binary.calls(address) {
            let label = call
                .name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", call.target));
            references.push(Reference {
                address: call.target,
                label,
                kind: ReferenceKind::Calls,
            });
        }

        // What calls the function.
        for caller in self.binary.called_by(address) {
            references.push(Reference {
                address: caller.address,
                label: caller.name,
                kind: ReferenceKind::CalledBy,
            });
        }

        references
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts {
            functions: self.binary.functions().len(),
            segments: self.binary.sections().len(),
            ..SectionCounts::default()
        }
    }

    fn segments(&self) -> Vec<SegmentEntry> {
        self.binary
            .sections()
            .iter()
            .map(|section| SegmentEntry {
                name: section.name.clone(),
                vma: section.vma,
                size: section.size,
                executable: section.executable,
            })
            .collect()
    }

    fn search(&self, query: &str, _deep: bool) -> Vec<SearchHit> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }

        self.binary
            .functions()
            .iter()
            .filter(|function| function.name.to_lowercase().contains(&needle))
            .map(|function| SearchHit {
                address: function.address,
                title: function.name.clone(),
                detail: "Function".into(),
                kind: HitKind::Function,
            })
            .collect()
    }

    fn problems(&self) -> Vec<Problem> {
        self.warnings
            .iter()
            .map(|warning| Problem {
                message: warning.clone(),
                address: None,
                action: Some("Open an x86-64 binary for a listing".into()),
            })
            .collect()
    }

    fn summary(&self) -> Option<crate::data::ProjectSummary> {
        let entry = self.binary.entry().map(|address| {
            let name = self
                .binary
                .function_name(address)
                .unwrap_or("entry")
                .to_string();
            (name, address)
        });

        let main = self
            .binary
            .functions()
            .iter()
            .find(|function| function.name == "main")
            .map(|function| (function.name.clone(), function.address));

        let code_bytes = self
            .binary
            .sections()
            .iter()
            .filter(|section| section.executable)
            .map(|section| section.size)
            .sum();

        Some(crate::data::ProjectSummary {
            entry,
            main,
            reachable: self.binary.reachable_from_entry().len(),
            no_callers: self.binary.functions_without_callers().len(),
            code_bytes,
            functions: self.binary.functions().len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::ReferenceKind;
    use crate::model::ProjectKind;
    use std::path::PathBuf;

    /// The address of `main` in the sample.
    const MAIN: u64 = 0x1198;

    /// The sample ELF the engine's own tests read.
    fn sample_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-engine/tests/fixtures/sample.elf")
    }

    /// The sample ELF, opened.
    fn sample() -> BinaryProvider {
        BinaryProvider::load(&sample_path()).expect("the sample ELF loads")
    }

    #[test]
    fn the_sample_opens_as_a_binary_project() {
        let provider = sample();

        let project = provider.project();
        assert_eq!(project.kind, ProjectKind::Binary);
        assert_eq!(project.name, "sample.elf");
        assert_eq!(
            project.architecture.as_deref(),
            Some("x86:LE:64:default:gcc"),
            "the language id is the project's architecture"
        );
    }

    #[test]
    fn the_listing_and_the_references_are_on_and_the_pseudocode_is_off() {
        let capabilities = sample().capabilities();

        assert!(capabilities.listing);
        assert!(capabilities.references);
        assert!(capabilities.segments);
        assert!(!capabilities.pseudocode, "there is no lifter yet");
    }

    #[test]
    fn the_functions_are_the_symbols_of_the_image() {
        let provider = sample();

        let rows = provider.functions();
        let names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();

        assert!(names.contains(&"main"), "{names:?}");
        assert!(names.contains(&"add"), "{names:?}");
    }

    #[test]
    fn the_listing_holds_the_instructions_of_the_function() {
        let provider = sample();

        let listing = provider.listing(MAIN).expect("main has a listing");
        assert!(!listing.is_empty());

        let first = &listing[0];
        assert_eq!(first.address, MAIN);
        assert!(!first.bytes.is_empty());
        assert!(!first.mnemonic.is_empty());

        // A call to a symbol shows the symbol, not the address.
        let call = listing
            .iter()
            .find(|line| line.mnemonic == "call")
            .expect("main calls something");
        assert!(
            call.operands == "add" || call.operands == "sum_to",
            "the call names its target: {call:?}"
        );
    }

    #[test]
    fn the_references_name_the_callees_and_the_callers() {
        let provider = sample();

        let references = provider.references(MAIN);

        let callees: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Calls)
            .map(|reference| reference.label.as_str())
            .collect();
        assert!(callees.contains(&"add"), "{callees:?}");
        assert!(callees.contains(&"sum_to"), "{callees:?}");

        // Nothing calls main in the sample.
        let callers: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::CalledBy)
            .map(|reference| reference.label.as_str())
            .collect();
        assert!(callers.is_empty(), "{callers:?}");
    }

    #[test]
    fn the_segments_are_the_sections_of_the_image() {
        let provider = sample();

        let segments = provider.segments();
        let text = segments
            .iter()
            .find(|segment| segment.name == ".text")
            .expect("a .text section");
        assert!(text.executable);

        let rodata = segments
            .iter()
            .find(|segment| segment.name == ".rodata")
            .expect("a .rodata section");
        assert!(!rodata.executable);

        assert_eq!(provider.counts().segments, segments.len());
    }

    #[test]
    fn the_entry_point_is_reported() {
        let provider = sample();

        let summary = provider.summary().expect("a summary");
        let (name, address) = summary.entry.expect("an entry point");
        assert_eq!(name, "_start");
        assert_eq!(address, 0x1060);
    }

    #[test]
    fn a_file_that_is_not_an_image_is_refused() {
        let result = BinaryProvider::load(Path::new("/tmp"));
        let error = match result {
            Ok(_) => panic!("a directory is not an image"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("reading"),
            "the error says what failed: {error}"
        );
    }
}
