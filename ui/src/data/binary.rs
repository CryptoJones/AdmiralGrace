//! A [`Provider`] over a program image read by the engine.
//!
//! This is the native path: the file is parsed by the engine's own loader,
//! its code sections are decoded by the native decoder, and its control-flow
//! graph is walked by the engine. There is no lifter yet, so there is no
//! pseudocode — the workbench says so rather than showing an empty pane.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ag_image::Binary;
use anyhow::Result;

use crate::data::{
    AnalysisState, ByteLine, DataSymbolEntry, FunctionDetail, FunctionRow, Graph, GraphBlock,
    HitKind, ListingLine, Problem, Provider, Reference, ReferenceKind, SearchHit, SectionCounts,
    SegmentEntry, StringEntry,
};
use crate::model::{Capabilities, Project, ProjectKind};

/// Reads a program image the engine loaded.
pub struct BinaryProvider {
    /// The image, read.
    binary: Arc<Binary>,
    /// The project identity.
    project: Project,
    /// What the reader could not do, and why.
    warnings: Vec<String>,
    /// Whether the calls between the functions have been worked out.
    ///
    /// The callers of a function are only known once the whole program has
    /// been read, so they arrive after the project opens.
    indexed: AtomicBool,
}

impl BinaryProvider {
    /// Read the image in the file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let binary = Arc::new(Binary::open(path)?);
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
            indexed: AtomicBool::new(false),
        })
    }

    /// The image itself, so that the work it needs can be done off the UI
    /// thread.
    pub fn binary(&self) -> Arc<Binary> {
        Arc::clone(&self.binary)
    }

    /// Whether the calls between the functions have been worked out.
    fn indexed(&self) -> bool {
        self.indexed.load(Ordering::Relaxed)
    }

    /// The functions that use the data at `address`.
    ///
    /// Which functions use a piece of data needs the whole program read, so
    /// nothing is known until the index has landed. An address that is not
    /// data at all names no users.
    fn data_users_of(&self, address: u64) -> Vec<u64> {
        if self.binary.data_section(address).is_none() {
            return Vec::new();
        }

        let Some(users) = self.binary.data_users_ready() else {
            return Vec::new();
        };

        // The symbol that holds the data is the one that is filed under it.
        let key = self
            .binary
            .data_symbol(address)
            .map(|symbol| symbol.address)
            .unwrap_or(address);

        users.get(&key).cloned().unwrap_or_default()
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

    /// The rows of a hex dump centred on an address.
    ///
    /// The dump holds eight rows of sixteen bytes with the address in the
    /// middle of it, and it stops at the end of the section the address is
    /// in: the bytes of a section are the bytes of the file, and the file
    /// holds one copy of them.
    fn byte_rows(&self, address: u64) -> Vec<ByteLine> {
        /// The bytes of one row.
        const ROW: u64 = 16;
        /// The rows of the dump.
        const ROWS: u64 = 8;

        let Some(section) = self.binary.section_of(address) else {
            return Vec::new();
        };

        let row = address / ROW;
        let section_row = section.vma / ROW;
        let above = (ROWS / 2).min(row.saturating_sub(section_row));
        let first = row - above;

        let mut rows = Vec::new();
        for index in 0..ROWS {
            let start = (first + index) * ROW;
            if start >= section.vma.saturating_add(section.size) {
                break;
            }

            let Some(bytes) = self.binary.bytes_at(start, ROW as usize) else {
                // The section has no bytes in the file here, so there is
                // nothing to show for this row.
                continue;
            };

            rows.push(ByteLine {
                address: start,
                bytes,
            });
        }

        rows
    }
}

impl Provider for BinaryProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            listing: self.binary.supports_disassembly(),
            graph: self.binary.supports_disassembly(),
            references: true,
            segments: true,
            bytes: true,
            strings: true,
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
        let section = self.binary.section_of(address);

        // A named piece of data is not a function, but the reader still wants
        // to know what the selection is.
        let Some(name) = self.binary.function_name(address) else {
            let symbol = self
                .binary
                .data_symbols()
                .iter()
                .find(|symbol| symbol.address == address)?;

            return Some(FunctionDetail {
                name: symbol.name.clone(),
                status: "Loaded".into(),
                start: Some(address),
                end: Some(address + symbol.size),
                provenance: "Symbol table".to_string(),
                summary: match section {
                    Some(section) => format!("The symbol lives in {}.", section.name),
                    None => "The symbol lives outside every section.".to_string(),
                },
            });
        };

        let name = name.to_string();

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

    /// The control-flow graph of a function.
    ///
    /// The engine's walk already cut the function into blocks, so the
    /// blocks come back with their successors attached, and the edges
    /// between them come with the kind each edge has.
    fn graph(&self, address: u64) -> Option<Graph> {
        let graph = self.binary.control_flow(address)?;

        Some(Graph {
            blocks: graph
                .blocks
                .iter()
                .map(|block| GraphBlock {
                    from: block.from,
                    to: block.to,
                    successors: block.successors.clone(),
                    instructions: block.instructions.iter().map(Self::listing_line).collect(),
                })
                .collect(),
            edges: graph.edges.clone(),
        })
    }

    fn pseudocode(&self, _address: u64) -> Option<String> {
        // There is no lifter yet, so there is no pseudocode to show.
        None
    }

    fn bytes(&self, address: u64) -> Option<Vec<ByteLine>> {
        Some(self.byte_rows(address))
    }

    fn references(&self, address: u64) -> Vec<Reference> {
        let mut references = Vec::new();

        // What the function calls. This is known at once: it is the one
        // function's own disassembly.
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

        // What calls the function. This is only known once the whole program
        // has been read, so it is empty until the index has landed.
        if self.indexed() {
            for caller in self.binary.called_by(address) {
                references.push(Reference {
                    address: caller.address,
                    label: caller.name,
                    kind: ReferenceKind::CalledBy,
                });
            }
        }

        // The strings the function names. This is the function's own
        // disassembly, so it is known at once.
        for string in self.binary.string_references(address) {
            references.push(Reference {
                address: string.address,
                label: string.text,
                kind: ReferenceKind::String,
            });
        }

        // The data the function names. This is the function's own
        // disassembly too, so it is known at once.
        for data in self.binary.data_references(address) {
            let label = data
                .name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", data.address));
            references.push(Reference {
                address: data.address,
                label,
                kind: ReferenceKind::Data,
            });
        }

        // The functions that use the data at the address. This is only known
        // once the whole program has been read, so it is empty until the
        // index has landed.
        for user in self.data_users_of(address) {
            references.push(Reference {
                address: user,
                label: self
                    .binary
                    .function_name(user)
                    .unwrap_or("entry")
                    .to_string(),
                kind: ReferenceKind::UsedBy,
            });
        }

        references
    }

    fn references_pending(&self) -> bool {
        !self.indexed()
    }

    fn mark_references_ready(&self) {
        self.indexed.store(true, Ordering::Relaxed);
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts {
            functions: self.binary.functions().len(),
            segments: self.binary.sections().len(),
            strings: self.binary.strings().len(),
            ..SectionCounts::default()
        }
    }

    fn strings(&self) -> Vec<StringEntry> {
        // Which functions use a string is only known once the whole program
        // has been read, so the strings carry no users until then.
        let users = self.binary.string_users_ready();

        self.binary
            .strings()
            .iter()
            .map(|string| StringEntry {
                address: string.address,
                text: string.text.clone(),
                section: Some(string.section.clone()),
                functions: users
                    .and_then(|users| users.get(&string.address))
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect()
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
                mapped: section.vma != 0,
            })
            .collect()
    }

    fn data_symbols(&self) -> Vec<DataSymbolEntry> {
        self.binary
            .data_symbols()
            .iter()
            .map(|symbol| DataSymbolEntry {
                address: symbol.address,
                name: symbol.name.clone(),
                size: Some(symbol.size),
                section: self
                    .binary
                    .section_of(symbol.address)
                    .map(|section| section.name.clone()),
            })
            .collect()
    }

    fn search(&self, query: &str, _deep: bool) -> Vec<SearchHit> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }

        let mut hits: Vec<SearchHit> = self
            .binary
            .functions()
            .iter()
            .filter(|function| function.name.to_lowercase().contains(&needle))
            .map(|function| SearchHit {
                address: function.address,
                title: function.name.clone(),
                detail: "Function".into(),
                kind: HitKind::Function,
            })
            .collect();

        // The named data of the image is worth finding too: a search that
        // names a symbol should lead to its bytes.
        hits.extend(
            self.binary
                .data_symbols()
                .iter()
                .filter(|symbol| symbol.name.to_lowercase().contains(&needle))
                .map(|symbol| SearchHit {
                    address: symbol.address,
                    title: symbol.name.clone(),
                    detail: "Data".into(),
                    kind: HitKind::Data,
                }),
        );

        hits.extend(
            self.binary
                .strings()
                .iter()
                .filter(|string| string.text.to_lowercase().contains(&needle))
                .map(|string| SearchHit {
                    address: string.address,
                    title: string.text.clone(),
                    detail: string.section.clone(),
                    kind: HitKind::String,
                }),
        );

        hits
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
            // The two numbers that need the whole program read are not known
            // until the index has been worked out.
            reachable: self
                .indexed()
                .then(|| self.binary.reachable_from_entry().len()),
            no_callers: self
                .indexed()
                .then(|| self.binary.functions_without_callers().len()),
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
        assert!(capabilities.bytes, "the image holds its bytes");
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
    fn the_graph_carries_the_edges_with_their_kinds() {
        let provider = sample();

        let graph = provider.graph(0x1000).expect("_init has a graph");

        // The edges are the ones the engine's walk found, and each carries
        // the kind the shared rule gives it.
        let flow = provider.binary.control_flow(0x1000).expect("_init walks");

        assert_eq!(graph.edges, flow.edges);

        let kind = |to: u64| {
            graph
                .edges
                .iter()
                .find(|edge| edge.from == 0x1000 && edge.to == to)
                .map(|edge| edge.kind)
        };

        assert_eq!(kind(0x1014), Some(ag_image::EdgeKind::Fallthrough));
        assert_eq!(kind(0x1016), Some(ag_image::EdgeKind::Taken));
    }

    #[test]
    fn the_references_name_the_callees_and_the_callers() {
        let provider = sample();
        provider.mark_references_ready();

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
    fn the_callers_of_a_function_arrive_with_the_index() {
        let provider = sample();

        // Before the index lands, only what the function itself calls is
        // known: who calls it needs the whole program read.
        let before = provider.references(0x1149);
        assert!(
            before
                .iter()
                .all(|reference| reference.kind == ReferenceKind::Calls),
            "the callers are not known yet: {before:?}"
        );

        provider.mark_references_ready();

        let after = provider.references(0x1149);
        let callers: Vec<&str> = after
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::CalledBy)
            .map(|reference| reference.label.as_str())
            .collect();
        assert!(callers.contains(&"main"), "{callers:?}");
    }

    #[test]
    fn the_references_are_pending_until_the_index_has_landed() {
        let provider = sample();

        assert!(provider.references_pending(), "the index has not landed");

        provider.mark_references_ready();

        assert!(!provider.references_pending(), "the index has landed");
    }

    #[test]
    fn the_summary_waits_for_the_index_before_it_counts_the_callers() {
        let provider = sample();

        let pending = provider.summary().expect("a summary");
        assert_eq!(
            pending.reachable, None,
            "the reachable count is not known yet"
        );
        assert_eq!(
            pending.no_callers, None,
            "the caller count is not known yet"
        );
        assert_eq!(pending.functions, 12, "the function count is known at once");

        provider.mark_references_ready();

        let ready = provider.summary().expect("a summary");
        assert_eq!(
            ready.reachable,
            Some(0),
            "nothing is reached by a direct call"
        );
        assert_eq!(
            ready.no_callers,
            Some(7),
            "only five of the twelve are called"
        );
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

    #[test]
    fn the_bytes_are_the_rows_around_the_selection() {
        let provider = sample();

        let rows = provider.bytes(MAIN).expect("the image has bytes");

        assert_eq!(rows.len(), 8, "the dump holds eight rows");
        assert!(
            rows.iter().all(|row| row.bytes.len() == 16),
            "sixteen bytes to a row: {rows:?}"
        );

        // The address is in the middle of the dump.
        let index = rows
            .iter()
            .position(|row| row.address <= MAIN && MAIN < row.address + 16)
            .expect("the address is in the dump");
        assert_eq!(index, 4, "the address is in the middle: {rows:?}");
    }

    #[test]
    fn the_bytes_stop_at_the_end_of_the_section() {
        let provider = sample();

        // .text runs to 0x11ec, so the dump of its last bytes is short.
        let rows = provider.bytes(0x11e8).expect("the image has bytes");

        assert_eq!(rows.len(), 5, "the dump stops at the section: {rows:?}");
        let last = rows.last().expect("a last row");
        assert_eq!(last.address, 0x11e0);
        assert_eq!(last.bytes.len(), 12, "the section holds twelve more");
    }

    #[test]
    fn a_symbol_that_lives_only_in_memory_has_no_bytes() {
        let provider = sample();

        // .bss is at 0x4010 and the file holds nothing for it.
        let rows = provider.bytes(0x4010).expect("the image has a dump");

        assert!(rows.is_empty(), "there are no bytes to show: {rows:?}");
    }

    #[test]
    fn the_named_data_of_the_image_is_listed() {
        let provider = sample();

        let symbols = provider.data_symbols();
        let names: Vec<&str> = symbols.iter().map(|symbol| symbol.name.as_str()).collect();

        assert!(names.contains(&"completed.0"), "{names:?}");

        let symbol = symbols
            .iter()
            .find(|symbol| symbol.name == "completed.0")
            .expect("the symbol");
        assert_eq!(symbol.address, 0x4010);
        assert_eq!(symbol.section.as_deref(), Some(".bss"));
    }

    #[test]
    fn the_search_finds_the_named_data_as_well_as_the_functions() {
        let provider = sample();

        let hits = provider.search("completed", false);
        assert!(
            hits.iter().any(|hit| hit.kind == HitKind::Data),
            "the named data is found: {hits:?}"
        );

        let hits = provider.search("main", false);
        assert!(
            hits.iter().any(|hit| hit.kind == HitKind::Function),
            "the function is found: {hits:?}"
        );
    }

    #[test]
    fn the_detail_of_a_data_symbol_says_what_it_is() {
        let provider = sample();

        let detail = provider.function_detail(0x4010).expect("a detail");
        assert_eq!(detail.name, "completed.0");
        assert_eq!(detail.provenance, "Symbol table");
    }

    #[test]
    fn the_strings_of_the_image_are_listed() {
        let provider = sample();

        let strings = provider.strings();
        assert!(!strings.is_empty(), "the sample holds strings");

        let format = strings
            .iter()
            .find(|string| string.text == "%ld\\n")
            .expect("the format string of the sample");
        assert_eq!(format.address, 0x2004);
        assert_eq!(format.section.as_deref(), Some(".rodata"));
    }

    #[test]
    fn the_functions_that_use_a_string_are_named_once_the_index_has_landed() {
        let provider = sample();

        // Before the index lands, no string knows who uses it.
        let before = provider.strings();
        let format = before
            .iter()
            .find(|string| string.address == 0x2004)
            .expect("the format string");
        assert!(format.functions.is_empty(), "{format:?}");

        // The index is worked out off the UI thread; here it is done by hand.
        let _ = provider.binary().string_users();
        provider.mark_references_ready();

        let after = provider.strings();
        let format = after
            .iter()
            .find(|string| string.address == 0x2004)
            .expect("the format string");
        assert_eq!(format.functions, &[MAIN], "main uses the format string");
    }

    #[test]
    fn the_references_of_a_function_name_the_strings_it_uses() {
        let provider = sample();

        let references = provider.references(MAIN);

        let strings: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::String)
            .map(|reference| reference.label.as_str())
            .collect();
        assert_eq!(strings, vec!["%ld\\n"], "{references:?}");
    }

    #[test]
    fn the_references_of_a_function_name_the_data_it_uses() {
        let provider = sample();

        // `_start` reads the flag the C runtime sets when it is done.
        let references = provider.references(0x1060);

        let data: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Data)
            .map(|reference| reference.label.as_str())
            .collect();

        assert!(
            data.contains(&"completed.0"),
            "the data of the function is named: {references:?}"
        );
    }

    #[test]
    fn the_users_of_a_piece_of_data_arrive_with_the_index() {
        let provider = sample();

        // Who uses a piece of data needs the whole program read, so nothing
        // is known about it before the index has landed.
        let before = provider.references(0x4010);
        assert!(
            before
                .iter()
                .all(|reference| reference.kind != ReferenceKind::UsedBy),
            "the users are not known yet: {before:?}"
        );

        let _ = provider.binary().data_users();

        let after = provider.references(0x4010);

        let users: Vec<&str> = after
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::UsedBy)
            .map(|reference| reference.label.as_str())
            .collect();

        assert_eq!(users.len(), 5, "{users:?}");
        assert!(users.contains(&"_start"), "{users:?}");
    }

    #[test]
    fn a_function_is_not_the_data_it_holds() {
        let provider = sample();

        // The address of a function is in a section that holds code, so it
        // names no data and no users.
        let references = provider.references(MAIN);

        assert!(
            references
                .iter()
                .all(|reference| reference.kind != ReferenceKind::UsedBy),
            "{references:?}"
        );
    }

    #[test]
    fn the_search_finds_the_strings_as_well_as_the_functions() {
        let provider = sample();

        let hits = provider.search("printf", false);

        let strings: Vec<u64> = hits
            .iter()
            .filter(|hit| hit.kind == HitKind::String)
            .map(|hit| hit.address)
            .collect();
        assert!(strings.contains(&0x4a2), "{hits:?}");
    }

    #[test]
    fn the_strings_are_on_and_they_are_counted() {
        let provider = sample();

        assert!(provider.capabilities().strings);
        assert_eq!(provider.counts().strings, provider.strings().len());
    }
}
