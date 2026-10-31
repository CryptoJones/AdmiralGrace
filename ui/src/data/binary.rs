//! A [`Provider`] over a program image read by the engine.
//!
//! This is the native path: the file is parsed by the engine's own loader,
//! its code sections are decoded by the native decoder, and its control-flow
//! graph is walked by the engine, and its pseudocode is the engine's lifter's:
//! x86-64 code with calls, branches and loops reads as C — `if`/`else`,
//! `while`, `for`, early `return` — with every line mapped to the
//! instructions it came from. A function the lifter refuses has no body, and
//! the Problems panel says why.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ag_image::{Binary, Options};
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
    /// Read the image in the file at `path`, with the engine's defaults.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_options(path, Options::default())
    }

    /// Read the image in the file at `path`, lifting its functions under
    /// `options` (`--option NAME VALUE` on the command line).
    pub fn load_with_options(path: &Path, options: Options) -> Result<Self> {
        Self::load_with(path, options, &ag_image::Layout::default(), None, None)
    }

    /// Read the image in the file at `path` under the analyst's `layout`,
    /// lifting its functions under `options`; as raw bytes loaded as `raw`
    /// says, when it says.
    pub fn load_with(
        path: &Path,
        options: Options,
        layout: &ag_image::Layout,
        raw: Option<&ag_image::RawSpec>,
        slice: Option<&str>,
    ) -> Result<Self> {
        let binary = match (raw, slice) {
            (Some(spec), _) => Binary::open_raw_with_layout(path, spec, layout)?,
            (None, Some(slice)) => Binary::open_slice_with_layout(path, slice, layout)?,
            (None, None) => Binary::open_with_layout(path, layout)?,
        };
        let binary = Arc::new(binary.with_options(options));
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
                "The listing is off: the native decoder reads x86, 32-bit and 64-bit, and this image is {}.",
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
    /// A jump through a GOT slot keeps its operand: the slot is what the
    /// instruction names, and the import it holds is the reference's.
    fn listing_line(instruction: &ag_image::Instruction) -> ListingLine {
        // A direct call names one function, whether or not the analysis had
        // a symbol for it: the address is what the rename keys on, so the
        // line carries it and the view can replace the name.
        let call_target = instruction
            .call
            .as_ref()
            .filter(|call| call.slot.is_none())
            .map(|call| call.target);
        let operands = match instruction
            .call
            .as_ref()
            .filter(|call| call.slot.is_none())
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
            call_target,
            registers: instruction.registers.clone(),
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
            pseudocode: self.binary.supports_pseudocode(),
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
                space: None,
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
                mangled: self.binary.mangled_name(address).map(str::to_string),
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
                match self.binary.bitness() {
                    Some(width) => format!(
                        "Decoded from {} by the native {width} x86 decoder.",
                        section.name
                    ),
                    None => format!(
                        "Decoded from {} by the SLEIGH decoder, as {}.",
                        section.name,
                        self.binary.language()
                    ),
                }
            }
            Some(section) => format!("The symbol lives in {}.", section.name),
            None => "The symbol lives outside every section.".to_string(),
        };

        Some(FunctionDetail {
            name,
            status: "Loaded".into(),
            start: Some(address),
            // The unwind data knows where the function ends; failing that,
            // its section does.
            end: self
                .binary
                .function_end(address)
                .or_else(|| section.map(|section| section.vma + section.size)),
            provenance,
            mangled: self.binary.mangled_name(address).map(str::to_string),
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

    /// The pseudocode of a function the lifter reads.
    ///
    /// A function the lifter refuses has none; the reason is reported as a
    /// problem of the function instead.
    fn pseudocode(&self, address: u64) -> Option<String> {
        self.binary
            .pseudocode(address)
            .ok()
            .map(|pseudocode| pseudocode.text())
    }

    fn line_addresses(&self, address: u64) -> BTreeMap<usize, Vec<u64>> {
        self.binary
            .pseudocode(address)
            .ok()
            .map(|pseudocode| pseudocode.line_addresses())
            .unwrap_or_default()
    }

    fn bytes(&self, address: u64) -> Option<Vec<ByteLine>> {
        Some(self.byte_rows(address))
    }

    fn set_jump_table_hints(&self, hints: BTreeMap<u64, ag_image::JumpTableHint>) -> bool {
        self.binary.set_jump_table_hints(hints)
    }

    fn set_patches(&self, patches: BTreeMap<u64, Vec<u8>>) -> bool {
        self.binary.set_patches(patches)
    }

    fn bitness(&self) -> Option<ag_image::Bitness> {
        self.binary.bitness()
    }

    fn instruction_length_at(&self, address: u64) -> Option<usize> {
        self.binary.instruction_length_at(address)
    }

    fn base(&self) -> Option<u64> {
        self.binary.base()
    }

    fn mode_at(&self, address: u64) -> Option<String> {
        self.binary
            .mode_at(address)
            .map(|mode| mode.label().to_string())
    }

    fn set_modes(&self, modes: BTreeMap<u64, String>) -> bool {
        self.binary.set_modes(
            modes
                .into_iter()
                .filter_map(|(address, mode)| Some((address, ag_image::ArmMode::parse(&mode)?)))
                .collect(),
        )
    }

    fn section_end(&self, address: u64) -> Option<u64> {
        self.binary
            .section_of(address)
            .map(|section| section.vma.saturating_add(section.size))
    }

    fn write_patched(&self, out: &Path) -> Option<Result<usize, String>> {
        let source = self.project.root.as_ref()?;
        let write = || -> Result<usize, String> {
            let original = std::fs::read(source)
                .map_err(|error| format!("reading {}: {error}", source.display()))?;
            let written = self
                .binary
                .patched_file(&original)
                .map_err(|error| error.to_string())?;
            // The copy runs as the program does, and is whole or not there.
            ag_image::write_copy(source, out, &written)
                .map_err(|error| format!("writing {}: {error}", out.display()))?;
            Ok(written.len())
        };
        Some(write())
    }

    fn references(&self, address: u64) -> Vec<Reference> {
        let mut references = Vec::new();

        // What the function calls. This is known at once: it is the one
        // function's own disassembly. A tail call — the `jmp` a PLT stub or
        // a forwarding stub ends in — says so.
        for call in self.binary.calls(address) {
            let mut label = call
                .name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", call.target));
            if call.tail {
                label.push_str(" (tail call)");
            }
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

    fn objc_header(&self) -> Option<String> {
        self.binary.objc_header()
    }

    fn mangled_name(&self, address: u64) -> Option<String> {
        self.binary.mangled_name(address).map(str::to_string)
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
                    .as_ref()
                    .and_then(|users| users.get(&string.address).cloned())
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
                action: Some("Open an x86 binary for a listing".into()),
            })
            .collect()
    }

    /// Why the function has no pseudocode, when the lifter refused it.
    fn function_problems(&self, address: u64) -> Vec<Problem> {
        if !self.binary.supports_pseudocode() || self.binary.function_name(address).is_none() {
            return Vec::new();
        }

        match self.binary.pseudocode(address) {
            Ok(_) => Vec::new(),
            Err(error) => vec![Problem {
                message: format!("No pseudocode: {error}."),
                address: Some(address),
                action: Some(
                    "The lifter reads x86-64 code with the instructions it knows; the reason names what stopped it".into(),
                ),
            }],
        }
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

    /// The address of `sum_to` in the sample, which has a loop.
    const SUM_TO: u64 = 0x1161;

    /// The address of `_init` in the sample, which calls through a register.
    /// `register_tm_clones`: shifts right, which the lifter does not read.
    const REFUSED: u64 = 0x10c0;

    /// The address of the `printf` PLT stub in the sample: a thunk.
    const PRINTF: u64 = 0x1050;

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
    fn the_listing_the_references_and_the_pseudocode_are_on() {
        let capabilities = sample().capabilities();

        assert!(capabilities.listing);
        assert!(capabilities.references);
        assert!(capabilities.segments);
        assert!(capabilities.bytes, "the image holds its bytes");
        assert!(capabilities.pseudocode, "the lifter reads 64-bit x86");
    }

    #[test]
    fn the_pseudocode_of_add_is_c_with_its_lines_mapped() {
        let provider = sample();

        let body = provider.pseudocode(0x1149).expect("add lifts");
        assert_eq!(
            body,
            "// returns int: main reads eax after the call\n\
             int add(int a, int b)\n{\n  return b + a;\n}"
        );

        let lines = provider.line_addresses(0x1149);
        assert!(
            !lines.contains_key(&0),
            "the reason comment came from no instruction"
        );
        assert_eq!(
            lines.get(&1),
            Some(&vec![0x1149, 0x114d, 0x114e, 0x115f]),
            "the signature stands for the entry and the frame"
        );
        assert!(
            lines
                .get(&3)
                .is_some_and(|addresses| addresses.contains(&0x115d)),
            "the return came from the add: {lines:?}"
        );
        assert!(!lines.contains_key(&2), "a brace came from no instruction");

        assert!(provider.function_problems(0x1149).is_empty());
    }

    #[test]
    fn the_pseudocode_of_main_is_c_with_its_calls() {
        let provider = sample();

        let body = provider.pseudocode(MAIN).expect("main lifts");
        assert_eq!(
            body,
            "// returns long: no caller in the image, and the function writes rax itself before the ret\n\
             long main(int a, long b)\n\
             {\n\
             \x20 long v2;\n\
             \n\
             \x20 v2 = sum_to(add(a, 3));\n\
             \x20 printf(\"%ld\\n\", v2);\n\
             \x20 return v2;\n\
             }"
        );

        // The printf line is mapped to the call, so a click on it lands there.
        let lines = provider.line_addresses(MAIN);
        assert!(
            lines
                .get(&6)
                .is_some_and(|addresses| addresses.contains(&0x11e1)),
            "the printf came from the call: {lines:?}"
        );
        assert!(provider.function_problems(MAIN).is_empty());
    }

    #[test]
    fn an_engine_option_from_the_command_line_changes_the_pseudocode() {
        let options = Options::from_pairs([("loop-form", "while")]).expect("a known option");
        let provider =
            BinaryProvider::load_with_options(&sample_path(), options).expect("the sample loads");

        let body = provider.pseudocode(SUM_TO).expect("sum_to lifts");

        assert!(
            body.contains("  local_14 = 1;\n  while (local_14 <= a) {\n"),
            "{body}"
        );
        assert!(!body.contains("for ("), "{body}");
    }

    #[test]
    fn the_pseudocode_of_sum_to_is_a_for_loop_with_its_lines_mapped() {
        let provider = sample();

        let body = provider.pseudocode(SUM_TO).expect("sum_to lifts");
        assert_eq!(
            body,
            "// returns long: main reads rax after the call\n\
             long sum_to(int a)\n\
             {\n\
             \x20 long local_10;\n\
             \x20 int local_14;\n\
             \n\
             \x20 local_10 = 0;\n\
             \x20 for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {\n\
             \x20   local_10 = local_10 + (long)local_14;\n\
             \x20 }\n\
             \x20 return local_10;\n\
             }"
        );

        // The for line is mapped to the compare and the branch, the body to
        // the add, so a click on either lands in the loop.
        let lines = provider.line_addresses(SUM_TO);
        assert!(
            lines
                .get(&7)
                .is_some_and(|addresses| addresses.contains(&0x118d)),
            "the for came from the cmp: {lines:?}"
        );
        assert!(
            lines
                .get(&8)
                .is_some_and(|addresses| addresses.contains(&0x1182)),
            "the body came from the add: {lines:?}"
        );
        assert!(provider.function_problems(SUM_TO).is_empty());
    }

    #[test]
    fn a_function_the_lifter_refuses_has_no_body_and_a_problem_that_says_why() {
        let provider = sample();

        assert_eq!(provider.pseudocode(REFUSED), None);
        assert!(provider.line_addresses(REFUSED).is_empty());

        let problems = provider.function_problems(REFUSED);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(
            problems[0].message,
            "No pseudocode: not lifted yet: shr."
        );
        assert_eq!(problems[0].address, Some(REFUSED));
    }

    #[test]
    fn a_plt_stub_is_a_thunk_line_and_its_reference_is_a_tail_call() {
        let provider = sample();

        // printf@plt is endbr64; jmp [rip+slot]: no body of its own, so the
        // one line says what it stands for, and carries both instructions.
        assert_eq!(
            provider.pseudocode(PRINTF).as_deref(),
            Some("// thunk for printf")
        );
        assert_eq!(
            provider.line_addresses(PRINTF).get(&0),
            Some(&vec![0x1050, 0x1054])
        );
        assert!(provider.function_problems(PRINTF).is_empty());

        // The References tab names the import the stub jumps to, as a tail
        // call; the listing keeps the slot the jump reads.
        let references = provider.references(PRINTF);
        let calls: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Calls)
            .map(|reference| reference.label.as_str())
            .collect();
        assert_eq!(calls, vec!["printf (tail call)"]);
        let listing = provider.listing(PRINTF).expect("the stub has a listing");
        let jmp = listing
            .iter()
            .find(|line| line.address == 0x1054)
            .expect("the jmp");
        assert_eq!(jmp.operands, "jmp qword ptr [3FD0h]");

        // frame_dummy jumps to register_tm_clones by address, and the
        // listing names it.
        let listing = provider.listing(0x1140).expect("frame_dummy has a listing");
        let jmp = listing
            .iter()
            .find(|line| line.address == 0x1144)
            .expect("the jmp");
        assert_eq!(jmp.operands, "register_tm_clones");
        assert_eq!(
            provider.pseudocode(0x1140).as_deref(),
            Some("// thunk for register_tm_clones")
        );

        // The listing and the graph stop at the jump: frame_dummy is its two
        // instructions in one block, not register_tm_clones' blocks after it.
        let addresses: Vec<u64> = listing.iter().map(|line| line.address).collect();
        assert_eq!(addresses, vec![0x1140, 0x1144]);
        let graph = provider.graph(0x1140).expect("frame_dummy has a graph");
        assert_eq!(graph.blocks.len(), 1, "{graph:?}");
        assert!(graph.edges.is_empty(), "{:?}", graph.edges);
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
            Some(6),
            "only six of the twelve are called: five by a call, and register_tm_clones by frame_dummy's tail jump"
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

        // `deregister_tm_clones` reads the flag the C runtime sets when it
        // is done.
        let references = provider.references(0x1090);

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

        // Three: frame_dummy's read of the flag was register_tm_clones',
        // which it tail-calls, and the walk stops at the jump; _start ends
        // in hlt before deregister_tm_clones, and the walk stops there too.
        assert_eq!(users.len(), 3, "{users:?}");
        assert!(users.contains(&"deregister_tm_clones"), "{users:?}");
        assert!(!users.contains(&"_start"), "{users:?}");
        assert!(!users.contains(&"frame_dummy"), "{users:?}");
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

    /// The PE fixture the image tests read.
    fn pe_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-image/tests/fixtures/sample.exe")
    }

    /// The Mach-O fixture the image tests read.
    fn macho_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-image/tests/fixtures/sample.macho")
    }

    /// The PE fixture, opened.
    fn pe() -> BinaryProvider {
        BinaryProvider::load(&pe_path()).expect("the PE fixture loads")
    }

    /// The Mach-O fixture, opened.
    fn macho() -> BinaryProvider {
        BinaryProvider::load(&macho_path()).expect("the Mach-O fixture loads")
    }

    #[test]
    fn the_pe_opens_as_a_binary_project() {
        let provider = pe();

        let project = provider.project();
        assert_eq!(project.kind, ProjectKind::Binary);
        assert_eq!(project.name, "sample.exe");
        assert_eq!(
            project.architecture.as_deref(),
            Some("x86:LE:64:default:windows"),
            "the language id is the project's architecture"
        );
    }

    #[test]
    fn the_functions_of_the_pe_are_listed() {
        let provider = pe();

        let functions = provider.functions();
        let names: Vec<&str> = functions
            .iter()
            .map(|function| function.name.as_str())
            .collect();
        assert!(names.contains(&"add"), "{names:?}");
        assert!(names.contains(&"main"), "{names:?}");
    }

    #[test]
    fn the_add_of_the_pe_lifts_with_the_windows_argument_registers() {
        let provider = pe();

        let body = provider.pseudocode(0x140001000).expect("add lifts");
        assert_eq!(
            body,
            "// returns int: main reads eax after the call\n\
             int add(int a, int b)\n{\n  return a + b;\n}"
        );
    }

    #[test]
    fn the_main_of_the_pe_is_a_for_loop_over_add() {
        let provider = pe();

        let body = provider.pseudocode(0x140001020).expect("main lifts");
        assert!(
            body.contains("for (local_c = 0; local_c < 3; local_c = local_c + 1) {"),
            "{body}"
        );
        assert!(body.contains("local_8 = add(local_8, local_c);"), "{body}");
        assert!(provider.function_problems(0x140001020).is_empty());
    }

    #[test]
    fn the_listing_of_a_pe_function_is_read() {
        let provider = pe();

        let listing = provider.listing(0x140001020).expect("main is listed");
        assert!(!listing.is_empty(), "the listing is not empty");
    }

    #[test]
    fn the_strings_of_the_pe_are_listed() {
        let provider = pe();

        let strings = provider.strings();
        let hello = strings
            .iter()
            .find(|string| string.text == "hello")
            .expect("the greeting is in the image");
        assert_eq!(hello.section.as_deref(), Some(".rdata"));
    }

    /// The 32-bit ELF fixture the image tests read.
    fn elf32_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-image/tests/fixtures/sample32.elf")
    }

    /// The 32-bit ELF fixture, opened.
    fn elf32() -> BinaryProvider {
        BinaryProvider::load(&elf32_path()).expect("the 32-bit ELF fixture loads")
    }

    #[test]
    fn a_32_bit_elf_opens_as_a_binary_project_with_the_listing_on() {
        let provider = elf32();

        let project = provider.project();
        assert_eq!(project.kind, ProjectKind::Binary);
        assert_eq!(project.name, "sample32.elf");
        assert_eq!(
            project.architecture.as_deref(),
            Some("x86:LE:32:default:gcc"),
            "the language id is the project's architecture"
        );

        let capabilities = provider.capabilities();
        assert!(capabilities.listing, "32-bit x86 is decoded");
        assert!(capabilities.graph);
        assert!(capabilities.strings);
        assert!(
            !capabilities.pseudocode,
            "the lifter reads 64-bit code only"
        );
        assert!(
            provider.function_problems(0x8049000).is_empty(),
            "a tab that is off is not a problem of every function"
        );
        assert!(
            provider.problems().is_empty(),
            "nothing is off: {:?}",
            provider.problems()
        );
    }

    #[test]
    fn the_listing_of_a_32_bit_function_names_32_bit_registers() {
        let provider = elf32();

        let listing = provider.listing(0x8049000).expect("add is listed");
        let text: Vec<String> = listing
            .iter()
            .map(|line| {
                format!("{} {}", line.mnemonic, line.operands)
                    .trim_end()
                    .to_string()
            })
            .collect();
        assert_eq!(text[0], "push ebp", "{text:?}");
        assert_eq!(text[1], "mov ebp,esp", "{text:?}");
        assert!(
            text.iter().all(|line| !line.contains("rbp")),
            "no 64-bit register in 32-bit code: {text:?}"
        );

        let detail = provider
            .function_detail(0x8049000)
            .expect("add has a detail");
        assert!(
            detail.summary.contains("32-bit x86 decoder"),
            "the detail says the width: {}",
            detail.summary
        );
    }

    #[test]
    fn the_graph_and_the_references_of_a_32_bit_function_are_read() {
        let provider = elf32();

        let graph = provider.graph(0x804900d).expect("main has a graph");
        assert_eq!(graph.blocks.len(), 5, "{graph:?}");

        let references = provider.references(0x804900d);
        let calls: Vec<u64> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Calls)
            .map(|reference| reference.address)
            .collect();
        assert_eq!(calls, vec![0x8049000], "main calls add: {references:?}");

        let data: Vec<u64> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Data)
            .map(|reference| reference.address)
            .collect();
        assert_eq!(
            data,
            vec![0x804b008, 0x804b00c],
            "main reads counter and greeting: {references:?}"
        );

        let hello = provider
            .strings()
            .into_iter()
            .find(|string| string.text == "hello")
            .expect("the greeting is in the image");
        assert_eq!(hello.section.as_deref(), Some(".rodata"));
    }

    #[test]
    fn the_macho_opens_as_a_binary_project() {
        let provider = macho();

        let project = provider.project();
        assert_eq!(project.kind, ProjectKind::Binary);
        assert_eq!(project.name, "sample.macho");
        assert_eq!(
            project.architecture.as_deref(),
            Some("x86:LE:64:default:gcc"),
            "the language id is the project's architecture"
        );
    }

    #[test]
    fn the_functions_of_the_macho_are_listed() {
        let provider = macho();

        let functions = provider.functions();
        let names: Vec<&str> = functions
            .iter()
            .map(|function| function.name.as_str())
            .collect();
        // A Mach-O names its symbols with a leading underscore.
        assert!(names.contains(&"_add"), "{names:?}");
        assert!(names.contains(&"_main"), "{names:?}");
    }

    #[test]
    fn the_add_of_the_macho_lifts_to_c() {
        let provider = macho();

        let body = provider.pseudocode(0x100000420).expect("_add lifts");
        assert_eq!(
            body,
            "// returns int: _main reads eax after the call\n\
             int _add(int a, int b)\n{\n  return a + b;\n}"
        );
    }

    #[test]
    fn the_main_of_the_macho_is_a_for_loop_over_add() {
        let provider = macho();

        let body = provider.pseudocode(0x100000440).expect("_main lifts");
        assert!(
            body.contains("for (local_14 = 0; local_14 < 3; local_14 = local_14 + 1) {"),
            "{body}"
        );
        assert!(
            body.contains("local_10 = _add(local_10, local_14);"),
            "{body}"
        );
    }

    #[test]
    fn the_listing_of_a_macho_function_is_read() {
        let provider = macho();

        let listing = provider.listing(0x100000440).expect("main is listed");
        assert!(!listing.is_empty(), "the listing is not empty");
    }

    #[test]
    fn the_strings_of_the_macho_are_listed() {
        let provider = macho();

        let strings = provider.strings();
        let hello = strings
            .iter()
            .find(|string| string.text == "hello")
            .expect("the greeting is in the image");
        assert_eq!(hello.section.as_deref(), Some("__cstring"));
    }
}
