//! A reader for a [kuna](https://github.com/Noelo-Lab/kuna) project export.
//!
//! `kuna decompile-project <binary> -o <dir>` writes a folder of four
//! artifacts:
//!
//! - `<name>.c` — every decompiled function under a `// Function: <name> @
//!   <addr>` header, failures as comments.
//! - `<name>.h` — prototypes plus the recovered type block.
//! - `<name>.asm` — labeled linear disassembly of every CODE section.
//! - `index.jsonl` — one record per function, giving the exact byte span of
//!   that function's block in the `.c`.
//!
//! A streamed export (`.streaming` present) writes the `.c` in decompile
//! order rather than address order, so every lookup resolves through the
//! index rather than through a position in the file. An export without an
//! index is address-ordered, and its `// Function:` headers carry the same
//! information, so both layouts are read the same way.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The index file a kuna export writes.
pub const INDEX_FILE: &str = "index.jsonl";

/// The marker file a streaming export carries while it runs.
pub const STREAMING_FILE: &str = ".streaming";

/// One record of `index.jsonl`.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexRecord {
    /// Position in write order.
    pub seq: u64,
    /// The function's name.
    pub name: String,
    /// The function's display address, as a `0x…` string.
    pub addr: String,
    /// The inventory extent in bytes; `0` when unknown.
    pub size: u64,
    /// The block's byte offset in the `.c`.
    pub c_offset: u64,
    /// The block's byte length in the `.c`.
    pub c_len: u64,
    /// The function's error, when it failed.
    pub error: Option<String>,
}

/// A function recorded by a kuna export.
#[derive(Debug, Clone)]
pub struct KunaFunction {
    /// The function's name.
    pub name: String,
    /// The function's address.
    pub address: u64,
    /// The function's extent in bytes, when known.
    pub size: Option<u64>,
    /// The block's byte offset in the `.c`.
    pub c_offset: u64,
    /// The block's byte length in the `.c`.
    pub c_len: u64,
    /// The function's error, when it failed.
    pub error: Option<String>,
}

/// One instruction of a kuna listing.
#[derive(Debug, Clone)]
pub struct KunaListingLine {
    /// Address of the instruction.
    pub address: u64,
    /// Encoded bytes, hex formatted.
    pub bytes: String,
    /// Mnemonic.
    pub mnemonic: String,
    /// Operand text.
    pub operands: String,
}

/// A function's listing, as sliced out of a `.asm`.
#[derive(Debug, Clone, Default)]
pub struct KunaListing {
    /// The function's instructions.
    pub lines: Vec<KunaListingLine>,
    /// The function's `; arg:` and `; stack:` notes.
    pub variables: Vec<String>,
}

/// A kuna project export, read from disk.
pub struct KunaExport {
    /// The export directory.
    pub root: PathBuf,
    /// The export's base name, shared by the `.c`, `.h` and `.asm` files.
    pub name: String,
    /// The `.c` file.
    pub c_path: PathBuf,
    /// The `.h` file, when the export has one.
    pub h_path: Option<PathBuf>,
    /// The `.asm` file, when the export has one.
    pub asm_path: Option<PathBuf>,
    /// Whether the export is still being written.
    pub streaming: bool,
    /// The binary the export was made from, as its README records it.
    pub binary: Option<PathBuf>,
    /// Every function the export records.
    pub functions: Vec<KunaFunction>,
    /// Function indexes by address.
    pub by_address: BTreeMap<u64, usize>,
    /// Function indexes by name.
    pub by_name: BTreeMap<String, Vec<usize>>,
    /// The `.c` file's text, read once.
    ///
    /// A function's body is a slice of this file, so holding the text turns
    /// every lookup into a slice instead of another read of the whole file.
    c_text: String,
    /// The `.asm` file's text, read once, for the same reason.
    asm_text: Option<String>,
}

impl KunaExport {
    /// Read the export in `root`.
    pub fn load(root: &Path) -> Result<KunaExport> {
        let c_path =
            c_file(root).with_context(|| format!("no kuna `.c` file in {}", root.display()))?;
        let name = c_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_string())
            .unwrap_or_default();
        let sibling = |suffix: &str| {
            let path = root.join(format!("{name}.{suffix}"));
            path.is_file().then_some(path)
        };

        let h_path = sibling("h");
        let asm_path = sibling("asm");

        let c_text =
            fs::read_to_string(&c_path).with_context(|| format!("reading {}", c_path.display()))?;
        let asm_text = asm_path
            .as_ref()
            .map(fs::read_to_string)
            .transpose()
            .with_context(|| {
                format!(
                    "reading {}",
                    asm_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default()
                )
            })?;

        let functions = read_functions(root, &c_text)?;
        let mut by_address = BTreeMap::new();
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, function) in functions.iter().enumerate() {
            by_address.entry(function.address).or_insert(index);
            by_name
                .entry(function.name.clone())
                .or_default()
                .push(index);
        }

        Ok(KunaExport {
            root: root.to_path_buf(),
            name,
            c_path,
            h_path,
            asm_path,
            streaming: root.join(STREAMING_FILE).is_file(),
            binary: readme_binary(root),
            functions,
            by_address,
            by_name,
            c_text,
            asm_text,
        })
    }

    /// The function at `address`, when the export has one.
    pub fn function(&self, address: u64) -> Option<&KunaFunction> {
        let index = *self.by_address.get(&address)?;
        self.functions.get(index)
    }

    /// The decompiled body of `function`, without its `// Function:` header.
    ///
    /// A function that failed has a comment block rather than a body, and
    /// yields `None`.
    pub fn function_body(&self, function: &KunaFunction) -> Result<Option<String>> {
        if function.error.is_some() {
            return Ok(None);
        }

        let start = usize::try_from(function.c_offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(function.c_len).unwrap_or(usize::MAX));
        let block = self.c_text.get(start..end).ok_or_else(|| {
            anyhow::anyhow!(
                "function block {}+{} is outside {}",
                function.c_offset,
                function.c_len,
                self.c_path.display()
            )
        })?;

        Ok(Some(strip_header(block)))
    }

    /// The listing of `function`, sliced out of the `.asm` by its label.
    ///
    /// The instructions and the `; arg:` / `; stack:` notes are collected from
    /// wherever the export keeps them: a plain export writes the notes under
    /// the label, a streamed export moves them to a `; --- variables ---`
    /// section at the end of the file.
    pub fn function_listing(&self, function: &KunaFunction) -> Result<Option<KunaListing>> {
        let Some(asm) = &self.asm_text else {
            return Ok(None);
        };
        Ok(Some(slice_listing(asm, &function.name, function.address)))
    }
}

/// Whether `root` holds a kuna project export.
pub fn is_kuna_export(root: &Path) -> bool {
    c_file(root).is_some()
}

/// The export's `.c` file, when the directory holds one.
fn c_file(root: &Path) -> Option<PathBuf> {
    let mut found: Option<PathBuf> = None;

    for entry in fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("c") {
            continue;
        }
        if found.is_some() {
            // An export holds exactly one `.c`; two means this is something
            // else, and guessing would open the wrong file.
            return None;
        }
        found = Some(path);
    }

    found
}

/// Every function the export records, in index order when there is an index.
fn read_functions(root: &Path, c_text: &str) -> Result<Vec<KunaFunction>> {
    let index = root.join(INDEX_FILE);
    if index.is_file() {
        return read_index(&index);
    }
    Ok(read_headers(c_text))
}

/// Read `index.jsonl`, one record per line.
fn read_index(path: &Path) -> Result<Vec<KunaFunction>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut functions = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A torn final line is a reader's problem, not the export's: the
        // record is written after its block is whole, so a partial line is a
        // write in flight.
        let Ok(record) = serde_json::from_str::<IndexRecord>(line) else {
            continue;
        };
        functions.push(to_function(record));
    }

    Ok(functions)
}

/// Turn an index record into a function.
fn to_function(record: IndexRecord) -> KunaFunction {
    let address = parse_address(&record.addr);
    KunaFunction {
        name: record.name,
        address,
        size: (record.size > 0).then_some(record.size),
        c_offset: record.c_offset,
        c_len: record.c_len,
        error: record.error,
    }
}

/// Read the `// Function:` headers of a `.c` that carries no index.
fn read_headers(text: &str) -> Vec<KunaFunction> {
    let mut functions = Vec::new();

    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if let Some(header) = trimmed.strip_prefix("// Function: ") {
            let (name, address, error) = parse_header(header);
            functions.push(KunaFunction {
                name,
                address,
                size: None,
                c_offset: offset as u64,
                c_len: 0,
                error,
            });
        }
        offset += line.len();
    }

    // Without an index the block lengths are unknown, so each block runs to
    // the next header.
    let total = text.len() as u64;
    let offsets: Vec<u64> = functions.iter().map(|function| function.c_offset).collect();
    for (index, function) in functions.iter_mut().enumerate() {
        let end = offsets.get(index + 1).copied().unwrap_or(total);
        function.c_len = end.saturating_sub(function.c_offset);
    }

    functions
}

/// The binary the export was made from, as the export's README records it.
///
/// The README's binary table has a `| Path | … |` row, and the path it names
/// is the only thing that lets the kuna CLI answer questions the export
/// itself cannot.
fn readme_binary(root: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(root.join("README.md")).ok()?;

    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("| Path |") else {
            continue;
        };
        let value = rest.split('|').next().unwrap_or_default().trim();
        let value = value.trim_matches('`').trim();
        if value.is_empty() {
            continue;
        }
        return Some(PathBuf::from(value));
    }

    None
}

/// Parse the `name @ 0xaddr` part of a `// Function:` header.
fn parse_header(header: &str) -> (String, u64, Option<String>) {
    let (head, error) = match header.split_once("  (error: ") {
        Some((head, error)) => (head, Some(error.trim_end_matches(')').to_string())),
        None => (header, None),
    };

    match head.rsplit_once(" @ ") {
        Some((name, address)) => (
            name.trim().to_string(),
            parse_address(address.trim()),
            error,
        ),
        None => (head.trim().to_string(), 0, error),
    }
}

/// Parse a `0x…` address.
fn parse_address(text: &str) -> u64 {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(digits, 16).unwrap_or(0)
}

/// Drop the leading `// Function: …` header from a block.
fn strip_header(block: &str) -> String {
    match block.split_once('\n') {
        Some((first, rest)) if first.trim_start().starts_with("// Function:") => {
            rest.trim_end().to_string()
        }
        _ => block.trim_end().to_string(),
    }
}

/// One label block of a `.asm`.
struct AsmBlock {
    /// The label's name.
    name: String,
    /// The label's address.
    address: u64,
    /// The instructions under the label.
    lines: Vec<KunaListingLine>,
    /// The `; arg:` and `; stack:` notes under the label.
    variables: Vec<String>,
}

/// The section of a `.asm` that is being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsmSection {
    /// Instructions, in `; --- code section … ---` blocks.
    Code,
    /// The `; arg:` and `; stack:` notes, in a `; --- variables ---` section.
    Variables,
    /// Named globals and strings, which are not instructions.
    Data,
}

/// Slice the listing of `name` at `address` out of an `.asm` file.
///
/// The `.asm` labels match the `.c` function names, so the label is found by
/// name and confirmed by address; a label that carries neither match is not
/// this function's.
fn slice_listing(asm: &str, name: &str, address: u64) -> KunaListing {
    let mut listing = KunaListing::default();

    for block in asm_blocks(asm) {
        if block.name != name || block.address != address {
            continue;
        }
        listing.lines.extend(block.lines);
        listing.variables.extend(block.variables);
    }

    listing
}

/// Every labeled block of an `.asm`, in file order.
fn asm_blocks(asm: &str) -> Vec<AsmBlock> {
    let mut blocks: Vec<AsmBlock> = Vec::new();
    let mut section = AsmSection::Code;
    let mut open: Option<AsmBlock> = None;

    for line in asm.lines() {
        let line = line.trim_end();

        if let Some(marked) = section_marker(line) {
            // A section marker ends the block that was open.
            flush(&mut open, &mut blocks);
            section = marked;
            continue;
        }

        match section {
            AsmSection::Code => {
                if let Some((name, address)) = parse_label(line) {
                    flush(&mut open, &mut blocks);
                    open = Some(AsmBlock {
                        name,
                        address,
                        lines: Vec::new(),
                        variables: Vec::new(),
                    });
                } else if let Some(note) = variable_note(line) {
                    if let Some(block) = open.as_mut() {
                        block.variables.push(note);
                    }
                } else if let Some(instruction) = parse_instruction(line) {
                    if let Some(block) = open.as_mut() {
                        block.lines.push(instruction);
                    }
                }
            }
            AsmSection::Variables => {
                // The variables section repeats the labels, commented out.
                if let Some((name, address)) = parse_commented_label(line) {
                    flush(&mut open, &mut blocks);
                    open = Some(AsmBlock {
                        name,
                        address,
                        lines: Vec::new(),
                        variables: Vec::new(),
                    });
                } else if let Some(note) = variable_note(line) {
                    if let Some(block) = open.as_mut() {
                        block.variables.push(note);
                    }
                }
            }
            // The data section holds named globals and strings, not code.
            AsmSection::Data => {}
        }
    }

    flush(&mut open, &mut blocks);
    blocks
}

/// Close the open block, keeping it when it carries anything.
fn flush(open: &mut Option<AsmBlock>, blocks: &mut Vec<AsmBlock>) {
    if let Some(block) = open.take() {
        if !block.name.is_empty() {
            blocks.push(block);
        }
    }
}

/// The section a `; --- … ---` marker opens.
fn section_marker(line: &str) -> Option<AsmSection> {
    let marker = line.strip_prefix("; --- ")?.strip_suffix(" ---")?;
    if marker.contains("code section") {
        Some(AsmSection::Code)
    } else if marker.contains("variables") {
        Some(AsmSection::Variables)
    } else if marker.contains("data") {
        Some(AsmSection::Data)
    } else {
        None
    }
}

/// The note of a `; arg:` or `; stack:` line.
fn variable_note(line: &str) -> Option<String> {
    let note = line.strip_prefix(';')?.trim_start();
    if note.starts_with("arg:") || note.starts_with("stack:") {
        Some(note.to_string())
    } else {
        None
    }
}

/// Parse a `<name>:  ; 0x<addr>` label line.
fn parse_label(line: &str) -> Option<(String, u64)> {
    if line.starts_with(char::is_whitespace) || line.starts_with(';') {
        return None;
    }
    let (name, comment) = line.split_once(":  ; ")?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), parse_address(comment.trim())))
}

/// Parse a `; <name>:  ; 0x<addr>` label line, as the variables section writes
/// them.
fn parse_commented_label(line: &str) -> Option<(String, u64)> {
    let label = line.strip_prefix("; ")?;
    parse_label(label)
}

/// Parse one instruction line of a `.asm`.
fn parse_instruction(line: &str) -> Option<KunaListingLine> {
    let rest = line.strip_prefix("  ")?;
    let (address, rest) = rest.split_once(": ")?;
    let address = u64::from_str_radix(address.trim(), 16).ok()?;

    if let Some(operands) = rest.strip_prefix("db ") {
        return Some(KunaListingLine {
            address,
            bytes: String::new(),
            mnemonic: "db".to_string(),
            operands: operands.trim().to_string(),
        });
    }

    // The byte field is separated from the mnemonic by two or more spaces;
    // the bytes inside it are separated by single ones.
    let separator = rest.find("  ")?;
    let bytes = rest[..separator].trim().to_string();
    let tail = rest[separator + 2..].trim_start();
    let (mnemonic, operands) = match tail.find(' ') {
        Some(index) => (tail[..index].trim(), tail[index + 1..].trim()),
        None => (tail.trim(), ""),
    };

    Some(KunaListingLine {
        address,
        bytes,
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A temporary directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "ag-kuna-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&path).expect("a temporary directory");
            TempDir(path)
        }

        fn write(&self, name: &str, contents: &str) {
            let mut file = fs::File::create(self.0.join(name)).expect("a file");
            file.write_all(contents.as_bytes()).expect("contents");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A `.c` with two functions, as a kuna export writes them.
    const C: &str = "#include \"a.h\"\n\n// Function: one @ 0x1000\nint one(void)\n{\n  return 1;\n}\n\n// Function: two @ 0x2000\nint two(void)\n{\n  return 2;\n}\n\n";

    /// The index that matches [`C`], with the byte spans of its two blocks.
    fn index() -> String {
        let one = C.find("// Function: one").expect("the first block");
        let two = C.find("// Function: two").expect("the second block");
        let end = C.len();

        format!(
            concat!(
                "{{\"seq\":0,\"name\":\"one\",\"addr\":\"0x1000\",\"size\":16,\"c_offset\":{one},\"c_len\":{one_len},\"error\":null}}\n",
                "{{\"seq\":1,\"name\":\"two\",\"addr\":\"0x2000\",\"size\":16,\"c_offset\":{two},\"c_len\":{two_len},\"error\":null}}\n",
            ),
            one = one,
            one_len = two - one,
            two = two,
            two_len = end - two,
        )
    }

    #[test]
    fn an_index_resolves_the_c_blocks() {
        let dir = TempDir::new("index");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());

        let export = KunaExport::load(&dir.0).expect("an export");
        assert_eq!(export.functions.len(), 2);
        assert_eq!(export.functions[0].name, "one");
        assert_eq!(export.functions[0].address, 0x1000);
        assert_eq!(export.functions[0].size, Some(16));
        assert!(!export.streaming);
        assert!(export.by_name.contains_key("two"));

        let one = export.function(0x1000).expect("a function");
        let body = export.function_body(one).expect("a body").expect("a body");
        assert_eq!(body, "int one(void)\n{\n  return 1;\n}");
    }

    #[test]
    fn a_c_without_an_index_is_read_by_its_headers() {
        let dir = TempDir::new("headers");
        dir.write("a.c", C);

        let export = KunaExport::load(&dir.0).expect("an export");
        assert_eq!(export.functions.len(), 2);
        assert_eq!(export.functions[1].name, "two");
        assert_eq!(export.functions[1].address, 0x2000);

        let two = export.function(0x2000).expect("a function");
        let body = export.function_body(two).expect("a body").expect("a body");
        assert_eq!(body, "int two(void)\n{\n  return 2;\n}");
    }

    #[test]
    fn a_failed_function_has_no_body() {
        let dir = TempDir::new("failed");
        dir.write("a.c", "// Function: one @ 0x1000  (error: boom)\n\n");
        dir.write(
            "index.jsonl",
            "{\"seq\":0,\"name\":\"one\",\"addr\":\"0x1000\",\"size\":0,\"c_offset\":0,\"c_len\":40,\"error\":\"boom\"}\n",
        );

        let export = KunaExport::load(&dir.0).expect("an export");
        let one = export.function(0x1000).expect("a function");
        assert_eq!(one.error.as_deref(), Some("boom"));
        assert!(export.function_body(one).expect("a body").is_none());
    }

    #[test]
    fn a_streaming_export_says_so() {
        let dir = TempDir::new("streaming");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());
        dir.write(".streaming", "{}");

        let export = KunaExport::load(&dir.0).expect("an export");
        assert!(export.streaming);
    }

    #[test]
    fn the_listing_is_sliced_by_label() {
        let asm = "\
; kuna decompile-project — a
; arch: x86:LE:64:default:gcc

; --- code section 0x1000..0x1010 ---

one:  ; 0x1000
  00001000: 55                   PUSH       RBP
  00001001: 5d                   POP        RBP
  00001002: c3                   RET

two:  ; 0x2000
  00002000: 90                   NOP
";
        let dir = TempDir::new("listing");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());
        dir.write("a.asm", asm);

        let export = KunaExport::load(&dir.0).expect("an export");
        let one = export.function(0x1000).expect("a function");
        let listing = export
            .function_listing(one)
            .expect("a listing")
            .expect("a listing");

        assert_eq!(listing.lines.len(), 3);
        assert_eq!(listing.lines[0].address, 0x1000);
        assert_eq!(listing.lines[0].bytes, "55");
        assert_eq!(listing.lines[0].mnemonic, "PUSH");
        assert_eq!(listing.lines[0].operands, "RBP");
        assert_eq!(listing.lines[2].mnemonic, "RET");
    }

    #[test]
    fn the_notes_under_a_label_belong_to_the_function() {
        let asm = "\
; --- code section 0x1000..0x1010 ---

one:  ; 0x1000
; stack: local_8 @ [stack-0x8] (undefined8)
  00001000: 55                   PUSH       RBP
";
        let dir = TempDir::new("notes");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());
        dir.write("a.asm", asm);

        let export = KunaExport::load(&dir.0).expect("an export");
        let one = export.function(0x1000).expect("a function");
        let listing = export
            .function_listing(one)
            .expect("a listing")
            .expect("a listing");

        assert_eq!(listing.lines.len(), 1);
        assert_eq!(listing.variables.len(), 1);
        assert_eq!(
            listing.variables[0],
            "stack: local_8 @ [stack-0x8] (undefined8)"
        );
    }

    #[test]
    fn a_streamed_export_keeps_its_notes_in_a_variables_section() {
        let asm = "\
; --- code section 0x1000..0x1010 ---

one:  ; 0x1000
  00001000: 55                   PUSH       RBP

; --- variables ---

; one:  ; 0x1000
; arg:   param_1 (char *)
";
        let dir = TempDir::new("streamed-notes");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());
        dir.write("a.asm", asm);

        let export = KunaExport::load(&dir.0).expect("an export");
        let one = export.function(0x1000).expect("a function");
        let listing = export
            .function_listing(one)
            .expect("a listing")
            .expect("a listing");

        assert_eq!(listing.lines.len(), 1);
        assert_eq!(listing.variables, vec!["arg:   param_1 (char *)"]);
    }

    #[test]
    fn the_data_section_is_not_a_listing() {
        let asm = "\
; --- code section 0x1000..0x1010 ---

one:  ; 0x1000
  00001000: 55                   PUSH       RBP

; --- data ---

secret:  ; 0x4010
  00004010: 04 20 00 00 00 00 00 00                          |. ......|
";
        let dir = TempDir::new("data");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());
        dir.write("a.asm", asm);

        let export = KunaExport::load(&dir.0).expect("an export");
        let one = export.function(0x1000).expect("a function");
        let listing = export
            .function_listing(one)
            .expect("a listing")
            .expect("a listing");

        assert_eq!(listing.lines.len(), 1);
        assert_eq!(listing.lines[0].mnemonic, "PUSH");
    }

    #[test]
    fn a_directory_without_a_c_file_is_not_an_export() {
        let dir = TempDir::new("empty");
        dir.write("README.md", "hello");

        assert!(!is_kuna_export(&dir.0));
        assert!(KunaExport::load(&dir.0).is_err());
    }

    #[test]
    fn the_readme_names_the_binary_the_export_came_from() {
        let dir = TempDir::new("readme");
        dir.write("a.c", C);
        dir.write(
            "README.md",
            "# a — kuna project export\n\n## Binary\n\n| Field | Value |\n|---|---|\n| Path | `/tmp/target.elf` |\n| File size | 17 bytes |\n",
        );

        let export = KunaExport::load(&dir.0).expect("an export");
        assert_eq!(
            export.binary.as_deref(),
            Some(Path::new("/tmp/target.elf")),
            "the README's Path row names the analysed binary"
        );
    }

    #[test]
    fn an_export_without_a_readme_names_no_binary() {
        let dir = TempDir::new("no-readme");
        dir.write("a.c", C);

        let export = KunaExport::load(&dir.0).expect("an export");
        assert!(export.binary.is_none());
    }

    #[test]
    fn the_body_is_read_from_the_cached_text() {
        let dir = TempDir::new("cached");
        dir.write("a.c", C);
        dir.write("index.jsonl", &index());

        let export = KunaExport::load(&dir.0).expect("an export");
        let one = export.function(0x1000).expect("a function");
        let first = export.function_body(one).expect("a body").expect("a body");

        // The `.c` is gone, and the body still resolves: the export holds the
        // text it read at load time.
        fs::remove_file(dir.0.join("a.c")).expect("the c file");
        let second = export.function_body(one).expect("a body").expect("a body");

        assert_eq!(first, second);
        assert_eq!(first, "int one(void)\n{\n  return 1;\n}");
    }
}
