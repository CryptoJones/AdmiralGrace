//! The JSON surfaces of the [kuna](https://github.com/Noelo-Lab/kuna) CLI.
//!
//! A project export holds the decompiled bodies, the linear listing and the
//! recovered prototypes. The kuna CLI can also answer questions about the
//! *binary* behind an export: which lines of C came from which addresses, what
//! refers to what, which strings it holds and how its functions are shaped.
//! Those answers are JSON documents, and this module reads them.
//!
//! Every question is asked of the binary the export was made from, so the
//! export's README — which records that path — is what makes the JSON
//! surfaces reachable at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use ag_corpus::kuna::KunaExport;
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// The environment variable that names the kuna executable.
pub const KUNA_BIN_ENV: &str = "AG_KUNA_BIN";

/// Which way a cross reference runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// References the function makes.
    From,
    /// References made to the function.
    To,
}

impl Direction {
    /// The flag kuna takes for this direction.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::From => "--from",
            Direction::To => "--to",
        }
    }
}

/// One line of C and the addresses it came from.
#[derive(Debug, Clone, Deserialize)]
pub struct LineMapping {
    /// The line number inside the function's body, counting from one.
    pub line_number: u32,
    /// The addresses the line was written from.
    #[serde(default)]
    pub addresses: Vec<u64>,
}

/// A function's decompilation, as `kuna decompile --json` reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionJson {
    /// The decompiled body, when the function decompiled.
    #[serde(default)]
    pub code: Option<String>,
    /// Why the function failed, when it did.
    #[serde(default)]
    pub error: Option<String>,
    /// How many jumps in the body are a diverging panic rather than a
    /// translation.
    #[serde(default)]
    pub unstructured_gotos: usize,
    /// The mapping from the body's lines to the addresses they came from.
    #[serde(default)]
    pub line_mappings: Vec<LineMapping>,
}

/// A function named by a cross reference or a string.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRef {
    /// The function's name.
    #[serde(default)]
    pub name: String,
    /// Its address.
    #[serde(default)]
    pub address: u64,
}

/// One cross reference.
#[derive(Debug, Clone, Deserialize)]
pub struct XrefJson {
    /// What kind of reference it is: `call`, `jump`, `data`, `read` or `write`.
    #[serde(default)]
    pub kind: String,
    /// Where the reference is made from.
    #[serde(default)]
    pub from_address: u64,
    /// Where the reference points to.
    #[serde(default)]
    pub to_address: u64,
    /// The function the reference is made from.
    #[serde(default)]
    pub from_function: Option<FunctionRef>,
    /// The function the reference points to.
    #[serde(default)]
    pub to_function: Option<FunctionRef>,
    /// The instruction that makes the reference.
    #[serde(default)]
    pub instruction: Option<String>,
}

/// One string the binary holds.
#[derive(Debug, Clone, Deserialize)]
pub struct StringJson {
    /// Where the string lives.
    #[serde(default)]
    pub address: u64,
    /// The string itself.
    #[serde(default)]
    pub text: String,
    /// The section it lives in.
    #[serde(default)]
    pub section: Option<String>,
    /// The functions that refer to the string.
    #[serde(default)]
    pub functions: Vec<FunctionRef>,
}

/// The body of the `functions --summary --json` document.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SummaryBody {
    /// The program's entry point.
    #[serde(default)]
    pub entry: Option<FunctionRef>,
    /// The program's `main`, when it has one.
    #[serde(default)]
    pub main: Option<FunctionRef>,
    /// How many functions are reachable from the entry point.
    #[serde(default)]
    pub reachable_from_entry: usize,
    /// How many functions nothing calls.
    #[serde(default)]
    pub no_callers: usize,
    /// How many bytes of code the program holds.
    #[serde(default)]
    pub code_bytes: u64,
}

/// The `functions --summary --json` document.
#[derive(Debug, Clone, Deserialize)]
pub struct SummaryJson {
    /// How many functions the program holds.
    #[serde(default)]
    pub total: usize,
    /// The run-level error, when the run failed.
    #[serde(default)]
    pub error: Option<String>,
    /// The warnings the run produced.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The summary itself.
    #[serde(default)]
    pub summary: SummaryBody,
}

/// The kuna CLI, and the binary it works on.
#[derive(Debug, Clone)]
pub struct KunaCli {
    /// The kuna executable.
    program: PathBuf,
    /// The binary being analysed.
    binary: PathBuf,
}

impl KunaCli {
    /// A CLI that runs `program` against `binary`.
    pub fn new(program: PathBuf, binary: PathBuf) -> KunaCli {
        KunaCli { program, binary }
    }

    /// The CLI for an export, when the export names a binary that is still
    /// there.
    ///
    /// The export's README records the path of the binary it was made from.
    /// When that path no longer holds a file, a copy of the binary sitting
    /// beside the export is used instead — an export is usually kept next to
    /// what it was made from.
    ///
    /// The fallback beside the export is `root.join(export.name)`, so it only
    /// finds the binary when the export was named after it. An export named
    /// for something else — a version, a target — has to keep the binary
    /// where its README says it is.
    ///
    /// The executable is named here, so a caller can say which kuna to run.
    pub fn for_export(export: &KunaExport, program: PathBuf) -> Option<KunaCli> {
        let binary = export
            .binary
            .as_ref()
            .filter(|path| path.is_file())
            .cloned()
            .or_else(|| {
                let beside = export.root.join(&export.name);
                beside.is_file().then_some(beside)
            })?;

        Some(KunaCli::new(program, binary))
    }

    /// The kuna executable the workbench shells out to.
    ///
    /// `AG_KUNA_BIN` names it; otherwise the `kuna` on the path is used.
    pub fn program() -> PathBuf {
        std::env::var_os(KUNA_BIN_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("kuna"))
    }

    /// Whether the kuna executable is there to be run.
    ///
    /// A path is used when it names a file; a bare name is looked for on the
    /// `PATH`, the way a shell would find it. When neither resolves, there is
    /// no CLI to ask, and the workbench carries on without one.
    pub fn available(program: &Path) -> bool {
        let name = program.to_string_lossy();

        if name.contains(std::path::MAIN_SEPARATOR) {
            return program.is_file();
        }

        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };

        std::env::split_paths(&path).any(|dir| dir.join(&*name).is_file())
    }

    /// The binary being analysed.
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Decompile one function, with the mapping from its lines to addresses.
    pub fn decompile(&self, address: u64) -> Result<FunctionJson> {
        let document: DecompileDocument = self.json(&[
            "decompile".to_string(),
            self.binary.display().to_string(),
            format!("{address:#x}"),
            "--addr".to_string(),
            "--json".to_string(),
        ])?;

        document
            .functions
            .into_iter()
            .next()
            .context("kuna decompiled nothing")
    }

    /// The cross references of one function, in one direction.
    pub fn xrefs(&self, address: u64, direction: Direction) -> Result<Vec<XrefJson>> {
        let document: XrefDocument = self.json(&[
            "xrefs".to_string(),
            self.binary.display().to_string(),
            direction.as_str().to_string(),
            format!("{address:#x}"),
            "--json".to_string(),
        ])?;

        Ok(document.xrefs)
    }

    /// The strings the binary holds.
    pub fn strings(&self) -> Result<Vec<StringJson>> {
        let document: StringDocument = self.json(&[
            "strings".to_string(),
            self.binary.display().to_string(),
            "--json".to_string(),
        ])?;

        Ok(document.strings)
    }

    /// The shape of the program: its entry point, its `main` and how much of
    /// it is reachable.
    pub fn summary(&self) -> Result<SummaryJson> {
        self.json(&[
            "functions".to_string(),
            self.binary.display().to_string(),
            "--summary".to_string(),
            "--json".to_string(),
        ])
    }

    /// Run kuna and read the JSON document it printed.
    fn json<T: DeserializeOwned>(&self, args: &[String]) -> Result<T> {
        let output = Command::new(&self.program)
            .args(args)
            .output()
            .with_context(|| format!("running {}", self.program.display()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        match serde_json::from_str::<T>(&stdout) {
            Ok(document) => Ok(document),
            Err(error) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stderr = stderr.trim();
                anyhow::bail!(
                    "kuna {}: {error}{}",
                    args.join(" "),
                    if stderr.is_empty() {
                        String::new()
                    } else {
                        format!(": {stderr}")
                    }
                )
            }
        }
    }
}

/// The `decompile --json` document.
#[derive(Debug, Clone, Deserialize)]
struct DecompileDocument {
    #[serde(default)]
    functions: Vec<FunctionJson>,
}

/// The `xrefs --json` document.
#[derive(Debug, Clone, Deserialize)]
struct XrefDocument {
    #[serde(default)]
    xrefs: Vec<XrefJson>,
}

/// The `strings --json` document.
#[derive(Debug, Clone, Deserialize)]
struct StringDocument {
    #[serde(default)]
    strings: Vec<StringJson>,
}

/// The addresses each line of the displayed pseudocode came from.
///
/// The line numbers kuna reports count the lines of the body it produced, so
/// they only mean something next to that same body. When the export's copy
/// and the copy kuna just produced still agree, the two line up and the
/// mapping holds; when they have drifted apart, no mapping is reported rather
/// than a wrong one.
pub fn line_addresses(
    displayed: &str,
    code: &str,
    mappings: &[LineMapping],
) -> BTreeMap<usize, Vec<u64>> {
    let mut addresses = BTreeMap::new();

    let displayed: Vec<&str> = displayed.lines().collect();
    let code: Vec<&str> = code.lines().collect();

    if displayed.len() != code.len() {
        return addresses;
    }
    if !displayed
        .iter()
        .zip(code.iter())
        .all(|(shown, made)| shown.trim_end() == made.trim_end())
    {
        return addresses;
    }

    for mapping in mappings {
        let Some(line) = mapping.line_number.checked_sub(1) else {
            continue;
        };
        let index = line as usize;
        if index >= displayed.len() {
            continue;
        }
        addresses
            .entry(index)
            .or_insert_with(Vec::new)
            .extend(mapping.addresses.iter().copied());
    }

    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `decompile --json` document of one function.
    const DECOMPILE: &str = r#"{
      "binary": "sample.elf",
      "language": "c-language",
      "count": 1,
      "error": null,
      "functions": [
        {
          "name": "main",
          "address": 4504,
          "address_hex": "0x1198",
          "aliases": ["sub_1198"],
          "object_location": null,
          "size": 84,
          "code": "int main(int argc,char **argv)\n{\n  v1 = sum_to(add(argc,3));\n  return v1;\n}",
          "error": null,
          "unstructured_gotos": 0,
          "line_mappings": [
            {"line_number": 3, "addresses": [4533, 4546]},
            {"line_number": 4, "addresses": [4587]}
          ],
          "variables": [
            {"name": "argc", "type": "int", "kind": "arg", "arg_index": 0, "stack_offset": null, "size": 4, "line_numbers": [3], "addresses": [4533]}
          ],
          "types": []
        }
      ],
      "assertions": []
    }"#;

    /// The `xrefs --json` document.
    const XREFS: &str = r#"{
      "binary": "sample.elf",
      "target": {"name": "main", "address": 4504, "address_hex": "0x1198", "aliases": []},
      "direction": "from",
      "count": 1,
      "xrefs": [
        {
          "address": 4176,
          "address_hex": "0x1050",
          "kind": "call",
          "from_address": 4577,
          "from_address_hex": "0x11e1",
          "to_address": 4176,
          "to_address_hex": "0x1050",
          "from_function": {"name": "main", "address": 4504, "address_hex": "0x1198"},
          "to_function": {"name": "printf", "address": 4176, "address_hex": "0x1050"},
          "instruction": "CALL 0x1050"
        }
      ]
    }"#;

    /// The `strings --json` document.
    const STRINGS: &str = r#"{
      "binary": "sample.elf",
      "encoding": "ascii",
      "min_length": 5,
      "filter": null,
      "section": null,
      "termination": "any",
      "scanned": "sections",
      "xrefs": true,
      "count": 1,
      "strings": [
        {
          "address": 8198,
          "address_hex": "0x2006",
          "text": "%ld\n",
          "length": 4,
          "byte_length": 5,
          "nul_terminated": true,
          "encoding": "ascii",
          "section": ".rodata",
          "xrefs_count": 1,
          "functions": [{"name": "main", "address": 4504, "address_hex": "0x1198"}]
        }
      ]
    }"#;

    /// The `functions --summary --json` document.
    const SUMMARY: &str = r#"{
      "binary": "sample.elf",
      "count": 13,
      "total": 13,
      "error": null,
      "warnings": [],
      "summary": {
        "entry": {"name": "_start", "address": 4192, "address_hex": "0x1060"},
        "main": {"name": "main", "address": 4504, "address_hex": "0x1198"},
        "reachable_from_entry": 5,
        "no_callers": 8,
        "code_bytes": 500,
        "size_buckets": [],
        "largest": [],
        "runtime": null,
        "limits": null
      }
    }"#;

    #[test]
    fn the_decompile_document_carries_the_line_mappings() {
        let document: DecompileDocument = serde_json::from_str(DECOMPILE).expect("a document");
        let function = document.functions.first().expect("a function");

        assert_eq!(function.unstructured_gotos, 0);
        assert!(function.code.is_some());
        assert_eq!(function.line_mappings.len(), 2);
        assert_eq!(function.line_mappings[0].line_number, 3);
        assert_eq!(function.line_mappings[0].addresses, vec![4533, 4546]);
    }

    #[test]
    fn the_xref_document_carries_the_referring_function() {
        let document: XrefDocument = serde_json::from_str(XREFS).expect("a document");
        let xref = document.xrefs.first().expect("a cross reference");

        assert_eq!(xref.kind, "call");
        assert_eq!(xref.from_address, 0x11e1);
        assert_eq!(xref.instruction.as_deref(), Some("CALL 0x1050"));
        assert_eq!(xref.to_address, 0x1050);
        assert_eq!(
            xref.to_function
                .as_ref()
                .map(|function| function.name.as_str()),
            Some("printf")
        );
    }

    #[test]
    fn the_strings_document_carries_the_referring_functions() {
        let document: StringDocument = serde_json::from_str(STRINGS).expect("a document");
        let string = document.strings.first().expect("a string");

        assert_eq!(string.text, "%ld\n");
        assert_eq!(string.section.as_deref(), Some(".rodata"));
        assert_eq!(string.functions.len(), 1);
        assert_eq!(string.functions[0].address, 0x1198);
    }

    #[test]
    fn the_summary_document_carries_the_shape_of_the_program() {
        let document: SummaryJson = serde_json::from_str(SUMMARY).expect("a document");

        assert_eq!(document.total, 13);
        assert_eq!(
            document.summary.entry.as_ref().map(|e| e.name.as_str()),
            Some("_start")
        );
        assert_eq!(
            document.summary.main.as_ref().map(|m| m.address),
            Some(0x1198)
        );
        assert_eq!(document.summary.reachable_from_entry, 5);
        assert_eq!(document.summary.code_bytes, 500);
    }

    #[test]
    fn the_line_mappings_become_addresses_per_line() {
        let function = FunctionJson {
            code: Some(
                "int main(int argc,char **argv)\n{\n  v1 = sum_to(add(argc,3));\n  return v1;\n}"
                    .into(),
            ),
            error: None,
            unstructured_gotos: 0,
            line_mappings: vec![
                LineMapping {
                    line_number: 3,
                    addresses: vec![4533, 4546],
                },
                LineMapping {
                    line_number: 4,
                    addresses: vec![4587],
                },
            ],
        };

        let displayed = function.code.as_deref().unwrap_or_default();
        let addresses = line_addresses(displayed, displayed, &function.line_mappings);

        assert_eq!(addresses.get(&2), Some(&vec![4533, 4546]));
        assert_eq!(addresses.get(&3), Some(&vec![4587]));
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn a_body_that_drifted_from_the_export_reports_no_mapping() {
        let mappings = vec![LineMapping {
            line_number: 3,
            addresses: vec![4533],
        }];

        let addresses = line_addresses(
            "int main(void)\n{\n  something else;\n}",
            "int main(void)\n{\n  v1 = x;\n}",
            &mappings,
        );

        assert!(addresses.is_empty(), "a stale mapping is worse than none");
    }

    #[test]
    fn the_kuna_executable_comes_from_the_environment_or_the_path() {
        // The lookup is a fallback chain, so the only thing a test can say is
        // that it never returns nothing.
        assert!(!KunaCli::program().as_os_str().is_empty());
    }

    #[test]
    fn a_kuna_on_the_path_counts_as_found() {
        // A bare name is looked for on the PATH, the way a shell would find
        // it; a path is used when it names a file.
        assert!(KunaCli::available(Path::new("sh")), "sh is on the path");
        assert!(!KunaCli::available(Path::new("no-such-program-anywhere")));
        assert!(!KunaCli::available(Path::new("/nonexistent/kuna")));
    }
}
