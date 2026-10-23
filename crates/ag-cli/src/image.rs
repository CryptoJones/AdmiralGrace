//! `ag image` — inspecting a program image with the engine.
//!
//! The loader, the decoder and the control-flow walk are the engine's, so
//! what these subcommands report is what the engine itself sees. Every
//! subcommand has a `--json` surface as well, so an agent can read the
//! numbers without scraping the text.

use std::path::Path;

use ag_image::Binary;
use anyhow::{Context, Result};
use clap::Subcommand;
use regex::Regex;
use serde::Serialize;

/// What to report about a program image.
#[derive(Subcommand)]
pub enum ImageCmd {
    /// The language, the entry point and the sections of the image.
    Info {
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The function and data symbols of the image.
    Symbols {
        /// Only the symbols whose name matches the regular expression.
        #[arg(long)]
        filter: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The disassembly of one function.
    Disasm {
        /// The function: an address such as `0x1198`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The strings the image holds.
    Strings {
        /// Only the strings whose text matches the regular expression.
        #[arg(long)]
        filter: Option<String>,
        /// Report the strings that are held as UTF-16LE.
        #[arg(long)]
        utf16: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// One section of the image, as JSON.
#[derive(Debug, Serialize)]
struct SectionJson {
    /// The section's name.
    name: String,
    /// The address the section maps to.
    vma: u64,
    /// The address, as a hex string.
    vma_hex: String,
    /// The section's size in memory.
    size: u64,
    /// Whether the section holds code.
    executable: bool,
    /// Where the section's bytes start in the file.
    file_offset: Option<u64>,
    /// How many of the section's bytes the file holds.
    file_size: Option<u64>,
}

/// One function symbol, as JSON.
#[derive(Debug, Serialize)]
struct FunctionJson {
    /// The function's entry address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The function's name.
    name: String,
}

/// One data symbol, as JSON.
#[derive(Debug, Serialize)]
struct DataJson {
    /// The symbol's address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The symbol's name.
    name: String,
    /// The symbol's size in bytes.
    size: u64,
}

/// The image, as JSON.
#[derive(Debug, Serialize)]
struct InfoJson {
    /// The SLEIGH language id the loader resolved.
    language: String,
    /// The container's declared entry point.
    entry: Option<u64>,
    /// The entry point, as a hex string.
    entry_hex: Option<String>,
    /// The sections of the image.
    sections: Vec<SectionJson>,
}

/// The symbols of the image, as JSON.
#[derive(Debug, Serialize)]
struct SymbolsJson {
    /// The function symbols.
    functions: Vec<FunctionJson>,
    /// The data symbols.
    data: Vec<DataJson>,
}

/// One call, as JSON.
#[derive(Debug, Serialize)]
struct CallJson {
    /// The address of the call instruction.
    site: u64,
    /// The address, as a hex string.
    site_hex: String,
    /// The address the call goes to.
    target: u64,
    /// The address, as a hex string.
    target_hex: String,
    /// The name of the function at the target, when it has one.
    name: Option<String>,
}

/// One instruction, as JSON.
#[derive(Debug, Serialize)]
struct InstructionJson {
    /// The address of the instruction.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The bytes of the instruction, hex.
    bytes: String,
    /// The mnemonic.
    mnemonic: String,
    /// The operands.
    operands: String,
    /// The call the instruction makes, when it is a direct call.
    call: Option<CallJson>,
}

/// One basic block, as JSON.
#[derive(Debug, Serialize)]
struct BlockJson {
    /// The address the block starts at.
    from: u64,
    /// The address, as a hex string.
    from_hex: String,
    /// The address the block ends at.
    to: u64,
    /// The address, as a hex string.
    to_hex: String,
    /// The addresses the block goes to.
    successors: Vec<u64>,
    /// The instructions of the block.
    instructions: Vec<InstructionJson>,
}

/// The disassembly of a function, as JSON.
#[derive(Debug, Serialize)]
struct DisasmJson {
    /// The function's entry address.
    function: u64,
    /// The address, as a hex string.
    function_hex: String,
    /// The function's name, when it has one.
    name: Option<String>,
    /// The section the function sits in.
    section: String,
    /// The blocks of the function.
    blocks: Vec<BlockJson>,
    /// The direct calls the function makes.
    calls: Vec<CallJson>,
}

/// One string of the image, as JSON.
#[derive(Debug, Serialize)]
struct StringJson {
    /// Where the string lives.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The text of the string.
    text: String,
    /// The section the string lives in.
    section: String,
    /// How many bytes the string holds, the terminator included.
    length: u64,
    /// The functions that refer to the string.
    functions: Vec<StringFunctionJson>,
}

/// One function that refers to a string, as JSON.
#[derive(Debug, Serialize)]
struct StringFunctionJson {
    /// The address of the function.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The name of the function.
    name: String,
}

/// The strings of the image, as JSON.
#[derive(Debug, Serialize)]
struct StringsJson {
    /// The strings.
    strings: Vec<StringJson>,
}

/// Report on a program image.
pub fn run(binary: &Path, cmd: ImageCmd) -> Result<i32> {
    let image = Binary::open(binary).with_context(|| format!("reading {}", binary.display()))?;

    match cmd {
        ImageCmd::Info { json } => info(&image, json),
        ImageCmd::Symbols { filter, json } => symbols(&image, filter.as_deref(), json),
        ImageCmd::Disasm { target, json } => disasm(&image, &target, json),
        ImageCmd::Strings {
            filter,
            utf16,
            json,
        } => strings(&image, filter.as_deref(), utf16, json),
    }
}

/// Report the language, the entry point and the sections.
fn info(image: &Binary, json: bool) -> Result<i32> {
    let sections: Vec<SectionJson> = image
        .sections()
        .iter()
        .map(|section| SectionJson {
            name: section.name.clone(),
            vma: section.vma,
            vma_hex: format!("{:#x}", section.vma),
            size: section.size,
            executable: section.executable,
            file_offset: section.file_offset,
            file_size: section.file_size,
        })
        .collect();

    if json {
        let report = InfoJson {
            language: image.language().to_string(),
            entry: image.entry(),
            entry_hex: image.entry().map(|entry| format!("{entry:#x}")),
            sections,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("language: {}", image.language());
    match image.entry() {
        Some(entry) => println!("entry: {entry:#x}"),
        None => println!("entry: none"),
    }
    println!("sections: {}", sections.len());

    for section in &sections {
        let file = match (section.file_offset, section.file_size) {
            (Some(offset), Some(size)) => format!("{offset:#x}-{:#x}", offset + size),
            (Some(offset), None) => format!("{offset:#x}-"),
            _ => "none".to_string(),
        };

        println!(
            "  {} vma={} size={} exec={} file={file}",
            section.name,
            section.vma_hex,
            section.size,
            if section.executable { "yes" } else { "no" }
        );
    }

    Ok(0)
}

/// Report the symbols of the image.
fn symbols(image: &Binary, filter: Option<&str>, json: bool) -> Result<i32> {
    let pattern = filter.map(Regex::new).transpose()?;

    let matches = |name: &str| match &pattern {
        Some(pattern) => pattern.is_match(name),
        None => true,
    };

    let functions: Vec<FunctionJson> = image
        .functions()
        .iter()
        .filter(|function| matches(&function.name))
        .map(|function| FunctionJson {
            address: function.address,
            address_hex: format!("{:#x}", function.address),
            name: function.name.clone(),
        })
        .collect();

    let data: Vec<DataJson> = image
        .data_symbols()
        .iter()
        .filter(|symbol| matches(&symbol.name))
        .map(|symbol| DataJson {
            address: symbol.address,
            address_hex: format!("{:#x}", symbol.address),
            name: symbol.name.clone(),
            size: symbol.size,
        })
        .collect();

    if json {
        let report = SymbolsJson { functions, data };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("functions:");
    for function in &functions {
        println!("{} {}", function.address_hex, function.name);
    }

    println!("data:");
    for symbol in &data {
        println!(
            "{} {} size={}",
            symbol.address_hex, symbol.name, symbol.size
        );
    }

    Ok(0)
}

/// Report the disassembly of one function.
fn disasm(image: &Binary, target: &str, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86-64 and this image is {}",
        image.language()
    );

    let address = resolve(image, target)?;
    let disassembly = image
        .disassembly(address)
        .with_context(|| format!("disassembling {target}"))?;

    if json {
        let report = DisasmJson {
            function: address,
            function_hex: format!("{address:#x}"),
            name: image.function_name(address).map(str::to_string),
            section: disassembly.section.clone(),
            blocks: disassembly
                .blocks
                .iter()
                .map(|block| BlockJson {
                    from: block.from,
                    from_hex: format!("{:#x}", block.from),
                    to: block.to,
                    to_hex: format!("{:#x}", block.to),
                    successors: block.successors.clone(),
                    instructions: block
                        .instructions
                        .iter()
                        .map(|instruction| InstructionJson {
                            address: instruction.address,
                            address_hex: format!("{:#x}", instruction.address),
                            bytes: instruction
                                .bytes
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect(),
                            mnemonic: instruction.mnemonic.clone(),
                            operands: operands_of(instruction),
                            call: instruction.call.as_ref().map(call_json),
                        })
                        .collect(),
                })
                .collect(),
            calls: disassembly.calls.iter().map(call_json).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    let name = image.function_name(address).unwrap_or("entry");
    println!("; {name} at {address:#x} in {}", disassembly.section);

    for block in &disassembly.blocks {
        let successors: Vec<String> = block
            .successors
            .iter()
            .map(|successor| format!("{successor:#x}"))
            .collect();

        if successors.is_empty() {
            println!("; block {:#x}", block.from);
        } else {
            println!("; block {:#x} -> {}", block.from, successors.join(", "));
        }

        for instruction in &block.instructions {
            let bytes: Vec<String> = instruction
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            let line = format!(
                "{:#x} {} {} {}",
                instruction.address,
                bytes.join(" "),
                instruction.mnemonic,
                operands_of(instruction)
            );
            println!("{}", line.trim_end());
        }
    }

    Ok(0)
}

/// Report the strings the image holds.
///
/// The strings are found in the sections that are not code. The functions
/// that refer to them are worked out as well, which needs the whole program
/// read, so that is what this call costs.
fn strings(image: &Binary, filter: Option<&str>, utf16: bool, json: bool) -> Result<i32> {
    let strings = strings_of(image, filter, utf16)?;

    if json {
        let report = StringsJson { strings };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("strings: {}", strings.len());

    for string in &strings {
        let users = if string.functions.is_empty() {
            "-".to_string()
        } else {
            string
                .functions
                .iter()
                .map(|function| function.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };

        println!(
            "{} {} \"{}\" {}",
            string.address_hex, string.section, string.text, users
        );
    }

    Ok(0)
}

/// The strings of the image that match the filter.
///
/// The wide strings are the ones held as UTF-16LE; they are not in the index
/// of the users of a string, so they carry none.
fn strings_of(image: &Binary, filter: Option<&str>, utf16: bool) -> Result<Vec<StringJson>> {
    let pattern = filter.map(Regex::new).transpose()?;

    let matches = |text: &str| match &pattern {
        Some(pattern) => pattern.is_match(text),
        None => true,
    };

    let found = if utf16 {
        image.wide_strings()
    } else {
        image.strings()
    };

    // Who refers to each string is only known once the whole program has been
    // read.
    let users = image.string_users();

    Ok(found
        .iter()
        .filter(|string| matches(&string.text))
        .map(|string| StringJson {
            address: string.address,
            address_hex: format!("{:#x}", string.address),
            text: string.text.clone(),
            section: string.section.clone(),
            length: string.length,
            functions: users
                .get(&string.address)
                .map(|functions| {
                    functions
                        .iter()
                        .map(|address| StringFunctionJson {
                            address: *address,
                            address_hex: format!("{address:#x}"),
                            name: image.function_name(*address).unwrap_or("entry").to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect())
}

/// The operands of an instruction, with a call's target named.
fn operands_of(instruction: &ag_image::Instruction) -> String {
    match instruction
        .call
        .as_ref()
        .and_then(|call| call.name.as_deref())
    {
        Some(name) => name.to_string(),
        None => instruction.operands.clone(),
    }
}

/// One call, as JSON.
fn call_json(call: &ag_image::Call) -> CallJson {
    CallJson {
        site: call.site,
        site_hex: format!("{:#x}", call.site),
        target: call.target,
        target_hex: format!("{:#x}", call.target),
        name: call.name.clone(),
    }
}

/// The address of the function `target` names.
///
/// A target that reads as an address is looked for as one first — `0x1000`,
/// `0X1000`, or a bare hexadecimal number. An address that names no function
/// is not an error: the target may still be a name.
fn resolve(image: &Binary, target: &str) -> Result<u64> {
    if let Ok(address) = ag_corpus::parse_addr(target) {
        if image.function_name(address).is_some() {
            return Ok(address);
        }
    }

    if let Some(function) = image
        .functions()
        .iter()
        .find(|function| function.name == target)
    {
        return Ok(function.address);
    }

    let loose: Vec<u64> = image
        .functions()
        .iter()
        .filter(|function| function.name.contains(target))
        .map(|function| function.address)
        .collect();

    anyhow::ensure!(!loose.is_empty(), "no function matching {target:?}");
    Ok(loose[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The sample ELF the engine's own tests read.
    fn sample_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf")
    }

    /// The sample ELF, read.
    fn sample() -> Binary {
        Binary::open(&sample_path()).expect("the sample ELF loads")
    }

    #[test]
    fn an_address_names_the_function_at_it() {
        let image = sample();

        assert_eq!(resolve(&image, "0x1198").expect("a function"), 0x1198);
        assert_eq!(resolve(&image, "1198").expect("a function"), 0x1198);
        assert_eq!(resolve(&image, "0X1198").expect("a function"), 0x1198);
    }

    #[test]
    fn a_name_names_its_function() {
        let image = sample();

        assert_eq!(resolve(&image, "main").expect("a function"), 0x1198);
        assert_eq!(resolve(&image, "add").expect("a function"), 0x1149);
    }

    #[test]
    fn a_name_that_reads_like_an_address_is_still_a_name() {
        let image = sample();

        // The target reads as an address, but no function is there.
        let error = resolve(&image, "0Xdead").expect_err("no function");
        assert!(
            error.to_string().contains("no function matching"),
            "the lookup falls through to the name: {error}"
        );
    }

    #[test]
    fn a_target_that_names_nothing_is_an_error() {
        let image = sample();

        let error = resolve(&image, "nonesuch").expect_err("no function");
        assert!(error.to_string().contains("no function matching"));
    }

    #[test]
    fn a_call_shows_the_symbol_it_calls() {
        let image = sample();

        let disassembly = image.disassembly(0x1198).expect("main disassembles");
        let call = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find_map(|instruction| instruction.call.as_ref())
            .expect("a call");

        let instruction = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|instruction| instruction.call.is_some())
            .expect("a call instruction");

        assert_eq!(operands_of(instruction), call.name.clone().unwrap());
    }

    #[test]
    fn the_strings_of_the_image_are_listed_with_the_functions_that_use_them() {
        let image = sample();

        let strings = strings_of(&image, None, false).expect("the strings are listed");

        let format = strings
            .iter()
            .find(|string| string.text == "%ld\\n")
            .expect("the format string of the sample");

        assert_eq!(format.address_hex, "0x2004");
        assert_eq!(format.section, ".rodata");
        assert_eq!(format.length, 5, "the string holds four bytes and its NUL");

        assert_eq!(format.functions.len(), 1, "one function uses it");
        assert_eq!(format.functions[0].name, "main");
        assert_eq!(format.functions[0].address_hex, "0x1198");
    }

    #[test]
    fn a_filter_leaves_out_the_strings_that_do_not_match() {
        let image = sample();

        let strings = strings_of(&image, Some("^%ld"), false).expect("the strings are listed");

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].address_hex, "0x2004");
    }

    #[test]
    fn a_filter_that_matches_nothing_lists_no_strings() {
        let image = sample();

        let strings = strings_of(&image, Some("nonesuch"), false).expect("the strings are listed");

        assert!(strings.is_empty(), "{strings:?}");
    }
}
