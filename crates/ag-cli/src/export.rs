//! `ag image … export` — the whole analysis of an image, as a directory.
//!
//! An agent working from the skill runs `ag image` six times for one binary.
//! This writes what those six print, in one pass, as files it can read
//! offline: the same JSON the subcommands print under `--json`, built by the
//! same code, and the listing text `disasm` prints. The `README.md` names
//! the binary the way a kuna project export does, so the reader that finds
//! the binary of an export finds this one's too.
//!
//! The layout:
//!
//! ```text
//! <dir>/
//!   README.md                  the binary, its hash, the ag version, the layout
//!   index.json                 the same, as JSON, with every function and its files
//!   info.json                  ag image info --json
//!   symbols.json               ag image symbols --json
//!   strings.json               ag image strings --json
//!   data.json                  ag image data --json
//!   calls.json                 ag image calls --json
//!   functions/<address>.json   cfg, calls, data references, pseudocode or the reason
//!   functions/<address>.asm    ag image disasm <address>
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_image::Binary;
use ag_corpus::project::sha256_of;
use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;

use crate::image::{
    calls_json, cfg_json, data_json, function_calls_json, function_data_json, info_json,
    listing_text, pseudocode_json, strings_json, symbols_json, CfgJson, FunctionCallsJson,
    FunctionDataJson, PseudocodeJson,
};

/// The version of the layout, for a reader that has to tell one from the next.
const LAYOUT_VERSION: u32 = 1;

/// The whole-image files, by the name a reader knows them by.
const FILES: &[(&str, &str)] = &[
    ("README.md", "This file: the binary, its hash, the version of `ag`, and the layout."),
    ("index.json", "The same as JSON, with every function of the export and its files."),
    ("info.json", "The language, the entry point and the sections: `ag image info --json`."),
    ("symbols.json", "The function and data symbols: `ag image symbols --json`."),
    ("strings.json", "The strings, with the functions that use them: `ag image strings --json`."),
    ("data.json", "The data, with the functions that use it: `ag image data --json`."),
    ("calls.json", "The whole call graph: `ag image calls --json`."),
    ("functions/<address>.json", "One function: its control-flow graph (`cfg`), its calls and callers (`calls`), the data it refers to (`data`), and its pseudocode or the reason it has none (`pseudocode`)."),
    ("functions/<address>.asm", "The listing of the function, as `ag image disasm` prints it."),
];

/// One function of the export, as `index.json` lists it.
#[derive(Debug, Serialize)]
struct IndexFunctionJson {
    /// The function's entry address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The function's name.
    name: String,
    /// The section the function sits in.
    section: String,
    /// How many blocks the walk found.
    blocks: usize,
    /// Whether the lifter read it to C.
    lifted: bool,
    /// The function's JSON, relative to the export's root.
    json: String,
    /// The function's listing, relative to the export's root.
    asm: String,
}

/// The whole-image files of the export, relative to its root.
#[derive(Debug, Serialize)]
struct IndexFilesJson {
    readme: &'static str,
    info: &'static str,
    symbols: &'static str,
    strings: &'static str,
    data: &'static str,
    calls: &'static str,
}

/// The export, as `index.json` describes it.
#[derive(Debug, Serialize)]
struct IndexJson {
    /// The version of the layout.
    version: u32,
    /// The binary the export was made from.
    binary: String,
    /// The SHA-256 of the binary, hex.
    sha256: String,
    /// The version of `ag` that wrote the export.
    ag_version: &'static str,
    /// The SLEIGH language id the loader resolved.
    language: String,
    /// The container's declared entry point.
    entry: Option<u64>,
    /// The entry point, as a hex string.
    entry_hex: Option<String>,
    /// When the export was written, UTC.
    written: String,
    /// The regular expression the per-function set was limited to, when it was.
    functions_filter: Option<String>,
    /// The engine options set away from their defaults, in registry order.
    options: Vec<OptionJson>,
    /// The whole-image files.
    files: IndexFilesJson,
    /// The functions, with their files.
    functions: Vec<IndexFunctionJson>,
}

/// One engine option the export was made with.
#[derive(Debug, Serialize)]
struct OptionJson {
    /// The option's name, as `--option` takes it.
    name: &'static str,
    /// Its value.
    value: String,
}

/// One function, as `functions/<address>.json` holds it.
///
/// Each member is what the matching subcommand prints under `--json`.
#[derive(Debug, Serialize)]
struct FunctionExportJson {
    /// The function's entry address.
    function: u64,
    /// The address, as a hex string.
    function_hex: String,
    /// The function's name, when it has one.
    name: Option<String>,
    /// The section the function sits in.
    section: String,
    /// The control-flow graph: `ag image cfg --json`.
    cfg: CfgJson,
    /// The calls it makes and the functions that call it: `ag image calls --json`.
    calls: FunctionCallsJson,
    /// The data it refers to: `ag image data --json`.
    data: FunctionDataJson,
    /// The pseudocode, or the reason there is none: `ag image pseudocode --json`.
    pseudocode: PseudocodeJson,
}

/// What has been written so far, for the summary.
struct Writer<'a> {
    root: &'a Path,
    files: usize,
    bytes: u64,
}

impl Writer<'_> {
    /// Write one file under the root. An error names the file.
    fn write(&mut self, relative: &str, contents: &[u8]) -> Result<()> {
        let path = self.root.join(relative);
        fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
        self.files += 1;
        self.bytes += contents.len() as u64;
        Ok(())
    }

    /// Write one value as pretty JSON, the way the subcommands print it.
    fn write_json<T: Serialize>(&mut self, relative: &str, value: &T) -> Result<()> {
        let mut text = serde_json::to_string_pretty(value)
            .with_context(|| format!("serialising {relative}"))?;
        text.push('\n');
        self.write(relative, text.as_bytes())
    }
}

/// Write the whole analysis of `image` to `dir`.
///
/// The directory is made when it is not there. One that is not empty is
/// refused unless `force` is set, and then it is written over: nothing in
/// it is removed, so `index.json` is the list of what this run wrote.
/// `functions` limits the per-function files to the functions whose name
/// matches, as `symbols --filter` does; the whole-image files are never
/// limited.
pub fn run(
    image: &Binary,
    binary: &Path,
    dir: &Path,
    functions: Option<&str>,
    force: bool,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );
    let pattern = functions.map(Regex::new).transpose()?;

    prepare(dir, force)?;
    let functions_dir = dir.join("functions");
    fs::create_dir_all(&functions_dir)
        .with_context(|| format!("creating {}", functions_dir.display()))?;

    let sha256 = sha256_of(binary)?;
    let binary_path = fs::canonicalize(binary).unwrap_or_else(|_| binary.to_path_buf());

    let mut writer = Writer {
        root: dir,
        files: 0,
        bytes: 0,
    };

    // The whole image first: these are what `info`, `symbols`, `strings`,
    // `data` and `calls` print, and the call graph they build is what the
    // functions below are read against.
    writer.write_json("info.json", &info_json(image))?;
    writer.write_json("symbols.json", &symbols_json(image, None)?)?;
    writer.write_json("strings.json", &strings_json(image)?)?;
    writer.write_json("data.json", &data_json(image))?;
    writer.write_json("calls.json", &calls_json(image))?;

    // Then one pair of files per function.
    let mut index = Vec::new();
    for function in image.functions() {
        if let Some(pattern) = &pattern {
            if !pattern.is_match(&function.name) {
                continue;
            }
        }

        let address = function.address;
        let (Some(disassembly), Some(graph)) =
            (image.disassembly(address), image.control_flow(address))
        else {
            // Nothing is dropped in silence: a function the decoder cannot
            // reach has no listing, and the export says so.
            eprintln!(
                "warning: {} at {address:#x} sits in no code section, so it has no files",
                function.name
            );
            continue;
        };

        let json = format!("functions/{address:#x}.json");
        let asm = format!("functions/{address:#x}.asm");

        let report = FunctionExportJson {
            function: address,
            function_hex: format!("{address:#x}"),
            name: image.function_name(address).map(str::to_string),
            section: disassembly.section.clone(),
            cfg: cfg_json(&graph),
            calls: function_calls_json(image, address),
            data: function_data_json(image, address),
            pseudocode: pseudocode_json(image, address),
        };

        writer.write_json(&json, &report)?;
        writer.write(&asm, listing_text(image, address, &disassembly).as_bytes())?;

        index.push(IndexFunctionJson {
            address,
            address_hex: format!("{address:#x}"),
            name: function.name.clone(),
            section: disassembly.section.clone(),
            blocks: report.cfg.block_count(),
            lifted: report.pseudocode.lifted,
            json,
            asm,
        });
    }

    let written = utc_stamp(SystemTime::now());
    let index = IndexJson {
        version: LAYOUT_VERSION,
        binary: binary_path.display().to_string(),
        sha256,
        ag_version: env!("CARGO_PKG_VERSION"),
        language: image.language().to_string(),
        entry: image.entry(),
        entry_hex: image.entry().map(|entry| format!("{entry:#x}")),
        written,
        functions_filter: functions.map(str::to_string),
        options: image
            .options()
            .changed()
            .into_iter()
            .map(|(name, value)| OptionJson { name, value })
            .collect(),
        files: IndexFilesJson {
            readme: "README.md",
            info: "info.json",
            symbols: "symbols.json",
            strings: "strings.json",
            data: "data.json",
            calls: "calls.json",
        },
        functions: index,
    };

    writer.write_json("index.json", &index)?;
    writer.write(
        "README.md",
        readme(&index, image.functions().len()).as_bytes(),
    )?;

    println!(
        "wrote {} functions to {}: {} files, {} bytes",
        index.functions.len(),
        dir.display(),
        writer.files,
        writer.bytes
    );

    Ok(0)
}

/// Make the directory, or make sure the one that is there may be written.
fn prepare(dir: &Path, force: bool) -> Result<()> {
    if !dir.exists() {
        return fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()));
    }

    anyhow::ensure!(dir.is_dir(), "{} is not a directory", dir.display());

    let mut entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    anyhow::ensure!(
        force || entries.next().is_none(),
        "{} is not empty; pass --force to write over it",
        dir.display()
    );

    Ok(())
}

/// The README of the export.
///
/// Its first table has a `| Path | … |` row, which is how a kuna project
/// export names its binary, so the reader that finds one finds this.
fn readme(index: &IndexJson, total: usize) -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    let name = Path::new(&index.binary)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| index.binary.clone());

    let _ = writeln!(text, "# {name}");
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "An AdmiralGrace export: the analysis of one program image, written by `ag image export`\n\
         as a directory of JSON and text. Every `.json` is what the matching `ag image` subcommand\n\
         prints under `--json`, and every `.asm` is what `disasm` prints."
    );
    let _ = writeln!(text);
    let _ = writeln!(text, "| | |");
    let _ = writeln!(text, "|---|---|");
    let _ = writeln!(text, "| Path | `{}` |", index.binary);
    let _ = writeln!(text, "| SHA-256 | `{}` |", index.sha256);
    let _ = writeln!(text, "| Language | `{}` |", index.language);
    let _ = writeln!(
        text,
        "| Entry | {} |",
        index
            .entry_hex
            .as_deref()
            .map(|entry| format!("`{entry}`"))
            .unwrap_or_else(|| "none".to_string())
    );
    match &index.functions_filter {
        Some(filter) => {
            let _ = writeln!(
                text,
                "| Functions | {} of {total}, matching `{filter}` |",
                index.functions.len()
            );
        }
        None => {
            let _ = writeln!(text, "| Functions | {} of {total} |", index.functions.len());
        }
    }
    if !index.options.is_empty() {
        let options: Vec<String> = index
            .options
            .iter()
            .map(|option| format!("`--option {} {}`", option.name, option.value))
            .collect();
        let _ = writeln!(text, "| Options | {} |", options.join(" "));
    }
    let _ = writeln!(text, "| ag | {} |", index.ag_version);
    let _ = writeln!(text, "| Written | {} |", index.written);
    let _ = writeln!(text);
    let _ = writeln!(text, "## Files");
    let _ = writeln!(text);
    let _ = writeln!(text, "| File | What it holds |");
    let _ = writeln!(text, "|---|---|");
    for (file, what) in FILES {
        let _ = writeln!(text, "| `{file}` | {what} |");
    }
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "`<address>` is the function's entry address as `ag` prints it, `0x1149`. Every address\n\
         in the JSON is given twice, as a number and as a hex string. `index.json` lists the\n\
         functions that were written, with their files; a function the decoder could not reach\n\
         is not in it."
    );

    text
}

/// The time, as an RFC 3339 stamp in UTC: `2026-10-24T12:34:56Z`.
fn utc_stamp(now: SystemTime) -> String {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let rest = seconds % 86_400;

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// The civil date of a day counted from 1970-01-01.
///
/// Howard Hinnant's algorithm, which is exact for every day of the
/// proleptic Gregorian calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_epoch_is_the_first_of_january_1970() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_known_second_is_stamped_right() {
        let then = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(utc_stamp(then), "2023-11-14T22:13:20Z");

        // The last second of a leap day.
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_251_199);
        assert_eq!(utc_stamp(leap), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn the_readme_names_the_binary_the_way_a_kuna_export_does() {
        let index = IndexJson {
            version: LAYOUT_VERSION,
            binary: "/tmp/sample.elf".to_string(),
            sha256: "ab".repeat(32),
            ag_version: "0.1.0",
            language: "x86:LE:64:default:gcc".to_string(),
            entry: Some(0x1060),
            entry_hex: Some("0x1060".to_string()),
            written: "2026-10-24T00:00:00Z".to_string(),
            functions_filter: Some("main".to_string()),
            options: vec![OptionJson {
                name: "loop-form",
                value: "while".to_string(),
            }],
            files: IndexFilesJson {
                readme: "README.md",
                info: "info.json",
                symbols: "symbols.json",
                strings: "strings.json",
                data: "data.json",
                calls: "calls.json",
            },
            functions: Vec::new(),
        };

        let text = readme(&index, 15);

        assert!(text.starts_with("# sample.elf\n"), "{text}");
        assert!(text.contains("| Path | `/tmp/sample.elf` |"), "{text}");
        assert!(
            text.contains(&format!("| SHA-256 | `{}` |", "ab".repeat(32))),
            "{text}"
        );
        assert!(
            text.contains("| Functions | 0 of 15, matching `main` |"),
            "{text}"
        );
        assert!(text.contains("| ag | 0.1.0 |"), "{text}");
        assert!(
            text.contains("| Options | `--option loop-form while` |"),
            "{text}"
        );
        assert!(text.contains("| `functions/<address>.asm` |"), "{text}");
    }
}
