//! The image commands of the `ag` binary, run against the fixtures.
//!
//! The fixtures are the PE, the Mach-O and the 32-bit ELF in
//! `crates/ag-image/tests/fixtures`, so the commands are read against the
//! containers the loader reads beside the 64-bit ELF, and against the other
//! width of x86; the 64-bit ELF itself is the engine's sample.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture of the given name.
///
/// The 64-bit ELF is the engine's own sample; the other containers are the
/// image crate's.
fn fixture(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = root.join("../ag-image/tests/fixtures").join(name);
    if image.exists() {
        image
    } else {
        root.join("../ag-engine/tests/fixtures").join(name)
    }
}

/// Run `ag image <fixture> <args>` and return whether it succeeded, with
/// what it printed.
fn image_result(name: &str, args: &[&str]) -> (bool, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture(name))
        .args(args)
        .output()
        .expect("the ag binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run `ag image <fixture> <args>` and return what it printed.
fn image(name: &str, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture(name))
        .args(args)
        .output()
        .expect("the ag binary runs");

    assert!(
        output.status.success(),
        "ag image {} {} failed: {}",
        name,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("the report is text")
}

/// Run `ag image <fixture> <args>` and return its JSON report.
fn image_json(name: &str, args: &[&str]) -> serde_json::Value {
    let mut args = args.to_vec();
    args.push("--json");

    let report = image(name, &args);
    serde_json::from_str(&report).expect("the report is JSON")
}

#[test]
fn the_info_of_a_pe_names_its_language_and_sections() {
    let report = image("sample.exe", &["info"]);

    assert!(report.contains("x86:LE:64:default:windows"), "{report}");
    assert!(report.contains(".text"), "{report}");
    assert!(report.contains("exec=yes"), "{report}");
}

#[test]
fn the_symbols_of_a_pe_name_its_functions() {
    let report = image("sample.exe", &["symbols"]);

    assert!(report.contains("add"), "{report}");
    assert!(report.contains("main"), "{report}");
}

#[test]
fn the_disassembly_of_a_pe_is_reported() {
    let report = image("sample.exe", &["disasm", "main"]);

    assert!(report.contains("; main at 0x140001020"), "{report}");
    assert!(report.contains("call"), "{report}");
}

#[test]
fn the_info_of_a_pe_is_reported_as_json() {
    let report = image_json("sample.exe", &["info"]);

    assert_eq!(
        report["language"],
        serde_json::json!("x86:LE:64:default:windows")
    );
    assert_eq!(report["entry_hex"], serde_json::json!("0x140001020"));

    let sections = report["sections"].as_array().expect("the sections");
    assert!(
        sections.iter().any(|section| section["name"] == ".text"),
        "{report}"
    );
}

#[test]
fn the_info_of_a_macho_names_its_language_and_sections() {
    let report = image("sample.macho", &["info"]);

    assert!(report.contains("x86:LE:64:default:gcc"), "{report}");
    assert!(report.contains("__text"), "{report}");
    assert!(report.contains("exec=yes"), "{report}");
}

#[test]
fn the_symbols_of_a_macho_name_its_functions() {
    let report = image("sample.macho", &["symbols"]);

    // A Mach-O names its symbols with a leading underscore.
    assert!(report.contains("_add"), "{report}");
    assert!(report.contains("_main"), "{report}");
}

#[test]
fn the_disassembly_of_a_macho_is_reported() {
    let report = image("sample.macho", &["disasm", "_main"]);

    assert!(report.contains("; _main at 0x100000440"), "{report}");
    assert!(report.contains("call"), "{report}");
}

#[test]
fn the_disassembly_of_a_macho_is_reported_as_json() {
    let report = image_json("sample.macho", &["disasm", "_main"]);

    assert_eq!(report["name"], serde_json::json!("_main"));
    assert_eq!(report["function_hex"], serde_json::json!("0x100000440"));

    let blocks = report["blocks"].as_array().expect("the blocks");
    assert!(!blocks.is_empty(), "{report}");
}

#[test]
fn a_target_that_names_nothing_in_a_pe_is_an_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.exe"))
        .args(["disasm", "nowhere"])
        .output()
        .expect("the ag binary runs");

    assert!(!output.status.success(), "the command fails");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("no function matching"), "{error}");
}

// ---- The 32-bit ELF -------------------------------------------------------
//
// The width of the code comes from the image's language, so a 32-bit image
// gets the same reports as a 64-bit one: the listing names 32-bit registers,
// and the data is found through the absolute operands 32-bit code uses.

#[test]
fn the_info_of_a_32_bit_elf_names_its_language_and_sections() {
    let report = image("sample32.elf", &["info"]);

    assert!(report.contains("x86:LE:32:default:gcc"), "{report}");
    assert!(report.contains("0x804900d"), "the entry point: {report}");
    assert!(report.contains(".text"), "{report}");
    assert!(report.contains("exec=yes"), "{report}");
}

#[test]
fn the_info_of_a_32_bit_elf_is_reported_as_json() {
    let report = image_json("sample32.elf", &["info"]);

    assert_eq!(
        report["language"],
        serde_json::json!("x86:LE:32:default:gcc")
    );
    assert_eq!(report["entry_hex"], serde_json::json!("0x804900d"));

    let sections = report["sections"].as_array().expect("the sections");
    assert!(
        sections.iter().any(|section| section["name"] == ".data"),
        "{report}"
    );
}

#[test]
fn the_symbols_of_a_32_bit_elf_name_its_functions_and_its_data() {
    let report = image("sample32.elf", &["symbols"]);

    assert!(report.contains("0x8049000 add"), "{report}");
    assert!(report.contains("0x804900d main"), "{report}");
    assert!(report.contains("0x804b008 counter size=4"), "{report}");
    assert!(report.contains("0x804b00c greeting size=4"), "{report}");

    let report = image_json("sample32.elf", &["symbols", "--filter", "^add$"]);
    let functions = report["functions"].as_array().expect("the functions");
    assert_eq!(functions.len(), 1, "{report}");
    assert_eq!(functions[0]["address_hex"], serde_json::json!("0x8049000"));
}

#[test]
fn the_disassembly_of_a_32_bit_elf_names_32_bit_registers() {
    let report = image("sample32.elf", &["disasm", "add"]);

    assert!(report.contains("; add at 0x8049000"), "{report}");
    assert!(report.contains("push ebp"), "{report}");
    assert!(report.contains("mov ebp,esp"), "{report}");
    assert!(report.contains("mov edx,[ebp+8]"), "{report}");
    assert!(
        !report.contains("rbp"),
        "no 64-bit register in 32-bit code: {report}"
    );
}

#[test]
fn the_disassembly_of_a_32_bit_elf_is_reported_as_json() {
    let report = image_json("sample32.elf", &["disasm", "main"]);

    assert_eq!(report["name"], serde_json::json!("main"));
    assert_eq!(report["function_hex"], serde_json::json!("0x804900d"));

    let blocks = report["blocks"].as_array().expect("the blocks");
    assert_eq!(blocks.len(), 5, "{report}");

    let calls = report["calls"].as_array().expect("the calls");
    assert_eq!(calls.len(), 1, "{report}");
    assert_eq!(calls[0]["name"], serde_json::json!("add"));
    assert_eq!(calls[0]["target_hex"], serde_json::json!("0x8049000"));
}

#[test]
fn the_cfg_of_the_start_up_glue_stops_at_the_hlt() {
    // _start calls __libc_start_main and then halts; the nop padding and
    // deregister_tm_clones after the hlt are not its blocks. The call ends
    // a block of its own, so the hlt is the second.
    let report = image("sample.elf", &["cfg", "_start"]);

    assert!(report.contains("blocks: 2\nedges: 1\n"), "{report}");
    assert!(
        report.contains("block 0x1085 - 0x1086\n  successors: -\n  instructions: 0x1085\n"),
        "{report}"
    );
    assert!(!report.contains("0x1090"), "{report}");
    assert!(!report.contains("0x10b8"), "{report}");

    // The flag of the runtime is deregister_tm_clones's to read, not _start's.
    let report = image("sample.elf", &["data", "completed.0"]);
    assert!(!report.contains("_start"), "{report}");
    assert!(report.contains("deregister_tm_clones"), "{report}");
}

#[test]
fn the_cfg_of_a_function_that_tail_calls_another_stops_at_the_jump() {
    // frame_dummy is endbr64; jmp register_tm_clones: its graph is its one
    // block, not register_tm_clones' blocks after it.
    let report = image("sample.elf", &["cfg", "frame_dummy"]);

    assert!(report.contains("blocks: 1\nedges: 0\n"), "{report}");
    assert!(report.contains("block 0x1140 - 0x1149\n"), "{report}");
    assert!(
        report.contains("  instructions: 0x1140 0x1144\n"),
        "{report}"
    );
    assert!(!report.contains("0x10c0"), "{report}");

    let report = image_json("sample.elf", &["cfg", "frame_dummy"]);
    assert_eq!(report["blocks"].as_array().expect("the blocks").len(), 1);
    assert_eq!(report["edges"].as_array().expect("the edges").len(), 0);

    // The listing stops there too, and the call is still reported.
    let report = image("sample.elf", &["disasm", "frame_dummy"]);
    assert!(report.contains("; block 0x1140\n"), "{report}");
    assert!(!report.contains("0x10c0 "), "{report}");
    let report = image("sample.elf", &["calls", "frame_dummy"]);
    assert!(
        report.contains("  0x1144 -> 0x10c0 register_tm_clones (tail call)\n"),
        "{report}"
    );
}

#[test]
fn the_cfg_is_drawn_as_svg_and_pdf_when_asked() {
    let stem = std::env::temp_dir().join(format!(
        "ag-cli-cfg-picture-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let svg = stem.with_extension("svg");
    let pdf = stem.with_extension("pdf");
    let report = image(
        "sample.elf",
        &[
            "cfg",
            "main",
            "--svg",
            svg.to_str().unwrap(),
            "--pdf",
            pdf.to_str().unwrap(),
        ],
    );
    assert!(
        report.contains(&format!("wrote {}", svg.display())),
        "{report}"
    );
    assert!(
        report.contains(&format!("wrote {}", pdf.display())),
        "{report}"
    );
    // The pictures stand in for the report of the blocks.
    assert!(!report.contains("block 0x"), "{report}");

    let json = image_json("sample.elf", &["cfg", "main"]);
    let blocks = json["blocks"].as_array().expect("blocks").len();
    let text = std::fs::read_to_string(&svg).expect("the SVG");
    assert!(text.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
    assert_eq!(text.matches("<rect x=").count(), blocks, "{text}");
    assert!(text.contains("<title>main at "), "{text}");
    let bytes = std::fs::read(&pdf).expect("the PDF");
    assert!(bytes.starts_with(b"%PDF-1.4"));
    assert!(bytes.ends_with(b"%%EOF\n"));
    let _ = std::fs::remove_file(&svg);
    let _ = std::fs::remove_file(&pdf);
    // A picture and the JSON report are not asked for together.
    let (ok, _, stderr) = image_result(
        "sample.elf",
        &["cfg", "main", "--json", "--svg", stem.to_str().unwrap()],
    );
    assert!(!ok);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(!stem.exists());
}

#[test]
fn the_cfg_of_a_32_bit_elf_has_its_loop() {
    let report = image("sample32.elf", &["cfg", "main"]);

    assert!(report.contains("block 0x8049038 - 0x804903e"), "{report}");
    assert!(report.contains("0x8049038 -> 0x8049023 taken"), "{report}");
    assert!(
        report.contains("0x8049038 -> 0x804903e fall-through"),
        "{report}"
    );

    let report = image_json("sample32.elf", &["cfg", "main"]);
    let edges = report["edges"].as_array().expect("the edges");
    assert!(
        edges.iter().any(|edge| {
            edge["from_hex"] == "0x8049038"
                && edge["to_hex"] == "0x8049023"
                && edge["kind"] == "taken"
        }),
        "{report}"
    );
}

#[test]
fn the_calls_of_a_32_bit_elf_say_main_calls_add() {
    let report = image("sample32.elf", &["calls", "add"]);
    assert!(
        report.contains("0x804900d main"),
        "main calls add: {report}"
    );

    let report = image_json("sample32.elf", &["calls"]);
    let functions = report["functions"].as_array().expect("the functions");
    let main = functions
        .iter()
        .find(|function| function["name"] == "main")
        .expect("main is in the call graph");
    let callees: Vec<&str> = main["calls"]
        .as_array()
        .expect("the calls of main")
        .iter()
        .filter_map(|call| call["name"].as_str())
        .collect();
    assert_eq!(callees, vec!["add"], "{report}");
}

#[test]
fn the_strings_of_a_32_bit_elf_are_reported() {
    let report = image("sample32.elf", &["strings"]);
    assert!(report.contains("0x804a000 .rodata \"hello\""), "{report}");

    let report = image_json("sample32.elf", &["strings", "--filter", "hello"]);
    let strings = report["strings"].as_array().expect("the strings");
    assert_eq!(strings.len(), 1, "{report}");
    assert_eq!(strings[0]["section"], serde_json::json!(".rodata"));
}

#[test]
fn the_data_of_a_32_bit_elf_is_found_through_absolute_operands() {
    let report = image("sample32.elf", &["data", "main"]);

    assert!(report.contains("0x804b008 .data counter"), "{report}");
    assert!(report.contains("0x804b00c .data greeting"), "{report}");

    let report = image_json("sample32.elf", &["data", "counter"]);
    let users = report["functions"]
        .as_array()
        .expect("the users of counter");
    assert_eq!(users.len(), 1, "{report}");
    assert_eq!(users[0]["name"], serde_json::json!("main"));
}

// ---- Pseudocode -----------------------------------------------------------
//
// The lifter reads straight-line x86-64 code — blocks joined only by
// fall-through — and the `add` of every fixture is one block. The PE passes
// its arguments the Windows way, in rcx and rdx, and the lifter reads that
// from the image's language. The sample ELF's `main` is a chain of blocks cut
// at its calls, and reads as C with them; a function that branches is
// refused at the branch.

#[test]
fn the_pseudocode_of_the_sample_elf_main_is_c_with_its_calls() {
    let report = image("sample.elf", &["pseudocode", "main"]);

    assert_eq!(
        report,
        "// main at 0x1198\n\
         // returns long: no caller in the image, and the function writes rax itself before the ret\n\
         long main(int a, long b)\n\
         {\n\
         \x20 long v2;\n\
         \n\
         \x20 v2 = sum_to(add(a, 3));\n\
         \x20 printf(\"%ld\\n\", v2);\n\
         \x20 return v2;\n\
         }\n"
    );
}

#[test]
fn the_pseudocode_of_the_sample_elf_add_is_c() {
    let report = image("sample.elf", &["pseudocode", "add"]);

    assert_eq!(
        report,
        "// add at 0x1149\n\
         // returns int: main reads eax after the call\n\
         int add(int a, int b)\n{\n  return b + a;\n}\n"
    );
}

#[test]
fn the_pseudocode_of_a_plt_stub_is_a_thunk_line_and_its_call_is_a_tail_call() {
    let report = image("sample.elf", &["pseudocode", "printf"]);
    assert_eq!(report, "// printf at 0x1050\n// thunk for printf\n");

    let report = image("sample.elf", &["pseudocode", "frame_dummy"]);
    assert_eq!(
        report,
        "// frame_dummy at 0x1140\n// thunk for register_tm_clones\n"
    );

    let report = image_json("sample.elf", &["pseudocode", "__cxa_finalize"]);
    assert_eq!(report["lifted"], serde_json::json!(true));
    assert_eq!(
        report["text"],
        serde_json::json!("// thunk for __cxa_finalize")
    );
    let lines = report["lines"].as_array().expect("the lines");
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0]["addresses_hex"],
        serde_json::json!(["0x1040", "0x1044"])
    );

    let report = image("sample.elf", &["calls", "printf"]);
    assert_eq!(
        report,
        "printf at 0x1050\n\
         calls:\n\
         \x20 0x1054 -> 0x3fd0 printf (tail call)\n\
         called by:\n\
         \x20 0x1198 main\n"
    );

    let report = image_json("sample.elf", &["calls", "frame_dummy"]);
    let calls = report["calls"].as_array().expect("the calls");
    assert_eq!(calls.len(), 1, "{report}");
    assert_eq!(calls[0]["name"], serde_json::json!("register_tm_clones"));
    assert_eq!(calls[0]["tail"], serde_json::json!(true));
    assert_eq!(calls[0]["slot"], serde_json::Value::Null);

    let report = image("sample.elf", &["calls"]);
    assert!(
        report.contains("  0x1050 printf -> 0x3fd0 printf (tail call)\n"),
        "{report}"
    );
    assert!(
        report.contains("  0x1140 frame_dummy -> 0x10c0 register_tm_clones (tail call)\n"),
        "{report}"
    );
}

#[test]
fn a_conditional_tail_call_through_a_register_is_lifted() {
    let report = image("sample.elf", &["pseudocode", "deregister_tm_clones"]);
    assert_eq!(
        report,
        "// deregister_tm_clones at 0x1090\n\
         // void: no caller reads the result\n\
         void deregister_tm_clones(void)\n\
         {\n\
         \x20 long rax;\n\
         \n\
         \x20 rax = &completed.0;\n\
         \x20 if (0) { // constant: &completed.0 != &completed.0\n\
         \x20   rax = _ITM_deregisterTMCloneTable;\n\
         \x20   if (rax != 0) {\n\
         \x20     _ITM_deregisterTMCloneTable(&completed.0);\n\
         \x20     return;\n\
         \x20   }\n\
         \x20 }\n\
         \x20 return;\n\
         }\n"
    );

    // The option refuses the jump, naming the callee.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "printf", "--option", "tail-calls", "refuse"])
        .output()
        .expect("the ag binary runs");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "// printf at 0x1050: not lifted yet: a tail call to printf at 0x1054\n"
    );
}

#[test]
fn the_pseudocode_of_the_pe_add_is_c() {
    let report = image("sample.exe", &["pseudocode", "add"]);

    assert_eq!(
        report,
        "// add at 0x140001000\n\
         // returns int: main reads eax after the call\n\
         int add(int a, int b)\n{\n  return a + b;\n}\n"
    );
}

#[test]
fn the_pseudocode_of_the_macho_add_is_c() {
    let report = image("sample.macho", &["pseudocode", "_add"]);

    assert_eq!(
        report,
        "// _add at 0x100000420\n\
         // returns int: _main reads eax after the call\n\
         int _add(int a, int b)\n{\n  return a + b;\n}\n"
    );
}

#[test]
fn the_pseudocode_is_reported_as_json_with_the_addresses_of_each_line() {
    let report = image_json("sample.elf", &["pseudocode", "0x1149"]);

    assert_eq!(report["name"], serde_json::json!("add"));
    assert_eq!(report["lifted"], serde_json::json!(true));
    assert_eq!(
        report["text"],
        serde_json::json!(
            "// returns int: main reads eax after the call\nint add(int a, int b)\n{\n  return b + a;\n}"
        )
    );
    assert_eq!(report["return_type"], serde_json::json!("int"));
    assert_eq!(
        report["return_reason"],
        serde_json::json!("main reads eax after the call")
    );

    let lines = report["lines"].as_array().expect("the lines");
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0]["addresses"], serde_json::json!([]));
    assert_eq!(lines[3]["line"], serde_json::json!(4));
    assert_eq!(lines[3]["text"], serde_json::json!("  return b + a;"));
    let addresses = lines[3]["addresses_hex"].as_array().expect("the addresses");
    assert!(
        addresses.contains(&serde_json::json!("0x115d")),
        "the add is one of them: {addresses:?}"
    );
}

#[test]
fn the_pseudocode_is_printed_sliced_with_the_rest_as_comments_or_left_out() {
    // sum_to's `local_14` at the end: the loop's init, condition and step
    // are its; the sum is not.
    let report = image(
        "sample.elf",
        &["pseudocode", "sum_to", "--slice", "local_14"],
    );
    assert_eq!(
        report,
        "// sum_to at 0x1161\n\
         // backward slice of local_14 at the end\n\
         // returns long: main reads rax after the call\n\
         long sum_to(int a)\n\
         {\n\
         \x20 long local_10;\n\
         \x20 int local_14;\n\
         \n\
         \x20 // local_10 = 0;\n\
         \x20 for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {\n\
         \x20   // local_10 = local_10 + (long)local_14;\n\
         \x20 }\n\
         \x20 // return local_10;\n\
         }\n"
    );

    // ping of the inline fixture, forward from the call's result at one of
    // its line's addresses: the `if` stays for what it holds, the stores
    // before it go.
    let report = image(
        "inline.elf",
        &[
            "pseudocode",
            "ping",
            "--slice",
            "v1@0x401021",
            "--forward",
            "--slice-hide",
        ],
    );
    assert!(
        report.contains("// forward slice of v1 at 0x401021\n"),
        "{report}"
    );
    assert!(!report.contains("local_c = a;"), "{report}");
    assert!(!report.contains("eax = a;"), "{report}");
    assert!(
        report.contains(
            "  if (eax > 0) {\n    v1 = pong(a - 1);\n    local_c = v1 + 1;\n    eax = v1 + 1;\n  }\n  return local_c;\n"
        ),
        "{report}"
    );

    // The return value, backward, as JSON: every line marked.
    let report = image_json("inline.elf", &["pseudocode", "ping", "--slice", "return"]);
    assert_eq!(
        report["slice"],
        serde_json::json!({
            "variable": "return",
            "address": null,
            "address_hex": null,
            "direction": "backward",
        })
    );
    let out: Vec<&str> = report["lines"]
        .as_array()
        .expect("the lines")
        .iter()
        .filter(|line| line["in_slice"] == serde_json::json!(false))
        .map(|line| line["text"].as_str().expect("text").trim())
        .collect();
    assert_eq!(out, ["eax = v1 + 1;"]);
    // Unsliced, the lines say nothing of a slice.
    let report = image_json("inline.elf", &["pseudocode", "ping"]);
    assert!(report.get("slice").is_none());
    assert!(report["lines"][0].get("in_slice").is_none());

    // A variable or a statement the function lacks is said.
    let (ok, _, error) = image_result("sample.elf", &["pseudocode", "main", "--slice", "nothing"]);
    assert!(!ok);
    assert!(error.contains("main names no variable nothing"), "{error}");
    let (ok, _, error) = image_result("sample.elf", &["pseudocode", "main", "--slice", "v2@0x1"]);
    assert!(!ok);
    assert!(error.contains("main has no statement at 0x1"), "{error}");
    let (ok, _, _) = image_result("sample.elf", &["pseudocode", "main", "--forward"]);
    assert!(!ok, "--forward needs --slice");
}

#[test]
fn the_start_up_glue_is_void_by_use_and_the_option_restores_the_refusal() {
    let report = image("sample.elf", &["pseudocode", "__do_global_dtors_aux"]);
    assert_eq!(
        report,
        "// __do_global_dtors_aux at 0x1100\n\
         // void: no caller in the image, and rax at the ret holds only deregister_tm_clones's result, which nothing reads\n\
         void __do_global_dtors_aux(void)\n\
         {\n\
         \x20 if (completed.0 != 0) {\n\
         \x20   return;\n\
         \x20 }\n\
         \x20 if (__cxa_finalize != 0) {\n\
         \x20   __cxa_finalize(*(long *)0x4008);\n\
         \x20 }\n\
         \x20 deregister_tm_clones();\n\
         \x20 completed.0 = 1;\n\
         \x20 return;\n\
         }\n"
    );

    // `return-liveness presence` decides from the value in rax alone, and
    // the two paths disagree, as they always did.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args([
            "pseudocode",
            "__do_global_dtors_aux",
            "--option",
            "return-liveness",
            "presence",
        ])
        .output()
        .expect("the ag binary runs");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "// __do_global_dtors_aux at 0x1100: not lifted yet: returns a value at one ret and \
         nothing at another\n"
    );
}

#[test]
fn a_function_the_lifter_refuses_is_reported_with_the_reason() {
    // register_tm_clones shifts right, which the lifter does not read.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "register_tm_clones"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(1), "nothing was lifted");
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        report,
        "// register_tm_clones at 0x10c0: not lifted yet: shr\n"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "register_tm_clones", "--json"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["lifted"], serde_json::json!(false));
    assert_eq!(
        report["reason"],
        serde_json::json!("not lifted yet: shr")
    );
    assert_eq!(report["text"], serde_json::Value::Null);
}

#[test]
fn a_loop_is_lifted_as_a_for() {
    // sum_to counts from 1 to its argument into an accumulator.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "sum_to"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(0), "sum_to lifts");
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        report,
        "// sum_to at 0x1161\n\
         // returns long: main reads rax after the call\n\
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
         }\n"
    );
}

#[test]
fn a_32_bit_function_is_not_lifted_yet() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample32.elf"))
        .args(["pseudocode", "add"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(1));
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(report, "// add at 0x8049000: not lifted yet: 32-bit code\n");
}

// ---- Export ---------------------------------------------------------------
//
// `export` writes what the other subcommands print, as a directory, in one
// pass. The files are the same JSON the subcommands print under `--json`,
// built by the same code, so a check of one against the other is a check
// that the export is not a second implementation.

/// A directory for one export, cleaned up when the test is done.
struct ExportDir(PathBuf);

impl ExportDir {
    fn new(tag: &str) -> ExportDir {
        let path = std::env::temp_dir().join(format!(
            "ag-export-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        ExportDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Every file under the directory, relative to it, sorted.
    fn files(&self) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("the directory reads") {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let relative = path.strip_prefix(root).expect("under the root");
                    out.push(relative.to_string_lossy().replace('\\', "/"));
                }
            }
        }

        let mut files = Vec::new();
        walk(&self.0, &self.0, &mut files);
        files.sort();
        files
    }

    /// One JSON file of the export, parsed.
    fn json(&self, relative: &str) -> serde_json::Value {
        let text = std::fs::read_to_string(self.0.join(relative))
            .unwrap_or_else(|error| panic!("{relative} reads: {error}"));
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{relative} is JSON: {error}"))
    }
}

impl Drop for ExportDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `ag image <fixture> export <dir> <args>`, and return what it printed
/// and whether it succeeded.
fn export(name: &str, dir: &ExportDir, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture(name))
        .arg("export")
        .arg(dir.path())
        .args(args)
        .output()
        .expect("the ag binary runs");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The whole-image files every export holds.
const WHOLE_IMAGE_FILES: &[&str] = &[
    "README.md",
    "calls.json",
    "data.json",
    "index.json",
    "info.json",
    "strings.json",
    "symbols.json",
];

#[test]
fn an_export_of_the_elf_writes_the_whole_analysis() {
    let dir = ExportDir::new("elf");
    let (ok, stdout, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    // One line: the functions, the files and the bytes.
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.starts_with("wrote 12 functions to "), "{stdout}");
    assert!(stdout.contains(" files, "), "{stdout}");
    assert!(stdout.trim_end().ends_with(" bytes"), "{stdout}");

    let files = dir.files();
    for file in WHOLE_IMAGE_FILES {
        assert!(
            files.contains(&file.to_string()),
            "{file} is missing: {files:?}"
        );
    }
    assert!(
        files.contains(&"functions/0x1149.json".to_string()),
        "{files:?}"
    );
    assert!(
        files.contains(&"functions/0x1149.asm".to_string()),
        "{files:?}"
    );
    assert!(
        files.contains(&"functions/0x1198.json".to_string()),
        "{files:?}"
    );
    assert!(
        files.contains(&"functions/0x1198.asm".to_string()),
        "{files:?}"
    );

    // Every function of the image has its pair, and the index lists each.
    let index = dir.json("index.json");
    let functions = index["functions"].as_array().expect("the functions");
    assert_eq!(functions.len(), 12, "{index}");
    for function in functions {
        let json = function["json"].as_str().expect("the json path");
        let asm = function["asm"].as_str().expect("the asm path");
        assert!(files.contains(&json.to_string()), "{json} is missing");
        assert!(files.contains(&asm.to_string()), "{asm} is missing");
    }
    assert_eq!(files.len(), WHOLE_IMAGE_FILES.len() + 2 * 12, "{files:?}");

    assert_eq!(index["version"], serde_json::json!(1));
    assert_eq!(
        index["ag_version"],
        serde_json::json!(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        index["language"],
        serde_json::json!("x86:LE:64:default:gcc")
    );
    assert_eq!(index["entry_hex"], serde_json::json!("0x1060"));
    assert_eq!(index["functions_filter"], serde_json::Value::Null);
    assert_eq!(
        index["sha256"],
        serde_json::json!("055b65d2704a9d2468dedd027f7154c8de1fc4c3040171344627050183474849")
    );
    let written = index["written"].as_str().expect("the time");
    assert!(
        written.len() == 20 && written.ends_with('Z') && &written[10..11] == "T",
        "an RFC 3339 UTC stamp: {written}"
    );
    assert!(
        index["binary"]
            .as_str()
            .expect("the binary")
            .ends_with("sample.elf"),
        "{index}"
    );
}

#[test]
fn an_export_of_an_objective_c_image_writes_its_header_and_the_rest_do_not() {
    let dir = ExportDir::new("objc");
    let (ok, _, stderr) = export("sample_objc_stripped", &dir, &[]);
    assert!(ok, "{stderr}");
    let files = dir.files();
    assert!(files.contains(&"objc.h".to_string()), "{files:?}");
    assert!(files.contains(&"objc.json".to_string()), "{files:?}");
    let header = std::fs::read_to_string(dir.path().join("objc.h")).expect("objc.h");
    assert_eq!(header, image("sample_objc_stripped", &["objc", "--header"]));
    assert_eq!(
        dir.json("objc.json")["classes"][1]["name"],
        serde_json::json!("Derived")
    );
    let readme = std::fs::read_to_string(dir.path().join("README.md")).expect("README");
    assert!(readme.contains("objc.h"), "{readme}");

    let dir = ExportDir::new("elf-no-objc");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");
    let files = dir.files();
    assert!(
        !files.iter().any(|file| file.starts_with("objc.")),
        "{files:?}"
    );
    assert!(!files.contains(&"swift.json".to_string()), "{files:?}");

    let dir = ExportDir::new("swift");
    let (ok, _, stderr) = export("sample_swift_x86", &dir, &[]);
    assert!(ok, "{stderr}");
    assert!(dir.files().contains(&"swift.json".to_string()));
    assert_eq!(
        dir.json("swift.json")["types"][0]["name"],
        serde_json::json!("sample.Point")
    );
}

#[test]
fn the_info_of_an_export_is_what_the_subcommand_prints() {
    let dir = ExportDir::new("info");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    assert_eq!(dir.json("info.json"), image_json("sample.elf", &["info"]));
    assert_eq!(
        dir.json("symbols.json"),
        image_json("sample.elf", &["symbols"])
    );
    assert_eq!(
        dir.json("strings.json"),
        image_json("sample.elf", &["strings"])
    );
    assert_eq!(dir.json("data.json"), image_json("sample.elf", &["data"]));
    assert_eq!(dir.json("calls.json"), image_json("sample.elf", &["calls"]));
}

#[test]
fn a_function_of_an_export_names_itself_and_holds_the_four_reports() {
    let dir = ExportDir::new("function");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    let add = dir.json("functions/0x1149.json");
    assert_eq!(add["name"], serde_json::json!("add"));
    assert_eq!(add["function_hex"], serde_json::json!("0x1149"));
    assert_eq!(add["section"], serde_json::json!(".text"));

    // Each member is the report the subcommand prints.
    assert_eq!(add["cfg"], image_json("sample.elf", &["cfg", "add"]));
    assert_eq!(add["calls"], image_json("sample.elf", &["calls", "add"]));
    assert_eq!(add["data"], image_json("sample.elf", &["data", "add"]));
    assert_eq!(
        add["pseudocode"],
        image_json("sample.elf", &["pseudocode", "add"])
    );
    assert_eq!(add["pseudocode"]["lifted"], serde_json::json!(true));

    // A function with a loop is lifted too.
    let sum_to = dir.json("functions/0x1161.json");
    assert_eq!(sum_to["name"], serde_json::json!("sum_to"));
    assert_eq!(sum_to["pseudocode"]["lifted"], serde_json::json!(true));

    // A function the lifter refuses carries the reason instead.
    let init = dir.json("functions/0x10c0.json");
    assert_eq!(init["name"], serde_json::json!("register_tm_clones"));
    assert_eq!(init["pseudocode"]["lifted"], serde_json::json!(false));
    assert_eq!(
        init["pseudocode"]["reason"],
        serde_json::json!("not lifted yet: shr")
    );

    // The listing is what `disasm` prints.
    let listing =
        std::fs::read_to_string(dir.path().join("functions/0x1149.asm")).expect("the asm");
    assert_eq!(listing, image("sample.elf", &["disasm", "add"]));
    assert!(
        listing.starts_with("; add at 0x1149 in .text\n"),
        "{listing}"
    );
}

#[test]
fn the_functions_of_an_export_can_be_limited_by_a_regular_expression() {
    let dir = ExportDir::new("filter");
    let (ok, stdout, stderr) = export("sample.elf", &dir, &["--functions", "^(main|add)$"]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("wrote 2 functions to "), "{stdout}");

    let files = dir.files();
    let per_function: Vec<&String> = files
        .iter()
        .filter(|file| file.starts_with("functions/"))
        .collect();
    assert_eq!(
        per_function,
        vec![
            "functions/0x1149.asm",
            "functions/0x1149.json",
            "functions/0x1198.asm",
            "functions/0x1198.json"
        ],
        "{files:?}"
    );

    let index = dir.json("index.json");
    assert_eq!(index["functions_filter"], serde_json::json!("^(main|add)$"));
    let names: Vec<&str> = index["functions"]
        .as_array()
        .expect("the functions")
        .iter()
        .filter_map(|function| function["name"].as_str())
        .collect();
    assert_eq!(names, vec!["add", "main"]);

    // The whole-image files are never limited.
    assert_eq!(
        dir.json("symbols.json"),
        image_json("sample.elf", &["symbols"])
    );

    let readme = std::fs::read_to_string(dir.path().join("README.md")).expect("the README");
    assert!(
        readme.contains("| Functions | 2 of 12, matching `^(main|add)$` |"),
        "{readme}"
    );
}

#[test]
fn a_bad_regular_expression_is_an_error_before_anything_is_written() {
    let dir = ExportDir::new("bad-regex");
    let (ok, _, stderr) = export("sample.elf", &dir, &["--functions", "("]);
    assert!(!ok, "the command fails");
    assert!(stderr.contains("regex"), "{stderr}");
    assert!(!dir.path().exists(), "nothing was written");
}

#[test]
fn a_directory_that_is_not_empty_is_refused_without_force() {
    let dir = ExportDir::new("refuse");
    std::fs::create_dir_all(dir.path()).expect("the directory");
    std::fs::write(dir.path().join("keep.txt"), "mine").expect("a file");

    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(!ok, "the command fails");
    assert!(stderr.contains("is not empty"), "{stderr}");
    assert!(stderr.contains("--force"), "{stderr}");
    assert_eq!(dir.files(), vec!["keep.txt"], "nothing was written");

    let (ok, _, stderr) = export("sample.elf", &dir, &["--force"]);
    assert!(ok, "{stderr}");
    let files = dir.files();
    assert!(
        files.contains(&"keep.txt".to_string()),
        "nothing is removed: {files:?}"
    );
    assert!(files.contains(&"index.json".to_string()), "{files:?}");
}

#[test]
fn the_readme_of_an_export_names_the_binary_its_hash_and_the_version() {
    let dir = ExportDir::new("readme");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    let readme = std::fs::read_to_string(dir.path().join("README.md")).expect("the README");
    assert!(readme.starts_with("# sample.elf\n"), "{readme}");
    assert!(readme.contains("| Path | `"), "{readme}");
    assert!(
        readme.contains("055b65d2704a9d2468dedd027f7154c8de1fc4c3040171344627050183474849"),
        "{readme}"
    );
    assert!(
        readme.contains("| Language | `x86:LE:64:default:gcc` |"),
        "{readme}"
    );
    assert!(
        readme.contains(&format!("| ag | {} |", env!("CARGO_PKG_VERSION"))),
        "{readme}"
    );
    assert!(
        readme.contains("| `functions/<address>.json` |"),
        "{readme}"
    );
    assert!(readme.contains("| `functions/<address>.asm` |"), "{readme}");
}

#[test]
fn an_export_of_the_pe_the_macho_and_the_32_bit_elf_writes_each_function() {
    for (name, main, language) in [
        ("sample.exe", "0x140001020", "x86:LE:64:default:windows"),
        ("sample.macho", "0x100000440", "x86:LE:64:default:gcc"),
        ("sample32.elf", "0x804900d", "x86:LE:32:default:gcc"),
    ] {
        let dir = ExportDir::new(name);
        let (ok, stdout, stderr) = export(name, &dir, &[]);
        assert!(ok, "{name}: {stderr}");
        assert!(stdout.starts_with("wrote "), "{name}: {stdout}");

        let files = dir.files();
        for file in WHOLE_IMAGE_FILES {
            assert!(
                files.contains(&file.to_string()),
                "{name}: {file} is missing: {files:?}"
            );
        }
        assert!(
            files.contains(&format!("functions/{main}.json")),
            "{name}: {files:?}"
        );
        assert!(
            files.contains(&format!("functions/{main}.asm")),
            "{name}: {files:?}"
        );

        let index = dir.json("index.json");
        assert_eq!(index["language"], serde_json::json!(language), "{name}");
        assert_eq!(dir.json("info.json"), image_json(name, &["info"]), "{name}");

        let function = dir.json(&format!("functions/{main}.json"));
        assert_eq!(function["function_hex"], serde_json::json!(main), "{name}");
        assert_eq!(function["cfg"], image_json(name, &["cfg", main]), "{name}");
        assert!(
            function["name"].as_str().expect("a name").contains("main"),
            "{name}: {function}"
        );
    }
}

#[test]
fn the_cfg_of_a_switch_holds_every_case_the_jump_table_names() {
    // classify jumps through an absolute table of six 8-byte entries; the
    // block that jumps goes to every case, and the report says so.
    let report = image("switch.elf", &["cfg", "classify"]);
    assert!(report.contains("blocks: 9\n"), "{report}");
    assert!(
        report.contains(
            "block 0x401005 - 0x40100e\n  successors: 0x40100e, 0x401033, 0x401014, 0x40101b, 0x401021, 0x401027\n"
        ),
        "{report}"
    );
    assert!(
        report.contains("switches:\n  jmp at 0x401007: table 0x402000, 6 entries of 8 bytes\n"),
        "{report}"
    );
    assert!(
        report.contains("    case 0 -> 0x40100e\n    case 1 -> 0x401033\n"),
        "{report}"
    );
    assert!(report.contains("    case 5 -> 0x401027\n"), "{report}");

    let report = image_json("switch.elf", &["cfg", "classify"]);
    let switches = report["switches"].as_array().expect("the switches");
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0]["site"], serde_json::json!(0x401007));
    assert_eq!(switches[0]["cases"].as_array().map(Vec::len), Some(6));

    // The position-independent build reads offsets from the table.
    let report = image("switch_pie.elf", &["cfg", "classify"]);
    assert!(
        report.contains(
            "jmp at 0x1015: table 0x2000, 6 entries of 4 bytes, offsets from the table\n"
        ),
        "{report}"
    );
    assert!(report.contains("    case 1 -> 0x103c\n"), "{report}");
}

#[test]
fn the_pseudocode_of_a_switch_prints_its_cases() {
    // The guard the compiler put before the table is an early return, and
    // the table is a switch on the zero-extended index; each case returns.
    let expected = "{\n\
         \x20 if ((unsigned int)a > 5) {\n\
         \x20   return;\n\
         \x20 }\n\
         \x20 switch ((unsigned long)(unsigned int)a) {\n\
         \x20 case 0:\n\
         \x20   return;\n\
         \x20 case 1:\n\
         \x20   return;\n\
         \x20 case 2:\n\
         \x20   return;\n\
         \x20 case 3:\n\
         \x20   return;\n\
         \x20 case 4:\n\
         \x20   return;\n\
         \x20 case 5:\n\
         \x20   return;\n\
         \x20 }\n\
         }\n";
    let report = image("switch.elf", &["pseudocode", "classify"]);
    assert!(report.starts_with("// classify at 0x401000\n"), "{report}");
    assert!(report.ends_with(expected), "{report}");

    // The position-independent build reads the same switch.
    let report = image("switch_pie.elf", &["pseudocode", "classify"]);
    assert!(report.starts_with("// classify at 0x1000\n"), "{report}");
    assert!(report.ends_with(expected), "{report}");
}

#[test]
fn a_switch_whose_cases_start_above_zero_keeps_the_sources_values() {
    // gcc brings the first case to zero with `sub edi, 3` before the guard;
    // the cases are 3..8 in the source, and the switch says so on `a`.
    let report = image("switch_sub.elf", &["pseudocode", "classify"]);
    assert!(
        report.contains("switch ((unsigned long)(unsigned int)a) {\n"),
        "{report}"
    );
    assert!(report.contains("  case 3:\n"), "{report}");
    assert!(report.contains("  case 8:\n"), "{report}");
    assert!(!report.contains("case 0:"), "{report}");
    assert!(!report.contains("case 9:"), "{report}");
    let report = image("switch_sub.elf", &["cfg", "classify"]);
    assert!(report.contains("    case 3 -> 0x401011\n"), "{report}");

    // A switch inside a loop lifts, and no arm leaves the loop with a
    // `break` that would only leave the switch.
    let report = image("switch_loop.elf", &["pseudocode", "scan"]);
    assert!(
        report.contains("switch ((unsigned long)(unsigned int)(edx_2 & 7)) {\n"),
        "{report}"
    );
    assert!(report.contains("do {\n"), "{report}");
}

#[test]
fn the_analysis_options_bound_procedures_and_find_the_unnamed_ones() {
    // main jumps into helper's tail: by default that is main's own block.
    let report = image("boundaries.elf", &["cfg", "main"]);
    assert!(report.contains("blocks: 2\n"), "{report}");
    assert!(report.contains("block 0x40100c - 0x40100d\n"), "{report}");

    // Told that branches end procedures, the jump is a tail call.
    let report = image(
        "boundaries.elf",
        &["cfg", "main", "--option", "branches-end-procedures", "yes"],
    );
    assert!(report.contains("blocks: 1\n"), "{report}");
    assert!(!report.contains("0x40100c - "), "{report}");
    let report = image(
        "boundaries.elf",
        &[
            "calls",
            "main",
            "--option",
            "branches-end-procedures",
            "yes",
        ],
    );
    assert!(
        report.contains("0x40100c") && report.contains("tail call"),
        "{report}"
    );

    // The routine after the padding that nothing names is a procedure only
    // when the code sections are said to hold nothing else.
    let report = image("boundaries.elf", &["symbols"]);
    assert!(!report.contains("sub_401010"), "{report}");
    let report = image(
        "boundaries.elf",
        &["symbols", "--option", "code-sections", "procedures"],
    );
    assert!(report.contains("0x401010 sub_401010\n"), "{report}");
    assert!(
        !report.contains("0x40100d"),
        "the padding starts no procedure: {report}"
    );
    assert!(
        !report.contains("0x40100c sub_"),
        "the shared ret is helper's: {report}"
    );
    let report = image(
        "boundaries.elf",
        &[
            "pseudocode",
            "sub_401010",
            "--option",
            "code-sections",
            "procedures",
        ],
    );
    assert!(report.contains("// sub_401010 at 0x401010\n"), "{report}");
}

#[test]
fn a_branch_that_leaves_lifts_by_address_and_padding_starts_no_procedure() {
    // Under the option main's jump into helper's tail is a tail call to a
    // routine the image names nothing at: lifted by its address.
    let report = image(
        "boundaries.elf",
        &[
            "pseudocode",
            "main",
            "--option",
            "branches-end-procedures",
            "yes",
        ],
    );
    assert!(report.contains("sub_40100c("), "{report}");

    // Both options together: the same list, the same lift.
    let report = image(
        "boundaries.elf",
        &[
            "symbols",
            "--option",
            "branches-end-procedures",
            "yes",
            "--option",
            "code-sections",
            "procedures",
        ],
    );
    assert!(report.contains("0x401010 sub_401010\n"), "{report}");
    assert!(!report.contains("0x40100c sub_"), "{report}");

    // 32-bit GNU padding — `lea esi, [esi+0]` — starts no procedure either.
    let report = image(
        "boundaries32.elf",
        &["symbols", "--option", "code-sections", "procedures"],
    );
    assert!(report.contains("0x8049010 sub_8049010\n"), "{report}");
    assert!(!report.contains("0x804900d"), "{report}");
}

#[test]
fn ag_asm_prints_the_bytes_of_an_instruction() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["asm", "jmp 0x401010", "--at", "0x401000"])
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "EB 0E\n");

    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["asm", "mov eax, [ebp+8]", "--bits", "32"])
        .output()
        .expect("the ag binary runs");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "8B 45 08\n");

    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["asm", "frob eax"])
        .output()
        .expect("the ag binary runs");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not assembled"));
}

#[test]
fn an_arm_object_is_decoded_in_thumb_and_arm_and_the_project_switches_the_mode() {
    let report = image("arm_thumb.elf", &["info"]);
    assert!(report.contains("language: ARM:LE:32"), "{report}");
    let report = image("arm_thumb.elf", &["symbols"]);
    assert!(
        report.contains("0x20000 add\n"),
        "the Thumb bit is not the address: {report}"
    );
    assert!(report.contains("0x20038 other_mode\n"), "{report}");

    // Thumb: the two-byte add and the return, as SLEIGH spells them.
    let report = image("arm_thumb.elf", &["disasm", "add"]);
    assert!(report.contains("add r0,r1"), "{report}");
    assert!(report.contains("bx lr"), "{report}");
    let report = image("arm_thumb.elf", &["disasm", "sum"]);
    assert!(report.contains("bl "), "sum calls add: {report}");
    let report = image("arm_thumb.elf", &["cfg", "sum"]);
    assert!(
        report.lines().filter(|line| line.contains("->")).count() >= 2,
        "sum loops: {report}"
    );
    let report = image("arm_thumb.elf", &["calls"]);
    assert!(report.contains("add"), "{report}");

    // ARM throughout: every instruction four bytes.
    let report = image("arm_arm.elf", &["disasm", "add", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&report).expect("JSON");
    let lengths: Vec<usize> = json["blocks"]
        .as_array()
        .expect("blocks")
        .iter()
        .flat_map(|block| block["instructions"].as_array().expect("instructions"))
        .map(|line| {
            line["bytes"]
                .as_str()
                .expect("bytes")
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .count()
                / 2
        })
        .collect();
    assert!(
        !lengths.is_empty() && lengths.iter().all(|len| *len == 4),
        "{lengths:?}"
    );

    // The pseudocode is refused by name, not printed as nonsense.
    let (ok, stdout, stderr) = image_result("arm_thumb.elf", &["pseudocode", "add"]);
    assert!(!ok || stdout.contains("ARM"), "{stdout}{stderr}");
}

#[test]
fn an_aarch64_executable_is_decoded_walked_and_listed() {
    let report = image("arm64.elf", &["info"]);
    assert!(report.contains("language: AARCH64:LE:64"), "{report}");
    let report = image("arm64.elf", &["disasm", "add"]);
    assert!(report.contains("add w0, w1, w0"), "{report}");
    assert!(report.contains("ret"), "{report}");
    let report = image("arm64.elf", &["cfg", "sum"]);
    assert!(report.lines().filter(|line| line.contains("->")).count() >= 2, "sum loops: {report}");
    let report = image("arm64.elf", &["calls"]);
    assert!(report.contains("add"), "{report}");
    let (ok, stdout, stderr) = image_result("arm64.elf", &["pseudocode", "add"]);
    assert!(!ok || stdout.contains("AARCH64"), "{stdout}{stderr}");
}

#[test]
fn raw_bytes_are_read_where_the_flags_say_they_load() {
    // The sample's `.text`, as raw bytes at its own address.
    let flags = [
        "--raw", "x86-64", "--base", "0x1060", "--offset", "0x1060", "--length", "0x18c",
        "--entry", "0x1149",
    ];
    let args: Vec<&str> = flags.iter().copied().chain(["info"]).collect();
    let report = image("sample.elf", &args);
    assert!(report.contains("language: x86:LE:64"), "{report}");
    assert!(report.contains("entry: 0x1149"), "{report}");
    assert!(report.contains("raw vma=0x1060 size=396"), "{report}");
    let args: Vec<&str> = flags.iter().copied().chain(["disasm", "0x1149"]).collect();
    let report = image("sample.elf", &args);
    assert!(report.contains("endbr64"), "{report}");
    assert!(report.contains("entry_0x1149"), "{report}");

    // Without --base the bytes have nowhere to load; an architecture that
    // is not one is refused by name.
    let (ok, _, stderr) = image_result("sample.elf", &["--raw", "x86-64", "info"]);
    assert!(!ok);
    assert!(stderr.contains("--base"), "{stderr}");
    let (ok, _, stderr) = image_result("sample.elf", &["--raw", "sparc", "--base", "0", "info"]);
    assert!(!ok);
    assert!(stderr.contains("not an architecture"), "{stderr}");
}

#[test]
fn a_universal_macho_lists_its_slices_and_is_read_as_the_one_chosen() {
    let report = image("sample_fat.macho", &["slices"]);
    assert!(report.contains("0: x86_64 offset=0x4000"), "{report}");
    assert!(report.contains("1: arm64 offset=0x8000"), "{report}");
    let report = image("sample.macho", &["slices"]);
    assert!(report.contains("one image: no slices"), "{report}");

    // Opened whole it says what to choose; chosen, it is that image.
    let (ok, _, stderr) = image_result("sample_fat.macho", &["info"]);
    assert!(!ok);
    assert!(stderr.contains("universal Mach-O"), "{stderr}");
    assert!(stderr.contains("x86_64, arm64"), "{stderr}");
    let report = image("sample_fat.macho", &["--slice", "arm64", "info"]);
    assert!(report.contains("language: AARCH64:LE:64"), "{report}");
    let report = image("sample_fat.macho", &["--slice", "0", "info"]);
    assert!(report.contains("language: x86:LE:64"), "{report}");
    let report = image("sample_fat.macho", &["--slice", "x86_64", "symbols"]);
    assert!(report.contains("add"), "{report}");
    let (ok, _, stderr) = image_result("sample_fat.macho", &["--slice", "ppc", "info"]);
    assert!(!ok);
    assert!(stderr.contains("has no slice"), "{stderr}");
}

#[test]
fn the_dead_code_option_drops_what_nothing_uses() {
    // As made: a store nothing reads, and a branch that can only go one way.
    let report = image("sample.elf", &["pseudocode", "deregister_tm_clones"]);
    assert!(report.contains("  rax = &completed.0;\n"), "{report}");
    assert!(report.contains("  if (0) {"), "{report}");
    // Dropped: neither, and the local they needed goes with them.
    let report = image(
        "sample.elf",
        &["pseudocode", "deregister_tm_clones", "--option", "dead-code", "drop"],
    );
    assert!(!report.contains("rax"), "{report}");
    assert!(!report.contains("if ("), "{report}");
    assert!(report.contains("{\n  return;\n}"), "{report}");
    // A function with nothing dead reads the same under either, and so
    // does one whose store is to a global: `completed.0 = 1;` is for the
    // rest of the program.
    for function in ["add", "__do_global_dtors_aux"] {
        let kept = image("sample.elf", &["pseudocode", function]);
        let dropped = image(
            "sample.elf",
            &["pseudocode", function, "--option", "dead-code", "drop"],
        );
        assert_eq!(kept, dropped, "{function}");
    }
    assert!(
        image("sample.elf", &["pseudocode", "__do_global_dtors_aux"]).contains("completed.0 = 1;")
    );
    // The option is in the catalog.
    let catalog = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["catalog", "--markdown"])
        .output()
        .expect("runs");
    let catalog = String::from_utf8_lossy(&catalog.stdout);
    assert!(catalog.contains("`dead-code`"), "{catalog}");
}

#[test]
fn a_stripped_image_lists_the_functions_its_unwind_data_names() {
    let report = image("unwind_stripped.elf", &["symbols"]);
    assert!(report.contains("0x401000 sub_401000\n"), "{report}");
    assert!(report.contains("0x401014 sub_401014\n"), "{report}");
    assert!(report.contains("0x401047 sub_401047\n"), "{report}");
    let json = image_json("unwind_stripped.elf", &["symbols"]);
    assert_eq!(json["functions"][1]["end"], serde_json::json!(0x401047));
    let report = image("unwind_stripped.elf", &["disasm", "sub_401014"]);
    assert!(report.contains("sub_401014"), "{report}");
    let report = image("unwind.exe", &["symbols"]);
    assert!(report.contains("0x140001090 sub_140001090\n"), "{report}");
    let report = image("unwind_stripped.macho", &["symbols"]);
    assert!(report.contains("0x100000440 sub_100000440\n"), "{report}");
    // A function a symbol names has its end from the same data.
    let json = image_json("sample.elf", &["symbols"]);
    let add = json["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|function| function["name"] == "add")
        .expect("add");
    assert_eq!(add["end"], serde_json::json!(0x1161));
}

#[test]
fn a_swift_image_is_described_and_its_names_demangled() {
    let report = image("sample_swift_x86", &["swift"]);
    assert!(report.contains("types: 4"), "{report}");
    assert!(report.contains("  struct sample.Point  0x"), "{report}");
    assert!(report.contains("    var x: Swift.Int"), "{report}");
    assert!(
        report.contains("    case circle: (radius: Swift.Int)"),
        "{report}"
    );
    assert!(report.contains("    case empty\n"), "{report}");
    assert!(
        report.contains("  class sample.Derived : sample.Base <sample.Greeting>  0x"),
        "{report}"
    );
    assert!(
        report.contains("    method #4  0x")
            && report.contains("  sample.Base.twice(Swift.Int) -> Swift.Int"),
        "{report}"
    );
    assert!(report.contains("protocols: 1"), "{report}");
    assert!(report.contains("  sample.Greeting  0x"), "{report}");
    let json = image_json("sample_swift_x86", &["swift"]);
    assert_eq!(
        json["types"][3]["superclass"],
        serde_json::json!("sample.Base")
    );
    assert_eq!(
        json["types"][3]["protocols"][0],
        serde_json::json!("sample.Greeting")
    );
    assert_eq!(
        json["types"][1]["fields"][0]["type"],
        serde_json::json!("(radius: Swift.Int)")
    );
    assert_eq!(
        json["types"][2]["methods"][4]["kind"],
        serde_json::json!("method")
    );
    assert_eq!(json["protocols"][0]["requirements"], serde_json::json!(1));

    // The names are demangled everywhere, the mangled one kept.
    let report = image("sample_swift_x86", &["symbols"]);
    assert!(
        report.contains(" sample.Derived.area(of: sample.Shape) -> Swift.Int\n"),
        "{report}"
    );
    assert!(
        report.contains(" static sample.Base.answer() -> Swift.Int\n"),
        "{report}"
    );
    assert!(
        report.contains(" protocol witness for sample.Greeting.greet(times: Swift.Int) -> Swift.Int in conformance sample.Derived : sample.Greeting in sample\n"),
        "{report}"
    );
    // The one name left mangled is a function signature specialization,
    // past the demangler's grammar.
    assert!(
        report
            .lines()
            .filter(|line| line.contains("$s6sample"))
            .all(|line| line.contains("Tf")),
        "{report}"
    );
    let json = image_json("sample_swift_x86", &["symbols"]);
    assert!(json["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .any(|function| function["mangled"] == "_$s6sample7DerivedC4area2ofSiAA5ShapeO_tF"));
    let report = image(
        "sample_swift_x86",
        &["disasm", "_$s6sample7DerivedC4area2ofSiAA5ShapeO_tF"],
    );
    assert!(report.contains("sample.Derived.area"), "{report}");
    let report = image(
        "sample_swift_x86",
        &["cfg", "$s6sample7DerivedC4area2ofSiAA5ShapeO_tF"],
    );
    assert!(!report.trim().is_empty(), "{report}");

    // Stripped, the vtable names what it points at.
    let report = image("sample_swift_x86_stripped", &["symbols"]);
    assert!(report.contains(" sample.Base.getter#0\n"), "{report}");
    assert!(report.contains(" sample.Base.method#4\n"), "{report}");

    // An image without Swift says so.
    let report = image("sample_objc", &["swift"]);
    assert!(report.contains("no Swift metadata"), "{report}");
    let json = image_json("sample.elf", &["swift"]);
    assert_eq!(json["types"].as_array().map(Vec::len), Some(0));
}

#[test]
fn mangled_names_are_reported_demangled_and_still_name_their_functions() {
    // Itanium names, in an ELF: the two overloads read apart.
    let report = image("sample_cpp.elf", &["symbols"]);
    assert!(report.contains(" geometry::area(int)\n"), "{report}");
    assert!(report.contains(" geometry::area(int, int)\n"), "{report}");
    assert!(
        report.contains(" geometry::Shape::corner(int) const\n"),
        "{report}"
    );
    assert!(report.contains(" geometry::Shape::count size="), "{report}");
    assert!(!report.contains("_ZN8geometry"), "{report}");
    // The JSON carries the mangled name beside the shown one.
    let json = image_json("sample_cpp.elf", &["symbols"]);
    let area = json["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|function| function["name"] == "geometry::area(int, int)")
        .expect("area");
    assert_eq!(area["mangled"], serde_json::json!("_ZN8geometry4areaEii"));
    let main = json["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|function| function["name"] == "main")
        .expect("main");
    assert!(main["mangled"].is_null());
    let count = json["data"]
        .as_array()
        .expect("data")
        .iter()
        .find(|symbol| symbol["name"] == "geometry::Shape::count")
        .expect("count");
    assert_eq!(
        count["mangled"],
        serde_json::json!("_ZN8geometry5Shape5countE")
    );
    // The filter matches the mangled name too.
    let report = image(
        "sample_cpp.elf",
        &["symbols", "--filter", "ZN8geometry4areaEii"],
    );
    assert!(report.contains("geometry::area(int, int)"), "{report}");
    assert!(!report.contains("geometry::area(int)\n"), "{report}");
    // A function is named by either name.
    let report = image("sample_cpp.elf", &["disasm", "_ZN8geometry4areaEii"]);
    assert!(report.contains("geometry::area(int, int)"), "{report}");
    let report = image("sample_cpp.elf", &["disasm", "geometry::area(int, int)"]);
    assert!(report.contains("geometry::area(int, int)"), "{report}");
    let report = image("sample_cpp.elf", &["data", "_ZN8geometry5Shape5countE"]);
    assert!(report.contains("geometry::Shape::count"), "{report}");
    // In the pseudocode a name stands as code: the scope and the name.
    let report = image("sample_cpp.elf", &["pseudocode", "main"]);
    assert!(report.contains("geometry::area("), "{report}");
    assert!(!report.contains("geometry::area(int"), "{report}");
    let report = image("sample_cpp.elf", &["pseudocode", "_ZN8geometry4areaEii"]);
    assert!(report.contains(" geometry::area("), "{report}");
    assert!(!report.contains("(int, int)("), "{report}");
    // The PE's exported static member is data under either name.
    let report = image("sample_cpp.exe", &["data", "?count@Shape@geometry@@2HA"]);
    assert!(report.contains("geometry::Shape::count"), "{report}");

    // Microsoft names, from a PE's export table.
    let report = image("sample_cpp.exe", &["symbols"]);
    assert!(report.contains(" geometry::area(int, int)\n"), "{report}");
    assert!(
        report.contains(" geometry::Shape::Shape(int)\n"),
        "{report}"
    );
    assert!(!report.contains("?area@geometry"), "{report}");
    let json = image_json("sample_cpp.exe", &["symbols"]);
    assert!(json["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .any(|function| function["mangled"] == "?area@geometry@@YAHHH@Z"));

    // Itanium names under a Mach-O's leading underscore.
    let report = image("sample_cpp.macho", &["symbols"]);
    assert!(report.contains(" geometry::area(int, int)\n"), "{report}");
    assert!(report.contains(" _main\n"), "{report}");
}

#[test]
fn an_objective_c_image_is_described_and_its_methods_named_from_its_metadata() {
    // The stripped twin names nothing in its symbol table; the metadata does.
    let report = image("sample_objc_stripped", &["symbols"]);
    assert!(report.contains(" -[Derived greet:]\n"), "{report}");
    assert!(report.contains(" +[Base answer]\n"), "{report}");
    assert!(report.contains(" -[Base(Extra) thrice:]\n"), "{report}");
    assert!(report.contains(" OBJC_CLASS_$_Base"), "{report}");
    // An instance method's name starts with `-`, so `--` ends the flags first.
    let report = image(
        "sample_objc_stripped",
        &["disasm", "--", "-[Derived greet:]"],
    );
    assert!(report.contains("-[Derived greet:]"), "{report}");
    let report = image("sample_objc_stripped", &["calls"]);
    assert!(report.contains("-[Derived greet:]"), "{report}");

    // The pseudocode reads a call of the dispatcher as the message it sends.
    let report = image("sample_objc", &["pseudocode", "_main"]);
    assert!(report.contains("[0 greet:[Base answer]]"), "{report}");
    assert!(report.contains("[0 thrice:2]"), "{report}");
    assert!(!report.contains("objc_msgSend("), "{report}");
    let report = image("sample_objc", &["pseudocode", "--", "-[Derived greet:]"]);
    assert!(report.contains("[a twice:c] + 1"), "{report}");

    // The classes, categories and protocols, as text and as JSON.
    let report = image("sample_objc_stripped", &["objc"]);
    assert!(report.contains("classes: 2"), "{report}");
    assert!(report.contains("  Derived : Base <Greeting>"), "{report}");
    assert!(report.contains("    - greet:  0x"), "{report}");
    assert!(report.contains("    + answer  0x"), "{report}");
    assert!(report.contains("    ivar isa"), "{report}");
    assert!(report.contains("  Base(Extra)"), "{report}");
    assert!(report.contains("protocols: 1"), "{report}");
    assert!(report.contains("  Greeting"), "{report}");
    let report = image("sample_objc_stripped", &["objc", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&report).expect("JSON");
    assert_eq!(json["classes"][1]["name"], serde_json::json!("Derived"));
    assert_eq!(json["classes"][1]["superclass"], serde_json::json!("Base"));
    assert_eq!(json["categories"][0]["class"], serde_json::json!("Base"));
    assert_eq!(
        json["protocols"][0]["instance_methods"][0]["selector"],
        serde_json::json!("greet:")
    );
    assert!(json["protocols"][0]["instance_methods"][0]["imp"].is_null());
    assert_eq!(
        json["classes"][1]["properties"][0]["attributes"],
        serde_json::json!("Ti,N,V_count")
    );
    let text = image("sample_objc_stripped", &["objc"]);
    assert!(text.contains("    property count  Ti,N,V_count"), "{text}");

    // The same as a header: declarations in dependency order, the types
    // decoded, the accessors folded into their properties.
    let header = image("sample_objc_stripped", &["objc", "--header"]);
    assert!(
        header.starts_with(
            "// Objective-C declarations recovered from the image: 2 classes, 1 category, 1 protocol.\n"
        ),
        "{header}"
    );
    let protocol = header.find("@protocol Greeting").expect("protocol");
    let base = header.find("@interface Base {").expect("base");
    let extra = header.find("@interface Base (Extra)").expect("category");
    let derived = header
        .find("@interface Derived : Base <Greeting>")
        .expect("derived");
    assert!(
        protocol < base && base < extra && extra < derived,
        "{header}"
    );
    assert!(
        header.contains("@property (nonatomic, readonly) struct Point origin;\n"),
        "{header}"
    );
    assert!(
        header.contains(
            "- (unsigned long long)hash:(const char *)arg1 at:(unsigned long long)arg2;\n"
        ),
        "{header}"
    );
    assert!(!header.contains("setCount:"), "{header}");
    let plain = image("sample.macho", &["objc", "--header"]);
    assert!(plain.contains("no Objective-C metadata"), "{plain}");
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["image"])
        .arg(fixture("sample_objc_stripped"))
        .args(["objc", "--header", "--json"])
        .output()
        .expect("runs");
    assert!(!output.status.success(), "--header and --json conflict");

    // An image without Objective-C says so.
    let report = image("sample.macho", &["objc"]);
    assert!(report.contains("no Objective-C metadata"), "{report}");
    let report = image("sample.elf", &["objc", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&report).expect("JSON");
    assert_eq!(json["classes"].as_array().map(Vec::len), Some(0));
}

#[test]
fn the_levels_render_options_decorate_the_text_and_the_json_has_the_fields() {
    let text = image(
        "sample.elf",
        &[
            "il",
            "sum_to",
            "--level",
            "medium",
            "--casts",
            "--opcodes",
            "--stack-pointer",
        ],
    );
    assert!(
        text.contains("[assign] local_14 = (int)1  ; sp = entry-0x8"),
        "{text}"
    );
    let lifted = image(
        "sample.elf",
        &["il", "sum_to", "--level", "lifted", "--flags", "--types"],
    );
    assert!(
        lifted.contains(
            "cmp eax,[rbp-14h]  ; flags: reads none, writes CF PF AF ZF SF OF  ; types: eax: int, rbp: long"
        ),
        "{lifted}"
    );
    let plain = image("sample.elf", &["il", "sum_to", "--level", "lifted"]);
    assert!(!plain.contains("flags:"), "{plain}");
    let report = image_json("sample.elf", &["il", "sum_to", "--level", "medium"]);
    let item = report["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["text"] == "local_14 = 1")
        .expect("the init");
    assert_eq!(item["opcode"], "assign");
    assert_eq!(item["stack_pointer"], -8);
    assert_eq!(item["types"], serde_json::json!([["local_14", "int"]]));
    assert_eq!(item["flags_read"], serde_json::json!([]));
}

#[test]
fn a_function_is_emulated_with_its_arguments_and_the_run_is_reported() {
    let text = image("sample.elf", &["emulate", "sum_to", "--arg", "5"]);
    assert!(text.contains("; sum_to at 0x1161: emulated"), "{text}");
    assert!(text.contains("; returned 15 (0xf)"), "{text}");
    assert!(text.contains(";   local_14 = 6"), "{text}");
    let report = image_json(
        "sample.elf",
        &["emulate", "main", "--arg", "0x1", "--arg", "0"],
    );
    assert_eq!(report["returned"]["value"], 10);
    assert_eq!(report["stop"], "returned 10 (0xa)");
    // A negative argument, and a negative return read as such.
    let negative = image_json(
        "sample.elf",
        &["emulate", "add", "--arg", "-7", "--arg", "3"],
    );
    assert_eq!(negative["returned"]["as_signed"], -4, "{negative}");
    assert_eq!(negative["returned"]["signed"], true);
    assert_eq!(negative["returned"]["value"], 4294967292u64);
    assert!(report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step["note"]
            .as_str()
            .is_some_and(|n| n.contains("not followed"))));
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["emulate", "sum_to", "--arg", "five"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is a number"));
}

#[test]
fn a_function_is_transpiled_to_c_plus_plus_with_a_harness() {
    let text = image(
        "sample.elf",
        &["transpile", "sum_to", "--harness", "sum_to"],
    );
    assert!(text.contains("long sum_to(int a)"), "{text}");
    assert!(text.contains("block_1161:"), "{text}");
    assert!(text.contains("goto block_118a;"), "{text}");
    assert!(text.contains("int main(int argc, char **argv)"), "{text}");
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .arg("transpile")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("name the functions"));
}

#[test]
fn the_pseudocode_reads_as_rust_or_python_when_asked() {
    let rust = image(
        "sample.elf",
        &["pseudocode", "sum_to", "--option", "language", "rust"],
    );
    assert!(rust.contains("fn sum_to(a: i32) -> i64 {"), "{rust}");
    assert!(rust.contains("let mut local_14: i32;"), "{rust}");
    assert!(rust.contains("while local_14 <= a {"), "{rust}");
    assert!(
        rust.contains("local_10 = local_10 + (local_14 as i64);"),
        "{rust}"
    );
    let python = image(
        "sample.elf",
        &["pseudocode", "sum_to", "--option", "language", "python"],
    );
    assert!(python.contains("def sum_to(a):"), "{python}");
    assert!(python.starts_with("# sum_to at "), "{python}");
    assert!(!python.contains("//"), "{python}");
    assert!(python.contains("  while local_14 <= a:"), "{python}");
    assert!(
        python.contains("    local_10 = local_10 + long(local_14)"),
        "{python}"
    );
    assert!(python.contains("  return local_10"), "{python}");
    assert!(!python.contains(';'), "{python}");
    let objc = image(
        "sample.elf",
        &["pseudocode", "sum_to", "--option", "language", "objc"],
    );
    assert!(objc.contains("long sum_to(int a)"), "{objc}");
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "sum_to", "--option", "language", "cobol"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn the_formatting_options_reach_the_command_line() {
    // Broken braces: the `for` head alone, its brace under it.
    let broken = image(
        "sample.elf",
        &["pseudocode", "sum_to", "--option", "brace-style", "broken"],
    );
    assert!(
        broken.contains("  for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1)\n  {\n"),
        "{broken}"
    );
    // Wrapped at a narrow column: printf's arguments on two lines.
    let wrapped = image("sample.elf", &["pseudocode", "main", "--option", "wrap", "16"]);
    assert!(
        wrapped.contains("  printf(\"%ld\\n\",\n      v2);"),
        "{wrapped}"
    );
    // The callees' parameter names: main calls sum_to(add(a, 3)).
    let hinted = image(
        "sample.elf",
        &["pseudocode", "main", "--option", "call-hints", "names"],
    );
    // add's first argument is `a`, which is its parameter's own name.
    assert!(
        hinted.contains("sum_to(/* a */ add(a, /* b */ 3))"),
        "{hinted}"
    );
    let plain = image("sample.elf", &["pseudocode", "main"]);
    assert!(plain.contains("sum_to(add(a, 3))"), "{plain}");
    // Expanded ternaries change nothing where there is none.
    let expanded = image(
        "sample.elf",
        &["pseudocode", "main", "--option", "ternaries", "expand"],
    );
    assert_eq!(expanded, plain);
}

#[test]
fn inlined_memory_operations_read_as_builtins() {
    // `rep movsb` and `rep stosb`, with rcx the count.
    let copy = image("builtins.elf", &["pseudocode", "rep_copy"]);
    assert!(copy.contains("  __builtin_memcpy(a, b, c);"), "{copy}");
    let fill = image("builtins.elf", &["pseudocode", "rep_fill"]);
    assert!(
        fill.contains("  __builtin_memset(a, (char)b, c);"),
        "{fill}"
    );
    // A string put on the stack in two overlapping words, whose address
    // goes to a call.
    let text = image("builtins.elf", &["pseudocode", "stack_string"]);
    assert!(
        text.contains("  __builtin_strcpy(&local_d, \"hello, world\");\n  consume(&local_d);"),
        "{text}"
    );
    assert!(
        !text.contains("local_8"),
        "the word written into the string is not a variable: {text}"
    );
    // The stores themselves, when asked: the second word written into the
    // first's variable.
    let kept = image(
        "builtins.elf",
        &["pseudocode", "stack_string", "--option", "builtins", "keep"],
    );
    assert!(kept.contains("  local_d = 0x77202c6f6c6c6568;"), "{kept}");
    assert!(
        kept.contains("  *(long *)((char *)&local_d + 5) = 0x646c726f77202c;"),
        "{kept}"
    );
    // The low level has the builtin as the call it is.
    let low = image("builtins.elf", &["il", "rep_copy", "--level", "low"]);
    assert!(low.contains("__builtin_memcpy("), "{low}");
}

#[test]
fn a_run_of_field_stores_reads_as_a_struct_initializer() {
    let text = image("structs.elf", &["pseudocode", "init"]);
    assert!(
        text.contains(
            "  *(struct { int at_0; int at_4; long at_8; } *)a = { b, 2, 0x1122334455667788 };"
        ),
        "{text}"
    );
    let kept = image(
        "structs.elf",
        &[
            "pseudocode",
            "init",
            "--option",
            "struct-initializers",
            "keep",
        ],
    );
    assert!(
        kept.contains("  *(int *)a = b;\n  *(int *)(a + 4) = 2;"),
        "{kept}"
    );
    // The globals an address names stay their own stores.
    let global = image("structs.elf", &["pseudocode", "init_global"]);
    assert!(global.contains("  here = a;\n  *(int *)0x4030"), "{global}");
    assert!(global.contains(" = a + 1;\n  *(long *)0x4030"), "{global}");
    assert!(!global.contains("struct {"), "{global}");
    // The transpiler writes the stores a compiler reads.
    let cpp = image("structs.elf", &["transpile", "init"]);
    assert!(cpp.contains("*(int *)((char *)a + 4) = 2;"), "{cpp}");
    assert!(!cpp.contains("struct {"), "{cpp}");
    // The emulator stores each field: the run writes the three fields.
    let run = image_json("structs.elf", &["emulate", "init", "--arg", "0x5000", "--arg", "9"]);
    assert!(
        run.to_string().contains("wrote 3 fields at 0x5000"),
        "{run}"
    );
    // An indexed store into a global array is an address far from its
    // pointer, not a field: the stores stay their own.
    let indexed = image("structs.elf", &["pseudocode", "fill_pair"]);
    assert!(!indexed.contains("struct {"), "{indexed}");
    assert!(
        indexed.contains("= 1;") && indexed.contains("= 2;"),
        "{indexed}"
    );
}

#[test]
fn a_windows_control_flow_guard_dispatch_reads_as_the_call_it_guards() {
    // The load configuration names the guard's pointers as data.
    let symbols = image("cfg.exe", &["symbols"]);
    assert!(symbols.contains("__guard_dispatch_icall_fptr"), "{symbols}");
    assert!(symbols.contains("__guard_check_icall_fptr"), "{symbols}");
    // A tail call through the dispatcher to a parameter.
    let through = image("cfg.exe", &["pseudocode", "call_through"]);
    assert!(through.contains("  return a(b, 1);"), "{through}");
    let tail = image("cfg.exe", &["pseudocode", "tail_through"]);
    assert!(tail.contains("  a(a);"), "{tail}");
    // Through a pointer loaded from a struct; the register the function's
    // own parameter was moved into is passed on, as any call's are.
    let field = image("cfg.exe", &["pseudocode", "field_call"]);
    assert!(
        field.contains("return (*(long *)a)(b, *(int *)(a + 8)"),
        "{field}"
    );
    assert!(!field.contains("__guard_dispatch_icall_fptr"), "{field}");
    // Refused when asked.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("cfg.exe"))
        .args([
            "pseudocode",
            "call_through",
            "--option",
            "indirect-calls",
            "refuse",
        ])
        .output()
        .expect("the ag binary runs");
    assert!(!output.status.success());
    // The dispatch here is a jump, and is refused as the jump it is.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("an indirect jump at 0x140001015"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn functions_that_do_not_return_end_their_paths_and_are_noted() {
    // die ends in a system call and runs up to the next function: it never
    // returns, so the graph of a function that calls it ends at the call.
    let cfg = image("noreturn.elf", &["cfg", "die"]);
    assert!(cfg.contains("blocks: 1\n"), "{cfg}");
    let cfg = image("noreturn.elf", &["cfg", "positive"]);
    assert!(cfg.contains("blocks: 3\n"), "{cfg}");
    assert!(
        !cfg.contains("0x401044"),
        "the next function's code is not positive's: {cfg}"
    );
    // An exit-on-error helper: the arm that dies ends there, and the
    // condition is noted.
    let positive = image("noreturn.elf", &["pseudocode", "positive"]);
    assert!(
        positive.contains("  if (a < 0) {\n    die(3);\n  }\n  return;"),
        "{positive}"
    );
    assert!(
        positive.contains("// does not return when a < 0"),
        "{positive}"
    );
    let checked = image("noreturn.elf", &["pseudocode", "checked"]);
    assert!(
        checked.contains("// does not return when a == 0"),
        "{checked}"
    );
    assert!(
        checked.contains("  if (a == 0) {\n    die(2);\n  }\n"),
        "{checked}"
    );
    // The caller says it of its own arguments.
    let caller = image("noreturn.elf", &["pseudocode", "caller"]);
    // Both calls' conditions, the inner call's result named as the call.
    assert!(
        caller.contains("// checked does not return when (a + 4) == 0; positive does not return when checked(a + 4, 5) < 0"),
        "{caller}"
    );
    assert!(!caller.contains("__builtin_unreachable"), "{caller}");
}

#[test]
fn the_possible_values_are_listed_and_end_the_pseudocodes_lines() {
    // classify's guard leaves `a` in 0..=5 for the switch.
    let report = image("switch.elf", &["values", "classify"]);
    assert_eq!(
        report,
        "// possible values of classify at 0x401000\n\
         0x401000  reads a: any\n\
         0x401005  reads a: 0..=5\n"
    );
    let report = image(
        "switch.elf",
        &["values", "classify", "--at", "0x401005", "--variable", "a"],
    );
    assert!(report.ends_with("0x401005  reads a: 0..=5\n"), "{report}");
    let report = image("switch.elf", &["pseudocode", "classify", "--values"]);
    assert!(
        report.contains("  if ((unsigned int)a > 5) {\n"),
        "{report}"
    );
    assert!(
        report.contains("  switch ((unsigned long)(unsigned int)a) { // a: 0..=5\n"),
        "{report}"
    );
    // The lines are the pseudocode's own, with the notes at their ends.
    let plain = image("switch.elf", &["pseudocode", "classify"]);
    assert_eq!(report.lines().count(), plain.lines().count());

    // sum_to's loop: the counter starts at 1, and nothing bounds `a`.
    let report = image(
        "sample.elf",
        &["values", "sum_to", "--variable", "local_14"],
    );
    assert!(report.contains("  writes local_14: any\n"), "{report}");
    let report = image_json("sample.elf", &["values", "sum_to"]);
    assert_eq!(report["function"], "sum_to");
    let first = &report["statements"][0];
    assert_eq!(
        first["writes"][0],
        serde_json::json!({
            "variable": "local_10",
            "values": { "kind": "constant", "value": 0, "text": "0" },
        })
    );

    // The arm a constant condition never takes is on no path.
    let report = image("opaque.elf", &["values", "zeroed"]);
    assert!(
        report.contains("0x4010ee  writes eax: undetermined\n"),
        "{report}"
    );
    let report = image_json("opaque.elf", &["pseudocode", "zeroed", "--values"]);
    assert_eq!(report["lifted"], true);

    // A statement or a variable the function lacks is said.
    let (ok, _, error) = image_result("switch.elf", &["values", "classify", "--at", "0x1"]);
    assert!(!ok);
    assert!(
        error.contains("classify has no statement at 0x1"),
        "{error}"
    );
    let (ok, _, error) = image_result("switch.elf", &["values", "classify", "--variable", "b"]);
    assert!(!ok);
    assert!(
        error.contains("classify reads and writes no variable b"),
        "{error}"
    );
}

#[test]
fn the_variables_of_a_function_say_where_each_lives() {
    // The parameters in their argument registers, at the width read; the
    // locals in their stack slots, by the offset from the entry's stack
    // pointer; a call's result kept in the accumulator.
    assert_eq!(
        image("sample.elf", &["variables", "sum_to"]),
        "// variables of sum_to at 0x1161\n\
         name      type  kind   placement          defs  uses\n\
         a         int   param  edi (in rdi)          0     1\n\
         local_10  long  local  [sp-0x10] 8 bytes     2     2\n\
         local_14  int   local  [sp-0x14] 4 bytes     2     3\n"
    );
    let main = image("sample.elf", &["variables", "main"]);
    assert!(
        main.contains("b     long  param  rsi              0     0\n"),
        "{main}"
    );
    assert!(
        main.contains("v2    long  local  rax              1     2\n"),
        "{main}"
    );
    // A register two paths leave different lives in it.
    let ping = image("inline.elf", &["variables", "ping"]);
    assert!(
        ping.contains("eax      int   local  eax (in rax)         2     1\n"),
        "{ping}"
    );
    let classify = image("switch.elf", &["variables", "classify"]);
    assert!(
        classify.ends_with("a     int   param  edi (in rdi)     0     2\n"),
        "{classify}"
    );

    // As JSON, with the parts of each placement and the addresses.
    let report = image_json("sample.elf", &["variables", "sum_to"]);
    assert_eq!(report["function"], "sum_to");
    assert_eq!(report["address"], "0x1161");
    let local = &report["variables"][1];
    assert_eq!(local["name"], "local_10");
    assert_eq!(local["lift_name"], "local_10");
    assert_eq!(local["kind"], "local");
    assert_eq!(
        local["placements"],
        serde_json::json!([
            { "kind": "stack", "offset": -16, "size": 8, "text": "[sp-0x10] 8 bytes" }
        ])
    );
    assert_eq!(local["definitions"], 2);
    assert_eq!(local["defined_at"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        report["variables"][0]["placements"][0],
        serde_json::json!({ "kind": "register", "register": "edi", "in": "rdi", "text": "edi (in rdi)" })
    );

    // A function the lifter refuses says why.
    let (ok, _, error) = image_result("inline.elf", &["variables", "tangle"]);
    assert!(!ok);
    assert!(error.contains("tangle at 0x401067: irreducible"), "{error}");
}
