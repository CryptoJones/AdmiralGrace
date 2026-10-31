//! The transpiled C++ builds with the machine's compiler, when it has one,
//! and runs to the emulator's answer.

use std::path::PathBuf;
use std::process::Command;

use ag_image::{Binary, EmulationLimits};

fn sample() -> Binary {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Binary::open(&root.join("../ag-engine/tests/fixtures/sample.elf")).expect("the sample opens")
}

fn address_of(image: &Binary, name: &str) -> u64 {
    image
        .functions()
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.address)
        .unwrap_or_else(|| panic!("{name}"))
}

/// A scratch directory, removed when the test ends however it ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_functions_are_written_as_c_plus_plus_with_their_callees_and_globals() {
    let image = sample();
    let (main, sum_to, add) = (
        address_of(&image, "main"),
        address_of(&image, "sum_to"),
        address_of(&image, "add"),
    );
    let text = image.transpile(&[main], true, None).expect("main lifts");
    assert!(
        text.contains("int main_(") || text.contains("main("),
        "{text}"
    );
    assert!(text.contains("block_1161:"), "sum_to is followed: {text}");
    assert!(text.contains("goto block_118a;"), "{text}");
    assert!(
        text.contains("if (local_14 <= a) goto block_117d; else goto block_1192;"),
        "{text}"
    );
    assert!(
        text.contains("long sum_to(int a);"),
        "declared before defined: {text}"
    );
    assert!(
        !text.contains("long printf("),
        "the library declares printf: {text}"
    );
    // Not followed: the callees are declared, not defined.
    let alone = image.transpile(&[main], false, None).expect("main lifts");
    assert!(!alone.contains("block_1161:"), "{alone}");
    assert!(
        alone.contains("long sum_to(int a);"),
        "declared with its own signature: {alone}"
    );
    assert!(image
        .transpile(&[address_of(&image, "_start")], true, None)
        .is_err());
    let _ = (sum_to, add);
}

#[test]
fn the_harness_builds_and_runs_to_the_emulators_answer() {
    let compiler = ["c++", "g++", "clang++"].into_iter().find(|name| {
        Command::new(name)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    });
    let Some(compiler) = compiler else {
        eprintln!("no C++ compiler on this machine: the harness is not built");
        return;
    };
    let image = sample();
    let sum_to = address_of(&image, "sum_to");
    let text = image
        .transpile(&[sum_to], true, Some(sum_to))
        .expect("sum_to lifts");
    assert!(text.contains("int main(int argc, char **argv)"), "{text}");
    let dir = Scratch(std::env::temp_dir().join(format!(
        "ag-transpile-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    std::fs::create_dir_all(&dir.0).unwrap();
    let source = dir.0.join("sum_to.cpp");
    let binary = dir.0.join("sum_to");
    std::fs::write(&source, &text).unwrap();
    let built = Command::new(compiler)
        .args(["-std=c++17", "-w", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("the compiler runs");
    assert!(
        built.status.success(),
        "{}\n{text}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&binary)
        .arg("5")
        .output()
        .expect("the program runs");
    assert!(ran.status.success());
    let printed = String::from_utf8_lossy(&ran.stdout).trim().to_string();
    let emulated = image
        .emulate(sum_to, &[5], &EmulationLimits::default())
        .expect("sum_to lifts")
        .returned()
        .and_then(|value| value.value)
        .expect("a value");
    assert_eq!(printed, emulated.to_string());
    // main too, with its callees and its call to printf.
    let main = address_of(&image, "main");
    let text = image
        .transpile(&[main], true, Some(main))
        .expect("main lifts");
    std::fs::write(&source, &text).unwrap();
    let built = Command::new(compiler)
        .args(["-std=c++17", "-w", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("the compiler runs");
    assert!(
        built.status.success(),
        "{}\n{text}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&binary)
        .args(["1", "0"])
        .output()
        .expect("the program runs");
    let printed = String::from_utf8_lossy(&ran.stdout);
    assert!(printed.lines().any(|line| line.trim() == "10"), "{printed}");
}

#[test]
fn the_builtins_transpile_to_c_plus_plus_a_compiler_reads() {
    let compiler = ["c++", "g++", "clang++"].into_iter().find(|name| {
        Command::new(name)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    });
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let image = Binary::open(&root.join("../ag-engine/tests/fixtures/builtins.elf"))
        .expect("the fixture opens");
    let targets: Vec<u64> = ["rep_copy", "rep_fill", "stack_string"]
        .iter()
        .map(|name| address_of(&image, name))
        .collect();
    let text = image
        .transpile(&targets, false, None)
        .expect("the three lift");
    // The builtins' pointer arguments are cast for the compiler.
    assert!(
        text.contains("__builtin_memcpy((void *)a, (const void *)b, (unsigned long)c);"),
        "{text}"
    );
    assert!(
        text.contains("__builtin_memset((void *)a, (int)(char)b, (unsigned long)c);"),
        "{text}"
    );
    assert!(
        text.contains("__builtin_strcpy((char *)&local_d, \"hello, world\");"),
        "{text}"
    );
    let Some(compiler) = compiler else {
        eprintln!("no C++ compiler on this machine: the text is not compiled");
        return;
    };
    let dir = Scratch(std::env::temp_dir().join(format!(
        "ag-transpile-builtins-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    std::fs::create_dir_all(&dir.0).unwrap();
    let source = dir.0.join("builtins.cpp");
    std::fs::write(&source, &text).unwrap();
    let checked = Command::new(compiler)
        .args(["-fsyntax-only", "-x", "c++"])
        .arg(&source)
        .output()
        .expect("the compiler runs");
    assert!(
        checked.status.success(),
        "{}\n{text}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
