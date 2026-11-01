//! Type propagation over a whole image (#370): the types carried between
//! functions through their calls, the stack arrays and structures found
//! from their accesses, the analyst's words over them, the options that
//! turn them off, and the C++ written from them still compiling.

use std::path::PathBuf;
use std::process::Command;

use ag_image::{Binary, Options};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/propagate.elf")
}

fn image() -> Binary {
    Binary::open(&fixture()).expect("the fixture opens")
}

fn image_with(settings: &[(&str, &str)]) -> Binary {
    let mut options = Options::default();
    for (name, value) in settings {
        options.set(name, value).expect("an option");
    }
    image().with_options(options)
}

fn address_of(image: &Binary, name: &str) -> u64 {
    image
        .functions()
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.address)
        .unwrap_or_else(|| panic!("{name}"))
}

fn text(image: &Binary, name: &str) -> String {
    image
        .pseudocode(address_of(image, name))
        .unwrap_or_else(|e| panic!("{name}: {}", e.reason))
        .text()
}

/// The variable `name` of the function `function`: its type and where the
/// type came from.
fn variable(image: &Binary, function: &str, name: &str) -> (String, Option<String>) {
    let variables = image
        .variables(address_of(image, function))
        .expect("the function lifts");
    let found = variables
        .iter()
        .find(|v| v.lift_name == name)
        .unwrap_or_else(|| panic!("{function} declares {name}: {variables:?}"));
    (found.ty.clone(), found.source.clone())
}

#[test]
fn a_helper_called_with_strings_takes_a_string_and_its_callers_pass_them() {
    let image = image();
    // measure's parameter goes to strlen.
    assert_eq!(
        variable(&image, "measure", "a"),
        (
            "char *".to_string(),
            Some("from strlen's parameter 1".to_string())
        )
    );
    assert!(text(&image, "measure").contains("void measure(char *a)"));
    // Both callers pass a constant address the image holds a string at,
    // which the parameter's type makes the string.
    assert!(text(&image, "greet").contains("measure(\"hello\");"));
    assert!(text(&image, "part").contains("measure(\"goodbye\");"));
    // A function of the image named as a known one takes its prototype.
    assert_eq!(
        variable(&image, "fgets", "c"),
        (
            "FILE *".to_string(),
            Some("from fgets's prototype".to_string())
        )
    );
    // A caller's argument takes the callee's parameter's type.
    assert_eq!(
        variable(&image, "line", "a"),
        (
            "FILE *".to_string(),
            Some("from fgets's parameter 3".to_string())
        )
    );
}

#[test]
fn stack_arrays_come_from_an_indexed_loop_and_from_a_known_length() {
    let image = image();
    let sum = text(&image, "sum");
    assert!(sum.contains("  int local_38[8];\n"), "{sum}");
    assert!(
        sum.contains("local_38[(long)local_c] = local_c * a;"),
        "{sum}"
    );
    assert!(
        sum.contains("local_10 = local_10 + local_38[(long)local_14];"),
        "{sum}"
    );
    assert_eq!(
        variable(&image, "sum", "local_38"),
        (
            "int[8]".to_string(),
            Some("indexed as an array at 0x4011cd".to_string())
        )
    );
    let line = text(&image, "line");
    assert!(line.contains("  char local_48[64];\n"), "{line}");
    assert!(line.contains("fgets(local_48, 0x40, a);"), "{line}");
    assert_eq!(
        variable(&image, "line", "local_48").1.as_deref(),
        Some("from fgets's parameter 1, 0x40 bytes at 0x40119c")
    );
    let copy = text(&image, "copy");
    assert!(copy.contains("  char local_28[32];\n"), "{copy}");
}

#[test]
fn a_structure_passed_to_a_known_prototype_is_that_structure() {
    let image = image_with(&[("return-liveness", "presence")]);
    let now = text(&image, "now");
    assert!(now.contains("  struct timeval local_18;\n"), "{now}");
    assert!(now.contains("gettimeofday(&local_18, 0);"), "{now}");
    assert!(
        now.contains("return local_18.tv_usec + local_18.tv_sec;"),
        "{now}"
    );
    // The callee's own body reads its parameter as the structure.
    let callee = text(&image, "gettimeofday");
    assert!(callee.contains("a->tv_usec = 2;"), "{callee}");
}

#[test]
fn a_structure_no_prototype_types_is_drafted_only_when_asked() {
    let plain = text(&image(), "pairs");
    assert!(plain.contains("  long local_18;\n"), "{plain}");
    let drafted = image_with(&[("auto-structs", "on")]);
    let pairs = text(&drafted, "pairs");
    assert!(
        pairs.contains("  struct struct_pairs_local_18 local_18;\n"),
        "{pairs}"
    );
    let stages = drafted
        .stages(address_of(&drafted, "pairs"))
        .expect("pairs lifts");
    assert_eq!(stages.inferred.definitions.len(), 1);
    assert!(stages.inferred.definitions[0]
        .c
        .starts_with("struct struct_pairs_local_18 {"));
}

#[test]
fn the_analysts_words_win() {
    let image = image();
    let measure = address_of(&image, "measure");
    let sum = address_of(&image, "sum");
    let edits = std::collections::BTreeMap::from([
        (
            measure,
            ag_image::VariableEdits {
                var_types: vec![("a".to_string(), "long".to_string())],
                ..Default::default()
            },
        ),
        (
            sum,
            ag_image::VariableEdits {
                stack_vars: vec![ag_image::StackVar {
                    offset: -0x38,
                    size: 16,
                    name: Some("half".to_string()),
                    ty: Some("int[4]".to_string()),
                }],
                ..Default::default()
            },
        ),
    ]);
    image.set_variable_edits(edits);
    assert_eq!(
        variable(&image, "measure", "a"),
        ("long".to_string(), Some("analyst".to_string()))
    );
    let text = text(&image, "sum");
    assert!(text.contains("  int half[4];\n"), "{text}");
    assert!(!text.contains("local_38[8]"), "{text}");
    assert_eq!(
        variable(&image, "sum", "half"),
        ("int[4]".to_string(), Some("analyst".to_string()))
    );
}

#[test]
fn type_propagation_off_reads_as_before() {
    let image = image_with(&[("type-propagation", "off")]);
    assert!(text(&image, "measure").contains("void measure(long a)"));
    assert!(text(&image, "greet").contains("measure(0x402000);"));
    let line = text(&image, "line");
    assert!(line.contains("void line(long a)"), "{line}");
    assert!(line.contains("fgets(&local_48, 0x40, a);"), "{line}");
    let refused = image
        .pseudocode(address_of(&image, "sum"))
        .expect_err("an indexed slot is refused");
    assert!(refused.reason.contains("arithmetic on the stack pointer"));
    assert_eq!(variable(&image, "measure", "a").1, None);
}

#[test]
fn the_inferred_types_transpile_to_c_plus_plus_that_compiles() {
    let compiler = ["c++", "g++", "clang++"].into_iter().find(|name| {
        Command::new(name)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    });
    let image = image();
    let targets: Vec<u64> = ["line", "now", "sum", "greet", "part", "copy"]
        .iter()
        .map(|name| address_of(&image, name))
        .collect();
    let program = image.transpile(&targets, false, None).expect("they lift");
    assert!(
        program.contains("typedef struct _IO_FILE FILE;\n"),
        "{program}"
    );
    assert!(
        program.contains("struct timeval {\n    long tv_sec;\n    long tv_usec;\n};\n"),
        "{program}"
    );
    assert!(
        program.contains("fgets((char *)&local_48, 0x40, (FILE *)(long)a);"),
        "{program}"
    );
    let Some(compiler) = compiler else {
        eprintln!("no C++ compiler on this machine: the text is not compiled");
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "ag-propagate-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("propagate.cpp");
    std::fs::write(&source, &program).unwrap();
    let checked = Command::new(compiler)
        .args(["-fsyntax-only", "-x", "c++"])
        .arg(&source)
        .output()
        .expect("the compiler runs");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        checked.status.success(),
        "{}\n{program}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
