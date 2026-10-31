//! The emulator runs a function of the sample against its memory, following
//! calls into the image and leaving an import's result unknown.

use std::path::PathBuf;

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

#[test]
fn sum_to_runs_to_its_sum_and_main_follows_its_calls() {
    let image = sample();
    let sum_to = address_of(&image, "sum_to");
    let run = image
        .emulate(sum_to, &[5], &EmulationLimits::default())
        .expect("sum_to lifts");
    assert_eq!(
        run.returned().and_then(|v| v.value),
        Some(15),
        "{}",
        run.text()
    );
    assert!(run.text().contains("; returned 15 (0xf)"), "{}", run.text());
    assert!(run.steps.iter().all(|step| step.address.is_some()));
    assert_eq!(run.variables["a"].value, Some(5));
    assert_eq!(run.variables["local_14"].value, Some(6));

    // main(1, 0): add(a, 3) is followed, sum_to(4) is 10, printf is not
    // followed, and the sum is returned.
    let main = address_of(&image, "main");
    let run = image
        .emulate(main, &[1, 0], &EmulationLimits::default())
        .expect("main lifts");
    assert_eq!(
        run.returned().and_then(|v| v.value),
        Some(10),
        "{}",
        run.text()
    );
    let printf = run
        .steps
        .iter()
        .find(|step| step.text.starts_with("printf("))
        .expect("the call to printf is a step");
    assert!(
        printf
            .note
            .as_deref()
            .is_some_and(|note| note.contains("not followed")),
        "{printf:?}"
    );
    // A step limit, and a parameter not given.
    let run = image
        .emulate(
            sum_to,
            &[1_000_000],
            &EmulationLimits {
                steps: 30,
                depth: 8,
            },
        )
        .expect("sum_to lifts");
    assert!(
        run.text().contains("; stopped after 30 steps"),
        "{}",
        run.text()
    );
    let run = image
        .emulate(sum_to, &[], &EmulationLimits::default())
        .expect("sum_to lifts");
    assert!(
        run.text().contains("depends on an unknown value"),
        "{}",
        run.text()
    );
    assert!(run.returned().is_none());
    // A global the file holds no bytes for is zero when loaded: the run
    // reads it, not an unknown.
    let dtors = address_of(&image, "__do_global_dtors_aux");
    let run = image
        .emulate(dtors, &[], &EmulationLimits::default())
        .expect("the destructor glue lifts");
    assert!(
        !run.text().contains("completed.0 != 0 depends"),
        "{}",
        run.text()
    );
    // It goes on to the import slot it reads next, which is not the image's
    // to know.
    assert!(run.text().contains("__cxa_finalize"), "{}", run.text());
    // A function the lifter refuses is not run.
    assert!(image
        .emulate(
            address_of(&image, "_start"),
            &[],
            &EmulationLimits::default()
        )
        .is_err());
}
