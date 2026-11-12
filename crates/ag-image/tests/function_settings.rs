//! The per-function analysis settings: the engine options and the emulation
//! limits one function is read under, over the run's own, and kept to itself.

use std::collections::BTreeMap;
use std::path::Path;

use ag_image::{Binary, EmulationLimits, FunctionProperties};

fn sample() -> Binary {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    Binary::open(&root.join("../ag-engine/tests/fixtures/sample.elf")).expect("the sample opens")
}

const ADD: u64 = 0x1149;
const SUM_TO: u64 = 0x1161;

fn options(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn emulation_limits_are_the_runs_until_the_function_says() {
    let image = sample();
    let defaults = EmulationLimits::default();
    // Nothing said: the run's own limits.
    assert_eq!(image.emulation_limits(ADD).steps, defaults.steps);
    assert_eq!(image.emulation_limits(ADD).depth, defaults.depth);

    // Both said: the function's own.
    let props = BTreeMap::from([(
        ADD,
        FunctionProperties {
            emulation_steps: Some(500),
            emulation_depth: Some(3),
            ..Default::default()
        },
    )]);
    assert!(image.set_function_properties(props));
    assert_eq!(image.emulation_limits(ADD).steps, 500);
    assert_eq!(image.emulation_limits(ADD).depth, 3);
    // The other function keeps the run's.
    assert_eq!(image.emulation_limits(SUM_TO).steps, defaults.steps);
    assert_eq!(image.emulation_limits(SUM_TO).depth, defaults.depth);

    // Only the steps said: the depth is left to the run's.
    let props = BTreeMap::from([(
        ADD,
        FunctionProperties {
            emulation_steps: Some(7),
            ..Default::default()
        },
    )]);
    assert!(image.set_function_properties(props));
    assert_eq!(image.emulation_limits(ADD).steps, 7);
    assert_eq!(image.emulation_limits(ADD).depth, defaults.depth);
}

#[test]
fn options_for_lays_the_functions_words_over_the_runs() {
    let image = sample();
    // Nothing said: the run's own options.
    assert_eq!(image.options_for(ADD).get("language").as_deref(), Some("c"));
    assert_eq!(image.abi_for(ADD), image.abi());

    let props = BTreeMap::from([(
        ADD,
        FunctionProperties {
            options: options(&[("language", "rust"), ("abi", "win64")]),
            ..Default::default()
        },
    )]);
    assert!(image.set_function_properties(props));
    // The function's words stand over the run's; the rest is the run's.
    assert_eq!(
        image.options_for(ADD).get("language").as_deref(),
        Some("rust")
    );
    assert_eq!(image.options_for(ADD).get("abi").as_deref(), Some("win64"));
    assert_eq!(image.options_for(ADD).get("indent").as_deref(), Some("2"));
    assert_ne!(image.abi_for(ADD), image.abi());
    // The other function keeps the run's.
    assert_eq!(
        image.options_for(SUM_TO).get("language").as_deref(),
        Some("c")
    );
    assert_eq!(image.abi_for(SUM_TO), image.abi());
}

#[test]
fn a_functions_option_is_read_by_the_lift_and_kept_to_itself() {
    let image = sample();
    assert!(image
        .pseudocode(ADD)
        .expect("add lifts")
        .text()
        .contains("int add("));

    // An option set for add alone is read by the lift: Rust where the run
    // reads C, and the same words set again change nothing.
    let props = BTreeMap::from([(
        ADD,
        FunctionProperties {
            options: options(&[("language", "rust")]),
            ..Default::default()
        },
    )]);
    assert!(image.set_function_properties(props.clone()));
    assert!(image
        .pseudocode(ADD)
        .expect("add lifts")
        .text()
        .contains("fn add("));
    assert!(!image.set_function_properties(props));
    // sum_to is untouched: it still reads C.
    assert!(image
        .pseudocode(SUM_TO)
        .expect("sum_to lifts")
        .text()
        .contains("long sum_to("));

    // Taking the option back reads C again.
    assert!(image.set_function_properties(BTreeMap::new()));
    assert!(image
        .pseudocode(ADD)
        .expect("add lifts")
        .text()
        .contains("int add("));
}
