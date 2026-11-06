use std::path::Path;

use ag_engine::Image;

fn cxx() -> Image {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cxx.elf");
    Image::open(&path).expect("the C++ fixture ELF loads")
}

#[test]
fn the_cxx_metadata_names_the_classes_and_their_vtables() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    assert!(metadata.classes.contains_key("base"), "{:?}", metadata.classes.keys());
    assert!(metadata.classes.contains_key("derived"), "{:?}", metadata.classes.keys());
    // The ABI's own classes are not classes of the program.
    assert!(
        !metadata.classes.keys().any(|name| name.contains("__cxxabiv1")),
        "{:?}",
        metadata.classes.keys()
    );
    let base = &metadata.classes["base"];
    assert_eq!(base.vtable, Some(0x402048));
    assert_eq!(base.type_info, Some(0x402010));
    let derived = &metadata.classes["derived"];
    assert_eq!(derived.vtable, Some(0x402068));
    assert_eq!(derived.type_info, Some(0x402030));
}

#[test]
fn the_vtables_hold_the_virtual_functions_in_declaration_order() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let base = &metadata.classes["base"];
    let names: Vec<&str> = base.vfuncs.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["base::f(int)", "base::g()"]);
    assert_eq!(base.vfuncs[0].slot, 0);
    assert_eq!(base.vfuncs[1].slot, 1);
    assert!(base.vfuncs.iter().all(|v| v.implementation.is_some()));
    // The derived table overrides the first slot and inherits the second.
    let derived = &metadata.classes["derived"];
    let names: Vec<&str> = derived.vfuncs.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["derived::f(int)", "base::g()"]);
    assert_ne!(derived.vfuncs[0].implementation, base.vfuncs[0].implementation);
    assert_eq!(derived.vfuncs[1].implementation, base.vfuncs[1].implementation);
}

#[test]
fn the_vtable_references_name_the_class_and_the_slot() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    // The first slot of each table, by its address in the image.
    assert_eq!(metadata.vtable_refs.get(&0x402058), Some(&("base".to_string(), 0)));
    assert_eq!(metadata.vtable_refs.get(&0x402060), Some(&("base".to_string(), 1)));
    assert_eq!(
        metadata.vtable_refs.get(&0x402078),
        Some(&("derived".to_string(), 0))
    );
    assert_eq!(
        metadata.vtable_refs.get(&0x402080),
        Some(&("derived".to_string(), 1))
    );
    assert_eq!(metadata.vfunc_names.get(&0x401136).map(String::as_str), Some("base::f(int)"));
    assert_eq!(metadata.vfunc_names.get(&0x40113e).map(String::as_str), Some("base::g()"));
    assert_eq!(metadata.vfunc_names.get(&0x401146).map(String::as_str), Some("derived::f(int)"));
}

#[test]
fn the_constructors_are_noted_by_their_address() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let base = &metadata.classes["base"];
    assert_eq!(base.constructor, Some(0x40114e));
    let derived = &metadata.classes["derived"];
    assert_eq!(derived.constructor, Some(0x401162));
}

#[test]
fn the_cxx_references_invert_the_vtable_refs() {
    let image = cxx();
    let references = image.cxx_references().expect("the fixture carries C++ classes");
    assert_eq!(
        references.vtable_refs.get(&0x402058),
        Some(&("base".to_string(), 0))
    );
    // Each vtable stands with its own slots.
    assert_eq!(
        references.vtable_users.get(&0x402048),
        Some(&vec![0x402058, 0x402060])
    );
    assert_eq!(
        references.vtable_users.get(&0x402068),
        Some(&vec![0x402078, 0x402080])
    );
    assert_eq!(
        references.vfunc_names.get(&0x401136).map(String::as_str),
        Some("base::f(int)")
    );
}

#[test]
fn the_rtti_names_the_si_base() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let derived = &metadata.classes["derived"];
    assert_eq!(derived.base_classes.len(), 1);
    let base = &derived.base_classes[0];
    assert_eq!(base.class, "base");
    assert_eq!(base.offset, 0);
    assert!(base.is_public);
    assert!(!base.is_virtual);
    assert!(metadata.classes["base"].base_classes.is_empty());
}

#[test]
fn the_rtti_names_the_vmi_bases_in_order() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cxx_mi.elf");
    let image = Image::open(&path).expect("the MI fixture loads");
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let multi = &metadata.classes["multi"];
    assert_eq!(multi.type_info, Some(0x402040));
    assert_eq!(multi.base_classes.len(), 2);
    let primary = &multi.base_classes[0];
    assert_eq!(primary.class, "base");
    assert_eq!(primary.offset, 0);
    assert!(primary.is_public);
    assert!(!primary.is_virtual);
    // The secondary base sits a pointer-width after the primary's data.
    let secondary = &multi.base_classes[1];
    assert_eq!(secondary.class, "side");
    assert_eq!(secondary.offset, 16);
    assert!(secondary.is_public);
    assert!(!secondary.is_virtual);
}

#[test]
fn the_vtable_carries_two_groups_for_mi() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cxx_mi.elf");
    let image = Image::open(&path).expect("the MI fixture loads");
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let multi = &metadata.classes["multi"];
    assert_eq!(multi.vtable_groups.len(), 2);
    let primary = &multi.vtable_groups[0];
    assert_eq!(primary.address, 0x4020a8);
    assert_eq!(primary.offset_to_top, 0);
    assert_eq!(primary.owner, "multi");
    assert_eq!(primary.slots, vec![0, 1]);
    let secondary = &multi.vtable_groups[1];
    assert_eq!(secondary.address, 0x4020c8);
    assert_eq!(secondary.offset_to_top, -16);
    assert_eq!(secondary.owner, "multi");
    assert_eq!(secondary.slots, vec![2]);
    // A single-base class carries one group.
    let base = &metadata.classes["base"];
    assert_eq!(base.vtable_groups.len(), 1);
}

#[test]
fn a_c_image_has_no_cxx_classes() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.elf");
    let image = Image::open(&path).expect("the sample ELF loads");
    assert!(image.cxx().is_none());
    assert!(image.cxx_references().is_none());
}

#[test]
fn the_rtti_names_virtual_bases() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cxx_vi.elf");
    let image = Image::open(&path).expect("the VI fixture loads");
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    // left and right each virtually inherit vbase: the flag word carries
    // the virtual bit (0x1) with public (0x2), and the offset to the top.
    let left = &metadata.classes["left"];
    assert_eq!(left.base_classes.len(), 1);
    let vb = &left.base_classes[0];
    assert_eq!(vb.class, "vbase");
    assert!(vb.is_virtual);
    assert!(vb.is_public);
    assert_eq!(vb.offset, -32);
    // diamond inherits left and right non-virtually: public, not virtual,
    // the second base displaced by one subobject.
    let diamond = &metadata.classes["diamond"];
    assert_eq!(diamond.base_classes.len(), 2);
    assert_eq!(diamond.base_classes[0].class, "left");
    assert!(!diamond.base_classes[0].is_virtual);
    assert_eq!(diamond.base_classes[0].offset, 0);
    assert_eq!(diamond.base_classes[1].class, "right");
    assert!(!diamond.base_classes[1].is_virtual);
    assert_eq!(diamond.base_classes[1].offset, 8);
}
