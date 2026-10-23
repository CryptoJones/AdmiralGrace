//! The Objective-C method overlay.
//!
//! A method map is a JSON array of records, each naming the IMP of a method,
//! the class it belongs to, its selector and its types:
//!
//! ```json
//! [
//!   { "imp": "0x1000", "class": "NSString", "sel": "length", "types": "Q" },
//!   { "imp": "0x2000", "class": "NSString", "sel": "alloc", "types": "@16@0:8" }
//! ]
//! ```
//!
//! A class method is an instance method of the class's metaclass, and the
//! two are told apart in the display: `-` for an instance method, `+` for a
//! class method. A map may say which it is with a flag
//! (`"is_class_method": true`), or by writing the class with a leading `+`
//! (`"class": "+NSString"`). A map that says neither is read as instance
//! methods, which is what such a map holds.
//!
//! Nothing here is dropped in silence: a record whose IMP is not an address
//! is skipped and named in the warnings, and two records that claim the same
//! address or the same name are both reported.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::parse_addr;

/// One method, as a method map records it.
#[derive(Debug, Clone, Deserialize)]
pub struct ObjCMethodRecord {
    /// The address of the method's implementation.
    pub imp: String,
    /// The class the method belongs to.
    pub class: Option<String>,
    /// The selector.
    pub sel: String,
    /// The type encoding.
    pub types: Option<String>,
    /// Whether the method is a class method.
    ///
    /// A map may leave this out and write the class with a leading `+`
    /// instead.
    #[serde(default, alias = "class_method")]
    pub is_class_method: Option<bool>,
}

/// One method, read from a method map.
#[derive(Debug, Clone)]
pub struct ObjCMethod {
    /// The address of the method's implementation.
    pub imp: u64,
    /// The class the method belongs to, without the `+` marker.
    pub class: String,
    /// The selector.
    pub sel: String,
    /// The type encoding.
    pub types: Option<String>,
    /// Whether the method is a class method rather than an instance method.
    pub is_class_method: bool,
}

/// A method map, and what could not be read from it.
#[derive(Debug, Default, Clone)]
pub struct MethodMap {
    /// The methods the map holds.
    pub methods: Vec<ObjCMethod>,
    /// What the map held that could not be read.
    pub warnings: Vec<String>,
}

/// Read a method map.
pub fn load_map(path: &Path) -> Result<MethodMap> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let records: Vec<ObjCMethodRecord> =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

    let mut map = MethodMap {
        methods: Vec::with_capacity(records.len()),
        warnings: Vec::new(),
    };

    for record in &records {
        let imp = match parse_addr(&record.imp) {
            Ok(imp) => imp,
            Err(error) => {
                map.warnings.push(format!(
                    "{} was skipped: its IMP {:?} is not an address ({error})",
                    record_name(record),
                    record.imp
                ));
                continue;
            }
        };

        map.methods.push(ObjCMethod {
            imp,
            class: record_class(record),
            sel: record.sel.clone(),
            types: record.types.clone(),
            is_class_method: is_class_method(record),
        });
    }

    Ok(map)
}

/// Whether the record names a class method.
fn is_class_method(record: &ObjCMethodRecord) -> bool {
    if let Some(flag) = record.is_class_method {
        return flag;
    }

    record
        .class
        .as_deref()
        .is_some_and(|class| class.trim_start().starts_with('+'))
}

/// The class of the record, without the marker that says it is a class method.
fn record_class(record: &ObjCMethodRecord) -> String {
    let class = record.class.as_deref().unwrap_or("").trim();
    class.trim_start_matches('+').trim().to_string()
}

/// The name of a method, as it is displayed.
fn record_name(record: &ObjCMethodRecord) -> String {
    let sign = if is_class_method(record) { "+" } else { "-" };
    format!("{sign}[{} {}]", record_class(record), record.sel)
}

/// The display of a method: `-[Class sel]` for an instance method, `+[Class
/// sel]` for a class method.
pub fn method_display(m: &ObjCMethod) -> String {
    let sign = if m.is_class_method { "+" } else { "-" };
    format!("{sign}[{} {}]", m.class, m.sel)
}

/// The Objective-C methods laid over a corpus.
pub struct Overlay {
    /// The image-base shift: a corpus address is `imp + shift`.
    pub shift: u64,
    /// The methods, keyed by the corpus address they sit at.
    pub by_imp: BTreeMap<u64, ObjCMethod>,
    /// The methods, keyed by their qualified name.
    ///
    /// The name is qualified — the class and the kind of method — so that
    /// `-[Foo bar]` and `+[Foo bar]` are two names and not one.
    pub by_name: BTreeMap<String, u64>,
    /// What the map held that could not be read, and what clashed.
    pub warnings: Vec<String>,
    /// The methods as they were read, before the shift.
    base: Vec<ObjCMethod>,
    /// The warnings of the map itself, kept apart from the clashes.
    map_warnings: Vec<String>,
}

impl Overlay {
    /// An overlay of the methods a map holds.
    pub fn new(map: MethodMap) -> Overlay {
        let mut overlay = Overlay {
            shift: 0,
            by_imp: BTreeMap::new(),
            by_name: BTreeMap::new(),
            warnings: Vec::new(),
            base: map.methods,
            map_warnings: map.warnings,
        };

        overlay.rebuild();
        overlay
    }

    /// Set the image-base shift: corpus addresses are `imp + shift`.
    ///
    /// The shift is applied once, however many times this is called: the
    /// methods are kept as they were read, and the address of each is worked
    /// out from them afresh. Applying it twice does not move the methods
    /// twice.
    pub fn with_shift(mut self, shift: u64) -> Overlay {
        self.shift = shift;
        self.rebuild();
        self
    }

    /// The corpus address of an IMP.
    pub fn imp_addr(&self, imp: u64) -> u64 {
        imp.wrapping_add(self.shift)
    }

    /// Work out the address and the name of every method from the shift.
    fn rebuild(&mut self) {
        self.by_imp.clear();
        self.by_name.clear();

        let mut clashes = Vec::new();
        let methods = std::mem::take(&mut self.base);

        for method in &methods {
            let address = self.imp_addr(method.imp);
            let name = method_display(method);

            // Two methods at one address: the first keeps it, and the clash
            // is said out loud.
            match self.by_imp.entry(address) {
                Entry::Vacant(slot) => {
                    slot.insert(method.clone());
                }
                Entry::Occupied(slot) => {
                    let first = method_display(slot.get());
                    clashes.push(format!(
                        "two methods share the address {address:#x}: {first} and {name}; \
                         the first is kept"
                    ));
                }
            }

            // Two methods with one name: the first keeps it, and the clash
            // is said out loud.
            match self.by_name.entry(name.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(address);
                }
                Entry::Occupied(slot) => {
                    let first = *slot.get();
                    clashes.push(format!(
                        "two methods share the name {name}: one at {first:#x} and one at \
                         {address:#x}; the first is kept"
                    ));
                }
            }
        }

        self.base = methods;
        self.warnings = self.map_warnings.clone();
        self.warnings.extend(clashes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// A temporary directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "ag-objc-{tag}-{}-{:?}",
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

        fn path(&self) -> PathBuf {
            self.0.join("methods.json")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// One method, as a map holds it.
    fn method(imp: u64, class: &str, sel: &str, is_class_method: bool) -> ObjCMethod {
        ObjCMethod {
            imp,
            class: class.into(),
            sel: sel.into(),
            types: None,
            is_class_method,
        }
    }

    #[test]
    fn a_record_whose_imp_is_not_an_address_is_skipped_and_said() {
        let dir = TempDir::new("bad-imp");
        dir.write(
            "methods.json",
            r#"[{"imp":"nope","class":"Foo","sel":"broken"},
                {"imp":"0x1000","class":"Foo","sel":"good"}]"#,
        );

        let map = load_map(&dir.path()).expect("a map");

        assert_eq!(map.methods.len(), 1, "the bad record is not kept");
        assert_eq!(map.methods[0].sel, "good");
        assert_eq!(
            map.warnings.len(),
            1,
            "the break is said: {:?}",
            map.warnings
        );
        assert!(
            map.warnings[0].contains("nope"),
            "the warning names the record: {:?}",
            map.warnings
        );
    }

    #[test]
    fn a_class_written_with_a_plus_is_a_class_method() {
        let dir = TempDir::new("plus-class");
        dir.write(
            "methods.json",
            r#"[{"imp":"0x1000","class":"+Foo","sel":"bar"}]"#,
        );

        let map = load_map(&dir.path()).expect("a map");

        assert!(map.methods[0].is_class_method, "the plus says it is one");
        assert_eq!(map.methods[0].class, "Foo", "the marker is not in the name");
        assert_eq!(method_display(&map.methods[0]), "+[Foo bar]");
    }

    #[test]
    fn a_class_method_and_an_instance_method_are_two_names() {
        let map = MethodMap {
            methods: vec![
                method(0x1000, "Foo", "bar", false),
                method(0x2000, "Foo", "bar", true),
            ],
            warnings: Vec::new(),
        };

        let overlay = Overlay::new(map);

        assert_eq!(
            overlay.by_name.len(),
            2,
            "the two kinds of method are two names: {:?}",
            overlay.by_name
        );
        assert_eq!(overlay.by_name.get("-[Foo bar]"), Some(&0x1000));
        assert_eq!(overlay.by_name.get("+[Foo bar]"), Some(&0x2000));
        assert!(
            overlay.warnings.is_empty(),
            "two names are no clash: {:?}",
            overlay.warnings
        );
    }

    #[test]
    fn two_methods_at_one_address_are_a_clash_and_said() {
        let map = MethodMap {
            methods: vec![
                method(0x1000, "Foo", "bar", false),
                method(0x1000, "Foo", "baz", false),
            ],
            warnings: Vec::new(),
        };

        let overlay = Overlay::new(map);

        assert_eq!(overlay.by_imp.len(), 1, "the address is kept once");
        assert_eq!(
            overlay.warnings.len(),
            1,
            "the clash is said: {:?}",
            overlay.warnings
        );
        assert!(
            overlay.warnings[0].contains("0x1000"),
            "the warning names the address: {:?}",
            overlay.warnings
        );
    }

    #[test]
    fn the_shift_is_applied_once_however_many_times_it_is_set() {
        let map = MethodMap {
            methods: vec![method(0x1000, "Foo", "bar", false)],
            warnings: Vec::new(),
        };

        let once = Overlay::new(map.clone()).with_shift(0x400000);
        let twice = Overlay::new(map).with_shift(0x400000).with_shift(0x400000);

        assert_eq!(
            once.by_imp.keys().collect::<Vec<_>>(),
            vec![&0x401000],
            "the method sits at the address once"
        );
        assert_eq!(
            twice.by_imp.keys().collect::<Vec<_>>(),
            once.by_imp.keys().collect::<Vec<_>>(),
            "setting the shift twice does not move the method twice"
        );
        assert_eq!(twice.by_name.get("-[Foo bar]"), Some(&0x401000));
    }
}
