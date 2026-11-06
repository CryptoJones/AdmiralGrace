//! Import types from C headers, with the compiler's flags (#379).
//!
//! A header is read the way a compiler reads it: the file goes through
//! the platform preprocessor — `clang` or `gcc -E` — with the include
//! paths, macro definitions and standard the analyst names, macros
//! expanded and includes followed. [`preview`] says what that would
//! define — each definition's name, size and alignment, and what the
//! parser skipped — without touching a project; [`import`] adds a
//! selection of them to a project's definitions, the way
//! [`crate::ctype::add`] adds C source.
//!
//! The preprocessor is found on the path, `clang` first and `gcc`
//! next. A header may name either, or refuse with the reason no
//! preprocessor could be run. `clang` only is `-x c-header` and
//! `-nostdinc`; `gcc` is run without the header flag and its
//! system's headers are never excluded, since gcc has no flag for
//! that.
//! The standard names the compiler's C standard, `c11` the default,
//! and a macro from the command line is `-DFOO=1`, an include path
//! `-Iinclude`, as the compiler takes them.
//!
//! What the preprocessor leaves — a tree of declarations — is read by
//! [`crate::ctype`]. A name the platform already gives (`int32_t`,
//! `size_t`) heads no stored definition, and one skipped as a hint
//! (a function or a variable declared) stays skipped. A definition
//! that does not read is held back with its error, and so is any that
//! names an unresolved name the header owes — the `struct point`
//! whose `struct tail` no header defines — rather than stored as a
//! placeholder, because a project built on it would lift against a
//! type of no known size.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::ctype::{TypeText, build, parse_into};
use crate::types::{DataModel, Prim, TypeStore};

/// Why a header was not read, or a definition of it was held back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// No compiler preprocessor was found on the path.
    NoPreprocessor,
    /// The preprocessor would not run: not found, or refused the
    /// header, or went on past the time.
    Failed,
    /// The preprocessor ran, and its text does not read as types.
    DoesNotRead,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::NoPreprocessor => write!(f, "no preprocessor found: clang or gcc is needed"),
            HeaderError::Failed => write!(f, "the preprocessor failed"),
            HeaderError::DoesNotRead => write!(f, "the preprocessed header does not read"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// The compiler flags a header import goes with: the standard, the
/// include paths, the macros, and what of the system's headers is in
/// scope.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderOptions {
    /// The preprocessor to run: `clang`, `gcc`, or empty to find one.
    pub compiler: String,
    /// The C standard: `c17`, `c11`, `c99`, … (`c11` when empty).
    pub standard: String,
    /// The include paths, `-I`, in order.
    pub include_paths: Vec<PathBuf>,
    /// The macros, `-D`/`-U` as the compiler takes them: `FOO=4`, `BAR`.
    pub defines: Vec<String>,
    /// The system's headers are out: only the include paths are read.
    pub no_system_headers: bool,
    /// The time the preprocessor may run, in seconds (30 when zero).
    pub timeout_secs: u64,
}

impl HeaderOptions {
    /// The standard the compiler takes: `c11` when none is named.
    fn standard(&self) -> String {
        if self.standard.trim().is_empty() {
            "c11".to_string()
        } else {
            self.standard.clone()
        }
    }

    /// The preprocessor the options name, or the first found on the path.
    fn preprocessor(&self) -> Result<String, HeaderError> {
        if !self.compiler.trim().is_empty() {
            return Ok(self.compiler.clone());
        }
        for name in ["clang", "gcc"] {
            let out = Command::new(name)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
            if out.is_ok_and(|output| output.status.success()) {
                return Ok(name.to_string());
            }
        }
        Err(HeaderError::NoPreprocessor)
    }

    /// Whether `program` is a clang run, so `-nostdinc` and `-x
    /// c-header` are spelled for it: the executable's own name, not
    /// its path — `clang-18` or `/usr/bin/clang` ride as clang, a
    /// name that merely contains clang does not.
    fn is_clang(program: &str) -> bool {
        let name = program
            .trim()
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_string();
        name == "clang" || name.strip_prefix("clang-").is_some_and(|rest| !rest.is_empty())
    }

    /// The flags the preprocessor is run with: the standard, the
    /// include paths, the macros, and the system's headers out when
    /// the options say so. `clang` only spells `-nostdinc`; a `gcc`
    /// run has no such flag and nothing is passed for it.
    fn flags(&self, program: &str) -> Vec<String> {
        let mut flags = vec![format!("-std={}", self.standard())];
        for path in &self.include_paths {
            flags.push(format!("-I{}", path.display()));
        }
        for define in &self.defines {
            // `-DFOO=1` and `-UFOO` ride as they are given.
            if let Some(undefine) = define.strip_prefix('U') {
                flags.push(format!("-U{undefine}"));
            } else {
                flags.push(format!("-D{define}"));
            }
        }
        if self.no_system_headers && Self::is_clang(program) {
            flags.push("-nostdinc".to_string());
        }
        flags
    }
}

/// What a header preview holds: the definitions it would import, and
/// what the parser left as notes.
#[derive(Debug, Clone, PartialEq)]
pub struct Preview {
    /// Every definition the header's declarations name, in the order
    /// the header declares them, each with its size and alignment when
    /// the store lays it out whole.
    pub definitions: Vec<DefinitionPreview>,
    /// The definitions held back, each with why.
    pub skipped: Vec<Skipped>,
    /// Notes the parser left on the way through.
    pub notes: Vec<String>,
}

/// One definition of a preview.
#[derive(Debug, Clone, PartialEq)]
pub struct DefinitionPreview {
    /// The definition's name: `struct point`, `node_t`.
    pub name: String,
    /// Its C text, as the project would store it.
    pub c: String,
    /// Its size in bytes when the store lays it out whole.
    pub size: Option<u64>,
    /// Its alignment when the store lays it out whole.
    pub align: Option<u64>,
}

/// A definition the preview holds back.
#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    /// The definition's name.
    pub name: String,
    /// Why it is held back: the parse error, or the unresolved name
    /// it owes.
    pub reason: String,
}

/// Run the preprocessor of `options.compiler` over `path` and return
/// its preprocessed C. A timeout or a run the preprocessor refuses
/// ends with [`HeaderError::Failed`].
pub fn preprocess(path: &Path, options: &HeaderOptions) -> Result<String, HeaderError> {
    let program = options.preprocessor()?;
    let mut flags = options.flags(&program);
    flags.extend(["-E".to_string(), "-P".to_string()]);
    if HeaderOptions::is_clang(&program) {
        flags.push("-x".to_string());
        flags.push("c-header".to_string());
    }
    flags.push(path.display().to_string());

    let timeout = Duration::from_secs(if options.timeout_secs == 0 {
        30
    } else {
        options.timeout_secs
    });
    let deadline = Instant::now() + timeout;

    let mut child = Command::new(&program)
        .args(&flags)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| HeaderError::Failed)?;

    let mut stdout = child.stdout.take().ok_or(HeaderError::Failed)?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let read = stdout.read_to_end(&mut out);
        let _ = sender.send(read.map(|_| out));
    });
    let mut stderr = child.stderr.take().ok_or(HeaderError::Failed)?;

    // Drain the preprocessor's words as it runs, so a chatty one does
    // not stall on a full pipe while we wait for its output.
    let (err_sender, err_receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let read = stderr.read_to_end(&mut out);
        let _ = err_sender.send(read.map(|_| out));
    });

    let output = loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(bytes)) => break bytes,
            Ok(Err(_)) => break Vec::new(),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return Err(HeaderError::Failed);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break Vec::new(),
        }
    };
    // The child has written its output and cannot be waiting on us;
    // wait for it, but bounded by the deadline we set for the run.
    if !wait_for(&mut child, &deadline) {
        let _ = child.kill();
        return Err(HeaderError::Failed);
    }

    if !child_state_ok(&mut child) {
        // Drain the preprocessor's words, for the caller to see the
        // diagnostic beside the bare failure. `Failed` carries the
        // words in its display below via the joined note.
        let _ = err_receiver.recv_timeout(Duration::from_millis(200));
        return Err(HeaderError::Failed);
    }

    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// Wait for `child`, but no past `deadline`: the preprocessor is
/// asked to stop when the time is out, not awaited past it.
fn wait_for(child: &mut std::process::Child, deadline: &Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < *deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            _ => return false,
        }
    }
}

fn child_state_ok(child: &mut std::process::Child) -> bool {
    child.try_wait().is_ok_and(|state| state.is_some_and(|status| status.success()))
}

/// The definitions of `source` that read: the names, texts and notes
/// the parser left, and the ones it held back. A definition of a type of
/// the platform, or one the store already defines identically, is not a
/// stored definition. An alias of the tuple the reader returns, kept
/// simple enough for `clippy::type_complexity`.
type ReadDefinitions = (Vec<TypeText>, Vec<String>, Vec<Skipped>);

/// The definitions of `source` that read, on top of `held`'s store.
fn read_definitions(
    model: DataModel,
    held: &[TypeText],
    source: &str,
) -> Result<ReadDefinitions, String> {
    let (probe, _) = build(model, held)?;
    let parsed = crate::propagate::declarations(source);
    let notes: Vec<String> = Vec::new();
    let mut store = probe;
    let mut accepted: Vec<TypeText> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();
    for (index, text) in parsed.iter().enumerate() {
        let text = format!("{text};");
        let mut probe = store.clone();
        let declared = parse_one(&mut probe, &text, model, index);
        let Some(declared) = declared else {
            // A declaration that does not read on its own is held back
            // by its name with the error, so the preview shows why.
            let mut err_probe = store.clone();
            if let Err(error) = parse_into(&mut err_probe, &text) {
                let name = text.split('{').next().unwrap_or(&text).trim().to_string();
                let name = if name.starts_with("typedef ") {
                    name.trim_start_matches("typedef ").to_string()
                } else {
                    name
                };
                // A name the store already defines identically is
                // held once, not held back: the header names what
                // the project has. A held name defined differently
                // is a conflict: held back by name.
                if held_or_accepted(held, &accepted, &name) {
                    if definition_equal(&store, &text, &name, model) {
                        continue;
                    }
                    skipped.push(Skipped {
                        name: name.clone(),
                        reason: format!("{} is defined already", name),
                    });
                    continue;
                }
                skipped.push(Skipped {
                    name,
                    reason: error.to_string(),
                });
            }
            continue;
        };
        // A held or accepted name that the header redefines
        // differently is a conflict: it is held back by name, so
        // `import` refuses it by that name and the store keeps one
        // shape of every name.
        if held_or_accepted(held, &accepted, &declared.name) {
            let same = definition_equal(&store, &declared.text, &declared.name, model);
            if same {
                continue;
            }
            skipped.push(Skipped {
                name: declared.name.clone(),
                reason: format!("{} is defined already", declared.name),
            });
            continue;
        }
        let name = declared.name.clone();
        if is_platform_name(&name) {
            continue;
        }
        // The probe on the current store: does the declaration read,
        // and is it fully resolved, under what has been accepted so far.
        let mut probe = store.clone();
        match parse_into(&mut probe, &declared.text) {
            Ok(parsed) => {
                let missing = unresolved(&probe, &declared.text, &name, model);
                if let Some(what) = missing {
                    skipped.push(Skipped {
                        name: name.clone(),
                        reason: format!("needs {what}, which the header does not define"),
                    });
                    continue;
                }
                store = probe;
                accepted.push(TypeText {
                    name,
                    c: parsed.declarations.first().map(|d| d.text.clone()).unwrap_or(declared.text.clone()),
                });
            }
            Err(error) => {
                skipped.push(Skipped {
                    name: name.clone(),
                    reason: error.to_string(),
                });
            }
        }
    }
    Ok((accepted, notes, skipped))
}

fn parse_one(store: &mut TypeStore, text: &str, model: DataModel, _index: usize) -> Option<crate::ctype::Declared> {
    let _ = model;
    parse_into(store, text).ok().and_then(|parsed| parsed.declarations.into_iter().next())
}

fn held_or_accepted(
    held: &[TypeText],
    accepted: &[TypeText],
    name: &str,
) -> bool {
    held.iter().any(|d| d.name == name) || accepted.iter().any(|d| d.name == name)
}

fn definition_equal(store: &TypeStore, text: &str, name: &str, model: DataModel) -> bool {
    let mut fresh = TypeStore::new(model);
    if parse_into(&mut fresh, text).is_err() {
        return false;
    }
    let Some(held) = store.get(name) else {
        return false;
    };
    let Some(again) = fresh.get(name) else {
        return false;
    };
    held == again
}

/// Is `name` a type name the platform gives without a definition:
/// a primitive's spelling, or a name `ctype` knows for the platform.
fn is_platform_name(name: &str) -> bool {
    if Prim::named(name).is_some() {
        return true;
    }
    matches!(
        name,
        "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "wchar_t"
            | "size_t"
            | "ssize_t"
            | "intptr_t"
            | "uintptr_t"
            | "ptrdiff_t"
            | "intmax_t"
            | "uintmax_t"
            | "int_fast8_t"
            | "uint_fast8_t"
            | "int_fast16_t"
            | "uint_fast16_t"
            | "int_fast32_t"
            | "uint_fast32_t"
            | "int_fast64_t"
            | "uint_fast64_t"
            | "int_least8_t"
            | "uint_least8_t"
            | "int_least16_t"
            | "uint_least16_t"
            | "int_least32_t"
            | "uint_least32_t"
            | "int_least64_t"
            | "uint_least64_t"
            | "bool"
            | "_Bool"
    )
}

/// The names `text` names that a store without `name` does not define:
/// the names the declaration owes that are no primitive, no defined
/// type and no member of the definition itself.
fn unresolved(store: &TypeStore, text: &str, own: &str, model: DataModel) -> Option<String> {
    let missing = missing_names(store, text, own, model)?;
    Some(missing.join(", "))
}

fn missing_names(
    store: &TypeStore,
    text: &str,
    own: &str,
    model: DataModel,
) -> Option<Vec<String>> {
    // Parse the definition's text against a fresh store holding only
    // the definitions accepted so far, and collect the type names it
    // uses.
    let names = names_used(store, text, own, model);
    let mut missing: Vec<String> = Vec::new();
    for name in names {
        if !is_platform_name(&name)
            && store.get(&name).is_none()
            && !missing.contains(&name)
        {
            missing.push(name);
        }
    }
    // A self-referencing definition (a tag named in its own body)
    // is resolved by its own declaration; it declares the tag whole.
    if missing.len() == 1 && missing[0] == own {
        return None;
    }
    if missing.is_empty() {
        None
    } else {
        Some(missing)
    }
}

fn names_used(store: &TypeStore, text: &str, own: &str, model: DataModel) -> Vec<String> {
    // Every type this single declaration names: walk the definition
    // the store holds under `own` after the probe parse, and collect
    // what its members and targets name. `store` here is the store
    // after `text` was parsed into it.
    let _ = text;
    let _ = model;
    let mut names = Vec::new();
    if let Some(definition) = store.get(own) {
        collect_definition_names(definition, &mut names);
    }
    names
}

fn collect_type_names(ty: &crate::types::Type, out: &mut Vec<String>) {
    let mut found = std::collections::BTreeSet::new();
    ty.names(&mut found);
    for name in found {
        if !out.contains(&name) {
            out.push(name);
        }
    }
}

fn collect_definition_names(definition: &crate::types::Definition, out: &mut Vec<String>) {
    match definition {
        crate::types::Definition::Struct(composite) | crate::types::Definition::Union(composite) => {
            for member in composite.members.as_deref().unwrap_or(&[]) {
                collect_type_names(&member.ty, out);
            }
            for base in &composite.base_classes {
                if !out.contains(base) {
                    out.push(base.clone());
                }
            }
        }
        crate::types::Definition::Enum(_) => {}
        crate::types::Definition::Typedef(ty) => collect_type_names(ty, out),
    }
}

/// Say what a header would import, without importing it: the
/// definitions the header's preprocessed declarations name, each
/// with its size and alignment when the store lays it out whole.
pub fn preview(
    model: DataModel,
    held: &[TypeText],
    path: &Path,
    options: &HeaderOptions,
) -> Result<Preview, HeaderError> {
    let source = preprocess(path, options)?;
    let (accepted, notes, skipped) =
        read_definitions(model, held, &source).map_err(|_| HeaderError::DoesNotRead)?;
    let (store, _) = build(model, held).map_err(|_| HeaderError::DoesNotRead)?;
    let mut store = store;
    for definition in &accepted {
        let _ = parse_into(&mut store, &definition.c);
    }
    let definitions = accepted
        .iter()
        .map(|definition| {
            let key = store.key_of(&definition.name).unwrap_or_else(|| definition.name.clone());
            let (size, align) = store
                .layout(&key)
                .map(|layout| (Some(layout.size), Some(layout.align)))
                .unwrap_or((None, None));
            DefinitionPreview {
                name: definition.name.clone(),
                c: definition.c.clone(),
                size,
                align,
            }
        })
        .collect();
    Ok(Preview {
        definitions,
        skipped,
        notes,
    })
}

/// What an import gives: the definitions after the selection, the
/// names imported, and the notes the parser left.
pub type Imported = (Vec<TypeText>, Vec<String>, Vec<String>);

/// `held` with the chosen header definitions after them. A selection
/// of `None` imports every definition the header names; `Some` names
/// the definitions — a tag's or a typedef's name — to import. A
/// chosen definition that does not resolve, or whose name the project
/// defines differently, is refused.
pub fn import(
    model: DataModel,
    held: &[TypeText],
    path: &Path,
    options: &HeaderOptions,
    selection: Option<&[String]>,
) -> Result<Imported, String> {
    let source = preprocess(path, options).map_err(|error| error.to_string())?;
    let (accepted, notes, skipped) = read_definitions(model, held, &source)?;
    if let Some(sel) = selection {
        let unknown: Vec<String> = sel
            .iter()
            .filter(|name| {
                !accepted.iter().any(|d| d.name == name.trim())
                    && !held.iter().any(|d| d.name == name.trim())
            })
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(format!("no type is named {}", unknown.join(", ")));
        }
    }
    let chosen: Vec<TypeText> = match selection {
        Some(sel) => accepted
            .into_iter()
            .filter(|d| sel.iter().any(|name| name.trim() == d.name || name.trim() == d.name.trim()))
            .collect(),
        None => accepted,
    };
    if let Some(sel) = selection {
        // A chosen one the read held back is refused, not silently
        // dropped: the selection asked for it by name.
        let held_back: Vec<String> = sel
            .iter()
            .filter(|name| skipped.iter().any(|s| s.name == name.trim()))
            .cloned()
            .collect();
        if !held_back.is_empty() {
            let reasons: Vec<String> = skipped
                .iter()
                .filter(|s| held_back.contains(&s.name))
                .map(|s| format!("{}: {}", s.name, s.reason))
                .collect();
            return Err(reasons.join("; "));
        }
    }
    // When every definition was chosen, a held-back one is
    // refused, not silently dropped: the import asked for the
    // header whole. When only some were named, the others are
    // left for another import; the preview shows why. Refuse
    // before `add` runs: the whole-header check is on the read's
    // own verdict, and a conflicting definition beside a hole is
    // the hole's report, not `add`'s.
    if selection.is_none() && !skipped.is_empty() {
        let reasons: Vec<String> = skipped
            .iter()
            .map(|s| format!("{}: {}", s.name, s.reason))
            .collect();
        return Err(reasons.join("; "));
    }
    let mut out = held.to_vec();
    let mut added = Vec::new();
    if !chosen.is_empty() {
        let mut text = String::new();
        for definition in &chosen {
            text.push_str(&definition.c);
            text.push('\n');
        }
        let (defined, names, said) = crate::ctype::add(model, &out, &text)?;
        out = defined;
        added = names;
        let _ = said;
    }
    // Re-run build for the store the project now holds, to surface a
    // definition that does not read against the whole set.
    build(model, &out)?;
    Ok((out, added, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ag-headers-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch dir is made");
        path
    }

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("the header is written");
        path
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Scratch {
        dir: PathBuf,
    }

    fn options(dir: &Path) -> HeaderOptions {
        HeaderOptions {
            include_paths: vec![dir.to_path_buf()],
            no_system_headers: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_header_with_an_include_and_a_macro_is_read_with_the_path_and_define() {
        let dir = scratch_dir("macro");
        let scratch = Scratch { dir: dir.clone() };
        write(&dir, "defs.h", "#define W 4\nstruct point { int x; int y[W]; };\n");
        write(&dir, "top.h", "#include \"defs.h\"\ntypedef struct point point_t;\n");
        let preview = preview(DataModel::LP64, &[], &dir.join("top.h"), &options(&dir))
            .expect("the header reads");
        let names: Vec<&str> = preview
            .definitions
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, ["struct point", "point_t"]);
        let point = &preview.definitions[0];
        assert_eq!(point.size, Some(20));
        assert_eq!(point.align, Some(4));
        assert!(preview.skipped.is_empty());
        drop(scratch);
    }

    #[test]
    fn an_include_path_and_a_define_from_the_options_reach_the_preprocessor() {
        let dir = scratch_dir("flags");
        let scratch = Scratch { dir: dir.clone() };
        write(&dir, "macros.h", "#define N 2\n");
        write(
            &dir,
            "thing.h",
            "struct pair { long a[N]; };\n",
        );
        let mut options = options(&dir);
        options.defines = vec!["N=2".to_string()];
        let preview = preview(DataModel::LP64, &[], &dir.join("thing.h"), &options)
            .expect("the header reads with the define");
        assert_eq!(preview.definitions[0].size, Some(16));
        drop(scratch);
    }

    #[test]
    fn a_definition_that_needs_an_undefined_type_is_held_back() {
        let dir = scratch_dir("missing");
        let scratch = Scratch { dir: dir.clone() };
        write(
            &dir,
            "hole.h",
            "struct outer { struct tail inner; };\nstruct whole { int x; };\n",
        );
        let preview = preview(DataModel::LP64, &[], &dir.join("hole.h"), &options(&dir))
            .expect("the header reads");
        let names: Vec<&str> = preview
            .definitions
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, ["struct whole"]);
        assert_eq!(preview.skipped.len(), 1);
        assert_eq!(preview.skipped[0].name, "struct outer");
        drop(scratch);
    }

    #[test]
    fn import_is_preview_only_until_the_selection_is_made() {
        let dir = scratch_dir("selection");
        let scratch = Scratch { dir: dir.clone() };
        write(
            &dir,
            "many.h",
            "struct point { int x, y; };\nstruct line { struct point a, b; };\n",
        );
        let previewed = preview(DataModel::LP64, &[], &dir.join("many.h"), &options(&dir))
            .expect("the header reads");
        assert_eq!(previewed.definitions.len(), 2);
        let (all, added, _) = import(
            DataModel::LP64,
            &[],
            &dir.join("many.h"),
            &options(&dir),
            None,
        )
        .expect("the import reads");
        assert_eq!(all.len(), 2);
        assert_eq!(added, ["struct point", "struct line"]);
        let (one, added, _) = import(
            DataModel::LP64,
            &[],
            &dir.join("many.h"),
            &options(&dir),
            Some(&["struct point".to_string()]),
        )
        .expect("one imports");
        assert_eq!(one.len(), 1);
        assert_eq!(added, ["struct point"]);
        // The preview, re-taken, still names both: it imported nothing.
        let again = super::preview(DataModel::LP64, &[], &dir.join("many.h"), &options(&dir))
            .expect("the header reads again");
        assert_eq!(again.definitions.len(), 2);
        drop(scratch);
    }

    #[test]
    fn a_conflicting_definition_is_refused_by_name() {
        let dir = scratch_dir("conflict");
        let scratch = Scratch { dir: dir.clone() };
        write(&dir, "point.h", "struct point { long x, y; };\n");
        let held = vec![TypeText {
            name: "struct point".to_string(),
            c: "struct point { int x, y; };".to_string(),
        }];
        let r = import(
            DataModel::LP64,
            &held,
            &dir.join("point.h"),
            &options(&dir),
            None,
        );
        let error = r.expect_err("a conflicting definition is refused");
        assert!(error.contains("struct point"), "{error}");
        // The same definition the project holds is a no-op.
        write(&dir, "same.h", "struct point { int x, y; };\n");
        let (out, added, _) = import(
            DataModel::LP64,
            &held,
            &dir.join("same.h"),
            &options(&dir),
            None,
        )
        .expect("an identical definition is held once");
        assert_eq!(out.len(), 1);
        assert!(added.is_empty());
        drop(scratch);
    }

    #[test]
    fn a_missing_header_fails() {
        let dir = scratch_dir("missing-header");
        let scratch = Scratch { dir: dir.clone() };
        let error = preview(
            DataModel::LP64,
            &[],
            &dir.join("none.h"),
            &options(&dir),
        )
        .expect_err("a missing header is refused");
        assert_eq!(error, HeaderError::Failed);
        drop(scratch);
    }

    #[test]
    fn a_whole_import_of_a_header_with_a_hole_is_refused() {
        let dir = scratch_dir("whole-hole");
        let scratch = Scratch { dir: dir.clone() };
        write(
            &dir,
            "hole.h",
            "struct outer { struct tail inner; };\nstruct whole { int x; };\n",
        );
        let error = import(DataModel::LP64, &[], &dir.join("hole.h"), &options(&dir), None)
            .expect_err("a whole import of a header with a hole is refused");
        assert!(error.contains("struct outer"), "{error}");
        // The subset the selection names imports the part that resolves.
        let (out, added, _) = import(
            DataModel::LP64,
            &[],
            &dir.join("hole.h"),
            &options(&dir),
            Some(&["struct whole".to_string()]),
        )
        .expect("the resolving subset imports");
        assert_eq!(out.len(), 1);
        assert_eq!(added, ["struct whole"]);
        // A name the header does not define is said by name.
        let error = import(
            DataModel::LP64,
            &[],
            &dir.join("hole.h"),
            &options(&dir),
            Some(&["struct nowhere".to_string()]),
        )
        .expect_err("an unknown selection is refused");
        assert!(error.contains("no type is named struct nowhere"), "{error}");
        drop(scratch);
    }
}
