//! JNI types: the JNI environment and object types, by name (#383).
//!
//! A Java native library exports entry points named `Java_<class>_<method>`
//! — the class with package dots turned to underscores, and,
//! for overloaded methods, a `__<signature>` suffix — and their signature
//! is fixed by the JNI spec: the first parameter is a `JNIEnv *`, the
//! second is the object or class the method is called on, `jobject` where
//! the name alone cannot say whether the method is static (`jclass` is
//! what a signature spells out, `L<java/lang/Class>;`), and the return is
//! the return type the Java declaration names. A JNI function whose name starts
//! `JNI_` is a function of the JNI runtime itself — the `JNIEnv` table's
//! functions spelled as plain functions — whose first parameter is likewise
//! the environment. Typing those parameters turns the register arithmetic
//! at the front of a JNI function into `JNIEnv *env, jobject obj` — a
//! Java native method returning an int reads `int Java_com_example_Native_add(JNIEnv *env, jobject obj, int a, int b)`, not five bare registers.
//!
//! A name is JNI when it is `Java_` followed by at least one underscore —
//! `Java_com_example_Native_add` — or it is a JNI runtime function the
//! spec exports as a plain function, `JNI_OnLoad`, `JNI_OnUnload`,
//! `JNI_GetCreatedJavaVMs` and `JNI_GetDefaultJavaVMInitArgs`. The
//! `Java_` check reads past the export's prefix and its class: the
//! function has a class and a method only when a dot-underscore or a
//! second underscore follows, so `Java` and `Javali` are not JNI and
//! `Java_foo` — a class with no method — is not either. A JNI-subclass
//! function may carry the overload suffix `__<signature>`: the suffix
//! spells the method's parameters in Java's internal form, `IILjava/lang/String;`
//! for a `String`, with `/` and `;` mangled to `_` as an export spells
//! them (`Java_com_example_Native_get__ILjava_lang_String_`), and the
//! parser un-mangles it. `V`, `Z`, `B`, `C`, `S`, `I`, `J`, `F` and `D`
//! are the primitives, `L<class>;` is the class (a `String` is
//! `jstring`), and `[I` and its kin are the array types. A malformed
//! or unknown signature keeps the spec's own types: `jobject` in,
//! `jobject` out.
//!
//! The object types are the JNI header's: `JNIEnv`, `jobject`, `jclass`,
//! `jstring`, `jarray`, `jobjectArray`, `jbooleanArray`, `jbyteArray`,
//! `jcharArray`, `jshortArray`, `jintArray`, `jlongArray`, `jfloatArray`
//! and `jdoubleArray`, `jmethodID`, `jfieldID`, `jclass`'s siblings
//! `jthrowable`, `jobjectRefType`, `jweak`, `jvalue` — and the primitive
//! types `jboolean` through `jdouble`, `jsize`, `jbyteArray`'s kin.
//! [`jni_types`] gives them as C; [`apply`] types a function name's
//! parameters and return from the name alone.

/// The JNI C types a Java native library uses: the environment, the object
/// types, and the primitives, in the order a header defines them. A project
/// that defines one of these names wins over this one.
pub fn jni_types() -> String {
    let mut out = String::new();
    out.push_str("typedef int jboolean;\n");
    out.push_str("typedef signed char jbyte;\n");
    out.push_str("typedef unsigned short jchar;\n");
    out.push_str("typedef short jshort;\n");
    out.push_str("typedef int jint;\n");
    out.push_str("typedef long long jlong;\n");
    out.push_str("typedef float jfloat;\n");
    out.push_str("typedef double jdouble;\n");
    out.push_str("typedef int jsize;\n");
    out.push_str("typedef struct _JNIEnv JNIEnv;\n");
    out.push_str("typedef struct _JavaVM JavaVM;\n");
    out.push_str("typedef struct _jobject *jobject;\n");
    out.push_str("typedef struct _jclass *jclass;\n");
    out.push_str("typedef struct _jstring *jstring;\n");
    out.push_str("typedef struct _jarray *jarray;\n");
    out.push_str("typedef struct _jobjectArray *jobjectArray;\n");
    out.push_str("typedef struct _jbooleanArray *jbooleanArray;\n");
    out.push_str("typedef struct _jbyteArray *jbyteArray;\n");
    out.push_str("typedef struct _jcharArray *jcharArray;\n");
    out.push_str("typedef struct _jshortArray *jshortArray;\n");
    out.push_str("typedef struct _jintArray *jintArray;\n");
    out.push_str("typedef struct _jlongArray *jlongArray;\n");
    out.push_str("typedef struct _jfloatArray *jfloatArray;\n");
    out.push_str("typedef struct _jdoubleArray *jdoubleArray;\n");
    out.push_str("typedef struct _jthrowable *jthrowable;\n");
    out.push_str("typedef struct _jmethodID *jmethodID;\n");
    out.push_str("typedef struct _jfieldID *jfieldID;\n");
    out.push_str("typedef struct _jobjectRefType *jobjectRefType;\n");
    out.push_str("typedef unsigned char _jvalue;\n");
    out.push_str("typedef struct _jvalue jvalue;\n");
    out
}

/// The return type a JNI signature letter names, when the letter names one:
/// the void, boolean, byte, char, short, int, long, float and double of
/// the Java primitives, and `jobject` for another. `V` and `Z` through
/// `D` are the primitives; any other letter is an object or malformed,
/// and is given no C type here.
fn primitive(letter: u8) -> Option<&'static str> {
    Some(match letter {
        b'V' => "void",
        b'Z' => "jboolean",
        b'B' => "jbyte",
        b'C' => "jchar",
        b'S' => "jshort",
        b'I' => "jint",
        b'J' => "jlong",
        b'F' => "jfloat",
        b'D' => "jdouble",
        _ => return None,
    })
}

/// The C type a JNI signature's class letter names, when the class is the
/// one `jni.h` types by name: a `String` is `jstring`, an `Object` is
/// `jobject`, and the array of the same is the array type. Any other
/// class has no known C type and reads `jobject`.
///
/// `class` is the class between `L` and `;`, as Java writes it — `java/lang/String`.
fn class_type(class: &str) -> &'static str {
    match class {
        "java/lang/Object" => "jobject",
        "java/lang/String" => "jstring",
        "java/lang/Class" => "jclass",
        "java/lang/Throwable" => "jthrowable",
        _ => "jobject",
    }
}

/// The array type a JNI signature's array letter names, when the
/// element is one `jni.h` arrays as: `[I` is `jintArray`, an array of
/// arrays is `jobjectArray`. `dims` is the number of `[` read, and an
/// unknown element has no type.
fn array_type(dims: u32, inner: u8) -> Option<&'static str> {
    Some(match inner {
        b'L' => "jobjectArray",
        _ if dims != 1 => "jobjectArray",
        b'Z' => "jbooleanArray",
        b'B' => "jbyteArray",
        b'C' => "jcharArray",
        b'S' => "jshortArray",
        b'I' => "jintArray",
        b'J' => "jlongArray",
        b'F' => "jfloatArray",
        b'D' => "jdoubleArray",
        _ => return None,
    })
}

/// Whether the symbol `name` is a JNI function: a `Java_` export naming a
/// class and a method, or a `JNI_` runtime function such as `JNI_OnLoad`.
pub fn is_jni(name: &str) -> bool {
    let name = name.trim();
    jni_signature(name).is_some() || jni_runtime(name).is_some()
}

/// Whether `name` is a JNI runtime function: one of the functions the
/// JNI spec exports as plain functions — `JNI_OnLoad`, `JNI_OnUnload`,
/// `JNI_GetCreatedJavaVMs`, `JNI_GetDefaultJavaVMInitArgs`. A name the
/// table does not list has no types to apply, so it is not JNI here.
fn jni_runtime(name: &str) -> Option<&str> {
    match name.trim() {
        "JNI_OnLoad" | "JNI_OnUnload" | "JNI_GetCreatedJavaVMs" | "JNI_GetDefaultJavaVMInitArgs" => {
            Some(name)
        }
        _ => None,
    }
}


/// The class, method and overload signature a `Java_` export names, when
/// it names them: `Java_com_example_Native_add` is the class
/// `com.example.Native` and the method `add`, with no overload signature;
/// `Java_com_example_Native_add__IJ` carries the signature `IJ`, the
/// overload after `__`. The class is everything up to the last underscore
/// of the part before `__` and the method the rest, so a method whose
/// own name carries an underscore reads whole — the C `str` trick is to
/// escape it `Java_…_str_1x` and not to look here for it.
fn jni_signature(name: &str) -> Option<(&str, &str, Option<&str>)> {
    let rest = name.trim().strip_prefix("Java_")?;
    let (head, overload) = match rest.split_once("__") {
        Some((head, tail)) => (head, Some(tail)),
        None => (rest, None),
    };
    // The class's last underscore, then the method: `com_example_Native_add`
    // splits at its last `_`, giving the class `com.example.Native` and
    // the method `add`.
    let (class, method) = head.rsplit_once('_')?;
    if class.is_empty() || method.is_empty() {
        return None;
    }
    // The class and the method must each begin with a letter; `Java_1x`
    // names no class and `Java_foo_1x` no method. The head's rsplit
    // keeps both halves nonempty above; a `$` in the class is Java's own.
    if !method.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    if !class.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    Some((class, method, overload))
}

/// One JNI type at the front of `letters`: a primitive letter (never
/// `V` outside return position), or a class `L<name>;`, or an array of
/// either — `[I`, `[[I`, `[[Ljava/lang/Object;` —
/// with every `[` the signature spells.
fn jni_type(letters: &mut std::iter::Peekable<std::str::Chars>) -> Option<&'static str> {
    let letter = letters.next()? as u8;
    match letter {
        b'L' => {
            // The class runs to the `;` that closes it.
            let mut class = String::new();
            loop {
                match letters.next()? {
                    ';' => break,
                    c => class.push(c),
                }
            }
            if class.is_empty() {
                return None;
            }
            Some(class_type(&class))
        }
        b'[' => {
            // An array of a class spells `[L`, of a primitive `[I`; a
            // second `[` makes it an array of arrays.
            let mut dims = 1;
            let inner = loop {
                match letters.peek()? {
                    '[' => {
                        letters.next();
                        dims += 1;
                    }
                    _ => break letters.next()? as u8,
                }
            };
            let ty = array_type(dims, inner)?;
            if inner == b'L' {
                let mut class = String::new();
                loop {
                    match letters.next()? {
                        ';' => break,
                        c => class.push(c),
                    }
                }
                if class.is_empty() {
                    return None;
                }
            }
            Some(ty)
        }
        b'V' => None,
        _ => primitive(letter),
    }
}

/// Parse a JNI overload signature — `IJ`, or `(IJ)Ljava/lang/String;` —
/// into the parameter types and the return type, as the C types the JNI
/// header defines them. The overloaded name spells the parameters alone:
/// `Java_com_example_Native_add__IJ`, `Java_com_example_Native_get__ILjava_lang_String_`
/// (un-mangled to `ILjava/lang/String;` before parsing); the return is
/// the bare form's `jobject` fallback, or `void` for a trailing `V`.
/// A malformed signature — an unknown letter, an unterminated class,
/// a `V` outside return position, trailing garbage — returns `None`,
/// and the caller keeps the fallback: `jobject` in, `jobject` out.
fn parse_signature(signature: &str) -> Option<(Vec<&'static str>, &'static str)> {
    // The full form `(params)return`: the return is the type past the
    // close, so read it after it — `V` there is the void here.
    if let Some(rest) = signature.strip_prefix('(') {
        let mut letters = rest.chars().peekable();
        let mut params = Vec::new();
        // The loop has to break on `)`; without the break the return
        // type would be walked as a parameter.
        loop {
            match letters.peek()? {
                ')' => {
                    letters.next();
                    break;
                }
                _ => params.push(jni_type(&mut letters)?),
            }
        }
        // `V` names the void return here and only here; nowhere else
        // does a parameter take it.
        let returned = if letters.peek() == Some(&'V') {
            letters.next();
            "void"
        } else {
            jni_type(&mut letters)?
        };
        // Trailing garbage after the return type is malformed.
        if letters.next().is_some() {
            return None;
        }
        // The `V` void return, checked via a peek above, never falls
        // through here: this is the tail check only.
        return Some((params, returned));
    }
    // The name's form spells the parameters alone; a trailing `V` names
    // the void return. A lone `V` is that return with no parameters.
    if signature.is_empty() {
        return None;
    }
    if signature == "V" {
        return Some((Vec::new(), "void"));
    }
    let mut letters = signature.chars().peekable();
    let mut params = Vec::new();
    while let Some(&next) = letters.peek() {
        if next == 'V' {
            letters.next();
            if letters.next().is_none() {
                return Some((params, "void"));
            }
            return None;
        }
        params.push(jni_type(&mut letters)?);
    }
    Some((params, "jobject"))
}

/// Un-mangle an overload signature as an export spells it: `_1` is a
/// literal underscore, `_2` is `;`, `_3` is `[`, and a bare `_` is `/` —
/// the per-escape mangling the spec spells out. A trailing bare `_` or
/// an unterminated class reads as the class's closing `;`, the way
/// `ILjava_lang_String_` for `ILjava/lang/String;` reads. The
/// parenthesised form has no mangling.
fn unmangle(signature: &str) -> String {
    if signature.starts_with('(') {
        return signature.to_string();
    }
    let mut out = String::new();
    let mut chars = signature.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '_' {
            match chars.peek() {
                Some('1') | Some('2') | Some('3') => {
                    let digit = chars.next().unwrap();
                    out.push(match digit {
                        '1' => '_',
                        '2' => ';',
                        _ => '[',
                    });
                    // A class on the far side of `[` opens after it.
                    // The `[` itself just pushes; the next `_` is its
                    // own separator.
                }
                Some(_) => out.push('/'),
                None => out.push(';'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The types of a JNI function's parameters and return, from its name:
/// `JNIEnv *`, then `jobject` or `jclass` for the object or class the
/// method runs on, then the signature's own when it carries one, and
/// the signature's return, `jobject` where no signature names one. A
/// runtime function has no object and no signature: its types are those
/// of its name in [`runtime_types`].
pub fn apply(name: &str) -> Option<JniTypes> {
    let name = name.trim();
    if let Some((_, _, overload)) = jni_signature(name) {
        let mut params: Vec<String> = vec!["JNIEnv *".to_string(), "jobject".to_string()];
        let mut returns = "jobject".to_string();
        if let Some(signature) = overload {
            let signature = unmangle(signature);
            if let Some((typed, returned)) = parse_signature(&signature) {
                params.extend(typed.iter().map(|s| s.to_string()));
                returns = returned.to_string();
            }
        }
        return Some(JniTypes { params, returns });
    }
    runtime_types(name).map(|(params, returns)| JniTypes {
        params: params.iter().map(|s| s.to_string()).collect(),
        returns: returns.to_string(),
    })
}

/// The types a JNI runtime function takes and returns, by name — the
/// functions the spec exports as plain functions, `JNI_OnLoad` and
/// `JNI_OnUnload` returning the VM version the library was built for,
/// the `JNI_Get*` functions returning the values they name. (`JNI_*`
/// functions that take no JNI type read no return and are not here.)
fn runtime_types(name: &str) -> Option<(Vec<&'static str>, &'static str)> {
    match name {
        "JNI_OnLoad" => Some((vec!["JavaVM *", "void *"], "jint")),
        "JNI_OnUnload" => Some((vec!["JavaVM *", "void *"], "void")),
        "JNI_GetCreatedJavaVMs" => Some((
            vec!["JavaVM **", "jsize", "jsize *"],
            "jint",
        )),
        "JNI_GetDefaultJavaVMInitArgs" => Some((vec!["void *", "void *"], "jint")),
        _ => None,
    }
}

/// A JNI function's parameters and return, as the C types.
/// One JNI function of an image: its name and the types the name gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JniFunction {
    /// The function's entry address.
    pub address: u64,
    /// The function's name, as the image spells it.
    pub name: String,
    /// The parameter types in order: the environment, the object or
    /// class, and the signature's own when it carries one.
    pub params: Vec<String>,
    /// The return type.
    pub returns: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JniTypes {
    /// The parameter types in order: the environment, the object or
    /// class, and the signature's own when the name carries one.
    pub params: Vec<String>,
    /// The return type.
    pub returns: String,
}

/// The C of the JNI types, one declaration each: what [`jni_types`] gives
/// when it is written as individual type definitions.
pub fn definitions() -> Vec<crate::ctype::TypeText> {
    jni_types()
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let name = trimmed
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(|at| trimmed[at + 1..].to_string())
                .unwrap_or_default();
            // `_jvalue` is only the union's member spelling, not a name
            // `jvalue` is spelled by; importing it pollutes the store.
            if name.starts_with('_') {
                return None;
            }
            Some(crate::ctype::TypeText {
                name,
                c: trimmed.to_string(),
            })
        })
        .collect()
}

/// The prototype `name` types to, when it is a JNI function: the same
/// [`apply`] types as a known prototype, read under `store`, with the
/// name the image spells `name`. The store already carries the JNI types
/// ([`with_jni`]); a parameter of another read stays the default `jobject`
/// the overload names no class. Returns `None` for a name that is not
/// JNI and for a type that does not read.
pub fn prototype_of(store: &crate::types::TypeStore, name: &str) -> Option<crate::propagate::Prototype> {
    let typed = apply(name)?;
    let mut params = Vec::new();
    for param in &typed.params {
        params.push(crate::ctype::parse_type(store, param).ok()?);
    }
    let ret = crate::ctype::parse_type(store, &typed.returns).ok()?;
    Some(crate::propagate::Prototype {
        name: name.trim().to_string(),
        ret,
        params,
        variadic: false,
        attrs: crate::types::TypeAttrs::default(),
        sizes: Vec::new(),
    })
}

/// The JNI type names, in the order `jni.h` defines them.
pub const JNI_TYPE_NAMES: &[&str] = &[
    "jboolean",
    "jbyte",
    "jchar",
    "jshort",
    "jint",
    "jlong",
    "jfloat",
    "jdouble",
    "jsize",
    "JNIEnv",
    "JavaVM",
    "jobject",
    "jclass",
    "jstring",
    "jarray",
    "jobjectArray",
    "jbooleanArray",
    "jbyteArray",
    "jcharArray",
    "jshortArray",
    "jintArray",
    "jlongArray",
    "jfloatArray",
    "jdoubleArray",
    "jthrowable",
    "jmethodID",
    "jfieldID",
    "jobjectRefType",
    "jvalue",
];

/// `store` with the JNI types it does not define itself: the environment
/// and object types, read from [`jni_types`] under its data model. An
/// analyst's types win over these, as with the built-in libraries.
///
/// Two declarations need care: `jvalue` is spelled as a one-byte member
/// first (`typedef unsigned char _jvalue;`) and then as the full union
/// (`typedef struct _jvalue jvalue;`), and `JNIEnv` and `JavaVM` are
/// forward-declared structs the functions only ever hold by pointer.
/// Both ride with the header; the store reads what the declarations
/// name.
pub fn with_jni(store: &crate::types::TypeStore) -> crate::types::TypeStore {
    let mut out = store.clone();
    for definition in definitions() {
        if store.key_of(&definition.name).is_some() || store.get(&definition.name).is_some() {
            continue;
        }
        let _ = crate::ctype::parse_into(&mut out, &definition.c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_names_are_jni_and_javali_is_not() {
        assert!(is_jni("Java_com_example_Native_add"));
        assert!(is_jni("Java_com/example/Native_add"));
        assert!(is_jni("JNI_OnLoad"));
        assert!(!is_jni("Java_foo"));
        assert!(!is_jni("Java"));
        assert!(!is_jni("Javali"));
        assert!(!is_jni("Java_"));
        assert!(!is_jni("JNI_"));
        assert!(!is_jni("JNI_foo"));
        assert!(!is_jni("JNI_Unknown"));
        assert!(!is_jni("main"));
    }

    #[test]
    fn a_java_name_splits_class_method_and_overload() {
        assert_eq!(
            jni_signature("Java_com_example_Native_add"),
            Some(("com_example_Native", "add", None))
        );
        assert_eq!(
            jni_signature("Java_com_example_Native_add__IJ"),
            Some(("com_example_Native", "add", Some("IJ")))
        );
        // A method whose own name carries an underscore reads whole.
        assert_eq!(
            jni_signature("Java_foo_bar_baz"),
            Some(("foo_bar", "baz", None))
        );
    }

    #[test]
    fn the_primitives_name_their_c_types() {
        assert_eq!(primitive(b'V'), Some("void"));
        assert_eq!(primitive(b'I'), Some("jint"));
        assert_eq!(primitive(b'J'), Some("jlong"));
        assert_eq!(primitive(b'Z'), Some("jboolean"));
        assert_eq!(primitive(b'X'), None);
    }

    #[test]
    fn the_classes_name_their_object_types() {
        assert_eq!(class_type("java/lang/String"), "jstring");
        assert_eq!(class_type("java/lang/Object"), "jobject");
        assert_eq!(class_type("java/util/List"), "jobject");
    }

    #[test]
    fn an_overload_signature_types_its_params_and_return() {
        assert_eq!(parse_signature("(IJ)Ljava/lang/String;"), Some((vec!["jint", "jlong"], "jstring")));
        assert_eq!(parse_signature("IJ"), Some((vec!["jint", "jlong"], "jobject")));
        assert_eq!(parse_signature("V"), Some((vec![], "void")));
        assert_eq!(parse_signature("(I)V"), Some((vec!["jint"], "void")));
        assert_eq!(parse_signature("IILjava/lang/String;"), Some((vec!["jint", "jint", "jstring"], "jobject")));
        assert_eq!(parse_signature(""), None);
        // The array forms and the double array.
        assert_eq!(parse_signature("[I"), Some((vec!["jintArray"], "jobject")));
        assert_eq!(parse_signature("[[I"), Some((vec!["jobjectArray"], "jobject")));
        // Malformed signatures keep the fallback: `V` outside return
        // position, an unknown array element, trailing garbage, and an
        // unterminated class are all None.
        assert_eq!(parse_signature("VI"), None);
        assert_eq!(parse_signature("IVI"), None);
        assert_eq!(parse_signature("[X"), None);
        assert_eq!(parse_signature("(I)Vx"), None);
        assert_eq!(parse_signature("Ljava/lang/String"), None);
        // The mangled export spelling un-mangles round-trip.
        assert_eq!(
            parse_signature(&unmangle("ILjava_lang_String_")),
            Some((vec!["jint", "jstring"], "jobject"))
        );
    }

    #[test]
    fn apply_types_a_java_method() {
        let types = apply("Java_com_example_Native_add").unwrap();
        assert_eq!(types.params, vec!["JNIEnv *", "jobject"]);
        assert_eq!(types.returns, "jobject");
        let types = apply("Java_com_example_Native_add__II").unwrap();
        assert_eq!(
            types.params,
            vec!["JNIEnv *", "jobject", "jint", "jint"]
        );
        assert_eq!(types.returns, "jobject");
        // The export's mangled spelling: `Java_com_example_Native_get__ILjava_lang_String_`.
        let types = apply("Java_com_example_Native_get__ILjava_lang_String_").unwrap();
        assert_eq!(
            types.params,
            vec!["JNIEnv *", "jobject", "jint", "jstring"]
        );
        assert_eq!(types.returns, "jobject");
        let types = apply("Java_com_example_Native_g__I").unwrap();
        assert_eq!(types.params, vec!["JNIEnv *", "jobject", "jint"]);
        assert_eq!(types.returns, "jobject");
    }

    #[test]
    fn runtime_functions_take_their_spec_types() {
        let types = apply("JNI_OnLoad").unwrap();
        assert_eq!(types.params, vec!["JavaVM *", "void *"]);
        assert_eq!(types.returns, "jint");
        let types = apply("JNI_OnUnload").unwrap();
        assert_eq!(types.returns, "void");
        assert!(apply("JNI_Unknown").is_none());
        assert!(apply("Java_").is_none());
    }

    #[test]
    fn the_types_header_names_the_jni_objects() {
        let header = jni_types();
        assert!(header.contains("JNIEnv"));
        assert!(header.contains("jobject"));
        assert!(header.contains("jclass"));
        assert!(header.contains("jstring"));
        assert!(header.contains("jarray"));
        assert!(header.contains("jmethodID"));
        assert!(header.contains("jbyteArray"));
    }
}
