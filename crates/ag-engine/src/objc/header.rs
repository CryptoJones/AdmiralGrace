//! An Objective-C header written from the metadata: the quickest overview
//! of an Objective-C binary.
//!
//! Each protocol, class and category the image describes is declared as a
//! compiler would read it back — `@protocol`, `@interface Class :
//! Superclass <Protocols>`, `@interface Class (Category)` — with its
//! properties, instance variables and methods. The types come from the
//! runtime's type encodings (`i20@0:8i16` for `- (int)greet:(int)times`),
//! decoded by [`decode_type`] and [`decode_method`]; where an encoding is
//! missing or unreadable the type is `id`, and the header still parses.
//! Every class and protocol is forward-declared first, those of other images
//! — a framework's — marked as such; then the structs the encodings spell
//! out are defined — an instance variable's encoding names the fields,
//! `{Point="x"i"y"i}` — each after the structs it holds by value; then the
//! declarations, ordered so that what one needs comes first: a protocol
//! before the protocol that adopts it, a superclass before its subclass, a
//! class before its categories. A category on a class of another image is
//! written as a comment, since there is no class to extend. The header
//! compiles against the runtime's `objc/objc.h` alone where the image is
//! whole; a superclass or a type of another image needs that image's
//! headers too.
//!
//! A property's accessors are its own declaration, so a method the property
//! already declares — its getter, its setter — is not listed twice.

use std::collections::{BTreeMap, BTreeSet};

use super::{ObjcCategory, ObjcClass, ObjcMetadata, ObjcMethod, ObjcProperty, ObjcProtocol};

/// Write the header of `objc`.
pub fn write(objc: &ObjcMetadata) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "// Objective-C declarations recovered from the image: {} {}, {} {}, {} {}.\n",
        objc.classes.len(),
        plural(objc.classes.len(), "class", "classes"),
        objc.categories.len(),
        plural(objc.categories.len(), "category", "categories"),
        objc.protocols.len(),
        plural(objc.protocols.len(), "protocol", "protocols"),
    ));
    out.push_str("// Types are read from the runtime's encodings; where an encoding is missing, a type is `id`.\n");
    out.push_str("#import <objc/objc.h>\n");

    // What the image refers to but does not hold.
    let held_classes: BTreeSet<&str> = objc.classes.iter().map(|c| c.name.as_str()).collect();
    let held_protocols: BTreeSet<&str> = objc.protocols.iter().map(|p| p.name.as_str()).collect();
    let mut classes_referred = BTreeSet::new();
    let mut protocols_referred = BTreeSet::new();
    fn note(encoding: &str, classes: &mut BTreeSet<String>, protocols: &mut BTreeSet<String>) {
        let (named_classes, named_protocols) = names_in(encoding);
        classes.extend(named_classes);
        protocols.extend(named_protocols);
    }
    for class in &objc.classes {
        if let Some(superclass) = &class.superclass {
            classes_referred.insert(superclass.clone());
        }
        protocols_referred.extend(class.protocols.iter().cloned());
        for method in class.instance_methods.iter().chain(&class.class_methods) {
            if let Some(types) = &method.types {
                note(types, &mut classes_referred, &mut protocols_referred);
            }
        }
        for ivar in &class.ivars {
            if let Some(types) = &ivar.types {
                note(types, &mut classes_referred, &mut protocols_referred);
            }
        }
        for property in &class.properties {
            if let Some(attributes) = &property.attributes {
                note(attributes, &mut classes_referred, &mut protocols_referred);
            }
        }
    }
    for category in &objc.categories {
        if let Some(class) = &category.class {
            classes_referred.insert(class.clone());
        }
        protocols_referred.extend(category.protocols.iter().cloned());
        for method in category
            .instance_methods
            .iter()
            .chain(&category.class_methods)
        {
            if let Some(types) = &method.types {
                note(types, &mut classes_referred, &mut protocols_referred);
            }
        }
        for property in &category.properties {
            if let Some(attributes) = &property.attributes {
                note(attributes, &mut classes_referred, &mut protocols_referred);
            }
        }
    }
    for protocol in &objc.protocols {
        protocols_referred.extend(protocol.protocols.iter().cloned());
        for method in protocol
            .instance_methods
            .iter()
            .chain(&protocol.class_methods)
            .chain(&protocol.optional_instance_methods)
            .chain(&protocol.optional_class_methods)
        {
            if let Some(types) = &method.types {
                note(types, &mut classes_referred, &mut protocols_referred);
            }
        }
        for property in &protocol.properties {
            if let Some(attributes) = &property.attributes {
                note(attributes, &mut classes_referred, &mut protocols_referred);
            }
        }
    }
    // Every class and protocol, declared before anything refers to it: a
    // protocol's method may take a class declared later, a class may hold a
    // pointer to its own subclass.
    let external_classes: Vec<&str> = classes_referred
        .iter()
        .map(String::as_str)
        .filter(|name| !held_classes.contains(name))
        .collect();
    let external_protocols: Vec<&str> = protocols_referred
        .iter()
        .map(String::as_str)
        .filter(|name| !held_protocols.contains(name))
        .collect();
    if !held_classes.is_empty() || !held_protocols.is_empty() {
        out.push('\n');
        if !held_classes.is_empty() {
            let names: Vec<&str> = held_classes.iter().copied().collect();
            out.push_str(&format!("@class {};\n", names.join(", ")));
        }
        if !held_protocols.is_empty() {
            let names: Vec<&str> = held_protocols.iter().copied().collect();
            out.push_str(&format!("@protocol {};\n", names.join(", ")));
        }
    }
    if !external_classes.is_empty() || !external_protocols.is_empty() {
        out.push('\n');
        out.push_str("// Of other images, bound at load; their own headers declare them.\n");
        if !external_classes.is_empty() {
            out.push_str(&format!("@class {};\n", external_classes.join(", ")));
        }
        if !external_protocols.is_empty() {
            out.push_str(&format!("@protocol {};\n", external_protocols.join(", ")));
        }
    }

    let structs = struct_definitions(objc);
    if !structs.is_empty() {
        out.push('\n');
        out.push_str(&structs);
    }

    for protocol in ordered_protocols(objc) {
        out.push('\n');
        write_protocol(&mut out, protocol);
    }
    // The categories, by the class each extends, in the image's order.
    let mut categories_of: BTreeMap<&str, Vec<&ObjcCategory>> = BTreeMap::new();
    let mut unplaced: Vec<&ObjcCategory> = Vec::new();
    for category in &objc.categories {
        match category.class.as_deref() {
            Some(class) if held_classes.contains(class) => {
                categories_of.entry(class).or_default().push(category)
            }
            _ => unplaced.push(category),
        }
    }
    for class in ordered_classes(objc) {
        out.push('\n');
        write_class(&mut out, class);
        for category in categories_of
            .remove(class.name.as_str())
            .unwrap_or_default()
        {
            out.push('\n');
            write_category(&mut out, category);
        }
    }
    for category in unplaced {
        out.push('\n');
        write_category(&mut out, category);
    }
    out
}

/// The structs and unions the encodings spell out, defined: `struct Point {
/// int x; int y; };`. An instance variable's encoding names the fields; a
/// method's does not, and a struct seen only there gets its fields numbered.
/// A struct named without a body (`{Point}` or `{Point=}`) is only declared.
fn struct_definitions(objc: &ObjcMetadata) -> String {
    let mut found: std::collections::BTreeMap<String, (String, Option<String>)> =
        std::collections::BTreeMap::new();
    let mut see = |encoding: &str| {
        for (keyword, name, body) in aggregates_in(encoding) {
            let entry = found
                .entry(name)
                .or_insert_with(|| (keyword.to_string(), None));
            // A body with field names beats one without; any beats none.
            let better = match (&entry.1, &body) {
                (None, Some(_)) => true,
                (Some(have), Some(new)) => !have.contains('"') && new.contains('"'),
                _ => false,
            };
            if better {
                entry.1 = body;
            }
        }
    };
    let mut encodings: Vec<&str> = Vec::new();
    for class in &objc.classes {
        encodings.extend(class.ivars.iter().filter_map(|ivar| ivar.types.as_deref()));
        encodings.extend(
            class
                .properties
                .iter()
                .filter_map(|p| p.attributes.as_deref()),
        );
        encodings.extend(
            class
                .instance_methods
                .iter()
                .chain(&class.class_methods)
                .filter_map(|m| m.types.as_deref()),
        );
    }
    for category in &objc.categories {
        encodings.extend(
            category
                .properties
                .iter()
                .filter_map(|p| p.attributes.as_deref()),
        );
        encodings.extend(
            category
                .instance_methods
                .iter()
                .chain(&category.class_methods)
                .filter_map(|m| m.types.as_deref()),
        );
    }
    for protocol in &objc.protocols {
        encodings.extend(
            protocol
                .properties
                .iter()
                .filter_map(|p| p.attributes.as_deref()),
        );
        encodings.extend(
            protocol
                .instance_methods
                .iter()
                .chain(&protocol.class_methods)
                .chain(&protocol.optional_instance_methods)
                .chain(&protocol.optional_class_methods)
                .filter_map(|m| m.types.as_deref()),
        );
    }
    for encoding in encodings {
        see(encoding);
    }
    // Each struct after the structs it holds by value, so a field of one
    // never names an incomplete type; a pointer to one needs no definition.
    let bodies: BTreeMap<&str, (&str, Option<Vec<Field>>)> = found
        .iter()
        .map(|(name, (keyword, body))| {
            let fields = body
                .as_deref()
                .filter(|body| !body.is_empty())
                .map(|body| fields_of(body, 0));
            (name.as_str(), (keyword.as_str(), fields))
        })
        .collect();
    let held_by_value = |fields: &[Field]| -> Vec<String> {
        fields
            .iter()
            .filter(|(base, _, _)| !base.ends_with('*'))
            .filter_map(|(base, _, _)| {
                base.strip_prefix("struct ")
                    .or_else(|| base.strip_prefix("union "))
                    .map(str::to_string)
            })
            .collect()
    };
    let mut out = String::new();
    let mut written: BTreeSet<&str> = BTreeSet::new();
    for name in bodies.keys() {
        // Each entry: the struct, and whether what it holds was pushed.
        let mut stack: Vec<(&str, bool)> = vec![(name, false)];
        while let Some((name, expanded)) = stack.pop() {
            if written.contains(name) {
                continue;
            }
            let Some((keyword, fields)) = bodies.get(name) else {
                continue;
            };
            if !expanded {
                stack.push((name, true));
                if let Some(fields) = fields {
                    for held in held_by_value(fields) {
                        if let Some((held, _)) = bodies.get_key_value(held.as_str()) {
                            if !written.contains(held) && !stack.iter().any(|(on, _)| *on == *held)
                            {
                                stack.push((held, false));
                            }
                        }
                    }
                }
                continue;
            }
            written.insert(name);
            match fields {
                None => out.push_str(&format!("{keyword} {name};\n")),
                Some(fields) => {
                    out.push_str(&format!("{keyword} {name} {{\n"));
                    for (base, suffix, field) in fields {
                        out.push_str(&format!("    {}{field}{suffix};\n", declarator(base)));
                    }
                    out.push_str("};\n");
                }
            }
        }
    }
    out
}

/// Every named struct (`{Name=...}`) and union (`(Name=...)`) an encoding
/// holds, at any depth: the keyword, the name and the body after `=`, when
/// there is one.
fn aggregates_in(encoding: &str) -> Vec<(&'static str, String, Option<String>)> {
    let mut found = Vec::new();
    let mut quoted = false;
    for (at, c) in encoding.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '{' | '(' if !quoted => {
                let keyword = if c == '{' { "struct" } else { "union" };
                let mut parser = Parser::new(&encoding[at + 1..]);
                let inner = parser.nested(c, if c == '{' { '}' } else { ')' });
                let (name, body) = match inner.find('=') {
                    Some(eq) => (&inner[..eq], Some(inner[eq + 1..].to_string())),
                    None => (inner.as_str(), None),
                };
                if !name.is_empty()
                    && name != "?"
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    found.push((keyword, name.to_string(), body));
                }
            }
            _ => {}
        }
    }
    found
}

fn plural<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 {
        one
    } else {
        many
    }
}

/// The protocols, each after the protocols it adopts; otherwise in the
/// image's order. A walk with its own stack, so a crafted chain of
/// thousands cannot overflow the thread's.
fn ordered_protocols(objc: &ObjcMetadata) -> Vec<&ObjcProtocol> {
    let by_name: BTreeMap<&str, &ObjcProtocol> = objc
        .protocols
        .iter()
        .map(|protocol| (protocol.name.as_str(), protocol))
        .collect();
    let mut ordered = Vec::new();
    let mut placed = BTreeSet::new();
    for protocol in &objc.protocols {
        // Each entry: the protocol, and whether its adoptions were pushed.
        let mut stack = vec![(protocol, false)];
        while let Some((protocol, expanded)) = stack.pop() {
            if placed.contains(protocol.name.as_str()) {
                continue;
            }
            if expanded {
                placed.insert(protocol.name.as_str());
                ordered.push(protocol);
                continue;
            }
            stack.push((protocol, true));
            for adopted in protocol.protocols.iter().rev() {
                if let Some(adopted) = by_name.get(adopted.as_str()) {
                    if !placed.contains(adopted.name.as_str())
                        && !stack.iter().any(|(on, _)| std::ptr::eq(*on, *adopted))
                    {
                        stack.push((adopted, false));
                    }
                }
            }
        }
    }
    ordered
}

/// The classes, each after its superclass; otherwise in the image's order.
/// The superclass chain is followed by a loop, so a crafted chain of
/// thousands cannot overflow the thread's stack.
fn ordered_classes(objc: &ObjcMetadata) -> Vec<&ObjcClass> {
    let by_name: BTreeMap<&str, &ObjcClass> = objc
        .classes
        .iter()
        .map(|class| (class.name.as_str(), class))
        .collect();
    let mut ordered = Vec::new();
    let mut placed = BTreeSet::new();
    for class in &objc.classes {
        // The chain up from this class to the first one already placed, or
        // to a root or a class of another image; then placed top down.
        let mut chain = Vec::new();
        let mut current = class;
        while placed.insert(current.name.as_str()) {
            chain.push(current);
            match current
                .superclass
                .as_deref()
                .and_then(|superclass| by_name.get(superclass))
            {
                Some(superclass) => current = superclass,
                None => break,
            }
        }
        ordered.extend(chain.into_iter().rev());
    }
    ordered
}

fn adopts(protocols: &[String]) -> String {
    if protocols.is_empty() {
        String::new()
    } else {
        format!(" <{}>", protocols.join(", "))
    }
}

fn write_protocol(out: &mut String, protocol: &ObjcProtocol) {
    out.push_str(&format!(
        "@protocol {}{}\n",
        protocol.name,
        adopts(&protocol.protocols)
    ));
    let accessors = accessors_of(&protocol.properties);
    for property in &protocol.properties {
        out.push_str(&property_line(property));
    }
    for method in &protocol.class_methods {
        out.push_str(&method_line('+', method));
    }
    for method in &protocol.instance_methods {
        if !accessors.contains(method.selector.as_str()) {
            out.push_str(&method_line('-', method));
        }
    }
    if !protocol.optional_class_methods.is_empty() || !protocol.optional_instance_methods.is_empty()
    {
        out.push_str("@optional\n");
        for method in &protocol.optional_class_methods {
            out.push_str(&method_line('+', method));
        }
        for method in &protocol.optional_instance_methods {
            if !accessors.contains(method.selector.as_str()) {
                out.push_str(&method_line('-', method));
            }
        }
    }
    out.push_str("@end\n");
}

fn write_class(out: &mut String, class: &ObjcClass) {
    let superclass = class
        .superclass
        .as_deref()
        .map(|superclass| format!(" : {superclass}"))
        .unwrap_or_default();
    if class.superclass.is_none() {
        out.push_str("__attribute__((objc_root_class))\n");
    }
    out.push_str(&format!(
        "@interface {}{superclass}{}",
        class.name,
        adopts(&class.protocols)
    ));
    if class.ivars.is_empty() {
        out.push('\n');
    } else {
        out.push_str(" {\n");
        for ivar in &class.ivars {
            let (base, suffix) = match &ivar.types {
                Some(types) => decode_type(types),
                None => ("id".to_string(), String::new()),
            };
            out.push_str(&format!(
                "    {}{}{suffix};\n",
                declarator(&base),
                ivar.name
            ));
        }
        out.push_str("}\n");
    }
    write_members(
        out,
        &class.properties,
        &class.class_methods,
        &class.instance_methods,
    );
    out.push_str("@end\n");
}

fn write_category(out: &mut String, category: &ObjcCategory) {
    let mut text = String::new();
    text.push_str(&format!(
        "@interface {} ({}){}\n",
        category.class.as_deref().unwrap_or("?"),
        category.name,
        adopts(&category.protocols)
    ));
    write_members(
        &mut text,
        &category.properties,
        &category.class_methods,
        &category.instance_methods,
    );
    text.push_str("@end\n");
    if category.class.is_some() {
        out.push_str(&text);
    } else {
        // The class is another image's, bound at load: there is nothing
        // here to extend, so the category is kept as a comment.
        out.push_str("// A category on a class of another image, bound at load.\n");
        for line in text.lines() {
            out.push_str(&format!("// {line}\n"));
        }
    }
}

fn write_members(
    out: &mut String,
    properties: &[ObjcProperty],
    class_methods: &[ObjcMethod],
    instance_methods: &[ObjcMethod],
) {
    let accessors = accessors_of(properties);
    for property in properties {
        out.push_str(&property_line(property));
    }
    for method in class_methods {
        out.push_str(&method_line('+', method));
    }
    for method in instance_methods {
        if !accessors.contains(method.selector.as_str()) {
            out.push_str(&method_line('-', method));
        }
    }
}

/// The selectors the properties declare already: each getter and setter.
fn accessors_of(properties: &[ObjcProperty]) -> BTreeSet<String> {
    let mut accessors = BTreeSet::new();
    for property in properties {
        let attributes = decode_property(property);
        accessors.insert(attributes.getter.clone());
        if let Some(setter) = attributes.setter {
            accessors.insert(setter);
        }
    }
    accessors
}

/// `@property (nonatomic, readonly) struct Point origin;`
fn property_line(property: &ObjcProperty) -> String {
    let decoded = decode_property(property);
    let qualifiers = if decoded.qualifiers.is_empty() {
        String::new()
    } else {
        format!(" ({})", decoded.qualifiers.join(", "))
    };
    format!(
        "@property{qualifiers} {}{}{};\n",
        declarator(&decoded.base),
        property.name,
        decoded.suffix
    )
}

/// `- (int)greet:(int)arg1;`
fn method_line(kind: char, method: &ObjcMethod) -> String {
    let (ret, args) = method
        .types
        .as_deref()
        .map(decode_method)
        .unwrap_or_else(|| ("id".to_string(), Vec::new()));
    let pieces: Vec<&str> = method.selector.split(':').collect();
    let mut line = format!("{kind} ({ret})");
    if pieces.len() == 1 {
        line.push_str(pieces[0]);
    } else {
        // `a:b:` splits as ["a", "b", ""]; each piece but the last takes
        // an argument. A piece past the encoded arguments is typed `id`.
        let named = &pieces[..pieces.len() - 1];
        for (index, piece) in named.iter().enumerate() {
            let arg = args.get(index).cloned().unwrap_or_else(|| "id".to_string());
            if index > 0 {
                line.push(' ');
            }
            line.push_str(&format!("{piece}:({arg})arg{}", index + 1));
        }
        // A malformed selector ending without a colon keeps its last piece.
        if let Some(last) = pieces.last().filter(|last| !last.is_empty()) {
            line.push_str(&format!(" {last}"));
        }
    }
    line.push_str(";\n");
    line
}

/// A type as it stands before a name: `int `, `Base *`, `struct Point `.
fn declarator(base: &str) -> String {
    if base.ends_with('*') {
        base.to_string()
    } else {
        format!("{base} ")
    }
}

/// A property's attribute string, decoded.
struct Property {
    /// The qualifiers, in the order a header lists them.
    qualifiers: Vec<String>,
    /// The type before the name, and what follows the name (an array's bound).
    base: String,
    suffix: String,
    /// The accessors the property declares.
    getter: String,
    setter: Option<String>,
}

/// Decode `Ti,N,V_count`: the type encoding, then the attributes — `R`
/// readonly, `C` copy, `&` retain, `W` weak, `N` nonatomic, `D` dynamic,
/// `G<getter>`, `S<setter>` — then `V<ivar>`.
fn decode_property(property: &ObjcProperty) -> Property {
    let mut base = "id".to_string();
    let mut suffix = String::new();
    let mut readonly = false;
    let mut ownership: Option<&str> = None;
    let mut nonatomic = false;
    let mut getter = property.name.clone();
    let mut setter_given = None;
    if let Some(attributes) = &property.attributes {
        for attribute in split_attributes(attributes) {
            let mut chars = attribute.chars();
            match chars.next() {
                Some('T') => (base, suffix) = decode_type(chars.as_str()),
                Some('R') => readonly = true,
                Some('C') => ownership = Some("copy"),
                Some('&') => ownership = Some("retain"),
                Some('W') => ownership = Some("weak"),
                Some('N') => nonatomic = true,
                Some('G') => getter = chars.as_str().to_string(),
                Some('S') => setter_given = Some(chars.as_str().to_string()),
                _ => {}
            }
        }
    }
    let mut qualifiers = Vec::new();
    if nonatomic {
        qualifiers.push("nonatomic".to_string());
    }
    if readonly {
        qualifiers.push("readonly".to_string());
    }
    if let Some(ownership) = ownership {
        qualifiers.push(ownership.to_string());
    } else if base.ends_with('*')
        && (base.starts_with(|c: char| c.is_ascii_uppercase()) || base == "id *")
    {
        // An object held without a stated ownership is assigned.
        qualifiers.push("assign".to_string());
    }
    if getter != property.name {
        qualifiers.push(format!("getter={getter}"));
    }
    let setter = if readonly {
        None
    } else {
        match setter_given {
            Some(setter) => {
                qualifiers.push(format!("setter={setter}"));
                Some(setter)
            }
            None => {
                let mut chars = property.name.chars();
                let first = chars
                    .next()
                    .map(|c| c.to_ascii_uppercase())
                    .unwrap_or_default();
                Some(format!("set{first}{}:", chars.as_str()))
            }
        }
    };
    Property {
        qualifiers,
        base,
        suffix,
        getter,
        setter,
    }
}

/// The attributes of a property string, split at the commas that are not
/// inside a type encoding's quotes, braces or brackets.
fn split_attributes(attributes: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quoted = false;
    let mut start = 0;
    for (index, c) in attributes.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '{' | '(' | '[' | '<' if !quoted => depth += 1,
            '}' | ')' | ']' | '>' if !quoted => depth -= 1,
            ',' if !quoted && depth <= 0 => {
                parts.push(&attributes[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&attributes[start..]);
    parts
}

/// Decode a method's type encoding — the return type, then every argument
/// type, each with its frame offset — into the return type and the types
/// of the arguments after the implicit `self` and `_cmd`.
pub fn decode_method(encoding: &str) -> (String, Vec<String>) {
    let mut parser = Parser::new(encoding);
    let ret = parser.ty().map(joined).unwrap_or_else(|| "id".to_string());
    parser.digits();
    let mut args = Vec::new();
    while !parser.done() {
        let Some(ty) = parser.ty() else { break };
        parser.digits();
        args.push(joined(ty));
    }
    // `self` and `_cmd` come first in every method.
    let args = args.into_iter().skip(2).collect();
    (ret, args)
}

/// Decode one type encoding into the type before a name and what follows
/// it: `i` → `int`; `@"Base"` → `Base *`; `[4i]` → `int`, `[4]`;
/// `{Point=ii}` → `struct Point`; `^v` → `void *`. An encoding that cannot
/// be read is `id`.
pub fn decode_type(encoding: &str) -> (String, String) {
    Parser::new(encoding)
        .ty()
        .unwrap_or_else(|| ("id".to_string(), String::new()))
}

fn joined((base, suffix): (String, String)) -> String {
    if suffix.is_empty() {
        base
    } else {
        format!("{base}{suffix}")
    }
}

/// The classes (`@"Name"`) and protocols (`@"<Name>"`, `@"Name<P>"`) an
/// encoding names.
fn names_in(encoding: &str) -> (Vec<String>, Vec<String>) {
    let mut classes = Vec::new();
    let mut protocols = Vec::new();
    let mut rest = encoding;
    while let Some(at) = rest.find("@\"") {
        let after = &rest[at + 2..];
        let Some(end) = after.find('"') else { break };
        let name = &after[..end];
        let (class, protos) = class_and_protocols(name);
        if !class.is_empty() && class.chars().all(|c| c.is_alphanumeric() || c == '_') {
            classes.push(class.to_string());
        }
        protocols.extend(protos.into_iter().map(str::to_string));
        rest = &after[end + 1..];
    }
    (classes, protocols)
}

/// The class and the protocols an object encoding's name spells: `Name`,
/// `<A><B>` (`id` under two protocols), `Name<A><B>`.
fn class_and_protocols(name: &str) -> (&str, Vec<&str>) {
    let (class, protocols) = match name.find('<') {
        Some(open) => (&name[..open], &name[open..]),
        None => (name, ""),
    };
    let protocols = protocols
        .split(['<', '>'])
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty())
        .collect();
    (class, protocols)
}

/// One field of an aggregate: its type before the name, what follows the
/// name, and the name — the encoding's (`"x"`) or a numbered one.
type Field = (String, String, String);

/// The fields of an aggregate's body.
fn fields_of(body: &str, depth: usize) -> Vec<Field> {
    let mut parser = Parser::new(body);
    parser.depth = depth + 1;
    let mut fields = Vec::new();
    if parser.depth > DEEPEST_TYPE {
        return fields;
    }
    let mut index = 0;
    while !parser.done() {
        let field = parser.quoted_name();
        let Some((base, suffix)) = parser.ty() else {
            break;
        };
        fields.push((
            base,
            suffix,
            field.unwrap_or_else(|| format!("field{index}")),
        ));
        index += 1;
    }
    fields
}

/// A reader over one type encoding.
struct Parser<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    /// How many pointers and arrays are open: a bound on the recursion a
    /// crafted `^^^^…` would cause.
    depth: usize,
}

/// No real type is nested deeper.
const DEEPEST_TYPE: usize = 64;

impl<'a> Parser<'a> {
    fn new(encoding: &'a str) -> Self {
        Parser {
            chars: encoding.chars().peekable(),
            depth: 0,
        }
    }

    /// One type under a pointer or an array: the recursion, bounded.
    fn inner(&mut self) -> Option<(String, String)> {
        if self.depth >= DEEPEST_TYPE {
            return None;
        }
        self.depth += 1;
        let inner = self.ty();
        self.depth -= 1;
        inner
    }

    fn done(&mut self) -> bool {
        self.chars.peek().is_none()
    }

    /// Skip a frame offset or a bound.
    fn digits(&mut self) -> Option<usize> {
        let mut text = String::new();
        while let Some(c) = self.chars.peek().filter(|c| c.is_ascii_digit()) {
            text.push(*c);
            self.chars.next();
        }
        text.parse().ok()
    }

    /// A field's name, `"x"`, when the next thing is one.
    fn quoted_name(&mut self) -> Option<String> {
        if self.chars.peek() != Some(&'"') {
            return None;
        }
        self.chars.next();
        Some(self.until('"'))
    }

    /// Read up to and past `close`, keeping what came before it.
    fn until(&mut self, close: char) -> String {
        let mut text = String::new();
        for c in self.chars.by_ref() {
            if c == close {
                break;
            }
            text.push(c);
        }
        text
    }

    /// One type: the base and the suffix an array puts after the name.
    fn ty(&mut self) -> Option<(String, String)> {
        let mut qualifiers = Vec::new();
        // The method qualifiers: `r` const, `n` in, `N` inout, `o` out,
        // `O` bycopy, `R` byref, `V` oneway, `A` atomic. Only `const`
        // and `_Atomic` are C.
        while let Some(c) = self.chars.peek().copied() {
            match c {
                'r' => qualifiers.push("const"),
                'A' => qualifiers.push("_Atomic"),
                'n' | 'N' | 'o' | 'O' | 'R' | 'V' | '!' => {}
                _ => break,
            }
            self.chars.next();
        }
        let c = self.chars.next()?;
        let (base, suffix) = match c {
            'c' => ("char".to_string(), String::new()),
            'i' => ("int".to_string(), String::new()),
            's' => ("short".to_string(), String::new()),
            // `l` and `L` are 32 bits in the runtime's encodings, whatever
            // the platform's `long`.
            'l' => ("int".to_string(), String::new()),
            'q' => ("long long".to_string(), String::new()),
            'C' => ("unsigned char".to_string(), String::new()),
            'I' => ("unsigned int".to_string(), String::new()),
            'S' => ("unsigned short".to_string(), String::new()),
            'L' => ("unsigned int".to_string(), String::new()),
            'Q' => ("unsigned long long".to_string(), String::new()),
            't' => ("__int128".to_string(), String::new()),
            'T' => ("unsigned __int128".to_string(), String::new()),
            'f' => ("float".to_string(), String::new()),
            'd' => ("double".to_string(), String::new()),
            'D' => ("long double".to_string(), String::new()),
            'B' => ("BOOL".to_string(), String::new()),
            'v' => ("void".to_string(), String::new()),
            '*' => ("char *".to_string(), String::new()),
            '#' => ("Class".to_string(), String::new()),
            ':' => ("SEL".to_string(), String::new()),
            '?' => ("void *".to_string(), String::new()),
            '%' => ("NXAtom".to_string(), String::new()),
            'j' => {
                let (inner, suffix) = self.inner()?;
                (format!("_Complex {inner}"), suffix)
            }
            'b' => {
                let bits = self.digits().unwrap_or(0);
                ("unsigned int".to_string(), format!(" : {bits}"))
            }
            '@' => match self.chars.peek() {
                Some('?') => {
                    self.chars.next();
                    ("id /* block */".to_string(), String::new())
                }
                Some('"') => {
                    self.chars.next();
                    let name = self.until('"');
                    // `@"Name"`, `@"<A><B>"` (`id<A, B>`), `@"Name<A><B>"`.
                    let (class, protocols) = class_and_protocols(&name);
                    let protocols = if protocols.is_empty() {
                        String::new()
                    } else {
                        format!("<{}>", protocols.join(", "))
                    };
                    if class.is_empty() {
                        (format!("id{protocols}"), String::new())
                    } else {
                        (format!("{class}{protocols} *"), String::new())
                    }
                }
                _ => ("id".to_string(), String::new()),
            },
            '^' => {
                if self.chars.peek() == Some(&'?') {
                    // `^?`: a pointer to a function, whose signature the
                    // encoding does not carry.
                    self.chars.next();
                    ("void *".to_string(), String::new())
                } else {
                    let (inner, suffix) = self.inner()?;
                    (format!("{}*", declarator(&inner)), suffix)
                }
            }
            '[' => {
                let count = self.digits().unwrap_or(0);
                let (inner, suffix) = self.inner()?;
                let _ = self.until(']');
                (inner, format!("[{count}]{suffix}"))
            }
            '{' | '(' => {
                let close = if c == '{' { '}' } else { ')' };
                let keyword = if c == '{' { "struct" } else { "union" };
                let body = self.nested(c, close);
                let (name, fields) = match body.find('=') {
                    Some(eq) => (&body[..eq], Some(&body[eq + 1..])),
                    None => (body.as_str(), None),
                };
                if name.is_empty() || name == "?" {
                    // Anonymous: the fields are spelled where the type is.
                    let fields = fields
                        .filter(|fields| !fields.is_empty())
                        .map(|fields| {
                            fields_of(fields, self.depth)
                                .into_iter()
                                .map(|(base, suffix, field)| {
                                    format!("{}{field}{suffix}; ", declarator(&base))
                                })
                                .collect::<String>()
                        })
                        .unwrap_or_default();
                    (format!("{keyword} {{ {fields}}}"), String::new())
                } else {
                    (format!("{keyword} {name}"), String::new())
                }
            }
            _ => return None,
        };
        let base = if qualifiers.is_empty() {
            base
        } else {
            format!("{} {base}", qualifiers.join(" "))
        };
        Some((base, suffix))
    }

    /// The text inside a bracketed encoding whose opening bracket was just
    /// read, past the matching close, nesting kept.
    fn nested(&mut self, open: char, close: char) -> String {
        let mut text = String::new();
        let mut depth = 1;
        let mut quoted = false;
        for c in self.chars.by_ref() {
            if c == '"' {
                quoted = !quoted;
            } else if !quoted {
                if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            text.push(c);
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(encoding: &str) -> String {
        joined(decode_type(encoding))
    }

    #[test]
    fn primitive_object_and_pointer_encodings_decode() {
        assert_eq!(ty("i"), "int");
        assert_eq!(ty("Q"), "unsigned long long");
        assert_eq!(ty("v"), "void");
        assert_eq!(ty("*"), "char *");
        assert_eq!(ty("r*"), "const char *");
        assert_eq!(ty("@"), "id");
        assert_eq!(ty("@\"Base\""), "Base *");
        assert_eq!(ty("@\"<Greeting>\""), "id<Greeting>");
        assert_eq!(ty("@?"), "id /* block */");
        assert_eq!(ty("#"), "Class");
        assert_eq!(ty(":"), "SEL");
        assert_eq!(ty("^i"), "int *");
        assert_eq!(ty("^^c"), "char **");
        assert_eq!(ty("^{Point=ii}"), "struct Point *");
        assert_eq!(ty("{Point=ii}"), "struct Point");
        assert_eq!(ty("{?=ii}"), "struct { int field0; int field1; }");
        assert_eq!(ty("{?=\"x\"i\"y\"d}"), "struct { int x; double y; }");
        assert_eq!(ty("(U=ii)"), "union U");
        assert_eq!(ty("[4i]"), "int[4]");
        assert_eq!(ty("b3"), "unsigned int : 3");
        assert_eq!(ty(""), "id");
        assert_eq!(ty("~"), "id");
        // `l` and `L` are 32 bits in an encoding, whatever the platform.
        assert_eq!(ty("l"), "int");
        assert_eq!(ty("L"), "unsigned int");
        // A pointer to a function, a pointer to a pointer, and the two apart.
        assert_eq!(ty("^?"), "void *");
        assert_eq!(ty("^^v"), "void **");
        assert_eq!(ty("^^?"), "void **");
        // Several protocols, on `id` and on a class.
        assert_eq!(ty("@\"<A><B>\""), "id<A, B>");
        assert_eq!(ty("@\"NSObject<A><B>\""), "NSObject<A, B> *");
        // A crafted depth is refused, not recursed into.
        let deep = format!("{}i", "^".repeat(10_000));
        assert_eq!(ty(&deep), "id");
        let deep = format!("{}i{}", "[2".repeat(10_000), "]".repeat(10_000));
        assert_eq!(ty(&deep), "id");
    }

    #[test]
    fn the_names_an_encoding_refers_to_are_found() {
        let (classes, protocols) = names_in("v32@0:8@\"NSObject<A><B>\"16@\"<C>\"24@\"Base\"32");
        assert_eq!(classes, ["NSObject", "Base"]);
        assert_eq!(protocols, ["A", "B", "C"]);
    }

    #[test]
    fn a_method_encoding_drops_self_and_cmd() {
        let (ret, args) = decode_method("i20@0:8i16");
        assert_eq!(ret, "int");
        assert_eq!(args, ["int"]);
        let (ret, args) = decode_method("Q32@0:8r*16Q24");
        assert_eq!(ret, "unsigned long long");
        assert_eq!(args, ["const char *", "unsigned long long"]);
        let (ret, args) = decode_method("v24@0:8@?16");
        assert_eq!(ret, "void");
        assert_eq!(args, ["id /* block */"]);
        assert_eq!(decode_method(""), ("id".to_string(), vec![]));
    }

    #[test]
    fn a_method_line_names_its_arguments_by_position() {
        let method = ObjcMethod {
            selector: "hash:at:".to_string(),
            types: Some("Q32@0:8r*16Q24".to_string()),
            imp: None,
        };
        assert_eq!(
            method_line('-', &method),
            "- (unsigned long long)hash:(const char *)arg1 at:(unsigned long long)arg2;\n"
        );
        let method = ObjcMethod {
            selector: "answer".to_string(),
            types: Some("i16@0:8".to_string()),
            imp: None,
        };
        assert_eq!(method_line('+', &method), "+ (int)answer;\n");
        let method = ObjcMethod {
            selector: "mystery:".to_string(),
            types: None,
            imp: None,
        };
        assert_eq!(method_line('-', &method), "- (id)mystery:(id)arg1;\n");
    }

    #[test]
    fn a_property_line_reads_its_attributes() {
        let line = |name: &str, attributes: &str| {
            property_line(&ObjcProperty {
                name: name.to_string(),
                attributes: Some(attributes.to_string()),
            })
        };
        assert_eq!(
            line("count", "Ti,N,V_count"),
            "@property (nonatomic) int count;\n"
        );
        assert_eq!(
            line("origin", "T{Point=ii},R,N,V_origin"),
            "@property (nonatomic, readonly) struct Point origin;\n"
        );
        assert_eq!(
            line("parent", "T@\"Base\",N,V_parent"),
            "@property (nonatomic, assign) Base *parent;\n"
        );
        assert_eq!(
            line("name", "T@\"NSString\",C,N,V_name"),
            "@property (nonatomic, copy) NSString *name;\n"
        );
        assert_eq!(
            line("on", "TB,N,GisOn,SsetOn:,V_on"),
            "@property (nonatomic, getter=isOn, setter=setOn:) BOOL on;\n"
        );
        assert_eq!(
            line("items", "T[4i],R"),
            "@property (readonly) int items[4];\n"
        );
    }

    #[test]
    fn the_structs_the_encodings_spell_out_are_defined() {
        let objc = ObjcMetadata {
            classes: vec![ObjcClass {
                address: 0x2000,
                name: "Shape".to_string(),
                superclass: None,
                protocols: vec![],
                instance_methods: vec![ObjcMethod {
                    selector: "origin".to_string(),
                    types: Some("{Point=ii}16@0:8".to_string()),
                    imp: Some(0x1000),
                }],
                class_methods: vec![],
                ivars: vec![
                    super::super::ObjcIvar {
                        name: "_origin".to_string(),
                        types: Some("{Point=\"x\"i\"y\"i}".to_string()),
                        offset: Some(8),
                    },
                    super::super::ObjcIvar {
                        name: "_box".to_string(),
                        types: Some("{Box=\"at\"{Point=\"x\"i\"y\"i}\"size\"[2d]}".to_string()),
                        offset: Some(16),
                    },
                    super::super::ObjcIvar {
                        name: "_opaque".to_string(),
                        types: Some("^{Opaque}".to_string()),
                        offset: Some(48),
                    },
                ],
                properties: vec![],
            }],
            categories: vec![],
            protocols: vec![],
            selectors: Default::default(),
            class_refs: Default::default(),
        };
        let header = write(&objc);
        assert!(
            header.contains("struct Box {\n    struct Point at;\n    double size[2];\n};\n"),
            "{header}"
        );
        assert!(header.contains("struct Opaque;\n"), "{header}");
        assert!(
            header.contains("struct Point {\n    int x;\n    int y;\n};\n"),
            "{header}"
        );
        // Point is held by value in Box, so it is defined first.
        assert!(
            header.find("struct Point {").unwrap() < header.find("struct Box {").unwrap(),
            "{header}"
        );
        assert!(header.contains("    struct Point _origin;\n"), "{header}");
        assert!(header.contains("    struct Box _box;\n"), "{header}");
        assert!(header.contains("    struct Opaque *_opaque;\n"), "{header}");
        assert!(header.contains("- (struct Point)origin;\n"), "{header}");
    }

    #[test]
    fn a_category_on_a_class_of_another_image_is_a_comment_and_a_struct_body_may_be_empty() {
        let objc = ObjcMetadata {
            classes: vec![],
            categories: vec![ObjcCategory {
                address: 0x2200,
                name: "Extra".to_string(),
                class: None,
                protocols: vec![],
                instance_methods: vec![ObjcMethod {
                    selector: "thrice:".to_string(),
                    types: Some("i20@0:8i16".to_string()),
                    imp: Some(0x1000),
                }],
                class_methods: vec![],
                properties: vec![ObjcProperty {
                    name: "ref".to_string(),
                    attributes: Some("T^{__CFString=},N".to_string()),
                }],
            }],
            protocols: vec![],
            selectors: Default::default(),
            class_refs: Default::default(),
        };
        let header = write(&objc);
        assert!(header.contains("struct __CFString;\n"), "{header}");
        assert!(!header.contains("struct __CFString {"), "{header}");
        assert!(
            header.contains(
                "// A category on a class of another image, bound at load.\n// @interface ? (Extra)\n// @property (nonatomic) struct __CFString *ref;\n// - (int)thrice:(int)arg1;\n// @end\n"
            ),
            "{header}"
        );
        assert!(!header.contains("\n@interface"), "{header}");
    }

    #[test]
    fn a_chain_of_thousands_of_classes_and_protocols_is_ordered_without_recursion() {
        let classes = (0..50_000u64)
            .map(|index| ObjcClass {
                address: index,
                name: format!("C{index}"),
                superclass: Some(format!("C{}", index + 1)),
                protocols: vec![],
                instance_methods: vec![],
                class_methods: vec![],
                ivars: vec![],
                properties: vec![],
            })
            .collect();
        let protocols = (0..50_000u64)
            .map(|index| ObjcProtocol {
                address: index,
                name: format!("P{index}"),
                protocols: vec![format!("P{}", index + 1)],
                instance_methods: vec![],
                class_methods: vec![],
                optional_instance_methods: vec![],
                optional_class_methods: vec![],
                properties: vec![],
            })
            .collect();
        let objc = ObjcMetadata {
            classes,
            categories: vec![],
            protocols,
            selectors: Default::default(),
            class_refs: Default::default(),
        };
        let header = write(&objc);
        // The last of each chain is the root, and comes first.
        let root = header.find("@interface C49999").expect("root class");
        let leaf = header.find("@interface C0 ").expect("leaf class");
        assert!(root < leaf);
        let root = header.find("@protocol P49999 ").expect("root protocol");
        let leaf = header.find("@protocol P0 ").expect("leaf protocol");
        assert!(root < leaf);
    }

    #[test]
    fn the_header_declares_in_dependency_order_and_hides_accessors() {
        let method = |selector: &str, types: &str| ObjcMethod {
            selector: selector.to_string(),
            types: Some(types.to_string()),
            imp: Some(0x1000),
        };
        let objc = ObjcMetadata {
            classes: vec![
                ObjcClass {
                    address: 0x2000,
                    name: "Derived".to_string(),
                    superclass: Some("Base".to_string()),
                    protocols: vec!["Greeting".to_string()],
                    instance_methods: vec![
                        method("greet:", "i20@0:8i16"),
                        method("count", "i16@0:8"),
                        method("setCount:", "v20@0:8i16"),
                    ],
                    class_methods: vec![],
                    ivars: vec![super::super::ObjcIvar {
                        name: "_count".to_string(),
                        types: Some("i".to_string()),
                        offset: Some(8),
                    }],
                    properties: vec![ObjcProperty {
                        name: "count".to_string(),
                        attributes: Some("Ti,N,V_count".to_string()),
                    }],
                },
                ObjcClass {
                    address: 0x2100,
                    name: "Base".to_string(),
                    superclass: Some("NSObject".to_string()),
                    protocols: vec![],
                    instance_methods: vec![],
                    class_methods: vec![method("answer", "i16@0:8")],
                    ivars: vec![],
                    properties: vec![],
                },
            ],
            categories: vec![ObjcCategory {
                address: 0x2200,
                name: "Extra".to_string(),
                class: Some("Base".to_string()),
                protocols: vec![],
                instance_methods: vec![method("thrice:", "i20@0:8i16")],
                class_methods: vec![],
                properties: vec![],
            }],
            protocols: vec![ObjcProtocol {
                address: 0x2300,
                name: "Greeting".to_string(),
                protocols: vec!["NSObject".to_string()],
                instance_methods: vec![ObjcMethod {
                    selector: "greet:".to_string(),
                    types: Some("i20@0:8i16".to_string()),
                    imp: None,
                }],
                class_methods: vec![],
                optional_instance_methods: vec![ObjcMethod {
                    selector: "wave".to_string(),
                    types: Some("v16@0:8".to_string()),
                    imp: None,
                }],
                optional_class_methods: vec![],
                properties: vec![],
            }],
            selectors: Default::default(),
            class_refs: Default::default(),
        };
        let header = write(&objc);
        let expected = "\
// Objective-C declarations recovered from the image: 2 classes, 1 category, 1 protocol.
// Types are read from the runtime's encodings; where an encoding is missing, a type is `id`.
#import <objc/objc.h>

@class Base, Derived;
@protocol Greeting;

// Of other images, bound at load; their own headers declare them.
@class NSObject;
@protocol NSObject;

@protocol Greeting <NSObject>
- (int)greet:(int)arg1;
@optional
- (void)wave;
@end

@interface Base : NSObject
+ (int)answer;
@end

@interface Base (Extra)
- (int)thrice:(int)arg1;
@end

@interface Derived : Base <Greeting> {
    int _count;
}
@property (nonatomic) int count;
- (int)greet:(int)arg1;
@end
";
        assert_eq!(header, expected);
    }
}
