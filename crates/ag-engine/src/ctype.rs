//! C declarations read into a [`TypeStore`]: the analyst's structures,
//! unions, enumerations and typedefs, written as C.
//!
//! The parser reads a run of declarations:
//!
//! - `struct`, `union` and `enum` definitions, named or anonymous, nested
//!   in a member — `struct { int x; } at;`, or an anonymous `union { int
//!   i; float f; };` whose members are the outer one's — and in a
//!   typedef, `typedef struct { … } point_t;`; a declaration with no body,
//!   `struct node;`, declares the tag, and naming an undeclared tag,
//!   `struct node *next`, declares it too;
//! - typedefs, of every declarator C has: pointers, arrays, functions and
//!   pointers to them, `typedef int (*cmp_t)(const void *, const void *);`;
//! - an enumerator's value and an array's count as a constant expression:
//!   integer and character literals, the enumerators before it, `sizeof`
//!   and `_Alignof` of a type the store knows, casts, and `+ - * / % << >>
//!   & | ^ ~ !` with parentheses;
//! - bit-fields, `unsigned flags : 3;`, and unnamed ones, `int : 0;`;
//! - `#pragma pack(N)`, `#pragma pack(push, N)`, `#pragma pack(pop)` and
//!   `#pragma pack()`, and `__attribute__((packed))` and
//!   `__attribute__((aligned(N)))` on a structure;
//! - comments of both kinds, and whitespace.
//!
//! What it does not read it says in a note and goes on: `const`,
//! `volatile` and `restrict` are dropped — a type keeps no qualifiers —
//! and so are storage classes; another preprocessor line is skipped, for
//! no macro is expanded and no file included (#379 imports headers with
//! the compiler's flags); another attribute is skipped; a function or a
//! variable declared is no type and is skipped. What it cannot read is an
//! error at a line and column: `3:14: expected ; after the member`.
//!
//! The same parser reads one type, as a variable or a member is given
//! one: `struct point *`, `int (*)(char *, ...)`, `char[16]`
//! ([`parse_type`]). There a name the store does not define is taken as a
//! type of no known size, as the lift took the analyst's types before
//! there were definitions.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use crate::types::{Composite, Definition, Enumeration, Member, Prim, Type, TypeStore};

/// Why C text was not read: where, and what was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CError {
    pub line: u32,
    pub column: u32,
    pub message: String,
}

impl fmt::Display for CError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for CError {}

/// One declaration read: the names it defines, the name it goes by — a
/// typedef's when it declares one, the tag's otherwise — and its C text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    pub name: String,
    pub names: Vec<String>,
    /// The declaration's own text, under the `#pragma pack` it was read
    /// under when one was in force.
    pub text: String,
}

/// What a run of C declarations defined, and what was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parsed {
    /// The declarations that define a type, in order.
    pub declarations: Vec<Declared>,
    /// What was read loosely or skipped, each with its line and column.
    pub notes: Vec<String>,
}

/// Read the C declarations of `source` into `store`. On an error the store
/// is as it was.
pub fn parse_into(store: &mut TypeStore, source: &str) -> Result<Parsed, CError> {
    let tokens = lex(source)?;
    let mut parser = Parser::new(source, tokens, Cow::Owned(store.clone()), false);
    parser.translation_unit()?;
    let notes = std::mem::take(&mut parser.notes);
    let declarations = std::mem::take(&mut parser.declarations);
    *store = parser.store.into_owned();
    Ok(Parsed {
        declarations,
        notes,
    })
}

/// The one type `text` names — `struct point *`, `int (*)(char *, ...)`,
/// `char[16]` — read against `store`. A name it does not define is a type
/// of no known size: `struct point` with no definition, `foo_t`.
pub fn parse_type(store: &TypeStore, text: &str) -> Result<Type, CError> {
    let tokens = lex(text)?;
    let mut parser = Parser::new(text, tokens, Cow::Borrowed(store), true);
    let ty = parser.type_name()?;
    if !parser.at_end() {
        return Err(parser.error_here(format!("{} is not one type", text.trim())));
    }
    Ok(ty)
}

/// `text` as a type's spelling, `struct point *`, when it reads as one;
/// as it is otherwise.
pub fn normalized(store: &TypeStore, text: &str) -> String {
    match parse_type(store, text) {
        Ok(ty) => ty.spelled(store),
        Err(_) => text.trim().to_string(),
    }
}

/// The declaration of `name` of the type `ty` as C writes it — `int i`,
/// `char buf[16]`, `int (*cb)(int)` — the type read as [`parse_type`]
/// reads it, against the platform's primitives alone; a type that does not
/// read is put before the name as it is.
pub fn declarator(ty: &str, name: &str) -> String {
    let store = TypeStore::default();
    match parse_type(&store, ty) {
        Ok(parsed) => crate::types::declaration(&parsed, name, &store),
        Err(_) => format!("{} {name}", ty.trim()),
    }
}

// ---------------------------------------------------------------------
// The analyst's definitions, as the project keeps them.

/// One definition as the project keeps it: the name it goes by and its C
/// text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeText {
    pub name: String,
    pub c: String,
}

/// The store `definitions` build under `model`, in order, with the notes
/// the parser left; or the first that does not read, by its name.
pub fn build(
    model: crate::types::DataModel,
    definitions: &[TypeText],
) -> Result<(TypeStore, Vec<String>), String> {
    let mut store = TypeStore::new(model);
    let mut notes = Vec::new();
    for definition in definitions {
        let parsed = parse_into(&mut store, &definition.c)
            .map_err(|error| format!("{}: {error}", definition.name))?;
        notes.extend(
            parsed
                .notes
                .into_iter()
                .map(|note| format!("{}: {note}", definition.name)),
        );
    }
    Ok((store, notes))
}

/// The definition `name` stands for in `definitions`: the one by that
/// name, the one defining it, or the structure, union or enumeration it is
/// the tag of when only one is.
pub fn find(store: &TypeStore, definitions: &[TypeText], name: &str) -> Option<usize> {
    let name = name.trim();
    if let Some(at) = definitions.iter().position(|d| d.name == name) {
        return Some(at);
    }
    let defined = defined_names(*store.model(), definitions);
    let defines = |at: usize, key: &str| defined[at].iter().any(|n| n == key);
    let mut keys = vec![name.to_string()];
    if !name.contains(' ') {
        keys.extend(["struct", "union", "enum"].map(|kind| format!("{kind} {name}")));
    }
    for key in keys {
        let found: Vec<usize> = (0..definitions.len())
            .filter(|&at| definitions[at].name == key || defines(at, &key))
            .collect();
        if let [one] = found.as_slice() {
            return Some(*one);
        }
    }
    None
}

/// What an addition gives: the definitions, the names added, and the
/// parser's notes.
pub type Added = (Vec<TypeText>, Vec<String>, Vec<String>);

/// `definitions` with the declarations of `source` after them, each one a
/// definition of its own, and the notes the parser left; refused when a
/// name is defined already or the source does not read. A declaration
/// completing a tag only declared before takes the declaration's place.
pub fn add(
    model: crate::types::DataModel,
    definitions: &[TypeText],
    source: &str,
) -> Result<Added, String> {
    let (mut store, _) = build(model, definitions)?;
    let before = store.clone();
    let parsed = parse_into(&mut store, source).map_err(|error| error.to_string())?;
    if parsed.declarations.is_empty() {
        return Err("the source defines no type".to_string());
    }
    let mut out = definitions.to_vec();
    let mut added = Vec::new();
    for declared in &parsed.declarations {
        // A tag only declared before is completed: its declaration goes.
        out.retain(|held| {
            !(declared.names.contains(&held.name)
                && before
                    .get(&held.name)
                    .is_some_and(|definition| !definition.is_complete()))
        });
        let name = declared.name.clone();
        if out.iter().any(|held| held.name == name) {
            return Err(format!("{name} is defined already"));
        }
        added.push(name.clone());
        out.push(TypeText {
            name,
            c: declared.text.clone(),
        });
    }
    build(model, &out)?;
    Ok((out, added, parsed.notes))
}

/// `definitions` with the one `name` stands for replaced by `source`, in
/// its place — or, when the new text needs a definition after it, last.
pub fn replace(
    model: crate::types::DataModel,
    definitions: &[TypeText],
    name: &str,
    source: &str,
) -> Result<(Vec<TypeText>, Vec<String>), String> {
    let (store, _) = build(model, definitions)?;
    let Some(at) = find(&store, definitions, name) else {
        return Err(format!("no type is named {name}"));
    };
    let mut probe = TypeStore::new(model);
    let parsed = parse_into(&mut probe, source).map_err(|error| error.to_string())?;
    let Some(first) = parsed.declarations.first() else {
        return Err("the source defines no type".to_string());
    };
    let text = parsed
        .declarations
        .iter()
        .map(|d| d.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let replacement = TypeText {
        name: first.name.clone(),
        c: text,
    };
    let mut in_place = definitions.to_vec();
    in_place[at] = replacement.clone();
    let built = build(model, &in_place);
    let out = match built {
        Ok(_) => in_place,
        Err(why) => {
            let mut last = definitions.to_vec();
            last.remove(at);
            last.push(replacement);
            if build(model, &last).is_err() {
                return Err(why);
            }
            last
        }
    };
    let (_, notes) = build(model, &out)?;
    Ok((
        out,
        notes
            .into_iter()
            .filter(|n| n.starts_with(&first.name))
            .collect(),
    ))
}

/// `definitions` without the one `name` stands for; refused while another
/// definition, or a type in `users` — `(who, type)`, a variable's type
/// and what it is the type of — names what it defines.
pub fn remove(
    model: crate::types::DataModel,
    definitions: &[TypeText],
    name: &str,
    users: &[(String, String)],
) -> Result<(Vec<TypeText>, String), String> {
    let (store, _) = build(model, definitions)?;
    let Some(at) = find(&store, definitions, name) else {
        return Err(format!("no type is named {name}"));
    };
    let defined: Vec<String> = defined_names(model, definitions).swap_remove(at);
    let mut referring: Vec<String> = Vec::new();
    for key in store.names() {
        if defined.iter().any(|d| d == key) {
            continue;
        }
        let refs = store.references_of(key);
        if defined.iter().any(|d| refs.contains(d)) {
            referring.push(key.to_string());
        }
    }
    // A reference through an anonymous definition is its owner's.
    for key in store.keys() {
        if !store.is_anonymous(key) {
            continue;
        }
        let refs = store.references_of(key);
        if defined.iter().any(|d| refs.contains(d)) {
            for owner in store.names() {
                if store.references_of(owner).contains(key)
                    && !defined.iter().any(|d| d == owner)
                    && !referring.iter().any(|r| r == owner)
                {
                    referring.push(owner.to_string());
                }
            }
        }
    }
    for (who, ty) in users {
        if let Ok(parsed) = parse_type(&store, ty) {
            let mut names = std::collections::BTreeSet::new();
            parsed.names(&mut names);
            if defined.iter().any(|d| names.contains(d)) {
                referring.push(who.clone());
            }
        }
    }
    let shown = definitions[at].name.clone();
    if !referring.is_empty() {
        return Err(format!(
            "{shown} is not removed: {} {} to it",
            list(&referring),
            if referring.len() == 1 {
                "refers"
            } else {
                "refer"
            }
        ));
    }
    let mut out = definitions.to_vec();
    out.remove(at);
    Ok((out, shown))
}

/// The names each of `definitions` defines, read in order.
fn defined_names(model: crate::types::DataModel, definitions: &[TypeText]) -> Vec<Vec<String>> {
    let mut store = TypeStore::new(model);
    definitions
        .iter()
        .map(|definition| {
            parse_into(&mut store, &definition.c)
                .map(|parsed| {
                    parsed
                        .declarations
                        .into_iter()
                        .flat_map(|d| d.names)
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect()
}

/// `a`, `a and b`, `a, b and c`.
fn list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

// ---------------------------------------------------------------------
// The tokens.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Number(u64),
    Punct(&'static str),
    /// A `#pragma pack` line.
    Pack(PackOp),
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackOp {
    /// `#pragma pack(N)`, or `#pragma pack()` to the default.
    Set(Option<u64>),
    /// `#pragma pack(push)` or `#pragma pack(push, N)`.
    Push(Option<u64>),
    /// `#pragma pack(pop)`.
    Pop,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    line: u32,
    column: u32,
    start: usize,
    end: usize,
}

const PUNCTS: &[&str] = &[
    "...", "<<", ">>", "==", "!=", "<=", ">=", "&&", "||", "->", "{", "}", "(", ")", "[", "]", ";",
    ",", "*", ":", "=", "+", "-", "/", "%", "|", "&", "^", "~", "!", "<", ">", "?", ".",
];

/// The tokens of `source`, the preprocessor's lines read for `#pragma
/// pack` and otherwise left for the parser to note.
fn lex(source: &str) -> Result<Vec<Token>, CError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let mut line = 1u32;
    let mut line_start = 0usize;
    let mut at_line_start = true;
    let column = |i: usize, line_start: usize| (source[line_start..i].chars().count() + 1) as u32;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\n' {
            i += 1;
            line += 1;
            line_start = i;
            at_line_start = true;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if source[i..].starts_with("//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if source[i..].starts_with("/*") {
            let (open_line, open_column) = (line, column(i, line_start));
            i += 2;
            loop {
                if i >= bytes.len() {
                    return Err(CError {
                        line: open_line,
                        column: open_column,
                        message: "the comment is not closed".to_string(),
                    });
                }
                if source[i..].starts_with("*/") {
                    i += 2;
                    break;
                }
                if bytes[i] == b'\n' {
                    line += 1;
                    line_start = i + 1;
                }
                i += 1;
            }
            continue;
        }
        let start = i;
        let col = column(i, line_start);
        if c == b'#' && at_line_start {
            // The directive runs to the end of the line, and past a
            // backslash ending one.
            let mut text = String::new();
            while i < bytes.len() && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'\n') {
                    i += 2;
                    line += 1;
                    line_start = i;
                    text.push(' ');
                    continue;
                }
                text.push(bytes[i] as char);
                i += 1;
            }
            let directive = text.trim_start_matches('#').trim().to_string();
            tokens.push(Token {
                tok: match pack_pragma(&directive) {
                    Some(Ok(op)) => Tok::Pack(op),
                    Some(Err(why)) => {
                        return Err(CError {
                            line,
                            column: col,
                            message: why,
                        })
                    }
                    None => Tok::Ident(format!("#{directive}")),
                },
                line,
                column: col,
                start,
                end: i,
            });
            continue;
        }
        at_line_start = false;
        if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            tokens.push(Token {
                tok: Tok::Ident(source[start..i].to_string()),
                line,
                column: col,
                start,
                end: i,
            });
            continue;
        }
        if c.is_ascii_digit() {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let text = &source[start..i];
            let value = number(text).ok_or_else(|| CError {
                line,
                column: col,
                message: format!("{text} is not a number"),
            })?;
            tokens.push(Token {
                tok: Tok::Number(value),
                line,
                column: col,
                start,
                end: i,
            });
            continue;
        }
        if c == b'\'' {
            let (value, len) = char_literal(&source[i..]).ok_or_else(|| CError {
                line,
                column: col,
                message: "the character literal is not closed".to_string(),
            })?;
            i += len;
            tokens.push(Token {
                tok: Tok::Number(value),
                line,
                column: col,
                start,
                end: i,
            });
            continue;
        }
        match PUNCTS.iter().find(|p| source[i..].starts_with(**p)) {
            Some(p) => {
                i += p.len();
                tokens.push(Token {
                    tok: Tok::Punct(p),
                    line,
                    column: col,
                    start,
                    end: i,
                });
            }
            None => {
                let shown = source[i..].chars().next().unwrap_or('?');
                return Err(CError {
                    line,
                    column: col,
                    message: format!("{shown:?} is not read in a declaration"),
                });
            }
        }
    }
    let col = column(bytes.len(), line_start);
    tokens.push(Token {
        tok: Tok::End,
        line,
        column: col,
        start: bytes.len(),
        end: bytes.len(),
    });
    Ok(tokens)
}

/// The `#pragma pack` a directive is, when it is one.
fn pack_pragma(directive: &str) -> Option<Result<PackOp, String>> {
    let rest = directive.strip_prefix("pragma")?.trim_start();
    let rest = rest.strip_prefix("pack")?.trim();
    let inside = rest
        .strip_prefix('(')
        .and_then(|r| r.strip_suffix(')'))
        .map(str::trim);
    let Some(inside) = inside else {
        return Some(Err(format!(
            "#{directive} is not read: pack(N), pack(push, N) or pack(pop)"
        )));
    };
    let parts: Vec<&str> = inside.split(',').map(str::trim).collect();
    let size = |text: &str| -> Result<u64, String> {
        match number(text) {
            Some(n) if n.is_power_of_two() && n <= 16 => Ok(n),
            _ => Err(format!("{text} is no packing: 1, 2, 4, 8 or 16")),
        }
    };
    Some(match parts.as_slice() {
        [""] => Ok(PackOp::Set(None)),
        ["push"] => Ok(PackOp::Push(None)),
        ["pop"] => Ok(PackOp::Pop),
        ["push", n] => size(n).map(|n| PackOp::Push(Some(n))),
        [n] => size(n).map(|n| PackOp::Set(Some(n))),
        _ => Err(format!(
            "#{directive} is not read: pack(N), pack(push, N) or pack(pop)"
        )),
    })
}

/// An integer literal's value: decimal, `0x` hex, `0b` binary or octal,
/// with any of C's suffixes.
fn number(text: &str) -> Option<u64> {
    let digits = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let (radix, digits) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if let Some(bin) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (2, bin)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    u64::from_str_radix(&digits.replace('_', ""), radix).ok()
}

/// A character literal's value and length: `'a'`, `'\n'`, `'\x41'`.
fn char_literal(text: &str) -> Option<(u64, usize)> {
    let body = text.strip_prefix('\'')?;
    let close = body.find('\'')?;
    let inner = &body[..close];
    let value = match inner.strip_prefix('\\') {
        None => inner.chars().next()? as u64,
        Some(escape) => match escape {
            "n" => 10,
            "t" => 9,
            "r" => 13,
            "0" => 0,
            "\\" => 92,
            "'" => 39,
            "\"" => 34,
            "a" => 7,
            "b" => 8,
            "f" => 12,
            "v" => 11,
            _ => match escape.strip_prefix('x') {
                Some(hex) => u64::from_str_radix(hex, 16).ok()?,
                None => u64::from_str_radix(escape, 8).ok()?,
            },
        },
    };
    Some((value, close + 2))
}

// ---------------------------------------------------------------------
// The parser.

/// What a declaration's specifiers say.
struct Specs {
    typedef: bool,
    base: Type,
}

/// The attributes read on a structure.
#[derive(Default)]
struct Attrs {
    packed: bool,
    aligned: Option<u64>,
}

/// One step of a declarator, applied to the type inside out.
enum Op {
    Pointer,
    Array(Option<u64>),
    Function(Vec<Type>, bool),
}

struct Parser<'a> {
    source: &'a str,
    tokens: Vec<Token>,
    pos: usize,
    store: Cow<'a, TypeStore>,
    /// One type is read, and an unknown name is a type of no known size.
    lenient: bool,
    pack: Option<u64>,
    pack_stack: Vec<Option<u64>>,
    notes: Vec<String>,
    qualifiers_noted: bool,
    declarations: Vec<Declared>,
    /// The names defined by the declaration being read.
    defining: Vec<String>,
    /// The enumerators of the enumeration being read, for its own values.
    local_constants: BTreeMap<String, i64>,
}

const QUALIFIERS: &[&str] = &[
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
    "__const",
    "__volatile__",
    "_Atomic",
];

const STORAGE: &[&str] = &[
    "extern",
    "static",
    "inline",
    "__inline",
    "__inline__",
    "register",
    "auto",
    "_Noreturn",
    "__extension__",
    "_Thread_local",
];

const BASIC: &[&str] = &[
    "void",
    "char",
    "short",
    "int",
    "long",
    "signed",
    "unsigned",
    "float",
    "double",
    "_Bool",
    "__signed__",
    "__signed",
];

impl<'a> Parser<'a> {
    fn new(source: &'a str, tokens: Vec<Token>, store: Cow<'a, TypeStore>, lenient: bool) -> Self {
        Parser {
            source,
            tokens,
            pos: 0,
            store,
            lenient,
            pack: None,
            pack_stack: Vec::new(),
            notes: Vec::new(),
            qualifiers_noted: false,
            declarations: Vec::new(),
            defining: Vec::new(),
            local_constants: BTreeMap::new(),
        }
    }

    fn peek(&self) -> &Tok {
        &self.tokens[self.pos].tok
    }

    fn peek_at(&self, ahead: usize) -> &Tok {
        let at = (self.pos + ahead).min(self.tokens.len() - 1);
        &self.tokens[at].tok
    }

    fn token(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens[self.pos].clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        token
    }

    fn at_end(&self) -> bool {
        matches!(self.peek(), Tok::End)
    }

    fn is_punct(&self, p: &str) -> bool {
        matches!(self.peek(), Tok::Punct(q) if *q == p)
    }

    fn eat(&mut self, p: &str) -> bool {
        if self.is_punct(p) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn is_word(&self, word: &str) -> bool {
        matches!(self.peek(), Tok::Ident(w) if w == word)
    }

    fn error_here(&self, message: String) -> CError {
        let token = self.token();
        CError {
            line: token.line,
            column: token.column,
            message,
        }
    }

    fn note_here(&mut self, message: String) {
        let token = self.token();
        let note = format!("{}:{}: {message}", token.line, token.column);
        self.notes.push(note);
    }

    /// What the next token is, as an error's message names it.
    fn shown(&self) -> String {
        match self.peek() {
            Tok::Ident(word) => word.clone(),
            Tok::Number(_) => self.source[self.token().start..self.token().end].to_string(),
            Tok::Punct(p) => (*p).to_string(),
            Tok::Pack(_) => "#pragma pack".to_string(),
            Tok::End => "the end".to_string(),
        }
    }

    fn expect(&mut self, p: &str, after: &str) -> Result<(), CError> {
        if self.eat(p) {
            Ok(())
        } else {
            Err(self.error_here(format!("expected {p} {after}, not {}", self.shown())))
        }
    }

    fn define(&mut self, key: &str, definition: Definition) -> Result<(), CError> {
        let at = self.token().clone();
        self.define_at(key, definition, &at)
    }

    /// [`Parser::define`], an error placed at `at`.
    fn define_at(&mut self, key: &str, definition: Definition, at: &Token) -> Result<(), CError> {
        if self.lenient {
            return Err(self.error_here(format!(
                "{} is defined here: define it among the types first",
                crate::types::shown_key(key)
            )));
        }
        self.store
            .to_mut()
            .define(key, definition)
            .map_err(|message| CError {
                line: at.line,
                column: at.column,
                message,
            })
    }

    /// Apply the `#pragma pack` lines at the parser's position, and note
    /// the other preprocessor lines.
    fn directives(&mut self) -> Result<(), CError> {
        loop {
            match self.peek().clone() {
                Tok::Pack(op) => {
                    match op {
                        PackOp::Set(n) => self.pack = n,
                        PackOp::Push(n) => {
                            self.pack_stack.push(self.pack);
                            if n.is_some() {
                                self.pack = n;
                            }
                        }
                        PackOp::Pop => {
                            self.pack = self.pack_stack.pop().flatten();
                        }
                    }
                    self.advance();
                }
                Tok::Ident(word) if word.starts_with('#') => {
                    if word != "#pragma once" && !word.trim().is_empty() && word != "#" {
                        self.note_here(format!(
                            "{word} is skipped: no macro is expanded and no file included"
                        ));
                    }
                    self.advance();
                }
                _ => return Ok(()),
            }
        }
    }

    fn translation_unit(&mut self) -> Result<(), CError> {
        loop {
            self.directives()?;
            if self.at_end() {
                return Ok(());
            }
            if self.eat(";") {
                continue;
            }
            self.declaration()?;
        }
    }

    /// One top-level declaration, through its `;`.
    fn declaration(&mut self) -> Result<(), CError> {
        let start = self.token().start;
        let pack = self.pack;
        self.defining.clear();
        let Some(specs) = self.specifiers()? else {
            return Err(self.error_here(format!("expected a declaration, not {}", self.shown())));
        };
        let mut typedefs = Vec::new();
        if !self.is_punct(";") {
            loop {
                let at = self.token().clone();
                let (name, ops) = self.declarator(false)?;
                self.attributes_skipped("a declarator")?;
                let Some(name) = name else {
                    return Err(self.error_here("the declaration names nothing".to_string()));
                };
                let ty = self.apply(specs.base.clone(), ops, &at)?;
                if self.is_punct("=") {
                    return Err(
                        self.error_here(format!("{name} has an initializer: a type has none"))
                    );
                }
                if specs.typedef {
                    if BASIC.contains(&name.as_str()) || Prim::named(&name).is_some() {
                        return Err(CError {
                            line: at.line,
                            column: at.column,
                            message: format!("{name} is a type of the platform already"),
                        });
                    }
                    self.define(&name, Definition::Typedef(ty))?;
                    self.defining.push(name.clone());
                    typedefs.push(name);
                } else {
                    let what = if matches!(ty, Type::Function { .. }) {
                        "a function"
                    } else {
                        "a variable"
                    };
                    self.notes.push(format!(
                        "{}:{}: {name} is {what}, not a type: it is skipped",
                        at.line, at.column
                    ));
                }
                if !self.eat(",") {
                    break;
                }
            }
        }
        let end_token = self.token().clone();
        self.expect(";", "after the declaration")?;
        if self.defining.is_empty() {
            return Ok(());
        }
        let mut names = std::mem::take(&mut self.defining);
        names.dedup();
        // A typedef's name, or the outermost tag: the last defined.
        let name = typedefs
            .first()
            .cloned()
            .unwrap_or_else(|| names[names.len() - 1].clone());
        let own = self.source[start..end_token.end].trim().to_string();
        let text = match pack {
            Some(n) => format!("#pragma pack(push, {n})\n{own}\n#pragma pack(pop)"),
            None => own,
        };
        self.declarations.push(Declared { name, names, text });
        Ok(())
    }

    /// A declaration's specifiers: its storage class, qualifiers and type.
    /// `None` when the next token starts none.
    fn specifiers(&mut self) -> Result<Option<Specs>, CError> {
        let mut typedef = false;
        let mut words: Vec<String> = Vec::new();
        let mut base: Option<Type> = None;
        let mut any = false;
        while let Tok::Ident(word) = self.peek().clone() {
            let word = word.as_str();
            if word == "typedef" {
                typedef = true;
            } else if STORAGE.contains(&word) {
            } else if QUALIFIERS.contains(&word) {
                self.note_qualifier();
            } else if word == "__attribute__" || word == "__attribute" {
                self.attributes_skipped("a declaration")?;
                any = true;
                continue;
            } else if word == "__declspec" {
                self.advance();
                self.balanced_skipped()?;
                self.note_here("__declspec is skipped".to_string());
                any = true;
                continue;
            } else if BASIC.contains(&word) {
                if base.is_some() {
                    return Err(self.error_here(format!("{word} follows a type already")));
                }
                words.push(word.trim_matches('_').replace("signed__", "signed"));
            } else if word == "bool" && base.is_none() && words.is_empty() {
                base = Some(Type::Prim(Prim::Bool));
            } else if word == "struct" || word == "union" || word == "enum" {
                if base.is_some() || !words.is_empty() {
                    return Err(self.error_here(format!("{word} follows a type already")));
                }
                self.advance();
                base = Some(if word == "enum" {
                    self.enum_specifier()?
                } else {
                    self.composite_specifier(word)?
                });
                any = true;
                continue;
            } else if base.is_none() && words.is_empty() {
                // A typedef's name, or the platform's.
                if let Some(prim) = Prim::named(word) {
                    if self.store.get(word).is_none() {
                        base = Some(Type::Prim(prim));
                    } else {
                        base = Some(Type::Named(word.to_string()));
                    }
                } else if matches!(self.store.get(word), Some(Definition::Typedef(_)))
                    || (self.lenient && !word.starts_with('#'))
                {
                    base = Some(Type::Named(word.to_string()));
                } else {
                    break;
                }
            } else {
                break;
            }
            any = true;
            self.advance();
        }
        if !any {
            return Ok(None);
        }
        let base = match base {
            Some(base) => base,
            None if words.is_empty() => {
                return Err(self.error_here(format!("expected a type, not {}", self.shown())))
            }
            None => Type::Prim(
                basic(&words)
                    .ok_or_else(|| self.error_here(format!("{} is not a type", words.join(" "))))?,
            ),
        };
        Ok(Some(Specs { typedef, base }))
    }

    fn note_qualifier(&mut self) {
        if !self.qualifiers_noted {
            self.qualifiers_noted = true;
            self.note_here(
                "const, volatile and restrict are dropped: a type keeps no qualifiers".to_string(),
            );
        }
    }

    /// Skip a parenthesized run of tokens.
    fn balanced_skipped(&mut self) -> Result<(), CError> {
        if !self.is_punct("(") {
            return Ok(());
        }
        let mut depth = 0usize;
        loop {
            match self.peek() {
                Tok::Punct("(") => depth += 1,
                Tok::Punct(")") => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        return Ok(());
                    }
                }
                Tok::End => {
                    return Err(self.error_here("the parenthesis is not closed".to_string()))
                }
                _ => {}
            }
            self.advance();
        }
    }

    /// `__attribute__((…))` lists at the position, read for `packed` and
    /// `aligned(N)`.
    fn attributes(&mut self, attrs: &mut Attrs) -> Result<(), CError> {
        while self.is_word("__attribute__") || self.is_word("__attribute") {
            self.advance();
            self.expect("(", "after __attribute__")?;
            self.expect("(", "after __attribute__(")?;
            loop {
                if self.eat(")") {
                    break;
                }
                let Tok::Ident(word) = self.peek().clone() else {
                    return Err(
                        self.error_here(format!("expected an attribute, not {}", self.shown()))
                    );
                };
                self.advance();
                let bare = word.trim_matches('_');
                match bare {
                    "packed" => attrs.packed = true,
                    "aligned" => {
                        if self.eat("(") {
                            let n = self.constant()?;
                            self.expect(")", "after the alignment")?;
                            if n <= 0 || !(n as u64).is_power_of_two() {
                                return Err(self.error_here(format!("{n} is no alignment")));
                            }
                            attrs.aligned = Some(n as u64);
                        } else {
                            attrs.aligned = Some(self.store.model().long_double.1.max(8));
                        }
                    }
                    _ => {
                        self.balanced_skipped()?;
                        self.note_here(format!("the attribute {word} is skipped"));
                    }
                }
                if !self.eat(",") {
                    self.expect(")", "after the attributes")?;
                    break;
                }
            }
            self.expect(")", "after __attribute__((…)")?;
        }
        Ok(())
    }

    /// Attributes where the parser keeps none, noted.
    fn attributes_skipped(&mut self, on: &str) -> Result<(), CError> {
        if !(self.is_word("__attribute__") || self.is_word("__attribute")) {
            return Ok(());
        }
        let mut attrs = Attrs::default();
        let token = self.token().clone();
        self.attributes(&mut attrs)?;
        if attrs.packed || attrs.aligned.is_some() {
            self.notes.push(format!(
                "{}:{}: an attribute on {on} is skipped: packed and aligned are read on a structure",
                token.line, token.column
            ));
        }
        Ok(())
    }

    /// `struct`/`union` after its keyword: a reference to its tag, or a
    /// definition.
    fn composite_specifier(&mut self, kind: &str) -> Result<Type, CError> {
        let mut attrs = Attrs::default();
        self.attributes(&mut attrs)?;
        let tag = match self.peek().clone() {
            Tok::Ident(word) if !word.starts_with('#') => {
                self.advance();
                Some(word)
            }
            _ => None,
        };
        if !self.is_punct("{") {
            let Some(tag) = tag else {
                return Err(self.error_here(format!(
                    "expected a tag or {{ after {kind}, not {}",
                    self.shown()
                )));
            };
            let key = format!("{kind} {tag}");
            if !self.lenient && self.store.get(&key).is_none() {
                // Named before it is defined: declared.
                let empty = Composite {
                    tag: Some(tag.clone()),
                    ..Composite::default()
                };
                let definition = if kind == "union" {
                    Definition::Union(empty)
                } else {
                    Definition::Struct(empty)
                };
                self.define(&key, definition)?;
                if self.is_punct(";") {
                    self.defining.push(key.clone());
                }
            } else if !self.lenient && self.is_punct(";") {
                if let Some(held) = self.store.get(&key) {
                    if held.kind() != kind {
                        return Err(self.error_here(format!("{key} is a {} already", held.kind())));
                    }
                }
            }
            return Ok(Type::Named(key));
        }
        let open = self.token().clone();
        self.advance();
        let key = match &tag {
            Some(tag) => format!("{kind} {tag}"),
            None if self.lenient => {
                return Err(CError {
                    line: open.line,
                    column: open.column,
                    message: format!(
                        "an anonymous {kind} is defined here: define it among the types first"
                    ),
                })
            }
            None => self.store.to_mut().anonymous_key(kind),
        };
        if self.lenient {
            return Err(CError {
                line: open.line,
                column: open.column,
                message: format!("{key} is defined here: define it among the types first"),
            });
        }
        if let Some(held) = self.store.get(&key) {
            if held.is_complete() {
                return Err(CError {
                    line: open.line,
                    column: open.column,
                    message: format!("{key} is defined already"),
                });
            }
        }
        let outer_defining = std::mem::take(&mut self.defining);
        let mut members = Vec::new();
        loop {
            self.directives()?;
            if self.eat("}") {
                break;
            }
            if self.at_end() {
                return Err(CError {
                    line: open.line,
                    column: open.column,
                    message: format!(
                        "the body of {} is not closed",
                        crate::types::shown_key(&key)
                    ),
                });
            }
            if self.eat(";") {
                continue;
            }
            self.member_declaration(&mut members)?;
        }
        self.attributes(&mut attrs)?;
        let composite = Composite {
            tag: tag.clone(),
            members: Some(members),
            pack: self.pack,
            packed: attrs.packed,
            aligned: attrs.aligned,
        };
        let definition = if kind == "union" {
            Definition::Union(composite)
        } else {
            Definition::Struct(composite)
        };
        self.define_at(&key, definition, &open)?;
        let inner = std::mem::replace(&mut self.defining, outer_defining);
        self.defining.extend(inner);
        if tag.is_some() {
            self.defining.push(key.clone());
        }
        Ok(Type::Named(key))
    }

    /// One member declaration of a structure or union, through its `;`.
    fn member_declaration(&mut self, members: &mut Vec<Member>) -> Result<(), CError> {
        let at = self.token().clone();
        let Some(specs) = self.specifiers()? else {
            return Err(self.error_here(format!("expected a member, not {}", self.shown())));
        };
        if specs.typedef {
            return Err(CError {
                line: at.line,
                column: at.column,
                message: "a typedef is no member".to_string(),
            });
        }
        if self.eat(";") {
            // An anonymous structure or union: its members are this one's.
            match &specs.base {
                Type::Named(key) if self.store.is_anonymous(key) => {
                    members.push(Member {
                        name: None,
                        ty: specs.base.clone(),
                        bits: None,
                    });
                }
                _ => self.notes.push(format!(
                    "{}:{}: the member declares nothing: it is skipped",
                    at.line, at.column
                )),
            }
            return Ok(());
        }
        loop {
            let here = self.token().clone();
            if self.eat(":") {
                let width = self.bit_width()?;
                members.push(Member {
                    name: None,
                    ty: specs.base.clone(),
                    bits: Some(width),
                });
            } else {
                let (name, ops) = self.declarator(false)?;
                let Some(name) = name else {
                    return Err(CError {
                        line: here.line,
                        column: here.column,
                        message: "the member has no name".to_string(),
                    });
                };
                let ty = self.apply(specs.base.clone(), ops, &here)?;
                if matches!(ty, Type::Function { .. }) {
                    return Err(CError {
                        line: here.line,
                        column: here.column,
                        message: format!("{name} is a function: a member is a pointer to one"),
                    });
                }
                if members
                    .iter()
                    .any(|m| m.name.as_deref() == Some(name.as_str()))
                {
                    return Err(CError {
                        line: here.line,
                        column: here.column,
                        message: format!("{name} is a member already"),
                    });
                }
                let bits = if self.eat(":") {
                    Some(self.bit_width()?)
                } else {
                    None
                };
                if bits == Some(0) {
                    return Err(CError {
                        line: here.line,
                        column: here.column,
                        message: format!("{name} is zero bits wide: only an unnamed bit-field is"),
                    });
                }
                self.attributes_skipped("a member")?;
                members.push(Member {
                    name: Some(name),
                    ty,
                    bits,
                });
            }
            if !self.eat(",") {
                break;
            }
        }
        self.expect(";", "after the member")
    }

    fn bit_width(&mut self) -> Result<u32, CError> {
        let at = self.token().clone();
        let width = self.constant()?;
        u32::try_from(width).map_err(|_| CError {
            line: at.line,
            column: at.column,
            message: format!("{width} is no bit-field width"),
        })
    }

    /// `enum` after its keyword: a reference to its tag, or a definition.
    fn enum_specifier(&mut self) -> Result<Type, CError> {
        let mut attrs = Attrs::default();
        self.attributes(&mut attrs)?;
        let tag = match self.peek().clone() {
            Tok::Ident(word) if !word.starts_with('#') => {
                self.advance();
                Some(word)
            }
            _ => None,
        };
        let mut underlying = None;
        if self.eat(":") {
            let at = self.token().clone();
            let Some(specs) = self.specifiers()? else {
                return Err(self.error_here("expected the enumeration's integer type".to_string()));
            };
            match self.store.resolve(&specs.base) {
                Type::Prim(p) if p.is_integer() => underlying = Some(*p),
                _ => {
                    return Err(CError {
                        line: at.line,
                        column: at.column,
                        message: "an enumeration is held in an integer type".to_string(),
                    })
                }
            }
        }
        if !self.is_punct("{") {
            let Some(tag) = tag else {
                return Err(self.error_here(format!(
                    "expected a tag or {{ after enum, not {}",
                    self.shown()
                )));
            };
            let key = format!("enum {tag}");
            if !self.lenient && self.store.get(&key).is_none() {
                self.define(
                    &key,
                    Definition::Enum(Enumeration {
                        tag: Some(tag),
                        underlying: underlying.unwrap_or(Prim::Int),
                        values: Vec::new(),
                        complete: false,
                    }),
                )?;
                if self.is_punct(";") {
                    self.defining.push(key.clone());
                }
            }
            return Ok(Type::Named(key));
        }
        let open = self.token().clone();
        self.advance();
        if self.lenient {
            return Err(CError {
                line: open.line,
                column: open.column,
                message: "an enumeration is defined here: define it among the types first"
                    .to_string(),
            });
        }
        let key = match &tag {
            Some(tag) => format!("enum {tag}"),
            None => self.store.to_mut().anonymous_key("enum"),
        };
        let mut values: Vec<(String, i64)> = Vec::new();
        let mut next: i64 = 0;
        self.local_constants.clear();
        loop {
            if self.eat("}") {
                break;
            }
            let Tok::Ident(name) = self.peek().clone() else {
                return Err(
                    self.error_here(format!("expected an enumerator, not {}", self.shown()))
                );
            };
            let at = self.token().clone();
            self.advance();
            if values.iter().any(|(n, _)| *n == name) || self.store.constant(&name).is_some() {
                return Err(CError {
                    line: at.line,
                    column: at.column,
                    message: format!("{name} is an enumerator already"),
                });
            }
            let value = if self.eat("=") {
                self.constant()?
            } else {
                next
            };
            values.push((name.clone(), value));
            self.local_constants.insert(name, value);
            next = value.wrapping_add(1);
            if !self.eat(",") {
                self.expect("}", "after the enumerators")?;
                break;
            }
        }
        self.local_constants.clear();
        let underlying = underlying.unwrap_or_else(|| {
            if values.iter().all(|(_, v)| i32::try_from(*v).is_ok()) {
                Prim::Int
            } else if values.iter().all(|(_, v)| u32::try_from(*v).is_ok()) {
                Prim::UInt
            } else if values.iter().any(|(_, v)| *v < 0) {
                Prim::LongLong
            } else {
                Prim::ULongLong
            }
        });
        self.define(
            &key,
            Definition::Enum(Enumeration {
                tag: tag.clone(),
                underlying,
                values,
                complete: true,
            }),
        )?;
        if tag.is_some() {
            self.defining.push(key.clone());
        }
        Ok(Type::Named(key))
    }

    /// A declarator: its name, when it has one, and the steps that make its
    /// type from the specifiers'. With `abstract`, a name is not needed.
    fn declarator(&mut self, abstract_ok: bool) -> Result<(Option<String>, Vec<Op>), CError> {
        let mut stars = 0usize;
        loop {
            if self.eat("*") {
                stars += 1;
                continue;
            }
            if let Tok::Ident(word) = self.peek() {
                if QUALIFIERS.contains(&word.as_str()) {
                    self.note_qualifier();
                    self.advance();
                    continue;
                }
                if word == "__attribute__" {
                    self.attributes_skipped("a pointer")?;
                    continue;
                }
            }
            break;
        }
        let mut name = None;
        let mut inner = Vec::new();
        if self.is_punct("(") && self.nested_follows() {
            self.advance();
            let (n, ops) = self.declarator(abstract_ok)?;
            self.expect(")", "after the declarator")?;
            name = n;
            inner = ops;
        } else if let Tok::Ident(word) = self.peek().clone() {
            let typename = abstract_ok && self.names_type(&word);
            if !typename && !word.starts_with('#') && word != "__attribute__" {
                self.advance();
                name = Some(word);
            }
        }
        let mut suffixes = Vec::new();
        loop {
            if self.eat("[") {
                if self.eat("]") {
                    suffixes.push(Op::Array(None));
                    continue;
                }
                let at = self.token().clone();
                let count = self.constant()?;
                if count < 0 {
                    return Err(CError {
                        line: at.line,
                        column: at.column,
                        message: format!("{count} is no count"),
                    });
                }
                self.expect("]", "after the count")?;
                suffixes.push(Op::Array(Some(count as u64)));
            } else if self.is_punct("(") {
                self.advance();
                let (params, variadic) = self.parameters()?;
                suffixes.push(Op::Function(params, variadic));
            } else {
                break;
            }
        }
        let mut ops: Vec<Op> = (0..stars).map(|_| Op::Pointer).collect();
        ops.extend(suffixes.into_iter().rev());
        ops.extend(inner);
        if name.is_none() && !abstract_ok {
            return Ok((None, ops));
        }
        Ok((name, ops))
    }

    /// Whether a name is a type here: a typedef, a platform type, a
    /// keyword that starts one.
    fn names_type(&self, word: &str) -> bool {
        BASIC.contains(&word)
            || QUALIFIERS.contains(&word)
            || matches!(word, "struct" | "union" | "enum" | "bool")
            || Prim::named(word).is_some()
            || matches!(self.store.get(word), Some(Definition::Typedef(_)))
    }

    /// Whether the `(` at the position opens a nested declarator, `(*fp)`,
    /// rather than a parameter list.
    fn nested_follows(&self) -> bool {
        match self.peek_at(1) {
            Tok::Punct("*") | Tok::Punct("(") | Tok::Punct("[") => true,
            Tok::Ident(word) => !self.names_type(word) && !word.starts_with("__attribute"),
            _ => false,
        }
    }

    /// A parameter list after its `(`, through its `)`: the parameters'
    /// types, and whether it ends in `...`.
    fn parameters(&mut self) -> Result<(Vec<Type>, bool), CError> {
        let mut params = Vec::new();
        let mut variadic = false;
        if self.eat(")") {
            return Ok((params, false));
        }
        if self.is_word("void") && matches!(self.peek_at(1), Tok::Punct(")")) {
            self.advance();
            self.advance();
            return Ok((params, false));
        }
        loop {
            if self.eat("...") {
                variadic = true;
                self.expect(")", "after ...")?;
                break;
            }
            let at = self.token().clone();
            let Some(specs) = self.specifiers()? else {
                return Err(self.error_here(format!("expected a parameter, not {}", self.shown())));
            };
            let (_, ops) = self.declarator(true)?;
            let ty = self.apply(specs.base, ops, &at)?;
            // An array or a function parameter is a pointer.
            let ty = match ty {
                Type::Array(element, _) => Type::Pointer(element),
                f @ Type::Function { .. } => Type::pointer(f),
                other => other,
            };
            params.push(ty);
            if !self.eat(",") {
                self.expect(")", "after the parameters")?;
                break;
            }
        }
        Ok((params, variadic))
    }

    /// The type the steps `ops` make of `base`.
    fn apply(&self, base: Type, ops: Vec<Op>, at: &Token) -> Result<Type, CError> {
        let fail = |message: String| CError {
            line: at.line,
            column: at.column,
            message,
        };
        let mut ty = base;
        for op in ops {
            ty = match op {
                Op::Pointer => Type::pointer(ty),
                Op::Array(count) => {
                    if matches!(ty, Type::Function { .. }) {
                        return Err(fail("an array of functions is no type".to_string()));
                    }
                    if ty == Type::Prim(Prim::Void) {
                        return Err(fail("an array of void is no type".to_string()));
                    }
                    Type::Array(Box::new(ty), count)
                }
                Op::Function(params, variadic) => {
                    if matches!(ty, Type::Function { .. } | Type::Array(..)) {
                        return Err(fail("a function returns no array or function".to_string()));
                    }
                    Type::Function {
                        ret: Box::new(ty),
                        params,
                        variadic,
                    }
                }
            };
        }
        Ok(ty)
    }

    /// A type name: specifiers and an abstract declarator.
    fn type_name(&mut self) -> Result<Type, CError> {
        let at = self.token().clone();
        let Some(specs) = self.specifiers()? else {
            return Err(self.error_here(format!("expected a type, not {}", self.shown())));
        };
        if specs.typedef {
            return Err(CError {
                line: at.line,
                column: at.column,
                message: "typedef names no type here".to_string(),
            });
        }
        let (name, ops) = self.declarator(true)?;
        if let Some(name) = name {
            return Err(CError {
                line: at.line,
                column: at.column,
                message: format!("{name} is a name, not part of the type"),
            });
        }
        self.apply(specs.base, ops, &at)
    }

    // -----------------------------------------------------------------
    // Constant expressions.

    fn constant(&mut self) -> Result<i64, CError> {
        self.binary(0)
    }

    fn binary(&mut self, min: u8) -> Result<i64, CError> {
        let mut lhs = self.unary()?;
        while let Tok::Punct(op) = self.peek().clone() {
            let Some(prec) = precedence(op) else {
                break;
            };
            if prec < min {
                break;
            }
            let at = self.token().clone();
            self.advance();
            let rhs = self.binary(prec + 1)?;
            lhs = match op {
                "||" => i64::from(lhs != 0 || rhs != 0),
                "&&" => i64::from(lhs != 0 && rhs != 0),
                "|" => lhs | rhs,
                "^" => lhs ^ rhs,
                "&" => lhs & rhs,
                "==" => i64::from(lhs == rhs),
                "!=" => i64::from(lhs != rhs),
                "<" => i64::from(lhs < rhs),
                ">" => i64::from(lhs > rhs),
                "<=" => i64::from(lhs <= rhs),
                ">=" => i64::from(lhs >= rhs),
                "<<" => lhs.wrapping_shl(rhs as u32),
                ">>" => lhs.wrapping_shr(rhs as u32),
                "+" => lhs.wrapping_add(rhs),
                "-" => lhs.wrapping_sub(rhs),
                "*" => lhs.wrapping_mul(rhs),
                "/" | "%" => {
                    if rhs == 0 {
                        return Err(CError {
                            line: at.line,
                            column: at.column,
                            message: "the expression divides by zero".to_string(),
                        });
                    }
                    if op == "/" {
                        lhs.wrapping_div(rhs)
                    } else {
                        lhs.wrapping_rem(rhs)
                    }
                }
                _ => unreachable!("an operator with a precedence"),
            };
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<i64, CError> {
        if self.eat("-") {
            return Ok(self.unary()?.wrapping_neg());
        }
        if self.eat("+") {
            return self.unary();
        }
        if self.eat("~") {
            return Ok(!self.unary()?);
        }
        if self.eat("!") {
            return Ok(i64::from(self.unary()? == 0));
        }
        if self.is_word("sizeof")
            || self.is_word("_Alignof")
            || self.is_word("alignof")
            || self.is_word("__alignof__")
        {
            let size = self.is_word("sizeof");
            let at = self.token().clone();
            self.advance();
            self.expect("(", "after sizeof")?;
            let ty = self.type_name()?;
            self.expect(")", "after the type")?;
            let measured = if size {
                self.store.size_of(&ty)
            } else {
                self.store.align_of(&ty)
            };
            return measured.map(|n| n as i64).map_err(|why| CError {
                line: at.line,
                column: at.column,
                message: why,
            });
        }
        if self.is_punct("(") {
            // A cast, `(int)5`, or a parenthesized expression.
            if let Tok::Ident(word) = self.peek_at(1).clone() {
                if self.names_type(&word) {
                    self.advance();
                    self.type_name()?;
                    self.expect(")", "after the cast's type")?;
                    return self.unary();
                }
            }
            self.advance();
            let value = self.constant()?;
            self.expect(")", "after the expression")?;
            return Ok(value);
        }
        match self.peek().clone() {
            Tok::Number(n) => {
                self.advance();
                Ok(n as i64)
            }
            Tok::Ident(name) => {
                let value = self
                    .local_constants
                    .get(&name)
                    .copied()
                    .or_else(|| self.store.constant(&name).map(|(_, v)| v));
                match value {
                    Some(value) => {
                        self.advance();
                        Ok(value)
                    }
                    None => Err(self.error_here(format!("{name} is no constant the types define"))),
                }
            }
            _ => Err(self.error_here(format!("expected a constant, not {}", self.shown()))),
        }
    }
}

fn precedence(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | ">" | "<=" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    })
}

/// The primitive the basic type words name together, in any order: `long
/// unsigned int` is `unsigned long`.
fn basic(words: &[String]) -> Option<Prim> {
    let count = |w: &str| words.iter().filter(|x| *x == w).count();
    let (signed, unsigned) = (count("signed"), count("unsigned"));
    let (char_, short, int, long) = (count("char"), count("short"), count("int"), count("long"));
    let (void, float, double, bool_) = (
        count("void"),
        count("float"),
        count("double"),
        count("Bool"),
    );
    if signed + unsigned > 1 || char_ > 1 || short > 1 || int > 1 || long > 2 {
        return None;
    }
    let sign = signed + unsigned;
    let others = void + float + double + bool_;
    if others > 0 {
        return match (void, float, double, bool_, sign, char_ + short + int, long) {
            (1, 0, 0, 0, 0, 0, 0) => Some(Prim::Void),
            (0, 1, 0, 0, 0, 0, 0) => Some(Prim::Float),
            (0, 0, 1, 0, 0, 0, 0) => Some(Prim::Double),
            (0, 0, 1, 0, 0, 0, 1) => Some(Prim::LongDouble),
            (0, 0, 0, 1, 0, 0, 0) => Some(Prim::Bool),
            _ => None,
        };
    }
    if char_ == 1 {
        if short + int + long > 0 {
            return None;
        }
        return Some(match (signed, unsigned) {
            (1, _) => Prim::SChar,
            (_, 1) => Prim::UChar,
            _ => Prim::Char,
        });
    }
    if short == 1 {
        if long > 0 {
            return None;
        }
        return Some(if unsigned == 1 {
            Prim::UShort
        } else {
            Prim::Short
        });
    }
    Some(match (long, unsigned == 1) {
        (0, false) => Prim::Int,
        (0, true) => Prim::UInt,
        (1, false) => Prim::Long,
        (1, true) => Prim::ULong,
        (_, false) => Prim::LongLong,
        (_, true) => Prim::ULongLong,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DataModel;

    fn read(source: &str) -> (TypeStore, Parsed) {
        let mut store = TypeStore::new(DataModel::LP64);
        let parsed = parse_into(&mut store, source).unwrap_or_else(|e| panic!("{e}"));
        (store, parsed)
    }

    fn fails(source: &str) -> String {
        let mut store = TypeStore::new(DataModel::LP64);
        parse_into(&mut store, source).unwrap_err().to_string()
    }

    fn spelled(store: &TypeStore, key: &str) -> String {
        match store.get(key).unwrap() {
            Definition::Typedef(ty) => ty.spelled(store),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn each_kind_of_definition_is_read() {
        let (store, parsed) = read(
            "struct point { int x, y; };\n\
             union value { long i; double d; char bytes[8]; };\n\
             enum color { RED, GREEN, BLUE };\n\
             typedef unsigned long long u64;\n\
             typedef struct node { struct node *next; u64 key; } node_t, *node_p;",
        );
        let names: Vec<&str> = parsed
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["struct point", "union value", "enum color", "u64", "node_t"]
        );
        assert_eq!(
            parsed.declarations[4].names,
            ["struct node", "node_t", "node_p"]
        );
        assert_eq!(
            parsed.declarations[4].text,
            "typedef struct node { struct node *next; u64 key; } node_t, *node_p;"
        );
        assert_eq!(store.size_of(&Type::Named("struct point".into())), Ok(8));
        assert_eq!(store.size_of(&Type::Named("union value".into())), Ok(8));
        assert_eq!(store.size_of(&Type::Named("node_t".into())), Ok(16));
        assert_eq!(spelled(&store, "node_p"), "struct node *");
        assert_eq!(spelled(&store, "u64"), "unsigned long long");
        assert_eq!(store.constant("BLUE"), Some(("enum color", 2)));
        assert!(parsed.notes.is_empty(), "{:?}", parsed.notes);
    }

    #[test]
    fn function_pointer_typedefs_and_declarators_are_read() {
        let (store, _) = read(
            "typedef int (*cmp_t)(const void *, const void *);\n\
             typedef void (*handlers_t[4])(int, ...);\n\
             typedef char *(*getter_t)(void);\n\
             typedef int matrix_t[2][3];\n\
             typedef int (*row_t)[3];\n\
             typedef int fn_t(char *argv[], int (*cb)(long));",
        );
        assert_eq!(spelled(&store, "cmp_t"), "int (*)(void *, void *)");
        assert_eq!(spelled(&store, "handlers_t"), "void (*[4])(int, ...)");
        assert_eq!(spelled(&store, "getter_t"), "char *(*)(void)");
        assert_eq!(spelled(&store, "matrix_t"), "int[2][3]");
        assert_eq!(spelled(&store, "row_t"), "int (*)[3]");
        assert_eq!(spelled(&store, "fn_t"), "int(char **, int (*)(long))");
        assert_eq!(store.size_of(&Type::Named("matrix_t".into())), Ok(24));
        assert_eq!(store.size_of(&Type::Named("handlers_t".into())), Ok(32));
    }

    #[test]
    fn enumerators_take_constant_expressions() {
        let (store, _) = read(
            "enum flags { F_A = 1 << 0, F_B = 1 << 1, F_AB = F_A | F_B, F_C = (F_AB + 2) * 2, \
             F_MASK = ~0 & 0xff, F_NEG = -3, F_NEXT, F_CHAR = 'A', F_SIZE = sizeof(long) };\n\
             enum big { HUGE = 0x100000000 };\n\
             struct arr { char name[F_C]; int more[sizeof(struct arr *) / 2]; };",
        );
        let value = |name: &str| store.constant(name).unwrap().1;
        assert_eq!(value("F_AB"), 3);
        assert_eq!(value("F_C"), 10);
        assert_eq!(value("F_MASK"), 0xff);
        assert_eq!(value("F_NEG"), -3);
        assert_eq!(value("F_NEXT"), -2);
        assert_eq!(value("F_CHAR"), 65);
        assert_eq!(value("F_SIZE"), 8);
        assert_eq!(store.size_of(&Type::Named("enum big".into())), Ok(8));
        assert_eq!(store.size_of(&Type::Named("struct arr".into())), Ok(28));
    }

    #[test]
    fn anonymous_nested_and_forward_declared_types_are_read() {
        let (store, parsed) = read(
            "struct list;\n\
             typedef struct list list_t;\n\
             struct list { list_t *next; struct { int a; short b; } inner; \
             union { int i; float f; }; struct tail { char c; } tail; };\n\
             typedef struct { int x; } anon_t;",
        );
        let names: Vec<&str> = parsed
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, ["struct list", "list_t", "struct list", "anon_t"]);
        assert_eq!(parsed.declarations[2].names, ["struct tail", "struct list"]);
        let list = Type::Named("struct list".into());
        assert_eq!(store.size_of(&list), Ok(24));
        assert_eq!(store.member_type(&list, "i"), Some(Type::Prim(Prim::Int)));
        assert!(store.get("struct tail").is_some());
        // A completed declaration stands after what named it.
        assert_eq!(
            store.names(),
            ["list_t", "struct tail", "struct list", "anon_t"]
        );
        assert_eq!(
            store.definition_text("anon_t", false).unwrap(),
            "typedef struct {\n    int x;\n} anon_t;"
        );
    }

    #[test]
    fn a_recursive_type_is_read_through_pointers_and_refused_by_value() {
        let (store, _) = read("struct tree { struct tree *left, *right; int key; };");
        assert_eq!(store.size_of(&Type::Named("struct tree".into())), Ok(24));
        assert_eq!(
            fails("struct loop { int n; struct loop again; };"),
            "1:13: again of struct loop is not laid out: struct loop is incomplete"
        );
        assert_eq!(
            fails("struct a { struct b *b; };\nstruct b { struct a a; struct b inner; };"),
            "2:10: inner of struct b is not laid out: struct b is incomplete"
        );
    }

    #[test]
    fn bit_fields_and_pragmas_are_read() {
        let (store, parsed) = read(
            "#include <stdint.h>\n\
             #define N 4\n\
             #pragma pack(push, 1)\n\
             struct wire { uint8_t kind; uint32_t len; unsigned flags : 3, : 0, mode : 2; };\n\
             #pragma pack(pop)\n\
             struct loose { uint8_t kind; uint32_t len; };",
        );
        assert_eq!(store.size_of(&Type::Named("struct wire".into())), Ok(9));
        assert_eq!(store.size_of(&Type::Named("struct loose".into())), Ok(8));
        assert_eq!(
            parsed.notes,
            [
                "1:1: #include <stdint.h> is skipped: no macro is expanded and no file included",
                "2:1: #define N 4 is skipped: no macro is expanded and no file included",
            ]
        );
        assert_eq!(
            parsed.declarations[0].text,
            "#pragma pack(push, 1)\nstruct wire { uint8_t kind; uint32_t len; unsigned flags : 3, : 0, mode : 2; };\n#pragma pack(pop)"
        );
        // Read again, the text lays the structure out the same.
        let mut again = TypeStore::new(DataModel::LP64);
        parse_into(&mut again, &parsed.declarations[0].text).unwrap();
        assert_eq!(again.size_of(&Type::Named("struct wire".into())), Ok(9));
    }

    #[test]
    fn qualifiers_functions_and_variables_are_noted() {
        let (store, parsed) =
            read("typedef const char *name_t;\nint main(int argc, char **argv);\nint counter;");
        assert_eq!(spelled(&store, "name_t"), "char *");
        assert_eq!(
            parsed.notes,
            [
                "1:9: const, volatile and restrict are dropped: a type keeps no qualifiers",
                "2:5: main is a function, not a type: it is skipped",
                "3:5: counter is a variable, not a type: it is skipped",
            ]
        );
        let names: Vec<&str> = parsed
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, ["name_t"]);
    }

    #[test]
    fn errors_carry_their_line_and_column() {
        assert_eq!(
            fails("struct p { int x }"),
            "1:18: expected ; after the member, not }"
        );
        assert_eq!(
            fails("struct p { int x; };\nstruct p { int y; };"),
            "2:10: struct p is defined already"
        );
        assert_eq!(
            fails("typedef mystery_t thing;"),
            "1:9: expected a type, not mystery_t"
        );
        assert_eq!(
            fails("enum e { A = B };"),
            "1:14: B is no constant the types define"
        );
        assert_eq!(
            fails("struct s { int a[1/0]; };"),
            "1:19: the expression divides by zero"
        );
        assert_eq!(
            fails("struct s { char c : 9; };"),
            "1:10: c of struct s is 9 bits wide, wider than its 8 bits"
        );
        assert_eq!(fails("/* open"), "1:1: the comment is not closed");
        assert_eq!(
            fails("struct s { int f(void); };"),
            "1:16: f is a function: a member is a pointer to one"
        );
        assert_eq!(
            fails("#pragma pack(3)\n"),
            "1:1: 3 is no packing: 1, 2, 4, 8 or 16"
        );
        assert_eq!(
            fails("typedef int size_t;"),
            "1:13: size_t is a type of the platform already"
        );
    }

    #[test]
    fn one_type_is_read_as_a_variable_is_given_it() {
        let (store, _) = read("struct point { int x, y; };\ntypedef struct point point_t;");
        let text = |t: &str| {
            parse_type(&store, t)
                .map(|ty| ty.spelled(&store))
                .map_err(|e| e.to_string())
        };
        assert_eq!(text("struct point *"), Ok("struct point *".to_string()));
        assert_eq!(text("point_t*"), Ok("point_t *".to_string()));
        assert_eq!(
            text(" unsigned  int [ 0x4 ] "),
            Ok("unsigned int[4]".to_string())
        );
        assert_eq!(
            text("int (*)(char *, ...)"),
            Ok("int (*)(char *, ...)".to_string())
        );
        assert_eq!(text("long unsigned"), Ok("unsigned long".to_string()));
        // A name with no definition is a type of no known size.
        assert_eq!(text("struct other"), Ok("struct other".to_string()));
        assert_eq!(text("foo_t *"), Ok("foo_t *".to_string()));
        assert_eq!(
            text("int x"),
            Err("1:1: x is a name, not part of the type".to_string())
        );
        assert_eq!(
            text("struct q { int a; }"),
            Err("1:10: struct q is defined here: define it among the types first".to_string())
        );
        assert_eq!(declarator("char[16]", "buf"), "char buf[16]");
        assert_eq!(declarator("int (*)(int)", "cb"), "int (*cb)(int)");
        assert_eq!(declarator("struct point *", "p"), "struct point *p");
        assert_eq!(declarator("flags", "f"), "flags f");
    }

    #[test]
    fn definitions_are_added_replaced_and_removed_by_name() {
        let model = DataModel::LP64;
        let (defs, added, _) = add(
            model,
            &[],
            "struct point { int x, y; };\nstruct line { struct point a, b; };",
        )
        .unwrap();
        assert_eq!(added, ["struct point", "struct line"]);
        assert_eq!(defs[0].c, "struct point { int x, y; };");
        assert_eq!(
            add(model, &defs, "struct point { long x; };").unwrap_err(),
            "1:14: struct point is defined already"
        );
        // Taken away while another names it: refused, saying what does.
        assert_eq!(
            remove(
                model,
                &defs,
                "point",
                &[("f's p".to_string(), "struct point *".to_string())]
            )
            .unwrap_err(),
            "struct point is not removed: struct line and f's p refer to it"
        );
        let (defs, _) = replace(model, &defs, "point", "struct point { long x, y; };").unwrap();
        let (store, _) = build(model, &defs).unwrap();
        assert_eq!(store.size_of(&Type::Named("struct line".into())), Ok(32));
        let (defs, gone) = remove(model, &defs, "struct line", &[]).unwrap();
        assert_eq!(gone, "struct line");
        let (defs, _) = remove(model, &defs, "point", &[]).unwrap();
        assert!(defs.is_empty());
        // A forward declaration is completed in its place.
        let (defs, _, _) = add(model, &[], "struct n;\ntypedef struct n n_t;").unwrap();
        let (defs, _, _) = add(model, &defs, "struct n { n_t *next; };").unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["n_t", "struct n"]);
    }
}
