//! Swift names read back from the compiler's mangling.
//!
//! A Swift compiler encodes an entity's module, its context, its name, its
//! labels and its types into one symbol — `$s6sample7DerivedC5greet5timesS2i_tF`
//! for `sample.Derived.greet(times: Swift.Int) -> Swift.Int` — and the
//! metadata the runtime reads names types the same way, without the prefix.
//! This reads the scheme back the way the compiler's own demangler does: as
//! a stack machine over the mangled text, each operator taking what the
//! ones before it pushed. The grammar is the one shipped binaries use most:
//! entities (functions, variables and their accessors, initializers and
//! deinitializers, static members), nominal types, tuples, function types
//! with `throws` and `async`, optionals, arrays and dictionaries, bound
//! generic types, protocol lists, generic signatures with their
//! requirements, dependent member types, substitutions, the standard
//! library's shorthand, and the runtime's records (type metadata, nominal
//! type and protocol descriptors, witness tables, value witnesses, field
//! offsets, method and property descriptors, async function pointers). A
//! name past the grammar — a specialization, a key path, a closure's
//! context — demangles to nothing, and is shown as it is.
//!
//! Every name is read under a budget — of operators, of nodes a
//! substitution may copy, of nested types — so a crafted name costs no more
//! than a real one; past the budget it reads as nothing.

/// The name a Swift symbol spells, when it is one: a `$s` or `_$s` name
/// (`$S`, too, as Swift 5.0 wrote it). `None` for any other.
pub fn demangle(symbol: &str) -> Option<String> {
    let (body, suffix) = split(symbol)?;
    let node = Demangler::new(body).symbol()?;
    let mut text = node.print_global();
    if let Some(suffix) = suffix {
        text.push_str(&format!(" with unmangled suffix \"{suffix}\""));
    }
    Some(text)
}

/// The scope and the name of a Swift entity alone, as it stands in code:
/// `sample.Derived.greet` for the function above, `sample.Base.count.getter`
/// for an accessor. A record of the runtime's reads in full.
pub fn demangle_short(symbol: &str) -> Option<String> {
    let (body, _) = split(symbol)?;
    let node = Demangler::new(body).symbol()?;
    Some(node.print_short())
}

/// The type a mangled type name spells, as the runtime's metadata writes
/// them: `Si` for `Swift.Int`, `6sample5PointV` for `sample.Point`.
pub fn demangle_type(mangled: &str) -> Option<String> {
    let mut demangler = Demangler::new(mangled);
    demangler.run()?;
    let node = demangler.stack.pop()?;
    if !demangler.stack.is_empty() || !node.is_type() {
        return None;
    }
    Some(node.print())
}

/// Whether a name is a Swift symbol.
pub fn is_swift(symbol: &str) -> bool {
    split(symbol).is_some()
}

/// The body of a Swift symbol after its prefix, and the suffix the linker
/// or the optimizer appended past a `.`, kept as it is: `.resume.0` names a
/// coroutine's continuation.
fn split(symbol: &str) -> Option<(&str, Option<&str>)> {
    let rest = symbol
        .strip_prefix("_$s")
        .or_else(|| symbol.strip_prefix("$s"))
        .or_else(|| symbol.strip_prefix("_$S"))
        .or_else(|| symbol.strip_prefix("$S"))?;
    if rest.is_empty() {
        return None;
    }
    Some(match rest.find('.') {
        Some(dot) => (&rest[..dot], Some(&rest[dot..])),
        None => (rest, None),
    })
}

/// One node of the demangled tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Identifier(String),
    Module(String),
    /// A class, struct, enum, protocol or type alias: its context and name.
    Nominal {
        kind: NominalKind,
        context: Box<Node>,
        name: String,
    },
    /// A generic parameter: `A`, `B`, `A1`.
    GenericParam {
        depth: usize,
        index: usize,
    },
    /// A member type of a generic parameter: `A.Unit`.
    DependentMember {
        base: Box<Node>,
        name: String,
    },
    /// A tuple: each element a label, when it has one, and a type.
    Tuple(Vec<(Option<String>, Node)>),
    /// `(params) async throws -> result`.
    FunctionType {
        params: Box<Node>,
        result: Box<Node>,
        throws: bool,
        is_async: bool,
    },
    /// A type under a generic signature: `<A where A: P>`.
    GenericType {
        signature: Box<Node>,
        inner: Box<Node>,
    },
    GenericSignature {
        params: usize,
        requirements: Vec<Node>,
    },
    /// `A: P`, or `A: Base`.
    ConformanceRequirement {
        param: Box<Node>,
        protocol: Box<Node>,
    },
    /// `A == T`.
    SameTypeRequirement {
        param: Box<Node>,
        other: Box<Node>,
    },
    /// A protocol composition: `P & Q`, or `Any` when empty.
    ProtocolList(Vec<Node>),
    /// A type's metatype: `T.Type`.
    Metatype(Box<Node>),
    /// `inout T`.
    InOut(Box<Node>),
    /// `T?`, `[T]`, `[K : V]`, `Box<T>`.
    BoundGeneric {
        base: Box<Node>,
        args: Vec<Node>,
    },
    /// A function, with its labels when it has any.
    Function {
        context: Box<Node>,
        name: String,
        labels: Option<Vec<Option<String>>>,
        ty: Box<Node>,
    },
    Variable {
        context: Box<Node>,
        name: String,
        ty: Box<Node>,
    },
    /// `getter`, `setter`, `modify`, … of a variable.
    Accessor {
        kind: &'static str,
        variable: Box<Node>,
    },
    /// `init` and `__allocating_init`, with the labels and the type.
    Initializer {
        allocating: bool,
        context: Box<Node>,
        labels: Option<Vec<Option<String>>>,
        ty: Box<Node>,
    },
    /// `deinit` and `__deallocating_deinit`.
    Deinitializer {
        deallocating: bool,
        context: Box<Node>,
    },
    /// The initial-value expression of a variable.
    VariableInitializer(Box<Node>),
    Static(Box<Node>),
    /// A runtime record about an entity or a type: `type metadata for T`.
    Record {
        what: String,
        of: Box<Node>,
    },
    /// `T : P in M`.
    Conformance {
        ty: Box<Node>,
        protocol: Box<Node>,
        module: Box<Node>,
    },
    /// `protocol witness for E in conformance C`.
    ProtocolWitness {
        entity: Box<Node>,
        conformance: Box<Node>,
    },
    /// `<kind> value witness for T`.
    ValueWitness {
        kind: &'static str,
        ty: Box<Node>,
    },
    // Markers of the stack machine.
    EmptyList,
    FirstElementMarker,
    VariadicMarker,
    Throws,
    Async,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NominalKind {
    Class,
    Struct,
    Enum,
    Protocol,
    TypeAlias,
}

impl Node {
    fn is_entity(&self) -> bool {
        matches!(
            self,
            Node::Function { .. }
                | Node::Variable { .. }
                | Node::Accessor { .. }
                | Node::Initializer { .. }
                | Node::Deinitializer { .. }
                | Node::VariableInitializer(_)
                | Node::Static(_)
        )
    }

    fn is_context(&self) -> bool {
        matches!(self, Node::Module(_) | Node::Nominal { .. }) || self.is_entity()
    }

    fn is_type(&self) -> bool {
        matches!(
            self,
            Node::Nominal { .. }
                | Node::GenericParam { .. }
                | Node::DependentMember { .. }
                | Node::Tuple(_)
                | Node::FunctionType { .. }
                | Node::GenericType { .. }
                | Node::ProtocolList(_)
                | Node::Metatype(_)
                | Node::InOut(_)
                | Node::BoundGeneric { .. }
        )
    }

    fn is_protocol(&self) -> bool {
        matches!(
            self,
            Node::Nominal {
                kind: NominalKind::Protocol,
                ..
            }
        )
    }

    /// How many nodes the tree holds: what a substitution copies.
    fn size(&self) -> usize {
        1 + match self {
            Node::Identifier(_)
            | Node::Module(_)
            | Node::GenericParam { .. }
            | Node::EmptyList
            | Node::FirstElementMarker
            | Node::VariadicMarker
            | Node::Throws
            | Node::Async => 0,
            Node::Nominal { context, .. } => context.size(),
            Node::DependentMember { base, .. } => base.size(),
            Node::Tuple(elements) => elements.iter().map(|(_, ty)| ty.size()).sum(),
            Node::FunctionType { params, result, .. } => params.size() + result.size(),
            Node::GenericType { signature, inner } => signature.size() + inner.size(),
            Node::GenericSignature { requirements, .. } => {
                requirements.iter().map(Node::size).sum()
            }
            Node::ConformanceRequirement { param, protocol } => param.size() + protocol.size(),
            Node::SameTypeRequirement { param, other } => param.size() + other.size(),
            Node::ProtocolList(protocols) => protocols.iter().map(Node::size).sum(),
            Node::Metatype(ty) | Node::InOut(ty) => ty.size(),
            Node::BoundGeneric { base, args } => {
                base.size() + args.iter().map(Node::size).sum::<usize>()
            }
            Node::Function { context, ty, .. } | Node::Variable { context, ty, .. } => {
                context.size() + ty.size()
            }
            Node::Accessor { variable, .. } => variable.size(),
            Node::Initializer { context, ty, .. } => context.size() + ty.size(),
            Node::Deinitializer { context, .. } => context.size(),
            Node::VariableInitializer(inner) | Node::Static(inner) => inner.size(),
            Node::Record { of, .. } => of.size(),
            Node::Conformance {
                ty,
                protocol,
                module,
            } => ty.size() + protocol.size() + module.size(),
            Node::ProtocolWitness {
                entity,
                conformance,
            } => entity.size() + conformance.size(),
            Node::ValueWitness { ty, .. } => ty.size(),
        }
    }

    /// The text of a whole symbol.
    fn print_global(&self) -> String {
        self.print()
    }

    /// The scope and the name alone, for an entity; the full text for the
    /// rest.
    fn print_short(&self) -> String {
        match self {
            Node::Function { context, name, .. } | Node::Variable { context, name, .. } => {
                format!("{}.{name}", context.print())
            }
            Node::Accessor { kind, variable } => format!("{}.{kind}", variable.print_short()),
            Node::Initializer {
                allocating,
                context,
                ..
            } => format!(
                "{}.{}",
                context.print(),
                initializer_name(*allocating, context)
            ),
            Node::Static(entity) => format!("static {}", entity.print_short()),
            other => other.print(),
        }
    }

    /// The text of the node.
    fn print(&self) -> String {
        match self {
            Node::Identifier(name) | Node::Module(name) => name.clone(),
            Node::Nominal { context, name, .. } => format!("{}.{name}", context.print()),
            Node::GenericParam { depth, index } => generic_param_name(*depth, *index),
            Node::DependentMember { base, name } => format!("{}.{name}", base.print()),
            Node::Tuple(elements) => {
                let parts: Vec<String> = elements
                    .iter()
                    .map(|(label, ty)| match label {
                        Some(label) => format!("{label}: {}", ty.print()),
                        None => ty.print(),
                    })
                    .collect();
                format!("({})", parts.join(", "))
            }
            Node::FunctionType {
                params,
                result,
                throws,
                is_async,
            } => format!(
                "{}{}{} -> {}",
                print_params(params, None),
                if *is_async { " async" } else { "" },
                if *throws { " throws" } else { "" },
                result.print()
            ),
            Node::GenericType { signature, inner } => {
                format!("{}{}", signature.print(), inner.print())
            }
            Node::GenericSignature {
                params,
                requirements,
            } => {
                let names: Vec<String> = (0..*params).map(|i| generic_param_name(0, i)).collect();
                let mut text = format!("<{}", names.join(", "));
                if !requirements.is_empty() {
                    let reqs: Vec<String> = requirements.iter().map(Node::print).collect();
                    text.push_str(&format!(" where {}", reqs.join(", ")));
                }
                text.push('>');
                text
            }
            Node::ConformanceRequirement { param, protocol } => {
                format!("{}: {}", param.print(), protocol.print())
            }
            Node::SameTypeRequirement { param, other } => {
                format!("{} == {}", param.print(), other.print())
            }
            Node::ProtocolList(protocols) => {
                if protocols.is_empty() {
                    "Any".to_string()
                } else {
                    protocols
                        .iter()
                        .map(Node::print)
                        .collect::<Vec<_>>()
                        .join(" & ")
                }
            }
            Node::Metatype(ty) => format!("{}.Type", ty.print()),
            Node::InOut(ty) => format!("inout {}", ty.print()),
            Node::BoundGeneric { base, args } => {
                let args: Vec<String> = args.iter().map(Node::print).collect();
                let standard = |name: &str| match base.as_ref() {
                    Node::Nominal {
                        name: own, context, ..
                    } => own == name && context.print() == "Swift",
                    _ => false,
                };
                match args.as_slice() {
                    [arg] if standard("Optional") => format!("{arg}?"),
                    [arg] if standard("Array") => format!("[{arg}]"),
                    [key, value] if standard("Dictionary") => format!("[{key} : {value}]"),
                    _ => format!("{}<{}>", base.print(), args.join(", ")),
                }
            }
            Node::Function {
                context,
                name,
                labels,
                ty,
            } => {
                let (signature, fn_type) = split_generic(ty);
                match fn_type {
                    Node::FunctionType {
                        params,
                        result,
                        throws,
                        is_async,
                    } => format!(
                        "{}.{name}{signature}{}{}{} -> {}",
                        context.print(),
                        print_params(params, labels.as_deref()),
                        if *is_async { " async" } else { "" },
                        if *throws { " throws" } else { "" },
                        result.print()
                    ),
                    other => format!("{}.{name}{signature} : {}", context.print(), other.print()),
                }
            }
            Node::Variable { context, name, ty } => {
                format!("{}.{name} : {}", context.print(), ty.print())
            }
            Node::Accessor { kind, variable } => match variable.as_ref() {
                Node::Variable { context, name, ty } => {
                    format!("{}.{name}.{kind} : {}", context.print(), ty.print())
                }
                other => format!("{}.{kind}", other.print()),
            },
            Node::Initializer {
                allocating,
                context,
                labels,
                ty,
            } => {
                let name = initializer_name(*allocating, context);
                let (signature, fn_type) = split_generic(ty);
                match fn_type {
                    Node::FunctionType {
                        params,
                        result,
                        throws,
                        is_async,
                    } => format!(
                        "{}.{name}{signature}{}{}{} -> {}",
                        context.print(),
                        print_params(params, labels.as_deref()),
                        if *is_async { " async" } else { "" },
                        if *throws { " throws" } else { "" },
                        result.print()
                    ),
                    other => format!("{}.{name}{signature} : {}", context.print(), other.print()),
                }
            }
            Node::Deinitializer {
                deallocating,
                context,
            } => format!(
                "{}.{}",
                context.print(),
                if *deallocating {
                    "__deallocating_deinit"
                } else {
                    "deinit"
                }
            ),
            Node::VariableInitializer(variable) => {
                format!("variable initialization expression of {}", variable.print())
            }
            Node::Static(entity) => format!("static {}", entity.print()),
            Node::Record { what, of } => format!("{what}{}", of.print()),
            Node::Conformance {
                ty,
                protocol,
                module,
            } => format!(
                "{} : {} in {}",
                ty.print(),
                protocol.print(),
                module.print()
            ),
            Node::ProtocolWitness {
                entity,
                conformance,
            } => format!(
                "protocol witness for {} in conformance {}",
                entity.print(),
                conformance.print()
            ),
            Node::ValueWitness { kind, ty } => format!("{kind} value witness for {}", ty.print()),
            Node::EmptyList => "()".to_string(),
            Node::FirstElementMarker | Node::VariadicMarker | Node::Throws | Node::Async => {
                String::new()
            }
        }
    }
}

/// `__allocating_init` for a class; `init` for the rest, which allocate
/// nothing.
fn initializer_name(allocating: bool, context: &Node) -> &'static str {
    let is_class = matches!(
        context,
        Node::Nominal {
            kind: NominalKind::Class,
            ..
        }
    );
    if allocating && is_class {
        "__allocating_init"
    } else {
        "init"
    }
}

/// A generic parameter's name: `A`, `B`, …, `Z`, `AB`, …, with the depth
/// after it past the first: `A1`.
fn generic_param_name(depth: usize, index: usize) -> String {
    let mut name = String::new();
    let mut index = index;
    loop {
        name.push((b'A' + (index % 26) as u8) as char);
        index /= 26;
        if index == 0 {
            break;
        }
    }
    if depth > 0 {
        name.push_str(&depth.to_string());
    }
    name
}

/// A type under its generic signature, split: the signature's text (empty
/// without one) and the type.
fn split_generic(ty: &Node) -> (String, &Node) {
    match ty {
        Node::GenericType { signature, inner } => (signature.print(), inner.as_ref()),
        other => (String::new(), other),
    }
}

/// The parameters of a function, labelled when the labels are given:
/// `(times: Swift.Int)`, `(_: (Swift.Int) -> Swift.Int, to: Swift.Int)`,
/// `(Swift.Int)`.
fn print_params(params: &Node, labels: Option<&[Option<String>]>) -> String {
    let elements: Vec<(Option<String>, Node)> = match params {
        Node::Tuple(elements) => elements.clone(),
        Node::EmptyList => Vec::new(),
        other => vec![(None, other.clone())],
    };
    let parts: Vec<String> = elements
        .iter()
        .enumerate()
        .map(|(index, (own_label, ty))| {
            let label = labels
                .and_then(|labels| labels.get(index))
                .map(|label| label.clone().unwrap_or_else(|| "_".to_string()))
                .or_else(|| own_label.clone());
            match label {
                Some(label) => format!("{label}: {}", ty.print()),
                None => ty.print(),
            }
        })
        .collect();
    format!("({})", parts.join(", "))
}

/// The stack machine over one mangled name.
struct Demangler<'a> {
    text: &'a [u8],
    pos: usize,
    stack: Vec<Node>,
    substitutions: Vec<Node>,
    words: Vec<String>,
    /// Operators read: a bound on a crafted name.
    steps: usize,
    /// Nodes made or copied: a bound on what substitutions may multiply.
    nodes: usize,
    /// Types wrapped in another — tuples, functions, pointers, bound
    /// generics: a bound on the depth of the tree.
    wraps: usize,
}

/// No real name has more operators.
const MOST_STEPS: usize = 4096;
/// No real name builds a larger tree.
const MOST_NODES: usize = 1 << 16;
/// No real name nests types deeper.
const MOST_WRAPS: usize = 256;
/// No real name has more words to substitute.
const MOST_WORDS: usize = 26;

impl<'a> Demangler<'a> {
    fn new(text: &'a str) -> Self {
        Demangler {
            text: text.as_bytes(),
            pos: 0,
            stack: Vec::new(),
            substitutions: Vec::new(),
            words: Vec::new(),
            steps: 0,
            nodes: 0,
            wraps: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn next_if(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn done(&self) -> bool {
        self.pos >= self.text.len()
    }

    fn push(&mut self, node: Node) {
        self.stack.push(node);
    }

    fn pop(&mut self) -> Option<Node> {
        self.stack.pop()
    }

    /// Pop the top node when `want` accepts it.
    fn pop_if(&mut self, want: impl Fn(&Node) -> bool) -> Option<Node> {
        if self.stack.last().is_some_and(want) {
            self.stack.pop()
        } else {
            None
        }
    }

    /// Count a type wrapped in another; `None` past the bound.
    fn wrap(&mut self) -> Option<()> {
        self.wraps += 1;
        (self.wraps <= MOST_WRAPS).then_some(())
    }

    /// Count `count` nodes made or copied; `None` past the bound.
    fn charge(&mut self, count: usize) -> Option<()> {
        self.nodes = self.nodes.checked_add(count)?;
        (self.nodes <= MOST_NODES).then_some(())
    }

    /// Remember a node for `A` substitutions later.
    fn remember(&mut self, node: &Node) {
        self.substitutions.push(node.clone());
    }

    /// A whole symbol: every operator, leaving one entity or type.
    fn symbol(&mut self) -> Option<Node> {
        self.run()?;
        let node = self.pop()?;
        // An identifier alone names nothing; a leftover below means the
        // grammar was not understood.
        if !self.stack.is_empty() || matches!(node, Node::Identifier(_)) {
            return None;
        }
        Some(node)
    }

    /// Every operator of the text, pushing what each makes.
    fn run(&mut self) -> Option<()> {
        while !self.done() {
            self.steps += 1;
            if self.steps > MOST_STEPS {
                return None;
            }
            self.charge(1)?;
            let node = self.operator()?;
            self.push(node);
        }
        Some(())
    }

    /// A natural number, when the text has one here.
    fn natural(&mut self) -> Option<usize> {
        let start = self.pos;
        let mut value: usize = 0;
        while let Some(c) = self.peek().filter(u8::is_ascii_digit) {
            value = value.checked_mul(10)?.checked_add((c - b'0') as usize)?;
            self.pos += 1;
        }
        (self.pos > start).then_some(value)
    }

    /// An index: `_` is 0, `<n>_` is n + 1.
    fn index(&mut self) -> Option<usize> {
        if self.next_if(b'_') {
            return Some(0);
        }
        let n = self.natural()?;
        if !self.next_if(b'_') {
            return None;
        }
        n.checked_add(1)
    }

    /// One operator and what it makes.
    fn operator(&mut self) -> Option<Node> {
        let c = self.next()?;
        match c {
            b'0'..=b'9' => {
                self.pos -= 1;
                self.identifier()
            }
            b'A' => self.substitutions(),
            b'C' => self.nominal(NominalKind::Class),
            b'V' => self.nominal(NominalKind::Struct),
            b'O' => self.nominal(NominalKind::Enum),
            b'P' => self.nominal(NominalKind::Protocol),
            b'a' => self.nominal(NominalKind::TypeAlias),
            b'S' => self.standard(),
            b's' => Some(Node::Module("Swift".to_string())),
            b'y' => Some(Node::EmptyList),
            b'_' => Some(Node::FirstElementMarker),
            b'd' => Some(Node::VariadicMarker),
            b'K' => Some(Node::Throws),
            b't' => self.tuple(),
            b'c' => self.function_type(),
            b'X' => self.special_type(),
            b'Y' => self.async_type(),
            b'x' => Some(Node::GenericParam { depth: 0, index: 0 }),
            b'q' => self
                .generic_param_index()
                .map(|(depth, index)| Node::GenericParam { depth, index }),
            b'Q' => self.archetype(),
            b'z' => {
                self.wrap()?;
                let ty = self.pop_if(Node::is_type)?;
                Some(Node::InOut(Box::new(ty)))
            }
            b'm' => {
                self.wrap()?;
                let ty = self.pop_if(Node::is_type)?;
                Some(Node::Metatype(Box::new(ty)))
            }
            b'p' => self.protocol_list(),
            b'G' => self.bound_generic(),
            b'R' => self.requirement(),
            b'l' => self.generic_signature(false),
            b'r' => self.generic_signature(true),
            b'F' => self.plain_function(),
            b'v' => self.variable(),
            b'f' => self.function_entity(),
            b'Z' => {
                let entity = self.pop_if(Node::is_entity)?;
                Some(Node::Static(Box::new(entity)))
            }
            b'M' => self.metatype_record(),
            b'N' => {
                let ty = self.pop_if(Node::is_type)?;
                Some(record("type metadata for ", ty))
            }
            b'W' => self.witness(),
            b'w' => self.value_witness(),
            b'T' => self.thunk(),
            _ => None,
        }
    }

    /// An identifier: its length and its text, with the words of earlier
    /// identifiers substituted where it says so.
    fn identifier(&mut self) -> Option<Node> {
        let mut has_word_substitutions = false;
        let mut punycoded = false;
        if self.peek() == Some(b'0') {
            self.pos += 1;
            if self.peek() == Some(b'0') {
                self.pos += 1;
                punycoded = true;
            } else {
                has_word_substitutions = true;
            }
        }
        let mut identifier = String::new();
        loop {
            while has_word_substitutions && self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
                let c = self.next()?;
                let index = if c.is_ascii_lowercase() {
                    (c - b'a') as usize
                } else {
                    has_word_substitutions = false;
                    (c - b'A') as usize
                };
                identifier.push_str(self.words.get(index)?);
            }
            if self.next_if(b'0') {
                break;
            }
            let count = self.natural()?;
            if count == 0 {
                return None;
            }
            if punycoded {
                self.next_if(b'_');
            }
            let end = self.pos.checked_add(count)?;
            let slice = self.text.get(self.pos..end)?;
            let slice = std::str::from_utf8(slice).ok()?;
            // Punycode is not decoded; such a name keeps its coded form.
            identifier.push_str(slice);
            if !punycoded {
                self.note_words(slice);
            }
            self.pos = end;
            if !has_word_substitutions {
                break;
            }
        }
        if identifier.is_empty() {
            return None;
        }
        let node = Node::Identifier(identifier);
        self.remember(&node);
        Some(node)
    }

    /// Remember the words of an identifier, for the ones after it.
    fn note_words(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let mut word_start: Option<usize> = None;
        for index in 0..=bytes.len() {
            let c = bytes.get(index).copied();
            if let Some(start) = word_start {
                let previous = bytes[index - 1];
                let ends = match c {
                    None | Some(b'_') => true,
                    Some(c) => !previous.is_ascii_uppercase() && c.is_ascii_uppercase(),
                };
                if ends {
                    if index - start >= 2 && self.words.len() < MOST_WORDS {
                        self.words.push(text[start..index].to_string());
                    }
                    word_start = None;
                }
            }
            if word_start.is_none() {
                if let Some(c) = c {
                    if !c.is_ascii_digit() && c != b'_' {
                        word_start = Some(index);
                    }
                }
            }
        }
    }

    /// `A` and what follows: substitutions of earlier nodes, several at
    /// once in lower case, each repeated as many times as the number before
    /// it says, the last in upper case; `_` after a number is an index past
    /// the letters.
    fn substitutions(&mut self) -> Option<Node> {
        let mut repeat: Option<usize> = None;
        loop {
            let c = self.next()?;
            if c.is_ascii_lowercase() {
                let node = self.substitution(repeat, (c - b'a') as usize)?;
                self.push(node);
                repeat = None;
                continue;
            }
            if c.is_ascii_uppercase() {
                return self.substitution(repeat, (c - b'A') as usize);
            }
            if c == b'_' {
                let index = match repeat {
                    Some(repeat) => repeat.checked_add(27)?,
                    None => 26,
                };
                return self.substitution(None, index);
            }
            self.pos -= 1;
            repeat = Some(self.natural()?);
        }
    }

    /// Substitution `index`, pushed `repeat - 1` times and returned once;
    /// every copy counts against the budget of nodes.
    fn substitution(&mut self, repeat: Option<usize>, index: usize) -> Option<Node> {
        let node = self.substitutions.get(index)?.clone();
        let copies = repeat.unwrap_or(1).max(1);
        self.charge(node.size().checked_mul(copies)?)?;
        for _ in 1..copies {
            self.push(node.clone());
        }
        Some(node)
    }

    /// A nominal type: its name, then its context.
    fn nominal(&mut self, kind: NominalKind) -> Option<Node> {
        let name = match self.pop()? {
            Node::Identifier(name) => name,
            _ => return None,
        };
        let context = self.context()?;
        let node = Node::Nominal {
            kind,
            context: Box::new(context),
            name,
        };
        self.remember(&node);
        Some(node)
    }

    /// The context on top of the stack: a module (an identifier alone is
    /// one), a type or an entity.
    fn context(&mut self) -> Option<Node> {
        match self.pop()? {
            Node::Identifier(name) => Some(Node::Module(name)),
            node if node.is_context() => Some(node),
            _ => None,
        }
    }

    /// `S` and a letter: a standard library type or protocol — or a count
    /// and a letter, that many of it; `Sg` the optional of the type below.
    fn standard(&mut self) -> Option<Node> {
        let repeat = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.natural()?
        } else {
            1
        };
        if repeat == 0 || repeat > MOST_STEPS {
            return None;
        }
        let c = self.next()?;
        let node = match c {
            b'o' => Node::Module("__C".to_string()),
            b'C' => Node::Module("__C_Synthesized".to_string()),
            b'g' => {
                self.wrap()?;
                let ty = self.pop_if(Node::is_type)?;
                let node = Node::BoundGeneric {
                    base: Box::new(standard_nominal(NominalKind::Enum, "Optional")),
                    args: vec![ty],
                };
                self.remember(&node);
                node
            }
            _ => {
                let (kind, name) = standard_type(c)?;
                standard_nominal(kind, name)
            }
        };
        self.charge(node.size().checked_mul(repeat)?)?;
        for _ in 1..repeat {
            self.push(node.clone());
        }
        Some(node)
    }

    /// `t`: a tuple of the elements down to the first-element marker, or
    /// of none.
    fn tuple(&mut self) -> Option<Node> {
        self.wrap()?;
        let mut elements = Vec::new();
        if self
            .pop_if(|node| matches!(node, Node::EmptyList))
            .is_none()
        {
            loop {
                let first = self
                    .pop_if(|node| matches!(node, Node::FirstElementMarker))
                    .is_some();
                let _variadic = self.pop_if(|node| matches!(node, Node::VariadicMarker));
                // An element's own label, when the tuple names one, comes
                // after its type in the text, so it is on top.
                let label = match self.pop_if(|node| matches!(node, Node::Identifier(_))) {
                    Some(Node::Identifier(name)) => Some(name),
                    _ => None,
                };
                let ty = self.pop_if(Node::is_type)?;
                elements.push((label, ty));
                if first {
                    break;
                }
            }
            elements.reverse();
        }
        Some(Node::Tuple(elements))
    }

    /// A function type: its `throws` and `async` marks on top, then the
    /// parameters, then the result under them.
    fn function_type(&mut self) -> Option<Node> {
        self.wrap()?;
        let throws = self.pop_if(|node| matches!(node, Node::Throws)).is_some();
        let is_async = self.pop_if(|node| matches!(node, Node::Async)).is_some();
        let params = self.function_params()?;
        let result = self.function_params()?;
        Some(Node::FunctionType {
            params: Box::new(params),
            result: Box::new(result),
            throws,
            is_async,
        })
    }

    /// One side of a function type: an empty list, or a type.
    fn function_params(&mut self) -> Option<Node> {
        if self
            .pop_if(|node| matches!(node, Node::EmptyList))
            .is_some()
        {
            return Some(Node::Tuple(Vec::new()));
        }
        self.pop_if(Node::is_type)
    }

    /// `X` and a letter: the special types — the function kinds among them,
    /// and `AnyObject`.
    fn special_type(&mut self) -> Option<Node> {
        match self.next()? {
            // A function type that does not escape, a block, a C function,
            // an autoclosure, a thin function: all read as function types.
            b'E' | b'B' | b'C' | b'A' | b'K' | b'f' | b'L' | b'U' => self.function_type(),
            b'l' => Some(standard_nominal(NominalKind::Protocol, "AnyObject")),
            b'M' => {
                // `XM` and a letter: a metatype with a representation.
                self.next()?;
                self.wrap()?;
                let ty = self.pop_if(Node::is_type)?;
                Some(Node::Metatype(Box::new(ty)))
            }
            b'p' => {
                // An existential metatype.
                self.wrap()?;
                let ty = self.pop_if(Node::is_type)?;
                Some(Node::Metatype(Box::new(ty)))
            }
            _ => None,
        }
    }

    /// `Y` and a letter: the marks of a function type — `async` among them.
    fn async_type(&mut self) -> Option<Node> {
        match self.next()? {
            b'a' => Some(Node::Async),
            _ => None,
        }
    }

    /// A generic parameter's depth and index, after `q`: `z` is the first,
    /// `d` says the depth, an index alone is at depth 0.
    fn generic_param_index(&mut self) -> Option<(usize, usize)> {
        if self.next_if(b'd') {
            let depth = self.index()?.checked_add(1)?;
            let index = self.index()?;
            Some((depth, index))
        } else if self.next_if(b'z') {
            Some((0, 0))
        } else {
            let index = self.index()?.checked_add(1)?;
            Some((0, index))
        }
    }

    /// `Q` and a letter: a member type of a generic parameter — `Qz` of the
    /// first, `Qy` and an index of another — named by the identifier on top.
    fn archetype(&mut self) -> Option<Node> {
        let (depth, index) = match self.next()? {
            b'z' => (0, 0),
            b'y' => (0, self.index()?.checked_add(1)?),
            b'd' => {
                let depth = self.index()?.checked_add(1)?;
                (depth, self.index()?)
            }
            _ => return None,
        };
        let name = self.assoc_type_name()?;
        let node = Node::DependentMember {
            base: Box::new(Node::GenericParam { depth, index }),
            name,
        };
        self.remember(&node);
        Some(node)
    }

    /// An associated type's name: an identifier, under a protocol when the
    /// name says which.
    fn assoc_type_name(&mut self) -> Option<String> {
        let _protocol = self.pop_if(Node::is_protocol);
        match self.pop()? {
            Node::Identifier(name) => Some(name),
            _ => None,
        }
    }

    /// `p`: a protocol list type from the protocols down to the marker.
    fn protocol_list(&mut self) -> Option<Node> {
        self.wrap()?;
        let mut protocols = Vec::new();
        if self
            .pop_if(|node| matches!(node, Node::EmptyList))
            .is_none()
        {
            loop {
                let first = self
                    .pop_if(|node| matches!(node, Node::FirstElementMarker))
                    .is_some();
                protocols.push(self.protocol()?);
                if first {
                    break;
                }
            }
            protocols.reverse();
        }
        Some(Node::ProtocolList(protocols))
    }

    /// A protocol on the stack: a protocol type, or an identifier and its
    /// context, as a conformance names one.
    fn protocol(&mut self) -> Option<Node> {
        match self.pop()? {
            node if node.is_protocol() => Some(node),
            Node::ProtocolList(mut list) if list.len() == 1 => list.pop(),
            Node::Identifier(name) => {
                let context = self.context()?;
                Some(Node::Nominal {
                    kind: NominalKind::Protocol,
                    context: Box::new(context),
                    name,
                })
            }
            _ => None,
        }
    }

    /// `G`: a generic type bound to the arguments above its marker: the
    /// types down to the empty-list marker that opens them, or to a
    /// first-element marker between the levels of a nested context.
    fn bound_generic(&mut self) -> Option<Node> {
        self.wrap()?;
        let mut args = Vec::new();
        loop {
            let mut level = Vec::new();
            while let Some(ty) = self.pop_if(Node::is_type) {
                level.push(ty);
            }
            level.reverse();
            args.splice(0..0, level);
            if self
                .pop_if(|node| matches!(node, Node::EmptyList))
                .is_some()
            {
                break;
            }
            self.pop_if(|node| matches!(node, Node::FirstElementMarker))?;
        }
        let base = self.pop_if(Node::is_type)?;
        let node = Node::BoundGeneric {
            base: Box::new(base),
            args,
        };
        self.remember(&node);
        Some(node)
    }

    /// `R` and a letter: a requirement of a generic signature — on a
    /// generic parameter (the letter's lower case), a type on the stack
    /// (`Q`, `S`, `B`, `L`) or a member type (`p`, `t`, `c`, `m`): that it
    /// conforms to a protocol, has a superclass, or equals a type.
    fn requirement(&mut self) -> Option<Node> {
        let c = self.peek()?;
        // (what is constrained, the kind of constraint)
        let (subject, constraint) = match c {
            b'p' => ('a', ':'),
            b'Q' => ('s', ':'),
            b'b' => ('g', 'b'),
            b'B' => ('s', 'b'),
            b'c' => ('a', 'b'),
            b's' => ('g', '='),
            b'S' => ('s', '='),
            b't' => ('a', '='),
            b'l' => ('g', 'l'),
            b'L' => ('s', 'l'),
            b'm' => ('a', 'l'),
            // The compound member-type forms are past the grammar.
            b'P' | b'C' | b'T' | b'M' => return None,
            _ => ('g', ':'),
        };
        if subject != 'g' || constraint != ':' {
            self.pos += 1;
        }
        let param = match subject {
            'g' => {
                let (depth, index) = self.generic_param_index()?;
                Node::GenericParam { depth, index }
            }
            's' => self.pop_if(Node::is_type)?,
            _ => {
                let (depth, index) = self.generic_param_index()?;
                let name = self.assoc_type_name()?;
                Node::DependentMember {
                    base: Box::new(Node::GenericParam { depth, index }),
                    name,
                }
            }
        };
        match constraint {
            ':' => {
                let protocol = self.protocol()?;
                Some(Node::ConformanceRequirement {
                    param: Box::new(param),
                    protocol: Box::new(protocol),
                })
            }
            'b' => {
                let superclass = self.pop_if(Node::is_type)?;
                Some(Node::ConformanceRequirement {
                    param: Box::new(param),
                    protocol: Box::new(superclass),
                })
            }
            '=' => {
                let other = self.pop_if(Node::is_type)?;
                Some(Node::SameTypeRequirement {
                    param: Box::new(param),
                    other: Box::new(other),
                })
            }
            _ => {
                // A layout constraint: only the class one reads as a type.
                match self.next()? {
                    b'C' => Some(Node::ConformanceRequirement {
                        param: Box::new(param),
                        protocol: Box::new(standard_nominal(NominalKind::Protocol, "AnyObject")),
                    }),
                    _ => None,
                }
            }
        }
    }

    /// `l` or `r`: a generic signature from the requirements on the stack,
    /// with its parameter counts, one per depth, after `r` up to `l`.
    fn generic_signature(&mut self, has_counts: bool) -> Option<Node> {
        let mut requirements = Vec::new();
        while let Some(requirement) = self.pop_if(|node| {
            matches!(
                node,
                Node::ConformanceRequirement { .. } | Node::SameTypeRequirement { .. }
            )
        }) {
            requirements.push(requirement);
        }
        requirements.reverse();
        let params = if has_counts {
            let mut params = 0;
            let mut depths = 0;
            while !self.next_if(b'l') {
                depths += 1;
                if depths > MOST_WRAPS {
                    return None;
                }
                params = if self.next_if(b'z') {
                    0
                } else {
                    self.index()?.checked_add(1)?
                };
            }
            params
        } else {
            1
        };
        Some(Node::GenericSignature {
            params,
            requirements,
        })
    }

    /// The labels of a function's parameters, as many as the type has: an
    /// empty list for none, else one identifier or marker each.
    fn labels(&mut self, ty: &Node) -> Option<Option<Vec<Option<String>>>> {
        if self
            .pop_if(|node| matches!(node, Node::EmptyList))
            .is_some()
        {
            return Some(Some(Vec::new()));
        }
        let (_, fn_type) = split_generic(ty);
        let Node::FunctionType { params, .. } = fn_type else {
            return Some(None);
        };
        let count = match params.as_ref() {
            Node::Tuple(elements) => elements.len(),
            _ => 1,
        };
        if count == 0 {
            return Some(None);
        }
        let mut labels = Vec::with_capacity(count);
        for _ in 0..count {
            match self.pop()? {
                Node::Identifier(name) => labels.push(Some(name)),
                Node::FirstElementMarker => labels.push(None),
                _ => return None,
            }
        }
        labels.reverse();
        Some(Some(labels))
    }

    /// A type under the generic signature on the stack, when there is one.
    fn under_signature(&mut self, ty: Node) -> Option<Node> {
        match self.pop_if(|node| matches!(node, Node::GenericSignature { .. })) {
            Some(signature) => {
                self.wrap()?;
                Some(Node::GenericType {
                    signature: Box::new(signature),
                    inner: Box::new(ty),
                })
            }
            None => Some(ty),
        }
    }

    /// `F`: a function — its type, its labels, its name, its context.
    fn plain_function(&mut self) -> Option<Node> {
        let signature = self.pop_if(|node| matches!(node, Node::GenericSignature { .. }));
        let mut ty = self.function_type()?;
        if let Some(signature) = signature {
            self.wrap()?;
            ty = Node::GenericType {
                signature: Box::new(signature),
                inner: Box::new(ty),
            };
        }
        let labels = self.labels(&ty)?;
        let name = match self.pop()? {
            Node::Identifier(name) => name,
            _ => return None,
        };
        let context = self.context()?;
        Some(Node::Function {
            context: Box::new(context),
            name,
            labels,
            ty: Box::new(ty),
        })
    }

    /// `v` and a letter: a variable, and the accessor the letter names.
    fn variable(&mut self) -> Option<Node> {
        let ty = self.pop_if(Node::is_type)?;
        let ty = self.under_signature(ty)?;
        // A variable has no labels, yet the compiler writes an empty label
        // list before some: a protocol requirement's, for one.
        let _labels = self.pop_if(|node| matches!(node, Node::EmptyList));
        let name = match self.pop()? {
            Node::Identifier(name) => name,
            _ => return None,
        };
        let context = self.context()?;
        let variable = Node::Variable {
            context: Box::new(context),
            name,
            ty: Box::new(ty),
        };
        let kind = match self.next()? {
            b'p' => return Some(variable),
            b'g' => "getter",
            b's' => "setter",
            b'M' => "modify",
            b'r' => "read",
            b'm' => "materializeForSet",
            b'w' => "willset",
            b'W' => "didset",
            b'G' => "unsafeAddressor",
            b'a' => "unsafeMutableAddressor",
            b'l' => "modify",
            _ => return None,
        };
        Some(Node::Accessor {
            kind,
            variable: Box::new(variable),
        })
    }

    /// `f` and a letter: an initializer, a deinitializer, a variable's
    /// initial value.
    fn function_entity(&mut self) -> Option<Node> {
        match self.next()? {
            c @ (b'C' | b'c') => {
                let signature = self.pop_if(|node| matches!(node, Node::GenericSignature { .. }));
                let mut ty = self.pop_if(Node::is_type)?;
                if let Some(signature) = signature {
                    self.wrap()?;
                    ty = Node::GenericType {
                        signature: Box::new(signature),
                        inner: Box::new(ty),
                    };
                }
                let labels = self.labels(&ty)?;
                let context = self.context()?;
                Some(Node::Initializer {
                    allocating: c == b'C',
                    context: Box::new(context),
                    labels,
                    ty: Box::new(ty),
                })
            }
            c @ (b'D' | b'd') => {
                let context = self.context()?;
                Some(Node::Deinitializer {
                    deallocating: c == b'D',
                    context: Box::new(context),
                })
            }
            b'i' => {
                let variable = self.pop_if(|node| matches!(node, Node::Variable { .. }))?;
                Some(Node::VariableInitializer(Box::new(variable)))
            }
            b'e' => {
                let context = self.context()?;
                Some(record("ivar initializer for ", context))
            }
            b'E' => {
                let context = self.context()?;
                Some(record("ivar destroyer for ", context))
            }
            _ => None,
        }
    }

    /// `M` and a letter: the runtime's records about a type.
    fn metatype_record(&mut self) -> Option<Node> {
        let what = match self.next()? {
            b'a' => "type metadata accessor for ",
            b'f' => "full type metadata for ",
            b'm' => "metaclass for ",
            b'n' => "nominal type descriptor for ",
            b'F' => "reflection metadata field descriptor ",
            b'B' => "reflection metadata builtin descriptor ",
            b'S' => "reflection metadata superclass descriptor ",
            b'A' => "reflection metadata assocType descriptor ",
            b'p' => {
                let protocol = self.protocol()?;
                return Some(record("protocol descriptor for ", protocol));
            }
            b'c' => {
                let conformance = self.conformance()?;
                return Some(record("protocol conformance descriptor for ", conformance));
            }
            b'V' => {
                let entity = self.pop_if(Node::is_entity)?;
                return Some(record("property descriptor for ", entity));
            }
            b'K' => {
                let of = self.pop()?;
                return Some(record("metadata instantiation cache for ", of));
            }
            b'L' => "lazy cache variable for type metadata for ",
            b'i' => "type metadata instantiation function for ",
            b'I' => "type metadata instantiation cache for ",
            b'l' => "type metadata singleton initialization cache for ",
            b'r' => "type metadata completion function for ",
            b'P' => "generic type metadata pattern for ",
            b'd' => "demangling cache variable for type metadata for ",
            b'R' => "mangled name ref for type metadata for ",
            b'X' => {
                let what = match self.next()? {
                    b'M' => "module descriptor ",
                    b'E' => "extension descriptor ",
                    b'X' => "anonymous descriptor ",
                    _ => return None,
                };
                let context = self.context()?;
                return Some(record(what, context));
            }
            _ => return None,
        };
        let ty = self.pop_if(Node::is_type)?;
        Some(record(what, ty))
    }

    /// A conformance on the stack: the module, the protocol, the type.
    fn conformance(&mut self) -> Option<Node> {
        let module = self.context()?;
        let protocol = self.protocol()?;
        let ty = self.pop_if(Node::is_type)?;
        Some(Node::Conformance {
            ty: Box::new(ty),
            protocol: Box::new(protocol),
            module: Box::new(module),
        })
    }

    /// `W` and a letter: the witness records.
    fn witness(&mut self) -> Option<Node> {
        match self.next()? {
            b'V' => {
                let ty = self.pop_if(Node::is_type)?;
                Some(record("value witness table for ", ty))
            }
            b'v' => {
                let what = match self.next()? {
                    b'd' => "direct field offset for ",
                    b'i' => "indirect field offset for ",
                    _ => return None,
                };
                let entity = self.pop_if(Node::is_entity)?;
                Some(record(what, entity))
            }
            c @ (b'l' | b'L') => {
                // The lazy accessor and its cache: the conformance, and the
                // type it is for.
                let conformance = self.conformance()?;
                let ty = self.pop_if(Node::is_type)?;
                let what = if c == b'l' {
                    "lazy protocol witness table accessor for type "
                } else {
                    "lazy protocol witness table cache variable for type "
                };
                Some(record(
                    what,
                    Node::Identifier(format!(
                        "{} and conformance {}",
                        ty.print(),
                        conformance.print()
                    )),
                ))
            }
            c => {
                let what = match c {
                    b'P' => "protocol witness table for ",
                    b'p' => "protocol witness table pattern for ",
                    b'a' => "protocol witness table accessor for ",
                    b'S' => "protocol self-conformance witness table for ",
                    _ => return None,
                };
                let conformance = self.conformance()?;
                Some(record(what, conformance))
            }
        }
    }

    /// `w` and two letters: a value witness of a type.
    fn value_witness(&mut self) -> Option<Node> {
        let a = self.next()?;
        let b = self.next()?;
        let kind = match (a, b) {
            (b'a', b'l') => "allocateBuffer",
            (b'c', b'a') => "assignWithCopy",
            (b't', b'a') => "assignWithTake",
            (b'd', b'e') => "deallocateBuffer",
            (b'x', b'x') => "destroy",
            (b'X', b'X') => "destroyBuffer",
            (b'X', b'x') => "destroyArray",
            (b'C', b'P') => "initializeBufferWithCopyOfBuffer",
            (b'C', b'p') => "initializeBufferWithCopy",
            (b'c', b'p') => "initializeWithCopy",
            (b'T', b'k') => "initializeBufferWithTake",
            (b't', b'k') => "initializeWithTake",
            (b'p', b'r') => "projectBuffer",
            (b'T', b'K') => "initializeBufferWithTakeOfBuffer",
            (b'C', b'c') => "initializeArrayWithCopy",
            (b'T', b't') => "initializeArrayWithTakeFrontToBack",
            (b't', b'T') => "initializeArrayWithTakeBackToFront",
            (b'x', b's') => "storeExtraInhabitant",
            (b'x', b'g') => "getExtraInhabitantIndex",
            (b'u', b'g') => "getEnumTag",
            (b'u', b'p') => "destructiveProjectEnumData",
            (b'u', b'i') => "destructiveInjectEnumTag",
            (b'e', b't') => "getEnumTagSinglePayload",
            (b's', b't') => "storeEnumTagSinglePayload",
            _ => return None,
        };
        let ty = self.pop_if(Node::is_type)?;
        Some(Node::ValueWitness {
            kind,
            ty: Box::new(ty),
        })
    }

    /// `T` and a letter: the thunks and descriptors.
    fn thunk(&mut self) -> Option<Node> {
        match self.next()? {
            b'W' => {
                let entity = self.pop_if(Node::is_entity)?;
                let conformance = self.conformance()?;
                Some(Node::ProtocolWitness {
                    entity: Box::new(entity),
                    conformance: Box::new(conformance),
                })
            }
            b'L' => {
                let protocol = self.protocol()?;
                Some(record(
                    "protocol requirements base descriptor for ",
                    protocol,
                ))
            }
            b'S' => {
                let protocol = self.protocol()?;
                Some(record(
                    "protocol self-conformance descriptor for ",
                    protocol,
                ))
            }
            b'l' => {
                // An associated type's descriptor: the protocol, then the
                // type's name.
                let protocol = self.protocol()?;
                let name = match self.pop()? {
                    Node::Identifier(name) => name,
                    _ => return None,
                };
                Some(record(
                    "associated type descriptor for ",
                    Node::DependentMember {
                        base: Box::new(protocol),
                        name,
                    },
                ))
            }
            b'n' => {
                // An associated conformance's descriptor: the protocol
                // required, the associated type's path, the protocol.
                let required = self.protocol()?;
                let _first = self.pop_if(|node| matches!(node, Node::FirstElementMarker));
                let qualifier = self.pop_if(Node::is_protocol);
                let name = match self.pop()? {
                    Node::Identifier(name) => name,
                    _ => return None,
                };
                let protocol = self.pop_if(Node::is_type)?;
                let path = match qualifier {
                    Some(qualifier) => format!("{}.{name}", qualifier.print()),
                    None => name,
                };
                Some(record(
                    "associated conformance descriptor for ",
                    Node::Identifier(format!("{}.{path}: {}", protocol.print(), required.print())),
                ))
            }
            b'Y' => {
                // `TY` and an index: a partial function an async function
                // resumes at.
                let index = self.index()?;
                let entity = self.pop_if(Node::is_entity)?;
                Some(record(
                    &format!("({index}) suspend resume partial function for "),
                    entity,
                ))
            }
            c => {
                let what = match c {
                    b'q' => "method descriptor for ",
                    b'u' => "async function pointer to ",
                    b'j' => "dispatch thunk of ",
                    b'V' => "vtable thunk for ",
                    b'o' => "@objc ",
                    b'O' => "@nonobjc ",
                    b'D' => "dynamically replaceable function for ",
                    b'I' => "dynamically replaceable variable for ",
                    b'X' => "dynamically replaceable key for ",
                    b'm' => "merged ",
                    _ => return None,
                };
                let entity = self.pop_if(Node::is_entity)?;
                Some(record(what, entity))
            }
        }
    }
}

/// A runtime record about a node.
fn record(what: &str, of: Node) -> Node {
    Node::Record {
        what: what.to_string(),
        of: Box::new(of),
    }
}

/// A type of the standard library, under its module.
fn standard_nominal(kind: NominalKind, name: &str) -> Node {
    Node::Nominal {
        kind,
        context: Box::new(Node::Module("Swift".to_string())),
        name: name.to_string(),
    }
}

/// The standard library's shorthand: `S` and a letter.
fn standard_type(c: u8) -> Option<(NominalKind, &'static str)> {
    use NominalKind::*;
    Some(match c {
        b'a' => (Struct, "Array"),
        b'A' => (Struct, "AutoreleasingUnsafeMutablePointer"),
        b'b' => (Struct, "Bool"),
        b'D' => (Struct, "Dictionary"),
        b'd' => (Struct, "Double"),
        b'f' => (Struct, "Float"),
        b'h' => (Struct, "Set"),
        b'I' => (Struct, "DefaultIndices"),
        b'i' => (Struct, "Int"),
        b'J' => (Struct, "Character"),
        b'N' => (Struct, "ClosedRange"),
        b'n' => (Struct, "Range"),
        b'O' => (Struct, "ObjectIdentifier"),
        b'P' => (Struct, "UnsafePointer"),
        b'p' => (Struct, "UnsafeMutablePointer"),
        b'R' => (Struct, "UnsafeBufferPointer"),
        b'r' => (Struct, "UnsafeMutableBufferPointer"),
        b'S' => (Struct, "String"),
        b's' => (Struct, "Substring"),
        b'u' => (Struct, "UInt"),
        b'V' => (Struct, "UnsafeRawPointer"),
        b'v' => (Struct, "UnsafeMutableRawPointer"),
        b'W' => (Struct, "UnsafeRawBufferPointer"),
        b'w' => (Struct, "UnsafeMutableRawBufferPointer"),
        b'q' => (Enum, "Optional"),
        b'B' => (Protocol, "BinaryFloatingPoint"),
        b'E' => (Protocol, "Encodable"),
        b'e' => (Protocol, "Decodable"),
        b'F' => (Protocol, "FloatingPoint"),
        b'G' => (Protocol, "RandomNumberGenerator"),
        b'H' => (Protocol, "Hashable"),
        b'j' => (Protocol, "Numeric"),
        b'K' => (Protocol, "BidirectionalCollection"),
        b'k' => (Protocol, "RandomAccessCollection"),
        b'L' => (Protocol, "Comparable"),
        b'l' => (Protocol, "Collection"),
        b'M' => (Protocol, "MutableCollection"),
        b'm' => (Protocol, "RangeReplaceableCollection"),
        b'Q' => (Protocol, "Equatable"),
        b'T' => (Protocol, "Sequence"),
        b't' => (Protocol, "IteratorProtocol"),
        b'U' => (Protocol, "UnsignedInteger"),
        b'X' => (Protocol, "RangeExpression"),
        b'x' => (Protocol, "Strideable"),
        b'Y' => (Protocol, "RawRepresentable"),
        b'y' => (Protocol, "StringProtocol"),
        b'Z' => (Protocol, "SignedInteger"),
        b'z' => (Protocol, "BinaryInteger"),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{demangle, demangle_short, demangle_type};

    /// Every name of the two Swift fixtures, against what the Swift
    /// toolchain's own demangler says of it. The specializations — a
    /// function signature's (`Tf`), a generic one's (`Tg`) — are past the
    /// grammar, and read as nothing; everything else must agree.
    fn check_oracle(oracle: &str) -> (usize, Vec<String>) {
        let mut checked = 0;
        let mut misses = Vec::new();
        for line in oracle.lines() {
            let Some((mangled, expected)) = line.split_once('\t') else {
                continue;
            };
            let got = demangle(mangled);
            let specialization = expected.contains("specialization <");
            if specialization {
                assert_eq!(got, None, "{mangled} is past the grammar");
                continue;
            }
            checked += 1;
            if got.as_deref() != Some(expected) {
                misses.push(format!("{mangled}\n   want {expected}\n   got  {got:?}"));
            }
        }
        (checked, misses)
    }

    #[test]
    fn the_fixtures_names_demangle_as_the_toolchain_does() {
        let (checked, misses) = check_oracle(include_str!("../tests/fixtures/swift_names.tsv"));
        assert!(
            misses.is_empty(),
            "{} of {checked} differ:\n{}",
            misses.len(),
            misses.join("\n")
        );
        assert!(checked >= 90, "{checked}");
    }

    #[test]
    fn optionals_arrays_throws_async_and_generics_demangle_as_the_toolchain_does() {
        let (checked, misses) = check_oracle(include_str!("../tests/fixtures/swift_names2.tsv"));
        assert!(
            misses.is_empty(),
            "{} of {checked} differ:\n{}",
            misses.len(),
            misses.join("\n")
        );
        assert!(checked >= 85, "{checked}");
    }

    #[test]
    fn types_as_the_metadata_spells_them() {
        assert_eq!(demangle_type("Si").as_deref(), Some("Swift.Int"));
        assert_eq!(demangle_type("SS").as_deref(), Some("Swift.String"));
        assert_eq!(
            demangle_type("6sample5PointV").as_deref(),
            Some("sample.Point")
        );
        assert_eq!(demangle_type("SiSg").as_deref(), Some("Swift.Int?"));
        assert_eq!(demangle_type("SiSgSg").as_deref(), Some("Swift.Int??"));
        assert_eq!(
            demangle_type("Si_SSt").as_deref(),
            Some("(Swift.Int, Swift.String)")
        );
        // A labelled element: an enum case's payload.
        assert_eq!(
            demangle_type("Si6radius_t").as_deref(),
            Some("(radius: Swift.Int)")
        );
        assert_eq!(
            demangle_type("Si1x_Sd1yt").as_deref(),
            Some("(x: Swift.Int, y: Swift.Double)")
        );
        assert_eq!(
            demangle_type("SiSdXE").as_deref(),
            Some("(Swift.Double) -> Swift.Int")
        );
        assert_eq!(
            demangle_type("SiSdKXE").as_deref(),
            Some("(Swift.Double) throws -> Swift.Int")
        );
        assert_eq!(demangle_type("SaySiG").as_deref(), Some("[Swift.Int]"));
        assert_eq!(demangle_type("SqySSG").as_deref(), Some("Swift.String?"));
        assert_eq!(
            demangle_type("SDySSSiG").as_deref(),
            Some("[Swift.String : Swift.Int]")
        );
        // A bound generic type is a substitution, as the compiler counts.
        assert_eq!(
            demangle_type("SaySiG_AAt").as_deref(),
            Some("([Swift.Int], [Swift.Int])")
        );
        assert_eq!(demangle_type("Xl").as_deref(), Some("Swift.AnyObject"));
        assert_eq!(demangle_type(""), None);
        assert_eq!(demangle_type("~"), None);
        assert_eq!(demangle_type("Si_SStpd"), None);
    }

    #[test]
    fn the_short_form_is_the_scope_and_the_name() {
        assert_eq!(
            demangle_short("_$s6sample7DerivedC5greet5timesS2i_tF").as_deref(),
            Some("sample.Derived.greet")
        );
        assert_eq!(
            demangle_short("_$s6sample4BaseC5countSivg").as_deref(),
            Some("sample.Base.count.getter")
        );
        assert_eq!(
            demangle_short("_$s6sample5PointV1x1yACSi_SitcfC").as_deref(),
            Some("sample.Point.init")
        );
        assert_eq!(
            demangle_short("_$s6sample4BaseC6answerSiyFZ").as_deref(),
            Some("static sample.Base.answer")
        );
    }

    #[test]
    fn names_that_are_not_swift_are_left_alone() {
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("_ZN8geometry4areaEii"), None);
        assert_eq!(demangle("$s"), None);
        assert_eq!(demangle("_$s6sample"), None);
    }

    #[test]
    fn a_crafted_name_reads_as_nothing_within_bounds() {
        // Numbers past the machine's.
        assert_eq!(demangle("$s18446744073709551615a"), None);
        assert_eq!(demangle("$s4mainA18446744073709551615_"), None);
        assert_eq!(demangle("$s4mainSiq18446744073709551615_"), None);
        assert_eq!(demangle("$s4main99999999999999999999x"), None);
        // Substitutions repeated to multiply a tree: the budget of nodes
        // ends it.
        assert_eq!(
            demangle(&format!("$s6sample{}", "A99999999999a".repeat(50))),
            None
        );
        let mut blowup = "$s4main1xSi".to_string();
        for _ in 0..6 {
            blowup.push_str("A4000c");
            blowup.push_str("yG1yv");
            blowup.push_str("p1zC");
        }
        assert_eq!(demangle(&blowup), None);
        // Types nested deeper than any real one.
        assert_eq!(
            demangle(&format!("$s4main1xSi{}vp", "m".repeat(2000))),
            None
        );
        assert_eq!(
            demangle(&format!("$s4main1xSi{}vp", "Sg".repeat(2000))),
            None
        );
        assert_eq!(
            demangle(&format!("$s4main1xSi{}vp", "_t".repeat(2000))),
            None
        );
        assert_eq!(
            demangle(&format!("$s4main1x{}Sivp", "y".repeat(5000))),
            None
        );
    }
}
