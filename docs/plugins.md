# Plugins

A loader, an architecture or a tool is added without forking. A **loader** reads a container
the engine does not — a firmware image with its own header, a packed format, an archive —
into the sections, symbols and entry point everything else works from. An **architecture**
decodes the code of a language the engine does not, into the instructions and the flow
between them that the control-flow walk, the listing and the graph work from. A **tool** is
an analysis of its own over an open image, run with `ag tool` or called by a language model
through the MCP server beside the image's own tools.

A plugin is written one of two ways: in Rust, against the traits of `ag_engine::plugin` and
`ag_image::plugin`, by a crate that builds on the engine; or in any language, as a command
declared in a **manifest** that the `ag` binary finds as it starts.

```bash
cargo run --bin ag -- plugins
cargo run --bin ag -- tool count_strings ./sample.elf --arg 'pattern=^http'
```

## Manifests

A manifest is a JSON file in a plugin directory: the directories `AG_PLUGINS` names (separated
as the platform separates paths), then `$XDG_CONFIG_HOME/ag/plugins` or `~/.config/ag/plugins`.
Every `.json` file there is read when `ag` starts; one that does not read is reported on
standard error and skipped. `ag plugins` lists the directories, the manifests and everything
registered, as text or with `--json`.

```json
{
  "name": "toy",
  "loaders": [
    { "name": "toyfile", "magic": "544f5921", "command": ["python3", "/opt/toy/load.py"] }
  ],
  "architectures": [
    { "name": "toycpu", "languages": ["TOY:LE:8:default"], "bitness": 32, "command": ["python3", "/opt/toy/decode.py"],
      "blocks": ["python3", "/opt/toy/blocks.py"], "lift": ["python3", "/opt/toy/lift.py"] }
  ],
  "tools": [
    { "name": "count_strings", "description": "How many strings match a pattern.", "command": ["python3", "/opt/toy/count.py"],
      "inputSchema": { "type": "object", "properties": { "pattern": { "type": "string" } } } }
  ],
  "rewriters": [
    { "name": "unflatten", "command": ["python3", "/opt/toy/unflatten.py"] }
  ],
  "formatters": [
    { "name": "house-style", "command": ["python3", "/opt/toy/format.py"] }
  ]
}
```

A loader names the `magic` — the hex of the bytes a file of its format starts with — and
the engine offers it every file that starts so, before its own loaders; a loader that fails
is reported on standard error and the engine's own loaders read the file after all, so a
loader with a common magic cannot keep a program from opening. An architecture names the
`languages` it decodes (the language ids a loader reports) and its `bitness` (16, 32 or 64),
and may give two more commands: `blocks`, which recovers a function's basic blocks itself,
and `lift`, which lifts a whole function at once (below).
A tool names itself (letters, digits, `_` and `-`), says what it does, and may give the JSON
Schema of its arguments (an object). A rewriter needs only its command: every function lifted
passes through it. A formatter needs only its command too: every function's pseudocode passes
through it after the engine has printed it. An entry without a `name` is named for the manifest,
the second and later with their place (`toy-1`); a name declared twice is reported, and the
later declaration replaces the earlier. Every command is a list: the program and its
arguments. A bare program name is found on `PATH`, as a shell finds it; a program that names
a path — one with a separator in it — is taken from the manifest's directory when it is
relative; the arguments are passed as they are, with `${dir}` in any element standing for
the manifest's directory, so a manifest and its scripts move together. Every entry may give a `timeout` in seconds (60 unless said): a command that has
not answered by then is ended and its answer is an error.

## The five conversations

Each command is given its input on standard input and answers on standard output, in one
go; its standard error is the terminal's. Numbers may be JSON numbers or hex text such as
`"0x100"`.

**A loader** is given the file's bytes and answers with the image:

```json
{
  "language": "TOY:LE:8:default",
  "entry": "0x100",
  "base": "0x100",
  "sections": [ { "name": "code", "vma": "0x100", "size": 6, "executable": true, "file_offset": 5, "file_size": 6 } ],
  "functions": [ { "address": "0x100", "name": "start" } ],
  "data": [ { "address": "0x200", "name": "table", "size": 16 } ],
  "imports": [ { "address": "0x300", "name": "puts" } ]
}
```

`sections` carry where each sits in the file (`file_offset`, `file_size`), which is how the
bytes of a section are found — a section without a `file_offset` has no bytes, and so no
code to list; `functions`, `data` and `imports` are optional, as are `entry` and `base`.

**An architecture** is given one section — `{"language": "…", "base": 256, "bytes": "<hex>"}`
— and answers with its instructions, in address order:

```json
{ "instructions": [
  { "address": "0x100", "length": 2, "mnemonic": "br", "operands": "0x104", "flow": "branch", "target": "0x104" },
  { "address": "0x102", "length": 1, "mnemonic": "nop" },
  { "address": "0x103", "length": 1, "mnemonic": "ret", "flow": "return" }
] }
```

`flow` is what the control-flow walk follows: `next` (the default), `jump` and `branch` with
a `target` (without one they are `indirect-jump`), `call` with a `target` (without one
`indirect-call`), `return`, `halt`, `trap`, `interrupt`, `syscall` or `invalid`. `registers`
may list the registers the operands name, so a rename reaches them; `memory` may give the
address a memory operand names, so a reference to data or a string is found. An instruction
outside the section, or running past its end, or on an address already given, is left out
with a warning. An image a plugin's architecture decodes has its listing, its graph and its
cross references; the engine's lifter reads x86-64 alone, so it has pseudocode only when the
architecture lifts it itself:

**An architecture's `blocks` command**, when the manifest gives one, recovers a function's
basic blocks where the flows alone cannot — delay slots, hardware loops, a bytecode whose
jumps the decoder cannot read. It is given `{"language": "…", "entry": 256, "instructions":
[ {"address": 256, "length": 2, "flow": "branch", "target": 260}, … ]}` (each number with a
`_hex` twin beside it) and answers `{"blocks": [ {"from": 256, "to": 259, "successors": [260,
259], "calls": [ {"site": 258, "target": 266} ]}, … ]}`: the blocks in address order, each
ending where the next begins or the code does, with the blocks control goes on to and the
calls its instructions' flows do not say, each the instruction that calls and the function
called — they reach the listing, the call graph and the cross references as any call does.
The answer is checked: every block runs forward, no two overlap, the entry starts one, and
every successor starts one. Without the command, when it fails, or when its answer does not
pass (reported on standard error, once per function), the engine walks the flows.

**An architecture's `lift` command**, when the manifest gives one, lifts a whole function at
once, with the context one instruction does not have, to the medium level (`docs/il.md`): it
is given the function — `{"language": "…", "function": 256, "name": "start", "base": 256,
"bytes": "<hex of the section>", "instructions": [ … ], "blocks": [ {"from": 256, "to": 259,
"successors": [260, 259]}, … ]}` — and answers with its graph:

```json
{ "return_type": "void", "params": [], "locals": [ { "name": "flag", "type": "int" } ], "entry": 0, "frame": [],
  "blocks": [
    { "address": 256, "statements": [ { "addresses": [258], "expr": { "call": "sub_10a", "args": [] } } ],
      "terminator": { "kind": "branch", "cond": { "var": "flag" }, "taken": 2, "next": 1, "addresses": [256] } },
    { "address": 259, "statements": [], "terminator": { "kind": "return" } },
    { "address": 260, "statements": [], "terminator": { "kind": "return" } }
  ] }
```

A block's `terminator` is `return`, `goto` (a `target` block), `branch` (a `cond`, the block
`taken` when it holds, the `next` otherwise) or `switch` (an `index` and `cases`, at least
one, each its `values`, at least one, and `target`), with the `addresses` it came from. The
`entry` is block 0 unless said; a variable's `type` is `long` unless said; `frame` lists the
instructions no statement came from, which the signature line stands for in the listing. A
function whose `return_type` is not `void` returns its value in a statement — a block that
ends in `return` ends with `{"return": …}` — or is refused. A statement's `expr`, a branch's
`cond` and a switch's `index` are expression trees:

| Tree | Expression |
|---|---|
| a number; `{"const": 1, "width": 4}` | A constant, 8 bytes wide unless `width` says. |
| a string; `{"var": "x"}` | A variable: a parameter or a local by name. |
| `{"string": "text"}` | A string literal. |
| `true`, `false` | A condition that always holds, or never. |
| `{"binary": "+", "lhs": …, "rhs": …}` | An operator spelled as C: `+ - * / % & \| ^ << >> == != < <= > >= && \|\|`. |
| `{"assign": lhs, "rhs": …}` | An assignment. |
| `{"deref": …}`, `{"address_of": …}` | `*p`, `&x`. |
| `{"call": "name", "address": 768, "args": […]}` | A call to a function by name (its address when known), or to the tree given as `call`. |
| `{"return": …}`, `{"return": null}` | A return, with or without a value. |
| `{"cast": "long", "target": …}` | A C cast. |
| `{"intrinsic": "name", "args": […]}` | A builtin the pseudocode spells by name. |

The engine runs the registered rewriters over the graph, analyzes and structures it into the
pseudocode as it does its own lift's, and gives the function its levels: the lifted level by
the function's blocks, the medium and high levels from the graph, and no low level (the level
prints `; no blocks at this level`). An answer that is not such a graph, a block pointing
outside the function, a command that fails or runs out of time, refuses the function with the
architecture's name; so does an architecture that lifts the language and answers nothing for
a function, since the engine's lifter reads x86-64 alone. The `blocks` and `lift` commands
are each run once per function and remembered with the image.

**A tool** is given `{"tool": "…", "image": "<path>", "project": "<path or null>",
"arguments": {…}}` — the image's path and the project file's, so it can open them itself
(for instance by running `ag mcp` or `ag run` on them) — and answers with JSON, or with
text when its output is not JSON. `ag tool NAME IMAGE [--project FILE] [--arg name=value]…`
runs one from the command line, a value that reads as JSON given as JSON; the MCP server
lists every registered tool after the image's own and calls it the same way, its failure
told as the tool's own (`isError`). A tool named like one of the image's own is not listed:
the image's answers to the name.

**A rewriter** is given a function's medium-level graph — the blocks of statements over
variables the lifter built, before they are structured into pseudocode — and answers with
the edits to make. It is run for every function lifted — or for the ones its manifest entry
names under `functions`, by name or address, which spares the process for the rest — in the
order the rewriters were registered; what it leaves is what the medium and high levels
(`docs/il.md`) and the pseudocode show, while the lifted and low levels stay the machine's.
A thunk, which has no graph, passes no rewriter. The graph, its numbers as JSON numbers with
a `_hex` twin beside each address:

```json
{ "function": 4449, "function_hex": "0x1161", "name": "sum_to", "entry": 0,
  "blocks": [
    { "id": 0, "address": 4449, "address_hex": "0x1161",
      "statements": [ { "index": 0, "text": "local_10 = 0", "addresses": [4460] }, { "index": 1, "text": "local_14 = 1", "addresses": [4468] } ],
      "terminator": { "kind": "goto", "target": 1 } },
    { "id": 1, "address": 4490, "address_hex": "0x118a", "statements": [],
      "terminator": { "kind": "branch", "cond": "local_14 <= a", "taken": 2, "next": 3 } },
    { "id": 2, "address": 4477, "address_hex": "0x117d",
      "statements": [ { "index": 0, "text": "local_10 = local_10 + (long)local_14", "addresses": [4477, 4480, 4483] }, { "index": 1, "text": "local_14 = local_14 + 1", "addresses": [4486] } ],
      "terminator": { "kind": "goto", "target": 1 } },
    { "id": 3, "address": 4498, "address_hex": "0x1192", "statements": [ { "index": 0, "text": "return local_10", "addresses": [4498, 4499, 4500] } ],
      "terminator": { "kind": "return" } }
  ] }
```

A terminator is `return`, `goto` (a `target`), `branch` (a `cond`, the block `taken` when it
holds, the `next` otherwise) or `switch` (an `index` and `cases`, each its `values` and
`target`). The answer is `{"edits": […]}` — or nothing, or `{}`, for a function left alone —
applied in order, each naming blocks and statements as they stand when it is applied:

| Edit | What it does |
|---|---|
| `{"op": "remove", "block": B, "statement": I}` | Takes statement `I` out of block `B`. |
| `{"op": "copy", "from": B, "statement": I, "to": B2, "at": I2}` | Puts a copy of the statement at `I2` of `B2` (its end without `at`). `move` does the same and takes the original out first — so `at` within the same block counts after the removal. |
| `{"op": "add_block", "address": A, "statements": [{"from": B, "statement": I}, …], "terminator": T}` | Adds a block of copied statements; its id is the next number. `address` labels the block and is optional (one past the highest, a label rather than an instruction's address) but must be no other block's; `terminator` is required — `{"kind": "return"}`, `{"kind": "goto", "target": T}` or `{"kind": "branch", "cond_of": B, "taken": T1, "next": T2}`, the condition reused from block `B`'s branch. |
| `{"op": "redirect", "block": B, "from": T1, "to": T2}` | Every way out of `B` that led to `T1` leads to `T2`. |
| `{"op": "goto", "block": B, "target": T}` | `B` goes straight to `T`. |
| `{"op": "return", "block": B}` | `B` returns. |
| `{"op": "branch", "block": B, "cond_of": B2, "taken": T1, "next": T2}` | `B` branches on block `B2`'s condition. |
| `{"op": "switch_case", "block": B, "from": T1, "to": T2}` | The cases of `B`'s switch that led to `T1` lead to `T2`. |
| `{"op": "prune"}` | Drops the blocks the entry no longer reaches and renumbers the rest; until then a block cut off stays, so it can still be copied from. |

**A formatter** is given a function's pseudocode after the engine has printed it — under the
options in force, `brace-style`, `wrap` and the rest — and answers with the lines as they are
to be: a house style the options do not cover, a line joined or split, a note added. It is
run for every function's pseudocode, in the order the formatters were registered; the levels
(`docs/il.md`) and the transpiler are not formatted. The lines, each with the addresses it
came from and whether it is dead code the `dead-code` option kept:

```json
{ "function": 4425, "function_hex": "0x1149", "name": "add", "language": "c",
  "lines": [
    { "text": "// returns long: main reads rax after the call", "addresses": [], "addresses_hex": [], "dead": false },
    { "text": "long add(int a, int b)", "addresses": [4425], "addresses_hex": ["0x1149"], "dead": false },
    { "text": "{", "addresses": [], "addresses_hex": [], "dead": false },
    { "text": "  return (long)(a + b);", "addresses": [4440, 4443], "addresses_hex": ["0x1158", "0x115b"], "dead": false },
    { "text": "}", "addresses": [], "addresses_hex": [], "dead": false }
  ] }
```

The answer is `{"lines": […]}` — or nothing, or `{}`, for pseudocode left alone — each line
an object with its `text` and, optional, its `addresses` (none when left out, so a line
added maps to no instruction) and whether it is `dead` (false when left out); a bare string
is a line with neither. The lines replace the function's wholesale, so a formatter that keeps
a line passes its addresses and its `dead` back. A formatter that fails, or answers with
something that is not lines, refuses the function's pseudocode with the formatter's name
and the reason, as a rewriter does the lift.

A command cannot write expressions, only reuse the lifter's; a rewriter in Rust can (below).
An edit that names a block or statement there is not, a terminator left pointing outside the
graph, two blocks left at one address, an answer that is not JSON, or a command that fails or
runs out of time, refuses the function: it is not lifted, and the reason names the rewriter —
`not lifted yet: the rewriter unflatten: edit 2 (goto): no block 99: there are 4`. The
instructions of a statement a rewriter removes belong to no statement afterwards, so the
listing counts them with the frame. A command is a process started per function lifted, and a
function is lifted again for each level, form and option asked of it: name the functions
under `functions`, and keep the command quick. Control-flow unflattening is the kind of work
a rewriter is for: find the dispatcher's switch, point each block at the block the state
variable would have led to next, and remove the dispatcher.

## In Rust

A crate that builds on the engine implements the traits and registers before an image is
opened; the workbench and the command line are such crates, and a fork of `ag` with one
more loader is three lines in `main`.

```rust
use std::sync::Arc;
use ag_engine::plugin::{self, Loader, LoadedImage, Architecture, DecodedSection};

struct Toy;

impl Loader for Toy {
    fn name(&self) -> &str { "toy" }
    fn recognizes(&self, bytes: &[u8]) -> bool { bytes.starts_with(b"TOY!") }
    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String> { /* … */ }
}

plugin::register_loader(Arc::new(Toy));
```

- `ag_engine::plugin::Loader` — `name`, `recognizes(bytes)`, `load(name, bytes) -> LoadedImage`
  (the language, entry, base, sections, functions, data and imports). Registered with
  `register_loader`; `Image::from_bytes` offers every file to the registered loaders first.
- `ag_engine::plugin::Architecture` — `name`, `languages`, `bitness(language)` and
  `decode_section(language, bytes, base) -> DecodedSection`: the engine's `Disasm` of
  `DecodedInsn`s with their `Flow`, and the text of each. Registered with
  `register_architecture`; an image whose language no built-in decoder reads is decoded by
  the registered architecture that names it. Three more have defaults: `lifts(language)`
  (false), `blocks(language, disasm, entry) -> Option<Result<Vec<RecoveredBlock>>>` (the
  function's blocks recovered by the architecture, each with its `successors` and the
  `calls` its flows do not say; `None` leaves the walk to the engine) and
  `lift(&FunctionCode) -> Option<Result<LiftedGraph>>` (a whole function lifted at once to
  `Node`s over `AstNode`s, with its `params`, `locals`, `return_type`, `entry` and
  `frame`; `None` from an architecture that `lifts` refuses the function). `Rewrite::statement(node, addresses)`
  makes a statement; the engine structures the graph and gives it its levels.
- `ag_image::plugin::Tool` — `name`, `description`, `input_schema` and
  `run(image, context, arguments)` over the open `Binary`, with the image's and the
  project's paths in the `ToolContext`. Registered with `register_tool`.
- `ag_engine::plugin::Formatter` — `name` and `format(&mut Formatting)`, over a function's
  pseudocode after the engine has printed it: `Formatting` holds the `function`, its `name`,
  the `language` and the `lines` (each an `emit::Line` with its `text` and `addresses`) with
  the indices of the `dead` ones, and offers `to_json` and `apply(&answer)`, the shapes the
  command conversation uses. Registered with `register_formatter`; `formatters()` lists them
  in the order they run, `unregister_formatter(name)` takes one off, and
  `format_pseudocode(&mut pseudocode, function, name, language)` runs them all, as the
  image does after each `emit_function_in`.
- `ag_engine::plugin::Rewriter` — `name`, `wants(address, name)` (every function unless
  said) and `rewrite(&mut Rewrite)`, over a function's medium-level graph before it is
  structured: `Rewrite` holds the `nodes` (each a `Node` of `Statement`s over `AstNode`s
  and a `Terminator`) and the `entry()`, which cannot move, and offers
  `add_block`, `copy_statement`, `remove_statement`, `insert_statement`, `redirect`,
  `set_goto`, `set_return`, `set_branch`, `set_terminator`, `fresh_address`,
  `prune_unreachable` and `validate`; the nodes may also be edited directly — the graph is
  analyzed again after every rewriter that ran. `Rewrite::statement(node, addresses)` makes a plain statement of an
  expression the rewriter builds. An `Err` refuses the function with the rewriter's name.
  Registered with `register_rewriter`; run for every function lifted, in order.

The registry is one for the process, and a plugin registered under a name already taken
replaces it. `ag_image::plugin::load_all` reads the manifests of the plugin directories and
registers what they declare, as `ag` does when it starts.
