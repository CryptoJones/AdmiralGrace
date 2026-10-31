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
    { "name": "toycpu", "languages": ["TOY:LE:8:default"], "bitness": 32, "command": ["python3", "/opt/toy/decode.py"] }
  ],
  "tools": [
    { "name": "count_strings", "description": "How many strings match a pattern.", "command": ["python3", "/opt/toy/count.py"],
      "inputSchema": { "type": "object", "properties": { "pattern": { "type": "string" } } } }
  ],
  "rewriters": [
    { "name": "unflatten", "command": ["python3", "/opt/toy/unflatten.py"] }
  ]
}
```

A loader names the `magic` — the hex of the bytes a file of its format starts with — and
the engine offers it every file that starts so, before its own loaders; a loader that fails
is reported on standard error and the engine's own loaders read the file after all, so a
loader with a common magic cannot keep a program from opening. An architecture names the
`languages` it decodes (the language ids a loader reports) and its `bitness` (16, 32 or 64).
A tool names itself (letters, digits, `_` and `-`), says what it does, and may give the JSON
Schema of its arguments (an object). A rewriter needs only its command: every function lifted
passes through it. An entry without a `name` is named for the manifest,
the second and later with their place (`toy-1`); a name declared twice is reported, and the
later declaration replaces the earlier. Every command is a list: the program and its
arguments. A bare program name is found on `PATH`, as a shell finds it; a program that names
a path — one with a separator in it — is taken from the manifest's directory when it is
relative; the arguments are passed as they are, with `${dir}` in any element standing for
the manifest's directory, so a manifest and its scripts move together. Every entry may give a `timeout` in seconds (60 unless said): a command that has
not answered by then is ended and its answer is an error.

## The four conversations

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
cross references; the lifter does not read it, so it has no pseudocode.

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
the edits to make. It is run for every function lifted, in the order the rewriters were
registered; what it leaves is what the medium and high levels (`docs/il.md`) and the
pseudocode show, while the lifted and low levels stay the machine's. The graph:

```json
{ "function": "0x1161", "name": "sum_to", "entry": 0,
  "blocks": [
    { "id": 0, "address": "0x1161",
      "statements": [ { "index": 0, "text": "local_10 = 0", "addresses": ["0x116c"] }, { "index": 1, "text": "local_14 = 1", "addresses": ["0x1174"] } ],
      "terminator": { "kind": "goto", "target": 1 } },
    { "id": 1, "address": "0x118a", "statements": [],
      "terminator": { "kind": "branch", "cond": "local_14 <= a", "taken": 2, "next": 3 } },
    { "id": 3, "address": "0x1192", "statements": [ { "index": 0, "text": "return local_10", "addresses": ["0x1192"] } ],
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
| `{"op": "copy", "from": B, "statement": I, "to": B2, "at": I2}` | Puts a copy of the statement at `I2` of `B2` (its end without `at`). `move` does the same and takes the original out. |
| `{"op": "add_block", "address": A, "statements": [{"from": B, "statement": I}, …], "terminator": T}` | Adds a block of copied statements; its id is the next number. `address` is optional (one past the highest), `terminator` is `return` unless given — `{"kind": "goto", "target": T}` or `{"kind": "branch", "cond_of": B, "taken": T1, "next": T2}`, the condition reused from block `B`'s branch. |
| `{"op": "redirect", "block": B, "from": T1, "to": T2}` | Every way out of `B` that led to `T1` leads to `T2`. |
| `{"op": "goto", "block": B, "target": T}` | `B` goes straight to `T`. |
| `{"op": "return", "block": B}` | `B` returns. |
| `{"op": "branch", "block": B, "cond_of": B2, "taken": T1, "next": T2}` | `B` branches on block `B2`'s condition. |
| `{"op": "switch_case", "block": B, "from": T1, "to": T2}` | The cases of `B`'s switch that led to `T1` lead to `T2`. |
| `{"op": "prune"}` | Drops the blocks the entry no longer reaches and renumbers the rest; until then a block cut off stays, so it can still be copied from. |

A command cannot write expressions, only reuse the lifter's; a rewriter in Rust can (below).
An edit that names a block or statement there is not, a terminator left pointing outside the
graph, an answer that is not JSON, or a command that fails or runs out of time, refuses the
function: it is not lifted, and the reason names the rewriter — `not lifted yet: the rewriter
unflatten: edit 2 (goto): no block 99: there are 4`. Control-flow unflattening is the kind of
work a rewriter is for: find the dispatcher's switch, point each block at the block the state
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
  the registered architecture that names it.
- `ag_image::plugin::Tool` — `name`, `description`, `input_schema` and
  `run(image, context, arguments)` over the open `Binary`, with the image's and the
  project's paths in the `ToolContext`. Registered with `register_tool`.
- `ag_engine::plugin::Rewriter` — `name` and `rewrite(&mut Rewrite)`, over a function's
  medium-level graph before it is structured: `Rewrite` holds the `nodes` (each a
  `Node` of `Statement`s over `AstNode`s and a `Terminator`) and the `entry`, and offers
  `add_block`, `copy_statement`, `remove_statement`, `insert_statement`, `redirect`,
  `set_goto`, `set_return`, `set_branch`, `set_terminator`, `fresh_address`,
  `prune_unreachable` and `validate`; the nodes may also be edited directly, with `mark_changed` so the graph is
  analyzed again. `Rewrite::statement(node, addresses)` makes a plain statement of an
  expression the rewriter builds. An `Err` refuses the function with the rewriter's name.
  Registered with `register_rewriter`; run for every function lifted, in order.

The registry is one for the process, and a plugin registered under a name already taken
replaces it. `ag_image::plugin::load_all` reads the manifests of the plugin directories and
registers what they declare, as `ag` does when it starts.
