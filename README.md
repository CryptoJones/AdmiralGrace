# AdmiralGrace

<img src="images/headshot.jpg" alt="Admiral Grace Hopper" width="220">

AdmiralGrace is an open-source disassembler and decompiler utility written in Rust. It is named in honor of Admiral Grace Hopper, a pioneer of computer programming and compiler development.

The project is in an early, actively developing stage. The workspace holds a desktop analysis workbench, a command-line tool that reads decompilation output, and the beginnings of a native disassembly and decompilation engine. Today the workbench and the CLI read two kinds of analysis: an indexed decompilation corpus, and a project export from the [kuna](https://github.com/Noelo-Lab/kuna) decompiler. The native binary-to-pseudocode pipeline is not implemented yet.

## Screenshots

The workbench on a kuna project export of a small ELF. The listing comes from the export's `.asm`, the cross references, strings and program summary from the kuna CLI, and the selection is shared by every pane.

![The workbench showing the listing of main from a kuna export, with calls and data references in the inspector](images/workbench-kuna.png)

The same function on the Pseudocode tab. Lines that kuna mapped to addresses are numbered and clickable, so a click on a line moves the listing to the instructions it came from.

![The workbench showing the decompiled C of main with numbered, address-mapped lines](images/workbench-kuna-pseudocode.png)

The bundled sample project, which opens when no corpus or export is given, so the interface can be explored without a binary.

![The workbench showing the bundled sample project with an ARM64 listing, bytes, and references](images/workbench-sample.png)

## Workspace

- `ag-corpus` reads an indexed decompilation corpus and a kuna project export, and overlays Objective-C method names.
- `ag-cli` builds the `ag` command-line tool: it reports on either source and carries its own manual and an agent skill.
- `ag-engine` holds the program image loader (ELF, PE, COFF and Mach-O, through the kuna-analysis crate), the native x86-64 decoder, the control-flow graph builder, and the AST and emission scaffolding the decompiler will grow into.
- `ag-image` reads a program image through the engine: its sections, its symbols, the bytes of the file, the disassembly of a function, the calls between the functions, and the strings of the data sections.
- `ag-ui` builds the `ag-ui` desktop analysis workbench, an [Iced](https://iced.rs) application that reads both sources through the same data layer the CLI uses and asks the kuna CLI for what an export does not carry.

## Build

Install the [Rust toolchain](https://www.rust-lang.org/tools/install), then build from the repository root:

```sh
cargo build
```

Run the CLI with Cargo:

```sh
cargo run --bin ag -- --help
```

## Corpus CLI

The current CLI reads a corpus directory containing `decompile-index.json` and the function files referenced by that index. Pass `--root` to select the corpus directory.

```sh
# Summarize the corpus
cargo run --bin ag -- corpus --root ./corpus stats

# List functions, optionally filtering names with a regular expression
cargo run --bin ag -- corpus --root ./corpus list --named-only --filter 'decrypt|parse'

# Show a function by address or name
cargo run --bin ag -- corpus --root ./corpus show 0x1000

# Search function bodies with a regular expression
cargo run --bin ag -- corpus --root ./corpus grep 'memcpy|malloc'
```

Objective-C method names can be overlaid from a method map with `--methods PATH`. See `cargo run --bin ag -- corpus --help` and `cargo run --bin ag -- corpus --root ./corpus list --help` for all options.

## Image CLI

The CLI reads a program image as well: an ELF, PE, COFF or Mach-O file, parsed by the engine's own loader.

```sh
# The language, the entry point and the sections
cargo run --bin ag -- image ./sample.elf info

# The function and data symbols
cargo run --bin ag -- image ./sample.elf symbols --filter 'main|add'

# The disassembly of one function, by name or by address
cargo run --bin ag -- image ./sample.elf disasm main

# The strings of the image, and the functions that use them
cargo run --bin ag -- image ./sample.elf strings
```

Every subcommand takes `--json` for the same report as JSON. `info` and `symbols` read any format the loader reads; `disasm` decodes x86-64, so it refuses an image of another architecture rather than printing nonsense.

`strings` reads the sections that are not code and reports the text that ends in a NUL, with the functions that use it. `--filter` keeps only the strings whose text matches a regular expression, and `--utf16` reports the strings that are held as UTF-16LE.

## Corpus format

A corpus is a directory holding `decompile-index.json` and one file per function. The index is JSON: a `version`, the `target_sha256` of the binary that was analysed, the `provider` that produced it, and a `functions` array. Each entry gives the function's `address` and `name`, its `status`, and the byte `range` its body covers. The body lives in `functions/<address>.c`, or wherever the entry's `relative_path` points. The leading `//` comment header of a body is dropped; the signature and the locals are kept.

A kuna project export is the other layout `ag` reads: a `.c` of every function, a `.h` of prototypes, an `.asm` of every code section, and — under `--stream` — an `index.jsonl` giving each function's byte span in the `.c`.

The `--methods` map is a JSON array of records, each naming the IMP of a method, its class, its selector and its types. A class method is the instance method of the class's metaclass: the map says which it is with `is_class_method`, or by writing the class with a leading `+`. The two are told apart in the display, `-[Class sel]` and `+[Class sel]`, so they are two names and not one.

Nothing is dropped in silence. A record that cannot be read is skipped and named, and two records that claim one address are both kept, with the first resolving it. `ag` says so on stderr, and the workbench shows it in the Problems pane.

## Embedded manual and agent skill

The `ag` binary carries its own documentation and an agent skill, so a session with no checkout and no network can still read the reference and learn to drive the tool.

```sh
# List the embedded manual's topics
ag docs

# Print one topic
ag docs cli

# Install the agent skill where coding agents load skills
ag install-skill --agent claude
```

`ag install-skill` writes the skill offline, into `$CLAUDE_CONFIG_DIR/skills`, `$CODEX_HOME/skills` or `$OPENCODE_CONFIG_DIR/skills` (or the project directory with `--project`). `ag docs` prints the manual: the command reference, the corpus format and the workbench.

## Desktop workbench

`ag-ui` is the desktop analysis workbench: a menu bar, a function navigator, a work surface with listing, pseudocode, graph, bytes and references, an inspector, and a bottom workspace for search results and problems. The layout follows `ui/UI_PLAN.md`.

```sh
# Launch with the bundled sample project
cargo run --bin ag-ui

# Launch on a corpus
cargo run --bin ag-ui -- --corpus ./corpus

# Overlay an Objective-C method map
cargo run --bin ag-ui -- --corpus ./corpus --methods ./corpus/methods.json
```

The corpus directory must contain a `decompile-index.json`. Without one the workbench opens a bundled sample project so the interface can be explored. `ui/README.md` covers the workbench in more detail.

The workbench opens a kuna project export as well:

```sh
cargo run --bin ag-ui -- --kuna ./challenge.kuna
```

The export fills the Listing and Pseudocode tabs on its own. With the kuna executable available, named by `AG_KUNA_BIN` or found on the `PATH` as `kuna`, the workbench also asks it for the cross references, the strings, the program summary, and the mapping from each line of C to the addresses it came from. Without it those panes stay empty and the Problems panel says why.

The workbench opens a program image as well:

```sh
cargo run --bin ag-ui -- --binary ./sample.elf
```

That is the native path: the image is parsed by the engine's own loader, the navigator lists its symbols, the inspector shows its sections and entry point, and the Listing tab holds the native x86-64 disassembly of the selected function. There is no pseudocode yet, because the lifter has not been written, so that tab says so rather than showing an empty pane.

Who calls what is only known once the whole program has been read, so that is worked out in the background when the image opens: the References tab says `indexing…` until the callers are known.

The Bytes tab shows the bytes of the file around the selection, sixteen to a row, with the address, the hex and the ASCII column, and the bytes of the selected instruction marked. The pane follows the selection, and picking a section or a named symbol in the navigator moves it there.

The Strings tab lists the text the image holds, with the functions that use it. The list filters as you type, and picking a string moves the selection to it.

The Graph tab draws the control-flow graph of the selected function: one box for each block the walk found, with the instructions in it, and an arrow for each way the code goes on. The arrow that leaves the end of a block is the fall-through, and the other one is the branch that is taken. An arrow that skips a row goes around the blocks in between rather than through them. The graph can be dragged and zoomed, and clicking a box moves the selection to it.

## Development status

The engine is under active development. The x86-64 decoder and the control-flow graph builder are in place with tests; the lifter, the structuring passes and the emitter are still scaffolding. The engine's loader is kuna-analysis, adopted as a pinned git dependency; the evaluation and the decision are in `docs/KUNA_CRATES_EVALUATION.md`. Open work is tracked in `BACKLOG.md`, which mirrors the GitHub Issues tab. At this stage, AdmiralGrace should be treated as an experimental project rather than a production-grade tool.

## License

The workspace declares the MIT license in `Cargo.toml`; the text is in `LICENSE`. The kuna crates it depends on are Apache-2.0, and `NOTICE` carries their attribution and Ghidra's.
