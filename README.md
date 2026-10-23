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
- `ag-engine` holds the native x86-64 decoder, the control-flow graph builder, and the AST and emission scaffolding the decompiler will grow into.
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

## Corpus format

A corpus is a directory holding `decompile-index.json` and one file per function. The index is JSON: a `version`, the `target_sha256` of the binary that was analysed, the `provider` that produced it, and a `functions` array. Each entry gives the function's `address` and `name`, its `status`, and the byte `range` its body covers. The body lives in `functions/<address>.c`, or wherever the entry's `relative_path` points.

A kuna project export is the other layout `ag` reads: a `.c` of every function, a `.h` of prototypes, an `.asm` of every code section, and — under `--stream` — an `index.jsonl` giving each function's byte span in the `.c`.

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

`ag-ui` is the desktop analysis workbench: a menu bar, a function navigator, a work surface with listing, pseudocode, bytes and references, an inspector, and a bottom workspace for search results and problems. The layout follows `ui/UI_PLAN.md`.

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

## Development status

The engine is under active development. The x86-64 decoder and the control-flow graph builder are in place with tests; the lifter, the structuring passes and the emitter are still scaffolding. Whether the engine should build on the kuna crates instead of its own decoder and loader is evaluated in `docs/KUNA_CRATES_EVALUATION.md`. Open work is tracked in `BACKLOG.md`, which mirrors the GitHub Issues tab. At this stage, AdmiralGrace should be treated as an experimental project rather than a production-grade tool.

## License

The workspace declares the MIT license in `Cargo.toml`.
