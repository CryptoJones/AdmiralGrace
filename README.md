# AdmiralGrace

![Admiral Grace Hopper](images/headshot.jpg)

AdmiralGrace is an open-source disassembler and decompiler utility written in Rust. It is named in honor of Admiral Grace Hopper, a pioneer of computer programming and compiler development.

The project is in an early, actively developing stage. The Rust workspace contains a decompilation corpus reader and browsing CLI, plus the beginnings of a reusable disassembly and decompilation engine. The full binary-to-pseudocode pipeline is not implemented yet.

## Workspace

- `ag-corpus` loads indexed decompilation output and provides function and Objective-C metadata helpers.
- `ag-cli` builds the `ag` command-line tool for inspecting a corpus.
- `ag-engine` contains the developing CPU decoding, control-flow, AST, and decompilation components.
- `ag-ui` builds the `ag-ui` desktop analysis workbench, an [Iced](https://iced.rs) application that reads a corpus through the same data layer the CLI uses.

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

## Development status

The engine is under active development. Several stages of the full decompilation pipeline are still planned or incomplete. At this stage, AdmiralGrace should be treated as an experimental project rather than a production-grade tool.

## License

The workspace declares the MIT license in `Cargo.toml`.
