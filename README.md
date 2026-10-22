# AdmiralGrace

![Admiral Grace Hopper](images/headshot.jpg)

AdmiralGrace is an open-source disassembler and decompiler utility written in Rust. It is named in honor of Admiral Grace Hopper, a pioneer of computer programming and compiler development.

The project is in an early, actively developing stage. The Rust workspace contains a decompilation corpus reader and browsing CLI, plus the beginnings of a reusable disassembly and decompilation engine. The full binary-to-pseudocode pipeline is not implemented yet.

## Workspace

- `ag-corpus` loads indexed decompilation output and provides function and Objective-C metadata helpers.
- `ag-cli` builds the `ag` command-line tool for inspecting a corpus.
- `ag-engine` contains the developing CPU decoding, control-flow, AST, and decompilation components.

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

## Development status

The engine is under active development. Several stages of the full decompilation pipeline are still planned or incomplete. At this stage, AdmiralGrace should be treated as an experimental project rather than a complete replacement for a production disassembler.

## License

The workspace declares the MIT license in `Cargo.toml`.
