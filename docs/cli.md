# The `ag` CLI reference

`ag` reads an indexed decompilation corpus, or a kuna project export, and reports on it.
Every subcommand lives under `corpus`, because both sources are described the same way.
`ag image` reads a program image instead, through the engine's own loader.

## Building and running

Install the Rust toolchain, then build from the repository root:

```sh
cargo build
```

Run the CLI with Cargo:

```sh
cargo run --bin ag -- --help
```

Once installed, the binary is `ag` and the `cargo run --bin ag --` prefix is not needed.

## Reporting on a corpus

The CLI reads a corpus directory containing `decompile-index.json` and the function files
referenced by that index. Pass `--root` to select the corpus directory.

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

Objective-C method names can be overlaid from a method map with `--methods PATH`. See
`cargo run --bin ag -- corpus --help` and
`cargo run --bin ag -- corpus --root ./corpus list --help` for all options.

## `ag corpus` options

| Option | Meaning |
|---|---|
| `--root DIR` | The corpus directory, or a kuna project export directory. Defaults to `./corpus`. |
| `--methods PATH` | A method map that overlays Objective-C names on the addresses. |
| `--shift ADDR` | The image-base shift applied to the method map's addresses. Defaults to `0x0`. |

## `ag corpus` subcommands

| Subcommand | What it prints |
|---|---|
| `stats` | One line: `total`, `written`, `failed`, `external`, `named_distinct`, `methods`. |
| `list` | One line per function: address, status, name. |
| `list --named-only` | Only the functions that carry a name. |
| `list --with-body` | Only the functions that have a body. |
| `list --filter REGEX` | Only the functions whose name matches the regular expression. |
| `show TARGET` | The function's name, status, address, range and decompiled body. `TARGET` is an address (`0x1000`) or a name. |
| `grep PATTERN` | The address and name of every function whose body matches the regular expression. |
| `methods` | The Objective-C methods of the map, one per line. Needs `--methods PATH`. |
| `methods --class NAME` | Only the methods of that class. |
| `methods --filter REGEX` | Only the methods whose selector matches the regular expression. |

`show` matches a name loosely: an exact name first, then a substring, and the first
candidate with a body wins.

## A kuna project export

A directory holding a kuna export is read as one, so the same subcommands report on it:

```sh
ag corpus --root ./challenge.kuna stats
ag corpus --root ./challenge.kuna show main
```

The export holds a `.c` of every function, an `.asm` of every code section, and, under
`--stream`, an `index.jsonl` giving each function's byte span in the `.c`. `ag docs
corpus-format` describes both layouts.

## Reading a program image

`ag image` reads a program image: an ELF, PE, COFF or Mach-O file, parsed by the engine's
own loader rather than read out of a corpus.

```sh
# The language, the entry point and the sections
cargo run --bin ag -- image ./sample.elf info

# The function and data symbols
cargo run --bin ag -- image ./sample.elf symbols --filter 'main|add'

# The disassembly of one function, by name or by address
cargo run --bin ag -- image ./sample.elf disasm main

# The control-flow graph of one function
cargo run --bin ag -- image ./sample.elf cfg main

# Who calls whom
cargo run --bin ag -- image ./sample.elf calls

# The strings of the image, and the functions that use them
cargo run --bin ag -- image ./sample.elf strings
```

## `ag image` subcommands

| Subcommand | What it prints |
|---|---|
| `info` | The language id, the entry point, and one line per section: its name, its vma, its size, whether it holds code, and its range in the file. |
| `symbols` | The function symbols as `address name`, and the data symbols with their size. |
| `symbols --filter REGEX` | Only the symbols whose name matches the regular expression. |
| `disasm TARGET` | The blocks of the function: a `; block 0x…` header with its successors, then `address bytes mnemonic operands` for each instruction. |
| `cfg TARGET` | The control-flow graph of the function: a `block 0x… - 0x…` header per block, with its successors and the addresses of its instructions, then the edges, each marked `fall-through` or `taken`. |
| `calls [TARGET]` | With a function, the calls it makes and the functions that call it. Without one, the whole call graph: every function with the calls it makes and the calls it gets, the functions reachable from the entry point, and the functions nothing calls. |
| `strings` | The strings the image holds: the address, the section, the text, and the functions that use it. |
| `strings --filter REGEX` | Only the strings whose text matches the regular expression. |
| `strings --utf16` | The strings that are held as UTF-16LE. |

`--json` is on every subcommand, and reports the same thing as JSON: `info` gives the
language, the entry point and the sections; `symbols` gives the functions and the data
symbols; `disasm` gives the blocks, their instructions, and the calls the function makes;
`cfg` gives the blocks and the edges between them; `calls` gives the calls of one function
or of the whole image; `strings` gives the strings and the functions that use them. Every
address is reported twice, as a number and as a hex string.

`disasm` takes the function as an address (`0x1198`) or as a name (`main`). A name is
matched loosely: an exact name first, then a substring. A direct call prints the name of
the function it calls, when that function has one.

`info` and `symbols` read any format the loader reads. `disasm` decodes x86-64, so it
refuses an image of another architecture rather than printing nonsense.

`strings` reads the sections that are not code, and reports every run of text that ends
in a NUL. A tab, a newline and a carriage return are part of the text, and they are
written out as `\t`, `\n` and `\r`, so a string never breaks the line it is printed on.
A section that is not mapped into memory holds text as well — the debug sections do — but
it has no address, so it is left out.

Who uses a string is found from the instructions that point at it, which needs the whole
program read. The wide strings are not in that index, so they are reported without users.

`cfg` reports the graph the Graph tab of the workbench draws: the blocks the walk found,
and the ways the code goes from one block to the next. An edge that leaves the end of a
block is the fall-through; every other edge is a branch that is taken. It is one rule, in
one place, so the workbench and the command line name an edge the same way. Its JSON shape is
the one a graph tool can be fed directly: `blocks`, with the `from`, the `to` and the
instructions of each block, and `edges`, with the `from`, the `to` and the `kind` of each
one.

`calls` reports who calls whom, which needs the whole program read. With a function it
gives the calls that function makes, with the address of every call site, and the
functions that call it. Without one it gives the whole call graph, and the two facts the
summary of the workbench shows: the functions reachable from the entry point, and the
functions that nothing calls.

## The embedded manual and agent skill

The `ag` binary carries its own documentation and an agent skill, so a session with no
checkout and no network can still read the reference and learn to drive the tool.

```sh
# List the embedded manual's topics
ag docs

# Print one topic
ag docs cli

# Install the agent skill where coding agents load skills
ag install-skill --agent claude
```

`ag install-skill` writes the skill offline, into `$CLAUDE_CONFIG_DIR/skills`,
`$CODEX_HOME/skills` or `$OPENCODE_CONFIG_DIR/skills` (or the project directory with
`--project`). `ag docs` prints the manual: the command reference, the corpus format and
the workbench.

| Command | What it does |
|---|---|
| `ag docs` | Lists the embedded topics. |
| `ag docs TOPIC` | Prints one topic to stdout. |
| `ag install-skill --agent A` | Installs the skill for `claude`, `codex`, `opencode` or `all`. |
| `ag install-skill --project` | Installs into the current directory, to commit alongside a repo. |
| `ag install-skill --dir DIR` | Installs into `DIR/<skill-name>/` for any other agent. |
| `ag install-skill --print` | Writes the skill to stdout and installs nothing. |
| `ag install-skill --force` | Replaces an installed copy that differs. An identical copy is left alone. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The command ran, or the skill was installed or already current. |
| 1 | A write failed, or a differing skill copy was kept. |
| 2 | A usage error: an unknown option, an unknown topic, or no agent to install for. |
