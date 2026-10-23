# The `ag` CLI reference

`ag` reads an indexed decompilation corpus, or a kuna project export, and reports on it.
Every subcommand lives under `corpus`, because both sources are described the same way.

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
