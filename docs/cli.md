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

# The pseudocode of one function, as C
cargo run --bin ag -- image ./sample.elf pseudocode main

# The same with an engine option set: the counted loop left as a while
cargo run --bin ag -- image ./sample.elf pseudocode sum_to --option loop-form while

# The control-flow graph of one function
cargo run --bin ag -- image ./sample.elf cfg main

# Who calls whom
cargo run --bin ag -- image ./sample.elf calls

# The strings of the image, and the functions that use them
cargo run --bin ag -- image ./sample.elf strings

# The data of the image, and the functions that use it
cargo run --bin ag -- image ./sample.elf data

# All of the above, written as a directory of JSON and text
cargo run --bin ag -- image ./sample.elf export ./sample.ag
```

## `ag image` subcommands

| Subcommand | What it prints |
|---|---|
| `info` | The language id, the entry point, and one line per section: its name, its vma, its size, whether it holds code, and its range in the file. |
| `symbols` | The function symbols as `address name`, and the data symbols with their size. |
| `symbols --filter REGEX` | Only the symbols whose name matches the regular expression. |
| `disasm TARGET` | The blocks of the function: a `; block 0x…` header with its successors, then `address bytes mnemonic operands` for each instruction. |
| `pseudocode TARGET` | The function as C — its calls, branches and loops structured into `if`/`else`, `while`, `do`/`while`, `for` and early `return`: a `// name at 0x…` header, then a comment that says what decided the return type (`// returns int: main reads eax after the call`, `// void: no caller reads the result`), then the signature, the locals and the statements. A `jmp` to another function is `return callee(args);` — or `callee(args); return;` when nothing in the image reads the result — and a function that is only that jump — a PLT stub — is the one line `// thunk for callee`. A function the lifter refuses prints the header with `not lifted yet` and the reason, and exit code 1. |
| `pseudocode TARGET --option NAME VALUE` | The same with an engine option set, such as `--option loop-form while`; the flag repeats. `ag catalog` lists the options. |
| `cfg TARGET` | The control-flow graph of the function: a `block 0x… - 0x…` header per block, with its successors and the addresses of its instructions, then the edges, each marked `fall-through` or `taken`. |
| `calls [TARGET]` | With a function, the calls it makes and the functions that call it. Without one, the whole call graph: every function with the calls it makes and the calls it gets, the functions reachable from the entry point, and the functions nothing calls. A `jmp` out of a function — to a function the image names, or through a GOT slot it resolves to an import — is a call marked `(tail call)`. |
| `strings` | The strings the image holds: the address, the section, the text, and the functions that use it. |
| `strings --filter REGEX` | Only the strings whose text matches the regular expression. |
| `strings --utf16` | The strings that are held as UTF-16LE. |
| `data [TARGET]` | The data of the image: the address, the section, the name, and the functions that use it. With a function, the data that function refers to. With a piece of data, the functions that use it. |
| `export DIR` | The whole analysis, written to `DIR` as files: `info.json`, `symbols.json`, `strings.json`, `data.json`, `calls.json`, one `functions/<address>.json` and `functions/<address>.asm` per function, an `index.json` and a `README.md`. One line on stdout: the functions, the files and the bytes written. |
| `export DIR --functions REGEX` | Only the per-function files of the functions whose name matches the regular expression. |
| `export DIR --force` | Write into a directory that is not empty. |
| `export DIR --option NAME VALUE` | Lift every function with an engine option set; the flag repeats. `index.json` and the `README.md` record the options that differ from the defaults. |

`--json` is on every subcommand, and reports the same thing as JSON: `info` gives the
language, the entry point and the sections; `symbols` gives the functions and the data
symbols; `disasm` gives the blocks, their instructions, and the calls the function makes;
`pseudocode` gives the text, the `return_type` and the `return_reason` that decided it, and
the lines, each with the addresses it came from, or `lifted: false` and the `reason`; `cfg` gives the blocks and the edges between them; `calls` gives the calls of one function
or of the whole image; `strings` gives the strings and the functions that use them; `data`
gives the data and the functions that use it. Every address is reported twice, as a number
and as a hex string.

`disasm` takes the function as an address (`0x1198`) or as a name (`main`). A name is
matched loosely: an exact name first, then a substring. A direct call prints the name of
the function it calls, when that function has one.

`info` and `symbols` read any format the loader reads. `disasm` decodes x86, 32-bit and
64-bit, taking the width from the image's language (`x86:LE:32:...` or `x86:LE:64:...`), so
it refuses an image of another architecture rather than printing nonsense. In 32-bit code
there is no `rip`, so the strings and the data a function refers to are found through the
absolute memory operands it names them with.

`pseudocode` lifts one function to C with the engine's own lifter, which reads the whole
control-flow graph of x86-64 code: integer `mov`, `movsx`, `movzx`, `cdqe`, `add`, `sub`,
`and`, `or`, `xor`, `inc`, `dec`, `imul`, `lea`, `push`, `pop`, `leave`, a direct `call`,
`cmp`, `test`, `jmp`, the conditional jumps and `ret`. Blocks joined only by fall-through
are one node of the graph; the graph is structured with its dominators and the back edges
that make its loops. A node that branches is an `if`, and its join is the nearest node both
arms reach that the branch dominates; an arm that returns is an early `return` and the other
arm follows it unnested. A loop whose header branches out is a `while`, one whose latch
branches back is a `do`/`while`, and any other is `while (1)` with a `break` at its exit;
inside a loop an edge to the header is `continue`. A `for` is folded from
`init; while (cond) { …; step }` when the init and the step assign the variable the condition
reads. A node reached twice that neither arm dominates is a `goto` to a label on it, and a
loop with two entries is refused as irreducible. Registers are temporaries and stack slots
are locals, so a value copied through the frame comes back as the expression it was; the
state is split at a branch and merged at a join, where a slot or register that differs
between the paths becomes a declared variable assigned on each — a slot keeps its
`local_<hex>` name, a register is named after itself, `eax` — and a loop is lifted again with
everything it changes made a variable, until it settles. A condition comes from the
instruction that set the flags: `cmp a, b; jl` is `a < b`, `jb` is the unsigned
`(unsigned int)a < (unsigned int)b`, and `test x, x; je` is `x == 0`. The argument registers
read before they are written are the parameters, named by position (`a`, `b`, …), with
`rdi, rsi, rdx, rcx, r8, r9` under System V and `rcx, rdx, r8, r9` for a Windows image; a
call passes the argument registers written before it, and its result is a temporary (`v1`,
`v2`, …) that is inlined where it is used once and declared where it is used more. The
return is decided from use, not presence: when the image knows the function's callers, a
caller that reads `eax`/`rax` after the call — a store, a compare, a move into another
register, an argument to the next call — makes the function return a value at the width of
the widest read, and callers that all write or ignore it make it `void` (a caller that
carries the value untouched to its own `ret` passes the question to its callers); with no
caller in the image, a value at a `ret` counts only if the function wrote `rax` itself on
that path, and a callee's result left untouched there, read by nothing else in the function,
is dead. The decision opens the function as a comment — `// returns int: main reads eax after
the call`, `// void: no caller reads the result`, `// void: no caller in the image, and rax at
the ret holds only deregister_tm_clones's result, which nothing reads` — and is the
`return_type` and `return_reason` of the JSON; every `ret` must agree on what is live, and
`--option return-liveness presence` restores the old rule, `rax` at the width of its last
write, whatever reads it. A width is a type: 32 bits is `int`, 64 is `long`. A pointer taken
through `lea` is asked of the image: one that lands on a string
prints as the string's literal, one that lands on named data as `&name`, and one on a
function as its name; a load through a pointer is `*(int *)p`, and one from an address the
image does not name is `*(int *)0x…`. A `jmp` out of the function is a tail call: a node that
ends in a `jmp` to another function — direct, or through a GOT slot the image's dynamic
relocations name as an import, or through a register that holds one — with the stack back
where it was at entry is lifted as the `call` and the `ret` it stands for, `return callee(args);`,
the arguments from the register state as a call's, and the callee's result returned at the
width the callers read it — or, when nothing in the image reads it, the call followed by a
bare `return;`; a function that is only the jump, behind at most `endbr64` and `nop`s — a PLT
stub, a forwarding stub — is a thunk, and its whole pseudocode is the one line
`// thunk for callee`, which carries every instruction of the stub. A `jmp` to an address inside
the function is an edge of the graph. The sample's `add` reads
`int add(int a, int b) { return b + a; }`, the operands in the order the `add` instruction
names them; its `main` reads

```c
long main(int a, long b)
{
  long v2;

  v2 = sum_to(add(a, 3));
  printf("%ld\n", v2);
  return v2;
}
```

and its `sum_to`, a counted loop, reads

```c
long sum_to(int a)
{
  long local_10;
  int local_14;

  local_10 = 0;
  for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {
    local_10 = local_10 + (long)local_14;
  }
  return local_10;
}
```

and its `printf` stub — `endbr64; bnd jmp [rip+0x2f75]`, through the GOT slot of `printf` —
reads as the one line `// thunk for printf`, as `frame_dummy`, which is `endbr64; jmp
register_tm_clones`, reads `// thunk for register_tm_clones`; its `deregister_tm_clones`
ends in a `jmp rax` with `rax` loaded from the GOT slot of `_ITM_deregisterTMCloneTable`,
and that path reads `return _ITM_deregisterTMCloneTable(&completed.0);` under the guard
`if (rax != 0)`, the merged `rax` being what the bytes say. Its two `lea`s name the same
address, so the `cmp` of them can only go one way: the condition is printed as the constant
it is, `if (0) { // constant: &completed.0 != &completed.0`, the comment carrying the
addresses the bytes compared — an address is a constant at the compare and keeps its
expression, where a value computed on the way reads the variable the join names — and the
`constant-conditions` option prints the comparison itself instead.

The start-up glue `__do_global_dtors_aux`, which one path leaves with `deregister_tm_clones`'s
result in `rax` and the other with nothing there, is `void` — the value is a callee's that
nothing reads, and its comment says so — where deciding from presence alone would refuse it
for returning a value at one `ret` and nothing at another.

A function with an instruction outside that set, a 32-bit function, an indirect call, a
`jmp` to an address outside the function that no symbol names (`jumps to 0x…`) or through a
register or memory that holds no function the lifter can name (`an indirect jump at 0x…`),
a `jmp` out with the stack not back at its entry value, a branch whose flags no tracked
instruction set (`the je at 0x… reads flags that nothing tracked set`), a loop with two
entries (`irreducible control flow at 0x…`), a stack pointer that differs between two paths,
`ret`s that disagree, or a value the lifter cannot follow prints `not lifted yet` and the
reason instead, with exit code 1 — the sample's `_init`, which calls through a register, says
`not lifted yet: an indirect call`, its `_start`, which aligns the stack with `and rsp, -16`,
says `the stack pointer is not tracked`, and its `register_tm_clones` says `shr`; `--json`
reports the same as `lifted: false` and a `reason`. Every line of C carries the addresses of
the instructions it came from — a `for` line those of its init, its compare, its branch and
its step — which is what the workbench's Pseudocode tab clicks through.

The judgment calls in all of that — whether the counted loop is a `for` or a `while`,
whether a `jmp` to another function is lifted as its `return callee(args);` or refused
(`tail-calls`), whether a tail two paths share is a `goto` or a copy, how a merged register (`eax`, `eax_2`)
and a stack slot (`local_14`) are named, whether a load from named data prints as the name
or as `*(int *)0x4010`, whether the operands of `b + a` keep the instruction's order, whether
an unsigned comparison is cast, whether a `cmp` no branch reads is dropped, which argument
registers are parameters, the calling convention, how a constant is spelled and how far a body
is indented — are the engine's *options*, and `pseudocode` and `export` take them with
`--option NAME VALUE`, repeated as needed:

```sh
cargo run --bin ag -- image ./sample.elf pseudocode sum_to --option loop-form while
cargo run --bin ag -- image ./sample.elf pseudocode add --option operand-order canonical
cargo run --bin ag -- image ./sample.elf export ./sample.ag --option constant-style hex --option indent 4
```

An option nobody registered, or a value the option does not take, is an error that names the
row and what it takes (`option "loop-form" takes for | while, not "sometimes"`), before the
image is read. `ag catalog` prints the registry, and `docs/options.md` — also `ag docs
options` — is its generated document, opening with the symptom index: *if the output shows
X, try `--option Y`*.

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
one. The walk is of the function alone: a `jmp` to the entry of another function the image
names, or through a GOT slot it resolves to an import, is a tail call — the block ends there
with no successor, and `calls` reports the call — while a jump inside the function, or to
an address no function is known at, is an edge as any other. So the sample's `frame_dummy`,
which is `endbr64; jmp register_tm_clones`, is one block of two instructions and no edges,
and `register_tm_clones`' blocks are its own; `disasm` lists the same blocks.

`calls` reports who calls whom, which needs the whole program read. With a function it
gives the calls that function makes, with the address of every call site, and the
functions that call it. Without one it gives the whole call graph, and the two facts the
summary of the workbench shows: the functions reachable from the entry point, and the
functions that nothing calls. A `jmp` that leaves a function is a call too — a tail call,
marked `(tail call)` in the text and `tail: true` in the JSON: one to a function the image
names goes to that function, and one through a GOT slot the dynamic relocations name — the
`jmp [rip+slot]` of a PLT stub — names the import, with the slot as its target and in `slot`.
So the sample's `printf` stub calls `0x3fd0 printf (tail call)`, and `frame_dummy` is a caller
of `register_tm_clones`. A `jmp` through a register is not resolved here; the lifter reads
what the register holds, and `pseudocode` shows it. In the listing a direct jump names the
function it goes to, like a call, and a jump through a slot keeps its `[rip+…]` operand.

`data` reports the data of the image. A function refers to data when one of its
instructions points at it: the pointer lands in a section that holds no code. A pointer
that lands on a string is a string reference, and is not reported as data. The symbol that
holds the address is the one that is named, so a pointer into the middle of a symbol names
that symbol. Who uses a piece of data needs the whole program read, so the whole image and
the reverse lookup both cost that. The target is read as a function first and as a piece
of data after: an address (`0x4010`) or a name (`completed.0`).

`export` writes, in one pass, what the other subcommands print, so an agent can read the
whole analysis offline without running six commands. `info.json`, `symbols.json`,
`strings.json`, `data.json` and `calls.json` are what `info`, `symbols`, `strings`, `data`
and `calls` print under `--json` for the whole image, byte for byte. `functions/<address>.json`
holds one function — its `cfg`, its `calls`, the `data` it refers to and its `pseudocode`,
each what that subcommand prints under `--json` for the function, so a function the lifter
refuses carries `lifted: false` and the `reason` rather than failing the export — and
`functions/<address>.asm` is the listing `disasm` prints. `<address>` is the entry address
as `ag` prints it, `0x1149`. `index.json` lists every function that was written, with its
files, and names the binary, its SHA-256, the `ag` version, the language, the entry point
and the time the export was written, UTC; `README.md` says the same in a table whose
`| Path |` row is the one a kuna project export's README has, so the reader that finds the
binary of an export finds this one's too. The directory is made when it is not there. One
that is not empty is refused unless `--force` is given, and then it is written over and
nothing in it is removed, so `index.json` is the list of what the last run wrote.
`--functions` limits the per-function files, with the regular expression `symbols --filter`
takes; the whole-image files are never limited. A function the decoder cannot reach — a
symbol in no code section — gets no files, and a warning on stderr names it. An image the
decoder does not read is refused, like `disasm`. An error names the file it could not write.

## The project file: `ag project`

A project file (`.agproj`) records what was analysed — the target's path and SHA-256 — the
analysis options the run used, and the analyst's own changes: names, comments, bookmarks,
tags, colors and byte types, each keyed by address. It is versioned JSON, so it survives a
session, travels between machines, and stays readable without this program. The workbench
opens and saves the same file. See `ag docs project-format` for the format itself.

```sh
# Create a project file for a binary, recording two options
ag project ./bin/ls save --out ls.agproj --option-pair loop-form=while

# Record a rename, a comment and a bookmark
ag project ./bin/ls rename --file ls.agproj 0x1198 main
ag project ./bin/ls comment --file ls.agproj EXTERNAL:0x1 "imported qsort"
ag project ./bin/ls bookmark --file ls.agproj 0x1198

# Name a label at an address, or a local variable of the function there
ag project ./bin/ls label --file ls.agproj 0x1198 start_here
ag project ./bin/ls var --file ls.agproj 0x1161 local_14 count

# Report what it holds, as text or JSON
ag project ./bin/ls show ls.agproj
ag project ./bin/ls show ls.agproj --json
```

The target binary comes first: it is what the project describes, and `show` re-hashes it to
say so when it no longer matches the recorded SHA-256. Addresses are written the way a
corpus writes them, with the address space when the record names one (`EXTERNAL:0x1`). An
edit to a project file that does not exist yet creates it from the target. A file whose
`format` is newer than this program reads is refused with a notice, not misread.

| Command | What it does |
|---|---|
| `ag project TARGET save --out FILE` | Creates a project file for `TARGET`, hashing it; `--option-pair NAME=VALUE` records an option (repeatable). Refuses an existing `FILE` without `--force`. |
| `ag project TARGET show FILE` | Prints what the project holds; `--json` prints the file itself. |
| `ag project TARGET rename --file FILE ADDRESS NAME` | Records a name for the function at `ADDRESS`. |
| `ag project TARGET label --file FILE ADDRESS NAME` | Records a name for the label at `ADDRESS`. The entry label of a function and the function's name are the same record. |
| `ag project TARGET var --file FILE ADDRESS VARIABLE NAME` | Records a name for the local variable `VARIABLE` of the function at `ADDRESS`, as the pseudocode declares it. |
| `ag project TARGET comment --file FILE ADDRESS TEXT` | Records a comment at `ADDRESS`. |
| `ag project TARGET bookmark --file FILE ADDRESS` | Flips a bookmark on the function at `ADDRESS`. |

## `ag catalog`: the engine's options

Every judgment call the engine makes is a row of one registry
(`crates/ag-engine/src/options.rs`): its name, the phase that reads it (`decode`, `lift`,
`structure`, `emit`), its tier (`transform`, `analysis`, `rendering`), what it takes, its
default, one line of description, and its *symptoms* — what the output looks like when you
want to flip it. `ag catalog` prints that registry.

```sh
# The document, symptom index first: if the output shows X, try --option Y
ag catalog --markdown

# The same rows as JSON
ag catalog --json

# Does the committed docs/options.md match the registry? Exit 1 when it is stale.
ag catalog --check
```

| Command | What it does |
|---|---|
| `ag catalog` | The same as `--markdown`. |
| `ag catalog --markdown` | Prints the catalog as Markdown: the symptom index, then one section per phase with a table of its options, then what the tiers mean. This is what `docs/options.md` holds. |
| `ag catalog --json` | Prints the rows as a JSON array: `name`, `phase`, `tier`, `type` (`{"choice": […]}` or `{"integer": {"min", "max"}}`), `default`, `description` and `symptoms` (`shows`, `value`). |
| `ag catalog --check` | Reads `docs/options.md` and compares it with `--markdown`. Prints `is current` and exits 0 when they match; names the first line that differs and exits 1 when they do not. |
| `ag catalog --check --path FILE` | Compares `FILE` instead. |

`docs/options.md` is generated: regenerate it with `ag catalog --markdown > docs/options.md`
after changing the registry. A test in `ag-cli` does the same comparison against the copy
compiled into the binary, so `cargo test` fails on drift as well.

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
`--project`). `ag docs` prints the manual: the command reference, the corpus format, the
engine's options and the workbench.

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
| 1 | A write failed, a differing skill copy was kept, a function was not lifted, or `catalog --check` found `docs/options.md` stale. |
| 2 | A usage error: an unknown flag, an unknown topic, or no agent to install for. An unknown engine option or a bad value under `--option` is reported as an error, exit code 1, naming the row and what it takes. |
