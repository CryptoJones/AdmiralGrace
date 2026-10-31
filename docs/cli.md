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
own loader rather than read out of a corpus — or raw bytes, with `--raw ARCH --base ADDRESS`
before the subcommand: firmware, shellcode, a dump, a file with no container to say where
it loads. `ARCH` is `x86-64`, `x86`, `arm`, `thumb` (Cortex-M: Thumb throughout, under the ARMv7
specification) or `aarch64`; the base cannot be 0, where nothing is mapped;
`--entry`, `--offset` into the file and `--length` apply when they are not the start and the
rest of the file. The bytes are one section of code, and the entry, when named, is a
function. `ag project TARGET --raw … save` records the same in the project file, and every
command that reads the project reads the target that way after, flags or not.

An Objective-C Mach-O describes its classes, categories and protocols in its `__objc_*`
sections, for the runtime to register at load; `ag image FILE objc` prints them, and every
method's implementation is a function under its runtime name — `-[Class sel]`, `+[Class
sel]`, `-[Class(Category) sel]` — in every report, symbols or none. An instance method's name
starts with `-`, so `--` goes before it on the command line: `ag image app disasm -- '-[Foo
bar:]'`. The pointers of an image linked for macOS 12 or iOS 15 and later are chained
fixups, and are resolved before they are followed; a class of another image — a superclass,
or the class a category extends — is bound at load, so a category on one names the class
`?`. (The external method map `ag corpus … --methods` takes is for a corpus; an image needs
none.)

A C++ or Rust image names its functions by mangled symbols — Itanium (`_ZN8geometry4areaEii`,
on ELF and Mach-O), Microsoft (`?area@geometry@@YAHHH@Z`, on PE) or Rust (`_ZN4core3fmt5write17h…E`,
`_R…`). Every report shows them demangled, signature kept, so two overloads read apart:
`geometry::area(int)` and `geometry::area(int, int)`. The mangled name is kept beside the shown
one: `symbols --json` carries it as `mangled`, and a command that takes a function or a piece of
data by name — `disasm`, `cfg`, `pseudocode`, `data` — takes the mangled name too. The
pseudocode, where a name stands in code, uses the scope and the name alone: `geometry::area(2,
3)`. `--filter` is a regular expression, so the brackets and question marks of a signature or a
Microsoft name want escaping: `--filter 'area\(int'`.

An image's unwind data — an ELF's `.eh_frame`, a PE's `.pdata`, a Mach-O's `__unwind_info` and
`__eh_frame` — records the start and the end of nearly every function, since an exception has
to unwind through each frame, and a stripped binary keeps it. Every function it names is in the
function list, under its symbol or, with none, as `sub_` and its address; `symbols --json`
carries each function's `end` where the unwind data says, and the workbench's inspector sizes
a function by it.

A Swift Mach-O describes its types in its `__swift5_*` sections, for the runtime and for
reflection: `ag image FILE swift` prints them — each class, struct and enum with its module,
its superclass, its fields or cases with their types, the protocols it conforms to and, for a
class, the methods its vtable dispatches with each implementation's address — and each
protocol. Swift names are demangled everywhere like C++ ones (`sample.Derived.greet(times:
Swift.Int) -> Swift.Int` for `$s6sample7DerivedC5greet5timesS2i_tF`), the mangled name kept
beside; a vtable entry no symbol names is a function under `Type.<kind>#N` — `sample.Base.getter#0`,
`sample.Base.method#4`. The types inside
the records are decoded the same way, symbolic references followed to the descriptor they
name.

`--option dead-code drop` prunes the pseudocode of the statements whose results nothing uses
— a variable assigned and never read, or assigned again before it is read, a branch whose
condition can only go one way — keeping a call a dropped assignment held, as the call it is;
the default, `keep`, shows the code as it was made.

The pseudocode reads a call of the runtime's dispatcher — `objc_msgSend` and its variants, for
the superclass and for a struct result — as the message it sends, the selector resolved from
the selector reference the code loads: `[0 greet:[Base answer]]`, `[a twice:c] + 1`, a class
by its name where a class reference was loaded, `super` where the superclass's dispatcher is
called, one argument per colon of the selector. The dispatcher is reached through its import
slot, which a Mach-O's indirect symbol table names, so a call through a register loaded from
the slot lifts like a direct one. A send whose selector the lifter did not resolve reads as the
call it is.

`ag image FILE objc --header` writes the same as an Objective-C header — the quickest
overview of such a binary: every protocol, class and category declared, with its properties,
instance variables and methods under the types the runtime's encodings say (`i20@0:8i16` is
`- (int)greet:(int)arg1;`). Every class and protocol is forward-declared first, those of other
images marked as such; the structs the encodings spell out are defined, each after the structs
it holds; a protocol comes before the protocol that adopts it, a superclass before its subclass,
a class before its categories; a category on a class of another image is kept as a comment; a
property's accessors are not listed again as methods; where an encoding is missing, the type is
`id`. The header compiles against the runtime's `objc/objc.h` where the image is whole; a
superclass or a type of another image needs that image's headers too. `export` writes it as
`objc.h`, beside `objc.json`, when the image has Objective-C.

A universal (fat) Mach-O holds several images, one per architecture. `ag image FILE slices`
lists them, and `--slice ARCH` (or the slice's position, from 0) before the subcommand says
which one to read: `ag image app --slice arm64 disasm main`. Opened without one, the file is
refused with its slices named. `ag project TARGET --slice … save` records the choice, and
every command that reads the project reads that slice after; a `--slice` that names another
is refused. The file offsets `info` prints for a slice are the slice's own, measured from
where it starts in the file.

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

# Raw bytes: a Thumb firmware image loaded at 0x8000000, its entry named
cargo run --bin ag -- image ./firmware.bin --raw thumb --base 0x8000000 --entry 0x8000101 disasm 0x8000100

# A universal Mach-O: its slices, and one of them read
cargo run --bin ag -- image ./app slices
cargo run --bin ag -- image ./app --slice arm64 symbols
```

## `ag image` subcommands

| Subcommand | What it prints |
|---|---|
| `swift` | The Swift a Mach-O describes: each type with its kind, module, superclass, fields or cases (with their types), conformances and vtable methods (with the implementation's address), and each protocol; `--json` gives the same as JSON. |
| `objc` | The Objective-C a Mach-O describes: each class with its superclass, protocols, properties, instance variables and methods (`+` class, `-` instance, with the implementation's address and the type encoding), each category on a class, each protocol with its required and optional selectors; `--json` gives the same as JSON; `--header` writes it as an Objective-C header, declarations in dependency order and types decoded from the encodings. The methods' code is in `symbols`, `disasm`, `calls` and the rest under its runtime name — `-[Class sel]`, `+[Class sel]`, `-[Class(Category) sel]` — from the metadata alone, so a stripped image is named too. |
| `slices` | The slices of a universal (fat) Mach-O — each architecture in the file, with its position, offset and size — or that the file is one image. The only subcommand that reads a universal file whole; the rest take `--slice`. |
| `info` | The language id, the entry point, and one line per section: its name, its vma, its size, whether it holds code, and its range in the file. With `--project FILE`, `info` and `symbols` read the image under the project's layout — its base and its segments — as `disasm`, `cfg` and `pseudocode` do. |
| `symbols` | The function symbols as `address name` — the functions the unwind data alone knows as `sub_<address>` — and the data symbols with their size; `--json` carries each function's `end` where the unwind data says. A C++ or Rust name is shown demangled, with its signature — `geometry::area(int, int)` for `_ZN8geometry4areaEii` or `?area@geometry@@YAHHH@Z` — and `--json` carries the mangled name beside it as `mangled`; `--filter` matches either. |
| `symbols --filter REGEX` | Only the symbols whose name matches the regular expression. |
| `disasm TARGET` | The blocks of the function: a `; block 0x…` header with its successors, then `address bytes mnemonic operands` for each instruction. |
| `pseudocode TARGET` | The function as C — its calls, branches and loops structured into `if`/`else`, `while`, `do`/`while`, `for` and early `return`: a `// name at 0x…` header, then a comment that says what decided the return type (`// returns int: main reads eax after the call`, `// void: no caller reads the result`), then the signature, the locals and the statements. A `jmp` to another function is `return callee(args);` — or `callee(args); return;` when nothing in the image reads the result — and a function that is only that jump — a PLT stub — is the one line `// thunk for callee`. A function the lifter refuses prints the header with `not lifted yet` and the reason, and exit code 1. |
| `pseudocode TARGET --option language c\|rust\|objc\|python` | The same lift, spelled each language's way: C; Rust (`fn sum_to(a: i32) -> i64 {`, `let mut local_14: i32;`, `x as i64`, `match`, `loop` for a do-while); Objective-C (C with `YES` and `NO`); Python (`def sum_to(a):`, blocks by indentation, `and`/`or`, `True`, `x if c else y`, the locals as a `# locals:` comment). The workbench's pseudocode pane and the MCP server's `decompile` take the same `--option`. |
| `pseudocode TARGET --option NAME VALUE` | The same with an engine option set, such as `--option loop-form while`; the flag repeats. `ag catalog` lists the options. |
| `pseudocode TARGET --option indirect-calls lift\|refuse` | Whether a call or a jump through a value the lift knows — a parameter, a loaded field — is the call through it, `a(b, 1)`, or refused as `an indirect call`. A Windows control-flow guard's dispatch reads as the call it guards and its check is dropped. See `docs/il.md`. |
| `pseudocode TARGET --option struct-initializers recognize\|keep` | Whether a run of stores through one pointer at distinct offsets reads as one struct initializer — `*(struct { int at_0; int at_4; long at_8; } *)a = { b, 2, 7 };` — or stays the stores they are. See `docs/il.md`. |
| `pseudocode TARGET --option builtins recognize\|keep` | Whether the constant stores that put a string on the stack read back as one `__builtin_strcpy(&local, "text")` (or a `__builtin_memcpy` of bytes with no NUL), or stay the stores they are. `rep movs` and `rep stos` read as `__builtin_memcpy` and `__builtin_memset` either way. See `docs/il.md`. |
| `pseudocode TARGET --option brace-style broken\|ternaries expand\|wrap N\|call-hints names` | How the text is laid out: `brace-style broken` puts each control statement's `{` on a line of its own under its head and `else` on its own line (C and Objective-C; Rust keeps its braces attached, Python has none); `ternaries expand` writes `x = c ? a : b;` as an `if`/`else` assigning in each arm, and a return of one as two returns; `wrap N` breaks a statement longer than `N` columns between a call's arguments, the rest indented two levels; `call-hints names` labels each argument with the callee's parameter name — `sum_to(/* a */ add(a, /* b */ 3))`, or `add(a=1, b=2)` in Python, where every argument has a name — where the callee is a function of the image; an argument that is the parameter's own name takes no label. The workbench's View menu adds rainbow braces and indent guides, which are drawing, not text. A registered formatter plugin has the last word on the lines (`docs/plugins.md`). |
| `pseudocode TARGET --json` | The same as JSON: each line with the addresses it came from, and `dead` on a line the `dead-code` option kept that its `drop` would take out — a store nothing reads, a branch that can only go one way — so a reader can grey it out. A project's `stores drop` words (`--project FILE`) take one variable's dead stores out while the rest stay. |
| `pseudocode TARGET --slice VAR[@ADDRESS] [--forward] [--slice-hide]` | The pseudocode sliced: backward (the default), the statements the value of `VAR` depends on; `--forward`, the statements it affects. The value is taken at the statement at `ADDRESS` — any of the addresses of its line, which `--json` lists — or, without one (or with `@end`), at the function's end; `return` at the end is the value the function returns. At a statement that assigns `VAR`, the slice runs from that assignment; at one that reads it, from the statement and the assignments reaching it (backward) or from the statement and what it defines (forward); forward from the end runs from every assignment of `VAR` and its value at the entry. A statement depends on the assignments of what it reads that reach it — through loops, to a fixed point — and on the conditions that decide whether it runs: the `if`, loop and `switch` holding it, and a branch one path of which leaves before it, such as an `if` whose arm returns. A call reads and may write all memory — what pointers point at, a variable whose address is taken, a name the function does not declare — and so may a store through a pointer: a call whose arguments or result reach the value is in a backward slice, with every store and call before it that wrote memory, and every read of memory after a call or a store a forward slice holds is in it too. The lines outside the slice are commented out where their text begins, or left out with `--slice-hide`; the control statements holding a kept statement, the signature, the declarations and the braces stay. A second header line says the slice: `// backward slice of local_14 at the end`. `--json` marks each line `in_slice` and names the `slice` (`variable`, `address`, `direction`). A variable or a statement the function lacks is an error. |
| `symbols\|disasm\|cfg\|calls … --option NAME VALUE` | The engine's decode options, which change what the walk finds: `branches-end-procedures yes` makes a branch out of a procedure's range a tail call, and `code-sections procedures` lists every run of instructions no named function reaches as a `sub_` procedure. The flag repeats; `ag catalog` lists the options. |
| `cfg TARGET` | The control-flow graph of the function: a `block 0x… - 0x…` header per block, with its successors and the addresses of its instructions, then the edges, each marked `fall-through` or `taken`, then the jump tables the function's indirect jumps read, each with its cases. `--project FILE` tells the walk the project's jump-table notes. `--svg PATH` or `--pdf PATH` draws the graph as a picture instead — the blocks in rows, every instruction a line, fall-throughs blue and taken branches orange — for a report; both may be given, neither with `--json`. |
| `il TARGET [--level lifted\|low\|medium\|high] [--ssa]` | The function at one level of the lift — the machine's instructions, the lifter's statements over temporaries and slots, the statements over variables on the block graph, or the structured body — each item with the addresses it came from; `--ssa` for the static single assignment form, every definition a version and a φ where paths meet. `medium` unless said. A function the lifter refuses prints `not lifted yet` with the reason, exit code 1. See `docs/il.md`. |
| `transpile TARGET… [--all] [--no-follow] [--harness TARGET] [--out FILE]` | Writes the functions as C++ that compiles: the medium level of each, a label per block and a `goto` for every way out, the globals they name defined with the image's bytes, the imports declared, every function of the image they call written too unless `--no-follow`; `--harness` adds a `main` that calls that function with the command line's numbers and prints what it returns. To standard output, or to `--out FILE`. See `docs/il.md`. |
| `emulate TARGET [--arg N]… [--steps N] [--depth N]` | Runs the function on its medium level against the image's memory, the arguments its parameters in order: each statement as it ran, what it wrote, the stop — returned with a value, the step limit, or a branch, switch, return or address depending on a value the run does not know — and the variables at the end. A call to a function of the image is followed `--depth` deep; any other call's result is unknown. `--json` for the steps, the stop, the value returned, the variables and the memory written. See `docs/il.md`. |
| `opaque TARGET… [--all] [--json] [--project FILE]` | The opaque predicates of the functions: the conditional branches whose condition is decided whatever the input, one line each — the branch's address, the function, `always taken` or `never taken`, and why. Read off the lifted conditions — a value compared with itself (`x != x`, `x - x == 0`, `x ^ x`), the arithmetic an obfuscator hides a constant in (`x * (x + 1)` and `x * x + x` are even, so their low bit is clear and `% 2` is 0; `x \| 1` is odd, so never 0; an unsigned value is never below 0), in any order of the operands and through the variables the block assigned, and a condition over constants — and off the instructions themselves, block by block: the constants moved into registers and the flags set to known values, as `xor eax, eax; test eax, eax; jnz`, `stc; jc`, `clc; jnc` and `cmp eax, eax; jne` leave them, which needs no lift, so a function the lifter refuses is read too. The why is short: `x * (x + 1) is always even`, `eax is 0 here`, `stc sets the carry`. `--json` adds the target and the bytes that patch each out. x86 only. `--project FILE` reads the image with the project's patches, so one patched out is not found again. |
| `il TARGET --opcodes --flags --stack-pointer --types --casts` | The same with notes beside each item: its opcode (the instruction's form, or the statement's kind), the flags an instruction reads and writes, the stack pointer's offset from the entry's, the type of every name; `--casts` spells every constant with its width and casts a value stored at another width. Each flag on its own. The JSON has them all without asking. |
| `calls [TARGET]` | With a function, the calls it makes and the functions that call it. Without one, the whole call graph: every function with the calls it makes and the calls it gets, the functions reachable from the entry point, and the functions nothing calls. A `jmp` out of a function — to a function the image names, or through a GOT slot it resolves to an import — is a call marked `(tail call)`. |
| `strings` | The strings the image holds: the address, the section, the text, and the functions that use it. |
| `strings --filter REGEX` | Only the strings whose text matches the regular expression. |
| `strings --utf16` | The strings that are held as UTF-16LE. |
| `data [TARGET]` | The data of the image: the address, the section, the name, and the functions that use it. With a function, the data that function refers to. With a piece of data, the functions that use it. |
| `export DIR` | The whole analysis, written to `DIR` as files: `info.json`, `symbols.json`, `strings.json`, `data.json`, `calls.json`, `objc.json` and `objc.h` when the image has Objective-C, `swift.json` when it has Swift, one `functions/<address>.json` and `functions/<address>.asm` per function, an `index.json` and a `README.md`. One line on stdout: the functions, the files and the bytes written. |
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
64-bit, taking the width from the image's language (`x86:LE:32:...` or `x86:LE:64:...`), and
little-endian ARM: 32-bit (`ARM:LE:32:...`) in both its instruction sets, ARM and Thumb — the
mode of each address comes from the image's symbols (a Thumb function's symbol has its low
bit set), from the analyst's `mode` marks in a project file, and from the instructions
themselves — and AArch64 (`AARCH64:LE:64:...`), which has one instruction set; so it refuses an
image of another architecture rather than printing nonsense. ARM and AArch64 are decoded,
walked and listed; they are not lifted to pseudocode yet. In 32-bit code
there is no `rip`, so the strings and the data a function refers to are found through the
absolute memory operands it names them with.

`pseudocode` lifts one function to C with the engine's own lifter, which reads the whole
control-flow graph of x86-64 code: integer `mov`, `movsx`, `movzx`, `cdqe`, `add`, `sub`,
`adc`, `sbb`, `and`, `or`, `xor`, `inc`, `dec`, `neg`, `imul`, `lea`, `push`, `pop`, `leave`,
a direct `call`, `cmp`, `test`, `bt`, `jmp`, the conditional jumps, `setcc`, `cmovcc` and
`ret`. Blocks joined only by fall-through
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
instruction set (`the je at 0x… reads ZF that nothing tracked set`) or that two instructions
set (`reads flags two instructions set: the cmp at 0x… and the inc at 0x…`), a loop with two
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

## Assembling one instruction: `ag asm`

```sh
ag asm "mov eax, 1"
ag asm "jmp 0x401010" --at 0x401000
ag asm "mov eax, [ebp+8]" --bits 32
```

Prints the bytes of one instruction, in Intel syntax, as it would sit at `--at` (a branch is
encoded against it) in a program of `--bits` 64 or 32. The assembler knows the instructions
patching reaches for and refuses anything else by name.

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
ag project ./bin/ls tag --file ls.agproj --on function 0x1198 crypto parser
ag project ./bin/ls tags ls.agproj
ag project ./bin/ls tags ls.agproj crypto
ag project ./bin/ls color --file ls.agproj --on function 0x1198 amber
ag project ./bin/ls color --file ls.agproj 0x11a0 none
ag project ./bin/ls xref --file ls.agproj 0x11a0 0x1300
ag project ./bin/ls mark --file ls.agproj 0x2010 data:4[8]
ag project ./bin/ls mark --file ls.agproj 0x1300 function
ag project ./bin/ls operand --file ls.agproj 0x1170 decimal
ag project ./bin/ls switch --file ls.agproj 0x1207 0x2000 6 --relative
ag project ./bin/ls asm --file ls.agproj 0x1198 "mov eax, 1"
ag project ./bin/ls patch --file ls.agproj 0x11a0 "90 90"
ag project ./bin/ls nop --file ls.agproj 0x1198
ag project ./bin/ls nop --file ls.agproj 0x11a0 --to 0x11a8
ag project ./bin/ls opaque --file ls.agproj --all --dry-run
ag project ./bin/ls opaque --file ls.agproj main
ag project ./bin/ls write-patched --file ls.agproj --out ls.patched

# On ARM, say which instruction set the code from an address onward is in
ag project ./firmware.elf mode --file fw.agproj 0x8000 thumb

# Correct the layout the image is read under; `ag image … --project` reads it
ag project ./bin/ls rebase --file ls.agproj 0x400000
ag project ./bin/ls segment --file ls.agproj rename .text code
ag project ./bin/ls segment --file ls.agproj add extra 0x405000 16 --file-offset 0x3000
ag project ./bin/ls segment --file ls.agproj remove .comment
ag image ./bin/ls info --project ls.agproj
ag asm "jmp 0x401010" --at 0x401000
ag image ./bin/ls cfg 0x1200 --project ls.agproj

# Name a label at an address, a local variable, or a register of the function there
ag project ./bin/ls label --file ls.agproj 0x1198 start_here
ag project ./bin/ls var --file ls.agproj 0x1161 local_14 count
ag project ./bin/ls reg --file ls.agproj 0x1161 rax total

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
| `ag project TARGET stores --file FILE ADDRESS VARIABLE drop\|keep` | Says whether the stores to the local variable `VARIABLE` of the function at `ADDRESS` that nothing reads are taken out of the pseudocode (`drop`) or left in (`keep`, the default) while the `dead-code` option keeps the rest. `ag image pseudocode … --project FILE` lifts with the word; the workbench's **Edit ▸ Drop dead stores of variable…** records one for the function on screen. |
| `ag project TARGET reg --file FILE ADDRESS REGISTER NAME` | Records a name for the register `REGISTER` within the function at `ADDRESS`, spelled as the listing spells it. The rename reaches that function's pseudocode and listing alone. |
| `ag project TARGET comment --file FILE ADDRESS TEXT` | Records a comment at `ADDRESS`; `--above` stands it on its own line over the instruction instead of inline. Empty `TEXT` clears the comment, placement and all. |
| `ag project TARGET bookmark --file FILE ADDRESS` | Flips a bookmark on the function at `ADDRESS`. |
| `ag project TARGET tag --file FILE ADDRESS TAG…` | Attaches one or more tags to the address; `--remove` takes them off, and `--on function` or `--on block` puts them on the function entered there or the block of bytes starting there. A tag is one word: it is trimmed, a space inside one becomes a hyphen, and `a,b` is two tags. |
| `ag project TARGET tags FILE [TAG]` | Prints every tag with how many places carry it; with `TAG`, the places carrying it, in address order. |
| `ag project TARGET xref --file FILE FROM TO` | Records that the code at `FROM` reaches `TO` — a computed call or jump the analysis cannot see; `--remove` takes the reference back. `TO` must be an address, spelled with its space when the analysis gave the place one (`EXTERNAL:0x1`), since the command cannot ask the analysis; the workbench's prompt adds the space itself. The workbench shows it in the inspector's references, marked manual, from both ends. |
| `ag project TARGET mark --file FILE ADDRESS KIND` | Says how the bytes at `ADDRESS` are read, correcting the analysis: `code`, `function`, `string`, `undefined`, `data`, `data:W` for items of 1, 2, 4 or 8 bytes, `data:W[N]` for an array of `N`; `none` takes the mark off. The workbench shows a data, string or undefined mark in place of the instructions it covers, and lists a function mark as a function. |
| `ag project TARGET operand --file FILE ADDRESS FORMAT` | Says how the constants in the operands of the instruction at `ADDRESS` are shown: `hex`, `signed`, `decimal`, `octal` or `address`. `hex` is how the analysis prints them, so it clears the record. |
| `ag project TARGET override --file FILE ADDRESS guard\|fold\|invert\|switch\|taken\|next on\|off\|clear` | Allows or prevents one of the lift's judgment calls at the site `ADDRESS` — the branch instruction (`jcc`) or the indirect jump (`jmp`), the last of the pseudocode line's addresses in `pseudocode --json`; a word at the compare before it is not the branch's — or leaves it to the lift: `guard` (a branch whose one arm never falls through read as a guard the rest follows unnested; `off` keeps the `if`/`else`), `fold` (a condition comparing an expression with itself folded to the constant it is; `off` keeps the comparison), `invert` (`on` turns the condition round with its arms when both have statements, and the lift does not turn it back; `off` keeps the taken arm first even where the lift would turn it to make a guard), `switch` (the indirect jump read as a switch through a jump table the walk recovers or is told; `off`, the jump reads no table, the graph ends at it and the lift refuses the function with `an indirect jump at …`), and on the walk's: `taken` (the walk follows the branch to its target — a conditional branch's taken side, a jump's target, a jump table's cases; `off`, the side is not analyzed: the graph leaves it out, the pseudocode says `// not analyzed: 0x401010` where the path would go and notes `analysis halted at 0x401010: told to` under the return comment; `on` follows a target whose bytes do not decode, or that lands inside an instruction, where the walk halts by itself and notes `the target does not decode`), `next` (the walk goes on to the instruction after — a conditional branch's fall-through, which it also halts at by itself when it does not decode; `off` at a call says the callee does not return, and `on` that it does). `ag image cfg` lists the halts. On the lift's kinds `on` is the lift's own call, which is the default — it does not override a `constant-conditions expression` option — so `on` reads as `clear` unless an `off` is being taken back; on the walk's, `on` follows where the walk would halt by itself. `ag image pseudocode\|il\|cfg … --project FILE` lifts with the words; the workbench's **Edit ▸ Override at address…** records one at the selected line's branch. A function a plugin architecture lifts takes the `switch` word alone. |
| `ag project TARGET inline --file FILE FUNCTION on\|off\|clear` | Says whether the function `FUNCTION` — a name, or an address spelled `0x…` — is inlined into its callers' pseudocode. `on`: a call to it reads as its own lifted body after the comment `// inlined: FUNCTION`, its parameters standing for the call's arguments and its locals declared in the caller as `FUNCTION_LOCAL` (`_2`, `_3`… where the name is taken); an argument that is not a variable or a constant, and would be read other than once in order, or whose parameter the body writes or takes the address of, is assigned to `FUNCTION_PARAM` first. The value the body returns at its end is the call's: `a = f(b);` takes it, `return f(b);` returns it, and a bare `f(b);` drops it unless it has an effect of its own. A call inside a larger expression is inlined only where the body is one `return expr;`, which stands in its place. Every statement of the body carries the call's address. A call stays where the body cannot stand there, and the caller's leading comments say why: `f is not inlined at 0x401020: its body has a goto` (or `it returns before its end`, `it takes 2 arguments and the call passes 1`, `it returns no value`, `it is recursive`, `it is not lifted: …`, `it is a thunk for …`). A cycle of calls through inlined functions is not followed round, and no function is inlined into itself. `off` says the function is never inlined; `clear` leaves it to the analysis, which inlines nothing by itself. `ag image pseudocode\|il … --project FILE` lifts with the words; the walks and the graphs do not change. The workbench's **Edit ▸ Inline function into callers…** records one for the function on screen. |
| `ag project TARGET switch --file FILE ADDRESS TABLE COUNT [--width 4\|8] [--relative]` | Says where the jump table the indirect `jmp` at `ADDRESS` reads is — its first entry and how many — when the analysis cannot read it from the code; `--relative` for entries that are offsets from the table, whose width is then 4 unless said. `TABLE` of `none` takes the note off. `ag image disasm\|cfg\|pseudocode … --project FILE` reads the notes. |
| `ag project TARGET asm --file FILE ADDRESS TEXT` | Assembles the instruction `TEXT` (Intel syntax) as it would sit at `ADDRESS`, at the target's width, and records its bytes as a patch there; warns on stderr when it is longer than the instruction it replaces. |
| `ag project TARGET nop --file FILE ADDRESS [--len N \| --to END]` | Fills bytes from `ADDRESS` with the architecture's no-op as a patch: the instruction there, as long as it is, or `--len N` bytes, or up to `--to END`. |
| `ag project TARGET opaque --file FILE [FUNCTION…\|--all] [--dry-run]` | Patches out the opaque predicates `ag image … opaque` finds in the functions named, or in every one: an always taken branch becomes a `jmp` to the same target in the same bytes — a short `7x rel8` is `EB rel8`, a near `0F 8x rel32` is `90 E9 rel32` — and a never taken one as many `nop`s. Each is a patch like any other, recorded with the instruction it spells (`jmp 0x401074`, `nop x2`): `show` lists it, `patch … none` takes it off, `write-patched` writes it out, and `ag image pseudocode … --project FILE` reads the function without the branch. The image is read with the patches the project holds already. `--dry-run` prints the patches and saves nothing. The workbench's **Edit ▸ Patch opaque predicates** does it for the function on screen, with undo. |
| `ag project TARGET write-patched --file FILE --out OUT` | Writes a copy of `TARGET` to `OUT` with every patch `FILE` holds in it, with the target's mode, leaving the target as it is. Refuses an existing `OUT` without `--force`, the target or the project file as `OUT` (a hard link to either included), a project with no patches, a target whose SHA-256 is no longer the one the project recorded (`--force` writes anyway), and a patch over bytes the file does not hold — or that reaches past the end of its section, which the image cuts but the file does not. The copy is written whole or not at all. |
| `ag project TARGET mode --file FILE ADDRESS arm\|thumb\|none` | On an ARM image, says which instruction set the code from `ADDRESS` onward decodes in, over what the symbols say, until the next mark or symbol; `none` takes the mark off. `ag image … --project FILE` reads the marks. |
| `ag project TARGET rebase --file FILE BASE` | Moves the whole image to `BASE` — its lowest mapped page goes there, and every section, function, symbol and string with it — for every `ag project` command and for `ag image … --project` (`info`, `symbols`, `disasm`, `cfg`, `pseudocode`); `none` puts it back. The base is the one the format states — a PE's image base, an ELF's first load segment — and a move that would leave the address space, or a layout the image cannot take, is refused before it is written. Nothing is relocated: an absolute address in the code still names what it named, and the project's records keep the addresses they were made at. |
| `ag project TARGET segment --file FILE add NAME ADDRESS SIZE [--file-offset OFF] [--exec]` | Adds a segment the loader missed, at `ADDRESS` in the moved image's addresses, `SIZE` bytes long (`16` or `0x10`), holding the file's bytes from `--file-offset` when the file holds them, and code with `--exec`. One that would overlap a segment the image has, or reuse a name, is refused. |
| `ag project TARGET segment --file FILE remove NAME` | Takes the segment out of the image, and the functions, data and import slots that lay in it with it. Removing a segment the layout added drops the addition. |
| `ag project TARGET segment --file FILE rename NAME NEW` | Calls the segment `NEW`. Renaming one the layout added or renamed folds into that edit. |
| `ag project TARGET patch --file FILE ADDRESS BYTES` | Records the hex pairs `BYTES` as a patch at `ADDRESS`; `none` takes the patch off. The file on disk is never changed: `ag image … --project FILE` reads the image with the patches on. |
| `ag project TARGET color --file FILE ADDRESS COLOR` | Sets a highlight color on the address: a name — `red`, `orange`, `amber`, `yellow`, `green`, `cyan`, `blue`, `purple`, `pink`, `gray` — or `#rrggbb`; `none` clears it. A color on a function's entry is the function's, and the workbench tints the whole function with it. `--on function` or `--on block` puts it on the function entered there or the block of bytes starting there, which the workbench tints as a whole. |

## A program under the debugger: `ag debug`

```bash
cargo run --bin ag -- debug ./sample.elf --break main --break 0x1149 -- arg1 arg2
```

`ag debug IMAGE [--break TARGET]… [--debugger gdb|lldb] [--project FILE] [-- ARGS…]` runs the
program under GDB (or LLDB through `lldb-mi`), stopped first at its first instruction, where
the session learns the slide a position-independent program runs under; then it runs the
program to each breakpoint — a function by address or name — and prints where it stopped in
the image's addresses, the registers and the stack, lets it go on, and ends with the
program's exit code (1 when a signal or a fault stopped it, with the reason). A `--break`
target is a function by address or name, or any address in the image's code. GDB on Linux is
the supported path; LLDB through `lldb-mi` is untested, and starts the program at `main`. The
program's terminal is `/dev/null`. The workbench drives the same session with its panes; see
`docs/workbench.md`, which also says what attaching needs.

## Plugins: `ag plugins` and `ag tool`

`ag plugins` lists the plugin directories, the manifests read from them, and every loader,
architecture, tool, rewriter and formatter registered — as text, or as JSON with `--json`. `ag tool NAME IMAGE
[--project FILE] [--option N V]… [--arg name=value]…` runs a plugin's tool over the image and
prints its answer: JSON pretty, or the text it is; a value that reads as JSON is given as
JSON. A tool's own failure is exit code 1 with its message. The manifests, the five kinds of
plugin — loaders, architectures (which may recover a function's blocks and lift it whole
themselves), tools, rewriters, which change a function's medium-level graph as it is
lifted, and formatters, which change the pseudocode's lines after they are printed — and the
conversations the commands speak are in `docs/plugins.md`.

## An MCP server: `ag mcp`

Language models drive analysis through the Model Context Protocol, and `ag mcp` serves the
image to one: JSON-RPC 2.0, one message a line, over the process's standard input and
output, which is how MCP clients start a local server. Point a client at the command and the
image's facts are tools it calls.

```bash
cargo run --bin ag -- mcp ./sample.elf
cargo run --bin ag -- mcp ./sample.elf --project sample.agproj --option dead-code drop
```

A client configuration names the command and its arguments; for one that takes a JSON
block, something like:

```json
{ "mcpServers": { "ag": { "command": "ag", "args": ["mcp", "/path/to/sample.elf", "--project", "/path/to/sample.agproj"] } } }
```

The image opens the way `ag image` opens it: `--raw` and its flags for raw bytes, `--slice`
for a universal Mach-O, `--option NAME VALUE` for the engine's options, and `--project FILE`
for the project file, under whose layout the image is read and whose patches, mode marks and
jump-table notes the walk is told. A project file that is not there yet is made from the
image on the first change, as `ag project` makes it.

The tools, each answering with text and, where the answer is a record, the same as JSON in
`structuredContent`:

| Tool | Answer |
|---|---|
| `image_info` | The file, its language, entry point and sections, how many functions and strings it has, and the project file in use. |
| `list_functions [filter] [limit]` | The functions: address, name (demangled), the mangled name when there was one, where it ends when the unwind data says, and the analyst's name from the project when it has one. `filter` is a case-insensitive regular expression, or a plain substring. |
| `search query [limit]` | The function names, data symbol names and strings matching a regular expression. |
| `disassemble target` | The listing of one function, as `ag image disasm` prints it. A target is an address, such as `0x1198`, or a name — exact first, then a substring, a mangled name too. |
| `decompile target` | The pseudocode of one function; a function the lifter refuses is a tool error with the reason. |
| `slice target variable [address] [direction] [hide]` | The pseudocode of one function sliced, as `ag image pseudocode --slice` prints it: `direction` `backward` (the default) for the statements the value of `variable` depends on, `forward` for the ones it affects; the value at the statement at `address`, or at the function's end without one, `return` there for the value returned. The lines outside the slice are commented out, or left out when `hide` is true. A variable or a statement the function lacks is a tool error. |
| `control_flow target` | The blocks, edges and jump tables of one function, as `ag image cfg --json` reports them. |
| `transpile [targets] [all] [follow] [harness]` | The functions as C++ that compiles, as `ag image transpile` writes it (`docs/il.md`). |
| `emulate target [args] [steps] [depth]` | Runs the function on its medium level with `args` as its parameters, as `ag image emulate --json` reports it (`docs/il.md`). |
| `il target [level] [ssa] [opcodes] [flags] [stack_pointer] [types] [casts]` | The function at one level of the lift — `lifted`, `low`, `medium` (the default) or `high` — in SSA form when `ssa` is true, as `ag image il --json` reports it; the booleans show the opcodes, flags, stack pointer and types in the text and make the casts explicit (`docs/il.md`). |
| `callers target`, `callees target` | Who calls the function; the calls it makes, tail calls marked. |
| `cross_references target` | For a function: the data and strings it refers to, its callers and callees. For a piece of data or a string: the functions that refer to it. Both with the references the analyst recorded in the project, to and from the address. |
| `strings [filter] [limit]` | The strings of the image with the functions that use them. |
| `read_bytes address [length]` | The bytes at an address, as hex and ASCII; 64 unless said, 4096 at most. |
| `annotations address` | The analyst's records at an address from the project file: the address's own and the block's. |
| `set_name address name` | Names the function at the address; an empty name clears the analyst's. |
| `set_comment address text [above]` | Puts a comment on the address, inline or above; empty text clears it. |
| `set_override address kind [on]` | Allows (`true`, the default), prevents (`false`) or leaves to the lift (`null`) the judgment call `kind` — `guard`, `fold`, `invert`, `switch`, `taken` (the walk follows the branch to its target) or `next` (the walk goes on to the instruction after) — at the site `address`, the branch or the indirect jump; the pseudocode is read again with the word. |
| `set_inline function [on]` | Inlines the function `function` — a name or an address — into its callers' pseudocode (`true`, the default), never (`false`), or leaves it to the analysis (`null`), as `ag project … inline` does; the pseudocode is read again with the word. |
| `opaque_predicates [targets] [all]` | The opaque predicates of the functions, as `ag image … opaque --json` reports them: each branch's site, function, whether it is always or never taken, why, and the bytes that patch it out. |
| `patch_opaque_predicates [targets] [all] [dry_run]` | Patches them out into the project file, as `ag project … opaque` does; the pseudocode is read again with the patches. `dry_run` says them without saving. |
| `set_dead_stores address variable drop` | Takes the stores nothing reads to the variable `variable` of the function at `address` out of the pseudocode (`true`) or leaves them in (`false`); the pseudocode is read again with the word. |
| `set_bookmark address [on]` | Bookmarks the function, or takes the bookmark off. |
| `bookmarks` | The project's bookmarks. |
| `set_label address name` | Names the address — a label on a branch target, a piece of data; an empty name clears it. |
| `set_tags address [add] [remove] [on]` | Adds tags to and takes tags off the record at the address; `on` is `function`, `address` (the default) or `block`, as the workbench's prompt asks. |
| `set_color address color [on]` | Highlights the record: a color name or `#rrggbb`; `none` clears it. |
| `add_reference from to`, `remove_reference from to` | Records that the instruction at `from` reaches `to` — a computed call or jump the analysis cannot see — or takes the record off. |
| `tags` | Every tag of the project with how many records carry it. |
| `tagged tag` | The records that carry a tag. |

The same tools drive a script: `ag run IMAGE [--project FILE] -- COMMAND ARGS…` starts the
command with the server on its standard input and output and ends with the command's exit
status — see `docs/scripting.md`, and the Python client in `scripts/ag.py`.

Every write reads the project file again, changes the one record and saves the file whole —
written beside itself and moved into place — so a change the analyst saved from the command
line or the workbench between two of the model's is kept; the last writer of one record has
the last word, and the workbench opened on the same file sees the model's changes on its
next reload (and writes its own over the file when it saves). Without
`--project` the write tools answer with an error saying so. Lists are cut at 200 rows unless
`limit` says otherwise, and at 5000 at most; a tool's own failure — a function that is not
there, an address outside the image — is answered as a tool error (`isError`), and a request
the server cannot take — an unknown method, an unknown tool, arguments that are not an
object — as a JSON-RPC error. The server stops when its input ends.

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
project file, the engine's options, the intermediate languages, plugins, scripting and the
workbench.

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
| the program's | `ag debug` ends with the exit code of the program it ran, or 1 when a signal or a fault stopped it. |
| the command's | `ag run` ends with the exit status of the command it ran — 128 plus the signal, for one a signal ended — so a script's failure is the batch's; 1 is also `ag` failing to open the image or to start the command. |
