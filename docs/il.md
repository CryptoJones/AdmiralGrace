# Intermediate languages

The lifter goes from the machine's instructions to a C-like tree in stages, and each stage
is a language of its own that scripts, plugins and the command line can read, each with a
static single assignment form, and each item carrying the addresses it came from, so one
level maps onto another and onto the listing.

```bash
cargo run --bin ag -- image ./sample.elf il sum_to --level medium
cargo run --bin ag -- image ./sample.elf il sum_to --level medium --ssa
cargo run --bin ag -- image ./sample.elf il sum_to --level high --ssa --json
```

## The four levels

| Level | What an item is |
|---|---|
| `lifted` | One machine instruction, as the listing spells it, with the registers it reads and writes named and a note of where its flow goes (`; jump 0x118a`, `; return`). One block per chain of the lift. |
| `low` | One of the lifter's own statements, before its temporaries are resolved: a store to a stack slot, with its width (`local_10:64 = 0`), a call into a temporary (`v1 = f(…)`), a compare into the flags, a `return`; a `branch if …` or `switch on …` at the end of a chain that branches. A slot is named by the variable it becomes (`local_10`, `&local_10` for its address), a call's result by its temporary (`v1`), a register's value at entry `entry5`, so a read at this level names the write it reads. |
| `medium` | One statement over variables and parameters, calls resolved with their arguments, laid on the chain graph: each block ends in `goto block_…`, `if (…) goto … else goto …` or `switch (…) …`. |
| `high` | One statement of the structured body — `if (…)`, `else`, `while (…)`, `do` / `while`, `for (…; …; …)`, `switch (…)` and its `case` labels, `return` — each at its depth in the tree, as the pseudocode prints them. |

The lifted, low and medium levels lie on the same graph of chains (a chain is a run of
blocks the lift reads as one), so a block at one level is the same block at the others. An
item's `addresses` are the machine addresses it came from; `correspondence(a, b)` in the
engine, and the `addresses` in the JSON, map an item of one level onto the items of another
that share an address. A function the lifter refuses — 32-bit code, an instruction it does
not read — has no level; a thunk has its instructions at the lifted level and nothing at the
others. A function a plugin's architecture lifts itself (`docs/plugins.md`) has the lifted
level by the function's blocks, the medium and high levels from the graph the architecture
built, and no low level. A plugin's rewriter (`docs/plugins.md`) changes the medium level before it is
structured, so the medium and high levels and the pseudocode show what it left, while the
lifted and low levels stay the machine's and the lifter's: after a rewrite the medium level
may have more or fewer blocks than the chains, or other edges, so a block's id at one level
is no longer its id at another — the addresses still map the levels onto each other — and
its SSA form is built on its own graph. A thunk passes no rewriter.

## Emulating a function

The medium level runs. `ag image X emulate FUNCTION --arg N…` runs the function's statements
over variables on its block graph, against the image's memory, without a debugger: the
arguments are its parameters in order, a global the lift names is read from the image at its
symbol's width and written to a memory of the run's own, a load through a pointer reads the
image's bytes under what the run has written, and a call to a function of the image is run in
turn (`--depth` calls deep, 8 unless said) while any other call — an import, a function the
lifter refuses — leaves its result unknown. The run stops when the function returns, after
`--steps` statements (10000 unless said), or when a branch, a switch, a return or an address
depends on a value the run does not know, and says why:

```
; sum_to at 0x1161: emulated
  0000116c  local_10 = 0  ; local_10 = 0
  00001174  local_14 = 1  ; local_14 = 1
  0000117d  local_10 = local_10 + (long)local_14  ; local_10 = 1
  00001186  local_14 = local_14 + 1  ; local_14 = 2
  …
  00001192  return local_10
; returned 15 (0xf)
;   a = 5
;   local_10 = 15 (0xf)
;   local_14 = 6
```

Every step carries the address it came from, the statement, what it wrote and a note when a
call was not followed or a store went to memory. A section the file holds no bytes for reads
as the zeros it is loaded with. A call that is followed runs on the memory the caller has
written so far and leaves its own writes behind; the whole run, calls and all, has one step
budget, and a block costs a step as a statement does, so a loop of nothing but jumps runs out
too. A call that is not followed leaves its result unknown, and so the locals whose addresses
it was given; what it may have written to memory the run does not know, and says so beside
the step. `--json` gives the steps, the `stop`, the
value `returned` (its bits, its signed reading, its hex and its width), the `variables` and
the `memory` written. The MCP tool `emulate` and `scripts/ag.py`'s `emulate(target, *args)`
answer the same; in Rust, `Binary::emulate(address, args, limits)` runs
`ag_engine::emulate::run` over the function's `Stages`, with the image as the emulator's
`World` — any `World` will do for a run outside an image. Values are the machine's words with
the width and signedness their C type gives them; a comparison is a byte that is 1 or 0. A
plugin's rewriter has already had the graph, as has an architecture that lifts its own.

## The pseudocode's language

The pseudocode reads as C unless the `language` option says otherwise — `--option language rust`,
`objc` or `python`, on the command line of `ag image pseudocode`, the MCP server and the
workbench: the same lift, spelled each language's way. Rust writes `fn sum_to(a: i32) -> i64 {`,
declares a local as `let mut local_14: i32;`, casts with `x as i64`, turns a `switch` into a
`match`, a `while (1)` into `loop` and a `do`/`while` into a `loop` that breaks, and a `goto`
out of a loop into `break`; Objective-C is C with `YES` and `NO`; Python writes `def sum_to(a):`,
blocks by indentation with `elif` and `while True:`, `and`/`or`, `True`, `x if c else y`,
`deref_int(p)` for a load through a pointer, and the locals as a `# locals:` comment in place
of declarations. It is pseudocode in each language, not a program: `long(x)` and
`unsigned_int(x)` are the widths C would wrap to, `deref_T` and `addr` stand for loads and
addresses the language has no spelling for, and `/` and `>>` keep C's meaning. The levels
and the transpiler keep C, which a compiler reads. `docs/options.md` has the option.

## Calls through pointers, and Windows control-flow guard

A call or a jump through a value the lift knows — a parameter, a field loaded from a struct —
is the call through that value: `return a(b, 1);`, `(*(long *)a)(b, …)`. Under
`--option indirect-calls refuse` it is `not lifted yet: an indirect call`, as it used to be. A
Windows image built under control-flow guard makes every such call through the guard: the
target goes in `rax` and the code calls, or jumps, through `__guard_dispatch_icall_fptr`, or
validates `rcx` through `__guard_check_icall_fptr` and then calls `rcx`; under the extended
guard the pointers are `__guard_xfg_dispatch_icall_fptr` and its kin. The image names the
pointers from its load configuration, as far as the configuration's own length goes, and the
lift reads the dispatch as the call it guards — to the function `rax` names outright when it
is one, else through the value — and drops the check, which calls nothing of the function's
own; a `jmp` through the dispatcher is the tail call it is. A `rax` that holds a guard pointer
itself is refused, not followed round. The transpiler writes a call through an expression as
a call through a pointer to a function of integers, `((long (*)(...))a)(b, 1)`, and a function
passed as an argument as the integer it is, `(long)add`.

## Builtins

The memory operations a compiler writes inline are read back as the calls they stand for.
`rep movs` and `rep stos` — a copy or a fill of `rcx` elements through `rdi` and `rsi`, which
`memcpy` and `memset` of a size the compiler does not know become — are `__builtin_memcpy(a,
b, c)` and `__builtin_memset(a, (char)b, c)`, the count in bytes (`c * 8` for `rep stosq`),
and `rdi`, `rsi` and `rcx` after them are what the instruction leaves: the pointers past what
was moved, the count at zero, the direction flag taken as clear. A string put on the stack
word by word — `mov rax, 0x77202c6f6c6c6568; mov [rsp+3], rax` and the word after it — or
byte by byte is one `__builtin_strcpy(&local_d, "hello, world")` when the bytes read as text
ending in NUL, or a `__builtin_memcpy(&local_d, "text", n)` of bytes that read as text with no
NUL; the stores must be two or more, to or into one variable whose address is taken, and
cover their span, so one wide constant stays the number it may be and another variable's
store stays its own. The variable keeps the type of its first word; the string runs past it.
`--option builtins keep` leaves the stores as they are — the second word written into the
first's variable as `*(long *)((char *)&local_d + 5) = 0x646c726f77202c;` — while the `rep`
instructions are builtins either way, having no other reading. The byte loops a compiler
writes in place of `rep` are left the loops they are.

## Struct initializers

A run of stores through one pointer at distinct offsets — `*(int *)a = b; *(int *)(a + 4) = 2;
*(long *)(a + 8) = 7;`, a struct filled field by field — is read as one initializer,
`*(struct { int at_0; int at_4; long at_8; } *)a = { b, 2, 7 };`: the pointer cast to a struct
of the fields by their offsets, assigned the values in order. Two stores at least; the pointer
no constant and the offsets under 4096, so that the globals an address names, indexed or not,
stay their own stores; no field written twice or over another; and neither the pointer nor a
value reading memory or calling, since the initializer reads the pointer once and stores them
all at once. `--option struct-initializers keep` leaves the stores as they are. Rust reads it as
`*(a as *mut Struct) = Struct { at_0: b, … }` and Python as `deref_struct(a) = {"at_0": b, …}`;
the transpiler writes the stores a compiler reads, and the emulator stores each field at its
offset.

## The pseudocode's layout

How the text is laid out is the analyst's too, apart from what it says: `--option brace-style broken`
puts each control statement's `{` on a line of its own under its head and `else` on its own line
(C and Objective-C; Rust keeps its braces attached and Python has none); `--option ternaries expand`
writes `x = c ? a : b;` as an `if`/`else` assigning in each arm, and a return of one as two returns;
`--option wrap 80` breaks a statement longer than eighty columns between a call's arguments, the
rest indented two levels; `--option call-hints names` labels each argument with the callee's
parameter name — `sum_to(/* a */ add(a, /* b */ 3))`, or `add(a=1, b=2)` in Python, where every
argument has a name — where the callee is a function of the image; an argument that is the
parameter's own name takes no label. Every line keeps the addresses it came from, so a wrapped
statement's pieces all map to its instructions and a brace alone maps to none. The workbench adds
rainbow braces and indent guides, which are drawing, not text; and a formatter plugin
(`docs/plugins.md`) has the last word on the lines.

## Transpiling to C++

The medium level compiles. `ag image X transpile FUNCTION… [--all] [--no-follow] [--harness
FUNCTION] [--out FILE]` writes the functions as C++: each one's signature and locals as the pseudocode
declares them, then its blocks, each under a label named by its address (`block_1161:`), its
statements as the pseudocode spells them and a `goto` for every way out — `goto block_118a;`,
`if (local_14 <= a) goto block_117d; else goto block_1192;`, a `switch` whose cases `goto`
their blocks. The lift's own types and casts are C, so the text builds with a C++ compiler:
only `<cstdint>` is included — `printf`, `strtoll` and `abort`, which the program itself
calls, are declared exactly, so a function of the image may bear any name the C library has
— a compare kept as a statement (`__cmp(a, b)`) is a template that does nothing, the globals
the functions name are defined with the bytes the image holds for them (`static int32_t
counter = (int32_t)0x7; // at 0x4010`), every function of the image a function calls is
written too unless `--no-follow` says to declare it instead (with its own signature when its
lift is known), a thunk is written as the call it is, an import is declared `extern "C" long
name(...)`, and a function the lifter refuses is declared with the reason beside it — so
`--all` writes every function that lifts and names the rest. A function, an address or a
string held in an integer variable is converted to it (`rax = (decltype(rax))(&completed_0)`),
as the machine held it in a register. `--harness FUNCTION` adds a `main` that calls that function with the numbers
on its command line, each read by `strtoll`, and prints what it returns, so a lifter's reading
of the machine can be built and run beside the program it came from:

```bash
cargo run --bin ag -- image ./sample.elf transpile sum_to --harness sum_to --out sum_to.cpp
c++ -std=c++17 -w sum_to.cpp -o sum_to && ./sum_to 5   # 15, as emulate sum_to --arg 5 says
```

A name that is not a C++ identifier (`completed.0`) is spelled with underscores wherever it
appears, a keyword's or `main` with a leading underscore (`_main`) so the harness can be
`main`; two names that spell the same identifier are a collision the compiler reports. A load from an absolute address (`*(int *)0x4010`)
compiles and would fault when run: the program's memory is not the image's. The MCP tool
`transpile` and `scripts/ag.py`'s `transpile(*targets, harness=…)` answer the same text; in
Rust, `Binary::transpile(targets, follow, harness)` builds it, and `ag_engine::transpile`
writes a `Program` of `Stages`.

## How the lifter reads the flags

The machine's flags are read back as the relations they stand for, by who wrote them. Each
status flag (`CF`, `PF`, `AF`, `ZF`, `SF`, `OF`) remembers the instruction that wrote it last
— the decoder says which flags each instruction writes, so `inc` and `dec` leave the carry's
producer standing while they take the others — and a consumer reads the flags its condition
code needs: `je` the zero flag, `jl` the sign and overflow flags, `jb` the carry, `jbe` the
carry and the zero flag. The producers are kinds of write: a compare (`cmp a, b`: every flag
of `a - b`, so `jl` is `a < b` and `jb` is `(unsigned int)a < (unsigned int)b`), a test
(`test a, b`: the flags of `a & b`, the carry clear, so `jne` after `test a, a` is `a != 0`),
an arithmetic instruction with its operands and result (the destination is written, so the
relations are read from the result — the zero and sign flags are its, `(a + 1) == 0` after
`inc` — the carry of an addition from the sum wrapping below the source, the borrow of a
subtraction from the difference plus the subtrahend wrapping below it, when the source is
not the destination too; the logical operations clear the carry and the overflow, so every
relation is the result's; a signed relation after `sub` is refused), and `bt` (the carry is
the bit, `(a >> 3) & 1`). The consumers are the
conditional jumps, `setcc` (the condition as the byte it is: `eax = a < b`), `cmovcc` (a
value chosen by the condition: `(a < b) ? b : a`) and `adc`/`sbb` (the carry added or borrowed,
`sbb eax, eax` the idiom for `0 - (a < b)`).

A consumer whose flags two instructions wrote — `cmp` then `inc` then `jbe` — is refused by
name (`reads flags two instructions set: the cmp at … and the inc at …`), as is one reading
a flag nothing tracked wrote (`jb` after `inc`: `reads CF that nothing tracked set`), and a
condition no producer can say (`jo`, `jp`, a `jb` after an instruction known only by its
result). A flag survives a join only when every path had the same instruction write it, and
is dropped when a variable its producer read is written again.

## SSA form

With `--ssa`, every definition of a name gets a version — `local_14#1 = 1`,
`local_14#3 = local_14#2 + 1` — and a φ item stands at the start of every block where paths
with different versions meet, by the dominance frontiers of the chain graph:

```
block_118a:  ; -> 0x117d, 0x1192
  0000118a  local_10#2 = φ(local_10#1 from block_1161, local_10#3 from block_117d)
  0000118a  local_14#2 = φ(local_14#1 from block_1161, local_14#3 from block_117d)
  00001169+  if (local_14#2 <= a#0) goto block_117d else goto block_1192
```

A name read before any definition is version `#0` — a parameter, a register at entry. When
the entry block is itself a loop header, its φ has an operand `from entry` for the way in.
Two edges from one block to another are one operand. A block the entry does not reach keeps
its plain names. The φ items are appended after the function's own, so their ids follow the
last item's rather than their block's; a block's `items` list them first all the same.

At the lifted level the names are the registers (`r1_0` for the first general register, as
the emitter spells them). An instruction's text is kept whole, with what it writes noted
beside it; the versions of what it reads are in its `uses` alone. A register and its parts
share one name: a write of 32 bits or more is a new version, a narrower write (`mov al, …`)
reads the old version too. The flags are not a register the level tracks, so a `cmp` defines
nothing here; the low level's `flags = …` does. The high level takes its versions from the
medium level's statements, which it is a rearrangement of — a header (`if`, `while`,
`switch`, `for`) part by part, from the statements and the branch at its addresses — and
has no SSA form without the medium's.

## Render options

Every item carries more than its text: its opcode — the instruction's form as the decoder
numbers it at the lifted level (`Mov_r32_rm32`), the statement's kind at the others
(`assign`, `store`, `call`, `intrinsic`, `return`, `compare`, `branch`, `switch`, `goto`,
`label`, `break`, `continue`, `expression`, `if`, `else`, `while`, `do`, `for`, `case`,
`phi`) — the flags an instruction reads and writes, the stack pointer's offset from the
entry's before the item's earliest instruction, and the C type of every name it reads or
writes. The JSON has them always; the text shows them when asked:

```bash
cargo run --bin ag -- image ./sample.elf il sum_to --level lifted --opcodes --flags --stack-pointer
cargo run --bin ag -- image ./sample.elf il sum_to --level medium --types --casts
```

```
  00001166  [Mov_rm64_r64] mov rbp,rsp  ; sp = entry-0x8
  0000118d  [Cmp_r32_rm32] cmp eax,[rbp-14h]  ; sp = entry-0x8  ; flags: reads none, writes CF PF AF ZF SF OF
  00001190  [Jle_rel8_64] jle short 000000000000117Dh  ; branch 0x117d  ; sp = entry-0x8  ; flags: reads ZF SF OF, writes none
  00001174  local_14 = (int)1  ; types: local_14: int
```

`--opcodes` puts the opcode before the item in brackets; `--flags`, `--stack-pointer` and
`--types` add notes after `  ; `. `--casts` changes the text itself: every constant is spelled
with the type of its width (`(int)1`, `(long)0`), and a value stored at a width other than its
own is cast to it, whole. The MCP tool `il` and `scripts/ag.py`'s `il()` take the same five
as booleans; in Rust, `Binary::il_with(address, level, ssa, casts)` builds the function and
`IlFunction::render(&Render)` prints it. In the workbench the options are under **View**
(`docs/workbench.md`). The types are the lift's: a parameter's or local's declared type, a
slot's by the width stored to it (the first, when there are two), a temporary's by the
width it was read at (`long` when it never was), a register's value at entry `long`, the
flags `flags`; at the lifted level the registers as the text spells them, typed by their
width (`eax: int`, `rbp: long`). The flags and the opcode forms are the x86 decoder's; an
image another architecture decodes has neither.

## The output

As text, each level prints a header (`; sum_to at 0x1161: medium level, SSA form`), then its
blocks — a label and the blocks it goes on to — and their items, each with the first address
it came from (`+` when there are more) and indented by depth. As JSON (`--json`): `function`,
`name`, `level`, `ssa`, the `blocks` (`id`, `address`, `successors`, the ids of their
`items`) and the `items` (`id`, `block`, `depth`, `addresses`, `text`, `defines`, `uses`,
`phi`, `opcode`, `flags_read`, `flags_written`, `stack_pointer`, and `types` as `[name, type]`
pairs in the text's order). The MCP server's `il` tool answers the same for a language model, and a script asks
it through `ag run`. In Rust, `ag_image::Binary::il(address, level, ssa)` gives the
`IlFunction`, and `ag_engine::il` holds the types, `build`, `to_ssa` and `correspondence`;
`ag_engine::lift::lift_stages` keeps every stage of one lift for a plugin that wants them
all at once.

In the workbench, the Listing and Graph panes show any level: F7 cycles the active pane's
level and Shift+F7 toggles its SSA form (`docs/workbench.md`).
