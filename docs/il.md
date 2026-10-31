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

## How the lifter reads the flags

The machine's flags are read back as the relations they stand for, by who wrote them. Each
status flag (`CF`, `PF`, `AF`, `ZF`, `SF`, `OF`) remembers the instruction that wrote it last
— the decoder says which flags each instruction writes, so `inc` and `dec` leave the carry's
producer standing while they take the others — and a consumer reads the flags its condition
code needs: `je` the zero flag, `jl` the sign and overflow flags, `jb` the carry, `jbe` the
carry and the zero flag. The producers are kinds of write: a compare (`cmp a, b`: every flag
of `a - b`, so `jl` is `a < b` and `jb` is `(unsigned int)a < (unsigned int)b`), a test
(`test a, b`: the flags of `a & b`, the carry clear, so `jne` after `test a, a` is `a != 0`),
an arithmetic instruction with its operands and result (`sub` reads as a compare of its
operands; the zero and sign flags of any operation are its result's, `(a + 1) == 0` after
`inc`; the carry of an addition is the sum wrapping below an operand, and the logical
operations clear it), and `bt` (the carry is the bit, `(a >> 3) & 1`). The consumers are the
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
