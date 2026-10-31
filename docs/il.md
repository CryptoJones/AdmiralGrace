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
| `low` | One of the lifter's own statements, before its temporaries are resolved: a store to a stack slot (`slot[-0x10]:64 = 0`), a call into a temporary (`t3 = f(…)`), a compare into the flags, a `return`; a `branch if …` or `switch on …` at the end of a chain that branches. The names are temporaries (`t0`), slots, the values registers held at entry (`entry5`), variables once they are known. |
| `medium` | One statement over variables and parameters, calls resolved with their arguments, laid on the chain graph: each block ends in `goto block_…`, `if (…) goto … else goto …` or `switch (…) …`. |
| `high` | One statement of the structured body — `if (…)`, `else`, `while (…)`, `do` / `while`, `for (…; …; …)`, `switch (…)` and its `case` labels, `return` — each at its depth in the tree, as the pseudocode prints them. |

The lifted, low and medium levels lie on the same graph of chains (a chain is a run of
blocks the lift reads as one), so a block at one level is the same block at the others. An
item's `addresses` are the machine addresses it came from; `correspondence(a, b)` in the
engine, and the `addresses` in the JSON, map an item of one level onto the items of another
that share an address. A function the lifter refuses — 32-bit code, an instruction it does
not read — has no level; a thunk has its instructions at the lifted level and nothing at the
others.

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

A name read before any definition is version `#0` — a parameter, a register at entry. At the
lifted level the names are the registers (`r1_0` for the first general register, as the
emitter spells them), and an instruction's text is kept whole with what it writes noted
beside it. The high level takes its versions from the medium level's statements, which it is
a rearrangement of; a statement folded into a `for` header keeps its plain names.

## The output

As text, each level prints a header (`; sum_to at 0x1161: medium level, SSA form`), then its
blocks — a label and the blocks it goes on to — and their items, each with the first address
it came from (`+` when there are more) and indented by depth. As JSON (`--json`): `function`,
`name`, `level`, `ssa`, the `blocks` (`id`, `address`, `successors`, the ids of their
`items`) and the `items` (`id`, `block`, `depth`, `addresses`, `text`, `defines`, `uses`,
`phi`). The MCP server's `il` tool answers the same for a language model, and a script asks
it through `ag run`. In Rust, `ag_image::Binary::il(address, level, ssa)` gives the
`IlFunction`, and `ag_engine::il` holds the types, `build`, `to_ssa` and `correspondence`;
`ag_engine::lift::lift_stages` keeps every stage of one lift for a plugin that wants them
all at once.
