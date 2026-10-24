---
name: admiralgrace
description: Use the AdmiralGrace `ag` CLI to read a decompilation corpus, a kuna project export or a program image - list the functions, show a body, grep across the bodies, read an image's symbols and disassembly, and check what you find against the bytes. Covers driving ag, not developing it.
---

# AdmiralGrace for reading decompilations

`ag` reads an indexed decompilation corpus, or a kuna project export, and reports on it.
It is a CLI on PATH, not an MCP server: no connection, no state between invocations.

The index is the analysis. Read it before you search it.

## Look before you leap

Start with the shape of the target, not with a guess at a function name:

```sh
ag corpus --root ./corpus stats
```

`stats` reports how many functions the index holds, how many decompiled, how many failed,
and how many carry a name. A failed count means some have no body, and `ag` prints none.

Then list the functions, filtered:

```sh
ag corpus --root ./corpus list --named-only --filter 'decrypt|parse'
```

`list` prints `address status name`, one function per line. `--filter` is a regular
expression over the name, `--named-only` leaves out the unnamed functions, and
`--with-body` leaves out the ones with no body.

## Read the index first

`decompile-index.json` is the map of the target: every function's address, name, status,
and the byte range its body covers. Reading it directly - with any JSON tool - is how
you learn the shape of the target without decompiling anything:

```sh
jq '.functions | length' ./corpus/decompile-index.json
jq -r '.functions[] | select(.status != "written") | .address' ./corpus/decompile-index.json
```

`ag` reads that same index, so anything you learn from it applies to what `ag` prints.

## Show a function, then grep for it

`show` takes an address or a name and prints the decompiled body:

```sh
ag corpus --root ./corpus show 0x1000
ag corpus --root ./corpus show main
```

A name that matches several functions prints the first one with a body. Names are matched
loosely, so a partial name is enough.

`grep` searches the bodies and prints the address and name of every function whose body
matches:

```sh
ag corpus --root ./corpus grep 'memcpy|malloc'
```

Grep gives you the where, never the what: follow it with `show` for the body. Grep reads
every body in the corpus, so it is the expensive call - run it once with a good pattern
rather than in a loop.

## Objective-C targets

A method map overlays Objective-C names on the addresses:

```sh
ag corpus --root ./corpus --methods ./corpus/methods.json methods --class 'NSString'
ag corpus --root ./corpus --methods ./corpus/methods.json list --filter '-\['
```

`--shift` moves the map's addresses by the image base, for a map recorded against a
different base: `--shift 0x100000`.

## Kuna project exports

An export is the other shape of the same analysis: a `.c` of every function, an `.asm` of
every code section, and, under `--stream`, an `index.jsonl` giving each function's place
in the `.c`. `ag` reads both, and the same commands report on either:

```sh
ag corpus --root ./challenge.kuna stats
ag corpus --root ./challenge.kuna show main
```

The export's `README.md` names the binary it was made from. The workbench can ask kuna
about that binary - cross references, strings, the mapping from C lines to addresses -
and `ag docs workbench` explains how.

## Program images

`ag image` reads a program image directly, through the engine's own loader:

```sh
ag image ./sample.elf info
ag image ./sample.elf symbols --filter 'main|add'
ag image ./sample.elf disasm main
ag image ./sample.elf cfg main
ag image ./sample.elf calls
ag image ./sample.elf strings
ag image ./sample.elf data
```

`info` gives the language, the entry point and the sections. `symbols` gives the function
and data symbols. `disasm` gives the blocks of one function: a `; block 0x…` header per
block, then the address, the bytes, the mnemonic and the operands of every instruction. A
call shows the name of the function it calls. `cfg` gives the control-flow graph of a
function: its blocks and the edges between them, each edge marked fall-through or taken.
`calls` gives who calls whom: with a function, what it calls and who calls it; without one,
the whole call graph. `strings` gives the text the image holds and `data` the data, each
with the functions that use it. `--json` reports the same thing as JSON, with every address
as both a number and a hex string.

`info` and `symbols` read any format the loader reads. `disasm`, `cfg`, `calls` and `data`
decode x86-64 only, so they refuse another architecture rather than guessing.

Reach for this when there is no corpus yet: the symbols say what the program has, and the
disassembly says what one function does.

## Verify what you find

Decompiled C is an estimate. Check the branch, the width and the signedness of a value
against the bytes the function covers - the index records that range, and the export's
`.asm` holds the instructions - before you report a finding that depends on it.

## Read the manual without a checkout

```sh
ag docs            # list the embedded topics
ag docs cli        # the command reference
ag docs corpus-format
ag docs workbench
```

The manual is embedded in the binary, so it is there with no repo and no network.

## When a command fails

Read the error before retrying. `no function matching` means the name is not in the index:
list the functions and use one of those names. `no data matching` means the address or the
name is in no piece of data. `reading ...` means the corpus directory is wrong or a body
file is missing. `loading kuna export` means the directory is not an export. `no body for
matched functions` means the name matched only functions that failed to decompile.
