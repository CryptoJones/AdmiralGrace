---
name: admiralgrace
description: Use the AdmiralGrace `ag` CLI to read a decompilation corpus, a kuna project export or a program image - list the functions, show a body, grep across the bodies, read an image's symbols, disassembly and pseudocode, and check what you find against the bytes. Covers driving ag, not developing it.
---

# AdmiralGrace for reading decompilations

`ag` reads an indexed decompilation corpus, or a kuna project export, and reports on it.
It is a CLI on PATH, not an MCP server: no connection, no state between invocations.

## Look before you leap

Start with the shape of the target, not with a guess at a function name:

```sh
ag corpus --root ./corpus stats
```

`stats` reports how many functions the index holds, how many decompiled, how many failed,
and how many carry a name. A failed count means some have no body. Then list them, filtered:

```sh
ag corpus --root ./corpus list --named-only --filter 'decrypt|parse'
```

`list` prints `address status name`, one function per line. `--filter` is a regular
expression over the name, `--named-only` leaves out the unnamed functions, and
`--with-body` leaves out the ones with no body.

## Read the index first

`decompile-index.json` is the map of the target: every function's address, name, status,
and the byte range its body covers. Read it directly, with any JSON tool, to learn the shape
of the target without decompiling anything; `ag` reads that same index:

```sh
jq -r '.functions[] | select(.status != "written") | .address' ./corpus/decompile-index.json
```

## Show a function, then grep for it

`show` takes an address or a name and prints the decompiled body:

```sh
ag corpus --root ./corpus show 0x1000
ag corpus --root ./corpus show main
```

A name that matches several functions prints the first one with a body. Names are matched loosely, so a partial name is enough.

`grep` searches the bodies and prints the address and name of every function whose body
matches:

```sh
ag corpus --root ./corpus grep 'memcpy|malloc'
```

Grep gives you the where, never the what: follow it with `show` for the body. Grep reads
every body in the corpus, so run it once with a good pattern rather than in a loop.

## Objective-C targets

A method map overlays Objective-C names on the addresses:

```sh
ag corpus --root ./corpus --methods ./corpus/methods.json methods --class 'NSString'
```

`--shift 0x100000` moves the map's addresses by the image base, for a map recorded elsewhere.

## Kuna project exports

An export is the other shape of the same analysis: a `.c` of every function, an `.asm` of
every code section, and, under `--stream`, an `index.jsonl` giving each function's place
in the `.c`. `ag` reads both, and the same commands report on either:

```sh
ag corpus --root ./challenge.kuna stats
ag corpus --root ./challenge.kuna show main
```

The export's `README.md` names the binary it was made from; the workbench can ask kuna about
that binary, and `ag docs workbench` explains how.

## Program images

`ag image` reads a program image directly, through the engine's own loader:

```sh
ag image ./sample.elf info
ag image ./sample.elf symbols --filter 'main|add'
ag image ./sample.elf disasm main
ag image ./sample.elf pseudocode add
ag image ./sample.elf cfg main
ag image ./sample.elf calls
ag image ./sample.elf strings
ag image ./sample.elf data
ag image ./sample.elf export ./sample.ag
```

`info` gives the language, the entry point and the sections; `symbols` the function and data
symbols. `disasm` gives the blocks of one function: a `; block 0x…` header per block, then
the address, bytes, mnemonic and operands of every instruction; a call names its callee.
`pseudocode` gives one function as C — calls, `if`/`else`, `while` and `for`, early `return`,
the parameters named `a`, `b`…; a `jmp` to another function is `return callee(args);`, a PLT
stub the one line `// thunk for printf`; a function it cannot read prints `not lifted yet` and
the reason, exit code 1. `cfg` gives the blocks and the edges between them, each marked
fall-through or taken. `calls` gives who calls whom, a `jmp` out marked `(tail call)`: with a
function, what it calls and who calls it; without one, the whole call graph. `strings` gives
the text the image holds and `data` the data, each with the functions that use it. `--json`
reports the same as JSON, every address a number and a hex string. `export DIR` writes all of
it in one pass: `info.json`, `symbols.json`, `strings.json`, `data.json`, `calls.json`, a
`functions/<address>.json` (cfg, calls, data, pseudocode) and `.asm` per function, an
`index.json`, and a `README.md` naming the binary, its SHA-256 and the `ag` version.
`--functions REGEX` limits the functions; a non-empty directory needs `--force`. `info` and
`symbols` read any format; the rest decode x86 only. Reach for this when there is no corpus yet.

## When the C does not read right

Every judgment call the lifter makes is an option, and each is documented by symptom. Read
the symptom index first - `ag docs options` opens with it: *if the output shows X, try
`--option Y`* - then set the option on the command, as often as needed:

```sh
ag image ./sample.elf pseudocode sum_to --option loop-form while
ag image ./sample.elf export ./sample.ag --option constant-style hex --option indent 4
ag catalog --markdown     # the whole registry, symptom index first; --json for a program
```

## Verify what you find

Decompiled C is an estimate. Check the branch, the width and the signedness of a value
against the bytes - the index records the range, the export's `.asm` and `ag image disasm`
hold the instructions - before you report a finding that depends on it.

## Read the manual without a checkout

```sh
ag docs            # list the embedded topics
ag docs cli        # the command reference; also options, corpus-format and workbench
```

## When a command fails

Read the error before retrying. `no function matching` means the name is not in the index:
list the functions and use one of those names. `no data matching` means no piece of data has
that address or name. `reading ...` means the corpus directory is wrong or a body file is
missing. `loading kuna export` means the directory is not an export. `no body for matched
functions` means the name matched only functions that failed to decompile. `no option named`
and `option "…" takes` mean the `--option` is wrong: `ag docs options` lists them.
