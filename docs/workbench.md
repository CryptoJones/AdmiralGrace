# The desktop workbench

`ag-ui` is the desktop analysis workbench: a menu bar, a function navigator, a work
surface with listing, pseudocode, bytes and references, an inspector, and a bottom
workspace for search results and problems. The layout follows `ui/UI_PLAN.md`.

```sh
# Launch with the bundled sample project
cargo run --bin ag-ui

# Launch on a corpus
cargo run --bin ag-ui -- --corpus ./corpus

# Overlay an Objective-C method map
cargo run --bin ag-ui -- --corpus ./corpus --methods ./corpus/methods.json
```

The corpus directory must contain a `decompile-index.json`. Without one the workbench
opens a bundled sample project so the interface can be explored. `ui/README.md` covers
the workbench in more detail.

## The panes

| Pane | What it holds |
|---|---|
| Navigator | The project's functions, a name filter, and the explore sections with their counts. |
| Work surface | The selected function: listing, pseudocode, bytes, and references. |
| Inspector | The selection's detail, its cross references, the project's provenance and its shape. |
| Bottom workspace | Search results, problems, and the log. |

## A kuna project export in the workbench

The workbench opens a kuna export as well as a corpus:

```sh
cargo run --bin ag-ui -- --kuna ./challenge.kuna
```

The export carries the pseudocode and a labeled listing of every code section, so the
Listing and Pseudocode tabs fill in straight away. The export's `README.md` also names
the binary it was made from, and that is what lets the workbench ask kuna about the
binary itself:

| Surface | What the workbench does with it |
|---|---|
| `kuna decompile --json` | The mapping from each line of C to the addresses it came from. A mapped line in the Pseudocode tab can be clicked to move the selection, and the line holding the selection is highlighted. |
| `kuna xrefs --from/--to --json` | The References tab and the inspector: what the function calls and refers to, and what calls and refers to it. |
| `kuna strings --json` | The Strings count in the navigator, and the lower Strings tab. |
| `kuna functions --summary --json` | The program summary in the navigator - entry point, `main`, reachability, code bytes - and the inspector's project card. |
| The per-function `error` and `unstructured_gotos` | The Problems panel. |

The kuna executable is found through `AG_KUNA_BIN`, or on the `PATH` as `kuna`. When
neither resolves, the export is still read in full - the listing and the pseudocode are
unaffected - and the JSON surfaces are off, with one problem saying kuna was not found.

Every question of the CLI is asked in the background, so the workbench stays responsive
while kuna works.

## A program image in the workbench

The workbench opens a program image as well:

```sh
cargo run --bin ag-ui -- --binary ./sample.elf
```

That is the native path: the image is parsed by the engine's own loader, the navigator
lists its symbols, the inspector shows its sections and entry point, and the Listing tab
holds the native x86-64 disassembly of the selected function. There is no pseudocode yet,
because the lifter has not been written, so that tab says so rather than showing an empty
pane.

Who calls what is only known once the whole program has been read, so that is worked out
in the background when the image opens: the References tab says `indexing…` until the
callers are known. The two numbers of the program summary that need the whole program —
the reachable count and the no-callers count — are unknown until then as well, and say
so rather than showing a zero that is not true.

The Bytes tab and the lower Bytes panel show the bytes of the file around the selection:
sixteen bytes to a row, with the address, the hex and the ASCII column, and the bytes of
the selected instruction marked. The pane follows the selection, so picking an instruction
in the listing moves the bytes to it. Picking a section or a named symbol in the navigator
moves them there too; a symbol that lives only in memory — in `.bss` — has no bytes in the
file, and the pane says so rather than showing zeroes.

The File menu opens an image the same way, with `Open binary...`.

The Strings tab lists the text the image holds, with the functions that use it. The list
filters as you type, and picking a string moves the selection to it. The inspector then
names the string, says which section holds it, and lists the functions that use it.

What the workbench reads:

| Surface | What the workbench does with it |
|---|---|
| The sections of the image | The Segments section of the navigator, and the inspector's image card, with the flag that says which of them hold code. |
| The function symbols | The function list of the navigator. |
| The data symbols | The Data part of the Segments section of the navigator, and the search results. |
| The disassembly of a function | The Listing tab: the instructions of the blocks the control-flow walk found. |
| The bytes of the file | The Bytes tab and the lower Bytes panel: the bytes around the selection. |
| The direct calls of a function | The References tab and the inspector: what the function calls, and what calls it. |
| The strings of the data sections | The Strings tab: the text of the image, and the functions that use it. |

The decoder is x86-64. An image of another architecture opens with its symbols and its
sections, but with the listing off, and the Problems panel says why.

## Reading the panes

The selection is shared: a function picked in the navigator, an address picked in the
pseudocode, and a reference picked in the References tab all move the same selection.

The Problems panel holds what the analysis could not do: functions that failed to
decompile, an export that is still being written, and the per-function diagnostics kuna
reports.
