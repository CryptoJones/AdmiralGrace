# The desktop workbench

`ag-ui` is the desktop analysis workbench: a menu bar, a function navigator, a work
surface with listing, pseudocode, graph, bytes and references, an inspector, and a bottom
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
| Work surface | The selected function: listing, pseudocode, graph, bytes, and references; for an Objective-C image, a Header tab with the recovered declarations. |
| Inspector | The selection's detail — its name, the mangled name a C++ or Rust symbol spelled, its size from the unwind data — its cross references, the project's provenance and its shape. |
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
holds the native x86 disassembly of the selected function, 32-bit or 64-bit as the image's
language says, with an arrow in the margin from every branch to its target — blue for a jump
down the listing, amber (the color of the analyst's notes too) for one back up it, so a loop
reads as a loop — the shortest arrows nearest the text, and a tail call, the jump that
leaves the function for another, a stub off the left edge. The Pseudocode tab holds the engine's own lifting of the selected function:
its calls, branches and loops as C, structured into `if`/`else`, `while`, `for` and early
`return`. Each function opens with a comment that says what decided its return type —
`// returns int: main reads eax after the call`, `// void: no caller reads the result` — since
the type is decided from use: what the callers do with `eax`/`rax` after the call, or, with
no caller in the image, whether the function wrote `rax` itself. The sample's `add` reads as
C, its `main` reads as C with its three calls, the format string printed as the literal
`"%ld\n"`, and its `sum_to` reads as a `for` loop over its counter and accumulator. The
lines are numbered and clickable like the kuna provider's, so a click on `return b + a;`
moves the listing to the add, a click on the `printf` line moves it to the call, and a click
on the `for` line moves it to the compare at the loop's head; the comment came from no
instruction. A function that ends in a `jmp` to another function reads as the call and the
return it stands for, `return callee(args);` — or the call and a bare `return;` when nothing
in the image reads the result — and one that is only that jump — a PLT stub such as
the sample's `printf`, or its `frame_dummy` — is a thunk, whose whole pseudocode is the one
line `// thunk for printf`, standing for both of its instructions. A function the lifter
refuses — one with an instruction it does not know, a branch whose condition it cannot
read, or a loop with two entries, such as the sample's `_init` with its indirect call —
leaves the tab empty, and the Problems panel says why.

The engine's options — the judgment calls `ag catalog` lists, such as whether a counted
loop is a `for` or a `while` — are read from the command line, `--option NAME VALUE`,
repeated as needed, and every function of the image is lifted with them:

```sh
cargo run --bin ag-ui -- --binary ./sample.elf --option loop-form while
```

There is no options pane yet; the symptom index in `ag docs options` says which option to
set when the pseudocode does not read the way you want.

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

The Graph tab draws the control-flow graph of the selected function. Every block the
control-flow walk found is a box with the instructions of the block in it, and every way
the code goes on is an arrow. The walk stops at a `jmp` to another function the image
knows — a tail call, which the references list — so the sample's `frame_dummy` is one box,
not `register_tm_clones`' boxes after it. A block that goes on in two ways is a branch: the arrow that
leaves the end of the block is the fall-through, and the other one is the branch that is
taken, and both say so. The blocks are laid out in rows — a block sits below the deepest
block that reaches it — and the graph is drawn to fit the pane. It can be dragged with the
mouse and zoomed with the wheel, and clicking a box moves the selection to the start of
that block.

A minimap of the whole graph sits in the pane's bottom right corner — every block a mark, the
selected one bright, the part of the graph the pane shows outlined — and a click on it moves
the view there. The arrow keys walk the graph while the tab is open: Down follows the
fall-through out of the selected block, Up goes to the block that reaches it, Left and Right
move along its row. The keys reach the graph from any pane, so Up and Down typed into a
filter field while the tab is open move the selection too. **Block text…** (Ctrl+Shift+L, or
the inspector's button, or the Edit menu) puts the
analyst's own title on the block holding the selection, in place of its range of addresses;
**Group…** (Ctrl+G) puts the block in a named group, and every block of the function in one
group is drawn as one node under the name, with a line per member and the ways in and out of
the group as its arrows — empty text takes the block out again. Both are kept in the project
file beside the block's highlight.

**Export graph…** in the File menu writes the graph on screen as a picture, for a report or a
write-up: the blocks as the tab draws them — groups, block text, block highlights and the
selected block — and the arrows along the routes it draws them by, fall-throughs blue and
taken branches orange. The path's extension picks the picture, `.svg` or `.pdf`; the prompt
offers a file named for the function beside the program (or beside the project file, when
there is no program), and a file already there is written over on a second submit of the same
path. The PDF uses the standard fonts every reader has, so text past Latin-1 is shown as `?`
there; the SVG keeps every character. The command line draws the same graph with
`ag image FILE cfg TARGET --svg PATH` or `--pdf PATH`, laid out in rows without the
workbench's annotations.

The kind of an arrow is worked out by the rule the `ag image cfg` command reports by, so
the workbench and the command line name an edge the same way: the way that is the address
after the block is the fall-through, and every other way is the branch that is taken.

An arrow that skips a row goes around the blocks in between rather than through them: it
runs along a lane to the side of them and comes back in above the block it goes to. Every
arrow names itself at its last bend, so the names of two arrows that leave the same block
are never painted over one another.

The layout of the graph is worked out by pure functions that take the blocks of a
function and say where every box is drawn, so it is tested without a window. The canvas on
top of it draws the boxes, the arrows and the text, and takes the mouse.

The File menu opens an image the same way, with `Open binary...`.

The Strings tab lists the text the image holds, with the functions that use it. The list
filters as you type, and picking a string moves the selection to it. The inspector then
names the string, says which section holds it, and lists the functions that use it.

The References tab holds the data a function uses as well. The DATA group names the
pieces of data the instructions of the function point at, and a piece of data with no
symbol of its own is named by its address. Picking a piece of data in the navigator
turns the pane around: the inspector names the data, says which section holds it, and the
USED BY group names the functions that use it. Which functions use a piece of data needs
the whole program read, so that group arrives with the rest of the index.

What the workbench reads:

| Surface | What the workbench does with it |
|---|---|
| The sections of the image | The Segments section of the navigator, and the inspector's image card, with the flag that says which of them hold code. |
| The function symbols | The function list of the navigator. |
| The data symbols | The Data part of the Segments section of the navigator, and the search results. |
| The disassembly of a function | The Listing tab: the instructions of the blocks the control-flow walk found, with the margin's arrows from each branch to its target — blue down the listing, amber back up it, bright for the selected instruction's, and a stub off the left for a tail call out of the function. |
| The blocks of the control-flow walk | The Graph tab: a box for every block, with the arrows that join them. |
| The bytes of the file | The Bytes tab and the lower Bytes panel: the bytes around the selection. |
| The calls of a function | The References tab and the inspector: what the function calls, and what calls it. A `jmp` that leaves the function — a PLT stub's jump through its GOT slot, a forwarding stub's jump to another function — is in CALLS too, marked `(tail call)`, so the stub names the import it stands for. |
| The strings of the data sections | The Strings tab: the text of the image, and the functions that use it. |
| The data the instructions point at | The References tab: the DATA group of a function, and the USED BY group of a piece of data. |

The decoder is x86, and reads the width of the code — 32-bit or 64-bit — from the image's
language. An image of another architecture opens with its symbols and its sections, but
with the listing off, and the Problems panel says why.

## The lift's levels in the panes

The Listing and Graph tabs show the disassembly, or any level of the lift. **View ▸ Cycle the
pane's level** (F7) moves the active pane on: the disassembly, then the `lifted`, `low`,
`medium` and `high` levels, and back; **Toggle SSA form** (Shift+F7) shows the level with
every definition versioned and a φ where paths meet. Each pane keeps its own level — the
graph at the medium level beside the listing's disassembly, say — and the level follows the
function selected. A row or a block line of a level carries the addresses the statement came
from, so the selection, the highlights and the breakpoints still land; what belongs to an
instruction — its comment, its breakpoint, the debugger's mark — is drawn on the first of the
rows that came from it. The tab row names the level the pane shows. A function the lifter does
not read shows the disassembly, and the status line says so; the pane keeps its level for the
next function. The margin's arrows and the block lookups follow the disassembly, and the
arrows are drawn for the disassembly and the lifted level, whose rows are the instructions.
The analyst's names for variables and registers reach the disassembly and the pseudocode, not
yet a level's text. Under **View**, five options decorate a level's rows and are marked when
on: **Opcodes** (the instruction's form, or the statement's kind, before the item), **Flag
use** (what an instruction reads and writes, at the lifted level), **Stack pointer** (its
offset from the entry's), **Types** (of every name the item uses) and **Explicit casts**
(every constant with its width). The levels are described in `docs/il.md`.

## Overriding the lift at one site

**Edit ▸ Override at address…** records the analyst's word on a judgment call the lift makes
at the branch or the jump of the selected pseudocode line — the last of the line's
instructions; the compare before it and the instructions that fed it are not the site — as
`KIND on`, `KIND off` or `KIND clear`, several apart by commas: `guard` (a branch whose one
arm never falls through is read as a guard the rest follows unnested; `off` keeps the
`if`/`else`), `fold` (a condition comparing an expression with itself is folded to the
constant it is; `off` keeps the comparison), `invert` (`on` turns the condition round with
its arms and the lift does not turn it back; `off` keeps the taken arm first even where the
lift would turn it to make a guard), `switch` (the indirect jump reads a jump table the
analysis recovers or is told; `off`, it reads none, and the function is not lifted — the
Problems panel says why). `on` is the lift's own call, the default. The prompt opens filled
with the words already at the site. The word is kept in the project file, the pseudocode is
read again with it, and Undo takes it back. Click a line of the pseudocode to select it,
then open the prompt from the Edit menu — the workbench has no context menus yet.

## Rainbow braces and indent guides

**View ▸ Rainbow braces** colors each brace of the pseudocode by its depth, the pair that
opens and closes a block in one color; **View ▸ Indent guides** draws a line down each
indented block, one per level of the engine's `indent`. Both are drawing, not text: the
pseudocode's lines, their addresses and the project file are as they were. The text's own
layout — the brace style, expanded conditional expressions, wrapping, the callees' parameter
names beside the arguments — is the engine's `brace-style`, `ternaries`, `wrap` and
`call-hints` options (`docs/options.md`), set with `--option` when the workbench is started.

## Dead stores, greyed out or gone

Under **Dead code: shown** the pseudocode pane keeps every statement the lift made, and greys
out the ones the `dead-code` option's `drop` would take out: a store to a variable nothing
reads, or that is stored over before anything reads it, and a branch whose condition can only
go one way. **Edit ▸ Drop dead stores of variable…** takes one variable's dead stores out
while the rest stay: type the variable's declared name (`rax`), or `NAME keep` to put them
back. The word is kept on the variable's record in the project file, so a project opened
again reads the same; **Dead code: hidden** still drops everything at once.

## Slices

**View ▸ Slice backward from variable…** dims every line of the pseudocode the value of one
variable does not depend on, the way dead code is greyed out; **Slice forward from
variable…** dims every line the value does not affect. The prompt opens on the variable the
selected line assigns, or the first it names, at an address of that line —
`local_10@0x1180` — and takes `NAME` or `NAME@end` for the variable's value at the
function's end, `return` for the value the function returns, and a name the analyst gave a
variable for the variable. The control statements holding a kept line stay undimmed, so the
shape of the function still reads. The slice follows the pseudocode as it is read again, and
**Clear slice**, or opening another function, shows every line again. What a slice keeps is
`ag image pseudocode --slice`'s (`docs/cli.md`).

## Merging and splitting variables

**Edit ▸ Merge variables…** merges two of the variables of the function on screen: type
`KEEP GONE`, and every occurrence of `GONE` reads `KEEP`. The prompt opens on the first merge
`ag image merges` suggests — a copy, or a register declared again past a join — and takes a
name the analyst gave a variable for the variable. A merge that changes the meaning is made
on the analyst's word, and the notice and the function's leading comments say where both are
live. **Unmerge variable…** takes one back by the variable merged away. **Split variable
here…** splits the variable the selected line assigns at that line's address, `NAME@ADDRESS`:
the assignment and the uses it reaches take a fresh name, `NAME_2`; a split that would need
both names at one use is refused, and the leading comments say which use. The words are kept
on the function's record in the project file, by the names the lift declares, and undo takes
them back.

## Debugging

Some behavior only shows when the code runs, so the workbench drives a debugger — GDB, or
LLDB through `lldb-mi`, whichever is on the machine — and the static listing follows the
program. **Debug ▸ Start under debugger** (F6) runs the open program under it,
stopped at its first instruction; **Attach to process…** asks for a process id instead. A
click in the listing's margin puts a **breakpoint** on that instruction (a red dot) or takes
it off, as does F9 on the selection; breakpoints are kept across sessions and set in the
debugger when one starts. **Continue** (F8), **Step into** (F11), **Step over** (F10) and
**Finish function** (Shift+F11) run the stopped program; **Interrupt** stops a running one;
**Stop** ends the session.

When the program stops, the listing moves to the instruction it stopped at — the function
is selected and the instruction marked with an amber wedge in the margin — in the image's
addresses: a position-independent program runs under a slide the session learns from the
process's mappings, and every address the debugger reports is read back through it. The
**Debug** panel at the bottom holds the controls, where the program is, the registers, the
stack (a frame is a button that moves the listing there), the bytes at the program counter
and the debugger's log. The lifter and the listing are the image's; what runs is the
program's, so a patch the project holds is not in the running program unless a patched copy
is run.

The same session runs headless as `ag debug IMAGE --break TARGET…`: the program runs to each
breakpoint, the registers and the stack are printed there, and the command ends with the
program's exit code.

What to expect of the debuggers: GDB on Linux is the supported path. The slide is learned from
the process's mappings, which GDB prints on Linux; without them a position-independent
program's breakpoints wait, and the log says so. LLDB through `lldb-mi` speaks the same
interface but is untested here — `lldb-mi` is rarely installed, has no `starti` (the program
is started at `main` instead) and no mappings. Attaching needs permission to trace the
process: on Linux, `/proc/sys/kernel/yama/ptrace_scope` at 1 (the usual default) refuses a
process that is not the debugger's own child unless the debugger runs with the right. The
program's own terminal is nowhere (`/dev/null`): what it reads and prints is not shown, and
cannot be mistaken for the debugger's words. Interrupt relies on the interface's asynchronous
mode, which every modern GDB has. The debugger is driven on the window's thread: a command
that reads the program's state is given three seconds, one that starts or moves it twenty,
and the window waits meanwhile.

## Reading the panes

The selection is shared: a function picked in the navigator, an address picked in the
pseudocode, and a reference picked in the References tab all move the same selection.

The Problems panel holds what the analysis could not do: functions that failed to
decompile, an export that is still being written, and the per-function diagnostics kuna
reports.

## The project file

The workbench's Rename, Comment, Bookmark, Tags and Highlight record the analyst's changes in a project
file (`.agproj`): versioned JSON holding the target's path and SHA-256, the analysis
options, and every annotation keyed by address. **File ▸ Open project file…** reads one
back and applies its renames to the function list; **File ▸ Save project** (Ctrl+S) writes
the changes out, and **Save project as…** prompts for a path. The same file is what
`ag project` reads and writes, so a rename recorded in the workbench is visible to the CLI
and to a script.

Four names are the analyst's to give:

- **Rename function…** (F2) names the selected function.
- **Rename label…** (F3) names the label at the selected address. The entry label of a
  function and the function's name are the same record, so the two agree by construction.
- **Rename local variable…** (Ctrl+F2) names one of the locals the function on screen
  declares. The prompt reads `declared=new name`, the declared name as the pseudocode
  writes it; an empty right side returns the declared name.
- **Rename register…** (Ctrl+F3) names a register the function on screen prints, as its
  listing spells it — `rax`, `ebp`. The prompt reads `register=new name`; an empty right
  side returns the register's own name. A register rename belongs to the one function:
  `rax` renamed in `add` is untouched in `main`.

A rename replaces the analysis's name wherever the workbench shows one: the navigator, the
header, the inspector, the call operands in the listing and the graph, the reference labels,
and the pseudocode — where a renamed function, local, or register is replaced as a whole
word, so `add` never reaches into `address`. A renamed register also reaches the operands of
the listing and graph, including inside a memory operand, so a renamed `rbp` reads
`[frame-0x8]`. The provider's own text is never rewritten; the names are applied as the
views draw. Returning the analysis's own name clears the annotation. An annotation that
carries nothing is dropped on save, so the file says only what the analyst changed.

A comment is the analyst's note at one address, and the analyst chooses where it stands:

- **Add comment inline** (Ctrl+/) rides at the end of the instruction's line.
- **Add comment above** (Ctrl+Shift+/) stands on its own line over the instruction.

The note reaches every view that shows the address: the listing, the graph block, and —
where a pseudocode line maps to the address — the pseudocode. An above-comment takes a line
of its own in each; an inline one rides at the end. The disassembler's own comment (what the
bytes point at) keeps its slot beside the instruction, so the two never fight for the same
place. The prompt prefills the comment already there, so moving a note between inline and
above is a re-submit.

A bookmark marks a place of interest so the analyst can come back to it:

- **Toggle bookmark** (Ctrl+Shift+B) marks or clears the selected place.

The **Bookmarks** explore section lists every marked place in address order, and clicking a
row jumps to it: a function entry opens the function across the work surface, and any other
address moves the selection there. A bookmark borrows the name of the place it marks — the
analyst's own name for the address when there is one (a label, F3), the function's name at a
function entry, and the address itself where nothing names the place — so naming a bookmark
means naming the place. The section's count is the analyst's own marks, not something the
analysis reported.

A tag is one word the analyst groups places by, so a large function list is navigable by
what has been found:

- **Tags…** (Ctrl+T) edits the tags on the selected place. The prompt reads the tags as
  words separated by spaces or commas, and prefills the ones already there; an empty submit
  clears them. A tag is trimmed, and a space inside one becomes a hyphen.
- Typing `#tag` into the navigator's filter keeps only the functions carrying that tag,
  spelled as it is stored — `#Crypto` and `#crypto` are two tags. Any other filter text still
  matches names.

The **Tags** explore section lists every tag with how many functions carry it, and clicking
one filters the function list to those functions. A tag on a place that is not a function —
a bare address, a block of bytes — is counted beside the row as `+N places`, since the
function list cannot show it; the inspector shows it at that address. Two tags are the
analysis's own and need no
hand: `entry` marks the function the program starts in, and `objc:Class` marks each method
the Objective-C method map named, by its class, so one class's methods gather under one tag.
Automatic tags are read off the analysis as the views draw, not written to the project file,
and the inspector's **Tags** line shows both kinds together.

A highlight is a color on a place, so what has been reviewed and what has not is told at a
glance:

- **Highlight…** (Ctrl+H) colors the selected place: the function, when the selection is a
  function entry, or the one address otherwise. The prompt reads a color name — `red`,
  `orange`, `amber`, `yellow`, `green`, `cyan`, `blue`, `purple`, `pink`, `gray` — or a
  `#rrggbb` value, prefills the color already there, and an empty submit clears it.
- **Highlight block…** (Ctrl+Shift+H) colors the basic block of the function on screen that
  holds the selection.

A color reaches the listing and the graph. A color on a function's entry is the function's:
it tints every line of the function and every block of its graph. A block's color is a record
of its own, apart from the entry's, and tints that block and its lines; a line's own color
tints that one row, and in the graph a band behind the line. The nearest mark wins, so a
green block with one red line in it reads as the analyst meant, and the entry block colored
apart from its function keeps both colors. One address holds one color, so an entry line
cannot be colored apart from its function. The color is mixed into the surface rather than
painted outright, so the text on it stays legible; the selected row and block show the focus
color instead, so a highlight shows once the selection moves on. The inspector shows the
value the file holds beside a swatch. The same color is what `ag project color` records.

A cross reference the analysis cannot see — a computed call, a jump through a table — is the
analyst's to record:

- **Add cross reference…** (Ctrl+X) records that the selected place reaches the address typed
  into the prompt, as the listing prints it: a bare `0x1` reaches the import the analysis calls
  `EXTERNAL:0x1`. **Remove cross reference…** (Ctrl+Shift+X) takes one back, offering the one
  there is when there is only one.

A manual reference shows in the inspector's References from both ends, under **Reaches
(manual)** at the place it leaves from and **Reached from (manual)** at the place it reaches,
each named by the place's name and address so a reference to a renamed function reads by the
analyst's name; clicking one jumps there. The same reference is what `ag project xref`
records.

The automatic split of code and data is sometimes wrong, and the analyst corrects it
directly:

- **Mark as data** (Ctrl+Shift+D) shows the bytes at the selection as one item of data;
  marking again makes the item wider, a byte to a word to a double word to a quad word and
  round again. **Mark as string** (Ctrl+Shift+A) shows them as a string up to its zero.
  **Mark undefined** (Ctrl+Shift+U) shows them one by one. **Mark as code** (Ctrl+Shift+C)
  puts the instruction back and takes the mark off. A mark stands where the analysis decoded
  an instruction; the selection must be one, not a byte inside one.
- **Mark as function** (Ctrl+Shift+F) says a function starts at the selection. It joins the
  function list as `sub_` and its address — the analyst's name for it when there is one —
  and opening it reads the function from there; where the analysis found none, the inspector
  says the mark is the analyst's.

A data, string or undefined mark stands in place of the instructions it covers, in the
listing and the graph alike, and the bytes it shows are the ones the analysis decoded there:
a mark that reaches past one instruction takes the next ones' bytes too, as long as each
follows the last with no gap and none starts a block, and what is left of the last
instruction a data mark cut into follows as bytes. A string with no zero runs 256 bytes at
most. The line that stands in keeps the header of the one it replaced. A function the analyst
marked is the function the addresses after it belong to, until the next. An array — `data:4[8]` — is
recorded with `ag project mark`; the workbench cycles the width of one item. The inspector
shows the mark as the file holds it.

The right base for a constant depends on what it means — a flag mask, a count, an address —
so the analyst chooses it per instruction:

- **Operand format** (Ctrl+Shift+N) shows the constants in the selected instruction's
  operands the next way round: hexadecimal as the analysis prints them, signed hexadecimal,
  decimal, octal, then as an address, and round to hexadecimal, which is the default and
  leaves no record. Signed reads a constant in the width it is printed in — two digits a
  byte, four a word, eight a double word — so `0xff` is `-0x1`; a constant the analysis
  already printed with a sign, `[rbp-0x88]`, is signed already and stays. An address shows
  the name of the place the constant points at when the analysis or the analyst named one,
  and leaves a constant that names nothing as it was. A constant is read whether the listing
  spells it `0x30` or, as a program image's does, `30h`, and keeps its spelling.

The format reaches the listing and the graph, every constant of the one instruction alike; a
`-` the analysis printed before a constant stays with it. `ag project operand` records the
same choice.

A `switch` compiled to a jump table reaches its cases through an indirect `jmp`, which the
analysis recovers by itself when the code has the usual shape — `jmp [index*8 + table]`
into an absolute table, or the position-independent `lea`/`movsxd`/`add`/`jmp` through a
table of offsets — bounded by the `cmp` that guards it. The graph then holds every case,
and the pseudocode prints a `switch`. Where the recovery fails, the analyst says where the
table is:

- **Jump table…** (Ctrl+Shift+J) records, on the selected `jmp`, the table's address and
  entry count — `0x402000 6` — with the entry width between them when it is not 8 bytes,
  and `rel` after when the entries are offsets from the table rather than addresses:
  `0x2000 4 6 rel`. The note stands in for what the walk would read from the code; an
  empty submit takes it off.

The graph and the pseudocode follow the note at once, and so do undo and redo. The same note
is what `ag project switch` records and `ag image … --project` reads.

Patching a binary starts with changing an instruction:

- **Assemble over bytes…** (Ctrl+Shift+E) takes an instruction in Intel syntax — `mov eax, 1`,
  `jmp 0x401010`, `add qword ptr [rsp+8], 2` — encodes it as it would sit at the selected
  address, and writes the bytes over the image's there. The notice says what was written, and
  when the instruction is longer than the one it replaces, that the next instruction is
  overwritten; the patch is written all the same, since that may be what is meant. The prompt
  offers the instruction written there before; an empty submit takes the patch off.

- **NOP instruction** (Ctrl+Shift+O) fills the selected instruction, as long as it is, with
  the architecture's no-op; **NOP range…** (Ctrl+Shift+R) fills a run from the selection up to
  an address typed into the prompt, or `+N` bytes of it. On x86 the no-op is the one-byte
  `nop`, repeated, so the run decodes as that many instructions that do nothing. A run that
  would leave the section it starts in is refused.

- **Edit bytes…** (Ctrl+Shift+Y) edits the bytes at the selection as hex pairs. The prompt
  starts from the patch written there before, else from the bytes of the instruction the
  selection sits on; clicking a byte in the **Bytes** pane picks it. The bytes typed become a
  patch like any other, so the listing, the graph and the pseudocode follow at once. Half a
  byte is refused, as are bytes that would run past the end of the section; an empty submit
  takes the patch off, and the prompt submitted as it came up changes nothing.

- **Write patched program…** (File menu) writes a copy of the program with every patch in it,
  wherever the file holds the bytes a patch changes, and leaves the program itself as it is.
  The prompt offers a path beside the program; a file already there is written over on a
  second submit of the same path, and never the program or the project file. A patch over
  bytes the file does not hold — an address no section holds, or a section with no bytes in
  the file — is refused by address, and so is writing into a program that has changed since
  the project recorded its hash. The copy is written whole or not at all.
- The **Patch History** tab of the bottom panel lists the patches in address order: the
  address, the bytes, and the instruction they were assembled from when they were. Clicking
  one goes there.

A patch written over another takes the other off: the bytes written last are the bytes. The
file on disk is never changed. The patch is a record in the project file — the bytes, and
the instruction they came from — and the image is read as if its bytes were the patched ones,
so the listing, the graph, the pseudocode and the bytes pane follow at once; the bytes pane
shows a patch's bytes in the analyst's color. Undo and redo cover a patch like every other
mark. `ag project asm` and `ag project patch` record the same, and `ag image … --project`
reads the image with the patches on; `ag asm` prints the bytes of an instruction on its own.
The assembler knows the instructions patching reaches for — moves, arithmetic, compares, tests,
pushes and pops, branches to an address, `nop`, `ret`, `int3` and their kin — and refuses
anything else by name rather than guess.

A 32-bit ARM image is decoded too, in both its instruction sets: the SLEIGH decoder reads
the ARM processor specification SLEIGH reads, and the mode of each address — ARM or Thumb — comes from the
image's symbols (a Thumb function's symbol has its low bit set), from the instructions
themselves (`blx` to an address switches it), and from the analyst:

- **Decode from here as ARM or Thumb…** (Edit menu) says which instruction set the code from
  the selection onward is in, until the next mark or symbol that says otherwise; the prompt
  offers the mode the address has now, and `none` lets the image say again. The listing, the
  graph and the calls read the function again at once, and undo covers the mark like every
  other. `ag project mode` records the same for `ag image … --project` to read.

An AArch64 image is decoded the same way, under its own specification; it has one instruction
set, so there is no mode to choose. ARM and AArch64 are decoded, walked and listed; they are
not lifted to pseudocode yet, and the assembler and the no-op fill are x86's. The decode reads each section once from its start, so a `blx` that
reaches backwards, or into another section, does not switch what was already read; the
prompt offers the mode the marks and symbols give an address, not one a `blx` set; a `tbb`/
`tbh` table branch is an indirect branch whose table is not read yet, so the cases after it
are not reached by the graph; and a call or jump through a register under a condition is read
as falling through.

A C++ or Rust image's functions are listed under their demangled names, the signature kept —
`geometry::area(int, int)`, not `_ZN8geometry4areaEii` — in the navigator, the listing and the
graph; the pseudocode, where a name stands in code, uses the scope and the name alone
(`geometry::area(2, 3)`); the inspector's **Mangled** row shows what the symbol table spelled,
for a function and for a piece of data alike.

The functions an image's unwind data names — `.eh_frame`, `.pdata`, `__unwind_info` — are in
the navigator whether or not a symbol names them, a nameless one as `sub_` and its address, so
a stripped binary lists its functions; the inspector's **Size** is the unwind data's where it
has one.

A Swift Mach-O's functions are listed under their demangled names — `sample.Derived.greet(times:
Swift.Int) -> Swift.Int` — the mangled `$s…` name in the inspector's **Mangled** row; a method
a class's vtable points at and no symbol names is listed as `Type.<kind>#N`
(`sample.Base.getter#0`). `ag image FILE
swift` prints the types, their fields and their conformances.

The Pseudocode tab's **Dead code** button shows or hides the statements whose results
nothing uses — a variable assigned and never read, or assigned again before it is read, a
branch whose condition can only go one way — the engine's `dead-code` option, flipped: dead
code is sometimes noise and sometimes the point, so the reader chooses. A call in a hidden
assignment stays, as the call it is.

The Pseudocode tab reads an Objective-C method's calls of the runtime's dispatcher as the
messages they send — `[a twice:c] + 1`, `[Base answer]` — the selector resolved from the
reference the code loads.

An Objective-C Mach-O's methods are listed under their runtime names — `-[Class sel]`,
`+[Class sel]`, `-[Class(Category) sel]` — read from the image's own metadata, so a stripped
binary is named too; `ag image FILE objc` prints the classes, categories and protocols. The
work surface gains a **Header** tab for such an image: the same metadata as an Objective-C
header — every protocol, class and category declared with its properties, instance variables
and methods, the types decoded from the runtime's encodings — the quickest overview of the
binary. `ag image FILE objc --header` prints the same, and `export` writes it as `objc.h`.

A universal (fat) Mach-O holds several images, one per architecture. **Open binary…** takes
`slice=ARCH` after the path — `app slice=arm64`, or the slice's position from 0 — to say which;
opened without one, the notice names the slices. The project file remembers the choice.

A file with no container — firmware, shellcode, a dump — is opened as raw bytes:

- **Open raw bytes…** (File menu) takes `PATH ARCH BASE`, with `entry=ADDRESS`, `offset=N` and
  `length=N` after when they apply: `firmware.bin thumb 0x8000000 entry=0x8000101`. `ARCH` is
  `x86-64`, `x86`, `arm`, `thumb` or `aarch64`. The bytes are one section of code at the base,
  the entry a function; the project file remembers how the bytes load, so opening the project
  opens them the same way.

The image itself can be corrected, when the loader read it at the wrong base or missed a
segment:

- **Rebase image…** moves the whole image to a new base address — every section, function,
  symbol, string and line with it. The prompt offers the base the image has now, its lowest
  mapped address rounded down to the page; `none` puts the image back where the loader reads
  it.
- **Add segment…** takes `NAME ADDRESS SIZE`, with `file:OFFSET` after when the file holds the
  segment's bytes from that offset, and `exec` when it holds code: `extra 0x405000 16
  file:0x3000`. A segment that would overlap one the image has, or reuse a name, is refused and
  nothing changes. **Remove segment…** takes a name — the functions, data and import slots
  that lay in it go with it — and **Rename segment…** takes `NAME NEW`; both offer the
  segment the selection is in.

The layout is a record in the project file, read under on every open and reload, with the
addresses of the moved image; `ag project rebase` and `ag project segment` record the same
for `ag image … --project` to read. The image is read again under the layout, so a layout
change is not on the undo stack: it is taken back by its own door — `none`, a removal of what
was added, a name put back — and a project file that carries a layout is written at format 5.
The move is for an image the loader placed wrongly: nothing is relocated, so an absolute
address in the code still names what it named, and the analyst's marks, patches and notes
keep the addresses they were made at. The base offered is the one the format states — a
PE's image base, an ELF's first load segment. A project whose layout the image cannot take
opens all the same, read as the loader reads it, and the notice says why; the layout stays
recorded, so it is mended by its own doors — taking the edit away, or `none` for the base.

Every one of these changes can be taken back:

- **Undo** (Ctrl+Z) takes back the last change; **Redo** (Ctrl+Shift+Z) puts it back. The
  Edit menu names the change each would reach, as the notice named it when it was made:
  `Undo: Renamed 0x1198`. A new change after an undo forgets what was taken back.

Undo covers every mark the analyst makes — renames, labels, local variable and register
names, comments, bookmarks, tags, highlights, cross references, byte marks, operand
formats, jump-table notes and patches — in the order they were made, and the
navigator and every view follow. Opening a project file or a different analysis starts
afresh: the marks those changes were made to are gone.

Annotations belong to the analysis they were made against. Opening a different binary or
corpus drops them — a rename of `0x1198` means that address in the other file — while a
reload of the same one keeps them.
