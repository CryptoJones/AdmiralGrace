# AdmiralGrace backlog

One list, two views: this file and the [GitHub Issues tab](https://github.com/CryptoJones/AdmiralGrace/issues) are kept in sync. Every open item here has an issue and every open issue has a line here; adding an item means filing the issue and linking it, closing an issue means checking the box.

Seeded 2026-10-23 from two sources: the code review of the engine foundation at `e9e6ced` (PR #1), and the review of [kuna](https://github.com/Noelo-Lab/kuna), the agent-first Rust port of the Ghidra decompiler. Review items are grouped; each group is one issue, and the issue carries the full repro list.

## P0 — Engine correctness (`ag-engine`)

### CFG builder (done) — [#9](https://github.com/CryptoJones/AdmiralGrace/issues/9)
- [x] No block splitting → **overlapping blocks**: `74 02 90 90 c3` @0x1000 (if-diamond) yields blocks `[0x1000,0x1002)` and `[0x1002,0x1005)` overlapping tail block `[0x1004,0x1005)`; backward `jne` into mid-block (`31 c0 ff c0 83 f8 0a 75 f9 c3`) overlaps the entry block. `resolve_branches` (`cfgwalk.rs` ~23–97) never checks whether the next address starts/extends an existing block.
- [x] Dangling successor: `eb 00 c3` → block `[0x1000,0x1002)` lists successor `0x1002` but that block start is never scheduled.
- [x] Indirect calls lose the graph: `ff d0 c3` → 1 block, no successor, `call_sites` empty; the continuation is unreachable in the CFG (catch-all arm, `cfgwalk.rs` ~87–90).
- [x] Called targets walked into the caller's `ProcedureCfg`: `e8 …` pushes the callee onto the same frontier — callee blocks end up inside the caller; targets belong in `call_sites` only.
- [x] Duplicate successors not filtered within a block (loop case lists target + fallthrough twice).

### Decoder instruction flow (done) — [#10](https://github.com/CryptoJones/AdmiralGrace/issues/10)
- [x] `ud2` / `xbegin` abort the **whole segment** decode (`FlowControl::Exception → bail!`). Real x86-64 functions carry `ud2` constantly. Expected: decode the instruction, record a trap marker, continue. Pinned test: `0f 0b c3` currently → `Err`.
- [x] `syscall` decodes to `Flow::Call(0)` — misleading semantics.
- [x] `Flow::Xbegin` declared but never constructed (dead variant).

### Register identity (done) — [#11](https://github.com/CryptoJones/AdmiralGrace/issues/11)
- [x] 8-bit GPR numbering collision: `AH` → index 4, same as `SP`/`RSP` → AH ≡ RSP in `Operands`.
- [x] Non-GPR/XMM registers forced to index 0: every `ymm`/`zmm`/k-register collapses to the same `RegisterId`.
- [x] Operand width dropped: `89 c0` and `48 89 c0` produce identical `Operands`.
- [x] `RegisterSet` `1u64 << (index & 63)`: silently **aliases** any index ≥ 64 into 0 (latent until identity is fixed).

## P0 — CLI (`ag-cli`) (done) — [#12](https://github.com/CryptoJones/AdmiralGrace/issues/12)
- [x] Byte-boundary panics: `&types[..60]` and `name.truncate(70)` panic on multi-byte characters at the cut point (valid non-ASCII names/type encodings). Needs char-safe truncation.
- [x] `0X1000` accepted by the resolve prefix check but rejected by `parse_addr` (only lowercase `0x` is stripped) → whole subcommand errors out.

## P0 — Silent data damage (`ag-corpus`) (done) — [#13](https://github.com/CryptoJones/AdmiralGrace/issues/13)
- [x] Unparseable IMP silently becomes `imp_addr 0` (`unwrap_or(0)`); hex parse also strips only lowercase `0x`.
- [x] Class methods `+[Class sel]` rendered/stored as `-[Class sel]`; `by_name` uses that key, so collisions resolve last-write-wins via `insert`.
- [x] Double `with_shift` desyncs `by_imp` (keys accumulate) vs `imp_addr` (current shift only); `by_name` is never re-shifted.
- [x] `drop_header` cuts the function head at the first blank line (`"// hdr\nint f(void) {\n  int a;\n\n  return a;\n}"` → `"  return a;\n}"`); single-line headers stay glued in.
- [x] `to_function` errors silently skipped; duplicate addresses silently keep the first entry.
- [x] `parse_addr` rejects uppercase `0X` prefix. — fixed in #37
- [x] `Sha256` field is dead storage (never read).

## Hygiene (done) — [#14](https://github.com/CryptoJones/AdmiralGrace/issues/14)
- [x] `LICENSE` file missing (Cargo.toml declares MIT).
- [x] Unused dependencies: `walkdir` (workspace), `serde`/`serde_json` (`ag-engine`, `ag-cli`), `regex` (`ag-corpus`).
- [x] Dead variant: `Flow::Xbegin` (see decoder flow) — tracked in #10.

## kuna-derived work

### data layer and workbench

- [x] Graph tab: draw the control-flow graph of the selected function for a program image — [#49](https://github.com/CryptoJones/AdmiralGrace/issues/49)
- [x] Graph tab: route an edge that skips a rank around the blocks in between, and keep the edge labels apart — [#59](https://github.com/CryptoJones/AdmiralGrace/issues/59)
- [x] ag image: cfg and calls subcommands, so the CLI reports what the Graph and References tabs show — [#62](https://github.com/CryptoJones/AdmiralGrace/issues/62)
- [x] README screenshots: add the bytes pane, the strings tab and the graph tab of a program image — [#63](https://github.com/CryptoJones/AdmiralGrace/issues/63)
- [x] One rule for fall-through and taken edges: the Graph tab takes its edges from ag-image — [#67](https://github.com/CryptoJones/AdmiralGrace/issues/67)
- [x] References tab for a program image: data references, from the instructions that point at named data — [#70](https://github.com/CryptoJones/AdmiralGrace/issues/70)
- [x] Fixtures and tests for a PE and a Mach-O image — [#71](https://github.com/CryptoJones/AdmiralGrace/issues/71)
- [x] Decode 32-bit x86: take the bitness from the image's language — [#76](https://github.com/CryptoJones/AdmiralGrace/issues/76)
- [x] Lifter, first milestone: pseudocode for straight-line x86-64 functions — [#77](https://github.com/CryptoJones/AdmiralGrace/issues/77)
- [x] Lifter, second milestone: straight-line functions that call, by lifting the fall-through chain of blocks — [#83](https://github.com/CryptoJones/AdmiralGrace/issues/83)
- [x] Lifter, third milestone: structured control flow (if/else, loops) — [#88](https://github.com/CryptoJones/AdmiralGrace/issues/88)
- [x] Lifter: tail jumps and thunks (PLT stubs, tail calls) — [#91](https://github.com/CryptoJones/AdmiralGrace/issues/91)
- [x] Lifter: a comparison of two computed addresses prints as rax != rax — [#97](https://github.com/CryptoJones/AdmiralGrace/issues/97)
- [x] CFG walk: stop at a jmp to another function's entry (tail-call edge) — [#98](https://github.com/CryptoJones/AdmiralGrace/issues/98)
- [x] CFG walk: hlt does not fall through — [#104](https://github.com/CryptoJones/AdmiralGrace/issues/104)
- [x] Lifter: return-value liveness from the callers — [#92](https://github.com/CryptoJones/AdmiralGrace/issues/92)
- [x] ag image export: the whole analysis of an image as a directory of JSON and text — [#78](https://github.com/CryptoJones/AdmiralGrace/issues/78)
- [x] Bytes pane for a program image: show the bytes around the selection — [#50](https://github.com/CryptoJones/AdmiralGrace/issues/50)
- [x] Strings for a program image: scan the data sections and link each string to the code that uses it — [#51](https://github.com/CryptoJones/AdmiralGrace/issues/51)
- [x] Open a raw binary in the workbench through ag-engine::Image — [#42](https://github.com/CryptoJones/AdmiralGrace/issues/42)
- [ ] Read corpus addresses that name an address space (EXTERNAL:0xN) — [#491](https://github.com/CryptoJones/AdmiralGrace/issues/491)

- [x] Add a kuna project-export provider (index.jsonl + .c/.h/.asm) to ag-corpus and ag-ui — [#4](https://github.com/CryptoJones/AdmiralGrace/issues/4)
- [x] Use kuna's JSON surfaces to fill the navigator, inspector and graph panes — [#5](https://github.com/CryptoJones/AdmiralGrace/issues/5)

### engine

- [x] Evaluate depending on kuna-sleigh and kuna-analysis instead of a hand-written decoder and loader — [#6](https://github.com/CryptoJones/AdmiralGrace/issues/6)
- [x] Option registry with a generated catalog and symptom index for engine decisions — [#8](https://github.com/CryptoJones/AdmiralGrace/issues/8)

### cli

- [x] `ag image`: inspect a binary from the CLI through ag-engine::Image — [#43](https://github.com/CryptoJones/AdmiralGrace/issues/43)

- [x] `ag install-skill` and `ag docs`: ship an agent skill and the manual inside the binary — [#7](https://github.com/CryptoJones/AdmiralGrace/issues/7)

## Roadmap: analyst workflow and platform coverage

Filed 2026-10-26.

### Annotation and persistence

- [x] Project file: save the analysis and the analyst's annotations in a portable format — [#302](https://github.com/CryptoJones/AdmiralGrace/issues/302)
- [x] Rename functions, labels and local variables, in the CLI and the workbench — [#303](https://github.com/CryptoJones/AdmiralGrace/issues/303)
- [x] Rename a register within one function's pseudocode — [#304](https://github.com/CryptoJones/AdmiralGrace/issues/304)
- [x] Comments: line and inline comments at an address — [#305](https://github.com/CryptoJones/AdmiralGrace/issues/305)
- [x] Bookmarks: named places of interest, listed and navigable — [#306](https://github.com/CryptoJones/AdmiralGrace/issues/306)
- [x] Tags on addresses, blocks and functions, with filtering by tag — [#307](https://github.com/CryptoJones/AdmiralGrace/issues/307)
- [x] Colors on addresses, blocks and functions — [#308](https://github.com/CryptoJones/AdmiralGrace/issues/308)
- [x] Undo and redo for every analyst change — [#309](https://github.com/CryptoJones/AdmiralGrace/issues/309)
- [x] Manually add and remove cross references — [#310](https://github.com/CryptoJones/AdmiralGrace/issues/310)

### Correcting the analysis

- [x] Mark bytes as code, function, data, string or undefined — [#311](https://github.com/CryptoJones/AdmiralGrace/issues/311)
- [x] Operand display format: hex, signed, decimal, octal, or as an address — [#312](https://github.com/CryptoJones/AdmiralGrace/issues/312)
- [x] Switch tables: recover jump tables, with a manual hint when recovery fails — [#313](https://github.com/CryptoJones/AdmiralGrace/issues/313)
- [x] Analysis options: branches end procedures, and code sections hold only procedures — [#314](https://github.com/CryptoJones/AdmiralGrace/issues/314)

### Modifying the binary

- [x] Assembler: assemble an instruction in place — [#315](https://github.com/CryptoJones/AdmiralGrace/issues/315)
- [x] NOP a region — [#316](https://github.com/CryptoJones/AdmiralGrace/issues/316)
- [x] Editable Bytes pane — [#317](https://github.com/CryptoJones/AdmiralGrace/issues/317)
- [x] Write a patched executable — [#318](https://github.com/CryptoJones/AdmiralGrace/issues/318)
- [x] Rebase the image, and create, delete and rename segments — [#319](https://github.com/CryptoJones/AdmiralGrace/issues/319)

### Architectures and formats

- [x] Decode 32-bit ARM and Thumb, with per-address mode switching — [#320](https://github.com/CryptoJones/AdmiralGrace/issues/320)
- [ ] Decode and lift AArch64 — [#321](https://github.com/CryptoJones/AdmiralGrace/issues/321) — decoded, walked and listed (v0.21.0); the lift to pseudocode remains
- [x] Load a raw binary with a base address, entry point, file offset and length — [#322](https://github.com/CryptoJones/AdmiralGrace/issues/322) — a base of 0 is refused until sections carry a mapped flag
- [x] Universal (FAT) Mach-O: list the slices and pick one — [#323](https://github.com/CryptoJones/AdmiralGrace/issues/323)

### Metadata recovery

- [x] Read Objective-C metadata from the binary — [#324](https://github.com/CryptoJones/AdmiralGrace/issues/324)
- [x] Generate an Objective-C header from a binary — [#325](https://github.com/CryptoJones/AdmiralGrace/issues/325)
- [x] Read Swift metadata and demangle Swift names — [#326](https://github.com/CryptoJones/AdmiralGrace/issues/326)
- [x] Demangle C++ names — [#327](https://github.com/CryptoJones/AdmiralGrace/issues/327)
- [x] Find functions from exception and unwind data — [#328](https://github.com/CryptoJones/AdmiralGrace/issues/328)

### Decompiler and views

- [x] Pseudocode: print Objective-C message sends as [receiver selector] — [#329](https://github.com/CryptoJones/AdmiralGrace/issues/329)
- [x] Pseudocode: a toggle to show or hide dead code — [#330](https://github.com/CryptoJones/AdmiralGrace/issues/330)
- [x] Graph tab: minimap, block grouping, block colors, editable block text, keyboard navigation — [#331](https://github.com/CryptoJones/AdmiralGrace/issues/331)
- [x] Graph tab: export the graph as PDF and SVG — [#332](https://github.com/CryptoJones/AdmiralGrace/issues/332)
- [x] Listing: jump arrows in the margin — [#333](https://github.com/CryptoJones/AdmiralGrace/issues/333)

### Automation

- [x] MCP server over the ag data layer — [#334](https://github.com/CryptoJones/AdmiralGrace/issues/334)
- [x] Scripting API with headless script execution — [#335](https://github.com/CryptoJones/AdmiralGrace/issues/335)
- [x] Plugin SDK for loaders, architectures and tools — [#336](https://github.com/CryptoJones/AdmiralGrace/issues/336)

### Dynamic analysis

- [x] Debugger frontend for LLDB and GDB — [#337](https://github.com/CryptoJones/AdmiralGrace/issues/337)

## Roadmap: advanced analysis

Filed 2026-10-26.

### Intermediate languages

- [x] Expose a multi-level IL (low, medium, high) with SSA forms to the API — [#338](https://github.com/CryptoJones/AdmiralGrace/issues/338)
- [ ] Workbench: switch any pane between disassembly and each IL level — [#339](https://github.com/CryptoJones/AdmiralGrace/issues/339)
- [ ] IL render options: opcodes, flag use, stack pointer value, expression types, casts — [#340](https://github.com/CryptoJones/AdmiralGrace/issues/340)
- [ ] IL rewriting API for plugins — [#341](https://github.com/CryptoJones/AdmiralGrace/issues/341)
- [ ] Function-level, context-aware lifting for complex ISAs — [#342](https://github.com/CryptoJones/AdmiralGrace/issues/342)
- [ ] Model architecture flags with producer and consumer semantics — [#343](https://github.com/CryptoJones/AdmiralGrace/issues/343)
- [ ] IL emulator — [#344](https://github.com/CryptoJones/AdmiralGrace/issues/344)
- [ ] IL-to-C++ transpiler for testing lifters — [#345](https://github.com/CryptoJones/AdmiralGrace/issues/345)

### Decompiler output and control

- [ ] Pluggable output languages: Pseudo-C, Pseudo-Rust, Pseudo-ObjC, Pseudo-Python — [#346](https://github.com/CryptoJones/AdmiralGrace/issues/346)
- [ ] Per-site decompiler overrides: early return, expression folding, condition inversion, switch recovery — [#347](https://github.com/CryptoJones/AdmiralGrace/issues/347)
- [ ] Per-variable dead store elimination — [#348](https://github.com/CryptoJones/AdmiralGrace/issues/348)
- [ ] Pseudocode formatting options: brace style, rainbow braces, indent guides, ternaries, wrapping, call parameter hints — [#349](https://github.com/CryptoJones/AdmiralGrace/issues/349)
- [ ] Outline inlined memcpy, memset and strcpy into builtins — [#350](https://github.com/CryptoJones/AdmiralGrace/issues/350)
- [ ] Struct initializer expressions in pseudocode — [#351](https://github.com/CryptoJones/AdmiralGrace/issues/351)
- [ ] Translate Windows CFG dispatch calls and jumps to functions into direct calls and tail calls — [#352](https://github.com/CryptoJones/AdmiralGrace/issues/352)
- [ ] Detect conditionally non-returning functions — [#353](https://github.com/CryptoJones/AdmiralGrace/issues/353)
- [ ] Guided analysis: choose per block which branch targets to analyze — [#354](https://github.com/CryptoJones/AdmiralGrace/issues/354)
- [ ] Inline a function during analysis — [#355](https://github.com/CryptoJones/AdmiralGrace/issues/355)
- [ ] Opaque predicate patcher — [#356](https://github.com/CryptoJones/AdmiralGrace/issues/356)
- [ ] Program slicing views — [#357](https://github.com/CryptoJones/AdmiralGrace/issues/357)

### Variables and data flow

- [ ] Merge and split variables — [#358](https://github.com/CryptoJones/AdmiralGrace/issues/358)
- [ ] Force a new variable version for per-path naming and typing — [#359](https://github.com/CryptoJones/AdmiralGrace/issues/359)
- [ ] User-informed data flow: set a variable's value or range — [#360](https://github.com/CryptoJones/AdmiralGrace/issues/360)
- [ ] Expose possible-value-set analysis in the workbench and the CLI — [#361](https://github.com/CryptoJones/AdmiralGrace/issues/361)
- [ ] Variables pane: register, stack and flag variables with their placement — [#362](https://github.com/CryptoJones/AdmiralGrace/issues/362)
- [ ] Stack layout pane with variable creation — [#363](https://github.com/CryptoJones/AdmiralGrace/issues/363)
- [ ] Listing: stack-offset column — [#364](https://github.com/CryptoJones/AdmiralGrace/issues/364)
- [ ] Highlight every instruction that reads or writes the selected register's value — [#365](https://github.com/CryptoJones/AdmiralGrace/issues/365)
- [ ] Track and override global pointer registers — [#366](https://github.com/CryptoJones/AdmiralGrace/issues/366)
- [ ] Type fragments: track parts of a struct held in registers — [#367](https://github.com/CryptoJones/AdmiralGrace/issues/367)

### Type system

- [ ] Type system: structs, unions, enums and typedefs, with a C type parser and a Types view — [#368](https://github.com/CryptoJones/AdmiralGrace/issues/368)
- [ ] Smart structures: build a struct from the accesses to a pointer — [#369](https://github.com/CryptoJones/AdmiralGrace/issues/369)
- [ ] Type propagation with automatic array and struct detection — [#370](https://github.com/CryptoJones/AdmiralGrace/issues/370)
- [ ] Choose the union field per instruction — [#371](https://github.com/CryptoJones/AdmiralGrace/issues/371)
- [ ] Bitfield struct members — [#372](https://github.com/CryptoJones/AdmiralGrace/issues/372)
- [ ] Type attributes: packing, base classes, noreturn, pure, custom value locations and more — [#373](https://github.com/CryptoJones/AdmiralGrace/issues/373)
- [ ] Model C++ classes, inheritance and virtual function tables — [#374](https://github.com/CryptoJones/AdmiralGrace/issues/374)
- [ ] Parse MSVC and Itanium RTTI and build vtable structures — [#375](https://github.com/CryptoJones/AdmiralGrace/issues/375)
- [ ] Type libraries: per-library types and signatures, applied by import name — [#376](https://github.com/CryptoJones/AdmiralGrace/issues/376)
- [ ] Type archives shared across projects — [#377](https://github.com/CryptoJones/AdmiralGrace/issues/377)
- [ ] Platform types per OS and architecture, editable by the user — [#378](https://github.com/CryptoJones/AdmiralGrace/issues/378)
- [ ] Import types from C headers with compiler flags — [#379](https://github.com/CryptoJones/AdmiralGrace/issues/379)
- [ ] Export types as a C header — [#380](https://github.com/CryptoJones/AdmiralGrace/issues/380)
- [ ] Port types and signatures from another project by matching symbols — [#381](https://github.com/CryptoJones/AdmiralGrace/issues/381)
- [ ] Import COM interface types by GUID — [#382](https://github.com/CryptoJones/AdmiralGrace/issues/382)
- [ ] Apply JNI types to Java_* and JNI_* functions automatically — [#383](https://github.com/CryptoJones/AdmiralGrace/issues/383)
- [ ] Cross references for types and struct members — [#384](https://github.com/CryptoJones/AdmiralGrace/issues/384)
- [ ] Show a constant as an enum member — [#385](https://github.com/CryptoJones/AdmiralGrace/issues/385)
- [ ] Quick data-typing keys: width, sign, complement, char array, pointer, array — [#386](https://github.com/CryptoJones/AdmiralGrace/issues/386)

### Function signatures

- [ ] Edit function properties: prototype, calling convention, stack adjustment, clobbers, value locations — [#387](https://github.com/CryptoJones/AdmiralGrace/issues/387)
- [ ] Support more calling conventions, including Go, Pascal and struct-by-value — [#388](https://github.com/CryptoJones/AdmiralGrace/issues/388)
- [ ] Per-function analysis settings — [#389](https://github.com/CryptoJones/AdmiralGrace/issues/389)

### Strings and constants

- [ ] Strings: UTF-32, big-endian wide strings and code pages — [#390](https://github.com/CryptoJones/AdmiralGrace/issues/390)
- [ ] String recognizer API for decoding obfuscated strings — [#391](https://github.com/CryptoJones/AdmiralGrace/issues/391)
- [ ] Constant renderer API — [#392](https://github.com/CryptoJones/AdmiralGrace/issues/392)
- [ ] Strings that are not NUL-terminated (Go) — [#393](https://github.com/CryptoJones/AdmiralGrace/issues/393)

### Library identification

- [ ] Function matching by whole-function hash that applies names, types and comments — [#394](https://github.com/CryptoJones/AdmiralGrace/issues/394)
- [ ] Networked signature server — [#395](https://github.com/CryptoJones/AdmiralGrace/issues/395)
- [ ] Highlight matched library functions and choose between matches — [#396](https://github.com/CryptoJones/AdmiralGrace/issues/396)
- [ ] Byte-pattern signature libraries — [#397](https://github.com/CryptoJones/AdmiralGrace/issues/397)

### Diffing

- [ ] Binary similarity and diffing between versions — [#398](https://github.com/CryptoJones/AdmiralGrace/issues/398)
- [ ] Export BinExport for BinDiff — [#399](https://github.com/CryptoJones/AdmiralGrace/issues/399)

### Debug info and interop

- [ ] Import PDB debug info, with symbol server download — [#400](https://github.com/CryptoJones/AdmiralGrace/issues/400)
- [ ] Import DWARF from the image, a sibling file, a dSYM, debuginfod or a build-ID directory — [#401](https://github.com/CryptoJones/AdmiralGrace/issues/401)
- [ ] Export the analysis as DWARF — [#402](https://github.com/CryptoJones/AdmiralGrace/issues/402)
- [ ] Import IDA databases and type libraries — [#403](https://github.com/CryptoJones/AdmiralGrace/issues/403)
- [ ] Import Ghidra databases and projects — [#404](https://github.com/CryptoJones/AdmiralGrace/issues/404)
- [ ] Export to a Ghidra .gzf — [#405](https://github.com/CryptoJones/AdmiralGrace/issues/405)
- [ ] Import CMSIS SVD peripheral maps — [#406](https://github.com/CryptoJones/AdmiralGrace/issues/406)
- [ ] Load an external debug info file, through a pluggable debug info parser API — [#407](https://github.com/CryptoJones/AdmiralGrace/issues/407)

### Architectures

- [ ] Decode and lift MIPS, including nanoMIPS — [#408](https://github.com/CryptoJones/AdmiralGrace/issues/408)
- [ ] Decode and lift PowerPC, including VLE — [#409](https://github.com/CryptoJones/AdmiralGrace/issues/409)
- [ ] Decode and lift RISC-V — [#410](https://github.com/CryptoJones/AdmiralGrace/issues/410)
- [ ] Decode and lift MSP430 — [#411](https://github.com/CryptoJones/AdmiralGrace/issues/411)
- [ ] Decode TriCore, Hexagon, TMS320C6x, C-SKY and NDS32 — [#412](https://github.com/CryptoJones/AdmiralGrace/issues/412)
- [ ] Decode 6502, Z80 and SuperH — [#413](https://github.com/CryptoJones/AdmiralGrace/issues/413)
- [ ] x86 extras: AT&T syntax, APX, MPX and the x32 ABI — [#414](https://github.com/CryptoJones/AdmiralGrace/issues/414)
- [ ] Architecture hook API: patch an architecture's lifting from a plugin — [#415](https://github.com/CryptoJones/AdmiralGrace/issues/415)

### Formats and loaders

- [ ] Load the dyld shared cache, one image at a time — [#416](https://github.com/CryptoJones/AdmiralGrace/issues/416)
- [ ] Load an Apple kernelcache — [#417](https://github.com/CryptoJones/AdmiralGrace/issues/417)
- [ ] Load MediaTek MD1ROM modem images — [#418](https://github.com/CryptoJones/AdmiralGrace/issues/418)
- [ ] Load VxWorks images and TI COFF — [#419](https://github.com/CryptoJones/AdmiralGrace/issues/419)
- [ ] Load minidumps and core dumps — [#420](https://github.com/CryptoJones/AdmiralGrace/issues/420)
- [ ] Load Intel HEX, Motorola S-record and TI-TXT — [#421](https://github.com/CryptoJones/AdmiralGrace/issues/421)
- [ ] UEFI and TE images, with EFI protocol resolution — [#422](https://github.com/CryptoJones/AdmiralGrace/issues/422)
- [ ] More platforms: FreeBSD, Windows kernel, macOS kernel, EFI, DECREE — [#423](https://github.com/CryptoJones/AdmiralGrace/issues/423)
- [ ] Detect the base address of raw firmware — [#424](https://github.com/CryptoJones/AdmiralGrace/issues/424)
- [ ] Memory map editing: file-backed, pattern and unbacked regions, section semantics — [#425](https://github.com/CryptoJones/AdmiralGrace/issues/425)
- [ ] Load options per loader, remembered per file — [#426](https://github.com/CryptoJones/AdmiralGrace/issues/426)
- [ ] Kaitai Struct parsing in a structure tree — [#427](https://github.com/CryptoJones/AdmiralGrace/issues/427)

### Containers and transforms

- [ ] Open files inside archives and containers — [#428](https://github.com/CryptoJones/AdmiralGrace/issues/428)
- [ ] Byte transforms: Base64, hex, XOR, compression, and copy-as and paste-from — [#429](https://github.com/CryptoJones/AdmiralGrace/issues/429)
- [ ] Extract embedded blobs from firmware — [#430](https://github.com/CryptoJones/AdmiralGrace/issues/430)

### Patching

- [ ] Compile C source into a patch — [#431](https://github.com/CryptoJones/AdmiralGrace/issues/431)
- [ ] Preset branch patches: invert, always branch, never branch, skip and return a value — [#432](https://github.com/CryptoJones/AdmiralGrace/issues/432)
- [ ] Create a memory region when a patch writes to unbacked addresses — [#433](https://github.com/CryptoJones/AdmiralGrace/issues/433)

### Analysis pipeline and automation

- [ ] Workflows: customizable analysis pipelines — [#434](https://github.com/CryptoJones/AdmiralGrace/issues/434)
- [ ] Analysis modes and limits — [#435](https://github.com/CryptoJones/AdmiralGrace/issues/435)
- [ ] Find functions by linear sweep and pointer sweep — [#436](https://github.com/CryptoJones/AdmiralGrace/issues/436)
- [ ] Open at main rather than the entry point — [#437](https://github.com/CryptoJones/AdmiralGrace/issues/437)
- [ ] Settings with user, project and resource scopes — [#438](https://github.com/CryptoJones/AdmiralGrace/issues/438)
- [ ] C API and bindings for other languages — [#439](https://github.com/CryptoJones/AdmiralGrace/issues/439)
- [ ] Render layer API — [#440](https://github.com/CryptoJones/AdmiralGrace/issues/440)
- [ ] Data renderer API — [#441](https://github.com/CryptoJones/AdmiralGrace/issues/441)
- [ ] Custom flow graph and graph layout API — [#442](https://github.com/CryptoJones/AdmiralGrace/issues/442)
- [ ] Plugin UI API: forms and background tasks — [#443](https://github.com/CryptoJones/AdmiralGrace/issues/443)
- [ ] Pluggable providers for scripting, secrets and downloads — [#444](https://github.com/CryptoJones/AdmiralGrace/issues/444)
- [ ] Store arbitrary metadata in the project, per function and globally — [#445](https://github.com/CryptoJones/AdmiralGrace/issues/445)
- [ ] Let plugins add MCP tools — [#446](https://github.com/CryptoJones/AdmiralGrace/issues/446)

### Workbench

- [ ] Triage summary view — [#447](https://github.com/CryptoJones/AdmiralGrace/issues/447)
- [ ] Feature map: a colored overview of the whole binary — [#448](https://github.com/CryptoJones/AdmiralGrace/issues/448)
- [ ] Byte overview view in CP437 — [#449](https://github.com/CryptoJones/AdmiralGrace/issues/449)
- [ ] Command palette — [#450](https://github.com/CryptoJones/AdmiralGrace/issues/450)
- [ ] Custom key bindings, with IDA and Ghidra presets — [#451](https://github.com/CryptoJones/AdmiralGrace/issues/451)
- [ ] Themes and a color-blind mode — [#452](https://github.com/CryptoJones/AdmiralGrace/issues/452)
- [ ] Tiled, synced and locked panes — [#453](https://github.com/CryptoJones/AdmiralGrace/issues/453)
- [ ] History pane: revert to any earlier annotation state — [#454](https://github.com/CryptoJones/AdmiralGrace/issues/454)
- [ ] Folders in the symbols list — [#455](https://github.com/CryptoJones/AdmiralGrace/issues/455)
- [ ] Cross references pane: tree and table layouts, filters, pinning — [#456](https://github.com/CryptoJones/AdmiralGrace/issues/456)
- [ ] Advanced search: wildcard byte patterns, YARA hex, regex, constants, text in pseudocode — [#457](https://github.com/CryptoJones/AdmiralGrace/issues/457)
- [ ] Hover previews of a reference's target — [#458](https://github.com/CryptoJones/AdmiralGrace/issues/458)
- [ ] URL handler: deep links to an address, and copy location as URL — [#459](https://github.com/CryptoJones/AdmiralGrace/issues/459)
- [ ] Analysis log: filter by view and by logger — [#460](https://github.com/CryptoJones/AdmiralGrace/issues/460)
- [ ] Address display relative to the section, segment, function or image base — [#461](https://github.com/CryptoJones/AdmiralGrace/issues/461)
- [ ] Snippets: saved scripts bound to keys — [#462](https://github.com/CryptoJones/AdmiralGrace/issues/462)
- [ ] Extension manager with repositories, versions and dependencies — [#463](https://github.com/CryptoJones/AdmiralGrace/issues/463)
- [ ] Project file viewer and snapshot diff — [#464](https://github.com/CryptoJones/AdmiralGrace/issues/464)
- [ ] Type library explorer — [#465](https://github.com/CryptoJones/AdmiralGrace/issues/465)
- [ ] Save options: purge undo history and snapshots — [#466](https://github.com/CryptoJones/AdmiralGrace/issues/466)

### Multi-binary projects

- [ ] Projects holding several binaries and their resources — [#467](https://github.com/CryptoJones/AdmiralGrace/issues/467)
- [ ] Navigate across binaries through their imports and exports — [#468](https://github.com/CryptoJones/AdmiralGrace/issues/468)

### Collaboration

- [ ] Collaboration server: shared projects with sync and merge — [#469](https://github.com/CryptoJones/AdmiralGrace/issues/469)
- [ ] Live collaboration: chat, other users' positions, access control — [#470](https://github.com/CryptoJones/AdmiralGrace/issues/470)
- [ ] Type archives synced through the collaboration server — [#471](https://github.com/CryptoJones/AdmiralGrace/issues/471)

### Firmware analysis

- [ ] Classify firmware regions by entropy and create sections — [#472](https://github.com/CryptoJones/AdmiralGrace/issues/472)
- [ ] Detect memory-mapped I/O and RAM accesses — [#473](https://github.com/CryptoJones/AdmiralGrace/issues/473)
- [ ] Board description database for microcontrollers — [#474](https://github.com/CryptoJones/AdmiralGrace/issues/474)
- [ ] Relationships between firmware images — [#475](https://github.com/CryptoJones/AdmiralGrace/issues/475)

### Debugger

- [ ] Windows debugging: native, DbgEng, dump files and Wine — [#476](https://github.com/CryptoJones/AdmiralGrace/issues/476)
- [ ] GDB remote protocol: debug under QEMU, VMware and emulators — [#477](https://github.com/CryptoJones/AdmiralGrace/issues/477)
- [ ] Remote debugging through a debug server — [#478](https://github.com/CryptoJones/AdmiralGrace/issues/478)
- [ ] Time-travel debugging with WinDbg TTD and rr — [#479](https://github.com/CryptoJones/AdmiralGrace/issues/479)
- [ ] Time-travel queries and coverage — [#480](https://github.com/CryptoJones/AdmiralGrace/issues/480)
- [ ] Windows kernel debugging — [#481](https://github.com/CryptoJones/AdmiralGrace/issues/481)
- [ ] Conditional and hardware breakpoints and watchpoints — [#482](https://github.com/CryptoJones/AdmiralGrace/issues/482)
- [ ] Debugger panes: registers, stack, threads, modules, memory map, console — [#483](https://github.com/CryptoJones/AdmiralGrace/issues/483)
- [ ] Step by IL instruction and annotate stack variables while debugging — [#484](https://github.com/CryptoJones/AdmiralGrace/issues/484)
- [ ] Debugger scripting API and custom debug adapters — [#485](https://github.com/CryptoJones/AdmiralGrace/issues/485)
- [ ] Extract capabilities from a time-travel trace — [#486](https://github.com/CryptoJones/AdmiralGrace/issues/486)

### Objective-C and Swift

- [ ] Objective-C: resolve objc_msgSend to direct calls and drop retain and release noise — [#487](https://github.com/CryptoJones/AdmiralGrace/issues/487)
- [ ] Objective-C: constant sections, CFStrings, and cross references from selector to implementation — [#488](https://github.com/CryptoJones/AdmiralGrace/issues/488)

### AI

- [ ] AI assistant with name and type recovery tied back to the analysis — [#489](https://github.com/CryptoJones/AdmiralGrace/issues/489)

---

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
