# AdmiralGrace desktop UI plan

**Status:** Initial proposal  
**Scope:** A cross-platform analysis workbench for static binary analysis, decompilation, and byte-level inspection.

## Product direction

AdmiralGrace should make it easy to move between three questions without losing context:

1. What is this file and what has analysis discovered?
2. How does this function behave, and what calls or data lead to it?
3. Which bytes, types, and file structures support that interpretation?

The defining interaction is a synchronized workspace: selecting a function, address, or byte range updates the related views, and every view can be opened independently when the analyst needs to compare locations. Results should expose confidence and provenance (decoder output, analysis inference, imported symbols, or analyst annotation) instead of presenting guesses as facts.

## Product context

The current repository contains `ag-cli`, `ag-corpus`, and an early `ag-engine`. Corpus stats, function listing, function display, regex search, and Objective-C method overlays are real foundations. Binary-to-pseudocode is not complete. The first UI milestone should therefore support corpus projects and sample/imported analysis results, with capability-aware empty states for work still being built.

## Reference review

The references below suggest interaction patterns, not a visual copy.

| Product | Useful patterns | Design implication for AdmiralGrace |
| --- | --- | --- |
| IDA | Dockable synchronized subviews; function and name lists; linear, graph, and proximity views; shared navigation history and cross-reference tree. | Keep one address context across listing, decompilation, and bytes. Offer graph and linear modes from the same location. |
| Ghidra CodeBrowser and Debugger | Configurable tool layouts; listing, decompiler, bytes, graph, and debugger panes; synchronized static and dynamic views; diagnostics and session panels. | Make panels rearrangeable later, but ship a strong default layout. Keep analysis status and actionable diagnostics visible. |
| Hopper | Symbols and strings on the left, contextual inspector on the right, code representations in the center. | Use a clear navigator / work surface / inspector structure and filterable symbol lists. |
| ImHex | Rich byte view, patch tracking, data interpretation, highlighting, bookmarks, and pattern-based structure parsing. | Treat bytes as a first-class view, with typed interpretation, annotations, and reversible patches. |
| Hex Fiend | Large-file performance, insert/delete editing, binary diff, and a data inspector. | Design for virtualized large-file access, explicit edits, and useful comparison tools. |

### Source links

- [IDA subviews and synchronization](https://docs.hex-rays.com/ida-9.2/user-guide/user-interface/subviews)
- [IDA basic usage and view modes](https://docs.hex-rays.com/9.0sp1/getting-started/basic-usage)
- [Ghidra CodeBrowser default tool layout](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Configurations/Public_Release/src/main/resources/defaultTools/CodeBrowser.tool)
- [Ghidra Debugger UI tour](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Debugger/A2-UITour.md)
- [Hopper tutorial](https://www.hopperapp.com/tutorial.html)
- [ImHex feature list and project](https://github.com/WerWolv/ImHex)
- [Hex Fiend](https://hexfiend.com/)

## Proposed default workspace

Use a dark, low-glare theme with restrained semantic color. Preserve dense technical data while providing strong hierarchy, readable monospace text, keyboard navigation, and scalable text size. The static mockup shows one plausible desktop state.

```text
┌ Application menu / project tabs / global search / analysis state ─────────────┐
├ Project navigator ─┬ Main analysis work surface ─────┬ Context inspector ───┤
│ Functions          │ Disassembly | Pseudocode | Graph │ Address / function   │
│ Imports / Exports  │ address  bytes  instruction     │ selected item        │
│ Strings            │ labels, xrefs, comments         │ xrefs / properties   │
│ Segments / Types   ├─────────────────────────────────┤ type interpretation  │
│ Bookmarks          │ Bytes | Strings | References    │ notes / history      │
├───────────────────┴─────────────────────────────────┴───────────────────────┤
│ Search results / Problems / Analysis log / Patch history                     │
├ status: file, architecture, analysis progress, dirty state, selection         ┤
└───────────────────────────────────────────────────────────────────────────────┘
```

### Global navigation

- Project tabs for multiple binaries or corpus datasets.
- A command/search field accepting symbol names, addresses, strings, and actions.
- Back/forward history shared across synchronized views.
- Analysis progress, current architecture, active file, and save/modified state.

### Left navigator

Filterable, sortable lists for Functions, Imports, Exports, Strings, Segments, Types, Bookmarks, and Search Results. Each list shows only high-value columns by default; users can add columns such as address, size, references, and confidence. Selecting a row navigates the central views. The navigator can collapse to a narrow icon rail.

### Center work surface

Tabbed and split views for:

- **Listing:** linear disassembly/data view, with instruction bytes, address, labels, xref indicators, comments, and analysis annotations.
- **Pseudocode:** decompiler output when available; otherwise a clear explanation and link to supported alternatives.
- **Graph:** basic blocks, control-flow edges, minimap, and current-block focus. Keep linear listing available for data and non-function regions.
- **Bytes:** hex plus ASCII/decoded text, selection synchronization, endian-aware inspector, and patch overlay.
- **Strings / References:** structured tables that can be docked or opened as tabs.

A tab should retain its location and view state. Split panes should support pinning a location so analysts can compare two functions without synchronization moving both.

### Right inspector

Contextual details for the active selection: address and mapped file offset, segment, decoded bytes, inferred data type, references to/from, containing function, analysis origin/confidence, and analyst comments. For a byte selection, show common integer/float interpretations and endianness. For a function, show signature, size, callers/callees, and local analysis status.

### Bottom workspace

Dockable tabs for Problems, Search Results, Analysis Log, Patch History, and (in a later debugger milestone) Console and Trace. Errors should include a short cause and a direct action where possible. Do not use the log as the only place to show analysis state.

## Core workflows

### Open and orient

1. Open a binary or corpus project.
2. Show format, architecture, entry points, file segments, and analysis state.
3. Let the analyst start, pause, or inspect analysis; surface unsupported format/architecture details plainly.
4. Land at entry point with Functions and Strings available.

### Find a behavior

1. Search a symbol, string, address, or regex.
2. Open the match in Listing and show the containing function in Pseudocode/Graph when available.
3. Inspect callers, callees, and data references in the side panel.
4. Rename, comment, bookmark, or apply a type without leaving the work surface.

### Inspect bytes

1. Navigate from a function operand or string to its file bytes.
2. Keep address and byte selection synchronized across Listing and Bytes.
3. Interpret selected bytes using alternate widths and endianness.
4. Preview edits, show affected offsets, and record patches in an undoable patch history.

### Compare builds

1. Load a second binary as a comparison target.
2. Align symbols and byte ranges where possible.
3. Show changed functions, strings, and byte ranges with navigation back to each image.
4. Clearly distinguish unmatched or uncertain alignments.

## Interaction principles

- Keyboard-first: command search, jump-to-address, rename, comment, bookmark, view switching, and history navigation need discoverable shortcuts.
- One selection, shared context: synchronized by default, with explicit pin/unpin for comparisons.
- Safe edits: rename/comment/type changes are undoable; byte patches are previewed and tracked separately from analyst metadata.
- Explain analysis: show where a label/type came from and whether it is inferred or user-defined.
- Scale: virtualize long lists and byte ranges; avoid loading whole large files into UI memory.
- Accessible density: scalable fonts, strong focus states, color plus text/icon meaning, and usable contrast.
- Layout persistence: restore per-project workspace and offer a one-action reset to a known default.

## Suggested delivery sequence

### 0. UI foundation

Choose the desktop framework after a small platform/accessibility spike. Define project, address, selection, navigation-history, and capability models. Build the shell, command search, status area, saved layouts, and mock data provider.

### 1. Corpus browser

Connect `ag-corpus` to browse stats, functions, regex results, function bodies, and Objective-C method overlays. This makes the UI useful before the full binary pipeline exists. Provide fast filtering and address/name deep links.

### 2. Static analysis workbench

Connect file opening and engine capabilities as they become available. Add segments, imports/exports, strings, listing, control-flow graph, references, annotations, and typed byte inspector. Views should declare feature availability rather than assume every file has every analysis result.

### 3. Analyst productivity

Add project persistence, bookmarks, comments, renaming, undo/redo, exports, comparison view, and patch preview/history. Define a portable project format before storing annotations long term.

### 4. Dynamic analysis and extension points

Only after a debugger backend exists, add session/target controls, registers, stack, threads, memory, trace, and synchronized dynamic listing. Consider scripting/plugins after core data models and extension boundaries stabilize.

## Initial screen contents

A representative first project should show a sample corpus or binary with:

- filtered function list and address/size columns,
- one function selected,
- synchronized disassembly and pseudocode tabs,
- nearby bytes available in the lower tab strip,
- callers/callees and provenance in the inspector,
- analysis progress and diagnostic count in the status area.

The included HTML wireframe uses fabricated data solely to explain layout and interaction.

## Decisions to validate

1. Which desktop framework best fits Rust integration, native accessibility, docking, and cross-platform packaging?
2. Is the first target a corpus UI, a binary viewer, or both in one application shell? This proposal starts with corpus functionality and grows toward binary analysis.
3. Which executable formats and architectures are the first practical target?
4. Should edits persist in a sidecar project database, in the binary, or both? The proposal keeps annotations in a project and patches explicit.
5. How much of debugger support belongs in the initial product scope?

## First usability review

Ask 3–5 reverse engineers to complete these tasks with the mockup/prototype: locate a function by string, explain its caller path, inspect a pointer's bytes with endianness, compare two functions, and identify why a result is inferred. Record where navigation loses context, which columns are missing, and whether the density is comfortable at common laptop resolutions.
