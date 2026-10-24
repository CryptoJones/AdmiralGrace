# AdmiralGrace UI

This directory holds the AdmiralGrace desktop workbench: an [Iced](https://iced.rs) application that reads a decompilation corpus through the same data layer the `ag` CLI uses. `UI_PLAN.md` is the product and interaction plan it is built from.

## Files

- `UI_PLAN.md` — product goals, reference review, layout, workflows, roadmap, and decisions.
- `wireframe.html` — a self-contained static desktop-screen mockup with sample data. It is a layout reference; the application is implemented in Iced.
- `src/` — the workbench crate (`ag-ui`).

## Run it

```sh
# From the repository root
cargo run --bin ag-ui

# Open a corpus
cargo run --bin ag-ui -- --corpus ./corpus

# Overlay an Objective-C method map
cargo run --bin ag-ui -- --corpus ./corpus --methods ./corpus/methods.json

# Open a program image
cargo run --bin ag-ui -- --binary ./sample.elf
```

The corpus directory must contain a `decompile-index.json`. Opened from the File menu, the workbench prompts for a path and refuses a directory without that index. With no corpus on the command line the workbench opens a bundled sample project so the interface can be explored.

A program image is parsed by the engine's own loader: the navigator lists its symbols, the inspector shows its sections and entry point, and the Listing tab holds the native x86-64 disassembly. The Graph tab draws the control-flow graph of the selected function: a box for every block, an arrow for every way the code goes on, and the branch that is taken told from the fall-through. The Bytes tab and the lower Bytes panel show the bytes of the file around the selection, sixteen to a row, with the bytes of the selected instruction marked. The Strings tab holds the text the image carries, with the functions that use it; it filters as you type, and picking a string moves the selection to it and names the functions that use it in the inspector. Opened from the File menu, the workbench prompts for a path and refuses a path that is not a file.

## Shape of the code

- `src/main.rs` — argument parsing and the Iced application entry point.
- `src/app.rs` — application state, messages, the update loop, and the keyboard shortcuts.
- `src/data/` — the `Provider` trait and its implementations: `corpus` (a real corpus), `binary` (a program image read by the engine), `kuna` (a kuna project export), `sample` (the bundled demo project), and `empty` (no project open).
- `src/model/` — the shared selection, navigation history, project identity, and the capability flags that tell the views what a provider can supply.
- `src/views/` — the panes: menu bar, header, navigator, work surface, inspector, bottom workspace, status bar, and the inline path prompt. The graph of a function is in `src/views/graph.rs`: the layout of the blocks is pure and tested, and the canvas on top of it draws them.

Providers advertise capabilities, so a corpus that only carries pseudocode shows an honest empty state for listing and bytes instead of a blank panel.

## Open the mockup

Open `wireframe.html` in a browser. It has no dependencies and does not connect to the repository or load binaries.
