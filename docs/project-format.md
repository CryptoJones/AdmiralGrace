# The project file format

A project file — the extension is `.agproj` — holds the analyst's work: what was analysed,
the options the run used, and every change the analyst made on top of the analysis. It is
versioned JSON, so it survives a session, travels between machines, and stays readable
without AdmiralGrace. `ag project` reads and writes it, and so does the workbench.

The corpus and the image say what the machine found. The project file says what the analyst
decided. The two are separate files on purpose: the analysis can be thrown away and
regenerated, and the annotations stay.

## The shape

```json
{
  "format": 5,
  "target": {
    "path": "/bin/ls",
    "sha256": "35ee8f62…"
  },
  "options": { "loop-form": "while" },
  "layout": {
    "base": "0x400000",
    "segments": [
      { "action": "rename", "name": ".text", "to": "code" },
      { "action": "add", "name": "extra", "address": "0x405000", "size": 16, "file_offset": "0x3000" }
    ]
  },
  "annotations": [
    { "kind": "function", "address": "0x1198", "name": "main", "bookmark": true },
    { "kind": "address", "address": "EXTERNAL:0x1", "comment": "imported qsort" },
    { "kind": "variable", "address": "0x1161", "variable": "local_14", "name": "count" },
    { "kind": "register", "address": "0x1161", "register": "rax", "name": "total" },
    { "kind": "region", "address": "0x1161", "block": true, "color": "#8bcf9c" }
  ]
}
```

| Field | Meaning |
|---|---|
| `format` | The format version. This program writes and reads `6`. Version 2 lets one address carry a record per local variable as well as its own; version 3 adds a record per renamed register; version 4 adds a record for the block of bytes starting at an address, apart from the address's own; version 5 adds the `layout`; version 6 adds `target.raw`. A reader of an older version would misread those records as the address's own, read the image unmoved, or read raw bytes as a container. A file naming a newer version is refused with a notice, not misread. An older file that gains a register or block record, a layout, or a raw target, is written back at `6`, so a reader that would misread it refuses it instead. |
| `target.path` | Where the target was when the project was written. |
| `target.sha256` | The SHA-256 of the target, so a project can be checked against the binary it describes. |
| `target.raw` | How the target loads when it is raw bytes with no container to say — firmware, shellcode, a dump: `arch` (`x86-64`, `x86`, `arm`, `thumb`, `aarch64`), `base`, and when they apply `entry`, `offset` into the file and `length`. A reader opens the target as those bytes; left out for an image with a container. |
| `target.slice` | Which slice of a universal (fat) Mach-O the target is — the architecture's name, `arm64`, or its position — when the file holds several images. A reader opens that slice; left out for a file that is one image. A segment's `file_offset` in the layout is then the slice's, measured from where the slice starts in the file. A target is raw bytes or a slice, not both. |
| `options` | The analysis options the run used, as name to value — the names `ag catalog` lists. |
| `layout` | The layout the image is read under, when the analyst corrected the loader's — for raw bytes, measured from the base they were said to load at —: `base`, the address its lowest mapped page is moved to, and `segments`, the edits in order — `{ "action": "add", "name", "address", "size", "file_offset", "executable" }`, `{ "action": "remove", "name" }`, `{ "action": "rename", "name", "to" }`. Addresses are the moved image's; a reader applies the base first, measuring the move from the base the format states — a PE's image base, else the page of the lowest segment the file holds bytes for. Left out when it changes nothing. |
| `annotations` | The analyst's changes, in the order they were made. |

## An annotation

An annotation is one address's worth of the analyst's decisions.

| Field | Meaning |
|---|---|
| `kind` | What the annotation is attached to: `function`, `address`, `region`, `variable` or `register`. A record made at a bare address becomes a `function`'s when a later change knows the address is a function entry; it never goes back, so a mark that reaches the whole function keeps reaching it. |
| `address` | The address, written the way a corpus writes it — `EXTERNAL:0x1` when the record names an address space. The space is part of the address's meaning, so a function and its `EXTERNAL` twin key apart. |
| `variable` | The local variable the record names, as the pseudocode declares it. A variable is a different thing from the function or label at the same address, so it carries this field and gets a record of its own; a record without it belongs to the address. |
| `block` | `true` on the record of the block of bytes starting at the address, as opposed to the address's own record. A block and its first instruction share an address but are two things — a color on the block tints every line of it, a color on the address one — so the block's record stands apart, and the two never overwrite each other. Always written with `kind` `region`. |
| `references` | The addresses the target refers to that the analysis cannot see — a computed call, a jump through a table — each in its canonical spelling, sorted and unique. A reference is recorded on the place it leaves from. |
| `operand_format` | How the constants in the instruction's operands are shown: `signed`, `decimal`, `octal` or `address`. Hexadecimal is how the analysis prints them, so it is never recorded. |
| `jump_table` | Where the jump table the instruction at the address reads is, as the analyst said: the table's address, the width of an entry in bytes and the number of entries — `0x402000 8 6` — with ` rel` after for entries that are offsets from the table. Told to the analysis where its own recovery fails. |
| `patch` | The bytes the analyst wrote over the image's, starting at the address, as hex pairs: `B8 01 00 00 00`. The file on disk is never changed; a reader applies the patch as it reads the image. |
| `patch_text` | What the analyst typed to make the patch, when it was an instruction: `mov eax, 1`. |
| `overrides` | The analyst's word at the address on the judgment calls the lift makes there, each `true` to allow or `false` to prevent: `guard` (a branch whose one arm never falls through is a guard the rest follows unnested), `fold` (a condition comparing an expression with itself is the constant it is), `invert` (the condition turned round with its arms), `switch` (the indirect jump reads a jump table). `{"guard": false}` keeps the `if`/`else`. A kind left out is the lift's own call; a reader that does not know the field lifts as it always did. |
| `register` | The register the record renames, spelled as the listing spells it — `rax`, `ebp`. A register belongs to no one address; it is printed across one function's pseudocode and listing, so the record keys on the register's name beside the function's entry address and the rename reaches that function alone. |
| `name` | The analyst's name, replacing the analysis's own. |
| `comment` | The analyst's note. |
| `comment_above` | Whether the note stands on its own line above the instruction. Absent means inline, at the end of the line. A reader that does not know the field prints every comment inline, which loses placement but misreads nothing. |
| `bookmark` | Whether the target is bookmarked. |
| `tags` | Tags carried by the target. |
| `color` | A color for the target, as `#rrggbb`. |
| `mode` | The instruction set the code from the target onward decodes in, on an architecture that has more than one: `arm` or `thumb`. The mark reaches to the next mark or symbol that says otherwise. |
| `byte_type` | How the bytes at the target are read, as the analyst said: `code`, `function`, `string`, `undefined`, or `data:W` for items of `W` bytes (1, 2, 4 or 8) with `[N]` after it for an array of `N` — `data:4[8]`. A reader that does not know a spelling keeps it and shows nothing for it. |

Every field but `kind` and `address` is optional and is left out when it carries nothing. An
annotation that has come to carry nothing at all is dropped on save, so the file says only
what the analyst changed.

## Reading one

A reader keeps what it knows and refuses a `format` newer than it reads. A field it does not
recognize is ignored rather than fatal, so a newer project still opens. `ag project TARGET
show FILE` prints the annotations, and re-hashes `TARGET` to say so when it no longer
matches the recorded SHA-256.
