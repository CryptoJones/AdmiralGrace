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
  "format": 1,
  "target": {
    "path": "/bin/ls",
    "sha256": "35ee8f62…"
  },
  "options": { "loop-form": "while" },
  "annotations": [
    { "kind": "function", "address": "0x1198", "name": "main", "bookmark": true },
    { "kind": "address", "address": "EXTERNAL:0x1", "comment": "imported qsort" }
  ]
}
```

| Field | Meaning |
|---|---|
| `format` | The format version. This program writes and reads `1`. A file naming a newer version is refused with a notice, not misread. |
| `target.path` | Where the target was when the project was written. |
| `target.sha256` | The SHA-256 of the target, so a project can be checked against the binary it describes. |
| `options` | The analysis options the run used, as name to value — the names `ag catalog` lists. |
| `annotations` | The analyst's changes, in the order they were made. |

## An annotation

An annotation is one address's worth of the analyst's decisions.

| Field | Meaning |
|---|---|
| `kind` | What the annotation is attached to: `function`, `address` or `region`. |
| `address` | The address, written the way a corpus writes it — `EXTERNAL:0x1` when the record names an address space. The space is part of the address's meaning, so a function and its `EXTERNAL` twin key apart. |
| `name` | The analyst's name, replacing the analysis's own. |
| `comment` | The analyst's note. |
| `bookmark` | Whether the target is bookmarked. |
| `tags` | Tags carried by the target. |
| `color` | A color for the target, as `#rrggbb`. |
| `byte_type` | How the bytes at the target are classified: `code`, `function`, `data`, `string` or `undefined`. |

Every field but `kind` and `address` is optional and is left out when it carries nothing. An
annotation that has come to carry nothing at all is dropped on save, so the file says only
what the analyst changed.

## Reading one

A reader keeps what it knows and refuses a `format` newer than it reads. A field it does not
recognize is ignored rather than fatal, so a newer project still opens. `ag project TARGET
show FILE` prints the annotations, and re-hashes `TARGET` to say so when it no longer
matches the recorded SHA-256.
