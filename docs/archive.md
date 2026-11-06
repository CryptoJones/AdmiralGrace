# Type archives shared across projects

A type archive (`.agarchive`) is one file of types several projects sync
with — the stock a project buys into, and pays its own discoveries back
into. A project holds its own `types`; the archive holds the shared
ones, one entry per name, each its `name` and its `c`, the same shape a
project stores. `ag archive` pushes the project's types in and pulls
the archive's down, says where every name stands between the two sides,
and settles a name both hold differently, per type, with the analyst's
choice of which side wins.

```jsonc
{
  "format": 1,
  "types": [
    { "name": "struct point", "c": "struct point { int x, y; };" }
  ]
}
```

## The format

Versioned JSON like the project file, so it survives a session, travels
between machines, and stays readable without AdmiralGrace. `format` is
the format version — this program writes and reads `1`. A reader of a
newer version is refused with a notice, not misread, and an unknown
field is ignored rather than fatal. `types` is the definitions in stored
order, each `{"name": ..., "c": ...}` — the same record the project's
`types` holds, and the `c` the definition: the layout is read from it
under the image's data model each time the image is read, exactly as a
project's own type is. An empty archive is `{"format": 1}`. The archive
carries no target of its own: one archive serves every project.

## The sync

- `ag archive create ARCHIVE [--from PROJECT]` — make the archive,
  empty, or seeded with the types a project file holds. Refuses a path
  that is already there.
- `ag archive show ARCHIVE [--json]` — the archive's types, with their
  C, each its name and definition; `--json` as `{"name", "c"}` entries.
- `ag archive push --project PROJECT ARCHIVE [--keep project|archive] [--json]`
  — the project's types into the archive: every name the project holds
  goes in; a name in-sync is left, one the archive alone holds untouched.
  An archive not there yet is made on the first push, and the push says
  so on stderr.
- `ag archive pull --project PROJECT ARCHIVE [--keep project|archive] [--json]`
  — the archive's types into the project, the same way round. A project
  file not there yet is made, with the archive's types in it. The
  archive itself must exist: a pull from a missing path is refused, not
  read as empty. The same goes for `show`, `status`, and `resolve` — a
  missing archive is an error, so a mistyped path is never read as an
  empty, divergent shared archive.
- `ag archive status --project PROJECT ARCHIVE [--json]` — where every
  name stands between the two sides, in name order: `in-sync` (both hold
  the name with the same `c`), `project-only`, `archive-only`, `conflict`
  (both hold it, with different `c`). With `--json`, the rows carry the
  `c` each side holds when it holds the name.
- `ag archive resolve --project PROJECT ARCHIVE NAME --keep project|archive`
  — settle one conflict by changing one side alone: `--keep project`
  keeps the project's `c` and replaces the archive's with it;
  `--keep archive` keeps the archive's and replaces the project's.

There is no common ancestor: the sync is two-sided, and equality is on
the definition itself, the `name` and the `c`. `push` and `pull` settle
every conflict they meet or they stop: without `--keep`, a conflict
leaves both sides kept, prints the status, and exits 1; with it, the
side the word names wins — on a push `--keep project` overwrites the
archive, `--keep archive` keeps the archive's and skips the project's;
on a pull, the other way round. A name the archive does not hold is
pushed; a name the project does not hold is pulled; neither is ever
deleted by a sync. `resolve` refuses a name that is not a conflict.
