# The IDA fixtures

The IDA databases and type libraries the IDA reader (`ag-engine/src/ida`,
`ag ida`) is tested against, and what each holds. They are copied from the
test data of **python-idb** (Willi Ballenthin, Apache-2.0), the reference
reader the format was worked out against; see NOTICE for the attribution.
The ground truth the tests assert was dumped with python-idb 0.8.0.

| Fixture | What it is |
|---|---|
| `small.bin` | The 13-byte raw binary (`hello world!\n`) the small databases below were made from. Its MD5 is `c897d1410af8f2c74fba11b1db511e9e`, which the databases record. |
| `func-comment_small.idb` | A 32-bit IDA 6.95 database of `small.bin`: one function at `0x3..0xd` (flags `0x401`) with a regular and a repeatable function comment, and anterior/posterior lines at `0x1`. Every section is uncompressed. |
| `ant-post-comments_small.idb` | The same binary with two anterior and two posterior comment lines at `0x1`, and the loader's header lines at `0x0`. |
| `small_small-colored.idb` | The same binary with colored instructions and segments; a second uncompressed 32-bit database. |
| `empty_empty.idb` | An empty 32-bit database: the index and sections are present but hold no names or functions. |
| `elf_cat.i64` | A 64-bit IDA 7.00 database of a stripped ELF `cat` (x86-64, imagebase `0x400000`): 321 names, 139 functions, 23 segments, 84 function prototypes, and a local type library of 21 types (`Elf64_Sym`, `Elf64_Rela`, `Elf64_Dyn`, `stat`, `timespec` and the `__*_t` typedefs, beside two C++ classes). Every section is zlib-compressed, so it exercises the inflate. |
| `empty_empty.til` | An empty type library: the `IDATIL` header and three empty buckets (symbols, types, macros), 72 bytes. |
| `inflate_vectors.json` | zlib streams made with Python's `zlib` at several levels (including a stored block), each beside its plaintext, for the inflate unit test. |

The two C++ classes in `elf_cat.i64` (scoped `$…::$…` names, base classes)
are no plain C and are held back by the type import, as they should be; the
plain-C types all render and read back through the engine's C parser.

Larger databases used while developing the reader (a compressed
`kernel32.idb`/`.i64` and the 313-type `TILTest.dll.i64`) are not shipped
here; they are python-idb test data too, and the reader was checked against
them locally.
