# The program image fixtures

The images the image tests read, and how they were made.

| Fixture | What it is |
|---|---|
| `sample.exe` | A PE32+ (x86-64) console executable for Windows. |
| `sample.macho` | A Mach-O (x86-64) executable. |
| `sample.c` | The source both of them were built from. |

The ELF the tests read is in `crates/ag-engine/tests/fixtures/sample.elf`; the engine's
own tests read it, and the image tests read it from there.

## The source

```c
int counter = 41;
const char *greeting = "hello";

int add(int a, int b) {
    return a + b;
}

int main(void) {
    int total = 0;
    for (int i = 0; i < 3; i++) {
        total = add(total, i);
    }
    return total + counter + greeting[0];
}
```

Two functions, a piece of data and a string, so that every surface the image tests
read has something in it.

## How they were built

Both were built with the LLVM toolchain (clang 21.1.8 and lld 21.1.8):

```sh
# The Mach-O
clang -target x86_64-apple-darwin -c sample.c -o sample.o
ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -o sample.macho sample.o -e _main

# The PE
clang -target x86_64-pc-windows-msvc -c sample.c -o sample.obj
lld-link /def:exports.def /entry:main /subsystem:console /out:sample.exe sample.obj
```

The PE names its functions through an export table, which is how a Windows image
without a symbol table names them. The export table is:

```
EXPORTS
    add
    main
    counter
```

A Mach-O names its symbols with a leading underscore, so the functions of
`sample.macho` are `_add` and `_main`.
