# The program image fixtures

The images the image tests read, and how they were made.

| Fixture | What it is |
|---|---|
| `sample.exe` | A PE32+ (x86-64) console executable for Windows. |
| `sample.macho` | A Mach-O (x86-64) executable. |
| `sample32.elf` | A 32-bit ELF (i386) executable, statically linked with no C library. |
| `sample.c` | The source all of them were built from. |

The 64-bit ELF the tests read is in `crates/ag-engine/tests/fixtures/sample.elf`; the
engine's own tests read it, and the image tests read it from there.

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

The PE and the Mach-O were built with the LLVM toolchain (clang 21.1.8 and lld 21.1.8):

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

The 32-bit ELF was built with GCC (gcc 15.2.0 and GNU ld, Ubuntu), with no C library
and `main` as the entry point, so that the whole image is the two functions, the data
and the string:

```sh
# The 32-bit ELF
gcc -m32 -O0 -fno-pic -no-pie -fno-stack-protector -fcf-protection=none \
    -fno-asynchronous-unwind-tables -nostdlib -static -Wl,-e,main \
    -o sample32.elf sample.c
```

The loader names its language `x86:LE:32:default:gcc`, which is what tells the decoder
to read 32-bit code. `-fno-pic -no-pie` is what makes `main` read `counter` and
`greeting` through absolute memory operands (`mov edx,[804B008h]`) rather than off a
GOT register, so the data references of the image tests have something to find. The
functions are `add` at `0x8049000` and `main` at `0x804900d`; `counter` is at
`0x804b008` and `greeting` at `0x804b00c`.
