# The program image fixtures

The images the image tests read, and how they were made.

| Fixture | What it is |
|---|---|
| `sample.exe` | A PE32+ (x86-64) console executable for Windows. |
| `sample.macho` | A Mach-O (x86-64) executable. |
| `sample32.elf` | A 32-bit ELF (i386) executable, statically linked with no C library. |
| `sample.c` | The source all of them were built from. |
| `arm_thumb.elf` | A 32-bit ARM ELF executable, statically linked with no C library, whose code is Thumb but for one function built as ARM: what the SLEIGH decoder reads in both instruction sets, and switches between. |
| `arm_arm.elf` | The same source built as ARM throughout. |
| `arm_sample.c` | The source of the two ARM executables. |
| `arm_flows.elf` | A hand-written ARM executable: a call and a return under a condition, a Thumb `blx` into ARM code no symbol names, a literal-pool load. |
| `arm_flows_stripped.elf` | The same with every symbol removed: only the entry point's low bit says the mode. |
| `arm_flows.s` | The source of the two. |
| `arm64.elf` | An AArch64 ELF executable built from `arm_sample.c`, statically linked with no C library. |
| `sample_fat.macho` | A universal (fat) Mach-O holding two slices: `sample.macho` (x86-64) and an arm64 Mach-O built from `arm_sample.c`. |
| `make_fat.py` | Combines thin Mach-O files into a universal one, as `lipo -create` would, for hosts without `lipo`. |
| `sample_objc` | An x86-64 Mach-O built from `sample.m`: a root class, a subclass with properties, a category and a protocol with an optional method, and methods whose types are a struct, a pointer, a class and a block, with the Objective-C metadata the runtime reads and the symbols the linker kept. |
| `sample_objc_stripped` | The same file with its symbol table emptied: the method names come from the metadata alone, as in a shipped binary. |
| `sample_cpp.elf`, `sample_cpp.macho`, `sample_cpp.exe` | A C++ program built from `sample.cpp` for the three containers, with no runtime library: a namespace, a class with a constructor, two methods and a static member, two overloads of a free function and two instances of a template — every common shape of a mangled name, Itanium in the ELF and the Mach-O, Microsoft in the PE's export table. |
| `unwind.elf`, `unwind_stripped.elf`, `unwind.exe`, `unwind_stripped.macho` | Images whose functions only the unwind data names: `unwind.c` (three functions, two of them static) built as an ELF with its `.eh_frame` and then stripped of every symbol, and as a PE with its `.pdata` and no export table; and `sample.macho` with its symbol table emptied, its `__unwind_info` kept. |
| `sample_swift_x86`, `sample_swift_arm64`, `sample_swift_x86_stripped` | A Swift program built from `sample.swift` for x86-64 and arm64 macOS 12, and the x86-64 image with its symbol table emptied by `strip_symtab.py`: a protocol, a struct, an enum with payloads, a class and a subclass with properties and methods, a generic function and a closure, with the `__swift5_*` metadata the runtime reads and every symbol the compiler kept. `crates/ag-engine/tests/fixtures/swift_names.tsv` holds every mangled name of the x86-64 image beside what the Swift toolchain's own demangler says of it, and `swift_names2.tsv` the same for a second program (`swift_names2.swift`, not shipped as an image) whose names hold optionals, arrays, dictionaries, `throws`, `async`, associated types and multi-parameter generics. |
| `sample_objc_chained` | The same source linked for macOS 12 with chained fixups (`LC_DYLD_CHAINED_FIXUPS`): every pointer slot of the metadata holds a packed fixup, not an address, as every Mach-O linked for macOS 12 or iOS 15 and later does. |
| `sample.m` | The Objective-C source of the two. |
| `strip_symtab.py` | Empties a Mach-O's symbol table in place, for hosts without `strip` for Mach-O. |

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

## The switch fixtures

`crates/ag-engine/tests/fixtures/switch.elf` and `switch_pie.elf` hold a function with a
six-case `switch` that GCC (gcc 15.2.0, GNU ld 2.46, Ubuntu) compiles to a jump table,
built from `switch.c` beside them. The first reads an absolute table of 8-byte entries;
the second, position-independent, reads 4-byte offsets from the table's own address
through `lea`/`movsxd`/`add`:

```sh
gcc -O1 -fno-pic -no-pie -fno-stack-protector -fcf-protection=none \
    -fno-asynchronous-unwind-tables -nostdlib -static -Wl,-e,main \
    -o switch.elf switch.c
gcc -O1 -fpie -pie -fno-stack-protector -fcf-protection=none \
    -fno-asynchronous-unwind-tables -nostdlib -static-pie -Wl,-e,main \
    -o switch_pie.elf switch.c
```

`classify` is at `0x401000` (table at `0x402000`) and at `0x1000` (table at `0x2000`).

`switch_sub.elf` (from `switch_sub.c`, the same cases numbered 3..8, so gcc puts a `sub edi, 3`
before the guard) and `switch_loop.elf` (from `switch_loop.c`, a `switch` inside a `for` with
an arm that leaves the loop) are built the non-position-independent way. `classify` and `scan`
are at `0x401000`.

## The boundaries fixture

`crates/ag-engine/tests/fixtures/boundaries.elf` is hand-written code, from `boundaries.s`
beside it: `main` jumps into `helper`'s tail, which no function symbol names, and a routine
after the padding has no symbol at all. It is what the `branches-end-procedures` and
`code-sections` options are tested against.

```sh
gcc -nostdlib -static -no-pie -Wl,-e,main -o boundaries.elf boundaries.s
```

`main` is at `0x401000`, `helper` at `0x401007`, the shared `ret` at `0x40100c` and the
unnamed routine at `0x401010`. `boundaries32.elf` is the same source built `-m32`, where the
assembler pads with `lea esi, [esi+0]` rather than `nop`: `main` at `0x8049000`, the padding
at `0x804900d`, the unnamed routine at `0x8049010`.

```sh
gcc -m32 -nostdlib -static -no-pie -Wl,-e,main -o boundaries32.elf boundaries.s
```

The ARM executables were built with clang and its own linker (`-fuse-ld=lld`), with no C
library, `.text` pinned at `0x20000` so the addresses in the tests hold:

```sh
clang --target=armv7a-none-eabi -mthumb -O1 -nostdlib -static -fuse-ld=lld -Wl,-e,sum \
      -Wl,--gc-sections -Wl,-z,max-page-size=4096 -Wl,-z,noseparate-code -Wl,-Ttext=0x20000 \
      arm_sample.c -o arm_thumb.elf
clang --target=armv7a-none-eabi -marm   -O1 -nostdlib -static -fuse-ld=lld -Wl,-e,sum \
      -Wl,--gc-sections -Wl,-z,max-page-size=4096 -Wl,-z,noseparate-code -Wl,-Ttext=0x20000 \
      arm_sample.c -o arm_arm.elf
clang --target=aarch64-none-elf -O1 -nostdlib -static -fuse-ld=lld -Wl,-e,sum \
      -Wl,--gc-sections -Wl,-z,max-page-size=4096 -Wl,-z,noseparate-code \
      -Wl,--image-base=0x10000 -Wl,-Ttext=0x20000 arm_sample.c -o arm64.elf
clang --target=armv7a-none-eabi -c arm_flows.s -o arm_flows.o
clang --target=armv7a-none-eabi -nostdlib -static -fuse-ld=lld -Wl,-e,_start \
      -Wl,-z,max-page-size=4096 -Wl,-z,noseparate-code -Wl,-Ttext=0x20000 arm_flows.o -o arm_flows.elf
clang --target=armv7a-none-eabi -nostdlib -static -fuse-ld=lld -Wl,-e,_start -Wl,-s \
      -Wl,-z,max-page-size=4096 -Wl,-z,noseparate-code -Wl,-Ttext=0x20000 arm_flows.o -o arm_flows_stripped.elf
```

A Thumb function's symbol has its low bit set (`add` is `0x20001` in `arm_thumb.elf`), the
entry point's low bit says the same, and the assembler's `$t`/`$a` mapping symbols mark where
the mode changes: that is how the decoder learns the mode. In `arm_thumb.elf` `other_mode`
(`0x20038`) is the one ARM function; `arm_flows.elf` holds a call and a return under a
condition, a Thumb `blx` into ARM code that no symbol names, and a literal-pool load, and its
stripped twin keeps only the entry point's bit.

The universal Mach-O was put together here, where there is no `lipo`: the arm64 slice linked
with clang and lld, and the two slices combined by `make_fat.py`, a big-endian fat header and
one `fat_arch` per slice, each slice at an offset aligned to 2^14 as `lipo` aligns arm64.

```sh
clang --target=arm64-apple-macos11 -O1 -nostdlib -fuse-ld=lld -Wl,-e,_sum \
      -Wl,-platform_version,macos,11.0,11.0 arm_sample.c -o sample_arm64.macho
python3 make_fat.py sample_fat.macho x86_64=sample.macho arm64=sample_arm64.macho
```

The C++ program was built with g++ (the ELF), clang and lld (the Mach-O and the PE), with no
runtime library, so the whole image is the program's own functions; the PE exports every
function and the static member by `__declspec(dllexport)`, since the export table is how a PE
names its functions:

```sh
g++ -O0 -fno-pic -no-pie -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables \
    -fno-exceptions -fno-rtti -nostdlib -static -Wl,-e,main -o sample_cpp.elf sample.cpp
clang++ -target x86_64-apple-darwin -fno-exceptions -fno-rtti -O0 -c sample.cpp -o sample_cpp.o
ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -o sample_cpp.macho sample_cpp.o -e _main
clang++ -target x86_64-pc-windows-msvc -fno-exceptions -fno-rtti -O0 -c sample.cpp -o sample_cpp.obj
lld-link /entry:main /subsystem:console /out:sample_cpp.exe /nodefaultlib /noimplib sample_cpp.obj
```

The unwind fixtures were built with the toolchains' default unwind tables, and stripped:

```sh
gcc -O0 -fno-pic -no-pie -fno-stack-protector -fcf-protection=none -nostdlib -static -Wl,-e,main \
    -o unwind.elf unwind.c
strip --strip-all -o unwind_stripped.elf unwind.elf
clang -target x86_64-pc-windows-msvc -O0 -c unwind.c -o unwind.obj
lld-link /entry:main /subsystem:console /out:unwind.exe /nodefaultlib unwind.obj
python3 strip_symtab.py sample.macho unwind_stripped.macho
```

In `unwind.elf` `add` is at `0x401000`, `sum_to` at `0x401014` and `main` at `0x401047`; in
`unwind.exe` the three begin at `0x140001000`, `0x140001070` and `0x140001090`.

The Swift program was built on a Mac with the Swift 6.4 toolchain (no Swift compiler runs
here), and its names were demangled there for the oracle:

```sh
xcrun swiftc -O -module-name sample -target x86_64-apple-macos12 sample.swift -o sample_swift_x86
xcrun swiftc -O -module-name sample -target arm64-apple-macos12 sample.swift -o sample_swift_arm64
nm sample_swift_x86 | awk '{print $3}' | grep '^_\$s' | sort -u > names.txt
xcrun swift-demangle < names.txt | paste names.txt - > swift_names.tsv
python3 strip_symtab.py sample_swift_x86 sample_swift_x86_stripped
```

The Objective-C program was built with clang and lld, with no Foundation and no runtime
library linked — the runtime's symbols are left for the dynamic loader — and the stripped
twin's symbol table emptied by `strip_symtab.py`, since lld's `-s` is obsolete and does
nothing:

```sh
clang --target=x86_64-apple-macos11 -x objective-c -fno-objc-arc -fobjc-runtime=macosx-11.0 \
      -O1 -nostdlib -fuse-ld=lld -Wl,-e,_main -Wl,-platform_version,macos,11.0,11.0 \
      -Wl,-undefined,dynamic_lookup sample.m -o sample_objc
python3 strip_symtab.py sample_objc sample_objc_stripped
clang --target=x86_64-apple-macos12 -x objective-c -fno-objc-arc -fobjc-runtime=macosx-12.0 \
      -O1 -nostdlib -fuse-ld=lld -Wl,-e,_main -Wl,-platform_version,macos,12.0,12.0 \
      -Wl,-fixup_chains -Wl,-undefined,dynamic_lookup sample.m -o sample_objc_chained
```
