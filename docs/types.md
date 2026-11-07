# Types

The analyst writes C types — structures, unions, enumerations and typedefs — and the engine
lays them out as the image's platform does, reads them into the pseudocode where a variable
carries one, and keeps the C text in the project as the definition.

```bash
ag project ./structs.elf types --file p.agproj add 'struct point { int x; int y; long tag; };'
ag project ./structs.elf var-type --file p.agproj init a 'struct point *'
ag image ./structs.elf pseudocode init --project p.agproj   # a->x = b; a->y = 2; …
ag project ./structs.elf types --file p.agproj show point
```

## The model

A type (`ag_engine::types::Type`) is one of:

| Type | What it is |
|---|---|
| a primitive | `void`, `_Bool`, `char`, `signed char`, `unsigned char`, `short`, `int`, `long`, `long long` and their unsigned forms, `float`, `double`, `long double`, and the platform typedefs `int8_t` … `uint64_t`, `wchar_t`, `size_t`, `ssize_t`, `intptr_t`, `uintptr_t`, `ptrdiff_t`, known without a definition |
| a pointer | to any type, `struct node *` |
| an array | of a type, of a count or of none, `int[4]`, `char[]` |
| a function | its return type, its parameters' types and whether it ends in `...`, and the attributes of #373: the calling convention (`__cdecl`, `__stdcall`, …), `noreturn` and `pure`; a variable or member is a pointer to one |
| a based pointer | MSVC's `__based(ptr)`, `#373`: the pointee addressed by a base, laid out like the platform pointer (`char __based(void*) *`) |
| a name | a definition's key: `struct point`, `union value`, `enum color`, or a typedef's name, `node_t` |

A definition is a structure or union — its tag, its members (each a name, a type and, for a
bit-field, a width), the `#pragma pack` it was read under, whether it is `packed` or
`aligned(N)`, and — `#373` — its base classes, `struct derived : public base`, laid out
first, the first non-empty base at offset 0 — an enumeration — its tag, the integer it is
held in and its enumerators with their values — or a typedef. A structure named before it is defined, `struct node *next`, is
declared and incomplete: a pointer to it is whole, a member or variable of it is refused
until it is defined. A structure holding itself by value, directly or through another, is
refused the same way, so a cycle by value cannot be made; one through pointers is a list or
a tree, as in C.

The store (`TypeStore`) holds the definitions by key under one data model and answers the
size and alignment of any type, the layout of each structure and union, and the member at
an offset: `field_at(type, offset, size)` gives the path to the bytes — `.inner.a[2].f` —
when they are exactly a member's, inside nested structures and arrays, through anonymous
members as C reaches them, a union's first member they fit. The bytes that are the whole
unit of a bit-field's declared type are the bit-field's when exactly one named bit-field of
that type fills the unit: `field_at(…, 0, 4)` on `struct solo { unsigned flags : 3; };` is
`.flags` in `unsigned`, read in pseudocode as `s.flags` (or `p->flags`) and printed as the
whole-unit load/store — `s.flags = x;`, `return (s.flags >> 4) & 0xf;` where the lift's
select reads the field at bit 4 — because the value the code names is the bit-field. When
two bit-fields share a unit, or the access is part of a unit, it names no member as before.

## Data models

The image's data model follows its language — and, for x86-64, the calling convention its
functions are lifted with:

| Model | Images | `long` | pointer | `long double` | `wchar_t` | 8-byte scalars align to |
|---|---|---|---|---|---|---|
| `LP64` | 64-bit ELF and Mach-O: x86-64, AArch64 | 8 | 8 | 16, align 16 | 4 | 8 |
| `LLP64` | 64-bit Windows, and x86-64 under `--option abi win64` | 4 | 8 | 8 | 2 | 8 |
| `ILP32` | 32-bit ARM, MIPS and Windows (`wchar_t` 2) | 4 | 4 | 8 | 4 | 8 |
| `ILP32 (i386)` | 32-bit x86 under System V | 4 | 4 | 12, align 4 | 4 | 4 |

`char` is 1 byte, `short` 2, `int` and `float` 4, `long long` and `double` 8 everywhere.

## Layout

Each member of a structure goes at the next offset its alignment allows, and the structure's
size is rounded up to its alignment, the greatest of its members'. A union's members all
start at 0; its size is its largest member's, rounded the same way. Under `#pragma pack(N)` a
member's alignment is at most N; under `__attribute__((packed))` it is 1;
`__attribute__((aligned(N)))` raises the structure's alignment to N. A last member of an
array of no count is a flexible array member, of no size.

Bit-fields follow the System V (GCC) rule on every data model: a bit-field of declared type
T goes at the next free bit when it fits in the T-sized, T-aligned unit holding that bit,
and at the start of the next such unit otherwise; a zero-width bit-field moves to the next
unit; a named bit-field gives the structure T's alignment, an unnamed one does not. Packed —
by the attribute or any `#pragma pack` — bit-fields follow one another bit by bit, a zero
width still moving to the next unit. Microsoft's rule, which starts a new unit whenever the
declared type changes, is not followed yet. The layouts are checked against GCC on x86-64.

A definition is shown as C with its layout in comments:

```c
struct node {
    /* 0x00 */ int value;
    /* 0x04: 4 bytes of padding */
    /* 0x08 */ struct node *next;
    /* 0x10 */ unsigned flags : 3;    // a bit-field: /* 0x10:0 */, its unit and first bit
}; /* size 0x18, align 8 */
```

## The C the parser reads

`ag_engine::ctype` reads a run of declarations:

- `struct`, `union` and `enum` definitions, named or anonymous, nested in a member — a
  nested named one is defined as C defines it, at file scope — and an anonymous structure
  or union member whose members are the outer one's;
- `typedef` of any declarator: pointers, arrays, functions, pointers to functions and arrays
  of them, `typedef int (*cmp_t)(const void *, const void *);`, `typedef struct { … } point_t;`;
- an enumerator's value or an array's count as a constant expression: integer literals
  (decimal, hex, octal, binary, any suffix), character literals, the enumerators defined
  before, `sizeof` and `_Alignof` of a type the store knows, casts, `+ - * / % << >> & | ^ ~
  !`, comparisons and parentheses; an enumeration is held in `int`, or `unsigned int`, `long
  long` or `unsigned long long` when a value does not fit, or in the type it says, `enum e :
  unsigned char`;
- bit-fields, named and unnamed;
- `#pragma pack(N)`, `#pragma pack(push[, N])`, `#pragma pack(pop)`, `#pragma pack()`, and
  `__attribute__((packed))` and `__attribute__((aligned(N)))` on a structure;
- comments of both kinds.

What it does not read it notes and goes on: `const`, `volatile` and `restrict` are dropped,
for a type keeps no qualifiers; storage classes are dropped; another preprocessor line is
skipped — no macro is expanded and no file included; another attribute is skipped; a
function or a variable declared is no type and is skipped. An error says where:
`3:14: expected ; after the member, not }`, `1:14: struct point is defined already`.

The same parser reads one type, as a variable or member is given one: `struct point *`,
`int (*)(char *, ...)`, `char[16]`. There a name the store does not define is a type of no
known size, as a stack variable's `struct point` was before there were definitions.

## In the project

The project keeps the definitions as C, a top-level `types` list of `{"name", "c"}`, one
top-level declaration each, in the order C reads them (`docs/project-format.md`). `add`
splits the source it is given into its declarations; `replace` and `remove` reach one by its
name, `struct point` or `point`; a removal is refused while another definition or a
variable's type names what it defines. The store is built from the list each time the image
is read with the project; a definition that does not read is reported, and the types read
before are kept.

A function's record carries `var_types`, the types given its variables by their lift names.

## In the pseudocode

- An analyst's stack variable (`ag project … stack-var`) of a structure, union or array type
  reads each access inside it as the member or element it is: `p.x`, `v.inner.g`,
  `v.a[2].f`; a union's first member the bytes fit. Bytes that are no member's read at their
  offset, `*(int *)((char *)&v + 2)`.
- Which member of a union an access means is the analyst's word, not the code's: a union's
  members all lie at 0. The word is said per instruction (`ag project … union`, **Edit ▸
  Union field** in the workbench) and reads the access as that member, `w.f` where the
  analysis prints `w.i`; a word naming no member the bytes are leaves the first it fits.
- A variable given a pointer type (`ag project … var-type`) reads a load or store through it
  at a constant offset as the member there, `a->y`, past the first as `a[1].y`, an array
  member indexed by a register in the shape `a + 8 + b*4` as `a->counts[b]`; through a pointer
  to a scalar, `a[2]`. A run of stores the lift reads as one struct initializer is the stores
  to the members, `a->x = b; a->y = 2;`. Byte arithmetic left on the pointer is said in bytes,
  `(char *)a + 6`.
- A variable of an enumeration reads a constant compared with it, assigned to it, masked with
  it or switched on as its enumerator, `if (state == S_READY)`, `case C_TWO:`; in an
  enumeration of flags — every nonzero value a distinct power of two — a combination as
  `M_READ | M_EXEC`. Only where the values spell the constant one way: two enumerators of one
  value, or a bit no flag has, keep the number.
- The declarations print the type as C, `struct point p;`, `enum color c;`, `node_t *head`,
  and `ag image … transpile --project` writes the definitions the functions need ahead of
  them.

A variable's type must be a scalar of its width — a pointer, an integer, a floating type or
an enumeration; a structure on the stack is a stack variable. One that does not fit is
refused in the function's leading comments: `b is not typed char *: char * is 8 bytes, b
holds 4`.

## Fragments

Code moves a structure about in parts: `mov eax, [rbp-0x10]` loads `p.x` of a `struct point p`,
`mov rax, [rbp-0x10]` loads `p.x` and `p.y` together as one eight-byte value and `shr rax, 32`
leaves `p.y`, and System V passes a `struct point { int x, y; }` by value in one register and
returns it in `rax`. A fragment is the type of such a value: the bytes `[offset, offset +
size)` of a known structure or union. `struct point [4..8) (y)` is `p.y`; `[0..8)` is the whole
of it. A fragment lives on the variable (`ag_engine::lift::Fragment`, `Variable::fragment`), not
in its C type: `ty` stays the integer the machine holds the bytes in, so the medium level — and
the C++ the transpiler writes from it — reads them with the machine's own shifts and masks and
still computes what the machine did. Only the pseudocode's declarations and the variables
listing say the structure.

```bash
ag project ./fragments.elf types --file p.agproj add 'struct point { int x; int y; };'
ag project ./fragments.elf var-type --file p.agproj weigh a 'struct point'
ag project ./fragments.elf var-type --file p.agproj make return 'struct point'
ag image ./fragments.elf pseudocode weigh --project p.agproj   # return (a.y + (a.y * 2)) + a.x;
ag image ./fragments.elf pseudocode second --project p.agproj  # return make(…).y;
```

What is bytes of a structure:

- a typed stack variable, a member or element of one, and bytes at an offset into one — a slot
  of the variable read at another width than its own is the bytes there, `*(long *)&p`, not
  the member the slot was first read as;
- the pointee of a typed pointer, a member of it, bytes through it, `*(long *)a`, and the
  pointee of a member that is a pointer, `a->next->v`;
- a parameter a structure is passed in, and the result of a call to a function whose `return`
  is typed a structure.

How the operations narrow a fragment, the structure little-endian:

| Operation | Fragment |
|---|---|
| `x >> 32` (`shr`, `sar`) on `[0..8)` | `[4..8)`, the value above it zeros, or its sign for `sar` |
| `x & 0xffffffff`, `& 0xffff`, `& 0xff` | `[0..4)`, `[0..2)`, `[0..1)` |
| `(int)x` — `eax` of `rax`, the source of `movzx` or `movsx` | `[0..4)` |
| a wider cast | the same bytes, extended by the narrower type's sign or with zeros |
| `(long)b << 32 \| (unsigned int)a`, `a` and `b` neighbours of one source | the bytes of both |

How a fragment reads:

- exactly one member: the member, `p.y`, `a->y`, `make(b, 5).y`. Held wider than the member,
  it is cast to the type the value has, through the extension the machine made where the
  member's own type would not make it: `(unsigned long)(unsigned int)p.y` for `shr`, `(long)p.y`
  for `sar`;
- several members, loaded or stored where it stands: the bytes from the first member it starts
  at, with the members it holds in a comment — `*(long *)&p.x /* p.x, p.y */`. The comment is
  the `__fragment` intrinsic, a value and no call;
- a whole structure assigned from a whole one of its type: the copy, `q = p;`, `*a = *b;`;
- bytes that are no member's, or of no known structure: as before.

A store of a fragment into a structure at the offset it came from is the member assigned, `q.y
= p.y;`; a run of such stores, in order, that covers a structure — but its padding — from one
other structure of its type is the copy, `q = p;`.

A variable assigned a fragment — each of its assignments the same bytes — holds it:

- exactly a member of pointer or enumeration type: the variable takes the member's type, and
  the loads through it and the constants compared with it read as such, `b = a->next; … return
  b->v;`. An integer member leaves the variable its integer;
- the whole of a structure: the variable is declared as the structure and its parts read as
  its members, `v.y`, where every read of it is a member, a copy, an argument or a return —
  another read leaves it its integer, holding `[0..size)`;
- a part of a stack variable or of a whole structure's variable, assigned once at the top of
  the body, the structure not written from there on and its address never passed or stored:
  its parts read as the structure's members, `p.y`;
- another part: its integer, and the listing says what it holds.

The variables listing (`ag image … variables`, the workbench's Variables pane) gives a
fragment's variable the type `struct point [4..8) (y)`, the structure alone for a whole one.

### Structures by value

A parameter typed a structure or union (`var-type … a 'struct point'`) is the structure passed
by value:

- **System V**: a structure of the INTEGER class — at most 16 bytes, every member an integer,
  an enumeration or a pointer at its natural alignment — comes in general registers: its first
  eight bytes in the parameter's argument register, `[0..8)`, the rest in the next, `[8..16)`.
  The signature declares the structure once, `long width(struct span a)`, the second register's
  parameter standing in it, and both registers' reads are its members, `a.lo`, `a.hi`, while
  the body leaves the registers as they came. A structure with a floating member (the SSE
  class), one of more than 16 bytes or with a member out of its alignment (MEMORY), and one
  that needs two registers when its parameter is in the last, are refused with a note; those
  classes are #388's, with the other calling conventions.
- **Microsoft x64**: a structure of 1, 2, 4 or 8 bytes comes whole in its register; another is
  passed by its address, and the parameter is typed a pointer to it, with a note: `a is struct
  big *: Microsoft x64 passes struct big, of 24 bytes, by its address`.

A function's `return` typed a structure (`var-type … make return 'struct point'`) is read at its
calls: the call's result in `rax` is the structure's first eight bytes, `make(a, 5).y`. A
structure the System V convention returns in `rax` and `rdx` is refused — the calls read `rax`
alone — as are the SSE and MEMORY classes, and under Microsoft x64 a size other than 1, 2, 4 or
8 bytes, which is returned through memory the caller passes. The function's own pseudocode keeps
the integer it returns in.

A fragment rides with its variable through the analyst's splits, new versions and merges, which
copy the variable's declaration, and through inlining: a structure passed by value is bound to a
local of the caller's that holds the same bytes.

## Smart structures

Before the analyst writes a structure, the code says much of it. `ag image … struct-from
FUNCTION VARIABLE` drafts one from what the function does through a pointer variable, and
`ag project … struct-from` makes it the project's and types the variable a pointer to it:

```bash
ag image ./smart.elf struct-from make_conn v1                          # the draft, and where each member came from
ag project ./smart.elf struct-from --file p.agproj make_conn v1 --name conn
ag image ./smart.elf pseudocode make_conn --project p.agproj           # v1->field_0 = a; v1->field_4 = 0x50; …
ag project ./smart.elf struct-from --file p.agproj read_conn a --update conn   # adds int field_18[4]
```

```c
struct conn {
    int field_0;
    short field_4;
    char field_6;
    long field_8;
    long field_10;
    char gap_18[16];
};
```

### The accesses

The accesses (`ag_engine::smart_struct::struct_accesses`) are read off the function's lift as
it reads, the analyst's words made:

- **through the variable**: a load or store `*(T *)(p + k)` is an access of `sizeof(T)` bytes
  at `k`; an index by a variable, `*(T *)(p + k + i*s)` — or `(i + j)*s`, which is `j*s` bytes
  on — is one at a stride of `s`, and a variable added unscaled, `*(char *)(p + i)`, one at a
  stride of 1; a run of stores the lift reads as one struct initializer is one store a field.
  Through a pointer already typed, `p->f`, `p->inner.g`, `p->a[i]` and `p[1].x` are the
  member's bytes;
- **through its copies**: a variable each assignment of which is the pointer, or the pointer
  and one constant — `q = p;`, `q = p + 8;` — is the pointer at that offset; a variable
  assigned two offsets is not;
- **through the callees, one level deep**: the pointer, or a copy, passed to a function the
  image lifts is read in the callee the same way, through the parameter it arrives in — the
  argument's position — at the offset it was passed at. The callee's own callees, and a call
  back into the function, are not followed.

What the uses of a value say of it:

| Use | Hint |
|---|---|
| the load cast to a wider signed integer, `(long)*(int *)p` | signed |
| the load cast to an unsigned integer — a zero extension, an unsigned comparison | unsigned |
| the loaded value dereferenced, `*(char *)*(long *)(p + 8)` | a pointer, to the width it is read at |
| the loaded value passed to a callee that reads or writes through that parameter, or to `free`, `strlen`, `strcmp`, `memcpy`, `memset`, `puts`, `printf`'s format and their like | a pointer |
| a stored value that is a string, an address, a function, a variable of pointer type, the pointer itself, or an allocation | a pointer (`char *` for a string) |

### The size

When the pointer — or the variable it is a copy of — is assigned once, from a call to a known
allocator with constant arguments, the structure is the size it asks for: `malloc(0x18)`,
`calloc(2, 8)`, `realloc(p, 0x40)`, `aligned_alloc`, `xmalloc`, `g_malloc`, `g_malloc0`,
`g_slice_alloc`, `kmalloc`, `kzalloc`, `kcalloc`, `vmalloc`, `devm_kzalloc`, `HeapAlloc`,
`RtlAllocateHeap`, `LocalAlloc`, `GlobalAlloc`, `VirtualAlloc`, `CoTaskMemAlloc`,
`ExAllocatePool(WithTag)`, and `operator new` and `new[]` as Itanium (`_Znwm`, `_Znam`) and
MSVC (`??2@YAPEAX_K@Z`) mangle them, under an import's or a stub's decoration — `malloc@plt`,
`__imp_HeapAlloc`, `_malloc`, `j_malloc`. An access past the allocation is left out with a note.
Otherwise the size is the extent of the accesses: the end of the last, rounded up to the
alignment of the widest. An allocation that is no multiple of the members' alignment is
rounded up the same way, with a note.

### The draft

`ag_engine::smart_struct::infer_struct` makes one member of each distinct offset and width:

- **names**: `field_<offset in hex>` — `field_0`, `field_1c` — and `gap_<offset in hex>` for
  bytes no access reaches;
- **types**: the width's integer — `char`, `short`, `int`, `long` (`long long` where `long` is
  4 bytes) — unsigned where an unsigned use is seen and no signed one; a pointer where the value
  is one and the width is a pointer's, to the integer it is dereferenced at (`char *`) or
  `void *` when it is dereferenced at no one width or only passed on; `unsigned char[N]` for a
  width no integer has;
- **arrays**: an access indexed at a stride of its own width is an element, and the array runs
  from it — over the accesses of that width at that stride before and after it — to the next
  member, or to the end of the allocation, or to the last element seen: `int field_18[4]`. An
  access indexed at a wider stride is an element of an array of structures, which is noted and
  left to the analyst;
- **overlaps**: two accesses that share bytes are one member — the wider of two at one
  offset, the first of two that cross — and the other is a note: `field_0 is reached as 4 bytes
  at 0x0 too, at 0x401000: the wider is kept`. A union of both is the analyst's to write;
- **gaps**: bytes no access reaches are a `char gap_<offset>[n]` only where natural alignment
  would not leave them as padding — a `char` at 0 and a `long` at 8 need none, a `char` at 0 and
  an `int` at 8 need `char gap_1[7]` — and at the end, to reach the size;
- **packing**: a member natural alignment cannot place at its offset — an `int` at 2 — makes
  the structure `__attribute__((packed))`, every gap spelled out.

The draft is C the parser reads back, and it is checked: each member at its offset, the size
the size chosen.

### Made and updated

`struct-from` without `--update` adds the draft to the project's `types` — named by `--name`,
or `struct_<function>_<variable>`, made an identifier and numbered `_2`, `_3` past the names
defined — and gives the variable the type `struct NAME *` in its function's `var_types`, so the
pseudocode reads it at once: `v1->field_0 = a;`. A name defined already is refused.

`--update STRUCT` merges the accesses into a structure already defined. Each access in bytes
no member holds — padding, the bytes past the end, or a `gap_<offset>` a draft left, which is
split about the new member — is a member, with a gap before it where natural alignment would
not place it; an array runs on to the next member or the end of its gap. An access exactly a
member's bytes adds nothing; one that meets a member at other bytes is a note, `an access of 4
bytes at 0xc meets y at other bytes: left as it is`. No member is renamed, retyped or moved: a
member that would move one is left out with a note. The structure's C is written again from
its members — a `#pragma pack` it was read under is kept — and replaces the definition in its
place; the variable is given a pointer to it.

Both are the project's ordinary words, `types` and `var_types`: `types remove` and `var-type …
clear` take them back, and the workbench's undo does.

## Propagation

With no word from the analyst the pseudocode is typed from what the code says of its values
(`ag_engine::propagate`), and the variables listing says where each type came from:

```bash
ag image ./propagate.elf pseudocode measure     # void measure(char *a) { strlen(a); … }
ag image ./propagate.elf pseudocode greet       # measure("hello");
ag image ./propagate.elf pseudocode sum         # int local_38[8]; … local_38[(long)local_c] = …
ag image ./propagate.elf variables line         # local_48  char[64] … from fgets's parameter 1, 0x40 bytes at 0x40119c
```

### Seeds

| What the code does | What the value is | Source |
|---|---|---|
| passed to, or returned by, a function of known prototype | the prototype's type | `from strlen's parameter 1`, `returned by fopen at 0x401020` |
| is a parameter of a function of the image named as a known one | the prototype's type | `from fgets's prototype` |
| typed by the analyst (`var-type`) | that type, never changed | `analyst` |
| assigned the result of an allocator `smart_struct` knows | a pointer, `void *` | `allocated by malloc at 0x401004` |
| assigned or passed a string — a literal, or a constant address the image holds one at | `char *` | `a string passed at 0x401159 in greet` |
| dereferenced — every access one width, at multiples of it, unindexed or at that stride | a pointer to that type, `int *` | `dereferenced at 0x401010`, `indexed as an array at 0x401020` |
| dereferenced otherwise, or assigned an address and no number | `void *` | `an address assigned at 0x401008` |
| compared with a pointer, or a pointer with an offset added | that pointer (a structure's pointer plus an offset is `void *`) | `compared with p at …`, `p plus an offset at …` |
| read only through unsigned casts — an unsigned comparison, a zero extension | the unsigned integer of its width | `used unsigned at 0x401003` |

The prototypes are C in the type libraries under `crates/ag-engine/src/typelib/` —
`libc.h` (the C library and POSIX), `kernel32.h` and `user32.h` (Windows), and the Linux
syscall table — a few dozen of the common functions, with the types they name (`FILE`,
`struct timeval`, `struct timespec`, `struct tm`, `struct sockaddr_in`, `HANDLE`, `DWORD` …),
read by the parser under the image's data model. A function is found under an import's or a
stub's decoration, `strlen@plt`, `__imp_ReadFile`, `_strlen`, `j_strlen`. Adding a prototype
to a library's file teaches it; a buffer whose length another argument gives carries
`/* size: N */`, the length's argument counted from 1, or `/* size: N*M */` for a count of
elements of a size. The library's types are known to every lift beside the project's, which
win where both define a name, and the transpiler writes the ones the functions name.

The libraries are also what an image's imports are typed from (#376). A PE names each import
by library and by name or ordinal; where the library of that name knows the function — by
name, or by the `#[ordinal(N)]` a DLL export carries — the import takes its prototype, and an
import by ordinal is shown by name (`GetLastError`, ordinal 490, not `ord_490`). A syscall is
a function named by number: `#[syscall(N)]` gives a number its prototype, and the built-in
Linux table covers the common x86-64 `syscall` numbers.

### Directions

The facts of each function — its slots and their widths, the seeds, the copies between its
variables, its calls with their arguments and results, its returns — are read off its lift once
(`Facts`), and the types are carried through them by `solve`:

- **through copies**, both ways: `b = a;`, `return a;` and the function's return;
- **call site to callee**: an argument's type is the callee's parameter's — every call site
  passing a string makes the parameter `char *`, `a string passed at 0x401159 in greet`;
- **callee to call site**: a callee's parameter's type is the argument variable's, `from the call
  at 0x401234 to parse(char *)`, and a callee's return the result's, `returned by make at …`;
- a known prototype's types go into the arguments and the result and do not come back.

The image solves each function with the functions about it in the call graph — its callers and
callees and theirs, 48 at most, the nearest first — each one's facts read once and kept with the
pseudocode. The solution is a fixed point, or 16 rounds over every link when it is not reached
sooner.

Evidence ranks: the analyst's above a prototype's, a string's, an allocation's and what calls
and returns carry; those above a dereference's, a comparison's and an address's; and an unsigned
use last. A higher rank replaces a lower one; one rank joins — `void *` and `char *` are `char *`;
two pointers to different types are `void *`, and a pointer and an integer, or two integers,
leave the variable the integer of its width, each with a note in the function's leading comments:
`p is void *: char * from strlen's parameter 1, int * dereferenced at 0x401010`. A type is only
given where it is a scalar of the variable's width. A variable the analyst pins values of keeps
its sign.

What is inferred is read as the analyst's types are: `p[i]`, `p->f`, enumerators, `char *f(…)`.
A pointer to `void` says nothing of what it points at, so its loads and arithmetic stay as the
lift reads them. A constant passed where the callee takes a `char *` and the image holds a string
is the string, `measure("hello")`.

### Arrays and structures on the stack

The first lift reads a slot's address plus an index as that sum, `(long)&local_38 + (long)i *
4`, and looks at the frame:

- **an indexed run**: a slot read or written through an index at the stride of the access's
  width is an array of that element, as many as a comparison of the index with a constant bounds
  (`i <= 7` is 8), or reaching to the next slot the code touches: `int local_38[8]`, `indexed as
  an array at 0x4011cd`;
- **a known length**: a slot whose address is passed where a prototype's buffer has a constant
  length is an array of that many bytes — `char` for a `void *` or `char *` buffer, the
  prototype's element otherwise: `fgets(&local_48, 64, f)` makes `char local_48[64]`,
  `memcpy(&local_28, s, 0x20)` `char local_28[32]`;
- **a known structure**: a slot whose address is passed where a prototype, or the analyst's type
  of the callee's parameter (by its lift name, `a`, `b`, …), takes a pointer to a structure the
  types define is that structure: `gettimeofday(&local_18, 0)` makes `struct timeval local_18`,
  read `local_18.tv_sec`;
- **a drafted structure**, under `--option auto-structs on`: a run of slots from one whose
  address is taken to the next such slot, a saved register or the return address, reached at two
  offsets at least, is drafted as `struct-from` drafts one (`infer_struct`), `struct
  struct_<function>_<slot>`, and made a stack variable of it. Off by default: the draft is a
  guess at a layout the analyst has not seen, with new names in the output, and is no type the
  other functions know; `ag project … struct-from` makes one the analyst keeps.

None of them overlaps a saved register, the return address, another, or a byte of an analyst's
stack variable — the analyst's words win. Each is made a stack variable as the analyst's are, the
function is lifted again with them, and its accesses read as its elements, `local_38[i]`, its
address passed as the array, `fgets(local_48, 0x40, a)`, or the structure's, `&local_18`.

### Options and sources

`--option type-propagation off` turns all of it off: the variables keep the integer of their
width, the slots stay a local each, and a slot indexed outside an analyst's variable is refused as
before (`arithmetic on the stack pointer`). Inside an analyst's stack variable an indexed access
is read either way. `--option auto-structs on` adds the drafts.

`ag image … variables` gives each variable's `source` — `analyst`, the inference's source, or
`-` — as does `--json` (`type_source`), the MCP `variables` tool and the workbench's Variables
pane.

## Type archives (#377)

One definition may serve several projects: the file of types they sync
with is a type archive (`.agarchive`), `{"format": 1, "types": [...]}` —
each entry a `name` and its `c`, as the project's `types` holds them,
carrying no target of its own. `ag archive push --project FILE
ARCHIVE` puts the project's types into the archive; `pull` brings the
archive's into the project; `status` says where every name stands
between the two sides — `in-sync`, `project-only`, `archive-only`,
`conflict` — and `resolve` settles one conflict by changing one side
alone. A conflict is settled with `--keep project` or `--keep archive`,
per type, and without the word both sides are kept and the command fails.
Equality is on the name and the `c`, so the sync is two-sided with no
common ancestor, and neither side is ever deleted by a sync. See
`ag docs archive` for the format and the full command reference.

## Platform types (#378)

An image is read under the platform it is: an operating system and an
architecture — `windows/x86-64`, `linux/aarch64`, `macos/arm64`,
`linux/x86` — each carrying the types its images name. A PE is Windows,
a Mach-O is macOS, an ELF is Linux, and raw bytes are what their
language id says; the SLEIGH id's width picks 32- or 64-bit x86, so a
32-bit ELF reads under `linux/x86` and the `ILP32 (i386)` model. Each
platform ships default C types — the Windows SDK's `HANDLE`, `DWORD`,
`SIZE_T`, `SECURITY_ATTRIBUTES`, the Linux and macOS C libraries' `FILE`,
`timeval`, `sockaddr_in`, `pthread_t`, `sigaction` — read under the
platform's data model (LLP64 for Windows 64, LP64 elsewhere at 64 bits,
ILP32 at 32). They open on the store before the project's types, so a
project definition corrects a platform one where both define a name,
and the builtin type libraries (#376) add only what neither holds;
`ag image … types` reports the platform and lists the merged store,
and every type check — variable types, stack variables, `struct-from`
— reads against it.

The analyst extends a platform in a file of their own, per platform:
`$XDG_CONFIG_HOME/ag/platform/<os>-<arch>.h` or
`~/.config/ag/platform/<os>-<arch>.h`, in the same C dialect as the
project's types. `ag platform list` names the platforms the engine
knows, `ag platform show windows/x86-64` prints one's defaults and
its user types, and `ag platform path windows/x86-64` creates the
file and prints where it lives. The user types layer above the
defaults and below the project's, so the project still wins.

## What comes later

The model leaves room for the items that build on it:

- **Struct-by-value calling conventions (#388)** add the SSE and MEMORY classes, `rdx` of a
  returned structure, and the other conventions to the INTEGER class the fragments read.
- **The union field per instruction (#371)** replaces the first-member-that-fits choice, made
  in one place (`TypeStore::field_at`).

### Type attributes (#373)

Function types carry `TypeAttrs` — the calling convention spelled MSVC-style
(`__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`, `__vectorcall`, `__clrcall`), and
`noreturn`/`pure` — read from `_Noreturn`, `__attribute__((noreturn))`/`__attribute__((pure))`,
`__declspec(noreturn)`/`__declspec(pure)` and bare convention words, in any position, with a
suffix attribute after the parameters (`typedef __stdcall int (*cb)(int) __cdecl;` — the
last convention wins). `__declspec(align(N))` on a structure raises its alignment, and a
`__declspec` elsewhere is skipped with a note.

A structure's base classes, `struct derived : public base`, are laid out first, each
aligned, the first non-empty base at offset 0, and rendered back by `definition_text`
with the base's members already in place. That flattened rendering is for display: the
base clause and the copied members both appear, so re-parsing the text of a struct with
bases counts the base's members twice. A derived member shadows a base member of the
same name in `member_type` and in the offset path, as C++ lookup does. Access specifiers
and `virtual` are skipped where the base list is read. The full C++ inheritance model —
access control, virtual inheritance, vtables — stays with #374.

A based pointer, `char __based(void*) *p`, is `Type::BasedPointer { base, pointee }`,
pointer-sized and scalar, with the base kept for what the analyst wrote. #387
owns per-function property editing.

### C++ classes and vtables (#374)

A `class` is a structure the parser reads with the `class` keyword, `is_class` on
its composite, and its `definition_text` and class listing render it as a class.
Access labels — `public:`, `private:`, `protected:` — are skipped where the body
is read, and the members they guard are kept in declaration order; a missing
label body reads under no label, as the source wrote it.

A class with virtual methods holds a vtable pointer. The pointer is laid out at
offset 0, pointer-sized and pointer-aligned, and every member follows it. A
derived class whose base holds one shares the base's pointer at offset 0 and
holds no second; a derived class with a vtabled base is offset by the base's
size. A composite with no virtual methods takes no vtable pointer, and `struct`
still reads as a structure: a virtual method in a structure makes the structure
a class for layout purposes without renaming it.

Methods are kept on the composite, in declaration order, each with its
`is_virtual` flag, and rendered after the members. `definition_text` round-trips:
a class's rendered form re-parses to the same layout, and a duplicate
definition is an error the parser reports. `member_texts` pairs each own member
with its own layout, past the bases and the vtable pointer, as the layout lays
them.

The image's own vtables come from [`ag_engine::cxx`], read from the symbols the
image carries: an Itanium `_ZTV<class>` on ELF and Mach-O, a Microsoft `??_7`
on PE, each with its type information and constructor when the image holds
them. The vtable's words, after its two header words, hold the implementations
in declaration order, named by the symbol at the address each holds. A vtable
ends where the next begins, or where a word is no function address. The ABI's
own classes — `__cxxabiv1::__class_type_info` and its kin — name no class of
the program. The RTTI names each class's bases as well: the Itanium
`_ZTI<class>` structures (`si_class_type_info` for one base, `vmi_class_type_info`
for several, with each base's offset, public access and virtual flag) and, on PE,
the Microsoft `??_R0`–`??_R4` hierarchy give each class a `base_classes` list,
and a vtable reached with more than one base carries one group per base, each
with its `offset_to_top`, its owning type, and the slot indices its entries hold,
in [`CppClass::vtable_groups`]. Every group header stores the derived class's
type information, so a group's owner is the derived class, primary or secondary
alike. The Itanium path is verified against ELF fixtures for single, multiple
and virtual inheritance; the Microsoft path is best-effort — it is read from
the locator and hierarchy tables but has no PE fixture yet. [`Image::cxx`](ag_engine::image::Image::cxx) reads the metadata
once, under the image's own data model, and [`Image::cxx_references`] hands
the cross references: the slots by address, the class and index each names, and
the virtual functions by implementation address. [`simplify_template_name`]
keeps a demangled template's arguments whole, nested as the source nests
them.
- **Attributes (#373)** — Microsoft's bit-field rule and the remaining custom attributes
  beyond `noreturn`, `pure`, calling conventions, base classes and based pointers — join
  `packed` and `aligned` on `Composite`; the parser notes the attributes it skips.
- **Type libraries (#376)** add definitions to the store from the libraries an image imports; **type archives (#377)** share them between projects; **header import (#379)** adds
  definitions to the store from elsewhere than the project, the last with a preprocessor;
  **export as a header (#380)** writes `definition_text` in the store's order.

### Importing types from C headers (#379)

A header is imported the way a compiler reads it. The file goes through the
system preprocessor — `clang` or `gcc -E`, first found on the path — with the
standard, include paths and macros the options name: `-std=c11` by default,
`-Iinclude`, `-DFOO=1`, and `-nostdinc` when the system's headers are out and
the run is `clang`. Macros are expanded and includes followed, so a header that
includes another and parameterizes a member by a macro reads whole.

The preprocessed text is fed to the C type parser one declaration at a time.
A definition whose name the platform already gives — `int32_t`, `size_t` —
is not stored, and neither is a declaration without a body. A definition
that does not read, or that names a type the header does not define, is held
back with its error rather than stored as a placeholder: a project built on
it would lift against a type of no known size. A name the store already
defines is held once when the header's form is the same definition, and
refused by name when the two differ.

The preview says what the header would define — each definition's name,
size and alignment as the store lays it out, and the held-back ones with
why — without adding any to a project. The import adds a selection, or
every definition the header names; the header previews before the selection
is made, and the names it adds are reported. A whole-header import that
drops a definition is refused: the header names it and it does not resolve,
and silently importing the rest would hide why it was left out. Naming a
subset asks only for those, and the rest stay for another import.

The command is `ag project TARGET types import HEADER [NAME …]` with
`--include`, `--define`, `--compiler`, `--standard`, `--no-system-headers`,
`--preview` and `--json`.

### Exporting types as a C header (#380)

The project's types can be written back out as a C header the analyst
keeps with the rest of the work: every definition in the store's order —
so a type that holds another by value comes after it — with a guard
(`ADMIRALGRACE_TYPES_H`), `<stdint.h>` when a fixed-width type is
spelled and `<stddef.h>` when one of `size_t`, `wchar_t` and their kin
is. A definition read under `#pragma pack(N)` is wrapped in the pragma
around it; C++ class definitions open an `#ifdef __cplusplus` section,
since they are not C. What is written is `definition_text` with no
layout comments, so the header reads as the C the types were defined
in, and it round-trips through `types add` and `types import`.

The command is `ag image FILE types --header` (or
`ag project TARGET types show --header`), the same text the MCP
`export_types_header` tool returns, and the file `ag image export`
writes as `types.h` in the export directory. The header holds the
types the image is read with — the platform's defaults and the
project's — as `ag image … types` prints them.

### Porting types and signatures by matching symbols (#381)

A project holds its analyst's types at addresses, so the types of one
build of a binary do not travel to the next by copying records. A
function of one image is the same function of another when both name
it, and the types of that function — the definitions it names and the
types of its variables — move with the name: `ag project TARGET types
port FROM` reads the source project and carries its definitions and
its per-function signatures onto the destination project's. The source
side's spellings are the names its image prints, the mangled name when
the image demangled one, and the analyst's own rename of the entry;
the destination is searched by those same spellings, its image's own
names first and its analyst's renames last, since a rename recorded
for one version names that version's address and no other. Every
definition the matched signatures name, with what those name in turn,
is drawn from the source, so a signature comes whole or is held back
whole.

The port is a preview and a move: `--preview` says what would move —
each definition, each matched function with the symbol it matched on
and its variable types, the source functions no symbol carries, and
what is held back with why — and writes nothing; without it the
definitions are added and each applied word is set on its function's
record. A definition the destination already holds with the same C is
held once, not twice; one it holds differently is held back by name, so
no port changes the shape of a type already held. A signature is held
back when its type does not read, when it names a definition neither
store defines, when the destination's function declares no variable of
that lift name, or when the variable is already typed differently; a
stack variable the destination already holds at the same offset stands.
Like the rest of the types commands, the report is `--json`, and the
same move is the MCP `port_types` tool's.

The command is `ag project TARGET types port FROM [--preview] [--json]`.

### Cross references for types and members (#384)

A type is in use where a variable or a return is given it, where another
definition names it — a member's type, a typedef, a base class — and
where the pseudocode reads one of its members or enumerators. Those
reads stand as the `__member`, `__arrow` and `__enumerator` intrinsics
(and the bit-field forms of the first two): `p->y` is a use of `y`,
`v.f` of `f`, `S_READY` of that enumerator. Each member and enumerator
is listed with the instruction and the function, or `(none)` when
nothing reads it.

`ag project TARGET types xrefs [NAME] [--json]` prints that list. With
`NAME` (`struct point`, `point`, `node_t`) it is that definition; with
no name it is every definition the project holds. The same list is the
MCP `type_cross_references` tool, and the Types tab writes it under the
selected definition.

### COM interface types by GUID (#382)

A COM object is created by GUID: the class GUID (CLSID) names the coclass that implements it, and the interface GUID (IID) names the interface the caller wants back, both passed to `CoCreateInstance`. A binary that uses COM carries those GUIDs as 16-byte values in its data, and types name the GUIDs the call uses — `CLSID_ShellLink`, `IID_IShellLinkW` — instead of leaving them as raw addresses.

A GUID is 16 bytes: the first three fields little-endian, the last eight as written, spelled `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`. The image's data sections — `.data`, `.rdata`, `__DATA`, `__TEXT,__const`, and the rest that are not code — are walked at 4-byte alignment for each known COM GUID's bytes, and each hit is reported under its address. The known GUIDs are the engine's catalog: the core interfaces every COM object answers to — `IUnknown`, `IDispatch`, the `IEnum*` family, `IPersist`, `IConnectionPoint` and friends — and the coclasses the Windows SDK prints.

`ag image com` prints the GUIDs the image holds, each as text and the interface or class the catalog names it, filed as interfaces and classes. With `--json` it gives `guids` — each `address`, `guid`, `name`, `interface`, and `at` (null for now: no statement attribution yet) — plus `interfaces` and `classes`, empty lists for an image with none. With `--header` it writes the found types as a C header: `GUID` itself, each interface as a vtable struct with `QueryInterface`, `AddRef`, `Release` first and the interface's own methods in slot order, and each class as a `GUID` typedef with the `CLSID_` comment.

The command is `ag image com [--json] [--header]`.

### JNI types by name (#383)

A Java native library exports entry points named by the JNI spec: `Java_<class>_<method>` — the class with package dots turned to underscores — and, for an overloaded method, a `__<signature>` suffix carrying the Java types the method takes; and `JNI_OnLoad` and its kin, the runtime functions the spec exports as plain functions. The spec fixes their shape: the first parameter is the environment, `JNIEnv *`, the second is the object or class the method is called on — `jobject` from the name alone, where static or instance is not distinguished there (`jclass` is what a signature spells out, `L<java/lang/Class>;`) — and the signature's own types follow.

Typing the front of a JNI function turns register arithmetic into readable code: a native method's pseudocode reads `int Java_com_example_Native_add(JNIEnv *env, jobject obj, int a, int b)` instead of five bare registers. The types are the JNI header's — `JNIEnv`, `JavaVM`, `jobject` and its kin (`jclass`, `jstring`, `jobjectArray` and the per-primitive array types), `jmethodID`, `jfieldID`, `jthrowable`, `jobjectRefType`, `jvalue` — and the primitives `jboolean` through `jdouble` with `jsize`. A project's own definitions win over these, as with the type libraries.

A signature letter names its type: `V`, `Z`, `B`, `C`, `S`, `I`, `J`, `F`, `D` are the primitives, `L<name>;` is the class (a `String` is `jstring`, an `Object` is `jobject`), and `[I`, `[[I` and `[[Ljava/lang/Object;` are the array types. A malformed signature keeps the spec's fallback — `jobject` in, `jobject` out.

`ag image jni` prints the JNI functions the image holds, each with its address, name, parameters and return. With `--json` it gives `functions` — each `address`, `name`, `params` and `returns`. With `--header` it writes the JNI types as a C header. A function whose parameters the type propagation already knows is retyped from its name — `from Java_com_example_Native_add's JNI prototype` is where `variables` says the type came from — and the analyst's pinned types stand.

The command is `ag image jni [--json] [--header]`.


