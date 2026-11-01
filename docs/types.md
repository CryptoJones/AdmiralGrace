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
| a function | its return type, its parameters' types and whether it ends in `...`; a variable or member is a pointer to one |
| a name | a definition's key: `struct point`, `union value`, `enum color`, or a typedef's name, `node_t` |

A definition is a structure or union — its tag, its members (each a name, a type and, for a
bit-field, a width), the `#pragma pack` it was read under, and whether it is `packed` or
`aligned(N)` — an enumeration — its tag, the integer it is held in and its enumerators with
their values — or a typedef. A structure named before it is defined, `struct node *next`, is
declared and incomplete: a pointer to it is whole, a member or variable of it is refused
until it is defined. A structure holding itself by value, directly or through another, is
refused the same way, so a cycle by value cannot be made; one through pointers is a list or
a tree, as in C.

The store (`TypeStore`) holds the definitions by key under one data model and answers the
size and alignment of any type, the layout of each structure and union, and the member at
an offset: `field_at(type, offset, size)` gives the path to the bytes — `.inner.a[2].f` —
when they are exactly a member's, inside nested structures and arrays, through anonymous
members as C reaches them, a union's first member they fit.

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

## What comes later

The model leaves room for the items that build on it:

- **Struct-by-value calling conventions (#388)** add the SSE and MEMORY classes, `rdx` of a
  returned structure, and the other conventions to the INTEGER class the fragments read.
- **Type propagation (#370)** carries a type from a variable to what it is copied into and
  passed to; the lift's variables already take a type by name.
- **The union field per instruction (#371)** replaces the first-member-that-fits choice, made
  in one place (`TypeStore::field_at`).
- **Bit-field members (#372)** read the accesses to a bit-field's unit as the bit-field: the
  layout already places each with its unit and first bit, and `field_at` skips them now.
- **Attributes (#373)** — Microsoft's bit-field rule, base classes, `noreturn` and the rest —
  join `packed` and `aligned` on `Composite`; the parser notes the attributes it skips.
- **Type libraries (#376)**, **platform types (#378)** and **header import (#379)** add
  definitions to the store from elsewhere than the project, the last with a preprocessor;
  **export as a header (#380)** writes `definition_text` in the store's order.
- **Cross references for types and members (#384)** follow the members and enumerators the
  pseudocode reads, which stand as the `__member`, `__arrow` and `__enumerator` intrinsics.
