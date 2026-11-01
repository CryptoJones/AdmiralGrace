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

## What comes later

The model leaves room for the items that build on it:

- **Type fragments (#367)** and **smart structures (#369)** read and build structures from
  the accesses through a pointer: `field_at` answers what lies at an offset, and a structure
  is made by writing its C.
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
