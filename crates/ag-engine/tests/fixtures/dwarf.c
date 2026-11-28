// A program whose DWARF the importer reads (#401): structures, a
// self-reference, an enumeration, typedefs, a packed structure,
// bit-fields, globals of each kind, and functions with parameters and
// locals — one a static, which stands in memory rather than the frame.
//
// Built with:
//   gcc -g -O0 -fno-pic -no-pie -o dwarf.elf dwarf.c
//   gcc -gdwarf-4 -g -O0 -fno-pic -no-pie -o dwarf4.elf dwarf.c
//   objcopy --only-keep-debug dwarf.elf dwarf.debug
//   objcopy --strip-debug dwarf.elf dwarf_stripped.elf
//   objcopy --add-gnu-debuglink=dwarf.debug dwarf_stripped.elf

struct point { int x; int y; };
struct node { int value; struct node *next; };
enum color { RED, GREEN = 5, BLUE };
typedef struct point point_t;
typedef int (*cmp_t)(int, int);
struct packed { char c; int i; short s; } __attribute__((packed));
struct flags { unsigned a : 3; unsigned b : 5; unsigned : 0; unsigned c : 4; };
struct outer { struct point p; struct flags f; char name[8]; };

int global_count = 7;
struct point global_point = { 1, 2 };
long global_table[4] = { 1, 2, 3, 4 };
enum color global_color = GREEN;
struct node global_node = { 1, 0 };
struct packed global_packed = { 'a', 2, 3 };

__attribute__((noinline)) int add(int a, int b) {
    int sum = a + b;
    return sum;
}

__attribute__((noinline)) long sum_to(int n) {
    long acc = 0;
    for (int i = 0; i < n; i++) {
        acc += i;
    }
    return acc;
}

__attribute__((noinline)) int use_point(struct point *p, point_t q) {
    struct point local = *p;
    static int calls = 0;
    calls++;
    return local.x + q.y + calls;
}

int main(void) {
    struct outer o;
    enum color c = BLUE;
    cmp_t compare = add;
    o.p.x = add(1, 2);
    o.f.a = 3;
    return (int)sum_to(o.p.x) + c + global_count
        + use_point(&global_point, global_point) + (compare != 0);
}