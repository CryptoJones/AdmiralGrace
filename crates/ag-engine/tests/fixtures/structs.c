// A struct filled field by field through a pointer, and a global filled
// by its address.
//
// Built with:
//   gcc -O1 -fno-pic -no-pie -nostdlib -static -o structs.elf structs.c
struct point {
    int x;
    int y;
    long tag;
};

struct point here;

__attribute__((noinline)) void init(struct point *p, int x) {
    p->x = x;
    p->y = 2;
    p->tag = 0x1122334455667788;
}

__attribute__((noinline)) void init_global(int v) {
    here.x = v;
    here.y = v + 1;
    here.tag = 7;
}

void _start(void) {
    init(&here, 1);
    init_global(2);
    __asm__ volatile("mov $60, %eax\n syscall");
}
