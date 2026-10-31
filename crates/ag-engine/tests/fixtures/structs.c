// A struct filled field by field through a pointer, a global filled by
// its address, and a global array filled by index.
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

long pairs[8];

__attribute__((noinline)) void fill_pair(long i) {
    pairs[i] = 1;
    pairs[i + 1] = 2;
}

void _start(void) {
    init(&here, 1);
    init_global(2);
    fill_pair(3);
    __asm__ volatile("mov $60, %eax\n syscall");
}
