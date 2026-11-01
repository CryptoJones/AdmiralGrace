// Structures held in registers: passed by value, returned in rax, and a
// member copied through a register by an eight-byte value and a shift.
//
// Built with:
//   gcc -O1 -fno-pic -no-pie -nostdlib -static -o fragments.elf fragments.c
struct point {
    int x;
    int y;
};

struct span {
    long lo;
    long hi;
};

struct point here;
struct point there;
int out;
long total;

// System V passes p in rdi: x in its low half, y in its high.
__attribute__((noinline)) int weigh(struct point p) {
    return p.x + p.y * 3;
}

// A structure of 16 bytes comes in rdi and rsi.
__attribute__((noinline)) long width(struct span s) {
    return s.hi - s.lo;
}

// And one of 8 bytes goes back in rax.
__attribute__((noinline)) struct point make(int x, int y) {
    struct point p = {x, y};
    return p;
}

// The caller reads y from the high half of rax.
__attribute__((noinline)) int second(int x) {
    struct point p = make(x, 5);
    return p.y;
}

// Both members loaded, joined into one register, and y shifted back out.
__attribute__((noinline)) void copy_y(struct point *to, const struct point *from) {
    struct point p = *from;
    __asm__ volatile("" : "+r"(p));
    to->y = p.y;
}

void _start(void) {
    struct span s = {2, 9};
    here = make(1, 2);
    copy_y(&there, &here);
    out = weigh(here) + second(3);
    total = width(s);
    __asm__ volatile("mov $60, %eax\n syscall");
}
