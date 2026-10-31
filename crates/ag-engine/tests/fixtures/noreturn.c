// Functions that do not return: one that never does, and helpers that
// do not under a condition — exit-on-error helpers — and their caller.
//
// Built with:
//   gcc -O1 -fno-pic -no-pie -nostdlib -static -o noreturn.elf noreturn.c
int status;

__attribute__((noinline, noreturn)) void die(int code) {
    status = code;
    __asm__ volatile("mov $60, %eax\n syscall");
    __builtin_unreachable();
}

__attribute__((noinline)) int checked(int *p, int v) {
    if (p == 0) {
        die(2);
    }
    *p = v;
    return v + 1;
}

__attribute__((noinline)) int positive(int x) {
    if (x < 0) {
        die(3);
    }
    return x * 2;
}

__attribute__((noinline)) int caller(int *p) {
    int r = checked(p + 1, 5);
    return positive(r);
}

void _start(void) {
    caller(&status);
    die(0);
}
